#include "Common.h"
#include "ExceptionReporter.h"
#include "LeechCoreEngine.h"
#include "RpcDispatcher.h"
#include "TransportManager.h"
#include "usb_hub.h"
#include "usb_server.h"

#if ENABLE_TRANSPORT_MODES
#define IOCTL_WINUSB_READ_PIPE 0x0350401E
#define IOCTL_WINUSB_WRITE_PIPE 0x03508021
#define IOCTL_WINUSB_FLUSH_PIPE 0x03504048
#define IOCTL_WINUSB_RESET_PIPE 0x0350C024
#define IOCTL_WINUSB_ABORT_PIPE 0x0350C028

#ifdef KeClearEvent
#undef KeClearEvent
#endif
#define KeClearEvent(Event)                                                                                                                \
    do                                                                                                                                     \
    {                                                                                                                                      \
        if (UserVar && UserVar->Func.KeClearEvent)                                                                                         \
            UserVar->Func.KeClearEvent(Event);                                                                                             \
    } while (0)

#ifdef KeGetCurrentIrql
#undef KeGetCurrentIrql
#endif
#define KeGetCurrentIrql() ((KIRQL)__readcr8())
MK_USB_SERVER g_UsbServer = {0};

/*
 * 无头物理页分配辅助原语（零 PoolBigPageTable 登记）：
 * 使用 MmAllocatePagesForMdl 直接向 MiAllocatePagesForMdl 索取游离物理页，
 * 并通过 MmMapLockedPagesSpecifyCache 映射至 System PTE 区间。
 * 单槽 0x110000 (272 页) 的 MDL 头部仅 2224 字节 (< 4KB)，连 MDL 结构本身也落入 Small Pool。
 */
static PUCHAR UsbServer_AllocHeadlessBuffer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ SIZE_T cbSize, _Out_ PMDL *ppPagesMdl)
{
    if (ppPagesMdl)
        *ppPagesMdl = NULL;
    if (!UserVar || cbSize == 0 || !ppPagesMdl || !UserVar->Func.MmAllocatePagesForMdl ||
        !UserVar->Func.MmMapLockedPagesSpecifyCache || !UserVar->Func.MmFreePagesFromMdl || !UserVar->Func.ExFreePoolWithTag)
    {
        return NULL;
    }

    SIZE_T cbAligned = (cbSize + PAGE_SIZE - 1) & ~((SIZE_T)PAGE_SIZE - 1);
    PHYSICAL_ADDRESS lowAddr, highAddr, skipBytes;
    lowAddr.QuadPart = 0;
    highAddr.QuadPart = ~0ULL;
    skipBytes.QuadPart = 0;

    PMDL pMdl = UserVar->Func.MmAllocatePagesForMdl(lowAddr, highAddr, skipBytes, cbAligned);
    if (!pMdl)
        return NULL;

    if (MmGetMdlByteCount(pMdl) < cbAligned)
    {
        UserVar->Func.MmFreePagesFromMdl(pMdl);
        UserVar->Func.ExFreePoolWithTag(pMdl, 0);
        return NULL;
    }

    PUCHAR pVa = (PUCHAR)UserVar->Func.MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!pVa)
    {
        UserVar->Func.MmFreePagesFromMdl(pMdl);
        UserVar->Func.ExFreePoolWithTag(pMdl, 0);
        return NULL;
    }

    if (UserVar->Func.RtlZeroMemory)
        UserVar->Func.RtlZeroMemory(pVa, cbAligned);

    *ppPagesMdl = pMdl;
    return pVa;
}

static VOID UsbServer_FreeHeadlessBuffer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ PVOID pVa, _In_opt_ PMDL pPagesMdl)
{
    if (!UserVar || !pPagesMdl)
        return;
    if (pVa && UserVar->Func.MmUnmapLockedPages)
        UserVar->Func.MmUnmapLockedPages(pVa, pPagesMdl);
    if (UserVar->Func.MmFreePagesFromMdl)
        UserVar->Func.MmFreePagesFromMdl(pPagesMdl);
    if (UserVar->Func.ExFreePoolWithTag)
        UserVar->Func.ExFreePoolWithTag(pPagesMdl, 0);
}

static VOID UsbServer_FreeFastBuffers(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
        return;

    if (g_UsbServer.pSendMdlSlot[0])
    {
        if (UserVar->Func.IoFreeMdl)
            UserVar->Func.IoFreeMdl(g_UsbServer.pSendMdlSlot[0]);
        g_UsbServer.pSendMdlSlot[0] = NULL;
    }
    if (g_UsbServer.pSendMdlSlot[1])
    {
        if (UserVar->Func.IoFreeMdl)
            UserVar->Func.IoFreeMdl(g_UsbServer.pSendMdlSlot[1]);
        g_UsbServer.pSendMdlSlot[1] = NULL;
    }
    if (g_UsbServer.pFastRecvMdl)
    {
        if (UserVar->Func.IoFreeMdl)
            UserVar->Func.IoFreeMdl(g_UsbServer.pFastRecvMdl);
        g_UsbServer.pFastRecvMdl = NULL;
    }

    if (g_UsbServer.pSendPagesMdlSlot[0])
    {
        UsbServer_FreeHeadlessBuffer(UserVar, g_UsbServer.pSendBufSlot[0], g_UsbServer.pSendPagesMdlSlot[0]);
        g_UsbServer.pSendPagesMdlSlot[0] = NULL;
        g_UsbServer.pSendBufSlot[0] = NULL;
    }
    if (g_UsbServer.pSendPagesMdlSlot[1])
    {
        UsbServer_FreeHeadlessBuffer(UserVar, g_UsbServer.pSendBufSlot[1], g_UsbServer.pSendPagesMdlSlot[1]);
        g_UsbServer.pSendPagesMdlSlot[1] = NULL;
        g_UsbServer.pSendBufSlot[1] = NULL;
    }
    g_UsbServer.pFastSendBuf = NULL;

    if (g_UsbServer.pFastRecvPagesMdl)
    {
        UsbServer_FreeHeadlessBuffer(UserVar, g_UsbServer.pFastRecvBuf, g_UsbServer.pFastRecvPagesMdl);
        g_UsbServer.pFastRecvPagesMdl = NULL;
        g_UsbServer.pFastRecvBuf = NULL;
    }
}

#pragma pack(push, 1)
typedef struct _WINUSB_PIPE_PARAM
{
    UCHAR InterfaceNumber; // 0x00: 接口编号 (必须为 0)
    UCHAR PipeId;          // 0x01: 管道端点 ID (例如 0x89, 0x08)
} WINUSB_PIPE_PARAM;
#pragma pack(pop)

static VOID UsbServer_AbortPipe(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ HANDLE hDev, _In_ UCHAR pipeId)
{
    if (!UserVar)
    {
        return;
    }

    if (g_UsbServer.fHubMode)
    {
        BOOLEAN bIsIn = (pipeId & 0x80) != 0;
        DBG("UsbServer_AbortPipe: [USBHUB] Aborting Pipe 0x%02X...", pipeId);
        UsbHub_AbortPipe(UserVar, bIsIn);
        return;
    }

    if (!hDev)
    {
        return;
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    if (pFileObj)
    {
        KeClearEvent(&pFileObj->Event);
    }
    IO_STATUS_BLOCK iosb = {0};
    WINUSB_PIPE_PARAM pipeParam = {0, pipeId};
    NTSTATUS status =
        UserVar->Func.ZwDeviceIoControlFile(hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_ABORT_PIPE, &pipeParam, sizeof(pipeParam), NULL, 0);
    if (status == STATUS_PENDING && pFileObj)
    {
        UserVar->Func.KeWaitForSingleObject(&pFileObj->Event, Executive, KernelMode, FALSE, NULL);
    }
}

static NTSTATUS UsbServer_ReadPipe(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ HANDLE hDev, _In_ UCHAR pipeId, _Out_ PVOID pBuf,
                                   _In_ ULONG cbBuf, _Out_opt_ PULONG pcbRead)
{
    if (!UserVar || !pBuf || cbBuf == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pcbRead)
    {
        *pcbRead = 0;
    }

    if (g_UsbServer.fHubMode)
    {
        return UsbHub_BulkRead(UserVar, pBuf, cbBuf, 500, FALSE, pcbRead);
    }

    if (!hDev)
    {
        return STATUS_INVALID_HANDLE;
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    BOOLEAN fNeedDeref = FALSE;

    if (!pFileObj)
    {
        NTSTATUS refStatus = UserVar->Func.ObReferenceObjectByHandle(hDev, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&pFileObj, NULL);
        if (NT_SUCCESS(refStatus) && pFileObj)
        {
            fNeedDeref = TRUE;
        }
    }

    if (pFileObj)
    {
        KeClearEvent(&pFileObj->Event);
    }

    IO_STATUS_BLOCK iosb = {0};
    WINUSB_PIPE_PARAM pipeParam = {0, pipeId};

    NTSTATUS status = UserVar->Func.ZwDeviceIoControlFile(hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_READ_PIPE, &pipeParam,
                                                          sizeof(pipeParam), pBuf, cbBuf);

    if (status == STATUS_PENDING)
    {
        if (pFileObj)
        {
            LARGE_INTEGER Timeout;
            Timeout.QuadPart = -10 * 1000 * 500; // 500ms 守护超时
            while (g_UsbServer.fRunning)
            {
                status = UserVar->Func.KeWaitForSingleObject(&pFileObj->Event, Executive, KernelMode, FALSE, &Timeout);
                if (status == STATUS_TIMEOUT)
                {
                    if (!g_UsbServer.fRunning)
                    {
                        UsbServer_AbortPipe(UserVar, hDev, pipeId);
                        status = STATUS_CANCELLED;
                        break;
                    }
                    continue;
                }
                if (status == STATUS_SUCCESS)
                {
                    status = iosb.Status;
                    break;
                }
                break;
            }
        }
    }

    if (fNeedDeref && pFileObj)
    {
        UserVar->Func.ObfDereferenceObject(pFileObj);
    }

    if (status == STATUS_SUCCESS && pcbRead)
    {
        *pcbRead = (ULONG)iosb.Information;
    }

    return status;
}

static NTSTATUS UsbServer_WritePipe(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ HANDLE hDev, _In_ UCHAR pipeId, _In_ PVOID pBuf,
                                    _In_ ULONG cbBuf, _Out_opt_ PULONG pcbWritten)
{
    if (!UserVar || !pBuf || cbBuf == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pcbWritten)
    {
        *pcbWritten = 0;
    }

    if (g_UsbServer.fHubMode)
    {
        return UsbHub_BulkWrite(UserVar, pBuf, cbBuf, pcbWritten);
    }

    if (!hDev)
    {
        return STATUS_INVALID_HANDLE;
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    BOOLEAN fNeedDeref = FALSE;

    if (!pFileObj)
    {
        NTSTATUS refStatus = UserVar->Func.ObReferenceObjectByHandle(hDev, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&pFileObj, NULL);
        if (NT_SUCCESS(refStatus) && pFileObj)
        {
            fNeedDeref = TRUE;
        }
    }

    ULONG cbTotalWritten = 0;
    PUCHAR pCur = (PUCHAR)pBuf;
    NTSTATUS status = STATUS_SUCCESS;
    const ULONG CHUNK_SIZE = 1024 * 1024;

    while (cbTotalWritten < cbBuf && g_UsbServer.fRunning)
    {
        ULONG cbChunk = min(cbBuf - cbTotalWritten, CHUNK_SIZE);
        IO_STATUS_BLOCK iosb = {0};
        WINUSB_PIPE_PARAM pipeParam = {0, pipeId};

        if (pFileObj)
        {
            KeClearEvent(&pFileObj->Event);
        }

        status = UserVar->Func.ZwDeviceIoControlFile(hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_WRITE_PIPE, &pipeParam, sizeof(pipeParam),
                                                     pCur + cbTotalWritten, cbChunk);

        if (status == STATUS_PENDING && pFileObj)
        {
            status = UserVar->Func.KeWaitForSingleObject(&pFileObj->Event, Executive, KernelMode, FALSE, NULL);
            if (status == STATUS_SUCCESS)
            {
                status = iosb.Status;
            }
        }

        if (!NT_SUCCESS(status))
        {
            break;
        }

        ULONG cbThisWrite = (ULONG)iosb.Information;
        if (cbThisWrite == 0)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        cbTotalWritten += cbThisWrite;
    }

    if (fNeedDeref && pFileObj)
    {
        UserVar->Func.ObfDereferenceObject(pFileObj);
    }

    if (pcbWritten)
    {
        *pcbWritten = cbTotalWritten;
    }

    return (cbTotalWritten == cbBuf) ? STATUS_SUCCESS : (NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status);
}

static VOID UsbServer_FlushPipe(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ HANDLE hDev, _In_ UCHAR pipeId)
{
    if (!UserVar)
    {
        return;
    }

    if (g_UsbServer.fHubMode)
    {
        BOOLEAN bIsIn = (pipeId & 0x80) != 0;
        UsbHub_AbortPipe(UserVar, bIsIn);
        return;
    }

    if (!hDev)
    {
        return;
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    if (pFileObj)
    {
        KeClearEvent(&pFileObj->Event);
    }
    IO_STATUS_BLOCK iosb = {0};
    WINUSB_PIPE_PARAM pipeParam = {0, pipeId};
    NTSTATUS status =
        UserVar->Func.ZwDeviceIoControlFile(hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_FLUSH_PIPE, &pipeParam, sizeof(pipeParam), NULL, 0);
    if (status == STATUS_PENDING && pFileObj)
    {
        UserVar->Func.KeWaitForSingleObject(&pFileObj->Event, Executive, KernelMode, FALSE, NULL);
    }
}

static VOID UsbServer_ResetPipe(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ HANDLE hDev, _In_ UCHAR pipeId)
{
    if (!UserVar)
    {
        return;
    }

    if (g_UsbServer.fHubMode)
    {
        BOOLEAN bIsIn = (pipeId & 0x80) != 0;
        UsbHub_ResetPipe(UserVar, bIsIn);
        return;
    }

    if (!hDev)
    {
        return;
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    if (pFileObj)
    {
        KeClearEvent(&pFileObj->Event);
    }
    IO_STATUS_BLOCK iosb = {0};
    WINUSB_PIPE_PARAM pipeParam = {0, pipeId};
    NTSTATUS status =
        UserVar->Func.ZwDeviceIoControlFile(hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_RESET_PIPE, &pipeParam, sizeof(pipeParam), NULL, 0);
    if (status == STATUS_PENDING && pFileObj)
    {
        UserVar->Func.KeWaitForSingleObject(&pFileObj->Event, Executive, KernelMode, FALSE, NULL);
    }
}

static NTSTATUS UsbServer_AutoDetectDeviceAndPipes(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ PMK_SERVER_START_PARAMS pParams,
                                                   _Out_ PHANDLE phDevice, _Out_ PFILE_OBJECT *ppFileObj,
                                                   _Out_ PUCHAR pPipeIn, _Out_ PUCHAR pPipeOut,
                                                   _Out_writes_(cchMaxPath) PWSTR pszSelectedPath, _In_ ULONG cchMaxPath,
                                                   _In_ BOOLEAN bQuiet);

static BOOLEAN UsbServer_FindResyncFrame(_In_reads_bytes_(cbTail) const UCHAR *pBuf, _In_ ULONG cbTail,
                                            _In_ ULONG cbStart, _Out_ PULONG pFound)
{
    if (!pBuf || !pFound || cbTail < USB_SERVER_HEADER_SIZE + sizeof(LEECHRPC_MSG_HDR))
    {
        return FALSE;
    }

    ULONG cbMinimum = USB_SERVER_HEADER_SIZE + sizeof(LEECHRPC_MSG_HDR);
    if (cbStart >= cbTail || cbTail - cbStart < cbMinimum)
    {
        return FALSE;
    }

    ULONG cbLastCandidate = cbTail - cbMinimum;
    for (ULONG pos = cbStart; pos <= cbLastCandidate; ++pos)
    {
        if (*(PULONG64)(pBuf + pos) == 0)
        {
            continue;
        }

        ULONG cbPayload = *(PULONG)(pBuf + pos + 8);
        if (cbPayload < sizeof(LEECHRPC_MSG_HDR) || cbPayload > USB_SERVER_MAX_MSG_SIZE)
        {
            continue;
        }
        if (cbPayload > cbTail - pos - USB_SERVER_HEADER_SIZE)
        {
            continue;
        }

        PLEECHRPC_MSG_HDR pHdr = (PLEECHRPC_MSG_HDR)(pBuf + pos + USB_SERVER_HEADER_SIZE);
        if (pHdr->dwMagic != LEECHRPC_MSGMAGIC || pHdr->cbMsg != cbPayload ||
            pHdr->tpMsg <= LEECHRPC_MSGTYPE_NA || pHdr->tpMsg > LEECHRPC_MSGTYPE_MAX)
        {
            continue;
        }

        *pFound = pos;
        return TRUE;
    }
    return FALSE;
}

static VOID UsbServer_WorkerThread(_In_ PVOID Context)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = (MACHENIKE_KERNEL_INTERFACE *)Context;
    if (!UserVar)
    {
        return;
    }

    DBG("UsbServer_WorkerThread: Worker thread started, listening on PipeIn=0x%02X, PipeOut=0x%02X", g_UsbServer.PipeIn,
        g_UsbServer.PipeOut);

    g_UsbServer.ActiveConnections = 1;

    UCHAR currentIn = g_UsbServer.PipeIn;
    UCHAR currentOut = g_UsbServer.PipeOut;

    // 启动前先重置并刷新硬件端点与 FIFO，清除跨会话残留的 Data Toggle 失步与 Halted 状态
    UsbServer_ResetPipe(UserVar, g_UsbServer.hDevice, currentIn);
    UsbServer_ResetPipe(UserVar, g_UsbServer.hDevice, currentOut);
    UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
    UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentOut);

    ULONG curSlot = 0;
    ULONG cbRemain = 0;
    ULONG cbPendingRead = 0;
    ULONG consecErrors = 0;
    ULONG consecFrameSyncFailures = 0;

    // Hub 模式启动/重连后用短超时读取一次：有数据则交给同一解析器，不丢弃合法帧；
    // 超时表示当前 FIFO 已空，随后进入常规常驻 IRP 读取。
    if (g_UsbServer.fHubMode && g_UsbServer.pFastRecvBuf)
    {
        NTSTATUS drainStatus = UsbHub_BulkRead(UserVar, g_UsbServer.pFastRecvBuf, USB_SERVER_SLOT_SIZE, 20, TRUE, &cbPendingRead);
        if (!NT_SUCCESS(drainStatus) && drainStatus != STATUS_TIMEOUT)
        {
            DBG("UsbServer_WorkerThread: initial hub FIFO drain read failed: 0x%08X", drainStatus);
            cbPendingRead = 0;
        }
    }

    while (g_UsbServer.fRunning)
    {
        ULONG cbFastRead = 0;
        NTSTATUS status = STATUS_SUCCESS;
        ULONG64 tscRecv0 = MK_PERF_RDTSC();

        if (cbPendingRead > 0)
        {
            cbFastRead = cbPendingRead;
            cbPendingRead = 0;
        }
        // ★★★ 优先采用常驻 IRP / MDL 零分配高速直读 (一跳直达 ucx01000 / USBXHCI RootHub PDO) ★★★
        else if (g_UsbServer.fHubMode && g_UsbServer.pFastRecvMdl && cbRemain == 0)
        {
            status =
                UsbHub_BulkReadFast(UserVar, g_UsbServer.pFastRecvBuf, g_UsbServer.pFastRecvMdl, USB_SERVER_SLOT_SIZE, &cbFastRead);
        }
        else
        {
            ULONG cbReadReq = (USB_SERVER_SLOT_SIZE > cbRemain) ? ((USB_SERVER_SLOT_SIZE - cbRemain) & ~0x3FFU) : 1024;
            if (cbReadReq == 0)
            {
                cbReadReq = 1024;
            }
            status =
                UsbServer_ReadPipe(UserVar, g_UsbServer.hDevice, currentIn, g_UsbServer.pFastRecvBuf + cbRemain, cbReadReq, &cbFastRead);
        }
        ULONG64 tscRecvWait = MK_PERF_RDTSC() - tscRecv0;
        (VOID)tscRecvWait;

        if (!NT_SUCCESS(status))
        {
            if (!g_UsbServer.fRunning)
            {
                break;
            }

            if (status == STATUS_IO_TIMEOUT || status == STATUS_TIMEOUT || status == STATUS_CANCELLED)
            {
                MkRpc_PerfRecordIo(&g_UsbServer.TransportCtx, MK_PERF_TRANSPORT_USB, 0, 0, 0, 0, FALSE);
                continue;
            }

            consecErrors++;

            if (status != (NTSTATUS)0xC000000EL && status != STATUS_DEVICE_NOT_CONNECTED &&
                status != STATUS_DELETE_PENDING && status != (NTSTATUS)0xC00002B6L && consecErrors < 16)
            {
                DBG("UsbServer_WorkerThread: ReadPipe on 0x%02X transient error status=0x%08X (usbd=0x%08X, consec=%u), aborting & resetting pipe...",
                    currentIn, status, g_UsbHubLastUsbdStatus, consecErrors);
                cbRemain = 0;
                UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
                UsbServer_ResetPipe(UserVar, g_UsbServer.hDevice, currentIn);
                if (UserVar)
                {
                    LARGE_INTEGER Timeout;
                    Timeout.QuadPart = -10LL * 1000 * 25; // 25ms 退避
                    UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
                }
                continue;
            }

            // USB 桥接硬件被拔出、重置或断开 (或连续 16 次 ResetPipe 无法恢复)
            {
                ULONG usbdSt = g_UsbHubLastUsbdStatus;
                DBG("UsbServer_WorkerThread: USB device disconnected on 0x%02X (status=0x%08X, usbd=0x%08X, consec=%u), releasing stale handles and awaiting reconnect...",
                    currentIn, status, usbdSt, consecErrors);
                if (status != (NTSTATUS)0xC000000EL && status != STATUS_DEVICE_NOT_CONNECTED &&
                    status != STATUS_DELETE_PENDING && status != (NTSTATUS)0xC00002B6L &&
                    usbdSt != 0xC0000011UL && usbdSt != 0xC0000030UL)
                {
                    ExceptionReporter_ReportFormat("UsbServer_ReadPipe", status,
                        "ReadPipe on 0x%02X failed after %u resets (status=0x%08X, usbd=0x%08X)",
                        currentIn, consecErrors, status, usbdSt);
                }

                cbRemain = 0;
                consecErrors = 0;
                g_UsbServer.ActiveConnections = 0;

                if (g_UsbServer.fHubMode)
                {
                    g_UsbServer.fHubMode = FALSE;
                    UsbHub_Cleanup(UserVar);
                }
                if (g_UsbServer.pFileObj)
                {
                    UserVar->Func.ObfDereferenceObject(g_UsbServer.pFileObj);
                    g_UsbServer.pFileObj = NULL;
                }
                if (g_UsbServer.hDevice)
                {
                    UserVar->Func.ZwClose(g_UsbServer.hDevice);
                    g_UsbServer.hDevice = NULL;
                }

                while (g_UsbServer.fRunning)
                {
                    LARGE_INTEGER ReconnectDelay;
                    ReconnectDelay.QuadPart = -10LL * 1000 * 1000; // 1s 热插拔探测间隔
                    UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &ReconnectDelay);
                    if (!g_UsbServer.fRunning)
                    {
                        break;
                    }

                    HANDLE hNewDev = NULL;
                    PFILE_OBJECT pNewFileObj = NULL;
                    UCHAR newIn = 0;
                    UCHAR newOut = 0;
                    NTSTATUS reconnStatus = UsbServer_AutoDetectDeviceAndPipes(
                        UserVar, NULL, &hNewDev, &pNewFileObj, &newIn, &newOut, g_UsbServer.DevicePath, 260, TRUE);
                    if (NT_SUCCESS(reconnStatus))
                    {
                        g_UsbServer.hDevice = hNewDev;
                        g_UsbServer.pFileObj = pNewFileObj;
                        g_UsbServer.PipeIn = newIn;
                        g_UsbServer.PipeOut = newOut;
                        g_UsbServer.fHubMode = TRUE;
                        g_UsbServer.ActiveConnections = 1;
                        currentIn = newIn;
                        currentOut = newOut;
                        curSlot = 0;
                        UsbServer_ResetPipe(UserVar, g_UsbServer.hDevice, currentIn);
                        UsbServer_ResetPipe(UserVar, g_UsbServer.hDevice, currentOut);
                        UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
                        UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentOut);
                        cbPendingRead = 0;
                        NTSTATUS drainStatus = UsbHub_BulkRead(UserVar, g_UsbServer.pFastRecvBuf, USB_SERVER_SLOT_SIZE, 20, TRUE, &cbPendingRead);
                        if (!NT_SUCCESS(drainStatus) && drainStatus != STATUS_TIMEOUT)
                        {
                            DBG("UsbServer_WorkerThread: reconnect hub FIFO drain read failed: 0x%08X", drainStatus);
                            cbPendingRead = 0;
                        }
                        DBG("UsbServer_WorkerThread: [+] USB device hot-plug reconnected! PipeIn=0x%02X, PipeOut=0x%02X",
                            currentIn, currentOut);
                        break;
                    }
                }
                continue;
            }
        }

        consecErrors = 0;
        ULONG cbRecvTail = cbRemain + cbFastRead;
        cbRemain = 0;

        if (cbRecvTail < USB_SERVER_HEADER_SIZE)
        {
            cbRemain = cbRecvTail;
            continue;
        }

        // ★★★ 全双工异步批处理流水线 —— 连续收割请求帧并原位直写当前活跃槽位 ★★★
        ULONG cbOffset = 0;
        ULONG cbSendTotal = 0;
        ULONG cbBatchWireSend = 0;
        ULONG64 tscSendWait = 0;
        BOOLEAN fBatchFallback = FALSE;
        if (g_UsbServer.fHubMode && g_UsbServer.pSendMdlSlot[curSlot])
        {
            ULONG64 tWait0 = MK_PERF_RDTSC();
            UsbHub_WaitWriteSlot(UserVar, curSlot, NULL);
            tscSendWait += (MK_PERF_RDTSC() - tWait0);
        }
        PUCHAR pCurSendBuf = g_UsbServer.pSendBufSlot[curSlot] ? g_UsbServer.pSendBufSlot[curSlot] : g_UsbServer.pFastSendBuf;
        PMDL pCurSendMdl = g_UsbServer.pSendMdlSlot[curSlot];

        while ((cbRecvTail - cbOffset) >= USB_SERVER_HEADER_SIZE)
        {
            ULONG64 qwReqNonce = *(PULONG64)(g_UsbServer.pFastRecvBuf + cbOffset + 0);
            ULONG cbPayload = *(PULONG)(g_UsbServer.pFastRecvBuf + cbOffset + 8);

            // ★ 过滤 12 字节全零哑元短包尾标 (ZLP-Avoidance Trailer)
            if (qwReqNonce == 0 && cbPayload == 0)
            {
                cbOffset += USB_SERVER_HEADER_SIZE;
                continue;
            }

            if (cbPayload < sizeof(LEECHRPC_MSG_HDR) || cbPayload > USB_SERVER_MAX_MSG_SIZE)
            {
                ULONG resyncPos = 0;
                if (UsbServer_FindResyncFrame(g_UsbServer.pFastRecvBuf, cbRecvTail, cbOffset + 1, &resyncPos))
                {
                    DBG("UsbServer_WorkerThread: resynchronized invalid payload at offset=%u -> %u", cbOffset, resyncPos);
                    consecFrameSyncFailures = 0;
                    cbOffset = resyncPos;
                    continue;
                }

                DBG("UsbServer_WorkerThread: Invalid payload length %u without resync anchor", cbPayload);
                if (++consecFrameSyncFailures == 2)
                {
                    ExceptionReporter_ReportFormat("UsbServer_Payload", STATUS_INFO_LENGTH_MISMATCH,
                        "Invalid payload length %u on pipe 0x%02X after consecutive desync", cbPayload, currentIn);
                }
                cbOffset = cbRecvTail;
                break;
            }

            ULONG cbCurFrame = USB_SERVER_HEADER_SIZE + cbPayload;
            if ((cbRecvTail - cbOffset) < cbCurFrame)
            {
                break;
            }

            PUCHAR pbPayload = g_UsbServer.pFastRecvBuf + cbOffset + USB_SERVER_HEADER_SIZE;
            PLEECHRPC_MSG_HDR pHdr = (PLEECHRPC_MSG_HDR)pbPayload;
            if (pHdr->dwMagic != LEECHRPC_MSGMAGIC)
            {
                ULONG resyncPos = 0;
                if (UsbServer_FindResyncFrame(g_UsbServer.pFastRecvBuf, cbRecvTail, cbOffset + 1, &resyncPos))
                {
                    DBG("UsbServer_WorkerThread: resynchronized magic mismatch at offset=%u -> %u", cbOffset, resyncPos);
                    consecFrameSyncFailures = 0;
                    cbOffset = resyncPos;
                    continue;
                }

                DBG("UsbServer_WorkerThread: Magic mismatch 0x%08X without resync anchor", pHdr->dwMagic);
                if (++consecFrameSyncFailures == 2)
                {
                    ExceptionReporter_ReportFormat("UsbServer_Magic", STATUS_INVALID_IMAGE_FORMAT,
                        "Magic mismatch: 0x%08X (exp 0x%08X), pipe=0x%02X, Key=0x%016llX after consecutive desync",
                        pHdr->dwMagic, LEECHRPC_MSGMAGIC, currentIn, Transport_GetSessionCryptKey());
                }
                cbOffset = cbRecvTail;
                break;
            }

            consecFrameSyncFailures = 0;
            ULONG cbEstNeeded = 256;
            if (cbPayload >= sizeof(LEECHRPC_MSG_BIN))
            {
                PLEECHRPC_MSG_BIN pBinPeek = (PLEECHRPC_MSG_BIN)pbPayload;
                if (pBinPeek->dwMagic == LEECHRPC_MSGMAGIC && pBinPeek->tpMsg == LEECHRPC_MSGTYPE_READSCATTER_REQ)
                {
                    ULONG cMEMs = (ULONG)pBinPeek->qwData[0];
                    ULONG cbMax = (ULONG)pBinPeek->qwData[1];
                    if (cMEMs <= 0x2000 && cbMax <= (cMEMs << 12))
                    {
                        cbEstNeeded = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_SCATTER) + cbMax + 32;
                    }
                }
            }

            if (cbSendTotal > 0 && (cbSendTotal + USB_SERVER_HEADER_SIZE + cbEstNeeded > USB_SERVER_SLOT_SIZE))
            {
                if ((cbSendTotal & 0x1FF) == 0 && (cbSendTotal + USB_SERVER_HEADER_SIZE <= USB_SERVER_SLOT_SIZE))
                {
                    *(PULONG64)(pCurSendBuf + cbSendTotal + 0) = 0;
                    *(PULONG)(pCurSendBuf + cbSendTotal + 8) = 0;
                    cbSendTotal += USB_SERVER_HEADER_SIZE;
                }

                ULONG64 tSend0 = MK_PERF_RDTSC();
                if (g_UsbServer.fHubMode && pCurSendMdl)
                {
                    status = UsbHub_BulkWriteAsync(UserVar, curSlot, pCurSendBuf, pCurSendMdl, cbSendTotal);
                    if (!NT_SUCCESS(status))
                    {
                        fBatchFallback = TRUE;
                        ULONG cbWritten = 0;
                        UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, pCurSendBuf, cbSendTotal, &cbWritten);
                    }
                    cbBatchWireSend += cbSendTotal;
                    curSlot = 1 - curSlot;
                    UsbHub_WaitWriteSlot(UserVar, curSlot, NULL);
                    pCurSendBuf = g_UsbServer.pSendBufSlot[curSlot];
                    pCurSendMdl = g_UsbServer.pSendMdlSlot[curSlot];
                    cbSendTotal = 0;
                }
                else
                {
                    fBatchFallback = TRUE;
                    ULONG cbWritten = 0;
                    status = UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, pCurSendBuf, cbSendTotal, &cbWritten);
                    cbBatchWireSend += cbSendTotal;
                    cbSendTotal = 0;
                }
                tscSendWait += (MK_PERF_RDTSC() - tSend0);
            }

            PUCHAR pbDirectOut = NULL;
            ULONG cbDirectOutMax = 0;
            if (cbSendTotal + USB_SERVER_HEADER_SIZE < USB_SERVER_SLOT_SIZE)
            {
                pbDirectOut = pCurSendBuf + cbSendTotal + USB_SERVER_HEADER_SIZE;
                cbDirectOutMax = USB_SERVER_SLOT_SIZE - (cbSendTotal + USB_SERVER_HEADER_SIZE);
            }

            PUCHAR pbRsp = NULL;
            ULONG cbRsp = 0;
            status = MkRpc_DispatchCommandEx(&g_UsbServer.TransportCtx, pbPayload, pHdr->cbMsg, &pbRsp, &cbRsp,
                                             (cbDirectOutMax >= 256) ? pbDirectOut : NULL, (cbDirectOutMax >= 256) ? cbDirectOutMax : 0);

            if (NT_SUCCESS(status) && pbRsp && cbRsp > 0)
            {
                ULONG cbTotalFrame = USB_SERVER_HEADER_SIZE + cbRsp;

                if (pbRsp == pbDirectOut)
                {
                    *(PULONG64)(pCurSendBuf + cbSendTotal + 0) = qwReqNonce;
                    *(PULONG)(pCurSendBuf + cbSendTotal + 8) = cbRsp;
                    cbSendTotal += cbTotalFrame;
                    g_UsbServer.TotalRequestsHandled++;
                }
                else
                {
                    fBatchFallback = TRUE;
                    if (pCurSendBuf && (cbSendTotal + cbTotalFrame <= USB_SERVER_SLOT_SIZE))
                    {
                        *(PULONG64)(pCurSendBuf + cbSendTotal + 0) = qwReqNonce;
                        *(PULONG)(pCurSendBuf + 8 + cbSendTotal) = cbRsp;
                        UserVar->Func.RtlCopyMemory(pCurSendBuf + cbSendTotal + USB_SERVER_HEADER_SIZE, pbRsp, cbRsp);
                        cbSendTotal += cbTotalFrame;
                        g_UsbServer.TotalRequestsHandled++;
                    }
                    else
                    {
                        if (cbSendTotal > 0)
                        {
                            if ((cbSendTotal & 0x1FF) == 0 && (cbSendTotal + USB_SERVER_HEADER_SIZE <= USB_SERVER_SLOT_SIZE))
                            {
                                *(PULONG64)(pCurSendBuf + cbSendTotal + 0) = 0;
                                *(PULONG)(pCurSendBuf + cbSendTotal + 8) = 0;
                                cbSendTotal += USB_SERVER_HEADER_SIZE;
                            }

                            ULONG64 tSend0 = MK_PERF_RDTSC();
                            if (g_UsbServer.fHubMode && pCurSendMdl)
                            {
                                status = UsbHub_BulkWriteAsync(UserVar, curSlot, pCurSendBuf, pCurSendMdl, cbSendTotal);
                                if (!NT_SUCCESS(status))
                                {
                                    ULONG cbWritten = 0;
                                    UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, pCurSendBuf, cbSendTotal, &cbWritten);
                                }
                                cbBatchWireSend += cbSendTotal;
                                curSlot = 1 - curSlot;
                                UsbHub_WaitWriteSlot(UserVar, curSlot, NULL);
                                pCurSendBuf = g_UsbServer.pSendBufSlot[curSlot];
                                pCurSendMdl = g_UsbServer.pSendMdlSlot[curSlot];
                                cbSendTotal = 0;
                            }
                            else
                            {
                                ULONG cbWritten = 0;
                                UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, pCurSendBuf, cbSendTotal, &cbWritten);
                                cbBatchWireSend += cbSendTotal;
                                cbSendTotal = 0;
                            }
                            tscSendWait += (MK_PERF_RDTSC() - tSend0);
                        }

                        ULONG64 tWaitAll0 = MK_PERF_RDTSC();
                        if (g_UsbServer.fHubMode)
                        {
                            UsbHub_WaitWriteSlot(UserVar, 0, NULL);
                            UsbHub_WaitWriteSlot(UserVar, 1, NULL);
                        }

                        PMDL pTempPagesMdl = NULL;
                        PUCHAR pSendBuf = UsbServer_AllocHeadlessBuffer(UserVar, cbTotalFrame, &pTempPagesMdl);
                        if (pSendBuf)
                        {
                            *(PULONG64)(pSendBuf + 0) = qwReqNonce;
                            *(PULONG)(pSendBuf + 8) = cbRsp;
                            UserVar->Func.RtlCopyMemory(pSendBuf + USB_SERVER_HEADER_SIZE, pbRsp, cbRsp);
                            ULONG cbWritten = 0;
                            status = UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, pSendBuf, cbTotalFrame, &cbWritten);
                            if (NT_SUCCESS(status))
                            {
                                g_UsbServer.TotalRequestsHandled++;
                                cbBatchWireSend += cbTotalFrame;
                            }
                            else
                            {
                                UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentOut);
                            }
                            UsbServer_FreeHeadlessBuffer(UserVar, pSendBuf, pTempPagesMdl);
                        }
                        tscSendWait += (MK_PERF_RDTSC() - tWaitAll0);
                    }

                    UserVar->Func.ExFreePoolWithTag(pbRsp, LC_POOL_TAG);
                }
                pbRsp = NULL;
            }
            else
            {
                if (pbRsp && pbRsp != pbDirectOut)
                {
                    UserVar->Func.ExFreePoolWithTag(pbRsp, LC_POOL_TAG);
                    pbRsp = NULL;
                }

                ExceptionReporter_ReportFormat("UsbServer_Dispatch", status,
                    "MkRpc_DispatchCommandEx failed (tpMsg=0x%08X, status=0x%08X)", pHdr->tpMsg, status);

                LEECHRPC_MSG_HDR hdrErr = {0};
                hdrErr.dwMagic = LEECHRPC_MSGMAGIC;
                hdrErr.cbMsg = sizeof(LEECHRPC_MSG_HDR);
                hdrErr.fMsgResult = FALSE;

                ULONG cbErrTotal = USB_SERVER_HEADER_SIZE + sizeof(hdrErr);
                if (pCurSendBuf && (cbSendTotal + cbErrTotal <= USB_SERVER_SLOT_SIZE))
                {
                    *(PULONG64)(pCurSendBuf + cbSendTotal + 0) = qwReqNonce;
                    *(PULONG)(pCurSendBuf + cbSendTotal + 8) = sizeof(hdrErr);
                    UserVar->Func.RtlCopyMemory(pCurSendBuf + cbSendTotal + USB_SERVER_HEADER_SIZE, &hdrErr, sizeof(hdrErr));
                    cbSendTotal += cbErrTotal;
                }
            }

            cbOffset += cbCurFrame;
        }

        if (cbSendTotal > 0)
        {
            if ((cbSendTotal & 0x1FF) == 0 && (cbSendTotal + USB_SERVER_HEADER_SIZE <= USB_SERVER_SLOT_SIZE))
            {
                *(PULONG64)(pCurSendBuf + cbSendTotal + 0) = 0;
                *(PULONG)(pCurSendBuf + cbSendTotal + 8) = 0;
                cbSendTotal += USB_SERVER_HEADER_SIZE;
            }

            ULONG64 tSend0 = MK_PERF_RDTSC();
            if (g_UsbServer.fHubMode && pCurSendMdl)
            {
                status = UsbHub_BulkWriteAsync(UserVar, curSlot, pCurSendBuf, pCurSendMdl, cbSendTotal);
                if (!NT_SUCCESS(status))
                {
                    fBatchFallback = TRUE;
                    ULONG cbWritten = 0;
                    status = UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, pCurSendBuf, cbSendTotal, &cbWritten);
                    if (!NT_SUCCESS(status))
                    {
                        UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentOut);
                    }
                }
                cbBatchWireSend += cbSendTotal;
                curSlot = 1 - curSlot;
            }
            else
            {
                fBatchFallback = TRUE;
                ULONG cbWritten = 0;
                status = UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, pCurSendBuf, cbSendTotal, &cbWritten);
                if (!NT_SUCCESS(status))
                {
                    UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentOut);
                }
                cbBatchWireSend += cbSendTotal;
            }
            tscSendWait += (MK_PERF_RDTSC() - tSend0);
        }

        MkRpc_PerfRecordIo(&g_UsbServer.TransportCtx, MK_PERF_TRANSPORT_USB, cbFastRead, cbBatchWireSend, tscRecvWait, tscSendWait,
                           fBatchFallback);

        if (cbOffset < cbRecvTail)
        {
            cbRemain = cbRecvTail - cbOffset;
            UserVar->Func.RtlMoveMemory(g_UsbServer.pFastRecvBuf, g_UsbServer.pFastRecvBuf + cbOffset, cbRemain);
        }
        else
        {
            cbRemain = 0;
        }
    }

    if (g_UsbServer.fHubMode)
    {
        UsbHub_WaitWriteSlot(UserVar, 0, NULL);
        UsbHub_WaitWriteSlot(UserVar, 1, NULL);
    }

    g_UsbServer.ActiveConnections = 0;
    DBG("UsbServer_WorkerThread: Exited");

    if (UserVar)
    {
        UserVar->Func.KeSetEvent(&g_UsbServer.WorkerExitEvent, IO_NO_INCREMENT, FALSE);
    }
}

static BOOLEAN UsbServer_IsMi05Device(_In_opt_ PCWSTR pszPath)
{
    if (!pszPath)
    {
        return FALSE;
    }
    for (PCWSTR p = pszPath; *p != L'\0'; p++)
    {
        if ((p[0] == L'm' || p[0] == L'M') && (p[1] == L'i' || p[1] == L'I') && (p[2] == L'_') && (p[3] == L'0') && (p[4] == L'5'))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN UsbServer_ContainsSubstrCaseless(_In_reads_(cchStr) PCWSTR pszStr, _In_ ULONG cchStr, _In_ PCWSTR pszSub)
{
    if (!pszStr || !pszSub || cchStr == 0)
    {
        return FALSE;
    }
    ULONG subLen = 0;
    while (pszSub[subLen] != L'\0')
    {
        subLen++;
    }
    if (subLen == 0 || subLen > cchStr)
    {
        return FALSE;
    }

    for (ULONG i = 0; i <= cchStr - subLen; i++)
    {
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < subLen; j++)
        {
            WCHAR c1 = pszStr[i + j];
            WCHAR c2 = pszSub[j];
            if (c1 >= L'a' && c1 <= L'z')
                c1 -= 32;
            if (c2 >= L'a' && c2 <= L'z')
                c2 -= 32;
            if (c1 != c2)
            {
                match = FALSE;
                break;
            }
        }
        if (match)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * UsbServer_ProbeAndInitCandidate — 验证候选设备是否为 WinUSB，执行零 IOCTL 内存管道扫描与 USBHUB3 PDO 穿透。
 * 注意：必须保持赢家候选的 hDev 与 pFileObj 打开状态，防止 WinUsb!EvtFileCleanup 触发 WdfDeviceResumeIdle
 * 导致 MI_05 接口进入 D2/D3 选择性挂起 (Selective Suspend) 及 WdfIoTargetStop 停止管道。
 */
static BOOLEAN UsbServer_ProbeAndInitCandidate(
    _In_  MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_  HANDLE hDev,
    _In_  UCHAR reqPipeIn,
    _In_  UCHAR reqPipeOut,
    _Out_ PFILE_OBJECT *ppFileObj,
    _Out_ PUCHAR pPipeIn,
    _Out_ PUCHAR pPipeOut)
{
    *ppFileObj = NULL;
    PFILE_OBJECT pFileObj = NULL;
    NTSTATUS status = UserVar->Func.ObReferenceObjectByHandle(hDev, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&pFileObj, NULL);
    if (!NT_SUCCESS(status) || !pFileObj || !pFileObj->DeviceObject)
    {
        if (pFileObj)
            UserVar->Func.ObfDereferenceObject(pFileObj);
        return FALSE;
    }

    BOOLEAN bIsWinUsb = FALSE;
    PDEVICE_OBJECT pDev = pFileObj->DeviceObject;
    while (pDev != NULL)
    {
        if (pDev->DriverObject != NULL && pDev->DriverObject->DriverName.Buffer != NULL)
        {
            UNICODE_STRING drvName = pDev->DriverObject->DriverName;
            if (UsbServer_ContainsSubstrCaseless(drvName.Buffer, drvName.Length / sizeof(WCHAR), L"WINUSB"))
            {
                bIsWinUsb = TRUE;
                break;
            }
        }
        pDev = pDev->AttachedDevice;
    }

    if (!bIsWinUsb)
    {
        UserVar->Func.ObfDereferenceObject(pFileObj);
        return FALSE;
    }

    UCHAR epIn = reqPipeIn;
    UCHAR epOut = reqPipeOut;
    NTSTATUS hubStatus = UsbHub_Init(UserVar, pFileObj->DeviceObject, &epIn, &epOut);
    if (!NT_SUCCESS(hubStatus) || epIn == 0 || epOut == 0)
    {
        UserVar->Func.ObfDereferenceObject(pFileObj);
        return FALSE;
    }

    *ppFileObj = pFileObj;
    *pPipeIn = epIn;
    *pPipeOut = epOut;
    return TRUE;
}

static NTSTATUS UsbServer_AutoDetectDeviceAndPipes(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ PMK_SERVER_START_PARAMS pParams,
                                                   _Out_ PHANDLE phDevice, _Out_ PFILE_OBJECT *ppFileObj,
                                                   _Out_ PUCHAR pPipeIn, _Out_ PUCHAR pPipeOut,
                                                   _Out_writes_(cchMaxPath) PWSTR pszSelectedPath, _In_ ULONG cchMaxPath,
                                                   _In_ BOOLEAN bQuiet)
{
    if (!UserVar || !phDevice || !ppFileObj || !pPipeIn || !pPipeOut || !pszSelectedPath || cchMaxPath == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *phDevice = NULL;
    *ppFileObj = NULL;
    UCHAR reqIn = pParams ? pParams->PipeIn : 0;
    UCHAR reqOut = pParams ? pParams->PipeOut : 0;

    // 1. 若外部显式传入指定 DevicePath 则优先打开
    if (pParams && pParams->DevicePath[0] != L'\0')
    {
        UNICODE_STRING ustrExplicit;
        UserVar->Func.RtlInitUnicodeString(&ustrExplicit, pParams->DevicePath);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &ustrExplicit, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        IO_STATUS_BLOCK iosb = {0};
        HANDLE hDev = NULL;
        NTSTATUS status =
            UserVar->Func.ZwCreateFile(&hDev, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (NT_SUCCESS(status) && hDev)
        {
            PFILE_OBJECT pFileObj = NULL;
            if (UsbServer_ProbeAndInitCandidate(UserVar, hDev, reqIn, reqOut, &pFileObj, pPipeIn, pPipeOut))
            {
                *phDevice = hDev;
                *ppFileObj = pFileObj;
                ULONG copyLen = 0;
                while (pParams->DevicePath[copyLen] != L'\0' && copyLen < cchMaxPath - 1)
                {
                    pszSelectedPath[copyLen] = pParams->DevicePath[copyLen];
                    copyLen++;
                }
                pszSelectedPath[copyLen] = L'\0';
                return STATUS_SUCCESS;
            }
            UserVar->Func.ZwClose(hDev);
        }
    }

    // 2. 遍历系统设备接口，专门匹配 MI_05 接口
    static const GUID guidWinUsbGeneric = {0xDEE824EF, 0x729B, 0x4A0E, {0x9C, 0x14, 0xB7, 0x11, 0x7D, 0x33, 0xA8, 0x17}};
    static const GUID guidZadigCustom = {0xBC103702, 0xDD72, 0x406F, {0x9B, 0x28, 0x95, 0xC8, 0x68, 0x33, 0x7B, 0x59}};
    static const GUID guidUsb3380 = {0xF72FE0D4, 0xCBCB, 0x407d, {0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B}};
    static const GUID guidWinUsbTest = {0xDA812BFF, 0x12C3, 0x46A2, {0x8E, 0x2B, 0xDB, 0xD3, 0xB7, 0x83, 0x4C, 0x43}};
    const GUID *targetGuids[] = {&guidWinUsbGeneric, &guidZadigCustom, &guidUsb3380, &guidWinUsbTest};

    for (ULONG g = 0; g < sizeof(targetGuids) / sizeof(targetGuids[0]); g++)
    {
        PWSTR pLinkList = NULL;
        NTSTATUS ifStatus = UserVar->Func.IoGetDeviceInterfaces(targetGuids[g], NULL, 0x00000001, &pLinkList);
        if (!NT_SUCCESS(ifStatus) || !pLinkList)
        {
            continue;
        }

        for (PWSTR pCur = pLinkList; *pCur != L'\0';)
        {
            ULONG curLen = 0;
            while (pCur[curLen] != L'\0')
            {
                curLen++;
            }

            if (UsbServer_IsMi05Device(pCur))
            {
                UNICODE_STRING ustrDevice;
                UserVar->Func.RtlInitUnicodeString(&ustrDevice, pCur);

                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, &ustrDevice, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                IO_STATUS_BLOCK iosb = {0};
                HANDLE hDev = NULL;
                NTSTATUS status = UserVar->Func.ZwCreateFile(&hDev, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, NULL,
                                                             FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                             FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

                if (NT_SUCCESS(status) && hDev)
                {
                    PFILE_OBJECT pFileObj = NULL;
                    if (UsbServer_ProbeAndInitCandidate(UserVar, hDev, reqIn, reqOut, &pFileObj, pPipeIn, pPipeOut))
                    {
                        *phDevice = hDev;
                        *ppFileObj = pFileObj;
                        ULONG copyLen = (curLen < cchMaxPath - 1) ? curLen : (cchMaxPath - 1);
                        for (ULONG k = 0; k < copyLen; k++)
                        {
                            pszSelectedPath[k] = pCur[k];
                        }
                        pszSelectedPath[copyLen] = L'\0';

                        UserVar->Func.ExFreePoolWithTag(pLinkList, 0);
                        DBG("UsbServer_AutoDetect: Selected MI_05 device! Path: %ws, PipeIn=0x%02X, PipeOut=0x%02X",
                            pszSelectedPath, *pPipeIn, *pPipeOut);
                        return STATUS_SUCCESS;
                    }
                    UserVar->Func.ZwClose(hDev);
                }
            }

            pCur += (curLen + 1);
        }

        UserVar->Func.ExFreePoolWithTag(pLinkList, 0);
    }

    if (!bQuiet)
    {
        DBG("UsbServer_AutoDetect: No MI_05 USB transport device found in system");
        ExceptionReporter_ReportFormat("UsbServer_AutoDetect", STATUS_DEVICE_NOT_CONNECTED,
            "No active WinUSB MI_05 device found in system");
    }
    return STATUS_DEVICE_NOT_CONNECTED;
}

NTSTATUS UsbServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ PMK_SERVER_START_PARAMS pParams)
{
    if (!UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_UsbServer.fRunning)
    {
        DBG("UsbServer_Init: USB server already running");
        return STATUS_ALREADY_COMMITTED;
    }

    UserVar->Func.RtlZeroMemory(&g_UsbServer, sizeof(MK_USB_SERVER));

    HANDLE hDev = NULL;
    PFILE_OBJECT pFileObj = NULL;
    UCHAR pipeIn = 0;
    UCHAR pipeOut = 0;
    NTSTATUS status = UsbServer_AutoDetectDeviceAndPipes(UserVar, pParams, &hDev, &pFileObj, &pipeIn, &pipeOut, g_UsbServer.DevicePath, 260, FALSE);

    if (!NT_SUCCESS(status))
    {
        DBG("UsbServer_Init: Auto-detect failed, status=0x%08X", status);
        if (Transport_GetLastErrorDesc()[0] == '\0')
        {
            Transport_SetLastErrorDesc("[USB:AutoDetect] No active WinUSB MI_05 candidate interface found");
        }
        return status;
    }

    g_UsbServer.hDevice = hDev;
    g_UsbServer.pFileObj = pFileObj;
    g_UsbServer.PipeIn = pipeIn;
    g_UsbServer.PipeOut = pipeOut;
    g_UsbServer.fHubMode = TRUE;

    // ★★★ 无头 MDL 物理页分配（零 PoolBigPageTable 登记，单槽 MDL 头部 2224B 落入 Small Pool）★★★
    g_UsbServer.pFastRecvBuf =
        UsbServer_AllocHeadlessBuffer(UserVar, USB_SERVER_SLOT_SIZE + PAGE_SIZE, &g_UsbServer.pFastRecvPagesMdl);
    g_UsbServer.pSendBufSlot[0] =
        UsbServer_AllocHeadlessBuffer(UserVar, USB_SERVER_SLOT_SIZE, &g_UsbServer.pSendPagesMdlSlot[0]);
    g_UsbServer.pSendBufSlot[1] =
        UsbServer_AllocHeadlessBuffer(UserVar, USB_SERVER_SLOT_SIZE, &g_UsbServer.pSendPagesMdlSlot[1]);
    g_UsbServer.pFastSendBuf = g_UsbServer.pSendBufSlot[0];

    if (!g_UsbServer.pFastRecvBuf || !g_UsbServer.pSendBufSlot[0] || !g_UsbServer.pSendBufSlot[1])
    {
        g_UsbServer.fHubMode = FALSE;
        UsbHub_Cleanup(UserVar);
        UsbServer_FreeFastBuffers(UserVar);
        if (g_UsbServer.pFileObj)
        {
            UserVar->Func.ObfDereferenceObject(g_UsbServer.pFileObj);
            g_UsbServer.pFileObj = NULL;
        }
        if (g_UsbServer.hDevice)
        {
            UserVar->Func.ZwClose(g_UsbServer.hDevice);
            g_UsbServer.hDevice = NULL;
        }
        Transport_SetLastErrorDesc("[USB:Memory] Insufficient headless MDL pages for FastBuf");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ★★★ 预构建常驻传输 MDL：与底层物理页所有权 MDL 解耦，提供合法 StartVa 供 USBXHCI DMA 散列构建 ★★★
    if (UserVar->Func.IoAllocateMdl && UserVar->Func.MmBuildMdlForNonPagedPool)
    {
        g_UsbServer.pFastRecvMdl = UserVar->Func.IoAllocateMdl(g_UsbServer.pFastRecvBuf, USB_SERVER_SLOT_SIZE, FALSE, FALSE, NULL);
        if (g_UsbServer.pFastRecvMdl)
            UserVar->Func.MmBuildMdlForNonPagedPool(g_UsbServer.pFastRecvMdl);

        g_UsbServer.pSendMdlSlot[0] = UserVar->Func.IoAllocateMdl(g_UsbServer.pSendBufSlot[0], USB_SERVER_SLOT_SIZE, FALSE, FALSE, NULL);
        if (g_UsbServer.pSendMdlSlot[0])
            UserVar->Func.MmBuildMdlForNonPagedPool(g_UsbServer.pSendMdlSlot[0]);

        g_UsbServer.pSendMdlSlot[1] = UserVar->Func.IoAllocateMdl(g_UsbServer.pSendBufSlot[1], USB_SERVER_SLOT_SIZE, FALSE, FALSE, NULL);
        if (g_UsbServer.pSendMdlSlot[1])
            UserVar->Func.MmBuildMdlForNonPagedPool(g_UsbServer.pSendMdlSlot[1]);
    }

    if (!UserVar->Func.ExQueueWorkItem)
    {
        g_UsbServer.fHubMode = FALSE;
        UsbHub_Cleanup(UserVar);
        UsbServer_FreeFastBuffers(UserVar);
        if (g_UsbServer.pFileObj)
        {
            UserVar->Func.ObfDereferenceObject(g_UsbServer.pFileObj);
            g_UsbServer.pFileObj = NULL;
        }
        if (g_UsbServer.hDevice)
        {
            UserVar->Func.ZwClose(g_UsbServer.hDevice);
            g_UsbServer.hDevice = NULL;
        }
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    UserVar->Func.KeInitializeEvent(&g_UsbServer.WorkerExitEvent, NotificationEvent, FALSE);
    g_UsbServer.fRunning = TRUE;
    g_UsbServer.WorkerItem.List.Flink = NULL;
    g_UsbServer.WorkerItem.WorkerRoutine = UsbServer_WorkerThread;
    g_UsbServer.WorkerItem.Parameter = (PVOID)UserVar;
    UserVar->Func.ExQueueWorkItem(&g_UsbServer.WorkerItem, DelayedWorkQueue);
    DBG("UsbServer_Init: USB Server started successfully (PipeIn=0x%02X, PipeOut=0x%02X)", g_UsbServer.PipeIn, g_UsbServer.PipeOut);

    return STATUS_SUCCESS;
}

VOID UsbServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar || !g_UsbServer.fRunning)
    {
        return;
    }

    DBG("UsbServer_Stop: Stopping USB Server...");
    g_UsbServer.fRunning = FALSE;

    if (g_UsbServer.PipeIn)
    {
        UsbServer_AbortPipe(UserVar, g_UsbServer.hDevice, g_UsbServer.PipeIn);
    }
    if (g_UsbServer.PipeOut)
    {
        UsbServer_AbortPipe(UserVar, g_UsbServer.hDevice, g_UsbServer.PipeOut);
    }

    if (g_UsbServer.WorkerItem.WorkerRoutine)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10 * 1000 * 5000;
        NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(&g_UsbServer.WorkerExitEvent, Executive, KernelMode, FALSE, &Timeout);
        if (waitStatus == STATUS_TIMEOUT)
        {
            DBG("UsbServer_Stop: WARNING: WorkerItem did not exit within 5s!");
        }
        else
        {
            DBG("UsbServer_Stop: WorkerItem exited cleanly");
        }
        g_UsbServer.WorkerItem.WorkerRoutine = NULL;
    }

    if (g_UsbServer.fHubMode)
    {
        g_UsbServer.fHubMode = FALSE;
        UsbHub_Cleanup(UserVar);
    }

    if (g_UsbServer.pFileObj)
    {
        UserVar->Func.ObfDereferenceObject(g_UsbServer.pFileObj);
        g_UsbServer.pFileObj = NULL;
    }

    if (g_UsbServer.hDevice)
    {
        UserVar->Func.ZwClose(g_UsbServer.hDevice);
        g_UsbServer.hDevice = NULL;
    }

    UsbServer_FreeFastBuffers(UserVar);

    g_UsbServer.Cached_hLC = NULL;
    g_UsbServer.Cached_dwRpcClientID = 0;
    DBG("UsbServer_Stop: USB Server stopped completely");
}

VOID UsbServer_GetStatus(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PULONG pActiveConnections, _Out_ PBOOLEAN pfRunning)
{
    UNREFERENCED_PARAMETER(UserVar);
    if (pActiveConnections)
    {
        *pActiveConnections = (ULONG)g_UsbServer.ActiveConnections;
    }
    if (pfRunning)
    {
        *pfRunning = g_UsbServer.fRunning;
    }
}
#else
typedef int dummy_usb_server_translation_unit;
#endif
