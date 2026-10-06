#include "usb_server.h"
#include "Common.h"
#include "transport_manager.h"
#include "rpc_dispatch.h"
#include "leechcore_kernel.h"
#include "usb_hub.h"


static const GUID GUID_DEVINTERFACE_USB3380_TRANSPORT = {
    0xF72FE0D4, 0xCBCB, 0x407d, {0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B}};


#define IOCTL_WINUSB_READ_PIPE 0x0350401E
#define IOCTL_WINUSB_WRITE_PIPE 0x03508021
#define IOCTL_WINUSB_FLUSH_PIPE 0x03504048
#define IOCTL_WINUSB_RESET_PIPE 0x0350C024
#define IOCTL_WINUSB_ABORT_PIPE 0x0350C028

#define NNG_CRYPT_KEY 0x8899AABBCCDDEEFFULL

MK_USB_SERVER g_UsbServer = {0};




static __forceinline VOID UsbNngFastCrypt(PUCHAR pbData, ULONG cbData, ULONG64 qwNonce)
{
    ULONG64 key = NNG_CRYPT_KEY ^ qwNonce;
    ULONG64 *pQ = (ULONG64 *)pbData;
    ULONG numQwords = cbData / 8;
    for (ULONG i = 0; i < numQwords; i++)
    {
        pQ[i] ^= key;
    }
    PUCHAR pB = (PUCHAR)&pQ[numQwords];
    ULONG rem = cbData % 8;
    for (ULONG i = 0; i < rem; i++)
    {
        pB[i] ^= (UCHAR)(key >> (i * 8));
    }
}





#pragma pack(push, 1)
typedef struct _WINUSB_PIPE_PARAM
{
    UCHAR InterfaceNumber; // 0x00: 接口编号 (必须为 0)
    UCHAR PipeId;          // 0x01: 管道端点 ID (例如 0x89, 0x08)
} WINUSB_PIPE_PARAM;
#pragma pack(pop)

static VOID UsbServer_AbortPipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ HANDLE hDev,
    _In_ UCHAR pipeId)
{
    if (!UserVar || !hDev)
    {
        return;
    }

    if (g_UsbServer.fHubMode)
    {
        BOOLEAN bIsIn = (pipeId & 0x80) != 0;
        MachenikePrint("UsbServer_AbortPipe: [USBHUB] Aborting Pipe 0x%02X...", pipeId);
        UsbHub_AbortPipe(UserVar, bIsIn);
        return;
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    if (pFileObj)
    {
        KeClearEvent(&pFileObj->Event);
    }
    IO_STATUS_BLOCK iosb = {0};
    WINUSB_PIPE_PARAM pipeParam = {0, pipeId};
    MachenikePrint("UsbServer_AbortPipe: Aborting Pipe 0x%02X...", pipeId);
    NTSTATUS status = UserVar->Func.ZwDeviceIoControlFile(hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_ABORT_PIPE,
                                                          &pipeParam, sizeof(pipeParam), NULL, 0);
    if (status == STATUS_PENDING)
    {
        if (pFileObj)
        {
            UserVar->Func.KeWaitForSingleObject(&pFileObj->Event, Executive, KernelMode, FALSE, NULL);
        }
    }
    UNREFERENCED_PARAMETER(status);
    MachenikePrint("UsbServer_AbortPipe: Pipe 0x%02X abort returned status=0x%08X, iosb.Status=0x%08X", pipeId, status, iosb.Status);
}

static NTSTATUS UsbServer_ReadPipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ HANDLE hDev,
    _In_ UCHAR pipeId,
    _Out_ PVOID pBuf,
    _In_ ULONG cbBuf,
    _Out_opt_ PULONG pcbRead)
{
    if (!UserVar || !hDev || !pBuf || cbBuf == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pcbRead)
    {
        *pcbRead = 0;
    }

    if (g_UsbServer.fHubMode && (hDev == g_UsbServer.hDevice))
    {
        return UsbHub_BulkRead(UserVar, pBuf, cbBuf, pcbRead);
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    BOOLEAN fNeedDeref = FALSE;

    if (!pFileObj)
    {
        NTSTATUS refStatus = UserVar->Func.ObReferenceObjectByHandle(
            hDev, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&pFileObj, NULL);
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

    NTSTATUS status = UserVar->Func.ZwDeviceIoControlFile(
        hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_READ_PIPE, &pipeParam, sizeof(pipeParam), pBuf, cbBuf);

    if (status == STATUS_PENDING)
    {
        if (pFileObj)
        {
            // 在异步句柄模式下等待底层 IRP 完成 (决不抛弃正在挂起的 IRP)
            // 当服务停止时，UsbServer_Stop 会并发调用 UsbServer_AbortPipe 取消该 IRP 并置位事件，返回 STATUS_CANCELLED
            status = UserVar->Func.KeWaitForSingleObject(
                &pFileObj->Event, Executive, KernelMode, FALSE, NULL);
            if (status == STATUS_SUCCESS)
            {
                status = iosb.Status;
            }
        }
    }

    if (fNeedDeref && pFileObj)
    {
        UserVar->Func.ObfDereferenceObject(pFileObj);
    }

    if (status == STATUS_SUCCESS)
    {
        if (pcbRead)
        {
            *pcbRead = (ULONG)iosb.Information;
        }
    }

    return status;
}

static NTSTATUS UsbServer_WritePipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ HANDLE hDev,
    _In_ UCHAR pipeId,
    _In_ PVOID pBuf,
    _In_ ULONG cbBuf,
    _Out_opt_ PULONG pcbWritten)
{
    if (!UserVar || !hDev || !pBuf || cbBuf == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pcbWritten)
    {
        *pcbWritten = 0;
    }

    if (g_UsbServer.fHubMode && (hDev == g_UsbServer.hDevice))
    {
        return UsbHub_BulkWrite(UserVar, pBuf, cbBuf, pcbWritten);
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    BOOLEAN fNeedDeref = FALSE;

    if (!pFileObj)
    {
        NTSTATUS refStatus = UserVar->Func.ObReferenceObjectByHandle(
            hDev, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&pFileObj, NULL);
        if (NT_SUCCESS(refStatus) && pFileObj)
        {
            fNeedDeref = TRUE;
        }
    }

    ULONG cbTotalWritten = 0;
    PUCHAR pCur = (PUCHAR)pBuf;
    NTSTATUS status = STATUS_SUCCESS;
    const ULONG CHUNK_SIZE = 1024 * 1024; // 1MB 安全分块传输

    while (cbTotalWritten < cbBuf && g_UsbServer.fRunning)
    {
        ULONG cbChunk = min(cbBuf - cbTotalWritten, CHUNK_SIZE);
        IO_STATUS_BLOCK iosb = {0};
        WINUSB_PIPE_PARAM pipeParam = {0, pipeId};

        if (pFileObj)
        {
            KeClearEvent(&pFileObj->Event);
        }

        status = UserVar->Func.ZwDeviceIoControlFile(
            hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_WRITE_PIPE,
            &pipeParam, sizeof(pipeParam), pCur + cbTotalWritten, cbChunk);

        if (status == STATUS_PENDING)
        {
            if (pFileObj)
            {
                status = UserVar->Func.KeWaitForSingleObject(
                    &pFileObj->Event, Executive, KernelMode, FALSE, NULL);
                if (status == STATUS_SUCCESS)
                {
                    status = iosb.Status;
                }
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

static VOID UsbServer_FlushPipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ HANDLE hDev,
    _In_ UCHAR pipeId)
{
    if (!UserVar || !hDev)
    {
        return;
    }

    if (g_UsbServer.fHubMode)
    {
        BOOLEAN bIsIn = (pipeId & 0x80) != 0;
        UsbHub_AbortPipe(UserVar, bIsIn);
        return;
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    if (pFileObj)
    {
        KeClearEvent(&pFileObj->Event);
    }
    IO_STATUS_BLOCK iosb = {0};
    WINUSB_PIPE_PARAM pipeParam = {0, pipeId};
    NTSTATUS status = UserVar->Func.ZwDeviceIoControlFile(hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_FLUSH_PIPE,
                                                          &pipeParam, sizeof(pipeParam), NULL, 0);
    if (status == STATUS_PENDING)
    {
        if (pFileObj)
        {
            UserVar->Func.KeWaitForSingleObject(&pFileObj->Event, Executive, KernelMode, FALSE, NULL);
        }
    }
}

static VOID UsbServer_ResetPipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ HANDLE hDev,
    _In_ UCHAR pipeId)
{
    if (!UserVar || !hDev)
    {
        return;
    }

    if (g_UsbServer.fHubMode)
    {
        BOOLEAN bIsIn = (pipeId & 0x80) != 0;
        UsbHub_ResetPipe(UserVar, bIsIn);
        return;
    }

    PFILE_OBJECT pFileObj = (g_UsbServer.hDevice == hDev && g_UsbServer.pFileObj) ? g_UsbServer.pFileObj : NULL;
    if (pFileObj)
    {
        KeClearEvent(&pFileObj->Event);
    }
    IO_STATUS_BLOCK iosb = {0};
    WINUSB_PIPE_PARAM pipeParam = {0, pipeId};
    NTSTATUS status = UserVar->Func.ZwDeviceIoControlFile(hDev, NULL, NULL, NULL, &iosb, IOCTL_WINUSB_RESET_PIPE,
                                                          &pipeParam, sizeof(pipeParam), NULL, 0);
    if (status == STATUS_PENDING)
    {
        if (pFileObj)
        {
            UserVar->Func.KeWaitForSingleObject(&pFileObj->Event, Executive, KernelMode, FALSE, NULL);
        }
    }
}

static NTSTATUS UsbServer_RecvExact(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ HANDLE hDev,
    _In_ UCHAR pipeId,
    _Out_ PUCHAR pBuf,
    _In_ ULONG cbExpected)
{
    if (!UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG cbTotal = 0;
    ULONG dwRetries = 0;

    while (cbTotal < cbExpected && g_UsbServer.fRunning)
    {
        ULONG cbRead = 0;
        NTSTATUS status = UsbServer_ReadPipe(UserVar, hDev, pipeId, pBuf + cbTotal, cbExpected - cbTotal, &cbRead);

        if (!NT_SUCCESS(status) || cbRead == 0)
        {
            dwRetries++;
            if (dwRetries > 2000 || !g_UsbServer.fRunning)
            {
                MachenikePrint("UsbServer_RecvExact: Receive incomplete! cbTotal=%u, cbExpected=%u, status=0x%08X",
                               cbTotal, cbExpected, status);
                return status;
            }
            LARGE_INTEGER Timeout;
            Timeout.QuadPart = -10 * 50; // 50 微秒微延时退避
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
            continue;
        }

        cbTotal += cbRead;
        dwRetries = 0;
    }

    return (cbTotal == cbExpected) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}






static VOID UsbServer_WorkerThread(_In_ PVOID Context)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = (MACHENIKE_KERNEL_INTERFACE *)Context;
    if (!UserVar)
    {
        return;
    }

    MachenikePrint("UsbServer_WorkerThread: Worker thread started, listening on PipeIn=0x%02X, PipeOut=0x%02X",
                   g_UsbServer.PipeIn, g_UsbServer.PipeOut);

    g_UsbServer.ActiveConnections = 1;

    UCHAR currentIn = g_UsbServer.PipeIn;
    UCHAR currentOut = g_UsbServer.PipeOut;

    // 启动前重置并刷新硬件端点与 FIFO，确保起步状态绝对干净
    UsbServer_ResetPipe(UserVar, g_UsbServer.hDevice, currentIn);
    UsbServer_ResetPipe(UserVar, g_UsbServer.hDevice, currentOut);
    UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
    UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentOut);

    while (g_UsbServer.fRunning)
    {
        ULONG cbFastRead = 0;
        // 坚守确定唯一的主端点 currentIn 读取完整帧 (Header + Payload)
        NTSTATUS status = UsbServer_ReadPipe(UserVar, g_UsbServer.hDevice, currentIn,
                                             g_UsbServer.pFastRecvBuf, USB_SERVER_FAST_BUF_SIZE, &cbFastRead);

        if (!NT_SUCCESS(status))
        {
            if (!g_UsbServer.fRunning)
            {
                break;
            }

            // 真正的异常错误代码 (非超时、非主动取消) 打印警告并进行毫秒级退避
            if (status != STATUS_IO_TIMEOUT && status != STATUS_TIMEOUT && status != STATUS_CANCELLED)
            {
                MachenikePrint("UsbServer_WorkerThread: ReadPipe on 0x%02X error status=0x%08X", currentIn, status);
                if (UserVar)
                {
                    LARGE_INTEGER Timeout;
                    Timeout.QuadPart = -10 * 1000 * 2; // 2ms 错误退避，避免异常时打满单个 CPU 核心
                    UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
                }
            }
            continue;
        }

        if (cbFastRead == 0)
        {
            continue;
        }

      //  MachenikePrint("UsbServer_WorkerThread: Received %u bytes on PipeIn=0x%02X", cbFastRead, currentIn);

        // 若读到的字节少于 12 字节 Header，补读至完整 Header
        if (cbFastRead < USB_SERVER_HEADER_SIZE)
        {
            status = UsbServer_RecvExact(UserVar, g_UsbServer.hDevice, currentIn,
                                         g_UsbServer.pFastRecvBuf + cbFastRead, USB_SERVER_HEADER_SIZE - cbFastRead);
            if (!NT_SUCCESS(status))
            {
                UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
                continue;
            }
            cbFastRead = USB_SERVER_HEADER_SIZE;
        }

        ULONG64 qwReqNonce = *(PULONG64)(g_UsbServer.pFastRecvBuf + 0);
        UNREFERENCED_PARAMETER(qwReqNonce);
        ULONG cbPayload = *(PULONG)(g_UsbServer.pFastRecvBuf + 8);

        if (cbPayload < sizeof(LEECHRPC_MSG_HDR) || cbPayload > USB_SERVER_MAX_MSG_SIZE)
        {
            MachenikePrint("UsbServer_WorkerThread: Invalid payload length %u, flushing pipe", cbPayload);
            UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
            continue;
        }

        BOOLEAN fAllocPayload = FALSE;
        PUCHAR pbPayload = NULL;
        ULONG cbAlreadyReadPayload = cbFastRead - USB_SERVER_HEADER_SIZE;
        if (cbAlreadyReadPayload > cbPayload)
        {
            cbAlreadyReadPayload = cbPayload;
        }

        if (cbPayload <= (USB_SERVER_FAST_BUF_SIZE - USB_SERVER_HEADER_SIZE))
        {
            // 绝大部分 RPC 请求已完全读入 pFastRecvBuf，直接零拷贝零分配指向！
            pbPayload = g_UsbServer.pFastRecvBuf + USB_SERVER_HEADER_SIZE;
            if (cbAlreadyReadPayload < cbPayload)
            {
                status = UsbServer_RecvExact(UserVar, g_UsbServer.hDevice, currentIn,
                                             pbPayload + cbAlreadyReadPayload, cbPayload - cbAlreadyReadPayload);
                if (!NT_SUCCESS(status))
                {
                    UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
                    continue;
                }
            }
        }
        else
        {
            // 超大报文扩容
            pbPayload = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, cbPayload, MK_USB_POOL_TAG);
            fAllocPayload = TRUE;
            if (!pbPayload)
            {
                MachenikePrint("UsbServer_WorkerThread: Failed to allocate %u bytes for payload", cbPayload);
                UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
                continue;
            }

            if (cbAlreadyReadPayload > 0)
            {
                UserVar->Func.RtlCopyMemory(pbPayload, g_UsbServer.pFastRecvBuf + USB_SERVER_HEADER_SIZE, cbAlreadyReadPayload);
            }
            if (cbAlreadyReadPayload < cbPayload)
            {
                status = UsbServer_RecvExact(UserVar, g_UsbServer.hDevice, currentIn,
                                             pbPayload + cbAlreadyReadPayload, cbPayload - cbAlreadyReadPayload);
                if (!NT_SUCCESS(status))
                {
                    UserVar->Func.ExFreePoolWithTag(pbPayload, MK_USB_POOL_TAG);
                    UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
                    continue;
                }
            }
        }

        PLEECHRPC_MSG_HDR pHdr = (PLEECHRPC_MSG_HDR)pbPayload;
        if (pHdr->dwMagic != LEECHRPC_MSGMAGIC)
        {
            MachenikePrint("UsbServer_WorkerThread: Magic mismatch 0x%08X (exp 0x%08X)",
                           pHdr->dwMagic, LEECHRPC_MSGMAGIC);
            if (fAllocPayload && pbPayload)
            {
                UserVar->Func.ExFreePoolWithTag(pbPayload, MK_USB_POOL_TAG);
            }
            UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentIn);
            continue;
        }

        PUCHAR pbRsp = NULL;
        ULONG cbRsp = 0;
        PUCHAR pbDirectOut = g_UsbServer.pFastSendBuf ? (g_UsbServer.pFastSendBuf + USB_SERVER_HEADER_SIZE) : NULL;
        ULONG cbDirectOutMax = g_UsbServer.pFastSendBuf ? (USB_SERVER_FAST_BUF_SIZE - USB_SERVER_HEADER_SIZE) : 0;

        //MachenikePrint("UsbServer_WorkerThread: Recv tpMsg=%u, cbMsg=%u, ClientId=%u",
        //               pHdr->tpMsg, pHdr->cbMsg, pHdr->dwRpcClientID);

        status = MkRpc_DispatchCommandEx(NULL, pbPayload, pHdr->cbMsg, &pbRsp, &cbRsp, pbDirectOut, cbDirectOutMax);

        if (fAllocPayload && pbPayload)
        {
            UserVar->Func.ExFreePoolWithTag(pbPayload, MK_USB_POOL_TAG);
        }
        pbPayload = NULL;
        fAllocPayload = FALSE;

        if (NT_SUCCESS(status) && pbRsp && cbRsp > 0)
        {
            ULONG64 qwRspNonce = __rdtsc();
            ULONG cbTotalSend = USB_SERVER_HEADER_SIZE + cbRsp;
            BOOLEAN fAllocSend = FALSE;
            PUCHAR pSendBuf = NULL;

            if (pbRsp == pbDirectOut)
            {
                pSendBuf = g_UsbServer.pFastSendBuf;
                *(PULONG64)(pSendBuf + 0) = qwRspNonce;
                *(PULONG)(pSendBuf + 8) = cbRsp;
            }
            else
            {
                if (g_UsbServer.pFastSendBuf && cbTotalSend <= USB_SERVER_FAST_BUF_SIZE)
                {
                    pSendBuf = g_UsbServer.pFastSendBuf;
                }
                else
                {
                    pSendBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(
                        NonPagedPoolNx, cbTotalSend, MK_USB_POOL_TAG);
                    fAllocSend = TRUE;
                }

                if (pSendBuf)
                {
                    *(PULONG64)(pSendBuf + 0) = qwRspNonce;
                    *(PULONG)(pSendBuf + 8) = cbRsp;
                    UserVar->Func.RtlCopyMemory(pSendBuf + USB_SERVER_HEADER_SIZE, pbRsp, cbRsp);
                }

                UserVar->Func.ExFreePoolWithTag(pbRsp, LC_POOL_TAG);
            }
            pbRsp = NULL;

            if (pSendBuf)
            {
                ULONG cbWritten = 0;
                status = UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, pSendBuf, cbTotalSend, &cbWritten);
               /* MachenikePrint("UsbServer_WorkerThread: Sent rsp for tpMsg=%u (%u/%u bytes, retStatus=0x%08X)",
                               pHdr->tpMsg, cbWritten, cbTotalSend, status);*/
                if (!NT_SUCCESS(status))
                {
                    MachenikePrint("UsbServer_WorkerThread: Failed to send response (%u bytes) on PipeOut=0x%02X, status=0x%08X",
                                   cbTotalSend, currentOut, status);
                    UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentOut);
                }
                else
                {
                    g_UsbServer.TotalRequestsHandled++;
                }

                if (fAllocSend && pSendBuf)
                {
                    UserVar->Func.ExFreePoolWithTag(pSendBuf, MK_USB_POOL_TAG);
                }
            }
        }
        else
        {
            if (pbRsp && pbRsp != pbDirectOut)
            {
                UserVar->Func.ExFreePoolWithTag(pbRsp, LC_POOL_TAG);
                pbRsp = NULL;
            }

            LEECHRPC_MSG_HDR hdrErr = {0};
            hdrErr.dwMagic = LEECHRPC_MSGMAGIC;
            hdrErr.cbMsg = sizeof(LEECHRPC_MSG_HDR);
            hdrErr.fMsgResult = FALSE;

            ULONG64 qwRspNonce = __rdtsc();
            ULONG cbErrTotal = USB_SERVER_HEADER_SIZE + sizeof(hdrErr);
            UCHAR errFrame[USB_SERVER_HEADER_SIZE + sizeof(hdrErr)] = {0};
            *(PULONG64)(errFrame + 0) = qwRspNonce;
            *(PULONG)(errFrame + 8) = sizeof(hdrErr);
            UserVar->Func.RtlCopyMemory(errFrame + USB_SERVER_HEADER_SIZE, &hdrErr, sizeof(hdrErr));

            ULONG cbWritten = 0;
            status = UsbServer_WritePipe(UserVar, g_UsbServer.hDevice, currentOut, errFrame, cbErrTotal, &cbWritten);
            if (!NT_SUCCESS(status))
            {
                UsbServer_FlushPipe(UserVar, g_UsbServer.hDevice, currentOut);
            }
        }
    }

    g_UsbServer.ActiveConnections = 0;
    MachenikePrint("UsbServer_WorkerThread: Exited");

    if (UserVar)
    {
        UserVar->Func.PsTerminateSystemThread(STATUS_SUCCESS);
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
        if ((p[0] == L'm' || p[0] == L'M') &&
            (p[1] == L'i' || p[1] == L'I') &&
            (p[2] == L'_') &&
            (p[3] == L'0') &&
            (p[4] == L'5'))
        {
            return TRUE;
        }
    }
    return FALSE;
}

#define IOCTL_WINUSB_GET_DESCRIPTOR 0x0350C004

#pragma pack(push, 1)
typedef struct _WINUSB_DESCRIPTOR_REQUEST {
    UCHAR  DescriptorType; // 0x02 = USB_CONFIGURATION_DESCRIPTOR_TYPE
    UCHAR  Index;
    USHORT LanguageID;
} WINUSB_DESCRIPTOR_REQUEST, *PWINUSB_DESCRIPTOR_REQUEST;

typedef struct _USB_CONFIGURATION_DESCRIPTOR_HEADER {
    UCHAR  bLength;
    UCHAR  bDescriptorType;
    USHORT wTotalLength;
    UCHAR  bNumInterfaces;
    UCHAR  bConfigurationValue;
    UCHAR  iConfiguration;
    UCHAR  bmAttributes;
    UCHAR  MaxPower;
} USB_CONFIGURATION_DESCRIPTOR_HEADER, *PUSB_CONFIGURATION_DESCRIPTOR_HEADER;

typedef struct _USB_ENDPOINT_DESCRIPTOR_RAW {
    UCHAR  bLength;
    UCHAR  bDescriptorType;
    UCHAR  bEndpointAddress;
    UCHAR  bmAttributes;
    USHORT wMaxPacketSize;
    UCHAR  bInterval;
} USB_ENDPOINT_DESCRIPTOR_RAW, *PUSB_ENDPOINT_DESCRIPTOR_RAW;
#pragma pack(pop)

static NTSTATUS UsbServer_QueryDeviceEndpoints(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ HANDLE hDev,
    _Out_ PUCHAR pPipeIn,
    _Out_ PUCHAR pPipeOut)
{
    if (!UserVar || !hDev || !pPipeIn || !pPipeOut)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *pPipeIn = 0;
    *pPipeOut = 0;

    // 1. 请求配置描述符头部以获取总长度
    WINUSB_DESCRIPTOR_REQUEST req = {0};
    req.DescriptorType = 0x02; // USB_CONFIGURATION_DESCRIPTOR_TYPE
    req.Index = 0;
    req.LanguageID = 0;

    USB_CONFIGURATION_DESCRIPTOR_HEADER cfgHeader = {0};
    IO_STATUS_BLOCK iosb = {0};

    NTSTATUS status = UserVar->Func.ZwDeviceIoControlFile(
        hDev, NULL, NULL, NULL, &iosb,
        IOCTL_WINUSB_GET_DESCRIPTOR,
        &req, sizeof(req),
        &cfgHeader, sizeof(cfgHeader));

    if (status == STATUS_PENDING)
    {
        PFILE_OBJECT pFileObj = NULL;
        NTSTATUS refStatus = UserVar->Func.ObReferenceObjectByHandle(
            hDev, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&pFileObj, NULL);
        if (NT_SUCCESS(refStatus) && pFileObj)
        {
            LARGE_INTEGER Timeout;
            Timeout.QuadPart = -10 * 1000 * 500; // 500ms 超时
            status = UserVar->Func.KeWaitForSingleObject(
                &pFileObj->Event, Executive, KernelMode, FALSE, &Timeout);
            if (status == STATUS_SUCCESS)
            {
                status = iosb.Status;
            }
            UserVar->Func.ObfDereferenceObject(pFileObj);
        }
    }

    if (!NT_SUCCESS(status) || cfgHeader.bDescriptorType != 0x02 || cfgHeader.wTotalLength < sizeof(cfgHeader))
    {
        MachenikePrint("UsbServer_QueryEndpoints: Failed to query config descriptor header, status=0x%08X (using fallback PipeIn=0x89, PipeOut=0x08)", status);
        *pPipeIn = 0x89;
        *pPipeOut = 0x08;
        return STATUS_SUCCESS;
    }

    ULONG totalLen = cfgHeader.wTotalLength;
    if (totalLen > 4096)
    {
        totalLen = 4096;
    }

    MachenikePrint("UsbServer_QueryEndpoints: Configuration total length = %u bytes, interfaces = %u",
                   totalLen, cfgHeader.bNumInterfaces);

    // 2. 读取完整的配置描述符集合
    PUCHAR pDescBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, totalLen, MK_USB_POOL_TAG);
    if (!pDescBuf)
    {
        *pPipeIn = 0x89;
        *pPipeOut = 0x08;
        return STATUS_SUCCESS;
    }

    UserVar->Func.RtlZeroMemory(&iosb, sizeof(iosb));
    status = UserVar->Func.ZwDeviceIoControlFile(
        hDev, NULL, NULL, NULL, &iosb,
        IOCTL_WINUSB_GET_DESCRIPTOR,
        &req, sizeof(req),
        pDescBuf, totalLen);

    if (status == STATUS_PENDING)
    {
        PFILE_OBJECT pFileObj = NULL;
        NTSTATUS refStatus = UserVar->Func.ObReferenceObjectByHandle(
            hDev, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&pFileObj, NULL);
        if (NT_SUCCESS(refStatus) && pFileObj)
        {
            LARGE_INTEGER Timeout;
            Timeout.QuadPart = -10 * 1000 * 500; // 500ms 超时
            status = UserVar->Func.KeWaitForSingleObject(
                &pFileObj->Event, Executive, KernelMode, FALSE, &Timeout);
            if (status == STATUS_SUCCESS)
            {
                status = iosb.Status;
            }
            UserVar->Func.ObfDereferenceObject(pFileObj);
        }
    }

    if (!NT_SUCCESS(status))
    {
        MachenikePrint("UsbServer_QueryEndpoints: Failed to read full config descriptors, status=0x%08X (using fallback 0x89/0x08)", status);
        UserVar->Func.ExFreePoolWithTag(pDescBuf, MK_USB_POOL_TAG);
        *pPipeIn = 0x89;
        *pPipeOut = 0x08;
        return STATUS_SUCCESS;
    }

    // 3. 遍历解析所有的端点描述符 (bDescriptorType == 0x05)
    PUCHAR pCur = pDescBuf;
    PUCHAR pEnd = pDescBuf + totalLen;
    UCHAR inList[8] = {0};
    UCHAR outList[8] = {0};
    ULONG inCount = 0;
    ULONG outCount = 0;
    ULONG epIndex = 0;
    UNREFERENCED_PARAMETER(epIndex);

    while (pCur + 2 <= pEnd)
    {
        UCHAR bLength = pCur[0];
        UCHAR bDescType = pCur[1];

        if (bLength < 2 || pCur + bLength > pEnd)
        {
            break;
        }

        if (bDescType == 0x05 && bLength >= sizeof(USB_ENDPOINT_DESCRIPTOR_RAW))
        {
            PUSB_ENDPOINT_DESCRIPTOR_RAW pEp = (PUSB_ENDPOINT_DESCRIPTOR_RAW)pCur;
            UCHAR epType = pEp->bmAttributes & 0x03; // 0=Control, 1=Isoch, 2=Bulk, 3=Interrupt
            BOOLEAN isInput = (pEp->bEndpointAddress & 0x80) != 0;

            MachenikePrint("UsbServer_QueryEndpoints: Endpoint #%u: ID=0x%02X (%s), Type=0x%02X (%s), MaxPacket=%u",
                           epIndex++,
                           pEp->bEndpointAddress,
                           isInput ? "IN" : "OUT",
                           epType,
                           (epType == 2) ? "BULK" : ((epType == 3) ? "INTERRUPT" : "OTHER"),
                           pEp->wMaxPacketSize);

            if (epType == 2)
            {
                if (isInput && inCount < 8)
                {
                    inList[inCount++] = pEp->bEndpointAddress;
                }
                else if (!isInput && outCount < 8)
                {
                    outList[outCount++] = pEp->bEndpointAddress;
                }
            }
        }

        pCur += bLength;
    }

    UserVar->Func.ExFreePoolWithTag(pDescBuf, MK_USB_POOL_TAG);

    if (inCount > 0 && outCount > 0)
    {
        *pPipeIn = inList[0];
        *pPipeOut = outList[0];
        MachenikePrint("UsbServer_QueryEndpoints: Successfully matched hardware Bulk endpoints: PipeIn=0x%02X, PipeOut=0x%02X",
                       *pPipeIn, *pPipeOut);
        return STATUS_SUCCESS;
    }

    MachenikePrint("UsbServer_QueryEndpoints: Bi-directional Bulk pair not fully parsed, applying standard MI_05 bulk endpoints (PipeIn=0x89, PipeOut=0x08)");
    *pPipeIn = 0x89;
    *pPipeOut = 0x08;
    return STATUS_SUCCESS;
}

static BOOLEAN UsbServer_ContainsSubstrCaseless(
    _In_reads_(cchStr) PCWSTR pszStr,
    _In_ ULONG cchStr,
    _In_ PCWSTR pszSub)
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
            if (c1 >= L'a' && c1 <= L'z') c1 -= 32;
            if (c2 >= L'a' && c2 <= L'z') c2 -= 32;
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

static BOOLEAN UsbServer_IsWinUsbDriver(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ HANDLE hDev)
{
    if (!UserVar || !hDev)
    {
        return FALSE;
    }

    PFILE_OBJECT pFileObj = NULL;
    NTSTATUS status = UserVar->Func.ObReferenceObjectByHandle(
        hDev, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&pFileObj, NULL);

    if (!NT_SUCCESS(status) || !pFileObj)
    {
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
                MachenikePrint("UsbServer_IsWinUsbDriver: Verified device handled by WinUSB driver (%wZ)", &drvName);
                break;
            }
        }
        pDev = pDev->AttachedDevice;
    }

    UserVar->Func.ObfDereferenceObject(pFileObj);
    return bIsWinUsb;
}

static NTSTATUS UsbServer_AutoDetectDeviceAndPipes(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_opt_ PMK_SERVER_START_PARAMS pParams,
    _Out_ PHANDLE phDevice,
    _Out_ PUCHAR pPipeIn,
    _Out_ PUCHAR pPipeOut,
    _Out_writes_(cchMaxPath) PWSTR pszSelectedPath,
    _In_ ULONG cchMaxPath)
{
    if (!UserVar || !phDevice || !pPipeIn || !pPipeOut || !pszSelectedPath || cchMaxPath == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 1. 若外部显式传入指定 DevicePath 则优先打开
    if (pParams && pParams->DevicePath[0] != L'\0')
    {
        MachenikePrint("UsbServer_AutoDetect: Using explicitly specified DevicePath: %ws", pParams->DevicePath);
        UNICODE_STRING ustrExplicit;
        UserVar->Func.RtlInitUnicodeString(&ustrExplicit, pParams->DevicePath);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &ustrExplicit, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        IO_STATUS_BLOCK iosb = {0};
        HANDLE hDev = NULL;
        NTSTATUS status = UserVar->Func.ZwCreateFile(
            &hDev,
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            0);

        if (NT_SUCCESS(status))
        {
            if (!UsbServer_IsWinUsbDriver(UserVar, hDev))
            {
                MachenikePrint("UsbServer_AutoDetect: Explicit device %ws is NOT handled by WinUSB driver, falling back...", pParams->DevicePath);
                UserVar->Func.ZwClose(hDev);
                hDev = NULL;
            }
            else
            {
                UCHAR queriedIn = 0;
                UCHAR queriedOut = 0;
                NTSTATUS epStatus = UsbServer_QueryDeviceEndpoints(UserVar, hDev, &queriedIn, &queriedOut);
                if (!NT_SUCCESS(epStatus) || queriedIn == 0 || queriedOut == 0)
                {
                    MachenikePrint("UsbServer_AutoDetect: Explicit device %ws has no valid WinUSB Bulk endpoints, falling back...", pParams->DevicePath);
                    UserVar->Func.ZwClose(hDev);
                    hDev = NULL;
                }
                else
                {
                    *phDevice = hDev;
                    *pPipeIn = (pParams && pParams->PipeIn != 0) ? pParams->PipeIn : queriedIn;
                    *pPipeOut = (pParams && pParams->PipeOut != 0) ? pParams->PipeOut : queriedOut;

                    ULONG copyLen = 0;
                    while (pParams->DevicePath[copyLen] != L'\0' && copyLen < cchMaxPath - 1)
                    {
                        pszSelectedPath[copyLen] = pParams->DevicePath[copyLen];
                        copyLen++;
                    }
                    pszSelectedPath[copyLen] = L'\0';

                    MachenikePrint("UsbServer_AutoDetect: Opened explicit WinUSB device successfully! PipeIn=0x%02X, PipeOut=0x%02X",
                                   *pPipeIn, *pPipeOut);
                    return STATUS_SUCCESS;
                }
            }
        }
        else
        {
            MachenikePrint("UsbServer_AutoDetect: Failed to open explicit device: 0x%08X, falling back to scanning...", status);
        }
    }

    // 2. 遍历系统设备接口，专门匹配 MI_05 接口
    // 优先使用当前设备绑定的 Zadig 专属 GUID，确保驱动与应用层选择同一个专属接口
    static const GUID guidZadigCustom = {
        0xBC103702, 0xDD72, 0x406F, {0x9B, 0x28, 0x95, 0xC8, 0x68, 0x33, 0x7B, 0x59}};
    static const GUID guidWinUsbGeneric = {
        0xDEE824EF, 0x729B, 0x4A0E, {0x9C, 0x14, 0xB7, 0x11, 0x7D, 0x33, 0xA8, 0x17}};
    static const GUID guidUsb3380 = {
        0xF72FE0D4, 0xCBCB, 0x407d, {0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B}};
    static const GUID guidWinUsbTest = {
        0xDA812BFF, 0x12C3, 0x46A2, {0x8E, 0x2B, 0xDB, 0xD3, 0xB7, 0x83, 0x4C, 0x43}};

    const GUID *targetGuids[] = {
        &guidZadigCustom,
        &guidWinUsbGeneric,
        &guidUsb3380,
        &guidWinUsbTest};

    MachenikePrint("UsbServer_AutoDetect: Scanning device interfaces for MI_05 (WinUSB filtered, active only)...");

    for (ULONG g = 0; g < sizeof(targetGuids) / sizeof(targetGuids[0]); g++)
    {
        PWSTR pLinkList = NULL;
        // 使用 DEVICE_INTERFACE_ACTIVE (0x01) 确保只枚举当前物理连接的有效活动设备 (对标应用层 DIGCF_PRESENT)，排除已断开的历史旧端口幽灵设备
        NTSTATUS ifStatus = UserVar->Func.IoGetDeviceInterfaces(targetGuids[g], NULL, 0x00000001, &pLinkList);
        if (!NT_SUCCESS(ifStatus) || !pLinkList)
        {
            // 若未找到活动设备，兜底尝试全量枚举
            ifStatus = UserVar->Func.IoGetDeviceInterfaces(targetGuids[g], NULL, 0, &pLinkList);
            if (!NT_SUCCESS(ifStatus) || !pLinkList)
            {
                continue;
            }
        }

        for (PWSTR pCur = pLinkList; *pCur != L'\0'; )
        {
            ULONG curLen = 0;
            while (pCur[curLen] != L'\0')
            {
                curLen++;
            }

            // 必须且仅匹配包含 mi_05 (不区分大小写) 的设备接口
            if (UsbServer_IsMi05Device(pCur))
            {
                MachenikePrint("UsbServer_AutoDetect: Found MI_05 candidate: %ws", pCur);
                MachenikePrint("UsbServer_AutoDetect: Opening device handle (IRQL=%u)...", (ULONG)KeGetCurrentIrql());

                UNICODE_STRING ustrDevice;
                UserVar->Func.RtlInitUnicodeString(&ustrDevice, pCur);

                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, &ustrDevice, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                IO_STATUS_BLOCK iosb = {0};
                HANDLE hDev = NULL;
                // 以原生异步模式打开设备，杜绝 I/O 管理器 FileObject 同步锁导致的跨线程 AbortPipe 死锁
                NTSTATUS status = UserVar->Func.ZwCreateFile(
                    &hDev,
                    GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                    &oa,
                    &iosb,
                    NULL,
                    FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE,
                    NULL,
                    0);

                MachenikePrint("UsbServer_AutoDetect: Synchronous ZwCreateFile returned status=0x%08X, iosb.Status=0x%08X, hDev=%p",
                               status, iosb.Status, hDev);

                if (NT_SUCCESS(status))
                {
                    // 严格过滤 1: 底层设备驱动对象必须是 WINUSB，过滤其它驱动 (如串口/HID/第三方驱动)
                    if (!UsbServer_IsWinUsbDriver(UserVar, hDev))
                    {
                        MachenikePrint("UsbServer_AutoDetect: Candidate %ws is NOT handled by WinUSB driver, FILTERED OUT!", pCur);
                        UserVar->Func.ZwClose(hDev);
                        hDev = NULL;
                        pCur += (curLen + 1);
                        continue;
                    }

                    // 严格过滤 2: 必须能成功查询并匹配到真实的硬件 Bulk IN 和 Bulk OUT 端点
                    UCHAR queriedIn = 0;
                    UCHAR queriedOut = 0;
                    NTSTATUS epStatus = UsbServer_QueryDeviceEndpoints(UserVar, hDev, &queriedIn, &queriedOut);
                    if (!NT_SUCCESS(epStatus) || queriedIn == 0 || queriedOut == 0)
                    {
                        MachenikePrint("UsbServer_AutoDetect: Candidate %ws does NOT have valid Bulk endpoints (status=0x%08X), FILTERED OUT!",
                                       pCur, epStatus);
                        UserVar->Func.ZwClose(hDev);
                        hDev = NULL;
                        pCur += (curLen + 1);
                        continue;
                    }

                    // 双重过滤通过，确认为合法的 WinUSB 数据传输设备
                    *phDevice = hDev;
                    *pPipeIn = (pParams && pParams->PipeIn != 0) ? pParams->PipeIn : queriedIn;
                    *pPipeOut = (pParams && pParams->PipeOut != 0) ? pParams->PipeOut : queriedOut;

                    MachenikePrint("UsbServer_AutoDetect: Selected verified WinUSB device: PipeIn=0x%02X, PipeOut=0x%02X",
                                   *pPipeIn, *pPipeOut);

                    ULONG copyLen = (curLen < cchMaxPath - 1) ? curLen : (cchMaxPath - 1);
                    for (ULONG k = 0; k < copyLen; k++)
                    {
                        pszSelectedPath[k] = pCur[k];
                    }
                    pszSelectedPath[copyLen] = L'\0';

                    UserVar->Func.ExFreePoolWithTag(pLinkList, 0);

                    MachenikePrint("UsbServer_AutoDetect: Selected MI_05 device successfully! Path: %ws, PipeIn=0x%02X, PipeOut=0x%02X",
                                   pszSelectedPath, *pPipeIn, *pPipeOut);
                    return STATUS_SUCCESS;
                }
                else
                {
                    MachenikePrint("UsbServer_AutoDetect: Failed to open MI_05 candidate, status=0x%08X", status);
                }
            }

            pCur += (curLen + 1);
        }

        UserVar->Func.ExFreePoolWithTag(pLinkList, 0);
    }

    MachenikePrint("UsbServer_AutoDetect: No MI_05 USB transport device found in system");
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
        MachenikePrint("UsbServer_Init: USB server already running");
        return STATUS_ALREADY_COMMITTED;
    }

    UserVar->Func.RtlZeroMemory(&g_UsbServer, sizeof(MK_USB_SERVER));

    HANDLE hDev = NULL;
    UCHAR pipeIn = 0;
    UCHAR pipeOut = 0;
    NTSTATUS status = UsbServer_AutoDetectDeviceAndPipes(
        UserVar, pParams, &hDev, &pipeIn, &pipeOut, g_UsbServer.DevicePath, 260);

    if (!NT_SUCCESS(status))
    {
        MachenikePrint("UsbServer_Init: Auto-detect failed, status=0x%08X", status);
        return status;
    }

    g_UsbServer.hDevice = hDev;
    // 一次性长效持有 FileObject 与底层设备对象引用，消灭每次 I/O 频繁 ObReference/Dereference 开销
    UserVar->Func.ObReferenceObjectByHandle(
        g_UsbServer.hDevice, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID *)&g_UsbServer.pFileObj, NULL);

    g_UsbServer.PipeIn = pipeIn;
    g_UsbServer.PipeOut = pipeOut;

    g_UsbServer.pFastRecvBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, USB_SERVER_FAST_BUF_SIZE, MK_USB_POOL_TAG);
    g_UsbServer.pFastSendBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, USB_SERVER_FAST_BUF_SIZE, MK_USB_POOL_TAG);

    g_UsbServer.fRunning = TRUE;
    MachenikePrint("UsbServer_Init: Creating worker thread...");

    if (g_UsbServer.pFileObj && g_UsbServer.pFileObj->DeviceObject)
    {
        NTSTATUS hubStatus = UsbHub_Init(
            UserVar,
            g_UsbServer.pFileObj->DeviceObject,
            g_UsbServer.PipeIn,
            g_UsbServer.PipeOut);
        if (NT_SUCCESS(hubStatus))
        {
            g_UsbServer.fHubMode = TRUE;
            MachenikePrint("UsbServer_Init: USB Hub mode initialized");
        }
        else
        {
            g_UsbServer.fHubMode = FALSE;
            MachenikePrint("UsbServer_Init: USB Hub init failed (0x%08X)", hubStatus);
#if defined(USBHUB3_STRICT_MODE) && (USBHUB3_STRICT_MODE != 0)
            g_UsbServer.fRunning = FALSE;
            if (g_UsbServer.pFastRecvBuf)
            {
                UserVar->Func.ExFreePoolWithTag(g_UsbServer.pFastRecvBuf, MK_USB_POOL_TAG);
                g_UsbServer.pFastRecvBuf = NULL;
            }
            if (g_UsbServer.pFastSendBuf)
            {
                UserVar->Func.ExFreePoolWithTag(g_UsbServer.pFastSendBuf, MK_USB_POOL_TAG);
                g_UsbServer.pFastSendBuf = NULL;
            }
            if (g_UsbServer.pFileObj)
            {
                UserVar->Func.ObfDereferenceObject(g_UsbServer.pFileObj);
                g_UsbServer.pFileObj = NULL;
            }
            UserVar->Func.ZwClose(g_UsbServer.hDevice);
            g_UsbServer.hDevice = NULL;
            return hubStatus;
#endif
        }
    }
    else
    {
#if defined(USBHUB3_STRICT_MODE) && (USBHUB3_STRICT_MODE != 0)
        g_UsbServer.fRunning = FALSE;
        if (g_UsbServer.pFastRecvBuf)
        {
            UserVar->Func.ExFreePoolWithTag(g_UsbServer.pFastRecvBuf, MK_USB_POOL_TAG);
            g_UsbServer.pFastRecvBuf = NULL;
        }
        if (g_UsbServer.pFastSendBuf)
        {
            UserVar->Func.ExFreePoolWithTag(g_UsbServer.pFastSendBuf, MK_USB_POOL_TAG);
            g_UsbServer.pFastSendBuf = NULL;
        }
        if (g_UsbServer.pFileObj)
        {
            UserVar->Func.ObfDereferenceObject(g_UsbServer.pFileObj);
            g_UsbServer.pFileObj = NULL;
        }
        UserVar->Func.ZwClose(g_UsbServer.hDevice);
        g_UsbServer.hDevice = NULL;
        return STATUS_DEVICE_NOT_READY;
#endif
    }

    status = UserVar->Func.PsCreateSystemThread(
        &g_UsbServer.hWorkerThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, UsbServer_WorkerThread, (PVOID)UserVar);

    if (NT_SUCCESS(status))
    {
        UserVar->Func.ObReferenceObjectByHandle(
            g_UsbServer.hWorkerThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
            (PVOID *)&g_UsbServer.pWorkerThread, NULL);
        MachenikePrint("UsbServer_Init: USB Server started successfully (PipeIn=0x%02X, PipeOut=0x%02X)",
                       g_UsbServer.PipeIn, g_UsbServer.PipeOut);
    }
    else
    {
        MachenikePrint("UsbServer_Init: Failed to create WorkerThread, status=0x%08X", status);
        g_UsbServer.fRunning = FALSE;
        if (g_UsbServer.pFastRecvBuf)
        {
            UserVar->Func.ExFreePoolWithTag(g_UsbServer.pFastRecvBuf, MK_USB_POOL_TAG);
            g_UsbServer.pFastRecvBuf = NULL;
        }
        if (g_UsbServer.pFastSendBuf)
        {
            UserVar->Func.ExFreePoolWithTag(g_UsbServer.pFastSendBuf, MK_USB_POOL_TAG);
            g_UsbServer.pFastSendBuf = NULL;
        }
        if (g_UsbServer.pFileObj)
        {
            UserVar->Func.ObfDereferenceObject(g_UsbServer.pFileObj);
            g_UsbServer.pFileObj = NULL;
        }
        UserVar->Func.ZwClose(g_UsbServer.hDevice);
        g_UsbServer.hDevice = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}


VOID UsbServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar || !g_UsbServer.fRunning)
    {
        return;
    }

    MachenikePrint("UsbServer_Stop: Stopping USB Server...");
    g_UsbServer.fRunning = FALSE;

    if (g_UsbServer.PipeIn)
    {
        UsbServer_AbortPipe(UserVar, g_UsbServer.hDevice, g_UsbServer.PipeIn);
    }
    if (g_UsbServer.PipeOut)
    {
        UsbServer_AbortPipe(UserVar, g_UsbServer.hDevice, g_UsbServer.PipeOut);
    }

    // 2. 等待 WorkerThread 完全退出，确保工作线程不再执行驱动内任何代码
    if (g_UsbServer.pWorkerThread)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10 * 1000 * 5000; // 5 秒安全超时
        NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(
            g_UsbServer.pWorkerThread, Executive, KernelMode, FALSE, &Timeout);
        if (waitStatus == STATUS_TIMEOUT)
        {
            MachenikePrint("UsbServer_Stop: WARNING: WorkerThread did not exit within 5s!");
        }
        else
        {
            MachenikePrint("UsbServer_Stop: WorkerThread exited cleanly");
        }
        UserVar->Func.ObDereferenceObject(g_UsbServer.pWorkerThread);
        g_UsbServer.pWorkerThread = NULL;
    }

    if (g_UsbServer.hWorkerThread)
    {
        UserVar->Func.ZwClose(g_UsbServer.hWorkerThread);
        g_UsbServer.hWorkerThread = NULL;
    }

    if (g_UsbServer.fHubMode)
    {
        g_UsbServer.fHubMode = FALSE;
        UsbHub_Cleanup(UserVar);
    }

    // 线程退出后再安全释放 FileObject 引用并关闭设备句柄
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

    if (g_UsbServer.pFastRecvBuf)
    {
        UserVar->Func.ExFreePoolWithTag(g_UsbServer.pFastRecvBuf, MK_USB_POOL_TAG);
        g_UsbServer.pFastRecvBuf = NULL;
    }
    if (g_UsbServer.pFastSendBuf)
    {
        UserVar->Func.ExFreePoolWithTag(g_UsbServer.pFastSendBuf, MK_USB_POOL_TAG);
        g_UsbServer.pFastSendBuf = NULL;
    }
    MachenikePrint("UsbServer_Stop: USB Server stopped completely");
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
