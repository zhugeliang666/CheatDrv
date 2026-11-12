#include "Common.h"
#include "Struct.h"
#include "usb_hub.h"
#include "usb_server.h"

#if ENABLE_TRANSPORT_MODES
static MACHENIKE_KERNEL_INTERFACE *g_pUsbHubUserVar = NULL;
static PDEVICE_OBJECT g_pWinUsbFdo = NULL;
static PDEVICE_OBJECT g_pLowerDev = NULL;
static PDEVICE_OBJECT g_pHubPdo = NULL;
static PDEVICE_OBJECT g_pUcxRootHubPdo = NULL;
static PDEVICE_OBJECT g_pTargetPdo = NULL;
static PVOID g_UcxUsbDeviceHandle = NULL;
static USBD_PIPE_HANDLE g_PipeHandleIn = NULL;
static USBD_PIPE_HANDLE g_PipeHandleOut = NULL;
static UCHAR g_EpIn = 0;
static UCHAR g_EpOut = 0;
static BOOLEAN g_HubReady = FALSE;
static PDRIVER_DISPATCH g_pUsbOriginalDispatch = NULL;
volatile ULONG g_UsbHubLastUsbdStatus = 0;

// ★★★ 全双工重叠 I/O 常驻资源：0 动态池分配、0 动态 IRP 申请 ★★★
static PIRP g_pHubRecvIrp = NULL;
static KEVENT g_HubRecvEvent;

typedef struct _HUB_SEND_SLOT
{
    PIRP pIrp;
    KEVENT Event;
    struct _URB_BULK_OR_INTERRUPT_TRANSFER Urb;
    BOOLEAN bInFlight;
} HUB_SEND_SLOT;

static HUB_SEND_SLOT g_HubSendSlots[2] = {0};

#ifdef MmIsAddressValid
#undef MmIsAddressValid
#endif
#define MmIsAddressValid(va)                                                                                                               \
    ((g_pUsbHubUserVar && g_pUsbHubUserVar->Func.MmIsAddressValid) ? g_pUsbHubUserVar->Func.MmIsAddressValid((PVOID)(va)) : FALSE)

static BOOLEAN UsbHub_ContainsSubstrCaseless(_In_reads_(cchStr) PCWSTR pszStr, _In_ ULONG cchStr, _In_ PCWSTR pszSub)
{
    if (!pszStr || !pszSub || cchStr == 0)
        return FALSE;
    ULONG subLen = 0;
    while (pszSub[subLen] != L'\0')
        subLen++;
    if (subLen == 0 || subLen > cchStr)
        return FALSE;

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
            return TRUE;
    }
    return FALSE;
}

/*
 * UsbHub_IsValidUcxPipeHandle — 校验候选指针是否为合法的 UCX / USBD_PIPE_HANDLE 结构
 *
 * 逆向依据 (ucx01000!Endpoint_Create & Urb_USBPORTStyle_ProcessURB):
 *   - [PipeHandle - 0x10] == 'Endp' (0x70646E45)
 *   - [PipeHandle + 0x08] == 0 (bIsStreamPipe == FALSE)
 *   - [PipeHandle + 0x0C] == 2 (UsbdPipeTypeBulk)
 *   - [PipeHandle + 0x20] == PipeHandle (自引用校验，Urb_USBPORTStyle_ProcessURB 强校验项)
 */
static BOOLEAN UsbHub_IsValidUcxPipeHandle(_In_ ULONG_PTR raw)
{
    if (raw < 0xFFFF800000000000ULL || (raw & 0x7) != 0)
        return FALSE;

    PUCHAR pPipe = (PUCHAR)raw;
    if (!MmIsAddressValid(pPipe - 0x10) || !MmIsAddressValid(pPipe + 0x28))
        return FALSE;

    if (*(PULONG_PTR)(pPipe + 0x20) == raw)
    {
        ULONG pipeType = *(PULONG)(pPipe + 0x0C);
        if (pipeType == 2 && *(PUCHAR)(pPipe + 0x08) == 0)
            return TRUE;
    }

    if (*(PULONG)(pPipe - 0x10) == 0x70646E45) // 'Endp'
    {
        return TRUE;
    }

    return FALSE;
}

/*
 * UsbHub_ExtractUcxDeviceHandle — 从 USBD_PIPE_HANDLE 确定性提取所属 UCXUSBDEVICE 句柄
 *
 * 逆向依据 (ucx01000!UcxEndpointCreate & UcxUsbDeviceCreate & Urb_USBPORTStyle_ProcessURB):
 *   - PipeHandle 指向 UCXENDPOINT_PRIVCONTEXT + 0x10:
 *       [PipeHandle - 0x10] == 'Endp' (0x70646E45)
 *       [PipeHandle + 0x30] == PUCXCONTROLLER_PRIVCONTEXT
 *       [PipeHandle + 0x38] == PUCXUSBDEVICE_PRIVCONTEXT
 *   - PUCXUSBDEVICE_PRIVCONTEXT 头部布局:
 *       [pUsbDevCtx + 0x00] == 'Devi' (0x69766544)
 *       [pUsbDevCtx + 0x10] == UCXUSBDEVICE (WDF 句柄，即 UrbHeader.UsbdDeviceHandle)
 *       [pUsbDevCtx + 0x18] == PUCXCONTROLLER_PRIVCONTEXT (与 Endpoint 交叉校验)
 */
static PVOID UsbHub_ExtractUcxDeviceHandle(_In_ USBD_PIPE_HANDLE PipeHandle)
{
    ULONG_PTR raw = (ULONG_PTR)PipeHandle;
    if (raw < 0xFFFF800000000000ULL || (raw & 0x7) != 0)
        return NULL;

    PUCHAR pPipe = (PUCHAR)raw;
    if (!MmIsAddressValid(pPipe - 0x10) || !MmIsAddressValid(pPipe + 0x40))
        return NULL;

    if (*(PULONG)(pPipe - 0x10) != 0x70646E45) // 'Endp'
        return NULL;

    PVOID pCtlrCtx = *(PVOID *)(pPipe + 0x30);
    PUCHAR pUsbDevCtx = *(PUCHAR *)(pPipe + 0x38);
    if ((ULONG_PTR)pUsbDevCtx < 0xFFFF800000000000ULL || ((ULONG_PTR)pUsbDevCtx & 0x7) != 0)
        return NULL;

    if (!MmIsAddressValid(pUsbDevCtx) || !MmIsAddressValid(pUsbDevCtx + 0x20))
        return NULL;

    if (*(PULONG)(pUsbDevCtx + 0x00) != 0x69766544) // 'Devi'
        return NULL;

    if (pCtlrCtx && *(PVOID *)(pUsbDevCtx + 0x18) != pCtlrCtx)
        return NULL;

    return *(PVOID *)(pUsbDevCtx + 0x10);
}

static USBD_PIPE_HANDLE UsbHub_ResolvePipeHandleFromObject(
    _In_      PDEVICE_OBJECT pWinUsbFdo,
    _In_      PVOID pPipeObj,
    _In_      UCHAR expectedEp,
    _Out_opt_ PUCHAR pResolvedEp)
{
    UNREFERENCED_PARAMETER(pWinUsbFdo);
    if (pResolvedEp)
        *pResolvedEp = 0;
    if (!pPipeObj)
        return NULL;

    ULONG_PTR raw = (ULONG_PTR)pPipeObj;

    __try
    {
        // 路径 1: WDFUSBPIPE 句柄解算 (Wdf01000!imp_WdfUsbTargetPipeWdmGetPipeHandle: FxUsbPipe Type=0x1203)
        if (raw < 0xFFFF800000000000ULL)
        {
            PUCHAR pFx = (PUCHAR)((~raw) & ~7ULL);
            if ((ULONG_PTR)pFx >= 0xFFFF800000000000ULL && MmIsAddressValid(pFx) && MmIsAddressValid(pFx + 0x20))
            {
                if (raw & 1)
                {
                    PUSHORT pOffset = (PUSHORT)pFx;
                    if (MmIsAddressValid(pOffset))
                    {
                        pFx -= *pOffset;
                    }
                }

                if (MmIsAddressValid(pFx) && MmIsAddressValid(pFx + 0x198))
                {
                    PUSHORT pType = (PUSHORT)(pFx + 8);
                    if (MmIsAddressValid(pType) && *pType == 0x1203)
                    {
                        // 标准偏移: FxUsbPipe + 0x180 为 USBD_PIPE_INFORMATION (+0x182=EndpointAddress, +0x184=PipeType, +0x188=PipeHandle)
                        UCHAR fxEp = *(PUCHAR)(pFx + 0x182);
                        ULONG fxPipeType = *(PULONG)(pFx + 0x184);
                        PVOID *ppPipeHandle = (PVOID *)(pFx + 0x188);
                        if (fxEp != 0 && fxPipeType == USBHUB_BULK_PIPE_TYPE &&
                            (expectedEp == 0 || fxEp == expectedEp) &&
                            MmIsAddressValid(ppPipeHandle) && *ppPipeHandle != NULL)
                        {
                            ULONG_PTR val = (ULONG_PTR)*ppPipeHandle;
                            if (UsbHub_IsValidUcxPipeHandle(val))
                            {
                                if (pResolvedEp)
                                    *pResolvedEp = fxEp;
                                return (USBD_PIPE_HANDLE)val;
                            }
                        }

                        // 跨版本兜底扫描 FxUsbPipe 内嵌的 USBD_PIPE_INFORMATION
                        for (ULONG off = 0x120; off <= 0x220; off += sizeof(ULONG))
                        {
                            if (!MmIsAddressValid(pFx + off + 0x10))
                                continue;
                            UCHAR candEp = *(PUCHAR)(pFx + off + 2);
                            ULONG candType = *(PULONG)(pFx + off + 4);
                            ULONG_PTR val = *(PULONG_PTR)(pFx + off + 8);
                            if (candEp != 0 && (expectedEp == 0 || candEp == expectedEp) &&
                                candType == USBHUB_BULK_PIPE_TYPE && UsbHub_IsValidUcxPipeHandle(val))
                            {
                                if (pResolvedEp)
                                    *pResolvedEp = candEp;
                                return (USBD_PIPE_HANDLE)val;
                            }
                        }
                    }
                }
            }
            return NULL;
        }

        // 路径 2: 直接传入内核指针时，必须满足 UCXPIPE_INFO 自引用与 'Endp' 契约
        if (expectedEp != 0 && UsbHub_IsValidUcxPipeHandle(raw))
        {
            if (pResolvedEp)
                *pResolvedEp = expectedEp;
            return (USBD_PIPE_HANDLE)raw;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}

static VOID UsbHub_RecordPipeCandidate(
    _In_    UCHAR epAddr,
    _In_    USBD_PIPE_HANDLE hUsbd,
    _Inout_ PUCHAR pEpIn,
    _Inout_ PUCHAR pEpOut,
    _Inout_ USBD_PIPE_HANDLE *phPipeIn,
    _Inout_ USBD_PIPE_HANDLE *phPipeOut)
{
    if (epAddr == 0 || !hUsbd)
        return;

    if ((epAddr & 0x80) != 0)
    {
        if (*phPipeIn == NULL && (*pEpIn == 0 || *pEpIn == epAddr))
        {
            *phPipeIn = hUsbd;
            *pEpIn = epAddr;
        }
    }
    else
    {
        if (*phPipeOut == NULL && (*pEpOut == 0 || *pEpOut == epAddr))
        {
            *phPipeOut = hUsbd;
            *pEpOut = epAddr;
        }
    }
}

/*
 * UsbHub_AutoScanBulkPipes — 零 IOCTL 内存直扫提取 WinUSB 双向 Bulk 端点地址与 USBD_PIPE_HANDLE
 */
static BOOLEAN UsbHub_AutoScanBulkPipes(
    _In_    PDEVICE_OBJECT pFdo,
    _Inout_ PUCHAR pEpIn,
    _Inout_ PUCHAR pEpOut,
    _Out_   USBD_PIPE_HANDLE *phPipeIn,
    _Out_   USBD_PIPE_HANDLE *phPipeOut)
{
    *phPipeIn = NULL;
    *phPipeOut = NULL;

    if (!pFdo || !pFdo->DeviceExtension)
        return FALSE;

    PUCHAR pDevExt = (PUCHAR)pFdo->DeviceExtension;
    if (!MmIsAddressValid(pDevExt))
        return FALSE;

    PUCHAR candidateExts[2] = {NULL, pDevExt};
    USHORT ctxOffset = *(PUSHORT)(pDevExt + 0x0A);
    if (ctxOffset > 0 && ctxOffset < 0x2000 && MmIsAddressValid(pDevExt + ctxOffset))
    {
        candidateExts[0] = pDevExt + ctxOffset + 0x30;
    }

    for (int c = 0; c < 2; c++)
    {
        PUCHAR pWinUsbDevExt = candidateExts[c];
        if (!pWinUsbDevExt || !MmIsAddressValid(pWinUsbDevExt))
            continue;

        for (ULONG off = 0x10; off <= 0x150; off += sizeof(PVOID))
        {
            ULONG checkOff = (off == 0x10) ? 0x88 : ((off == 0x88) ? 0x10 : off);

            PVOID *ppTable = (PVOID *)(pWinUsbDevExt + checkOff);
            if (!MmIsAddressValid(ppTable) || *ppTable == NULL)
                continue;

            ULONG_PTR tableAddr = (ULONG_PTR)*ppTable;
            if (tableAddr < 0xFFFF800000000000ULL || !MmIsAddressValid((PVOID)tableAddr))
                continue;

            PUCHAR pPipeTable = (PUCHAR)tableAddr;

            for (ULONG slot = 0; slot < 64; slot++)
            {
                for (ULONG baseOff = 0; baseOff <= 0x18; baseOff += 0x18)
                {
                    PVOID *ppEntry = (PVOID *)(pPipeTable + slot * sizeof(PVOID) + baseOff);
                    if (!MmIsAddressValid(ppEntry) || *ppEntry == NULL)
                        continue;

                    ULONG_PTR entryAddr = (ULONG_PTR)*ppEntry;
                    if (entryAddr < 0xFFFF800000000000ULL || !MmIsAddressValid((PVOID)entryAddr))
                        continue;

                    PUCHAR pPipeEntry = (PUCHAR)entryAddr;
                    if (!MmIsAddressValid(pPipeEntry + 0xA8))
                        continue;

                    // 1. 标准 WINUSB_PIPE_ENTRY (+0x08=EndpointAddress, +0x0C=PipeType, +0xA0=WDFUSBPIPE)
                    PVOID hWdfPipe = *(PVOID *)(pPipeEntry + 0xA0);
                    if (hWdfPipe != NULL)
                    {
                        UCHAR resolvedEp = 0;
                        USBD_PIPE_HANDLE hUsbd = UsbHub_ResolvePipeHandleFromObject(pFdo, hWdfPipe, 0, &resolvedEp);
                        if (hUsbd && resolvedEp != 0)
                        {
                            UsbHub_RecordPipeCandidate(resolvedEp, hUsbd, pEpIn, pEpOut, phPipeIn, phPipeOut);
                            if (*phPipeIn && *phPipeOut)
                                return TRUE;
                        }
                    }

                    // 2. 跨版本偏移兜底扫描
                    for (ULONG hOff = 0x20; hOff <= 0xD0; hOff += sizeof(PVOID))
                    {
                        if (hOff == 0xA0 || !MmIsAddressValid(pPipeEntry + hOff))
                            continue;
                        PVOID hCand = *(PVOID *)(pPipeEntry + hOff);
                        if (hCand != NULL && ((ULONG_PTR)hCand < 0xFFFF800000000000ULL))
                        {
                            UCHAR resolvedEp = 0;
                            USBD_PIPE_HANDLE hUsbd = UsbHub_ResolvePipeHandleFromObject(pFdo, hCand, 0, &resolvedEp);
                            if (hUsbd && resolvedEp != 0)
                            {
                                UsbHub_RecordPipeCandidate(resolvedEp, hUsbd, pEpIn, pEpOut, phPipeIn, phPipeOut);
                                if (*phPipeIn && *phPipeOut)
                                    return TRUE;
                            }
                        }
                    }
                }
            }
        }
    }

    // 兜底直接扫描 DeviceExtension 指针表
    for (ULONG off = 0; off <= 0x200; off += sizeof(PVOID))
    {
        PVOID *pCand = (PVOID *)(pDevExt + off);
        if (!MmIsAddressValid(pCand) || *pCand == NULL)
            continue;

        ULONG_PTR candAddr = (ULONG_PTR)*pCand;
        if (candAddr < 0xFFFF800000000000ULL || !MmIsAddressValid((PVOID)candAddr))
            continue;

        PUCHAR pPtr = (PUCHAR)candAddr;
        if (MmIsAddressValid(pPtr + 0xB0))
        {
            UCHAR candEp = *(PUCHAR)(pPtr + 0x08);
            ULONG pipeType = *(PULONG)(pPtr + 0x0C);
            ULONG maxPkt = *(PULONG)(pPtr + 0x04);
            if (candEp != 0 && pipeType == USBHUB_BULK_PIPE_TYPE && maxPkt >= 64 && maxPkt <= 1024)
            {
                for (ULONG fOff = 0x10; fOff <= 0x120; fOff += sizeof(PVOID))
                {
                    if (!MmIsAddressValid(pPtr + fOff))
                        continue;
                    PVOID candPtr = *(PVOID *)(pPtr + fOff);
                    UCHAR resolvedEp = 0;
                    USBD_PIPE_HANDLE resolved = UsbHub_ResolvePipeHandleFromObject(pFdo, candPtr, candEp, &resolvedEp);
                    if (resolved)
                    {
                        UsbHub_RecordPipeCandidate(candEp, resolved, pEpIn, pEpOut, phPipeIn, phPipeOut);
                        if (*phPipeIn && *phPipeOut)
                            return TRUE;
                    }
                }
            }
        }
    }

    return (*phPipeIn != NULL && *phPipeOut != NULL);
}

static BOOLEAN UsbHub_IsHub3Driver(_In_ PDEVICE_OBJECT pDev)
{
    if (!pDev || !pDev->DriverObject || !pDev->DriverObject->DriverName.Buffer)
        return FALSE;
    UNICODE_STRING *pName = &pDev->DriverObject->DriverName;
    return UsbHub_ContainsSubstrCaseless(pName->Buffer, pName->Length / sizeof(WCHAR), L"USBHUB3") ||
           UsbHub_ContainsSubstrCaseless(pName->Buffer, pName->Length / sizeof(WCHAR), L"USBHUB");
}

/*
 * UsbHub_PenetrateToHub3Pdo — 严格硬件总线穿透直达 \Driver\usbhub3 (排除其他中间驱动)
 */
static PDEVICE_OBJECT UsbHub_PenetrateToHub3Pdo(_In_ PDEVICE_OBJECT pStartDev)
{
    if (!pStartDev)
        return NULL;

    // 路径 1: 检查 pStartDev 自身是否就是 \Driver\usbhub3
    if (UsbHub_IsHub3Driver(pStartDev))
    {
        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfReferenceObject)
        {
            g_pUsbHubUserVar->Func.ObfReferenceObject(pStartDev);
        }
        DBG("[+] UsbHub_PenetrateToHub3: StartDev is already authentic USBHUB3 device %p", pStartDev);
        return pStartDev;
    }

    // 路径 2: 沿垂直设备栈向下穿透查找 USBHUB3
    if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoGetLowerDeviceObject)
    {
        PDEVICE_OBJECT pCur = pStartDev;
        while (pCur != NULL)
        {
            PDEVICE_OBJECT pNextLower = g_pUsbHubUserVar->Func.IoGetLowerDeviceObject(pCur);
            if (!pNextLower)
                break;

            if (UsbHub_IsHub3Driver(pNextLower))
            {
                if (pCur != pStartDev && g_pUsbHubUserVar->Func.ObfDereferenceObject)
                {
                    g_pUsbHubUserVar->Func.ObfDereferenceObject(pCur);
                }
                DBG("[+] UsbHub_PenetrateToHub3: Found direct USBHUB3 device from vertical stack: %p", pNextLower);
                return pNextLower; // IoGetLowerDeviceObject 已持有引用
            }

            if (pCur != pStartDev && g_pUsbHubUserVar->Func.ObfDereferenceObject)
            {
                g_pUsbHubUserVar->Func.ObfDereferenceObject(pCur);
            }
            pCur = pNextLower;
        }

        if (pCur && pCur != pStartDev && g_pUsbHubUserVar->Func.ObfDereferenceObject)
        {
            g_pUsbHubUserVar->Func.ObfDereferenceObject(pCur);
        }
    }

    // 路径 3A: 针对 usbccgp 子 PDO ('PdoC')，精确解算其所属的 ParentFdoExt ('FdoC') 指向的真实 USBHUB3 PDO
    if (pStartDev->DeviceExtension && MmIsAddressValid(pStartDev->DeviceExtension))
    {
        PUCHAR pChildDevExt = (PUCHAR)pStartDev->DeviceExtension;
        for (ULONG off = 0x80; off <= 0x160; off += sizeof(PVOID))
        {
            ULONG checkOff = (off == 0x80) ? 0xF0 : ((off == 0xF0) ? 0x80 : off);
            if (!MmIsAddressValid(pChildDevExt + checkOff))
                continue;

            ULONG_PTR candFdoExt = *(PULONG_PTR)(pChildDevExt + checkOff);
            if (candFdoExt < 0xFFFF800000000000ULL || (candFdoExt & 0x7) != 0)
                continue;

            PUCHAR pFdoExt = (PUCHAR)candFdoExt;
            if (!MmIsAddressValid(pFdoExt - 8) || !MmIsAddressValid(pFdoExt + 0x30))
                continue;

            if (*(PULONG)(pFdoExt - 8) == 0x43627355 && *(PULONG)pFdoExt == 0x436F6446) // 'UsbC' & 'FdoC'
            {
                PDEVICE_OBJECT pDirectPdo = *(PDEVICE_OBJECT *)(pFdoExt + 0x18);
                if (pDirectPdo && MmIsAddressValid(pDirectPdo) && UsbHub_IsHub3Driver(pDirectPdo))
                {
                    if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfReferenceObject)
                    {
                        g_pUsbHubUserVar->Func.ObfReferenceObject(pDirectPdo);
                    }
                    DBG("[+] UsbHub_PenetrateToHub3: Exact match USBHUB3 PDO %p via usbccgp FdoC (+0x%X)", pDirectPdo, checkOff);
                    return pDirectPdo;
                }

                PDEVICE_OBJECT pParentFdo = *(PDEVICE_OBJECT *)(pFdoExt + 0x20);
                if (pParentFdo && MmIsAddressValid(pParentFdo) && g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoGetLowerDeviceObject)
                {
                    PDEVICE_OBJECT pCur = pParentFdo;
                    while (pCur != NULL)
                    {
                        PDEVICE_OBJECT pNextLower = g_pUsbHubUserVar->Func.IoGetLowerDeviceObject(pCur);
                        if (!pNextLower)
                            break;
                        if (UsbHub_IsHub3Driver(pNextLower))
                        {
                            if (pCur != pParentFdo && g_pUsbHubUserVar->Func.ObfDereferenceObject)
                                g_pUsbHubUserVar->Func.ObfDereferenceObject(pCur);
                            DBG("[+] UsbHub_PenetrateToHub3: Resolved USBHUB3 PDO %p from matched ParentFdo %p", pNextLower, pParentFdo);
                            return pNextLower;
                        }
                        if (pCur != pParentFdo && g_pUsbHubUserVar->Func.ObfDereferenceObject)
                            g_pUsbHubUserVar->Func.ObfDereferenceObject(pCur);
                        pCur = pNextLower;
                    }
                }
            }
        }
    }

    // 路径 3B: 遍历 usbccgp 驱动实例的设备链表定位 Parent FDO 并向栈底穿透
    if (pStartDev->DriverObject && g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoGetLowerDeviceObject)
    {
        PDEVICE_OBJECT pCand = pStartDev->DriverObject->DeviceObject;
        while (pCand != NULL)
        {
            PDEVICE_OBJECT pCur = pCand;
            while (pCur != NULL)
            {
                PDEVICE_OBJECT pNextLower = g_pUsbHubUserVar->Func.IoGetLowerDeviceObject(pCur);
                if (!pNextLower)
                    break;

                if (UsbHub_IsHub3Driver(pNextLower))
                {
                    if (pCur != pCand && g_pUsbHubUserVar->Func.ObfDereferenceObject)
                    {
                        g_pUsbHubUserVar->Func.ObfDereferenceObject(pCur);
                    }
                    DBG("[+] UsbHub_PenetrateToHub3: Resolved authentic USBHUB3 PDO %p (Drv=%wZ, StackSize=%d) from Parent FDO %p stack",
                        pNextLower, (pNextLower->DriverObject) ? &pNextLower->DriverObject->DriverName : NULL,
                        (int)pNextLower->StackSize, pCand);
                    return pNextLower;
                }

                if (pCur != pCand && g_pUsbHubUserVar->Func.ObfDereferenceObject)
                {
                    g_pUsbHubUserVar->Func.ObfDereferenceObject(pCur);
                }
                pCur = pNextLower;
            }

            if (pCur && pCur != pCand && g_pUsbHubUserVar->Func.ObfDereferenceObject)
            {
                g_pUsbHubUserVar->Func.ObfDereferenceObject(pCur);
            }

            pCand = pCand->NextDevice;
        }
    }

    return NULL;
}

/*
 * UsbHub_GetWdfModuleBounds — 遍历内核模块链表查找 Wdf01000.sys 的基址与内存范围
 */
static BOOLEAN UsbHub_GetWdfModuleBounds(_In_ PDRIVER_OBJECT pDrv, _Out_ PULONG_PTR pBase, _Out_ PULONG_PTR pEnd)
{
    *pBase = 0;
    *pEnd = 0;

    if (!pDrv || !pDrv->DriverSection)
        return FALSE;

    PKLDR_DATA_TABLE_ENTRY pEntry = (PKLDR_DATA_TABLE_ENTRY)pDrv->DriverSection;
    PLIST_ENTRY pHead = &pEntry->InLoadOrderLinks;
    PLIST_ENTRY pCurr = pHead->Flink;

    for (int i = 0; i < 512; i++)
    {
        if (pCurr == pHead || !pCurr)
            break;

        PKLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pCurr, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (pMod && pMod->BaseDllName.Buffer && pMod->BaseDllName.Length >= 6 * sizeof(WCHAR))
        {
            if (UsbHub_ContainsSubstrCaseless(pMod->BaseDllName.Buffer, pMod->BaseDllName.Length / sizeof(WCHAR), L"wdf01000"))
            {
                *pBase = (ULONG_PTR)pMod->DllBase;
                *pEnd = *pBase + (ULONG_PTR)pMod->SizeOfImage;
                return TRUE;
            }
        }
        pCurr = pCurr->Flink;
    }

    return FALSE;
}

/*
 * UsbHub_ResolveOriginalDispatch — 提取目标 KMDF 驱动的 Wdf01000!FxDevice::DispatchWithLock 原生分发网关
 */
static PDRIVER_DISPATCH UsbHub_ResolveOriginalDispatch(_In_ PDRIVER_OBJECT pDrv)
{
    if (!pDrv)
        return NULL;

    ULONG_PTR wdfBase = 0;
    ULONG_PTR wdfEnd = 0;
    BOOLEAN hasWdfBounds = UsbHub_GetWdfModuleBounds(pDrv, &wdfBase, &wdfEnd);

    if (hasWdfBounds)
    {
        /* 阶段 1：若 IRP_MJ_INTERNAL_DEVICE_CONTROL 自身落在 Wdf01000.sys 内（例如未被 Hook 的 USBXHCI），直接使用 */
        ULONG_PTR pfnInternal = (ULONG_PTR)pDrv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
        if (pfnInternal >= wdfBase && pfnInternal < wdfEnd)
        {
            DBG("[+] UsbHub: Target driver IRP_MJ_INTERNAL_DEVICE_CONTROL is clean Wdf01000 gateway: %p", (PVOID)pfnInternal);
            return (PDRIVER_DISPATCH)pfnInternal;
        }

        /* 阶段 2：从同驱动未受篡改的相邻槽位提取 Wdf01000!FxDevice::DispatchWithLock */
        static const UCHAR preferSlots[] = {IRP_MJ_DEVICE_CONTROL, IRP_MJ_SYSTEM_CONTROL, IRP_MJ_POWER,
                                            IRP_MJ_CREATE,         IRP_MJ_CLOSE,          IRP_MJ_CLEANUP};

        for (ULONG i = 0; i < sizeof(preferSlots); i++)
        {
            UCHAR slot = preferSlots[i];
            ULONG_PTR pfn = (ULONG_PTR)pDrv->MajorFunction[slot];
            if (pfn >= wdfBase && pfn < wdfEnd)
            {
                DBG("[+] UsbHub: Found authentic Wdf01000 dispatch from intra-driver slot 0x%X: %p", slot, (PVOID)pfn);
                return (PDRIVER_DISPATCH)pfn;
            }
        }

        for (ULONG slot = 0; slot <= IRP_MJ_MAXIMUM_FUNCTION; slot++)
        {
            if (slot == IRP_MJ_INTERNAL_DEVICE_CONTROL)
                continue;

            ULONG_PTR pfn = (ULONG_PTR)pDrv->MajorFunction[slot];
            if (pfn >= wdfBase && pfn < wdfEnd)
            {
                DBG("[+] UsbHub: Found authentic Wdf01000 dispatch from slot 0x%X: %p", slot, (PVOID)pfn);
                return (PDRIVER_DISPATCH)pfn;
            }
        }
    }

    ULONG_PTR drvBase = (ULONG_PTR)pDrv->DriverStart;
    ULONG_PTR drvEnd = drvBase + pDrv->DriverSize;
    if (drvBase != 0 && drvEnd > drvBase)
    {
        ULONG_PTR pfn = (ULONG_PTR)pDrv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
        if (pfn >= drvBase && pfn < drvEnd)
        {
            return (PDRIVER_DISPATCH)pfn;
        }

        for (ULONG slot = 0; slot <= IRP_MJ_MAXIMUM_FUNCTION; slot++)
        {
            if (slot == IRP_MJ_INTERNAL_DEVICE_CONTROL)
                continue;
            pfn = (ULONG_PTR)pDrv->MajorFunction[slot];
            if (pfn >= drvBase && pfn < drvEnd)
            {
                return (PDRIVER_DISPATCH)pfn;
            }
        }
    }

    return NULL;
}

/*
 * UsbHub_SyncCompletionRoutine — 同步 IRP 完成例程
 * 阻止 I/O 管理器提前释放 IRP，并在底层驱动处理完成时唤醒等待事件
 */
static NTSTATUS UsbHub_SyncCompletionRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp,
                                             _In_reads_opt_(_Inexpressible_("varies")) PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    PKEVENT pEvent = (PKEVENT)Context;
    if (pEvent)
    {
        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.KeSetEvent)
        {
            g_pUsbHubUserVar->Func.KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
        }
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS UsbHub_SubmitUrb(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PURB pUrb,
                                   _In_ ULONG TimeoutMs, _In_ BOOLEAN fReturnOnTimeout)
{
    if (UserVar)
    {
        g_pUsbHubUserVar = UserVar;
    }

    PDEVICE_OBJECT pTarget = g_pTargetPdo;
    if (!pTarget)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    if (g_UcxUsbDeviceHandle)
    {
        pUrb->UrbHeader.UsbdDeviceHandle = g_UcxUsbDeviceHandle;
    }

    CCHAR stackSize = pTarget->StackSize;
    if (stackSize < 4)
        stackSize = 4;

    PIRP pIrp =
        (UserVar && UserVar->Func.IoAllocateIrp)
            ? UserVar->Func.IoAllocateIrp(stackSize, FALSE)
            : ((g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoAllocateIrp) ? g_pUsbHubUserVar->Func.IoAllocateIrp(stackSize, FALSE) : NULL);
    if (!pIrp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KEVENT event;
    if (UserVar && UserVar->Func.KeInitializeEvent)
    {
        UserVar->Func.KeInitializeEvent(&event, NotificationEvent, FALSE);
    }
    else if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.KeInitializeEvent)
    {
        g_pUsbHubUserVar->Func.KeInitializeEvent(&event, NotificationEvent, FALSE);
    }

    PIO_STACK_LOCATION nextSp = IoGetNextIrpStackLocation(pIrp);
    nextSp->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    nextSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    nextSp->Parameters.Others.Argument1 = pUrb;
    nextSp->DeviceObject = pTarget;

    IoSetCompletionRoutine(pIrp, UsbHub_SyncCompletionRoutine, &event, TRUE, TRUE, TRUE);

    PDRIVER_DISPATCH pDispatch = g_pUsbOriginalDispatch;
    if (!pDispatch && pTarget->DriverObject)
    {
        pDispatch = UsbHub_ResolveOriginalDispatch(pTarget->DriverObject);
        g_pUsbOriginalDispatch = pDispatch;
    }

    if (!pDispatch)
    {
        if (UserVar && UserVar->Func.IoFreeIrp)
            UserVar->Func.IoFreeIrp(pIrp);
        else if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoFreeIrp)
            g_pUsbHubUserVar->Func.IoFreeIrp(pIrp);
        return STATUS_ACCESS_DENIED;
    }

    pIrp->CurrentLocation--;
    pIrp->Tail.Overlay.CurrentStackLocation--;
    IoGetCurrentIrpStackLocation(pIrp)->DeviceObject = pTarget;

    NTSTATUS status = pDispatch(pTarget, pIrp);

    if (status == STATUS_PENDING)
    {
        LARGE_INTEGER Timeout;
        if (TimeoutMs == 0)
        {
            TimeoutMs = 500;
        }
        Timeout.QuadPart = -10LL * 1000LL * (LONGLONG)TimeoutMs;
        while (TRUE)
        {
            NTSTATUS waitStatus = STATUS_SUCCESS;
            if (UserVar && UserVar->Func.KeWaitForSingleObject)
            {
                waitStatus = UserVar->Func.KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &Timeout);
            }
            else if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.KeWaitForSingleObject)
            {
                waitStatus = g_pUsbHubUserVar->Func.KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &Timeout);
            }

            if (waitStatus == STATUS_SUCCESS)
            {
                status = pIrp->IoStatus.Status;
                break;
            }

            if (waitStatus == STATUS_TIMEOUT && (fReturnOnTimeout || !g_UsbServer.fRunning))
            {
                if (UserVar && UserVar->Func.IoCancelIrp)
                {
                    UserVar->Func.IoCancelIrp(pIrp);
                }
                else if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoCancelIrp)
                {
                    g_pUsbHubUserVar->Func.IoCancelIrp(pIrp);
                }
                if (UserVar && UserVar->Func.KeWaitForSingleObject)
                {
                    UserVar->Func.KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
                }
                else if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.KeWaitForSingleObject)
                {
                    g_pUsbHubUserVar->Func.KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
                }
                status = pIrp->IoStatus.Status;
                if (fReturnOnTimeout && status == STATUS_CANCELLED)
                {
                    status = STATUS_TIMEOUT;
                }
                break;
            }
        }
    }
    else
    {
        status = pIrp->IoStatus.Status;
    }

    if (UserVar && UserVar->Func.IoFreeIrp)
    {
        UserVar->Func.IoFreeIrp(pIrp);
    }
    else if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoFreeIrp)
    {
        g_pUsbHubUserVar->Func.IoFreeIrp(pIrp);
    }

    return status;
}

NTSTATUS UsbHub_Init(
    _In_    MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_    PDEVICE_OBJECT pBaseDev,
    _Inout_ PUCHAR pEpIn,
    _Inout_ PUCHAR pEpOut)
{
    g_pUsbHubUserVar = UserVar;

    if (!pBaseDev || !pBaseDev->DriverObject || !pEpIn || !pEpOut)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PDEVICE_OBJECT pTargetFdo = NULL;
    PDEVICE_OBJECT pCur = pBaseDev;
    while (pCur != NULL)
    {
        if (pCur->DriverObject && pCur->DriverObject->DriverName.Buffer)
        {
            UNICODE_STRING *pName = &pCur->DriverObject->DriverName;
            if (UsbHub_ContainsSubstrCaseless(pName->Buffer, pName->Length / sizeof(WCHAR), L"WINUSB"))
            {
                pTargetFdo = pCur;
                break;
            }
        }
        pCur = pCur->AttachedDevice;
    }

    if (!pTargetFdo)
    {
        pTargetFdo = pBaseDev;
    }

    UCHAR epIn = *pEpIn;
    UCHAR epOut = *pEpOut;
    USBD_PIPE_HANDLE hPipeIn = NULL;
    USBD_PIPE_HANDLE hPipeOut = NULL;

    // ★★★ 零 IOCTL 内存直扫：直接从 WinUsb DeviceExtension 扫描双向 Bulk 端点与 USBD_PIPE_HANDLE ★★★
    if (!UsbHub_AutoScanBulkPipes(pTargetFdo, &epIn, &epOut, &hPipeIn, &hPipeOut) || !hPipeIn || !hPipeOut)
    {
        DBG("[-] UsbHub_Init: AutoScanBulkPipes failed on TargetFdo=%p (epIn=0x%02X->%p, epOut=0x%02X->%p)",
            pTargetFdo, epIn, hPipeIn, epOut, hPipeOut);
        Transport_SetLastErrorFormat("[USB:ScanPipe] Bulk PipeHandles not found (epIn=0x%02X, epOut=0x%02X)", epIn, epOut);
        return STATUS_NOT_FOUND;
    }

    // ★★★ 从 PipeHandle 提取 UCXUSBDEVICE 句柄 (urb.Hdr.UsbdDeviceHandle)，校验 In/Out 归属同一设备 ★★★
    PVOID hUcxDevIn = UsbHub_ExtractUcxDeviceHandle(hPipeIn);
    PVOID hUcxDevOut = UsbHub_ExtractUcxDeviceHandle(hPipeOut);
    if (!hUcxDevIn || hUcxDevIn != hUcxDevOut)
    {
        DBG("[-] UsbHub_Init: UcxUsbDeviceHandle mismatch or invalid (In=%p, Out=%p)", hUcxDevIn, hUcxDevOut);
        Transport_SetLastErrorDesc("[USB:UcxDev] Invalid or mismatched UCXUSBDEVICE handle in PipeHandle");
        return STATUS_NOT_FOUND;
    }

    PDEVICE_OBJECT pLower = (UserVar && UserVar->Func.IoGetLowerDeviceObject) ? UserVar->Func.IoGetLowerDeviceObject(pTargetFdo) : NULL;
    if (!pLower)
    {
        Transport_SetLastErrorDesc("[USB:HubInit] IoGetLowerDeviceObject returned NULL for target FDO");
        return STATUS_DEVICE_NOT_READY;
    }

    PDEVICE_OBJECT pHubPdo = UsbHub_PenetrateToHub3Pdo(pLower);
    if (!pHubPdo || !UsbHub_IsHub3Driver(pHubPdo))
    {
        if (UserVar && UserVar->Func.ObfDereferenceObject)
            UserVar->Func.ObfDereferenceObject(pLower);
        Transport_SetLastErrorFormat("[USB:HubInit] PenetrateToHub3Pdo failed (LowerDrv=%wZ)",
                                     (pLower->DriverObject) ? &pLower->DriverObject->DriverName : NULL);
        return STATUS_NOT_FOUND;
    }

    // ★★★ 绑定至真实 USBHUB3 PDO 并使用其纯净 Wdf01000 网关（原生支持 0x1E SYNC_RESET_PIPE_AND_CLEAR_STALL 且内部直转 USBXHCI RootHub PDO）★★★
    PDEVICE_OBJECT pActiveTarget = pHubPdo;

    PDRIVER_DISPATCH pCleanDispatch = UsbHub_ResolveOriginalDispatch(pActiveTarget->DriverObject);
    if (!pCleanDispatch)
    {
        if (UserVar && UserVar->Func.ObfDereferenceObject)
        {
            UserVar->Func.ObfDereferenceObject(pHubPdo);
            UserVar->Func.ObfDereferenceObject(pLower);
        }
        Transport_SetLastErrorDesc("[USB:Dispatch] Failed to resolve Wdf01000 original dispatch gateway");
        return STATUS_NOT_FOUND;
    }

    if (UserVar && UserVar->Func.ObfReferenceObject)
    {
        UserVar->Func.ObfReferenceObject(pTargetFdo);
    }

    g_pWinUsbFdo = pTargetFdo;
    g_pLowerDev = pLower;
    g_pHubPdo = pHubPdo;
    g_pUcxRootHubPdo = NULL;
    g_pTargetPdo = pActiveTarget;
    g_UcxUsbDeviceHandle = hUcxDevIn;
    g_PipeHandleIn = hPipeIn;
    g_PipeHandleOut = hPipeOut;
    g_EpIn = epIn;
    g_EpOut = epOut;
    g_pUsbOriginalDispatch = pCleanDispatch;
    *pEpIn = epIn;
    *pEpOut = epOut;

    DBG("[+] UsbHub_Init: Direct TargetPdo=%p (Drv=%wZ, StackSize=%d), UcxUsbDevice=%p, EpIn=0x%02X(%p), EpOut=0x%02X(%p)",
        g_pTargetPdo, &g_pTargetPdo->DriverObject->DriverName, (int)g_pTargetPdo->StackSize,
        g_UcxUsbDeviceHandle, g_EpIn, g_PipeHandleIn, g_EpOut, g_PipeHandleOut);

    CCHAR stackSize = g_pTargetPdo->StackSize + 1;
    if (stackSize < 6)
        stackSize = 6;

    // ★★★ 初始化常驻接收 IRP 与双缓冲发送 IRP（消灭热路径动态 IRP 分配开销）★★★
    if (UserVar && UserVar->Func.IoAllocateIrp && UserVar->Func.KeInitializeEvent)
    {
        g_pHubRecvIrp = UserVar->Func.IoAllocateIrp(stackSize, FALSE);
        UserVar->Func.KeInitializeEvent(&g_HubRecvEvent, NotificationEvent, FALSE);

        for (int i = 0; i < 2; i++)
        {
            g_HubSendSlots[i].pIrp = UserVar->Func.IoAllocateIrp(stackSize, FALSE);
            UserVar->Func.KeInitializeEvent(&g_HubSendSlots[i].Event, NotificationEvent, FALSE);
            g_HubSendSlots[i].bInFlight = FALSE;
        }
    }

    g_HubReady = TRUE;
    return STATUS_SUCCESS;
}

VOID UsbHub_Cleanup(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);

    g_HubReady = FALSE;

    // 优雅排空处于在飞状态的发送 IRP
    for (int i = 0; i < 2; i++)
    {
        if (g_HubSendSlots[i].bInFlight && g_HubSendSlots[i].pIrp)
        {
            if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoCancelIrp)
            {
                g_pUsbHubUserVar->Func.IoCancelIrp(g_HubSendSlots[i].pIrp);
            }
            if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.KeWaitForSingleObject)
            {
                g_pUsbHubUserVar->Func.KeWaitForSingleObject(&g_HubSendSlots[i].Event, Executive, KernelMode, FALSE, NULL);
            }
            g_HubSendSlots[i].bInFlight = FALSE;
        }

        if (g_HubSendSlots[i].pIrp)
        {
            if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoFreeIrp)
            {
                g_pUsbHubUserVar->Func.IoFreeIrp(g_HubSendSlots[i].pIrp);
            }
            g_HubSendSlots[i].pIrp = NULL;
        }
    }

    if (g_pHubRecvIrp)
    {
        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoFreeIrp)
        {
            g_pUsbHubUserVar->Func.IoFreeIrp(g_pHubRecvIrp);
        }
        g_pHubRecvIrp = NULL;
    }

    g_PipeHandleIn = NULL;
    g_PipeHandleOut = NULL;
    g_UcxUsbDeviceHandle = NULL;
    g_pTargetPdo = NULL;
    g_pUsbOriginalDispatch = NULL;
    g_EpIn = 0;
    g_EpOut = 0;

    if (g_pUcxRootHubPdo)
    {
        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfDereferenceObject)
        {
            g_pUsbHubUserVar->Func.ObfDereferenceObject(g_pUcxRootHubPdo);
        }
        g_pUcxRootHubPdo = NULL;
    }

    if (g_pHubPdo)
    {
        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfDereferenceObject)
        {
            g_pUsbHubUserVar->Func.ObfDereferenceObject(g_pHubPdo);
        }
        g_pHubPdo = NULL;
    }

    if (g_pLowerDev)
    {
        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfDereferenceObject)
        {
            g_pUsbHubUserVar->Func.ObfDereferenceObject(g_pLowerDev);
        }
        g_pLowerDev = NULL;
    }

    if (g_pWinUsbFdo)
    {
        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfDereferenceObject)
        {
            g_pUsbHubUserVar->Func.ObfDereferenceObject(g_pWinUsbFdo);
        }
        g_pWinUsbFdo = NULL;
    }
}

NTSTATUS UsbHub_BulkRead(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PVOID pBuf, _In_ ULONG cbBuf, _In_ ULONG TimeoutMs,
                           _In_ BOOLEAN fReturnOnTimeout, _Out_ PULONG pcbRead)
{
    if (pcbRead)
        *pcbRead = 0;
    if (!g_HubReady || !g_PipeHandleIn)
        return STATUS_DEVICE_NOT_READY;
    if (!pBuf || cbBuf == 0)
        return STATUS_INVALID_PARAMETER;

    struct _URB_BULK_OR_INTERRUPT_TRANSFER urb;
    UserVar->Func.RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    urb.Hdr.Function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    urb.Hdr.UsbdDeviceHandle = g_UcxUsbDeviceHandle;
    urb.PipeHandle = g_PipeHandleIn;
    urb.TransferFlags = USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK;
    urb.TransferBufferLength = cbBuf;
    urb.TransferBuffer = pBuf;

    PMDL pMdl = UserVar->Func.IoAllocateMdl(pBuf, cbBuf, FALSE, FALSE, NULL);
    if (pMdl)
    {
        UserVar->Func.MmBuildMdlForNonPagedPool(pMdl);
        urb.TransferBufferMDL = pMdl;
    }

    NTSTATUS status = UsbHub_SubmitUrb(UserVar, (PURB)&urb, TimeoutMs, fReturnOnTimeout);
    g_UsbHubLastUsbdStatus = (ULONG)urb.Hdr.Status;

    if (pMdl)
    {
        UserVar->Func.IoFreeMdl(pMdl);
    }

    if (NT_SUCCESS(status))
    {
        if (pcbRead)
        {
            *pcbRead = urb.TransferBufferLength;
        }
    }
    return status;
}

NTSTATUS UsbHub_BulkWrite(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PVOID pBuf, _In_ ULONG cbBuf, _Out_ PULONG pcbWritten)
{
    if (pcbWritten)
        *pcbWritten = 0;
    if (!g_HubReady || !g_PipeHandleOut)
        return STATUS_DEVICE_NOT_READY;
    if (!pBuf || cbBuf == 0)
        return STATUS_INVALID_PARAMETER;

    struct _URB_BULK_OR_INTERRUPT_TRANSFER urb;
    UserVar->Func.RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    urb.Hdr.Function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    urb.Hdr.UsbdDeviceHandle = g_UcxUsbDeviceHandle;
    urb.PipeHandle = g_PipeHandleOut;
    urb.TransferFlags = USBD_TRANSFER_DIRECTION_OUT;
    urb.TransferBufferLength = cbBuf;
    urb.TransferBuffer = pBuf;

    PMDL pMdl = UserVar->Func.IoAllocateMdl(pBuf, cbBuf, FALSE, FALSE, NULL);
    if (pMdl)
    {
        UserVar->Func.MmBuildMdlForNonPagedPool(pMdl);
        urb.TransferBufferMDL = pMdl;
    }

    NTSTATUS status = UsbHub_SubmitUrb(UserVar, (PURB)&urb, 500, FALSE);

    if (pMdl)
    {
        UserVar->Func.IoFreeMdl(pMdl);
    }

    if (NT_SUCCESS(status))
    {
        if (pcbWritten)
        {
            *pcbWritten = urb.TransferBufferLength;
        }
    }
    return status;
}

NTSTATUS UsbHub_AbortPipe(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ BOOLEAN bIsIn)
{
    USBD_PIPE_HANDLE hPipe = bIsIn ? g_PipeHandleIn : g_PipeHandleOut;
    if (!g_HubReady || !hPipe)
        return STATUS_DEVICE_NOT_READY;

    struct _URB_PIPE_REQUEST urb;
    RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length = sizeof(struct _URB_PIPE_REQUEST);
    urb.Hdr.Function = URB_FUNCTION_ABORT_PIPE;
    urb.Hdr.UsbdDeviceHandle = g_UcxUsbDeviceHandle;
    urb.PipeHandle = hPipe;

    return UsbHub_SubmitUrb(UserVar, (PURB)&urb, 500, FALSE);
}

NTSTATUS UsbHub_ResetPipe(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ BOOLEAN bIsIn)
{
    USBD_PIPE_HANDLE hPipe = bIsIn ? g_PipeHandleIn : g_PipeHandleOut;
    UCHAR epAddr = bIsIn ? g_EpIn : g_EpOut;
    if (!g_HubReady || !hPipe)
        return STATUS_DEVICE_NOT_READY;

    // 针对直通 ucx01000 RootHub PDO 模式：使用 UCX 原生支持的 ABORT_PIPE (0x02) + CLEAR_FEATURE_TO_ENDPOINT (0x11)
    if (g_pTargetPdo == g_pUcxRootHubPdo && g_pUcxRootHubPdo != NULL)
    {
        UsbHub_AbortPipe(UserVar, bIsIn);

        struct _URB_CONTROL_FEATURE_REQUEST featUrb;
        RtlZeroMemory(&featUrb, sizeof(featUrb));
        featUrb.Hdr.Length = sizeof(struct _URB_CONTROL_FEATURE_REQUEST);
        featUrb.Hdr.Function = URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT;
        featUrb.Hdr.UsbdDeviceHandle = g_UcxUsbDeviceHandle;
        featUrb.FeatureSelector = 0; // USB_FEATURE_ENDPOINT_STALL (ENDPOINT_HALT)
        featUrb.Index = epAddr;
        return UsbHub_SubmitUrb(UserVar, (PURB)&featUrb, 500, FALSE);
    }

    struct _URB_PIPE_REQUEST urb;
    RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length = sizeof(struct _URB_PIPE_REQUEST);
    urb.Hdr.Function = URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL;
    urb.Hdr.UsbdDeviceHandle = g_UcxUsbDeviceHandle;
    urb.PipeHandle = hPipe;

    return UsbHub_SubmitUrb(UserVar, (PURB)&urb, 500, FALSE);
}

BOOLEAN UsbHub_IsReady(VOID) { return g_HubReady; }
BOOLEAN UsbHub_HasAceInfo(VOID) { return g_bAceDetected; }

// ★★★ 常驻 IRP 与预构建 MDL 零分配快速读 ★★★
NTSTATUS UsbHub_BulkReadFast(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PVOID pBuf, _In_ PMDL pMdl, _In_ ULONG cbBuf,
                             _Out_ PULONG pcbRead)
{
    if (pcbRead)
        *pcbRead = 0;
    if (!g_HubReady || !g_PipeHandleIn || !g_pTargetPdo || !g_pUsbOriginalDispatch)
        return STATUS_DEVICE_NOT_READY;
    if (!pBuf || cbBuf == 0)
        return STATUS_INVALID_PARAMETER;

    // 防御性校验：若传入的 pBuf 并非从 pMdl 虚拟基址起始（例如带有 cbRemain 残片偏移），安全回退到动态 MDL 分配
    if (!g_pHubRecvIrp || (pMdl && pBuf != MmGetMdlVirtualAddress(pMdl)))
    {
        return UsbHub_BulkRead(UserVar, pBuf, cbBuf, 500, FALSE, pcbRead);
    }

    struct _URB_BULK_OR_INTERRUPT_TRANSFER urb;
    UserVar->Func.RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    urb.Hdr.Function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    urb.Hdr.UsbdDeviceHandle = g_UcxUsbDeviceHandle;
    urb.PipeHandle = g_PipeHandleIn;
    urb.TransferFlags = USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK;
    urb.TransferBufferLength = cbBuf;
    urb.TransferBufferMDL = pMdl;
    urb.TransferBuffer = pBuf;

    PIRP pIrp = g_pHubRecvIrp;
    UserVar->Func.IoReuseIrp(pIrp, STATUS_SUCCESS);

    if (UserVar->Func.KeClearEvent)
        UserVar->Func.KeClearEvent(&g_HubRecvEvent);
    else
        UserVar->Func.KeInitializeEvent(&g_HubRecvEvent, NotificationEvent, FALSE);

    PIO_STACK_LOCATION nextSp = IoGetNextIrpStackLocation(pIrp);
    nextSp->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    nextSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    nextSp->Parameters.Others.Argument1 = &urb;
    nextSp->DeviceObject = g_pTargetPdo;

    IoSetCompletionRoutine(pIrp, UsbHub_SyncCompletionRoutine, &g_HubRecvEvent, TRUE, TRUE, TRUE);

    pIrp->CurrentLocation--;
    pIrp->Tail.Overlay.CurrentStackLocation--;
    IoGetCurrentIrpStackLocation(pIrp)->DeviceObject = g_pTargetPdo;

    NTSTATUS status = g_pUsbOriginalDispatch(g_pTargetPdo, pIrp);

    if (status == STATUS_PENDING)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10 * 1000 * 500; // 500ms 守护轮询
        while (TRUE)
        {
            NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(&g_HubRecvEvent, Executive, KernelMode, FALSE, &Timeout);
            if (waitStatus == STATUS_SUCCESS)
            {
                status = pIrp->IoStatus.Status;
                break;
            }
            if (waitStatus == STATUS_TIMEOUT)
            {
                if (!g_UsbServer.fRunning)
                {
                    if (UserVar->Func.IoCancelIrp)
                        UserVar->Func.IoCancelIrp(pIrp);
                    UserVar->Func.KeWaitForSingleObject(&g_HubRecvEvent, Executive, KernelMode, FALSE, NULL);
                    status = pIrp->IoStatus.Status;
                    break;
                }
            }
        }
    }
    else
    {
        status = pIrp->IoStatus.Status;
    }
    g_UsbHubLastUsbdStatus = (ULONG)urb.Hdr.Status;

    if (NT_SUCCESS(status))
    {
        if (pcbRead)
            *pcbRead = urb.TransferBufferLength;
    }

    return status;
}

// ★★★ 双缓冲异步提交发送（0 阻塞、与接收端全双工重叠流水线）★★★
NTSTATUS UsbHub_BulkWriteAsync(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ ULONG slotIndex, _In_ PVOID pBuf, _In_ PMDL pMdl,
                               _In_ ULONG cbBuf)
{
    if (slotIndex >= 2)
        return STATUS_INVALID_PARAMETER;
    if (!g_HubReady || !g_PipeHandleOut || !g_pTargetPdo || !g_pUsbOriginalDispatch)
        return STATUS_DEVICE_NOT_READY;
    if (!pBuf || cbBuf == 0)
        return STATUS_INVALID_PARAMETER;

    HUB_SEND_SLOT *pSlot = &g_HubSendSlots[slotIndex];
    if (!pSlot->pIrp)
    {
        ULONG cbWritten = 0;
        return UsbHub_BulkWrite(UserVar, pBuf, cbBuf, &cbWritten);
    }

    // 若该槽位处于在飞状态，先等待其完成
    if (pSlot->bInFlight)
    {
        UsbHub_WaitWriteSlot(UserVar, slotIndex, NULL);
    }

    UserVar->Func.RtlZeroMemory(&pSlot->Urb, sizeof(pSlot->Urb));
    pSlot->Urb.Hdr.Length = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    pSlot->Urb.Hdr.Function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    pSlot->Urb.Hdr.UsbdDeviceHandle = g_UcxUsbDeviceHandle;
    pSlot->Urb.PipeHandle = g_PipeHandleOut;
    pSlot->Urb.TransferFlags = USBD_TRANSFER_DIRECTION_OUT;
    pSlot->Urb.TransferBufferLength = cbBuf;
    pSlot->Urb.TransferBufferMDL = pMdl;
    pSlot->Urb.TransferBuffer = pBuf;

    PIRP pIrp = pSlot->pIrp;
    UserVar->Func.IoReuseIrp(pIrp, STATUS_SUCCESS);

    if (UserVar->Func.KeClearEvent)
        UserVar->Func.KeClearEvent(&pSlot->Event);
    else
        UserVar->Func.KeInitializeEvent(&pSlot->Event, NotificationEvent, FALSE);

    PIO_STACK_LOCATION nextSp = IoGetNextIrpStackLocation(pIrp);
    nextSp->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    nextSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    nextSp->Parameters.Others.Argument1 = &pSlot->Urb;
    nextSp->DeviceObject = g_pTargetPdo;

    IoSetCompletionRoutine(pIrp, UsbHub_SyncCompletionRoutine, &pSlot->Event, TRUE, TRUE, TRUE);

    pIrp->CurrentLocation--;
    pIrp->Tail.Overlay.CurrentStackLocation--;
    IoGetCurrentIrpStackLocation(pIrp)->DeviceObject = g_pTargetPdo;

    pSlot->bInFlight = TRUE;
    NTSTATUS status = g_pUsbOriginalDispatch(g_pTargetPdo, pIrp);

    if (status == STATUS_PENDING)
    {
        return STATUS_SUCCESS;
    }

    pSlot->bInFlight = FALSE;
    return pIrp->IoStatus.Status;
}

// ★★★ 等待指定发送槽位完成并返回结果 ★★★
NTSTATUS UsbHub_WaitWriteSlot(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ ULONG slotIndex, _Out_opt_ PULONG pcbWritten)
{
    if (slotIndex >= 2)
        return STATUS_INVALID_PARAMETER;

    HUB_SEND_SLOT *pSlot = &g_HubSendSlots[slotIndex];
    if (!pSlot->pIrp)
        return STATUS_SUCCESS;

    if (!pSlot->bInFlight)
    {
        if (pcbWritten)
            *pcbWritten = pSlot->Urb.TransferBufferLength;
        return pSlot->pIrp->IoStatus.Status;
    }

    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10 * 1000 * 500; // 500ms 守护轮询

    while (TRUE)
    {
        NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(&pSlot->Event, Executive, KernelMode, FALSE, &Timeout);
        if (waitStatus == STATUS_SUCCESS)
        {
            status = pSlot->pIrp->IoStatus.Status;
            break;
        }
        if (waitStatus == STATUS_TIMEOUT)
        {
            if (!g_UsbServer.fRunning)
            {
                if (UserVar->Func.IoCancelIrp)
                    UserVar->Func.IoCancelIrp(pSlot->pIrp);
                UserVar->Func.KeWaitForSingleObject(&pSlot->Event, Executive, KernelMode, FALSE, NULL);
                status = pSlot->pIrp->IoStatus.Status;
                break;
            }
        }
    }

    pSlot->bInFlight = FALSE;

    if (pcbWritten)
    {
        *pcbWritten = NT_SUCCESS(status) ? pSlot->Urb.TransferBufferLength : 0;
    }

    return status;
}
#else
typedef int dummy_usb_hub_translation_unit;
#endif
