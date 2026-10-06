#include "usb_hub.h"
#include "usb_server.h"
#include "Common.h"

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID *Object);

NTKERNELAPI NTSTATUS FASTCALL IofCallDriver(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp);
#ifndef IoCallDriver
#define IoCallDriver(DeviceObject, Irp) IofCallDriver(DeviceObject, Irp)
#endif

extern POBJECT_TYPE *IoDriverObjectType;

static PDEVICE_OBJECT   g_pWinUsbFdo       = NULL;
static PDEVICE_OBJECT   g_pLowerDev        = NULL;
static PDEVICE_OBJECT   g_pHubPdo          = NULL;
static USBD_PIPE_HANDLE g_PipeHandleIn     = NULL;
static USBD_PIPE_HANDLE g_PipeHandleOut    = NULL;
static UCHAR            g_EpIn             = 0;
static UCHAR            g_EpOut            = 0;
static BOOLEAN          g_HubReady         = FALSE;
static ULONG_PTR        g_UsbAceBase       = 0;
static ULONG_PTR        g_UsbAceEnd        = 0;

VOID UsbHub_SetAceInfo(ULONG_PTR aceBase, ULONG_PTR aceEnd)
{
    g_UsbAceBase = aceBase;
    g_UsbAceEnd  = aceEnd;
}

static BOOLEAN UsbHub_ContainsSubstrCaseless(
    _In_reads_(cchStr) PCWSTR pszStr,
    _In_ ULONG cchStr,
    _In_ PCWSTR pszSub)
{
    if (!pszStr || !pszSub || cchStr == 0) return FALSE;
    ULONG subLen = 0;
    while (pszSub[subLen] != L'\0') subLen++;
    if (subLen == 0 || subLen > cchStr) return FALSE;

    for (ULONG i = 0; i <= cchStr - subLen; i++)
    {
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < subLen; j++)
        {
            WCHAR c1 = pszStr[i + j];
            WCHAR c2 = pszSub[j];
            if (c1 >= L'a' && c1 <= L'z') c1 -= 32;
            if (c2 >= L'a' && c2 <= L'z') c2 -= 32;

            if (c1 != c2) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

static USBD_PIPE_HANDLE UsbHub_ResolvePipeHandleFromObject(
    _In_ PDEVICE_OBJECT pWinUsbFdo,
    _In_ PVOID pPipeObj)
{
    UNREFERENCED_PARAMETER(pWinUsbFdo);
    if (!pPipeObj) return NULL;

    ULONG_PTR raw = (ULONG_PTR)pPipeObj;
    USBD_PIPE_HANDLE hFound = NULL;

    __try
    {
        if (raw >= 0xFFFF800000000000ULL && MmIsAddressValid((PVOID)raw))
        {
            if ((raw & 0x7) == 0)
            {
                hFound = (USBD_PIPE_HANDLE)raw;
            }
        }

        PUCHAR pFx = (PUCHAR)((~raw) & ~7ULL);
        if (MmIsAddressValid(pFx) && MmIsAddressValid(pFx + 0x20))
        {
            if (raw & 1)
            {
                PUSHORT pOffset = (PUSHORT)pFx;
                if (MmIsAddressValid(pOffset))
                {
                    pFx -= *pOffset;
                }
            }

            if (MmIsAddressValid(pFx) && MmIsAddressValid(pFx + 0x20))
            {
                PUSHORT pType = (PUSHORT)(pFx + 8);
                if (MmIsAddressValid(pType) && *pType == 0x1203)
                {
                    PVOID *ppPipeHandle = (PVOID*)(pFx + 0x188);
                    if (MmIsAddressValid(ppPipeHandle) && *ppPipeHandle != NULL)
                    {
                        ULONG_PTR val = (ULONG_PTR)*ppPipeHandle;
                        if (val >= 0xFFFF800000000000ULL && MmIsAddressValid((PVOID)val))
                        {
                            return (USBD_PIPE_HANDLE)val;
                        }
                    }

                    for (ULONG off = 0x150; off <= 0x220; off += sizeof(PVOID))
                    {
                        PVOID *pCand = (PVOID*)(pFx + off);
                        if (MmIsAddressValid(pCand) && *pCand != NULL)
                        {
                            ULONG_PTR val = (ULONG_PTR)*pCand;
                            if (val >= 0xFFFF800000000000ULL && MmIsAddressValid((PVOID)val))
                            {
                                return (USBD_PIPE_HANDLE)val;
                            }
                        }
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}

static USBD_PIPE_HANDLE UsbHub_FindPipeHandleByContext(
    _In_ PDEVICE_OBJECT pFdo,
    _In_ UCHAR ep)
{
    if (!pFdo || !pFdo->DeviceExtension) return NULL;

    PUCHAR pDevExt = (PUCHAR)pFdo->DeviceExtension;
    if (!MmIsAddressValid(pDevExt)) return NULL;

    PUCHAR candidateExts[2] = { pDevExt, NULL };
    USHORT ctxOffset = *(PUSHORT)(pDevExt + 0x0A);
    if (ctxOffset > 0 && ctxOffset < 0x2000 && MmIsAddressValid(pDevExt + ctxOffset))
    {
        candidateExts[1] = pDevExt + ctxOffset + 0x30;
    }

    for (int c = 0; c < 2; c++)
    {
        PUCHAR pWinUsbDevExt = candidateExts[c];
        if (!pWinUsbDevExt || !MmIsAddressValid(pWinUsbDevExt)) continue;

        for (ULONG off = 0x10; off <= 0x150; off += sizeof(PVOID))
        {
            ULONG checkOff = (off == 0x10) ? 0x88 : off;

            PVOID *ppTable = (PVOID*)(pWinUsbDevExt + checkOff);
            if (!MmIsAddressValid(ppTable) || *ppTable == NULL) continue;

            ULONG_PTR tableAddr = (ULONG_PTR)*ppTable;
            if (tableAddr < 0xFFFF800000000000ULL || !MmIsAddressValid((PVOID)tableAddr)) continue;

            PUCHAR pPipeTable = (PUCHAR)tableAddr;

            for (ULONG slot = 0; slot < 64; slot++)
            {
                for (ULONG baseOff = 0; baseOff <= 0x18; baseOff += 0x18)
                {
                    PVOID *ppEntry = (PVOID*)(pPipeTable + slot * sizeof(PVOID) + baseOff);
                    if (!MmIsAddressValid(ppEntry) || *ppEntry == NULL) continue;

                    ULONG_PTR entryAddr = (ULONG_PTR)*ppEntry;
                    if (entryAddr < 0xFFFF800000000000ULL || !MmIsAddressValid((PVOID)entryAddr)) continue;

                    PUCHAR pPipeEntry = (PUCHAR)entryAddr;
                    if (!MmIsAddressValid(pPipeEntry + 0x30)) continue;

                    for (ULONG epOff = 0; epOff <= 24; epOff++)
                    {
                        if (*(PUCHAR)(pPipeEntry + epOff) == ep)
                        {
                            for (ULONG hOff = 0x20; hOff <= 0xD0; hOff += sizeof(PVOID))
                            {
                                if (MmIsAddressValid(pPipeEntry + hOff))
                                {
                                    PVOID hCand = *(PVOID*)(pPipeEntry + hOff);
                                    if (hCand != NULL)
                                    {
                                        USBD_PIPE_HANDLE hUsbd = UsbHub_ResolvePipeHandleFromObject(pFdo, hCand);
                                        if (hUsbd)
                                        {
                                            return hUsbd;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return NULL;
}

static USBD_PIPE_HANDLE UsbHub_ScanPipeHandle(
    _In_ PDEVICE_OBJECT pFdo,
    _In_ UCHAR ep)
{
    USBD_PIPE_HANDLE hPipe = UsbHub_FindPipeHandleByContext(pFdo, ep);
    if (hPipe) return hPipe;

    PUCHAR pBase = (PUCHAR)pFdo->DeviceExtension;
    if (!pBase || !MmIsAddressValid(pBase)) return NULL;

    for (ULONG off = 0; off <= 0x200; off += sizeof(PVOID))
    {
        PVOID *pCand = (PVOID*)(pBase + off);
        if (!MmIsAddressValid(pCand) || *pCand == NULL) continue;

        ULONG_PTR candAddr = (ULONG_PTR)*pCand;
        if (candAddr < 0xFFFF800000000000ULL || !MmIsAddressValid((PVOID)candAddr)) continue;

        PUCHAR pPtr = (PUCHAR)candAddr;

        if (MmIsAddressValid(pPtr + 0xB0))
        {
            UCHAR candEp   = *(PUCHAR)(pPtr + 0x08);
            ULONG pipeType = *(PULONG)(pPtr + 0x0C);
            ULONG maxPkt   = *(PULONG)(pPtr + 0x04);
            if (candEp == ep && pipeType == 2 && maxPkt >= 64 && maxPkt <= 1024)
            {
                PVOID hPipeObj = *(PVOID*)(pPtr + 0xA0);
                USBD_PIPE_HANDLE resolved = UsbHub_ResolvePipeHandleFromObject(pFdo, hPipeObj);
                if (resolved)
                {
                    return resolved;
                }
            }
        }
    }

    return NULL;
}

static PDEVICE_OBJECT UsbHub_PenetrateToHubPdo(
    _In_ PDEVICE_OBJECT pStartDev)
{
    if (!pStartDev) return NULL;

    PDEVICE_OBJECT pResult = NULL;

    if (pStartDev->DriverObject)
    {
        PDEVICE_OBJECT pDev = pStartDev->DriverObject->DeviceObject;
        while (pDev != NULL)
        {
            PDEVICE_OBJECT pLowerOfDev = IoGetLowerDeviceObject(pDev);
            if (pLowerOfDev != NULL)
            {
                if (pLowerOfDev->DriverObject && pLowerOfDev->DriverObject->DriverName.Buffer)
                {
                    UNICODE_STRING *pLowerDrvName = &pLowerOfDev->DriverObject->DriverName;

                    if (UsbHub_ContainsSubstrCaseless(pLowerDrvName->Buffer, pLowerDrvName->Length / sizeof(WCHAR), L"USBHUB3") ||
                        UsbHub_ContainsSubstrCaseless(pLowerDrvName->Buffer, pLowerDrvName->Length / sizeof(WCHAR), L"usbhub"))
                    {
                        pResult = pLowerOfDev;
                        ObReferenceObject(pResult);
                        ObDereferenceObject(pLowerOfDev);
                        break;
                    }
                    else
                    {
                        ObDereferenceObject(pLowerOfDev);
                    }
                }
                else
                {
                    ObDereferenceObject(pLowerOfDev);
                }
            }

            pDev = pDev->NextDevice;
        }
    }

    return pResult;
}

static NTSTATUS UsbHub_SubmitUrb(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PURB pUrb)
{
    UNREFERENCED_PARAMETER(UserVar);

    if (!g_pHubPdo)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KEVENT event;
    IO_STATUS_BLOCK iosb = { 0 };
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    PDEVICE_OBJECT pTarget = g_pHubPdo;

    PIRP pIrp = IoBuildDeviceIoControlRequest(
        IOCTL_INTERNAL_USB_SUBMIT_URB,
        pTarget,
        NULL, 0,
        NULL, 0,
        TRUE,
        &event,
        &iosb);

    if (!pIrp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PIO_STACK_LOCATION nextSp = IoGetNextIrpStackLocation(pIrp);
    nextSp->Parameters.Others.Argument1 = pUrb;

    PDRIVER_OBJECT pDrv = pTarget->DriverObject;
    PDRIVER_DISPATCH pCleanDispatch = NULL;

    if (pDrv)
    {
        PDRIVER_DISPATCH pHooked     = pDrv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
        PDRIVER_DISPATCH pDevControl = pDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL];

        BOOLEAN bInternalHooked   = FALSE;
        BOOLEAN bDevControlHooked = FALSE;

        ULONG_PTR fnInternal   = (ULONG_PTR)pHooked;
        ULONG_PTR fnDevControl = (ULONG_PTR)pDevControl;

        /* 1. 精确判定：检查是否落在 ACE / MockAce 模块地址空间内 */
        if (g_UsbAceBase && g_UsbAceEnd)
        {
            if (fnInternal >= g_UsbAceBase && fnInternal < g_UsbAceEnd)
            {
                bInternalHooked = TRUE;
            }
            if (fnDevControl >= g_UsbAceBase && fnDevControl < g_UsbAceEnd)
            {
                bDevControlHooked = TRUE;
            }
        }

        /* 2. 启发式防御：若 INTERNAL 与 DEVICE_CONTROL 不等，且脱离了驱动本身代码段 */
        if (!bInternalHooked && pHooked != pDevControl)
        {
            ULONG_PTR drvStart = (ULONG_PTR)pDrv->DriverStart;
            ULONG_PTR drvEnd   = drvStart + pDrv->DriverSize;
            if (drvStart && drvEnd && (fnInternal < drvStart || fnInternal >= drvEnd))
            {
                bInternalHooked = TRUE;
            }
        }

        /* 3. 核心安全防护：
         * 若两者均被 Hook，则拒绝投递数据并安全退出，避免向被劫持钩子暴露通信数据；
         * 若仅 INTERNAL 被 Hook，但 DEVICE_CONTROL 干净，则改走未挂钩的 DEVICE_CONTROL 通道。
         */
        if (bInternalHooked)
        {
            if (!pDevControl || bDevControlHooked)
            {
                MachenikePrint("UsbHub: Both dispatch pointers hooked by ACE, refusing to submit URB");
                IoFreeIrp(pIrp);
                return STATUS_ACCESS_DENIED;
            }

            pCleanDispatch = pDevControl;
        }
    }

    NTSTATUS status;
    if (pCleanDispatch)
    {
        pIrp->CurrentLocation--;
        pIrp->Tail.Overlay.CurrentStackLocation--;
        IoGetCurrentIrpStackLocation(pIrp)->DeviceObject = pTarget;
        status = pCleanDispatch(pTarget, pIrp);
    }
    else
    {
        status = IoCallDriver(pTarget, pIrp);
    }

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return status;
}

static VOID UsbHub_NeutralizeHooks(VOID)
{
    PCWSTR drvNames[] = {
        L"\\Driver\\USBHUB3",
        L"\\Driver\\WINUSB"
    };

    for (int i = 0; i < 2; i++)
    {
        UNICODE_STRING drvName;
        RtlInitUnicodeString(&drvName, drvNames[i]);
        PDRIVER_OBJECT pDrvObj = NULL;
        if (NT_SUCCESS(ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&pDrvObj)) && pDrvObj)
        {
            PDRIVER_DISPATCH pCleanDispatch = pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];

            if (pCleanDispatch != NULL)
            {
                /* 1. 脱钩还原 IRP_MJ_INTERNAL_DEVICE_CONTROL */
                ULONG_PTR fnInternal = (ULONG_PTR)pDrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
                BOOLEAN bHookInternal = FALSE;
                if (g_UsbAceBase && g_UsbAceEnd && fnInternal >= g_UsbAceBase && fnInternal < g_UsbAceEnd)
                    bHookInternal = TRUE;
                else if (pDrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] != pCleanDispatch)
                    bHookInternal = TRUE;

                if (bHookInternal)
                {
                    InterlockedExchangePointer((PVOID*)&pDrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL], (PVOID)pCleanDispatch);
                }

                /* 2. 脱钩还原 IRP_MJ_PNP */
                ULONG_PTR fnPnp = (ULONG_PTR)pDrvObj->MajorFunction[IRP_MJ_PNP];
                BOOLEAN bHookPnp = FALSE;
                if (g_UsbAceBase && g_UsbAceEnd && fnPnp >= g_UsbAceBase && fnPnp < g_UsbAceEnd)
                    bHookPnp = TRUE;
                else if (pDrvObj->MajorFunction[IRP_MJ_PNP] != pCleanDispatch)
                    bHookPnp = TRUE;

                if (bHookPnp)
                {
                    InterlockedExchangePointer((PVOID*)&pDrvObj->MajorFunction[IRP_MJ_PNP], (PVOID)pCleanDispatch);
                }
            }
            ObDereferenceObject(pDrvObj);
        }
    }
}

NTSTATUS UsbHub_Init(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PDEVICE_OBJECT pBaseDev,
    _In_ UCHAR epIn,
    _In_ UCHAR epOut)
{
    UNREFERENCED_PARAMETER(UserVar);

    if (!pBaseDev || !pBaseDev->DriverObject)
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

    g_pWinUsbFdo = pTargetFdo;
    g_EpIn       = epIn;
    g_EpOut      = epOut;

    g_PipeHandleIn  = UsbHub_ScanPipeHandle(pTargetFdo, epIn);
    g_PipeHandleOut = UsbHub_ScanPipeHandle(pTargetFdo, epOut);

    if (!g_PipeHandleIn || !g_PipeHandleOut)
    {
        return STATUS_NOT_FOUND;
    }

    PDEVICE_OBJECT pLower = IoGetLowerDeviceObject(pTargetFdo);
    if (!pLower)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    g_pLowerDev = pLower;

    g_pHubPdo = UsbHub_PenetrateToHubPdo(pLower);
    if (!g_pHubPdo)
    {
        return STATUS_NOT_FOUND;
    }

    g_HubReady = TRUE;
    return STATUS_SUCCESS;
}

VOID UsbHub_Cleanup(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);

    g_HubReady         = FALSE;
    g_PipeHandleIn     = NULL;
    g_PipeHandleOut    = NULL;
    g_pWinUsbFdo       = NULL;
    g_EpIn             = 0;
    g_EpOut            = 0;

    if (g_pHubPdo)
    {
        ObDereferenceObject(g_pHubPdo);
        g_pHubPdo = NULL;
    }

    if (g_pLowerDev)
    {
        ObDereferenceObject(g_pLowerDev);
        g_pLowerDev = NULL;
    }
}

NTSTATUS UsbHub_BulkRead(
    _In_  MACHENIKE_KERNEL_INTERFACE *UserVar,
    _Out_ PVOID pBuf,
    _In_  ULONG cbBuf,
    _Out_ PULONG pcbRead)
{
    if (pcbRead) *pcbRead = 0;
    if (!g_HubReady || !g_PipeHandleIn) return STATUS_DEVICE_NOT_READY;
    if (!pBuf || cbBuf == 0) return STATUS_INVALID_PARAMETER;

    struct _URB_BULK_OR_INTERRUPT_TRANSFER urb;
    RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length               = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    urb.Hdr.Function             = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    urb.PipeHandle               = g_PipeHandleIn;
    urb.TransferFlags            = USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK;
    urb.TransferBufferLength     = cbBuf;
    urb.TransferBuffer           = pBuf;

    PMDL pMdl = IoAllocateMdl(pBuf, cbBuf, FALSE, FALSE, NULL);
    if (pMdl)
    {
        MmBuildMdlForNonPagedPool(pMdl);
        urb.TransferBufferMDL = pMdl;
    }

    NTSTATUS status = UsbHub_SubmitUrb(UserVar, (PURB)&urb);

    if (pMdl)
    {
        IoFreeMdl(pMdl);
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

NTSTATUS UsbHub_BulkWrite(
    _In_  MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_  PVOID pBuf,
    _In_  ULONG cbBuf,
    _Out_ PULONG pcbWritten)
{
    if (pcbWritten) *pcbWritten = 0;
    if (!g_HubReady || !g_PipeHandleOut) return STATUS_DEVICE_NOT_READY;
    if (!pBuf || cbBuf == 0) return STATUS_INVALID_PARAMETER;

    struct _URB_BULK_OR_INTERRUPT_TRANSFER urb;
    RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length               = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    urb.Hdr.Function             = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    urb.PipeHandle               = g_PipeHandleOut;
    urb.TransferFlags            = USBD_TRANSFER_DIRECTION_OUT;
    urb.TransferBufferLength     = cbBuf;
    urb.TransferBuffer           = pBuf;

    PMDL pMdl = IoAllocateMdl(pBuf, cbBuf, FALSE, FALSE, NULL);
    if (pMdl)
    {
        MmBuildMdlForNonPagedPool(pMdl);
        urb.TransferBufferMDL = pMdl;
    }

    NTSTATUS status = UsbHub_SubmitUrb(UserVar, (PURB)&urb);

    if (pMdl)
    {
        IoFreeMdl(pMdl);
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

NTSTATUS UsbHub_AbortPipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ BOOLEAN bIsIn)
{
    USBD_PIPE_HANDLE hPipe = bIsIn ? g_PipeHandleIn : g_PipeHandleOut;
    if (!g_HubReady || !hPipe) return STATUS_DEVICE_NOT_READY;

    struct _URB_PIPE_REQUEST urb;
    RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length   = sizeof(struct _URB_PIPE_REQUEST);
    urb.Hdr.Function = URB_FUNCTION_ABORT_PIPE;
    urb.PipeHandle   = hPipe;

    return UsbHub_SubmitUrb(UserVar, (PURB)&urb);
}

NTSTATUS UsbHub_ResetPipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ BOOLEAN bIsIn)
{
    USBD_PIPE_HANDLE hPipe = bIsIn ? g_PipeHandleIn : g_PipeHandleOut;
    if (!g_HubReady || !hPipe) return STATUS_DEVICE_NOT_READY;

    struct _URB_PIPE_REQUEST urb;
    RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length   = sizeof(struct _URB_PIPE_REQUEST);
    urb.Hdr.Function = URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL;
    urb.PipeHandle   = hPipe;

    return UsbHub_SubmitUrb(UserVar, (PURB)&urb);
}

BOOLEAN UsbHub_IsReady(VOID)
{
    return g_HubReady;
}

BOOLEAN UsbHub_HasAceInfo(VOID)
{
    return g_UsbAceBase != 0;
}
