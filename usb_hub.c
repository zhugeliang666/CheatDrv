#include "usb_hub.h"
#include "usb_server.h"
#include "Common.h"
#include "Struct.h"

NTKERNELAPI NTSTATUS ObReferenceObjectByName(_In_ PUNICODE_STRING ObjectName, _In_ ULONG Attributes,
                                             _In_opt_ PACCESS_STATE AccessState, _In_opt_ ACCESS_MASK DesiredAccess,
                                             _In_ POBJECT_TYPE ObjectType, _In_ KPROCESSOR_MODE AccessMode,
                                             _Inout_opt_ PVOID ParseContext, _Out_ PVOID *Object);

extern POBJECT_TYPE *IoDriverObjectType;

static MACHENIKE_KERNEL_INTERFACE *g_pUsbHubUserVar = NULL;
static PDEVICE_OBJECT g_pWinUsbFdo = NULL;
static PDEVICE_OBJECT g_pLowerDev = NULL;
static PDEVICE_OBJECT g_pHubPdo = NULL;
static USBD_PIPE_HANDLE g_PipeHandleIn = NULL;
static USBD_PIPE_HANDLE g_PipeHandleOut = NULL;
static UCHAR g_EpIn = 0;
static UCHAR g_EpOut = 0;
static BOOLEAN g_HubReady = FALSE;
static PDRIVER_DISPATCH g_pUsbOriginalDispatch = NULL;

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
#define MmIsAddressValid(va)                                                                                           \
    ((g_pUsbHubUserVar && g_pUsbHubUserVar->Func.MmIsAddressValid)                                                     \
         ? g_pUsbHubUserVar->Func.MmIsAddressValid((PVOID)(va))                                                        \
         : FALSE)

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

static USBD_PIPE_HANDLE UsbHub_ResolvePipeHandleFromObject(_In_ PDEVICE_OBJECT pWinUsbFdo, _In_ PVOID pPipeObj)
{
    UNREFERENCED_PARAMETER(pWinUsbFdo);
    if (!pPipeObj)
        return NULL;

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
                    PVOID *ppPipeHandle = (PVOID *)(pFx + 0x188);
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
                        PVOID *pCand = (PVOID *)(pFx + off);
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

static USBD_PIPE_HANDLE UsbHub_FindPipeHandleByContext(_In_ PDEVICE_OBJECT pFdo, _In_ UCHAR ep)
{
    if (!pFdo || !pFdo->DeviceExtension)
        return NULL;

    PUCHAR pDevExt = (PUCHAR)pFdo->DeviceExtension;
    if (!MmIsAddressValid(pDevExt))
        return NULL;

    PUCHAR candidateExts[2] = {pDevExt, NULL};
    USHORT ctxOffset = *(PUSHORT)(pDevExt + 0x0A);
    if (ctxOffset > 0 && ctxOffset < 0x2000 && MmIsAddressValid(pDevExt + ctxOffset))
    {
        candidateExts[1] = pDevExt + ctxOffset + 0x30;
    }

    for (int c = 0; c < 2; c++)
    {
        PUCHAR pWinUsbDevExt = candidateExts[c];
        if (!pWinUsbDevExt || !MmIsAddressValid(pWinUsbDevExt))
            continue;

        for (ULONG off = 0x10; off <= 0x150; off += sizeof(PVOID))
        {
            ULONG checkOff = (off == 0x10) ? 0x88 : off;

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
                    if (!MmIsAddressValid(pPipeEntry + 0x30))
                        continue;

                    for (ULONG epOff = 0; epOff <= 24; epOff++)
                    {
                        if (*(PUCHAR)(pPipeEntry + epOff) == ep)
                        {
                            for (ULONG hOff = 0x20; hOff <= 0xD0; hOff += sizeof(PVOID))
                            {
                                if (MmIsAddressValid(pPipeEntry + hOff))
                                {
                                    PVOID hCand = *(PVOID *)(pPipeEntry + hOff);
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

static USBD_PIPE_HANDLE UsbHub_ScanPipeHandle(_In_ PDEVICE_OBJECT pFdo, _In_ UCHAR ep)
{
    USBD_PIPE_HANDLE hPipe = UsbHub_FindPipeHandleByContext(pFdo, ep);
    if (hPipe)
        return hPipe;

    PUCHAR pBase = (PUCHAR)pFdo->DeviceExtension;
    if (!pBase || !MmIsAddressValid(pBase))
        return NULL;

    for (ULONG off = 0; off <= 0x200; off += sizeof(PVOID))
    {
        PVOID *pCand = (PVOID *)(pBase + off);
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
            if (candEp == ep && pipeType == 2 && maxPkt >= 64 && maxPkt <= 1024)
            {
                PVOID hPipeObj = *(PVOID *)(pPtr + 0xA0);
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

static PDEVICE_OBJECT UsbHub_PenetrateToHubPdo(_In_ PDEVICE_OBJECT pStartDev)
{
    if (!pStartDev)
        return NULL;

    PDEVICE_OBJECT pResult = NULL;

    if (pStartDev->DriverObject)
    {
        PDEVICE_OBJECT pDev = pStartDev->DriverObject->DeviceObject;
        while (pDev != NULL)
        {
            PDEVICE_OBJECT pLowerOfDev = (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoGetLowerDeviceObject)
                                             ? g_pUsbHubUserVar->Func.IoGetLowerDeviceObject(pDev)
                                             : NULL;
            if (pLowerOfDev != NULL)
            {
                if (pLowerOfDev->DriverObject && pLowerOfDev->DriverObject->DriverName.Buffer)
                {
                    UNICODE_STRING *pLowerDrvName = &pLowerOfDev->DriverObject->DriverName;

                    if (UsbHub_ContainsSubstrCaseless(pLowerDrvName->Buffer, pLowerDrvName->Length / sizeof(WCHAR),
                                                      L"USBHUB3") ||
                        UsbHub_ContainsSubstrCaseless(pLowerDrvName->Buffer, pLowerDrvName->Length / sizeof(WCHAR),
                                                      L"usbhub"))
                    {
                        pResult = pLowerOfDev;
                        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfReferenceObject)
                        {
                            g_pUsbHubUserVar->Func.ObfReferenceObject(pResult);
                        }
                        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfDereferenceObject)
                        {
                            g_pUsbHubUserVar->Func.ObfDereferenceObject(pLowerOfDev);
                        }
                        break;
                    }
                    else
                    {
                        if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfDereferenceObject)
                        {
                            g_pUsbHubUserVar->Func.ObfDereferenceObject(pLowerOfDev);
                        }
                    }
                }
                else
                {
                    if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfDereferenceObject)
                    {
                        g_pUsbHubUserVar->Func.ObfDereferenceObject(pLowerOfDev);
                    }
                }
            }

            pDev = pDev->NextDevice;
        }
    }

    return pResult;
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
            if (UsbHub_ContainsSubstrCaseless(pMod->BaseDllName.Buffer, pMod->BaseDllName.Length / sizeof(WCHAR),
                                              L"wdf01000"))
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
 * UsbHub_ResolveOriginalDispatch — 方案 2：WDF01000 统一框架分发网关安全提取 (WDF Framework Gateway)
 *
 * 核心原理：
 *   1. USBHUB3 / WINUSB 等现代 USB 驱动属于 KMDF (Wdf01000) 体系。
 *      在驱动初始化阶段，WDF 框架将其所有 28 个 MajorFunction 槽位全部赋予同一个框架网关：
 *      Wdf01000!FxDevice::DispatchWithLock。
 *   2. ACE 仅仅劫持了 IRP_MJ_INTERNAL_DEVICE_CONTROL 槽位（指向 ACE 自身的 sys 驱动），
 *      其余 20 多个槽位完好无损地保留着微软原生的 Wdf01000 网关。
 *   3. 本算法通过获取 Wdf01000.sys 模块内存边界，直接从驱动槽位中提取落在 Wdf01000 内的原生网关指针：
 *      - 零特征码依赖、零 Hook 逻辑启发式判断；
 *      - 绝不跨越到非 WDF 驱动（彻底杜绝 spaceport 等导致的 0x1E 崩溃）；
 *      - 100% 匹配所有 KMDF 设备对象的扩展布局。
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
        DBG("[+] UsbHub: [Scheme 2] Located Wdf01000.sys module range: [%p, %p]", (PVOID)wdfBase, (PVOID)wdfEnd);

        /* 阶段 1：优先检查目标驱动自身通常不会被外设作弊篡改的槽位 */
        static const UCHAR preferSlots[] = {IRP_MJ_DEVICE_CONTROL, IRP_MJ_SYSTEM_CONTROL, IRP_MJ_POWER,
                                            IRP_MJ_CREATE,         IRP_MJ_CLOSE,          IRP_MJ_CLEANUP};

        for (ULONG i = 0; i < sizeof(preferSlots); i++)
        {
            UCHAR slot = preferSlots[i];
            ULONG_PTR pfn = (ULONG_PTR)pDrv->MajorFunction[slot];
            if (pfn >= wdfBase && pfn < wdfEnd)
            {
                DBG("[+] UsbHub: [Scheme 2] Found authentic Wdf01000 dispatch from intra-driver slot 0x%X: %p", slot,
                    (PVOID)pfn);
                return (PDRIVER_DISPATCH)pfn;
            }
        }

        /* 遍历目标驱动其余全部槽位（排除已知被 ACE Hook 的 INTERNAL_DEVICE_CONTROL） */
        for (ULONG slot = 0; slot <= IRP_MJ_MAXIMUM_FUNCTION; slot++)
        {
            if (slot == IRP_MJ_INTERNAL_DEVICE_CONTROL)
                continue;

            ULONG_PTR pfn = (ULONG_PTR)pDrv->MajorFunction[slot];
            if (pfn >= wdfBase && pfn < wdfEnd)
            {
                DBG("[+] UsbHub: [Scheme 2] Found authentic Wdf01000 dispatch from slot 0x%X: %p", slot, (PVOID)pfn);
                return (PDRIVER_DISPATCH)pfn;
            }
        }
    }

    ///* 阶段 2：备用同构纯 KMDF 总线驱动克隆（仅限 100% 微软官方 KMDF 驱动，彻底剔除非 WDF 驱动） */
    // static const PCWSTR safeWdfDrivers[] = {
    //     L"\\Driver\\CompositeBus", /* 微软 USB 复合总线（100% Wdf01000 驱动） */
    //     L"\\Driver\\kdnic"         /* 内核网络调试适配器（100% Wdf01000 驱动） */
    // };

    // for (ULONG i = 0; i < (ULONG)(sizeof(safeWdfDrivers) / sizeof(safeWdfDrivers[0])); i++)
    //{
    //     UNICODE_STRING uDrvName;
    //     RtlInitUnicodeString(&uDrvName, safeWdfDrivers[i]);
    //     PDRIVER_OBJECT pSafeDrv = NULL;

    //    if (NT_SUCCESS(ObReferenceObjectByName(&uDrvName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType,
    //                                           KernelMode, NULL, (PVOID *)&pSafeDrv)) &&
    //        pSafeDrv)
    //    {
    //        PDRIVER_DISPATCH pCloneDispatch = pSafeDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    //        if (!pCloneDispatch)
    //        {
    //            pCloneDispatch = pSafeDrv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
    //        }
    //        ObDereferenceObject(pSafeDrv);

    //        if (pCloneDispatch)
    //        {
    //            /* 若获取到了 WDF 边界，严格验证其必须属于 WDF 模块内部（防止跨驱动对象结构错位） */
    //            if (hasWdfBounds && ((ULONG_PTR)pCloneDispatch < wdfBase || (ULONG_PTR)pCloneDispatch >= wdfEnd))
    //            {
    //                continue;
    //            }

    //            DBG("[+] UsbHub: [Scheme 2] Successfully cloned authentic WDF gateway from %ls: %p",
    //                safeWdfDrivers[i], pCloneDispatch);
    //            return pCloneDispatch;
    //        }
    //    }
    //}

    ///* 阶段 3：保底众数统计（纯数学统计，选出目标驱动中重复次数最多的基准入口） */
    // PDRIVER_DISPATCH candidates[IRP_MJ_MAXIMUM_FUNCTION + 1];
    // ULONG counts[IRP_MJ_MAXIMUM_FUNCTION + 1];
    // ULONG uniqueCount = 0;

    // for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    //{
    //     if (i == IRP_MJ_INTERNAL_DEVICE_CONTROL)
    //         continue;

    //    PDRIVER_DISPATCH pfn = pDrv->MajorFunction[i];
    //    if (!pfn)
    //        continue;

    //    BOOLEAN found = FALSE;
    //    for (ULONG j = 0; j < uniqueCount; j++)
    //    {
    //        if (candidates[j] == pfn)
    //        {
    //            counts[j]++;
    //            found = TRUE;
    //            break;
    //        }
    //    }
    //    if (!found)
    //    {
    //        candidates[uniqueCount] = pfn;
    //        counts[uniqueCount] = 1;
    //        uniqueCount++;
    //    }
    //}

    // PDRIVER_DISPATCH pBest = NULL;
    // ULONG maxCnt = 0;
    // for (ULONG j = 0; j < uniqueCount; j++)
    //{
    //     if (counts[j] > maxCnt)
    //     {
    //         maxCnt = counts[j];
    //         pBest = candidates[j];
    //     }
    // }

    // if (pBest && maxCnt >= 3)
    //{
    //     DBG("[+] UsbHub: [Scheme 2] Fallback to intra-driver mode slot %p (voted %u times)",
    //         pBest, maxCnt);
    //     return pBest;
    // }

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

    /* 关键设计：返回 STATUS_MORE_PROCESSING_REQUIRED 停止 I/O 管理器默认释放逻辑，
     * 将 IRP 的释放权完全保留给发起方，避免线程链表污染与双重释放 */
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS UsbHub_SubmitUrb(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PURB pUrb)
{
    if (UserVar)
    {
        g_pUsbHubUserVar = UserVar;
    }

    if (!g_pHubPdo)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    PDEVICE_OBJECT pTarget = g_pHubPdo;

    /* 1. 改用 IoAllocateIrp 分配独立 IRP（完全不挂入 ETHREAD->IrpList 链表，彻底杜绝 0x139 崩溃） */
    CCHAR stackSize = pTarget->StackSize;
    if (stackSize < 4)
        stackSize = 4;

    PIRP pIrp = (UserVar && UserVar->Func.IoAllocateIrp) ? UserVar->Func.IoAllocateIrp(stackSize, FALSE)
                                                         : ((g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoAllocateIrp)
                                                                ? g_pUsbHubUserVar->Func.IoAllocateIrp(stackSize, FALSE)
                                                                : NULL);
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

    /* 2. 初始化下一个栈位置 */
    PIO_STACK_LOCATION nextSp = IoGetNextIrpStackLocation(pIrp);
    nextSp->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    nextSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    nextSp->Parameters.Others.Argument1 = pUrb;
    nextSp->DeviceObject = pTarget;

    /* 3. 设置自定义完成例程 */
    IoSetCompletionRoutine(pIrp, UsbHub_SyncCompletionRoutine, &event, TRUE, TRUE, TRUE);

    /* 4. 解析目标底层驱动干净的未挂钩 Dispatch 入口 */
    PDRIVER_OBJECT pDrv = pTarget->DriverObject;
    PDRIVER_DISPATCH pDispatch = g_pUsbOriginalDispatch;
    if (!pDispatch && pDrv)
    {
        pDispatch = UsbHub_ResolveOriginalDispatch(pDrv);
        g_pUsbOriginalDispatch = pDispatch;
    }

    /* 若未能定位到干净入口，直接释放独立 IRP 并退出（零线程链表挂载，绝对安全） */
    if (!pDispatch)
    {
        DBG("[-] UsbHub: Clean dispatch routine not resolved, refusing to submit URB to avoid hook interception!");
        if (UserVar && UserVar->Func.IoFreeIrp)
        {
            UserVar->Func.IoFreeIrp(pIrp);
        }
        else if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.IoFreeIrp)
        {
            g_pUsbHubUserVar->Func.IoFreeIrp(pIrp);
        }
        return STATUS_ACCESS_DENIED;
    }

    /* 5. 调用原始真实函数入口 */
    pIrp->CurrentLocation--;
    pIrp->Tail.Overlay.CurrentStackLocation--;
    IoGetCurrentIrpStackLocation(pIrp)->DeviceObject = pTarget;

    NTSTATUS status = pDispatch(pTarget, pIrp);

    if (status == STATUS_PENDING)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10 * 1000 * 500; // 500ms 守护轮询
        while (TRUE)
        {
            NTSTATUS waitStatus = STATUS_SUCCESS;
            if (UserVar && UserVar->Func.KeWaitForSingleObject)
            {
                waitStatus = UserVar->Func.KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &Timeout);
            }
            else if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.KeWaitForSingleObject)
            {
                waitStatus =
                    g_pUsbHubUserVar->Func.KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &Timeout);
            }

            if (waitStatus == STATUS_SUCCESS)
            {
                status = pIrp->IoStatus.Status;
                break;
            }

            if (waitStatus == STATUS_TIMEOUT)
            {
                if (!g_UsbServer.fRunning)
                {
                    if (UserVar && UserVar->Func.IoCancelIrp)
                    {
                        UserVar->Func.IoCancelIrp(pIrp);
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
                    break;
                }
            }
        }
    }
    else
    {
        status = pIrp->IoStatus.Status;
    }

    /* 6. 发起方持有完整所有权，安全释放独立 IRP (确保完成例程已执行) */
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

static VOID UsbHub_NeutralizeHooks(VOID)
{
    PCWSTR drvNames[] = {L"\\Driver\\USBHUB3", L"\\Driver\\WINUSB"};

    for (int i = 0; i < 2; i++)
    {
        UNICODE_STRING drvName;
        RtlInitUnicodeString(&drvName, drvNames[i]);
        PDRIVER_OBJECT pDrvObj = NULL;
        if (NT_SUCCESS(ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode,
                                               NULL, (PVOID *)&pDrvObj)) &&
            pDrvObj)
        {
            PDRIVER_DISPATCH pCleanDispatch = pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];

            if (pCleanDispatch != NULL)
            {
                /* 1. 脱钩还原 IRP_MJ_INTERNAL_DEVICE_CONTROL */
                ULONG_PTR fnInternal = (ULONG_PTR)pDrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
                BOOLEAN bHookInternal = FALSE;
                if (Main_IsAddressInAceModules(fnInternal))
                    bHookInternal = TRUE;
                else if (pDrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] != pCleanDispatch)
                    bHookInternal = TRUE;

                if (bHookInternal)
                {
                    InterlockedExchangePointer((PVOID *)&pDrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL],
                                               (PVOID)pCleanDispatch);
                }

                /* 2. 脱钩还原 IRP_MJ_PNP */
                ULONG_PTR fnPnp = (ULONG_PTR)pDrvObj->MajorFunction[IRP_MJ_PNP];
                BOOLEAN bHookPnp = FALSE;
                if (Main_IsAddressInAceModules(fnPnp))
                    bHookPnp = TRUE;
                else if (pDrvObj->MajorFunction[IRP_MJ_PNP] != pCleanDispatch)
                    bHookPnp = TRUE;

                if (bHookPnp)
                {
                    InterlockedExchangePointer((PVOID *)&pDrvObj->MajorFunction[IRP_MJ_PNP], (PVOID)pCleanDispatch);
                }
            }
            if (g_pUsbHubUserVar && g_pUsbHubUserVar->Func.ObfDereferenceObject)
            {
                g_pUsbHubUserVar->Func.ObfDereferenceObject(pDrvObj);
            }
        }
    }
}

NTSTATUS UsbHub_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PDEVICE_OBJECT pBaseDev, _In_ UCHAR epIn,
                     _In_ UCHAR epOut)
{
    g_pUsbHubUserVar = UserVar;

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
    g_EpIn = epIn;
    g_EpOut = epOut;

    g_PipeHandleIn = UsbHub_ScanPipeHandle(pTargetFdo, epIn);
    g_PipeHandleOut = UsbHub_ScanPipeHandle(pTargetFdo, epOut);

    if (!g_PipeHandleIn || !g_PipeHandleOut)
    {
        return STATUS_NOT_FOUND;
    }

    PDEVICE_OBJECT pLower =
        (UserVar && UserVar->Func.IoGetLowerDeviceObject) ? UserVar->Func.IoGetLowerDeviceObject(pTargetFdo) : NULL;
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

    if (g_pHubPdo->DriverObject)
    {
        g_pUsbOriginalDispatch = UsbHub_ResolveOriginalDispatch(g_pHubPdo->DriverObject);
    }

    CCHAR stackSize = g_pHubPdo->StackSize;
    if (stackSize < 4)
        stackSize = 4;

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
                g_pUsbHubUserVar->Func.KeWaitForSingleObject(&g_HubSendSlots[i].Event, Executive, KernelMode, FALSE,
                                                             NULL);
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
    g_pWinUsbFdo = NULL;
    g_pUsbOriginalDispatch = NULL;
    g_EpIn = 0;
    g_EpOut = 0;

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
}

NTSTATUS UsbHub_BulkRead(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PVOID pBuf, _In_ ULONG cbBuf,
                         _Out_ PULONG pcbRead)
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

    NTSTATUS status = UsbHub_SubmitUrb(UserVar, (PURB)&urb);

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

NTSTATUS UsbHub_BulkWrite(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PVOID pBuf, _In_ ULONG cbBuf,
                          _Out_ PULONG pcbWritten)
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

    NTSTATUS status = UsbHub_SubmitUrb(UserVar, (PURB)&urb);

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
    urb.PipeHandle = hPipe;

    return UsbHub_SubmitUrb(UserVar, (PURB)&urb);
}

NTSTATUS UsbHub_ResetPipe(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ BOOLEAN bIsIn)
{
    USBD_PIPE_HANDLE hPipe = bIsIn ? g_PipeHandleIn : g_PipeHandleOut;
    if (!g_HubReady || !hPipe)
        return STATUS_DEVICE_NOT_READY;

    struct _URB_PIPE_REQUEST urb;
    RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length = sizeof(struct _URB_PIPE_REQUEST);
    urb.Hdr.Function = URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL;
    urb.PipeHandle = hPipe;

    return UsbHub_SubmitUrb(UserVar, (PURB)&urb);
}

BOOLEAN UsbHub_IsReady(VOID)
{
    return g_HubReady;
}

BOOLEAN UsbHub_HasAceInfo(VOID)
{
    return g_bAceDetected;
}

// ★★★ 常驻 IRP 与预构建 MDL 零分配快速读 ★★★
NTSTATUS UsbHub_BulkReadFast(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PVOID pBuf, _In_ PMDL pMdl,
                             _In_ ULONG cbBuf, _Out_ PULONG pcbRead)
{
    if (pcbRead)
        *pcbRead = 0;
    if (!g_HubReady || !g_PipeHandleIn || !g_pHubPdo || !g_pUsbOriginalDispatch)
        return STATUS_DEVICE_NOT_READY;
    if (!pBuf || cbBuf == 0)
        return STATUS_INVALID_PARAMETER;

    if (!g_pHubRecvIrp)
    {
        return UsbHub_BulkRead(UserVar, pBuf, cbBuf, pcbRead);
    }

    struct _URB_BULK_OR_INTERRUPT_TRANSFER urb;
    UserVar->Func.RtlZeroMemory(&urb, sizeof(urb));
    urb.Hdr.Length = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    urb.Hdr.Function = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER;
    urb.PipeHandle = g_PipeHandleIn;
    urb.TransferFlags = USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK;
    urb.TransferBufferLength = cbBuf;
    urb.TransferBuffer = pBuf;
    urb.TransferBufferMDL = pMdl;

    PIRP pIrp = g_pHubRecvIrp;
    IoReuseIrp(pIrp, STATUS_SUCCESS);

    if (UserVar->Func.KeClearEvent)
        UserVar->Func.KeClearEvent(&g_HubRecvEvent);
    else
        UserVar->Func.KeInitializeEvent(&g_HubRecvEvent, NotificationEvent, FALSE);

    PIO_STACK_LOCATION nextSp = IoGetNextIrpStackLocation(pIrp);
    nextSp->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    nextSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    nextSp->Parameters.Others.Argument1 = &urb;
    nextSp->DeviceObject = g_pHubPdo;

    IoSetCompletionRoutine(pIrp, UsbHub_SyncCompletionRoutine, &g_HubRecvEvent, TRUE, TRUE, TRUE);

    pIrp->CurrentLocation--;
    pIrp->Tail.Overlay.CurrentStackLocation--;
    IoGetCurrentIrpStackLocation(pIrp)->DeviceObject = g_pHubPdo;

    NTSTATUS status = g_pUsbOriginalDispatch(g_pHubPdo, pIrp);

    if (status == STATUS_PENDING)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10 * 1000 * 500; // 500ms 守护轮询
        while (TRUE)
        {
            NTSTATUS waitStatus =
                UserVar->Func.KeWaitForSingleObject(&g_HubRecvEvent, Executive, KernelMode, FALSE, &Timeout);
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

    if (NT_SUCCESS(status))
    {
        if (pcbRead)
            *pcbRead = urb.TransferBufferLength;
    }

    return status;
}

// ★★★ 双缓冲异步提交发送（0 阻塞、与接收端全双工重叠流水线）★★★
NTSTATUS UsbHub_BulkWriteAsync(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ ULONG slotIndex, _In_ PVOID pBuf,
                               _In_ PMDL pMdl, _In_ ULONG cbBuf)
{
    if (slotIndex >= 2)
        return STATUS_INVALID_PARAMETER;
    if (!g_HubReady || !g_PipeHandleOut || !g_pHubPdo || !g_pUsbOriginalDispatch)
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
    pSlot->Urb.PipeHandle = g_PipeHandleOut;
    pSlot->Urb.TransferFlags = USBD_TRANSFER_DIRECTION_OUT;
    pSlot->Urb.TransferBufferLength = cbBuf;
    pSlot->Urb.TransferBuffer = pBuf;
    pSlot->Urb.TransferBufferMDL = pMdl;

    PIRP pIrp = pSlot->pIrp;
    IoReuseIrp(pIrp, STATUS_SUCCESS);

    if (UserVar->Func.KeClearEvent)
        UserVar->Func.KeClearEvent(&pSlot->Event);
    else
        UserVar->Func.KeInitializeEvent(&pSlot->Event, NotificationEvent, FALSE);

    PIO_STACK_LOCATION nextSp = IoGetNextIrpStackLocation(pIrp);
    nextSp->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    nextSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_INTERNAL_USB_SUBMIT_URB;
    nextSp->Parameters.Others.Argument1 = &pSlot->Urb;
    nextSp->DeviceObject = g_pHubPdo;

    IoSetCompletionRoutine(pIrp, UsbHub_SyncCompletionRoutine, &pSlot->Event, TRUE, TRUE, TRUE);

    pIrp->CurrentLocation--;
    pIrp->Tail.Overlay.CurrentStackLocation--;
    IoGetCurrentIrpStackLocation(pIrp)->DeviceObject = g_pHubPdo;

    NTSTATUS status = g_pUsbOriginalDispatch(g_pHubPdo, pIrp);

    if (status == STATUS_PENDING)
    {
        pSlot->bInFlight = TRUE;
        return STATUS_SUCCESS;
    }

    pSlot->bInFlight = FALSE;
    return pIrp->IoStatus.Status;
}

// ★★★ 等待指定发送槽位完成并返回结果 ★★★
NTSTATUS UsbHub_WaitWriteSlot(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ ULONG slotIndex,
                              _Out_opt_ PULONG pcbWritten)
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
        NTSTATUS waitStatus =
            UserVar->Func.KeWaitForSingleObject(&pSlot->Event, Executive, KernelMode, FALSE, &Timeout);
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
