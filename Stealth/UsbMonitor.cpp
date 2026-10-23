#include "UsbMonitor.h"
#include "Utils.h"
#include "ExceptionReporter.h"

/*
 * ============================================================================
 * UsbMonitor: 内核 USB 链路安全监控引擎
 *
 * 核心设计铁律：
 * 1. 100% 纯只读巡检，严禁对任何第三方系统驱动的函数指针执行覆写或脱钩中和，
 *    彻底杜绝触碰 PatchGuard (0x109) 与 HVCI 只读违例 (0xBE)。
 * 2. 覆盖关键 USB 驱动（USBHUB3, USBXHCI, WINUSB, usbccgp, usbhub）。
 * 3. 前置 ACE 存活门禁 + 跨页范围安全探针 + 单次去重上报机制。
 * ============================================================================
 */

static MACHENIKE_KERNEL_INTERFACE *g_pUsbMonUserVar = NULL;
VOID UsbMonitor::SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar) { g_pUsbMonUserVar = UserVar; }

#define RtlInitUnicodeString SafeInitUnicodeString

static const PCWSTR g_MonitoredUsbDrivers[] = {
    L"\\Driver\\USBHUB3",
    L"\\Driver\\USBXHCI",
    L"\\Driver\\WINUSB",
    L"\\Driver\\usbccgp",
    L"\\Driver\\usbhub"
};

#define MONITORED_USB_DRIVER_COUNT (sizeof(g_MonitoredUsbDrivers) / sizeof(g_MonitoredUsbDrivers[0]))

static UINT32 s_ReportedUsbMajorMask[MONITORED_USB_DRIVER_COUNT] = {0};
static UINT32 s_ReportedUsbInlineMask[MONITORED_USB_DRIVER_COUNT] = {0};
static BOOLEAN s_ReportedUsbAttached[MONITORED_USB_DRIVER_COUNT] = {FALSE};

VOID UsbMonitor::ResetReportState(VOID)
{
    RtlZeroMemory(s_ReportedUsbMajorMask, sizeof(s_ReportedUsbMajorMask));
    RtlZeroMemory(s_ReportedUsbInlineMask, sizeof(s_ReportedUsbInlineMask));
    RtlZeroMemory(s_ReportedUsbAttached, sizeof(s_ReportedUsbAttached));
    DBG("[+] UsbMonitor: Report deduplication state reset");
}

/*
 * 扫描核心 USB 驱动的分发例程 (指针 Hook 与入口 Inline Hook)
 */
ULONG UsbMonitor::CheckUsbHooks(VOID)
{
    if (!g_bAceDetected || g_AceModuleCount == 0)
        return 0;

    ULONG hookCount = 0;

    for (ULONG d = 0; d < MONITORED_USB_DRIVER_COUNT; d++)
    {
        UNICODE_STRING drvName;
        RtlInitUnicodeString(&drvName, g_MonitoredUsbDrivers[d]);

        PDRIVER_OBJECT pDrvObj = NULL;
        POBJECT_TYPE driverObjType = (g_pUsbMonUserVar && g_pUsbMonUserVar->Func.pIoDriverObjectType)
                                         ? *(POBJECT_TYPE *)g_pUsbMonUserVar->Func.pIoDriverObjectType
                                         : NULL;
        if (!driverObjType || !g_pUsbMonUserVar || !g_pUsbMonUserVar->Func.ObReferenceObjectByName)
            continue;
        NTSTATUS status = g_pUsbMonUserVar->Func.ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, NULL, 0, driverObjType,
                                                                         KernelMode, NULL, (PVOID *)&pDrvObj);
        if (!NT_SUCCESS(status) || !pDrvObj)
            continue;

        __try
        {
            if (Utils::IsValidKernelRange(pDrvObj, sizeof(DRIVER_OBJECT)))
            {
                for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                {
                    ULONG_PTR fn = (ULONG_PTR)pDrvObj->MajorFunction[i];
                    if (!fn)
                        continue;

                    /* 1. 指针 Hook 检测 */
                    if (IsAddressInAceModules(fn))
                    {
                        WCHAR aceMod[32] = {0};
                        ULONG_PTR aceBase = 0, aceRva = 0;
                        ResolveAceModuleInfo(fn, aceMod, &aceBase, &aceRva);
                        DBG("[!] [HOOK ALARM-USB] %ws MajorFunction[%u] POINTER HOOKED by %ws! Handler=0x%p (+0x%llX)",
                            g_MonitoredUsbDrivers[d], i, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, aceRva);
                        hookCount++;

                        if (!(s_ReportedUsbMajorMask[d] & (1U << (i & 31))))
                        {
                            s_ReportedUsbMajorMask[d] |= (1U << (i & 31));
                            ExceptionReporter::ReportFormat("UsbMonitor::MajorPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                                "USB Hook: %ws MajorFunction[%u] POINTER HOOKED by %ws! Handler=0x%p (Base=0x%p +0x%llX)",
                                g_MonitoredUsbDrivers[d], i, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, (PVOID)aceBase, aceRva);
                        }
                    }

                    /* 2. 函数入口 Inline Hook 检测 */
                    ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(fn);
                    if (inlineTarget && IsAddressInAceModules(inlineTarget))
                    {
                        WCHAR aceMod[32] = {0};
                        ULONG_PTR aceBase = 0, aceRva = 0;
                        ResolveAceModuleInfo(inlineTarget, aceMod, &aceBase, &aceRva);
                        DBG("[!] [HOOK ALARM-USB] %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> %ws Target=0x%p (+0x%llX)",
                            g_MonitoredUsbDrivers[d], i, (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, aceRva);
                        hookCount++;

                        if (!(s_ReportedUsbInlineMask[d] & (1U << (i & 31))))
                        {
                            s_ReportedUsbInlineMask[d] |= (1U << (i & 31));
                            ExceptionReporter::ReportFormat("UsbMonitor::MajorInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                                "USB Hook: %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                                g_MonitoredUsbDrivers[d], i, (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, (PVOID)aceBase, aceRva);
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] UsbMonitor: Exception checking hooks on %ws", g_MonitoredUsbDrivers[d]);
        }

        if (g_pUsbMonUserVar && g_pUsbMonUserVar->Func.ObfDereferenceObject)
        {
            g_pUsbMonUserVar->Func.ObfDereferenceObject(pDrvObj);
        }
    }

    return hookCount;
}

/*
 * 扫描 USB 设备栈 AttachedDevice 附加过滤设备
 */
ULONG UsbMonitor::CheckUsbAttached(VOID)
{
    if (!g_bAceDetected || g_AceModuleCount == 0)
        return 0;

    ULONG attachedCount = 0;

    for (ULONG d = 0; d < MONITORED_USB_DRIVER_COUNT; d++)
    {
        UNICODE_STRING drvName;
        RtlInitUnicodeString(&drvName, g_MonitoredUsbDrivers[d]);

        PDRIVER_OBJECT pDrvObj = NULL;
        POBJECT_TYPE driverObjType = (g_pUsbMonUserVar && g_pUsbMonUserVar->Func.pIoDriverObjectType)
                                         ? *(POBJECT_TYPE *)g_pUsbMonUserVar->Func.pIoDriverObjectType
                                         : NULL;
        if (!driverObjType || !g_pUsbMonUserVar || !g_pUsbMonUserVar->Func.ObReferenceObjectByName)
            continue;
        NTSTATUS status = g_pUsbMonUserVar->Func.ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, NULL, 0, driverObjType,
                                                                         KernelMode, NULL, (PVOID *)&pDrvObj);
        if (!NT_SUCCESS(status) || !pDrvObj)
            continue;

        __try
        {
            PDEVICE_OBJECT pDev = Utils::IsValidKernelRange(pDrvObj, sizeof(DRIVER_OBJECT)) ? pDrvObj->DeviceObject : NULL;
            ULONG devCount = 0;
            while (Utils::IsValidKernelRange(pDev, sizeof(DEVICE_OBJECT)) && devCount++ < 128)
            {
                PDEVICE_OBJECT pCurr = pDev->AttachedDevice;
                ULONG depth = 0;

                while (Utils::IsValidKernelRange(pCurr, sizeof(DEVICE_OBJECT)) && depth < 16)
                {
                    PDRIVER_OBJECT pAttachedDrv = pCurr->DriverObject;
                    if (Utils::IsValidKernelRange(pAttachedDrv, sizeof(DRIVER_OBJECT)))
                    {
                        ULONG_PTR drvStart = (ULONG_PTR)pAttachedDrv->DriverStart;
                        if (IsAddressInAceModules(drvStart))
                        {
                            WCHAR aceMod[32] = {0};
                            ULONG_PTR aceBase = 0, aceRva = 0;
                            ResolveAceModuleInfo(drvStart, aceMod, &aceBase, &aceRva);
                            DBG("[!] [HOOK ALARM-USB] %ws AttachedDevice found on %ws device stack! Driver=0x%p",
                                aceMod[0] ? aceMod : L"ACE", g_MonitoredUsbDrivers[d], (PVOID)drvStart);
                            attachedCount++;

                            if (!s_ReportedUsbAttached[d])
                            {
                                s_ReportedUsbAttached[d] = TRUE;
                                ExceptionReporter::ReportFormat("UsbMonitor::AttachedDevice", STATUS_SECURITY_CHECKS_FAILED,
                                    "USB Hook: AttachedDevice by %ws on %ws! Driver=0x%p (Base=0x%p +0x%llX)",
                                    aceMod[0] ? aceMod : L"ACE", g_MonitoredUsbDrivers[d], (PVOID)drvStart, (PVOID)aceBase, aceRva);
                            }
                        }

                        for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                        {
                            ULONG_PTR fn = (ULONG_PTR)pAttachedDrv->MajorFunction[i];
                            if (fn && IsAddressInAceModules(fn))
                            {
                                WCHAR aceMod[32] = {0};
                                ULONG_PTR aceBase = 0, aceRva = 0;
                                ResolveAceModuleInfo(fn, aceMod, &aceBase, &aceRva);
                                DBG("[!] [HOOK ALARM-USB] AttachedDevice on %ws has %ws Handler[%u]=0x%p (+0x%llX)",
                                    g_MonitoredUsbDrivers[d], aceMod[0] ? aceMod : L"ACE", i, (PVOID)fn, aceRva);
                                attachedCount++;

                                if (!s_ReportedUsbAttached[d])
                                {
                                    s_ReportedUsbAttached[d] = TRUE;
                                    ExceptionReporter::ReportFormat("UsbMonitor::AttachedHandler", STATUS_SECURITY_CHECKS_FAILED,
                                        "USB Hook: AttachedDevice on %ws has %ws Handler[%u]=0x%p (Base=0x%p +0x%llX)",
                                        g_MonitoredUsbDrivers[d], aceMod[0] ? aceMod : L"ACE", i, (PVOID)fn, (PVOID)aceBase, aceRva);
                                }
                                break;
                            }
                        }
                    }

                    pCurr = pCurr->AttachedDevice;
                    depth++;
                }

                pDev = pDev->NextDevice;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] UsbMonitor: Exception checking attached devices on %ws", g_MonitoredUsbDrivers[d]);
        }

        if (g_pUsbMonUserVar && g_pUsbMonUserVar->Func.ObfDereferenceObject)
        {
            g_pUsbMonUserVar->Func.ObfDereferenceObject(pDrvObj);
        }
    }

    return attachedCount;
}

/*
 * USB 全栈主动只读扫描入口 (10秒周期)
 */
ULONG UsbMonitor::ScanAll(VOID)
{
    static ULONG s_usbScanRound = 0;
    s_usbScanRound++;

    ULONG hooks = CheckUsbHooks();
    ULONG attached = CheckUsbAttached();
    ULONG total = hooks + attached;

    if (total > 0)
    {
        DBG("[!] UsbMonitor [Round #%lu]: >>> THREAT DETECTED! Total=%u (MajorHooks=%u, AttachedDevices=%u) <<<",
            s_usbScanRound, total, hooks, attached);
    }
    else
    {
        if (s_usbScanRound <= 3 || (s_usbScanRound % 5) == 0)
        {
            DBG("[+] UsbMonitor [Round #%lu]: All clean — USB (USBHUB3/USBXHCI/WINUSB/usbccgp/usbhub) dispatch routines intact, no AttachedDevices",
                s_usbScanRound);
        }
    }

    return total;
}

NTSTATUS UsbMonitor::Init(VOID)
{
    ResetReportState();
    DBG("[+] UsbMonitor: USB Security Monitoring Engine Initialized (10s Deduplicated, 100%% Read-Only)");
    return STATUS_SUCCESS;
}
