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
 * 3. 针对 MajorFunction 指针偏离、入口 Inline Hook、设备栈 AttachedDevice 监控。
 * 4. 单次去重上报机制：相同 Hook 槽位首次捕获打印日志并出网上报，后续周期静默，
 *    避免 10 秒周期下重复向服务端风暴上报。
 * ============================================================================
 */

static MACHENIKE_KERNEL_INTERFACE *g_pUsbMonUserVar = NULL;
VOID UsbMonitor::SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar) { g_pUsbMonUserVar = UserVar; }

#ifdef MmIsAddressValid
#undef MmIsAddressValid
#endif
#define MmIsAddressValid(va)                                                                                                               \
    ((g_pUsbMonUserVar && g_pUsbMonUserVar->Func.MmIsAddressValid) ? g_pUsbMonUserVar->Func.MmIsAddressValid((PVOID)(va)) : FALSE)

/*
 * 监控的核心 USB 驱动名称列表
 */
static const PCWSTR g_MonitoredUsbDrivers[] = {
    L"\\Driver\\USBHUB3",
    L"\\Driver\\USBXHCI",
    L"\\Driver\\WINUSB",
    L"\\Driver\\usbccgp",
    L"\\Driver\\usbhub"
};

#define MONITORED_USB_DRIVER_COUNT (sizeof(g_MonitoredUsbDrivers) / sizeof(g_MonitoredUsbDrivers[0]))

/* ============================================================================
 * 去重防抖状态位图（确保单个 Hook 异常仅上报一次）
 * ============================================================================ */
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
 * 辅助函数: 解码函数入口前 16 字节中的跳转指令目标地址 (Inline Hook)
 */
static ULONG_PTR GetUsbInlineHookTarget(ULONG_PTR fnAddr)
{
    if (!fnAddr || !MmIsAddressValid((PVOID)fnAddr))
        return 0;

    __try
    {
        PUCHAR p = (PUCHAR)fnAddr;

        /* 1. E9 xx xx xx xx  (jmp rel32) */
        if (p[0] == 0xE9)
        {
            LONG disp = *(PLONG)(p + 1);
            return (ULONG_PTR)(p + 5 + disp);
        }

        /* 2. E8 xx xx xx xx  (call rel32 劫持前置) */
        if (p[0] == 0xE8)
        {
            LONG disp = *(PLONG)(p + 1);
            return (ULONG_PTR)(p + 5 + disp);
        }

        /* 3. FF 25 xx xx xx xx  (jmp qword ptr [rip + disp32]) */
        if (p[0] == 0xFF && p[1] == 0x25)
        {
            LONG disp = *(PLONG)(p + 2);
            ULONG_PTR pTargetSlot = (ULONG_PTR)(p + 6 + disp);
            if (MmIsAddressValid((PVOID)pTargetSlot))
            {
                return *(PULONG_PTR)pTargetSlot;
            }
        }

        /* 4. 48 FF 25 xx xx xx xx  (rex.W jmp qword ptr [rip + disp32]) */
        if (p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25)
        {
            LONG disp = *(PLONG)(p + 3);
            ULONG_PTR pTargetSlot = (ULONG_PTR)(p + 7 + disp);
            if (MmIsAddressValid((PVOID)pTargetSlot))
            {
                return *(PULONG_PTR)pTargetSlot;
            }
        }

        /* 5. 48 B8 [imm64] FF E0/E1/E2  (mov rax/rcx/rdx, imm64; jmp reg) */
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && (p[11] >= 0xE0 && p[11] <= 0xE2))
        {
            return *(PULONG_PTR)(p + 2);
        }

        /* 6. 49 BB [imm64] 41 FF E3  (mov r11, imm64; jmp r11) */
        if (p[0] == 0x49 && p[1] == 0xBB && p[10] == 0x41 && p[11] == 0xFF && p[12] == 0xE3)
        {
            return *(PULONG_PTR)(p + 2);
        }

        /* 7. 50 48 B8 [imm64] 48 87 04 24 C3 (push rax; mov rax, imm64; xchg [rsp], rax; ret) */
        if (p[0] == 0x50 && p[1] == 0x48 && p[2] == 0xB8 && p[11] == 0x48 && p[12] == 0x87 && p[13] == 0x04 && p[14] == 0x24 && p[15] == 0xC3)
        {
            return *(PULONG_PTR)(p + 3);
        }

        /* 8. 68 [imm32] C7 44 24 04 [imm32] C3 (push low32; mov [rsp+4], high32; ret) */
        if (p[0] == 0x68 && p[5] == 0xC7 && p[6] == 0x44 && p[7] == 0x24 && p[8] == 0x04 && p[13] == 0xC3)
        {
            ULONG low = *(PULONG)(p + 1);
            ULONG high = *(PULONG)(p + 9);
            return (((ULONG_PTR)high) << 32) | low;
        }

        /* 9. EB xx (jmp short rel8) 二级跳板 */
        if (p[0] == 0xEB)
        {
            CHAR disp8 = *(PCHAR)(p + 1);
            ULONG_PTR nextTarget = (ULONG_PTR)(p + 2 + disp8);
            if (MmIsAddressValid((PVOID)nextTarget) && nextTarget != fnAddr)
            {
                PUCHAR p2 = (PUCHAR)nextTarget;
                if (p2[0] == 0xE9)
                {
                    LONG disp32 = *(PLONG)(p2 + 1);
                    return (ULONG_PTR)(p2 + 5 + disp32);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }

    return 0;
}

/*
 * 扫描核心 USB 驱动的分发例程 (指针 Hook 与入口 Inline Hook)
 */
ULONG UsbMonitor::CheckUsbHooks(VOID)
{
    ULONG hookCount = 0;

    for (ULONG d = 0; d < MONITORED_USB_DRIVER_COUNT; d++)
    {
        UNICODE_STRING drvName;
        RtlInitUnicodeString(&drvName, g_MonitoredUsbDrivers[d]);

        PDRIVER_OBJECT pDrvObj = NULL;
        NTSTATUS status = ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL,
                                                   (PVOID *)&pDrvObj);
        if (!NT_SUCCESS(status) || !pDrvObj)
            continue;

        __try
        {
            for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
            {
                ULONG_PTR fn = (ULONG_PTR)pDrvObj->MajorFunction[i];
                if (!fn)
                    continue;

                /* 1. 指针 Hook 检测 */
                if (IsAddressInAceModules(fn))
                {
                    DBG("[!] [HOOK ALARM-USB] %ws MajorFunction[%u] POINTER HOOKED by ACE! Handler=0x%p", g_MonitoredUsbDrivers[d], i,
                        (PVOID)fn);
                    hookCount++;

                    if (!(s_ReportedUsbMajorMask[d] & (1U << (i & 31))))
                    {
                        s_ReportedUsbMajorMask[d] |= (1U << (i & 31));
                        ExceptionReporter::ReportFormat("UsbMonitor::MajorPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                            "USB Hook: %ws MajorFunction[%u] POINTER HOOKED by ACE! Handler=0x%p",
                            g_MonitoredUsbDrivers[d], i, (PVOID)fn);
                    }
                }

                /* 2. 函数入口 Inline Hook 检测 */
                ULONG_PTR inlineTarget = GetUsbInlineHookTarget(fn);
                if (inlineTarget && IsAddressInAceModules(inlineTarget))
                {
                    DBG("[!] [HOOK ALARM-USB] %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> ACE Target=0x%p", g_MonitoredUsbDrivers[d], i,
                        (PVOID)fn, (PVOID)inlineTarget);
                    hookCount++;

                    if (!(s_ReportedUsbInlineMask[d] & (1U << (i & 31))))
                    {
                        s_ReportedUsbInlineMask[d] |= (1U << (i & 31));
                        ExceptionReporter::ReportFormat("UsbMonitor::MajorInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                            "USB Hook: %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> ACE Target=0x%p",
                            g_MonitoredUsbDrivers[d], i, (PVOID)fn, (PVOID)inlineTarget);
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
    ULONG attachedCount = 0;

    for (ULONG d = 0; d < MONITORED_USB_DRIVER_COUNT; d++)
    {
        UNICODE_STRING drvName;
        RtlInitUnicodeString(&drvName, g_MonitoredUsbDrivers[d]);

        PDRIVER_OBJECT pDrvObj = NULL;
        NTSTATUS status = ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL,
                                                   (PVOID *)&pDrvObj);
        if (!NT_SUCCESS(status) || !pDrvObj)
            continue;

        __try
        {
            PDEVICE_OBJECT pDev = pDrvObj->DeviceObject;
            while (pDev)
            {
                PDEVICE_OBJECT pCurr = pDev->AttachedDevice;
                ULONG depth = 0;

                while (pCurr && depth < 16)
                {
                    if (pCurr->DriverObject)
                    {
                        ULONG_PTR drvStart = (ULONG_PTR)pCurr->DriverObject->DriverStart;
                        if (IsAddressInAceModules(drvStart))
                        {
                            DBG("[!] [HOOK ALARM-USB] ACE AttachedDevice found on %ws device stack! Driver=0x%p (%wZ)",
                                g_MonitoredUsbDrivers[d], (PVOID)drvStart, &pCurr->DriverObject->DriverName);
                            attachedCount++;

                            if (!s_ReportedUsbAttached[d])
                            {
                                s_ReportedUsbAttached[d] = TRUE;
                                ExceptionReporter::ReportFormat("UsbMonitor::AttachedDevice", STATUS_SECURITY_CHECKS_FAILED,
                                    "USB Hook: ACE AttachedDevice on %ws stack! Driver=0x%p", g_MonitoredUsbDrivers[d], (PVOID)drvStart);
                            }
                        }

                        for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                        {
                            ULONG_PTR fn = (ULONG_PTR)pCurr->DriverObject->MajorFunction[i];
                            if (fn && IsAddressInAceModules(fn))
                            {
                                DBG("[!] [HOOK ALARM-USB] AttachedDevice on %ws has ACE Handler[%u]=0x%p", g_MonitoredUsbDrivers[d], i,
                                    (PVOID)fn);
                                attachedCount++;

                                if (!s_ReportedUsbAttached[d])
                                {
                                    s_ReportedUsbAttached[d] = TRUE;
                                    ExceptionReporter::ReportFormat("UsbMonitor::AttachedHandler", STATUS_SECURITY_CHECKS_FAILED,
                                        "USB Hook: AttachedDevice on %ws has ACE Handler[%u]=0x%p", g_MonitoredUsbDrivers[d], i, (PVOID)fn);
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
