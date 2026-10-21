#include "Common.h"
#include "NetMonitor.h"
#include "Utils.h"
#if ENABLE_TRANSPORT_MODES
#include "wsk_server.h"
#endif
#include "ExceptionReporter.h"
#include "WfpBypass.h"

/*
 * ============================================================================
 * NetMonitor: 内核网络全栈多维安全监控引擎
 *
 * 针对除 WFP Callout 之外的反作弊常见网络拦截面实施全方位主动探测与告警：
 *
 * 1. 核心网络/套接字设备分发例程监控（\Device\Afd, Tcp, Udp, RawIp, Ip 及 \Driver\pacer）
 *    - 指针替换 Hook（Pointer Hook）
 *    - 函数入口内联跳板 Hook（Inline Jmp/Call Hook: E9/FF 25/48 B8/49 BB/ROP 等）
 *    - 快速 I/O 分发例程 Hook（FastIoDispatch）
 * 2. TDI / 设备栈附加过滤设备监控（AttachedDevice 链，包含 \Device\Afd）
 * 3. NDIS LWF 轻量级网络过滤驱动链表监控（ndisFilterDriverList）
 * 4. 通讯驱动自身的 WSK Provider Dispatch 函数表完整性自检
 * 5. WFP Callout 状态巡检（防止 ACE 动态重挂钩或还原）
 * 6. 单次去重上报机制（已上报异常的槽位与设备不再重复向服务器上报）
 * ============================================================================
 */
static MACHENIKE_KERNEL_INTERFACE *g_pNetMonUserVar = NULL;
VOID NetMonitor::SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar) { g_pNetMonUserVar = UserVar; }
#ifdef MmIsAddressValid
#undef MmIsAddressValid
#endif
#define MmIsAddressValid(va)                                                                                                               \
    ((g_pNetMonUserVar && g_pNetMonUserVar->Func.MmIsAddressValid) ? g_pNetMonUserVar->Func.MmIsAddressValid((PVOID)(va)) : FALSE)

#define RtlInitUnicodeString SafeInitUnicodeString
#define IoGetDeviceObjectPointer(name, access, fileObj, devObj)                                                                            \
    ((g_pNetMonUserVar && g_pNetMonUserVar->Func.IoGetDeviceObjectPointer)                                                                \
         ? g_pNetMonUserVar->Func.IoGetDeviceObjectPointer(name, access, fileObj, devObj)                                                 \
         : STATUS_NOT_FOUND)

static ULONG_PTR g_NdisBase = 0;
static ULONG_PTR g_NdisEnd = 0;
static ULONG_PTR g_NdisTextStart = 0;
static ULONG_PTR g_NdisTextEnd = 0;
static PVOID *g_pFilterDriverList = NULL;
static BOOLEAN g_bNdisScanned = FALSE;

/* 监控的核心网络设备与驱动名称列表 */
static const PCWSTR g_MonitoredDevices[] = {
    L"\\Device\\Afd", 
    L"\\Device\\Tcp", 
    L"\\Device\\Udp", 
    L"\\Device\\RawIp", 
    L"\\Device\\Ip"
};

#define MONITORED_DEVICE_COUNT (sizeof(g_MonitoredDevices) / sizeof(g_MonitoredDevices[0]))

/* 核心网络过滤/包调度驱动名称 */
static const PCWSTR g_MonitoredNetDrivers[] = {
    L"\\Driver\\pacer",
    L"\\Driver\\tcpip",
    L"\\Driver\\afd"
};

#define MONITORED_NET_DRIVER_COUNT (sizeof(g_MonitoredNetDrivers) / sizeof(g_MonitoredNetDrivers[0]))

/* ============================================================================
 * 去重防抖状态位图（确保单个 Hook 异常仅上报一次）
 * ============================================================================ */
static UINT32 s_ReportedNetMajorMask[MONITORED_DEVICE_COUNT] = {0};
static UINT32 s_ReportedNetInlineMask[MONITORED_DEVICE_COUNT] = {0};
static UINT32 s_ReportedNetFastIoMask[MONITORED_DEVICE_COUNT] = {0};
static BOOLEAN s_ReportedNetAttached[MONITORED_DEVICE_COUNT] = {FALSE};

static UINT32 s_ReportedDrvMajorMask[MONITORED_NET_DRIVER_COUNT] = {0};
static UINT32 s_ReportedDrvInlineMask[MONITORED_NET_DRIVER_COUNT] = {0};

static BOOLEAN s_ReportedNdisFilterAlarm = FALSE;
static UINT32 s_ReportedWskMask = 0;
static BOOLEAN s_ReportedWfpUnprotectedAlarm = FALSE;

VOID NetMonitor::SetNdisModule(ULONG_PTR Base, ULONG_PTR End)
{
    g_NdisBase = Base;
    g_NdisEnd = End;

    ULONG_PTR textStart = 0, textEnd = 0;
    if (Utils::GetModuleTextSection(Base, &textStart, &textEnd) && textEnd > textStart)
    {
        g_NdisTextStart = textStart;
        g_NdisTextEnd = textEnd;
        DBG("[+] NetMonitor: NDIS scan range strictly restricted to .text section [0x%p - 0x%p] (size=0x%IX)",
            (PVOID)textStart, (PVOID)textEnd, textEnd - textStart);
    }
    else
    {
        g_NdisTextStart = 0;
        g_NdisTextEnd = 0;
        DBG("[-] NetMonitor: Failed to find .text section in ndis.sys [0x%p - 0x%p], scan disabled", (PVOID)Base, (PVOID)End);
    }
    g_bNdisScanned = FALSE;
}

VOID NetMonitor::ResetReportState(VOID)
{
    RtlZeroMemory(s_ReportedNetMajorMask, sizeof(s_ReportedNetMajorMask));
    RtlZeroMemory(s_ReportedNetInlineMask, sizeof(s_ReportedNetInlineMask));
    RtlZeroMemory(s_ReportedNetFastIoMask, sizeof(s_ReportedNetFastIoMask));
    RtlZeroMemory(s_ReportedNetAttached, sizeof(s_ReportedNetAttached));
    RtlZeroMemory(s_ReportedDrvMajorMask, sizeof(s_ReportedDrvMajorMask));
    RtlZeroMemory(s_ReportedDrvInlineMask, sizeof(s_ReportedDrvInlineMask));
    s_ReportedNdisFilterAlarm = FALSE;
    s_ReportedWskMask = 0;
    s_ReportedWfpUnprotectedAlarm = FALSE;
    DBG("[+] NetMonitor: Report deduplication state reset");
}

/*
 * ============================================================================
 * 辅助函数: 解码函数入口前 16 字节中的绝对/相对跳转指令目标地址 (Inline Hook)
 * ============================================================================
 */
static ULONG_PTR GetInlineHookTarget(ULONG_PTR fnAddr)
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
 * ============================================================================
 * 监控面 1: 网络驱动分发例程 Hook 监控 (Pointer Hook + Inline Hook + FastIo)
 * ============================================================================
 */
ULONG NetMonitor::CheckTcpipHooks(VOID)
{
    ULONG hookCount = 0;

    for (ULONG d = 0; d < MONITORED_DEVICE_COUNT; d++)
    {
        UNICODE_STRING devName;
        RtlInitUnicodeString(&devName, g_MonitoredDevices[d]);

        PFILE_OBJECT pFileObj = NULL;
        PDEVICE_OBJECT pDevObj = NULL;

        NTSTATUS status = IoGetDeviceObjectPointer(&devName, FILE_READ_DATA, &pFileObj, &pDevObj);
        if (!NT_SUCCESS(status) || !pDevObj)
            continue;

        __try
        {
            PDRIVER_OBJECT pDrv = pDevObj->DriverObject;
            if (pDrv)
            {
                /* 1. 扫描 IRP MajorFunction 表 (指针 Hook 与函数头部 Inline Hook) */
                for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                {
                    ULONG_PTR fn = (ULONG_PTR)pDrv->MajorFunction[i];
                    if (!fn)
                        continue;

                    /* 1.1 指针 Hook 检测 */
                    if (IsAddressInAceModules(fn))
                    {
                        DBG("[!] [HOOK ALARM-NET] %ws MajorFunction[%u] POINTER HOOKED by ACE! Handler=0x%p", g_MonitoredDevices[d], i,
                            (PVOID)fn);
                        hookCount++;
                        if (!(s_ReportedNetMajorMask[d] & (1U << (i & 31))))
                        {
                            s_ReportedNetMajorMask[d] |= (1U << (i & 31));
                            ExceptionReporter::ReportFormat("NetMonitor::MajorPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                                "NET Hook: %ws MajorFunction[%u] POINTER HOOKED by ACE! Handler=0x%p",
                                g_MonitoredDevices[d], i, (PVOID)fn);
                        }
                    }

                    /* 1.2 函数入口 Inline Hook 检测 (JMP 跳转至 ACE) */
                    ULONG_PTR inlineTarget = GetInlineHookTarget(fn);
                    if (inlineTarget && IsAddressInAceModules(inlineTarget))
                    {
                        DBG("[!] [HOOK ALARM-NET] %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> ACE Target=0x%p", g_MonitoredDevices[d], i,
                            (PVOID)fn, (PVOID)inlineTarget);
                        hookCount++;
                        if (!(s_ReportedNetInlineMask[d] & (1U << (i & 31))))
                        {
                            s_ReportedNetInlineMask[d] |= (1U << (i & 31));
                            ExceptionReporter::ReportFormat("NetMonitor::MajorInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                                "NET Hook: %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> ACE Target=0x%p",
                                g_MonitoredDevices[d], i, (PVOID)fn, (PVOID)inlineTarget);
                        }
                    }
                }

                /* 2. 扫描 FastIoDispatch 快速通道 Hook */
                PFAST_IO_DISPATCH pFastIo = pDrv->FastIoDispatch;
                if (pFastIo && MmIsAddressValid(pFastIo))
                {
                    ULONG_PTR *pFastIoArr = (ULONG_PTR *)pFastIo;
                    ULONG totalEntries = (pFastIo->SizeOfFastIoDispatch > 0 && pFastIo->SizeOfFastIoDispatch <= 512)
                                             ? (pFastIo->SizeOfFastIoDispatch / sizeof(PVOID))
                                             : 24;

                    for (ULONG j = 1; j < totalEntries && j < 32; j++)
                    {
                        ULONG_PTR fn = pFastIoArr[j];
                        if (!fn)
                            continue;

                        if (IsAddressInAceModules(fn))
                        {
                            DBG("[!] [HOOK ALARM-NET] %ws FastIoDispatch[%u] POINTER HOOKED by ACE! Handler=0x%p", g_MonitoredDevices[d], j,
                                (PVOID)fn);
                            hookCount++;
                            if (!(s_ReportedNetFastIoMask[d] & (1U << j)))
                            {
                                s_ReportedNetFastIoMask[d] |= (1U << j);
                                ExceptionReporter::ReportFormat("NetMonitor::FastIoPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                                    "NET Hook: %ws FastIoDispatch[%u] POINTER HOOKED by ACE! Handler=0x%p",
                                    g_MonitoredDevices[d], j, (PVOID)fn);
                            }
                        }

                        ULONG_PTR inlineTarget = GetInlineHookTarget(fn);
                        if (inlineTarget && IsAddressInAceModules(inlineTarget))
                        {
                            DBG("[!] [HOOK ALARM-NET] %ws FastIoDispatch[%u] INLINE HOOKED -> ACE Target=0x%p", g_MonitoredDevices[d], j,
                                (PVOID)inlineTarget);
                            hookCount++;
                            if (!(s_ReportedNetFastIoMask[d] & (1U << j)))
                            {
                                s_ReportedNetFastIoMask[d] |= (1U << j);
                                ExceptionReporter::ReportFormat("NetMonitor::FastIoInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                                    "NET Hook: %ws FastIoDispatch[%u] INLINE HOOKED -> ACE Target=0x%p",
                                    g_MonitoredDevices[d], j, (PVOID)inlineTarget);
                            }
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] NetMonitor: Exception while checking hooks on %ws", g_MonitoredDevices[d]);
        }

        if (pFileObj)
        {
            if (g_pNetMonUserVar && g_pNetMonUserVar->Func.ObfDereferenceObject)
            {
                g_pNetMonUserVar->Func.ObfDereferenceObject(pFileObj);
            }
        }
    }

    /* 3. 扫描核心网络驱动对象（如 \Driver\pacer 等调度器） */
    for (ULONG nd = 0; nd < MONITORED_NET_DRIVER_COUNT; nd++)
    {
        UNICODE_STRING drvName;
        RtlInitUnicodeString(&drvName, g_MonitoredNetDrivers[nd]);
        PDRIVER_OBJECT pNetDrvObj = NULL;
        POBJECT_TYPE driverObjType = (g_pNetMonUserVar && g_pNetMonUserVar->Func.pIoDriverObjectType)
                                         ? *(POBJECT_TYPE *)g_pNetMonUserVar->Func.pIoDriverObjectType
                                         : NULL;
        if (!driverObjType || !g_pNetMonUserVar || !g_pNetMonUserVar->Func.ObReferenceObjectByName)
            continue;
        if (NT_SUCCESS(g_pNetMonUserVar->Func.ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, NULL, 0, driverObjType,
                                                                      KernelMode, NULL, (PVOID *)&pNetDrvObj)) &&
            pNetDrvObj)
        {
            __try
            {
                for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                {
                    ULONG_PTR fn = (ULONG_PTR)pNetDrvObj->MajorFunction[i];
                    if (!fn)
                        continue;

                    if (IsAddressInAceModules(fn))
                    {
                        DBG("[!] [HOOK ALARM-NET] %ws MajorFunction[%u] POINTER HOOKED by ACE! Handler=0x%p", g_MonitoredNetDrivers[nd], i, (PVOID)fn);
                        hookCount++;
                        if (!(s_ReportedDrvMajorMask[nd] & (1U << (i & 31))))
                        {
                            s_ReportedDrvMajorMask[nd] |= (1U << (i & 31));
                            ExceptionReporter::ReportFormat("NetMonitor::DriverMajorPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                                "NET Hook: %ws MajorFunction[%u] POINTER HOOKED by ACE! Handler=0x%p",
                                g_MonitoredNetDrivers[nd], i, (PVOID)fn);
                        }
                    }

                    ULONG_PTR inlineTarget = GetInlineHookTarget(fn);
                    if (inlineTarget && IsAddressInAceModules(inlineTarget))
                    {
                        DBG("[!] [HOOK ALARM-NET] %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> ACE Target=0x%p", g_MonitoredNetDrivers[nd], i, (PVOID)fn, (PVOID)inlineTarget);
                        hookCount++;
                        if (!(s_ReportedDrvInlineMask[nd] & (1U << (i & 31))))
                        {
                            s_ReportedDrvInlineMask[nd] |= (1U << (i & 31));
                            ExceptionReporter::ReportFormat("NetMonitor::DriverMajorInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                                "NET Hook: %ws MajorFunction[%u] INLINE HOOKED -> ACE Target=0x%p",
                                g_MonitoredNetDrivers[nd], i, (PVOID)inlineTarget);
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DBG("[-] NetMonitor: Exception while checking driver hooks on %ws", g_MonitoredNetDrivers[nd]);
            }

            if (g_pNetMonUserVar && g_pNetMonUserVar->Func.ObfDereferenceObject)
            {
                g_pNetMonUserVar->Func.ObfDereferenceObject(pNetDrvObj);
            }
        }
    }

    return hookCount;
}

/*
 * ============================================================================
 * 监控面 2: TDI / 设备栈附加过滤设备监控 (AttachedDevice 链，包含 \Device\Afd)
 * ============================================================================
 */
ULONG NetMonitor::CheckTdiAttached(VOID)
{
    ULONG attachedCount = 0;

    for (ULONG d = 0; d < MONITORED_DEVICE_COUNT; d++)
    {
        UNICODE_STRING devName;
        RtlInitUnicodeString(&devName, g_MonitoredDevices[d]);

        PFILE_OBJECT pFileObj = NULL;
        PDEVICE_OBJECT pDevObj = NULL;

        NTSTATUS status = IoGetDeviceObjectPointer(&devName, FILE_READ_DATA, &pFileObj, &pDevObj);
        if (!NT_SUCCESS(status) || !pDevObj)
            continue;

        __try
        {
            PDEVICE_OBJECT pCurr = pDevObj->AttachedDevice;
            ULONG depth = 0;

            while (pCurr && depth < 16)
            {
                if (pCurr->DriverObject)
                {
                    ULONG_PTR drvStart = (ULONG_PTR)pCurr->DriverObject->DriverStart;
                    if (IsAddressInAceModules(drvStart))
                    {
                        DBG("[!] [HOOK ALARM-NET] ACE AttachedDevice found on %ws stack! Driver=0x%p (%wZ)", g_MonitoredDevices[d],
                            (PVOID)drvStart, &pCurr->DriverObject->DriverName);
                        attachedCount++;
                        if (!s_ReportedNetAttached[d])
                        {
                            s_ReportedNetAttached[d] = TRUE;
                            ExceptionReporter::ReportFormat("NetMonitor::TdiAttachedDevice", STATUS_SECURITY_CHECKS_FAILED,
                                "NET Hook: ACE AttachedDevice on %ws stack! Driver=0x%p", g_MonitoredDevices[d], (PVOID)drvStart);
                        }
                    }

                    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                    {
                        ULONG_PTR fn = (ULONG_PTR)pCurr->DriverObject->MajorFunction[i];
                        if (fn && IsAddressInAceModules(fn))
                        {
                            DBG("[!] [HOOK ALARM-NET] AttachedDevice on %ws has ACE Handler[%u]=0x%p", g_MonitoredDevices[d], i, (PVOID)fn);
                            attachedCount++;
                            if (!s_ReportedNetAttached[d])
                            {
                                s_ReportedNetAttached[d] = TRUE;
                                ExceptionReporter::ReportFormat("NetMonitor::TdiAttachedHandler", STATUS_SECURITY_CHECKS_FAILED,
                                    "NET Hook: AttachedDevice on %ws has ACE Handler[%u]=0x%p", g_MonitoredDevices[d], i, (PVOID)fn);
                            }
                            break;
                        }
                    }
                }

                pCurr = pCurr->AttachedDevice;
                depth++;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] NetMonitor: Exception while checking attached devices on %ws", g_MonitoredDevices[d]);
        }

        if (pFileObj)
        {
            if (g_pNetMonUserVar && g_pNetMonUserVar->Func.ObfDereferenceObject)
            {
                g_pNetMonUserVar->Func.ObfDereferenceObject(pFileObj);
            }
        }
    }

    return attachedCount;
}

/*
 * ============================================================================
 * 监控面 3: NDIS LWF 轻量级网络过滤驱动链表监控 (ndisFilterDriverList)
 * ============================================================================
 */
static PVOID *NetMonitor_LocateNdisFilterDriverList(VOID)
{
    if (g_pFilterDriverList)
        return g_pFilterDriverList;

    if (!g_NdisBase || !g_NdisEnd || g_NdisEnd <= g_NdisBase)
        return NULL;

    // 确保仅在锁定 .text 代码段范围内扫描，若无法解析 .text 则坚决不扫描，阻断缺页蓝屏
    if (!g_NdisTextStart || !g_NdisTextEnd || g_NdisTextEnd <= g_NdisTextStart)
    {
        if (!Utils::GetModuleTextSection(g_NdisBase, &g_NdisTextStart, &g_NdisTextEnd) || g_NdisTextEnd <= g_NdisTextStart)
        {
            DBG("[-] NetMonitor: Cannot locate .text section in ndis.sys, scan rejected for safety");
            return NULL;
        }
    }

    PUCHAR pStart = (PUCHAR)g_NdisTextStart;
    ULONG scanLen = (ULONG)(g_NdisTextEnd - g_NdisTextStart);

    __try
    {
        for (ULONG i = 0; i + 14 < scanLen; i++)
        {
            // 每次跨 4KB 页边界时校验地址有效性，防止触碰非驻留页触发 0x50 BugCheck
            if ((i & 0xFFF) == 0 && !MmIsAddressValid(pStart + i))
            {
                i += 0xFFF; // 跳过整页
                continue;
            }

            if (pStart[i] == 0x48 && pStart[i + 1] == 0x8B && pStart[i + 2] == 0x0D && pStart[i + 7] == 0x48 && pStart[i + 8] == 0x8D &&
                pStart[i + 9] == 0x15)
            {
                LONG d1 = *(PLONG)(pStart + i + 3);
                LONG d2 = *(PLONG)(pStart + i + 10);

                if (d1 - d2 == 7)
                {
                    ULONG_PTR target = (ULONG_PTR)(pStart + i + 7 + d1);
                    if (target >= g_NdisBase && target < g_NdisEnd && MmIsAddressValid((PVOID)target))
                    {
                        g_pFilterDriverList = (PVOID *)target;
                        DBG("[+] NetMonitor: Resolved ndisFilterDriverList @ 0x%p (offset +0x%X in ndis.sys)", (PVOID)target, i);
                        return g_pFilterDriverList;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG("[-] NetMonitor: Exception scanning for ndisFilterDriverList");
    }

    return NULL;
}

ULONG NetMonitor::CheckNdisFilters(VOID)
{
    ULONG fltMatchCount = 0;

    PVOID *pList = NetMonitor_LocateNdisFilterDriverList();
    if (!pList)
    {
        if (!g_bNdisScanned)
        {
            g_bNdisScanned = TRUE;
            DBG("[*] NetMonitor: ndis.sys information pending or pattern not found yet");
        }
        return 0;
    }

    __try
    {
        PVOID pBlock = *pList;
        ULONG count = 0;

        while (pBlock && count < 64)
        {
            PDRIVER_OBJECT pFltDrv = *(PDRIVER_OBJECT *)((PUCHAR)pBlock + 0x10);
            PUNICODE_STRING pImageName = (PUNICODE_STRING)((PUCHAR)pBlock + 0x160);
            UNREFERENCED_PARAMETER(pImageName);

            if (pFltDrv && MmIsAddressValid(pFltDrv))
            {
                ULONG_PTR drvBase = (ULONG_PTR)pFltDrv->DriverStart;
                if (IsAddressInAceModules(drvBase))
                {
                    DBG("[!] [HOOK ALARM-NET] ACE NDIS Filter Driver detected! Driver=0x%p (ImageName=%wZ)", (PVOID)drvBase, pImageName);
                    fltMatchCount++;
                    if (!s_ReportedNdisFilterAlarm)
                    {
                        s_ReportedNdisFilterAlarm = TRUE;
                        ExceptionReporter::ReportFormat("NetMonitor::NdisFilterDriver", STATUS_SECURITY_CHECKS_FAILED,
                            "NET Hook: ACE NDIS Filter Driver detected! Driver=0x%p", (PVOID)drvBase);
                    }
                }
            }

            /* 扫描该过滤驱动注册的接收/发送/请求回调 (含 Inline Hook 检测) */
            PUCHAR pChars = (PUCHAR)pBlock + 0x60;
            for (ULONG k = 0; k < 0x80; k += sizeof(PVOID))
            {
                ULONG_PTR fn = *(ULONG_PTR *)(pChars + k);
                if (!fn)
                    continue;

                if (IsAddressInAceModules(fn))
                {
                    DBG("[!] [HOOK ALARM-NET] ACE NDIS Filter Callback detected! Handler=0x%p (FilterBlock=0x%p)", (PVOID)fn, pBlock);
                    fltMatchCount++;
                    if (!s_ReportedNdisFilterAlarm)
                    {
                        s_ReportedNdisFilterAlarm = TRUE;
                        ExceptionReporter::ReportFormat("NetMonitor::NdisFilterCallback", STATUS_SECURITY_CHECKS_FAILED,
                            "NET Hook: ACE NDIS Filter Callback detected! Handler=0x%p", (PVOID)fn);
                    }
                    break;
                }

                ULONG_PTR inlineTarget = GetInlineHookTarget(fn);
                if (inlineTarget && IsAddressInAceModules(inlineTarget))
                {
                    DBG("[!] [HOOK ALARM-NET] ACE NDIS Filter Callback (0x%p) INLINE HOOKED -> ACE Target=0x%p", (PVOID)fn,
                        (PVOID)inlineTarget);
                    fltMatchCount++;
                    if (!s_ReportedNdisFilterAlarm)
                    {
                        s_ReportedNdisFilterAlarm = TRUE;
                        ExceptionReporter::ReportFormat("NetMonitor::NdisFilterInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                            "NET Hook: ACE NDIS Filter Callback (0x%p) INLINE HOOKED -> ACE Target=0x%p", (PVOID)fn, (PVOID)inlineTarget);
                    }
                    break;
                }
            }

            pBlock = *(PVOID *)((PUCHAR)pBlock + 0x08);
            count++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG("[-] NetMonitor: Exception traversing ndisFilterDriverList");
    }

    return fltMatchCount;
}

/*
 * ============================================================================
 * 监控面 4: 通讯驱动自身 WSK Provider Dispatch 函数表完整性自检
 * ============================================================================
 */
ULONG NetMonitor::CheckWskDispatch(VOID)
{
#if ENABLE_TRANSPORT_MODES
    ULONG alarmCount = 0;

    if (!g_WskServer.fCapturedNpi || !g_WskServer.ProviderNpi.Dispatch)
        return 0;

    __try
    {
        const WSK_PROVIDER_DISPATCH *pDisp = g_WskServer.ProviderNpi.Dispatch;
        if (!MmIsAddressValid((PVOID)pDisp))
            return 0;

        /* WSK_PROVIDER_DISPATCH 内含 Version, Reserved, WskSocket, WskSocketConnect, WskControlSocket, WskGetLocalAddress */
        ULONG_PTR *pFuncArray = (ULONG_PTR *)pDisp;
        for (ULONG i = 1; i <= 6; i++)
        {
            ULONG_PTR fn = pFuncArray[i];
            if (!fn)
                continue;

            /* 4.1 指针是否指向 ACE */
            if (IsAddressInAceModules(fn))
            {
                DBG("[!] [HOOK ALARM-NET] WSK ProviderDispatch[%u] (0x%p) POINTER POINTS TO ACE!", i, (PVOID)fn);
                alarmCount++;
                if (!(s_ReportedWskMask & (1U << i)))
                {
                    s_ReportedWskMask |= (1U << i);
                    ExceptionReporter::ReportFormat("NetMonitor::WskDispatchPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                        "NET Hook: WSK ProviderDispatch[%u] POINTER POINTS TO ACE! Handler=0x%p", i, (PVOID)fn);
                }
            }

            /* 4.2 函数入口是否被 Inline Hook 到 ACE */
            ULONG_PTR target = GetInlineHookTarget(fn);
            if (target && IsAddressInAceModules(target))
            {
                DBG("[!] [HOOK ALARM-NET] WSK ProviderDispatch[%u] (0x%p) INLINE HOOKED -> ACE Target=0x%p", i, (PVOID)fn, (PVOID)target);
                alarmCount++;
                if (!(s_ReportedWskMask & (1U << i)))
                {
                    s_ReportedWskMask |= (1U << i);
                    ExceptionReporter::ReportFormat("NetMonitor::WskDispatchInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                        "NET Hook: WSK ProviderDispatch[%u] INLINE HOOKED -> ACE Target=0x%p", i, (PVOID)target);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG("[-] NetMonitor: Exception during WSK Dispatch audit");
    }

    return alarmCount;
#else
    return 0;
#endif
}

/*
 * ============================================================================
 * 监控面 5: WFP 核心 Callout 状态巡检（防止 ACE 动态重挂钩或还原）
 * ============================================================================
 */
ULONG NetMonitor::CheckWfpCallouts(VOID)
{
    ULONG wfpAlarms = 0;
    if (g_bAceDetected && !WfpBypass::IsInstalled())
    {
        /* 只要目标 ACE 存在且尚未成功接管，持续尝试探测初始化（应对 ACE 刚启动尚未完成 Callout 注册的时间差） */
        MACHENIKE_KERNEL_INTERFACE *pUserVar = g_pNetMonUserVar ? g_pNetMonUserVar : g_pGlobalUserVar;
        if (pUserVar)
        {
            DBG("[*] NetMonitor: ACE active in memory but Callouts not yet hooked/detected, trying WfpBypass::Init...");
            WfpBypass::Init(pUserVar);
        }

        /* 尝试初始化后若仍未成功接管，触发告警 */
        if (!WfpBypass::IsInstalled())
        {
            wfpAlarms++;
            DBG("[!] [HOOK ALARM-WFP] ACE active in memory but WFP Callouts NOT bypassed/protected!");
            if (!s_ReportedWfpUnprotectedAlarm)
            {
                s_ReportedWfpUnprotectedAlarm = TRUE;
                ExceptionReporter::ReportFormat("NetMonitor::WfpUnprotected", STATUS_SECURITY_CHECKS_FAILED,
                    "WFP Alarm: Target ACE active in memory but WFP Callouts NOT bypassed!");
            }
        }
        else
        {
            s_ReportedWfpUnprotectedAlarm = FALSE;
        }
    }
    else if (!g_bAceDetected)
    {
        s_ReportedWfpUnprotectedAlarm = FALSE;
    }
    return wfpAlarms;
}

/*
 * ============================================================================
 * 全栈主动扫描入口 (10秒周期)
 * ============================================================================
 */
VOID NetMonitor::ScanAll(VOID)
{
    static ULONG s_scanRound = 0;
    s_scanRound++;

    ULONG hooks = CheckTcpipHooks();
    ULONG attached = CheckTdiAttached();
    ULONG ndis = CheckNdisFilters();
    ULONG wskDisp = CheckWskDispatch();
    ULONG wfpStatus = CheckWfpCallouts();

    ULONG totalAlarms = hooks + attached + ndis + wskDisp + wfpStatus;

    if (totalAlarms > 0)
    {
        DBG("[!] NetMonitor [Round #%lu]: >>> THREAT DETECTED! Total=%u (TCP/AFD/PACER Hooks=%u, AttachedDevices=%u, NDIS Filters=%u, WSK "
            "Tamper=%u, WFP Alert=%u) <<<",
            s_scanRound, totalAlarms, hooks, attached, ndis, wskDisp, wfpStatus);
    }
    else
    {
        /* 仅每 5 轮或前 3 轮输出一次心跳正常日志，避免刷屏 */
        if (s_scanRound <= 3 || (s_scanRound % 5) == 0)
        {
            DBG("[+] NetMonitor [Round #%lu]: All clean — AFD/TCP/IP/PACER intact (no pointer/inline hooks), no AttachedDevices, "
                "NDIS filters clean, WSK dispatch intact",
                s_scanRound);
        }
    }
}

NTSTATUS NetMonitor::Init(VOID)
{
    ResetReportState();
    DBG("[+] NetMonitor: Network Full-Stack Security Monitoring Engine Initialized (10s Deduplicated)");
    return STATUS_SUCCESS;
}
