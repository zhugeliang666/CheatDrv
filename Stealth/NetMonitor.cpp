#include "Common.h"
#include "NetMonitor.h"
#include "Utils.h"
#if ENABLE_TRANSPORT_MODES
#include "wsk_server.h"
#endif
#include "ExceptionReporter.h"
#include "TransportManager.h"
#include "WfpBypass.h"

/*
 * ============================================================================
 * NetMonitor: 内核网络全栈多维安全监控引擎
 *
 * 1. 核心网络/套接字设备分发例程监控（\Device\Afd, Tcp, Udp, RawIp, Ip 及 \Driver\pacer）
 * 2. TDI / 设备栈附加过滤设备监控（AttachedDevice 链，包含 \Device\Afd）
 * 3. NDIS LWF 轻量级网络过滤驱动链表监控（ndisFilterDriverList）
 * 4. 通讯驱动自身的 WSK Provider Dispatch 函数表完整性自检
 * 5. WFP Callout 状态巡检（防止 ACE 动态重挂钩或还原）
 * 6. 前置 ACE 存活门禁 + 跨页范围安全探针 + 单次去重上报机制
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

static const PCWSTR g_MonitoredDevices[] = {
    L"\\Device\\Afd",
    L"\\Device\\Tcp",
    L"\\Device\\Udp",
    L"\\Device\\RawIp",
    L"\\Device\\Ip"
};

#define MONITORED_DEVICE_COUNT (sizeof(g_MonitoredDevices) / sizeof(g_MonitoredDevices[0]))

static const PCWSTR g_MonitoredNetDrivers[] = {
    L"\\Driver\\pacer",
    L"\\Driver\\tcpip",
    L"\\Driver\\afd"
};

#define MONITORED_NET_DRIVER_COUNT (sizeof(g_MonitoredNetDrivers) / sizeof(g_MonitoredNetDrivers[0]))

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
 * 监控面 1: 网络驱动分发例程 Hook 监控 (Pointer Hook + Inline Hook + FastIo)
 * ============================================================================
 */
ULONG NetMonitor::CheckTcpipHooks(VOID)
{
    if (!g_bAceDetected || g_AceModuleCount == 0)
        return 0;

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
            PDRIVER_OBJECT pDrv = Utils::IsValidKernelRange(pDevObj, sizeof(DEVICE_OBJECT)) ? pDevObj->DriverObject : NULL;
            if (Utils::IsValidKernelRange(pDrv, sizeof(DRIVER_OBJECT)))
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
                        WCHAR aceMod[32] = {0};
                        ULONG_PTR aceBase = 0, aceRva = 0;
                        ResolveAceModuleInfo(fn, aceMod, &aceBase, &aceRva);
                        DBG("[!] [HOOK ALARM-NET] %ws MajorFunction[%u] POINTER HOOKED by %ws! Handler=0x%p (+0x%llX)",
                            g_MonitoredDevices[d], i, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, aceRva);
                        hookCount++;
                        if (!(s_ReportedNetMajorMask[d] & (1U << (i & 31))))
                        {
                            s_ReportedNetMajorMask[d] |= (1U << (i & 31));
                            ExceptionReporter::ReportFormat("NetMonitor::MajorPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                                "NET Hook: %ws MajorFunction[%u] POINTER HOOKED by %ws! Handler=0x%p (Base=0x%p +0x%llX)",
                                g_MonitoredDevices[d], i, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, (PVOID)aceBase, aceRva);
                        }
                    }

                    /* 1.2 函数入口 Inline Hook 检测 (JMP 跳转至 ACE) */
                    ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(fn);
                    if (inlineTarget && IsAddressInAceModules(inlineTarget))
                    {
                        WCHAR aceMod[32] = {0};
                        ULONG_PTR aceBase = 0, aceRva = 0;
                        ResolveAceModuleInfo(inlineTarget, aceMod, &aceBase, &aceRva);
                        DBG("[!] [HOOK ALARM-NET] %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> %ws Target=0x%p (+0x%llX)",
                            g_MonitoredDevices[d], i, (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, aceRva);
                        hookCount++;
                        if (!(s_ReportedNetInlineMask[d] & (1U << (i & 31))))
                        {
                            s_ReportedNetInlineMask[d] |= (1U << (i & 31));
                            ExceptionReporter::ReportFormat("NetMonitor::MajorInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                                "NET Hook: %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                                g_MonitoredDevices[d], i, (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, (PVOID)aceBase, aceRva);
                        }
                    }
                }

                /* 2. 扫描 FastIoDispatch 快速通道 Hook */
                PFAST_IO_DISPATCH pFastIo = pDrv->FastIoDispatch;
                if (Utils::IsValidKernelRange(pFastIo, sizeof(ULONG)))
                {
                    ULONG_PTR *pFastIoArr = (ULONG_PTR *)pFastIo;
                    ULONG totalEntries = (pFastIo->SizeOfFastIoDispatch > 0 && pFastIo->SizeOfFastIoDispatch <= 512)
                                             ? (pFastIo->SizeOfFastIoDispatch / sizeof(PVOID))
                                             : 24;
                    if (totalEntries > 32)
                        totalEntries = 32;

                    if (Utils::IsValidKernelRange(pFastIo, (SIZE_T)totalEntries * sizeof(PVOID)))
                    {
                        for (ULONG j = 1; j < totalEntries; j++)
                        {
                            ULONG_PTR fn = pFastIoArr[j];
                            if (!fn)
                                continue;

                            if (IsAddressInAceModules(fn))
                            {
                                WCHAR aceMod[32] = {0};
                                ULONG_PTR aceBase = 0, aceRva = 0;
                                ResolveAceModuleInfo(fn, aceMod, &aceBase, &aceRva);
                                DBG("[!] [HOOK ALARM-NET] %ws FastIoDispatch[%u] POINTER HOOKED by %ws! Handler=0x%p (+0x%llX)",
                                    g_MonitoredDevices[d], j, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, aceRva);
                                hookCount++;
                                if (!(s_ReportedNetFastIoMask[d] & (1U << j)))
                                {
                                    s_ReportedNetFastIoMask[d] |= (1U << j);
                                    ExceptionReporter::ReportFormat("NetMonitor::FastIoPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                                        "NET Hook: %ws FastIoDispatch[%u] POINTER HOOKED by %ws! Handler=0x%p (Base=0x%p +0x%llX)",
                                        g_MonitoredDevices[d], j, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, (PVOID)aceBase, aceRva);
                                }
                            }

                            ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(fn);
                            if (inlineTarget && IsAddressInAceModules(inlineTarget))
                            {
                                WCHAR aceMod[32] = {0};
                                ULONG_PTR aceBase = 0, aceRva = 0;
                                ResolveAceModuleInfo(inlineTarget, aceMod, &aceBase, &aceRva);
                                DBG("[!] [HOOK ALARM-NET] %ws FastIoDispatch[%u] INLINE HOOKED -> %ws Target=0x%p (+0x%llX)",
                                    g_MonitoredDevices[d], j, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, aceRva);
                                hookCount++;
                                if (!(s_ReportedNetFastIoMask[d] & (1U << j)))
                                {
                                    s_ReportedNetFastIoMask[d] |= (1U << j);
                                    ExceptionReporter::ReportFormat("NetMonitor::FastIoInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                                        "NET Hook: %ws FastIoDispatch[%u] INLINE HOOKED -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                                        g_MonitoredDevices[d], j, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, (PVOID)aceBase, aceRva);
                                }
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

        if (pFileObj && g_pNetMonUserVar && g_pNetMonUserVar->Func.ObfDereferenceObject)
        {
            g_pNetMonUserVar->Func.ObfDereferenceObject(pFileObj);
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
                if (Utils::IsValidKernelRange(pNetDrvObj, sizeof(DRIVER_OBJECT)))
                {
                    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                    {
                        ULONG_PTR fn = (ULONG_PTR)pNetDrvObj->MajorFunction[i];
                        if (!fn)
                            continue;

                        if (IsAddressInAceModules(fn))
                        {
                            WCHAR aceMod[32] = {0};
                            ULONG_PTR aceBase = 0, aceRva = 0;
                            ResolveAceModuleInfo(fn, aceMod, &aceBase, &aceRva);
                            DBG("[!] [HOOK ALARM-NET] %ws MajorFunction[%u] POINTER HOOKED by %ws! Handler=0x%p (+0x%llX)",
                                g_MonitoredNetDrivers[nd], i, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, aceRva);
                            hookCount++;
                            if (!(s_ReportedDrvMajorMask[nd] & (1U << (i & 31))))
                            {
                                s_ReportedDrvMajorMask[nd] |= (1U << (i & 31));
                                ExceptionReporter::ReportFormat("NetMonitor::DriverMajorPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                                    "NET Hook: %ws MajorFunction[%u] POINTER HOOKED by %ws! Handler=0x%p (Base=0x%p +0x%llX)",
                                    g_MonitoredNetDrivers[nd], i, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, (PVOID)aceBase, aceRva);
                            }
                        }

                        ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(fn);
                        if (inlineTarget && IsAddressInAceModules(inlineTarget))
                        {
                            WCHAR aceMod[32] = {0};
                            ULONG_PTR aceBase = 0, aceRva = 0;
                            ResolveAceModuleInfo(inlineTarget, aceMod, &aceBase, &aceRva);
                            DBG("[!] [HOOK ALARM-NET] %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> %ws Target=0x%p (+0x%llX)",
                                g_MonitoredNetDrivers[nd], i, (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, aceRva);
                            hookCount++;
                            if (!(s_ReportedDrvInlineMask[nd] & (1U << (i & 31))))
                            {
                                s_ReportedDrvInlineMask[nd] |= (1U << (i & 31));
                                ExceptionReporter::ReportFormat("NetMonitor::DriverMajorInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                                    "NET Hook: %ws MajorFunction[%u] INLINE HOOKED -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                                    g_MonitoredNetDrivers[nd], i, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, (PVOID)aceBase, aceRva);
                            }
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
    if (!g_bAceDetected || g_AceModuleCount == 0)
        return 0;

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
            PDEVICE_OBJECT pCurr = Utils::IsValidKernelRange(pDevObj, sizeof(DEVICE_OBJECT)) ? pDevObj->AttachedDevice : NULL;
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
                        DBG("[!] [HOOK ALARM-NET] %ws AttachedDevice found on %ws stack! Driver=0x%p",
                            aceMod[0] ? aceMod : L"ACE", g_MonitoredDevices[d], (PVOID)drvStart);
                        attachedCount++;
                        if (!s_ReportedNetAttached[d])
                        {
                            s_ReportedNetAttached[d] = TRUE;
                            ExceptionReporter::ReportFormat("NetMonitor::TdiAttachedDevice", STATUS_SECURITY_CHECKS_FAILED,
                                "NET Hook: AttachedDevice by %ws on %ws! Driver=0x%p (Base=0x%p +0x%llX)",
                                aceMod[0] ? aceMod : L"ACE", g_MonitoredDevices[d], (PVOID)drvStart, (PVOID)aceBase, aceRva);
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
                            DBG("[!] [HOOK ALARM-NET] AttachedDevice on %ws has %ws Handler[%u]=0x%p (+0x%llX)",
                                g_MonitoredDevices[d], aceMod[0] ? aceMod : L"ACE", i, (PVOID)fn, aceRva);
                            attachedCount++;
                            if (!s_ReportedNetAttached[d])
                            {
                                s_ReportedNetAttached[d] = TRUE;
                                ExceptionReporter::ReportFormat("NetMonitor::TdiAttachedHandler", STATUS_SECURITY_CHECKS_FAILED,
                                    "NET Hook: AttachedDevice on %ws has %ws Handler[%u]=0x%p (Base=0x%p +0x%llX)",
                                    g_MonitoredDevices[d], aceMod[0] ? aceMod : L"ACE", i, (PVOID)fn, (PVOID)aceBase, aceRva);
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

        if (pFileObj && g_pNetMonUserVar && g_pNetMonUserVar->Func.ObfDereferenceObject)
        {
            g_pNetMonUserVar->Func.ObfDereferenceObject(pFileObj);
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
            if ((i & 0xFFF) == 0 && !MmIsAddressValid(pStart + i))
            {
                i += 0xFFF;
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
                    if (target >= g_NdisBase && target < g_NdisEnd && Utils::IsValidKernelRange((PVOID)target, sizeof(PVOID)))
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
    if (!g_bAceDetected || g_AceModuleCount == 0)
        return 0;

    ULONG fltMatchCount = 0;

    PVOID *pList = NetMonitor_LocateNdisFilterDriverList();
    if (!pList || !Utils::IsValidKernelRange(pList, sizeof(PVOID)))
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

        while (Utils::IsValidKernelRange(pBlock, 0xE8) && count < 64)
        {
            PDRIVER_OBJECT pFltDrv = *(PDRIVER_OBJECT *)((PUCHAR)pBlock + 0x10);
            if (Utils::IsValidKernelRange(pFltDrv, sizeof(DRIVER_OBJECT)))
            {
                ULONG_PTR drvBase = (ULONG_PTR)pFltDrv->DriverStart;
                if (IsAddressInAceModules(drvBase))
                {
                    WCHAR aceMod[32] = {0};
                    ULONG_PTR aceBase = 0, aceRva = 0;
                    ResolveAceModuleInfo(drvBase, aceMod, &aceBase, &aceRva);
                    DBG("[!] [HOOK ALARM-NET] %ws NDIS Filter Driver detected! Driver=0x%p",
                        aceMod[0] ? aceMod : L"ACE", (PVOID)drvBase);
                    fltMatchCount++;
                    if (!s_ReportedNdisFilterAlarm)
                    {
                        s_ReportedNdisFilterAlarm = TRUE;
                        ExceptionReporter::ReportFormat("NetMonitor::NdisFilterDriver", STATUS_SECURITY_CHECKS_FAILED,
                            "NET Hook: %ws NDIS Filter Driver detected! Driver=0x%p (Base=0x%p +0x%llX)",
                            aceMod[0] ? aceMod : L"ACE", (PVOID)drvBase, (PVOID)aceBase, aceRva);
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
                    WCHAR aceMod[32] = {0};
                    ULONG_PTR aceBase = 0, aceRva = 0;
                    ResolveAceModuleInfo(fn, aceMod, &aceBase, &aceRva);
                    DBG("[!] [HOOK ALARM-NET] %ws NDIS Filter Callback detected! Handler=0x%p (+0x%llX)",
                        aceMod[0] ? aceMod : L"ACE", (PVOID)fn, aceRva);
                    fltMatchCount++;
                    if (!s_ReportedNdisFilterAlarm)
                    {
                        s_ReportedNdisFilterAlarm = TRUE;
                        ExceptionReporter::ReportFormat("NetMonitor::NdisFilterCallback", STATUS_SECURITY_CHECKS_FAILED,
                            "NET Hook: %ws NDIS Filter Callback detected! Handler=0x%p (Base=0x%p +0x%llX)",
                            aceMod[0] ? aceMod : L"ACE", (PVOID)fn, (PVOID)aceBase, aceRva);
                    }
                    break;
                }

                ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(fn);
                if (inlineTarget && IsAddressInAceModules(inlineTarget))
                {
                    WCHAR aceMod[32] = {0};
                    ULONG_PTR aceBase = 0, aceRva = 0;
                    ResolveAceModuleInfo(inlineTarget, aceMod, &aceBase, &aceRva);
                    DBG("[!] [HOOK ALARM-NET] NDIS Filter Callback (0x%p) INLINE HOOKED -> %ws Target=0x%p (+0x%llX)",
                        (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, aceRva);
                    fltMatchCount++;
                    if (!s_ReportedNdisFilterAlarm)
                    {
                        s_ReportedNdisFilterAlarm = TRUE;
                        ExceptionReporter::ReportFormat("NetMonitor::NdisFilterInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                            "NET Hook: NDIS Filter Callback (0x%p) INLINE HOOKED -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                            (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)inlineTarget, (PVOID)aceBase, aceRva);
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
    if (!g_bAceDetected || g_AceModuleCount == 0)
        return 0;

    ULONG alarmCount = 0;

    if (!g_WskServer.fCapturedNpi || !g_WskServer.ProviderNpi.Dispatch)
        return 0;

    __try
    {
        const WSK_PROVIDER_DISPATCH *pDisp = g_WskServer.ProviderNpi.Dispatch;
        if (!Utils::IsValidKernelRange(pDisp, 7 * sizeof(ULONG_PTR)))
            return 0;

        ULONG_PTR *pFuncArray = (ULONG_PTR *)pDisp;
        for (ULONG i = 1; i <= 6; i++)
        {
            ULONG_PTR fn = pFuncArray[i];
            if (!fn)
                continue;

            /* 4.1 指针是否指向 ACE */
            if (IsAddressInAceModules(fn))
            {
                WCHAR aceMod[32] = {0};
                ULONG_PTR aceBase = 0, aceRva = 0;
                ResolveAceModuleInfo(fn, aceMod, &aceBase, &aceRva);
                DBG("[!] [HOOK ALARM-NET] WSK ProviderDispatch[%u] (0x%p) POINTER POINTS TO %ws! (+0x%llX)",
                    i, (PVOID)fn, aceMod[0] ? aceMod : L"ACE", aceRva);
                alarmCount++;
                if (!(s_ReportedWskMask & (1U << i)))
                {
                    s_ReportedWskMask |= (1U << i);
                    ExceptionReporter::ReportFormat("NetMonitor::WskDispatchPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                        "NET Hook: WSK ProviderDispatch[%u] POINTS TO %ws! Handler=0x%p (Base=0x%p +0x%llX)",
                        i, aceMod[0] ? aceMod : L"ACE", (PVOID)fn, (PVOID)aceBase, aceRva);
                }
            }

            /* 4.2 函数入口是否被 Inline Hook 到 ACE */
            ULONG_PTR target = Utils::DecodeInlineHookTarget(fn);
            if (target && IsAddressInAceModules(target))
            {
                WCHAR aceMod[32] = {0};
                ULONG_PTR aceBase = 0, aceRva = 0;
                ResolveAceModuleInfo(target, aceMod, &aceBase, &aceRva);
                DBG("[!] [HOOK ALARM-NET] WSK ProviderDispatch[%u] (0x%p) INLINE HOOKED -> %ws Target=0x%p (+0x%llX)",
                    i, (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)target, aceRva);
                alarmCount++;
                if (!(s_ReportedWskMask & (1U << i)))
                {
                    s_ReportedWskMask |= (1U << i);
                    ExceptionReporter::ReportFormat("NetMonitor::WskDispatchInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                        "NET Hook: WSK ProviderDispatch[%u] (0x%p) INLINE HOOKED -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                        i, (PVOID)fn, aceMod[0] ? aceMod : L"ACE", (PVOID)target, (PVOID)aceBase, aceRva);
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
    /* 严格门禁：若为 USB 传输模式，网络不经过宿主 WFP 过滤栈，绝不替换 Callout 且不产生误报 */
    if (TransportManager::IsUsbMode())
    {
        s_ReportedWfpUnprotectedAlarm = FALSE;
        return 0;
    }

    ULONG wfpAlarms = 0;
    if (!g_bAceDetected || g_AceModuleCount == 0)
    {
        s_ReportedWfpUnprotectedAlarm = FALSE;
        return 0;
    }

    /* 路径 1: 尚未成功安装或尚未捕获到 Callout（冷启动/等待 ACE 注册完成） */
    if (!WfpBypass::IsInstalled())
    {
        NTSTATUS initSt = STATUS_UNSUCCESSFUL;
        MACHENIKE_KERNEL_INTERFACE *pUserVar = g_pNetMonUserVar ? g_pNetMonUserVar : g_pGlobalUserVar;
        if (pUserVar)
        {
            DBG("[*] NetMonitor: ACE active in memory but Callouts not yet hooked/detected, trying WfpBypass::Init...");
            initSt = WfpBypass::Init(pUserVar);
        }

        /* 若处于 5 秒防抖等待期 (STATUS_DEVICE_NOT_READY)，属正常初始化窗口，不产生误报 */
        if (initSt == STATUS_DEVICE_NOT_READY)
        {
            return 0;
        }

        /* 方案 1:
         * 仅当系统 Callout 表中真实扫描到指向 ACE 范围的 Callout 且未能成功保护/替换时（存在未保护回调），才触发告警；
         * 若整个 Callout 表中根本没有匹配到任何 ACE Callout（例如仅加载了 ACE-BOOT.sys，尚未注册任何 Callout），
         * 则保持静默监听等待后续驱动注册，绝不误报 WfpUnprotected。
         */
        ULONG unprotectedCount = WfpBypass::GetUnprotectedCalloutCount();
        if (unprotectedCount > 0)
        {
            wfpAlarms++;
            DBG("[!] [HOOK ALARM-WFP] %lu ACE Callouts found in WFP but FAILED to protect!", unprotectedCount);
            if (!s_ReportedWfpUnprotectedAlarm)
            {
                s_ReportedWfpUnprotectedAlarm = TRUE;
                WCHAR allMods[128] = {0};
                ULONG offset = 0;
                for (ULONG m = 0; m < g_AceModuleCount && m < ACE_MAX_TRACKED_MODULES; m++)
                {
                    if (g_AceModules[m].Name[0])
                    {
                        if (offset > 0 && offset < 120)
                        {
                            allMods[offset++] = L',';
                            allMods[offset++] = L' ';
                        }
                        for (ULONG c = 0; c < 31 && g_AceModules[m].Name[c] && offset < 126; c++)
                        {
                            allMods[offset++] = g_AceModules[m].Name[c];
                        }
                        allMods[offset] = L'\0';
                    }
                }

                ExceptionReporter::ReportFormat("NetMonitor::WfpUnprotected", STATUS_SECURITY_CHECKS_FAILED,
                    "WFP Alarm: %lu Active ACE Mods [%ws] (Base=0x%p) Callouts NOT bypassed/protected! (UnprotectedCount=%lu)",
                    g_AceModuleCount, allMods[0] ? allMods : L"ACE", (PVOID)(g_AceModuleCount > 0 ? g_AceModules[0].Base : 0),
                    unprotectedCount);
            }
        }
        else
        {
            s_ReportedWfpUnprotectedAlarm = FALSE;
        }
    }
    /* 路径 2: 已经成功接管（执行防还原与自愈巡检） */
    else
    {
        WFP_ALARM_DETAIL alarm = {0};
        ULONG reverted = WfpBypass::VerifyAndRepairSlots(&alarm);
        if (reverted > 0)
        {
            wfpAlarms += reverted;
            DBG("[!] [HOOK ALARM-WFP] %lu WFP Callouts REVERTED by ACE! Repaired successfully.", reverted);

            ExceptionReporter::ReportFormat("NetMonitor::WfpReverted", STATUS_SECURITY_CHECKS_FAILED,
                "WFP Revert Alarm: Slot[%u] Mod=%ws (Base=0x%p) ClassifyFn=0x%p (+0x%llX) Reverted&Repaired!",
                alarm.SlotIndex, alarm.ModuleName[0] ? alarm.ModuleName : L"ACE", (PVOID)alarm.ModuleBase,
                (PVOID)alarm.ClassifyFn, alarm.Rva);
        }
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
