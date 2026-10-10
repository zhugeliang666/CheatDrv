#include "Common.h"
#include "MachenikeString.h"
#include "Struct.h"
#include "Utils.h"
#include "rpc_dispatch.h"
#include "transport_manager.h"
#include "wsk_server.h"
#include "udp_discovery.h"
#include "stealth_reloc.h"
#include "wfp_bypass.h"
#include "usb_hub.h"
#include "net_monitor.h"


static PDEVICE_OBJECT g_pControlDevObj = NULL;
static PDRIVER_OBJECT g_pDriverObj = NULL;
static PMACHENIKE_KERNEL_INTERFACE g_pGlobalUserVar = NULL;
static PVOID g_pDriverActualPoolBase = NULL;
static PKLDR_DATA_TABLE_ENTRY g_pHostDriverSection = NULL;

#ifdef IoCompleteRequest
#undef IoCompleteRequest
#endif
#define IoCompleteRequest(irp, prio) do { if (g_pGlobalUserVar && g_pGlobalUserVar->Func.IofCompleteRequest) { g_pGlobalUserVar->Func.IofCompleteRequest(irp, prio); } } while(0)


/* 全局 ACE 反作弊驱动探测缓存（支持同时追踪多个核心模块如 102706/202706/302706） */
ACE_MODULE_RANGE g_AceModules[ACE_MAX_TRACKED_MODULES] = {0};
ULONG g_AceModuleCount = 0;
ULONG_PTR g_AceModuleBase = 0;
ULONG_PTR g_AceModuleEnd = 0;
BOOLEAN g_bAceDetected = FALSE;

/*
 * 独立常驻 ACE 模块监控上下文：
 * 单独创建 WorkItem 去一直寻找 ACE 驱动（应对游戏关闭、重启后基址改变），
 * 探测到变化自动更新全局变量 g_AceModuleBase / g_AceModuleEnd / g_bAceDetected。
 */
typedef struct _ACE_MONITOR_WORK_CONTEXT
{
    WORK_QUEUE_ITEM WorkItem; /* 必须位于结构体首部 */
    PKLDR_DATA_TABLE_ENTRY pDriverSection;
    KTIMER Timer;
    KDPC Dpc;
    volatile LONG fStopped;
    volatile LONG fWorkItemQueued;
} ACE_MONITOR_WORK_CONTEXT, *PACE_MONITOR_WORK_CONTEXT;

static ACE_MONITOR_WORK_CONTEXT g_AceMonitorCtx;
static BOOLEAN g_AceMonitorTimerStarted = FALSE;

static BOOLEAN Main_ContainsSubstrCaseless(PCWSTR pszStr, ULONG cchStr, PCWSTR pszSub)
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

static BOOLEAN Main_IsAceModuleName(PCWSTR pName, ULONG cchName, ULONG u32Hash)
{
    if (!pName || cchName == 0)
        return FALSE;

    // 1. 已知静态哈希命中（快速路径）
    if (u32Hash == wstr_AceCore302706 || u32Hash == wstr_AceCore202706 ||
        u32Hash == wstr_AceCore102706 || u32Hash == wstr_AceBase)
    {
        return TRUE;
    }

    // 2. 本地模拟/测试驱动
    if (Main_ContainsSubstrCaseless(pName, cchName, L"mockace") ||
        Main_ContainsSubstrCaseless(pName, cchName, L"mock_ace"))
    {
        return TRUE;
    }

    // 3. 通配所有 ACE 反作弊子驱动（如 ACE_ADVT.sys, ace_game_0.sys, ACE_SSC_DRV64.sys, ACE-GAME.sys, ACE-BOOT.sys 等）
    // 匹配前缀 "ace-" 或 "ace_" 或 "ace." (不区分大小写)
    if (cchName >= 4)
    {
        WCHAR c0 = (pName[0] >= L'a' && pName[0] <= L'z') ? (pName[0] - 32) : pName[0];
        WCHAR c1 = (pName[1] >= L'a' && pName[1] <= L'z') ? (pName[1] - 32) : pName[1];
        WCHAR c2 = (pName[2] >= L'a' && pName[2] <= L'z') ? (pName[2] - 32) : pName[2];
        WCHAR c3 = pName[3];

        if (c0 == L'A' && c1 == L'C' && c2 == L'E')
        {
            if (c3 == L'-' || c3 == L'_' || c3 == L'.')
                return TRUE;
        }
    }

    // 匹配包含 "_ace_" 或 "-ace-" 的子驱动
    if (Main_ContainsSubstrCaseless(pName, cchName, L"_ace_") ||
        Main_ContainsSubstrCaseless(pName, cchName, L"-ace-"))
    {
        return TRUE;
    }

    return FALSE;
}


VOID MachenikeScanBypassModules(IN PKLDR_DATA_TABLE_ENTRY DriverSection)
{
    if (!DriverSection)
        return;

    ULONG_PTR targetBase = 0;
    ULONG_PTR targetEnd = 0;
    ULONG_PTR targetFn = 0;

    for (PLIST_ENTRY pListEntry = DriverSection->InLoadOrderLinks.Flink; pListEntry != &DriverSection->InLoadOrderLinks;
         pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!pEntry->DllBase || !pEntry->BaseDllName.Buffer)
            continue;

        ULONG cchName = pEntry->BaseDllName.Length / sizeof(WCHAR);
        ULONG U32ModuleName = Utils_HashStringImulMagicExW(pEntry->BaseDllName.Buffer, cchName, TRUE);

        if (U32ModuleName == wstr_Netio || Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"netio"))
        {
            ULONG_PTR netioBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR netioEnd = netioBase + pEntry->SizeOfImage;
            ULONG_PTR fnAddr = 0;

            if (Utils_GetModuleExport(netioBase, str_KfdAddCalloutEntry, &fnAddr) && fnAddr)
            {
                targetBase = netioBase;
                targetEnd = netioEnd;
                targetFn = fnAddr;
                DBG("[+] netio [0x%p-0x%p] KfdAddCalloutEntry=0x%p", (PVOID)netioBase, (PVOID)netioEnd, (PVOID)fnAddr);
            }
            else if (Utils_GetModuleExport(netioBase, str_FwpsCalloutRegister2, &fnAddr) && fnAddr)
            {
                targetBase = netioBase;
                targetEnd = netioEnd;
                targetFn = fnAddr;
                DBG("[+] netio [0x%p-0x%p] FwpsCalloutRegister2=0x%p", (PVOID)netioBase, (PVOID)netioEnd,
                    (PVOID)fnAddr);
            }
        }
        else if (U32ModuleName == wstr_Fwpkclnt ||
                 Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"fwpkclnt"))
        {
            ULONG_PTR fwpBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR fwpEnd = fwpBase + pEntry->SizeOfImage;
            ULONG_PTR fnAddr = 0;

            if (Utils_GetModuleExport(fwpBase, str_FwpsCalloutRegister2, &fnAddr) && fnAddr)
            {
                DBG("[+] fwpkclnt [0x%p-0x%p] FwpsCalloutRegister2=0x%p", (PVOID)fwpBase, (PVOID)fwpEnd, (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
            else if (Utils_GetModuleExport(fwpBase, str_FwpsCalloutRegister1, &fnAddr) && fnAddr)
            {
                DBG("[+] fwpkclnt FwpsCalloutRegister1=0x%p", (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
            else if (Utils_GetModuleExport(fwpBase, str_FwpsCalloutRegister0, &fnAddr) && fnAddr)
            {
                DBG("[+] fwpkclnt FwpsCalloutRegister0=0x%p", (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
        }
        else if (Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"ndis.sys") ||
                 Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"ndis"))
        {
            ULONG_PTR ndisBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR ndisEnd  = ndisBase + pEntry->SizeOfImage;
            NetMonitor_SetNdisModule(ndisBase, ndisEnd);
        }
    }

    if (targetBase && targetEnd && targetFn)
    {
        WfpBypass_SetNetioInfo(targetBase, targetEnd, (PVOID)targetFn);
    }
}

/*
 * MachenikeReadMsrSafe — 安全读取 CPU MSR 寄存器 (仿照 ComputerZ_x64.sys sub_12404)
 * 使用 __try / __except 捕获 #GP 异常，防止读取未实现/保留的 MSR 寄存器导致内核崩溃
 */
extern "C" BOOLEAN MachenikeReadMsrSafe(ULONG MsrIndex, PULONG64 pValue)
{
    if (!pValue)
        return FALSE;

    __try
    {
        *pValue = __readmsr(MsrIndex);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *pValue = 0;
        return FALSE;
    }
}

ULONGLONG MachenikeGetUnixTimeSeconds(IN MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    LARGE_INTEGER CurrentTime = {};
    UserVar->Func.KeQuerySystemTimePrecise(&CurrentTime);
    ULONGLONG sec = (ULONGLONG)CurrentTime.QuadPart / 10000000ULL;
    return (sec >= 11644473600ULL) ? (sec - 11644473600ULL) : 0;
}

ULONG MachenikeCalcToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONGLONG Counter, IN ULONG ProcessId)
{
    UCHAR msg[16] = {0};

    UserVar->Func.memcpy(&msg[0], &Counter, 8);
    UserVar->Func.memcpy(&msg[8], &ProcessId, 4);
    UserVar->Func.memcpy(&msg[12], &UserVar->Salt4, 4);
    UINT64 Hash = Utils_SipHash24(UserVar->SipHashKey, msg, sizeof(msg));
    return (ULONG)(Hash ^ (Hash >> 32));
}

NTSTATUS MachenikeDispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS status = STATUS_SUCCESS;
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG CurrentToken = 0;
    ULONG CurrentProcessId = HandleToULong(UserVar->Func.PsGetCurrentProcessId());
    ULONGLONG Counter = MachenikeGetUnixTimeSeconds(UserVar) / UserVar->Step;
    BOOLEAN ok = FALSE;
    status = Utils_ParseTokenFromFileName(&pIrpStack->FileObject->FileName, &CurrentToken);
    if (!NT_SUCCESS(status))
    {
        DBG("DispatchCreate: Invalid token format in filename (status=0x%08X)", status);
        pIrp->IoStatus.Status = STATUS_ACCESS_DENIED;
        pIrp->IoStatus.Information = 0;
        UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }
    for (LONGLONG i = -1; i <= 1; i++)
    {
        if (MachenikeCalcToken(UserVar, (ULONGLONG)((LONGLONG)Counter + i), CurrentProcessId) == CurrentToken)
        {
            ok = TRUE;
            break;
        }
    }
    DBG("DispatchCreate: Client PID=%u, Token=0x%08X, Access=%s", CurrentProcessId, CurrentToken,
        ok ? "GRANTED" : "DENIED");
    pIrp->IoStatus.Status = ok ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    pIrp->IoStatus.Information = 0;
    UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    return pIrp->IoStatus.Status;
}

NTSTATUS MachenikeDispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);
    DBG("DispatchClose: Device handle closed");
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * Main_AceMonitorWorkRoutine — 独立常驻 WorkItem，持续寻找并监控 ACE 驱动模块
 * 专门应对游戏关闭、重启后模块基址随 ASLR 改变的情况；检测到变化直接更新全局变量，
 * 后续所有逻辑统一消费全局变量，无需再次重复遍历。
 */
static VOID Main_AceMonitorWorkRoutine(IN PVOID Parameter)
{
    PACE_MONITOR_WORK_CONTEXT pCtx = (PACE_MONITOR_WORK_CONTEXT)Parameter;
    if (!pCtx)
        return;

    InterlockedExchange(&pCtx->fWorkItemQueued, 0);

    if (InterlockedCompareExchange(&pCtx->fStopped, 0, 0) != 0)
        return;

    if (!pCtx->pDriverSection)
        return;

    static ULONG s_scanRound = 0;
    s_scanRound++;

    PKLDR_DATA_TABLE_ENTRY DriverSection = pCtx->pDriverSection;
    ACE_MODULE_RANGE curModules[ACE_MAX_TRACKED_MODULES] = {0};
    ULONG foundCount = 0;
    ULONG totalModules = 0;

    for (PLIST_ENTRY pListEntry = DriverSection->InLoadOrderLinks.Flink; pListEntry != &DriverSection->InLoadOrderLinks;
         pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!pEntry->DllBase || !pEntry->BaseDllName.Buffer)
            continue;

        totalModules++;

        ULONG cchName = pEntry->BaseDllName.Length / sizeof(WCHAR);
        ULONG U32ModuleName = Utils_HashStringImulMagicExW(pEntry->BaseDllName.Buffer, cchName, TRUE);

        if (Main_IsAceModuleName(pEntry->BaseDllName.Buffer, cchName, U32ModuleName))
        {
            if (foundCount < ACE_MAX_TRACKED_MODULES)
            {
                curModules[foundCount].Base = (ULONG_PTR)pEntry->DllBase;
                curModules[foundCount].End = curModules[foundCount].Base + pEntry->SizeOfImage;
                curModules[foundCount].Hash = U32ModuleName;

                ULONG copyChars = (cchName < 31) ? cchName : 31;
                for (ULONG k = 0; k < copyChars; k++)
                {
                    curModules[foundCount].Name[k] = pEntry->BaseDllName.Buffer[k];
                }
                curModules[foundCount].Name[copyChars] = L'\0';
                foundCount++;
            }
        }
    }

    BOOLEAN bChanged = FALSE;
    if (foundCount != g_AceModuleCount)
    {
        bChanged = TRUE;
    }
    else
    {
        for (ULONG m = 0; m < foundCount; m++)
        {
            if (g_AceModules[m].Base != curModules[m].Base || g_AceModules[m].End != curModules[m].End)
            {
                bChanged = TRUE;
                break;
            }
        }
    }

    if (foundCount > 0)
    {
        /* 若基址改变或首次探测到，更新全局变量与各个子系统的缓存 */
        if (!g_bAceDetected || bChanged)
        {
            RtlCopyMemory(g_AceModules, curModules, sizeof(curModules));
            g_AceModuleCount = foundCount;
            g_AceModuleBase = curModules[0].Base;
            g_AceModuleEnd = curModules[0].End;
            g_bAceDetected = TRUE;

            DBG("[+] AceMonitor [Round #%lu]: >>> DETECTED %lu Target ACE Modules in memory! <<<", s_scanRound,
                foundCount);
            for (ULONG m = 0; m < foundCount; m++)
            {
                DBG("    [%lu] %ws [0x%p-0x%p]", m + 1, g_AceModules[m].Name, (PVOID)g_AceModules[m].Base,
                    (PVOID)g_AceModules[m].End);
            }

            /* ACE 首次出现或基址改变（游戏重启），重置旧的 WFP 记录以便重新挂接 */
            WfpBypass_ResetState();
        }
        else
        {
            /* 维持已发现的心跳状态输出 */
            if (s_scanRound <= 5 || (s_scanRound % 5) == 0)
            {
                DBG("[*] AceMonitor [Round #%lu]: %lu Target ACE modules active in memory (modules=%lu)", s_scanRound,
                    g_AceModuleCount, totalModules);
            }
        }

#if ENABLE_WFP_BYPASS
        /* 只要目标 ACE 存在且尚未成功接管/检测，持续在每个周期尝试探测（应对 ACE 刚启动尚未完成 Callout 注册的时间差）
         */
        if (g_pGlobalUserVar && !WfpBypass_IsInstalled())
        {
            DBG("[*] AceMonitor [Round #%lu]: ACE present but Callouts not yet hooked/detected, trying "
                "WfpBypass_Init...",
                s_scanRound);
            WfpBypass_Init(g_pGlobalUserVar);
        }
#endif

        /* 执行非 WFP 维度的网络全栈主动监控：
         * 1. TCP/IP MajorFunction Hooks
         * 2. TDI / AttachedDevices 过滤设备栈
         * 3. NDIS LWF 过滤驱动链表 (ndisFilterDriverList)
         */
        NetMonitor_ScanAll();
    }
    else
    {
        /* 游戏未开启或已关闭退出：若先前已检测到，重置状态以备下次重启重新捕获新基址 */
        if (g_bAceDetected)
        {
            DBG("[-] AceMonitor [Round #%lu]: Target ACE drivers exited/unloaded, resetting cached bases & WFP state",
                s_scanRound);
            RtlZeroMemory(g_AceModules, sizeof(g_AceModules));
            g_AceModuleCount = 0;
            g_AceModuleBase = 0;
            g_AceModuleEnd = 0;
            g_bAceDetected = FALSE;
            WfpBypass_ResetState();
        }
        else
        {
            /* 未找到目标 ACE 驱动：输出心跳寻找日志，让用户明确知晓线程在运行 */
            if (s_scanRound <= 5 || (s_scanRound % 5) == 0)
            {
                DBG("[*] AceMonitor [Round #%lu]: Scanning PsLoadedModuleList (total %lu modules), target ACE driver "
                    "not yet loaded...",
                    s_scanRound, totalModules);
            }
        }
    }

    /* 模块寻址独归后台线程：在工作项中一并确保系统网络过滤模块 (netio) 信息就绪 */
    static BOOLEAN s_bNetioScanned = FALSE;
    if (!s_bNetioScanned)
    {
        MachenikeScanBypassModules(DriverSection);
        s_bNetioScanned = TRUE;
    }
}

static VOID Main_AceMonitorDpc(IN PKDPC Dpc, IN PVOID Context, IN PVOID SystemArg1, IN PVOID SystemArg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArg1);
    UNREFERENCED_PARAMETER(SystemArg2);

    PACE_MONITOR_WORK_CONTEXT pCtx = (PACE_MONITOR_WORK_CONTEXT)Context;
    if (!pCtx || InterlockedCompareExchange(&pCtx->fStopped, 0, 0) != 0)
        return;

    if (InterlockedCompareExchange(&pCtx->fWorkItemQueued, 1, 0) == 0)
    {
        ExQueueWorkItem(&pCtx->WorkItem, DelayedWorkQueue);
    }
}

/*
 * Main_StartAceMonitorEngine — 启动常驻 ACE 模块监控引擎
 */
static VOID Main_StartAceMonitorEngine(PKLDR_DATA_TABLE_ENTRY pHostDriverSection)
{
    if (g_AceMonitorTimerStarted || !pHostDriverSection)
        return;

    PACE_MONITOR_WORK_CONTEXT pCtx = &g_AceMonitorCtx;
    ExInitializeWorkItem(&pCtx->WorkItem, Main_AceMonitorWorkRoutine, pCtx);
    pCtx->pDriverSection = pHostDriverSection;
    InterlockedExchange(&pCtx->fStopped, 0);
    InterlockedExchange(&pCtx->fWorkItemQueued, 0);

    KeInitializeDpc(&pCtx->Dpc, Main_AceMonitorDpc, pCtx);
    KeInitializeTimerEx(&pCtx->Timer, SynchronizationTimer);

    LARGE_INTEGER DueTime;
    DueTime.QuadPart = -(LONGLONG)(1ULL * 1000 * 10000); /* 1s 后首次触发 */
    KeSetTimerEx(&pCtx->Timer, DueTime, 2000 /* 周期 2s 持续寻找 */, &pCtx->Dpc);
    g_AceMonitorTimerStarted = TRUE;

    DBG("[+] AceMonitor: Dedicated background monitor engine started (2s period)");
}

#if !MK_ENABLE_MANUAL_MAP
static PDEVICE_OBJECT g_pDeviceObject = NULL;
static UNICODE_STRING g_DeviceName = {};
static UNICODE_STRING g_SymbolicLinkName = {};
static BOOLEAN g_SymbolicLinkCreated = FALSE;

/*
 * 正常加载模式：通过 IOCTL 控制启动通信服务端 (TCP / UDP / USB)
 * 客户端由同机 R3 控制下发，无需经过 UDP 广播发现等待，直接上线并设置 WFP 保护
 */
static NTSTATUS Main_StartTransportByIo(MACHENIKE_KERNEL_INTERFACE *UserVar, const DRV_BOOT_CONFIG *pBootConfig)
{
    if (!UserVar || !pBootConfig)
    {
        return STATUS_INVALID_PARAMETER;
    }

    MK_SERVER_START_PARAMS srvParams = {};
    if (pBootConfig->TransportMode == DRV_TRANSPORT_TCP)
    {
        srvParams.Mode = MK_SERVER_MODE_WSK_TCP;
        srvParams.Port = pBootConfig->Port ? pBootConfig->Port : MK_WSK_DEFAULT_PORT;
    }
    else if (pBootConfig->TransportMode == DRV_TRANSPORT_UDP)
    {
        srvParams.Mode = MK_SERVER_MODE_WSK_UDP;
        srvParams.Port = pBootConfig->Port ? pBootConfig->Port : MK_UDP_SERVER_DEFAULT_PORT;
    }
    else if (pBootConfig->TransportMode == DRV_TRANSPORT_USB)
    {
        srvParams.Mode = MK_SERVER_MODE_USB;
    }
    else
    {
        DBG("[-] Main_StartTransportByIo: Invalid transport mode %u", pBootConfig->TransportMode);
        return STATUS_INVALID_PARAMETER;
    }

    DBG("[+] Main_StartTransportByIo: Starting server by IO command (Mode=%u Port=%u)...",
        srvParams.Mode, srvParams.Port);

    NTSTATUS srvStatus = Transport_StartServer(UserVar, &srvParams);
    if (!NT_SUCCESS(srvStatus))
    {
        DBG("[-] Main_StartTransportByIo: Transport_StartServer failed (0x%08X)", srvStatus);
        return srvStatus;
    }

    DBG("[+] Main_StartTransportByIo: Server online successfully (Mode=%u Port=%u)",
        srvParams.Mode, srvParams.Port);

    return STATUS_SUCCESS;
}

/*
 * 正常加载模式：启动发现设备例程 (对应 IOCTL_MK_DISCOVER_CLIENT)
 * 仅执行 UDP 广播握手探测客户端，将结果返回给应用层，不启动服务端
 */
static NTSTATUS Main_DiscoverDeviceByIo(
    MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_opt_ const MK_DISCOVERY_PARAMS *pCustomParams,
    _Out_ PMK_DISCOVERY_RESULT pOutResult)
{
    if (!UserVar || !pOutResult)
    {
        return STATUS_INVALID_PARAMETER;
    }

    MK_DISCOVERY_PARAMS discParams = {0};
    discParams.TimeoutMs = 5000;
    discParams.ServerTcpPort = MK_WSK_DEFAULT_PORT;

    if (pCustomParams)
    {
        discParams = *pCustomParams;
        if (discParams.TimeoutMs == 0)
        {
            discParams.TimeoutMs = 5000;
        }
        if (discParams.ServerTcpPort == 0)
        {
            discParams.ServerTcpPort = MK_WSK_DEFAULT_PORT;
        }
    }

    DBG("[*] Main_DiscoverDeviceByIo: Starting UDP client device discovery (Timeout=%ums, Port=%u)...",
        discParams.TimeoutMs, discParams.ServerTcpPort);

    NTSTATUS status = UdpDiscovery_DiscoverClient(UserVar, &discParams, pOutResult);
    if (NT_SUCCESS(status) && pOutResult->fFound)
    {
        DBG("[+] Main_DiscoverDeviceByIo: Target client discovered at %s:%u",
            pOutResult->ClientIpStr, pOutResult->ClientPort);
    }
    else
    {
        DBG("[-] Main_DiscoverDeviceByIo: Client discovery finished, not found (status=0x%08X, fFound=%d)",
            status, pOutResult->fFound);
    }

    return status;
}

/*
 * 正常加载模式：Create / Close 分发例程
 */
static NTSTATUS MachenikeIoCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * 正常加载模式：DeviceControl 分发例程，响应 R3 下发的启动/停止/发现/状态查询 IOCTL
 */
static NTSTATUS MachenikeIoDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inBufLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outBufLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID inBuf = Irp->AssociatedIrp.SystemBuffer;
    PVOID outBuf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytesReturned = 0;

    switch (ioControlCode)
    {
    case IOCTL_MK_START_TRANSPORT:
    {
        if (inBufLen < sizeof(DRV_BOOT_CONFIG) || !inBuf)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PDRV_BOOT_CONFIG pCfg = (PDRV_BOOT_CONFIG)inBuf;
        if (pCfg->Magic != DRV_BOOT_CONFIG_MAGIC)
        {
            DBG("[-] IOCTL_MK_START_TRANSPORT: Invalid Magic 0x%08X (expected 0x%08X)", pCfg->Magic,
                DRV_BOOT_CONFIG_MAGIC);
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        DBG("[+] IOCTL_MK_START_TRANSPORT: R3 requested start server (Mode=%u Port=%u)",
            pCfg->TransportMode, pCfg->Port);

        status = Main_StartTransportByIo(g_pGlobalUserVar, pCfg);
        break;
    }

    case IOCTL_MK_DISCOVER_CLIENT:
    {
        if (outBufLen < sizeof(MK_DISCOVERY_RESULT) || !outBuf)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (g_pGlobalUserVar)
        {
            const MK_DISCOVERY_PARAMS *pParams = NULL;
            if (inBuf && inBufLen >= sizeof(MK_DISCOVERY_PARAMS))
            {
                pParams = (const MK_DISCOVERY_PARAMS *)inBuf;
            }

            status = Main_DiscoverDeviceByIo(g_pGlobalUserVar, pParams, (PMK_DISCOVERY_RESULT)outBuf);
            bytesReturned = sizeof(MK_DISCOVERY_RESULT);
        }
        else
        {
            status = STATUS_DEVICE_NOT_READY;
        }
    }

    case IOCTL_MK_STOP_TRANSPORT:
    {
        DBG("[*] IOCTL_MK_STOP_TRANSPORT: R3 requested stop server");
        if (g_pGlobalUserVar)
        {
            Transport_StopServer(g_pGlobalUserVar);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_DEVICE_NOT_READY;
        }
        break;
    }

    case IOCTL_MK_GET_STATUS:
    {
        if (outBufLen < sizeof(MK_SERVER_STATUS) || !outBuf)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (g_pGlobalUserVar)
        {
            Transport_GetStatus(g_pGlobalUserVar, (PMK_SERVER_STATUS)outBuf);
            bytesReturned = sizeof(MK_SERVER_STATUS);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_DEVICE_NOT_READY;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
#endif

VOID MachenikeDriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
    UNREFERENCED_PARAMETER(pDriverObj);
    DBG("DriverUnload: Stopping server and cleaning up...");

    MACHENIKE_KERNEL_INTERFACE *UserVar = g_pGlobalUserVar;
    if (!UserVar)
    {
        DBG("[-] DriverUnload: CRITICAL - Failed to obtain valid UserVar!");
        return;
    }

    /* 停止常驻 ACE 监控定时器 */
    if (g_AceMonitorTimerStarted)
    {
        InterlockedExchange(&g_AceMonitorCtx.fStopped, 1);
        if (UserVar->Func.KeCancelTimer)
        {
            UserVar->Func.KeCancelTimer(&g_AceMonitorCtx.Timer);
        }
        g_AceMonitorTimerStarted = FALSE;
    }

#if ENABLE_WFP_BYPASS
    WfpBypass_Cleanup(UserVar);
#endif
    Transport_StopServer(UserVar);
    MkRpc_Cleanup(UserVar);

#if !MK_ENABLE_MANUAL_MAP
    /* 正常加载模式：删除创建的符号链接与设备对象 */
    if (g_SymbolicLinkCreated)
    {
        UserVar->Func.IoDeleteSymbolicLink(&g_SymbolicLinkName);
        g_SymbolicLinkCreated = FALSE;
        DBG("[+] Normal Driver Load: Deleted symbolic link %ws", MK_DOS_DEVICE_NAME);
    }
    if (g_pDeviceObject)
    {
        UserVar->Func.IoDeleteDevice(g_pDeviceObject);
        g_pDeviceObject = NULL;
        DBG("[+] Normal Driver Load: Deleted device object %ws", MK_DEVICE_NAME);
    }
#endif

#if (MK_ENABLE_FAKE_LDR)
    /* ACE 对抗：在启用伪造 LDR 模式下清理并恢复宿主真实 LDR 项，防止驱动卸载后悬空指针导致 BSOD */
    Stealth_CleanupFakeLdrEntry(UserVar);
#endif

    if (UserVar->MmPhysicalMemoryRange)
        UserVar->Func.ExFreePoolWithTag(UserVar->MmPhysicalMemoryRange, 0);

    if (g_pGlobalUserVar)
    {
        UserVar->Func.ExFreePoolWithTag(g_pGlobalUserVar, MK_POOL_TAG);
        g_pGlobalUserVar = NULL;
    }

    /* 清理 KUSER_SHARED_DATA 保留区暗桩标记 */
    PDRV_WSK_CANARY pCanary = (PDRV_WSK_CANARY)(KUSER_SHARED_DATA_R0_VA + KUSER_SHARED_DATA_CANARY_OFF);
    if (pCanary->Magic == DRV_WSK_CANARY_MAGIC)
    {
        RtlZeroMemory(pCanary, sizeof(DRV_WSK_CANARY));
        DBG("[+] DriverUnload: Cleared Canary from KUSER_SHARED_DATA.");
    }

    DBG("[+] DriverUnload: Cleanup completed successfully.");
}

/*
 * 异步卸载工作项例程：在独立系统工作线程中安全停止服务并清理驱动
 */
static VOID Main_UnloadWorkRoutine(IN PVOID Parameter)
{
    PWORK_QUEUE_ITEM pWorkItem = (PWORK_QUEUE_ITEM)Parameter;
    DBG("[*] Main_UnloadWorkRoutine: Executing async driver unload...");

    MachenikeDriverUnload(g_pDriverObj);

    DBG("[+] Main_UnloadWorkRoutine: Driver cleanup finished.");
    if (pWorkItem)
    {
        if (g_pGlobalUserVar)
        {
            g_pGlobalUserVar->Func.ExFreePoolWithTag(pWorkItem, MK_POOL_TAG);
        }
    }
}

EXTERN_C VOID Main_TriggerUnload(VOID)
{
    DBG("[*] Main_TriggerUnload: Scheduling driver unload work item...");
    MACHENIKE_KERNEL_INTERFACE *UserVar = g_pGlobalUserVar;
    if (UserVar)
    {
        PWORK_QUEUE_ITEM pWorkItem =
            (PWORK_QUEUE_ITEM)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM), MK_POOL_TAG);
        if (pWorkItem)
        {
            ExInitializeWorkItem(pWorkItem, Main_UnloadWorkRoutine, pWorkItem);
            ExQueueWorkItem(pWorkItem, DelayedWorkQueue);
            return;
        }
    }

    /* 降级为同步卸载 */
    MachenikeDriverUnload(g_pDriverObj);
}

NTSTATUS MachenikeUserVarInit(IN PKLDR_DATA_TABLE_ENTRY DriverSection, OUT MACHENIKE_KERNEL_INTERFACE **pUserVar)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG FunctionArray[] = {
        str_RtlGetVersion,
        str_RtlInitUnicodeString,
        str_IoAllocateMdl,
        str_IoFreeMdl,
        str_IoCreateDevice,
        str_IoCreateSymbolicLink,
        str_IoDeleteDevice,
        str_IoDeleteSymbolicLink,
        str_IofCompleteRequest,
        str_DbgPrint,
        str_ProbeForRead,
        str_ProbeForWrite,
        str_ExAllocatePoolWithTag,
        str_ExFreePoolWithTag,
        str_ZwOpenSection,
        str_ZwClose,
        str_MmProbeAndLockPages,
        str_MmUnlockPages,
        str_MmMapLockedPagesSpecifyCache,

        str_MmGetPhysicalMemoryRanges,
        str_KeGetCurrentIrql,
        str_KeQueryActiveProcessors,
        str_KeSetSystemAffinityThread,
        str_KeRevertToUserAffinityThread,
        str_KeQuerySystemTimePrecise,
        str_PsGetCurrentProcessId,
        str_memset,
        str_memcpy,
        str_memmove,
        str_strlen,
        str_RtlCopyMemory,
        str_RtlZeroMemory,
        str_KeDelayExecutionThread,
        str_PsTerminateSystemThread,
        str_PsCreateSystemThread,
        str_KeQueryPerformanceCounter,
        str_IoAllocateIrp,
        str_IoFreeIrp,
        str_KeInitializeEvent,
        str_KeWaitForSingleObject,
        str_KeSetEvent,
        str_ZwCreateFile,
        str_ZwReadFile,
        str_ZwWriteFile,
        str_ZwDeviceIoControlFile,
        str_IoGetDeviceInterfaces,
        str_ObReferenceObjectByHandle,
        str_ObfDereferenceObject,
        str_MmAllocateContiguousMemorySpecifyCache,
        str_MmFreeContiguousMemory,
        /* ACE Bypass 新增函数 */
        str_IoGetDeviceObjectPointer,
        str_IoAttachDeviceToDeviceStack,
        str_IoDetachDevice,
        str_IoCallDriver,
        str_ExAcquireFastMutex,
        str_ExReleaseFastMutex,

        /* 敏感反作弊特征函数动态解析（ntoskrnl.exe） */
        str_MmGetVirtualForPhysical,
        str_RtlPcToFileHeader,
        str_MmIsAddressValid,
        str_MmBuildMdlForNonPagedPool,
        str_IoGetLowerDeviceObject,
        str_ObfReferenceObject,
        str_IoCancelIrp,
        str_KeInitializeSpinLock,
        str_KeAcquireSpinLockRaiseToDpc,
        str_KeReleaseSpinLock,
        str_KeLowerIrql,
        str_KfRaiseIrql,
        str_KeInitializeMutex,
        str_KeReleaseMutex,
        str_KeClearEvent,
        str_KeQueryTimeIncrement,
        str_KeCancelTimer,
        str_PsInitialSystemProcess,
        str_PsThreadType,
    };

    MACHENIKE_PFN pfnTable = {};
    MACHENIKE_KERNEL_INTERFACE *UserVar = NULL;
    BOOLEAN bNtoskrnlFound = FALSE;

    for (PLIST_ENTRY pListEntry = DriverSection->InLoadOrderLinks.Flink; pListEntry != &DriverSection->InLoadOrderLinks;
         pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!pEntry->DllBase || !pEntry->BaseDllName.Buffer)
            continue;

        ULONG cchName = pEntry->BaseDllName.Length / sizeof(WCHAR);
        ULONG U32ModuleName = Utils_HashStringImulMagicExW(pEntry->BaseDllName.Buffer, cchName, TRUE);

        if (!bNtoskrnlFound && (U32ModuleName == wstr_Ntoskrnl ||
                                Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"ntoskrnl")))
        {
            ULONG_PTR *TableAsArray = (ULONG_PTR *)&pfnTable;
            for (size_t i = 0; i < ARRAY_SIZE(FunctionArray); i++)
            {
                if (!Utils_GetModuleExport((ULONG_PTR)pEntry->DllBase, FunctionArray[i], &TableAsArray[i]))
                {
                    // 若目标为 KeQueryPerformanceCounter，从链表中寻找 hal.dll 进行兜底解析
                    if (FunctionArray[i] == str_KeQueryPerformanceCounter)
                    {
                        BOOLEAN bHalFound = FALSE;
                        for (PLIST_ENTRY pHalEntry = DriverSection->InLoadOrderLinks.Flink;
                             pHalEntry != &DriverSection->InLoadOrderLinks; pHalEntry = pHalEntry->Flink)
                        {
                            PKLDR_DATA_TABLE_ENTRY pHal =
                                CONTAINING_RECORD(pHalEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                            if (pHal->DllBase && pHal->BaseDllName.Buffer)
                            {
                                ULONG cchHal = pHal->BaseDllName.Length / sizeof(WCHAR);
                                if (Main_ContainsSubstrCaseless(pHal->BaseDllName.Buffer, cchHal, L"hal"))
                                {
                                    if (Utils_GetModuleExport((ULONG_PTR)pHal->DllBase, str_KeQueryPerformanceCounter,
                                                              &TableAsArray[i]))
                                    {
                                        DBG("[+] Resolved KeQueryPerformanceCounter from hal.dll Addr:[0x%p]",
                                            (PVOID)TableAsArray[i]);
                                        bHalFound = TRUE;
                                        break;
                                    }
                                }
                            }
                        }
                        if (bHalFound)
                        {
                            continue;
                        }
                    }

                    DBG("[-] Failed to find Index:[%02lld] U32Hash:[0x%08X]", i, FunctionArray[i]);
                    return STATUS_NOT_FOUND;
                }
                DBG("[+] Resolved Index:[%02lld] U32Hash:[0x%08X] Addr:[0x%p]", i, FunctionArray[i],
                    (PVOID)TableAsArray[i]);
            }
            DBG("[+] Successfully resolved all %lld kernel functions from ntoskrnl!",
                (LONGLONG)ARRAY_SIZE(FunctionArray));
            if (!pfnTable.ExAllocatePoolWithTag || !pfnTable.memset || !pfnTable.memcpy || !pfnTable.RtlCopyMemory ||
                !pfnTable.RtlZeroMemory)
                return STATUS_NOT_FOUND;

            UserVar = (MACHENIKE_KERNEL_INTERFACE *)pfnTable.ExAllocatePoolWithTag(
                NonPagedPool, sizeof(MACHENIKE_KERNEL_INTERFACE), MK_POOL_TAG);
            if (!UserVar)
                return STATUS_INSUFFICIENT_RESOURCES;
            pfnTable.memset(UserVar, 0, sizeof(MACHENIKE_KERNEL_INTERFACE));
            pfnTable.memcpy(&UserVar->Func, &pfnTable, sizeof(MACHENIKE_PFN));

            RTL_OSVERSIONINFOW VersInfo = {};
            pfnTable.memset(&VersInfo, 0, sizeof(RTL_OSVERSIONINFOW));
            VersInfo.dwOSVersionInfoSize = sizeof(VersInfo);
            status = UserVar->Func.RtlGetVersion(&VersInfo);
            if (!NT_SUCCESS(status))
            {
                UserVar->Func.ExFreePoolWithTag(UserVar, MK_POOL_TAG);
                return status;
            }
            UserVar->NtBuildNumber.QuadPart = (LONGLONG)VersInfo.dwBuildNumber;
            UserVar->NtBuildNumberAddr.QuadPart = (LONGLONG)&UserVar->NtBuildNumber.QuadPart;
            UserVar->Cr3.QuadPart = __readcr3();
            UserVar->KernelBase.QuadPart = (LONGLONG)pEntry->DllBase;

            UserVar->SipHashKey[0] = 0x21;
            UserVar->SipHashKey[1] = 0x7A;
            UserVar->SipHashKey[2] = 0xA9;
            UserVar->SipHashKey[3] = 0x3C;
            UserVar->SipHashKey[4] = 0x10;
            UserVar->SipHashKey[5] = 0x55;
            UserVar->SipHashKey[6] = 0xD2;
            UserVar->SipHashKey[7] = 0x6F;
            UserVar->SipHashKey[8] = 0x9B;
            UserVar->SipHashKey[9] = 0x4E;
            UserVar->SipHashKey[10] = 0x01;
            UserVar->SipHashKey[11] = 0x88;
            UserVar->SipHashKey[12] = 0xC7;
            UserVar->SipHashKey[13] = 0x33;
            UserVar->SipHashKey[14] = 0xFA;
            UserVar->SipHashKey[15] = 0x90;
            UserVar->Step = 30;
            UserVar->Salt4 = 0x4D43484EU;
            *pUserVar = UserVar;
            bNtoskrnlFound = TRUE;
            break;
        }
    }

    if (!bNtoskrnlFound || !UserVar)
    {
        return STATUS_NOT_FOUND;
    }

    // 动态解析 netio.sys 中的 WSK 套接字函数
    for (PLIST_ENTRY pListEntry = DriverSection->InLoadOrderLinks.Flink; pListEntry != &DriverSection->InLoadOrderLinks;
         pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!pEntry->DllBase || !pEntry->BaseDllName.Buffer)
            continue;

        ULONG cchName = pEntry->BaseDllName.Length / sizeof(WCHAR);
        ULONG U32ModuleName = Utils_HashStringImulMagicExW(pEntry->BaseDllName.Buffer, cchName, TRUE);

        if (U32ModuleName == wstr_Netio || Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"netio"))
        {
            Utils_GetModuleExport((ULONG_PTR)pEntry->DllBase, str_WskRegister, (PULONG_PTR)&UserVar->Func.WskRegister);
            Utils_GetModuleExport((ULONG_PTR)pEntry->DllBase, str_WskCaptureProviderNPI,
                                  (PULONG_PTR)&UserVar->Func.WskCaptureProviderNPI);
            Utils_GetModuleExport((ULONG_PTR)pEntry->DllBase, str_WskReleaseProviderNPI,
                                  (PULONG_PTR)&UserVar->Func.WskReleaseProviderNPI);
            Utils_GetModuleExport((ULONG_PTR)pEntry->DllBase, str_WskDeregister,
                                  (PULONG_PTR)&UserVar->Func.WskDeregister);
            DBG("[+] Resolved WSK functions from netio.sys (Base=0x%p, WskRegister=0x%p)", pEntry->DllBase,
                (PVOID)UserVar->Func.WskRegister);
            break;
        }
    }

    return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PVOID pContextOrBootConfig)
{
    UNREFERENCED_PARAMETER(pContextOrBootConfig);
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (pDriverObj)
    {
        PKLDR_DATA_TABLE_ENTRY pHostDriverSection = (PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;
        g_pHostDriverSection = pHostDriverSection;
        g_pDriverObj = pDriverObj;

        MACHENIKE_KERNEL_INTERFACE *UserVar = NULL;
        status = MachenikeUserVarInit(pHostDriverSection, &UserVar);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        g_pGlobalUserVar = UserVar;
        NetMonitor_SetUserVar(UserVar);

#if ENABLE_ACE_MONITOR_ENGINE
        /* 启动后台常驻 WorkItem 监控引擎，持续寻找并追踪 ACE 驱动模块（应对游戏关闭与重启） */
        Main_StartAceMonitorEngine(pHostDriverSection);
#endif

#if MK_ENABLE_MANUAL_MAP
        /* 【手动映射模式专属逻辑 - 保持原逻辑】
         * 1. 读取 shellcode 暂存的实际内核池基址并立即复位 DeviceObject 为 NULL，消除对象表审计风险
         * 2. Manual Map 到宿主白驱动或 tcpip.sys 时切勿挂接 DriverUnload，防止未签名指针触发反作弊报警
         */
        g_pDriverActualPoolBase = pDriverObj->DeviceObject;
        pDriverObj->DeviceObject = NULL;

        /* 启动通讯服务：由 Loader 传入的 BootConfig 决定启动模式 (TCP / UDP / USB) 及端口 */
        status = MkRpc_Init(UserVar);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] ManualMap: MkRpc_Init failed with status 0x%08X", status);
            return status;
        }
        Transport_Init(UserVar);

        NTSTATUS srvStatus = STATUS_UNSUCCESSFUL;
        MK_SERVER_START_PARAMS srvParams = {};

        PDRV_BOOT_CONFIG pBootConfig = (PDRV_BOOT_CONFIG)pContextOrBootConfig;
        if (pBootConfig && pBootConfig->Magic == DRV_BOOT_CONFIG_MAGIC)
        {
            DBG("[+] Received BootConfig from Loader: Mode=%u Port=%u",
                pBootConfig->TransportMode, pBootConfig->Port);
            if (pBootConfig->TransportMode == DRV_TRANSPORT_TCP)
            {
                srvParams.Mode = MK_SERVER_MODE_WSK_TCP;
                srvParams.Port = pBootConfig->Port ? pBootConfig->Port : MK_WSK_DEFAULT_PORT;
            }
            else if (pBootConfig->TransportMode == DRV_TRANSPORT_UDP)
            {
                srvParams.Mode = MK_SERVER_MODE_WSK_UDP;
                srvParams.Port = pBootConfig->Port ? pBootConfig->Port : MK_UDP_SERVER_DEFAULT_PORT;
            }
            else if (pBootConfig->TransportMode == DRV_TRANSPORT_USB)
            {
                srvParams.Mode = MK_SERVER_MODE_USB;
            }
        }

        /* 若没传入模式或模式无效，则返回失败并卸载驱动 */
        if (srvParams.Mode == 0)
        {
            DBG("[-] CRITICAL: No valid transport mode provided. Auto-unloading driver!");
            MachenikeDriverUnload(pDriverObj);
            RtlZeroMemory(pDriverObj, 0x200);
            g_pDriverObj = NULL;
            return STATUS_INVALID_PARAMETER;
        }

        /* 若为 TCP 或 UDP 模式，先根据宏开关判断是否调用 UdpDiscovery_DiscoverClient 发现设备 */
        if (srvParams.Mode == MK_SERVER_MODE_WSK_TCP || srvParams.Mode == MK_SERVER_MODE_WSK_UDP)
        {
#if ENABLE_UDP_CLIENT_DISCOVERY
            MK_DISCOVERY_RESULT discResult = {0};
            MK_DISCOVERY_PARAMS discParams = {0};
            discParams.TimeoutMs = 5000;
            discParams.ServerTcpPort = (USHORT)srvParams.Port;

            DBG("[*] DriverEntry: Discovering client before starting %s server (Port=%u)...",
                (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "WSK TCP" : "WSK UDP", srvParams.Port);

            NTSTATUS discStatus = UdpDiscovery_DiscoverClient(UserVar, &discParams, &discResult);
            if (NT_SUCCESS(discStatus) && discResult.fFound)
            {
                DBG("[+] DriverEntry: Client discovered at %s:%u, starting server...",
                    discResult.ClientIpStr, discResult.ClientPort);
                srvStatus = Transport_StartServer(UserVar, &srvParams);
                DBG("[*] DriverEntry: Start %s server status=0x%08X (port=%u)",
                    (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP", srvStatus, srvParams.Port);
            }
            else
            {
                DBG("[-] DriverEntry: Client discovery failed (status=0x%08X, fFound=%d), abort starting server",
                    discStatus, discResult.fFound);
                srvStatus = NT_SUCCESS(discStatus) ? STATUS_DEVICE_NOT_CONNECTED : discStatus;
            }
#else
            DBG("[*] DriverEntry: ENABLE_UDP_CLIENT_DISCOVERY=0, skipping discovery and starting %s server directly (Port=%u)...",
                (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP", srvParams.Port);
            srvStatus = Transport_StartServer(UserVar, &srvParams);
            DBG("[*] DriverEntry: Start %s server status=0x%08X (port=%u)",
                (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP", srvStatus, srvParams.Port);
#endif
        }
        else
        {
            /* USB 或其他模式直接启动 */
            srvStatus = Transport_StartServer(UserVar, &srvParams);
            DBG("[*] DriverEntry: Start server status=0x%08X (Mode=%u)", srvStatus, srvParams.Mode);
        }

        /* 关键自愈防护：若指定服务启动失败，自动卸载驱动并返回错误码 */
        if (!NT_SUCCESS(srvStatus))
        {
            DBG("[-] CRITICAL: Transport server failed to start (status=0x%08X). Auto-unloading driver!", srvStatus);
            MachenikeDriverUnload(pDriverObj);
            RtlZeroMemory(pDriverObj, 0x200);
            g_pDriverObj = NULL;
            return srvStatus;
        }

    DBG("[+] Transport server online successfully (Mode=%u)", srvParams.Mode);

        /* ACE 对抗防护：清空擦除内存池尾部的伪造 DRIVER_OBJECT 结构体（0x200 字节） */
        RtlZeroMemory(pDriverObj, 0x200);
        g_pDriverObj = NULL;
#else
        /* 【正常驱动加载模式专属逻辑】
         * 标准 SCM 服务加载：
         * 1. 注册标准 DriverUnload 例程以支持系统停止服务并安全卸载
         * 2. 创建设备对象与符号链接，挂接 IRP_MJ_DEVICE_CONTROL
         * 3. 驱动进入待命状态，等待 R3 通过 IO 通讯 (IOCTL_MK_START_TRANSPORT) 动态传入参数并启动指定模式 (TCP/UDP/USB)
         */
        pDriverObj->DriverUnload = MachenikeDriverUnload;
        g_pDriverActualPoolBase = NULL;
        DBG("[+] Normal Driver Load: Registered DriverUnload at 0x%p", (PVOID)MachenikeDriverUnload);

        /* 注册 IRP 派发例程 */
        pDriverObj->MajorFunction[IRP_MJ_CREATE] = MachenikeIoCreateClose;
        pDriverObj->MajorFunction[IRP_MJ_CLOSE] = MachenikeIoCreateClose;
        pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MachenikeIoDeviceControl;

        /* 创建设备对象与符号链接 */
        UserVar->Func.RtlInitUnicodeString(&g_DeviceName, MK_DEVICE_NAME);
        UserVar->Func.RtlInitUnicodeString(&g_SymbolicLinkName, MK_DOS_DEVICE_NAME);

        status = UserVar->Func.IoCreateDevice(pDriverObj, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                                &g_pDeviceObject);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] Normal Driver Load: IoCreateDevice failed (0x%08X)", status);
            MachenikeDriverUnload(pDriverObj);
            return status;
        }

        g_pDeviceObject->Flags |= DO_BUFFERED_IO;
        g_pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

        status = UserVar->Func.IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] Normal Driver Load: IoCreateSymbolicLink failed (0x%08X)", status);
            UserVar->Func.IoDeleteDevice(g_pDeviceObject);
            g_pDeviceObject = NULL;
            MachenikeDriverUnload(pDriverObj);
            return status;
        }
        g_SymbolicLinkCreated = TRUE;
        DBG("[+] Normal Driver Load: Created device %ws and symlink %ws successfully", MK_DEVICE_NAME,
            MK_DOS_DEVICE_NAME);

        /* 初始化 RPC 与传输管理器底座 */
        status = MkRpc_Init(UserVar);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] Normal Driver Load: MkRpc_Init failed with status 0x%08X", status);
            UserVar->Func.IoDeleteSymbolicLink(&g_SymbolicLinkName);
            g_SymbolicLinkCreated = FALSE;
            if (g_pDeviceObject)
            {
                UserVar->Func.IoDeleteDevice(g_pDeviceObject);
                g_pDeviceObject = NULL;
            }
            MachenikeDriverUnload(pDriverObj);
            return status;
        }
        Transport_Init(UserVar);

        DBG("[+] Normal Driver Load: Driver ready and waiting for R3 IOCTL commands (device: %ws)",
            MK_USER_DEVICE_NAME);
#endif

        /* 记录 KUSER_SHARED_DATA 保留区暗桩标记（防重复加载），零 PE 头部修改，规避反作弊检测 */
        PDRV_WSK_CANARY pCanary = (PDRV_WSK_CANARY)(KUSER_SHARED_DATA_R0_VA + KUSER_SHARED_DATA_CANARY_OFF);
        pCanary->Magic = DRV_WSK_CANARY_MAGIC;
        pCanary->KernelImageVA = (ULONG64)(g_pDriverActualPoolBase ? g_pDriverActualPoolBase : (pHostDriverSection ? pHostDriverSection->DllBase : NULL));
        pCanary->ImageSize = pHostDriverSection ? (ULONG)pHostDriverSection->SizeOfImage : 0;
        pCanary->Reserved = 0;
        DBG("[+] DriverEntry: Recorded active Canary into KUSER_SHARED_DATA (VA=0x%p, Offset=0x%llX)",
            (PVOID)pCanary, KUSER_SHARED_DATA_CANARY_OFF);

        status = STATUS_SUCCESS;
    }

    return status;
}
