#include "Common.h"
#include "DriverCore.h"
#include "DrvSecurity.h"
#include "ExceptionReporter.h"
#include "MachenikeString.h"
#include "NetMonitor.h"
#include "UsbMonitor.h"
#include "ApiMonitor.h"
#include "RpcDispatcher.h"
#include "StealthReloc.h"
#include "Struct.h"
#include "TransportManager.h"
#include "Utils.h"
#include "WfpBypass.h"
#include "udp_discovery.h"
#include "usb_hub.h"
#include "wsk_server.h"
#include <bcrypt.h>
static PDEVICE_OBJECT g_pControlDevObj = NULL;
static PDRIVER_OBJECT g_pDriverObj = NULL;
PMACHENIKE_KERNEL_INTERFACE g_pGlobalUserVar = NULL;
static PVOID g_pDriverActualPoolBase = NULL;
static PKLDR_DATA_TABLE_ENTRY g_pHostDriverSection = NULL;
#ifdef IoCompleteRequest
#undef IoCompleteRequest
#endif
#define IoCompleteRequest(irp, prio)                                                                                                       \
    do                                                                                                                                     \
    {                                                                                                                                      \
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.IofCompleteRequest)                                                                 \
        {                                                                                                                                  \
            g_pGlobalUserVar->Func.IofCompleteRequest(irp, prio);                                                                          \
        }                                                                                                                                  \
    } while (0)
/* 全局 ACE 反作弊驱动探测缓存（支持同时追踪多个核心模块如 102706/202706/302706） */
ACE_MODULE_RANGE g_AceModules[ACE_MAX_TRACKED_MODULES] = {0};
ULONG g_AceModuleCount = 0;
ULONG_PTR g_AceModuleBase = 0;
ULONG_PTR g_AceModuleEnd = 0;
BOOLEAN g_bAceDetected = FALSE;
CHAR g_ApiUrl[128] = {0};
CHAR g_LoginUrl[128] = {0};
CHAR g_ReportUrl[128] = {0};
CHAR g_BrandVersion[32] = {0};
CHAR g_SelectedGame[32] = {0};
CHAR g_ClientVersion[32] = {0};
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
static BOOLEAN ContainsSubstrCaseless(PCWSTR pszStr, ULONG cchStr, PCWSTR pszSub)
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
static BOOLEAN IsAceModuleName(PCWSTR pName, ULONG cchName, ULONG u32Hash)
{
    if (!pName || cchName == 0)
        return FALSE;
    // 1. 已知静态哈希命中（快速路径）
    if (u32Hash == wstr_AceCore302706 || u32Hash == wstr_AceCore202706 || u32Hash == wstr_AceCore102706 || u32Hash == wstr_AceBase)
    {
        return TRUE;
    }
    // 2. 本地模拟/测试驱动
    if (ContainsSubstrCaseless(pName, cchName, L"mockace") || ContainsSubstrCaseless(pName, cchName, L"mock_ace"))
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
    if (ContainsSubstrCaseless(pName, cchName, L"_ace_") || ContainsSubstrCaseless(pName, cchName, L"-ace-"))
    {
        return TRUE;
    }
    return FALSE;
}

NO_OBFUS VOID DriverCore::ScanBypassModules(IN PKLDR_DATA_TABLE_ENTRY DriverSection)
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
        ULONG U32ModuleName = Utils::HashStringW(pEntry->BaseDllName.Buffer, cchName, TRUE);
        if (U32ModuleName == wstr_Netio || ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"netio"))
        {
            ULONG_PTR netioBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR netioEnd = netioBase + pEntry->SizeOfImage;
            ULONG_PTR fnAddr = 0;
            if (Utils::GetModuleExport(netioBase, str_KfdAddCalloutEntry, &fnAddr) && fnAddr)
            {
                targetBase = netioBase;
                targetEnd = netioEnd;
                targetFn = fnAddr;
                DBG("[+] netio [0x%p-0x%p] KfdAddCalloutEntry=0x%p", (PVOID)netioBase, (PVOID)netioEnd, (PVOID)fnAddr);
            }
            else if (Utils::GetModuleExport(netioBase, str_FwpsCalloutRegister2, &fnAddr) && fnAddr)
            {
                targetBase = netioBase;
                targetEnd = netioEnd;
                targetFn = fnAddr;
                DBG("[+] netio [0x%p-0x%p] FwpsCalloutRegister2=0x%p", (PVOID)netioBase, (PVOID)netioEnd, (PVOID)fnAddr);
            }
        }
        else if (U32ModuleName == wstr_Fwpkclnt || ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"fwpkclnt"))
        {
            ULONG_PTR fwpBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR fwpEnd = fwpBase + pEntry->SizeOfImage;
            ULONG_PTR fnAddr = 0;
            if (Utils::GetModuleExport(fwpBase, str_FwpsCalloutRegister2, &fnAddr) && fnAddr)
            {
                DBG("[+] fwpkclnt [0x%p-0x%p] FwpsCalloutRegister2=0x%p", (PVOID)fwpBase, (PVOID)fwpEnd, (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
            else if (Utils::GetModuleExport(fwpBase, str_FwpsCalloutRegister1, &fnAddr) && fnAddr)
            {
                DBG("[+] fwpkclnt FwpsCalloutRegister1=0x%p", (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
            else if (Utils::GetModuleExport(fwpBase, str_FwpsCalloutRegister0, &fnAddr) && fnAddr)
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
        else if ((cchName == 8 && _wcsnicmp(pEntry->BaseDllName.Buffer, L"ndis.sys", 8) == 0) ||
                 (cchName == 4 && _wcsnicmp(pEntry->BaseDllName.Buffer, L"ndis", 4) == 0))
        {
            ULONG_PTR ndisBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR ndisEnd = ndisBase + pEntry->SizeOfImage;
            NetMonitor::SetNdisModule(ndisBase, ndisEnd);
        }
    }
    if (targetBase && targetEnd && targetFn)
    {
        WfpBypass::SetNetioInfo(targetBase, targetEnd, (PVOID)targetFn);
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
/*
 * 启动通信服务端 (TCP / UDP / USB)
 * 客户端由同机 R3 控制下发，无需经过 UDP 广播发现等待，直接上线并设置 WFP 保护
 */
static NTSTATUS StartTransportByIo(MACHENIKE_KERNEL_INTERFACE *UserVar, const DRV_BOOT_CONFIG *pBootConfig)
{
    if (!UserVar || !pBootConfig)
    {
        ExceptionReporter::Report("StartTransportByIo", STATUS_INVALID_PARAMETER, "UserVar or pBootConfig is NULL");
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
        DBG("[-] StartTransportByIo: Invalid transport mode %u", pBootConfig->TransportMode);
        ExceptionReporter::Report("StartTransportByIo", STATUS_INVALID_PARAMETER, "Invalid transport mode");
        return STATUS_INVALID_PARAMETER;
    }
    // 方案 1: 基于 SessionToken 动态派生通信加密密钥 (去分支化抗 Patch 绑定)
    volatile ULONG64 maskA = 0x55AA55AA55AA55AAULL;
    volatile ULONG64 maskB = 0xAA55AA55AA55AA55ULL;
    UCHAR dynAuthKey[16];
    *(PULONG64)&dynAuthKey[0] = 0x72446C656E72654BULL ^ maskA;
    *(PULONG64)&dynAuthKey[8] = 0x79654B6874754176ULL ^ maskB;
    *(PULONG64)&dynAuthKey[0] ^= maskA;
    *(PULONG64)&dynAuthKey[8] ^= maskB;

    ULONG64 dynamicKey = 0;
    BOOLEAN fHasSessionToken = FALSE;
    for (int k = 0; k < 16; k++)
    {
        if (pBootConfig->SessionToken[k] != 0)
        {
            fHasSessionToken = TRUE;
            break;
        }
    }
    if (fHasSessionToken)
    {
        dynamicKey = *(const ULONG64 *)pBootConfig->SessionToken;
    }
    else if (pBootConfig->AuthToken != 0)
    {
        dynamicKey = Utils::SipHash24(dynAuthKey, (const UCHAR *)&pBootConfig->AuthToken, sizeof(pBootConfig->AuthToken));
    }
    RtlSecureZeroMemory(dynAuthKey, sizeof(dynAuthKey));
    if (dynamicKey != 0)
    {
        TransportManager::SetSessionCryptKey(dynamicKey);
        DrvSecurity::SetAuthStateInvariant(dynamicKey);
        DBG("[+] StartTransportByIo: Derived dynamic SessionCryptKey=0x%016llX", dynamicKey);
    }
    DBG("[+] StartTransportByIo: Starting server by IO command (Mode=%u Port=%u)...", srvParams.Mode, srvParams.Port);
    NTSTATUS srvStatus = TransportManager::StartServer(UserVar, &srvParams);
    if (!NT_SUCCESS(srvStatus))
    {
        DBG("[-] StartTransportByIo: Transport_StartServer failed (0x%08X)", srvStatus);
        ExceptionReporter::Report("StartTransportByIo", srvStatus, "Transport_StartServer failed");
        return srvStatus;
    }
    DBG("[+] StartTransportByIo: Server online successfully (Mode=%u Port=%u)", srvParams.Mode, srvParams.Port);
    return STATUS_SUCCESS;
}
// ============================================================
// 异常上报子系统：已独立抽取至 ExceptionReporter 类 (ExceptionReporter.h / ExceptionReporter.cpp)
// ============================================================
NTSTATUS DriverCore::ApplyBootConfigAndStart(MACHENIKE_KERNEL_INTERFACE *UserVar, const DRV_BOOT_CONFIG_EX *pCfgEx, ULONG callerPid)
{
    if (!pCfgEx)
        return STATUS_INVALID_PARAMETER;
#if NO_AUTH || ENABLE_NO_AUTH
    UNREFERENCED_PARAMETER(callerPid);
#endif
    if (pCfgEx->ApiUrl[0] != '\0')
    {
        if (UserVar && UserVar->Func.memcpy)
            UserVar->Func.memcpy(g_ApiUrl, pCfgEx->ApiUrl, sizeof(g_ApiUrl));
        else
            memcpy(g_ApiUrl, pCfgEx->ApiUrl, sizeof(g_ApiUrl));
        DBG("[+] Driver received ApiUrl: %s", g_ApiUrl);
        ExceptionReporter::SetApiUrl(g_ApiUrl);
    }
    if (pCfgEx->LoginUrl[0] != '\0')
    {
        if (UserVar && UserVar->Func.memcpy)
            UserVar->Func.memcpy(g_LoginUrl, pCfgEx->LoginUrl, sizeof(g_LoginUrl));
        else
            memcpy(g_LoginUrl, pCfgEx->LoginUrl, sizeof(g_LoginUrl));
        DBG("[+] Driver received LoginUrl: %s", g_LoginUrl);
    }
    if (pCfgEx->ReportUrl[0] != '\0')
    {
        if (UserVar && UserVar->Func.memcpy)
            UserVar->Func.memcpy(g_ReportUrl, pCfgEx->ReportUrl, sizeof(g_ReportUrl));
        else
            memcpy(g_ReportUrl, pCfgEx->ReportUrl, sizeof(g_ReportUrl));
        DBG("[+] Driver received ReportUrl: %s", g_ReportUrl);
        ExceptionReporter::SetApiUrl(g_ReportUrl);
    }
    if (pCfgEx->BrandVersion[0] != '\0')
    {
        if (UserVar && UserVar->Func.memcpy)
            UserVar->Func.memcpy(g_BrandVersion, pCfgEx->BrandVersion, sizeof(g_BrandVersion));
        else
            memcpy(g_BrandVersion, pCfgEx->BrandVersion, sizeof(g_BrandVersion));
        DBG("[+] Driver received BrandVersion: %s", g_BrandVersion);
        ExceptionReporter::SetBrandVersion(g_BrandVersion);
    }
    if (pCfgEx->SelectedGame[0] != '\0')
    {
        if (UserVar && UserVar->Func.memcpy)
            UserVar->Func.memcpy(g_SelectedGame, pCfgEx->SelectedGame, sizeof(g_SelectedGame));
        else
            memcpy(g_SelectedGame, pCfgEx->SelectedGame, sizeof(g_SelectedGame));
        DBG("[+] Driver received SelectedGame: %s", g_SelectedGame);
        ExceptionReporter::SetSelectedGame(g_SelectedGame);
    }
    if (pCfgEx->ClientVersion[0] != '\0')
    {
        if (UserVar && UserVar->Func.memcpy)
            UserVar->Func.memcpy(g_ClientVersion, pCfgEx->ClientVersion, sizeof(g_ClientVersion));
        else
            memcpy(g_ClientVersion, pCfgEx->ClientVersion, sizeof(g_ClientVersion));
        DBG("[+] Driver received ClientVersion: %s", g_ClientVersion);
        ExceptionReporter::SetClientVersion(g_ClientVersion);
    }
    NTSTATUS status = StartTransportByIo(UserVar, &pCfgEx->Base);
    if (NT_SUCCESS(status) && (pCfgEx->Base.Flags & DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP) && pCfgEx->HostLoaderPath[0] != L'\0')
    {
        DriverCore::SetPendingHostLoaderCleanup(pCfgEx->HostLoaderPath, callerPid);
    }
    return status;
}
NTSTATUS DriverCore::DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS status = STATUS_SUCCESS;
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);
    if (!UserVar)
    {
        UserVar = g_pGlobalUserVar;
    }
    if (!UserVar)
    {
        ExceptionReporter::Report("DriverCore::DispatchCreate", STATUS_DEVICE_NOT_READY, "Device or UserVar not ready");
        pIrp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        pIrp->IoStatus.Information = 0;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_DEVICE_NOT_READY;
    }
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG CurrentToken = 0;
    ULONG CurrentProcessId =
        UserVar->Func.PsGetCurrentProcessId ? HandleToULong(UserVar->Func.PsGetCurrentProcessId()) : 0;
#if NO_AUTH || ENABLE_NO_AUTH
    UNREFERENCED_PARAMETER(pDevObj);
    UNREFERENCED_PARAMETER(pIrpStack);
    UNREFERENCED_PARAMETER(CurrentToken);
    DBG("[*] DispatchCreate: NoAuth is enabled, skipping token validation (PID=%u, GRANTED)", CurrentProcessId);
    status = STATUS_SUCCESS;
    // NoAuth 模式：若传入了 Token，则从用户态内存扫描并解密动态锚点配置
    if (pIrpStack && pIrpStack->FileObject &&
        NT_SUCCESS(DrvSecurity::ParseTokenFromFileName(&pIrpStack->FileObject->FileName, &CurrentToken)))
    {
        DRV_BOOT_CONFIG_EX cfgEx = {};
        NTSTATUS anchorSt = DrvSecurity::ScanAndDecryptUserPayload(CurrentToken, &cfgEx);
        if (NT_SUCCESS(anchorSt))
        {
            DBG("[+] DispatchCreate: Parsed boot config from memory anchor, starting server (Mode=%u Port=%u)", cfgEx.Base.TransportMode,
                cfgEx.Base.Port);
            NTSTATUS srvSt = DriverCore::ApplyBootConfigAndStart(UserVar, &cfgEx, CurrentProcessId);
            if (!NT_SUCCESS(srvSt))
            {
                DBG("[-] DispatchCreate: NoAuth ApplyBootConfigAndStart failed (0x%08X)", srvSt);
                status = srvSt;
                ExceptionReporter::Report("DriverCore::DispatchCreate", srvSt, "NoAuth ApplyBootConfig failed");
            }
        }
        else
        {
            DBG("[-] DispatchCreate: NoAuth ScanAndDecryptUserPayload failed (0x%08X, Token=0x%08X)", anchorSt, CurrentToken);
        }
    }
    else if (pIrpStack && pIrpStack->FileObject && pIrpStack->FileObject->FileName.Length > 0)
    {
        DBG("[-] DispatchCreate: NoAuth ParseTokenFromFileName failed for path '%wZ'", &pIrpStack->FileObject->FileName);
    }
#else
    if (!pIrpStack || !pIrpStack->FileObject)
    {
        DBG("[-] DispatchCreate: Invalid IRP stack or FileObject");
        status = STATUS_INVALID_PARAMETER;
        ExceptionReporter::Report("DriverCore::DispatchCreate", status, "Invalid IRP stack or FileObject");
    }
    else
    {
        // 1. 优先校验动态防伪 Token（默认客户端必须带合法 Token 打开设备）
        status = DrvSecurity::ParseTokenFromFileName(&pIrpStack->FileObject->FileName, &CurrentToken);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] DispatchCreate: Invalid token format in filename '%wZ' (status=0x%08X)", &pIrpStack->FileObject->FileName, status);
            ExceptionReporter::Report("DriverCore::DispatchCreate", status, "Invalid token format in filename");
            status = STATUS_ACCESS_DENIED;
        }
        else
        {
            BOOLEAN ok = DrvSecurity::ValidateToken(UserVar, CurrentProcessId, CurrentToken, 1);
            DBG("DispatchCreate: Client PID=%u, Token=0x%08X, Access=%s", CurrentProcessId, CurrentToken, ok ? "GRANTED" : "DENIED");
            if (!ok)
            {
                DBG("[-] DispatchCreate: Dynamic token mismatch for PID=%u, Token=0x%08X", CurrentProcessId, CurrentToken);
                status = STATUS_ACCESS_DENIED;
                ExceptionReporter::Report("DriverCore::DispatchCreate", STATUS_ACCESS_DENIED, "Dynamic token mismatch");
            }
            else
            {
                status = STATUS_SUCCESS;
                DRV_BOOT_CONFIG_EX cfgEx = {};
                BOOLEAN bConfigLoaded = FALSE;
                // 2. Token 鉴权通过：直接从当前调用进程用户态内存扫描并解密动态锚点载荷 (零文件路径参数，无 MiniFilter
                // 痕迹，阅后即焚)
                NTSTATUS anchorSt = DrvSecurity::ScanAndDecryptUserPayload(CurrentToken, &cfgEx);
                if (NT_SUCCESS(anchorSt))
                {
                    DBG("[+] DispatchCreate: Successfully scanned and decrypted payload from caller process memory "
                        "(Mode=%u Port=%u)",
                        cfgEx.Base.TransportMode, cfgEx.Base.Port);
                    ULONG64 cloudKey = *(const ULONG64 *)cfgEx.Base.SessionToken;
                    DrvSecurity::SetAuthStateInvariant(cloudKey);
                    bConfigLoaded = TRUE;
                }
                else
                {
                    DBG("[-] DispatchCreate: ScanAndDecryptUserPayload failed (status=0x%08X, Token=0x%08X)", anchorSt, CurrentToken);
                }
                if (bConfigLoaded)
                {
                    NTSTATUS srvSt = DriverCore::ApplyBootConfigAndStart(UserVar, &cfgEx, CurrentProcessId);
                    if (!NT_SUCCESS(srvSt))
                    {
                        DBG("[-] DispatchCreate: ApplyBootConfigAndStart failed (status=0x%08X)", srvSt);
                        status = srvSt;
                        ExceptionReporter::Report("DriverCore::DispatchCreate", srvSt, "Token valid but ApplyBootConfig failed");
                    }
                }
            }
        }
    }
#endif
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    if (UserVar->Func.IofCompleteRequest)
    {
        UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    }
    else
    {
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    }
    return status;
}
NTSTATUS DriverCore::DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);
    if (!UserVar)
    {
        UserVar = g_pGlobalUserVar;
    }
    DBG("DispatchClose: Device handle closed");
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    if (UserVar && UserVar->Func.IofCompleteRequest)
    {
        UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    }
    else
    {
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    }
    return STATUS_SUCCESS;
}
/*
 * ResetAllScanStates — 当目标反作弊驱动卸载或游戏退出时，原子复位各个扫描器的告警去重位图与挂接状态
 */
NO_OBFUS static VOID ResetAllScanStates()
{
    WfpBypass::ResetState();
    NetMonitor::ResetReportState();
    UsbMonitor::ResetReportState();
    ApiMonitor::ResetReportState();
}

/*
 * ScanAceModuleState — 高频（2s）监控 ACE 驱动模块加载、卸载与 ASLR 基址变动
 */
NO_OBFUS static VOID ScanAceModuleState(PKLDR_DATA_TABLE_ENTRY DriverSection, ULONG scanRound)
{
    if (!DriverSection)
        return;

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
        ULONG U32ModuleName = Utils::HashStringW(pEntry->BaseDllName.Buffer, cchName, TRUE);
        if (IsAceModuleName(pEntry->BaseDllName.Buffer, cchName, U32ModuleName))
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
            DBG("[+] AceMonitor [Round #%lu]: >>> DETECTED %lu Target ACE Modules in memory! <<<", scanRound, foundCount);
            for (ULONG m = 0; m < foundCount; m++)
            {
                DBG("    [%lu] %ws [0x%p-0x%p]", m + 1, g_AceModules[m].Name, (PVOID)g_AceModules[m].Base, (PVOID)g_AceModules[m].End);
            }
            /* ACE 首次出现或基址改变（游戏重启），重置旧的 WFP 记录以便重新挂接 */
            WfpBypass::ResetState();
        }
        else
        {
            /* 维持已发现的心跳状态输出 */
            if (scanRound <= 5 || (scanRound % 5) == 0)
            {
                DBG("[*] AceMonitor [Round #%lu]: %lu Target ACE modules active in memory (modules=%lu)", scanRound, g_AceModuleCount,
                    totalModules);
            }
        }
    }
    else
    {
        /* 游戏未开启或已关闭退出：若先前已检测到，重置状态以备下次重启重新捕获新基址 */
        if (g_bAceDetected)
        {
            DBG("[-] AceMonitor [Round #%lu]: Target ACE drivers exited/unloaded, resetting cached bases, WFP & Hook deduplication state", scanRound);
            RtlZeroMemory(g_AceModules, sizeof(g_AceModules));
            g_AceModuleCount = 0;
            g_AceModuleBase = 0;
            g_AceModuleEnd = 0;
            g_bAceDetected = FALSE;
            ResetAllScanStates();
        }
        else
        {
            /* 未找到目标 ACE 驱动：输出心跳寻找日志，让用户明确知晓线程在运行 */
            if (scanRound <= 5 || (scanRound % 5) == 0)
            {
                DBG("[*] AceMonitor [Round #%lu]: Scanning PsLoadedModuleList (total %lu modules), target ACE driver not yet loaded...",
                    scanRound, totalModules);
            }
        }
    }
}

/*
 * ExecuteDeepSecurityScans — 各类型内核深度安全扫描统一挂载点
 * 每 10 秒（Worker 2s 周期 * 5 轮）执行一次，独立解耦，便于横向挂载更多检测项
 */
NO_OBFUS static VOID ExecuteDeepSecurityScans(ULONG scanRound)
{
    UNREFERENCED_PARAMETER(scanRound);

    /* [类型 1]: 网络驱动与 WFP Hook 深度检测（只读探针 + 去重上报） */
    NetMonitor::ScanAll();

    /* [类型 2]: USB 设备栈与 MajorFunction Hook 深度检测（只读探针 + 去重上报） */
    UsbMonitor::ScanAll();

    /* [类型 3]: 28 个敏感高危函数 EAT/Inline/SSDT/IAT Hook 深度检测（只读探针 + 去重上报） */
    ApiMonitor::ScanAll();

    /* [类型 4]: 驱动自身核心代码段 (.text) 内存完整性校验 (Adler32 动态比对) */
    if (!DrvSecurity::VerifyTextIntegrity())
    {
        DBG("[-] SecurityWorker: VerifyTextIntegrity failed! Tampering detected, clearing session key.");
        TransportManager::SetSessionCryptKey(0);
        ExceptionReporter::Report("ExecuteDeepSecurityScans", STATUS_VIRUS_INFECTED, "Kernel code text integrity violated");
    }

    /* [类型 5]: CPU 硬件断点自检 (DR0-DR3 / DR7) */
    if (!DrvSecurity::AuditHardwareBreakpoints())
    {
        DBG("[-] SecurityWorker: AuditHardwareBreakpoints failed! Active hardware breakpoint in DR0-DR7.");
        TransportManager::SetSessionCryptKey(0);
        ExceptionReporter::Report("ExecuteDeepSecurityScans", STATUS_BREAKPOINT, "Active hardware breakpoint detected in DR registers");
    }
}

/*
 * SecurityWorkerRoutine — 统一常驻系统安全工作项
 * 运行于 Windows 原生 ExpWorkerThread (PASSIVE_LEVEL)，零 PsCreateSystemThread 暴露
 * 统一调度 ACE 驱动监控与各类型内核安全扫描
 */
NO_OBFUS static VOID SecurityWorkerRoutine(IN PVOID Parameter)
{
    PACE_MONITOR_WORK_CONTEXT pCtx = (PACE_MONITOR_WORK_CONTEXT)Parameter;
    if (!pCtx)
        return;
    InterlockedExchange(&pCtx->fWorkItemQueued, 0);
    if (InterlockedCompareExchange(&pCtx->fStopped, 0, 0) != 0)
        return;
    if (!pCtx->pDriverSection)
        return;

#if !ENABLE_SECURITY_MONITOR
    return;
#else
    static ULONG s_scanRound = 0;
    s_scanRound++;

    // 1. 每 2 秒高频流：执行 ACE 驱动监控与 WFP 联动
    ScanAceModuleState(pCtx->pDriverSection, s_scanRound);

    // 2. 每 10 秒低频流（2s 周期 * 5 轮 = 10s）：执行各类型深度安全扫描
    if ((s_scanRound % 5) == 0 || s_scanRound == 1)
    {
        ExecuteDeepSecurityScans(s_scanRound);
    }
#endif
}
NO_OBFUS static VOID AceMonitorDpc(IN PKDPC Dpc, IN PVOID Context, IN PVOID SystemArg1, IN PVOID SystemArg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArg1);
    UNREFERENCED_PARAMETER(SystemArg2);
    PACE_MONITOR_WORK_CONTEXT pCtx = (PACE_MONITOR_WORK_CONTEXT)Context;
    if (!pCtx || InterlockedCompareExchange(&pCtx->fStopped, 0, 0) != 0)
        return;
    if (InterlockedCompareExchange(&pCtx->fWorkItemQueued, 1, 0) == 0)
    {
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.ExQueueWorkItem)
            g_pGlobalUserVar->Func.ExQueueWorkItem(&pCtx->WorkItem, DelayedWorkQueue);
    }
}
#if !MK_ENABLE_MANUAL_MAP
static PDEVICE_OBJECT g_pDeviceObject = NULL;
static UNICODE_STRING g_DeviceName = {};
static UNICODE_STRING g_SymbolicLinkName = {};
static BOOLEAN g_SymbolicLinkCreated = FALSE;

/*
 * 正常加载模式：启动发现设备例程 (对应 IOCTL_MK_DISCOVER_CLIENT)
 * 仅执行 UDP 广播握手探测客户端，将结果返回给应用层，不启动服务端
 */
static NTSTATUS DiscoverDeviceByIo(MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ const MK_DISCOVERY_PARAMS *pCustomParams,
                                   _Out_ PMK_DISCOVERY_RESULT pOutResult)
{
    if (!UserVar || !pOutResult)
    {
        ExceptionReporter::Report("DiscoverDeviceByIo", STATUS_INVALID_PARAMETER, "UserVar or pOutResult is NULL");
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
    DBG("[*] DiscoverDeviceByIo: Starting UDP client device discovery (Timeout=%ums, Port=%u)...", discParams.TimeoutMs,
        discParams.ServerTcpPort);
    NTSTATUS status = UdpDiscovery_DiscoverClient(UserVar, &discParams, pOutResult);
    if (NT_SUCCESS(status) && pOutResult->fFound)
    {
        DBG("[+] DiscoverDeviceByIo: Target client discovered at %s:%u", pOutResult->ClientIpStr, pOutResult->ClientPort);
    }
    else
    {
        DBG("[-] DiscoverDeviceByIo: Client discovery finished, not found (status=0x%08X, fFound=%d)", status, pOutResult->fFound);
        ExceptionReporter::Report("DiscoverDeviceByIo", status, "Client discovery finished or not found");
    }
    return status;
}
#endif // !MK_ENABLE_MANUAL_MAP

/*
 * 挂靠系统工作线程：针对性异步粉碎删除宿主加载器 (零额外系统线程审计，工作项运行于 System 进程)
 */
typedef struct _DELETE_LOADER_WORK_CONTEXT
{
    WORK_QUEUE_ITEM WorkItem;
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    ULONG ProcessId; // 宿主加载器进程 PID
    WCHAR FilePath[260];
} DELETE_LOADER_WORK_CONTEXT, *PDELETE_LOADER_WORK_CONTEXT;
static BOOLEAN IsProcessAlive(MACHENIKE_KERNEL_INTERFACE *UserVar, ULONG ProcessId)
{
    if (ProcessId == 0 || !UserVar || !UserVar->Func.PsLookupProcessByProcessId)
    {
        return FALSE;
    }
    PEPROCESS pProcess = NULL;
    NTSTATUS status = UserVar->Func.PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pProcess);
    if (NT_SUCCESS(status) && pProcess)
    {
        if (UserVar->Func.ObfDereferenceObject)
        {
            UserVar->Func.ObfDereferenceObject(pProcess);
        }
        return TRUE;
    }
    return FALSE;
}
static NTSTATUS ForceDeleteFile(MACHENIKE_KERNEL_INTERFACE *UserVar, const WCHAR *pFilePath)
{
    if (!UserVar || !pFilePath || !UserVar->Func.ZwCreateFile || !UserVar->Func.ZwClose)
        return STATUS_INVALID_PARAMETER;

    UNICODE_STRING uPath;
    WCHAR ntPath[300] = {0};

    if (pFilePath[0] == L'\\' && pFilePath[1] == L'?' && pFilePath[2] == L'?' && pFilePath[3] == L'\\')
    {
        for (ULONG i = 0; i < 299 && pFilePath[i] != L'\0'; i++)
            ntPath[i] = pFilePath[i];
    }
    else
    {
        ntPath[0] = L'\\';
        ntPath[1] = L'?';
        ntPath[2] = L'?';
        ntPath[3] = L'\\';
        for (ULONG i = 0; i < 295 && pFilePath[i] != L'\0'; i++)
            ntPath[4 + i] = pFilePath[i];
    }
    SafeInitUnicodeString(&uPath, ntPath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb = {0};
    HANDLE hFile = NULL;
    NTSTATUS status = UserVar->Func.ZwCreateFile(
        &hFile,
        DELETE | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
        NULL,
        0);

    if (NT_SUCCESS(status) && hFile)
    {
        UserVar->Func.ZwClose(hFile);
    }
    return status;
}
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif
static NTSTATUS TerminateProcessById(MACHENIKE_KERNEL_INTERFACE *UserVar, ULONG ProcessId)
{
    if (ProcessId == 0 || !UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!UserVar->Func.ZwOpenProcess || !UserVar->Func.ZwTerminateProcess)
    {
        return STATUS_NOT_FOUND;
    }

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
    cid.UniqueThread = NULL;

    HANDLE hProcess = NULL;
    NTSTATUS status = UserVar->Func.ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &oa, &cid);
    if (NT_SUCCESS(status) && hProcess)
    {
        status = UserVar->Func.ZwTerminateProcess(hProcess, STATUS_SUCCESS);
        if (UserVar->Func.ZwClose)
        {
            UserVar->Func.ZwClose(hProcess);
        }
        DBG("[+] TerminateProcessById: Successfully requested termination for PID %u (status=0x%08X)", ProcessId, status);
        return status;
    }
    DBG("[-] TerminateProcessById: Failed to open PID %u for termination (status=0x%08X)", ProcessId, status);
    return status;
}
static VOID AsyncDeleteHostLoaderWorkRoutine(IN PVOID Parameter)
{
    PDELETE_LOADER_WORK_CONTEXT pCtx = (PDELETE_LOADER_WORK_CONTEXT)Parameter;
    if (!pCtx || !pCtx->UserVar)
    {
        return;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = pCtx->UserVar;
    // 1. 先主动终止宿主加载器进程，确保其释放自身二进制镜像与文件句柄
    if (pCtx->ProcessId != 0)
    {
        DBG("[*] AsyncDeleteHostLoader: Terminating host loader process (PID=%u)...", pCtx->ProcessId);
        TerminateProcessById(UserVar, pCtx->ProcessId);

        // 短暂等待进程完全退出与句柄解除
        const ULONG maxProcessWaitRounds = 30; // 30 * 100ms = 3000ms
        for (ULONG round = 0; round < maxProcessWaitRounds; round++)
        {
            if (!IsProcessAlive(UserVar, pCtx->ProcessId))
            {
                DBG("[+] Host process PID %u has terminated cleanly", pCtx->ProcessId);
                break;
            }
            LARGE_INTEGER interval;
            interval.QuadPart = -1000000LL; // 100ms
            if (UserVar->Func.KeDelayExecutionThread)
            {
                UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &interval);
            }
        }
    }
    // 2. 执行自删除重试循环 (最多重试 30 次，每次间隔 1 秒)
    const ULONG maxRetries = 30;
    BOOLEAN bDeleted = FALSE;
    for (ULONG attempt = 1; attempt <= maxRetries; attempt++)
    {
        NTSTATUS status = ForceDeleteFile(UserVar, pCtx->FilePath);
        if (NT_SUCCESS(status) || status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            DBG("[+] Successfully self-deleted host loader file: %ws (attempt %u)", pCtx->FilePath, attempt);
            bDeleted = TRUE;
            break;
        }
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL; // 1s
        if (UserVar->Func.KeDelayExecutionThread)
        {
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
    }
    if (!bDeleted)
    {
        DBG("[-] Failed to self-delete host loader file after %u attempts: %ws", maxRetries, pCtx->FilePath);
    }
    // 3. 阅后即焚: 彻底清空并释放工作上下文内存
    if (UserVar->Func.RtlZeroMemory)
    {
        UserVar->Func.RtlZeroMemory(pCtx, sizeof(DELETE_LOADER_WORK_CONTEXT));
    }
    if (UserVar->Func.ExFreePoolWithTag)
    {
        UserVar->Func.ExFreePoolWithTag(pCtx, MK_POOL_TAG);
    }
}
static VOID ScheduleDeleteHostLoader(MACHENIKE_KERNEL_INTERFACE *UserVar, const WCHAR *pPath, ULONG ProcessId = 0)
{
    if (!UserVar || !pPath || pPath[0] == L'\0')
    {
        return;
    }
    if (ProcessId == 0 && UserVar->Func.PsGetCurrentProcessId)
    {
        ProcessId = HandleToULong(UserVar->Func.PsGetCurrentProcessId());
    }
    PDELETE_LOADER_WORK_CONTEXT pCtx =
        (PDELETE_LOADER_WORK_CONTEXT)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sizeof(DELETE_LOADER_WORK_CONTEXT), MK_POOL_TAG);
    if (!pCtx)
    {
        return;
    }
    UserVar->Func.RtlZeroMemory(pCtx, sizeof(DELETE_LOADER_WORK_CONTEXT));
    pCtx->UserVar = UserVar;
    pCtx->ProcessId = ProcessId;
    for (ULONG i = 0; i < 259 && pPath[i] != L'\0'; i++)
    {
        pCtx->FilePath[i] = pPath[i];
    }
    ExInitializeWorkItem(&pCtx->WorkItem, AsyncDeleteHostLoaderWorkRoutine, pCtx);
    if (g_pGlobalUserVar && g_pGlobalUserVar->Func.ExQueueWorkItem)
        g_pGlobalUserVar->Func.ExQueueWorkItem(&pCtx->WorkItem, DelayedWorkQueue);
    DBG("[+] CheatDrv: Scheduled targeted host loader deletion for %ws (PID=%u, via system worker thread)", pCtx->FilePath,
        pCtx->ProcessId);
}

static ULONG s_PendingLoaderPid = 0;
static WCHAR s_PendingLoaderPath[260] = {0};
static volatile LONG s_CleanupTriggered = 0;

VOID DriverCore::SetPendingHostLoaderCleanup(const WCHAR *pPath, ULONG pid)
{
    s_PendingLoaderPid = pid;
    if (pPath)
    {
        for (ULONG i = 0; i < 259 && pPath[i] != L'\0'; i++)
        {
            s_PendingLoaderPath[i] = pPath[i];
        }
        s_PendingLoaderPath[259] = L'\0';
    }
    InterlockedExchange(&s_CleanupTriggered, 0);
    DBG("[+] DriverCore: Staged pending host loader cleanup (PID=%u, Path=%ws), awaiting first client ping/handshake",
        s_PendingLoaderPid, s_PendingLoaderPath);
}

VOID DriverCore::TriggerPendingHostLoaderCleanup(VOID)
{
    if (s_PendingLoaderPid == 0 && s_PendingLoaderPath[0] == L'\0')
    {
        return;
    }
    if (InterlockedCompareExchange(&s_CleanupTriggered, 1, 0) == 0)
    {
        DBG("[+] DriverCore: First business packet/ping received from client! Triggering host loader purge (PID=%u, Path=%ws)",
            s_PendingLoaderPid, s_PendingLoaderPath);
        ScheduleDeleteHostLoader(g_pGlobalUserVar, s_PendingLoaderPath, s_PendingLoaderPid);
        s_PendingLoaderPid = 0;
        RtlSecureZeroMemory(s_PendingLoaderPath, sizeof(s_PendingLoaderPath));
    }
}

#if !MK_ENABLE_MANUAL_MAP
static NTSTATUS WskIoDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
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
        // 允许基础 20 字节配置或扩展带 SessionToken 的配置
        if (inBufLen < 20 || !inBuf)
        {
            DBG("[-] IOCTL_MK_START_TRANSPORT: Input buffer too small (%u < 20) or NULL", inBufLen);
            status = STATUS_BUFFER_TOO_SMALL;
            ExceptionReporter::Report("WskIoDeviceControl_StartTransport", status, "Input buffer too small or NULL");
            break;
        }
        PDRV_BOOT_CONFIG pCfg = (PDRV_BOOT_CONFIG)inBuf;
#if !(NO_AUTH || ENABLE_NO_AUTH)
        if (pCfg->Magic != DRV_BOOT_CONFIG_MAGIC)
        {
            DBG("[-] IOCTL_MK_START_TRANSPORT: Invalid Magic 0x%08X (expected 0x%08X)", pCfg->Magic, DRV_BOOT_CONFIG_MAGIC);
            status = STATUS_INVALID_PARAMETER;
            ExceptionReporter::Report("WskIoDeviceControl_StartTransport", status, "Invalid Magic header");
            break;
        }
#else
        if (pCfg->Magic != DRV_BOOT_CONFIG_MAGIC)
        {
            DBG("[*] IOCTL_MK_START_TRANSPORT: NoAuth enabled, bypassing Magic check (got 0x%08X, expected 0x%08X)", pCfg->Magic,
                DRV_BOOT_CONFIG_MAGIC);
        }
#endif
        DBG("[+] IOCTL_MK_START_TRANSPORT: R3 requested start server (Mode=%u Port=%u)", pCfg->TransportMode, pCfg->Port);
        ULONG callerPid = g_pGlobalUserVar && g_pGlobalUserVar->Func.PsGetCurrentProcessId
                              ? HandleToULong(g_pGlobalUserVar->Func.PsGetCurrentProcessId())
                              : 0;
        if (inBufLen >= sizeof(DRV_BOOT_CONFIG_EX))
        {
            PDRV_BOOT_CONFIG_EX pCfgEx = (PDRV_BOOT_CONFIG_EX)inBuf;
            status = DriverCore::ApplyBootConfigAndStart(g_pGlobalUserVar, pCfgEx, callerPid);
        }
        else
        {
            status = StartTransportByIo(g_pGlobalUserVar, pCfg);
        }
        if (!NT_SUCCESS(status))
        {
            ExceptionReporter::Report("WskIoDeviceControl_StartTransport", status, "Failed to start transport server");
        }
        // 若调用方提供了输出缓冲，组装 DRV_BOOT_RESPONSE 回传真实内核指纹
        if (outBuf && outBufLen >= sizeof(DRV_BOOT_RESPONSE))
        {
            PDRV_BOOT_RESPONSE pRsp = (PDRV_BOOT_RESPONSE)outBuf;
            pRsp->Status = status;
            pRsp->BoundPort = pCfg->Port ? pCfg->Port : MK_WSK_DEFAULT_PORT;
            pRsp->TransportMode = (USHORT)pCfg->TransportMode;
            // 运行时栈混淆动态构建防伪私钥，彻底抹除 .rdata/.text 中的静态字符串常量 "KernelDrvAuthKey"
            volatile ULONG64 maskA = 0x55AA55AA55AA55AAULL;
            volatile ULONG64 maskB = 0xAA55AA55AA55AA55ULL;
            UCHAR dynAuthKey[16];
            *(PULONG64)&dynAuthKey[0] = 0x72446C656E72654BULL ^ maskA;
            *(PULONG64)&dynAuthKey[8] = 0x79654B6874754176ULL ^ maskB;
            *(PULONG64)&dynAuthKey[0] ^= maskA;
            *(PULONG64)&dynAuthKey[8] ^= maskB;

            if (inBufLen >= sizeof(DRV_BOOT_CONFIG))
            {
                pRsp->DriverSignature = Utils::SipHash24(dynAuthKey, pCfg->SessionToken, 16);
            }
            else
            {
                pRsp->DriverSignature = Utils::SipHash24(dynAuthKey, (const UCHAR *)&pCfg->AuthToken, sizeof(pCfg->AuthToken));
            }
            RtlSecureZeroMemory(dynAuthKey, sizeof(dynAuthKey));
            bytesReturned = sizeof(DRV_BOOT_RESPONSE);
            DBG("[+] IOCTL_MK_START_TRANSPORT: Returned DriverSignature=0x%llX to loader", pRsp->DriverSignature);
        }
        break;
    }
    case IOCTL_MK_DISCOVER_CLIENT:
    {
        if (outBufLen < sizeof(MK_DISCOVERY_RESULT) || !outBuf)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            ExceptionReporter::Report("WskIoDeviceControl_DiscoverClient", status, "Output buffer too small");
            break;
        }
        if (g_pGlobalUserVar)
        {
            const MK_DISCOVERY_PARAMS *pParams = NULL;
            if (inBuf && inBufLen >= sizeof(MK_DISCOVERY_PARAMS))
            {
                pParams = (const MK_DISCOVERY_PARAMS *)inBuf;
            }
            status = DiscoverDeviceByIo(g_pGlobalUserVar, pParams, (PMK_DISCOVERY_RESULT)outBuf);
            bytesReturned = sizeof(MK_DISCOVERY_RESULT);
        }
        else
        {
            status = STATUS_DEVICE_NOT_READY;
            ExceptionReporter::Report("WskIoDeviceControl_DiscoverClient", status, "g_pGlobalUserVar is NULL");
        }
        break;
    }
    case IOCTL_MK_STOP_TRANSPORT:
    {
        DBG("[*] IOCTL_MK_STOP_TRANSPORT: R3 requested stop server");
        if (g_pGlobalUserVar)
        {
            TransportManager::StopServer(g_pGlobalUserVar);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_DEVICE_NOT_READY;
            ExceptionReporter::Report("WskIoDeviceControl_StopTransport", status, "g_pGlobalUserVar is NULL");
        }
        break;
    }
    case IOCTL_MK_GET_STATUS:
    {
        if (outBufLen < sizeof(MK_SERVER_STATUS) || !outBuf)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            ExceptionReporter::Report("WskIoDeviceControl_GetStatus", status, "Output buffer too small");
            break;
        }
        if (g_pGlobalUserVar)
        {
            TransportManager::GetStatus(g_pGlobalUserVar, (PMK_SERVER_STATUS)outBuf);
            bytesReturned = sizeof(MK_SERVER_STATUS);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_DEVICE_NOT_READY;
            ExceptionReporter::Report("WskIoDeviceControl_GetStatus", status, "g_pGlobalUserVar is NULL");
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        ExceptionReporter::Report("WskIoDeviceControl_Default", status, "Unknown IOCTL code");
        break;
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
#endif
static PMDL g_pHeadlessCanaryMdl = NULL;
static __inline BOOLEAN InitHeadlessCanary(MACHENIKE_KERNEL_INTERFACE *UserVar, ULONG64 KernelBase, ULONG ImageSize)
{
    UNREFERENCED_PARAMETER(UserVar);
    if (g_pHeadlessCanaryMdl)
    {
        return TRUE;
    }
    PHYSICAL_ADDRESS lowAddr, highAddr, skipBytes;
    lowAddr.QuadPart = DRV_CANARY_WINDOW_LOW;
    highAddr.QuadPart = DRV_CANARY_WINDOW_HIGH;
    skipBytes.QuadPart = 0;
    // 方案 5：优先在限定窗口 [256MB ~ 512MB] 分配纯游离物理页 (零系统大池登记，零内核 VA 挂载)
    PMDL pMdl = MmAllocatePagesForMdl(lowAddr, highAddr, skipBytes, PAGE_SIZE);
    if (!pMdl)
    {
        // 兜底策略：若限定窗口内存紧张，放宽至 1GB 窗口
        highAddr.QuadPart = 0x40000000ULL;
        pMdl = MmAllocatePagesForMdl(lowAddr, highAddr, skipBytes, PAGE_SIZE);
    }
    if (!pMdl)
    {
        DBG("[-] InitHeadlessCanary: Failed to allocate headless MDL page");
        ExceptionReporter::Report("InitHeadlessCanary", STATUS_INSUFFICIENT_RESOURCES, "Failed to allocate headless MDL page");
        return FALSE;
    }
    PPFN_NUMBER pfnArray = MmGetMdlPfnArray(pMdl);
    if (!pfnArray || pfnArray[0] == 0)
    {
        ExceptionReporter::Report("InitHeadlessCanary", STATUS_INVALID_ADDRESS, "MmGetMdlPfnArray returned null or zero PFN");
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.MmFreePagesFromMdl)
            g_pGlobalUserVar->Func.MmFreePagesFromMdl(pMdl);
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.ExFreePoolWithTag)
            g_pGlobalUserVar->Func.ExFreePoolWithTag(pMdl, 0);
        return FALSE;
    }
    ULONG64 canaryPa = ((ULONG64)pfnArray[0]) << PAGE_SHIFT;
    // 映射极短临时的内核 VA 写入初始数据，写完立即注销 VA，保持物理页无虚拟地址关联
    PVOID tempVa = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (tempVa)
    {
        PDRV_WSK_CANARY pCanary = (PDRV_WSK_CANARY)tempVa;
        RtlZeroMemory(pCanary, PAGE_SIZE);
        static const GUID canaryGuid = {DRV_CANARY_GUID_D1, DRV_CANARY_GUID_D2, DRV_CANARY_GUID_D3, DRV_CANARY_GUID_D4};
        pCanary->Signature = canaryGuid;
        pCanary->Magic = DRV_WSK_CANARY_MAGIC;
        pCanary->KernelImageVA = KernelBase;
        pCanary->ImageSize = ImageSize;
        pCanary->ProtocolVersion = 0x01000001;
        pCanary->CanaryPhysAddr = canaryPa;
        LARGE_INTEGER sysTime;
        KeQuerySystemTime(&sysTime);
        pCanary->Timestamp = (ULONG64)sysTime.QuadPart;
        MmUnmapLockedPages(tempVa, pMdl);
        g_pHeadlessCanaryMdl = pMdl;
        DBG("[+] InitHeadlessCanary: Scheme 5 Headless Canary active at PA=0x%016llX (PFN=0x%llX)", canaryPa, (ULONG64)pfnArray[0]);
        return TRUE;
    }
    ExceptionReporter::Report("InitHeadlessCanary", STATUS_UNSUCCESSFUL, "MmMapLockedPagesSpecifyCache failed");
    if (g_pGlobalUserVar && g_pGlobalUserVar->Func.MmFreePagesFromMdl)
        g_pGlobalUserVar->Func.MmFreePagesFromMdl(pMdl);
    if (g_pGlobalUserVar && g_pGlobalUserVar->Func.ExFreePoolWithTag)
        g_pGlobalUserVar->Func.ExFreePoolWithTag(pMdl, 0);
    return FALSE;
}
static VOID CleanupHeadlessCanary(VOID)
{
    if (g_pHeadlessCanaryMdl)
    {
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.MmFreePagesFromMdl)
            g_pGlobalUserVar->Func.MmFreePagesFromMdl(g_pHeadlessCanaryMdl);
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.ExFreePoolWithTag)
            g_pGlobalUserVar->Func.ExFreePoolWithTag(g_pHeadlessCanaryMdl, 0);
        g_pHeadlessCanaryMdl = NULL;
        DBG("[+] CleanupHeadlessCanary: Cleared Headless Canary MDL.");
    }
}
VOID DriverCore::DriverUnload(IN PDRIVER_OBJECT pDriverObj)
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
    WfpBypass::Cleanup(UserVar);
    TransportManager::StopServer(UserVar);
    MkRpc_Cleanup(UserVar);
#if !MK_ENABLE_MANUAL_MAP
    /* 正常加载模式：删除创建的符号链接与设备对象 */
    if (g_SymbolicLinkCreated)
    {
        UserVar->Func.IoDeleteSymbolicLink(&g_SymbolicLinkName);
        g_SymbolicLinkCreated = FALSE;
        DBG("[+] Normal Driver Load: Deleted symbolic link %wZ", &g_SymbolicLinkName);
    }
    if (g_pDeviceObject)
    {
        UserVar->Func.IoDeleteDevice(g_pDeviceObject);
        g_pDeviceObject = NULL;
        DBG("[+] Normal Driver Load: Deleted device object %wZ", &g_DeviceName);
    }
#endif
#if (MK_ENABLE_FAKE_LDR)
    /* ACE 对抗：在启用伪造 LDR 模式下清理并恢复宿主真实 LDR 项，防止驱动卸载后悬空指针导致 BSOD */
    StealthReloc::CleanupFakeLdrEntry(UserVar);
#endif
    if (UserVar->MmPhysicalMemoryRange)
        UserVar->Func.ExFreePoolWithTag(UserVar->MmPhysicalMemoryRange, 0);
    if (g_pGlobalUserVar)
    {
        UserVar->Func.ExFreePoolWithTag(g_pGlobalUserVar, MK_POOL_TAG);
        g_pGlobalUserVar = NULL;
    }
    /* 方案 5：安全释放纯游离物理页 Canary 暗桩 */
    CleanupHeadlessCanary();
    DBG("[+] DriverUnload: Cleanup completed successfully.");
}
/*
 * 异步卸载工作项例程：在独立系统工作线程中安全停止服务并清理驱动
 */
static VOID UnloadWorkRoutine(IN PVOID Parameter)
{
    PWORK_QUEUE_ITEM pWorkItem = (PWORK_QUEUE_ITEM)Parameter;
    DBG("[*] UnloadWorkRoutine: Executing async driver unload...");
    DriverCore::DriverUnload(g_pDriverObj);
    DBG("[+] UnloadWorkRoutine: Driver cleanup finished.");
    if (pWorkItem)
    {
        if (g_pGlobalUserVar)
        {
            g_pGlobalUserVar->Func.ExFreePoolWithTag(pWorkItem, MK_POOL_TAG);
        }
    }
}
VOID DriverCore::TriggerUnload(VOID)
{
    DBG("[*] DriverCore::TriggerUnload: Scheduling driver unload work item...");
    MACHENIKE_KERNEL_INTERFACE *UserVar = g_pGlobalUserVar;
    if (UserVar)
    {
        PWORK_QUEUE_ITEM pWorkItem =
            (PWORK_QUEUE_ITEM)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM), MK_POOL_TAG);
        if (pWorkItem)
        {
            ExInitializeWorkItem(pWorkItem, UnloadWorkRoutine, pWorkItem);
            if (UserVar && UserVar->Func.ExQueueWorkItem)
                UserVar->Func.ExQueueWorkItem(pWorkItem, DelayedWorkQueue);
            return;
        }
    }
    /* 降级为同步卸载 */
    DriverCore::DriverUnload(g_pDriverObj);
}
NTSTATUS MachenikeUserVarInit(IN PKLDR_DATA_TABLE_ENTRY DriverSection, OUT MACHENIKE_KERNEL_INTERFACE **pUserVar)
{
    if (!DriverSection || !DriverSection->InLoadOrderLinks.Flink)
    {
        DBG("[-] MachenikeUserVarInit: DriverSection is NULL or invalid");
        return STATUS_INVALID_PARAMETER;
    }
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
        str_KeSetTimerEx,
        str_KeInitializeDpc,
        str_KeInitializeTimerEx,
        str_ExQueueWorkItem,
        str_MmFreePagesFromMdl,
        str_IoReuseIrp,
        str_ObReferenceObjectByName,
        str_IoDriverObjectType,
        str_KeQueryActiveProcessorCount,
        str_IoGetCurrentProcess,
        str_PsGetProcessSectionBaseAddress,
        str_ExAllocatePool2,
        str___C_specific_handler,
        str__snprintf,
        str__vsnprintf,
        str_ZwMapViewOfSection,
        str_ZwUnmapViewOfSection,
        str_MmAllocateMappingAddress,
        str_MmFreeMappingAddress,
        str_PsLookupProcessByProcessId,
        str_ZwOpenProcess,
        str_ZwTerminateProcess,
        /* 内核压缩 API 函数（ntoskrnl.exe） */
        str_RtlGetCompressionWorkSpaceSize,
        str_RtlCompressBuffer,
        str_RtlDecompressBuffer,
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
        ULONG U32ModuleName = Utils::HashStringW(pEntry->BaseDllName.Buffer, cchName, TRUE);
        if (!bNtoskrnlFound && (U32ModuleName == wstr_Ntoskrnl || ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"ntoskrnl")))
        {
            ULONG_PTR *TableAsArray = (ULONG_PTR *)&pfnTable;
            for (size_t i = 0; i < ARRAY_SIZE(FunctionArray); i++)
            {
                if (!Utils::GetModuleExport((ULONG_PTR)pEntry->DllBase, FunctionArray[i], &TableAsArray[i]))
                {
                    // 若目标为 KeQueryPerformanceCounter，从链表中寻找 hal.dll 进行兜底解析
                    if (FunctionArray[i] == str_KeQueryPerformanceCounter)
                    {
                        BOOLEAN bHalFound = FALSE;
                        for (PLIST_ENTRY pHalEntry = DriverSection->InLoadOrderLinks.Flink; pHalEntry != &DriverSection->InLoadOrderLinks;
                             pHalEntry = pHalEntry->Flink)
                        {
                            PKLDR_DATA_TABLE_ENTRY pHal = CONTAINING_RECORD(pHalEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                            if (pHal->DllBase && pHal->BaseDllName.Buffer)
                            {
                                ULONG cchHal = pHal->BaseDllName.Length / sizeof(WCHAR);
                                if (ContainsSubstrCaseless(pHal->BaseDllName.Buffer, cchHal, L"hal"))
                                {
                                    if (Utils::GetModuleExport((ULONG_PTR)pHal->DllBase, str_KeQueryPerformanceCounter, &TableAsArray[i]))
                                    {
                                        DBG("[+] Resolved KeQueryPerformanceCounter from hal.dll Addr:[0x%p]", (PVOID)TableAsArray[i]);
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
                DBG("[+] Resolved Index:[%02lld] U32Hash:[0x%08X] Addr:[0x%p]", i, FunctionArray[i], (PVOID)TableAsArray[i]);
            }
            DBG("[+] Successfully resolved all %lld kernel functions from ntoskrnl!", (LONGLONG)ARRAY_SIZE(FunctionArray));
            if (!pfnTable.ExAllocatePoolWithTag || !pfnTable.memset || !pfnTable.memcpy || !pfnTable.RtlCopyMemory ||
                !pfnTable.RtlZeroMemory)
                return STATUS_NOT_FOUND;
            UserVar =
                (MACHENIKE_KERNEL_INTERFACE *)pfnTable.ExAllocatePoolWithTag(NonPagedPool, sizeof(MACHENIKE_KERNEL_INTERFACE), MK_POOL_TAG);
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
        ULONG U32ModuleName = Utils::HashStringW(pEntry->BaseDllName.Buffer, cchName, TRUE);
        if (U32ModuleName == wstr_Netio || ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"netio"))
        {
            Utils::GetModuleExport((ULONG_PTR)pEntry->DllBase, str_WskRegister, (PULONG_PTR)&UserVar->Func.WskRegister);
            Utils::GetModuleExport((ULONG_PTR)pEntry->DllBase, str_WskCaptureProviderNPI, (PULONG_PTR)&UserVar->Func.WskCaptureProviderNPI);
            Utils::GetModuleExport((ULONG_PTR)pEntry->DllBase, str_WskReleaseProviderNPI, (PULONG_PTR)&UserVar->Func.WskReleaseProviderNPI);
            Utils::GetModuleExport((ULONG_PTR)pEntry->DllBase, str_WskDeregister, (PULONG_PTR)&UserVar->Func.WskDeregister);
            Utils::GetModuleExport((ULONG_PTR)pEntry->DllBase, str_KfdGetRefCallout, (PULONG_PTR)&UserVar->Func.KfdGetRefCallout);
            Utils::GetModuleExport((ULONG_PTR)pEntry->DllBase, str_KfdDeRefCallout, (PULONG_PTR)&UserVar->Func.KfdDeRefCallout);
            DBG("[+] Resolved WSK & KFD functions from netio.sys (Base=0x%p, WskRegister=0x%p, KfdGetRef=0x%p)", pEntry->DllBase,
                (PVOID)UserVar->Func.WskRegister, (PVOID)UserVar->Func.KfdGetRefCallout);
            break;
        }
    }
    // 动态解析 cng.sys 中的密码学函数
    for (PLIST_ENTRY pListEntry = DriverSection->InLoadOrderLinks.Flink; pListEntry != &DriverSection->InLoadOrderLinks;
         pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!pEntry->DllBase || !pEntry->BaseDllName.Buffer)
            continue;
        ULONG cchName = pEntry->BaseDllName.Length / sizeof(WCHAR);
        if (ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"cng"))
        {
            ULONG FunctionArrayCng[] = {
                str_BCryptOpenAlgorithmProvider,
                str_BCryptCloseAlgorithmProvider,
                str_BCryptCreateHash,
                str_BCryptDestroyHash,
                str_BCryptHashData,
                str_BCryptFinishHash,
                str_BCryptDuplicateHash,
                str_BCryptGenRandom,
                str_BCryptGenerateSymmetricKey,
                str_BCryptDestroyKey,
                str_BCryptEncrypt,
                str_BCryptImportKeyPair,
                str_BCryptSetProperty,
            };
            ULONG_PTR *CngTableAsArray = (ULONG_PTR *)&UserVar->Cng;
            for (size_t i = 0; i < ARRAY_SIZE(FunctionArrayCng); i++)
            {
                Utils::GetModuleExport((ULONG_PTR)pEntry->DllBase, FunctionArrayCng[i], &CngTableAsArray[i]);
            }
            DBG("[+] Resolved 13 BCrypt functions from cng.sys (Base=0x%p)", pEntry->DllBase);
            break;
        }
    }
    return STATUS_SUCCESS;
}
NTSTATUS DriverCore::Initialize(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (pDriverObj)
    {
        PKLDR_DATA_TABLE_ENTRY pHostDriverSection = (PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;
        if (!pHostDriverSection)
        {
            DBG("[-] DriverCore::Initialize: DriverSection is NULL");
            return STATUS_INVALID_PARAMETER;
        }
        g_pHostDriverSection = pHostDriverSection;
        g_pDriverObj = pDriverObj;
        MACHENIKE_KERNEL_INTERFACE *UserVar = NULL;
        status = MachenikeUserVarInit(pHostDriverSection, &UserVar);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        g_pGlobalUserVar = UserVar;
        NetMonitor::SetUserVar(UserVar);
        NetMonitor::Init();
        UsbMonitor::SetUserVar(UserVar);
        UsbMonitor::Init();
        ApiMonitor::Init(UserVar, pHostDriverSection);
        ExceptionReporter::SetUserVar(UserVar);
        DrvSecurity::InitTextIntegrity();
        /* 初始化阶段立即完成系统旁路模块与网络过滤驱动扫描，杜绝延迟执行 */
        DriverCore::ScanBypassModules(pHostDriverSection);
        /* 启动常驻系统安全工作项调度引擎，持续执行 ACE 追踪与各类型安全扫描 */
#if ENABLE_SECURITY_MONITOR
        if (!g_AceMonitorTimerStarted && pHostDriverSection)
        {
            PACE_MONITOR_WORK_CONTEXT pCtx = &g_AceMonitorCtx;
            ExInitializeWorkItem(&pCtx->WorkItem, SecurityWorkerRoutine, pCtx);
            pCtx->pDriverSection = pHostDriverSection;
            InterlockedExchange(&pCtx->fStopped, 0);
            if (UserVar->Func.KeInitializeDpc)
                UserVar->Func.KeInitializeDpc(&pCtx->Dpc, AceMonitorDpc, pCtx);
            if (UserVar->Func.KeInitializeTimerEx)
                UserVar->Func.KeInitializeTimerEx(&pCtx->Timer, SynchronizationTimer);
            LARGE_INTEGER DueTime;
            DueTime.QuadPart = -(LONGLONG)(1ULL * 1000 * 10000); /* 1s 后首次触发 */
            if (UserVar->Func.KeSetTimerEx)
                UserVar->Func.KeSetTimerEx(&pCtx->Timer, DueTime, 2000 /* 周期 2s 持续寻找 */, &pCtx->Dpc);
            g_AceMonitorTimerStarted = TRUE;
            DBG("[+] SecurityMonitor: Dedicated background scan engine started (2s period)");
        }
#else
        DBG("[*] SecurityMonitor: Dedicated background scan engine disabled by ENABLE_SECURITY_MONITOR=0");
#endif
#if MK_ENABLE_MANUAL_MAP
        // 深度防御：手动映射入口自检硬件断点与内存完整性
        DrvSecurity::InitTextIntegrity();
        if (!DrvSecurity::AuditHardwareBreakpoints())
        {
            DBG("[-] ManualMap: AuditHardwareBreakpoints failed (Hardware BP detected)");
            return STATUS_ACCESS_DENIED;
        }
        /* 【手动映射模式专属逻辑 - 保持原逻辑】
         * 1. 读取 shellcode 暂存的实际内核池基址并立即复位 DeviceObject 为 NULL，消除对象表审计风险
         * 2. Manual Map 到宿主白驱动或 tcpip.sys 时切勿挂接 DriverUnload，防止未签名指针触发反作弊报警
         */
        g_pDriverActualPoolBase = pDriverObj->DeviceObject;
        pDriverObj->DeviceObject = NULL;
        /* 启动通讯服务：由 Loader 传入的 BootConfig 决定启动模式 (TCP / UDP / USB) 及端口 */
        status = RpcDispatcher::Init(UserVar);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] ManualMap: MkRpc_Init failed with status 0x%08X", status);
            ExceptionReporter::Report("DriverEntry_ManualMap", status, "MkRpc_Init failed");
            return status;
        }
        TransportManager::Init(UserVar);
        NTSTATUS srvStatus = STATUS_UNSUCCESSFUL;
        MK_SERVER_START_PARAMS srvParams = {};
        PDRV_BOOT_CONFIG pBootConfig = (PDRV_BOOT_CONFIG)pRegistryPath;
        PDRV_BOOT_CONFIG_EX pBootConfigEx = NULL;
#if !(NO_AUTH || ENABLE_NO_AUTH)
        if (pBootConfig && pBootConfig->Magic == DRV_BOOT_CONFIG_MAGIC)
#else
        if (pBootConfig)
#endif
        {
            DBG("[+] Received BootConfig from Loader: Mode=%u Port=%u", pBootConfig->TransportMode, pBootConfig->Port);
            pBootConfigEx = (PDRV_BOOT_CONFIG_EX)pBootConfig;
            if (pBootConfigEx->ApiUrl[0] != '\0')
            {
                if (UserVar && UserVar->Func.memcpy)
                    UserVar->Func.memcpy(g_ApiUrl, pBootConfigEx->ApiUrl, sizeof(g_ApiUrl));
                else
                    memcpy(g_ApiUrl, pBootConfigEx->ApiUrl, sizeof(g_ApiUrl));
                DBG("[+] Driver received ApiUrl: %s", g_ApiUrl);
            }
            if (pBootConfigEx->LoginUrl[0] != '\0')
            {
                if (UserVar && UserVar->Func.memcpy)
                    UserVar->Func.memcpy(g_LoginUrl, pBootConfigEx->LoginUrl, sizeof(g_LoginUrl));
                else
                    memcpy(g_LoginUrl, pBootConfigEx->LoginUrl, sizeof(g_LoginUrl));
                DBG("[+] Driver received LoginUrl: %s", g_LoginUrl);
            }
            if (pBootConfigEx->ReportUrl[0] != '\0')
            {
                if (UserVar && UserVar->Func.memcpy)
                    UserVar->Func.memcpy(g_ReportUrl, pBootConfigEx->ReportUrl, sizeof(g_ReportUrl));
                else
                    memcpy(g_ReportUrl, pBootConfigEx->ReportUrl, sizeof(g_ReportUrl));
                DBG("[+] Driver received ReportUrl: %s", g_ReportUrl);
            }
            if (pBootConfigEx->BrandVersion[0] != '\0')
            {
                if (UserVar && UserVar->Func.memcpy)
                    UserVar->Func.memcpy(g_BrandVersion, pBootConfigEx->BrandVersion, sizeof(g_BrandVersion));
                else
                    memcpy(g_BrandVersion, pBootConfigEx->BrandVersion, sizeof(g_BrandVersion));
                DBG("[+] Driver received BrandVersion: %s", g_BrandVersion);
            }
            if (pBootConfigEx->SelectedGame[0] != '\0')
            {
                if (UserVar && UserVar->Func.memcpy)
                    UserVar->Func.memcpy(g_SelectedGame, pBootConfigEx->SelectedGame, sizeof(g_SelectedGame));
                else
                    memcpy(g_SelectedGame, pBootConfigEx->SelectedGame, sizeof(g_SelectedGame));
                DBG("[+] Driver received SelectedGame: %s", g_SelectedGame);
            }
            if (pBootConfigEx->ClientVersion[0] != '\0')
            {
                if (UserVar && UserVar->Func.memcpy)
                    UserVar->Func.memcpy(g_ClientVersion, pBootConfigEx->ClientVersion, sizeof(g_ClientVersion));
                else
                    memcpy(g_ClientVersion, pBootConfigEx->ClientVersion, sizeof(g_ClientVersion));
                DBG("[+] Driver received ClientVersion: %s", g_ClientVersion);
            }
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
        else
        {
            if (!pBootConfig)
            {
                DBG("[-] ManualMap: BootConfig pointer is NULL");
            }
#if !(NO_AUTH || ENABLE_NO_AUTH)
            else if (pBootConfig->Magic != DRV_BOOT_CONFIG_MAGIC)
            {
                DBG("[-] ManualMap: BootConfig Magic invalid: 0x%08X (expected 0x%08X)", pBootConfig->Magic, DRV_BOOT_CONFIG_MAGIC);
            }
#endif
        }
        if (pBootConfig)
        {
#if NO_AUTH || ENABLE_NO_AUTH
            // 免认证调试模式：强制会话密钥固定为 0x8899AABBCCDDEEFFULL，阻断 Loader 传入的动态 AuthToken 覆盖密钥，与测试客户端 100% 对齐
            ULONG64 dynamicKey = 0x8899AABBCCDDEEFFULL;
            TransportManager::SetSessionCryptKey(dynamicKey);
            DrvSecurity::SetAuthStateInvariant(dynamicKey);
            DBG("[+] DriverEntry_ManualMap: NoAuth mode - Enforced default SessionCryptKey=0x%016llX", dynamicKey);
#else
            volatile ULONG64 maskA = 0x55AA55AA55AA55AAULL;
            volatile ULONG64 maskB = 0xAA55AA55AA55AA55ULL;
            UCHAR dynAuthKey[16];
            *(PULONG64)&dynAuthKey[0] = 0x72446C656E72654BULL ^ maskA;
            *(PULONG64)&dynAuthKey[8] = 0x79654B6874754176ULL ^ maskB;
            *(PULONG64)&dynAuthKey[0] ^= maskA;
            *(PULONG64)&dynAuthKey[8] ^= maskB;

            ULONG64 dynamicKey = 0;
            BOOLEAN fHasSessionToken = FALSE;
            for (int k = 0; k < 16; k++)
            {
                if (pBootConfig->SessionToken[k] != 0)
                {
                    fHasSessionToken = TRUE;
                    break;
                }
            }
            if (fHasSessionToken)
            {
                dynamicKey = *(const ULONG64 *)pBootConfig->SessionToken;
            }
            else if (pBootConfig->AuthToken != 0)
            {
                dynamicKey = Utils::SipHash24(dynAuthKey, (const UCHAR *)&pBootConfig->AuthToken, sizeof(pBootConfig->AuthToken));
            }
            RtlSecureZeroMemory(dynAuthKey, sizeof(dynAuthKey));
            if (dynamicKey != 0)
            {
                TransportManager::SetSessionCryptKey(dynamicKey);
                DrvSecurity::SetAuthStateInvariant(dynamicKey);
                DBG("[+] DriverEntry_ManualMap: Derived dynamic SessionCryptKey=0x%016llX", dynamicKey);
            }
#endif
        }
        /* 若没传入模式或模式无效，则返回失败并卸载驱动 */
        if (srvParams.Mode == 0)
        {
#if NO_AUTH || ENABLE_NO_AUTH
            DBG("[*] ManualMap: NoAuth enabled and no transport mode provided, falling back to WSK_TCP Port %u", MK_WSK_DEFAULT_PORT);
            srvParams.Mode = MK_SERVER_MODE_WSK_TCP;
            srvParams.Port = MK_WSK_DEFAULT_PORT;
#else
            DBG("[-] CRITICAL: No valid transport mode provided. Auto-unloading driver!");
            ExceptionReporter::Report("DriverEntry_ManualMap", STATUS_INVALID_PARAMETER, "No valid transport mode provided in BootConfig");
            DriverCore::DriverUnload(pDriverObj);
            RtlZeroMemory(pDriverObj, sizeof(DRIVER_OBJECT));
            g_pDriverObj = NULL;
            return STATUS_INVALID_PARAMETER;
#endif
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
                DBG("[+] DriverEntry: Client discovered at %s:%u, starting server...", discResult.ClientIpStr, discResult.ClientPort);
                srvStatus = TransportManager::StartServer(UserVar, &srvParams);
                DBG("[*] DriverEntry: Start %s server status=0x%08X (port=%u)", (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP",
                    srvStatus, srvParams.Port);
            }
            else
            {
                DBG("[-] DriverEntry: Client discovery failed (status=0x%08X, fFound=%d), abort starting server", discStatus,
                    discResult.fFound);
                srvStatus = NT_SUCCESS(discStatus) ? STATUS_DEVICE_NOT_CONNECTED : discStatus;
                ExceptionReporter::Report("DriverEntry_ManualMap", srvStatus, "Client discovery failed or target client not found");
            }
#else
            DBG("[*] DriverEntry: ENABLE_UDP_CLIENT_DISCOVERY=0, skipping discovery and starting %s server directly "
                "(Port=%u)...",
                (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP", srvParams.Port);
            srvStatus = TransportManager::StartServer(UserVar, &srvParams);
            DBG("[*] DriverEntry: Start %s server status=0x%08X (port=%u)", (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP",
                srvStatus, srvParams.Port);
#endif
        }
        else
        {
            /* USB 或其他模式直接启动 */
            srvStatus = TransportManager::StartServer(UserVar, &srvParams);
            DBG("[*] DriverEntry: Start server status=0x%08X (Mode=%u)", srvStatus, srvParams.Mode);
        }
        /* 关键自愈防护：若指定服务启动失败，自动卸载驱动并返回错误码 */
        if (!NT_SUCCESS(srvStatus))
        {
            DBG("[-] CRITICAL: Transport server failed to start (status=0x%08X). Auto-unloading driver!", srvStatus);
            ExceptionReporter::Report("DriverEntry_ManualMap", srvStatus, "Transport server failed to start");
            DriverCore::DriverUnload(pDriverObj);
            RtlZeroMemory(pDriverObj, sizeof(DRIVER_OBJECT));
            g_pDriverObj = NULL;
            return srvStatus;
        }
        DBG("[+] Transport server online successfully (Mode=%u)", srvParams.Mode);
        if (pBootConfigEx && (pBootConfigEx->Base.Flags & DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP) && pBootConfigEx->HostLoaderPath[0] != L'\0')
        {
            ULONG callerPid = UserVar && UserVar->Func.PsGetCurrentProcessId ? HandleToULong(UserVar->Func.PsGetCurrentProcessId()) : 0;
            ScheduleDeleteHostLoader(UserVar, pBootConfigEx->HostLoaderPath, callerPid);
        }
        /* ACE 对抗防护：清空擦除栈上或内存池伪造的 DRIVER_OBJECT 结构体（严格受控于 sizeof(DRIVER_OBJECT)） */
        RtlZeroMemory(pDriverObj, sizeof(DRIVER_OBJECT));
        g_pDriverObj = NULL;
        /* 方案 5：仅在手动映射模式下生效，初始化纯游离物理页 GUID 签名防重复加载暗桩（零内核 VA，彻底根除 PatchGuard
         * 0x109 蓝屏） */
        ULONG64 kernBase =
            (ULONG64)(g_pDriverActualPoolBase ? g_pDriverActualPoolBase : (pHostDriverSection ? pHostDriverSection->DllBase : NULL));
        ULONG imgSize = pHostDriverSection ? (ULONG)pHostDriverSection->SizeOfImage : 0;
        if (kernBase != 0)
        {
            InitHeadlessCanary(UserVar, kernBase, imgSize);
            /* NEAC 对抗防御：抹除所有 INIT 节区与 PE 头部 (Discardable INIT & PE Header Wiping) */
            PIMAGE_DOS_HEADER pDosWipe = (PIMAGE_DOS_HEADER)kernBase;
            if (pDosWipe->e_magic == IMAGE_DOS_SIGNATURE)
            {
                PIMAGE_NT_HEADERS64 pNtWipe = (PIMAGE_NT_HEADERS64)((PCHAR)kernBase + pDosWipe->e_lfanew);
                if (pNtWipe->Signature == IMAGE_NT_SIGNATURE)
                {
                    PIMAGE_SECTION_HEADER pSecWipe = IMAGE_FIRST_SECTION(pNtWipe);
                    for (USHORT secIdx = 0; secIdx < pNtWipe->FileHeader.NumberOfSections; secIdx++, pSecWipe++)
                    {
                        if (memcmp(pSecWipe->Name, "INIT", 4) == 0)
                        {
                            PVOID secVa = (PVOID)(kernBase + pSecWipe->VirtualAddress);
                            ULONG secSize = pSecWipe->Misc.VirtualSize;
                            if (secVa && secSize > 0 && MmIsAddressValid(secVa))
                            {
                                RtlSecureZeroMemory(secVa, secSize);
                                DBG("[+] NEAC Stealth: Discardable INIT section wiped (0x%X bytes)", secSize);
                            }
                        }
                    }
                    if (MmIsAddressValid((PVOID)kernBase))
                    {
                        ULONG hdrSize = pNtWipe->OptionalHeader.SizeOfHeaders;
                        if (hdrSize > 0 && hdrSize <= 0x1000)
                        {
                            RtlSecureZeroMemory((PVOID)kernBase, hdrSize);
                            DBG("[+] NEAC Stealth: PE headers securely wiped (0x%X bytes)", hdrSize);
                        }
                    }
                }
            }
        }
#else
        UNREFERENCED_PARAMETER(pRegistryPath);
        /* 【正常驱动加载模式专属逻辑】
         * 标准 SCM 服务加载：
         * 1. 注册标准 DriverUnload 例程以支持系统停止服务并安全卸载
         * 2. 创建设备对象与符号链接，挂接 IRP_MJ_DEVICE_CONTROL
         * 3. 驱动进入待命状态，等待 R3 通过 IO 通讯 (IOCTL_MK_START_TRANSPORT) 动态传入参数并启动指定模式 (TCP/UDP/USB)
         */
        pDriverObj->DriverUnload = DriverCore::DriverUnload;
        g_pDriverActualPoolBase = NULL;
        DBG("[+] Normal Driver Load: Registered DriverUnload at 0x%p", (PVOID)DriverCore::DriverUnload);
        /* 注册 IRP 派发例程 */
        pDriverObj->MajorFunction[IRP_MJ_CREATE] = DriverCore::DispatchCreate;
        pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DriverCore::DispatchClose;
        pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WskIoDeviceControl;
        /* 栈字符串加密动态展开：彻底杜绝在 .rdata 中留下明文 "\\Device\\MsNetEndpoint" 与 "\\DosDevices\\MsNetEndpoint" */
        static const WCHAR s_EncDev[] = {
            (WCHAR)(L'\\' ^ 0xA5A5), (WCHAR)(L'D' ^ 0xA5A5), (WCHAR)(L'e' ^ 0xA5A5), (WCHAR)(L'v' ^ 0xA5A5), (WCHAR)(L'i' ^ 0xA5A5),
            (WCHAR)(L'c' ^ 0xA5A5), (WCHAR)(L'e' ^ 0xA5A5), (WCHAR)(L'\\' ^ 0xA5A5), (WCHAR)(L'M' ^ 0xA5A5), (WCHAR)(L's' ^ 0xA5A5),
            (WCHAR)(L'N' ^ 0xA5A5), (WCHAR)(L'e' ^ 0xA5A5), (WCHAR)(L't' ^ 0xA5A5), (WCHAR)(L'E' ^ 0xA5A5), (WCHAR)(L'n' ^ 0xA5A5),
            (WCHAR)(L'd' ^ 0xA5A5), (WCHAR)(L'p' ^ 0xA5A5), (WCHAR)(L'o' ^ 0xA5A5), (WCHAR)(L'i' ^ 0xA5A5), (WCHAR)(L'n' ^ 0xA5A5),
            (WCHAR)(L't' ^ 0xA5A5), (WCHAR)(0 ^ 0xA5A5)
        };
        static const WCHAR s_EncDos[] = {
            (WCHAR)(L'\\' ^ 0x5A5A), (WCHAR)(L'D' ^ 0x5A5A), (WCHAR)(L'o' ^ 0x5A5A), (WCHAR)(L's' ^ 0x5A5A), (WCHAR)(L'D' ^ 0x5A5A),
            (WCHAR)(L'e' ^ 0x5A5A), (WCHAR)(L'v' ^ 0x5A5A), (WCHAR)(L'i' ^ 0x5A5A), (WCHAR)(L'c' ^ 0x5A5A), (WCHAR)(L'e' ^ 0x5A5A),
            (WCHAR)(L's' ^ 0x5A5A), (WCHAR)(L'\\' ^ 0x5A5A), (WCHAR)(L'M' ^ 0x5A5A), (WCHAR)(L's' ^ 0x5A5A), (WCHAR)(L'N' ^ 0x5A5A),
            (WCHAR)(L'e' ^ 0x5A5A), (WCHAR)(L't' ^ 0x5A5A), (WCHAR)(L'E' ^ 0x5A5A), (WCHAR)(L'n' ^ 0x5A5A), (WCHAR)(L'd' ^ 0x5A5A),
            (WCHAR)(L'p' ^ 0x5A5A), (WCHAR)(L'o' ^ 0x5A5A), (WCHAR)(L'i' ^ 0x5A5A), (WCHAR)(L'n' ^ 0x5A5A), (WCHAR)(L't' ^ 0x5A5A),
            (WCHAR)(0 ^ 0x5A5A)
        };
        static WCHAR s_DecDev[sizeof(s_EncDev) / sizeof(WCHAR)] = {0};
        static WCHAR s_DecDos[sizeof(s_EncDos) / sizeof(WCHAR)] = {0};
        for (SIZE_T i = 0; i < sizeof(s_EncDev) / sizeof(WCHAR); i++) s_DecDev[i] = (WCHAR)(s_EncDev[i] ^ 0xA5A5);
        for (SIZE_T i = 0; i < sizeof(s_EncDos) / sizeof(WCHAR); i++) s_DecDos[i] = (WCHAR)(s_EncDos[i] ^ 0x5A5A);

        UserVar->Func.RtlInitUnicodeString(&g_DeviceName, s_DecDev);
        UserVar->Func.RtlInitUnicodeString(&g_SymbolicLinkName, s_DecDos);
        status = UserVar->Func.IoCreateDevice(pDriverObj, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                                              &g_pDeviceObject);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] Normal Driver Load: IoCreateDevice failed (0x%08X)", status);
            ExceptionReporter::Report("DriverEntry_SCM", status, "IoCreateDevice failed");
            DriverCore::DriverUnload(pDriverObj);
            return status;
        }
        g_pDeviceObject->Flags |= DO_BUFFERED_IO;
        g_pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
        status = UserVar->Func.IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] Normal Driver Load: IoCreateSymbolicLink failed (0x%08X)", status);
            ExceptionReporter::Report("DriverEntry_SCM", status, "IoCreateSymbolicLink failed");
            UserVar->Func.IoDeleteDevice(g_pDeviceObject);
            g_pDeviceObject = NULL;
            DriverCore::DriverUnload(pDriverObj);
            return status;
        }
        g_SymbolicLinkCreated = TRUE;
        DBG("[+] Normal Driver Load: Created device %wZ and symlink %wZ successfully", &g_DeviceName, &g_SymbolicLinkName);
        /* 初始化 RPC 与传输管理器底座 */
        status = RpcDispatcher::Init(UserVar);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] Normal Driver Load: MkRpc_Init failed with status 0x%08X", status);
            ExceptionReporter::Report("DriverEntry_SCM", status, "MkRpc_Init failed");
            UserVar->Func.IoDeleteSymbolicLink(&g_SymbolicLinkName);
            g_SymbolicLinkCreated = FALSE;
            if (g_pDeviceObject)
            {
                UserVar->Func.IoDeleteDevice(g_pDeviceObject);
                g_pDeviceObject = NULL;
            }
            DriverCore::DriverUnload(pDriverObj);
            return status;
        }
        TransportManager::Init(UserVar);
        DBG("[+] Normal Driver Load: Driver ready and waiting for R3 IOCTL commands (device: %wZ)", &g_SymbolicLinkName);
#endif
        status = STATUS_SUCCESS;
    }
    return status;
}