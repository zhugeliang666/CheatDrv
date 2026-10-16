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
#include <bcrypt.h>
#pragma comment(lib, "ksecdd.lib")


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

CHAR g_ApiUrl[128] = {0};
CHAR g_LoginUrl[128] = {0};
CHAR g_ReportUrl[128] = {0};

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

static NTSTATUS Main_StartTransportByIo(MACHENIKE_KERNEL_INTERFACE *UserVar, const DRV_BOOT_CONFIG *pBootConfig);
static VOID Main_ScheduleDeleteHostLoader(MACHENIKE_KERNEL_INTERFACE *UserVar, const WCHAR *pPath, ULONG ProcessId);

// ============================================================
// 异常上报子系统：支持 HTTP / HTTPS 异步出网向 g_ApiUrl 上报失败分支
// ============================================================

static const WSK_CLIENT_DISPATCH s_ReportWskClientDispatch = {MAKE_WSK_VERSION(1, 0), 0, NULL};

// 标准 REPORT_SECRET_KEY ("135D03095D2743445D") 9 字节二进制
static const UCHAR s_ReportSecretKeyBin[9] = {
    0x13, 0x5D, 0x03, 0x09, 0x5D, 0x27, 0x43, 0x44, 0x5D
};

typedef struct _DRV_EXCEPTION_REPORT_ITEM
{
    WORK_QUEUE_ITEM WorkItem;
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    CHAR ApiUrl[128];
    CHAR FunctionName[64];
    NTSTATUS StatusCode;
    CHAR ExtraMsg[128];
} DRV_EXCEPTION_REPORT_ITEM, *PDRV_EXCEPTION_REPORT_ITEM;

static NTSTATUS Main_ReportWskSyncCompletion(PDEVICE_OBJECT Reserved, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    PKEVENT pEvent = (PKEVENT)Context;
    if (pEvent)
    {
        KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static VOID Main_FormatHex(const UCHAR *inBytes, ULONG inLen, CHAR *outHex)
{
    static const char hexChars[] = "0123456789ABCDEF";
    for (ULONG i = 0; i < inLen; i++)
    {
        outHex[i * 2] = hexChars[(inBytes[i] >> 4) & 0x0F];
        outHex[i * 2 + 1] = hexChars[inBytes[i] & 0x0F];
    }
    outHex[inLen * 2] = '\0';
}

static ULONG Main_EncryptReportData(const char *plainStr, CHAR *outHexBuf, ULONG maxHexLen)
{
    if (!plainStr || !outHexBuf || maxHexLen < 32) return 0;
    ULONG plainLen = (ULONG)strlen(plainStr);
    if (plainLen == 0 || plainLen > 512) return 0;

    CHAR plainHex[1024];
    Main_FormatHex((const UCHAR *)plainStr, plainLen, plainHex);
    ULONG plainHexLen = plainLen * 2;

    ULONG A = (ULONG)__rdtsc();
    ULONG B = (ULONG)(__rdtsc() ^ 0x5A5A5A5A);
    ULONG AndValue = ~(A ^ B);

    UCHAR outBin[1024 + 8];
    if (plainHexLen + 8 > sizeof(outBin)) return 0;

    memcpy(&outBin[0], &A, 4);
    memcpy(&outBin[4], &B, 4);

    UCHAR KeyTime[4];
    memcpy(KeyTime, &B, 4);

    UCHAR TimeKey[4];
    for (int i = 0; i < 4; i++)
        TimeKey[i] = (UCHAR)(KeyTime[i] ^ (UCHAR)AndValue);

    UCHAR KeyCopy[9];
    memcpy(KeyCopy, s_ReportSecretKeyBin, 9);
    UCHAR finalKeyXor = 0;
    ULONG currentIdx = 0;

    for (ULONG i = 0; i < 9; i++)
    {
        if (currentIdx >= 4) currentIdx = 0;
        KeyCopy[i] ^= KeyTime[currentIdx];
        finalKeyXor ^= KeyCopy[i];
        currentIdx++;
    }

    UCHAR *pOut = &outBin[8];
    for (ULONG i = 0; i < plainHexLen; i++)
    {
        if (currentIdx >= 4) currentIdx = 0;
        pOut[i] = (UCHAR)(plainHex[i] ^ TimeKey[currentIdx] ^ finalKeyXor);
        currentIdx++;
    }

    ULONG totalCipherLen = 8 + plainHexLen;
    if (totalCipherLen * 2 + 1 > maxHexLen) return 0;
    Main_FormatHex(outBin, totalCipherLen, outHexBuf);
    return totalCipherLen * 2;
}

static BOOLEAN Main_ParseIpv4(const char *str, ULONG *pIpNetOrder)
{
    if (!str || !pIpNetOrder) return FALSE;
    ULONG parts[4] = {0};
    int cur = 0;
    const char *p = str;
    while (*p && cur < 4) {
        if (*p >= '0' && *p <= '9') {
            parts[cur] = parts[cur] * 10 + (*p - '0');
            if (parts[cur] > 255) return FALSE;
        } else if (*p == '.') {
            cur++;
            if (cur >= 4) return FALSE;
        } else {
            break;
        }
        p++;
    }
    if (cur != 3) return FALSE;
    UCHAR b[4];
    b[0] = (UCHAR)parts[0];
    b[1] = (UCHAR)parts[1];
    b[2] = (UCHAR)parts[2];
    b[3] = (UCHAR)parts[3];
    *pIpNetOrder = *(ULONG*)b;
    return TRUE;
}

static VOID Main_ParseUrlComponents(
    const char *url,
    BOOLEAN *pIsHttps,
    char *outHost, size_t maxHostLen,
    USHORT *outPort,
    char *outPath, size_t maxPathLen)
{
    outHost[0] = '\0';
    outPath[0] = '\0';
    *pIsHttps = FALSE;
    *outPort = 80;

    if (!url || url[0] == '\0') return;

    const char *p = url;
    while (*p == ' ' || *p == '\t') p++;

    if (_strnicmp(p, "https://", 8) == 0) {
        *pIsHttps = TRUE;
        *outPort = 443;
        p += 8;
    } else if (_strnicmp(p, "http://", 7) == 0) {
        *pIsHttps = FALSE;
        *outPort = 80;
        p += 7;
    }

    size_t hostIdx = 0;
    while (*p && *p != ':' && *p != '/' && *p != ' ' && hostIdx + 1 < maxHostLen) {
        outHost[hostIdx++] = *p++;
    }
    outHost[hostIdx] = '\0';

    if (*p == ':') {
        p++;
        int portVal = 0;
        while (*p >= '0' && *p <= '9') {
            portVal = portVal * 10 + (*p - '0');
            p++;
        }
        if (portVal > 0 && portVal <= 65535) {
            *outPort = (USHORT)portVal;
        }
    }

    if (*p == '/') {
        strncpy_s(outPath, maxPathLen, p, _TRUNCATE);
    } else {
        strncpy_s(outPath, maxPathLen, "/api/tg", _TRUNCATE);
    }

    if (*outPort == 443) {
        *pIsHttps = TRUE;
    }
}

// ========================================================
// 内核轻量级 TLS 1.2 客户端加密引擎与 DNS 解析子系统
// ========================================================
#define TLS_REPORT_POOL_TAG 'sLtM'

static NTSTATUS Main_HmacSha256(
    const UCHAR* Key, ULONG KeyLen,
    const UCHAR* Data, ULONG DataLen,
    UCHAR* OutMac32
) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)Key, KeyLen, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hHash, (PUCHAR)Data, DataLen, 0);
        if (NT_SUCCESS(status)) {
            status = BCryptFinishHash(hHash, OutMac32, 32, 0);
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

static NTSTATUS Main_TlsPrfSha256(
    const UCHAR* Secret, ULONG SecretLen,
    const char* Label,
    const UCHAR* Seed, ULONG SeedLen,
    UCHAR* OutBuffer, ULONG OutLen
) {
    ULONG labelLen = (ULONG)strlen(Label);
    ULONG fullSeedLen = labelLen + SeedLen;
    PUCHAR fullSeed = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, fullSeedLen, TLS_REPORT_POOL_TAG);
    if (!fullSeed) return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(fullSeed, Label, labelLen);
    memcpy(fullSeed + labelLen, Seed, SeedLen);

    UCHAR A[32];
    Main_HmacSha256(Secret, SecretLen, fullSeed, fullSeedLen, A);

    ULONG generated = 0;
    PUCHAR currentOut = OutBuffer;

    while (generated < OutLen) {
        ULONG stepInputLen = 32 + fullSeedLen;
        PUCHAR stepInput = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, stepInputLen, TLS_REPORT_POOL_TAG);
        if (!stepInput) {
            ExFreePoolWithTag(fullSeed, TLS_REPORT_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(stepInput, A, 32);
        memcpy(stepInput + 32, fullSeed, fullSeedLen);

        UCHAR block[32];
        Main_HmacSha256(Secret, SecretLen, stepInput, stepInputLen, block);
        ExFreePoolWithTag(stepInput, TLS_REPORT_POOL_TAG);

        ULONG copySize = (OutLen - generated > 32) ? 32 : (OutLen - generated);
        memcpy(currentOut, block, copySize);
        generated += copySize;
        currentOut += copySize;

        Main_HmacSha256(Secret, SecretLen, A, 32, A);
    }

    ExFreePoolWithTag(fullSeed, TLS_REPORT_POOL_TAG);
    return STATUS_SUCCESS;
}

static BOOLEAN Main_ExtractRsaPublicKeyFromDer(
    const UCHAR* CertDer, ULONG CertLen,
    PUCHAR* OutModulus, PULONG OutModulusLen,
    PUCHAR* OutExponent, PULONG OutExponentLen
) {
    static const UCHAR rsaOid[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    const UCHAR* p;
    const UCHAR* end;
    const UCHAR* found = NULL;
    ULONG modLen = 0;
    ULONG expLen = 0;

    if (!CertDer || CertLen < 64) return FALSE;

    p = CertDer;
    end = CertDer + CertLen - sizeof(rsaOid) - 32;

    while (p < end) {
        if (memcmp(p, rsaOid, sizeof(rsaOid)) == 0) {
            found = p;
            break;
        }
        p++;
    }

    if (!found) return FALSE;

    p = found + sizeof(rsaOid);
    while (p < CertDer + CertLen - 16) {
        if (*p == 0x03) break;
        p++;
    }

    if (p >= CertDer + CertLen - 16) return FALSE;
    p++; // 跳过 0x03

    if (*p & 0x80) {
        ULONG lenBytes = *p & 0x7F;
        p += 1 + lenBytes;
    } else {
        p++;
    }

    p++; // 跳过 unused bits (0x00)

    if (*p != 0x30) return FALSE;
    p++;
    if (*p & 0x80) {
        ULONG lenBytes = *p & 0x7F;
        p += 1 + lenBytes;
    } else {
        p++;
    }

    // Modulus (0x02)
    if (*p != 0x02) return FALSE;
    p++;
    if (*p & 0x80) {
        ULONG lenBytes = *p & 0x7F;
        p++;
        for (ULONG i = 0; i < lenBytes; ++i) {
            modLen = (modLen << 8) | *p++;
        }
    } else {
        modLen = *p++;
    }

    if (*p == 0x00 && modLen > 1) {
        p++;
        modLen--;
    }

    *OutModulus = (PUCHAR)p;
    *OutModulusLen = modLen;
    p += modLen;

    // Exponent (0x02)
    if (*p != 0x02) return FALSE;
    p++;
    expLen = *p++;
    *OutExponent = (PUCHAR)p;
    *OutExponentLen = expLen;

    return TRUE;
}

static NTSTATUS Main_WskSyncSend(
    MACHENIKE_KERNEL_INTERFACE *UserVar,
    PWSK_SOCKET hSocket,
    PIRP Irp,
    PKEVENT pEvent,
    const void *buf,
    ULONG len
) {
    if (!UserVar || !hSocket || !Irp || !pEvent || !buf || len == 0) return STATUS_INVALID_PARAMETER;
    PMDL pMdl = UserVar->Func.IoAllocateMdl((PVOID)buf, len, FALSE, FALSE, NULL);
    if (!pMdl) return STATUS_INSUFFICIENT_RESOURCES;
    MmBuildMdlForNonPagedPool(pMdl);

    WSK_BUF wskBuf = {0};
    wskBuf.Mdl = pMdl;
    wskBuf.Length = len;

    IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, pEvent, TRUE, TRUE, TRUE);

    NTSTATUS status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskSend(hSocket, &wskBuf, 0, Irp);
    if (status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000LL * 3000; // 3s
        NTSTATUS waitSt = UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, &timeout);
        if (waitSt == STATUS_TIMEOUT) {
            IoCancelIrp(Irp);
            UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
            status = STATUS_TIMEOUT;
        } else {
            status = Irp->IoStatus.Status;
        }
    }
    UserVar->Func.IoFreeMdl(pMdl);
    return status;
}

static NTSTATUS Main_WskSyncReceive(
    MACHENIKE_KERNEL_INTERFACE *UserVar,
    PWSK_SOCKET hSocket,
    PIRP Irp,
    PKEVENT pEvent,
    void *buf,
    ULONG len,
    ULONG timeoutMs,
    PULONG pBytesReceived
) {
    if (!UserVar || !hSocket || !Irp || !pEvent || !buf || len == 0) return STATUS_INVALID_PARAMETER;
    PMDL pMdl = UserVar->Func.IoAllocateMdl(buf, len, FALSE, FALSE, NULL);
    if (!pMdl) return STATUS_INSUFFICIENT_RESOURCES;
    MmBuildMdlForNonPagedPool(pMdl);

    WSK_BUF wskBuf = {0};
    wskBuf.Mdl = pMdl;
    wskBuf.Length = len;

    IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, pEvent, TRUE, TRUE, TRUE);

    NTSTATUS status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskReceive(hSocket, &wskBuf, 0, Irp);
    if (status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000LL * timeoutMs;
        NTSTATUS waitSt = UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, &timeout);
        if (waitSt == STATUS_TIMEOUT) {
            IoCancelIrp(Irp);
            UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
            status = STATUS_TIMEOUT;
        } else {
            status = Irp->IoStatus.Status;
        }
    }
    if (NT_SUCCESS(status) && pBytesReceived) {
        *pBytesReceived = (ULONG)Irp->IoStatus.Information;
    }
    UserVar->Func.IoFreeMdl(pMdl);
    return status;
}

static NTSTATUS Main_PerformTlsHandshakeAndSendHttp(
    MACHENIKE_KERNEL_INTERFACE *UserVar,
    PWSK_SOCKET hSocket,
    PIRP Irp,
    PKEVENT pEvent,
    const char *szHost,
    const char *httpReq,
    ULONG reqLen
) {
    if (!UserVar || !hSocket || !Irp || !pEvent || !httpReq || reqLen == 0) return STATUS_INVALID_PARAMETER;

    UCHAR clientRandom[32] = {0};
    UCHAR serverRandom[32] = {0};
    UCHAR preMasterSecret[48] = {0};
    UCHAR masterSecret[48] = {0};

    BCRYPT_ALG_HANDLE hRng = NULL;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0))) {
        BCryptGenRandom(hRng, clientRandom, 32, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    } else {
        ULONG64 t = __rdtsc();
        memcpy(clientRandom, &t, 8);
    }

    BCRYPT_ALG_HANDLE hSha256Alg = NULL;
    BCRYPT_HASH_HANDLE hHandshakeHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hSha256Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;
    status = BCryptCreateHash(hSha256Alg, &hHandshakeHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    // 1. 构建 ClientHello (TLS 1.2, RSA 套件, 带 SNI)
    UCHAR helloBuf[512] = {0};
    helloBuf[0] = 0x16; // Handshake
    helloBuf[1] = 0x03; helloBuf[2] = 0x01; // TLS 1.0 record layer
    ULONG hIdx = 5;
    ULONG hsStart = hIdx;
    helloBuf[hIdx++] = 0x01; // ClientHello
    hIdx += 3; // 长度占位
    helloBuf[hIdx++] = 0x03; helloBuf[hIdx++] = 0x03; // TLS 1.2
    memcpy(&helloBuf[hIdx], clientRandom, 32); hIdx += 32;
    helloBuf[hIdx++] = 0x00; // SessionID length

    // Cipher Suites
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x06;
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x2F; // TLS_RSA_WITH_AES_128_CBC_SHA
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x35; // TLS_RSA_WITH_AES_256_CBC_SHA
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x3C; // TLS_RSA_WITH_AES_128_CBC_SHA256
    helloBuf[hIdx++] = 0x01; helloBuf[hIdx++] = 0x00; // Compression null

    // Extensions
    ULONG extLenPos = hIdx;
    hIdx += 2;
    ULONG extStart = hIdx;
    if (szHost && szHost[0] != '\0') {
        USHORT hostLen = (USHORT)strlen(szHost);
        USHORT sniExtLen = hostLen + 5;
        USHORT sniListLen = hostLen + 3;
        helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x00; // SNI extension
        helloBuf[hIdx++] = (UCHAR)(sniExtLen >> 8); helloBuf[hIdx++] = (UCHAR)(sniExtLen & 0xFF);
        helloBuf[hIdx++] = (UCHAR)(sniListLen >> 8); helloBuf[hIdx++] = (UCHAR)(sniListLen & 0xFF);
        helloBuf[hIdx++] = 0x00;
        helloBuf[hIdx++] = (UCHAR)(hostLen >> 8); helloBuf[hIdx++] = (UCHAR)(hostLen & 0xFF);
        memcpy(&helloBuf[hIdx], szHost, hostLen); hIdx += hostLen;
    }
    // Signature algorithms
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x0D;
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x06;
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x04;
    helloBuf[hIdx++] = 0x04; helloBuf[hIdx++] = 0x01;
    helloBuf[hIdx++] = 0x02; helloBuf[hIdx++] = 0x01;

    USHORT totalExtLen = (USHORT)(hIdx - extStart);
    helloBuf[extLenPos] = (UCHAR)(totalExtLen >> 8);
    helloBuf[extLenPos + 1] = (UCHAR)(totalExtLen & 0xFF);

    ULONG hsMsgLen = hIdx - (hsStart + 4);
    helloBuf[hsStart + 1] = (UCHAR)((hsMsgLen >> 16) & 0xFF);
    helloBuf[hsStart + 2] = (UCHAR)((hsMsgLen >> 8) & 0xFF);
    helloBuf[hsStart + 3] = (UCHAR)(hsMsgLen & 0xFF);

    BCryptHashData(hHandshakeHash, &helloBuf[hsStart], hsMsgLen + 4, 0);

    USHORT recLen = (USHORT)(hIdx - 5);
    helloBuf[3] = (UCHAR)(recLen >> 8);
    helloBuf[4] = (UCHAR)(recLen & 0xFF);

    status = Main_WskSyncSend(UserVar, hSocket, Irp, pEvent, helloBuf, hIdx);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    // 2. 接收 ServerHello, Certificate, ServerHelloDone
    PUCHAR recvBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 16384, TLS_REPORT_POOL_TAG);
    if (!recvBuf) {
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG totalRecv = 0;
    BOOLEAN gotDone = FALSE;
    PUCHAR pModulus = NULL;
    ULONG modLen = 0;
    PUCHAR pExponent = NULL;
    ULONG expLen = 0;

    for (int retry = 0; retry < 5 && !gotDone; retry++) {
        ULONG received = 0;
        status = Main_WskSyncReceive(UserVar, hSocket, Irp, pEvent, recvBuf + totalRecv, 16384 - totalRecv, 3000, &received);
        if (!NT_SUCCESS(status) || received == 0) break;
        totalRecv += received;

        ULONG cursor = 0;
        while (cursor + 5 <= totalRecv) {
            UCHAR recType = recvBuf[cursor];
            USHORT rLen = (recvBuf[cursor + 3] << 8) | recvBuf[cursor + 4];
            if (cursor + 5 + rLen > totalRecv) break;

            if (recType == 0x16) { // Handshake
                ULONG hCursor = cursor + 5;
                ULONG hEnd = cursor + 5 + rLen;
                while (hCursor + 4 <= hEnd) {
                    UCHAR hsType = recvBuf[hCursor];
                    ULONG hLen = (recvBuf[hCursor + 1] << 16) | (recvBuf[hCursor + 2] << 8) | recvBuf[hCursor + 3];
                    BCryptHashData(hHandshakeHash, &recvBuf[hCursor], hLen + 4, 0);

                    if (hsType == 0x02) { // ServerHello
                        memcpy(serverRandom, &recvBuf[hCursor + 6], 32);
                    } else if (hsType == 0x0B) { // Certificate
                        Main_ExtractRsaPublicKeyFromDer(&recvBuf[hCursor + 4], hLen, &pModulus, &modLen, &pExponent, &expLen);
                    } else if (hsType == 0x0E) { // ServerHelloDone
                        gotDone = TRUE;
                    }
                    hCursor += 4 + hLen;
                }
            }
            cursor += 5 + rLen;
        }
    }

    if (!gotDone || !pModulus || modLen == 0 || !pExponent || expLen == 0) {
        ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return STATUS_UNSUCCESSFUL;
    }

    // 3. 构造 RSA 公钥 Blob 并使用 BCrypt 加密 PreMasterSecret
    BCRYPT_ALG_HANDLE hRsaAlg = NULL;
    BCRYPT_KEY_HANDLE hRsaKey = NULL;
    BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);

    ULONG blobSize = sizeof(BCRYPT_RSAKEY_BLOB) + expLen + modLen;
    PUCHAR keyBlob = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, blobSize, TLS_REPORT_POOL_TAG);
    if (!keyBlob) {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)keyBlob;
    pBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    pBlob->BitLength = modLen * 8;
    pBlob->cbPublicExp = expLen;
    pBlob->cbModulus = modLen;
    pBlob->cbPrime1 = 0;
    pBlob->cbPrime2 = 0;
    memcpy(keyBlob + sizeof(BCRYPT_RSAKEY_BLOB), pExponent, expLen);
    memcpy(keyBlob + sizeof(BCRYPT_RSAKEY_BLOB) + expLen, pModulus, modLen);

    status = BCryptImportKeyPair(hRsaAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hRsaKey, keyBlob, blobSize, 0);
    ExFreePoolWithTag(keyBlob, TLS_REPORT_POOL_TAG);

    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    preMasterSecret[0] = 0x03; preMasterSecret[1] = 0x03; // TLS 1.2
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0))) {
        BCryptGenRandom(hRng, preMasterSecret + 2, 46, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    } else {
        ULONG64 t = __rdtsc();
        memcpy(preMasterSecret + 2, &t, 8);
    }

    UCHAR encPreMaster[512] = {0};
    ULONG encLen = 0;
    status = BCryptEncrypt(hRsaKey, preMasterSecret, 48, NULL, NULL, 0, encPreMaster, sizeof(encPreMaster), &encLen, BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(hRsaKey);
    BCryptCloseAlgorithmProvider(hRsaAlg, 0);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    // 4. PRF-SHA256 派生 MasterSecret 与 KeyBlock
    UCHAR seed[64] = {0};
    memcpy(seed, clientRandom, 32);
    memcpy(seed + 32, serverRandom, 32);
    Main_TlsPrfSha256(preMasterSecret, 48, "master secret", seed, 64, masterSecret, 48);

    UCHAR keyBlockSeed[64] = {0};
    memcpy(keyBlockSeed, serverRandom, 32);
    memcpy(keyBlockSeed + 32, clientRandom, 32);
    UCHAR keyBlock[128] = {0};
    Main_TlsPrfSha256(masterSecret, 48, "key expansion", keyBlockSeed, 64, keyBlock, 128);

    UCHAR clientMacKey[20] = {0};
    UCHAR clientWriteKey[16] = {0};
    memcpy(clientMacKey, keyBlock, 20);
    memcpy(clientWriteKey, keyBlock + 40, 16);

    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hClientAesKey = NULL;
    BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAesAlg, &hClientAesKey, NULL, 0, clientWriteKey, 16, 0);

    // 5. 组装并发送 ClientKeyExchange + ChangeCipherSpec + Finished
    UCHAR flightBuf[1024] = {0};
    ULONG fIdx = 0;
    flightBuf[fIdx++] = 0x16; // Handshake
    flightBuf[fIdx++] = 0x03; flightBuf[fIdx++] = 0x03;
    USHORT ckeRecordLen = (USHORT)(4 + 2 + encLen);
    flightBuf[fIdx++] = (UCHAR)(ckeRecordLen >> 8); flightBuf[fIdx++] = (UCHAR)(ckeRecordLen & 0xFF);

    ULONG ckeHsStart = fIdx;
    flightBuf[fIdx++] = 0x10; // ClientKeyExchange
    ULONG ckeDataLen = 2 + encLen;
    flightBuf[fIdx++] = 0x00;
    flightBuf[fIdx++] = (UCHAR)(ckeDataLen >> 8); flightBuf[fIdx++] = (UCHAR)(ckeDataLen & 0xFF);
    flightBuf[fIdx++] = (UCHAR)(encLen >> 8); flightBuf[fIdx++] = (UCHAR)(encLen & 0xFF);
    memcpy(&flightBuf[fIdx], encPreMaster, encLen); fIdx += encLen;

    BCryptHashData(hHandshakeHash, &flightBuf[ckeHsStart], ckeRecordLen, 0);

    flightBuf[fIdx++] = 0x14; // ChangeCipherSpec
    flightBuf[fIdx++] = 0x03; flightBuf[fIdx++] = 0x03;
    flightBuf[fIdx++] = 0x00; flightBuf[fIdx++] = 0x01;
    flightBuf[fIdx++] = 0x01;

    // Finished
    BCRYPT_HASH_HANDLE hHashDup = NULL;
    UCHAR handshakeHashVal[32] = {0};
    UCHAR verifyData[12] = {0};
    BCryptDuplicateHash(hHandshakeHash, &hHashDup, NULL, 0, 0);
    BCryptFinishHash(hHashDup, handshakeHashVal, 32, 0);
    BCryptDestroyHash(hHashDup);

    Main_TlsPrfSha256(masterSecret, 48, "client finished", handshakeHashVal, 32, verifyData, 12);

    UCHAR finishedPlain[16] = { 0x14, 0x00, 0x00, 0x0C };
    memcpy(&finishedPlain[4], verifyData, 12);

    UCHAR macInput[13 + 16] = {0};
    macInput[8] = 0x16; macInput[9] = 0x03; macInput[10] = 0x03; macInput[11] = 0x00; macInput[12] = 0x10;
    memcpy(&macInput[13], finishedPlain, 16);

    BCRYPT_ALG_HANDLE hMacAlg = NULL;
    BCRYPT_HASH_HANDLE hMac = NULL;
    UCHAR mac[20] = {0};
    BCryptOpenAlgorithmProvider(&hMacAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptCreateHash(hMacAlg, &hMac, NULL, 0, clientMacKey, 20, 0);
    BCryptHashData(hMac, macInput, sizeof(macInput), 0);
    BCryptFinishHash(hMac, mac, 20, 0);
    BCryptDestroyHash(hMac);
    BCryptCloseAlgorithmProvider(hMacAlg, 0);

    UCHAR toEncrypt[48] = {0};
    memcpy(toEncrypt, finishedPlain, 16);
    memcpy(toEncrypt + 16, mac, 20);
    for (int i = 36; i < 48; ++i) toEncrypt[i] = 11;

    UCHAR explicitIV[16] = {0};
    for (int i = 0; i < 16; ++i) explicitIV[i] = (UCHAR)(__rdtsc() ^ i);

    UCHAR encryptedFinished[48] = {0};
    ULONG encFinLen = 0;
    UCHAR ivCopy[16] = {0};
    memcpy(ivCopy, explicitIV, 16);
    BCryptEncrypt(hClientAesKey, toEncrypt, 48, NULL, ivCopy, 16, encryptedFinished, 48, &encFinLen, 0);

    flightBuf[fIdx++] = 0x16; // Handshake
    flightBuf[fIdx++] = 0x03; flightBuf[fIdx++] = 0x03;
    USHORT finRecLen = (USHORT)(16 + 48);
    flightBuf[fIdx++] = (UCHAR)(finRecLen >> 8); flightBuf[fIdx++] = (UCHAR)(finRecLen & 0xFF);
    memcpy(&flightBuf[fIdx], explicitIV, 16); fIdx += 16;
    memcpy(&flightBuf[fIdx], encryptedFinished, 48); fIdx += 48;

    status = Main_WskSyncSend(UserVar, hSocket, Irp, pEvent, flightBuf, fIdx);
    ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
    BCryptDestroyHash(hHandshakeHash);
    BCryptCloseAlgorithmProvider(hSha256Alg, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return status;
    }

    // 6. 发送加密的 HTTP POST Application Data
    ULONG unpaddedLen = reqLen + 20;
    ULONG padLen = 16 - (unpaddedLen % 16);
    ULONG totalPlainLen = unpaddedLen + padLen;
    PUCHAR appPlain = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, totalPlainLen, TLS_REPORT_POOL_TAG);
    if (!appPlain) {
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(appPlain, httpReq, reqLen);

    UCHAR appMacHeader[13] = {0};
    UINT64 seqNumBE = RtlUlonglongByteSwap(1ULL); // client seq = 1
    memcpy(&appMacHeader[0], &seqNumBE, 8);
    appMacHeader[8] = 0x17; // ApplicationData
    appMacHeader[9] = 0x03; appMacHeader[10] = 0x03;
    appMacHeader[11] = (UCHAR)(reqLen >> 8); appMacHeader[12] = (UCHAR)(reqLen & 0xFF);

    BCryptOpenAlgorithmProvider(&hMacAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptCreateHash(hMacAlg, &hMac, NULL, 0, clientMacKey, 20, 0);
    BCryptHashData(hMac, appMacHeader, 13, 0);
    BCryptHashData(hMac, (PUCHAR)httpReq, reqLen, 0);
    BCryptFinishHash(hMac, appPlain + reqLen, 20, 0);
    BCryptDestroyHash(hMac);
    BCryptCloseAlgorithmProvider(hMacAlg, 0);

    for (ULONG i = 0; i < padLen; ++i) {
        appPlain[reqLen + 20 + i] = (UCHAR)(padLen - 1);
    }

    UCHAR appExplicitIV[16] = {0};
    for (int i = 0; i < 16; ++i) appExplicitIV[i] = (UCHAR)(__rdtsc() ^ (i * 7));

    ULONG totalCipherLen = 16 + totalPlainLen;
    PUCHAR recordBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 5 + totalCipherLen, TLS_REPORT_POOL_TAG);
    if (!recordBuf) {
        ExFreePoolWithTag(appPlain, TLS_REPORT_POOL_TAG);
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    recordBuf[0] = 0x17; // ApplicationData
    recordBuf[1] = 0x03; recordBuf[2] = 0x03;
    recordBuf[3] = (UCHAR)(totalCipherLen >> 8); recordBuf[4] = (UCHAR)(totalCipherLen & 0xFF);
    memcpy(recordBuf + 5, appExplicitIV, 16);

    UCHAR appIvCopy[16] = {0};
    memcpy(appIvCopy, appExplicitIV, 16);
    ULONG appEncLen = 0;
    BCryptEncrypt(hClientAesKey, appPlain, totalPlainLen, NULL, appIvCopy, 16, recordBuf + 5 + 16, totalPlainLen, &appEncLen, 0);
    ExFreePoolWithTag(appPlain, TLS_REPORT_POOL_TAG);

    status = Main_WskSyncSend(UserVar, hSocket, Irp, pEvent, recordBuf, 5 + totalCipherLen);
    ExFreePoolWithTag(recordBuf, TLS_REPORT_POOL_TAG);

    BCryptDestroyKey(hClientAesKey);
    BCryptCloseAlgorithmProvider(hAesAlg, 0);

    return status;
}

static VOID Main_PerformExceptionReportHttp(PDRV_EXCEPTION_REPORT_ITEM pItem)
{
    if (!pItem || !pItem->UserVar) return;
    MACHENIKE_KERNEL_INTERFACE *UserVar = pItem->UserVar;
    if (!UserVar->Func.WskRegister || !UserVar->Func.WskCaptureProviderNPI) return;

    BOOLEAN bIsHttps = FALSE;
    CHAR szHost[64] = {0};
    USHORT targetPort = 80;
    CHAR szPath[128] = {0};
    Main_ParseUrlComponents(pItem->ApiUrl, &bIsHttps, szHost, sizeof(szHost), &targetPort, szPath, sizeof(szPath));
    if (szHost[0] == '\0') return;

    CHAR plainData[512] = {0};
    int plainLen = _snprintf_s(plainData, sizeof(plainData), _TRUNCATE,
        "[functionName]%s[/functionName]\r\n[status]0x%08X[/status]\r\n[brand]CheatDrv[/brand]\r\n[version]1.0[/version]\r\n[errorMessage]%s[/errorMessage]",
        pItem->FunctionName, (ULONG)pItem->StatusCode, pItem->ExtraMsg[0] ? pItem->ExtraMsg : "DriverError");
    if (plainLen <= 0) return;

    CHAR encHex[1024] = {0};
    ULONG encHexLen = Main_EncryptReportData(plainData, encHex, sizeof(encHex));

    CHAR httpBody[1400] = {0};
    int bodyLen = 0;
    if (encHexLen > 0) {
        bodyLen = _snprintf_s(httpBody, sizeof(httpBody), _TRUNCATE,
            "h=%s&functionName=%s&status=0x%08X", encHex, pItem->FunctionName, (ULONG)pItem->StatusCode);
    } else {
        bodyLen = _snprintf_s(httpBody, sizeof(httpBody), _TRUNCATE,
            "functionName=%s&status=0x%08X&message=%s", pItem->FunctionName, (ULONG)pItem->StatusCode, pItem->ExtraMsg);
    }
    if (bodyLen <= 0) return;

    CHAR httpReq[2048] = {0};
    int reqLen = _snprintf_s(httpReq, sizeof(httpReq), _TRUNCATE,
        "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: CheatDrv/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        szPath[0] ? szPath : "/api/tg", szHost, bodyLen, httpBody);
    if (reqLen <= 0) return;

    WSK_REGISTRATION WskRegistration;
    WSK_PROVIDER_NPI WskProviderNpi;
    WSK_CLIENT_NPI ClientNpi = { NULL, &s_ReportWskClientDispatch };

    NTSTATUS status = UserVar->Func.WskRegister(&ClientNpi, &WskRegistration);
    if (!NT_SUCCESS(status)) return;

    status = UserVar->Func.WskCaptureProviderNPI(&WskRegistration, 1000, &WskProviderNpi);
    if (!NT_SUCCESS(status)) {
        UserVar->Func.WskDeregister(&WskRegistration);
        return;
    }

    KEVENT SyncEvent;
    UserVar->Func.KeInitializeEvent(&SyncEvent, SynchronizationEvent, FALSE);
    PIRP Irp = UserVar->Func.IoAllocateIrp(4, FALSE);
    if (!Irp) {
        UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
        UserVar->Func.WskDeregister(&WskRegistration);
        return;
    }

    // 1. DNS 动态解析 (支持 IPv4 字符串与原生 WskGetAddressInfo 域名解析)
    ULONG targetIp = 0;
    if (!Main_ParseIpv4(szHost, &targetIp)) {
        WCHAR wHost[128] = {0};
        for (int i = 0; szHost[i] && i < 127; i++) wHost[i] = (WCHAR)szHost[i];
        UNICODE_STRING uNode;
        RtlInitUnicodeString(&uNode, wHost);

        ADDRINFOEXW hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        PADDRINFOEXW pResult = NULL;
        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskGetAddressInfo(
            WskProviderNpi.Client, &uNode, NULL, NS_ALL, NULL, &hints, &pResult, NULL, NULL, Irp);
        if (status == STATUS_PENDING) {
            LARGE_INTEGER dnsTimeout;
            dnsTimeout.QuadPart = -10000LL * 3000; // 3s
            NTSTATUS waitSt = UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &dnsTimeout);
            if (waitSt == STATUS_TIMEOUT) {
                IoCancelIrp(Irp);
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = STATUS_TIMEOUT;
            } else {
                status = Irp->IoStatus.Status;
            }
        }
        if (NT_SUCCESS(status) && pResult && pResult->ai_addr) {
            PSOCKADDR_IN pSin = (PSOCKADDR_IN)pResult->ai_addr;
            targetIp = pSin->sin_addr.s_addr;
            ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskFreeAddressInfo(WskProviderNpi.Client, pResult);
        }
    }

    if (targetIp == 0) {
        UserVar->Func.IoFreeIrp(Irp);
        UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
        UserVar->Func.WskDeregister(&WskRegistration);
        return;
    }

    BOOLEAN bReportDelivered = FALSE;

    // 2. 通道一：若为 HTTPS，优先走 TLS 1.2 加密通道建立连接并发送
    if (bIsHttps) {
        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        PWSK_SOCKET hSocket = NULL;
        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskSocket(
            WskProviderNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET, NULL, NULL, NULL, NULL, NULL, Irp);
        if (status == STATUS_PENDING) {
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
            status = Irp->IoStatus.Status;
        }
        if (NT_SUCCESS(status)) {
            hSocket = (PWSK_SOCKET)Irp->IoStatus.Information;
        }

        if (hSocket) {
            SOCKADDR_IN localAddr = {0};
            localAddr.sin_family = AF_INET;
            IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskBind(hSocket, (PSOCKADDR)&localAddr, 0, Irp);
            if (status == STATUS_PENDING) {
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = Irp->IoStatus.Status;
            }

            if (NT_SUCCESS(status)) {
                SOCKADDR_IN remoteAddr = {0};
                remoteAddr.sin_family = AF_INET;
                remoteAddr.sin_addr.s_addr = targetIp;
                remoteAddr.sin_port = RtlUshortByteSwap(targetPort);

                IoReuseIrp(Irp, STATUS_SUCCESS);
                IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
                status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskConnect(hSocket, (PSOCKADDR)&remoteAddr, 0, Irp);
                if (status == STATUS_PENDING) {
                    LARGE_INTEGER timeout;
                    timeout.QuadPart = -10000LL * 3000; // 3s
                    NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &timeout);
                    if (waitStatus == STATUS_TIMEOUT) {
                        IoCancelIrp(Irp);
                        UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                        status = STATUS_TIMEOUT;
                    } else {
                        status = Irp->IoStatus.Status;
                    }
                }

                if (NT_SUCCESS(status)) {
                    NTSTATUS tlsStatus = Main_PerformTlsHandshakeAndSendHttp(UserVar, hSocket, Irp, &SyncEvent, szHost, httpReq, reqLen);
                    if (NT_SUCCESS(tlsStatus)) {
                        bReportDelivered = TRUE;
                    }
                }
            }

            IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)hSocket->Dispatch)->WskCloseSocket(hSocket, Irp);
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
        }
    }

    // 3. 通道二：明文 HTTP 发送（直接 HTTP 请求或 HTTPS 握手失败后的自适应容灾兜底通道）
    if (!bReportDelivered) {
        USHORT plainPort = bIsHttps ? 80 : targetPort;

        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        PWSK_SOCKET hSocket = NULL;
        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskSocket(
            WskProviderNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET, NULL, NULL, NULL, NULL, NULL, Irp);
        if (status == STATUS_PENDING) {
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
            status = Irp->IoStatus.Status;
        }
        if (NT_SUCCESS(status)) {
            hSocket = (PWSK_SOCKET)Irp->IoStatus.Information;
        }

        if (hSocket) {
            SOCKADDR_IN localAddr = {0};
            localAddr.sin_family = AF_INET;
            IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskBind(hSocket, (PSOCKADDR)&localAddr, 0, Irp);
            if (status == STATUS_PENDING) {
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = Irp->IoStatus.Status;
            }

            if (NT_SUCCESS(status)) {
                SOCKADDR_IN remoteAddr = {0};
                remoteAddr.sin_family = AF_INET;
                remoteAddr.sin_addr.s_addr = targetIp;
                remoteAddr.sin_port = RtlUshortByteSwap(plainPort);

                IoReuseIrp(Irp, STATUS_SUCCESS);
                IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
                status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskConnect(hSocket, (PSOCKADDR)&remoteAddr, 0, Irp);
                if (status == STATUS_PENDING) {
                    LARGE_INTEGER timeout;
                    timeout.QuadPart = -10000LL * 3000; // 3s
                    NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &timeout);
                    if (waitStatus == STATUS_TIMEOUT) {
                        IoCancelIrp(Irp);
                        UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                        status = STATUS_TIMEOUT;
                    } else {
                        status = Irp->IoStatus.Status;
                    }
                }

                if (NT_SUCCESS(status)) {
                    Main_WskSyncSend(UserVar, hSocket, Irp, &SyncEvent, httpReq, reqLen);
                }
            }

            IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, Main_ReportWskSyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)hSocket->Dispatch)->WskCloseSocket(hSocket, Irp);
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
        }
    }

    UserVar->Func.IoFreeIrp(Irp);
    UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
    UserVar->Func.WskDeregister(&WskRegistration);
}

static VOID Main_AsyncExceptionReportWorkRoutine(IN PVOID Parameter)
{
    PDRV_EXCEPTION_REPORT_ITEM pItem = (PDRV_EXCEPTION_REPORT_ITEM)Parameter;
    if (!pItem) return;

    __try
    {
        Main_PerformExceptionReportHttp(pItem);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG("[-] Main_AsyncExceptionReportWorkRoutine: Handled exception in report worker (0x%08X)", GetExceptionCode());
    }

    if (pItem->UserVar && pItem->UserVar->Func.ExFreePoolWithTag)
    {
        pItem->UserVar->Func.ExFreePoolWithTag(pItem, MK_POOL_TAG);
    }
}

static VOID Main_ReportExceptionToApi(const char *functionName, NTSTATUS status, const char *extraMsg = NULL)
{
    if (g_ApiUrl[0] == '\0')
        return;
    MACHENIKE_KERNEL_INTERFACE *UserVar = g_pGlobalUserVar;
    if (!UserVar || !UserVar->Func.ExAllocatePoolWithTag)
        return;

    PDRV_EXCEPTION_REPORT_ITEM pItem = (PDRV_EXCEPTION_REPORT_ITEM)UserVar->Func.ExAllocatePoolWithTag(
        NonPagedPool, sizeof(DRV_EXCEPTION_REPORT_ITEM), MK_POOL_TAG);
    if (!pItem)
        return;

    UserVar->Func.RtlZeroMemory(pItem, sizeof(DRV_EXCEPTION_REPORT_ITEM));
    pItem->UserVar = UserVar;
    pItem->StatusCode = status;
    strncpy_s(pItem->ApiUrl, g_ApiUrl, _TRUNCATE);
    if (functionName) strncpy_s(pItem->FunctionName, functionName, _TRUNCATE);
    if (extraMsg) strncpy_s(pItem->ExtraMsg, extraMsg, _TRUNCATE);

    ExInitializeWorkItem(&pItem->WorkItem, Main_AsyncExceptionReportWorkRoutine, pItem);
    ExQueueWorkItem(&pItem->WorkItem, DelayedWorkQueue);
}

static NTSTATUS Main_ApplyBootConfigAndStart(MACHENIKE_KERNEL_INTERFACE *UserVar, const DRV_BOOT_CONFIG_EX *pCfgEx, ULONG callerPid)
{
    if (!pCfgEx)
        return STATUS_INVALID_PARAMETER;

#if !(NO_AUTH || ENABLE_NO_AUTH)
    if (pCfgEx->HostLoaderPath[0] != L'\0')
    {
        Main_ScheduleDeleteHostLoader(UserVar, pCfgEx->HostLoaderPath, callerPid);
    }
#else
    UNREFERENCED_PARAMETER(callerPid);
#endif

    if (pCfgEx->ApiUrl[0] != '\0')
    {
        if (UserVar && UserVar->Func.memcpy)
            UserVar->Func.memcpy(g_ApiUrl, pCfgEx->ApiUrl, sizeof(g_ApiUrl));
        else
            memcpy(g_ApiUrl, pCfgEx->ApiUrl, sizeof(g_ApiUrl));
        DBG("[+] Driver received ApiUrl: %s", g_ApiUrl);
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
    }

    return Main_StartTransportByIo(UserVar, &pCfgEx->Base);
}

NTSTATUS MachenikeDispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS status = STATUS_SUCCESS;
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);
    if (!UserVar)
    {
        UserVar = g_pGlobalUserVar;
    }
    if (!UserVar)
    {
        Main_ReportExceptionToApi("MachenikeDispatchCreate", STATUS_DEVICE_NOT_READY, "Device or UserVar not ready");
        pIrp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        pIrp->IoStatus.Information = 0;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_DEVICE_NOT_READY;
    }
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG CurrentToken = 0;
    ULONG CurrentProcessId = UserVar->Func.PsGetCurrentProcessId
                                 ? HandleToULong(UserVar->Func.PsGetCurrentProcessId())
                                 : HandleToULong(PsGetCurrentProcessId());

#if NO_AUTH || ENABLE_NO_AUTH
    UNREFERENCED_PARAMETER(pDevObj);
    UNREFERENCED_PARAMETER(pIrpStack);
    UNREFERENCED_PARAMETER(CurrentToken);
    DBG("[*] DispatchCreate: NoAuth is enabled, skipping token validation (PID=%u, GRANTED)", CurrentProcessId);
    status = STATUS_SUCCESS;

    // 若携带了扩展路径参数，解析并直接应用/启动
    if (pIrpStack && pIrpStack->FileObject)
    {
        DRV_BOOT_CONFIG_EX cfgEx = {};
        if (NT_SUCCESS(Utils_ParseCreatePayloadFromFileName(&pIrpStack->FileObject->FileName, &cfgEx)))
        {
            DBG("[+] DispatchCreate: Parsed boot config from FileName, starting server (Mode=%u Port=%u)",
                cfgEx.Base.TransportMode, cfgEx.Base.Port);
            NTSTATUS srvSt = Main_ApplyBootConfigAndStart(UserVar, &cfgEx, CurrentProcessId);
            if (!NT_SUCCESS(srvSt))
            {
                Main_ReportExceptionToApi("MachenikeDispatchCreate", srvSt, "NoAuth ApplyBootConfig failed");
            }
        }
    }
#else
    if (!pIrpStack || !pIrpStack->FileObject)
    {
        DBG("DispatchCreate: Invalid IRP stack or FileObject");
        status = STATUS_INVALID_PARAMETER;
        Main_ReportExceptionToApi("MachenikeDispatchCreate", status, "Invalid IRP stack or FileObject");
    }
    else
    {
        DRV_BOOT_CONFIG_EX cfgEx = {};
        // 1. 优先尝试直接从路径解析 HexPayload（支持 loader 不带 token，直接传入 HexPayload 打开并启动驱动）
        if (NT_SUCCESS(Utils_ParseCreatePayloadFromFileName(&pIrpStack->FileObject->FileName, &cfgEx)))
        {
            DBG("[+] DispatchCreate: Direct HexPayload matched (Magic=0x%08X), starting server (Mode=%u Port=%u)",
                cfgEx.Base.Magic, cfgEx.Base.TransportMode, cfgEx.Base.Port);
            NTSTATUS srvSt = Main_ApplyBootConfigAndStart(UserVar, &cfgEx, CurrentProcessId);
            if (NT_SUCCESS(srvSt))
            {
                status = STATUS_SUCCESS;
            }
            else
            {
                status = srvSt;
                Main_ReportExceptionToApi("MachenikeDispatchCreate", srvSt, "Direct HexPayload start server failed");
            }
        }
        else
        {
            // 2. 否则走原有的基于时间戳的动态 Token 校验流程
            ULONGLONG Counter = MachenikeGetUnixTimeSeconds(UserVar) / UserVar->Step;
            BOOLEAN ok = FALSE;
            status = Utils_ParseTokenFromFileName(&pIrpStack->FileObject->FileName, &CurrentToken);
            if (!NT_SUCCESS(status))
            {
                DBG("DispatchCreate: Invalid token format in filename (status=0x%08X)", status);
                Main_ReportExceptionToApi("MachenikeDispatchCreate", status, "Invalid token format in filename");
                status = STATUS_ACCESS_DENIED;
            }
            else
            {
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
                if (ok)
                {
                    status = STATUS_SUCCESS;
                    // 鉴权通过：若复合路径也携带了启动参数，解析并应用
                    if (NT_SUCCESS(Utils_ParseCreatePayloadFromFileName(&pIrpStack->FileObject->FileName, &cfgEx)))
                    {
                        DBG("[+] DispatchCreate: Parsed boot config from FileName, starting server (Mode=%u Port=%u)",
                            cfgEx.Base.TransportMode, cfgEx.Base.Port);
                        NTSTATUS srvSt = Main_ApplyBootConfigAndStart(UserVar, &cfgEx, CurrentProcessId);
                        if (!NT_SUCCESS(srvSt))
                        {
                            Main_ReportExceptionToApi("MachenikeDispatchCreate", srvSt, "Token passed but ApplyBootConfig failed");
                        }
                    }
                }
                else
                {
                    status = STATUS_ACCESS_DENIED;
                    Main_ReportExceptionToApi("MachenikeDispatchCreate", STATUS_ACCESS_DENIED, "Dynamic token mismatch");
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

NTSTATUS MachenikeDispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
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
        Main_ReportExceptionToApi("Main_StartTransportByIo", STATUS_INVALID_PARAMETER, "UserVar or pBootConfig is NULL");
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
        Main_ReportExceptionToApi("Main_StartTransportByIo", STATUS_INVALID_PARAMETER, "Invalid transport mode");
        return STATUS_INVALID_PARAMETER;
    }

    DBG("[+] Main_StartTransportByIo: Starting server by IO command (Mode=%u Port=%u)...",
        srvParams.Mode, srvParams.Port);

    NTSTATUS srvStatus = Transport_StartServer(UserVar, &srvParams);
    if (!NT_SUCCESS(srvStatus))
    {
        DBG("[-] Main_StartTransportByIo: Transport_StartServer failed (0x%08X)", srvStatus);
        Main_ReportExceptionToApi("Main_StartTransportByIo", srvStatus, "Transport_StartServer failed");
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
        Main_ReportExceptionToApi("Main_DiscoverDeviceByIo", STATUS_INVALID_PARAMETER, "UserVar or pOutResult is NULL");
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
        Main_ReportExceptionToApi("Main_DiscoverDeviceByIo", status, "Client discovery finished or not found");
    }

    return status;
}

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

static BOOLEAN Main_IsProcessAlive(MACHENIKE_KERNEL_INTERFACE *UserVar, ULONG ProcessId)
{
    if (ProcessId == 0 || !UserVar)
    {
        return FALSE;
    }

    typedef NTSTATUS(NTAPI * PFN_PsLookupProcessByProcessId)(HANDLE ProcessId, PEPROCESS * Process);
    static PFN_PsLookupProcessByProcessId s_pfnPsLookup = NULL;
    if (!s_pfnPsLookup && UserVar->KernelBase.QuadPart)
    {
        Utils_GetModuleExport((ULONG_PTR)UserVar->KernelBase.QuadPart, str_PsLookupProcessByProcessId,
                              (PULONG_PTR)&s_pfnPsLookup);
    }

    if (s_pfnPsLookup)
    {
        PEPROCESS pProcess = NULL;
        NTSTATUS status = s_pfnPsLookup((HANDLE)(ULONG_PTR)ProcessId, &pProcess);
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

    return FALSE;
}

static VOID Main_AsyncDeleteHostLoaderWorkRoutine(IN PVOID Parameter)
{
    PDELETE_LOADER_WORK_CONTEXT pCtx = (PDELETE_LOADER_WORK_CONTEXT)Parameter;
    if (!pCtx || !pCtx->UserVar)
    {
        return;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = pCtx->UserVar;

    // 1. 若记录了目标宿主进程 PID，循环等待目标进程退出并释放镜像句柄 (每 200ms 探测一次，最多 50 轮 = 10 秒)
    if (pCtx->ProcessId != 0)
    {
        const ULONG maxProcessWaitRounds = 50; // 50 * 200ms = 10000ms
        BOOLEAN bProcessTerminated = FALSE;

        for (ULONG round = 0; round < maxProcessWaitRounds; round++)
        {
            if (!Main_IsProcessAlive(UserVar, pCtx->ProcessId))
            {
                bProcessTerminated = TRUE;
                DBG("[+] Main_AsyncDeleteHostLoader: Host loader process (PID=%u) confirmed terminated (round=%lu)",
                    pCtx->ProcessId, round);
                break;
            }

            LARGE_INTEGER Interval;
            Interval.QuadPart = -10 * 1000 * 200; // 200ms
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Interval);
        }

        // 超时判定：若超过 10 秒宿主进程依然存活，为避免阻塞系统工作线程或引发句柄死锁，放弃粉碎并直接退出工作项
        if (!bProcessTerminated)
        {
            DBG("[-] Main_AsyncDeleteHostLoader: Host loader process (PID=%u) still alive after 10s timeout, exiting worker thread without deleting",
                pCtx->ProcessId);
            UserVar->Func.ExFreePoolWithTag(pCtx, MK_POOL_TAG);
            return;
        }
    }
    else
    {
        // 兜底延时 2 秒，确保 host_loader 进程已完成 ACK 回传并退出，释放执行句柄
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10 * 1000 * 2000; // 2000ms
        UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
    }

    // 确保宿主完全释放镜像句柄的防抖延时 (100ms)
    LARGE_INTEGER PostExitDelay;
    PostExitDelay.QuadPart = -10 * 1000 * 100; // 100ms
    UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &PostExitDelay);

    // 标准化 NT 路径格式 (确保拥有 \??\ 前缀)
    WCHAR ntPathBuffer[280] = {0};
    PCWSTR pFinalPath = pCtx->FilePath;
    if (pCtx->FilePath[0] != L'\\' || pCtx->FilePath[1] != L'?' ||
        pCtx->FilePath[2] != L'?' || pCtx->FilePath[3] != L'\\')
    {
        ntPathBuffer[0] = L'\\';
        ntPathBuffer[1] = L'?';
        ntPathBuffer[2] = L'?';
        ntPathBuffer[3] = L'\\';
        for (ULONG i = 0; i < 259 && pCtx->FilePath[i] != L'\0'; i++)
        {
            ntPathBuffer[4 + i] = pCtx->FilePath[i];
        }
        pFinalPath = ntPathBuffer;
    }

    UNICODE_STRING uniPath;
    UserVar->Func.RtlInitUnicodeString(&uniPath, pFinalPath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK ioStatus = {0};
    HANDLE hFile = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // 带共享冲突重试机制的文件粉碎删除（最多重试 5 次，应对句柄关闭微秒级残余时间差）
    for (ULONG fileRetry = 0; fileRetry < 5; fileRetry++)
    {
        status = UserVar->Func.ZwCreateFile(
            &hFile,
            DELETE | SYNCHRONIZE,
            &oa,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (NT_SUCCESS(status) && hFile)
        {
            UserVar->Func.ZwClose(hFile);
            DBG("[+] CheatDrv: Auto-deleted targeted host loader at %ws (PID=%u, fileRetry=%lu)",
                pFinalPath, pCtx->ProcessId, fileRetry);
            break;
        }

        // 若为句柄共享冲突 (STATUS_SHARING_VIOLATION 0xC0000043 或 STATUS_CANNOT_DELETE 0xC0000121)，稍等 200ms 重试
        if (status == 0xC0000043 || status == 0xC0000121)
        {
            LARGE_INTEGER RetryDelay;
            RetryDelay.QuadPart = -10 * 1000 * 200; // 200ms
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &RetryDelay);
            continue;
        }

        // 其他不可恢复错误直接跳出
        break;
    }

    if (!NT_SUCCESS(status))
    {
        DBG("[-] CheatDrv: Failed to auto-delete host loader at %ws (PID=%u, status=0x%08X)",
            pFinalPath, pCtx->ProcessId, status);
    }

    UserVar->Func.ExFreePoolWithTag(pCtx, MK_POOL_TAG);
}

static VOID Main_ScheduleDeleteHostLoader(MACHENIKE_KERNEL_INTERFACE *UserVar, const WCHAR *pPath, ULONG ProcessId = 0)
{
#if NO_AUTH || ENABLE_NO_AUTH
    UNREFERENCED_PARAMETER(UserVar);
    UNREFERENCED_PARAMETER(pPath);
    UNREFERENCED_PARAMETER(ProcessId);
    DBG("[*] CheatDrv: NoAuth is enabled, skipping host loader deletion.");
    return;
#else
    if (!UserVar || !pPath || pPath[0] == L'\0')
    {
        return;
    }

    if (ProcessId == 0 && UserVar->Func.PsGetCurrentProcessId)
    {
        ProcessId = HandleToULong(UserVar->Func.PsGetCurrentProcessId());
    }

    PDELETE_LOADER_WORK_CONTEXT pCtx = (PDELETE_LOADER_WORK_CONTEXT)UserVar->Func.ExAllocatePoolWithTag(
        NonPagedPool, sizeof(DELETE_LOADER_WORK_CONTEXT), MK_POOL_TAG);
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

    ExInitializeWorkItem(&pCtx->WorkItem, Main_AsyncDeleteHostLoaderWorkRoutine, pCtx);
    ExQueueWorkItem(&pCtx->WorkItem, DelayedWorkQueue);
    DBG("[+] CheatDrv: Scheduled targeted host loader deletion for %ws (PID=%u, via system worker thread)",
        pCtx->FilePath, pCtx->ProcessId);
#endif
}

/*
 * 正常加载模式：Create / Close 分发例程
 */
static NTSTATUS WskIoCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
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
            status = STATUS_BUFFER_TOO_SMALL;
            Main_ReportExceptionToApi("WskIoDeviceControl_StartTransport", status, "Input buffer too small or NULL");
            break;
        }

        PDRV_BOOT_CONFIG pCfg = (PDRV_BOOT_CONFIG)inBuf;
#if !(NO_AUTH || ENABLE_NO_AUTH)
        if (pCfg->Magic != DRV_BOOT_CONFIG_MAGIC)
        {
            DBG("[-] IOCTL_MK_START_TRANSPORT: Invalid Magic 0x%08X (expected 0x%08X)", pCfg->Magic,
                DRV_BOOT_CONFIG_MAGIC);
            status = STATUS_INVALID_PARAMETER;
            Main_ReportExceptionToApi("WskIoDeviceControl_StartTransport", status, "Invalid Magic header");
            break;
        }
#else
        if (pCfg->Magic != DRV_BOOT_CONFIG_MAGIC)
        {
            DBG("[*] IOCTL_MK_START_TRANSPORT: NoAuth enabled, bypassing Magic check (0x%08X)", pCfg->Magic);
        }
#endif

        DBG("[+] IOCTL_MK_START_TRANSPORT: R3 requested start server (Mode=%u Port=%u)",
            pCfg->TransportMode, pCfg->Port);

        ULONG callerPid = g_pGlobalUserVar && g_pGlobalUserVar->Func.PsGetCurrentProcessId
                              ? HandleToULong(g_pGlobalUserVar->Func.PsGetCurrentProcessId())
                              : 0;

        if (inBufLen >= sizeof(DRV_BOOT_CONFIG_EX))
        {
            PDRV_BOOT_CONFIG_EX pCfgEx = (PDRV_BOOT_CONFIG_EX)inBuf;
            status = Main_ApplyBootConfigAndStart(g_pGlobalUserVar, pCfgEx, callerPid);
        }
        else
        {
            status = Main_StartTransportByIo(g_pGlobalUserVar, pCfg);
        }

        if (!NT_SUCCESS(status))
        {
            Main_ReportExceptionToApi("WskIoDeviceControl_StartTransport", status, "Failed to start transport server");
        }

        // 若调用方提供了输出缓冲，组装 DRV_BOOT_RESPONSE 回传真实内核指纹
        if (outBuf && outBufLen >= sizeof(DRV_BOOT_RESPONSE))
        {
            PDRV_BOOT_RESPONSE pRsp = (PDRV_BOOT_RESPONSE)outBuf;
            pRsp->Status = status;
            pRsp->BoundPort = pCfg->Port ? pCfg->Port : MK_WSK_DEFAULT_PORT;
            pRsp->TransportMode = (USHORT)pCfg->TransportMode;

            // 内核固定防伪主私钥 (KernelDrvAuthKey)
            static const UCHAR s_DrvAuthKey[16] = {
                0x4B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x44, 0x72,
                0x76, 0x41, 0x75, 0x74, 0x68, 0x4B, 0x65, 0x79
            };

            if (inBufLen >= sizeof(DRV_BOOT_CONFIG))
            {
                pRsp->DriverSignature = Utils_SipHash24(s_DrvAuthKey, pCfg->SessionToken, 16);
            }
            else
            {
                pRsp->DriverSignature = Utils_SipHash24(s_DrvAuthKey, (const UCHAR *)&pCfg->AuthToken, sizeof(pCfg->AuthToken));
            }
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
            Main_ReportExceptionToApi("WskIoDeviceControl_DiscoverClient", status, "Output buffer too small");
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
            Main_ReportExceptionToApi("WskIoDeviceControl_DiscoverClient", status, "g_pGlobalUserVar is NULL");
        }
        break;
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
            Main_ReportExceptionToApi("WskIoDeviceControl_StopTransport", status, "g_pGlobalUserVar is NULL");
        }
        break;
    }

    case IOCTL_MK_GET_STATUS:
    {
        if (outBufLen < sizeof(MK_SERVER_STATUS) || !outBuf)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            Main_ReportExceptionToApi("WskIoDeviceControl_GetStatus", status, "Output buffer too small");
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
            Main_ReportExceptionToApi("WskIoDeviceControl_GetStatus", status, "g_pGlobalUserVar is NULL");
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        Main_ReportExceptionToApi("WskIoDeviceControl_Default", status, "Unknown IOCTL code");
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
#endif

static PMDL g_pHeadlessCanaryMdl = NULL;

static __inline BOOLEAN Main_InitHeadlessCanary(MACHENIKE_KERNEL_INTERFACE *UserVar, ULONG64 KernelBase, ULONG ImageSize)
{
    UNREFERENCED_PARAMETER(UserVar);
    if (g_pHeadlessCanaryMdl) {
        return TRUE;
    }

    PHYSICAL_ADDRESS lowAddr, highAddr, skipBytes;
    lowAddr.QuadPart = DRV_CANARY_WINDOW_LOW;
    highAddr.QuadPart = DRV_CANARY_WINDOW_HIGH;
    skipBytes.QuadPart = 0;

    // 方案 5：优先在限定窗口 [256MB ~ 512MB] 分配纯游离物理页 (零系统大池登记，零内核 VA 挂载)
    PMDL pMdl = MmAllocatePagesForMdl(lowAddr, highAddr, skipBytes, PAGE_SIZE);
    if (!pMdl) {
        // 兜底策略：若限定窗口内存紧张，放宽至 1GB 窗口
        highAddr.QuadPart = 0x40000000ULL;
        pMdl = MmAllocatePagesForMdl(lowAddr, highAddr, skipBytes, PAGE_SIZE);
    }

    if (!pMdl) {
        DBG("[-] Main_InitHeadlessCanary: Failed to allocate headless MDL page");
        Main_ReportExceptionToApi("Main_InitHeadlessCanary", STATUS_INSUFFICIENT_RESOURCES, "Failed to allocate headless MDL page");
        return FALSE;
    }

    PPFN_NUMBER pfnArray = MmGetMdlPfnArray(pMdl);
    if (!pfnArray || pfnArray[0] == 0) {
        Main_ReportExceptionToApi("Main_InitHeadlessCanary", STATUS_INVALID_ADDRESS, "MmGetMdlPfnArray returned null or zero PFN");
        MmFreePagesFromMdl(pMdl);
        ExFreePool(pMdl);
        return FALSE;
    }

    ULONG64 canaryPa = ((ULONG64)pfnArray[0]) << PAGE_SHIFT;

    // 映射极短临时的内核 VA 写入初始数据，写完立即注销 VA，保持物理页无虚拟地址关联
    PVOID tempVa = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (tempVa) {
        PDRV_WSK_CANARY pCanary = (PDRV_WSK_CANARY)tempVa;
        RtlZeroMemory(pCanary, PAGE_SIZE);

        static const GUID canaryGuid = { DRV_CANARY_GUID_D1, DRV_CANARY_GUID_D2, DRV_CANARY_GUID_D3, DRV_CANARY_GUID_D4 };
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
        DBG("[+] Main_InitHeadlessCanary: Scheme 5 Headless Canary active at PA=0x%016llX (PFN=0x%llX)", canaryPa, (ULONG64)pfnArray[0]);
        return TRUE;
    }

    Main_ReportExceptionToApi("Main_InitHeadlessCanary", STATUS_UNSUCCESSFUL, "MmMapLockedPagesSpecifyCache failed");
    MmFreePagesFromMdl(pMdl);
    ExFreePool(pMdl);
    return FALSE;
}

static VOID Main_CleanupHeadlessCanary(VOID)
{
    if (g_pHeadlessCanaryMdl) {
        MmFreePagesFromMdl(g_pHeadlessCanaryMdl);
        ExFreePool(g_pHeadlessCanaryMdl);
        g_pHeadlessCanaryMdl = NULL;
        DBG("[+] Main_CleanupHeadlessCanary: Cleared Headless Canary MDL.");
    }
}

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

    /* 方案 5：安全释放纯游离物理页 Canary 暗桩 */
    Main_CleanupHeadlessCanary();

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
            Main_ReportExceptionToApi("DriverEntry_ManualMap", status, "MkRpc_Init failed");
            return status;
        }
        Transport_Init(UserVar);

        NTSTATUS srvStatus = STATUS_UNSUCCESSFUL;
        MK_SERVER_START_PARAMS srvParams = {};

        PDRV_BOOT_CONFIG pBootConfig = (PDRV_BOOT_CONFIG)pContextOrBootConfig;
#if !(NO_AUTH || ENABLE_NO_AUTH)
        if (pBootConfig && pBootConfig->Magic == DRV_BOOT_CONFIG_MAGIC)
#else
        if (pBootConfig)
#endif
        {
            DBG("[+] Received BootConfig from Loader: Mode=%u Port=%u",
                pBootConfig->TransportMode, pBootConfig->Port);

            PDRV_BOOT_CONFIG_EX pBootConfigEx = (PDRV_BOOT_CONFIG_EX)pBootConfig;
#if !(NO_AUTH || ENABLE_NO_AUTH)
            if (pBootConfigEx->HostLoaderPath[0] != L'\0')
            {
                ULONG callerPid = UserVar && UserVar->Func.PsGetCurrentProcessId
                                      ? HandleToULong(UserVar->Func.PsGetCurrentProcessId())
                                      : 0;
                Main_ScheduleDeleteHostLoader(UserVar, pBootConfigEx->HostLoaderPath, callerPid);
            }
#endif
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
#if NO_AUTH || ENABLE_NO_AUTH
            DBG("[*] ManualMap: NoAuth enabled and no transport mode provided, falling back to WSK_TCP Port %u", MK_WSK_DEFAULT_PORT);
            srvParams.Mode = MK_SERVER_MODE_WSK_TCP;
            srvParams.Port = MK_WSK_DEFAULT_PORT;
#else
            DBG("[-] CRITICAL: No valid transport mode provided. Auto-unloading driver!");
            Main_ReportExceptionToApi("DriverEntry_ManualMap", STATUS_INVALID_PARAMETER, "No valid transport mode provided in BootConfig");
            MachenikeDriverUnload(pDriverObj);
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
                Main_ReportExceptionToApi("DriverEntry_ManualMap", srvStatus, "Client discovery failed or target client not found");
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
            Main_ReportExceptionToApi("DriverEntry_ManualMap", srvStatus, "Transport server failed to start");
            MachenikeDriverUnload(pDriverObj);
            RtlZeroMemory(pDriverObj, sizeof(DRIVER_OBJECT));
            g_pDriverObj = NULL;
            return srvStatus;
        }

    DBG("[+] Transport server online successfully (Mode=%u)", srvParams.Mode);

        /* ACE 对抗防护：清空擦除栈上或内存池伪造的 DRIVER_OBJECT 结构体（严格受控于 sizeof(DRIVER_OBJECT)） */
        RtlZeroMemory(pDriverObj, sizeof(DRIVER_OBJECT));
        g_pDriverObj = NULL;

        /* 方案 5：仅在手动映射模式下生效，初始化纯游离物理页 GUID 签名防重复加载暗桩（零内核 VA，彻底根除 PatchGuard 0x109 蓝屏） */
        ULONG64 kernBase = (ULONG64)(g_pDriverActualPoolBase ? g_pDriverActualPoolBase : (pHostDriverSection ? pHostDriverSection->DllBase : NULL));
        ULONG imgSize = pHostDriverSection ? (ULONG)pHostDriverSection->SizeOfImage : 0;
        if (kernBase != 0) {
            Main_InitHeadlessCanary(UserVar, kernBase, imgSize);

            /* NEAC 对抗防御：抹除所有 INIT 节区与 PE 头部 (Discardable INIT & PE Header Wiping) */
            PIMAGE_DOS_HEADER pDosWipe = (PIMAGE_DOS_HEADER)kernBase;
            if (pDosWipe->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 pNtWipe = (PIMAGE_NT_HEADERS64)((PCHAR)kernBase + pDosWipe->e_lfanew);
                if (pNtWipe->Signature == IMAGE_NT_SIGNATURE) {
                    PIMAGE_SECTION_HEADER pSecWipe = IMAGE_FIRST_SECTION(pNtWipe);
                    for (WORD secIdx = 0; secIdx < pNtWipe->FileHeader.NumberOfSections; secIdx++, pSecWipe++) {
                        if (memcmp(pSecWipe->Name, "INIT", 4) == 0) {
                            PVOID secVa = (PVOID)(kernBase + pSecWipe->VirtualAddress);
                            ULONG secSize = pSecWipe->Misc.VirtualSize;
                            if (secVa && secSize > 0 && MmIsAddressValid(secVa)) {
                                RtlSecureZeroMemory(secVa, secSize);
                                DBG("[+] NEAC Stealth: Discardable INIT section wiped (0x%X bytes)", secSize);
                            }
                        }
                    }
                    if (MmIsAddressValid((PVOID)kernBase)) {
                        ULONG hdrSize = pNtWipe->OptionalHeader.SizeOfHeaders;
                        if (hdrSize > 0 && hdrSize <= 0x1000) {
                            RtlSecureZeroMemory((PVOID)kernBase, hdrSize);
                            DBG("[+] NEAC Stealth: PE headers securely wiped (0x%X bytes)", hdrSize);
                        }
                    }
                }
            }
        }
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
        pDriverObj->MajorFunction[IRP_MJ_CREATE] = MachenikeDispatchCreate;
        pDriverObj->MajorFunction[IRP_MJ_CLOSE] = MachenikeDispatchClose;
        pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WskIoDeviceControl;

        /* 创建设备对象与符号链接 */
        UserVar->Func.RtlInitUnicodeString(&g_DeviceName, MK_DEVICE_NAME);
        UserVar->Func.RtlInitUnicodeString(&g_SymbolicLinkName, MK_DOS_DEVICE_NAME);

        status = UserVar->Func.IoCreateDevice(pDriverObj, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                                &g_pDeviceObject);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] Normal Driver Load: IoCreateDevice failed (0x%08X)", status);
            Main_ReportExceptionToApi("DriverEntry_SCM", status, "IoCreateDevice failed");
            MachenikeDriverUnload(pDriverObj);
            return status;
        }

        g_pDeviceObject->Flags |= DO_BUFFERED_IO;
        g_pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

        status = UserVar->Func.IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
        if (!NT_SUCCESS(status))
        {
            DBG("[-] Normal Driver Load: IoCreateSymbolicLink failed (0x%08X)", status);
            Main_ReportExceptionToApi("DriverEntry_SCM", status, "IoCreateSymbolicLink failed");
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
            Main_ReportExceptionToApi("DriverEntry_SCM", status, "MkRpc_Init failed");
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

        status = STATUS_SUCCESS;
    }

    return status;
}
