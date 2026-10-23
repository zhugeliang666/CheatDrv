#include "ApiMonitor.h"
#include "DrvSecurity.h"
#include "ExceptionReporter.h"
#include "MachenikeString.h"
#include "Struct.h"
#include "TransportManager.h"
#include "Utils.h"

extern "C" BOOLEAN MachenikeReadMsrSafe(ULONG MsrIndex, PULONG64 pValue);

static MACHENIKE_KERNEL_INTERFACE *g_pApiMonUserVar = NULL;
static PKLDR_DATA_TABLE_ENTRY g_pApiMonDriverSection = NULL;
static ULONG_PTR g_KernelBase = 0;
static ULONG_PTR g_KernelEnd = 0;
static ULONG_PTR g_NetioBase = 0;
static ULONG_PTR g_NetioEnd = 0;

#ifdef MmIsAddressValid
#undef MmIsAddressValid
#endif
#define MmIsAddressValid(va)                                                                                                               \
    ((g_pApiMonUserVar && g_pApiMonUserVar->Func.MmIsAddressValid) ? g_pApiMonUserVar->Func.MmIsAddressValid((PVOID)(va)) : FALSE)

#define API_MONITOR_COUNT 28
#define SSDT_ZW_MONITOR_COUNT 7
#define API_BASELINE_SAMPLE_BYTES 32
#define CORE_SYS_DRV_COUNT 5

typedef struct _API_MONITOR_TARGET
{
    ULONG_PTR InitialVa;       /* 已解析的目标函数虚拟地址 */
    ULONG     BaselineAdler32; /* 前 32 字节代码基线 Adler32 */
    BOOLEAN   BaselineReady;   /* 基线是否就绪 */
    BOOLEAN   IsNetio;         /* 是否属于 netio.sys (否则为 ntoskrnl.exe) */
} API_MONITOR_TARGET;

static API_MONITOR_TARGET s_MonitoredTargets[API_MONITOR_COUNT] = {0};

typedef struct _CACHED_SYS_DRV
{
    ULONG     Hash;
    ULONG_PTR Base;
    ULONG_PTR End;
} CACHED_SYS_DRV;

/* 5 大核心通信/USB 系统驱动缓存（Init 时单次解析基址，运行期零链表遍历、零明文匹配） */
static CACHED_SYS_DRV s_CachedSysDrvs[CORE_SYS_DRV_COUNT] = {
    {wstr_Netio, 0, 0},
    {wstr_Tcpip, 0, 0},
    {wstr_Ndis, 0, 0},
    {wstr_Usbxhci, 0, 0},
    {wstr_Usbhub3, 0, 0}
};

typedef struct _API_INIT_ENTRY
{
    ULONG   Hash;
    BOOLEAN IsNetio;
} API_INIT_ENTRY;

/* 仅在 Init 阶段使用的临时特征表（初始化完成后物理擦除） */
static API_INIT_ENTRY s_InitApiTable[API_MONITOR_COUNT] = {
    /* 1. 物理内存与节区映射 (8项: Slot 0-7) */
    {str_ZwMapViewOfSection, FALSE},
    {str_ZwUnmapViewOfSection, FALSE},
    {str_ZwOpenSection, FALSE},
    {str_MmGetVirtualForPhysical, FALSE},
    {str_MmAllocateMappingAddress, FALSE},
    {str_MmFreeMappingAddress, FALSE},
    {str_MmMapLockedPagesSpecifyCache, FALSE},
    {str_MmIsAddressValid, FALSE},
    /* 2. 进程/线程与句柄权限 (6项: Slot 8-13) */
    {str_ZwOpenProcess, FALSE},
    {str_ZwTerminateProcess, FALSE},
    {str_PsLookupProcessByProcessId, FALSE},
    {str_PsGetProcessSectionBaseAddress, FALSE},
    {str_PsCreateSystemThread, FALSE},
    {str_ObReferenceObjectByHandle, FALSE},
    /* 3. 设备栈检索与 I/O 派遣 (7项: Slot 14-20) */
    {str_ObReferenceObjectByName, FALSE},
    {str_IoGetDeviceObjectPointer, FALSE},
    {str_IoGetDeviceInterfaces, FALSE},
    {str_IoCallDriver, FALSE},
    {str_IofCompleteRequest, FALSE},
    {str_ZwCreateFile, FALSE},
    {str_ZwDeviceIoControlFile, FALSE},
    /* 4. 内存池与后台调度 (3项: Slot 21-23) */
    {str_ExAllocatePoolWithTag, FALSE},
    {str_ExAllocatePool2, FALSE},
    {str_ExQueueWorkItem, FALSE},
    /* 5. 网络与 WFP 核心导出 (4项: Slot 24-27) */
    {str_WskRegister, TRUE},
    {str_WskCaptureProviderNPI, TRUE},
    {str_KfdAddCalloutEntry, TRUE},
    {str_FwpsCalloutRegister2, TRUE},
};

/* 名单内 7 个 Zw* 函数在 s_MonitoredTargets 中的索引映射 */
static const ULONG s_ZwApiIndices[SSDT_ZW_MONITOR_COUNT] = {
    0,  /* ZwMapViewOfSection */
    1,  /* ZwUnmapViewOfSection */
    2,  /* ZwOpenSection */
    8,  /* ZwOpenProcess */
    9,  /* ZwTerminateProcess */
    19, /* ZwCreateFile */
    20  /* ZwDeviceIoControlFile */
};

static ULONG s_NtBaselineAdler32[SSDT_ZW_MONITOR_COUNT] = {0};
static BOOLEAN s_NtBaselineReady[SSDT_ZW_MONITOR_COUNT] = {FALSE};
static PULONG g_pSsdtServiceTable = NULL;
static ULONG g_SsdtServiceLimit = 0;

/* 去重位图：每个异常槽位仅上报一次 */
static UINT32 s_ReportedEatMask = 0;
static UINT32 s_ReportedInlineMask = 0;
static UINT32 s_ReportedPatchMask = 0;
static UINT32 s_ReportedSsdtMask = 0;
static UINT32 s_ReportedIatDrvMask = 0;

VOID ApiMonitor::ResetReportState(VOID)
{
    s_ReportedEatMask = 0;
    s_ReportedInlineMask = 0;
    s_ReportedPatchMask = 0;
    s_ReportedSsdtMask = 0;
    s_ReportedIatDrvMask = 0;
    DBG("[+] ApiMonitor: Report deduplication state reset");
}

static BOOLEAN MatchWideSubstrCaseless(PCWSTR pszStr, ULONG cchStr, PCWSTR pszSub)
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

static BOOLEAN LocateKeServiceDescriptorTable(VOID)
{
    if (g_pSsdtServiceTable && g_SsdtServiceLimit > 0)
        return TRUE;
    if (!g_KernelBase || !g_KernelEnd)
        return FALSE;

    ULONG64 lstar = 0;
    if (MachenikeReadMsrSafe(0xC0000082, &lstar) && lstar >= g_KernelBase && lstar < g_KernelEnd)
    {
        __try
        {
            PUCHAR pStart = (PUCHAR)lstar;
            for (ULONG i = 0; i < 1536 && (ULONG_PTR)(pStart + i + 14) <= g_KernelEnd; i++)
            {
                if (!MmIsAddressValid(pStart + i + 14))
                    break;
                if (pStart[i] == 0x4C && pStart[i + 1] == 0x8D && pStart[i + 2] == 0x15 && pStart[i + 7] == 0x4C && pStart[i + 8] == 0x8D &&
                    pStart[i + 9] == 0x1D)
                {
                    LONG disp = *(PLONG)(pStart + i + 3);
                    ULONG_PTR ksdAddr = (ULONG_PTR)(pStart + i + 7 + disp);
                    if (ksdAddr >= g_KernelBase && ksdAddr < g_KernelEnd && Utils::IsValidKernelRange((PVOID)ksdAddr, 0x18))
                    {
                        PULONG pTable = *(PULONG *)ksdAddr;
                        ULONG limit = *(PULONG)(ksdAddr + 0x10);
                        if ((ULONG_PTR)pTable >= g_KernelBase && (ULONG_PTR)pTable < g_KernelEnd && limit > 100 && limit < 2048)
                        {
                            g_pSsdtServiceTable = pTable;
                            g_SsdtServiceLimit = limit;
                            DBG("[+] ApiMonitor: Located SSDT via LSTAR @ 0x%p (Limit=%lu)", (PVOID)pTable, limit);
                            return TRUE;
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    ULONG_PTR kTextStart = 0, kTextEnd = 0;
    if (Utils::GetModuleTextSection(g_KernelBase, &kTextStart, &kTextEnd) && kTextEnd > kTextStart)
    {
        PUCHAR pText = (PUCHAR)kTextStart;
        ULONG scanLen = (ULONG)(kTextEnd - kTextStart);
        __try
        {
            for (ULONG i = 0; i + 14 < scanLen; i++)
            {
                if ((i & 0xFFF) == 0 && !MmIsAddressValid(pText + i))
                {
                    i += 0xFFF;
                    continue;
                }

                if (pText[i] == 0x4C && pText[i + 1] == 0x8D && pText[i + 2] == 0x15 && pText[i + 7] == 0x4C && pText[i + 8] == 0x8D &&
                    pText[i + 9] == 0x1D)
                {
                    LONG disp = *(PLONG)(pText + i + 3);
                    ULONG_PTR ksdAddr = (ULONG_PTR)(pText + i + 7 + disp);
                    if (ksdAddr >= g_KernelBase && ksdAddr < g_KernelEnd && Utils::IsValidKernelRange((PVOID)ksdAddr, 0x18))
                    {
                        PULONG pTable = *(PULONG *)ksdAddr;
                        ULONG limit = *(PULONG)(ksdAddr + 0x10);
                        if ((ULONG_PTR)pTable >= g_KernelBase && (ULONG_PTR)pTable < g_KernelEnd && limit > 100 && limit < 2048)
                        {
                            g_pSsdtServiceTable = pTable;
                            g_SsdtServiceLimit = limit;
                            DBG("[+] ApiMonitor: Located SSDT via kernel .text section scan @ 0x%p (Limit=%lu)", (PVOID)pTable, limit);
                            return TRUE;
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] ApiMonitor: Exception scanning for SSDT in kernel .text");
        }
    }

    return FALSE;
}

static BOOLEAN ExtractZwSyscallIndex(ULONG_PTR zwFnAddr, ULONG *pIndexOut)
{
    if (!zwFnAddr || !pIndexOut || !Utils::IsValidKernelRange((PVOID)zwFnAddr, 25))
        return FALSE;
    __try
    {
        PUCHAR p = (PUCHAR)zwFnAddr;
        for (ULONG i = 0; i < 24; i++)
        {
            /* mov eax, <syscall_idx> (B8 xx xx 00 00) */
            if (p[i] == 0xB8 && p[i + 3] == 0x00 && p[i + 4] == 0x00)
            {
                *pIndexOut = *(PULONG)(p + i + 1);
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return FALSE;
}

NTSTATUS ApiMonitor::Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PKLDR_DATA_TABLE_ENTRY DriverSection)
{
    g_pApiMonUserVar = UserVar;
    g_pApiMonDriverSection = DriverSection;
    ResetReportState();

    if (!UserVar || !DriverSection)
        return STATUS_INVALID_PARAMETER;

    for (PLIST_ENTRY pEntry = DriverSection->InLoadOrderLinks.Flink; pEntry != &DriverSection->InLoadOrderLinks; pEntry = pEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pLdr = CONTAINING_RECORD(pEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!pLdr->DllBase || !pLdr->BaseDllName.Buffer)
            continue;
        ULONG cch = pLdr->BaseDllName.Length / sizeof(WCHAR);
        ULONG hash = Utils::HashStringW(pLdr->BaseDllName.Buffer, cch, TRUE);
        if (!g_KernelBase && (hash == wstr_Ntoskrnl || MatchWideSubstrCaseless(pLdr->BaseDllName.Buffer, cch, L"ntoskrnl")))
        {
            g_KernelBase = (ULONG_PTR)pLdr->DllBase;
            g_KernelEnd = g_KernelBase + pLdr->SizeOfImage;
        }
        else if (!g_NetioBase && (hash == wstr_Netio || MatchWideSubstrCaseless(pLdr->BaseDllName.Buffer, cch, L"netio")))
        {
            g_NetioBase = (ULONG_PTR)pLdr->DllBase;
            g_NetioEnd = g_NetioBase + pLdr->SizeOfImage;
        }

        for (ULONG d = 0; d < CORE_SYS_DRV_COUNT; d++)
        {
            if (s_CachedSysDrvs[d].Base == 0 && hash == s_CachedSysDrvs[d].Hash)
            {
                s_CachedSysDrvs[d].Base = (ULONG_PTR)pLdr->DllBase;
                s_CachedSysDrvs[d].End = s_CachedSysDrvs[d].Base + pLdr->SizeOfImage;
            }
        }
    }

    for (ULONG i = 0; i < API_MONITOR_COUNT; i++)
    {
        s_MonitoredTargets[i].IsNetio = s_InitApiTable[i].IsNetio;
        ULONG_PTR modBase = s_InitApiTable[i].IsNetio ? g_NetioBase : g_KernelBase;
        ULONG_PTR fnVa = 0;
        if (modBase && Utils::GetModuleExport(modBase, s_InitApiTable[i].Hash, &fnVa) && fnVa)
        {
            s_MonitoredTargets[i].InitialVa = fnVa;
            if (Utils::IsValidKernelRange((PVOID)fnVa, API_BASELINE_SAMPLE_BYTES))
            {
                s_MonitoredTargets[i].BaselineAdler32 = Utils::CalcAdler32((const UCHAR *)fnVa, API_BASELINE_SAMPLE_BYTES);
                s_MonitoredTargets[i].BaselineReady = TRUE;
            }
        }
    }

    /* 关键双阶段分离：初始化完成后立即将 s_InitApiTable 物理原位清零，阅后即焚 */
    RtlSecureZeroMemory(s_InitApiTable, sizeof(s_InitApiTable));

    LocateKeServiceDescriptorTable();
    DBG("[+] ApiMonitor: Initialized 28 high-risk sensitive API targets (Kernel=0x%p, Netio=0x%p, SSDT=0x%p)",
        (PVOID)g_KernelBase, (PVOID)g_NetioBase, (PVOID)g_pSsdtServiceTable);
    return STATUS_SUCCESS;
}

/*
 * 维度 1 & 2: 28 个已解析槽位的入口跳板解码 + 32 字节防篡改基线校验 (零字符串、零静态Hash)
 */
ULONG ApiMonitor::CheckSensitiveApiHooks(VOID)
{
    ULONG alarms = 0;
    if (!g_KernelBase)
        return 0;

    for (ULONG i = 0; i < API_MONITOR_COUNT; i++)
    {
        ULONG_PTR modBase = s_MonitoredTargets[i].IsNetio ? g_NetioBase : g_KernelBase;
        ULONG_PTR modEnd = s_MonitoredTargets[i].IsNetio ? g_NetioEnd : g_KernelEnd;
        if (!modBase || !modEnd)
            continue;

        ULONG_PTR fnVa = s_MonitoredTargets[i].InitialVa;
        if (!fnVa || !Utils::IsValidKernelRange((PVOID)fnVa, API_BASELINE_SAMPLE_BYTES))
            continue;

        /* 1. 目标地址越界或指向 ACE 模块检测 */
        if (fnVa < modBase || fnVa >= modEnd || IsAddressInAceModules(fnVa))
        {
            WCHAR aceMod[32] = {0};
            ULONG_PTR aceBase = 0, aceRva = 0;
            ResolveAceModuleInfo(fnVa, aceMod, &aceBase, &aceRva);
            alarms++;
            DBG("[!] [HOOK ALARM-API] Slot %u VA out of bounds or in %ws! VA=0x%p (+0x%llX)",
                i, aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID)fnVa, aceRva);
            if (!(s_ReportedEatMask & (1U << i)))
            {
                s_ReportedEatMask |= (1U << i);
                ExceptionReporter::ReportFormat("ApiMonitor::EatPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                    "API Hook: Slot %u VA out of bounds or in %ws! VA=0x%p (Base=0x%p +0x%llX)",
                    i, aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID)fnVa, (PVOID)aceBase, aceRva);
            }
        }

        /* 2. 函数入口 Inline Hook / INT3 陷阱检测 */
        BOOLEAN bBreakTrap = FALSE;
        ULONG_PTR target = Utils::DecodeInlineHookTarget(fnVa, &bBreakTrap);
        if (bBreakTrap || (target && (IsAddressInAceModules(target) || target < modBase || target >= modEnd)))
        {
            WCHAR aceMod[32] = {0};
            ULONG_PTR aceBase = 0, aceRva = 0;
            ResolveAceModuleInfo(target, aceMod, &aceBase, &aceRva);
            alarms++;
            DBG("[!] [HOOK ALARM-API] Inline Hook on Slot %u (0x%p) -> %ws Target=0x%p (+0x%llX)",
                i, (PVOID)fnVa, aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID)target, aceRva);
            if (!(s_ReportedInlineMask & (1U << i)))
            {
                s_ReportedInlineMask |= (1U << i);
                ExceptionReporter::ReportFormat("ApiMonitor::ApiInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                    "API Inline Hook: Slot %u (0x%p) hooked -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                    i, (PVOID)fnVa, aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID)target, (PVOID)aceBase, aceRva);
            }
        }

        /* 3. 前 32 字节 Adler32 基线防篡改校验 */
        ULONG curHash = Utils::CalcAdler32((const UCHAR *)fnVa, API_BASELINE_SAMPLE_BYTES);
        if (!s_MonitoredTargets[i].BaselineReady)
        {
            s_MonitoredTargets[i].BaselineAdler32 = curHash;
            s_MonitoredTargets[i].BaselineReady = TRUE;
        }
        else if (curHash != s_MonitoredTargets[i].BaselineAdler32)
        {
            alarms++;
            DBG("[!] [HOOK ALARM-API] Byte Patch on Slot %u (0x%p)! Hash=0x%08X (Base=0x%08X)",
                i, (PVOID)fnVa, curHash, s_MonitoredTargets[i].BaselineAdler32);
            if (!(s_ReportedPatchMask & (1U << i)))
            {
                s_ReportedPatchMask |= (1U << i);
                ExceptionReporter::ReportFormat("ApiMonitor::ApiBytePatched", STATUS_SECURITY_CHECKS_FAILED,
                    "API Byte Patch: Slot %u (0x%p) modified! Hash=0x%08X Base=0x%08X",
                    i, (PVOID)fnVa, curHash, s_MonitoredTargets[i].BaselineAdler32);
            }
        }
    }

    return alarms;
}

/*
 * 维度 3: SSDT (Zw* -> Nt*) 双端监控（针对名单内 7 个高危 Zw* 函数背后的 Nt* 真实例程）
 */
ULONG ApiMonitor::CheckSsdtZwHooks(VOID)
{
    ULONG alarms = 0;
    if (!LocateKeServiceDescriptorTable() || !g_pSsdtServiceTable)
        return 0;

    for (ULONG k = 0; k < SSDT_ZW_MONITOR_COUNT; k++)
    {
        ULONG apiIdx = s_ZwApiIndices[k];
        ULONG_PTR zwVa = s_MonitoredTargets[apiIdx].InitialVa;
        if (!zwVa)
            continue;

        ULONG syscallIdx = 0;
        if (!ExtractZwSyscallIndex(zwVa, &syscallIdx) || syscallIdx >= g_SsdtServiceLimit)
            continue;

        if (!Utils::IsValidKernelRange(&g_pSsdtServiceTable[syscallIdx], sizeof(ULONG)))
            continue;

        LONG offset = (LONG)g_pSsdtServiceTable[syscallIdx] >> 4;
        ULONG_PTR ntVa = (ULONG_PTR)g_pSsdtServiceTable + offset;

        BOOLEAN bHooked = FALSE;
        ULONG_PTR hookTarget = 0;

        if (ntVa < g_KernelBase || ntVa >= g_KernelEnd || IsAddressInAceModules(ntVa))
        {
            bHooked = TRUE;
            hookTarget = ntVa;
        }
        else if (Utils::IsValidKernelRange((PVOID)ntVa, API_BASELINE_SAMPLE_BYTES))
        {
            BOOLEAN bTrap = FALSE;
            ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(ntVa, &bTrap);
            if (bTrap || (inlineTarget && (IsAddressInAceModules(inlineTarget) || inlineTarget < g_KernelBase || inlineTarget >= g_KernelEnd)))
            {
                bHooked = TRUE;
                hookTarget = inlineTarget;
            }
            else
            {
                ULONG ntHash = Utils::CalcAdler32((const UCHAR *)ntVa, API_BASELINE_SAMPLE_BYTES);
                if (!s_NtBaselineReady[k])
                {
                    s_NtBaselineAdler32[k] = ntHash;
                    s_NtBaselineReady[k] = TRUE;
                }
                else if (ntHash != s_NtBaselineAdler32[k])
                {
                    bHooked = TRUE;
                    hookTarget = ntVa;
                }
            }
        }

        if (bHooked)
        {
            WCHAR aceMod[32] = {0};
            ULONG_PTR aceBase = 0, aceRva = 0;
            ResolveAceModuleInfo(hookTarget, aceMod, &aceBase, &aceRva);
            alarms++;
            DBG("[!] [HOOK ALARM-SSDT] SSDT Nt* Hook on Zw Slot %u (Syscall=%u, NtVA=0x%p) -> %ws Target=0x%p (+0x%llX)",
                apiIdx, syscallIdx, (PVOID)ntVa, aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID)hookTarget, aceRva);
            if (!(s_ReportedSsdtMask & (1U << k)))
            {
                s_ReportedSsdtMask |= (1U << k);
                ExceptionReporter::ReportFormat("ApiMonitor::SsdtNtHook", STATUS_SECURITY_CHECKS_FAILED,
                    "SSDT Hook: Zw Slot %u (Syscall=%u, NtVA=0x%p) -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                    apiIdx, syscallIdx, (PVOID)ntVa, aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID)hookTarget, (PVOID)aceBase, aceRva);
            }
        }
    }

    return alarms;
}

/*
 * 维度 4: 关键通信/USB 系统驱动导入表 (IAT) 精准监控 (基于预缓存模块基址，零链表遍历)
 */
ULONG ApiMonitor::CheckSystemDriverIatHooks(VOID)
{
    if (!g_bAceDetected || g_AceModuleCount == 0)
        return 0;

    ULONG alarms = 0;

    for (ULONG d = 0; d < CORE_SYS_DRV_COUNT; d++)
    {
        ULONG_PTR drvBase = s_CachedSysDrvs[d].Base;
        ULONG_PTR drvEnd = s_CachedSysDrvs[d].End;
        if (!drvBase || drvEnd <= drvBase || !Utils::IsValidKernelRange((PVOID)drvBase, PAGE_SIZE))
            continue;

        __try
        {
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)drvBase;
            if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
                continue;
            PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(drvBase + pDos->e_lfanew);
            if (!Utils::IsValidKernelRange(pNt, sizeof(IMAGE_NT_HEADERS64)) || pNt->Signature != IMAGE_NT_SIGNATURE)
                continue;

            IMAGE_DATA_DIRECTORY impDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!impDir.VirtualAddress || !impDir.Size || impDir.VirtualAddress >= (drvEnd - drvBase))
                continue;

            PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)(drvBase + impDir.VirtualAddress);
            for (ULONG m = 0; m < 32 && Utils::IsValidKernelRange(pDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && pDesc->FirstThunk != 0; m++, pDesc++)
            {
                if (pDesc->FirstThunk >= (drvEnd - drvBase))
                    break;
                PULONG_PTR pIat = (PULONG_PTR)(drvBase + pDesc->FirstThunk);

                for (ULONG s = 0; s < 512 && Utils::IsValidKernelRange(&pIat[s], sizeof(ULONG_PTR)); s++)
                {
                    ULONG_PTR fnVa = pIat[s];
                    if (!fnVa)
                        break;

                    /* IAT 槽位直接指向 ACE 模块 */
                    if (IsAddressInAceModules(fnVa))
                    {
                        WCHAR aceMod[32] = {0};
                        ULONG_PTR aceBase = 0, aceRva = 0;
                        ResolveAceModuleInfo(fnVa, aceMod, &aceBase, &aceRva);
                        alarms++;
                        if (!(s_ReportedIatDrvMask & (1U << d)))
                        {
                            s_ReportedIatDrvMask |= (1U << d);
                            ExceptionReporter::ReportFormat("ApiMonitor::SystemDrvIatHook", STATUS_SECURITY_CHECKS_FAILED,
                                "IAT Hook: SysDrv[%u] IAT slot[%u] points to %ws (0x%p, Base=0x%p +0x%llX)",
                                d, s, aceMod[0] ? aceMod : L"ACE", (PVOID)fnVa, (PVOID)aceBase, aceRva);
                        }
                        break;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    return alarms;
}

VOID ApiMonitor::ScanAll(VOID)
{
    static ULONG s_apiScanRound = 0;
    s_apiScanRound++;

    ULONG apiAlarms = CheckSensitiveApiHooks();
    ULONG ssdtAlarms = CheckSsdtZwHooks();
    ULONG iatAlarms = CheckSystemDriverIatHooks();
    ULONG total = apiAlarms + ssdtAlarms + iatAlarms;

    if (total > 0)
    {
        DBG("[!] ApiMonitor [Round #%lu]: >>> THREAT DETECTED! Total=%u (Slot/Inline/Patch=%u, SSDT=%u, IAT=%u) <<<",
            s_apiScanRound, total, apiAlarms, ssdtAlarms, iatAlarms);
    }
    else if (s_apiScanRound <= 3 || (s_apiScanRound % 5) == 0)
    {
        DBG("[+] ApiMonitor [Round #%lu]: All 28 sensitive slots, 7 SSDT Zw/Nt stubs & 5 core driver IATs intact",
            s_apiScanRound);
    }
}
