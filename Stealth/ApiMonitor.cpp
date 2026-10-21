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

/*
 * 运行时常驻结构体：彻底剥离任何函数名字符串与符号特征，仅占用紧凑 16 字节
 */
typedef struct _API_MONITOR_TARGET
{
    ULONG_PTR InitialVa;       /* 已解析的目标函数虚拟地址 */
    ULONG     BaselineAdler32; /* 前 32 字节代码基线 Adler32 */
    BOOLEAN   BaselineReady;   /* 基线是否就绪 */
    BOOLEAN   IsNetio;         /* 是否属于 netio.sys (否则为 ntoskrnl.exe) */
} API_MONITOR_TARGET;

static API_MONITOR_TARGET s_MonitoredTargets[API_MONITOR_COUNT] = {0};

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

static ULONG_PTR DecodeApiInlineHookTarget(ULONG_PTR fnAddr, BOOLEAN *pbBreakTrapOut)
{
    if (pbBreakTrapOut)
        *pbBreakTrapOut = FALSE;
    if (!fnAddr || !MmIsAddressValid((PVOID)fnAddr) || !MmIsAddressValid((PVOID)(fnAddr + 15)))
        return 0;

    __try
    {
        PUCHAR p = (PUCHAR)fnAddr;

        /* 0. INT3 (0xCC) / UD2 (0x0F 0x0B) 异常陷阱 Hook */
        if (p[0] == 0xCC || (p[0] == 0x0F && p[1] == 0x0B))
        {
            if (pbBreakTrapOut)
                *pbBreakTrapOut = TRUE;
            return fnAddr;
        }

        /* 1. E9 rel32 / E8 rel32 */
        if (p[0] == 0xE9 || p[0] == 0xE8)
        {
            LONG disp = *(PLONG)(p + 1);
            return (ULONG_PTR)(p + 5 + disp);
        }

        /* 2. FF 25 [rip + disp32] */
        if (p[0] == 0xFF && p[1] == 0x25)
        {
            LONG disp = *(PLONG)(p + 2);
            ULONG_PTR slot = (ULONG_PTR)(p + 6 + disp);
            if (MmIsAddressValid((PVOID)slot))
                return *(PULONG_PTR)slot;
        }

        /* 3. 48 FF 25 [rip + disp32] */
        if (p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25)
        {
            LONG disp = *(PLONG)(p + 3);
            ULONG_PTR slot = (ULONG_PTR)(p + 7 + disp);
            if (MmIsAddressValid((PVOID)slot))
                return *(PULONG_PTR)slot;
        }

        /* 4. 48 B8 [imm64] FF E0..E2 */
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && (p[11] >= 0xE0 && p[11] <= 0xE2))
        {
            return *(PULONG_PTR)(p + 2);
        }

        /* 5. 49 BB [imm64] 41 FF E3 */
        if (p[0] == 0x49 && p[1] == 0xBB && p[10] == 0x41 && p[11] == 0xFF && p[12] == 0xE3)
        {
            return *(PULONG_PTR)(p + 2);
        }

        /* 6. 50 48 B8 [imm64] 48 87 04 24 C3 (ROP push/xchg/ret) */
        if (p[0] == 0x50 && p[1] == 0x48 && p[2] == 0xB8 && p[11] == 0x48 && p[12] == 0x87 && p[13] == 0x04 && p[14] == 0x24 && p[15] == 0xC3)
        {
            return *(PULONG_PTR)(p + 3);
        }

        /* 7. 68 [low32] C7 44 24 04 [high32] C3 */
        if (p[0] == 0x68 && p[5] == 0xC7 && p[6] == 0x44 && p[7] == 0x24 && p[8] == 0x04 && p[13] == 0xC3)
        {
            ULONG low = *(PULONG)(p + 1);
            ULONG high = *(PULONG)(p + 9);
            return (((ULONG_PTR)high) << 32) | low;
        }

        /* 8. EB rel8 -> E9 rel32 二级跳板 */
        if (p[0] == 0xEB)
        {
            CHAR disp8 = *(PCHAR)(p + 1);
            ULONG_PTR next = (ULONG_PTR)(p + 2 + disp8);
            if (MmIsAddressValid((PVOID)next) && next != fnAddr)
            {
                PUCHAR p2 = (PUCHAR)next;
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

static BOOLEAN LocateKeServiceDescriptorTable(VOID)
{
    if (g_pSsdtServiceTable && g_SsdtServiceLimit > 0)
        return TRUE;
    if (!g_KernelBase || !g_KernelEnd)
        return FALSE;

    ULONG64 lstar = 0;
    if (MachenikeReadMsrSafe(0xC0000082, &lstar) && lstar >= g_KernelBase && lstar < g_KernelEnd)
    {
        // 路径 1 (快速通道)：从 LSTAR 直接向后扫描 1536 字节 (适用于未开启 KVA Shadow 的系统)
        __try
        {
            PUCHAR pStart = (PUCHAR)lstar;
            for (ULONG i = 0; i < 1536 && (ULONG_PTR)(pStart + i + 14) <= g_KernelEnd; i++)
            {
                if (!MmIsAddressValid(pStart + i + 14))
                    break;
                /* 匹配 lea r10, KeServiceDescriptorTable (4C 8D 15 disp32) + lea r11, KeServiceDescriptorTableShadow (4C 8D 1D disp32) */
                if (pStart[i] == 0x4C && pStart[i + 1] == 0x8D && pStart[i + 2] == 0x15 && pStart[i + 7] == 0x4C && pStart[i + 8] == 0x8D &&
                    pStart[i + 9] == 0x1D)
                {
                    LONG disp = *(PLONG)(pStart + i + 3);
                    ULONG_PTR ksdAddr = (ULONG_PTR)(pStart + i + 7 + disp);
                    if (ksdAddr >= g_KernelBase && ksdAddr < g_KernelEnd && MmIsAddressValid((PVOID)ksdAddr))
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

    // 路径 2 (KVA Shadow 兼容通道)：现代 Win10/Win11 开启 Meltdown 缓解后 LSTAR 指向 KVASCODE 影子例程，
    // 真实 KeServiceDescriptorTable 位于 ntoskrnl 的主 .text 代码段 (KiSystemServiceRepeat)
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
                    if (ksdAddr >= g_KernelBase && ksdAddr < g_KernelEnd && MmIsAddressValid((PVOID)ksdAddr))
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
    if (!zwFnAddr || !pIndexOut || !MmIsAddressValid((PVOID)zwFnAddr) || !MmIsAddressValid((PVOID)(zwFnAddr + 24)))
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
    }

    for (ULONG i = 0; i < API_MONITOR_COUNT; i++)
    {
        s_MonitoredTargets[i].IsNetio = s_InitApiTable[i].IsNetio;
        ULONG_PTR modBase = s_InitApiTable[i].IsNetio ? g_NetioBase : g_KernelBase;
        ULONG_PTR fnVa = 0;
        if (modBase && Utils::GetModuleExport(modBase, s_InitApiTable[i].Hash, &fnVa) && fnVa)
        {
            s_MonitoredTargets[i].InitialVa = fnVa;
            if (MmIsAddressValid((PVOID)fnVa) && MmIsAddressValid((PVOID)(fnVa + API_BASELINE_SAMPLE_BYTES - 1)))
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
        if (!fnVa || !MmIsAddressValid((PVOID)fnVa) || !MmIsAddressValid((PVOID)(fnVa + API_BASELINE_SAMPLE_BYTES - 1)))
            continue;

        /* 1. 目标地址越界或指向 ACE 模块检测 */
        if (fnVa < modBase || fnVa >= modEnd || IsAddressInAceModules(fnVa))
        {
            alarms++;
            DBG("[!] [HOOK ALARM-API] Slot %u VA out of bounds or in ACE! VA=0x%p", i, (PVOID)fnVa);
            if (!(s_ReportedEatMask & (1U << i)))
            {
                s_ReportedEatMask |= (1U << i);
                ExceptionReporter::ReportFormat("ApiMonitor::EatPointerHook", STATUS_SECURITY_CHECKS_FAILED,
                    "API Hook: Slot %u VA out of bounds or in ACE! VA=0x%p", i, (PVOID)fnVa);
            }
        }

        /* 2. 函数入口 Inline Hook / INT3 陷阱检测 */
        BOOLEAN bBreakTrap = FALSE;
        ULONG_PTR target = DecodeApiInlineHookTarget(fnVa, &bBreakTrap);
        if (bBreakTrap || (target && (IsAddressInAceModules(target) || target < modBase || target >= modEnd)))
        {
            alarms++;
            DBG("[!] [HOOK ALARM-API] Inline Hook on Slot %u (0x%p) -> Target=0x%p", i, (PVOID)fnVa, (PVOID)target);
            if (!(s_ReportedInlineMask & (1U << i)))
            {
                s_ReportedInlineMask |= (1U << i);
                ExceptionReporter::ReportFormat("ApiMonitor::ApiInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                    "API Inline Hook: Slot %u (0x%p) hooked -> Target=0x%p", i, (PVOID)fnVa, (PVOID)target);
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
            DBG("[!] [HOOK ALARM-API] Byte Patch on Slot %u (0x%p)! Hash=0x%08X (Base=0x%08X)", i, (PVOID)fnVa,
                curHash, s_MonitoredTargets[i].BaselineAdler32);
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

        if (!MmIsAddressValid(&g_pSsdtServiceTable[syscallIdx]))
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
        else if (MmIsAddressValid((PVOID)ntVa) && MmIsAddressValid((PVOID)(ntVa + API_BASELINE_SAMPLE_BYTES - 1)))
        {
            BOOLEAN bTrap = FALSE;
            ULONG_PTR inlineTarget = DecodeApiInlineHookTarget(ntVa, &bTrap);
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
            alarms++;
            DBG("[!] [HOOK ALARM-SSDT] SSDT Nt* Hook on Zw Slot %u (Syscall=%u, NtVA=0x%p, Target=0x%p)",
                apiIdx, syscallIdx, (PVOID)ntVa, (PVOID)hookTarget);
            if (!(s_ReportedSsdtMask & (1U << k)))
            {
                s_ReportedSsdtMask |= (1U << k);
                ExceptionReporter::ReportFormat("ApiMonitor::SsdtNtHook", STATUS_SECURITY_CHECKS_FAILED,
                    "SSDT Hook: Zw Slot %u (Syscall=%u) NtVA=0x%p Target=0x%p",
                    apiIdx, syscallIdx, (PVOID)ntVa, (PVOID)hookTarget);
            }
        }
    }

    return alarms;
}

/*
 * 维度 4: 关键通信/USB 系统驱动导入表 (IAT) 精准监控 (仅针对 28 个高危敏感函数及 ACE 指向)
 */
ULONG ApiMonitor::CheckSystemDriverIatHooks(VOID)
{
    ULONG alarms = 0;
    if (!g_pApiMonDriverSection)
        return 0;

    static const PCWSTR s_TargetDrivers[] = {
        L"netio.sys",
        L"tcpip.sys",
        L"ndis.sys",
        L"usbxhci.sys",
        L"usbhub3.sys"
    };

    for (ULONG d = 0; d < ARRAY_SIZE(s_TargetDrivers); d++)
    {
        ULONG_PTR drvBase = 0;
        ULONG_PTR drvEnd = 0;

        for (PLIST_ENTRY pEntry = g_pApiMonDriverSection->InLoadOrderLinks.Flink;
             pEntry != &g_pApiMonDriverSection->InLoadOrderLinks; pEntry = pEntry->Flink)
        {
            PKLDR_DATA_TABLE_ENTRY pLdr = CONTAINING_RECORD(pEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (!pLdr->DllBase || !pLdr->BaseDllName.Buffer)
                continue;
            ULONG cch = pLdr->BaseDllName.Length / sizeof(WCHAR);
            if (MatchWideSubstrCaseless(pLdr->BaseDllName.Buffer, cch, s_TargetDrivers[d]))
            {
                drvBase = (ULONG_PTR)pLdr->DllBase;
                drvEnd = drvBase + pLdr->SizeOfImage;
                break;
            }
        }

        if (!drvBase || !MmIsAddressValid((PVOID)drvBase))
            continue;

        __try
        {
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)drvBase;
            if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
                continue;
            PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(drvBase + pDos->e_lfanew);
            if (pNt->Signature != IMAGE_NT_SIGNATURE)
                continue;

            IMAGE_DATA_DIRECTORY impDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!impDir.VirtualAddress || !impDir.Size || impDir.VirtualAddress >= (drvEnd - drvBase))
                continue;

            PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)(drvBase + impDir.VirtualAddress);
            for (ULONG m = 0; m < 32 && MmIsAddressValid(pDesc) && pDesc->FirstThunk != 0; m++, pDesc++)
            {
                PULONG_PTR pIat = (PULONG_PTR)(drvBase + pDesc->FirstThunk);

                for (ULONG s = 0; s < 512 && MmIsAddressValid(&pIat[s]); s++)
                {
                    ULONG_PTR fnVa = pIat[s];
                    if (!fnVa)
                        break;

                    /* 4.1 IAT 槽位直接指向 ACE 模块 */
                    if (IsAddressInAceModules(fnVa))
                    {
                        alarms++;
                        if (!(s_ReportedIatDrvMask & (1U << d)))
                        {
                            s_ReportedIatDrvMask |= (1U << d);
                            ExceptionReporter::ReportFormat("ApiMonitor::SystemDrvIatHook", STATUS_SECURITY_CHECKS_FAILED,
                                "IAT Hook: %ws IAT slot[%u] points to ACE (0x%p)", s_TargetDrivers[d], s, (PVOID)fnVa);
                        }
                        break;
                    }

                    /* 4.2 校验命中 28 个槽位中的已解析地址 */
                    for (ULONG k = 0; k < API_MONITOR_COUNT; k++)
                    {
                        if (s_MonitoredTargets[k].InitialVa != 0 && fnVa == s_MonitoredTargets[k].InitialVa)
                        {
                            break;
                        }
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

    // 硬件断点审计自检（仅上报，不熔断置零会话密钥）
    DrvSecurity::AuditHardwareBreakpoints();

    // 核心代码段 Adler32 自检（违规即熔断）
    if (!DrvSecurity::VerifyTextIntegrity())
    {
        DBG("[-] ApiMonitor::ScanAll [Round #%lu]: Security integrity check failed! SessionCryptKey poisoned", s_apiScanRound);
        TransportManager::SetSessionCryptKey(0);
        return;
    }

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
