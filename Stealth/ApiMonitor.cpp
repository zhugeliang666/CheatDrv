#include "ApiMonitor.h"
#include "DrvSecurity.h"
#include "ExceptionReporter.h"
#include "MachenikeString.h"
#include "Struct.h"
#include "TransportManager.h"
#include "Utils.h"

BOOLEAN MachenikeReadMsrSafe(ULONG MsrIndex, PULONG64 pValue);

static MACHENIKE_KERNEL_INTERFACE *g_pApiMonUserVar = NULL;
static PKLDR_DATA_TABLE_ENTRY g_pApiMonDriverSection = NULL;
static ULONG_PTR g_KernelBase = 0;
static ULONG_PTR g_KernelEnd = 0;
static ULONG_PTR g_NetioBase = 0;
static ULONG_PTR g_NetioEnd = 0;
static ULONG_PTR g_HalBase = 0;
static ULONG_PTR g_HalEnd = 0;
static ULONG_PTR g_KernelTextStart = 0;
static ULONG_PTR g_KernelTextEnd = 0;

#ifdef MmIsAddressValid
#undef MmIsAddressValid
#endif
#define MmIsAddressValid(va)                                                                                                               \
    ((g_pApiMonUserVar && g_pApiMonUserVar->Func.MmIsAddressValid) ? g_pApiMonUserVar->Func.MmIsAddressValid((PVOID)(va)) : FALSE)

#define API_MONITOR_COUNT 28
#define SSDT_ZW_MONITOR_COUNT 7
#define API_BASELINE_SAMPLE_BYTES 32
#define CORE_SYS_DRV_COUNT 7

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

/* 7 大核心通信/USB/WDF 系统驱动缓存（Init 时单次解析基址，运行期零链表遍历、零明文匹配） */
static CACHED_SYS_DRV s_CachedSysDrvs[CORE_SYS_DRV_COUNT] = {
    {wstr_Netio, 0, 0},
    {wstr_Tcpip, 0, 0},
    {wstr_Ndis, 0, 0},
    {wstr_Usbxhci, 0, 0},
    {wstr_Usbhub3, 0, 0},
    {wstr_Ucx01000, 0, 0},
    {wstr_Wdf01000, 0, 0}
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

/* ---- SwapContext / HalDispatch / HalPrivateDispatch / #PF 链监控状态 ---- */
#define HAL_DISPATCH_MAX_SLOTS      16
#define HAL_PRIV_DISPATCH_MAX_SLOTS 48
#define HAL_TOTAL_MAX_SLOTS         (HAL_DISPATCH_MAX_SLOTS + HAL_PRIV_DISPATCH_MAX_SLOTS)
#define HAL_SEC_MAX_SLOTS           16
#define PF_CHAIN_MAX_TARGETS        6

typedef struct _HAL_SLOT_TARGET
{
    PULONG_PTR pSlotAddr;       /* 表内槽位虚拟地址 (&Table[idx]) */
    ULONG_PTR  InitialVa;       /* 初始函数指针目标地址 */
    ULONG      BaselineAdler32; /* 目标函数前 32B 基线 */
    USHORT     SlotIndex;       /* 原始表内索引 */
    BOOLEAN    IsPrivateTable;  /* TRUE: HalPrivateDispatchTable, FALSE: HalDispatchTable */
    BOOLEAN    BaselineReady;
} HAL_SLOT_TARGET;

typedef struct _HAL_SEC_SLOT_TARGET
{
    PULONG_PTR pDataPtrAddr;    /* 二级结构体或 .data 中的函数指针槽位地址 */
    ULONG_PTR  InitialTargetVa; /* 初始指向的内核/HAL函数地址 */
    USHORT     ParentSlotIdx;   /* 关联的一级槽位索引 (0xFFFF 表示 KeQueryPerformanceCounter) */
} HAL_SEC_SLOT_TARGET;

typedef struct _PF_CHAIN_TARGET
{
    ULONG_PTR  InitialVa;       /* KiPageFault 或内部调用的 MmAccessFault 等函数地址 */
    PLONG      pRelCallDisp;    /* 若为内部 E8 call 目标，记录指令 disp32 地址以检测 call 篡改 */
    LONG       InitialDisp;     /* 初始 E8 相对偏移 */
    ULONG      BaselineAdler32; /* 前 32B 基线 */
    BOOLEAN    BaselineReady;
} PF_CHAIN_TARGET;

#pragma pack(push, 1)
typedef struct _MK_IDTR64
{
    USHORT    Limit;
    ULONG_PTR Base;
} MK_IDTR64;

typedef struct _MK_IDTENTRY64
{
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR  IstIndex;
    UCHAR  Attributes;
    USHORT OffsetMiddle;
    ULONG  OffsetHigh;
    ULONG  Reserved;
} MK_IDTENTRY64;
#pragma pack(pop)

static HAL_SLOT_TARGET s_HalSlots[HAL_TOTAL_MAX_SLOTS] = {0};
static ULONG s_HalSlotCount = 0;

static HAL_SEC_SLOT_TARGET s_HalSecSlots[HAL_SEC_MAX_SLOTS] = {0};
static ULONG s_HalSecSlotCount = 0;

static PF_CHAIN_TARGET s_PfChainTargets[PF_CHAIN_MAX_TARGETS] = {0};
static ULONG s_PfChainCount = 0;
static ULONG_PTR s_InitialIdt0EHandler = 0;
static PULONG g_pPerfCswitchMaskDword = NULL;

/* 去重位图：64 槽一级 HAL 表、16 槽二级指针、缺页链与 CSWITCH 掩码 */
static UINT64 s_ReportedHalPtrMask = 0;
static UINT64 s_ReportedHalInlineMask = 0;
static UINT32 s_ReportedHalSecMask = 0;
static UINT32 s_ReportedPfChainMask = 0;
static BOOLEAN s_ReportedIdt0E = FALSE;
static BOOLEAN s_ReportedPerfCswitch = FALSE;

VOID ApiMonitor::ResetReportState(VOID)
{
    s_ReportedEatMask = 0;
    s_ReportedInlineMask = 0;
    s_ReportedPatchMask = 0;
    s_ReportedSsdtMask = 0;
    s_ReportedIatDrvMask = 0;
    s_ReportedHalPtrMask = 0;
    s_ReportedHalInlineMask = 0;
    s_ReportedHalSecMask = 0;
    s_ReportedPfChainMask = 0;
    s_ReportedIdt0E = FALSE;
    s_ReportedPerfCswitch = FALSE;
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

static FORCEINLINE BOOLEAN IsAddressInKernelOrHal(ULONG_PTR va)
{
    if (g_KernelBase && va >= g_KernelBase && va < g_KernelEnd)
        return TRUE;
    if (g_HalBase && va >= g_HalBase && va < g_HalEnd)
        return TRUE;
    return FALSE;
}

static VOID RecordHalSecondarySlot(PULONG_PTR pDataSlot, ULONG_PTR targetFnVa, USHORT parentIdx)
{
    if (!pDataSlot || !targetFnVa || s_HalSecSlotCount >= HAL_SEC_MAX_SLOTS)
        return;

    for (ULONG i = 0; i < s_HalSecSlotCount; i++)
    {
        if (s_HalSecSlots[i].pDataPtrAddr == pDataSlot)
            return;
    }

    s_HalSecSlots[s_HalSecSlotCount].pDataPtrAddr = pDataSlot;
    s_HalSecSlots[s_HalSecSlotCount].InitialTargetVa = targetFnVa;
    s_HalSecSlots[s_HalSecSlotCount].ParentSlotIdx = parentIdx;
    s_HalSecSlotCount++;
}

static VOID ExtractSecondaryPointersFromFunction(ULONG_PTR fnVa, USHORT parentSlotIdx)
{
    if (!fnVa || s_HalSecSlotCount >= HAL_SEC_MAX_SLOTS || !Utils::IsValidKernelRange((PVOID)fnVa, 64))
        return;

    __try
    {
        PUCHAR p = (PUCHAR)fnVa;
        for (ULONG i = 0; i < 56 && s_HalSecSlotCount < HAL_SEC_MAX_SLOTS; i++)
        {
            ULONG instrLen = 0;
            LONG disp = 0;

            /* mov reg, qword ptr [rip + disp32] (48 8B 05/0D/15/1D/25/2D/35/3D xx xx xx xx) */
            if (p[i] == 0x48 && p[i + 1] == 0x8B && (p[i + 2] & 0xC7) == 0x05)
            {
                instrLen = 7;
                disp = *(PLONG)(p + i + 3);
            }
            /* call/jmp qword ptr [rip + disp32] (FF 15 / FF 25 xx xx xx xx) */
            else if (p[i] == 0xFF && (p[i + 1] == 0x15 || p[i + 1] == 0x25))
            {
                instrLen = 6;
                disp = *(PLONG)(p + i + 2);
            }

            if (instrLen == 0)
                continue;

            ULONG_PTR dataVa = (ULONG_PTR)(p + i + instrLen + disp);
            if (!IsAddressInKernelOrHal(dataVa) || !Utils::IsValidKernelRange((PVOID)dataVa, sizeof(ULONG_PTR)))
                continue;

            ULONG_PTR val = *(PULONG_PTR)dataVa;
            if (!val)
                continue;

            /* 情况 1: .data 全局槽位本身直接存放了指向内核/HAL代码段的函数指针 */
            if (IsAddressInKernelOrHal(val) &&
                ((g_KernelTextStart && val >= g_KernelTextStart && val < g_KernelTextEnd) ||
                 (g_HalBase && val >= g_HalBase && val < g_HalEnd)) &&
                Utils::IsValidKernelRange((PVOID)val, API_BASELINE_SAMPLE_BYTES))
            {
                RecordHalSecondarySlot((PULONG_PTR)dataVa, val, parentSlotIdx);
            }
            /* 情况 2: .data 全局槽位指向二级对象结构体 (如 HalpPerformanceCounter)，扫描对象内部函数指针字段 */
            else if (val > 0xFFFF800000000000ULL && val < 0xFFFFFF0000000000ULL &&
                     Utils::IsValidKernelRange((PVOID)val, 0x100))
            {
                for (ULONG off = 0; off < 0x100 && s_HalSecSlotCount < HAL_SEC_MAX_SLOTS; off += sizeof(ULONG_PTR))
                {
                    PULONG_PTR pField = (PULONG_PTR)(val + off);
                    ULONG_PTR fieldFn = *pField;
                    if (IsAddressInKernelOrHal(fieldFn) &&
                        ((g_KernelTextStart && fieldFn >= g_KernelTextStart && fieldFn < g_KernelTextEnd) ||
                         (g_HalBase && fieldFn >= g_HalBase && fieldFn < g_HalEnd)) &&
                        Utils::IsValidKernelRange((PVOID)fieldFn, API_BASELINE_SAMPLE_BYTES))
                    {
                        RecordHalSecondarySlot(pField, fieldFn, parentSlotIdx);
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static VOID InitHalAndSwapContextTargets(VOID)
{
    s_HalSlotCount = 0;
    s_HalSecSlotCount = 0;
    if (!g_KernelBase)
        return;

    ULONG_PTR halDispVa = 0;
    if (Utils::GetModuleExport(g_KernelBase, str_HalDispatchTable, &halDispVa) && halDispVa &&
        Utils::IsValidKernelRange((PVOID)halDispVa, (HAL_DISPATCH_MAX_SLOTS + 1) * sizeof(ULONG_PTR)))
    {
        PULONG_PTR pTable = (PULONG_PTR)halDispVa;
        for (ULONG idx = 1; idx <= HAL_DISPATCH_MAX_SLOTS && s_HalSlotCount < HAL_TOTAL_MAX_SLOTS; idx++)
        {
            ULONG_PTR fnVa = pTable[idx];
            if (!fnVa || !IsAddressInKernelOrHal(fnVa) || !Utils::IsValidKernelRange((PVOID)fnVa, API_BASELINE_SAMPLE_BYTES))
                continue;

            s_HalSlots[s_HalSlotCount].pSlotAddr = &pTable[idx];
            s_HalSlots[s_HalSlotCount].InitialVa = fnVa;
            s_HalSlots[s_HalSlotCount].BaselineAdler32 = Utils::CalcAdler32((const UCHAR *)fnVa, API_BASELINE_SAMPLE_BYTES);
            s_HalSlots[s_HalSlotCount].SlotIndex = (USHORT)idx;
            s_HalSlots[s_HalSlotCount].IsPrivateTable = FALSE;
            s_HalSlots[s_HalSlotCount].BaselineReady = TRUE;
            s_HalSlotCount++;
        }
    }

    ULONG_PTR halPrivDispVa = 0;
    if (Utils::GetModuleExport(g_KernelBase, str_HalPrivateDispatchTable, &halPrivDispVa) && halPrivDispVa &&
        Utils::IsValidKernelRange((PVOID)halPrivDispVa, (HAL_PRIV_DISPATCH_MAX_SLOTS + 1) * sizeof(ULONG_PTR)))
    {
        PULONG_PTR pPrivTable = (PULONG_PTR)halPrivDispVa;
        for (ULONG idx = 1; idx <= HAL_PRIV_DISPATCH_MAX_SLOTS && s_HalSlotCount < HAL_TOTAL_MAX_SLOTS; idx++)
        {
            ULONG_PTR fnVa = pPrivTable[idx];
            if (!fnVa || !IsAddressInKernelOrHal(fnVa) || !Utils::IsValidKernelRange((PVOID)fnVa, API_BASELINE_SAMPLE_BYTES))
                continue;

            s_HalSlots[s_HalSlotCount].pSlotAddr = &pPrivTable[idx];
            s_HalSlots[s_HalSlotCount].InitialVa = fnVa;
            s_HalSlots[s_HalSlotCount].BaselineAdler32 = Utils::CalcAdler32((const UCHAR *)fnVa, API_BASELINE_SAMPLE_BYTES);
            s_HalSlots[s_HalSlotCount].SlotIndex = (USHORT)idx;
            s_HalSlots[s_HalSlotCount].IsPrivateTable = TRUE;
            s_HalSlots[s_HalSlotCount].BaselineReady = TRUE;
            s_HalSlotCount++;

            ExtractSecondaryPointersFromFunction(fnVa, (USHORT)idx);
        }
    }

    ULONG_PTR kqpcVa = 0;
    if (Utils::GetModuleExport(g_KernelBase, str_KeQueryPerformanceCounter, &kqpcVa) && kqpcVa)
    {
        ExtractSecondaryPointersFromFunction(kqpcVa, 0xFFFF);
    }
}

static ULONG_PTR ReadCurrentIdt0EHandler(VOID)
{
    __try
    {
        MK_IDTR64 idtr = {0};
        __sidt(&idtr);
        if (idtr.Base <= 0xFFFF800000000000ULL || idtr.Limit < (0x0F * sizeof(MK_IDTENTRY64) - 1))
            return 0;

        ULONG_PTR entryAddr = idtr.Base + (0x0E * sizeof(MK_IDTENTRY64));
        if (!Utils::IsValidKernelRange((PVOID)entryAddr, sizeof(MK_IDTENTRY64)))
            return 0;

        const MK_IDTENTRY64 *pEntry = (const MK_IDTENTRY64 *)entryAddr;
        return ((ULONG_PTR)pEntry->OffsetHigh << 32) | ((ULONG_PTR)pEntry->OffsetMiddle << 16) | (ULONG_PTR)pEntry->OffsetLow;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

static VOID InitPageFaultAndCswitchTargets(VOID)
{
    s_PfChainCount = 0;
    s_InitialIdt0EHandler = ReadCurrentIdt0EHandler();
    if (s_InitialIdt0EHandler && IsAddressInKernelOrHal(s_InitialIdt0EHandler) &&
        Utils::IsValidKernelRange((PVOID)s_InitialIdt0EHandler, API_BASELINE_SAMPLE_BYTES))
    {
        s_PfChainTargets[0].InitialVa = s_InitialIdt0EHandler;
        s_PfChainTargets[0].pRelCallDisp = NULL;
        s_PfChainTargets[0].InitialDisp = 0;
        s_PfChainTargets[0].BaselineAdler32 = Utils::CalcAdler32((const UCHAR *)s_InitialIdt0EHandler, API_BASELINE_SAMPLE_BYTES);
        s_PfChainTargets[0].BaselineReady = TRUE;
        s_PfChainCount = 1;

        /* 扫描 KiPageFault 前 384 字节内的直接 E8 call 指令，定位 MmAccessFault 等核心内层例程 */
        __try
        {
            PUCHAR p = (PUCHAR)s_InitialIdt0EHandler;
            for (ULONG i = 0; i < 384 && s_PfChainCount < PF_CHAIN_MAX_TARGETS; i++)
            {
                if (!Utils::IsValidKernelRange(p + i, 5))
                    break;
                if (p[i] == 0xE8)
                {
                    LONG disp = *(PLONG)(p + i + 1);
                    ULONG_PTR callTarget = (ULONG_PTR)(p + i + 5 + disp);
                    if (g_KernelTextStart && callTarget >= g_KernelTextStart && callTarget < g_KernelTextEnd &&
                        Utils::IsValidKernelRange((PVOID)callTarget, API_BASELINE_SAMPLE_BYTES))
                    {
                        BOOLEAN exists = FALSE;
                        for (ULONG k = 0; k < s_PfChainCount; k++)
                        {
                            if (s_PfChainTargets[k].InitialVa == callTarget)
                            {
                                exists = TRUE;
                                break;
                            }
                        }
                        if (!exists)
                        {
                            s_PfChainTargets[s_PfChainCount].InitialVa = callTarget;
                            s_PfChainTargets[s_PfChainCount].pRelCallDisp = (PLONG)(p + i + 1);
                            s_PfChainTargets[s_PfChainCount].InitialDisp = disp;
                            s_PfChainTargets[s_PfChainCount].BaselineAdler32 =
                                Utils::CalcAdler32((const UCHAR *)callTarget, API_BASELINE_SAMPLE_BYTES);
                            s_PfChainTargets[s_PfChainCount].BaselineReady = TRUE;
                            s_PfChainCount++;
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    /* 在内核 .text 段单次扫描 test dword ptr [PerfGlobalGroupMask+8], 0x20000004 (F7 05 xx xx xx xx 04 00 00 20) */
    if (g_KernelTextStart && g_KernelTextEnd > g_KernelTextStart)
    {
        PUCHAR pText = (PUCHAR)g_KernelTextStart;
        ULONG scanLen = (ULONG)(g_KernelTextEnd - g_KernelTextStart);
        __try
        {
            for (ULONG i = 0; i + 10 < scanLen; i++)
            {
                if ((i & 0xFFF) == 0 && !MmIsAddressValid(pText + i))
                {
                    i += 0xFFF;
                    continue;
                }
                if (pText[i] == 0xF7 && pText[i + 1] == 0x05 && pText[i + 6] == 0x04 && pText[i + 7] == 0x00 &&
                    pText[i + 8] == 0x00 && pText[i + 9] == 0x20)
                {
                    LONG disp = *(PLONG)(pText + i + 2);
                    ULONG_PTR maskAddr = (ULONG_PTR)(pText + i + 10 + disp);
                    if (maskAddr >= g_KernelBase && maskAddr < g_KernelEnd &&
                        Utils::IsValidKernelRange((PVOID)maskAddr, sizeof(ULONG)))
                    {
                        g_pPerfCswitchMaskDword = (PULONG)maskAddr;
                        break;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
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
        else if (!g_HalBase && (hash == wstr_Hal || MatchWideSubstrCaseless(pLdr->BaseDllName.Buffer, cch, L"hal.dll")))
        {
            g_HalBase = (ULONG_PTR)pLdr->DllBase;
            g_HalEnd = g_HalBase + pLdr->SizeOfImage;
        }
        if (0)
        {
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
    if (g_KernelBase)
    {
        Utils::GetModuleTextSection(g_KernelBase, &g_KernelTextStart, &g_KernelTextEnd);
    }
    InitHalAndSwapContextTargets();
    InitPageFaultAndCswitchTargets();
    DBG("[+] ApiMonitor: Initialized 28 APIs, %lu HAL slots, %lu SecPtrs, %lu #PF targets (Kernel=0x%p, Hal=0x%p, SSDT=0x%p, CswitchMask=0x%p)",
        s_HalSlotCount, s_HalSecSlotCount, s_PfChainCount, (PVOID)g_KernelBase, (PVOID)g_HalBase, (PVOID)g_pSsdtServiceTable,
        (PVOID)g_pPerfCswitchMaskDword);
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

/*
 * 维度 5: HalDispatchTable / HalPrivateDispatchTable 一级表与二级 .data 深层指针监控 (SwapContext / LBR / PMC / InfinityHook)
 */
ULONG ApiMonitor::CheckHalAndSwapContextHooks(VOID)
{
    if (!g_KernelBase)
        return 0;

    ULONG alarms = 0;

    /* 1. 一级表槽位指针归属 + 目标函数入口 Inline Hook + 32B 基线校验 */
    for (ULONG i = 0; i < s_HalSlotCount && i < 64; i++)
    {
        PULONG_PTR pSlot = s_HalSlots[i].pSlotAddr;
        if (!pSlot || !Utils::IsValidKernelRange(pSlot, sizeof(ULONG_PTR)))
            continue;

        ULONG_PTR curVa = *pSlot;
        PCSTR tblName = s_HalSlots[i].IsPrivateTable ? "HalPrivateDispatchTable" : "HalDispatchTable";

        if (curVa != s_HalSlots[i].InitialVa || !IsAddressInKernelOrHal(curVa) || IsAddressInAceModules(curVa))
        {
            WCHAR aceMod[32] = {0};
            ULONG_PTR aceBase = 0, aceRva = 0;
            ResolveAceModuleInfo(curVa, aceMod, &aceBase, &aceRva);
            alarms++;
            DBG("[!] [HOOK ALARM-HAL] %s[%u] pointer modified! Cur=0x%p (Init=0x%p) -> %ws (+0x%llX)",
                tblName, s_HalSlots[i].SlotIndex, (PVOID)curVa, (PVOID)s_HalSlots[i].InitialVa,
                aceMod[0] ? aceMod : L"Foreign/ACE", aceRva);
            if (!(s_ReportedHalPtrMask & (1ULL << i)))
            {
                s_ReportedHalPtrMask |= (1ULL << i);
                ExceptionReporter::ReportFormat("ApiMonitor::HalTablePtrHook", STATUS_SECURITY_CHECKS_FAILED,
                    "%s[%u] Hooked: Cur=0x%p (Init=0x%p) -> %ws (Base=0x%p +0x%llX)",
                    tblName, s_HalSlots[i].SlotIndex, (PVOID)curVa, (PVOID)s_HalSlots[i].InitialVa,
                    aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID)aceBase, aceRva);
            }
            continue;
        }

        if (!Utils::IsValidKernelRange((PVOID)curVa, API_BASELINE_SAMPLE_BYTES))
            continue;

        BOOLEAN bTrap = FALSE;
        ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(curVa, &bTrap);
        ULONG curHash = Utils::CalcAdler32((const UCHAR *)curVa, API_BASELINE_SAMPLE_BYTES);
        BOOLEAN bInlineOrPatched = bTrap ||
            (inlineTarget && (IsAddressInAceModules(inlineTarget) || !IsAddressInKernelOrHal(inlineTarget))) ||
            (s_HalSlots[i].BaselineReady && curHash != s_HalSlots[i].BaselineAdler32);

        if (bInlineOrPatched)
        {
            ULONG_PTR reportTarget = inlineTarget ? inlineTarget : curVa;
            WCHAR aceMod[32] = {0};
            ULONG_PTR aceBase = 0, aceRva = 0;
            ResolveAceModuleInfo(reportTarget, aceMod, &aceBase, &aceRva);
            alarms++;
            DBG("[!] [HOOK ALARM-HAL] %s[%u] (0x%p) Inline/Byte Hook -> %ws Target=0x%p (+0x%llX) Hash=0x%08X",
                tblName, s_HalSlots[i].SlotIndex, (PVOID)curVa, aceMod[0] ? aceMod : L"Foreign/ACE",
                (PVOID)reportTarget, aceRva, curHash);
            if (!(s_ReportedHalInlineMask & (1ULL << i)))
            {
                s_ReportedHalInlineMask |= (1ULL << i);
                ExceptionReporter::ReportFormat("ApiMonitor::HalSlotInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                    "%s[%u] (0x%p) Inline/Byte Hook -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                    tblName, s_HalSlots[i].SlotIndex, (PVOID)curVa, aceMod[0] ? aceMod : L"Foreign/ACE",
                    (PVOID)aceBase, aceRva);
            }
        }
    }

    /* 2. 二级 .data / 计数器对象深层函数指针校验 (捕获绕过 PG 的 InfinityHook 变种) */
    for (ULONG s = 0; s < s_HalSecSlotCount && s < HAL_SEC_MAX_SLOTS; s++)
    {
        PULONG_PTR pSecSlot = s_HalSecSlots[s].pDataPtrAddr;
        if (!pSecSlot || !Utils::IsValidKernelRange(pSecSlot, sizeof(ULONG_PTR)))
            continue;

        ULONG_PTR curFn = *pSecSlot;
        if (!curFn)
            continue;

        if (curFn != s_HalSecSlots[s].InitialTargetVa && (!IsAddressInKernelOrHal(curFn) || IsAddressInAceModules(curFn)))
        {
            WCHAR aceMod[32] = {0};
            ULONG_PTR aceBase = 0, aceRva = 0;
            ResolveAceModuleInfo(curFn, aceMod, &aceBase, &aceRva);
            alarms++;
            DBG("[!] [HOOK ALARM-HALSEC] Secondary DataPtr @ 0x%p (ParentSlot=%u) -> %ws Target=0x%p (+0x%llX)",
                (PVOID)pSecSlot, s_HalSecSlots[s].ParentSlotIdx, aceMod[0] ? aceMod : L"Foreign/ACE",
                (PVOID)curFn, aceRva);
            if (!(s_ReportedHalSecMask & (1U << s)))
            {
                s_ReportedHalSecMask |= (1U << s);
                ExceptionReporter::ReportFormat("ApiMonitor::HalSecondaryPtrHook", STATUS_SECURITY_CHECKS_FAILED,
                    "HAL Secondary DataPtr @ 0x%p (Parent=%u) Hooked -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                    (PVOID)pSecSlot, s_HalSecSlots[s].ParentSlotIdx, aceMod[0] ? aceMod : L"Foreign/ACE",
                    (PVOID)aceBase, aceRva);
            }
        }
    }

    return alarms;
}

/*
 * 维度 6: #PF 缺页异常链 (IDT[0x0E] -> KiPageFault -> MmAccessFault) 与 ETW PERF_CONTEXT_SWITCH 状态监控
 */
ULONG ApiMonitor::CheckPageFaultAndCswitchState(VOID)
{
    if (!g_KernelBase)
        return 0;

    ULONG alarms = 0;

    /* 1. 校验当前核 IDT[0x0E] (#PF) 门描述符是否被重定向 */
    if (s_InitialIdt0EHandler)
    {
        ULONG_PTR curIdt0E = ReadCurrentIdt0EHandler();
        if (curIdt0E && (curIdt0E != s_InitialIdt0EHandler || !IsAddressInKernelOrHal(curIdt0E) || IsAddressInAceModules(curIdt0E)))
        {
            WCHAR aceMod[32] = {0};
            ULONG_PTR aceBase = 0, aceRva = 0;
            ResolveAceModuleInfo(curIdt0E, aceMod, &aceBase, &aceRva);
            alarms++;
            DBG("[!] [HOOK ALARM-IDT0E] IDT[0x0E] (#PF) redirected! Cur=0x%p (Init=0x%p) -> %ws (+0x%llX)",
                (PVOID)curIdt0E, (PVOID)s_InitialIdt0EHandler, aceMod[0] ? aceMod : L"Foreign/ACE", aceRva);
            if (!s_ReportedIdt0E)
            {
                s_ReportedIdt0E = TRUE;
                ExceptionReporter::ReportFormat("ApiMonitor::IdtPageFaultHook", STATUS_SECURITY_CHECKS_FAILED,
                    "IDT[0x0E] (#PF) Hooked: Cur=0x%p (Init=0x%p) -> %ws (Base=0x%p +0x%llX)",
                    (PVOID)curIdt0E, (PVOID)s_InitialIdt0EHandler, aceMod[0] ? aceMod : L"Foreign/ACE",
                    (PVOID)aceBase, aceRva);
            }
        }
    }

    /* 2. 校验 KiPageFault 与内部调用的 MmAccessFault 等核心例程 (E8 call 偏移 + 入口跳板 + 32B 基线) */
    for (ULONG i = 0; i < s_PfChainCount && i < PF_CHAIN_MAX_TARGETS; i++)
    {
        ULONG_PTR fnVa = s_PfChainTargets[i].InitialVa;
        if (!fnVa || !Utils::IsValidKernelRange((PVOID)fnVa, API_BASELINE_SAMPLE_BYTES))
            continue;

        BOOLEAN bHooked = FALSE;
        ULONG_PTR hookTarget = fnVa;

        if (s_PfChainTargets[i].pRelCallDisp && Utils::IsValidKernelRange(s_PfChainTargets[i].pRelCallDisp, sizeof(LONG)))
        {
            LONG curDisp = *s_PfChainTargets[i].pRelCallDisp;
            if (curDisp != s_PfChainTargets[i].InitialDisp)
            {
                bHooked = TRUE;
                hookTarget = (ULONG_PTR)((PUCHAR)s_PfChainTargets[i].pRelCallDisp + 4 + curDisp);
            }
        }

        if (!bHooked)
        {
            BOOLEAN bTrap = FALSE;
            ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(fnVa, &bTrap);
            ULONG curHash = Utils::CalcAdler32((const UCHAR *)fnVa, API_BASELINE_SAMPLE_BYTES);
            if (bTrap || (inlineTarget && (IsAddressInAceModules(inlineTarget) || !IsAddressInKernelOrHal(inlineTarget))) ||
                (s_PfChainTargets[i].BaselineReady && curHash != s_PfChainTargets[i].BaselineAdler32))
            {
                bHooked = TRUE;
                if (inlineTarget)
                    hookTarget = inlineTarget;
            }
        }

        if (bHooked)
        {
            WCHAR aceMod[32] = {0};
            ULONG_PTR aceBase = 0, aceRva = 0;
            ResolveAceModuleInfo(hookTarget, aceMod, &aceBase, &aceRva);
            alarms++;
            DBG("[!] [HOOK ALARM-PFCHAIN] #PF Chain Target[%u] (0x%p) Hooked -> %ws Target=0x%p (+0x%llX)",
                i, (PVOID)fnVa, aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID)hookTarget, aceRva);
            if (!(s_ReportedPfChainMask & (1U << i)))
            {
                s_ReportedPfChainMask |= (1U << i);
                ExceptionReporter::ReportFormat("ApiMonitor::PageFaultChainHook", STATUS_SECURITY_CHECKS_FAILED,
                    "#PF Chain[%u] (0x%p, KiPageFault/MmAccessFault) Hooked -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                    i, (PVOID)fnVa, aceMod[0] ? aceMod : L"Foreign/ACE", (PVOID) hookTarget, (PVOID)aceBase, aceRva);
            }
        }
    }

    /* 3. 校验 PerfGlobalGroupMask 的 PERF_CONTEXT_SWITCH (0x20000004) 是否在 ACE 激活期间被开启 */
    if (g_bAceDetected && g_pPerfCswitchMaskDword && Utils::IsValidKernelRange(g_pPerfCswitchMaskDword, sizeof(ULONG)))
    {
        ULONG maskVal = *g_pPerfCswitchMaskDword;
        if ((maskVal & 0x00000004U) != 0)
        {
            alarms++;
            DBG("[!] [HOOK ALARM-CSWITCH] PerfGlobalGroupMask PERF_CONTEXT_SWITCH enabled! Mask=0x%08X @ 0x%p",
                maskVal, (PVOID)g_pPerfCswitchMaskDword);
            if (!s_ReportedPerfCswitch)
            {
                s_ReportedPerfCswitch = TRUE;
                ExceptionReporter::ReportFormat("ApiMonitor::EtwContextSwitchHook", STATUS_SECURITY_CHECKS_FAILED,
                    "ETW PERF_CONTEXT_SWITCH active in PerfGlobalGroupMask (Mask=0x%08X @ 0x%p)",
                    maskVal, (PVOID)g_pPerfCswitchMaskDword);
            }
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
    ULONG halAlarms = CheckHalAndSwapContextHooks();
    ULONG pfAlarms = CheckPageFaultAndCswitchState();
    ULONG total = apiAlarms + ssdtAlarms + iatAlarms + halAlarms + pfAlarms;

    if (total > 0)
    {
        DBG("[!] ApiMonitor [Round #%lu]: >>> THREAT DETECTED! Total=%u (API=%u, SSDT=%u, IAT=%u, HAL=%u, #PF/CSW=%u) <<<",
            s_apiScanRound, total, apiAlarms, ssdtAlarms, iatAlarms, halAlarms, pfAlarms);
    }
    else if (s_apiScanRound <= 3 || (s_apiScanRound % 5) == 0)
    {
        DBG("[+] ApiMonitor [Round #%lu]: All 28 APIs, 7 SSDT stubs, 7 IATs, %lu HAL slots, %lu SecPtrs & #PF chain intact",
            s_apiScanRound, s_HalSlotCount, s_HalSecSlotCount);

    }
}
