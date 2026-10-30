#include "ApiMonitor.h"
#include "DrvSecurity.h"
#include "ExceptionReporter.h"
#include "MachenikeString.h"
#include "Struct.h"
#include "TransportManager.h"
#include "Utils.h"
#include <intrin.h>

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
    {str_KfdGetRefCallout, TRUE},
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

/* ---- 维度 7: 硬件虚拟化 (VT / Hypervisor) 状态监控缓存 ---- */
static ULONG   s_InitVtMask = 0;
static ULONG   s_LastReportedVtMask = 0;
static CHAR    s_InitHvVendor[16] = {0};
static CHAR    s_LastReportedHvVendor[16] = {0};
static BOOLEAN s_VtBaselineReady = FALSE;
static BOOLEAN s_ReportedVtWithAce = FALSE;
static BOOLEAN s_ReportedAceVtMod = FALSE;

/* ---- 维度 8: DWM 桌面窗口管理器 (R3 dwm.exe + R0 dxgkrnl.sys) 截图 Hook 监控缓存 ---- */
#define DXGK_EXPORT_MONITOR_COUNT 6
#define DWM_CORE_MOD_COUNT        5
#define DWM_TEXT_PAGE_SAMPLE_MAX  64

typedef struct _DXGK_EXPORT_TARGET
{
    const char *Name;
    ULONG_PTR   InitialVa;
    ULONG       BaselineAdler32;
    BOOLEAN     BaselineReady;
} DXGK_EXPORT_TARGET;

static DXGK_EXPORT_TARGET s_DxgkExports[DXGK_EXPORT_MONITOR_COUNT] = {
    {"DxgkPresent", 0, 0, FALSE},
    {"DxgkOutputDuplPresent", 0, 0, FALSE},
    {"DxgkOutputDuplGetFrameInfo", 0, 0, FALSE},
    {"DxgkSubmitCommand", 0, 0, FALSE},
    {"DxgkGetSharedPrimaryHandle", 0, 0, FALSE},
    {"DxgkLock2", 0, 0, FALSE}
};

static ULONG_PTR g_DxgkrnlBase = 0;
static ULONG_PTR g_DxgkrnlEnd = 0;
static BOOLEAN   s_DxgkExportsResolved = FALSE;
static UINT32    s_ReportedDxgkExpMask = 0;
static UINT32    s_ReportedDxgkMajorMask = 0;
static BOOLEAN   s_ReportedDxgkIat = FALSE;
static BOOLEAN   s_ReportedDxgkAttached = FALSE;
static BOOLEAN   s_ReportedAceSscMod = FALSE;

typedef struct _DWM_MOD_BASELINE
{
    ULONG_PTR ModBase;
    ULONG     ModSize;
    ULONG     TextRva;
    ULONG     TextSize;
    ULONG     PageCount;
    BOOLEAN   BaselineReady;
    ULONG     PageAdler32[DWM_TEXT_PAGE_SAMPLE_MAX];
} DWM_MOD_BASELINE;

static HANDLE           s_CachedDwmPid = NULL;
static DWM_MOD_BASELINE s_DwmModBaselines[DWM_CORE_MOD_COUNT] = {0};
static UINT32           s_ReportedDwmIatMask = 0;
static UINT32           s_ReportedDwmExpMask = 0;
static UINT32           s_ReportedDwmTextMask = 0;
static ULONG            s_ReportedDwmInjHashes[8] = {0};
static BOOLEAN          s_ReportedCr4Ex = FALSE;
static BOOLEAN          s_ReportedDwmApiMissing = FALSE;
static BOOLEAN          s_ReportedDwmProcMissing = FALSE;
static BOOLEAN          s_ReportedDwmExitSyncFail = FALSE;
static BOOLEAN          s_ReportedDwmModsMissing = FALSE;
static BOOLEAN          s_ReportedDwmLdrHeadFail = FALSE;
static BOOLEAN          s_ReportedDwmPebFail = FALSE;
static BOOLEAN          s_ReportedDxgkMissing = FALSE;
static BOOLEAN          s_ReportedDxgkScanEx = FALSE;
static BOOLEAN          s_ReportedDxgkDrvEx = FALSE;
static BOOLEAN          s_ReportedDxgkOpenFail = FALSE;

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
    s_ReportedVtWithAce = FALSE;
    s_ReportedAceVtMod = FALSE;
    s_LastReportedVtMask = s_InitVtMask;
    RtlCopyMemory(s_LastReportedHvVendor, s_InitHvVendor, sizeof(s_LastReportedHvVendor));
    s_ReportedDxgkExpMask = 0;
    s_ReportedDxgkMajorMask = 0;
    s_ReportedDxgkIat = FALSE;
    s_ReportedDxgkAttached = FALSE;
    s_ReportedAceSscMod = FALSE;
    s_ReportedDwmIatMask = 0;
    s_ReportedDwmExpMask = 0;
    s_ReportedDwmTextMask = 0;
    RtlZeroMemory(s_ReportedDwmInjHashes, sizeof(s_ReportedDwmInjHashes));
    s_ReportedCr4Ex = FALSE;
    s_ReportedDwmApiMissing = FALSE;
    s_ReportedDwmProcMissing = FALSE;
    s_ReportedDwmExitSyncFail = FALSE;
    s_ReportedDwmModsMissing = FALSE;
    s_ReportedDwmLdrHeadFail = FALSE;
    s_ReportedDwmPebFail = FALSE;
    s_ReportedDxgkMissing = FALSE;
    s_ReportedDxgkScanEx = FALSE;
    s_ReportedDxgkDrvEx = FALSE;
    s_ReportedDxgkOpenFail = FALSE;
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
            NTSTATUS exCode = GetExceptionCode();
            ExceptionReporter::ReportFormat("ApiMonitor::LstarScanException", exCode,
                "Exception 0x%08X scanning LSTAR (0x%p) for SSDT", exCode, (PVOID)lstar);
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
            NTSTATUS exCode = GetExceptionCode();
            DBG("[-] ApiMonitor: Exception 0x%08X scanning for SSDT in kernel .text", exCode);
            ExceptionReporter::ReportFormat("ApiMonitor::SsdtScanException", exCode,
                "Exception 0x%08X scanning kernel .text for KeServiceDescriptorTable", exCode);
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
            NTSTATUS exCode = GetExceptionCode();
            ExceptionReporter::ReportFormat("ApiMonitor::PfChainScanException", exCode,
                "Exception 0x%08X scanning KiPageFault (0x%p) E8 call chain", exCode, (PVOID)s_InitialIdt0EHandler);
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
            NTSTATUS exCode = GetExceptionCode();
            ExceptionReporter::ReportFormat("ApiMonitor::CswitchScanException", exCode,
                "Exception 0x%08X scanning kernel .text for PerfGlobalGroupMask", exCode);
        }
    }
}

NTSTATUS ApiMonitor::Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PKLDR_DATA_TABLE_ENTRY DriverSection)
{
    g_pApiMonUserVar = UserVar;
    g_pApiMonDriverSection = DriverSection;
    ResetReportState();

    if (!UserVar || !DriverSection)
    {
        ExceptionReporter::Report("ApiMonitor::Init", STATUS_INVALID_PARAMETER, "UserVar or DriverSection is NULL");
        return STATUS_INVALID_PARAMETER;
    }

    PLIST_ENTRY pStartHead = &DriverSection->InLoadOrderLinks;
    PLIST_ENTRY pEntry = pStartHead;
    ULONG walkGuard = 0;
    do
    {
        if (!Utils::IsValidKernelRange(pEntry, sizeof(KLDR_DATA_TABLE_ENTRY)))
            break;
        PKLDR_DATA_TABLE_ENTRY pLdr = CONTAINING_RECORD(pEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (pLdr->DllBase && pLdr->BaseDllName.Buffer && pLdr->SizeOfImage > 0 &&
            Utils::IsValidKernelRange(pLdr->BaseDllName.Buffer, pLdr->BaseDllName.Length))
        {
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
            else if (!g_HalBase && (hash == wstr_Hal || MatchWideSubstrCaseless(pLdr->BaseDllName.Buffer, cch, L"hal")))
            {
                g_HalBase = (ULONG_PTR)pLdr->DllBase;
                g_HalEnd = g_HalBase + pLdr->SizeOfImage;
            }
            else if (!g_DxgkrnlBase && MatchWideSubstrCaseless(pLdr->BaseDllName.Buffer, cch, L"dxgkrnl"))
            {
                g_DxgkrnlBase = (ULONG_PTR)pLdr->DllBase;
                g_DxgkrnlEnd = g_DxgkrnlBase + pLdr->SizeOfImage;
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
        pEntry = pEntry->Flink;
    } while (pEntry && pEntry != pStartHead && ++walkGuard < 512);

    if (!g_KernelBase && UserVar->KernelBase.QuadPart != 0)
    {
        g_KernelBase = (ULONG_PTR)UserVar->KernelBase.QuadPart;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_KernelBase;
        if (Utils::IsValidKernelRange(pDos, PAGE_SIZE) && pDos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(g_KernelBase + pDos->e_lfanew);
            if (Utils::IsValidKernelRange(pNt, sizeof(IMAGE_NT_HEADERS64)) && pNt->Signature == IMAGE_NT_SIGNATURE)
                g_KernelEnd = g_KernelBase + pNt->OptionalHeader.SizeOfImage;
        }
    }

    if (!g_KernelBase || !g_NetioBase)
    {
        ExceptionReporter::ReportFormat("ApiMonitor::InitModuleMissing", STATUS_NOT_FOUND,
            "ApiMonitor missing core module base: Kernel=0x%p Netio=0x%p Hal=0x%p",
            (PVOID)g_KernelBase, (PVOID)g_NetioBase, (PVOID)g_HalBase);
    }

    ULONG failedApiCount = 0;
    ULONG firstFailedSlot = 0xFFFFFFFFU;
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
        else
        {
            failedApiCount++;
            if (firstFailedSlot == 0xFFFFFFFFU)
                firstFailedSlot = i;
        }
    }

    if (failedApiCount > 0)
    {
        ExceptionReporter::ReportFormat("ApiMonitor::InitTargetFailed", STATUS_PROCEDURE_NOT_FOUND,
            "ApiMonitor failed to resolve %lu/%u target APIs (firstSlot=%lu)",
            failedApiCount, (ULONG)API_MONITOR_COUNT, firstFailedSlot);
    }

    /* 关键双阶段分离：初始化完成后立即将 s_InitApiTable 物理原位清零，阅后即焚 */
    RtlSecureZeroMemory(s_InitApiTable, sizeof(s_InitApiTable));

    if (!LocateKeServiceDescriptorTable() || !g_pSsdtServiceTable)
    {
        ExceptionReporter::Report("ApiMonitor::InitSsdtFailed", STATUS_NOT_FOUND,
            "Failed to locate KeServiceDescriptorTable during ApiMonitor::Init");
    }
    if (g_KernelBase)
    {
        Utils::GetModuleTextSection(g_KernelBase, &g_KernelTextStart, &g_KernelTextEnd);
    }
    InitHalAndSwapContextTargets();
    InitPageFaultAndCswitchTargets();
    if (s_HalSlotCount == 0)
    {
        ExceptionReporter::Report("ApiMonitor::InitHalFailed", STATUS_NOT_FOUND,
            "Failed to baseline HalDispatchTable slots during ApiMonitor::Init");
    }
    if (s_PfChainCount == 0)
    {
        ExceptionReporter::Report("ApiMonitor::InitPfChainFailed", STATUS_NOT_FOUND,
            "Failed to baseline IDT 0x0E KiPageFault chain during ApiMonitor::Init");
    }
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
            static UINT32 s_ReportedIatExMask = 0;
            NTSTATUS exCode = GetExceptionCode();
            if (!(s_ReportedIatExMask & (1U << d)))
            {
                s_ReportedIatExMask |= (1U << d);
                ExceptionReporter::ReportFormat("ApiMonitor::IatScanException", exCode,
                    "Exception 0x%08X scanning IAT of SysDrv[%u] (Base=0x%p)", exCode, d, (PVOID)drvBase);
            }
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

/*
 * 维度 7: CPU 硬件虚拟化 (Intel VT-x / AMD-V / Hypervisor) 开启状态与 ACE VT 模块监控
 */
static VOID QueryHardwareVtSnapshot(
    _Out_ PULONG pOutMask,
    _Out_writes_(16) PCHAR outVendor,
    _Out_writes_(32) PWCHAR outAceVtMod,
    _Out_ PULONG_PTR pOutAceVtBase)
{
    ULONG mask = 0;
    RtlZeroMemory(outVendor, 16);
    RtlZeroMemory(outAceVtMod, 32 * sizeof(WCHAR));
    *pOutAceVtBase = 0;

    __try
    {
        ULONG64 cr4 = __readcr4();
        if ((cr4 & (1ULL << 13)) != 0)
            mask |= 0x01U; /* CR4.VMXE (Intel VT-x) */
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /* uses file-scope s_ReportedCr4Ex */
        NTSTATUS exCode = GetExceptionCode();
        if (!s_ReportedCr4Ex)
        {
            s_ReportedCr4Ex = TRUE;
            ExceptionReporter::ReportFormat("ApiMonitor::ReadCr4Exception", exCode,
                "Exception 0x%08X reading CR4 in QueryHardwareVtSnapshot", exCode);
        }
    }

    ULONG64 efer = 0;
    if (MachenikeReadMsrSafe(0xC0000080, &efer) && (efer & (1ULL << 12)) != 0)
        mask |= 0x02U; /* EFER.SVME (AMD-V) */

    ULONG64 hsavePa = 0;
    if (MachenikeReadMsrSafe(0xC0010117, &hsavePa) && hsavePa != 0)
        mask |= 0x04U; /* VM_HSAVE_PA active (AMD-V Host Save Area) */

    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & (1 << 31)) != 0)
    {
        mask |= 0x08U; /* CPUID.1:ECX[31] Hypervisor Present */
        int hvInfo[4] = {0};
        __cpuid(hvInfo, 0x40000000);
        RtlCopyMemory(&outVendor[0], &hvInfo[1], 4);
        RtlCopyMemory(&outVendor[4], &hvInfo[2], 4);
        RtlCopyMemory(&outVendor[8], &hvInfo[3], 4);
        outVendor[12] = '\0';
        for (int k = 0; k < 12; k++)
        {
            if (outVendor[k] != '\0' && (outVendor[k] < 0x20 || outVendor[k] > 0x7E))
                outVendor[k] = '?';
        }
    }
    else
    {
        SafeStrncpy(outVendor, 16, "None");
    }

    if (g_bAceDetected)
    {
        for (ULONG i = 0; i < g_AceModuleCount && i < ACE_MAX_TRACKED_MODULES; i++)
        {
            ULONG cch = 0;
            while (cch < 31 && g_AceModules[i].Name[cch] != L'\0')
                cch++;
            if (MatchWideSubstrCaseless(g_AceModules[i].Name, cch, L"ADVT") ||
                MatchWideSubstrCaseless(g_AceModules[i].Name, cch, L"ACE_VT") ||
                MatchWideSubstrCaseless(g_AceModules[i].Name, cch, L"ACE-VT"))
            {
                mask |= 0x10U; /* ACE VT 驱动模块在列 */
                *pOutAceVtBase = g_AceModules[i].Base;
                for (ULONG c = 0; c <= cch && c < 31; c++)
                    outAceVtMod[c] = g_AceModules[i].Name[c];
                outAceVtMod[31] = L'\0';
                break;
            }
        }
    }

    *pOutMask = mask;
}

ULONG ApiMonitor::CheckHardwareVtState(VOID)
{
    ULONG curMask = 0;
    CHAR curVendor[16] = {0};
    WCHAR aceVtMod[32] = {0};
    ULONG_PTR aceVtBase = 0;

    QueryHardwareVtSnapshot(&curMask, curVendor, aceVtMod, &aceVtBase);

    if (!s_VtBaselineReady)
    {
        s_InitVtMask = curMask;
        s_LastReportedVtMask = curMask;
        RtlCopyMemory(s_InitHvVendor, curVendor, sizeof(s_InitHvVendor));
        RtlCopyMemory(s_LastReportedHvVendor, curVendor, sizeof(s_LastReportedHvVendor));
        s_VtBaselineReady = TRUE;
    }

    ULONG alarms = 0;
    BOOLEAN bChanged = (curMask != s_LastReportedVtMask) ||
                       (SafeStrnicmp(curVendor, s_LastReportedHvVendor, 12) != 0);
    BOOLEAN bAceVtNew = ((curMask & 0x10U) != 0 && !s_ReportedAceVtMod);
    BOOLEAN bReportUnderAce = (g_bAceDetected && curMask != 0 && !s_ReportedVtWithAce);

    if (bChanged || bAceVtNew || bReportUnderAce)
    {
        s_LastReportedVtMask = curMask;
        RtlCopyMemory(s_LastReportedHvVendor, curVendor, sizeof(s_LastReportedHvVendor));
        if ((curMask & 0x10U) != 0)
            s_ReportedAceVtMod = TRUE;
        if (g_bAceDetected)
            s_ReportedVtWithAce = TRUE;

        /* 若开启了非初始的硬件 VT (VMXE/SVME/HSAVE 突变) 或检测到 ACE_ADVT，计入威胁告警 */
        if ((curMask & 0x10U) != 0 || ((curMask & 0x07U) != (s_InitVtMask & 0x07U)))
            alarms++;

        if (aceVtBase)
            InterlockedExchange64(&g_LastResolvedAceAddr, (LONGLONG)aceVtBase);

        ExceptionReporter::ReportFormat("ApiMonitor::HardwareVtState",
            alarms > 0 ? STATUS_SECURITY_CHECKS_FAILED : STATUS_SUCCESS,
            "VT State: Mask=0x%02X (Init=0x%02X) [VMXE=%u SVME=%u HSAVE=%u HV=%u Vendor='%s' AceVT=%ws]",
            curMask, s_InitVtMask,
            (curMask & 0x01U) ? 1 : 0,
            (curMask & 0x02U) ? 1 : 0,
            (curMask & 0x04U) ? 1 : 0,
            (curMask & 0x08U) ? 1 : 0,
            curVendor,
            aceVtMod[0] ? aceVtMod : L"None");
    }

    return alarms;
}

/*
 * 维度 8: DWM 桌面窗口管理器截图链路 (R0 dxgkrnl.sys + R3 dwm.exe) Hook 监控
 */
typedef NTSTATUS(NTAPI *PFN_MmCopyVirtualMemory)(
    _In_ PEPROCESS FromProcess,
    _In_ PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _Out_writes_bytes_(BufferSize) PVOID ToAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T NumberOfBytesCopied);

typedef PVOID(NTAPI *PFN_PsGetProcessPeb)(_In_ PEPROCESS Process);

static PFN_MmCopyVirtualMemory s_pfnMmCopyVirtualMemory = NULL;
static PFN_PsGetProcessPeb     s_pfnPsGetProcessPeb = NULL;

static BOOLEAN ReadUserProcessMemorySafe(
    _In_ PEPROCESS Process,
    _In_ ULONG_PTR UserVa,
    _Out_writes_bytes_(Size) PVOID OutBuf,
    _In_ SIZE_T Size)
{
    if (!Process || !UserVa || !OutBuf || Size == 0 || UserVa >= 0x00007FFFFFFF0000ULL)
        return FALSE;
    if (!s_pfnMmCopyVirtualMemory || !g_pApiMonUserVar || !g_pApiMonUserVar->Func.IoGetCurrentProcess)
        return FALSE;

    SIZE_T bytesCopied = 0;
    NTSTATUS st = s_pfnMmCopyVirtualMemory(
        Process,
        (PVOID)UserVa,
        g_pApiMonUserVar->Func.IoGetCurrentProcess(),
        OutBuf,
        Size,
        KernelMode,
        &bytesCopied);
    return NT_SUCCESS(st) && (bytesCopied == Size);
}

static BOOLEAN IsDwmImageName(_In_opt_ const CHAR *ImageName)
{
    if (!ImageName)
        return FALSE;
    static const CHAR kDwm[] = "dwm.exe";
    for (ULONG i = 0; i < 7; i++)
    {
        CHAR c = ImageName[i];
        if (c >= 'A' && c <= 'Z')
            c += 32;
        if (c != kDwm[i])
            return FALSE;
    }
    return ImageName[7] == '\0';
}

static PEPROCESS LookupActiveDwmProcess(VOID)
{
    if (!g_pApiMonUserVar || !g_pApiMonUserVar->Func.PsLookupProcessByProcessId ||
        !g_pApiMonUserVar->Func.PsGetProcessImageFileName ||
        !g_pApiMonUserVar->Func.PsGetProcessExitStatus ||
        !g_pApiMonUserVar->Func.ObfDereferenceObject)
    {
        return NULL;
    }

    if (s_CachedDwmPid != NULL)
    {
        PEPROCESS cachedProc = NULL;
        if (NT_SUCCESS(g_pApiMonUserVar->Func.PsLookupProcessByProcessId(s_CachedDwmPid, &cachedProc)) && cachedProc)
        {
            if (g_pApiMonUserVar->Func.PsGetProcessExitStatus(cachedProc) == STATUS_PENDING &&
                IsDwmImageName((const CHAR *)g_pApiMonUserVar->Func.PsGetProcessImageFileName(cachedProc)))
            {
                return cachedProc;
            }
            g_pApiMonUserVar->Func.ObfDereferenceObject(cachedProc);
        }
        s_CachedDwmPid = NULL;
    }

    for (ULONG_PTR pid = 4; pid <= 0x40000; pid += 4)
    {
        PEPROCESS proc = NULL;
        if (!NT_SUCCESS(g_pApiMonUserVar->Func.PsLookupProcessByProcessId((HANDLE)pid, &proc)) || !proc)
            continue;

        if (g_pApiMonUserVar->Func.PsGetProcessExitStatus(proc) == STATUS_PENDING &&
            IsDwmImageName((const CHAR *)g_pApiMonUserVar->Func.PsGetProcessImageFileName(proc)))
        {
            s_CachedDwmPid = (HANDLE)pid;
            RtlZeroMemory(s_DwmModBaselines, sizeof(s_DwmModBaselines));
            return proc;
        }
        g_pApiMonUserVar->Func.ObfDereferenceObject(proc);
    }

    return NULL;
}

typedef struct _DWM_LOADED_MOD_RANGE
{
    ULONG_PTR Base;
    ULONG_PTR End;
} DWM_LOADED_MOD_RANGE;

static BOOLEAN IsAddressInDwmModules(
    _In_ ULONG_PTR Va,
    _In_reads_(ModCount) const DWM_LOADED_MOD_RANGE *Mods,
    _In_ ULONG ModCount)
{
    for (ULONG i = 0; i < ModCount; i++)
    {
        if (Va >= Mods[i].Base && Va < Mods[i].End)
            return TRUE;
    }
    return FALSE;
}

typedef struct _DWM_RUNTIME_FUNCTION_ENTRY
{
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} DWM_RUNTIME_FUNCTION_ENTRY;

static BOOLEAN IsMappedDwmTrampoline(_In_ PEPROCESS DwmProc, _In_ ULONG_PTR TargetVa)
{
    if (TargetVa < 0x10000ULL || TargetVa >= 0x00007FFFFFFF0000ULL)
        return FALSE;
    UCHAR probe[16] = {0};
    if (!ReadUserProcessMemorySafe(DwmProc, TargetVa, probe, sizeof(probe)))
        return FALSE;
    for (ULONG i = 0; i < sizeof(probe); i++)
    {
        if (probe[i] != 0x00 && probe[i] != 0xCC)
            return TRUE;
    }
    return FALSE;
}

static ULONG DecodeUserModeHookTarget(
    _In_ ULONG_PTR CodeVa,
    _In_reads_bytes_(16) const UCHAR *Bytes,
    _Out_ PULONG_PTR pOutTarget)
{
    *pOutTarget = 0;
    ULONG_PTR target = 0;
    ULONG hookType = 0;
    /* 1. E9 <disp32> 相对跳转 */
    if (Bytes[0] == 0xE9)
    {
        LONG disp = *(const LONG *)(Bytes + 1);
        target = (ULONG_PTR)((LONG_PTR)(CodeVa + 5) + disp);
        hookType = 1;
    }
    /* 2. FF 25 00 00 00 00 <abs64> 绝对间接跳转 */
    else if (Bytes[0] == 0xFF && Bytes[1] == 0x25 && *(const LONG *)(Bytes + 2) == 0)
    {
        target = *(const ULONG_PTR *)(Bytes + 6);
        hookType = 2;
    }
    /* 3. 48 B8 <abs64> FF E0 (mov rax, imm64; jmp rax) */
    else if (Bytes[0] == 0x48 && Bytes[1] == 0xB8 && Bytes[10] == 0xFF && Bytes[11] == 0xE0)
    {
        target = *(const ULONG_PTR *)(Bytes + 2);
        hookType = 3;
    }
    /* 4. 50 48 B8 <abs64> 48 87 04 24 C3 (push rax; mov rax, imm64; xchg [rsp], rax; ret) */
    else if (Bytes[0] == 0x50 && Bytes[1] == 0x48 && Bytes[2] == 0xB8 &&
             Bytes[11] == 0x48 && Bytes[12] == 0x87 && Bytes[13] == 0x04 && Bytes[14] == 0x24 && Bytes[15] == 0xC3)
    {
        target = *(const ULONG_PTR *)(Bytes + 3);
        hookType = 4;
    }

    if (hookType != 0 && target >= 0x10000ULL && target < 0x00007FFFFFFF0000ULL)
    {
        *pOutTarget = target;
        return hookType;
    }
    return 0;
}

static ULONG ScanDwmUserProcessHooks(VOID)
{
    if (!g_pApiMonUserVar || !g_pApiMonUserVar->Func.KeGetCurrentIrql ||
        g_pApiMonUserVar->Func.KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return 0;
    }

    if (!s_pfnMmCopyVirtualMemory && g_KernelBase)
    {
        ULONG_PTR fnVa = 0;
        if (Utils::GetModuleExport(g_KernelBase, 0xD63B7937U /* MmCopyVirtualMemory */, &fnVa))
            s_pfnMmCopyVirtualMemory = (PFN_MmCopyVirtualMemory)fnVa;
    }
    if (!s_pfnPsGetProcessPeb && g_KernelBase)
    {
        ULONG_PTR fnVa = 0;
        ULONG pebHash = Utils::HashStringA((PCHAR)"PsGetProcessPeb", 15, TRUE);
        if (Utils::GetModuleExport(g_KernelBase, pebHash, &fnVa))
            s_pfnPsGetProcessPeb = (PFN_PsGetProcessPeb)fnVa;
    }

    if (!s_pfnMmCopyVirtualMemory || !s_pfnPsGetProcessPeb ||
        !g_pApiMonUserVar->Func.PsAcquireProcessExitSynchronization ||
        !g_pApiMonUserVar->Func.PsReleaseProcessExitSynchronization)
    {
        /* uses file-scope s_ReportedDwmApiMissing */
        if (!s_ReportedDwmApiMissing)
        {
            s_ReportedDwmApiMissing = TRUE;
            ExceptionReporter::ReportFormat("ApiMonitor::DwmApiResolveFailed", STATUS_PROCEDURE_NOT_FOUND,
                "DWM monitor missing kernel API: MmCopyVirtualMemory=0x%p PsGetProcessPeb=0x%p ExitSync=0x%p",
                (PVOID)s_pfnMmCopyVirtualMemory, (PVOID)s_pfnPsGetProcessPeb,
                (PVOID)(g_pApiMonUserVar ? g_pApiMonUserVar->Func.PsAcquireProcessExitSynchronization : NULL));
        }
        return 0;
    }

    PEPROCESS dwmProc = LookupActiveDwmProcess();
    if (!dwmProc)
    {
        /* uses file-scope s_ReportedDwmProcMissing */
        if (g_bAceDetected && !s_ReportedDwmProcMissing)
        {
            s_ReportedDwmProcMissing = TRUE;
            ExceptionReporter::Report("ApiMonitor::DwmProcessNotFound", STATUS_NOT_FOUND,
                "Failed to locate active dwm.exe process during DWM hook scan");
        }
        return 0;
    }

    NTSTATUS syncSt = g_pApiMonUserVar->Func.PsAcquireProcessExitSynchronization(dwmProc);
    if (!NT_SUCCESS(syncSt))
    {
        /* uses file-scope s_ReportedDwmExitSyncFail */
        if (g_bAceDetected && !s_ReportedDwmExitSyncFail)
        {
            s_ReportedDwmExitSyncFail = TRUE;
            ExceptionReporter::ReportFormat("ApiMonitor::DwmExitSyncFailed", syncSt,
                "PsAcquireProcessExitSynchronization failed for dwm.exe (PID=%llu, status=0x%08X)",
                (ULONG64)(ULONG_PTR)s_CachedDwmPid, syncSt);
        }
        g_pApiMonUserVar->Func.ObfDereferenceObject(dwmProc);
        return 0;
    }

    ULONG alarms = 0;
    ULONG_PTR pebAddr = (ULONG_PTR)s_pfnPsGetProcessPeb(dwmProc);
    ULONG_PTR ldrAddr = 0;
    if (pebAddr && ReadUserProcessMemorySafe(dwmProc, pebAddr + 0x18, &ldrAddr, sizeof(ldrAddr)) && ldrAddr)
    {
        LIST_ENTRY headLinks = {0};
        ULONG_PTR listHeadVa = ldrAddr + 0x10; /* PEB_LDR_DATA.InLoadOrderModuleList */
        if (ReadUserProcessMemorySafe(dwmProc, listHeadVa, &headLinks, sizeof(headLinks)))
        {
            DWM_LOADED_MOD_RANGE allMods[160] = {0};
            ULONG allModCount = 0;

            static const PCWSTR kTargetDwmDlls[DWM_CORE_MOD_COUNT] = {
                L"dwmcore.dll",
                L"dxgi.dll",
                L"d3d11.dll",
                L"udwm.dll",
                L"win32u.dll"
            };
            static const PCSTR kTargetDwmNamesA[DWM_CORE_MOD_COUNT] = {
                "dwmcore.dll",
                "dxgi.dll",
                "d3d11.dll",
                "udwm.dll",
                "win32u.dll"
            };

            ULONG_PTR targetModBases[DWM_CORE_MOD_COUNT] = {0};
            ULONG targetModSizes[DWM_CORE_MOD_COUNT] = {0};

            ULONG_PTR curLink = (ULONG_PTR)headLinks.Flink;
            for (ULONG step = 0; step < 160 && curLink && curLink != listHeadVa; step++)
            {
                UCHAR ldrEntryBuf[0x70] = {0};
                if (!ReadUserProcessMemorySafe(dwmProc, curLink, ldrEntryBuf, sizeof(ldrEntryBuf)))
                    break;

                ULONG_PTR nextLink = *(ULONG_PTR *)(ldrEntryBuf + 0x00);
                ULONG_PTR dllBase = *(ULONG_PTR *)(ldrEntryBuf + 0x30);
                ULONG sizeOfImage = *(ULONG *)(ldrEntryBuf + 0x40);
                USHORT nameLen = *(USHORT *)(ldrEntryBuf + 0x58);
                ULONG_PTR nameBufPtr = *(ULONG_PTR *)(ldrEntryBuf + 0x60);

                if (dllBase && sizeOfImage > 0 && sizeOfImage < 0x20000000U)
                {
                    if (allModCount < 160)
                    {
                        allMods[allModCount].Base = dllBase;
                        allMods[allModCount].End = dllBase + sizeOfImage;
                        allModCount++;
                    }

                    if (nameBufPtr && nameLen > 0 && nameLen <= 120)
                    {
                        WCHAR modNameW[64] = {0};
                        ULONG copyBytes = (nameLen < 120) ? nameLen : 120;
                        if (ReadUserProcessMemorySafe(dwmProc, nameBufPtr, modNameW, copyBytes))
                        {
                            ULONG cch = copyBytes / sizeof(WCHAR);
                            modNameW[cch] = L'\0';

                            for (ULONG t = 0; t < DWM_CORE_MOD_COUNT; t++)
                            {
                                if (targetModBases[t] == 0 && MatchWideSubstrCaseless(modNameW, cch, kTargetDwmDlls[t]))
                                {
                                    targetModBases[t] = dllBase;
                                    targetModSizes[t] = sizeOfImage;
                                }
                            }

                            /* 检测注入到 dwm.exe 的可疑反作弊或截屏 Hook 模块 */
                            if (MatchWideSubstrCaseless(modNameW, cch, L"ace") ||
                                MatchWideSubstrCaseless(modNameW, cch, L"sguard") ||
                                MatchWideSubstrCaseless(modNameW, cch, L"tensafe") ||
                                MatchWideSubstrCaseless(modNameW, cch, L"gameoverlay") ||
                                MatchWideSubstrCaseless(modNameW, cch, L"dxhook"))
                            {
                                ULONG injHash = Utils::HashStringW(modNameW, cch, TRUE);
                                BOOLEAN bSeen = FALSE;
                                for (ULONG h = 0; h < 8; h++)
                                {
                                    if (s_ReportedDwmInjHashes[h] == injHash)
                                    {
                                        bSeen = TRUE;
                                        break;
                                    }
                                    if (s_ReportedDwmInjHashes[h] == 0)
                                    {
                                        s_ReportedDwmInjHashes[h] = injHash;
                                        break;
                                    }
                                }
                                alarms++;
                                if (!bSeen)
                                {
                                    ExceptionReporter::ReportFormat("ApiMonitor::DwmInjectedModule", STATUS_SECURITY_CHECKS_FAILED,
                                        "DWM Injected Module: %ws loaded in dwm.exe (PID=%llu) @ [0x%p-0x%p]",
                                        modNameW, (ULONG64)(ULONG_PTR)s_CachedDwmPid, (PVOID)dllBase, (PVOID)(dllBase + sizeOfImage));
                                }
                            }
                        }
                    }
                }

                curLink = nextLink;
            }

            /* 逐个扫描 dwmcore.dll / dxgi.dll / d3d11.dll / udwm.dll / win32u.dll */
            for (ULONG m = 0; m < DWM_CORE_MOD_COUNT; m++)
            {
                ULONG_PTR modBase = targetModBases[m];
                ULONG modSize = targetModSizes[m];
                if (!modBase || modSize < PAGE_SIZE)
                    continue;

                UCHAR peHdr[0x600] = {0};
                if (!ReadUserProcessMemorySafe(dwmProc, modBase, peHdr, sizeof(peHdr)))
                    continue;

                PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)peHdr;
                if (pDos->e_magic != IMAGE_DOS_SIGNATURE || pDos->e_lfanew <= 0 || pDos->e_lfanew > 0x380)
                    continue;

                PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(peHdr + pDos->e_lfanew);
                if (pNt->Signature != IMAGE_NT_SIGNATURE || pNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    continue;

                /* 1. 校验 DWM 核心模块的 IAT 指针是否被重定向到未知私有内存 (VTable/IAT Hook) */
                IMAGE_DATA_DIRECTORY impDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (impDir.VirtualAddress > 0 && impDir.VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) < modSize)
                {
                    IMAGE_IMPORT_DESCRIPTOR impDescs[24] = {0};
                    ULONG readDescs = (impDir.Size < sizeof(impDescs)) ? impDir.Size : sizeof(impDescs);
                    if (ReadUserProcessMemorySafe(dwmProc, modBase + impDir.VirtualAddress, impDescs, readDescs))
                    {
                        for (ULONG d = 0; d < 24 && impDescs[d].FirstThunk != 0; d++)
                        {
                            if (impDescs[d].FirstThunk >= modSize)
                                break;
                            ULONG_PTR iatSlots[64] = {0};
                            if (!ReadUserProcessMemorySafe(dwmProc, modBase + impDescs[d].FirstThunk, iatSlots, sizeof(iatSlots)))
                                continue;
                            for (ULONG s = 0; s < 64 && iatSlots[s] != 0; s++)
                            {
                                ULONG_PTR targetVa = iatSlots[s];
                                if (!IsAddressInDwmModules(targetVa, allMods, allModCount))
                                {
                                    alarms++;
                                    if (!(s_ReportedDwmIatMask & (1U << m)))
                                    {
                                        s_ReportedDwmIatMask |= (1U << m);
                                        ExceptionReporter::ReportFormat("ApiMonitor::DwmIatHook", STATUS_SECURITY_CHECKS_FAILED,
                                            "DWM IAT Hook: %s IAT(RVA=0x%X) redirected outside modules -> 0x%p",
                                            kTargetDwmNamesA[m], (ULONG)(impDescs[d].FirstThunk + s * 8), (PVOID)targetVa);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                /* 2. 校验导出函数入口是否被挂接 (E9 / FF 25 / mov rax, imm64; jmp rax) */
                IMAGE_DATA_DIRECTORY expDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (expDir.VirtualAddress > 0 && expDir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) < modSize)
                {
                    IMAGE_EXPORT_DIRECTORY expHdr = {0};
                    if (ReadUserProcessMemorySafe(dwmProc, modBase + expDir.VirtualAddress, &expHdr, sizeof(expHdr)) &&
                        expHdr.NumberOfFunctions > 0 && expHdr.AddressOfFunctions < modSize)
                    {
                        ULONG fnCount = (expHdr.NumberOfFunctions < 192) ? expHdr.NumberOfFunctions : 192;
                        ULONG fnRvas[192] = {0};
                        if (ReadUserProcessMemorySafe(dwmProc, modBase + expHdr.AddressOfFunctions, fnRvas, fnCount * sizeof(ULONG)))
                        {
                            for (ULONG f = 0; f < fnCount; f++)
                            {
                                ULONG rva = fnRvas[f];
                                if (!rva || rva >= modSize || (rva >= expDir.VirtualAddress && rva < expDir.VirtualAddress + expDir.Size))
                                    continue;

                                UCHAR fnBytes[16] = {0};
                                if (!ReadUserProcessMemorySafe(dwmProc, modBase + rva, fnBytes, sizeof(fnBytes)))
                                    continue;

                                ULONG_PTR jmpTarget = 0;
                                ULONG hookType = DecodeUserModeHookTarget(modBase + rva, fnBytes, &jmpTarget);
                                if (hookType != 0 &&
                                    (jmpTarget < modBase || jmpTarget >= modBase + modSize) &&
                                    !IsAddressInDwmModules(jmpTarget, allMods, allModCount) &&
                                    IsMappedDwmTrampoline(dwmProc, jmpTarget))
                                {
                                    alarms++;
                                    if (!(s_ReportedDwmExpMask & (1U << m)))
                                    {
                                        s_ReportedDwmExpMask |= (1U << m);
                                        ExceptionReporter::ReportFormat("ApiMonitor::DwmExportHook", STATUS_SECURITY_CHECKS_FAILED,
                                            "DWM Export Hook: %s+0x%X hooked (Type=%u, Bytes=%02X %02X %02X %02X %02X) -> Target=0x%p",
                                            kTargetDwmNamesA[m], rva, hookType,
                                            fnBytes[0], fnBytes[1], fnBytes[2], fnBytes[3], fnBytes[4], (PVOID)jmpTarget);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                /* 3. 定位 .text 节：执行前 64 页 (256KB) Adler32 基线比对 + 基于 .pdata 函数入口的 Trampoline 扫描 */
                ULONG textRva = pNt->OptionalHeader.BaseOfCode;
                ULONG textSize = pNt->OptionalHeader.SizeOfCode;
                USHORT numSecs = pNt->FileHeader.NumberOfSections;
                PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
                if (numSecs > 0 && numSecs <= 16 &&
                    ((PUCHAR)(pSec + numSecs) <= peHdr + sizeof(peHdr)))
                {
                    for (USHORT sc = 0; sc < numSecs; sc++)
                    {
                        if ((pSec[sc].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && pSec[sc].VirtualAddress > 0)
                        {
                            textRva = pSec[sc].VirtualAddress;
                            textSize = pSec[sc].Misc.VirtualSize ? pSec[sc].Misc.VirtualSize : pSec[sc].SizeOfRawData;
                            break;
                        }
                    }
                }

                if (textRva > 0 && textSize >= PAGE_SIZE && textRva + PAGE_SIZE <= modSize)
                {
                    ULONG maxPages = (textSize / PAGE_SIZE);
                    if (maxPages > DWM_TEXT_PAGE_SAMPLE_MAX)
                        maxPages = DWM_TEXT_PAGE_SAMPLE_MAX;

                    if (s_DwmModBaselines[m].ModBase != modBase)
                    {
                        RtlZeroMemory(&s_DwmModBaselines[m], sizeof(DWM_MOD_BASELINE));
                        s_DwmModBaselines[m].ModBase = modBase;
                        s_DwmModBaselines[m].ModSize = modSize;
                        s_DwmModBaselines[m].TextRva = textRva;
                        s_DwmModBaselines[m].TextSize = textSize;
                        s_DwmModBaselines[m].PageCount = maxPages;
                    }

                    IMAGE_DATA_DIRECTORY excDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                    ULONG pdataRva = excDir.VirtualAddress;
                    ULONG pdataCount = (pdataRva > 0 && excDir.Size >= sizeof(DWM_RUNTIME_FUNCTION_ENTRY) &&
                                        pdataRva < modSize && excDir.Size <= modSize - pdataRva)
                                           ? (excDir.Size / sizeof(DWM_RUNTIME_FUNCTION_ENTRY))
                                           : 0;
                    if (pdataCount > 16384)
                        pdataCount = 16384;
                    DWM_RUNTIME_FUNCTION_ENTRY pdataChunk[32] = {0};
                    ULONG pdataIdx = 0;
                    ULONG pdataChunkBase = 0;
                    ULONG pdataChunkValid = 0;

                    UCHAR pageBuf[PAGE_SIZE];
                    for (ULONG p = 0; p < maxPages; p++)
                    {
                        ULONG pageRva = textRva + p * PAGE_SIZE;
                        ULONG pageEndRva = pageRva + PAGE_SIZE;
                        if (!ReadUserProcessMemorySafe(dwmProc, modBase + pageRva, pageBuf, PAGE_SIZE))
                            continue;

                        ULONG pageHash = Utils::CalcAdler32(pageBuf, PAGE_SIZE);
                        if (!s_DwmModBaselines[m].BaselineReady)
                        {
                            s_DwmModBaselines[m].PageAdler32[p] = pageHash;
                        }
                        else if (s_DwmModBaselines[m].PageAdler32[p] != 0 &&
                                 pageHash != s_DwmModBaselines[m].PageAdler32[p])
                        {
                            ULONG hookRva = pageRva;
                            ULONG_PTR hookTarget = 0;
                            for (ULONG off = 0; off + 16 <= PAGE_SIZE; off++)
                            {
                                ULONG_PTR candTarget = 0;
                                if (DecodeUserModeHookTarget(modBase + pageRva + off, &pageBuf[off], &candTarget) != 0 &&
                                    (candTarget < modBase || candTarget >= modBase + modSize) &&
                                    IsMappedDwmTrampoline(dwmProc, candTarget))
                                {
                                    hookRva = pageRva + off;
                                    hookTarget = candTarget;
                                    break;
                                }
                            }
                            alarms++;
                            if (!(s_ReportedDwmTextMask & (1U << m)))
                            {
                                s_ReportedDwmTextMask |= (1U << m);
                                ExceptionReporter::ReportFormat("ApiMonitor::DwmTextHook", STATUS_SECURITY_CHECKS_FAILED,
                                    "DWM .text Patched: %s+0x%X (Page=%lu, Hash=0x%08X!=0x%08X, Target=0x%p)",
                                    kTargetDwmNamesA[m], hookRva, p, pageHash, s_DwmModBaselines[m].PageAdler32[p], (PVOID)hookTarget);
                            }
                            break;
                        }

                        /* 仅在 .pdata (IMAGE_DIRECTORY_ENTRY_EXCEPTION) 记录的真实函数入口点检测跨模块 Trampoline 跳板 */
                        while (pdataIdx < pdataCount)
                        {
                            if (pdataIdx >= pdataChunkBase + pdataChunkValid)
                            {
                                ULONG toRead = pdataCount - pdataIdx;
                                if (toRead > 32)
                                    toRead = 32;
                                if (!ReadUserProcessMemorySafe(
                                        dwmProc,
                                        modBase + pdataRva + pdataIdx * sizeof(DWM_RUNTIME_FUNCTION_ENTRY),
                                        pdataChunk,
                                        toRead * sizeof(DWM_RUNTIME_FUNCTION_ENTRY)))
                                {
                                    pdataCount = 0;
                                    break;
                                }
                                pdataChunkBase = pdataIdx;
                                pdataChunkValid = toRead;
                            }

                            ULONG fnBegin = pdataChunk[pdataIdx - pdataChunkBase].BeginAddress;
                            ULONG fnUnwind = pdataChunk[pdataIdx - pdataChunkBase].UnwindData;
                            if (fnBegin < pageRva)
                            {
                                pdataIdx++;
                                continue;
                            }
                            if (fnBegin >= pageEndRva)
                                break;

                            pdataIdx++;
                            if ((fnUnwind & 1U) != 0 || fnBegin + 16 > pageEndRva)
                                continue;

                            ULONG off = fnBegin - pageRva;
                            ULONG_PTR candTarget = 0;
                            ULONG hType = DecodeUserModeHookTarget(modBase + fnBegin, &pageBuf[off], &candTarget);
                            if (hType != 0 &&
                                (candTarget < modBase || candTarget >= modBase + modSize) &&
                                !IsAddressInDwmModules(candTarget, allMods, allModCount) &&
                                IsMappedDwmTrampoline(dwmProc, candTarget))
                            {
                                alarms++;
                                if (!(s_ReportedDwmTextMask & (1U << m)))
                                {
                                    s_ReportedDwmTextMask |= (1U << m);
                                    ExceptionReporter::ReportFormat("ApiMonitor::DwmPresentInlineHook", STATUS_SECURITY_CHECKS_FAILED,
                                        "DWM Inline Hook: %s+0x%X jumps to unbacked trampoline 0x%p (Bytes=%02X %02X %02X %02X %02X)",
                                        kTargetDwmNamesA[m], fnBegin, (PVOID)candTarget,
                                        pageBuf[off], pageBuf[off + 1], pageBuf[off + 2], pageBuf[off + 3], pageBuf[off + 4]);
                                }
                                break;
                            }
                        }
                    }

                    s_DwmModBaselines[m].BaselineReady = TRUE;
                }
            }

            if (targetModBases[0] == 0 && targetModBases[1] == 0)
            {
                /* uses file-scope s_ReportedDwmModsMissing */
                if (g_bAceDetected && !s_ReportedDwmModsMissing)
                {
                    s_ReportedDwmModsMissing = TRUE;
                    ExceptionReporter::ReportFormat("ApiMonitor::DwmCoreModulesMissing", STATUS_NOT_FOUND,
                        "Failed to locate dwmcore.dll/dxgi.dll in dwm.exe (PID=%llu, scannedMods=%lu)",
                        (ULONG64)(ULONG_PTR)s_CachedDwmPid, allModCount);
                }
            }
        }
        else
        {
            /* uses file-scope s_ReportedDwmLdrHeadFail */
            if (g_bAceDetected && !s_ReportedDwmLdrHeadFail)
            {
                s_ReportedDwmLdrHeadFail = TRUE;
                ExceptionReporter::ReportFormat("ApiMonitor::DwmLdrReadFailed", STATUS_PARTIAL_COPY,
                    "Failed to read PEB_LDR_DATA.InLoadOrderModuleList @ 0x%p in dwm.exe (PID=%llu)",
                    (PVOID)listHeadVa, (ULONG64)(ULONG_PTR)s_CachedDwmPid);
            }
        }
    }
    else
    {
        /* uses file-scope s_ReportedDwmPebFail */
        if (g_bAceDetected && !s_ReportedDwmPebFail)
        {
            s_ReportedDwmPebFail = TRUE;
            ExceptionReporter::ReportFormat("ApiMonitor::DwmPebReadFailed", STATUS_PARTIAL_COPY,
                "Failed to read PEB (0x%p) or PEB->Ldr in dwm.exe (PID=%llu)",
                (PVOID)pebAddr, (ULONG64)(ULONG_PTR)s_CachedDwmPid);
        }
    }

    g_pApiMonUserVar->Func.PsReleaseProcessExitSynchronization(dwmProc);
    g_pApiMonUserVar->Func.ObfDereferenceObject(dwmProc);
    return alarms;
}

ULONG ApiMonitor::CheckDwmAndGraphicsHooks(VOID)
{
    ULONG alarms = 0;

    /* 1. 检查 ACE 专属截屏驱动模块 (ACE_SSC_DRV64.sys) 是否加载 */
    if (g_bAceDetected)
    {
        for (ULONG i = 0; i < g_AceModuleCount && i < ACE_MAX_TRACKED_MODULES; i++)
        {
            ULONG cch = 0;
            while (cch < 31 && g_AceModules[i].Name[cch] != L'\0')
                cch++;
            if (MatchWideSubstrCaseless(g_AceModules[i].Name, cch, L"SSC") ||
                MatchWideSubstrCaseless(g_AceModules[i].Name, cch, L"SCREEN"))
            {
                alarms++;
                if (!s_ReportedAceSscMod)
                {
                    s_ReportedAceSscMod = TRUE;
                    InterlockedExchange64(&g_LastResolvedAceAddr, (LONGLONG)g_AceModules[i].Base);
                    ExceptionReporter::ReportFormat("ApiMonitor::AceScreenshotDrv", STATUS_SECURITY_CHECKS_FAILED,
                        "ACE Screenshot Driver Active: %ws [0x%p-0x%p]",
                        g_AceModules[i].Name, (PVOID)g_AceModules[i].Base, (PVOID)g_AceModules[i].End);
                }
            }
        }
    }

    /* 2. 检查内核图形子系统 dxgkrnl.sys 导出表、IAT 与 \\Driver\\dxgkrnl 分发表 */
    if (!g_DxgkrnlBase || g_DxgkrnlEnd <= g_DxgkrnlBase)
    {
        /* uses file-scope s_ReportedDxgkMissing */
        if (g_bAceDetected && !s_ReportedDxgkMissing)
        {
            s_ReportedDxgkMissing = TRUE;
            ExceptionReporter::Report("ApiMonitor::DxgkrnlBaseMissing", STATUS_NOT_FOUND,
                "dxgkrnl.sys base not found in PsLoadedModuleList");
        }
    }
    else if (Utils::IsValidKernelRange((PVOID)g_DxgkrnlBase, PAGE_SIZE))
    {
        __try
        {
            if (!s_DxgkExportsResolved)
            {
                ULONG resolvedDxgkCount = 0;
                for (ULONG i = 0; i < DXGK_EXPORT_MONITOR_COUNT; i++)
                {
                    ULONG_PTR fnVa = 0;
                    ULONG h = Utils::HashStringA((PCHAR)s_DxgkExports[i].Name, (SIZE_T)SafeStrlen(s_DxgkExports[i].Name), TRUE);
                    if (Utils::GetModuleExport(g_DxgkrnlBase, h, &fnVa) && fnVa)
                    {
                        s_DxgkExports[i].InitialVa = fnVa;
                        resolvedDxgkCount++;
                        if (Utils::IsValidKernelRange((PVOID)fnVa, API_BASELINE_SAMPLE_BYTES))
                        {
                            s_DxgkExports[i].BaselineAdler32 = Utils::CalcAdler32((const UCHAR *)fnVa, API_BASELINE_SAMPLE_BYTES);
                            s_DxgkExports[i].BaselineReady = TRUE;
                        }
                    }
                }
                if (resolvedDxgkCount == 0)
                {
                    ExceptionReporter::ReportFormat("ApiMonitor::DxgkExportResolveFailed", STATUS_PROCEDURE_NOT_FOUND,
                        "Failed to resolve any monitored exports from dxgkrnl.sys (Base=0x%p)", (PVOID)g_DxgkrnlBase);
                }
                s_DxgkExportsResolved = TRUE;
            }

            for (ULONG i = 0; i < DXGK_EXPORT_MONITOR_COUNT; i++)
            {
                ULONG_PTR fnVa = s_DxgkExports[i].InitialVa;
                if (!fnVa || !Utils::IsValidKernelRange((PVOID)fnVa, API_BASELINE_SAMPLE_BYTES))
                    continue;

                BOOLEAN bTrap = FALSE;
                ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(fnVa, &bTrap);
                ULONG curHash = Utils::CalcAdler32((const UCHAR *)fnVa, API_BASELINE_SAMPLE_BYTES);
                BOOLEAN bHooked = bTrap ||
                                  (inlineTarget && (IsAddressInAceModules(inlineTarget) ||
                                                    inlineTarget < g_DxgkrnlBase || inlineTarget >= g_DxgkrnlEnd)) ||
                                  (s_DxgkExports[i].BaselineReady && curHash != s_DxgkExports[i].BaselineAdler32);
                if (bHooked)
                {
                    ULONG_PTR reportTarget = inlineTarget ? inlineTarget : fnVa;
                    WCHAR aceMod[32] = {0};
                    ULONG_PTR aceBase = 0, aceRva = 0;
                    ResolveAceModuleInfo(reportTarget, aceMod, &aceBase, &aceRva);
                    alarms++;
                    if (!(s_ReportedDxgkExpMask & (1U << i)))
                    {
                        s_ReportedDxgkExpMask |= (1U << i);
                        ExceptionReporter::ReportFormat("ApiMonitor::DxgkExportHook", STATUS_SECURITY_CHECKS_FAILED,
                            "dxgkrnl!%s (0x%p) Hooked -> %ws Target=0x%p (Base=0x%p +0x%llX)",
                            s_DxgkExports[i].Name, (PVOID)fnVa, aceMod[0] ? aceMod : L"Foreign/ACE",
                            (PVOID)reportTarget, (PVOID)aceBase, aceRva);
                    }
                }
            }

            /* 校验 dxgkrnl.sys IAT 是否存在指向 ACE 模块的劫持 */
            if (g_bAceDetected)
            {
                PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_DxgkrnlBase;
                if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
                {
                    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(g_DxgkrnlBase + pDos->e_lfanew);
                    if (Utils::IsValidKernelRange(pNt, sizeof(IMAGE_NT_HEADERS64)) && pNt->Signature == IMAGE_NT_SIGNATURE)
                    {
                        IMAGE_DATA_DIRECTORY impDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                        if (impDir.VirtualAddress && impDir.Size && impDir.VirtualAddress < (g_DxgkrnlEnd - g_DxgkrnlBase))
                        {
                            PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)(g_DxgkrnlBase + impDir.VirtualAddress);
                            for (ULONG m = 0; m < 32 && Utils::IsValidKernelRange(pDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && pDesc->FirstThunk != 0; m++, pDesc++)
                            {
                                PULONG_PTR pIat = (PULONG_PTR)(g_DxgkrnlBase + pDesc->FirstThunk);
                                for (ULONG s = 0; s < 512 && Utils::IsValidKernelRange(&pIat[s], sizeof(ULONG_PTR)); s++)
                                {
                                    ULONG_PTR fnVa = pIat[s];
                                    if (!fnVa)
                                        break;
                                    if (IsAddressInAceModules(fnVa))
                                    {
                                        WCHAR aceMod[32] = {0};
                                        ULONG_PTR aceBase = 0, aceRva = 0;
                                        ResolveAceModuleInfo(fnVa, aceMod, &aceBase, &aceRva);
                                        alarms++;
                                        if (!s_ReportedDxgkIat)
                                        {
                                            s_ReportedDxgkIat = TRUE;
                                            ExceptionReporter::ReportFormat("ApiMonitor::DxgkIatHook", STATUS_SECURITY_CHECKS_FAILED,
                                                "dxgkrnl.sys IAT[%u] Hooked -> %ws (0x%p, Base=0x%p +0x%llX)",
                                                s, aceMod[0] ? aceMod : L"ACE", (PVOID)fnVa, (PVOID)aceBase, aceRva);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            /* uses file-scope s_ReportedDxgkScanEx */
            NTSTATUS exCode = GetExceptionCode();
            if (!s_ReportedDxgkScanEx)
            {
                s_ReportedDxgkScanEx = TRUE;
                ExceptionReporter::ReportFormat("ApiMonitor::DxgkScanException", exCode,
                    "Exception 0x%08X scanning dxgkrnl.sys exports/IAT (Base=0x%p)", exCode, (PVOID)g_DxgkrnlBase);
            }
        }
    }

    /* 3. 检查 \\Driver\\dxgkrnl 驱动对象 MajorFunction 与 AttachedDevice */
    if (g_bAceDetected && g_pApiMonUserVar && g_pApiMonUserVar->Func.ObReferenceObjectByName &&
        g_pApiMonUserVar->Func.pIoDriverObjectType && g_pApiMonUserVar->Func.ObfDereferenceObject)
    {
        POBJECT_TYPE drvObjType = *(POBJECT_TYPE *)g_pApiMonUserVar->Func.pIoDriverObjectType;
        if (drvObjType)
        {
            UNICODE_STRING dxgkDrvName;
            SafeInitUnicodeString(&dxgkDrvName, L"\\Driver\\dxgkrnl");
            PDRIVER_OBJECT pDxgkDrv = NULL;
            NTSTATUS refSt = g_pApiMonUserVar->Func.ObReferenceObjectByName(
                &dxgkDrvName, OBJ_CASE_INSENSITIVE, NULL, 0, drvObjType, KernelMode, NULL, (PVOID *)&pDxgkDrv);
            if (NT_SUCCESS(refSt) && pDxgkDrv)
            {
                __try
                {
                    if (Utils::IsValidKernelRange(pDxgkDrv, sizeof(DRIVER_OBJECT)))
                    {
                        for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                        {
                            ULONG_PTR fn = (ULONG_PTR)pDxgkDrv->MajorFunction[i];
                            if (!fn)
                                continue;
                            ULONG_PTR inlineTarget = Utils::DecodeInlineHookTarget(fn);
                            ULONG_PTR hitAddr = IsAddressInAceModules(fn) ? fn :
                                                ((inlineTarget && IsAddressInAceModules(inlineTarget)) ? inlineTarget : 0);
                            if (hitAddr)
                            {
                                WCHAR aceMod[32] = {0};
                                ULONG_PTR aceBase = 0, aceRva = 0;
                                ResolveAceModuleInfo(hitAddr, aceMod, &aceBase, &aceRva);
                                alarms++;
                                if (!(s_ReportedDxgkMajorMask & (1U << (i & 31))))
                                {
                                    s_ReportedDxgkMajorMask |= (1U << (i & 31));
                                    ExceptionReporter::ReportFormat("ApiMonitor::DxgkMajorHook", STATUS_SECURITY_CHECKS_FAILED,
                                        "\\Driver\\dxgkrnl MajorFunction[%u] Hooked -> %ws (0x%p, Base=0x%p +0x%llX)",
                                        i, aceMod[0] ? aceMod : L"ACE", (PVOID)hitAddr, (PVOID)aceBase, aceRva);
                                }
                            }
                        }

                        PDEVICE_OBJECT pDev = pDxgkDrv->DeviceObject;
                        for (ULONG d = 0; d < 32 && Utils::IsValidKernelRange(pDev, sizeof(DEVICE_OBJECT)); d++)
                        {
                            PDEVICE_OBJECT pAtt = pDev->AttachedDevice;
                            for (ULONG depth = 0; depth < 8 && Utils::IsValidKernelRange(pAtt, sizeof(DEVICE_OBJECT)); depth++)
                            {
                                if (Utils::IsValidKernelRange(pAtt->DriverObject, sizeof(DRIVER_OBJECT)))
                                {
                                    ULONG_PTR attStart = (ULONG_PTR)pAtt->DriverObject->DriverStart;
                                    if (IsAddressInAceModules(attStart))
                                    {
                                        WCHAR aceMod[32] = {0};
                                        ULONG_PTR aceBase = 0, aceRva = 0;
                                        ResolveAceModuleInfo(attStart, aceMod, &aceBase, &aceRva);
                                        alarms++;
                                        if (!s_ReportedDxgkAttached)
                                        {
                                            s_ReportedDxgkAttached = TRUE;
                                            ExceptionReporter::ReportFormat("ApiMonitor::DxgkAttachedDevice", STATUS_SECURITY_CHECKS_FAILED,
                                                "\\Driver\\dxgkrnl AttachedDevice by %ws (Base=0x%p)",
                                                aceMod[0] ? aceMod : L"ACE", (PVOID)aceBase);
                                        }
                                    }
                                }
                                pAtt = pAtt->AttachedDevice;
                            }
                            pDev = pDev->NextDevice;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    /* uses file-scope s_ReportedDxgkDrvEx */
                    NTSTATUS exCode = GetExceptionCode();
                    if (!s_ReportedDxgkDrvEx)
                    {
                        s_ReportedDxgkDrvEx = TRUE;
                        ExceptionReporter::ReportFormat("ApiMonitor::DxgkDrvObjException", exCode,
                            "Exception 0x%08X scanning \\Driver\\dxgkrnl object (0x%p)", exCode, pDxgkDrv);
                    }
                }
                g_pApiMonUserVar->Func.ObfDereferenceObject(pDxgkDrv);
            }
            else
            {
                /* uses file-scope s_ReportedDxgkOpenFail */
                if (!s_ReportedDxgkOpenFail)
                {
                    s_ReportedDxgkOpenFail = TRUE;
                    ExceptionReporter::ReportFormat("ApiMonitor::DxgkDriverObjFailed", refSt,
                        "ObReferenceObjectByName(\\Driver\\dxgkrnl) failed (status=0x%08X)", refSt);
                }
            }
        }
    }

    /* 4. 扫描用户态 dwm.exe 进程内部模块 (dwmcore.dll / dxgi.dll / d3d11.dll / udwm.dll / win32u.dll) 截图 Hook */
    alarms += ScanDwmUserProcessHooks();

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
    ULONG vtAlarms = CheckHardwareVtState();
    ULONG dwmAlarms = CheckDwmAndGraphicsHooks();
    ULONG total = apiAlarms + ssdtAlarms + iatAlarms + halAlarms + pfAlarms + vtAlarms + dwmAlarms;

    if (total > 0)
    {
        DBG("[!] ApiMonitor [Round #%lu]: >>> THREAT DETECTED! Total=%u (API=%u, SSDT=%u, IAT=%u, HAL=%u, #PF/CSW=%u, VT=%u, DWM=%u) <<<",
            s_apiScanRound, total, apiAlarms, ssdtAlarms, iatAlarms, halAlarms, pfAlarms, vtAlarms, dwmAlarms);
    }
    else if (s_apiScanRound <= 3 || (s_apiScanRound % 5) == 0)
    {
        DBG("[+] ApiMonitor [Round #%lu]: All 28 APIs, 7 SSDT stubs, 7 IATs, %lu HAL slots, %lu SecPtrs, #PF, VT & DWM intact",
            s_apiScanRound, s_HalSlotCount, s_HalSecSlotCount);
    }
}
