#include "EtwMonitor.h"
#include "MachenikeString.h"
#include "Utils.h"
#include "ExceptionReporter.h"

/*
 * ============================================================================
 * EtwMonitor: 内核 ETW 全局注册项与 ACE 监控引擎
 *
 * 核心设计铁律：
 * 1. 100% 纯只读巡检，严禁对任何系统 ETW 结构、链表或回调执行覆写或脱钩中和，
 *    彻底杜绝触碰 PatchGuard (0x109) 与 HVCI 只读违例 (0xBE)。
 * 2. 60 秒低频巡检 + 前置 ACE 存活门禁 + 偏移自学习缓存 (O(1) 直达 RegListHead)。
 * 3. 基于 (ModuleHash + RVA) 的 128 槽位永久去重：已报项绝不覆盖、绝不重报，仅出现新回调时上报。
 * ============================================================================
 */

static MACHENIKE_KERNEL_INTERFACE *g_pEtwMonUserVar = NULL;
VOID EtwMonitor::SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    g_pEtwMonUserVar = UserVar;
}

#ifdef MmIsAddressValid
#undef MmIsAddressValid
#endif
#define MmIsAddressValid(va)                                                                                                               \
    ((g_pEtwMonUserVar && g_pEtwMonUserVar->Func.MmIsAddressValid) ? g_pEtwMonUserVar->Func.MmIsAddressValid((PVOID)(va)) : FALSE)

static inline BOOLEAN EtwMon_IsValidListEntry(const LIST_ENTRY *pEntry)
{
    return (((ULONG_PTR)pEntry & 0x7) == 0) && Utils::IsValidKernelRange(pEntry, sizeof(LIST_ENTRY));
}

/* 全局 EtwpGuidHashTable 状态 (64 个 _ETW_HASH_BUCKET) */
static ULONG_PTR s_EtwpGuidHashTableBase = 0;
static ULONG s_EtwBucketStride = 0x38;
static ULONG s_EtwListsPerBucket = 3;
static BOOLEAN s_EtwInitialized = FALSE;
static BOOLEAN s_EtwLocateAttempted = FALSE;

/* 自学习结构偏移缓存 (首次命中后固化，消除 6x4 内层试探循环) */
static ULONG s_CachedRegListOffset = 0;
static ULONG s_CachedBackPtrOffset = 0;

/* 64 位永久去重指纹缓存 (128 槽位只增不覆写，绑定 ModuleHash + RVA，仅出现新回调时上报) */
#define MAX_REPORTED_ETW_ITEMS 128
static ULONG64 s_ReportedEtwFingerprints[MAX_REPORTED_ETW_ITEMS] = {0};
static ULONG s_ReportedEtwCount = 0;

VOID EtwMonitor::ResetReportState(VOID)
{
    /* 保持永久去重表不清空，确保跨局/重启也仅在出现全新 ETW 回调时上报 */
}

static BOOLEAN EtwMon_ShouldReport(ULONG64 fp)
{
    if (fp == 0)
        return FALSE;

    for (ULONG i = 0; i < s_ReportedEtwCount; i++)
    {
        if (s_ReportedEtwFingerprints[i] == fp)
            return FALSE;
    }

    if (s_ReportedEtwCount >= MAX_REPORTED_ETW_ITEMS)
        return FALSE;

    s_ReportedEtwFingerprints[s_ReportedEtwCount++] = fp;
    return TRUE;
}

/*
 * 按指定桶步长 (0x38 / 0x18 / 0x10) 与每桶链表数校验是否为合法的 64 桶 EtwpGuidHashTable
 */
static BOOLEAN EtwMon_ValidateGuidHashTableWithLayout(ULONG_PTR tableBase, ULONG stride, ULONG listsPerBucket)
{
    if (((tableBase & 0x7) != 0) || !Utils::IsValidKernelRange((PVOID)tableBase, (SIZE_T)stride * 64))
        return FALSE;

    ULONG emptyLoops = 0;
    ULONG validHeads = 0;
    ULONG totalHeads = 64 * listsPerBucket;

    for (ULONG b = 0; b < 64; b++)
    {
        ULONG_PTR bucketAddr = tableBase + (SIZE_T)b * stride;
        for (ULONG l = 0; l < listsPerBucket; l++)
        {
            PLIST_ENTRY pHead = (PLIST_ENTRY)(bucketAddr + (SIZE_T)l * sizeof(LIST_ENTRY));
            if (pHead->Flink == pHead && pHead->Blink == pHead)
            {
                emptyLoops++;
                validHeads++;
            }
            else if (EtwMon_IsValidListEntry(pHead->Flink) && EtwMon_IsValidListEntry(pHead->Blink))
            {
                if (pHead->Flink->Blink == pHead && pHead->Blink->Flink == pHead)
                    validHeads++;
                else
                    return FALSE;
            }
            else
            {
                return FALSE;
            }
        }
    }

    return (emptyLoops >= 8 && validHeads == totalHeads);
}

static BOOLEAN EtwMon_ValidateGuidHashTable(ULONG_PTR candidate, PULONG pOutStride, PULONG pOutLists)
{
    static const struct
    {
        ULONG Stride;
        ULONG ListsPerBucket;
    } s_Layouts[] = {
        {0x38, 3}, /* Win10 RS1~22H2 / Win11 22H2~24H2: LIST_ENTRY[3] + EX_PUSH_LOCK */
        {0x18, 1}, /* 早期 Win8/Win10: LIST_ENTRY[1] + EX_PUSH_LOCK */
        {0x10, 1}  /* 纯 LIST_ENTRY[64] 紧凑表 */
    };

    for (ULONG i = 0; i < sizeof(s_Layouts) / sizeof(s_Layouts[0]); i++)
    {
        if (EtwMon_ValidateGuidHashTableWithLayout(candidate, s_Layouts[i].Stride, s_Layouts[i].ListsPerBucket))
        {
            *pOutStride = s_Layouts[i].Stride;
            *pOutLists = s_Layouts[i].ListsPerBucket;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * 在 _ETW_SILO_TRACING_BLOCK (EtwpHostSiloState) 内部探测 64 桶 EtwpGuidHashTable
 * Win10 RS1~22H2 / Win11 21H2~24H2 中，GuidHashTable 位于 EtwSiloState + 0x1D0 (64 * 0x38 字节)
 */
static ULONG_PTR EtwMon_ProbeSiloStateForTable(ULONG_PTR siloState, ULONG_PTR kBase, PULONG pStride, PULONG pLists)
{
    if (((siloState & 0x7) != 0) || (siloState >= kBase && siloState < kBase + 0x2000000ULL))
        return 0;

    if (!Utils::IsValidKernelRange((PVOID)siloState, 0x1000))
        return 0;

    // 优先命中现代 Win10/Win11 标准偏移 +0x1D0
    if (EtwMon_ValidateGuidHashTable(siloState + 0x1D0, pStride, pLists))
        return siloState + 0x1D0;

    // 跨版本兜底：在 _ETW_SILO_TRACING_BLOCK 前 0x480 字节内按 8 字节步长探测
    for (ULONG off = 0x80; off <= 0x480; off += 8)
    {
        if (off == 0x1D0)
            continue;
        PLIST_ENTRY pHead = (PLIST_ENTRY)(siloState + off);
        if (!Utils::IsValidKernelRange(pHead, sizeof(LIST_ENTRY)))
            break;
        if ((pHead->Flink == pHead && pHead->Blink == pHead) ||
            (EtwMon_IsValidListEntry(pHead->Flink) && pHead->Flink->Blink == pHead))
        {
            if (EtwMon_ValidateGuidHashTable(siloState + off, pStride, pLists))
                return siloState + off;
        }
    }

    return 0;
}

/*
 * 递归扫描函数体内的 RIP 相对寻址：
 * 1. mov reg64, qword ptr [rip + disp32] (48/4C 8B 05..3D) -> 解引用 nt!EtwpHostSiloState 探测 +0x1D0
 * 2. lea reg64, [rip + disp32] (48/4C 8D 05..3D) -> 直接验证静态表，或作为 nt!PspHostSiloGlobals (+0x360) 探测
 * 3. E8 rel32 子调用跟进 (最多 3 层)
 */
static ULONG_PTR EtwMon_ScanFunctionForTable(ULONG_PTR fnAddr, ULONG_PTR kBase, ULONG depth, PULONG pStride, PULONG pLists)
{
    if (depth > 3 || fnAddr < kBase || fnAddr >= kBase + 0x2000000ULL)
        return 0;

    PUCHAR pCode = (PUCHAR)fnAddr;
    for (ULONG i = 0; i < 420; i++)
    {
        if (!MmIsAddressValid(&pCode[i]) || !MmIsAddressValid(&pCode[i + 7]))
            break;

        // 函数尾部连续 INT3 填充边界判定（避免将 displacement 内的单个 0xCC 字节误判为函数结束）
        if (pCode[i] == 0xCC && pCode[i + 1] == 0xCC && i > 16)
            break;

        // 1. 匹配 (0x48 | 0x4C) 8B (Mod=00, R/M=101): mov reg64, qword ptr [rip + disp32] (如 EtwRegisterClassicProvider / EtwpAddGuidEntry 加载 nt!EtwpHostSiloState)
        if ((pCode[i] & 0xFB) == 0x48 && pCode[i + 1] == 0x8B && (pCode[i + 2] & 0xC7) == 0x05)
        {
            LONG disp = *(PLONG)&pCode[i + 3];
            ULONG_PTR ptrVarAddr = (ULONG_PTR)&pCode[i + 7] + disp;
            if (ptrVarAddr >= kBase && ptrVarAddr < kBase + 0x2000000ULL &&
                ((ptrVarAddr & 0x7) == 0) && Utils::IsValidKernelRange((PVOID)ptrVarAddr, sizeof(ULONG_PTR)))
            {
                ULONG_PTR siloState = *(PULONG_PTR)ptrVarAddr;
                ULONG_PTR found = EtwMon_ProbeSiloStateForTable(siloState, kBase, pStride, pLists);
                if (found != 0)
                    return found;
            }
        }

        // 2. 匹配 (0x48 | 0x4C) 8D (Mod=00, R/M=101): lea reg64, [rip + disp32]
        if ((pCode[i] & 0xFB) == 0x48 && pCode[i + 1] == 0x8D && (pCode[i + 2] & 0xC7) == 0x05)
        {
            LONG disp = *(PLONG)&pCode[i + 3];
            ULONG_PTR candidate = (ULONG_PTR)&pCode[i + 7] + disp;
            // 2a. 早期 Win10 直接静态表
            if (EtwMon_ValidateGuidHashTable(candidate, pStride, pLists))
                return candidate;

            // 2b. Win10 RS1+ / Win11: PsGetCurrentServerSiloGlobals 内的 lea rax, nt!PspHostSiloGlobals
            if (candidate >= kBase && candidate < kBase + 0x2000000ULL &&
                ((candidate & 0x7) == 0) && Utils::IsValidKernelRange((PVOID)candidate, 0x400))
            {
                // 优先测试标准 EtwSiloState 偏移 +0x360
                ULONG_PTR siloAt360 = *(PULONG_PTR)(candidate + 0x360);
                ULONG_PTR found = EtwMon_ProbeSiloStateForTable(siloAt360, kBase, pStride, pLists);
                if (found != 0)
                    return found;

                for (ULONG sOff = 0x240; sOff <= 0x3F8; sOff += 8)
                {
                    if (sOff == 0x360)
                        continue;
                    ULONG_PTR siloState = *(PULONG_PTR)(candidate + sOff);
                    found = EtwMon_ProbeSiloStateForTable(siloState, kBase, pStride, pLists);
                    if (found != 0)
                        return found;
                }
            }
        }

        // 3. 跟进 E8 rel32 子调用
        if (pCode[i] == 0xE8 && depth < 3)
        {
            LONG callDisp = *(PLONG)&pCode[i + 1];
            ULONG_PTR subFn = (ULONG_PTR)&pCode[i + 5] + callDisp;
            ULONG_PTR found = EtwMon_ScanFunctionForTable(subFn, kBase, depth + 1, pStride, pLists);
            if (found != 0)
                return found;
        }
    }
    return 0;
}

/*
 * 动态定位 EtwpGuidHashTable
 */
static ULONG_PTR EtwMon_LocateGuidHashTable(PULONG pOutStride, PULONG pOutLists)
{
    if (!g_pEtwMonUserVar || g_pEtwMonUserVar->KernelBase.QuadPart == 0)
        return 0;

    ULONG_PTR kBase = (ULONG_PTR)g_pEtwMonUserVar->KernelBase.QuadPart;

    // 路径 A: 通过预计算哈希解析 EtwRegisterClassicProvider / EtwRegister / EtwEventRegister / EtwUnregister 并反汇编
    static const ULONG s_EtwExportHashes[] = {
        str_EtwRegisterClassicProvider,
        str_EtwRegister,
        str_EtwEventRegister,
        str_EtwUnregister};
    for (ULONG e = 0; e < sizeof(s_EtwExportHashes) / sizeof(s_EtwExportHashes[0]); e++)
    {
        ULONG_PTR pfn = 0;
        if (Utils::GetModuleExport(kBase, s_EtwExportHashes[e], &pfn) && pfn != 0)
        {
            ULONG_PTR found = EtwMon_ScanFunctionForTable(pfn, kBase, 0, pOutStride, pOutLists);
            if (found != 0)
            {
                DBG("[+] EtwMonitor: Located EtwpGuidHashTable via export[0x%08X]: 0x%p (Stride=0x%X, Lists=%u)",
                    s_EtwExportHashes[e], (PVOID)found, *pOutStride, *pOutLists);
                return found;
            }
        }
    }

    // 路径 B: 解析 ntoskrnl PE 节表，在非分页可写数据节 (.data) 范围内扫描 nt!EtwpHostSiloState 指针或内联 64 桶表
    if (!Utils::IsValidKernelRange((PVOID)kBase, PAGE_SIZE))
        return 0;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)kBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(kBase + pDos->e_lfanew);
    if (!Utils::IsValidKernelRange(pNt, sizeof(IMAGE_NT_HEADERS64)) || pNt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    USHORT numSecs = pNt->FileHeader.NumberOfSections;
    if (numSecs > 64)
        numSecs = 64;

    for (USHORT s = 0; s < numSecs; s++, pSec++)
    {
        if (!Utils::IsValidKernelRange(pSec, sizeof(IMAGE_SECTION_HEADER)))
            break;

        if ((pSec->Characteristics & IMAGE_SCN_MEM_WRITE) == 0 ||
            (pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 ||
            (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
        {
            continue;
        }

        if (pSec->Name[0] == 'P' && pSec->Name[1] == 'A' && pSec->Name[2] == 'G' && pSec->Name[3] == 'E')
            continue;

        ULONG secSize = pSec->Misc.VirtualSize;
        if (secSize < 0x100 || secSize > 0x1000000)
            continue;

        ULONG_PTR scanStart = (kBase + pSec->VirtualAddress + 7) & ~7ULL;
        ULONG_PTR scanEnd = kBase + pSec->VirtualAddress + secSize - sizeof(ULONG_PTR);

        for (ULONG_PTR addr = scanStart; addr < scanEnd; addr += 8)
        {
            if ((addr & 0xFFF) == 0 && !MmIsAddressValid((PVOID)addr))
            {
                addr += 0x1000 - 8;
                continue;
            }

            if (!MmIsAddressValid((PVOID)addr))
                continue;

            // 1. 检查该 .data 槽位是否为指向 _ETW_SILO_TRACING_BLOCK (nt!EtwpHostSiloState) 的指针
            ULONG_PTR ptrVal = *(PULONG_PTR)addr;
            if (ptrVal > 0xFFFF800000000000ULL && ptrVal < 0xFFFFFF0000000000ULL && ((ptrVal & 0x7) == 0) &&
                !(ptrVal >= kBase && ptrVal < kBase + 0x2000000ULL))
            {
                ULONG_PTR candidateTable = ptrVal + 0x1D0;
                if (MmIsAddressValid((PVOID)candidateTable))
                {
                    PLIST_ENTRY pHead0 = (PLIST_ENTRY)candidateTable;
                    if ((pHead0->Flink == pHead0 && pHead0->Blink == pHead0) ||
                        (EtwMon_IsValidListEntry(pHead0->Flink) && pHead0->Flink->Blink == pHead0))
                    {
                        if (EtwMon_ValidateGuidHashTable(candidateTable, pOutStride, pOutLists))
                        {
                            DBG("[+] EtwMonitor: Located EtwpGuidHashTable via .data SiloState ptr[0x%p -> 0x%p]: 0x%p (Stride=0x%X, Lists=%u)",
                                (PVOID)addr, (PVOID)ptrVal, (PVOID)candidateTable, *pOutStride, *pOutLists);
                            return candidateTable;
                        }
                    }
                }
            }

            // 2. 兼容早期内联在 .data 节内的静态 64 桶表
            if (addr + (0x38 * 64) <= scanEnd && EtwMon_IsValidListEntry((PLIST_ENTRY)addr))
            {
                PLIST_ENTRY pFirstHead = (PLIST_ENTRY)addr;
                BOOLEAN bLooksLikeHead = (pFirstHead->Flink == pFirstHead && pFirstHead->Blink == pFirstHead) ||
                                         (EtwMon_IsValidListEntry(pFirstHead->Flink) && pFirstHead->Flink->Blink == pFirstHead);
                if (bLooksLikeHead && EtwMon_ValidateGuidHashTable(addr, pOutStride, pOutLists))
                {
                    DBG("[+] EtwMonitor: Located EtwpGuidHashTable via .data section scan: 0x%p (Stride=0x%X, Lists=%u)",
                        (PVOID)addr, *pOutStride, *pOutLists);
                    return addr;
                }
            }
        }
    }

    return 0;
}

/*
 * 初始化 ETW 安全监控引擎
 */
NTSTATUS EtwMonitor::Init(VOID)
{
    if (s_EtwInitialized && s_EtwpGuidHashTableBase != 0)
        return STATUS_SUCCESS;

    s_EtwLocateAttempted = TRUE;
    s_EtwpGuidHashTableBase = EtwMon_LocateGuidHashTable(&s_EtwBucketStride, &s_EtwListsPerBucket);
    if (s_EtwpGuidHashTableBase != 0)
    {
        s_EtwInitialized = TRUE;
        DBG("[+] EtwMonitor::Init: Success, EtwpGuidHashTable=0x%p (Stride=0x%X, Lists=%u)",
            (PVOID)s_EtwpGuidHashTableBase, s_EtwBucketStride, s_EtwListsPerBucket);
        return STATUS_SUCCESS;
    }

    DBG("[-] EtwMonitor::Init: Failed to locate EtwpGuidHashTable");
    static volatile LONG s_ReportedEtwInitFail = 0;
    if (InterlockedCompareExchange(&s_ReportedEtwInitFail, 1, 0) == 0)
    {
        ExceptionReporter::ReportFormat("EtwMonitor::InitFailed", STATUS_NOT_FOUND,
            "Failed to locate EtwpGuidHashTable (KernelBase=0x%p)",
            (PVOID)(g_pEtwMonUserVar ? g_pEtwMonUserVar->KernelBase.QuadPart : 0));
    }
    return STATUS_NOT_FOUND;
}

/*
 * 扫描单个已定位的 RegListHead 双向链表
 */
static ULONG EtwMon_ScanRegList(PLIST_ENTRY pRegListHead, ULONG bucketIdx)
{
    ULONG hits = 0;
    PLIST_ENTRY pCurReg = pRegListHead->Flink;
    ULONG regDepth = 0;

    while (pCurReg && pCurReg != pRegListHead && regDepth++ < 64)
    {
        if (((ULONG_PTR)pCurReg & 0x7) != 0 || !Utils::IsValidKernelRange(pCurReg, 0x68))
            break;
        if (!EtwMon_IsValidListEntry(pCurReg->Flink) || pCurReg->Flink->Blink != pCurReg)
            break;

        PUCHAR pRegEntryRaw = (PUCHAR)pCurReg;
        // _ETW_REG_ENTRY (0x70 bytes): CallbackContext @ +0x50, Callback @ +0x58
        for (ULONG slot = 0x10; slot <= 0x60; slot += 8)
        {
            ULONG_PTR candidatePtr = *(ULONG_PTR *)(pRegEntryRaw + slot);
            if (candidatePtr && IsAddressInAceModules(candidatePtr))
            {
                WCHAR aceMod[32] = {0};
                ULONG_PTR aceBase = 0, aceRva = 0;
                ResolveAceModuleInfo(candidatePtr, aceMod, &aceBase, &aceRva);

                hits++;
                ULONG modHash = aceMod[0] ? Utils::HashStringW(aceMod, 32, TRUE) : 0xACE00001U;
                ULONG64 fp = ((ULONG64)modHash << 32) | (ULONG64)(aceRva & 0xFFFFFFFFULL);
                if (fp == 0)
                    fp = 1;

                if (EtwMon_ShouldReport(fp))
                {
                    DBG("[!] [HOOK ALARM-ETW] New ACE ETW Provider detected! Module=%ws Callback=0x%p (Base=0x%p +0x%llX) Bucket=%u",
                        aceMod[0] ? aceMod : L"ACE", (PVOID)candidatePtr, (PVOID)aceBase, aceRva, bucketIdx);

                    ExceptionReporter::ReportFormat("EtwMonitor::AceProvider", STATUS_SECURITY_CHECKS_FAILED,
                        "ETW Hook: ACE Provider registered by %ws! Callback=0x%p (Base=0x%p +0x%llX, Bucket=%u)",
                        aceMod[0] ? aceMod : L"ACE", (PVOID)candidatePtr, (PVOID)aceBase, aceRva, bucketIdx);
                }
                break; // 同一 _ETW_REG_ENTRY 命中一次即跳出槽位循环
            }
        }

        pCurReg = pCurReg->Flink;
    }

    return hits;
}

/*
 * 扫描全局 EtwpGuidHashTable，检测是否存在 ACE 注册的 Provider 与 Callback
 */
ULONG EtwMonitor::CheckAceEtwProviders(VOID)
{
    if (!g_bAceDetected || g_AceModuleCount == 0)
        return 0;

    if (s_EtwpGuidHashTableBase == 0)
    {
        if (s_EtwLocateAttempted)
            return 0;
        EtwMonitor::Init();
        if (s_EtwpGuidHashTableBase == 0)
            return 0;
    }

    ULONG detectedCount = 0;

    __try
    {
        for (ULONG b = 0; b < 64; b++)
        {
            ULONG_PTR bucketAddr = s_EtwpGuidHashTableBase + (SIZE_T)b * s_EtwBucketStride;
            for (ULONG l = 0; l < s_EtwListsPerBucket; l++)
            {
                // EtwpGuidHashTable 常驻于 ntoskrnl .data 节，空桶直接跳过，省去桶头 MmIsAddressValid
                PLIST_ENTRY pBucketHead = (PLIST_ENTRY)(bucketAddr + (SIZE_T)l * sizeof(LIST_ENTRY));
                PLIST_ENTRY pCurGuidEntry = pBucketHead->Flink;
                if (!pCurGuidEntry || pCurGuidEntry == pBucketHead)
                    continue;

                ULONG guidDepth = 0;
                while (pCurGuidEntry && pCurGuidEntry != pBucketHead && guidDepth++ < 128)
                {
                    if (((ULONG_PTR)pCurGuidEntry & 0x7) != 0 || !Utils::IsValidKernelRange(pCurGuidEntry, 0x58))
                        break;

                    if (!EtwMon_IsValidListEntry(pCurGuidEntry->Flink) || pCurGuidEntry->Flink->Blink != pCurGuidEntry)
                        break;

                    PUCHAR pGuidEntryRaw = (PUCHAR)pCurGuidEntry;

                    // 快路径：若已自学习缓存了当前系统的 RegListHead 与父指针偏移，直接 O(1) 定位
                    if (s_CachedRegListOffset != 0 && s_CachedBackPtrOffset != 0)
                    {
                        PLIST_ENTRY pRegListHead = (PLIST_ENTRY)(pGuidEntryRaw + s_CachedRegListOffset);
                        PLIST_ENTRY pFirstReg = pRegListHead->Flink;
                        if (pFirstReg != pRegListHead && (((ULONG_PTR)pFirstReg & 0x7) == 0) &&
                            Utils::IsValidKernelRange(pFirstReg, 0x68) && pFirstReg->Blink == pRegListHead &&
                            *(ULONG_PTR *)((PUCHAR)pFirstReg + s_CachedBackPtrOffset) == (ULONG_PTR)pCurGuidEntry)
                        {
                            detectedCount += EtwMon_ScanRegList(pRegListHead, b);
                        }
                    }
                    else
                    {
                        // 慢路径：首次自学习探测 RegListHead (+0x20..+0x48) 与父指针偏移 (+0x10..+0x28)
                        for (ULONG regListOffset = 0x20; regListOffset <= 0x48; regListOffset += 8)
                        {
                            PLIST_ENTRY pRegListHead = (PLIST_ENTRY)(pGuidEntryRaw + regListOffset);
                            PLIST_ENTRY pFirstReg = pRegListHead->Flink;
                            if (pFirstReg == pRegListHead || (((ULONG_PTR)pFirstReg & 0x7) != 0) ||
                                !Utils::IsValidKernelRange(pFirstReg, 0x68) || pFirstReg->Blink != pRegListHead)
                            {
                                continue;
                            }

                            ULONG matchedBackOff = 0;
                            for (ULONG backOff = 0x10; backOff <= 0x28; backOff += 8)
                            {
                                if (*(ULONG_PTR *)((PUCHAR)pFirstReg + backOff) == (ULONG_PTR)pCurGuidEntry)
                                {
                                    matchedBackOff = backOff;
                                    break;
                                }
                            }
                            if (matchedBackOff != 0)
                            {
                                s_CachedRegListOffset = regListOffset;
                                s_CachedBackPtrOffset = matchedBackOff;
                                detectedCount += EtwMon_ScanRegList(pRegListHead, b);
                                break;
                            }
                        }
                    }

                    pCurGuidEntry = pCurGuidEntry->Flink;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        NTSTATUS exCode = GetExceptionCode();
        DBG("[-] EtwMonitor::CheckAceEtwProviders: Exception caught (0x%08X)", exCode);
        static volatile LONG s_ReportedEtwScanEx = 0;
        if (InterlockedCompareExchange(&s_ReportedEtwScanEx, 1, 0) == 0)
        {
            ExceptionReporter::ReportFormat("EtwMonitor::CheckException", exCode,
                "Exception 0x%08X scanning EtwpGuidHashTable @ 0x%p",
                exCode, (PVOID)s_EtwpGuidHashTableBase);
        }
    }

    return detectedCount;
}

/*
 * 周期性执行 ETW 全局扫描 (由 10s 深度扫描流驱动，内部控频为 60s 一次；ACE 首次出现时立即首扫)
 */
ULONG EtwMonitor::ScanAll(VOID)
{
    static ULONG s_etwTick = 0;
    if (!g_bAceDetected || g_AceModuleCount == 0)
    {
        s_etwTick = 0;
        return 0;
    }

    if ((s_etwTick++ % 6) != 0)
        return 0;

    return CheckAceEtwProviders();
}
