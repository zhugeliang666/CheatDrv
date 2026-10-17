#include "Common.h"
#include "LeechCoreEngine.h"
#include "MachenikeString.h"
#include "Utils.h"
#include <intrin.h>

#ifdef ExAcquireFastMutex
#undef ExAcquireFastMutex
#endif
#define ExAcquireFastMutex(m)                                                                                                              \
    do                                                                                                                                     \
    {                                                                                                                                      \
        if (g_ctx.UserVar && g_ctx.UserVar->Func.ExAcquireFastMutex)                                                                       \
            g_ctx.UserVar->Func.ExAcquireFastMutex(m);                                                                                     \
    } while (0)

#ifdef ExReleaseFastMutex
#undef ExReleaseFastMutex
#endif
#define ExReleaseFastMutex(m)                                                                                                              \
    do                                                                                                                                     \
    {                                                                                                                                      \
        if (g_ctx.UserVar && g_ctx.UserVar->Func.ExReleaseFastMutex)                                                                       \
            g_ctx.UserVar->Func.ExReleaseFastMutex(m);                                                                                     \
    } while (0)
LC_MAIN_CONTEXT g_ctx = {0};
extern BOOLEAN MachenikeReadMsrSafe(ULONG MsrIndex, PULONG64 pValue);
// ============================================================================
// 高性能轻量级 System PTE 驻留窗口缓存 (PTE-Cache)
// 特性：
// 1. 驻留缓存：PTE 映射后不频繁清除，命中直接纳秒级内存解引用读取
// 2. 硬件级反 ACE/EDR：显式启用 Bit 63 NX (No-Execute) 标志位，杜绝 W+X 异常
// 3. 读写分离权限：读操作强制 Read-Only (NX=1, RW=0)，仅写操作开启 Write=1
// 4. 并发无锁快路径：1024 槽黄金平衡斐波那契散列 + Sequence Lock 极速无锁并发读取，零锁竞争
// ============================================================================
#define LC_PTE_SLOT_COUNT 1024
#define LC_PTE_INVALID_PFN 0xFFFFFFFFFFFFFFFFULL

// PTE 属性标志常量
// Bit 63: NX (No-Execute，防 W+X 违规与 ACE 扫描) = 0x8000000000000000ULL
// Bit 1: Write = 0x2ULL
// Bit 0: Valid/Present = 0x1ULL
// 负向知识：严禁置位 Bit 8 Global (0x100)，避免多核硬件 TLB 永久锁定残留映射导致跨核脏读
#define LC_PTE_FLAGS_READ (0x8000000000000001ULL)  // NX(1) | Present(1) [纯只读数据页]
#define LC_PTE_FLAGS_WRITE (0x8000000000000003ULL) // NX(1) | Write(1) | Present(1)

typedef struct _LC_PTE_SLOT
{
    PVOID pMappedPage;
    ULONG64 *pPteVa;
    ULONG64 OriginalPte;
    volatile ULONG64 CachedPfn; // 驻留映射的物理页帧号 (PhysAddr >> 12)
    volatile LONG isWritable;   // 当前槽位是否具备可写权限
    volatile LONG Lock;         // 槽位重映射排他自旋锁
    volatile LONG Sequence;     // 槽位版本序列号 (偶数=稳定可读，奇数=换页修改中)
} LC_PTE_SLOT, *PLC_PTE_SLOT;

typedef struct _LC_PTE_ENGINE
{
    ULONG64 PteBase;
    BOOLEAN fInitialized;
    LC_PTE_SLOT Slots[LC_PTE_SLOT_COUNT];
} LC_PTE_ENGINE, *PLC_PTE_ENGINE;

static LC_PTE_ENGINE g_PteEngine = {0};

// ============================================================================
// 内存读取吞吐量与 QPS 实时性能监测引擎 (Lock-Free 1Hz 节流采样)
// 1. 无锁原子累加：支持多核心高并发直读，零锁开销
// 2. 1Hz 单核抢占节流：严格防范 DbgPrint 自旋锁风暴 (ADR-0004 规范)
// 3. 纯 64 位整数定点换算：杜绝内核浮点操作导致的上下文异常
// ============================================================================
#define LC_ENABLE_READ_STATS 0

#if LC_ENABLE_READ_STATS
typedef struct _LC_READ_PERF_STATS
{
    volatile LONG64 TotalReadReqs;  // 累计读取总请求数
    volatile LONG64 TotalReadBytes; // 累计读取总字节数
    volatile LONG64 PeriodReadReqs; // 当前周期读取请求数
    volatile LONG64 PeriodPages;    // 当前周期读取物理页数
    volatile LONG64 PeriodFastHits; // 当前周期快路径命中页数
    volatile LONG64 PeriodBytes;    // 当前周期读取总字节数
    volatile LONG64 LastReportTime; // 上次打印的 100ns 系统时间戳
    volatile LONG ReportingGate;    // 1Hz 打印放行栅栏 (CAS 单核抢占)
} LC_READ_PERF_STATS;

static LC_READ_PERF_STATS g_LcPteStats = {0};

static __forceinline VOID LcPte_RecordReadStat(ULONG BytesRead, BOOLEAN fFastHit)
{
    _InterlockedIncrement64(&g_LcPteStats.PeriodPages);
    _InterlockedExchangeAdd64(&g_LcPteStats.PeriodBytes, (LONG64)BytesRead);
    if (fFastHit)
    {
        _InterlockedIncrement64(&g_LcPteStats.PeriodFastHits);
    }
}

static VOID LcPte_CheckAndReportStats(ULONG RequestBytes)
{
    _InterlockedIncrement64(&g_LcPteStats.TotalReadReqs);
    _InterlockedIncrement64(&g_LcPteStats.PeriodReadReqs);
    _InterlockedExchangeAdd64(&g_LcPteStats.TotalReadBytes, (LONG64)RequestBytes);

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    LONG64 lastTime = g_LcPteStats.LastReportTime;
    if (lastTime == 0)
    {
        _InterlockedCompareExchange64(&g_LcPteStats.LastReportTime, now.QuadPart, 0);
        return;
    }

    // 判定是否达到 1 秒时间窗口 (1 秒 = 10,000,000 个 100ns)
    if ((now.QuadPart - lastTime) >= 10000000ULL)
    {
        if (_InterlockedCompareExchange(&g_LcPteStats.ReportingGate, 1, 0) == 0)
        {
            LONG64 elapsed100ns = now.QuadPart - g_LcPteStats.LastReportTime;
            if (elapsed100ns >= 10000000ULL)
            {
                LONG64 periodReqs = _InterlockedExchange64(&g_LcPteStats.PeriodReadReqs, 0);
                LONG64 periodPages = _InterlockedExchange64(&g_LcPteStats.PeriodPages, 0);
                LONG64 periodHits = _InterlockedExchange64(&g_LcPteStats.PeriodFastHits, 0);
                LONG64 periodBytes = _InterlockedExchange64(&g_LcPteStats.PeriodBytes, 0);
                _InterlockedExchange64(&g_LcPteStats.LastReportTime, now.QuadPart);

                // 纯 64 位整数运算换算速率（规避内核浮点寄存器风险）
                ULONG64 qps = (periodReqs * 10000000ULL) / elapsed100ns;
                ULONG64 pps = (periodPages * 10000000ULL) / elapsed100ns;
                ULONG64 kbps = (periodBytes * 10000000ULL) / (elapsed100ns * 1024ULL);
                ULONG64 mbInt = kbps / 1024ULL;
                ULONG64 mbDec = ((kbps % 1024ULL) * 100ULL) / 1024ULL;

                ULONG64 hitRateInt = (periodPages > 0) ? ((periodHits * 100ULL) / periodPages) : 100;

                DbgPrint("[Perf] MemRead: %I64u req/s (%I64u pages/s) | %I64u.%02I64u MB/s | FastHit: %I64u%% | Total: %I64u reqs\n", qps,
                         pps, mbInt, mbDec, hitRateInt, (ULONG64)g_LcPteStats.TotalReadReqs);
            }
            _InterlockedExchange(&g_LcPteStats.ReportingGate, 0);
        }
    }
}
#endif

// 斐波那契黄金分割散列函数，乘数 11400714819323198485ULL (2^64 / 1.6180339887...)
// 彻底打散连续物理页与 2MB/4MB 周期对齐地址，消灭哈希碰撞与缓存颠簸
static __forceinline ULONG LcPte_HashPfn(ULONG64 pfn)
{
    return (ULONG)(((pfn ^ (pfn >> 12)) * 11400714819323198485ULL) & (LC_PTE_SLOT_COUNT - 1));
}
static ULONG64 _ScanPteBase(VOID)
{
    // 方法 1 (首选)：ACE 函数 96 (sub_140031EF0) 动态 PML4 自引用槽位扫描
    // 兼容 Windows 10/11 全版本 KASLR 随机化页表基址，基于纯硬件页表结构，无特征码失效风险
    __try
    {
        ULONG64 cr3 = __readcr3();
        PHYSICAL_ADDRESS pml4Phys;
        pml4Phys.QuadPart = (LONGLONG)(cr3 & 0xFFFFFFFFFFFFF000ULL);
        PULONG64 pml4Virt = (PULONG64)((g_ctx.UserVar && g_ctx.UserVar->Func.MmGetVirtualForPhysical)
                                           ? g_ctx.UserVar->Func.MmGetVirtualForPhysical(pml4Phys)
                                           : NULL);
        if (pml4Virt)
        {
            ULONG64 selfPfn = (ULONG64)pml4Phys.QuadPart & 0xFFFFFFFFF000ULL;
            // 遍历 PML4 高 256 个内核条目 (256 ~ 511)
            for (ULONG slot = 256; slot < 512; slot++)
            {
                if ((pml4Virt[slot] & 0xFFFFFFFFF000ULL) == selfPfn)
                {
                    // 命中自引用槽位！推导 PTE 虚拟基地址 (PteBase)
                    // 公式：((slot + 0x1FFFE00ULL) << 39)，其中 0x1FFFE00LL = 33553920LL
                    ULONG64 candidate = ((ULONG64)slot + 0x1FFFE00ULL) << 39;
                    if ((candidate >> 48) == 0xFFFF)
                    {
                        DBG("LcPteEngine: Located PteBase via ACE PML4 Self-Ref Slot [%lu] -> 0x%016llX", slot, candidate);
                        return candidate;
                    }
                }
            }
        }
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 捕获异常，继续回退到备用方法
    }

    // 方法 2 (备用)：从内核导出函数 MmGetVirtualForPhysical 提取动态重定位修补的 PteBase
    // 指令特征：movabs rdx, <PteBase>; shl rdx, 0x19 (48 BA <8 bytes> 48 C1 E2 19)
    PUCHAR pMmGVP =
        (PUCHAR)((g_ctx.UserVar && g_ctx.UserVar->Func.MmGetVirtualForPhysical) ? (PVOID)g_ctx.UserVar->Func.MmGetVirtualForPhysical
                                                                                : NULL);
    if (pMmGVP)
    {
        __try
        {
            for (ULONG i = 0; i < 48; i++)
            {
                if (pMmGVP[i] == 0x48 && pMmGVP[i + 1] == 0xBA && pMmGVP[i + 10] == 0x48 && pMmGVP[i + 11] == 0xC1 &&
                    pMmGVP[i + 12] == 0xE2 && pMmGVP[i + 13] == 0x19)
                {
                    ULONG64 candidate = *(PULONG64)(pMmGVP + i + 2);
                    if ((candidate >> 48) == 0xFFFF)
                    {
                        DBG("LcPteEngine: Located PteBase via MmGetVirtualForPhysical+0x%X -> 0x%016llX", i + 2, candidate);
                        return candidate;
                    }
                }
            }

            // 直接校验偏移 +0x22 处（标准 Windows 10/11 编译偏移）
            ULONG64 candidate22 = *(PULONG64)(pMmGVP + 0x22);
            if ((candidate22 >> 48) == 0xFFFF)
            {
                DBG("LcPteEngine: Located PteBase via MmGetVirtualForPhysical direct +0x22 -> 0x%016llX", candidate22);
                return candidate22;
            }
        }

        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    // 方法 3 (历史低版本兜底，Win10 1607 之前未随机化固定基址)
    return 0xFFFFF68000000000ULL;
}

typedef PVOID (*PFN_MmAllocateMappingAddress)(SIZE_T NumberOfBytes, ULONG PoolTag);
typedef VOID (*PFN_MmFreeMappingAddress)(PVOID BaseAddress, ULONG PoolTag);
static PFN_MmAllocateMappingAddress g_pfnMmAllocateMappingAddress = NULL;
static PFN_MmFreeMappingAddress g_pfnMmFreeMappingAddress = NULL;
static PVOID g_pReservedSystemVa = NULL;
static NTSTATUS LcPteEngine_Init(VOID)
{
    if (g_PteEngine.fInitialized)
        return STATUS_SUCCESS;
    g_PteEngine.PteBase = _ScanPteBase();
    if (!g_PteEngine.PteBase)
    {
        DBG("LcPteEngine: Failed to locate PteBase");
        return STATUS_NOT_FOUND;
    }

    DBG("LcPteEngine: Found PteBase = 0x%016llX", g_PteEngine.PteBase);
    if (!g_pfnMmAllocateMappingAddress || !g_pfnMmFreeMappingAddress)
    {
        if (g_ctx.UserVar && g_ctx.UserVar->KernelBase.QuadPart)
        {
            Utils::GetModuleExport((ULONG_PTR)g_ctx.UserVar->KernelBase.QuadPart, str_MmAllocateMappingAddress,
                                   (PULONG_PTR)&g_pfnMmAllocateMappingAddress);
            Utils::GetModuleExport((ULONG_PTR)g_ctx.UserVar->KernelBase.QuadPart, str_MmFreeMappingAddress,
                                   (PULONG_PTR)&g_pfnMmFreeMappingAddress);
        }
        if (!g_pfnMmAllocateMappingAddress || !g_pfnMmFreeMappingAddress)
        {
            DBG("[-] LcPteEngine: Failed to resolve MmAllocateMappingAddress/MmFreeMappingAddress");
            return STATUS_NOT_FOUND;
        }
    }

    SIZE_T totalBytes = LC_PTE_SLOT_COUNT * PAGE_SIZE;
    // 使用 'Mmdl' 伪装为系统合法 MDL 内存映射 Tag，规避 BigPool 审计
    g_pReservedSystemVa = g_pfnMmAllocateMappingAddress(totalBytes, 'Mmdl');
    if (!g_pReservedSystemVa)
    {
        DBG("[-] LcPteEngine: MmAllocateMappingAddress failed (size=%zu)", totalBytes);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (INT i = 0; i < LC_PTE_SLOT_COUNT; i++)
    {
        PLC_PTE_SLOT slot = &g_PteEngine.Slots[i];
        slot->pMappedPage = (PUCHAR)g_pReservedSystemVa + (i * PAGE_SIZE);
        slot->pPteVa = (ULONG64 *)(g_PteEngine.PteBase + (((ULONG64)slot->pMappedPage >> 9) & 0x7FFFFFFFF8ULL));
        slot->OriginalPte = *slot->pPteVa;
        slot->CachedPfn = LC_PTE_INVALID_PFN;
        slot->isWritable = 0;
        slot->Lock = 0;
        slot->Sequence = 0;
    }

    g_PteEngine.fInitialized = TRUE;
    DBG("[+] LcPteEngine: Successfully initialized %d slots via System PTEs (BaseVa=%p)", LC_PTE_SLOT_COUNT, g_pReservedSystemVa);
    return STATUS_SUCCESS;
}

static VOID LcPteEngine_Cleanup(VOID)
{
    if (!g_PteEngine.fInitialized)
        return;
    for (INT i = 0; i < LC_PTE_SLOT_COUNT; i++)
    {
        PLC_PTE_SLOT slot = &g_PteEngine.Slots[i];
        if (slot->pMappedPage && slot->pPteVa)
        {
            *slot->pPteVa = slot->OriginalPte;
            __invlpg(slot->pMappedPage);
        }

        slot->pMappedPage = NULL;
        slot->pPteVa = NULL;
        slot->CachedPfn = LC_PTE_INVALID_PFN;
        slot->isWritable = 0;
        slot->Lock = 0;
        slot->Sequence = 0;
    }

    if (g_pReservedSystemVa && g_pfnMmFreeMappingAddress)
    {
        g_pfnMmFreeMappingAddress(g_pReservedSystemVa, 'Mmdl');
        g_pReservedSystemVa = NULL;
    }

    g_PteEngine.fInitialized = FALSE;
    DBG("LcPteEngine: Cleaned up");
}

static BOOLEAN LcPte_CopyPhysical(_In_ ULONG64 PhysAddr, _Inout_ PVOID Buffer, _In_ ULONG Size, _In_ BOOLEAN fWrite)
{
    // 防御性校验：空指针、零尺寸、以及跨 4KB 物理页边界越界访问保护
    if (!g_PteEngine.fInitialized || !Buffer || Size == 0 || (((PhysAddr & 0xFFFULL) + Size) > PAGE_SIZE))
    {
        return FALSE;
    }

    ULONG64 targetPfn = PhysAddr >> 12;
    ULONG slotIndex = LcPte_HashPfn(targetPfn);
    PLC_PTE_SLOT slot = &g_PteEngine.Slots[slotIndex];

    // ========================================================================
    // 快路径 (Fast-Path)：基于 Sequence Lock (序列锁) 的读读全并发无锁直读
    // 1. 无需排他获取 slot->Lock，允许多个并发线程同时直读同一物理页！
    // 2. 只有在 slot->Sequence 为偶数（无并发换页）且 CachedPfn 严格匹配时执行。
    // 3. 读取完毕后再次比对 Sequence 与 CachedPfn，确保读取期间未发生任何换页覆写。
    // ========================================================================
    if (!fWrite)
    {
        LONG seq1 = slot->Sequence;
        _ReadWriteBarrier(); // 编译器屏障：阻断指令乱序，确保读取 sequence 发生在内存拷贝之前
        if ((seq1 & 1) == 0 && slot->CachedPfn == targetPfn)
        {
            PUCHAR pTarget = (PUCHAR)slot->pMappedPage + (PhysAddr & 0xFFFULL);
            BOOLEAN fFastSuccess = FALSE;
            __try
            {
                __movsb((PUCHAR)Buffer, pTarget, Size);
                fFastSuccess = TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                fFastSuccess = FALSE;
            }

            _ReadWriteBarrier(); // 编译器屏障：确保内存拷贝完成后再比对版本序列号
            // 二次校验版本序列号与 PFN：若一致，证明读取全过程数据处于原子稳定态，直接返回！
            if (fFastSuccess && slot->Sequence == seq1 && slot->CachedPfn == targetPfn)
            {
#if LC_ENABLE_READ_STATS
                LcPte_RecordReadStat(Size, TRUE);
#endif
                return TRUE;
            }
        }
    }

    // ========================================================================
    // 慢路径 (Slow-Path)：Cache Miss 或并发换页争用
    // 获取该 Slot 专属自旋锁，采用轻量阶梯式退避 (Ladder Backoff)，杜绝微架构长时间卡顿
    // ========================================================================
    ULONG spinCount = 0;
    while (_InterlockedCompareExchange(&slot->Lock, 1, 0) != 0)
    {
        if (spinCount < 32)
        {
            _mm_pause();
        }
        else if (spinCount < 128)
        {
            for (int p = 0; p < 4; p++)
            {
                _mm_pause();
            }
        }
        else
        {
            YieldProcessor();
        }

        if (++spinCount > 4000)
        {
            // 超时直接返回失败，严禁调用 DBG()，彻底杜绝全局 DbgPrint 自旋锁风暴
            return FALSE;
        }
    }

    // 二次确认：在自旋争用期间已有并发线程完成了目标 PFN 的映射
    BOOLEAN needRemap = (slot->CachedPfn != targetPfn);
    if (fWrite && !slot->isWritable)
    {
        needRemap = TRUE;
    }

    if (needRemap)
    {
        // 核心序列锁机制：先递增 Sequence 使其变奇数，宣告快路径此槽正在换页，禁止采用
        _InterlockedIncrement(&slot->Sequence);

        // 清空 CachedPfn，阻断并发快路径脏读
        _InterlockedExchange64((volatile LONG64 *)&slot->CachedPfn, (LONG64)LC_PTE_INVALID_PFN);

        // 强制开启 Bit 63 NX (No-Execute，防 W+X 违规与 ACE 扫描)
        // 读操作严格赋予只读权限 (RW=0)，无 Global 标志防多核 TLB 永久残留
        ULONG64 flags = fWrite ? LC_PTE_FLAGS_WRITE : LC_PTE_FLAGS_READ;
        ULONG64 newPte = (PhysAddr & 0xFFFFFFFFFF000ULL) | flags;

        *slot->pPteVa = newPte;
        __invlpg(slot->pMappedPage); // 刷新当前 CPU 核心的 TLB
        slot->isWritable = fWrite ? 1 : 0;

        _InterlockedExchange64((volatile LONG64 *)&slot->CachedPfn, (LONG64)targetPfn);

        // 递增 Sequence 恢复为偶数，宣告换页完毕，快路径重新放行并发直读
        _InterlockedIncrement(&slot->Sequence);
    }

    PUCHAR pTarget = (PUCHAR)slot->pMappedPage + (PhysAddr & 0xFFFULL);
    BOOLEAN fSuccess = FALSE;
    __try
    {
        if (!fWrite)
        {
            __movsb((PUCHAR)Buffer, pTarget, Size);
        }
        else
        {
            __movsb(pTarget, (PUCHAR)Buffer, Size);
        }
        fSuccess = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        fSuccess = FALSE;
    }

    // 释放槽位排他锁。保持该物理页驻留缓存，供后续高频命中！
    _InterlockedExchange(&slot->Lock, 0);

#if LC_ENABLE_READ_STATS
    if (fSuccess && !fWrite)
    {
        LcPte_RecordReadStat(Size, FALSE);
    }
#endif

    return fSuccess;
}

ULONG LcPte_ReadPhysicalContiguous(LARGE_INTEGER physAddr, PUCHAR buf, ULONG count)
{
    if (!buf || count == 0)
        return 0;

    ULONG uReadOffset = 0;
    while (uReadOffset < count)
    {
        ULONG64 currentPa = (ULONG64)physAddr.QuadPart + uReadOffset;
        ULONG pageOffset = (ULONG)(currentPa & 0xFFFULL);
        ULONG toRead = min(PAGE_SIZE - pageOffset, count - uReadOffset);
        if (!LcPte_CopyPhysical(currentPa, buf + uReadOffset, toRead, FALSE))
        {
            break;
        }

        uReadOffset += toRead;
    }

#if LC_ENABLE_READ_STATS
    if (uReadOffset > 0)
    {
        LcPte_CheckAndReportStats(uReadOffset);
    }
#endif

    return uReadOffset;
}

static ULONG LcPte_WritePhysicalContiguous(LARGE_INTEGER physAddr, PUCHAR buf, ULONG count)
{
    if (!buf || count == 0)
        return 0;

    ULONG uWriteOffset = 0;
    while (uWriteOffset < count)
    {
        ULONG64 currentPa = (ULONG64)physAddr.QuadPart + uWriteOffset;
        ULONG pageOffset = (ULONG)(currentPa & 0xFFFULL);
        ULONG toWrite = min(PAGE_SIZE - pageOffset, count - uWriteOffset);
        if (!LcPte_CopyPhysical(currentPa, buf + uWriteOffset, toWrite, TRUE))
        {
            DBG("[-] LcPte_WritePhysical: Failed at PA=0x%016llX (offset=%lu/%lu)", currentPa, uWriteOffset, count);
            break;
        }

        uWriteOffset += toWrite;
    }

    if (uWriteOffset < count)
    {
        DBG("[-] LcPte_WritePhysical: Incomplete write PA=0x%016llX, Written=%lu/%lu", physAddr.QuadPart, uWriteOffset, count);
    }

    return uWriteOffset;
}

static BOOLEAN LcVirtToPhys(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _Out_ PULONG64 pPhysAddr)
{
    if (!Cr3 || !pPhysAddr)
        return FALSE;

    ULONG64 pml4_idx = (Va >> 39) & 0x1FF;
    ULONG64 pdpt_idx = (Va >> 30) & 0x1FF;
    ULONG64 pd_idx = (Va >> 21) & 0x1FF;
    ULONG64 pt_idx = (Va >> 12) & 0x1FF;
    ULONG64 page_off = Va & 0xFFFULL;

    // 级别 1: PML4
    ULONG64 pml4_pa = (Cr3 & 0x000FFFFFFFFFF000ULL) + pml4_idx * 8;
    ULONG64 pml4e = 0;
    if (!LcPte_CopyPhysical(pml4_pa, &pml4e, sizeof(pml4e), FALSE) || !(pml4e & 1))
        return FALSE;

    // 级别 2: PDPT
    ULONG64 pdpt_pa = (pml4e & 0x000FFFFFFFFFF000ULL) + pdpt_idx * 8;
    ULONG64 pdpte = 0;
    if (!LcPte_CopyPhysical(pdpt_pa, &pdpte, sizeof(pdpte), FALSE) || !(pdpte & 1))
        return FALSE;
    if (pdpte & (1ULL << 7))
    { // 1GB 超大页
        *pPhysAddr = (pdpte & 0x000FFFFFC0000000ULL) + (Va & 0x3FFFFFFFULL);
        return TRUE;
    }

    // 级别 3: PD
    ULONG64 pd_pa = (pdpte & 0x000FFFFFFFFFF000ULL) + pd_idx * 8;
    ULONG64 pde = 0;
    if (!LcPte_CopyPhysical(pd_pa, &pde, sizeof(pde), FALSE) || !(pde & 1))
        return FALSE;
    if (pde & (1ULL << 7))
    { // 2MB 大页
        *pPhysAddr = (pde & 0x000FFFFFFFE00000ULL) + (Va & 0x1FFFFFULL);
        return TRUE;
    }

    // 级别 4: PT
    ULONG64 pt_pa = (pde & 0x000FFFFFFFFFF000ULL) + pt_idx * 8;
    ULONG64 pte = 0;
    if (!LcPte_CopyPhysical(pt_pa, &pte, sizeof(pte), FALSE) || !(pte & 1))
        return FALSE;

    *pPhysAddr = (pte & 0x000FFFFFFFFFF000ULL) + page_off;
    return TRUE;
}

BOOLEAN LcReadVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _Out_ PVOID Buffer, _In_ ULONG Size)
{
    if (!Cr3 || !Va || !Buffer || Size == 0)
        return FALSE;

    PUCHAR pDst = (PUCHAR)Buffer;
    ULONG bytesRemaining = Size;
    ULONG64 curVa = Va;

    while (bytesRemaining > 0)
    {
        ULONG pageOffset = (ULONG)(curVa & 0xFFFULL);
        ULONG bytesInPage = PAGE_SIZE - pageOffset;
        ULONG chunk = (bytesRemaining < bytesInPage) ? bytesRemaining : bytesInPage;

        ULONG64 pa = 0;
        if (!LcVirtToPhys(Cr3, curVa, &pa))
        {
            return FALSE;
        }

        if (!LcPte_CopyPhysical(pa, pDst, chunk, FALSE))
        {
            return FALSE;
        }

        pDst += chunk;
        curVa += chunk;
        bytesRemaining -= chunk;
    }

    return TRUE;
}

BOOLEAN LcWriteVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _In_ const PVOID Buffer, _In_ ULONG Size)
{
    if (!Cr3 || !Va || !Buffer || Size == 0)
        return FALSE;

    const UCHAR *pSrc = (const UCHAR *)Buffer;
    ULONG bytesRemaining = Size;
    ULONG64 curVa = Va;

    while (bytesRemaining > 0)
    {
        ULONG pageOffset = (ULONG)(curVa & 0xFFFULL);
        ULONG bytesInPage = PAGE_SIZE - pageOffset;
        ULONG chunk = (bytesRemaining < bytesInPage) ? bytesRemaining : bytesInPage;

        ULONG64 pa = 0;
        if (!LcVirtToPhys(Cr3, curVa, &pa))
        {
            return FALSE;
        }

        if (!LcPte_CopyPhysical(pa, (PVOID)pSrc, chunk, TRUE))
        {
            return FALSE;
        }

        pSrc += chunk;
        curVa += chunk;
        bytesRemaining -= chunk;
    }

    return TRUE;
}

static __forceinline ULONG Rotr32(ULONG value, ULONG shift)
{
    shift &= 31;
    if (shift == 0)
        return value;
    return (value >> shift) | (value << (32 - shift));
}

static BOOLEAN LcExecBytecode(_In_ ULONG64 Cr3, _In_reads_(cInstructions) const VM_INSTRUCTION *pInstructions, _In_ ULONG cInstructions,
                              _Out_ PULONG64 pqwResult, _Out_ PULONG pdwError)
{
    if (!pInstructions || cInstructions == 0 || !pqwResult || !pdwError)
    {
        if (pdwError)
            *pdwError = 0xC000000D; // STATUS_INVALID_PARAMETER
        return FALSE;
    }

    ULONG64 R[8] = {0};
    ULONG pc = 0;
    ULONG stepCount = 0;
    const ULONG maxSteps = 100000;

    *pqwResult = 0;
    *pdwError = 0;

    while (pc < cInstructions)
    {
        if (++stepCount > maxSteps)
        {
            *pdwError = 0xC000002E; // STATUS_TIME_LIMIT_EXCEEDED
            return FALSE;
        }

        const VM_INSTRUCTION *pInst = &pInstructions[pc];
        UCHAR op = pInst->op;
        UCHAR dst = pInst->regDst;
        UCHAR src = pInst->regSrc;
        ULONG imm = pInst->imm32;

        if (dst >= 8 || src >= 8)
        {
            *pdwError = 0xC0000005; // STATUS_ACCESS_VIOLATION
            return FALSE;
        }

        switch (op)
        {
        case VM_OP_LOAD_IMM:
            R[dst] = (ULONG64)imm;
            break;

        case VM_OP_READ_VA64:
        {
            ULONG64 targetVa = R[src] + (LONG64)(LONG)imm;
            ULONG64 val64 = 0;
            if (!LcReadVirtualMemory(Cr3, targetVa, &val64, sizeof(val64)))
            {
                *pdwError = 0xC0000005;
                return FALSE;
            }
            R[dst] = val64;
            break;
        }

        case VM_OP_READ_VA32:
        {
            ULONG64 targetVa = R[src] + (LONG64)(LONG)imm;
            ULONG32 val32 = 0;
            if (!LcReadVirtualMemory(Cr3, targetVa, &val32, sizeof(val32)))
            {
                *pdwError = 0xC0000005;
                return FALSE;
            }
            R[dst] = (ULONG64)val32;
            break;
        }

        case VM_OP_ADD:
            R[dst] = R[dst] + R[src];
            break;

        case VM_OP_ADD_IMM:
            R[dst] = R[dst] + (LONG64)(LONG)imm;
            break;

        case VM_OP_SUB:
            R[dst] = R[dst] - R[src];
            break;

        case VM_OP_XOR:
            R[dst] = R[dst] ^ R[src];
            break;

        case VM_OP_ROR32:
        {
            ULONG v = (ULONG)R[dst];
            ULONG shift = (ULONG)(R[src] & 0x1F);
            R[dst] = (ULONG64)Rotr32(v, shift);
            break;
        }

        case VM_OP_AND_IMM:
            R[dst] = R[dst] & (ULONG64)imm;
            break;

        case VM_OP_SHL_IMM:
            R[dst] = R[dst] << (imm & 0x3F);
            break;

        case VM_OP_SHR_IMM:
            R[dst] = R[dst] >> (imm & 0x3F);
            break;

        case VM_OP_OR:
            R[dst] = R[dst] | R[src];
            break;

        case VM_OP_JMP:
            if (imm >= cInstructions)
            {
                *pdwError = 0xC0000005;
                return FALSE;
            }
            pc = imm;
            continue;

        case VM_OP_JMP_EQ:
            if (R[dst] == R[src])
            {
                if (imm >= cInstructions)
                {
                    *pdwError = 0xC0000005;
                    return FALSE;
                }
                pc = imm;
                continue;
            }
            break;

        case VM_OP_JMP_NE:
            if (R[dst] != R[src])
            {
                if (imm >= cInstructions)
                {
                    *pdwError = 0xC0000005;
                    return FALSE;
                }
                pc = imm;
                continue;
            }
            break;

        case VM_OP_JMP_LT:
            if (R[dst] < R[src])
            {
                if (imm >= cInstructions)
                {
                    *pdwError = 0xC0000005;
                    return FALSE;
                }
                pc = imm;
                continue;
            }
            break;

        case VM_OP_JMP_LE:
            if (R[dst] <= R[src])
            {
                if (imm >= cInstructions)
                {
                    *pdwError = 0xC0000005;
                    return FALSE;
                }
                pc = imm;
                continue;
            }
            break;

        case VM_OP_JMP_GT:
            if (R[dst] > R[src])
            {
                if (imm >= cInstructions)
                {
                    *pdwError = 0xC0000005;
                    return FALSE;
                }
                pc = imm;
                continue;
            }
            break;

        case VM_OP_JMP_GE:
            if (R[dst] >= R[src])
            {
                if (imm >= cInstructions)
                {
                    *pdwError = 0xC0000005;
                    return FALSE;
                }
                pc = imm;
                continue;
            }
            break;

        case VM_OP_RET:
            *pqwResult = R[dst];
            *pdwError = 0;
            return TRUE;

        default:
            *pdwError = 0xC0000002; // STATUS_NOT_IMPLEMENTED
            return FALSE;
        }

        pc++;
    }

    // 顺序执行完毕，默认返回 R[0]
    *pqwResult = R[0];
    *pdwError = 0;
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL) ULONG
    PhysicalMemoryPartialRead(IN MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ LARGE_INTEGER physAddr, _Inout_ PUCHAR buf, _In_ ULONG count)
{
    UNREFERENCED_PARAMETER(UserVar);
    return LcPte_ReadPhysicalContiguous(physAddr, buf, count);
}

_IRQL_requires_max_(PASSIVE_LEVEL) ULONG
    PhysicalMemoryPartialWrite(IN MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ LARGE_INTEGER PhysicalAddress, _In_ PUCHAR lpBuffer,
                               _In_ SIZE_T Length)
{
    UNREFERENCED_PARAMETER(UserVar);
    return LcPte_WritePhysicalContiguous(PhysicalAddress, lpBuffer, (ULONG)Length);
}

static ULONG DeviceKernel_ReadPhys(_In_ PLC_CONTEXT ctxLC, _In_ LARGE_INTEGER physAddr, _Out_writes_bytes_(count) PUCHAR buf,
                                   _In_ ULONG count)
{
    UNREFERENCED_PARAMETER(ctxLC);
    return LcPte_ReadPhysicalContiguous(physAddr, buf, count);
}

static __forceinline ULONG64 LcMemMap_TranslateAddress(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 pa, _In_ ULONG cb)
{
    if (!ctxLC || ctxLC->cMemMap == 0 || !ctxLC->pMemMap)
    {
        return pa;
    }

    PLC_MEMMAP_ENTRY peMap = ctxLC->pMemMap;
    if ((pa >= peMap->pa) && (pa + cb <= peMap->pa + peMap->cb))
    {
        return pa + peMap->paRemap - peMap->pa;
    }

    for (ULONG i = 0; i < ctxLC->cMemMap; i++)
    {
        peMap = &ctxLC->pMemMap[i];
        if ((pa >= peMap->pa) && (pa + cb <= peMap->pa + peMap->cb))
        {
            return pa + peMap->paRemap - peMap->pa;
        }
    }

    return pa;
}

static VOID DeviceKernel_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ ULONG cpMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!ctxLC || !ppMEMs || cpMEMs == 0)
    {
        return;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    UNREFERENCED_PARAMETER(UserVar);
    ULONG i = 0;
    while (i < cpMEMs)
    {
        PMEM_SCATTER pMEM = ppMEMs[i];
        if (!pMEM || !pMEM->pb || pMEM->cb == 0 || pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM))
        {
            if (pMEM && !pMEM->f)
            {
                pMEM->f = FALSE;
            }
            i++;
            continue;
        }

        // 探测后续相邻散列项是否在物理地址和内存缓冲区上完全连续 (Contiguous Range Burst)
        ULONG j = i + 1;
        ULONG totalContigBytes = pMEM->cb;
        while (j < cpMEMs)
        {
            PMEM_SCATTER pNext = ppMEMs[j];
            if (!pNext || !pNext->pb || pNext->cb == 0 || pNext->f || MEM_SCATTER_ADDR_ISINVALID(pNext))
            {
                break;
            }
            PMEM_SCATTER pPrev = ppMEMs[j - 1];
            if ((pNext->qwA == pPrev->qwA + pPrev->cb) && (pNext->pb == pPrev->pb + pPrev->cb))
            {
                totalContigBytes += pNext->cb;
                j++;
            }
            else
            {
                break;
            }
        }

        if (j > i + 1)
        {
            // ★★★ 命中物理连续跨页块！单次跨页突发直读 (例如连续 16KB~400KB) ★★★
            LARGE_INTEGER paStart;
            paStart.QuadPart = pMEM->qwA;
            ULONG nRead = DeviceKernel_ReadPhys(ctxLC, paStart, pMEM->pb, totalContigBytes);
            if (nRead == totalContigBytes)
            {
                for (ULONG k = i; k < j; k++)
                {
                    ppMEMs[k]->f = TRUE;
                }
                i = j;
                continue;
            }
            // 若大块读取偶发未全量成功，安全回退至单项逐页处理
        }

        // 单项物理读路径
        LARGE_INTEGER pa;
        pa.QuadPart = pMEM->qwA;
        ULONG nRead = DeviceKernel_ReadPhys(ctxLC, pa, pMEM->pb, pMEM->cb);
        if (nRead == pMEM->cb)
        {
            pMEM->f = TRUE;
        }
        else
        {
            pMEM->f = FALSE;
        }
        i++;
    }
}

static VOID DeviceKernel_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ ULONG cpMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!ctxLC)
    {
        return;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    UNREFERENCED_PARAMETER(UserVar);
    for (ULONG i = 0; i < cpMEMs; i++)
    {
        PMEM_SCATTER pMEM = ppMEMs[i];
        if (!pMEM || !pMEM->pb || pMEM->cb == 0 || pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM))
        {
            if (pMEM && !pMEM->f)
            {
                pMEM->f = FALSE;
            }
            continue;
        }

        LARGE_INTEGER pa;
        pa.QuadPart = pMEM->qwA;
        ULONG nWritten = LcPte_WritePhysicalContiguous(pa, pMEM->pb, (ULONG)pMEM->cb);
        pMEM->f = (nWritten == pMEM->cb);
        if (!pMEM->f)
        {
            DBG("[-] DeviceKernel_WriteScatter: Write failed at PA=0x%016llX, Size=%lu", pMEM->qwA, pMEM->cb);
        }
    }
}

static ULONG64 _GetSystemDirectoryTableBase(VOID)
{
    ULONG64 cr3 = 0;
    if (g_ctx.UserVar && g_ctx.UserVar->Func.pPsInitialSystemProcess && *g_ctx.UserVar->Func.pPsInitialSystemProcess)
    {
        PEPROCESS pSysProc = *g_ctx.UserVar->Func.pPsInitialSystemProcess;
        cr3 = *(PULONG64)((PUCHAR)pSysProc + 0x28);
    }

    if (cr3 == 0)
    {
        cr3 = __readcr3() & 0xFFFFFFFFFFFFF000ULL;
    }

    return cr3;
}

static ULONG64 _GetKernelBase(VOID)
{
    PVOID pBase = NULL;
    PVOID pRefFunc =
        (g_ctx.UserVar && g_ctx.UserVar->Func.IoCreateDevice) ? (PVOID)g_ctx.UserVar->Func.IoCreateDevice : (PVOID)g_ctx.UserVar;
    if (g_ctx.UserVar && g_ctx.UserVar->Func.RtlPcToFileHeader && pRefFunc)
    {
        if (g_ctx.UserVar->Func.RtlPcToFileHeader(pRefFunc, &pBase) && pBase)
        {
            return (ULONG64)pBase;
        }
    }

    if (pRefFunc)
    {
        ULONG_PTR addr = ((ULONG_PTR)pRefFunc) & ~0xFFFULL;
        for (ULONG i = 0; i < 0x20000; i++, addr -= PAGE_SIZE)
        {
            BOOLEAN bAddrValid =
                (g_ctx.UserVar && g_ctx.UserVar->Func.MmIsAddressValid) ? g_ctx.UserVar->Func.MmIsAddressValid((PVOID)addr) : FALSE;
            if (bAddrValid)
            {
                PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)addr;
                if (pDos->e_magic == IMAGE_DOS_SIGNATURE && pDos->e_lfanew > 0 && pDos->e_lfanew < 0x1000)
                {
                    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(addr + pDos->e_lfanew);
                    BOOLEAN bNtValid =
                        (g_ctx.UserVar && g_ctx.UserVar->Func.MmIsAddressValid) ? g_ctx.UserVar->Func.MmIsAddressValid(pNt) : FALSE;
                    if (bNtValid && pNt->Signature == IMAGE_NT_SIGNATURE)
                    {
                        return (ULONG64)addr;
                    }
                }
            }
        }
    }

    return 0;
}

static BOOLEAN DeviceKernel_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if (!ctxLC || !pqwValue)
    {
        return FALSE;
    }

    *pqwValue = 0;

    switch (fOption)
    {
    case LC_OPT_CORE_ADDR_MAX:
        *pqwValue = ctxLC->Config.paMax;
        return TRUE;

    case LC_OPT_CORE_PRINTF_ENABLE:
    case LC_OPT_CORE_VERBOSE:
        *pqwValue = 1;
        return TRUE;

    case LC_OPT_CORE_VERBOSE_EXTRA:
    case LC_OPT_CORE_VERBOSE_EXTRA_TLP:
        *pqwValue = 0;
        return TRUE;

    case LC_OPT_CORE_VERSION_MAJOR:
        *pqwValue = 2;
        return TRUE;

    case LC_OPT_CORE_VERSION_MINOR:
        *pqwValue = 15;
        return TRUE;

    case LC_OPT_CORE_VERSION_REVISION:
        *pqwValue = 0;
        return TRUE;

    case LC_OPT_CORE_VOLATILE:
        *pqwValue = 1;
        return TRUE;

    case LC_OPT_CORE_READONLY:
        *pqwValue = 0;
        return TRUE;

    case LC_OPT_MEMORYINFO_VALID:
        *pqwValue = 1;
        return TRUE;

    case LC_OPT_MEMORYINFO_ARCH:
        *pqwValue = 3; // LC_ARCH_X64 (0:NA, 1:X86, 2:X86PAE, 3:X64, 4:ARM64)
        return TRUE;

    case LC_OPT_MEMORYINFO_FLAG_32BIT:
    case LC_OPT_MEMORYINFO_FLAG_PAE:
        *pqwValue = 0;
        return TRUE;

    case LC_OPT_MEMORYINFO_OS_DTB:
        if (ctxLC->MemInfo.CR3.QuadPart == 0)
        {
            ctxLC->MemInfo.CR3.QuadPart = _GetSystemDirectoryTableBase();
        }
        *pqwValue = ctxLC->MemInfo.CR3.QuadPart;
        return TRUE;

    case LC_OPT_MEMORYINFO_OS_KERNELBASE:
        if (ctxLC->MemInfo.KernBase.QuadPart == 0)
        {
            ctxLC->MemInfo.KernBase.QuadPart = _GetKernelBase();
        }
        *pqwValue = ctxLC->MemInfo.KernBase.QuadPart;
        return TRUE;

    case LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP:
        *pqwValue = 0x8664; // IMAGE_FILE_MACHINE_AMD64 (Intel 64 和 AMD64 统一标准码)
        return TRUE;

    case LC_OPT_MEMORYINFO_OS_VERSION_MAJOR:
        *pqwValue = 10;
        return TRUE;

    case LC_OPT_MEMORYINFO_OS_VERSION_MINOR:
        *pqwValue = 0;
        return TRUE;

    case LC_OPT_MEMORYINFO_OS_NUM_PROCESSORS:
        *pqwValue = (ULONG64)KeQueryActiveProcessorCount(NULL);
        return TRUE;

    case LC_OPT_MEMORYINFO_OS_SYSTEMTIME:
    {
        LARGE_INTEGER SystemTime;
        KeQuerySystemTime(&SystemTime);
        *pqwValue = (ULONG64)SystemTime.QuadPart;
    }
        return TRUE;

    case LC_OPT_MEMORYINFO_OS_UPTIME:
    {
        LARGE_INTEGER TickCount;
        KeQueryTickCount(&TickCount);
        ULONG TimeInc = KeQueryTimeIncrement();
        *pqwValue = (ULONG64)((TickCount.QuadPart * TimeInc) / 10000000ULL);
    }
        return TRUE;

    default:
        // 未显式列举的扩展/探测类选项统一赋 0 并返回 TRUE，彻底杜绝客户端 Check 3 因 fMsgResult=0 致命中断
        *pqwValue = 0;
        return TRUE;
    }
}

static __forceinline VOID LcFormatHex(char *dst, ULONG64 val, int digits)
{
    static const char hexChars[] = "0123456789abcdef";
    for (int i = digits - 1; i >= 0; i--)
    {
        dst[i] = hexChars[val & 0xF];
        val >>= 4;
    }
}

BOOLEAN LcMemMap_GetRangesAsText(_In_ PLC_CONTEXT ctxLC, _Out_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!ctxLC || !ppbDataOut || !ctxLC->UserVar)
    {
        return FALSE;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    if (ctxLC->cMemMap == 0 || ctxLC->cMemMap > 1024)
    {
        return FALSE;
    }

    ULONG cb = ctxLC->cMemMap * 64 + 1;
    PCHAR pb = (PCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cb, LC_POOL_TAG);
    if (!pb)
    {
        return FALSE;
    }

    UserVar->Func.RtlZeroMemory(pb, cb);
    ULONG o = 0;
    for (ULONG i = 0; i < ctxLC->cMemMap && o < cb - 64; i++)
    {
        ULONG64 paStart = ctxLC->pMemMap[i].pa;
        ULONG64 paEnd = ctxLC->pMemMap[i].pa + ctxLC->pMemMap[i].cb - 1;
        ULONG64 paRemap = ctxLC->pMemMap[i].paRemap;

        LcFormatHex(pb + o, i, 4);
        o += 4;
        pb[o++] = ' ';
        LcFormatHex(pb + o, paStart, 16);
        o += 16;
        pb[o++] = ' ';
        pb[o++] = '-';
        pb[o++] = ' ';
        LcFormatHex(pb + o, paEnd, 16);
        o += 16;
        pb[o++] = ' ';
        pb[o++] = '-';
        pb[o++] = '>';
        pb[o++] = ' ';
        LcFormatHex(pb + o, paRemap, 16);
        o += 16;
        pb[o++] = '\n';
    }

    pb[cb - 1] = '\0';
    *ppbDataOut = (PUCHAR)pb;
    if (pcbDataOut)
    {
        *pcbDataOut = o + 1;
    }

    return TRUE;
}

static BOOLEAN DeviceKernel_SetOption(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    UNREFERENCED_PARAMETER(ctxLC);
    UNREFERENCED_PARAMETER(fOption);
    UNREFERENCED_PARAMETER(qwValue);
    return TRUE;
}

BOOLEAN LcMemMap_GetRangesAsStruct(_In_ PLC_CONTEXT ctxLC, _Out_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut);

static BOOLEAN DeviceKernel_Command(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _In_ ULONG cbDataIn,
                                    _In_reads_opt_(cbDataIn) PUCHAR pbDataIn, _Out_opt_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    UNREFERENCED_PARAMETER(cbDataIn);
    UNREFERENCED_PARAMETER(pbDataIn);

    if (ppbDataOut)
    {
        *ppbDataOut = NULL;
    }
    if (pcbDataOut)
    {
        *pcbDataOut = 0;
    }

    if (!ctxLC)
    {
        return FALSE;
    }

    switch (fOption)
    {
    case LC_CMD_STATISTICS_GET:
        if (ppbDataOut && pcbDataOut && ctxLC->UserVar)
        {
            PLC_STATISTICS pStat =
                (PLC_STATISTICS)ctxLC->UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sizeof(LC_STATISTICS), LC_POOL_TAG);
            if (pStat)
            {
                ctxLC->UserVar->Func.RtlZeroMemory(pStat, sizeof(LC_STATISTICS));
                pStat->dwVersion = 1;
                *ppbDataOut = (PUCHAR)pStat;
                *pcbDataOut = sizeof(LC_STATISTICS);
                return TRUE;
            }
        }
        return TRUE;

    case LC_CMD_MEMMAP_GET:
        return LcMemMap_GetRangesAsText(ctxLC, ppbDataOut, pcbDataOut);

    case LC_CMD_MEMMAP_GET_STRUCT:
        return LcMemMap_GetRangesAsStruct(ctxLC, ppbDataOut, pcbDataOut);

    case LC_CMD_MEMMAP_SET:
    case LC_CMD_MEMMAP_SET_STRUCT:
        // 允许客户端更新内存映射，应答成功
        return TRUE;

    case LC_CMD_AGENT_GET_MSR:
    {
        if (!pbDataIn || cbDataIn < sizeof(LC_CMD_AGENT_MSR_REQ) || !ctxLC->UserVar)
        {
            return FALSE;
        }
        PLC_CMD_AGENT_MSR_REQ pReq = (PLC_CMD_AGENT_MSR_REQ)pbDataIn;
        ULONG cbRsp = sizeof(LC_CMD_AGENT_MSR_RSP);
        PLC_CMD_AGENT_MSR_RSP pRsp = (PLC_CMD_AGENT_MSR_RSP)ctxLC->UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cbRsp, LC_POOL_TAG);
        if (!pRsp)
            return FALSE;
        ctxLC->UserVar->Func.RtlZeroMemory(pRsp, cbRsp);
        pRsp->dwTag = pReq->dwTag;

        ULONG64 msrVal = 0;
        if (MachenikeReadMsrSafe((ULONG)pReq->qwMsr, &msrVal))
        {
            pRsp->fSuccess = TRUE;
            pRsp->dwError = 0;
            pRsp->qwValue = msrVal;
        }
        else
        {
            pRsp->fSuccess = FALSE;
            pRsp->dwError = 1;
            pRsp->qwValue = 0;
        }

        if (ppbDataOut)
            *ppbDataOut = (PUCHAR)pRsp;
        if (pcbDataOut)
            *pcbDataOut = cbRsp;
        return TRUE;
    }

    case LC_CMD_AGENT_EXEC_BYTECODE:
    {
        if (!pbDataIn || cbDataIn < sizeof(LC_CMD_AGENT_BYTECODE_REQ) || !ctxLC->UserVar)
        {
            return FALSE;
        }
        PLC_CMD_AGENT_BYTECODE_REQ pReq = (PLC_CMD_AGENT_BYTECODE_REQ)pbDataIn;
        ULONG expectedMin = sizeof(LC_CMD_AGENT_BYTECODE_REQ) + pReq->cInstructions * sizeof(VM_INSTRUCTION);
        if (cbDataIn < expectedMin)
        {
            return FALSE;
        }

        ULONG cbRsp = sizeof(LC_CMD_AGENT_BYTECODE_RSP);
        PLC_CMD_AGENT_BYTECODE_RSP pRsp =
            (PLC_CMD_AGENT_BYTECODE_RSP)ctxLC->UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cbRsp, LC_POOL_TAG);
        if (!pRsp)
            return FALSE;
        ctxLC->UserVar->Func.RtlZeroMemory(pRsp, cbRsp);

        ULONG64 result = 0;
        ULONG error = 0;
        BOOLEAN fExec = LcExecBytecode(pReq->qwCr3, pReq->Instructions, pReq->cInstructions, &result, &error);

        pRsp->fSuccess = fExec ? 1 : 0;
        pRsp->dwError = error;
        pRsp->qwResult = result;

        if (ppbDataOut)
            *ppbDataOut = (PUCHAR)pRsp;
        if (pcbDataOut)
            *pcbDataOut = cbRsp;
        return TRUE;
    }

    case LC_CMD_BENCHMARK_READ_1S:
    {
        ULONG64 targetPa = 0x1000;
        ULONG testReadSize = PAGE_SIZE;

        if (pbDataIn && cbDataIn >= sizeof(LC_CMD_BENCHMARK_REQ))
        {
            PLC_CMD_BENCHMARK_REQ pReq = (PLC_CMD_BENCHMARK_REQ)pbDataIn;
            if (pReq->qwPhysicalAddress != 0)
            {
                targetPa = pReq->qwPhysicalAddress;
            }
            if (pReq->cbRead > 0 && pReq->cbRead <= PAGE_SIZE)
            {
                testReadSize = pReq->cbRead;
            }
        }

        // 分配 4KB 独立非分页缓冲用于压测接收，杜绝内核栈溢出风险
        PUCHAR pTestBuf = NULL;
        if (ctxLC->UserVar)
        {
            pTestBuf = (PUCHAR)ctxLC->UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, LC_POOL_TAG);
        }
        if (!pTestBuf)
        {
            return FALSE;
        }

        ULONG64 opCount = 0;
        ULONG64 byteCount = 0;
        ULONG64 fastHitCount = 0;

        LARGE_INTEGER startTime, curTime;
        KeQuerySystemTime(&startTime);
        ULONG64 targetTime = startTime.QuadPart + 10000000ULL; // 1秒 = 10,000,000 个 100ns

#if LC_ENABLE_READ_STATS
        LONG64 hitsBefore = g_LcPteStats.PeriodFastHits;
#endif

        // 执行 1 秒无限制高速物理内存直读压测
        while (TRUE)
        {
            if (LcPte_CopyPhysical(targetPa, pTestBuf, testReadSize, FALSE))
            {
                opCount++;
                byteCount += testReadSize;
            }

            // 每 256 次采样一次时间，将计时开销降到千分之一以下，真实榨干物理读取极限性能
            if ((opCount & 0xFF) == 0)
            {
                KeQuerySystemTime(&curTime);
                if ((ULONG64)curTime.QuadPart >= targetTime)
                {
                    break;
                }
            }
        }

        KeQuerySystemTime(&curTime);
        ULONG64 elapsed100ns = curTime.QuadPart - startTime.QuadPart;
        if (elapsed100ns == 0)
        {
            elapsed100ns = 1;
        }

#if LC_ENABLE_READ_STATS
        LONG64 hitsAfter = g_LcPteStats.PeriodFastHits;
        fastHitCount = (hitsAfter >= hitsBefore) ? (ULONG64)(hitsAfter - hitsBefore) : opCount;
        if (fastHitCount > opCount)
            fastHitCount = opCount;
#else
        fastHitCount = opCount;
#endif

        ULONG64 qps = (opCount * 10000000ULL) / elapsed100ns;
        ULONG64 kbps = (byteCount * 10000000ULL) / (elapsed100ns * 1024ULL);
        ULONG64 mbInt = kbps / 1024ULL;
        ULONG64 mbDec = ((kbps % 1024ULL) * 100ULL) / 1024ULL;
        ULONG64 hitRate = (opCount > 0) ? ((fastHitCount * 100ULL) / opCount) : 100;

        // 调试器控制台输出格式化压测报告
        DBG("\n"
            "====================================================================\n"
            "[BENCHMARK] 1-Second Continuous Memory Read Benchmark Finished!\n"
            "[BENCHMARK] Target PA     : 0x%016I64X (Read Size: %u bytes)\n"
            "[BENCHMARK] Total Reads   : %I64u ops (in %I64u.%04I64u sec)\n"
            "[BENCHMARK] QPS / Speed   : %I64u reads/sec\n"
            "[BENCHMARK] Bandwidth     : %I64u.%02I64u MB/s\n"
            "[BENCHMARK] Fast-Path Hit : %I64u%% (%I64u / %I64u)\n"
            "====================================================================\n\n",
            targetPa, testReadSize, opCount, elapsed100ns / 10000000ULL, (elapsed100ns % 10000000ULL) / 1000ULL, qps, mbInt, mbDec, hitRate,
            fastHitCount, opCount);

        // 释放临时读取缓冲
        ctxLC->UserVar->Func.ExFreePoolWithTag(pTestBuf, LC_POOL_TAG);

        // 如果调用者要求返回数据，组装并返回 LC_CMD_BENCHMARK_RSP
        if (ppbDataOut && pcbDataOut && ctxLC->UserVar)
        {
            ULONG cbRsp = sizeof(LC_CMD_BENCHMARK_RSP);
            PLC_CMD_BENCHMARK_RSP pRsp =
                (PLC_CMD_BENCHMARK_RSP)ctxLC->UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cbRsp, LC_POOL_TAG);
            if (pRsp)
            {
                ctxLC->UserVar->Func.RtlZeroMemory(pRsp, cbRsp);
                pRsp->TotalOperations = opCount;
                pRsp->TotalBytes = byteCount;
                pRsp->FastPathHits = fastHitCount;
                pRsp->Elapsed100ns = elapsed100ns;
                pRsp->Qps = qps;
                pRsp->BandwidthMBs = mbInt;
                pRsp->BandwidthDecMBs = mbDec;
                pRsp->HitRatePercent = hitRate;

                *ppbDataOut = (PUCHAR)pRsp;
                *pcbDataOut = cbRsp;
            }
        }

        return TRUE;
    }

    default:
        // 未显式列举的扩展/探测类命令统一应答成功 (fMsgResult=1)，彻底杜绝客户端 Check 3 报错中断
        return TRUE;
    }
}

static VOID DeviceKernel_Close(_Inout_ PLC_CONTEXT ctxLC) { UNREFERENCED_PARAMETER(ctxLC); }

BOOLEAN LcMemMap_AddRange(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 pa, _In_ ULONG64 cb, _In_ ULONG64 paRemap)
{
    if (!ctxLC || !ctxLC->pMemMap || !ctxLC->UserVar)
    {
        return FALSE;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    if ((cb & 0xfff) == 1)
    {
        cb--;
    }

    if ((pa & 0xfff) || (cb & 0xfff))
    {
        return FALSE;
    }

    if (ctxLC->cMemMap >= 0x00100000)
    {
        return FALSE;
    }

    if (ctxLC->cMemMap == ctxLC->cMemMapMax)
    {
        ULONG newMax = ctxLC->cMemMapMax * 2;
        PLC_MEMMAP_ENTRY pNew =
            (PLC_MEMMAP_ENTRY)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, newMax * sizeof(LC_MEMMAP_ENTRY), LC_POOL_TAG);
        if (!pNew)
        {
            return FALSE;
        }

        UserVar->Func.RtlCopyMemory(pNew, ctxLC->pMemMap, ctxLC->cMemMap * sizeof(LC_MEMMAP_ENTRY));
        UserVar->Func.ExFreePoolWithTag(ctxLC->pMemMap, LC_POOL_TAG);
        ctxLC->pMemMap = pNew;
        ctxLC->cMemMapMax = newMax;
    }

    ctxLC->pMemMap[ctxLC->cMemMap].pa = pa;
    ctxLC->pMemMap[ctxLC->cMemMap].cb = cb;
    ctxLC->pMemMap[ctxLC->cMemMap].paRemap = paRemap ? paRemap : pa;
    ctxLC->cMemMap++;
    return TRUE;
}

ULONG64 LcMemMap_GetMaxAddress(_In_ PLC_CONTEXT ctxLC)
{
    if (ctxLC->cMemMap == 0)
    {
        return 0x0000ffffffffffffULL;
    }

    return ctxLC->pMemMap[ctxLC->cMemMap - 1].pa + ctxLC->pMemMap[ctxLC->cMemMap - 1].cb;
}

BOOLEAN LcMemMap_GetRangesAsStruct(_In_ PLC_CONTEXT ctxLC, _Out_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!ctxLC || !ppbDataOut || !ctxLC->UserVar)
    {
        return FALSE;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    ULONG cb = ctxLC->cMemMap * sizeof(LC_MEMMAP_ENTRY);
    PUCHAR pb = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cb ? cb : sizeof(LC_MEMMAP_ENTRY), LC_POOL_TAG);
    if (!pb)
    {
        return FALSE;
    }

    if (cb > 0)
    {
        UserVar->Func.RtlCopyMemory(pb, ctxLC->pMemMap, cb);
    }

    *ppbDataOut = pb;
    if (pcbDataOut)
    {
        *pcbDataOut = cb;
    }

    return TRUE;
}

NTSTATUS LcCore_Initialize(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    g_ctx.UserVar = UserVar;
    DBG("LcCore_Initialize: Initializing LeechCore engine...");
    if (!g_ctx.fInitialized)
    {
        g_ctx.Lock.Count = 1;
        g_ctx.Lock.Owner = NULL;
        g_ctx.Lock.Contention = 0;
        if (UserVar && UserVar->Func.KeInitializeEvent)
        {
            UserVar->Func.KeInitializeEvent(&g_ctx.Lock.Event, SynchronizationEvent, FALSE);
        }
        g_ctx.FLink = NULL;
        // 彻底启用硬件 PTE 跳板读写
        NTSTATUS status = LcPteEngine_Init();
        if (!NT_SUCCESS(status))
        {
            DBG("LcCore_Initialize: LcPteEngine_Init failed with status 0x%08X", status);
            return status;
        }

        g_ctx.fInitialized = TRUE;
    }

    return STATUS_SUCCESS;
}

VOID LcCore_Cleanup(VOID)
{
    DBG("LcCore_Cleanup: Cleaning up LeechCore engine...");
    if (!g_ctx.fInitialized)
    {
        return;
    }

    ExAcquireFastMutex(&g_ctx.Lock);
    PLC_CONTEXT pCur = g_ctx.FLink;
    while (pCur)
    {
        PLC_CONTEXT pNext = pCur->FLink;
        MACHENIKE_KERNEL_INTERFACE *UserVar = pCur->UserVar;
        if (pCur->pfnClose)
        {
            pCur->pfnClose(pCur);
        }

        if (pCur->pMemMap && UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pCur->pMemMap, LC_POOL_TAG);
        }

        if (UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pCur, LC_POOL_TAG);
        }

        pCur = pNext;
    }

    g_ctx.FLink = NULL;
    ExReleaseFastMutex(&g_ctx.Lock);
    // ?? PTE ??
    LcPteEngine_Cleanup();
    g_ctx.fInitialized = FALSE;
    DBG("LcCore_Cleanup: Cleanup completed");
}

HANDLE LcCreateEx(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Inout_ PLC_CONFIG pLcCreateConfig,
                  _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    DBG("LcCreateEx: Creating new LeechCore context...");
    if (ppLcCreateErrorInfo)
    {
        *ppLcCreateErrorInfo = NULL;
    }

    if (!pLcCreateConfig || pLcCreateConfig->dwVersion != LC_CONFIG_VERSION)
    {
        DBG("LcCreateEx: Invalid config or version mismatch (Got=0x%08X, Expected=0x%08X)",
            pLcCreateConfig ? pLcCreateConfig->dwVersion : 0, LC_CONFIG_VERSION);
        return NULL;
    }

    if (!UserVar)
    {
        DBG("LcCreateEx: UserVar is NULL");
        return NULL;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sizeof(LC_CONTEXT), LC_POOL_TAG);
    if (!ctxLC)
    {
        return NULL;
    }

    UserVar->Func.RtlZeroMemory(ctxLC, sizeof(LC_CONTEXT));
    ctxLC->UserVar = UserVar;
    ctxLC->version = LC_CONTEXT_VERSION;
    ctxLC->Lock.Count = 1;
    ctxLC->Lock.Owner = NULL;
    ctxLC->Lock.Contention = 0;
    if (UserVar->Func.KeInitializeEvent)
    {
        UserVar->Func.KeInitializeEvent(&ctxLC->Lock.Event, SynchronizationEvent, FALSE);
    }
    pLcCreateConfig->fRemote = TRUE;
    pLcCreateConfig->fVolatile = TRUE;
    pLcCreateConfig->fWritable = TRUE;
    // 允许网络压缩协商：保留客户端配置 (若客户端未指定禁用则保持 FALSE 以激活 XPRESS 压缩)
    pLcCreateConfig->fRemoteDisableCompress = pLcCreateConfig->fRemoteDisableCompress ? TRUE : FALSE;
    UserVar->Func.RtlCopyMemory(pLcCreateConfig->szDeviceName, "MachenikeKernel", sizeof("MachenikeKernel"));
    UserVar->Func.RtlCopyMemory(&ctxLC->Config, pLcCreateConfig, sizeof(LC_CONFIG));
    ctxLC->pfnReadScatter = DeviceKernel_ReadScatter;
    ctxLC->pfnWriteScatter = DeviceKernel_WriteScatter;
    ctxLC->pfnGetOption = DeviceKernel_GetOption;
    ctxLC->pfnSetOption = DeviceKernel_SetOption;
    ctxLC->pfnCommand = DeviceKernel_Command;
    ctxLC->pfnClose = DeviceKernel_Close;
    ctxLC->cMemMapMax = 64;
    ctxLC->pMemMap =
        (PLC_MEMMAP_ENTRY)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, ctxLC->cMemMapMax * sizeof(LC_MEMMAP_ENTRY), LC_POOL_TAG);
    if (ctxLC->pMemMap)
    {
        UserVar->Func.RtlZeroMemory(ctxLC->pMemMap, ctxLC->cMemMapMax * sizeof(LC_MEMMAP_ENTRY));
    }

    PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange = UserVar->Func.MmGetPhysicalMemoryRanges();
    if (MmPhysicalMemoryRange)
    {
        int number_of_runs = 0;
        for (number_of_runs = 0;
             (MmPhysicalMemoryRange[number_of_runs].BaseAddress.QuadPart) || (MmPhysicalMemoryRange[number_of_runs].NumberOfBytes.QuadPart);
             number_of_runs++)
            ;
        if (number_of_runs <= 100)
        {
            ctxLC->MemInfo.NumberOfRuns.QuadPart = number_of_runs;
            UserVar->Func.memmove(&ctxLC->MemInfo.Run[0], MmPhysicalMemoryRange, number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));
            if (ctxLC->pMemMap)
            {
                for (int r = 0; r < number_of_runs; r++)
                {
                    LcMemMap_AddRange(ctxLC, (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart,
                                      (ULONG64)MmPhysicalMemoryRange[r].NumberOfBytes.QuadPart,
                                      (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart);
                    ULONG64 runMax =
                        (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart + (ULONG64)MmPhysicalMemoryRange[r].NumberOfBytes.QuadPart;
                    if (runMax > ctxLC->Config.paMax)
                    {
                        ctxLC->Config.paMax = runMax;
                    }
                }
            }
        }
    }

    if (ctxLC->Config.paMax == 0)
    {
        ctxLC->Config.paMax = 0x1000000000ULL; // 兜底 64GB
    }
    pLcCreateConfig->paMax = ctxLC->Config.paMax;

    ExAcquireFastMutex(&g_ctx.Lock);
    ctxLC->FLink = g_ctx.FLink;
    g_ctx.FLink = ctxLC;
    ExReleaseFastMutex(&g_ctx.Lock);
    ctxLC->MemInfo.KernBase.QuadPart = _GetKernelBase();
    DBG("LcCreateEx: Initialized MemInfo: KernelBase=0x%llX", ctxLC->MemInfo.KernBase.QuadPart);
    DBG("LcCreateEx: LeechCore context created successfully (hLC=%p)", ctxLC);
    return (HANDLE)ctxLC;
}

VOID LcClose(_In_opt_ HANDLE hLC)
{
    if (!hLC || (ULONG_PTR)hLC < 0xFFFF800000000000ULL)
    {
        return;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->version != LC_CONTEXT_VERSION)
    {
        return;
    }

    // 先原子抹除 version 签名与函数指针，阻断任何并发悬垂访问
    ctxLC->version = 0;
    ctxLC->pfnReadScatter = NULL;
    ctxLC->pfnWriteScatter = NULL;
    ctxLC->pfnGetOption = NULL;
    ctxLC->pfnSetOption = NULL;
    ctxLC->pfnCommand = NULL;

    ExAcquireFastMutex(&g_ctx.Lock);
    PLC_CONTEXT *ppCur = &g_ctx.FLink;
    while (*ppCur)
    {
        if (*ppCur == ctxLC)
        {
            *ppCur = ctxLC->FLink;
            break;
        }

        ppCur = &(*ppCur)->FLink;
    }

    ExReleaseFastMutex(&g_ctx.Lock);
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    if (ctxLC->pfnClose && (ULONG_PTR)ctxLC->pfnClose >= 0xFFFF800000000000ULL)
    {
        ctxLC->pfnClose(ctxLC);
    }

    if (ctxLC->pMemMap && UserVar)
    {
        UserVar->Func.ExFreePoolWithTag(ctxLC->pMemMap, LC_POOL_TAG);
        ctxLC->pMemMap = NULL;
    }

    if (UserVar)
    {
        UserVar->Func.RtlZeroMemory(ctxLC, sizeof(LC_CONTEXT));
        UserVar->Func.ExFreePoolWithTag(ctxLC, LC_POOL_TAG);
    }
}

VOID LcReadScatter(_In_ HANDLE hLC, _In_ ULONG cMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!hLC || !ppMEMs || cMEMs == 0 || (ULONG_PTR)hLC < 0xFFFF800000000000ULL)
    {
        return;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->version == LC_CONTEXT_VERSION && ctxLC->pfnReadScatter && (ULONG_PTR)ctxLC->pfnReadScatter >= 0xFFFF800000000000ULL)
    {
        ctxLC->pfnReadScatter(ctxLC, cMEMs, ppMEMs);
    }
}

VOID LcWriteScatter(_In_ HANDLE hLC, _In_ ULONG cMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!hLC || !ppMEMs || cMEMs == 0 || (ULONG_PTR)hLC < 0xFFFF800000000000ULL)
    {
        return;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->version == LC_CONTEXT_VERSION && ctxLC->pfnWriteScatter && (ULONG_PTR)ctxLC->pfnWriteScatter >= 0xFFFF800000000000ULL)
    {
        ctxLC->pfnWriteScatter(ctxLC, cMEMs, ppMEMs);
    }
}

BOOLEAN LcCommand(_In_ HANDLE hLC, _In_ ULONG64 fCommand, _In_ ULONG cbDataIn, _In_reads_opt_(cbDataIn) PUCHAR pbDataIn,
                  _Out_opt_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!hLC || (ULONG_PTR)hLC < 0xFFFF800000000000ULL)
    {
        return FALSE;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->version == LC_CONTEXT_VERSION && ctxLC->pfnCommand && (ULONG_PTR)ctxLC->pfnCommand >= 0xFFFF800000000000ULL)
    {
        return ctxLC->pfnCommand(ctxLC, fCommand, cbDataIn, pbDataIn, ppbDataOut, pcbDataOut);
    }

    return FALSE;
}

BOOLEAN LcGetOption(_In_ HANDLE hLC, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if (!hLC || (ULONG_PTR)hLC < 0xFFFF800000000000ULL)
    {
        return FALSE;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->version == LC_CONTEXT_VERSION && ctxLC->pfnGetOption && (ULONG_PTR)ctxLC->pfnGetOption >= 0xFFFF800000000000ULL)
    {
        return ctxLC->pfnGetOption(ctxLC, fOption, pqwValue);
    }

    return FALSE;
}

BOOLEAN LcSetOption(_In_ HANDLE hLC, _In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    if (!hLC || (ULONG_PTR)hLC < 0xFFFF800000000000ULL)
    {
        return FALSE;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->version == LC_CONTEXT_VERSION && ctxLC->pfnSetOption && (ULONG_PTR)ctxLC->pfnSetOption >= 0xFFFF800000000000ULL)
    {
        return ctxLC->pfnSetOption(ctxLC, fOption, qwValue);
    }

    return FALSE;
}
// ============================================================
// LeechCoreEngine 纯静态类实现
// ============================================================
NTSTATUS LeechCoreEngine::Initialize(MACHENIKE_KERNEL_INTERFACE *UserVar) { return LcCore_Initialize(UserVar); }

VOID LeechCoreEngine::Cleanup(VOID) { LcCore_Cleanup(); }

HANDLE LeechCoreEngine::CreateContext(MACHENIKE_KERNEL_INTERFACE *UserVar, PLC_CONFIG pLcCreateConfig,
                                      PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    return LcCreateEx(UserVar, pLcCreateConfig, ppLcCreateErrorInfo);
}

VOID LeechCoreEngine::CloseContext(HANDLE hLC) { LcClose(hLC); }

ULONG LeechCoreEngine::ReadPhysicalContiguous(LARGE_INTEGER physAddr, PUCHAR buf, ULONG count)
{
    return LcPte_ReadPhysicalContiguous(physAddr, buf, count);
}
VOID LeechCoreEngine::ReadScatter(HANDLE hLC, ULONG cMEMs, PMEM_SCATTER *ppMEMs) { LcReadScatter(hLC, cMEMs, ppMEMs); }
VOID LeechCoreEngine::WriteScatter(HANDLE hLC, ULONG cMEMs, PMEM_SCATTER *ppMEMs) { LcWriteScatter(hLC, cMEMs, ppMEMs); }
BOOLEAN LeechCoreEngine::ReadVirtualMemory(ULONG64 Cr3, ULONG64 Va, PVOID Buffer, ULONG Size)
{
    return LcReadVirtualMemory(Cr3, Va, Buffer, Size);
}

BOOLEAN LeechCoreEngine::WriteVirtualMemory(ULONG64 Cr3, ULONG64 Va, const PVOID Buffer, ULONG Size)
{
    return LcWriteVirtualMemory(Cr3, Va, Buffer, Size);
}

BOOLEAN LeechCoreEngine::ReadMsrSafe(ULONG MsrIndex, PULONG64 pValue) { return MachenikeReadMsrSafe(MsrIndex, pValue); }
