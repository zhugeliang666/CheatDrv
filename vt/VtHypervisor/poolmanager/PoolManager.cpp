#include "PoolManager.h"
#include "../common/ntapi.h"
#include "../vt/hv.h"

#pragma warning(disable:4996)

// Physical-machine policy: PoolManager backing must come from
// MmAllocateIndependentPages only. The ExAllocatePoolWithTag fallback was a VM
// bisect path and is intentionally disabled.
#define POOL_ENABLE_INDEPENDENT_PAGES 1
// Per-call retry attempts when independent-pages route fails any of
// alloc / protect / writetest / direct-map validation. Each retry waits
// POOL_RETRY_DELAY_US.
#define POOL_INDEP_RETRY_COUNT  3
#define POOL_RETRY_DELAY_US     50000  // 50ms between attempts


namespace Util
{
	POOL_ENTRYS Pools;
	bool IsPoolManagerInit = false;
}
#pragma code_seg(".vm")

VOID Util::PoolManagerInitialize()
{
	if (!IsPoolManagerInit)
	{
		IsPoolManagerInit = true;
		InitializeListHead(&Pools.ActiveListHead);
		InitializeListHead(&Pools.FreeListHead);

		for (size_t i = 0; i < PoolCount; i++)
		{
			RtlZeroMemory(&Pools.Entrys[i], sizeof(POOL_ENTRY));
			InsertTailList(&Pools.FreeListHead, &Pools.Entrys[i].ListEntry);
		}
	}
}


bool Util::IsInPool(PVOID VritualAddress)
{
	if (!IsPoolManagerInit)
	{
		PoolManagerInitialize();
	}

	bool result = false;
	auto Temp = Pools.ActiveListHead.Flink;
	while (Temp != &Pools.ActiveListHead)
	{
		auto Pool = (PPOOL_ENTRY)Temp;
		if (Pool->VritualAddress == VritualAddress)
		{
			result = true;
			break;
		}
		Temp = Temp->Flink;
	}

	return result;
}

VOID Util::PoolManagerUninitialize()
{
	PoolManagerInitialize();

	while (!IsListEmpty(&Pools.ActiveListHead))
	{
		auto Pool = (PPOOL_ENTRY)RemoveHeadList(&Pools.ActiveListHead);
		if (Pool)
		{
			if (Pool->UsedIndependent && MmFreeIndependentPages) {
				MmFreeIndependentPages(Pool->VritualAddress, Pool->NumberOfBytes);
			}
			InsertTailList(&Pools.FreeListHead, &Pool->ListEntry);
		}
	}
}

PVOID Util::PoolManagertAllocation(SIZE_T Size, ULONG Source)
{
	PoolManagerInitialize();

	PVOID Buffer = NULL;
	bool used_independent = false;

	// Step 2 (2026-05-26): MmAllocateIndependentPages bypasses ExpBigPoolTable
	// and requires no Pool Tag, so PoolMon / !poolfind can't enumerate these
	// blocks. Pages come back with restrictive protection (default seems to
	// be inaccessible / readonly depending on build) 鈥?must call
	// MmSetPageProtection right after to make them usable. mapDriver's pool
	// has been doing this for a long time; matching that pattern.
	//
	// Symbol resolution happens in InitNtSymbol (PDB lookup). If the
	// independent-page APIs are unavailable or fail validation, return NULL;
	// do not fall back to ExAllocatePoolWithTag.
	_InterlockedIncrement64((volatile LONG64*)&hv::g_ghv->diag_pool_alloc_attempted);

#if POOL_ENABLE_INDEPENDENT_PAGES
	if (MmAllocateIndependentPages && MmFreeIndependentPages && MmSetPageProtection) {
		uint32_t fail_step = 0;
		for (int attempt = 0; attempt <= POOL_INDEP_RETRY_COUNT; attempt++) {
			if (attempt > 0) {
				_InterlockedIncrement64((volatile LONG64*)&hv::g_ghv->diag_pool_indep_retried);
				LARGE_INTEGER w; w.QuadPart = -(LONGLONG)POOL_RETRY_DELAY_US * 10;
				KeDelayExecutionThread(KernelMode, FALSE, &w);
			}

			// Node = MAXULONG64 lets the system pick any NUMA node.
			// Passing 0 forces Node 0; on multi-socket hosts that node may
			// not have enough contiguous backing for large blocks (547MB
			// vcpus[]), and the call either fails or hands back partially-
			// backed VA 鈫?host triple fault / freeze. mapDriver's PoolManager
			// uses MAXULONG64 and is stable; match it.
			PVOID candidate = MmAllocateIndependentPages(Size, MAXULONG64);
			if (!candidate) {
				fail_step = 1;
				_InterlockedIncrement64((volatile LONG64*)&hv::g_ghv->diag_pool_indep_alloc_null);
				continue;
			}
			BOOLEAN prot_ok = MmSetPageProtection(candidate, Size, PAGE_EXECUTE_READWRITE);
			if (!prot_ok) {
				fail_step = 2;
				_InterlockedIncrement64((volatile LONG64*)&hv::g_ghv->diag_pool_indep_protect_fail);
				MmFreeIndependentPages(candidate, Size);
				continue;
			}
			// CRITICAL: walk EVERY 4K page in the buffer, write one byte
			// to commit physical backing AND verify MmGetPhysicalAddress
			// returns a non-zero PFN. MmAllocateIndependentPages returns
			// VA with a present PTE, but the PFN may still be zero / lazy
			// 鈥?host PT tree (prepare_host_page_tables) copies the PFN as-is
			// from system CR3, so a zero PFN here means host-mode access
			// faults later 鈫?triple fault 鈫?black screen reboot.
			//
			// Per-page touch+validate replaces the previous first/last-byte
			// probe, which only fault-ed in 2 of N pages.
			volatile UCHAR* probe = (volatile UCHAR*)candidate;
			bool pages_ok = true;
			__try {
				for (SIZE_T off = 0; off < Size; off += PAGE_SIZE) {
					probe[off] = 0;
					PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(
						(PVOID)((UINT64)candidate + off));
					if (pa.QuadPart == 0) {
						fail_step = 3;
						pages_ok = false;
						break;
					}
					if (!hv::host_physical_range_mapped((uint64_t)pa.QuadPart)) {
						fail_step = 4;
						pages_ok = false;
						break;
					}
				}
				if (pages_ok && Size > 0) {
					// Touch the last byte too in case Size is not page-aligned.
					probe[Size - 1] = 0;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				fail_step = 3;
				pages_ok = false;
			}
			if (!pages_ok) {
				if (fail_step == 4)
					_InterlockedIncrement64((volatile LONG64*)&hv::g_ghv->diag_pool_indep_directmap_fail);
				else
					_InterlockedIncrement64((volatile LONG64*)&hv::g_ghv->diag_pool_indep_writetest_fail);
				MmFreeIndependentPages(candidate, Size);
				continue;
			}

			RtlZeroMemory(candidate, Size);  // restore zeroed state expected by callers
			Buffer = candidate;
			used_independent = true;
			fail_step = 0;
			_InterlockedIncrement64((volatile LONG64*)&hv::g_ghv->diag_pool_indep_success);
			hv::g_ghv->diag_pool_last_alloc_buffer = (uint64_t)Buffer;
			break;
		}
		if (!Buffer) {
			hv::g_ghv->diag_pool_last_fail_size   = Size;
			hv::g_ghv->diag_pool_last_fail_source = Source;
			hv::g_ghv->diag_pool_last_fail_step   = fail_step;
		}
	}
#endif
	// Physical-machine policy: do not fall back to ExAllocatePoolWithTag.

	if (!Buffer)
	{
		char tag[5] = { 0 };
		tag[0] = (char)((Source >> 0) & 0xff);
		tag[1] = (char)((Source >> 8) & 0xff);
		tag[2] = (char)((Source >> 16) & 0xff);
		tag[3] = (char)((Source >> 24) & 0xff);
		LOG_DEBUG(_XOR_("[PoolMgr] alloc FAILED tag=[%s] size=0x%zX\n"), tag, Size);
	}

	if (Buffer)
	{
		// The independent-page path above already touches, validates and clears
		// every page.  Do not repeat the full-buffer walk and zero here; vcpu[]
		// can be hundreds of MiB on many-core hosts.
		if (IsListEmpty(&Pools.FreeListHead))
		{
			LOG_DEBUG(_XOR_("[PoolMgr] tracking table exhausted size=0x%zX tag=0x%08X\n"),
				Size, Source);
			if (used_independent && MmFreeIndependentPages)
				MmFreeIndependentPages(Buffer, Size);
			return NULL;
		}

		auto Pool = (PPOOL_ENTRY)RemoveHeadList(&Pools.FreeListHead);
		if (Pool)
		{
			RtlZeroMemory(Pool, sizeof(POOL_ENTRY));
			Pool->VritualAddress  = Buffer;
			Pool->NumberOfBytes   = Size;
			Pool->Source          = Source;
			Pool->UsedIndependent = used_independent;
			InsertHeadList(&Pools.ActiveListHead, &Pool->ListEntry);
		}
	}

	return Buffer;
}

VOID Util::PoolManagerFreePool(PVOID VritualAddress)
{
	PoolManagerInitialize();

	if (VritualAddress == NULL) return;

	auto Temp = Pools.ActiveListHead.Flink;
	while (Temp != &Pools.ActiveListHead)
	{
		auto Pool = (PPOOL_ENTRY)Temp;
		if (Pool->VritualAddress == VritualAddress)
		{
			RemoveEntryList(&Pool->ListEntry);
			if (Pool->UsedIndependent && MmFreeIndependentPages) {
				MmFreeIndependentPages(Pool->VritualAddress, Pool->NumberOfBytes);
			}
			InsertTailList(&Pools.FreeListHead, &Pool->ListEntry);
			break;
		}
		Temp = Temp->Flink;
	}
}

// === Statistics interface implementations ===

ULONG Util::PoolManagerCountBySource(ULONG Source)
{
	if (!IsPoolManagerInit) return 0;

	ULONG count = 0;
	auto Temp = Pools.ActiveListHead.Flink;
	while (Temp != &Pools.ActiveListHead)
	{
		auto Pool = (PPOOL_ENTRY)Temp;
		if (Pool->Source == Source)
			count++;
		Temp = Temp->Flink;
	}
	return count;
}

SIZE_T Util::PoolManagerTotalBytesBySource(ULONG Source)
{
	if (!IsPoolManagerInit) return 0;

	SIZE_T total = 0;
	auto Temp = Pools.ActiveListHead.Flink;
	while (Temp != &Pools.ActiveListHead)
	{
		auto Pool = (PPOOL_ENTRY)Temp;
		if (Pool->Source == Source)
			total += Pool->NumberOfBytes;
		Temp = Temp->Flink;
	}
	return total;
}

VOID Util::PoolManagerDumpStats()
{
	if (!IsPoolManagerInit) return;

	// Per-source aggregate with path breakdown. Lets us confirm at a glance
	// that allocations past the early-boot window are going through
	// MmAllocateIndependentPages (no Big Pool / no tag) and not the
	// 'File'-tagged fallback. Any non-zero fallback count for a source
	// allocated after find_offsets() means PDB resolution regressed.
	struct SrcStat {
		ULONG  src;
		ULONG  count;
		SIZE_T bytes;
		ULONG  independ_count;
		SIZE_T independ_bytes;
		ULONG  fallback_count;
		SIZE_T fallback_bytes;
	};
	SrcStat stats[20] = { 0 };
	ULONG kinds = 0;
	ULONG total_independ = 0;
	ULONG total_fallback = 0;

	auto Temp = Pools.ActiveListHead.Flink;
	while (Temp != &Pools.ActiveListHead)
	{
		auto Pool = (PPOOL_ENTRY)Temp;
		if (Pool->UsedIndependent) total_independ++; else total_fallback++;

		bool found = false;
		for (ULONG i = 0; i < kinds; i++)
		{
			if (stats[i].src == Pool->Source)
			{
				stats[i].count++;
				stats[i].bytes += Pool->NumberOfBytes;
				if (Pool->UsedIndependent) {
					stats[i].independ_count++;
					stats[i].independ_bytes += Pool->NumberOfBytes;
				} else {
					stats[i].fallback_count++;
					stats[i].fallback_bytes += Pool->NumberOfBytes;
				}
				found = true;
				break;
			}
		}
		if (!found && kinds < 20)
		{
			stats[kinds].src = Pool->Source;
			stats[kinds].count = 1;
			stats[kinds].bytes = Pool->NumberOfBytes;
			if (Pool->UsedIndependent) {
				stats[kinds].independ_count = 1;
				stats[kinds].independ_bytes = Pool->NumberOfBytes;
			} else {
				stats[kinds].fallback_count = 1;
				stats[kinds].fallback_bytes = Pool->NumberOfBytes;
			}
			kinds++;
		}

		Temp = Temp->Flink;
	}

	LOG_DEBUG(_XOR_("[PoolMgr] === DumpStats: %u kinds  totals: independ=%u fallback=%u  (Independent=MmAllocateIndependentPages, Fallback=ExAllocatePool('File')) ===\n"),
		kinds, total_independ, total_fallback);
	for (ULONG i = 0; i < kinds; i++)
	{
		char tag[5] = { 0 };
		tag[0] = (char)((stats[i].src >> 0) & 0xff);
		tag[1] = (char)((stats[i].src >> 8) & 0xff);
		tag[2] = (char)((stats[i].src >> 16) & 0xff);
		tag[3] = (char)((stats[i].src >> 24) & 0xff);
		LOG_DEBUG(_XOR_("[PoolMgr]   [%s] count=%u bytes=0x%zX  independ=%u/0x%zX  fallback=%u/0x%zX\n"),
			tag, stats[i].count, stats[i].bytes,
			stats[i].independ_count, stats[i].independ_bytes,
			stats[i].fallback_count, stats[i].fallback_bytes);
	}
}

