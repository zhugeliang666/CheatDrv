#pragma once
#include <ntifs.h>


namespace Util
{
	typedef struct _POOL_ENTRY
	{
		LIST_ENTRY ListEntry;
		PVOID VritualAddress;
		UINT64 NumberOfBytes;
		ULONG Source;
		// true: allocated via MmAllocateIndependentPages (normal physical-machine path).
		// false is kept only for old/diagnostic records; current allocations do
		// not fall back to ExAllocatePoolWithTag.
		bool UsedIndependent;
	}POOL_ENTRY, * PPOOL_ENTRY;

	inline constexpr ULONG PoolCount = 8 * PAGE_SIZE;

	typedef struct _POOL_ENTRYS
	{
		LIST_ENTRY ActiveListHead;
		LIST_ENTRY FreeListHead;
		POOL_ENTRY Entrys[PoolCount];
	}POOL_ENTRYS, * PPOOL_ENTRYS;

	extern POOL_ENTRYS Pools;
	extern bool IsPoolManagerInit;

	inline constexpr ULONG MMTYPE = 'p??>';

	// init
	VOID PoolManagerInitialize();

	// uninit
	VOID PoolManagerUninitialize();

	// allocate (Source: 4-char tag identifying caller module)
	PVOID PoolManagertAllocation(SIZE_T Size, ULONG Source);

	// free
	VOID PoolManagerFreePool(PVOID VritualAddress);

	// query whether address is managed by PoolManager
	bool IsInPool(PVOID VritualAddress);

	// statistics by source tag (debug/self-check only)
	ULONG PoolManagerCountBySource(ULONG Source);
	SIZE_T PoolManagerTotalBytesBySource(ULONG Source);
	VOID PoolManagerDumpStats();
};

