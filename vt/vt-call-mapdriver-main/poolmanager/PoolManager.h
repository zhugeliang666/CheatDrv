#pragma once
#include <ntifs.h>

namespace Util
{
	typedef struct _POOL_ENTRY
	{
		LIST_ENTRY ListEntry;
		PVOID VritualAddress;
		UINT64 NumberOfBytes;
		bool isVtPage;
		bool UsedIndependent;
	}POOL_ENTRY, * PPOOL_ENTRY;

	// 预分配内存块结构
	typedef struct _PREALLOC_BLOCK
	{
		LIST_ENTRY ListEntry;
		PVOID VirtualAddress;
		SIZE_T Size;
		bool IsUsed;
	}PREALLOC_BLOCK, * PPREALLOC_BLOCK;

	inline constexpr ULONG PoolCount = 8 * PAGE_SIZE;
	inline constexpr ULONG PreallocBlockCount = 1; // 预分配128个0x1000大小的块
	inline constexpr SIZE_T PreallocBlockSize = 0x1000;

	typedef struct _POOL_ENTRYS
	{
		LIST_ENTRY ActiveListHead;
		LIST_ENTRY FreeListHead;
		POOL_ENTRY Entrys[PoolCount];

		// 预分配内存池
		LIST_ENTRY PreallocFreeListHead;
		LIST_ENTRY PreallocUsedListHead;
		PREALLOC_BLOCK PreallocBlocks[PreallocBlockCount];
		bool IsPreallocInitialized;

		// 锁机制
		FAST_MUTEX PoolLock;
		FAST_MUTEX PreallocLock;
	}POOL_ENTRYS, * PPOOL_ENTRYS;

	extern POOL_ENTRYS Pools;
	extern bool IsPoolManagerInit;

	inline constexpr ULONG MMTYPE = 'p>>>';

	//初始化
	VOID PoolManagerInitialize();

	//反初始化
	VOID PoolManagerUninitialize();

	//分配内存
	PVOID PoolManagertAllocation(SIZE_T Size);

	bool PoolManagerAddVtEntry(PVOID address, SIZE_T size);

	//释放一个pool
	VOID PoolManagerFreePool(PVOID VritualAddress);

	bool IsInPool(PVOID VritualAddress);


};