#include "PoolManager.h"
#include "../base.h"
#include "../common/ntapi.h"

#pragma warning(disable:4996)

namespace Util
{
    POOL_ENTRYS Pools;
    bool IsPoolManagerInit = false;
    POOL_ENTRYS VTPools;
}

static bool MapPoolTouchAndZero(PVOID Buffer, SIZE_T Size)
{
    if (!Buffer || !Size)
        return false;

    __try
    {
        volatile UCHAR* p = (volatile UCHAR*)Buffer;
        for (SIZE_T off = 0; off < Size; off += PAGE_SIZE)
            p[off] = 0;
        p[Size - 1] = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    RtlZeroMemory(Buffer, Size);
    return true;
}

static void MapPoolFreeBacking(PVOID Buffer, SIZE_T Size, bool UsedIndependent)
{
    if (!Buffer)
        return;

    if (Size)
        RtlSecureZeroMemory(Buffer, Size);

    if (UsedIndependent && MmFreeIndependentPages)
        MmFreeIndependentPages(Buffer, Size);
}

VOID Util::PoolManagerInitialize()
{
    if (!IsPoolManagerInit)
    {
        IsPoolManagerInit = true;
        InitializeListHead(&Pools.ActiveListHead);
        InitializeListHead(&Pools.FreeListHead);

        ExInitializeFastMutex(&Pools.PoolLock);
        ExInitializeFastMutex(&Pools.PreallocLock);

        for (size_t i = 0; i < PoolCount; i++)
        {
            RtlZeroMemory(&Pools.Entrys[i], sizeof(POOL_ENTRY));
            InsertTailList(&Pools.FreeListHead, &Pools.Entrys[i].ListEntry);
        }
    }
}

PVOID Util::PoolManagertAllocation(SIZE_T Size)
{
    PoolManagerInitialize();
    if (!Size)
        return NULL;

    PVOID Buffer = NULL;
    bool usedIndependent = false;

    if (MmAllocateIndependentPages && MmFreeIndependentPages && MmSetPageProtection)
    {
        Buffer = MmAllocateIndependentPages(Size, MAXULONG64);
        if (Buffer)
        {
            if (!MmSetPageProtection(Buffer, Size, PAGE_EXECUTE_READWRITE))
            {
                MmFreeIndependentPages(Buffer, Size);
                Buffer = NULL;
            }
            else
            {
                usedIndependent = true;
            }
        }
    }

    if (!Buffer)
        return NULL;

    if (!MapPoolTouchAndZero(Buffer, Size))
    {
        MapPoolFreeBacking(Buffer, Size, usedIndependent);
        return NULL;
    }

    ExAcquireFastMutex(&Pools.PoolLock);
    if (IsListEmpty(&Pools.FreeListHead))
    {
        ExReleaseFastMutex(&Pools.PoolLock);
        MapPoolFreeBacking(Buffer, Size, usedIndependent);
        return NULL;
    }

    auto Pool = (PPOOL_ENTRY)RemoveHeadList(&Pools.FreeListHead);
    RtlZeroMemory(Pool, sizeof(POOL_ENTRY));
    Pool->VritualAddress = Buffer;
    Pool->NumberOfBytes = Size;
    Pool->isVtPage = false;
    Pool->UsedIndependent = usedIndependent;
    InsertHeadList(&Pools.ActiveListHead, &Pool->ListEntry);
    ExReleaseFastMutex(&Pools.PoolLock);

    return Buffer;
}

VOID Util::PoolManagerFreePool(PVOID VritualAddress)
{
    PoolManagerInitialize();
    if (VritualAddress == NULL)
        return;

    ExAcquireFastMutex(&Pools.PoolLock);
    auto Temp = Pools.ActiveListHead.Flink;
    while (Temp != &Pools.ActiveListHead)
    {
        auto Pool = (PPOOL_ENTRY)Temp;
        Temp = Temp->Flink;
        if (Pool->VritualAddress == VritualAddress)
        {
            RemoveEntryList(&Pool->ListEntry);
            PVOID address = Pool->VritualAddress;
            SIZE_T bytes = (SIZE_T)Pool->NumberOfBytes;
            bool isVt = Pool->isVtPage;
            bool usedIndependent = Pool->UsedIndependent;

            Pool->VritualAddress = NULL;
            Pool->NumberOfBytes = 0;
            Pool->isVtPage = false;
            Pool->UsedIndependent = false;
            InsertTailList(&Pools.FreeListHead, &Pool->ListEntry);
            ExReleaseFastMutex(&Pools.PoolLock);

            if (!isVt)
                MapPoolFreeBacking(address, bytes, usedIndependent);
            return;
        }
    }

    ExReleaseFastMutex(&Pools.PoolLock);
}

bool Util::PoolManagerDetachPool(PVOID VritualAddress)
{
    PoolManagerInitialize();
    if (VritualAddress == NULL)
        return false;

    ExAcquireFastMutex(&Pools.PoolLock);
    auto Temp = Pools.ActiveListHead.Flink;
    while (Temp != &Pools.ActiveListHead)
    {
        auto Pool = (PPOOL_ENTRY)Temp;
        Temp = Temp->Flink;
        if (Pool->VritualAddress != VritualAddress)
            continue;

        RemoveEntryList(&Pool->ListEntry);
        Pool->VritualAddress = NULL;
        Pool->NumberOfBytes = 0;
        Pool->isVtPage = false;
        Pool->UsedIndependent = false;
        InsertTailList(&Pools.FreeListHead, &Pool->ListEntry);
        ExReleaseFastMutex(&Pools.PoolLock);
        return true;
    }

    ExReleaseFastMutex(&Pools.PoolLock);
    return false;
}

bool Util::PoolManagerAddVtEntry(PVOID address, SIZE_T size)
{
    PoolManagerInitialize();
    if (!address)
        return false;

    ExAcquireFastMutex(&Pools.PoolLock);
    if (IsListEmpty(&Pools.FreeListHead))
    {
        ExReleaseFastMutex(&Pools.PoolLock);
        return false;
    }

    auto Pool = (PPOOL_ENTRY)RemoveHeadList(&Pools.FreeListHead);
    RtlZeroMemory(Pool, sizeof(POOL_ENTRY));
    Pool->VritualAddress = address;
    Pool->NumberOfBytes = size;
    Pool->isVtPage = true;
    Pool->UsedIndependent = false;
    InsertHeadList(&Pools.ActiveListHead, &Pool->ListEntry);
    ExReleaseFastMutex(&Pools.PoolLock);
    return true;
}

bool Util::IsInPool(PVOID VritualAddress)
{
    if (!IsPoolManagerInit)
        PoolManagerInitialize();

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

    ExAcquireFastMutex(&Pools.PreallocLock);
    for (size_t i = 0; i < PreallocBlockCount; i++)
    {
        PPREALLOC_BLOCK block = &Pools.PreallocBlocks[i];
        if (block->VirtualAddress)
        {
            if (block->Size)
                RtlSecureZeroMemory(block->VirtualAddress, block->Size);
            if (MmFreeIndependentPages)
                MmFreeIndependentPages(block->VirtualAddress, block->Size);
            block->VirtualAddress = NULL;
            block->Size = 0;
        }
    }
    ExReleaseFastMutex(&Pools.PreallocLock);

    ExAcquireFastMutex(&Pools.PoolLock);
    while (!IsListEmpty(&Pools.ActiveListHead))
    {
        auto Pool = (PPOOL_ENTRY)RemoveHeadList(&Pools.ActiveListHead);
        PVOID address = Pool->VritualAddress;
        SIZE_T bytes = (SIZE_T)Pool->NumberOfBytes;
        bool isVt = Pool->isVtPage;
        bool usedIndependent = Pool->UsedIndependent;

        Pool->VritualAddress = NULL;
        Pool->NumberOfBytes = 0;
        Pool->isVtPage = false;
        Pool->UsedIndependent = false;
        InsertTailList(&Pools.FreeListHead, &Pool->ListEntry);

        if (!isVt)
            MapPoolFreeBacking(address, bytes, usedIndependent);
    }
    ExReleaseFastMutex(&Pools.PoolLock);
}
