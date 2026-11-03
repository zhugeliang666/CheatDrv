#pragma once

namespace ShellCodeSpoof
{

static constexpr unsigned long kX2SharedLogMaxReturns = 5;
static constexpr unsigned long kX2SharedLogCapacity = 512;
static constexpr unsigned long kX2SharedLogQueueMask = kX2SharedLogCapacity - 1;

#pragma pack(push, 8)
struct X2_SHARED_LOG
{
    volatile unsigned long long Sequence;
    unsigned long ReturnCount;
    unsigned long Flags;
    unsigned long SpoofMode;
    unsigned long RuntimeFlags;
    unsigned long Reserved;
    unsigned long long SlotVa;
    unsigned long long CpuContextVa;
    unsigned long long DispatchReturnVa;
    unsigned long long ReturnSlotVa;
    unsigned long long OriginalRsp;
    unsigned long long Rcx;
    unsigned long long Rdx;
    unsigned long long R8;
    unsigned long long R9;
    unsigned long long ReturnSlots[kX2SharedLogMaxReturns];
    unsigned long long ReturnValues[kX2SharedLogMaxReturns];
};
#pragma pack(pop)

static_assert(sizeof(X2_SHARED_LOG) == 0xB8, "X2_SHARED_LOG ABI changed");

#pragma pack(push, 8)
struct X2_SHARED_LOG_QUEUE_HEADER
{
    volatile unsigned long long EnqueuePosition;
    volatile unsigned long long DroppedCount;
    unsigned long Capacity;
    unsigned long Version;
    unsigned long long Reserved[2];
};
#pragma pack(pop)

static_assert(sizeof(X2_SHARED_LOG_QUEUE_HEADER) == 0x28, "X2_SHARED_LOG_QUEUE_HEADER ABI changed");

static constexpr unsigned long long kX2SharedLogQueueBytes =
    sizeof(X2_SHARED_LOG_QUEUE_HEADER) +
    static_cast<unsigned long long>(kX2SharedLogCapacity) * sizeof(X2_SHARED_LOG);
static constexpr unsigned long kX2SharedLogQueuePages =
    static_cast<unsigned long>((kX2SharedLogQueueBytes + 0xFFFULL) >> 12);
static_assert((kX2SharedLogCapacity & kX2SharedLogQueueMask) == 0,
              "X2 shared log capacity must be a power of two");

} // namespace ShellCodeSpoof
