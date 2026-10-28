#include "nested-page-instrumentation.h"
#include <intrin.h>

#ifndef VT_NESTED_PAGE_INSTRUMENTATION_DEFAULT_ARMED
#define VT_NESTED_PAGE_INSTRUMENTATION_DEFAULT_ARMED 0
#endif

namespace {
constexpr uint32_t kRingCapacity = 256;
constexpr uint32_t kRingMask = kRingCapacity - 1;

alignas(64) volatile LONG g_armed = VT_NESTED_PAGE_INSTRUMENTATION_DEFAULT_ARMED ? 1 : 0;
volatile LONG64 g_next = 0;
hv::nested_page_event g_ring[kRingCapacity] = {};
}

namespace hv {

void NestedPageInstrumentation::Initialize() noexcept
{
    Reset();
    SetArmed(VT_NESTED_PAGE_INSTRUMENTATION_DEFAULT_ARMED != 0);
}

void NestedPageInstrumentation::SetArmed(bool armed) noexcept
{
    InterlockedExchange(&g_armed, armed ? 1 : 0);
}

bool NestedPageInstrumentation::IsArmed() noexcept
{
    return InterlockedCompareExchange(&g_armed, 0, 0) != 0;
}

void NestedPageInstrumentation::Record(nested_page_backend backend,
                                       uint16_t access,
                                       uint64_t guest_physical,
                                       uint64_t guest_virtual,
                                       uint64_t guest_rip,
                                       uint64_t guest_cr3,
                                       uint32_t vcpu) noexcept
{
    if (!IsArmed())
        return;

    const LONG64 ticket = InterlockedIncrement64(&g_next) - 1;
    nested_page_event& event = g_ring[static_cast<uint32_t>(ticket) & kRingMask];
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&event.sequence), 0);
    event.timestamp = __rdtsc();
    event.guest_physical = guest_physical;
    event.guest_virtual = guest_virtual;
    event.guest_rip = guest_rip;
    event.guest_cr3 = guest_cr3;
    event.vcpu = vcpu;
    event.access = access;
    event.backend = static_cast<uint8_t>(backend);
    event.reserved = 0;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&event.sequence), ticket + 1);
}

uint32_t NestedPageInstrumentation::Snapshot(nested_page_event* output, uint32_t capacity) noexcept
{
    if (!output || capacity == 0)
        return 0;

    LONG64 next = InterlockedCompareExchange64(&g_next, 0, 0);
    uint32_t count = static_cast<uint32_t>(next < static_cast<LONG64>(kRingCapacity) ? next : kRingCapacity);
    if (count > capacity)
        count = capacity;

    const LONG64 first = next - count;
    uint32_t copied = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t index = static_cast<uint32_t>(first + i) & kRingMask;
        const LONG64 before = InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&g_ring[index].sequence), 0, 0);
        if (before == 0)
            continue;
        RtlCopyMemory(&output[copied], &g_ring[index], sizeof(nested_page_event));
        const LONG64 after = InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&g_ring[index].sequence), 0, 0);
        if (before != after)
            continue;
        ++copied;
    }
    return copied;
}

void NestedPageInstrumentation::Reset() noexcept
{
    InterlockedExchange64(&g_next, 0);
    RtlZeroMemory(g_ring, sizeof(g_ring));
}

} // namespace hv
