#pragma once

#include <ntddk.h>
#include <stdint.h>

namespace hv {

enum class nested_page_backend : uint8_t {
    unknown = 0,
    ept = 1,
    npt = 2,
};

enum nested_page_access : uint16_t {
    nested_page_read = 1u << 0,
    nested_page_write = 1u << 1,
    nested_page_execute = 1u << 2,
    nested_page_present = 1u << 3,
    nested_page_hook_match = 1u << 4,
};

struct alignas(64) nested_page_event {
    volatile uint64_t sequence;
    uint64_t timestamp;
    uint64_t guest_physical;
    uint64_t guest_virtual;
    uint64_t guest_rip;
    uint64_t guest_cr3;
    uint32_t vcpu;
    uint16_t access;
    uint8_t backend;
    uint8_t reserved;
};

static_assert(sizeof(nested_page_event) == 64, "nested page event must remain cache-line sized");

class NestedPageInstrumentation final {
  public:
    static void Initialize() noexcept;
    static void SetArmed(bool armed) noexcept;
    static bool IsArmed() noexcept;
    static void Record(nested_page_backend backend,
                       uint16_t access,
                       uint64_t guest_physical,
                       uint64_t guest_virtual,
                       uint64_t guest_rip,
                       uint64_t guest_cr3,
                       uint32_t vcpu) noexcept;
    static uint32_t Snapshot(nested_page_event* output, uint32_t capacity) noexcept;
    static void Reset() noexcept;
};

} // namespace hv
