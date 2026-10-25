#pragma once

#include <ntddk.h>
#include <ia32.hpp>

#include "spin-lock.h"

namespace hv {

struct vcpu;

inline constexpr uint32_t ept_probe_slot_count = 16;
inline constexpr uint32_t ept_probe_hit_count  = 256;
inline constexpr uint32_t ept_probe_stack_qwords = 16;

enum ept_probe_flags : uint64_t {
    ept_probe_flag_kernel = 1ull << 0,  // use system_cr3 / kernel VA
};

struct ept_probe_slot {
    uint64_t id;
    uint64_t target_va;       // exact VA requested by host
    uint64_t target_page_va;  // page-aligned VA
    uint64_t target_cr3;      // normalized CR3 used for GVA->GPA
    uint64_t orig_pfn;
    uint64_t shadow_pfn;
    uint64_t page_offset;
    uint64_t hit_count;
    uint64_t hit_limit;       // 0 = unlimited recording
    uint64_t active_bitmap;   // vCPU EPT trees that installed this probe
    bool     is_kernel;
    bool     active;
};

struct ept_probe_hit {
    uint64_t seq;
    uint64_t probe_id;
    uint64_t target_va;
    uint64_t rip;       // RIP restored for original instruction execution
    uint64_t bp_rip;    // raw VMCS_GUEST_RIP observed on #BP
    uint64_t rsp;
    uint64_t rflags;
    uint64_t cr3;
    uint64_t process;
    uint64_t thread;
    uint64_t pid;
    uint64_t cpu_index;

    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

    uint64_t stack[ept_probe_stack_qwords];
};

struct ept_probe_table {
    spin_lock lock;
    uint64_t next_id;
    uint64_t next_seq;
    uint32_t hit_write;
    uint32_t hit_count;

    ept_probe_slot slots[ept_probe_slot_count];
    ept_probe_hit  hits[ept_probe_hit_count];

    alignas(0x1000) uint8_t shadow_pages[ept_probe_slot_count][0x1000];
    uint64_t shadow_pfns[ept_probe_slot_count];
};

void init_ept_probe_table();

uint64_t ept_probe_install_current(vcpu* cpu, uint64_t target_cr3,
                                   uint64_t target_va, uint64_t flags,
                                   uint64_t hit_limit);
uint64_t ept_probe_remove_current(vcpu* cpu, uint64_t target_cr3,
                                  uint64_t target_va, uint64_t flags);

// Host/root-模式 helper: 安装/卸载移除 the same probe in every live vCPU EPT.
// This only mutates EPT page tables + host-owned 影子页面s; it does not 写入
// guest memory and therefore does not trigger guest copy-on-写入.
uint64_t ept_probe_install_all(vcpu* current_cpu, uint64_t target_cr3,
                               uint64_t target_va, uint64_t flags,
                               uint64_t hit_limit,
                               uint64_t* installed_mask = nullptr);
uint64_t ept_probe_remove_all(vcpu* current_cpu, uint64_t target_cr3,
                              uint64_t target_va, uint64_t flags,
                              uint64_t* removed_mask = nullptr);

uint64_t ept_probe_copy_hits(vcpu* cpu, uint64_t out_gva,
                             uint64_t max_hits, bool clear_after);
uint64_t ept_probe_clear_hits();

bool try_handle_ept_probe_bp(vcpu* cpu);
bool handle_ept_probe_mtf(vcpu* cpu);

} // namespace hv
