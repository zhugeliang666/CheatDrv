#pragma once

#include <ntddk.h>
#include <stdint.h>
#include "spin-lock.h"

namespace hv {

struct vcpu;

namespace eh {

// Maximum vCPU count 鈥 kept for per_vcpu_active_bitmap tracking only.
// fake_pages are no longer per-vCPU; trampoline handles the race instead.
inline constexpr uint32_t MAX_HOOK_VCPU = 32;

struct ept_hook_entry {
    ept_hook_entry* next;

    PEPROCESS  process;
    uint64_t   process_cr3;
    uint64_t   va;
    uint64_t   orig_pfn;
    uint64_t   fake_pfn;          // single shared fake PFN (no longer per-vCPU)

    uint32_t   fake_page_idx;
    bool       in_use;
    bool       is_fake_page;
    uint16_t   _pad;

    uint64_t   per_vcpu_active_bitmap;
};

struct ept_hook_table {
    // Reverted to single fake_page per 条目项 now that dispatcher fallthrough
    // no longer mutates fake_page bytes (trampoline handles execution).
    static constexpr size_t capacity = 32;

    spin_lock        lock;
    uint32_t         in_use_count;
    uint32_t         _pad;

    ept_hook_entry*  active_list_head;
    ept_hook_entry*  free_list_head;

    ept_hook_entry   buffer[capacity];

    // Single fake page per entry 鈥 32 脳 4KB = 128KB.
    alignas(0x1000) uint8_t fake_pages[capacity][0x1000];
    uint64_t         fake_page_pfns[capacity];
};

void init_ept_hook_table();

ept_hook_entry* find_entry_locked(uint64_t process_cr3, uint64_t va_page);
ept_hook_entry* alloc_entry_locked();
void            free_entry_locked(ept_hook_entry* entry);

// Locked wrapper for callers outside the 表-lock section.
void            free_entry(ept_hook_entry* entry);

bool eh_install_internal(vcpu* cpu, PEPROCESS process, uint64_t va,
                         bool full_zero, bool is_fake_page);

// Two-phase 安装 for IPI path:
//   1) eh_prepare_entry 鈥 alloc entry, capture orig_pfn, memcpy fake_page.
// Does NOT touch EPT. Idempotent: returns existing 条目项 if (cr3,va_page)
//      already has one. Run by the IPI initializer vCPU only.
//      out_freshly_allocated tells caller whether this was a new alloc
//      (caller must free_entry on later failure) or a reuse (caller must NOT).
//   2) eh_install_self  鈥 install EPT hook on the calling vCPU's own ept tree
//      and invept_single. Each vCPU runs this for itself.
ept_hook_entry* eh_prepare_entry(PEPROCESS process, uint64_t va,
                                  bool full_zero, bool is_fake_page,
                                  bool* out_freshly_allocated);

void eh_install_self(vcpu* cpu, ept_hook_entry* entry);

// Host-handler 安装 path: 当前 vCPU writes EVERY vCPU's ept tree
// and sets pending_ept_invept_bitmap; other vCPUs 刷新 their own TLB on
// their next vmexit. Used when there's no IPI to 分发 per-vCPU.
void eh_install_all(vcpu* cpu, ept_hook_entry* entry);

// Host-handler DEFERRED 安装 path: 当前 vCPU installs EPT on its OWN
// ept tree only. The 条目项 指针 is enqueued in
// g_ghv->pending_ept_install_entries[] and bits 设置 in
// g_ghv->pending_ept_install_bitmap for every other vCPU. Each other vCPU,
// on its next vmexit (any reason), drains the queue and installs the 条目项
// on its own ept tree. No cross-vCPU EPT writes 鈥 eliminates the race
// where this vCPU writes another vCPU's ept while that vCPU is mid-instr
// on the same page (PDE split + hw page walk overlap 鈫 DWM crash).
//
// Cost: other vCPUs see the hook ~1 vmexit later (timer / interrupt / any
// other vmexit; sub-millisecond on healthy systems). Acceptable for hooks
// installed lazily from a host handler.
void eh_install_all_deferred(vcpu* cpu, ept_hook_entry* entry);

// Drain pending_ept_install_entries on the 当前 vCPU. Called by
// dispatch_vm_exit when this vCPU's bit is 设置 in pending_ept_install_bitmap.
void drain_pending_installs(vcpu* cpu);

void* eh_get_fake_hva_for_entry(ept_hook_entry* entry, uint64_t va);

bool eh_write_internal(uint64_t process_cr3, uint64_t dst_va,
                       const void* src_hva, size_t size);

void* eh_get_fake_hva_for_cpu(uint64_t process_cr3, uint64_t va_page, uint32_t cpuid);

}  // namespace eh

}  // namespace hv
