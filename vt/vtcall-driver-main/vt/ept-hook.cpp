#include "ept-hook.h"
#include "hv.h"
#include "mm.h"
#include "ept.h"
#include "vcpu.h"
#include "vmx.h"
#include "hypercalls.h"
#include "page-tables.h"

namespace hv {

#pragma code_seg(".vm")

namespace eh {

// --- internal static helpers ---

static inline uint32_t vcpu_idx(vcpu* cpu) {
    return static_cast<uint32_t>(cpu - g_ghv->vcpus);
}

static inline uint64_t page_align(uint64_t va) {
    return va & ~static_cast<uint64_t>(0xFFF);
}

static uint64_t read_process_cr3(PEPROCESS process) {
    if (!process)
        return 0;
    uint64_t cr3_val = 0;
    auto addr = reinterpret_cast<uint8_t*>(process) + g_ghv->kprocess_directory_table_base_offset;
    if (read_guest_virtual_memory(g_ghv->system_cr3, addr, &cr3_val, sizeof(cr3_val))
        != sizeof(cr3_val))
        return 0;
    return cr3_val & ~static_cast<uint64_t>(0xFFF);
}

static uint64_t resolve_process_cr3(PEPROCESS process) {
    // Compare against cached System EPROCESS pointer (avoid touching the
    // PsInitialSystemProcess kernel global directly from root mode).
    if (!process || reinterpret_cast<uint8_t*>(process) == g_ghv->system_eprocess)
        return g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
    return read_process_cr3(process);
}

// --- table management (exposed for vtcall-hook.cpp) ---

void init_ept_hook_table() {
    auto& t = g_ghv->ept_hook_table;

    t.lock.initialize();
    t.in_use_count = 0;
    t.active_list_head = nullptr;
    t.free_list_head = nullptr;

    for (size_t i = 0; i < ept_hook_table::capacity; i++) {
        auto& e = t.buffer[i];
        e.next = nullptr;
        e.process = nullptr;
        e.process_cr3 = 0;
        e.va = 0;
        e.orig_pfn = 0;
        e.fake_pfn = 0;
        e.fake_page_idx = static_cast<uint32_t>(i);
        e.in_use = false;
        e.is_fake_page = false;
        e.per_vcpu_active_bitmap = 0;
    }

    for (size_t i = 0; i + 1 < ept_hook_table::capacity; i++)
        t.buffer[i].next = &t.buffer[i + 1];
    t.buffer[ept_hook_table::capacity - 1].next = nullptr;
    t.free_list_head = &t.buffer[0];

    for (uint32_t i = 0; i < ept_hook_table::capacity; i++) {
        void* va = &t.fake_pages[i][0];
        t.fake_page_pfns[i] =
            static_cast<uint64_t>(MmGetPhysicalAddress(va).QuadPart) >> 12;
        memset(va, 0, 0x1000);
    }
}

ept_hook_entry* find_entry_locked(uint64_t process_cr3, uint64_t va_page) {
    auto& t = g_ghv->ept_hook_table;
    for (auto e = t.active_list_head; e; e = e->next) {
        if (e->process_cr3 == process_cr3 && e->va == va_page)
            return e;
    }
    return nullptr;
}

ept_hook_entry* alloc_entry_locked() {
    auto& t = g_ghv->ept_hook_table;
    if (!t.free_list_head)
        return nullptr;

    auto e = t.free_list_head;
    t.free_list_head = e->next;

    e->next = t.active_list_head;
    t.active_list_head = e;

    e->in_use = true;
    t.in_use_count++;
    return e;
}

void free_entry_locked(ept_hook_entry* entry) {
    auto& t = g_ghv->ept_hook_table;

    // Unlink from active list.
    if (t.active_list_head == entry) {
        t.active_list_head = entry->next;
    } else {
        for (auto p = t.active_list_head; p; p = p->next) {
            if (p->next == entry) {
                p->next = entry->next;
                break;
            }
        }
    }

    // Reset, preserving the stable fake_page_idx.
    auto idx = entry->fake_page_idx;
    entry->next = nullptr;
    entry->process = nullptr;
    entry->process_cr3 = 0;
    entry->va = 0;
    entry->orig_pfn = 0;
    entry->fake_pfn = 0;
    entry->fake_page_idx = idx;
    entry->in_use = false;
    entry->is_fake_page = false;
    entry->per_vcpu_active_bitmap = 0;

    // Push to free list.
    entry->next = t.free_list_head;
    t.free_list_head = entry;
    if (t.in_use_count > 0)
        t.in_use_count--;
}

void free_entry(ept_hook_entry* entry) {
    if (!entry) return;
    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    free_entry_locked(entry);
    t.lock.release();
}

// --- internal install (called from vtcall-hook.cpp or vmcall handler) ---

// Phase 1 of IPI install. Only the IPI initializer vCPU runs this.
// alloc entry, capture orig_pfn, memcpy fake_page. Does NOT touch EPT.
// out_freshly_allocated=true 鈫 caller owns the entry and must free_entry
// on later failure. =false 鈫 entry was reused, caller must NOT free.
ept_hook_entry* eh_prepare_entry(PEPROCESS process, uint64_t va,
                                  bool full_zero, bool is_fake_page,
                                  bool* out_freshly_allocated) {
    if (out_freshly_allocated) *out_freshly_allocated = false;
    auto va_page = page_align(va);

    auto process_cr3 = resolve_process_cr3(process);
    if (!process_cr3)
        return nullptr;

    // Kernel VA shortcut: when targeting a kernel-space VA (>= 0xFFFF8...),
    // force lookup AND entry index through system_cr3. Per-process page
    // tables can have NX bits / shadowed entries / partial KVA mappings for
    // kernel space, which would walk to the wrong PFN and cause us to
    // redirect an unrelated physical page. system_cr3 always has the
    // canonical kernel mapping. The caller's `process` is still preserved
    // on the entry record so dispatcher can do its filtering, but the
    // `process_cr3` used to KEY the entry table must match what enable /
    // disable / remove paths look up below 鈥 they too must normalize kernel
    // VAs to system_cr3 (see vtcall-hook.cpp callers).
    if (va_page >= 0xFFFF800000000000ULL && g_ghv->system_cr3.flags) {
        process_cr3 = g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
    }

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = find_entry_locked(process_cr3, va_page);
    if (entry) { t.lock.release(); return entry; }

    entry = alloc_entry_locked();
    if (!entry) { t.lock.release(); return nullptr; }

    cr3 c{};
    c.flags = process_cr3;

    size_t off = 0;
    uint64_t orig_gpa = gva2gpa(c, reinterpret_cast<void*>(va_page), &off);
    if (!orig_gpa) {
        free_entry_locked(entry);
        t.lock.release();
        return nullptr;
    }

    entry->process = process;
    entry->process_cr3 = process_cr3;
    entry->va = va_page;
    entry->orig_pfn = orig_gpa >> 12;
    entry->fake_pfn = t.fake_page_pfns[entry->fake_page_idx];
    entry->is_fake_page = is_fake_page;
    entry->per_vcpu_active_bitmap = 0;

    uint8_t* fake = &t.fake_pages[entry->fake_page_idx][0];
    if (full_zero) {
        memset(fake, 0, 0x1000);
    } else {
        void* orig_hva = gva2hva(c, reinterpret_cast<void*>(va_page));
        if (orig_hva) memcpy(fake, orig_hva, 0x1000);
        else          memset(fake, 0, 0x1000);
    }

    t.lock.release();
    if (out_freshly_allocated) *out_freshly_allocated = true;
    return entry;
}

// Phase 2 of IPI install. Each vCPU runs this for itself: writes its own
// EPT tree to redirect orig_pfn鈫抐ake_pfn (execute-only view) and flushes
// its own TLB.
void eh_install_self(vcpu* cpu, ept_hook_entry* entry) {
    if (!entry) return;

    auto self_idx = vcpu_idx(cpu);
    uint64_t bit = 1ULL << self_idx;

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    bool already = (entry->per_vcpu_active_bitmap & bit) != 0;
    auto orig_pfn = entry->orig_pfn;
    auto fake_pfn = entry->fake_pfn;
    bool ifp      = entry->is_fake_page;
    t.lock.release();

    if (already) return;

    // install_ept_hook can fail (no free hook node / get_ept_pte returned
    // nullptr / failed to split a 2MB PDE). Only mark the bit AFTER success
    // so a failed install can be retried later 鈥 and so the diag bitmap
    // accurately reflects which vCPUs actually have the hook.
    if (!install_ept_hook(cpu->ept, orig_pfn, fake_pfn, ifp))
        return;

    t.lock.acquire();
    entry->per_vcpu_active_bitmap |= bit;
    t.lock.release();
}

// Install on ALL vCPUs from a single calling vCPU (host handler path) 鈥
// Install on ALL vCPUs from a single calling vCPU (host handler path).
// Used when there's no IPI rendezvous 鈥 current vCPU writes every vCPU's
// EPT tree synchronously and sets pending_ept_invept_bitmap so the other
// vCPUs flush their own TLB on their next vmexit.
//
// This is the known-working pattern: NtSetEvent installed via this path
// (single vCPU writes all 16 ept trees + invept_all_context for self) +
// driver IPI for PMO produced handler_count > 0, hit_count > 0.
void eh_install_all(vcpu* cpu, ept_hook_entry* entry) {
    if (!entry) return;

    auto self_idx = vcpu_idx(cpu);
    uint32_t vcpu_count = g_ghv->vcpu_count;

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto orig_pfn = entry->orig_pfn;
    auto fake_pfn = entry->fake_pfn;
    bool ifp      = entry->is_fake_page;
    uint64_t bitmap_snapshot = entry->per_vcpu_active_bitmap;
    t.lock.release();

    uint64_t newly_installed_bitmap = 0;
    for (uint32_t v = 0; v < vcpu_count; v++) {
        uint64_t bit = 1ULL << v;
        if (bitmap_snapshot & bit) continue;
        if (install_ept_hook(g_ghv->vcpus[v].ept, orig_pfn, fake_pfn, ifp))
            newly_installed_bitmap |= bit;
    }

    if (newly_installed_bitmap) {
        t.lock.acquire();
        entry->per_vcpu_active_bitmap |= newly_installed_bitmap;
        t.lock.release();
    }

    uint64_t others = newly_installed_bitmap & ~(1ULL << self_idx);
    if (others)
        _InterlockedOr64((volatile LONG64*)&g_ghv->pending_ept_invept_bitmap,
                         (LONG64)others);
}

// drain_pending_installs: scan the deferred-install array and install any
// entries this vCPU hasn't yet picked up. Entries whose per_vcpu_active_bitmap
// is fully set across the live vCPU set are CAS-cleared back to nullptr so
// the slot can be reused by a later install.
void drain_pending_installs(vcpu* cpu) {
    if (!cpu) return;
    uint32_t vc = g_ghv->vcpu_count;
    uint64_t full_mask = (vc >= 64) ? ~0ULL : ((1ULL << vc) - 1);
    for (uint32_t i = 0; i < g_ghv->pending_install_capacity; i++) {
        auto e = g_ghv->pending_ept_install_entries[i];
        if (!e) continue;
        // eh_install_self is idempotent (per_vcpu_active_bitmap check inside)
        // 鈥 safe to call even for entries this vCPU already installed.
        eh_install_self(cpu, e);

        // If every live vCPU now has this entry installed, retire the slot
        // so a future install can reuse it. Use CAS so concurrent drains
        // don't double-clear (and so we don't race a fresh enqueue that
        // grabbed this slot 鈥 the cmpxchg only succeeds if the slot still
        // holds e).
        auto& t = g_ghv->ept_hook_table;
        t.lock.acquire();
        bool retire = (e->per_vcpu_active_bitmap & full_mask) == full_mask;
        t.lock.release();
        if (retire) {
            _InterlockedCompareExchangePointer(
                (PVOID volatile*)&g_ghv->pending_ept_install_entries[i],
                nullptr, e);
        }
    }
}

// Host-handler DEFERRED install: current vCPU installs OWN ept,
// other vCPUs enqueue + bit-set; each drains on its next vmexit.
void eh_install_all_deferred(vcpu* cpu, ept_hook_entry* entry) {
    if (!entry) return;

    // 1) Current vCPU installs its own EPT immediately (no race 鈥 own tree).
    eh_install_self(cpu, entry);

    // 2) Find a free slot (CAS nullptr 鈫 entry). Slots get retired by drain
    //    once every vCPU has installed, so the array is bounded reuse, not
    //    monotonic growth.
    bool placed = false;
    for (uint32_t i = 0; i < g_ghv->pending_install_capacity; i++) {
        auto prev = _InterlockedCompareExchangePointer(
            (PVOID volatile*)&g_ghv->pending_ept_install_entries[i],
            entry, nullptr);
        if (prev == nullptr) {
            placed = true;
            break;
        }
        // Same entry already pending (e.g., re-arm after idempotent path) 鈥
        // treat as success without claiming a new slot.
        if (prev == entry) {
            placed = true;
            break;
        }
    }
    if (!placed) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_pending_queue_full);
        return;
    }

    // 3) Arm bitmap for every OTHER vCPU. Current vCPU already done.
    uint32_t vc = g_ghv->vcpu_count;
    auto self_idx = vcpu_idx(cpu);
    uint64_t others = ((vc >= 64) ? ~0ULL : ((1ULL << vc) - 1))
                      & ~(1ULL << self_idx);
    _InterlockedOr64((volatile LONG64*)&g_ghv->pending_ept_install_bitmap,
                     (LONG64)others);
}

void* eh_get_fake_hva_for_entry(ept_hook_entry* entry, uint64_t va) {
    if (!entry) return nullptr;
    auto& t = g_ghv->ept_hook_table;
    auto offset = va & static_cast<uint64_t>(0xFFF);
    return &t.fake_pages[entry->fake_page_idx][offset];
}

bool eh_install_internal(vcpu* cpu, PEPROCESS process, uint64_t va,
                         bool full_zero, bool is_fake_page) {
    bool freshly = false;
    auto entry = eh_prepare_entry(process, va, full_zero, is_fake_page, &freshly);
    if (!entry) return false;
    eh_install_self(cpu, entry);
    return true;
}

bool eh_write_internal(uint64_t process_cr3, uint64_t dst_va,
                       const void* src_hva, size_t size) {
    auto va_page = page_align(dst_va);
    auto offset = dst_va & static_cast<uint64_t>(0xFFF);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        return false;
    }

    if (offset + size > 0x1000)
        size = 0x1000 - offset;

    auto dst = &t.fake_pages[entry->fake_page_idx][offset];
    memcpy(dst, src_hva, size);

    t.lock.release();
    return true;
}

// Get the host VA of the shared fake page at offset for (process_cr3, va_page).
// cpuid ignored 鈥 single shared fake page now (trampoline replaced per-vCPU mutation).
void* eh_get_fake_hva_for_cpu(uint64_t process_cr3, uint64_t va_page, uint32_t /*cpuid*/) {
    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto entry = find_entry_locked(process_cr3, va_page);
    if (!entry) { t.lock.release(); return nullptr; }
    auto idx = entry->fake_page_idx;
    auto offset = va_page & 0xFFFull;  // va_page is already page-aligned; offset = 0
    t.lock.release();
    return &t.fake_pages[idx][offset];
}

}  // namespace eh


namespace hc {

void vmcall_eh_install(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto flags = cpu->ctx->r8;
    bool full_zero    = (flags & 1) != 0;
    bool is_fake_page = (flags & 2) != 0;

    cpu->ctx->rax = eh::eh_install_internal(cpu, process, va, full_zero, is_fake_page) ? 1 : 0;
    skip_instruction();
}

void vmcall_eh_remove(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto va_page = eh::page_align(va);
    auto cpu_bit = 1ULL << eh::vcpu_idx(cpu);

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = eh::find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    bool need_remove = (entry->per_vcpu_active_bitmap & cpu_bit) != 0;
    if (need_remove)
        entry->per_vcpu_active_bitmap &= ~cpu_bit;

    auto orig_pfn = entry->orig_pfn;
    bool free_now = (entry->per_vcpu_active_bitmap == 0);
    if (free_now)
        eh::free_entry_locked(entry);

    t.lock.release();

    if (need_remove)
        remove_ept_hook(cpu->ept, orig_pfn);

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_eh_enable(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto va_page = eh::page_align(va);
    auto cpu_idx = eh::vcpu_idx(cpu);
    auto cpu_bit = 1ULL << cpu_idx;

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = eh::find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    bool need_install = (entry->per_vcpu_active_bitmap & cpu_bit) == 0;
    if (need_install)
        entry->per_vcpu_active_bitmap |= cpu_bit;

    auto orig_pfn = entry->orig_pfn;
    auto fake_pfn = entry->fake_pfn;
    bool ifp = entry->is_fake_page;

    t.lock.release();

    if (need_install)
        install_ept_hook(cpu->ept, orig_pfn, fake_pfn, ifp);

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_eh_disable(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto va_page = eh::page_align(va);
    auto cpu_bit = 1ULL << eh::vcpu_idx(cpu);

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = eh::find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    bool need_remove = (entry->per_vcpu_active_bitmap & cpu_bit) != 0;
    if (need_remove)
        entry->per_vcpu_active_bitmap &= ~cpu_bit;

    auto orig_pfn = entry->orig_pfn;

    t.lock.release();

    if (need_remove)
        remove_ept_hook(cpu->ept, orig_pfn);

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_eh_write(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto dst_va = cpu->ctx->rdx;
    auto src_va = cpu->ctx->r8;
    auto size = cpu->ctx->r9;

    auto process_cr3 = eh::resolve_process_cr3(process);
    if (!process_cr3) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    // Read source bytes (caller passes a kernel pointer in src_va; read via system CR3).
    uint8_t buf[0x1000];
    if (size > sizeof(buf))
        size = sizeof(buf);

    auto got = read_guest_virtual_memory(g_ghv->system_cr3,
        reinterpret_cast<void*>(src_va), buf, size);
    if (got != size) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    cpu->ctx->rax = eh::eh_write_internal(process_cr3, dst_va, buf, size) ? 1 : 0;
    skip_instruction();
}

void vmcall_eh_get_va(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto va_page = eh::page_align(va);
    auto offset = va & static_cast<uint64_t>(0xFFF);

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = eh::find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    auto fake_va = reinterpret_cast<uint64_t>(&t.fake_pages[entry->fake_page_idx][offset]);
    t.lock.release();

    cpu->ctx->rax = fake_va;
    skip_instruction();
}

void vmcall_eh_remove_all_by_process(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto cpu_bit = 1ULL << eh::vcpu_idx(cpu);

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;

    // Snapshot the PFNs we need to remove from EPT under the lock.
    uint64_t pfns[eh::ept_hook_table::capacity];
    size_t n = 0;

    t.lock.acquire();
    auto e = t.active_list_head;
    while (e) {
        auto next = e->next;
        if (e->process_cr3 == process_cr3) {
            if (e->per_vcpu_active_bitmap & cpu_bit) {
                if (n < eh::ept_hook_table::capacity)
                    pfns[n++] = e->orig_pfn;
                e->per_vcpu_active_bitmap &= ~cpu_bit;
            }
            if (e->per_vcpu_active_bitmap == 0)
                eh::free_entry_locked(e);
        }
        e = next;
    }
    t.lock.release();

    for (size_t i = 0; i < n; i++)
        remove_ept_hook(cpu->ept, pfns[i]);

    cpu->ctx->rax = 1;
    skip_instruction();
}

}  // namespace hc

}  // namespace hv
