#include "vtcall-hook.h"
#include "hv.h"
#include "mm.h"
#include "ept.h"
#include "vcpu.h"
#include "vmx.h"
#include "hypercalls.h"
#include "ept-hook.h"
#include "page-tables.h"
#include "../gamecommon/game.h"
#include "../hook/hde64.h"

namespace hv {

#pragma code_seg(".vm")

namespace vh {

void init_vtcall_hook_subsystem() {
    // g_vt_hook_table is zero-initialized at program load; nothing else to do.
}

// --- internal helpers (host side) ---

static uint64_t read_process_cr3_local(PEPROCESS process) {
    if (!process || reinterpret_cast<uint8_t*>(process) == g_ghv->system_eprocess)
        return g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);

    uint64_t cr3_val = 0;
    auto addr = reinterpret_cast<uint8_t*>(process) + g_ghv->kprocess_directory_table_base_offset;
    if (read_guest_virtual_memory(g_ghv->system_cr3, addr, &cr3_val, sizeof(cr3_val))
        != sizeof(cr3_val))
        return 0;
    return cr3_val & ~static_cast<uint64_t>(0xFFF);
}

// For kernel-space VAs (>= 0xFFFF8...), per-process CR3 may diverge from
// system_cr3 due to KVA Shadow / partial kernel mappings 鈥 using the wrong
// CR3 walks to the wrong PFN. eh_prepare_entry indexes kernel-VA entries
// under system_cr3; every enable/disable/remove path that finds entries by
// (cr3, va) must do the same normalization, otherwise lookups miss.
static uint64_t effective_cr3_for_target(PEPROCESS process, uint64_t target_va) {
    if (target_va >= 0xFFFF800000000000ULL && g_ghv->system_cr3.flags)
        return g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
    return read_process_cr3_local(process);
}

// Find the first 4-byte 0xCC run within [start, start+max_scan) in target_cr3,
// and return the address of the byte just after that 0xCC sequence (matches the
// pattern used by the driver-side find_blank originally).
static uint64_t find_blank_host(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    cr3 c{};
    c.flags = target_cr3;

    // Read in 4 KB chunks (page granularity) and scan within each 鈥 much
    // faster than per-byte read_guest_virtual_memory, and ntdll padding
    // is typically multi-page so we always find a 4-byte 0xCC run quickly.
    uint64_t scanned = 0;
    while (scanned < max_scan) {
        uint64_t va = start + scanned;
        size_t to_read = min(uint64_t(0x1000), max_scan - scanned);
        // Align to next page boundary for next iter to keep reads page-aligned.
        size_t page_off = va & 0xFFFu;
        if (page_off + to_read > 0x1000u)
            to_read = 0x1000u - page_off;

        uint8_t page[0x1000];
        size_t got = read_guest_virtual_memory(c, reinterpret_cast<void*>(va),
                                                page, to_read);
        if (got < 4) {
            // page not present or unreadable 鈥 skip ahead to next page boundary
            scanned += (0x1000 - page_off);
            continue;
        }
        for (size_t i = 0; i + 3 < got; i++) {
            if (page[i]   == 0xCC && page[i+1] == 0xCC &&
                page[i+2] == 0xCC && page[i+3] == 0xCC) {
                return va + i + 1;
            }
        }
        scanned += got;
    }
    return 0;
}

// Compute the instruction-block size (>= 3 bytes) starting at target_va.
// Reads from guest memory using target_cr3 and captures the original bytes
// (up to 20 for old, 3 for the following instruction) into the output pointers.
static bool disasm_target_host(uint64_t target_va, uint64_t target_cr3,
                                uint32_t& out_size,
                                uint64_t& out_next_va,
                                uint8_t (&out_old)[20],
                                uint8_t (&out_next_old)[20]) {
    cr3 c{};
    c.flags = target_cr3;

    // Read 32 bytes of code to disassemble (safely covers any HDE-encoded prefix+instr).
    uint8_t code_buf[32] = {};
    auto got = read_guest_virtual_memory(c, reinterpret_cast<void*>(target_va), code_buf, sizeof(code_buf));
    if (got < 4)
        return false;

    uint32_t size = 0;
    while (size < 3 && size < sizeof(code_buf)) {
        hde64s hs{};
        hde64_disasm(code_buf + size, &hs);
        if (hs.len == 0)
            return false;
        size += hs.len;
    }
    if (size == 0 || size > 20)
        return false;

    // Cross-page guards.
    // 1) vmcall stub (0F 01 C1, 3 bytes) is written into the fake page at the
    //    same offset as target_va. If (target_va & 0xFFF) + 3 > 0x1000, the
    //    stub spills into fake_pages[idx+1], corrupting another entry's
    //    fake page. Reject the install 鈥 fake_pages are virtually contiguous
    //    but physically not, so stub bytes cannot legally cross the boundary.
    if ((target_va & 0xFFF) + 3 > 0x1000) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_install_xpage_stub);
        return false;
    }
    // 2) target_resume = target_va + size lands on the next 4KB page. This is
    //    safe in practice 鈥 the guest CR3 + EPT continue to map that page
    //    with the original PFN (only the hook page itself is redirected),
    //    and the caller's working set already had that page (control flow
    //    came from there). Just count occurrences for diagnostics; don't
    //    refuse the install.
    if (((target_va + size - 1) >> 12) != (target_va >> 12)) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_install_xpage_resume);
    }

    out_size = size;
    out_next_va = target_va + size;

    memset(out_old, 0, 20);
    memset(out_next_old, 0, 20);
    memcpy(out_old, code_buf, size);

    // Read 3 bytes at the next instruction.
    uint8_t next_buf[8] = {};
    if (read_guest_virtual_memory(c, reinterpret_cast<void*>(out_next_va), next_buf, 3) >= 3)
        memcpy(out_next_old, next_buf, 3);

    return true;
}

// Find a fully-blank 4KB page (entire page == 0xCC) inside [start, start+max_scan).
// Returns the page-aligned VA, or 0 if none. start is rounded up to next page.
//
// Used by the trampoline pool: we need a whole page of 0xCC because the EPT
// hook redirects the *page*, not bytes. ntdll has ~2MB of 0xCC padding between
// the .text trailer and the next section, so finding 4KB is trivial.
static uint64_t find_blank_page_host(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    cr3 c{};
    c.flags = target_cr3;

    uint64_t va = (start + 0xFFFu) & ~0xFFFull;
    uint64_t end = start + max_scan;

    while (va + 0x1000 <= end) {
        uint8_t page[0x1000];
        size_t got = read_guest_virtual_memory(c, reinterpret_cast<void*>(va), page, 0x1000);
        if (got < 0x1000) {
            // Page not present / unreadable 鈥 skip ahead by a page.
            va += 0x1000;
            continue;
        }
        bool all_cc = true;
        for (size_t i = 0; i < 0x1000; i++) {
            if (page[i] != 0xCC) { all_cc = false; break; }
        }
        if (all_cc)
            return va;
        va += 0x1000;
    }
    return 0;
}

// Public wrapper.
uint64_t find_blank_page_host_public(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    return find_blank_page_host(start, max_scan, target_cr3);
}

static int find_free_slot() {
    for (int i = 0; i < VMCALL_HOOK_MAX; i++)
        if (!g_vt_hook_table[i].occupied)
            return i;
    return -1;
}

static int find_slot_by_address(uint64_t target_va) {
    for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
        auto& s = g_vt_hook_table[i];
        if (s.occupied && reinterpret_cast<uint64_t>(s.data.address) == target_va)
            return i;
    }
    return -1;
}

// Apply vmcall stub to single shared fake page.
static void apply_enable_transition_hva(void* fake_hva) {
    if (!fake_hva)
        return;
    static const uint8_t vmcall_stub[3] = { 0x0F, 0x01, 0xC1 };
    memcpy(fake_hva, vmcall_stub, 3);
    __invlpg(fake_hva);
}

// IPI-install rendezvous state. vmcall_vh_install is dispatched via
// KeIpiGenericCall, so every vCPU enters install_host_impl simultaneously.
// One vCPU wins the seq_lock CAS and does the shared init (slot/trampoline/
// fake_page/0F01C1 write), then signals init_done. All vCPUs (including the
// winner) install EPT on THEIR OWN ept tree + invept_single. No vCPU writes
// another vCPU's EPT 鈥 TLB invalidation is per-vCPU.
struct ipi_install_state {
    volatile long       seq_lock;
    volatile long       init_done;
    volatile long       init_failed;
    eh::ept_hook_entry* entry;
    uint64_t            target_va;
};
static ipi_install_state s_ipi_state = {};

// Idempotency helper: same (target, type) already in g_vt_hook_table.
// Each vCPU still needs to install EPT on its own tree.
static void install_self_ept_for_slot(vcpu* cpu, vt_hook_slot& s) {
    auto target_va = reinterpret_cast<uint64_t>(s.data.address);
    auto va_page   = target_va & ~static_cast<uint64_t>(0xFFF);
    auto target_cr3 = effective_cr3_for_target(s.data.process, target_va);
    if (!target_cr3) return;

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto entry = eh::find_entry_locked(target_cr3, va_page);
    t.lock.release();
    eh::eh_install_self(cpu, entry);
}

// Same but for the host-handler path: the calling vCPU writes EPT for ALL
// vCPUs (current vCPU is invept'd by install_ept_hook; others get pending
// invept bits, picked up at next vmexit).
static void install_all_ept_for_slot(vcpu* cpu, vt_hook_slot& s) {
    auto target_va = reinterpret_cast<uint64_t>(s.data.address);
    auto va_page   = target_va & ~static_cast<uint64_t>(0xFFF);
    auto target_cr3 = effective_cr3_for_target(s.data.process, target_va);
    if (!target_cr3) return;

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto entry = eh::find_entry_locked(target_cr3, va_page);
    t.lock.release();
    eh::eh_install_all(cpu, entry);
}

// Install EPT hook and return single shared fake HVA at the hook offset.
// Legacy entry point 鈥 kept for callers that haven't migrated to the
// two-phase prepare/install_self model. Uses the IPI-style for-each-vCPU
// path internally, so safe to call only from contexts where a single vCPU
// representing the install can broadcast.
static uint64_t eh_install_and_get_fake_va(vcpu* cpu, PEPROCESS process, uint64_t va,
                                            bool full_zero, bool is_fake_page) {
    if (!eh::eh_install_internal(cpu, process, va, full_zero, is_fake_page))
        return 0;

    auto process_cr3 = effective_cr3_for_target(process, va);
    if (!process_cr3)
        return 0;

    auto va_page = va & ~static_cast<uint64_t>(0xFFF);
    auto offset  = va & static_cast<uint64_t>(0xFFF);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto e = eh::find_entry_locked(process_cr3, va_page);
    uint64_t fake_va = 0;
    if (e)
        fake_va = reinterpret_cast<uint64_t>(&t.fake_pages[e->fake_page_idx][offset]);
    t.lock.release();
    return fake_va;
}

// Claim a free trampoline slot. Writes oldByte + 0xCC into the slot's
// exec_page, computes the three guest VAs (tramp_va / bp_rip / target_resume)
// and returns them via out params. Returns false if pool not ready or no
// slot has enough capacity (oldByte_size + 1 <= slot.capacity).
static bool alloc_trampoline(uint64_t target_va, const uint8_t* old_bytes,
                              uint32_t size, bool is_kernel,
                              uint64_t& out_tramp_va,
                              uint64_t& out_bp_rip,
                              uint64_t& out_target_resume) {
    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();

    bool ready = is_kernel ? pool.kernel_ready : pool.user_ready;
    g_ghv->diag_alloc_is_kernel  = is_kernel ? 1 : 0;
    g_ghv->diag_alloc_pool_ready = ready ? 1 : 0;
    if (!ready) { pool.lock.release(); return false; }

    auto slots       = is_kernel ? pool.kernel_slots      : pool.user_slots;
    auto slot_count  = is_kernel ? pool.kernel_slot_count : pool.user_slot_count;
    auto pages       = is_kernel ? pool.kernel_pages      : pool.user_pages;

    uint32_t needed = size + 1;  // oldByte + 0xCC
    g_ghv->diag_alloc_slot_count = slot_count;
    g_ghv->diag_alloc_needed     = needed;
    if (slot_count > 0) {
        g_ghv->diag_alloc_slot0_occupied    = slots[0].occupied ? 1 : 0;
        g_ghv->diag_alloc_slot0_capacity    = slots[0].capacity;
        g_ghv->diag_alloc_slot0_page_offset = slots[0].page_offset;
        g_ghv->diag_alloc_slot0_page_index  = slots[0].page_index;
    }
    int idx = -1;
    for (uint32_t i = 0; i < slot_count; i++) {
        if (slots[i].occupied) continue;
        if (slots[i].capacity < needed) continue;
        // Sanity: vmcall_vh_tramp_add_slot already rejects cross-page slots
        // at registration. This check is defence-in-depth 鈥 if it ever trips
        // the pool was constructed wrong.
        if ((uint32_t)slots[i].page_offset + (uint32_t)slots[i].capacity > 0x1000) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_alloc_xpage_skipped);
            continue;
        }
        idx = (int)i;
        break;
    }
    if (idx < 0) { pool.lock.release(); return false; }

    auto& s   = slots[idx];
    auto& pg  = pages[s.page_index];
    // Write through host_physical_memory_base instead of pg.exec_hva so we
    // don't depend on the driver-side system VA being mapped in host PT.
    uint8_t* exec_base = host_physical_to_virtual(pg.exec_pfn << 12);
    if (!exec_base) { pool.lock.release(); return false; }
    uint8_t* exec_hva = exec_base + s.page_offset;
    memcpy(exec_hva, old_bytes, size);
    exec_hva[size] = 0xCC;

    s.occupied      = true;
    s.tramp_va      = pg.guest_page_va + s.page_offset;
    // INT3 vm-exit reports GUEST_RIP pointing AT the 0xCC byte (not past it).
    // bp_rip must therefore be tramp_va + oldByte_size, the position of 0xCC.
    s.bp_rip        = s.tramp_va + size;
    s.target_resume = target_va + size;

    out_tramp_va      = s.tramp_va;
    out_bp_rip        = s.bp_rip;
    out_target_resume = s.target_resume;

    pool.lock.release();
    return true;
}

// Release a trampoline slot back to its pool. Called on hook remove.
static void free_trampoline(uint64_t tramp_va) {
    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();
    auto try_release = [&](tramp_slot* slots, uint32_t count) {
        for (uint32_t i = 0; i < count; i++) {
            if (slots[i].occupied && slots[i].tramp_va == tramp_va) {
                slots[i].occupied      = false;
                slots[i].tramp_va      = 0;
                slots[i].bp_rip        = 0;
                slots[i].target_resume = 0;
                return true;
            }
        }
        return false;
    };
    if (!try_release(pool.user_slots, pool.user_slot_count))
        try_release(pool.kernel_slots, pool.kernel_slot_count);
    pool.lock.release();
}

// Host-internal install path. Callable from any host root-mode code.
// PEPROCESS=nullptr 鈫 system process / system_cr3 (kernel hook).
//
// from_ipi:
//   true  鈥 caller is the vmcall_vh_install handler (KeIpiGenericCall
//           delivers vmcall to every vCPU simultaneously). One vCPU wins
//           seq_lock CAS and does the shared init; all vCPUs (winner
//           included) call eh_install_self on their own ept tree.
//   false 鈥 caller is a host vmexit handler running on a single vCPU
//           (e.g. PMO handler lazy-installing GetBuffer/NtSetEvent).
//           Current vCPU does shared init AND writes EPT for ALL vCPUs
//           via eh_install_all; other vCPUs flush their own TLB on
//           their next vmexit (pending_ept_invept_bitmap).
bool install_host_impl(vcpu* cpu, PEPROCESS process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable, bool from_ipi) {
    // PMO-only step diag.
    auto self_idx_diag = (uint32_t)(cpu - g_ghv->vcpus);
    bool is_pmo = (type == 1);
    auto bump_step = [&](uint32_t mask) {
        if (is_pmo && self_idx_diag < 16)
            _InterlockedOr((volatile LONG*)&g_ghv->diag_pmo_step[self_idx_diag], (LONG)mask);
    };
    bump_step(1 << 0);   // entered

    // Single global lock: serialize ALL install entries (shared-init phase).
    // First vCPU through allocates entry/slot/trampoline and writes 0F01C1.
    // Subsequent vCPUs see slot already occupied and skip those steps.
    // EVERY vCPU then unconditionally installs EPT on its OWN ept tree.
    static volatile long s_install_lock = 0;
    while (_InterlockedCompareExchange(&s_install_lock, 1, 0) != 0)
        _mm_pause();

    g_ghv->diag_install_last_target = target_va;
    g_ghv->diag_install_last_fail   = 0;

    // Look for existing slot (already installed by an earlier vCPU).
    int slot_idx = -1;
    for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
        auto& s = g_vt_hook_table[i];
        if (s.occupied && reinterpret_cast<uint64_t>(s.data.address) == target_va
            && s.data.type == type) {
            slot_idx = i;
            break;
        }
    }

    eh::ept_hook_entry* entry = nullptr;
    bool entry_freshly_allocated = false;

    auto target_cr3 = effective_cr3_for_target(process, target_va);
    if (!target_cr3) {
        g_ghv->diag_install_last_fail = 1;
        s_install_lock = 0;
        return false;
    }
    bump_step(1 << 3);

    if (slot_idx < 0) {
        // First-time install: allocate slot + entry + trampoline, write stub.
        slot_idx = find_free_slot();
        if (slot_idx < 0) {
            g_ghv->diag_install_last_fail = 2;
            s_install_lock = 0;
            return false;
        }
        bump_step(1 << 4);

        uint32_t instr_size = 0;
        uint64_t next_va = 0;
        uint8_t old_bytes[20] = {};
        uint8_t next_old[20] = {};
        if (!disasm_target_host(target_va, target_cr3, instr_size, next_va,
                                 old_bytes, next_old)) {
            g_ghv->diag_install_last_fail = 3;
            s_install_lock = 0;
            return false;
        }
        g_ghv->diag_install_last_instr_size = instr_size;
        bump_step(1 << 5);

        entry = eh::eh_prepare_entry(process, target_va,
                                      /*full_zero=*/false,
                                      /*is_fake_page=*/false,
                                      &entry_freshly_allocated);
        if (!entry) {
            g_ghv->diag_install_last_fail = 4;
            s_install_lock = 0;
            return false;
        }
        bump_step(1 << 6);

        bool is_kernel = (target_va >= 0xFFFF800000000000ULL);
        g_ghv->diag_install_last_is_kernel = is_kernel ? 1 : 0;
        uint64_t tramp_va = 0, bp_rip = 0, target_resume = 0;
        if (!alloc_trampoline(target_va, old_bytes, instr_size, is_kernel,
                              tramp_va, bp_rip, target_resume)) {
            g_ghv->diag_install_last_fail = 5;
            g_ghv->diag_install_pool_user_slots   = g_ghv->tramp_pool.user_slot_count;
            g_ghv->diag_install_pool_kernel_slots = g_ghv->tramp_pool.kernel_slot_count;
            if (entry_freshly_allocated)
                eh::free_entry(entry);
            s_install_lock = 0;
            return false;
        }
        bump_step(1 << 7);

        auto fake_target_hva = eh::eh_get_fake_hva_for_entry(entry, target_va);

        auto& slot = g_vt_hook_table[slot_idx];
        memset(&slot.data, 0, sizeof(slot.data));
        slot.data.address           = reinterpret_cast<PVOID>(target_va);
        slot.data.nextAddress       = reinterpret_cast<PUCHAR>(next_va);
        memcpy(slot.data.oldByte,     old_bytes, sizeof(slot.data.oldByte));
        memcpy(slot.data.nextOldByte, next_old,  sizeof(slot.data.nextOldByte));
        slot.data.size              = instr_size;
        slot.data.process           = process;
        slot.data.blankMemory       = blank_mem;
        slot.data.fakeMemoryAddress = reinterpret_cast<uint64_t>(fake_target_hva);
        slot.data.type              = type;
        slot.data.dispatch_mode     = dispatch_mode;
        slot.data.filter_by_process = filter_by_process;
        slot.data.isEnable          = false;
        slot.fake_mem_hva           = fake_target_hva;
        slot.trampoline_va          = tramp_va;
        slot.bp_rip                 = bp_rip;
        slot.target_resume          = target_resume;
        slot.occupied               = true;

        if (auto_enable) {
            slot.data.isEnable = true;
            apply_enable_transition_hva(slot.fake_mem_hva);
            bump_step(1 << 8);
        }

        if (is_pmo) g_ghv->diag_pmo_target_pa = entry->orig_pfn << 12;
    } else {
        // Slot already exists 鈥 fetch the entry to install EPT for this vCPU.
        auto& s = g_vt_hook_table[slot_idx];
        auto va_page = (uint64_t)s.data.address & ~0xFFFull;
        auto& t = g_ghv->ept_hook_table;
        t.lock.acquire();
        entry = eh::find_entry_locked(target_cr3, va_page);
        t.lock.release();
        bump_step(1 << 11);   // idemp: shared init already done
    }

    // EPT install:
    //   from_ipi=true  (driver affinity-loop):  current vCPU installs OWN ept.
    //                                            Loop visits every CPU so all
    //                                            vCPUs end up with their own
    //                                            install via this same path.
    //   from_ipi=false (host vmexit handler):   current vCPU is the only one
    //                                            that will ever enter this
    //                                            function 鈥 so it must write
    //                                            EPT for ALL vCPUs from here.
    bump_step(1 << 9);
    if (from_ipi)
        eh::eh_install_self(cpu, entry);
    else
        eh::eh_install_all(cpu, entry);
    bump_step(1 << 10);

    if (is_pmo && self_idx_diag < 16 && g_ghv->diag_ieh_last_pte_addr)
        g_ghv->diag_pmo_pte_after[self_idx_diag] =
            *(volatile uint64_t*)g_ghv->diag_ieh_last_pte_addr;

    s_install_lock = 0;
    return true;
}

// Public wrapper for find_blank_host (still namespace vh) so it can be
// called from outside this TU. Used by Stage 鈶 kernel hook code path
// (game.cpp scans ntoskrnl with system_cr3=0).
uint64_t find_blank_host_public(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    return find_blank_host(start, max_scan, target_cr3);
}

// DEFERRED variant of install_host_impl: current vCPU does its OWN ept
// install immediately, all other vCPUs are enqueued. Each other vCPU drains
// the queue on its next vmexit and installs its own ept tree. No cross-vCPU
// EPT writes 鈥 eliminates the race where this vCPU writes another vCPU's
// ept while that vCPU is mid-instruction on the same page.
bool install_host_impl_deferred(vcpu* cpu, PEPROCESS process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable) {
    // Idempotency: if (target, type) already installed, just re-arm pending
    // for other vCPUs in case some haven't drained yet, and ensure THIS vCPU
    // has it installed too.
    for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
        auto& s = g_vt_hook_table[i];
        if (s.occupied && reinterpret_cast<uint64_t>(s.data.address) == target_va
            && s.data.type == type) {
            auto va_page = target_va & ~static_cast<uint64_t>(0xFFF);
            auto target_cr3 = effective_cr3_for_target(process, target_va);
            if (target_cr3) {
                auto& t = g_ghv->ept_hook_table;
                t.lock.acquire();
                auto entry = eh::find_entry_locked(target_cr3, va_page);
                t.lock.release();
                if (entry) eh::eh_install_all_deferred(cpu, entry);
            }
            return true;
        }
    }

    static volatile long s_install_lock = 0;
    while (_InterlockedCompareExchange(&s_install_lock, 1, 0) != 0)
        _mm_pause();

    auto target_cr3 = effective_cr3_for_target(process, target_va);
    if (!target_cr3) { s_install_lock = 0; return false; }

    int slot_idx = find_free_slot();
    if (slot_idx < 0) { s_install_lock = 0; return false; }

    uint32_t instr_size = 0;
    uint64_t next_va = 0;
    uint8_t old_bytes[20] = {};
    uint8_t next_old[20] = {};
    if (!disasm_target_host(target_va, target_cr3, instr_size, next_va,
                             old_bytes, next_old)) {
        s_install_lock = 0; return false;
    }

    bool entry_freshly_allocated = false;
    auto entry = eh::eh_prepare_entry(process, target_va, /*full_zero=*/false,
                                       /*is_fake_page=*/false,
                                       &entry_freshly_allocated);
    if (!entry) { s_install_lock = 0; return false; }

    bool is_kernel = (target_va >= 0xFFFF800000000000ULL);
    uint64_t tramp_va = 0, bp_rip = 0, target_resume = 0;
    if (!alloc_trampoline(target_va, old_bytes, instr_size, is_kernel,
                          tramp_va, bp_rip, target_resume)) {
        if (entry_freshly_allocated) eh::free_entry(entry);
        s_install_lock = 0; return false;
    }

    auto fake_target_hva = eh::eh_get_fake_hva_for_entry(entry, target_va);

    auto& slot = g_vt_hook_table[slot_idx];
    memset(&slot.data, 0, sizeof(slot.data));
    slot.data.address           = reinterpret_cast<PVOID>(target_va);
    slot.data.nextAddress       = reinterpret_cast<PUCHAR>(next_va);
    memcpy(slot.data.oldByte,     old_bytes, sizeof(slot.data.oldByte));
    memcpy(slot.data.nextOldByte, next_old,  sizeof(slot.data.nextOldByte));
    slot.data.size              = instr_size;
    slot.data.process           = process;
    slot.data.blankMemory       = blank_mem;
    slot.data.fakeMemoryAddress = reinterpret_cast<uint64_t>(fake_target_hva);
    slot.data.type              = type;
    slot.data.dispatch_mode     = dispatch_mode;
    slot.data.filter_by_process = filter_by_process;
    slot.data.isEnable          = false;
    slot.fake_mem_hva           = fake_target_hva;
    slot.trampoline_va          = tramp_va;
    slot.bp_rip                 = bp_rip;
    slot.target_resume          = target_resume;
    slot.occupied               = true;

    if (auto_enable) {
        slot.data.isEnable = true;
        apply_enable_transition_hva(slot.fake_mem_hva);
    }

    // Current vCPU installs OWN ept now; others deferred via vmexit drain.
    eh::eh_install_all_deferred(cpu, entry);

    s_install_lock = 0;
    return true;
}

// (install_host moved out of namespace vh to ensure external linkage from
//  game.cpp; see definition at end of file in namespace hv directly.)

}  // namespace vh

// install_host needs external linkage so game.cpp can call it. This is the
// HOST-HANDLER path (host vmexit handler running on a single vCPU) 鈥 it writes
// EPT for ALL vCPUs because there is no IPI rendezvous to dispatch per-vCPU.
bool vh_install_host(vcpu* cpu, void* process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable) {
    return vh::install_host_impl(cpu, reinterpret_cast<PEPROCESS>(process),
                                  target_va, blank_mem, type,
                                  dispatch_mode, filter_by_process, auto_enable,
                                  /*from_ipi=*/false);
}

// DEFERRED variant. Identical to vh_install_host except for the EPT phase:
// instead of writing every vCPU's ept tree synchronously (which races with
// guest threads mid-instruction on the same page), the calling vCPU installs
// only its OWN ept tree and enqueues the entry for the other vCPUs. Each
// other vCPU drains the queue on its next vmexit and installs its own ept.
//
// Use this from host vmexit handlers (e.g. PMO handler lazy-installing
// GetBuffer) where the target page is hot 鈥 i.e. some other vCPU is almost
// certainly executing inside the page right now.
bool vh_install_host_deferred(vcpu* cpu, void* process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable) {
    return vh::install_host_impl_deferred(cpu, reinterpret_cast<PEPROCESS>(process),
                                           target_va, blank_mem, type,
                                           dispatch_mode, filter_by_process,
                                           auto_enable);
}

// Public find_blank scanner. Pass cr3=0 to use system_cr3 (kernel scan).
uint64_t vh_find_blank_host(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    if (!target_cr3)
        target_cr3 = g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
    return vh::find_blank_host_public(start, max_scan, target_cr3);
}


namespace hc {

// (install_host moved to namespace vh above; vmcall_vh_install delegates to it.)

// args:
//   rcx = process
//   rdx = target_va
//   r8  = blank_mem_va
//   r9  = packed flags: bit0=auto_enable, bit1=filter_by_process; (type<<8); (dispatch_mode<<16)
void vmcall_vh_install(vcpu* const cpu) {
    auto process       = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto target_va     = cpu->ctx->rdx;
    auto blank_mem     = cpu->ctx->r8;
    auto packed        = cpu->ctx->r9;

    bool auto_enable        = (packed & 0x1) != 0;
    bool filter_by_process  = (packed & 0x2) != 0;
    uint8_t type            = static_cast<uint8_t>((packed >> 8) & 0xFF);
    uint8_t dispatch_mode   = static_cast<uint8_t>((packed >> 16) & 0xFF);

    g_ghv->dwm_install_target_va = target_va;
    g_ghv->dwm_install_status    = 0xFF;  // entered handler

    // IPI path: caller is the driver invoking via KeIpiGenericCall, so this
    // handler runs once per vCPU. install_host_impl with from_ipi=true does
    // CAS rendezvous and per-vCPU eh_install_self.
    bool ok = vh::install_host_impl(cpu, process, target_va, blank_mem, type,
                                     dispatch_mode, filter_by_process,
                                     auto_enable, /*from_ipi=*/true);

    g_ghv->dwm_install_status = ok ? 1 : 0x14;
    cpu->ctx->rax = ok ? 1 : 0;
    skip_instruction();
}

// args:
//   rcx = process
//   rdx = target_va
//   r8  = blank_mem_va
//   r9  = trample_addr_va
//   r10 = packed: bit0=auto_enable, bit1=filter_by_process; (type<<8)
//
// Writes RetAbs trampoline bytes via host-side eh_write for trample_addr.
// hook_fn pointer (where to jump on hit) and original_out pointer not supported in this
// minimal port; callers should reuse vmcall_vh_install + handler dispatch instead.
void vmcall_vh_install_ret_abs(vcpu* const cpu) {
    // Not used by current call paths after the host-side rewrite; expose as
    // a stub returning failure. dwm's existing usage maps onto vmcall_vh_install
    // with dispatch_mode = VMCALL_DISPATCH_RETABS.
    cpu->ctx->rax = 0;
    skip_instruction();
}

void vmcall_vh_enable(vcpu* const cpu) {
    auto target_va = cpu->ctx->rdx;
    int idx = vh::find_slot_by_address(target_va);
    if (idx < 0) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }
    auto& slot = g_vt_hook_table[idx];
    slot.data.isEnable = true;
    if (slot.fake_mem_hva)
        vh::apply_enable_transition_hva(slot.fake_mem_hva);

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_vh_disable(vcpu* const cpu) {
    auto target_va = cpu->ctx->rdx;
    int idx = vh::find_slot_by_address(target_va);
    if (idx < 0) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }
    g_vt_hook_table[idx].data.isEnable = false;
    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_vh_remove(vcpu* const cpu) {
    auto process   = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto target_va = cpu->ctx->rdx;
    auto cpu_bit = 1ULL << static_cast<uint32_t>(cpu - g_ghv->vcpus);

    int idx = vh::find_slot_by_address(target_va);
    if (idx < 0) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }
    auto& slot = g_vt_hook_table[idx];

    auto target_cr3 = vh::effective_cr3_for_target(slot.data.process, target_va);
    auto blank_mem  = slot.data.blankMemory;

    // Remove the EPT hooks via the same per-vcpu path eh_install used.
    auto& t = g_ghv->ept_hook_table;
    auto remove_one = [&](uint64_t va) {
        auto va_page = va & ~static_cast<uint64_t>(0xFFF);
        t.lock.acquire();
        auto e = eh::find_entry_locked(target_cr3, va_page);
        if (!e) { t.lock.release(); return; }
        bool was_active = (e->per_vcpu_active_bitmap & cpu_bit) != 0;
        if (was_active)
            e->per_vcpu_active_bitmap &= ~cpu_bit;
        auto orig_pfn = e->orig_pfn;
        bool free_now = (e->per_vcpu_active_bitmap == 0);
        if (free_now)
            eh::free_entry_locked(e);
        t.lock.release();

        if (was_active)
            remove_ept_hook(cpu->ept, orig_pfn);
    };
    if (target_cr3) {
        remove_one(target_va);
        // blank_mem no longer has an EPT hook (handled via #BP trap), nothing to remove.
    }

    // Clear the slot completely on the last cpu (we let every cpu clear it; harmless idempotent).
    memset(&slot, 0, sizeof(slot));

    (void)process;
    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_vh_uninit(vcpu* const cpu) {
    auto cpu_bit = 1ULL << static_cast<uint32_t>(cpu - g_ghv->vcpus);
    auto& t = g_ghv->ept_hook_table;

    // Last-vcpu detection: clear our bit in a per-uninit bitmap, the vcpu that
    // sees a 0 bitmap is the last one and gets to memset slots. Without this,
    // vcpu0 would memset the slot on its pass and vcpu1 would see occupied=0
    // and skip its own EPT removal -> stale hook on vcpu1's EPT -> dxgi
    // renders from fake page after unload -> black screen.
    static volatile uint64_t s_uninit_bitmap = 0;
    if (s_uninit_bitmap == 0) {
        // Initialize on first entry: set bit per active vcpu.
        // Done atomically 鈥 only one vcpu will CAS from 0 to the full mask.
        uint64_t expected = 0;
        uint64_t full = (g_ghv->vcpu_count >= 64) ? ~0ULL : ((1ULL << g_ghv->vcpu_count) - 1);
        _InterlockedCompareExchange64((volatile LONG64*)&s_uninit_bitmap,
            (LONG64)full, (LONG64)expected);
    }

    for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
        auto& slot = g_vt_hook_table[i];
        if (!slot.occupied)
            continue;

        uint64_t addrs[2] = {
            reinterpret_cast<uint64_t>(slot.data.address),
            slot.data.blankMemory
        };
        for (int k = 0; k < 2; k++) {
            if (!addrs[k]) continue;
            auto target_cr3 = vh::effective_cr3_for_target(slot.data.process, addrs[k]);
            if (!target_cr3) continue;
            auto va_page = addrs[k] & ~static_cast<uint64_t>(0xFFF);
            t.lock.acquire();
            auto e = eh::find_entry_locked(target_cr3, va_page);
            if (!e) { t.lock.release(); continue; }
            bool was_active = (e->per_vcpu_active_bitmap & cpu_bit) != 0;
            if (was_active)
                e->per_vcpu_active_bitmap &= ~cpu_bit;
            auto orig_pfn = e->orig_pfn;
            bool free_now = (e->per_vcpu_active_bitmap == 0);
            if (free_now)
                eh::free_entry_locked(e);
            t.lock.release();
            if (was_active)
                remove_ept_hook(cpu->ept, orig_pfn);
        }
    }

    // Clear my bit; if I was the last vcpu, free the slot table now.
    auto remaining = _InterlockedAnd64((volatile LONG64*)&s_uninit_bitmap,
        ~(LONG64)cpu_bit) & ~cpu_bit;
    if (remaining == 0) {
        for (int i = 0; i < VMCALL_HOOK_MAX; i++)
            memset(&g_vt_hook_table[i], 0, sizeof(g_vt_hook_table[i]));
    }

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_vh_find_blank(vcpu* const cpu) {
    auto process    = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto start_va   = cpu->ctx->rdx;
    auto max_scan   = cpu->ctx->r8;

    auto target_cr3 = vh::read_process_cr3_local(process);
    if (!target_cr3) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    cpu->ctx->rax = vh::find_blank_host(start_va, max_scan, target_cr3);
    skip_instruction();
}

// args:
//   rcx = process     (PsGetCurrentProcess on driver side; nullptr -> system)
//   rdx = start_va
//   r8  = max_scan
//
// Returns the page-aligned VA of a fully-0xCC 4KB page, or 0 if none.
void vmcall_vh_find_blank_page(vcpu* const cpu) {
    auto process  = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto start_va = cpu->ctx->rdx;
    auto max_scan = cpu->ctx->r8;

    auto target_cr3 = vh::read_process_cr3_local(process);
    if (!target_cr3) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }
    cpu->ctx->rax = vh::find_blank_page_host_public(start_va, max_scan, target_cr3);
    skip_instruction();
}

// args:
//   rcx = orig_pfn       (PFN of the ntdll/ntoskrnl page containing 0xCC runs)
//   rdx = exec_pfn       (PFN of the PoolManager-allocated exec page)
//   r8  = page_va        (guest VA of the page, page-aligned)
//   r9  = exec_hva       (host VA of the exec page; we copy original-page content into it)
//   r10 = is_kernel      (1 = kernel pool, 0 = user pool)
//
// Returns page_index >= 0 on success, -1 on failure. The host caller-side
// allocation already verified PFNs; we install the EPT hook and seed the
// exec_page with a copy of the original 4KB so non-trampoline bytes still
// read back as the legit module bytes.
void vmcall_vh_tramp_add_page(vcpu* const cpu) {
    auto orig_pfn  = cpu->ctx->rcx;
    auto exec_pfn  = cpu->ctx->rdx;
    auto page_va   = cpu->ctx->r8;
    auto exec_hva  = cpu->ctx->r9;
    bool is_kernel = cpu->ctx->r10 != 0;

    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();

    auto& count = is_kernel ? pool.kernel_page_count : pool.user_page_count;
    auto  pages = is_kernel ? pool.kernel_pages      : pool.user_pages;

    if (count >= TRAMPOLINE_MAX_PAGES_PER_POOL ||
        !orig_pfn || !exec_pfn || !page_va || !exec_hva) {
        pool.lock.release();
        cpu->ctx->rax = static_cast<uint64_t>(-1);
        skip_instruction();
        return;
    }

    // Seed exec_page with original page content so non-trampoline bytes still
    // appear as the legit module's bytes when guest executes them.
    void* orig_hva = host_physical_to_virtual(orig_pfn << 12);
    void* exec_dst = host_physical_to_virtual(exec_pfn << 12);
    if (!orig_hva || !exec_dst) {
        pool.lock.release();
        cpu->ctx->rax = static_cast<uint64_t>(-1);
        skip_instruction();
        return;
    }

    uint32_t idx = count++;
    pages[idx].guest_page_va = page_va;
    pages[idx].orig_pfn      = orig_pfn;
    pages[idx].exec_pfn      = exec_pfn;
    pages[idx].exec_hva      = exec_hva;
    pool.lock.release();

    memcpy(exec_dst, orig_hva, 0x1000);

    // EPT double-view on EVERY vCPU: install_ept_hook(is_fake_page=false)
    // clears execute_access on the original PTE (PFN unchanged). On guest
    // instruction-fetch a violation fires, handle_ept_violation swaps PFN
    // to exec_pfn (X=1, R=W=0). On guest read/write, violation swaps back
    // to orig_pfn (R=W=1, X=0). PG / anti-cheat reading ntoskrnl/ntdll
    // bytes always see the original 0xCC padding, never our oldByte+0xCC.
    uint32_t vcpu_count = g_ghv->vcpu_count;
    for (uint32_t v = 0; v < vcpu_count; v++) {
        install_ept_hook(g_ghv->vcpus[v].ept, orig_pfn, exec_pfn,
                         /*is_fake_page=*/false);
    }
    vmx_invept(invept_all_context, {});

    cpu->ctx->rax = idx;
    skip_instruction();
}

// args:
//   rcx = page_index   (returned by vmcall_vh_tramp_add_page)
//   rdx = page_offset  (byte offset within the page where the 0xCC run starts)
//   r8  = capacity     (length of the 0xCC run; must be >= 8)
//   r9  = is_kernel
//
// Returns 1 on success.
void vmcall_vh_tramp_add_slot(vcpu* const cpu) {
    auto page_index = static_cast<uint32_t>(cpu->ctx->rcx);
    auto page_off   = static_cast<uint32_t>(cpu->ctx->rdx);
    auto capacity   = static_cast<uint32_t>(cpu->ctx->r8);
    bool is_kernel  = cpu->ctx->r9 != 0;

    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();

    auto& slot_count = is_kernel ? pool.kernel_slot_count : pool.user_slot_count;
    auto  slots      = is_kernel ? pool.kernel_slots      : pool.user_slots;
    auto& page_count = is_kernel ? pool.kernel_page_count : pool.user_page_count;
    auto  max_slots  = is_kernel ? TRAMPOLINE_POOL_KERNEL_SLOTS : TRAMPOLINE_POOL_USER_SLOTS;

    if (slot_count >= max_slots || page_index >= page_count ||
        page_off >= 0x1000 || capacity < 8 || capacity > 255 ||
        page_off + capacity > 0x1000) {
        // Reject slots whose [page_off, page_off+capacity) would cross the
        // 4KB exec_page boundary. The driver-side bootstrap walks ntdll/
        // ntoskrnl padding runs and could in principle hand us a run that
        // straddles a page; alloc_trampoline can't write oldByte+0xCC over
        // a page boundary because exec_pages aren't physically contiguous.
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_tramp_slot_xpage_reject);
        pool.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    auto& s = slots[slot_count++];
    s.page_index    = static_cast<uint16_t>(page_index);
    s.page_offset   = static_cast<uint16_t>(page_off);
    s.capacity      = static_cast<uint8_t>(capacity);
    s.occupied      = false;
    s.tramp_va      = 0;
    s.bp_rip        = 0;
    s.target_resume = 0;
    pool.lock.release();

    cpu->ctx->rax = 1;
    skip_instruction();
}

// args:
//   rcx = is_kernel (1=kernel, 0=user)
//
// Flips the pool's _ready flag. EPT was already installed by add_page on
// every vCPU synchronously.
void vmcall_vh_tramp_set_ready(vcpu* const cpu) {
    bool is_kernel = cpu->ctx->rcx != 0;
    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();
    if (is_kernel) pool.kernel_ready = true;
    else           pool.user_ready   = true;
    pool.lock.release();

    cpu->ctx->rax = 1;
    skip_instruction();
}

}  // namespace hc

}  // namespace hv
