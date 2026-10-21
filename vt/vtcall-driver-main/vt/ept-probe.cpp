#include "ept-probe.h"

#include <intrin.h>

#include "debug-events.h"
#include "ept.h"
#include "exception-routines.h"
#include "hv.h"
#include "introspection.h"
#include "mm.h"
#include "vcpu.h"
#include "vmx.h"

#include "../sjz/coord_cache.h"

namespace hv {

#pragma code_seg(".vm")

static inline uint64_t page_align(uint64_t va) {
    return va & ~static_cast<uint64_t>(0xFFF);
}

static inline bool is_kernel_va(uint64_t va) {
    return va >= 0xFFFF800000000000ULL;
}

static inline uint32_t vcpu_index(vcpu* cpu) {
    return static_cast<uint32_t>(cpu - g_ghv->vcpus);
}

static inline float f32_from_low_u64(uint64_t value) {
    union {
        uint32_t u;
        float f;
    } v{};
    v.u = static_cast<uint32_t>(value & 0xFFFFFFFFull);
    return v.f;
}

static inline float f32_from_high_u64(uint64_t value) {
    union {
        uint32_t u;
        float f;
    } v{};
    v.u = static_cast<uint32_t>((value >> 32) & 0xFFFFFFFFull);
    return v.f;
}

static uint64_t normalize_target_cr3(uint64_t target_cr3,
                                     uint64_t target_va,
                                     uint64_t flags) {
    if ((flags & ept_probe_flag_kernel) || is_kernel_va(target_va))
        return g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);

    if (!target_cr3)
        target_cr3 = vmx_vmread(VMCS_GUEST_CR3);

    return target_cr3 & ~static_cast<uint64_t>(0xFFF);
}

static ept_probe_slot* find_slot_by_key_locked(uint64_t target_cr3,
                                               uint64_t target_page_va,
                                               uint64_t page_offset) {
    auto& t = g_ghv->probe_table;
    for (auto& s : t.slots) {
        if (s.active &&
            s.target_cr3 == target_cr3 &&
            s.target_page_va == target_page_va &&
            s.page_offset == page_offset) {
            return &s;
        }
    }
    return nullptr;
}

static ept_probe_slot* find_slot_by_pfn_locked(uint64_t orig_pfn,
                                               uint64_t page_offset) {
    auto& t = g_ghv->probe_table;
    for (auto& s : t.slots) {
        if (s.active &&
            s.orig_pfn == orig_pfn &&
            s.page_offset == page_offset) {
            return &s;
        }
    }
    return nullptr;
}

static ept_probe_slot* alloc_slot_locked() {
    auto& t = g_ghv->probe_table;
    for (auto& s : t.slots) {
        if (!s.active)
            return &s;
    }
    return nullptr;
}

static size_t copy_to_guest_current(void* dst_gva,
                                    const void* src_hva,
                                    size_t size) {
    auto dst = reinterpret_cast<uint8_t*>(dst_gva);
    auto src = reinterpret_cast<const uint8_t*>(src_hva);
    size_t copied = 0;

    while (copied < size) {
        size_t dst_remaining = 0;
        auto curr_dst = gva2hva(dst + copied, &dst_remaining);
        if (!curr_dst)
            break;

        auto curr_size = min(size - copied, dst_remaining);

        host_exception_info e;
        memcpy_safe(e, curr_dst, src + copied, curr_size);
        if (e.exception_occurred)
            break;

        copied += curr_size;
    }

    return copied;
}

void init_ept_probe_table() {
    auto& t = g_ghv->probe_table;
    memset(&t, 0, sizeof(t));
    t.lock.initialize();
    t.next_id = 1;
    t.next_seq = 1;

    for (uint32_t i = 0; i < ept_probe_slot_count; i++) {
        memset(t.shadow_pages[i], 0xCC, 0x1000);
        t.shadow_pfns[i] =
            static_cast<uint64_t>(MmGetPhysicalAddress(&t.shadow_pages[i][0]).QuadPart) >> 12;
    }
}

uint64_t ept_probe_install_current(vcpu* cpu, uint64_t target_cr3,
                                   uint64_t target_va, uint64_t flags,
                                   uint64_t hit_limit) {
    if (!cpu || !target_va)
        return 0;

    auto const target_page_va = page_align(target_va);
    auto const page_offset = target_va & 0xFFFULL;
    auto const normalized_cr3 = normalize_target_cr3(target_cr3, target_va, flags);
    if (!normalized_cr3)
        return 0;

    cr3 c{};
    c.flags = normalized_cr3;

    bool fresh = false;
    uint64_t id = 0;
    uint64_t orig_pfn = 0;
    uint64_t shadow_pfn = 0;

    {
        scoped_spin_lock lock(g_ghv->probe_table.lock);

        auto slot = find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
        if (!slot) {
            size_t page_left = 0;
            auto orig_gpa = gva2gpa(c, reinterpret_cast<void*>(target_page_va), &page_left);
            if (!orig_gpa)
                return 0;

            auto source = gva2hva(c, reinterpret_cast<void*>(target_page_va), &page_left);
            if (!source || page_left < 0x1000)
                return 0;

            slot = alloc_slot_locked();
            if (!slot)
                return 0;

            auto idx = static_cast<uint32_t>(slot - g_ghv->probe_table.slots);
            auto shadow = g_ghv->probe_table.shadow_pages[idx];
            memcpy(shadow, source, 0x1000);

            // Avoid recursive #BP loops if the original byte is already INT3.
            if (shadow[page_offset] == 0xCC)
                return 0;

            shadow[page_offset] = 0xCC;

            memset(slot, 0, sizeof(*slot));
            slot->id = g_ghv->probe_table.next_id++;
            if (!slot->id)
                slot->id = g_ghv->probe_table.next_id++;
            slot->target_va = target_va;
            slot->target_page_va = target_page_va;
            slot->target_cr3 = normalized_cr3;
            slot->orig_pfn = orig_gpa >> 12;
            slot->shadow_pfn = g_ghv->probe_table.shadow_pfns[idx];
            slot->page_offset = page_offset;
            slot->hit_limit = hit_limit;
            slot->is_kernel = ((flags & ept_probe_flag_kernel) != 0) || is_kernel_va(target_va);
            slot->active = true;
            fresh = true;
        }

        id = slot->id;
        orig_pfn = slot->orig_pfn;
        shadow_pfn = slot->shadow_pfn;
    }

    auto const self_idx = vcpu_index(cpu);
    auto const self_bit = (self_idx < 64) ? (1ULL << self_idx) : 0;
    if (!self_bit)
        return 0;

    // Do not stack this generic probe on top of an existing EPT hook page.
    // Reusing our own shadow page is OK; any other exec_pfn is a conflict.
    auto existing = find_ept_hook(cpu->ept, orig_pfn);
    if (existing) {
        if (existing->exec_pfn != static_cast<uint32_t>(shadow_pfn)) {
            if (fresh) {
                scoped_spin_lock lock(g_ghv->probe_table.lock);
                auto slot = find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
                if (slot && slot->id == id && slot->active_bitmap == 0)
                    memset(slot, 0, sizeof(*slot));
            }
            return 0;
        }
    } else {
        if (!install_ept_hook(cpu->ept, orig_pfn, shadow_pfn, false)) {
            if (fresh) {
                scoped_spin_lock lock(g_ghv->probe_table.lock);
                auto slot = find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
                if (slot && slot->id == id && slot->active_bitmap == 0)
                    memset(slot, 0, sizeof(*slot));
            }
            return 0;
        }
    }

    {
        scoped_spin_lock lock(g_ghv->probe_table.lock);
        auto slot = find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
        if (slot && slot->id == id)
            slot->active_bitmap |= self_bit;
    }

    vmx_invept(invept_all_context, {});
    return id;
}

uint64_t ept_probe_remove_current(vcpu* cpu, uint64_t target_cr3,
                                  uint64_t target_va, uint64_t flags) {
    if (!cpu || !target_va)
        return 0;

    auto const target_page_va = page_align(target_va);
    auto const page_offset = target_va & 0xFFFULL;
    auto const normalized_cr3 = normalize_target_cr3(target_cr3, target_va, flags);
    if (!normalized_cr3)
        return 0;

    auto const self_idx = vcpu_index(cpu);
    auto const self_bit = (self_idx < 64) ? (1ULL << self_idx) : 0;
    if (!self_bit)
        return 0;

    uint64_t id = 0;
    uint64_t orig_pfn = 0;
    bool need_remove = false;

    {
        scoped_spin_lock lock(g_ghv->probe_table.lock);
        auto slot = find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
        if (!slot)
            return 0;

        id = slot->id;
        orig_pfn = slot->orig_pfn;
        need_remove = (slot->active_bitmap & self_bit) != 0;
        slot->active_bitmap &= ~self_bit;

        if (slot->active_bitmap == 0)
            memset(slot, 0, sizeof(*slot));
    }

    if (need_remove) {
        remove_ept_hook(cpu->ept, orig_pfn);
        if (cpu->ept.probe_mtf.active &&
            cpu->ept.probe_mtf.orig_pfn == orig_pfn) {
            memset(&cpu->ept.probe_mtf, 0, sizeof(cpu->ept.probe_mtf));
        }
        vmx_invept(invept_all_context, {});
    }

    return need_remove ? id : 0;
}

static uint32_t probe_vcpu_index(vcpu* cpu) {
    if (!cpu || !g_ghv->vcpus)
        return 64;
    return static_cast<uint32_t>(cpu - g_ghv->vcpus);
}

uint64_t ept_probe_install_all(vcpu* current_cpu, uint64_t target_cr3,
                               uint64_t target_va, uint64_t flags,
                               uint64_t hit_limit,
                               uint64_t* installed_mask) {
    if (installed_mask)
        *installed_mask = 0;
    if (!current_cpu || !g_ghv->vcpus || !target_va)
        return 0;

    const uint32_t count = g_ghv->vcpu_count;
    if (!count)
        return 0;

    uint64_t id = 0;
    uint64_t mask = 0;
    const uint32_t capped = (count > 64) ? 64 : count;

    // Install into every vCPU's private EPT tree.  ept_probe_install_current()
    // is idempotent: an already-installed probe returns the existing id and
    // only refreshes the active bitmap for that vCPU.
    for (uint32_t i = 0; i < capped; i++) {
        auto* cpu = &g_ghv->vcpus[i];
        const uint64_t one_id =
            ept_probe_install_current(cpu, target_cr3, target_va, flags, hit_limit);
        if (!one_id)
            continue;
        if (!id)
            id = one_id;
        mask |= (1ULL << i);
    }

    if (installed_mask)
        *installed_mask = mask;

    // We directly touched other vCPU EPT trees from this root-mode handler.
    // Ask those CPUs to INVEPT lazily on their next VM-exit; no IPI/NT call.
    const uint32_t self = probe_vcpu_index(current_cpu);
    if (self < 64) {
        const uint64_t others = mask & ~(1ULL << self);
        if (others)
            _InterlockedOr64((volatile LONG64*)&g_ghv->pending_ept_invept_bitmap,
                             (LONG64)others);
    }

    return id;
}

uint64_t ept_probe_remove_all(vcpu* current_cpu, uint64_t target_cr3,
                              uint64_t target_va, uint64_t flags,
                              uint64_t* removed_mask) {
    if (removed_mask)
        *removed_mask = 0;
    if (!current_cpu || !g_ghv->vcpus || !target_va)
        return 0;

    const uint32_t count = g_ghv->vcpu_count;
    if (!count)
        return 0;

    uint64_t id = 0;
    uint64_t mask = 0;
    const uint32_t capped = (count > 64) ? 64 : count;

    for (uint32_t i = 0; i < capped; i++) {
        auto* cpu = &g_ghv->vcpus[i];
        const uint64_t one_id =
            ept_probe_remove_current(cpu, target_cr3, target_va, flags);
        if (!one_id)
            continue;
        if (!id)
            id = one_id;
        mask |= (1ULL << i);
    }

    if (removed_mask)
        *removed_mask = mask;

    const uint32_t self = probe_vcpu_index(current_cpu);
    if (self < 64) {
        const uint64_t others = mask & ~(1ULL << self);
        if (others)
            _InterlockedOr64((volatile LONG64*)&g_ghv->pending_ept_invept_bitmap,
                             (LONG64)others);
    }

    return id;
}

uint64_t ept_probe_copy_hits(vcpu* /*cpu*/, uint64_t out_gva,
                             uint64_t max_hits, bool clear_after) {
    if (!out_gva || !max_hits)
        return 0;

    if (max_hits > ept_probe_hit_count)
        max_hits = ept_probe_hit_count;

    uint64_t copied = 0;
    scoped_spin_lock lock(g_ghv->probe_table.lock);
    auto& t = g_ghv->probe_table;

    auto count = static_cast<uint64_t>(t.hit_count);
    if (count > max_hits)
        count = max_hits;

    auto oldest = (t.hit_write + ept_probe_hit_count - t.hit_count) % ept_probe_hit_count;
    for (uint64_t i = 0; i < count; i++) {
        auto idx = (oldest + static_cast<uint32_t>(i)) % ept_probe_hit_count;
        auto dst = reinterpret_cast<void*>(
            out_gva + i * sizeof(ept_probe_hit));
        if (copy_to_guest_current(dst, &t.hits[idx], sizeof(ept_probe_hit)) != sizeof(ept_probe_hit))
            break;
        copied++;
    }

    if (clear_after) {
        t.hit_write = 0;
        t.hit_count = 0;
    }

    return copied;
}

uint64_t ept_probe_clear_hits() {
    scoped_spin_lock lock(g_ghv->probe_table.lock);
    auto old = g_ghv->probe_table.hit_count;
    g_ghv->probe_table.hit_write = 0;
    g_ghv->probe_table.hit_count = 0;
    return old;
}

static void fill_hit(ept_probe_hit& h, vcpu* cpu,
                     const ept_probe_slot& slot,
                     uint64_t target_rip,
                     uint64_t bp_rip,
                     uint64_t guest_cr3) {
    memset(&h, 0, sizeof(h));

    h.probe_id = slot.id;
    h.target_va = slot.target_va;
    h.rip = target_rip;
    h.bp_rip = bp_rip;
    h.rsp = vmx_vmread(VMCS_GUEST_RSP);
    h.rflags = vmx_vmread(VMCS_GUEST_RFLAGS);
    h.cr3 = guest_cr3;
    h.process = reinterpret_cast<uint64_t>(current_guest_eprocess());
    h.thread  = reinterpret_cast<uint64_t>(current_guest_ethread());
    h.pid = current_guest_pid();
    h.cpu_index = vcpu_index(cpu);

    auto ctx = cpu->ctx;
    h.rax = ctx->rax;
    h.rbx = ctx->rbx;
    h.rcx = ctx->rcx;
    h.rdx = ctx->rdx;
    h.rsi = ctx->rsi;
    h.rdi = ctx->rdi;
    h.rbp = ctx->rbp;
    h.r8  = ctx->r8;
    h.r9  = ctx->r9;
    h.r10 = ctx->r10;
    h.r11 = ctx->r11;
    h.r12 = ctx->r12;
    h.r13 = ctx->r13;
    h.r14 = ctx->r14;
    h.r15 = ctx->r15;

    cr3 c{};
    c.flags = guest_cr3 & ~static_cast<uint64_t>(0xFFF);
    read_guest_virtual_memory(c, reinterpret_cast<void*>(h.rsp),
                              h.stack, sizeof(h.stack));

    //
    // CTF/debug aid: keep the ABI and vtcall.exe output format unchanged, but
    // also capture the transient buffers that are usually gone by the time the
    // host polls probehits.  We preserve stack[0..7] (return/caller context)
    // and reuse stack[8..15] for pointed-to memory snapshots:
    //
    //   stack[8..9]   = 16 bytes at RSI
    //   stack[10..11] = 16 bytes at RCX
    //   stack[12..13] = 16 bytes at RDX
    //   stack[14..15] = 16 bytes at R13
    //
    // For the coordinate decrypt return site, RSI is the output buffer, so
    // probehits will print the decrypted x/y/z bits directly in stack[8..9].
    //
    read_guest_virtual_memory(c, reinterpret_cast<void*>(h.rsi),
                              &h.stack[8], 2 * sizeof(uint64_t));
    read_guest_virtual_memory(c, reinterpret_cast<void*>(h.rcx),
                              &h.stack[10], 2 * sizeof(uint64_t));
    read_guest_virtual_memory(c, reinterpret_cast<void*>(h.rdx),
                              &h.stack[12], 2 * sizeof(uint64_t));
    read_guest_virtual_memory(c, reinterpret_cast<void*>(h.r13),
                              &h.stack[14], 2 * sizeof(uint64_t));
}

static bool reserve_hit_record(const ept_probe_slot& slot, uint64_t& seq) {
    scoped_spin_lock lock(g_ghv->probe_table.lock);
    auto live = find_slot_by_pfn_locked(slot.orig_pfn, slot.page_offset);
    if (!live || live->id != slot.id)
        return false;

    auto new_count = ++live->hit_count;
    if (live->hit_limit && new_count > live->hit_limit)
        return false;

    seq = g_ghv->probe_table.next_seq++;
    if (!seq)
        seq = g_ghv->probe_table.next_seq++;
    return true;
}

static void record_hit(vcpu* cpu, const ept_probe_slot& slot,
                       uint64_t target_rip, uint64_t bp_rip,
                       uint64_t guest_cr3) {
    uint64_t seq = 0;
    if (!reserve_hit_record(slot, seq))
        return;

    ept_probe_hit hit{};
    fill_hit(hit, cpu, slot, target_rip, bp_rip, guest_cr3);
    hit.seq = seq;

    dbg_event ev{};
    ev.tsc = __rdtsc();
    ev.cpu = static_cast<uint32_t>(hit.cpu_index);
    ev.type = dbg_evt_exec;
    ev.size = sizeof(ev);
    ev.watch_id = hit.probe_id;
    ev.cr3 = hit.cr3;
    ev.rip = hit.rip;
    ev.rsp = hit.rsp;
    ev.gla = hit.target_va;
    ev.gpa = (slot.orig_pfn << 12) + slot.page_offset;
    ev.rax = hit.rax;
    ev.rcx = hit.rcx;
    ev.rdx = hit.rdx;
    ev.r8 = hit.r8;
    ev.r9 = hit.r9;
    auto sample_size = sizeof(ev.sample);
    auto page_left = static_cast<size_t>(0x1000 - slot.page_offset);
    if (sample_size > page_left)
        sample_size = page_left;
    read_guest_physical_memory(ev.gpa, ev.sample, sample_size);
    dbg_event_push(&ev);

    if (slot.target_va == sjz::kCoordProbeDecryptRet) {
        sjz::CoordProbeHitSubmit coord{};
        coord.seq = hit.seq;
        coord.targetVa = hit.target_va;
        coord.rip = hit.rip;
        coord.cr3 = hit.cr3;
        coord.pid = hit.pid;
        coord.rsp = hit.rsp;
        coord.rsi = hit.rsi;
        coord.r12 = hit.r12;
        coord.r13 = hit.r13;
        coord.r15 = hit.r15;
        coord.stack0 = hit.stack[0];
        coord.stack4 = hit.stack[4];
        coord.stack5 = hit.stack[5];
        coord.stack6 = hit.stack[6];
        coord.pos.x = f32_from_low_u64(hit.stack[8]);
        coord.pos.y = f32_from_high_u64(hit.stack[8]);
        coord.pos.z = f32_from_low_u64(hit.stack[9]);
        sjz::SubmitCoordProbeHit(coord);
    }

    scoped_spin_lock lock(g_ghv->probe_table.lock);
    auto live = find_slot_by_pfn_locked(slot.orig_pfn, slot.page_offset);
    if (!live || live->id != slot.id)
        return;

    auto& t = g_ghv->probe_table;
    auto idx = t.hit_write++ % ept_probe_hit_count;
    t.hits[idx] = hit;
    if (t.hit_count < ept_probe_hit_count)
        t.hit_count++;
}

bool try_handle_ept_probe_bp(vcpu* cpu) {
    if (!cpu)
        return false;

    auto const bp_rip = vmx_vmread(VMCS_GUEST_RIP);
    auto const guest_cr3 = vmx_vmread(VMCS_GUEST_CR3) & ~static_cast<uint64_t>(0xFFF);
    auto const self_idx = vcpu_index(cpu);
    auto const self_bit = (self_idx < 64) ? (1ULL << self_idx) : 0;
    if (!self_bit)
        return false;

    // Project diagnostics for the existing trampoline path show #BP exits
    // with GUEST_RIP at the INT3 byte.  Keep rip-1 as a compatibility
    // fallback for environments that report the post-INT3 address.
    uint64_t candidates[2] = { bp_rip, bp_rip ? bp_rip - 1 : 0 };

    for (uint32_t i = 0; i < 2; i++) {
        auto target_rip = candidates[i];
        if (!target_rip)
            continue;

        auto target_page_va = page_align(target_rip);
        auto page_offset = target_rip & 0xFFFULL;

        cr3 c{};
        c.flags = guest_cr3;
        auto gpa = gva2gpa(c, reinterpret_cast<void*>(target_page_va));
        if (!gpa && is_kernel_va(target_rip)) {
            c.flags = g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
            gpa = gva2gpa(c, reinterpret_cast<void*>(target_page_va));
        }
        if (!gpa)
            continue;

        ept_probe_slot snapshot{};
        {
            scoped_spin_lock lock(g_ghv->probe_table.lock);
            auto slot = find_slot_by_pfn_locked(gpa >> 12, page_offset);
            if (!slot || !(slot->active_bitmap & self_bit))
                continue;
            snapshot = *slot;
        }

        // The EPT hook is PFN-based.  If the same physical page is reachable
        // through a real/fake CR3 alias, still record it and include the
        // observed CR3/PID in the hit so host-side filtering can decide.
        record_hit(cpu, snapshot, target_rip, bp_rip, guest_cr3);

        auto pte = get_ept_pte(cpu->ept, snapshot.orig_pfn << 12, false);
        if (!pte)
            return false;

        pte->read_access = 1;
        pte->write_access = 1;
        pte->execute_access = 1;
        pte->page_frame_number = snapshot.orig_pfn;

        cpu->ept.probe_mtf.active = true;
        cpu->ept.probe_mtf.pte = pte;
        cpu->ept.probe_mtf.orig_pfn = snapshot.orig_pfn;
        cpu->ept.probe_mtf.shadow_pfn = snapshot.shadow_pfn;
        cpu->ept.probe_mtf.slot_id = snapshot.id;

        vmx_vmwrite(VMCS_GUEST_RIP, target_rip);
        enable_monitor_trap_flag();
        vmx_invept(invept_all_context, {});
        return true;
    }

    return false;
}

bool handle_ept_probe_mtf(vcpu* cpu) {
    if (!cpu || !cpu->ept.probe_mtf.active)
        return false;

    auto& s = cpu->ept.probe_mtf;
    if (s.pte) {
        s.pte->read_access = 0;
        s.pte->write_access = 0;
        s.pte->execute_access = 1;
        s.pte->page_frame_number = s.shadow_pfn;
        vmx_invept(invept_all_context, {});
    }

    memset(&s, 0, sizeof(s));
    return true;
}

} // namespace hv
