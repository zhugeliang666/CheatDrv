#include "debug-watch.h"

#include <intrin.h>

#include "debug-memory.h"
#include "exception-routines.h"
#include "hv.h"
#include "mm.h"
#include "vcpu.h"
#include "vmx.h"

namespace hv {

#pragma code_seg(".vm")

static uint64_t dbg_page_align(uint64_t va) {
    return va & ~0xfffull;
}

static bool dbg_is_kernel_va(uint64_t va) {
    return va >= 0xffff800000000000ull;
}

static uint32_t dbg_vcpu_index(vcpu* cpu) {
    return cpu ? static_cast<uint32_t>(cpu - g_ghv->vcpus) : 0;
}

static uint64_t dbg_normalize_watch_cr3(uint64_t cr3_value,
                                        uint64_t va,
                                        uint32_t flags) {
    if ((flags & dbg_watch_flag_kernel) || dbg_is_kernel_va(va))
        return g_ghv->system_cr3.flags & ~0xfffull;
    if (!cr3_value)
        cr3_value = vmx_vmread(VMCS_GUEST_CR3);
    return cr3_value & ~0xfffull;
}

static dbg_watch* dbg_find_watch_locked(uint64_t id) {
    if (!id)
        return nullptr;
    for (auto& w : g_ghv->dbg_watch.watches) {
        if (w.active && w.id == id)
            return &w;
    }
    return nullptr;
}

static dbg_watch_page* dbg_find_page_locked(uint64_t gpa_page) {
    for (auto& p : g_ghv->dbg_watch.pages) {
        if (p.active && p.gpa_page == gpa_page)
            return &p;
    }
    return nullptr;
}

static dbg_watch_page* dbg_find_page_by_id_locked(uint64_t id) {
    if (!id)
        return nullptr;
    for (auto& p : g_ghv->dbg_watch.pages) {
        if (p.active && p.id == id)
            return &p;
    }
    return nullptr;
}

static dbg_watch* dbg_alloc_watch_locked() {
    for (auto& w : g_ghv->dbg_watch.watches) {
        if (!w.active)
            return &w;
    }
    return nullptr;
}

static dbg_watch_page* dbg_alloc_page_locked() {
    for (auto& p : g_ghv->dbg_watch.pages) {
        if (!p.active)
            return &p;
    }
    return nullptr;
}

static uint32_t dbg_free_page_slots_locked() {
    uint32_t count = 0;
    for (auto const& p : g_ghv->dbg_watch.pages) {
        if (!p.active)
            ++count;
    }
    return count;
}

static void dbg_disable_watch_locked(dbg_watch& w) {
    if (!w.active)
        return;
    w.active = false;
    if (g_ghv->dbg_watch.active_watches)
        --g_ghv->dbg_watch.active_watches;
}

static bool dbg_watch_rate_exceeded_locked(dbg_watch& w, uint64_t now_tsc) {
    if (!w.max_events_per_sec)
        return false;

    if (!w.rate_window_start_tsc ||
        now_tsc - w.rate_window_start_tsc >= dbg_watch_rate_window_tsc) {
        w.rate_window_start_tsc = now_tsc;
        w.rate_window_events = 0;
    }

    if (w.rate_window_events != 0xffffffffu)
        ++w.rate_window_events;
    return w.rate_window_events > w.max_events_per_sec;
}

static bool dbg_watch_has_page(const dbg_watch& w, uint64_t gpa_page) {
    for (uint32_t i = 0; i < w.page_count && i < dbg_watch_max_pages_per_watch; ++i) {
        if (w.gpa_pages[i] == gpa_page)
            return true;
    }
    return false;
}

static void dbg_calc_trap_perms(const dbg_watch_page& p,
                                uint8_t& r, uint8_t& w, uint8_t& x) {
    r = p.orig_r;
    w = p.orig_w;
    x = p.orig_x;

    if (p.trap_mask & dbg_watch_exec)
        x = 0;
    if (p.trap_mask & dbg_watch_write)
        w = 0;
    if (p.trap_mask & dbg_watch_read) {
        r = 0;
        w = 0;
    }
    if (w && !r)
        w = 0;
}

static void dbg_recompute_page_locked(dbg_watch_page& p) {
    uint32_t trap = 0;
    uint32_t refs = 0;
    for (auto const& w : g_ghv->dbg_watch.watches) {
        if (!w.active)
            continue;
        if (!dbg_watch_has_page(w, p.gpa_page))
            continue;
        trap |= w.type_mask;
        ++refs;
    }
    p.trap_mask = trap;
    p.ref_count = refs;
}

static bool dbg_apply_page_to_cpu(vcpu* cpu, const dbg_watch_page& p) {
    if (!cpu)
        return false;
    auto pte = get_ept_pte(cpu->ept, p.gpa_page << 12, true);
    if (!pte)
        return false;

    uint8_t r = 0, w = 0, x = 0;
    if (p.active && p.ref_count && p.trap_mask) {
        dbg_calc_trap_perms(p, r, w, x);
    } else {
        r = p.orig_r;
        w = p.orig_w;
        x = p.orig_x;
    }

    pte->read_access = r;
    pte->write_access = w;
    pte->execute_access = x;
    if (pte->write_access && !pte->read_access)
        pte->write_access = 0;
    return true;
}

static bool dbg_apply_page_all_locked(dbg_watch_page& p) {
    bool ok = true;
    for (unsigned long i = 0; i < g_ghv->vcpu_count; ++i) {
        if (!dbg_apply_page_to_cpu(&g_ghv->vcpus[i], p))
            ok = false;
    }
    vmx_invept(invept_all_context, {});
    return ok;
}

static bool dbg_page_supports_watch_type(const dbg_watch_page& p,
                                         uint32_t type_mask) {
    if ((type_mask & dbg_watch_exec) && !p.orig_x)
        return false;
    if ((type_mask & dbg_watch_read) && !p.orig_r)
        return false;
    if ((type_mask & dbg_watch_write) && !p.orig_w)
        return false;
    return true;
}

static bool dbg_preflight_page_all(uint64_t gpa_page) {
    for (unsigned long i = 0; i < g_ghv->vcpu_count; ++i) {
        auto& cpu = g_ghv->vcpus[i];
        if (find_ept_hook(cpu.ept, gpa_page))
            return false;
        if (!get_ept_pte(cpu.ept, gpa_page << 12, true))
            return false;
    }
    return true;
}

static bool dbg_collect_gpa_pages(uint64_t cr3_value,
                                  uint64_t va,
                                  uint64_t size,
                                  uint64_t* pages,
                                  uint32_t* page_count) {
    if (!pages || !page_count || !size)
        return false;

    uint64_t const end = va + size;
    if (end <= va)
        return false;

    uint32_t count = 0;
    for (uint64_t page_va = dbg_page_align(va); page_va < end; page_va += 0x1000) {
        if (count >= dbg_watch_max_pages_per_watch)
            return false;

        dbg_pte_info info{};
        if (dbg_translate_va_ex(cr3_value, page_va, &info) != dbg_page_ok)
            return false;

        auto const gpa_page = info.gpa >> 12;
        bool seen = false;
        for (uint32_t i = 0; i < count; ++i) {
            if (pages[i] == gpa_page) {
                seen = true;
                break;
            }
        }
        if (!seen)
            pages[count++] = gpa_page;
    }

    *page_count = count;
    return count != 0;
}

void dbg_watch_init() {
    auto& s = g_ghv->dbg_watch;
    RtlZeroMemory(&s, sizeof(s));
    s.lock.initialize();
    s.next_watch_id = 1;
    s.next_page_id = 1;
}

void dbg_watch_uninit() {
    auto& s = g_ghv->dbg_watch;
    scoped_spin_lock guard(s.lock);
    for (auto& p : s.pages) {
        if (!p.active)
            continue;
        p.trap_mask = 0;
        p.ref_count = 0;
        dbg_apply_page_all_locked(p);
        RtlZeroMemory(&p, sizeof(p));
    }
    for (auto& w : s.watches)
        RtlZeroMemory(&w, sizeof(w));
    s.active_watches = 0;
    s.active_pages = 0;
}

static uint32_t dbg_remove_watch_locked(dbg_watch* w) {
    if (!w || !w->active)
        return 0;

    uint64_t pages[dbg_watch_max_pages_per_watch] = {};
    uint32_t const page_count = w->page_count;
    for (uint32_t i = 0; i < page_count && i < dbg_watch_max_pages_per_watch; ++i)
        pages[i] = w->gpa_pages[i];

    RtlZeroMemory(w, sizeof(*w));
    if (g_ghv->dbg_watch.active_watches)
        --g_ghv->dbg_watch.active_watches;

    uint32_t restored = 0;
    for (uint32_t i = 0; i < page_count && i < dbg_watch_max_pages_per_watch; ++i) {
        auto p = dbg_find_page_locked(pages[i]);
        if (!p)
            continue;
        dbg_recompute_page_locked(*p);
        if (!p->ref_count) {
            p->trap_mask = 0;
            dbg_apply_page_all_locked(*p);
            RtlZeroMemory(p, sizeof(*p));
            if (g_ghv->dbg_watch.active_pages)
                --g_ghv->dbg_watch.active_pages;
            ++restored;
        } else {
            dbg_apply_page_all_locked(*p);
        }
    }

    ++g_ghv->dbg_watch.remove_count;
    return restored;
}

uint32_t dbg_watch_remove_by_session(uint64_t session) {
    if (!session)
        return 0;

    uint64_t ids[dbg_watch_capacity] = {};
    uint32_t count = 0;
    {
        scoped_spin_lock guard(g_ghv->dbg_watch.lock);
        for (auto const& w : g_ghv->dbg_watch.watches) {
            if (w.active && w.session == session && count < dbg_watch_capacity)
                ids[count++] = w.id;
        }
        for (uint32_t i = 0; i < count; ++i)
            dbg_remove_watch_locked(dbg_find_watch_locked(ids[i]));
    }
    return count;
}

static uint32_t dbg_access_mask(vmx_exit_qualification_ept_violation q) {
    uint32_t mask = 0;
    if (q.execute_access)
        mask |= dbg_watch_exec;
    if (q.read_access)
        mask |= dbg_watch_read;
    if (q.write_access)
        mask |= dbg_watch_write;
    return mask;
}

static uint16_t dbg_event_type_from_access(uint32_t access_mask) {
    if (access_mask & dbg_watch_exec)
        return dbg_evt_exec;
    if (access_mask & dbg_watch_write)
        return dbg_evt_write;
    if (access_mask & dbg_watch_read)
        return dbg_evt_read;
    return dbg_evt_none;
}

static void dbg_fill_watch_event(dbg_event& ev,
                                 vcpu* cpu,
                                 const dbg_watch& w,
                                 uint16_t type,
                                 uint64_t guest_cr3,
                                 uint64_t guest_rip,
                                 uint64_t gla,
                                 uint64_t gpa,
                                 uint64_t qualification) {
    RtlZeroMemory(&ev, sizeof(ev));
    ev.tsc = __rdtsc();
    ev.cpu = dbg_vcpu_index(cpu);
    ev.type = type;
    ev.size = sizeof(ev);
    ev.session = w.session;
    ev.watch_id = w.id;
    ev.cr3 = guest_cr3;
    ev.rip = guest_rip;
    ev.rsp = vmx_vmread(VMCS_GUEST_RSP);
    ev.gla = gla;
    ev.gpa = gpa;
    ev.qualification = qualification;

    if (cpu && cpu->ctx) {
        ev.rax = cpu->ctx->rax;
        ev.rcx = cpu->ctx->rcx;
        ev.rdx = cpu->ctx->rdx;
        ev.r8 = cpu->ctx->r8;
        ev.r9 = cpu->ctx->r9;
    }

    auto sample_size = sizeof(ev.sample);
    auto page_left = static_cast<size_t>(0x1000 - (gpa & 0xfffull));
    if (sample_size > page_left)
        sample_size = page_left;
    read_guest_physical_memory(gpa, ev.sample, sample_size);
}

bool dbg_try_handle_ept_violation(vcpu* cpu,
                                  vmx_exit_qualification_ept_violation qualification,
                                  uint64_t physical_address,
                                  uint64_t virtual_address,
                                  uint64_t guest_rip) {
    if (!cpu)
        return false;

    auto const gpa_page = physical_address >> 12;
    auto const access = dbg_access_mask(qualification);
    auto const guest_cr3 = vmx_vmread(VMCS_GUEST_CR3) & ~0xfffull;

    dbg_event pending_events[dbg_watch_max_events_per_violation] = {};
    uint32_t pending_count = 0;
    dbg_watch_page page_snapshot{};
    bool handled = false;
    bool need_mtf = false;

    {
        scoped_spin_lock guard(g_ghv->dbg_watch.lock);
        auto page = dbg_find_page_locked(gpa_page);
        if (!page) {
            ++g_ghv->dbg_watch.miss_count;
            return false;
        }

        handled = true;
        ++g_ghv->dbg_watch.violation_count;

        for (auto& w : g_ghv->dbg_watch.watches) {
            if (!w.active)
                continue;
            if (!dbg_watch_has_page(w, gpa_page))
                continue;
            if (!(w.flags & dbg_watch_flag_kernel) && w.cr3 && w.cr3 != guest_cr3)
                continue;
            if (w.rip_filter_start || w.rip_filter_end) {
                if (guest_rip < w.rip_filter_start || guest_rip >= w.rip_filter_end)
                    continue;
            }
            if (virtual_address < w.va_start || virtual_address >= w.va_end)
                continue;
            if (!(w.type_mask & access))
                continue;

            ++w.hit_count;
            auto const now_tsc = __rdtsc();
            auto const total_exceeded =
                w.max_total_events && w.hit_count > w.max_total_events;
            auto const rate_exceeded =
                dbg_watch_rate_exceeded_locked(w, now_tsc);
            if (total_exceeded || rate_exceeded) {
                ++w.drop_count;
                dbg_disable_watch_locked(w);
                ++g_ghv->dbg_watch.storm_disabled;
                if (pending_count < dbg_watch_max_events_per_violation) {
                    dbg_fill_watch_event(pending_events[pending_count++], cpu, w,
                                         dbg_evt_storm_disabled, guest_cr3,
                                         guest_rip, virtual_address,
                                         physical_address, qualification.flags);
                }
                continue;
            }

            auto const sample_rate = w.sample_rate ? w.sample_rate : 1;
            if ((w.hit_count % sample_rate) != 0)
                continue;

            if (pending_count < dbg_watch_max_events_per_violation) {
                dbg_fill_watch_event(pending_events[pending_count++], cpu, w,
                                     dbg_event_type_from_access(access),
                                     guest_cr3, guest_rip, virtual_address,
                                     physical_address, qualification.flags);
                ++g_ghv->dbg_watch.event_count;
            } else {
                ++w.drop_count;
            }
        }

        dbg_recompute_page_locked(*page);
        if (!page->ref_count) {
            page->trap_mask = 0;
            page->active = 0;
        }

        dbg_apply_page_all_locked(*page);
        page_snapshot = *page;
        if (!page->ref_count) {
            RtlZeroMemory(page, sizeof(*page));
            if (g_ghv->dbg_watch.active_pages)
                --g_ghv->dbg_watch.active_pages;
        }
    }

    for (uint32_t i = 0; i < pending_count; ++i)
        dbg_event_push(&pending_events[i]);

    auto pte = get_ept_pte(cpu->ept, gpa_page << 12, false);
    if (!pte)
        return handled;

    pte->read_access = page_snapshot.orig_r;
    pte->write_access = page_snapshot.orig_w;
    pte->execute_access = page_snapshot.orig_x;
    if (pte->write_access && !pte->read_access)
        pte->write_access = 0;

    if (page_snapshot.active && page_snapshot.ref_count && page_snapshot.trap_mask) {
        uint8_t r = 0, w = 0, x = 0;
        dbg_calc_trap_perms(page_snapshot, r, w, x);
        cpu->dbg_pending.kind = dbg_pending_watch_rearm;
        cpu->dbg_pending.watch_page_id = page_snapshot.id;
        cpu->dbg_pending.pte = pte;
        cpu->dbg_pending.restore_r = r;
        cpu->dbg_pending.restore_w = w;
        cpu->dbg_pending.restore_x = x;
        cpu->dbg_pending.restore_pfn = pte->page_frame_number;
        need_mtf = true;
    }

    vmx_invept(invept_all_context, {});
    if (need_mtf)
        enable_monitor_trap_flag();
    return handled;
}

bool dbg_watch_handle_mtf(vcpu* cpu) {
    if (!cpu || cpu->dbg_pending.kind != dbg_pending_watch_rearm)
        return false;

    auto pending = cpu->dbg_pending;
    auto pte = pending.pte;

    {
        scoped_spin_lock guard(g_ghv->dbg_watch.lock);
        auto page = dbg_find_page_by_id_locked(pending.watch_page_id);
        if (pte && page && page->ref_count && page->trap_mask &&
            (pte->page_frame_number == pending.restore_pfn ||
             pte->page_frame_number == page->orig_pfn)) {
            uint8_t r = 0, w = 0, x = 0;
            dbg_calc_trap_perms(*page, r, w, x);
            pte->read_access = r;
            pte->write_access = w;
            pte->execute_access = x;
            if (pte->write_access && !pte->read_access)
                pte->write_access = 0;
            pte->page_frame_number = page->orig_pfn;
        }
    }

    RtlZeroMemory(&cpu->dbg_pending, sizeof(cpu->dbg_pending));
    vmx_invept(invept_all_context, {});
    disable_monitor_trap_flag();
    return true;
}

uint32_t dbg_cmd_watch_exec_add(vcpu* cpu, const dbg_packet_header& h,
                                uint64_t in_gva, uint64_t in_size,
                                uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_watch_exec_add_rsp))
        return dbg_err_bad_buffer;
    dbg_watch_exec_add_req req{};
    if (!in_gva || in_size < sizeof(req))
        return dbg_err_bad_packet;
    if (dbg_copy_from_guest(in_gva, &req, sizeof(req)) != sizeof(req))
        return dbg_err_bad_buffer;

    if (!req.va || !req.size || ((req.va & 0xfff) + req.size) > 0x1000)
        return dbg_err_bad_request;

    uint64_t mask = 0;
    auto id = ept_probe_install_all(cpu, req.cr3, req.va, req.flags,
                                    req.hit_limit, &mask);

    dbg_watch_exec_add_rsp rsp{};
    dbg_fill_result(rsp.h, h, id ? dbg_ok : dbg_err_bad_request, sizeof(rsp));
    rsp.watch_id = id;
    rsp.installed_mask = mask;
    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? rsp.h.status
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_watch_exec_remove(vcpu* cpu, const dbg_packet_header& h,
                                   uint64_t in_gva, uint64_t in_size,
                                   uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_watch_exec_remove_rsp))
        return dbg_err_bad_buffer;
    dbg_watch_exec_remove_req req{};
    if (!in_gva || in_size < sizeof(req))
        return dbg_err_bad_packet;
    if (dbg_copy_from_guest(in_gva, &req, sizeof(req)) != sizeof(req))
        return dbg_err_bad_buffer;

    uint64_t mask = 0;
    auto id = ept_probe_remove_all(cpu, req.cr3, req.va, req.flags, &mask);

    dbg_watch_exec_remove_rsp rsp{};
    dbg_fill_result(rsp.h, h, id ? dbg_ok : dbg_err_bad_request, sizeof(rsp));
    rsp.removed_id = id;
    rsp.removed_mask = mask;
    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? rsp.h.status
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_watch_exec_poll_compat(vcpu* cpu, const dbg_packet_header& h,
                                        uint64_t in_gva, uint64_t in_size,
                                        uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_watch_exec_poll_rsp))
        return dbg_err_bad_buffer;
    dbg_watch_exec_poll_req req{};
    if (!in_gva || in_size < sizeof(req))
        return dbg_err_bad_packet;
    if (dbg_copy_from_guest(in_gva, &req, sizeof(req)) != sizeof(req))
        return dbg_err_bad_buffer;

    uint64_t max_hits = req.max_hits ? req.max_hits : ept_probe_hit_count;
    auto const capacity =
        (out_size - sizeof(dbg_watch_exec_poll_rsp)) / sizeof(ept_probe_hit);
    if (max_hits > capacity)
        max_hits = capacity;

    auto copied = ept_probe_copy_hits(cpu, out_gva + sizeof(dbg_watch_exec_poll_rsp),
                                      max_hits, req.clear_after != 0);

    dbg_watch_exec_poll_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.copied = static_cast<uint32_t>(copied);
    rsp.hit_size = sizeof(ept_probe_hit);
    rsp.h.bytes_written = sizeof(rsp) + copied * sizeof(ept_probe_hit);

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_watch_add(vcpu* cpu, const dbg_packet_header& h,
                           uint64_t in_gva, uint64_t in_size,
                           uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_watch_add_rsp))
        return dbg_err_bad_buffer;

    dbg_watch_add_req req{};
    if (!in_gva || in_size < sizeof(req))
        return dbg_err_bad_packet;
    if (dbg_copy_from_guest(in_gva, &req, sizeof(req)) != sizeof(req))
        return dbg_err_bad_buffer;

    auto const valid_mask = dbg_watch_exec | dbg_watch_read | dbg_watch_write;
    if (!req.va || !req.size || !(req.type_mask & valid_mask))
        return dbg_err_bad_request;
    if ((req.rip_filter_start || req.rip_filter_end) &&
        req.rip_filter_start >= req.rip_filter_end)
        return dbg_err_bad_request;

    auto cr3_value = dbg_normalize_watch_cr3(req.cr3, req.va, req.flags);
    if (!cr3_value)
        return dbg_err_bad_request;

    uint64_t pages[dbg_watch_max_pages_per_watch] = {};
    uint32_t page_count = 0;
    if (!dbg_collect_gpa_pages(cr3_value, req.va, req.size, pages, &page_count))
        return dbg_err_bad_request;

    for (uint32_t i = 0; i < page_count; ++i) {
        if (!dbg_preflight_page_all(pages[i]))
            return dbg_err_bad_request;
    }

    dbg_watch_add_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.type_mask = req.type_mask & valid_mask;
    rsp.page_count = page_count;
    rsp.first_gpa_page = pages[0];

    {
        scoped_spin_lock guard(g_ghv->dbg_watch.lock);
        auto w = dbg_alloc_watch_locked();
        if (!w) {
            rsp.h.status = dbg_err_no_slot;
        } else {
            uint32_t required_new_pages = 0;
            for (uint32_t i = 0; i < page_count; ++i) {
                if (!dbg_find_page_locked(pages[i]))
                    ++required_new_pages;
            }
            if (required_new_pages > dbg_free_page_slots_locked()) {
                rsp.h.status = dbg_err_no_slot;
            } else {
                dbg_watch_page* page_records[dbg_watch_max_pages_per_watch] = {};
                uint8_t created_records[dbg_watch_max_pages_per_watch] = {};

                for (uint32_t i = 0; i < page_count; ++i) {
                    auto p = dbg_find_page_locked(pages[i]);
                    if (!p) {
                        p = dbg_alloc_page_locked();
                        if (!p) {
                            rsp.h.status = dbg_err_no_slot;
                            break;
                        }
                        RtlZeroMemory(p, sizeof(*p));
                        p->id = g_ghv->dbg_watch.next_page_id++;
                        if (!p->id)
                            p->id = g_ghv->dbg_watch.next_page_id++;
                        p->gpa_page = pages[i];
                        p->active = 1;
                        auto pte = get_ept_pte(cpu->ept, pages[i] << 12, true);
                        if (!pte) {
                            RtlZeroMemory(p, sizeof(*p));
                            rsp.h.status = dbg_err_bad_request;
                            break;
                        }
                        p->orig_r = static_cast<uint8_t>(pte->read_access);
                        p->orig_w = static_cast<uint8_t>(pte->write_access);
                        p->orig_x = static_cast<uint8_t>(pte->execute_access);
                        p->orig_pfn = pte->page_frame_number;
                        ++g_ghv->dbg_watch.active_pages;
                        created_records[i] = 1;
                    }

                    page_records[i] = p;
                    if (!dbg_page_supports_watch_type(*p, rsp.type_mask)) {
                        rsp.h.status = dbg_err_bad_request;
                        break;
                    }
                }

                if (rsp.h.status != dbg_ok) {
                    for (uint32_t i = 0; i < page_count; ++i) {
                        if (created_records[i] && page_records[i]) {
                            RtlZeroMemory(page_records[i], sizeof(*page_records[i]));
                            if (g_ghv->dbg_watch.active_pages)
                                --g_ghv->dbg_watch.active_pages;
                        }
                    }
                } else {
                    RtlZeroMemory(w, sizeof(*w));
                    w->id = g_ghv->dbg_watch.next_watch_id++;
                    if (!w->id)
                        w->id = g_ghv->dbg_watch.next_watch_id++;
                    w->session = h.session;
                    w->cr3 = cr3_value;
                    w->va_start = req.va;
                    w->va_end = req.va + req.size;
                    w->gpa_page = pages[0];
                    w->type_mask = req.type_mask & valid_mask;
                    w->flags = req.flags;
                    if (dbg_is_kernel_va(req.va))
                        w->flags |= dbg_watch_flag_kernel;
                    w->sample_rate = req.sample_rate ? req.sample_rate : 1;
                    w->max_events_per_sec =
                        req.max_events_per_sec == dbg_watch_unlimited_events_per_sec
                            ? 0
                            : (req.max_events_per_sec
                                   ? req.max_events_per_sec
                                   : dbg_watch_default_max_events_per_sec);
                    w->max_total_events = req.max_total_events ? req.max_total_events
                                                               : dbg_watch_default_max_events;
                    w->rip_filter_start = req.rip_filter_start;
                    w->rip_filter_end = req.rip_filter_end;
                    w->page_count = page_count;
                    for (uint32_t i = 0; i < page_count; ++i)
                        w->gpa_pages[i] = pages[i];
                    w->active = true;
                    ++g_ghv->dbg_watch.active_watches;
                    ++g_ghv->dbg_watch.add_count;

                    for (uint32_t i = 0; i < page_count; ++i) {
                        auto p = page_records[i];
                        if (!p)
                            continue;
                        dbg_recompute_page_locked(*p);
                        dbg_apply_page_all_locked(*p);
                    }

                    rsp.watch_id = w->id;
                }
            }
        }
    }

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? rsp.h.status
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_watch_remove(vcpu* /*cpu*/, const dbg_packet_header& h,
                              uint64_t in_gva, uint64_t in_size,
                              uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_watch_remove_rsp))
        return dbg_err_bad_buffer;

    dbg_watch_remove_req req{};
    if (!in_gva || in_size < sizeof(req))
        return dbg_err_bad_packet;
    if (dbg_copy_from_guest(in_gva, &req, sizeof(req)) != sizeof(req))
        return dbg_err_bad_buffer;

    dbg_watch_remove_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.watch_id = req.watch_id;

    {
        scoped_spin_lock guard(g_ghv->dbg_watch.lock);
        auto w = dbg_find_watch_locked(req.watch_id);
        if (!w) {
            rsp.h.status = dbg_err_bad_request;
        } else {
            rsp.restored_pages = dbg_remove_watch_locked(w);
            rsp.removed = 1;
        }
    }

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? rsp.h.status
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_watch_clear_session(vcpu* /*cpu*/, const dbg_packet_header& h,
                                     uint64_t /*in_gva*/, uint64_t /*in_size*/,
                                     uint64_t out_gva, uint64_t out_size) {
    auto removed = dbg_watch_remove_by_session(h.session);

    dbg_watch_remove_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.removed = removed;
    if (out_gva && out_size >= sizeof(rsp)) {
        if (dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) != sizeof(rsp))
            return dbg_err_bad_buffer;
    }
    return dbg_ok;
}

uint32_t dbg_cmd_watch_stats(vcpu* /*cpu*/, const dbg_packet_header& h,
                             uint64_t /*in_gva*/, uint64_t /*in_size*/,
                             uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_watch_stats_rsp))
        return dbg_err_bad_buffer;

    dbg_watch_stats_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.watch_capacity = dbg_watch_capacity;
    rsp.page_capacity = dbg_watch_page_capacity;
    {
        scoped_spin_lock guard(g_ghv->dbg_watch.lock);
        rsp.next_watch_id = g_ghv->dbg_watch.next_watch_id;
        rsp.add_count = g_ghv->dbg_watch.add_count;
        rsp.remove_count = g_ghv->dbg_watch.remove_count;
        rsp.violation_count = g_ghv->dbg_watch.violation_count;
        rsp.event_count = g_ghv->dbg_watch.event_count;
        rsp.miss_count = g_ghv->dbg_watch.miss_count;
        rsp.storm_disabled = g_ghv->dbg_watch.storm_disabled;
        rsp.active_watches = g_ghv->dbg_watch.active_watches;
        rsp.active_pages = g_ghv->dbg_watch.active_pages;
    }

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

} // namespace hv
