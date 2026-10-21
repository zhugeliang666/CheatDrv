#include "debug-core.h"

#include <intrin.h>

#include "debug-dump.h"
#include "debug-events.h"
#include "debug-memory.h"
#include "debug-watch.h"
#include "exception-routines.h"
#include "hv.h"
#include "mm.h"
#include "vcpu.h"

namespace hv {

#pragma code_seg(".vm")

static uint64_t dbg_now_tsc() {
    return __rdtsc();
}

size_t dbg_copy_from_guest(uint64_t gva, void* out, size_t size) {
    auto dst = reinterpret_cast<uint8_t*>(out);
    size_t copied = 0;
    while (copied < size) {
        size_t remain = 0;
        auto hva = gva2hva(reinterpret_cast<void*>(gva + copied), &remain);
        if (!hva || !remain)
            break;

        auto chunk = min(size - copied, remain);
        host_exception_info e{};
        memcpy_safe(e, dst + copied, hva, chunk);
        if (e.exception_occurred)
            break;
        copied += chunk;
    }
    return copied;
}

size_t dbg_copy_to_guest(uint64_t gva, const void* in, size_t size) {
    auto src = reinterpret_cast<const uint8_t*>(in);
    size_t copied = 0;
    while (copied < size) {
        size_t remain = 0;
        auto hva = gva2hva(reinterpret_cast<void*>(gva + copied), &remain);
        if (!hva || !remain)
            break;

        auto chunk = min(size - copied, remain);
        host_exception_info e{};
        memcpy_safe(e, hva, src + copied, chunk);
        if (e.exception_occurred)
            break;
        copied += chunk;
    }
    return copied;
}

void dbg_fill_result(dbg_result_header& r, const dbg_packet_header& h,
                     uint32_t status, uint16_t size) {
    r.magic = dbg_magic;
    r.version = dbg_abi_version;
    r.size = size;
    r.status = status;
    r.flags = 0;
    r.session = h.session;
    r.seq = h.seq;
    r.bytes_written = size;
}

static dbg_session* dbg_find_session_locked(uint64_t id) {
    if (!id)
        return nullptr;
    for (auto& s : g_ghv->dbg.sessions) {
        if (s.active && s.id == id)
            return &s;
    }
    return nullptr;
}

static uint32_t dbg_active_session_count_locked() {
    uint32_t n = 0;
    for (auto const& s : g_ghv->dbg.sessions) {
        if (s.active)
            ++n;
    }
    return n;
}

void dbg_init() {
    auto& d = g_ghv->dbg;
    RtlZeroMemory(&d, sizeof(d));
    d.lock.initialize();
    d.next_session_id = 1;
    dbg_event_init();
    dbg_watch_init();
}

void dbg_uninit() {
    dbg_watch_uninit();
    dbg_event_clear();
    auto& d = g_ghv->dbg;
    scoped_spin_lock guard(d.lock);
    for (auto& s : d.sessions) {
        RtlZeroMemory(&s, sizeof(s));
    }
}

static uint32_t dbg_cmd_session_open(const dbg_packet_header& h,
                                     uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_session_open_rsp))
        return dbg_err_bad_buffer;

    dbg_session_open_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.max_sessions = dbg_max_sessions;
    rsp.abi_version = dbg_abi_version;

    {
        scoped_spin_lock guard(g_ghv->dbg.lock);
        dbg_session* slot = nullptr;
        for (auto& s : g_ghv->dbg.sessions) {
            if (!s.active) {
                slot = &s;
                break;
            }
        }
        if (!slot) {
            rsp.h.status = dbg_err_no_slot;
        } else {
            auto id = g_ghv->dbg.next_session_id++;
            if (!id)
                id = g_ghv->dbg.next_session_id++;
            RtlZeroMemory(slot, sizeof(*slot));
            slot->id = id;
            slot->owner_pid = 0;
            slot->flags = h.flags;
            slot->created_tsc = dbg_now_tsc();
            slot->last_seen_tsc = slot->created_tsc;
            slot->active = true;
            rsp.session = id;
            rsp.h.session = id;
            g_ghv->dbg.open_count++;
        }
    }

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? rsp.h.status
        : dbg_err_bad_buffer;
}

static uint32_t dbg_cmd_session_close(const dbg_packet_header& h,
                                      uint64_t out_gva, uint64_t out_size) {
    dbg_result_header rsp{};
    dbg_fill_result(rsp, h, dbg_ok, sizeof(rsp));

    {
        scoped_spin_lock guard(g_ghv->dbg.lock);
        auto s = dbg_find_session_locked(h.session);
        if (!s) {
            rsp.status = dbg_err_bad_session;
        } else {
            dbg_watch_remove_by_session(h.session);
            RtlZeroMemory(s, sizeof(*s));
            g_ghv->dbg.close_count++;
        }
    }

    if (out_gva && out_size >= sizeof(rsp)) {
        if (dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) != sizeof(rsp))
            return dbg_err_bad_buffer;
    }
    return rsp.status;
}

static uint32_t dbg_cmd_event_stats(const dbg_packet_header& h,
                                    uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_event_stats_rsp))
        return dbg_err_bad_buffer;

    dbg_event_stats_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.max_sessions = dbg_max_sessions;

    {
        scoped_spin_lock guard(g_ghv->dbg.lock);
        rsp.dispatch_count = g_ghv->dbg.dispatch_count;
        rsp.bad_packet_count = g_ghv->dbg.bad_packet_count;
        rsp.bad_buffer_count = g_ghv->dbg.bad_buffer_count;
        rsp.open_count = g_ghv->dbg.open_count;
        rsp.close_count = g_ghv->dbg.close_count;
        rsp.active_sessions = dbg_active_session_count_locked();
    }

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

void dbg_handle_hypercall(vcpu* cpu) {
    if (!cpu || !cpu->ctx)
        return;

    auto const subcmd = static_cast<uint32_t>(cpu->ctx->rcx);
    auto const in_gva = cpu->ctx->rdx;
    auto const in_size = cpu->ctx->r8;
    auto const out_gva = cpu->ctx->r9;
    auto const out_size = cpu->ctx->r10;
    auto const flags_or_session = cpu->ctx->r11;

    {
        scoped_spin_lock guard(g_ghv->dbg.lock);
        g_ghv->dbg.dispatch_count++;
    }

    dbg_packet_header h{};
    if (in_gva && in_size >= sizeof(h)) {
        if (dbg_copy_from_guest(in_gva, &h, sizeof(h)) != sizeof(h)) {
            scoped_spin_lock guard(g_ghv->dbg.lock);
            g_ghv->dbg.bad_buffer_count++;
            cpu->ctx->rax = dbg_err_bad_buffer;
            return;
        }
        if (h.magic != dbg_magic || h.size < sizeof(dbg_packet_header)) {
            scoped_spin_lock guard(g_ghv->dbg.lock);
            g_ghv->dbg.bad_packet_count++;
            cpu->ctx->rax = dbg_err_bad_packet;
            return;
        }
        if (h.version != dbg_abi_version) {
            scoped_spin_lock guard(g_ghv->dbg.lock);
            g_ghv->dbg.bad_packet_count++;
            cpu->ctx->rax = dbg_err_bad_version;
            return;
        }
    } else {
        h.magic = dbg_magic;
        h.version = dbg_abi_version;
        h.size = sizeof(h);
        h.subcmd = subcmd;
        h.flags = static_cast<uint32_t>(flags_or_session & 0xFFFFFFFFu);
        h.session = flags_or_session;
        h.seq = 0;
    }

    if (!h.subcmd)
        h.subcmd = subcmd;
    if (!h.session && flags_or_session && h.subcmd != dbg_session_open)
        h.session = flags_or_session;

    uint32_t status = dbg_err_not_implemented;
    switch (h.subcmd) {
    case dbg_session_open:
        status = dbg_cmd_session_open(h, out_gva, out_size);
        break;
    case dbg_session_close:
        status = dbg_cmd_session_close(h, out_gva, out_size);
        break;
    case dbg_session_heartbeat:
        status = dbg_ok;
        break;
    case dbg_event_stats:
        status = dbg_cmd_event_stats(h, out_gva, out_size);
        break;
    case dbg_translate_va:
        status = dbg_cmd_translate_va(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_query_pte:
        status = dbg_cmd_query_pte(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_read_va:
        status = dbg_cmd_read_va(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_read_va_batch:
        status = dbg_cmd_read_va_batch(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_read_pa:
        status = dbg_cmd_read_pa(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_dump_range:
        status = dbg_cmd_dump_range(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_event_poll:
        status = dbg_cmd_event_poll(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_event_ring_stats:
        status = dbg_cmd_event_ring_stats(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_clear_events:
        status = dbg_cmd_clear_events(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_event_selftest:
        status = dbg_cmd_event_selftest(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_watch_exec_add:
        status = dbg_cmd_watch_exec_add(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_watch_exec_remove:
        status = dbg_cmd_watch_exec_remove(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_watch_exec_poll_compat:
        status = dbg_cmd_watch_exec_poll_compat(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_watch_add:
        status = dbg_cmd_watch_add(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_watch_remove:
        status = dbg_cmd_watch_remove(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_watch_clear_session:
        status = dbg_cmd_watch_clear_session(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    case dbg_watch_stats:
        status = dbg_cmd_watch_stats(cpu, h, in_gva, in_size, out_gva, out_size);
        break;
    default:
        status = dbg_err_not_implemented;
        break;
    }

    if (status == dbg_err_bad_buffer) {
        scoped_spin_lock guard(g_ghv->dbg.lock);
        g_ghv->dbg.bad_buffer_count++;
    }
    cpu->ctx->rax = status;
}

} // namespace hv
