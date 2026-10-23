#include "debug-events.h"

#include <intrin.h>

#include "hv.h"
#include "vcpu.h"
#include "vmx.h"

namespace hv {

#pragma code_seg(".vm")

void dbg_event_init() {
    auto& r = g_ghv->dbg_events;
    RtlZeroMemory(&r, sizeof(r));
    r.lock.initialize();
    r.next_seq = 1;
}

void dbg_event_clear() {
    auto& r = g_ghv->dbg_events;
    scoped_spin_lock guard(r.lock);
    r.write_index = 0;
    r.count = 0;
    r.dropped = 0;
    r.next_seq = 1;
    RtlZeroMemory(r.events, sizeof(r.events));
}

void dbg_event_push(const dbg_event* ev) {
    if (!ev)
        return;

    auto& r = g_ghv->dbg_events;
    scoped_spin_lock guard(r.lock);

    dbg_event copy = *ev;
    copy.seq = r.next_seq++;
    copy.size = sizeof(dbg_event);

    r.events[r.write_index] = copy;
    r.write_index = (r.write_index + 1) % dbg_event_ring_cap;
    if (r.count < dbg_event_ring_cap) {
        ++r.count;
    } else {
        ++r.dropped;
    }
}

uint32_t dbg_event_copy(uint64_t after_seq, dbg_event* out,
                        uint32_t max_count, bool clear) {
    if (!out || !max_count)
        return 0;
    if (max_count > dbg_event_poll_max)
        max_count = dbg_event_poll_max;

    auto& r = g_ghv->dbg_events;
    scoped_spin_lock guard(r.lock);

    uint32_t copied = 0;
    uint32_t const count = r.count;
    uint32_t const oldest =
        (r.write_index + dbg_event_ring_cap - count) % dbg_event_ring_cap;

    for (uint32_t i = 0; i < count && copied < max_count; ++i) {
        auto const idx = (oldest + i) % dbg_event_ring_cap;
        auto const& ev = r.events[idx];
        if (ev.seq > after_seq)
            out[copied++] = ev;
    }

    if (clear && copied) {
        r.write_index = 0;
        r.count = 0;
        RtlZeroMemory(r.events, sizeof(r.events));
    }
    return copied;
}

static void dbg_fill_event_snapshot(dbg_event& ev, vcpu* cpu,
                                    const dbg_packet_header& h,
                                    uint16_t type) {
    RtlZeroMemory(&ev, sizeof(ev));
    ev.tsc = __rdtsc();
    ev.cpu = cpu ? static_cast<uint32_t>(cpu->vpid) : 0;
    ev.type = type;
    ev.size = sizeof(ev);
    ev.session = h.session;

    if (cpu && cpu->ctx) {
        ev.rax = cpu->ctx->rax;
        ev.rcx = cpu->ctx->rcx;
        ev.rdx = cpu->ctx->rdx;
        ev.r8 = cpu->ctx->r8;
        ev.r9 = cpu->ctx->r9;
    }

    __try {
        ev.cr3 = vmx_vmread(VMCS_GUEST_CR3);
        ev.rip = vmx_vmread(VMCS_GUEST_RIP);
        ev.rsp = vmx_vmread(VMCS_GUEST_RSP);
    } __except (1) {
    }
}

uint32_t dbg_cmd_event_poll(vcpu* /*cpu*/, const dbg_packet_header& h,
                            uint64_t in_gva, uint64_t in_size,
                            uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_event_poll_rsp))
        return dbg_err_bad_buffer;

    dbg_event_poll_req req{};
    if (!in_gva || in_size < sizeof(req))
        return dbg_err_bad_packet;
    if (dbg_copy_from_guest(in_gva, &req, sizeof(req)) != sizeof(req))
        return dbg_err_bad_buffer;

    uint32_t max_count = req.max_count ? req.max_count : dbg_event_poll_max;
    if (max_count > dbg_event_poll_max)
        max_count = dbg_event_poll_max;

    uint64_t const capacity =
        (out_size - sizeof(dbg_event_poll_rsp)) / sizeof(dbg_event);
    if (max_count > capacity)
        max_count = static_cast<uint32_t>(capacity);

    dbg_event events[dbg_event_poll_max] = {};
    auto const copied = dbg_event_copy(req.after_seq, events, max_count,
        (req.flags & dbg_event_poll_clear) != 0);

    dbg_event_poll_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.count = copied;
    rsp.capacity = dbg_event_ring_cap;

    {
        scoped_spin_lock guard(g_ghv->dbg_events.lock);
        rsp.next_seq = g_ghv->dbg_events.next_seq;
        rsp.dropped = g_ghv->dbg_events.dropped;
    }

    auto const bytes = static_cast<uint64_t>(copied) * sizeof(dbg_event);
    if (bytes) {
        if (dbg_copy_to_guest(out_gva + sizeof(rsp), events,
                              static_cast<size_t>(bytes)) != bytes)
            return dbg_err_bad_buffer;
    }

    rsp.h.bytes_written = sizeof(rsp) + bytes;
    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_event_ring_stats(vcpu* /*cpu*/, const dbg_packet_header& h,
                                  uint64_t /*in_gva*/, uint64_t /*in_size*/,
                                  uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_event_ring_stats_rsp))
        return dbg_err_bad_buffer;

    dbg_event_ring_stats_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.capacity = dbg_event_ring_cap;

    {
        scoped_spin_lock guard(g_ghv->dbg_events.lock);
        rsp.next_seq = g_ghv->dbg_events.next_seq;
        rsp.dropped = g_ghv->dbg_events.dropped;
        rsp.count = g_ghv->dbg_events.count;
        rsp.write_index = g_ghv->dbg_events.write_index;
    }

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_clear_events(vcpu* /*cpu*/, const dbg_packet_header& h,
                              uint64_t /*in_gva*/, uint64_t /*in_size*/,
                              uint64_t out_gva, uint64_t out_size) {
    dbg_event_clear();

    dbg_result_header rsp{};
    dbg_fill_result(rsp, h, dbg_ok, sizeof(rsp));
    if (out_gva && out_size >= sizeof(rsp)) {
        if (dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) != sizeof(rsp))
            return dbg_err_bad_buffer;
    }
    return dbg_ok;
}

uint32_t dbg_cmd_event_selftest(vcpu* cpu, const dbg_packet_header& h,
                                uint64_t /*in_gva*/, uint64_t /*in_size*/,
                                uint64_t out_gva, uint64_t out_size) {
    dbg_event ev{};
    dbg_fill_event_snapshot(ev, cpu, h, dbg_evt_selftest);
    dbg_event_push(&ev);

    dbg_event_ring_stats_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.capacity = dbg_event_ring_cap;
    {
        scoped_spin_lock guard(g_ghv->dbg_events.lock);
        rsp.next_seq = g_ghv->dbg_events.next_seq;
        rsp.dropped = g_ghv->dbg_events.dropped;
        rsp.count = g_ghv->dbg_events.count;
        rsp.write_index = g_ghv->dbg_events.write_index;
    }

    if (out_gva && out_size >= sizeof(rsp)) {
        if (dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) != sizeof(rsp))
            return dbg_err_bad_buffer;
    }
    return dbg_ok;
}

} // namespace hv
