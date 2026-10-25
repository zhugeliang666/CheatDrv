#pragma once

#include <ntddk.h>
#include <ia32.hpp>

#include "debug-core.h"

namespace hv {

struct vcpu;

inline constexpr uint32_t dbg_event_ring_cap = 4096;
inline constexpr uint32_t dbg_event_poll_max = 128;

enum dbg_event_type : uint16_t {
    dbg_evt_none = 0,
    dbg_evt_exec = 1,
    dbg_evt_read = 2,
    dbg_evt_write = 3,
    dbg_evt_translate_fail = 4,
    dbg_evt_storm_disabled = 5,
    dbg_evt_selftest = 0xFFFF,
};

enum dbg_event_poll_flags : uint32_t {
    dbg_event_poll_clear = 1u << 0,
};

struct dbg_event {
    uint64_t seq;
    uint64_t tsc;
    uint32_t cpu;
    uint16_t type;
    uint16_t size;
    uint64_t session;
    uint64_t watch_id;
    uint64_t cr3;
    uint64_t rip;
    uint64_t rsp;
    uint64_t gla;
    uint64_t gpa;
    uint64_t qualification;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t r8;
    uint64_t r9;
    uint8_t sample[32];
};

struct dbg_event_ring {
    spin_lock lock;
    uint64_t next_seq;
    uint32_t write_index;
    uint32_t count;
    uint64_t dropped;
    dbg_event events[dbg_event_ring_cap];
};

struct dbg_event_poll_req {
    dbg_packet_header h;
    uint64_t after_seq;
    uint32_t max_count;
    uint32_t flags;
};

struct dbg_event_poll_rsp {
    dbg_result_header h;
    uint64_t next_seq;
    uint64_t dropped;
    uint32_t count;
    uint32_t capacity;
    // dbg_event events[] follows
};

struct dbg_event_ring_stats_rsp {
    dbg_result_header h;
    uint64_t next_seq;
    uint64_t dropped;
    uint32_t count;
    uint32_t capacity;
    uint32_t write_index;
    uint32_t reserved;
};

inline void dbg_event_init() {}
inline void dbg_event_clear() {}
inline void dbg_event_push(const dbg_event* /*ev*/) {}
inline uint32_t dbg_event_copy(uint64_t /*after_seq*/, dbg_event* /*out*/,
                               uint32_t /*max_count*/, bool /*clear*/) { return 0; }

inline uint32_t dbg_cmd_event_poll(vcpu* /*cpu*/, const dbg_packet_header& /*h*/,
                                   uint64_t /*in_gva*/, uint64_t /*in_size*/,
                                   uint64_t /*out_gva*/, uint64_t /*out_size*/) { return 6; }
inline uint32_t dbg_cmd_event_ring_stats(vcpu* /*cpu*/, const dbg_packet_header& /*h*/,
                                         uint64_t /*in_gva*/, uint64_t /*in_size*/,
                                         uint64_t /*out_gva*/, uint64_t /*out_size*/) { return 6; }
inline uint32_t dbg_cmd_clear_events(vcpu* /*cpu*/, const dbg_packet_header& /*h*/,
                                     uint64_t /*in_gva*/, uint64_t /*in_size*/,
                                     uint64_t /*out_gva*/, uint64_t /*out_size*/) { return 6; }
inline uint32_t dbg_cmd_event_selftest(vcpu* /*cpu*/, const dbg_packet_header& /*h*/,
                                       uint64_t /*in_gva*/, uint64_t /*in_size*/,
                                       uint64_t /*out_gva*/, uint64_t /*out_size*/) { return 6; }

} // namespace hv
