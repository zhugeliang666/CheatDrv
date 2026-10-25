#pragma once

#include <ntddk.h>
#include <ia32.hpp>

#include "spin-lock.h"

namespace hv {

struct vcpu;

inline constexpr uint32_t dbg_magic = 0x56444247u; // 'VDBG'
inline constexpr uint16_t dbg_abi_version = 1;
inline constexpr uint32_t dbg_max_sessions = 8;

enum dbg_status : uint32_t {
    dbg_ok = 0,
    dbg_err_bad_packet = 1,
    dbg_err_bad_version = 2,
    dbg_err_bad_session = 3,
    dbg_err_no_slot = 4,
    dbg_err_bad_buffer = 5,
    dbg_err_not_implemented = 6,
    dbg_err_bad_request = 7,
    dbg_err_too_large = 8,
};

enum dbg_subcmd : uint32_t {
    dbg_session_open = 0x1000,
    dbg_session_close = 0x1001,
    dbg_session_heartbeat = 0x1002,
    dbg_event_stats = 0x1003,

    dbg_translate_va = 0x2000,
    dbg_query_pte = 0x2001,
    dbg_read_va = 0x2002,
    dbg_read_va_batch = 0x2003,
    dbg_read_pa = 0x2004,

    dbg_dump_range = 0x3000,

    dbg_event_poll = 0x5000,
    dbg_event_ring_stats = 0x5001,
    dbg_clear_events = 0x5002,
    dbg_event_selftest = 0x5003,

    dbg_watch_exec_add = 0x4100,
    dbg_watch_exec_remove = 0x4101,
    dbg_watch_exec_poll_compat = 0x4102,

    dbg_watch_add = 0x6000,
    dbg_watch_remove = 0x6001,
    dbg_watch_clear_session = 0x6002,
    dbg_watch_stats = 0x6003,
};

struct dbg_packet_header {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t subcmd;
    uint32_t flags;
    uint64_t session;
    uint64_t seq;
};

struct dbg_result_header {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t status;
    uint32_t flags;
    uint64_t session;
    uint64_t seq;
    uint64_t bytes_written;
};

struct dbg_session {
    uint64_t id;
    uint32_t owner_pid;
    uint32_t flags;
    uint64_t created_tsc;
    uint64_t last_seen_tsc;
    uint64_t dropped_events;
    bool active;
};

struct dbg_state {
    spin_lock lock;
    uint64_t next_session_id;
    uint64_t dispatch_count;
    uint64_t bad_packet_count;
    uint64_t bad_buffer_count;
    uint64_t open_count;
    uint64_t close_count;
    dbg_session sessions[dbg_max_sessions];
};

struct dbg_session_open_req {
    dbg_packet_header h;
    uint32_t flags;
    uint32_t reserved;
};

struct dbg_session_open_rsp {
    dbg_result_header h;
    uint64_t session;
    uint32_t max_sessions;
    uint32_t abi_version;
};

struct dbg_session_close_req {
    dbg_packet_header h;
};

struct dbg_event_stats_rsp {
    dbg_result_header h;
    uint64_t dispatch_count;
    uint64_t bad_packet_count;
    uint64_t bad_buffer_count;
    uint64_t open_count;
    uint64_t close_count;
    uint32_t active_sessions;
    uint32_t max_sessions;
};

inline void dbg_init() {}
inline void dbg_uninit() {}
inline void dbg_handle_hypercall(vcpu* /*cpu*/) {}

inline size_t dbg_copy_from_guest(uint64_t /*gva*/, void* /*out*/, size_t /*size*/) { return 0; }
inline size_t dbg_copy_to_guest(uint64_t /*gva*/, const void* /*in*/, size_t /*size*/) { return 0; }
inline void dbg_fill_result(dbg_result_header& /*r*/, const dbg_packet_header& /*h*/,
                            uint32_t /*status*/, uint16_t /*size*/) {}

} // namespace hv
