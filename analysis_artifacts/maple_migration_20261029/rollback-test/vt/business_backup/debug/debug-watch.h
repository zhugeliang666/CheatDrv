#pragma once

#include <ntddk.h>
#include <ia32.hpp>

#include "debug-core.h"
#include "debug-events.h"
#include "ept.h"
#include "ept-probe.h"

namespace hv {

struct vcpu;

inline constexpr uint32_t dbg_watch_capacity = 64;
inline constexpr uint32_t dbg_watch_page_capacity = 512;
inline constexpr uint32_t dbg_watch_max_pages_per_watch = 64;
inline constexpr uint32_t dbg_watch_max_events_per_violation = 8;
inline constexpr uint64_t dbg_watch_default_max_events = 100000;
inline constexpr uint32_t dbg_watch_default_max_events_per_sec = 2000;
inline constexpr uint64_t dbg_watch_rate_window_tsc = 3'000'000'000ULL;
inline constexpr uint32_t dbg_watch_unlimited_events_per_sec = 0xffffffffu;

enum dbg_watch_type : uint32_t {
    dbg_watch_exec = 1u << 0,
    dbg_watch_read = 1u << 1,
    dbg_watch_write = 1u << 2,
};

enum dbg_watch_flags : uint32_t {
    dbg_watch_flag_kernel = 1u << 0,
    dbg_watch_flag_auto_disable_on_storm = 1u << 1,
};

struct dbg_watch {
    uint64_t id;
    uint64_t session;
    uint64_t cr3;
    uint64_t va_start;
    uint64_t va_end;
    uint64_t gpa_page;
    uint32_t type_mask;
    uint32_t flags;
    uint32_t sample_rate;
    uint32_t max_events_per_sec;
    uint64_t rip_filter_start;
    uint64_t rip_filter_end;
    uint64_t hit_count;
    uint64_t drop_count;
    uint64_t max_total_events;
    uint64_t rate_window_start_tsc;
    uint32_t rate_window_events;
    uint32_t page_count;
    uint8_t active;
    uint8_t reserved0[3];
    uint64_t gpa_pages[dbg_watch_max_pages_per_watch];
};

struct dbg_watch_page {
    uint64_t id;
    uint64_t gpa_page;
    uint32_t trap_mask;
    uint32_t ref_count;
    uint8_t orig_r;
    uint8_t orig_w;
    uint8_t orig_x;
    uint8_t active;
    uint64_t orig_pfn;
};

struct dbg_watch_state {
    spin_lock lock;
    uint64_t next_watch_id;
    uint64_t next_page_id;
    uint32_t active_watches;
    uint32_t active_pages;
    uint64_t add_count;
    uint64_t remove_count;
    uint64_t violation_count;
    uint64_t event_count;
    uint64_t miss_count;
    uint64_t storm_disabled;
    dbg_watch watches[dbg_watch_capacity];
    dbg_watch_page pages[dbg_watch_page_capacity];
};

struct dbg_watch_exec_add_req {
    dbg_packet_header h;
    uint64_t cr3;
    uint64_t va;
    uint64_t size;
    uint64_t hit_limit;
    uint32_t flags;
    uint32_t reserved;
};

struct dbg_watch_exec_add_rsp {
    dbg_result_header h;
    uint64_t watch_id;
    uint64_t installed_mask;
};

struct dbg_watch_exec_remove_req {
    dbg_packet_header h;
    uint64_t cr3;
    uint64_t va;
    uint32_t flags;
    uint32_t reserved;
};

struct dbg_watch_exec_remove_rsp {
    dbg_result_header h;
    uint64_t removed_id;
    uint64_t removed_mask;
};

struct dbg_watch_exec_poll_req {
    dbg_packet_header h;
    uint32_t max_hits;
    uint32_t clear_after;
};

struct dbg_watch_exec_poll_rsp {
    dbg_result_header h;
    uint32_t copied;
    uint32_t hit_size;
    // ept_probe_hit[] follows
};

struct dbg_watch_add_req {
    dbg_packet_header h;
    uint64_t cr3;
    uint64_t va;
    uint64_t size;
    uint32_t type_mask;
    uint32_t flags;
    uint32_t sample_rate;
    uint32_t max_events_per_sec;
    uint64_t max_total_events;
    uint64_t rip_filter_start;
    uint64_t rip_filter_end;
};

struct dbg_watch_add_rsp {
    dbg_result_header h;
    uint64_t watch_id;
    uint64_t first_gpa_page;
    uint32_t page_count;
    uint32_t type_mask;
};

struct dbg_watch_remove_req {
    dbg_packet_header h;
    uint64_t watch_id;
};

struct dbg_watch_remove_rsp {
    dbg_result_header h;
    uint64_t watch_id;
    uint32_t removed;
    uint32_t restored_pages;
};

struct dbg_watch_stats_rsp {
    dbg_result_header h;
    uint64_t next_watch_id;
    uint64_t add_count;
    uint64_t remove_count;
    uint64_t violation_count;
    uint64_t event_count;
    uint64_t miss_count;
    uint64_t storm_disabled;
    uint32_t active_watches;
    uint32_t active_pages;
    uint32_t watch_capacity;
    uint32_t page_capacity;
};

void dbg_watch_init();
void dbg_watch_uninit();
uint32_t dbg_watch_remove_by_session(uint64_t session);

bool dbg_try_handle_ept_violation(vcpu* cpu,
                                  vmx_exit_qualification_ept_violation qualification,
                                  uint64_t physical_address,
                                  uint64_t virtual_address,
                                  uint64_t guest_rip);
bool dbg_watch_handle_mtf(vcpu* cpu);

uint32_t dbg_cmd_watch_exec_add(vcpu* cpu, const dbg_packet_header& h,
                                uint64_t in_gva, uint64_t in_size,
                                uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_watch_exec_remove(vcpu* cpu, const dbg_packet_header& h,
                                   uint64_t in_gva, uint64_t in_size,
                                   uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_watch_exec_poll_compat(vcpu* cpu, const dbg_packet_header& h,
                                        uint64_t in_gva, uint64_t in_size,
                                        uint64_t out_gva, uint64_t out_size);

uint32_t dbg_cmd_watch_add(vcpu* cpu, const dbg_packet_header& h,
                           uint64_t in_gva, uint64_t in_size,
                           uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_watch_remove(vcpu* cpu, const dbg_packet_header& h,
                              uint64_t in_gva, uint64_t in_size,
                              uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_watch_clear_session(vcpu* cpu, const dbg_packet_header& h,
                                     uint64_t in_gva, uint64_t in_size,
                                     uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_watch_stats(vcpu* cpu, const dbg_packet_header& h,
                             uint64_t in_gva, uint64_t in_size,
                             uint64_t out_gva, uint64_t out_size);

} // namespace hv
