#pragma once

#include <ntddk.h>
#include <ia32.hpp>

#include "debug-core.h"

namespace hv {

struct vcpu;

inline constexpr uint32_t dbg_max_read_size = 0x100000;       // 1MB per vtcall
inline constexpr uint32_t dbg_max_batch_items = 256;
inline constexpr uint32_t dbg_max_batch_item_size = 0x4000;   // 16KB per item
inline constexpr uint32_t dbg_max_batch_data_size = 0x100000; // 1MB payload

enum dbg_page_status : uint32_t {
    dbg_page_ok = 0,
    dbg_page_bad_cr3 = 1,
    dbg_page_pml4_not_present = 2,
    dbg_page_pdpt_not_present = 3,
    dbg_page_pd_not_present = 4,
    dbg_page_pt_not_present = 5,
    dbg_page_bad_physical_range = 6,
    dbg_page_bad_output = 7,
    dbg_page_bad_request = 8,
    dbg_page_too_large = 9,
};

enum dbg_read_flags : uint32_t {
    dbg_read_allow_partial = 1u << 0,
    dbg_read_allow_holes = 1u << 1,
    dbg_read_physical = 1u << 2,
};

struct dbg_pte_info {
    uint64_t cr3;
    uint64_t va;
    uint64_t gpa;
    uint64_t pte_pa;
    uint64_t pte_value;
    uint32_t page_size;
    uint32_t status;
    uint32_t page_offset;
    uint32_t bytes_to_page_end;
    uint8_t present;
    uint8_t writable;
    uint8_t user;
    uint8_t nx;
};

struct dbg_translate_va_req {
    dbg_packet_header h;
    uint64_t cr3;
    uint64_t va;
    uint32_t flags;
    uint32_t reserved;
};

struct dbg_translate_va_rsp {
    dbg_result_header h;
    dbg_pte_info info;
};

struct dbg_read_va_req {
    dbg_packet_header h;
    uint64_t cr3;
    uint64_t va;
    uint32_t size;
    uint32_t flags;
};

struct dbg_read_va_rsp {
    dbg_result_header h;
    uint32_t requested;
    uint32_t read;
    uint32_t page_count;
    uint32_t hole_count;
    uint32_t first_status;
    uint32_t reserved;
    // data follows
};

struct dbg_read_pa_req {
    dbg_packet_header h;
    uint64_t pa;
    uint32_t size;
    uint32_t flags;
};

struct dbg_read_pa_rsp {
    dbg_result_header h;
    uint32_t requested;
    uint32_t read;
    uint32_t page_count;
    uint32_t status;
    // data follows
};

struct dbg_read_item {
    uint64_t cr3;
    uint64_t va;
    uint32_t size;
    uint32_t out_offset;
};

struct dbg_read_batch_req {
    dbg_packet_header h;
    uint32_t count;
    uint32_t flags;
    dbg_read_item items[dbg_max_batch_items];
};

struct dbg_read_item_result {
    uint32_t status;
    uint32_t requested;
    uint32_t read;
    uint32_t out_offset;
};

struct dbg_read_batch_rsp {
    dbg_result_header h;
    uint32_t count;
    uint32_t data_size;
    dbg_read_item_result results[dbg_max_batch_items];
    // data follows
};

dbg_page_status dbg_translate_va_ex(uint64_t cr3_value, uint64_t va,
                                    dbg_pte_info* out);
dbg_page_status dbg_read_virtual_to_guest(uint64_t cr3_value,
                                          uint64_t va,
                                          uint64_t out_gva,
                                          uint32_t size,
                                          uint32_t flags,
                                          uint32_t* bytes_read,
                                          uint32_t* page_count,
                                          uint32_t* hole_count,
                                          uint32_t* first_status);

uint32_t dbg_cmd_translate_va(vcpu* cpu, const dbg_packet_header& h,
                              uint64_t in_gva, uint64_t in_size,
                              uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_query_pte(vcpu* cpu, const dbg_packet_header& h,
                           uint64_t in_gva, uint64_t in_size,
                           uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_read_va(vcpu* cpu, const dbg_packet_header& h,
                         uint64_t in_gva, uint64_t in_size,
                         uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_read_va_batch(vcpu* cpu, const dbg_packet_header& h,
                               uint64_t in_gva, uint64_t in_size,
                               uint64_t out_gva, uint64_t out_size);
uint32_t dbg_cmd_read_pa(vcpu* cpu, const dbg_packet_header& h,
                         uint64_t in_gva, uint64_t in_size,
                         uint64_t out_gva, uint64_t out_size);

} // namespace hv
