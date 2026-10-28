#pragma once

#include <ntddk.h>
#include <ia32.hpp>

#include "debug-core.h"

namespace hv {

struct vcpu;

inline constexpr uint32_t dbg_dump_default_chunk = 0x10000;

struct dbg_dump_range_req {
    dbg_packet_header h;
    uint64_t cr3;
    uint64_t va;
    uint64_t size;
    uint64_t cursor;
    uint32_t chunk_size;
    uint32_t flags;
};

struct dbg_dump_range_rsp {
    dbg_result_header h;
    uint64_t next_cursor;
    uint64_t remaining;
    uint32_t chunk_va_offset;
    uint32_t data_size;
    uint32_t hole_count;
    uint32_t done;
    uint32_t first_status;
    uint32_t reserved;
    // data follows
};

uint32_t dbg_cmd_dump_range(vcpu* cpu, const dbg_packet_header& h,
                            uint64_t in_gva, uint64_t in_size,
                            uint64_t out_gva, uint64_t out_size);

} // namespace hv
