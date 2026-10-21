#include "debug-dump.h"

#include "debug-memory.h"
#include "vcpu.h"

namespace hv {

#pragma code_seg(".vm")

static uint64_t dbg_min64(uint64_t a, uint64_t b) {
    return a < b ? a : b;
}

uint32_t dbg_cmd_dump_range(vcpu* /*cpu*/, const dbg_packet_header& h,
                            uint64_t in_gva, uint64_t in_size,
                            uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_dump_range_rsp))
        return dbg_err_bad_buffer;

    dbg_dump_range_req req{};
    if (!in_gva || in_size < sizeof(req))
        return dbg_err_bad_packet;
    if (dbg_copy_from_guest(in_gva, &req, sizeof(req)) != sizeof(req))
        return dbg_err_bad_buffer;

    dbg_dump_range_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));

    if (req.cursor >= req.size) {
        rsp.next_cursor = req.size;
        rsp.remaining = 0;
        rsp.done = 1;
        rsp.first_status = dbg_page_ok;
        return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
            ? dbg_ok
            : dbg_err_bad_buffer;
    }

    uint64_t const data_capacity = out_size - sizeof(rsp);
    uint32_t chunk = req.chunk_size ? req.chunk_size : dbg_dump_default_chunk;
    if (chunk > dbg_max_read_size)
        chunk = dbg_max_read_size;
    chunk = static_cast<uint32_t>(dbg_min64(chunk, data_capacity));
    chunk = static_cast<uint32_t>(dbg_min64(chunk, req.size - req.cursor));

    if (!chunk)
        return dbg_err_bad_buffer;

    uint32_t bytes_read = 0;
    uint32_t page_count = 0;
    uint32_t first_status = dbg_page_ok;
    auto const status = dbg_read_virtual_to_guest(req.cr3, req.va + req.cursor,
                                                  out_gva + sizeof(rsp),
                                                  chunk,
                                                  req.flags | dbg_read_allow_partial,
                                                  &bytes_read,
                                                  &page_count,
                                                  &rsp.hole_count,
                                                  &first_status);

    rsp.chunk_va_offset = static_cast<uint32_t>(req.cursor & 0xffffffffu);
    rsp.data_size = bytes_read;
    rsp.first_status = first_status ? first_status : status;
    rsp.next_cursor = req.cursor + bytes_read;
    if ((req.flags & dbg_read_allow_holes) && bytes_read == chunk)
        rsp.next_cursor = req.cursor + chunk;
    if (rsp.next_cursor > req.size)
        rsp.next_cursor = req.size;
    rsp.remaining = req.size - rsp.next_cursor;
    rsp.done = rsp.remaining == 0 ? 1 : 0;
    rsp.h.bytes_written = sizeof(rsp) + rsp.data_size;

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

} // namespace hv
