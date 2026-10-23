#include "debug-memory.h"

#include "exception-routines.h"
#include "mm.h"
#include "page-tables.h"
#include "vcpu.h"

namespace hv {

#pragma code_seg(".vm")

static uint64_t dbg_min_u64(uint64_t a, uint64_t b) {
    return a < b ? a : b;
}

static uint32_t dbg_min_u32(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

static uint32_t dbg_page_end_4k(uint64_t va) {
    return static_cast<uint32_t>(0x1000ull - (va & 0xfffull));
}

static bool dbg_read_entry_u64(uint64_t pa, uint64_t* value) {
    if (!value || !host_physical_range_mapped(pa, sizeof(uint64_t)))
        return false;

    auto const hva = host_physical_to_virtual(pa, sizeof(uint64_t));
    if (!hva)
        return false;

    host_exception_info e{};
    memcpy_safe(e, value, hva, sizeof(uint64_t));
    return !e.exception_occurred;
}

static void dbg_set_not_present_result(dbg_pte_info* out,
                                       uint32_t status,
                                       uint64_t entry_pa,
                                       uint64_t entry_value) {
    if (!out)
        return;
    out->status = status;
    out->pte_pa = entry_pa;
    out->pte_value = entry_value;
    out->present = 0;
    out->page_offset = static_cast<uint32_t>(out->va & 0xfffull);
    out->bytes_to_page_end = dbg_page_end_4k(out->va);
}

static void dbg_fill_leaf_flags(dbg_pte_info* out,
                                bool writable,
                                bool user,
                                bool nx) {
    if (!out)
        return;
    out->present = 1;
    out->writable = writable ? 1 : 0;
    out->user = user ? 1 : 0;
    out->nx = nx ? 1 : 0;
}

dbg_page_status dbg_translate_va_ex(uint64_t cr3_value, uint64_t va,
                                    dbg_pte_info* out) {
    if (!out)
        return dbg_page_bad_request;

    RtlZeroMemory(out, sizeof(*out));
    out->cr3 = cr3_value;
    out->va = va;
    out->page_offset = static_cast<uint32_t>(va & 0xfffull);
    out->bytes_to_page_end = dbg_page_end_4k(va);

    cr3 c{};
    c.flags = cr3_value;

    pml4_virtual_address const vaddr = {
        reinterpret_cast<void const*>(va)
    };

    uint64_t const pml4_base = c.address_of_page_directory << 12;
    if (!host_physical_range_mapped(pml4_base, PAGE_SIZE)) {
        out->status = dbg_page_bad_cr3;
        return dbg_page_bad_cr3;
    }

    uint64_t entry_value = 0;
    uint64_t const pml4e_pa = pml4_base + vaddr.pml4_idx * sizeof(uint64_t);
    if (!dbg_read_entry_u64(pml4e_pa, &entry_value)) {
        out->status = dbg_page_bad_cr3;
        out->pte_pa = pml4e_pa;
        return dbg_page_bad_cr3;
    }

    pml4e_64 pml4e{};
    pml4e.flags = entry_value;
    if (!pml4e.present) {
        dbg_set_not_present_result(out, dbg_page_pml4_not_present,
                                   pml4e_pa, pml4e.flags);
        return dbg_page_pml4_not_present;
    }

    bool writable = pml4e.write != 0;
    bool user = pml4e.supervisor != 0;
    bool nx = pml4e.execute_disable != 0;

    uint64_t const pdpt_base = pml4e.page_frame_number << 12;
    if (!host_physical_range_mapped(pdpt_base, PAGE_SIZE)) {
        out->status = dbg_page_bad_physical_range;
        out->pte_pa = pdpt_base;
        return dbg_page_bad_physical_range;
    }

    uint64_t const pdpte_pa = pdpt_base + vaddr.pdpt_idx * sizeof(uint64_t);
    if (!dbg_read_entry_u64(pdpte_pa, &entry_value)) {
        out->status = dbg_page_bad_physical_range;
        out->pte_pa = pdpte_pa;
        return dbg_page_bad_physical_range;
    }

    pdpte_64 pdpte{};
    pdpte.flags = entry_value;
    if (!pdpte.present) {
        dbg_set_not_present_result(out, dbg_page_pdpt_not_present,
                                   pdpte_pa, pdpte.flags);
        return dbg_page_pdpt_not_present;
    }

    writable = writable && (pdpte.write != 0);
    user = user && (pdpte.supervisor != 0);
    nx = nx || (pdpte.execute_disable != 0);

    if (pdpte.large_page) {
        pdpte_1gb_64 leaf{};
        leaf.flags = pdpte.flags;

        uint64_t const offset =
            (static_cast<uint64_t>(vaddr.pd_idx) << 21) +
            (static_cast<uint64_t>(vaddr.pt_idx) << 12) +
            vaddr.offset;
        uint64_t const gpa = (leaf.page_frame_number << 30) + offset;
        if (!host_physical_range_mapped(gpa, 1)) {
            out->status = dbg_page_bad_physical_range;
            out->gpa = gpa;
            out->pte_pa = pdpte_pa;
            out->pte_value = pdpte.flags;
            return dbg_page_bad_physical_range;
        }

        writable = writable && (leaf.write != 0);
        user = user && (leaf.supervisor != 0);
        nx = nx || (leaf.execute_disable != 0);

        out->gpa = gpa;
        out->pte_pa = pdpte_pa;
        out->pte_value = pdpte.flags;
        out->page_size = 0x40000000;
        out->page_offset = static_cast<uint32_t>(offset);
        out->bytes_to_page_end = static_cast<uint32_t>(0x40000000ull - offset);
        out->status = dbg_page_ok;
        dbg_fill_leaf_flags(out, writable, user, nx);
        return dbg_page_ok;
    }

    uint64_t const pd_base = pdpte.page_frame_number << 12;
    if (!host_physical_range_mapped(pd_base, PAGE_SIZE)) {
        out->status = dbg_page_bad_physical_range;
        out->pte_pa = pd_base;
        return dbg_page_bad_physical_range;
    }

    uint64_t const pde_pa = pd_base + vaddr.pd_idx * sizeof(uint64_t);
    if (!dbg_read_entry_u64(pde_pa, &entry_value)) {
        out->status = dbg_page_bad_physical_range;
        out->pte_pa = pde_pa;
        return dbg_page_bad_physical_range;
    }

    pde_64 pde{};
    pde.flags = entry_value;
    if (!pde.present) {
        dbg_set_not_present_result(out, dbg_page_pd_not_present,
                                   pde_pa, pde.flags);
        return dbg_page_pd_not_present;
    }

    writable = writable && (pde.write != 0);
    user = user && (pde.supervisor != 0);
    nx = nx || (pde.execute_disable != 0);

    if (pde.large_page) {
        pde_2mb_64 leaf{};
        leaf.flags = pde.flags;

        uint64_t const offset =
            (static_cast<uint64_t>(vaddr.pt_idx) << 12) + vaddr.offset;
        uint64_t const gpa = (leaf.page_frame_number << 21) + offset;
        if (!host_physical_range_mapped(gpa, 1)) {
            out->status = dbg_page_bad_physical_range;
            out->gpa = gpa;
            out->pte_pa = pde_pa;
            out->pte_value = pde.flags;
            return dbg_page_bad_physical_range;
        }

        writable = writable && (leaf.write != 0);
        user = user && (leaf.supervisor != 0);
        nx = nx || (leaf.execute_disable != 0);

        out->gpa = gpa;
        out->pte_pa = pde_pa;
        out->pte_value = pde.flags;
        out->page_size = 0x200000;
        out->page_offset = static_cast<uint32_t>(offset);
        out->bytes_to_page_end = static_cast<uint32_t>(0x200000ull - offset);
        out->status = dbg_page_ok;
        dbg_fill_leaf_flags(out, writable, user, nx);
        return dbg_page_ok;
    }

    uint64_t const pt_base = pde.page_frame_number << 12;
    if (!host_physical_range_mapped(pt_base, PAGE_SIZE)) {
        out->status = dbg_page_bad_physical_range;
        out->pte_pa = pt_base;
        return dbg_page_bad_physical_range;
    }

    uint64_t const pte_pa = pt_base + vaddr.pt_idx * sizeof(uint64_t);
    if (!dbg_read_entry_u64(pte_pa, &entry_value)) {
        out->status = dbg_page_bad_physical_range;
        out->pte_pa = pte_pa;
        return dbg_page_bad_physical_range;
    }

    pte_64 pte{};
    pte.flags = entry_value;
    if (!pte.present) {
        dbg_set_not_present_result(out, dbg_page_pt_not_present,
                                   pte_pa, pte.flags);
        return dbg_page_pt_not_present;
    }

    writable = writable && (pte.write != 0);
    user = user && (pte.supervisor != 0);
    nx = nx || (pte.execute_disable != 0);

    uint64_t const gpa = (pte.page_frame_number << 12) + vaddr.offset;
    if (!host_physical_range_mapped(gpa, 1)) {
        out->status = dbg_page_bad_physical_range;
        out->gpa = gpa;
        out->pte_pa = pte_pa;
        out->pte_value = pte.flags;
        return dbg_page_bad_physical_range;
    }

    out->gpa = gpa;
    out->pte_pa = pte_pa;
    out->pte_value = pte.flags;
    out->page_size = PAGE_SIZE;
    out->page_offset = static_cast<uint32_t>(vaddr.offset);
    out->bytes_to_page_end = PAGE_SIZE - static_cast<uint32_t>(vaddr.offset);
    out->status = dbg_page_ok;
    dbg_fill_leaf_flags(out, writable, user, nx);
    return dbg_page_ok;
}

static dbg_page_status dbg_copy_physical_to_guest(uint64_t pa,
                                                  uint64_t out_gva,
                                                  uint32_t size) {
    uint32_t copied = 0;
    while (copied < size) {
        size_t dst_remaining = 0;
        auto const dst = gva2hva(reinterpret_cast<void*>(out_gva + copied),
                                 &dst_remaining);
        if (!dst || !dst_remaining)
            return dbg_page_bad_output;

        uint32_t const src_remaining =
            static_cast<uint32_t>(dbg_min_u64(0x1000ull - ((pa + copied) & 0xfffull),
                                              size - copied));
        uint32_t const chunk =
            dbg_min_u32(src_remaining,
                        static_cast<uint32_t>(dbg_min_u64(dst_remaining,
                                                          size - copied)));

        if (!chunk)
            return dbg_page_bad_request;
        if (!host_physical_range_mapped(pa + copied, chunk))
            return dbg_page_bad_physical_range;

        auto const src = host_physical_to_virtual(pa + copied, chunk);
        if (!src)
            return dbg_page_bad_physical_range;

        host_exception_info e{};
        memcpy_safe(e, dst, src, chunk);
        if (e.exception_occurred)
            return dbg_page_bad_output;

        copied += chunk;
    }
    return dbg_page_ok;
}

static dbg_page_status dbg_zero_to_guest(uint64_t out_gva, uint32_t size) {
    uint8_t zero[64] = {};
    uint32_t written = 0;
    while (written < size) {
        uint32_t const chunk = dbg_min_u32(sizeof(zero), size - written);
        if (dbg_copy_to_guest(out_gva + written, zero, chunk) != chunk)
            return dbg_page_bad_output;
        written += chunk;
    }
    return dbg_page_ok;
}

dbg_page_status dbg_read_virtual_to_guest(uint64_t cr3_value,
                                          uint64_t va,
                                          uint64_t out_gva,
                                          uint32_t size,
                                          uint32_t flags,
                                          uint32_t* bytes_read,
                                          uint32_t* page_count,
                                          uint32_t* hole_count,
                                          uint32_t* first_status) {
    if (bytes_read)
        *bytes_read = 0;
    if (page_count)
        *page_count = 0;
    if (hole_count)
        *hole_count = 0;
    if (first_status)
        *first_status = dbg_page_ok;

    uint32_t done = 0;
    while (done < size) {
        dbg_pte_info info{};
        auto status = dbg_translate_va_ex(cr3_value, va + done, &info);
        if (status != dbg_page_ok) {
            if (first_status && *first_status == dbg_page_ok)
                *first_status = status;
            if (hole_count)
                ++(*hole_count);

            uint32_t const hole_chunk =
                dbg_min_u32(dbg_page_end_4k(va + done), size - done);
            if (flags & dbg_read_allow_holes) {
                auto z = dbg_zero_to_guest(out_gva + done, hole_chunk);
                if (z != dbg_page_ok)
                    return z;
                done += hole_chunk;
                continue;
            }

            if ((flags & dbg_read_allow_partial) && done) {
                if (bytes_read)
                    *bytes_read = done;
                return status;
            }
            if (bytes_read)
                *bytes_read = done;
            return status;
        }

        uint32_t const chunk =
            dbg_min_u32(info.bytes_to_page_end, size - done);
        if (!chunk)
            return dbg_page_bad_request;

        auto copy_status = dbg_copy_physical_to_guest(info.gpa,
                                                      out_gva + done,
                                                      chunk);
        if (copy_status != dbg_page_ok) {
            if (first_status && *first_status == dbg_page_ok)
                *first_status = copy_status;
            if (bytes_read)
                *bytes_read = done;
            return copy_status;
        }

        done += chunk;
        if (page_count)
            ++(*page_count);
    }

    if (bytes_read)
        *bytes_read = done;
    return dbg_page_ok;
}

static uint32_t dbg_copy_basic_req(uint64_t in_gva, uint64_t in_size,
                                   void* req, uint64_t req_size) {
    if (!in_gva || in_size < req_size)
        return dbg_err_bad_packet;
    return dbg_copy_from_guest(in_gva, req, static_cast<size_t>(req_size)) == req_size
        ? dbg_ok
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_translate_va(vcpu* /*cpu*/, const dbg_packet_header& h,
                              uint64_t in_gva, uint64_t in_size,
                              uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_translate_va_rsp))
        return dbg_err_bad_buffer;

    dbg_translate_va_req req{};
    auto st = dbg_copy_basic_req(in_gva, in_size, &req, sizeof(req));
    if (st != dbg_ok)
        return st;

    dbg_translate_va_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    dbg_translate_va_ex(req.cr3, req.va, &rsp.info);
    rsp.h.bytes_written = sizeof(rsp);

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_query_pte(vcpu* cpu, const dbg_packet_header& h,
                           uint64_t in_gva, uint64_t in_size,
                           uint64_t out_gva, uint64_t out_size) {
    return dbg_cmd_translate_va(cpu, h, in_gva, in_size, out_gva, out_size);
}

uint32_t dbg_cmd_read_va(vcpu* /*cpu*/, const dbg_packet_header& h,
                         uint64_t in_gva, uint64_t in_size,
                         uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_read_va_rsp))
        return dbg_err_bad_buffer;

    dbg_read_va_req req{};
    auto st = dbg_copy_basic_req(in_gva, in_size, &req, sizeof(req));
    if (st != dbg_ok)
        return st;

    dbg_read_va_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.requested = req.size;

    if (req.size > dbg_max_read_size && !(req.flags & dbg_read_allow_partial)) {
        rsp.h.status = dbg_err_too_large;
        rsp.first_status = dbg_page_too_large;
        rsp.h.bytes_written = sizeof(rsp);
        dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp));
        return dbg_err_too_large;
    }

    uint32_t const capacity =
        out_size > sizeof(rsp)
            ? static_cast<uint32_t>(dbg_min_u64(out_size - sizeof(rsp),
                                                dbg_max_read_size))
            : 0;
    uint32_t to_read = req.size;
    if (to_read > dbg_max_read_size)
        to_read = dbg_max_read_size;

    if (to_read > capacity) {
        if (!(req.flags & dbg_read_allow_partial))
            return dbg_err_bad_buffer;
        to_read = capacity;
    }

    uint32_t first_status = dbg_page_ok;
    auto read_status = dbg_read_virtual_to_guest(req.cr3, req.va,
                                                 out_gva + sizeof(rsp),
                                                 to_read, req.flags,
                                                 &rsp.read,
                                                 &rsp.page_count,
                                                 &rsp.hole_count,
                                                 &first_status);
    rsp.first_status = first_status ? first_status : read_status;
    rsp.h.status = dbg_ok;
    rsp.h.bytes_written = sizeof(rsp) + rsp.read;
    if ((req.flags & dbg_read_allow_holes) && rsp.read < to_read)
        rsp.h.bytes_written = sizeof(rsp) + to_read;

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_read_pa(vcpu* /*cpu*/, const dbg_packet_header& h,
                         uint64_t in_gva, uint64_t in_size,
                         uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_read_pa_rsp))
        return dbg_err_bad_buffer;

    dbg_read_pa_req req{};
    auto st = dbg_copy_basic_req(in_gva, in_size, &req, sizeof(req));
    if (st != dbg_ok)
        return st;

    dbg_read_pa_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.requested = req.size;

    if (req.size > dbg_max_read_size && !(req.flags & dbg_read_allow_partial)) {
        rsp.status = dbg_page_too_large;
        rsp.h.status = dbg_err_too_large;
        rsp.h.bytes_written = sizeof(rsp);
        dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp));
        return dbg_err_too_large;
    }

    uint32_t const capacity =
        out_size > sizeof(rsp)
            ? static_cast<uint32_t>(dbg_min_u64(out_size - sizeof(rsp),
                                                dbg_max_read_size))
            : 0;
    uint32_t to_read = req.size;
    if (to_read > dbg_max_read_size)
        to_read = dbg_max_read_size;
    if (to_read > capacity) {
        if (!(req.flags & dbg_read_allow_partial))
            return dbg_err_bad_buffer;
        to_read = capacity;
    }

    if (!host_physical_range_mapped(req.pa, to_read)) {
        rsp.status = dbg_page_bad_physical_range;
        rsp.h.bytes_written = sizeof(rsp);
        dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp));
        return dbg_ok;
    }

    auto copy_status = dbg_copy_physical_to_guest(req.pa,
                                                  out_gva + sizeof(rsp),
                                                  to_read);
    rsp.status = copy_status;
    if (copy_status == dbg_page_ok) {
        rsp.read = to_read;
        rsp.page_count = (to_read + static_cast<uint32_t>(req.pa & 0xfff) + 0xfff) >> 12;
    }
    rsp.h.bytes_written = sizeof(rsp) + rsp.read;

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

uint32_t dbg_cmd_read_va_batch(vcpu* /*cpu*/, const dbg_packet_header& h,
                               uint64_t in_gva, uint64_t in_size,
                               uint64_t out_gva, uint64_t out_size) {
    if (out_size < sizeof(dbg_read_batch_rsp))
        return dbg_err_bad_buffer;

    struct batch_head {
        dbg_packet_header h;
        uint32_t count;
        uint32_t flags;
    } head{};

    constexpr uint64_t head_size = sizeof(batch_head);
    if (!in_gva || in_size < head_size)
        return dbg_err_bad_packet;
    if (dbg_copy_from_guest(in_gva, &head, sizeof(head)) != sizeof(head))
        return dbg_err_bad_buffer;

    if (head.count > dbg_max_batch_items)
        return dbg_err_too_large;

    uint64_t const items_size =
        static_cast<uint64_t>(head.count) * sizeof(dbg_read_item);
    if (in_size < head_size + items_size)
        return dbg_err_bad_packet;

    dbg_read_item items[dbg_max_batch_items] = {};
    if (items_size) {
        if (dbg_copy_from_guest(in_gva + head_size, items,
                                static_cast<size_t>(items_size)) != items_size)
            return dbg_err_bad_buffer;
    }

    dbg_read_batch_rsp rsp{};
    dbg_fill_result(rsp.h, h, dbg_ok, sizeof(rsp));
    rsp.count = head.count;

    uint64_t const data_capacity64 = out_size - sizeof(rsp);
    uint32_t const data_capacity =
        static_cast<uint32_t>(dbg_min_u64(data_capacity64,
                                          dbg_max_batch_data_size));
    uint32_t data_size = 0;

    for (uint32_t i = 0; i < head.count; ++i) {
        auto const& item = items[i];
        auto& r = rsp.results[i];
        r.requested = item.size;
        r.out_offset = item.out_offset;
        r.status = dbg_page_ok;

        if (item.size > dbg_max_batch_item_size) {
            r.status = dbg_page_too_large;
            continue;
        }
        if (item.out_offset > data_capacity ||
            item.size > data_capacity - item.out_offset) {
            r.status = dbg_page_bad_output;
            continue;
        }

        uint32_t first_status = dbg_page_ok;
        uint32_t page_count = 0;
        uint32_t hole_count = 0;
        auto status = dbg_read_virtual_to_guest(item.cr3, item.va,
                                                out_gva + sizeof(rsp) + item.out_offset,
                                                item.size, head.flags,
                                                &r.read,
                                                &page_count,
                                                &hole_count,
                                                &first_status);
        r.status = first_status ? first_status : status;
        if (status == dbg_page_ok && r.status == dbg_page_ok) {
            uint32_t const end = item.out_offset + item.size;
            if (end > data_size)
                data_size = end;
        } else if (r.read) {
            uint32_t const end = item.out_offset + r.read;
            if (end > data_size)
                data_size = end;
        }
    }

    rsp.data_size = data_size;
    rsp.h.bytes_written = sizeof(rsp) + data_size;

    return dbg_copy_to_guest(out_gva, &rsp, sizeof(rsp)) == sizeof(rsp)
        ? dbg_ok
        : dbg_err_bad_buffer;
}

} // namespace hv
