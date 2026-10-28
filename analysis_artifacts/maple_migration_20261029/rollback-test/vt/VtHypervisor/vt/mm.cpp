#include "mm.h"
#include "arch.h"
#include "page-tables.h"
#include "vmx.h"
#include "exception-routines.h"
#include "logger.h"

#include "xorstr.h"


namespace hv {
#pragma code_seg(".vm")

static bool host_direct_range_ok(uint64_t pa, size_t size) {
  if (pa >= host_physical_memory_bytes)
    return false;
  return size <= host_physical_memory_bytes - pa;
}

static void* host_direct_va(uint64_t pa, size_t size = PAGE_SIZE) {
  if (!host_direct_range_ok(pa, size))
    return nullptr;
  return host_physical_memory_base + pa;
}

// translate a GVA to a GPA. offset_to_next_page is the number of bytes to
// the next page (i.e. the number of bytes that can be safely accessed through
// the GPA in order to modify the GVA.
uint64_t gva2gpa(cr3 const guest_cr3, void* const gva, size_t* const offset_to_next_page) {
  if (offset_to_next_page)
    *offset_to_next_page = 0;

  pml4_virtual_address const vaddr = { gva };

  // guest PML4
  auto const pml4 = reinterpret_cast<pml4e_64*>(
    host_direct_va(guest_cr3.address_of_page_directory << 12));
  if (!pml4)
    return 0;
  auto const pml4e = pml4[vaddr.pml4_idx];

  if (!pml4e.present)
    return 0;

  // guest PDPT
  auto const pdpt = reinterpret_cast<pdpte_64*>(
    host_direct_va(pml4e.page_frame_number << 12));
  if (!pdpt)
    return 0;
  auto const pdpte = pdpt[vaddr.pdpt_idx];

  if (!pdpte.present)
    return 0;

  if (pdpte.large_page) {
    pdpte_1gb_64 pdpte_1gb;
    pdpte_1gb.flags = pdpte.flags;

    auto const offset = (vaddr.pd_idx << 21) + (vaddr.pt_idx << 12) + vaddr.offset;

    // 1GB
    if (offset_to_next_page)
      *offset_to_next_page = 0x40000000 - offset;

    return (pdpte_1gb.page_frame_number << 30) + offset;
  }

  // guest PD
  auto const pd = reinterpret_cast<pde_64*>(
    host_direct_va(pdpte.page_frame_number << 12));
  if (!pd)
    return 0;
  auto const pde = pd[vaddr.pd_idx];

  if (!pde.present)
    return 0;

  if (pde.large_page) {
    pde_2mb_64 pde_2mb;
    pde_2mb.flags = pde.flags;

    auto const offset = (vaddr.pt_idx << 12) + vaddr.offset;

    // 2MB page
    if (offset_to_next_page)
      *offset_to_next_page = 0x200000 - offset;

    return (pde_2mb.page_frame_number << 21) + offset;
  }

  // guest PT
  auto const pt = reinterpret_cast<pte_64*>(
    host_direct_va(pde.page_frame_number << 12));
  if (!pt)
    return 0;
  auto const pte = pt[vaddr.pt_idx];

  if (!pte.present)
    return 0;

  // 4KB page
  if (offset_to_next_page)
    *offset_to_next_page = 0x1000 - vaddr.offset;

  return (pte.page_frame_number << 12) + vaddr.offset;
}

// translate a GVA to a GPA. offset_to_next_page is the number of bytes to
// the next page (i.e. the number of bytes that can be safely accessed through
// the GPA in order to modify the GVA.
uint64_t gva2gpa(void* const gva, size_t* const offset_to_next_page) {
  cr3 guest_cr3;
  guest_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);
  return gva2gpa(guest_cr3, gva, offset_to_next_page);
}

// translate a GVA to an HVA. offset_to_next_page is the number of bytes to
// the next page (i.e. the number of bytes that can be safely accessed through
// the HVA in order to modify the GVA.
void* gva2hva(cr3 const guest_cr3, void* const gva, size_t* const offset_to_next_page) {
  auto const gpa = gva2gpa(guest_cr3, gva, offset_to_next_page);
  if (!gpa)
    return nullptr;
  return host_direct_va(gpa, offset_to_next_page ? *offset_to_next_page : 1);
}

// translate a GVA to an HVA. offset_to_next_page is the number of bytes to
// the next page (i.e. the number of bytes that can be safely accessed through
// the HVA in order to modify the GVA.
void* gva2hva(void* const gva, size_t* const offset_to_next_page) {
  cr3 guest_cr3;
  guest_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);
  return gva2hva(guest_cr3, gva, offset_to_next_page);
}

// attempt to 读取 the memory at the specified Guest 虚拟地址(GVA) from root-模式
size_t read_guest_virtual_memory(cr3 const guest_cr3,
    void* const gva, void* const buffer, size_t const size) {
  // the GVA that we're reading from
  auto const src = reinterpret_cast<uint8_t*>(gva);

  // the HVA that we're writing to
  auto const dst = reinterpret_cast<uint8_t*>(buffer);

  size_t bytes_read = 0;

  // translate and 读取 1 page at a time
  while (bytes_read < size) {
    size_t src_remaining = 0;

    // translate the Guest 虚拟地址(GVA) to a Host 虚拟地址(HVA)
    auto const curr_src = gva2hva(guest_cr3, src + bytes_read, &src_remaining);

    // paged out
    if (!curr_src)
      return bytes_read;

    // the 最大 allowed 大小尺寸 that we can 读取 at once with the translated HVA
    auto const curr_size = min(size - bytes_read, src_remaining);

    host_exception_info e;
    memcpy_safe(e, dst + bytes_read, curr_src, curr_size);

    // this shouldn't ever happen...
    if (e.exception_occurred) {
      HV_LOG_ERROR(_XOR_("Failed to memcpy in read_guest_virtual_memory()."));
      return bytes_read;
    }

    bytes_read += curr_size;
  }

  return bytes_read;
}

// attempt to 读取 the memory at the specified Guest 虚拟地址(GVA) from root-模式
size_t read_guest_virtual_memory(void* const gva, void* const buffer, size_t const size) {
  cr3 guest_cr3;
  guest_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);
  return read_guest_virtual_memory(guest_cr3, gva, buffer, size);
}

// attempt to 写入 the memory at the specified Guest 虚拟地址(GVA) from root-模式
size_t write_guest_virtual_memory(cr3 const guest_cr3,
    void* const gva, void const* const buffer, size_t const size) {
  if (!gva || !buffer || !size)
    return 0;

  auto const first = reinterpret_cast<uintptr_t>(gva);
  if (size - 1 > ~static_cast<uintptr_t>(0) - first)
    return 0;

  auto const src = reinterpret_cast<uint8_t const*>(buffer);

  // Preflight every guest page before modifying any destination byte. This is
  // required for fixed-size ABI records whose caller buffer can start near the
  // end of a page and continue in a non-contiguous physical page.
  size_t validated = 0;
  while (validated < size) {
    size_t dst_remaining = 0;
    auto const curr_gva = reinterpret_cast<void*>(first + validated);
    auto const curr_dst = gva2hva(guest_cr3, curr_gva, &dst_remaining);
    if (!curr_dst || !dst_remaining)
      return 0;

    validated += min(size - validated, dst_remaining);
  }

  size_t bytes_written = 0;
  while (bytes_written < size) {
    size_t dst_remaining = 0;
    auto const curr_gva = reinterpret_cast<void*>(first + bytes_written);
    auto const curr_dst = gva2hva(guest_cr3, curr_gva, &dst_remaining);
    if (!curr_dst || !dst_remaining)
      return bytes_written;

    auto const curr_size = min(size - bytes_written, dst_remaining);
    host_exception_info e;
    memcpy_safe(e, curr_dst, src + bytes_written, curr_size);
    if (e.exception_occurred) {
      HV_LOG_ERROR(_XOR_("Failed to memcpy in write_guest_virtual_memory()."));
      return bytes_written;
    }

    bytes_written += curr_size;
  }

  return bytes_written;
}

// attempt to 写入 the memory at the specified Guest 虚拟地址(GVA) from root-模式
size_t write_guest_virtual_memory(void* const gva, void const* const buffer, size_t const size) {
  cr3 guest_cr3;
  guest_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);
  return write_guest_virtual_memory(guest_cr3, gva, buffer, size);
}

// attempt to 读取 the memory at the specified Guest 物理地址(GPA) from root-模式
bool read_guest_physical_memory(uint64_t const gpa, void* const buffer, size_t const size) {
  auto const hva = host_direct_va(gpa, size);
  if (!hva)
    return false;
  host_exception_info e;
  memcpy_safe(e, buffer, hva, size);
  return !e.exception_occurred;
}

} // namespace hv
