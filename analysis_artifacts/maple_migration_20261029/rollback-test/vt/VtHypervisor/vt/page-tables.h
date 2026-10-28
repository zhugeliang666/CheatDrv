#pragma once

#include <ia32.hpp>

#define PAGE_SIZE 0x1000
namespace hv {

// how much of 物理内存 to map into the host 地址-space
inline constexpr size_t host_physical_memory_pd_count = 512;
inline constexpr uint64_t host_physical_memory_bytes =
  host_physical_memory_pd_count * 512ull * 0x200000ull;

inline bool host_physical_range_mapped(uint64_t pa, uint64_t size = PAGE_SIZE) {
  if (pa >= host_physical_memory_bytes)
    return false;
  return size <= host_physical_memory_bytes - pa;
}

// 物理内存 is directly mapped to this pml4 条目项
inline constexpr uint64_t host_physical_memory_pml4_idx = 255;

// Host page-表 scratch pool. Used by map_page() (page-tables.cpp) to back
// PDPT/PD/PT entries created when host VA mappings are added.
//
// Real-world usage is ~0x33 pages on a 2-vcpu config (after the large_page
// PDE fix that lets us inherit system_cr3 2MB mappings instead of building
// PT under them). 0x1000 = 16MB scratch is intentionally oversized so future
// vcpu_count bumps or inline-表 growth never silently overflow. map_page()
// failure is silent and causes host triple fault when accessed.
//
// If you need to shrink ghv's footprint, this is the easiest 10+MB to recover
// (drop to 0x100 = 1MB scratch which still leaves ~5x headroom over peak).
inline constexpr  uint64_t pages_max =  0x1000;

// directly access 物理内存 by using [base + 偏移]
inline uint8_t* const host_physical_memory_base = reinterpret_cast<uint8_t*>(
  host_physical_memory_pml4_idx << (9 + 9 + 9 + 12));

inline uint8_t* host_physical_to_virtual(uint64_t pa, uint64_t size = PAGE_SIZE) {
  if (!host_physical_range_mapped(pa, size))
    return nullptr;
  return host_physical_memory_base + pa;
}

struct host_page_tables {
  // 数组 of PML4 entries that point to a PDPT
  alignas(0x1000) pml4e_64 pml4[512];

  // PDPT for mapping 物理内存
  alignas(0x1000) pdpte_64 phys_pdpt[512];

  // PDs for mapping 物理内存
  alignas(0x1000) pde_2mb_64 phys_pds[host_physical_memory_pd_count][512];

  // 数组 for
  alignas((0x1000)) char pages[PAGE_SIZE * pages_max];

  uint64_t pages_pfns[pages_max];
  uint64_t pml4_pfn;
  uint64_t page_use;
};

// 初始化 the host page tables
bool prepare_host_page_tables();
bool map_host_virtual_range(uint64_t va, size_t size);

void update_cr3_monitor_info();


void update_cr3_map_info();


} // namespace hv

