#pragma once

#include <ia32.hpp>

#include "mtrr.h"
#include "spin-lock.h"

namespace hv {

struct vcpu;



struct _mtrr_range
{
    uint64_t physical_base_address;
    uint64_t physical_end_address;
    uint64_t memory_type;
    bool fixed_range;

};

struct mtrr_data
{
    ia32_mtrr_capabilities_register cap;
    ia32_mtrr_def_type_register def_type;

    _mtrr_range mtrr_range[120];


    size_t mtrr_range_count;
    //Ĭ������
    uint64_t default_memory_type;
};

// number of PDs in the EPT paging structures
inline constexpr size_t ept_pd_count = 512;
#ifndef VT_EPT_FREE_PAGE_SPLIT_COUNT
// 每个拆分页表覆盖一个 2 MiB 的 GPA 区域。因此 0x400 支持每个 vCPU 拥有 1024 个
// 独立的拆分区域，同时将每个 vCPU 的默认预留内存从 48 MiB 缩减到 4 MiB。
// 诊断计数器（最大使用量）可用于针对特定工作负载进行动态重配。
#define VT_EPT_FREE_PAGE_SPLIT_COUNT 0x400
#endif
inline constexpr size_t ept_free_page_count = VT_EPT_FREE_PAGE_SPLIT_COUNT;

// max number of MMRs
inline constexpr size_t ept_mmr_count = 120;

struct vcpu_ept_hook_node {
  vcpu_ept_hook_node* next;

  // these can be stored as 32-bit integers to conserve space since
  // nobody is going to have more than 16,000 GB of 物理内存
  uint32_t orig_pfn;
  uint32_t exec_pfn;
  uint8_t is_fake_page; // ept_view_mode；保留旧字段名与偏移。
};

// TODO: refactor this to just use an 数组 instead of a linked list
struct vcpu_ept_hooks {
  // 缓冲区 of nodes (there can be unused nodes in the middle
  // of the 缓冲区 if a hook was removed for example)
  static constexpr size_t capacity = 0x300;
  vcpu_ept_hook_node buffer[capacity];

  // list of currently active EPT hooks
  vcpu_ept_hook_node* active_list_head;

  // list of unused nodes
  vcpu_ept_hook_node* free_list_head;
};


struct vcpu_bp_hook_node
{
    vcpu_bp_hook_node* next;

    uint64_t cr3;
    uint64_t origin_guest_va;
    uint64_t origin_guest_pa;

    uint64_t fake_guest_va;
    uint64_t fake_guest_pa;

    bool is_cr3_monitor_hook;

};


struct vcpu_bp_hooks
{
    static constexpr  size_t capacity = 30;

    vcpu_bp_hook_node buffer[capacity];

    vcpu_bp_hook_node* active_list_head;

    vcpu_bp_hook_node* free_list_head;
};





// TODO: make this a bitfield instead
enum mmr_memory_mode {
  mmr_memory_mode_r = 0b001,
  mmr_memory_mode_w = 0b010,
  mmr_memory_mode_x = 0b100
};

// monitored memory ranges
struct vcpu_ept_mmr_entry {

  // start physical 地址
  uint64_t pa;

  // 大小尺寸 of the range in bytes, a 值 of 0 indicates that this 条目项 isn't being used
  uint32_t size;

  // the memory access type that we are monitoring for
  uint8_t mode;

};

// One-shot 恢复 状态 used by the generic EPT probe path.  Kept separate
// from mmr_mtf_* so the dynamic INT3 probe does not reuse or overwrite the
// existing hook/MMR 单步执行 bookkeeping.
struct ept_probe_mtf_state {
  bool     active;
  ept_pte* pte;
  uint64_t orig_pfn;
  uint64_t shadow_pfn;
  uint64_t slot_id;
};


struct vcpu_ept_data {
  // EPT PML4
  alignas(0x1000) ept_pml4e pml4[512];

  // EPT PDPT - a single one covers 512GB of 物理内存
  alignas(0x1000) ept_pdpte pdpt[512];
  static_assert(ept_pd_count <= 512, "Only 512 EPT PDs are supported!");

  // an 数组 of EPT PDs - each PD covers 1GB
  union {
    alignas(0x1000) ept_pde     pds[ept_pd_count][512];
    alignas(0x1000) ept_pde_2mb pds_2mb[ept_pd_count][512];
  };

  // 释放 pages that can be used to split PDEs or for other purposes
  alignas(0x1000) uint8_t free_pages[ept_free_page_count][0x1000];

  // a dummy page that hidden pages are pointed to
  uint64_t dummy_page_pfn;

  // an 数组 of PFNs that point to each 释放 page in the 释放 page 数组
  uint64_t free_page_pfns[ept_free_page_count];

  // # of free pages that are currently in use
  size_t num_used_free_pages;


  mtrr_data mtrrs;

  // EPT hooks
  vcpu_ept_hooks hooks;


  vcpu_bp_hooks bp_hooks;

  // monitored memory ranges
  vcpu_ept_mmr_entry mmr[ept_mmr_count];



  // PTE of the page that we should re-启用 memory monitoring on
  ept_pte* mmr_mtf_pte;
  uint8_t  mmr_mtf_mode;
  uint64_t mmr_mtf_page_frame;

  ept_probe_mtf_state probe_mtf;

  bool is_cr3_monitor;

};

// identity-map the EPT paging structures
void prepare_ept(vcpu_ept_data& ept);

// 更新 the memory types in the EPT paging structures based on the MTRRs.
// this 函数 should only be called from root-模式 during vmx-operation.
void update_ept_memory_type(vcpu_ept_data& ept);

// 设置 the memory type in every EPT paging 结构体 to the specified 值
void set_ept_memory_type(vcpu_ept_data& ept, uint8_t memory_type);

// 获取 the corresponding EPT PDPTE for a given physical 地址
ept_pdpte* get_ept_pdpte(vcpu_ept_data& ept, uint64_t physical_address);

// 获取 the corresponding EPT PDE for a given physical 地址
ept_pde* get_ept_pde(vcpu_ept_data& ept, uint64_t physical_address);

// 获取 the corresponding EPT PTE for a given physical 地址
ept_pte* get_ept_pte(vcpu_ept_data& ept,
    uint64_t physical_address, bool force_split = false);

// split a 2MB EPT PDE so that it points to an EPT PT
void split_ept_pde(vcpu_ept_data& ept, ept_pde_2mb* pde_2mb);

// memory 读取/written will use the original page while code
// being executed will use the executable page instead
bool install_ept_hook(vcpu_ept_data& ept,
    uint64_t original_page_pfn, uint64_t executable_page_pfn, uint8_t view_mode);

// 卸载移除 an EPT hook that was installed with install_ept_hook()
void remove_ept_hook(vcpu_ept_data& ept, uint64_t original_page_pfn);

// find the EPT hook for the specified PFN
vcpu_ept_hook_node* find_ept_hook(vcpu_ept_data& ept, uint64_t original_page_pfn);


bool install_bp_hook(vcpu_ept_data& ept, uint64_t cr3, uint64_t original_va, uint64_t fake_va,bool is_cr3_monitor_hook);

void remove_bp_hook(vcpu_ept_data& ept, uint64_t cr3, uint64_t original_va);

vcpu_bp_hook_node* find_bp_hook(vcpu_ept_data& ept, uint64_t cr3, uint64_t original_va);
} // namespace hv

