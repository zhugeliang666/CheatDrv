#pragma once

#include "amd64.h"
#include "../ia32.hpp"

namespace svm {

inline constexpr size_t npt_pd_count = 512; // 512 GB with 2 MB leaves.
// PFN 隐藏会把命中的 2MiB identity leaf 拆成 4KiB PT。Resident pool
// 页面物理上并不保证连续，0x400 个 PT 页在 31K 级别的隐藏批次下
// 可能被离散物理区域耗尽，后续 NVIDIA BAR/MMIO 的 NPF 会落入 #GP。
// 预留 0x1000 个 PT 页，仍保持每个 vCPU 独立分配，避免 VM-exit 路径
// 动态申请分页内存。
inline constexpr size_t npt_free_pt_count = 0x1000;

struct npt_hook_node {
	npt_hook_node* next;
	u64 orig_pfn;
	u64 exec_pfn;
	// 与 Intel EPT 的 ept_view_mode 保持一致：
	// 0=执行影子/读取原页，1=执行原页/读取影子，2=执行影子/读取零页。
	u8 view_mode;
	u8 reserved[7];
};

struct npt_hooks {
	static constexpr size_t capacity = 0x300;
	npt_hook_node buffer[capacity];
	npt_hook_node* active_list_head;
	npt_hook_node* free_list_head;
};

struct npt_single_step_restore {
	bool active;
	bool owned_tf;
	u64 saved_rflags;
	pte_64* pte;
	u64 restore_pfn;
	bool restore_present;
	bool restore_write;
	bool restore_nx;
};

struct npt_exec_view {
	alignas(0x1000) pml4e_64 pml4[512];
	alignas(0x1000) pdpte_64 pdpt[512];
	union {
		alignas(0x1000) u64 pd_raw[512];
		alignas(0x1000) pde_64 pd[512];
		alignas(0x1000) pde_2mb_64 pd_2mb[512];
	};
	alignas(0x1000) pte_64 pt[512];

	u64 pml4_pa;
	u64 pd_pfn;
	u64 pt_pfn;
	u64 active_orig_pfn;
	u64 active_exec_pfn;
	u64 active_base_pfn;
	u64 cached_generation;
	u64 cached_orig_pfn;
	u64 cached_exec_pfn;
	bool active;
	bool _pad[7];
};

struct npt_data {
	alignas(0x1000) pml4e_64 pml4[512];
	alignas(0x1000) pdpte_64 pdpt[512];
	union {
		alignas(0x1000) pde_64 pds[npt_pd_count][512];
		alignas(0x1000) pde_2mb_64 pds_2mb[npt_pd_count][512];
	};
	alignas(0x1000) pte_64 free_pts[npt_free_pt_count][512];
	u64 free_pt_pfns[npt_free_pt_count];
	size_t num_used_free_pts;

	alignas(0x1000) u8 dummy_page[0x1000];
	u64 dummy_page_pfn;
	u64 generation;
	npt_hooks hooks;
	npt_single_step_restore pending_restore;
	npt_exec_view exec_view;
	// 仅用于诊断页表容量耗尽；放在结构尾部，保持既有 ABI 偏移稳定。
	volatile u64 split_failures;
	volatile u64 dynamic_map_failures;
};

void prepare_npt(npt_data& npt);
bool ensure_npt_mapped(npt_data& npt, u64 physical_address);
pdpte_64* get_npt_pdpte(npt_data& npt, u64 physical_address);
pde_2mb_64* get_npt_pde_2mb(npt_data& npt, u64 physical_address);
pte_64* get_npt_pte(npt_data& npt, u64 physical_address, bool force_split = false);
bool install_npt_hook(npt_data& npt, u64 original_page_pfn, u64 executable_page_pfn, u8 view_mode);
void remove_npt_hook(npt_data& npt, u64 original_page_pfn);
npt_hook_node* find_npt_hook(npt_data& npt, u64 original_page_pfn);
u64 npt_exec_root_pa(npt_data& npt);
bool npt_exec_view_active(npt_data const& npt);
bool npt_exec_view_contains(npt_data const& npt, u64 physical_address);
bool activate_npt_exec_view(npt_data& npt, npt_hook_node const& hook);
void deactivate_npt_exec_view(npt_data& npt);
void mark_npt_changed(npt_data& npt);

} // namespace svm
