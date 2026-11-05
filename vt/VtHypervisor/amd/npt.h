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
// 单个执行视图最多同时展开 32 个离散 2MiB 物理块。该上限覆盖 Notepad
// .text、WndProc 与 X2 的常见布局；超过上限时保持原有失败关闭路径。
inline constexpr size_t npt_exec_view_max_blocks = 32;

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
	// NPT 的执行视图不能假设 Guest 虚拟连续页对应物理连续页。
	// 为每个离散 2MiB 物理块准备独立的 PD/PT，避免跨页取指时回退到
	// 普通根造成 #NPF 乒乓。所有页表均为内嵌存储，VM-exit 路径不分配内存。
	alignas(0x1000) pde_64 pd_pool[npt_exec_view_max_blocks][512];
	alignas(0x1000) pte_64 pt_pool[npt_exec_view_max_blocks][512];
	u64 pd_pfns[npt_exec_view_max_blocks];
	u64 pt_pfns[npt_exec_view_max_blocks];
	u64 pt_base_pfns[npt_exec_view_max_blocks];
	uint16_t pdpt_block_index[npt_pd_count];
	uint16_t pd_count;
	uint16_t pt_count;
	uint16_t _pool_pad;

	u64 pml4_pa;
	u64 active_orig_pfn;
	u64 active_exec_pfn;
	u64 active_base_pfn;
	u64 cached_hook_generation;
	// 记录构建失败的 hook_generation：同一代内不再重复重建/单步回退，
	// 结构变化（hook 增删）后自动重试。
	u64 failed_hook_generation;
	bool active;
	bool tlb_flush_required;
	bool _pad[6];
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
	u64 hook_generation;
	u64 mapping_generation;
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
bool activate_npt_exec_view(npt_data& npt, npt_hook_node const& hook);
void deactivate_npt_exec_view(npt_data& npt);
void mark_npt_structure_changed(npt_data& npt);
void mark_npt_mapping_changed(npt_data& npt);

} // namespace svm
