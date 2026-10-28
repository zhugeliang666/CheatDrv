#include "npt.h"
#include "../base.h"
#include "../vt/page-tables.h"
#include "../base.h"

namespace svm {

namespace {

constexpr u64 paging_nx_bit = 1ull << 63;

static void init_hook_lists(npt_data& npt) {
	npt.hooks.active_list_head = nullptr;
	npt.hooks.free_list_head = &npt.hooks.buffer[0];

	for (size_t i = 0; i < npt.hooks.capacity - 1; ++i)
		npt.hooks.buffer[i].next = &npt.hooks.buffer[i + 1];

	npt.hooks.buffer[npt.hooks.capacity - 1].next = nullptr;
}

static u64 phys_pfn(void* va) {
	return MmGetPhysicalAddress(va).QuadPart >> 12;
}

static u64 phys_pa(void* va) {
	return MmGetPhysicalAddress(va).QuadPart;
}

// NPT 的页表页来自 npt_data::free_pts[]，其物理页可能位于 Host 物理
// 线性窗口（当前窗口为 512 GiB）之外。VM-exit 期间不能依赖
// MmGetVirtualForPhysical()，因为当前 CR3 是自有 Host CR3；同时也不能
// 让 host_physical_to_virtual() 把这些已由本 vCPU 映射的页误判为不可达。
// 优先按 PFN 回查本 vCPU 的页表页，只有不属于本地页表池时才回退到
// Host 物理窗口。该路径仅访问页表元数据，不放宽任意物理内存读取范围。
static void* npt_page_virtual(npt_data& npt, u64 const pfn)
{
	if (!pfn)
		return nullptr;

	size_t const used =
		npt.num_used_free_pts < npt_free_pt_count
			? npt.num_used_free_pts
			: npt_free_pt_count;
	for (size_t i = 0; i < used; ++i)
	{
		if (npt.free_pt_pfns[i] == pfn)
			return npt.free_pts[i];
	}

	return hv::host_physical_to_virtual(pfn << 12);
}

static void fill_pt_from_2mb(pte_64* const pt, pde_2mb_64 const& large_pde) {
	u64 const base_pfn = large_pde.page_frame_number << 9;

	for (size_t i = 0; i < 512; ++i) {
		auto& pte = pt[i];
		pte.flags = 0;
		pte.present = large_pde.present;
		pte.write = large_pde.write;
		pte.supervisor = large_pde.supervisor;
		pte.page_level_write_through = large_pde.page_level_write_through;
		pte.page_level_cache_disable = large_pde.page_level_cache_disable;
		pte.pat = large_pde.pat;
		pte.global = large_pde.global;
		pte.page_frame_number = base_pfn + i;
		pte.execute_disable = large_pde.execute_disable;
	}
}

static bool split_2mb_pde(npt_data& npt, u64 const physical_address) {
	auto const large_pde = get_npt_pde_2mb(npt, physical_address);
	if (!large_pde || !large_pde->large_page)
		return large_pde != nullptr;

	if (npt.num_used_free_pts >= npt_free_pt_count)
		return false;

	size_t const pt_idx = npt.num_used_free_pts++;
	auto const pt = npt.free_pts[pt_idx];
	fill_pt_from_2mb(pt, *large_pde);

	auto& pde = *reinterpret_cast<pde_64*>(large_pde);
	pde.flags = 0;
	pde.present = 1;
	pde.write = 1;
	// AMD NPT uses the normal x86 U/S bit.  DBVM sets US=1 for all nested
	// paging levels so user-模式 guest accesses are not blocked by NPT.
	pde.supervisor = 1;
	pde.page_frame_number = npt.free_pt_pfns[pt_idx];
	return true;
}

static void init_exec_view(npt_data& npt) {
	auto& exec = npt.exec_view;
	RtlZeroMemory(&exec, sizeof(exec));

	auto& pml4e = exec.pml4[0];
	pml4e.flags = 0;
	pml4e.present = 1;
	pml4e.write = 1;
	pml4e.supervisor = 1;
	pml4e.page_frame_number = phys_pfn(exec.pdpt);
	pml4e.execute_disable = 0;

	for (size_t i = 0; i < npt_pd_count; ++i) {
		exec.pdpt[i].flags = npt.pdpt[i].flags;
		exec.pdpt[i].execute_disable = 1;
	}

	exec.pml4_pa = phys_pa(exec.pml4);
	exec.pd_pfn = phys_pfn(exec.pd_raw);
	exec.pt_pfn = phys_pfn(exec.pt);
}

static pte_64* normal_pt_for_2mb(npt_data& npt, u64 const physical_address) {
	if (!get_npt_pte(npt, physical_address, true))
		return nullptr;

	u64 const pdpt_idx = (physical_address >> 30) & 0x1ff;
	u64 const pd_idx = (physical_address >> 21) & 0x1ff;
	auto& pde = npt.pds[pdpt_idx][pd_idx];
	if (!pde.present)
		return nullptr;



	return reinterpret_cast<pte_64*>(npt_page_virtual(npt, pde.page_frame_number));
}

static u64 hook_exec_pfn(npt_hook_node const& hook) {
	return hook.is_fake_page ? hook.orig_pfn : hook.exec_pfn;
}

static u64 hook_read_pfn(npt_hook_node const& hook) {
	return hook.is_fake_page ? hook.exec_pfn : hook.orig_pfn;
}

} // namespace

void prepare_npt(npt_data& npt) {
	RtlZeroMemory(&npt, sizeof(npt));

	auto& pml4e = npt.pml4[0];
	pml4e.flags = 0;
	pml4e.present = 1;
	pml4e.write = 1;
	pml4e.supervisor = 1;
	pml4e.page_frame_number = phys_pfn(npt.pdpt);

	for (size_t pdpt_idx = 0; pdpt_idx < npt_pd_count; ++pdpt_idx) {
		auto& pdpte = npt.pdpt[pdpt_idx];
		pdpte.flags = 0;
		pdpte.present = 1;
		pdpte.write = 1;
		pdpte.supervisor = 1;
		pdpte.page_frame_number = phys_pfn(npt.pds_2mb[pdpt_idx]);

		for (size_t pd_idx = 0; pd_idx < 512; ++pd_idx) {
			auto& pde = npt.pds_2mb[pdpt_idx][pd_idx];
			pde.flags = 0;
			pde.present = 1;
			pde.write = 1;
			pde.supervisor = 1;
			pde.large_page = 1;
			pde.page_frame_number = ((pdpt_idx * 512ull) + pd_idx);
		}
	}

	for (size_t i = 0; i < npt_free_pt_count; ++i)
		npt.free_pt_pfns[i] = phys_pfn(npt.free_pts[i]);
	npt.dummy_page_pfn = phys_pfn(npt.dummy_page);
	npt.generation = 1;
	init_hook_lists(npt);
	init_exec_view(npt);
}

pdpte_64* get_npt_pdpte(npt_data& npt, u64 const physical_address) {
	u64 const pml4_idx = (physical_address >> 39) & 0x1ff;
	u64 const pdpt_idx = (physical_address >> 30) & 0x1ff;

	if (pml4_idx == 0) {
		if (pdpt_idx >= npt_pd_count)
			return nullptr;
		return &npt.pdpt[pdpt_idx];
	}

	auto const& pml4e = npt.pml4[pml4_idx];
	if (!pml4e.present)
		return nullptr;

	auto const pdpt = reinterpret_cast<pdpte_64*>(
		npt_page_virtual(npt, pml4e.page_frame_number));
	if (!pdpt)
		return nullptr;

	return &pdpt[pdpt_idx];
}

pde_2mb_64* get_npt_pde_2mb(npt_data& npt, u64 const physical_address) {
	u64 const pml4_idx = (physical_address >> 39) & 0x1ff;
	u64 const pdpt_idx = (physical_address >> 30) & 0x1ff;
	u64 const pd_idx = (physical_address >> 21) & 0x1ff;

	if (pml4_idx == 0) {
		if (pdpt_idx >= npt_pd_count)
			return nullptr;
		return &npt.pds_2mb[pdpt_idx][pd_idx];
	}

	auto const pdpte = get_npt_pdpte(npt, physical_address);
	if (!pdpte || !pdpte->present)
		return nullptr;

	auto const pd = reinterpret_cast<pde_2mb_64*>(
		npt_page_virtual(npt, pdpte->page_frame_number));
	if (!pd)
		return nullptr;

	return &pd[pd_idx];
}

bool ensure_npt_mapped(npt_data& npt, u64 const physical_address) {
	u64 const pml4_idx = (physical_address >> 39) & 0x1ff;
	u64 const pdpt_idx = (physical_address >> 30) & 0x1ff;
	u64 const pd_idx = (physical_address >> 21) & 0x1ff;
	u64 const pt_idx = (physical_address >> 12) & 0x1ff;

	if (pml4_idx >= 512)
		return false;

	auto& pml4e = npt.pml4[pml4_idx];
	if (!pml4e.present) {
		if (pml4_idx == 0 || npt.num_used_free_pts >= npt_free_pt_count)
			return false;
		size_t const page_idx = npt.num_used_free_pts++;
		RtlZeroMemory(npt.free_pts[page_idx], PAGE_SIZE);
		pml4e.flags = 0;
		pml4e.present = 1;
		pml4e.write = 1;
		pml4e.supervisor = 1;
		pml4e.page_frame_number = npt.free_pt_pfns[page_idx];
	}

	auto const pdpte = get_npt_pdpte(npt, physical_address);
	if (!pdpte)
		return false;

	if (!pdpte->present) {
		if ((pml4_idx == 0 && pdpt_idx < npt_pd_count) ||
			npt.num_used_free_pts >= npt_free_pt_count)
			return false;
		size_t const page_idx = npt.num_used_free_pts++;
		auto const dyn_pd = reinterpret_cast<pde_2mb_64*>(npt.free_pts[page_idx]);
		u64 const base_2mb_pfn = (pml4_idx << 18) | (pdpt_idx << 9);
		for (size_t i = 0; i < 512; ++i) {
			auto& pde = dyn_pd[i];
			pde.flags = 0;
			pde.present = 1;
			pde.write = 1;
			pde.supervisor = 1;
			pde.large_page = 1;
			pde.page_frame_number = base_2mb_pfn + i;
		}
		pdpte->flags = 0;
		pdpte->present = 1;
		pdpte->write = 1;
		pdpte->supervisor = 1;
		pdpte->page_frame_number = npt.free_pt_pfns[page_idx];
		mark_npt_changed(npt);
		return true;
	}

	auto const pde_2mb = get_npt_pde_2mb(npt, physical_address);
	if (!pde_2mb)
		return false;

	if (!pde_2mb->present) {
		pde_2mb->flags = 0;
		pde_2mb->present = 1;
		pde_2mb->write = 1;
		pde_2mb->supervisor = 1;
		pde_2mb->large_page = 1;
		pde_2mb->page_frame_number = (pml4_idx << 18) | (pdpt_idx << 9) | pd_idx;
		mark_npt_changed(npt);
		return true;
	}

	if (pde_2mb->large_page) {
		pde_2mb->write = 1;
		pde_2mb->supervisor = 1;
		pde_2mb->execute_disable = 0;
		return true;
	}

	auto const& pde = *reinterpret_cast<pde_64*>(pde_2mb);
	auto const pt = reinterpret_cast<pte_64*>(
		npt_page_virtual(npt, pde.page_frame_number));
	if (!pt)
		return false;

	auto& pte = pt[pt_idx];
	if (!pte.present) {
		pte.flags = 0;
		pte.present = 1;
		pte.write = 1;
		pte.supervisor = 1;
		pte.page_frame_number = physical_address >> 12;
		pte.execute_disable = 0;
		mark_npt_changed(npt);
	}
	return true;
}

pte_64* get_npt_pte(npt_data& npt, u64 const physical_address, bool const force_split) {
	auto pde_2mb = get_npt_pde_2mb(npt, physical_address);
	if (!pde_2mb || !pde_2mb->present) {
		// 高于初始 512 GiB identity leaf 的页需要先建立动态 PML4/PDPT/PD
		// 路径。隐藏 PFN 的 VM-exit 路径直接调用本函数；若此处只返回空指针，
		// Guest 随后的首次访问会再次触发 NPF，handle_npf 在映射失败时注入
		// #GP(0)，最终把普通内核线程转成 BugCheck 0x7E。
		if (!force_split || (physical_address >> 52) != 0 ||
			!ensure_npt_mapped(npt, physical_address))
			return nullptr;

		pde_2mb = get_npt_pde_2mb(npt, physical_address);
		if (!pde_2mb || !pde_2mb->present)
			return nullptr;
	}

	if (pde_2mb->large_page) {
		if (!force_split)
			return nullptr;

		if (!split_2mb_pde(npt, physical_address))
			return nullptr;
	}

	auto const pt_idx = (physical_address >> 12) & 0x1ff;
	auto const& pde = *reinterpret_cast<pde_64*>(pde_2mb);
	if (!pde.present)
		return nullptr;

	auto const pt = reinterpret_cast<pte_64*>(npt_page_virtual(npt, pde.page_frame_number));
	if (!pt)
		return nullptr;

	return &pt[pt_idx];
}

bool install_npt_hook(npt_data& npt,
	u64 const original_page_pfn,
	u64 const executable_page_pfn,
	bool const is_fake_page)
{
	if (find_npt_hook(npt, original_page_pfn))
		return true;

	if (!npt.hooks.free_list_head)
		return false;

	auto const pte = get_npt_pte(npt, original_page_pfn << 12, true);
	if (!pte)
		return false;

	auto const node = npt.hooks.free_list_head;
	npt.hooks.free_list_head = node->next;
	node->next = npt.hooks.active_list_head;
	npt.hooks.active_list_head = node;
	node->orig_pfn = original_page_pfn;
	node->exec_pfn = executable_page_pfn;
	node->is_fake_page = is_fake_page;

	// AMD NPT lacks independent 读取 permission. Keep the 默认 读取 view
	// mapped in the normal NPT root and force 执行 through NX.  The
	// optimized NPF handler switches VMCB.N_CR3 to exec_view, where only the
	// active cloaked page is executable and all other execution paths are NX.
	pte->present = 1;
	pte->write = 1;
	pte->supervisor = 1;
	pte->page_frame_number = hook_read_pfn(*node);
	pte->execute_disable = 1;
	mark_npt_changed(npt);
	return true;
}

void remove_npt_hook(npt_data& npt, u64 const original_page_pfn) {
	npt_hook_node* prev = nullptr;
	auto node = npt.hooks.active_list_head;
	while (node) {
		if (node->orig_pfn == original_page_pfn)
			break;
		prev = node;
		node = node->next;
	}

	if (!node)
		return;

	if (prev)
		prev->next = node->next;
	else
		npt.hooks.active_list_head = node->next;

	node->next = npt.hooks.free_list_head;
	npt.hooks.free_list_head = node;

	auto const pte = get_npt_pte(npt, original_page_pfn << 12, false);
	if (pte) {
		pte->present = 1;
		pte->write = 1;
		pte->supervisor = 1;
		pte->page_frame_number = original_page_pfn;
		pte->execute_disable = 0;
		mark_npt_changed(npt);
	}

	if (npt.exec_view.active && npt.exec_view.active_orig_pfn == original_page_pfn)
		deactivate_npt_exec_view(npt);
}

npt_hook_node* find_npt_hook(npt_data& npt, u64 const original_page_pfn) {
	for (auto hook = npt.hooks.active_list_head; hook; hook = hook->next) {
		if (hook->orig_pfn == original_page_pfn)
			return hook;
	}

	return nullptr;
}

u64 npt_exec_root_pa(npt_data& npt) {
	if (!npt.exec_view.pml4_pa)
		npt.exec_view.pml4_pa = phys_pa(npt.exec_view.pml4);
	return npt.exec_view.pml4_pa;
}

bool npt_exec_view_active(npt_data const& npt) {
	return npt.exec_view.active;
}

bool npt_exec_view_contains(npt_data const& npt, u64 const physical_address) {
	return npt.exec_view.active &&
		((physical_address >> 12) == npt.exec_view.active_orig_pfn);
}

bool activate_npt_exec_view(npt_data& npt, npt_hook_node const& hook) {
	u64 const physical_address = hook.orig_pfn << 12;
	u64 const pml4_idx = (physical_address >> 39) & 0x1ff;
	if (pml4_idx != 0)
		return false;

	u64 const exec_pfn = hook_exec_pfn(hook);
	auto& exec = npt.exec_view;
	if (!exec.active &&
		exec.cached_generation == npt.generation &&
		exec.cached_orig_pfn == hook.orig_pfn &&
		exec.cached_exec_pfn == exec_pfn) {
		exec.active = true;
		exec.active_orig_pfn = hook.orig_pfn;
		exec.active_exec_pfn = exec_pfn;
		exec.active_base_pfn = hook.orig_pfn & ~0x1ffull;
		return true;
	}

	auto const normal_pt = normal_pt_for_2mb(npt, physical_address);
	if (!normal_pt)
		return false;

	u64 const pdpt_idx = (physical_address >> 30) & 0x1ff;
	u64 const pd_idx = (physical_address >> 21) & 0x1ff;
	u64 const pt_idx = (physical_address >> 12) & 0x1ff;
	u64 const base_pfn = hook.orig_pfn & ~0x1ffull;

	for (size_t i = 0; i < npt_pd_count; ++i) {
		exec.pdpt[i].flags = npt.pdpt[i].flags;
		exec.pdpt[i].execute_disable = 1;
	}

	auto& active_pdpte = exec.pdpt[pdpt_idx];
	active_pdpte.flags = 0;
	active_pdpte.present = 1;
	active_pdpte.write = 1;
	active_pdpte.supervisor = 1;
	active_pdpte.page_frame_number = exec.pd_pfn;
	active_pdpte.execute_disable = 0;

	for (size_t i = 0; i < 512; ++i) {
		exec.pd_raw[i] = npt.pds_2mb[pdpt_idx][i].flags | paging_nx_bit;
	}

	auto& active_pde = exec.pd[pd_idx];
	active_pde.flags = 0;
	active_pde.present = 1;
	active_pde.write = 1;
	active_pde.supervisor = 1;
	active_pde.page_frame_number = exec.pt_pfn;
	active_pde.execute_disable = 0;

	for (size_t i = 0; i < 512; ++i) {
		exec.pt[i].flags = normal_pt[i].flags;
		exec.pt[i].execute_disable = 1;
	}

	auto& active_pte = exec.pt[pt_idx];
	active_pte.present = 1;
	active_pte.write = 1;
	active_pte.supervisor = 1;
	active_pte.page_frame_number = exec_pfn;
	active_pte.execute_disable = 0;

	// Allow an instruction at the end of active_pte that straddles into the
	// next 4KB page to complete fetching without ping-ponging between views.
	if (pt_idx + 1 < 512 && !find_npt_hook(npt, hook.orig_pfn + 1)) {
		exec.pt[pt_idx + 1].execute_disable = 0;
	}

	exec.active = true;
	exec.active_orig_pfn = hook.orig_pfn;
	exec.active_exec_pfn = exec_pfn;
	exec.active_base_pfn = base_pfn;
	exec.cached_generation = npt.generation;
	exec.cached_orig_pfn = hook.orig_pfn;
	exec.cached_exec_pfn = exec_pfn;
	return true;
}

void deactivate_npt_exec_view(npt_data& npt) {
	npt.exec_view.active = false;
	npt.exec_view.active_orig_pfn = 0;
	npt.exec_view.active_exec_pfn = 0;
	npt.exec_view.active_base_pfn = 0;
}

void mark_npt_changed(npt_data& npt) {
	++npt.generation;
	if (!npt.generation)
		npt.generation = 1;
}

} // namespace svm
