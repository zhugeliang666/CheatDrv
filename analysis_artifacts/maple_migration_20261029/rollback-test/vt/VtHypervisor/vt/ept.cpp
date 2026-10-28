#include "ept.h"
#include "arch.h"
#include "hv.h"
#include "vcpu.h"
#include "mtrr.h"
#include "mm.h"

namespace hv {
#pragma code_seg(".vm")
// identity-map the EPT paging structures
void prepare_ept(vcpu_ept_data& ept) {
  memset(&ept, 0, sizeof(ept));

  ept.dummy_page_pfn = MmGetPhysicalAddress(g_ghv->dummy_page).QuadPart >> 12;

  ept.num_used_free_pages = 0;

  for (size_t i = 0; i < ept_free_page_count; ++i)
    ept.free_page_pfns[i] = MmGetPhysicalAddress(&ept.free_pages[i]).QuadPart >> 12;

  ept.hooks.active_list_head = nullptr;
  ept.hooks.free_list_head   = &ept.hooks.buffer[0];

  for (size_t i = 0; i < ept.hooks.capacity - 1; ++i)
    ept.hooks.buffer[i].next = &ept.hooks.buffer[i + 1];

  // the last node points to NULL
  ept.hooks.buffer[ept.hooks.capacity - 1].next = nullptr;



  ept.bp_hooks.active_list_head = nullptr;
  ept.bp_hooks.free_list_head = &ept.bp_hooks.buffer[0];
  for (size_t i = 0; i < ept.bp_hooks.capacity - 1; ++i)
      ept.bp_hooks.buffer[i].next = &ept.bp_hooks.buffer[i + 1];
  ept.bp_hooks.buffer[ept.bp_hooks.capacity - 1].next = nullptr;



  // setup the first PML4E so that it points to our PDPT
  auto& pml4e             = ept.pml4[0];
  pml4e.flags             = 0;
  pml4e.read_access       = 1;
  pml4e.write_access      = 1;
  pml4e.execute_access    = 1;
  pml4e.accessed          = 0;
  pml4e.user_mode_execute = 1;
  pml4e.page_frame_number = MmGetPhysicalAddress(&ept.pdpt).QuadPart >> 12;

  // MTRR data for setting memory types
  read_mtrr_data(ept);

  // TODO: 分配 a PT for the fixed MTRRs region so that we can 获取
  // more accurate memory typing in that area (as opposed to just
  // mapping the whole PDE as UC).

  for (size_t i = 0; i < ept_pd_count; ++i) {
    // point each PDPTE to the corresponding PD
    auto& pdpte             = ept.pdpt[i];
    pdpte.flags             = 0;
    pdpte.read_access       = 1;
    pdpte.write_access      = 1;
    pdpte.execute_access    = 1;
    pdpte.accessed          = 0;
    pdpte.user_mode_execute = 1;
    pdpte.page_frame_number = MmGetPhysicalAddress(&ept.pds[i]).QuadPart >> 12;

    for (size_t j = 0; j < 512; ++j) {
      // identity-map every GPA to the corresponding HPA
      auto& pde             = ept.pds_2mb[i][j];
      pde.flags             = 0;
      pde.read_access       = 1;
      pde.write_access      = 1;
      pde.execute_access    = 1;
      pde.ignore_pat        = 0;
      pde.large_page        = 1;
      pde.accessed          = 0;
      pde.dirty             = 0;
      pde.user_mode_execute = 1;
      pde.suppress_ve       = 0;
      pde.page_frame_number = (i << 9) + j;
      pde.memory_type       = calc_mtrr_mem_type(ept.mtrrs,
          pde.page_frame_number, true);
    }
  }
}

// 更新 the memory types in the EPT paging structures based on the MTRRs.
// this 函数 should only be called from root-模式 during vmx-operation.
void update_ept_memory_type(vcpu_ept_data& ept) {
  // TODO: completely virtualize the guest MTRRs
    read_mtrr_data(ept);

  for (size_t i = 0; i < ept_pd_count; ++i) {
    for (size_t j = 0; j < 512; ++j) {
      auto& pde = ept.pds_2mb[i][j];

      // 2MB large page
      if (pde.large_page) {
        // 更新 the memory type for this PDE
        pde.memory_type = calc_mtrr_mem_type(ept.mtrrs, pde.page_frame_number, true);
      }
      // PDE points to a PT
      else {
        auto const pt = reinterpret_cast<ept_pte*>(host_physical_memory_base
          + (ept.pds[i][j].page_frame_number << 12));

        // 更新 the memory type for every PTE
        for (size_t k = 0; k < 512; ++k) {
          pt[k].memory_type = calc_mtrr_mem_type(ept.mtrrs,
              pt[k].page_frame_number, false);
        }
      }
    }
  }
}

// 设置 the memory type in every EPT paging 结构体 to the specified 值
void set_ept_memory_type(vcpu_ept_data& ept, uint8_t const memory_type) {
  for (size_t i = 0; i < ept_pd_count; ++i) {
    for (size_t j = 0; j < 512; ++j) {
      auto& pde = ept.pds_2mb[i][j];

      // 2MB large page
      if (pde.large_page)
        pde.memory_type = memory_type;
      // PDE points to a PT
      else {
        auto const pt = reinterpret_cast<ept_pte*>(host_physical_memory_base
          + (ept.pds[i][j].page_frame_number << 12));

        // 更新 the memory type for every PTE
        for (size_t k = 0; k < 512; ++k)
          pt[k].memory_type = memory_type;
      }
    }
  }
}

// 获取 the corresponding EPT PDPTE for a given physical 地址
ept_pdpte* get_ept_pdpte(vcpu_ept_data& ept, uint64_t const physical_address) {
  pml4_virtual_address const addr = { reinterpret_cast<void*>(physical_address) };

  if (addr.pml4_idx != 0)
    return nullptr;

  if (addr.pdpt_idx >= ept_pd_count)
    return nullptr;

  return &ept.pdpt[addr.pdpt_idx];
}

// 获取 the corresponding EPT PDE for a given physical 地址
ept_pde* get_ept_pde(vcpu_ept_data& ept, uint64_t const physical_address) {
  pml4_virtual_address const addr = { reinterpret_cast<void*>(physical_address) };

  if (addr.pml4_idx != 0)
    return nullptr;

  if (addr.pdpt_idx >= ept_pd_count)
    return nullptr;

  return &ept.pds[addr.pdpt_idx][addr.pd_idx];
}

// 获取 the corresponding EPT PTE for a given physical 地址
ept_pte* get_ept_pte(vcpu_ept_data& ept,
    uint64_t const physical_address, bool const force_split) {
  pml4_virtual_address const addr = { reinterpret_cast<void*>(physical_address) };

  if (addr.pml4_idx != 0)
    return nullptr;

  if (addr.pdpt_idx >= ept_pd_count)
    return nullptr;

  auto& pde_2mb = ept.pds_2mb[addr.pdpt_idx][addr.pd_idx];

  if (pde_2mb.large_page) {
    if (!force_split)
      return nullptr;

    split_ept_pde(ept, &pde_2mb);

    // 执行失败 to split the PDE
    if (pde_2mb.large_page)
      return nullptr;
  }

  auto const pt = reinterpret_cast<ept_pte*>(host_physical_memory_base
    + (ept.pds[addr.pdpt_idx][addr.pd_idx].page_frame_number << 12));

  return &pt[addr.pt_idx];
}

// split a 2MB EPT PDE so that it points to an EPT PT
void split_ept_pde(vcpu_ept_data& ept, ept_pde_2mb* const pde_2mb) {
  // this PDE is already split
  if (!pde_2mb->large_page)
    return;

  // no available 释放 pages
  if (ept.num_used_free_pages >= ept_free_page_count)
    return;

  // 分配 a 释放 page for the PT
  auto const pt_pfn = ept.free_page_pfns[ept.num_used_free_pages];
  auto const pt = reinterpret_cast<ept_pte*>(
    &ept.free_pages[ept.num_used_free_pages]);
  ++ept.num_used_free_pages;

  for (size_t i = 0; i < 512; ++i) {
    auto& pte = pt[i];
    pte.flags = 0;

    // copy the parent PDE 标志位集合
    pte.read_access             = pde_2mb->read_access;
    pte.write_access            = pde_2mb->write_access;
    pte.execute_access          = pde_2mb->execute_access;
    pte.ignore_pat              = pde_2mb->ignore_pat;
    pte.accessed                = pde_2mb->accessed;
    pte.dirty                   = pde_2mb->dirty;
    pte.user_mode_execute       = pde_2mb->user_mode_execute;
    pte.verify_guest_paging     = pde_2mb->verify_guest_paging;
    pte.paging_write_access     = pde_2mb->paging_write_access;
    pte.supervisor_shadow_stack = pde_2mb->supervisor_shadow_stack;
    pte.suppress_ve             = pde_2mb->suppress_ve;
    pte.page_frame_number       = (pde_2mb->page_frame_number << 9) + i;
    pte.memory_type = calc_mtrr_mem_type(ept.mtrrs, pte.page_frame_number, false);
  }

  auto const pde         = reinterpret_cast<ept_pde*>(pde_2mb);
  pde->flags             = 0;
  pde->read_access       = 1;
  pde->write_access      = 1;
  pde->execute_access    = 1;
  pde->user_mode_execute = 1;
  pde->page_frame_number = pt_pfn;
}

// memory 读取/written will use the original page while code
// being executed will use the executable page instead
bool install_ept_hook(vcpu_ept_data& ept,
    uint64_t const original_page_pfn,
    uint64_t const executable_page_pfn,bool is_fake_page)
{
	_InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ieh_calls);

	// Idempotency: if this orig_pfn already has a hook on this vCPU's EPT
	// tree, do not consume another hook_node and do not rewrite the PTE.
	// Repeated drain of pending_ept_install_entries could otherwise overwrite
	// good 状态 with a fresh PTE 写入 and double-pop the 释放 list.
	for (auto h = ept.hooks.active_list_head; h; h = h->next) {
		if (h->orig_pfn == static_cast<uint32_t>(original_page_pfn)) {
			_InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ieh_idempotent);
			return true;
		}
	}

	// we ran out of EPT hooks :(
	if (!ept.hooks.free_list_head) {
		_InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ieh_no_freelist);
		return false;
	}

	// 获取 the EPT PTE, and possible split an existing PDE if needed
	auto const pte = get_ept_pte(ept, original_page_pfn << 12, true);
	if (!pte) {
		_InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ieh_no_pte);
		return false;
	}

	// 卸载移除 a hook node from the 释放 list
	auto const hook_node = ept.hooks.free_list_head;
	ept.hooks.free_list_head = hook_node->next;

	// insert the hook node into the active list
	hook_node->next = ept.hooks.active_list_head;
	ept.hooks.active_list_head = hook_node;

	// 初始化 the hook node
	hook_node->orig_pfn = static_cast<uint32_t>(original_page_pfn);
	hook_node->exec_pfn = static_cast<uint32_t>(executable_page_pfn);
    hook_node->is_fake_page = is_fake_page;

    // Snapshot PTE before 写入 so we can verify the modification took.
    auto pte_before = *(volatile uint64_t*)pte;
    g_ghv->diag_ieh_last_pte_addr   = (uint64_t)pte;
    g_ghv->diag_ieh_last_pte_before = pte_before;

    // an instruction fetch to this physical 地址 will now trigger
    // an ept-violation vm-exit where the real "meat" of the ept hook is
    if (is_fake_page) {
        pte->read_access  = 0;
        pte->write_access = 0;
    }
    else {
        pte->execute_access = 0;
    }

    g_ghv->diag_ieh_last_pte_after = *(volatile uint64_t*)pte;

	vmx_invept(invept_all_context, {});

	_InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ieh_success);
	return true;
}


// 卸载移除 an EPT hook that was installed with install_ept_hook()
void remove_ept_hook(vcpu_ept_data& ept, uint64_t const original_page_pfn) {
  if (!ept.hooks.active_list_head)
    return;

  // the head is the 目标 node
  if (ept.hooks.active_list_head->orig_pfn == original_page_pfn) {
    auto const new_head = ept.hooks.active_list_head->next;

    // add to the 释放 list
    ept.hooks.active_list_head->next = ept.hooks.free_list_head;
    ept.hooks.free_list_head = ept.hooks.active_list_head;

    // 卸载移除 from the active list
    ept.hooks.active_list_head = new_head;
  } else {
    auto prev = ept.hooks.active_list_head;

    // search for the node BEFORE the 目标 node (prev if this was doubly)
    while (prev->next) {
      if (prev->next->orig_pfn == original_page_pfn)
        break;

      prev = prev->next;
    }

    if (!prev->next)
      return;

    auto const new_next = prev->next->next;

    // add to the 释放 list
    prev->next->next = ept.hooks.free_list_head;
    ept.hooks.free_list_head = prev->next;

    // 卸载移除 from the active list
    prev->next = new_next;
  }

  auto const pte = get_ept_pte(ept, original_page_pfn << 12, false);

  // this should NOT fail
  if (!pte)
    return;

  // 恢复 original EPT page attributes
  pte->read_access       = 1;
  pte->write_access      = 1;
  pte->execute_access    = 1;
  pte->page_frame_number = original_page_pfn;

  vmx_invept(invept_all_context, {});
}

// find the EPT hook for the specified PFN
vcpu_ept_hook_node* find_ept_hook(vcpu_ept_data& ept,
    uint64_t const original_page_pfn) {
  // TODO:
  // maybe use a more optimal data 结构体 to 处理 a large
  //   amount of EPT hooks?

  // linear search through the active hook list
  for (auto curr = ept.hooks.active_list_head; curr; curr = curr->next) {
    if (curr->orig_pfn == original_page_pfn)
      return curr;
  }

  return nullptr;
}


bool install_bp_hook(vcpu_ept_data& ept, uint64_t cr3, uint64_t original_va, uint64_t fake_va,bool is_cr3_monitor_hook)
{


    if (!ept.bp_hooks.free_list_head)
        return false;


    auto const hook_node = ept.bp_hooks.free_list_head;
    ept.bp_hooks.free_list_head = hook_node->next;


    hook_node->next = ept.bp_hooks.active_list_head;
    ept.bp_hooks.active_list_head = hook_node;


    hook_node->cr3 = cr3;
    hook_node->origin_guest_va = original_va;
    hook_node->fake_guest_va = fake_va;
    hook_node->is_cr3_monitor_hook = is_cr3_monitor_hook;
    return true;
}

void remove_bp_hook(vcpu_ept_data& ept, uint64_t cr3, uint64_t original_va)
{
    if (!ept.bp_hooks.active_list_head)
        return;

    // the head is the 目标 node
    if (ept.bp_hooks.active_list_head->origin_guest_va == original_va) {
        auto const new_head = ept.bp_hooks.active_list_head->next;

        // add to the 释放 list
        ept.bp_hooks.active_list_head->next = ept.bp_hooks.free_list_head;
        ept.bp_hooks.free_list_head = ept.bp_hooks.active_list_head;

        // 卸载移除 from the active list
        ept.bp_hooks.active_list_head = new_head;
    }
    else {
        auto prev = ept.bp_hooks.active_list_head;

        // search for the node BEFORE the 目标 node (prev if this was doubly)
        while (prev->next) {
            if (prev->next->origin_guest_va == original_va && prev->next->cr3 == cr3)
                break;

            prev = prev->next;
        }

        if (!prev->next)
            return;

        auto const new_next = prev->next->next;

        // add to the 释放 list
        prev->next->next = ept.bp_hooks.free_list_head;
        ept.bp_hooks.free_list_head = prev->next;

        // 卸载移除 from the active list
        prev->next = new_next;
    }

}

vcpu_bp_hook_node* find_bp_hook(vcpu_ept_data& ept, uint64_t cr3, uint64_t original_va)
{
    for (auto curr = ept.bp_hooks.active_list_head; curr; curr = curr->next) {

        if (curr->cr3 == 0)
        {

            if (curr->origin_guest_va == original_va)
                return curr;
        }
        else
        {



            if (curr->cr3 == cr3 && curr->origin_guest_va == original_va)
                return curr;

            if (g_ghv->is_cr3_monitor_open)
                if (((curr->cr3 &(~0xfff)) == (g_ghv->g_cr3_monitor.fake_cr3.flags & (~0xfff)) ||
                   ( curr->cr3 & (~0xfff))  == (g_ghv->g_cr3_monitor.real_cr3.flags & (~0xfff)))
                    && curr->origin_guest_va == original_va)
                    return curr;
        }

    }

    return nullptr;

}

} // namespace hv

