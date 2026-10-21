#include "base.h"

#include "page-tables.h"



#include "vcpu.h"
#include "hv.h"
#include "mm.h"
#include  "vmx.h"
#include <common/ntutils.h>
namespace hv {
#pragma code_seg(".vm")
// directly map physical memory into the host page tables
static void map_physical_memory(host_page_tables& pt) {
  auto& pml4e = pt.pml4[host_physical_memory_pml4_idx];
  pml4e.flags                    = 0;
  pml4e.present                  = 1;
  pml4e.write                    = 1;
  pml4e.supervisor               = 0;
  pml4e.page_level_write_through = 0;
  pml4e.page_level_cache_disable = 0;
  pml4e.accessed                 = 0;
  pml4e.execute_disable          = 0;
  pml4e.page_frame_number = MmGetPhysicalAddress(&pt.phys_pdpt).QuadPart >> 12;

  // TODO: add support for 1GB pages
  // TODO: check if 2MB pages are supported (pretty much always are)

  for (uint64_t i = 0; i < host_physical_memory_pd_count; ++i) {
    auto& pdpte = pt.phys_pdpt[i];
    pdpte.flags                    = 0;
    pdpte.present                  = 1;
    pdpte.write                    = 1;
    pdpte.supervisor               = 0;
    pdpte.page_level_write_through = 0;
    pdpte.page_level_cache_disable = 0;
    pdpte.accessed                 = 0;
    pdpte.execute_disable          = 0;
    pdpte.page_frame_number = MmGetPhysicalAddress(&pt.phys_pds[i]).QuadPart >> 12;

    for (uint64_t j = 0; j < 512; ++j) {
      auto& pde = pt.phys_pds[i][j];
      pde.flags                    = 0;
      pde.present                  = 1;
      pde.write                    = 1;
      pde.supervisor               = 0;
      pde.page_level_write_through = 0;
      pde.page_level_cache_disable = 0;
      pde.accessed                 = 0;
      pde.dirty                    = 0;
      pde.large_page               = 1;
      pde.global                   = 0;
      pde.pat                      = 0;
      pde.execute_disable          = 0;
      pde.page_frame_number = (i << 9) + j;
    }
  }
}

#define pt_index(va) (((va) >> 12) & 0x1FF)
#define pd_index(va) (((va) >> 21) & 0x1FF)
#define pdpt_index(va) (((va) >> 30) & 0x1FF)
#define pml4_index(va) (((va) >> 39) & 0x1FF)

struct page_table_entry
{
    pml4_virtual_address va;
    pml4e_64 pml4;
    pdpte_64 pdpt;
    pde_64 pdt;
    pte_64 pt;
};

static void clone_host_page_table_page(void* dst_page, uint64_t source_pfn)
{
    if (!dst_page || !source_pfn)
        return;

    PHYSICAL_ADDRESS src_pa = {};
    src_pa.QuadPart = source_pfn << 12;
    auto src = reinterpret_cast<pte_64*>(MmGetVirtualForPhysical(src_pa));
    if (!src)
    {
        memset(dst_page, 0, PAGE_SIZE);
        return;
    }

    auto dst = reinterpret_cast<pte_64*>(dst_page);
    for (int i = 0; i < 512; ++i)
    {
        if (src[i].present)
        {
            dst[i] = src[i];
            dst[i].write = 1;
            dst[i].execute_disable = 0;
        }
        else
        {
            dst[i].flags = 0;
        }
    }
}

static bool allocate_host_table_from_source(char*& free_page,
                                            uint64_t& use,
                                            uint64_t source_pfn,
                                            uint64_t* new_pfn)
{
    if (!new_pfn || use >= pages_max)
        return false;

    char* table_page = free_page;
    *new_pfn = MmGetPhysicalAddress(table_page).QuadPart >> 12;
    clone_host_page_table_page(table_page, source_pfn);

    ++use;
    free_page += PAGE_SIZE;
    return true;
}


uint64_t get_page_entry(cr3 const guest_cr3, page_table_entry& page_entry)
{


    PHYSICAL_ADDRESS pa;
    pa.QuadPart = guest_cr3.address_of_page_directory << 12;
    // guest PML4
    auto const pml4 = reinterpret_cast<pml4e_64*>(MmGetVirtualForPhysical(pa));
    if (!pml4)
        return false;
    page_entry.pml4 = pml4[page_entry.va.pml4_idx];

    if (!page_entry.pml4.present)
    {
        return true;

    }


    // guest PDPT
    pa.QuadPart = page_entry.pml4.page_frame_number << 12;
    auto const pdpt = reinterpret_cast<pdpte_64*>(MmGetVirtualForPhysical(pa));
    if (!pdpt)
        return false;
    page_entry.pdpt = pdpt[page_entry.va.pdpt_idx];

    if (!page_entry.pdpt.present)
    {
        return true;
    }


    if (page_entry.pdpt.large_page)
    {
        return true;
    }

    // guest PD
    pa.QuadPart = page_entry.pdpt.page_frame_number << 12;
    auto const pd = reinterpret_cast<pde_64*>(MmGetVirtualForPhysical(pa));
    if (!pd)
        return false;
    page_entry.pdt = pd[page_entry.va.pd_idx];
    if (!page_entry.pdt.present)
    {

        return true;
    }


    if (page_entry.pdt.large_page)
    {

        return true;
    }

    // guest PT
    pa.QuadPart = page_entry.pdt.page_frame_number << 12;
    auto const pt = reinterpret_cast<pte_64*>(MmGetVirtualForPhysical(pa));
    if (!pt)
        return false;
    page_entry.pt = pt[page_entry.va.pt_idx];

    return true;
}


static bool  map_page(uint64_t va)
{

    pml4e_64* pml4 = g_ghv->host_page_tables.pml4 + pml4_index(va);
    if (g_ghv->host_page_tables.page_use >= pages_max) {
        LOG_DEBUG(_XOR_("[YVT] map_page: pool EXHAUSTED at use=0x%llX (max=0x%llX) va=%p\n"),
            g_ghv->host_page_tables.page_use, (uint64_t)pages_max, (void*)va);
        return false;
    }
    char* free_page = g_ghv->host_page_tables.pages + PAGE_SIZE * g_ghv->host_page_tables.page_use;
    auto& use = g_ghv->host_page_tables.page_use;
    PHYSICAL_ADDRESS pa = {};

    page_table_entry page_entry;

    memset(&page_entry, 0, sizeof(page_entry));

    page_entry.va.address = (void*)va;

    if (!get_page_entry(g_ghv->system_cr3, page_entry))
    {
        LOG_DEBUG(_XOR_("[YVT] map_page: source walk failed va=%p\n"), (void*)va);
        return false;
    }
    if (!page_entry.pml4.present ||
        !page_entry.pdpt.present ||
        (!page_entry.pdpt.large_page && !page_entry.pdt.present) ||
        (!page_entry.pdpt.large_page && !page_entry.pdt.large_page && !page_entry.pt.present))
    {
        LOG_DEBUG(_XOR_("[YVT] map_page: source PTE not present va=%p pml4=%llx pdpt=%llx pde=%llx pte=%llx\n"),
            (void*)va,
            page_entry.pml4.flags,
            page_entry.pdpt.flags,
            page_entry.pdt.flags,
            page_entry.pt.flags);
        return false;
    }

    if (!pml4->flags)
    {
        uint64_t new_pfn = 0;
        if (!allocate_host_table_from_source(free_page, use, page_entry.pml4.page_frame_number, &new_pfn))
            return false;
        pml4->flags = page_entry.pml4.flags;
        pml4->write = 1;
        pml4->execute_disable = 0;
        pml4->page_frame_number = new_pfn;
    }

    pa.QuadPart = pml4->page_frame_number << 12;
    pdpte_64* pdpt = (pdpte_64*)MmGetVirtualForPhysical(pa) + pdpt_index(va);
    if (page_entry.pdpt.large_page)
    {
        if (!pdpt->flags)
            pdpt->flags = page_entry.pdpt.flags;
        pdpt->write = 1;
        pdpt->execute_disable = 0;
        return true;
    }

    if (!pdpt->flags)
    {
        uint64_t new_pfn = 0;
        if (!allocate_host_table_from_source(free_page, use, page_entry.pdpt.page_frame_number, &new_pfn))
            return false;
        pdpt->flags = page_entry.pdpt.flags;
        pdpt->write = 1;
        pdpt->execute_disable = 0;
        pdpt->large_page = 0;
        pdpt->page_frame_number = new_pfn;
    }

    if (pdpt->page_frame_number == page_entry.pdpt.page_frame_number)
    {
        uint64_t new_pfn = 0;
        if (!allocate_host_table_from_source(free_page, use, page_entry.pdpt.page_frame_number, &new_pfn))
            return false;
        pdpt->write = 1;
        pdpt->execute_disable = 0;
        pdpt->large_page = 0;
        pdpt->page_frame_number = new_pfn;
    }
    pa.QuadPart = pdpt->page_frame_number << 12;
    pde_64* pd = (pde_64*)MmGetVirtualForPhysical(pa) + pd_index(va);

    // If the System CR3 backs this VA with a 2MB large page, we cannot
    // build our own PT under it. Inherit the full PDE (with its original
    // PFN pointing at the 2MB data region) and stop here.
    if (page_entry.pdt.large_page)
    {
        if (!pd->flags) {
            pd->flags = page_entry.pdt.flags;  // keep original PFN of the 2MB page
            pd->execute_disable = 0;
        }
        return true;
    }

    if (!pd->flags)
    {
        uint64_t new_pfn = 0;
        if (!allocate_host_table_from_source(free_page, use, page_entry.pdt.page_frame_number, &new_pfn))
            return false;
        pd->flags = page_entry.pdt.flags;
        pd->write = 1;
        pd->execute_disable = 0;
        pd->large_page = 0;
        pd->page_frame_number = new_pfn;
    }

    if (pd->large_page)
    {
        pd->execute_disable = 0;

        return true;
    }
    if (pd->page_frame_number == page_entry.pdt.page_frame_number)
    {
        uint64_t new_pfn = 0;
        if (!allocate_host_table_from_source(free_page, use, page_entry.pdt.page_frame_number, &new_pfn))
            return false;
        pd->write = 1;
        pd->execute_disable = 0;
        pd->large_page = 0;
        pd->page_frame_number = new_pfn;
    }
    pa.QuadPart = pd->page_frame_number << 12;
    pte_64* pt = (pte_64*)MmGetVirtualForPhysical(pa) + pt_index(va);
    if (!pt->flags)
    {

        pt->flags = page_entry.pt.flags;

    }
    pt->write = 1;
    pt->execute_disable = 0;

    return true;
}


static bool map_memory(uint64_t va, size_t size)
{
    size_t offset = (size_t)(va % PAGE_SIZE);
    size_t num_frames = (size + offset + PAGE_SIZE - 1) / PAGE_SIZE;
    for (size_t i = 0; i < num_frames; i++)
    {
        if (!map_page(va + i * PAGE_SIZE - offset))
            return false;
    }
    return true;
}

bool map_host_virtual_range(uint64_t va, size_t size)
{
    return map_memory(va, size);
}

static void copy_page_table(pte_64* dst, pte_64* src, int level)
{

    if (!dst || !src || level <= 0)
        return;

    // map_memory() may intentionally clone only the path needed by HOST_CR3.
    // Other entries in the cloned table can still point at the original
    // System-CR3 child tables.  Never "merge" such shared tables in place:
    // doing so turns this helper into a writer of Windows' real paging
    // structures and can clear non-present/software system PTEs.
    if (dst == src)
        return;

    size_t start = 0;
    if (level == 4) start = 256; else start = 0;
    if (level > 0)
    {
        for (int i = start; i < 512; i++)
        {

            if (dst[i].present)//
            {
                if (!src[i].present || level == 1 ||
                    (dst[i].flags & (1ull << 7)) ||
                    (src[i].flags & (1ull << 7)))
                {
                    continue;
                }
                PHYSICAL_ADDRESS pSrc;
                PHYSICAL_ADDRESS pDst;
                pSrc.QuadPart = src[i].page_frame_number << 12;
                pDst.QuadPart = dst[i].page_frame_number << 12;
                if (pDst.QuadPart == pSrc.QuadPart)
                {
                    continue;
                }

                pte_64* src_next = (pte_64*)MmGetVirtualForPhysical(pSrc);
                pte_64* dst_next = (pte_64*)MmGetVirtualForPhysical(pDst);
                if (!src_next || !dst_next)
                {
                    continue;
                }

                copy_page_table(dst_next, src_next, level - 1);

            }
            else {
                if (src[i].present)
                {
                    memcpy(&dst[i], &src[i], sizeof(pte_64));
                    dst[i].write = 1;
                    dst[i].execute_disable = 0;
                }
                else
                {
                    dst[i].flags = 0;
                }
            }


        }

    }
}


// initialize the host page tables
bool prepare_host_page_tables() {


	  auto& pt = g_ghv->host_page_tables;
	  memset(&pt, 0, sizeof(pt));


	  // map all of physical memory into our address space
	  map_physical_memory(pt);

	  PHYSICAL_ADDRESS pml4_address;
	  pml4_address.QuadPart = g_ghv->system_cr3.address_of_page_directory << 12;

	  // kernel PML4 address
	  auto const guest_pml4 = static_cast<pml4e_64*>(MmGetVirtualForPhysical(pml4_address));
      if (!guest_pml4)
      {
          LOG_DEBUG(_XOR_("[YVT] prepare_host_page_tables: guest_pml4 is null\n"));
          return false;
      }

      LOG_DEBUG(_XOR_("[YVT] vm-exit address:%p\n"),vm_exit);





      for (int i = 0; i < g_ghv->vcpu_count; i++)
      {
          if (!map_memory((uint64_t)g_ghv->vcpus[i].host_stack, host_stack_size))
              return false;
      }

      for (int i = 0; i < g_ghv->vcpu_count; i++)
      {
          if (!map_memory((uint64_t)&g_ghv->vcpus[i], sizeof(vcpu)))
              return false;
      }

	 if (!map_memory((uint64_t) g_ghv, sizeof(hypervisor)))
         return false;

      if (g_ghv->kernel_format_buf_va && !map_memory(g_ghv->kernel_format_buf_va, 0x1000)) return false;
      if (g_ghv->vt_log_ring_va       && !map_memory(g_ghv->vt_log_ring_va, VT_LOG_RING_BYTES)) return false;
      if (g_ghv->vt_log_format_va     && !map_memory(g_ghv->vt_log_format_va, 0x1000)) return false;
      if (g_ghv->csec_scratch_va      && !map_memory(g_ghv->csec_scratch_va, 0x1000)) return false;
      if (g_ghv->csec_format_va       && !map_memory(g_ghv->csec_format_va, 0x1000)) return false;
      if (g_ghv->alloc_format_va      && !map_memory(g_ghv->alloc_format_va, 0x1000)) return false;
      if (g_ghv->protect_format_va    && !map_memory(g_ghv->protect_format_va, 0x1000)) return false;
      if (g_ghv->map_format_va        && !map_memory(g_ghv->map_format_va, 0x1000)) return false;
      for (uint32_t i = 0; i < g_ghv->tramp_prealloc_count; i++)
      {
          if (g_ghv->tramp_prealloc_pages[i])
          {
              if (!map_memory(g_ghv->tramp_prealloc_pages[i], 0x1000))
                  return false;
          }
      }

	 // Map testDriver image into its own deep host PT subtree so mapDriver
	 // can later strip system-CR3 PTEs (PAGE_NOACCESS) on the image range
	 // without breaking host root-mode access to .text / .vm / .vm2 /
	 // .rdata / .data globals (g_yvt et al). copy_page_table's shallow
	 // mode shares the PML4 entry with system PT, so without this every
	 // image-locking write would also dead-page the host's own code path.
	 if (g_yvt.vtInfo.imageBase && g_yvt.vtInfo.imageSize) {
	   map_memory((uint64_t)g_yvt.vtInfo.imageBase, g_yvt.vtInfo.imageSize);
	 }

	 LOG_DEBUG(_XOR_("[YVT] host PT pool use=0x%llX / max=0x%llX (ghv size=0x%zX, vcpu size=0x%zX x %u)\n"),
		 g_ghv->host_page_tables.page_use, (uint64_t)pages_max,
		 sizeof(hypervisor), sizeof(vcpu), g_ghv->vcpu_count);

	 //copy the top half of the System pml4 (a. k. a. the kernel address space)
	 copy_page_table((pte_64*)pt.pml4, (pte_64*)guest_pml4, 4);

	  // copy the top half of the System pml4 (a.k.a. the kernel address space)
	 
      return true;
	}


void update_cr3_monitor_info()
{

    auto real_cr3_va = (pml4e_64*)(host_physical_memory_base + (g_ghv->g_cr3_monitor.real_cr3.address_of_page_directory << 12));
    auto fake_cr3_va = (pml4e_64*)(host_physical_memory_base + (g_ghv->g_cr3_monitor.fake_cr3.address_of_page_directory << 12));
    memcpy(fake_cr3_va, real_cr3_va, sizeof(pml4e_64) * 254);
    fake_cr3_va[255].flags = (fake_cr3_va[255].flags & (PML4E_64_PAGE_FRAME_NUMBER_FLAG | PML4E_64_IGNORED_2_FLAG)) | (real_cr3_va[255].flags & (~(PML4E_64_PAGE_FRAME_NUMBER_FLAG | PML4E_64_IGNORED_2_FLAG)));

    if ((fake_cr3_va[255].ignored_2 & 0x400) == 0x400)
    {
        pdpte_64* real_pdpte_va = (pdpte_64*)(host_physical_memory_base + (real_cr3_va[255].page_frame_number << 12));
        pdpte_64* fake_pdpte_va = (pdpte_64*)(host_physical_memory_base + (fake_cr3_va[255].page_frame_number << 12));
        memcpy(fake_pdpte_va, real_pdpte_va, sizeof(pdpte_64) * 448);
        int i = 448;
        for (; i < 512; i++)
            if ((fake_pdpte_va[i].ignored_2 & 0x400) == 0x400)
                break;

        if (i == 512)
            memcpy(&fake_pdpte_va[448], &real_pdpte_va[448], sizeof(pdpte_64) * (64));
        else
        {

            memcpy(&fake_pdpte_va[448], &real_pdpte_va[448], sizeof(pdpte_64) * (i - 448));

            for (; i < 512; i++)
            {
                if ((fake_pdpte_va[i].ignored_2 & 0x400) != 0x400)
                {
                    break;
                }

                fake_pdpte_va[i].flags = (fake_pdpte_va[i].flags & (PDPTE_64_PAGE_FRAME_NUMBER_FLAG | PDPTE_64_IGNORED_2_FLAG)) | (real_pdpte_va[i].flags & ~(PDPTE_64_PAGE_FRAME_NUMBER_FLAG | PDPTE_64_IGNORED_2_FLAG));

                pde_64* real_pde_va = (pde_64*)(host_physical_memory_base + (real_pdpte_va[i].page_frame_number << 12));
                pde_64* fake_pde_va = (pde_64*)(host_physical_memory_base + (fake_pdpte_va[i].page_frame_number << 12));

                int j = 0;
                for (; j < 512; j++)
                    if ((fake_pde_va[j].ignored_2 & 0x400) == 0x400)
                        break;

                if (j == 512)
                    memcpy(fake_pde_va, real_pde_va, sizeof(pde_64) * 512);
                else
                {
                    memcpy(&fake_pde_va[0], &real_pde_va[0], sizeof(pde_64) * (j));
                    for (; j < 512; j++)
                    {

                        if ((fake_pde_va[j].ignored_2 & 0x400) != 0x400)
                            break;

                        fake_pde_va[j].flags = (fake_pde_va[j].flags & (PDE_64_PAGE_FRAME_NUMBER_FLAG | PDE_64_IGNORED_2_FLAG)) | (real_pde_va[j].flags & ~(PDE_64_PAGE_FRAME_NUMBER_FLAG | PDE_64_IGNORED_2_FLAG));

                        pte_64* real_pte_va = (pte_64*)(host_physical_memory_base + (real_pde_va[j].page_frame_number << 12));
                        pte_64* fake_pte_va = (pte_64*)(host_physical_memory_base + (fake_pde_va[j].page_frame_number << 12));

                        int k = 0;
                        for (; k < 512; k++)
                            if ((fake_pte_va[k].ignored_1 & 0x1) == 0x1)
                                break;
                        if (k == 512)
                            memcpy(&fake_pte_va[k], &real_pte_va[k], sizeof(pte_64) * 512);
                        else
                        {
                            memcpy(&fake_pte_va[0], &real_pte_va[0], sizeof(pte_64) * (k));
                            for (; k < 512; k++)
                            {
                                if ((fake_pte_va[k].ignored_1 & 0x1) != 0x1)
                                    break;
                                fake_pte_va[k].flags = (fake_pte_va[k].flags & (PTE_64_PAGE_FRAME_NUMBER_FLAG | PTE_64_IGNORED_1_FLAG)) | (real_pte_va[k].flags & ~(PTE_64_PAGE_FRAME_NUMBER_FLAG | PTE_64_IGNORED_1_FLAG));
                               fake_pte_va[k].execute_disable = 0;
                                fake_pte_va[k].write = 1;

                            }
                            memcpy(&fake_pte_va[k], &real_pte_va[k], sizeof(pte_64) * (512 - k));
                        }
                    }
                    memcpy(&fake_pde_va[j], &real_pde_va[j], sizeof(pde_64) * (512 - j));
                }
            }
            memcpy(&fake_pdpte_va[i], &real_pdpte_va[i], sizeof(pdpte_64) * (512 - i));
        }
    }
    else
    {
        memcpy(&fake_cr3_va[255], &real_cr3_va[255], sizeof(pml4e_64));
    }
    memcpy(&fake_cr3_va[256], &real_cr3_va[256], sizeof(pml4e_64*) * 256);

}


void update_cr3_map_info()
{
   
    if (g_ghv->g_cr3_map.srcCr3.flags == 0)
        return;

    auto src_cr3_va = (pml4e_64*)(host_physical_memory_base + (g_ghv->g_cr3_map.srcCr3.address_of_page_directory << 12));
    auto fake_cr3_va = (pml4e_64*)(host_physical_memory_base + (g_ghv->g_cr3_map.fakeCr3.address_of_page_directory << 12));
    auto dst_cr3_va = (pml4e_64*)(host_physical_memory_base + (g_ghv->g_cr3_map.dstCr3.address_of_page_directory << 12));

    memcpy(fake_cr3_va, dst_cr3_va, sizeof(pml4e_64) * 254);
	memcpy(&fake_cr3_va[254], &src_cr3_va[g_ghv->g_cr3_map.pml4e_index], sizeof(pml4e_64));
    memcpy(&fake_cr3_va[255], &dst_cr3_va[255], sizeof(pml4e_64*) * 257);

}



} // namespace hv
