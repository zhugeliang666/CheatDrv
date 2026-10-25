#include "../base.h"
#include "vtcall-hook.h"
#include "ept-hook.h"
#include "hypercalls.h"
#include <cstddef>
#include "ia32.hpp"
#include "vcpu.h"
#include "vmx.h"
#include "mm.h"
#include "hv.h"
#include "debug-core.h"
#include "ept-probe.h"
#include "exception-routines.h"
#include "introspection.h"
#include <ntimage.h>
#include "../xorstr.h"
#include "../common/ntutils.h"
#include <poolmanager/PoolManager.h>

UINT64 gamevt_image_base = 0;
UINT64 gamevt_driver_unload = 0;

// first byte at the start of the image
extern "C" uint8_t __ImageBase;
extern "C" void yvt_set_keep_hv_on_unload(bool enable);
extern "C" volatile uint64_t* yvt_get_boot_flags_ptr();

namespace hv {
bool handle_vm_exit(guest_context* const ctx);
}

namespace hv::hc {

#pragma code_seg(".vm")

// 发送超调用探测虚拟机监控程序以确认其正常运行
void ping(vcpu* const cpu) {
  cpu->ctx->rax = hypervisor_signature;

  skip_instruction();
}

// 快速测试超调用
void test(vcpu* const cpu) {
  skip_instruction();
}

// devirtualize the current VCPU
void unload(vcpu* const cpu) {
  if (cpu && g_ghv->vcpus && g_ghv->vcpu_count) {
    auto const index = static_cast<uint64_t>(cpu - g_ghv->vcpus);
    if (index < 64) {
      _InterlockedOr64((volatile LONG64*)&g_ghv->stop_ack_bitmap,
                       (LONG64)(1ull << index));
    }
  }
  cpu->stop_virtualization = true;
  skip_instruction();
}

// read from arbitrary physical memory
void read_phys_mem(vcpu* const cpu) {
  auto const ctx = cpu->ctx;

  // arguments
  auto const dst  = reinterpret_cast<uint8_t*>(ctx->rcx);
  auto const src  = host_physical_memory_base + ctx->rdx;
  auto const size = ctx->r8;

  size_t bytes_read = 0;

  while (bytes_read < size) {
    size_t dst_remaining = 0;

    // translate the guest buffer into hypervisor space
    auto const curr_dst = gva2hva(dst + bytes_read, &dst_remaining);

    if (!curr_dst) {
      // guest virtual address that caused the fault
      ctx->cr2 = reinterpret_cast<uint64_t>(dst + bytes_read);

      page_fault_exception error;
      error.flags            = 0;
      error.present          = 0;
      error.write            = 1;
      error.user_mode_access = (current_guest_cpl() == 3);

      inject_hw_exception(page_fault, error.flags);
      return;
    }

    auto const curr_size = min(dst_remaining, size - bytes_read);

    host_exception_info e;
    memcpy_safe(e, curr_dst, src + bytes_read, curr_size);

    if (e.exception_occurred) {
      inject_hw_exception(general_protection, 0);
      return;
    }

    bytes_read += curr_size;
  }

  ctx->rax = bytes_read;
  skip_instruction();
}

// write to arbitrary physical memory
void write_phys_mem(vcpu* const cpu) {
  auto const ctx = cpu->ctx;

  // arguments
  auto const dst  = host_physical_memory_base + ctx->rcx;
  auto const src  = reinterpret_cast<uint8_t*>(ctx->rdx);
  auto const size = ctx->r8;

  size_t bytes_read = 0;

  while (bytes_read < size) {
    size_t src_remaining = 0;

    // translate the guest buffer into hypervisor space
    auto const curr_src = gva2hva(src + bytes_read, &src_remaining);

    if (!curr_src) {
      // guest virtual address that caused the fault
      ctx->cr2 = reinterpret_cast<uint64_t>(src + bytes_read);

      page_fault_exception error;
      error.flags            = 0;
      error.present          = 0;
      error.write            = 0;
      error.user_mode_access = (current_guest_cpl() == 3);

      //inject_hw_exception(page_fault, error.flags);
      return;
    }

    auto const curr_size = min(size - bytes_read, src_remaining);

    host_exception_info e;
    memcpy_safe(e, dst + bytes_read, curr_src, curr_size);

    if (e.exception_occurred) {
      inject_hw_exception(general_protection, 0);
      return;
    }

    bytes_read += curr_size;
  }

  ctx->rax = bytes_read;
  skip_instruction();
}

// read from virtual memory in another process
void read_virt_mem(vcpu* const cpu) {
  auto const ctx = cpu->ctx;

  // arguments
  cr3 guest_cr3 = g_ghv->system_cr3;
  if (ctx->rcx)
    guest_cr3.flags = ctx->rcx;

  auto const dst  = reinterpret_cast<uint8_t*>(ctx->rdx);
  auto const src  = reinterpret_cast<uint8_t*>(ctx->r8);
  auto const size = ctx->r9;

  size_t bytes_read = 0;

  while (bytes_read < size) {
    size_t dst_remaining = 0, src_remaining = 0;

    // translate the guest virtual addresses into host virtual addresses.
    // this has to be done 1 page at a time. :(
    auto const curr_dst = gva2hva(dst + bytes_read, &dst_remaining);
    auto const curr_src = gva2hva(guest_cr3, src + bytes_read, &src_remaining);

    if (!curr_dst) {
      // guest virtual address that caused the fault
      ctx->cr2 = reinterpret_cast<uint64_t>(dst + bytes_read);

      page_fault_exception error;
      error.flags            = 0;
      error.present          = 0;
      error.write            = 1;
      error.user_mode_access = (current_guest_cpl() == 3);

      //inject_hw_exception(page_fault, error.flags);
      return;
    }

    // this means that the target memory isn't paged in. there's nothing
    // we can do about that since we're not currently in that process's context.
    if (!curr_src)
      break;

    // the maximum allowed size that we can read at once with the translated HVAs
    auto const curr_size = min(size - bytes_read, min(dst_remaining, src_remaining));

    host_exception_info e;
    memcpy_safe(e, curr_dst, curr_src, curr_size);

    if (e.exception_occurred) {
      // this REALLY shouldn't happen... ever...
      inject_hw_exception(general_protection, 0);
      return;
    }

    bytes_read += curr_size;
  }

  ctx->rax = bytes_read;
  skip_instruction();
}

// write to virtual memory in another process
void write_virt_mem(vcpu* const cpu) {
  auto const ctx = cpu->ctx;

  // arguments
  cr3 guest_cr3 = g_ghv->system_cr3;
  if (ctx->rcx)
    guest_cr3.flags = ctx->rcx;

  auto const dst  = reinterpret_cast<uint8_t*>(ctx->rdx);
  auto const src  = reinterpret_cast<uint8_t*>(ctx->r8);
  auto const size = ctx->r9;

  size_t bytes_read = 0;

  while (bytes_read < size) {
    size_t dst_remaining = 0, src_remaining = 0;

    // translate the guest virtual addresses into host virtual addresses.
    // this has to be done 1 page at a time. :(
    auto const curr_dst = gva2hva(guest_cr3, dst + bytes_read, &dst_remaining);
    auto const curr_src = gva2hva(src + bytes_read, &src_remaining);

    if (!curr_src) {
      // guest virtual address that caused the fault
      ctx->cr2 = reinterpret_cast<uint64_t>(src + bytes_read);

      page_fault_exception error;
      error.flags            = 0;
      error.present          = 0;
      error.write            = 0;
      error.user_mode_access = (current_guest_cpl() == 3);

      //inject_hw_exception(page_fault, error.flags);
      ctx->rax = 0;
      return;
    }

    // this means that the target memory isn't paged in. there's nothing
    // we can do about that since we're not currently in that process's context.
    if (!curr_dst)
      break;

    // the maximum allowed size that we can read at once with the translated HVAs
    auto const curr_size = min(size - bytes_read, min(dst_remaining, src_remaining));

    host_exception_info e;
    memcpy_safe(e, curr_dst, curr_src, curr_size);

    if (e.exception_occurred) {
      // this REALLY shouldn't happen... ever...
      inject_hw_exception(general_protection, 0);
      ctx->rax = 0;
      return;
    }

    bytes_read += curr_size;
  }

  ctx->rax = bytes_read;
  skip_instruction();
}

// get the kernel CR3 value of an arbitrary process
void query_process_cr3(vcpu* const cpu) {
  // PID of the process to get the CR3 value of
  auto const target_pid = cpu->ctx->rcx;

  // System process
  if (target_pid == 4) {
    cpu->ctx->rax = g_ghv->system_cr3.flags;
    skip_instruction();
    return;
  }

  cpu->ctx->rax = 0;

  // ActiveProcessLinks is right after UniqueProcessId in memory
  auto const apl_offset = g_ghv->eprocess_unique_process_id_offset + 8;
  auto const head = g_ghv->system_eprocess + apl_offset;
  auto curr_entry = head;

  // iterate over every EPROCESS in the APL linked list
  do {
    // get the next entry in the linked list
    if (sizeof(curr_entry) != read_guest_virtual_memory(g_ghv->system_cr3,
        curr_entry + offsetof(LIST_ENTRY, Flink), &curr_entry, sizeof(curr_entry)))
      break;

    // EPROCESS
    auto const process = curr_entry - apl_offset;

    // EPROCESS::UniqueProcessId
    uint64_t pid = 0;
    if (sizeof(pid) != read_guest_virtual_memory(g_ghv->system_cr3,
        process + g_ghv->eprocess_unique_process_id_offset, &pid, sizeof(pid)))
      break;

    // we found the target process
    if (target_pid == pid) {
      // EPROCESS::DirectoryTableBase
      uint64_t cr3 = 0;
      if (sizeof(cr3) != read_guest_virtual_memory(g_ghv->system_cr3,
          process + g_ghv->kprocess_directory_table_base_offset, &cr3, sizeof(cr3)))
        break;

      cpu->ctx->rax = cr3;
      break;
    }
  } while (curr_entry != head);

  skip_instruction();
}

// install an EPT hook for the CURRENT logical processor ONLY
void install_ept_hook(vcpu* const cpu) {
  // arguments
  auto const orig_page_pfn = cpu->ctx->rcx;
  auto const exec_page_pfn = cpu->ctx->rdx;
  auto const is_fake_page = cpu->ctx->r8;

  cpu->ctx->rax = install_ept_hook(cpu->ept, orig_page_pfn, exec_page_pfn,is_fake_page);

  skip_instruction();
}

// remove a previously installed EPT hook
void remove_ept_hook(vcpu* const cpu) {
  // arguments
  auto const orig_page_pfn = cpu->ctx->rcx;

  remove_ept_hook(cpu->ept, orig_page_pfn);

  skip_instruction();
}

// flush the hypervisor logs into a buffer
void flush_logs(vcpu* const cpu) {
  auto const ctx = cpu->ctx;

  // arguments
  uint32_t count = ctx->ecx;
  uint8_t* buffer = reinterpret_cast<uint8_t*>(ctx->rdx);

  ctx->eax = 0;

  if (count <= 0) {
    skip_instruction();
    return;
  }

  auto& l = g_ghv->logger;

  scoped_spin_lock lock(l.lock);

  count = min(count, l.msg_count);

  auto start = reinterpret_cast<uint8_t*>(&l.msgs[l.msg_start]);
  auto size = min(l.max_msg_count - l.msg_start, count) * sizeof(l.msgs[0]);

  // read the first chunk of logs before circling back around (if needed)
  for (size_t bytes_read = 0; bytes_read < size;) {
    size_t dst_remaining = 0;

    // translate the guest virtual address
    auto const curr_dst = gva2hva(buffer + bytes_read, &dst_remaining);

    if (!curr_dst) {
      // guest virtual address that caused the fault
      ctx->cr2 = reinterpret_cast<uint64_t>(buffer + bytes_read);

      page_fault_exception error;
      error.flags = 0;
      error.present = 0;
      error.write = 1;
      error.user_mode_access = (current_guest_cpl() == 3);

      inject_hw_exception(page_fault, error.flags);

      return;
    }

    // the maximum allowed size that we can read at once with the translated HVAs
    auto const curr_size = min(size - bytes_read, dst_remaining);

    host_exception_info e;
    memcpy_safe(e, curr_dst, start + bytes_read, curr_size);

    if (e.exception_occurred) {
      // this REALLY shouldn't happen... ever...
      inject_hw_exception(general_protection, 0);
      return;
    }

    bytes_read += curr_size;
  }

  buffer += size;
  start = reinterpret_cast<uint8_t*>(&l.msgs[0]);
  size = (count * sizeof(l.msgs[0])) - size;

  for (size_t bytes_read = 0; bytes_read < size;) {
    size_t dst_remaining = 0;

    // translate the guest virtual address
    auto const curr_dst = gva2hva(buffer + bytes_read, &dst_remaining);

    if (!curr_dst) {
      // guest virtual address that caused the fault
      ctx->cr2 = reinterpret_cast<uint64_t>(buffer + bytes_read);

      page_fault_exception error;
      error.flags = 0;
      error.present = 0;
      error.write = 1;
      error.user_mode_access = (current_guest_cpl() == 3);

      inject_hw_exception(page_fault, error.flags);
      return;
    }

    // the maximum allowed size that we can read at once with the translated HVAs
    auto const curr_size = min(size - bytes_read, dst_remaining);

    host_exception_info e;
    memcpy_safe(e, curr_dst, start + bytes_read, curr_size);

    if (e.exception_occurred) {
      // this REALLY shouldn't happen... ever...
      inject_hw_exception(general_protection, 0);
      return;
    }

    bytes_read += curr_size;
  }

  l.msg_count -= count;
  l.msg_start = (l.msg_start + count) % l.max_msg_count;

  ctx->eax = count;

  skip_instruction();
}

// translate a virtual address to its physical address
void get_physical_address(vcpu* const cpu) {
  auto guest_cr3 = g_ghv->system_cr3;

  // use the system CR3 if none is provided
  if (cpu->ctx->rcx)
    guest_cr3.flags = cpu->ctx->rcx;

  cpu->ctx->rax = gva2gpa(guest_cr3, reinterpret_cast<void*>(cpu->ctx->rdx));

  skip_instruction();
}

// hide a physical page from the guest
void hide_physical_page(vcpu* const cpu) {
  auto const pfn = cpu->ctx->rcx;
  auto const pte = get_ept_pte(cpu->ept, pfn << 12, true);

  // this can occur if we failed to split the PDE
  if (!pte) {
    cpu->ctx->rax = 0;
    skip_instruction();
    return;
  }

  pte->page_frame_number = cpu->ept.dummy_page_pfn;
  vmx_invept(invept_all_context, {});

  cpu->ctx->rax = 1;
  skip_instruction();


}

// unhide a physical page from the guest
void unhide_physical_page(vcpu* const cpu) {
  auto const pfn = cpu->ctx->rcx;
  auto const pte = get_ept_pte(cpu->ept, pfn << 12, false);

  // this can occur if we never hid the page in the first place
  if (!pte) {
    skip_instruction();
    return;
  }

  pte->page_frame_number = pfn;
  vmx_invept(invept_all_context, {});

  skip_instruction();
}

// Append a PFN to g_ghv->pending_hide_pfns[]. mapDriver calls this once per PFN
// it wants hidden. Idempotent on overflow (silently drops). Uses interlocked
// increment so multiple vcpus could call concurrently though typical use is
// single-threaded from mapDriver.
void prepare_self_hide_add(vcpu* const cpu) {
  auto const pfn = cpu->ctx->rcx;
  auto const idx = (uint32_t)_InterlockedIncrement(
      (volatile LONG*)&g_ghv->pending_hide_count) - 1;
  if (idx < hypervisor::pending_hide_capacity) {
    g_ghv->pending_hide_pfns[idx] = pfn;
    cpu->ctx->rax = 1;
  } else {
    // overflow 鈥 undo the increment cap and report failure
    g_ghv->pending_hide_count = hypervisor::pending_hide_capacity;
    cpu->ctx->rax = 0;
  }
  skip_instruction();
}

// Arm the deferred hide. Before publishing the bitmap, automatically queue
// testDriver's own PoolManager blocks (vcpus / host_stack / pml4e / hide
// PFN buffer / etc) 鈥 those are physical pages allocated by testDriver via
// MmAllocateIndependentPages, not contiguous with the testDriver image, so
// the caller (mapDriver) can't reach them just by walking the image VA.
//
//   args[0] = rcx = delay_microseconds (e.g. 100 leaves time for mapDriver
//             to return and Windows to schedule something else before any
//             vcpu actually starts hiding).
void prepare_self_hide_commit(vcpu* const cpu) {
  // Auto-queue testDriver's PoolManager blocks. Each entry's VritualAddress
  // is a system VA; translate via system CR3 to PFN.
  //
  // NOTE 2026-05-26: 'tram' (trampoline exec pages) used to be skipped on
  // the theory that hiding them would break trampoline execution. That
  // theory was wrong 鈥 guest never accesses tram block via its own GPA;
  // the only access path is `orig_pfn 鈫 EPT(orig_pfn).PFN = exec_pfn 鈫
  // CPU physical fetch of exec_pfn`. EPT translation happens once, so
  // adding a second hook on exec_pfn (redirect to dummy when guest
  // probes exec_pfn's GPA directly) is invisible to the trampoline path.
  // Host's own writes to tram bytes already go through host_physical_memory_base
  // (vtcall-hook.cpp alloc_trampoline), bypassing system VA / PTE entirely.
  if (Util::IsPoolManagerInit) {
    auto temp = Util::Pools.ActiveListHead.Flink;
    while (temp != &Util::Pools.ActiveListHead) {
      auto entry = CONTAINING_RECORD(temp, Util::POOL_ENTRY, ListEntry);
      uint64_t const block_base = (uint64_t)entry->VritualAddress;
      uint64_t const block_end  = block_base + entry->NumberOfBytes;

      // Register the block's full VA range in prot_ranges so Mm* hooks
      // can fast-reject probes touching it (one entry per pool block,
      // not per page).
      {
        auto idx = g_ghv->prot_range_count;
        if (idx < hypervisor::prot_range_capacity) {
          g_ghv->prot_ranges[idx].base = block_base;
          g_ghv->prot_ranges[idx].end  = block_end;
          g_ghv->prot_range_count = idx + 1;
        }
      }

      for (uint64_t va = block_base; va < block_end; va += PAGE_SIZE) {
        auto gpa = gva2gpa(g_ghv->system_cr3, reinterpret_cast<void*>(va));
        if (!gpa) continue;
        auto idx = (uint32_t)_InterlockedIncrement(
            (volatile LONG*)&g_ghv->pending_hide_count) - 1;
        if (idx < hypervisor::pending_hide_capacity) {
          g_ghv->pending_hide_pfns[idx] = gpa >> 12;
        } else {
          g_ghv->pending_hide_count = hypervisor::pending_hide_capacity;
          break;
        }
      }
      temp = temp->Flink;
    }
  }

  // Register testDriver image VA range (covered by mapDriver's emit() too,
  // but adding it as a single prot_range entry makes Mm* hook lookup O(1)
  // for the image and avoids walking individual PFNs).
  if (g_yvt.vtInfo.imageBase && g_yvt.vtInfo.imageSize) {
    auto idx = g_ghv->prot_range_count;
    if (idx < hypervisor::prot_range_capacity) {
      g_ghv->prot_ranges[idx].base = (uint64_t)g_yvt.vtInfo.imageBase;
      g_ghv->prot_ranges[idx].end  = (uint64_t)g_yvt.vtInfo.imageBase
                                + g_yvt.vtInfo.imageSize;
      g_ghv->prot_range_count = idx + 1;
    }
  }

  uint64_t const delay_us = cpu->ctx->rcx ? cpu->ctx->rcx : 100;
  uint64_t const tsc_hz = 3'000'000'000ULL;
  g_ghv->pending_hide_tsc_threshold = __rdtsc() + (tsc_hz * delay_us) / 1'000'000ULL;

  auto const ncpus = (uint64_t)g_ghv->vcpu_count;
  auto const bitmap = (ncpus >= 64) ? ~0ULL : ((1ULL << ncpus) - 1);
  _InterlockedExchange64((volatile LONG64*)&g_ghv->pending_hide_vcpu_bitmap,
      (LONG64)bitmap);

  cpu->ctx->rax = g_ghv->pending_hide_count;
  skip_instruction();
}

// Master switch for KTHREAD.Affinity rewrite in hv::Call. rcx=1 enable, 0 disable.
// Affects entry-side write only; restore side always runs to undo any pending pin.
void set_affinity_lock(vcpu* const cpu) {
  g_ghv->affinity_lock_enabled = (cpu->ctx->rcx != 0);
  cpu->ctx->rax = 1;
  skip_instruction();
}

// rcx=1 keeps resident HV on DriverUnload, rcx=0 allows a full hv::stop().
void set_keep_hv_on_unload(vcpu* const cpu) {
  yvt_set_keep_hv_on_unload(cpu->ctx->rcx != 0);
  cpu->ctx->rax = 1;
  skip_instruction();
}

// Caller-supplied buffer element layout matches mapDriver's pool_block_record.
struct pool_block_record {
  uint64_t va;
  uint64_t bytes;
  uint32_t tag;
  uint32_t flags;
};

// rcx = guest VA of output array (must be writable in current CR3)
// rdx = max records
// returns count actually written in rax.
void get_pool_blocks(vcpu* const cpu) {
  auto const out_gva = (pool_block_record*)cpu->ctx->rcx;
  uint64_t const max = cpu->ctx->rdx;
  uint64_t written = 0;

  if (Util::IsPoolManagerInit && out_gva && max) {
    auto temp = Util::Pools.ActiveListHead.Flink;
    while (temp != &Util::Pools.ActiveListHead && written < max) {
      auto entry = CONTAINING_RECORD(temp, Util::POOL_ENTRY, ListEntry);
      auto rec_host = (pool_block_record*)gva2hva(out_gva + written);
      if (!rec_host) break;
      rec_host->va    = (uint64_t)entry->VritualAddress;
      rec_host->bytes = entry->NumberOfBytes;
      rec_host->tag   = entry->Source;
      rec_host->flags = entry->UsedIndependent ? 0x00000001u : 0x00000002u;
      written++;
      temp = temp->Flink;
    }
  }

  cpu->ctx->rax = written;
  skip_instruction();
}

// Hide a list of PFNs on the CURRENT vcpu's EPT only (mapDriver wraps this
// in an affinity loop, one call per CPU). Bulk path avoids the 30K+ vmcall
// round trips that prepare_self_hide_add would need.
//
// args[0] = guest VA of uint64[count] PFN array (system CR3)
// args[1] = count
//
// Returns count of PFNs successfully redirected to dummy_page_pfn in rax.
//
// Each PFN: find its EPT PTE in current vcpu's tree (force split if 2MB),
// rewrite page_frame_number = dummy_page_pfn. After the loop a single
// invept_all_context flushes stale EPT translations.
//
// IMPORTANT: keep total work bounded 鈥 too long a host-mode spin starves
// clock interrupts on every other CPU (one of them will hit BugCheck 0x101
// CLOCK_WATCHDOG_TIMEOUT). 30K PFNs at ~100ns per get_ept_pte 鈮 3ms which
// is well under the 120ms threshold. If callers pass >> 100K PFNs we may
// need a per-call cap with continuation cursor.
void hide_pfn_list(vcpu* const cpu) {
  auto const pfn_array_gva = reinterpret_cast<uint64_t*>(cpu->ctx->rcx);
  uint64_t count = cpu->ctx->rdx;
  uint64_t hidden = 0;
  uint64_t pte_null = 0;

  if (!pfn_array_gva || !count) {
    cpu->ctx->rax = 0;
    skip_instruction();
    return;
  }

  if (count > hypervisor::pending_hide_capacity)
    count = hypervisor::pending_hide_capacity;

  auto const dummy_pfn = cpu->ept.dummy_page_pfn;

  // Walk array page-by-page: one gva2hva per chunk of consecutive PFNs
  // that share a 4K page, instead of per-PFN.
  uint64_t idx = 0;
  while (idx < count) {
    uint64_t const chunk_gva = (uint64_t)(pfn_array_gva + idx);
    auto const chunk_hva = (uint64_t*)gva2hva(reinterpret_cast<void*>(chunk_gva));
    if (!chunk_hva) break;

    uint64_t const page_off = chunk_gva & 0xFFFull;
    uint64_t const room     = (PAGE_SIZE - page_off) / sizeof(uint64_t);
    uint64_t const this_chunk = (count - idx < room) ? (count - idx) : room;

    for (uint64_t k = 0; k < this_chunk; k++) {
      uint64_t const pfn = chunk_hva[k];
      if (!pfn) continue;
      auto const pte = get_ept_pte(cpu->ept, pfn << 12, true);
      if (!pte) {
        pte_null++;
        continue;
      }
      pte->page_frame_number = dummy_pfn;
      hidden++;
    }
    idx += this_chunk;
  }

  _InterlockedExchangeAdd64((volatile LONG64*)&g_ghv->diag_hide_pte_total, (LONG64)count);
  _InterlockedExchangeAdd64((volatile LONG64*)&g_ghv->diag_hide_pte_null, (LONG64)pte_null);
  vmx_invept(invept_all_context, {});

  cpu->ctx->rax = hidden;
  skip_instruction();
}

void ept_probe_install(vcpu* const cpu) {
  auto const target_cr3 = cpu->ctx->rcx;
  auto const target_va = cpu->ctx->rdx;
  auto const flags = cpu->ctx->r8;
  auto const hit_limit = cpu->ctx->r9;
  cpu->ctx->rax = hv::ept_probe_install_current(cpu, target_cr3, target_va, flags, hit_limit);
  skip_instruction();
}

void ept_probe_remove(vcpu* const cpu) {
  auto const target_cr3 = cpu->ctx->rcx;
  auto const target_va = cpu->ctx->rdx;
  auto const flags = cpu->ctx->r8;
  cpu->ctx->rax = hv::ept_probe_remove_current(cpu, target_cr3, target_va, flags);
  skip_instruction();
}

void ept_probe_get_hits(vcpu* const cpu) {
  auto const out_gva = cpu->ctx->rcx;
  auto const max_hits = cpu->ctx->rdx;
  auto const clear_after = cpu->ctx->r8 != 0;
  cpu->ctx->rax = hv::ept_probe_copy_hits(cpu, out_gva, max_hits, clear_after);
  skip_instruction();
}

void ept_probe_clear_hits(vcpu* const cpu) {
  cpu->ctx->rax = hv::ept_probe_clear_hits();
  skip_instruction();
}

void dbg_dispatch(vcpu* const cpu) {
  hv::dbg_handle_hypercall(cpu);
  skip_instruction();
}

// rcx = guest VA of 6 x uint64 buffer; writes:
//   [0] diag_hide_enter
//   [1] diag_hide_pte_total
//   [2] diag_hide_pte_null
//   [3] diag_hide_done_bitmap
//   [4] max num_used_free_pages across all vcpus
//   [5] ept_free_page_count (capacity)
void get_hide_diag(vcpu* const cpu) {
  auto const out_gva = (uint64_t*)cpu->ctx->rcx;
  if (out_gva) {
    auto out_host = (uint64_t*)gva2hva(out_gva);
    if (out_host) {
      out_host[0] = g_ghv->diag_hide_enter;
      out_host[1] = g_ghv->diag_hide_pte_total;
      out_host[2] = g_ghv->diag_hide_pte_null;
      out_host[3] = g_ghv->diag_hide_done_bitmap;
      // max EPT split pages used across all vcpus
      size_t max_used = 0;
      for (int i = 0; i < g_ghv->vcpu_count; i++) {
        if (g_ghv->vcpus[i].ept.num_used_free_pages > max_used)
          max_used = g_ghv->vcpus[i].ept.num_used_free_pages;
      }
      out_host[4] = (uint64_t)max_used;
      out_host[5] = (uint64_t)ept_free_page_count;
    }
  }
  skip_instruction();
}

static constexpr uint64_t resident_hv_diag_magic = 0x4D41504856444731ull; // MAPHVDG1

struct resident_hv_diag_record
{
  uint64_t magic;
  uint64_t size;
  uint64_t version;
  uint64_t current_vcpu;
  uint64_t vcpu_count;
  uint64_t ghv_ptr;
  uint64_t vcpus_ptr;
  uint64_t current_vcpu_ptr;
  uint64_t vmcs_host_rip;
  uint64_t vmcs_host_rsp;
  uint64_t current_host_stack;
  uint64_t host_stack_bytes;
  uint64_t vm_exit_ptr;
  uint64_t handle_vm_exit_ptr;
  uint64_t image_base;
  uint64_t driver_unload;
  uint64_t flags;
  uint64_t ghv_off_kpcr_prcb_offset;
  uint64_t ghv_off_kprcb_current_thread_offset;
  uint64_t ghv_off_kthread_apc_state_offset;
  uint64_t ghv_off_kapc_state_process_offset;
  uint64_t ghv_off_vtcallstack_list;
  uint64_t ghv_off_tramp_pool;
  uint64_t ghv_off_dbg;
  uint64_t ghv_off_dbg_events;
  uint64_t ghv_off_dbg_watch;
  uint64_t vcpu_stride;
  uint64_t vcpu_off_ept;
  uint64_t vcpu_off_ept_free_pages;
  uint64_t vcpu_off_ept_free_page_pfns;
  uint64_t vcpu_off_ept_hook_active_list;
  uint64_t vcpu_off_dbg_pending;
  uint64_t ghv_off_affinity_lock_enabled;
  uint64_t ghv_off_diag_hide_enter;
  uint64_t ghv_off_diag_hide_pte_total;
  uint64_t ghv_off_diag_hide_pte_null;
  uint64_t ghv_off_diag_hide_done_bitmap;
  uint64_t vcpu_off_ept_num_used_free_pages;
  uint64_t vcpu_off_ept_dummy_page_pfn;
  uint64_t ept_free_page_count;
  uint64_t gamevt_image_base_ptr;
  uint64_t gamevt_driver_unload_ptr;
  uint64_t yvt_boot_flags_ptr;
  uint64_t system_eprocess;
  uint64_t kprocess_directory_table_base_offset;
  uint64_t eprocess_unique_process_id_offset;
  uint64_t ghv_off_cr3_map_real_cr3;
  uint64_t vt_hook_table_ptr;
  uint64_t vt_hook_slot_count;
  uint64_t vt_hook_slot_size;
  uint64_t vt_hook_slot_off_data_address;
  uint64_t vt_hook_slot_off_data_type;
  uint64_t vt_hook_slot_off_data_blank_memory;
  uint64_t vt_hook_slot_off_data_dispatch_mode;
  uint64_t vt_hook_slot_off_occupied;
  uint64_t vt_hook_slot_off_trampoline_va;
  uint64_t vt_hook_slot_off_bp_rip;
  uint64_t vt_hook_slot_off_target_resume;
  uint64_t render_swapchain_ptr;
  uint64_t render_isfinish_ptr;
  uint64_t ghv_off_dwm_hit_count;
  uint64_t ghv_off_diag_handler_count;
  uint64_t render_d2d_rt_ptr;
  uint64_t render_color_brush_ptr;
  uint64_t render_text_format_ptr;
  uint64_t render_buffer0_ptr;
  uint64_t render_buffer0_hva_ptr;
  uint64_t render_desc_buffer_ptr;
  uint64_t render_desc_buffer_hva_ptr;
  uint64_t ghv_off_kthread_affinity_offset;
  uint64_t ghv_off_kthread_user_affinity_offset;
  uint64_t ghv_off_kthread_ideal_processor_offset;
  uint64_t ghv_off_kthread_user_ideal_processor_offset;
  uint64_t vcpu_off_pending_state;
  uint64_t vcpu_off_pending_host_rsp_restore;
  uint64_t vcpu_off_pending_vtcallstack_node;
  uint64_t vcpu_off_pending_release_delay;
  uint64_t ghv_size;
  uint64_t vt_hook_table_bytes;
  uint64_t ntapi_virtual_alloc;
  uint64_t ntapi_read_process_memory;
  uint64_t ntapi_virtual_lock;
  uint64_t ntapi_d2d1_create_factory;
  uint64_t ntapi_dwrite_create_factory;
  uint64_t ob_reference_object_by_handle_va;
  uint64_t obf_dereference_object_va;
  uint64_t ntapi_file_name_offset;
  uint64_t ghv_off_kernel_blank_va;
  uint64_t ghv_off_csec_scratch_va;
  uint64_t ghv_off_csec_format_va;
  uint64_t ghv_off_stop_phase;
  uint64_t ghv_off_stop_expected_bitmap;
  uint64_t ghv_off_stop_requested_bitmap;
  uint64_t ghv_off_stop_before_vmcall_bitmap;
  uint64_t ghv_off_stop_after_vmcall_bitmap;
  uint64_t ghv_off_stop_ack_bitmap;
  uint64_t ghv_off_stop_exception_bitmap;
  uint64_t ghv_off_stop_cleanup_bitmap;
  uint64_t ghv_off_stop_last_cpu;
  uint64_t ghv_off_stop_result;
  uint64_t vt_hook_slot_off_data_process;
  uint64_t vt_hook_slot_off_data_filter_by_process;
  uint64_t vt_hook_slot_off_data_is_enable;
  uint64_t ghv_off_prot_ranges;
  uint64_t ghv_off_prot_range_count;
  uint64_t ghv_prot_range_capacity;
  uint64_t ghv_prot_range_stride;
  uint64_t ghv_prot_range_off_base;
  uint64_t ghv_prot_range_off_end;
  uint64_t ghv_off_fake_data;
  uint64_t ghv_off_diag_getbuffer_hits;
  uint64_t ghv_off_diag_getbuffer_alien;
  uint64_t ghv_off_diag_present_hits;
  uint64_t ghv_off_diag_present_alien;
  uint64_t ghv_off_diag_present1_hits;
  uint64_t ghv_off_diag_present1_alien;
  uint64_t ghv_off_diag_copyresource_hits;
  uint64_t ghv_off_diag_copyresource_alien;
  uint64_t ghv_off_diag_duplicateoutput_hits;
  uint64_t ghv_off_diag_duplicateoutput_alien;
  uint64_t ghv_off_diag_nt_alloc_hits;
  uint64_t ghv_off_diag_nt_alloc_alien;
  uint64_t ghv_off_diag_nt_protect_hits;
  uint64_t ghv_off_diag_nt_protect_alien;
  uint64_t ghv_off_diag_nt_map_hits;
  uint64_t ghv_off_diag_nt_map_alien;
  uint64_t ghv_off_diag_nt_csec_hits;
  uint64_t ghv_off_diag_nt_csec_image;
  uint64_t ghv_off_diag_nt_csec_alien;
  uint64_t ghv_off_diag_capture_notify_count;
  uint64_t ghv_off_diag_mmcopy_hits;
  uint64_t ghv_off_diag_mmcopy_last_caller_rip;
  uint64_t ghv_off_diag_mmcm_hits;
  uint64_t ghv_off_diag_mmcm_blocked;
  uint64_t ghv_off_diag_mmcvm_hits;
  uint64_t ghv_off_diag_mmcvm_blocked;
  uint64_t ghv_off_diag_mmisav_hits;
  uint64_t ghv_off_diag_mmisav_blocked;
  uint64_t ghv_off_diag_mmmio_hits;
  uint64_t ghv_off_diag_mmmio_blocked;
  uint64_t dwmcore_base;
  uint64_t dwmcore_size;
  uint64_t dxgi_base;
  uint64_t dxgi_size;
  uint64_t ghv_off_ept_hook_table;
  uint64_t ghv_off_pending_ept_install_entries;
  uint64_t ghv_off_pending_ept_install_bitmap;
  uint64_t ghv_off_diag_pending_queue_full;
  uint64_t ghv_pending_install_capacity;
  uint64_t ept_hook_table_off_lock;
  uint64_t ept_hook_table_off_in_use_count;
  uint64_t ept_hook_table_off_active_list_head;
  uint64_t ept_hook_table_off_free_list_head;
  uint64_t ept_hook_table_off_buffer;
  uint64_t ept_hook_table_off_fake_pages;
  uint64_t ept_hook_table_off_fake_page_pfns;
  uint64_t ept_hook_table_capacity;
  uint64_t ept_hook_entry_size;
  uint64_t ept_hook_entry_off_next;
  uint64_t ept_hook_entry_off_process;
  uint64_t ept_hook_entry_off_process_cr3;
  uint64_t ept_hook_entry_off_va;
  uint64_t ept_hook_entry_off_orig_pfn;
  uint64_t ept_hook_entry_off_fake_pfn;
  uint64_t ept_hook_entry_off_fake_page_idx;
  uint64_t ept_hook_entry_off_in_use;
  uint64_t ept_hook_entry_off_is_fake_page;
  uint64_t ept_hook_entry_off_per_vcpu_active_bitmap;
  uint64_t nt_create_section_va;
  uint64_t nt_set_event_va;
  uint64_t nt_allocate_virtual_memory_va;
  uint64_t nt_protect_virtual_memory_va;
  uint64_t nt_map_view_of_section_va;
  uint64_t mm_copy_memory_va;
  uint64_t mm_copy_virtual_memory_va;
  uint64_t mm_is_address_valid_va;
  uint64_t mm_map_io_space_va;
  uint64_t mm_is_address_valid_ex_va;
  uint64_t nt_query_virtual_memory_va;
  uint64_t mm_get_physical_address_va;
  uint64_t ghv_off_copyresource_addr;
  uint64_t ghv_off_duplicateoutput_addr;
  uint64_t vcpu_off_ctx;
  uint64_t ghv_off_pending_ept_invept_bitmap;
  uint64_t ghv_off_pending_hide_pfns;
  uint64_t ghv_off_pending_hide_count;
  uint64_t ghv_off_pending_hide_vcpu_bitmap;
  uint64_t ghv_off_pending_hide_tsc_threshold;
  uint64_t ghv_off_diag_per_vcpu_vmexits;
  uint64_t vcpu_off_hide_vm_exit_overhead;
  uint64_t vcpu_off_stop_virtualization;
  uint64_t vcpu_off_ept_mmr_mtf_pte;
  uint64_t vcpu_off_ept_mmr_mtf_mode;
  uint64_t vcpu_off_ept_mmr_mtf_page_frame;
  uint64_t vcpu_ept_hook_node_off_next;
  uint64_t vcpu_ept_hook_node_off_orig_pfn;
  uint64_t vcpu_ept_hook_node_off_exec_pfn;
  uint64_t vcpu_ept_hook_node_off_is_fake_page;
  uint64_t vcpu_off_svm_resident_loop;
  uint64_t vcpu_off_svm_resident_ack;
};

static_assert(sizeof(resident_hv_diag_record) == 0x640,
              "Intel resident_hv_diag_record must match mapctl_hv_diag layout");

void get_resident_hv_diag(vcpu* const cpu) {
  auto const out_gva = reinterpret_cast<void*>(cpu->ctx->rcx);
  auto const out_size = cpu->ctx->rdx;
  cpu->ctx->rax = 0;

  if (!out_gva || out_size < sizeof(resident_hv_diag_record)) {
    skip_instruction();
    return;
  }

  resident_hv_diag_record record = {};

  uint64_t current_index = ~0ull;
  if (g_ghv->vcpus && cpu >= g_ghv->vcpus && cpu < (g_ghv->vcpus + g_ghv->vcpu_count))
    current_index = (uint64_t)(cpu - g_ghv->vcpus);

  record.magic = resident_hv_diag_magic;
  record.size = sizeof(record);
  record.version = 24;
  record.current_vcpu = current_index;
  record.vcpu_count = g_ghv->vcpu_count;
  record.ghv_ptr = (uint64_t)g_ghv;
  record.vcpus_ptr = (uint64_t)g_ghv->vcpus;
  record.current_vcpu_ptr = (uint64_t)cpu;
  record.vmcs_host_rip = vmx_vmread(VMCS_HOST_RIP);
  record.vmcs_host_rsp = vmx_vmread(VMCS_HOST_RSP);
  record.current_host_stack = cpu ? (uint64_t)cpu->host_stack : 0;
  record.host_stack_bytes = host_stack_size;
  record.vm_exit_ptr = (uint64_t)vm_exit;
  record.handle_vm_exit_ptr = (uint64_t)handle_vm_exit;
  record.image_base = gamevt_image_base;
  record.driver_unload = gamevt_driver_unload;
  record.flags = 1;
  record.ghv_off_kpcr_prcb_offset = offsetof(hypervisor, kpcr_pcrb_offset);
  record.ghv_off_kprcb_current_thread_offset = offsetof(hypervisor, kprcb_current_thread_offset);
  record.ghv_off_kthread_apc_state_offset = offsetof(hypervisor, kthread_apc_state_offset);
  record.ghv_off_kapc_state_process_offset = offsetof(hypervisor, kapc_state_process_offset);
  record.ghv_off_vtcallstack_list = offsetof(hypervisor, vtcallstack_list);
  record.ghv_off_tramp_pool = offsetof(hypervisor, tramp_pool);
  record.ghv_off_dbg = offsetof(hypervisor, dbg);
  record.ghv_off_dbg_events = offsetof(hypervisor, dbg_events);
  record.ghv_off_dbg_watch = offsetof(hypervisor, dbg_watch);
  record.vcpu_stride = sizeof(vcpu);
  record.vcpu_off_ept = offsetof(vcpu, ept);
  record.vcpu_off_ept_free_pages =
      offsetof(vcpu, ept) + offsetof(vcpu_ept_data, free_pages);
  record.vcpu_off_ept_free_page_pfns =
      offsetof(vcpu, ept) + offsetof(vcpu_ept_data, free_page_pfns);
  record.vcpu_off_ept_hook_active_list =
      offsetof(vcpu, ept) +
      offsetof(vcpu_ept_data, hooks) +
      offsetof(vcpu_ept_hooks, active_list_head);
  record.vcpu_off_dbg_pending = offsetof(vcpu, dbg_pending);
  record.ghv_off_affinity_lock_enabled = offsetof(hypervisor, affinity_lock_enabled);
  record.ghv_off_diag_hide_enter = offsetof(hypervisor, diag_hide_enter);
  record.ghv_off_diag_hide_pte_total = offsetof(hypervisor, diag_hide_pte_total);
  record.ghv_off_diag_hide_pte_null = offsetof(hypervisor, diag_hide_pte_null);
  record.ghv_off_diag_hide_done_bitmap = offsetof(hypervisor, diag_hide_done_bitmap);
  record.vcpu_off_ept_num_used_free_pages =
      offsetof(vcpu, ept) + offsetof(vcpu_ept_data, num_used_free_pages);
  record.vcpu_off_ept_dummy_page_pfn =
      offsetof(vcpu, ept) + offsetof(vcpu_ept_data, dummy_page_pfn);
  record.ept_free_page_count = ept_free_page_count;
  record.gamevt_image_base_ptr = (uint64_t)&gamevt_image_base;
  record.gamevt_driver_unload_ptr = (uint64_t)&gamevt_driver_unload;
  record.yvt_boot_flags_ptr = (uint64_t)yvt_get_boot_flags_ptr();
  record.system_eprocess = (uint64_t)g_ghv->system_eprocess;
  record.kprocess_directory_table_base_offset = g_ghv->kprocess_directory_table_base_offset;
  record.eprocess_unique_process_id_offset = g_ghv->eprocess_unique_process_id_offset;
  record.ghv_off_cr3_map_real_cr3 =
      offsetof(hypervisor, g_cr3_map) + offsetof(ghv_cr3_map, realCr3);
  record.vt_hook_table_ptr = (uint64_t)g_vt_hook_table;
  record.vt_hook_slot_count = VMCALL_HOOK_MAX;
  record.vt_hook_slot_size = sizeof(vt_hook_slot);
  record.vt_hook_slot_off_data_address =
      offsetof(vt_hook_slot, data) + offsetof(VMCALLHookData, address);
  record.vt_hook_slot_off_data_type =
      offsetof(vt_hook_slot, data) + offsetof(VMCALLHookData, type);
  record.vt_hook_slot_off_data_blank_memory =
      offsetof(vt_hook_slot, data) + offsetof(VMCALLHookData, blankMemory);
  record.vt_hook_slot_off_data_dispatch_mode =
      offsetof(vt_hook_slot, data) + offsetof(VMCALLHookData, dispatch_mode);
  record.vt_hook_slot_off_occupied = offsetof(vt_hook_slot, occupied);
  record.vt_hook_slot_off_trampoline_va = offsetof(vt_hook_slot, trampoline_va);
  record.vt_hook_slot_off_bp_rip = offsetof(vt_hook_slot, bp_rip);
  record.vt_hook_slot_off_target_resume = offsetof(vt_hook_slot, target_resume);
  static uint64_t s_dummy_render = 0;
  record.render_swapchain_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.render_isfinish_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.ghv_off_dwm_hit_count = offsetof(hypervisor, dwm_hit_count);
  record.ghv_off_diag_handler_count = offsetof(hypervisor, diag_handler_count);
  record.render_d2d_rt_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.render_color_brush_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.render_text_format_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.render_buffer0_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.render_buffer0_hva_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.render_desc_buffer_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.render_desc_buffer_hva_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
  record.ntapi_virtual_alloc = (uint64_t)VirtualAlloc;
  record.ntapi_read_process_memory = (uint64_t)ReadProcessMemory;
  record.ntapi_virtual_lock = (uint64_t)VirtualLock;
  record.ntapi_d2d1_create_factory = (uint64_t)D2D1CreateFactory;
  record.ntapi_dwrite_create_factory = (uint64_t)DWriteCreateFactory;
  record.ob_reference_object_by_handle_va = ObReferenceObjectByHandle_va;
  record.obf_dereference_object_va = ObfDereferenceObject_va;
  record.ntapi_file_name_offset = g_yvt.NtapiOffsets.FileName;
  record.ghv_off_kernel_blank_va = offsetof(hypervisor, kernel_blank_va);
  record.ghv_off_csec_scratch_va = offsetof(hypervisor, csec_scratch_va);
  record.ghv_off_csec_format_va = offsetof(hypervisor, csec_format_va);
  record.ghv_off_stop_phase = offsetof(hypervisor, stop_phase);
  record.ghv_off_stop_expected_bitmap = offsetof(hypervisor, stop_expected_bitmap);
  record.ghv_off_stop_requested_bitmap = offsetof(hypervisor, stop_requested_bitmap);
  record.ghv_off_stop_before_vmcall_bitmap = offsetof(hypervisor, stop_before_vmcall_bitmap);
  record.ghv_off_stop_after_vmcall_bitmap = offsetof(hypervisor, stop_after_vmcall_bitmap);
  record.ghv_off_stop_ack_bitmap = offsetof(hypervisor, stop_ack_bitmap);
  record.ghv_off_stop_exception_bitmap = offsetof(hypervisor, stop_exception_bitmap);
  record.ghv_off_stop_cleanup_bitmap = offsetof(hypervisor, stop_cleanup_bitmap);
  record.ghv_off_stop_last_cpu = offsetof(hypervisor, stop_last_cpu);
  record.ghv_off_stop_result = offsetof(hypervisor, stop_result);
  record.vt_hook_slot_off_data_process =
      offsetof(vt_hook_slot, data) + offsetof(VMCALLHookData, process);
  record.vt_hook_slot_off_data_filter_by_process =
      offsetof(vt_hook_slot, data) + offsetof(VMCALLHookData, filter_by_process);
  record.vt_hook_slot_off_data_is_enable =
      offsetof(vt_hook_slot, data) + offsetof(VMCALLHookData, isEnable);
  record.ghv_off_prot_ranges = offsetof(hypervisor, prot_ranges);
  record.ghv_off_prot_range_count = offsetof(hypervisor, prot_range_count);
  record.ghv_prot_range_capacity = hypervisor::prot_range_capacity;
  record.ghv_prot_range_stride = sizeof(hypervisor::prot_va_range);
  record.ghv_prot_range_off_base = offsetof(hypervisor::prot_va_range, base);
  record.ghv_prot_range_off_end = offsetof(hypervisor::prot_va_range, end);
  record.ghv_off_fake_data = offsetof(hypervisor, fake_data);
  record.ghv_off_diag_getbuffer_hits = offsetof(hypervisor, diag_getbuffer_hits);
  record.ghv_off_diag_getbuffer_alien = offsetof(hypervisor, diag_getbuffer_alien);
  record.ghv_off_diag_present_hits = offsetof(hypervisor, diag_present_hits);
  record.ghv_off_diag_present_alien = offsetof(hypervisor, diag_present_alien);
  record.ghv_off_diag_present1_hits = offsetof(hypervisor, diag_present1_hits);
  record.ghv_off_diag_present1_alien = offsetof(hypervisor, diag_present1_alien);
  record.ghv_off_diag_copyresource_hits = offsetof(hypervisor, diag_copyresource_hits);
  record.ghv_off_diag_copyresource_alien = offsetof(hypervisor, diag_copyresource_alien);
  record.ghv_off_diag_duplicateoutput_hits = offsetof(hypervisor, diag_duplicateoutput_hits);
  record.ghv_off_diag_duplicateoutput_alien = offsetof(hypervisor, diag_duplicateoutput_alien);
  record.ghv_off_diag_nt_alloc_hits = offsetof(hypervisor, diag_nt_alloc_hits);
  record.ghv_off_diag_nt_alloc_alien = offsetof(hypervisor, diag_nt_alloc_alien);
  record.ghv_off_diag_nt_protect_hits = offsetof(hypervisor, diag_nt_protect_hits);
  record.ghv_off_diag_nt_protect_alien = offsetof(hypervisor, diag_nt_protect_alien);
  record.ghv_off_diag_nt_map_hits = offsetof(hypervisor, diag_nt_map_hits);
  record.ghv_off_diag_nt_map_alien = offsetof(hypervisor, diag_nt_map_alien);
  record.ghv_off_diag_nt_csec_hits = offsetof(hypervisor, diag_nt_csec_hits);
  record.ghv_off_diag_nt_csec_image = offsetof(hypervisor, diag_nt_csec_image);
  record.ghv_off_diag_nt_csec_alien = offsetof(hypervisor, diag_nt_csec_alien);
  record.ghv_off_diag_capture_notify_count = offsetof(hypervisor, diag_capture_notify_count);
  record.ghv_off_diag_mmcopy_hits = offsetof(hypervisor, diag_mmcopy_hits);
  record.ghv_off_diag_mmcopy_last_caller_rip = offsetof(hypervisor, diag_mmcopy_last_caller_rip);
  record.ghv_off_diag_mmcm_hits = offsetof(hypervisor, diag_mmcm_hits);
  record.ghv_off_diag_mmcm_blocked = offsetof(hypervisor, diag_mmcm_blocked);
  record.ghv_off_diag_mmcvm_hits = offsetof(hypervisor, diag_mmcvm_hits);
  record.ghv_off_diag_mmcvm_blocked = offsetof(hypervisor, diag_mmcvm_blocked);
  record.ghv_off_diag_mmisav_hits = offsetof(hypervisor, diag_mmisav_hits);
  record.ghv_off_diag_mmisav_blocked = offsetof(hypervisor, diag_mmisav_blocked);
  record.ghv_off_diag_mmmio_hits = offsetof(hypervisor, diag_mmmio_hits);
  record.ghv_off_diag_mmmio_blocked = offsetof(hypervisor, diag_mmmio_blocked);
  record.dwmcore_base = (uint64_t)g_yvt.dwmcoreInfo.imageBase;
  record.dwmcore_size = (uint64_t)g_yvt.dwmcoreInfo.imageSize;
  record.dxgi_base = (uint64_t)g_yvt.dxgiInfo.imageBase;
  record.dxgi_size = (uint64_t)g_yvt.dxgiInfo.imageSize;
  record.ghv_off_ept_hook_table = offsetof(hypervisor, ept_hook_table);
  record.ghv_off_pending_ept_install_entries = offsetof(hypervisor, pending_ept_install_entries);
  record.ghv_off_pending_ept_install_bitmap = offsetof(hypervisor, pending_ept_install_bitmap);
  record.ghv_off_diag_pending_queue_full = offsetof(hypervisor, diag_pending_queue_full);
  record.ghv_pending_install_capacity = hypervisor::pending_install_capacity;
  record.ept_hook_table_off_lock = offsetof(eh::ept_hook_table, lock);
  record.ept_hook_table_off_in_use_count = offsetof(eh::ept_hook_table, in_use_count);
  record.ept_hook_table_off_active_list_head = offsetof(eh::ept_hook_table, active_list_head);
  record.ept_hook_table_off_free_list_head = offsetof(eh::ept_hook_table, free_list_head);
  record.ept_hook_table_off_buffer = offsetof(eh::ept_hook_table, buffer);
  record.ept_hook_table_off_fake_pages = offsetof(eh::ept_hook_table, fake_pages);
  record.ept_hook_table_off_fake_page_pfns = offsetof(eh::ept_hook_table, fake_page_pfns);
  record.ept_hook_table_capacity = eh::ept_hook_table::capacity;
  record.ept_hook_entry_size = sizeof(eh::ept_hook_entry);
  record.ept_hook_entry_off_next = offsetof(eh::ept_hook_entry, next);
  record.ept_hook_entry_off_process = offsetof(eh::ept_hook_entry, process);
  record.ept_hook_entry_off_process_cr3 = offsetof(eh::ept_hook_entry, process_cr3);
  record.ept_hook_entry_off_va = offsetof(eh::ept_hook_entry, va);
  record.ept_hook_entry_off_orig_pfn = offsetof(eh::ept_hook_entry, orig_pfn);
  record.ept_hook_entry_off_fake_pfn = offsetof(eh::ept_hook_entry, fake_pfn);
  record.ept_hook_entry_off_fake_page_idx = offsetof(eh::ept_hook_entry, fake_page_idx);
  record.ept_hook_entry_off_in_use = offsetof(eh::ept_hook_entry, in_use);
  record.ept_hook_entry_off_is_fake_page = offsetof(eh::ept_hook_entry, is_fake_page);
  record.ept_hook_entry_off_per_vcpu_active_bitmap = offsetof(eh::ept_hook_entry, per_vcpu_active_bitmap);
  record.nt_create_section_va = NtCreatSection;
  record.nt_set_event_va = NtSetEvent_va;
  record.nt_allocate_virtual_memory_va = NtAllocateVirtualMemory_va;
  record.nt_protect_virtual_memory_va = NtProtectVirtualMemory_va;
  record.nt_map_view_of_section_va = NtMapViewOfSection_va;
  record.mm_copy_memory_va = MmCopyMemory_va;
  record.mm_copy_virtual_memory_va = MmCopyVirtualMemory_va;
  record.mm_is_address_valid_va = MmIsAddressValid_va;
  record.mm_map_io_space_va = MmMapIoSpace_va;
  record.mm_is_address_valid_ex_va = MmIsAddressValidEx_va;
  record.nt_query_virtual_memory_va = NtQueryVirtualMemory_va;
  record.mm_get_physical_address_va = MmGetPhysicalAddress_va;
  record.ghv_off_copyresource_addr = offsetof(hypervisor, copyresource_addr);
  record.ghv_off_duplicateoutput_addr = offsetof(hypervisor, duplicateoutput_addr);
  record.vcpu_off_ctx = offsetof(vcpu, ctx);
  record.ghv_off_pending_ept_invept_bitmap = offsetof(hypervisor, pending_ept_invept_bitmap);
  record.ghv_off_pending_hide_pfns = offsetof(hypervisor, pending_hide_pfns);
  record.ghv_off_pending_hide_count = offsetof(hypervisor, pending_hide_count);
  record.ghv_off_pending_hide_vcpu_bitmap = offsetof(hypervisor, pending_hide_vcpu_bitmap);
  record.ghv_off_pending_hide_tsc_threshold = offsetof(hypervisor, pending_hide_tsc_threshold);
  record.ghv_off_diag_per_vcpu_vmexits = offsetof(hypervisor, diag_per_vcpu_vmexits);
  record.vcpu_off_hide_vm_exit_overhead = offsetof(vcpu, hide_vm_exit_overhead);
  record.vcpu_off_stop_virtualization = offsetof(vcpu, stop_virtualization);
  record.vcpu_off_ept_mmr_mtf_pte = offsetof(vcpu, ept) + offsetof(vcpu_ept_data, mmr_mtf_pte);
  record.vcpu_off_ept_mmr_mtf_mode = offsetof(vcpu, ept) + offsetof(vcpu_ept_data, mmr_mtf_mode);
  record.vcpu_off_ept_mmr_mtf_page_frame = offsetof(vcpu, ept) + offsetof(vcpu_ept_data, mmr_mtf_page_frame);
  record.vcpu_ept_hook_node_off_next = offsetof(vcpu_ept_hook_node, next);
  record.vcpu_ept_hook_node_off_orig_pfn = offsetof(vcpu_ept_hook_node, orig_pfn);
  record.vcpu_ept_hook_node_off_exec_pfn = offsetof(vcpu_ept_hook_node, exec_pfn);
  record.vcpu_ept_hook_node_off_is_fake_page = offsetof(vcpu_ept_hook_node, is_fake_page);
  record.vcpu_off_svm_resident_loop =
      offsetof(vcpu, svm) + offsetof(svm_vcpu_state, resident_loop);
  record.vcpu_off_svm_resident_ack =
      offsetof(vcpu, svm) + offsetof(svm_vcpu_state, resident_ack);
  record.ghv_off_kthread_affinity_offset = offsetof(hypervisor, kthread_affinity_offset);
  record.ghv_off_kthread_user_affinity_offset = offsetof(hypervisor, kthread_user_affinity_offset);
  record.ghv_off_kthread_ideal_processor_offset = offsetof(hypervisor, kthread_ideal_processor_offset);
  record.ghv_off_kthread_user_ideal_processor_offset = offsetof(hypervisor, kthread_user_ideal_processor_offset);
  record.vcpu_off_pending_state = offsetof(vcpu, pending_state);
  record.vcpu_off_pending_host_rsp_restore = offsetof(vcpu, pending_host_rsp_restore);
  record.vcpu_off_pending_vtcallstack_node = offsetof(vcpu, pending_vtcallstack_node);
  record.vcpu_off_pending_release_delay = offsetof(vcpu, pending_release_delay);
  record.ghv_size = sizeof(*g_ghv);
  record.vt_hook_table_bytes = VMCALL_HOOK_MAX * sizeof(vt_hook_slot);

  auto written = write_guest_virtual_memory(out_gva, &record, sizeof(record));
  if (written != sizeof(record) && g_ghv->system_cr3.flags) {
    written = write_guest_virtual_memory(g_ghv->system_cr3, out_gva, &record, sizeof(record));
  }
  cpu->ctx->rax = written == sizeof(record) ? sizeof(record) : 0;
  skip_instruction();
}

void set_host_rsp(vcpu* const cpu) {
  auto const new_rsp = cpu->ctx->rcx;
  auto const old_rsp = vmx_vmread(VMCS_HOST_RSP);

  if (!new_rsp) {
    cpu->ctx->rax = 0;
    skip_instruction();
    return;
  }

  vmx_vmwrite(VMCS_HOST_RSP, new_rsp);
  cpu->ctx->rax = old_rsp;
  skip_instruction();
}

void map_host_range(vcpu* const cpu) {
  auto const va = cpu->ctx->rcx;
  auto const bytes = cpu->ctx->rdx;
  if (!va || !bytes) {
    cpu->ctx->rax = 0;
    skip_instruction();
    return;
  }

  cpu->ctx->rax = map_host_virtual_range(va, bytes) ? 1 : 0;
  skip_instruction();
}

void set_host_rip(vcpu* const cpu) {
  auto const new_rip = cpu->ctx->rcx;
  auto const old_rip = vmx_vmread(VMCS_HOST_RIP);

  if (!new_rip) {
    cpu->ctx->rax = 0;
    skip_instruction();
    return;
  }

  vmx_vmwrite(VMCS_HOST_RIP, new_rip);
  cpu->ctx->rax = old_rip;
  skip_instruction();
}

// get the base address of the hypervisor
void get_hv_base(vcpu* const cpu) {
  cpu->ctx->rax = reinterpret_cast<uint64_t>(&__ImageBase);
  skip_instruction();
}

// write to the logger whenever a certain physical memory range is accessed
void install_mmr(vcpu* const cpu) {

  auto const phys = cpu->ctx->rcx;
  auto const size = static_cast<uint32_t>(cpu->ctx->rdx);
  auto const mode = static_cast<uint8_t>(cpu->ctx->r8 & 0b111);

  // return null by default
  cpu->ctx->rax = 0;

  // TODO: check for overlap with EPT hooking

  vcpu_ept_mmr_entry* entry = nullptr;

  for (auto& e : cpu->ept.mmr) {
    if (e.size != 0)
      continue;

    entry = &e;
    break;
  }

  // all entries are in use
  if (!entry) {
    skip_instruction();
    return;
  }

  entry->mode  = mode;
  entry->pa = phys;
  entry->size  = size;

    auto const pte = get_ept_pte(cpu->ept, entry->pa, true);
    if (!pte) {
      // TODO: properly handle errors, i.e. restore previous PTE permissions'
      skip_instruction();
      return;
    }


	pte->read_access    = !(mode & mmr_memory_mode_r);
	pte->write_access   = !(mode & mmr_memory_mode_w);
	pte->execute_access = !(mode & mmr_memory_mode_x);

	// write access but no read access will generate an EPT misconfiguration
	if (pte->write_access && !pte->read_access)
	  pte->write_access = 0;
  
	vmx_invept(invept_all_context, {});

	cpu->ctx->rax = reinterpret_cast<uint64_t>(entry);
	skip_instruction();
}

// remove a monitored memory range
void remove_mmr(vcpu* cpu) {


  auto const pa = cpu->ctx->rcx;

  //find mmr
  vcpu_ept_mmr_entry* entry = nullptr;
  for (auto& e : cpu->ept.mmr) {
      if (e.size == 0)
          continue;
      if (e.pa = pa)
      {
          entry = &e;
			break;
      }
  }


  if(!entry)
  {
	skip_instruction();
	return;
  }


    auto const pte = get_ept_pte(cpu->ept, entry->pa, true);
    if (!pte) {
      // TODO: properly handle errors, i.e. restore previous PTE permissions
      skip_instruction();
      return;
    }

    pte->read_access    = 1;
    pte->write_access   = 1;
    pte->execute_access = 1;
  

  entry->size = 0;
  vmx_invept(invept_all_context, {});


  skip_instruction();
}



void add_cr3_monitor(vcpu* cpu)
{
    auto const real_cr3= cpu->ctx->rcx;
    auto const fake_cr3 = cpu->ctx->rdx;
    auto const process = cpu->ctx->r8;
    auto const image_base = cpu->ctx->r9;
    auto const text_section_size = cpu->ctx->r10;
    auto const image_size = cpu->ctx->r11;
    g_ghv->g_cr3_monitor.fake_cr3.flags = fake_cr3;
    g_ghv->g_cr3_monitor.real_cr3.flags = real_cr3;
    g_ghv->g_cr3_monitor.process = process;
    g_ghv->g_cr3_monitor.image_base = image_base;
    g_ghv->g_cr3_monitor.text_section_size = text_section_size;
    g_ghv->g_cr3_monitor.image_size = image_size;

    g_ghv->is_cr3_monitor_open = true;
    g_ghv->is_check_thread = false;

    g_ghv->is_check_rip = false;
    skip_instruction();
}
void remove_cr3_monitor(vcpu* cpu)
{

    g_ghv->is_cr3_monitor_open = false;
    g_ghv->is_check_thread = false;
    g_ghv->is_check_rip = false;
    g_ghv->g_cr3_monitor.real_cr3.flags = 0;
    g_ghv->g_cr3_monitor.fake_cr3.flags = 0;
    g_ghv->g_cr3_monitor.process = 0;
    g_ghv->g_cr3_monitor.image_base = 0;
    g_ghv->g_cr3_monitor.text_section_size = 0;
    g_ghv->g_cr3_monitor.image_size = 0;


    skip_instruction();
}

void enable_cr3_monitor_check_thread(vcpu* cpu)
{

    g_ghv->is_check_thread = true;
    skip_instruction();
}

void disable_cr3_monitor_check_thread(vcpu* cpu)
{
    g_ghv->is_check_thread = false;
    skip_instruction();
}

    void enable_check_monitor_check_rip(vcpu* cpu)
{
        g_ghv->is_check_rip = true;
        skip_instruction();
}
    void disable_check_monitor_check_rip(vcpu* cpu)
    {
        g_ghv->is_check_rip = false;
        skip_instruction();
    }

void cr3_monitor_jmp(vcpu* cpu)
{
    auto const rip = cpu->ctx->rcx;
    auto process = current_guest_eprocess();
    auto thread = current_guest_ethread();
    remove_cr3_monitor_thread((uint64_t)process, (uint64_t)thread);
    vmx_vmwrite(VMCS_GUEST_CR3, g_ghv->g_cr3_monitor.real_cr3.flags);
    cpu->ctx->rax = 0;
    vmx_vmwrite(VMCS_GUEST_RIP, rip);
}

void add_cr3_monitor_thread_s(vcpu* cpu)
{
    auto const process = cpu->ctx->rcx;
	auto const thread = cpu->ctx->rdx;
	add_cr3_monitor_thread(process, thread);
	skip_instruction();
}

void remove_cr3_monitor_thread_s(vcpu* cpu)
{
    auto const process = cpu->ctx->rcx;
    auto const thread = cpu->ctx->rdx;
    remove_cr3_monitor_thread(process, thread);
    skip_instruction();
}

void active_cr3_monitor_data_region(vcpu* cpu)
{
	auto const ori_pfn = cpu->ctx->rcx;

    auto node = find_ept_hook(cpu->ept, ori_pfn >> 12);
    if(node)
    {
	   auto pte =  get_ept_pte(cpu->ept, ori_pfn, true);
        if(pte)
        {
            pte->page_frame_number = node->exec_pfn;
            pte->read_access = 0;
            pte->write_access = 0;
            pte->execute_access = 0;
            vmx_invept(invept_all_context, {});
        }
    }

	skip_instruction();
}


// remove every installed MMR
void remove_all_mmrs(vcpu* const cpu) {
  for (auto& entry : cpu->ept.mmr) {
    if (entry.size == 0)
      continue;

    for (auto addr = entry.pa; addr < entry.pa + entry.size; addr += 0x1000) {
      auto const pte = get_ept_pte(cpu->ept, addr, true);
      if (!pte) {
        // TODO: properly handle errors, i.e. restore previous PTE permissions
        skip_instruction();
        return;
      }

      pte->read_access    = 1;
      pte->write_access   = 1;
      pte->execute_access = 1;
    }

    entry.size = 0;
  }

  vmx_invept(invept_all_context, {});
  skip_instruction();
}

void install_breakpoint_hook(vcpu* cpu)
{
    auto const cr3 = cpu->ctx->rcx;
    auto const origin_va = cpu->ctx->rdx;
    auto const fake_va = cpu->ctx->r8;
    bool const is_cr3_monitor_hook = cpu->ctx->r9;
    install_bp_hook(cpu->ept, cr3, origin_va, fake_va, is_cr3_monitor_hook);

    skip_instruction();

}

void remove_breakpoint_hook(vcpu* cpu)
{

    auto const cr3 = cpu->ctx->rcx;
    auto const origin_va = cpu->ctx->rdx;

    remove_bp_hook(cpu->ept, cr3, origin_va);

    skip_instruction();

}
void add_protect_process(vcpu* cpu)
{
    auto const process = cpu->ctx->rcx;
    hv::add_protect_process(process);
    skip_instruction();


 
}

void remove_protect_process(vcpu* cpu)
{
    auto const process = cpu->ctx->rcx;

    hv::remove_protect_process(process);

    skip_instruction();
}

void start_get_game_cr3(vcpu* cpu)
{
    auto const src_process = cpu->ctx->rcx;

    g_ghv->g_cr3_map.realCr3.flags = 0;
    g_ghv->g_cr3_map.srcProcess = (PEPROCESS)src_process;

    skip_instruction();
}

void start_get_game_cr3_by_pid(vcpu* cpu) {

    auto const target_pid = cpu->ctx->rcx;
    PEPROCESS src_process = nullptr;
    // System process
    if (target_pid == 4) {
        src_process = (PEPROCESS)g_ghv->system_eprocess;
 
    }
    else {
        // ActiveProcessLinks is right after UniqueProcessId in memory
        auto const apl_offset = g_ghv->eprocess_unique_process_id_offset + 8;
        auto const head = g_ghv->system_eprocess + apl_offset;
        auto curr_entry = head;

        // iterate over every EPROCESS in the APL linked list
        do {
            // get the next entry in the linked list
            if (sizeof(curr_entry) != read_guest_virtual_memory(g_ghv->system_cr3,
                curr_entry + offsetof(LIST_ENTRY, Flink), &curr_entry, sizeof(curr_entry)))
                break;

            // EPROCESS
            auto const process = curr_entry - apl_offset;

            // EPROCESS::UniqueProcessId
            uint64_t pid = 0;
            if (sizeof(pid) != read_guest_virtual_memory(g_ghv->system_cr3,
                process + g_ghv->eprocess_unique_process_id_offset, &pid, sizeof(pid)))
                break;

            // we found the target process
            if (target_pid == pid) {
                // EPROCESS::DirectoryTableBase
            
                src_process = (PEPROCESS)process;
                break;
            }
        } while (curr_entry != head);


    }

    g_ghv->g_cr3_map.realCr3.flags = 0;
    g_ghv->g_cr3_map.srcProcess = (PEPROCESS)src_process;

    //cpu->ctx->rax = (ULONG64)g_ghv->g_cr3_map.srcProcess;

    skip_instruction();

}

void add_cr3_map(vcpu* cpu)
{
	auto const src_cr3 = cpu->ctx->rcx;
	auto const dst_cr3 = cpu->ctx->rdx;
	auto const fake_cr3 = cpu->ctx->r8;
	auto const process = cpu->ctx->r9;
	auto const pml4e_index = cpu->ctx->r10;
   
	g_ghv->g_cr3_map.srcCr3.flags = src_cr3;
    g_ghv->g_cr3_map.dstCr3.flags = dst_cr3;
    g_ghv->g_cr3_map.fakeCr3.flags = fake_cr3;
    g_ghv->g_cr3_map.process = (PEPROCESS)process;
    g_ghv->g_cr3_map.pml4e_index = pml4e_index;
    g_ghv->g_cr3_map.is_open = true;

    vmx_vmwrite(VMCS_GUEST_CR3, g_ghv->g_cr3_map.fakeCr3.flags);


	skip_instruction();
}

void add_cr3_map_by_user_mode(vcpu* cpu) {

    g_ghv->g_cr3_map.is_open = false;

    ULONG64 const src_cr3 = 0;
    ULONG64 const dst_cr3 = current_guest_cr3().flags;
    ULONG64 const process = (ULONG64)current_guest_eprocess();
    ULONG64 address = cpu->ctx->r10;
    ULONG64 const pml4e_index = (address >> 39) & 0x1ff;;


    void* fake_cr3_va = gva2hva((void*)g_ghv->g_cr3_map.pml4e);

    ULONG64 dst_cr3_pa = dst_cr3 & ~0xFFF;
    void* dst_cr3_va = host_physical_memory_base + dst_cr3_pa;

    memcpy(fake_cr3_va, (void*)dst_cr3_va, PAGE_SIZE);

    auto fake_cr3_pa = gva2gpa(g_ghv->g_cr3_map.pml4e);
    cr3 fake_cr3;
    fake_cr3.flags = dst_cr3;
    fake_cr3.address_of_page_directory = fake_cr3_pa >> 12;




    g_ghv->g_cr3_map.srcCr3.flags = src_cr3;
    g_ghv->g_cr3_map.dstCr3.flags = dst_cr3;
    g_ghv->g_cr3_map.fakeCr3.flags = fake_cr3.flags;
    g_ghv->g_cr3_map.process = (PEPROCESS)process;
    g_ghv->g_cr3_map.pml4e_index = pml4e_index;

    g_ghv->g_cr3_map.is_open = true;

    vmx_vmwrite(VMCS_GUEST_CR3, g_ghv->g_cr3_map.fakeCr3.flags);

    skip_instruction();
}


void remove_cr3_map(vcpu* cpu)
{

    g_ghv->g_cr3_map.is_open = false;


    
    g_ghv->g_cr3_map.srcCr3.flags = NULL;
    g_ghv->g_cr3_map.dstCr3.flags = NULL;
    g_ghv->g_cr3_map.fakeCr3.flags = NULL;
    g_ghv->g_cr3_map.process = nullptr;
    g_ghv->g_cr3_map.pml4e_index = 0;

    skip_instruction();
}

void get_src_cr3(vcpu* cpu)
{
    auto const buffer = cpu->ctx->rcx;

    //璁＄畻buffer鍦℉ost涓鐨勮櫄鎷熷湴鍧
    auto const curr_dst = gva2hva((void*)buffer);
    *(uint64_t*)curr_dst = g_ghv->g_cr3_map.realCr3.flags;

    skip_instruction();

}

void add_real_cr3(vcpu* cpu) { skip_instruction(); }

} // namespace hv::hc

