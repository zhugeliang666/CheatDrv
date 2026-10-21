#pragma once

#include "guest-context.h"
#include "page-tables.h"
#include "gdt.h"
#include "idt.h"
#include "ept.h"
#include "vmx.h"
#include "timing.h"

namespace hv {

namespace svm_detail {
  struct reserved;
}

} // namespace hv

namespace svm {
  struct vmcb;
  struct npt_data;
}

namespace hv {
    
// size of the host stack for handling vm-exits
inline constexpr size_t host_stack_size =0x10000;

// guest virtual-processor identifier
inline  uint16_t guest_vpid = 1;

struct vcpu_cached_data {
  // maximum number of bits in a physical address (MAXPHYSADDR)
  uint64_t max_phys_addr;

  // reserved bits in CR0/CR4
  uint64_t vmx_cr0_fixed0;
  uint64_t vmx_cr0_fixed1;
  uint64_t vmx_cr4_fixed0;
  uint64_t vmx_cr4_fixed1;

  // mask of unsupported processor state components for XCR0
  uint64_t xcr0_unsupported_mask;

  // IA32_FEATURE_CONTROL
  ia32_feature_control_register feature_control;
  ia32_feature_control_register guest_feature_control;

  // IA32_VMX_MISC
  ia32_vmx_misc_register vmx_misc;

  // CPUID 0x00
  cpuid_eax_00 cpuid_00;

  // CPUID 0x01
  cpuid_eax_01 cpuid_01;
 
};

struct svm_vcpu_state {
  svm::vmcb* vmcb;
  uint64_t vmcb_pa;

  void* host_save;
  uint64_t host_save_pa;

  void* msrpm;
  uint64_t msrpm_pa;
  size_t msrpm_size;

  svm::npt_data* npt;
  uint64_t npt_pml4_pa;

  uint64_t original_efer;
  uint64_t original_hsave_pa;
  uint64_t original_vm_cr;
  uint64_t original_cr3;

  // Guest-visible SVM MSR shadows. The AMD backend keeps SVME/HSAVE enabled
  // for host VMRUN but presents a non-virtualized CPU to the guest.
  uint64_t guest_efer;
  uint64_t guest_hsave_pa;
  uint64_t guest_vm_cr;

  uint64_t host_rsp_base;
  uint64_t host_rsp_next;
  uint64_t host_rsp_current;

  uint32_t asid;
  bool allocated;
  bool launched;
  bool should_stop;
};

enum dbg_pending_kind : uint32_t {
  dbg_pending_none = 0,
  dbg_pending_watch_rearm = 1,
};

struct dbg_vcpu_pending {
  uint32_t kind;
  uint64_t watch_page_id;
  ept_pte* pte;
  uint8_t restore_r;
  uint8_t restore_w;
  uint8_t restore_x;
  uint64_t restore_pfn;
};

struct vcpu {
  // 4 KiB vmxon region
  alignas(0x1000) vmxon vmxon;

  // 4 KiB vmcs region
  alignas(0x1000) vmcs vmcs;

  // 4 KiB msr bitmap
  alignas(0x1000) vmx_msr_bitmap msr_bitmap;

  // host interrupt descriptor table
  alignas(0x1000) segment_descriptor_interrupt_gate_64 host_idt[host_idt_descriptor_count];

  // host global descriptor table
  alignas(0x1000) segment_descriptor_32 host_gdt[host_gdt_descriptor_count];

  // host task state segment
  alignas(0x1000) task_state_segment_64 host_tss;


  // host stack used for handling vm-exits

	uint8_t* host_stack;
  // vm-exit MSR store area
  struct alignas(0x10) {
    //vmx_msr_entry tsc;
    //vmx_msr_entry perf_global_ctrl;
    //vmx_msr_entry aperf;
    //vmx_msr_entry mperf;
      vmx_msr_entry riti;
      //vmx_msr_entry lbr_ctl;
  } msr_exit_store;

  // vm-entry MSR load area
  struct alignas(0x10) {
    //vmx_msr_entry aperf;
    //vmx_msr_entry mperf;
      vmx_msr_entry riti;
      //vmx_msr_entry lbr_ctl;
  } msr_entry_load;

  // cached values that are assumed to NEVER change
  vcpu_cached_data cached;

  // pointer to the current guest context, set in exit-handler
  guest_context* ctx;

  // the number of NMIs that need to be delivered
  uint32_t volatile queued_nmis;

  // current TSC offset
  uint64_t tsc_offset;

  // Fake perfmon counters synthesized from RDTSC. We never read the real
  // IA32_FIXED_CTR2 / IA32_APERF / IA32_MPERF MSRs in vm-exit handlers
  // (those can #GP on PMU-disabled CPUs and triple-fault host). Instead we
  // expose values derived from the offset-corrected TSC, so guest sees
  // perfmon counters consistent with the masked RDTSC.
  uint64_t fake_perfmon_base_tsc;

  // current preemption timer
  uint64_t preemption_timer;

  // the overhead caused by world-transitions
  uint64_t vm_exit_tsc_overhead;
  uint64_t vm_exit_mperf_overhead;
  uint64_t vm_exit_ref_tsc_overhead;



  // whether to use TSC offsetting for the current vm-exit--false by default
  bool hide_vm_exit_overhead;

  // whether to devirtualize the current VCPU
  bool stop_virtualization;

  bool is_hide_vt;

  uint64_t vpid;

  // hv::Call lazy-restore (cross-vCPU return fallback). When a hv::Call's
  // callee is rescheduled to another vCPU and #BP returns there, the return
  // vCPU posts the entry vCPU's restore work here instead of writing the
  // entry vCPU's VMCS directly (which violates Intel SDM Vol3C 24.4 and
  // triple-faults). The entry vCPU drains this on its next vm-exit.
  //
  // pending_state state machine (atomic via cmpxchg, no spin-lock):
  //   0 = free
  //   1 = producer owns slot; payload fields are not yet published
  //   2 = restore-ready; consumer may read payload and vmwrite HOST_RSP
  //   3 = release-pending; vmwrite completed and delay is counting down
  uint64_t pending_host_rsp_restore;
  void*    pending_vtcallstack_node;
  uint32_t pending_release_delay;
  volatile uint8_t pending_state;

  // Debug EPT watch one-shot rearm state.  Kept separate from legacy MMR and
  // ept_probe MTF state so debug watches cannot steal their single-step owner.
  dbg_vcpu_pending dbg_pending;

  // EPT paging structures
  alignas(0x1000) vcpu_ept_data ept;

  // AMD SVM state is allocated lazily and stays inert on Intel.
  svm_vcpu_state svm;
};

// virtualize the specified cpu. this assumes that execution is already
// restricted to the desired logical proocessor.
bool virtualize_cpu(vcpu* cpu);

} // namespace hv

