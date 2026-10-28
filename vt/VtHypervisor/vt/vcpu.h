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
    
// VM-Exit 处理栈必须覆盖深层图形驱动调用链以及异常展开路径。
// 64 KiB 现场已在 nvlddmkm 线程的异常分发阶段越过栈底；固定扩大到
// 256 KiB，并保持页对齐，避免自定义 HOST_RSP 把一次普通缺页放大为 0x7F。
inline constexpr size_t host_stack_size = 0x40000;
static_assert((host_stack_size & 0xFFFu) == 0, "host stack must be page aligned");

// guest virtual-processor identifier
inline  uint16_t guest_vpid = 1;

struct vcpu_cached_data {
  // 最大 number of bits in a physical 地址 (MAXPHYSADDR)
  uint64_t max_phys_addr;

  // reserved bits in CR0/CR4
  uint64_t vmx_cr0_fixed0;
  uint64_t vmx_cr0_fixed1;
  uint64_t vmx_cr4_fixed0;
  uint64_t vmx_cr4_fixed1;

  // 掩码 of unsupported processor 状态 components for XCR0
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

  void* host_vmcb;
  uint64_t host_vmcb_pa;

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

  // One-shot AMD root-loop ownership transfer.  The legacy VMRUN loop
  // atomically consumes resident_loop on the next #VMEXIT and jumps to that
  // image before dispatching the exit.  resident_ack is written by the
  // destination image after the jump, so the bootstrap can prove that neither
  // the 当前 RIP nor the saved return path references VtHypervisor text.
  volatile uint64_t resident_loop;
  volatile uint64_t resident_ack;
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

  // host interrupt descriptor 表
  alignas(0x1000) segment_descriptor_interrupt_gate_64 host_idt[host_idt_descriptor_count];

  // host global descriptor 表
  alignas(0x1000) segment_descriptor_32 host_gdt[host_gdt_descriptor_count];

  // host task 状态 segment
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

  // vm-条目项 MSR load area
  struct alignas(0x10) {
    //vmx_msr_entry aperf;
    //vmx_msr_entry mperf;
      vmx_msr_entry riti;
      //vmx_msr_entry lbr_ctl;
  } msr_entry_load;

  // cached values that are assumed to NEVER change
  vcpu_cached_data cached;

  // 指针 to the 当前 guest 上下文, 设置 in exit-handler
  guest_context* ctx;

  // the number of NMIs that need to be delivered
  uint32_t volatile queued_nmis;

  // 当前 TSC 偏移
  uint64_t tsc_offset;

  // Fake perfmon counters synthesized from RDTSC. We never 读取 the real
  // IA32_FIXED_CTR2 / IA32_APERF / IA32_MPERF MSRs in vm-exit handlers
  // (those can #GP on PMU-disabled CPUs and triple-fault host). Instead we
  // expose values derived from the 偏移-corrected TSC, so guest sees
  // perfmon counters consistent with the masked RDTSC.
  uint64_t fake_perfmon_base_tsc;

  // 当前 preemption timer
  uint64_t preemption_timer;

  // the overhead caused by world-transitions
  uint64_t vm_exit_tsc_overhead;
  uint64_t vm_exit_mperf_overhead;
  uint64_t vm_exit_ref_tsc_overhead;



  // whether to use TSC offsetting for the 当前 vm-exit--false by 默认
  bool hide_vm_exit_overhead;

  // whether to devirtualize the 当前 VCPU
  bool stop_virtualization;

  bool is_hide_vt;

  uint64_t vpid;

  // hv::Call lazy-恢复 (cross-vCPU return fallback). When a hv::Call's
  // callee is rescheduled to another vCPU and #BP returns there, the return
  // vCPU posts the 条目项 vCPU's 恢复 work here instead of writing the
  // 条目项 vCPU's VMCS directly (which violates Intel SDM Vol3C 24.4 and
  // triple-faults). The 条目项 vCPU drains this on its next vm-exit.
  //
  // pending_state 状态 machine (atomic via cmpxchg, no spin-lock):
  //   0 = free
  //   1 = producer owns slot; payload fields are not yet published
  //   2 = restore-ready; consumer may read payload and vmwrite HOST_RSP
  //   3 = release-pending; vmwrite completed and delay is counting down
  uint64_t pending_host_rsp_restore;
  void*    pending_vtcallstack_node;
  uint32_t pending_release_delay;
  volatile uint8_t pending_state;

  // Debug EPT watch one-shot rearm 状态.  Kept separate from legacy MMR and
  // ept_probe MTF 状态 so debug watches cannot steal their 单步执行 owner.
  dbg_vcpu_pending dbg_pending;

  // EPT paging structures
  alignas(0x1000) vcpu_ept_data ept;

  // AMD SVM 状态 is allocated lazily and stays inert on Intel.
  svm_vcpu_state svm;

  // Per-vCPU Host-CR3-mapped payload_status scratch buffer (Path A) with
  // generation + head/tail canary guards against concurrent tearing or OOB.
  struct {
    volatile uint64_t head_canary;
    volatile uint64_t generation;
    volatile uint32_t active_cpu;
    volatile uint32_t in_use;
    volatile uint64_t tear_or_canary_error_count;
    alignas(16) uint8_t status_bytes[0x20B8];
    volatile uint64_t tail_canary;
    // mapctl_memcheck 大于 payload_status，使用独立缓冲避免验证结果覆盖状态尾 canary。
    alignas(16) uint8_t memcheck_bytes[0x2258];
  } status_scratch;

  // Per-vCPU active safe-probe descriptor for deterministic Host exception recovery.
  struct {
    volatile uint64_t magic;
    volatile uint64_t active;
    volatile uint64_t fault_rip_start;
    volatile uint64_t fault_rip_end;
    volatile uint64_t recovery_rip;
    volatile uint64_t exception_info_va;
    volatile uint64_t expected_rsp_low;
    volatile uint64_t expected_rsp_high;
  } active_probe;

  // Deterministic per-vCPU Host exception diagnostics (captures the very first
  // Host fault before any recovery or secondary fault can mask it).
  struct {
    volatile uint64_t count;
    volatile uint64_t recovered_count;
    volatile uint64_t unrecovered_count;
    volatile uint64_t false_probe_rejected_count;
    volatile uint64_t first_captured;
    volatile uint64_t first_vector;
    volatile uint64_t first_error;
    volatile uint64_t first_rip;
    volatile uint64_t first_cr2;
    volatile uint64_t first_rsp;
    volatile uint64_t last_vector;
    volatile uint64_t last_error;
    volatile uint64_t last_rip;
    volatile uint64_t last_cr2;
    volatile uint64_t last_rsp;
  } host_exception_diag;
};

inline constexpr uint64_t vcpu_status_canary_head   = 0x53544154434E5231ULL; // 'STATCNR1'
inline constexpr uint64_t vcpu_status_canary_tail   = 0x53544154434E5232ULL; // 'STATCNR2'
inline constexpr size_t   vcpu_status_scratch_bytes = 0x20B8;
inline constexpr size_t   vcpu_memcheck_scratch_bytes = 0x2258;
inline constexpr uint64_t vcpu_probe_desc_magic     = 0x50524F4244534331ULL; // 'PROBDSC1'

vcpu* resolve_vcpu_from_host_rsp(uint64_t rsp_probe, uint64_t* out_stack_low = nullptr, uint64_t* out_stack_high = nullptr);
vcpu* begin_host_exception_probe(void* exception_info, uint64_t fault_rip_start, uint64_t fault_rip_end, uint64_t recovery_rip, uint64_t caller_rsp);
void  end_host_exception_probe(vcpu* cpu);

// virtualize the specified cpu. this assumes that execution is already
// restricted to the desired logical proocessor.
bool virtualize_cpu(vcpu* cpu);

} // namespace hv

