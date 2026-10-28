#include "vmcs.h"
#include "hv.h"
#include "vmx.h"
#include "vcpu.h"
#include "segment.h"
#include "timing.h"
#include "intrin.h"

namespace hv {
#pragma code_seg(".vm")
// defined in vm-exit.asm
void vm_exit();

// setup the VMCS control fields
void write_vmcs_ctrl_fields(vcpu* const cpu) {
  // 3.26.2

  // 3.24.6.1
  ia32_vmx_pinbased_ctls_register pin_based_ctrl;
  pin_based_ctrl.flags                         = 0;
  pin_based_ctrl.virtual_nmi                   = 1;
  pin_based_ctrl.nmi_exiting                   = 1;
  //pin_based_ctrl.activate_vmx_preemption_timer = 1;
  write_ctrl_pin_based_safe(pin_based_ctrl);

  // 3.24.6.2
  ia32_vmx_procbased_ctls_register proc_based_ctrl;
  proc_based_ctrl.flags                       = 0;
//#ifndef NDEBUG
  //proc_based_ctrl.cr3_load_exiting            = 1;
  //proc_based_ctrl.cr3_store_exiting           = 1;
//#endif
  proc_based_ctrl.use_msr_bitmaps             = 1;
  // TSC offsetting disabled 鈥 caused DWM black screen. Suspected cause:
  // negative tsc_offset accumulating over time made DWM's RDTSC-based frame
  // pacing freeze. Need a smarter accumulator (reset on long idle, cap delta).
  //proc_based_ctrl.use_tsc_offsetting          = 1;
  proc_based_ctrl.activate_secondary_controls = 1;
  write_ctrl_proc_based_safe(proc_based_ctrl);

  // 3.24.6.2
  ia32_vmx_procbased_ctls2_register proc_based_ctrl2;
  proc_based_ctrl2.flags                            = 0;
  proc_based_ctrl2.enable_ept                       = 1;
  proc_based_ctrl2.enable_rdtscp                    = 1;
  proc_based_ctrl2.enable_vpid                      = 1;
  proc_based_ctrl2.enable_invpcid                   = 1;
  proc_based_ctrl2.enable_xsaves                    = 1;
  proc_based_ctrl2.enable_user_wait_pause           = 1;
  proc_based_ctrl2.conceal_vmx_from_pt              = 1;
  write_ctrl_proc_based2_safe(proc_based_ctrl2);

  // 3.24.7
  ia32_vmx_exit_ctls_register exit_ctrl;
  exit_ctrl.flags                      = 0;
  exit_ctrl.save_debug_controls        = 1;
  exit_ctrl.host_address_space_size    = 1;
  exit_ctrl.save_ia32_pat              = 1;
  exit_ctrl.load_ia32_pat              = 1;
  //exit_ctrl.load_ia32_perf_global_ctrl = 1;
  //exit_ctrl.clear_ia32_rtit_ctl        = 1; 
  exit_ctrl.conceal_vmx_from_pt        = 1;
  //exit_ctrl.clear_ia32_lbr_ctl         = 1;
  write_ctrl_exit_safe(exit_ctrl);

  // 3.24.8
  ia32_vmx_entry_ctls_register entry_ctrl;
  entry_ctrl.flags                      = 0;
  entry_ctrl.load_debug_controls        = 1;
  entry_ctrl.ia32e_mode_guest           = 1;
  entry_ctrl.load_ia32_pat              = 1;
  //entry_ctrl.load_ia32_perf_global_ctrl = 1;
  entry_ctrl.conceal_vmx_from_pt        = 1;
  //entry_ctrl.load_ia32_rtit_ctl         = 1;
  //entry_ctrl.load_ia32_lbr_ctl          = 1;
  write_ctrl_entry_safe(entry_ctrl);

  // 3.24.6.3
  // Trap #BP (vector 3): blank_memory points at an existing 0xCC byte in ntdll
  // padding. hv::Call's callee RET jumps to blank_memory, executes 0xCC, #BP
  // vmexits, exit-handlers.cpp's breakpoint case dispatches via return_old_func.
  // Legit guest #BP (debugger / __debugbreak) is re-injected in the same case.
  vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, (1u << exception_vector::breakpoint));

  // 设置 up the 掩码 and match in such a way so
  // that a vm-exit is never triggered for a pagefault
  vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK,  0);
  vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
  
  // 3.24.6.5
  vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);

  // 3.24.6.6
#ifdef NDEBUG
  // only vm-exit when guest tries to change a reserved bit
  vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK,
    cpu->cached.vmx_cr0_fixed0 | ~cpu->cached.vmx_cr0_fixed1 |
    CR0_CACHE_DISABLE_FLAG | CR0_WRITE_PROTECT_FLAG);
  vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK,
    cpu->cached.vmx_cr4_fixed0 | ~cpu->cached.vmx_cr4_fixed1);
#else
  // vm-exit on every CR0/CR4 modification
  vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0xFFFFFFFF'FFFFFFFF);
  vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0xFFFFFFFF'FFFFFFFF);
#endif
  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, __readcr0());
  vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, __readcr4() & ~CR4_VMX_ENABLE_FLAG);

  // 3.24.6.7
  // try to trigger the least amount of CR3 exits as possible
  vmx_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT,   1);
  vmx_vmwrite(VMCS_CTRL_CR3_TARGET_VALUE_0, g_ghv->system_cr3.flags);

  // 3.24.6.9
  vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, MmGetPhysicalAddress(&cpu->msr_bitmap).QuadPart);

  // 3.24.6.11
  ept_pointer eptp;
  eptp.flags                                = 0;
  eptp.memory_type                          = MEMORY_TYPE_WRITE_BACK;
  eptp.page_walk_length                     = 3;
  eptp.enable_access_and_dirty_flags        = 0;
  eptp.enable_supervisor_shadow_stack_pages = 0;
  eptp.page_frame_number                    = MmGetPhysicalAddress(&cpu->ept.pml4).QuadPart >> 12;
  vmx_vmwrite(VMCS_CTRL_EPT_POINTER, eptp.flags);

  // 3.24.6.12
  vmx_vmwrite(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER, cpu->vpid);


  // 3.24.7.2
  //cpu->msr_exit_store.tsc.msr_idx              = IA32_TIME_STAMP_COUNTER;
  //cpu->msr_exit_store.perf_global_ctrl.msr_idx = IA32_PERF_GLOBAL_CTRL;
  //cpu->msr_exit_store.aperf.msr_idx            = IA32_APERF;
  //cpu->msr_exit_store.mperf.msr_idx            = IA32_MPERF;
  //cpu->msr_exit_store.riti.msr_idx            = IA32_RTIT_CTL;
  ////cpu->msr_exit_store.lbr_ctl.msr_idx         = IA32_LBR_CTL;
  //vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT,
  //  sizeof(cpu->msr_exit_store) / 16);
  //vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_ADDRESS,
  //  MmGetPhysicalAddress(&cpu->msr_exit_store).QuadPart);

  // 3.24.7.2
  vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT,    0);
  vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_ADDRESS,  0);

  // 3.24.8.2
  //cpu->msr_entry_load.aperf.msr_idx = IA32_APERF;
  //cpu->msr_entry_load.mperf.msr_idx = IA32_MPERF;
  //cpu->msr_entry_load.aperf.msr_data = __readmsr(IA32_APERF);
  //cpu->msr_entry_load.mperf.msr_data = __readmsr(IA32_MPERF);
  //cpu->msr_entry_load.riti.msr_idx = IA32_RTIT_CTL;
  //cpu->msr_entry_load.riti.msr_data = 0;

  //vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT,
  //  sizeof(cpu->msr_entry_load) / 16);
  //vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_ADDRESS,
  //  MmGetPhysicalAddress(&cpu->msr_entry_load).QuadPart);

  // 3.24.8.3
  vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
  vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE,           0);
  vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH,             0);
}

// setup the VMCS host fields
void write_vmcs_host_fields(vcpu const* const cpu) {
  // 3.24.5
  // 3.26.2

  cr3 host_cr3;
  host_cr3.flags                     = 0;
  host_cr3.page_level_cache_disable  = 0;
  host_cr3.page_level_write_through  = 0;
  host_cr3.address_of_page_directory =
    MmGetPhysicalAddress(&g_ghv->host_page_tables.pml4).QuadPart >> 12;
  vmx_vmwrite(VMCS_HOST_CR3, host_cr3.flags);

  //cr4 host_cr4;
  // host_cr4.标志位集合 = __readcr4();

  // // these are 标志位集合 that may or may not be 设置 by Windows
  //host_cr4.fsgsbase_enable = 1;
  //host_cr4.os_xsave        = 1;
  //host_cr4.smap_enable     = 0;
  //host_cr4.smep_enable     = 0;

  vmx_vmwrite(VMCS_HOST_CR0, __readcr0());

  //锟斤拷锟斤拷HOSTCR4
  cr4 HostCr4 = { 0 };
  HostCr4.flags = __readcr4();
  if (cpu->cached.cpuid_01.cpuid_feature_information_ecx.xsave_xrstor_instruction)
  {
      HostCr4.os_xsave = 1;
  }
  vmx_vmwrite(VMCS_HOST_CR4, HostCr4.flags);

  // ensure that rsp is NOT aligned to 16 bytes when execution starts
  auto const rsp = ((reinterpret_cast<size_t>(cpu->host_stack)
    + host_stack_size) & ~0b1111ull) - 8;

  vmx_vmwrite(VMCS_HOST_RSP, rsp);
  vmx_vmwrite(VMCS_HOST_RIP, reinterpret_cast<size_t>(vm_exit));

  vmx_vmwrite(VMCS_HOST_CS_SELECTOR, host_cs_selector.flags);
  vmx_vmwrite(VMCS_HOST_SS_SELECTOR, host_ss_selector.flags);
  vmx_vmwrite(VMCS_HOST_DS_SELECTOR, host_ds_selector.flags);
  vmx_vmwrite(VMCS_HOST_ES_SELECTOR, host_ds_selector.flags);
  vmx_vmwrite(VMCS_HOST_FS_SELECTOR, host_ds_selector.flags);
  vmx_vmwrite(VMCS_HOST_GS_SELECTOR, host_ds_selector.flags);
  vmx_vmwrite(VMCS_HOST_TR_SELECTOR, host_tr_selector.flags);

  vmx_vmwrite(VMCS_HOST_FS_BASE,   reinterpret_cast<size_t>(cpu));
  vmx_vmwrite(VMCS_HOST_GS_BASE,   0);
  vmx_vmwrite(VMCS_HOST_TR_BASE,   reinterpret_cast<size_t>(&cpu->host_tss));
  vmx_vmwrite(VMCS_HOST_GDTR_BASE, reinterpret_cast<size_t>(&cpu->host_gdt));
  vmx_vmwrite(VMCS_HOST_IDTR_BASE, reinterpret_cast<size_t>(&cpu->host_idt));

  vmx_vmwrite(VMCS_HOST_SYSENTER_CS,  0);
  vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, 0);
  vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, 0);

  // 3.11.12.4
  // configure PAT as if it wasn't supported (i.e. 默认 settings after a reset)
  ia32_pat_register host_pat;
  host_pat.flags = 0;
  host_pat.pa0   = MEMORY_TYPE_WRITE_BACK;
  host_pat.pa1   = MEMORY_TYPE_WRITE_THROUGH;
  host_pat.pa2   = MEMORY_TYPE_UNCACHEABLE_MINUS;
  host_pat.pa3   = MEMORY_TYPE_UNCACHEABLE;
  host_pat.pa4   = MEMORY_TYPE_WRITE_BACK;
  host_pat.pa5   = MEMORY_TYPE_WRITE_THROUGH;
  host_pat.pa6   = MEMORY_TYPE_UNCACHEABLE_MINUS;
  host_pat.pa7   = MEMORY_TYPE_UNCACHEABLE;
  vmx_vmwrite(VMCS_HOST_PAT, host_pat.flags);

  // 禁用 every PMC
  //vmx_vmwrite(VMCS_HOST_PERF_GLOBAL_CTRL, 0);
}

// setup the Guest 客户机状态 in the VMCS so that it mirrors the currently running system
void write_vmcs_guest_fields() {
  // 3.24.4
  // 3.26.3

  vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());

  vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
  vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());

  vmx_vmwrite(VMCS_GUEST_DR7, __readdr(7));

  // RIP and RSP are 设置 in vm-launch.asm
  vmx_vmwrite(VMCS_GUEST_RSP, 0);
  vmx_vmwrite(VMCS_GUEST_RIP, 0);

  vmx_vmwrite(VMCS_GUEST_RFLAGS, __readeflags());

  vmx_vmwrite(VMCS_GUEST_CS_SELECTOR,   read_cs().flags);
  vmx_vmwrite(VMCS_GUEST_SS_SELECTOR,   read_ss().flags);
  vmx_vmwrite(VMCS_GUEST_DS_SELECTOR,   read_ds().flags);
  vmx_vmwrite(VMCS_GUEST_ES_SELECTOR,   read_es().flags);
  vmx_vmwrite(VMCS_GUEST_FS_SELECTOR,   read_fs().flags);
  vmx_vmwrite(VMCS_GUEST_GS_SELECTOR,   read_gs().flags);
  vmx_vmwrite(VMCS_GUEST_TR_SELECTOR,   read_tr().flags);
  vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, read_ldtr().flags);

  segment_descriptor_register_64 gdtr, idtr;
  _sgdt(&gdtr);
  __sidt(&idtr);

  vmx_vmwrite(VMCS_GUEST_CS_BASE,   segment_base(gdtr, read_cs()));
  vmx_vmwrite(VMCS_GUEST_SS_BASE,   segment_base(gdtr, read_ss()));
  vmx_vmwrite(VMCS_GUEST_DS_BASE,   segment_base(gdtr, read_ds()));
  vmx_vmwrite(VMCS_GUEST_ES_BASE,   segment_base(gdtr, read_es()));
  vmx_vmwrite(VMCS_GUEST_FS_BASE,   __readmsr(IA32_FS_BASE));
  vmx_vmwrite(VMCS_GUEST_GS_BASE,   __readmsr(IA32_GS_BASE));
  vmx_vmwrite(VMCS_GUEST_TR_BASE,   segment_base(gdtr, read_tr()));
  vmx_vmwrite(VMCS_GUEST_LDTR_BASE, segment_base(gdtr, read_ldtr()));

  vmx_vmwrite(VMCS_GUEST_CS_LIMIT,   __segmentlimit(read_cs().flags));
  vmx_vmwrite(VMCS_GUEST_SS_LIMIT,   __segmentlimit(read_ss().flags));
  vmx_vmwrite(VMCS_GUEST_DS_LIMIT,   __segmentlimit(read_ds().flags));
  vmx_vmwrite(VMCS_GUEST_ES_LIMIT,   __segmentlimit(read_es().flags));
  vmx_vmwrite(VMCS_GUEST_FS_LIMIT,   __segmentlimit(read_fs().flags));
  vmx_vmwrite(VMCS_GUEST_GS_LIMIT,   __segmentlimit(read_gs().flags));
  vmx_vmwrite(VMCS_GUEST_TR_LIMIT,   __segmentlimit(read_tr().flags));
  vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(read_ldtr().flags));

  vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS,   segment_access(gdtr, read_cs()).flags);
  vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS,   segment_access(gdtr, read_ss()).flags);
  vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS,   segment_access(gdtr, read_ds()).flags);
  vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS,   segment_access(gdtr, read_es()).flags);
  vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS,   segment_access(gdtr, read_fs()).flags);
  vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS,   segment_access(gdtr, read_gs()).flags);
  vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS,   segment_access(gdtr, read_tr()).flags);
  vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, segment_access(gdtr, read_ldtr()).flags);

  vmx_vmwrite(VMCS_GUEST_GDTR_BASE, gdtr.base_address);
  vmx_vmwrite(VMCS_GUEST_IDTR_BASE, idtr.base_address);

  vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr.limit);
  vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr.limit);

  vmx_vmwrite(VMCS_GUEST_SYSENTER_CS,      __readmsr(IA32_SYSENTER_CS));
  vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP,     __readmsr(IA32_SYSENTER_ESP));
  vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP,     __readmsr(IA32_SYSENTER_EIP));
  vmx_vmwrite(VMCS_GUEST_DEBUGCTL,         __readmsr(IA32_DEBUGCTL) & (~(IA32_DEBUGCTL_LBR_FLAG || IA32_DEBUGCTL_BTS_FLAG)));
  vmx_vmwrite(VMCS_GUEST_PAT,              __readmsr(IA32_PAT));
  //vmx_vmwrite(VMCS_GUEST_PERF_GLOBAL_CTRL, __readmsr(IA32_PERF_GLOBAL_CTRL));


  vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, vmx_active);

  vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);

  vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);

  vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, MAXULONG64);

  vmx_vmwrite(VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE, MAXULONG64);

  //锟斤拷锟斤拷RTTI
  ia32_rtit_ctl_register rtti = { 0 };
  vmx_vmwrite(VMCS_GUEST_RTIT_CTL, rtti.flags);
  //锟斤拷锟斤拷DEBUGCTL
  ia32_debugctl_register Debugctl = { 0 };
  vmx_vmwrite(VMCS_GUEST_DEBUGCTL, Debugctl.flags);

  
}

} // namespace hv

