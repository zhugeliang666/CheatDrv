#include "base.h"
#include "vcpu.h"
#include "hv.h"
#include "ept.h"
#include "gdt.h"
#include "idt.h"
#include "vmx.h"
#include "vmcs.h"
#include "timing.h"
#include "trap-frame.h"
#include "exit-handlers.h"
#include "exception-routines.h"
#include "introspection.h"
#include "../amd/svm.h"
#include "../amd/vmcb.h"
#pragma  intrinsic(_disable)
#pragma  intrinsic(_enable)
// first byte at the start of the image
extern "C" uint8_t __ImageBase;
extern "C" void svm_stgi_asm();
extern "C" void svm_prepare_stop_c(hv::vcpu* cpu, hv::guest_context* ctx);
extern "C" volatile LONG g_hv_panic_dump_claimed;
extern "C" [[noreturn]] void hv_bugcheck_on_stack_asm(
  uint64_t new_rsp,
  uint64_t bugcheck_code,
  uint64_t param1,
  uint64_t param2,
  uint64_t param3,
  uint64_t param4);

namespace hv {
    #pragma code_seg(".vm")
// defined in vm-launch.asm
bool vm_launch();

// cache certain fixed values (CPUID results, MSRs, etc) that are used
// frequently during VMX operation (to speed up vm-exit handling).
static void cache_cpu_data(vcpu_cached_data& cached) {

  __cpuidex(reinterpret_cast<int*>(&cached.cpuid_00), 0x00,0);

  __cpuid(reinterpret_cast<int*>(&cached.cpuid_01), 0x01);

  cpuid_eax_80000008 cpuid_80000008;
  __cpuid(reinterpret_cast<int*>(&cpuid_80000008), 0x80000008);

  cached.max_phys_addr = cpuid_80000008.eax.number_of_physical_address_bits;

  // VMX needs to be enabled to 读取 from certain VMX_* MSRS. Keep generic
  // CPUID/MAXPHYSADDR populated for the AMD SVM backend before returning on
  // non-VMX processors.
  if (!cached.cpuid_01.cpuid_feature_information_ecx.virtual_machine_extensions)
    return;

  cached.vmx_cr0_fixed0 = __readmsr(IA32_VMX_CR0_FIXED0);
  cached.vmx_cr0_fixed1 = __readmsr(IA32_VMX_CR0_FIXED1);
  cached.vmx_cr4_fixed0 = __readmsr(IA32_VMX_CR4_FIXED0);
  cached.vmx_cr4_fixed1 = __readmsr(IA32_VMX_CR4_FIXED1);

  cpuid_eax_0d_ecx_00 cpuid_0d;
  __cpuidex(reinterpret_cast<int*>(&cpuid_0d), 0x0D, 0x00);
  
  // features in XCR0 that are supported
  cached.xcr0_unsupported_mask = ~((static_cast<uint64_t>(
    cpuid_0d.edx.flags) << 32) | cpuid_0d.eax.flags);

  cached.feature_control.flags = __readmsr(IA32_FEATURE_CONTROL);
  cached.vmx_misc.flags        = __readmsr(IA32_VMX_MISC);

  // 创建 a fake guest FEATURE_CONTROL MSR that has VMX and SMX disabled
  cached.guest_feature_control                               = cached.feature_control;
  cached.guest_feature_control.lock_bit                      = 1;
  cached.guest_feature_control.enable_vmx_inside_smx         = 0;
  cached.guest_feature_control.enable_vmx_outside_smx        = 0;
  cached.guest_feature_control.senter_local_function_enables = 0;
  cached.guest_feature_control.senter_global_enable          = 0;
}

// 启用 VMX operation prior to execution of the VMXON instruction
static bool enable_vmx_operation(vcpu const* const cpu) {
  // 3.23.6
  if (!cpu->cached.cpuid_01.cpuid_feature_information_ecx.virtual_machine_extensions) {
    LOG_DEBUG(_XOR_("[YVT] VMX not supported by CPUID.\n"));
    return false;
  }

  // 3.23.7
  if (!cpu->cached.feature_control.lock_bit ||
      !cpu->cached.feature_control.enable_vmx_outside_smx) {
    LOG_DEBUG(_XOR_("[YVT] VMX not enabled outside SMX.\n"));
    return false;
  }

  _disable();

  auto cr0 = __readcr0();
  auto cr4 = __readcr4();

  // 3.23.7
  cr4 |= CR4_VMX_ENABLE_FLAG;

  // 3.23.8
  cr0 |= cpu->cached.vmx_cr0_fixed0;
  cr0 &= cpu->cached.vmx_cr0_fixed1;
  cr4 |= cpu->cached.vmx_cr4_fixed0;
  cr4 &= cpu->cached.vmx_cr4_fixed1;

  __writecr0(cr0);
  __writecr4(cr4);

  _enable();

  return true;
}

// enter VMX operation by executing VMXON
static bool enter_vmx_operation(vmxon& vmxon_region) {
  ia32_vmx_basic_register vmx_basic;
  vmx_basic.flags = __readmsr(IA32_VMX_BASIC);

  // 3.24.11.5
  vmxon_region.revision_id = vmx_basic.vmcs_revision_id;
  vmxon_region.must_be_zero = 0;

  auto vmxon_phys = MmGetPhysicalAddress(&vmxon_region).QuadPart;
  NT_ASSERT(vmxon_phys % 0x1000 == 0);

  // enter vmx operation
  if (!vmx_vmxon(vmxon_phys)) {
    LOG_DEBUG(_XOR_("[YVT] VMXON failed.\n"));
    return false;
  }

  // 3.28.3.3.4
  vmx_invept(invept_all_context, {});

  return true;
}

// load the VMCS 指针 by executing VMPTRLD
static bool load_vmcs_pointer(vmcs& vmcs_region) {
  ia32_vmx_basic_register vmx_basic;
  vmx_basic.flags = __readmsr(IA32_VMX_BASIC);

  // 3.24.2
  vmcs_region.revision_id = vmx_basic.vmcs_revision_id;
  vmcs_region.shadow_vmcs_indicator = 0;

  auto vmcs_phys = MmGetPhysicalAddress(&vmcs_region).QuadPart;
  NT_ASSERT(vmcs_phys % 0x1000 == 0);

  if (!vmx_vmclear(vmcs_phys)) {
    LOG_DEBUG(_XOR_("[YVT] VMCLEAR failed.\n"));
    return false;
  }

  if (!vmx_vmptrld(vmcs_phys)) {
    LOG_DEBUG(_XOR_("[YVT] VMPTRLD failed.\n"));
    return false;
  }

  return true;
}

// 启用 vm-exits for MTRR MSR writes
static void enable_mtrr_exiting(vcpu* const cpu) {
  ia32_mtrr_capabilities_register mtrr_cap;
  mtrr_cap.flags = __readmsr(IA32_MTRR_CAPABILITIES);

  enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_DEF_TYPE, true);

  // 启用 exiting for fixed-range MTRRs
  if (mtrr_cap.fixed_range_supported) {
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_FIX64K_00000, true);
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_FIX16K_80000, true);
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_FIX16K_A0000, true);

    for (uint32_t i = 0; i < 8; ++i)
      enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_FIX4K_C0000 + i, true);
  }

  // 启用 exiting for variable-range MTRRs
  for (uint32_t i = 0; i < mtrr_cap.variable_range_count; ++i) {
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_PHYSBASE0 + i * 2, true);
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_PHYSMASK0 + i * 2, true);
  }




}

// 初始化 external structures that are not included in the VMCS
static void prepare_external_structures(vcpu* const cpu) {
  memset(&cpu->msr_bitmap, 0, sizeof(cpu->msr_bitmap));

  enable_exit_for_msr_read(cpu->msr_bitmap, IA32_FEATURE_CONTROL, true);
  enable_exit_for_msr_read(cpu->msr_bitmap, IA32_VMX_EPT_VPID_CAP, true);

  // Perfmon MSR trapping disabled 鈥 caused DWM black screen.
  //enable_exit_for_msr_read(cpu->msr_bitmap, IA32_FIXED_CTR2, true);
  //enable_exit_for_msr_read(cpu->msr_bitmap, IA32_APERF, true);
  //enable_exit_for_msr_read(cpu->msr_bitmap, IA32_MPERF, true);

  enable_exit_for_msr_read(cpu->msr_bitmap, IA32_BIOS_UPDATE_TRIGGER, true);
  enable_exit_for_msr_write(cpu->msr_bitmap, IA32_BIOS_UPDATE_TRIGGER, true);


  // Intel PT 鈥 trap reads + writes. CPUID(7,0).EBX bit25 also cleared.
  // DEBUGCTL only write-trapped (kernel needs valid reads 鈥 see exit-handlers
  // comment). VMCS_GUEST_DEBUGCTL clears LBR/BTS bits on every vm-条目项.
  enable_exit_for_msr_write(cpu->msr_bitmap, IA32_RTIT_CTL, true);
  enable_exit_for_msr_write(cpu->msr_bitmap, IA32_DEBUGCTL, true);
  enable_exit_for_msr_read(cpu->msr_bitmap, IA32_RTIT_CTL, true);
  enable_exit_for_msr_read(cpu->msr_bitmap, IA32_RTIT_STATUS, true);
  enable_exit_for_msr_read(cpu->msr_bitmap, IA32_RTIT_OUTPUT_BASE, true);
  enable_exit_for_msr_read(cpu->msr_bitmap, IA32_RTIT_OUTPUT_MASK_PTRS, true);
  enable_exit_for_msr_read(cpu->msr_bitmap, IA32_RTIT_CR3_MATCH, true);
  // IA32_DEBUGCTL read NOT trapped 鈥 kernel actively uses it.
  //enable_exit_for_msr_read(cpu->msr_bitmap, IA32_DEBUGCTL, true);

  enable_mtrr_exiting(cpu);

  // we don't care about anything that's in the TSS
  memset(&cpu->host_tss, 0, sizeof(cpu->host_tss));

  prepare_host_idt(cpu->host_idt);
  prepare_host_gdt(cpu->host_gdt, &cpu->host_tss);

  prepare_ept(cpu->ept);
  memset(&cpu->dbg_pending, 0, sizeof(cpu->dbg_pending));




}

// call the appropriate exit-handler for this vm-exit
static void dispatch_vm_exit(vcpu* const cpu, vmx_vmexit_reason const reason) {
  // Pending invept bitmap: host-handler 安装 path writes EPT for all
  // vCPUs from one vCPU; the OTHER vCPUs need to 刷新 their own TLB on
  // their next vmexit. Bit v set 鈫 vCPU v invepts itself, then clears bit.
  // invept_all_context flushes only this vCPU's TLB (per-vCPU EPTP), so
  // it's safe and avoids reconstructing the EPTP descriptor here.
  {
    auto self_idx = static_cast<uint32_t>(cpu - g_ghv->vcpus);
    uint64_t my_bit = 1ULL << self_idx;
    if (self_idx < 16)
      _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_per_vcpu_vmexits[self_idx]);

    // 数量计数 vmexits where guest is in DWM. Compare against the process of the
    // PMO ept_hook 条目项 (first active 条目项 with user-模式 CR3).
    if (self_idx < 16) {
      auto& t = g_ghv->ept_hook_table;
      PEPROCESS dwm = nullptr;
      for (auto e = t.active_list_head; e; e = e->next) {
        if (e->process_cr3 != (g_ghv->system_cr3.flags & ~0xFFFull)) {
          dwm = e->process;
          break;
        }
      }
      if (dwm) {
        auto cur = current_guest_eprocess();
        if (cur == dwm) {
          _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_per_vcpu_dwm_vmexits[self_idx]);
          g_ghv->diag_dwm_eprocess_observed = (uint64_t)cur;
        }
      }
    }

    if (g_ghv->pending_ept_invept_bitmap & my_bit) {
      vmx_invept(invept_all_context, {});
      _InterlockedAnd64((volatile LONG64*)&g_ghv->pending_ept_invept_bitmap,
                        (LONG64)~my_bit);
    }
    // Deferred 安装 drain: host-handler path enqueued entries; this
    // vCPU now installs its own EPT for each. eh_install_self is idempotent
    // (per_vcpu_active_bitmap), so processing the whole queue is safe even
    // if some entries were already installed for this vCPU.
    if (g_ghv->pending_ept_install_bitmap & my_bit) {
      eh::drain_pending_installs(cpu);
      _InterlockedAnd64((volatile LONG64*)&g_ghv->pending_ept_install_bitmap,
                        (LONG64)~my_bit);
    }

    // Walk our EPT for PMO 目标 once, capture PDE+PTE so we can verify
    // hardware is consulting the same PTE we modified during 安装.
    if (self_idx < 16 && !g_ghv->diag_pmo_walk_done[self_idx] && g_ghv->diag_pmo_target_pa) {
      uint64_t pa = g_ghv->diag_pmo_target_pa;
      pml4_virtual_address addr_ = { reinterpret_cast<void*>(pa) };
      if (addr_.pml4_idx == 0 && addr_.pdpt_idx < ept_pd_count) {
        auto& pde_2mb = cpu->ept.pds_2mb[addr_.pdpt_idx][addr_.pd_idx];
        g_ghv->diag_pmo_walk_pde[self_idx] = *(volatile uint64_t*)&pde_2mb;
        if (!pde_2mb.large_page) {
          auto pde_pfn = cpu->ept.pds[addr_.pdpt_idx][addr_.pd_idx].page_frame_number;
          auto pt = reinterpret_cast<ept_pte*>(host_physical_memory_base + (pde_pfn << 12));
          g_ghv->diag_pmo_walk_pte[self_idx] = *(volatile uint64_t*)&pt[addr_.pt_idx];
        } else {
          g_ghv->diag_pmo_walk_pte[self_idx] = 0xDEADDEADDEADDEAD;   // still large page!
        }
        g_ghv->diag_pmo_walk_done[self_idx] = 1;
      }
    }
  }

  switch (reason.basic_exit_reason) {
  case VMX_EXIT_REASON_EXCEPTION_OR_NMI:             handle_exception_or_nmi(cpu);     break;
  case VMX_EXIT_REASON_EXECUTE_GETSEC:               emulate_getsec(cpu);              break;
  case VMX_EXIT_REASON_EXECUTE_INVD:                 emulate_invd(cpu);                break;
  case VMX_EXIT_REASON_EXECUTE_INVLPG:               emulate_invlpg(cpu);              break;
  case VMX_EXIT_REASON_NMI_WINDOW:                   handle_nmi_window(cpu);           break;
  case VMX_EXIT_REASON_EXECUTE_CPUID:                emulate_cpuid(cpu);               break;
  case VMX_EXIT_REASON_MOV_CR:                       handle_mov_cr(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_RDMSR:                emulate_rdmsr(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_WRMSR:                emulate_wrmsr(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_XSETBV:               emulate_xsetbv(cpu);              break;
  case VMX_EXIT_REASON_EXECUTE_VMXON:                emulate_vmxon(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_VMCALL:               emulate_vmcall(cpu);              break;
  case VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED: handle_vmx_preemption(cpu);       break;
  case VMX_EXIT_REASON_EPT_VIOLATION:                handle_ept_violation(cpu);        break;
  case VMX_EXIT_REASON_EXECUTE_RDTSC:                emulate_rdtsc(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_RDTSCP:               emulate_rdtscp(cpu);              break;
  case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:            handle_monitor_trap_flag(cpu);    break;
  case VMX_EXIT_REASON_EPT_MISCONFIGURATION:         handle_ept_misconfiguration(cpu); break;
  // VMX instructions (except for VMXON and VMCALL)
  case VMX_EXIT_REASON_EXECUTE_INVEPT:
  case VMX_EXIT_REASON_EXECUTE_INVVPID:
  case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
  case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
  case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
  case VMX_EXIT_REASON_EXECUTE_VMPTRST:
  case VMX_EXIT_REASON_EXECUTE_VMREAD:
  case VMX_EXIT_REASON_EXECUTE_VMRESUME:
  case VMX_EXIT_REASON_EXECUTE_VMWRITE:
  case VMX_EXIT_REASON_EXECUTE_VMXOFF:
  case VMX_EXIT_REASON_EXECUTE_VMFUNC:               handle_vmx_instruction(cpu);    break;

  // unhandled VM-exit
  default:
    HV_LOG_ERROR(_XOR_("Unhandled VM-exit. Exit Reason: %u. RIP: %p."),
      reason.basic_exit_reason, vmx_vmread(VMCS_GUEST_RIP));
    inject_hw_exception(general_protection, 0);
    break;
  }
}

// called for every vm-exit
bool handle_vm_exit(guest_context* const ctx) {
  // measure host-side overhead so we can subtract it from guest TSC
  auto const tsc_at_exit_entry = __rdtsc();

  // 获取 the 当前 vcpu
    //auto const cpu = reinterpret_cast<vcpu*>(vmx_vmread(VMCS_HOST_FS_BASE));

    auto cpuid = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;
    auto const cpu = &g_ghv->vcpus[cpuid];

   cpu->ctx = ctx;

   // hv::Call lazy-恢复: drain pending VMCS_HOST_RSP 恢复 from a prior
   // cross-vCPU return. MUST run before any host code that touches the host
   // stack 鈥 until we vmwrite, VMCS_HOST_RSP still points at a vtcallstack
   // node about to be released.
   process_pending_vtcall_restore(cpu);

   vmx_vmexit_reason reason;
   reason.flags = static_cast<uint32_t>(vmx_vmread(VMCS_EXIT_REASON));

  // dont hide tsc overhead by 默认
  cpu->hide_vm_exit_overhead = false;
  cpu->stop_virtualization   = false;

  // Deferred self-hide: prepare_self_hide() in DriverMain populates the PFN
  // list and sets one bit per vcpu in pending_hide_vcpu_bitmap. On the first
  // VM-exit past the TSC threshold, this vcpu walks the list and redirects
  // each EPT 条目项 to dummy_page. Runs in host 模式 (Host CR3 寄存器, no EPT) so
  // hiding driver image here is safe 鈥 by now guest is in NTOS, not in our
  // .text.
  auto const my_bit = 1ULL << cpuid;
  if ((g_ghv->pending_hide_vcpu_bitmap & my_bit) && __rdtsc() >= g_ghv->pending_hide_tsc_threshold) {
    _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_hide_enter);
    auto const pfns  = g_ghv->pending_hide_pfns;
    auto const count = g_ghv->pending_hide_count;
    uint64_t local_null = 0;
    for (uint32_t i = 0; i < count; i++) {
      auto const pte = get_ept_pte(cpu->ept, pfns[i] << 12, true);
      if (pte) pte->page_frame_number = cpu->ept.dummy_page_pfn;
      else     local_null++;
    }
    _InterlockedExchangeAdd64((volatile LONG64*)&g_ghv->diag_hide_pte_total, (LONG64)count);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_ghv->diag_hide_pte_null,  (LONG64)local_null);
    vmx_invept(invept_all_context, {});
    _InterlockedOr64((volatile LONG64*)&g_ghv->diag_hide_done_bitmap, (LONG64)my_bit);
    _InterlockedAnd64((volatile LONG64*)&g_ghv->pending_hide_vcpu_bitmap,
      ~(LONG64)my_bit);
  }

  // 执行跳板 pool: add_page handler now writes the EPT PTE on every vCPU
  // directly (R=W=X=1, pfn=exec_pfn), so no per-vCPU lazy broadcast needed.
  #if 0
  {
    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    bool any_installed = false;
    for (uint32_t i = 0; i < t.capacity; i++) {
      auto& e = t.buffer[i];
      if (!e.in_use) continue;
      if (e.per_vcpu_active_bitmap & my_bit) continue;
      e.per_vcpu_active_bitmap |= my_bit;
      install_ept_hook(cpu->ept, e.orig_pfn, e.fake_pfn, e.is_fake_page);
      any_installed = true;
    }
    t.lock.release();
    if (any_installed) vmx_invept(invept_all_context, {});
  }
  #endif

  dispatch_vm_exit(cpu, reason);

  // hv::Call lazy-恢复 stack reclamation: VMCS_HOST_RSP has been
  // re-pointed, but this vm-exit is still executing on the deferred stack.
  // Decrements release_delay each vm-exit; actual 卸载移除 happens after the
  // counter hits 0 (i.e. after this exit cycle completes and another exit
  // lands on the new host stack).
  process_pending_vtcall_release(cpu);

  vmentry_interrupt_information interrupt_info;
  interrupt_info.flags = static_cast<uint32_t>(
    vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD));

  vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL) & (~(IA32_DEBUGCTL_LBR_FLAG || IA32_DEBUGCTL_BTS_FLAG)));

  vmx_vmwrite(VMCS_GUEST_RTIT_CTL, 0);

  vmx_vmwrite(VMCS_GUEST_LBR_CTL, 0);


  if (interrupt_info.valid) {
    char name[16] = {};
    current_guest_image_file_name(name);
    HV_LOG_INJECT_INT(_XOR_("Injecting interrupt into guest (%s). BasicExitReason=%i, Vector=%i, Error=%i."),
      name, reason.basic_exit_reason, interrupt_info.vector, vmx_vmread(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE));
  }

  // 恢复 Guest 客户机状态. the assembly code is responsible for restoring
  // RIP, CS, RFLAGS, RSP, SS, CR0, CR4, as well as the usual fields in
  // the guest_context 结构体. the C++ code is responsible for the rest.
  if (cpu->stop_virtualization) {
    // TODO: assert that CPL is 0

    // ensure that the 控制寄存器 shadows reflect the guest values
    vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, read_effective_guest_cr0().flags);
    vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, read_effective_guest_cr4().flags);

    // DR7
    __writedr(7, vmx_vmread(VMCS_GUEST_DR7));

    // MSRs
    __writemsr(IA32_SYSENTER_CS,      vmx_vmread(VMCS_GUEST_SYSENTER_CS));
    __writemsr(IA32_SYSENTER_ESP,     vmx_vmread(VMCS_GUEST_SYSENTER_ESP));
    __writemsr(IA32_SYSENTER_EIP,     vmx_vmread(VMCS_GUEST_SYSENTER_EIP));
    __writemsr(IA32_PAT,              vmx_vmread(VMCS_GUEST_PAT));
    __writemsr(IA32_DEBUGCTL,         vmx_vmread(VMCS_GUEST_DEBUGCTL));
    //__writemsr(IA32_PERF_GLOBAL_CTRL, cpu->msr_exit_store.perf_global_ctrl.msr_data);

    // CR3
    __writecr3(vmx_vmread(VMCS_GUEST_CR3));

    // GDT
    segment_descriptor_register_64 gdtr;
    gdtr.base_address = vmx_vmread(VMCS_GUEST_GDTR_BASE);
    gdtr.limit = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_GDTR_LIMIT));
    _lgdt(&gdtr);

    // IDT
    segment_descriptor_register_64 idtr;
    idtr.base_address = vmx_vmread(VMCS_GUEST_IDTR_BASE);
    idtr.limit = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_IDTR_LIMIT));
    __lidt(&idtr);

    segment_selector guest_tr;
    guest_tr.flags = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_TR_SELECTOR));

    // TSS
    (reinterpret_cast<segment_descriptor_32*>(gdtr.base_address)
      + guest_tr.index)->type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
    write_tr(guest_tr.flags);

    // segment selectors
    write_ds(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_DS_SELECTOR)));
    write_es(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_ES_SELECTOR)));
    write_fs(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_FS_SELECTOR)));
    write_gs(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_GS_SELECTOR)));
    write_ldtr(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_LDTR_SELECTOR)));

    // FS and GS base 地址
    _writefsbase_u64(vmx_vmread(VMCS_GUEST_FS_BASE));
    _writegsbase_u64(vmx_vmread(VMCS_GUEST_GS_BASE));

    return true;
  }

  //hide_vm_exit_overhead(cpu);

  // TSC offsetting disabled 鈥 see vmcs.cpp comment. Old code accumulated
  // host overhead unconditionally which broke DWM's frame pacing. To re-启用
  // safely: cap per-exit delta (e.g. <0x10000), reset on long idle, and only
  // emit on hide_vm_exit_overhead-marked exits.
  //auto const host_overhead = __rdtsc() - tsc_at_exit_entry;
  //cpu->tsc_offset -= host_overhead;
  //vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, cpu->tsc_offset);
  (void)tsc_at_exit_entry;

  //vmx_vmwrite(VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE, cpu->preemption_timer);


  //invvpid_descriptor desc;
  //desc.linear_address = 0;
  //desc.reserved1 = 0;
  //desc.reserved2 = 0;
  //desc.vpid = cpu->vpid;
  //vmx_invvpid(invvpid_single_context_retaining_globals, desc);


  // cpu->ctx = nullptr;
  // Disabled: line 277 (cpu->ctx = ctx) rewrites this on every vmexit, so the
  // 清除 here is redundant. Worse, it introduces a NULL window: if a
  // host-模式 code path re-reads cpu->ctx between this 清除 and the next
  // vmexit (observed: emulate_rdmsr crashed dereferencing cpu->ctx==NULL on
  // the OTHER vCPU after a fault-recovered rdmsr_safe), it #PFs.

  return false;
}

static vcpu* find_vcpu_from_host_rsp(uint64_t const rsp_probe) {
  if (!g_ghv || !g_ghv->vcpus)
    return nullptr;

  for (unsigned int i = 0; i < g_ghv->vcpu_count; ++i) {
    auto const base = reinterpret_cast<uint64_t>(g_ghv->vcpus[i].host_stack);
    if (rsp_probe >= base && rsp_probe < base + host_stack_size)
      return &g_ghv->vcpus[i];
  }
  return nullptr;
}

static uint64_t resolve_kernel_rsp_from_kpcr(uint64_t const kpcr, uint64_t const guest_rsp, uint64_t const fallback_rsp) {
  if (guest_rsp >= 0xFFFF800000000000ULL)
    return guest_rsp;

  if (kpcr >= 0xFFFF800000000000ULL) {
    auto const tss_base = *reinterpret_cast<uint64_t const*>(kpcr + 0x08);
    if (tss_base >= 0xFFFF800000000000ULL) {
      auto const rsp0 = *reinterpret_cast<uint64_t const*>(tss_base + 4);
      if (rsp0 >= 0xFFFF800000000000ULL)
        return rsp0;
    }
  }
  return fallback_rsp;
}

[[noreturn]] static void trigger_host_crash_dump(
    uint64_t const vector,
    uint64_t const error_code,
    uint64_t const fault_rip,
    uint64_t const fault_rsp) {
  _disable();

  uint64_t const fault_cr2 = __readcr2();
  uint64_t const rip_rva   = fault_rip - reinterpret_cast<uint64_t>(&__ImageBase);
  auto cpu = find_vcpu_from_host_rsp(fault_rsp);

  if ((cpu && cpu->svm.launched) || svm::available()) {
    uint64_t exit_code  = 0;
    uint64_t guest_krsp = fault_rsp;
    uint64_t orig_hsave = 0;
    uint64_t guest_efer = __readmsr(0xC0000080) & ~(1ULL << 12);
    uint64_t sys_cr3    = (g_ghv && g_ghv->system_cr3.flags) ? g_ghv->system_cr3.flags : 0;

    if (cpu && cpu->svm.vmcb) {
      auto const v = cpu->svm.vmcb;
      auto const host_v = reinterpret_cast<svm::vmcb const*>(cpu->svm.host_vmcb);
      exit_code  = v->exitcode;
      orig_hsave = cpu->svm.original_hsave_pa;
      guest_efer = cpu->svm.guest_efer & ~(1ULL << 12);
      if (!sys_cr3)
        sys_cr3 = cpu->svm.original_cr3;

      uint64_t const host_kpcr = (host_v && host_v->gs.base >= 0xFFFF800000000000ULL) ? host_v->gs.base : 0;
      uint64_t const kpcr = host_kpcr ? host_kpcr : ((v->gs.base >= 0xFFFF800000000000ULL) ? v->gs.base : v->kernel_gs_base);
      uint64_t const kgs  = (v->gs.base >= 0xFFFF800000000000ULL) ? v->kernel_gs_base : v->gs.base;

      svm_prepare_stop_c(cpu, nullptr);

      if (kpcr >= 0xFFFF800000000000ULL) {
        __writemsr(0xC0000101, kpcr);
        __writemsr(0xC0000102, kgs);
      }

      guest_krsp = resolve_kernel_rsp_from_kpcr(
        kpcr,
        v->rsp,
        reinterpret_cast<uint64_t>(cpu->host_stack) + host_stack_size - 0x100);
    }

    __writemsr(0xC0010117, orig_hsave);
    __writemsr(0xC0000080, guest_efer);
    if (sys_cr3)
      __writecr3(sys_cr3);
    svm_stgi_asm();
    __writecr8(0);
    if (_InterlockedCompareExchange(&g_hv_panic_dump_claimed, 1, 0) != 0) {
      _enable();
      for (;;)
        _mm_pause();
    }
    hv_bugcheck_on_stack_asm(
      guest_krsp,
      0xDEAD0000ULL | (vector & 0xFFULL),
      fault_rip,
      rip_rva,
      fault_cr2,
      ((error_code & 0xFFFFFFFFULL) << 32) | (exit_code & 0xFFFFFFFFULL));
  }

  uint64_t const exit_code = vmx_vmread(VMCS_EXIT_REASON);
  uint64_t const g_cr3     = vmx_vmread(VMCS_GUEST_CR3);
  uint64_t const g_rsp     = vmx_vmread(VMCS_GUEST_RSP);
  uint16_t const g_cs      = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_CS_SELECTOR));
  uint64_t const g_fs      = vmx_vmread(VMCS_GUEST_FS_BASE);
  uint64_t const g_gs      = vmx_vmread(VMCS_GUEST_GS_BASE);
  uint64_t const g_kgs     = __readmsr(0xC0000102);

  __writedr(7, vmx_vmread(VMCS_GUEST_DR7));
  __writemsr(IA32_SYSENTER_CS,  vmx_vmread(VMCS_GUEST_SYSENTER_CS));
  __writemsr(IA32_SYSENTER_ESP, vmx_vmread(VMCS_GUEST_SYSENTER_ESP));
  __writemsr(IA32_SYSENTER_EIP, vmx_vmread(VMCS_GUEST_SYSENTER_EIP));
  __writemsr(IA32_PAT,          vmx_vmread(VMCS_GUEST_PAT));
  __writemsr(IA32_DEBUGCTL,     vmx_vmread(VMCS_GUEST_DEBUGCTL));

  __writecr3(((g_cs & 3) == 0 && g_cr3) ? g_cr3 : g_ghv->system_cr3.flags);

  segment_descriptor_register_64 gdtr;
  gdtr.base_address = vmx_vmread(VMCS_GUEST_GDTR_BASE);
  gdtr.limit = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_GDTR_LIMIT));
  _lgdt(&gdtr);

  segment_descriptor_register_64 idtr;
  idtr.base_address = vmx_vmread(VMCS_GUEST_IDTR_BASE);
  idtr.limit = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_IDTR_LIMIT));
  __lidt(&idtr);

  segment_selector guest_tr;
  guest_tr.flags = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_TR_SELECTOR));
  (reinterpret_cast<segment_descriptor_32*>(gdtr.base_address) + guest_tr.index)->type =
    SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
  write_tr(guest_tr.flags);

  write_ds(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_DS_SELECTOR)));
  write_es(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_ES_SELECTOR)));
  write_fs(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_FS_SELECTOR)));
  write_gs(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_GS_SELECTOR)));
  write_ldtr(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_LDTR_SELECTOR)));

  uint64_t const kpcr = (g_gs >= 0xFFFF800000000000ULL) ? g_gs : g_kgs;
  uint64_t const kgs  = (g_gs >= 0xFFFF800000000000ULL) ? g_kgs : g_gs;
  _writefsbase_u64(g_fs);
  if (kpcr >= 0xFFFF800000000000ULL) {
    _writegsbase_u64(kpcr);
    __writemsr(0xC0000102, kgs);
  }

  uint64_t const guest_krsp = resolve_kernel_rsp_from_kpcr(kpcr, g_rsp, fault_rsp);
  vmx_vmxoff();
  __writecr8(0);

  hv_bugcheck_on_stack_asm(
    guest_krsp,
    0xDEAD0000ULL | (vector & 0xFFULL),
    fault_rip,
    rip_rva,
    fault_cr2,
    ((error_code & 0xFFFFFFFFULL) << 32) | (exit_code & 0xFFFFFFFFULL));
}

// called for every host interrupt
void handle_host_interrupt(trap_frame* const frame) {
  switch (frame->vector) {
  // host NMIs
  case nmi: {
    if (!svm::available())
      inject_nmi();
    break;
  }
  // host exceptions
  default: {
    // no registered exception handler: exit root/SVM 模式 and trigger a Windows
    // 崩溃转储 (0xDEAD00xx) with exact Host RIP, RVA, CR2, and VMEXIT reason.
    if (!frame->r10 || !frame->r11) {
      HV_LOG_ERROR(_XOR_("Unhandled exception. RIP=hv.sys+%p. Vector=%u."),
        frame->rip - reinterpret_cast<UINT64>(&__ImageBase), frame->vector);

      trigger_host_crash_dump(frame->vector, frame->error, frame->rip, frame->rsp);
      break;
    }

    HV_LOG_HOST_EXCEPTION(_XOR_("Handling host exception. RIP=hv.sys+%p. Vector=%u"),
      frame->rip - reinterpret_cast<UINT64>(&__ImageBase), frame->vector);

    // jump to the exception handler
    frame->rip = frame->r10;

    auto const e = reinterpret_cast<host_exception_info*>(frame->r11);

    e->exception_occurred = true;
    e->vector             = frame->vector;
    e->error              = frame->error;

    // slightly helps prevent infinite exceptions
    frame->r10 = 0;
    frame->r11 = 0;
  }
  }
}

// virtualize the specified cpu. this assumes that execution is already
// restricted to the desired logical proocessor.
bool virtualize_cpu(vcpu* const cpu) {
	unsigned long const index = (cpu && g_ghv && g_ghv->vcpus)
		? static_cast<unsigned long>(cpu - g_ghv->vcpus)
		: MAXULONG;
	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=cache-before irql=%lu current=%lu\n"),
		index,
		static_cast<unsigned long>(KeGetCurrentIrql()),
		static_cast<unsigned long>(KeGetCurrentProcessorIndex()));
  cache_cpu_data(cpu->cached);
	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=cache-after\n"), index);

	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=svm-available-before\n"), index);
	bool const svm_available = svm::available();
	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=svm-available-after result=%d\n"),
		index, static_cast<int>(svm_available));

  if (svm_available) {
	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=create-state-before allocated=%d\n"),
		index, static_cast<int>(cpu->svm.allocated));
	bool const state_ready = svm::create_vcpu_state(cpu, index);
	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=create-state-after result=%d allocated=%d\n"),
		index, static_cast<int>(state_ready), static_cast<int>(cpu->svm.allocated));
    if (!state_ready) {
      return false;
    }

	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=launch-before marker=%lu\n"),
		index, index < RTL_NUMBER_OF(svm::g_launch_stage) ? svm::g_launch_stage[index] : MAXULONG);
	bool const launched = svm::launch_vcpu(cpu);
	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=launch-after result=%d launched=%d marker=%lu\n"),
		index,
		static_cast<int>(launched),
		static_cast<int>(cpu->svm.launched),
		index < RTL_NUMBER_OF(svm::g_launch_stage) ? svm::g_launch_stage[index] : MAXULONG);
    if (!launched) {
      svm::destroy_vcpu_state(cpu);
      return false;
    }

    hypercall_input input = {};
    input.code = hypercall_ping;
    input.key = hypercall_key;
	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=ping-before\n"), index);
	unsigned __int64 const ping_result = svm::vmmcall(input);
	LOG_DEBUG(_XOR_("[YVT-VCPU] cpu=%lu stage=ping-after result=0x%llX expected=0x%llX match=%d\n"),
		index,
		ping_result,
		static_cast<unsigned __int64>(hypervisor_signature),
		static_cast<int>(ping_result == hypervisor_signature));

    return true;
  }

  if (!enable_vmx_operation(cpu)) {
    LOG_DEBUG(_XOR_("[YVT] Failed to enable VMX operation.\n"));
    return false;
  }

  LOG_DEBUG(_XOR_("[YVT] Enabled VMX operation.\n"));

  if (!enter_vmx_operation(cpu->vmxon)) {
    LOG_DEBUG(_XOR_("[YVT] Failed to enter VMX operation.\n"));
    return false;
  }

  LOG_DEBUG(_XOR_("[YVT] Entered VMX operation.\n"));

  if (!load_vmcs_pointer(cpu->vmcs)) {
    LOG_DEBUG(_XOR_("[YVT] Failed to load VMCS pointer.\n"));
    vmx_vmxoff();
    return false;
  }

  LOG_DEBUG(_XOR_("[YVT] Loaded VMCS pointer.\n"));

  prepare_external_structures(cpu);

  LOG_DEBUG(_XOR_("[YVT] Initialized external structures.\n"));

  write_vmcs_ctrl_fields(cpu);
  write_vmcs_host_fields(cpu);
  write_vmcs_guest_fields();

  LOG_DEBUG(_XOR_("[YVT] Wrote VMCS fields.\n"));

  // TODO: should these fields really be 设置 here? lol
  cpu->ctx                       = nullptr;
  cpu->queued_nmis               = 0;
  cpu->tsc_offset                = 0;
  cpu->preemption_timer          = 0;
  cpu->vm_exit_tsc_overhead      = 0;
  cpu->vm_exit_mperf_overhead    = 0;
  cpu->vm_exit_ref_tsc_overhead  = 0;

  LOG_DEBUG(_XOR_("Launching VM on VCPU#%i...\n"), KeGetCurrentProcessorIndex() + 1);

  if (!vm_launch()) {
    LOG_DEBUG(_XOR_("[YVT] VMLAUNCH failed. Instruction error = %lli.\n"),
      vmx_vmread(VMCS_VM_INSTRUCTION_ERROR));

    vmx_vmxoff();
    return false;
  }

  LOG_DEBUG(_XOR_("[YVT] Launched VM on VCPU#%i.\n"), KeGetCurrentProcessorIndex() + 1);

  hypercall_input input;
  input.code = hypercall_ping;
  input.key  = hypercall_key;

  if (vmx_vmcall(input) == hypervisor_signature)
    LOG_DEBUG(_XOR_("[YVT] Successfully pinged the hypervisor.\n"));

  cpu->vm_exit_tsc_overhead      = measure_vm_exit_tsc_overhead();
  cpu->vm_exit_mperf_overhead    = measure_vm_exit_mperf_overhead();
  cpu->vm_exit_ref_tsc_overhead  = measure_vm_exit_ref_tsc_overhead();

  LOG_DEBUG(_XOR_("[YVT] Measured VM-exit overhead (TSC = %zi).\n"),
    cpu->vm_exit_tsc_overhead);
  LOG_DEBUG(_XOR_("[YVT] Measured VM-exit overhead (MPERF = %zi).\n"),
    cpu->vm_exit_mperf_overhead);
  LOG_DEBUG(_XOR_("[YVT] Measured VM-exit overhead (CPU_CLK_UNHALTED.REF_TSC = %zi).\n"),
    cpu->vm_exit_ref_tsc_overhead);

  return true;
}

} // namespace hv

