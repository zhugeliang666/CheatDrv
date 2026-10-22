#include "exit-handlers.h"
#include <system_error>

#include "guest-context.h"
#include "exception-routines.h"
#include "introspection.h"
#include "hypercalls.h"
#include "vcpu.h"
#include "vmx.h"
#include "logger.h"
#include "hv.h"
#include "ept-probe.h"
#include "debug-watch.h"
#include "gamecommon/game.h"
#include "../xorstr.h"

namespace hv {

#pragma code_seg(".vm")

void emulate_cpuid(vcpu* const cpu) {
  auto const ctx = cpu->ctx;
  bool isPt = false;
  if (ctx->eax == CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS) {

      isPt = true;
  }

  int regs[4];

  // CPUID 0x40000000-0x4FFFFFFF: hypervisor info leaves.
  // We impersonate Microsoft Hv (Hyper-V) 鈥 anti-cheat must whitelist Hyper-V
  // because Win11 has it on by default for VBS/HVCI/WSL2. Returning native
  // GenuineIntel here would be obvious forgery; returning all zeros looks
  // suspicious; returning our own brand gets blacklisted on first encounter.
  // Hv signature gives us the broadest compatibility.
  if (ctx->eax >= 0x40000000 && ctx->eax <= 0x4FFFFFFF) {
      switch (ctx->eax) {
      case 0x40000000:
          // Max leaf + "Microsoft Hv" vendor signature
          regs[0] = 0x40000006;        // EAX = max hv leaf
          regs[1] = 0x7263694D;        // EBX = "Micr"
          regs[2] = 0x666F736F;        // ECX = "osof"
          regs[3] = 0x76482074;        // EDX = "t Hv"
          break;
      case 0x40000001:
          // Hypervisor interface signature: "Hv#1"
          regs[0] = 0x31237648;        // "Hv#1"
          regs[1] = 0;
          regs[2] = 0;
          regs[3] = 0;
          break;
      case 0x40000002:
          // Hypervisor system identity (build/version) 鈥 minimal plausible.
          regs[0] = 0x00001bbc;        // build 7100
          regs[1] = 0x00060001;        // major.minor 6.1
          regs[2] = 0;                 // service pack
          regs[3] = 0;                 // service branch
          break;
      case 0x40000003:
          // Hypervisor feature identification 鈥 advertise nothing privileged.
          regs[0] = 0;
          regs[1] = 0;
          regs[2] = 0;
          regs[3] = 0;
          break;
      case 0x40000004:
      case 0x40000005:
      case 0x40000006:
      default:
          // Implementation recommendations / hardware features / etc.
          regs[0] = regs[1] = regs[2] = regs[3] = 0;
          break;
      }
  }
  else
  {

      __cpuidex(regs, ctx->eax, ctx->ecx);

      // CPUID(1).ECX bit31 = hypervisor present flag. Pass-through (we ARE
      // a hypervisor 鈥 clearing it would conflict with the 0x40000000 "Hv"
      // signature we report above and trip "lying hypervisor" heuristics).

      // CPUID(7, 0).EBX bit25 = Intel Processor Trace capability. Hide it so
      // anti-cheat won't try to enable PT (we trap RTIT_CTL writes anyway,
      // but advertising PT support + silently dropping writes is detectable).
      // Pair: vt/exit-handlers.cpp WRMSR trap on IA32_RTIT_CTL/DEBUGCTL,
      //       vt/vcpu.cpp VMCS_GUEST_RTIT_CTL = 0 each vm-entry.
      if (ctx->eax == 0x07 && ctx->ecx == 0) {
          regs[1] &= ~(1u << 25);
      }

      // CPUID(0x14): Intel PT enumeration leaf. If anti-cheat queries this
      // anyway (some bypass the EBX[25] capability check), report all-zero
      // so PT looks completely unsupported rather than partially detectable.
      if (ctx->eax == 0x14) {
          regs[0] = regs[1] = regs[2] = regs[3] = 0;
      }
      if (ctx->eax == 0x01) {
          regs[2] &= ~CPUID_FEATURE_INFORMATION_ECX_VIRTUAL_MACHINE_EXTENSIONS_FLAG;
      }
      if (ctx->eax == 0x80000001) {
          regs[2] &= ~(1 << 2);
      }
  }

  //if (ctx->eax == 0x01) {
  //    regs[2] = regs[2] & (~CPUID_FEATURE_INFORMATION_ECX_VIRTUAL_MACHINE_EXTENSIONS_FLAG);
  //}
  //AuthenticAMD
  //GenuineIntel

  //if (ctx->eax == 0x0) {

  //    regs[1] = 'Auth';
  //    regs[2] = 'cAMD';
  //    regs[3] = 'enti';

  //    //ctx->rbx = 0x41757468;
  //    //ctx->rcx = 0x656e7469;
  //    //ctx->rdx = 0x63414d44;

  //}



  ctx->rax = regs[0];
  ctx->rbx = regs[1];
  ctx->rcx = regs[2];
  ctx->rdx = regs[3];






  cpu->hide_vm_exit_overhead = true;

  skip_instruction();
}

void emulate_rdmsr(vcpu* const cpu) {

  //if (cpu->ctx->ecx == IA32_FEATURE_CONTROL ) {
  //  // return the fake guest FEATURE_CONTROL MSR
  //  cpu->ctx->rax = cpu->cached.guest_feature_control.flags & 0xFFFF'FFFF;
  //  cpu->ctx->rdx = cpu->cached.guest_feature_control.flags >> 32;

  //  cpu->hide_vm_exit_overhead = true;



  //  

  //  skip_instruction();
  //  return;
  //}


  auto const msr = cpu->ctx->ecx;
  auto const value = (cpu->ctx->rdx << 32) | cpu->ctx->eax;
  if (msr == IA32_FEATURE_CONTROL) {
    cpu->ctx->rax = cpu->cached.guest_feature_control.flags & 0xFFFF'FFFF;
    cpu->ctx->rdx = cpu->cached.guest_feature_control.flags >> 32;
    cpu->hide_vm_exit_overhead = true;
    skip_instruction();
    return;
  }

  // PT MSR read trap. We never enable Intel PT for the guest
  // (WRMSR trapped below, and VMCS_GUEST_RTIT_CTL forced to 0 on every
  // vm-entry). Return 0 on read so anti-cheat sees a stable "disabled" state.
  //
  // NOTE: IA32_DEBUGCTL is NOT trapped on read 鈥 Windows kernel actively
  // reads/writes it (KiDebugRoutine BTF bit, context save/restore). Lying
  // about it causes kernel state-machine corruption. Write trap below still
  // prevents the guest from enabling LBR/BTS, and VMCS clears those bits on
  // vm-entry anyway.
  if (msr == IA32_RTIT_CTL    || msr == IA32_RTIT_STATUS ||
      msr == IA32_RTIT_OUTPUT_BASE || msr == IA32_RTIT_OUTPUT_MASK_PTRS ||
      msr == IA32_RTIT_CR3_MATCH) {
      cpu->ctx->rax = 0;
      cpu->ctx->rdx = 0;
      cpu->hide_vm_exit_overhead = true;
      skip_instruction();
      return;
  }

  //if (msr == IA32_RTIT_CTL || msr == IA32_DEBUGCTL) {

  //    cpu->hide_vm_exit_overhead = true;
  //    cpu->ctx->rax = 0;
  //    cpu->ctx->rdx = 0;
  //    skip_instruction();
  //    return;

  //}

  // Perfmon MSR interception disabled 鈥 combined with TSC offsetting it caused
  // DWM black screen. To re-enable safely: do not zero fake_perfmon_base_tsc
  // on first read mid-frame, and verify DWM's perfmon usage pattern.
  //if (msr == IA32_FIXED_CTR2 || msr == IA32_APERF || msr == IA32_MPERF) {
  //  auto const masked_tsc = __rdtsc() + cpu->tsc_offset;
  //  if (cpu->fake_perfmon_base_tsc == 0)
  //    cpu->fake_perfmon_base_tsc = masked_tsc;
  //  auto const synth = masked_tsc - cpu->fake_perfmon_base_tsc;
  //  cpu->ctx->rax = synth & 0xFFFFFFFF;
  //  cpu->ctx->rdx = synth >> 32;
  //  cpu->hide_vm_exit_overhead = true;
  //  skip_instruction();
  //  return;
  //}


  host_exception_info e;

  // the guest could be reading from MSRs that are outside of the MSR bitmap
  // range. refer to https://www.unknowncheats.me/forum/3425463-post15.html
  auto  msr_value = rdmsr_safe(e, cpu->ctx->ecx);

  if (e.exception_occurred) {
    // reflect the exception back into the guest
    inject_hw_exception(general_protection, 0);
    return;
  }


  if (msr == IA32_VMX_EPT_VPID_CAP) {


      ia32_vmx_ept_vpid_cap_register ept_cap = { 0 };
      ept_cap.flags = msr_value;
      ept_cap.invept = 0;
      ept_cap.invept_all_contexts = 0;
      msr_value = ept_cap.flags;

  }



  cpu->ctx->rax = msr_value & 0xFFFF'FFFF;
  cpu->ctx->rdx = msr_value >> 32;

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
}

void emulate_wrmsr(vcpu* const cpu) {
  auto const msr = cpu->ctx->ecx;
  auto const value = (cpu->ctx->rdx << 32) | cpu->ctx->eax;

  if (msr == IA32_RTIT_CTL || msr==IA32_DEBUGCTL) {

      cpu->hide_vm_exit_overhead = true;
      skip_instruction();
      return;

  }

  // let the guest write to the MSRs
  host_exception_info e;
  wrmsr_safe(e, msr, value);

  if (e.exception_occurred) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // we need to make sure to update EPT memory types if the guest
  // modifies any of the MTRR registers
  if (msr == IA32_MTRR_DEF_TYPE     || msr == IA32_MTRR_FIX64K_00000 ||
      msr == IA32_MTRR_FIX16K_80000 || msr == IA32_MTRR_FIX16K_A0000 ||
     (msr >= IA32_MTRR_FIX4K_C0000  && msr <= IA32_MTRR_FIX4K_F8000) ||
     (msr >= IA32_MTRR_PHYSBASE0    && msr <= IA32_MTRR_PHYSBASE0 + 511)) {
    // update EPT memory types
    if (!read_effective_guest_cr0().cache_disable)
      update_ept_memory_type(cpu->ept);

    vmx_invept(invept_all_context, {});
  }


  

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
  return;
}

void emulate_getsec(vcpu*) {
  // inject a #GP(0) since SMX is disabled in the IA32_FEATURE_CONTROL MSR
  inject_hw_exception(general_protection, 0);
}

void emulate_invlpg(vcpu* cpu) {



    invvpid_descriptor desc = { 0 };
    desc.vpid = cpu->vpid;
    desc.linear_address = vmx_vmread(VMCS_EXIT_QUALIFICATION);

    vmx_invvpid(invvpid_type::invvpid_individual_address, desc);

    skip_instruction();

    return;
}

void emulate_invd(vcpu*) {
  // TODO: properly implement INVD (can probably make a very small stub
  //       that flushes specific cacheline entries prior to executing INVD)

   

    vmx_segment_access_rights ss = { 0 };
     ss.flags = static_cast<ULONG>(vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS));

     if (ss.descriptor_privilege_level == 0) {

         AsmInvd();

         skip_instruction();
         return;
     }

  inject_hw_exception(general_protection, 0);
}

void emulate_xsetbv(vcpu* const cpu) {
  // 3.2.6

  // CR4.OSXSAVE must be 1
  if (!read_effective_guest_cr4().os_xsave) {
    inject_hw_exception(invalid_opcode);
    return;
  }

  xcr0 new_xcr0;
  new_xcr0.flags = (cpu->ctx->rdx << 32) | cpu->ctx->eax;

  // only XCR0 is supported
  if (cpu->ctx->ecx != 0) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if trying to set an unsupported bit
  if (new_xcr0.flags & cpu->cached.xcr0_unsupported_mask) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if clearing XCR0.X87
  if (!new_xcr0.x87) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if XCR0.AVX is 1 while XCRO.SSE is cleared
  if (new_xcr0.avx && !new_xcr0.sse) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if XCR0.AVX is clear and XCR0.opmask, XCR0.ZMM_Hi256, or XCR0.Hi16_ZMM is set
  if (!new_xcr0.avx && (new_xcr0.opmask || new_xcr0.zmm_hi256 || new_xcr0.zmm_hi16)) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if setting XCR0.BNDREG or XCR0.BNDCSR while not setting the other
  if (new_xcr0.bndreg != new_xcr0.bndcsr) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if setting XCR0.opmask, XCR0.ZMM_Hi256, or XCR0.Hi16_ZMM while not setting all of them
  if (new_xcr0.opmask != new_xcr0.zmm_hi256 || new_xcr0.zmm_hi256 != new_xcr0.zmm_hi16) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  host_exception_info e;
  xsetbv_safe(e, cpu->ctx->ecx, new_xcr0.flags);

  if (e.exception_occurred) {
    // TODO: assert that it was a #GP(0) that occurred, although I really
    //       doubt that any other exception could happen (according to manual).
    inject_hw_exception(general_protection, 0);
    return;
  }

  HV_LOG_VERBOSE(_XOR_("Wrote %p to XCR0."), new_xcr0.flags);

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
}

void emulate_vmxon(vcpu*) {
  // usually a #UD doesn't trigger a vm-exit, but in this case it is possible
  // that CR4.VMXE is 1 while guest shadow CR4.VMXE is 0.
  if (!read_effective_guest_cr4().vmx_enable) {
    inject_hw_exception(invalid_opcode);
    return;
  }

  // we are spoofing the value of the IA32_FEATURE_CONTROL MSR in
  // order to convince the guest that VMX has been disabled by BIOS.
  inject_hw_exception(general_protection, 0);
}

void emulate_vmcall(vcpu* const cpu) {

    if (hv::return_old_func(cpu))
        return;


    if (hv::vmcall_hook_dispatch(cpu))
        return;





    uint64_t cr3 = vmx_vmread(VMCS_GUEST_CR3);
    uint64_t rip = vmx_vmread(VMCS_GUEST_RIP);



    if (hv::is_vmcall_blank_rip(rip)) {
        return;
    }



    vcpu_bp_hook_node* node = nullptr;


    node = find_bp_hook(cpu->ept, cr3, rip);

    if (node)
    {


        if(node->is_cr3_monitor_hook)
        {
            vmx_vmwrite(VMCS_GUEST_CR3, g_ghv->g_cr3_monitor.fake_cr3.flags);

            auto process = (UINT64)current_guest_eprocess();
            auto thread = (UINT64)current_guest_ethread();
            add_cr3_monitor_thread(process, thread);


            //璁＄畻椤佃〃椤圭殑鍦板潃
            auto fake_va  = node->fake_guest_va;
            auto pml4e_index = (fake_va >> 39) & 0x1ff;
            auto pdpte_index = (fake_va >> 30) & 0x1ff;
            auto pde_index = (fake_va >> 21) & 0x1ff;
            auto pte_index = (fake_va >> 12) & 0x1ff;

            auto fake_cr3_va = (pml4e_64*)(host_physical_memory_base + (g_ghv->g_cr3_monitor.fake_cr3.address_of_page_directory << 12));
            auto fake_pml4e = fake_cr3_va[pml4e_index];
            auto fake_pdpte_va = (pdpte_64*)(host_physical_memory_base + (fake_pml4e.page_frame_number << 12));
            auto fake_pdpte  = fake_pdpte_va[pdpte_index];
            auto fake_pdte_va = (pde_64*)(host_physical_memory_base + (fake_pdpte.page_frame_number << 12));
            auto fake_pde = fake_pdte_va[pde_index];
            auto fake_pte_va = (pte_64*)(host_physical_memory_base + (fake_pde.page_frame_number << 12));
            auto fake_pte = fake_pte_va[pte_index];
            auto fake_pfn = fake_pte.page_frame_number;
            auto fake_ept_hook_node = find_ept_hook(cpu->ept, fake_pfn);
            if(fake_ept_hook_node)
            {
                auto pte = get_ept_pte(cpu->ept, fake_pfn << 12, false);
                if (pte)
					pte->page_frame_number = fake_ept_hook_node->exec_pfn;
            }

            vmx_invept(invept_all_context, {});


        }

        vmx_vmwrite(VMCS_GUEST_RIP, node->fake_guest_va);
        return;
    }




  


  auto const code = cpu->ctx->rax & 0xFF;
  auto const key  = cpu->ctx->rax >> 8;
  do {
  // validate the hypercall key
      if (key != hypercall_key) {
        HV_LOG_VERBOSE(_XOR_("Invalid VMCALL key. RIP=%p."), vmx_vmread(VMCS_GUEST_RIP));
        // Resident payload freetest parity: do not allow gamevt-range bad-key
        // VMCALLs to bypass key validation and fall into legacy dispatch.
        vmx_segment_access_rights ss = { 0 };
        ss.flags = static_cast<ULONG>(vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS));
        cpu->hide_vm_exit_overhead = true;
        if (ss.descriptor_privilege_level > 0) {
          inject_hw_exception(invalid_opcode);
          return;
        }
        cpu->ctx->rax = 0x0002;
        skip_instruction();
        return;
      }
  } while (0);
  // handle the hypercall
  switch (code) {
  case hypercall_ping:                 hc::ping(cpu);                 return;
  case hypercall_test:                 hc::test(cpu);                 return;
  case hypercall_unload:               hc::unload(cpu);               return;
  case hypercall_read_phys_mem:        hc::read_phys_mem(cpu);        return;
  case hypercall_write_phys_mem:       hc::write_phys_mem(cpu);       return;
  case hypercall_read_virt_mem:        hc::read_virt_mem(cpu);        return;
  case hypercall_write_virt_mem:       hc::write_virt_mem(cpu);       return;
  case hypercall_query_process_cr3:    hc::query_process_cr3(cpu);    return;
  case hypercall_install_ept_hook:     hc::install_ept_hook(cpu);     return;
  case hypercall_remove_ept_hook:      hc::remove_ept_hook(cpu);      return;
  case hypercall_flush_logs:           hc::flush_logs(cpu);           return;
  case hypercall_get_physical_address: hc::get_physical_address(cpu); return;
  case hypercall_hide_physical_page:   hc::hide_physical_page(cpu);   return;
  case hypercall_unhide_physical_page: hc::unhide_physical_page(cpu); return;
  case hypercall_get_hv_base:          hc::get_hv_base(cpu);          return;
  case hypercall_install_mmr:          hc::install_mmr(cpu);          return;
  case hypercall_remove_mmr:           hc::remove_mmr(cpu);           return;
  case hypercall_remove_all_mmrs:      hc::remove_all_mmrs(cpu);      return;
  case hypercall_install_breakpoint_hook:
      hc::install_breakpoint_hook(cpu);
      return;
  case hypercall_remove_breakpoint_hook:
      hc::remove_breakpoint_hook(cpu);
      return;

  case hypercall_add_protect_process:
      hc::add_protect_process(cpu);
      return;

  case hypercall_remove_protect_process:
      hc::remove_protect_process(cpu);
      return;

  case hypercall_add_cr3_monitor:
      hc::add_cr3_monitor(cpu);
      return;
  case hypercall_remove_cr3_monitor:
      hc::remove_cr3_monitor(cpu);
      return;
  case hypercall_open_cr3_monitor_check_thread:
      hc::enable_cr3_monitor_check_thread(cpu);
      return;
  case hypercall_close_cr3_monitor_check_thread:
      hc::disable_cr3_monitor_check_thread(cpu);
      return;

  case hypercall_end_cr3_monitor_hook:
	  hc::cr3_monitor_jmp(cpu);
      return;

  case  hypercall_add_cr3_monitor_thread:
      hc::add_cr3_monitor_thread_s(cpu);
      return;
  case    hypercall_remove_cr3_monitor_thread:
      hc::remove_cr3_monitor_thread_s(cpu);
      return;

    case hypercall_active_cr3_monitor_data_region:
		hc::active_cr3_monitor_data_region(cpu);
		return;

  case     hypercall_open_cr3_monitor_check_rip:
      hc::enable_check_monitor_check_rip(cpu);
      return;
  case  hypercall_close_cr3_monitor_check_rip:
      hc::disable_check_monitor_check_rip(cpu);
      return;
  case hypercall_add_cr3_map:
      hc::add_cr3_map(cpu);
      return;
  case hypercall_add_cr3_map_by_user_mode:
      	hc::add_cr3_map_by_user_mode(cpu);
	  return;
  case hypercall_remove_cr3_map:
      hc::remove_cr3_map(cpu);
      return;
  case hypercall_get_info:
      hc::get_src_cr3(cpu);
      return;
  case hypercall_start_get_game_cr3:
	  hc::start_get_game_cr3(cpu);
      return;
  case hypercall_start_get_game_cr3_by_pid:
      hc::start_get_game_cr3_by_pid(cpu);
	  return;

  case hypercall_get_game_path:
      hc::get_game_path(cpu);
      return;
  case hypercall_get_game_module_base:
      hc::get_game_module_info(cpu);
      return;
  case hypercall_hide_hv:
      hc::hide_hv(cpu);
      return;
  case hypercall_unhide_hv:
      hc::unhide_hv(cpu);
	  return;

  case hypercall_add_real_cr3:
      hc::add_real_cr3(cpu);
	  return;
   case hypercall_read_game_mem:
      hc::read_game_memory(cpu);
      return;
   case hypercall_write_game_mem:
      hc::write_game_memory(cpu);
      return;
   case hypercall_hide_cache_info:
       
       hc::hide_cache_info(cpu);

       return;

   case hypercall_unhide_cache_info:
       hc::unhide_cache_info(cpu);
       return;

    case hypercall_save_gamevt_image_base:
		hc::save_gamevt_image_base(cpu);
		return;

    case hypercall_get_gamevt_image_base:
        hc::get_gamevt_image_base(cpu);
        return;
    case hypercall_call_function:
	    hc::call_function(cpu);
	    return;

    case hypercall_add_vmcall_hook:
        hc::add_vmcall_hook(cpu);
        return;
    case hypercall_remove_vmcall_hook:
        hc::remove_vmcall_hook(cpu);
        return;

    case hypercall_enable_vmcall_hook:
        hc::enable_vmcall_hook(cpu);
        return;
    case hypercall_disable_vmcall_hook:
        hc::disable_vmcall_hook(cpu);
        return;

    // Host-managed EPT hook (see vt/ept-hook.cpp)
    case hypercall_eh_install:                hc::vmcall_eh_install(cpu);                return;
    case hypercall_eh_remove:                 hc::vmcall_eh_remove(cpu);                 return;
    case hypercall_eh_enable:                 hc::vmcall_eh_enable(cpu);                 return;
    case hypercall_eh_disable:                hc::vmcall_eh_disable(cpu);                return;
    case hypercall_eh_write:                  hc::vmcall_eh_write(cpu);                  return;
    case hypercall_eh_get_va:                 hc::vmcall_eh_get_va(cpu);                 return;
    case hypercall_eh_remove_all_by_process:  hc::vmcall_eh_remove_all_by_process(cpu);  return;

    // Host-managed VTCall hook (see vt/vtcall-hook.cpp)
    case hypercall_vh_install:                hc::vmcall_vh_install(cpu);                return;
    case hypercall_vh_install_ret_abs:        hc::vmcall_vh_install_ret_abs(cpu);        return;
    case hypercall_vh_enable:                 hc::vmcall_vh_enable(cpu);                 return;
    case hypercall_vh_disable:                hc::vmcall_vh_disable(cpu);                return;
    case hypercall_vh_remove:                 hc::vmcall_vh_remove(cpu);                 return;
    case hypercall_vh_uninit:                 hc::vmcall_vh_uninit(cpu);                 return;
    case hypercall_vh_find_blank:             hc::vmcall_vh_find_blank(cpu);             return;
    case hypercall_vh_find_blank_page:        hc::vmcall_vh_find_blank_page(cpu);        return;
    case hypercall_vh_init_tramp_pool:        cpu->ctx->rax = 0; skip_instruction();     return;
    case hypercall_vh_tramp_add_page:         hc::vmcall_vh_tramp_add_page(cpu);         return;
    case hypercall_vh_tramp_add_slot:         hc::vmcall_vh_tramp_add_slot(cpu);         return;
    case hypercall_vh_tramp_set_ready:        hc::vmcall_vh_tramp_set_ready(cpu);        return;
    case hypercall_prepare_self_hide_add:     hc::prepare_self_hide_add(cpu);            return;
    case hypercall_prepare_self_hide_commit:  hc::prepare_self_hide_commit(cpu);         return;
    case hypercall_set_affinity_lock:         hc::set_affinity_lock(cpu);                return;
    case hypercall_get_pool_blocks:           hc::get_pool_blocks(cpu);                  return;
    case hypercall_get_hide_diag:             hc::get_hide_diag(cpu);                    return;
    case hypercall_hide_pfn_list:             hc::hide_pfn_list(cpu);                    return;
    case hypercall_ept_probe_install:         hc::ept_probe_install(cpu);                return;
    case hypercall_ept_probe_remove:          hc::ept_probe_remove(cpu);                 return;
    case hypercall_ept_probe_get_hits:        hc::ept_probe_get_hits(cpu);               return;
    case hypercall_ept_probe_clear_hits:      hc::ept_probe_clear_hits(cpu);             return;
    case hypercall_get_resident_hv_diag:      hc::get_resident_hv_diag(cpu);             return;
    case hypercall_set_host_rsp:              hc::set_host_rsp(cpu);                     return;
    case hypercall_map_host_range:            hc::map_host_range(cpu);                   return;
    case hypercall_set_host_rip:              hc::set_host_rip(cpu);                     return;
    case hypercall_set_keep_hv_on_unload:     hc::set_keep_hv_on_unload(cpu);            return;
    case hypercall_dbg_dispatch:              hc::dbg_dispatch(cpu);                     return;
    case hypercall_get_payload_status:
    case hypercall_set_payload_mode:
    case hypercall_payload_ping:
        // These are payload-owned after bridge handoff. If they ever reach the
        // legacy handler, fail closed and skip instead of injecting #UD/#PF.
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
  }

  HV_LOG_VERBOSE(_XOR_("Unhandled VMCALL. RIP=%p."), vmx_vmread(VMCS_GUEST_RIP));
  cpu->ctx->rax = 0;
  skip_instruction();
  return;
}

void handle_vmx_preemption(vcpu*) {
  // do nothing.
}

void emulate_mov_to_cr0(vcpu* const cpu, uint64_t const gpr) {
  // 2.4.3
  // 3.2.5
  // 3.4.10.1
  // 3.26.3.2.1

  cr0 new_cr0;
  new_cr0.flags = read_guest_gpr(cpu->ctx, gpr);

  auto const curr_cr0 = read_effective_guest_cr0();
  auto const curr_cr4 = read_effective_guest_cr4();

  // CR0[15:6] is always 0
  new_cr0.reserved1 = 0;

  // CR0[17] is always 0
  new_cr0.reserved2 = 0;

  // CR0[28:19] is always 0
  new_cr0.reserved3 = 0;

  // CR0.ET is always 1
  new_cr0.extension_type = 1;

  // #GP(0) if setting any reserved bits in CR0[63:32]
  if (new_cr0.reserved4) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if setting CR0.PG while CR0.PE is clear
  if (new_cr0.paging_enable && !new_cr0.protection_enable) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if invalid bit combination
  if (!new_cr0.cache_disable && new_cr0.not_write_through) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if an attempt is made to clear CR0.PG
  if (!new_cr0.paging_enable) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if an attempt is made to clear CR0.WP while CR4.CET is set
  if (!new_cr0.write_protect && curr_cr4.control_flow_enforcement_enable) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // the guest tried to modify CR0.CD or CR0.NW, which must be updated manually
  if (new_cr0.cache_disable     != curr_cr0.cache_disable ||
      new_cr0.not_write_through != curr_cr0.not_write_through) {
    // TODO: should we care about NW?
    if (new_cr0.cache_disable)
      set_ept_memory_type(cpu->ept, MEMORY_TYPE_UNCACHEABLE);
    else
      update_ept_memory_type(cpu->ept);

    vmx_invept(invept_all_context, {});
  }

  HV_LOG_VERBOSE(_XOR_("Writing %p to CR0."), new_cr0.flags);

  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, new_cr0.flags);

  // make sure to account for VMX reserved bits when setting the real CR0
  new_cr0.flags |= cpu->cached.vmx_cr0_fixed0;
  new_cr0.flags &= cpu->cached.vmx_cr0_fixed1;

  vmx_vmwrite(VMCS_GUEST_CR0, new_cr0.flags);

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
}



void emulate_mov_to_cr3(vcpu* const cpu, uint64_t const gpr) {

    cr3 new_cr3;
    new_cr3.flags = read_guest_gpr(cpu->ctx, gpr);

    auto const curr_cr4 = read_effective_guest_cr4();

    bool invalidate_tlb = true;

    // 3.4.10.4.1
    if (curr_cr4.pcid_enable && (new_cr3.flags & (1ull << 63))) {
        invalidate_tlb = false;
        new_cr3.flags &= ~(1ull << 63);
    }

    // a mask where bits [63:MAXPHYSADDR] are set to 1
    auto const reserved_mask = ~((1ull << cpu->cached.max_phys_addr) - 1);

    // 3.2.5
    if (new_cr3.flags & reserved_mask) {
        inject_hw_exception(general_protection, 0);
        return;
    }

    // 3.28.4.3.3
    if (invalidate_tlb) {
        invvpid_descriptor desc;
        desc.linear_address = 0;
        desc.reserved1 = 0;
        desc.reserved2 = 0;
        desc.vpid = cpu->vpid;
        vmx_invvpid(invvpid_single_context_retaining_globals, desc);

    }

    // it is now safe to write the new guest cr3
    vmx_vmwrite(VMCS_GUEST_CR3, new_cr3.flags);

    skip_instruction();

}

void emulate_mov_to_cr4(vcpu* const cpu, uint64_t const gpr) {
  // 2.4.3
  // 2.6.2.1
  // 3.2.5
  // 3.4.10.1
  // 3.4.10.4.1

  cr4 new_cr4;
  new_cr4.flags = read_guest_gpr(cpu->ctx, gpr);

  cr3 curr_cr3;
  curr_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);

  auto const curr_cr0 = read_effective_guest_cr0();
  auto const curr_cr4 = read_effective_guest_cr4();

  // #GP(0) if an attempt is made to set CR4.SMXE when SMX is not supported
  if (!cpu->cached.cpuid_01.cpuid_feature_information_ecx.safer_mode_extensions
      && new_cr4.smx_enable) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if an attempt is made to write a 1 to any reserved bits
  if (new_cr4.reserved1 || new_cr4.reserved2) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if an attempt is made to change CR4.PCIDE from 0 to 1 while CR3[11:0] != 000H
  if ((new_cr4.pcid_enable && !curr_cr4.pcid_enable) && (curr_cr3.flags & 0xFFF)) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if CR4.PAE is cleared
  if (!new_cr4.physical_address_extension) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if CR4.LA57 is enabled
  if (new_cr4.linear_addresses_57_bit) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if CR4.CET == 1 and CR0.WP == 0
  if (new_cr4.control_flow_enforcement_enable && !curr_cr0.write_protect) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // invalidate TLB entries if required
  if (new_cr4.page_global_enable != curr_cr4.page_global_enable ||
      !new_cr4.pcid_enable && curr_cr4.pcid_enable ||
      new_cr4.smep_enable && !curr_cr4.smep_enable) {
    invvpid_descriptor desc;
    desc.linear_address = 0;
    desc.reserved1      = 0;
    desc.reserved2      = 0;
    desc.vpid           = cpu->vpid/*vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER)*/;
    vmx_invvpid(invvpid_single_context, desc);
  }
  
  //HV_LOG_VERBOSE(_XOR_("Writing %p to CR4."), new_cr4.flags);

  vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, new_cr4.flags);

  // make sure to account for VMX reserved bits when setting the real CR4
  new_cr4.flags |= cpu->cached.vmx_cr4_fixed0;
  new_cr4.flags &= cpu->cached.vmx_cr4_fixed1;

  vmx_vmwrite(VMCS_GUEST_CR4, new_cr4.flags);

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
}

void emulate_mov_from_cr3(vcpu* const cpu, uint64_t const gpr) {

    cr3 old_cr3;
    old_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);

  write_guest_gpr(cpu->ctx, gpr,old_cr3.flags );

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
}

void emulate_clts(vcpu* const cpu) {
  // clear CR0.TS in the read shadow
  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW,
    vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW) & ~CR0_TASK_SWITCHED_FLAG);

  // clear CR0.TS in the real CR0 register
  vmx_vmwrite(VMCS_GUEST_CR0,
    vmx_vmread(VMCS_GUEST_CR0) & ~CR0_TASK_SWITCHED_FLAG);

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
}

void emulate_lmsw(vcpu* const cpu, uint16_t const value) {
  // 3.25.1.3

  cr0 new_cr0;
  new_cr0.flags = value;

  // update the guest CR0 read shadow
  cr0 shadow_cr0;
  shadow_cr0.flags = vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW);
  shadow_cr0.protection_enable   = new_cr0.protection_enable;
  shadow_cr0.monitor_coprocessor = new_cr0.monitor_coprocessor;
  shadow_cr0.emulate_fpu         = new_cr0.emulate_fpu;
  shadow_cr0.task_switched       = new_cr0.task_switched;
  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow_cr0.flags);

  // update the real guest CR0.
  // we don't have to worry about VMX reserved bits since CR0.PE (the only
  // reserved bit) can't be cleared to 0 by the LMSW instruction while in
  // protected mode.
  cr0 real_cr0;
  real_cr0.flags = vmx_vmread(VMCS_GUEST_CR0);
  real_cr0.protection_enable   = new_cr0.protection_enable;
  real_cr0.monitor_coprocessor = new_cr0.monitor_coprocessor;
  real_cr0.emulate_fpu         = new_cr0.emulate_fpu;
  real_cr0.task_switched       = new_cr0.task_switched;
  vmx_vmwrite(VMCS_GUEST_CR0, real_cr0.flags);

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
}

void handle_mov_cr(vcpu* const cpu) {
  vmx_exit_qualification_mov_cr qualification;
  qualification.flags = vmx_vmread(VMCS_EXIT_QUALIFICATION);

  switch (qualification.access_type) {
  // MOV CRn, XXX
  case VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR:
    switch (qualification.control_register) {
    case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
      emulate_mov_to_cr0(cpu, qualification.general_purpose_register);
      break;
    case VMX_EXIT_QUALIFICATION_REGISTER_CR3:
      emulate_mov_to_cr3(cpu, qualification.general_purpose_register);
      break;
    case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
      emulate_mov_to_cr4(cpu, qualification.general_purpose_register);
      break;
    }
    break;
  // MOV XXX, CRn
  case VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR:
    // TODO: assert that we're accessing CR3 (and not CR8)
    emulate_mov_from_cr3(cpu, qualification.general_purpose_register);
    break;
  // CLTS
  case VMX_EXIT_QUALIFICATION_ACCESS_CLTS:
    emulate_clts(cpu);
    break;
  // LMSW XXX
  case VMX_EXIT_QUALIFICATION_ACCESS_LMSW:
    emulate_lmsw(cpu, qualification.lmsw_source_data);
    break;
  }
}

void handle_nmi_window(vcpu* const cpu) {
  //--cpu->queued_nmis;

  // inject the NMI into the guest
  inject_nmi();


  auto ctrl = read_ctrl_proc_based();
  ctrl.nmi_window_exiting = 0;
  write_ctrl_proc_based(ctrl);

  //if (cpu->queued_nmis == 0) {
  //  // disable NMI-window exiting since we have no more NMIs to inject
  //  auto ctrl = read_ctrl_proc_based();
  //  ctrl.nmi_window_exiting = 0;
  //  write_ctrl_proc_based(ctrl);
  //}
  //
  //// there is the possibility that a host NMI occurred right before we
  //// disabled NMI-window exiting. make sure to re-enable it if this is the case.
  //if (cpu->queued_nmis > 0) {
  //  auto ctrl = read_ctrl_proc_based();
  //  ctrl.nmi_window_exiting = 1;
  //  write_ctrl_proc_based(ctrl);
  //}
}

void handle_exception_or_nmi(vcpu* const cpu) {
  // enqueue an NMI to be injected into the guest later on


    vmexit_interrupt_information interrupt_information;
    interrupt_information.flags = (uint32_t)vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION);

    vmentry_interrupt_information new_interrupt_information = {};

    switch (interrupt_information.vector)
    {

    case exception_vector::breakpoint:
    {
        // DIAG: count all #BP vmexits and record last RIP.
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_bp_total);
        auto const bp_rip = vmx_vmread(VMCS_GUEST_RIP);
        g_ghv->diag_bp_last_rip = bp_rip;

        // 0xCC trampoline match: VMCS_GUEST_RIP at INT3 vm-exit points AT
        // the 0xCC byte (not past it). slot.bp_rip is precomputed to that
        // exact address; on match we rewrite RIP to slot's target_resume so
        // the guest continues right after the hooked instruction in the real
        // function (NOT in our exec_page).
        {
            auto& pool = g_ghv->tramp_pool;
            // Lock-free read: pool slots only mutate during install/remove,
            // and bp_rip is unique per occupied slot. Worst case is missing
            // a freshly installed slot for one cycle, which is harmless.
            auto try_match = [&](tramp_slot* slots, uint32_t count) -> bool {
                for (uint32_t i = 0; i < count; i++) {
                    auto& s = slots[i];
                    if (s.occupied && s.bp_rip == bp_rip) {
                        vmx_vmwrite(VMCS_GUEST_RIP, s.target_resume);
                        return true;
                    }
                }
                return false;
            };
            if (try_match(pool.user_slots,   pool.user_slot_count) ||
                try_match(pool.kernel_slots, pool.kernel_slot_count)) {
                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_bp_match);
                return;
            }
        }

        // INT3 vmexit: GUEST_RIP points past the 0xCC byte. If this is hv::Call's
        // blank_memory landing site, return_old_func consumes the trap and exits.
        if (hv::return_old_func(cpu)) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_bp_match);
            return;
        }

        // Generic EPT probe: shadow exec page contains a one-byte INT3 at
        // the requested address.  On hit we snapshot registers, map the
        // original PFN for exactly one instruction via MTF, then restore the
        // shadow page.  This path is independent from hv::Call/tramp slots.
        if (hv::try_handle_ept_probe_bp(cpu)) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_bp_match);
            return;
        }

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_bp_miss);
        if (g_ghv->diag_bp_first_miss_rip == 0)
            g_ghv->diag_bp_first_miss_rip = g_ghv->diag_bp_last_rip;

        // Otherwise legit guest #BP (debugger / __debugbreak / ntdll assert) -
        // re-inject back into guest.
        // CRITICAL: Intel SDM Vol3A 24.8.3 鈥 when re-injecting INT3, the
        // interruption_type MUST be software_exception (6), NOT the
        // hardware_exception (3) that the vmexit info field reports. Using the
        // wrong type causes guest IDT delivery to corrupt and DWM hangs.
        new_interrupt_information.vector = interrupt_information.vector;
        new_interrupt_information.interruption_type = software_exception;
        new_interrupt_information.deliver_error_code = interrupt_information.error_code_valid;
        new_interrupt_information.valid = interrupt_information.valid;


        vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, vmx_vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE));
        vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, new_interrupt_information.flags);
        vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH));
        break;
    }
    case exception_vector::nmi: 
    {

        if (interrupt_information.valid) {

            //++cpu->queued_nmis;

            auto ctrl = read_ctrl_proc_based();
            ctrl.nmi_window_exiting = 1;
            write_ctrl_proc_based(ctrl);
            break;
        }

    }

    default:
        // enqueue an NMI to be injected into the guest later on
    {
        break;
    }

    }
}

void handle_vmx_instruction(vcpu*) {
  // inject #UD for every VMX instruction since we
  // don't allow the guest to ever enter VMX operation.
  inject_hw_exception(invalid_opcode);
}

void handle_ept_violation(vcpu* const cpu) {
  vmx_exit_qualification_ept_violation qualification;
  qualification.flags = vmx_vmread(VMCS_EXIT_QUALIFICATION);

  // guest physical address that caused the ept-violation
  auto const physical_address = vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS);

  auto const virtual_address = vmx_vmread(VMCS_EXIT_GUEST_LINEAR_ADDRESS);

  auto const instr_length = vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH);

  auto const guest_rip = vmx_vmread(VMCS_GUEST_RIP);

  auto const pte = get_ept_pte(cpu->ept, physical_address);


  auto const pa_pfn = physical_address & (~0xfff);

 /* for (auto const& entry : cpu->ept.mmr) {


    if (entry.size == 0 || entry.pa != pa_pfn )
          continue;



    pte->read_access = 1;
    pte->write_access = 1;
    pte->execute_access = 1;

    auto const is_relevant_mode =
        (qualification.read_access  && (entry.mode & mmr_memory_mode_r))
        || (qualification.write_access  && (entry.mode & mmr_memory_mode_w))
        || (qualification.execute_access && (entry.mode & mmr_memory_mode_x));

    if (is_relevant_mode) {

            

    }

    cpu->ept.mmr_mtf_pte = pte;
    cpu->ept.mmr_mtf_mode = entry.mode;
    cpu->ept.mmr_mtf_page_frame = pte->page_frame_number;
    enable_monitor_trap_flag();


    return;
  }*/



  // Debug EPT permission watches are intentionally separate from legacy
  // ept_hook.  Handle them before find_ept_hook(), otherwise watched pages
  // would look like "hook miss" and get injected as #GP.
  if (hv::dbg_try_handle_ept_violation(cpu, qualification, physical_address,
                                       virtual_address, guest_rip)) {
    return;
  }

  auto const hook = find_ept_hook(cpu->ept, physical_address >> 12);

  _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ept_violation_total);
  g_ghv->diag_ept_violation_last_pa  = physical_address;
  g_ghv->diag_ept_violation_last_rip = guest_rip;

  if (!hook) {
    _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ept_violation_nohook);
    HV_LOG_ERROR(_XOR_("Failed to find EPT hook. PhysAddr = %p."), physical_address);
    inject_hw_exception(general_protection, 0);
    return;
  }
  _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ept_violation_match);

  // PMO match check: did the violation fire on the page we hooked for PMO?
  {
      auto& t = g_ghv->ept_hook_table;
      t.lock.acquire();
      for (auto e = t.active_list_head; e; e = e->next) {
          if (e->orig_pfn == (physical_address >> 12)) {
              _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_ept_violation_pmo_match);
              break;
          }
      }
      t.lock.release();
  }


  auto process = current_guest_eprocess();

  auto node = find_protect_process((uint64_t)process);


  if (!hook->is_fake_page) {


      if (node)
      {
          pte->read_access = 1;
          pte->write_access = 1;
          pte->execute_access = 1;
          pte->page_frame_number = hook->exec_pfn;
          cpu->ept.mmr_mtf_pte = pte;
          cpu->ept.mmr_mtf_mode = mmr_memory_mode_r | mmr_memory_mode_w;
          cpu->ept.mmr_mtf_page_frame = pte->page_frame_number;
          enable_monitor_trap_flag();

      }
      else
          if (qualification.execute_access) {
              pte->read_access = 0;
              pte->write_access = 0;
              pte->execute_access = 1;
              pte->page_frame_number = hook->exec_pfn;
          }
          else {
              // Read/write access on a hook page. Default policy: point to
              // orig_pfn so the guest sees the real bytes (anti-cheat hash /
              // self-verify safe). Exception: if guest_rip is on the same
              // page as the access, the executing code IS our trampoline
              // (oldByte copy may include RIP-relative reads, push/pop
              // touching same-page stack, etc.). In that case grant the
              // trampoline R+W+X on exec_pfn for one instruction via MTF
              // and restore X-only on exec_pfn afterwards 鈥 this matches
              // the trampoline's expectation that its own bytes / data
              // refs come from exec_pfn, not the original page.
              if ((virtual_address >> 12) == (guest_rip >> 12)) {
                  pte->read_access = 1;
                  pte->write_access = 1;
                  pte->execute_access = 1;
                  pte->page_frame_number = hook->exec_pfn;
                  cpu->ept.mmr_mtf_pte = pte;
                  cpu->ept.mmr_mtf_mode = mmr_memory_mode_r | mmr_memory_mode_w;
                  cpu->ept.mmr_mtf_page_frame = pte->page_frame_number;
                  enable_monitor_trap_flag();
              } else {
                  pte->read_access = 1;
                  pte->write_access = 1;
                  pte->execute_access = 0;
                  pte->page_frame_number = hook->orig_pfn;
              }
          }
  }
  else {

      if (node)
      {
          pte->read_access = 1;
          pte->write_access = 1;
          pte->execute_access = 1;
          pte->page_frame_number = hook->orig_pfn;
          cpu->ept.mmr_mtf_pte = pte;
          cpu->ept.mmr_mtf_mode = mmr_memory_mode_r | mmr_memory_mode_w;
          cpu->ept.mmr_mtf_page_frame = pte->page_frame_number;
          enable_monitor_trap_flag();

      }
	  else if (qualification.execute_access) {
          pte->read_access = 0;
          pte->write_access = 0;
          pte->execute_access = 1;
          pte->page_frame_number = hook->orig_pfn;
      }
      else {
          pte->read_access = 1;
          pte->write_access = 1;
          pte->execute_access = 0;
          pte->page_frame_number = hook->exec_pfn;
          if (PAGE_ALIGN(virtual_address) == PAGE_ALIGN(guest_rip)) {
              pte->page_frame_number = hook->orig_pfn;
              pte->execute_access = 1;
              cpu->ept.mmr_mtf_pte = pte;
              cpu->ept.mmr_mtf_mode = mmr_memory_mode_r | mmr_memory_mode_w;
              cpu->ept.mmr_mtf_page_frame = pte->page_frame_number;
              enable_monitor_trap_flag();
          }

      }

  }



    //if(qualification.execute_access && (qualification.read_access || qualification.write_access))
    //{
    //        pte->read_access = 1;
		  //  pte->write_access = 1;
		  //  pte->execute_access = 1;
		  //  pte->page_frame_number = hook->exec_pfn;
		  //  cpu->ept.mmr_mtf_pte = pte;
		  //  cpu->ept.mmr_mtf_mode = mmr_memory_mode_r | mmr_memory_mode_w;
		  //  cpu->ept.mmr_mtf_page_frame = pte->page_frame_number;
		  //  enable_monitor_trap_flag();
    //}



  /*do
  {

      if (!g_ghv->is_cr3_monitor_open) break;

      if (node) break;
		
      if ((uint64_t)process != g_ghv->g_cr3_monitor.process) break;

      if ((virtual_address < (g_ghv->g_cr3_monitor.image_base)) || (virtual_address >= ((g_ghv->g_cr3_monitor.image_base + g_ghv->g_cr3_monitor.image_size + PAGE_SIZE - 1) & (~0xfff)))) break;

      auto thread = current_guest_ethread();
      auto thread_node = find_cr3_monitor_thread((uint64_t)process, (UINT64)thread);

     
      pte->read_access = 1;
      pte->write_access = 1;
      pte->execute_access = 1;
      if(g_ghv->is_check_thread)
      {
          if ((virtual_address >= (g_ghv->g_cr3_monitor.image_base)) && (virtual_address < ((g_ghv->g_cr3_monitor.image_base + PAGE_SIZE + g_ghv->g_cr3_monitor.text_section_size + PAGE_SIZE - 1) & (~0xfff))))
          {
              if (thread_node)
              {
            
                    if ((guest_rip < (g_ghv->g_cr3_monitor.image_base)) || (guest_rip >= ((g_ghv->g_cr3_monitor.image_base + PAGE_SIZE + g_ghv->g_cr3_monitor.text_section_size + PAGE_SIZE - 1) & (~0xfff))))
                    {
                        pte->page_frame_number = hook->orig_pfn;
                    }
                    else
                    {
                        pte->page_frame_number = hook->exec_pfn;

                    }

              }
              else
              {
                  pte->page_frame_number = hook->orig_pfn;

              }

          }
          else
          {
              if (thread_node)
              {
                if(g_ghv->is_check_rip)
                {
                    if (((guest_rip >= (g_ghv->g_cr3_monitor.image_base)) && (guest_rip < ((g_ghv->g_cr3_monitor.image_base + PAGE_SIZE + g_ghv->g_cr3_monitor.text_section_size + PAGE_SIZE - 1) & (~0xfff)))) || (guest_rip >= g_ghv->module_info.lowAddress && guest_rip < (g_ghv->module_info.highAddress + g_ghv->module_info.highSize + PAGE_SIZE - 1 & ~0xfff)))
                    {
                        pte->page_frame_number = hook->exec_pfn;
                    }
                    else
                    {
                        pte->page_frame_number = hook->orig_pfn;
                    }
                }
                else
                {
                    pte->page_frame_number = hook->exec_pfn;
                }
                 
              }
              else
                  pte->page_frame_number = hook->orig_pfn;
          }
             
      }
      else
      {
          if ((virtual_address >= (g_ghv->g_cr3_monitor.image_base)) && (virtual_address < ((g_ghv->g_cr3_monitor.image_base + PAGE_SIZE + g_ghv->g_cr3_monitor.text_section_size + PAGE_SIZE - 1) & (~0xfff))))
          {
            
              if ((guest_rip < (g_ghv->g_cr3_monitor.image_base)) || (guest_rip >= ((g_ghv->g_cr3_monitor.image_base + PAGE_SIZE + g_ghv->g_cr3_monitor.text_section_size + PAGE_SIZE - 1) & (~0xfff))))
              {
                  pte->page_frame_number = hook->orig_pfn;

              }
              else
              {
                  pte->page_frame_number = hook->exec_pfn;

              }

          }
          else
          {

            if(g_ghv->is_check_rip)
            {
                if (((guest_rip >= (g_ghv->g_cr3_monitor.image_base)) && (guest_rip < ((g_ghv->g_cr3_monitor.image_base + PAGE_SIZE + g_ghv->g_cr3_monitor.text_section_size + PAGE_SIZE - 1) & (~0xfff)))) || (guest_rip >= g_ghv->module_info.lowAddress && guest_rip < (g_ghv->module_info.highAddress + g_ghv->module_info.highSize + PAGE_SIZE - 1 & ~0xfff)))

                {
                    pte->page_frame_number = hook->exec_pfn;
                }
                else
                {
                    pte->page_frame_number = hook->orig_pfn;

                }
            }
            else
            {
	            {
                    pte->page_frame_number = hook->exec_pfn;
	            }
            }
          

          }


          
      }


      cpu->ept.mmr_mtf_pte = pte;
      cpu->ept.mmr_mtf_mode = mmr_memory_mode_r | mmr_memory_mode_w | mmr_memory_mode_x;
      cpu->ept.mmr_mtf_page_frame = pte->page_frame_number;
      enable_monitor_trap_flag();


  } while (0);*/



}


void handle_monitor_trap_flag(vcpu* const cpu) {
    if (hv::dbg_watch_handle_mtf(cpu))
        return;

    hv::handle_ept_probe_mtf(cpu);

    auto pte = cpu->ept.mmr_mtf_pte;
    auto const mode = cpu->ept.mmr_mtf_mode;
    auto  page_frame = cpu->ept.mmr_mtf_page_frame;
    // restore MMR mode
    if (pte)
    {
        pte->read_access = !(mode & mmr_memory_mode_r);
        pte->write_access = !(mode & mmr_memory_mode_w);
        pte->execute_access = !(mode & mmr_memory_mode_x);

        // write access but no read access will generate an EPT misconfiguration
        if (pte->write_access && !pte->read_access)
            pte->write_access = 0;

        if (page_frame)
            pte->page_frame_number = cpu->ept.mmr_mtf_page_frame;

        cpu->ept.mmr_mtf_pte = nullptr;
        cpu->ept.mmr_mtf_page_frame = 0;


        //vmx_invept(invept_all_context, {});

    }

    disable_monitor_trap_flag();
}


void emulate_rdtsc(vcpu* const cpu) {
  auto const tsc = __rdtsc();

  // return current TSC
  cpu->ctx->rax = tsc & 0xFFFFFFFF;
  cpu->ctx->rdx = (tsc >> 32) & 0xFFFFFFFF;

  skip_instruction();
}

void emulate_rdtscp(vcpu* const cpu) {
  unsigned int aux = 0;
  auto const tsc = __rdtscp(&aux);

  // return current TSC
  cpu->ctx->rax = tsc & 0xFFFFFFFF;
  cpu->ctx->rdx = (tsc >> 32) & 0xFFFFFFFF;
  cpu->ctx->rcx = aux;

  skip_instruction();
}



void handle_ept_misconfiguration(vcpu*) {
  auto const phys = vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS);
  HV_LOG_ERROR(_XOR_("Unhandled EPT Misconfiguration: %p"), phys);
}

} // namespace hv

