#include "../base.h"
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
#include "nested-page-instrumentation.h"
#include "vtcall-hook.h"
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

  // CPUID 0x40000000-0x4FFFFFFF：虚拟机监控程序信息叶子。
  // 模拟 Microsoft Hv (Hyper-V) 规范——现代反作弊系统对 Hyper-V 均有内置白名单，
  // 因为 Windows 11 在默认开启 VBS/HVCI/WSL2 时就是此环境。此处返回原生 GenuineIntel
  // 会是明显的伪造漏洞；返回全零则极度可疑；若返回自定义品牌特征则初次扫描就会被列入黑名单。
  // 采用 Hyper-V 签名可获得最强且最广泛的系统与反作弊兼容性。
    if (ctx->eax >= 0x40000000 && ctx->eax <= 0x4FFFFFFF) {
      switch (ctx->eax) {
      case 0x40000000:
          // 最大叶子号 + "Microsoft Hv" 厂商签名特征
          regs[0] = 0x40000006;        // EAX = max hv leaf
          regs[1] = 0x7263694D;        // EBX = "Micr"
          regs[2] = 0x666F736F;        // ECX = "osof"
          regs[3] = 0x76482074;        // EDX = "t Hv"
          break;
      case 0x40000001:
          // 虚拟机监控程序接口签名："Hv#1"
          regs[0] = 0x31237648;        // "Hv#1"
          regs[1] = 0;
          regs[2] = 0;
          regs[3] = 0;
          break;
      case 0x40000002:
          // 虚拟机监控程序系统标识（内部版本号/版本信息）——模拟合理合规的极简配置。
          regs[0] = 0x00001bbc;        // build 7100
          regs[1] = 0x00060001;        // major.minor 6.1
          regs[2] = 0;                 // service pack
          regs[3] = 0;                 // service branch
          break;
      case 0x40000003:
          // 虚拟机监控程序功能标识——不通告任何高危特权功能。
          regs[0] = 0;
          regs[1] = 0;
          regs[2] = 0;
          regs[3] = 0;
          break;
      case 0x40000004:
      case 0x40000005:
      case 0x40000006:
      default:
          // 实现建议 / 硬件特性标志等
          regs[0] = regs[1] = regs[2] = regs[3] = 0;
          break;
      }
  }
  else
  {

      __cpuidex(regs, ctx->eax, ctx->ecx);

      // CPUID(1).ECX bit31 = 虚拟机监控程序存在标志位。透传真实状态（当前已处于 Hypervisor
      // 环境下，若将其强行清零将与上方通告的 0x40000000 "Hv" 签名产生冲突，触发反作弊的虚假欺骗检测启发式规则）。

      // CPUID(7, 0).EBX bit25 = Intel Processor Trace (PT) 硬件能力位。主动隐藏此标志，
      // 阻止反作弊系统尝试开启 PT（尽管我们拦截了 RTIT_CTL 写入，但宣称支持 PT 却静默丢弃写入会被检出）。
      // 关联联动：vt/exit-handlers.cpp 拦截 IA32_RTIT_CTL/DEBUGCTL 写入，
      //            vt/vcpu.cpp 保证每次 VM-entry 时 VMCS_GUEST_RTIT_CTL = 0。
      if (ctx->eax == 0x07 && ctx->ecx == 0) {
          regs[1] &= ~(1u << 25);
      }

      // CPUID(0x14): Intel PT 枚举叶子。若反作弊绕过 EBX[25] 仍强行查询此项，
      // 全量返回 0，使其表现为硬件完全不支持 PT，杜绝局部特征暴露。
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

  // PT MSR 读取 trap. We never 启用 Intel PT for the guest
  // (WRMSR trapped below, and VMCS_GUEST_RTIT_CTL forced to 0 on every
  // vm-条目项). Return 0 on 读取 so 反作弊系统 sees a stable "disabled" 状态.
  //
  // 注意：IA32_DEBUGCTL 严禁拦截读取操作——Windows 内核（KiDebugRoutine BTF 位、上下文保存/恢复例程）
// 会高频主动读写该 MSR。若对读取进行虚假应答将导致内核调度与调试状态机彻底紊乱引发蓝屏。
// 下方的写入拦截仍会阻止 Guest 开启 LBR/BTS，且 VMCS 会在每次 VM-exit 时自动清零这些位。
  // reads/writes it (KiDebugRoutine BTF bit, 上下文 保存/恢复). Lying
  // about it causes kernel 状态-machine corruption. 写入 trap below still
  // prevents the guest from enabling LBR/BTS, and VMCS clears those bits on
  // vm-条目项 anyway.
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

  // 性能监控(Perfmon) MSR 拦截已停用——该拦截若与 TSC 偏移混用会导致 DWM 黑屏闪烁。
// 若需安全重新启用，切勿清零 fake_perfmon_base_tsc。
  // DWM black screen. To re-启用 safely: do not zero fake_perfmon_base_tsc
  // on first 读取 mid-frame, and verify DWM's perfmon usage pattern.
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

  // Guest 可能正在读取超出 MSR 位图管理范围之外的 MSR 寄存器。
  auto  msr_value = rdmsr_safe(e, cpu->ctx->ecx);

  if (e.exception_occurred) {
    // 将异常直接反射注入回 Guest 上下文中
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

  // 允许 Guest 写入目标 MSR 寄存器
  host_exception_info e;
  wrmsr_safe(e, msr, value);

  if (e.exception_occurred) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // 若 Guest 修改了任何 MTRR 寄存器，必须同步更新 EPT 内存类型映射。
  if (msr == IA32_MTRR_DEF_TYPE     || msr == IA32_MTRR_FIX64K_00000 ||
      msr == IA32_MTRR_FIX16K_80000 || msr == IA32_MTRR_FIX16K_A0000 ||
     (msr >= IA32_MTRR_FIX4K_C0000  && msr <= IA32_MTRR_FIX4K_F8000) ||
     (msr >= IA32_MTRR_PHYSBASE0    && msr <= IA32_MTRR_PHYSBASE0 + 511)) {
    // 更新 EPT 内存缓存类型(MTRR 属性)
    if (!read_effective_guest_cr0().cache_disable)
      update_ept_memory_type(cpu->ept);

    vmx_invept(invept_all_context, {});
  }


  

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
  return;
}

void emulate_getsec(vcpu*) {
  // 因 IA32_FEATURE_CONTROL MSR 中禁用了 SMX，向 Guest 注入通用保护异常 #GP(0)
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
  // TODO: 完善 INVD 指令模拟（可在执行 INVD 前构造微型存根刷新特定高速缓存行）
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

  // 当前仅支持 XCR0 扩展控制寄存器
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
    // TODO: 断言触发的是 #GP(0) 异常（依据 Intel 手册规范，此处不会触发其它类型异常）
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

  // we are spoofing the 值 of the IA32_FEATURE_CONTROL MSR in
  // 旨在向 Guest 伪造证明 VMX 虚拟化技术已在 BIOS 层面被硬件级禁用。
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
  // 校验超调用身份鉴权密钥（Hypercall Key）
      if (key != hypercall_key) {
        HV_LOG_VERBOSE(_XOR_("Invalid VMCALL key. RIP=%p."), vmx_vmread(VMCS_GUEST_RIP));
        // 常驻 Payload freetest parity: do not allow gamevt-range bad-key
        // VMCALLs to bypass key validation and fall into legacy 分发.
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
  // 分发并处理经鉴权确认的超调用请求
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

  case hypercall_add_real_cr3:
      hc::add_real_cr3(cpu);
	  return;

  case hypercall_get_game_path:
  case hypercall_get_game_module_base:
  case hypercall_hide_hv:
  case hypercall_unhide_hv:
  case hypercall_read_game_mem:
  case hypercall_write_game_mem:
  case hypercall_hide_cache_info:
  case hypercall_unhide_cache_info:
  case hypercall_save_gamevt_image_base:
  case hypercall_get_gamevt_image_base:
  case hypercall_call_function:
  case hypercall_add_vmcall_hook:
  case hypercall_remove_vmcall_hook:
  case hypercall_enable_vmcall_hook:
  case hypercall_disable_vmcall_hook:
      cpu->ctx->rax = 0;
      skip_instruction();
      return;

    // Host 根模式统一托管的 EPT 隐藏挂钩（参见 hooks/ept-hook.cpp）
    case hypercall_eh_install:                hc::vmcall_eh_install(cpu);                return;
    case hypercall_eh_remove:                 hc::vmcall_eh_remove(cpu);                 return;
    case hypercall_eh_enable:                 hc::vmcall_eh_enable(cpu);                 return;
    case hypercall_eh_disable:                hc::vmcall_eh_disable(cpu);                return;
    case hypercall_eh_write:                  hc::vmcall_eh_write(cpu);                  return;
    case hypercall_eh_get_va:                 hc::vmcall_eh_get_va(cpu);                 return;
    case hypercall_eh_remove_all_by_process:  hc::vmcall_eh_remove_all_by_process(cpu);  return;

    // Host 根模式统一托管的 VTCall 内核挂钩（参见 hooks/vtcall-hook.cpp）
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

  // Guest 尝试修改 CR0.CD（高速缓存禁用）或 CR0.NW（非穿透写），需由 Host 态手动同步更新
  if (new_cr0.cache_disable     != curr_cr0.cache_disable ||
      new_cr0.not_write_through != curr_cr0.not_write_through) {
    // TODO: 评估是否需针对 CR0.NW 采取特殊处理
    if (new_cr0.cache_disable)
      set_ept_memory_type(cpu->ept, MEMORY_TYPE_UNCACHEABLE);
    else
      update_ept_memory_type(cpu->ept);

    vmx_invept(invept_all_context, {});
  }

  HV_LOG_VERBOSE(_XOR_("Writing %p to CR0."), new_cr0.flags);

  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, new_cr0.flags);

  // 设置真实 CR0 寄存器时，必须严格处理 VMX 架构保留位约束
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

    // a 掩码 where bits [63:MAXPHYSADDR] are 设置 to 1
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

    // it is now safe to 写入 the new Guest CR3 寄存器
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

  // 若有必要，执行指令刷新相关 TLB 转换表项
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

  // 设置真实 CR4 寄存器时，必须严格处理 VMX 架构保留位约束
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
  // 在 CR0 读取影子中清除任务切换标志位(CR0.TS)
  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW,
    vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW) & ~CR0_TASK_SWITCHED_FLAG);

  // 在真实 CR0 控制寄存器中清除任务切换标志位(CR0.TS)
  vmx_vmwrite(VMCS_GUEST_CR0,
    vmx_vmread(VMCS_GUEST_CR0) & ~CR0_TASK_SWITCHED_FLAG);

  cpu->hide_vm_exit_overhead = true;
  skip_instruction();
}

void emulate_lmsw(vcpu* const cpu, uint16_t const value) {
  // 3.25.1.3

  cr0 new_cr0;
  new_cr0.flags = value;

  // 同步更新 Guest 视角的 CR0 读取影子寄存器
  cr0 shadow_cr0;
  shadow_cr0.flags = vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW);
  shadow_cr0.protection_enable   = new_cr0.protection_enable;
  shadow_cr0.monitor_coprocessor = new_cr0.monitor_coprocessor;
  shadow_cr0.emulate_fpu         = new_cr0.emulate_fpu;
  shadow_cr0.task_switched       = new_cr0.task_switched;
  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow_cr0.flags);

  // 同步更新底层真实的 Guest CR0 寄存器
  // we don't have to worry about VMX reserved bits since CR0.PE (the only
  // reserved bit) can't be cleared to 0 by the LMSW instruction while in
  // protected 模式.
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
  // MOV CRn, 寄存器操作指令
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
  // MOV 寄存器, CRn 操作指令
  case VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR:
    // TODO: 断言当前访问的是 CR3 控制寄存器（而非 CR8）
    emulate_mov_from_cr3(cpu, qualification.general_purpose_register);
    break;
  // 清任务切换标志指令 CLTS
  case VMX_EXIT_QUALIFICATION_ACCESS_CLTS:
    emulate_clts(cpu);
    break;
  // 加载机器状态字指令 LMSW
  case VMX_EXIT_QUALIFICATION_ACCESS_LMSW:
    emulate_lmsw(cpu, qualification.lmsw_source_data);
    break;
  }
}

void handle_nmi_window(vcpu* const cpu) {
  //--cpu->queued_nmis;

  // 向 Guest 注入不可屏蔽中断(NMI)
  inject_nmi();


  auto ctrl = read_ctrl_proc_based();
  ctrl.nmi_window_exiting = 0;
  write_ctrl_proc_based(ctrl);

  //if (cpu->queued_nmis == 0) {
  // // 禁用 NMI-window exiting since we have no more NMIs to 注入
  //  auto ctrl = read_ctrl_proc_based();
  //  ctrl.nmi_window_exiting = 0;
  //  write_ctrl_proc_based(ctrl);
  //}
  //
  //// there is the possibility that a host NMI occurred right before we
  // // disabled NMI-window exiting. make sure to re-启用 it if this is the case.
  //if (cpu->queued_nmis > 0) {
  //  auto ctrl = read_ctrl_proc_based();
  //  ctrl.nmi_window_exiting = 1;
  //  write_ctrl_proc_based(ctrl);
  //}
}

void handle_exception_or_nmi(vcpu* const cpu) {
  // 将 NMI 中断压入等待队列，在后续安全时机向 Guest 注入


    vmexit_interrupt_information interrupt_information;
    interrupt_information.flags = (uint32_t)vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION);

    vmentry_interrupt_information new_interrupt_information = {};

    switch (interrupt_information.vector)
    {

    case exception_vector::breakpoint:
    {
        // 诊断度量：统计所有 #BP 导致的 VM-exit 频次并记录最后触发的 RIP
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_bp_total);
        auto const bp_rip = vmx_vmread(VMCS_GUEST_RIP);
        g_ghv->diag_bp_last_rip = bp_rip;

        // 0xCC trampoline match: VMCS_GUEST_RIP at INT3 vm-exit points AT
        // the 0xCC byte (not past it). slot.bp_rip is precomputed to that
        // exact 地址; on match we rewrite RIP to slot's target_resume so
        // the guest continues right after the hooked instruction in the real
        // function (NOT in our exec_page).
        {
            auto& pool = g_ghv->tramp_pool;
            // Lock-释放 读取: pool slots only mutate during 安装/卸载移除,
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
        // the requested 地址.  On hit we snapshot registers, map the
        // original PFN for exactly one instruction via MTF, then 恢复 the
        // 影子页面.  This path is independent from hv::Call/tramp slots.
        if (hv::try_handle_ept_probe_bp(cpu)) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_bp_match);
            return;
        }

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_bp_miss);
        if (g_ghv->diag_bp_first_miss_rip == 0)
            g_ghv->diag_bp_first_miss_rip = g_ghv->diag_bp_last_rip;

        // Otherwise legit guest #BP (debugger / __debugbreak / ntdll assert) -
        // re-注入 back into guest.
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
        // 将 NMI 中断压入等待队列，在后续安全时机向 Guest 注入
    {
        break;
    }

    }
}

void handle_vmx_instruction(vcpu*) {
  // 注入 #UD for every VMX instruction since we
  // don't allow the guest to ever enter VMX operation.
  inject_hw_exception(invalid_opcode);
}

void handle_ept_violation(vcpu* const cpu) {
  vmx_exit_qualification_ept_violation qualification;
  qualification.flags = vmx_vmread(VMCS_EXIT_QUALIFICATION);

  // 触发 EPT 违例异常的 Guest 物理地址(GPA)
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
  // ept_hook.  处理 them before find_ept_hook(), otherwise watched pages
  // would look like "hook miss" and 获取 injected as #GP.
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

  uint16_t observed_access = nested_page_present | nested_page_hook_match;
  if (qualification.read_access) observed_access |= nested_page_read;
  if (qualification.write_access) observed_access |= nested_page_write;
  if (qualification.execute_access) observed_access |= nested_page_execute;
  const uint32_t vcpu_index = (g_ghv && g_ghv->vcpus)
      ? static_cast<uint32_t>(cpu - g_ghv->vcpus) : 0;
  NestedPageInstrumentation::Record(nested_page_backend::ept, observed_access,
      physical_address, virtual_address, guest_rip,
      vmx_vmread(VMCS_GUEST_CR3), vcpu_index);

  // PMO 命中校验：判断当前 EPT 违例是否发生在专为 PMO 挂接的物理页上
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
              // 读取/写访问 on a hook page. 默认 policy: point to
              // orig_pfn so the guest sees the real bytes (反作弊系统 hash
              // self-verify safe). Exception: if guest_rip is on the same
              // page as the access, the executing code IS our trampoline
              // (oldByte copy may include RIP-relative reads, push/pop
              // touching same-page stack, etc.). In that case grant the
              // 执行跳板 R+W+X on exec_pfn for one instruction via MTF
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
    // 恢复内存监控(MMR)模式状态
    if (pte)
    {
        pte->read_access = !(mode & mmr_memory_mode_r);
        pte->write_access = !(mode & mmr_memory_mode_w);
        pte->execute_access = !(mode & mmr_memory_mode_x);

        // EPT 架构规范：仅有写权限而无读权限的页表配置属于非法状态，会引发 EPT Misconfiguration 虚拟机崩溃
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

  // 返回当前时间戳计数器(TSC)计数值
  cpu->ctx->rax = tsc & 0xFFFFFFFF;
  cpu->ctx->rdx = (tsc >> 32) & 0xFFFFFFFF;

  skip_instruction();
}

void emulate_rdtscp(vcpu* const cpu) {
  unsigned int aux = 0;
  auto const tsc = __rdtscp(&aux);

  // 返回当前时间戳计数器(TSC)计数值
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

