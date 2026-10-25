#pragma once

#include "arch.h"
#include "guest-context.h"
#include "hypercalls.h"

namespace hv {

// TODO: move to ia32?
struct vmx_msr_entry {
  uint32_t msr_idx;
  uint32_t _reserved;
  uint64_t msr_data;
};

extern void vm_exit();

// INVEPT instruction
void vmx_invept(invept_type type, invept_descriptor const& desc);

// INVVPID instruction
void vmx_invvpid(invvpid_type type, invvpid_descriptor const& desc);

// VMCALL instruction
uint64_t vmx_vmcall(hypercall_input& input);

// VMXON instruction
bool vmx_vmxon(uint64_t vmxon_phys_addr);

// VMXOFF instruction
void vmx_vmxoff();

// VMCLEAR instruction
bool vmx_vmclear(uint64_t vmcs_phys_addr);

// VMPTRLD instruction
bool vmx_vmptrld(uint64_t vmcs_phys_addr);

// VMWRITE instruction
void vmx_vmwrite(uint64_t field, uint64_t value);

// VMREAD instruction
uint64_t vmx_vmread(uint64_t field);

// 写入 to the guest interruptibility 状态
void write_interruptibility_state(vmx_interruptibility_state value);

// 读取 the guest interruptibility 状态
vmx_interruptibility_state read_interruptibility_state();

// 写入 to a guest general-purpose 注册
void write_guest_gpr(guest_context* ctx, uint64_t gpr_idx, uint64_t value);

// 读取 a guest general-purpose 注册
uint64_t read_guest_gpr(guest_context const* ctx, uint64_t gpr_idx);

// 获取 the 值 of CR0 that the guest believes is active.
// this is a mixture of the Guest CR0 寄存器 and the CR0 读取 shadow.
cr0 read_effective_guest_cr0();

// 获取 the 值 of CR4 that the guest believes is active.
// this is a mixture of the Guest CR4 寄存器 and the CR4 读取 shadow.
cr4 read_effective_guest_cr4();

// 写入 to the 基于引脚的 VM 执行控制
void write_ctrl_pin_based_safe(ia32_vmx_pinbased_ctls_register value);

// 写入 to the processor-based vm-execution controls
void write_ctrl_proc_based_safe(ia32_vmx_procbased_ctls_register value);

// 写入 to the 基于次要处理器的 vm-execution controls
void write_ctrl_proc_based2_safe(ia32_vmx_procbased_ctls2_register value);

// 写入 to the vm-exit controls
void write_ctrl_exit_safe(ia32_vmx_exit_ctls_register value);

// 写入 to the vm-条目项 controls
void write_ctrl_entry_safe(ia32_vmx_entry_ctls_register value);

// 写入 to the 基于引脚的 VM 执行控制
void write_ctrl_pin_based(ia32_vmx_pinbased_ctls_register value);

// 写入 to the processor-based vm-execution controls
void write_ctrl_proc_based(ia32_vmx_procbased_ctls_register value);

// 写入 to the 基于次要处理器的 vm-execution controls
void write_ctrl_proc_based2(ia32_vmx_procbased_ctls2_register value);

// 写入 to the vm-exit controls
void write_ctrl_exit(ia32_vmx_exit_ctls_register value);

// 写入 to the vm-条目项 controls
void write_ctrl_entry(ia32_vmx_entry_ctls_register value);

// 读取 the 基于引脚的 VM 执行控制
ia32_vmx_pinbased_ctls_register read_ctrl_pin_based();

// 读取 the processor-based vm-execution controls
ia32_vmx_procbased_ctls_register read_ctrl_proc_based();

// 读取 the 基于次要处理器的 vm-execution controls
ia32_vmx_procbased_ctls2_register read_ctrl_proc_based2();

// 读取 the vm-exit controls
ia32_vmx_exit_ctls_register read_ctrl_exit();

// 读取 the vm-条目项 controls
ia32_vmx_entry_ctls_register read_ctrl_entry();

// 获取 the CPL (当前 privilege level) of the 当前 guest
uint16_t current_guest_cpl();

// increment the instruction 指针 after emulating an instruction
void skip_instruction();

// 注入 a 不可屏蔽中断(NMI) into the guest
void inject_nmi();

// 注入 a vectored exception into the guest
void inject_hw_exception(uint32_t vector);

// 注入 a vectored exception into the guest (with an error code)
void inject_hw_exception(uint32_t vector, uint32_t error);

// 启用/禁用 vm-exits when the guest tries to 读取 the specified MSR
void enable_exit_for_msr_read(vmx_msr_bitmap& bitmap, uint32_t msr, bool enable_exiting);

// 启用/禁用 vm-exits when the guest tries to 写入 to the specified MSR
void enable_exit_for_msr_write(vmx_msr_bitmap& bitmap, uint32_t msr, bool enable_exiting);

// 启用 MTF exiting
void enable_monitor_trap_flag();

// 禁用 MTF exiting
void disable_monitor_trap_flag();


extern void inline AsmInvd();

} // namespace hv

#include "vmx.inl"

