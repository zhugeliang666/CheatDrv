#pragma once

namespace hv {

struct vcpu;

// setup the VMCS control fields
void write_vmcs_ctrl_fields(vcpu* cpu);

// setup the VMCS host fields
void write_vmcs_host_fields(vcpu const* cpu);

// setup the Guest 客户机状态 in the VMCS so that it mirrors the currently running system
void write_vmcs_guest_fields();

} // namespace hv

