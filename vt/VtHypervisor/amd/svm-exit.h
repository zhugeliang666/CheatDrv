#pragma once

namespace hv {
struct vcpu;
struct guest_context;
}

namespace svm {
struct vmcb;

bool handle_vmexit(hv::vcpu* cpu, hv::guest_context* ctx);
void inject_exception(vmcb* vmcb, unsigned int vector);
void inject_exception(vmcb* vmcb, unsigned int vector, unsigned int error_code);
void advance_guest_ip(vmcb* vmcb, unsigned int fallback_length);

} // namespace svm
