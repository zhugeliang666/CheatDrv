#pragma once

namespace hv {
struct hypercall_input;
struct vcpu;
}

namespace svm {

struct features {
	bool     is_amd;
	bool     svm_supported;
	bool     svm_disabled;
	bool     npt_supported;
	bool     nrips_supported;
	bool     decode_assists;
	bool     vmcb_clean_bits;
	bool     flush_by_asid;
	unsigned __int32 max_ext_leaf;
	unsigned __int32 svm_revision;
	unsigned __int32 max_asid;
	unsigned __int64 vm_cr;
	unsigned __int32 raw_8000000a_edx;
};

// Query AMD SVM capabilities without mutating CPU state. Safe to call before
// hv::start() decides whether to use the Intel VMX or AMD SVM backend.
bool detect(features* out_features = nullptr);

// True only when the current CPU is AMD, SVM is enabled by firmware, and NPT is
// present. NRIPS is not required by this predicate yet because Phase 0 is only
// a passive capability probe; Phase 1+ can enforce it before launch.
bool available();

// AMD backend lifecycle. Phase 0 keeps these as non-invasive stubs so the
// Intel path remains untouched while the SVM backend is built out.
bool start();
void stop();

bool create_vcpu_state(hv::vcpu* cpu, unsigned long index);
void destroy_vcpu_state(hv::vcpu* cpu);
bool setup_vmcb_for_current_guest(hv::vcpu* cpu, void* guest_rip, void* guest_rsp);
bool launch_vcpu(hv::vcpu* cpu);

// Executes AMD VMMCALL with the same register ABI as hv::vmx_vmcall. This must
// only be used after the AMD backend has launched; outside SVM it will #UD.
unsigned __int64 vmmcall(hv::hypercall_input& input);

}
