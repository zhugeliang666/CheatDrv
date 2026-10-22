#pragma once

namespace hv {
struct hypercall_input;
struct vcpu;
}

namespace svm {

// First-launch diagnostic marker.  It is deliberately a fixed nonpaged scalar
// array so the watchdog CPU can report progress without calling kernel services
// on the CPU whose GIF/IF/IDTR state is being changed.
enum launch_stage : unsigned long {
	launch_stage_idle = 0,
	launch_stage_enter = 10,
	launch_stage_host_cr3_ready = 20,
	launch_stage_msrs_captured = 30,
	launch_stage_vmcb_ready = 40,
	launch_stage_before_disable = 50,
	launch_stage_if_disabled = 51,
	launch_stage_efer_enabled = 52,
	launch_stage_hsave_installed = 53,
	launch_stage_gif_cleared = 54,
	launch_stage_guest_saved = 55,
	launch_stage_host_saved = 56,
	launch_stage_host_idt_loaded = 57,
	launch_stage_asm_enter = 58,
	launch_stage_asm_return = 59,
	launch_stage_failure_restored = 60,
	launch_stage_success = 61,
};

extern volatile unsigned long g_launch_stage[64];

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
