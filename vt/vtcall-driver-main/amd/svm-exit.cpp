#include "svm-exit.h"

#include "amd64.h"
#include "npt.h"
#include "svm.h"
#include "vmcb.h"

#include "../base.h"
#include "../common/ntutils.h"
#include "../vt/arch.h"
#include "../vt/ept-hook.h"
#include "../vt/exception-routines.h"
#include "../vt/guest-context.h"
#include "../vt/hv.h"
#include "../vt/hypercalls.h"
#include "../vt/mm.h"
#include "../vt/vcpu.h"
#include "../gamecommon/game.h"
#include "../gamecommon/memory.h"
#include "../hook/hde64.h"
#include "../poolmanager/PoolManager.h"
#include "../render/render.h"

#include <cstddef>
#include <intrin.h>

extern "C" uint8_t __ImageBase;
extern "C" void yvt_set_keep_hv_on_unload(bool enable);
extern "C" volatile uint64_t* yvt_get_boot_flags_ptr();

namespace hv {
extern UINT64 gamevt_image_base;
extern UINT64 gamevt_driver_unload;
}

extern "C" void svm_stgi_asm();
extern "C" void svm_vmload_asm(unsigned __int64 pa);
extern "C" void svm_prepare_stop_c(hv::vcpu* const cpu, hv::guest_context*);
extern "C" volatile LONG g_hv_panic_dump_claimed = 0;
extern "C" [[noreturn]] void hv_bugcheck_on_stack_asm(
	uint64_t new_rsp,
	uint64_t bugcheck_code,
	uint64_t param1,
	uint64_t param2,
	uint64_t param3,
	uint64_t param4);

namespace {

struct vmexit_storm_tracker {
	u64 last_rip;
	u64 last_exitcode;
	u32 streak;
};

static vmexit_storm_tracker g_vmexit_storm[64] = {};

[[noreturn]] static void bugcheck_from_svm_vmexit(
	hv::vcpu* const cpu,
	hv::guest_context* const,
	u64 const bugcheck_code)
{
	auto const v = cpu->svm.vmcb;
	auto const host_v = reinterpret_cast<svm::vmcb const*>(cpu->svm.host_vmcb);
	u64 const exit_code  = v->exitcode;
	u64 const guest_rip  = v->rip;
	u64 const exit_info1 = v->exitinfo1;
	u64 const exit_info2 = v->exitinfo2;
	u64 const host_kpcr  = (host_v && host_v->gs.base >= 0xFFFF800000000000ULL) ? host_v->gs.base : 0;
	u64 const kpcr       = host_kpcr ? host_kpcr : ((v->gs.base >= 0xFFFF800000000000ULL) ? v->gs.base : v->kernel_gs_base);
	u64 const kgs        = (v->gs.base >= 0xFFFF800000000000ULL) ? v->kernel_gs_base : v->gs.base;
	u64 const orig_hsave = cpu->svm.original_hsave_pa;
	u64 const guest_efer = cpu->svm.guest_efer & ~amd64_efer_svme_bit;
	u64 const sys_cr3    = (hv::g_ghv && hv::g_ghv->system_cr3.flags) ? hv::g_ghv->system_cr3.flags : cpu->svm.original_cr3;
	u64 guest_krsp       = v->rsp;

	svm_prepare_stop_c(cpu, nullptr);

	if (kpcr >= 0xFFFF800000000000ULL) {
		__writemsr(amd64_gs_base, kpcr);
		__writemsr(amd64_kernel_gs_base, kgs);
		if (guest_krsp < 0xFFFF800000000000ULL) {
			auto const tss_base = *reinterpret_cast<u64 const*>(kpcr + 0x08);
			if (tss_base >= 0xFFFF800000000000ULL) {
				auto const rsp0 = *reinterpret_cast<u64 const*>(tss_base + 4);
				if (rsp0 >= 0xFFFF800000000000ULL)
					guest_krsp = rsp0;
			}
		}
	}
	if (guest_krsp < 0xFFFF800000000000ULL)
		guest_krsp = reinterpret_cast<u64>(cpu->host_stack) + hv::host_stack_size - 0x100;

	__writemsr(amd64_hsave_pa, orig_hsave);
	__writemsr(amd64_efer, guest_efer);
	if (sys_cr3)
		__writecr3(sys_cr3);
	svm_stgi_asm();
	__writecr8(0);
	hv_bugcheck_on_stack_asm(
		guest_krsp,
		bugcheck_code,
		exit_code,
		guest_rip,
		exit_info1,
		exit_info2);
}

} // namespace

extern "C" bool svm_handle_vmexit_c(hv::vcpu* const cpu, hv::guest_context* const ctx) {
	return svm::handle_vmexit(cpu, ctx);
}

extern "C" void svm_prepare_stop_c(hv::vcpu* const cpu, hv::guest_context* const ctx) {
	if (!cpu || !cpu->svm.vmcb)
		return;

	auto const v = cpu->svm.vmcb;
	auto const host_v = reinterpret_cast<svm::vmcb const*>(cpu->svm.host_vmcb);

	_disable();

	u64 const vmcb_pa    = cpu->svm.vmcb_pa;
	u64 const orig_hsave = cpu->svm.original_hsave_pa;
	u64 const guest_efer = cpu->svm.guest_efer & ~amd64_efer_svme_bit;
	u64 const guest_cr3  = v->cr3;
	u64 const host_kpcr  = (host_v && host_v->gs.base >= 0xFFFF800000000000ULL) ? host_v->gs.base : 0;
	u64 const kpcr       = host_kpcr ? host_kpcr : ((v->gs.base >= 0xFFFF800000000000ULL) ? v->gs.base : v->kernel_gs_base);
	u64 const kgs        = (v->gs.base >= 0xFFFF800000000000ULL) ? v->kernel_gs_base : v->gs.base;

	segment_descriptor_register_64 gdtr = {};
	gdtr.limit = static_cast<u16>(v->gdtr.limit);
	gdtr.base_address = v->gdtr.base;
	_lgdt(&gdtr);

	hv::write_ds(v->ds.selector);
	hv::write_es(v->es.selector);

	if (vmcb_pa)
		svm_vmload_asm(vmcb_pa);

	if (!ctx && kpcr >= 0xFFFF800000000000ULL) {
		__writemsr(amd64_gs_base, kpcr);
		__writemsr(amd64_kernel_gs_base, kgs);
	}

	segment_descriptor_register_64 idtr = {};
	idtr.limit = static_cast<u16>(v->idtr.limit);
	idtr.base_address = v->idtr.base;
	__lidt(&idtr);

	__writedr(7, v->dr7);
	__writedr(6, v->dr6);
	__writecr2(v->cr2);
	__writecr4(v->cr4);
	__writecr0(v->cr0);
	__writemsr(amd64_pat, v->g_pat);

	cpu->svm.launched = false;
	cpu->svm.should_stop = false;
	cpu->stop_virtualization = false;

	if (ctx) {
		__writecr3(guest_cr3);
		svm_stgi_asm();
		__writemsr(amd64_hsave_pa, orig_hsave);
		__writemsr(amd64_efer, guest_efer);
	}
}

namespace svm {

namespace {

constexpr u64 resident_hv_diag_magic = 0x4D41504856444731ull; // MAPHVDG1

struct resident_hv_diag_record {
	u64 magic;
	u64 size;
	u64 version;
	u64 current_vcpu;
	u64 vcpu_count;
	u64 ghv_ptr;
	u64 vcpus_ptr;
	u64 current_vcpu_ptr;
	u64 vmcs_host_rip;
	u64 vmcs_host_rsp;
	u64 current_host_stack;
	u64 host_stack_bytes;
	u64 vm_exit_ptr;
	u64 handle_vm_exit_ptr;
	u64 image_base;
	u64 driver_unload;
	u64 flags;
	u64 ghv_off_kpcr_prcb_offset;
	u64 ghv_off_kprcb_current_thread_offset;
	u64 ghv_off_kthread_apc_state_offset;
	u64 ghv_off_kapc_state_process_offset;
	u64 ghv_off_vtcallstack_list;
	u64 ghv_off_tramp_pool;
	u64 ghv_off_dbg;
	u64 ghv_off_dbg_events;
	u64 ghv_off_dbg_watch;
	u64 vcpu_stride;
	u64 vcpu_off_ept;
	u64 vcpu_off_ept_free_pages;
	u64 vcpu_off_ept_free_page_pfns;
	u64 vcpu_off_ept_hook_active_list;
	u64 vcpu_off_dbg_pending;
	u64 ghv_off_affinity_lock_enabled;
	u64 ghv_off_diag_hide_enter;
	u64 ghv_off_diag_hide_pte_total;
	u64 ghv_off_diag_hide_pte_null;
	u64 ghv_off_diag_hide_done_bitmap;
	u64 vcpu_off_ept_num_used_free_pages;
	u64 vcpu_off_ept_dummy_page_pfn;
	u64 ept_free_page_count;
	u64 gamevt_image_base_ptr;
	u64 gamevt_driver_unload_ptr;
	u64 yvt_boot_flags_ptr;
	u64 system_eprocess;
	u64 kprocess_directory_table_base_offset;
	u64 eprocess_unique_process_id_offset;
	u64 ghv_off_cr3_map_real_cr3;
	u64 vt_hook_table_ptr;
	u64 vt_hook_slot_count;
	u64 vt_hook_slot_size;
	u64 vt_hook_slot_off_data_address;
	u64 vt_hook_slot_off_data_type;
	u64 vt_hook_slot_off_data_blank_memory;
	u64 vt_hook_slot_off_data_dispatch_mode;
	u64 vt_hook_slot_off_occupied;
	u64 vt_hook_slot_off_trampoline_va;
	u64 vt_hook_slot_off_bp_rip;
	u64 vt_hook_slot_off_target_resume;
	u64 render_swapchain_ptr;
	u64 render_isfinish_ptr;
	u64 ghv_off_dwm_hit_count;
	u64 ghv_off_diag_handler_count;
	u64 render_d2d_rt_ptr;
	u64 render_color_brush_ptr;
	u64 render_text_format_ptr;
	u64 render_buffer0_ptr;
	u64 render_buffer0_hva_ptr;
	u64 render_desc_buffer_ptr;
	u64 render_desc_buffer_hva_ptr;
	u64 ghv_off_kthread_affinity_offset;
	u64 ghv_off_kthread_user_affinity_offset;
	u64 ghv_off_kthread_ideal_processor_offset;
	u64 ghv_off_kthread_user_ideal_processor_offset;
	u64 vcpu_off_pending_state;
	u64 vcpu_off_pending_host_rsp_restore;
	u64 vcpu_off_pending_vtcallstack_node;
	u64 vcpu_off_pending_release_delay;
	u64 ghv_size;
	u64 vt_hook_table_bytes;
	u64 ntapi_virtual_alloc;
	u64 ntapi_read_process_memory;
	u64 ntapi_virtual_lock;
	u64 ntapi_d2d1_create_factory;
	u64 ntapi_dwrite_create_factory;
	u64 ob_reference_object_by_handle_va;
	u64 obf_dereference_object_va;
	u64 ntapi_file_name_offset;
	u64 ghv_off_kernel_blank_va;
	u64 ghv_off_csec_scratch_va;
	u64 ghv_off_csec_format_va;
	u64 ghv_off_stop_phase;
	u64 ghv_off_stop_expected_bitmap;
	u64 ghv_off_stop_requested_bitmap;
	u64 ghv_off_stop_before_vmcall_bitmap;
	u64 ghv_off_stop_after_vmcall_bitmap;
	u64 ghv_off_stop_ack_bitmap;
	u64 ghv_off_stop_exception_bitmap;
	u64 ghv_off_stop_cleanup_bitmap;
	u64 ghv_off_stop_last_cpu;
	u64 ghv_off_stop_result;
	u64 vt_hook_slot_off_data_process;
	u64 vt_hook_slot_off_data_filter_by_process;
	u64 vt_hook_slot_off_data_is_enable;
	u64 ghv_off_prot_ranges;
	u64 ghv_off_prot_range_count;
	u64 ghv_prot_range_capacity;
	u64 ghv_prot_range_stride;
	u64 ghv_prot_range_off_base;
	u64 ghv_prot_range_off_end;
	u64 ghv_off_fake_data;
	u64 ghv_off_diag_getbuffer_hits;
	u64 ghv_off_diag_getbuffer_alien;
	u64 ghv_off_diag_present_hits;
	u64 ghv_off_diag_present_alien;
	u64 ghv_off_diag_present1_hits;
	u64 ghv_off_diag_present1_alien;
	u64 ghv_off_diag_copyresource_hits;
	u64 ghv_off_diag_copyresource_alien;
	u64 ghv_off_diag_duplicateoutput_hits;
	u64 ghv_off_diag_duplicateoutput_alien;
	u64 ghv_off_diag_nt_alloc_hits;
	u64 ghv_off_diag_nt_alloc_alien;
	u64 ghv_off_diag_nt_protect_hits;
	u64 ghv_off_diag_nt_protect_alien;
	u64 ghv_off_diag_nt_map_hits;
	u64 ghv_off_diag_nt_map_alien;
	u64 ghv_off_diag_nt_csec_hits;
	u64 ghv_off_diag_nt_csec_image;
	u64 ghv_off_diag_nt_csec_alien;
	u64 ghv_off_diag_capture_notify_count;
	u64 ghv_off_diag_mmcopy_hits;
	u64 ghv_off_diag_mmcopy_last_caller_rip;
	u64 ghv_off_diag_mmcm_hits;
	u64 ghv_off_diag_mmcm_blocked;
	u64 ghv_off_diag_mmcvm_hits;
	u64 ghv_off_diag_mmcvm_blocked;
	u64 ghv_off_diag_mmisav_hits;
	u64 ghv_off_diag_mmisav_blocked;
	u64 ghv_off_diag_mmmio_hits;
	u64 ghv_off_diag_mmmio_blocked;
	u64 dwmcore_base;
	u64 dwmcore_size;
	u64 dxgi_base;
	u64 dxgi_size;
	u64 ghv_off_ept_hook_table;
	u64 ghv_off_pending_ept_install_entries;
	u64 ghv_off_pending_ept_install_bitmap;
	u64 ghv_off_diag_pending_queue_full;
	u64 ghv_pending_install_capacity;
	u64 ept_hook_table_off_lock;
	u64 ept_hook_table_off_in_use_count;
	u64 ept_hook_table_off_active_list_head;
	u64 ept_hook_table_off_free_list_head;
	u64 ept_hook_table_off_buffer;
	u64 ept_hook_table_off_fake_pages;
	u64 ept_hook_table_off_fake_page_pfns;
	u64 ept_hook_table_capacity;
	u64 ept_hook_entry_size;
	u64 ept_hook_entry_off_next;
	u64 ept_hook_entry_off_process;
	u64 ept_hook_entry_off_process_cr3;
	u64 ept_hook_entry_off_va;
	u64 ept_hook_entry_off_orig_pfn;
	u64 ept_hook_entry_off_fake_pfn;
	u64 ept_hook_entry_off_fake_page_idx;
	u64 ept_hook_entry_off_in_use;
	u64 ept_hook_entry_off_is_fake_page;
	u64 ept_hook_entry_off_per_vcpu_active_bitmap;
	u64 nt_create_section_va;
	u64 nt_set_event_va;
	u64 nt_allocate_virtual_memory_va;
	u64 nt_protect_virtual_memory_va;
	u64 nt_map_view_of_section_va;
	u64 mm_copy_memory_va;
	u64 mm_copy_virtual_memory_va;
	u64 mm_is_address_valid_va;
	u64 mm_map_io_space_va;
	u64 mm_is_address_valid_ex_va;
	u64 nt_query_virtual_memory_va;
	u64 mm_get_physical_address_va;
	u64 ghv_off_copyresource_addr;
	u64 ghv_off_duplicateoutput_addr;
	u64 vcpu_off_ctx;
	u64 ghv_off_pending_ept_invept_bitmap;
	u64 ghv_off_pending_hide_pfns;
	u64 ghv_off_pending_hide_count;
	u64 ghv_off_pending_hide_vcpu_bitmap;
	u64 ghv_off_pending_hide_tsc_threshold;
	u64 ghv_off_diag_per_vcpu_vmexits;
	u64 vcpu_off_hide_vm_exit_overhead;
	u64 vcpu_off_stop_virtualization;
	u64 vcpu_off_ept_mmr_mtf_pte;
	u64 vcpu_off_ept_mmr_mtf_mode;
	u64 vcpu_off_ept_mmr_mtf_page_frame;
	u64 vcpu_ept_hook_node_off_next;
	u64 vcpu_ept_hook_node_off_orig_pfn;
	u64 vcpu_ept_hook_node_off_exec_pfn;
	u64 vcpu_ept_hook_node_off_is_fake_page;
};

static_assert(sizeof(resident_hv_diag_record) == 0x630,
	"AMD resident_hv_diag_record must match mapctl_hv_diag layout");

inline bool guest_cpl0(vmcb const* const v) {
	return (((v->ss.attrib >> 5) & 3) == 0);
}

inline void mark_vmcb_dirty(vmcb* const v) {
	v->vmcb_clean_bits = 0;
}

cr3 current_guest_cr3(vmcb const* const v) {
	cr3 value = {};
	value.flags = v->cr3;
	return value;
}

void* guest_va_to_host(vmcb const* const v, void* const gva, size_t* const remain = nullptr) {
	return hv::gva2hva(current_guest_cr3(v), gva, remain);
}

u32 vcpu_index(hv::vcpu* const cpu) {
	return static_cast<u32>(cpu - hv::g_ghv->vcpus);
}

u64 page_align(u64 const va) {
	return va & ~0xfffull;
}

void deactivate_npt_exec_root(vmcb* const v, hv::vcpu* const cpu) {
	if (!v || !cpu || !cpu->svm.npt || !npt_exec_view_active(*cpu->svm.npt))
		return;

	deactivate_npt_exec_view(*cpu->svm.npt);
	v->n_cr3 = cpu->svm.npt_pml4_pa;
	v->tlb_control = 1;
	mark_vmcb_dirty(v);
}

bool activate_npt_exec_root(vmcb* const v, hv::vcpu* const cpu, npt_hook_node const& hook) {
	if (!v || !cpu || !cpu->svm.npt)
		return false;

	if (!activate_npt_exec_view(*cpu->svm.npt, hook))
		return false;

	v->n_cr3 = npt_exec_root_pa(*cpu->svm.npt);
	v->tlb_control = 1;
	mark_vmcb_dirty(v);
	return true;
}

u64 read_process_cr3(PEPROCESS const process) {
	if (!process)
		return 0;
	u64 value = 0;
	auto const addr = reinterpret_cast<u8*>(process) + hv::g_ghv->kprocess_directory_table_base_offset;
	if (hv::read_guest_virtual_memory(hv::g_ghv->system_cr3, addr, &value, sizeof(value)) != sizeof(value))
		return 0;
	return value & ~0xfffull;
}

u64 resolve_process_cr3(PEPROCESS const process) {
	if (!process || reinterpret_cast<u8*>(process) == hv::g_ghv->system_eprocess)
		return hv::g_ghv->system_cr3.flags & ~0xfffull;
	return read_process_cr3(process);
}

void inject_page_fault(vmcb* const v,
	hv::guest_context* const ctx,
	u64 const fault_va,
	bool const write)
{
	ctx->cr2 = fault_va;
	v->cr2 = fault_va;
	amd64_page_fault_error_code error = {};
	error.present = 0;
	error.write = write ? 1 : 0;
	error.user = guest_cpl0(v) ? 0 : 1;
	inject_exception(v, amd64_page_fault, error.value);
}

void set_event(vmcb* const v, u32 const vector, bool const has_error, u32 const error) {
	event_injection inj = {};
	inj.vector = vector;
	inj.type = 3; // hardware exception
	inj.error_code_valid = has_error ? 1 : 0;
	inj.valid = 1;
	inj.error_code = error;
	v->eventinj = inj;
	mark_vmcb_dirty(v);
}

void clear_event(vmcb* const v) {
	v->eventinj.flags = 0;
	v->tlb_control = 0;
}

void reinject_exitintinfo_if_valid(vmcb* const v) {
	event_injection pending = {};
	pending.flags = v->exitintinfo;
	if (!pending.valid)
		return;

	v->eventinj.flags = v->exitintinfo;
	mark_vmcb_dirty(v);
}

void cpuidex(u32 const leaf, u32 const subleaf, int regs[4]) {
	__cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
}

void emulate_cpuid(vmcb* const v, hv::guest_context* const ctx) {
	int regs[4] = {};
	auto const leaf = ctx->eax;
	auto const subleaf = ctx->ecx;

	cpuidex(leaf, subleaf, regs);

	// Anti-detect posture for AMD: present bare-metal AMD instead of exposing
	// our nested SVM state.  Hypervisor leaves are zero and SVM CPUID leaves
	// are masked even though SVME remains set in the host VMCB.
	if (leaf == 0x00000001) {
		regs[2] &= ~static_cast<int>(amd64_cpuid_hv_presence_bit);
	} else if (leaf >= 0x40000000 && leaf <= 0x4fffffff) {
		regs[0] = regs[1] = regs[2] = regs[3] = 0;
	} else if (leaf == amd64_cpuid_ext_proc_feature) {
		regs[2] &= ~static_cast<int>(amd64_cpuid_svm_bit);
	} else if (leaf == amd64_cpuid_ext_svm_features) {
		regs[0] = regs[1] = regs[2] = regs[3] = 0;
	}

	ctx->rax = static_cast<u32>(regs[0]);
	ctx->rbx = static_cast<u32>(regs[1]);
	ctx->rcx = static_cast<u32>(regs[2]);
	ctx->rdx = static_cast<u32>(regs[3]);
	v->rax = ctx->rax;

	advance_guest_ip(v, 2);
}

bool emulate_rdmsr(vmcb* const v, hv::vcpu* const cpu, hv::guest_context* const ctx) {
	u64 value = 0;
	u32 const msr = ctx->ecx;

	switch (msr) {
	case amd64_efer:
		value = cpu->svm.guest_efer & ~amd64_efer_svme_bit;
		break;
	case amd64_vmcr:
		value = cpu->svm.guest_vm_cr | (1ull << amd64_vmcr_svmdis);
		break;
	case amd64_hsave_pa:
	case amd64_svm_key:
	case amd64_svm_ghcb_pa:
	case amd64_sev_status:
		value = 0;
		break;
	default: {
		hv::host_exception_info e = {};
		value = hv::rdmsr_safe(e, msr);
		if (e.exception_occurred) {
			inject_exception(v, amd64_general_protection, 0);
			return false;
		}
		break;
	}
	}

	ctx->rax = static_cast<u32>(value);
	ctx->rdx = static_cast<u32>(value >> 32);
	v->rax = ctx->rax;
	advance_guest_ip(v, 2);
	return true;
}

bool emulate_wrmsr(vmcb* const v, hv::vcpu* const cpu, hv::guest_context* const ctx) {
	u32 const msr = ctx->ecx;
	u64 const value = (ctx->rdx << 32) | ctx->eax;

	switch (msr) {
	case amd64_efer:
		cpu->svm.guest_efer = value & ~amd64_efer_svme_bit;
		v->efer = cpu->svm.guest_efer | amd64_efer_svme_bit;
		mark_vmcb_dirty(v);
		break;
	case amd64_vmcr:
		cpu->svm.guest_vm_cr = value | (1ull << amd64_vmcr_svmdis);
		break;
	case amd64_hsave_pa:
		cpu->svm.guest_hsave_pa = value;
		break;
	case amd64_debug_control:
		// Match the Intel backend posture: guest reads see the VMCB value, but
		// writes cannot enable LBR/BTS/BTF.  BTF in particular breaks the
		// RFLAGS.TF based NPT hook restore path on AMD.
		v->dbgctl = 0;
		mark_vmcb_dirty(v);
		break;
	case amd64_svm_key:
	case amd64_svm_ghcb_pa:
	case amd64_sev_status:
		// Keep host SVM/SEV-related state immutable and guest-inert.
		break;
	default: {
		hv::host_exception_info e = {};
		hv::wrmsr_safe(e, msr, value);
		if (e.exception_occurred) {
			inject_exception(v, amd64_general_protection, 0);
			return false;
		}
		break;
	}
	}

	advance_guest_ip(v, 2);
	return true;
}

bool handle_msr(vmcb* const v, hv::vcpu* const cpu, hv::guest_context* const ctx) {
	// EXITINFO1: 0 = RDMSR, 1 = WRMSR (same convention used by DBVM).
	if (v->exitinfo1)
		return emulate_wrmsr(v, cpu, ctx);
	return emulate_rdmsr(v, cpu, ctx);
}

bool amd_read_phys(vmcb* const v, hv::guest_context* const ctx) {
	auto const dst = reinterpret_cast<u8*>(ctx->rcx);
	auto const src_pa = ctx->rdx;
	auto const size = ctx->r8;
	u64 done = 0;

	while (done < size) {
		size_t dst_remaining = 0;
		auto const curr_dst = guest_va_to_host(v, dst + done, &dst_remaining);
		if (!curr_dst) {
			inject_page_fault(v, ctx, reinterpret_cast<u64>(dst + done), true);
			return false;
		}

		auto const curr_size = min(size - done, dst_remaining);
		auto const curr_src = hv::host_physical_to_virtual(src_pa + done, curr_size);
		if (!curr_src) {
			inject_exception(v, amd64_general_protection, 0);
			return false;
		}

		hv::host_exception_info e = {};
		hv::memcpy_safe(e, curr_dst, curr_src, curr_size);
		if (e.exception_occurred) {
			inject_exception(v, amd64_general_protection, 0);
			return false;
		}

		done += curr_size;
	}

	ctx->rax = done;
	return true;
}

bool amd_write_phys(vmcb* const v, hv::guest_context* const ctx) {
	auto const dst_pa = ctx->rcx;
	auto const src = reinterpret_cast<u8*>(ctx->rdx);
	auto const size = ctx->r8;
	u64 done = 0;

	while (done < size) {
		size_t src_remaining = 0;
		auto const curr_src = guest_va_to_host(v, src + done, &src_remaining);
		if (!curr_src) {
			inject_page_fault(v, ctx, reinterpret_cast<u64>(src + done), false);
			return false;
		}

		auto const curr_size = min(size - done, src_remaining);
		auto const curr_dst = hv::host_physical_to_virtual(dst_pa + done, curr_size);
		if (!curr_dst) {
			inject_exception(v, amd64_general_protection, 0);
			return false;
		}

		hv::host_exception_info e = {};
		hv::memcpy_safe(e, curr_dst, curr_src, curr_size);
		if (e.exception_occurred) {
			inject_exception(v, amd64_general_protection, 0);
			return false;
		}

		done += curr_size;
	}

	ctx->rax = done;
	return true;
}

bool amd_read_virt(vmcb* const v, hv::guest_context* const ctx) {
	cr3 src_cr3 = hv::g_ghv->system_cr3;
	if (ctx->rcx)
		src_cr3.flags = ctx->rcx;

	auto const dst = reinterpret_cast<u8*>(ctx->rdx);
	auto const src = reinterpret_cast<u8*>(ctx->r8);
	auto const size = ctx->r9;
	u64 done = 0;

	while (done < size) {
		size_t dst_remaining = 0;
		size_t src_remaining = 0;
		auto const curr_dst = guest_va_to_host(v, dst + done, &dst_remaining);
		auto const curr_src = hv::gva2hva(src_cr3, src + done, &src_remaining);

		if (!curr_dst) {
			inject_page_fault(v, ctx, reinterpret_cast<u64>(dst + done), true);
			return false;
		}
		if (!curr_src)
			break;

		auto const curr_size = min(size - done, min(dst_remaining, src_remaining));
		hv::host_exception_info e = {};
		hv::memcpy_safe(e, curr_dst, curr_src, curr_size);
		if (e.exception_occurred) {
			inject_exception(v, amd64_general_protection, 0);
			return false;
		}
		done += curr_size;
	}

	ctx->rax = done;
	return true;
}

bool amd_write_virt(vmcb* const v, hv::guest_context* const ctx) {
	cr3 dst_cr3 = hv::g_ghv->system_cr3;
	if (ctx->rcx)
		dst_cr3.flags = ctx->rcx;

	auto const dst = reinterpret_cast<u8*>(ctx->rdx);
	auto const src = reinterpret_cast<u8*>(ctx->r8);
	auto const size = ctx->r9;
	u64 done = 0;

	while (done < size) {
		size_t dst_remaining = 0;
		size_t src_remaining = 0;
		auto const curr_dst = hv::gva2hva(dst_cr3, dst + done, &dst_remaining);
		auto const curr_src = guest_va_to_host(v, src + done, &src_remaining);

		if (!curr_src) {
			inject_page_fault(v, ctx, reinterpret_cast<u64>(src + done), false);
			return false;
		}
		if (!curr_dst)
			break;

		auto const curr_size = min(size - done, min(dst_remaining, src_remaining));
		hv::host_exception_info e = {};
		hv::memcpy_safe(e, curr_dst, curr_src, curr_size);
		if (e.exception_occurred) {
			inject_exception(v, amd64_general_protection, 0);
			return false;
		}
		done += curr_size;
	}

	ctx->rax = done;
	return true;
}

void amd_query_process_cr3(hv::guest_context* const ctx) {
	auto const target_pid = ctx->rcx;
	if (target_pid == 4) {
		ctx->rax = hv::g_ghv->system_cr3.flags;
		return;
	}

	ctx->rax = 0;
	auto const apl_offset = hv::g_ghv->eprocess_unique_process_id_offset + 8;
	auto const head = hv::g_ghv->system_eprocess + apl_offset;
	auto curr_entry = head;

	do {
		if (sizeof(curr_entry) != hv::read_guest_virtual_memory(hv::g_ghv->system_cr3,
			reinterpret_cast<void*>(curr_entry + offsetof(LIST_ENTRY, Flink)),
			&curr_entry,
			sizeof(curr_entry)))
			break;

		auto const process = curr_entry - apl_offset;
		u64 pid = 0;
		if (sizeof(pid) != hv::read_guest_virtual_memory(hv::g_ghv->system_cr3,
			reinterpret_cast<void*>(process + hv::g_ghv->eprocess_unique_process_id_offset),
			&pid,
			sizeof(pid)))
			break;

		if (target_pid == pid) {
			u64 process_cr3 = 0;
			if (sizeof(process_cr3) == hv::read_guest_virtual_memory(hv::g_ghv->system_cr3,
				reinterpret_cast<void*>(process + hv::g_ghv->kprocess_directory_table_base_offset),
				&process_cr3,
				sizeof(process_cr3)))
				ctx->rax = process_cr3;
			break;
		}
	} while (curr_entry != head);
}

bool amd_eh_install_self(hv::vcpu* const cpu, hv::eh::ept_hook_entry* const entry) {
	if (!cpu || !entry || !hv::g_ghv->vcpus)
		return false;

	auto const self_idx = vcpu_index(cpu);
	if (self_idx >= 64)
		return false;

	u64 const bit = 1ull << self_idx;
	auto& t = hv::g_ghv->ept_hook_table;
	t.lock.acquire();
	bool linked = false;
	for (auto e = t.active_list_head; e; e = e->next) {
		if (e == entry) {
			linked = true;
			break;
		}
	}
	if (!entry->in_use || !linked) {
		t.lock.release();
		return false;
	}
	bool const already = (entry->per_vcpu_active_bitmap & bit) != 0;
	auto const orig_pfn = entry->orig_pfn;
	auto const fake_pfn = entry->fake_pfn;
	bool const is_fake_page = entry->is_fake_page;
	t.lock.release();

	if (already)
		return true;

	if (!cpu->svm.npt ||
		!install_npt_hook(*cpu->svm.npt, orig_pfn, fake_pfn, is_fake_page))
		return false;

	t.lock.acquire();
	entry->per_vcpu_active_bitmap |= bit;
	t.lock.release();
	return true;
}

void cancel_pending_npt_install(hv::eh::ept_hook_entry* const entry) {
	if (!entry)
		return;

	for (u32 i = 0; i < hv::g_ghv->pending_install_capacity; ++i) {
		_InterlockedCompareExchangePointer(
			reinterpret_cast<PVOID volatile*>(&hv::g_ghv->pending_ept_install_entries[i]),
			nullptr,
			entry);
	}
}

bool amd_eh_install_all(hv::vcpu* const cpu, hv::eh::ept_hook_entry* const entry) {
	if (!entry)
		return false;

	bool const installed_self = amd_eh_install_self(cpu, entry);
	if (!installed_self)
		return false;

	bool placed = false;
	for (u32 i = 0; i < hv::g_ghv->pending_install_capacity; ++i) {
		auto const prev = _InterlockedCompareExchangePointer(
			reinterpret_cast<PVOID volatile*>(&hv::g_ghv->pending_ept_install_entries[i]),
			entry,
			nullptr);
		if (prev == nullptr || prev == entry) {
			placed = true;
			break;
		}
	}

	if (!placed) {
		_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_pending_queue_full));
		return installed_self;
	}

	u32 const vc = hv::g_ghv->vcpu_count;
	auto const self = vcpu_index(cpu);
	u64 const full_mask = (vc >= 64) ? ~0ull : ((1ull << vc) - 1);
	u64 const others = full_mask & ~(1ull << self);
	if (others)
		_InterlockedOr64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->pending_ept_install_bitmap),
			static_cast<LONG64>(others));

	return installed_self;
}

void drain_pending_npt_installs(vmcb* const v, hv::vcpu* const cpu) {
	if (!v || !cpu || !hv::g_ghv->vcpus)
		return;

	auto const self_idx = vcpu_index(cpu);
	if (self_idx >= 64)
		return;

	u64 const my_bit = 1ull << self_idx;
	if ((hv::g_ghv->pending_ept_install_bitmap & my_bit) == 0)
		return;

	if (v->exitcode == vmexit_npf &&
		cpu->svm.npt &&
		npt_exec_view_active(*cpu->svm.npt))
		return;

	deactivate_npt_exec_root(v, cpu);

	u32 const vc = hv::g_ghv->vcpu_count;
	u64 const full_mask = (vc >= 64) ? ~0ull : ((1ull << vc) - 1);
	bool installed_any = false;

	for (u32 i = 0; i < hv::g_ghv->pending_install_capacity; ++i) {
		auto const entry = hv::g_ghv->pending_ept_install_entries[i];
		if (!entry)
			continue;

		if (amd_eh_install_self(cpu, entry))
			installed_any = true;

		auto& t = hv::g_ghv->ept_hook_table;
		t.lock.acquire();
		bool const retire = (entry->per_vcpu_active_bitmap & full_mask) == full_mask;
		t.lock.release();
		if (retire) {
			_InterlockedCompareExchangePointer(
				reinterpret_cast<PVOID volatile*>(&hv::g_ghv->pending_ept_install_entries[i]),
				nullptr,
				entry);
		}
	}

	_InterlockedAnd64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->pending_ept_install_bitmap),
		static_cast<LONG64>(~my_bit));

	if (installed_any) {
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
	}
}

hv::eh::ept_hook_entry* amd_find_eh_entry(PEPROCESS const process, u64 const va_page) {
	auto const process_cr3 = resolve_process_cr3(process);
	auto& t = hv::g_ghv->ept_hook_table;
	t.lock.acquire();
	auto entry = hv::eh::find_entry_locked(process_cr3, va_page);
	t.lock.release();
	return entry;
}

hv::eh::ept_hook_entry* amd_prepare_eh_entry(PEPROCESS process,
	u64 va,
	bool full_zero,
	bool is_fake_page,
	bool* out_fresh);
void restore_npt_single_step(vmcb* v, hv::vcpu* cpu, bool reflect_db);

struct pending_raw_npt_hook {
	volatile LONG allocated;
	u64 orig_pfn;
	u64 exec_pfn;
	bool is_fake_page;
	u8 reserved[7];
	volatile LONG64 installed_bitmap;
};

constexpr u32 pending_raw_npt_hook_capacity = 64;
pending_raw_npt_hook g_pending_raw_npt_hooks[pending_raw_npt_hook_capacity] = {};
volatile LONG64 g_pending_raw_npt_bitmap = 0;

struct pending_raw_npt_remove {
	volatile LONG allocated;
	u64 orig_pfn;
	volatile LONG64 removed_bitmap;
};

pending_raw_npt_remove g_pending_raw_npt_removes[pending_raw_npt_hook_capacity] = {};
volatile LONG64 g_pending_raw_npt_remove_bitmap = 0;

u64 active_vcpu_mask() {
	u32 const count = hv::g_ghv->vcpu_count;
	if (!count)
		return 0;
	return count >= 64 ? ~0ull : ((1ull << count) - 1);
}

bool install_raw_npt_hook_self(hv::vcpu* const cpu,
	u64 const orig_pfn,
	u64 const exec_pfn,
	bool const is_fake_page)
{
	if (!cpu || !cpu->svm.npt || !orig_pfn || !exec_pfn)
		return false;

	if (auto const existing = find_npt_hook(*cpu->svm.npt, orig_pfn))
		return existing->exec_pfn == exec_pfn &&
			existing->is_fake_page == is_fake_page;

	return install_npt_hook(*cpu->svm.npt, orig_pfn, exec_pfn, is_fake_page);
}

bool enqueue_raw_npt_hook_all(hv::vcpu* const cpu,
	u64 const orig_pfn,
	u64 const exec_pfn,
	bool const is_fake_page)
{
	if (!cpu || !hv::g_ghv->vcpus || !orig_pfn || !exec_pfn)
		return false;

	auto const self = vcpu_index(cpu);
	if (self >= 64)
		return false;

	auto const self_bit = 1ull << self;
	auto const full_mask = active_vcpu_mask();
	bool const installed_self =
		install_raw_npt_hook_self(cpu, orig_pfn, exec_pfn, is_fake_page);

	pending_raw_npt_hook* slot = nullptr;
	for (u32 i = 0; i < pending_raw_npt_hook_capacity; ++i) {
		auto& e = g_pending_raw_npt_hooks[i];
		if (e.allocated &&
			e.orig_pfn == orig_pfn &&
			e.exec_pfn == exec_pfn &&
			e.is_fake_page == is_fake_page) {
			slot = &e;
			break;
		}
	}

	if (!slot) {
		for (u32 i = 0; i < pending_raw_npt_hook_capacity; ++i) {
			auto& e = g_pending_raw_npt_hooks[i];
			if (_InterlockedCompareExchange(&e.allocated, 1, 0) == 0) {
				e.orig_pfn = orig_pfn;
				e.exec_pfn = exec_pfn;
				e.is_fake_page = is_fake_page;
				e.installed_bitmap = 0;
				slot = &e;
				break;
			}
		}
	}

	if (!slot)
		return installed_self;

	if (installed_self)
		_InterlockedOr64(&slot->installed_bitmap, static_cast<LONG64>(self_bit));

	auto const installed = static_cast<u64>(slot->installed_bitmap);
	auto const pending = full_mask & ~installed;
	if (pending)
		_InterlockedOr64(&g_pending_raw_npt_bitmap, static_cast<LONG64>(pending));

	return installed_self;
}

void cancel_pending_raw_npt_hook(u64 const orig_pfn) {
	for (u32 i = 0; i < pending_raw_npt_hook_capacity; ++i) {
		auto& e = g_pending_raw_npt_hooks[i];
		if (e.allocated && e.orig_pfn == orig_pfn)
			_InterlockedExchange(&e.allocated, 0);
	}
}

bool remove_raw_npt_hook_self(hv::vcpu* const cpu, u64 const orig_pfn) {
	if (!cpu || !cpu->svm.npt || !orig_pfn)
		return false;
	if (!find_npt_hook(*cpu->svm.npt, orig_pfn))
		return true;
	remove_npt_hook(*cpu->svm.npt, orig_pfn);
	return true;
}

bool enqueue_raw_npt_remove_all(hv::vcpu* const cpu, u64 const orig_pfn) {
	if (!cpu || !hv::g_ghv->vcpus || !orig_pfn)
		return false;

	auto const self = vcpu_index(cpu);
	if (self >= 64)
		return false;

	cancel_pending_raw_npt_hook(orig_pfn);

	auto const self_bit = 1ull << self;
	auto const full_mask = active_vcpu_mask();
	bool const removed_self = remove_raw_npt_hook_self(cpu, orig_pfn);

	pending_raw_npt_remove* slot = nullptr;
	for (u32 i = 0; i < pending_raw_npt_hook_capacity; ++i) {
		auto& e = g_pending_raw_npt_removes[i];
		if (e.allocated && e.orig_pfn == orig_pfn) {
			slot = &e;
			break;
		}
	}

	if (!slot) {
		for (u32 i = 0; i < pending_raw_npt_hook_capacity; ++i) {
			auto& e = g_pending_raw_npt_removes[i];
			if (_InterlockedCompareExchange(&e.allocated, 1, 0) == 0) {
				e.orig_pfn = orig_pfn;
				e.removed_bitmap = 0;
				slot = &e;
				break;
			}
		}
	}

	if (!slot)
		return removed_self;

	if (removed_self)
		_InterlockedOr64(&slot->removed_bitmap, static_cast<LONG64>(self_bit));

	auto const removed = static_cast<u64>(slot->removed_bitmap);
	auto const pending = full_mask & ~removed;
	if (pending)
		_InterlockedOr64(&g_pending_raw_npt_remove_bitmap, static_cast<LONG64>(pending));

	return removed_self;
}

void drain_pending_raw_npt_hooks(vmcb* const v, hv::vcpu* const cpu) {
	if (!v || !cpu || !hv::g_ghv->vcpus)
		return;

	auto const self = vcpu_index(cpu);
	if (self >= 64)
		return;

	auto const self_bit = 1ull << self;
	if ((static_cast<u64>(g_pending_raw_npt_bitmap) & self_bit) == 0)
		return;

	if (v->exitcode == vmexit_npf &&
		cpu->svm.npt &&
		npt_exec_view_active(*cpu->svm.npt))
		return;

	deactivate_npt_exec_root(v, cpu);

	auto const full_mask = active_vcpu_mask();
	bool installed_any = false;
	for (u32 i = 0; i < pending_raw_npt_hook_capacity; ++i) {
		auto& e = g_pending_raw_npt_hooks[i];
		if (!e.allocated)
			continue;

		if (install_raw_npt_hook_self(cpu, e.orig_pfn, e.exec_pfn, e.is_fake_page)) {
			installed_any = true;
			auto const before = static_cast<u64>(
				_InterlockedOr64(&e.installed_bitmap, static_cast<LONG64>(self_bit)));
			auto const after = before | self_bit;
			if ((after & full_mask) == full_mask)
				_InterlockedExchange(&e.allocated, 0);
		}
	}

	_InterlockedAnd64(&g_pending_raw_npt_bitmap, static_cast<LONG64>(~self_bit));

	if (installed_any) {
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
	}
}

void drain_pending_raw_npt_removes(vmcb* const v, hv::vcpu* const cpu) {
	if (!v || !cpu || !hv::g_ghv->vcpus)
		return;

	auto const self = vcpu_index(cpu);
	if (self >= 64)
		return;

	auto const self_bit = 1ull << self;
	if ((static_cast<u64>(g_pending_raw_npt_remove_bitmap) & self_bit) == 0)
		return;

	if (v->exitcode == vmexit_npf &&
		cpu->svm.npt &&
		npt_exec_view_active(*cpu->svm.npt))
		return;

	deactivate_npt_exec_root(v, cpu);

	auto const full_mask = active_vcpu_mask();
	bool removed_any = false;
	for (u32 i = 0; i < pending_raw_npt_hook_capacity; ++i) {
		auto& e = g_pending_raw_npt_removes[i];
		if (!e.allocated)
			continue;

		if (remove_raw_npt_hook_self(cpu, e.orig_pfn)) {
			removed_any = true;
			auto const before = static_cast<u64>(
				_InterlockedOr64(&e.removed_bitmap, static_cast<LONG64>(self_bit)));
			auto const after = before | self_bit;
			if ((after & full_mask) == full_mask)
				_InterlockedExchange(&e.allocated, 0);
		}
	}

	_InterlockedAnd64(&g_pending_raw_npt_remove_bitmap, static_cast<LONG64>(~self_bit));

	if (removed_any) {
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
	}
}

int amd_vh_find_slot_by_address(u64 const target_va) {
	for (int i = 0; i < VMCALL_HOOK_MAX; ++i) {
		auto& s = hv::g_vt_hook_table[i];
		if (s.occupied && reinterpret_cast<u64>(s.data.address) == target_va)
			return i;
	}
	return -1;
}

int amd_vh_find_free_slot() {
	for (int i = 0; i < VMCALL_HOOK_MAX; ++i) {
		if (!hv::g_vt_hook_table[i].occupied)
			return i;
	}
	return -1;
}

u64 amd_vh_effective_cr3_for_target(PEPROCESS const process, u64 const target_va) {
	if (target_va >= 0xffff800000000000ull && hv::g_ghv->system_cr3.flags)
		return hv::g_ghv->system_cr3.flags & ~0xfffull;
	return resolve_process_cr3(process);
}

void amd_vh_apply_enable_transition_hva(void* const fake_hva) {
	if (!fake_hva)
		return;

	// AMD must execute VMMCALL (0F 01 D9).  Intel's VTCall fake page uses
	// VMCALL (0F 01 C1), which #UDs on AMD before our VMMCALL intercept.
	static constexpr u8 vmmcall_stub[3] = { 0x0f, 0x01, 0xd9 };
	RtlCopyMemory(fake_hva, vmmcall_stub, sizeof(vmmcall_stub));
	__invlpg(fake_hva);
}

u64 amd_vh_find_blank_host(u64 const start, u64 const max_scan, u64 const target_cr3) {
	cr3 c = {};
	c.flags = target_cr3;

	u64 scanned = 0;
	while (scanned < max_scan) {
		u64 const va = start + scanned;
		size_t to_read = min(0x1000ull, max_scan - scanned);
		size_t const page_off = va & 0xfffull;
		if (page_off + to_read > 0x1000)
			to_read = 0x1000 - page_off;

		u8 page[0x1000] = {};
		size_t const got = hv::read_guest_virtual_memory(c,
			reinterpret_cast<void*>(va),
			page,
			to_read);
		if (got < 4) {
			scanned += (0x1000 - page_off);
			continue;
		}

		for (size_t i = 0; i + 3 < got; ++i) {
			if (page[i] == 0xcc &&
				page[i + 1] == 0xcc &&
				page[i + 2] == 0xcc &&
				page[i + 3] == 0xcc)
				return va + i + 1;
		}
		scanned += got;
	}
	return 0;
}

u64 amd_vh_find_blank_page_host(u64 const start, u64 const max_scan, u64 const target_cr3) {
	cr3 c = {};
	c.flags = target_cr3;

	u64 va = (start + 0xfffull) & ~0xfffull;
	u64 const end = start + max_scan;
	while (va + 0x1000 <= end) {
		u8 page[0x1000] = {};
		size_t const got = hv::read_guest_virtual_memory(c,
			reinterpret_cast<void*>(va),
			page,
			0x1000);
		if (got < 0x1000) {
			va += 0x1000;
			continue;
		}

		bool all_cc = true;
		for (size_t i = 0; i < 0x1000; ++i) {
			if (page[i] != 0xcc) {
				all_cc = false;
				break;
			}
		}
		if (all_cc)
			return va;
		va += 0x1000;
	}
	return 0;
}

bool amd_vh_disasm_target_host(u64 const target_va,
	u64 const target_cr3,
	u32& out_size,
	u64& out_next_va,
	u8(&out_old)[20],
	u8(&out_next_old)[20])
{
	cr3 c = {};
	c.flags = target_cr3;

	u8 code_buf[32] = {};
	auto const got = hv::read_guest_virtual_memory(c,
		reinterpret_cast<void*>(target_va),
		code_buf,
		sizeof(code_buf));
	if (got < 4)
		return false;

	u32 size = 0;
	while (size < 3 && size < sizeof(code_buf)) {
		hde64s hs = {};
		hde64_disasm(code_buf + size, &hs);
		if (hs.len == 0)
			return false;
		size += hs.len;
	}
	if (!size || size > sizeof(out_old))
		return false;

	if ((target_va & 0xfffull) + 3 > 0x1000) {
		_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_install_xpage_stub));
		return false;
	}
	if (((target_va + size - 1) >> 12) != (target_va >> 12))
		_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_install_xpage_resume));

	out_size = size;
	out_next_va = target_va + size;
	RtlZeroMemory(out_old, sizeof(out_old));
	RtlZeroMemory(out_next_old, sizeof(out_next_old));
	RtlCopyMemory(out_old, code_buf, size);

	u8 next_buf[8] = {};
	if (hv::read_guest_virtual_memory(c,
		reinterpret_cast<void*>(out_next_va),
		next_buf,
		3) >= 3)
		RtlCopyMemory(out_next_old, next_buf, 3);
	return true;
}

bool amd_vh_alloc_trampoline(u64 const target_va,
	u8 const* const old_bytes,
	u32 const size,
	bool const is_kernel,
	u64& out_tramp_va,
	u64& out_bp_rip,
	u64& out_target_resume)
{
	auto& pool = hv::g_ghv->tramp_pool;
	pool.lock.acquire();

	bool const ready = is_kernel ? pool.kernel_ready : pool.user_ready;
	hv::g_ghv->diag_alloc_is_kernel = is_kernel ? 1 : 0;
	hv::g_ghv->diag_alloc_pool_ready = ready ? 1 : 0;
	if (!ready) {
		pool.lock.release();
		return false;
	}

	auto slots = is_kernel ? pool.kernel_slots : pool.user_slots;
	auto const slot_count = is_kernel ? pool.kernel_slot_count : pool.user_slot_count;
	auto pages = is_kernel ? pool.kernel_pages : pool.user_pages;
	u32 const needed = size + 1;
	hv::g_ghv->diag_alloc_slot_count = slot_count;
	hv::g_ghv->diag_alloc_needed = needed;

	int idx = -1;
	for (u32 i = 0; i < slot_count; ++i) {
		if (slots[i].occupied || slots[i].capacity < needed)
			continue;
		if (static_cast<u32>(slots[i].page_offset) +
			static_cast<u32>(slots[i].capacity) > 0x1000) {
			_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_alloc_xpage_skipped));
			continue;
		}
		idx = static_cast<int>(i);
		break;
	}
	if (idx < 0) {
		pool.lock.release();
		return false;
	}

	auto& s = slots[idx];
	auto& pg = pages[s.page_index];
	auto const exec_base = static_cast<u8*>(hv::host_physical_to_virtual(pg.exec_pfn << 12));
	if (!exec_base) {
		pool.lock.release();
		return false;
	}

	auto const exec_hva = exec_base + s.page_offset;
	RtlCopyMemory(exec_hva, old_bytes, size);
	exec_hva[size] = 0xcc;

	s.occupied = true;
	s.tramp_va = pg.guest_page_va + s.page_offset;
	s.bp_rip = s.tramp_va + size;
	s.target_resume = target_va + size;

	out_tramp_va = s.tramp_va;
	out_bp_rip = s.bp_rip;
	out_target_resume = s.target_resume;
	pool.lock.release();
	return true;
}

void amd_vh_free_trampoline(u64 const tramp_va) {
	if (!tramp_va)
		return;

	auto& pool = hv::g_ghv->tramp_pool;
	pool.lock.acquire();
	auto release = [&](hv::tramp_slot* slots, u32 const count) -> bool {
		for (u32 i = 0; i < count; ++i) {
			if (slots[i].occupied && slots[i].tramp_va == tramp_va) {
				slots[i].occupied = false;
				slots[i].tramp_va = 0;
				slots[i].bp_rip = 0;
				slots[i].target_resume = 0;
				return true;
			}
		}
		return false;
	};
	if (!release(pool.user_slots, pool.user_slot_count))
		release(pool.kernel_slots, pool.kernel_slot_count);
	pool.lock.release();
}

bool amd_vh_remove_target_hook_current(hv::vcpu* const cpu,
	PEPROCESS const process,
	u64 const target_va,
	bool* const out_free_now = nullptr)
{
	if (out_free_now)
		*out_free_now = false;
	if (!cpu || !hv::g_ghv->vcpus)
		return false;

	auto const target_cr3 = amd_vh_effective_cr3_for_target(process, target_va);
	if (!target_cr3)
		return false;

	auto const self = vcpu_index(cpu);
	if (self >= 64)
		return false;
	auto const self_bit = 1ull << self;
	auto const va_page = page_align(target_va);

	auto& t = hv::g_ghv->ept_hook_table;
	t.lock.acquire();
	auto const entry = hv::eh::find_entry_locked(target_cr3, va_page);
	if (!entry) {
		t.lock.release();
		return false;
	}

	bool const was_active = (entry->per_vcpu_active_bitmap & self_bit) != 0;
	if (was_active)
		entry->per_vcpu_active_bitmap &= ~self_bit;
	auto const orig_pfn = entry->orig_pfn;
	bool const free_now = entry->per_vcpu_active_bitmap == 0;
	if (free_now) {
		cancel_pending_npt_install(entry);
		hv::eh::free_entry_locked(entry);
	}
	t.lock.release();

	if (was_active && cpu->svm.npt)
		remove_npt_hook(*cpu->svm.npt, orig_pfn);
	if (out_free_now)
		*out_free_now = free_now;
	return was_active;
}

bool amd_vh_install(hv::vcpu* const cpu,
	PEPROCESS const process,
	u64 const target_va,
	u64 const blank_mem,
	u8 const type,
	u8 const dispatch_mode,
	bool const filter_by_process,
	bool const auto_enable)
{
	static volatile LONG s_install_lock = 0;
	while (_InterlockedCompareExchange(&s_install_lock, 1, 0) != 0)
		_mm_pause();

	hv::g_ghv->diag_install_last_target = target_va;
	hv::g_ghv->diag_install_last_fail = 0;

	auto const target_cr3 = amd_vh_effective_cr3_for_target(process, target_va);
	if (!target_cr3) {
		hv::g_ghv->diag_install_last_fail = 1;
		s_install_lock = 0;
		return false;
	}

	int slot_idx = -1;
	for (int i = 0; i < VMCALL_HOOK_MAX; ++i) {
		auto& s = hv::g_vt_hook_table[i];
		if (s.occupied &&
			reinterpret_cast<u64>(s.data.address) == target_va &&
			s.data.type == type) {
			slot_idx = i;
			break;
		}
	}

	hv::eh::ept_hook_entry* entry = nullptr;
	bool fresh = false;

	if (slot_idx < 0) {
		slot_idx = amd_vh_find_free_slot();
		if (slot_idx < 0) {
			hv::g_ghv->diag_install_last_fail = 2;
			s_install_lock = 0;
			return false;
		}

		u32 instr_size = 0;
		u64 next_va = 0;
		u8 old_bytes[20] = {};
		u8 next_old[20] = {};
		if (!amd_vh_disasm_target_host(target_va, target_cr3,
			instr_size, next_va, old_bytes, next_old)) {
			hv::g_ghv->diag_install_last_fail = 3;
			s_install_lock = 0;
			return false;
		}
		hv::g_ghv->diag_install_last_instr_size = instr_size;

		entry = amd_prepare_eh_entry(process,
			target_va,
			/*full_zero=*/false,
			/*is_fake_page=*/false,
			&fresh);
		if (!entry) {
			hv::g_ghv->diag_install_last_fail = 4;
			s_install_lock = 0;
			return false;
		}

		bool const is_kernel = target_va >= 0xffff800000000000ull;
		hv::g_ghv->diag_install_last_is_kernel = is_kernel ? 1 : 0;
		u64 tramp_va = 0;
		u64 bp_rip = 0;
		u64 target_resume = 0;
		if (!amd_vh_alloc_trampoline(target_va,
			old_bytes,
			instr_size,
			is_kernel,
			tramp_va,
			bp_rip,
			target_resume)) {
			hv::g_ghv->diag_install_last_fail = 5;
			hv::g_ghv->diag_install_pool_user_slots = hv::g_ghv->tramp_pool.user_slot_count;
			hv::g_ghv->diag_install_pool_kernel_slots = hv::g_ghv->tramp_pool.kernel_slot_count;
			if (fresh)
				hv::eh::free_entry(entry);
			s_install_lock = 0;
			return false;
		}

		auto const fake_target_hva = hv::eh::eh_get_fake_hva_for_entry(entry, target_va);
		if (!fake_target_hva) {
			amd_vh_free_trampoline(tramp_va);
			if (fresh)
				hv::eh::free_entry(entry);
			hv::g_ghv->diag_install_last_fail = 6;
			s_install_lock = 0;
			return false;
		}

		auto& slot = hv::g_vt_hook_table[slot_idx];
		RtlZeroMemory(&slot.data, sizeof(slot.data));
		slot.data.address = reinterpret_cast<PVOID>(target_va);
		slot.data.nextAddress = reinterpret_cast<PUCHAR>(next_va);
		RtlCopyMemory(slot.data.oldByte, old_bytes, sizeof(slot.data.oldByte));
		RtlCopyMemory(slot.data.nextOldByte, next_old, sizeof(slot.data.nextOldByte));
		slot.data.size = instr_size;
		slot.data.process = process;
		slot.data.blankMemory = blank_mem;
		slot.data.fakeMemoryAddress = reinterpret_cast<u64>(fake_target_hva);
		slot.data.type = type;
		slot.data.dispatch_mode = dispatch_mode;
		slot.data.filter_by_process = filter_by_process;
		slot.data.isEnable = false;
		slot.fake_mem_hva = fake_target_hva;
		slot.trampoline_va = tramp_va;
		slot.bp_rip = bp_rip;
		slot.target_resume = target_resume;
		slot.occupied = true;

		if (auto_enable) {
			slot.data.isEnable = true;
			amd_vh_apply_enable_transition_hva(slot.fake_mem_hva);
		}
	} else {
		auto const va_page = page_align(target_va);
		auto& t = hv::g_ghv->ept_hook_table;
		t.lock.acquire();
		entry = hv::eh::find_entry_locked(target_cr3, va_page);
		t.lock.release();
	}

	bool const ok = amd_eh_install_all(cpu, entry);
	s_install_lock = 0;
	return ok;
}

bool amd_vh_dispatch(vmcb* const v, hv::vcpu* const cpu, hv::guest_context* const ctx) {
	if (!v || !cpu || !ctx || !hv::g_vt_hook_table)
		return false;

	auto const rip = v->rip;
	_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_dispatch_count));
	hv::g_ghv->dwm_dispatch_seen_rip = rip;
	auto const ring_idx = static_cast<u32>(_InterlockedIncrement(
		reinterpret_cast<volatile LONG*>(&hv::g_ghv->diag_dispatch_rip_idx)) - 1);
	hv::g_ghv->diag_dispatch_rip_ring[ring_idx & 7] = rip;

	for (int i = 0; i < VMCALL_HOOK_MAX; ++i) {
		auto& slot = hv::g_vt_hook_table[i];
		if (!slot.occupied || !slot.data.address)
			continue;

		hv::g_ghv->dwm_dispatch_compared_addr = reinterpret_cast<u64>(slot.data.address);
		if (rip != reinterpret_cast<u64>(slot.data.address))
			continue;

		_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->dwm_hit_count));

		switch (slot.data.dispatch_mode) {
		case VMCALL_DISPATCH_RETABS:
			if (slot.data.isEnable && slot.data.trampleAddress) {
				v->rip = slot.data.trampleAddress;
				mark_vmcb_dirty(v);
				return true;
			}
			break;
		case VMCALL_DISPATCH_SELF:
			// The AMD backend does not yet call the VMX-specific game handler
			// table.  Avoid an infinite VMMCALL loop by falling back to the
			// original-instruction trampoline when one exists.
			break;
		default:
			break;
		}

		if (slot.trampoline_va) {
			v->rip = slot.trampoline_va;
			mark_vmcb_dirty(v);
			return true;
		}

		advance_guest_ip(v, 3);
		v->rax = ctx->rax;
		return true;
	}

	return false;
}

bool amd_vh_handle_breakpoint(vmcb* const v, hv::vcpu* const cpu) {
	if (!v || !cpu)
		return false;

	_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_bp_total));
	hv::g_ghv->diag_bp_last_rip = v->rip;

	u64 const candidates[2] = { v->rip, v->rip ? v->rip - 1 : 0 };
	auto& pool = hv::g_ghv->tramp_pool;
	auto match = [&](hv::tramp_slot* slots, u32 const count, u64 const bp_rip) -> bool {
		for (u32 i = 0; i < count; ++i) {
			auto& s = slots[i];
			if (s.occupied && s.bp_rip == bp_rip) {
				v->rip = s.target_resume;
				mark_vmcb_dirty(v);
				return true;
			}
		}
		return false;
	};

	for (u32 i = 0; i < 2; ++i) {
		if (!candidates[i])
			continue;
		if (match(pool.user_slots, pool.user_slot_count, candidates[i]) ||
			match(pool.kernel_slots, pool.kernel_slot_count, candidates[i])) {
			_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_bp_match));
			return true;
		}
	}

	_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_bp_miss));
	if (!hv::g_ghv->diag_bp_first_miss_rip)
		hv::g_ghv->diag_bp_first_miss_rip = v->rip;
	return false;
}

bool amd_copy_to_guest_current(vmcb* const v,
	u64 const dst_gva,
	void const* const src_hva,
	size_t const size)
{
	auto const src = static_cast<u8 const*>(src_hva);
	size_t copied = 0;
	while (copied < size) {
		size_t dst_remaining = 0;
		auto const dst = guest_va_to_host(v,
			reinterpret_cast<void*>(dst_gva + copied),
			&dst_remaining);
		if (!dst)
			return false;

		auto const curr_size = min(size - copied, dst_remaining);
		hv::host_exception_info e = {};
		hv::memcpy_safe(e, dst, src + copied, curr_size);
		if (e.exception_occurred)
			return false;

		copied += curr_size;
	}
	return true;
}

u64 amd_flush_logs(vmcb* const v, hv::guest_context* const ctx) {
	auto count = static_cast<u32>(ctx->rcx);
	auto const out_gva = ctx->rdx;
	if (!count || !out_gva)
		return 0;

	auto& l = hv::g_ghv->logger;
	l.lock.acquire();
	count = min(count, l.msg_count);

	u64 written = 0;
	for (; written < count; ++written) {
		auto const idx = (l.msg_start + static_cast<u32>(written)) % l.max_msg_count;
		auto const dst = out_gva + written * sizeof(l.msgs[0]);
		if (!amd_copy_to_guest_current(v, dst, &l.msgs[idx], sizeof(l.msgs[0])))
			break;
	}

	l.msg_count -= static_cast<u32>(written);
	l.msg_start = (l.msg_start + static_cast<u32>(written)) % l.max_msg_count;
	l.lock.release();
	return written;
}

struct amd_pool_block_record {
	u64 va;
	u64 bytes;
	u32 tag;
	u32 flags;
};

u64 amd_get_pool_blocks(vmcb* const v, u64 const out_gva, u64 const max_records) {
	if (!Util::IsPoolManagerInit || !out_gva || !max_records)
		return 0;

	u64 written = 0;
	auto temp = Util::Pools.ActiveListHead.Flink;
	while (temp != &Util::Pools.ActiveListHead && written < max_records) {
		auto const entry = CONTAINING_RECORD(temp, Util::POOL_ENTRY, ListEntry);
		amd_pool_block_record rec = {};
		rec.va = reinterpret_cast<u64>(entry->VritualAddress);
		rec.bytes = entry->NumberOfBytes;
		rec.tag = entry->Source;
		rec.flags = entry->UsedIndependent ? 0x00000001u : 0x00000002u;
		if (!amd_copy_to_guest_current(v,
			out_gva + written * sizeof(rec),
			&rec,
			sizeof(rec)))
			break;
		++written;
		temp = temp->Flink;
	}
	return written;
}

u64 amd_probe_copy_hits(vmcb* const v,
	u64 const out_gva,
	u64 max_hits,
	bool const clear_after)
{
	if (!out_gva || !max_hits)
		return 0;
	if (max_hits > hv::ept_probe_hit_count)
		max_hits = hv::ept_probe_hit_count;

	auto& t = hv::g_ghv->probe_table;
	t.lock.acquire();

	u64 count = t.hit_count;
	if (count > max_hits)
		count = max_hits;

	u64 copied = 0;
	auto const oldest = (t.hit_write + hv::ept_probe_hit_count - t.hit_count) %
		hv::ept_probe_hit_count;
	for (; copied < count; ++copied) {
		auto const idx = (oldest + static_cast<u32>(copied)) % hv::ept_probe_hit_count;
		if (!amd_copy_to_guest_current(v,
			out_gva + copied * sizeof(hv::ept_probe_hit),
			&t.hits[idx],
			sizeof(hv::ept_probe_hit)))
			break;
	}

	if (clear_after) {
		t.hit_write = 0;
		t.hit_count = 0;
	}

	t.lock.release();
	return copied;
}

u64 amd_probe_clear_hits() {
	auto& t = hv::g_ghv->probe_table;
	t.lock.acquire();
	auto const old = t.hit_count;
	t.hit_write = 0;
	t.hit_count = 0;
	t.lock.release();
	return old;
}

bool amd_probe_is_kernel_va(u64 const va) {
	return va >= 0xffff800000000000ull;
}

u64 amd_probe_normalize_cr3(vmcb* const v,
	u64 target_cr3,
	u64 const target_va,
	u64 const flags)
{
	if ((flags & hv::ept_probe_flag_kernel) || amd_probe_is_kernel_va(target_va))
		return hv::g_ghv->system_cr3.flags & ~0xfffull;
	if (!target_cr3)
		target_cr3 = v ? v->cr3 : 0;
	return target_cr3 & ~0xfffull;
}

hv::ept_probe_slot* amd_probe_find_slot_by_key_locked(u64 const target_cr3,
	u64 const target_page_va,
	u64 const page_offset)
{
	auto& t = hv::g_ghv->probe_table;
	for (auto& s : t.slots) {
		if (s.active &&
			s.target_cr3 == target_cr3 &&
			s.target_page_va == target_page_va &&
			s.page_offset == page_offset)
			return &s;
	}
	return nullptr;
}

hv::ept_probe_slot* amd_probe_find_slot_by_pfn_locked(u64 const orig_pfn,
	u64 const page_offset)
{
	auto& t = hv::g_ghv->probe_table;
	for (auto& s : t.slots) {
		if (s.active &&
			s.orig_pfn == orig_pfn &&
			s.page_offset == page_offset)
			return &s;
	}
	return nullptr;
}

hv::ept_probe_slot* amd_probe_alloc_slot_locked() {
	auto& t = hv::g_ghv->probe_table;
	for (auto& s : t.slots) {
		if (!s.active)
			return &s;
	}
	return nullptr;
}

u64 amd_probe_install_all(vmcb* const v,
	hv::vcpu* const cpu,
	u64 const target_cr3,
	u64 const target_va,
	u64 const flags,
	u64 const hit_limit)
{
	if (!v || !cpu || !target_va)
		return 0;

	auto const target_page_va = page_align(target_va);
	auto const page_offset = target_va & 0xfffull;
	auto const normalized_cr3 = amd_probe_normalize_cr3(v, target_cr3, target_va, flags);
	if (!normalized_cr3)
		return 0;

	cr3 c = {};
	c.flags = normalized_cr3;

	bool fresh = false;
	u64 id = 0;
	u64 orig_pfn = 0;
	u64 shadow_pfn = 0;

	auto& t = hv::g_ghv->probe_table;
	t.lock.acquire();
	auto slot = amd_probe_find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
	if (!slot) {
		size_t page_left = 0;
		auto const orig_gpa = hv::gva2gpa(c, reinterpret_cast<void*>(target_page_va), &page_left);
		if (!orig_gpa) {
			t.lock.release();
			return 0;
		}

		auto const source = hv::gva2hva(c, reinterpret_cast<void*>(target_page_va), &page_left);
		if (!source || page_left < 0x1000) {
			t.lock.release();
			return 0;
		}

		slot = amd_probe_alloc_slot_locked();
		if (!slot) {
			t.lock.release();
			return 0;
		}

		auto const idx = static_cast<u32>(slot - hv::g_ghv->probe_table.slots);
		auto shadow = hv::g_ghv->probe_table.shadow_pages[idx];
		RtlCopyMemory(shadow, source, 0x1000);
		if (shadow[page_offset] == 0xcc) {
			t.lock.release();
			return 0;
		}
		shadow[page_offset] = 0xcc;

		RtlZeroMemory(slot, sizeof(*slot));
		slot->id = hv::g_ghv->probe_table.next_id++;
		if (!slot->id)
			slot->id = hv::g_ghv->probe_table.next_id++;
		slot->target_va = target_va;
		slot->target_page_va = target_page_va;
		slot->target_cr3 = normalized_cr3;
		slot->orig_pfn = orig_gpa >> 12;
		slot->shadow_pfn = hv::g_ghv->probe_table.shadow_pfns[idx];
		slot->page_offset = page_offset;
		slot->hit_limit = hit_limit;
		slot->is_kernel = ((flags & hv::ept_probe_flag_kernel) != 0) ||
			amd_probe_is_kernel_va(target_va);
		slot->active = true;
		fresh = true;
	}

	id = slot->id;
	orig_pfn = slot->orig_pfn;
	shadow_pfn = slot->shadow_pfn;
	t.lock.release();

	auto existing = cpu->svm.npt ? find_npt_hook(*cpu->svm.npt, orig_pfn) : nullptr;
	if (existing && (existing->exec_pfn != shadow_pfn || existing->is_fake_page)) {
		if (fresh) {
			t.lock.acquire();
			auto live = amd_probe_find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
			if (live && live->id == id && live->active_bitmap == 0)
				RtlZeroMemory(live, sizeof(*live));
			t.lock.release();
		}
		return 0;
	}

	if (!enqueue_raw_npt_hook_all(cpu, orig_pfn, shadow_pfn, false)) {
		if (fresh) {
			t.lock.acquire();
			auto live = amd_probe_find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
			if (live && live->id == id && live->active_bitmap == 0)
				RtlZeroMemory(live, sizeof(*live));
			t.lock.release();
		}
		return 0;
	}

	t.lock.acquire();
	slot = amd_probe_find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
	if (slot && slot->id == id)
		slot->active_bitmap |= active_vcpu_mask();
	t.lock.release();

	return id;
}

u64 amd_probe_remove_all(vmcb* const v,
	hv::vcpu* const cpu,
	u64 const target_cr3,
	u64 const target_va,
	u64 const flags)
{
	if (!v || !cpu || !target_va)
		return 0;

	auto const target_page_va = page_align(target_va);
	auto const page_offset = target_va & 0xfffull;
	auto const normalized_cr3 = amd_probe_normalize_cr3(v, target_cr3, target_va, flags);
	if (!normalized_cr3)
		return 0;

	u64 id = 0;
	u64 orig_pfn = 0;
	auto& t = hv::g_ghv->probe_table;
	t.lock.acquire();
	auto const slot = amd_probe_find_slot_by_key_locked(normalized_cr3, target_page_va, page_offset);
	if (!slot) {
		t.lock.release();
		return 0;
	}
	id = slot->id;
	orig_pfn = slot->orig_pfn;
	RtlZeroMemory(slot, sizeof(*slot));
	t.lock.release();

	enqueue_raw_npt_remove_all(cpu, orig_pfn);
	return id;
}

void amd_probe_fill_hit(vmcb* const v,
	hv::vcpu* const cpu,
	hv::guest_context* const ctx,
	hv::ept_probe_hit& h,
	hv::ept_probe_slot const& slot,
	u64 const target_rip,
	u64 const bp_rip,
	u64 const guest_cr3)
{
	RtlZeroMemory(&h, sizeof(h));
	h.probe_id = slot.id;
	h.target_va = slot.target_va;
	h.rip = target_rip;
	h.bp_rip = bp_rip;
	h.rsp = v->rsp;
	h.rflags = v->rflags;
	h.cr3 = guest_cr3;
	h.cpu_index = vcpu_index(cpu);
	h.rax = ctx->rax;
	h.rbx = ctx->rbx;
	h.rcx = ctx->rcx;
	h.rdx = ctx->rdx;
	h.rsi = ctx->rsi;
	h.rdi = ctx->rdi;
	h.rbp = ctx->rbp;
	h.r8 = ctx->r8;
	h.r9 = ctx->r9;
	h.r10 = ctx->r10;
	h.r11 = ctx->r11;
	h.r12 = ctx->r12;
	h.r13 = ctx->r13;
	h.r14 = ctx->r14;
	h.r15 = ctx->r15;

	cr3 c = {};
	c.flags = guest_cr3 & ~0xfffull;
	hv::read_guest_virtual_memory(c, reinterpret_cast<void*>(h.rsp), h.stack, sizeof(h.stack));
	hv::read_guest_virtual_memory(c, reinterpret_cast<void*>(h.rsi), &h.stack[8], 2 * sizeof(u64));
	hv::read_guest_virtual_memory(c, reinterpret_cast<void*>(h.rcx), &h.stack[10], 2 * sizeof(u64));
	hv::read_guest_virtual_memory(c, reinterpret_cast<void*>(h.rdx), &h.stack[12], 2 * sizeof(u64));
	hv::read_guest_virtual_memory(c, reinterpret_cast<void*>(h.r13), &h.stack[14], 2 * sizeof(u64));
}

bool amd_probe_record_hit(vmcb* const v,
	hv::vcpu* const cpu,
	hv::guest_context* const ctx,
	hv::ept_probe_slot const& snapshot,
	u64 const target_rip,
	u64 const bp_rip,
	u64 const guest_cr3)
{
	auto& t = hv::g_ghv->probe_table;
	u64 seq = 0;
	t.lock.acquire();
	auto live = amd_probe_find_slot_by_pfn_locked(snapshot.orig_pfn, snapshot.page_offset);
	if (!live || live->id != snapshot.id) {
		t.lock.release();
		return false;
	}

	auto const new_count = ++live->hit_count;
	if (live->hit_limit && new_count > live->hit_limit) {
		t.lock.release();
		return false;
	}

	seq = t.next_seq++;
	if (!seq)
		seq = t.next_seq++;
	t.lock.release();

	hv::ept_probe_hit hit = {};
	amd_probe_fill_hit(v, cpu, ctx, hit, snapshot, target_rip, bp_rip, guest_cr3);
	hit.seq = seq;

	t.lock.acquire();
	live = amd_probe_find_slot_by_pfn_locked(snapshot.orig_pfn, snapshot.page_offset);
	if (!live || live->id != snapshot.id) {
		t.lock.release();
		return false;
	}

	auto const idx = t.hit_write++ % hv::ept_probe_hit_count;
	t.hits[idx] = hit;
	if (t.hit_count < hv::ept_probe_hit_count)
		t.hit_count++;
	t.lock.release();
	return true;
}

bool amd_probe_handle_breakpoint(vmcb* const v,
	hv::vcpu* const cpu,
	hv::guest_context* const ctx)
{
	if (!v || !cpu || !ctx || !cpu->svm.npt || !hv::g_ghv->vcpus)
		return false;

	bool any_active = false;
	for (auto const& s : hv::g_ghv->probe_table.slots) {
		if (s.active) {
			any_active = true;
			break;
		}
	}
	if (!any_active)
		return false;

	auto const self = vcpu_index(cpu);
	if (self >= 64)
		return false;
	auto const self_bit = 1ull << self;
	auto const bp_rip = v->rip;
	auto const guest_cr3 = v->cr3 & ~0xfffull;
	u64 const candidates[2] = { bp_rip, bp_rip ? bp_rip - 1 : 0 };

	for (u32 i = 0; i < 2; ++i) {
		auto const target_rip = candidates[i];
		if (!target_rip)
			continue;

		auto const target_page_va = page_align(target_rip);
		auto const page_offset = target_rip & 0xfffull;
		cr3 c = {};
		c.flags = guest_cr3;
		auto gpa = hv::gva2gpa(c, reinterpret_cast<void*>(target_page_va));
		if (!gpa && amd_probe_is_kernel_va(target_rip)) {
			c.flags = hv::g_ghv->system_cr3.flags & ~0xfffull;
			gpa = hv::gva2gpa(c, reinterpret_cast<void*>(target_page_va));
		}
		if (!gpa)
			continue;

		hv::ept_probe_slot snapshot = {};
		auto& t = hv::g_ghv->probe_table;
		t.lock.acquire();
		auto const slot = amd_probe_find_slot_by_pfn_locked(gpa >> 12, page_offset);
		if (!slot || !(slot->active_bitmap & self_bit)) {
			t.lock.release();
			continue;
		}
		snapshot = *slot;
		t.lock.release();

		amd_probe_record_hit(v, cpu, ctx, snapshot, target_rip, bp_rip, guest_cr3);

		if (cpu->svm.npt->pending_restore.active)
			restore_npt_single_step(v, cpu, false);

		deactivate_npt_exec_root(v, cpu);
		auto const pte = get_npt_pte(*cpu->svm.npt, snapshot.orig_pfn << 12, false);
		if (!pte)
			return false;

		auto& restore = cpu->svm.npt->pending_restore;
		restore.active = true;
		restore.owned_tf = (v->rflags & (1ull << amd64_rflags_tf)) == 0;
		restore.saved_rflags = v->rflags;
		restore.pte = pte;
		restore.restore_pfn = pte->page_frame_number;
		restore.restore_present = pte->present != 0;
		restore.restore_write = pte->write != 0;
		restore.restore_nx = pte->execute_disable != 0;

		pte->present = 1;
		pte->write = 1;
		pte->page_frame_number = snapshot.orig_pfn;
		pte->execute_disable = 0;

		v->rip = target_rip;
		v->rflags |= (1ull << amd64_rflags_tf);
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		return true;
	}

	return false;
}

hv::eh::ept_hook_entry* amd_prepare_eh_entry(PEPROCESS const process,
	u64 const va,
	bool const full_zero,
	bool const is_fake_page,
	bool* const out_fresh)
{
	if (out_fresh)
		*out_fresh = false;

	auto const va_page = page_align(va);
	u64 process_cr3 = resolve_process_cr3(process);
	if (va_page >= 0xffff800000000000ull && hv::g_ghv->system_cr3.flags)
		process_cr3 = hv::g_ghv->system_cr3.flags & ~0xfffull;
	if (!process_cr3)
		return nullptr;

	auto& t = hv::g_ghv->ept_hook_table;
	t.lock.acquire();

	auto entry = hv::eh::find_entry_locked(process_cr3, va_page);
	if (entry) {
		t.lock.release();
		return entry;
	}

	entry = hv::eh::alloc_entry_locked();
	if (!entry) {
		t.lock.release();
		return nullptr;
	}

	cr3 c = {};
	c.flags = process_cr3;
	auto const orig_gpa = hv::gva2gpa(c, reinterpret_cast<void*>(va_page));
	if (!orig_gpa) {
		hv::eh::free_entry_locked(entry);
		t.lock.release();
		return nullptr;
	}

	entry->process = process;
	entry->process_cr3 = process_cr3;
	entry->va = va_page;
	entry->orig_pfn = orig_gpa >> 12;
	entry->fake_pfn = t.fake_page_pfns[entry->fake_page_idx];
	entry->is_fake_page = is_fake_page;
	entry->per_vcpu_active_bitmap = 0;

	auto const fake = &t.fake_pages[entry->fake_page_idx][0];
	if (full_zero) {
		RtlZeroMemory(fake, 0x1000);
	} else {
		auto const orig_hva = hv::gva2hva(c, reinterpret_cast<void*>(va_page));
		if (orig_hva)
			RtlCopyMemory(fake, orig_hva, 0x1000);
		else
			RtlZeroMemory(fake, 0x1000);
	}

	t.lock.release();
	if (out_fresh)
		*out_fresh = true;
	return entry;
}

void restore_npt_single_step(vmcb* const v, hv::vcpu* const cpu, bool const reflect_db) {
	auto& restore = cpu->svm.npt->pending_restore;
	if (!restore.active)
		return;

	if (restore.pte) {
		restore.pte->present = restore.restore_present ? 1 : 0;
		restore.pte->write = restore.restore_write ? 1 : 0;
		restore.pte->page_frame_number = restore.restore_pfn;
		restore.pte->execute_disable = restore.restore_nx ? 1 : 0;
	}

	// Only undo the TF bit we borrowed.  Restoring the whole saved RFLAGS would
	// discard flag results produced by the one instruction that just executed on
	// the temporary NPT view.
	if (restore.saved_rflags & (1ull << amd64_rflags_tf))
		v->rflags |= (1ull << amd64_rflags_tf);
	else
		v->rflags &= ~(1ull << amd64_rflags_tf);
	v->tlb_control = 1;
	mark_vmcb_dirty(v);

	bool const inject_guest_db = reflect_db || !restore.owned_tf;
	restore.active = false;
	restore.pte = nullptr;

	if (inject_guest_db)
		inject_exception(v, amd64_debug_exception);
}

bool handle_npf(vmcb* const v, hv::vcpu* const cpu) {
	if (!cpu->svm.npt)
		return false;

	npf_error_code err = {};
	err.flags = v->exitinfo1;
	u64 const pa = v->exitinfo2;

	// Optimized DBVM-style AMD cloak path:
	// while VMCB.N_CR3 points at exec_view, only the active cloaked 4KB page is
	// executable.  Any execute fault outside that page means the guest is
	// leaving the active page.  Switch back to the normal read/write NPT root
	// and let the same instruction be retried there.
	if (npt_exec_view_active(*cpu->svm.npt)) {
		deactivate_npt_exec_root(v, cpu);
		reinject_exitintinfo_if_valid(v);
		return true;
	}

	if (!err.present) {
		if (ensure_npt_mapped(*cpu->svm.npt, pa)) {
			v->tlb_control = 1;
			mark_vmcb_dirty(v);
			reinject_exitintinfo_if_valid(v);
			return true;
		}
		inject_exception(v, amd64_general_protection, 0);
		return false;
	}

	auto const pte = get_npt_pte(*cpu->svm.npt, pa, false);
	auto const hook = find_npt_hook(*cpu->svm.npt, pa >> 12);

	if (!pte || !hook || !err.execute) {
		if (pte && err.execute && pte->execute_disable && !hook) {
			pte->execute_disable = 0;
			v->tlb_control = 1;
			mark_vmcb_dirty(v);
			reinject_exitintinfo_if_valid(v);
			return true;
		}
		if (ensure_npt_mapped(*cpu->svm.npt, pa)) {
			v->tlb_control = 1;
			mark_vmcb_dirty(v);
			reinject_exitintinfo_if_valid(v);
			return true;
		}
		inject_exception(v, amd64_general_protection, 0);
		return false;
	}

	auto& restore = cpu->svm.npt->pending_restore;
	if (restore.active)
		restore_npt_single_step(v, cpu, false);

	if (activate_npt_exec_root(v, cpu, *hook)) {
		reinject_exitintinfo_if_valid(v);
		return true;
	}

	restore.active = true;
	restore.owned_tf = (v->rflags & (1ull << amd64_rflags_tf)) == 0;
	restore.saved_rflags = v->rflags;
	restore.pte = pte;
	restore.restore_pfn = pte->page_frame_number;
	restore.restore_present = pte->present != 0;
	restore.restore_write = pte->write != 0;
	restore.restore_nx = pte->execute_disable != 0;

	// AMD NPT has no independent read permission. Temporarily grant execute
	// on the exec PFN for one instruction, then restore on the #DB VMEXIT.
	pte->present = 1;
	pte->write = 1;
	pte->page_frame_number = hook->is_fake_page ? hook->orig_pfn : hook->exec_pfn;
	pte->execute_disable = 0;

	v->rflags |= (1ull << amd64_rflags_tf);
	v->tlb_control = 1;
	mark_vmcb_dirty(v);
	reinject_exitintinfo_if_valid(v);
	return true;
}

void emulate_vmmcall(vmcb* const v, hv::vcpu* const cpu, hv::guest_context* const ctx) {
	auto const code = static_cast<hv::hypercall_code>(ctx->rax & 0xff);
	auto const key = ctx->rax >> 8;

	if (amd_vh_dispatch(v, cpu, ctx))
		return;

	if (key != hv::hypercall_key) {
		if (!guest_cpl0(v)) {
			inject_page_fault(v, ctx, v->rip, true);
			return;
		}
		inject_exception(v, amd64_invalid_opcode);
		return;
	}

	switch (code) {
	case hv::hypercall_ping:
		ctx->rax = hv::hypervisor_signature;
		break;
	case hv::hypercall_unload:
		deactivate_npt_exec_root(v, cpu);
		// Match the VMX hc::unload contract used by hv::stop(): acknowledge
		// this exact vCPU while g_ghv and the vCPU array are still valid in
		// Host context.  Without this bit AMD teardown returned to Guest but
		// hv::stop() always observed ack=0 and deliberately leaked the runtime.
		if (cpu && hv::g_ghv && hv::g_ghv->vcpus) {
			auto const index = static_cast<u64>(cpu - hv::g_ghv->vcpus);
			if (index < 64) {
				_InterlockedOr64(
					reinterpret_cast<volatile LONG64*>(&hv::g_ghv->stop_ack_bitmap),
					static_cast<LONG64>(1ull << index));
			}
		}
		cpu->svm.should_stop = true;
		cpu->stop_virtualization = true;
		ctx->rax = hv::hypervisor_signature;
		break;
	case hv::hypercall_set_host_rsp: {
		auto const old_rsp = cpu->svm.host_rsp_next;
		auto const new_rsp = ctx->rcx;
		if (new_rsp) {
			cpu->svm.host_rsp_next = new_rsp;
			ctx->rax = old_rsp;
		} else {
			ctx->rax = 0;
		}
		break;
	}
	case hv::hypercall_read_phys_mem:
		if (!amd_read_phys(v, ctx))
			return;
		break;
	case hv::hypercall_write_phys_mem:
		if (!amd_write_phys(v, ctx))
			return;
		break;
	case hv::hypercall_read_virt_mem:
		if (!amd_read_virt(v, ctx))
			return;
		break;
	case hv::hypercall_write_virt_mem:
		if (!amd_write_virt(v, ctx))
			return;
		break;
	case hv::hypercall_query_process_cr3:
		amd_query_process_cr3(ctx);
		break;
	case hv::hypercall_flush_logs:
		ctx->rax = amd_flush_logs(v, ctx);
		break;
	case hv::hypercall_get_hv_base:
		ctx->rax = reinterpret_cast<u64>(&__ImageBase);
		break;
	case hv::hypercall_get_info: {
		ctx->rax = 0;
		auto const out = static_cast<u64*>(guest_va_to_host(v, reinterpret_cast<void*>(ctx->rcx)));
		if (out) {
			*out = hv::g_ghv->g_cr3_map.realCr3.flags;
			ctx->rax = sizeof(u64);
		}
		break;
	}
	case hv::hypercall_save_gamevt_image_base:
		hv::gamevt_image_base = ctx->rcx;
		hv::gamevt_driver_unload = ctx->rdx;
		ctx->rax = 1;
		break;
	case hv::hypercall_get_gamevt_image_base: {
		ctx->rax = 0;
		auto const out = static_cast<u64*>(guest_va_to_host(v, reinterpret_cast<void*>(ctx->rcx)));
		if (out) {
			out[0] = hv::gamevt_image_base;
			out[1] = hv::gamevt_driver_unload;
			ctx->rax = 2 * sizeof(u64);
		}
		break;
	}
	case hv::hypercall_get_resident_hv_diag: {
		ctx->rax = 0;
		auto const out_size = ctx->rdx;
		auto out = static_cast<resident_hv_diag_record*>(
			guest_va_to_host(v, reinterpret_cast<void*>(ctx->rcx)));
		if (!out && hv::g_ghv->system_cr3.flags) {
			out = static_cast<resident_hv_diag_record*>(
				hv::gva2hva(hv::g_ghv->system_cr3, reinterpret_cast<void*>(ctx->rcx)));
		}
		if (out && out_size >= sizeof(*out)) {
			RtlZeroMemory(out, sizeof(*out));
			u64 current_index = ~0ull;
			if (hv::g_ghv->vcpus && cpu >= hv::g_ghv->vcpus && cpu < (hv::g_ghv->vcpus + hv::g_ghv->vcpu_count))
				current_index = static_cast<u64>(cpu - hv::g_ghv->vcpus);
			out->magic = resident_hv_diag_magic;
			out->size = sizeof(*out);
			out->version = 24;
			out->current_vcpu = current_index;
			out->vcpu_count = hv::g_ghv->vcpu_count;
			out->ghv_ptr = reinterpret_cast<u64>(hv::g_ghv);
			out->vcpus_ptr = reinterpret_cast<u64>(hv::g_ghv->vcpus);
			out->current_vcpu_ptr = reinterpret_cast<u64>(cpu);
			out->vmcs_host_rip = 0;
			out->vmcs_host_rsp = cpu->svm.host_rsp_current;
			out->current_host_stack = reinterpret_cast<u64>(cpu->host_stack);
			out->host_stack_bytes = hv::host_stack_size;
			out->vm_exit_ptr = reinterpret_cast<u64>(svm_handle_vmexit_c);
			out->handle_vm_exit_ptr = reinterpret_cast<u64>(svm_handle_vmexit_c);
			out->image_base = hv::gamevt_image_base;
			out->driver_unload = hv::gamevt_driver_unload;
			out->flags = 2; // AMD SVM backend
			out->ghv_off_kpcr_prcb_offset = offsetof(hv::hypervisor, kpcr_pcrb_offset);
			out->ghv_off_kprcb_current_thread_offset = offsetof(hv::hypervisor, kprcb_current_thread_offset);
			out->ghv_off_kthread_apc_state_offset = offsetof(hv::hypervisor, kthread_apc_state_offset);
			out->ghv_off_kapc_state_process_offset = offsetof(hv::hypervisor, kapc_state_process_offset);
			out->ghv_off_vtcallstack_list = offsetof(hv::hypervisor, vtcallstack_list);
			out->ghv_off_tramp_pool = offsetof(hv::hypervisor, tramp_pool);
			out->ghv_off_dbg = offsetof(hv::hypervisor, dbg);
			out->ghv_off_dbg_events = offsetof(hv::hypervisor, dbg_events);
			out->ghv_off_dbg_watch = offsetof(hv::hypervisor, dbg_watch);
			out->vcpu_stride = sizeof(hv::vcpu);
			out->vcpu_off_ept = offsetof(hv::vcpu, ept);
			out->vcpu_off_ept_free_pages =
				offsetof(hv::vcpu, ept) + offsetof(hv::vcpu_ept_data, free_pages);
			out->vcpu_off_ept_free_page_pfns =
				offsetof(hv::vcpu, ept) + offsetof(hv::vcpu_ept_data, free_page_pfns);
			out->vcpu_off_ept_hook_active_list =
				offsetof(hv::vcpu, ept) +
				offsetof(hv::vcpu_ept_data, hooks) +
				offsetof(hv::vcpu_ept_hooks, active_list_head);
			out->vcpu_off_dbg_pending = offsetof(hv::vcpu, dbg_pending);
			out->ghv_off_affinity_lock_enabled = offsetof(hv::hypervisor, affinity_lock_enabled);
			out->ghv_off_diag_hide_enter = offsetof(hv::hypervisor, diag_hide_enter);
			out->ghv_off_diag_hide_pte_total = offsetof(hv::hypervisor, diag_hide_pte_total);
			out->ghv_off_diag_hide_pte_null = offsetof(hv::hypervisor, diag_hide_pte_null);
			out->ghv_off_diag_hide_done_bitmap = offsetof(hv::hypervisor, diag_hide_done_bitmap);
			out->vcpu_off_ept_num_used_free_pages =
				offsetof(hv::vcpu, ept) + offsetof(hv::vcpu_ept_data, num_used_free_pages);
			out->vcpu_off_ept_dummy_page_pfn =
				offsetof(hv::vcpu, ept) + offsetof(hv::vcpu_ept_data, dummy_page_pfn);
			out->ept_free_page_count = hv::ept_free_page_count;
			out->gamevt_image_base_ptr = reinterpret_cast<u64>(&hv::gamevt_image_base);
			out->gamevt_driver_unload_ptr = reinterpret_cast<u64>(&hv::gamevt_driver_unload);
			out->yvt_boot_flags_ptr = reinterpret_cast<u64>(yvt_get_boot_flags_ptr());
			out->system_eprocess = reinterpret_cast<u64>(hv::g_ghv->system_eprocess);
			out->kprocess_directory_table_base_offset = hv::g_ghv->kprocess_directory_table_base_offset;
			out->eprocess_unique_process_id_offset = hv::g_ghv->eprocess_unique_process_id_offset;
			out->ghv_off_cr3_map_real_cr3 =
				offsetof(hv::hypervisor, g_cr3_map) + offsetof(hv::ghv_cr3_map, realCr3);
			out->vt_hook_table_ptr = reinterpret_cast<u64>(hv::g_vt_hook_table);
			out->vt_hook_slot_count = VMCALL_HOOK_MAX;
			out->vt_hook_slot_size = sizeof(hv::vt_hook_slot);
			out->vt_hook_slot_off_data_address =
				offsetof(hv::vt_hook_slot, data) + offsetof(hv::VMCALLHookData, address);
			out->vt_hook_slot_off_data_type =
				offsetof(hv::vt_hook_slot, data) + offsetof(hv::VMCALLHookData, type);
			out->vt_hook_slot_off_data_blank_memory =
				offsetof(hv::vt_hook_slot, data) + offsetof(hv::VMCALLHookData, blankMemory);
			out->vt_hook_slot_off_data_dispatch_mode =
				offsetof(hv::vt_hook_slot, data) + offsetof(hv::VMCALLHookData, dispatch_mode);
			out->vt_hook_slot_off_occupied = offsetof(hv::vt_hook_slot, occupied);
			out->vt_hook_slot_off_trampoline_va = offsetof(hv::vt_hook_slot, trampoline_va);
			out->vt_hook_slot_off_bp_rip = offsetof(hv::vt_hook_slot, bp_rip);
			out->vt_hook_slot_off_target_resume = offsetof(hv::vt_hook_slot, target_resume);
			out->render_swapchain_ptr = reinterpret_cast<u64>(&hv::swapChain);
			out->render_isfinish_ptr = reinterpret_cast<u64>(&hv::isFinish);
			out->ghv_off_dwm_hit_count = offsetof(hv::hypervisor, dwm_hit_count);
			out->ghv_off_diag_handler_count = offsetof(hv::hypervisor, diag_handler_count);
			out->render_d2d_rt_ptr = reinterpret_cast<u64>(&hv::d2dRenderTarget);
			out->render_color_brush_ptr = reinterpret_cast<u64>(&hv::colorBrush);
			out->render_text_format_ptr = reinterpret_cast<u64>(&hv::TextFormat);
			out->render_buffer0_ptr = reinterpret_cast<u64>(&::buffer0);
			out->render_buffer0_hva_ptr = reinterpret_cast<u64>(&::buffer0_hva);
			out->render_desc_buffer_ptr = reinterpret_cast<u64>(&hv::descBuffer);
			out->render_desc_buffer_hva_ptr = reinterpret_cast<u64>(&hv::descBuffer_hva);
			out->ghv_off_kthread_affinity_offset = offsetof(hv::hypervisor, kthread_affinity_offset);
			out->ghv_off_kthread_user_affinity_offset = offsetof(hv::hypervisor, kthread_user_affinity_offset);
			out->ghv_off_kthread_ideal_processor_offset = offsetof(hv::hypervisor, kthread_ideal_processor_offset);
			out->ghv_off_kthread_user_ideal_processor_offset = offsetof(hv::hypervisor, kthread_user_ideal_processor_offset);
			out->vcpu_off_pending_state = offsetof(hv::vcpu, pending_state);
			out->vcpu_off_pending_host_rsp_restore = offsetof(hv::vcpu, pending_host_rsp_restore);
			out->vcpu_off_pending_vtcallstack_node = offsetof(hv::vcpu, pending_vtcallstack_node);
			out->vcpu_off_pending_release_delay = offsetof(hv::vcpu, pending_release_delay);
			out->ghv_size = sizeof(*hv::g_ghv);
			out->vt_hook_table_bytes = VMCALL_HOOK_MAX * sizeof(hv::vt_hook_slot);
			out->ob_reference_object_by_handle_va = ::ObReferenceObjectByHandle_va;
			out->obf_dereference_object_va = ::ObfDereferenceObject_va;
			out->ntapi_file_name_offset = g_yvt.NtapiOffsets.FileName;
			out->ghv_off_kernel_blank_va = offsetof(hv::hypervisor, kernel_blank_va);
			out->ghv_off_csec_scratch_va = offsetof(hv::hypervisor, csec_scratch_va);
			out->ghv_off_csec_format_va = offsetof(hv::hypervisor, csec_format_va);
			out->ghv_off_stop_phase = offsetof(hv::hypervisor, stop_phase);
			out->ghv_off_stop_expected_bitmap = offsetof(hv::hypervisor, stop_expected_bitmap);
			out->ghv_off_stop_requested_bitmap = offsetof(hv::hypervisor, stop_requested_bitmap);
			out->ghv_off_stop_before_vmcall_bitmap = offsetof(hv::hypervisor, stop_before_vmcall_bitmap);
			out->ghv_off_stop_after_vmcall_bitmap = offsetof(hv::hypervisor, stop_after_vmcall_bitmap);
			out->ghv_off_stop_ack_bitmap = offsetof(hv::hypervisor, stop_ack_bitmap);
			out->ghv_off_stop_exception_bitmap = offsetof(hv::hypervisor, stop_exception_bitmap);
			out->ghv_off_stop_cleanup_bitmap = offsetof(hv::hypervisor, stop_cleanup_bitmap);
			out->ghv_off_stop_last_cpu = offsetof(hv::hypervisor, stop_last_cpu);
			out->ghv_off_stop_result = offsetof(hv::hypervisor, stop_result);
			out->vt_hook_slot_off_data_process =
				offsetof(hv::vt_hook_slot, data) + offsetof(hv::VMCALLHookData, process);
			out->vt_hook_slot_off_data_filter_by_process =
				offsetof(hv::vt_hook_slot, data) + offsetof(hv::VMCALLHookData, filter_by_process);
			out->vt_hook_slot_off_data_is_enable =
				offsetof(hv::vt_hook_slot, data) + offsetof(hv::VMCALLHookData, isEnable);
			out->ghv_off_prot_ranges = offsetof(hv::hypervisor, prot_ranges);
			out->ghv_off_prot_range_count = offsetof(hv::hypervisor, prot_range_count);
			out->ghv_prot_range_capacity = hv::hypervisor::prot_range_capacity;
			out->ghv_prot_range_stride = sizeof(hv::hypervisor::prot_va_range);
			out->ghv_prot_range_off_base = offsetof(hv::hypervisor::prot_va_range, base);
			out->ghv_prot_range_off_end = offsetof(hv::hypervisor::prot_va_range, end);
			out->ghv_off_fake_data = offsetof(hv::hypervisor, fake_data);
			out->ghv_off_diag_getbuffer_hits = offsetof(hv::hypervisor, diag_getbuffer_hits);
			out->ghv_off_diag_getbuffer_alien = offsetof(hv::hypervisor, diag_getbuffer_alien);
			out->ghv_off_diag_present_hits = offsetof(hv::hypervisor, diag_present_hits);
			out->ghv_off_diag_present_alien = offsetof(hv::hypervisor, diag_present_alien);
			out->ghv_off_diag_present1_hits = offsetof(hv::hypervisor, diag_present1_hits);
			out->ghv_off_diag_present1_alien = offsetof(hv::hypervisor, diag_present1_alien);
			out->ghv_off_diag_copyresource_hits = offsetof(hv::hypervisor, diag_copyresource_hits);
			out->ghv_off_diag_copyresource_alien = offsetof(hv::hypervisor, diag_copyresource_alien);
			out->ghv_off_diag_duplicateoutput_hits = offsetof(hv::hypervisor, diag_duplicateoutput_hits);
			out->ghv_off_diag_duplicateoutput_alien = offsetof(hv::hypervisor, diag_duplicateoutput_alien);
			out->ghv_off_diag_nt_alloc_hits = offsetof(hv::hypervisor, diag_nt_alloc_hits);
			out->ghv_off_diag_nt_alloc_alien = offsetof(hv::hypervisor, diag_nt_alloc_alien);
			out->ghv_off_diag_nt_protect_hits = offsetof(hv::hypervisor, diag_nt_protect_hits);
			out->ghv_off_diag_nt_protect_alien = offsetof(hv::hypervisor, diag_nt_protect_alien);
			out->ghv_off_diag_nt_map_hits = offsetof(hv::hypervisor, diag_nt_map_hits);
			out->ghv_off_diag_nt_map_alien = offsetof(hv::hypervisor, diag_nt_map_alien);
			out->ghv_off_diag_nt_csec_hits = offsetof(hv::hypervisor, diag_nt_csec_hits);
			out->ghv_off_diag_nt_csec_image = offsetof(hv::hypervisor, diag_nt_csec_image);
			out->ghv_off_diag_nt_csec_alien = offsetof(hv::hypervisor, diag_nt_csec_alien);
			out->ghv_off_diag_capture_notify_count = offsetof(hv::hypervisor, diag_capture_notify_count);
			out->ghv_off_diag_mmcopy_hits = offsetof(hv::hypervisor, diag_mmcopy_hits);
			out->ghv_off_diag_mmcopy_last_caller_rip = offsetof(hv::hypervisor, diag_mmcopy_last_caller_rip);
			out->ghv_off_diag_mmcm_hits = offsetof(hv::hypervisor, diag_mmcm_hits);
			out->ghv_off_diag_mmcm_blocked = offsetof(hv::hypervisor, diag_mmcm_blocked);
			out->ghv_off_diag_mmcvm_hits = offsetof(hv::hypervisor, diag_mmcvm_hits);
			out->ghv_off_diag_mmcvm_blocked = offsetof(hv::hypervisor, diag_mmcvm_blocked);
			out->ghv_off_diag_mmisav_hits = offsetof(hv::hypervisor, diag_mmisav_hits);
			out->ghv_off_diag_mmisav_blocked = offsetof(hv::hypervisor, diag_mmisav_blocked);
			out->ghv_off_diag_mmmio_hits = offsetof(hv::hypervisor, diag_mmmio_hits);
			out->ghv_off_diag_mmmio_blocked = offsetof(hv::hypervisor, diag_mmmio_blocked);
			out->dwmcore_base = static_cast<u64>(g_yvt.dwmcoreInfo.imageBase);
			out->dwmcore_size = static_cast<u64>(g_yvt.dwmcoreInfo.imageSize);
			out->dxgi_base = static_cast<u64>(g_yvt.dxgiInfo.imageBase);
			out->dxgi_size = static_cast<u64>(g_yvt.dxgiInfo.imageSize);
			out->ghv_off_ept_hook_table = offsetof(hv::hypervisor, ept_hook_table);
			out->ghv_off_pending_ept_install_entries = offsetof(hv::hypervisor, pending_ept_install_entries);
			out->ghv_off_pending_ept_install_bitmap = offsetof(hv::hypervisor, pending_ept_install_bitmap);
			out->ghv_off_diag_pending_queue_full = offsetof(hv::hypervisor, diag_pending_queue_full);
			out->ghv_pending_install_capacity = hv::hypervisor::pending_install_capacity;
			out->ept_hook_table_off_lock = offsetof(hv::eh::ept_hook_table, lock);
			out->ept_hook_table_off_in_use_count = offsetof(hv::eh::ept_hook_table, in_use_count);
			out->ept_hook_table_off_active_list_head = offsetof(hv::eh::ept_hook_table, active_list_head);
			out->ept_hook_table_off_free_list_head = offsetof(hv::eh::ept_hook_table, free_list_head);
			out->ept_hook_table_off_buffer = offsetof(hv::eh::ept_hook_table, buffer);
			out->ept_hook_table_off_fake_pages = offsetof(hv::eh::ept_hook_table, fake_pages);
			out->ept_hook_table_off_fake_page_pfns = offsetof(hv::eh::ept_hook_table, fake_page_pfns);
			out->ept_hook_table_capacity = hv::eh::ept_hook_table::capacity;
			out->ept_hook_entry_size = sizeof(hv::eh::ept_hook_entry);
			out->ept_hook_entry_off_next = offsetof(hv::eh::ept_hook_entry, next);
			out->ept_hook_entry_off_process = offsetof(hv::eh::ept_hook_entry, process);
			out->ept_hook_entry_off_process_cr3 = offsetof(hv::eh::ept_hook_entry, process_cr3);
			out->ept_hook_entry_off_va = offsetof(hv::eh::ept_hook_entry, va);
			out->ept_hook_entry_off_orig_pfn = offsetof(hv::eh::ept_hook_entry, orig_pfn);
			out->ept_hook_entry_off_fake_pfn = offsetof(hv::eh::ept_hook_entry, fake_pfn);
			out->ept_hook_entry_off_fake_page_idx = offsetof(hv::eh::ept_hook_entry, fake_page_idx);
			out->ept_hook_entry_off_in_use = offsetof(hv::eh::ept_hook_entry, in_use);
			out->ept_hook_entry_off_is_fake_page = offsetof(hv::eh::ept_hook_entry, is_fake_page);
			out->ept_hook_entry_off_per_vcpu_active_bitmap = offsetof(hv::eh::ept_hook_entry, per_vcpu_active_bitmap);
			out->nt_create_section_va = ::NtCreatSection;
			out->nt_set_event_va = ::NtSetEvent_va;
			out->nt_allocate_virtual_memory_va = ::NtAllocateVirtualMemory_va;
			out->nt_protect_virtual_memory_va = ::NtProtectVirtualMemory_va;
			out->nt_map_view_of_section_va = ::NtMapViewOfSection_va;
			out->mm_copy_memory_va = ::MmCopyMemory_va;
			out->mm_copy_virtual_memory_va = ::MmCopyVirtualMemory_va;
			out->mm_is_address_valid_va = ::MmIsAddressValid_va;
			out->mm_map_io_space_va = ::MmMapIoSpace_va;
			out->mm_is_address_valid_ex_va = ::MmIsAddressValidEx_va;
			out->nt_query_virtual_memory_va = ::NtQueryVirtualMemory_va;
			out->mm_get_physical_address_va = ::MmGetPhysicalAddress_va;
			out->ghv_off_copyresource_addr = offsetof(hv::hypervisor, copyresource_addr);
			out->ghv_off_duplicateoutput_addr = offsetof(hv::hypervisor, duplicateoutput_addr);
			out->vcpu_off_ctx = offsetof(hv::vcpu, ctx);
			out->ghv_off_pending_ept_invept_bitmap = offsetof(hv::hypervisor, pending_ept_invept_bitmap);
			out->ghv_off_pending_hide_pfns = offsetof(hv::hypervisor, pending_hide_pfns);
			out->ghv_off_pending_hide_count = offsetof(hv::hypervisor, pending_hide_count);
			out->ghv_off_pending_hide_vcpu_bitmap = offsetof(hv::hypervisor, pending_hide_vcpu_bitmap);
			out->ghv_off_pending_hide_tsc_threshold = offsetof(hv::hypervisor, pending_hide_tsc_threshold);
			out->ghv_off_diag_per_vcpu_vmexits = offsetof(hv::hypervisor, diag_per_vcpu_vmexits);
			out->vcpu_off_hide_vm_exit_overhead = offsetof(hv::vcpu, hide_vm_exit_overhead);
			out->vcpu_off_stop_virtualization = offsetof(hv::vcpu, stop_virtualization);
			out->vcpu_off_ept_mmr_mtf_pte = offsetof(hv::vcpu, ept) + offsetof(hv::vcpu_ept_data, mmr_mtf_pte);
			out->vcpu_off_ept_mmr_mtf_mode = offsetof(hv::vcpu, ept) + offsetof(hv::vcpu_ept_data, mmr_mtf_mode);
			out->vcpu_off_ept_mmr_mtf_page_frame = offsetof(hv::vcpu, ept) + offsetof(hv::vcpu_ept_data, mmr_mtf_page_frame);
			out->vcpu_ept_hook_node_off_next = offsetof(hv::vcpu_ept_hook_node, next);
			out->vcpu_ept_hook_node_off_orig_pfn = offsetof(hv::vcpu_ept_hook_node, orig_pfn);
			out->vcpu_ept_hook_node_off_exec_pfn = offsetof(hv::vcpu_ept_hook_node, exec_pfn);
			out->vcpu_ept_hook_node_off_is_fake_page = offsetof(hv::vcpu_ept_hook_node, is_fake_page);
			ctx->rax = sizeof(*out);
		}
		break;
	}
	case hv::hypercall_eh_install: {
		deactivate_npt_exec_root(v, cpu);
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const va = ctx->rdx;
		auto const flags = ctx->r8;
		bool const full_zero = (flags & 1) != 0;
		bool const is_fake_page = (flags & 2) != 0;
		bool fresh = false;
		auto const entry = amd_prepare_eh_entry(process, va, full_zero, is_fake_page, &fresh);
		ctx->rax = amd_eh_install_all(cpu, entry) ? 1 : 0;
		if (!ctx->rax && fresh)
			hv::eh::free_entry(entry);
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		break;
	}
	case hv::hypercall_eh_remove:
	case hv::hypercall_eh_disable: {
		deactivate_npt_exec_root(v, cpu);
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const va_page = page_align(ctx->rdx);
		auto const cpu_bit = 1ull << vcpu_index(cpu);
		auto const process_cr3 = resolve_process_cr3(process);
		auto& t = hv::g_ghv->ept_hook_table;
		t.lock.acquire();
		auto const entry = hv::eh::find_entry_locked(process_cr3, va_page);
		if (!entry) {
			t.lock.release();
			ctx->rax = 0;
			break;
		}
		bool const need_remove = (entry->per_vcpu_active_bitmap & cpu_bit) != 0;
		if (need_remove)
			entry->per_vcpu_active_bitmap &= ~cpu_bit;
		auto const orig_pfn = entry->orig_pfn;
		bool const free_now = (code == hv::hypercall_eh_remove) && entry->per_vcpu_active_bitmap == 0;
		if (free_now) {
			cancel_pending_npt_install(entry);
			hv::eh::free_entry_locked(entry);
		}
		t.lock.release();
		if (need_remove && cpu->svm.npt)
			remove_npt_hook(*cpu->svm.npt, orig_pfn);
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_eh_enable: {
		deactivate_npt_exec_root(v, cpu);
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const va_page = page_align(ctx->rdx);
		auto const entry = amd_find_eh_entry(process, va_page);
		ctx->rax = 0;
		if (entry && amd_eh_install_self(cpu, entry)) {
			v->tlb_control = 1;
			mark_vmcb_dirty(v);
			ctx->rax = 1;
		}
		break;
	}
	case hv::hypercall_eh_write: {
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const dst_va = ctx->rdx;
		auto const src_va = ctx->r8;
		auto size = ctx->r9;
		u8 buf[0x1000];
		if (size > sizeof(buf))
			size = sizeof(buf);
		auto const process_cr3 = resolve_process_cr3(process);
		if (!process_cr3 ||
			hv::read_guest_virtual_memory(hv::g_ghv->system_cr3,
				reinterpret_cast<void*>(src_va),
				buf,
				size) != size) {
			ctx->rax = 0;
			break;
		}
		ctx->rax = hv::eh::eh_write_internal(process_cr3, dst_va, buf, size) ? 1 : 0;
		break;
	}
	case hv::hypercall_eh_get_va: {
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const va = ctx->rdx;
		auto const va_page = page_align(va);
		auto const offset = va & 0xfffull;
		auto const entry = amd_find_eh_entry(process, va_page);
		ctx->rax = entry ? reinterpret_cast<u64>(&hv::g_ghv->ept_hook_table.fake_pages[entry->fake_page_idx][offset]) : 0;
		break;
	}
	case hv::hypercall_eh_remove_all_by_process: {
		deactivate_npt_exec_root(v, cpu);
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const process_cr3 = resolve_process_cr3(process);
		auto const cpu_bit = 1ull << vcpu_index(cpu);
		u64 pfns[hv::eh::ept_hook_table::capacity] = {};
		u64 n = 0;
		auto& t = hv::g_ghv->ept_hook_table;
		t.lock.acquire();
		for (auto e = t.active_list_head; e;) {
			auto const next = e->next;
			if (e->process_cr3 == process_cr3) {
				if ((e->per_vcpu_active_bitmap & cpu_bit) && n < hv::eh::ept_hook_table::capacity)
					pfns[n++] = e->orig_pfn;
				e->per_vcpu_active_bitmap &= ~cpu_bit;
				if (e->per_vcpu_active_bitmap == 0) {
					cancel_pending_npt_install(e);
					hv::eh::free_entry_locked(e);
				}
			}
			e = next;
		}
		t.lock.release();
		if (cpu->svm.npt) {
			for (u64 i = 0; i < n; ++i)
				remove_npt_hook(*cpu->svm.npt, pfns[i]);
		}
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_install_ept_hook:
		deactivate_npt_exec_root(v, cpu);
		ctx->rax = (cpu->svm.npt != nullptr) ?
			install_npt_hook(*cpu->svm.npt, ctx->rcx, ctx->rdx, ctx->r8 != 0) : 0;
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		break;
	case hv::hypercall_remove_ept_hook:
		deactivate_npt_exec_root(v, cpu);
		if (cpu->svm.npt)
			remove_npt_hook(*cpu->svm.npt, ctx->rcx);
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		ctx->rax = 1;
		break;
	case hv::hypercall_hide_physical_page: {
		deactivate_npt_exec_root(v, cpu);
		ctx->rax = 0;
		if (cpu->svm.npt) {
			auto const pte = get_npt_pte(*cpu->svm.npt, ctx->rcx << 12, true);
			if (pte) {
				pte->page_frame_number = cpu->svm.npt->dummy_page_pfn;
				pte->execute_disable = 0;
				mark_npt_changed(*cpu->svm.npt);
				v->tlb_control = 1;
				mark_vmcb_dirty(v);
				ctx->rax = 1;
			}
		}
		break;
	}
	case hv::hypercall_unhide_physical_page: {
		deactivate_npt_exec_root(v, cpu);
		if (cpu->svm.npt) {
			auto const pte = get_npt_pte(*cpu->svm.npt, ctx->rcx << 12, false);
			if (pte) {
				pte->page_frame_number = ctx->rcx;
				pte->execute_disable = 0;
				mark_npt_changed(*cpu->svm.npt);
				v->tlb_control = 1;
				mark_vmcb_dirty(v);
			}
		}
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_get_physical_address: {
		cr3 guest = {};
		guest.flags = ctx->rcx ? ctx->rcx : v->cr3;
		ctx->rax = hv::gva2gpa(guest, reinterpret_cast<void*>(ctx->rdx));
		break;
	}
	case hv::hypercall_prepare_self_hide_add: {
		auto const idx = static_cast<u32>(_InterlockedIncrement(
			reinterpret_cast<volatile LONG*>(&hv::g_ghv->pending_hide_count)) - 1);
		if (idx < hv::hypervisor::pending_hide_capacity) {
			hv::g_ghv->pending_hide_pfns[idx] = ctx->rcx;
			ctx->rax = 1;
		} else {
			hv::g_ghv->pending_hide_count = hv::hypervisor::pending_hide_capacity;
			ctx->rax = 0;
		}
		break;
	}
	case hv::hypercall_prepare_self_hide_commit: {
		u64 const delay_us = ctx->rcx ? ctx->rcx : 100;
		u64 const tsc_hz = 3'000'000'000ULL;
		hv::g_ghv->pending_hide_tsc_threshold = __rdtsc() + (tsc_hz * delay_us) / 1'000'000ULL;
		auto const ncpus = static_cast<u64>(hv::g_ghv->vcpu_count);
		auto const bitmap = (ncpus >= 64) ? ~0ull : ((1ull << ncpus) - 1);
		_InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->pending_hide_vcpu_bitmap),
			static_cast<LONG64>(bitmap));
		ctx->rax = hv::g_ghv->pending_hide_count;
		break;
	}
	case hv::hypercall_hide_pfn_list: {
		deactivate_npt_exec_root(v, cpu);
		u64 hidden = 0;
		u64 pte_null = 0;
		auto const pfn_array_gva = reinterpret_cast<u64*>(ctx->rcx);
		u64 count = ctx->rdx;
		if (cpu->svm.npt && pfn_array_gva && count) {
			if (count > hv::hypervisor::pending_hide_capacity)
				count = hv::hypervisor::pending_hide_capacity;
			u64 idx = 0;
			while (idx < count) {
				u64 const chunk_gva = reinterpret_cast<u64>(pfn_array_gva + idx);
				auto const chunk_hva = static_cast<u64*>(guest_va_to_host(v,
					reinterpret_cast<void*>(chunk_gva)));
				if (!chunk_hva)
					break;
				u64 const page_off = chunk_gva & 0xfffull;
				u64 const room = (0x1000 - page_off) / sizeof(u64);
				u64 const this_chunk = ((count - idx) < room) ? (count - idx) : room;
				for (u64 k = 0; k < this_chunk; ++k) {
					u64 const pfn = chunk_hva[k];
					if (!pfn)
						continue;
					auto const pte = get_npt_pte(*cpu->svm.npt, pfn << 12, true);
					if (!pte) {
						++pte_null;
						continue;
					}
					pte->page_frame_number = cpu->svm.npt->dummy_page_pfn;
					pte->execute_disable = 0;
					++hidden;
				}
				idx += this_chunk;
			}
			_InterlockedExchangeAdd64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_hide_pte_total),
				static_cast<LONG64>(count));
			_InterlockedExchangeAdd64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_hide_pte_null),
				static_cast<LONG64>(pte_null));
			if (hidden)
				mark_npt_changed(*cpu->svm.npt);
			v->tlb_control = 1;
			mark_vmcb_dirty(v);
		}
		ctx->rax = hidden;
		break;
	}
	case hv::hypercall_get_hide_diag: {
		ctx->rax = 0;
		auto const out = static_cast<u64*>(guest_va_to_host(v, reinterpret_cast<void*>(ctx->rcx)));
		if (out) {
			out[0] = hv::g_ghv->diag_hide_enter;
			out[1] = hv::g_ghv->diag_hide_pte_total;
			out[2] = hv::g_ghv->diag_hide_pte_null;
			out[3] = hv::g_ghv->diag_hide_done_bitmap;
			out[4] = 0;
			out[5] = npt_free_pt_count;
			ctx->rax = 6 * sizeof(u64);
		}
		break;
	}
	case hv::hypercall_vh_install: {
		deactivate_npt_exec_root(v, cpu);
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const target_va = ctx->rdx;
		auto const blank_mem = ctx->r8;
		auto const packed = ctx->r9;
		bool const auto_enable = (packed & 1) != 0;
		bool const filter_by_process = (packed & 2) != 0;
		auto const type = static_cast<u8>((packed >> 8) & 0xff);
		auto const dispatch_mode = static_cast<u8>((packed >> 16) & 0xff);
		ctx->rax = amd_vh_install(cpu,
			process,
			target_va,
			blank_mem,
			type,
			dispatch_mode,
			filter_by_process,
			auto_enable) ? 1 : 0;
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		break;
	}
	case hv::hypercall_vh_install_ret_abs:
		ctx->rax = 0;
		break;
	case hv::hypercall_vh_enable: {
		auto const idx = amd_vh_find_slot_by_address(ctx->rdx);
		if (idx < 0) {
			ctx->rax = 0;
			break;
		}
		auto& slot = hv::g_vt_hook_table[idx];
		slot.data.isEnable = true;
		amd_vh_apply_enable_transition_hva(slot.fake_mem_hva);
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_vh_disable: {
		auto const idx = amd_vh_find_slot_by_address(ctx->rdx);
		if (idx < 0) {
			ctx->rax = 0;
			break;
		}
		hv::g_vt_hook_table[idx].data.isEnable = false;
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_vh_remove: {
		deactivate_npt_exec_root(v, cpu);
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const target_va = ctx->rdx;
		auto const idx = amd_vh_find_slot_by_address(target_va);
		if (idx < 0) {
			ctx->rax = 0;
			break;
		}
		auto& slot = hv::g_vt_hook_table[idx];
		bool free_now = false;
		amd_vh_remove_target_hook_current(cpu, process, target_va, &free_now);
		if (free_now) {
			amd_vh_free_trampoline(slot.trampoline_va);
			RtlZeroMemory(&slot, sizeof(slot));
		}
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_vh_uninit: {
		deactivate_npt_exec_root(v, cpu);
		auto const self = vcpu_index(cpu);
		auto const self_bit = self < 64 ? (1ull << self) : 0;
		static volatile LONG64 s_uninit_bitmap = 0;
		if (s_uninit_bitmap == 0) {
			auto const full = active_vcpu_mask();
			_InterlockedCompareExchange64(&s_uninit_bitmap,
				static_cast<LONG64>(full),
				0);
		}

		if (cpu->svm.npt) {
			for (int i = 0; i < VMCALL_HOOK_MAX; ++i) {
				auto& slot = hv::g_vt_hook_table[i];
				if (!slot.occupied)
					continue;
				amd_vh_remove_target_hook_current(cpu,
					slot.data.process,
					reinterpret_cast<u64>(slot.data.address),
					nullptr);
			}

			auto& pool = hv::g_ghv->tramp_pool;
			for (u32 i = 0; i < pool.user_page_count; ++i)
				remove_npt_hook(*cpu->svm.npt, pool.user_pages[i].orig_pfn);
			for (u32 i = 0; i < pool.kernel_page_count; ++i)
				remove_npt_hook(*cpu->svm.npt, pool.kernel_pages[i].orig_pfn);
		}

		u64 remaining = 0;
		if (self_bit)
			remaining = static_cast<u64>(_InterlockedAnd64(&s_uninit_bitmap,
				static_cast<LONG64>(~self_bit))) & ~self_bit;
		if (!remaining) {
			for (int i = 0; i < VMCALL_HOOK_MAX; ++i)
				RtlZeroMemory(&hv::g_vt_hook_table[i], sizeof(hv::g_vt_hook_table[i]));
			s_uninit_bitmap = 0;
		}

		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_vh_find_blank: {
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const target_cr3 = resolve_process_cr3(process);
		ctx->rax = target_cr3 ? amd_vh_find_blank_host(ctx->rdx, ctx->r8, target_cr3) : 0;
		break;
	}
	case hv::hypercall_vh_find_blank_page: {
		auto const process = reinterpret_cast<PEPROCESS>(ctx->rcx);
		auto const target_cr3 = resolve_process_cr3(process);
		ctx->rax = target_cr3 ? amd_vh_find_blank_page_host(ctx->rdx, ctx->r8, target_cr3) : 0;
		break;
	}
	case hv::hypercall_vh_init_tramp_pool:
		ctx->rax = 0;
		break;
	case hv::hypercall_vh_tramp_add_page: {
		deactivate_npt_exec_root(v, cpu);
		auto const orig_pfn = ctx->rcx;
		auto const exec_pfn = ctx->rdx;
		auto const page_va = ctx->r8;
		auto const exec_hva = ctx->r9;
		bool const is_kernel = ctx->r10 != 0;
		auto& pool = hv::g_ghv->tramp_pool;
		pool.lock.acquire();
		auto& count = is_kernel ? pool.kernel_page_count : pool.user_page_count;
		auto pages = is_kernel ? pool.kernel_pages : pool.user_pages;
		if (count >= hv::TRAMPOLINE_MAX_PAGES_PER_POOL ||
			!orig_pfn || !exec_pfn || !page_va || !exec_hva) {
			pool.lock.release();
			ctx->rax = static_cast<u64>(-1);
			break;
		}
		auto const orig_hva = hv::host_physical_to_virtual(orig_pfn << 12);
		auto const exec_dst = hv::host_physical_to_virtual(exec_pfn << 12);
		if (!orig_hva || !exec_dst) {
			pool.lock.release();
			ctx->rax = static_cast<u64>(-1);
			break;
		}
		u32 const idx = count++;
		pages[idx].guest_page_va = page_va;
		pages[idx].orig_pfn = orig_pfn;
		pages[idx].exec_pfn = exec_pfn;
		pages[idx].exec_hva = exec_hva;
		pool.lock.release();

		RtlCopyMemory(exec_dst, orig_hva, 0x1000);
		if (!enqueue_raw_npt_hook_all(cpu, orig_pfn, exec_pfn, false)) {
			pool.lock.acquire();
			if (count == idx + 1) {
				--count;
				RtlZeroMemory(&pages[idx], sizeof(pages[idx]));
			}
			pool.lock.release();
			ctx->rax = static_cast<u64>(-1);
			break;
		}
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		ctx->rax = idx;
		break;
	}
	case hv::hypercall_vh_tramp_add_slot: {
		auto const page_index = static_cast<u32>(ctx->rcx);
		auto const page_off = static_cast<u32>(ctx->rdx);
		auto const capacity = static_cast<u32>(ctx->r8);
		bool const is_kernel = ctx->r9 != 0;
		auto& pool = hv::g_ghv->tramp_pool;
		pool.lock.acquire();
		auto& slot_count = is_kernel ? pool.kernel_slot_count : pool.user_slot_count;
		auto slots = is_kernel ? pool.kernel_slots : pool.user_slots;
		auto const page_count = is_kernel ? pool.kernel_page_count : pool.user_page_count;
		auto const max_slots = is_kernel ? hv::TRAMPOLINE_POOL_KERNEL_SLOTS : hv::TRAMPOLINE_POOL_USER_SLOTS;
		if (slot_count >= max_slots ||
			page_index >= page_count ||
			page_off >= 0x1000 ||
			capacity < 8 ||
			capacity > 255 ||
			page_off + capacity > 0x1000) {
			_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_tramp_slot_xpage_reject));
			pool.lock.release();
			ctx->rax = 0;
			break;
		}
		auto& s = slots[slot_count++];
		s.page_index = static_cast<u16>(page_index);
		s.page_offset = static_cast<u16>(page_off);
		s.capacity = static_cast<u8>(capacity);
		s.occupied = false;
		s.tramp_va = 0;
		s.bp_rip = 0;
		s.target_resume = 0;
		pool.lock.release();
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_vh_tramp_set_ready: {
		bool const is_kernel = ctx->rcx != 0;
		auto& pool = hv::g_ghv->tramp_pool;
		pool.lock.acquire();
		if (is_kernel)
			pool.kernel_ready = true;
		else
			pool.user_ready = true;
		pool.lock.release();
		ctx->rax = 1;
		break;
	}
	case hv::hypercall_map_host_range:
		ctx->rax = (ctx->rcx && ctx->rdx &&
			hv::map_host_virtual_range(ctx->rcx, ctx->rdx)) ? 1 : 0;
		break;
	case hv::hypercall_set_affinity_lock:
		hv::g_ghv->affinity_lock_enabled = ctx->rcx ? 1 : 0;
		ctx->rax = hv::g_ghv->affinity_lock_enabled;
		break;
	case hv::hypercall_set_keep_hv_on_unload:
		yvt_set_keep_hv_on_unload(ctx->rcx != 0);
		ctx->rax = 1;
		break;
	case hv::hypercall_get_pool_blocks:
		ctx->rax = amd_get_pool_blocks(v, ctx->rcx, ctx->rdx);
		break;
	case hv::hypercall_ept_probe_get_hits:
		ctx->rax = amd_probe_copy_hits(v, ctx->rcx, ctx->rdx, ctx->r8 != 0);
		break;
	case hv::hypercall_ept_probe_clear_hits:
		ctx->rax = amd_probe_clear_hits();
		break;
	case hv::hypercall_ept_probe_install:
		deactivate_npt_exec_root(v, cpu);
		ctx->rax = amd_probe_install_all(v, cpu, ctx->rcx, ctx->rdx, ctx->r8, ctx->r9);
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		break;
	case hv::hypercall_ept_probe_remove:
		deactivate_npt_exec_root(v, cpu);
		ctx->rax = amd_probe_remove_all(v, cpu, ctx->rcx, ctx->rdx, ctx->r8);
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		break;
	default:
		inject_exception(v, amd64_invalid_opcode);
		return;
	}

	v->rax = ctx->rax;
	advance_guest_ip(v, 3);
}

void drain_deferred_hide(vmcb* const v, hv::vcpu* const cpu) {
	if (!cpu->svm.npt || !hv::g_ghv->vcpus)
		return;

	auto const self_idx = static_cast<u32>(cpu - hv::g_ghv->vcpus);
	if (self_idx >= 64)
		return;

	u64 const my_bit = 1ull << self_idx;
	if ((hv::g_ghv->pending_hide_vcpu_bitmap & my_bit) == 0 ||
		__rdtsc() < hv::g_ghv->pending_hide_tsc_threshold)
		return;

	if (v->exitcode == vmexit_npf &&
		npt_exec_view_active(*cpu->svm.npt))
		return;

	deactivate_npt_exec_root(v, cpu);

	_InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_hide_enter));
	auto const count = hv::g_ghv->pending_hide_count;
	u64 pte_null = 0;
	for (u32 i = 0; i < count; ++i) {
		auto const pfn = hv::g_ghv->pending_hide_pfns[i];
		auto const pte = get_npt_pte(*cpu->svm.npt, pfn << 12, true);
		if (pte) {
			pte->page_frame_number = cpu->svm.npt->dummy_page_pfn;
			pte->execute_disable = 0;
		} else {
			++pte_null;
		}
	}

	_InterlockedExchangeAdd64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_hide_pte_total),
		static_cast<LONG64>(count));
	_InterlockedExchangeAdd64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_hide_pte_null),
		static_cast<LONG64>(pte_null));
	if (count != pte_null)
		mark_npt_changed(*cpu->svm.npt);
	_InterlockedOr64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->diag_hide_done_bitmap),
		static_cast<LONG64>(my_bit));
	_InterlockedAnd64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->pending_hide_vcpu_bitmap),
		static_cast<LONG64>(~my_bit));

	v->tlb_control = 1;
	mark_vmcb_dirty(v);
}

void drain_pending_npt_flush(vmcb* const v, hv::vcpu* const cpu) {
	if (!hv::g_ghv->vcpus)
		return;

	auto const self_idx = static_cast<u32>(cpu - hv::g_ghv->vcpus);
	if (self_idx >= 64)
		return;

	auto const my_bit = 1ull << self_idx;
	if ((hv::g_ghv->pending_ept_invept_bitmap & my_bit) == 0)
		return;

	v->tlb_control = 1;
	mark_vmcb_dirty(v);
	_InterlockedAnd64(reinterpret_cast<volatile LONG64*>(&hv::g_ghv->pending_ept_invept_bitmap),
		static_cast<LONG64>(~my_bit));
}

void emulate_rdtscp(vmcb* const v, hv::guest_context* const ctx) {
	unsigned int aux = 0;
	auto const tsc = __rdtscp(&aux);
	ctx->rax = static_cast<u32>(tsc);
	ctx->rdx = static_cast<u32>(tsc >> 32);
	ctx->rcx = aux;
	v->rax = ctx->rax;
	advance_guest_ip(v, 3);
}

void emulate_xsetbv(vmcb* const v, hv::guest_context* const ctx) {
	hv::host_exception_info e = {};
	hv::xsetbv_safe(e, ctx->ecx, (ctx->rdx << 32) | ctx->eax);
	if (e.exception_occurred) {
		inject_exception(v, amd64_general_protection, 0);
		return;
	}

	advance_guest_ip(v, 3);
}

void emulate_privileged_cache_op(vmcb* const v, unsigned int const length, bool const writeback) {
	if (!guest_cpl0(v)) {
		inject_exception(v, amd64_general_protection, 0);
		return;
	}

	if (writeback)
		__wbinvd();

	advance_guest_ip(v, length);
}

} // namespace

void advance_guest_ip(vmcb* const v, unsigned int const fallback_length) {
	u64 new_rip = v->nrip ? v->nrip : (v->rip + fallback_length);

	if (v->rip < (1ull << 32) && new_rip >= (1ull << 32)) {
		bool const long_mode = (v->cs.attrib & (1u << 10)) != 0;
		if (!long_mode)
			new_rip &= 0xffffffffull;
	}

	v->rip = new_rip;
	mark_vmcb_dirty(v);
}

void inject_exception(vmcb* const v, unsigned int const vector) {
	set_event(v, vector, false, 0);
}

void inject_exception(vmcb* const v, unsigned int const vector, unsigned int const error_code) {
	set_event(v, vector, true, error_code);
}

bool handle_vmexit(hv::vcpu* const cpu, hv::guest_context* const ctx) {
	if (!cpu || !ctx || !cpu->svm.vmcb)
		return true;

	auto const v = cpu->svm.vmcb;
	cpu->ctx = ctx;
	ctx->rax = v->rax;
	cpu->hide_vm_exit_overhead = false;
	cpu->stop_virtualization = false;
	clear_event(v);

	if (g_hv_panic_dump_claimed != 0) {
		cpu->svm.should_stop = true;
		cpu->stop_virtualization = true;
		v->rflags |= (1ull << 9);
		return true;
	}

	if (hv::g_ghv && hv::g_ghv->vcpus) {
		auto const idx = static_cast<u32>(cpu - hv::g_ghv->vcpus);
		if (idx < 64) {
			auto& st = g_vmexit_storm[idx];
			if (v->rip == st.last_rip && v->exitcode == st.last_exitcode && v->exitcode != vmexit_hlt) {
				if (++st.streak >= 50000) {
					if (_InterlockedCompareExchange(&g_hv_panic_dump_claimed, 1, 0) == 0)
						bugcheck_from_svm_vmexit(cpu, ctx, 0xDEAD00FDULL);
					cpu->svm.should_stop = true;
					cpu->stop_virtualization = true;
					v->rflags |= (1ull << 9);
					return true;
				}
			} else {
				st.last_rip = v->rip;
				st.last_exitcode = v->exitcode;
				st.streak = 0;
			}
		}
	}

	drain_pending_npt_installs(v, cpu);
	drain_pending_raw_npt_removes(v, cpu);
	drain_pending_raw_npt_hooks(v, cpu);
	drain_pending_npt_flush(v, cpu);
	drain_deferred_hide(v, cpu);

	switch (v->exitcode) {
	case vmexit_cpuid:
		emulate_cpuid(v, ctx);
		break;
	case vmexit_msr:
		handle_msr(v, cpu, ctx);
		break;
	case vmexit_vmmcall:
		emulate_vmmcall(v, cpu, ctx);
		break;
	case vmexit_excp1:
		if (cpu->svm.npt && cpu->svm.npt->pending_restore.active)
			restore_npt_single_step(v, cpu, false);
		else
			inject_exception(v, amd64_debug_exception);
		break;
	case vmexit_excp3:
		if (!amd_vh_handle_breakpoint(v, cpu) &&
			!amd_probe_handle_breakpoint(v, cpu, ctx)) {
			advance_guest_ip(v, 1);
			inject_exception(v, amd64_breakpoint);
		}
		break;
	case vmexit_excp6:
		inject_exception(v, amd64_invalid_opcode);
		break;
	case vmexit_npf:
		handle_npf(v, cpu);
		break;
	case vmexit_rdtscp:
		emulate_rdtscp(v, ctx);
		break;
	case vmexit_xsetbv:
		emulate_xsetbv(v, ctx);
		break;
	case vmexit_invd:
		emulate_privileged_cache_op(v, 2, false);
		break;
	case vmexit_invlpg:
		v->tlb_control = 1;
		mark_vmcb_dirty(v);
		advance_guest_ip(v, 3);
		break;
	case vmexit_invlpga:
		inject_exception(v, amd64_invalid_opcode);
		break;
	case vmexit_wbinvd:
		emulate_privileged_cache_op(v, 2, true);
		break;
	case vmexit_vmrun:
	case vmexit_vmload:
	case vmexit_vmsave:
	case vmexit_stgi:
	case vmexit_clgi:
	case vmexit_skinit:
		// SVM is hidden from the guest, so executing SVM-only instructions
		// should look like bare-metal with SVM unavailable.
		inject_exception(v, amd64_invalid_opcode);
		break;
	case vmexit_invalid:
	case vmexit_shutdown: {
		if (_InterlockedCompareExchange(&g_hv_panic_dump_claimed, 1, 0) == 0)
			bugcheck_from_svm_vmexit(cpu, ctx, 0xDEAD00FEULL);
		cpu->svm.should_stop = true;
		cpu->stop_virtualization = true;
		v->rflags |= (1ull << 9);
		return true;
	}
	default:
		inject_exception(v, amd64_general_protection, 0);
		break;
	}

	// AMD has no MTF. If a hooked page's one-instruction window exits for an
	// intercepted instruction (CPUID/MSR/VMMCALL/etc.) instead of #DB, the
	// instruction was emulated here, so close the window before re-entering.
	if (v->exitcode != vmexit_npf &&
		v->exitcode != vmexit_excp1 &&
		cpu->svm.npt &&
		cpu->svm.npt->pending_restore.active)
		restore_npt_single_step(v, cpu, false);

	u32 want_excp = 0;
	if (cpu->svm.npt && cpu->svm.npt->pending_restore.active)
		want_excp |= (1u << amd64_debug_exception);
	if (hv::g_ghv) {
		bool want_bp = hv::g_ghv->tramp_pool.user_ready || hv::g_ghv->tramp_pool.kernel_ready;
		if (!want_bp) {
			for (auto const& s : hv::g_ghv->probe_table.slots) {
				if (s.active) {
					want_bp = true;
					break;
				}
			}
		}
		if (want_bp)
			want_excp |= (1u << amd64_breakpoint);
	}
	if (v->intercept_exceptions != want_excp) {
		v->intercept_exceptions = want_excp;
		mark_vmcb_dirty(v);
	}

	if (!v->eventinj.valid)
		reinject_exitintinfo_if_valid(v);

	v->rax = ctx->rax;
	return cpu->stop_virtualization || cpu->svm.should_stop;
}

} // namespace svm

