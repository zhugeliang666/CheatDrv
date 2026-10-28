#include "svm.h"
#include "amd64.h"
#include "vmcb.h"
#include "npt.h"
#include "../base.h"
#include "../vt/vcpu.h"
#include "../vt/arch.h"
#include "../vt/hv.h"
#include "../vt/idt.h"
#include "../vt/page-tables.h"
#include "../vt/segment.h"
#include "../poolmanager/PoolManager.h"
#include "../vt/hv.h"

#include <intrin.h>

namespace svm {

volatile unsigned long g_launch_stage[64] = {};

extern "C" unsigned __int64 svm_vmmcall_asm(hv::hypercall_input* input);
extern "C" void svm_clgi_asm();
extern "C" void svm_stgi_asm();
extern "C" void svm_vmsave_asm(unsigned __int64 pa);
extern "C" bool svm_launch_asm(svm::vmcb* vmcb,
	unsigned __int64 vmcb_pa,
	unsigned __int64 host_save_pa,
	unsigned __int64 host_rsp,
	hv::vcpu* cpu,
	unsigned __int64 host_cr3);

#ifndef YVT_RESIDENT_PAYLOAD_COPY
extern "C" unsigned __int64 svm_take_resident_loop_c(hv::vcpu* const cpu) {
	if (!cpu)
		return 0;

	return static_cast<unsigned __int64>(
		_InterlockedExchange64(
			reinterpret_cast<volatile LONG64*>(&cpu->svm.resident_loop),
			0));
}

extern "C" void svm_ack_resident_loop_c(hv::vcpu* const cpu) {
	if (!cpu)
		return;

	KeMemoryBarrier();
	_InterlockedExchange64(
		reinterpret_cast<volatile LONG64*>(&cpu->svm.resident_ack),
		1);
}
#endif

namespace {

features g_features = {};
bool g_features_initialized = false;

static void cpuid(int regs[4], int leaf) {
	__cpuid(regs, leaf);
}

static void cpuidex(int regs[4], int leaf, int subleaf) {
	__cpuidex(regs, leaf, subleaf);
}

static bool cpuid_vendor_is_amd() {
	int regs[4] = {};
	cpuid(regs, 0);

	// CPUID vendor order is EBX, EDX, ECX.
	// AuthenticAMD:
	//   EBX = "Auth" = 0x68747541
	//   EDX = "enti" = 0x69746E65
	//   ECX = "cAMD" = 0x444D4163
	return regs[1] == 0x68747541 &&
	       regs[3] == 0x69746E65 &&
	       regs[2] == 0x444D4163;
}

static void* alloc_contiguous(size_t const size) {
	PHYSICAL_ADDRESS low = {};
	PHYSICAL_ADDRESS high = {};
	PHYSICAL_ADDRESS boundary = {};
	high.QuadPart = MAXLONGLONG;

	auto const ptr = MmAllocateContiguousMemorySpecifyCache(
		size,
		low,
		high,
		boundary,
		MmCached);
	if (ptr)
		RtlZeroMemory(ptr, size);
	return ptr;
}

static void free_contiguous(void* const ptr) {
	if (ptr)
		MmFreeContiguousMemory(ptr);
}

static bool msrpm_bit_position(u32 msr, u32* const byte_offset, u8* const bit_offset) {
	u32 base = 0;

	if (msr <= 0x00001fff) {
		base = 0x0000;
	} else if (msr >= 0xc0000000 && msr <= 0xc0001fff) {
		base = 0x0800;
		msr -= 0xc0000000;
	} else if (msr >= 0xc0010000 && msr <= 0xc0011fff) {
		base = 0x1000;
		msr -= 0xc0010000;
	} else {
		return false;
	}

	u32 const bit = msr * 2;
	*byte_offset = base + (bit / 8);
	*bit_offset = static_cast<u8>(bit & 7);
	return true;
}

static void set_msrpm_intercept(void* const msrpm,
	u32 const msr,
	bool const read,
	bool const write)
{
	u32 byte_offset = 0;
	u8 bit_offset = 0;
	if (!msrpm || !msrpm_bit_position(msr, &byte_offset, &bit_offset))
		return;

	auto const bitmap = static_cast<u8*>(msrpm);
	if (read)
		bitmap[byte_offset] |= static_cast<u8>(1u << bit_offset);
	if (write)
		bitmap[byte_offset] |= static_cast<u8>(1u << ((bit_offset + 1) & 7));
}

static void prepare_msrpm(hv::vcpu* const cpu) {
	if (!cpu || !cpu->svm.msrpm)
		return;

	RtlZeroMemory(cpu->svm.msrpm, cpu->svm.msrpm_size);

	// Hide the SVM 启用 path while keeping it active for the host. This is
	// the same split-brain model DBVM uses for EFER/VM_HSAVE_PA.
	set_msrpm_intercept(cpu->svm.msrpm, amd64_efer, true, true);
	set_msrpm_intercept(cpu->svm.msrpm, amd64_vmcr, true, true);
	set_msrpm_intercept(cpu->svm.msrpm, amd64_hsave_pa, true, true);
	// Keep IA32_DEBUGCTL stable at the VMCB 值 (0).  The NPT hook
	// 单步执行 path uses RFLAGS.TF; allowing the guest to 设置 BTF would turn
	// that into branch-step and delay/skip the 恢复 VMEXIT.
	set_msrpm_intercept(cpu->svm.msrpm, amd64_debug_control, false, true);

	// Common virtualization/security probes should observe inert 状态.
	set_msrpm_intercept(cpu->svm.msrpm, amd64_svm_key, true, true);
	set_msrpm_intercept(cpu->svm.msrpm, amd64_svm_ghcb_pa, true, true);
	set_msrpm_intercept(cpu->svm.msrpm, amd64_sev_status, true, false);
}

static u16 svm_segment_attrib(vmx_segment_access_rights const access) {
	if (access.unusable)
		return 0;

	u16 attrib = static_cast<u16>(access.flags & 0xff);
	attrib |= static_cast<u16>((access.flags >> 4) & 0x0f00);
	return attrib;
}

static void fill_segment(segment& dst,
	segment_descriptor_register_64 const& gdtr,
	segment_selector const selector,
	u64 const forced_base = MAXUINT64)
{
	dst.selector = selector.flags;
	dst.attrib = svm_segment_attrib(hv::segment_access(gdtr, selector));
	dst.limit = __segmentlimit(selector.flags);
	dst.base = forced_base == MAXUINT64 ? hv::segment_base(gdtr, selector) : forced_base;
}

static void load_svm_host_idt(hv::vcpu* const cpu) {
	if (!cpu)
		return;

	hv::prepare_host_idt(cpu->host_idt);

	// Unlike VMX, SVM initially saves the currently executing host GDT/CS into
	// the host-保存 area. Keep the Windows host GDT and make our exception IDT
	// gates 目标 the currently valid CS selector so rdmsr_safe/memcpy_safe can
	// still recover via vt/interrupt-handlers.asm on AMD VMEXITs.
	auto const host_cs = hv::read_cs().flags;
	for (auto& gate : cpu->host_idt)
		if (gate.present)
			gate.segment_selector = host_cs;

	segment_descriptor_register_64 idtr = {};
	idtr.limit = static_cast<u16>(sizeof(cpu->host_idt) - 1);
	idtr.base_address = reinterpret_cast<u64>(cpu->host_idt);
	__lidt(&idtr);
}

} // namespace

bool detect(features* const out_features) {
	if (g_features_initialized) {
		if (out_features)
			*out_features = g_features;
		return g_features.is_amd &&
			g_features.svm_supported &&
			!g_features.svm_disabled &&
			g_features.npt_supported;
	}

	features f = {};
	f.is_amd = cpuid_vendor_is_amd();

	int regs[4] = {};
	cpuid(regs, amd64_cpuid_ext_max_num_vstr);
	f.max_ext_leaf = static_cast<uint32_t>(regs[0]);

	if (!f.is_amd || f.max_ext_leaf < amd64_cpuid_ext_proc_feature) {
		g_features = f;
		g_features_initialized = true;
		if (out_features)
			*out_features = f;
		return false;
	}

	cpuid(regs, amd64_cpuid_ext_proc_feature);
	f.svm_supported = (static_cast<uint32_t>(regs[2]) & amd64_cpuid_svm_bit) != 0;

	if (f.svm_supported) {
		__try {
			f.vm_cr = __readmsr(amd64_vmcr);
			f.svm_disabled = (f.vm_cr & (1ull << amd64_vmcr_svmdis)) != 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			f.svm_disabled = true;
		}
	}

	if (f.max_ext_leaf >= amd64_cpuid_ext_svm_features) {
		cpuidex(regs, amd64_cpuid_ext_svm_features, 0);
		f.svm_revision = static_cast<uint32_t>(regs[0]);
		f.max_asid = static_cast<uint32_t>(regs[1]);
		f.raw_8000000a_edx = static_cast<uint32_t>(regs[3]);
		f.npt_supported = (f.raw_8000000a_edx & amd64_cpuid_npt_bit) != 0;
		f.nrips_supported = (f.raw_8000000a_edx & amd64_cpuid_nrips_bit) != 0;
		f.decode_assists = (f.raw_8000000a_edx & amd64_cpuid_decoder_bit) != 0;
		f.vmcb_clean_bits = (f.raw_8000000a_edx & amd64_cpuid_vmcb_clean_bit) != 0;
		f.flush_by_asid = (f.raw_8000000a_edx & amd64_cpuid_flush_asid_bit) != 0;
	}

	g_features = f;
	g_features_initialized = true;
	if (out_features)
		*out_features = f;

	LOG_DEBUG(_XOR_("[VtHypervisor:AMD] detect amd=%d svm=%d disabled=%d npt=%d nrips=%d decode=%d clean=%d flush_asid=%d max_asid=%u vm_cr=0x%llX\n"),
		(int)f.is_amd,
		(int)f.svm_supported,
		(int)f.svm_disabled,
		(int)f.npt_supported,
		(int)f.nrips_supported,
		(int)f.decode_assists,
		(int)f.vmcb_clean_bits,
		(int)f.flush_by_asid,
		f.max_asid,
		f.vm_cr);

	return f.is_amd && f.svm_supported && !f.svm_disabled && f.npt_supported;
}

bool available() {
	features f = {};
	return detect(&f);
}

bool start() {
	features f = {};
	if (!detect(&f))
		return false;

	// Phase 0 deliberately does not mutate SVM CPU 状态. The full AMD backend
	// will replace this stub once VMCB/VMRUN/VMMCALL bring-up is committed.
	LOG_DEBUG(_XOR_("[VtHypervisor:AMD] SVM backend detected but launch is not enabled in Phase 0.\n"));
	return false;
}

void stop() {
	// Phase 0 has no mutated AMD SVM 状态 to tear down.
}

bool create_vcpu_state(hv::vcpu* const cpu, unsigned long const index) {
	if (!cpu)
		return false;

	if (cpu->svm.allocated)
		return true;

	cpu->svm.vmcb = static_cast<vmcb*>(alloc_contiguous(0x1000));
	cpu->svm.host_save = alloc_contiguous(0x1000);
	cpu->svm.host_vmcb = alloc_contiguous(0x1000);
	cpu->svm.msrpm_size = 0x2000;
	cpu->svm.msrpm = alloc_contiguous(cpu->svm.msrpm_size);
	cpu->svm.npt = static_cast<npt_data*>(
		ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(npt_data), 'tpnS'));

	if (!cpu->svm.vmcb || !cpu->svm.host_save || !cpu->svm.host_vmcb || !cpu->svm.msrpm || !cpu->svm.npt) {
		destroy_vcpu_state(cpu);
		return false;
	}

	if (hv::g_ghv->host_page_tables.pml4[hv::host_physical_memory_pml4_idx].present) {
		if (!hv::map_host_virtual_range(reinterpret_cast<u64>(cpu->svm.vmcb), 0x1000) ||
			!hv::map_host_virtual_range(reinterpret_cast<u64>(cpu->svm.host_save), 0x1000) ||
			!hv::map_host_virtual_range(reinterpret_cast<u64>(cpu->svm.host_vmcb), 0x1000) ||
			!hv::map_host_virtual_range(reinterpret_cast<u64>(cpu->svm.msrpm), cpu->svm.msrpm_size) ||
			!hv::map_host_virtual_range(reinterpret_cast<u64>(cpu->svm.npt), sizeof(npt_data))) {
			LOG_DEBUG(_XOR_("[VtHypervisor:AMD] Failed to map SVM state into host page tables.\n"));
			destroy_vcpu_state(cpu);
			return false;
		}
	}

	RtlZeroMemory(cpu->svm.npt, sizeof(npt_data));
	prepare_npt(*cpu->svm.npt);
	prepare_msrpm(cpu);

	cpu->svm.vmcb_pa = MmGetPhysicalAddress(cpu->svm.vmcb).QuadPart;
	cpu->svm.host_save_pa = MmGetPhysicalAddress(cpu->svm.host_save).QuadPart;
	cpu->svm.host_vmcb_pa = MmGetPhysicalAddress(cpu->svm.host_vmcb).QuadPart;
	cpu->svm.msrpm_pa = MmGetPhysicalAddress(cpu->svm.msrpm).QuadPart;
	cpu->svm.npt_pml4_pa = MmGetPhysicalAddress(cpu->svm.npt->pml4).QuadPart;
	cpu->svm.asid = index + 1;
	cpu->svm.host_rsp_base = cpu->host_stack
		? ((reinterpret_cast<uint64_t>(cpu->host_stack) + hv::host_stack_size) & ~0xfull) - 8
		: 0;
	cpu->svm.host_rsp_next = cpu->svm.host_rsp_base;
	cpu->svm.host_rsp_current = cpu->svm.host_rsp_base;
	cpu->svm.original_cr3 = __readcr3();
	cpu->svm.original_efer = __readmsr(amd64_efer);
	cpu->svm.original_hsave_pa = __readmsr(amd64_hsave_pa);
	cpu->svm.original_vm_cr = __readmsr(amd64_vmcr);
	cpu->svm.guest_efer = cpu->svm.original_efer & ~amd64_efer_svme_bit;
	cpu->svm.guest_hsave_pa = cpu->svm.original_hsave_pa;
	cpu->svm.guest_vm_cr = cpu->svm.original_vm_cr | (1ull << amd64_vmcr_svmdis);
	cpu->svm.allocated = true;
	cpu->svm.resident_loop = 0;
	cpu->svm.resident_ack = 0;

	LOG_DEBUG(_XOR_("[VtHypervisor:AMD] allocated svm state cpu=%u vmcb_pa=0x%llX hsave_pa=0x%llX host_vmcb_pa=0x%llX msrpm_pa=0x%llX npt_pa=0x%llX asid=%u\n"),
		index,
		cpu->svm.vmcb_pa,
		cpu->svm.host_save_pa,
		cpu->svm.host_vmcb_pa,
		cpu->svm.msrpm_pa,
		cpu->svm.npt_pml4_pa,
		cpu->svm.asid);

	return true;
}

void destroy_vcpu_state(hv::vcpu* const cpu) {
	if (!cpu)
		return;

	if (cpu->svm.npt) {
		ExFreePoolWithTag(cpu->svm.npt, 'tpnS');
		cpu->svm.npt = nullptr;
	}

	free_contiguous(cpu->svm.msrpm);
	free_contiguous(cpu->svm.host_vmcb);
	free_contiguous(cpu->svm.host_save);
	free_contiguous(cpu->svm.vmcb);

	cpu->svm.msrpm = nullptr;
	cpu->svm.host_vmcb = nullptr;
	cpu->svm.host_save = nullptr;
	cpu->svm.vmcb = nullptr;
	cpu->svm.allocated = false;
	cpu->svm.launched = false;
	cpu->svm.resident_loop = 0;
	cpu->svm.resident_ack = 0;
}

bool setup_vmcb_for_current_guest(hv::vcpu* const cpu, void* const guest_rip, void* const guest_rsp) {
	if (!cpu || !cpu->svm.vmcb || !cpu->svm.npt)
		return false;

	auto const vmcb = cpu->svm.vmcb;
	RtlZeroMemory(vmcb, sizeof(*vmcb));

	vmcb->intercept_exceptions = 0;
	vmcb->intercept_instruction1 =
		intercept_cpuid |
		intercept_invlpga |
		intercept_msr_prot |
		intercept_shutdown;
	vmcb->intercept_instruction2 =
		intercept_vmrun |
		intercept_vmmcall |
		intercept_vmload |
		intercept_vmsave |
		intercept_stgi |
		intercept_clgi |
		intercept_skinit;

	vmcb->msrpm_base_pa = cpu->svm.msrpm_pa;
	vmcb->guest_asid = cpu->svm.asid;
	vmcb->tlb_control = 1;
	vmcb->np_enable = 1;
	vmcb->n_cr3 = cpu->svm.npt_pml4_pa;
	vmcb->vmcb_clean_bits = 0;

	vmcb->cr0 = __readcr0();
	vmcb->cr2 = __readcr2();
	vmcb->cr3 = __readcr3();
	vmcb->cr4 = __readcr4();
	vmcb->dr6 = __readdr(6);
	vmcb->dr7 = __readdr(7);
	vmcb->rflags = __readeflags();
	vmcb->rip = reinterpret_cast<u64>(guest_rip);
	vmcb->rsp = reinterpret_cast<u64>(guest_rsp);
	vmcb->rax = 0;
	vmcb->efer = cpu->svm.guest_efer | amd64_efer_svme_bit;
	vmcb->g_pat = __readmsr(amd64_pat);
	vmcb->star = __readmsr(amd64_star);
	vmcb->lstar = __readmsr(amd64_lstar);
	vmcb->cstar = __readmsr(amd64_cstar);
	vmcb->sfmask = __readmsr(amd64_sfmask);
	vmcb->kernel_gs_base = __readmsr(amd64_kernel_gs_base);
	vmcb->sysenter_cs = __readmsr(amd64_sysenter_cs);
	vmcb->sysenter_esp = __readmsr(amd64_sysenter_esp);
	vmcb->sysenter_eip = __readmsr(amd64_sysenter_eip);
	vmcb->dbgctl = 0;

	segment_descriptor_register_64 gdtr = {};
	segment_descriptor_register_64 idtr = {};
	_sgdt(&gdtr);
	__sidt(&idtr);

	fill_segment(vmcb->cs, gdtr, hv::read_cs());
	fill_segment(vmcb->ss, gdtr, hv::read_ss());
	fill_segment(vmcb->ds, gdtr, hv::read_ds());
	fill_segment(vmcb->es, gdtr, hv::read_es());
	fill_segment(vmcb->fs, gdtr, hv::read_fs(), __readmsr(amd64_fs_base));
	fill_segment(vmcb->gs, gdtr, hv::read_gs(), __readmsr(amd64_gs_base));
	fill_segment(vmcb->tr, gdtr, hv::read_tr());
	fill_segment(vmcb->ldtr, gdtr, hv::read_ldtr());

	vmcb->gdtr.selector = 0;
	vmcb->gdtr.attrib = 0;
	vmcb->gdtr.limit = gdtr.limit;
	vmcb->gdtr.base = gdtr.base_address;

	vmcb->idtr.selector = 0;
	vmcb->idtr.attrib = 0;
	vmcb->idtr.limit = idtr.limit;
	vmcb->idtr.base = idtr.base_address;

	vmcb->cpl = vmcb->cs.attrib ? static_cast<u8>((vmcb->cs.attrib >> 5) & 3) : 0;
	return true;
}

bool launch_vcpu(hv::vcpu* const cpu) {
	unsigned long const index = (cpu && hv::g_ghv && hv::g_ghv->vcpus)
		? static_cast<unsigned long>(cpu - hv::g_ghv->vcpus)
		: MAXULONG;
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_enter;

	LOG_DEBUG(_XOR_("[YVT-SVM-LAUNCH] cpu=%lu stage=entry irql=%lu allocated=%d vmcb=%p vmcb_pa=0x%llX hsave_pa=0x%llX host_vmcb_pa=0x%llX host_rsp=%p\n"),
		index,
		static_cast<unsigned long>(KeGetCurrentIrql()),
		cpu ? static_cast<int>(cpu->svm.allocated) : 0,
		cpu ? cpu->svm.vmcb : nullptr,
		cpu ? cpu->svm.vmcb_pa : 0,
		cpu ? cpu->svm.host_save_pa : 0,
		cpu ? cpu->svm.host_vmcb_pa : 0,
		cpu ? reinterpret_cast<void*>(cpu->svm.host_rsp_base) : nullptr);

	if (!cpu || !cpu->svm.allocated || !cpu->svm.vmcb || !cpu->svm.host_save_pa || !cpu->svm.host_vmcb_pa) {
		LOG_DEBUG(_XOR_("[YVT-SVM-LAUNCH] cpu=%lu stage=validate result=0\n"), index);
		return false;
	}

	cr3 host_cr3 = {};
	host_cr3.address_of_page_directory =
		MmGetPhysicalAddress(&hv::g_ghv->host_page_tables.pml4).QuadPart >> 12;
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_host_cr3_ready;

	auto const old_efer = __readmsr(amd64_efer);
	auto const old_hsave = __readmsr(amd64_hsave_pa);
	auto const old_vm_cr = __readmsr(amd64_vmcr);
	cpu->svm.original_cr3 = __readcr3();
	cpu->svm.original_efer = old_efer;
	cpu->svm.original_hsave_pa = old_hsave;
	cpu->svm.original_vm_cr = old_vm_cr;
	cpu->svm.guest_efer = old_efer & ~amd64_efer_svme_bit;
	cpu->svm.guest_hsave_pa = old_hsave;
	cpu->svm.guest_vm_cr = old_vm_cr | (1ull << amd64_vmcr_svmdis);
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_msrs_captured;

	// Capture Guest 客户机状态 BEFORE touching IDTR or disabling interrupts so
	// vmcb->idtr captures the real Windows IDT and vmcb->rflags captures IF=1.
	LOG_DEBUG(_XOR_("[YVT-SVM-LAUNCH] cpu=%lu stage=setup-vmcb-before host_cr3=0x%llX original_cr3=0x%llX efer=0x%llX hsave=0x%llX vm_cr=0x%llX\n"),
		index, host_cr3.flags, cpu->svm.original_cr3, old_efer, old_hsave, old_vm_cr);
	bool const vmcb_ready = setup_vmcb_for_current_guest(cpu, nullptr, nullptr);
	LOG_DEBUG(_XOR_("[YVT-SVM-LAUNCH] cpu=%lu stage=setup-vmcb-after result=%d\n"),
		index, static_cast<int>(vmcb_ready));
	if (!vmcb_ready)
		return false;
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_vmcb_ready;

	segment_descriptor_register_64 old_idtr = {};
	__sidt(&old_idtr);
	segment_descriptor_register_64 host_gdtr = {};
	_sgdt(&host_gdtr);
	if (hv::g_ghv && hv::g_ghv->host_page_tables.pml4[hv::host_physical_memory_pml4_idx].present) {
		static volatile LONG s_host_gdt_map_lock = 0;
		while (_InterlockedCompareExchange(&s_host_gdt_map_lock, 1, 0) != 0)
			_mm_pause();
		if (host_gdtr.base_address)
			hv::map_host_virtual_range(host_gdtr.base_address, static_cast<size_t>(host_gdtr.limit) + 1);
		u64 const host_kpcr = __readmsr(amd64_gs_base);
		if (host_kpcr >= 0xFFFF800000000000ULL)
			hv::map_host_virtual_range(host_kpcr, 0x1000);
		_InterlockedExchange(&s_host_gdt_map_lock, 0);
	}

	cpu->svm.should_stop = false;
	cpu->stop_virtualization = false;
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_before_disable;
	LOG_DEBUG(_XOR_("[YVT-SVM-LAUNCH] cpu=%lu stage=critical-enter marker=%lu; no kernel logging until state restore/guest return\n"),
		index, static_cast<unsigned long>(launch_stage_before_disable));

	_disable();
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_if_disabled;
	__writemsr(amd64_efer, old_efer | amd64_efer_svme_bit);
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_efer_enabled;
	__writemsr(amd64_hsave_pa, cpu->svm.host_save_pa);
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_hsave_installed;
	svm_clgi_asm();
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_gif_cleared;

	svm_vmsave_asm(cpu->svm.vmcb_pa);
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_guest_saved;
	svm_vmsave_asm(cpu->svm.host_vmcb_pa);
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_host_saved;

	load_svm_host_idt(cpu);
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_host_idt_loaded;
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_asm_enter;

	bool const launched = svm_launch_asm(cpu->svm.vmcb,
		cpu->svm.vmcb_pa,
		cpu->svm.host_vmcb_pa,
		cpu->svm.host_rsp_base,
		cpu,
		host_cr3.flags);
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_asm_return;

	if (!launched) {
		__lidt(&old_idtr);
		svm_stgi_asm();
		__writemsr(amd64_hsave_pa, old_hsave);
		__writemsr(amd64_efer, old_efer);
		_enable();
		if (index < RTL_NUMBER_OF(g_launch_stage))
			g_launch_stage[index] = launch_stage_failure_restored;
		LOG_DEBUG(_XOR_("[YVT-SVM-LAUNCH] cpu=%lu stage=asm-return launched=0 restored=1 marker=%lu\n"),
			index, static_cast<unsigned long>(launch_stage_failure_restored));
		return false;
	}

	cpu->svm.launched = true;
	if (index < RTL_NUMBER_OF(g_launch_stage))
		g_launch_stage[index] = launch_stage_success;
	LOG_DEBUG(_XOR_("[YVT-SVM-LAUNCH] cpu=%lu stage=asm-return launched=1 marker=%lu\n"),
		index, static_cast<unsigned long>(launch_stage_success));
	return true;
}

unsigned __int64 vmmcall(hv::hypercall_input& input) {
	return svm_vmmcall_asm(&input);
}

} // namespace svm
