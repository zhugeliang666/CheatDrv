#pragma once

#include "amd64.h"
#include <stddef.h>

namespace svm {

// AMD SVM #VMEXIT codes used by the TestDriver AMD backend. Values mirror the
// AMD APM and match DBVM's vmeventhandler_amd.h naming.
enum exit_code : u64 {
	vmexit_cr0_read  = 0x00,
	vmexit_cr3_read  = 0x03,
	vmexit_cr4_read  = 0x04,
	vmexit_cr0_write = 0x10,
	vmexit_cr3_write = 0x13,
	vmexit_cr4_write = 0x14,
	vmexit_excp0     = 0x40,
	vmexit_excp1     = 0x41,
	vmexit_excp3     = 0x43,
	vmexit_excp6     = 0x46,
	vmexit_excp14    = 0x4e,
	vmexit_intr      = 0x60,
	vmexit_nmi       = 0x61,
	vmexit_cpuid     = 0x72,
	vmexit_invd      = 0x76,
	vmexit_hlt       = 0x78,
	vmexit_invlpg    = 0x79,
	vmexit_invlpga   = 0x7a,
	vmexit_msr       = 0x7c,
	vmexit_shutdown  = 0x7f,
	vmexit_vmrun     = 0x80,
	vmexit_vmmcall   = 0x81,
	vmexit_vmload    = 0x82,
	vmexit_vmsave    = 0x83,
	vmexit_stgi      = 0x84,
	vmexit_clgi      = 0x85,
	vmexit_skinit    = 0x86,
	vmexit_rdtscp    = 0x87,
	vmexit_wbinvd    = 0x89,
	vmexit_xsetbv    = 0x8d,
	vmexit_npf       = 0x400,
	vmexit_invalid   = 0xffffffffffffffffull,
};

enum intercept_instruction1 : u32 {
	intercept_intr      = 1u << 0,
	intercept_nmi       = 1u << 1,
	intercept_smi       = 1u << 2,
	intercept_init      = 1u << 3,
	intercept_vintr     = 1u << 4,
	intercept_cpuid     = 1u << 18,
	intercept_invd      = 1u << 22,
	intercept_hlt       = 1u << 24,
	intercept_invlpg    = 1u << 25,
	intercept_invlpga   = 1u << 26,
	intercept_ioio_prot = 1u << 27,
	intercept_msr_prot  = 1u << 28,
	intercept_shutdown  = 1u << 31,
};

enum intercept_instruction2 : u32 {
	intercept_vmrun   = 1u << 0,
	intercept_vmmcall = 1u << 1,
	intercept_vmload  = 1u << 2,
	intercept_vmsave  = 1u << 3,
	intercept_stgi    = 1u << 4,
	intercept_clgi    = 1u << 5,
	intercept_skinit  = 1u << 6,
	intercept_rdtscp  = 1u << 7,
	intercept_wbinvd  = 1u << 9,
	intercept_xsetbv  = 1u << 13,
};

// VMCB clean bit groups. During bring-up we will use conservative
// vmcb_clean_bits=0; these flags document the DBVM-compatible fast path.
enum clean_bits : u32 {
	clean_intercepts = 1u << 0,
	clean_iopm       = 1u << 1,
	clean_msrpm      = 1u << 2,
	clean_asid       = 1u << 3,
	clean_np         = 1u << 4,
	clean_crx        = 1u << 5,
	clean_dr         = 1u << 6,
	clean_dt         = 1u << 7,
	clean_seg        = 1u << 8,
	clean_cr2        = 1u << 9,
	clean_lbr        = 1u << 10,
	clean_avic       = 1u << 11,
};

union event_injection {
	u64 flags;
	struct {
		u64 vector : 8;
		u64 type : 3;
		u64 error_code_valid : 1;
		u64 reserved0 : 19;
		u64 valid : 1;
		u64 error_code : 32;
	};
};

union npf_error_code {
	u64 flags;
	struct {
		u64 present : 1;
		u64 write : 1;
		u64 user : 1;
		u64 reserved_write : 1;
		u64 execute : 1;
		u64 reserved0 : 27;
		u64 guest_paging : 1;
		u64 final_physical : 1;
		u64 reserved1 : 30;
	};
};

#pragma pack(push, 1)

struct segment {
	u16 selector;
	u16 attrib;
	u32 limit;
	u64 base;
};

struct vmcb {
	// 0x000 - control area
	u16 intercept_cr_read;
	u16 intercept_cr_write;
	u16 intercept_dr_read;
	u16 intercept_dr_write;
	u32 intercept_exceptions;
	u32 intercept_instruction1;
	u32 intercept_instruction2;
	u8  reserved0[0x3c - 0x14];
	u16 pause_filter_threshold;
	u16 pause_filter_count;
	u64 iopm_base_pa;
	u64 msrpm_base_pa;
	u64 tsc_offset;
	u32 guest_asid;
	u8  tlb_control;
	u8  reserved1[3];
	u8  v_tpr;
	u8  v_irq_gif;
	u8  v_intr_prio_ign_tpr;
	u8  v_intr_masking;
	u8  v_intr_vector;
	u8  reserved2[3];
	u64 interrupt_shadow;
	u64 exitcode;
	u64 exitinfo1;
	u64 exitinfo2;
	u64 exitintinfo;
	u64 np_enable;
	u8  reserved3[0x10];
	event_injection eventinj;
	u64 n_cr3;
	u64 lbr_virtualization_enable;
	u32 vmcb_clean_bits;
	u32 reserved4;
	u64 nrip;
	u8  number_of_bytes_fetched;
	u8  guest_instruction_bytes[15];
	u8  reserved5[0x400 - 0xe0];

	// 0x400 - state save area
	segment es;
	segment cs;
	segment ss;
	segment ds;
	segment fs;
	segment gs;
	segment gdtr;
	segment ldtr;
	segment idtr;
	segment tr;
	u8  reserved6[43];
	u8  cpl;
	u32 reserved7;
	u64 efer;
	u8  reserved8[112];
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u8  reserved9[88];
	u64 rsp;
	u8  reserved10[24];
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kernel_gs_base;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8  reserved11[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;
};

#pragma pack(pop)

static_assert(offsetof(vmcb, intercept_cr_read) == 0x000, "bad VMCB layout");
static_assert(offsetof(vmcb, pause_filter_threshold) == 0x03c, "bad VMCB layout");
static_assert(offsetof(vmcb, iopm_base_pa) == 0x040, "bad VMCB layout");
static_assert(offsetof(vmcb, guest_asid) == 0x058, "bad VMCB layout");
static_assert(offsetof(vmcb, exitcode) == 0x070, "bad VMCB layout");
static_assert(offsetof(vmcb, np_enable) == 0x090, "bad VMCB layout");
static_assert(offsetof(vmcb, eventinj) == 0x0a8, "bad VMCB layout");
static_assert(offsetof(vmcb, n_cr3) == 0x0b0, "bad VMCB layout");
static_assert(offsetof(vmcb, vmcb_clean_bits) == 0x0c0, "bad VMCB layout");
static_assert(offsetof(vmcb, nrip) == 0x0c8, "bad VMCB layout");
static_assert(offsetof(vmcb, es) == 0x400, "bad VMCB layout");
static_assert(offsetof(vmcb, cs) == 0x410, "bad VMCB layout");
static_assert(offsetof(vmcb, efer) == 0x4d0, "bad VMCB layout");
static_assert(offsetof(vmcb, cr4) == 0x548, "bad VMCB layout");
static_assert(offsetof(vmcb, rip) == 0x578, "bad VMCB layout");
static_assert(offsetof(vmcb, rsp) == 0x5d8, "bad VMCB layout");
static_assert(offsetof(vmcb, rax) == 0x5f8, "bad VMCB layout");
static_assert(offsetof(vmcb, g_pat) == 0x668, "bad VMCB layout");
static_assert(sizeof(vmcb) <= 0x1000, "VMCB must fit in one 4KB page");

} // namespace svm
