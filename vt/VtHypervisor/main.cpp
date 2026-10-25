#include "fltKernel.h"
#include "vt/hv.h"
#include "vtcall-hook.h"
#include "base.h"
#include <ntimage.h>
#include "intrin.h"
#include "vt/hypercalls.h"
#include "common/ntutils.h"
#include <poolmanager/PoolManager.h>
#include "common/ntapi.h"
#include "amd/svm.h"

extern "C" uint8_t __ImageBase;

static constexpr uint64_t YVT_BOOT_MAGIC = 0x595654424F4F5431ull; // YVTBOOT1
static constexpr uint64_t YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD = 0x00000001ull;
static constexpr uint64_t YVT_BOOT_FLAG_LEGACY_UNINIT_ON_UNLOAD = 0x00000002ull;
static constexpr uint64_t YVT_BOOT_FLAG_EXTERNAL_STATE = 0x00000004ull;
static constexpr uint64_t YVT_BOOT_CONTEXT_BASE_SIZE = 4 * sizeof(uint64_t);
static constexpr uint64_t YVT_BOOT_CONTEXT_ARENA_SIZE = 7 * sizeof(uint64_t);

struct yvt_boot_context
{
	uint64_t magic;
	uint64_t size;
	uint64_t flags;
	uint64_t status;
	uint64_t state_arena;
	uint64_t state_arena_size;
	uint64_t state_arena_used;
	uint64_t mm_allocate_independent_pages;
	uint64_t mm_free_independent_pages;
	uint64_t mm_set_page_protection;
};

static volatile uint64_t g_yvt_boot_flags = 0;
static uint8_t* g_yvt_state_base = nullptr;
static uint64_t g_yvt_state_size = 0;
static uint64_t g_yvt_state_used = 0;
static bool g_yvt_external_state_active = false;

static bool yvt_boot_has_kernel_alloc_api(const yvt_boot_context* boot)
{
	return boot &&
		boot->size >= (FIELD_OFFSET(yvt_boot_context, mm_set_page_protection) + sizeof(boot->mm_set_page_protection)) &&
		boot->mm_allocate_independent_pages &&
		boot->mm_free_independent_pages &&
		boot->mm_set_page_protection;
}

static void yvt_apply_boot_kernel_alloc_api(const yvt_boot_context* boot)
{
	if (!yvt_boot_has_kernel_alloc_api(boot))
		return;

	*(uint64_t*)&MmAllocateIndependentPages = boot->mm_allocate_independent_pages;
	*(uint64_t*)&MmFreeIndependentPages = boot->mm_free_independent_pages;
	*(uint64_t*)&MmSetPageProtection = boot->mm_set_page_protection;

	LOG_DEBUG(_XOR_("[YVT] boot alloc api alloc=%p free=%p prot=%p\n"),
		MmAllocateIndependentPages, MmFreeIndependentPages, MmSetPageProtection);
}

static void yvt_init_symbols_expanded()
{
	typedef NTSTATUS(NTAPI* PKEXPAND_STACK_EX)(PEXPAND_STACK_CALLOUT, PVOID, SIZE_T, BOOLEAN, PVOID);
	UNICODE_STRING fname;
	RtlInitUnicodeString(&fname, L"KeExpandKernelStackAndCalloutEx");
	auto pExpand = (PKEXPAND_STACK_EX)MmGetSystemRoutineAddress(&fname);
	if (pExpand) {
		NTSTATUS expandStatus = pExpand([](PVOID) { g_yvt.InitNtSymbol(); }, nullptr, 24 * 1024, TRUE, nullptr);
		if (!NT_SUCCESS(expandStatus))
			LOG_DEBUG(_XOR_("[YVT] InitNtSymbol expanded-stack call failed: 0x%08X\n"), expandStatus);
	}
	else
		g_yvt.InitNtSymbol();
}

static uint64_t yvt_align_up_u64(uint64_t value, uint64_t align)
{
	if (!align)
		return value;
	return (value + align - 1) & ~(align - 1);
}

static void* yvt_state_alloc(uint64_t size, uint64_t align)
{
	if (!g_yvt_state_base || !g_yvt_state_size || !size)
		return nullptr;

	if (!align || (align & (align - 1)) != 0)
		align = 16;

	uint64_t const off = yvt_align_up_u64(g_yvt_state_used, align);
	if (off > g_yvt_state_size || size > (g_yvt_state_size - off))
		return nullptr;

	void* ptr = g_yvt_state_base + off;
	RtlZeroMemory(ptr, (SIZE_T)size);
	g_yvt_state_used = off + size;
	return ptr;
}

static void yvt_try_activate_external_state(yvt_boot_context* boot)
{
	if (!boot || boot->size < YVT_BOOT_CONTEXT_ARENA_SIZE)
		return;

	boot->state_arena_used = 0;
	if ((boot->flags & YVT_BOOT_FLAG_EXTERNAL_STATE) == 0 ||
		!boot->state_arena ||
		boot->state_arena_size < (sizeof(hv::hypervisor) + sizeof(hv::vt_hook_slot) * VMCALL_HOOK_MAX + 0x2000ull))
	{
		return;
	}

	g_yvt_state_base = (uint8_t*)boot->state_arena;
	g_yvt_state_size = boot->state_arena_size;
	g_yvt_state_used = boot->state_arena_used;

	auto hv_state = (hv::hypervisor*)yvt_state_alloc(sizeof(hv::hypervisor), 0x1000);
	auto vt_state = (hv::vt_hook_slot*)yvt_state_alloc(sizeof(hv::vt_hook_slot) * VMCALL_HOOK_MAX, 0x1000);
	if (!hv_state || !vt_state)
	{
		boot->status = STATUS_INSUFFICIENT_RESOURCES;
		if (boot->size >= YVT_BOOT_CONTEXT_ARENA_SIZE)
			boot->state_arena_used = g_yvt_state_used;
		LOG_DEBUG(_XOR_("[YVT] external state alloc failed arena=0x%llX size=0x%llX used=0x%llX need ghv=0x%zX vt=0x%zX\n"),
			boot->state_arena, boot->state_arena_size, g_yvt_state_used,
			sizeof(hv::hypervisor), sizeof(hv::vt_hook_slot) * VMCALL_HOOK_MAX);
		return;
	}

	hv::g_ghv = hv_state;
	hv::g_vt_hook_table = vt_state;
	g_yvt_external_state_active = true;
	if (boot->size >= YVT_BOOT_CONTEXT_ARENA_SIZE)
		boot->state_arena_used = g_yvt_state_used;
	boot->status = STATUS_SUCCESS;
	LOG_DEBUG(_XOR_("[YVT] external state active arena=0x%llX size=0x%llX used=0x%llX ghv=0x%p/0x%zX vt=0x%p/0x%zX\n"),
		boot->state_arena, boot->state_arena_size, boot->state_arena_used,
		hv::g_ghv, sizeof(hv::hypervisor), hv::g_vt_hook_table,
		sizeof(hv::vt_hook_slot) * VMCALL_HOOK_MAX);
}


extern "C" void yvt_set_keep_hv_on_unload(bool enable)
{
	if (enable)
		g_yvt_boot_flags |= YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
	else
		g_yvt_boot_flags &= ~YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
}

extern "C" volatile uint64_t* yvt_get_boot_flags_ptr()
{
	return &g_yvt_boot_flags;
}

// simple hypercall wrappers
static uint64_t ping() {


	hv::hypercall_input input;
	input.code = hv::hypercall_ping;
	input.key = hv::hypercall_key;
	return hv::vmx_vmcall(input);

}

static void vmcall_hide_phy_page(ULONG64 const pfn) {


	hv::hypercall_input input;
	// 锟斤拷锟絟ypercall_input
	input.code = hv::hypercall_hide_physical_page;
	input.key = hv::hypercall_key;
	input.args[0] = pfn;


	for (size_t i = 0; i < KeQueryActiveProcessorCount(0); i++)
	{
		auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);
		//执锟斤拷vmcall
		hv::vmx_vmcall(input);

		KeRevertToUserAffinityThreadEx(orig_affinity);
	}

}

// memorypool removed 鈥 was a dead nullptr global.

bool DeleteRegistryKey(PUNICODE_STRING RegistryPath)
{
	VMB
		NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES oa;
	HANDLE reg = NULL;

	if (!RegistryPath)
		return false;

	// 锟斤拷始锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷
	InitializeObjectAttributes(&oa,
		RegistryPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	// 锟斤拷删锟斤拷权锟睫达拷注锟斤拷锟斤拷锟
	ntStatus = ZwOpenKey(&reg, DELETE, &oa);
	if (ntStatus != STATUS_SUCCESS)
		return false;

	// 执锟斤拷删锟斤拷锟斤拷锟斤拷
	ntStatus = ZwDeleteKey(reg);

	// 锟斤拷锟斤拷删锟斤拷锟角凤拷晒锟斤拷锟斤拷乇站锟斤拷
	ZwClose(reg);

	return NT_SUCCESS(ntStatus);
	VME
}

// Self-hide is now driven by mapDriver via hypercall_prepare_self_hide_add /
// _commit. mapDriver collects PFNs (its own image, testDriver image, both
// PoolManager pools) and pushes them through the hypercall, then commits.
// The vm-exit dispatcher (vt/vcpu.cpp handle_vm_exit) consumes the queue on
// each vcpu's first qualifying VM-exit after commit.
//
// Doing it from testDriver's DriverEntry (the previous approach) couldn't
// hide mapDriver's footprint and required testDriver to know about every
// allocation it made 锟斤拷 moving control to mapDriver lets it batch-include
// its own allocations and the per-section 只读 step in the same flow.

void Driver_Unload(PDRIVER_OBJECT driver)
{
	VMB

	//DeleteDriverFile(driver);


	UNREFERENCED_PARAMETER(driver);

	if (g_yvt_boot_flags & YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD)
	{
		LOG_DEBUG(_XOR_("[YVT] Driver Unload skipped: resident HV requested flags=0x%llX\n"),
			g_yvt_boot_flags);
		return;
	}




	LOG_DEBUG(_XOR_("[YVT] Driver Unload: stopping hypervisor\n"));

	bool hv_stopped = hv::stop();
	if (hv_stopped)
	{
		// The AMD stop watchdog uses a cross-processor DPC.  Its timer is
		// cancelled by hv::stop(), then queued/running DPC work must drain
		// before the mapped image and its globals can be released.
		KeFlushQueuedDpcs();
		Util::PoolManagerUninitialize();
		RtlZeroMemory(hv::g_ghv, sizeof(*hv::g_ghv));
	}
	else
	{
		LOG_DEBUG(_XOR_("[YVT] Driver Unload: hv::stop incomplete, pool cleanup skipped\n"));
	}

	LOG_DEBUG((_XOR_("[YVT] Driver Unload\n")));

	VME
}


// Dumps only the VT-engine memory that is allocated separately at runtime.
// Inline members of hv::ghv / vcpu are not printed -- they share the parent block.
// Runtime-allocated objects:
//   - hv::ghv             (driver-image global, single block; all inline subfields share it)
//   - g_cr3_map.pml4e     ('pml4' tag, heap)
//   - vcpus[]             ('vcpu' tag, heap)
//   - vcpus[i].host_stack ('stak' tag, heap, one per vcpu)
void DumpVtMemoryLayout()
{
	LOG_DEBUG(_XOR_("----------------------------------------------------------------\n"));
	LOG_DEBUG(_XOR_("[VT] === VT engine memory layout (runtime allocations only) ===\n"));
	LOG_DEBUG(_XOR_("----------------------------------------------------------------\n"));

	// ---- VT-1. hv::ghv global block (driver-image BSS, one contiguous block) ----
	LOG_DEBUG(_XOR_("[VT-1] hv::ghv  @0x%p  size=0x%zX  (single block; host_page_tables/logger/dummy_page/*_list/g_cr3_map/ept_hook_table all inline)\n"),
		hv::g_ghv, sizeof(*hv::g_ghv));

	// ---- VT-2. CR3 map PML4 (heap, 'pml4' tag) ----
	LOG_DEBUG(_XOR_("[VT-2] g_cr3_map.pml4e  @0x%p  size=0x1000  ('pml4' tag, heap)\n"),
		hv::g_ghv->g_cr3_map.pml4e);

	// ---- VT-3. VCPU 数组 (heap, 'vcpu' tag) ----
	if (!hv::g_ghv->vcpus)
	{
		LOG_DEBUG(_XOR_("[VT-3] vcpus  <not allocated>\n"));
		LOG_DEBUG(_XOR_("----------------------------------------------------------------\n"));
		return;
	}
	auto const vcpu_count = hv::g_ghv->vcpu_count;
	auto const sz_each    = sizeof(hv::vcpu);
	LOG_DEBUG(_XOR_("[VT-3] vcpus  base=0x%p  count=%u  sizeof(vcpu)=0x%zX  total=0x%zX  ('vcpu' tag, heap; vmxon/vmcs/msr_bitmap/host_idt/host_gdt/host_tss/msr_*/cached/ept all inline)\n"),
		hv::g_ghv->vcpus, vcpu_count, sz_each, sz_each * vcpu_count);

	// ---- VT-4. Per-VCPU host_stack (heap, 'stak' tag) ----
	LOG_DEBUG(_XOR_("[VT-4] host_stack  ('stak' tag, heap, %u x 0x%X)\n"),
		vcpu_count, (ULONG)hv::host_stack_size);
	for (unsigned i = 0; i < vcpu_count; i++) {
		LOG_DEBUG(_XOR_("    vcpu[%u].host_stack  @0x%p\n"),
			i, hv::g_ghv->vcpus[i].host_stack);
	}

	LOG_DEBUG(_XOR_("----------------------------------------------------------------\n"));
}

// Prints only memory that is stored in genuinely separate regions:
//   [1] Driver image  -- single .sys load (all BSS globals: g_yvt / hv::ghv /
//                        Util::Pools / epthook::g_hook_data
// 指针; and all linker sections .text / .vm2
//                        .vm2data / .rdata / ... are inline within this image)
//   [2] PoolManager heap blocks -- every PoolManagertAllocation call is a
//                                  separate region (tags: vcpu / stak / pml4 /
//                                  epth / ...). PoolManagerDumpStats() lists them.
//   [3] VT runtime allocations -- detailed breakdown of the hv:: side
//                                 (hv::ghv block + vcpus + per-vcpu host_stack
//                                  + g_cr3_map.pml4e). Subset of [2].
//   [4] External modules / processes -- NOT driver-owned memory, just cached
//                                       snapshots for reference.
void DumpMemoryLayout()
{
	LOG_DEBUG(_XOR_("\n"));
	LOG_DEBUG(_XOR_("================================================================\n"));
	LOG_DEBUG(_XOR_("[YVT] === MEMORY LAYOUT SNAPSHOT (separately-stored regions only) ===\n"));
	LOG_DEBUG(_XOR_("================================================================\n"));

	// ---- 1. Driver image (single block; all globals + linker sections inline) ----
	LOG_DEBUG(_XOR_("[1] Driver Image  base=0x%llX  size=0x%llX  (single .sys load; g_yvt/hv::ghv/Util::Pools/mouse_obj/g_hook_data* and all sections .vm2/.vm2data/.text/... inline)\n"),
		g_yvt.vtInfo.imageBase, g_yvt.vtInfo.imageSize);

	// ---- 2. PoolManager-tracked heap blocks (each allocation is a separate region) ----
	LOG_DEBUG(_XOR_("[2] PoolManager heap blocks (each PoolManagertAllocation = separate region)\n"));
	Util::PoolManagerDumpStats();

	// ---- 3. VT engine runtime allocations (detailed breakdown; subset of [2]) ----
	DumpVtMemoryLayout();

	// ---- 4. External modules / processes (NOT driver memory; cached snapshot) ----
	LOG_DEBUG(_XOR_("[4] External cached handles (not driver-owned memory)\n"));
	LOG_DEBUG(_XOR_("    csrss=0x%p  explorer=0x%p  dwm=0x%p\n"),
		g_yvt.csrss, g_yvt.exploer, g_yvt.dwm);
	LOG_DEBUG(_XOR_("    ntoskrnl   base=0x%llX size=0x%llX\n"), g_yvt.ntosInfo.imageBase,    g_yvt.ntosInfo.imageSize);
	LOG_DEBUG(_XOR_("    ntdll      base=0x%llX size=0x%llX\n"), g_yvt.ntdllInfo.imageBase,   g_yvt.ntdllInfo.imageSize);
	LOG_DEBUG(_XOR_("    kernelbase base=0x%llX size=0x%llX\n"), g_yvt.kernelbaseInfo.imageBase, g_yvt.kernelbaseInfo.imageSize);
	LOG_DEBUG(_XOR_("    user32     base=0x%llX size=0x%llX\n"), g_yvt.user32Info.imageBase,  g_yvt.user32Info.imageSize);
	LOG_DEBUG(_XOR_("    d2d1       base=0x%llX size=0x%llX\n"), g_yvt.d2d1Info.imageBase,    g_yvt.d2d1Info.imageSize);
	LOG_DEBUG(_XOR_("    d3d11      base=0x%llX size=0x%llX\n"), g_yvt.d3d11Info.imageBase,   g_yvt.d3d11Info.imageSize);

	LOG_DEBUG(_XOR_("================================================================\n"));
	LOG_DEBUG(_XOR_("[YVT] === END MEMORY LAYOUT ===\n"));
	LOG_DEBUG(_XOR_("================================================================\n\n"));
}

#ifndef YVT_RESIDENT_PAYLOAD_COPY
EXTERN_C NTSTATUS  DriverMain(IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath)
{
	// 初始化启动上下文并绑定外部分配器；完成虚拟化启动后把运行态交给 ResidentPayload。
	UNREFERENCED_PARAMETER(DriverObject);
	g_yvt_boot_flags = 0;
	auto boot = (yvt_boot_context*)RegistryPath;
	if (boot && boot->magic == YVT_BOOT_MAGIC && boot->size >= YVT_BOOT_CONTEXT_BASE_SIZE)
	{
		g_yvt_boot_flags = boot->flags;
		boot->status = STATUS_SUCCESS;
		yvt_apply_boot_kernel_alloc_api(boot);
		yvt_try_activate_external_state(boot);
	}
	yvt_init_symbols_expanded();
	// CPUID(0) 的 EBX/EDX/ECX 为 CPU 厂商；0x40000000 是 Hypervisor 厂商。
	int regs[4] = {};
	char cpu_vendor[13] = {};
	__cpuid(regs, 0);
	memcpy(cpu_vendor, &regs[1], sizeof(int));
	memcpy(cpu_vendor + 4, &regs[3], sizeof(int));
	memcpy(cpu_vendor + 8, &regs[2], sizeof(int));
	LOG_DEBUG(_XOR_("[YVT-BISECT4] CPU vendor=\"%s\"\n"), cpu_vendor);

	char hypervisor_vendor[13] = {};
	__cpuid(regs, 0x40000000);
	memcpy(hypervisor_vendor, &regs[1], sizeof(int));
	memcpy(hypervisor_vendor + 4, &regs[2], sizeof(int));
	memcpy(hypervisor_vendor + 8, &regs[3], sizeof(int));
	g_yvt.is_vmware_host =
		(hypervisor_vendor[0] == 'V' && hypervisor_vendor[1] == 'M' &&
		 hypervisor_vendor[2] == 'w' && hypervisor_vendor[3] == 'a');
	LOG_DEBUG(_XOR_("[YVT-BISECT4] hypervisor vendor=\"%s\" is_vmware=%d\n"),
		hypervisor_vendor, (int)g_yvt.is_vmware_host);

	g_yvt.vtInfo.imageBase = (uint64_t)&__ImageBase;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_yvt.vtInfo.imageBase;
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)g_yvt.vtInfo.imageBase + pDos->e_lfanew);
	g_yvt.vtInfo.imageSize = pNts->OptionalHeader.SizeOfImage;
	LOG_DEBUG(_XOR_("[YVT-BISECT4] image base=0x%llX size=0x%llX\n"),
		(uint64_t)g_yvt.vtInfo.imageBase, (uint64_t)g_yvt.vtInfo.imageSize);
	// 旧映像只负责建立初始虚拟化环境和导出交接所需状态。
	// 任一 vCPU 未确认迁出时都禁止释放映像，避免 Host RIP 或 Host 栈悬空。
	constexpr ULONG bootstrap_phase = 1;
	LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] production lifecycle start begin\n"), bootstrap_phase);
	bool const start_ok = hv::start();
	ULONG const started_cpus = (hv::g_ghv && hv::g_ghv->vcpus) ? hv::g_ghv->vcpu_count : 0;
	LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] production start result=%d cpus=%lu\n"),
		bootstrap_phase, (int)start_ok, started_cpus);

	uint64_t ping_result = 0;
	if (start_ok)
		ping_result = ping();
	LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] production ping result=0x%llX expected=0x%llX match=%d\n"),
		bootstrap_phase, ping_result, (uint64_t)hv::hypervisor_signature,
		(int)(ping_result == hv::hypervisor_signature));

	if (start_ok) {
		LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] post-start init complete\n"), bootstrap_phase);
	}
	else {
		LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] post-start init skipped: hv::start failed\n"), bootstrap_phase);
	}

	// 启动和签名探测成功后向 Bootstrap 发布卸载入口。
	// 清除 KEEP 标志，确保未完成 ResidentPayload 接管时仍能执行成对停止。
	if (start_ok && ping_result == hv::hypervisor_signature && DriverObject) {
		DriverObject->DriverUnload = Driver_Unload;
		g_yvt_boot_flags &= ~YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
		LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] handoff ready unload=%p flags=0x%llX; returning STATUS_SUCCESS\n"),
			bootstrap_phase, DriverObject->DriverUnload, g_yvt_boot_flags);
		return STATUS_SUCCESS;
	}
	LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] handoff rejected start=%d ping=%d driver=%p; local stop follows\n"),
		bootstrap_phase, (int)start_ok, (int)(ping_result == hv::hypervisor_signature), DriverObject);

	bool stop_ok = false;
	if (start_ok) {
		LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] production stop begin\n"), bootstrap_phase);
		stop_ok = hv::stop();
		LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] production stop result=%d phase=0x%llX expected=0x%llX after=0x%llX ack=0x%llX exc=0x%llX cleanup=0x%llX\n"),
			bootstrap_phase, (int)stop_ok,
			hv::g_ghv->stop_phase,
			hv::g_ghv->stop_expected_bitmap,
			hv::g_ghv->stop_after_vmcall_bitmap,
			hv::g_ghv->stop_ack_bitmap,
			hv::g_ghv->stop_exception_bitmap,
			hv::g_ghv->stop_cleanup_bitmap);
	}

	bool any_launched = false;
	if (hv::g_ghv && hv::g_ghv->vcpus) {
		for (ULONG i = 0; i < hv::g_ghv->vcpu_count; ++i) {
			if (hv::g_ghv->vcpus[i].svm.launched) {
				any_launched = true;
				break;
			}
		}
	}
	if (any_launched || (start_ok && !stop_ok)) {
		KeBugCheckEx(0xE2000A04u,
			start_ok ? 1 : 2,
			hv::g_ghv->stop_expected_bitmap,
			hv::g_ghv->stop_after_vmcall_bitmap,
			hv::g_ghv->stop_ack_bitmap);
	}

	KeFlushQueuedDpcs();
	Util::PoolManagerUninitialize();
	RtlZeroMemory(hv::g_ghv, sizeof(*hv::g_ghv));
	LOG_DEBUG(_XOR_("[YVT-BOOTSTRAP%lu] release complete start=%d ping=%d stop=%d; returning STATUS_NOT_SUPPORTED\n"),
		bootstrap_phase, (int)start_ok,
		(int)(ping_result == hv::hypervisor_signature),
		(int)stop_ok);
	return STATUS_NOT_SUPPORTED;
}
#endif
