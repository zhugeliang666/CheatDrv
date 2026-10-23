#include "fltKernel.h"
#include "vt/hv.h"
#include "base.h"
#include <ntimage.h>
#include "intrin.h"
#include "vt/hypercalls.h"
#include "gamecommon/game.h"
#include "gamecommon/gamecommon.h"
#include "../common/ntutils.h"
#include <memorymanager/memorymanager.h>
#include <poolmanager/PoolManager.h>
#include "dwm/kerneldwm.h"
#include <hv/hv.h>
#include "mouse/mouse.h"
#include "hook/epthook.h"
#include "hook/vtcallhook.h"
#include "pdb/khttp.h"
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
// its own allocations and the per-section read-only step in the same flow.

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




	if (g_yvt_boot_flags & YVT_BOOT_FLAG_LEGACY_UNINIT_ON_UNLOAD)
	{
		g_yvt.csrss = NT::GetProcessByName(_XOR_(L"csrss.exe"));
		g_yvt.exploer = NT::GetProcessByName(_XOR_(L"explorer.exe"));
		g_yvt.dwm = NT::GetProcessByName(_XOR_(L"dwm.exe"));

		dwm::UnInit();
		epthook::hook_uninit();
	}
	else
	{
		LOG_DEBUG(_XOR_("[YVT] Driver Unload: skip legacy DWM/EPTHook uninit for framework stop\n"));
	}

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

	// ---- VT-3. VCPU array (heap, 'vcpu' tag) ----
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
//                        Util::Pools / mouse::mouse_obj / epthook::g_hook_data
//                        pointer; and all linker sections .text / .vm2 /
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

EXTERN_C NTSTATUS  DriverMain(IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath)
{
#if YVT_ENTRY_BISECT_BYPASS == 1
	// Deliberately fail before touching either argument or executing any YVT
	// initialization.  Returning success would make mapDriver continue into the
	// resident payload path without an active hypervisor and would invalidate
	// this isolation test.
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	return STATUS_NOT_SUPPORTED;
#elif YVT_ENTRY_BISECT_BYPASS >= 2 && YVT_ENTRY_BISECT_BYPASS <= 10
	{
	// 阶段 2～10 共用 boot context 初始化；阶段 9/10 进入受控成功交接。
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
#if YVT_ENTRY_BISECT_BYPASS >= 3
	yvt_init_symbols_expanded();
#endif
#if YVT_ENTRY_BISECT_BYPASS >= 4
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
#endif
#if YVT_ENTRY_BISECT_BYPASS == 5
	// hv::start 的诊断分支只执行 create 和清理，不进入逐核虚拟化。
	(void)hv::start();
	LOG_DEBUG(_XOR_("[YVT-BISECT5] create-only returned; returning STATUS_NOT_SUPPORTED\n"));
#elif YVT_ENTRY_BISECT_BYPASS == 6
	// 诊断分支负责全部逐核停止确认与清理，不会保持活动 Hypervisor。
	(void)hv::start();
	LOG_DEBUG(_XOR_("[YVT-BISECT6] start/stop diagnostic returned; returning STATUS_NOT_SUPPORTED\n"));
#elif YVT_ENTRY_BISECT_BYPASS >= 7 && YVT_ENTRY_BISECT_BYPASS <= 10
	// 使用生产 hv::start/hv::stop 路径验证生命周期，但仍隔离后续 Hook、
	// ResidentPayload、VMB 和后台任务。阶段 8 只追加正常入口中的启动后初始化，
	// 不安装任何 Hook。任何未停止 vCPU 都禁止随失败返回释放当前映像，
	// 否则 Host RIP/栈仍可能指向已释放内存。
	constexpr ULONG diagnostic_stage = YVT_ENTRY_BISECT_BYPASS;
	LOG_DEBUG(_XOR_("[YVT-BISECT%lu] production lifecycle start begin\n"), diagnostic_stage);
	bool const start_ok = hv::start();
	ULONG const started_cpus = (hv::g_ghv && hv::g_ghv->vcpus) ? hv::g_ghv->vcpu_count : 0;
	LOG_DEBUG(_XOR_("[YVT-BISECT%lu] production start result=%d cpus=%lu\n"),
		diagnostic_stage, (int)start_ok, started_cpus);

	uint64_t ping_result = 0;
	if (start_ok)
		ping_result = ping();
	LOG_DEBUG(_XOR_("[YVT-BISECT%lu] production ping result=0x%llX expected=0x%llX match=%d\n"),
		diagnostic_stage, ping_result, (uint64_t)hv::hypervisor_signature,
		(int)(ping_result == hv::hypervisor_signature));

#if YVT_ENTRY_BISECT_BYPASS >= 8 && YVT_ENTRY_BISECT_BYPASS <= 10
	// 与普通入口保持相同顺序，但只执行不会安装运行时 Hook 的初始化。
	// mouse::init_mouse 只解析并缓存现有 MouClass/MouHID 对象；
	// epthook::hook_init 当前为空操作；handler 初始化只写本映像内的函数表。
	NTSTATUS mouse_status = STATUS_UNSUCCESSFUL;
	bool fake_data_seeded = false;
	if (start_ok) {
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init mouse begin\n"), diagnostic_stage);
		mouse_status = mouse::init_mouse(&mouse::mouse_obj);
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init mouse end status=0x%08X device=%p callback=%p use=%d\n"),
			diagnostic_stage, (ULONG)mouse_status,
			mouse::mouse_obj.mouse_device,
			mouse::mouse_obj.service_callback,
			(int)mouse::mouse_obj.use_mouse);

		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init epthook begin\n"), diagnostic_stage);
		epthook::hook_init();
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init epthook end\n"), diagnostic_stage);

		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init handlers begin\n"), diagnostic_stage);
		hv::init_vmcall_handlers();
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init handlers end max=%u\n"),
			diagnostic_stage, (UINT)VMCALL_HOOK_MAX);

		if (g_yvt.ntosInfo.imageBase && hv::g_ghv) {
			__try {
				memcpy(hv::g_ghv->fake_data,
					(void*)((ULONG64)g_yvt.ntosInfo.imageBase + 0x10000),
					0x1000);
				fake_data_seeded = true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				fake_data_seeded = false;
			}
		}
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init fake-data seeded=%d\n"),
			diagnostic_stage, (int)fake_data_seeded);
	}
	else {
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init skipped: hv::start failed\n"), diagnostic_stage);
	}

	// InitNtSymbol 可能建立 WSK 注册。停止并释放映像前必须先关闭它，
	// 避免网络栈保留指向当前诊断映像的回调。
	khttp::shutdown();
	LOG_DEBUG(_XOR_("[YVT-BISECT%lu] post-start init complete mouse=0x%08X fake=%d\n"),
		diagnostic_stage, (ULONG)mouse_status, (int)fake_data_seeded);
#endif

#if YVT_ENTRY_BISECT_BYPASS == 9 || YVT_ENTRY_BISECT_BYPASS == 10
	// 阶段 9/10 将活动 Hypervisor 交给 Bootstrap。阶段 9 直接往返卸载；
	// 阶段 10 先批量验证 ResidentPayload 的纯生命周期，再调用本映像的
	// DriverUnload。清除 KEEP 标志，确保最终 unload 执行生产 hv::stop。
	if (start_ok && ping_result == hv::hypervisor_signature && DriverObject) {
		DriverObject->DriverUnload = Driver_Unload;
		g_yvt_boot_flags &= ~YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] handoff ready unload=%p flags=0x%llX; returning STATUS_SUCCESS\n"),
			diagnostic_stage, DriverObject->DriverUnload, g_yvt_boot_flags);
		return STATUS_SUCCESS;
	}
	LOG_DEBUG(_XOR_("[YVT-BISECT%lu] handoff rejected start=%d ping=%d driver=%p; local stop follows\n"),
		diagnostic_stage, (int)start_ok, (int)(ping_result == hv::hypervisor_signature), DriverObject);
#endif

	bool stop_ok = false;
	if (start_ok) {
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] production stop begin\n"), diagnostic_stage);
		stop_ok = hv::stop();
		LOG_DEBUG(_XOR_("[YVT-BISECT%lu] production stop result=%d phase=0x%llX expected=0x%llX after=0x%llX ack=0x%llX exc=0x%llX cleanup=0x%llX\n"),
			diagnostic_stage, (int)stop_ok,
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
	LOG_DEBUG(_XOR_("[YVT-BISECT%lu] release complete start=%d ping=%d stop=%d; returning STATUS_NOT_SUPPORTED\n"),
		diagnostic_stage, (int)start_ok,
		(int)(ping_result == hv::hypervisor_signature),
		(int)stop_ok);
#endif
	return STATUS_NOT_SUPPORTED;
	}
#endif

	VMB

	NTSTATUS status = STATUS_SUCCESS;
	g_yvt_boot_flags = 0;

	auto boot = (yvt_boot_context*)RegistryPath;
	if (boot && boot->magic == YVT_BOOT_MAGIC && boot->size >= YVT_BOOT_CONTEXT_BASE_SIZE)
	{
		g_yvt_boot_flags = boot->flags;
		boot->status = STATUS_SUCCESS;
		yvt_apply_boot_kernel_alloc_api(boot);
		yvt_try_activate_external_state(boot);
		LOG_DEBUG(_XOR_("[YVT] boot context flags=0x%llX state=%d used=0x%llX status=0x%llX alloc=%p free=%p prot=%p\n"),
			g_yvt_boot_flags, (int)g_yvt_external_state_active,
			(boot->size >= YVT_BOOT_CONTEXT_ARENA_SIZE) ? boot->state_arena_used : 0,
			boot->status,
			MmAllocateIndependentPages, MmFreeIndependentPages, MmSetPageProtection);
	}
	else
	{
		UNREFERENCED_PARAMETER(RegistryPath);
	}

	yvt_init_symbols_expanded();

	LOG_DEBUG(_XOR_("[BUILD-CHECK] MAGIC-%d-XYZ\n"), 87654321);

	// Detect VMware host BEFORE hv::start (which disguises hypervisor leaf).
	// CPUID 0x40000000: EAX = max hyper leaf, EBX/ECX/EDX = vendor string.
	// VMware: "VMwareVMware". Hyper-V: "Microsoft Hv". KVM: "KVMKVMKVM".
	// Bare-metal: EBX=ECX=EDX=0 (no hypervisor present).
	{
		int regs[4] = {0};
		__cpuid(regs, 0x40000000);
		char vendor[13] = {0};
		*(int*)&vendor[0] = regs[1];
		*(int*)&vendor[4] = regs[2];
		*(int*)&vendor[8] = regs[3];
		g_yvt.is_vmware_host =
			(vendor[0] == 'V' && vendor[1] == 'M' && vendor[2] == 'w' && vendor[3] == 'a');
		LOG_DEBUG(_XOR_("[BUILD-CHECK] hypervisor vendor=\"%s\" is_vmware=%d\n"),
			vendor, (int)g_yvt.is_vmware_host);
	}

	if (DriverObject)
		DriverObject->DriverUnload = Driver_Unload;

	g_yvt.vtInfo.imageBase = (uint64_t)&__ImageBase;
	//锟斤拷取imagesize
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_yvt.vtInfo.imageBase;
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)g_yvt.vtInfo.imageBase + pDos->e_lfanew);
	g_yvt.vtInfo.imageSize = pNts->OptionalHeader.SizeOfImage;


	if (!hv::start())
	{
		LOG_DEBUG((_XOR_("[YVT] Failed to start hypervisor\n")));
		return STATUS_HV_OPERATION_FAILED;
	}

	if (ping() == hv::hypervisor_signature)
		LOG_DEBUG((_XOR_("[YVT] Hypervisor signature matches.\n")));
	else
		LOG_DEBUG((_XOR_("[YVT] Failed to ping hypervisor!\n")));


	mouse::init_mouse(&mouse::mouse_obj);

	epthook::hook_init();

	hv::init_vmcall_handlers();

	//game::init_overlay_hide_window();

	// Stage 锟斤拷: prepare for in-handler CallK(DbgPrintEx).
	// 1. Scan ntoskrnl for a 4-byte 0xCC run (kernel blank for CallK retRip).
	// 2. Reuse host-visible buffers preallocated before host page-table build.
	{
		if (!svm::available()) {
			// Find kernel blank inside ntoskrnl padding. Skip first 0x1000 to
			// avoid PE header area; scan up to 4MB which covers most padding.
			hv::g_ghv->kernel_blank_va = vtcallhook::find_blank_system(
				g_yvt.ntosInfo.imageBase + 0x1000,
				(ULONG)0x400000);
			LOG_DEBUG(_XOR_("[STAGE4] kernel_blank_va = 0x%llX\n"),
				hv::g_ghv->kernel_blank_va);
		}

		// Fake-data seed: 4 KB slice of ntoskrnl body content (offset
		// 0x10000, well past PE header). Mm* hooks fill caller buffers
		// from here on protected-region hits so anti-cheat sees a
		// successful copy of "normal kernel-looking bytes" instead of
		// all-zero or an explicit failure status 鈥 much harder to flag.
		if (g_yvt.ntosInfo.imageBase) {
			__try {
				memcpy(hv::g_ghv->fake_data,
					(void*)((ULONG64)g_yvt.ntosInfo.imageBase + 0x10000),
					0x1000);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				// Leave fake_data zeroed if the read faults.
			}
		}

		// Host-visible buffers are preallocated before prepare_host_page_tables()
		// in hv::create(), then explicitly mapped into the host CR3 there.
		LOG_DEBUG(_XOR_("[STAGE4] prealloc kfmt=0x%llX vlog=0x%llX vfmt=0x%llX csec=0x%llX cfmt=0x%llX\n"),
			hv::g_ghv->kernel_format_buf_va,
			hv::g_ghv->vt_log_ring_va,
			hv::g_ghv->vt_log_format_va,
			hv::g_ghv->csec_scratch_va,
			hv::g_ghv->csec_format_va);
		LOG_DEBUG(_XOR_("[STAGE4] prealloc afmt=0x%llX pfmt=0x%llX mfmt=0x%llX tram=%u/%u\n"),
			hv::g_ghv->alloc_format_va,
			hv::g_ghv->protect_format_va,
			hv::g_ghv->map_format_va,
			hv::g_ghv->tramp_prealloc_count,
			hv::hypervisor::TRAMP_PREALLOC_PAGE_COUNT);

		LOG_DEBUG(_XOR_("[TRAMP-K] ntos=0x%llX NtSetEvent_va=0x%llX\n"),
			g_yvt.ntosInfo.imageBase, NtSetEvent_va);
		if (!svm::available() && !hv::g_ghv->tramp_pool.kernel_ready) {
			dwm::bootstrap_tramp_pool(
				g_yvt.ntosInfo.imageBase,
				g_yvt.ntosInfo.imageSize,
				/*is_kernel=*/ true);
			LOG_DEBUG(_XOR_("[TRAMP-K] kernel_ready=%d kernel_slot_count=%u\n"),
				(int)hv::g_ghv->tramp_pool.kernel_ready,
				hv::g_ghv->tramp_pool.kernel_slot_count);
		}
	}

	// (g_diag_dump bank removed 锟斤拷 read g_ghv->diag_* directly via WinDbg)

	// All PDB lookups (find_offsets in hv::start + InitNtSymbol) done 锟斤拷 tear down
	// WSK so kernel no longer holds a registration pointing into driver image.
	khttp::shutdown();

#if YVT_DWM_HOOK_ENABLED
	if (!svm::available()) {
		dwm::Init();
	}
#else
	LOG_DEBUG(_XOR_("[YVT] DWM hook disabled; EPT-only test profile active\n"));
#endif



	DumpMemoryLayout();


	// Stage 锟斤拷 EPT self-check REMOVED 锟斤拷 was a system thread that waited 30s
	// for mmcopy_hook_installed, then compared host-PT vs EPT exec views.
	// Caused bugcheck 50 on driver unload: thread still running when
	// TestDriver.sys was unloaded, accessing freed code/data.
	// Verification was done manually (screenshot turned magenta = EPT works).



	return status;


	VME


}
