#pragma once
#include "fltKernel.h"
#include "../ia32.hpp"
#include "../kli.hpp"
#include "../poolmanager/PoolManager.h"


namespace hv {

#pragma code_seg(".vm")


uint64_t vmx_vmcall(hypercall_input& input);

uint64_t vmx_vmcall(hypercall_input* input);



static void vmcall_hide_phy_page(ULONG64 const pfn) {

    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');

    memset(input, 0, sizeof(*input));
    // 填充hypercall_input
    input->code = hv::hypercall_hide_physical_page;
    input->key = hv::hypercall_key;
    input->args[0] = pfn;


    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }

    Util::PoolManagerFreePool(input);

}

static void vmcall_unhide_phy_page(ULONG64 const pfn) {


    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    memset(input, 0, sizeof(*input));
    // 填充hypercall_input
    input->code = hv::hypercall_unhide_physical_page;
    input->key = hv::hypercall_key;
    input->args[0] = pfn;


    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }
    Util::PoolManagerFreePool(input);

}

static void vmcall_instal_ept_hook(uint64_t pf, uint64_t fake_pf, bool is_fake_page) {



    //获取hypercall_input
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    //填充hypercall_input
    input->code = hv::hypercall_install_ept_hook;
    input->key = hv::hypercall_key;
    input->args[0] = pf >> 12;
    input->args[1] = fake_pf >> 12;
    input->args[2] = is_fake_page;

    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }

    Util::PoolManagerFreePool(input);

}

static bool vmcall_save_image_base(uint64_t image_base, uint64_t unload) {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_save_gamevt_image_base;
    input->key = hv::hypercall_key;

    input->args[0] = image_base;
    input->args[1] = unload;
    bool result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;
}


static void vmcall_remove_ept_hook(uint64_t pf) {



    //获取hypercall_input
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    //填充hypercall_input
    input->code = hv::hypercall_remove_ept_hook;
    input->key = hv::hypercall_key;
    input->args[0] = pf >> 12;

    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }
    Util::PoolManagerFreePool(input);

}

static void vmcall_install_bp_hook(uint64_t cr3, uint64_t origin_va, uint64_t fake_va, bool is_cr3_monitor_hook)
{


    // 获取hypercall_input
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    // 填充hypercall_input
    input->code = hv::hypercall_install_breakpoint_hook;
    input->key = hv::hypercall_key;
    input->args[0] = cr3;
    input->args[1] = origin_va;
    input->args[2] = fake_va;
    input->args[3] = is_cr3_monitor_hook;
    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }
    Util::PoolManagerFreePool(input);

}

static void vmcall_remove_bp_hook(uint64_t cr3, uint64_t origin_va)
{



    // 获取hypercall_input
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    // 填充hypercall_input
    input->code = hv::hypercall_remove_breakpoint_hook;
    input->key = hv::hypercall_key;
    input->args[0] = cr3;
    input->args[1] = origin_va;


    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }
    Util::PoolManagerFreePool(input);

}

static void start_get_game_cr3_by_pid(uint64_t pid)
{

    // 获取hypercall_input
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    // 填充hypercall_input
    input->code = hv::hypercall_start_get_game_cr3_by_pid;
    input->key = hv::hypercall_key;
    input->args[0] = pid;


    //执行vmcall
    hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);

}

static void set_real_cr3(UINT64 realCr3)
{
    // 获取hypercall_input
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    // 填充hypercall_input
    input->code = hv::hypercall_add_real_cr3;
    input->key = hv::hypercall_key;
    input->args[0] = realCr3;


    //执行vmcall
    hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);

}

static void get_game_module_info(WCHAR* module_name, ULONG64* module_base, ULONG64* module_size)
{

    // 获取hypercall_input
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    // 填充hypercall_input
    input->code = hv::hypercall_get_game_module_base;
    input->key = hv::hypercall_key;
    input->args[0] = (UINT64)module_name;
    input->args[1] = (UINT64)module_base;
    input->args[2] = (UINT64)module_size;

    hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);

}


static bool hide_cache_info() {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_hide_cache_info;
    input->key = hv::hypercall_key;




    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }
    bool result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;
}


static bool hide_vt() {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_hide_hv;
    input->key = hv::hypercall_key;
    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }
    bool result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;
}

static bool unhide_vt() {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_unhide_hv;
    input->key = hv::hypercall_key;

    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }
    bool result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;

}


static bool unhide_cache_info() {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_unhide_cache_info;
    input->key = hv::hypercall_key;

    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++)
    {
        auto const orig_affinity = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        //执行vmcall
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserAffinityThreadEx)(orig_affinity);
    }
    bool result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;

}

static bool vmcall_save_image_base(uint64_t image_base) {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_save_gamevt_image_base;
    input->key = hv::hypercall_key;

    input->args[0] = image_base;

    bool result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;
}

static bool vmcall_get_image_base(uint64_t* image_base) {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_get_gamevt_image_base;
    input->key = hv::hypercall_key;

    input->args[0] = (uint64_t)image_base;

    bool result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;
}


static size_t read_virt_mem(ULONG64  cr3, void* dst,
    void* src, size_t  size) {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_read_virt_mem;
    input->key = hv::hypercall_key;
    input->args[0] = cr3;
    input->args[1] = reinterpret_cast<ULONG64>(dst);
    input->args[2] = reinterpret_cast<ULONG64>(src);
    input->args[3] = size;
    size_t result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;
}

static void write_virt_memory(ULONG64  cr3, ULONG64  dst, ULONG64  src,
    size_t  size)
{
    // 将虚拟地址转换成物理地址

    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_write_virt_mem;
    input->key = hv::hypercall_key;
    input->args[0] = cr3;
    input->args[1] = dst;
    input->args[2] = src;
    input->args[3] = size;
    hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);

}


static size_t read_game_virt_mem(ULONG64  cr3, void* dst,
    void* src, size_t  size) {
    hv::hypercall_input* input = (hv::hypercall_input*)Util::PoolManagertAllocation(sizeof(hv::hypercall_input), 'hyca');
    input->code = hv::hypercall_read_game_mem;
    input->key = hv::hypercall_key;
    input->args[0] = cr3;
    input->args[1] = reinterpret_cast<ULONG64>(dst);
    input->args[2] = reinterpret_cast<ULONG64>(src);
    input->args[3] = size;
    size_t result = hv::vmx_vmcall(input);
    Util::PoolManagerFreePool(input);
    return result;
}



// ---------------------------------------------------------------------------
// Host-managed EPT hook (vt/ept-hook.cpp). All driver-side state lives in
// host inline tables; these wrappers are the only driver-layer interface.
//
// Per-CPU operations (install/remove/enable/disable/remove_all_by_process)
// dispatch via per-CPU affinity loop, matching the existing
// vmcall_instal_ept_hook pattern. Single-VMCALL operations (write/get_va)
// just fire once on the current CPU.
//
// hypercall_input is stack-allocated to avoid any pool tag.
// ---------------------------------------------------------------------------

namespace eh_wrap {

inline void _broadcast_one_arg(hv::hypercall_code code, uint64_t a0, uint64_t a1, uint64_t a2 = 0, uint64_t a3 = 0) {
    hv::hypercall_input input = {};
    input.code = code;
    input.key  = hv::hypercall_key;
    input.args[0] = a0;
    input.args[1] = a1;
    input.args[2] = a2;
    input.args[3] = a3;
    for (size_t i = 0; i < KLI_FN(KeQueryActiveProcessorCount)(0); i++) {
        auto const orig = KLI_FN(KeSetSystemAffinityThreadEx)(1ull << i);
        hv::vmx_vmcall(input);
        KLI_FN(KeRevertToUserAffinityThreadEx)(orig);
    }
}

inline uint64_t _single_call(hv::hypercall_code code, uint64_t a0, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0) {
    hv::hypercall_input input = {};
    input.code = code;
    input.key  = hv::hypercall_key;
    input.args[0] = a0;
    input.args[1] = a1;
    input.args[2] = a2;
    input.args[3] = a3;
    return hv::vmx_vmcall(input);
}

}  // namespace eh_wrap

static inline void vmcall_eh_install(PEPROCESS process, uint64_t va, uint32_t flags) {
    eh_wrap::_broadcast_one_arg(hv::hypercall_eh_install,
        reinterpret_cast<uint64_t>(process), va, flags);
}

static inline void vmcall_eh_remove(PEPROCESS process, uint64_t va) {
    eh_wrap::_broadcast_one_arg(hv::hypercall_eh_remove,
        reinterpret_cast<uint64_t>(process), va);
}

static inline void vmcall_eh_enable(PEPROCESS process, uint64_t va) {
    eh_wrap::_broadcast_one_arg(hv::hypercall_eh_enable,
        reinterpret_cast<uint64_t>(process), va);
}

static inline void vmcall_eh_disable(PEPROCESS process, uint64_t va) {
    eh_wrap::_broadcast_one_arg(hv::hypercall_eh_disable,
        reinterpret_cast<uint64_t>(process), va);
}

static inline void vmcall_eh_remove_all_by_process(PEPROCESS process) {
    eh_wrap::_broadcast_one_arg(hv::hypercall_eh_remove_all_by_process,
        reinterpret_cast<uint64_t>(process), 0);
}

static inline void vmcall_eh_write(PEPROCESS process, uint64_t dst_va, uint64_t src_va, uint64_t size) {
    eh_wrap::_single_call(hv::hypercall_eh_write,
        reinterpret_cast<uint64_t>(process), dst_va, src_va, size);
}

static inline uint64_t vmcall_eh_get_va(PEPROCESS process, uint64_t va) {
    return eh_wrap::_single_call(hv::hypercall_eh_get_va,
        reinterpret_cast<uint64_t>(process), va);
}


// ---------------------------------------------------------------------------
// Host-managed VTCall hook (vt/vtcall-hook.cpp).
// ---------------------------------------------------------------------------

namespace vh_wrap {

inline void _broadcast(hv::hypercall_code code, uint64_t a0, uint64_t a1, uint64_t a2 = 0, uint64_t a3 = 0) {
    // CRITICAL: previously we used KeSetSystemAffinityThreadEx + spin to migrate
    // the calling thread to each vCPU and issue vmcall. But this fails when the
    // caller is inside KeStackAttachProcess (APC disabled) — the scheduler
    // can't reschedule us so every iteration runs on the same CPU, leaving
    // other vCPUs without their EPT hook entry. Use KeIpiGenericCall instead:
    // it forces every CPU (including this one) to synchronously execute the
    // callback at IPI_LEVEL, guaranteeing each vCPU's vmcall runs on its own
    // physical CPU regardless of APC / dispatcher state.
    struct ipi_ctx_t {
        hv::hypercall_input input;
    };
    static ipi_ctx_t ipi_ctx;
    ipi_ctx.input = {};
    ipi_ctx.input.code = code;
    ipi_ctx.input.key  = hv::hypercall_key;
    ipi_ctx.input.args[0] = a0;
    ipi_ctx.input.args[1] = a1;
    ipi_ctx.input.args[2] = a2;
    ipi_ctx.input.args[3] = a3;

    auto callback = [](ULONG_PTR ctx) -> ULONG_PTR {
        auto c = reinterpret_cast<ipi_ctx_t*>(ctx);
        hv::vmx_vmcall(c->input);
        return 0;
    };

    KLI_FN(KeIpiGenericCall)(callback, reinterpret_cast<ULONG_PTR>(&ipi_ctx));
}

inline uint64_t _single(hv::hypercall_code code, uint64_t a0, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0) {
    hv::hypercall_input input = {};
    input.code = code;
    input.key  = hv::hypercall_key;
    input.args[0] = a0;
    input.args[1] = a1;
    input.args[2] = a2;
    input.args[3] = a3;
    return hv::vmx_vmcall(input);
}

}  // namespace vh_wrap

static inline void vmcall_vh_install(PEPROCESS process, uint64_t target_va, uint64_t blank_mem,
                                      uint8_t type, uint8_t dispatch_mode,
                                      bool filter_by_process, bool auto_enable) {
    uint64_t packed = (auto_enable ? 0x1ULL : 0)
                    | (filter_by_process ? 0x2ULL : 0)
                    | (static_cast<uint64_t>(type) << 8)
                    | (static_cast<uint64_t>(dispatch_mode) << 16);
    // Affinity-loop install: explicitly migrate driver thread to each CPU and
    // issue a single vmcall per CPU. Each vCPU installs its own EPT via
    // install_host_impl(from_ipi=true). KeIpiGenericCall removed — the host
    // never observed 16 distinct vCPU entries reliably in 5s with IPI.
    //
    // CAVEAT: this requires APCs enabled. Callers inside KeStackAttachProcess
    // must detach before invoking this wrapper.
    ULONG cpu_count = KLI_FN(KeQueryActiveProcessorCountEx)(ALL_PROCESSOR_GROUPS);
    if (cpu_count == 0) cpu_count = 1;
    for (ULONG i = 0; i < cpu_count; i++) {
        GROUP_AFFINITY ga = {};
        PROCESSOR_NUMBER pn = {};
        KLI_FN(KeGetProcessorNumberFromIndex)(i, &pn);
        ga.Group = pn.Group;
        ga.Mask  = 1ULL << pn.Number;
        GROUP_AFFINITY prev_ga = {};
        KLI_FN(KeSetSystemGroupAffinityThread)(&ga, &prev_ga);

        hv::hypercall_input input = {};
        input.code    = hv::hypercall_vh_install;
        input.key     = hv::hypercall_key;
        input.args[0] = reinterpret_cast<uint64_t>(process);
        input.args[1] = target_va;
        input.args[2] = blank_mem;
        input.args[3] = packed;
        hv::vmx_vmcall(input);

        KLI_FN(KeRevertToUserGroupAffinityThread)(&prev_ga);
    }
}

static inline void vmcall_vh_enable(uint64_t target_va) {
    vh_wrap::_broadcast(hv::hypercall_vh_enable, 0, target_va);
}

static inline void vmcall_vh_disable(uint64_t target_va) {
    vh_wrap::_broadcast(hv::hypercall_vh_disable, 0, target_va);
}

static inline void vmcall_vh_remove(PEPROCESS process, uint64_t target_va) {
    vh_wrap::_broadcast(hv::hypercall_vh_remove,
        reinterpret_cast<uint64_t>(process), target_va);
}

static inline void vmcall_vh_uninit() {
    vh_wrap::_broadcast(hv::hypercall_vh_uninit, 0, 0);
}

static inline uint64_t vmcall_vh_find_blank(PEPROCESS process, uint64_t start_va, uint64_t max_scan) {
    return vh_wrap::_single(hv::hypercall_vh_find_blank,
        reinterpret_cast<uint64_t>(process), start_va, max_scan);
}

// Returns the page-aligned VA of a fully-0xCC 4KB page in [start, start+max_scan),
// or 0 if none. Used to allocate the trampoline pool's exec page slot.
static inline uint64_t vmcall_vh_find_blank_page(PEPROCESS process, uint64_t start_va, uint64_t max_scan) {
    return vh_wrap::_single(hv::hypercall_vh_find_blank_page,
        reinterpret_cast<uint64_t>(process), start_va, max_scan);
}

// Trampoline pool bootstrap (multi-page, multi-slot). Driver scans
// ntdll/ntoskrnl .text for 0xCC runs and registers each page + slot via
// these three vmcalls. Tear-down is implicit (pool stays for driver lifetime).
//
// Returns the page_index (>=0) or -1 on failure.
static inline int64_t vmcall_vh_tramp_add_page(uint64_t orig_pfn, uint64_t exec_pfn,
                                                uint64_t page_va, uint64_t exec_hva,
                                                bool is_kernel) {
    hv::hypercall_input input = {};
    input.code    = hv::hypercall_vh_tramp_add_page;
    input.key     = hv::hypercall_key;
    input.args[0] = orig_pfn;
    input.args[1] = exec_pfn;
    input.args[2] = page_va;
    input.args[3] = exec_hva;
    input.args[4] = is_kernel ? 1ULL : 0ULL;
    return static_cast<int64_t>(hv::vmx_vmcall(input));
}

static inline bool vmcall_vh_tramp_add_slot(uint32_t page_index, uint32_t page_offset,
                                             uint32_t capacity, bool is_kernel) {
    hv::hypercall_input input = {};
    input.code    = hv::hypercall_vh_tramp_add_slot;
    input.key     = hv::hypercall_key;
    input.args[0] = page_index;
    input.args[1] = page_offset;
    input.args[2] = capacity;
    input.args[3] = is_kernel ? 1ULL : 0ULL;
    return hv::vmx_vmcall(input) != 0;
}

static inline void vmcall_vh_tramp_set_ready(bool is_kernel) {
    // Single-vCPU vmcall: EPT was already installed by add_page (cross-vCPU
    // write on all N ept trees) so set_ready just flips the ready flag.
    hv::hypercall_input input = {};
    input.code    = hv::hypercall_vh_tramp_set_ready;
    input.key     = hv::hypercall_key;
    input.args[0] = is_kernel ? 1ULL : 0ULL;
    hv::vmx_vmcall(input);
}

// Master switch for KTHREAD.Affinity rewrite in hv::CallUser (game.h). 1=on (default), 0=off.
static inline void vmcall_set_affinity_lock(bool enable) {
    vh_wrap::_single(hv::hypercall_set_affinity_lock, enable ? 1ULL : 0ULL);
}


#pragma code_seg()
#pragma code_seg(".vm2")

static void vmcall_test(UINT64* count_ptr)
{
    hv::hypercall_input input = { 0 };
    input.code = hv::hypercall_test;
    input.key = hv::hypercall_key;
    input.args[0] = (UINT64)count_ptr;
    hv::vmx_vmcall(input);
}
#pragma code_seg()

} 

