#pragma once
#include "fltKernel.h"

namespace hv {

inline constexpr uint64_t hypercall_key = 0x88554466885;
inline constexpr uint64_t hypervisor_signature = 'sb?d';

enum hypercall_code : uint64_t {
    hypercall_ping = 0,
    hypercall_test,
    hypercall_unload,
    hypercall_read_phys_mem,
    hypercall_write_phys_mem,
    hypercall_read_virt_mem,
    hypercall_write_virt_mem,
    hypercall_query_process_cr3,
    hypercall_install_ept_hook,
    hypercall_remove_ept_hook,
    hypercall_flush_logs,
    hypercall_get_physical_address,
    hypercall_hide_physical_page,
    hypercall_unhide_physical_page,
    hypercall_get_hv_base,
    hypercall_install_mmr,
    hypercall_remove_mmr,
    hypercall_remove_all_mmrs,
    hypercall_install_breakpoint_hook,
    hypercall_remove_breakpoint_hook,
    hypercall_add_protect_process,
    hypercall_remove_protect_process,
    hypercall_add_mmr_point,
    hypercall_delete_mmr_point,
    hypercall_add_cr3_monitor,
    hypercall_remove_cr3_monitor,
    hypercall_open_cr3_monitor_check_thread,
    hypercall_close_cr3_monitor_check_thread,
    hypercall_open_cr3_monitor_check_rip,
    hypercall_close_cr3_monitor_check_rip,
    hypercall_end_cr3_monitor_hook,
    hypercall_add_cr3_monitor_thread,
    hypercall_remove_cr3_monitor_thread,
    hypercall_active_cr3_monitor_data_region,
    hypercall_add_cr3_map,
    hypercall_add_cr3_map_by_user_mode,
    hypercall_remove_cr3_map,
    hypercall_get_info,
    hypercall_start_get_game_cr3,
    hypercall_start_get_game_cr3_by_pid,
    hypercall_get_game_path,
    hypercall_get_game_module_base,
    hypercall_hide_hv,
    hypercall_unhide_hv,
    hypercall_add_real_cr3,
    hypercall_read_game_mem,
    hypercall_write_game_mem,
    hypercall_hide_cache_info,
    hypercall_unhide_cache_info,
    hypercall_get_gamevt_image_base,
    hypercall_save_gamevt_image_base,
    hypercall_call_function,
    hypercall_add_vmcall_hook,
    hypercall_enable_vmcall_hook,
    hypercall_disable_vmcall_hook,
    hypercall_remove_vmcall_hook,
    hypercall_eh_install,
    hypercall_eh_remove,
    hypercall_eh_enable,
    hypercall_eh_disable,
    hypercall_eh_write,
    hypercall_eh_get_va,
    hypercall_eh_remove_all_by_process,
    hypercall_vh_install,
    hypercall_vh_install_ret_abs,
    hypercall_vh_enable,
    hypercall_vh_disable,
    hypercall_vh_remove,
    hypercall_vh_uninit,
    hypercall_vh_find_blank,
    hypercall_vh_find_blank_page,
    hypercall_vh_init_tramp_pool,
    hypercall_vh_tramp_add_page,
    hypercall_vh_tramp_add_slot,
    hypercall_vh_tramp_set_ready,
    hypercall_prepare_self_hide_add,
    hypercall_prepare_self_hide_commit,
    hypercall_set_affinity_lock,
    hypercall_get_pool_blocks,
    hypercall_get_hide_diag,
    hypercall_hide_pfn_list,
    hypercall_ept_probe_install,
    hypercall_ept_probe_remove,
    hypercall_ept_probe_get_hits,
    hypercall_ept_probe_clear_hits,
    hypercall_get_resident_hv_diag,
    hypercall_set_host_rsp,
    hypercall_map_host_range,
    hypercall_set_host_rip,
    hypercall_set_keep_hv_on_unload,
    hypercall_dbg_dispatch,
    hypercall_get_payload_status,
    hypercall_set_payload_mode,
    hypercall_payload_ping,
    hypercall_verify_hide_pfn_list,
    hypercall_unhide_pfn_list,
    hypercall_set_machenike_status,
    hypercall_get_machenike_status,
};

static_assert(hypercall_vh_find_blank_page == 70, "hypercall ABI drift");
static_assert(hypercall_prepare_self_hide_add == 75, "hypercall ABI drift");
static_assert(hypercall_get_hide_diag == 79, "hypercall ABI drift");
static_assert(hypercall_hide_pfn_list == 80, "hypercall ABI drift");
static_assert(hypercall_get_resident_hv_diag == 85, "hypercall ABI drift");
static_assert(hypercall_set_host_rsp == 86, "hypercall ABI drift");
static_assert(hypercall_map_host_range == 87, "hypercall ABI drift");
static_assert(hypercall_set_host_rip == 88, "hypercall ABI drift");
static_assert(hypercall_set_keep_hv_on_unload == 89, "hypercall ABI drift");
static_assert(hypercall_dbg_dispatch == 90, "hypercall ABI drift");
static_assert(hypercall_get_payload_status == 91, "hypercall ABI drift");
static_assert(hypercall_set_payload_mode == 92, "hypercall ABI drift");
static_assert(hypercall_payload_ping == 93, "hypercall ABI drift");
static_assert(hypercall_verify_hide_pfn_list == 94, "hypercall ABI drift");
static_assert(hypercall_unhide_pfn_list == 95, "hypercall ABI drift");
static_assert(hypercall_set_machenike_status == 96, "hypercall ABI drift");
static_assert(hypercall_get_machenike_status == 97, "hypercall ABI drift");

enum payload_mode_kind : uint64_t {
    payload_mode_vtret = 1,
    payload_mode_tramp = 2,
    payload_mode_hook = 3,
    payload_mode_ept = 4,
    payload_mode_cutover = 5,
    payload_mode_legacy_detach = 6,
    payload_mode_host_idt = 7,
    payload_mode_hostex_test = 8,
};

struct hypercall_input {
    union {
        uint64_t flags;
        struct {
            hypercall_code code : 8;
            uint64_t key : 56;
        };
    };
    uint64_t args[6];
};

struct pool_block_record {
    uint64_t va;
    uint64_t bytes;
    uint32_t tag;
    uint32_t flags;
};

#pragma code_seg(".vm")

uint64_t vmx_vmcall(hypercall_input& input);
uint64_t vmx_vmcall_preserve_nonvol(hypercall_input& input);
static bool try_vmcall(hypercall_input& input, uint64_t* out_result = nullptr)
{
    if (out_result)
        *out_result = 0;

    __try
    {
        uint64_t const res = vmx_vmcall(input);
        if (out_result)
            *out_result = res;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static uint64_t ping()
{
    hypercall_input input = { 0 };
    input.code = hypercall_ping;
    input.key = hypercall_key;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_unload()
{
    hypercall_input input = { 0 };
    input.code = hypercall_unload;
    input.key = hypercall_key;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static bool vmcall_save_image_base(uint64_t image_base, uint64_t unload)
{
    hypercall_input input = { 0 };
    input.code = hypercall_save_gamevt_image_base;
    input.key = hypercall_key;
    input.args[0] = image_base;
    input.args[1] = unload;
    return vmx_vmcall(input) != 0;
}

static void vmcall_set_affinity_lock(bool enable)
{
    hypercall_input input = { 0 };
    input.code = hypercall_set_affinity_lock;
    input.key = hypercall_key;
    input.args[0] = enable ? 1ULL : 0ULL;
    vmx_vmcall(input);
}

static uint64_t vmcall_get_pool_blocks(pool_block_record* out, uint64_t max_count)
{
    hypercall_input input = { 0 };
    input.code = hypercall_get_pool_blocks;
    input.key = hypercall_key;
    input.args[0] = (uint64_t)out;
    input.args[1] = max_count;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_hide_pfn_list(uint64_t* pfns, uint64_t count)
{
    hypercall_input input = { 0 };
    input.code = hypercall_hide_pfn_list;
    input.key = hypercall_key;
    input.args[0] = (uint64_t)pfns;
    input.args[1] = count;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_verify_hide_pfn_list(void* req, uint64_t bytes)
{
    hypercall_input input = { 0 };
    input.code = hypercall_verify_hide_pfn_list;
    input.key = hypercall_key;
    input.args[0] = (uint64_t)req;
    input.args[1] = bytes;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_unhide_physical_page(uint64_t pfn)
{
    hypercall_input input = { 0 };
    input.code = hypercall_unhide_physical_page;
    input.key = hypercall_key;
    input.args[0] = pfn;
    return vmx_vmcall_preserve_nonvol(input);
}

static uint64_t vmcall_get_physical_address(uint64_t cr3, uint64_t va)
{
    hypercall_input input = { 0 };
    input.code = hypercall_get_physical_address;
    input.key = hypercall_key;
    input.args[0] = cr3;
    input.args[1] = va;
    return vmx_vmcall_preserve_nonvol(input);
}

static uint64_t vmcall_unhide_pfn_list(uint64_t* pfns, uint64_t count)
{
    hypercall_input input = { 0 };
    input.code = hypercall_unhide_pfn_list;
    input.key = hypercall_key;
    input.args[0] = (uint64_t)pfns;
    input.args[1] = count;
    return vmx_vmcall_preserve_nonvol(input);
}

static void vmcall_get_hide_diag(uint64_t* out6)
{
    hypercall_input input = { 0 };
    input.code = hypercall_get_hide_diag;
    input.key = hypercall_key;
    input.args[0] = (uint64_t)out6;
    vmx_vmcall(input);
}

static uint64_t vmcall_get_resident_hv_diag(void* out, uint64_t bytes)
{
    hypercall_input input = { 0 };
    input.code = hypercall_get_resident_hv_diag;
    input.key = hypercall_key;
    input.args[0] = (uint64_t)out;
    input.args[1] = bytes;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_get_payload_status(void* out, uint64_t bytes)
{
    hypercall_input input = { 0 };
    input.code = hypercall_get_payload_status;
    input.key = hypercall_key;
    input.args[0] = (uint64_t)out;
    input.args[1] = bytes;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_set_payload_mode(uint64_t kind, uint64_t mode)
{
    hypercall_input input = { 0 };
    input.code = hypercall_set_payload_mode;
    input.key = hypercall_key;
    input.args[0] = kind;
    input.args[1] = mode;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_payload_ping(uint64_t nonce)
{
    hypercall_input input = { 0 };
    input.code = hypercall_payload_ping;
    input.key = hypercall_key;
    input.args[0] = nonce;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_set_host_rsp(uint64_t new_rsp)
{
    hypercall_input input = { 0 };
    input.code = hypercall_set_host_rsp;
    input.key = hypercall_key;
    input.args[0] = new_rsp;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static bool vmcall_map_host_range(uint64_t va, uint64_t bytes)
{
    hypercall_input input = { 0 };
    input.code = hypercall_map_host_range;
    input.key = hypercall_key;
    input.args[0] = va;
    input.args[1] = bytes;
    return vmx_vmcall(input) != 0;
}

static uint64_t vmcall_set_host_rip(uint64_t new_rip)
{
    hypercall_input input = { 0 };
    input.code = hypercall_set_host_rip;
    input.key = hypercall_key;
    input.args[0] = new_rip;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_set_keep_hv_on_unload(bool enable)
{
    hypercall_input input = { 0 };
    input.code = hypercall_set_keep_hv_on_unload;
    input.key = hypercall_key;
    input.args[0] = enable ? 1ULL : 0ULL;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}


static bool try_ping()
{
    hypercall_input input = { 0 };
    input.code = hypercall_ping;
    input.key = hypercall_key;
    uint64_t sig = 0;
    return try_vmcall(input, &sig) && (sig == hypervisor_signature);
}

static bool try_vmcall_set_machenike_status(uint64_t base, uint64_t size, uint64_t flags, uint64_t unload)
{
    hypercall_input input = { 0 };
    input.code = hypercall_set_machenike_status;
    input.key = hypercall_key;
    input.args[0] = base;
    input.args[1] = size;
    input.args[2] = flags;
    input.args[3] = unload;
    uint64_t res = 0;
    return try_vmcall(input, &res) && (res != 0);
}

static uint64_t vmcall_set_machenike_status(uint64_t base, uint64_t size, uint64_t flags, uint64_t unload)
{
    hypercall_input input = { 0 };
    input.code = hypercall_set_machenike_status;
    input.key = hypercall_key;
    input.args[0] = base;
    input.args[1] = size;
    input.args[2] = flags;
    input.args[3] = unload;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

static uint64_t vmcall_get_machenike_status(void* out_buf = nullptr, uint64_t size = 0)
{
    hypercall_input input = { 0 };
    input.code = hypercall_get_machenike_status;
    input.key = hypercall_key;
    input.args[0] = (uint64_t)out_buf;
    input.args[1] = size;
    uint64_t res = 0;
    return try_vmcall(input, &res) ? res : 0ULL;
}

#pragma code_seg()

}
