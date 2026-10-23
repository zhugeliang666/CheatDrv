#include <ntifs.h>
#include <intrin.h>
#include <stddef.h>
#if __has_include("..\..\VtBootstrapDriver\common\payload_abi.h")
#include "..\..\VtBootstrapDriver\common\payload_abi.h"
#include "..\..\VtBootstrapDriver\common\mapctl_ioctl.h"
#else
#include "..\..\VtBootstrapDriver\common\payload_abi.h"
#include "..\..\VtBootstrapDriver\common\mapctl_ioctl.h"
#endif

// 实机内存策略：载荷自有分配统一使用 MmAllocateIndependentPages，
// 避免把 Host Pool 的生命周期混入常驻载荷所有权。
#ifndef PAYLOAD_FORCE_HOST_POOL_ALLOC
#define PAYLOAD_FORCE_HOST_POOL_ALLOC 0
#endif

// 内存过滤属于正式业务能力：基础处理器负责类型 18～21，扩展处理器负责
// 类型 27～29。安装策略、EPT 刷新策略和 vCPU 范围在这里集中声明。
#ifndef PAYLOAD_MM4_INSTALL_AUTO_ENABLE
#define PAYLOAD_MM4_INSTALL_AUTO_ENABLE 1
#endif
#ifndef PAYLOAD_MM4_INSTALL_EPT_POLICY
#define PAYLOAD_MM4_INSTALL_EPT_POLICY PAYLOAD_NATIVE_EPT_POLICY_IMMEDIATE_ALL
#endif
#ifndef PAYLOAD_MM4_INSTALL_EXTRA_VCPU_INDEX
#define PAYLOAD_MM4_INSTALL_EXTRA_VCPU_INDEX 0
#endif
#ifndef PAYLOAD_MMCM_SKIP_PROTECTED_NO_TOUCH
#define PAYLOAD_MMCM_SKIP_PROTECTED_NO_TOUCH 0
#endif
#ifndef PAYLOAD_MMISAV_FORCE_LOCAL_RETURN
#define PAYLOAD_MMISAV_FORCE_LOCAL_RETURN 0
#endif
#ifndef PAYLOAD_MMISAV_FORCE_LOCAL_RESULT
#define PAYLOAD_MMISAV_FORCE_LOCAL_RESULT 0
#endif
#ifndef PAYLOAD_MM4_DIRECT_RIP_CLAIM
#define PAYLOAD_MM4_DIRECT_RIP_CLAIM 1
#endif
#ifndef PAYLOAD_DIRECT_SLOT_CLAIM_ALL
#define PAYLOAD_DIRECT_SLOT_CLAIM_ALL 1
#endif

// 强制保留 VMX/Root-mode 汇编入口，防止链接器裁剪常驻桥接代码。
// 这些符号是载荷 ABI 的组成部分，不能依赖偶然引用来维持布局。
#pragma comment(linker, "/include:PayloadVmExitBridge")
#pragma comment(linker, "/include:PayloadVmxVmcall")

#ifndef PAYLOAD_WORKER_AUTOSTART
#define PAYLOAD_WORKER_AUTOSTART 0
#endif

#ifndef PAYLOAD_RESIDENT_CTL_ENABLED
#define PAYLOAD_RESIDENT_CTL_ENABLED 0
#endif

// Root-mode 不可恢复故障统一进入可诊断的 BugCheck 路径，避免静默三重故障。
#ifndef PAYLOAD_VT_FATAL_BUGCHECK_ENABLED
#define PAYLOAD_VT_FATAL_BUGCHECK_ENABLED 1
#endif

// Hard-hang breaker: if all CPUs are trapped in a VMX-root livelock there is
// no Windows watchdog/worker context left to produce a dump.  Count consecutive
// identical VMEXIT signatures per vCPU; once the threshold is reached, schedule
// the already-validated guest KeBugCheckEx handoff from the VMEXIT path.
#ifndef PAYLOAD_VTPANIC_STORM_BREAKER_ENABLED
#define PAYLOAD_VTPANIC_STORM_BREAKER_ENABLED 1
#endif

#ifndef PAYLOAD_VTPANIC_STORM_BREAKER_THRESHOLD
#define PAYLOAD_VTPANIC_STORM_BREAKER_THRESHOLD 100000ull
#endif

#ifndef PAYLOAD_VTPANIC_VISIBLE_BUGCHECK_CODE_ENABLED
#define PAYLOAD_VTPANIC_VISIBLE_BUGCHECK_CODE_ENABLED 1
#endif

#ifndef PAYLOAD_DEFERRED_EPT_USE_LEGACY_PENDING
#define PAYLOAD_DEFERRED_EPT_USE_LEGACY_PENDING 1
#endif

#ifndef PAYLOAD_BRIDGE_SELF_MAP_ENABLED
#define PAYLOAD_BRIDGE_SELF_MAP_ENABLED 1
#endif

// 固化后的业务模式：常驻桥接器接管 VMEXIT 分发，旧映像不再作为流程回退点；
// PMO、EPT、Hook 和调试事件分别由下方业务能力宏决定。

#ifndef PAYLOAD_PMO_FORCE_AFFINITY_LOCK
#define PAYLOAD_PMO_FORCE_AFFINITY_LOCK 1
#endif

// DWM 兼容策略：载荷负责 dbg_dispatch 和 dbg-watch EPT 所有权；
// 普通 INT3 默认只观察，严格匹配的返回断点与跳板断点由载荷处理。
#ifndef PAYLOAD_DWM_SAFE_BRIDGE_ENABLED
#define PAYLOAD_DWM_SAFE_BRIDGE_ENABLED 1
#endif

#define PAYLOAD_MOV_CR_HANDLER_ENABLED 1
#undef PAYLOAD_DEFAULT_HOOK_MODE
#define PAYLOAD_DEFAULT_HOOK_MODE PAYLOAD_HOOK_MODE_OBSERVE
#define PAYLOAD_STABLE_GETBUFFER_ONLY 1
#define PAYLOAD_ENABLE_NATIVE_GETBUFFER_INSTALL 1
#define PAYLOAD_ENABLE_NATIVE_SWAPCHAIN_EXTRA_INSTALL 0
#define PAYLOAD_ENABLE_NATIVE_COPY_DUP_INSTALL 0
#define PAYLOAD_ENABLE_NATIVE_NT_MEMORY_INSTALL 0
#define PAYLOAD_ENABLE_NATIVE_MM_FILTER_INSTALL 0
// PMO 绘制和 GetBuffer 安装属于常驻载荷业务入口；未受保护的访问保持透传。
#define PAYLOAD_ENABLE_PMO_RENDER_INIT_CALLOUT 1
#define PAYLOAD_ENABLE_PMO_DRAW_CALLOUT 1

#ifndef PAYLOAD_DEFAULT_EXBP_MODE
#if PAYLOAD_DWM_SAFE_BRIDGE_ENABLED
#define PAYLOAD_DEFAULT_EXBP_MODE PAYLOAD_EXBP_MODE_OBSERVE
#else
#define PAYLOAD_DEFAULT_EXBP_MODE PAYLOAD_EXBP_MODE_REINJECT
#endif
#endif

#ifndef PAYLOAD_DEFAULT_VTRET_MODE
#define PAYLOAD_DEFAULT_VTRET_MODE PAYLOAD_VTRET_MODE_HANDLE_STRICT
#endif

#ifndef PAYLOAD_DEFAULT_TRAMP_MODE
#define PAYLOAD_DEFAULT_TRAMP_MODE PAYLOAD_TRAMP_MODE_HANDLE
#endif

#ifndef PAYLOAD_DEFAULT_HOOK_MODE
#define PAYLOAD_DEFAULT_HOOK_MODE PAYLOAD_HOOK_MODE_PASSTHROUGH
#endif

#ifndef PAYLOAD_DEFAULT_EPT_MODE
#define PAYLOAD_DEFAULT_EPT_MODE PAYLOAD_EPT_MODE_HANDLE_TRAMP
#endif

static PDRIVER_OBJECT g_driver_object = nullptr;
static volatile LONG64 g_started = 0;
static volatile LONG64 g_start_count = 0;
static volatile LONG64 g_stop_count = 0;
static volatile LONG64 g_ping_count = 0;
static volatile payload_u64 g_last_nonce = 0;
static volatile payload_u64 g_last_pong = 0;
static volatile payload_u64 g_last_result = PAYLOAD_RESULT_OK;
static volatile payload_u64 g_image_base = 0;
static volatile payload_u64 g_image_size = 0;
static volatile payload_u64 g_boot_flags = 0;
static volatile payload_u64 g_host_api = 0;
static volatile payload_u64 g_host_api_magic = 0;
static volatile payload_u64 g_host_api_flags = 0;
static volatile payload_u64 g_host_alloc_fn = 0;
static volatile payload_u64 g_host_free_fn = 0;
static volatile payload_u64 g_system_cr3 = 0;
static volatile payload_u64 g_arena_base = 0;
static volatile payload_u64 g_arena_size = 0;
static volatile payload_u64 g_arena_used = 0;
static volatile payload_u64 g_arena_flags = 0;
static volatile payload_u64 g_kernel_api_flags = 0;
static volatile payload_u64 g_external_ref_flags = PAYLOAD_EXTERNAL_REF_NONE;
static volatile payload_u64 g_independent = 0;
static volatile payload_u64 g_runtime_block = 0;
static volatile payload_u64 g_mm_allocate_independent_pages = 0;
static volatile payload_u64 g_mm_free_independent_pages = 0;
static volatile payload_u64 g_mm_set_page_protection = 0;
static volatile payload_u64 g_ps_create_system_thread = 0;
static volatile payload_u64 g_ps_terminate_system_thread = 0;
static volatile payload_u64 g_zw_wait_for_single_object = 0;
static volatile payload_u64 g_zw_close = 0;
static volatile payload_u64 g_ke_delay_execution_thread = 0;
static volatile payload_u64 g_ke_set_system_affinity_thread_ex = 0;
static volatile payload_u64 g_ke_revert_to_user_affinity_thread_ex = 0;
static volatile payload_u64 g_ke_bug_check_ex = 0;
static volatile payload_u64 g_io_create_driver = 0;
static volatile payload_u64 g_io_create_device = 0;
static volatile payload_u64 g_io_create_symbolic_link = 0;
static volatile payload_u64 g_io_delete_symbolic_link = 0;
static volatile payload_u64 g_io_delete_device = 0;
static volatile payload_u64 g_io_complete_request = 0;
static volatile payload_u64 g_dbg_print_ex = 0;
typedef ULONG (__cdecl *payload_dbg_print_ex_fn)(ULONG ComponentId, ULONG Level, PCSTR Format, ...);
#define PAYLOAD_LOG(fmt, ...) \
    do { \
        auto _fn = (payload_dbg_print_ex_fn)g_dbg_print_ex; \
        if (_fn) _fn(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ##__VA_ARGS__); \
    } while (0)
static volatile payload_u64 g_direct_alloc_base = 0;
static volatile payload_u64 g_direct_alloc_size = 0;
static volatile payload_u64 g_owned_alloc_count = 0;
static volatile payload_u64 g_owned_alloc_bytes = 0;
static volatile payload_u64 g_host_state_base = 0;
static volatile payload_u64 g_host_state_size = 0;
static volatile payload_u64 g_host_state_flags = 0;
static volatile payload_u64 g_host_state_stage = 0;
static volatile payload_u64 g_host_state_hv_pings = 0;
static volatile payload_u64 g_host_state_last_hv = 0;
static volatile payload_u64 g_host_stack_base = 0;
static volatile payload_u64 g_host_stack_size = 0;
static volatile payload_u64 g_host_stack_slot_size = 0;
static volatile payload_u64 g_host_stack_slot_count = 0;
static volatile payload_u64 g_host_stack_desc_base = 0;
static volatile payload_u64 g_host_stack_desc_count = 0;
static volatile payload_u64 g_host_stack_first_rsp = 0;
static volatile payload_u64 g_host_stack_mapped_in_host = 0;
extern "C" payload_u64 g_payload_vmexit_target = 0;
extern "C" payload_u64 g_payload_vmexit_hits = 0;
extern "C" payload_u64 g_payload_vmexit_bridge_target = 0;
extern "C" payload_u64 g_payload_vmexit_bridge_hits = 0;
extern "C" payload_u64 g_payload_vmexit_old_handler_call_count = 0;
extern "C" volatile payload_u64 g_payload_vmexit_old_handler_active_count = 0;
static volatile payload_u64 g_payload_vmexit_bridge_saved_target = 0;
static volatile payload_u64 g_payload_vmexit_bridge_observe_count = 0;
static volatile payload_u64 g_payload_vmexit_bridge_last_reason = 0;
static volatile payload_u64 g_payload_vmexit_bridge_vmread_fail = 0;
static volatile payload_u64 g_payload_vmexit_bridge_self_count = 0;
static volatile payload_u64 g_payload_vmexit_bridge_self_last_code = 0;
static volatile payload_u64 g_payload_vmexit_bridge_self_last_result = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_count = 0;
static volatile payload_u64 g_payload_vmexit_pending_restore_count = 0;
static volatile payload_u64 g_payload_vmexit_pending_release_count = 0;
static volatile payload_u64 g_payload_vmexit_pending_release_wait_count = 0;
static volatile payload_u64 g_payload_vmexit_pending_fail_count = 0;
static volatile payload_u64 g_payload_vmexit_pending_node_nonzero_count = 0;
static volatile payload_u64 g_payload_vmexit_pending_last_vcpu = 0;
static volatile payload_u64 g_payload_vmexit_pending_last_state = 0;
static volatile payload_u64 g_payload_vmexit_pending_last_rsp = 0;
static volatile payload_u64 g_payload_vmexit_trace_scrub_count = 0;
static volatile payload_u64 g_payload_vmexit_trace_scrub_fail_count = 0;
static volatile payload_u64 g_payload_vmexit_trace_scrub_last_mask = 0;
static payload_u64 g_trace_unload_mm_unloaded_drivers = 0;
static payload_u64 g_trace_unload_mm_last_unloaded_driver = 0;
static payload_u64 g_trace_unload_name_bytes = 0;
static payload_u64 g_trace_unload_delay_exits = 0;
static payload_u64 g_trace_unload_interval_exits = 0;
static payload_u64 g_trace_unload_max_attempts = 0;
static unsigned short g_trace_unload_name[32] = {};
static volatile payload_u64 g_trace_unload_vmexit_seen = 0;
static volatile payload_u64 g_trace_unload_probe_count = 0;
static volatile payload_u64 g_trace_unload_clean_count = 0;
static volatile payload_u64 g_trace_unload_fail_count = 0;
static volatile payload_u64 g_trace_unload_last_result = 0;
static volatile payload_u64 g_trace_unload_last_index = 0;
static volatile payload_u64 g_trace_unload_last_count = 0;
static payload_u64 g_trace_hash_bucket_list = 0;
static payload_u64 g_trace_hash_cache_lock = 0;
static payload_u64 g_trace_hash_delay_exits = 0;
static payload_u64 g_trace_hash_interval_exits = 0;
static payload_u64 g_trace_hash_max_attempts = 0;
static volatile payload_u64 g_trace_hash_vmexit_seen = 0;
static volatile payload_u64 g_trace_hash_probe_count = 0;
static volatile payload_u64 g_trace_hash_clean_count = 0;
static volatile payload_u64 g_trace_hash_fail_count = 0;
static volatile payload_u64 g_trace_hash_last_result = 0;
static volatile payload_u64 g_trace_hash_last_index = 0;
static volatile payload_u64 g_trace_hash_last_count = 0;
static volatile payload_u64 g_trace_hash_last_entry = 0;
static volatile payload_u64 g_payload_vmexit_ctx_set_count = 0;
static volatile payload_u64 g_payload_vmexit_ctx_set_fail_count = 0;
static volatile payload_u64 g_payload_vmexit_ctx_set_last_vcpu = 0;
static volatile payload_u64 g_payload_vmexit_ctx_set_last_ptr = 0;
static volatile payload_u64 g_payload_vmexit_vcpu_reset_count = 0;
static volatile payload_u64 g_payload_vmexit_vcpu_reset_fail_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_invept_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_invept_fail_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_invept_last_bitmap = 0;
static volatile payload_u64 g_payload_vmexit_legacy_install_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_install_fail_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_install_retire_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_hide_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_hide_fail_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_hide_last_hidden = 0;
static volatile payload_u64 g_payload_vmexit_legacy_mtf_count = 0;
static volatile payload_u64 g_payload_vmexit_legacy_mtf_fail_count = 0;
static volatile payload_u64 g_payload_vmexit_ept_misconfig_count = 0;
static volatile payload_u64 g_payload_vmexit_ept_misconfig_last_gpa = 0;
static mapctl_hv_diag g_cached_hv_diag = {};
static volatile payload_u64 g_hv_diag_cache_ready = 0;
static volatile payload_u64 g_hv_diag_self_count = 0;
static volatile payload_u64 g_hv_diag_gva_fail = 0;
static volatile payload_u64 g_hv_diag_vcpu_stride = 0;
static volatile payload_u64 g_legacy_detach_result = PAYLOAD_RESULT_INVALID_CONTEXT;
static volatile payload_u64 g_legacy_detach_flags = 0;
static volatile payload_u64 g_legacy_detach_generation = 0;
static volatile payload_u64 g_legacy_ghv_original = 0;
static volatile payload_u64 g_legacy_ghv_copy = 0;
static volatile payload_u64 g_legacy_ghv_size = 0;
static volatile payload_u64 g_legacy_vt_hook_original = 0;
static volatile payload_u64 g_legacy_vt_hook_copy = 0;
static volatile payload_u64 g_legacy_vt_hook_size = 0;
static volatile payload_u64 g_legacy_shadow_base = 0;
static volatile payload_u64 g_legacy_shadow_size = 0;
static volatile payload_u64 g_legacy_shadow_count = 0;
static volatile payload_u64 g_resident_pool_manifest = 0;
static volatile payload_u64 g_resident_pool_capacity = 0;
static volatile payload_u64 g_resident_pool_count = 0;
static volatile payload_u64 g_resident_pool_bytes = 0;
static volatile payload_u64 g_resident_pool_independent_count = 0;
static volatile payload_u64 g_resident_pool_fallback_count = 0;
static volatile payload_u64 g_resident_pool_generation = 0;
static volatile payload_u64 g_resident_pool_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
static volatile payload_u64 g_legacy_gamevt_image_base_shadow = 0;
static volatile payload_u64 g_legacy_gamevt_driver_unload_shadow = 0;
static volatile payload_u64 g_legacy_yvt_boot_flags_shadow = 0;
static volatile payload_u64 g_legacy_render_swapchain_shadow = 0;
static volatile unsigned char g_legacy_render_isfinish_shadow = 0;
static volatile payload_u64 g_legacy_render_d2d_rt_shadow = 0;
static volatile payload_u64 g_legacy_render_color_brush_shadow = 0;
static volatile payload_u64 g_legacy_render_text_format_shadow = 0;
static volatile payload_u64 g_legacy_render_buffer0_shadow = 0;
static volatile payload_u64 g_legacy_render_buffer0_hva_shadow = 0;
static volatile payload_u64 g_legacy_render_desc_buffer_shadow = 0;
static volatile payload_u64 g_legacy_render_desc_buffer_hva_shadow = 0;
static volatile payload_u64 g_bridge_self_ping = 0;
static volatile payload_u64 g_bridge_self_diag = 0;
static volatile payload_u64 g_bridge_self_map = 0;
static volatile payload_u64 g_bridge_self_rsp = 0;
static volatile payload_u64 g_bridge_self_rip = 0;
static volatile payload_u64 g_bridge_self_cpuid = 0;
static volatile payload_u64 g_bridge_self_hv_base = 0;
static volatile payload_u64 g_bridge_self_vh_init_tramp_pool = 0;
static volatile payload_u64 g_bridge_self_affinity_lock = 0;
static volatile payload_u64 g_bridge_self_hide_diag = 0;
static volatile payload_u64 g_bridge_self_hide_diag_fail = 0;
static volatile payload_u64 g_bridge_self_hide_diag_max_used = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_list = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_fail = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_requested = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_hidden = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_null = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_last_count = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_last_hidden = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_last_pfn = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_last_pte_va = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_last_pte_before = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_last_pte_after = 0;
static volatile payload_u64 g_bridge_self_hide_pfn_last_vcpu = 0;
static volatile payload_u64 g_bridge_self_get_pa = 0;
static volatile payload_u64 g_bridge_self_get_pa_fail = 0;
static volatile payload_u64 g_bridge_self_get_pa_last_cr3 = 0;
static volatile payload_u64 g_bridge_self_get_pa_last_gva = 0;
static volatile payload_u64 g_bridge_self_get_pa_last_gpa = 0;
static volatile payload_u64 g_bridge_self_gamevt_get = 0;
static volatile payload_u64 g_bridge_self_gamevt_save = 0;
static volatile payload_u64 g_bridge_self_gamevt_fail = 0;
static volatile payload_u64 g_payload_gamevt_image_base = 0;
static volatile payload_u64 g_payload_gamevt_driver_unload = 0;
static volatile payload_u64 g_bridge_self_keep_hv = 0;
static volatile payload_u64 g_payload_keep_hv_flags = 0;
extern "C" volatile payload_u64 g_payload_unload_quiesce = 0;
static volatile payload_u64 g_bridge_self_query_cr3 = 0;
static volatile payload_u64 g_bridge_self_query_cr3_fail = 0;
static volatile payload_u64 g_bridge_self_query_cr3_last_pid = 0;
static volatile payload_u64 g_bridge_self_query_cr3_last_cr3 = 0;
static volatile payload_u64 g_bridge_self_get_info = 0;
static volatile payload_u64 g_bridge_self_get_info_fail = 0;
static volatile payload_u64 g_payload_real_cr3 = 0;
static volatile payload_u64 g_bridge_self_read_phys = 0;
static volatile payload_u64 g_bridge_self_write_phys = 0;
static volatile payload_u64 g_bridge_self_read_virt = 0;
static volatile payload_u64 g_bridge_self_write_virt = 0;
static volatile payload_u64 g_bridge_self_mem_fail = 0;
static volatile payload_u64 g_bridge_self_mem_bytes = 0;
static volatile payload_u64 g_bridge_self_rdmsr = 0;
static volatile payload_u64 g_bridge_self_wrmsr = 0;
static volatile payload_u64 g_bridge_self_msr_last = 0;
static volatile payload_u64 g_bridge_self_rdtsc = 0;
static volatile payload_u64 g_bridge_self_rdtscp = 0;
static volatile payload_u64 g_bridge_self_tsc_last = 0;
static volatile payload_u64 g_bridge_self_tsc_aux = 0;
static volatile payload_u64 g_bridge_self_tsc_fail = 0;
static volatile payload_u64 g_payload_tsc_enter[64] = {};
static volatile payload_u64 g_payload_tsc_offset[64] = {};
static volatile payload_u64 g_payload_tsc_last_sensitive[64] = {};
static volatile unsigned char g_payload_tsc_hide_overhead[64] = {};
static volatile unsigned char g_payload_tsc_ctrl_enabled[64] = {};
static volatile payload_u64 g_payload_exbp_mode = PAYLOAD_DEFAULT_EXBP_MODE;
static volatile payload_u64 g_payload_exbp_probe_count = 0;
static volatile payload_u64 g_payload_exbp_reinject_count = 0;
static volatile payload_u64 g_payload_exbp_reinject_fail_count = 0;
static volatile payload_u64 g_payload_exbp_guard_count = 0;
static volatile payload_u64 g_payload_exbp_last_reason = 0;
static volatile payload_u64 g_payload_exbp_last_rip = 0;
static volatile payload_u64 g_payload_exbp_last_info = 0;
static volatile payload_u64 g_payload_exbp_last_entry_info = 0;
static volatile payload_u64 g_payload_exbp_last_instruction_length = 0;
static volatile payload_u64 g_payload_misc_exit_probe_count = 0;
static volatile payload_u64 g_payload_misc_exit_handle_count = 0;
static volatile payload_u64 g_payload_misc_exit_fail_count = 0;
static volatile payload_u64 g_payload_misc_exit_last_reason = 0;
static volatile payload_u64 g_payload_misc_exit_last_action = 0;
static volatile payload_u64 g_payload_misc_exit_last_vector = 0;
static volatile payload_u64 g_payload_misc_exit_preempt_count = 0;
static volatile payload_u64 g_payload_host_idt_install_count = 0;
static volatile payload_u64 g_payload_host_idt_fail_count = 0;
static volatile payload_u64 g_payload_host_idt_last_base = 0;
static volatile payload_u64 g_payload_host_exception_count = 0;
static volatile payload_u64 g_payload_host_exception_last_vector = 0;
static volatile payload_u64 g_payload_host_exception_last_rip = 0;
extern "C" volatile payload_u64 g_payload_host_panic_resume_rsp[64] = {};
extern "C" volatile payload_u64 g_payload_host_panic_resume_rip[64] = {};
static volatile payload_u64 g_payload_host_panic_landing_count = 0;
static volatile payload_u64 g_payload_host_panic_landing_fail_count = 0;
static volatile payload_u64 g_payload_host_panic_landing_last_index = 0;
static volatile payload_u64 g_payload_host_panic_landing_last_rsp = 0;
static volatile payload_u64 g_payload_host_panic_landing_last_rip = 0;
static volatile LONG g_payload_vtpanic_active = 0;
static volatile payload_u64 g_payload_vtpanic_mode = PAYLOAD_VT_FATAL_BUGCHECK_ENABLED ? 1ull : 0ull;
static volatile payload_u64 g_payload_vtpanic_count = 0;
static volatile payload_u64 g_payload_vtpanic_last_reason = 0;
static volatile payload_u64 g_payload_vtpanic_last_param1 = 0;
static volatile payload_u64 g_payload_vtpanic_last_param2 = 0;
static volatile payload_u64 g_payload_vtpanic_last_param3 = 0;
static volatile payload_u64 g_payload_vtpanic_last_vmexit_reason = 0;
static volatile payload_u64 g_payload_vtpanic_last_guest_rip = 0;
static volatile payload_u64 g_payload_vtpanic_last_guest_cr3 = 0;
static volatile payload_u64 g_payload_vtpanic_last_guest_rsp = 0;
static volatile payload_u64 g_payload_vtpanic_last_gla = 0;
static volatile payload_u64 g_payload_vtpanic_last_gpa = 0;
static volatile payload_u64 g_payload_vtpanic_last_qualification = 0;
static volatile payload_u64 g_payload_vtpanic_last_error = 0;
static volatile payload_u64 g_payload_vtpanic_last_frame = 0;
static volatile LONG g_payload_vtpanic_selftest_fired = 0;
static volatile payload_u64 g_payload_vtpanic_selftest_vmexit_seen = 0;
static volatile payload_u64 g_payload_vtpanic_selftest_wait_kernel = 0;
static volatile payload_u64 g_payload_vtpanic_selftest_schedule_fail = 0;
static volatile payload_u64 g_payload_vtpanic_storm_count = 0;
static volatile payload_u64 g_payload_vtpanic_storm_last_idx = 0;
static volatile payload_u64 g_payload_vtpanic_storm_last_seen = 0;
static volatile payload_u64 g_payload_vtpanic_storm_last_sig0 = 0;
static volatile payload_u64 g_payload_vtpanic_storm_last_sig1 = 0;
static volatile payload_u64 g_payload_vtpanic_storm_sig0[64] = {};
static volatile payload_u64 g_payload_vtpanic_storm_sig1[64] = {};
static volatile payload_u64 g_payload_vtpanic_storm_seen[64] = {};
static volatile payload_u64 g_payload_vtpanic_storm_attempt[64] = {};
static volatile payload_u64 g_payload_vtpanic_mm_hook_fuse_count = 0;
static volatile payload_u64 g_payload_vtpanic_mm_hook_fuse_last_type = 0;
static volatile payload_u64 g_payload_vtpanic_mm_hook_fuse_last_hit = 0;
static volatile payload_u64 g_payload_vtpanic_mm_hook_fuse_hits[32] = {};
static volatile LONG g_payload_vtpanic_deferred_pending = 0;
static volatile payload_u64 g_payload_vtpanic_deferred_reason = 0;
static volatile payload_u64 g_payload_vtpanic_deferred_param1 = 0;
static volatile payload_u64 g_payload_vtpanic_deferred_param2 = 0;
static volatile payload_u64 g_payload_vtpanic_deferred_param3 = 0;
static volatile payload_u64 g_payload_invlpg_probe_count = 0;
static volatile payload_u64 g_payload_invlpg_handle_count = 0;
static volatile payload_u64 g_payload_invlpg_fail_count = 0;
static volatile payload_u64 g_payload_invlpg_last_gla = 0;
static volatile payload_u64 g_payload_invlpg_last_vpid = 0;
static volatile payload_u64 g_payload_invlpg_last_result = 0;
static volatile payload_u64 g_payload_xsetbv_probe_count = 0;
static volatile payload_u64 g_payload_xsetbv_handle_count = 0;
static volatile payload_u64 g_payload_xsetbv_fail_count = 0;
static volatile payload_u64 g_payload_xsetbv_gp_count = 0;
static volatile payload_u64 g_payload_xsetbv_ud_count = 0;
static volatile payload_u64 g_payload_xsetbv_last_reason = 0;
static volatile payload_u64 g_payload_xsetbv_last_index = 0;
static volatile payload_u64 g_payload_xsetbv_last_value = 0;
static volatile payload_u64 g_payload_xsetbv_last_cr4 = 0;
static volatile payload_u64 g_payload_xsetbv_last_unsupported_mask = 0;
static volatile payload_u64 g_payload_xsetbv_last_result = 0;
static volatile payload_u64 g_payload_invd_probe_count = 0;
static volatile payload_u64 g_payload_invd_handle_count = 0;
static volatile payload_u64 g_payload_invd_fail_count = 0;
static volatile payload_u64 g_payload_invd_gp_count = 0;
static volatile payload_u64 g_payload_invd_last_dpl = 0;
static volatile payload_u64 g_payload_invd_last_result = 0;
static volatile payload_u64 g_payload_cr_probe_count = 0;
static volatile payload_u64 g_payload_cr_handle_count = 0;
static volatile payload_u64 g_payload_cr_fail_count = 0;
static volatile payload_u64 g_payload_cr_gp_count = 0;
static volatile payload_u64 g_payload_cr_last_reason = 0;
static volatile payload_u64 g_payload_cr_last_qualification = 0;
static volatile payload_u64 g_payload_cr_last_access = 0;
static volatile payload_u64 g_payload_cr_last_register = 0;
static volatile payload_u64 g_payload_cr_last_gpr = 0;
static volatile payload_u64 g_payload_cr_last_value = 0;
static payload_status g_payload_control_status_scratch = {};
static mapctl_status g_payload_control_map_status_scratch = {};
static mapctl_memcheck g_payload_memcheck_scratch = {};
static volatile payload_u64 g_payload_vmexit_bridge_forward_last_reason = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_last_code = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_last_key = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_last_rax = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_last_guest_rip = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_last_qualification = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_bad_key = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_unknown_code = 0;
static volatile payload_u64 g_payload_vmexit_bridge_forward_non_vmcall = 0;
extern "C" volatile payload_u64 g_payload_legacy_released = 0;
static volatile payload_u64 g_payload_legacy_ptrs_finalized = 0;
static volatile payload_u64 g_payload_vmexit_reason_hist[64] = {};
static volatile payload_u64 g_payload_vmexit_forward_reason_hist[64] = {};
static volatile payload_u64 g_payload_vmexit_exception_vector_hist[32] = {};
static volatile payload_u64 g_payload_vmexit_exception_last_info = 0;
static volatile payload_u64 g_payload_vmexit_exception_last_error = 0;
static volatile payload_u64 g_payload_vmexit_ept_last_gpa = 0;
static volatile payload_u64 g_payload_vmexit_ept_last_gla = 0;
static volatile payload_u64 g_payload_vmexit_ept_last_qualification = 0;
static volatile payload_u64 g_payload_vmexit_bp_last_rip = 0;
static volatile payload_u64 g_payload_vmexit_bp_user_count = 0;
static volatile payload_u64 g_payload_vmexit_bp_kernel_count = 0;
static volatile payload_u64 g_payload_vmexit_bp_type_software_count = 0;
static volatile payload_u64 g_payload_vmexit_bp_type_other_count = 0;
static volatile payload_u64 g_payload_vmexit_forward_badkey_last_rip = 0;
static volatile payload_u64 g_payload_vmexit_forward_nonvm_last_rip = 0;
static volatile payload_u64 g_payload_vmexit_bp_rip_hist_addr[PAYLOAD_RIP_HIST_SLOTS] = {};
static volatile payload_u64 g_payload_vmexit_bp_rip_hist_count[PAYLOAD_RIP_HIST_SLOTS] = {};
static volatile payload_u64 g_payload_vmexit_badkey_rip_hist_addr[PAYLOAD_RIP_HIST_SLOTS] = {};
static volatile payload_u64 g_payload_vmexit_badkey_rip_hist_count[PAYLOAD_RIP_HIST_SLOTS] = {};
static volatile payload_u64 g_payload_vmexit_nonvm_rip_hist_addr[PAYLOAD_RIP_HIST_SLOTS] = {};
static volatile payload_u64 g_payload_vmexit_nonvm_rip_hist_count[PAYLOAD_RIP_HIST_SLOTS] = {};
static volatile LONG64 g_payload_vmexit_bp_rip_hist_next = 0;
static volatile LONG64 g_payload_vmexit_badkey_rip_hist_next = 0;
static volatile LONG64 g_payload_vmexit_nonvm_rip_hist_next = 0;
static volatile payload_u64 g_payload_vmexit_ring_seq = 0;
static volatile payload_vmexit_ring_entry g_payload_vmexit_ring[PAYLOAD_VMEXIT_RING_SLOTS] = {};
static volatile payload_u64 g_payload_vtret_probe_count = 0;
static volatile payload_u64 g_payload_vtret_match_count = 0;
static volatile payload_u64 g_payload_vtret_scan_count = 0;
static volatile payload_u64 g_payload_vtret_scan_fail_count = 0;
static volatile payload_u64 g_payload_vtret_last_node = 0;
static volatile payload_u64 g_payload_vtret_last_old_vt_rsp = 0;
static volatile payload_u64 g_payload_vtret_last_rip = 0;
static volatile payload_u64 g_payload_vtret_last_reason = 0;
static volatile payload_u64 g_payload_vtret_last_process = 0;
static volatile payload_u64 g_payload_vtret_last_thread = 0;
static volatile payload_u64 g_payload_vtret_list_base = 0;
static volatile payload_u64 g_payload_vtret_active_head = 0;
static volatile payload_u64 g_payload_vtret_mode = PAYLOAD_DEFAULT_VTRET_MODE;
static volatile payload_u64 g_payload_vtret_strict_match_count = 0;
static volatile payload_u64 g_payload_vtret_loose_match_count = 0;
static volatile payload_u64 g_payload_vtret_handle_count = 0;
static volatile payload_u64 g_payload_vtret_handle_fail_count = 0;
static volatile payload_u64 g_payload_vtret_last_handle_result = 0;
static volatile payload_u64 g_payload_tramp_mode = PAYLOAD_DEFAULT_TRAMP_MODE;
static volatile payload_u64 g_payload_tramp_probe_count = 0;
static volatile payload_u64 g_payload_tramp_match_count = 0;
static volatile payload_u64 g_payload_tramp_scan_count = 0;
static volatile payload_u64 g_payload_tramp_scan_fail_count = 0;
static volatile payload_u64 g_payload_tramp_handle_count = 0;
static volatile payload_u64 g_payload_tramp_handle_fail_count = 0;
static volatile payload_u64 g_payload_tramp_last_reason = 0;
static volatile payload_u64 g_payload_tramp_last_pool = 0;
static volatile payload_u64 g_payload_tramp_last_slot = 0;
static volatile payload_u64 g_payload_tramp_last_rip = 0;
static volatile payload_u64 g_payload_tramp_last_tramp_va = 0;
static volatile payload_u64 g_payload_tramp_last_target = 0;
static volatile payload_u64 g_payload_tramp_last_kind = 0;
static volatile payload_u64 g_payload_tramp_user_match_count = 0;
static volatile payload_u64 g_payload_tramp_kernel_match_count = 0;
static volatile payload_u64 g_payload_tramp_pool_base = 0;
static volatile payload_u64 g_payload_tramp_user_slot_count = 0;
static volatile payload_u64 g_payload_tramp_kernel_slot_count = 0;
static volatile payload_u64 g_payload_tramp_user_ready = 0;
static volatile payload_u64 g_payload_tramp_kernel_ready = 0;
static volatile payload_u64 g_payload_hook_mode = PAYLOAD_DEFAULT_HOOK_MODE;
static volatile payload_u64 g_payload_hook_probe_count = 0;
static volatile payload_u64 g_payload_hook_match_count = 0;
static volatile payload_u64 g_payload_hook_scan_count = 0;
static volatile payload_u64 g_payload_hook_scan_fail_count = 0;
static volatile payload_u64 g_payload_hook_passthrough_count = 0;
static volatile payload_u64 g_payload_hook_passthrough_fail_count = 0;
static volatile payload_u64 g_payload_hook_pmo_forward_count = 0;
static volatile payload_u64 g_payload_pmo_probe_count = 0;
static volatile payload_u64 g_payload_pmo_match_count = 0;
static volatile payload_u64 g_payload_pmo_handle_count = 0;
static volatile payload_u64 g_payload_pmo_fail_count = 0;
static volatile payload_u64 g_payload_pmo_last_reason = 0;
static volatile payload_u64 g_payload_pmo_last_rip = 0;
static volatile payload_u64 g_payload_pmo_last_tramp_va = 0;
static volatile payload_u64 g_payload_pmo_last_target = 0;
static volatile payload_u64 g_payload_pmo_last_swapchain = 0;
static volatile payload_u64 g_payload_pmo_side_effect_count = 0;
static volatile payload_u64 g_payload_pmo_last_old_swapchain = 0;
static volatile payload_u64 g_payload_pmo_last_isfinish = 0;
static volatile payload_u64 g_payload_pmo_render_d2d_rt = 0;
static volatile payload_u64 g_payload_pmo_render_brush = 0;
static volatile payload_u64 g_payload_pmo_render_textfmt = 0;
static volatile payload_u64 g_payload_pmo_render_buf0 = 0;
static volatile payload_u64 g_payload_pmo_render_buf0_hva = 0;
static volatile payload_u64 g_payload_pmo_render_desc = 0;
static volatile payload_u64 g_payload_pmo_render_desc_hva = 0;
static volatile payload_u64 g_payload_pmo_render_entity = 0;
static volatile payload_u64 g_payload_pmo_render_entity_hva = 0;
static volatile payload_u64 g_payload_pmo_render_device = 0;
static volatile payload_u64 g_payload_pmo_render_context = 0;
static volatile payload_u64 g_payload_pmo_render_surface = 0;
static volatile payload_u64 g_payload_pmo_fake_texture = 0;
static volatile payload_u64 g_payload_pmo_marker_texture = 0;
static volatile payload_u64 g_payload_pmo_marker_ready = 0;
static volatile payload_u64 g_payload_pmo_marker_stage = 0;
static volatile payload_u64 g_payload_pmo_last_getbuffer_out = 0;
static volatile payload_u64 g_payload_pmo_call_probe_count = 0;
static volatile payload_u64 g_payload_pmo_call_return_count = 0;
static volatile payload_u64 g_payload_pmo_call_fail_count = 0;
static volatile payload_u64 g_payload_pmo_call_same_vcpu_count = 0;
static volatile payload_u64 g_payload_pmo_call_cross_vcpu_count = 0;
static volatile payload_u64 g_payload_pmo_call_cross_queue_count = 0;
static volatile payload_u64 g_payload_pmo_call_cross_leak_count = 0;
static volatile payload_u64 g_payload_pmo_call_last_reason = 0;
static volatile payload_u64 g_payload_pmo_call_last_function = 0;
static volatile payload_u64 g_payload_pmo_call_last_ret = 0;
static volatile payload_u64 g_payload_pmo_call_last_blank = 0;
static volatile payload_u64 g_payload_pmo_call_last_new_rsp = 0;
static volatile payload_u64 g_payload_pmo_call_last_vcpu = 0;
static volatile payload_u64 g_payload_pmo_vtret_match_count = 0;
static volatile payload_u64 g_payload_pmo_vtret_handle_count = 0;
static volatile payload_u64 g_payload_pmo_vtret_fail_count = 0;
static volatile payload_u64 g_payload_pmo_vtret_last_node = 0;
static volatile payload_u64 g_payload_pmo_vtret_last_rip = 0;
static volatile payload_u64 g_payload_pmo_draw_probe_count = 0;
static volatile payload_u64 g_payload_pmo_draw_ready_count = 0;
static volatile payload_u64 g_payload_pmo_draw_done_count = 0;
static volatile payload_u64 g_payload_pmo_draw_fail_count = 0;
static volatile payload_u64 g_payload_pmo_draw_last_stage = 0;
static volatile payload_u64 g_payload_pmo_draw_last_result = 0;
static volatile payload_u64 g_payload_business_probe_count = 0;
static volatile payload_u64 g_payload_business_tick_count = 0;
static volatile payload_u64 g_payload_business_skip_count = 0;
static volatile payload_u64 g_payload_business_fail_count = 0;
static volatile payload_u64 g_payload_business_last_stage = 0;
static volatile payload_u64 g_payload_business_last_reason = 0;
static volatile payload_u64 g_payload_business_last_vcpu = 0;
static volatile payload_u64 g_payload_business_last_guest_cr3 = 0;
static volatile payload_u64 g_payload_business_last_swapchain = 0;
static volatile payload_u64 g_payload_business_last_draw_done = 0;
static volatile payload_u64 g_payload_hook_last_reason = 0;
static volatile payload_u64 g_payload_hook_last_rip = 0;
static volatile payload_u64 g_payload_hook_last_tramp_va = 0;
static volatile payload_u64 g_payload_hook_last_bp_rip = 0;
static volatile payload_u64 g_payload_hook_last_target = 0;
static volatile payload_u64 g_payload_hook_last_kind = 0;
static volatile payload_u64 g_payload_hook_user_match_count = 0;
static volatile payload_u64 g_payload_hook_kernel_match_count = 0;
static volatile payload_u64 g_payload_hook_last_key = 0;
static volatile payload_u64 g_payload_hook_last_rax = 0;
static volatile payload_u64 g_payload_hook_resident_handle_count = 0;
static volatile payload_u64 g_payload_hook_resident_fail_count = 0;
static volatile payload_u64 g_payload_hook_last_type = 0;
static volatile payload_u64 g_payload_hook_last_action = 0;
static volatile payload_u64 g_payload_hook_last_retaddr = 0;
static volatile payload_u64 g_payload_hook_last_result = 0;
static volatile payload_u64 g_payload_getbuffer_hits = 0;
static volatile payload_u64 g_payload_getbuffer_alien = 0;
static volatile payload_u64 g_payload_getbuffer_substitute = 0;
static volatile payload_u64 g_payload_getbuffer_pass = 0;
static volatile payload_u64 g_payload_getbuffer_marker = 0;
static volatile payload_u64 g_payload_getbuffer_install_probe = 0;
static volatile payload_u64 g_payload_getbuffer_install_ok = 0;
static volatile payload_u64 g_payload_getbuffer_install_fail = 0;
static volatile payload_u64 g_payload_getbuffer_install_stage = 0;
static volatile payload_u64 g_payload_getbuffer_install_target = 0;
static volatile payload_u64 g_payload_getbuffer_install_blank = 0;
static volatile payload_u64 g_payload_getbuffer_install_fake = 0;
static volatile payload_u64 g_payload_getbuffer_install_tramp = 0;
static volatile payload_u64 g_payload_getbuffer_install_slot = 0;
static volatile payload_u64 g_payload_getbuffer_install_orig_pfn = 0;
static volatile payload_u64 g_payload_getbuffer_install_exec_pfn = 0;
static volatile payload_u64 g_payload_getbuffer_install_pending = 0;
static volatile payload_u64 g_payload_getbuffer_install_drain_ok = 0;
static volatile payload_u64 g_payload_getbuffer_install_drain_fail = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_reason = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_vcpu = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_vcpu_ptr = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_pte_va = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_pte_before = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_pte_pfn = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_used = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_free = 0;
static volatile payload_u64 g_payload_getbuffer_install_native_node = 0;
static volatile payload_u64 g_payload_present_hits = 0;
static volatile payload_u64 g_payload_present_alien = 0;
static volatile payload_u64 g_payload_present1_hits = 0;
static volatile payload_u64 g_payload_present1_alien = 0;
static volatile payload_u64 g_payload_copyresource_hits = 0;
static volatile payload_u64 g_payload_copyresource_alien = 0;
static volatile payload_u64 g_payload_duplicateoutput_hits = 0;
static volatile payload_u64 g_payload_duplicateoutput_alien = 0;
static volatile payload_u64 g_payload_ntsetevent_hits = 0;
static volatile payload_u64 g_payload_nt_alloc_hits = 0;
static volatile payload_u64 g_payload_nt_alloc_alien = 0;
static volatile payload_u64 g_payload_nt_protect_hits = 0;
static volatile payload_u64 g_payload_nt_protect_alien = 0;
static volatile payload_u64 g_payload_nt_map_hits = 0;
static volatile payload_u64 g_payload_nt_map_alien = 0;
static volatile payload_u64 g_payload_capture_notify_count = 0;
static volatile payload_u64 g_payload_mmcm_hits = 0;
static volatile payload_u64 g_payload_mmcm_blocked = 0;
static volatile payload_u64 g_payload_mmcvm_hits = 0;
static volatile payload_u64 g_payload_mmcvm_blocked = 0;
static volatile payload_u64 g_payload_mmisav_hits = 0;
static volatile payload_u64 g_payload_mmisav_blocked = 0;
static volatile payload_u64 g_payload_mmmio_hits = 0;
static volatile payload_u64 g_payload_mmmio_blocked = 0;
static volatile payload_u64 g_payload_ntqvm_hits = 0;
static volatile payload_u64 g_payload_ntqvm_blocked = 0;
static volatile payload_u64 g_payload_mmgpa_hits = 0;
static volatile payload_u64 g_payload_mmgpa_blocked = 0;
static volatile payload_u64 g_payload_mm4_install_probe = 0;
static volatile payload_u64 g_payload_mm4_install_ok = 0;
static volatile payload_u64 g_payload_mm4_install_fail = 0;
static volatile payload_u64 g_payload_mm4_install_already = 0;
static volatile payload_u64 g_payload_mm4_install_mask = 0;
static volatile payload_u64 g_payload_mm4_install_fail_mask = 0;
static volatile payload_u64 g_payload_mm4_install_last_type = 0;
static volatile payload_u64 g_payload_mm4_install_last_stage = 0;
static volatile payload_u64 g_payload_mm4_install_last_target = 0;
static volatile payload_u64 g_payload_mm4_install_last_slot = 0;
static volatile payload_u64 g_payload_mm4_install_last_pending = 0;
static volatile payload_u64 g_payload_mm4_hit_last_type = 0;
static volatile payload_u64 g_payload_mm4_hit_last_vcpu = 0;
static volatile payload_u64 g_payload_mm4_hit_vcpu_bitmap = 0;
static volatile payload_u64 g_payload_mm4_hit_vcpu0 = 0;
static volatile payload_u64 g_payload_mm4_hit_type18_last_vcpu = 0;
static volatile payload_u64 g_payload_mm4_hit_type18_vcpu_bitmap = 0;
static volatile payload_u64 g_payload_mm4_hit_type18_vcpu0 = 0;
static volatile payload_u64 g_payload_mm4_hit_type19_last_vcpu = 0;
static volatile payload_u64 g_payload_mm4_hit_type19_vcpu_bitmap = 0;
static volatile payload_u64 g_payload_mm4_hit_type19_vcpu0 = 0;
static volatile payload_u64 g_payload_mm4_hit_type20_last_vcpu = 0;
static volatile payload_u64 g_payload_mm4_hit_type20_vcpu_bitmap = 0;
static volatile payload_u64 g_payload_mm4_hit_type20_vcpu0 = 0;
static volatile payload_u64 g_payload_mm4_hit_type21_last_vcpu = 0;
static volatile payload_u64 g_payload_mm4_hit_type21_vcpu_bitmap = 0;
static volatile payload_u64 g_payload_mm4_hit_type21_vcpu0 = 0;
static volatile payload_u64 g_payload_overlay_hide_until_tsc = 0;
static volatile payload_u64 g_payload_ept_mode = PAYLOAD_DEFAULT_EPT_MODE;
static volatile payload_u64 g_payload_ept_tramp_probe_count = 0;
static volatile payload_u64 g_payload_ept_tramp_match_count = 0;
static volatile payload_u64 g_payload_ept_tramp_handle_count = 0;
static volatile payload_u64 g_payload_ept_tramp_handle_fail_count = 0;
static volatile payload_u64 g_payload_ept_tramp_scan_fail_count = 0;
static volatile payload_u64 g_payload_ept_tramp_mtf_count = 0;
static volatile payload_u64 g_payload_ept_tramp_mtf_fail_count = 0;
static volatile payload_u64 g_payload_ept_tramp_last_reason = 0;
static volatile payload_u64 g_payload_ept_tramp_last_gpa = 0;
static volatile payload_u64 g_payload_ept_tramp_last_gla = 0;
static volatile payload_u64 g_payload_ept_tramp_last_rip = 0;
static volatile payload_u64 g_payload_ept_tramp_last_qualification = 0;
static volatile payload_u64 g_payload_ept_tramp_last_pte_pa = 0;
static volatile payload_u64 g_payload_ept_tramp_last_pte_before = 0;
static volatile payload_u64 g_payload_ept_tramp_last_pte_after = 0;
static volatile payload_u64 g_payload_ept_tramp_last_orig_pfn = 0;
static volatile payload_u64 g_payload_ept_tramp_last_exec_pfn = 0;
static volatile payload_u64 g_payload_ept_tramp_last_guest_page = 0;
static volatile payload_u64 g_payload_ept_tramp_last_kind = 0;
static volatile payload_u64 g_payload_ept_tramp_exec_count = 0;
static volatile payload_u64 g_payload_ept_tramp_data_count = 0;
static volatile payload_u64 g_payload_ept_tramp_same_count = 0;
static volatile payload_u64 g_payload_ept_tramp_user_match_count = 0;
static volatile payload_u64 g_payload_ept_tramp_kernel_match_count = 0;
static volatile payload_u64 g_payload_ept_tramp_last_vcpu = 0;
static volatile payload_u64 g_payload_ept_tramp_last_mtf_restore = 0;
static volatile payload_u64 g_payload_ept_generic_match_count = 0;
static volatile payload_u64 g_payload_ept_fake_match_count = 0;
static volatile payload_u64 g_payload_ept_last_hook_node = 0;
static volatile payload_u64 g_payload_ept_last_is_fake = 0;
static volatile payload_u64 g_payload_ept_mtf_active[64] = {};
static volatile payload_u64 g_payload_ept_mtf_pte_pa[64] = {};
static volatile payload_u64 g_payload_ept_mtf_restore_entry[64] = {};
static volatile payload_u64 g_payload_ept_mtf_prev_ctrl[64] = {};
static constexpr payload_u64 PAYLOAD_NATIVE_EPT_PENDING_CAPACITY = 16ull;
struct payload_native_ept_pending_entry
{
    volatile payload_u64 orig_pfn;
    volatile payload_u64 exec_pfn;
    volatile payload_u64 is_fake_page;
    volatile payload_u64 entry_ptr;
    volatile payload_u64 pending_bitmap;
};
static volatile LONG g_payload_native_ept_pending_lock = 0;
static payload_native_ept_pending_entry g_payload_native_ept_pending[PAYLOAD_NATIVE_EPT_PENDING_CAPACITY] = {};
static volatile payload_u64 g_payload_vmexit_bridge_rsp_last = 0;
static volatile payload_u64 g_payload_vmexit_bridge_rsp_class = 0;
static volatile payload_u64 g_payload_vmexit_bridge_rsp_payload_count = 0;
static volatile payload_u64 g_payload_vmexit_bridge_rsp_external_count = 0;
static volatile payload_u64 g_payload_host_map_success_count = 0;
static volatile payload_u64 g_payload_host_map_fail_count = 0;
static volatile payload_u64 g_payload_host_map_page_table_pages = 0;
extern "C" void PayloadVmExitTrampoline();
extern "C" void PayloadVmExitBridge();
extern "C" void PayloadVtCallEntry(void* ctx, payload_u64* old_vt_rsp, payload_u64* cdata);
extern "C" void PayloadVtCallExit(void* ctx, payload_u64 old_vt_rsp);
extern "C" void PayloadInvept(payload_u64 type, const void* descriptor);
extern "C" void PayloadInvvpid(payload_u64 type, const void* descriptor);
extern "C" void PayloadXsetbv(payload_u64 index, payload_u64 value);
extern "C" void PayloadInvd();
extern "C" payload_u64 PayloadRdmsrSafe(void* exception_info, unsigned long msr);
extern "C" void PayloadWrmsrSafe(void* exception_info, unsigned long msr, payload_u64 value);
extern "C" void PayloadXsetbvSafe(void* exception_info, unsigned long index, payload_u64 value);
extern "C" void PayloadTriggerHostGp();
extern "C" void PayloadTriggerHostUd2();
extern "C" void PayloadHostInterrupt0();
extern "C" void PayloadHostInterrupt1();
extern "C" void PayloadHostInterrupt2();
extern "C" void PayloadHostInterrupt3();
extern "C" void PayloadHostInterrupt4();
extern "C" void PayloadHostInterrupt5();
extern "C" void PayloadHostInterrupt6();
extern "C" void PayloadHostInterrupt7();
extern "C" void PayloadHostInterrupt8();
extern "C" void PayloadHostInterrupt10();
extern "C" void PayloadHostInterrupt11();
extern "C" void PayloadHostInterrupt12();
extern "C" void PayloadHostInterrupt13();
extern "C" void PayloadHostInterrupt14();
extern "C" void PayloadHostInterrupt16();
extern "C" void PayloadHostInterrupt17();
extern "C" void PayloadHostInterrupt18();
extern "C" void PayloadHostInterrupt19();
extern "C" void PayloadHostInterrupt20();
extern "C" void PayloadHostInterrupt30();
extern "C" payload_u64 PayloadSetVtretMode(payload_u64 mode);
extern "C" payload_u64 PayloadSetTrampMode(payload_u64 mode);
extern "C" payload_u64 PayloadSetHookMode(payload_u64 mode);
extern "C" payload_u64 PayloadSetEptMode(payload_u64 mode);
extern "C" payload_u64 PayloadSetCutoverMode(payload_u64 mode);
extern "C" payload_u64 PayloadDetachLegacyData(payload_u64 mode);
extern "C" payload_u64 PayloadAdoptPoolBlocks(
    const payload_pool_block* blocks,
    payload_u64 count,
    payload_u64 flags);
extern "C" payload_u64 PayloadInstallHostIdt(payload_u64 mode);
extern "C" payload_u64 PayloadAmdResidentActivate(
    payload_u64 ghv,
    payload_u64 vt_hook_table,
    payload_u64 vcpus,
    payload_u64 vcpu_count,
    payload_u64 vcpu_stride,
    payload_u64 resident_loop_offset,
    payload_u64 resident_ack_offset,
    payload_u64 mode);
static volatile payload_u64 g_vmexit_trampoline = 0;
static volatile payload_u64 g_vmexit_bridge = 0;
static PDRIVER_OBJECT g_resident_driver_object = nullptr;
static PDEVICE_OBJECT g_resident_device_object = nullptr;
static UNICODE_STRING g_resident_symlink = {};
static volatile LONG g_resident_control_ready = 0;
static HANDLE g_worker_handle = nullptr;
static volatile LONG g_worker_stop = 0;
static volatile LONG g_worker_running = 0;
static volatile LONG64 g_heartbeat_count = 0;

typedef PVOID(*payload_mm_allocate_independent_pages_fn)(SIZE_T NumberOfBytes, ULONG64 NodeMask);
typedef VOID(*payload_mm_free_independent_pages_fn)(PVOID BaseAddress, SIZE_T NumberOfBytes);
typedef BOOLEAN(*payload_mm_set_page_protection_fn)(PVOID BaseAddress, SIZE_T NumberOfBytes, ULONG NewProtect);
typedef NTSTATUS(*payload_ps_create_system_thread_fn)(
    PHANDLE ThreadHandle,
    ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PKSTART_ROUTINE StartRoutine,
    PVOID StartContext);
typedef NTSTATUS(*payload_ps_terminate_system_thread_fn)(NTSTATUS ExitStatus);
typedef NTSTATUS(*payload_zw_wait_for_single_object_fn)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS(*payload_zw_close_fn)(HANDLE Handle);
typedef NTSTATUS(*payload_ke_delay_execution_thread_fn)(KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval);
typedef KAFFINITY(*payload_ke_set_system_affinity_thread_ex_fn)(KAFFINITY Affinity);
typedef VOID(*payload_ke_revert_to_user_affinity_thread_ex_fn)(KAFFINITY Affinity);
typedef VOID(NTAPI* payload_ke_bug_check_ex_fn)(
    ULONG BugCheckCode,
    ULONG_PTR BugCheckParameter1,
    ULONG_PTR BugCheckParameter2,
    ULONG_PTR BugCheckParameter3,
    ULONG_PTR BugCheckParameter4);
typedef NTSTATUS(*payload_io_create_driver_fn)(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
typedef NTSTATUS(*payload_io_create_device_fn)(
    PDRIVER_OBJECT DriverObject,
    ULONG DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    DEVICE_TYPE DeviceType,
    ULONG DeviceCharacteristics,
    BOOLEAN Exclusive,
    PDEVICE_OBJECT* DeviceObject);
typedef NTSTATUS(*payload_io_create_symbolic_link_fn)(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName);
typedef VOID(*payload_io_delete_symbolic_link_fn)(PUNICODE_STRING SymbolicLinkName);
typedef VOID(*payload_io_delete_device_fn)(PDEVICE_OBJECT DeviceObject);
typedef VOID(*payload_io_complete_request_fn)(PIRP Irp, CCHAR PriorityBoost);

struct payload_hypercall_input
{
    payload_u64 flags;
    payload_u64 args[6];
};

extern "C" payload_u64 PayloadVmxVmcall(payload_hypercall_input* input);

static constexpr payload_u64 PAYLOAD_HYPERCALL_KEY = 0x88554466885ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_PING = 0ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_TEST = 1ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_UNLOAD = 2ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_READ_PHYS_MEM = 3ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_WRITE_PHYS_MEM = 4ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_READ_VIRT_MEM = 5ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_WRITE_VIRT_MEM = 6ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_QUERY_PROCESS_CR3 = 7ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_INSTALL_EPT_HOOK = 8ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_REMOVE_EPT_HOOK = 9ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_FLUSH_LOGS = 10ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_GET_PHYSICAL_ADDRESS = 11ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_HIDE_PHYSICAL_PAGE = 12ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_UNHIDE_PHYSICAL_PAGE = 13ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_GET_HV_BASE = 14ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_INSTALL_MMR = 15ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_REMOVE_MMR = 16ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_REMOVE_ALL_MMRS = 17ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_INSTALL_BREAKPOINT_HOOK = 18ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_REMOVE_BREAKPOINT_HOOK = 19ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_ADD_MMR_POINT = 22ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_DELETE_MMR_POINT = 23ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_GET_INFO = 37ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_GET_GAMEVT_IMAGE_BASE = 49ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_SAVE_GAMEVT_IMAGE_BASE = 50ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_ADD_VMCALL_HOOK = 52ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_ENABLE_VMCALL_HOOK = 53ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_DISABLE_VMCALL_HOOK = 54ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_REMOVE_VMCALL_HOOK = 55ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EH_INSTALL = 56ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EH_REMOVE = 57ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EH_ENABLE = 58ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EH_DISABLE = 59ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EH_WRITE = 60ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EH_GET_VA = 61ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EH_REMOVE_ALL_BY_PROCESS = 62ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_INSTALL = 63ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_INSTALL_RET_ABS = 64ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_ENABLE = 65ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_DISABLE = 66ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_REMOVE = 67ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_UNINIT = 68ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_FIND_BLANK = 69ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_FIND_BLANK_PAGE = 70ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_INIT_TRAMP_POOL = 71ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_TRAMP_ADD_PAGE = 72ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_TRAMP_ADD_SLOT = 73ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VH_TRAMP_SET_READY = 74ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_PREPARE_SELF_HIDE_ADD = 75ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_PREPARE_SELF_HIDE_COMMIT = 76ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_GET_POOL_BLOCKS = 78ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_SET_AFFINITY_LOCK = 77ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_GET_HIDE_DIAG = 79ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_HIDE_PFN_LIST = 80ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EPT_PROBE_INSTALL = 81ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EPT_PROBE_REMOVE = 82ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EPT_PROBE_GET_HITS = 83ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_EPT_PROBE_CLEAR_HITS = 84ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_GET_RESIDENT_HV_DIAG = 85ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_SET_HOST_RSP = 86ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_MAP_HOST_RANGE = 87ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_SET_HOST_RIP = 88ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_SET_KEEP_HV_ON_UNLOAD = 89ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_DBG_DISPATCH = 90ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_GET_PAYLOAD_STATUS = 91ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_SET_PAYLOAD_MODE = 92ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_PAYLOAD_PING = 93ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_VERIFY_HIDE_PFN_LIST = 94ull;
static constexpr payload_u64 PAYLOAD_HYPERCALL_UNHIDE_PFN_LIST = 95ull;
static constexpr payload_u64 PAYLOAD_YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD = 0x00000001ull;
static constexpr payload_u64 PAYLOAD_HYPERVISOR_SIGNATURE = 0x73623F64ull; // 'sb?d'
static constexpr ULONG PAYLOAD_VTPANIC_BUGCHECK_CODE = 0xE2u; // MANUALLY_INITIATED_CRASH
static constexpr payload_u64 PAYLOAD_VTPANIC_PARAM_TAG = 0x5654500000000000ull; // "VTP" marker
static constexpr payload_u64 PAYLOAD_VTPANIC_REASON_ROOT_EXCEPTION = 0x0001ull;
static constexpr payload_u64 PAYLOAD_VTPANIC_REASON_EPT_MTF_RESTORE_FAIL = 0x0002ull;
static constexpr payload_u64 PAYLOAD_VTPANIC_REASON_EPT_SANITIZE_FAIL = 0x0003ull;
static constexpr payload_u64 PAYLOAD_VTPANIC_REASON_EPT_MISCONFIG_SANITIZE_FAIL = 0x0004ull;
static constexpr payload_u64 PAYLOAD_VTPANIC_REASON_SELFTEST_FIRST_VMEXIT = 0x0005ull;
static constexpr payload_u64 PAYLOAD_VTPANIC_REASON_SELFTEST_HOST_INTERRUPT = 0x0006ull;
static constexpr payload_u64 PAYLOAD_VTPANIC_REASON_VMEXIT_STORM = 0x0007ull;
static constexpr payload_u64 PAYLOAD_VTPANIC_REASON_MM_HOOK_FUSE = 0x0008ull;
static constexpr payload_u64 PAYLOAD_HOST_PHYSICAL_MEMORY_BASE = 255ull << 39;
static constexpr payload_u64 PAYLOAD_HOST_PHYSICAL_MEMORY_BYTES = 512ull * 512ull * 0x200000ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_VPID = 0x0000ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_TSC_OFFSET = 0x2010ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC = 0x4002ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_SECONDARY_PROC_BASED_EXEC = 0x401Eull;
static constexpr payload_u64 PAYLOAD_VMX_PROCBASED_USE_TSC_OFFSETTING = 1ull << 3;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_EPT_POINTER = 0x201Aull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_CR0_GUEST_HOST_MASK = 0x6000ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW = 0x6004ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_CR4_GUEST_HOST_MASK = 0x6002ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_CR4_READ_SHADOW = 0x6006ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_PHYSICAL_ADDRESS = 0x2400ull;
static constexpr payload_u64 PAYLOAD_VMCS_EXIT_REASON = 0x4402ull;
static constexpr payload_u64 PAYLOAD_VMCS_VMEXIT_INTERRUPTION_INFORMATION = 0x4404ull;
static constexpr payload_u64 PAYLOAD_VMCS_VMEXIT_INTERRUPTION_ERROR_CODE = 0x4406ull;
static constexpr payload_u64 PAYLOAD_VMCS_IDT_VECTORING_INFORMATION_FIELD = 0x4408ull;
static constexpr payload_u64 PAYLOAD_VMCS_IDT_VECTORING_ERROR_CODE = 0x440Aull;
static constexpr payload_u64 PAYLOAD_VMCS_VMEXIT_INSTRUCTION_LENGTH = 0x440Cull;
static constexpr payload_u64 PAYLOAD_VMCS_EXIT_QUALIFICATION = 0x6400ull;
static constexpr payload_u64 PAYLOAD_VMCS_EXIT_GUEST_LINEAR_ADDRESS = 0x640Aull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_ES_SELECTOR = 0x0800ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_CS_SELECTOR = 0x0802ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_SS_SELECTOR = 0x0804ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_DS_SELECTOR = 0x0806ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_FS_SELECTOR = 0x0808ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_GS_SELECTOR = 0x080Aull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_LDTR_SELECTOR = 0x080Cull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_TR_SELECTOR = 0x080Eull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_PAT = 0x2804ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_GDTR_LIMIT = 0x4810ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_IDTR_LIMIT = 0x4812ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_SYSENTER_CS = 0x482Aull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_CR0 = 0x6800ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_CR3 = 0x6802ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_CR4 = 0x6804ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_FS_BASE = 0x680Eull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_GS_BASE = 0x6810ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_GDTR_BASE = 0x6816ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_IDTR_BASE = 0x6818ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_DR7 = 0x681Aull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_SS_ACCESS_RIGHTS = 0x4818ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_SYSENTER_ESP = 0x6824ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_SYSENTER_EIP = 0x6826ull;
static constexpr payload_u64 PAYLOAD_VMCS_HOST_CS_SELECTOR = 0x0C02ull;
static constexpr payload_u64 PAYLOAD_VMCS_HOST_CR3 = 0x6C02ull;
static constexpr payload_u64 PAYLOAD_VMCS_HOST_IDTR_BASE = 0x6C0Eull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_DEBUGCTL = 0x2802ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_RTIT_CTL = 0x2814ull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_LBR_CTL = 0x2816ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD = 0x4016ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE = 0x4018ull;
static constexpr payload_u64 PAYLOAD_VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH = 0x401Aull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_RSP = 0x681Cull;
static constexpr payload_u64 PAYLOAD_VMCS_GUEST_RIP = 0x681Eull;
static constexpr payload_u64 PAYLOAD_VMCS_HOST_RSP = 0x6C14ull;
static constexpr payload_u64 PAYLOAD_VMCS_HOST_RIP = 0x6C16ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_CPUID = 0x0Aull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_NMI_WINDOW = 0x08ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_GETSEC = 0x0Bull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_HLT = 0x0Cull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVD = 0x0Dull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVLPG = 0x0Eull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDPMC = 0x0Full;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDTSC = 0x10ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMCALL = 0x12ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMCLEAR = 0x13ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMLAUNCH = 0x14ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMPTRLD = 0x15ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMPTRST = 0x16ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMREAD = 0x17ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMRESUME = 0x18ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMWRITE = 0x19ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMXOFF = 0x1Aull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMXON = 0x1Bull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_MOV_CR = 0x1Cull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDMSR = 0x1Full;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_WRMSR = 0x20ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_MWAIT = 0x24ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_MONITOR_TRAP_FLAG = 0x25ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_MONITOR = 0x27ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_PAUSE = 0x28ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI = 0x00ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EPT_VIOLATION = 0x30ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EPT_MISCONFIGURATION = 0x31ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVEPT = 0x32ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDTSCP = 0x33ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED = 0x34ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVVPID = 0x35ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV = 0x37ull;
static constexpr payload_u64 PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMFUNC = 0x3Bull;
static constexpr payload_u64 PAYLOAD_INVVPID_INDIVIDUAL_ADDRESS = 0x0ull;
static constexpr payload_u64 PAYLOAD_INVVPID_SINGLE_CONTEXT = 0x1ull;
static constexpr payload_u64 PAYLOAD_INVVPID_SINGLE_CONTEXT_RETAINING_GLOBALS = 0x3ull;
static constexpr payload_u64 PAYLOAD_VMX_PROCBASED_MTF = 1ull << 27;
static constexpr payload_u64 PAYLOAD_VMX_PROCBASED_NMI_WINDOW = 1ull << 22;
static constexpr payload_u64 PAYLOAD_VMX_PROCBASED_HLT_EXITING = 1ull << 7;
static constexpr payload_u64 PAYLOAD_VMX_PROCBASED_MWAIT_EXITING = 1ull << 10;
static constexpr payload_u64 PAYLOAD_VMX_PROCBASED_MONITOR_EXITING = 1ull << 29;
static constexpr payload_u64 PAYLOAD_VMX_PROCBASED_PAUSE_EXITING = 1ull << 30;
static constexpr payload_u64 PAYLOAD_VMX_PROCBASED_IDLE_EXIT_MASK =
    PAYLOAD_VMX_PROCBASED_HLT_EXITING |
    PAYLOAD_VMX_PROCBASED_MWAIT_EXITING |
    PAYLOAD_VMX_PROCBASED_MONITOR_EXITING |
    PAYLOAD_VMX_PROCBASED_PAUSE_EXITING;
static constexpr payload_u64 PAYLOAD_VMX_SECONDARY_ENABLE_USER_WAIT_PAUSE = 1ull << 26;
static constexpr payload_u64 PAYLOAD_IA32_VMX_CR0_FIXED0 = 0x486ull;
static constexpr payload_u64 PAYLOAD_IA32_VMX_CR0_FIXED1 = 0x487ull;
static constexpr payload_u64 PAYLOAD_IA32_VMX_CR4_FIXED0 = 0x488ull;
static constexpr payload_u64 PAYLOAD_IA32_VMX_CR4_FIXED1 = 0x489ull;
static constexpr payload_u64 PAYLOAD_IA32_VMX_EPT_VPID_CAP = 0x48Cull;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_CAPABILITIES = 0xFEull;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_PHYSBASE0 = 0x200ull;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_PHYSMASK0 = 0x201ull;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_FIX64K_00000 = 0x250ull;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_FIX16K_80000 = 0x258ull;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_FIX16K_A0000 = 0x259ull;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_FIX4K_C0000 = 0x268ull;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_FIX4K_F8000 = 0x26Full;
static constexpr payload_u64 PAYLOAD_IA32_MTRR_DEF_TYPE = 0x2FFull;
static constexpr payload_u64 PAYLOAD_IA32_SYSENTER_CS = 0x174ull;
static constexpr payload_u64 PAYLOAD_IA32_SYSENTER_ESP = 0x175ull;
static constexpr payload_u64 PAYLOAD_IA32_SYSENTER_EIP = 0x176ull;
static constexpr payload_u64 PAYLOAD_IA32_DEBUGCTL = 0x1D9ull;
static constexpr payload_u64 PAYLOAD_IA32_PAT = 0x277ull;
static constexpr payload_u64 PAYLOAD_IA32_FS_BASE = 0xC0000100ull;
static constexpr payload_u64 PAYLOAD_IA32_GS_BASE = 0xC0000101ull;
static constexpr payload_u64 PAYLOAD_IA32_KERNEL_GS_BASE = 0xC0000102ull;
static constexpr payload_u64 PAYLOAD_IA32_DEBUGCTL_LBR_FLAG = 0x01ull;
static constexpr payload_u64 PAYLOAD_IA32_DEBUGCTL_BTS_FLAG = 0x80ull;
static constexpr payload_u64 PAYLOAD_IA32_RTIT_OUTPUT_BASE = 0x560ull;
static constexpr payload_u64 PAYLOAD_IA32_RTIT_OUTPUT_MASK_PTRS = 0x561ull;
static constexpr payload_u64 PAYLOAD_IA32_RTIT_CTL = 0x570ull;
static constexpr payload_u64 PAYLOAD_IA32_RTIT_STATUS = 0x571ull;
static constexpr payload_u64 PAYLOAD_IA32_RTIT_CR3_MATCH = 0x572ull;
static constexpr payload_u64 PAYLOAD_IA32_U_CET = 0x6A0ull;
static constexpr payload_u64 PAYLOAD_IA32_S_CET = 0x6A2ull;

extern "C" void PayloadWriteDs(unsigned short selector);
extern "C" void PayloadWriteEs(unsigned short selector);
extern "C" void PayloadWriteFs(unsigned short selector);
extern "C" void PayloadWriteGs(unsigned short selector);
extern "C" void PayloadWriteTr(unsigned short selector);
extern "C" void PayloadWriteLdtr(unsigned short selector);
extern "C" void PayloadLoadGdtr(void const* descriptor_register);
extern "C" void PayloadLoadIdtr(void const* descriptor_register);
extern "C" void PayloadHostPanicLanding();

struct payload_guest_context
{
    payload_u64 rax;
    payload_u64 rcx;
    payload_u64 rdx;
    payload_u64 rbx;
    payload_u64 rsp_shadow;
    payload_u64 rbp;
    payload_u64 rsi;
    payload_u64 rdi;
    payload_u64 r8;
    payload_u64 r9;
    payload_u64 r10;
    payload_u64 r11;
    payload_u64 r12;
    payload_u64 r13;
    payload_u64 r14;
    payload_u64 r15;
    payload_u64 cr2;
    payload_u64 cr8;
    payload_u64 dr0;
    payload_u64 dr1;
    payload_u64 dr2;
    payload_u64 dr3;
    payload_u64 dr6;
};

static bool PayloadBridgeScheduleGuestBugCheck(payload_guest_context* ctx,
                                               payload_u64 reason,
                                               payload_u64 param1,
                                               payload_u64 param2,
                                               payload_u64 param3);
static payload_u64 PayloadTriggerHostExceptionSelftest(payload_u64 mode);

struct payload_runtime_context
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 generation;
    payload_u64 owner;
    payload_u64 phase;
    payload_u64 flags;
    payload_u64 image_base;
    payload_u64 image_size;
    payload_u64 boot_flags;
    payload_u64 host_api;
    payload_u64 host_api_magic;
    payload_u64 host_api_flags;
    payload_u64 arena_base;
    payload_u64 arena_size;
    payload_u64 arena_used;
    payload_u64 arena_flags;
    payload_u64 kernel_api_flags;
    payload_u64 external_ref_flags;
    payload_u64 independent;
    payload_u64 direct_alloc_base;
    payload_u64 direct_alloc_size;
    payload_u64 owned_alloc_count;
    payload_u64 owned_alloc_bytes;
    payload_u64 last_result;
};

struct payload_host_state_block
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 abi_version;
    payload_u64 flags;
    payload_u64 stage;
    payload_u64 generation;
    payload_u64 image_base;
    payload_u64 image_size;
    payload_u64 runtime_context;
    payload_u64 vmcall_stub;
    payload_u64 hv_ping_count;
    payload_u64 last_hv_pong;
    payload_u64 host_stack_base;
    payload_u64 host_stack_size;
    payload_u64 host_stack_slot_size;
    payload_u64 host_stack_slot_count;
    payload_u64 host_stack_desc_base;
    payload_u64 host_stack_desc_count;
    payload_u64 host_stack_first_rsp;
    payload_u64 reserved[13];
};

static payload_runtime_context g_runtime = {
    PAYLOAD_RUNTIME_MAGIC,
    sizeof(payload_runtime_context),
    0,
    PAYLOAD_RUNTIME_OWNER_NONE,
    PAYLOAD_RUNTIME_PHASE_ZERO,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    PAYLOAD_EXTERNAL_REF_NONE,
    0,
    0,
    0,
    0,
    0,
    PAYLOAD_RESULT_OK,
};

extern "C" NTSTATUS PayloadResidentDriverInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
extern "C" payload_u64 PayloadGetStatus(void* status_out);
extern "C" payload_u64 PayloadPing(payload_u64 nonce);
static NTSTATUS PayloadResidentCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS PayloadResidentDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static void PayloadDeleteResidentControl();
static void PayloadMemcheckControl(mapctl_memcheck* req);

static payload_host_api* PayloadHostApi()
{
    auto api = (payload_host_api*)g_host_api;
    if (!api || api->magic != PAYLOAD_API_MAGIC || api->size < sizeof(payload_host_api))
        return nullptr;
    return api;
}

static void* PayloadHostAlloc(payload_u64 size, payload_u64 tag)
{
    auto api = PayloadHostApi();
    if (!api || !(api->flags & PAYLOAD_HOST_API_FLAG_ALLOC) || !api->alloc)
        return nullptr;
    return api->alloc(size, tag);
}

static void PayloadHostFree(void* ptr)
{
    auto api = PayloadHostApi();
    if (api && (api->flags & PAYLOAD_HOST_API_FLAG_FREE) && api->free)
        api->free(ptr);
}

static void* PayloadHostResolveRoutine(payload_host_api* api, const unsigned short* name)
{
    if (!api ||
        api->magic != PAYLOAD_API_MAGIC ||
        api->size < sizeof(payload_host_api) ||
        !(api->flags & PAYLOAD_HOST_API_FLAG_RESOLVE) ||
        !api->resolve_system_routine ||
        !name)
    {
        return nullptr;
    }

    return api->resolve_system_routine(name);
}

static bool PayloadResolveWorkerRoutines(payload_host_api* api)
{
    static const unsigned short kPsCreateSystemThread[] = {
        'P','s','C','r','e','a','t','e','S','y','s','t','e','m','T','h','r','e','a','d',0
    };
    static const unsigned short kPsTerminateSystemThread[] = {
        'P','s','T','e','r','m','i','n','a','t','e','S','y','s','t','e','m','T','h','r','e','a','d',0
    };
    static const unsigned short kZwWaitForSingleObject[] = {
        'Z','w','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0
    };
    static const unsigned short kZwClose[] = {
        'Z','w','C','l','o','s','e',0
    };
    static const unsigned short kKeDelayExecutionThread[] = {
        'K','e','D','e','l','a','y','E','x','e','c','u','t','i','o','n','T','h','r','e','a','d',0
    };
    static const unsigned short kKeSetSystemAffinityThreadEx[] = {
        'K','e','S','e','t','S','y','s','t','e','m','A','f','f','i','n','i','t','y','T','h','r','e','a','d','E','x',0
    };
    static const unsigned short kKeRevertToUserAffinityThreadEx[] = {
        'K','e','R','e','v','e','r','t','T','o','U','s','e','r','A','f','f','i','n','i','t','y','T','h','r','e','a','d','E','x',0
    };

    g_ps_create_system_thread = (payload_u64)PayloadHostResolveRoutine(api, kPsCreateSystemThread);
    g_ps_terminate_system_thread = (payload_u64)PayloadHostResolveRoutine(api, kPsTerminateSystemThread);
    g_zw_wait_for_single_object = (payload_u64)PayloadHostResolveRoutine(api, kZwWaitForSingleObject);
    g_zw_close = (payload_u64)PayloadHostResolveRoutine(api, kZwClose);
    g_ke_delay_execution_thread = (payload_u64)PayloadHostResolveRoutine(api, kKeDelayExecutionThread);
    g_ke_set_system_affinity_thread_ex = (payload_u64)PayloadHostResolveRoutine(api, kKeSetSystemAffinityThreadEx);
    g_ke_revert_to_user_affinity_thread_ex = (payload_u64)PayloadHostResolveRoutine(api, kKeRevertToUserAffinityThreadEx);

    return g_ps_create_system_thread &&
        g_ps_terminate_system_thread &&
        g_zw_wait_for_single_object &&
        g_zw_close &&
        g_ke_delay_execution_thread;
}

static bool PayloadResolveBugcheckRoutine(payload_host_api* api)
{
    static const unsigned short kKeBugCheckEx[] = {
        'K','e','B','u','g','C','h','e','c','k','E','x',0
    };

    g_ke_bug_check_ex = (payload_u64)PayloadHostResolveRoutine(api, kKeBugCheckEx);
    return g_ke_bug_check_ex != 0;
}

static bool PayloadResolveIoRoutines(payload_host_api* api)
{
    static const unsigned short kIoCreateDriver[] = {
        'I','o','C','r','e','a','t','e','D','r','i','v','e','r',0
    };
    static const unsigned short kIoCreateDevice[] = {
        'I','o','C','r','e','a','t','e','D','e','v','i','c','e',0
    };
    static const unsigned short kIoCreateSymbolicLink[] = {
        'I','o','C','r','e','a','t','e','S','y','m','b','o','l','i','c','L','i','n','k',0
    };
    static const unsigned short kIoDeleteSymbolicLink[] = {
        'I','o','D','e','l','e','t','e','S','y','m','b','o','l','i','c','L','i','n','k',0
    };
    static const unsigned short kIoDeleteDevice[] = {
        'I','o','D','e','l','e','t','e','D','e','v','i','c','e',0
    };
    static const unsigned short kIofCompleteRequest[] = {
        'I','o','f','C','o','m','p','l','e','t','e','R','e','q','u','e','s','t',0
    };

    g_io_create_driver = (payload_u64)PayloadHostResolveRoutine(api, kIoCreateDriver);
    g_io_create_device = (payload_u64)PayloadHostResolveRoutine(api, kIoCreateDevice);
    g_io_create_symbolic_link = (payload_u64)PayloadHostResolveRoutine(api, kIoCreateSymbolicLink);
    g_io_delete_symbolic_link = (payload_u64)PayloadHostResolveRoutine(api, kIoDeleteSymbolicLink);
    g_io_delete_device = (payload_u64)PayloadHostResolveRoutine(api, kIoDeleteDevice);
    g_io_complete_request = (payload_u64)PayloadHostResolveRoutine(api, kIofCompleteRequest);

    return g_io_create_driver &&
        g_io_create_device &&
        g_io_create_symbolic_link &&
        g_io_delete_symbolic_link &&
        g_io_delete_device &&
        g_io_complete_request;
}

static payload_u64 PayloadAlignUp(payload_u64 value, payload_u64 align)
{
    if (!align)
        return value;
    return (value + align - 1) & ~(align - 1);
}

static void PayloadZeroMemory(void* ptr, payload_u64 size)
{
    if (!ptr || !size)
        return;

    volatile unsigned char* p = (volatile unsigned char*)ptr;
    for (payload_u64 i = 0; i < size; ++i)
        p[i] = 0;
}

static void PayloadCopyMemory(void* dst, const void* src, payload_u64 size)
{
    if (!dst || !src || !size)
        return;

    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (payload_u64 i = 0; i < size; ++i)
        d[i] = s[i];
}

static void* PayloadArenaAlloc(payload_u64 size, payload_u64 align)
{
    if (!g_arena_base || !g_arena_size || !size)
        return nullptr;

    payload_u64 current = PayloadAlignUp(g_arena_used, align ? align : 16);
    if (current > g_arena_size || size > (g_arena_size - current))
        return nullptr;

    g_arena_used = current + size;
    return (void*)(g_arena_base + current);
}

static void* PayloadDirectAlloc(payload_u64 size, ULONG protection)
{
    if (!size || size > 0x7FFFFFFFull)
        return nullptr;

#if !PAYLOAD_FORCE_HOST_POOL_ALLOC
    if (g_mm_allocate_independent_pages &&
        g_mm_free_independent_pages &&
        g_mm_set_page_protection)
    {
        auto alloc_pages = (payload_mm_allocate_independent_pages_fn)g_mm_allocate_independent_pages;
        auto free_pages = (payload_mm_free_independent_pages_fn)g_mm_free_independent_pages;
        auto protect_pages = (payload_mm_set_page_protection_fn)g_mm_set_page_protection;

        void* block = alloc_pages((SIZE_T)size, MAXULONG64);
        if (!block)
            return nullptr;

        if (!protect_pages(block, (SIZE_T)size, protection))
        {
            free_pages(block, (SIZE_T)size);
            return nullptr;
        }

        PayloadZeroMemory(block, size);
        return block;
    }

    return nullptr;
#else
    if (g_host_alloc_fn && g_host_free_fn)
    {
        UNREFERENCED_PARAMETER(protection);
        auto host_alloc = (payload_host_alloc_fn)g_host_alloc_fn;
        void* block = host_alloc(size, 0x504C4441ull); // PLDA
        if (!block)
            return nullptr;

        PayloadZeroMemory(block, size);
        return block;
    }

    return nullptr;
#endif
}

static void PayloadDirectFree(void* ptr, payload_u64 size)
{
    if (!ptr || !size)
        return;

    PayloadZeroMemory(ptr, size);

#if !PAYLOAD_FORCE_HOST_POOL_ALLOC
    if (g_mm_allocate_independent_pages &&
        g_mm_free_independent_pages &&
        g_mm_set_page_protection)
    {
        auto free_pages = (payload_mm_free_independent_pages_fn)g_mm_free_independent_pages;
        free_pages(ptr, (SIZE_T)size);
        return;
    }

    return;
#else
    if (g_host_free_fn)
    {
        auto host_free = (payload_host_free_fn)g_host_free_fn;
        host_free(ptr);
        return;
    }
#endif
}

static void* PayloadOwnedAlloc(payload_u64 size, ULONG protection, payload_u64* actual_size)
{
    if (actual_size)
        *actual_size = 0;
    if (!size)
        return nullptr;

    payload_u64 aligned_size = PayloadAlignUp(size, PAGE_SIZE);
    if (!aligned_size || aligned_size < size)
        return nullptr;

    void* block = PayloadDirectAlloc(aligned_size, protection);
    if (!block)
        return nullptr;

    g_owned_alloc_count++;
    g_owned_alloc_bytes += aligned_size;
    g_runtime.owned_alloc_count = g_owned_alloc_count;
    g_runtime.owned_alloc_bytes = g_owned_alloc_bytes;

    if (actual_size)
        *actual_size = aligned_size;
    return block;
}

static payload_u64 PayloadEnsureSelfAllocation()
{
    if (g_direct_alloc_base && g_direct_alloc_size)
        return PAYLOAD_RESULT_OK;

    constexpr payload_u64 kSelfBlockSize = PAGE_SIZE;
    void* block = PayloadDirectAlloc(kSelfBlockSize, PAGE_READWRITE);
    if (!block)
        return PAYLOAD_RESULT_ALLOC_FAILED;

    g_direct_alloc_base = (payload_u64)block;
    g_direct_alloc_size = kSelfBlockSize;
    g_owned_alloc_count = 1;
    g_owned_alloc_bytes = kSelfBlockSize;
    return PAYLOAD_RESULT_OK;
}

static payload_u64 PayloadEnsureHostStackSlab()
{
    if (g_host_stack_base && g_host_stack_size)
        return PAYLOAD_RESULT_OK;

    constexpr payload_u64 kStackSlabSize = PAYLOAD_HOST_STACK_SLAB_SIZE;
    void* block = PayloadDirectAlloc(kStackSlabSize, PAGE_READWRITE);
    if (!block)
        return PAYLOAD_RESULT_ALLOC_FAILED;

    g_host_stack_base = (payload_u64)block;
    g_host_stack_size = kStackSlabSize;
    g_host_stack_slot_size = PAYLOAD_HOST_STACK_SLOT_SIZE;
    g_host_stack_slot_count = PAYLOAD_HOST_STACK_SLOT_COUNT;
    g_owned_alloc_count++;
    g_owned_alloc_bytes += kStackSlabSize;
    return PAYLOAD_RESULT_OK;
}

static payload_u64 PayloadPrepareHostStackDescriptors()
{
    if (!g_direct_alloc_base ||
        g_direct_alloc_size < PAGE_SIZE ||
        !g_host_stack_base ||
        !g_host_stack_size ||
        !g_host_stack_slot_size ||
        !g_host_stack_slot_count)
    {
        return PAYLOAD_RESULT_ALLOC_FAILED;
    }

    payload_u64 desc_offset = PayloadAlignUp(sizeof(payload_host_state_block), 16);
    payload_u64 desc_bytes = sizeof(payload_host_stack_descriptor) * g_host_stack_slot_count;
    if (desc_offset > g_direct_alloc_size || desc_bytes > (g_direct_alloc_size - desc_offset))
        return PAYLOAD_RESULT_ALLOC_FAILED;

    auto desc = (payload_host_stack_descriptor*)(g_direct_alloc_base + desc_offset);
    PayloadZeroMemory(desc, desc_bytes);

    for (payload_u64 i = 0; i < g_host_stack_slot_count; ++i)
    {
        payload_u64 base = g_host_stack_base + (i * g_host_stack_slot_size);
        payload_u64 limit = base + g_host_stack_slot_size;
        payload_u64 initial_rsp = (limit & ~0xFull) - 8;

        desc[i].index = i;
        desc[i].stack_base = base;
        desc[i].stack_limit = limit;
        desc[i].initial_rsp = initial_rsp;
        desc[i].flags = 1;
        desc[i].old_rsp = 0;
        desc[i].last_rsp = initial_rsp;
    }

    g_host_stack_desc_base = (payload_u64)desc;
    g_host_stack_desc_count = g_host_stack_slot_count;
    g_host_stack_first_rsp = desc[0].initial_rsp;
    g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_STACK_DESC_READY;
    return PAYLOAD_RESULT_OK;
}

static void PayloadReleaseSelfAllocation()
{
    void* stack_block = (void*)g_host_stack_base;
    payload_u64 stack_size = g_host_stack_size;
    void* block = (void*)g_direct_alloc_base;
    payload_u64 size = g_direct_alloc_size;

    g_host_state_base = 0;
    g_host_state_size = 0;
    g_host_state_flags = 0;
    g_host_state_stage = 0;
    g_host_state_hv_pings = 0;
    g_host_state_last_hv = 0;
    g_host_stack_base = 0;
    g_host_stack_size = 0;
    g_host_stack_slot_size = 0;
    g_host_stack_slot_count = 0;
    g_host_stack_desc_base = 0;
    g_host_stack_desc_count = 0;
    g_host_stack_first_rsp = 0;
    g_host_stack_mapped_in_host = 0;

    if (stack_block && stack_size)
        PayloadDirectFree(stack_block, stack_size);

    if (block && size)
        PayloadDirectFree(block, size);

    g_direct_alloc_base = 0;
    g_direct_alloc_size = 0;
    g_owned_alloc_count = 0;
    g_owned_alloc_bytes = 0;
}

static payload_host_state_block* PayloadHostState()
{
    auto block = (payload_host_state_block*)g_host_state_base;
    if (!block ||
        g_host_state_size < sizeof(payload_host_state_block) ||
        block->magic != PAYLOAD_HOST_STATE_MAGIC ||
        block->size < sizeof(payload_host_state_block))
    {
        return nullptr;
    }
    return block;
}

static payload_u64 PayloadPrepareHostState()
{
    if (!g_direct_alloc_base || g_direct_alloc_size < sizeof(payload_host_state_block))
        return PAYLOAD_RESULT_ALLOC_FAILED;

    auto block = (payload_host_state_block*)g_direct_alloc_base;
    PayloadZeroMemory(block, sizeof(*block));

    g_host_state_base = (payload_u64)block;
    g_host_state_size = sizeof(*block);
    g_host_state_flags =
        PAYLOAD_HOST_STATE_FLAG_READY |
        PAYLOAD_HOST_STATE_FLAG_DIRECT_BLOCK;
    g_host_state_stage = PAYLOAD_HOST_STATE_STAGE_PREPARED;
    g_host_state_hv_pings = 0;
    g_host_state_last_hv = 0;

    block->magic = PAYLOAD_HOST_STATE_MAGIC;
    block->size = sizeof(*block);
    block->abi_version = PAYLOAD_ABI_VERSION;
    block->flags = g_host_state_flags;
    block->stage = g_host_state_stage;
    block->generation = g_runtime.generation + 1;
    block->image_base = g_image_base;
    block->image_size = g_image_size;
    block->runtime_context = (payload_u64)&g_runtime;
    block->vmcall_stub = (payload_u64)&PayloadVmxVmcall;
    block->hv_ping_count = g_host_state_hv_pings;
    block->last_hv_pong = g_host_state_last_hv;
    block->host_stack_base = g_host_stack_base;
    block->host_stack_size = g_host_stack_size;
    block->host_stack_slot_size = g_host_stack_slot_size;
    block->host_stack_slot_count = g_host_stack_slot_count;
    block->host_stack_desc_base = g_host_stack_desc_base;
    block->host_stack_desc_count = g_host_stack_desc_count;
    block->host_stack_first_rsp = g_host_stack_first_rsp;

    g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_HOST_STATE_READY;
    if (g_host_stack_base && g_host_stack_size)
        g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_HOST_STACK_READY;
    if (g_host_stack_desc_base && g_host_stack_desc_count)
        g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_STACK_DESC_READY;
    return PAYLOAD_RESULT_OK;
}

static payload_u64 PayloadStateFlags()
{
    payload_u64 flags = PAYLOAD_STATE_READY;
    if (g_started)
        flags |= PAYLOAD_STATE_STARTED;
    else if (g_stop_count)
        flags |= PAYLOAD_STATE_STOPPED;
    return flags;
}

static payload_u64 PayloadWideLength(const WCHAR* text)
{
    payload_u64 len = 0;
    if (!text)
        return 0;
    while (text[len])
        ++len;
    return len;
}

static void PayloadInitUnicodeString(PUNICODE_STRING out, WCHAR* text)
{
    if (!out)
        return;

    payload_u64 chars = PayloadWideLength(text);
    out->Buffer = text;
    out->Length = (USHORT)(chars * sizeof(WCHAR));
    out->MaximumLength = (USHORT)((chars + 1) * sizeof(WCHAR));
}

static bool PayloadBarrierReadyLocal(const payload_status* status)
{
    if (!status || status->magic != PAYLOAD_STATUS_MAGIC)
        return false;

    payload_u64 required =
        PAYLOAD_RUNTIME_FLAG_STARTED |
        PAYLOAD_RUNTIME_FLAG_ARENA_READY |
        PAYLOAD_RUNTIME_FLAG_KERNEL_API_READY |
        PAYLOAD_RUNTIME_FLAG_BOOTSTRAP_SEALED |
        PAYLOAD_RUNTIME_FLAG_DIRECT_ALLOC_READY |
        PAYLOAD_RUNTIME_FLAG_SELF_ALLOC_READY |
        PAYLOAD_RUNTIME_FLAG_WORKER_API_READY |
        PAYLOAD_RUNTIME_FLAG_HOST_STATE_READY |
        PAYLOAD_RUNTIME_FLAG_HOST_STACK_READY |
        PAYLOAD_RUNTIME_FLAG_STACK_DESC_READY;

    return status->independent &&
        status->external_ref_flags == PAYLOAD_EXTERNAL_REF_NONE &&
        status->host_api == 0 &&
        (status->runtime_flags & required) == required &&
        status->runtime_owner == PAYLOAD_RUNTIME_OWNER_PAYLOAD &&
        status->runtime_phase == PAYLOAD_RUNTIME_PHASE_STARTED;
}

static payload_u64 PayloadHvPingRaw()
{
    payload_hypercall_input input = {};
    input.flags = (PAYLOAD_HYPERCALL_KEY << 8) | PAYLOAD_HYPERCALL_PING;
    payload_u64 pong = PayloadVmxVmcall(&input);

    g_host_state_hv_pings++;
    g_host_state_last_hv = pong;

    auto block = PayloadHostState();
    if (block)
    {
        block->hv_ping_count = g_host_state_hv_pings;
        block->last_hv_pong = pong;
        block->generation++;
    }

    return pong;
}

static payload_u64 PayloadHvDiagRaw(mapctl_hv_diag* out)
{
    if (!out)
        return 0;

    payload_hypercall_input input = {};
    input.flags = (PAYLOAD_HYPERCALL_KEY << 8) | PAYLOAD_HYPERCALL_GET_RESIDENT_HV_DIAG;
    input.args[0] = (payload_u64)out;
    input.args[1] = sizeof(*out);
    return PayloadVmxVmcall(&input);
}

static payload_u64 PayloadHvSetHostRspRaw(payload_u64 new_rsp)
{
    payload_hypercall_input input = {};
    input.flags = (PAYLOAD_HYPERCALL_KEY << 8) | PAYLOAD_HYPERCALL_SET_HOST_RSP;
    input.args[0] = new_rsp;
    return PayloadVmxVmcall(&input);
}

static payload_u64 PayloadHvSetHostRipRaw(payload_u64 new_rip)
{
    payload_hypercall_input input = {};
    input.flags = (PAYLOAD_HYPERCALL_KEY << 8) | PAYLOAD_HYPERCALL_SET_HOST_RIP;
    input.args[0] = new_rip;
    return PayloadVmxVmcall(&input);
}

static bool PayloadHvMapHostRangeRaw(payload_u64 va, payload_u64 bytes)
{
    if (!va || !bytes)
        return false;

    payload_hypercall_input input = {};
    input.flags = (PAYLOAD_HYPERCALL_KEY << 8) | PAYLOAD_HYPERCALL_MAP_HOST_RANGE;
    input.args[0] = va;
    input.args[1] = bytes;
    return PayloadVmxVmcall(&input) != 0;
}

static void PayloadMemcheckControl(mapctl_memcheck* req)
{
    if (!req)
        return;

    payload_u64 flags = req->flags;
    if (!flags)
        flags = MAPCTL_MEMCHECK_FLAG_DATA_DEFAULT;
    payload_u64 max_pages = req->max_pages;
    payload_u64 cursor_kind = req->cursor_kind;
    payload_u64 cursor_index = req->cursor_index;
    payload_u64 cursor_page = req->cursor_page;

    PayloadZeroMemory(req, sizeof(*req));
    req->magic = MAPCTL_MEMCHECK_MAGIC;
    req->size = sizeof(*req);
    req->flags = flags;
    req->max_pages = max_pages;
    req->cursor_kind = cursor_kind;
    req->cursor_index = cursor_index;
    req->cursor_page = cursor_page;
    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;

    payload_hypercall_input input = {};
    input.flags = (PAYLOAD_HYPERCALL_KEY << 8) | PAYLOAD_HYPERCALL_VERIFY_HIDE_PFN_LIST;
    input.args[0] = (payload_u64)req;
    input.args[1] = sizeof(*req);

    payload_u64 result = PayloadVmxVmcall(&input);
    if (result != PAYLOAD_RESULT_OK && req->result == PAYLOAD_RESULT_INVALID_CONTEXT)
        req->result = result ? result : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void PayloadFillMapStatus(mapctl_status* out)
{
    if (!out)
        return;

    PayloadZeroMemory(out, sizeof(*out));
    out->magic = MAPCTL_STATUS_MAGIC;
    // Resident payload deliberately does not VMCALL during passive status:
    // when HV is absent, VMCALL would fault and the manually mapped image has
    // no registered unwind/SEH table. RawPack v2 resolves its IAT before entry.
    // Use MAPCTL_IOCTL_HV_PING explicitly when the test expects VT to be live.
    out->hv_ready = 0;
    out->payload_detached = 1;
    // The resident control path is normally reached only after mapDriver's
    // control device has been dropped.  From this path TestDriver is no longer
    // owned by mapDriver; report it as detached/quarantined while keeping the
    // last payload-observed TestDriver base useful for status diagnostics.
    out->test_unloaded = 1;
    out->test_quarantined = 1;
    out->payload_base = g_image_base;
    out->payload_size = g_image_size;
    out->payload_exports = (payload_u64)0;
    if (PayloadGetStatus(&out->payload) == PAYLOAD_RESULT_OK)
    {
        out->test_base = out->payload.payload_gamevt_image_base;
        out->payload_base = out->payload.image_base;
        out->payload_size = out->payload.image_size;
        out->payload_independent = out->payload.independent;
        out->payload_external_refs = out->payload.external_ref_flags;
        out->payload_barrier_ok = PayloadBarrierReadyLocal(&out->payload) ? 1 : 0;
    }
}

static void PayloadFillMigrationCheck(mapctl_migration_check* out)
{
    if (!out)
        return;

    PayloadZeroMemory(out, sizeof(*out));
    out->magic = MAPCTL_MIGRATE_CHECK_MAGIC;
    out->size = sizeof(*out);

    if (PayloadGetStatus(&out->payload) == PAYLOAD_RESULT_OK &&
        out->payload.magic == PAYLOAD_STATUS_MAGIC &&
        PayloadBarrierReadyLocal(&out->payload))
    {
        out->flags |= MAPCTL_MIGRATE_CHECK_PAYLOAD_READY;
    }

    payload_u64 copied = PayloadHvDiagRaw(&out->diag);
    if (copied >= sizeof(out->diag) && out->diag.magic == MAPCTL_HV_DIAG_MAGIC)
    {
        out->flags |= MAPCTL_MIGRATE_CHECK_HV_DIAG_READY;

        if (out->diag.vmcs_host_rip && out->diag.vmcs_host_rip == out->diag.vm_exit)
            out->flags |= MAPCTL_MIGRATE_CHECK_OLD_RIP_IS_VMEXIT;

        if (out->payload.vmexit_trampoline &&
            out->diag.vmcs_host_rip == out->payload.vmexit_trampoline)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_TRAMP;
        }

        if (out->payload.vmexit_bridge &&
            out->diag.vmcs_host_rip == out->payload.vmexit_bridge)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_BRIDGE;
        }

        if (out->diag.current_host_stack &&
            out->diag.host_stack_size &&
            out->diag.vmcs_host_rsp >= out->diag.current_host_stack &&
            out->diag.vmcs_host_rsp < (out->diag.current_host_stack + out->diag.host_stack_size))
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_OLD_RSP_IN_STACK;
        }

        if (out->payload.host_stack_base &&
            out->payload.host_stack_size &&
            out->payload.host_stack_desc_base &&
            out->payload.host_stack_desc_count &&
            out->payload.host_stack_first_rsp >= out->payload.host_stack_base &&
            out->payload.host_stack_first_rsp < (out->payload.host_stack_base + out->payload.host_stack_size))
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_PAYLOAD_STACK_READY;
        }

        if (out->payload.host_stack_base &&
            out->payload.host_stack_size &&
            out->diag.vmcs_host_rsp >= out->payload.host_stack_base &&
            out->diag.vmcs_host_rsp < (out->payload.host_stack_base + out->payload.host_stack_size))
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD;
        }

        if (out->diag.vcpu_count && out->payload.host_stack_desc_count &&
            out->diag.vcpu_count <= out->payload.host_stack_desc_count)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_VCPU_COUNT_FITS;
        }

        if (out->payload.vmexit_trampoline &&
            out->payload.vmexit_target &&
            out->payload.vmexit_target == out->diag.vm_exit)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_VMEXIT_TRAMP_READY;
        }

        if (out->payload.vmexit_bridge &&
            out->payload.vmexit_bridge_target &&
            out->diag.handle_vm_exit &&
            out->payload.vmexit_bridge_target == out->diag.handle_vm_exit)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_VMEXIT_BRIDGE_READY;
        }
    }

    payload_u64 required =
        MAPCTL_MIGRATE_CHECK_PAYLOAD_READY |
        MAPCTL_MIGRATE_CHECK_HV_DIAG_READY |
        MAPCTL_MIGRATE_CHECK_PAYLOAD_STACK_READY |
        MAPCTL_MIGRATE_CHECK_VCPU_COUNT_FITS |
        MAPCTL_MIGRATE_CHECK_VMEXIT_TRAMP_READY;

    bool rip_ok = (out->flags & (MAPCTL_MIGRATE_CHECK_OLD_RIP_IS_VMEXIT | MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_TRAMP | MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_BRIDGE)) != 0;
    bool rsp_ok = (out->flags & (MAPCTL_MIGRATE_CHECK_OLD_RSP_IN_STACK | MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD)) != 0;
    out->result = (((out->flags & required) == required) && rip_ok && rsp_ok)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static bool PayloadAffinityReady()
{
    return g_ke_set_system_affinity_thread_ex &&
        g_ke_revert_to_user_affinity_thread_ex;
}

static void PayloadSwitchHostRsp(mapctl_host_rsp_switch* req, bool restore)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->switched_count = 0;
    req->failed_index = ~0ull;
    req->last_new_rsp = 0;
    req->last_old_rsp = 0;

    if (req->magic != MAPCTL_HOST_RSP_SWITCH_MAGIC ||
        req->size < sizeof(mapctl_host_rsp_switch) ||
        req->arm != MAPCTL_HOST_RSP_SWITCH_ARM ||
        !PayloadAffinityReady())
    {
        return;
    }

    payload_status* ps = &g_payload_control_status_scratch;
    if (PayloadGetStatus(ps) != PAYLOAD_RESULT_OK ||
        ps->magic != PAYLOAD_STATUS_MAGIC ||
        (!restore && !PayloadBarrierReadyLocal(ps)) ||
        !ps->host_stack_desc_base ||
        !ps->host_stack_desc_count)
    {
        return;
    }

    mapctl_hv_diag diag = {};
    payload_u64 copied = PayloadHvDiagRaw(&diag);
    if (copied < sizeof(diag) || diag.magic != MAPCTL_HV_DIAG_MAGIC || !diag.vcpu_count)
        return;

    auto desc = (payload_host_stack_descriptor*)ps->host_stack_desc_base;
    payload_u64 count = diag.vcpu_count;
    if (count > ps->host_stack_desc_count)
        count = ps->host_stack_desc_count;
    if (count > 64)
        count = 64;

    req->requested_count = count;

    // Mapping the payload stack slab into HOST_CR3 is required before HOST_RSP
    // points at it, but repeatedly replaying map_host_range after the bridge is
    // active can still forward into the old TestDriver handler.  Treat this as
    // a one-time barrier for the resident lifetime; later re-arms only rewrite
    // HOST_RSP and preserve the first observed old_rsp for a real restore.
    if (!restore && !g_host_stack_mapped_in_host)
    {
        if (!PayloadHvMapHostRangeRaw(ps->host_stack_base, ps->host_stack_size))
            return;
        g_host_stack_mapped_in_host = 1;
    }

    auto set_affinity = (payload_ke_set_system_affinity_thread_ex_fn)g_ke_set_system_affinity_thread_ex;
    auto revert_affinity = (payload_ke_revert_to_user_affinity_thread_ex_fn)g_ke_revert_to_user_affinity_thread_ex;

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 target_rsp = restore ? desc[i].old_rsp : desc[i].initial_rsp;
        bool already_switched = !restore && ((desc[i].flags & 2ull) != 0) && desc[i].old_rsp;
        req->last_new_rsp = target_rsp;

        if (!target_rsp ||
            (!restore &&
                (target_rsp < ps->host_stack_base ||
                 target_rsp >= (ps->host_stack_base + ps->host_stack_size))))
        {
            req->failed_index = i;
            return;
        }

        KAFFINITY old_affinity = set_affinity((KAFFINITY)(1ull << i));
        payload_u64 previous_rsp = PayloadHvSetHostRspRaw(target_rsp);
        revert_affinity(old_affinity);

        req->last_old_rsp = previous_rsp;
        if (!previous_rsp)
        {
            req->failed_index = i;
            return;
        }

        if (restore)
        {
            desc[i].last_rsp = target_rsp;
            desc[i].flags &= ~2ull;
        }
        else
        {
            // Preserve the original pre-payload HOST_RSP across repeated
            // switch attempts.  A second switch often returns the payload RSP
            // (or a transient vtcall stack) as previous_rsp; overwriting
            // old_rsp with that value destroys the only safe restore target.
            if (!already_switched)
                desc[i].old_rsp = previous_rsp;
            desc[i].last_rsp = target_rsp;
            desc[i].flags |= 2;
        }
        req->switched_count++;
    }

    req->result = (req->switched_count == req->requested_count)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void PayloadSwitchHostRip(mapctl_host_rip_switch* req, bool restore, bool bridge)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->switched_count = 0;
    req->failed_index = ~0ull;
    req->last_new_rip = 0;
    req->last_old_rip = 0;

    if (req->magic != MAPCTL_HOST_RIP_SWITCH_MAGIC ||
        req->size < sizeof(mapctl_host_rip_switch) ||
        req->arm != MAPCTL_HOST_RIP_SWITCH_ARM ||
        !PayloadAffinityReady())
    {
        return;
    }

    payload_status* ps = &g_payload_control_status_scratch;
    if (PayloadGetStatus(ps) != PAYLOAD_RESULT_OK ||
        ps->magic != PAYLOAD_STATUS_MAGIC ||
        (!restore && !PayloadBarrierReadyLocal(ps)) ||
        !ps->host_stack_desc_base ||
        !ps->host_stack_desc_count)
    {
        return;
    }

    if (!restore &&
        (!ps->image_base ||
         !ps->image_size ||
         (!bridge && (!ps->vmexit_trampoline || !ps->vmexit_target)) ||
         (bridge && (!ps->vmexit_bridge || !ps->vmexit_bridge_target))))
    {
        return;
    }

    mapctl_hv_diag diag = {};
    payload_u64 copied = PayloadHvDiagRaw(&diag);
    if (copied < sizeof(diag) || diag.magic != MAPCTL_HV_DIAG_MAGIC || !diag.vcpu_count)
        return;

    if (!restore && !bridge && diag.vm_exit != ps->vmexit_target)
        return;
    if (!restore && bridge && (!diag.handle_vm_exit || diag.handle_vm_exit != ps->vmexit_bridge_target))
        return;

    auto desc = (payload_host_stack_descriptor*)ps->host_stack_desc_base;
    payload_u64 count = diag.vcpu_count;
    if (count > ps->host_stack_desc_count)
        count = ps->host_stack_desc_count;
    if (count > 64)
        count = 64;

    req->requested_count = count;

    if (!restore && !PayloadHvMapHostRangeRaw(ps->image_base, ps->image_size))
        return;

    auto set_affinity = (payload_ke_set_system_affinity_thread_ex_fn)g_ke_set_system_affinity_thread_ex;
    auto revert_affinity = (payload_ke_revert_to_user_affinity_thread_ex_fn)g_ke_revert_to_user_affinity_thread_ex;

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 target_rip = restore ? desc[i].old_rip : (bridge ? ps->vmexit_bridge : ps->vmexit_trampoline);
        req->last_new_rip = target_rip;

        if (!target_rip)
        {
            req->failed_index = i;
            return;
        }

        KAFFINITY old_affinity = set_affinity((KAFFINITY)(1ull << i));
        payload_u64 previous_rip = PayloadHvSetHostRipRaw(target_rip);
        revert_affinity(old_affinity);

        req->last_old_rip = previous_rip;
        if (!previous_rip)
        {
            req->failed_index = i;
            return;
        }

        if (restore)
        {
            desc[i].last_rip = target_rip;
            desc[i].flags &= ~4ull;
            desc[i].flags &= ~8ull;
        }
        else
        {
            desc[i].old_rip = previous_rip;
            desc[i].last_rip = target_rip;
            desc[i].flags |= bridge ? 8 : 4;
        }
        req->switched_count++;
    }

    req->result = (req->switched_count == req->requested_count)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void PayloadVtretModeControl(mapctl_vtret_mode* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_mode = g_payload_vtret_mode;
    req->new_mode = g_payload_vtret_mode;

    if (req->magic != MAPCTL_VTRET_MODE_MAGIC ||
        req->size < sizeof(mapctl_vtret_mode) ||
        req->arm != MAPCTL_VTRET_MODE_ARM)
    {
        return;
    }

    req->result = PayloadSetVtretMode(req->mode);
    req->new_mode = g_payload_vtret_mode;
    PayloadGetStatus(&req->payload);
}

static void PayloadTrampModeControl(mapctl_tramp_mode* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_mode = g_payload_tramp_mode;
    req->new_mode = g_payload_tramp_mode;

    if (req->magic != MAPCTL_TRAMP_MODE_MAGIC ||
        req->size < sizeof(mapctl_tramp_mode) ||
        req->arm != MAPCTL_TRAMP_MODE_ARM)
    {
        return;
    }

    req->result = PayloadSetTrampMode(req->mode);
    req->new_mode = g_payload_tramp_mode;
    PayloadGetStatus(&req->payload);
}

static void PayloadHookModeControl(mapctl_hook_mode* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_mode = g_payload_hook_mode;
    req->new_mode = g_payload_hook_mode;

    if (req->magic != MAPCTL_HOOK_MODE_MAGIC ||
        req->size < sizeof(mapctl_hook_mode) ||
        req->arm != MAPCTL_HOOK_MODE_ARM)
    {
        return;
    }

    req->result = PayloadSetHookMode(req->mode);
    req->new_mode = g_payload_hook_mode;
    PayloadGetStatus(&req->payload);
}

static void PayloadEptModeControl(mapctl_ept_mode* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_mode = g_payload_ept_mode;
    req->new_mode = g_payload_ept_mode;

    if (req->magic != MAPCTL_EPT_MODE_MAGIC ||
        req->size < sizeof(mapctl_ept_mode) ||
        req->arm != MAPCTL_EPT_MODE_ARM)
    {
        return;
    }

    req->result = PayloadSetEptMode(req->mode);
    req->new_mode = g_payload_ept_mode;
    PayloadGetStatus(&req->payload);
}

static void PayloadCutoverControl(mapctl_cutover* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_target = g_payload_vmexit_bridge_target;
    req->new_target = g_payload_vmexit_bridge_target;

    if (req->magic != MAPCTL_CUTOVER_MAGIC ||
        req->size < sizeof(mapctl_cutover) ||
        req->arm != MAPCTL_CUTOVER_ARM)
    {
        return;
    }

    req->result = PayloadSetCutoverMode(req->mode);
    req->new_target = g_payload_vmexit_bridge_target;
    PayloadGetStatus(&req->payload);
}

static void PayloadLegacyDetachControl(mapctl_legacy_detach* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_flags = g_legacy_detach_flags;
    req->new_flags = g_legacy_detach_flags;
    req->ghv_original = g_legacy_ghv_original;
    req->ghv_copy = g_legacy_ghv_copy;
    req->ghv_size = g_legacy_ghv_size;
    req->vt_hook_original = g_legacy_vt_hook_original;
    req->vt_hook_copy = g_legacy_vt_hook_copy;
    req->vt_hook_size = g_legacy_vt_hook_size;
    req->shadow_base = g_legacy_shadow_base;
    req->shadow_size = g_legacy_shadow_size;
    req->shadow_count = g_legacy_shadow_count;
    PayloadZeroMemory(&req->payload, sizeof(req->payload));

    if (req->magic != MAPCTL_LEGACY_DETACH_MAGIC ||
        req->size < sizeof(mapctl_legacy_detach) ||
        req->arm != MAPCTL_LEGACY_DETACH_ARM)
    {
        return;
    }

    req->result = PayloadDetachLegacyData(req->mode);
    req->new_flags = g_legacy_detach_flags;
    req->ghv_original = g_legacy_ghv_original;
    req->ghv_copy = g_legacy_ghv_copy;
    req->ghv_size = g_legacy_ghv_size;
    req->vt_hook_original = g_legacy_vt_hook_original;
    req->vt_hook_copy = g_legacy_vt_hook_copy;
    req->vt_hook_size = g_legacy_vt_hook_size;
    req->shadow_base = g_legacy_shadow_base;
    req->shadow_size = g_legacy_shadow_size;
    req->shadow_count = g_legacy_shadow_count;
    PayloadGetStatus(&req->payload);
}

static NTSTATUS PayloadCompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR information)
{
    if (!Irp)
        return status;

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;

    auto complete_request = (payload_io_complete_request_fn)g_io_complete_request;
    if (complete_request)
        complete_request(Irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS PayloadResidentCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return PayloadCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS PayloadResidentDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    auto stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG in_len = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
    auto buffer = Irp->AssociatedIrp.SystemBuffer;

    switch (code)
    {
    case MAPCTL_IOCTL_STATUS:
        if (buffer && out_len >= sizeof(payload_u64))
        {
            auto st = &g_payload_control_map_status_scratch;
            PayloadZeroMemory(st, sizeof(*st));
            PayloadFillMapStatus(st);
            ULONG copy_len = out_len < sizeof(*st) ? out_len : sizeof(*st);
            PayloadZeroMemory(buffer, out_len);
            PayloadCopyMemory(buffer, st, copy_len);
            information = copy_len;
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_PAYLOAD_PING:
        if (buffer && in_len >= sizeof(mapctl_ping) && out_len >= sizeof(mapctl_ping))
        {
            auto ping = (mapctl_ping*)buffer;
            ping->pong = PayloadPing(ping->nonce);
            ping->result = (ping->pong == (ping->nonce ^ PAYLOAD_PONG_MAGIC))
                ? PAYLOAD_RESULT_OK
                : PAYLOAD_RESULT_INVALID_CONTEXT;
            information = sizeof(*ping);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HV_PING:
        if (buffer && in_len >= sizeof(mapctl_ping) && out_len >= sizeof(mapctl_ping))
        {
            auto ping = (mapctl_ping*)buffer;
            ping->pong = PayloadHvPingRaw();
            ping->result = (ping->pong == PAYLOAD_HYPERVISOR_SIGNATURE)
                ? PAYLOAD_RESULT_OK
                : PAYLOAD_RESULT_INVALID_CONTEXT;
            information = sizeof(*ping);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HV_DIAG:
        if (buffer && out_len >= sizeof(mapctl_hv_diag))
        {
            auto diag = (mapctl_hv_diag*)buffer;
            PayloadZeroMemory(diag, sizeof(*diag));
            payload_u64 copied = PayloadHvDiagRaw(diag);
            if (copied >= sizeof(*diag) && diag->magic == MAPCTL_HV_DIAG_MAGIC)
            {
                information = sizeof(*diag);
                status = STATUS_SUCCESS;
            }
            else
            {
                status = STATUS_DEVICE_NOT_READY;
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_MIGRATE_CHECK:
        if (buffer && out_len >= sizeof(mapctl_migration_check))
        {
            auto check = (mapctl_migration_check*)buffer;
            PayloadFillMigrationCheck(check);
            information = sizeof(*check);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_RSP_SWITCH:
        if (buffer && in_len >= sizeof(mapctl_host_rsp_switch) && out_len >= sizeof(mapctl_host_rsp_switch))
        {
            auto req = (mapctl_host_rsp_switch*)buffer;
            PayloadSwitchHostRsp(req, false);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_RSP_RESTORE:
        if (buffer && in_len >= sizeof(mapctl_host_rsp_switch) && out_len >= sizeof(mapctl_host_rsp_switch))
        {
            auto req = (mapctl_host_rsp_switch*)buffer;
            PayloadSwitchHostRsp(req, true);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_RIP_SWITCH:
        if (buffer && in_len >= sizeof(mapctl_host_rip_switch) && out_len >= sizeof(mapctl_host_rip_switch))
        {
            auto req = (mapctl_host_rip_switch*)buffer;
            PayloadSwitchHostRip(req, false, false);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_RIP_RESTORE:
        if (buffer && in_len >= sizeof(mapctl_host_rip_switch) && out_len >= sizeof(mapctl_host_rip_switch))
        {
            auto req = (mapctl_host_rip_switch*)buffer;
            PayloadSwitchHostRip(req, true, false);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_BRIDGE_SWITCH:
        if (buffer && in_len >= sizeof(mapctl_host_rip_switch) && out_len >= sizeof(mapctl_host_rip_switch))
        {
            auto req = (mapctl_host_rip_switch*)buffer;
            PayloadSwitchHostRip(req, false, true);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_BRIDGE_RESTORE:
        if (buffer && in_len >= sizeof(mapctl_host_rip_switch) && out_len >= sizeof(mapctl_host_rip_switch))
        {
            auto req = (mapctl_host_rip_switch*)buffer;
            PayloadSwitchHostRip(req, true, true);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_VTRET_MODE:
        if (buffer && in_len >= sizeof(mapctl_vtret_mode) && out_len >= sizeof(mapctl_vtret_mode))
        {
            auto req = (mapctl_vtret_mode*)buffer;
            PayloadVtretModeControl(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_TRAMP_MODE:
        if (buffer && in_len >= sizeof(mapctl_tramp_mode) && out_len >= sizeof(mapctl_tramp_mode))
        {
            auto req = (mapctl_tramp_mode*)buffer;
            PayloadTrampModeControl(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOOK_MODE:
        if (buffer && in_len >= sizeof(mapctl_hook_mode) && out_len >= sizeof(mapctl_hook_mode))
        {
            auto req = (mapctl_hook_mode*)buffer;
            PayloadHookModeControl(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_EPT_MODE:
        if (buffer && in_len >= sizeof(mapctl_ept_mode) && out_len >= sizeof(mapctl_ept_mode))
        {
            auto req = (mapctl_ept_mode*)buffer;
            PayloadEptModeControl(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_CUTOVER:
        if (buffer && in_len >= sizeof(mapctl_cutover) && out_len >= sizeof(mapctl_cutover))
        {
            auto req = (mapctl_cutover*)buffer;
            PayloadCutoverControl(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_LEGACY_DETACH:
        if (buffer && in_len >= sizeof(mapctl_legacy_detach) && out_len >= sizeof(mapctl_legacy_detach))
        {
            auto req = (mapctl_legacy_detach*)buffer;
            PayloadLegacyDetachControl(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_MEMCHECK:
        if (buffer && in_len >= sizeof(mapctl_memcheck) && out_len >= sizeof(mapctl_memcheck))
        {
            auto req = (mapctl_memcheck*)buffer;
            PayloadMemcheckControl(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    return PayloadCompleteIrp(Irp, status, information);
}

static void PayloadDeleteResidentControl()
{
#if PAYLOAD_RESIDENT_CTL_ENABLED
    if (g_resident_symlink.Buffer && g_io_delete_symbolic_link)
    {
        auto delete_symbolic_link = (payload_io_delete_symbolic_link_fn)g_io_delete_symbolic_link;
        delete_symbolic_link(&g_resident_symlink);
    }

    if (g_resident_device_object && g_io_delete_device)
    {
        auto delete_device = (payload_io_delete_device_fn)g_io_delete_device;
        delete_device(g_resident_device_object);
    }

    g_resident_device_object = nullptr;
    g_resident_driver_object = nullptr;
    g_resident_symlink.Buffer = nullptr;
    g_resident_symlink.Length = 0;
    g_resident_symlink.MaximumLength = 0;
    _InterlockedExchange(&g_resident_control_ready, 0);
#endif
}

extern "C" NTSTATUS PayloadResidentDriverInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

#if !PAYLOAD_RESIDENT_CTL_ENABLED
    UNREFERENCED_PARAMETER(DriverObject);
    return STATUS_NOT_SUPPORTED;
#else
    if (!DriverObject ||
        !g_io_create_device ||
        !g_io_create_symbolic_link)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    static WCHAR kDeviceName[] = PAYLOADCTL_NT_DEVICE_NAME;
    static WCHAR kSymlinkName[] = PAYLOADCTL_DOS_DEVICE_NAME;

    UNICODE_STRING device_name = {};
    PayloadInitUnicodeString(&device_name, kDeviceName);
    PayloadInitUnicodeString(&g_resident_symlink, kSymlinkName);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = PayloadResidentCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = PayloadResidentCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PayloadResidentDeviceControl;

    auto create_device = (payload_io_create_device_fn)g_io_create_device;
    auto create_symbolic_link = (payload_io_create_symbolic_link_fn)g_io_create_symbolic_link;

    PDEVICE_OBJECT device = nullptr;
    NTSTATUS status = create_device(
        DriverObject,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device);
    if (!NT_SUCCESS(status) || !device)
        return status;

    status = create_symbolic_link(&g_resident_symlink, &device_name);
    if (!NT_SUCCESS(status))
    {
        auto delete_device = (payload_io_delete_device_fn)g_io_delete_device;
        if (delete_device)
            delete_device(device);
        g_resident_symlink.Buffer = nullptr;
        return status;
    }

    device->Flags &= ~DO_DEVICE_INITIALIZING;
    g_resident_driver_object = DriverObject;
    g_resident_device_object = device;
    _InterlockedExchange(&g_resident_control_ready, 1);
    return STATUS_SUCCESS;
#endif
}

static payload_u64 PayloadCreateResidentControl()
{
#if !PAYLOAD_RESIDENT_CTL_ENABLED
    return PAYLOAD_RESULT_OK;
#else
    if (g_resident_control_ready)
        return PAYLOAD_RESULT_OK;
    if (!g_io_create_driver)
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    auto create_driver = (payload_io_create_driver_fn)g_io_create_driver;
    NTSTATUS status = create_driver(nullptr, PayloadResidentDriverInit);
    return NT_SUCCESS(status) ? PAYLOAD_RESULT_OK : PAYLOAD_RESULT_INVALID_CONTEXT;
#endif
}

extern "C" payload_u64 PayloadPing(payload_u64 nonce)
{
    payload_u64 pong = nonce ^ PAYLOAD_PONG_MAGIC;
    g_last_nonce = nonce;
    g_last_pong = pong;
    _InterlockedIncrement64(&g_ping_count);
    return pong;
}

static bool PayloadVtPanicDrainDeferredFromWorker();

#if PAYLOAD_WORKER_AUTOSTART
extern "C" VOID PayloadWorker(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    auto delay_thread = (payload_ke_delay_execution_thread_fn)g_ke_delay_execution_thread;
    auto terminate_thread = (payload_ps_terminate_system_thread_fn)g_ps_terminate_system_thread;

    _InterlockedExchange(&g_worker_running, 1);

    LARGE_INTEGER delay = {};
    delay.QuadPart = -10 * 1000 * 1000; // 1 second

    while (!g_worker_stop)
    {
        _InterlockedIncrement64(&g_heartbeat_count);
        if (PayloadVtPanicDrainDeferredFromWorker())
            break;
        if (delay_thread)
            delay_thread(KernelMode, FALSE, &delay);
        else
            break;
    }

    _InterlockedExchange(&g_worker_running, 0);
    if (terminate_thread)
        terminate_thread(STATUS_SUCCESS);
}
#endif

static void PayloadCaptureBootContext(payload_boot_context* ctx)
{
    if (!ctx)
        return;

    g_image_base = ctx->image_base;
    g_image_size = ctx->image_size;
    g_boot_flags = ctx->boot_flags;
    g_system_cr3 = ctx->system_cr3;
    g_host_api = (payload_u64)ctx->host_api;
    g_host_api_magic = (ctx->host_api && ctx->host_api->size >= sizeof(payload_host_api))
        ? ctx->host_api->magic
        : 0;
    g_host_api_flags = (ctx->host_api && ctx->host_api->size >= sizeof(payload_host_api))
        ? ctx->host_api->flags
        : 0;
    g_host_alloc_fn = 0;
    g_host_free_fn = 0;
    g_arena_base = ctx->arena_base;
    g_arena_size = ctx->arena_size;
    g_arena_used = (ctx->arena_used <= ctx->arena_size) ? ctx->arena_used : 0;
    g_arena_flags = (g_arena_base && g_arena_size) ? PAYLOAD_RUNTIME_FLAG_ARENA_READY : 0;

    g_trace_unload_mm_unloaded_drivers = ctx->trace_unload_mm_unloaded_drivers;
    g_trace_unload_mm_last_unloaded_driver = ctx->trace_unload_mm_last_unloaded_driver;
    g_trace_unload_name_bytes = ctx->trace_unload_name_bytes;
    if (g_trace_unload_name_bytes > sizeof(g_trace_unload_name))
        g_trace_unload_name_bytes = sizeof(g_trace_unload_name);
    g_trace_unload_delay_exits = ctx->trace_unload_delay_exits ? ctx->trace_unload_delay_exits : 8192ull;
    g_trace_unload_interval_exits = ctx->trace_unload_interval_exits ? ctx->trace_unload_interval_exits : 4096ull;
    g_trace_unload_max_attempts = ctx->trace_unload_max_attempts ? ctx->trace_unload_max_attempts : 512ull;
    PayloadZeroMemory(g_trace_unload_name, sizeof(g_trace_unload_name));
    if (g_trace_unload_name_bytes)
        PayloadCopyMemory(g_trace_unload_name, ctx->trace_unload_name_qwords, g_trace_unload_name_bytes);
    g_trace_unload_vmexit_seen = 0;
    g_trace_unload_probe_count = 0;
    g_trace_unload_clean_count = 0;
    g_trace_unload_fail_count = 0;
    g_trace_unload_last_result = 0;
    g_trace_unload_last_index = 0;
    g_trace_unload_last_count = 0;
    g_trace_hash_bucket_list = ctx->trace_hash_bucket_list;
    g_trace_hash_cache_lock = ctx->trace_hash_cache_lock;
    g_trace_hash_delay_exits = ctx->trace_hash_delay_exits ? ctx->trace_hash_delay_exits : 8192ull;
    g_trace_hash_interval_exits = ctx->trace_hash_interval_exits ? ctx->trace_hash_interval_exits : 4096ull;
    g_trace_hash_max_attempts = ctx->trace_hash_max_attempts ? ctx->trace_hash_max_attempts : 512ull;
    g_trace_hash_vmexit_seen = 0;
    g_trace_hash_probe_count = 0;
    g_trace_hash_clean_count = 0;
    g_trace_hash_fail_count = 0;
    g_trace_hash_last_result = 0;
    g_trace_hash_last_index = 0;
    g_trace_hash_last_count = 0;
    g_trace_hash_last_entry = 0;

    g_kernel_api_flags = 0;
    g_mm_allocate_independent_pages = 0;
    g_mm_free_independent_pages = 0;
    g_mm_set_page_protection = 0;
    g_ps_create_system_thread = 0;
    g_ps_terminate_system_thread = 0;
    g_zw_wait_for_single_object = 0;
    g_zw_close = 0;
    g_ke_delay_execution_thread = 0;
    g_ke_set_system_affinity_thread_ex = 0;
    g_ke_revert_to_user_affinity_thread_ex = 0;
    g_ke_bug_check_ex = 0;
    g_io_create_driver = 0;
    g_io_create_device = 0;
    g_io_create_symbolic_link = 0;
    g_io_delete_symbolic_link = 0;
    g_io_delete_device = 0;
    g_io_complete_request = 0;

    bool host_api_valid =
        ctx->host_api &&
        ctx->host_api->magic == PAYLOAD_API_MAGIC &&
        ctx->host_api->size >= sizeof(payload_host_api);

    if (host_api_valid &&
        (ctx->host_api->flags & PAYLOAD_HOST_API_FLAG_ALLOC) &&
        (ctx->host_api->flags & PAYLOAD_HOST_API_FLAG_FREE) &&
        ctx->host_api->alloc &&
        ctx->host_api->free)
    {
        g_host_alloc_fn = (payload_u64)ctx->host_api->alloc;
        g_host_free_fn = (payload_u64)ctx->host_api->free;
    }

    if (host_api_valid &&
        (ctx->host_api->kernel_flags & PAYLOAD_KERNEL_API_FLAG_INDEPENDENT_PAGES) &&
        ctx->host_api->mm_allocate_independent_pages &&
        ctx->host_api->mm_free_independent_pages &&
        ctx->host_api->mm_set_page_protection)
    {
        g_kernel_api_flags |= PAYLOAD_KERNEL_API_FLAG_INDEPENDENT_PAGES;
        g_mm_allocate_independent_pages = (payload_u64)ctx->host_api->mm_allocate_independent_pages;
        g_mm_free_independent_pages = (payload_u64)ctx->host_api->mm_free_independent_pages;
        g_mm_set_page_protection = (payload_u64)ctx->host_api->mm_set_page_protection;
    }

    if (host_api_valid && PayloadResolveWorkerRoutines(ctx->host_api))
        g_kernel_api_flags |= PAYLOAD_KERNEL_API_FLAG_THREAD_ROUTINES;
    if (host_api_valid)
    {
        PayloadResolveBugcheckRoutine(ctx->host_api);
        static const unsigned short kDbgPrintEx[] = {
            'D','b','g','P','r','i','n','t','E','x',0
        };
        g_dbg_print_ex = (payload_u64)PayloadHostResolveRoutine(ctx->host_api, kDbgPrintEx);
    }
    if (host_api_valid && PayloadResolveIoRoutines(ctx->host_api))
        g_kernel_api_flags |= PAYLOAD_KERNEL_API_FLAG_IO_ROUTINES;

    payload_u64 flags = PAYLOAD_RUNTIME_FLAG_CONTEXT_READY;
    if (g_image_base && g_image_size)
        flags |= PAYLOAD_RUNTIME_FLAG_IMAGE_CAPTURED;
    if (g_host_api_magic == PAYLOAD_API_MAGIC && g_host_api_flags)
        flags |= PAYLOAD_RUNTIME_FLAG_HOST_API_CAPTURED;
    if (g_arena_flags)
        flags |= PAYLOAD_RUNTIME_FLAG_ARENA_READY;
    if (g_kernel_api_flags)
        flags |= PAYLOAD_RUNTIME_FLAG_KERNEL_API_READY;
    if ((g_mm_allocate_independent_pages && g_mm_free_independent_pages && g_mm_set_page_protection) ||
        (g_host_alloc_fn && g_host_free_fn))
        flags |= PAYLOAD_RUNTIME_FLAG_DIRECT_ALLOC_READY;
    if (g_kernel_api_flags & PAYLOAD_KERNEL_API_FLAG_THREAD_ROUTINES)
        flags |= PAYLOAD_RUNTIME_FLAG_WORKER_API_READY;
    g_vmexit_trampoline = (payload_u64)&PayloadVmExitTrampoline;
    if (g_vmexit_trampoline)
        flags |= PAYLOAD_RUNTIME_FLAG_VMEXIT_TRAMP_READY;
    g_vmexit_bridge = (payload_u64)&PayloadVmExitBridge;
    if (g_vmexit_bridge)
        flags |= PAYLOAD_RUNTIME_FLAG_VMEXIT_BRIDGE_READY;

    // The bootstrap host_api object lives in mapDriver.  Copy what we need and
    // deliberately drop the long-lived pointer so payload state can become
    // independent before mapDriver unload.
    bool saw_host_api = host_api_valid;
    g_host_api = 0;
    g_external_ref_flags = PAYLOAD_EXTERNAL_REF_NONE;
    if (saw_host_api)
        flags |= PAYLOAD_RUNTIME_FLAG_BOOTSTRAP_SEALED;
    g_independent = (g_arena_flags &&
        (flags & PAYLOAD_RUNTIME_FLAG_DIRECT_ALLOC_READY)) ? 1 : 0;

    g_runtime.magic = PAYLOAD_RUNTIME_MAGIC;
    g_runtime.size = sizeof(g_runtime);
    g_runtime.owner = PAYLOAD_RUNTIME_OWNER_PAYLOAD;
    g_runtime.phase = PAYLOAD_RUNTIME_PHASE_BOOT;
    g_runtime.flags = flags;
    g_runtime.image_base = g_image_base;
    g_runtime.image_size = g_image_size;
    g_runtime.boot_flags = g_boot_flags;
    g_runtime.host_api = g_host_api;
    g_runtime.host_api_magic = g_host_api_magic;
    g_runtime.host_api_flags = g_host_api_flags;
    g_runtime.arena_base = g_arena_base;
    g_runtime.arena_size = g_arena_size;
    g_runtime.arena_used = g_arena_used;
    g_runtime.arena_flags = g_arena_flags;
    g_runtime.kernel_api_flags = g_kernel_api_flags;
    g_runtime.external_ref_flags = g_external_ref_flags;
    g_runtime.independent = g_independent;
    g_runtime.direct_alloc_base = g_direct_alloc_base;
    g_runtime.direct_alloc_size = g_direct_alloc_size;
    g_runtime.owned_alloc_count = g_owned_alloc_count;
    g_runtime.owned_alloc_bytes = g_owned_alloc_bytes;
    g_runtime.last_result = g_last_result;
    g_runtime.generation++;
}

static payload_u64 PayloadStartWorker()
{
#if !PAYLOAD_WORKER_AUTOSTART
    return PAYLOAD_RESULT_OK;
#else
    if (g_worker_handle)
        return PAYLOAD_RESULT_OK;

    auto create_thread = (payload_ps_create_system_thread_fn)g_ps_create_system_thread;
    if (!create_thread || !g_ke_delay_execution_thread || !g_ps_terminate_system_thread)
        return PAYLOAD_RESULT_THREAD_FAILED;

    _InterlockedExchange(&g_worker_stop, 0);

    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(oa);
    oa.Attributes = OBJ_KERNEL_HANDLE;

    HANDLE thread_handle = nullptr;
    NTSTATUS status = create_thread(
        &thread_handle,
        THREAD_ALL_ACCESS,
        &oa,
        nullptr,
        nullptr,
        PayloadWorker,
        nullptr);
    if (!NT_SUCCESS(status) || !thread_handle)
        return PAYLOAD_RESULT_THREAD_FAILED;

    g_worker_handle = thread_handle;
    return PAYLOAD_RESULT_OK;
#endif
}

static void PayloadStopWorker()
{
#if !PAYLOAD_WORKER_AUTOSTART
    _InterlockedExchange(&g_worker_running, 0);
    _InterlockedExchange(&g_worker_stop, 1);
    return;
#else
    _InterlockedExchange(&g_worker_stop, 1);

    HANDLE thread_handle = g_worker_handle;
    if (thread_handle)
    {
        auto wait_object = (payload_zw_wait_for_single_object_fn)g_zw_wait_for_single_object;
        auto close_handle = (payload_zw_close_fn)g_zw_close;
        if (wait_object)
            wait_object(thread_handle, FALSE, nullptr);
        if (close_handle)
            close_handle(thread_handle);
        g_worker_handle = nullptr;
    }
#endif
}

extern "C" payload_u64 PayloadStart(void* boot_context)
{
    auto ctx = (payload_boot_context*)boot_context;
    if (!ctx || ctx->magic != PAYLOAD_BOOT_MAGIC || ctx->size < sizeof(payload_boot_context))
    {
        g_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    PayloadCaptureBootContext(ctx);

    LONG64 old = _InterlockedCompareExchange64(&g_started, 1, 0);
    payload_u64 result = old ? PAYLOAD_RESULT_ALREADY_STARTED : PAYLOAD_RESULT_STARTED;
    if (old)
    {
        g_runtime.phase = PAYLOAD_RUNTIME_PHASE_STARTED;
        g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_STARTED;
        g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_STOPPED;
        if (g_direct_alloc_base && g_direct_alloc_size)
        {
            g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_SELF_ALLOC_READY;
            if (PayloadEnsureHostStackSlab() == PAYLOAD_RESULT_OK)
                g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_HOST_STACK_READY;
            if (PayloadPrepareHostStackDescriptors() == PAYLOAD_RESULT_OK)
                g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_STACK_DESC_READY;
            if (PayloadPrepareHostState() == PAYLOAD_RESULT_OK)
                g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_HOST_STATE_READY;
        }
        if (g_resident_control_ready)
            g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_CONTROL_READY;
        g_runtime.direct_alloc_base = g_direct_alloc_base;
        g_runtime.direct_alloc_size = g_direct_alloc_size;
        g_runtime.owned_alloc_count = g_owned_alloc_count;
        g_runtime.owned_alloc_bytes = g_owned_alloc_bytes;
    }
    else
    {
        payload_u64 worker_result = PayloadStartWorker();
        payload_u64 self_alloc_result = (worker_result == PAYLOAD_RESULT_OK)
            ? PayloadEnsureSelfAllocation()
            : worker_result;
        payload_u64 host_stack_result = (self_alloc_result == PAYLOAD_RESULT_OK)
            ? PayloadEnsureHostStackSlab()
            : self_alloc_result;
        payload_u64 stack_desc_result = (host_stack_result == PAYLOAD_RESULT_OK)
            ? PayloadPrepareHostStackDescriptors()
            : host_stack_result;
        payload_u64 host_state_result = (stack_desc_result == PAYLOAD_RESULT_OK)
            ? PayloadPrepareHostState()
            : stack_desc_result;

        if (host_state_result != PAYLOAD_RESULT_OK)
        {
            PayloadStopWorker();
            PayloadReleaseSelfAllocation();
            _InterlockedExchange64(&g_started, 0);
            result = host_state_result;
            g_runtime.phase = PAYLOAD_RUNTIME_PHASE_ERROR;
            g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_ERROR;
        }
        else
        {
            PayloadCreateResidentControl();
            if (!g_runtime_block)
                g_runtime_block = (payload_u64)PayloadArenaAlloc(0x100, 16);
            g_runtime.arena_used = g_arena_used;
            g_runtime.direct_alloc_base = g_direct_alloc_base;
            g_runtime.direct_alloc_size = g_direct_alloc_size;
            g_runtime.owned_alloc_count = g_owned_alloc_count;
            g_runtime.owned_alloc_bytes = g_owned_alloc_bytes;
            g_payload_unload_quiesce = 0;
            result = PAYLOAD_RESULT_STARTED;
            g_runtime.phase = PAYLOAD_RUNTIME_PHASE_STARTED;
            g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_STARTED;
            g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_SELF_ALLOC_READY;
            g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_HOST_STATE_READY;
            g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_HOST_STACK_READY;
            g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_STACK_DESC_READY;
            if (g_resident_control_ready)
                g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_CONTROL_READY;
            g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_STOPPED;
        }

        _InterlockedIncrement64(&g_start_count);
        g_runtime.generation++;
    }

    g_last_result = result;
    g_runtime.last_result = result;
    ctx->status = result;
    PAYLOAD_LOG("[payload] PayloadStart leave result=0x%llX image=0x%llX/0x%llX arena=0x%llX/0x%llX direct=0x%llX/0x%llX stack=0x%llX/0x%llX flags=0x%llX\n",
        result, g_image_base, g_image_size, g_arena_base, g_arena_size,
        g_direct_alloc_base, g_direct_alloc_size, g_host_stack_base, g_host_stack_size, g_runtime.flags);
    return result;
}

extern "C" payload_u64 PayloadStop()
{
    g_payload_unload_quiesce = 1;
    LONG64 old = _InterlockedCompareExchange64(&g_started, 0, 1);
    if (old)
    {
        PayloadStopWorker();
        PayloadDeleteResidentControl();
        PayloadReleaseSelfAllocation();
        _InterlockedIncrement64(&g_stop_count);
    }

    g_last_result = PAYLOAD_RESULT_STOPPED;
    g_runtime.phase = PAYLOAD_RUNTIME_PHASE_STOPPED;
    g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_STARTED;
    g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_SELF_ALLOC_READY;
    g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_CONTROL_READY;
    g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_HOST_STATE_READY;
    g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_HOST_STACK_READY;
    g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_STACK_DESC_READY;
    g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_STOPPED;
    g_runtime.direct_alloc_base = g_direct_alloc_base;
    g_runtime.direct_alloc_size = g_direct_alloc_size;
    g_runtime.owned_alloc_count = g_owned_alloc_count;
    g_runtime.owned_alloc_bytes = g_owned_alloc_bytes;
    g_runtime.last_result = PAYLOAD_RESULT_STOPPED;
    g_runtime.generation++;
    PAYLOAD_LOG("[payload] PayloadStop complete stop_count=%lld flags=0x%llX\n", g_stop_count, g_runtime.flags);
    return PAYLOAD_RESULT_STOPPED;
}

static void PayloadFillDbgWatchStatus(payload_status* out);
static bool PayloadIsKernelPointer(payload_u64 va);
static payload_u64 PayloadReadHostU64(payload_u64 va);

static void PayloadQueryEptSplitUsage(payload_u64* used_out,
                                      payload_u64* capacity_out,
                                      payload_u64* remaining_out)
{
    payload_u64 max_used = 0;
    payload_u64 capacity = 0;

    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.magic == MAPCTL_HV_DIAG_MAGIC)
    {
        capacity = g_cached_hv_diag.ept_free_page_count;

        if (g_cached_hv_diag.vcpus &&
            g_hv_diag_vcpu_stride &&
            g_cached_hv_diag.vcpu_off_ept_num_used_free_pages)
        {
            payload_u64 count = g_cached_hv_diag.vcpu_count;
            if (count > 64ull)
                count = 64ull;

            for (payload_u64 i = 0; i < count; ++i)
            {
                payload_u64 vcpu_ptr = g_cached_hv_diag.vcpus + i * g_hv_diag_vcpu_stride;
                payload_u64 used_ptr = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_num_used_free_pages;
                if (!PayloadIsKernelPointer(used_ptr))
                    continue;

                payload_u64 used = PayloadReadHostU64(used_ptr);
                if (used > max_used)
                    max_used = used;
            }
        }
    }

    if (used_out)
        *used_out = max_used;
    if (capacity_out)
        *capacity_out = capacity;
    if (remaining_out)
        *remaining_out = (capacity > max_used) ? (capacity - max_used) : 0;
}

extern "C" payload_u64 PayloadGetStatus(void* status_out)
{
    auto out = (payload_status*)status_out;
    if (!out)
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    payload_u64 ept_split_used = 0;
    payload_u64 ept_split_capacity = 0;
    payload_u64 ept_split_remaining = 0;
    PayloadQueryEptSplitUsage(&ept_split_used, &ept_split_capacity, &ept_split_remaining);

    out->magic = PAYLOAD_STATUS_MAGIC;
    out->abi_version = PAYLOAD_ABI_VERSION;
    out->state_flags = PayloadStateFlags();
    out->start_count = (payload_u64)g_start_count;
    out->stop_count = (payload_u64)g_stop_count;
    out->ping_count = (payload_u64)g_ping_count;
    out->last_nonce = g_last_nonce;
    out->last_pong = g_last_pong;
    out->last_result = g_last_result;
    out->heartbeat_count = (payload_u64)g_heartbeat_count;
    out->worker_running = (payload_u64)g_worker_running;
    out->image_base = g_image_base;
    out->image_size = g_image_size;
    out->boot_flags = g_boot_flags;
    out->host_api = g_host_api;
    out->host_api_magic = g_host_api_magic;
    out->host_api_flags = g_host_api_flags;
    out->arena_base = g_arena_base;
    out->arena_size = g_arena_size;
    out->arena_used = g_arena_used;
    out->arena_flags = g_arena_flags;
    out->kernel_api_flags = g_kernel_api_flags;
    out->external_ref_flags = g_external_ref_flags;
    out->independent = g_independent;
    out->runtime_magic = g_runtime.magic;
    out->runtime_owner = g_runtime.owner;
    out->runtime_phase = g_runtime.phase;
    out->runtime_flags = g_runtime.flags;
    out->runtime_generation = g_runtime.generation;
    out->runtime_context = (payload_u64)&g_runtime;
    out->direct_alloc_base = g_direct_alloc_base;
    out->direct_alloc_size = g_direct_alloc_size;
    out->owned_alloc_count = g_owned_alloc_count;
    out->owned_alloc_bytes = g_owned_alloc_bytes;
    out->host_state_base = g_host_state_base;
    out->host_state_size = g_host_state_size;
    out->host_state_magic = g_host_state_base ? PAYLOAD_HOST_STATE_MAGIC : 0;
    out->host_state_flags = g_host_state_flags;
    out->host_state_stage = g_host_state_stage;
    out->host_state_hv_pings = g_host_state_hv_pings;
    out->host_state_last_hv = g_host_state_last_hv;
    out->host_stack_base = g_host_stack_base;
    out->host_stack_size = g_host_stack_size;
    out->host_stack_slot_size = g_host_stack_slot_size;
    out->host_stack_slot_count = g_host_stack_slot_count;
    out->host_stack_desc_base = g_host_stack_desc_base;
    out->host_stack_desc_count = g_host_stack_desc_count;
    out->host_stack_first_rsp = g_host_stack_first_rsp;
    out->vmexit_trampoline = g_vmexit_trampoline;
    out->vmexit_target = g_payload_vmexit_target;
    out->vmexit_hits = g_payload_vmexit_hits;
    out->vmexit_bridge = g_vmexit_bridge;
    out->vmexit_bridge_target = g_payload_vmexit_bridge_target;
    out->vmexit_bridge_hits = g_payload_vmexit_bridge_hits;
    out->vmexit_bridge_observe_count = g_payload_vmexit_bridge_observe_count;
    out->vmexit_bridge_last_reason = g_payload_vmexit_bridge_last_reason;
    out->vmexit_bridge_vmread_fail = g_payload_vmexit_bridge_vmread_fail;
    out->vmexit_bridge_self_count = g_payload_vmexit_bridge_self_count;
    out->vmexit_bridge_self_last_code = g_payload_vmexit_bridge_self_last_code;
    out->vmexit_bridge_self_last_result = g_payload_vmexit_bridge_self_last_result;
    out->vmexit_bridge_forward_count = g_payload_vmexit_bridge_forward_count;
    out->hv_diag_cache_ready = g_hv_diag_cache_ready;
    out->hv_diag_self_count = g_hv_diag_self_count;
    out->hv_diag_gva_fail = g_hv_diag_gva_fail;
    out->vmexit_bridge_self_ping = g_bridge_self_ping;
    out->vmexit_bridge_self_diag = g_bridge_self_diag;
    out->vmexit_bridge_self_map = g_bridge_self_map;
    out->vmexit_bridge_self_rsp = g_bridge_self_rsp;
    out->vmexit_bridge_self_rip = g_bridge_self_rip;
    out->vmexit_bridge_rsp_last = g_payload_vmexit_bridge_rsp_last;
    out->vmexit_bridge_rsp_class = g_payload_vmexit_bridge_rsp_class;
    out->vmexit_bridge_rsp_payload_count = g_payload_vmexit_bridge_rsp_payload_count;
    out->vmexit_bridge_rsp_external_count = g_payload_vmexit_bridge_rsp_external_count;
    out->system_cr3 = g_system_cr3;
    out->host_map_success_count = g_payload_host_map_success_count;
    out->host_map_fail_count = g_payload_host_map_fail_count;
    out->host_map_page_table_pages = g_payload_host_map_page_table_pages;
    out->vmexit_bridge_self_cpuid = g_bridge_self_cpuid;
    out->vmexit_bridge_forward_last_reason = g_payload_vmexit_bridge_forward_last_reason;
    out->vmexit_bridge_forward_last_code = g_payload_vmexit_bridge_forward_last_code;
    out->vmexit_bridge_forward_last_key = g_payload_vmexit_bridge_forward_last_key;
    out->vmexit_bridge_forward_bad_key = g_payload_vmexit_bridge_forward_bad_key;
    out->vmexit_bridge_forward_unknown_code = g_payload_vmexit_bridge_forward_unknown_code;
    out->vmexit_bridge_forward_non_vmcall = g_payload_vmexit_bridge_forward_non_vmcall;
    out->vmexit_bridge_self_hv_base = g_bridge_self_hv_base;
    out->vmexit_bridge_self_vh_init_tramp_pool = g_bridge_self_vh_init_tramp_pool;
    out->vmexit_bridge_self_affinity_lock = g_bridge_self_affinity_lock;
    out->vmexit_bridge_self_hide_diag = g_bridge_self_hide_diag;
    out->vmexit_bridge_self_hide_diag_fail = g_bridge_self_hide_diag_fail;
    out->vmexit_bridge_self_hide_diag_max_used =
        ept_split_capacity ? ept_split_used : g_bridge_self_hide_diag_max_used;
    out->ept_split_max_used = ept_split_used;
    out->ept_split_capacity = ept_split_capacity;
    out->ept_split_remaining = ept_split_remaining;
    out->vmexit_bridge_self_hide_pfn_list = g_bridge_self_hide_pfn_list;
    out->vmexit_bridge_self_hide_pfn_fail = g_bridge_self_hide_pfn_fail;
    out->vmexit_bridge_self_hide_pfn_requested = g_bridge_self_hide_pfn_requested;
    out->vmexit_bridge_self_hide_pfn_hidden = g_bridge_self_hide_pfn_hidden;
    out->vmexit_bridge_self_hide_pfn_null = g_bridge_self_hide_pfn_null;
    out->vmexit_bridge_self_hide_pfn_last_count = g_bridge_self_hide_pfn_last_count;
    out->vmexit_bridge_self_hide_pfn_last_hidden = g_bridge_self_hide_pfn_last_hidden;
    out->vmexit_bridge_self_hide_pfn_last_pfn = g_bridge_self_hide_pfn_last_pfn;
    out->vmexit_bridge_self_hide_pfn_last_pte_va = g_bridge_self_hide_pfn_last_pte_va;
    out->vmexit_bridge_self_hide_pfn_last_pte_before = g_bridge_self_hide_pfn_last_pte_before;
    out->vmexit_bridge_self_hide_pfn_last_pte_after = g_bridge_self_hide_pfn_last_pte_after;
    out->vmexit_bridge_self_hide_pfn_last_vcpu = g_bridge_self_hide_pfn_last_vcpu;
    out->vmexit_bridge_forward_last_rax = g_payload_vmexit_bridge_forward_last_rax;
    out->vmexit_bridge_forward_last_guest_rip = g_payload_vmexit_bridge_forward_last_guest_rip;
    out->vmexit_bridge_forward_last_qualification = g_payload_vmexit_bridge_forward_last_qualification;
    for (payload_u64 i = 0; i < 64; ++i)
    {
        out->vmexit_reason_hist[i] = g_payload_vmexit_reason_hist[i];
        out->vmexit_forward_reason_hist[i] = g_payload_vmexit_forward_reason_hist[i];
    }
    out->vmexit_bridge_self_rdmsr = g_bridge_self_rdmsr;
    out->vmexit_bridge_self_wrmsr = g_bridge_self_wrmsr;
    out->vmexit_bridge_self_msr_last = g_bridge_self_msr_last;
    out->vmexit_exception_last_info = g_payload_vmexit_exception_last_info;
    out->vmexit_exception_last_error = g_payload_vmexit_exception_last_error;
    for (payload_u64 i = 0; i < 32; ++i)
        out->vmexit_exception_vector_hist[i] = g_payload_vmexit_exception_vector_hist[i];
    out->vmexit_ept_last_gpa = g_payload_vmexit_ept_last_gpa;
    out->vmexit_ept_last_gla = g_payload_vmexit_ept_last_gla;
    out->vmexit_ept_last_qualification = g_payload_vmexit_ept_last_qualification;
    out->vmexit_bp_last_rip = g_payload_vmexit_bp_last_rip;
    out->vmexit_bp_user_count = g_payload_vmexit_bp_user_count;
    out->vmexit_bp_kernel_count = g_payload_vmexit_bp_kernel_count;
    out->vmexit_bp_type_software_count = g_payload_vmexit_bp_type_software_count;
    out->vmexit_bp_type_other_count = g_payload_vmexit_bp_type_other_count;
    out->vmexit_forward_badkey_last_rip = g_payload_vmexit_forward_badkey_last_rip;
    out->vmexit_forward_nonvm_last_rip = g_payload_vmexit_forward_nonvm_last_rip;
    for (payload_u64 i = 0; i < PAYLOAD_RIP_HIST_SLOTS; ++i)
    {
        out->vmexit_bp_rip_hist_addr[i] = g_payload_vmexit_bp_rip_hist_addr[i];
        out->vmexit_bp_rip_hist_count[i] = g_payload_vmexit_bp_rip_hist_count[i];
        out->vmexit_badkey_rip_hist_addr[i] = g_payload_vmexit_badkey_rip_hist_addr[i];
        out->vmexit_badkey_rip_hist_count[i] = g_payload_vmexit_badkey_rip_hist_count[i];
        out->vmexit_nonvm_rip_hist_addr[i] = g_payload_vmexit_nonvm_rip_hist_addr[i];
        out->vmexit_nonvm_rip_hist_count[i] = g_payload_vmexit_nonvm_rip_hist_count[i];
    }
    out->vtret_probe_count = g_payload_vtret_probe_count;
    out->vtret_match_count = g_payload_vtret_match_count;
    out->vtret_scan_count = g_payload_vtret_scan_count;
    out->vtret_scan_fail_count = g_payload_vtret_scan_fail_count;
    out->vtret_last_node = g_payload_vtret_last_node;
    out->vtret_last_old_vt_rsp = g_payload_vtret_last_old_vt_rsp;
    out->vtret_last_rip = g_payload_vtret_last_rip;
    out->vtret_last_reason = g_payload_vtret_last_reason;
    out->vtret_last_process = g_payload_vtret_last_process;
    out->vtret_last_thread = g_payload_vtret_last_thread;
    out->vtret_list_base = g_payload_vtret_list_base;
    out->vtret_active_head = g_payload_vtret_active_head;
    out->vtret_mode = g_payload_vtret_mode;
    out->vtret_strict_match_count = g_payload_vtret_strict_match_count;
    out->vtret_loose_match_count = g_payload_vtret_loose_match_count;
    out->vtret_handle_count = g_payload_vtret_handle_count;
    out->vtret_handle_fail_count = g_payload_vtret_handle_fail_count;
    out->vtret_last_handle_result = g_payload_vtret_last_handle_result;
    out->tramp_mode = g_payload_tramp_mode;
    out->tramp_probe_count = g_payload_tramp_probe_count;
    out->tramp_match_count = g_payload_tramp_match_count;
    out->tramp_scan_count = g_payload_tramp_scan_count;
    out->tramp_scan_fail_count = g_payload_tramp_scan_fail_count;
    out->tramp_handle_count = g_payload_tramp_handle_count;
    out->tramp_handle_fail_count = g_payload_tramp_handle_fail_count;
    out->tramp_last_reason = g_payload_tramp_last_reason;
    out->tramp_last_pool = g_payload_tramp_last_pool;
    out->tramp_last_slot = g_payload_tramp_last_slot;
    out->tramp_last_rip = g_payload_tramp_last_rip;
    out->tramp_last_tramp_va = g_payload_tramp_last_tramp_va;
    out->tramp_last_target = g_payload_tramp_last_target;
    out->tramp_last_kind = g_payload_tramp_last_kind;
    out->tramp_user_match_count = g_payload_tramp_user_match_count;
    out->tramp_kernel_match_count = g_payload_tramp_kernel_match_count;
    out->tramp_pool_base = g_payload_tramp_pool_base;
    out->tramp_user_slot_count = g_payload_tramp_user_slot_count;
    out->tramp_kernel_slot_count = g_payload_tramp_kernel_slot_count;
    out->tramp_user_ready = g_payload_tramp_user_ready;
    out->tramp_kernel_ready = g_payload_tramp_kernel_ready;
    out->hook_mode = g_payload_hook_mode;
    out->hook_probe_count = g_payload_hook_probe_count;
    out->hook_match_count = g_payload_hook_match_count;
    out->hook_scan_count = g_payload_hook_scan_count;
    out->hook_scan_fail_count = g_payload_hook_scan_fail_count;
    out->hook_passthrough_count = g_payload_hook_passthrough_count;
    out->hook_passthrough_fail_count = g_payload_hook_passthrough_fail_count;
    out->hook_pmo_forward_count = g_payload_hook_pmo_forward_count;
    out->pmo_probe_count = g_payload_pmo_probe_count;
    out->pmo_match_count = g_payload_pmo_match_count;
    out->pmo_handle_count = g_payload_pmo_handle_count;
    out->pmo_fail_count = g_payload_pmo_fail_count;
    out->pmo_last_reason = g_payload_pmo_last_reason;
    out->pmo_last_rip = g_payload_pmo_last_rip;
    out->pmo_last_tramp_va = g_payload_pmo_last_tramp_va;
    out->pmo_last_target = g_payload_pmo_last_target;
    out->pmo_last_swapchain = g_payload_pmo_last_swapchain;
    out->pmo_side_effect_count = g_payload_pmo_side_effect_count;
    out->pmo_last_old_swapchain = g_payload_pmo_last_old_swapchain;
    out->pmo_last_isfinish = g_payload_pmo_last_isfinish;
    out->pmo_render_d2d_rt = g_payload_pmo_render_d2d_rt;
    out->pmo_render_brush = g_payload_pmo_render_brush;
    out->pmo_render_textfmt = g_payload_pmo_render_textfmt;
    out->pmo_render_buf0 = g_payload_pmo_render_buf0;
    out->pmo_render_buf0_hva = g_payload_pmo_render_buf0_hva;
    out->pmo_render_desc = g_payload_pmo_render_desc;
    out->pmo_render_desc_hva = g_payload_pmo_render_desc_hva;
    out->pmo_call_probe_count = g_payload_pmo_call_probe_count;
    out->pmo_call_return_count = g_payload_pmo_call_return_count;
    out->pmo_call_fail_count = g_payload_pmo_call_fail_count;
    out->pmo_call_same_vcpu_count = g_payload_pmo_call_same_vcpu_count;
    out->pmo_call_cross_vcpu_count = g_payload_pmo_call_cross_vcpu_count;
    out->pmo_call_cross_queue_count = g_payload_pmo_call_cross_queue_count;
    out->pmo_call_cross_leak_count = g_payload_pmo_call_cross_leak_count;
    out->pmo_call_last_reason = g_payload_pmo_call_last_reason;
    out->pmo_call_last_function = g_payload_pmo_call_last_function;
    out->pmo_call_last_ret = g_payload_pmo_call_last_ret;
    out->pmo_call_last_blank = g_payload_pmo_call_last_blank;
    out->pmo_call_last_new_rsp = g_payload_pmo_call_last_new_rsp;
    out->pmo_call_last_vcpu = g_payload_pmo_call_last_vcpu;
    out->pmo_vtret_match_count = g_payload_pmo_vtret_match_count;
    out->pmo_vtret_handle_count = g_payload_pmo_vtret_handle_count;
    out->pmo_vtret_fail_count = g_payload_pmo_vtret_fail_count;
    out->pmo_vtret_last_node = g_payload_pmo_vtret_last_node;
    out->pmo_vtret_last_rip = g_payload_pmo_vtret_last_rip;
    out->pmo_draw_probe_count = g_payload_pmo_draw_probe_count;
    out->pmo_draw_ready_count = g_payload_pmo_draw_ready_count;
    out->pmo_draw_done_count = g_payload_pmo_draw_done_count;
    out->pmo_draw_fail_count = g_payload_pmo_draw_fail_count;
    out->pmo_draw_last_stage = g_payload_pmo_draw_last_stage;
    out->pmo_draw_last_result = g_payload_pmo_draw_last_result;
    out->hook_resident_handle_count = g_payload_hook_resident_handle_count;
    out->hook_resident_fail_count = g_payload_hook_resident_fail_count;
    out->hook_last_type = g_payload_hook_last_type;
    out->hook_last_action = g_payload_hook_last_action;
    out->hook_last_retaddr = g_payload_hook_last_retaddr;
    out->hook_last_result = g_payload_hook_last_result;
    out->getbuffer_hits = g_payload_getbuffer_hits;
    out->getbuffer_alien = g_payload_getbuffer_alien;
    out->getbuffer_substitute = g_payload_getbuffer_substitute;
    out->getbuffer_pass = g_payload_getbuffer_pass;
    out->getbuffer_marker = g_payload_getbuffer_marker;
    out->getbuffer_install_probe = g_payload_getbuffer_install_probe;
    out->getbuffer_install_ok = g_payload_getbuffer_install_ok;
    out->getbuffer_install_fail = g_payload_getbuffer_install_fail;
    out->getbuffer_install_stage = g_payload_getbuffer_install_stage;
    out->getbuffer_install_target = g_payload_getbuffer_install_target;
    out->getbuffer_install_blank = g_payload_getbuffer_install_blank;
    out->getbuffer_install_fake = g_payload_getbuffer_install_fake;
    out->getbuffer_install_tramp = g_payload_getbuffer_install_tramp;
    out->getbuffer_install_slot = g_payload_getbuffer_install_slot;
    out->getbuffer_install_orig_pfn = g_payload_getbuffer_install_orig_pfn;
    out->getbuffer_install_exec_pfn = g_payload_getbuffer_install_exec_pfn;
    out->getbuffer_install_pending = g_payload_getbuffer_install_pending;
    out->getbuffer_install_drain_ok = g_payload_getbuffer_install_drain_ok;
    out->getbuffer_install_drain_fail = g_payload_getbuffer_install_drain_fail;
    out->getbuffer_install_native_reason = g_payload_getbuffer_install_native_reason;
    out->getbuffer_install_native_vcpu = g_payload_getbuffer_install_native_vcpu;
    out->getbuffer_install_native_vcpu_ptr = g_payload_getbuffer_install_native_vcpu_ptr;
    out->getbuffer_install_native_pte_va = g_payload_getbuffer_install_native_pte_va;
    out->getbuffer_install_native_pte_before = g_payload_getbuffer_install_native_pte_before;
    out->getbuffer_install_native_pte_pfn = g_payload_getbuffer_install_native_pte_pfn;
    out->getbuffer_install_native_used = g_payload_getbuffer_install_native_used;
    out->getbuffer_install_native_free = g_payload_getbuffer_install_native_free;
    out->getbuffer_install_native_node = g_payload_getbuffer_install_native_node;
    out->present_hits = g_payload_present_hits;
    out->present_alien = g_payload_present_alien;
    out->present1_hits = g_payload_present1_hits;
    out->present1_alien = g_payload_present1_alien;
    out->copyresource_hits = g_payload_copyresource_hits;
    out->copyresource_alien = g_payload_copyresource_alien;
    out->duplicateoutput_hits = g_payload_duplicateoutput_hits;
    out->duplicateoutput_alien = g_payload_duplicateoutput_alien;
    out->ntsetevent_hits = g_payload_ntsetevent_hits;
    out->nt_alloc_hits = g_payload_nt_alloc_hits;
    out->nt_alloc_alien = g_payload_nt_alloc_alien;
    out->nt_protect_hits = g_payload_nt_protect_hits;
    out->nt_protect_alien = g_payload_nt_protect_alien;
    out->nt_map_hits = g_payload_nt_map_hits;
    out->nt_map_alien = g_payload_nt_map_alien;
    out->capture_notify_count = g_payload_capture_notify_count;
    out->mmcm_hits = g_payload_mmcm_hits;
    out->mmcm_blocked = g_payload_mmcm_blocked;
    out->mmcvm_hits = g_payload_mmcvm_hits;
    out->mmcvm_blocked = g_payload_mmcvm_blocked;
    out->mmisav_hits = g_payload_mmisav_hits;
    out->mmisav_blocked = g_payload_mmisav_blocked;
    out->mmmio_hits = g_payload_mmmio_hits;
    out->mmmio_blocked = g_payload_mmmio_blocked;
    out->ntqvm_hits = g_payload_ntqvm_hits;
    out->ntqvm_blocked = g_payload_ntqvm_blocked;
    out->mmgpa_hits = g_payload_mmgpa_hits;
    out->mmgpa_blocked = g_payload_mmgpa_blocked;
    out->mm4_install_probe = g_payload_mm4_install_probe;
    out->mm4_install_ok = g_payload_mm4_install_ok;
    out->mm4_install_fail = g_payload_mm4_install_fail;
    out->mm4_install_already = g_payload_mm4_install_already;
    out->mm4_install_mask = g_payload_mm4_install_mask;
    out->mm4_install_fail_mask = g_payload_mm4_install_fail_mask;
    out->mm4_install_last_type = g_payload_mm4_install_last_type;
    out->mm4_install_last_stage = g_payload_mm4_install_last_stage;
    out->mm4_install_last_target = g_payload_mm4_install_last_target;
    out->mm4_install_last_slot = g_payload_mm4_install_last_slot;
    out->mm4_install_last_pending = g_payload_mm4_install_last_pending;
    out->mm4_hit_last_type = g_payload_mm4_hit_last_type;
    out->mm4_hit_last_vcpu = g_payload_mm4_hit_last_vcpu;
    out->mm4_hit_vcpu_bitmap = g_payload_mm4_hit_vcpu_bitmap;
    out->mm4_hit_vcpu0 = g_payload_mm4_hit_vcpu0;
    out->mm4_hit_type18_last_vcpu = g_payload_mm4_hit_type18_last_vcpu;
    out->mm4_hit_type18_vcpu_bitmap = g_payload_mm4_hit_type18_vcpu_bitmap;
    out->mm4_hit_type18_vcpu0 = g_payload_mm4_hit_type18_vcpu0;
    out->mm4_hit_type19_last_vcpu = g_payload_mm4_hit_type19_last_vcpu;
    out->mm4_hit_type19_vcpu_bitmap = g_payload_mm4_hit_type19_vcpu_bitmap;
    out->mm4_hit_type19_vcpu0 = g_payload_mm4_hit_type19_vcpu0;
    out->mm4_hit_type20_last_vcpu = g_payload_mm4_hit_type20_last_vcpu;
    out->mm4_hit_type20_vcpu_bitmap = g_payload_mm4_hit_type20_vcpu_bitmap;
    out->mm4_hit_type20_vcpu0 = g_payload_mm4_hit_type20_vcpu0;
    out->mm4_hit_type21_last_vcpu = g_payload_mm4_hit_type21_last_vcpu;
    out->mm4_hit_type21_vcpu_bitmap = g_payload_mm4_hit_type21_vcpu_bitmap;
    out->mm4_hit_type21_vcpu0 = g_payload_mm4_hit_type21_vcpu0;
    out->pmo_device = g_payload_pmo_render_device;
    out->pmo_context = g_payload_pmo_render_context;
    out->pmo_surface = g_payload_pmo_render_surface;
    out->pmo_fake_texture = g_payload_pmo_fake_texture;
    out->pmo_marker_texture = g_payload_pmo_marker_texture;
    out->pmo_marker_ready = g_payload_pmo_marker_ready;
    out->pmo_marker_stage = g_payload_pmo_marker_stage;
    out->pmo_last_getbuffer_out = g_payload_pmo_last_getbuffer_out;
    out->overlay_hide_until_tsc = g_payload_overlay_hide_until_tsc;
    out->business_probe_count = g_payload_business_probe_count;
    out->business_tick_count = g_payload_business_tick_count;
    out->business_skip_count = g_payload_business_skip_count;
    out->business_fail_count = g_payload_business_fail_count;
    out->business_last_stage = g_payload_business_last_stage;
    out->business_last_reason = g_payload_business_last_reason;
    out->business_last_vcpu = g_payload_business_last_vcpu;
    out->business_last_guest_cr3 = g_payload_business_last_guest_cr3;
    out->business_last_swapchain = g_payload_business_last_swapchain;
    out->business_last_draw_done = g_payload_business_last_draw_done;
    out->hook_last_reason = g_payload_hook_last_reason;
    out->hook_last_rip = g_payload_hook_last_rip;
    out->hook_last_tramp_va = g_payload_hook_last_tramp_va;
    out->hook_last_bp_rip = g_payload_hook_last_bp_rip;
    out->hook_last_target = g_payload_hook_last_target;
    out->hook_last_kind = g_payload_hook_last_kind;
    out->hook_user_match_count = g_payload_hook_user_match_count;
    out->hook_kernel_match_count = g_payload_hook_kernel_match_count;
    out->hook_last_key = g_payload_hook_last_key;
    out->hook_last_rax = g_payload_hook_last_rax;
    out->ept_mode = g_payload_ept_mode;
    out->ept_tramp_probe_count = g_payload_ept_tramp_probe_count;
    out->ept_tramp_match_count = g_payload_ept_tramp_match_count;
    out->ept_tramp_handle_count = g_payload_ept_tramp_handle_count;
    out->ept_tramp_handle_fail_count = g_payload_ept_tramp_handle_fail_count;
    out->ept_tramp_scan_fail_count = g_payload_ept_tramp_scan_fail_count;
    out->ept_tramp_mtf_count = g_payload_ept_tramp_mtf_count;
    out->ept_tramp_mtf_fail_count = g_payload_ept_tramp_mtf_fail_count;
    out->ept_tramp_last_reason = g_payload_ept_tramp_last_reason;
    out->ept_tramp_last_gpa = g_payload_ept_tramp_last_gpa;
    out->ept_tramp_last_gla = g_payload_ept_tramp_last_gla;
    out->ept_tramp_last_rip = g_payload_ept_tramp_last_rip;
    out->ept_tramp_last_qualification = g_payload_ept_tramp_last_qualification;
    out->ept_tramp_last_pte_pa = g_payload_ept_tramp_last_pte_pa;
    out->ept_tramp_last_pte_before = g_payload_ept_tramp_last_pte_before;
    out->ept_tramp_last_pte_after = g_payload_ept_tramp_last_pte_after;
    out->ept_tramp_last_orig_pfn = g_payload_ept_tramp_last_orig_pfn;
    out->ept_tramp_last_exec_pfn = g_payload_ept_tramp_last_exec_pfn;
    out->ept_tramp_last_guest_page = g_payload_ept_tramp_last_guest_page;
    out->ept_tramp_last_kind = g_payload_ept_tramp_last_kind;
    out->ept_tramp_exec_count = g_payload_ept_tramp_exec_count;
    out->ept_tramp_data_count = g_payload_ept_tramp_data_count;
    out->ept_tramp_same_count = g_payload_ept_tramp_same_count;
    out->ept_tramp_user_match_count = g_payload_ept_tramp_user_match_count;
    out->ept_tramp_kernel_match_count = g_payload_ept_tramp_kernel_match_count;
    out->ept_tramp_last_vcpu = g_payload_ept_tramp_last_vcpu;
    out->ept_tramp_last_mtf_restore = g_payload_ept_tramp_last_mtf_restore;
    out->ept_generic_match_count = g_payload_ept_generic_match_count;
    out->ept_fake_match_count = g_payload_ept_fake_match_count;
    out->ept_last_hook_node = g_payload_ept_last_hook_node;
    out->ept_last_is_fake = g_payload_ept_last_is_fake;
    out->vmexit_bridge_self_rdtsc = g_bridge_self_rdtsc;
    out->vmexit_bridge_self_rdtscp = g_bridge_self_rdtscp;
    out->vmexit_bridge_self_tsc_last = g_bridge_self_tsc_last;
    out->vmexit_bridge_self_tsc_aux = g_bridge_self_tsc_aux;
    out->vmexit_bridge_self_tsc_fail = g_bridge_self_tsc_fail;
    out->exbp_mode = g_payload_exbp_mode;
    out->exbp_probe_count = g_payload_exbp_probe_count;
    out->exbp_reinject_count = g_payload_exbp_reinject_count;
    out->exbp_reinject_fail_count = g_payload_exbp_reinject_fail_count;
    out->exbp_guard_count = g_payload_exbp_guard_count;
    out->exbp_last_reason = g_payload_exbp_last_reason;
    out->exbp_last_rip = g_payload_exbp_last_rip;
    out->exbp_last_info = g_payload_exbp_last_info;
    out->exbp_last_entry_info = g_payload_exbp_last_entry_info;
    out->exbp_last_instruction_length = g_payload_exbp_last_instruction_length;
    out->misc_exit_probe_count = g_payload_misc_exit_probe_count;
    out->misc_exit_handle_count = g_payload_misc_exit_handle_count;
    out->misc_exit_fail_count = g_payload_misc_exit_fail_count;
    out->misc_exit_last_reason = g_payload_misc_exit_last_reason;
    out->misc_exit_last_action = g_payload_misc_exit_last_action;
    out->misc_exit_last_vector = g_payload_misc_exit_last_vector;
    out->misc_exit_preempt_count = g_payload_misc_exit_preempt_count;
    out->invlpg_probe_count = g_payload_invlpg_probe_count;
    out->invlpg_handle_count = g_payload_invlpg_handle_count;
    out->invlpg_fail_count = g_payload_invlpg_fail_count;
    out->invlpg_last_gla = g_payload_invlpg_last_gla;
    out->invlpg_last_vpid = g_payload_invlpg_last_vpid;
    out->invlpg_last_result = g_payload_invlpg_last_result;
    out->xsetbv_probe_count = g_payload_xsetbv_probe_count;
    out->xsetbv_handle_count = g_payload_xsetbv_handle_count;
    out->xsetbv_fail_count = g_payload_xsetbv_fail_count;
    out->xsetbv_gp_count = g_payload_xsetbv_gp_count;
    out->xsetbv_ud_count = g_payload_xsetbv_ud_count;
    out->xsetbv_last_reason = g_payload_xsetbv_last_reason;
    out->xsetbv_last_index = g_payload_xsetbv_last_index;
    out->xsetbv_last_value = g_payload_xsetbv_last_value;
    out->xsetbv_last_cr4 = g_payload_xsetbv_last_cr4;
    out->xsetbv_last_unsupported_mask = g_payload_xsetbv_last_unsupported_mask;
    out->xsetbv_last_result = g_payload_xsetbv_last_result;
    out->invd_probe_count = g_payload_invd_probe_count;
    out->invd_handle_count = g_payload_invd_handle_count;
    out->invd_fail_count = g_payload_invd_fail_count;
    out->invd_gp_count = g_payload_invd_gp_count;
    out->invd_last_dpl = g_payload_invd_last_dpl;
    out->invd_last_result = g_payload_invd_last_result;
    out->cr_probe_count = g_payload_cr_probe_count;
    out->cr_handle_count = g_payload_cr_handle_count;
    out->cr_fail_count = g_payload_cr_fail_count;
    out->cr_gp_count = g_payload_cr_gp_count;
    out->cr_last_reason = g_payload_cr_last_reason;
    out->cr_last_qualification = g_payload_cr_last_qualification;
    out->cr_last_access = g_payload_cr_last_access;
    out->cr_last_register = g_payload_cr_last_register;
    out->cr_last_gpr = g_payload_cr_last_gpr;
    out->cr_last_value = g_payload_cr_last_value;
    out->vmexit_bridge_self_get_pa = g_bridge_self_get_pa;
    out->vmexit_bridge_self_get_pa_fail = g_bridge_self_get_pa_fail;
    out->vmexit_bridge_self_get_pa_last_cr3 = g_bridge_self_get_pa_last_cr3;
    out->vmexit_bridge_self_get_pa_last_gva = g_bridge_self_get_pa_last_gva;
    out->vmexit_bridge_self_get_pa_last_gpa = g_bridge_self_get_pa_last_gpa;
    out->vmexit_bridge_self_gamevt_get = g_bridge_self_gamevt_get;
    out->vmexit_bridge_self_gamevt_save = g_bridge_self_gamevt_save;
    out->vmexit_bridge_self_gamevt_fail = g_bridge_self_gamevt_fail;
    out->payload_gamevt_image_base = g_payload_gamevt_image_base;
    out->payload_gamevt_driver_unload = g_payload_gamevt_driver_unload;
    out->vmexit_bridge_self_keep_hv = g_bridge_self_keep_hv;
    out->payload_keep_hv_flags = g_payload_keep_hv_flags;
    out->vmexit_bridge_self_query_cr3 = g_bridge_self_query_cr3;
    out->vmexit_bridge_self_query_cr3_fail = g_bridge_self_query_cr3_fail;
    out->vmexit_bridge_self_query_cr3_last_pid = g_bridge_self_query_cr3_last_pid;
    out->vmexit_bridge_self_query_cr3_last_cr3 = g_bridge_self_query_cr3_last_cr3;
    out->vmexit_bridge_self_get_info = g_bridge_self_get_info;
    out->vmexit_bridge_self_get_info_fail = g_bridge_self_get_info_fail;
    out->payload_real_cr3 = g_payload_real_cr3;
    out->vmexit_bridge_self_read_phys = g_bridge_self_read_phys;
    out->vmexit_bridge_self_write_phys = g_bridge_self_write_phys;
    out->vmexit_bridge_self_read_virt = g_bridge_self_read_virt;
    out->vmexit_bridge_self_write_virt = g_bridge_self_write_virt;
    out->vmexit_bridge_self_mem_fail = g_bridge_self_mem_fail;
    out->vmexit_bridge_self_mem_bytes = g_bridge_self_mem_bytes;
    PayloadFillDbgWatchStatus(out);
    out->legacy_detached =
        (g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) ? 1ull : 0ull;
    out->legacy_detach_result = g_legacy_detach_result;
    out->legacy_detach_flags = g_legacy_detach_flags;
    out->legacy_detach_generation = g_legacy_detach_generation;
    out->legacy_ghv_original = g_legacy_ghv_original;
    out->legacy_ghv_copy = g_legacy_ghv_copy;
    out->legacy_ghv_size = g_legacy_ghv_size;
    out->legacy_vt_hook_original = g_legacy_vt_hook_original;
    out->legacy_vt_hook_copy = g_legacy_vt_hook_copy;
    out->legacy_vt_hook_size = g_legacy_vt_hook_size;
    out->legacy_shadow_base = g_legacy_shadow_base;
    out->legacy_shadow_size = g_legacy_shadow_size;
    out->legacy_shadow_count = g_legacy_shadow_count;
    out->resident_pool_manifest = g_resident_pool_manifest;
    out->resident_pool_capacity = g_resident_pool_capacity;
    out->resident_pool_count = g_resident_pool_count;
    out->resident_pool_bytes = g_resident_pool_bytes;
    out->resident_pool_independent_count = g_resident_pool_independent_count;
    out->resident_pool_fallback_count = g_resident_pool_fallback_count;
    out->resident_pool_generation = g_resident_pool_generation;
    out->resident_pool_last_result = g_resident_pool_last_result;
    out->vmexit_bridge_old_handler_call_count = g_payload_vmexit_old_handler_call_count;
    out->vmexit_bridge_pending_restore_count = g_payload_vmexit_pending_restore_count;
    out->vmexit_bridge_pending_release_count = g_payload_vmexit_pending_release_count;
    out->vmexit_bridge_pending_release_wait_count = g_payload_vmexit_pending_release_wait_count;
    out->vmexit_bridge_pending_fail_count = g_payload_vmexit_pending_fail_count;
    out->vmexit_bridge_pending_node_nonzero_count = g_payload_vmexit_pending_node_nonzero_count;
    out->vmexit_bridge_pending_last_vcpu = g_payload_vmexit_pending_last_vcpu;
    out->vmexit_bridge_pending_last_state = g_payload_vmexit_pending_last_state;
    out->vmexit_bridge_pending_last_rsp = g_payload_vmexit_pending_last_rsp;
    out->vmexit_bridge_trace_scrub_count = g_payload_vmexit_trace_scrub_count;
    out->vmexit_bridge_trace_scrub_fail_count = g_payload_vmexit_trace_scrub_fail_count;
    out->vmexit_bridge_trace_scrub_last_mask = g_payload_vmexit_trace_scrub_last_mask;
    out->trace_unload_vmexit_seen = g_trace_unload_vmexit_seen;
    out->trace_unload_probe_count = g_trace_unload_probe_count;
    out->trace_unload_clean_count = g_trace_unload_clean_count;
    out->trace_unload_fail_count = g_trace_unload_fail_count;
    out->trace_unload_last_result = g_trace_unload_last_result;
    out->trace_unload_last_index = g_trace_unload_last_index;
    out->trace_unload_last_count = g_trace_unload_last_count;
    out->trace_unload_mm_unloaded_drivers = g_trace_unload_mm_unloaded_drivers;
    out->trace_unload_mm_last_unloaded_driver = g_trace_unload_mm_last_unloaded_driver;
    out->trace_hash_vmexit_seen = g_trace_hash_vmexit_seen;
    out->trace_hash_probe_count = g_trace_hash_probe_count;
    out->trace_hash_clean_count = g_trace_hash_clean_count;
    out->trace_hash_fail_count = g_trace_hash_fail_count;
    out->trace_hash_last_result = g_trace_hash_last_result;
    out->trace_hash_last_index = g_trace_hash_last_index;
    out->trace_hash_last_count = g_trace_hash_last_count;
    out->trace_hash_last_entry = g_trace_hash_last_entry;
    out->trace_hash_bucket_list = g_trace_hash_bucket_list;
    out->trace_hash_cache_lock = g_trace_hash_cache_lock;
    out->vmexit_bridge_ctx_set_count = g_payload_vmexit_ctx_set_count;
    out->vmexit_bridge_ctx_set_fail_count = g_payload_vmexit_ctx_set_fail_count;
    out->vmexit_bridge_ctx_set_last_vcpu = g_payload_vmexit_ctx_set_last_vcpu;
    out->vmexit_bridge_ctx_set_last_ptr = g_payload_vmexit_ctx_set_last_ptr;
    out->vmexit_bridge_vcpu_reset_count = g_payload_vmexit_vcpu_reset_count;
    out->vmexit_bridge_vcpu_reset_fail_count = g_payload_vmexit_vcpu_reset_fail_count;
    out->vmexit_bridge_legacy_invept_count = g_payload_vmexit_legacy_invept_count;
    out->vmexit_bridge_legacy_invept_fail_count = g_payload_vmexit_legacy_invept_fail_count;
    out->vmexit_bridge_legacy_invept_last_bitmap = g_payload_vmexit_legacy_invept_last_bitmap;
    out->vmexit_bridge_legacy_install_count = g_payload_vmexit_legacy_install_count;
    out->vmexit_bridge_legacy_install_fail_count = g_payload_vmexit_legacy_install_fail_count;
    out->vmexit_bridge_legacy_install_retire_count = g_payload_vmexit_legacy_install_retire_count;
    out->vmexit_bridge_legacy_hide_count = g_payload_vmexit_legacy_hide_count;
    out->vmexit_bridge_legacy_hide_fail_count = g_payload_vmexit_legacy_hide_fail_count;
    out->vmexit_bridge_legacy_hide_last_hidden = g_payload_vmexit_legacy_hide_last_hidden;
    out->vmexit_bridge_legacy_mtf_count = g_payload_vmexit_legacy_mtf_count;
    out->vmexit_bridge_legacy_mtf_fail_count = g_payload_vmexit_legacy_mtf_fail_count;
    out->vmexit_bridge_ept_misconfig_count = g_payload_vmexit_ept_misconfig_count;
    out->vmexit_bridge_ept_misconfig_last_gpa = g_payload_vmexit_ept_misconfig_last_gpa;
    out->vtpanic_mode = g_payload_vtpanic_mode;
    out->vtpanic_count = g_payload_vtpanic_count;
    out->vtpanic_active = g_payload_vtpanic_active;
    out->vtpanic_ke_bugcheck_ex = g_ke_bug_check_ex;
    out->vtpanic_last_reason = g_payload_vtpanic_last_reason;
    out->vtpanic_last_param1 = g_payload_vtpanic_last_param1;
    out->vtpanic_last_param2 = g_payload_vtpanic_last_param2;
    out->vtpanic_last_param3 = g_payload_vtpanic_last_param3;
    out->vtpanic_last_vmexit_reason = g_payload_vtpanic_last_vmexit_reason;
    out->vtpanic_last_guest_rip = g_payload_vtpanic_last_guest_rip;
    out->vtpanic_last_guest_cr3 = g_payload_vtpanic_last_guest_cr3;
    out->vtpanic_last_guest_rsp = g_payload_vtpanic_last_guest_rsp;
    out->vtpanic_last_gla = g_payload_vtpanic_last_gla;
    out->vtpanic_last_gpa = g_payload_vtpanic_last_gpa;
    out->vtpanic_last_qualification = g_payload_vtpanic_last_qualification;
    out->vtpanic_last_error = g_payload_vtpanic_last_error;
    out->vtpanic_last_frame = g_payload_vtpanic_last_frame;
    out->host_idt_install_count = g_payload_host_idt_install_count;
    out->host_idt_fail_count = g_payload_host_idt_fail_count;
    out->host_idt_last_base = g_payload_host_idt_last_base;
    out->host_exception_count = g_payload_host_exception_count;
    out->host_exception_last_vector = g_payload_host_exception_last_vector;
    out->host_exception_last_rip = g_payload_host_exception_last_rip;
    out->host_panic_landing_count = g_payload_host_panic_landing_count;
    out->host_panic_landing_fail_count = g_payload_host_panic_landing_fail_count;
    out->host_panic_landing_last_index = g_payload_host_panic_landing_last_index;
    out->host_panic_landing_last_rsp = g_payload_host_panic_landing_last_rsp;
    out->host_panic_landing_last_rip = g_payload_host_panic_landing_last_rip;
    out->vtpanic_selftest_fired = (payload_u64)g_payload_vtpanic_selftest_fired;
    out->vtpanic_selftest_vmexit_seen = g_payload_vtpanic_selftest_vmexit_seen;
    out->vtpanic_selftest_wait_kernel = g_payload_vtpanic_selftest_wait_kernel;
    out->vtpanic_selftest_schedule_fail = g_payload_vtpanic_selftest_schedule_fail;
    out->vtpanic_storm_count = g_payload_vtpanic_storm_count;
    out->vtpanic_storm_last_idx = g_payload_vtpanic_storm_last_idx;
    out->vtpanic_storm_last_seen = g_payload_vtpanic_storm_last_seen;
    out->vtpanic_storm_last_sig0 = g_payload_vtpanic_storm_last_sig0;
    out->vtpanic_storm_last_sig1 = g_payload_vtpanic_storm_last_sig1;
    out->vtpanic_deferred_pending = (payload_u64)g_payload_vtpanic_deferred_pending;
    out->vtpanic_deferred_reason = g_payload_vtpanic_deferred_reason;
    out->vtpanic_deferred_param1 = g_payload_vtpanic_deferred_param1;
    out->vtpanic_deferred_param2 = g_payload_vtpanic_deferred_param2;
    out->vtpanic_deferred_param3 = g_payload_vtpanic_deferred_param3;
    payload_u64 ring_seq = g_payload_vmexit_ring_seq;
    out->vmexit_ring_seq = ring_seq;
    out->vmexit_ring_next = ring_seq & (PAYLOAD_VMEXIT_RING_SLOTS - 1ull);
    for (payload_u64 i = 0; i < PAYLOAD_VMEXIT_RING_SLOTS; ++i)
    {
        out->vmexit_ring[i].seq = g_payload_vmexit_ring[i].seq;
        out->vmexit_ring[i].reason = g_payload_vmexit_ring[i].reason;
        out->vmexit_ring[i].guest_rip = g_payload_vmexit_ring[i].guest_rip;
        out->vmexit_ring[i].guest_rsp = g_payload_vmexit_ring[i].guest_rsp;
        out->vmexit_ring[i].guest_cr3 = g_payload_vmexit_ring[i].guest_cr3;
        out->vmexit_ring[i].qualification = g_payload_vmexit_ring[i].qualification;
        out->vmexit_ring[i].guest_linear = g_payload_vmexit_ring[i].guest_linear;
        out->vmexit_ring[i].guest_physical = g_payload_vmexit_ring[i].guest_physical;
        out->vmexit_ring[i].primary_exec = g_payload_vmexit_ring[i].primary_exec;
        out->vmexit_ring[i].secondary_exec = g_payload_vmexit_ring[i].secondary_exec;
        out->vmexit_ring[i].interruption_info = g_payload_vmexit_ring[i].interruption_info;
        out->vmexit_ring[i].interruption_error = g_payload_vmexit_ring[i].interruption_error;
        out->vmexit_ring[i].vcpu_index = g_payload_vmexit_ring[i].vcpu_index;
        out->vmexit_ring[i].host_rsp = g_payload_vmexit_ring[i].host_rsp;
        out->vmexit_ring[i].action = g_payload_vmexit_ring[i].action;
        out->vmexit_ring[i].result = g_payload_vmexit_ring[i].result;
    }
    return PAYLOAD_RESULT_OK;
}

static bool PayloadVmread(payload_u64 field, payload_u64* value)
{
    if (!value)
        return false;

    size_t raw = 0;
    if (__vmx_vmread((size_t)field, &raw) != 0)
        return false;

    *value = (payload_u64)raw;
    return true;
}

static bool PayloadVmwrite(payload_u64 field, payload_u64 value)
{
    return __vmx_vmwrite((size_t)field, (size_t)value) == 0;
}

static void PayloadVtPanicCaptureVmcs()
{
    payload_u64 value = 0;
    if (PayloadVmread(PAYLOAD_VMCS_EXIT_REASON, &value))
        g_payload_vtpanic_last_vmexit_reason = value;
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &value))
        g_payload_vtpanic_last_guest_rip = value;
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &value))
        g_payload_vtpanic_last_guest_cr3 = value;
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_RSP, &value))
        g_payload_vtpanic_last_guest_rsp = value;
    if (PayloadVmread(PAYLOAD_VMCS_EXIT_GUEST_LINEAR_ADDRESS, &value))
        g_payload_vtpanic_last_gla = value;
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_PHYSICAL_ADDRESS, &value))
        g_payload_vtpanic_last_gpa = value;
    if (PayloadVmread(PAYLOAD_VMCS_EXIT_QUALIFICATION, &value))
        g_payload_vtpanic_last_qualification = value;
    if (PayloadVmread(PAYLOAD_VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, &value))
        g_payload_vtpanic_last_error = value;
}

static bool PayloadVtPanicBugCheck(payload_u64 reason,
                                   payload_u64 param1,
                                   payload_u64 param2,
                                   payload_u64 param3)
{
#if PAYLOAD_VT_FATAL_BUGCHECK_ENABLED
    // This function is called from VMX-root paths.  Do not call NT routines
    // directly here: the root IDT/GDT/stack are not normal Windows execution
    // context and KeBugCheckEx from root mode has already produced unreliable
    // no-dump hangs.  Record the fatal request and let a later guest-kernel
    // VM-exit path schedule KeBugCheckEx in guest context.
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vtpanic_count);
    g_payload_vtpanic_last_reason = reason;
    g_payload_vtpanic_last_param1 = param1;
    g_payload_vtpanic_last_param2 = param2;
    g_payload_vtpanic_last_param3 = param3;
    PayloadVtPanicCaptureVmcs();

    g_payload_vtpanic_deferred_reason = reason;
    g_payload_vtpanic_deferred_param1 = param1;
    g_payload_vtpanic_deferred_param2 = param2;
    g_payload_vtpanic_deferred_param3 = param3;
    _InterlockedExchange(&g_payload_vtpanic_deferred_pending, 1);
    return false;
#else
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(param1);
    UNREFERENCED_PARAMETER(param2);
    UNREFERENCED_PARAMETER(param3);
    return false;
#endif
}

static bool PayloadVtPanicBugCheckNoVmcs(payload_u64 reason,
                                         payload_u64 param1,
                                         payload_u64 param2,
                                         payload_u64 param3)
{
#if PAYLOAD_VT_FATAL_BUGCHECK_ENABLED
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vtpanic_count);
    g_payload_vtpanic_last_reason = reason;
    g_payload_vtpanic_last_param1 = param1;
    g_payload_vtpanic_last_param2 = param2;
    g_payload_vtpanic_last_param3 = param3;

    auto bugcheck = (payload_ke_bug_check_ex_fn)(payload_u64)g_ke_bug_check_ex;
    if (!bugcheck)
        return false;

    _InterlockedExchange(&g_payload_vtpanic_active, 1);

    bugcheck(
        PAYLOAD_VTPANIC_BUGCHECK_CODE,
        (ULONG_PTR)(PAYLOAD_VTPANIC_PARAM_TAG | (reason & 0xFFFFFFFFull)),
        (ULONG_PTR)param1,
        (ULONG_PTR)param2,
        (ULONG_PTR)param3);

    for (;;)
        _mm_pause();
#else
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(param1);
    UNREFERENCED_PARAMETER(param2);
    UNREFERENCED_PARAMETER(param3);
    return false;
#endif
}

static void PayloadVtPanicQueueDeferred(payload_u64 reason,
                                        payload_u64 param1,
                                        payload_u64 param2,
                                        payload_u64 param3)
{
    g_payload_vtpanic_deferred_reason = reason;
    g_payload_vtpanic_deferred_param1 = param1;
    g_payload_vtpanic_deferred_param2 = param2;
    g_payload_vtpanic_deferred_param3 = param3;
    g_payload_vtpanic_last_reason = reason;
    g_payload_vtpanic_last_param1 = param1;
    g_payload_vtpanic_last_param2 = param2;
    g_payload_vtpanic_last_param3 = param3;
    PayloadVtPanicCaptureVmcs();
    _InterlockedExchange(&g_payload_vtpanic_deferred_pending, 1);
}

static bool PayloadVtPanicDrainDeferredFromWorker()
{
    if (_InterlockedCompareExchange(&g_payload_vtpanic_deferred_pending, 0, 1) != 1)
        return false;

    return PayloadVtPanicBugCheckNoVmcs(
        g_payload_vtpanic_deferred_reason,
        g_payload_vtpanic_deferred_param1,
        g_payload_vtpanic_deferred_param2,
        g_payload_vtpanic_deferred_param3);
}

static bool PayloadHostPhysicalRangeMapped(payload_u64 pa, payload_u64 size)
{
    if (!size || pa >= PAYLOAD_HOST_PHYSICAL_MEMORY_BYTES)
        return false;
    return size <= (PAYLOAD_HOST_PHYSICAL_MEMORY_BYTES - pa);
}

static bool PayloadReadPhys64(payload_u64 pa, payload_u64* value)
{
    if (!value || !PayloadHostPhysicalRangeMapped(pa, sizeof(payload_u64)))
        return false;

    auto ptr = (volatile payload_u64*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pa);
    *value = *ptr;
    return true;
}

static bool PayloadWritePhys64(payload_u64 pa, payload_u64 value)
{
    if (!PayloadHostPhysicalRangeMapped(pa, sizeof(payload_u64)))
        return false;

    auto ptr = (volatile payload_u64*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pa);
    *ptr = value;
    return true;
}

static bool PayloadGvaToGpa(payload_u64 cr3, payload_u64 gva, payload_u64* gpa, payload_u64* bytes_left)
{
    if (!gpa)
        return false;

    payload_u64 pml4 = cr3 & 0x000FFFFFFFFFF000ull;
    payload_u64 pml4_idx = (gva >> 39) & 0x1FFull;
    payload_u64 pdpt_idx = (gva >> 30) & 0x1FFull;
    payload_u64 pd_idx = (gva >> 21) & 0x1FFull;
    payload_u64 pt_idx = (gva >> 12) & 0x1FFull;
    payload_u64 page_off = gva & 0xFFFull;

    payload_u64 pml4e = 0;
    if (!PayloadReadPhys64(pml4 + pml4_idx * sizeof(payload_u64), &pml4e) || !(pml4e & 1))
        return false;

    payload_u64 pdpt = pml4e & 0x000FFFFFFFFFF000ull;
    payload_u64 pdpte = 0;
    if (!PayloadReadPhys64(pdpt + pdpt_idx * sizeof(payload_u64), &pdpte) || !(pdpte & 1))
        return false;

    if (pdpte & (1ull << 7))
    {
        payload_u64 off = gva & ((1ull << 30) - 1);
        *gpa = (pdpte & 0x000FFFFFC0000000ull) + off;
        if (bytes_left)
            *bytes_left = (1ull << 30) - off;
        return true;
    }

    payload_u64 pd = pdpte & 0x000FFFFFFFFFF000ull;
    payload_u64 pde = 0;
    if (!PayloadReadPhys64(pd + pd_idx * sizeof(payload_u64), &pde) || !(pde & 1))
        return false;

    if (pde & (1ull << 7))
    {
        payload_u64 off = gva & ((1ull << 21) - 1);
        *gpa = (pde & 0x000FFFFFFFE00000ull) + off;
        if (bytes_left)
            *bytes_left = (1ull << 21) - off;
        return true;
    }

    payload_u64 pt = pde & 0x000FFFFFFFFFF000ull;
    payload_u64 pte = 0;
    if (!PayloadReadPhys64(pt + pt_idx * sizeof(payload_u64), &pte) || !(pte & 1))
        return false;

    *gpa = (pte & 0x000FFFFFFFFFF000ull) + page_off;
    if (bytes_left)
        *bytes_left = 0x1000ull - page_off;
    return true;
}

static bool PayloadKernelVaToPa(payload_u64 va, payload_u64* pa)
{
    payload_u64 ignored = 0;
    if (!g_system_cr3)
        return false;
    return PayloadGvaToGpa(g_system_cr3, va, pa, &ignored);
}

static void PayloadZeroPhysPage(payload_u64 pa)
{
    if (!PayloadHostPhysicalRangeMapped(pa, PAGE_SIZE))
        return;
    PayloadZeroMemory((void*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pa), PAGE_SIZE);
}

static bool PayloadAllocHostPageTablePage(payload_u64* pa_out)
{
    if (!pa_out)
        return false;

    void* page = PayloadDirectAlloc(PAGE_SIZE, PAGE_READWRITE);
    if (!page)
        return false;

    payload_u64 pa = 0;
    if (!PayloadKernelVaToPa((payload_u64)page, &pa) ||
        !PayloadHostPhysicalRangeMapped(pa, PAGE_SIZE))
    {
        PayloadDirectFree(page, PAGE_SIZE);
        return false;
    }

    PayloadZeroPhysPage(pa);
    g_owned_alloc_count++;
    g_owned_alloc_bytes += PAGE_SIZE;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_host_map_page_table_pages);
    *pa_out = pa & 0x000FFFFFFFFFF000ull;
    return true;
}

struct payload_source_page_entries
{
    payload_u64 pml4e;
    payload_u64 pdpte;
    payload_u64 pde;
    payload_u64 pte;
    bool pdpte_large;
    bool pde_large;
};

static bool PayloadReadSourcePageEntries(payload_u64 va, payload_source_page_entries* out)
{
    if (!out || !g_system_cr3)
        return false;

    PayloadZeroMemory(out, sizeof(*out));
    payload_u64 pml4 = g_system_cr3 & 0x000FFFFFFFFFF000ull;
    payload_u64 pml4_idx = (va >> 39) & 0x1FFull;
    payload_u64 pdpt_idx = (va >> 30) & 0x1FFull;
    payload_u64 pd_idx = (va >> 21) & 0x1FFull;
    payload_u64 pt_idx = (va >> 12) & 0x1FFull;

    if (!PayloadReadPhys64(pml4 + pml4_idx * sizeof(payload_u64), &out->pml4e) ||
        !(out->pml4e & 1ull))
        return false;

    payload_u64 pdpt = out->pml4e & 0x000FFFFFFFFFF000ull;
    if (!PayloadReadPhys64(pdpt + pdpt_idx * sizeof(payload_u64), &out->pdpte) ||
        !(out->pdpte & 1ull))
        return false;
    out->pdpte_large = (out->pdpte & (1ull << 7)) != 0;
    if (out->pdpte_large)
        return true;

    payload_u64 pd = out->pdpte & 0x000FFFFFFFFFF000ull;
    if (!PayloadReadPhys64(pd + pd_idx * sizeof(payload_u64), &out->pde) ||
        !(out->pde & 1ull))
        return false;
    out->pde_large = (out->pde & (1ull << 7)) != 0;
    if (out->pde_large)
        return true;

    payload_u64 pt = out->pde & 0x000FFFFFFFFFF000ull;
    if (!PayloadReadPhys64(pt + pt_idx * sizeof(payload_u64), &out->pte) ||
        !(out->pte & 1ull))
        return false;

    return true;
}

struct payload_host_exception_info
{
    unsigned char exception_occurred;
    unsigned char reserved[7];
    payload_u64 vector;
    payload_u64 error;
};

extern "C" void PayloadMemcpySafe(payload_host_exception_info* exception_info,
                                  void* dst,
                                  const void* src,
                                  payload_u64 size);

static payload_u64 PayloadTriggerHostExceptionSelftest(payload_u64 mode)
{
    // Deliberately execute a faulting root-mode instruction without the
    // r10/r11 safe-probe convention.  If payload host IDT + panic landing
    // work, this function never returns: PayloadHandleHostInterrupt schedules
    // a guest bugcheck and jumps back to the VM-exit bridge landing path.
    if (mode == PAYLOAD_HOST_EXCEPTION_MODE_UD2)
        PayloadTriggerHostUd2();
    else if (mode == PAYLOAD_HOST_EXCEPTION_MODE_RDMSR_GP)
        PayloadTriggerHostGp();
    else
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    return PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void PayloadRedirectLegacyDiagPointersToShadows(mapctl_hv_diag* diag)
{
    if (!diag)
        return;

    diag->gamevt_image_base_ptr = (payload_u64)&g_legacy_gamevt_image_base_shadow;
    diag->gamevt_driver_unload_ptr = (payload_u64)&g_legacy_gamevt_driver_unload_shadow;
    diag->yvt_boot_flags_ptr = (payload_u64)&g_legacy_yvt_boot_flags_shadow;
    diag->render_swapchain_ptr = (payload_u64)&g_legacy_render_swapchain_shadow;
    diag->render_isfinish_ptr = (payload_u64)&g_legacy_render_isfinish_shadow;
    diag->render_d2d_rt_ptr = (payload_u64)&g_legacy_render_d2d_rt_shadow;
    diag->render_color_brush_ptr = (payload_u64)&g_legacy_render_color_brush_shadow;
    diag->render_text_format_ptr = (payload_u64)&g_legacy_render_text_format_shadow;
    diag->render_buffer0_ptr = (payload_u64)&g_legacy_render_buffer0_shadow;
    diag->render_buffer0_hva_ptr = (payload_u64)&g_legacy_render_buffer0_hva_shadow;
    diag->render_desc_buffer_ptr = (payload_u64)&g_legacy_render_desc_buffer_shadow;
    diag->render_desc_buffer_hva_ptr = (payload_u64)&g_legacy_render_desc_buffer_hva_shadow;
}

static void PayloadRedirectCachedLegacyPointersToShadows()
{
    PayloadRedirectLegacyDiagPointersToShadows(&g_cached_hv_diag);

    g_legacy_shadow_base = (payload_u64)&g_legacy_gamevt_image_base_shadow;
    g_legacy_shadow_size =
        ((payload_u64)&g_legacy_render_desc_buffer_hva_shadow + sizeof(g_legacy_render_desc_buffer_hva_shadow)) -
        g_legacy_shadow_base;
    g_legacy_shadow_count = 12;
    g_legacy_detach_flags |= PAYLOAD_LEGACY_DETACH_FLAG_GLOBAL_SHADOWS;
}

#pragma pack(push, 1)
struct payload_descriptor_register
{
    unsigned short limit;
    payload_u64 base;
};
#pragma pack(pop)

// Keep the bridge implementation in a separate include to keep payload.cpp
// focused on boot/runtime plumbing.  It is still one translation unit.
#include "payload_bridge.inl"

#pragma pack(push, 1)
struct payload_idt_entry
{
    unsigned short offset_low;
    unsigned short selector;
    unsigned char ist;
    unsigned char type_attr;
    unsigned short offset_middle;
    unsigned int offset_high;
    unsigned int reserved;
};
#pragma pack(pop)

struct payload_trap_frame
{
    payload_u64 rax;
    payload_u64 rcx;
    payload_u64 rdx;
    payload_u64 rbx;
    payload_u64 rbp;
    payload_u64 rsi;
    payload_u64 rdi;
    payload_u64 r8;
    payload_u64 r9;
    payload_u64 r10;
    payload_u64 r11;
    payload_u64 r12;
    payload_u64 r13;
    payload_u64 r14;
    payload_u64 r15;
    payload_u64 vector;
    payload_u64 error;
    payload_u64 rip;
    payload_u64 cs;
    payload_u64 rflags;
    payload_u64 rsp;
    payload_u64 ss;
};

__declspec(align(0x1000)) static payload_idt_entry g_payload_host_idt[256] = {};

static void PayloadSetHostIdtGate(unsigned int vector, void* handler, unsigned short selector)
{
    if (vector >= 256 || !handler || !selector)
        return;

    payload_u64 offset = (payload_u64)handler;
    payload_idt_entry gate = {};
    gate.offset_low = (unsigned short)(offset & 0xFFFFu);
    gate.selector = selector;
    gate.ist = 0;
    gate.type_attr = 0x8E; // present, DPL0, 64-bit interrupt gate
    gate.offset_middle = (unsigned short)((offset >> 16) & 0xFFFFu);
    gate.offset_high = (unsigned int)((offset >> 32) & 0xFFFFFFFFu);
    gate.reserved = 0;
    g_payload_host_idt[vector] = gate;
}

static void PayloadPrepareHostIdt(unsigned short selector)
{
    PayloadZeroMemory(g_payload_host_idt, sizeof(g_payload_host_idt));
    PayloadSetHostIdtGate(0, PayloadHostInterrupt0, selector);
    PayloadSetHostIdtGate(1, PayloadHostInterrupt1, selector);
    PayloadSetHostIdtGate(2, PayloadHostInterrupt2, selector);
    PayloadSetHostIdtGate(3, PayloadHostInterrupt3, selector);
    PayloadSetHostIdtGate(4, PayloadHostInterrupt4, selector);
    PayloadSetHostIdtGate(5, PayloadHostInterrupt5, selector);
    PayloadSetHostIdtGate(6, PayloadHostInterrupt6, selector);
    PayloadSetHostIdtGate(7, PayloadHostInterrupt7, selector);
    PayloadSetHostIdtGate(8, PayloadHostInterrupt8, selector);
    PayloadSetHostIdtGate(10, PayloadHostInterrupt10, selector);
    PayloadSetHostIdtGate(11, PayloadHostInterrupt11, selector);
    PayloadSetHostIdtGate(12, PayloadHostInterrupt12, selector);
    PayloadSetHostIdtGate(13, PayloadHostInterrupt13, selector);
    PayloadSetHostIdtGate(14, PayloadHostInterrupt14, selector);
    PayloadSetHostIdtGate(16, PayloadHostInterrupt16, selector);
    PayloadSetHostIdtGate(17, PayloadHostInterrupt17, selector);
    PayloadSetHostIdtGate(18, PayloadHostInterrupt18, selector);
    PayloadSetHostIdtGate(19, PayloadHostInterrupt19, selector);
    PayloadSetHostIdtGate(20, PayloadHostInterrupt20, selector);
    PayloadSetHostIdtGate(30, PayloadHostInterrupt30, selector);
}

extern "C" void PayloadHandleHostInterrupt(payload_trap_frame* frame)
{
    if (!frame)
        return;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_host_exception_count);
    g_payload_host_exception_last_vector = frame->vector;
    g_payload_host_exception_last_rip = frame->rip;

    if (frame->vector == 2)
    {
        payload_u64 entry = 0;
        entry |= 2ull;       // NMI vector
        entry |= 2ull << 8;  // non-maskable interrupt
        entry |= 1ull << 31; // valid
        PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, entry);
        return;
    }

    if (frame->r10 && frame->r11)
    {
        frame->rip = frame->r10;
        auto e = (payload_host_exception_info*)frame->r11;
        e->exception_occurred = 1;
        e->vector = frame->vector;
        e->error = frame->error;
        frame->r10 = 0;
        frame->r11 = 0;
        return;
    }

    g_payload_misc_exit_last_action = 0x771ull;
    g_payload_misc_exit_last_vector = frame->vector;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);

    g_payload_vtpanic_last_frame = (payload_u64)frame;
    payload_u64 packed_exception =
        ((frame->vector & 0xFFull) |
         ((frame->error & 0xFFFFFFFFull) << 8));
    payload_u64 vcpu_index = PayloadCurrentVcpuIndex();
    if (vcpu_index < 64)
    {
        auto ctx = (payload_guest_context*)g_payload_host_panic_resume_rsp[vcpu_index];
        payload_u64 landing_rip = g_payload_host_panic_resume_rip[vcpu_index];
        g_payload_host_panic_landing_last_index = vcpu_index;
        g_payload_host_panic_landing_last_rsp = (payload_u64)ctx;
        g_payload_host_panic_landing_last_rip = landing_rip;
        if (ctx &&
            landing_rip &&
            PayloadBridgeScheduleGuestBugCheck(
                ctx,
                PAYLOAD_VTPANIC_REASON_ROOT_EXCEPTION,
                frame->rip,
                packed_exception,
                (payload_u64)frame))
        {
            frame->rip = (payload_u64)&PayloadHostPanicLanding;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_host_panic_landing_count);
            return;
        }
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_host_panic_landing_fail_count);
    if (PayloadVtPanicBugCheck(
        PAYLOAD_VTPANIC_REASON_ROOT_EXCEPTION,
        frame->rip,
        packed_exception,
        (payload_u64)frame))
    {
        return;
    }

    // TestDriver fallback: if KeBugCheckEx could not be resolved, an unhandled
    // root-mode exception must still not iret back to the same faulting RIP.
    // Known recoverable probes set r10/r11 and are handled above; everything
    // else remains fail-stop.
    payload_descriptor_register idtr = {};
    idtr.base = frame->rsp;
    idtr.limit = 0x0FFF;
    PayloadLoadIdtr(&idtr);
}

extern "C" payload_u64 PayloadInstallHostIdt(payload_u64 mode)
{
    if (mode != PAYLOAD_HOST_IDT_MODE_INSTALL)
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    payload_u64 selector = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_HOST_CS_SELECTOR, &selector) || !(selector & 0xFFFFull))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_host_idt_fail_count);
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    PayloadPrepareHostIdt((unsigned short)(selector & 0xFFFFull));
    payload_u64 base = (payload_u64)&g_payload_host_idt[0];
    if (!PayloadVmwrite(PAYLOAD_VMCS_HOST_IDTR_BASE, base))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_host_idt_fail_count);
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    g_payload_host_idt_last_base = base;
    g_payload_misc_exit_last_action = 0x770ull;
    g_payload_misc_exit_last_vector = selector & 0xFFFFull;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_host_idt_install_count);
    return PAYLOAD_RESULT_OK;
}

static payload_u64 PayloadReadGlobalU64Or(payload_u64 ptr_to_global, payload_u64 fallback)
{
    if (!PayloadIsKernelPointer(ptr_to_global))
        return fallback;
    payload_u64 value = 0;
    if (PayloadReadSystemVa64(ptr_to_global, &value))
        return value;
    return fallback;
}

static unsigned char PayloadReadGlobalU8Or(payload_u64 ptr_to_global, unsigned char fallback)
{
    if (!PayloadIsKernelPointer(ptr_to_global))
        return fallback;
    if (!g_system_cr3 || !PayloadIsCanonical(ptr_to_global))
        return fallback;

    payload_u64 pa = 0;
    payload_u64 bytes_left = 0;
    if (!PayloadGvaToGpa(g_system_cr3, ptr_to_global, &pa, &bytes_left) ||
        bytes_left < sizeof(unsigned char) ||
        !PayloadHostPhysicalRangeMapped(pa, sizeof(unsigned char)))
    {
        return fallback;
    }

    return *(volatile unsigned char*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pa);
}

static bool PayloadCopySystemVaToOwned(void* dst, payload_u64 src_va, payload_u64 size)
{
    if (!dst || !src_va || !size || !g_system_cr3 || !PayloadIsCanonical(src_va))
        return false;

    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 pa = 0;
        payload_u64 left = 0;
        if (!PayloadGvaToGpa(g_system_cr3, src_va + done, &pa, &left) ||
            !left ||
            !PayloadHostPhysicalRangeMapped(pa, 1))
        {
            return false;
        }

        payload_u64 remain = size - done;
        payload_u64 chunk = left < remain ? left : remain;
        if (!PayloadHostPhysicalRangeMapped(pa, chunk))
            return false;

        PayloadCopyMemory((unsigned char*)dst + done,
            (const void*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pa),
            chunk);
        done += chunk;
    }

    return true;
}

extern "C" payload_u64 PayloadAdoptPoolBlocks(
    const payload_pool_block* blocks,
    payload_u64 count,
    payload_u64 flags)
{
    UNREFERENCED_PARAMETER(flags);

    constexpr payload_u64 kMaxResidentPoolBlocks = 4096;
    g_resident_pool_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;

    if (!blocks || !count || count > kMaxResidentPoolBlocks)
        return g_resident_pool_last_result;

    payload_u64 bytes = count * (payload_u64)sizeof(payload_pool_block);
    if (!bytes || (bytes / sizeof(payload_pool_block)) != count)
        return g_resident_pool_last_result;

    payload_pool_block* dst = (payload_pool_block*)g_resident_pool_manifest;
    if (!dst || g_resident_pool_capacity < count)
    {
        dst = (payload_pool_block*)PayloadArenaAlloc(bytes, 16);
        if (!dst)
        {
            g_resident_pool_last_result = PAYLOAD_RESULT_ALLOC_FAILED;
            return g_resident_pool_last_result;
        }

        g_resident_pool_manifest = (payload_u64)dst;
        g_resident_pool_capacity = count;
        g_runtime.arena_used = g_arena_used;
    }

    PayloadZeroMemory(dst, g_resident_pool_capacity * (payload_u64)sizeof(payload_pool_block));
    PayloadCopyMemory(dst, blocks, bytes);

    payload_u64 total = 0;
    payload_u64 independent = 0;
    payload_u64 fallback = 0;
    for (payload_u64 i = 0; i < count; ++i)
    {
        if (dst[i].va && dst[i].bytes)
            total += dst[i].bytes;
        if (dst[i].flags & PAYLOAD_POOL_BLOCK_FLAG_INDEPENDENT)
            independent++;
        if (dst[i].flags & PAYLOAD_POOL_BLOCK_FLAG_FALLBACK)
            fallback++;
    }

    g_resident_pool_count = count;
    g_resident_pool_bytes = total;
    g_resident_pool_independent_count = independent;
    g_resident_pool_fallback_count = fallback;
    g_resident_pool_generation++;
    g_resident_pool_last_result = PAYLOAD_RESULT_OK;
    g_runtime.generation++;
    g_runtime.arena_used = g_arena_used;
    return g_resident_pool_last_result;
}

extern "C" payload_u64 PayloadDetachLegacyData(payload_u64 mode)
{
    if (mode != PAYLOAD_LEGACY_DETACH_MODE_ARM)
    {
        g_legacy_detach_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        return g_legacy_detach_result;
    }

    if ((g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) &&
        g_legacy_ghv_copy &&
        g_legacy_ghv_size)
    {
        g_legacy_detach_result = PAYLOAD_RESULT_OK;
        return g_legacy_detach_result;
    }

    g_legacy_detach_result = PAYLOAD_RESULT_INVALID_CONTEXT;
    g_legacy_detach_flags = 0;

    if (!g_hv_diag_cache_ready ||
        g_cached_hv_diag.magic != MAPCTL_HV_DIAG_MAGIC ||
        !PayloadIsKernelPointer(g_cached_hv_diag.ghv) ||
        !g_cached_hv_diag.ghv_size ||
        g_cached_hv_diag.ghv_size < 0x1000ull ||
        g_cached_hv_diag.ghv_size > 0x4000000ull)
    {
        return g_legacy_detach_result;
    }

    PayloadDbgLock(&g_payload_dbg_watch_lock);
    bool dbg_watch_idle =
        (g_payload_dbg_watch_active_watches == 0) &&
        (g_payload_dbg_watch_active_pages == 0);
    PayloadDbgUnlock(&g_payload_dbg_watch_lock);
    if (!dbg_watch_idle)
        return g_legacy_detach_result;
    g_legacy_detach_flags |= PAYLOAD_LEGACY_DETACH_FLAG_DBGWATCH_IDLE;

    auto range_contains = [](payload_u64 base, payload_u64 bytes, payload_u64 ptr, payload_u64 size) -> bool
    {
        if (!base || !bytes || !ptr || !size)
            return false;
        payload_u64 end = ptr + size;
        payload_u64 limit = base + bytes;
        return end >= ptr && limit >= base && ptr >= base && end <= limit;
    };

    payload_u64 old_ghv = g_cached_hv_diag.ghv;
    if (!range_contains(g_arena_base, g_arena_size, old_ghv, g_cached_hv_diag.ghv_size))
    {
        // Final design: TestDriver must place ghv in the resident payload arena
        // before hv::start().  Do not copy a live multi-MB ghv block from VM-exit
        // context anymore; fail closed so freetest cannot release an image-owned ghv.
        return g_legacy_detach_result;
    }

    g_legacy_ghv_original = old_ghv;
    g_legacy_ghv_copy = old_ghv;
    g_legacy_ghv_size = g_cached_hv_diag.ghv_size;
    g_legacy_detach_flags |= PAYLOAD_LEGACY_DETACH_FLAG_GHV_COPY;

    payload_u64 vt_bytes = g_cached_hv_diag.vt_hook_table_bytes;
    if (!vt_bytes &&
        g_cached_hv_diag.vt_hook_slot_count &&
        g_cached_hv_diag.vt_hook_slot_size &&
        g_cached_hv_diag.vt_hook_slot_count <= 0x1000ull &&
        g_cached_hv_diag.vt_hook_slot_size <= 0x1000ull)
    {
        vt_bytes = g_cached_hv_diag.vt_hook_slot_count * g_cached_hv_diag.vt_hook_slot_size;
    }

    payload_u64 old_vt = g_cached_hv_diag.vt_hook_table_ptr;
    if (!PayloadIsKernelPointer(old_vt) ||
        !vt_bytes ||
        vt_bytes > 0x400000ull ||
        !range_contains(g_arena_base, g_arena_size, old_vt, vt_bytes))
    {
        return g_legacy_detach_result;
    }

    g_legacy_vt_hook_original = old_vt;
    g_legacy_vt_hook_copy = old_vt;
    g_legacy_vt_hook_size = vt_bytes;
    g_legacy_detach_flags |= PAYLOAD_LEGACY_DETACH_FLAG_VT_HOOK_COPY;

    // Do not dereference TestDriver image globals here.  Keep only values
    // already captured in the diag block or by payload PMO observation.  The
    // write pointers themselves intentionally stay as TestDriver's globals
    // until the second RELEASE/finalize step: the freetest CRT unload window
    // still needs SET_KEEP to update TestDriver::g_yvt_boot_flags so
    // Driver_Unload returns early.  After the wrapper has run, RELEASE is
    // called again and PayloadRedirectCachedLegacyPointersToShadows() makes all
    // late writes resident-owned before the image is actually freed.
    g_legacy_gamevt_image_base_shadow = g_cached_hv_diag.image_base;
    g_legacy_gamevt_driver_unload_shadow = g_cached_hv_diag.driver_unload;
    g_legacy_yvt_boot_flags_shadow = g_payload_keep_hv_flags;

    g_legacy_render_swapchain_shadow = g_payload_pmo_last_swapchain;
    g_legacy_render_isfinish_shadow = (unsigned char)(g_payload_pmo_last_isfinish ? 1 : 0);
    g_legacy_render_d2d_rt_shadow = g_payload_pmo_render_d2d_rt;
    g_legacy_render_color_brush_shadow = g_payload_pmo_render_brush;
    g_legacy_render_text_format_shadow = g_payload_pmo_render_textfmt;
    g_legacy_render_buffer0_shadow = g_payload_pmo_render_buf0;
    g_legacy_render_buffer0_hva_shadow = g_payload_pmo_render_buf0_hva;
    g_legacy_render_desc_buffer_shadow = g_payload_pmo_render_desc;
    g_legacy_render_desc_buffer_hva_shadow = g_payload_pmo_render_desc_hva;

    g_cached_hv_diag.image_base = g_legacy_gamevt_image_base_shadow;
    g_cached_hv_diag.driver_unload = g_legacy_gamevt_driver_unload_shadow;
    g_cached_hv_diag.size = sizeof(g_cached_hv_diag);
    g_cached_hv_diag.version = MAPCTL_HV_DIAG_LAYOUT_VERSION;

    g_payload_gamevt_image_base = g_legacy_gamevt_image_base_shadow;
    g_payload_gamevt_driver_unload = g_legacy_gamevt_driver_unload_shadow;
    g_payload_keep_hv_flags = g_legacy_yvt_boot_flags_shadow;

    g_legacy_shadow_base = (payload_u64)&g_legacy_gamevt_image_base_shadow;
    g_legacy_shadow_size =
        ((payload_u64)&g_legacy_render_desc_buffer_hva_shadow + sizeof(g_legacy_render_desc_buffer_hva_shadow)) -
        g_legacy_shadow_base;
    g_legacy_shadow_count = 12;
    g_legacy_detach_flags |= PAYLOAD_LEGACY_DETACH_FLAG_GLOBAL_SHADOWS;
    g_legacy_detach_flags |= PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE;
    g_legacy_detach_generation++;

    g_runtime.generation++;
    g_runtime.owned_alloc_count = g_owned_alloc_count;
    g_runtime.owned_alloc_bytes = g_owned_alloc_bytes;

    g_legacy_detach_result = PAYLOAD_RESULT_OK;
    PAYLOAD_LOG("[payload] PayloadDetachLegacyData complete flags=0x%llX ghv=0x%llX/0x%llX vt=0x%llX/0x%llX\n",
        g_legacy_detach_flags, g_legacy_ghv_copy, g_legacy_ghv_size, g_legacy_vt_hook_copy, g_legacy_vt_hook_size);
    return g_legacy_detach_result;
}

extern "C" payload_u64 PayloadActivateAmdSvm(payload_u64 mode)
{
    if ((mode != PAYLOAD_AMD_SVM_ACTIVATE_ARM &&
         mode != PAYLOAD_AMD_SVM_ACTIVATE_QUERY) ||
        !g_hv_diag_cache_ready ||
        (g_cached_hv_diag.flags & 2ull) == 0 ||
        !g_cached_hv_diag.ghv ||
        !g_cached_hv_diag.vcpus ||
        !g_cached_hv_diag.vcpu_count ||
        !g_cached_hv_diag.vcpu_stride ||
        !g_cached_hv_diag.vcpu_off_svm_resident_loop ||
        !g_cached_hv_diag.vcpu_off_svm_resident_ack ||
        (g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0 ||
        g_cached_hv_diag.ghv != g_legacy_ghv_copy ||
        g_cached_hv_diag.vt_hook_table_ptr != g_legacy_vt_hook_copy)
    {
        return 0;
    }

    return PayloadAmdResidentActivate(
        g_cached_hv_diag.ghv,
        g_cached_hv_diag.vt_hook_table_ptr,
        g_cached_hv_diag.vcpus,
        g_cached_hv_diag.vcpu_count,
        g_cached_hv_diag.vcpu_stride,
        g_cached_hv_diag.vcpu_off_svm_resident_loop,
        g_cached_hv_diag.vcpu_off_svm_resident_ack,
        mode);
}

// AMD-SVM does not have a VMCS HOST_RIP that can be redirected through the
// VMX bridge.  Once the resident VMRUN loop is active, its SVM exit dispatcher
// calls this image-local control entry for the three payload-owned hypercalls.
extern "C" payload_u64 PayloadAmdControlDispatch(
    payload_u64 code,
    payload_u64 arg1,
    payload_u64 arg2,
    payload_u64 arg3,
    payload_u64 arg4)
{
    UNREFERENCED_PARAMETER(arg3);
    UNREFERENCED_PARAMETER(arg4);

    switch (code)
    {
    case 91: // hypercall_get_payload_status
        if (!arg1 || arg2 < sizeof(payload_status))
            return 0;
        return PayloadGetStatus((void*)arg1);
    case 92: // hypercall_set_payload_mode
        switch (arg1)
        {
        case PAYLOAD_MODE_KIND_VTRET:
            return PayloadSetVtretMode(arg2);
        case PAYLOAD_MODE_KIND_TRAMP:
            return PayloadSetTrampMode(arg2);
        case PAYLOAD_MODE_KIND_HOOK:
            return PayloadSetHookMode(arg2);
        case PAYLOAD_MODE_KIND_EPT:
            return PayloadSetEptMode(arg2);
        case PAYLOAD_MODE_KIND_CUTOVER:
            return PayloadSetCutoverMode(arg2);
        case PAYLOAD_MODE_KIND_LEGACY_DETACH:
            return (g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE)
                ? PAYLOAD_RESULT_OK
                : PAYLOAD_RESULT_INVALID_CONTEXT;
        default:
            return PAYLOAD_RESULT_INVALID_CONTEXT;
        }
    case 93: // hypercall_payload_ping
        return PayloadPing(arg1);
    default:
        return 0;
    }
}

extern "C" payload_u64 PayloadSetVmExitTarget(payload_u64 target)
{
    if (g_payload_legacy_released && target)
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    if (!target)
    {
        g_payload_vmexit_target = 0;
        g_cached_hv_diag.vm_exit = 0;
        g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_VMEXIT_TRAMP_READY;
        g_runtime.generation++;
        return PAYLOAD_RESULT_OK;
    }

    g_vmexit_trampoline = (payload_u64)&PayloadVmExitTrampoline;
    g_payload_vmexit_target = target;
    g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_VMEXIT_TRAMP_READY;
    g_runtime.generation++;
    return PAYLOAD_RESULT_OK;
}

extern "C" payload_u64 PayloadSetVtretMode(payload_u64 mode)
{
    if (mode != PAYLOAD_VTRET_MODE_OBSERVE &&
        mode != PAYLOAD_VTRET_MODE_HANDLE_STRICT)
    {
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    g_payload_vtret_mode = mode;
    g_runtime.generation++;
    return PAYLOAD_RESULT_OK;
}

extern "C" payload_u64 PayloadSetTrampMode(payload_u64 mode)
{
    if (mode != PAYLOAD_TRAMP_MODE_OBSERVE &&
        mode != PAYLOAD_TRAMP_MODE_HANDLE)
    {
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    g_payload_tramp_mode = mode;
    g_runtime.generation++;
    return PAYLOAD_RESULT_OK;
}

extern "C" payload_u64 PayloadSetHookMode(payload_u64 mode)
{
    if (mode != PAYLOAD_HOOK_MODE_OBSERVE &&
        mode != PAYLOAD_HOOK_MODE_PASSTHROUGH)
    {
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    g_payload_hook_mode = mode;
    g_runtime.generation++;
    return PAYLOAD_RESULT_OK;
}

extern "C" payload_u64 PayloadSetEptMode(payload_u64 mode)
{
    if (mode != PAYLOAD_EPT_MODE_OBSERVE &&
        mode != PAYLOAD_EPT_MODE_HANDLE_TRAMP)
    {
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    g_payload_ept_mode = mode;
    g_runtime.generation++;
    return PAYLOAD_RESULT_OK;
}

static void PayloadDrainLegacyOldHandlerActive()
{
    for (payload_u64 spin = 0; spin < 0x100000ull; ++spin)
    {
        if (!g_payload_vmexit_old_handler_active_count)
            return;
        _mm_pause();
    }

    // Diagnostic only: this counter already represents VM-exit side wait/drain
    // pressure and is printed in status, so avoid an ABI bump for the short
    // freetest release wait path.
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_pending_release_wait_count);
}

extern "C" payload_u64 PayloadSetCutoverMode(payload_u64 mode)
{
    if (mode == PAYLOAD_CUTOVER_MODE_RELEASE)
    {
        payload_u64 already_released = g_payload_legacy_released ? 1ull : 0ull;
        // RELEASE is a short critical section for removing the legacy
        // TestDriver bridge/refs.  It must not become the steady-state
        // freetest mode: the PMO resident path checks g_payload_unload_quiesce
        // before running side effects/render init/GetBuffer install.  Leaving
        // it set after the second RELEASE makes status show pmo_handle > 0 but
        // pmo_sidefx/draw/gb_inst all stay 0, because every PMO hit only
        // passes through the trampoline.
        g_payload_unload_quiesce = 1;
        _InterlockedExchange64((volatile LONG64*)&g_payload_vmexit_bridge_target, 0);
        _InterlockedExchange64((volatile LONG64*)&g_payload_vmexit_target, 0);
        _InterlockedExchange64((volatile LONG64*)&g_payload_vmexit_bridge_saved_target, 0);
        _ReadWriteBarrier();
        PayloadDrainLegacyOldHandlerActive();
        g_payload_legacy_released = 1;
        _ReadWriteBarrier();
        g_cached_hv_diag.vm_exit = 0;
        g_cached_hv_diag.handle_vm_exit = 0;
        g_payload_gamevt_image_base = 0;
        g_payload_gamevt_driver_unload = 0;
        g_legacy_gamevt_image_base_shadow = 0;
        g_legacy_gamevt_driver_unload_shadow = 0;
        g_cached_hv_diag.image_base = 0;
        g_cached_hv_diag.driver_unload = 0;
        g_payload_keep_hv_flags &= ~PAYLOAD_YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
        g_legacy_yvt_boot_flags_shadow = g_payload_keep_hv_flags;
        g_payload_exbp_mode = PAYLOAD_EXBP_MODE_REINJECT;
        g_runtime.flags &= ~PAYLOAD_RUNTIME_FLAG_VMEXIT_TRAMP_READY;
        if (already_released)
        {
            g_payload_legacy_ptrs_finalized = 1;
            PayloadRedirectCachedLegacyPointersToShadows();
        }
        _ReadWriteBarrier();
        if (already_released && g_started)
            g_payload_unload_quiesce = 0;
        g_runtime.generation++;
        return PAYLOAD_RESULT_OK;
    }

    if (mode == PAYLOAD_CUTOVER_MODE_CLEAR)
    {
        payload_u64 old_target = g_payload_vmexit_bridge_target;
        if (old_target)
            g_payload_vmexit_bridge_saved_target = old_target;
        g_payload_vmexit_bridge_target = 0;
        g_runtime.generation++;
        return PAYLOAD_RESULT_OK;
    }

    if (mode == PAYLOAD_CUTOVER_MODE_RESTORE)
    {
        if (g_payload_legacy_released)
            return PAYLOAD_RESULT_INVALID_CONTEXT;

        payload_u64 target = g_payload_vmexit_bridge_saved_target;
        if (!target && g_cached_hv_diag.handle_vm_exit)
            target = g_cached_hv_diag.handle_vm_exit;
        if (!target)
            return PAYLOAD_RESULT_INVALID_CONTEXT;

        g_vmexit_bridge = (payload_u64)&PayloadVmExitBridge;
        g_payload_vmexit_bridge_target = target;
        g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_VMEXIT_BRIDGE_READY;
        g_runtime.generation++;
        return PAYLOAD_RESULT_OK;
    }

    return PAYLOAD_RESULT_INVALID_CONTEXT;
}

extern "C" payload_u64 PayloadSetHvDiag(const void* diag_in, payload_u64 size)
{
    auto diag = (const mapctl_hv_diag*)diag_in;
    const payload_u64 base_size = MAPCTL_HV_DIAG_BASE_U64_COUNT * sizeof(payload_u64);
    if (!diag || size < base_size || diag->magic != MAPCTL_HV_DIAG_MAGIC || diag->size < base_size)
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    payload_u64 copy_size = size;
    if (diag->size && diag->size < copy_size)
        copy_size = diag->size;
    if (copy_size > sizeof(g_cached_hv_diag))
        copy_size = sizeof(g_cached_hv_diag);

    mapctl_hv_diag next_diag = {};
    PayloadCopyMemory(&next_diag, diag, copy_size);
    next_diag.size = copy_size;

    if (g_payload_legacy_released)
    {
        next_diag.vm_exit = 0;
        next_diag.handle_vm_exit = 0;
        next_diag.image_base = 0;
        next_diag.driver_unload = 0;
        if (g_payload_legacy_ptrs_finalized)
            PayloadRedirectLegacyDiagPointersToShadows(&next_diag);
    }

    PayloadCopyMemory(&g_cached_hv_diag, &next_diag, sizeof(g_cached_hv_diag));

    g_hv_diag_vcpu_stride = 0;
    if (g_cached_hv_diag.vcpu_stride >= 0x100 && g_cached_hv_diag.vcpu_stride < 0x10000000)
        g_hv_diag_vcpu_stride = g_cached_hv_diag.vcpu_stride;
    if (g_cached_hv_diag.vcpus &&
        g_cached_hv_diag.current_vcpu != ~0ull &&
        g_cached_hv_diag.current_vcpu != 0 &&
        g_cached_hv_diag.current_vcpu_ptr > g_cached_hv_diag.vcpus &&
        !g_hv_diag_vcpu_stride)
    {
        payload_u64 stride = (g_cached_hv_diag.current_vcpu_ptr - g_cached_hv_diag.vcpus) / g_cached_hv_diag.current_vcpu;
        if (stride >= 0x100 && stride < 0x10000000)
            g_hv_diag_vcpu_stride = stride;
    }

    if (!g_payload_legacy_released)
    {
        g_payload_gamevt_image_base = g_cached_hv_diag.image_base;
        g_payload_gamevt_driver_unload = g_cached_hv_diag.driver_unload;
    }

    // Do not dereference TestDriver/global pointers here.  legacy arm runs
    // after TestDriver state may already be quarantined/rebased into the
    // resident arena; direct host VA reads from the payload export path can
    // fault before switchbridge/handoff.  Keep the cached diag and payload's
    // own boot/runtime values; later bridge code can refresh volatile values
    // through guarded VM-exit paths.

    // PMO resident CallUser temporarily uses payload-owned host stack slots for
    // return #BP VM-exits.  Because we no longer force-switch RSP globally, map
    // that slab into HOST_CR3 here while the legacy hypercall path is still
    // available and we are not inside the hot PMO VM-exit path.
    if (g_host_stack_base && g_host_stack_size && !g_host_stack_mapped_in_host)
    {
        if (PayloadHvMapHostRangeRaw(g_host_stack_base, g_host_stack_size))
        {
            g_host_stack_mapped_in_host = 1;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_host_map_success_count);
        }
        else
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_host_map_fail_count);
        }
    }

    g_hv_diag_cache_ready = 1;
    g_runtime.generation++;
    PAYLOAD_LOG("[payload] PayloadSetHvDiag cached vcpus=%llu ghv=0x%llX/0x%llX host_rip=0x%llX host_rsp=0x%llX stack_mapped=%llu\n",
        g_cached_hv_diag.vcpu_count, g_cached_hv_diag.ghv, g_cached_hv_diag.ghv_size,
        g_cached_hv_diag.vmcs_host_rip, g_cached_hv_diag.vmcs_host_rsp, g_host_stack_mapped_in_host);
    return PAYLOAD_RESULT_OK;
}

extern "C" payload_u64 PayloadSetVmExitBridgeTarget(payload_u64 target)
{
    if (!target)
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    if (g_payload_legacy_released)
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    g_vmexit_bridge = (payload_u64)&PayloadVmExitBridge;
    g_payload_vmexit_bridge_target = target;
    g_payload_vmexit_bridge_saved_target = target;
    g_runtime.flags |= PAYLOAD_RUNTIME_FLAG_VMEXIT_BRIDGE_READY;
    g_runtime.generation++;
    PAYLOAD_LOG("[payload] PayloadSetVmExitBridgeTarget bridge=0x%llX target=0x%llX\n",
        g_vmexit_bridge, g_payload_vmexit_bridge_target);
    return PAYLOAD_RESULT_OK;
}

extern "C" VOID PayloadUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PayloadStop();
}

// VtBootstrapDriver 完成交接后，SCM 仍需要调用一个有效的 DriverUnload
// 才能解除 Bootstrap 映像。此叶函数位于 ResidentPayload，不引用 Bootstrap
// 数据，也不停止 AMD-SVM/VMX 驻留运行时；返回后 I/O Manager 即可释放旧映像。
extern "C" __declspec(noinline) VOID PayloadReleaseBootstrap(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

static payload_exports g_payload_exports = {
    PAYLOAD_EXPORT_MAGIC,
    PAYLOAD_ABI_VERSION,
    PayloadPing,
    PayloadStart,
    PayloadStop,
    PayloadGetStatus,
    PayloadSetVmExitTarget,
    PayloadSetVmExitBridgeTarget,
    PayloadSetHvDiag,
    PayloadSetVtretMode,
    PayloadSetTrampMode,
    PayloadSetHookMode,
    PayloadSetEptMode,
    PayloadDetachLegacyData,
    PayloadAdoptPoolBlocks,
    PayloadActivateAmdSvm,
    reinterpret_cast<payload_release_bootstrap_fn>(PayloadReleaseBootstrap),
};

extern "C" NTSTATUS PayloadEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    auto ctx = (payload_boot_context*)RegistryPath;
    if (!ctx || ctx->magic != PAYLOAD_BOOT_MAGIC || ctx->size < sizeof(payload_boot_context))
        return STATUS_INVALID_PARAMETER;

    g_driver_object = DriverObject;
    if (DriverObject)
        DriverObject->DriverUnload = PayloadUnload;

    ctx->exports = &g_payload_exports;
    ctx->status = PayloadStart(ctx);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverMain(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    return PayloadEntry(DriverObject, RegistryPath);
}
