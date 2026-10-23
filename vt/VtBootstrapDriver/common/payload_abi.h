#pragma once

#define PAYLOAD_BOOT_MAGIC   0x504C44424F4F5431ull  // PLDBOOT1
#define PAYLOAD_API_MAGIC    0x504C444150493031ull  // PLDAPI01
#define PAYLOAD_EXPORT_MAGIC 0x504C444558504F31ull  // PLDEXPO1
#define PAYLOAD_PONG_MAGIC   0x504C44504F4E4731ull  // PLDPONG1
#define PAYLOAD_STATUS_MAGIC 0x504C445354415431ull  // PLDSTAT1
#define PAYLOAD_RUNTIME_MAGIC 0x504C4452544D3031ull // PLDRTM01
#define PAYLOAD_HOST_STATE_MAGIC 0x504C444853543031ull // PLDHST01
#define PAYLOAD_ABI_VERSION  86ull
#define PAYLOAD_RIP_HIST_SLOTS 8
#define PAYLOAD_VMEXIT_RING_SLOTS 16

#define PAYLOAD_STATE_READY   0x00000001ull
#define PAYLOAD_STATE_STARTED 0x00000002ull
#define PAYLOAD_STATE_STOPPED 0x00000004ull

#define PAYLOAD_BOOT_FLAG_PE_IMAGE  0x00000001ull
#define PAYLOAD_BOOT_FLAG_HOST_API  0x00000002ull
#define PAYLOAD_BOOT_FLAG_RAWPACK   0x00000004ull

#define PAYLOAD_RUNTIME_OWNER_NONE    0x00000000ull
#define PAYLOAD_RUNTIME_OWNER_PAYLOAD 0x00000001ull

#define PAYLOAD_RUNTIME_PHASE_ZERO    0x00000000ull
#define PAYLOAD_RUNTIME_PHASE_BOOT    0x00000001ull
#define PAYLOAD_RUNTIME_PHASE_STARTED 0x00000002ull
#define PAYLOAD_RUNTIME_PHASE_STOPPED 0x00000003ull
#define PAYLOAD_RUNTIME_PHASE_ERROR   0x00000004ull

#define PAYLOAD_RUNTIME_FLAG_CONTEXT_READY     0x00000001ull
#define PAYLOAD_RUNTIME_FLAG_IMAGE_CAPTURED    0x00000002ull
#define PAYLOAD_RUNTIME_FLAG_HOST_API_CAPTURED 0x00000004ull
#define PAYLOAD_RUNTIME_FLAG_STARTED           0x00000008ull
#define PAYLOAD_RUNTIME_FLAG_STOPPED           0x00000010ull
#define PAYLOAD_RUNTIME_FLAG_ARENA_READY       0x00000020ull
#define PAYLOAD_RUNTIME_FLAG_KERNEL_API_READY  0x00000040ull
#define PAYLOAD_RUNTIME_FLAG_BOOTSTRAP_SEALED  0x00000080ull
#define PAYLOAD_RUNTIME_FLAG_DIRECT_ALLOC_READY 0x00000100ull
#define PAYLOAD_RUNTIME_FLAG_SELF_ALLOC_READY  0x00000200ull
#define PAYLOAD_RUNTIME_FLAG_WORKER_API_READY  0x00000400ull
#define PAYLOAD_RUNTIME_FLAG_CONTROL_READY     0x00000800ull
#define PAYLOAD_RUNTIME_FLAG_HOST_STATE_READY  0x00001000ull
#define PAYLOAD_RUNTIME_FLAG_HOST_STACK_READY  0x00002000ull
#define PAYLOAD_RUNTIME_FLAG_STACK_DESC_READY  0x00004000ull
#define PAYLOAD_RUNTIME_FLAG_VMEXIT_TRAMP_READY 0x00008000ull
#define PAYLOAD_RUNTIME_FLAG_VMEXIT_BRIDGE_READY 0x00010000ull
#define PAYLOAD_RUNTIME_FLAG_ERROR             0x80000000ull

#define PAYLOAD_HOST_API_FLAG_ALLOC   0x00000001ull
#define PAYLOAD_HOST_API_FLAG_FREE    0x00000002ull
#define PAYLOAD_HOST_API_FLAG_RESOLVE 0x00000004ull

#define PAYLOAD_KERNEL_API_FLAG_INDEPENDENT_PAGES 0x00000001ull
#define PAYLOAD_KERNEL_API_FLAG_THREAD_ROUTINES   0x00000002ull
#define PAYLOAD_KERNEL_API_FLAG_IO_ROUTINES       0x00000004ull

#define PAYLOAD_EXTERNAL_REF_NONE     0x00000000ull
#define PAYLOAD_EXTERNAL_REF_HOST_API 0x00000001ull

#define PAYLOAD_RESULT_OK              0x00000000ull
#define PAYLOAD_RESULT_STARTED         0x00000001ull
#define PAYLOAD_RESULT_ALREADY_STARTED 0x00000002ull
#define PAYLOAD_RESULT_STOPPED         0x00000003ull
#define PAYLOAD_RESULT_INVALID_CONTEXT 0xC000000Dull
#define PAYLOAD_RESULT_THREAD_FAILED   0xC0000001ull
#define PAYLOAD_RESULT_ALLOC_FAILED    0xC0000017ull

#define PAYLOAD_HOST_STATE_FLAG_READY        0x00000001ull
#define PAYLOAD_HOST_STATE_FLAG_DIRECT_BLOCK 0x00000002ull
#define PAYLOAD_HOST_STATE_STAGE_PREPARED    0x00000001ull

#define PAYLOAD_HOST_STACK_SLOT_SIZE  0x10000ull
#define PAYLOAD_HOST_STACK_SLOT_COUNT 32ull
#define PAYLOAD_HOST_STACK_SLAB_SIZE  (PAYLOAD_HOST_STACK_SLOT_SIZE * PAYLOAD_HOST_STACK_SLOT_COUNT)

#define PAYLOAD_VTRET_MODE_OBSERVE       0ull
#define PAYLOAD_VTRET_MODE_HANDLE_STRICT 1ull

#define PAYLOAD_TRAMP_MODE_OBSERVE 0ull
#define PAYLOAD_TRAMP_MODE_HANDLE  1ull

#define PAYLOAD_HOOK_MODE_OBSERVE     0ull
#define PAYLOAD_HOOK_MODE_PASSTHROUGH 1ull

#define PAYLOAD_EPT_MODE_OBSERVE      0ull
#define PAYLOAD_EPT_MODE_HANDLE_TRAMP 1ull

#define PAYLOAD_EXBP_MODE_OBSERVE     0ull
#define PAYLOAD_EXBP_MODE_REINJECT    1ull

#define PAYLOAD_MODE_KIND_VTRET   1ull
#define PAYLOAD_MODE_KIND_TRAMP   2ull
#define PAYLOAD_MODE_KIND_HOOK    3ull
#define PAYLOAD_MODE_KIND_EPT     4ull
#define PAYLOAD_MODE_KIND_CUTOVER 5ull
#define PAYLOAD_MODE_KIND_LEGACY_DETACH 6ull
#define PAYLOAD_MODE_KIND_HOST_IDT 7ull
#define PAYLOAD_MODE_KIND_HOST_EXCEPTION 8ull

#define PAYLOAD_CUTOVER_MODE_RESTORE 0ull
#define PAYLOAD_CUTOVER_MODE_CLEAR   1ull
#define PAYLOAD_CUTOVER_MODE_RELEASE 2ull

#define PAYLOAD_LEGACY_DETACH_MODE_ARM 1ull

#define PAYLOAD_AMD_SVM_ACTIVATE_ARM   1ull
#define PAYLOAD_AMD_SVM_ACTIVATE_QUERY 2ull

#define PAYLOAD_HOST_IDT_MODE_INSTALL 1ull
#define PAYLOAD_HOST_EXCEPTION_MODE_RDMSR_GP 1ull
#define PAYLOAD_HOST_EXCEPTION_MODE_UD2 2ull

#define PAYLOAD_POOL_BLOCK_FLAG_INDEPENDENT 0x00000001u
#define PAYLOAD_POOL_BLOCK_FLAG_FALLBACK    0x00000002u
#define PAYLOAD_POOL_ADOPT_FLAG_REPLACE     0x00000001ull

#define PAYLOAD_LEGACY_DETACH_FLAG_GHV_COPY        0x00000001ull
#define PAYLOAD_LEGACY_DETACH_FLAG_VT_HOOK_COPY    0x00000002ull
#define PAYLOAD_LEGACY_DETACH_FLAG_GLOBAL_SHADOWS  0x00000004ull
#define PAYLOAD_LEGACY_DETACH_FLAG_DBGWATCH_IDLE   0x00000008ull
#define PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE        0x8000000000000000ull

typedef unsigned long long payload_u64;

typedef payload_u64 (*payload_ping_fn)(payload_u64 nonce);
typedef payload_u64 (*payload_start_fn)(void* boot_context);
typedef payload_u64 (*payload_stop_fn)();
typedef payload_u64 (*payload_get_status_fn)(void* status_out);
typedef payload_u64 (*payload_set_vmexit_target_fn)(payload_u64 target);
typedef payload_u64 (*payload_set_vmexit_bridge_target_fn)(payload_u64 target);
typedef payload_u64 (*payload_set_hv_diag_fn)(const void* diag, payload_u64 size);
typedef payload_u64 (*payload_set_vtret_mode_fn)(payload_u64 mode);
typedef payload_u64 (*payload_set_tramp_mode_fn)(payload_u64 mode);
typedef payload_u64 (*payload_set_hook_mode_fn)(payload_u64 mode);
typedef payload_u64 (*payload_set_ept_mode_fn)(payload_u64 mode);
typedef payload_u64 (*payload_detach_legacy_data_fn)(payload_u64 mode);
struct payload_pool_block;
typedef payload_u64 (*payload_adopt_pool_blocks_fn)(
    const payload_pool_block* blocks,
    payload_u64 count,
    payload_u64 flags);
typedef payload_u64 (*payload_activate_amd_svm_fn)(payload_u64 mode);
typedef void* (*payload_host_alloc_fn)(payload_u64 size, payload_u64 tag);
typedef void (*payload_host_free_fn)(void* ptr);
typedef void* (*payload_host_resolve_fn)(const unsigned short* routine_name);

struct payload_pool_block
{
    payload_u64 va;
    payload_u64 bytes;
    unsigned int tag;
    unsigned int flags;
};

struct payload_host_api
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 abi_version;
    payload_u64 flags;
    payload_host_alloc_fn alloc;
    payload_host_free_fn free;
    payload_host_resolve_fn resolve_system_routine;
    payload_u64 kernel_flags;
    void* mm_allocate_independent_pages;
    void* mm_free_independent_pages;
    void* mm_set_page_protection;
    payload_u64 reserved0;
    payload_u64 reserved1;
};

struct payload_vmexit_ring_entry
{
    payload_u64 seq;
    payload_u64 reason;
    payload_u64 guest_rip;
    payload_u64 guest_rsp;
    payload_u64 guest_cr3;
    payload_u64 qualification;
    payload_u64 guest_linear;
    payload_u64 guest_physical;
    payload_u64 primary_exec;
    payload_u64 secondary_exec;
    payload_u64 interruption_info;
    payload_u64 interruption_error;
    payload_u64 vcpu_index;
    payload_u64 host_rsp;
    payload_u64 action;
    payload_u64 result;
};

struct payload_status
{
    payload_u64 magic;
    payload_u64 abi_version;
    payload_u64 state_flags;
    payload_u64 start_count;
    payload_u64 stop_count;
    payload_u64 ping_count;
    payload_u64 last_nonce;
    payload_u64 last_pong;
    payload_u64 last_result;
    payload_u64 heartbeat_count;
    payload_u64 worker_running;
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
    payload_u64 runtime_magic;
    payload_u64 runtime_owner;
    payload_u64 runtime_phase;
    payload_u64 runtime_flags;
    payload_u64 runtime_generation;
    payload_u64 runtime_context;
    payload_u64 direct_alloc_base;
    payload_u64 direct_alloc_size;
    payload_u64 owned_alloc_count;
    payload_u64 owned_alloc_bytes;
    payload_u64 host_state_base;
    payload_u64 host_state_size;
    payload_u64 host_state_magic;
    payload_u64 host_state_flags;
    payload_u64 host_state_stage;
    payload_u64 host_state_hv_pings;
    payload_u64 host_state_last_hv;
    payload_u64 host_stack_base;
    payload_u64 host_stack_size;
    payload_u64 host_stack_slot_size;
    payload_u64 host_stack_slot_count;
    payload_u64 host_stack_desc_base;
    payload_u64 host_stack_desc_count;
    payload_u64 host_stack_first_rsp;
    payload_u64 vmexit_trampoline;
    payload_u64 vmexit_target;
    payload_u64 vmexit_hits;
    payload_u64 vmexit_bridge;
    payload_u64 vmexit_bridge_target;
    payload_u64 vmexit_bridge_hits;
    payload_u64 vmexit_bridge_observe_count;
    payload_u64 vmexit_bridge_last_reason;
    payload_u64 vmexit_bridge_vmread_fail;
    payload_u64 vmexit_bridge_self_count;
    payload_u64 vmexit_bridge_self_last_code;
    payload_u64 vmexit_bridge_self_last_result;
    payload_u64 vmexit_bridge_forward_count;
    payload_u64 hv_diag_cache_ready;
    payload_u64 hv_diag_self_count;
    payload_u64 hv_diag_gva_fail;
    payload_u64 vmexit_bridge_self_ping;
    payload_u64 vmexit_bridge_self_diag;
    payload_u64 vmexit_bridge_self_map;
    payload_u64 vmexit_bridge_self_rsp;
    payload_u64 vmexit_bridge_self_rip;
    payload_u64 vmexit_bridge_rsp_last;
    payload_u64 vmexit_bridge_rsp_class;
    payload_u64 vmexit_bridge_rsp_payload_count;
    payload_u64 vmexit_bridge_rsp_external_count;
    payload_u64 system_cr3;
    payload_u64 host_map_success_count;
    payload_u64 host_map_fail_count;
    payload_u64 host_map_page_table_pages;
    payload_u64 vmexit_bridge_self_cpuid;
    payload_u64 vmexit_bridge_forward_last_reason;
    payload_u64 vmexit_bridge_forward_last_code;
    payload_u64 vmexit_bridge_forward_last_key;
    payload_u64 vmexit_bridge_forward_bad_key;
    payload_u64 vmexit_bridge_forward_unknown_code;
    payload_u64 vmexit_bridge_forward_non_vmcall;
    payload_u64 vmexit_bridge_self_hv_base;
    payload_u64 vmexit_bridge_self_vh_init_tramp_pool;
    payload_u64 vmexit_bridge_self_affinity_lock;
    payload_u64 vmexit_bridge_self_hide_diag;
    payload_u64 vmexit_bridge_self_hide_diag_fail;
    payload_u64 vmexit_bridge_self_hide_diag_max_used;
    payload_u64 ept_split_max_used;
    payload_u64 ept_split_capacity;
    payload_u64 ept_split_remaining;
    payload_u64 vmexit_bridge_self_hide_pfn_list;
    payload_u64 vmexit_bridge_self_hide_pfn_fail;
    payload_u64 vmexit_bridge_self_hide_pfn_requested;
    payload_u64 vmexit_bridge_self_hide_pfn_hidden;
    payload_u64 vmexit_bridge_self_hide_pfn_null;
    payload_u64 vmexit_bridge_self_hide_pfn_last_count;
    payload_u64 vmexit_bridge_self_hide_pfn_last_hidden;
    payload_u64 vmexit_bridge_self_hide_pfn_last_pfn;
    payload_u64 vmexit_bridge_self_hide_pfn_last_pte_va;
    payload_u64 vmexit_bridge_self_hide_pfn_last_pte_before;
    payload_u64 vmexit_bridge_self_hide_pfn_last_pte_after;
    payload_u64 vmexit_bridge_self_hide_pfn_last_vcpu;
    payload_u64 vmexit_bridge_forward_last_rax;
    payload_u64 vmexit_bridge_forward_last_guest_rip;
    payload_u64 vmexit_bridge_forward_last_qualification;
    payload_u64 vmexit_reason_hist[64];
    payload_u64 vmexit_forward_reason_hist[64];
    payload_u64 vmexit_bridge_self_rdmsr;
    payload_u64 vmexit_bridge_self_wrmsr;
    payload_u64 vmexit_bridge_self_msr_last;
    payload_u64 vmexit_exception_last_info;
    payload_u64 vmexit_exception_last_error;
    payload_u64 vmexit_exception_vector_hist[32];
    payload_u64 vmexit_ept_last_gpa;
    payload_u64 vmexit_ept_last_gla;
    payload_u64 vmexit_ept_last_qualification;
    payload_u64 vmexit_bp_last_rip;
    payload_u64 vmexit_bp_user_count;
    payload_u64 vmexit_bp_kernel_count;
    payload_u64 vmexit_bp_type_software_count;
    payload_u64 vmexit_bp_type_other_count;
    payload_u64 vmexit_forward_badkey_last_rip;
    payload_u64 vmexit_forward_nonvm_last_rip;
    payload_u64 vmexit_bp_rip_hist_addr[PAYLOAD_RIP_HIST_SLOTS];
    payload_u64 vmexit_bp_rip_hist_count[PAYLOAD_RIP_HIST_SLOTS];
    payload_u64 vmexit_badkey_rip_hist_addr[PAYLOAD_RIP_HIST_SLOTS];
    payload_u64 vmexit_badkey_rip_hist_count[PAYLOAD_RIP_HIST_SLOTS];
    payload_u64 vmexit_nonvm_rip_hist_addr[PAYLOAD_RIP_HIST_SLOTS];
    payload_u64 vmexit_nonvm_rip_hist_count[PAYLOAD_RIP_HIST_SLOTS];
    payload_u64 vtret_probe_count;
    payload_u64 vtret_match_count;
    payload_u64 vtret_scan_count;
    payload_u64 vtret_scan_fail_count;
    payload_u64 vtret_last_node;
    payload_u64 vtret_last_old_vt_rsp;
    payload_u64 vtret_last_rip;
    payload_u64 vtret_last_reason;
    payload_u64 vtret_last_process;
    payload_u64 vtret_last_thread;
    payload_u64 vtret_list_base;
    payload_u64 vtret_active_head;
    payload_u64 vtret_mode;
    payload_u64 vtret_strict_match_count;
    payload_u64 vtret_loose_match_count;
    payload_u64 vtret_handle_count;
    payload_u64 vtret_handle_fail_count;
    payload_u64 vtret_last_handle_result;
    payload_u64 tramp_mode;
    payload_u64 tramp_probe_count;
    payload_u64 tramp_match_count;
    payload_u64 tramp_scan_count;
    payload_u64 tramp_scan_fail_count;
    payload_u64 tramp_handle_count;
    payload_u64 tramp_handle_fail_count;
    payload_u64 tramp_last_reason;
    payload_u64 tramp_last_pool;
    payload_u64 tramp_last_slot;
    payload_u64 tramp_last_rip;
    payload_u64 tramp_last_tramp_va;
    payload_u64 tramp_last_target;
    payload_u64 tramp_last_kind;
    payload_u64 tramp_user_match_count;
    payload_u64 tramp_kernel_match_count;
    payload_u64 tramp_pool_base;
    payload_u64 tramp_user_slot_count;
    payload_u64 tramp_kernel_slot_count;
    payload_u64 tramp_user_ready;
    payload_u64 tramp_kernel_ready;
    payload_u64 hook_mode;
    payload_u64 hook_probe_count;
    payload_u64 hook_match_count;
    payload_u64 hook_scan_count;
    payload_u64 hook_scan_fail_count;
    payload_u64 hook_passthrough_count;
    payload_u64 hook_passthrough_fail_count;
    payload_u64 hook_last_reason;
    payload_u64 hook_last_rip;
    payload_u64 hook_last_tramp_va;
    payload_u64 hook_last_bp_rip;
    payload_u64 hook_last_target;
    payload_u64 hook_last_kind;
    payload_u64 hook_user_match_count;
    payload_u64 hook_kernel_match_count;
    payload_u64 hook_last_key;
    payload_u64 hook_last_rax;
    payload_u64 ept_mode;
    payload_u64 ept_tramp_probe_count;
    payload_u64 ept_tramp_match_count;
    payload_u64 ept_tramp_handle_count;
    payload_u64 ept_tramp_handle_fail_count;
    payload_u64 ept_tramp_scan_fail_count;
    payload_u64 ept_tramp_mtf_count;
    payload_u64 ept_tramp_mtf_fail_count;
    payload_u64 ept_tramp_last_reason;
    payload_u64 ept_tramp_last_gpa;
    payload_u64 ept_tramp_last_gla;
    payload_u64 ept_tramp_last_rip;
    payload_u64 ept_tramp_last_qualification;
    payload_u64 ept_tramp_last_pte_pa;
    payload_u64 ept_tramp_last_pte_before;
    payload_u64 ept_tramp_last_pte_after;
    payload_u64 ept_tramp_last_orig_pfn;
    payload_u64 ept_tramp_last_exec_pfn;
    payload_u64 ept_tramp_last_guest_page;
    payload_u64 ept_tramp_last_kind;
    payload_u64 ept_tramp_exec_count;
    payload_u64 ept_tramp_data_count;
    payload_u64 ept_tramp_same_count;
    payload_u64 ept_tramp_user_match_count;
    payload_u64 ept_tramp_kernel_match_count;
    payload_u64 ept_tramp_last_vcpu;
    payload_u64 ept_tramp_last_mtf_restore;
    payload_u64 ept_generic_match_count;
    payload_u64 ept_fake_match_count;
    payload_u64 ept_last_hook_node;
    payload_u64 ept_last_is_fake;
    payload_u64 vmexit_bridge_self_rdtsc;
    payload_u64 vmexit_bridge_self_rdtscp;
    payload_u64 vmexit_bridge_self_tsc_last;
    payload_u64 vmexit_bridge_self_tsc_aux;
    payload_u64 vmexit_bridge_self_tsc_fail;
    payload_u64 exbp_mode;
    payload_u64 exbp_probe_count;
    payload_u64 exbp_reinject_count;
    payload_u64 exbp_reinject_fail_count;
    payload_u64 exbp_guard_count;
    payload_u64 exbp_last_reason;
    payload_u64 exbp_last_rip;
    payload_u64 exbp_last_info;
    payload_u64 exbp_last_entry_info;
    payload_u64 exbp_last_instruction_length;
    payload_u64 misc_exit_probe_count;
    payload_u64 misc_exit_handle_count;
    payload_u64 misc_exit_fail_count;
    payload_u64 misc_exit_last_reason;
    payload_u64 misc_exit_last_action;
    payload_u64 misc_exit_last_vector;
    payload_u64 misc_exit_preempt_count;
    payload_u64 invlpg_probe_count;
    payload_u64 invlpg_handle_count;
    payload_u64 invlpg_fail_count;
    payload_u64 invlpg_last_gla;
    payload_u64 invlpg_last_vpid;
    payload_u64 invlpg_last_result;
    payload_u64 xsetbv_probe_count;
    payload_u64 xsetbv_handle_count;
    payload_u64 xsetbv_fail_count;
    payload_u64 xsetbv_gp_count;
    payload_u64 xsetbv_ud_count;
    payload_u64 xsetbv_last_reason;
    payload_u64 xsetbv_last_index;
    payload_u64 xsetbv_last_value;
    payload_u64 xsetbv_last_cr4;
    payload_u64 xsetbv_last_unsupported_mask;
    payload_u64 xsetbv_last_result;
    payload_u64 invd_probe_count;
    payload_u64 invd_handle_count;
    payload_u64 invd_fail_count;
    payload_u64 invd_gp_count;
    payload_u64 invd_last_dpl;
    payload_u64 invd_last_result;
    payload_u64 cr_probe_count;
    payload_u64 cr_handle_count;
    payload_u64 cr_fail_count;
    payload_u64 cr_gp_count;
    payload_u64 cr_last_reason;
    payload_u64 cr_last_qualification;
    payload_u64 cr_last_access;
    payload_u64 cr_last_register;
    payload_u64 cr_last_gpr;
    payload_u64 cr_last_value;
    payload_u64 vmexit_bridge_self_get_pa;
    payload_u64 vmexit_bridge_self_get_pa_fail;
    payload_u64 vmexit_bridge_self_get_pa_last_cr3;
    payload_u64 vmexit_bridge_self_get_pa_last_gva;
    payload_u64 vmexit_bridge_self_get_pa_last_gpa;
    payload_u64 vmexit_bridge_self_gamevt_get;
    payload_u64 vmexit_bridge_self_gamevt_save;
    payload_u64 vmexit_bridge_self_gamevt_fail;
    payload_u64 payload_gamevt_image_base;
    payload_u64 payload_gamevt_driver_unload;
    payload_u64 vmexit_bridge_self_keep_hv;
    payload_u64 payload_keep_hv_flags;
    payload_u64 vmexit_bridge_self_query_cr3;
    payload_u64 vmexit_bridge_self_query_cr3_fail;
    payload_u64 vmexit_bridge_self_query_cr3_last_pid;
    payload_u64 vmexit_bridge_self_query_cr3_last_cr3;
    payload_u64 vmexit_bridge_self_get_info;
    payload_u64 vmexit_bridge_self_get_info_fail;
    payload_u64 payload_real_cr3;
    payload_u64 vmexit_bridge_self_read_phys;
    payload_u64 vmexit_bridge_self_write_phys;
    payload_u64 vmexit_bridge_self_read_virt;
    payload_u64 vmexit_bridge_self_write_virt;
    payload_u64 vmexit_bridge_self_mem_fail;
    payload_u64 vmexit_bridge_self_mem_bytes;
    payload_u64 hook_pmo_forward_count;
    payload_u64 pmo_probe_count;
    payload_u64 pmo_match_count;
    payload_u64 pmo_handle_count;
    payload_u64 pmo_fail_count;
    payload_u64 pmo_last_reason;
    payload_u64 pmo_last_rip;
    payload_u64 pmo_last_tramp_va;
    payload_u64 pmo_last_target;
    payload_u64 pmo_last_swapchain;
    payload_u64 pmo_side_effect_count;
    payload_u64 pmo_last_old_swapchain;
    payload_u64 pmo_last_isfinish;
    payload_u64 pmo_render_d2d_rt;
    payload_u64 pmo_render_brush;
    payload_u64 pmo_render_textfmt;
    payload_u64 pmo_render_buf0;
    payload_u64 pmo_render_buf0_hva;
    payload_u64 pmo_render_desc;
    payload_u64 pmo_render_desc_hva;
    payload_u64 pmo_call_probe_count;
    payload_u64 pmo_call_return_count;
    payload_u64 pmo_call_fail_count;
    payload_u64 pmo_call_same_vcpu_count;
    payload_u64 pmo_call_cross_vcpu_count;
    payload_u64 pmo_call_cross_queue_count;
    payload_u64 pmo_call_cross_leak_count;
    payload_u64 pmo_call_last_reason;
    payload_u64 pmo_call_last_function;
    payload_u64 pmo_call_last_ret;
    payload_u64 pmo_call_last_blank;
    payload_u64 pmo_call_last_new_rsp;
    payload_u64 pmo_call_last_vcpu;
    payload_u64 pmo_vtret_match_count;
    payload_u64 pmo_vtret_handle_count;
    payload_u64 pmo_vtret_fail_count;
    payload_u64 pmo_vtret_last_node;
    payload_u64 pmo_vtret_last_rip;
    payload_u64 pmo_draw_probe_count;
    payload_u64 pmo_draw_ready_count;
    payload_u64 pmo_draw_done_count;
    payload_u64 pmo_draw_fail_count;
    payload_u64 pmo_draw_last_stage;
    payload_u64 pmo_draw_last_result;
    payload_u64 hook_resident_handle_count;
    payload_u64 hook_resident_fail_count;
    payload_u64 hook_last_type;
    payload_u64 hook_last_action;
    payload_u64 hook_last_retaddr;
    payload_u64 hook_last_result;
    payload_u64 getbuffer_hits;
    payload_u64 getbuffer_alien;
    payload_u64 getbuffer_substitute;
    payload_u64 getbuffer_pass;
    payload_u64 getbuffer_marker;
    payload_u64 getbuffer_install_probe;
    payload_u64 getbuffer_install_ok;
    payload_u64 getbuffer_install_fail;
    payload_u64 getbuffer_install_stage;
    payload_u64 getbuffer_install_target;
    payload_u64 getbuffer_install_blank;
    payload_u64 getbuffer_install_fake;
    payload_u64 getbuffer_install_tramp;
    payload_u64 getbuffer_install_slot;
    payload_u64 getbuffer_install_orig_pfn;
    payload_u64 getbuffer_install_exec_pfn;
    payload_u64 getbuffer_install_pending;
    payload_u64 getbuffer_install_drain_ok;
    payload_u64 getbuffer_install_drain_fail;
    payload_u64 getbuffer_install_native_reason;
    payload_u64 getbuffer_install_native_vcpu;
    payload_u64 getbuffer_install_native_vcpu_ptr;
    payload_u64 getbuffer_install_native_pte_va;
    payload_u64 getbuffer_install_native_pte_before;
    payload_u64 getbuffer_install_native_pte_pfn;
    payload_u64 getbuffer_install_native_used;
    payload_u64 getbuffer_install_native_free;
    payload_u64 getbuffer_install_native_node;
    payload_u64 present_hits;
    payload_u64 present_alien;
    payload_u64 present1_hits;
    payload_u64 present1_alien;
    payload_u64 copyresource_hits;
    payload_u64 copyresource_alien;
    payload_u64 duplicateoutput_hits;
    payload_u64 duplicateoutput_alien;
    payload_u64 ntsetevent_hits;
    payload_u64 nt_alloc_hits;
    payload_u64 nt_alloc_alien;
    payload_u64 nt_protect_hits;
    payload_u64 nt_protect_alien;
    payload_u64 nt_map_hits;
    payload_u64 nt_map_alien;
    payload_u64 capture_notify_count;
    payload_u64 mmcm_hits;
    payload_u64 mmcm_blocked;
    payload_u64 mmcvm_hits;
    payload_u64 mmcvm_blocked;
    payload_u64 mmisav_hits;
    payload_u64 mmisav_blocked;
    payload_u64 mmmio_hits;
    payload_u64 mmmio_blocked;
    payload_u64 ntqvm_hits;
    payload_u64 ntqvm_blocked;
    payload_u64 mmgpa_hits;
    payload_u64 mmgpa_blocked;
    payload_u64 mm4_install_probe;
    payload_u64 mm4_install_ok;
    payload_u64 mm4_install_fail;
    payload_u64 mm4_install_already;
    payload_u64 mm4_install_mask;
    payload_u64 mm4_install_fail_mask;
    payload_u64 mm4_install_last_type;
    payload_u64 mm4_install_last_stage;
    payload_u64 mm4_install_last_target;
    payload_u64 mm4_install_last_slot;
    payload_u64 mm4_install_last_pending;
    payload_u64 mm4_hit_last_type;
    payload_u64 mm4_hit_last_vcpu;
    payload_u64 mm4_hit_vcpu_bitmap;
    payload_u64 mm4_hit_vcpu0;
    payload_u64 mm4_hit_type18_last_vcpu;
    payload_u64 mm4_hit_type18_vcpu_bitmap;
    payload_u64 mm4_hit_type18_vcpu0;
    payload_u64 mm4_hit_type19_last_vcpu;
    payload_u64 mm4_hit_type19_vcpu_bitmap;
    payload_u64 mm4_hit_type19_vcpu0;
    payload_u64 mm4_hit_type20_last_vcpu;
    payload_u64 mm4_hit_type20_vcpu_bitmap;
    payload_u64 mm4_hit_type20_vcpu0;
    payload_u64 mm4_hit_type21_last_vcpu;
    payload_u64 mm4_hit_type21_vcpu_bitmap;
    payload_u64 mm4_hit_type21_vcpu0;
    payload_u64 pmo_device;
    payload_u64 pmo_context;
    payload_u64 pmo_surface;
    payload_u64 pmo_fake_texture;
    payload_u64 pmo_marker_texture;
    payload_u64 pmo_marker_ready;
    payload_u64 pmo_marker_stage;
    payload_u64 pmo_last_getbuffer_out;
    payload_u64 overlay_hide_until_tsc;
    payload_u64 dbg_watch_add_count;
    payload_u64 dbg_watch_remove_count;
    payload_u64 dbg_watch_violation_count;
    payload_u64 dbg_watch_event_count;
    payload_u64 dbg_watch_miss_count;
    payload_u64 dbg_watch_storm_disabled;
    payload_u64 dbg_watch_active_watches;
    payload_u64 dbg_watch_active_pages;
    payload_u64 dbg_watch_last_reason;
    payload_u64 dbg_watch_last_gpa;
    payload_u64 dbg_watch_last_gla;
    payload_u64 dbg_watch_last_rip;
    payload_u64 dbg_watch_last_qualification;
    payload_u64 dbg_watch_last_watch_id;
    payload_u64 dbg_watch_last_pte_va;
    payload_u64 dbg_watch_last_pte_before;
    payload_u64 dbg_watch_last_pte_after;
    payload_u64 dbg_watch_last_vcpu;
    payload_u64 dbg_watch_mtf_count;
    payload_u64 dbg_watch_mtf_fail_count;
    payload_u64 legacy_detached;
    payload_u64 legacy_detach_result;
    payload_u64 legacy_detach_flags;
    payload_u64 legacy_detach_generation;
    payload_u64 legacy_ghv_original;
    payload_u64 legacy_ghv_copy;
    payload_u64 legacy_ghv_size;
    payload_u64 legacy_vt_hook_original;
    payload_u64 legacy_vt_hook_copy;
    payload_u64 legacy_vt_hook_size;
    payload_u64 legacy_shadow_base;
    payload_u64 legacy_shadow_size;
    payload_u64 legacy_shadow_count;
    payload_u64 resident_pool_manifest;
    payload_u64 resident_pool_capacity;
    payload_u64 resident_pool_count;
    payload_u64 resident_pool_bytes;
    payload_u64 resident_pool_independent_count;
    payload_u64 resident_pool_fallback_count;
    payload_u64 resident_pool_generation;
    payload_u64 resident_pool_last_result;
    payload_u64 business_probe_count;
    payload_u64 business_tick_count;
    payload_u64 business_skip_count;
    payload_u64 business_fail_count;
    payload_u64 business_last_stage;
    payload_u64 business_last_reason;
    payload_u64 business_last_vcpu;
    payload_u64 business_last_guest_cr3;
    payload_u64 business_last_swapchain;
    payload_u64 business_last_draw_done;
    // Direct assembly-side count of actually calling the saved legacy
    // TestDriver VM-exit handler target.  Unlike vmexit_bridge_forward_count,
    // this increments immediately before `call g_payload_vmexit_bridge_target`.
    payload_u64 vmexit_bridge_old_handler_call_count;
    payload_u64 vmexit_bridge_pending_restore_count;
    payload_u64 vmexit_bridge_pending_release_count;
    payload_u64 vmexit_bridge_pending_release_wait_count;
    payload_u64 vmexit_bridge_pending_fail_count;
    payload_u64 vmexit_bridge_pending_node_nonzero_count;
    payload_u64 vmexit_bridge_pending_last_vcpu;
    payload_u64 vmexit_bridge_pending_last_state;
    payload_u64 vmexit_bridge_pending_last_rsp;
    payload_u64 vmexit_bridge_trace_scrub_count;
    payload_u64 vmexit_bridge_trace_scrub_fail_count;
    payload_u64 vmexit_bridge_trace_scrub_last_mask;
    payload_u64 trace_unload_vmexit_seen;
    payload_u64 trace_unload_probe_count;
    payload_u64 trace_unload_clean_count;
    payload_u64 trace_unload_fail_count;
    payload_u64 trace_unload_last_result;
    payload_u64 trace_unload_last_index;
    payload_u64 trace_unload_last_count;
    payload_u64 trace_unload_mm_unloaded_drivers;
    payload_u64 trace_unload_mm_last_unloaded_driver;
    payload_u64 trace_hash_vmexit_seen;
    payload_u64 trace_hash_probe_count;
    payload_u64 trace_hash_clean_count;
    payload_u64 trace_hash_fail_count;
    payload_u64 trace_hash_last_result;
    payload_u64 trace_hash_last_index;
    payload_u64 trace_hash_last_count;
    payload_u64 trace_hash_last_entry;
    payload_u64 trace_hash_bucket_list;
    payload_u64 trace_hash_cache_lock;
    payload_u64 vmexit_bridge_ctx_set_count;
    payload_u64 vmexit_bridge_ctx_set_fail_count;
    payload_u64 vmexit_bridge_ctx_set_last_vcpu;
    payload_u64 vmexit_bridge_ctx_set_last_ptr;
    payload_u64 vmexit_bridge_vcpu_reset_count;
    payload_u64 vmexit_bridge_vcpu_reset_fail_count;
    payload_u64 vmexit_bridge_legacy_invept_count;
    payload_u64 vmexit_bridge_legacy_invept_fail_count;
    payload_u64 vmexit_bridge_legacy_invept_last_bitmap;
    payload_u64 vmexit_bridge_legacy_install_count;
    payload_u64 vmexit_bridge_legacy_install_fail_count;
    payload_u64 vmexit_bridge_legacy_install_retire_count;
    payload_u64 vmexit_bridge_legacy_hide_count;
    payload_u64 vmexit_bridge_legacy_hide_fail_count;
    payload_u64 vmexit_bridge_legacy_hide_last_hidden;
    payload_u64 vmexit_bridge_legacy_mtf_count;
    payload_u64 vmexit_bridge_legacy_mtf_fail_count;
    payload_u64 vmexit_bridge_ept_misconfig_count;
    payload_u64 vmexit_bridge_ept_misconfig_last_gpa;
    payload_u64 vtpanic_mode;
    payload_u64 vtpanic_count;
    payload_u64 vtpanic_active;
    payload_u64 vtpanic_ke_bugcheck_ex;
    payload_u64 vtpanic_last_reason;
    payload_u64 vtpanic_last_param1;
    payload_u64 vtpanic_last_param2;
    payload_u64 vtpanic_last_param3;
    payload_u64 vtpanic_last_vmexit_reason;
    payload_u64 vtpanic_last_guest_rip;
    payload_u64 vtpanic_last_guest_cr3;
    payload_u64 vtpanic_last_guest_rsp;
    payload_u64 vtpanic_last_gla;
    payload_u64 vtpanic_last_gpa;
    payload_u64 vtpanic_last_qualification;
    payload_u64 vtpanic_last_error;
    payload_u64 vtpanic_last_frame;
    payload_u64 host_idt_install_count;
    payload_u64 host_idt_fail_count;
    payload_u64 host_idt_last_base;
    payload_u64 host_exception_count;
    payload_u64 host_exception_last_vector;
    payload_u64 host_exception_last_rip;
    payload_u64 host_panic_landing_count;
    payload_u64 host_panic_landing_fail_count;
    payload_u64 host_panic_landing_last_index;
    payload_u64 host_panic_landing_last_rsp;
    payload_u64 host_panic_landing_last_rip;
    payload_u64 vtpanic_selftest_fired;
    payload_u64 vtpanic_selftest_vmexit_seen;
    payload_u64 vtpanic_selftest_wait_kernel;
    payload_u64 vtpanic_selftest_schedule_fail;
    payload_u64 vtpanic_storm_count;
    payload_u64 vtpanic_storm_last_idx;
    payload_u64 vtpanic_storm_last_seen;
    payload_u64 vtpanic_storm_last_sig0;
    payload_u64 vtpanic_storm_last_sig1;
    payload_u64 vtpanic_deferred_pending;
    payload_u64 vtpanic_deferred_reason;
    payload_u64 vtpanic_deferred_param1;
    payload_u64 vtpanic_deferred_param2;
    payload_u64 vtpanic_deferred_param3;
    payload_u64 vmexit_ring_seq;
    payload_u64 vmexit_ring_next;
    payload_vmexit_ring_entry vmexit_ring[PAYLOAD_VMEXIT_RING_SLOTS];
};

struct payload_host_stack_descriptor
{
    payload_u64 index;
    payload_u64 stack_base;
    payload_u64 stack_limit;
    payload_u64 initial_rsp;
    payload_u64 flags;
    payload_u64 old_rsp;
    payload_u64 last_rsp;
    payload_u64 old_rip;
    payload_u64 last_rip;
};

struct payload_exports
{
    payload_u64 magic;
    payload_u64 abi_version;
    payload_ping_fn ping;
    payload_start_fn start;
    payload_stop_fn stop;
    payload_get_status_fn get_status;
    payload_set_vmexit_target_fn set_vmexit_target;
    payload_set_vmexit_bridge_target_fn set_vmexit_bridge_target;
    payload_set_hv_diag_fn set_hv_diag;
    payload_set_vtret_mode_fn set_vtret_mode;
    payload_set_tramp_mode_fn set_tramp_mode;
    payload_set_hook_mode_fn set_hook_mode;
    payload_set_ept_mode_fn set_ept_mode;
    payload_detach_legacy_data_fn detach_legacy_data;
    payload_adopt_pool_blocks_fn adopt_pool_blocks;
    payload_activate_amd_svm_fn activate_amd_svm;
};

struct payload_boot_context
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 status;
    payload_exports* exports;
    payload_u64 image_base;
    payload_u64 image_size;
    payload_u64 boot_flags;
    payload_host_api* host_api;
    payload_u64 arena_base;
    payload_u64 arena_size;
    payload_u64 arena_used;
    payload_u64 system_cr3;
    payload_u64 trace_unload_mm_unloaded_drivers;
    payload_u64 trace_unload_mm_last_unloaded_driver;
    payload_u64 trace_unload_name_bytes;
    payload_u64 trace_unload_delay_exits;
    payload_u64 trace_unload_interval_exits;
    payload_u64 trace_unload_max_attempts;
    payload_u64 trace_unload_name_qwords[8];
    payload_u64 trace_hash_bucket_list;
    payload_u64 trace_hash_cache_lock;
    payload_u64 trace_hash_delay_exits;
    payload_u64 trace_hash_interval_exits;
    payload_u64 trace_hash_max_attempts;
};
