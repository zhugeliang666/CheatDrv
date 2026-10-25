#pragma once

#include "payload_abi.h"

#define MAPCTL_NT_DEVICE_NAME   L"\\Device\\MapPayloadCtl"
#define MAPCTL_DOS_DEVICE_NAME  L"\\DosDevices\\MapPayloadCtl"
#define MAPCTL_USER_DEVICE_NAME L"\\\\.\\MapPayloadCtl"

#define PAYLOADCTL_NT_DEVICE_NAME   L"\\Device\\PayloadResidentCtl"
#define PAYLOADCTL_DOS_DEVICE_NAME  L"\\DosDevices\\PayloadResidentCtl"
#define PAYLOADCTL_USER_DEVICE_NAME L"\\\\.\\PayloadResidentCtl"

#define MAPCTL_IOCTL_STATUS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HANDOFF       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_FORCE_PAYLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_CLEAN_RUNTIME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_PAYLOAD_PING  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HV_PING       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HV_DIAG       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_MIGRATE_CHECK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HOST_RSP_SWITCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HOST_RSP_RESTORE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HOST_RIP_SWITCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8AA, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HOST_RIP_RESTORE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8AB, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HOST_BRIDGE_SWITCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8AC, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HOST_BRIDGE_RESTORE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8AD, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_FULL_UNLOAD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8AE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_VTRET_MODE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8AF, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_TRAMP_MODE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HOOK_MODE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_EPT_MODE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HANDOFF_DROPCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_CUTOVER        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_RELEASE_LEGACY_IMAGE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_LEGACY_DETACH  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_MEMCHECK       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_MEMORY_AUDIT         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_HOST_EXCEPTION_PROBE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_SMOKE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8BA, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAPCTL_IOCTL_LOAD_MACHENIKE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8BB, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAPCTL_MK_MODE_NONE       0ull
#define MAPCTL_MK_MODE_NORMAL     1ull // 正常加载驱动：创建符号链接/设备对象，不隐藏 Machenike 内存
#define MAPCTL_MK_MODE_MANUAL_MAP 2ull // 内存映射驱动：不创建符号链接/设备对象，直接启动服务并隐藏 Machenike 内存
#define MAPCTL_LOAD_MK_MAGIC      0x4D41504C444D4B31ull // MAPLDMK1
#define MAPCTL_LOAD_MK_ARM        0x41524D5F4C4D4B31ull // ARM_LMK1

#define MAPCTL_STATUS_MAGIC 0x4D415043544C3031ull // MAPCTL01
#define MAPCTL_HV_DIAG_MAGIC 0x4D41504856444731ull // MAPHVDG1
#define MAPCTL_HV_DIAG_BASE_U64_COUNT 17ull
#define MAPCTL_HV_DIAG_LAYOUT_VERSION 26ull
#define MAPCTL_MIGRATE_CHECK_MAGIC 0x4D41504D43484B31ull // MAPMCHK1
#define MAPCTL_HOST_RSP_SWITCH_MAGIC 0x4D41505253505731ull // MAPRSPW1
#define MAPCTL_HOST_RSP_SWITCH_ARM   0x41524D5F53575031ull // ARM_SWP1
#define MAPCTL_HOST_RIP_SWITCH_MAGIC 0x4D41505249505731ull // MAPRIPW1
#define MAPCTL_HOST_RIP_SWITCH_ARM   0x41524D5F52495031ull // ARM_RIP1
#define MAPCTL_FULL_UNLOAD_MAGIC     0x4D4150554E4C4431ull // MAPUNLD1
#define MAPCTL_FULL_UNLOAD_ARM       0x41524D5F554C4431ull // ARM_ULD1
#define MAPCTL_FULL_UNLOAD_DELETE_CONTROL 0x00000001ull
#define MAPCTL_FULL_UNLOAD_PREFLIGHT_ONLY 0x00000002ull
#define MAPCTL_FULL_UNLOAD_STOP_LEGACY_ONLY 0x00000004ull
#define MAPCTL_VTRET_MODE_MAGIC      0x4D41505654523131ull // MAPVTR11
#define MAPCTL_VTRET_MODE_ARM        0x41524D5F56545231ull // ARM_VTR1
#define MAPCTL_TRAMP_MODE_MAGIC      0x4D415054524D3131ull // MAPTRM11
#define MAPCTL_TRAMP_MODE_ARM        0x41524D5F54524D31ull // ARM_TRM1
#define MAPCTL_HOOK_MODE_MAGIC       0x4D4150484B4D3131ull // MAPHKM11
#define MAPCTL_HOOK_MODE_ARM         0x41524D5F484B4D31ull // ARM_HKM1
#define MAPCTL_EPT_MODE_MAGIC        0x4D41504550543131ull // MAPEPT11
#define MAPCTL_EPT_MODE_ARM          0x41524D5F45505431ull // ARM_EPT1
#define MAPCTL_CUTOVER_MAGIC         0x4D41504355544F31ull // MAPCUTO1
#define MAPCTL_CUTOVER_ARM           0x41524D5F43555431ull // ARM_CUT1
#define MAPCTL_RELEASE_LEGACY_IMAGE_MAGIC       0x4D41504654455331ull // MAPFTES1
#define MAPCTL_RELEASE_LEGACY_IMAGE_ARM         0x41524D5F46544531ull // ARM_FTE1
#define MAPCTL_LEGACY_DETACH_MAGIC   0x4D41504C44455431ull // MAPLDET1
#define MAPCTL_LEGACY_DETACH_ARM     0x41524D5F4C445431ull // ARM_LDT1
#define MAPCTL_MEMCHECK_MAGIC        0x4D41504D43484D31ull // MAPMCHM1
#define MAPCTL_MEMORY_AUDIT_MAGIC          0x4D41504D4D545331ull // MAPMMTS1
#define MAPCTL_HOST_EXCEPTION_PROBE_MAGIC     0x4D41504858455431ull // MAPHXET1
#define MAPCTL_HOST_EXCEPTION_PROBE_ARM       0x41524D5F48584531ull // ARM_HXE1
#define MAPCTL_SMOKE_MAGIC           0x4D4150534D4F4B31ull // MAPSMOK1
#define MAPCTL_SMOKE_MARKER          0x4D4D4E4F4F505631ull // MMNOOPV1

#define MAPCTL_MEMORY_AUDIT_KIND_AUTO        0ull
#define MAPCTL_MEMORY_AUDIT_KIND_IMAGE       1ull
#define MAPCTL_MEMORY_AUDIT_KIND_ARENA       2ull
#define MAPCTL_MEMORY_AUDIT_KIND_DIRECT      3ull
#define MAPCTL_MEMORY_AUDIT_KIND_HOST_STACK  4ull
#define MAPCTL_MEMORY_AUDIT_KIND_POOL_FIRST  5ull

#define MAPCTL_MEMORY_AUDIT_OP_MMCM_VA       0x00000001ull
#define MAPCTL_MEMORY_AUDIT_OP_MMCM_PA       0x00000002ull
#define MAPCTL_MEMORY_AUDIT_OP_MMCVM         0x00000004ull
#define MAPCTL_MEMORY_AUDIT_OP_MMISAV        0x00000008ull
#define MAPCTL_MEMORY_AUDIT_OP_MMMIO         0x00000010ull
#define MAPCTL_MEMORY_AUDIT_OP_MMISAVEX      0x00000020ull
#define MAPCTL_MEMORY_AUDIT_OP_NTQVM         0x00000040ull
#define MAPCTL_MEMORY_AUDIT_OP_MMGPA         0x00000080ull
#define MAPCTL_MEMORY_AUDIT_OP_PEEK          0x00000100ull
#define MAPCTL_MEMORY_AUDIT_OP_STATUS_ONLY   0x00000200ull
#define MAPCTL_MEMORY_AUDIT_OP_STATUS_TWICE  0x00000400ull
#define MAPCTL_MEMORY_AUDIT_OP_FIRST_BATCH   (MAPCTL_MEMORY_AUDIT_OP_MMCM_VA | MAPCTL_MEMORY_AUDIT_OP_MMCM_PA | MAPCTL_MEMORY_AUDIT_OP_MMCVM | MAPCTL_MEMORY_AUDIT_OP_MMISAV | MAPCTL_MEMORY_AUDIT_OP_MMMIO)
#define MAPCTL_MEMORY_AUDIT_OP_ALL           (MAPCTL_MEMORY_AUDIT_OP_FIRST_BATCH | MAPCTL_MEMORY_AUDIT_OP_MMISAVEX | MAPCTL_MEMORY_AUDIT_OP_NTQVM | MAPCTL_MEMORY_AUDIT_OP_MMGPA)
#define MAPCTL_MEMORY_AUDIT_OP_NOOP          0x8000000000000000ull
#define MAPCTL_MEMORY_AUDIT_NOT_RUN          0xFFFFFFFFFFFFFFFFull

#define MAPCTL_MEMCHECK_FLAG_IMAGE        0x00000001ull // Payload PE .text 完整页集合
#define MAPCTL_MEMCHECK_FLAG_DIRECT       0x00000002ull
#define MAPCTL_MEMCHECK_FLAG_ARENA_USED   0x00000004ull
#define MAPCTL_MEMCHECK_FLAG_HOST_STACK   0x00000008ull
#define MAPCTL_MEMCHECK_FLAG_POOL_BLOCKS  0x00000010ull
#define MAPCTL_MEMCHECK_FLAG_REPAIR       0x00000020ull
#define MAPCTL_MEMCHECK_FLAG_ARENA_FULL   0x00000040ull
#define MAPCTL_MEMCHECK_FLAG_DATA_DEFAULT (MAPCTL_MEMCHECK_FLAG_ARENA_USED | MAPCTL_MEMCHECK_FLAG_HOST_STACK | MAPCTL_MEMCHECK_FLAG_POOL_BLOCKS)
#define MAPCTL_MEMCHECK_FLAG_FULL_DATA    (MAPCTL_MEMCHECK_FLAG_ARENA_FULL | MAPCTL_MEMCHECK_FLAG_HOST_STACK | MAPCTL_MEMCHECK_FLAG_POOL_BLOCKS)
#define MAPCTL_MEMCHECK_FLAG_ALL          (MAPCTL_MEMCHECK_FLAG_IMAGE | MAPCTL_MEMCHECK_FLAG_DIRECT | MAPCTL_MEMCHECK_FLAG_FULL_DATA)

#define MAPCTL_MEMCHECK_KIND_NONE       0ull
#define MAPCTL_MEMCHECK_KIND_IMAGE      1ull
#define MAPCTL_MEMCHECK_KIND_DIRECT     2ull
#define MAPCTL_MEMCHECK_KIND_ARENA_USED 3ull
#define MAPCTL_MEMCHECK_KIND_HOST_STACK 4ull
#define MAPCTL_MEMCHECK_KIND_POOL_BLOCK 5ull
#define MAPCTL_MEMCHECK_KIND_ARENA_FULL 6ull

#define MAPCTL_MIGRATE_CHECK_PAYLOAD_READY      0x00000001ull
#define MAPCTL_MIGRATE_CHECK_HV_DIAG_READY      0x00000002ull
#define MAPCTL_MIGRATE_CHECK_OLD_RIP_IS_VMEXIT  0x00000004ull
#define MAPCTL_MIGRATE_CHECK_OLD_RSP_IN_STACK   0x00000008ull
#define MAPCTL_MIGRATE_CHECK_PAYLOAD_STACK_READY 0x00000010ull
#define MAPCTL_MIGRATE_CHECK_VCPU_COUNT_FITS    0x00000020ull
#define MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD     0x00000040ull
#define MAPCTL_MIGRATE_CHECK_VMEXIT_TRAMP_READY 0x00000080ull
#define MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_TRAMP 0x00000100ull
#define MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_BRIDGE 0x00000200ull
#define MAPCTL_MIGRATE_CHECK_VMEXIT_BRIDGE_READY 0x00000400ull

struct mapctl_status
{
    payload_u64 magic;
    payload_u64 hv_ready;
    payload_u64 payload_detached;
    payload_u64 test_unloaded;
    payload_u64 test_quarantined;
    payload_u64 test_base;
    payload_u64 test_size;
    payload_u64 payload_base;
    payload_u64 payload_size;
    payload_u64 payload_exports;
    payload_u64 payload_independent;
    payload_u64 payload_external_refs;
    payload_u64 payload_barrier_ok;
    payload_status payload;
    payload_u64 machenike_loaded;
    payload_u64 machenike_mode;
    payload_u64 machenike_base;
    payload_u64 machenike_size;
};

struct mapctl_ping
{
    payload_u64 nonce;
    payload_u64 pong;
    payload_u64 result;
};

struct mapctl_hv_diag
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 version;
    payload_u64 current_vcpu;
    payload_u64 vcpu_count;
    payload_u64 ghv;
    payload_u64 vcpus;
    payload_u64 current_vcpu_ptr;
    payload_u64 vmcs_host_rip;
    payload_u64 vmcs_host_rsp;
    payload_u64 current_host_stack;
    payload_u64 host_stack_size;
    payload_u64 vm_exit;
    payload_u64 handle_vm_exit;
    payload_u64 image_base;
    payload_u64 driver_unload;
    payload_u64 flags;
    payload_u64 ghv_off_kpcr_prcb_offset;
    payload_u64 ghv_off_kprcb_current_thread_offset;
    payload_u64 ghv_off_kthread_apc_state_offset;
    payload_u64 ghv_off_kapc_state_process_offset;
    payload_u64 ghv_off_vtcallstack_list;
    payload_u64 ghv_off_tramp_pool;
    payload_u64 ghv_off_dbg;
    payload_u64 ghv_off_dbg_events;
    payload_u64 ghv_off_dbg_watch;
    payload_u64 vcpu_stride;
    payload_u64 vcpu_off_ept;
    payload_u64 vcpu_off_ept_free_pages;
    payload_u64 vcpu_off_ept_free_page_pfns;
    payload_u64 vcpu_off_ept_hook_active_list;
    payload_u64 vcpu_off_dbg_pending;
    payload_u64 ghv_off_affinity_lock_enabled;
    payload_u64 ghv_off_diag_hide_enter;
    payload_u64 ghv_off_diag_hide_pte_total;
    payload_u64 ghv_off_diag_hide_pte_null;
    payload_u64 ghv_off_diag_hide_done_bitmap;
    payload_u64 vcpu_off_ept_num_used_free_pages;
    payload_u64 vcpu_off_ept_dummy_page_pfn;
    payload_u64 ept_free_page_count;
    payload_u64 gamevt_image_base_ptr;
    payload_u64 gamevt_driver_unload_ptr;
    payload_u64 yvt_boot_flags_ptr;
    payload_u64 system_eprocess;
    payload_u64 kprocess_directory_table_base_offset;
    payload_u64 eprocess_unique_process_id_offset;
    payload_u64 ghv_off_cr3_map_real_cr3;
    payload_u64 vt_hook_table_ptr;
    payload_u64 vt_hook_slot_count;
    payload_u64 vt_hook_slot_size;
    payload_u64 vt_hook_slot_off_data_address;
    payload_u64 vt_hook_slot_off_data_type;
    payload_u64 vt_hook_slot_off_data_blank_memory;
    payload_u64 vt_hook_slot_off_data_dispatch_mode;
    payload_u64 vt_hook_slot_off_occupied;
    payload_u64 vt_hook_slot_off_trampoline_va;
    payload_u64 vt_hook_slot_off_bp_rip;
    payload_u64 vt_hook_slot_off_target_resume;
    payload_u64 render_swapchain_ptr;
    payload_u64 render_isfinish_ptr;
    payload_u64 ghv_off_dwm_hit_count;
    payload_u64 ghv_off_diag_handler_count;
    payload_u64 render_d2d_rt_ptr;
    payload_u64 render_color_brush_ptr;
    payload_u64 render_text_format_ptr;
    payload_u64 render_buffer0_ptr;
    payload_u64 render_buffer0_hva_ptr;
    payload_u64 render_desc_buffer_ptr;
    payload_u64 render_desc_buffer_hva_ptr;
    payload_u64 ghv_off_kthread_affinity_offset;
    payload_u64 ghv_off_kthread_user_affinity_offset;
    payload_u64 ghv_off_kthread_ideal_processor_offset;
    payload_u64 ghv_off_kthread_user_ideal_processor_offset;
    payload_u64 vcpu_off_pending_state;
    payload_u64 vcpu_off_pending_host_rsp_restore;
    payload_u64 vcpu_off_pending_vtcallstack_node;
    payload_u64 vcpu_off_pending_release_delay;
    payload_u64 ghv_size;
    payload_u64 vt_hook_table_bytes;
    payload_u64 ntapi_virtual_alloc;
    payload_u64 ntapi_read_process_memory;
    payload_u64 ntapi_virtual_lock;
    payload_u64 ntapi_d2d1_create_factory;
    payload_u64 ntapi_dwrite_create_factory;
    payload_u64 ob_reference_object_by_handle_va;
    payload_u64 obf_dereference_object_va;
    payload_u64 ntapi_file_name_offset;
    payload_u64 ghv_off_kernel_blank_va;
    payload_u64 ghv_off_csec_scratch_va;
    payload_u64 ghv_off_csec_format_va;
    payload_u64 ghv_off_stop_phase;
    payload_u64 ghv_off_stop_expected_bitmap;
    payload_u64 ghv_off_stop_requested_bitmap;
    payload_u64 ghv_off_stop_before_vmcall_bitmap;
    payload_u64 ghv_off_stop_after_vmcall_bitmap;
    payload_u64 ghv_off_stop_ack_bitmap;
    payload_u64 ghv_off_stop_exception_bitmap;
    payload_u64 ghv_off_stop_cleanup_bitmap;
    payload_u64 ghv_off_stop_last_cpu;
    payload_u64 ghv_off_stop_result;
    payload_u64 vt_hook_slot_off_data_process;
    payload_u64 vt_hook_slot_off_data_filter_by_process;
    payload_u64 vt_hook_slot_off_data_is_enable;
    payload_u64 ghv_off_prot_ranges;
    payload_u64 ghv_off_prot_range_count;
    payload_u64 ghv_prot_range_capacity;
    payload_u64 ghv_prot_range_stride;
    payload_u64 ghv_prot_range_off_base;
    payload_u64 ghv_prot_range_off_end;
    payload_u64 ghv_off_fake_data;
    payload_u64 ghv_off_diag_getbuffer_hits;
    payload_u64 ghv_off_diag_getbuffer_alien;
    payload_u64 ghv_off_diag_present_hits;
    payload_u64 ghv_off_diag_present_alien;
    payload_u64 ghv_off_diag_present1_hits;
    payload_u64 ghv_off_diag_present1_alien;
    payload_u64 ghv_off_diag_copyresource_hits;
    payload_u64 ghv_off_diag_copyresource_alien;
    payload_u64 ghv_off_diag_duplicateoutput_hits;
    payload_u64 ghv_off_diag_duplicateoutput_alien;
    payload_u64 ghv_off_diag_nt_alloc_hits;
    payload_u64 ghv_off_diag_nt_alloc_alien;
    payload_u64 ghv_off_diag_nt_protect_hits;
    payload_u64 ghv_off_diag_nt_protect_alien;
    payload_u64 ghv_off_diag_nt_map_hits;
    payload_u64 ghv_off_diag_nt_map_alien;
    payload_u64 ghv_off_diag_nt_csec_hits;
    payload_u64 ghv_off_diag_nt_csec_image;
    payload_u64 ghv_off_diag_nt_csec_alien;
    payload_u64 ghv_off_diag_capture_notify_count;
    payload_u64 ghv_off_diag_mmcopy_hits;
    payload_u64 ghv_off_diag_mmcopy_last_caller_rip;
    payload_u64 ghv_off_diag_mmcm_hits;
    payload_u64 ghv_off_diag_mmcm_blocked;
    payload_u64 ghv_off_diag_mmcvm_hits;
    payload_u64 ghv_off_diag_mmcvm_blocked;
    payload_u64 ghv_off_diag_mmisav_hits;
    payload_u64 ghv_off_diag_mmisav_blocked;
    payload_u64 ghv_off_diag_mmmio_hits;
    payload_u64 ghv_off_diag_mmmio_blocked;
    payload_u64 dwmcore_base;
    payload_u64 dwmcore_size;
    payload_u64 dxgi_base;
    payload_u64 dxgi_size;
    payload_u64 ghv_off_ept_hook_table;
    payload_u64 ghv_off_pending_ept_install_entries;
    payload_u64 ghv_off_pending_ept_install_bitmap;
    payload_u64 ghv_off_diag_pending_queue_full;
    payload_u64 ghv_pending_install_capacity;
    payload_u64 ept_hook_table_off_lock;
    payload_u64 ept_hook_table_off_in_use_count;
    payload_u64 ept_hook_table_off_active_list_head;
    payload_u64 ept_hook_table_off_free_list_head;
    payload_u64 ept_hook_table_off_buffer;
    payload_u64 ept_hook_table_off_fake_pages;
    payload_u64 ept_hook_table_off_fake_page_pfns;
    payload_u64 ept_hook_table_capacity;
    payload_u64 ept_hook_entry_size;
    payload_u64 ept_hook_entry_off_next;
    payload_u64 ept_hook_entry_off_process;
    payload_u64 ept_hook_entry_off_process_cr3;
    payload_u64 ept_hook_entry_off_va;
    payload_u64 ept_hook_entry_off_orig_pfn;
    payload_u64 ept_hook_entry_off_fake_pfn;
    payload_u64 ept_hook_entry_off_fake_page_idx;
    payload_u64 ept_hook_entry_off_in_use;
    payload_u64 ept_hook_entry_off_is_fake_page;
    payload_u64 ept_hook_entry_off_per_vcpu_active_bitmap;
    payload_u64 nt_create_section_va;
    payload_u64 nt_set_event_va;
    payload_u64 nt_allocate_virtual_memory_va;
    payload_u64 nt_protect_virtual_memory_va;
    payload_u64 nt_map_view_of_section_va;
    payload_u64 mm_copy_memory_va;
    payload_u64 mm_copy_virtual_memory_va;
    payload_u64 mm_is_address_valid_va;
    payload_u64 mm_map_io_space_va;
    payload_u64 mm_is_address_valid_ex_va;
    payload_u64 nt_query_virtual_memory_va;
    payload_u64 mm_get_physical_address_va;
    payload_u64 ghv_off_copyresource_addr;
    payload_u64 ghv_off_duplicateoutput_addr;
    payload_u64 vcpu_off_ctx;
    payload_u64 ghv_off_pending_ept_invept_bitmap;
    payload_u64 ghv_off_pending_hide_pfns;
    payload_u64 ghv_off_pending_hide_count;
    payload_u64 ghv_off_pending_hide_vcpu_bitmap;
    payload_u64 ghv_off_pending_hide_tsc_threshold;
    payload_u64 ghv_off_diag_per_vcpu_vmexits;
    payload_u64 vcpu_off_hide_vm_exit_overhead;
    payload_u64 vcpu_off_stop_virtualization;
    payload_u64 vcpu_off_ept_mmr_mtf_pte;
    payload_u64 vcpu_off_ept_mmr_mtf_mode;
    payload_u64 vcpu_off_ept_mmr_mtf_page_frame;
    payload_u64 vcpu_ept_hook_node_off_next;
    payload_u64 vcpu_ept_hook_node_off_orig_pfn;
    payload_u64 vcpu_ept_hook_node_off_exec_pfn;
    payload_u64 vcpu_ept_hook_node_off_is_fake_page;
    payload_u64 vcpu_off_svm_resident_loop;
    payload_u64 vcpu_off_svm_resident_ack;
};

struct mapctl_migration_check
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 flags;
    payload_u64 result;
    payload_status payload;
    mapctl_hv_diag diag;
};

struct mapctl_host_rsp_switch
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 flags;
    payload_u64 result;
    payload_u64 requested_count;
    payload_u64 switched_count;
    payload_u64 failed_index;
    payload_u64 last_new_rsp;
    payload_u64 last_old_rsp;
};

struct mapctl_host_rip_switch
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 flags;
    payload_u64 result;
    payload_u64 requested_count;
    payload_u64 switched_count;
    payload_u64 failed_index;
    payload_u64 last_new_rip;
    payload_u64 last_old_rip;
};

struct mapctl_full_unload
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 flags;
    payload_u64 result;
    payload_u64 hv_before;
    payload_u64 hv_after;
    payload_u64 keep_cleared;
    payload_u64 test_before;
    payload_u64 payload_before;
    payload_u64 test_after;
    payload_u64 payload_after;
    payload_u64 control_delete_queued;
    payload_u64 unhide_pfns;
    payload_u64 unhide_cpus;
    payload_u64 unhide_expected;
    payload_u64 unhide_done;
    payload_u64 unhide_ok;
    payload_u64 restore_rsp_requested;
    payload_u64 restore_rsp_done;
    payload_u64 restore_rsp_result;
    payload_u64 restore_rip_requested;
    payload_u64 restore_rip_done;
    payload_u64 restore_rip_result;
    payload_u64 selfstop_requested;
    payload_u64 selfstop_after;
    payload_u64 selfstop_ack;
    payload_u64 selfstop_exceptions;
    payload_u64 selfstop_result;
    payload_u64 pool_free_blocks;
    payload_u64 pool_free_bytes;
    payload_u64 pool_free_fail;
    payload_u64 test_unloaded_before_state;
    payload_u64 test_quarantined_before_state;
    payload_u64 test_unload_called_before_state;
    payload_u64 test_unloaded_after_stop;
    payload_u64 test_quarantined_after_stop;
    payload_u64 test_unload_called_after_stop;
    payload_u64 boot_flags_ptr;
    payload_u64 boot_flags_before;
    payload_u64 boot_flags_after;
    payload_u64 stop_phase;
    payload_u64 stop_result;
    payload_u64 stop_expected;
    payload_u64 stop_requested;
    payload_u64 stop_before_vmcall;
    payload_u64 stop_after_vmcall;
    payload_u64 stop_ack;
    payload_u64 stop_exception;
    payload_u64 stop_cleanup;
    payload_u64 stop_last_cpu;
};

struct mapctl_vtret_mode
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 mode;
    payload_u64 result;
    payload_u64 old_mode;
    payload_u64 new_mode;
    payload_status payload;
};

struct mapctl_tramp_mode
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 mode;
    payload_u64 result;
    payload_u64 old_mode;
    payload_u64 new_mode;
    payload_status payload;
};

struct mapctl_hook_mode
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 mode;
    payload_u64 result;
    payload_u64 old_mode;
    payload_u64 new_mode;
    payload_status payload;
};

struct mapctl_ept_mode
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 mode;
    payload_u64 result;
    payload_u64 old_mode;
    payload_u64 new_mode;
    payload_status payload;
};

struct mapctl_cutover
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 mode;
    payload_u64 result;
    payload_u64 old_target;
    payload_u64 new_target;
    payload_status payload;
};

struct mapctl_hostex_test
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 mode;
    payload_u64 result;
    payload_status before;
    payload_status after;
};

struct mapctl_free_test
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 flags;
    payload_u64 result;
    payload_u64 hv_ready;
    payload_u64 payload_detached;
    payload_u64 test_unloaded;
    payload_u64 test_quarantined;
    payload_u64 test_before;
    payload_u64 test_size_before;
    payload_u64 test_after;
    payload_u64 test_size_after;
    payload_u64 bridge;
    payload_u64 bridge_target;
    payload_u64 bridge_forward_count;
    payload_u64 vcpu_requested;
    payload_u64 vcpu_ready;
    payload_u64 failed_index;
    payload_u64 last_rip;
    payload_u64 last_rsp;
    payload_u64 legacy_detached;
    payload_u64 legacy_detach_flags;
    payload_u64 legacy_detach_result;
    payload_u64 scan_refs;
    payload_u64 scan_ghv_refs;
    payload_u64 scan_vth_refs;
    payload_u64 scan_shadow_refs;
    payload_u64 scan_first_range;
    payload_u64 scan_first_addr;
    payload_u64 scan_first_offset;
    payload_u64 scan_first_value;
    payload_u64 cutover_restore_result;
    payload_u64 cutover_clear_result;
    payload_u64 hostidt_requested;
    payload_u64 hostidt_ready;
    payload_u64 hostidt_failed_index;
    payload_u64 hostidt_result;
    payload_u64 crt_keep_result;
    payload_u64 crt_unload_called;
    payload_u64 free_phase;
    payload_status payload;
};

struct mapctl_legacy_detach
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 mode;
    payload_u64 result;
    payload_u64 old_flags;
    payload_u64 new_flags;
    payload_u64 ghv_original;
    payload_u64 ghv_copy;
    payload_u64 ghv_size;
    payload_u64 vt_hook_original;
    payload_u64 vt_hook_copy;
    payload_u64 vt_hook_size;
    payload_u64 shadow_base;
    payload_u64 shadow_size;
    payload_u64 shadow_count;
    payload_u64 stage;
    payload_u64 diag_copied;
    payload_u64 diag_magic;
    payload_u64 diag_version;
    payload_u64 diag_ghv;
    payload_u64 diag_ghv_size;
    payload_u64 diag_vt_hook;
    payload_u64 diag_vt_hook_bytes;
    payload_u64 export_table;
    payload_u64 export_flags;
    payload_status payload;
};

struct mapctl_memcheck
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 flags;
    payload_u64 result;
    payload_u64 observed_vcpu;
    payload_u64 dummy_pfn;
    payload_u64 range_count;
    payload_u64 pool_block_count;
    payload_u64 checked_pages;
    payload_u64 hidden_pages;
    payload_u64 visible_pages;
    payload_u64 unknown_pages;
    payload_u64 translate_fail;
    payload_u64 verify_fail;

    payload_u64 image_pages;
    payload_u64 image_hidden;
    payload_u64 image_visible;
    payload_u64 image_unknown;

    payload_u64 direct_pages;
    payload_u64 direct_hidden;
    payload_u64 direct_visible;
    payload_u64 direct_unknown;

    payload_u64 arena_pages;
    payload_u64 arena_hidden;
    payload_u64 arena_visible;
    payload_u64 arena_unknown;

    payload_u64 arena_full_pages;
    payload_u64 arena_full_hidden;
    payload_u64 arena_full_visible;
    payload_u64 arena_full_unknown;

    payload_u64 stack_pages;
    payload_u64 stack_hidden;
    payload_u64 stack_visible;
    payload_u64 stack_unknown;

    payload_u64 pool_pages;
    payload_u64 pool_hidden;
    payload_u64 pool_visible;
    payload_u64 pool_unknown;

    payload_u64 first_bad_kind;
    payload_u64 first_bad_va;
    payload_u64 first_bad_pfn;
    payload_u64 first_bad_ept_pfn;
    payload_u64 first_bad_pte;
    payload_u64 first_bad_index;

    payload_u64 max_pages;
    payload_u64 cursor_kind;
    payload_u64 cursor_index;
    payload_u64 cursor_page;
    payload_u64 next_kind;
    payload_u64 next_index;
    payload_u64 next_page;
    payload_u64 done;

    payload_status payload;
};

struct mapctl_mmtest
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 flags;
    payload_u64 result;

    payload_u64 target_kind;
    payload_u64 target_va;
    payload_u64 target_pa;
    payload_u64 target_size;

    payload_u64 before_mmcm_hits;
    payload_u64 before_mmcm_blocked;
    payload_u64 before_mmcvm_hits;
    payload_u64 before_mmcvm_blocked;
    payload_u64 before_mmisav_hits;
    payload_u64 before_mmisav_blocked;
    payload_u64 before_mmmio_hits;
    payload_u64 before_mmmio_blocked;
    payload_u64 before_ntqvm_hits;
    payload_u64 before_ntqvm_blocked;
    payload_u64 before_mmgpa_hits;
    payload_u64 before_mmgpa_blocked;

    payload_u64 after_mmcm_hits;
    payload_u64 after_mmcm_blocked;
    payload_u64 after_mmcvm_hits;
    payload_u64 after_mmcvm_blocked;
    payload_u64 after_mmisav_hits;
    payload_u64 after_mmisav_blocked;
    payload_u64 after_mmmio_hits;
    payload_u64 after_mmmio_blocked;
    payload_u64 after_ntqvm_hits;
    payload_u64 after_ntqvm_blocked;
    payload_u64 after_mmgpa_hits;
    payload_u64 after_mmgpa_blocked;

    payload_u64 mmcopy_virtual_status;
    payload_u64 mmcopy_virtual_bytes;
    payload_u64 mmcopy_virtual_qword;

    payload_u64 mmcopy_physical_status;
    payload_u64 mmcopy_physical_bytes;
    payload_u64 mmcopy_physical_qword;

    payload_u64 mmcvm_status;
    payload_u64 mmcvm_bytes;
    payload_u64 mmcvm_qword;

    payload_u64 mmisav_result;

    payload_u64 mmmio_va;
    payload_u64 mmmio_qword;

    payload_u64 mmisavex_result;

    payload_u64 ntqvm_status;
    payload_u64 ntqvm_return_length;
    payload_u64 ntqvm_qword;

    payload_u64 mmgpa_pa;
};

struct mapctl_smoke
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 result;
    payload_u64 marker;
    payload_u64 mmtest_noop_supported;
};

struct mapctl_load_machenike
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 arm;
    payload_u64 load_mode; // MAPCTL_MK_MODE_NORMAL (1) 或 MAPCTL_MK_MODE_MANUAL_MAP (2)
    payload_u64 result;
    payload_u64 machenike_base;
    payload_u64 machenike_size;
    unsigned char boot_config[1080]; // 容纳完整 DRV_BOOT_CONFIG_EX
};
