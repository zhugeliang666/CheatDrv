#pragma once

#include "page-tables.h"
#include "hypercalls.h"
#include "logger.h"
#include "vmx.h"
#include "vcpu.h"
#include "ept-hook.h"
#include "ept-probe.h"
#include "debug-core.h"
#include "debug-events.h"
#include "debug-watch.h"
#include <ntddk.h>

namespace hv {

// signature that is returned by the ping hypercall
inline constexpr uint64_t hypervisor_signature = 'sb?d';

// VT log ring sizing (Stage 鈶).
inline constexpr uint32_t VT_LOG_ENTRY_SIZE  = 128;
inline constexpr uint32_t VT_LOG_ENTRY_COUNT = 512;
inline constexpr uint32_t VT_LOG_RING_BYTES  = VT_LOG_ENTRY_SIZE * VT_LOG_ENTRY_COUNT;

// Trampoline pool: each slot is a small run of 0xCC bytes inside ntdll
// (user hooks) or ntoskrnl (kernel hooks) .text padding. We claim 16 such
// slots per pool, each at most 16 bytes. The slot layout per occupied slot:
//
//     [oldByte 3..7B] [0xCC]
//
// Hit flow:
//   1) hook site (target_va) executes 0F 01 C1 (vmcall stub from fake_page)
//   2) handler runs; dispatcher rewrites GUEST_RIP = slot.tramp_va
//   3) CPU runs oldByte via the slot's exec-view 4KB EPT redirect
//   4) CPU hits the 0xCC; #BP -> vm-exit
//   5) #BP handler matches RIP against slot.bp_rip and rewrites
//      GUEST_RIP = slot.target_resume = target_va + oldByte_size, no inject
//
// Each slot's host-side state lives in tramp_slot below. A pool keeps an
// array of slots plus a per-pool list of distinct 4KB exec_pages (multiple
// slots in the same physical page share one EPT redirect and one exec_page).
inline constexpr uint32_t TRAMPOLINE_SLOT_BYTES  = 16;       // max bytes claimed per slot
inline constexpr uint32_t TRAMPOLINE_POOL_USER_SLOTS   = 16; // ntdll-backed, ring-3 hooks
inline constexpr uint32_t TRAMPOLINE_POOL_KERNEL_SLOTS = 16; // ntoskrnl-backed, ring-0 hooks
inline constexpr uint32_t TRAMPOLINE_MAX_PAGES_PER_POOL = 16; // distinct 4KB exec_pages per pool

struct tramp_slot {
    uint64_t tramp_va;       // guest VA where oldByte+0xCC starts (= GUEST_RIP after dispatcher)
    uint64_t bp_rip;         // tramp_va + oldByte_size + 1; CPU lands here after #BP advances RIP past 0xCC
    uint64_t target_resume;  // target_va + oldByte_size; what we rewrite GUEST_RIP to
    uint16_t page_index;     // index into pool's pages[] (which exec_page hosts this slot)
    uint16_t page_offset;    // byte offset within the exec_page where oldByte starts
    uint8_t  capacity;       // length of this 0xCC run (>= oldByte_size + 1 required)
    bool     occupied;
};

struct tramp_page {
    uint64_t guest_page_va;  // page-aligned VA inside ntdll/ntoskrnl
    uint64_t orig_pfn;       // original PFN (read view)
    uint64_t exec_pfn;       // our exec PFN
    uint64_t exec_hva;       // host VA of our exec_page (to write tramp bytes)
};

struct trampoline_pool {
    spin_lock lock;

    // User pool (ntdll-backed)
    tramp_slot user_slots[TRAMPOLINE_POOL_USER_SLOTS];
    tramp_page user_pages[TRAMPOLINE_MAX_PAGES_PER_POOL];
    uint32_t   user_slot_count;
    uint32_t   user_page_count;
    bool       user_ready;

    // Kernel pool (ntoskrnl-backed)
    tramp_slot kernel_slots[TRAMPOLINE_POOL_KERNEL_SLOTS];
    tramp_page kernel_pages[TRAMPOLINE_MAX_PAGES_PER_POOL];
    uint32_t   kernel_slot_count;
    uint32_t   kernel_page_count;
    bool       kernel_ready;
};

//protect process list
struct ghv_protect_list_node
{
    ghv_protect_list_node* next;
    uint64_t pid;
    uint64_t process;
};


struct ghv_protect_list
{
    static constexpr  size_t capacity = 100;
    ghv_protect_list_node buffer[capacity];

    ghv_protect_list_node* active_list_head;

    ghv_protect_list_node* free_list_head;
};


struct ghv_vtcall_list_node {

    ghv_vtcall_list_node* next;
    UINT64 process;
    UINT64 thread;
    UINT64 oldRip;
    UINT64 retRip;
    UINT64 oldRsp;
    UINT64 oldStack;
    UINT64 oldVtRsp;
    UINT64 newStack;
    guest_context* oldContext_ptr;
    guest_context  oldContext;
    guest_context* newContext_ptr;
    guest_context  newContext;
    char stack[0x400];
    int  cpu_number;   // vcpu index that owns this node 鈥 disambiguates
                       // find/remove when 2 vcpus hit the same hook (same
                       // retRip, same DWM process, possibly same thread).
    UINT64 saved_affinity;   // KAFFINITY snapshot taken at hv::Call entry,
                             // restored on cleanup. Locking guest thread to
                             // entry vCPU prevents cross-vCPU migration that
                             // corrupts vt_call_exit's stack/VMCS writes.
    UINT64 saved_user_affinity;   // UserAffinity.Mask snapshot
    UINT8  saved_ideal_processor; // IdealProcessor snapshot (BYTE)
    UINT8  saved_user_ideal_processor; // UserIdealProcessor snapshot (BYTE)

};

struct ghv_vtcall_list {

    static constexpr  size_t capacity = 20;
    ghv_vtcall_list_node buffer[capacity];
    ghv_vtcall_list_node* active_list_head;
    ghv_vtcall_list_node* free_list_head;

};

struct ghv_vtcallstack_node {
    ghv_vtcallstack_node* next;
    ULONG64 stack_ptr;
    char stack[host_stack_size];
    int cpu_number;
    ULONG64 old_stack_ptr;
};


struct ghv_vtcallstack_list {


    static constexpr size_t capacity = 32;   // was 16; bumped to absorb cross-vCPU
                                              // lazy-defer occupancy on top of normal
                                              // active hv::Calls. With pool=32 and
                                              // host_stack_size=0x10000, total inline
                                              // here is ~2MB 鈥 check pages_max budget.
    spin_lock lock;
    ghv_vtcallstack_node buffer[capacity];
    ghv_vtcallstack_node* active_list_head;
    ghv_vtcallstack_node* free_list_head;
};


struct ghv_cr3_monitor_thread_list_node
{
    ghv_cr3_monitor_thread_list_node* next;
    uint64_t process;
    uint64_t thread;

};
struct ghv_cr3_monitor_thread_list
{
    static constexpr  size_t capacity = 10;
    ghv_cr3_monitor_thread_list_node buffer[capacity];

    ghv_cr3_monitor_thread_list_node* active_list_head;

    ghv_cr3_monitor_thread_list_node* free_list_head;
};


struct ghv_module_range_info
{
    uint64_t lowAddress;
    uint64_t lowSize;
    uint64_t highAddress;
    uint64_t highSize;
};


struct ghv_cr3_map
{
    cr3 srcCr3;
    cr3 dstCr3;
    cr3 fakeCr3;
    PEPROCESS process;
    cr3 realCr3;
    PEPROCESS srcProcess;

    ULONG64 pml4e_index;

    ULONG64* pml4e;

    bool is_open;

};

struct hypervisor {
  // host page tables that are shared between vcpus
  host_page_tables host_page_tables;

  // logger that can be used in root-mode
  logger logger;
  alignas(0x1000) uint8_t dummy_page[0x1000];
  // dynamically allocated array of vcpus
  unsigned long vcpu_count;

  struct vcpu* vcpus;

  // pointer to the System process
  uint8_t* system_eprocess;

  // kernel CR3 value of the System process
  cr3 system_cr3;

  // windows specific offsets D:
  uint64_t kprocess_directory_table_base_offset;
  uint64_t eprocess_unique_process_id_offset;
  uint64_t eprocess_image_file_name;
  uint64_t kpcr_pcrb_offset;
  uint64_t kprcb_current_thread_offset;
  uint64_t kthread_apc_state_offset;
  uint64_t kapc_state_process_offset;
  uint64_t kthread_affinity_offset;
  uint64_t kthread_user_affinity_offset;
  uint64_t kthread_ideal_processor_offset;
  uint64_t kthread_user_ideal_processor_offset;



  ULONG SeAuditProcessCreationInfoOffset;
  ULONG BypassProcessFreezeFlagOffset;
  ULONG ThreadHideFromDebuggerFlagOffset;
  ULONG ThreadBreakOnTerminationFlagOffset;
  ULONG PicoContextOffset;
  ULONG RestrictSetThreadContextOffset;
  ULONG DbgSsReserved;


  //_TEB
  ULONG ClientId;
  ULONG SuppressDebugMsg;

  //_ETHREAD
  ULONG Win32StartAddress;
  ULONG StartAddress;
  ULONG RundownProtect;
  ULONG SameThreadPassiveFlags;
  ULONG SameThreadApcFlags;
  ULONG CrossThreadFlags;
  ULONG AllowKernelWritesToExecutableMemory;
  ULONG AllowUserWritesToExecutableMemory;
  ULONG ThreadListEntry;
  //_KTHREAD
  ULONG TrapFrame;
  ULONG UserTime;
  ULONG KernelTime;


  ULONG ApcState;
  //kprocess
  ULONG  DirectoryTableBase;

  //EPROCESS
  ULONG VadRoot;
  ULONG VadHint;
  ULONG ExitTime;
  ULONG Flags;
  ULONG SectionBaseAddress;
  ULONG SectionObject;
  ULONG RundownProtect_Process;
  ULONG DebugPort;
  ULONG InheritedFromUniqueProcessId;
  ULONG Peb;
  ULONG Ldr;

  //_PEB
  ULONG ProcessParameters;

  //_RTL_USER_PROCESS_PARAMETERS
  ULONG CurrentDirectory;


  //_CURDIR
  ULONG DosPath;



  //_KAPC_STATE
  ULONG Process;

  //_PEB_LDR_DATA
  ULONG InLoadOrderModuleList;

  spin_lock vtcall_lock;

  ghv_vtcall_list vtcall_list;

  ghv_vtcallstack_list vtcallstack_list;


  ghv_protect_list protect_list;

  ghv_cr3_monitor_thread_list cr3_monitor_list;

  ghv_module_range_info module_info;
  cr3_monitor g_cr3_monitor;
  bool is_cr3_monitor_open;
  bool is_check_thread;
  bool is_save_cr3;
  bool is_check_rip;
  
  ghv_cr3_map g_cr3_map;

  spin_lock cr3_monitor_lock;


  bool is_hide_vt;

  // Hit counter for dwm install/hit-detection verification (TEST MODE).
  // Incremented from host vmcall_hook_dispatch on every target hit; driver
  // polls this directly (ghv lives in upper-half PML4, accessible from both
  // root mode and the driver thread).
  volatile uint64_t dwm_hit_count;

  // TEST MODE diagnostics 鈥 host writes status codes from vmcall_vh_install /
  // vmcall_hook_dispatch path, driver reads & prints. Layout:
  //   install_status: 0=not called, 1=ok, 0x10=no cr3, 0x11=no slot,
  //                   0x12=disasm fail, 0x13=eh_install fail
  //   install_target_va / install_fake_target_va / install_fake_blank_va:
  //                   echo back what host computed
  //   dispatch_seen_rip: last guest RIP that entered vmcall_hook_dispatch
  //   dispatch_compared_addr: last slot.data.address compared
  volatile uint32_t dwm_install_status;
  volatile uint32_t dwm_install_pad;
  volatile uint64_t dwm_install_target_va;
  volatile uint64_t dwm_install_fake_target_va;
  volatile uint64_t dwm_install_fake_blank_va;
  volatile uint64_t dwm_dispatch_seen_rip;
  volatile uint64_t dwm_dispatch_compared_addr;

  // Host-owned EPT hook table (inline, no separate allocation).
  eh::ept_hook_table ept_hook_table;

  // Host-owned generic EPT probe table.  This is intentionally separate from
  // ept_hook_table/tramp_pool so ad-hoc register probes do not mutate the
  // existing hook dispatch state.
  ept_probe_table probe_table;

  // Host-owned debug framework state.  Phase-1 only owns sessions/stat counters;
  // it does not mutate EPT hook/probe state.
  dbg_state dbg;

  // Host-owned debug event ring.  Producers only append fixed records; polling
  // is routed through dbg_dispatch and never touches legacy EPT hook state.
  dbg_event_ring dbg_events;

  // Host-owned debug EPT watch state.  This is separate from ept_hook_table and
  // probe_table; watched pages are handled before legacy find_ept_hook().
  dbg_watch_state dbg_watch;

  // Trampoline pool for race-free hook dispatch (no fake_page mutation).
  trampoline_pool tramp_pool;
  static constexpr uint32_t TRAMP_PREALLOC_PAGE_COUNT =
    TRAMPOLINE_MAX_PAGES_PER_POOL * 2;
  uint64_t tramp_prealloc_pages[TRAMP_PREALLOC_PAGE_COUNT];
  volatile uint32_t tramp_prealloc_count;
  volatile uint32_t tramp_prealloc_next;

  // Diagnostic step counters 鈥 host root mode bumps these. Diag thread polls
  // to know how far we got before VT-layer crash. Host can safely write to
  // these (they're inline in ghv, mapped in host page tables).
  volatile uint64_t diag_dispatch_count;    // vmcall_hook_dispatch entered
  volatile uint64_t diag_handler_count;     // game::handle_present_multiplane_overlay entered
  volatile uint64_t diag_init_enter_count;  // render::init entered
  volatile uint64_t diag_init_done_count;   // render::init isFinish=true reached
  volatile uint64_t diag_tick_count;        // render::tick entered
  volatile uint64_t diag_tick_draw_count;   // BeginDraw reached (before DrawFilledRect)
  volatile uint64_t diag_tick_end_count;    // EndDraw returned (full tick frame done)

  // Anti-screenshot hook hit counters (2026-05-23). Each hook handler bumps
  // its slot every time it fires; *_alien is incremented only when the
  // caller classified as alien (anti-cheat injected into DWM).
  volatile uint64_t diag_getbuffer_hits;       // GetBuffer hook total fires
  volatile uint64_t diag_getbuffer_alien;      // GetBuffer alien-caller fires
  volatile uint64_t diag_present_hits;         // Present hook total fires
  volatile uint64_t diag_present_alien;        // Present alien-caller fires
  volatile uint64_t diag_present1_hits;        // Present1 hook total fires
  volatile uint64_t diag_present1_alien;       // Present1 alien-caller fires
  volatile uint64_t diag_copyresource_hits;    // CopyResource hook total fires
  volatile uint64_t diag_copyresource_alien;   // CopyResource alien-caller fires
  volatile uint64_t diag_duplicateoutput_hits; // DuplicateOutput hook total fires
  volatile uint64_t diag_duplicateoutput_alien;// DuplicateOutput alien-caller fires
  volatile uint64_t diag_marker_ready;         // 1 once markerTexture cleared OK

  // Stage 鈶 kernel-hook diagnostics.
  volatile uint64_t diag_mmcopy_hits;          // MmCopyMemory hook fires
  volatile uint64_t diag_mmcopy_last_caller_rip; // last caller RIP seen
  volatile uint8_t  mmcopy_hook_installed;     // 0/1: handler installed it once
  volatile uint8_t  mmcopy_install_attempted; // 0/1: tried install at least once
  volatile uint8_t  mmcopy_install_result;    // 0=ok, 1=fail (vh_install_host returned false)
  volatile uint8_t  dwm_extra_hooks_installed; // 0/1: PMO handler installed GetBuffer/Present/Present1
  volatile uint8_t  ntsetevent_hook_installed; // 0/1: PMO handler installed NtSetEvent kernel hook
  // NtSetEvent install diagnostics
  volatile uint8_t  diag_ntse_install_attempted; // 1 = vh_install_host was called
  volatile uint8_t  diag_ntse_install_result;    // 1 = vh_install_host returned true
  volatile uint64_t diag_ntse_target_va;         // captured NtSetEvent_va at install time

  // Mouse in-place adjustment hook. EPT-hooks the original MouClass service
  // callback and edits only real movement packets before the original runs.
  volatile uint8_t  mouse_callback_hook_installed;
  volatile uint8_t  mouse_callback_install_attempted;
  volatile uint8_t  mouse_callback_install_result;
  volatile uint64_t diag_mouse_cb_target_va;
  volatile uint64_t diag_mouse_cb_hits;
  volatile uint64_t diag_mouse_cb_packets;
  volatile uint64_t diag_mouse_cb_modified;
  volatile uint64_t diag_mouse_cb_bad_args;
  volatile uint64_t diag_mouse_cb_last_device;
  volatile uint64_t diag_mouse_cb_expected_device;
  volatile uint64_t diag_mouse_cb_return_va;
  volatile uint64_t diag_mouse_cb_device_mismatch;
  volatile uint64_t diag_mouse_cb_movement_packets;
  volatile uint64_t diag_mouse_cb_zero_packets;
  volatile uint64_t diag_mouse_cb_last_start;
  volatile uint64_t diag_mouse_cb_last_end;
  volatile uint64_t diag_mouse_cb_last_count;
  volatile uint64_t diag_mouse_cb_last_flags;
  volatile int64_t  diag_mouse_cb_last_raw_x;
  volatile int64_t  diag_mouse_cb_last_raw_y;
  volatile int64_t  diag_mouse_cb_last_add_x;
  volatile int64_t  diag_mouse_cb_last_add_y;

  // MouHid_ReadComplete pre-call probe. The observed caller return address is
  // mouhid.sys + 0x3AA8, so the CFG indirect call instruction starts at
  // mouhid.sys + 0x3AA2. This probe runs before MouClassServiceCallback.
  volatile uint8_t  mouhid_pre_hook_installed;
  volatile uint8_t  mouhid_pre_install_attempted;
  volatile uint8_t  mouhid_pre_install_result;
  volatile uint8_t  mouhid_pre_signature_ok;
  volatile uint64_t diag_mouhid_base_va;
  volatile uint64_t diag_mouhid_size;
  volatile uint64_t diag_mouhid_pre_target_va;
  volatile uint64_t diag_mouhid_pre_hits;
  volatile uint64_t diag_mouhid_pre_packets;
  volatile uint64_t diag_mouhid_pre_movement_packets;
  volatile uint64_t diag_mouhid_pre_bad_args;
  volatile uint64_t diag_mouhid_pre_callback_va;
  volatile uint64_t diag_mouhid_pre_last_device;
  volatile uint64_t diag_mouhid_pre_last_start;
  volatile uint64_t diag_mouhid_pre_last_end;
  volatile uint64_t diag_mouhid_pre_last_count;
  volatile uint64_t diag_mouhid_pre_last_flags;
  volatile int64_t  diag_mouhid_pre_last_raw_x;
  volatile int64_t  diag_mouhid_pre_last_raw_y;
  volatile uint64_t diag_mouhid_pre_emulate_fail;

  // Read-only lower-stack probes for step testing without WinDbg/devstack.
  // type 24: mouhid.sys+0x3CB2, right before MouHid sends the read IRP to
  // the lower HID stack. RCX is the lower DeviceObject.
  volatile uint8_t  mouhid_down_hook_installed;
  volatile uint8_t  mouhid_down_install_attempted;
  volatile uint8_t  mouhid_down_install_result;
  volatile uint8_t  mouhid_down_signature_ok;
  volatile uint64_t diag_mouhid_down_target_va;
  volatile uint64_t diag_mouhid_down_hits;
  volatile uint64_t diag_mouhid_down_lower_device;
  volatile uint64_t diag_mouhid_down_lower_driver;
  volatile uint64_t diag_mouhid_down_driver_base;
  volatile uint64_t diag_mouhid_down_driver_size;
  volatile uint64_t diag_mouhid_down_name_hash;
  volatile uint64_t diag_mouhid_down_known_code;
  volatile uint64_t diag_mouhid_down_emulate_fail;

  // type 25: hidusb.sys+0x1485, right before HidUsb sends the IRP/URB to the
  // lower USB stack. RCX is the lower DeviceObject.
  volatile uint8_t  hidusb_down_hook_installed;
  volatile uint8_t  hidusb_down_install_attempted;
  volatile uint8_t  hidusb_down_install_result;
  volatile uint8_t  hidusb_down_signature_ok;
  volatile uint64_t diag_hidusb_base_va;
  volatile uint64_t diag_hidusb_size;
  volatile uint64_t diag_hidusb_down_target_va;
  volatile uint64_t diag_hidusb_down_hits;
  volatile uint64_t diag_hidusb_down_lower_device;
  volatile uint64_t diag_hidusb_down_lower_driver;
  volatile uint64_t diag_hidusb_down_driver_base;
  volatile uint64_t diag_hidusb_down_driver_size;
  volatile uint64_t diag_hidusb_down_name_hash;
  volatile uint64_t diag_hidusb_down_known_code;
  volatile uint64_t diag_hidusb_down_emulate_fail;

  // type 26: hidusb.sys+0x2D60, HumReadCompletion entry. Read-only capture
  // of IRP status and the USB interrupt transfer buffer pointer/length.
  volatile uint8_t  hidusb_comp_hook_installed;
  volatile uint8_t  hidusb_comp_install_attempted;
  volatile uint8_t  hidusb_comp_install_result;
  volatile uint8_t  hidusb_comp_signature_ok;
  volatile uint64_t diag_hidusb_comp_target_va;
  volatile uint64_t diag_hidusb_comp_hits;
  volatile uint64_t diag_hidusb_comp_bad_args;
  volatile uint64_t diag_hidusb_comp_device;
  volatile uint64_t diag_hidusb_comp_irp;
  volatile uint64_t diag_hidusb_comp_ctx;
  volatile uint64_t diag_hidusb_comp_status;
  volatile uint64_t diag_hidusb_comp_len;
  volatile uint64_t diag_hidusb_comp_buf;
  volatile uint64_t diag_hidusb_comp_mdl;
  volatile uint64_t diag_hidusb_comp_read_bytes;
  volatile uint64_t diag_hidusb_comp_first8;

  // anti-screenshot: DWM-only kernel hooks (alloc/protect/map with EXECUTE)
  volatile uint8_t  nt_alloc_hook_installed;
  volatile uint8_t  nt_protect_hook_installed;
  volatile uint8_t  nt_map_hook_installed;
  volatile uint8_t  nt_csec_hook_installed;
  volatile uint64_t diag_nt_alloc_hits;
  volatile uint64_t diag_nt_alloc_alien;
  volatile uint64_t diag_nt_protect_hits;
  volatile uint64_t diag_nt_protect_alien;
  volatile uint64_t diag_nt_map_hits;
  volatile uint64_t diag_nt_map_alien;
  volatile uint64_t diag_nt_csec_hits;       // NtCreateSection vmexit fires (DWM only via filter)
  volatile uint64_t diag_nt_csec_image;      // SEC_IMAGE creates (DLL/EXE map intent)
  volatile uint64_t diag_nt_csec_alien;      // SEC_IMAGE + filename matched DLL blacklist
  volatile uint64_t diag_capture_notify_count;  // notify_capture_attempt fires
  // Symbol-resolution diagnostic captured at driver init: VA + first 8 bytes of
  // NtAllocateVirtualMemory page. Compare to WinDbg `dq nt!NtAllocateVirtualMemory`
  // to confirm PDB returned the right offset for the running kernel build.
  volatile uint64_t diag_nt_alloc_resolved_va;
  volatile uint64_t diag_nt_alloc_first8;

  // install_host_impl failure reason counters (per call attempt; not just NtSetEvent).
  // Track which check rejected the most recent install attempt for forensics.
  // Set in install_host_impl right at the failing return false; cleared on success.
  volatile uint64_t diag_install_last_target;        // target_va of last attempt
  volatile uint8_t  diag_install_last_fail;          // 0=success, 1=cr3, 2=findslot, 3=disasm, 4=eh, 5=tramp
  volatile uint32_t diag_install_last_instr_size;    // captured oldByte size
  volatile uint8_t  diag_install_last_is_kernel;
  volatile uint32_t diag_install_pool_user_slots;   // pool counts captured at fail
  volatile uint32_t diag_install_pool_kernel_slots;
  // alloc_trampoline failure forensics 鈥 written inside alloc when it can't
  // find a usable slot. Tells us which condition rejected the slot.
  volatile uint32_t diag_alloc_slot_count;
  volatile uint8_t  diag_alloc_slot0_occupied;
  volatile uint8_t  diag_alloc_slot0_capacity;
  volatile uint16_t diag_alloc_slot0_page_offset;
  volatile uint16_t diag_alloc_slot0_page_index;
  volatile uint32_t diag_alloc_needed;
  volatile uint8_t  diag_alloc_is_kernel;
  volatile uint8_t  diag_alloc_pool_ready;

  // Ring of last 8 RIPs that entered vmcall_hook_dispatch. Lets us see what
  // VA the vmcall is coming from when hit_count stays 0.
  volatile uint64_t diag_dispatch_rip_ring[8];
  volatile uint32_t diag_dispatch_rip_idx;
  volatile uint8_t  getbuffer_hook_installed;  // 0/1: PMO handler installed GetBuffer via vh_install_host
  volatile uint64_t diag_getbuffer_install_retry; // count of commit-retry attempts
  // GetBuffer install diagnostics 鈥 tells us which stage failed
  volatile uint8_t  diag_gb_vt_pp_ok;          // 1 if gva2hva(swapChain) succeeded
  volatile uint8_t  diag_gb_vt_hva_ok;         // 1 if gva2hva(vtable_ptr) succeeded
  volatile uint64_t diag_gb_getbuf_va;         // captured target VA
  volatile uint64_t diag_gb_shared_blank;      // captured blank
  volatile uint8_t  diag_gb_lock_called;       // 1 if VirtualLock was even available + called
  volatile uint8_t  diag_gb_install_first;    // 1 = first install_host returned ok, 0 = failed
  volatile uint8_t  diag_gb_install_second;   // 1 = retry install_host ok

  // PoolManager independent-pages diagnostics.
  // PoolManagertAllocation tries MmAllocateIndependentPages first; failures
  // bump these counters so we can identify which step is failing in target
  // environments where independent-pages route crashes host. Each "last_*"
  // value is overwritten on every alloc; capture at crash time via WinDbg.
  volatile uint64_t diag_pool_alloc_attempted;   // PoolManagertAllocation called N times
  volatile uint64_t diag_pool_indep_success;     // alloc + protect + writetest passed
  volatile uint64_t diag_pool_indep_alloc_null;  // MmAllocateIndependentPages returned NULL
  volatile uint64_t diag_pool_indep_protect_fail;// MmSetPageProtection returned FALSE
  volatile uint64_t diag_pool_indep_writetest_fail;// alloc+protect OK but test write failed
  volatile uint64_t diag_pool_indep_directmap_fail;// PFN is outside host direct map
  volatile uint64_t diag_pool_indep_retried;     // total retry iterations across all calls
  volatile uint64_t diag_pool_fallback_used;     // ExAllocatePoolWithTag fallback hits
  volatile uint64_t diag_pool_last_fail_size;    // bytes
  volatile uint32_t diag_pool_last_fail_source;  // 4-char tag
  volatile uint32_t diag_pool_last_fail_step;    // 1=alloc 2=protect 3=writetest 4=directmap
  volatile uint64_t diag_pool_last_alloc_buffer; // VA returned by last successful alloc
  volatile uint8_t  diag_pool_purge_called;      // 1 = standby list purge attempted at boot
  volatile uint8_t  diag_pool_purge_status;      // 0xFF = not called, else NTSTATUS truncated

  // retRip pool: pre-allocated table of ntdll 0xCC bytes, one per 4K page.
  // Layout:
  //   entries[0]      = call_retrip  (hv::Call return rendezvous)
  //   entries[1..N-1] = slot pool    (each install consumes one entry)
  static constexpr uint32_t RETRIP_POOL_SIZE = 16;
  uint64_t retrip_pool[RETRIP_POOL_SIZE];
  volatile uint32_t retrip_next_alloc;   // next free slot entry, starts at 1
  uint64_t call_retrip_va;               // == retrip_pool[0]

  // Stage 鈶 in-handler kernel DbgPrintEx logging support.
  uint64_t kernel_blank_va;            // 4-byte 0xCC run inside ntoskrnl (CallK retRip)
  uint64_t kernel_format_buf_va;       // pool page holding DbgPrintEx format string
  uint64_t csec_scratch_va;            // 4KB scratch: [out] FILE_OBJECT* for ObReferenceObjectByHandle
  uint64_t csec_format_va;             // 4KB pool page holding DbgPrintEx format "[CSEC] file=%ws\n"
  uint64_t alloc_format_va;            // "[NVA] protect=0x%X size=0x%llX caller=0x%llX\n"
  uint64_t protect_format_va;          // "[NPV] new=0x%X base=0x%llX size=0x%llX\n"
  uint64_t map_format_va;              // "[NMV] protect=0x%X sec=0x%llX\n"
  uint64_t vt_log_format_va;           // pool page holding "%s\n" for vt_log flusher
  volatile uint64_t diag_callk_fired;  // count of CallK invocations from MMM handler
  volatile uint32_t mmm_log_throttle;  // tick counter for 1-in-N throttling
  volatile uint8_t  mmm_in_callk;      // reentrancy guard (1 = currently inside CallK)

  // VT log ring (Stage 鈶): host root mode pushes formatted log lines into
  // this ring (lock-free, fixed-size entries); a mid-frequency kernel hook
  // (NtSetEvent) flushes up to 8 entries per fire via CallK(DbgPrintEx).
  // Backing page allocated by DriverMain (PoolManagertAllocation 64KB).
  // Pointer is a system VA; host accesses via gva2hva 鈫 host_physical_memory_base.
  uint64_t vt_log_ring_va;             // system VA of the ring buffer
  volatile uint32_t vt_log_write_pos;  // next write index (modulo VT_LOG_ENTRY_COUNT)
  volatile uint32_t vt_log_read_pos;   // next read index
  volatile uint32_t vt_log_dropped;    // entries dropped due to ring full
  volatile uint8_t  vt_log_flush_in_progress;  // reentrancy guard for flusher

  // Stage 鈶-B: vfunc addresses captured by render::init for the driver to
  // install vmcall hooks on. Read by hypercall_test type==15 / 16.
  uint64_t copyresource_addr;     // ID3D11DeviceContext vfunc[47]
  uint64_t duplicateoutput_addr;  // IDXGIOutput1 vfunc[23]

  // #BP path tracing (added 2026-05-22 to debug hv::Call return-rendezvous).
  volatile uint64_t diag_bp_total;          // all #BP vmexits
  volatile uint64_t diag_bp_match;          // return_old_func returned true
  volatile uint64_t diag_bp_miss;           // return_old_func returned false (re-injected)
  volatile uint64_t diag_bp_last_rip;       // last #BP vmexit GUEST_RIP (raw, not -1)
  volatile uint64_t diag_bp_last_retrip;    // last node retRip we tried to match (rip-1)
  volatile uint64_t diag_bp_first_miss_rip; // first miss RIP, sticky
  volatile uint64_t diag_bp_wrong_cpu;      // #BP fired on wrong vCPU; spun until migration

  // EPT-violation diagnostics for hook trigger debugging.
  volatile uint64_t diag_ept_violation_total;     // every EPT-violation vmexit
  volatile uint64_t diag_ept_violation_match;     // matched an installed hook
  volatile uint64_t diag_ept_violation_nohook;    // no hook found for the PA
  volatile uint64_t diag_ept_violation_last_pa;   // last violation GPA
  volatile uint64_t diag_ept_violation_last_rip;  // last violation GUEST_RIP
  volatile uint64_t diag_ept_violation_pmo_match; // PA-PFN matched the orig_pfn captured during install

  // install_ept_hook diagnostics.
  volatile uint64_t diag_ieh_calls;          // # times install_ept_hook was called
  volatile uint64_t diag_ieh_success;        // returned true
  volatile uint64_t diag_ieh_no_pte;         // get_ept_pte returned nullptr
  volatile uint64_t diag_ieh_no_freelist;    // ran out of hook nodes
  volatile uint64_t diag_ieh_idempotent;     // returned true early because orig_pfn already hooked
  volatile uint64_t diag_ieh_last_pte_addr;  // host VA of last PTE we modified
  volatile uint64_t diag_ieh_last_pte_before;// PTE value snapshot before write
  volatile uint64_t diag_ieh_last_pte_after; // PTE value snapshot after write
  volatile uint64_t diag_ieh_last_pte_recheck; // re-read PTE 1ms later (in DIAG #1) to verify it stuck

  // Cross-page rejection counters (incremented in disasm_target_host before
  // any state is mutated). install attempts to a target_va that straddles
  // a 4KB boundary in either the stub-write window or the resume window
  // are refused so we don't corrupt adjacent fake_pages or land RIP on an
  // unmapped page.
  volatile uint64_t diag_install_xpage_stub;   // (target_va & 0xFFF) + 3 > 0x1000
  volatile uint64_t diag_install_xpage_resume; // target_va..target_va+size-1 spans pages
  volatile uint64_t diag_alloc_xpage_skipped;  // tramp slot rejected at alloc-time (defence-in-depth)
  volatile uint64_t diag_tramp_slot_xpage_reject; // tramp slot rejected at registration (page_off + capacity > 0x1000)

  // PMO install path step-by-step diagnostics. Each vCPU in the IPI broadcast
  // OR's its bits into diag_pmo_step[its_idx]. Bit meanings:
  //   bit 0 = entered install_host_impl
  //   bit 1 = won CAS rendezvous (initializer)
  //   bit 2 = lost CAS, became loser
  //   bit 3 = read_process_cr3_local OK
  //   bit 4 = find_free_slot OK
  //   bit 5 = disasm_target_host OK
  //   bit 6 = eh_prepare_entry OK
  //   bit 7 = alloc_trampoline OK
  //   bit 8 = apply_enable_transition_hva done
  //   bit 9 = eh_install_self called
  //   bit 10= install_ept_hook returned true (per-vCPU success)
  //   bit 11= idempotency-fast-path hit
  //   bit 12= loser woke up + install_self called
  volatile uint32_t diag_pmo_step[16];
  volatile uint64_t diag_pmo_pte_after[16];   // per-vCPU PTE value after install

  // Per-vCPU EPT walk: at next vmexit each vCPU walks its own EPT for PMO's
  // GPA and dumps PDE/PTE values. Lets us confirm the modified PTE is what
  // hardware actually consults.
  volatile uint64_t diag_pmo_walk_pde[16];
  volatile uint64_t diag_pmo_walk_pte[16];
  volatile uint8_t  diag_pmo_walk_done[16];
  volatile uint64_t diag_pmo_target_pa;        // = orig_pfn << 12 of PMO entry

  // Per-vCPU vmexit counter 鈥 bumped at dispatch_vm_exit entry. Lets us see
  // which vCPUs are actually executing vmexits. A vCPU stuck in host or in
  // guest with interrupts disabled would show 0/very-low counts.
  volatile uint64_t diag_per_vcpu_vmexits[16];

  // Full-stop diagnostics/fail-closed guard. hv::stop() frees runtime
  // allocations only after every vCPU both enters hc::unload() and returns
  // from the unload VMCALL on its own CPU.
  volatile uint64_t stop_phase;
  volatile uint64_t stop_expected_bitmap;
  volatile uint64_t stop_requested_bitmap;
  volatile uint64_t stop_before_vmcall_bitmap;
  volatile uint64_t stop_after_vmcall_bitmap;
  volatile uint64_t stop_ack_bitmap;
  volatile uint64_t stop_exception_bitmap;
  volatile uint64_t stop_cleanup_bitmap;
  volatile uint64_t stop_last_cpu;
  volatile uint64_t stop_result;

  // How many vmexits happened while guest was in DWM process. Lets us see
  // whether DWM is actually running on any vCPU.
  volatile uint64_t diag_per_vcpu_dwm_vmexits[16];
  volatile uint64_t diag_dwm_eprocess_observed;  // last EPROCESS that matched g_yvt.dwm


  // Host-handler install path: when current vCPU writes EPT for other vCPUs,
  // bit v is set; vCPU v invept_single_context's its own ept on next vmexit.
  volatile uint64_t pending_ept_invept_bitmap;

  // Trampoline pool set_ready completion bitmap: each vCPU sets its bit when
  // it finishes installing EPT for all pool pages. Lets us see whether IPI
  // really reached every vCPU during bootstrap.
  volatile uint64_t diag_tramp_user_done_bitmap;
  volatile uint64_t diag_tramp_kernel_done_bitmap;

  // Deferred per-vCPU install: host-handler path enqueues the prepared entry
  // here (no EPT writes yet), then sets pending_ept_install_bitmap. Each vCPU
  // walks the queue on its next vmexit and calls eh_install_self for entries
  // it hasn't yet installed (idempotent via per_vcpu_active_bitmap). This
  // avoids the cross-vCPU EPT/PDE-split race where the calling vCPU writes
  // another vCPU's ept tree while that vCPU is mid-execution on the same page.
  static constexpr uint32_t pending_install_capacity = 64;
  eh::ept_hook_entry* pending_ept_install_entries[pending_install_capacity];
  volatile uint64_t   diag_pending_queue_full;          // bumped when no free slot found
  volatile uint64_t   pending_ept_install_bitmap;       // bit v set 鈫 vCPU v has work to do

  // hv::Call cross-vCPU recovery counters (added 2026-05-22 to verify whether
  // affinity lock is actually preventing scheduler migration of the guest
  // thread between hv::Call entry and return).
  volatile uint64_t diag_cross_vcpu_call;   // cleanup ran on different vCPU than entry
  volatile uint64_t diag_same_vcpu_call;    // cleanup ran on entry vCPU (normal path)
  volatile uint64_t diag_pending_overwrite_wait;  // mark/restore spin-waited on pending_lock

  // hv::Call lazy-restore NMI-IPI wakeup diagnostics (2026-05-23).
  volatile uint64_t diag_mark_timeout;   // mark gave up after 5ms spin (rare)
  volatile uint64_t diag_leaked_node;    // stack node leaked due to mark timeout

  // Master switch for KTHREAD.Affinity lock in hv::Call (game.h).
  // true (default) = single-CPU pin reduces cross-vCPU return frequency.
  // false = no affinity rewrites, stress-test the cross-vCPU lazy restore path.
  volatile bool affinity_lock_enabled;

  // Deferred self-hide state. mapDriver populates pending_hide_pfns[] via
  // hypercall_prepare_self_hide_add (one PFN per call) then commits via
  // hypercall_prepare_self_hide_commit. The VM-exit dispatcher checks
  // pending_hide_vcpu_bitmap on every exit and, when the bit for the current
  // vcpu is set and the TSC threshold has passed, walks the buffer and
  // redirects each EPT entry to dummy_page_pfn. Host code runs in host CR3
  // so hiding driver image is safe 鈥 by then guest is in NTOS not in our .text.
  //
  // Buffer is inline in ghv so host can read it without gva2hva translation.
  // Size budget: 256K entries 脳 8 bytes = 2MB. Covers ~1GB of physical
  // memory worth of pages 鈥 needed because vcpu pool block alone is
  // ~545MB (136K pages) and the previous 64K cap silently dropped half
  // the vcpu hide queue.
  static constexpr uint32_t pending_hide_capacity = 256 * 1024;
  uint64_t pending_hide_pfns[pending_hide_capacity];
  volatile uint32_t pending_hide_count;
  uint32_t  pending_hide_pad_;
  volatile uint64_t pending_hide_vcpu_bitmap;   // (1<<N)-1, cleared per-vcpu
  uint64_t  pending_hide_tsc_threshold;         // earliest tsc to start hide

  // Protected VA-range table. Each entry covers a contiguous kernel VA
  // span that must be hidden from Mm* kernel probes. Filled by
  // prepare_self_hide_commit from:
  //   1. testDriver image (one entry: imageBase..imageBase+imageSize)
  //   2. each PoolManager block (one entry per Util::Pools active entry)
  //
  // Total memory: 128 entries 脳 16 bytes = 2 KB inline (vs 8 MB for a
  // page-granular bitmap). Lookup is O(N) over ~60 entries 鈥 a couple of
  // hundred ns per Mm* hook invocation, well within budget.
  //
  // Mm* hook handlers (MmCopyMemory / MmCopyVirtualMemory /
  // MmIsAddressValidEx) check the target VA against this table and bail
  // with STATUS_INVALID_ADDRESS (or FALSE) on a hit.
  struct prot_va_range {
    uint64_t base;
    uint64_t end;  // exclusive
  };
  static constexpr uint32_t prot_range_capacity = 128;
  prot_va_range  prot_ranges[prot_range_capacity];
  volatile uint32_t prot_range_count;

  // Fake-data page. Mm* hooks fill the caller's buffer with bytes from
  // here on a protected-region hit, instead of returning an error. The
  // anti-cheat sees a successful copy returning "normal looking" bytes
  // and doesn't escalate. Filled at driver init from a slice of ntoskrnl
  // image content (real kernel code/data layout 鈥 not all zeros, not
  // recognizable as testDriver).
  alignas(0x1000) uint8_t fake_data[0x1000];

  // Stage 5 Mm* memory-hide hooks. Each handler consults prot_ranges and
  // bails with STATUS_INVALID_ADDRESS / FALSE / NULL when target_va falls
  // inside a hidden region.
  volatile uint8_t  mmcm_hook_installed;
  volatile uint8_t  mmcvm_hook_installed;
  volatile uint8_t  mmisav_hook_installed;
  volatile uint8_t  mmmio_hook_installed;
  volatile uint64_t diag_mmcm_hits,   diag_mmcm_blocked;
  volatile uint64_t diag_mmcvm_hits,  diag_mmcvm_blocked;
  volatile uint64_t diag_mmisav_hits, diag_mmisav_blocked;
  volatile uint64_t diag_mmmio_hits,  diag_mmmio_blocked;

  // Hide-consume diagnostics. Each vcpu that enters the consume block bumps
  // diag_hide_enter once; total PTE writes attempted go in diag_hide_pte_total;
  // diag_hide_pte_null counts how many get_ept_pte() returned nullptr (split
  // fail or invalid GPA); diag_hide_done_bitmap sets bit cpuid when the
  // consume loop finishes for that vcpu.
  volatile uint64_t diag_hide_enter;
  volatile uint64_t diag_hide_pte_total;
  volatile uint64_t diag_hide_pte_null;
  volatile uint64_t diag_hide_done_bitmap;
};

// Active hypervisor state. Standalone TestDriver uses g_static_ghv; mapDriver
// can switch g_ghv to a resident arena block before hv::start(), so the state
// survives TestDriver image quarantine/free.
extern hypervisor g_static_ghv;
extern hypervisor* g_ghv;

// Test whether [va, va+size) overlaps any protected hide range. O(~60).
// Host-root-mode safe: walks g_ghv->prot_ranges directly via host CR3.
// Mm* kernel-hook handlers call this to fast-reject probes that read
// testDriver image / PoolManager blocks.
static __forceinline bool is_protected_va(uint64_t va, size_t size) {
  if (size == 0) size = 1;
  uint64_t const end = va + size;
  uint32_t const count = g_ghv->prot_range_count;
  for (uint32_t i = 0; i < count; i++) {
    auto const& r = g_ghv->prot_ranges[i];
    if (va < r.end && end > r.base) return true;
  }
  return false;
}

// virtualize the current system
bool start();

// devirtualize the current system
bool stop();

// VT log ring (Stage 鈶): host root mode pushes formatted entries; mid-freq
// kernel hook drains them via DbgPrintEx. Safe to call from any host context
// (vmexit handlers, hv::Call cleanup, etc.). Limited printf subset:
// %d %u %x %llx %p %s %c (no width spec, no float).
void vt_log(const char* fmt, ...);

// Pop one entry from the log ring into `out` (size = VT_LOG_ENTRY_SIZE bytes).
// Returns true if a line was popped (out is NUL-terminated). False if empty.
bool vt_log_pop(char* out);

void* take_preallocated_tramp_page();

bool add_protect_process(uint64_t process);

void remove_protect_process(uint64_t process);


ghv_protect_list_node* find_protect_process(uint64_t process);


ghv_vtcall_list_node* add_vtcall_node();

ghv_vtcallstack_node* add_vtcallstack_node();

bool remove_vtcallstack_node(ghv_vtcallstack_node* node);


ghv_vtcallstack_node* find_vtcallstack_node(UINT64 stack_ptr);

// hv::Call lazy-restore (cross-vCPU return fallback).
void mark_vtcall_cross_cpu_return(int entry_cpu_number, ghv_vtcallstack_node* stack_node);
void process_pending_vtcall_restore(vcpu* cpu);
void process_pending_vtcall_release(vcpu* cpu);

bool add_cr3_monitor_thread(uint64_t process, uint64_t thread);

bool remove_vtcall_node(ghv_vtcall_list_node* node);

ghv_vtcall_list_node* find_vtcall_node(UINT64 process, UINT64 thread, UINT64 retRip);

void remove_cr3_monitor_thread(uint64_t process, uint64_t thread);

ghv_cr3_monitor_thread_list_node* find_cr3_monitor_thread(uint64_t process, uint64_t thread);


} // namespace hv

// ntoskrnl symbol absolute addresses resolved in vt/hv.cpp find_offsets() via PDB.
// Consumed by dwm/kerneldwm.cpp (vtcallhook::install targets) and game.cpp.
extern ULONG64 MiReadWriteVirtualMemory;   // NtWriteVirtualMemory
extern ULONG64 NtGetContextThread;
extern ULONG64 NtOpenSection;
extern ULONG64 NtCreatSection;             // NtCreateSection (name preserved for callers)
extern ULONG64 HalReturnToFirmware;
extern ULONG64 MmCopyMemory_va;            // Stage 5 memory-hide hook
extern ULONG64 MmCopyVirtualMemory_va;     // Stage 5 memory-hide hook (cross-process)
extern ULONG64 MmIsAddressValid_va;        // Stage 5 memory-hide hook (probe)
extern ULONG64 MmMapIoSpace_va;            // Stage 5 memory-hide hook (PA map)
extern ULONG64 MmIsAddressValidEx_va;      // Optional Stage 5 memory-hide hook (extended probe)
extern ULONG64 NtQueryVirtualMemory_va;    // Optional Stage 5 memory-hide hook (VAD query)
extern ULONG64 MmGetPhysicalAddress_va;    // Optional Stage 5 memory-hide hook (VA->PA disclosure)
extern ULONG64 DbgPrintEx_va;              // Stage 鈶 in-handler kernel logging
// NtCreateThreadEx_va is now static inside vt/hv.cpp (no cross-TU readers).
extern ULONG64 NtSetEvent_va;              // Stage 鈶 mid-freq hook used to flush vt_log ring
extern ULONG64 NtAllocateVirtualMemory_va; // anti-screenshot: DWM-only, EXECUTE-class alloc 鈫 notify hide
extern ULONG64 NtProtectVirtualMemory_va;  // anti-screenshot: DWM-only, EXECUTE-class mprotect 鈫 notify hide
extern ULONG64 NtMapViewOfSection_va;      // anti-screenshot: DWM-only, EXECUTE-class map 鈫 notify hide
extern ULONG64 ObReferenceObjectByHandle_va; // anti-screenshot: NtCreateSection handler 鈫 FILE_OBJECT
extern ULONG64 ObfDereferenceObject_va;      // anti-screenshot: paired release

