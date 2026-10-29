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

// Ping 超调用所返回的特征签名
inline constexpr uint64_t hypervisor_signature = 'sb?d';

// VT 日志环形缓冲区大小规格（用于 Host 根模式日志记录）。
inline constexpr uint32_t VT_LOG_ENTRY_SIZE  = 128;
inline constexpr uint32_t VT_LOG_ENTRY_COUNT = 512;
inline constexpr uint32_t VT_LOG_RING_BYTES  = VT_LOG_ENTRY_SIZE * VT_LOG_ENTRY_COUNT;

// 跳板池（Trampoline pool）：每个槽位是 ntdll（用户层钩子）或 ntoskrnl（内核层钩子）
// .text 代码段填充区内的一段 0xCC 字节空间。每个池分配 16 个此类槽位，每个槽位至多 16 字节。
// 每个被占用的槽位内存布局如下：
//
//     [被覆盖的原始指令 3..7 字节] [0xCC 断点]
//
// 执行命中流程：
//   1) 挂接点（target_va）执行 0F 01 C1（影子页中的 vmcall 存根）；
//   2) 进入处理函数；分发器重写 GUEST_RIP = slot.tramp_va；
//   3) CPU 通过槽位执行视图的 4KB EPT 重定向执行被覆盖的原指令；
//   4) CPU 命中随后的 0xCC 断点，触发 #BP 异常导致 VM-exit；
//   5) #BP 处理例程将 RIP 与 slot.bp_rip 比对，匹配成功后重写
//      GUEST_RIP = slot.target_resume = target_va + oldByte_size，不向下注入异常。
//
// 每个槽位的 Host 端状态保存在下方的 tramp_slot 中。跳板池维护槽位数组，
// 以及每个池独占的 4KB exec_pages 列表（同一物理页中的多个槽位共享一个 EPT 重定向和一个 exec_page）。
inline constexpr uint32_t TRAMPOLINE_SLOT_BYTES  = 16;       // 每个槽位占用的最大字节数
inline constexpr uint32_t TRAMPOLINE_POOL_USER_SLOTS   = 16; // 基于 ntdll 的用户态（Ring-3）挂钩跳板
inline constexpr uint32_t TRAMPOLINE_POOL_KERNEL_SLOTS = 16; // 基于 ntoskrnl 的内核态（Ring-0）挂钩跳板
inline constexpr uint32_t TRAMPOLINE_MAX_PAGES_PER_POOL = 16; // 每个跳板池独立分配的 4KB 执行页数量上限

struct tramp_slot {
    uint64_t tramp_va;       // 包含旧指令机器码与 0xCC 断点的 Guest 虚拟地址（分发器重写后的 GUEST_RIP）
    uint64_t bp_rip;         // tramp_va + oldByte_size + 1；CPU 命中 0xCC 触发 #BP 步进后的返回地址
    uint64_t target_resume;  // target_va + oldByte_size；#BP 异常拦截处理后恢复重写的目标 Guest RIP
    uint16_t page_index;     // 跳板池 pages[] 数组的索引（指示承载当前槽位的 exec_page）
    uint16_t page_offset;    // exec_page 执行页内旧指令机器码的起始字节偏移
    uint8_t  capacity;       // 该 0xCC 填充区域的连续字节长度（必须满足 >= oldByte_size + 1）
    bool     occupied;
};

struct tramp_page {
    uint64_t guest_page_va;  // ntdll/ntoskrnl 内按 4KB 页对齐的虚拟地址
    uint64_t orig_pfn;       // 原始物理页号（只读/数据视图）
    uint64_t exec_pfn;       // 驱动分配的执行物理页号（可执行视图）
    uint64_t exec_hva;       // 当前 exec_page 的 Host 虚拟地址（用于向跳板写入机器码）
};

struct trampoline_pool {
    spin_lock lock;

    // 用户层跳板池（基于 ntdll 代码填充区）
    tramp_slot user_slots[TRAMPOLINE_POOL_USER_SLOTS];
    tramp_page user_pages[TRAMPOLINE_MAX_PAGES_PER_POOL];
    uint32_t   user_slot_count;
    uint32_t   user_page_count;
    bool       user_ready;

    // 内核层跳板池（基于 ntoskrnl 代码填充区）
    tramp_slot kernel_slots[TRAMPOLINE_POOL_KERNEL_SLOTS];
    tramp_page kernel_pages[TRAMPOLINE_MAX_PAGES_PER_POOL];
    uint32_t   kernel_slot_count;
    uint32_t   kernel_page_count;
    bool       kernel_ready;
};

// 保护进程链表
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
                       // 当 2 个 vCPU 命中相同钩子（相同 retRip、相同 DWM 进程，甚至可能相同线程）时查找/移除。
    UINT64 saved_affinity;   // KAFFINITY snapshot taken at hv::CallUser entry,
                             // 在清理时恢复。将 Guest 线程锁定在入口 vCPU 上，
                             // 防止跨 vCPU 迁移破坏 vt_call_exit 的栈和 VMCS 写入。
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
                                              // host_stack_size=0x40000, total inline
                                              // here is ~8MB; keep page-budget checks enabled.
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
  // 所有 vCPU 之间共享的 Host 端页表
  host_page_tables host_page_tables;

  // 可在 VMX Root-mode 下安全调用的日志记录器
  logger logger;
  alignas(0x1000) uint8_t dummy_page[0x1000];
  // 动态分配的 vCPU 结构体数组
  unsigned long vcpu_count;

  struct vcpu* vcpus;

  // 指向 System 进程（ntoskrnl）的 EPROCESS 指针
  uint8_t* system_eprocess;

  // System 进程的内核态 CR3 物理基址
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

  volatile uint64_t dwm_hit_count;

  volatile uint32_t dwm_install_status;
  volatile uint32_t dwm_install_pad;
  volatile uint64_t dwm_install_target_va;
  volatile uint64_t dwm_install_fake_target_va;
  volatile uint64_t dwm_install_fake_blank_va;
  volatile uint64_t dwm_dispatch_seen_rip;
  volatile uint64_t dwm_dispatch_compared_addr;

  // Host 端独占的 EPT 钩子表（内联，无需单独分配内存）。
  eh::ept_hook_table ept_hook_table;

  // Host 端独占的通用 EPT 探针表。特意与 ept_hook_table/tramp_pool 分离，
  // 确保单次/即席寄存器探针绝不会修改现有的钩子分发状态。
  ept_probe_table probe_table;

  // Host 端独占的调试框架状态。Phase-1 仅持有会话与统计计数器；不修改 EPT 钩子/探针状态。
  dbg_state dbg;

  // Host 端独占的调试事件环形缓冲区。生产者仅追加定长记录；轮询经由 dbg_dispatch 路由，绝不触碰传统 EPT 钩子状态。
  dbg_event_ring dbg_events;

  // Host 端独占的调试 EPT 监控状态。与 ept_hook_table 和 probe_table 完全隔离；受监控页面在传统 find_ept_hook() 之前被优先处理。
  dbg_watch_state dbg_watch;

  // 用于无竞态挂接分发的跳板池（无需动态修改影子页）。
  trampoline_pool tramp_pool;
  static constexpr uint32_t TRAMP_PREALLOC_PAGE_COUNT =
    TRAMPOLINE_MAX_PAGES_PER_POOL * 2;
  uint64_t tramp_prealloc_pages[TRAMP_PREALLOC_PAGE_COUNT];
  volatile uint32_t tramp_prealloc_count;
  volatile uint32_t tramp_prealloc_next;

  volatile uint64_t diag_dispatch_count;    // 进入 vmcall_hook_dispatch 计数
  volatile uint64_t diag_handler_count;     // 进入 PresentOverlay 处理计数
  volatile uint64_t diag_init_enter_count;  // 进入初始化例程计数
  volatile uint64_t diag_init_done_count;   // 初始化完成（isFinish=true）计数
  volatile uint64_t diag_tick_count;        // 进入渲染每帧 Tick 计数
  volatile uint64_t diag_tick_draw_count;   // 到达 BeginDraw 计数
  volatile uint64_t diag_tick_end_count;    // 到达 EndDraw 计数

  // 防截屏钩子命中计数器。每次钩子处理函数触发时递增对应槽位；
  // *_alien 仅在调用方被归类为外部侵入线程（反作弊注入 DWM）时递增。
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
  // NtSetEvent 安装 diagnostics
  volatile uint8_t  diag_ntse_install_attempted; // 1 = vh_install_host was called
  volatile uint8_t  diag_ntse_install_result;    // 1 = vh_install_host returned true
  volatile uint64_t diag_ntse_target_va;         // captured NtSetEvent_va at install time

  // 鼠标就地修正钩子。通过 EPT 挂接原生 MouClass 服务回调，
  // 在原函数执行前仅修改真实的鼠标移动数据包。
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

  // MouHid_ReadComplete 调用前探针。观测到的调用方返回地址为 mouhid.sys + 0x3AA8，
  // 因此 CFG 间接调用指令位于 mouhid.sys + 0x3AA2。此探针在 MouClassServiceCallback 之前执行。
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

  // 用于无需 WinDbg 即可进行单步测试的只读底层栈探针：
  // 类型 24: mouhid.sys+0x3CB2，在 MouHid 向底层 HID 栈发送读取 IRP 之前触发。RCX 为底层 DeviceObject。
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

  // 类型 25: hidusb.sys+0x1485，在 HidUsb 向底层 USB 栈发送 IRP/URB 之前触发。RCX 为底层 DeviceObject。
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

  // 类型 26: hidusb.sys+0x2D60，HumReadCompletion 入口。只读捕获 IRP 状态与 USB 中断传输缓冲区指针及长度。
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

  // 防截屏能力：仅针对 DWM 进程的内核钩子（拦截带有 EXECUTE 权限的申请/保护/映射操作）
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
  // 驱动初始化时捕获的符号解算诊断：NtAllocateVirtualMemory 页面的虚拟地址及前 8 字节。
  // 可与 WinDbg 命令 `dq nt!NtAllocateVirtualMemory` 比对，确认 PDB 为当前运行的内核版本返回了正确偏移。
  volatile uint64_t diag_nt_alloc_resolved_va;
  volatile uint64_t diag_nt_alloc_first8;

  // install_host_impl 失败原因计数器（按每次调用尝试统计）。
  // 用于取证追踪最近一次安装尝试被哪个校验步骤拒绝。
  // 在 install_host_impl 失败返回 false 处记录，安装成功时清零。
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

  // 最近 8 次进入 vmcall_hook_dispatch 的 RIP 环形缓冲区。
  // 便于在命中计数器为 0 时排查 vmcall 究竟来自哪个虚拟地址。
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

  // PoolManager 独立物理页分配诊断：
  // 内存分配优先尝试 MmAllocateIndependentPages；若失败则递增这些计数器，
  // 以便在特定目标环境中排查独立页面分配失败的具体原因。每次分配时覆盖更新，崩溃时可通过 WinDbg 取证。
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

  // retRip 池：ntdll 中预分配的 0xCC 断点字节表，每个 4KB 页面分配一个。
  // 布局结构：
  //   entries[0]      = call_retrip  (hv::CallUser 调用返回汇合点)
  //   entries[1..N-1] = 槽位池       (每次安装挂接消耗一个条目)
  static constexpr uint32_t RETRIP_POOL_SIZE = 16;
  uint64_t retrip_pool[RETRIP_POOL_SIZE];
  volatile uint32_t retrip_next_alloc;   // next free slot entry, starts at 1
  uint64_t call_retrip_va;               // == retrip_pool[0]

  // Stage 鈶 in-handler kernel DbgPrintEx logging support.
  uint64_t kernel_blank_va;            // 4-byte 0xCC run inside ntoskrnl (CallKernel retRip)
  uint64_t kernel_format_buf_va;       // pool page holding DbgPrintEx format string
  uint64_t csec_scratch_va;            // 4KB scratch: [out] FILE_OBJECT* for ObReferenceObjectByHandle
  uint64_t csec_format_va;             // 4KB pool page holding DbgPrintEx format "[CSEC] file=%ws\n"
  uint64_t alloc_format_va;            // "[NVA] protect=0x%X size=0x%llX caller=0x%llX\n"
  uint64_t protect_format_va;          // "[NPV] new=0x%X base=0x%llX size=0x%llX\n"
  uint64_t map_format_va;              // "[NMV] protect=0x%X sec=0x%llX\n"
  uint64_t vt_log_format_va;           // pool page holding "%s\n" for vt_log flusher
  volatile uint64_t diag_callk_fired;  // count of CallKernel invocations from MMM handler
  volatile uint32_t mmm_log_throttle;  // tick counter for 1-in-N throttling
  volatile uint8_t  mmm_in_callk;      // reentrancy guard (1 = currently inside CallKernel)

  uint64_t vt_log_ring_va;             // system VA of the ring buffer
  volatile uint32_t vt_log_write_pos;  // next write index (modulo VT_LOG_ENTRY_COUNT)
  volatile uint32_t vt_log_read_pos;   // next read index
  volatile uint32_t vt_log_dropped;    // entries dropped due to ring full
  volatile uint8_t  vt_log_flush_in_progress;  // reentrancy guard for flusher

  // Stage 鈶-B: vfunc addresses captured by render::init for the driver to
  // 安装 vmcall hooks on. 读取 by hypercall_test type==15 / 16.
  uint64_t copyresource_addr;     // ID3D11DeviceContext vfunc[47]
  uint64_t duplicateoutput_addr;  // IDXGIOutput1 vfunc[23]

  // #BP 路径追踪（用于排查调试 hv::CallUser 返回汇合逻辑）。
  volatile uint64_t diag_bp_total;          // all #BP vmexits
  volatile uint64_t diag_bp_match;          // return_old_func returned true
  volatile uint64_t diag_bp_miss;           // return_old_func returned false (re-injected)
  volatile uint64_t diag_bp_last_rip;       // last #BP vmexit GUEST_RIP (raw, not -1)
  volatile uint64_t diag_bp_last_retrip;    // last node retRip we tried to match (rip-1)
  volatile uint64_t diag_bp_first_miss_rip; // first miss RIP, sticky
  volatile uint64_t diag_bp_wrong_cpu;      // #BP fired on wrong vCPU; spun until migration

  // EPT 违例诊断结构（用于排查挂接触发问题）。
  volatile uint64_t diag_ept_violation_total;     // every EPT-violation vmexit
  volatile uint64_t diag_ept_violation_match;     // matched an installed hook
  volatile uint64_t diag_ept_violation_nohook;    // no hook found for the PA
  volatile uint64_t diag_ept_violation_last_pa;   // last violation GPA
  volatile uint64_t diag_ept_violation_last_rip;  // last violation GUEST_RIP
  volatile uint64_t diag_ept_violation_pmo_match; // PA-PFN matched the orig_pfn captured during install

  // install_ept_hook 安装诊断信息。
  volatile uint64_t diag_ieh_calls;          // # times install_ept_hook was called
  volatile uint64_t diag_ieh_success;        // returned true
  volatile uint64_t diag_ieh_no_pte;         // get_ept_pte returned nullptr
  volatile uint64_t diag_ieh_no_freelist;    // ran out of hook nodes
  volatile uint64_t diag_ieh_idempotent;     // returned true early because orig_pfn already hooked
  volatile uint64_t diag_ieh_last_pte_addr;  // host VA of last PTE we modified
  volatile uint64_t diag_ieh_last_pte_before;// PTE value snapshot before write
  volatile uint64_t diag_ieh_last_pte_after; // PTE value snapshot after write
  volatile uint64_t diag_ieh_last_pte_recheck; // re-read PTE 1ms later (in DIAG #1) to verify it stuck

  // 跨页拒绝计数器（在修改任何状态前于 disasm_target_host 中递增）。
  // 若安装目标的 target_va 在存根写入窗口或恢复窗口跨越了 4KB 页面边界，
  // 必须直接拒绝，防止破坏相邻影子页或将 RIP 跳入未映射的内存。
  volatile uint64_t diag_install_xpage_stub;   // (target_va & 0xFFF) + 3 > 0x1000
  volatile uint64_t diag_install_xpage_resume; // target_va..target_va+size-1 spans pages
  volatile uint64_t diag_alloc_xpage_skipped;  // tramp slot rejected at alloc-time (defence-in-depth)
  volatile uint64_t diag_tramp_slot_xpage_reject; // tramp slot rejected at registration (page_off + capacity > 0x1000)

  // PMO 安装路径单步诊断。每个参与 IPI 广播的 vCPU 将其状态位按位或记录至 diag_pmo_step[its_idx]：
  //   bit 0 = 进入 install_host_impl
  //   bit 1 = 赢得 CAS 汇合点（作为初始化者）
  //   bit 2 = CAS 竞态失败，转为从属核心
  //   bit 3 = read_process_cr3_local 执行成功
  //   bit 4 = find_free_slot 找到空闲槽位
  //   bit 5 = disasm_target_host 目标反汇编成功
  //   bit 6 = eh_prepare_entry 准备条目成功
  //   bit 7 = alloc_trampoline 分配跳板成功
  //   bit 8 = apply_enable_transition_hva 状态切换完成
  //   bit 9 = 调用了 eh_install_self
  //   bit 10= install_ept_hook 返回 true（当前 vCPU 安装成功）
  //   bit 11= 命中幂等性快速放行路径
  //   bit 12= 从属核心被唤醒并调用 install_self
  volatile uint32_t diag_pmo_step[16];
  volatile uint64_t diag_pmo_pte_after[16];   // 挂载后各 vCPU 对应的 PTE 实测值

  // 单核 EPT 遍历诊断：在下次 vmexit 时，各 vCPU 针对 PMO 的 GPA 遍历各自的 EPT，
  // 并输出 PDE/PTE 的实际值。用于确认硬件实际加载的正是已修改的 PTE。
  volatile uint64_t diag_pmo_walk_pde[16];
  volatile uint64_t diag_pmo_walk_pte[16];
  volatile uint8_t  diag_pmo_walk_done[16];
  volatile uint64_t diag_pmo_target_pa;        // 对应 PMO 条目的目标物理地址（orig_pfn << 12）

  // Per-vCPU vmexit counter 鈥 bumped at dispatch_vm_exit entry. Lets us see
  // which vCPUs are actually executing vmexits. A vCPU stuck in host or in
  // guest with interrupts disabled would show 0/very-low counts.
  volatile uint64_t diag_per_vcpu_vmexits[16];

  // 彻底停机诊断与故障闭环守卫：hv::stop() 必须在所有 vCPU 均进入 hc::unload()
  // 并在各自 CPU 上从卸载 VMCALL 正常返回后，才释放运行时内存分配。
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

  // 当 Guest 处于 DWM 进程中时发生的 VM-exit 次数。用于观测 DWM 是否实际在任何核心上运行。
  volatile uint64_t diag_per_vcpu_dwm_vmexits[16];
  volatile uint64_t diag_dwm_eprocess_observed;  // 最近一次与 g_yvt.dwm 匹配的 EPROCESS 地址


  // Host 端处理函数安装路径：当当前 vCPU 为其它核心写入 EPT 时设置对应位；
  // 目标 vCPU 在下一次 vmexit 时对自己所属的 EPT 上下文执行 invept_single_context 刷新。
  volatile uint64_t pending_ept_invept_bitmap;

  // 跳板池 set_ready 完成位图：每个 vCPU 在为所有池页面完成 EPT 安装后置位对应比特位。
  // 用于确认引导阶段 IPI 是否确实送达了每个物理核心。
  volatile uint64_t diag_tramp_user_done_bitmap;
  volatile uint64_t diag_tramp_kernel_done_bitmap;

  // 延迟单核安装机制：Host 处理路径将准备好的表项压入此队列（此时尚未写入 EPT），
  // 随后置位 pending_ept_install_bitmap。每个 vCPU 在其下一次 vmexit 时遍历该队列，
  // 并为尚未安装的条目调用 eh_install_self（通过 per_vcpu_active_bitmap 实现幂等保护）。
  // 彻底避免跨核心并发拆分 PDE 导致的写时竞态（防止调用核心正在写入目标核心的 EPT 树，而目标核心正在该页上执行）。
  static constexpr uint32_t pending_install_capacity = 64;
  eh::ept_hook_entry* pending_ept_install_entries[pending_install_capacity];
  volatile uint64_t   diag_pending_queue_full;          // 当跳板池无可用空闲槽位时递增计数
  volatile uint64_t   pending_ept_install_bitmap;       // 当对应位设置时表示对应的 vCPU 有待处理的 EPT 安装任务

  // hv::CallUser 跨 vCPU 恢复计数器（用于验证亲和性锁是否有效阻止了 Guest 线程在调用入口与返回之间被调度器迁移）。
  volatile uint64_t diag_cross_vcpu_call;   // 清理流程在与入口不同的 vCPU 上执行（跨核调用）
  volatile uint64_t diag_same_vcpu_call;    // 清理流程在入口同一个 vCPU 上执行（标准单核路径）
  volatile uint64_t diag_pending_overwrite_wait;  // mark/restore 操作在 pending_lock 自旋锁上产生等待的计数

  // hv::CallUser 延迟恢复 NMI-IPI 唤醒诊断。
  volatile uint64_t diag_mark_timeout;   // 自旋等待超过 5ms 超时放弃计数（极少触发）
  volatile uint64_t diag_leaked_node;    // 因标记超时导致栈节点未能及时回收的计数

  // hv::CallUser 中 KTHREAD.Affinity 锁的主开关（game.h）：
  // true（默认）= 单核绑定以降低跨 vCPU 返回频率；
  // false = 不重写亲和性，用于压力测试跨 vCPU 延迟恢复路径。
  volatile bool affinity_lock_enabled;

//[Guest: mapDriver]
//       │
//       ├─► 1. 逐页注册: hypercall_prepare_self_hide_add(pfn)
//       │        (向 pending_hide_pfns 数组填充目标 PFN)
//       │
//       └─► 2. 提交触发: hypercall_prepare_self_hide_commit()
//                (设置 pending_hide_vcpu_bitmap，标记目标 vCPU 与 TSC 延迟阈值)
//       │
//[VM-Exit 触发 / 调度]
//       │
//       ├─► 3. 条件判断 (VM-exit Dispatcher)
//       │        (检查当前 vCPU 位图 + RDTSC 检查当前时间是否超过阈值)
//       │
//       └─► 4. 执行替换 (EPT Remapping)
//                (遍历缓冲区的 PFN，将 EPT 条目重定向到 dummy_page_pfn)
  static constexpr uint32_t pending_hide_capacity = 256 * 1024;
  uint64_t pending_hide_pfns[pending_hide_capacity];
  volatile uint32_t pending_hide_count;
  uint32_t  pending_hide_pad_;
  volatile uint64_t pending_hide_vcpu_bitmap;   // 初始掩码为 (1<<N)-1，由每个 vCPU 完成隐藏后逐位清除
  uint64_t  pending_hide_tsc_threshold;         // 允许启动驱动隐藏的最早 TSC 时间戳阈值

  struct prot_va_range {
    uint64_t base;
    uint64_t end;  // 结束边界（左闭右开区间）
  };
  static constexpr uint32_t prot_range_capacity = 128;
  prot_va_range  prot_ranges[prot_range_capacity];
  volatile uint32_t prot_range_count;

  alignas(0x1000) uint8_t fake_data[0x1000];

  volatile uint8_t  mmcm_hook_installed;
  volatile uint8_t  mmcvm_hook_installed;
  volatile uint8_t  mmisav_hook_installed;
  volatile uint8_t  mmmio_hook_installed;
  volatile uint64_t diag_mmcm_hits,   diag_mmcm_blocked;
  volatile uint64_t diag_mmcvm_hits,  diag_mmcvm_blocked;
  volatile uint64_t diag_mmisav_hits, diag_mmisav_blocked;
  volatile uint64_t diag_mmmio_hits,  diag_mmmio_blocked;

  volatile uint64_t diag_hide_enter;
  volatile uint64_t diag_hide_pte_total;
  volatile uint64_t diag_hide_pte_null;
  volatile uint64_t diag_hide_done_bitmap;
};

extern hypervisor g_static_ghv;
extern hypervisor* g_ghv;

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

// 虚拟化当前系统（开启 VT-x / SVM）
bool start();

// 去虚拟化当前系统（关闭并退出 VT-x / SVM）
bool stop();

void vt_log(const char* fmt, ...);
bool vt_log_pop(char* out);

void* take_preallocated_tramp_page();

bool add_protect_process(uint64_t process);

void remove_protect_process(uint64_t process);


ghv_protect_list_node* find_protect_process(uint64_t process);


ghv_vtcall_list_node* add_vtcall_node();

ghv_vtcallstack_node* add_vtcallstack_node();

bool remove_vtcallstack_node(ghv_vtcallstack_node* node);


ghv_vtcallstack_node* find_vtcallstack_node(UINT64 stack_ptr);

// hv::CallUser 延迟恢复（跨 vCPU 返回兜底处理）。
void mark_vtcall_cross_cpu_return(int entry_cpu_number, ghv_vtcallstack_node* stack_node);
void process_pending_vtcall_restore(vcpu* cpu);
void process_pending_vtcall_release(vcpu* cpu);

bool add_cr3_monitor_thread(uint64_t process, uint64_t thread);

bool remove_vtcall_node(ghv_vtcall_list_node* node);

ghv_vtcall_list_node* find_vtcall_node(UINT64 process, UINT64 thread, UINT64 retRip);

void remove_cr3_monitor_thread(uint64_t process, uint64_t thread);

ghv_cr3_monitor_thread_list_node* find_cr3_monitor_thread(uint64_t process, uint64_t thread);


} // namespace hv

// ntoskrnl 符号绝对虚拟地址（由 vt/hv.cpp 中 find_offsets() 通过 PDB 符号解算）。
// 供 dwm/kerneldwm.cpp（vtcallhook::install 目标）和 game.cpp 使用。
extern ULONG64 MiReadWriteVirtualMemory;   // NtWriteVirtualMemory
extern ULONG64 NtGetContextThread;
extern ULONG64 NtOpenSection;
extern ULONG64 NtCreatSection;             // NtCreateSection (name preserved for callers)
extern ULONG64 HalReturnToFirmware;
extern ULONG64 MmCopyMemory_va;            // 阶段 5 内存隐藏钩子
extern ULONG64 MmCopyVirtualMemory_va;     // 阶段 5 内存隐藏钩子（跨进程安全拷贝）
extern ULONG64 MmIsAddressValid_va;        // 阶段 5 内存隐藏钩子（内存地址有效性校验）
extern ULONG64 MmMapIoSpace_va;            // 阶段 5 内存隐藏钩子（物理内存映射过滤）
extern ULONG64 MmIsAddressValidEx_va;      // 可选阶段 5 内存隐藏钩子（扩展地址有效性探测）
extern ULONG64 NtQueryVirtualMemory_va;    // 可选阶段 5 内存隐藏钩子（VAD 虚拟内存查询）
extern ULONG64 MmGetPhysicalAddress_va;    // 可选阶段 5 内存隐藏钩子（虚拟地址转物理地址泄露防护）
extern ULONG64 DbgPrintEx_va;              // 内核日志输出例程
// NtCreateThreadEx_va 已收敛为 vt/hv.cpp 内部 static 变量（无跨编译单元访问者）。
extern ULONG64 NtSetEvent_va;              // 用于定时刷出 VT 日志环形缓冲区的中频内核钩子
extern ULONG64 NtAllocateVirtualMemory_va; // 防截图感知：仅针对 DWM，拦截可执行内存申请并通知隐藏
extern ULONG64 NtProtectVirtualMemory_va;  // 防截图感知：仅针对 DWM，拦截可执行内存属性修改并通知隐藏
extern ULONG64 NtMapViewOfSection_va;      // 防截图感知：仅针对 DWM，拦截节区可执行映射并通知隐藏
extern ULONG64 ObReferenceObjectByHandle_va; // 防截图感知：NtCreateSection 处理中获取目标 FILE_OBJECT
extern ULONG64 ObfDereferenceObject_va;      // 防截图感知：成对释放 FILE_OBJECT 对象引用

