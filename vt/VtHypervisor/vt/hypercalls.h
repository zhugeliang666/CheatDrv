#pragma once
#include <ia32.hpp>

namespace hv {

   

struct vcpu;

// key used for executing hypercalls
// TODO: compute this at runtime
inline constexpr uint64_t hypercall_key = 0x88554466885;

// hypercall indices
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
    // Legacy VMCALL hook ABI 52-55 retired; keep the live ABI ordinals stable.
    hypercall_eh_install = 56,

    // EPT hook (host-managed 表; driver layer is thin VMCALL only)
    hypercall_eh_remove,
    hypercall_eh_enable,
    hypercall_eh_disable,
    hypercall_eh_write,
    hypercall_eh_get_va,
    hypercall_eh_remove_all_by_process,

    // VTCall hook (host-managed; driver layer is thin VMCALL only)
    hypercall_vh_install,
    hypercall_vh_install_ret_abs,
    hypercall_vh_enable,
    hypercall_vh_disable,
    hypercall_vh_remove,
    hypercall_vh_uninit,
    hypercall_vh_find_blank,
    hypercall_vh_find_blank_page,       // args: process, start, max_scan; returns page-aligned VA of fully-0xCC page
    hypercall_vh_init_tramp_pool,       // (DEPRECATED) old 1-page pool init
    hypercall_vh_tramp_add_page,        // args: orig_pfn, exec_pfn, page_va, exec_hva, is_kernel; returns page_index
    hypercall_vh_tramp_add_slot,        // args: page_index, page_offset, capacity, is_kernel
    hypercall_vh_tramp_set_ready,       // args: is_kernel
    hypercall_prepare_self_hide_add,    // args[0] = PFN to add to hide queue
    hypercall_prepare_self_hide_commit, // args[0] = delay_us; sets bitmap = all vcpus
    hypercall_set_affinity_lock,        // args[0] = 1 enable / 0 disable
    hypercall_get_pool_blocks,          // args[0]=out_buf gva, [1]=max_count; returns count
    hypercall_get_hide_diag,            // args[0] = out gva (6 x uint64)
    hypercall_hide_pfn_list,            // args[0]=pfn_array gva, [1]=count; hide on CURRENT vcpu only
    // Existing EPT probe is part of the debug system, but keep these raw IDs
    // stable for 当前 tooling; Phase-4 wraps them under dbg_dispatch.
    hypercall_ept_probe_install,        // args: cr3, va, flags, hit_limit; returns probe id
    hypercall_ept_probe_remove,         // args: cr3, va, flags; returns removed probe id
    hypercall_ept_probe_get_hits,       // args: out_gva, max_hits, clear_after; returns copied count
    hypercall_ept_probe_clear_hits,     // returns cleared count
    hypercall_get_resident_hv_diag,     // args[0]=out gva, args[1]=out bytes; returns bytes copied
    hypercall_set_host_rsp,             // args[0]=new HOST_RSP for current vcpu; returns old HOST_RSP
    hypercall_map_host_range,           // args[0]=host VA, args[1]=bytes; maps range into host CR3
    hypercall_set_host_rip,             // args[0]=new HOST_RIP for current vcpu; returns old HOST_RIP
    hypercall_set_keep_hv_on_unload,    // args[0]=1 keep resident HV on DriverUnload, 0 allow full stop
    hypercall_dbg_dispatch,             // args: subcmd, in_gva, in_size, out_gva, out_size, flags/session
    hypercall_get_payload_status,       // payload-owned after bridge handoff; args[0]=out, args[1]=bytes
    hypercall_set_payload_mode,         // payload-owned after bridge handoff; args[0]=kind, args[1]=mode
    hypercall_payload_ping,             // payload-owned after bridge handoff; args[0]=nonce
    hypercall_verify_hide_pfn_list,     // args[0]=memcheck request gva, args[1]=bytes
    hypercall_unhide_pfn_list,          // args[0]=pfn_array gva, [1]=count; unhide on CURRENT vcpu only
    hypercall_set_machenike_status,     // args[0]=base, args[1]=size, args[2]=flags, args[3]=driver_unload
    hypercall_get_machenike_status,     // args[0]=out_buf (optional), args[1]=size; returns loaded
};

// ABI guard: mapDriver has its own copy of this enum and issues raw VMCALL
// IDs. Keep these ordinals aligned or the host will 分发 the wrong handler.
static_assert(hypercall_vh_find_blank_page == 70, "hypercall ABI drift");
static_assert(hypercall_prepare_self_hide_add == 75, "hypercall ABI drift");
static_assert(hypercall_get_hide_diag == 79, "hypercall ABI drift");
static_assert(hypercall_hide_pfn_list == 80, "hypercall ABI drift");
static_assert(hypercall_ept_probe_install == 81, "hypercall ABI drift");
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

// hypercall input
struct hypercall_input {
  // rax
 
	  union 
	  {
          uint64_t flags;
	      struct {
	          hypercall_code code : 8;
	          uint64_t       key : 56;
	      };
	  };



  // rcx, rdx, r8, r9, r10, r11
  uint64_t args[6];
};

struct cr3_monitor
{
    cr3 real_cr3;
    cr3 fake_cr3;
    uint64_t process;
    uint64_t image_base;
    uint64_t text_section_size;
    uint64_t image_size;
};

namespace hc {



    // 发送超调用探测虚拟机监控程序以确认其正常运行
    void ping(vcpu* cpu);

    // a hypercall for quick testing
    void test(vcpu* cpu);

    // 去虚拟化当前 vCPU
    void unload(vcpu* cpu);

    // 读取 from arbitrary 物理内存
    void read_phys_mem(vcpu* cpu);

    // 写入 to arbitrary 物理内存
    void write_phys_mem(vcpu* cpu);

    // 读取 from 虚拟内存 in another process
    void read_virt_mem(vcpu* cpu);

    // 写入 to 虚拟内存 in another process
    void write_virt_mem(vcpu* cpu);

    // 获取 the kernel CR3 值 of an arbitrary process
    void query_process_cr3(vcpu* cpu);

    // 安装 an EPT hook for the 当前 逻辑处理器 ONLY
    void install_ept_hook(vcpu* cpu);

    // 卸载移除 a previously installed EPT hook
    void remove_ept_hook(vcpu* cpu);

    // 刷新 the hypervisor logs into a 缓冲区
    void flush_logs(vcpu* cpu);

    // translate a virtual 地址 to its physical 地址
    void get_physical_address(vcpu* cpu);

    // hide a physical page from the guest
    void hide_physical_page(vcpu* cpu);

    // unhide a physical page from the guest
    void unhide_physical_page(vcpu* cpu);

    // Append a single PFN to the deferred-hide queue (callable from any
    // 上下文, no bulk-hide happens until commit). args[0] = PFN.
    void prepare_self_hide_add(vcpu* cpu);

    // Publish the pending_hide_vcpu_bitmap (all vcpus) and TSC threshold,
    // arming the vm-exit dispatcher to consume the queue. args[0] = delay_us.
    void prepare_self_hide_commit(vcpu* cpu);

    // Master switch for KTHREAD.Affinity rewrite in hv::CallUser. args[0]: 1=on, 0=off.
    void set_affinity_lock(vcpu* cpu);
    void set_keep_hv_on_unload(vcpu* cpu);

    // Dump PoolManager active blocks for guest-模式 caller (mapDriver) so it
    // can apply MmSetPageProtection on the system PTEs. args[0]=out buf gva
    // (数组 of {va,大小尺寸,tag} records), args[1]=max records. rax = 数量计数.
    void get_pool_blocks(vcpu* cpu);

    // Dump hide-consume diagnostics into caller-provided 6 x uint64 缓冲区 at
    // args[0]: enter, pte_total, pte_null, done_bitmap, max_ept_split_used,
    // ept_split_capacity.
    void get_hide_diag(vcpu* cpu);

    // Hide a list of PFNs on the 当前 vcpu only (mapDriver issues this
    // inside a KeSetSystemGroupAffinityThread loop, one call per CPU, so
    // each vcpu hides on its own ept tree — no cross-vcpu EPT writes).
    // args[0] = guest VA of uint64[数量计数] PFN 数组, args[1] = 数量计数.
    // Returns 数量计数 of PFNs 执行成功fully redirected to dummy_page_pfn.
    void hide_pfn_list(vcpu* cpu);

    void ept_probe_install(vcpu* cpu);
    void ept_probe_remove(vcpu* cpu);
    void ept_probe_get_hits(vcpu* cpu);
    void ept_probe_clear_hits(vcpu* cpu);
    void get_resident_hv_diag(vcpu* cpu);
    void set_host_rsp(vcpu* cpu);
    void map_host_range(vcpu* cpu);
    void set_host_rip(vcpu* cpu);
    void dbg_dispatch(vcpu* cpu);

    // 获取 the base 地址 of the hypervisor
    void get_hv_base(vcpu* cpu);

    // 写入 to the logger whenever a certain 物理内存 range is accessed
    void install_mmr(vcpu* cpu);

    // 卸载移除 a monitored memory range
    void remove_mmr(vcpu* cpu);

    // 卸载移除 every installed MMR
    void remove_all_mmrs(vcpu* cpu);


    void install_breakpoint_hook(vcpu* cpu);


    void remove_breakpoint_hook(vcpu* cpu);

    void add_protect_process(vcpu* cpu);

    void remove_protect_process(vcpu* cpu);


    void add_cr3_monitor(vcpu* cpu);

    void remove_cr3_monitor(vcpu* cpu);

    void enable_cr3_monitor_check_thread(vcpu* cpu);

    void disable_cr3_monitor_check_thread(vcpu* cpu);

    void enable_check_monitor_check_rip(vcpu* cpu);
    void disable_check_monitor_check_rip(vcpu* cpu);

    void cr3_monitor_jmp(vcpu* cpu);

    void add_cr3_monitor_thread_s(vcpu* cpu);

    void remove_cr3_monitor_thread_s(vcpu* cpu);

    void active_cr3_monitor_data_region(vcpu* cpu);

    void add_cr3_map(vcpu* cpu);

    void add_cr3_map_by_user_mode(vcpu* cpu);

    void remove_cr3_map(vcpu* cpu);

    void start_get_game_cr3(vcpu* cpu);

    void start_get_game_cr3_by_pid(vcpu* cpu);

    void get_src_cr3(vcpu* cpu);

    void add_real_cr3(vcpu* cpu);

    // Host-managed EPT hook handlers (see vt/ept-hook.cpp)
    void vmcall_eh_install(vcpu* cpu);
    void vmcall_eh_remove(vcpu* cpu);
    void vmcall_eh_enable(vcpu* cpu);
    void vmcall_eh_disable(vcpu* cpu);
    void vmcall_eh_write(vcpu* cpu);
    void vmcall_eh_get_va(vcpu* cpu);
    void vmcall_eh_remove_all_by_process(vcpu* cpu);

    // Host-managed VTCall hook handlers (see vt/vtcall-hook.cpp)
    void vmcall_vh_install(vcpu* cpu);
    void vmcall_vh_install_ret_abs(vcpu* cpu);
    void vmcall_vh_enable(vcpu* cpu);
    void vmcall_vh_disable(vcpu* cpu);
    void vmcall_vh_remove(vcpu* cpu);
    void vmcall_vh_uninit(vcpu* cpu);
    void vmcall_vh_find_blank(vcpu* cpu);
    void vmcall_vh_find_blank_page(vcpu* cpu);
    void vmcall_vh_tramp_add_page(vcpu* cpu);
    void vmcall_vh_tramp_add_slot(vcpu* cpu);
    void vmcall_vh_tramp_set_ready(vcpu* cpu);
}


} // namespace hv

