#pragma once
#include "stdint.h"
#include <fltkernel.h>

#include "../common/ntutils.h"

#define _IN_
#define _Out_

namespace epthook
{
    typedef enum _EPT_STATUS{
        EPT_STATUS_SUCCESS = 0,
        EPT_UNINSTALL_ERROR,
    }EPT_STATUS;

    // Placeholder type retained only for API compatibility with the legacy
    // hook_get_hook_data() declaration. All hook state lives in the host
    // (vt/ept-hook.cpp) and is no longer exposed to driver-side callers.
    struct ept_hook_data;

    // Initialization is performed entirely on the host side now
    // (hv::eh::init_ept_hook_table from hv::create). These remain as no-ops
    // for source compatibility with existing call sites.
    void hook_init();
    void hook_uninit();

    // Install / remove / enable / disable an EPT hook on a (process, va) page.
    // All operations dispatch to the host via VMCALL (per-CPU broadcast).
    void hook_install(PEPROCESS process,_IN_ uint64_t pf,bool isFullZero = false,bool is_fake_page = false,bool is_switch_cr3 = false);
    void hook_remove(PEPROCESS process,_IN_ uint64_t pf, bool is_switch_cr3 = false);
    void hook_enable(PEPROCESS process,uint64_t pf, bool is_switch_cr3 = false);
    void hook_disable(PEPROCESS process,uint64_t pf, bool is_switch_cr3 = false);

    // Read / write helpers operating on the host-managed fake page.
    void hook_read(PEPROCESS process,uint64_t dst_va,uint64_t src_va,uint64_t size, bool is_switch_cr3 = false);
    void hook_write(PEPROCESS process, uint64_t dst_va, uint64_t buffer_va, uint64_t size, bool isSetWrite = true,bool is_switch_cr3 = false);
    void hook_write_fake(PEPROCESS process, uint64_t dst_va, uint64_t buffer_va, uint64_t size);

    // Remove by VA / by process.
    void hook_remove_by_va(PEPROCESS process,uint64_t dst_va, bool is_switch_cr3 = false);
    void hook_remove_all_by_process(PEPROCESS process, bool is_switch_cr3 = false);

    // Resolve the host VA of the fake-page byte that corresponds to (process, va).
    // Auto-installs the hook entry if needed.
    void hook_get_va(PEPROCESS process,uint64_t pf,uint64_t& fake_va,bool is_fake_page = false, bool is_switch_cr3 = false);

    // Legacy: returns nullptr now (no driver-side hook table).
    ept_hook_data* hook_get_hook_data(PEPROCESS process,uint64_t pf_va);

    // Install in fake-page (read/write trap) mode.
    void set_copy_write(PEPROCESS process, uint64_t dst_va, uint64_t size,bool isAll = false);
    bool set_copy_write_user(PEPROCESS process, uint64_t dst_va, uint64_t size, bool isAll = false);

} // namespace epthook
