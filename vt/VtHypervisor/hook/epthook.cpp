#include "epthook.h"
#include "../hv/hv.h"

namespace epthook
{
    // Host owns all EPT hook state (vt/ept-hook.cpp). Driver layer is a
    // pure VMCALL wrapper. Init/uninit are no-ops because the host inline
    // table (hv::g_ghv->ept_hook_table) is initialized from hv::create() and
    // torn down implicitly on driver unload (free of ghv image).

    void hook_init() {
        // intentionally empty
    }

    void hook_uninit() {
        // intentionally empty
    }

    static inline uint32_t make_install_flags(bool full_zero, bool is_fake_page) {
        return (full_zero ? 1u : 0u) | (is_fake_page ? 2u : 0u);
    }

    void hook_install(PEPROCESS process, uint64_t pf, bool isFullZero, bool is_fake_page, bool /*is_switch_cr3*/) {
        hv::vmcall_eh_install(process, pf, make_install_flags(isFullZero, is_fake_page));
    }

    void hook_remove(PEPROCESS process, uint64_t pf, bool /*is_switch_cr3*/) {
        hv::vmcall_eh_remove(process, pf);
    }

    void hook_enable(PEPROCESS process, uint64_t pf, bool /*is_switch_cr3*/) {
        hv::vmcall_eh_enable(process, pf);
    }

    void hook_disable(PEPROCESS process, uint64_t pf, bool /*is_switch_cr3*/) {
        hv::vmcall_eh_disable(process, pf);
    }

    void hook_write(PEPROCESS process, uint64_t dst_va, uint64_t buffer_va, uint64_t size, bool /*isSetWrite*/, bool /*is_switch_cr3*/) {
        // Ensure the hook entry exists (idempotent if already installed).
        hv::vmcall_eh_install(process, dst_va, 0);
        hv::vmcall_eh_write(process, dst_va, buffer_va, size);
    }

    void hook_write_fake(PEPROCESS process, uint64_t dst_va, uint64_t buffer_va, uint64_t size) {
        // Install in fake-page mode (R/W trap).
        hv::vmcall_eh_install(process, dst_va, 2);
        hv::vmcall_eh_write(process, dst_va, buffer_va, size);
    }

    void hook_get_va(PEPROCESS process, uint64_t pf, uint64_t& fake_va, bool is_fake_page, bool /*is_switch_cr3*/) {
        hv::vmcall_eh_install(process, pf, make_install_flags(false, is_fake_page));
        fake_va = hv::vmcall_eh_get_va(process, pf);
    }

    void hook_remove_by_va(PEPROCESS process, uint64_t dst_va, bool /*is_switch_cr3*/) {
        hv::vmcall_eh_remove(process, dst_va);
    }

    void hook_remove_all_by_process(PEPROCESS process, bool /*is_switch_cr3*/) {
        hv::vmcall_eh_remove_all_by_process(process);
    }

    void hook_read(PEPROCESS /*process*/, uint64_t /*dst_va*/, uint64_t /*src_va*/, uint64_t /*size*/, bool /*is_switch_cr3*/) {
        // No external callers in the active code paths. Kept as a stub for
        // API compatibility; can be removed once the header is cleaned up.
    }

    ept_hook_data* hook_get_hook_data(PEPROCESS /*process*/, uint64_t /*pf_va*/) {
        // Host-side table is not exposed to driver. No external caller relies on
        // the return value in active code paths; returns nullptr.
        return nullptr;
    }

    void set_copy_write(PEPROCESS process, uint64_t dst_va, uint64_t /*size*/, bool /*isAll*/) {
        // Install in fake-page (R/W trap) mode on the target page.
        hv::vmcall_eh_install(process, dst_va, 2);
    }

    bool set_copy_write_user(PEPROCESS process, uint64_t dst_va, uint64_t /*size*/, bool /*isAll*/) {
        hv::vmcall_eh_install(process, dst_va, 2);
        return true;
    }

} // namespace epthook
