#include <fltKernel.h>
#include "vtcallhook.h"
#include "../hv/hv.h"

// All driver-side state has been moved to host (vt/vtcall-hook.cpp).
// These functions are thin VMCALL wrappers; no NT API usage besides the
// per-CPU affinity loop already encapsulated in hv/hv.h.

namespace vtcallhook {

ULONG64 find_blank(ULONG64 start, ULONG max_scan) {
    return hv::vmcall_vh_find_blank(PsGetCurrentProcess(), start, max_scan);
}

// Scan with system process / system_cr3 — used for finding kernel blanks
// in ntoskrnl padding (no need to attach to any user process).
ULONG64 find_blank_system(ULONG64 start, ULONG max_scan) {
    return hv::vmcall_vh_find_blank(nullptr, start, max_scan);
}

bool install(PEPROCESS process, PVOID target, ULONG64 blank_mem,
             UINT64 type, bool /*lock_mdl*/, bool filter_by_process,
             UINT8 dispatch_mode, bool auto_enable) {
    hv::vmcall_vh_install(process, reinterpret_cast<uint64_t>(target), blank_mem,
                          static_cast<uint8_t>(type), dispatch_mode,
                          filter_by_process, auto_enable);
    return true;
}

bool install_ret_abs(PEPROCESS /*process*/, PVOID /*target*/, ULONG64 /*blank_mem*/,
                     UINT64 /*type*/, PVOID /*hook_fn*/, PVOID* /*original_out*/,
                     ULONG64 /*trample_addr*/, bool /*filter_by_process*/,
                     bool /*auto_enable*/) {
    // Not exercised by current call sites after the host-side rewrite.
    // Re-add a host-side handler if a future caller needs RetAbs trampolines.
    return false;
}

void enable(PVOID target) {
    hv::vmcall_vh_enable(reinterpret_cast<uint64_t>(target));
}

void disable(PVOID target) {
    hv::vmcall_vh_disable(reinterpret_cast<uint64_t>(target));
}

void remove(PVOID target) {
    hv::vmcall_vh_remove(PsGetCurrentProcess(), reinterpret_cast<uint64_t>(target));
}

void uninit() {
    hv::vmcall_vh_uninit();
}

} // namespace vtcallhook
