#pragma once

#include <ntddk.h>
#include <stdint.h>

namespace hv {

struct vcpu;

namespace vh {

// Initialize the host-side VTCall hook subsystem.
// Currently a no-op (state lives in g_vt_hook_table from gamecommon/game.cpp,
// already zero-initialized). Reserved for future locking/state.
void init_vtcall_hook_subsystem();

}  // namespace vh

// Host-internal install path: callable from any host root-mode code, bypasses
// the driver-side broadcast vmcall. Returns true on success. process=nullptr
// → system process / system_cr3 (use for kernel function hooks).
//
// process is void* not PEPROCESS to avoid type-decoration mismatch between
// TUs that include ntddk.h directly (_EPROCESS*) vs fltKernel.h indirectly
// (_KPROCESS*) — the underlying pointer is opaque to this layer anyway.
bool vh_install_host(vcpu* cpu, void* process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable);

// DEFERRED variant of vh_install_host. Current vCPU installs OWN ept tree
// immediately; other vCPUs are enqueued and install their own ept tree on
// their next vmexit. Avoids the cross-vCPU EPT-write race when target page
// is hot (e.g. dxgi GetBuffer page during DWM rendering).
bool vh_install_host_deferred(vcpu* cpu, void* process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable);

// Host-internal blank scanner. Pass target_cr3=0 to use system_cr3 (kernel
// scan). Returns the address of the byte just past a 4-byte 0xCC run inside
// [start, start+max_scan), or 0 if none found.
uint64_t vh_find_blank_host(uint64_t start, uint64_t max_scan, uint64_t target_cr3);

}  // namespace hv
