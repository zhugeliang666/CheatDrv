// Payload VM-exit bridge implementation.
//
// This file is intentionally included by payload.cpp instead of being compiled
// as a separate translation unit: most helpers and counters are internal/static
// to the 常驻 Payload image, and keeping one TU avoids changing linkage or
// the driver project while making the bridge code easier to navigate.

// MOV-CR emulation is staged separately because CR0/CR4 shadow/fixed-bit
// handling can poison VMCS 状态 before the legacy TestDriver handler sees the
// exit.  It is enabled only after hook/#BP/EPT paths proved stable.
#ifndef VT_MOV_CR_HANDLER_ENABLED
#define VT_MOV_CR_HANDLER_ENABLED 1
#endif

// DWM-safe bridge gates.  dbg_dispatch and payload-owned dbg-watch EPT/MTF are
// handled by the 常驻 Payload; ordinary INT3 reinjection remains staged.
#ifndef VT_DWM_SAFE_BRIDGE_ENABLED
#define VT_DWM_SAFE_BRIDGE_ENABLED 1
#endif

// Stage 1 after the DWM-safe baseline: allow only hook-分发 VMCALL
// passthrough back in.  INT3/#BP and EPT/MTF stay disabled below.

// Stage 2: allow the bridge to classify/observe #BP while keeping ordinary
// guest INT3 reinjection forwarded to the legacy TestDriver/dbg handler.
// VtRet/trampoline modes still 默认 to observe in payload.cpp, so their
// active RIP mutation stays off for this test.


// Stage 5: 启用 resident EPT handling only with dbg_watch-aware guards.

#ifndef PAYLOAD_BP_HANDLER_ENABLED
#if VT_DWM_SAFE_BRIDGE_ENABLED
#define PAYLOAD_BP_HANDLER_ENABLED 1
#else
#define PAYLOAD_BP_HANDLER_ENABLED 1
#endif
#endif

#ifndef PAYLOAD_HOOK_DISPATCH_ENABLED
#if VT_DWM_SAFE_BRIDGE_ENABLED
#define PAYLOAD_HOOK_DISPATCH_ENABLED 1
#else
#define PAYLOAD_HOOK_DISPATCH_ENABLED 1
#endif
#endif

#ifndef PAYLOAD_EPT_TRAMP_HANDLER_ENABLED
#if VT_DWM_SAFE_BRIDGE_ENABLED
#define PAYLOAD_EPT_TRAMP_HANDLER_ENABLED 1
#else
#define PAYLOAD_EPT_TRAMP_HANDLER_ENABLED 1
#endif
#endif

#ifndef PAYLOAD_EPT_MTF_HANDLER_ENABLED
#define PAYLOAD_EPT_MTF_HANDLER_ENABLED PAYLOAD_EPT_TRAMP_HANDLER_ENABLED
#endif

// After status/模式/ping moved behind resident root-模式 hypercalls and full
// payload image/direct hide passed, unknown keyed VMCALLs should not fall back
// into the quarantined TestDriver path anymore.  Non-VMCALL exits and bad-key
// hook-分发 misses remain forwarded/observable.
#ifndef PAYLOAD_FAIL_CLOSED_UNHANDLED_VMCALLS
#define PAYLOAD_FAIL_CLOSED_UNHANDLED_VMCALLS 1
#endif


#include "bridge/core/memory_access.inl"
#include "bridge/core/bridge_forwarding.inl"
#include "bridge/vtret/vtret_types.inl"
#include "bridge/core/host_guest_access.inl"
#include "bridge/vtret/vtret_dispatch.inl"
#include "bridge/tramp/tramp_dispatch.inl"
#include "bridge/exits/breakpoint_reinject.inl"
#include "bridge/exits/misc_exits.inl"
#include "bridge/ept/ept_trampoline.inl"
#include "bridge/hooks/hook_dispatch.inl"
#include "bridge/exits/vmexit_common.inl"
#include "bridge/hypercall/resident_commands.inl"
#include "bridge/hypercall/hook_management.inl"
#include "bridge/debug/debug_core.inl"
#include "bridge/memcheck/memcheck_runtime.inl"
#include "bridge/debug/debug_watch.inl"
#include "bridge/selfstop/self_stop.inl"
#include "bridge/entry/bridge_entry.inl"
