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

// ---------------------------------------------------------------------------
// TSC 透明抹平总开关
//
// 0 = 停用：VMCS TSC_OFFSET 恒 0，回到 ABI85 行为。
// 1 = 启用：每次 VM-exit 的宿主耗时（entry 硬件延迟 + bridge dispatch +
//     exit 硬件延迟）都换算成负向 TSC_OFFSET，在 VMRESUME 前写回 VMCS，
//     使 guest 的 RDTSC/RDTSCP 观测不到虚拟化开销。
//
// PAYLOAD_TSC_FIXED_OVERHEAD 必须按目标机型标定，取值 =
//     RDTSCP 自身耗时(~0x58) + VM-entry 硬件延迟 + VM-exit 硬件延迟
//     + asm 尾部恢复现场/VMRESUME 前的固定指令延迟
// 标定方法见 vt/VtHypervisor/vt/timing.cpp::measure_vm_exit_tsc_overhead()。
// ---------------------------------------------------------------------------
#ifndef PAYLOAD_TSC_COMP_ENABLED
#define PAYLOAD_TSC_COMP_ENABLED 0
#endif

#ifndef PAYLOAD_TSC_FIXED_OVERHEAD
#define PAYLOAD_TSC_FIXED_OVERHEAD 0x320ull
#endif

// 单次 exit 计入的补偿上限（≈5.4μs @3GHz）：宿主长中断不能被整段抹掉
#define PAYLOAD_TSC_PER_EXIT_CAP 0x4000ull
// 累计负向偏移幅值上限（≈175μs @3GHz）。该幅值同时就是 IA32_TSC_DEADLINE 的
// 最大触发偏移量，因此必须小于 Windows 定时器分辨率（1ms 级），才能免于拦截并
// 重写 deadline MSR（重写会引入 APIC 定时器状态机风险）。
#define PAYLOAD_TSC_TOTAL_CAP 0x80000ull
// 幅值逼近上限时每次 exit 回收的 cycles（guest 时间轴平滑加速，单调无跳变）
#define PAYLOAD_TSC_DECAY_STEP 8ull
// 跨核幅值收敛死区（≈0.68μs @3GHz）：低于一次 RDTSC 抖动量级，不可观测
#define PAYLOAD_TSC_CROSS_TOLERANCE 0x800ull

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
#include "..\VtBootstrapDriver\common\vt_call_abi.h"
#include "..\business_backup\pmo\pmo_state.inl"
#include "..\business_backup\pmo\pmo_callout_state.inl"
#include "..\business_backup\pmo\runtime\user_call.inl"
#include "bridge/vtret/vtret_dispatch.inl"
#include "bridge/tramp/tramp_dispatch.inl"
#include "bridge/exits/breakpoint_reinject.inl"
#include "bridge/exits/misc_exits.inl"
#include "bridge/ept/ept_trampoline.inl"
#include "bridge/exits/vmexit_common.inl"
#include "bridge/hypercall/resident_commands.inl"
#include "bridge/hypercall/hook_management.inl"
#include "bridge/debug/debug_core.inl"
#include "bridge/hooks/hook_dispatch.inl"
#include "bridge/memcheck/memcheck_runtime.inl"
#include "bridge/debug/debug_watch.inl"
#include "bridge/selfstop/self_stop.inl"
#include "bridge/entry/bridge_entry.inl"
