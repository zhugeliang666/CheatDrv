#pragma once

//#define ORIGINAL_DEBUG

#include  "fltKernel.h"
#include "ia32.hpp"
#include"xorstr.h"

# define MEM_TAG 'sdkd'

// =====================================================================
// Master log switch 鈥?set to 0 for release-clean builds (no DbgPrintEx
// calls in the binary), 1 for development (full LOG_DEBUG / LOG_INFO).
//
// Mirror of TestDriver/base.h::YVT_LOG_ENABLED so the two drivers can
// be flipped independently.
// =====================================================================
#ifndef MAPDRIVER_LOG_ENABLED
#define MAPDRIVER_LOG_ENABLED 0
#endif

// Temporary debug switches: keep all mapDriver-side hiding / cleanup paths off
// while testing load/unload stability. Re-enable one by one after unload is
// proven stable.
#ifndef MAPDRIVER_DRIVER_FILE_HIDE_ENABLED
#define MAPDRIVER_DRIVER_FILE_HIDE_ENABLED 0
#endif

#ifndef MAPDRIVER_DRIVER_FILE_DELETE_ENABLED
#define MAPDRIVER_DRIVER_FILE_DELETE_ENABLED 0
#endif

#ifndef MAPDRIVER_REGISTRY_DELETE_ENABLED
#define MAPDRIVER_REGISTRY_DELETE_ENABLED 1
#endif

#ifndef MAPDRIVER_TRACE_CLEAN_ENABLED
#define MAPDRIVER_TRACE_CLEAN_ENABLED 1
#endif

#ifndef MAPDRIVER_IMAGE_WIPE_ENABLED
#define MAPDRIVER_IMAGE_WIPE_ENABLED 1
#endif

// First migration stage:
//   1 = after TestDriver starts VT and payload starts successfully, immediately
//       handoff: unload TestDriver/stop VT and keep payload resident.
//   0 = keep the previous manual mode; call payload_ctl.exe handoff yourself.
#ifndef MAPDRIVER_AUTO_HANDOFF_AFTER_PAYLOAD
#define MAPDRIVER_AUTO_HANDOFF_AFTER_PAYLOAD 0
#endif

// One-key resident path:
//   1 = after TestDriver+payload start, automatically run the already-tested
//       manual chain: legacy arm -> switchrsp -> switchbridge -> handoff
//       keepctl -> cutover clear -> freetest -> drop mapDriver ctl.
//   0 = manual/debug mode; payload_ctl keeps driving every step.
#ifndef MAPDRIVER_AUTO_ONEKEY_LOAD
#define MAPDRIVER_AUTO_ONEKEY_LOAD 0
#endif

// Keep this 0 while validating the one-key path: the mapper sees a successful
// load and payload_ctl can still query the resident control after mapDriver ctl
// is dropped.  Flip to 1 only for the final no-service footprint build.
#ifndef MAPDRIVER_AUTO_ONEKEY_RETURN_FAILURE
#define MAPDRIVER_AUTO_ONEKEY_RETURN_FAILURE 1
#endif

// Validation mode: keep mapDriver ctl alive and use it for status/memcheck
// after the payload image/direct/pool pages are hidden.  Final footprint builds
// should set KEEP_MAP_CTL=0 and DROP_MAP_CTL=1.
#ifndef MAPDRIVER_AUTO_ONEKEY_KEEP_MAP_CTL
#define MAPDRIVER_AUTO_ONEKEY_KEEP_MAP_CTL 0
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_DROP_MAP_CTL
#define MAPDRIVER_AUTO_ONEKEY_DROP_MAP_CTL 0
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_WAIT_PMO_READY
#define MAPDRIVER_AUTO_ONEKEY_WAIT_PMO_READY 0
#endif

// One-key execution mode:
//   0 = no PsCreateSystemThread; run synchronously from DriverMain through
//       KeExpandKernelStackAndCallout. This is the low-artifact final path.
//   1 = old debug path; queue a dedicated system thread and return quickly.
#ifndef MAPDRIVER_AUTO_ONEKEY_USE_THREAD
#define MAPDRIVER_AUTO_ONEKEY_USE_THREAD 0
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_EXPAND_STACK_SIZE
#define MAPDRIVER_AUTO_ONEKEY_EXPAND_STACK_SIZE 0x10000ull
#endif

// Fixed pre-onekey delay.  Keep this 0 for the low-latency final path; the
// actual readiness gate is mapdriver_onekey_wait_payload_barrier() and the
// post-switchbridge migration check.
#ifndef MAPDRIVER_AUTO_ONEKEY_INITIAL_DELAY_MS
#define MAPDRIVER_AUTO_ONEKEY_INITIAL_DELAY_MS 0
#endif

// Loader-only lifecycle policy.  The external loader's normal load/unload
// buttons are the authoritative lifecycle path for validation.  If DriverMain
// sees HV already active, that means the previous loader unload did not finish;
// do not return STATUS_SUCCESS and make the loader think a fresh load happened.
#ifndef MAPDRIVER_FAIL_LOAD_IF_HV_ALREADY_READY
#define MAPDRIVER_FAIL_LOAD_IF_HV_ALREADY_READY 1
#endif

#ifndef MAPDRIVER_UNLOAD_RETRY_COUNT
#define MAPDRIVER_UNLOAD_RETRY_COUNT 30
#endif

#ifndef MAPDRIVER_UNLOAD_RETRY_DELAY_MS
#define MAPDRIVER_UNLOAD_RETRY_DELAY_MS 100
#endif

// Keep resident control usable in validation builds.  Hiding resident pool
// blocks can also hide metadata that live status/memcheck uses.  The final
// no-ctl seal path can flip this to 1 or run a one-shot repair/seal command.
#ifndef MAPDRIVER_AUTO_ONEKEY_HIDE_RESIDENT_POOLS
#define MAPDRIVER_AUTO_ONEKEY_HIDE_RESIDENT_POOLS 1
#endif

// Strict final payload hide: hide the whole preallocated payload arena
// (MAPDRIVER_PAYLOAD_ARENA_SIZE), not only the arena_used prefix.  This covers
// the currently unused tail as well, so memcheck "all" can verify the full
// 32 MiB allocation instead of only the active/managed arena range.
#ifndef MAPDRIVER_AUTO_ONEKEY_HIDE_FULL_ARENA
#define MAPDRIVER_AUTO_ONEKEY_HIDE_FULL_ARENA 1
#endif

// Before any PFN-hide/RW seal work, make sure VMX-root HOST_CR3 has private
// mappings for pool pages that may contain executable hook/trampoline code.
// This is intentionally only a HOST_CR3 mapping step: it must not touch guest
// PTEs or EPT visibility.
#ifndef MAPDRIVER_PAYLOAD_HOSTMAP_CODE_POOLS
#define MAPDRIVER_PAYLOAD_HOSTMAP_CODE_POOLS 1
#endif

// Wider bisect switch. Keep off by default: mapping every adopted PoolManager
// block can cover hundreds of MiB and is not needed for the first "code pool"
// coverage pass. Enable only if data pool pages also need private HOST_CR3
// coverage before a later guest-PTE seal stage.
#ifndef MAPDRIVER_PAYLOAD_HOSTMAP_ALL_POOLS
#define MAPDRIVER_PAYLOAD_HOSTMAP_ALL_POOLS 0
#endif

// Stability diagnostic gate: after payload takes over HOST_RIP/RSP, do not
// immediately hide payload image/direct/stack/arena from the one-key path.
// The MM/EPT crash currently happens right after freetest-skip, before the
// final "onekey complete" line, so keep resident ranges visible and let manual
// hide/memcheck commands bisect the PFN-hide path later.
#ifndef MAPDRIVER_AUTO_ONEKEY_HIDE_AFTER_HANDOFF
#define MAPDRIVER_AUTO_ONEKEY_HIDE_AFTER_HANDOFF 1
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_MIN_PMO_DRAWS
#define MAPDRIVER_AUTO_ONEKEY_MIN_PMO_DRAWS 8ull
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_MIN_BUSINESS_TICKS
#define MAPDRIVER_AUTO_ONEKEY_MIN_BUSINESS_TICKS 1ull
#endif

// Diagnostic unload-stability gate.  When this is 0, one-key handoff keeps the
// mapped TestDriver image quarantined instead of running the freetest/free-image
// phase.  Full unload can then clear KEEP_HV_ON_UNLOAD and call TestDriver's
// original DriverUnload once, avoiding the payload self-stop path that can hang
// in VT without producing a dump.
#ifndef MAPDRIVER_AUTO_ONEKEY_FREE_TEST_IMAGE
#define MAPDRIVER_AUTO_ONEKEY_FREE_TEST_IMAGE 1
#endif

// Diagnostic fallback gate.  During resident handoff, keep mapDriver's
// TestDriver ownership state as "loaded/not quarantined" so the legacy
// TestDriver handler remains the explicit fallback for VM-exit paths that the
// payload has not migrated yet.  Hide/MM/GetBuffer switches are unchanged.
#ifndef MAPDRIVER_KEEP_TESTDRIVER_ON_HANDOFF
#define MAPDRIVER_KEEP_TESTDRIVER_ON_HANDOFF 0
#endif

// Soft-quarantine gate for the legacy VM-exit target.  The resident payload is
// not yet a complete replacement for every TestDriver VM-exit path.  Clearing
// the legacy target immediately after handoff makes normal Windows Hyper-V/HAL
// probes (for example HviIsAnyHypervisorPresent) take the no-target fail path
// and inject a guest #GP.  Keep the bridge target available while the mapped
// TestDriver image is only quarantined/not freed; only clear it for the real
// freetest/free-image phase.
#ifndef MAPDRIVER_CLEAR_TESTDRIVER_FALLBACK_ON_HANDOFF
#define MAPDRIVER_CLEAR_TESTDRIVER_FALLBACK_ON_HANDOFF 1
#endif

// Resident payload private arena.  This is allocated once during bootstrap
// and then treated as payload-owned memory so later runtime allocations stay in
// a known range that can be hidden/released as a single unit.
#ifndef MAPDRIVER_PAYLOAD_ARENA_SIZE
#define MAPDRIVER_PAYLOAD_ARENA_SIZE 0x2000000ul
#endif

// Physical-machine policy: use MmAllocateIndependentPages for bootstrap,
// PoolManager, and payload-owned backing.  The old ExAllocatePoolWithTag path
// was only a VM bisect fallback and should stay off in the normal build.
#ifndef MAPDRIVER_FORCE_EXALLOCPOOL
#define MAPDRIVER_FORCE_EXALLOCPOOL 0
#endif

// Only used if MAPDRIVER_FORCE_EXALLOCPOOL is explicitly re-enabled for a
// named bisect.
#ifndef MAPDRIVER_FORCE_EXALLOCPOOL_TYPE
#define MAPDRIVER_FORCE_EXALLOCPOOL_TYPE NonPagedPoolExecute
#endif

// Unload-stability diagnostic gate.  The payload arena is allocated with
// MmAllocateIndependentPages during bootstrap and later handed to resident
// payload runtime.  Repeated load/unload tests have hit PFN_LIST_CORRUPT inside
// MmFreeIndependentPages(payloadArenaBase) during mapDriver unload, so keep the
// arena quarantined/leaked for the current stability baseline.  Re-enable this
// only after arena ownership/refcount is audited and validated separately.
#ifndef MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD
#define MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD 0
#endif

// Experimental VT migration switch. 0 keeps the stable behavior: TestDriver
// unload stops VT. 1 passes a boot flag so TestDriver leaves VT resident during
// handoff; the TestDriver image must then stay quarantined.
#ifndef MAPDRIVER_TESTDRIVER_KEEP_HV_ON_HANDOFF
#define MAPDRIVER_TESTDRIVER_KEEP_HV_ON_HANDOFF 1
#endif

// Temporary switches for the mapDriver-driven TestDriver stealth pass.
// Keep both off while debugging business data. The code remains present and can
// be re-enabled by setting these to 1.
#ifndef MAPDRIVER_TESTDRIVER_HIDE_ENABLED
#define MAPDRIVER_TESTDRIVER_HIDE_ENABLED 0
#endif

#ifndef MAPDRIVER_TESTDRIVER_LOCK_ENABLED
#define MAPDRIVER_TESTDRIVER_LOCK_ENABLED 0
#endif

// Payload memory hide is prepared but kept off for the current unload-stability
// baseline.  The hidden-memory path is validated separately; mixing it with
// TestDriver/hv::stop teardown caused no-dump VT resets during pre-unhide.
#ifndef MAPDRIVER_PAYLOAD_HIDE_ENABLED
#define MAPDRIVER_PAYLOAD_HIDE_ENABLED 1
#endif

// Full unload must not issue pre-unhide VMCALLs in this baseline.  The previous
// per-page and batched unhide paths both crashed/reset in VT before
// TestDriver::DriverUnload/hv::stop diagnostics could run.
#ifndef MAPDRIVER_FULL_UNLOAD_PRE_UNHIDE_ENABLED
#define MAPDRIVER_FULL_UNLOAD_PRE_UNHIDE_ENABLED 0
#endif

// Payload image/direct hiding.  Validation keeps mapDriver ctl alive for
// status/memcheck, so payload image/direct can still be hidden while control
// queries go through mapDriver instead of the resident WDM device.
#ifndef MAPDRIVER_PAYLOAD_HIDE_IMAGE_ENABLED
#define MAPDRIVER_PAYLOAD_HIDE_IMAGE_ENABLED 1
#endif

#ifndef MAPDRIVER_PAYLOAD_HIDE_ARENA_ENABLED
#define MAPDRIVER_PAYLOAD_HIDE_ARENA_ENABLED 1
#endif

#ifndef MAPDRIVER_PAYLOAD_HIDE_DIRECT_ENABLED
#define MAPDRIVER_PAYLOAD_HIDE_DIRECT_ENABLED 1
#endif

// Keep the last N pages of the TestDriver image visible/unlocked. These tail
// pages are skipped by both EPT hide and MmSetPageProtection lockdown.
#ifndef MAPDRIVER_TESTDRIVER_TAIL_VISIBLE_PAGES
#define MAPDRIVER_TESTDRIVER_TAIL_VISIBLE_PAGES 50
#endif

#if MAPDRIVER_LOG_ENABLED

#ifndef _DEBUG_FORMAT
#define _DEBUG_FORMAT
#define LOG_DEBUG(format, ...)       DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_INFO(format, ...)        DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_WARN(format, ...)        DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_ERROR(format, ...)       DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_DEBUG_SAFE(format, ...)  DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_INFO_SAFE(format, ...)   DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_WARN_SAFE(format, ...)   DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_ERROR_SAFE(format, ...)  DbgPrintEx(0, 0, format, __VA_ARGS__)
#endif // !_DEBUG_FORMAT

#else  // MAPDRIVER_LOG_ENABLED == 0 鈥?silent build
#define LOG_DEBUG(format, ...)       ((void)0)
#define LOG_INFO(format, ...)        ((void)0)
#define LOG_WARN(format, ...)        ((void)0)
#define LOG_ERROR(format, ...)       ((void)0)
#define LOG_DEBUG_SAFE(format, ...)  ((void)0)
#define LOG_INFO_SAFE(format, ...)   ((void)0)
#define LOG_WARN_SAFE(format, ...)   ((void)0)
#define LOG_ERROR_SAFE(format, ...)  ((void)0)
#define  VMProtectDecryptStringA
#endif



#define THREAD_TERMINATE						(0x0001)  
#define THREAD_SUSPEND_RESUME					(0x0002)  
#define THREAD_GET_CONTEXT						(0x0008)  
#define THREAD_SET_CONTEXT						(0x0010)  
#define THREAD_QUERY_INFORMATION				(0x0040)  
#define THREAD_SET_INFORMATION					(0x0020)  
#define THREAD_SET_THREAD_TOKEN					(0x0080)
#define THREAD_IMPERSONATE						(0x0100)
#define THREAD_DIRECT_IMPERSONATION				(0x0200)

#define PROCESS_TERMINATE						(0x0001)  
#define PROCESS_CREATE_THREAD					(0x0002)  
#define PROCESS_SET_SESSIONID					(0x0004)  
#define PROCESS_VM_OPERATION					(0x0008)  
#define PROCESS_VM_READ							(0x0010)  
#define PROCESS_VM_WRITE						(0x0020)  
#define PROCESS_DUP_HANDLE						(0x0040)  
#define PROCESS_CREATE_PROCESS					(0x0080)  
#define PROCESS_SET_QUOTA						(0x0100)  
#define PROCESS_SET_INFORMATION					(0x0200)  
#define PROCESS_QUERY_INFORMATION				(0x0400)  
#define PROCESS_SUSPEND_RESUME					(0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION		(0x1000)  

#define PROCESS_SET_PORT          (0x0800)


#define ASMJIT_EMBED 1
#define ASMJIT_BUILD_X86 1
#pragma warning(disable:4245)
#pragma warning(disable:4100)
#pragma warning(disable:4456)
#pragma warning(disable:4458 4189 4706 4702 4838)

#define GET_OFFSET_64(structure, member) ((int64_t)&((structure*)0)->member) // 64
#define GET_OFFSET_32(structure, member) ((int32_t)&((structure*)0)->member) // 32

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;
