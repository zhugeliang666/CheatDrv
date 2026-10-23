#pragma once

//#define ORIGINAL_DEBUG

#include  "fltKernel.h"
#include "ia32.hpp"
#include"xorstr.h"

# define MEM_TAG 'sdkd'

// 日志属于可观测性能力，不参与启动、迁移或卸载流程选择。
// 发布构建可以关闭日志，但关闭日志不得改变任何资源所有权和状态转换。
#ifndef MAPDRIVER_LOG_ENABLED
#define MAPDRIVER_LOG_ENABLED 1
#endif

// 以下宏是实际部署策略：分别控制文件、注册表、痕迹和映像清理。
// 它们只决定业务能力是否启用，不再承担分阶段测试或流程旁路职责。
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

// 自动交接策略：ResidentPayload 启动成功后，由 Bootstrap 主动完成所有权转移。
#ifndef MAPDRIVER_AUTO_HANDOFF_AFTER_PAYLOAD
#define MAPDRIVER_AUTO_HANDOFF_AFTER_PAYLOAD 0
#endif

#ifndef MAPDRIVER_AUTO_LOAD_MACHENIKE_ON_BOOT
#define MAPDRIVER_AUTO_LOAD_MACHENIKE_ON_BOOT 0
#endif

// 正式一键路径：启动旧映像和常驻载荷后，依次完成栈切换、桥接切换、
// AMD/Intel 运行态交接、旧映像释放以及控制设备收敛。
#ifndef MAPDRIVER_AUTO_ONEKEY_LOAD
#define MAPDRIVER_AUTO_ONEKEY_LOAD 1
#endif

// 保持正常加载返回语义；失败只由真实初始化或交接错误触发。
#ifndef MAPDRIVER_AUTO_ONEKEY_RETURN_FAILURE
#define MAPDRIVER_AUTO_ONEKEY_RETURN_FAILURE 0
#endif

// 控制设备生命周期属于部署策略，默认保留以支持状态查询和受控卸载。
#ifndef MAPDRIVER_AUTO_ONEKEY_KEEP_MAP_CTL
#define MAPDRIVER_AUTO_ONEKEY_KEEP_MAP_CTL 1
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_DROP_MAP_CTL
#define MAPDRIVER_AUTO_ONEKEY_DROP_MAP_CTL 0
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_WAIT_PMO_READY
#define MAPDRIVER_AUTO_ONEKEY_WAIT_PMO_READY 0
#endif

// 一键流程默认在扩展内核栈上同步执行；仅部署需要时才启用独立系统线程。
#ifndef MAPDRIVER_AUTO_ONEKEY_USE_THREAD
#define MAPDRIVER_AUTO_ONEKEY_USE_THREAD 0
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_EXPAND_STACK_SIZE
#define MAPDRIVER_AUTO_ONEKEY_EXPAND_STACK_SIZE 0x10000ull
#endif

// 固定延迟默认为零；真正的准入条件由载荷屏障和交接后的状态检查提供。
#ifndef MAPDRIVER_AUTO_ONEKEY_INITIAL_DELAY_MS
#define MAPDRIVER_AUTO_ONEKEY_INITIAL_DELAY_MS 0
#endif

// 若检测到残留 Hypervisor，必须先完成停止；残留状态不得伪装成新加载成功。
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

// 全池 HOST_CR3 映射可能覆盖大量内存，默认只映射代码池。
#ifndef MAPDRIVER_PAYLOAD_HOSTMAP_ALL_POOLS
#define MAPDRIVER_PAYLOAD_HOSTMAP_ALL_POOLS 0
#endif

// 交接确认完成后再隐藏常驻载荷映像、直接分配、Host 栈和私有 Arena。
#ifndef MAPDRIVER_AUTO_ONEKEY_HIDE_AFTER_HANDOFF
#define MAPDRIVER_AUTO_ONEKEY_HIDE_AFTER_HANDOFF 1
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_MIN_PMO_DRAWS
#define MAPDRIVER_AUTO_ONEKEY_MIN_PMO_DRAWS 8ull
#endif

#ifndef MAPDRIVER_AUTO_ONEKEY_MIN_BUSINESS_TICKS
#define MAPDRIVER_AUTO_ONEKEY_MIN_BUSINESS_TICKS 1ull
#endif

// 常驻载荷私有 Arena 在启动阶段一次性分配，交接后由载荷独占管理；
// 停止时必须先等待全部外部引用和 vCPU 引用归零，再释放整段内存。
#ifndef MAPDRIVER_PAYLOAD_ARENA_SIZE
#define MAPDRIVER_PAYLOAD_ARENA_SIZE 0x2000000ul
#endif

// 实机内存策略：Bootstrap、PoolManager 和载荷后备页统一使用独立页分配。
#ifndef MAPDRIVER_FORCE_EXALLOCPOOL
#define MAPDRIVER_FORCE_EXALLOCPOOL 0
#endif

// 仅在明确选择池分配策略时使用该池类型。
#ifndef MAPDRIVER_FORCE_EXALLOCPOOL_TYPE
#define MAPDRIVER_FORCE_EXALLOCPOOL_TYPE NonPagedPoolExecute
#endif

// 卸载时释放 Arena；调用点必须已经确认载荷引用归零且所有 vCPU 完成停止确认。
#ifndef MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD
#define MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD 1
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
#ifndef MAPDRIVER_LEGACY_HYPERVISOR_TAIL_VISIBLE_PAGES
#define MAPDRIVER_LEGACY_HYPERVISOR_TAIL_VISIBLE_PAGES 50
#endif

#if MAPDRIVER_LOG_ENABLED

#ifndef _DEBUG_FORMAT
#define _DEBUG_FORMAT
#define LOG_DEBUG(format, ...)       DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_INFO(format, ...)        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_WARN(format, ...)        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_ERROR(format, ...)       DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_DEBUG_SAFE(format, ...)  DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_INFO_SAFE(format, ...)   DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_WARN_SAFE(format, ...)   DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_ERROR_SAFE(format, ...)  DbgPrintEx(0, 0, format, __VA_ARGS__)
#endif // !_DEBUG_FORMAT

#else
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
