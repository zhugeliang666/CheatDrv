#pragma once

//#define ORIGINAL_DEBUG

#include  "fltKernel.h"
#include  "ia32.hpp"
#include "xorstr.h"
#include "kli.hpp"
#include "VMProtectDDK.h"
#include "../../Core/DbgLog.h"

#define MEM_TAG 'dsfs'

// =====================================================================
// Master log switch — set to 0 for release-clean builds (no DbgPrintEx
// calls in the binary), 1 for development (full LOG_DEBUG / LOG_INFO).
//
// Effect when YVT_LOG_ENABLED == 0:
//   - LOG_* macros expand to ((void)0); compiler optimizes the call
//     site to nothing.
//   - format-string literals wrapped in _XOR_(...) at the call site
//     are dead-code-eliminated, so .rdata stays free of log strings.
//   - DbgPrintEx import remains in the IAT (used elsewhere via CallK
//     in vt/), but no plaintext log messages reach DbgView.
// =====================================================================
#ifndef YVT_LOG_ENABLED
#define YVT_LOG_ENABLED 0
#endif

// Temporary switch for mouse/HID VT probes. Keep this off while debugging
// non-mouse business data on builds whose mouhid/hidusb offsets are not
// verified. The handler code stays compiled so it can be re-enabled quickly.
#ifndef YVT_MOUSE_HOOK_ENABLED
#define YVT_MOUSE_HOOK_ENABLED 0
#endif

// Temporary switch: master default for KTHREAD affinity locking in VT call paths.
// Keep this off while debugging business data; it can still be enabled later via
// the existing hypercall if needed.
#ifndef YVT_AFFINITY_LOCK_ENABLED
#define YVT_AFFINITY_LOCK_ENABLED 1
#endif

// PDB symbol server URL — XOR-encrypted at compile time so it doesn't show
// up in `.rdata`. Use yvt_default_pdb_url() from C++ to fetch the runtime
// string. The kqpdb static initializer can't call this (kqpdb is in a
// .vm code_seg and uses C-string default), so kquery_pdb.h has its own
// _XOR_ wrapper too — keep them in sync.
//
// For local server: run query_pdb_server.exe --port 9090 --path save

#if YVT_LOG_ENABLED

#ifndef _DEBUG_FORMAT
#define _DEBUG_FORMAT
#define LOG_DEBUG(format, ...) \
	DbgPrintEx(0, 0, format, __VA_ARGS__)
#define LOG_INFO(format, ...)        ((void)0)
#define LOG_WARN(format, ...)        ((void)0)
#define LOG_ERROR(format, ...)       ((void)0)
#define LOG_DEBUG_SAFE(format, ...)  ((void)0)
#define LOG_INFO_SAFE(format, ...)   ((void)0)
#define LOG_WARN_SAFE(format, ...)   ((void)0)
#define LOG_ERROR_SAFE(format, ...)  ((void)0)
#endif // !_DEBUG_FORMAT

#else  // YVT_LOG_ENABLED == 0 — silent build
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


//#define VMP
#ifdef VMP
#define VMB \
VMProtectBeginVirtualization(__FUNCTION__);
#define VME \
VMProtectEnd();
#else
#define VMB 
#define VME 
#endif


static UINT64 key = 0x12341234;

inline UINT64 encrypt(UINT64 data) {
	return  data;// data^ key;
}

inline UINT64 decrypt(UINT64 data) {
	return data;// data^ key;
}
