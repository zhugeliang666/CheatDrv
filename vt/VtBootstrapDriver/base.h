#pragma once

//#define ORIGINAL_DEBUG

#include  "fltKernel.h"
#include "ia32.hpp"
#include"xorstr.h"
#include "common/vt_config.h"

# define MEM_TAG 'sdkd'

#if VT_LOG_ENABLED

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
