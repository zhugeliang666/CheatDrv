#pragma once

//#define ORIGINAL_DEBUG

#include  "fltKernel.h"
#include  "ia32.hpp"
#include "xorstr.h"
#include "kli.hpp"
#include "VMProtectDDK.h"
#include "..\common\vt_config.h"

#define MEM_TAG 'dsfs'

// 调试启动阶段划分枚举：
// 0=正常启动运行态；1=空入口；2=仅引导上下文+分配API+外部状态；
// 3=阶段2+扩展符号初始化；4=阶段3+厂商探针与映像元数据；
// 5=阶段4+完整 hv::create 与资源清理（不执行 VMRUN）；
// 6=AMD 单核启动/停止往返（所有核心确认停止后才释放）；
// 7=正式生产环境 hv::start/hv::stop 生命周期（无钩子或常驻载荷）；
// 8=阶段7+启动后驱动初始化；9=阶段8+加载器成功移交；
// 10=阶段9+常驻载荷生命周期批处理（映射/启动/Ping/状态/停止）。
// 诊断阶段在执行后续启动工作之前返回失败。

// PDB 符号服务器 URL：编译期由 XOR 加密，防止明文暴露于 `.rdata` 节区。
// C++ 代码中通过 yvt_default_pdb_url() 获取运行时解密字符串。
// 本地调试服务端启动参考: query_pdb_server.exe --port 9090 --path save

#if VT_LOG_ENABLED

#ifndef _DEBUG_FORMAT
#define _DEBUG_FORMAT
#define LOG_DEBUG(format, ...) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_INFO(format, ...)        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_WARN(format, ...)        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_ERROR(format, ...)       DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_DEBUG_SAFE(format, ...)  ((void)0)
#define LOG_INFO_SAFE(format, ...)   ((void)0)
#define LOG_WARN_SAFE(format, ...)   ((void)0)
#define LOG_ERROR_SAFE(format, ...)  ((void)0)
#define VT_RING_LOG(format, ...)     hv::vt_log(format, ##__VA_ARGS__)
#endif // !_DEBUG_FORMAT

#else
#define LOG_DEBUG(format, ...)       ((void)0)
#define LOG_INFO(format, ...)        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_WARN(format, ...)        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_ERROR(format, ...)       DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_DEBUG_SAFE(format, ...)  ((void)0)
#define LOG_INFO_SAFE(format, ...)   ((void)0)
#define LOG_WARN_SAFE(format, ...)   ((void)0)
#define LOG_ERROR_SAFE(format, ...)  ((void)0)
#define VT_RING_LOG(...)             ((void)0)
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
