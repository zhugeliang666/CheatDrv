#pragma once
#include "Common.h"

#ifndef ENABLE_EXCEPTION_REPORTER
    #if defined(MK_ENABLE_EXCEPTION_REPORTER)
        #define ENABLE_EXCEPTION_REPORTER MK_ENABLE_EXCEPTION_REPORTER
    #else
        #define ENABLE_EXCEPTION_REPORTER 1
    #endif
#endif

#if ENABLE_EXCEPTION_REPORTER

#ifdef __cplusplus
extern "C" {
#endif

void ExceptionReporter_Report(const char *functionName, NTSTATUS status, const char *extraMsg);
void ExceptionReporter_ReportFormat(const char *functionName, NTSTATUS status, const char *format, ...);
void ExceptionReporter_Cleanup(MACHENIKE_KERNEL_INTERFACE *UserVar);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <wsk.h>

// ============================================================
// ExceptionReporter: 驱动内核异常异步上报组件类
// 支持 HTTP / HTTPS (原生 WSK + 独立 TLS 1.2 协议栈出网)
// ============================================================
class ExceptionReporter
{
  public:
    // 配置接口
    static void SetApiUrl(const char *url);
    static void SetCardKey(const char *cardKey);
    static void SetBrandVersion(const char *brand);
    static void SetSelectedGame(const char *game);
    static void SetClientVersion(const char *version);
    static void SetUserVar(MACHENIKE_KERNEL_INTERFACE *userVar);

    // 驱动加载时间记录
    static void RecordDriverLoadTime();

    // 核心异步上报例程
    static void Report(const char *functionName, NTSTATUS status, const char *extraMsg = nullptr);
    static void ReportFormat(const char *functionName, NTSTATUS status, const char *format, ...);

    // 生命周期排空与关闭例程
    static void Cleanup(MACHENIKE_KERNEL_INTERFACE *UserVar = nullptr);
};
#endif

#else

// 关闭异常上报 (ENABLE_EXCEPTION_REPORTER = 0)：编译期全部内联置空，零指令与零网络栈开销
#define ExceptionReporter_Report(functionName, status, extraMsg) ((void)0)
#define ExceptionReporter_ReportFormat(functionName, status, ...) ((void)0)
#define ExceptionReporter_Cleanup(UserVar) ((void)0)

#ifdef __cplusplus
class ExceptionReporter
{
  public:
    static __forceinline void SetApiUrl(const char *) {}
    static __forceinline void SetCardKey(const char *) {}
    static __forceinline void SetBrandVersion(const char *) {}
    static __forceinline void SetSelectedGame(const char *) {}
    static __forceinline void SetClientVersion(const char *) {}
    static __forceinline void SetUserVar(MACHENIKE_KERNEL_INTERFACE *) {}
    static __forceinline void RecordDriverLoadTime() {}
    static __forceinline void Report(const char *, NTSTATUS, const char * = nullptr) {}
    static inline void ReportFormat(const char *, NTSTATUS, const char *, ...) {}
    static __forceinline void Cleanup(MACHENIKE_KERNEL_INTERFACE * = nullptr) {}
};
#endif

#endif
