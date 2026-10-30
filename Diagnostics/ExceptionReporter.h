#pragma once
#include "Common.h"

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

    // 核心异步上报例程
    static void Report(const char *functionName, NTSTATUS status, const char *extraMsg = nullptr);
    static void ReportFormat(const char *functionName, NTSTATUS status, const char *format, ...);

    // 生命周期排空与关闭例程
    static void Cleanup(MACHENIKE_KERNEL_INTERFACE *UserVar = nullptr);
};
#endif
