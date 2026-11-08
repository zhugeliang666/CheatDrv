#pragma once
#include <string>
#include <cstdint>

// ============================================================
// 纯静态异常上报服务类 (对齐 CheatDrv 驱动排版与 keySaleSystem /api/tg 契约)
// ============================================================
class Reporter
{
public:
    // 异步非阻塞上报（对齐 CheatDrv 优美排版与结构化告警）
    static void Report(const char *functionName, uint32_t statusCode, const char *extraDetail);
    static void Report(const std::string &functionName, uint32_t statusCode, const std::string &extraDetail);
    static void Report(const std::string &functionName, const std::string &errorMessage);
    static void Report(const char *functionName, const char *errorMessage);

    // 格式化上报
    static void ReportFormat(const char *functionName, uint32_t statusCode, const char *format, ...);

    // 同步上报（用于进程退出前的关键异常）
    static void ReportSync(const char *functionName, uint32_t statusCode, const char *extraDetail, uint32_t timeoutMs = 3000);

    // 兼容历史调用接口
    static inline void ReportException(const std::string &functionName, const std::string &errorMessage)
    {
        Report(functionName, 0xC0000001, errorMessage);
    }
    static inline void ReportException(const char *functionName, const char *errorMessage)
    {
        Report(functionName, 0xC0000001, errorMessage ? errorMessage : "");
    }

    // 状态代码语义转换
    static const char *GetStatusSemantic(uint32_t status);

    // 错误原因中文翻译与状态码自动映射 (对齐驱动错误语义)
    static std::string FormatFailReason(const std::string &failReason, uint32_t &inOutStatusCode);

private:
    static bool PostToBackend(const std::string &plainText, const std::string &functionName, uint32_t statusCode, uint32_t timeoutMs);
    static bool SendWinHttpPost(const std::string &url, const std::string &postData, uint32_t timeoutMs);
    static bool ShouldReport(uint64_t fingerprint, uint32_t intervalMs = 60000);
    static uint64_t ComputeFingerprint(const char *cardKey, const char *functionName, uint32_t status);
};

#ifdef __cplusplus
extern "C" {
#endif

// C 兼容导出桥接
void HandleException(const char *functionName, const char *errorMessage);
void HandleExceptionWithStatus(const char *functionName, uint32_t statusCode, const char *errorMessage);

#ifdef __cplusplus
}
#endif
