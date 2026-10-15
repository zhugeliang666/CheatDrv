#pragma once

#if !(NO_AUTH || ENABLE_NO_AUTH)

#ifdef _WIN64
    #pragma comment(lib, "VMProtectSDK64.lib")
#else
    #pragma comment(lib, "VMProtectSDK32.lib")
#endif

#ifdef __cplusplus
extern "C" {
#endif

// VMProtect 核心标记原语（仅在验证版本使能）
__declspec(dllimport) void __stdcall VMProtectBegin(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginVirtualization(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginMutation(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginUltra(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginVirtualizationLockByKey(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginUltraLockByKey(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectEnd(void);

#ifdef __cplusplus
}
#endif

#else

// 调试免认证模式 (NO_AUTH=1)：宏完全置空，零链接开销与零外部符号
#define VMProtectBegin(MarkerName) ((void)0)
#define VMProtectBeginVirtualization(MarkerName) ((void)0)
#define VMProtectBeginMutation(MarkerName) ((void)0)
#define VMProtectBeginUltra(MarkerName) ((void)0)
#define VMProtectBeginVirtualizationLockByKey(MarkerName) ((void)0)
#define VMProtectBeginUltraLockByKey(MarkerName) ((void)0)
#define VMProtectEnd() ((void)0)

#endif
