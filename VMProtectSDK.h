#pragma once

#ifndef ENABLE_VMP_PROTECTION
    #if defined(MK_ENABLE_VMP_PROTECTION)
        #define ENABLE_VMP_PROTECTION MK_ENABLE_VMP_PROTECTION
    #else
        #define ENABLE_VMP_PROTECTION 1
    #endif
#endif

#if (ENABLE_VMP_PROTECTION) && !(defined(NO_AUTH) && NO_AUTH) && !(defined(ENABLE_NO_AUTH) && ENABLE_NO_AUTH)

#ifdef _WIN64
    #pragma comment(lib, "VMProtectDDK64.lib")
    #pragma comment(linker, "/INCLUDE:__imp_VMProtectBeginUltra")
    #pragma comment(linker, "/INCLUDE:__imp_VMProtectEnd")
#else
    #pragma comment(lib, "VMProtectSDK32.lib")
#endif

#ifdef __cplusplus
extern "C" {
#endif

// VMProtect 核心标记原语（仅在开启保护且非免认证模式下使能）
__declspec(dllimport) void __stdcall VMProtectBegin(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginVirtualization(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginMutation(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginUltra(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginVirtualizationLockByKey(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectBeginUltraLockByKey(const char *MarkerName);
__declspec(dllimport) void __stdcall VMProtectEnd(void);
void _ReadWriteBarrier(void);

#ifdef __cplusplus
}
#endif
#pragma intrinsic(_ReadWriteBarrier)

#if defined(__clang__) && defined(_WIN64)
// ReleaseLLVM 下免疫 -mllvm --string-obfus 对 MarkerName 的加密，强制生成紧邻的 lea rcx, [rip+disp32] + call [rip+disp32]
#define MK_VMP_CALL_MARKER(ApiFunc, MarkerName)                                                                        \
    __asm__ volatile(".pushsection .rdata,\"dr\"\n\t"                                                                  \
                     "1: .asciz \"" MarkerName "\"\n\t"                                                                \
                     ".popsection\n\t"                                                                                 \
                     "leaq 1b(%%rip), %%rcx\n\t"                                                                       \
                     "callq *__imp_" #ApiFunc "(%%rip)\n\t"                                                            \
                     :                                                                                                 \
                     :                                                                                                 \
                     : "rcx", "rax", "rdx", "r8", "r9", "r10", "r11", "memory")

#define VMProtectBegin(MarkerName)                        MK_VMP_CALL_MARKER(VMProtectBegin, MarkerName)
#define VMProtectBeginVirtualization(MarkerName)          MK_VMP_CALL_MARKER(VMProtectBeginVirtualization, MarkerName)
#define VMProtectBeginMutation(MarkerName)                MK_VMP_CALL_MARKER(VMProtectBeginMutation, MarkerName)
#define VMProtectBeginUltra(MarkerName)                   MK_VMP_CALL_MARKER(VMProtectBeginUltra, MarkerName)
#define VMProtectBeginVirtualizationLockByKey(MarkerName) MK_VMP_CALL_MARKER(VMProtectBeginVirtualizationLockByKey, MarkerName)
#define VMProtectBeginUltraLockByKey(MarkerName)          MK_VMP_CALL_MARKER(VMProtectBeginUltraLockByKey, MarkerName)
#define VMProtectEnd()                                                                                                 \
    __asm__ volatile("callq *__imp_VMProtectEnd(%%rip)\n\t"                                                            \
                     "nop\n\t"                                                                                         \
                     :                                                                                                 \
                     :                                                                                                 \
                     : "rcx", "rax", "rdx", "r8", "r9", "r10", "r11", "memory")
#else
#define VMProtectEnd()                                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        VMProtectEnd();                                                                                                \
        _ReadWriteBarrier();                                                                                           \
    } while (0)
#endif

#else

// 未开启 VMP 保护 (ENABLE_VMP_PROTECTION=0) 或调试免认证模式：宏完全置空，零链接开销与零外部符号
#define VMProtectBegin(MarkerName) ((void)0)
#define VMProtectBeginVirtualization(MarkerName) ((void)0)
#define VMProtectBeginMutation(MarkerName) ((void)0)
#define VMProtectBeginUltra(MarkerName) ((void)0)
#define VMProtectBeginVirtualizationLockByKey(MarkerName) ((void)0)
#define VMProtectBeginUltraLockByKey(MarkerName) ((void)0)
#define VMProtectEnd() ((void)0)

#endif
