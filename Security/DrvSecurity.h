#pragma once
#include "Common.h"

// ============================================================
// DrvSecurity: 驱动核心安全组件类 (纯静态类：验证、加密、解密)
// ============================================================
class DrvSecurity
{
  public:
    // ========================================================
    // 1. 验证 (Verification / Validation)
    // ========================================================
    // 解析设备访问路径 / 文件名中携带的 8 字符十六进制动态 Token
    static NTSTATUS ParseTokenFromFileName(IN PUNICODE_STRING FileName, OUT ULONG *outToken);

    // 计算特定时间步与 PID 的动态令牌
    static ULONG CalcToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONGLONG Counter, IN ULONG ProcessId);

    // 校验客户端动态令牌 (指定 Counter)
    static BOOLEAN ValidateToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONGLONG Counter, IN ULONG ProcessId, IN ULONG CurrentToken,
                                 IN int window = 1);

    // 校验客户端动态令牌 (自动获取当前系统时间步，最简一行调用)
    static BOOLEAN ValidateToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONG ProcessId, IN ULONG CurrentToken, IN int window = 1);

    // 异常上报数据混淆加密 (双随机时间戳因子 + 9 字节秘钥异或链)
    static ULONG EncryptReportData(const char *plainStr, CHAR *outHexBuf, ULONG maxHexLen);

    // 从当前调用方进程内存扫描并解密用户态锚点载荷 (校验 Adler32 与 Magic 后特权阅后即焚清零)
    static NTSTATUS ScanAndDecryptUserPayload(IN ULONG devToken, OUT struct _DRV_BOOT_CONFIG_EX *outConfig);
    // ========================================================
    // 4. 深度防御与抗逆向 (Anti-Tamper & Deep Defense)
    // ========================================================
    // 方案二：内存代码自完整性交叉校验 (记录并比对关键函数代码段前64字节散列)
    static VOID InitTextIntegrity();
    static BOOLEAN VerifyTextIntegrity();

    // 方案三：控制流数学不变量 (授权状态代数闭环，消灭单字节布尔Patch点)
    static VOID SetAuthStateInvariant(ULONG64 seed);
    static BOOLEAN VerifyAuthStateInvariant();

    // 方案四：内核硬件断点自检 (DR0-DR7 审查)
    static BOOLEAN AuditHardwareBreakpoints();

    // 方案五：双向动态心跳保活、挑战应答与超时阻断 (Mutual Challenge-Response Handshake)
    static VOID RefreshHeartbeat();
    static VOID ResetChallengeState();
    static BOOLEAN VerifyHeartbeatAlive();
    static ULONG64 ComputeChallengeResponse(ULONG64 qwChallenge, ULONG64 qwKey);
    static BOOLEAN VerifyAndRefreshChallenge(ULONG64 qwClientChallenge, ULONG64 qwClientResponse, ULONG64 *pqwDriverChallengeOut,
                                             ULONG64 *pqwDriverResponseOut);
};
