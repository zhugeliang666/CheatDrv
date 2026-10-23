#include "Common.h"
#include "DriverCore.h"
#include "DrvSecurity.h"
#include "ExceptionReporter.h"
#include "TransportManager.h"
#include "Utils.h"
#include <intrin.h>
#include <ntstrsafe.h>

// 标准 REPORT_SECRET_KEY ("135D03095D2743445D") 9 字节二进制
static const UCHAR s_ReportSecretKeyBin[9] = {0x13, 0x5D, 0x03, 0x09, 0x5D, 0x27, 0x43, 0x44, 0x5D};

static __forceinline BOOLEAN Security_CharToNibble(WCHAR c, UCHAR *n)
{
    if (c >= L'0' && c <= L'9')
    {
        *n = (UCHAR)(c - L'0');
        return TRUE;
    }
    if (c >= L'a' && c <= L'f')
    {
        *n = (UCHAR)(c - L'a' + 10);
        return TRUE;
    }
    if (c >= L'A' && c <= L'F')
    {
        *n = (UCHAR)(c - L'A' + 10);
        return TRUE;
    }
    return FALSE;
}

static __forceinline VOID Security_BytesToHex(const UCHAR *inBytes, ULONG inLen, CHAR *outHex)
{
    static const char hexChars[] = "0123456789ABCDEF";
    for (ULONG i = 0; i < inLen; i++)
    {
        outHex[i * 2] = hexChars[(inBytes[i] >> 4) & 0x0F];
        outHex[i * 2 + 1] = hexChars[inBytes[i] & 0x0F];
    }
    outHex[inLen * 2] = '\0';
}

// ============================================================
// 1. 验证 (Verification / Validation)
// ============================================================

NTSTATUS DrvSecurity::ParseTokenFromFileName(IN PUNICODE_STRING FileName, OUT ULONG *outToken)
{
    if (!FileName || FileName->Length < (9 * sizeof(WCHAR)) || !FileName->Buffer || FileName->Buffer[0] != L'\\')
        return STATUS_INVALID_PARAMETER;

    if (FileName->Length > (9 * sizeof(WCHAR)))
    {
        WCHAR sep = FileName->Buffer[9];
        if (sep != L'_' && sep != L'\\')
            return STATUS_INVALID_PARAMETER;
    }

    ULONG v = 0;
    for (int i = 0; i < 8; i++)
    {
        UCHAR nib = 0;
        if (!Security_CharToNibble(FileName->Buffer[1 + i], &nib))
            return STATUS_INVALID_PARAMETER;
        v = (v << 4) | nib;
    }
    if (outToken)
        *outToken = v;
    return STATUS_SUCCESS;
}

ULONG DrvSecurity::CalcToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONGLONG Counter, IN ULONG ProcessId)
{
    if (!UserVar)
        return 0;

    UCHAR msg[16] = {0};
    memcpy(&msg[0], &Counter, 8);
    memcpy(&msg[8], &ProcessId, 4);
    memcpy(&msg[12], &UserVar->Salt4, 4);

    UINT64 Hash = Utils::SipHash24(UserVar->SipHashKey, msg, sizeof(msg));
    return (ULONG)(Hash ^ (Hash >> 32));
}

BOOLEAN DrvSecurity::ValidateToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONGLONG Counter, IN ULONG ProcessId,
                                   IN ULONG CurrentToken, IN int window)
{
#if NO_AUTH || ENABLE_NO_AUTH
    UNREFERENCED_PARAMETER(UserVar);
    UNREFERENCED_PARAMETER(Counter);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CurrentToken);
    UNREFERENCED_PARAMETER(window);
    return TRUE;
#else
    if (!UserVar)
    {
        DBG("[-] DrvSecurity::ValidateToken failed: UserVar is NULL");
        return FALSE;
    }

    for (LONGLONG i = -window; i <= window; i++)
    {
        if (CalcToken(UserVar, (ULONGLONG)((LONGLONG)Counter + i), ProcessId) == CurrentToken)
        {
            return TRUE;
        }
    }

    DBG("[-] DrvSecurity::ValidateToken: Mismatch! PID=%u, ReceivedToken=0x%08X, CenterCounter=%llu, Window=%d",
        ProcessId, CurrentToken, Counter, window);
    for (LONGLONG i = -window; i <= window; i++)
    {
        ULONG expToken = CalcToken(UserVar, (ULONGLONG)((LONGLONG)Counter + i), ProcessId);
        DBG("    -> Candidate Token[offset %lld, counter %llu]: 0x%08X", i, (ULONGLONG)((LONGLONG)Counter + i),
            expToken);
        UNREFERENCED_PARAMETER(expToken);
    }
    return FALSE;
#endif
}

BOOLEAN DrvSecurity::ValidateToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONG ProcessId, IN ULONG CurrentToken,
                                   IN int window)
{
#if NO_AUTH || ENABLE_NO_AUTH
    UNREFERENCED_PARAMETER(UserVar);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CurrentToken);
    UNREFERENCED_PARAMETER(window);
    return TRUE;
#else
    if (!UserVar)
    {
        DBG("[-] DrvSecurity::ValidateToken failed: UserVar is NULL");
        return FALSE;
    }
    if (UserVar->Step == 0)
    {
        DBG("[-] DrvSecurity::ValidateToken failed: UserVar->Step is 0");
        return FALSE;
    }

    LARGE_INTEGER curTime;
    KeQuerySystemTime(&curTime);
    ULONGLONG sec = (ULONGLONG)curTime.QuadPart / 10000000ULL;
    ULONGLONG unixSec = (sec >= 11644473600ULL) ? (sec - 11644473600ULL) : 0;
    ULONGLONG counter = unixSec / UserVar->Step;

    return ValidateToken(UserVar, counter, ProcessId, CurrentToken, window);
#endif
}



ULONG DrvSecurity::EncryptReportData(const char *plainStr, CHAR *outHexBuf, ULONG maxHexLen)
{
    if (!plainStr || !outHexBuf || maxHexLen < 32)
        return 0;
    ULONG plainLen = (ULONG)strlen(plainStr);
    if (plainLen == 0 || plainLen > 1024)
        return 0;

    ULONG A = (ULONG)__rdtsc();
    ULONG B = (ULONG)(__rdtsc() ^ 0x5A5A5A5A);
    ULONG AndValue = ~(A ^ B);

    UCHAR outBin[1024 + 8];
    if (plainLen + 8 > sizeof(outBin))
        return 0;

    memcpy(&outBin[0], &A, 4);
    memcpy(&outBin[4], &B, 4);

    UCHAR KeyTime[4];
    memcpy(KeyTime, &B, 4);

    UCHAR TimeKey[4];
    for (int i = 0; i < 4; i++)
        TimeKey[i] = (UCHAR)(KeyTime[i] ^ (UCHAR)AndValue);

    UCHAR KeyCopy[9];
    memcpy(KeyCopy, s_ReportSecretKeyBin, 9);
    UCHAR finalKeyXor = 0;
    ULONG currentIdx = 0;

    for (ULONG i = 0; i < 9; i++)
    {
        if (currentIdx >= 4)
            currentIdx = 0;
        KeyCopy[i] ^= KeyTime[currentIdx];
        finalKeyXor ^= KeyCopy[i];
        currentIdx++;
    }

    UCHAR *pOut = &outBin[8];
    const UCHAR *pPlain = (const UCHAR *)plainStr;
    for (ULONG i = 0; i < plainLen; i++)
    {
        if (currentIdx >= 4)
            currentIdx = 0;
        pOut[i] = (UCHAR)(pPlain[i] ^ TimeKey[currentIdx] ^ finalKeyXor);
        currentIdx++;
    }

    ULONG totalCipherLen = 8 + plainLen;
    if (totalCipherLen * 2 + 1 > maxHexLen)
        return 0;
    Security_BytesToHex(outBin, totalCipherLen, outHexBuf);
    return totalCipherLen * 2;
}


// ============================================================
// 4. 深度防御与抗逆向四大机制落地实现
// ============================================================
// ------------------------------------------------------------
// 方案二：内存代码自完整性交叉校验 (In-Memory .text Hash Check)
// ------------------------------------------------------------
#define INTEGRITY_SAMPLE_SIZE 64
static volatile ULONG s_FuncHashBaseline[4] = {0};
static volatile BOOLEAN s_IntegrityInitialized = FALSE;

VOID DrvSecurity::InitTextIntegrity()
{
    if (s_IntegrityInitialized)
        return;

    BOOLEAN (*pfnValidate)(MACHENIKE_KERNEL_INTERFACE *, ULONG, ULONG, int) = &DrvSecurity::ValidateToken;
    const PVOID targetFuncs[4] = {(PVOID)pfnValidate, (PVOID)&DrvSecurity::ScanAndDecryptUserPayload,
                                  (PVOID)&DriverCore::DispatchCreate, (PVOID)&TransportManager::GetSessionCryptKey};

    for (int i = 0; i < 4; i++)
    {
        if (targetFuncs[i])
        {
            s_FuncHashBaseline[i] = Utils::CalcAdler32((const UCHAR *)targetFuncs[i], INTEGRITY_SAMPLE_SIZE);
        }
    }
    s_IntegrityInitialized = TRUE;
}

BOOLEAN DrvSecurity::VerifyTextIntegrity()
{
#if NO_AUTH || ENABLE_NO_AUTH
    return TRUE;
#else
    if (!s_IntegrityInitialized)
    {
        InitTextIntegrity();
        return TRUE;
    }

    BOOLEAN (*pfnValidate)(MACHENIKE_KERNEL_INTERFACE *, ULONG, ULONG, int) = &DrvSecurity::ValidateToken;
    const PVOID targetFuncs[4] = {(PVOID)pfnValidate, (PVOID)&DrvSecurity::ScanAndDecryptUserPayload,
                                  (PVOID)&DriverCore::DispatchCreate, (PVOID)&TransportManager::GetSessionCryptKey};

    for (int i = 0; i < 4; i++)
    {
        if (targetFuncs[i])
        {
            ULONG curHash = Utils::CalcAdler32((const UCHAR *)targetFuncs[i], INTEGRITY_SAMPLE_SIZE);
            if (curHash != s_FuncHashBaseline[i])
            {
                DBG("[-] DrvSecurity::VerifyTextIntegrity: Integrity check failed! func[%d] at %p hash=0x%08X "
                    "(baseline=0x%08X)",
                    i, targetFuncs[i], curHash, s_FuncHashBaseline[i]);
                // 检测到内存被 Patch (如 0xCC, 0x90, 0xEB, 0xE9)，彻底置空动态密钥，使传输链路静默瘫痪
                TransportManager::SetSessionCryptKey(0);
                return FALSE;
            }
        }
    }
    return TRUE;
#endif
}

// ------------------------------------------------------------
// 方案三：控制流数学不变量 (Invariants Verification)
// ------------------------------------------------------------
static volatile ULONG64 s_AuthInvariantA = 0;
static volatile ULONG64 s_AuthInvariantB = 0;
#define AUTH_INVARIANT_TARGET 0xC001CAFEF00D1122ULL
#define AUTH_INVARIANT_MULT 0x5DEECE66DULL
#define AUTH_INVARIANT_ADD 0x00000000BULL

VOID DrvSecurity::SetAuthStateInvariant(ULONG64 seed)
{
    if (seed == 0)
    {
        InterlockedExchange64((volatile LONG64 *)&s_AuthInvariantA, 0);
        InterlockedExchange64((volatile LONG64 *)&s_AuthInvariantB, 0);
        return;
    }
    ULONG64 a = seed ^ 0xA5A5A5A5A5A5A5A5ULL;
    ULONG64 b = ((a * AUTH_INVARIANT_MULT + AUTH_INVARIANT_ADD) ^ AUTH_INVARIANT_TARGET);
    InterlockedExchange64((volatile LONG64 *)&s_AuthInvariantA, (LONG64)a);
    InterlockedExchange64((volatile LONG64 *)&s_AuthInvariantB, (LONG64)b);
}

BOOLEAN DrvSecurity::VerifyAuthStateInvariant()
{
#if NO_AUTH || ENABLE_NO_AUTH
    return TRUE;
#else
    ULONG64 a = (ULONG64)InterlockedCompareExchange64((volatile LONG64 *)&s_AuthInvariantA, 0, 0);
    ULONG64 b = (ULONG64)InterlockedCompareExchange64((volatile LONG64 *)&s_AuthInvariantB, 0, 0);

    if (a == 0 && b == 0)
    {
        DBG("[-] DrvSecurity::VerifyAuthStateInvariant: Auth invariant not initialized (A=0, B=0)");
        return FALSE;
    }

    if (((a * AUTH_INVARIANT_MULT + AUTH_INVARIANT_ADD) ^ b) != AUTH_INVARIANT_TARGET)
    {
        DBG("[-] DrvSecurity::VerifyAuthStateInvariant: Math invariant violated! A=0x%016llX, B=0x%016llX", a, b);
        TransportManager::SetSessionCryptKey(0);
        return FALSE;
    }
    return TRUE;
#endif
}

// ------------------------------------------------------------
// 方案四：内核硬件断点自检 (DR0-DR7 Hardware Breakpoint Auditing)
// ------------------------------------------------------------
static volatile LONG64 s_LastHwbpFingerprint = 0;

BOOLEAN DrvSecurity::AuditHardwareBreakpoints()
{
#if NO_AUTH || ENABLE_NO_AUTH
    return TRUE;
#else
    // 读取全部断点控制寄存器 DR7
    ULONG64 dr7 = __readdr(7);

    // x86/x64 架构铁律：DR7 低 8 位为局部/全局断点使能位 (L0~L3, G0~G3)。
    // 若低 8 位全为 0 (如系统空闲默认值 DR7=0x400)，说明所有断点均处于停用/关闭状态。
    if ((dr7 & 0xFF) == 0)
    {
        // 断点全部解除时，原子复位指纹缓存，确保下次再次激活或切换断点时能即时重新上报
        if (s_LastHwbpFingerprint != 0)
        {
            InterlockedExchange64(&s_LastHwbpFingerprint, 0);
        }
        return TRUE;
    }

    // 断点处于激活状态：采集全部寄存器并计算 64 位状态组合指纹
    ULONG64 dr0 = __readdr(0);
    ULONG64 dr1 = __readdr(1);
    ULONG64 dr2 = __readdr(2);
    ULONG64 dr3 = __readdr(3);

    ULONG64 regs[5] = { dr0, dr1, dr2, dr3, dr7 };
    ULONG64 fp = 0xCBF29CE484222325ULL;
    for (int i = 0; i < 5; i++)
    {
        fp ^= regs[i];
        fp *= 0x100000001B3ULL;
    }
    if (fp == 0)
    {
        fp = 1; // 避免为 0 与未激活复位态冲突
    }

    LONG64 lastFp = s_LastHwbpFingerprint;
    // 仅在首次激活或寄存器配置发生实质变动时触发上报，状态未变时静默不刷屏
    if ((LONG64)fp != lastFp)
    {
        if (InterlockedCompareExchange64(&s_LastHwbpFingerprint, (LONG64)fp, lastFp) == lastFp)
        {
            DBG("[-] DrvSecurity::AuditHardwareBreakpoints: HWBP State Changed/Active! DR0=0x%llX DR1=0x%llX DR2=0x%llX DR3=0x%llX DR7=0x%llX (FP=0x%llX)",
                dr0, dr1, dr2, dr3, dr7, fp);
            ExceptionReporter::ReportFormat("AuditHardwareBreakpoints", STATUS_BREAKPOINT,
                                            "DR0=0x%llX DR1=0x%llX DR2=0x%llX DR3=0x%llX DR7=0x%llX",
                                            dr0, dr1, dr2, dr3, dr7);
        }
    }

    return FALSE;
#endif
}

// ------------------------------------------------------------
// 方案五：双向动态心跳保活与超时阻断 (Mutual Challenge-Response Handshake)
// ------------------------------------------------------------
static volatile LONGLONG s_LastHeartbeatTick = 0;
static volatile ULONG64 s_CurrentDriverChallenge = 0;
static volatile LONG s_HandshakeInitialized = 0;
// 保活超时窗口：60 秒 (60 * 10000000 100ns 间隔)
#define HEARTBEAT_TIMEOUT_TICKS (60ULL * 10000000ULL)

VOID DrvSecurity::RefreshHeartbeat()
{
    LARGE_INTEGER cur;
    KeQuerySystemTime(&cur);
    InterlockedExchange64(&s_LastHeartbeatTick, cur.QuadPart);
}

VOID DrvSecurity::ResetChallengeState()
{
    InterlockedExchange(&s_HandshakeInitialized, 0);
    InterlockedExchange64((volatile LONGLONG *)&s_CurrentDriverChallenge, 0);
    RefreshHeartbeat();
}

BOOLEAN DrvSecurity::VerifyHeartbeatAlive()
{
#if NO_AUTH || ENABLE_NO_AUTH
    return TRUE;
#else
    LONGLONG last = InterlockedCompareExchange64(&s_LastHeartbeatTick, 0, 0);
    if (last == 0)
    {
        return TRUE;
    }
    LARGE_INTEGER cur;
    KeQuerySystemTime(&cur);
    if ((cur.QuadPart - last) > (LONGLONG)HEARTBEAT_TIMEOUT_TICKS)
    {
        DBG("[-] DrvSecurity::VerifyHeartbeatAlive: Heartbeat timed out! Elapsed=%lld ticks (timeout=%llu)",
            (cur.QuadPart - last), HEARTBEAT_TIMEOUT_TICKS);
        TransportManager::SetSessionCryptKey(0);
        InterlockedExchange(&s_HandshakeInitialized, 0);
        return FALSE;
    }
    return TRUE;
#endif
}

ULONG64 DrvSecurity::ComputeChallengeResponse(ULONG64 qwChallenge, ULONG64 qwKey)
{
    // 基于 SipHash-2-4 轮函数的非线性映射单向哈希
    UINT64 k0 = qwKey;
    UINT64 k1 = qwKey ^ 0x736f6d6570736575ULL;
    UINT64 v0 = k0 ^ 0x736f6d6570736575ULL;
    UINT64 v1 = k1 ^ 0x646f72616e646f6dULL;
    UINT64 v2 = k0 ^ 0x6c65797367656e65ULL;
    UINT64 v3 = k1 ^ 0x7465646279746573ULL;

    UINT64 m = qwChallenge;
    v3 ^= m;
    SIPROUND;
    SIPROUND;
    v0 ^= m;

    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return (v0 ^ v1 ^ v2 ^ v3);
}

static __forceinline ULONG64 GetRandomChallengeSeed()
{
    ULONG64 qpc = (g_pGlobalUserVar && g_pGlobalUserVar->Func.KeQueryPerformanceCounter)
                      ? g_pGlobalUserVar->Func.KeQueryPerformanceCounter(NULL).QuadPart
                      : 0;
    return (qpc ^ __rdtsc()) | 1;
}

BOOLEAN DrvSecurity::VerifyAndRefreshChallenge(ULONG64 qwClientChallenge, ULONG64 qwClientResponse,
                                               ULONG64 *pqwDriverChallengeOut, ULONG64 *pqwDriverResponseOut)
{
#if NO_AUTH || ENABLE_NO_AUTH
    UNREFERENCED_PARAMETER(qwClientResponse);
    ULONG64 curKey = TransportManager::GetSessionCryptKey();
    ULONG64 newDriverChallenge = GetRandomChallengeSeed();
    InterlockedExchange64((volatile LONGLONG *)&s_CurrentDriverChallenge, (LONGLONG)newDriverChallenge);
    InterlockedExchange(&s_HandshakeInitialized, 1);

    if (pqwDriverChallengeOut)
        *pqwDriverChallengeOut = newDriverChallenge;
    if (pqwDriverResponseOut)
        *pqwDriverResponseOut =
            curKey ? ComputeChallengeResponse(qwClientChallenge, curKey) : (qwClientChallenge ^ 0xA5A5A5A5A5A5A5A5ULL);

    RefreshHeartbeat();
    return TRUE;
#else
    ULONG64 curKey = TransportManager::GetSessionCryptKey();
    if (curKey == 0)
    {
        DBG("[-] DrvSecurity::VerifyAndRefreshChallenge: SessionCryptKey is 0");
        return FALSE;
    }

    // 首次握手阶段：若尚未完成首轮挑战协商，或客户端初次连入请求初始挑战(qwClientResponse == 0)
    if (InterlockedCompareExchange(&s_HandshakeInitialized, 0, 0) == 0 || qwClientResponse == 0)
    {
        ULONG64 initDriverChallenge = GetRandomChallengeSeed();
        InterlockedExchange64((volatile LONGLONG *)&s_CurrentDriverChallenge, (LONGLONG)initDriverChallenge);
        InterlockedExchange(&s_HandshakeInitialized, 1);

        if (pqwDriverChallengeOut)
            *pqwDriverChallengeOut = initDriverChallenge;
        if (pqwDriverResponseOut)
            *pqwDriverResponseOut = ComputeChallengeResponse(qwClientChallenge, curKey);

        RefreshHeartbeat();
        return TRUE;
    }

    // 运行态动态验证：校验客户端针对上一轮驱动挑战值的应答
    ULONG64 expectedClientRsp = ComputeChallengeResponse(s_CurrentDriverChallenge, curKey);
    if (qwClientResponse != expectedClientRsp)
    {
        DBG("[-] DrvSecurity::VerifyAndRefreshChallenge: Challenge response mismatch! Got=0x%016llX, "
            "Expected=0x%016llX",
            qwClientResponse, expectedClientRsp);
        // 客户端应答错误（伪造协议、未授权调用或重放攻击）：立即清零密钥并废除心跳
        TransportManager::SetSessionCryptKey(0);
        InterlockedExchange64(&s_LastHeartbeatTick, 0);
        InterlockedExchange(&s_HandshakeInitialized, 0);
        return FALSE;
    }

    // 验证通过，生成新一轮驱动随机挑战并计算对客户端的应答
    ULONG64 newDriverChallenge = GetRandomChallengeSeed();
    InterlockedExchange64((volatile LONGLONG *)&s_CurrentDriverChallenge, (LONGLONG)newDriverChallenge);

    if (pqwDriverChallengeOut)
        *pqwDriverChallengeOut = newDriverChallenge;
    if (pqwDriverResponseOut)
        *pqwDriverResponseOut = ComputeChallengeResponse(qwClientChallenge, curKey);

    RefreshHeartbeat();
    return TRUE;
#endif
}
