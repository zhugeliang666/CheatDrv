#include "Common.h"
#include "DriverCore.h"
#include "DrvSecurity.h"
#include "TransportManager.h"
#include <intrin.h>
#include <ntstrsafe.h>

extern "C" NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(IN PEPROCESS Process);

// 标准 REPORT_SECRET_KEY ("135D03095D2743445D") 9 字节二进制
static const UCHAR s_ReportSecretKeyBin[9] = {0x13, 0x5D, 0x03, 0x09, 0x5D, 0x27, 0x43, 0x44, 0x5D};

static __forceinline UINT64 ROTL64(UINT64 x, int b) { return (x << b) | (x >> (64 - b)); }

#define SIPROUND                                                                                                                           \
    do                                                                                                                                     \
    {                                                                                                                                      \
        v0 += v1;                                                                                                                          \
        v1 = ROTL64(v1, 13);                                                                                                               \
        v1 ^= v0;                                                                                                                          \
        v0 = ROTL64(v0, 32);                                                                                                               \
        v2 += v3;                                                                                                                          \
        v3 = ROTL64(v3, 16);                                                                                                               \
        v3 ^= v2;                                                                                                                          \
        v0 += v3;                                                                                                                          \
        v3 = ROTL64(v3, 21);                                                                                                               \
        v3 ^= v0;                                                                                                                          \
        v2 += v1;                                                                                                                          \
        v1 = ROTL64(v1, 17);                                                                                                               \
        v1 ^= v2;                                                                                                                          \
        v2 = ROTL64(v2, 32);                                                                                                               \
    } while (0)

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

    UINT64 Hash = SipHash24(UserVar->SipHashKey, msg, sizeof(msg));
    return (ULONG)(Hash ^ (Hash >> 32));
}

BOOLEAN DrvSecurity::ValidateToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONGLONG Counter, IN ULONG ProcessId, IN ULONG CurrentToken,
                                   IN int window)
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

    DBG("[-] DrvSecurity::ValidateToken: Mismatch! PID=%u, ReceivedToken=0x%08X, CenterCounter=%llu, Window=%d", ProcessId,
        CurrentToken, Counter, window);
    for (LONGLONG i = -window; i <= window; i++)
    {
        ULONG expToken = CalcToken(UserVar, (ULONGLONG)((LONGLONG)Counter + i), ProcessId);
        DBG("    -> Candidate Token[offset %lld, counter %llu]: 0x%08X", i, (ULONGLONG)((LONGLONG)Counter + i), expToken);
    }
    return FALSE;
#endif
}

BOOLEAN DrvSecurity::ValidateToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONG ProcessId, IN ULONG CurrentToken, IN int window)
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

UINT64 DrvSecurity::SipHash24(const UCHAR key[16], const UCHAR *data, SIZE_T len)
{
    UINT64 k0 = *(const UINT64 *)(key + 0);
    UINT64 k1 = *(const UINT64 *)(key + 8);

    UINT64 v0 = k0 ^ 0x736f6d6570736575ULL;
    UINT64 v1 = k1 ^ 0x646f72616e646f6dULL;
    UINT64 v2 = k0 ^ 0x6c7967656e657261ULL;
    UINT64 v3 = k1 ^ 0x7465646279746573ULL;

    const UINT64 *blocks = (const UINT64 *)data;
    SIZE_T nblocks = len / 8;
    for (SIZE_T i = 0; i < nblocks; ++i)
    {
        UINT64 m = blocks[i];
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }

    const UCHAR *end = data + nblocks * 8;
    UINT64 b = ((UINT64)len) << 56;
    switch (len & 7)
    {
    case 7:
        b |= ((UINT64)end[6]) << 48;
    case 6:
        b |= ((UINT64)end[5]) << 40;
    case 5:
        b |= ((UINT64)end[4]) << 32;
    case 4:
        b |= ((UINT64)end[3]) << 24;
    case 3:
        b |= ((UINT64)end[2]) << 16;
    case 2:
        b |= ((UINT64)end[1]) << 8;
    case 1:
        b |= ((UINT64)end[0]) << 0;
    default:
        break;
    }
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

ULONG DrvSecurity::CalcAdler32(const UCHAR *data, SIZE_T len)
{
    ULONG a = 1, b = 0;
    for (SIZE_T i = 0; i < len; i++)
    {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

// ============================================================
// 2. 加密 (Encryption)
// ============================================================

void DrvSecurity::Rc4Encrypt(UCHAR *data, ULONG len, const UCHAR *key, ULONG keyLen)
{
    if (!data || len == 0 || !key || keyLen == 0)
        return;

    UCHAR S[256];
    for (ULONG i = 0; i < 256; i++)
        S[i] = (UCHAR)i;
    ULONG j = 0;
    for (ULONG i = 0; i < 256; i++)
    {
        j = (j + S[i] + key[i % keyLen]) & 0xFF;
        UCHAR tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    ULONG i = 0;
    j = 0;
    for (ULONG k = 0; k < len; k++)
    {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        UCHAR tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

ULONG DrvSecurity::EncryptReportData(const char *plainStr, CHAR *outHexBuf, ULONG maxHexLen)
{
    if (!plainStr || !outHexBuf || maxHexLen < 32)
        return 0;
    ULONG plainLen = (ULONG)strlen(plainStr);
    if (plainLen == 0 || plainLen > 512)
        return 0;

    CHAR plainHex[1024];
    Security_BytesToHex((const UCHAR *)plainStr, plainLen, plainHex);
    ULONG plainHexLen = plainLen * 2;

    ULONG A = (ULONG)__rdtsc();
    ULONG B = (ULONG)(__rdtsc() ^ 0x5A5A5A5A);
    ULONG AndValue = ~(A ^ B);

    UCHAR outBin[1024 + 8];
    if (plainHexLen + 8 > sizeof(outBin))
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
    for (ULONG i = 0; i < plainHexLen; i++)
    {
        if (currentIdx >= 4)
            currentIdx = 0;
        pOut[i] = (UCHAR)(plainHex[i] ^ TimeKey[currentIdx] ^ finalKeyXor);
        currentIdx++;
    }

    ULONG totalCipherLen = 8 + plainHexLen;
    if (totalCipherLen * 2 + 1 > maxHexLen)
        return 0;
    Security_BytesToHex(outBin, totalCipherLen, outHexBuf);
    return totalCipherLen * 2;
}

// ============================================================
// 3. 解密 (Decryption)
// ============================================================

void DrvSecurity::Rc4Decrypt(UCHAR *data, ULONG len, const UCHAR *key, ULONG keyLen)
{
    // RC4 具有完全对称性
    Rc4Encrypt(data, len, key, keyLen);
}

NTSTATUS DrvSecurity::ScanAndDecryptUserPayload(IN ULONG devToken, OUT PDRV_BOOT_CONFIG_EX outConfig)
{
    if (!outConfig)
    {
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: outConfig is NULL");
        return STATUS_INVALID_PARAMETER;
    }

    // 1. 动态 Tag0/Tag1: 完全由当前调用传入的 devToken 实时派生 (无静态常量特征)
    UINT64 expectedTag0 = SipHash24(g_SipHashKey, (const UCHAR *)&devToken, sizeof(devToken));
    UINT64 expectedTag1 = ~expectedTag0 ^ 0xA5A5A5A55A5A5A5AULL;

    PEPROCESS pProcess = PsGetCurrentProcess();
    if (!pProcess)
    {
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: PsGetCurrentProcess returned NULL");
        return STATUS_INVALID_PARAMETER;
    }

    PVOID baseAddress = PsGetProcessSectionBaseAddress(pProcess);
    if (!baseAddress)
    {
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: BaseAddress is NULL for PID=%u",
            HandleToULong(PsGetProcessId(pProcess)));
        return STATUS_NOT_FOUND;
    }

    NTSTATUS status = STATUS_NOT_FOUND;
    BOOLEAN bFoundTag = FALSE;

    __try
    {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)baseAddress;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Invalid DOS signature 0x%04X (expected 0x%04X)", pDos->e_magic,
                IMAGE_DOS_SIGNATURE);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((PUCHAR)baseAddress + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
        {
            DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Invalid NT signature 0x%08X (expected 0x%08X)", pNt->Signature,
                IMAGE_NT_SIGNATURE);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (USHORT i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++)
        {
            // 匹配读写数据节区 (.data 等)
            if ((pSec->Characteristics & IMAGE_SCN_MEM_READ) && (pSec->Characteristics & IMAGE_SCN_MEM_WRITE))
            {
                PUCHAR secVA = (PUCHAR)baseAddress + pSec->VirtualAddress;
                ULONG secSize = pSec->Misc.VirtualSize;

                if (secSize >= sizeof(DRV_USER_PAYLOAD_ANCHOR))
                {
                    ULONG maxOffset = secSize - sizeof(DRV_USER_PAYLOAD_ANCHOR);
                    for (ULONG offset = 0; offset <= maxOffset; offset += sizeof(ULONG_PTR))
                    {
                        PDRV_USER_PAYLOAD_ANCHOR pAnchor = (PDRV_USER_PAYLOAD_ANCHOR)(secVA + offset);
                        if (pAnchor->Tag0 == expectedTag0 && pAnchor->Tag1 == expectedTag1)
                        {
                            bFoundTag = TRUE;
                            if (pAnchor->CipherLen != sizeof(DRV_BOOT_CONFIG_EX))
                            {
                                DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Tag matched but CipherLen mismatch (%u != %u)",
                                    pAnchor->CipherLen, (ULONG)sizeof(DRV_BOOT_CONFIG_EX));
                                continue;
                            }

                            // 派生解密密钥: g_SipHashKey (16B) + devToken (4B) + Nonce (4B)
                            UCHAR key[24];
                            memcpy(&key[0], g_SipHashKey, 16);
                            memcpy(&key[16], &devToken, 4);
                            memcpy(&key[20], &pAnchor->Nonce, 4);

                            DRV_BOOT_CONFIG_EX plainCfg;
                            memcpy(&plainCfg, pAnchor->CipherData, sizeof(DRV_BOOT_CONFIG_EX));
                            Rc4Decrypt((UCHAR *)&plainCfg, sizeof(DRV_BOOT_CONFIG_EX), key, sizeof(key));

                            // 校验 Adler32 与 Magic
                            ULONG calcSum = CalcAdler32((const UCHAR *)&plainCfg, sizeof(plainCfg));
                            if (plainCfg.Base.Magic == DRV_BOOT_CONFIG_MAGIC && calcSum == pAnchor->Checksum)
                            {
                                memcpy(outConfig, &plainCfg, sizeof(DRV_BOOT_CONFIG_EX));

                                // 阅后即焚: 内核特权清零用户态内存中的锚点标记与密文，杜绝取证残留
                                RtlSecureZeroMemory(pAnchor, sizeof(DRV_USER_PAYLOAD_ANCHOR));
                                status = STATUS_SUCCESS;
                                break;
                            }
                            else
                            {
                                DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Payload validation failed! Magic=0x%08X (exp 0x%08X), Checksum=0x%08X (exp 0x%08X)",
                                    plainCfg.Base.Magic, DRV_BOOT_CONFIG_MAGIC, calcSum, pAnchor->Checksum);
                            }
                        }
                    }
                }
                if (status == STATUS_SUCCESS)
                    break;
            }
        }
        if (status != STATUS_SUCCESS && !bFoundTag)
        {
            DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Target anchor tags not found in user memory (Token=0x%08X, expectedTag0=0x%016llX)",
                devToken, expectedTag0);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: SEH exception 0x%08X while scanning user memory", status);
    }

    return status;
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
    const PVOID targetFuncs[4] = {(PVOID)pfnValidate, (PVOID)&DrvSecurity::ScanAndDecryptUserPayload, (PVOID)&DriverCore::DispatchCreate,
                                  (PVOID)&TransportManager::GetSessionCryptKey};

    for (int i = 0; i < 4; i++)
    {
        if (targetFuncs[i])
        {
            s_FuncHashBaseline[i] = CalcAdler32((const UCHAR *)targetFuncs[i], INTEGRITY_SAMPLE_SIZE);
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
    const PVOID targetFuncs[4] = {(PVOID)pfnValidate, (PVOID)&DrvSecurity::ScanAndDecryptUserPayload, (PVOID)&DriverCore::DispatchCreate,
                                  (PVOID)&TransportManager::GetSessionCryptKey};

    for (int i = 0; i < 4; i++)
    {
        if (targetFuncs[i])
        {
            ULONG curHash = CalcAdler32((const UCHAR *)targetFuncs[i], INTEGRITY_SAMPLE_SIZE);
            if (curHash != s_FuncHashBaseline[i])
            {
                DBG("[-] DrvSecurity::VerifyTextIntegrity: Integrity check failed! func[%d] at %p hash=0x%08X (baseline=0x%08X)",
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
BOOLEAN DrvSecurity::AuditHardwareBreakpoints()
{
#if NO_AUTH || ENABLE_NO_AUTH
    return TRUE;
#else
    // 读取 DR7 调试控制寄存器
    ULONG64 dr7 = __readdr(7);
    // DR7 低 8 位为局部/全局断点使能位 (L0..L3, G0..G3)
    if ((dr7 & 0xFF) != 0)
    {
        DBG("[-] DrvSecurity::AuditHardwareBreakpoints: Active hardware breakpoint in DR7 (0x%016llX)", dr7);
        TransportManager::SetSessionCryptKey(0);
        return FALSE;
    }

    // 检查断点地址寄存器 DR0~DR3
    ULONG64 dr0 = __readdr(0);
    ULONG64 dr1 = __readdr(1);
    ULONG64 dr2 = __readdr(2);
    ULONG64 dr3 = __readdr(3);
    if (dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0)
    {
        DBG("[-] DrvSecurity::AuditHardwareBreakpoints: Debug address registers non-zero! DR0=0x%llX DR1=0x%llX DR2=0x%llX DR3=0x%llX",
            dr0, dr1, dr2, dr3);
        TransportManager::SetSessionCryptKey(0);
        return FALSE;
    }

    return TRUE;
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

BOOLEAN DrvSecurity::VerifyAndRefreshChallenge(ULONG64 qwClientChallenge, ULONG64 qwClientResponse, ULONG64 *pqwDriverChallengeOut,
                                               ULONG64 *pqwDriverResponseOut)
{
#if NO_AUTH || ENABLE_NO_AUTH
    ULONG64 curKey = TransportManager::GetSessionCryptKey();
    ULONG64 newDriverChallenge = (KeQueryPerformanceCounter(NULL).QuadPart ^ __rdtsc()) | 1;
    InterlockedExchange64((volatile LONGLONG *)&s_CurrentDriverChallenge, (LONGLONG)newDriverChallenge);
    InterlockedExchange(&s_HandshakeInitialized, 1);

    if (pqwDriverChallengeOut)
        *pqwDriverChallengeOut = newDriverChallenge;
    if (pqwDriverResponseOut)
        *pqwDriverResponseOut = curKey ? ComputeChallengeResponse(qwClientChallenge, curKey) : (qwClientChallenge ^ 0xA5A5A5A5A5A5A5A5ULL);

    RefreshHeartbeat();
    return TRUE;
#else
    ULONG64 curKey = TransportManager::GetSessionCryptKey();
    if (curKey == 0)
    {
        DBG("[-] DrvSecurity::VerifyAndRefreshChallenge: SessionCryptKey is 0");
        return FALSE;
    }

    // 首次握手阶段：若尚未完成首轮挑战协商，记录初值
    if (InterlockedCompareExchange(&s_HandshakeInitialized, 0, 0) == 0)
    {
        ULONG64 initDriverChallenge = (KeQueryPerformanceCounter(NULL).QuadPart ^ __rdtsc()) | 1;
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
        DBG("[-] DrvSecurity::VerifyAndRefreshChallenge: Challenge response mismatch! Got=0x%016llX, Expected=0x%016llX",
            qwClientResponse, expectedClientRsp);
        // 客户端应答错误（伪造协议、未授权调用或重放攻击）：立即清零密钥并废除心跳
        TransportManager::SetSessionCryptKey(0);
        InterlockedExchange64(&s_LastHeartbeatTick, 0);
        InterlockedExchange(&s_HandshakeInitialized, 0);
        return FALSE;
    }

    // 验证通过，生成新一轮驱动随机挑战并计算对客户端的应答
    ULONG64 newDriverChallenge = (KeQueryPerformanceCounter(NULL).QuadPart ^ __rdtsc()) | 1;
    InterlockedExchange64((volatile LONGLONG *)&s_CurrentDriverChallenge, (LONGLONG)newDriverChallenge);

    if (pqwDriverChallengeOut)
        *pqwDriverChallengeOut = newDriverChallenge;
    if (pqwDriverResponseOut)
        *pqwDriverResponseOut = ComputeChallengeResponse(qwClientChallenge, curKey);

    RefreshHeartbeat();
    return TRUE;
#endif
}
