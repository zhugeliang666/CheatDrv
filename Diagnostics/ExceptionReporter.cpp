#include "DrvSecurity.h"
#include "ExceptionReporter.h"
#include <bcrypt.h>
#include <stdarg.h>
#include <stdio.h>

#define TLS_REPORT_POOL_TAG 'sLtM'

// BCrypt 动态函数重定向 (Zero IAT: 剥离 cng.sys / ksecdd.lib 静态依赖)
#define BCryptOpenAlgorithmProvider s_pUserVar->Cng.BCryptOpenAlgorithmProvider
#define BCryptCloseAlgorithmProvider s_pUserVar->Cng.BCryptCloseAlgorithmProvider
#define BCryptCreateHash s_pUserVar->Cng.BCryptCreateHash
#define BCryptDestroyHash s_pUserVar->Cng.BCryptDestroyHash
#define BCryptHashData s_pUserVar->Cng.BCryptHashData
#define BCryptFinishHash s_pUserVar->Cng.BCryptFinishHash
#define BCryptDuplicateHash s_pUserVar->Cng.BCryptDuplicateHash
#define BCryptGenRandom s_pUserVar->Cng.BCryptGenRandom
#define BCryptGenerateSymmetricKey s_pUserVar->Cng.BCryptGenerateSymmetricKey
#define BCryptDestroyKey s_pUserVar->Cng.BCryptDestroyKey
#define BCryptEncrypt s_pUserVar->Cng.BCryptEncrypt
#define BCryptImportKeyPair s_pUserVar->Cng.BCryptImportKeyPair
#define BCryptSetProperty s_pUserVar->Cng.BCryptSetProperty

#define _strnicmp SafeStrnicmp


template <size_t N>
static __forceinline void SafeStrncpyS(char (&dest)[N], const char *src, size_t = 0)
{
    SafeStrncpy(dest, N, src);
}
static __forceinline void SafeStrncpyS(char *dest, size_t destSize, const char *src, size_t = 0)
{
    SafeStrncpy(dest, destSize, src);
}
#define strncpy_s SafeStrncpyS

namespace
{
// ============================================================
// 静态配置与内部状态
// ============================================================
CHAR s_ApiUrl[128] = {0};
CHAR s_CardKey[64] = {0};
CHAR s_BrandVersion[64] = {0};
CHAR s_SelectedGame[64] = {0};
CHAR s_ClientVersion[64] = {0};
MACHENIKE_KERNEL_INTERFACE *s_pUserVar = nullptr;

static __forceinline int SafeVsnprintf(char *buf, size_t sz, const char *fmt, va_list args)
{
    if (!buf || sz == 0 || !fmt)
        return 0;
    buf[0] = '\0';
    if (!s_pUserVar || !s_pUserVar->Func.pfn_vsnprintf)
        return 0;
    int ret = s_pUserVar->Func.pfn_vsnprintf(buf, sz - 1, fmt, args);
    buf[sz - 1] = '\0';
    if (ret < 0 || (size_t)ret >= sz)
    {
        size_t len = 0;
        while (len < sz - 1 && buf[len] != '\0')
            len++;
        return (int)len;
    }
    return ret;
}

static __forceinline int SafeSnprintf(char *buf, size_t sz, const char *fmt, ...)
{
    if (!buf || sz == 0 || !fmt)
        return 0;
    va_list args;
    va_start(args, fmt);
    int ret = SafeVsnprintf(buf, sz, fmt, args);
    va_end(args);
    return ret;
}

#define _snprintf_s(buf, sz, tr, fmt, ...) SafeSnprintf(buf, sz, fmt, __VA_ARGS__)
#define _vsnprintf_s(buf, sz, tr, fmt, args) SafeVsnprintf(buf, sz, fmt, args)

// 内存池动态函数辅助 (Zero IAT: 剥离 ExAllocatePool2 / ExFreePoolWithTag 静态符号)
static __forceinline PVOID TlsAlloc(SIZE_T sz)
{
    if (!s_pUserVar)
        return NULL;
    if (s_pUserVar->Func.ExAllocatePool2)
        return s_pUserVar->Func.ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, TLS_REPORT_POOL_TAG);
    if (s_pUserVar->Func.ExAllocatePoolWithTag)
        return s_pUserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sz, TLS_REPORT_POOL_TAG);
    return NULL;
}

static __forceinline VOID TlsFree(PVOID p)
{
    if (p && s_pUserVar && s_pUserVar->Func.ExFreePoolWithTag)
    {
        s_pUserVar->Func.ExFreePoolWithTag(p, TLS_REPORT_POOL_TAG);
    }
}

const WSK_CLIENT_DISPATCH s_ReportWskClientDispatch = {MAKE_WSK_VERSION(1, 0), 0, NULL};

typedef struct _DRV_EXCEPTION_REPORT_ITEM
{
    WORK_QUEUE_ITEM WorkItem;
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    CHAR ApiUrl[128];
    CHAR FunctionName[64];
    NTSTATUS StatusCode;
    CHAR ExtraMsg[256];
    CHAR CardKey[64];
    CHAR BrandVersion[32];
    CHAR SelectedGame[32];
    CHAR ClientVersion[32];
} DRV_EXCEPTION_REPORT_ITEM, *PDRV_EXCEPTION_REPORT_ITEM;

// ============================================================
// 内部网络通信与加解密底层例程
// ============================================================
NTSTATUS SyncCompletion(PDEVICE_OBJECT Reserved, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    PKEVENT pEvent = (PKEVENT)Context;
    if (pEvent && s_pUserVar && s_pUserVar->Func.KeSetEvent)
        s_pUserVar->Func.KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

BOOLEAN ParseIpv4(const char *str, ULONG *pIpNetOrder)
{
    if (!str || !pIpNetOrder)
        return FALSE;
    ULONG parts[4] = {0};
    int cur = 0;
    const char *p = str;
    while (*p && cur < 4)
    {
        if (*p >= '0' && *p <= '9')
        {
            parts[cur] = parts[cur] * 10 + (*p - '0');
            if (parts[cur] > 255)
                return FALSE;
        }
        else if (*p == '.')
        {
            cur++;
            if (cur >= 4)
                return FALSE;
        }
        else
        {
            break;
        }
        p++;
    }
    if (cur != 3)
        return FALSE;
    UCHAR b[4] = {(UCHAR)parts[0], (UCHAR)parts[1], (UCHAR)parts[2], (UCHAR)parts[3]};
    *pIpNetOrder = *(ULONG *)b;
    return TRUE;
}

VOID ParseUrlComponents(const char *url, BOOLEAN *pIsHttps, char *outHost, size_t maxHostLen, USHORT *outPort,
                        char *outPath, size_t maxPathLen)
{
    outHost[0] = '\0';
    outPath[0] = '\0';
    *pIsHttps = FALSE;
    *outPort = 80;

    if (!url || url[0] == '\0')
        return;

    const char *p = url;
    while (*p == ' ' || *p == '\t')
        p++;

    if (_strnicmp(p, "https://", 8) == 0)
    {
        *pIsHttps = TRUE;
        *outPort = 443;
        p += 8;
    }
    else if (_strnicmp(p, "http://", 7) == 0)
    {
        *pIsHttps = FALSE;
        *outPort = 80;
        p += 7;
    }

    size_t hostIdx = 0;
    while (*p && *p != ':' && *p != '/' && *p != ' ' && hostIdx + 1 < maxHostLen)
    {
        outHost[hostIdx++] = *p++;
    }
    outHost[hostIdx] = '\0';

    if (*p == ':')
    {
        p++;
        int portVal = 0;
        while (*p >= '0' && *p <= '9')
        {
            portVal = portVal * 10 + (*p - '0');
            p++;
        }
        if (portVal > 0 && portVal <= 65535)
            *outPort = (USHORT)portVal;
    }

    if (*p == '/')
    {
        strncpy_s(outPath, maxPathLen, p, _TRUNCATE);
    }
    else
    {
        strncpy_s(outPath, maxPathLen, "/api/tg", _TRUNCATE);
    }

    if (*outPort == 443)
        *pIsHttps = TRUE;
}

NTSTATUS HmacSha256(const UCHAR *Key, ULONG KeyLen, const UCHAR *Data, ULONG DataLen, UCHAR *OutMac32)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status))
        return status;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)Key, KeyLen, 0);
    if (NT_SUCCESS(status))
    {
        status = BCryptHashData(hHash, (PUCHAR)Data, DataLen, 0);
        if (NT_SUCCESS(status))
            status = BCryptFinishHash(hHash, OutMac32, 32, 0);
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

NTSTATUS TlsPrfSha256(const UCHAR *Secret, ULONG SecretLen, const char *Label, const UCHAR *Seed, ULONG SeedLen,
                      UCHAR *OutBuffer, ULONG OutLen)
{
    ULONG labelLen = (ULONG)strlen(Label);
    ULONG fullSeedLen = labelLen + SeedLen;
    PUCHAR fullSeed = (PUCHAR)TlsAlloc(fullSeedLen);
    if (!fullSeed)
        return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(fullSeed, Label, labelLen);
    memcpy(fullSeed + labelLen, Seed, SeedLen);

    UCHAR A[32];
    HmacSha256(Secret, SecretLen, fullSeed, fullSeedLen, A);

    ULONG generated = 0;
    PUCHAR currentOut = OutBuffer;

    while (generated < OutLen)
    {
        ULONG stepInputLen = 32 + fullSeedLen;
        PUCHAR stepInput = (PUCHAR)TlsAlloc(stepInputLen);
        if (!stepInput)
        {
            TlsFree(fullSeed);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(stepInput, A, 32);
        memcpy(stepInput + 32, fullSeed, fullSeedLen);

        UCHAR block[32];
        HmacSha256(Secret, SecretLen, stepInput, stepInputLen, block);
        TlsFree(stepInput);

        ULONG copySize = (OutLen - generated > 32) ? 32 : (OutLen - generated);
        memcpy(currentOut, block, copySize);
        generated += copySize;
        currentOut += copySize;

        HmacSha256(Secret, SecretLen, A, 32, A);
    }

    TlsFree(fullSeed);
    return STATUS_SUCCESS;
}

BOOLEAN ExtractRsaPublicKeyFromDer(const UCHAR *CertDer, ULONG CertLen, PUCHAR *OutModulus, PULONG OutModulusLen,
                                   PUCHAR *OutExponent, PULONG OutExponentLen)
{
    static const UCHAR rsaOid[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
    if (!CertDer || CertLen < 64)
        return FALSE;

    const UCHAR *p = CertDer;
    const UCHAR *end = CertDer + CertLen - sizeof(rsaOid) - 32;
    const UCHAR *found = NULL;

    while (p < end)
    {
        if (memcmp(p, rsaOid, sizeof(rsaOid)) == 0)
        {
            found = p;
            break;
        }
        p++;
    }
    if (!found)
        return FALSE;

    p = found + sizeof(rsaOid);
    while (p < CertDer + CertLen - 16 && *p != 0x03)
        p++;
    if (p >= CertDer + CertLen - 16)
        return FALSE;
    p++; // 跳过 0x03

    if (*p & 0x80)
        p += 1 + (*p & 0x7F);
    else
        p++;
    p++; // 跳过 unused bits (0x00)

    if (*p != 0x30)
        return FALSE;
    p++;
    if (*p & 0x80)
        p += 1 + (*p & 0x7F);
    else
        p++;

    // Modulus (0x02)
    if (*p != 0x02)
        return FALSE;
    p++;
    ULONG modLen = 0;
    if (*p & 0x80)
    {
        ULONG lenBytes = *p & 0x7F;
        p++;
        for (ULONG i = 0; i < lenBytes; ++i)
            modLen = (modLen << 8) | *p++;
    }
    else
    {
        modLen = *p++;
    }

    if (*p == 0x00 && modLen > 1)
    {
        p++;
        modLen--;
    }
    *OutModulus = (PUCHAR)p;
    *OutModulusLen = modLen;
    p += modLen;

    // Exponent (0x02)
    if (*p != 0x02)
        return FALSE;
    p++;
    *OutExponentLen = *p++;
    *OutExponent = (PUCHAR)p;

    return TRUE;
}

NTSTATUS WskSyncSend(MACHENIKE_KERNEL_INTERFACE *UserVar, PWSK_SOCKET hSocket, PIRP Irp, PKEVENT pEvent,
                     const void *buf, ULONG len)
{
    if (!UserVar || !hSocket || !Irp || !pEvent || !buf || len == 0)
        return STATUS_INVALID_PARAMETER;
    PMDL pMdl = UserVar->Func.IoAllocateMdl((PVOID)buf, len, FALSE, FALSE, NULL);
    if (!pMdl)
        return STATUS_INSUFFICIENT_RESOURCES;
    UserVar->Func.MmBuildMdlForNonPagedPool(pMdl);

    WSK_BUF wskBuf = {pMdl, 0, len};
    UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(Irp, SyncCompletion, pEvent, TRUE, TRUE, TRUE);

    NTSTATUS status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskSend(hSocket, &wskBuf, 0, Irp);
    if (status == STATUS_PENDING)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000LL * 3000; // 3s
        NTSTATUS waitSt = UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, &timeout);
        if (waitSt == STATUS_TIMEOUT)
        {
            UserVar->Func.IoCancelIrp(Irp);
            UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
            status = STATUS_TIMEOUT;
        }
        else
        {
            status = Irp->IoStatus.Status;
        }
    }
    UserVar->Func.IoFreeMdl(pMdl);
    return status;
}

NTSTATUS WskSyncReceive(MACHENIKE_KERNEL_INTERFACE *UserVar, PWSK_SOCKET hSocket, PIRP Irp, PKEVENT pEvent, void *buf,
                        ULONG len, ULONG timeoutMs, PULONG pBytesReceived)
{
    if (!UserVar || !hSocket || !Irp || !pEvent || !buf || len == 0)
        return STATUS_INVALID_PARAMETER;
    PMDL pMdl = UserVar->Func.IoAllocateMdl(buf, len, FALSE, FALSE, NULL);
    if (!pMdl)
        return STATUS_INSUFFICIENT_RESOURCES;
    UserVar->Func.MmBuildMdlForNonPagedPool(pMdl);

    WSK_BUF wskBuf = {pMdl, 0, len};
    UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(Irp, SyncCompletion, pEvent, TRUE, TRUE, TRUE);

    NTSTATUS status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskReceive(hSocket, &wskBuf, 0, Irp);
    if (status == STATUS_PENDING)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000LL * timeoutMs;
        NTSTATUS waitSt = UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, &timeout);
        if (waitSt == STATUS_TIMEOUT)
        {
            UserVar->Func.IoCancelIrp(Irp);
            UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
            status = STATUS_TIMEOUT;
        }
        else
        {
            status = Irp->IoStatus.Status;
        }
    }
    if (NT_SUCCESS(status) && pBytesReceived)
        *pBytesReceived = (ULONG)Irp->IoStatus.Information;
    UserVar->Func.IoFreeMdl(pMdl);
    return status;
}

NTSTATUS PerformTlsHandshakeAndSendHttp(MACHENIKE_KERNEL_INTERFACE *UserVar, PWSK_SOCKET hSocket, PIRP Irp,
                                        PKEVENT pEvent, const char *szHost, const char *httpReq, ULONG reqLen)
{
    if (!UserVar || !hSocket || !Irp || !pEvent || !httpReq || reqLen == 0)
        return STATUS_INVALID_PARAMETER;

    UCHAR clientRandom[32] = {0};
    UCHAR serverRandom[32] = {0};
    UCHAR preMasterSecret[48] = {0};
    UCHAR masterSecret[48] = {0};

    BCRYPT_ALG_HANDLE hRng = NULL;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0)))
    {
        BCryptGenRandom(hRng, clientRandom, 32, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    }
    else
    {
        ULONG64 t = __rdtsc();
        memcpy(clientRandom, &t, 8);
    }

    BCRYPT_ALG_HANDLE hSha256Alg = NULL;
    BCRYPT_HASH_HANDLE hHandshakeHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hSha256Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;
    status = BCryptCreateHash(hSha256Alg, &hHandshakeHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    // 1. 构建 ClientHello
    UCHAR helloBuf[512] = {0};
    helloBuf[0] = 0x16;
    helloBuf[1] = 0x03;
    helloBuf[2] = 0x01;
    ULONG hIdx = 5;
    ULONG hsStart = hIdx;
    helloBuf[hIdx++] = 0x01; // ClientHello
    hIdx += 3;
    helloBuf[hIdx++] = 0x03;
    helloBuf[hIdx++] = 0x03;
    memcpy(&helloBuf[hIdx], clientRandom, 32);
    hIdx += 32;
    helloBuf[hIdx++] = 0x00;

    // Cipher Suites
    helloBuf[hIdx++] = 0x00;
    helloBuf[hIdx++] = 0x06;
    helloBuf[hIdx++] = 0x00;
    helloBuf[hIdx++] = 0x2F;
    helloBuf[hIdx++] = 0x00;
    helloBuf[hIdx++] = 0x35;
    helloBuf[hIdx++] = 0x00;
    helloBuf[hIdx++] = 0x3C;
    helloBuf[hIdx++] = 0x01;
    helloBuf[hIdx++] = 0x00;

    // Extensions (SNI)
    ULONG extLenPos = hIdx;
    hIdx += 2;
    ULONG extStart = hIdx;
    if (szHost && szHost[0] != '\0')
    {
        USHORT hostLen = (USHORT)strlen(szHost);
        USHORT sniExtLen = hostLen + 5;
        USHORT sniListLen = hostLen + 3;
        helloBuf[hIdx++] = 0x00;
        helloBuf[hIdx++] = 0x00;
        helloBuf[hIdx++] = (UCHAR)(sniExtLen >> 8);
        helloBuf[hIdx++] = (UCHAR)(sniExtLen & 0xFF);
        helloBuf[hIdx++] = (UCHAR)(sniListLen >> 8);
        helloBuf[hIdx++] = (UCHAR)(sniListLen & 0xFF);
        helloBuf[hIdx++] = 0x00;
        helloBuf[hIdx++] = (UCHAR)(hostLen >> 8);
        helloBuf[hIdx++] = (UCHAR)(hostLen & 0xFF);
        memcpy(&helloBuf[hIdx], szHost, hostLen);
        hIdx += hostLen;
    }
    // Signature algorithms
    helloBuf[hIdx++] = 0x00;
    helloBuf[hIdx++] = 0x0D;
    helloBuf[hIdx++] = 0x00;
    helloBuf[hIdx++] = 0x06;
    helloBuf[hIdx++] = 0x00;
    helloBuf[hIdx++] = 0x04;
    helloBuf[hIdx++] = 0x04;
    helloBuf[hIdx++] = 0x01;
    helloBuf[hIdx++] = 0x02;
    helloBuf[hIdx++] = 0x01;

    USHORT totalExtLen = (USHORT)(hIdx - extStart);
    helloBuf[extLenPos] = (UCHAR)(totalExtLen >> 8);
    helloBuf[extLenPos + 1] = (UCHAR)(totalExtLen & 0xFF);

    ULONG hsMsgLen = hIdx - (hsStart + 4);
    helloBuf[hsStart + 1] = (UCHAR)((hsMsgLen >> 16) & 0xFF);
    helloBuf[hsStart + 2] = (UCHAR)((hsMsgLen >> 8) & 0xFF);
    helloBuf[hsStart + 3] = (UCHAR)(hsMsgLen & 0xFF);

    BCryptHashData(hHandshakeHash, &helloBuf[hsStart], hsMsgLen + 4, 0);

    USHORT recLen = (USHORT)(hIdx - 5);
    helloBuf[3] = (UCHAR)(recLen >> 8);
    helloBuf[4] = (UCHAR)(recLen & 0xFF);

    status = WskSyncSend(UserVar, hSocket, Irp, pEvent, helloBuf, hIdx);
    if (!NT_SUCCESS(status))
    {
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    // 2. 接收 ServerHello, Certificate, ServerHelloDone
    PUCHAR recvBuf = (PUCHAR)TlsAlloc(16384);
    if (!recvBuf)
    {
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG totalRecv = 0;
    BOOLEAN gotDone = FALSE;
    PUCHAR pModulus = NULL;
    ULONG modLen = 0;
    PUCHAR pExponent = NULL;
    ULONG expLen = 0;
    ULONG processedCursor = 0;

    for (int retry = 0; retry < 5 && !gotDone && totalRecv < 16384; retry++)
    {
        ULONG received = 0;
        status = WskSyncReceive(UserVar, hSocket, Irp, pEvent, recvBuf + totalRecv, 16384 - totalRecv, 3000, &received);
        if (!NT_SUCCESS(status) || received == 0)
            break;
        totalRecv += received;

        while (processedCursor + 5 <= totalRecv)
        {
            UCHAR recType = recvBuf[processedCursor];
            USHORT rLen = (recvBuf[processedCursor + 3] << 8) | recvBuf[processedCursor + 4];
            if (processedCursor + 5 + rLen > totalRecv)
                break;

            if (recType == 0x16)
            {
                ULONG hCursor = processedCursor + 5;
                ULONG hEnd = processedCursor + 5 + rLen;
                while (hCursor + 4 <= hEnd)
                {
                    UCHAR hsType = recvBuf[hCursor];
                    ULONG hLen = (recvBuf[hCursor + 1] << 16) | (recvBuf[hCursor + 2] << 8) | recvBuf[hCursor + 3];
                    if (hCursor + 4 + hLen > hEnd)
                        break;

                    BCryptHashData(hHandshakeHash, &recvBuf[hCursor], hLen + 4, 0);

                    if (hsType == 0x02 && hCursor + 6 + 32 <= hEnd)
                    {
                        memcpy(serverRandom, &recvBuf[hCursor + 6], 32);
                    }
                    else if (hsType == 0x0B)
                    {
                        ExtractRsaPublicKeyFromDer(&recvBuf[hCursor + 4], hLen, &pModulus, &modLen, &pExponent,
                                                   &expLen);
                    }
                    else if (hsType == 0x0E)
                    {
                        gotDone = TRUE;
                    }
                    hCursor += 4 + hLen;
                }
            }
            processedCursor += 5 + rLen;
        }
    }

    if (!gotDone || !pModulus || modLen == 0 || !pExponent || expLen == 0)
    {
        TlsFree(recvBuf);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return STATUS_UNSUCCESSFUL;
    }

    // 3. 构造 RSA 公钥 Blob 并加密 PreMasterSecret
    BCRYPT_ALG_HANDLE hRsaAlg = NULL;
    BCRYPT_KEY_HANDLE hRsaKey = NULL;
    BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);

    ULONG blobSize = sizeof(BCRYPT_RSAKEY_BLOB) + expLen + modLen;
    PUCHAR keyBlob = (PUCHAR)TlsAlloc(blobSize);
    if (!keyBlob)
    {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        TlsFree(recvBuf);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BCRYPT_RSAKEY_BLOB *pBlob = (BCRYPT_RSAKEY_BLOB *)keyBlob;
    pBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    pBlob->BitLength = modLen * 8;
    pBlob->cbPublicExp = expLen;
    pBlob->cbModulus = modLen;
    pBlob->cbPrime1 = 0;
    pBlob->cbPrime2 = 0;
    memcpy(keyBlob + sizeof(BCRYPT_RSAKEY_BLOB), pExponent, expLen);
    memcpy(keyBlob + sizeof(BCRYPT_RSAKEY_BLOB) + expLen, pModulus, modLen);

    status = BCryptImportKeyPair(hRsaAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hRsaKey, keyBlob, blobSize, 0);
    TlsFree(keyBlob);

    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        TlsFree(recvBuf);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    preMasterSecret[0] = 0x03;
    preMasterSecret[1] = 0x03;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0)))
    {
        BCryptGenRandom(hRng, preMasterSecret + 2, 46, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    }
    else
    {
        ULONG64 t = __rdtsc();
        memcpy(preMasterSecret + 2, &t, 8);
    }

    UCHAR encPreMaster[512] = {0};
    ULONG encLen = 0;
    status = BCryptEncrypt(hRsaKey, preMasterSecret, 48, NULL, NULL, 0, encPreMaster, sizeof(encPreMaster), &encLen,
                           BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(hRsaKey);
    BCryptCloseAlgorithmProvider(hRsaAlg, 0);

    if (!NT_SUCCESS(status))
    {
        TlsFree(recvBuf);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    // 4. 派生 MasterSecret 与 KeyBlock
    UCHAR seed[64] = {0};
    memcpy(seed, clientRandom, 32);
    memcpy(seed + 32, serverRandom, 32);
    TlsPrfSha256(preMasterSecret, 48, "master secret", seed, 64, masterSecret, 48);

    UCHAR keyBlockSeed[64] = {0};
    memcpy(keyBlockSeed, serverRandom, 32);
    memcpy(keyBlockSeed + 32, clientRandom, 32);
    UCHAR keyBlock[128] = {0};
    TlsPrfSha256(masterSecret, 48, "key expansion", keyBlockSeed, 64, keyBlock, 128);

    UCHAR clientMacKey[20] = {0};
    UCHAR clientWriteKey[16] = {0};
    memcpy(clientMacKey, keyBlock, 20);
    memcpy(clientWriteKey, keyBlock + 40, 16);

    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hClientAesKey = NULL;
    BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAesAlg, &hClientAesKey, NULL, 0, clientWriteKey, 16, 0);

    // 5. ClientKeyExchange + ChangeCipherSpec + Finished
    UCHAR flightBuf[1024] = {0};
    ULONG fIdx = 0;
    flightBuf[fIdx++] = 0x16;
    flightBuf[fIdx++] = 0x03;
    flightBuf[fIdx++] = 0x03;
    USHORT ckeRecordLen = (USHORT)(4 + 2 + encLen);
    flightBuf[fIdx++] = (UCHAR)(ckeRecordLen >> 8);
    flightBuf[fIdx++] = (UCHAR)(ckeRecordLen & 0xFF);

    ULONG ckeHsStart = fIdx;
    flightBuf[fIdx++] = 0x10;
    ULONG ckeDataLen = 2 + encLen;
    flightBuf[fIdx++] = 0x00;
    flightBuf[fIdx++] = (UCHAR)(ckeDataLen >> 8);
    flightBuf[fIdx++] = (UCHAR)(ckeDataLen & 0xFF);
    flightBuf[fIdx++] = (UCHAR)(encLen >> 8);
    flightBuf[fIdx++] = (UCHAR)(encLen & 0xFF);
    memcpy(&flightBuf[fIdx], encPreMaster, encLen);
    fIdx += encLen;

    BCryptHashData(hHandshakeHash, &flightBuf[ckeHsStart], ckeRecordLen, 0);

    flightBuf[fIdx++] = 0x14;
    flightBuf[fIdx++] = 0x03;
    flightBuf[fIdx++] = 0x03;
    flightBuf[fIdx++] = 0x00;
    flightBuf[fIdx++] = 0x01;
    flightBuf[fIdx++] = 0x01;

    // Finished
    BCRYPT_HASH_HANDLE hHashDup = NULL;
    UCHAR handshakeHashVal[32] = {0};
    UCHAR verifyData[12] = {0};
    BCryptDuplicateHash(hHandshakeHash, &hHashDup, NULL, 0, 0);
    BCryptFinishHash(hHashDup, handshakeHashVal, 32, 0);
    BCryptDestroyHash(hHashDup);

    TlsPrfSha256(masterSecret, 48, "client finished", handshakeHashVal, 32, verifyData, 12);

    UCHAR finishedPlain[16] = {0x14, 0x00, 0x00, 0x0C};
    memcpy(&finishedPlain[4], verifyData, 12);

    UCHAR macInput[13 + 16] = {0};
    macInput[8] = 0x16;
    macInput[9] = 0x03;
    macInput[10] = 0x03;
    macInput[11] = 0x00;
    macInput[12] = 0x10;
    memcpy(&macInput[13], finishedPlain, 16);

    BCRYPT_ALG_HANDLE hMacAlg = NULL;
    BCRYPT_HASH_HANDLE hMac = NULL;
    UCHAR mac[20] = {0};
    BCryptOpenAlgorithmProvider(&hMacAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptCreateHash(hMacAlg, &hMac, NULL, 0, clientMacKey, 20, 0);
    BCryptHashData(hMac, macInput, sizeof(macInput), 0);
    BCryptFinishHash(hMac, mac, 20, 0);
    BCryptDestroyHash(hMac);
    BCryptCloseAlgorithmProvider(hMacAlg, 0);

    UCHAR toEncrypt[48] = {0};
    memcpy(toEncrypt, finishedPlain, 16);
    memcpy(toEncrypt + 16, mac, 20);
    for (int i = 36; i < 48; ++i)
        toEncrypt[i] = 11;

    UCHAR explicitIV[16] = {0};
    for (int i = 0; i < 16; ++i)
        explicitIV[i] = (UCHAR)(__rdtsc() ^ i);

    UCHAR encryptedFinished[48] = {0};
    ULONG encFinLen = 0;
    UCHAR ivCopy[16] = {0};
    memcpy(ivCopy, explicitIV, 16);
    BCryptEncrypt(hClientAesKey, toEncrypt, 48, NULL, ivCopy, 16, encryptedFinished, 48, &encFinLen, 0);

    flightBuf[fIdx++] = 0x16;
    flightBuf[fIdx++] = 0x03;
    flightBuf[fIdx++] = 0x03;
    USHORT finRecLen = (USHORT)(16 + 48);
    flightBuf[fIdx++] = (UCHAR)(finRecLen >> 8);
    flightBuf[fIdx++] = (UCHAR)(finRecLen & 0xFF);
    memcpy(&flightBuf[fIdx], explicitIV, 16);
    fIdx += 16;
    memcpy(&flightBuf[fIdx], encryptedFinished, 48);
    fIdx += 48;

    status = WskSyncSend(UserVar, hSocket, Irp, pEvent, flightBuf, fIdx);
    TlsFree(recvBuf);
    BCryptDestroyHash(hHandshakeHash);
    BCryptCloseAlgorithmProvider(hSha256Alg, 0);

    if (!NT_SUCCESS(status))
    {
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return status;
    }

    // 6. 发送加密的 HTTP POST Application Data
    ULONG unpaddedLen = reqLen + 20;
    ULONG padLen = 16 - (unpaddedLen % 16);
    ULONG totalPlainLen = unpaddedLen + padLen;
    PUCHAR appPlain = (PUCHAR)TlsAlloc(totalPlainLen);
    if (!appPlain)
    {
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(appPlain, httpReq, reqLen);

    UCHAR appMacHeader[13] = {0};
    UINT64 seqNumBE = RtlUlonglongByteSwap(1ULL);
    memcpy(&appMacHeader[0], &seqNumBE, 8);
    appMacHeader[8] = 0x17;
    appMacHeader[9] = 0x03;
    appMacHeader[10] = 0x03;
    appMacHeader[11] = (UCHAR)(reqLen >> 8);
    appMacHeader[12] = (UCHAR)(reqLen & 0xFF);

    BCryptOpenAlgorithmProvider(&hMacAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptCreateHash(hMacAlg, &hMac, NULL, 0, clientMacKey, 20, 0);
    BCryptHashData(hMac, appMacHeader, 13, 0);
    BCryptHashData(hMac, (PUCHAR)httpReq, reqLen, 0);
    BCryptFinishHash(hMac, appPlain + reqLen, 20, 0);
    BCryptDestroyHash(hMac);
    BCryptCloseAlgorithmProvider(hMacAlg, 0);

    for (ULONG i = 0; i < padLen; ++i)
        appPlain[reqLen + 20 + i] = (UCHAR)(padLen - 1);

    UCHAR appExplicitIV[16] = {0};
    for (int i = 0; i < 16; ++i)
        appExplicitIV[i] = (UCHAR)(__rdtsc() ^ (i * 7));

    ULONG totalCipherLen = 16 + totalPlainLen;
    PUCHAR recordBuf = (PUCHAR)TlsAlloc(5 + totalCipherLen);
    if (!recordBuf)
    {
        TlsFree(appPlain);
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    recordBuf[0] = 0x17;
    recordBuf[1] = 0x03;
    recordBuf[2] = 0x03;
    recordBuf[3] = (UCHAR)(totalCipherLen >> 8);
    recordBuf[4] = (UCHAR)(totalCipherLen & 0xFF);
    memcpy(recordBuf + 5, appExplicitIV, 16);

    UCHAR appIvCopy[16] = {0};
    memcpy(appIvCopy, appExplicitIV, 16);
    ULONG appEncLen = 0;
    BCryptEncrypt(hClientAesKey, appPlain, totalPlainLen, NULL, appIvCopy, 16, recordBuf + 5 + 16, totalPlainLen,
                  &appEncLen, 0);
    TlsFree(appPlain);

    status = WskSyncSend(UserVar, hSocket, Irp, pEvent, recordBuf, 5 + totalCipherLen);
    TlsFree(recordBuf);

    BCryptDestroyKey(hClientAesKey);
    BCryptCloseAlgorithmProvider(hAesAlg, 0);

    return status;
}

static const char *ExceptionReporter_GetStatusSemantic(NTSTATUS status, const char *functionName)
{
    if ((ULONG)status == 0xC0000424 && functionName && strstr(functionName, "HardwareVtState") != NULL)
        return "STATUS_SECURITY_CHECKS_FAILED (虚拟化启动)";

    switch ((ULONG)status)
    {
    case 0x00000000: return "STATUS_SUCCESS (成功)";
    case 0x00000102: return "STATUS_TIMEOUT (等待或心跳超时)";
    case 0xC0000004: return "STATUS_INFO_LENGTH_MISMATCH (数据包长度不匹配)";
    case 0xC0000225: return "STATUS_NOT_FOUND (未找到目标设备/穿透失败)";
    case 0xC000000D: return "STATUS_INVALID_PARAMETER (参数无效/句柄错误)";
    case 0xC000000E: return "STATUS_NO_SUCH_DEVICE (USB/硬件设备已断开或移除)";
    case 0xC0000023: return "STATUS_BUFFER_TOO_SMALL (缓冲区过小)";
    case 0xC0000043: return "STATUS_SHARING_VIOLATION (设备独占冲突)";
    case 0xC0000056: return "STATUS_DELETE_PENDING (设备对象正在销毁)";
    case 0xC000006A: return "STATUS_WRONG_PASSWORD (挑战应答或密钥校验失败)";
    case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND (对象路径不存在)";
    case 0x80000003: return "STATUS_BREAKPOINT (触发调试/硬件断点)";
    case 0xC0000424:
    case 0xC0000428: return "STATUS_SECURITY_CHECKS_FAILED (安全完整性校验失败/检测到Hook)";
    case 0xC000007A: return "STATUS_PROCEDURE_NOT_FOUND (未找到目标导出函数)";
    case 0xC000007B: return "STATUS_INVALID_IMAGE_FORMAT (报文魔数或格式校验失败)";
    case 0xC0000005: return "STATUS_ACCESS_VIOLATION (内存访问违例)";
    case 0xC000009A: return "STATUS_INSUFFICIENT_RESOURCES (内存或系统资源耗尽)";
    case 0xC00000BA: return "STATUS_FILE_IS_A_DIRECTORY (文件类型不匹配)";
    case 0xC00000BB: return "STATUS_NOT_SUPPORTED (不支持的操作)";
    case 0xC0000001: return "STATUS_UNSUCCESSFUL (未指定系统错误)";
    case 0xC0000008: return "STATUS_INVALID_HANDLE (无效句柄)";
    case 0xC0000022: return "STATUS_ACCESS_DENIED (访问被拒绝)";
    case 0xC000009D: return "STATUS_DEVICE_NOT_READY (设备未就绪/未连接)";
    case 0xC0000184: return "STATUS_INVALID_DEVICE_STATE (设备或会话状态无效)";
    case 0xC0000186: return "STATUS_PORT_DISCONNECTED (端口未连接/断开)";
    case 0xC00002B6: return "STATUS_DEVICE_REMOVED (硬件设备已移除)";
    case 0xC00000B5: return "STATUS_IO_TIMEOUT (通信超时)";
    default: return "未分类状态码";
    }
}

VOID PerformHttp(PDRV_EXCEPTION_REPORT_ITEM pItem)
{
    if (!pItem || !pItem->UserVar)
        return;
    MACHENIKE_KERNEL_INTERFACE *UserVar = pItem->UserVar;
    if (!UserVar->Func.WskRegister || !UserVar->Func.WskCaptureProviderNPI)
        return;

    BOOLEAN bIsHttps = FALSE;
    CHAR szHost[64] = {0};
    USHORT targetPort = 80;
    CHAR szPath[128] = {0};
    ParseUrlComponents(pItem->ApiUrl, &bIsHttps, szHost, sizeof(szHost), &targetPort, szPath, sizeof(szPath));
    if (szHost[0] == '\0')
        return;

    const char *szCardKey = pItem->CardKey[0] ? pItem->CardKey : (s_CardKey[0] ? s_CardKey : "N/A");
    const char *szBrand = pItem->BrandVersion[0] ? pItem->BrandVersion : (s_BrandVersion[0] ? s_BrandVersion : "CheatDrv");
    const char *szGame = pItem->SelectedGame[0] ? pItem->SelectedGame : (s_SelectedGame[0] ? s_SelectedGame : "Default");
    const char *szVer = pItem->ClientVersion[0] ? pItem->ClientVersion : (s_ClientVersion[0] ? s_ClientVersion : "1.0");

    PCHAR httpBufMemory = (PCHAR)TlsAlloc(6144);
    if (!httpBufMemory)
        return;

    CHAR *plainData = httpBufMemory;
    CHAR *encHex = httpBufMemory + 768;
    CHAR *httpBody = httpBufMemory + 768 + 1600;
    CHAR *httpReq = httpBufMemory + 768 + 1600 + 1700;

    BOOLEAN isSecurityAlert = (pItem->StatusCode == STATUS_BREAKPOINT) ||
                              (pItem->StatusCode == (NTSTATUS)0xC0000424L) ||
                              (pItem->StatusCode == (NTSTATUS)0xC0000428L) ||
                              (pItem->FunctionName[0] != '\0' &&
                               (strstr(pItem->FunctionName, "Audit") != NULL ||
                                strstr(pItem->FunctionName, "Security") != NULL ||
                                strstr(pItem->FunctionName, "Monitor") != NULL));

    const char *title = isSecurityAlert ? "\xF0\x9F\x9B\xA1\xEF\xB8\x8F 【安全防御拦截告警】"
                                        : "\xF0\x9F\x9A\xA8 【驱动内核异常告警】";
    const char *statusDesc = ExceptionReporter_GetStatusSemantic(pItem->StatusCode, pItem->FunctionName);
    const char *extraDetail = pItem->ExtraMsg[0] ? pItem->ExtraMsg : "无详细错误描述";

    int plainLen =
        _snprintf_s(plainData, 768, _TRUNCATE,
                    "%s\r\n"
                    "------------------------------------\r\n"
                    "\xF0\x9F\x8E\xAE 目标游戏：%s (v%s)\r\n"
                    "\xF0\x9F\x8F\xB7\xEF\xB8\x8F 客户端版本：%s\r\n"
                    "\xF0\x9F\x94\x91 用户卡密：%s\r\n"
                    "\xF0\x9F\x93\x8D 触发例程：%s\r\n"
                    "\xF0\x9F\x9B\x91 状态代码：0x%08X (%s)\r\n"
                    "------------------------------------\r\n"
                    "\xF0\x9F\x93\x8B 诊断详情：\r\n"
                    "%s",
                    title,
                    szGame, szVer,
                    szBrand,
                    szCardKey,
                    pItem->FunctionName,
                    (ULONG)pItem->StatusCode, statusDesc,
                    extraDetail);
    if (plainLen <= 0)
    {
        TlsFree(httpBufMemory);
        return;
    }

    ULONG encHexLen = DrvSecurity::EncryptReportData(plainData, encHex, 1600);

    int bodyLen = 0;
    if (encHexLen > 0)
    {
        bodyLen = _snprintf_s(httpBody, 1700, _TRUNCATE,
                              "h=%s&functionName=%s&status=0x%08X&CardKey=%s&brand=%s&game=%s&version=%s",
                              encHex, pItem->FunctionName, (ULONG)pItem->StatusCode,
                              szCardKey, szBrand, szGame, szVer);
    }
    else
    {
        bodyLen = _snprintf_s(httpBody, 1700, _TRUNCATE,
                              "functionName=%s&status=0x%08X&message=%s&CardKey=%s&brand=%s&game=%s&version=%s",
                              pItem->FunctionName, (ULONG)pItem->StatusCode, pItem->ExtraMsg,
                              szCardKey, szBrand, szGame, szVer);
    }
    if (bodyLen <= 0)
    {
        TlsFree(httpBufMemory);
        return;
    }

    int reqLen = _snprintf_s(httpReq, 2048, _TRUNCATE,
                             "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s/%s\r\nContent-Type: "
                             "application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                             szPath[0] ? szPath : "/api/tg", szHost, szBrand, szVer, bodyLen, httpBody);
    if (reqLen <= 0)
    {
        TlsFree(httpBufMemory);
        return;
    }

    WSK_REGISTRATION WskRegistration;
    WSK_PROVIDER_NPI WskProviderNpi;
    WSK_CLIENT_NPI ClientNpi = {NULL, &s_ReportWskClientDispatch};

    NTSTATUS status = UserVar->Func.WskRegister(&ClientNpi, &WskRegistration);
    if (!NT_SUCCESS(status))
    {
        DBG("[-] ExceptionReporter: WskRegister failed (0x%08X)", status);
        TlsFree(httpBufMemory);
        return;
    }

    status = UserVar->Func.WskCaptureProviderNPI(&WskRegistration, 1000, &WskProviderNpi);
    if (!NT_SUCCESS(status))
    {
        DBG("[-] ExceptionReporter: WskCaptureProviderNPI failed (0x%08X)", status);
        UserVar->Func.WskDeregister(&WskRegistration);
        TlsFree(httpBufMemory);
        return;
    }

    KEVENT SyncEvent;
    UserVar->Func.KeInitializeEvent(&SyncEvent, SynchronizationEvent, FALSE);
    PIRP Irp = UserVar->Func.IoAllocateIrp(4, FALSE);
    if (!Irp)
    {
        DBG("[-] ExceptionReporter: IoAllocateIrp failed");
        UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
        UserVar->Func.WskDeregister(&WskRegistration);
        TlsFree(httpBufMemory);
        return;
    }

    // 1. DNS 动态解析
    ULONG targetIp = 0;
    if (!ParseIpv4(szHost, &targetIp))
    {
        WCHAR wHost[128] = {0};
        for (int i = 0; szHost[i] && i < 127; i++)
            wHost[i] = (WCHAR)szHost[i];
        UNICODE_STRING uNode;
        SafeInitUnicodeString(&uNode, wHost);

        ADDRINFOEXW hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        PADDRINFOEXW pResult = NULL;
        UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)
                     ->WskGetAddressInfo(WskProviderNpi.Client, &uNode, NULL, NS_ALL, NULL, &hints, &pResult, NULL,
                                         NULL, Irp);
        if (status == STATUS_PENDING)
        {
            LARGE_INTEGER dnsTimeout;
            dnsTimeout.QuadPart = -10000LL * 3000;
            NTSTATUS waitSt =
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &dnsTimeout);
            if (waitSt == STATUS_TIMEOUT)
            {
                UserVar->Func.IoCancelIrp(Irp);
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = STATUS_TIMEOUT;
            }
            else
            {
                status = Irp->IoStatus.Status;
            }
        }
        if (pResult)
        {
            if (NT_SUCCESS(status) && pResult->ai_addr)
            {
                PSOCKADDR_IN pSin = (PSOCKADDR_IN)pResult->ai_addr;
                targetIp = pSin->sin_addr.s_addr;
            }
            ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskFreeAddressInfo(WskProviderNpi.Client, pResult);
        }
    }

    if (targetIp == 0)
    {
        DBG("[-] ExceptionReporter: Failed to resolve host IP for '%s'", szHost);
        UserVar->Func.IoFreeIrp(Irp);
        UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
        UserVar->Func.WskDeregister(&WskRegistration);
        TlsFree(httpBufMemory);
        return;
    }

    DBG("[*] ExceptionReporter: Sending %s report to %s (%u.%u.%u.%u:%u%s)...",
        bIsHttps ? "HTTPS" : "HTTP", szHost,
        (targetIp & 0xFF), ((targetIp >> 8) & 0xFF), ((targetIp >> 16) & 0xFF), ((targetIp >> 24) & 0xFF),
        bIsHttps ? targetPort : (bIsHttps ? 80 : targetPort), szPath[0] ? szPath : "/api/tg");

    BOOLEAN bReportDelivered = FALSE;

    // 2. 通道一：HTTPS 走 TLS 1.2
    if (bIsHttps)
    {
        UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        PWSK_SOCKET hSocket = NULL;
        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)
                     ->WskSocket(WskProviderNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET,
                                 NULL, NULL, NULL, NULL, NULL, Irp);
        if (status == STATUS_PENDING)
        {
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
            status = Irp->IoStatus.Status;
        }
        if (NT_SUCCESS(status))
            hSocket = (PWSK_SOCKET)Irp->IoStatus.Information;

        if (hSocket)
        {
            SOCKADDR_IN localAddr = {0};
            localAddr.sin_family = AF_INET;
            UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            status =
                ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskBind(hSocket, (PSOCKADDR)&localAddr, 0, Irp);
            if (status == STATUS_PENDING)
            {
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = Irp->IoStatus.Status;
            }

            if (NT_SUCCESS(status))
            {
                SOCKADDR_IN remoteAddr = {0};
                remoteAddr.sin_family = AF_INET;
                remoteAddr.sin_addr.s_addr = targetIp;
                remoteAddr.sin_port = RtlUshortByteSwap(targetPort);

                UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
                IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
                status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)
                             ->WskConnect(hSocket, (PSOCKADDR)&remoteAddr, 0, Irp);
                if (status == STATUS_PENDING)
                {
                    LARGE_INTEGER timeout;
                    timeout.QuadPart = -10000LL * 3000;
                    NTSTATUS waitStatus =
                        UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &timeout);
                    if (waitStatus == STATUS_TIMEOUT)
                    {
                        UserVar->Func.IoCancelIrp(Irp);
                        UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                        status = STATUS_TIMEOUT;
                    }
                    else
                    {
                        status = Irp->IoStatus.Status;
                    }
                }

                if (NT_SUCCESS(status))
                {
                    NTSTATUS tlsStatus =
                        PerformTlsHandshakeAndSendHttp(UserVar, hSocket, Irp, &SyncEvent, szHost, httpReq, reqLen);
                    if (NT_SUCCESS(tlsStatus))
                    {
                        bReportDelivered = TRUE;
                        DBG("[+] ExceptionReporter: HTTPS report delivered successfully to %s", szHost);
                    }
                    else
                    {
                        DBG("[-] ExceptionReporter: HTTPS delivery failed (0x%08X), attempting plain HTTP fallback...", tlsStatus);
                    }
                }
                else
                {
                    DBG("[-] ExceptionReporter: HTTPS TCP connect failed (0x%08X)", status);
                }
            }

            UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)hSocket->Dispatch)->WskCloseSocket(hSocket, Irp);
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
        }
    }

    if (!bReportDelivered)
    {
        // 保持用户指定的原始目标端口 (如 4000)，仅当未指定端口且使用默认 443 时才回退为 80
        USHORT plainPort = (bIsHttps && targetPort == 443) ? 80 : targetPort;

        UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        PWSK_SOCKET hSocket = NULL;
        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)
                     ->WskSocket(WskProviderNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET,
                                 NULL, NULL, NULL, NULL, NULL, Irp);
        if (status == STATUS_PENDING)
        {
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
            status = Irp->IoStatus.Status;
        }
        if (NT_SUCCESS(status))
            hSocket = (PWSK_SOCKET)Irp->IoStatus.Information;

        if (hSocket)
        {
            SOCKADDR_IN localAddr = {0};
            localAddr.sin_family = AF_INET;
            UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            status =
                ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskBind(hSocket, (PSOCKADDR)&localAddr, 0, Irp);
            if (status == STATUS_PENDING)
            {
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = Irp->IoStatus.Status;
            }

            if (NT_SUCCESS(status))
            {
                SOCKADDR_IN remoteAddr = {0};
                remoteAddr.sin_family = AF_INET;
                remoteAddr.sin_addr.s_addr = targetIp;
                remoteAddr.sin_port = RtlUshortByteSwap(plainPort);

                UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
                IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
                status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)
                             ->WskConnect(hSocket, (PSOCKADDR)&remoteAddr, 0, Irp);
                if (status == STATUS_PENDING)
                {
                    LARGE_INTEGER timeout;
                    timeout.QuadPart = -10000LL * 3000;
                    NTSTATUS waitStatus =
                        UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &timeout);
                    if (waitStatus == STATUS_TIMEOUT)
                    {
                        UserVar->Func.IoCancelIrp(Irp);
                        UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                        status = STATUS_TIMEOUT;
                    }
                    else
                    {
                        status = Irp->IoStatus.Status;
                    }
                }

                if (NT_SUCCESS(status))
                {
                    status = WskSyncSend(UserVar, hSocket, Irp, &SyncEvent, httpReq, reqLen);
                    if (NT_SUCCESS(status))
                    {
                        bReportDelivered = TRUE;
                        DBG("[+] ExceptionReporter: HTTP report delivered successfully to %s:%u", szHost, plainPort);
                    }
                    else
                    {
                        DBG("[-] ExceptionReporter: HTTP WskSyncSend failed (0x%08X)", status);
                    }
                }
                else
                {
                    DBG("[-] ExceptionReporter: HTTP TCP connect failed (0x%08X)", status);
                }
            }

            UserVar->Func.IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)hSocket->Dispatch)->WskCloseSocket(hSocket, Irp);
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
        }
    }

    UserVar->Func.IoFreeIrp(Irp);
    UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
    UserVar->Func.WskDeregister(&WskRegistration);
    TlsFree(httpBufMemory);
}

static volatile LONG s_ReporterClosing = 0;
static volatile LONG s_ActiveReportsCount = 0;

VOID AsyncWorkRoutine(IN PVOID Parameter)
{
    PDRV_EXCEPTION_REPORT_ITEM pItem = (PDRV_EXCEPTION_REPORT_ITEM)Parameter;
    if (!pItem)
    {
        InterlockedDecrement(&s_ActiveReportsCount);
        return;
    }

    if (InterlockedCompareExchange(&s_ReporterClosing, 0, 0) == 0)
    {
        DBG("[*] ExceptionReporter: Async worker executing report for '%s' (status=0x%08X)...",
            pItem->FunctionName, (ULONG)pItem->StatusCode);

        __try
        {
            PerformHttp(pItem);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] AsyncWorkRoutine: Exception 0x%08X in report worker", GetExceptionCode());
        }
    }
    else
    {
        DBG("[*] ExceptionReporter: Async worker suppressed report for '%s' due to closing state",
            pItem->FunctionName);
    }

    if (pItem->UserVar && pItem->UserVar->Func.ExFreePoolWithTag)
    {
        pItem->UserVar->Func.ExFreePoolWithTag(pItem, MK_POOL_TAG);
    }
    InterlockedDecrement(&s_ActiveReportsCount);
}
} // namespace

#define REPORT_DEDUP_SLOTS 32
#define REPORT_COOLDOWN_SECONDS 60          // 相同指纹 60 秒滑动冷却
#define REPORT_BURST_WINDOW_SECONDS 10      // 10 秒突发窗口
#define REPORT_BURST_MAX_PER_WINDOW 8       // 10 秒窗口内最多允许 8 条不同指纹的独立告警，兼顾同轮多路告警与防刷屏
#define REPORT_EARLY_STAGE_SLOTS 8          // ApiUrl 就绪前的冷启动早期暂存槽位数

struct REPORT_DEDUP_ENTRY
{
    ULONG64 Hash;
    LONGLONG LastTime; // 100ns 刻度
};

struct REPORT_EARLY_STAGE_ENTRY
{
    volatile LONG InUse;
    NTSTATUS StatusCode;
    CHAR FunctionName[64];
    CHAR ExtraMsg[256];
};

static REPORT_DEDUP_ENTRY s_DedupTable[REPORT_DEDUP_SLOTS] = {0};
static volatile LONG s_DedupSlotIndex = 0;
static volatile LONGLONG s_BurstWindowStartTime = 0;
static volatile LONG s_BurstCount = 0;
static REPORT_EARLY_STAGE_ENTRY s_EarlyStageTable[REPORT_EARLY_STAGE_SLOTS] = {0};

static ULONG64 ComputeReportFingerprint(const char *cardKey, const char *functionName, NTSTATUS status, const char *extraMsg)
{
    ULONG64 h = 0xcbf29ce484222325ULL;
    if (cardKey)
    {
        for (const char *p = cardKey; *p; ++p)
        {
            h ^= (UCHAR)*p;
            h *= 0x100000001b3ULL;
        }
    }
    if (functionName)
    {
        for (const char *p = functionName; *p; ++p)
        {
            h ^= (UCHAR)*p;
            h *= 0x100000001b3ULL;
        }
    }
    h ^= (ULONG)status;
    h *= 0x100000001b3ULL;
    if (extraMsg)
    {
        for (const char *p = extraMsg; *p; ++p)
        {
            if ((p[0] == ' ' && p[1] == '[' && p[2] == 'd' && p[3] == 't' && p[4] == '=') ||
                (p[0] == '[' && p[1] == 'd' && p[2] == 't' && p[3] == '='))
            {
                break;
            }
            h ^= (UCHAR)*p;
            h *= 0x100000001b3ULL;
        }
    }
    return h;
}

static void QueueReportWorkItemInternal(const char *functionName, NTSTATUS status, const char *extraMsg)
{
    if (InterlockedCompareExchange(&s_ReporterClosing, 0, 0) != 0)
    {
        DBG("[-] ExceptionReporter: Dropped - Reporter is closing");
        return;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = s_pUserVar;
    if (!UserVar || !UserVar->Func.ExAllocatePoolWithTag)
    {
        DBG("[-] ExceptionReporter: Dropped - UserVar not ready");
        return;
    }

    PDRV_EXCEPTION_REPORT_ITEM pItem = (PDRV_EXCEPTION_REPORT_ITEM)UserVar->Func.ExAllocatePoolWithTag(
        NonPagedPool, sizeof(DRV_EXCEPTION_REPORT_ITEM), MK_POOL_TAG);
    if (!pItem)
    {
        DBG("[-] ExceptionReporter: Dropped - ExAllocatePoolWithTag failed");
        return;
    }

    UserVar->Func.RtlZeroMemory(pItem, sizeof(DRV_EXCEPTION_REPORT_ITEM));
    pItem->UserVar = UserVar;
    pItem->StatusCode = status;
    strncpy_s(pItem->ApiUrl, s_ApiUrl, _TRUNCATE);
    if (functionName)
        strncpy_s(pItem->FunctionName, functionName, _TRUNCATE);
    if (extraMsg)
        strncpy_s(pItem->ExtraMsg, extraMsg, _TRUNCATE);
    if (s_CardKey[0])
        strncpy_s(pItem->CardKey, s_CardKey, _TRUNCATE);
    if (s_BrandVersion[0])
        strncpy_s(pItem->BrandVersion, s_BrandVersion, _TRUNCATE);
    if (s_SelectedGame[0])
        strncpy_s(pItem->SelectedGame, s_SelectedGame, _TRUNCATE);
    if (s_ClientVersion[0])
        strncpy_s(pItem->ClientVersion, s_ClientVersion, _TRUNCATE);

    ExInitializeWorkItem(&pItem->WorkItem, AsyncWorkRoutine, pItem);
    if (UserVar->Func.ExQueueWorkItem)
    {
        InterlockedIncrement(&s_ActiveReportsCount);
        UserVar->Func.ExQueueWorkItem(&pItem->WorkItem, DelayedWorkQueue);
        DBG("[+] ExceptionReporter::Report: WorkItem successfully queued to system worker thread");
    }
    else
    {
        DBG("[-] ExceptionReporter::Report: ExQueueWorkItem pointer is null, freeing item");
        if (UserVar->Func.ExFreePoolWithTag)
            UserVar->Func.ExFreePoolWithTag(pItem, MK_POOL_TAG);
    }
}

static void FlushEarlyStagedReports(void)
{
    if (s_ApiUrl[0] == '\0' || !s_pUserVar)
        return;

    for (int i = 0; i < REPORT_EARLY_STAGE_SLOTS; i++)
    {
        if (InterlockedCompareExchange(&s_EarlyStageTable[i].InUse, 2, 1) == 1)
        {
            DBG("[+] ExceptionReporter: Flushing early staged report [%d] func='%s' status=0x%08X",
                i, s_EarlyStageTable[i].FunctionName, (ULONG)s_EarlyStageTable[i].StatusCode);
            QueueReportWorkItemInternal(s_EarlyStageTable[i].FunctionName,
                                        s_EarlyStageTable[i].StatusCode,
                                        s_EarlyStageTable[i].ExtraMsg);
            s_EarlyStageTable[i].FunctionName[0] = '\0';
            s_EarlyStageTable[i].ExtraMsg[0] = '\0';
            InterlockedExchange(&s_EarlyStageTable[i].InUse, 0);
        }
    }
}

// ============================================================
// ExceptionReporter 类成员函数实现
// ============================================================
void ExceptionReporter::SetApiUrl(const char *url)
{
    if (url && url[0] != '\0')
    {
        strncpy_s(s_ApiUrl, url, _TRUNCATE);
        DBG("[+] ExceptionReporter::SetApiUrl: '%s'", s_ApiUrl);
        FlushEarlyStagedReports();
    }
    else
    {
        s_ApiUrl[0] = '\0';
        DBG("[+] ExceptionReporter::SetApiUrl: cleared");
    }
}

void ExceptionReporter::SetCardKey(const char *cardKey)
{
    if (cardKey)
        strncpy_s(s_CardKey, cardKey, _TRUNCATE);
    else
        s_CardKey[0] = '\0';
    DBG("[+] ExceptionReporter::SetCardKey: '%.16s...'", s_CardKey);
}

void ExceptionReporter::SetBrandVersion(const char *brand)
{
    if (brand)
        strncpy_s(s_BrandVersion, brand, _TRUNCATE);
    else
        s_BrandVersion[0] = '\0';
}

void ExceptionReporter::SetSelectedGame(const char *game)
{
    if (game)
        strncpy_s(s_SelectedGame, game, _TRUNCATE);
    else
        s_SelectedGame[0] = '\0';
}

void ExceptionReporter::SetClientVersion(const char *version)
{
    if (version)
        strncpy_s(s_ClientVersion, version, _TRUNCATE);
    else
        s_ClientVersion[0] = '\0';
}

void ExceptionReporter::SetUserVar(MACHENIKE_KERNEL_INTERFACE *userVar)
{
    s_pUserVar = userVar;
    InterlockedExchange(&s_ReporterClosing, 0);
    if (s_ApiUrl[0] != '\0')
        FlushEarlyStagedReports();
}

void ExceptionReporter::Report(const char *functionName, NTSTATUS status, const char *extraMsg)
{
    if (InterlockedCompareExchange(&s_ReporterClosing, 0, 0) != 0)
    {
        return;
    }

    DBG("[*] ExceptionReporter::Report: func='%s', status=0x%08X, msg='%s', targetUrl='%s'",
        functionName ? functionName : "(null)", (ULONG)status, extraMsg ? extraMsg : "", s_ApiUrl);

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    // 1. 相同故障指纹 60 秒冷却去重 (同卡密 + 同函数 + 同错误码 + 同诊断消息)
    ULONG64 fp = ComputeReportFingerprint(s_CardKey, functionName, status, extraMsg);
    BOOLEAN bMatchedSlot = FALSE;
    for (int i = 0; i < REPORT_DEDUP_SLOTS; i++)
    {
        if (s_DedupTable[i].Hash == fp)
        {
            LONGLONG diffSec = (now.QuadPart - s_DedupTable[i].LastTime) / 10000000LL;
            if (diffSec >= 0 && diffSec < REPORT_COOLDOWN_SECONDS)
            {
                DBG("[*] ExceptionReporter::Report: Suppressed duplicate report (fp=0x%016llX, elapsed=%llds < %ds)",
                    fp, diffSec, REPORT_COOLDOWN_SECONDS);
                return;
            }
            s_DedupTable[i].LastTime = now.QuadPart;
            bMatchedSlot = TRUE;
            break;
        }
    }

    if (!bMatchedSlot)
    {
        LONG slot = InterlockedIncrement(&s_DedupSlotIndex) & (REPORT_DEDUP_SLOTS - 1);
        s_DedupTable[slot].Hash = fp;
        s_DedupTable[slot].LastTime = now.QuadPart;
    }

    // 2. 10 秒突发窗口频控 (允许同一轮巡检并发上报多达 8 条不同指纹的告警，仅阻断失控死循环洪泛)
    LONGLONG winStart = InterlockedCompareExchange64(&s_BurstWindowStartTime, 0, 0);
    LONGLONG winDiffSec = (winStart != 0) ? ((now.QuadPart - winStart) / 10000000LL) : REPORT_BURST_WINDOW_SECONDS;
    if (winStart == 0 || winDiffSec < 0 || winDiffSec >= REPORT_BURST_WINDOW_SECONDS)
    {
        InterlockedExchange64(&s_BurstWindowStartTime, now.QuadPart);
        InterlockedExchange(&s_BurstCount, 1);
    }
    else
    {
        LONG curBurst = InterlockedIncrement(&s_BurstCount);
        if (curBurst > REPORT_BURST_MAX_PER_WINDOW)
        {
            DBG("[*] ExceptionReporter::Report: Suppressed by burst window limiter (%ld > %d within %llds)",
                curBurst, REPORT_BURST_MAX_PER_WINDOW, winDiffSec);
            return;
        }
    }

    // 3. 若当前已探测到 ACE 模块，自动计算对应 ACE 驱动模块加载时间戳与当前触发时刻的时间差 [dt=+%llums]
    LONGLONG gameStart = InterlockedCompareExchange64(&g_GameProcessStartTime, 0, 0);
    CHAR enrichedMsg[256] = {0};
    const char *finalExtraMsg = extraMsg;
    if (gameStart > 0 && extraMsg && extraMsg[0] != '\0')
    {
        BOOLEAN bHasDt = FALSE;
        for (const char *p = extraMsg; *p; ++p)
        {
            if (p[0] == '[' && p[1] == 'd' && p[2] == 't' && p[3] == '=')
            {
                bHasDt = TRUE;
                break;
            }
        }
        if (!bHasDt)
        {
            ULONG64 totalSec = (now.QuadPart >= gameStart) ? (ULONG64)((now.QuadPart - gameStart) / 10000000LL) : 0ULL;
            ULONG64 hours = totalSec / 3600ULL;
            ULONG minutes = (ULONG)((totalSec % 3600ULL) / 60ULL);
            ULONG seconds = (ULONG)(totalSec % 60ULL);
            _snprintf_s(enrichedMsg, sizeof(enrichedMsg), _TRUNCATE, "%s [dt=%llu小时%02u分%02u秒]",
                        extraMsg, hours, minutes, seconds);
            finalExtraMsg = enrichedMsg;
        }
    }

    if (s_ApiUrl[0] == '\0')
    {
        for (int i = 0; i < REPORT_EARLY_STAGE_SLOTS; i++)
        {
            if (InterlockedCompareExchange(&s_EarlyStageTable[i].InUse, -1, 0) == 0)
            {
                s_EarlyStageTable[i].StatusCode = status;
                if (functionName)
                    strncpy_s(s_EarlyStageTable[i].FunctionName, functionName, _TRUNCATE);
                else
                    s_EarlyStageTable[i].FunctionName[0] = '\0';
                if (finalExtraMsg)
                    strncpy_s(s_EarlyStageTable[i].ExtraMsg, finalExtraMsg, _TRUNCATE);
                else
                    s_EarlyStageTable[i].ExtraMsg[0] = '\0';
                InterlockedExchange(&s_EarlyStageTable[i].InUse, 1);
                DBG("[*] ExceptionReporter::Report: ApiUrl not yet configured, staged into early slot [%d]", i);
                return;
            }
        }
        DBG("[-] ExceptionReporter::Report: Dropped - ApiUrl is not configured and early staging slots full");
        return;
    }

    QueueReportWorkItemInternal(functionName, status, finalExtraMsg);
}

void ExceptionReporter::ReportFormat(const char *functionName, NTSTATUS status, const char *format, ...)
{
    if (InterlockedCompareExchange(&s_ReporterClosing, 0, 0) != 0)
    {
        return;
    }

    if (!format)
    {
        Report(functionName, status, nullptr);
        return;
    }

    CHAR buffer[256] = {0};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);

    Report(functionName, status, buffer);
}

void ExceptionReporter::Cleanup(MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    InterlockedExchange(&s_ReporterClosing, 1);

    for (int i = 0; i < REPORT_EARLY_STAGE_SLOTS; i++)
    {
        InterlockedExchange(&s_EarlyStageTable[i].InUse, 0);
    }

    if (!UserVar)
        UserVar = s_pUserVar;

    if (UserVar && UserVar->Func.KeDelayExecutionThread)
    {
        for (ULONG waitIdx = 0; waitIdx < 100; ++waitIdx)
        {
            if (InterlockedCompareExchange(&s_ActiveReportsCount, 0, 0) == 0)
            {
                break;
            }
            LARGE_INTEGER interval;
            interval.QuadPart = -500000LL; /* 50ms */
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
        LARGE_INTEGER drainDelay;
        drainDelay.QuadPart = -200000LL; /* 20ms 流水线排空屏障 */
        UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &drainDelay);
    }

    s_pUserVar = NULL;
    DBG("[+] ExceptionReporter::Cleanup: Drain completed successfully.");
}

extern "C" void ExceptionReporter_Report(const char *functionName, NTSTATUS status, const char *extraMsg)
{
    ExceptionReporter::Report(functionName, status, extraMsg);
}

extern "C" void ExceptionReporter_ReportFormat(const char *functionName, NTSTATUS status, const char *format, ...)
{
    if (!format)
    {
        ExceptionReporter::Report(functionName, status, nullptr);
        return;
    }

    CHAR buffer[256] = {0};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);

    ExceptionReporter::Report(functionName, status, buffer);
}

extern "C" void ExceptionReporter_Cleanup(MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    ExceptionReporter::Cleanup(UserVar);
}
