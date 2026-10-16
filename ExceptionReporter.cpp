#include "ExceptionReporter.h"
#include "DrvSecurity.h"
#include <bcrypt.h>
#include <stdarg.h>
#include <stdio.h>

#pragma comment(lib, "ksecdd.lib")

#define TLS_REPORT_POOL_TAG 'sLtM'

namespace {

// ============================================================
// 静态配置与内部状态
// ============================================================
CHAR s_ApiUrl[128] = {0};
CHAR s_BrandVersion[64] = {0};
CHAR s_SelectedGame[64] = {0};
CHAR s_ClientVersion[64] = {0};
MACHENIKE_KERNEL_INTERFACE *s_pUserVar = nullptr;

const WSK_CLIENT_DISPATCH s_ReportWskClientDispatch = {MAKE_WSK_VERSION(1, 0), 0, NULL};

typedef struct _DRV_EXCEPTION_REPORT_ITEM
{
    WORK_QUEUE_ITEM WorkItem;
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    CHAR ApiUrl[128];
    CHAR FunctionName[64];
    NTSTATUS StatusCode;
    CHAR ExtraMsg[128];
} DRV_EXCEPTION_REPORT_ITEM, *PDRV_EXCEPTION_REPORT_ITEM;

// ============================================================
// 内部网络通信与加解密底层例程
// ============================================================
NTSTATUS SyncCompletion(PDEVICE_OBJECT Reserved, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    PKEVENT pEvent = (PKEVENT)Context;
    if (pEvent) KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

BOOLEAN ParseIpv4(const char *str, ULONG *pIpNetOrder)
{
    if (!str || !pIpNetOrder) return FALSE;
    ULONG parts[4] = {0};
    int cur = 0;
    const char *p = str;
    while (*p && cur < 4) {
        if (*p >= '0' && *p <= '9') {
            parts[cur] = parts[cur] * 10 + (*p - '0');
            if (parts[cur] > 255) return FALSE;
        } else if (*p == '.') {
            cur++;
            if (cur >= 4) return FALSE;
        } else {
            break;
        }
        p++;
    }
    if (cur != 3) return FALSE;
    UCHAR b[4] = {(UCHAR)parts[0], (UCHAR)parts[1], (UCHAR)parts[2], (UCHAR)parts[3]};
    *pIpNetOrder = *(ULONG *)b;
    return TRUE;
}

VOID ParseUrlComponents(
    const char *url,
    BOOLEAN *pIsHttps,
    char *outHost, size_t maxHostLen,
    USHORT *outPort,
    char *outPath, size_t maxPathLen)
{
    outHost[0] = '\0';
    outPath[0] = '\0';
    *pIsHttps = FALSE;
    *outPort = 80;

    if (!url || url[0] == '\0') return;

    const char *p = url;
    while (*p == ' ' || *p == '\t') p++;

    if (_strnicmp(p, "https://", 8) == 0) {
        *pIsHttps = TRUE;
        *outPort = 443;
        p += 8;
    } else if (_strnicmp(p, "http://", 7) == 0) {
        *pIsHttps = FALSE;
        *outPort = 80;
        p += 7;
    }

    size_t hostIdx = 0;
    while (*p && *p != ':' && *p != '/' && *p != ' ' && hostIdx + 1 < maxHostLen) {
        outHost[hostIdx++] = *p++;
    }
    outHost[hostIdx] = '\0';

    if (*p == ':') {
        p++;
        int portVal = 0;
        while (*p >= '0' && *p <= '9') {
            portVal = portVal * 10 + (*p - '0');
            p++;
        }
        if (portVal > 0 && portVal <= 65535) *outPort = (USHORT)portVal;
    }

    if (*p == '/') {
        strncpy_s(outPath, maxPathLen, p, _TRUNCATE);
    } else {
        strncpy_s(outPath, maxPathLen, "/api/tg", _TRUNCATE);
    }

    if (*outPort == 443) *pIsHttps = TRUE;
}

NTSTATUS HmacSha256(const UCHAR *Key, ULONG KeyLen, const UCHAR *Data, ULONG DataLen, UCHAR *OutMac32)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)Key, KeyLen, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hHash, (PUCHAR)Data, DataLen, 0);
        if (NT_SUCCESS(status)) status = BCryptFinishHash(hHash, OutMac32, 32, 0);
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

NTSTATUS TlsPrfSha256(const UCHAR *Secret, ULONG SecretLen, const char *Label, const UCHAR *Seed, ULONG SeedLen, UCHAR *OutBuffer, ULONG OutLen)
{
    ULONG labelLen = (ULONG)strlen(Label);
    ULONG fullSeedLen = labelLen + SeedLen;
    PUCHAR fullSeed = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, fullSeedLen, TLS_REPORT_POOL_TAG);
    if (!fullSeed) return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(fullSeed, Label, labelLen);
    memcpy(fullSeed + labelLen, Seed, SeedLen);

    UCHAR A[32];
    HmacSha256(Secret, SecretLen, fullSeed, fullSeedLen, A);

    ULONG generated = 0;
    PUCHAR currentOut = OutBuffer;

    while (generated < OutLen) {
        ULONG stepInputLen = 32 + fullSeedLen;
        PUCHAR stepInput = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, stepInputLen, TLS_REPORT_POOL_TAG);
        if (!stepInput) {
            ExFreePoolWithTag(fullSeed, TLS_REPORT_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(stepInput, A, 32);
        memcpy(stepInput + 32, fullSeed, fullSeedLen);

        UCHAR block[32];
        HmacSha256(Secret, SecretLen, stepInput, stepInputLen, block);
        ExFreePoolWithTag(stepInput, TLS_REPORT_POOL_TAG);

        ULONG copySize = (OutLen - generated > 32) ? 32 : (OutLen - generated);
        memcpy(currentOut, block, copySize);
        generated += copySize;
        currentOut += copySize;

        HmacSha256(Secret, SecretLen, A, 32, A);
    }

    ExFreePoolWithTag(fullSeed, TLS_REPORT_POOL_TAG);
    return STATUS_SUCCESS;
}

BOOLEAN ExtractRsaPublicKeyFromDer(
    const UCHAR *CertDer, ULONG CertLen,
    PUCHAR *OutModulus, PULONG OutModulusLen,
    PUCHAR *OutExponent, PULONG OutExponentLen)
{
    static const UCHAR rsaOid[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    if (!CertDer || CertLen < 64) return FALSE;

    const UCHAR *p = CertDer;
    const UCHAR *end = CertDer + CertLen - sizeof(rsaOid) - 32;
    const UCHAR *found = NULL;

    while (p < end) {
        if (memcmp(p, rsaOid, sizeof(rsaOid)) == 0) { found = p; break; }
        p++;
    }
    if (!found) return FALSE;

    p = found + sizeof(rsaOid);
    while (p < CertDer + CertLen - 16 && *p != 0x03) p++;
    if (p >= CertDer + CertLen - 16) return FALSE;
    p++; // 跳过 0x03

    if (*p & 0x80) p += 1 + (*p & 0x7F); else p++;
    p++; // 跳过 unused bits (0x00)

    if (*p != 0x30) return FALSE;
    p++;
    if (*p & 0x80) p += 1 + (*p & 0x7F); else p++;

    // Modulus (0x02)
    if (*p != 0x02) return FALSE;
    p++;
    ULONG modLen = 0;
    if (*p & 0x80) {
        ULONG lenBytes = *p & 0x7F;
        p++;
        for (ULONG i = 0; i < lenBytes; ++i) modLen = (modLen << 8) | *p++;
    } else {
        modLen = *p++;
    }

    if (*p == 0x00 && modLen > 1) { p++; modLen--; }
    *OutModulus = (PUCHAR)p;
    *OutModulusLen = modLen;
    p += modLen;

    // Exponent (0x02)
    if (*p != 0x02) return FALSE;
    p++;
    *OutExponentLen = *p++;
    *OutExponent = (PUCHAR)p;

    return TRUE;
}

NTSTATUS WskSyncSend(MACHENIKE_KERNEL_INTERFACE *UserVar, PWSK_SOCKET hSocket, PIRP Irp, PKEVENT pEvent, const void *buf, ULONG len)
{
    if (!UserVar || !hSocket || !Irp || !pEvent || !buf || len == 0) return STATUS_INVALID_PARAMETER;
    PMDL pMdl = UserVar->Func.IoAllocateMdl((PVOID)buf, len, FALSE, FALSE, NULL);
    if (!pMdl) return STATUS_INSUFFICIENT_RESOURCES;
    MmBuildMdlForNonPagedPool(pMdl);

    WSK_BUF wskBuf = {pMdl, 0, len};
    IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(Irp, SyncCompletion, pEvent, TRUE, TRUE, TRUE);

    NTSTATUS status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskSend(hSocket, &wskBuf, 0, Irp);
    if (status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000LL * 3000; // 3s
        NTSTATUS waitSt = UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, &timeout);
        if (waitSt == STATUS_TIMEOUT) {
            IoCancelIrp(Irp);
            UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
            status = STATUS_TIMEOUT;
        } else {
            status = Irp->IoStatus.Status;
        }
    }
    UserVar->Func.IoFreeMdl(pMdl);
    return status;
}

NTSTATUS WskSyncReceive(MACHENIKE_KERNEL_INTERFACE *UserVar, PWSK_SOCKET hSocket, PIRP Irp, PKEVENT pEvent, void *buf, ULONG len, ULONG timeoutMs, PULONG pBytesReceived)
{
    if (!UserVar || !hSocket || !Irp || !pEvent || !buf || len == 0) return STATUS_INVALID_PARAMETER;
    PMDL pMdl = UserVar->Func.IoAllocateMdl(buf, len, FALSE, FALSE, NULL);
    if (!pMdl) return STATUS_INSUFFICIENT_RESOURCES;
    MmBuildMdlForNonPagedPool(pMdl);

    WSK_BUF wskBuf = {pMdl, 0, len};
    IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(Irp, SyncCompletion, pEvent, TRUE, TRUE, TRUE);

    NTSTATUS status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskReceive(hSocket, &wskBuf, 0, Irp);
    if (status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000LL * timeoutMs;
        NTSTATUS waitSt = UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, &timeout);
        if (waitSt == STATUS_TIMEOUT) {
            IoCancelIrp(Irp);
            UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
            status = STATUS_TIMEOUT;
        } else {
            status = Irp->IoStatus.Status;
        }
    }
    if (NT_SUCCESS(status) && pBytesReceived) *pBytesReceived = (ULONG)Irp->IoStatus.Information;
    UserVar->Func.IoFreeMdl(pMdl);
    return status;
}

NTSTATUS PerformTlsHandshakeAndSendHttp(
    MACHENIKE_KERNEL_INTERFACE *UserVar,
    PWSK_SOCKET hSocket,
    PIRP Irp,
    PKEVENT pEvent,
    const char *szHost,
    const char *httpReq,
    ULONG reqLen)
{
    if (!UserVar || !hSocket || !Irp || !pEvent || !httpReq || reqLen == 0) return STATUS_INVALID_PARAMETER;

    UCHAR clientRandom[32] = {0};
    UCHAR serverRandom[32] = {0};
    UCHAR preMasterSecret[48] = {0};
    UCHAR masterSecret[48] = {0};

    BCRYPT_ALG_HANDLE hRng = NULL;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0))) {
        BCryptGenRandom(hRng, clientRandom, 32, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    } else {
        ULONG64 t = __rdtsc();
        memcpy(clientRandom, &t, 8);
    }

    BCRYPT_ALG_HANDLE hSha256Alg = NULL;
    BCRYPT_HASH_HANDLE hHandshakeHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hSha256Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;
    status = BCryptCreateHash(hSha256Alg, &hHandshakeHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    // 1. 构建 ClientHello
    UCHAR helloBuf[512] = {0};
    helloBuf[0] = 0x16; helloBuf[1] = 0x03; helloBuf[2] = 0x01;
    ULONG hIdx = 5;
    ULONG hsStart = hIdx;
    helloBuf[hIdx++] = 0x01; // ClientHello
    hIdx += 3;
    helloBuf[hIdx++] = 0x03; helloBuf[hIdx++] = 0x03;
    memcpy(&helloBuf[hIdx], clientRandom, 32); hIdx += 32;
    helloBuf[hIdx++] = 0x00;

    // Cipher Suites
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x06;
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x2F;
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x35;
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x3C;
    helloBuf[hIdx++] = 0x01; helloBuf[hIdx++] = 0x00;

    // Extensions (SNI)
    ULONG extLenPos = hIdx;
    hIdx += 2;
    ULONG extStart = hIdx;
    if (szHost && szHost[0] != '\0') {
        USHORT hostLen = (USHORT)strlen(szHost);
        USHORT sniExtLen = hostLen + 5;
        USHORT sniListLen = hostLen + 3;
        helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x00;
        helloBuf[hIdx++] = (UCHAR)(sniExtLen >> 8); helloBuf[hIdx++] = (UCHAR)(sniExtLen & 0xFF);
        helloBuf[hIdx++] = (UCHAR)(sniListLen >> 8); helloBuf[hIdx++] = (UCHAR)(sniListLen & 0xFF);
        helloBuf[hIdx++] = 0x00;
        helloBuf[hIdx++] = (UCHAR)(hostLen >> 8); helloBuf[hIdx++] = (UCHAR)(hostLen & 0xFF);
        memcpy(&helloBuf[hIdx], szHost, hostLen); hIdx += hostLen;
    }
    // Signature algorithms
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x0D;
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x06;
    helloBuf[hIdx++] = 0x00; helloBuf[hIdx++] = 0x04;
    helloBuf[hIdx++] = 0x04; helloBuf[hIdx++] = 0x01;
    helloBuf[hIdx++] = 0x02; helloBuf[hIdx++] = 0x01;

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
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    // 2. 接收 ServerHello, Certificate, ServerHelloDone
    PUCHAR recvBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 16384, TLS_REPORT_POOL_TAG);
    if (!recvBuf) {
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

    for (int retry = 0; retry < 5 && !gotDone; retry++) {
        ULONG received = 0;
        status = WskSyncReceive(UserVar, hSocket, Irp, pEvent, recvBuf + totalRecv, 16384 - totalRecv, 3000, &received);
        if (!NT_SUCCESS(status) || received == 0) break;
        totalRecv += received;

        ULONG cursor = 0;
        while (cursor + 5 <= totalRecv) {
            UCHAR recType = recvBuf[cursor];
            USHORT rLen = (recvBuf[cursor + 3] << 8) | recvBuf[cursor + 4];
            if (cursor + 5 + rLen > totalRecv) break;

            if (recType == 0x16) {
                ULONG hCursor = cursor + 5;
                ULONG hEnd = cursor + 5 + rLen;
                while (hCursor + 4 <= hEnd) {
                    UCHAR hsType = recvBuf[hCursor];
                    ULONG hLen = (recvBuf[hCursor + 1] << 16) | (recvBuf[hCursor + 2] << 8) | recvBuf[hCursor + 3];
                    BCryptHashData(hHandshakeHash, &recvBuf[hCursor], hLen + 4, 0);

                    if (hsType == 0x02) {
                        memcpy(serverRandom, &recvBuf[hCursor + 6], 32);
                    } else if (hsType == 0x0B) {
                        ExtractRsaPublicKeyFromDer(&recvBuf[hCursor + 4], hLen, &pModulus, &modLen, &pExponent, &expLen);
                    } else if (hsType == 0x0E) {
                        gotDone = TRUE;
                    }
                    hCursor += 4 + hLen;
                }
            }
            cursor += 5 + rLen;
        }
    }

    if (!gotDone || !pModulus || modLen == 0 || !pExponent || expLen == 0) {
        ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return STATUS_UNSUCCESSFUL;
    }

    // 3. 构造 RSA 公钥 Blob 并加密 PreMasterSecret
    BCRYPT_ALG_HANDLE hRsaAlg = NULL;
    BCRYPT_KEY_HANDLE hRsaKey = NULL;
    BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);

    ULONG blobSize = sizeof(BCRYPT_RSAKEY_BLOB) + expLen + modLen;
    PUCHAR keyBlob = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, blobSize, TLS_REPORT_POOL_TAG);
    if (!keyBlob) {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
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
    ExFreePoolWithTag(keyBlob, TLS_REPORT_POOL_TAG);

    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
        BCryptDestroyHash(hHandshakeHash);
        BCryptCloseAlgorithmProvider(hSha256Alg, 0);
        return status;
    }

    preMasterSecret[0] = 0x03; preMasterSecret[1] = 0x03;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0))) {
        BCryptGenRandom(hRng, preMasterSecret + 2, 46, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    } else {
        ULONG64 t = __rdtsc();
        memcpy(preMasterSecret + 2, &t, 8);
    }

    UCHAR encPreMaster[512] = {0};
    ULONG encLen = 0;
    status = BCryptEncrypt(hRsaKey, preMasterSecret, 48, NULL, NULL, 0, encPreMaster, sizeof(encPreMaster), &encLen, BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(hRsaKey);
    BCryptCloseAlgorithmProvider(hRsaAlg, 0);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
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
    flightBuf[fIdx++] = 0x16; flightBuf[fIdx++] = 0x03; flightBuf[fIdx++] = 0x03;
    USHORT ckeRecordLen = (USHORT)(4 + 2 + encLen);
    flightBuf[fIdx++] = (UCHAR)(ckeRecordLen >> 8); flightBuf[fIdx++] = (UCHAR)(ckeRecordLen & 0xFF);

    ULONG ckeHsStart = fIdx;
    flightBuf[fIdx++] = 0x10;
    ULONG ckeDataLen = 2 + encLen;
    flightBuf[fIdx++] = 0x00;
    flightBuf[fIdx++] = (UCHAR)(ckeDataLen >> 8); flightBuf[fIdx++] = (UCHAR)(ckeDataLen & 0xFF);
    flightBuf[fIdx++] = (UCHAR)(encLen >> 8); flightBuf[fIdx++] = (UCHAR)(encLen & 0xFF);
    memcpy(&flightBuf[fIdx], encPreMaster, encLen); fIdx += encLen;

    BCryptHashData(hHandshakeHash, &flightBuf[ckeHsStart], ckeRecordLen, 0);

    flightBuf[fIdx++] = 0x14; flightBuf[fIdx++] = 0x03; flightBuf[fIdx++] = 0x03;
    flightBuf[fIdx++] = 0x00; flightBuf[fIdx++] = 0x01; flightBuf[fIdx++] = 0x01;

    // Finished
    BCRYPT_HASH_HANDLE hHashDup = NULL;
    UCHAR handshakeHashVal[32] = {0};
    UCHAR verifyData[12] = {0};
    BCryptDuplicateHash(hHandshakeHash, &hHashDup, NULL, 0, 0);
    BCryptFinishHash(hHashDup, handshakeHashVal, 32, 0);
    BCryptDestroyHash(hHashDup);

    TlsPrfSha256(masterSecret, 48, "client finished", handshakeHashVal, 32, verifyData, 12);

    UCHAR finishedPlain[16] = { 0x14, 0x00, 0x00, 0x0C };
    memcpy(&finishedPlain[4], verifyData, 12);

    UCHAR macInput[13 + 16] = {0};
    macInput[8] = 0x16; macInput[9] = 0x03; macInput[10] = 0x03; macInput[11] = 0x00; macInput[12] = 0x10;
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
    for (int i = 36; i < 48; ++i) toEncrypt[i] = 11;

    UCHAR explicitIV[16] = {0};
    for (int i = 0; i < 16; ++i) explicitIV[i] = (UCHAR)(__rdtsc() ^ i);

    UCHAR encryptedFinished[48] = {0};
    ULONG encFinLen = 0;
    UCHAR ivCopy[16] = {0};
    memcpy(ivCopy, explicitIV, 16);
    BCryptEncrypt(hClientAesKey, toEncrypt, 48, NULL, ivCopy, 16, encryptedFinished, 48, &encFinLen, 0);

    flightBuf[fIdx++] = 0x16; flightBuf[fIdx++] = 0x03; flightBuf[fIdx++] = 0x03;
    USHORT finRecLen = (USHORT)(16 + 48);
    flightBuf[fIdx++] = (UCHAR)(finRecLen >> 8); flightBuf[fIdx++] = (UCHAR)(finRecLen & 0xFF);
    memcpy(&flightBuf[fIdx], explicitIV, 16); fIdx += 16;
    memcpy(&flightBuf[fIdx], encryptedFinished, 48); fIdx += 48;

    status = WskSyncSend(UserVar, hSocket, Irp, pEvent, flightBuf, fIdx);
    ExFreePoolWithTag(recvBuf, TLS_REPORT_POOL_TAG);
    BCryptDestroyHash(hHandshakeHash);
    BCryptCloseAlgorithmProvider(hSha256Alg, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return status;
    }

    // 6. 发送加密的 HTTP POST Application Data
    ULONG unpaddedLen = reqLen + 20;
    ULONG padLen = 16 - (unpaddedLen % 16);
    ULONG totalPlainLen = unpaddedLen + padLen;
    PUCHAR appPlain = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, totalPlainLen, TLS_REPORT_POOL_TAG);
    if (!appPlain) {
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(appPlain, httpReq, reqLen);

    UCHAR appMacHeader[13] = {0};
    UINT64 seqNumBE = RtlUlonglongByteSwap(1ULL);
    memcpy(&appMacHeader[0], &seqNumBE, 8);
    appMacHeader[8] = 0x17; appMacHeader[9] = 0x03; appMacHeader[10] = 0x03;
    appMacHeader[11] = (UCHAR)(reqLen >> 8); appMacHeader[12] = (UCHAR)(reqLen & 0xFF);

    BCryptOpenAlgorithmProvider(&hMacAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptCreateHash(hMacAlg, &hMac, NULL, 0, clientMacKey, 20, 0);
    BCryptHashData(hMac, appMacHeader, 13, 0);
    BCryptHashData(hMac, (PUCHAR)httpReq, reqLen, 0);
    BCryptFinishHash(hMac, appPlain + reqLen, 20, 0);
    BCryptDestroyHash(hMac);
    BCryptCloseAlgorithmProvider(hMacAlg, 0);

    for (ULONG i = 0; i < padLen; ++i) appPlain[reqLen + 20 + i] = (UCHAR)(padLen - 1);

    UCHAR appExplicitIV[16] = {0};
    for (int i = 0; i < 16; ++i) appExplicitIV[i] = (UCHAR)(__rdtsc() ^ (i * 7));

    ULONG totalCipherLen = 16 + totalPlainLen;
    PUCHAR recordBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 5 + totalCipherLen, TLS_REPORT_POOL_TAG);
    if (!recordBuf) {
        ExFreePoolWithTag(appPlain, TLS_REPORT_POOL_TAG);
        BCryptDestroyKey(hClientAesKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    recordBuf[0] = 0x17; recordBuf[1] = 0x03; recordBuf[2] = 0x03;
    recordBuf[3] = (UCHAR)(totalCipherLen >> 8); recordBuf[4] = (UCHAR)(totalCipherLen & 0xFF);
    memcpy(recordBuf + 5, appExplicitIV, 16);

    UCHAR appIvCopy[16] = {0};
    memcpy(appIvCopy, appExplicitIV, 16);
    ULONG appEncLen = 0;
    BCryptEncrypt(hClientAesKey, appPlain, totalPlainLen, NULL, appIvCopy, 16, recordBuf + 5 + 16, totalPlainLen, &appEncLen, 0);
    ExFreePoolWithTag(appPlain, TLS_REPORT_POOL_TAG);

    status = WskSyncSend(UserVar, hSocket, Irp, pEvent, recordBuf, 5 + totalCipherLen);
    ExFreePoolWithTag(recordBuf, TLS_REPORT_POOL_TAG);

    BCryptDestroyKey(hClientAesKey);
    BCryptCloseAlgorithmProvider(hAesAlg, 0);

    return status;
}

VOID PerformHttp(PDRV_EXCEPTION_REPORT_ITEM pItem)
{
    if (!pItem || !pItem->UserVar) return;
    MACHENIKE_KERNEL_INTERFACE *UserVar = pItem->UserVar;
    if (!UserVar->Func.WskRegister || !UserVar->Func.WskCaptureProviderNPI) return;

    BOOLEAN bIsHttps = FALSE;
    CHAR szHost[64] = {0};
    USHORT targetPort = 80;
    CHAR szPath[128] = {0};
    ParseUrlComponents(pItem->ApiUrl, &bIsHttps, szHost, sizeof(szHost), &targetPort, szPath, sizeof(szPath));
    if (szHost[0] == '\0') return;

    const char *szBrand = s_BrandVersion[0] ? s_BrandVersion : "CheatDrv";
    const char *szGame = s_SelectedGame[0] ? s_SelectedGame : "Default";
    const char *szVer = s_ClientVersion[0] ? s_ClientVersion : "1.0";

    CHAR plainData[512] = {0};
    int plainLen = _snprintf_s(plainData, sizeof(plainData), _TRUNCATE,
        "[functionName]%s[/functionName]\r\n[status]0x%08X[/status]\r\n[brand]%s[/brand]\r\n[game]%s[/game]\r\n[version]%s[/version]\r\n[errorMessage]%s[/errorMessage]",
        pItem->FunctionName, (ULONG)pItem->StatusCode, szBrand, szGame, szVer, pItem->ExtraMsg[0] ? pItem->ExtraMsg : "DriverError");
    if (plainLen <= 0) return;

    CHAR encHex[1024] = {0};
    ULONG encHexLen = DrvSecurity::EncryptReportData(plainData, encHex, sizeof(encHex));

    CHAR httpBody[1400] = {0};
    int bodyLen = 0;
    if (encHexLen > 0) {
        bodyLen = _snprintf_s(httpBody, sizeof(httpBody), _TRUNCATE,
            "h=%s&functionName=%s&status=0x%08X", encHex, pItem->FunctionName, (ULONG)pItem->StatusCode);
    } else {
        bodyLen = _snprintf_s(httpBody, sizeof(httpBody), _TRUNCATE,
            "functionName=%s&status=0x%08X&message=%s", pItem->FunctionName, (ULONG)pItem->StatusCode, pItem->ExtraMsg);
    }
    if (bodyLen <= 0) return;

    CHAR httpReq[2048] = {0};
    int reqLen = _snprintf_s(httpReq, sizeof(httpReq), _TRUNCATE,
        "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s/%s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        szPath[0] ? szPath : "/api/tg", szHost, szBrand, szVer, bodyLen, httpBody);
    if (reqLen <= 0) return;

    WSK_REGISTRATION WskRegistration;
    WSK_PROVIDER_NPI WskProviderNpi;
    WSK_CLIENT_NPI ClientNpi = { NULL, &s_ReportWskClientDispatch };

    NTSTATUS status = UserVar->Func.WskRegister(&ClientNpi, &WskRegistration);
    if (!NT_SUCCESS(status)) return;

    status = UserVar->Func.WskCaptureProviderNPI(&WskRegistration, 1000, &WskProviderNpi);
    if (!NT_SUCCESS(status)) {
        UserVar->Func.WskDeregister(&WskRegistration);
        return;
    }

    KEVENT SyncEvent;
    UserVar->Func.KeInitializeEvent(&SyncEvent, SynchronizationEvent, FALSE);
    PIRP Irp = UserVar->Func.IoAllocateIrp(4, FALSE);
    if (!Irp) {
        UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
        UserVar->Func.WskDeregister(&WskRegistration);
        return;
    }

    // 1. DNS 动态解析
    ULONG targetIp = 0;
    if (!ParseIpv4(szHost, &targetIp)) {
        WCHAR wHost[128] = {0};
        for (int i = 0; szHost[i] && i < 127; i++) wHost[i] = (WCHAR)szHost[i];
        UNICODE_STRING uNode;
        RtlInitUnicodeString(&uNode, wHost);

        ADDRINFOEXW hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        PADDRINFOEXW pResult = NULL;
        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskGetAddressInfo(
            WskProviderNpi.Client, &uNode, NULL, NS_ALL, NULL, &hints, &pResult, NULL, NULL, Irp);
        if (status == STATUS_PENDING) {
            LARGE_INTEGER dnsTimeout;
            dnsTimeout.QuadPart = -10000LL * 3000;
            NTSTATUS waitSt = UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &dnsTimeout);
            if (waitSt == STATUS_TIMEOUT) {
                IoCancelIrp(Irp);
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = STATUS_TIMEOUT;
            } else {
                status = Irp->IoStatus.Status;
            }
        }
        if (NT_SUCCESS(status) && pResult && pResult->ai_addr) {
            PSOCKADDR_IN pSin = (PSOCKADDR_IN)pResult->ai_addr;
            targetIp = pSin->sin_addr.s_addr;
            ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskFreeAddressInfo(WskProviderNpi.Client, pResult);
        }
    }

    if (targetIp == 0) {
        UserVar->Func.IoFreeIrp(Irp);
        UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
        UserVar->Func.WskDeregister(&WskRegistration);
        return;
    }

    BOOLEAN bReportDelivered = FALSE;

    // 2. 通道一：HTTPS 走 TLS 1.2
    if (bIsHttps) {
        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        PWSK_SOCKET hSocket = NULL;
        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskSocket(
            WskProviderNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET, NULL, NULL, NULL, NULL, NULL, Irp);
        if (status == STATUS_PENDING) {
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
            status = Irp->IoStatus.Status;
        }
        if (NT_SUCCESS(status)) hSocket = (PWSK_SOCKET)Irp->IoStatus.Information;

        if (hSocket) {
            SOCKADDR_IN localAddr = {0};
            localAddr.sin_family = AF_INET;
            IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskBind(hSocket, (PSOCKADDR)&localAddr, 0, Irp);
            if (status == STATUS_PENDING) {
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = Irp->IoStatus.Status;
            }

            if (NT_SUCCESS(status)) {
                SOCKADDR_IN remoteAddr = {0};
                remoteAddr.sin_family = AF_INET;
                remoteAddr.sin_addr.s_addr = targetIp;
                remoteAddr.sin_port = RtlUshortByteSwap(targetPort);

                IoReuseIrp(Irp, STATUS_SUCCESS);
                IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
                status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskConnect(hSocket, (PSOCKADDR)&remoteAddr, 0, Irp);
                if (status == STATUS_PENDING) {
                    LARGE_INTEGER timeout;
                    timeout.QuadPart = -10000LL * 3000;
                    NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &timeout);
                    if (waitStatus == STATUS_TIMEOUT) {
                        IoCancelIrp(Irp);
                        UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                        status = STATUS_TIMEOUT;
                    } else {
                        status = Irp->IoStatus.Status;
                    }
                }

                if (NT_SUCCESS(status)) {
                    NTSTATUS tlsStatus = PerformTlsHandshakeAndSendHttp(UserVar, hSocket, Irp, &SyncEvent, szHost, httpReq, reqLen);
                    if (NT_SUCCESS(tlsStatus)) bReportDelivered = TRUE;
                }
            }

            IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)hSocket->Dispatch)->WskCloseSocket(hSocket, Irp);
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
        }
    }

    // 3. 通道二：明文 HTTP 兜底
    if (!bReportDelivered) {
        USHORT plainPort = bIsHttps ? 80 : targetPort;

        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);

        PWSK_SOCKET hSocket = NULL;
        status = ((PWSK_PROVIDER_DISPATCH)WskProviderNpi.Dispatch)->WskSocket(
            WskProviderNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET, NULL, NULL, NULL, NULL, NULL, Irp);
        if (status == STATUS_PENDING) {
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
            status = Irp->IoStatus.Status;
        }
        if (NT_SUCCESS(status)) hSocket = (PWSK_SOCKET)Irp->IoStatus.Information;

        if (hSocket) {
            SOCKADDR_IN localAddr = {0};
            localAddr.sin_family = AF_INET;
            IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskBind(hSocket, (PSOCKADDR)&localAddr, 0, Irp);
            if (status == STATUS_PENDING) {
                UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                status = Irp->IoStatus.Status;
            }

            if (NT_SUCCESS(status)) {
                SOCKADDR_IN remoteAddr = {0};
                remoteAddr.sin_family = AF_INET;
                remoteAddr.sin_addr.s_addr = targetIp;
                remoteAddr.sin_port = RtlUshortByteSwap(plainPort);

                IoReuseIrp(Irp, STATUS_SUCCESS);
                IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
                status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)hSocket->Dispatch)->WskConnect(hSocket, (PSOCKADDR)&remoteAddr, 0, Irp);
                if (status == STATUS_PENDING) {
                    LARGE_INTEGER timeout;
                    timeout.QuadPart = -10000LL * 3000;
                    NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, &timeout);
                    if (waitStatus == STATUS_TIMEOUT) {
                        IoCancelIrp(Irp);
                        UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
                        status = STATUS_TIMEOUT;
                    } else {
                        status = Irp->IoStatus.Status;
                    }
                }

                if (NT_SUCCESS(status)) {
                    WskSyncSend(UserVar, hSocket, Irp, &SyncEvent, httpReq, reqLen);
                }
            }

            IoReuseIrp(Irp, STATUS_SUCCESS);
            IoSetCompletionRoutine(Irp, SyncCompletion, &SyncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)hSocket->Dispatch)->WskCloseSocket(hSocket, Irp);
            UserVar->Func.KeWaitForSingleObject(&SyncEvent, Executive, KernelMode, FALSE, NULL);
        }
    }

    UserVar->Func.IoFreeIrp(Irp);
    UserVar->Func.WskReleaseProviderNPI(&WskRegistration);
    UserVar->Func.WskDeregister(&WskRegistration);
}

VOID AsyncWorkRoutine(IN PVOID Parameter)
{
    PDRV_EXCEPTION_REPORT_ITEM pItem = (PDRV_EXCEPTION_REPORT_ITEM)Parameter;
    if (!pItem) return;

    __try {
        PerformHttp(pItem);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG("[-] AsyncWorkRoutine: Exception 0x%08X in report worker", GetExceptionCode());
    }

    if (pItem->UserVar && pItem->UserVar->Func.ExFreePoolWithTag) {
        pItem->UserVar->Func.ExFreePoolWithTag(pItem, MK_POOL_TAG);
    }
}

} // namespace

// ============================================================
// ExceptionReporter 类成员函数实现
// ============================================================
void ExceptionReporter::SetApiUrl(const char *url)
{
    if (url) strncpy_s(s_ApiUrl, url, _TRUNCATE);
    else s_ApiUrl[0] = '\0';
}

void ExceptionReporter::SetBrandVersion(const char *brand)
{
    if (brand) strncpy_s(s_BrandVersion, brand, _TRUNCATE);
    else s_BrandVersion[0] = '\0';
}

void ExceptionReporter::SetSelectedGame(const char *game)
{
    if (game) strncpy_s(s_SelectedGame, game, _TRUNCATE);
    else s_SelectedGame[0] = '\0';
}

void ExceptionReporter::SetClientVersion(const char *version)
{
    if (version) strncpy_s(s_ClientVersion, version, _TRUNCATE);
    else s_ClientVersion[0] = '\0';
}

void ExceptionReporter::SetUserVar(MACHENIKE_KERNEL_INTERFACE *userVar)
{
    s_pUserVar = userVar;
}


void ExceptionReporter::Report(const char *functionName, NTSTATUS status, const char *extraMsg)
{
    if (s_ApiUrl[0] == '\0') return;

    MACHENIKE_KERNEL_INTERFACE *UserVar = s_pUserVar;
    if (!UserVar || !UserVar->Func.ExAllocatePoolWithTag) return;

    PDRV_EXCEPTION_REPORT_ITEM pItem = (PDRV_EXCEPTION_REPORT_ITEM)UserVar->Func.ExAllocatePoolWithTag(
        NonPagedPool, sizeof(DRV_EXCEPTION_REPORT_ITEM), MK_POOL_TAG);
    if (!pItem) return;

    UserVar->Func.RtlZeroMemory(pItem, sizeof(DRV_EXCEPTION_REPORT_ITEM));
    pItem->UserVar = UserVar;
    pItem->StatusCode = status;
    strncpy_s(pItem->ApiUrl, s_ApiUrl, _TRUNCATE);
    if (functionName) strncpy_s(pItem->FunctionName, functionName, _TRUNCATE);
    if (extraMsg) strncpy_s(pItem->ExtraMsg, extraMsg, _TRUNCATE);

    ExInitializeWorkItem(&pItem->WorkItem, AsyncWorkRoutine, pItem);
    ExQueueWorkItem(&pItem->WorkItem, DelayedWorkQueue);
}

void ExceptionReporter::ReportFormat(const char *functionName, NTSTATUS status, const char *format, ...)
{
    if (!format) {
        Report(functionName, status, nullptr);
        return;
    }

    CHAR buffer[128] = {0};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);

    Report(functionName, status, buffer);
}
