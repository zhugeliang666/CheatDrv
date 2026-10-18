#include "Common.h"
#include "Utils.h"

// ============================================================
// 密码学与哈希安全算法原语 (独立编译单元，专享重度 LLVM 混淆)
// 包含: SipHash24, CalcAdler32, Rc4Encrypt, Rc4Decrypt
// ============================================================

UINT64 Utils::SipHash24(IN const UCHAR key[16], IN const UCHAR *data, IN SIZE_T len)
{
    UINT64 k0 = *(const UINT64 *)(key);
    UINT64 k1 = *(const UINT64 *)(key + 8);
    UINT64 v0 = k0 ^ 0x736f6d6570736575ULL;
    UINT64 v1 = k1 ^ 0x646f72616e646f6dULL;
    UINT64 v2 = k0 ^ 0x6c7967656e657261ULL;
    UINT64 v3 = k1 ^ 0x7465646279746573ULL;

    SIZE_T nblocks = len / 8;
    for (SIZE_T i = 0; i < nblocks; i++)
    {
        UINT64 m = *(const UINT64 *)(data + i * 8);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }

    const UCHAR *end = data + nblocks * 8;
    UINT64 b = ((UINT64)len) << 56;
    SIZE_T left = len & 7;
    for (SIZE_T j = left - 1; j < left; j--)
    {
        b |= ((UINT64)end[j]) << (j * 8);
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

ULONG Utils::CalcAdler32(IN const UCHAR *data, IN SIZE_T len)
{
    if (!data || len == 0)
        return 1;
    ULONG a = 1, b = 0;
    for (SIZE_T i = 0; i < len; i++)
    {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

void Utils::Rc4Encrypt(IN OUT UCHAR *data, IN ULONG len, IN const UCHAR *key, IN ULONG keyLen)
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

void Utils::Rc4Decrypt(IN OUT UCHAR *data, IN ULONG len, IN const UCHAR *key, IN ULONG keyLen)
{
    Rc4Encrypt(data, len, key, keyLen);
}

extern "C"
{
    UINT64 Utils_SipHash24(IN const UCHAR key[16], IN const UCHAR *data, IN SIZE_T len)
    {
        return Utils::SipHash24(key, data, len);
    }
    ULONG Utils_CalcAdler32(IN const UCHAR *data, IN SIZE_T len)
    {
        return Utils::CalcAdler32(data, len);
    }
    void Utils_Rc4Encrypt(IN OUT UCHAR *data, IN ULONG len, IN const UCHAR *key, IN ULONG keyLen)
    {
        Utils::Rc4Encrypt(data, len, key, keyLen);
    }
    void Utils_Rc4Decrypt(IN OUT UCHAR *data, IN ULONG len, IN const UCHAR *key, IN ULONG keyLen)
    {
        Utils::Rc4Decrypt(data, len, key, keyLen);
    }
}
