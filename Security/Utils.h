#pragma once
#include <ntdef.h>

#ifndef ROTL64
static __forceinline UINT64 ROTL64(UINT64 x, int b) { return (x << b) | (x >> (64 - b)); }
#endif

#ifndef SIPROUND
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
#endif


#ifdef __cplusplus
// ============================================================
// Utils: 驱动内核基础工具类 (纯静态类：哈希计算、导出表解析、字符转换)
// ============================================================
class Utils
{
  public:
    static ULONG HashStringA(IN const PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
    static ULONG HashStringW(IN const PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
    static BOOLEAN HexCharToNibble(IN WCHAR c, OUT UCHAR *n);
    static BOOLEAN GetModuleExport(IN ULONG_PTR BaseAddress, IN ULONG U32FunctionName, OUT ULONG_PTR *FunctionAddress);
    static BOOLEAN GetModuleTextSection(IN ULONG_PTR BaseAddress, OUT ULONG_PTR *TextBase, OUT ULONG_PTR *TextEnd);
    static BOOLEAN IsValidKernelRange(IN const void *ptr, IN SIZE_T size);
    static ULONG_PTR DecodeInlineHookTarget(IN ULONG_PTR fnAddr, OUT BOOLEAN *pbBreakTrapOut = NULL);

    static UINT64 SipHash24(IN const UCHAR key[16], IN const UCHAR *data, IN SIZE_T len);
    static ULONG CalcAdler32(IN const UCHAR *data, IN SIZE_T len);
    static void Rc4Encrypt(IN OUT UCHAR *data, IN ULONG len, IN const UCHAR *key, IN ULONG keyLen);
    static void Rc4Decrypt(IN OUT UCHAR *data, IN ULONG len, IN const UCHAR *key, IN ULONG keyLen);

    static FORCEINLINE ULONG HashStringImulMagicExA(IN const PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase)
    {
        return HashStringA(s, Length, bIgnoreCase);
    }
    static FORCEINLINE ULONG HashStringImulMagicExW(IN const PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase)
    {
        return HashStringW(s, Length, bIgnoreCase);
    }
};

extern "C"
{
#endif

    UINT64 Utils_SipHash24(IN const UCHAR key[16], IN const UCHAR *data, IN SIZE_T len);
    ULONG Utils_CalcAdler32(IN const UCHAR *data, IN SIZE_T len);
    void Utils_Rc4Encrypt(IN OUT UCHAR *data, IN ULONG len, IN const UCHAR *key, IN ULONG keyLen);
    void Utils_Rc4Decrypt(IN OUT UCHAR *data, IN ULONG len, IN const UCHAR *key, IN ULONG keyLen);


    ULONG Utils_HashStringImulMagicExA(IN const PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
    ULONG Utils_HashStringImulMagicExW(IN const PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
    BOOLEAN Utils_HexCharToNibble(IN WCHAR c, OUT UCHAR *n);
    BOOLEAN Utils_GetModuleExport(IN ULONG_PTR BaseAddress, IN ULONG U32FunctionName, OUT ULONG_PTR *FunctionAddress);

#ifdef __cplusplus
}
#endif
