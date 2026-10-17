#pragma once
#include <ntdef.h>

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

    ULONG Utils_HashStringImulMagicExA(IN const PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
    ULONG Utils_HashStringImulMagicExW(IN const PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
    BOOLEAN Utils_HexCharToNibble(IN WCHAR c, OUT UCHAR *n);
    BOOLEAN Utils_GetModuleExport(IN ULONG_PTR BaseAddress, IN ULONG U32FunctionName, OUT ULONG_PTR *FunctionAddress);

#ifdef __cplusplus
}
#endif
