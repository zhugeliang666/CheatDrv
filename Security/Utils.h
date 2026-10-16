#pragma once

#ifdef __cplusplus
extern "C" {
#endif

extern ULONG Utils_HashStringImulMagicExA(IN const PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
extern ULONG Utils_HashStringImulMagicExW(IN const PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
extern BOOLEAN Utils_HexCharToNibble(IN WCHAR c, OUT UCHAR *n);
extern BOOLEAN Utils_GetModuleExport(IN ULONG_PTR BaseAddress, IN ULONG U32FunctionName,
                                     OUT ULONG_PTR *FunctionAddress);

#ifdef __cplusplus
}
#endif
