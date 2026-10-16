#pragma once

#ifdef __cplusplus
extern "C" {
#endif

extern ULONG Utils_HashStringImulMagicExA(IN const PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
extern ULONG Utils_HashStringImulMagicExW(IN const PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);
extern BOOLEAN Utils_HexCharToNibble(IN WCHAR c, OUT UCHAR *n);
extern NTSTATUS Utils_ParseTokenFromFileName(IN PUNICODE_STRING FileName, OUT ULONG *outToken);
extern NTSTATUS Utils_ParseCreatePayloadFromFileName(IN PUNICODE_STRING FileName, OUT struct _DRV_BOOT_CONFIG_EX *outConfig);
extern UINT64 Utils_SipHash24(const UCHAR key[16], const UCHAR *data, SIZE_T len);
extern BOOLEAN Utils_GetModuleExport(IN ULONG_PTR BaseAddress, IN ULONG U32FunctionName,
                                     OUT ULONG_PTR *FunctionAddress);

#ifdef __cplusplus
}
#endif
