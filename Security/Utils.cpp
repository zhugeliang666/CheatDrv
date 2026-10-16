#include "Common.h"
#include "Utils.h"

BOOLEAN Utils_HexCharToNibble(IN WCHAR c, OUT UCHAR *n)
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

SIZE_T Utils_Strlen(_In_ PCSTR Str)
{
    if (!Str)
        return 0;
    PCSTR p = Str;
    SIZE_T maxLen = 256;
    while (*p && maxLen--)
    {
        ++p;
    }
    return (SIZE_T)(p - Str);
}

BOOLEAN Utils_GetModuleExport(IN ULONG_PTR BaseAddress, IN ULONG U32FunctionName, OUT ULONG_PTR *FunctionAddress)
{
    PIMAGE_DOS_HEADER pDosHdr = NULL;
    PIMAGE_NT_HEADERS pNtHdr = NULL;
    pDosHdr = (PIMAGE_DOS_HEADER)BaseAddress;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }
    pNtHdr = (PIMAGE_NT_HEADERS)(BaseAddress + pDosHdr->e_lfanew);
    if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }
    if (pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return FALSE;
    }
    IMAGE_DATA_DIRECTORY exportDir = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size)
    {
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(BaseAddress + exportDir.VirtualAddress);
        PULONG AddressOfNames = (PULONG)(pExport->AddressOfNames + BaseAddress);
        PULONG AddressOfFunctions = (PULONG)(pExport->AddressOfFunctions + BaseAddress);
        PUSHORT AddressOfNameOrdinals = (PUSHORT)(pExport->AddressOfNameOrdinals + BaseAddress);
        for (ULONG i = 0; i < pExport->NumberOfNames; i++)
        {
            if (!AddressOfNames[i])
                continue;
            CHAR *cpFunctionName = (CHAR *)(BaseAddress + AddressOfNames[i]);
            SIZE_T NameSize = Utils_Strlen(cpFunctionName);
            if (NameSize == 0 || NameSize > 256)
                continue;

            ULONG uHash = Utils_HashStringImulMagicExA(cpFunctionName, NameSize, true);
            if (uHash == U32FunctionName)
            {
                USHORT ordinal = AddressOfNameOrdinals[i];
                if (ordinal < pExport->NumberOfFunctions)
                {
                    *FunctionAddress = ((ULONG_PTR)BaseAddress + AddressOfFunctions[ordinal]);
                    return TRUE;
                }
            }

            // 特殊兜底保障：当目标哈希为 KeQueryPerformanceCounter (0x7D929F9A) 时，若字符串直接匹配则命中
            if (U32FunctionName == 0x7D929F9A && NameSize == 25)
            {
                // 逐字符不区分大小写比较 "KeQueryPerformanceCounter"
                static const char szKqpc[] = "kequeryperformancecounter";
                BOOLEAN bMatch = TRUE;
                for (SIZE_T k = 0; k < 25; k++)
                {
                    char c = cpFunctionName[k];
                    if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
                    if (c != szKqpc[k]) { bMatch = FALSE; break; }
                }
                if (bMatch)
                {
                    USHORT ordinal = AddressOfNameOrdinals[i];
                    if (ordinal < pExport->NumberOfFunctions)
                    {
                        *FunctionAddress = ((ULONG_PTR)BaseAddress + AddressOfFunctions[ordinal]);
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}

ULONG Utils_HashStringImulMagicExA(IN CONST PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase)
{
    ULONG Result = 0;
    if (s && Length)
    {
        if (Length > 2048)
        {
            Length = 2048;
        }
        for (SIZE_T i = 0; i < Length; i++)
        {
            CHAR c = s[i];
            if (c == '\0')
            {
                break;
            }
            Result *= 0x1003f;
            if (bIgnoreCase && c >= 'A' && c <= 'Z')
            {
                Result += 'a' + c - 'A';
            }
            else
            {
                Result += c;
            }
        }
    }
    return Result;
}

ULONG Utils_HashStringImulMagicExW(IN CONST PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase)
{
    ULONG Result = 0;
    if (s && Length)
    {
        if (Length > 2048)
        {
            Length = 2048;
        }

        for (SIZE_T i = 0; i < Length; i++)
        {
            WCHAR c = s[i];
            if (c == L'\0')
            {
                break;
            }
            Result *= 0x1003f;
            if (bIgnoreCase && c >= L'A' && c <= L'Z')
            {
                Result += L'a' + c - L'A';
            }
            else
            {
                Result += c;
            }
        }
    }
    return Result;
}

