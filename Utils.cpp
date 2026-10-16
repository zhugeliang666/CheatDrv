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

NTSTATUS Utils_ParseTokenFromFileName(IN PUNICODE_STRING FileName, OUT ULONG *outToken)
{
    if (!FileName || FileName->Length < (9 * sizeof(WCHAR)) || !FileName->Buffer || FileName->Buffer[0] != L'\\')
        return STATUS_INVALID_PARAMETER;

    // 若长度大于 9 个字符，第 9 个字符必须为合法分隔符 ('_' 或 '\\')
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
        if (!Utils_HexCharToNibble(FileName->Buffer[1 + i], &nib))
            return STATUS_INVALID_PARAMETER;
        v = (v << 4) | nib;
    }
    *outToken = v;
    return STATUS_SUCCESS;
}

NTSTATUS Utils_ParseCreatePayloadFromFileName(IN PUNICODE_STRING FileName, OUT PDRV_BOOT_CONFIG_EX outConfig)
{
    if (!FileName || !outConfig || !FileName->Buffer)
        return STATUS_INVALID_PARAMETER;

    USHORT cchTotal = FileName->Length / sizeof(WCHAR);
    if (cchTotal <= 1 || FileName->Buffer[0] != L'\\')
        return STATUS_NOT_FOUND;

    USHORT hexStart = 0;
    USHORT cchHex = 0;

    // 格式 A (带 Token 的复合路径): \01234567_<HexPayload> 或 \01234567\<HexPayload>
    if (cchTotal > 10 && (FileName->Buffer[9] == L'_' || FileName->Buffer[9] == L'\\'))
    {
        hexStart = 10;
        cchHex = cchTotal - 10;
    }
    // 格式 B (纯 HexPayload 路径，不带 Token): \<HexPayload>
    else
    {
        hexStart = 1;
        cchHex = cchTotal - 1;
    }

    if ((cchHex % 2) != 0)
        return STATUS_INVALID_PARAMETER;

    USHORT binLen = cchHex / 2;
    if (binLen < sizeof(DRV_CREATE_PARAM_HEADER) || binLen > 512)
        return STATUS_INVALID_BUFFER_SIZE;

    UCHAR binBuf[512] = {0};
    const WCHAR *pHex = &FileName->Buffer[hexStart];
    for (USHORT i = 0; i < binLen; i++)
    {
        UCHAR hi = 0, lo = 0;
        if (!Utils_HexCharToNibble(pHex[i * 2], &hi) || !Utils_HexCharToNibble(pHex[i * 2 + 1], &lo))
            return STATUS_INVALID_PARAMETER;
        binBuf[i] = (hi << 4) | lo;
    }

    PDRV_CREATE_PARAM_HEADER pHdr = (PDRV_CREATE_PARAM_HEADER)binBuf;
    if (pHdr->Magic != DRV_BOOT_CONFIG_MAGIC)
        return STATUS_INVALID_PARAMETER;

    USHORT expectedMinLen = (USHORT)(sizeof(DRV_CREATE_PARAM_HEADER) +
                                    (USHORT)pHdr->ApiUrlLen +
                                    (USHORT)pHdr->LoginUrlLen +
                                    (USHORT)pHdr->ReportUrlLen +
                                    ((USHORT)pHdr->HostLoaderPathLen * sizeof(WCHAR)));

    if (binLen < expectedMinLen)
        return STATUS_BUFFER_TOO_SMALL;

    RtlZeroMemory(outConfig, sizeof(DRV_BOOT_CONFIG_EX));
    outConfig->Base.Magic = pHdr->Magic;
    outConfig->Base.TransportMode = pHdr->TransportMode;
    outConfig->Base.Port = pHdr->Port;
    RtlCopyMemory(outConfig->Base.SessionToken, pHdr->SessionToken, sizeof(outConfig->Base.SessionToken));

    USHORT offset = sizeof(DRV_CREATE_PARAM_HEADER);

    if (pHdr->ApiUrlLen > 0)
    {
        USHORT copyLen = (pHdr->ApiUrlLen < (sizeof(outConfig->ApiUrl) - 1)) ? (USHORT)pHdr->ApiUrlLen : (USHORT)(sizeof(outConfig->ApiUrl) - 1);
        RtlCopyMemory(outConfig->ApiUrl, &binBuf[offset], copyLen);
        outConfig->ApiUrl[copyLen] = '\0';
        offset += pHdr->ApiUrlLen;
    }

    if (pHdr->LoginUrlLen > 0)
    {
        USHORT copyLen = (pHdr->LoginUrlLen < (sizeof(outConfig->LoginUrl) - 1)) ? (USHORT)pHdr->LoginUrlLen : (USHORT)(sizeof(outConfig->LoginUrl) - 1);
        RtlCopyMemory(outConfig->LoginUrl, &binBuf[offset], copyLen);
        outConfig->LoginUrl[copyLen] = '\0';
        offset += pHdr->LoginUrlLen;
    }

    if (pHdr->ReportUrlLen > 0)
    {
        USHORT copyLen = (pHdr->ReportUrlLen < (sizeof(outConfig->ReportUrl) - 1)) ? (USHORT)pHdr->ReportUrlLen : (USHORT)(sizeof(outConfig->ReportUrl) - 1);
        RtlCopyMemory(outConfig->ReportUrl, &binBuf[offset], copyLen);
        outConfig->ReportUrl[copyLen] = '\0';
        offset += pHdr->ReportUrlLen;
    }

    if (pHdr->HostLoaderPathLen > 0)
    {
        USHORT copyChars = (pHdr->HostLoaderPathLen < (260 - 1)) ? pHdr->HostLoaderPathLen : (260 - 1);
        RtlCopyMemory(outConfig->HostLoaderPath, &binBuf[offset], copyChars * sizeof(WCHAR));
        outConfig->HostLoaderPath[copyChars] = L'\0';
    }

    return STATUS_SUCCESS;
}


static __forceinline UINT64 ROTL64(UINT64 x, int b)
{
    return (x << b) | (x >> (64 - b));
}

#define SIPROUND                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        v0 += v1;                                                                                                      \
        v1 = ROTL64(v1, 13);                                                                                           \
        v1 ^= v0;                                                                                                      \
        v0 = ROTL64(v0, 32);                                                                                           \
        v2 += v3;                                                                                                      \
        v3 = ROTL64(v3, 16);                                                                                           \
        v3 ^= v2;                                                                                                      \
        v0 += v3;                                                                                                      \
        v3 = ROTL64(v3, 21);                                                                                           \
        v3 ^= v0;                                                                                                      \
        v2 += v1;                                                                                                      \
        v1 = ROTL64(v1, 17);                                                                                           \
        v1 ^= v2;                                                                                                      \
        v2 = ROTL64(v2, 32);                                                                                           \
    } while (0)

UINT64 Utils_SipHash24(const UCHAR key[16], const UCHAR *data, SIZE_T len)
{
    UINT64 k0 = *(const UINT64 *)(key);
    UINT64 k1 = *(const UINT64 *)(key + 8);
    UINT64 v0 = 0x736f6d6570736575ULL ^ k0;
    UINT64 v1 = 0x646f72616e646f6dULL ^ k1;
    UINT64 v2 = 0x6c7967656e657261ULL ^ k0;
    UINT64 v3 = 0x7465646279746573ULL ^ k1;
    const UCHAR *end = data + (len & ~((SIZE_T)7));
    UINT64 m = 0;
    for (; data != end; data += 8)
    {
        m = *(const UINT64 *)(data);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }

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
