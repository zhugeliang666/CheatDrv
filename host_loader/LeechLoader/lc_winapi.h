// lc_winapi.h : customized dynamic Win32 API resolver for LeechLoader
// Based on leechcore dynamic Win32 API resolver design
//
#ifndef __LC_WINAPI_H__
#define __LC_WINAPI_H__

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif /* WIN32_LEAN_AND_MEAN */

#if !defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
#include <winsock2.h>
#endif
#ifdef _WINSOCK2API_
#include <ws2tcpip.h>
#endif
#include <Windows.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <psapi.h>
#include <rpc.h>
#include <setupapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <ws2spi.h>
#include <sporder.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <winsvc.h>
#include <winternl.h>
#include <winusb.h>

#define SECURITY_WIN32
#include <bcrypt.h>
#include <intrin.h>
#include <security.h>


#ifndef WSAAPI
#define WSAAPI WINAPI
#endif /* WSAAPI */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif /* NT_SUCCESS */

    typedef NTSTATUS(NTAPI *PLC_WINAPI_LdrLoadDll)(_In_opt_ PWSTR, _In_opt_ PULONG, _In_ PUNICODE_STRING, _Out_ PHANDLE);
    typedef NTSTATUS(NTAPI *PLC_WINAPI_LdrUnloadDll)(_In_ PVOID);

    static __forceinline PPEB LcWinApi_Peb()
    {
#if defined(_M_X64) || defined(_M_AMD64) || defined(__x86_64__)
        return (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86) || defined(__i386__)
    return (PPEB)(ULONG_PTR)__readfsdword(0x30);
#elif defined(_M_ARM64)
    return *(PPEB *)((PBYTE)__getReg(18) + 0x60);
#else
    return NtCurrentTeb()->ProcessEnvironmentBlock;
#endif
    }



    static __forceinline WCHAR LcWinApi_WideLower(_In_ WCHAR ch)
    {
        return (ch >= L'A' && ch <= L'Z') ? (ch + (L'a' - L'A')) : ch;
    }


    static __forceinline SIZE_T LcWinApi_StrLenW(_In_opt_ LPCWSTR wsz)
    {
        SIZE_T cch = 0;
        if (!wsz)
        {
            return 0;
        }
        while (wsz[cch])
        {
            cch++;
        }
        return cch;
    }

    static __forceinline BOOL LcWinApi_StrEqualsA(_In_ LPCSTR sz1, _In_ LPCSTR sz2)
    {
        SIZE_T i = 0;
        if (!sz1 || !sz2)
        {
            return FALSE;
        }
        while (sz1[i] && sz2[i])
        {
            if (sz1[i] != sz2[i])
            {
                return FALSE;
            }
            i++;
        }
        return sz1[i] == sz2[i];
    }

    static __forceinline BOOL LcWinApi_WideEqualsI(_In_reads_(cch1) LPCWSTR wsz1, _In_ SIZE_T cch1, _In_reads_(cch2) LPCWSTR wsz2, _In_ SIZE_T cch2)
    {
        SIZE_T i;
        if (cch1 != cch2)
        {
            return FALSE;
        }
        for (i = 0; i < cch1; i++)
        {
            if (LcWinApi_WideLower(wsz1[i]) != LcWinApi_WideLower(wsz2[i]))
            {
                return FALSE;
            }
        }
        return TRUE;
    }

    static BOOL LcWinApi_ModuleNameEquals(_In_ PUNICODE_STRING pusBaseName, _In_ LPCWSTR wszModuleName)
    {
        SIZE_T cchBuffer, cchBase, cchName, i;
        LPCWSTR wszBase;
        BOOL fNameHasDot = FALSE;
        if (!pusBaseName || !pusBaseName->Buffer || !wszModuleName)
        {
            return FALSE;
        }
        cchBuffer = pusBaseName->Length / sizeof(WCHAR);
        wszBase = pusBaseName->Buffer;
        cchBase = cchBuffer;
        for (i = 0; i < cchBuffer; i++)
        {
            if (pusBaseName->Buffer[i] == L'\\' || pusBaseName->Buffer[i] == L'/')
            {
                wszBase = pusBaseName->Buffer + i + 1;
                cchBase = cchBuffer - i - 1;
            }
        }
        cchName = LcWinApi_StrLenW(wszModuleName);
        if (LcWinApi_WideEqualsI(wszBase, cchBase, wszModuleName, cchName))
        {
            return TRUE;
        }
        for (i = 0; i < cchName; i++)
        {
            if (wszModuleName[i] == L'.')
            {
                fNameHasDot = TRUE;
                break;
            }
        }
        return !fNameHasDot && (cchBase == cchName + 4) && LcWinApi_WideEqualsI(wszBase, cchName, wszModuleName, cchName) && (LcWinApi_WideLower(wszBase[cchName + 0]) == L'.') &&
               (LcWinApi_WideLower(wszBase[cchName + 1]) == L'd') && (LcWinApi_WideLower(wszBase[cchName + 2]) == L'l') && (LcWinApi_WideLower(wszBase[cchName + 3]) == L'l');
    }

    static __forceinline DWORD LcWinApi_HashA(_In_opt_ LPCSTR szStr)
    {
        DWORD dwHash = 0x811C9DC5;
        if (!szStr)
            return 0;
        while (*szStr)
        {
            dwHash ^= (DWORD)(BYTE)*szStr++;
            dwHash *= 0x01000193;
        }
        return dwHash;
    }

    static __forceinline DWORD LcWinApi_HashW_CaseInsensitive(_In_ PUNICODE_STRING pusBaseName)
    {
        DWORD dwHash = 0x811C9DC5;
        SIZE_T cchBuffer, cchBase, i;
        LPCWSTR wszBase;
        if (!pusBaseName || !pusBaseName->Buffer)
            return 0;
        cchBuffer = pusBaseName->Length / sizeof(WCHAR);
        wszBase = pusBaseName->Buffer;
        cchBase = cchBuffer;
        for (i = 0; i < cchBuffer; i++)
        {
            if (pusBaseName->Buffer[i] == L'\\' || pusBaseName->Buffer[i] == L'/')
            {
                wszBase = pusBaseName->Buffer + i + 1;
                cchBase = cchBuffer - i - 1;
            }
        }
        for (i = 0; i < cchBase; i++)
        {
            WCHAR ch = LcWinApi_WideLower(wszBase[i]);
            dwHash ^= (DWORD)(BYTE)ch;
            dwHash *= 0x01000193;
            dwHash ^= (DWORD)(BYTE)(ch >> 8);
            dwHash *= 0x01000193;
        }
        return dwHash;
    }

    static HMODULE LcWinApi_GetModuleBaseByHash(_In_ DWORD dwModuleHash)
    {
        PPEB pPeb = LcWinApi_Peb();
        PPEB_LDR_DATA pLdr;
        PLIST_ENTRY pHead, pEntry;
        PLDR_DATA_TABLE_ENTRY pDataTableEntry;
        if (!pPeb)
        {
            return NULL;
        }
        pLdr = pPeb->Ldr;
        if (!pLdr)
        {
            return NULL;
        }
        pHead = &pLdr->InMemoryOrderModuleList;
        for (pEntry = pHead->Flink; pEntry && pEntry != pHead; pEntry = pEntry->Flink)
        {
            pDataTableEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (LcWinApi_HashW_CaseInsensitive(&pDataTableEntry->FullDllName) == dwModuleHash)
            {
                return (HMODULE)pDataTableEntry->DllBase;
            }
        }
        return NULL;
    }

// ---------------------------------------------------------------------------
// Pre-calculated FNV-1a Hashes for DLL Modules (Unicode Lowercase)
// ---------------------------------------------------------------------------
#define HASH_DLL_KERNEL32_DLL 0xC705800D
#define HASH_DLL_ADVAPI32_DLL 0x10258865
#define HASH_DLL_WS2_32_DLL 0x33BB3FA7
#define HASH_DLL_IPHLPAPI_DLL 0xDA63B8EA
#define HASH_DLL_SHELL32_DLL 0x9EFE1188
#define HASH_DLL_SETUPAPI_DLL 0x83886CB0
#define HASH_DLL_WINUSB_DLL 0xFC2F59EB
#define HASH_DLL_NTDLL_DLL 0x1CDE56F9
#define HASH_DLL_OLE32_DLL 0xFA37B760

// ---------------------------------------------------------------------------
// Pre-calculated FNV-1a Hashes for APIs (ASCII)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Full FNV-1a Hashes for API names - auto-generated
// ---------------------------------------------------------------------------
#define HASH_API_VirtualAlloc 0x03285501
#define HASH_API_VirtualFree 0x3A9ACC72
#define HASH_API_VirtualLock 0xD72B4ED3
#define HASH_API_VirtualUnlock 0x02A7E818
#define HASH_API_DeviceIoControl 0xB04CCE94
#define HASH_API_CreateProcessA 0x4A7C0A09
#define HASH_API_GetCurrentThread 0x9BC5A608
#define HASH_API_SetThreadAffinityMask 0x22B0E88F
#define HASH_API_GetProcessAffinityMask 0x166069F0
#define HASH_API_K32EnumDeviceDrivers 0xBC25FCCB
#define HASH_API_K32GetDeviceDriverBaseNameA 0x3CEDBC12
#define HASH_API_ChangeServiceConfigW 0x03590407
#define HASH_API_QueryServiceStatusEx 0x498CB79D

#define HASH_API_CloseHandle 0xFABA0065
#define HASH_API_CloseServiceHandle 0x2E47FE60
#define HASH_API_ControlService 0xC13850B5
#define HASH_API_CreateFileA 0xBDCAC9CE
#define HASH_API_CreateFileW 0xAFCAB3C4
#define HASH_API_CreateProcessW 0x3C7BF3FF
#define HASH_API_DeleteService 0x71C7BD51
#define HASH_API_GetAdaptersAddresses 0x8DBF5199
#define HASH_API_GetCurrentProcess 0x6DD8A845
#define HASH_API_GetCurrentProcessId 0x020A0780
#define HASH_API_GetLastError 0x5056DF37
#define HASH_API_GetModuleFileNameW 0xA3FBD5FB
#define HASH_API_GetModuleHandleW 0xD263BDE6
#define HASH_API_GetSystemDirectoryW 0xFC1273FE
#define HASH_API_GetTokenInformation 0x035F513A
#define HASH_API_LocalAlloc 0xC2C33C3D
#define HASH_API_LocalFree 0xBF0306F6
#define HASH_API_MultiByteToWideChar 0x9053F9C2
#define HASH_API_OpenProcessToken 0x5E5AD0C3
#define HASH_API_OpenSCManagerW 0xAB8189AB
#define HASH_API_OpenServiceW 0x67FF005D
#define HASH_API_OutputDebugStringW 0xCFF6B8A3
#define HASH_API_QueryServiceStatus 0x39F78448
#define HASH_API_RegCloseKey 0x1242154A
#define HASH_API_RegQueryValueExW 0x7E27CF26
#define HASH_API_SetConsoleCP 0x1CBBCDA3
#define HASH_API_SetConsoleOutputCP 0xCA500576
#define HASH_API_SetLastError 0x21DDCD8B
#define HASH_API_SetupDiDestroyDeviceInfoList 0x40C103C7
#define HASH_API_SetupDiEnumDeviceInfo 0xEA2D545A
#define HASH_API_SetupDiEnumDeviceInterfaces 0x646A639E
#define HASH_API_SetupDiGetClassDevsW 0xC0CA5052
#define HASH_API_SetupDiGetDeviceInterfaceDetailW 0x95A81972
#define HASH_API_SetupDiGetDeviceRegistryPropertyW 0xA0AD6864
#define HASH_API_SetupDiOpenDevRegKey 0xAB935339
#define HASH_API_ShellExecuteExW 0xB289D372
#define HASH_API_Sleep 0x2FA62CA8
#define HASH_API_TerminateProcess 0xF84EEE59
#define HASH_API_WSACleanup 0x8BD299C2
#define HASH_API_WSAGetLastError 0xDFBDD85C
#define HASH_API_WSAStartup 0x20125C5F
#define HASH_API_WideCharToMultiByte 0xE682DD7E
#define HASH_API_WinUsb_Free 0xEDEFDF5C
#define HASH_API_WinUsb_Initialize 0x0640B514
#define HASH_API_WinUsb_QueryInterfaceSettings 0xB8E2F9E4
#define HASH_API_WinUsb_QueryPipe 0xF1E0E206
#define HASH_API_accept 0x08247E29
#define HASH_API_bind 0xC7535F2E
#define HASH_API_closesocket 0x06834302
#define HASH_API_connect 0xAAE0CCF9
#define HASH_API_getsockopt 0xDD58403C
#define HASH_API_htonl 0xA2FDB778
#define HASH_API_htons 0xB1FDCF15
#define HASH_API_inet_addr 0xCC4CBCF3
#define HASH_API_inet_ntop 0xDFB6021D
#define HASH_API_listen 0x3B3B76A6
#define HASH_API_ntohl 0x9B4BE08C
#define HASH_API_ntohs 0xB24C04C1
#define HASH_API_recv 0xECE4502D
#define HASH_API_recvfrom 0x885F273D
#define HASH_API_select 0x11C2662D
#define HASH_API_send 0x7261C8AF
#define HASH_API_sendto 0x8489A1EA
#define HASH_API_setsockopt 0x364407C8
#define HASH_API_socket 0x9012766C

#define HASH_API_AdjustTokenPrivileges 0x5B11AD63
#define HASH_API_CreateServiceW 0xECF2A951
#define HASH_API_LookupPrivilegeValueA 0xF0ABBE5E
#define HASH_API_StartServiceW 0xD51FD8CF
#define HASH_API_ioctlsocket 0x8043A91F

#define HASH_API_AcquireSRWLockExclusive 0xDA2F90E4
#define HASH_API_AreFileApisANSI 0x562373D5
#define HASH_API_CLSIDFromString 0x99707DBB
#define HASH_API_CompareStringW 0x859A9166
#define HASH_API_CreateDirectoryW 0xC6C9AEF5
#define HASH_API_CreateThread 0x60AC7E39
#define HASH_API_DecodePointer 0x91125E9C
#define HASH_API_DeleteCriticalSection 0xE3735F52
#define HASH_API_EncodePointer 0x83FF1254
#define HASH_API_EnterCriticalSection 0xE91B4077
#define HASH_API_EnumSystemLocalesW 0x99CDD3E5
#define HASH_API_ExitProcess 0x0E80FD3A
#define HASH_API_ExitThread 0xE53F7A31
#define HASH_API_FindClose 0xDD35C6E6
#define HASH_API_FindFirstFileExW 0xF63A8F5C
#define HASH_API_FindFirstFileW 0xC1480CB3
#define HASH_API_FindNextFileW 0x854D363A
#define HASH_API_FlsAlloc 0xDBACFB39
#define HASH_API_FlsFree 0x9A41256A
#define HASH_API_FlsGetValue 0x24BE8561
#define HASH_API_FlsSetValue 0x93D31E35
#define HASH_API_FlushFileBuffers 0xAFD195A6
#define HASH_API_FormatMessageA 0x3F75A588
#define HASH_API_FreeEnvironmentStringsW 0xE333DDEF
#define HASH_API_FreeLibrary 0xAB45C5EE
#define HASH_API_FreeLibraryAndExitThread 0x9FAF5837
#define HASH_API_GetACP 0xB5484339
#define HASH_API_GetCPInfo 0x88E25918
#define HASH_API_GetCommandLineA 0x60007775
#define HASH_API_GetCommandLineW 0x4A0054D3
#define HASH_API_GetConsoleMode 0xC09860AF
#define HASH_API_GetConsoleOutputCP 0x5C4105E2
#define HASH_API_GetConsoleScreenBufferInfo 0x1114ACFA
#define HASH_API_GetCurrentDirectoryW 0x4CC2F954
#define HASH_API_GetCurrentThreadId 0xEBCDFE95
#define HASH_API_GetDateFormatW 0x76916491
#define HASH_API_GetEnvironmentStringsW 0x8B9FE86B
#define HASH_API_GetExitCodeProcess 0x433D448B
#define HASH_API_GetExitCodeThread 0xFF447F32
#define HASH_API_GetFileAttributesExW 0x468EBE86
#define HASH_API_GetFileInformationByHandle 0x839DA3CE
#define HASH_API_GetFileInformationByHandleEx 0xDCAE130B
#define HASH_API_GetFileSize 0x44ED8118
#define HASH_API_GetFileSizeEx 0xFDC9EFCD
#define HASH_API_GetFileType 0xCB91CF41
#define HASH_API_GetFullPathNameW 0x16E04DC7
#define HASH_API_GetLocaleInfoEx 0xDC4BA0AC
#define HASH_API_GetLocaleInfoW 0xEF47E252
#define HASH_API_GetModuleHandleExW 0xA9D0E95D
#define HASH_API_GetOEMCP 0xDE8C25C5
#define HASH_API_GetProcAddress 0xF8F45725
#define HASH_API_GetProcessHeap 0x86FE8652
#define HASH_API_GetStartupInfoW 0x65ECD249
#define HASH_API_GetStdHandle 0xE3B9876A
#define HASH_API_GetStringTypeW 0xC0F0297F
#define HASH_API_GetSystemTimeAsFileTime 0xEE9D4374
#define HASH_API_GetTimeFormatW 0x5DFF7646
#define HASH_API_GetTimeZoneInformation 0xAE064116
#define HASH_API_GetUserDefaultLCID 0x575A0CE9
#define HASH_API_HeapAlloc 0x0184ED74
#define HASH_API_HeapFree 0x29630F3D
#define HASH_API_HeapReAlloc 0x53A65E77
#define HASH_API_HeapSize 0x08497B36
#define HASH_API_InitializeCriticalSectionAndSpinCount 0xC429E295
#define HASH_API_InitializeCriticalSectionEx 0xF94AA6A8
#define HASH_API_InitializeSListHead 0xD2AFA952
#define HASH_API_IsDebuggerPresent 0x694A8C81
#define HASH_API_IsProcessorFeaturePresent 0x7AA3F32A
#define HASH_API_IsValidCodePage 0x7686D453
#define HASH_API_IsValidLocale 0x3F3284A3
#define HASH_API_LCMapStringEx 0x4A68E9E2
#define HASH_API_LCMapStringW 0x295D8758
#define HASH_API_LeaveCriticalSection 0xC70DD340
#define HASH_API_LoadLibraryExW 0x1CD12702
#define HASH_API_MoveFileExW 0xD716D510
#define HASH_API_QueryPerformanceCounter 0x27C5F681
#define HASH_API_QueryPerformanceFrequency 0xFDD349F7
#define HASH_API_RaiseException 0xC1D5565C
#define HASH_API_ReadConsoleW 0xA3F257C7
#define HASH_API_ReadFile 0x54FCC943
#define HASH_API_ReleaseSRWLockExclusive 0x5C87AA4D
#define HASH_API_RtlCaptureContext 0x542D2B40
#define HASH_API_RtlLookupFunctionEntry 0xA9C582CD
#define HASH_API_RtlPcToFileHeader 0xAE3DE392
#define HASH_API_RtlUnwind 0xDC1BE4A0
#define HASH_API_RtlUnwindEx 0xE24F4705
#define HASH_API_RtlVirtualUnwind 0xBC31FA31
#define HASH_API_SetConsoleTextAttribute 0xBC0E3315
#define HASH_API_SetEndOfFile 0x192000F7
#define HASH_API_SetEnvironmentVariableW 0xF890B659
#define HASH_API_SetFileAttributesW 0x5DC88031
#define HASH_API_SetFileInformationByHandle 0x27B00FC2
#define HASH_API_SetFilePointerEx 0xE6629347
#define HASH_API_SetStdHandle 0x5C681C6E
#define HASH_API_SetUnhandledExceptionFilter 0x0ABF23CD
#define HASH_API_SleepConditionVariableSRW 0xC89BA2BD
#define HASH_API_TlsAlloc 0x537F795B
#define HASH_API_TlsFree 0x182A6F20
#define HASH_API_TlsGetValue 0xCCD84087
#define HASH_API_TlsSetValue 0x7E0DB2F3
#define HASH_API_TryAcquireSRWLockExclusive 0xCFF2B985
#define HASH_API_UnhandledExceptionFilter 0x68166563
#define HASH_API_VirtualProtect 0x820621F3
#define HASH_API_WaitForSingleObject 0x71948CA4
#define HASH_API_WaitForSingleObjectEx 0xF8D32811
#define HASH_API_WakeAllConditionVariable 0xB10E0851
#define HASH_API_WriteConsoleW 0x40268996
#define HASH_API_WriteFile 0x7F07C44A

    static FARPROC LcWinApi_ResolveForwarder(_In_ LPCSTR szForwarder, _In_ DWORD cDepth);
    static HMODULE LcWinApi_LoadLibraryW(_In_ LPCWSTR wszModuleName);



    static HMODULE LcWinApi_GetModuleBaseW(_In_opt_ LPCWSTR wszModuleName)
    {
        PPEB pPeb = LcWinApi_Peb();
        PPEB_LDR_DATA pLdr;
        PLIST_ENTRY pHead, pEntry;
        PLDR_DATA_TABLE_ENTRY pDataTableEntry;
        if (!pPeb)
        {
            return NULL;
        }
        if (!wszModuleName)
        {
            return (HMODULE)pPeb->Reserved3[1];
        }
        pLdr = pPeb->Ldr;
        if (!pLdr)
        {
            return NULL;
        }
        pHead = &pLdr->InMemoryOrderModuleList;
        for (pEntry = pHead->Flink; pEntry && pEntry != pHead; pEntry = pEntry->Flink)
        {
            pDataTableEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (LcWinApi_ModuleNameEquals(&pDataTableEntry->FullDllName, wszModuleName))
            {
                return (HMODULE)pDataTableEntry->DllBase;
            }
        }
        return NULL;
    }

    static FARPROC LcWinApi_GetProcAddressRaw(_In_ HMODULE hModule, _In_opt_ LPCSTR szProcName, _In_ WORD wOrdinal, _In_ BOOL fOrdinal, _In_ DWORD cDepth);

    static HMODULE LcWinApi_LoadLibraryW(_In_ LPCWSTR wszModuleName)
    {
        static PLC_WINAPI_LdrLoadDll pfnLdrLoadDll = NULL;
        HMODULE hModule;
        UNICODE_STRING usModuleName;
        SIZE_T cchModuleName;
        if (!wszModuleName)
        {
            return NULL;
        }
        hModule = LcWinApi_GetModuleBaseW(wszModuleName);
        if (hModule)
        {
            return hModule;
        }
        if (!pfnLdrLoadDll)
        {
            HMODULE hNtdll = LcWinApi_GetModuleBaseW(L"ntdll.dll");
            pfnLdrLoadDll = (PLC_WINAPI_LdrLoadDll)LcWinApi_GetProcAddressRaw(hNtdll, "LdrLoadDll", 0, FALSE, 0);
        }
        if (!pfnLdrLoadDll)
        {
            return NULL;
        }
        cchModuleName = LcWinApi_StrLenW(wszModuleName);
        if (cchModuleName > 0x7fff)
        {
            return NULL;
        }
        usModuleName.Length = (USHORT)(cchModuleName * sizeof(WCHAR));
        usModuleName.MaximumLength = usModuleName.Length + sizeof(WCHAR);
        usModuleName.Buffer = (PWSTR)wszModuleName;
        hModule = NULL;
        return NT_SUCCESS(pfnLdrLoadDll(NULL, NULL, &usModuleName, (PHANDLE)&hModule)) ? hModule : NULL;
    }

    static FARPROC LcWinApi_ResolveForwarder(_In_ LPCSTR szForwarder, _In_ DWORD cDepth)
    {
        CHAR szModuleA[128];
        WCHAR wszModuleW[128];
        LPCSTR szFunction;
        SIZE_T i = 0, j = 0;
        BOOL fHasExtension = FALSE;
        HMODULE hModule;
        WORD wOrdinal = 0;
        if (!szForwarder || cDepth > 8)
        {
            return NULL;
        }
        while (szForwarder[i] && szForwarder[i] != '.' && i < sizeof(szModuleA) - 5)
        {
            szModuleA[i] = szForwarder[i];
            if (szForwarder[i] == '.')
            {
                fHasExtension = TRUE;
            }
            i++;
        }
        if (szForwarder[i] != '.')
        {
            return NULL;
        }
        szModuleA[i] = 0;
        szFunction = szForwarder + i + 1;
        for (j = 0; j < i; j++)
        {
            if (szModuleA[j] == '.')
            {
                fHasExtension = TRUE;
            }
        }
        if (!fHasExtension && i < sizeof(szModuleA) - 4)
        {
            szModuleA[i++] = '.';
            szModuleA[i++] = 'd';
            szModuleA[i++] = 'l';
            szModuleA[i++] = 'l';
            szModuleA[i] = 0;
        }
        for (j = 0; j <= i && j < _countof(wszModuleW); j++)
        {
            wszModuleW[j] = (WCHAR)(BYTE)szModuleA[j];
        }
        hModule = LcWinApi_LoadLibraryW(wszModuleW);
        if (!hModule)
        {
            return NULL;
        }
        if (szFunction[0] == '#')
        {
            for (j = 1; szFunction[j] >= '0' && szFunction[j] <= '9'; j++)
            {
                wOrdinal = (WORD)(wOrdinal * 10 + (szFunction[j] - '0'));
            }
            return LcWinApi_GetProcAddressRaw(hModule, NULL, wOrdinal, TRUE, cDepth + 1);
        }
        return LcWinApi_GetProcAddressRaw(hModule, szFunction, 0, FALSE, cDepth + 1);
    }

    static FARPROC LcWinApi_GetProcAddressRaw(_In_ HMODULE hModule, _In_opt_ LPCSTR szProcName, _In_ WORD wOrdinal, _In_ BOOL fOrdinal, _In_ DWORD cDepth)
    {
        PBYTE pbModule = (PBYTE)hModule;
        PIMAGE_DOS_HEADER pDos;
        PIMAGE_NT_HEADERS pNt;
        PIMAGE_EXPORT_DIRECTORY pExport;
        PDWORD pdwFunctions, pdwNames;
        PWORD pwOrdinals;
        DWORD i, rvaExport, cbExport, rvaFunction;
        if (!hModule || cDepth > 8)
        {
            return NULL;
        }
        pDos = (PIMAGE_DOS_HEADER)pbModule;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return NULL;
        }
        pNt = (PIMAGE_NT_HEADERS)(pbModule + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
        {
            return NULL;
        }
        rvaExport = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        cbExport = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!rvaExport || !cbExport)
        {
            return NULL;
        }
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pbModule + rvaExport);
        pdwFunctions = (PDWORD)(pbModule + pExport->AddressOfFunctions);
        pdwNames = (PDWORD)(pbModule + pExport->AddressOfNames);
        pwOrdinals = (PWORD)(pbModule + pExport->AddressOfNameOrdinals);
        if (fOrdinal)
        {
            if ((wOrdinal < pExport->Base) || (wOrdinal >= pExport->Base + pExport->NumberOfFunctions))
            {
                return NULL;
            }
            rvaFunction = pdwFunctions[wOrdinal - pExport->Base];
            if (!rvaFunction)
            {
                return NULL;
            }
            if ((rvaFunction >= rvaExport) && (rvaFunction < rvaExport + cbExport))
            {
                return LcWinApi_ResolveForwarder((LPCSTR)(pbModule + rvaFunction), cDepth + 1);
            }
            return (FARPROC)(pbModule + rvaFunction);
        }
        if (!szProcName)
        {
            return NULL;
        }
        DWORD dwProcHash = LcWinApi_HashA(szProcName);
        for (i = 0; i < pExport->NumberOfNames; i++)
        {
            LPCSTR szExportName = (LPCSTR)(pbModule + pdwNames[i]);
            if ((LcWinApi_HashA(szExportName) != dwProcHash) && (!LcWinApi_StrEqualsA(szExportName, szProcName)))
            {
                continue;
            }
            rvaFunction = pdwFunctions[pwOrdinals[i]];
            if (!rvaFunction)
            {
                return NULL;
            }
            if ((rvaFunction >= rvaExport) && (rvaFunction < rvaExport + cbExport))
            {
                return LcWinApi_ResolveForwarder((LPCSTR)(pbModule + rvaFunction), cDepth + 1);
            }
            return (FARPROC)(pbModule + rvaFunction);
        }
        return NULL;
    }

    static FARPROC LcWinApi_GetProcAddressByHashPure(_In_ DWORD dwModuleHash, _In_ DWORD dwProcHash)
    {
        HMODULE hModule = LcWinApi_GetModuleBaseByHash(dwModuleHash);
        if (!hModule)
        {
            return NULL;
        }
        PBYTE pbModule = (PBYTE)hModule;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pbModule;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return NULL;
        }
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pbModule + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
        {
            return NULL;
        }
        DWORD rvaExport = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD cbExport = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!rvaExport || !cbExport)
        {
            return NULL;
        }
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pbModule + rvaExport);
        PDWORD pdwFunctions = (PDWORD)(pbModule + pExport->AddressOfFunctions);
        PDWORD pdwNames = (PDWORD)(pbModule + pExport->AddressOfNames);
        PWORD pwOrdinals = (PWORD)(pbModule + pExport->AddressOfNameOrdinals);
        for (DWORD i = 0; i < pExport->NumberOfNames; i++)
        {
            LPCSTR szExportName = (LPCSTR)(pbModule + pdwNames[i]);
            if (LcWinApi_HashA(szExportName) != dwProcHash)
            {
                continue;
            }
            DWORD rvaFunction = pdwFunctions[pwOrdinals[i]];
            if (!rvaFunction)
            {
                return NULL;
            }
            if ((rvaFunction >= rvaExport) && (rvaFunction < rvaExport + cbExport))
            {
                return LcWinApi_ResolveForwarder((LPCSTR)(pbModule + rvaFunction), 1);
            }
            return (FARPROC)(pbModule + rvaFunction);
        }
        return NULL;
    }

static __forceinline FARPROC LcWinApi_GetProcAddressByName(_In_ LPCWSTR wszModuleName, _In_ LPCSTR szProcName)
    {
        HMODULE hModule = LcWinApi_LoadLibraryW(wszModuleName);
        return hModule ? LcWinApi_GetProcAddressRaw(hModule, szProcName, 0, FALSE, 0) : NULL;
    }



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _WIN32 */

#endif /* __LC_WINAPI_H__ */
