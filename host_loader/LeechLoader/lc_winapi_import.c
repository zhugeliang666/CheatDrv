#if defined(_MSC_VER)
#pragma warning(disable: 4273)
#endif
#if defined(__clang__)
#pragma clang diagnostic ignored "-Winconsistent-dllimport"
#endif

// lc_winapi_import.c : local import thunks backed by lc_winapi.h for
// LeechLoader.
//
// Keep static libraries, CRT, and third-party libraries (e.g. libcurl)
// from creating fixed Win32 import table (IAT) entries.
//
#define LC_WINAPI_NO_IMPORT_TABLE
#define LC_WINAPI_IMPORT_FILE
#include "lc_winapi.h"

#if defined(_WIN32) && defined(LC_WINAPI_NO_IMPORT_TABLE)

#define LC_WINAPI_IMPORT_HASH(_Ret, _Call, _DllHash, _NameHash, _DllStr, _NameStr, _Args, _CallArgs, _Fail) \
    typedef _Ret(_Call *PLC_WINAPI_IMPORT_##_NameStr) _Args; \
    static _Ret _Call LcWinApiImport_##_NameStr _Args \
    { \
        static PLC_WINAPI_IMPORT_##_NameStr pfn = NULL; \
        if (!pfn) \
        { \
            pfn = (PLC_WINAPI_IMPORT_##_NameStr)LcWinApi_GetProcAddressByHashPure(_DllHash, _NameHash); \
            if (!pfn) \
            { \
                pfn = (PLC_WINAPI_IMPORT_##_NameStr)LcWinApi_GetProcAddressByName(_DllStr, #_NameStr); \
            } \
        } \
        return pfn ? pfn _CallArgs : (_Ret)(_Fail); \
    } \
    PVOID __imp_##_NameStr = (PVOID)LcWinApiImport_##_NameStr;

#define LC_WINAPI_IMPORT(_Ret, _Call, _Dll, _Name, _Args, _CallArgs, _Fail) LC_WINAPI_IMPORT_HASH(_Ret, _Call, HASH_DLL_KERNEL32_DLL, HASH_API_##_Name, _Dll, _Name, _Args, _CallArgs, _Fail)

#define LC_WINAPI_IMPORT_VOID_HASH(_Call, _DllHash, _NameHash, _DllStr, _NameStr, _Args, _CallArgs) \
    typedef VOID(_Call *PLC_WINAPI_IMPORT_##_NameStr) _Args; \
    static VOID _Call LcWinApiImport_##_NameStr _Args \
    { \
        static PLC_WINAPI_IMPORT_##_NameStr pfn = NULL; \
        if (!pfn) \
        { \
            pfn = (PLC_WINAPI_IMPORT_##_NameStr)LcWinApi_GetProcAddressByHashPure(_DllHash, _NameHash); \
            if (!pfn) \
            { \
                pfn = (PLC_WINAPI_IMPORT_##_NameStr)LcWinApi_GetProcAddressByName(_DllStr, #_NameStr); \
            } \
        } \
        if (pfn) \
        { \
            pfn _CallArgs; \
        } \
    } \
    PVOID __imp_##_NameStr = (PVOID)LcWinApiImport_##_NameStr;

#define LC_WINAPI_IMPORT_VOID(_Call, _Dll, _Name, _Args, _CallArgs) LC_WINAPI_IMPORT_VOID_HASH(_Call, HASH_DLL_KERNEL32_DLL, HASH_API_##_Name, _Dll, _Name, _Args, _CallArgs)

#define LC_WINAPI_IMPORT_BOTH_HASH(_Ret, _Call, _DllHash, _NameHash, _DllStr, _NameStr, _Args, _CallArgs, _Fail) \
    typedef _Ret(_Call *PLC_WINAPI_IMPORT_##_NameStr) _Args; \
    static _Ret _Call LcWinApiImport_##_NameStr _Args \
    { \
        static PLC_WINAPI_IMPORT_##_NameStr pfn = NULL; \
        if (!pfn) \
        { \
            pfn = (PLC_WINAPI_IMPORT_##_NameStr)LcWinApi_GetProcAddressByHashPure(_DllHash, _NameHash); \
            if (!pfn) \
            { \
                pfn = (PLC_WINAPI_IMPORT_##_NameStr)LcWinApi_GetProcAddressByName(_DllStr, #_NameStr); \
            } \
        } \
        return pfn ? pfn _CallArgs : (_Ret)(_Fail); \
    } \
    PVOID __imp_##_NameStr = (PVOID)LcWinApiImport_##_NameStr; \
    _Ret _Call _NameStr _Args \
    { \
        return LcWinApiImport_##_NameStr _CallArgs; \
    }

#define LC_WINAPI_IMPORT_BOTH(_Ret, _Call, _Dll, _Name, _Args, _CallArgs, _Fail) LC_WINAPI_IMPORT_BOTH_HASH(_Ret, _Call, HASH_DLL_KERNEL32_DLL, HASH_API_##_Name, _Dll, _Name, _Args, _CallArgs, _Fail)

#define LC_WINAPI_IMPORT_BOTH_VOID_HASH(_Call, _DllHash, _NameHash, _DllStr, _NameStr, _Args, _CallArgs) \
    typedef VOID(_Call *PLC_WINAPI_IMPORT_##_NameStr) _Args; \
    static VOID _Call LcWinApiImport_##_NameStr _Args \
    { \
        static PLC_WINAPI_IMPORT_##_NameStr pfn = NULL; \
        if (!pfn) \
        { \
            pfn = (PLC_WINAPI_IMPORT_##_NameStr)LcWinApi_GetProcAddressByHashPure(_DllHash, _NameHash); \
            if (!pfn) \
            { \
                pfn = (PLC_WINAPI_IMPORT_##_NameStr)LcWinApi_GetProcAddressByName(_DllStr, #_NameStr); \
            } \
        } \
        if (pfn) \
        { \
            pfn _CallArgs; \
        } \
    } \
    PVOID __imp_##_NameStr = (PVOID)LcWinApiImport_##_NameStr; \
    VOID _Call _NameStr _Args \
    { \
        LcWinApiImport_##_NameStr _CallArgs; \
    }

#define LC_WINAPI_IMPORT_BOTH_VOID(_Call, _Dll, _Name, _Args, _CallArgs) LC_WINAPI_IMPORT_BOTH_VOID_HASH(_Call, HASH_DLL_KERNEL32_DLL, HASH_API_##_Name, _Dll, _Name, _Args, _CallArgs)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", AcquireSRWLockExclusive, (PSRWLOCK p0), (p0))

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", AreFileApisANSI, (VOID), (), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", CloseHandle, (HANDLE p0), (p0), FALSE)

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", CompareStringW, (LCID p0, DWORD p1, LPCWSTR p2, int p3, LPCWSTR p4, int p5), (p0, p1, p2, p3, p4, p5), 0)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", CreateDirectoryW, (LPCWSTR p0, LPSECURITY_ATTRIBUTES p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(HANDLE, WINAPI, L"kernel32.dll", CreateFileW, (LPCWSTR p0, DWORD p1, DWORD p2, LPSECURITY_ATTRIBUTES p3, DWORD p4, DWORD p5, HANDLE p6), (p0, p1, p2, p3, p4, p5, p6),

                 INVALID_HANDLE_VALUE)

LC_WINAPI_IMPORT_BOTH(HANDLE, WINAPI, L"kernel32.dll", CreateFileA, (LPCSTR p0, DWORD p1, DWORD p2, LPSECURITY_ATTRIBUTES p3, DWORD p4, DWORD p5, HANDLE p6), (p0, p1, p2, p3, p4, p5, p6),

                      INVALID_HANDLE_VALUE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", CreateProcessW,

                 (LPCWSTR p0, LPWSTR p1, LPSECURITY_ATTRIBUTES p2, LPSECURITY_ATTRIBUTES p3, BOOL p4, DWORD p5, LPVOID p6, LPCWSTR p7, LPSTARTUPINFOW p8, LPPROCESS_INFORMATION p9),

                 (p0, p1, p2, p3, p4, p5, p6, p7, p8, p9), FALSE)

LC_WINAPI_IMPORT(HANDLE, WINAPI, L"kernel32.dll", CreateThread, (LPSECURITY_ATTRIBUTES p0, SIZE_T p1, LPTHREAD_START_ROUTINE p2, LPVOID p3, DWORD p4, LPDWORD p5), (p0, p1, p2, p3, p4, p5), NULL)

LC_WINAPI_IMPORT(PVOID, WINAPI, L"kernel32.dll", DecodePointer, (PVOID p0), (p0), NULL)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", DeleteCriticalSection, (LPCRITICAL_SECTION p0), (p0))

LC_WINAPI_IMPORT(PVOID, WINAPI, L"kernel32.dll", EncodePointer, (PVOID p0), (p0), NULL)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", EnterCriticalSection, (LPCRITICAL_SECTION p0), (p0))

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", EnumSystemLocalesW, (LOCALE_ENUMPROCW p0, DWORD p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", ExitProcess, (UINT p0), (p0))

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", ExitThread, (DWORD p0), (p0))

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", FindClose, (HANDLE p0), (p0), FALSE)

LC_WINAPI_IMPORT(HANDLE, WINAPI, L"kernel32.dll", FindFirstFileExW, (LPCWSTR p0, FINDEX_INFO_LEVELS p1, LPVOID p2, FINDEX_SEARCH_OPS p3, LPVOID p4, DWORD p5), (p0, p1, p2, p3, p4, p5),

                 INVALID_HANDLE_VALUE)

LC_WINAPI_IMPORT(HANDLE, WINAPI, L"kernel32.dll", FindFirstFileW, (LPCWSTR p0, LPWIN32_FIND_DATAW p1), (p0, p1), INVALID_HANDLE_VALUE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", FindNextFileW, (HANDLE p0, LPWIN32_FIND_DATAW p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", FlsAlloc, (PFLS_CALLBACK_FUNCTION p0), (p0), FLS_OUT_OF_INDEXES)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", FlsFree, (DWORD p0), (p0), FALSE)

LC_WINAPI_IMPORT(PVOID, WINAPI, L"kernel32.dll", FlsGetValue, (DWORD p0), (p0), NULL)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", FlsSetValue, (DWORD p0, PVOID p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", FlushFileBuffers, (HANDLE p0), (p0), FALSE)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", FormatMessageA, (DWORD p0, LPCVOID p1, DWORD p2, DWORD p3, LPSTR p4, DWORD p5, va_list *p6), (p0, p1, p2, p3, p4, p5, p6), 0)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", FreeEnvironmentStringsW, (LPWCH p0), (p0), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", FreeLibrary, (HMODULE p0), (p0), FALSE)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", FreeLibraryAndExitThread, (HMODULE p0, DWORD p1), (p0, p1))

LC_WINAPI_IMPORT(UINT, WINAPI, L"kernel32.dll", GetACP, (VOID), (), 0)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetCPInfo, (UINT p0, LPCPINFO p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(LPSTR, WINAPI, L"kernel32.dll", GetCommandLineA, (VOID), (), NULL)

LC_WINAPI_IMPORT(LPWSTR, WINAPI, L"kernel32.dll", GetCommandLineW, (VOID), (), NULL)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetConsoleMode, (HANDLE p0, LPDWORD p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(UINT, WINAPI, L"kernel32.dll", GetConsoleOutputCP, (VOID), (), 0)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", GetConsoleScreenBufferInfo, (HANDLE p0, PCONSOLE_SCREEN_BUFFER_INFO p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetCurrentDirectoryW, (DWORD p0, LPWSTR p1), (p0, p1), 0)

LC_WINAPI_IMPORT(HANDLE, WINAPI, L"kernel32.dll", GetCurrentProcess, (VOID), (), NULL)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetCurrentProcessId, (VOID), (), 0)

LC_WINAPI_IMPORT_BOTH(HANDLE, WINAPI, L"kernel32.dll", GetCurrentThread, (VOID), (), NULL)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetCurrentThreadId, (VOID), (), 0)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", GetProcessAffinityMask, (HANDLE p0, PDWORD_PTR p1, PDWORD_PTR p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", GetDateFormatW, (LCID p0, DWORD p1, const SYSTEMTIME *p2, LPCWSTR p3, LPWSTR p4, int p5), (p0, p1, p2, p3, p4, p5), 0)

LC_WINAPI_IMPORT(LPWCH, WINAPI, L"kernel32.dll", GetEnvironmentStringsW, (VOID), (), NULL)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetExitCodeProcess, (HANDLE p0, LPDWORD p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetExitCodeThread, (HANDLE p0, LPDWORD p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetFileAttributesExW, (LPCWSTR p0, GET_FILEEX_INFO_LEVELS p1, LPVOID p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetFileInformationByHandle, (HANDLE p0, LPBY_HANDLE_FILE_INFORMATION p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetFileInformationByHandleEx, (HANDLE p0, FILE_INFO_BY_HANDLE_CLASS p1, LPVOID p2, DWORD p3), (p0, p1, p2, p3), FALSE)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetFileSize, (HANDLE p0, LPDWORD p1), (p0, p1), INVALID_FILE_SIZE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetFileSizeEx, (HANDLE p0, PLARGE_INTEGER p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetFileType, (HANDLE p0), (p0), FILE_TYPE_UNKNOWN)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetFullPathNameW, (LPCWSTR p0, DWORD p1, LPWSTR p2, LPWSTR *p3), (p0, p1, p2, p3), 0)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetLastError, (VOID), (), 0)

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", GetLocaleInfoEx, (LPCWSTR p0, LCTYPE p1, LPWSTR p2, int p3), (p0, p1, p2, p3), 0)

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", GetLocaleInfoW, (LCID p0, LCTYPE p1, LPWSTR p2, int p3), (p0, p1, p2, p3), 0)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetModuleFileNameW, (HMODULE p0, LPWSTR p1, DWORD p2), (p0, p1, p2), 0)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetModuleHandleExW, (DWORD p0, LPCWSTR p1, HMODULE *p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT(HMODULE, WINAPI, L"kernel32.dll", GetModuleHandleW, (LPCWSTR p0), (p0), NULL)

LC_WINAPI_IMPORT(UINT, WINAPI, L"kernel32.dll", GetOEMCP, (VOID), (), 0)

LC_WINAPI_IMPORT(FARPROC, WINAPI, L"kernel32.dll", GetProcAddress, (HMODULE p0, LPCSTR p1), (p0, p1), NULL)

LC_WINAPI_IMPORT(HANDLE, WINAPI, L"kernel32.dll", GetProcessHeap, (VOID), (), NULL)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", GetStartupInfoW, (LPSTARTUPINFOW p0), (p0))

LC_WINAPI_IMPORT(HANDLE, WINAPI, L"kernel32.dll", GetStdHandle, (DWORD p0), (p0), INVALID_HANDLE_VALUE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", GetStringTypeW, (DWORD p0, LPCWCH p1, int p2, LPWORD p3), (p0, p1, p2, p3), FALSE)

LC_WINAPI_IMPORT_BOTH(UINT, WINAPI, L"kernel32.dll", GetSystemDirectoryW, (LPWSTR p0, UINT p1), (p0, p1), 0)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", GetSystemTimeAsFileTime, (LPFILETIME p0), (p0))

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", GetTimeFormatW, (LCID p0, DWORD p1, const SYSTEMTIME *p2, LPCWSTR p3, LPWSTR p4, int p5), (p0, p1, p2, p3, p4, p5), 0)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", GetTimeZoneInformation, (LPTIME_ZONE_INFORMATION p0), (p0), TIME_ZONE_ID_INVALID)

LC_WINAPI_IMPORT(LCID, WINAPI, L"kernel32.dll", GetUserDefaultLCID, (VOID), (), 0)

LC_WINAPI_IMPORT(LPVOID, WINAPI, L"kernel32.dll", HeapAlloc, (HANDLE p0, DWORD p1, SIZE_T p2), (p0, p1, p2), NULL)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", HeapFree, (HANDLE p0, DWORD p1, LPVOID p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT(LPVOID, WINAPI, L"kernel32.dll", HeapReAlloc, (HANDLE p0, DWORD p1, LPVOID p2, SIZE_T p3), (p0, p1, p2, p3), NULL)

LC_WINAPI_IMPORT(SIZE_T, WINAPI, L"kernel32.dll", HeapSize, (HANDLE p0, DWORD p1, LPCVOID p2), (p0, p1, p2), (SIZE_T)-1)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", InitializeCriticalSectionAndSpinCount, (LPCRITICAL_SECTION p0, DWORD p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", InitializeCriticalSectionEx, (LPCRITICAL_SECTION p0, DWORD p1, DWORD p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", InitializeSListHead, (PSLIST_HEADER p0), (p0))

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", IsDebuggerPresent, (VOID), (), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", IsProcessorFeaturePresent, (DWORD p0), (p0), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", IsValidCodePage, (UINT p0), (p0), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", IsValidLocale, (LCID p0, DWORD p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", LCMapStringEx, (LPCWSTR p0, DWORD p1, LPCWSTR p2, int p3, LPWSTR p4, int p5, LPVOID p6, LPVOID p7, LPARAM p8), (p0, p1, p2, p3, p4, p5, p6, p7, p8), 0)

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", LCMapStringW, (LCID p0, DWORD p1, LPCWSTR p2, int p3, LPWSTR p4, int p5), (p0, p1, p2, p3, p4, p5), 0)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", LeaveCriticalSection, (LPCRITICAL_SECTION p0), (p0))

LC_WINAPI_IMPORT(HMODULE, WINAPI, L"kernel32.dll", LoadLibraryExW, (LPCWSTR p0, HANDLE p1, DWORD p2), (p0, p1, p2), NULL)

LC_WINAPI_IMPORT_BOTH(HLOCAL, WINAPI, L"kernel32.dll", LocalAlloc, (UINT p0, SIZE_T p1), (p0, p1), NULL)

LC_WINAPI_IMPORT(HLOCAL, WINAPI, L"kernel32.dll", LocalFree, (HLOCAL p0), (p0), NULL)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", MoveFileExW, (LPCWSTR p0, LPCWSTR p1, DWORD p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", MultiByteToWideChar, (UINT p0, DWORD p1, LPCCH p2, int p3, LPWSTR p4, int p5), (p0, p1, p2, p3, p4, p5), 0)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", OutputDebugStringW, (LPCWSTR p0), (p0))

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", QueryPerformanceCounter, (LARGE_INTEGER * p0), (p0), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", QueryPerformanceFrequency, (LARGE_INTEGER * p0), (p0), FALSE)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", RaiseException, (DWORD p0, DWORD p1, DWORD p2, const ULONG_PTR *p3), (p0, p1, p2, p3))

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", ReadConsoleW, (HANDLE p0, LPVOID p1, DWORD p2, LPDWORD p3, PVOID p4), (p0, p1, p2, p3, p4), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", ReadFile, (HANDLE p0, LPVOID p1, DWORD p2, LPDWORD p3, LPOVERLAPPED p4), (p0, p1, p2, p3, p4), FALSE)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", ReleaseSRWLockExclusive, (PSRWLOCK p0), (p0))

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", RtlCaptureContext, (PCONTEXT p0), (p0))

LC_WINAPI_IMPORT(PVOID, WINAPI, L"kernel32.dll", RtlLookupFunctionEntry, (DWORD64 p0, PDWORD64 p1, PVOID p2), (p0, p1, p2), NULL)

LC_WINAPI_IMPORT(PVOID, WINAPI, L"kernel32.dll", RtlPcToFileHeader, (PVOID p0, PVOID *p1), (p0, p1), NULL)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", RtlUnwind, (PVOID p0, PVOID p1, PVOID p2, PVOID p3), (p0, p1, p2, p3))

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", RtlUnwindEx, (PVOID p0, PVOID p1, PVOID p2, PVOID p3, PCONTEXT p4, PVOID p5), (p0, p1, p2, p3, p4, p5))

LC_WINAPI_IMPORT(PVOID, WINAPI, L"kernel32.dll", RtlVirtualUnwind, (DWORD p0, DWORD64 p1, DWORD64 p2, PVOID p3, PCONTEXT p4, PVOID *p5, PDWORD64 p6, PVOID p7), (p0, p1, p2, p3, p4, p5, p6, p7), NULL)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", SetConsoleCP, (UINT p0), (p0), FALSE)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", SetConsoleOutputCP, (UINT p0), (p0), FALSE)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", SetConsoleTextAttribute, (HANDLE p0, WORD p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT_BOTH(DWORD_PTR, WINAPI, L"kernel32.dll", SetThreadAffinityMask, (HANDLE p0, DWORD_PTR p1), (p0, p1), 0)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", SetEndOfFile, (HANDLE p0), (p0), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", SetEnvironmentVariableW, (LPCWSTR p0, LPCWSTR p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", SetFileAttributesW, (LPCWSTR p0, DWORD p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", SetFileInformationByHandle, (HANDLE p0, FILE_INFO_BY_HANDLE_CLASS p1, LPVOID p2, DWORD p3), (p0, p1, p2, p3), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", SetFilePointerEx, (HANDLE p0, LARGE_INTEGER p1, PLARGE_INTEGER p2, DWORD p3), (p0, p1, p2, p3), FALSE)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", SetLastError, (DWORD p0), (p0))

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", SetStdHandle, (DWORD p0, HANDLE p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(LPTOP_LEVEL_EXCEPTION_FILTER, WINAPI, L"kernel32.dll", SetUnhandledExceptionFilter, (LPTOP_LEVEL_EXCEPTION_FILTER p0), (p0), NULL)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", Sleep, (DWORD p0), (p0))

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", SleepConditionVariableSRW, (PCONDITION_VARIABLE p0, PSRWLOCK p1, DWORD p2, ULONG p3), (p0, p1, p2, p3), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", TerminateProcess, (HANDLE p0, UINT p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", TlsAlloc, (VOID), (), TLS_OUT_OF_INDEXES)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", TlsFree, (DWORD p0), (p0), FALSE)

LC_WINAPI_IMPORT(LPVOID, WINAPI, L"kernel32.dll", TlsGetValue, (DWORD p0), (p0), NULL)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", TlsSetValue, (DWORD p0, LPVOID p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", TryAcquireSRWLockExclusive, (PSRWLOCK p0), (p0), FALSE)

LC_WINAPI_IMPORT(LONG, WINAPI, L"kernel32.dll", UnhandledExceptionFilter, (struct _EXCEPTION_POINTERS * p0), (p0), EXCEPTION_EXECUTE_HANDLER)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", VirtualProtect, (LPVOID p0, SIZE_T p1, DWORD p2, PDWORD p3), (p0, p1, p2, p3), FALSE)

LC_WINAPI_IMPORT_BOTH(LPVOID, WINAPI, L"kernel32.dll", VirtualAlloc, (LPVOID p0, SIZE_T p1, DWORD p2, DWORD p3), (p0, p1, p2, p3), NULL)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", VirtualFree, (LPVOID p0, SIZE_T p1, DWORD p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", VirtualLock, (LPVOID p0, SIZE_T p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", VirtualUnlock, (LPVOID p0, SIZE_T p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", DeviceIoControl, (HANDLE p0, DWORD p1, LPVOID p2, DWORD p3, LPVOID p4, DWORD p5, LPDWORD p6, LPOVERLAPPED p7), (p0, p1, p2, p3, p4, p5, p6, p7), FALSE)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", CreateProcessA, (LPCSTR p0, LPSTR p1, LPSECURITY_ATTRIBUTES p2, LPSECURITY_ATTRIBUTES p3, BOOL p4, DWORD p5, LPVOID p6, LPCSTR p7, LPSTARTUPINFOA p8, LPPROCESS_INFORMATION p9), (p0, p1, p2, p3, p4, p5, p6, p7, p8, p9), FALSE)

LC_WINAPI_IMPORT_BOTH(BOOL, WINAPI, L"kernel32.dll", K32EnumDeviceDrivers, (LPVOID *p0, DWORD p1, LPDWORD p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_BOTH(DWORD, WINAPI, L"kernel32.dll", K32GetDeviceDriverBaseNameA, (LPVOID p0, LPSTR p1, DWORD p2), (p0, p1, p2), 0)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", WaitForSingleObject, (HANDLE p0, DWORD p1), (p0, p1), WAIT_FAILED)

LC_WINAPI_IMPORT(DWORD, WINAPI, L"kernel32.dll", WaitForSingleObjectEx, (HANDLE p0, DWORD p1, BOOL p2), (p0, p1, p2), WAIT_FAILED)

LC_WINAPI_IMPORT_VOID(WINAPI, L"kernel32.dll", WakeAllConditionVariable, (PCONDITION_VARIABLE p0), (p0))

LC_WINAPI_IMPORT(int, WINAPI, L"kernel32.dll", WideCharToMultiByte, (UINT p0, DWORD p1, LPCWCH p2, int p3, LPSTR p4, int p5, LPCCH p6, LPBOOL p7), (p0, p1, p2, p3, p4, p5, p6, p7), 0)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", WriteConsoleW, (HANDLE p0, const VOID *p1, DWORD p2, LPDWORD p3, LPVOID p4), (p0, p1, p2, p3, p4), FALSE)

LC_WINAPI_IMPORT(BOOL, WINAPI, L"kernel32.dll", WriteFile, (HANDLE p0, LPCVOID p1, DWORD p2, LPDWORD p3, LPOVERLAPPED p4), (p0, p1, p2, p3, p4), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(HRESULT, WINAPI, HASH_DLL_OLE32_DLL, HASH_API_CLSIDFromString, L"ole32.dll", CLSIDFromString, (LPCOLESTR p0, LPCLSID p1), (p0, p1), E_FAIL)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_SHELL32_DLL, HASH_API_ShellExecuteExW, L"shell32.dll", ShellExecuteExW, (SHELLEXECUTEINFOW *p0), (p0), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_AdjustTokenPrivileges, L"advapi32.dll", AdjustTokenPrivileges,

                           (HANDLE p0, BOOL p1, PTOKEN_PRIVILEGES p2, DWORD p3, PTOKEN_PRIVILEGES p4, PDWORD p5), (p0, p1, p2, p3, p4, p5), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_CloseServiceHandle, L"advapi32.dll", CloseServiceHandle, (SC_HANDLE p0), (p0), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_ControlService, L"advapi32.dll", ControlService, (SC_HANDLE p0, DWORD p1, LPSERVICE_STATUS p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(SC_HANDLE, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_CreateServiceW, L"advapi32.dll", CreateServiceW,

                           (SC_HANDLE p0, LPCWSTR p1, LPCWSTR p2, DWORD p3, DWORD p4, DWORD p5, DWORD p6, LPCWSTR p7, LPCWSTR p8, LPDWORD p9, LPCWSTR p10, LPCWSTR p11, LPCWSTR p12),

                           (p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12), NULL)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_ChangeServiceConfigW, L"advapi32.dll", ChangeServiceConfigW,

                           (SC_HANDLE p0, DWORD p1, DWORD p2, DWORD p3, LPCWSTR p4, LPCWSTR p5, LPDWORD p6, LPCWSTR p7, LPCWSTR p8, LPCWSTR p9, LPCWSTR p10),

                           (p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_QueryServiceStatusEx, L"advapi32.dll", QueryServiceStatusEx,

                           (SC_HANDLE p0, SC_STATUS_TYPE p1, LPBYTE p2, DWORD p3, LPDWORD p4), (p0, p1, p2, p3, p4), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_DeleteService, L"advapi32.dll", DeleteService, (SC_HANDLE p0), (p0), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_GetTokenInformation, L"advapi32.dll", GetTokenInformation, (HANDLE p0, TOKEN_INFORMATION_CLASS p1, LPVOID p2, DWORD p3, PDWORD p4),

                           (p0, p1, p2, p3, p4), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_LookupPrivilegeValueA, L"advapi32.dll", LookupPrivilegeValueA, (LPCSTR p0, LPCSTR p1, PLUID p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_OpenProcessToken, L"advapi32.dll", OpenProcessToken, (HANDLE p0, DWORD p1, PHANDLE p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(SC_HANDLE, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_OpenSCManagerW, L"advapi32.dll", OpenSCManagerW, (LPCWSTR p0, LPCWSTR p1, DWORD p2), (p0, p1, p2), NULL)

LC_WINAPI_IMPORT_BOTH_HASH(SC_HANDLE, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_OpenServiceW, L"advapi32.dll", OpenServiceW, (SC_HANDLE p0, LPCWSTR p1, DWORD p2), (p0, p1, p2), NULL)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_QueryServiceStatus, L"advapi32.dll", QueryServiceStatus, (SC_HANDLE p0, LPSERVICE_STATUS p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(LSTATUS, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_RegCloseKey, L"advapi32.dll", RegCloseKey, (HKEY p0), (p0), ERROR_INVALID_HANDLE)

LC_WINAPI_IMPORT_BOTH_HASH(LSTATUS, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_RegQueryValueExW, L"advapi32.dll", RegQueryValueExW, (HKEY p0, LPCWSTR p1, LPDWORD p2, LPDWORD p3, LPBYTE p4, LPDWORD p5),

                           (p0, p1, p2, p3, p4, p5), ERROR_INVALID_HANDLE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_ADVAPI32_DLL, HASH_API_StartServiceW, L"advapi32.dll", StartServiceW, (SC_HANDLE p0, DWORD p1, LPCWSTR *p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(SOCKET, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_accept, L"ws2_32.dll", accept, (SOCKET p0, struct sockaddr *p1, int *p2), (p0, p1, p2), INVALID_SOCKET)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_bind, L"ws2_32.dll", bind, (SOCKET p0, const struct sockaddr *p1, int p2), (p0, p1, p2), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_closesocket, L"ws2_32.dll", closesocket, (SOCKET p0), (p0), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_connect, L"ws2_32.dll", connect, (SOCKET p0, const struct sockaddr *p1, int p2), (p0, p1, p2), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_getsockopt, L"ws2_32.dll", getsockopt, (SOCKET p0, int p1, int p2, char *p3, int *p4), (p0, p1, p2, p3, p4), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(u_long, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_htonl, L"ws2_32.dll", htonl, (u_long p0), (p0), 0)

LC_WINAPI_IMPORT_BOTH_HASH(u_short, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_htons, L"ws2_32.dll", htons, (u_short p0), (p0), 0)

LC_WINAPI_IMPORT_BOTH_HASH(ULONG, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_inet_addr, L"ws2_32.dll", inet_addr, (const char *p0), (p0), INADDR_NONE)

LC_WINAPI_IMPORT_BOTH_HASH(PCSTR, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_inet_ntop, L"ws2_32.dll", inet_ntop, (INT p0, const VOID *p1, PSTR p2, SIZE_T p3), (p0, p1, p2, p3), NULL)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_ioctlsocket, L"ws2_32.dll", ioctlsocket, (SOCKET p0, long p1, u_long *p2), (p0, p1, p2), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_listen, L"ws2_32.dll", listen, (SOCKET p0, int p1), (p0, p1), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(u_long, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_ntohl, L"ws2_32.dll", ntohl, (u_long p0), (p0), 0)

LC_WINAPI_IMPORT_BOTH_HASH(u_short, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_ntohs, L"ws2_32.dll", ntohs, (u_short p0), (p0), 0)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_recv, L"ws2_32.dll", recv, (SOCKET p0, char *p1, int p2, int p3), (p0, p1, p2, p3), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_recvfrom, L"ws2_32.dll", recvfrom, (SOCKET p0, char *p1, int p2, int p3, struct sockaddr *p4, int *p5), (p0, p1, p2, p3, p4, p5),

                          SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_select, L"ws2_32.dll", select, (int p0, fd_set *p1, fd_set *p2, fd_set *p3, const struct timeval *p4), (p0, p1, p2, p3, p4),

                          SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_send, L"ws2_32.dll", send, (SOCKET p0, const char *p1, int p2, int p3), (p0, p1, p2, p3), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_sendto, L"ws2_32.dll", sendto, (SOCKET p0, const char *p1, int p2, int p3, const struct sockaddr *p4, int p5),

                          (p0, p1, p2, p3, p4, p5), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_setsockopt, L"ws2_32.dll", setsockopt, (SOCKET p0, int p1, int p2, const char *p3, int p4), (p0, p1, p2, p3, p4), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(SOCKET, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_socket, L"ws2_32.dll", socket, (int p0, int p1, int p2), (p0, p1, p2), INVALID_SOCKET)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_WSACleanup, L"ws2_32.dll", WSACleanup, (VOID), (), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_WSAGetLastError, L"ws2_32.dll", WSAGetLastError, (VOID), (), 0)

LC_WINAPI_IMPORT_BOTH_HASH(INT, WSAAPI, HASH_DLL_WS2_32_DLL, HASH_API_WSAStartup, L"ws2_32.dll", WSAStartup, (WORD p0, LPWSADATA p1), (p0, p1), SOCKET_ERROR)

LC_WINAPI_IMPORT_BOTH_HASH(ULONG, WINAPI, HASH_DLL_IPHLPAPI_DLL, HASH_API_GetAdaptersAddresses, L"iphlpapi.dll", GetAdaptersAddresses,

                           (ULONG p0, ULONG p1, PVOID p2, PIP_ADAPTER_ADDRESSES p3, PULONG p4), (p0, p1, p2, p3, p4), ERROR_NO_DATA)

LC_WINAPI_IMPORT_BOTH_HASH(HDEVINFO, WINAPI, HASH_DLL_SETUPAPI_DLL, HASH_API_SetupDiGetClassDevsW, L"setupapi.dll", SetupDiGetClassDevsW,

                           (const GUID *p0, PCWSTR p1, HWND p2, DWORD p3), (p0, p1, p2, p3), INVALID_HANDLE_VALUE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_SETUPAPI_DLL, HASH_API_SetupDiEnumDeviceInfo, L"setupapi.dll", SetupDiEnumDeviceInfo,

                           (HDEVINFO p0, DWORD p1, PSP_DEVINFO_DATA p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_SETUPAPI_DLL, HASH_API_SetupDiGetDeviceRegistryPropertyW, L"setupapi.dll", SetupDiGetDeviceRegistryPropertyW,

                           (HDEVINFO p0, PSP_DEVINFO_DATA p1, DWORD p2, PDWORD p3, PBYTE p4, DWORD p5, PDWORD p6), (p0, p1, p2, p3, p4, p5, p6), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(HKEY, WINAPI, HASH_DLL_SETUPAPI_DLL, HASH_API_SetupDiOpenDevRegKey, L"setupapi.dll", SetupDiOpenDevRegKey,

                           (HDEVINFO p0, PSP_DEVINFO_DATA p1, DWORD p2, DWORD p3, DWORD p4, REGSAM p5), (p0, p1, p2, p3, p4, p5), INVALID_HANDLE_VALUE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_SETUPAPI_DLL, HASH_API_SetupDiEnumDeviceInterfaces, L"setupapi.dll", SetupDiEnumDeviceInterfaces,

                           (HDEVINFO p0, PSP_DEVINFO_DATA p1, const GUID *p2, DWORD p3, PSP_DEVICE_INTERFACE_DATA p4), (p0, p1, p2, p3, p4), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_SETUPAPI_DLL, HASH_API_SetupDiGetDeviceInterfaceDetailW, L"setupapi.dll", SetupDiGetDeviceInterfaceDetailW,

                           (HDEVINFO p0, PSP_DEVICE_INTERFACE_DATA p1, PSP_DEVICE_INTERFACE_DETAIL_DATA_W p2, DWORD p3, PDWORD p4, PSP_DEVINFO_DATA p5), (p0, p1, p2, p3, p4, p5), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_SETUPAPI_DLL, HASH_API_SetupDiDestroyDeviceInfoList, L"setupapi.dll", SetupDiDestroyDeviceInfoList,

                           (HDEVINFO p0), (p0), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_WINUSB_DLL, HASH_API_WinUsb_Initialize, L"winusb.dll", WinUsb_Initialize,

                           (HANDLE p0, PWINUSB_INTERFACE_HANDLE p1), (p0, p1), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_WINUSB_DLL, HASH_API_WinUsb_QueryInterfaceSettings, L"winusb.dll", WinUsb_QueryInterfaceSettings,

                           (WINUSB_INTERFACE_HANDLE p0, UCHAR p1, PUSB_INTERFACE_DESCRIPTOR p2), (p0, p1, p2), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_WINUSB_DLL, HASH_API_WinUsb_QueryPipe, L"winusb.dll", WinUsb_QueryPipe,

                           (WINUSB_INTERFACE_HANDLE p0, UCHAR p1, UCHAR p2, PWINUSB_PIPE_INFORMATION p3), (p0, p1, p2, p3), FALSE)

LC_WINAPI_IMPORT_BOTH_HASH(BOOL, WINAPI, HASH_DLL_WINUSB_DLL, HASH_API_WinUsb_Free, L"winusb.dll", WinUsb_Free,

                           (WINUSB_INTERFACE_HANDLE p0), (p0), FALSE)
#endif /* _WIN32 && LC_WINAPI_NO_IMPORT_TABLE */
