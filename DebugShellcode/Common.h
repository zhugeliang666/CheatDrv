#pragma once

#include "FrameWork.h"
#include "GameStruct.h"
#include "../Core/StackSpoofConfig.h"

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

template <typename T> T Read(IN ULONG64 VirtualAddress)
{
    return *(T *)VirtualAddress;
}

template <typename T> VOID Write(IN ULONG64 VirtualAddress, IN T Value)
{
    *(T *)(VirtualAddress) = Value;
}

template <typename Key, typename Value> struct UnorderedMap
{
    enum EntryStatus : unsigned char
    {
        STATUS_EMPTY = 0,
        STATUS_OCCUPIED,
        STATUS_DELETED
    };
    struct Entry
    {
        Key First;
        Value Second;
        EntryStatus Status;
    };
    Entry *Data;
    int Size;
    int Capacity;
    void *(*CustomMalloc)(size_t);
    void *(*CustomRealloc)(void *, size_t);
    void (*CustomFree)(void *);
    void *(*CustomMemmove)(void *, const void *, size_t);

    UnorderedMap(void *(*malloc_func)(size_t), void (*free_func)(void *), void *(*realloc_func)(void *, size_t) = nullptr,
                 void *(*memmove_func)(void *, const void *, size_t) = nullptr)
        : Data(nullptr), Size(0), Capacity(0), CustomMalloc(malloc_func), CustomRealloc(realloc_func), CustomFree(free_func), CustomMemmove(memmove_func)
    {
    }
    ~UnorderedMap()
    {
        if (Data)
            CustomFree(Data);
    }
    int size() const
    {
        return Size;
    }
    int capacity() const
    {
        return Capacity;
    }
    bool empty() const
    {
        return Size == 0;
    }
    void clear()
    {
        for (int i = 0; i < Capacity; ++i) {
            Data[i].Status = STATUS_EMPTY;
        }
        Size = 0;
    }
    unsigned int GetHash(const Key &key) const
    {
        const unsigned char *p = reinterpret_cast<const unsigned char *>(&key);
        unsigned int hash = 2166136261U;
        for (size_t i = 0; i < sizeof(Key); ++i) {
            hash ^= p[i];
            hash *= 16777619U;
        }
        return hash;
    }
    bool insert(const Key &key, const Value &value)
    {
        if ((Size + 1) * 10 > Capacity * 7) {
            reserve(Capacity ? Capacity * 2 : 8);
        }
        return insert_internal(key, value);
    }
    const Value *find(const Key &key) const
    {
        return const_cast<UnorderedMap *>(this)->find(key);
    }

    void reserve(int new_capacity)
    {
        if (new_capacity <= Capacity)
            return;
        if (new_capacity < 8)
            new_capacity = 8;
        Entry *new_data = (Entry *)CustomMalloc(new_capacity * sizeof(Entry));
        if (!new_data)
            return;
        for (int i = 0; i < new_capacity; ++i)
            new_data[i].Status = STATUS_EMPTY;
        int old_capacity = Capacity;
        Entry *old_data = Data;
        Data = new_data;
        Capacity = new_capacity;
        Size = 0;
        if (old_data) {
            for (int i = 0; i < old_capacity; ++i) {
                if (old_data[i].Status == STATUS_OCCUPIED) {
                    insert_internal(old_data[i].First, old_data[i].Second);
                }
            }
            CustomFree(old_data);
        }
    }

    Value *find(const Key &key)
    {
        if (Capacity == 0)
            return nullptr;
        unsigned int hash = GetHash(key);
        int bucket = hash % Capacity;
        int original_bucket = bucket;
        while (Data[bucket].Status != STATUS_EMPTY) {
            if (Data[bucket].Status == STATUS_OCCUPIED && Data[bucket].First == key) {
                return &Data[bucket].Second;
            }
            bucket = (bucket + 1) % Capacity;
            if (bucket == original_bucket)
                break;
        }
        return nullptr;
    }

    bool erase(const Key &key)
    {
        if (Capacity == 0)
            return false;
        unsigned int hash = GetHash(key);
        int bucket = hash % Capacity;
        int original_bucket = bucket;
        while (Data[bucket].Status != STATUS_EMPTY) {
            if (Data[bucket].Status == STATUS_OCCUPIED && Data[bucket].First == key) {
                Data[bucket].Status = STATUS_DELETED;
                Size--;
                return true;
            }
            bucket = (bucket + 1) % Capacity;
            if (bucket == original_bucket)
                break;
        }
        return false;
    }
    Value &operator[](const Key &key)
    {
        Value *val = find(key);
        if (val)
            return *val;
        insert(key, Value());
        return *find(key);
    }

private:
    bool insert_internal(const Key &key, const Value &value)
    {
        unsigned int hash = GetHash(key);
        int bucket = hash % Capacity;
        int first_deleted = -1;
        int original_bucket = bucket;
        while (Data[bucket].Status != STATUS_EMPTY) {
            if (Data[bucket].Status == STATUS_OCCUPIED && Data[bucket].First == key) {
                Data[bucket].Second = value;
                return true;
            }
            if (Data[bucket].Status == STATUS_DELETED && first_deleted == -1) {
                first_deleted = bucket;
            }
            bucket = (bucket + 1) % Capacity;
            if (bucket == original_bucket)
                break;
        }
        int target_bucket = (first_deleted != -1) ? first_deleted : bucket;
        if (Data[target_bucket].Status == STATUS_EMPTY || Data[target_bucket].Status == STATUS_DELETED) {
            Data[target_bucket].First = key;
            Data[target_bucket].Second = value;
            Data[target_bucket].Status = STATUS_OCCUPIED;
            Size++;
            return true;
        }
        return false;
    }
    UnorderedMap(const UnorderedMap &) = delete;
    UnorderedMap &operator=(const UnorderedMap &) = delete;
};

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    PVOID CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB, *PPEB;

typedef VOID(__stdcall *FuncTypeDef_RtlInitializeCriticalSection)(_Out_ PRTL_CRITICAL_SECTION CriticalSection);

typedef VOID(__stdcall *FuncTypeDef_RtlEnterCriticalSection)(_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

typedef VOID(__stdcall *FuncTypeDef_RtlLeaveCriticalSection)(_Inout_ PRTL_CRITICAL_SECTION CriticalSection);

typedef VOID(__stdcall *FuncTypeDef_RtlAcquireSRWLockExclusive)(_Inout_ PRTL_SRWLOCK SRWLock);

typedef VOID(__stdcall *FuncTypeDef_RtlReleaseSRWLockExclusive)(_Inout_ PRTL_SRWLOCK SRWLock);

typedef VOID(__stdcall *FuncTypeDef_RtlAcquireSRWLockShared)(_Inout_ PRTL_SRWLOCK SRWLock);

typedef VOID(__stdcall *FuncTypeDef_RtlReleaseSRWLockShared)(_Inout_ PRTL_SRWLOCK SRWLock);

typedef bool(__stdcall *FuncTypeDef_RtlTryAcquireSRWLockExclusive)(_Inout_ PRTL_SRWLOCK SRWLock);

typedef errno_t(__cdecl *FuncTypeDef_strcpy_s)(_Out_writes_z_(_SizeInBytes) char *_Destination, _In_ rsize_t _SizeInBytes, _In_z_ char const *_Source);

typedef errno_t(__cdecl *FuncTypeDef_wcscpy_s)(_Out_writes_z_(_SizeInWords) wchar_t *_Destination, _In_ rsize_t _SizeInWords, _In_z_ wchar_t const *_Source);

typedef void *(__cdecl *FuncTypeDef_memset)(_Out_writes_bytes_all_(_Size) void *_Dst, _In_ int _Val, _In_ size_t _Size);

typedef void *(__cdecl *FuncTypeDef_memcpy)(_Out_writes_bytes_all_(_Size) void *_Dst, _In_reads_bytes_(_Size) void const *_Src, _In_ size_t _Size);

typedef void *(__cdecl *FuncTypeDef_memmove)(_Out_writes_bytes_all_opt_(_Size) void *_Dst, _In_reads_bytes_opt_(_Size) void const *_Src, _In_ size_t _Size);

typedef VOID(__stdcall *FuncTypeDef_OutputDebugStringA)(_In_opt_ LPCSTR lpOutputString);

typedef VOID(__stdcall *FuncTypeDef_OutputDebugStringW)(_In_opt_ LPCWSTR lpOutputString);

typedef ULONGLONG(__stdcall *FuncTypeDef_GetTickCount64)(VOID);

typedef BOOL(__stdcall *FuncTypeDef_TerminateProcess)(_In_ HANDLE hProcess, _In_ UINT uExitCode);

typedef HANDLE(__stdcall *FuncTypeDef_CreateFileW)(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode,
                                                   _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition,
                                                   _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile);

typedef BOOL(__stdcall *FuncTypeDef_CloseHandle)(_In_ _Post_ptr_invalid_ HANDLE hObject);

typedef SIZE_T(__stdcall *FuncDef_VirtualQuery)(_In_opt_ LPCVOID lpAddress, _Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
                                                _In_ SIZE_T dwLength);

typedef int(__cdecl *FuncTypeDef_stdio_common_vsprintf_s)(_In_ unsigned __int64 _Options, _Out_writes_z_(_BufferCount) char *_Buffer, _In_ size_t _BufferCount,
                                                          _In_z_ _Printf_format_string_params_(2) char const *_Format, _In_opt_ _locale_t _Locale,
                                                          va_list _ArgList);

typedef int(__cdecl *FuncTypeDef_stdio_common_vswprintf_s)(_In_ unsigned __int64 _Options, _Out_writes_z_(_BufferCount) wchar_t *_Buffer,
                                                           _In_ size_t _BufferCount, _In_z_ _Printf_format_string_params_(2) wchar_t const *_Format,
                                                           _In_opt_ _locale_t _Locale, va_list _ArgList);

typedef void *(__cdecl *FuncTypeDef_malloc)(_In_ _CRT_GUARDOVERFLOW size_t _Size);

typedef size_t(__cdecl *FuncTypeDef_msize)(_Pre_notnull_ void *_Block);

typedef void(__cdecl *FuncTypeDef_free)(_Pre_maybenull_ _Post_invalid_ void *_Block);

typedef void *(__cdecl *FuncTypeDef_realloc)(_Pre_maybenull_ _Post_invalid_ void *_Block, _In_ _CRT_GUARDOVERFLOW size_t _Size);

typedef SHORT(__stdcall *FuncTypeDef_GetAsyncKeyState)(_In_ int vKey);

typedef int(__stdcall *FuncTypeDef_MessageBoxW)(_In_opt_ PVOID hWnd, _In_opt_ PCWSTR lpText, _In_opt_ PCWSTR lpCaption, _In_ UINT uType);

typedef BOOL(__stdcall *FuncDef_MiniDumpWriteDump)(_In_ HANDLE hProcess, _In_ DWORD ProcessId, _In_ HANDLE hFile, _In_ MINIDUMP_TYPE DumpType,
                                                   _In_opt_ PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
                                                   _In_opt_ PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
                                                   _In_opt_ PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

#define YEAR (((((__DATE__[7] - '0') * 10 + (__DATE__[8] - '0')) * 10 + (__DATE__[9] - '0')) * 10 + (__DATE__[10] - '0')))
#define MONTH                                                                                                                                                  \
    (__DATE__[2] == 'n'   ? (__DATE__[1] == 'a' ? 1 : 6)                                                                                                       \
     : __DATE__[2] == 'b' ? 2                                                                                                                                  \
     : __DATE__[2] == 'r' ? (__DATE__[0] == 'M' ? 3 : 4)                                                                                                       \
     : __DATE__[2] == 'y' ? 5                                                                                                                                  \
     : __DATE__[2] == 'l' ? 7                                                                                                                                  \
     : __DATE__[2] == 'g' ? 8                                                                                                                                  \
     : __DATE__[2] == 'p' ? 9                                                                                                                                  \
     : __DATE__[2] == 't' ? 10                                                                                                                                 \
     : __DATE__[2] == 'v' ? 11                                                                                                                                 \
                          : 12)
#define DAY ((__DATE__[4] == ' ' ? 0 : __DATE__[4] - '0') * 10 + (__DATE__[5] - '0'))
#define HOUR ((__TIME__[0] - '0') * 10 + (__TIME__[1] - '0'))
#define MINUTE ((__TIME__[3] - '0') * 10 + (__TIME__[4] - '0'))

#define BUILD_VERSION_CODE (YEAR * 100000000ULL + MONTH * 1000000ULL + DAY * 10000ULL + HOUR * 100ULL + MINUTE)

typedef struct _GENERIC_FUNCTION_TABLE
{
    // ntdll.dll
    FuncTypeDef_RtlInitializeCriticalSection RtlInitializeCriticalSection;
    FuncTypeDef_RtlEnterCriticalSection RtlEnterCriticalSection;
    FuncTypeDef_RtlLeaveCriticalSection RtlLeaveCriticalSection;
    FuncTypeDef_RtlAcquireSRWLockExclusive RtlAcquireSRWLockExclusive;
    FuncTypeDef_RtlReleaseSRWLockExclusive RtlReleaseSRWLockExclusive;
    FuncTypeDef_RtlAcquireSRWLockShared RtlAcquireSRWLockShared;
    FuncTypeDef_RtlReleaseSRWLockShared RtlReleaseSRWLockShared;
    FuncTypeDef_RtlTryAcquireSRWLockExclusive RtlTryAcquireSRWLockExclusive;
    FuncTypeDef_strcpy_s strcpy_s;
    FuncTypeDef_wcscpy_s wcscpy_s;
    FuncTypeDef_memset memset;
    FuncTypeDef_memcpy memcpy;
    FuncTypeDef_memmove memmove;

    // KERNEL32.dll
    FuncTypeDef_OutputDebugStringA OutputDebugStringA;
    FuncTypeDef_OutputDebugStringW OutputDebugStringW;
    FuncTypeDef_GetTickCount64 GetTickCount64;
    FuncTypeDef_TerminateProcess TerminateProcess;
    FuncTypeDef_CreateFileW CreateFileW;
    FuncTypeDef_CloseHandle CloseHandle;
    FuncDef_VirtualQuery VirtualQuery;
    // ucrtbase.dll
    FuncTypeDef_stdio_common_vsprintf_s stdio_common_vsprintf_s;
    FuncTypeDef_stdio_common_vswprintf_s stdio_common_vswprintf_s;
    FuncTypeDef_malloc malloc;
    FuncTypeDef_free free;
    FuncTypeDef_msize msize;
    FuncTypeDef_realloc realloc;

    // user32.dll
    FuncTypeDef_GetAsyncKeyState GetAsyncKeyState;

    // dbgcore.dll
    FuncDef_MiniDumpWriteDump MiniDumpWriteDump;

    // user32.dll (消息框测试扩展，追加到表尾保持既有 ABI 顺序)
    FuncTypeDef_MessageBoxW MessageBoxW;

    // EncryptedU64 RtlInitializeCriticalSection;
    // EncryptedU64 RtlEnterCriticalSection;
    // EncryptedU64 RtlLeaveCriticalSection;
    // EncryptedU64 RtlAcquireSRWLockExclusive;
    // EncryptedU64 RtlReleaseSRWLockExclusive;
    // EncryptedU64 RtlAcquireSRWLockShared;
    // EncryptedU64 RtlReleaseSRWLockShared;
    // EncryptedU64 RtlTryAcquireSRWLockExclusive;
    // EncryptedU64 strcpy_s;
    // EncryptedU64 wcscpy_s;
    // EncryptedU64 memset;
    // EncryptedU64 memcpy;
    // EncryptedU64 memmove;

    ////KERNEL32.dll
    // EncryptedU64 OutputDebugStringA;
    // EncryptedU64 OutputDebugStringW;
    // EncryptedU64 GetTickCount64;
    // EncryptedU64 TerminateProcess;
    // EncryptedU64 CreateFileW;
    // EncryptedU64 CloseHandle;
    ////ucrtbase.dll
    // EncryptedU64 stdio_common_vsprintf_s;
    // EncryptedU64 stdio_common_vswprintf_s;
    // EncryptedU64 malloc;
    // EncryptedU64 free;
    // EncryptedU64 msize;
    // EncryptedU64 realloc;

    ////user32.dll
    // EncryptedU64 GetAsyncKeyState;

    ////dbgcore.dll
    // EncryptedU64 MiniDumpWriteDump;
} GENERIC_FUNCTION_TABLE;

typedef struct _GENERIC_OFFSET_TABLE
{
    // EncryptedU32 Class_UEngine;
    // EncryptedU32 Class_UWorld;
    // EncryptedU32 Class_UCanvas;
    // EncryptedU32 Class_GName;

    ////---------------------------------------------GName加密
    // EncryptedU32 Call_NameDecodeWCHAR;
    // EncryptedU32 Call_NameDecodeCHAR;
    ////---------------------------------------------GName加密

    //
    ////---------------------------------------------常规加密指针
    // EncryptedU32 Class_NormalDecodePtrMode;
    // EncryptedU32 Class_NormalDecodeCaseCallParame;
    // EncryptedU32 Class_NormalDecodeCase2;
    // EncryptedU32 Class_NormalDecodeCase3;

    // EncryptedU32 Class_NormalDecodeParame;
    // EncryptedU32 Class_NormalDecodeFlag;
    // EncryptedU32 Class_NormalDecodePtrFunc;
    ////---------------------------------------------常规加密

    ////---------------------------------------------动态加密
    ////.std:000000015411E1F0 off_15411E1F0   dq offset ?Value@External@v8_qjs@@QEBAPEAXXZ
    // EncryptedU32 Class_DynamicDecodeCallPtr;
    ////.std:00000001409E4960 ?Value@External@v8_qjs@@QEBAPEAXXZ proc near
    ////未加密的地址 是一个 mov     rax, [rcx] ret
    // EncryptedU32 Call_CryptoOffAddress;
    ////---------------------------------------------动态加密
    ////---------------------------------------------ComponentToWorld解密
    // EncryptedU32 Class_CTWWritePtrHook;
    ////---------------------------------------------ComponentToWorld解密
    ////---------------------------------------------坐标解密
    // EncryptedU32 Class_PosWritePtrHook;
    // EncryptedU32 Class_PosWritePtrOriginal;
    ////CALL
    // EncryptedU32 Class_PosASMCallPtr1;
    // EncryptedU32 Class_PosASMCallPtr2;
    // EncryptedU32 Class_PosASMCallAddress1;
    // EncryptedU32 Class_PosASMCallAddress2;
    ////---------------------------------------------坐标解密
    // EncryptedU32 OffSet_AActor_ObjectID;
    // EncryptedU32 OffSet_AActor_RootComponent;
    // EncryptedU32 OffSet_UWorld_PersistentLevel;
    // EncryptedU32 OffSet_UWorld_Levels;
    // EncryptedU32 OffSet_UWorld_GameState;
    // EncryptedU32 OffSet_ADFMGameState_DFMGamePlayerMode;
    // EncryptedU32 OffSet_UWorld_OwningGameInstance;
    // EncryptedU32 OffSet_UGameInstance_LocalPlayers;
    // EncryptedU32 OffSet_UPlayer_PlayerController;
    // EncryptedU32 OffSet_APlayerController_AcknowledgedPawn;
    // EncryptedU32 OffSet_APlayerController_PlayerCameraManager;
    // EncryptedU32 OffSet_APlayerCameraManager_CameraCachePrivate;
    // EncryptedU32 OffSet_FCameraCacheEntry_POV;
    // EncryptedU32 OffSet_FMinimalViewInfo_Location;
    // EncryptedU32 OffSet_ULevel_Tarray;
    // EncryptedU32 OffSet_ACHARACTER_Mesh;
    // EncryptedU32 OffSet_USceneComponent_Bounds;
    // EncryptedU32 OffSet_USceneComponent_RelativeLocation;
    // EncryptedU32 OffSet_USceneComponent_ComponentToWorld;
    // EncryptedU32 OffSet_ADFMCharacter_DFMHealthDataComponent;
    // EncryptedU32 OffSet_UGPHealthDataComponent_HealthSet;
    // EncryptedU32 OffSet_ADFMCharacter_CharacterEquipComponentCache;
    // EncryptedU32 OffSet_AGPCharacterBase_CacheCurWeapon;
    // EncryptedU32 OffSet_AWeaponBase_WeaponFuncComponentFiring;
    // EncryptedU32 OffSet_UGPWeaponFuncComponentFiring_CurrentFireMode;
    // EncryptedU32 OffSet_UGPWeaponFireModeBase_Params_0;
    // EncryptedU32 OffSet_UGPWeaponFireModeParamsBase_BulletBaseParam;
    // EncryptedU32 OffSet_FWeaponBulletBaseInitParam_InitSpeed;

    ULONG Class_UWorld;
    ULONG Class_GName;
    ULONG Call_NameDecodeWCHAR;
    ULONG Call_NameDecodeCHAR;
    ULONG OffSet_AActor_ObjectID;
    ULONG OffSet_UWorld_PersistentLevel;
    ULONG OffSet_ULevel_Tarray;
    ULONG OffSet_ACHARACTER_Mesh;
    ULONG OffSet_USceneComponent_ComponentToWorld;
} GENERIC_OFFSET_TABLE;

typedef struct _GENERIC_RUNTIME_PARAMS
{
    // ULONGLONG CurrentTick;
    // ULONGLONG FrameCount;
    // ULONGLONG LastFrameCount;
    // ULONGLONG LastTickCount;
    ULONG_PTR HostImageBase;
    ULONG_PTR SpoofCallRaxAddRsp28Ret;
    ULONG_PTR SpoofJmpQwordPtrRbx;
    ULONG JmpFrameSize;
    ULONG Reserved0;
    RTL_CRITICAL_SECTION ComponentToWorldCS;
    ULONG_PTR UWorld;
    struct
    {
        ULONG_PTR Address;
        ULONG CleanupBytes;
        ULONG Reserved;
    } SpoofCallGadgets[VT_SHELLCODE_NATIVE_GADGET_COUNT];
} GENERIC_RUNTIME_PARAMS;

#pragma pack(push, 8)
namespace ShellCodeSpoof
{
struct SPOOF_CALL_CONTEXT
{
    ULONG64 FixupRip;
    ULONG64 SavedRbx;
    ULONG64 SavedRetAddr;
    ULONG64 CallRaxGadget;
    ULONG64 JmpRbxGadget;
    ULONG64 TargetFunc;
    ULONG64 OriginalRsp;
    ULONG64 SavedPrivateRsp;
    ULONG64 GhostRetVa;
    ULONG64 JmpFrameSize;
    ULONG64 ArgumentFrame;
    ULONG64 ReturnXmm0;
    ULONG64 NativeCleanupBytes;
    ULONG64 NativeGadgetTable;
};
} // namespace ShellCodeSpoof
#pragma pack(pop)

typedef struct _GENERIC_RUNTIME_DATA
{
    ULONG64 Version;
    ULONG64 XorKey;
    volatile LONG MessageShown;
    volatile LONG SpoofContextBusy;
    ShellCodeSpoof::SPOOF_CALL_CONTEXT SpoofContext;
} GENERIC_RUNTIME_DATA;

namespace ShellCodeSpoof
{
struct RuntimeSlot;
}

typedef struct _GENERIC_RUNTIME_CONTEXT
{
    GENERIC_RUNTIME_DATA *u;
    GENERIC_RUNTIME_PARAMS *p;
    GENERIC_FUNCTION_TABLE *Func;
    GENERIC_OFFSET_TABLE *Offset;
    ShellCodeSpoof::RuntimeSlot *SpoofSlot;
} GENERIC_RUNTIME_CONTEXT, *PGENERIC_RUNTIME_CONTEXT;

namespace SpoofCallDetail
{

// 8 字节原位加密：函数表保持原有强类型布局，不引入 24 字节包装对象。
inline ULONG64 DeriveSlotXorKey(ULONG64 masterKey, SIZE_T slotIndex) noexcept
{
    const ULONG64 salt = (static_cast<ULONG64>(slotIndex) + 1ULL) * 0x9E3779B97F4A7C15ULL;
    const ULONG shift = static_cast<ULONG>((slotIndex * 7u) & 63u);
    const ULONG64 rotated = shift ? ((masterKey << shift) | (masterKey >> (64u - shift))) : masterKey;
    return rotated ^ salt;
}

inline ULONG_PTR CryptIndexedPtr(ULONG_PTR value, ULONG64 masterKey, SIZE_T slotIndex) noexcept
{
    return value ? static_cast<ULONG_PTR>(value ^ DeriveSlotXorKey(masterKey, slotIndex)) : 0;
}

template <typename TFuncPtr> inline TFuncPtr DecryptFuncSlot(const PGENERIC_RUNTIME_CONTEXT userVar, const TFuncPtr *memberAddr, SIZE_T slotIndex) noexcept
{
    if (!userVar || !userVar->u || !memberAddr)
        return nullptr;
    const ULONG_PTR cipher = *reinterpret_cast<const volatile ULONG_PTR *>(memberAddr);
    return reinterpret_cast<TFuncPtr>(CryptIndexedPtr(cipher, userVar->u->XorKey, slotIndex));
}

} // namespace SpoofCallDetail

#define XOR_FN(userVar, MemberName)                                                                                                                            \
    (::SpoofCallDetail::DecryptFuncSlot((userVar), &((userVar)->Func->MemberName), offsetof(GENERIC_FUNCTION_TABLE, MemberName) / sizeof(ULONG_PTR)))

#define VT_SPOOF_FN(userVar, MemberName, ...) (::SpoofCall((userVar), XOR_FN((userVar), MemberName) __VA_OPT__(, ) __VA_ARGS__))

inline void XDebugPrintA(IN GENERIC_RUNTIME_CONTEXT *&UserVar, IN const char *format, ...)
{
    const auto outputDebugStringA = XOR_FN(UserVar, OutputDebugStringA);
    const auto stdioCommonVsprintfS = XOR_FN(UserVar, stdio_common_vsprintf_s);
    if (!outputDebugStringA || !stdioCommonVsprintfS)
        return;
    char buffer[512];
    va_list args;
    va_start(args, format);
    stdioCommonVsprintfS(_CRT_INTERNAL_LOCAL_PRINTF_OPTIONS, buffer, 512, format, NULL, args);
    va_end(args);
    outputDebugStringA(buffer);
}

inline void XDebugPrintW(IN GENERIC_RUNTIME_CONTEXT *&UserVar, IN const wchar_t *format, ...)
{
    const auto outputDebugStringW = XOR_FN(UserVar, OutputDebugStringW);
    const auto stdioCommonVswprintfS = XOR_FN(UserVar, stdio_common_vswprintf_s);
    if (!outputDebugStringW || !stdioCommonVswprintfS)
        return;
    wchar_t buffer[512];
    va_list args;
    va_start(args, format);
    stdioCommonVswprintfS(_CRT_INTERNAL_LOCAL_PRINTF_OPTIONS, buffer, 512, format, NULL, args);
    va_end(args);
    outputDebugStringW(buffer);
}

#ifdef NRELEASE
#define DbgPrintA(UserVar, format, ...) XDebugPrintA(UserVar, "[VDBG] " format, ##__VA_ARGS__)
#define DbgPrintW(UserVar, format, ...) XDebugPrintW(UserVar, L"[VDBG] " format, ##__VA_ARGS__)
#else
// #define DbgPrintA(UserVar, format, ...)  XDebugPrintA(UserVar, "[VDBG] " format, ##__VA_ARGS__)
// #define DbgPrintW(UserVar, format, ...)  XDebugPrintW(UserVar, L"[VDBG] " format, ##__VA_ARGS__)
#define DbgPrintA(UserVar, format, ...) ((void)0)
#define DbgPrintW(UserVar, format, ...) ((void)0)
#endif

SIZE_T Utils_Strlen(PCSTR Str);

BOOLEAN Utils_GetModuleExport(IN ULONG_PTR BaseAddress, IN ULONG U32FunctionName, OUT ULONG_PTR *FunctionAddress);

ULONG Utils_HashStringImulMagicExA(IN const PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);

ULONG Utils_HashStringImulMagicExW(IN const PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase);

BOOLEAN Utils_HashStringImulMagicFindA(IN const PCHAR s, IN SIZE_T Length, IN ULONG FindData, IN SIZE_T FindSize);

BOOLEAN Utils_HashStringImulMagicFindW(IN const PWCHAR s, IN SIZE_T Length, IN ULONG FindData, IN SIZE_T FindSize);
