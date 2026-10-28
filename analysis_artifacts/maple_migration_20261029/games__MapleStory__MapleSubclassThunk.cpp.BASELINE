#include "MapleSubclassThunk.h"
#include "MapleRxPayloadImage.h"
#include "MapleMemory.h"
#include "../../Core/DriverCore.h"
#include "../../Security/Utils.h"

// 内核未导出/动态解析例程原型 (严格遵循 Zero-IAT 规范，运行时由 ntoskrnl.exe 导出表解析)
typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(_In_opt_ PVOID NormalContext, _In_opt_ PVOID SystemArgument1,
                                      _In_opt_ PVOID SystemArgument2);
typedef VOID(NTAPI *PKKERNEL_ROUTINE)(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
                                      _Inout_ PVOID *NormalContext, _Inout_ PVOID *SystemArgument1,
                                      _Inout_ PVOID *SystemArgument2);
typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(_In_ PKAPC Apc);

typedef NTSTATUS(NTAPI *PFN_ZwCreateSection)(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                             _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                             _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
                                             _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);
typedef NTSTATUS(NTAPI *PFN_PsLookupThreadByThreadId)(_In_ HANDLE ThreadId, _Outptr_ PETHREAD *Thread);
typedef HANDLE(NTAPI *PFN_PsGetThreadProcessId)(_In_ PETHREAD Thread);
typedef PVOID(NTAPI *PFN_PsGetThreadWin32Thread)(_In_ PETHREAD Thread);
typedef PVOID(NTAPI *PFN_PsGetProcessPeb)(_In_ PEPROCESS Process);
typedef VOID(NTAPI *PFN_KeInitializeApc)(_Out_ PRKAPC Apc, _In_ PRKTHREAD Thread, _In_ KAPC_ENVIRONMENT Environment,
                                         _In_ PKKERNEL_ROUTINE KernelRoutine, _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
                                         _In_opt_ PKNORMAL_ROUTINE NormalRoutine, _In_ KPROCESSOR_MODE ApcMode,
                                         _In_opt_ PVOID NormalContext);
typedef BOOLEAN(NTAPI *PFN_KeInsertQueueApc)(_Inout_ PRKAPC Apc, _In_opt_ PVOID SystemArgument1,
                                             _In_opt_ PVOID SystemArgument2, _In_ KPRIORITY Increment);
typedef BOOLEAN(NTAPI *PFN_KeRemoveQueueApc)(_Inout_ PKAPC Apc);
typedef BOOLEAN(NTAPI *PFN_KeTestAlertThread)(_In_ KPROCESSOR_MODE AlertMode);

typedef struct _MAPLE_VM_RANGE_ENTRY
{
    PVOID VirtualAddress;
    SIZE_T NumberOfBytes;
} MAPLE_VM_RANGE_ENTRY, *PMAPLE_VM_RANGE_ENTRY;

typedef struct _MAPLE_CFG_CALL_TARGET_INFO
{
    ULONG_PTR Offset;
    ULONG_PTR Flags; // 0x1 = CFG_CALL_TARGET_VALID
} MAPLE_CFG_CALL_TARGET_INFO, *PMAPLE_CFG_CALL_TARGET_INFO;

typedef struct _MAPLE_VM_CFG_TARGET_INFORMATION
{
    ULONG NumberOfTargets;                       // +0x00: 目标数量 (必须 > 0)
    ULONG Flags;                                 // +0x04: 标志位 (必须为 0)
    PULONG NumberOfOffsetsSuccessfullyProcessed; // +0x08: 输出成功处理的数量指针
    PMAPLE_CFG_CALL_TARGET_INFO CallTargets;     // +0x10: CFG_CALL_TARGET_INFO 数组指针
    PVOID Section;                               // +0x18: 可选 Section 句柄 (NULL)
    ULONG64 FileOffset;                          // +0x20: 偏移 (0)
} MAPLE_VM_CFG_TARGET_INFORMATION, *PMAPLE_VM_CFG_TARGET_INFORMATION;
static_assert(sizeof(MAPLE_VM_CFG_TARGET_INFORMATION) == 0x28, "MAPLE_VM_CFG_TARGET_INFORMATION must be 0x28 bytes");

typedef NTSTATUS(NTAPI *PFN_ZwSetInformationVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG VmInformationClass, // VmCfgCallTargetInformation = 2
    _In_ ULONG_PTR NumberOfEntries,
    _In_ PMAPLE_VM_RANGE_ENTRY VirtualAddresses,
    _In_ PVOID VmInformation,
    _In_ ULONG VmInformationLength);

static ULONG64 g_TargetCr3 = 0;
static ULONG64 g_ImageBase = 0;
static ULONG64 g_ClientSocket = 0;
static ULONG64 g_TargetHwnd = 0;
static ULONG g_TargetPid = 0;

static HANDLE g_hRxSection = NULL;
static HANDLE g_hRwSection = NULL;
static ULONG64 g_RxSectionUserBase = 0;
static ULONG64 g_RwSectionUserBase = 0;
static PMAPLE_SHARED_THUNK_DATA g_SharedKernelView = NULL;
static BOOLEAN g_IsInstalled = FALSE;

static BOOLEAN ResolveKernelExportByName(PCSTR ExportName, PVOID *OutRoutine)
{
    if (!ExportName || !OutRoutine || !g_pGlobalUserVar || !g_pGlobalUserVar->KernelBase.QuadPart)
        return FALSE;

    *OutRoutine = NULL;
    const SIZE_T len = SafeStrlen(ExportName);
    const ULONG hash = Utils::HashStringA(const_cast<PCHAR>(ExportName), len, TRUE);
    ULONG_PTR addr = 0;
    if (!Utils::GetModuleExport(static_cast<ULONG_PTR>(g_pGlobalUserVar->KernelBase.QuadPart), hash, &addr) || !addr)
        return FALSE;

    *OutRoutine = reinterpret_cast<PVOID>(addr);
    return TRUE;
}

#define MAPLE_MAX_APC_SLOTS 8
static KAPC g_UserApcSlots[MAPLE_MAX_APC_SLOTS] = {};
static KAPC g_KernelApcSlots[MAPLE_MAX_APC_SLOTS] = {};
static volatile LONG g_UserApcQueued[MAPLE_MAX_APC_SLOTS] = {};
static volatile LONG g_KernelApcQueued[MAPLE_MAX_APC_SLOTS] = {};
static PFN_KeTestAlertThread g_pfnKeTestAlertThread = NULL;
static PFN_KeRemoveQueueApc g_pfnKeRemoveQueueApc = NULL;

static VOID NTAPI MapleUserApcKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext,
                                            PVOID *SystemArgument1, PVOID *SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    const ULONG_PTR idx = static_cast<ULONG_PTR>(Apc - g_UserApcSlots);
    if (idx < MAPLE_MAX_APC_SLOTS)
    {
        InterlockedExchange(&g_UserApcQueued[idx], 0);
    }
}

static VOID NTAPI MapleUserApcRundownRoutine(PKAPC Apc)
{
    const ULONG_PTR idx = static_cast<ULONG_PTR>(Apc - g_UserApcSlots);
    if (idx < MAPLE_MAX_APC_SLOTS)
    {
        InterlockedExchange(&g_UserApcQueued[idx], 0);
    }
}

static VOID NTAPI MapleKernelBoosterRoutine(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext,
                                            PVOID *SystemArgument1, PVOID *SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    if (NormalRoutine)
    {
        *NormalRoutine = NULL;
    }
    if (g_pfnKeTestAlertThread)
    {
        g_pfnKeTestAlertThread(UserMode);
    }
    const ULONG_PTR idx = static_cast<ULONG_PTR>(Apc - g_KernelApcSlots);
    if (idx < MAPLE_MAX_APC_SLOTS)
    {
        InterlockedExchange(&g_KernelApcQueued[idx], 0);
    }
}

static VOID NTAPI MapleKernelBoosterRundownRoutine(PKAPC Apc)
{
    const ULONG_PTR idx = static_cast<ULONG_PTR>(Apc - g_KernelApcSlots);
    if (idx < MAPLE_MAX_APC_SLOTS)
    {
        InterlockedExchange(&g_KernelApcQueued[idx], 0);
    }
}

static VOID CancelAllPendingApcs()
{
    for (ULONG i = 0; i < MAPLE_MAX_APC_SLOTS; ++i)
    {
        if (InterlockedCompareExchange(&g_KernelApcQueued[i], 0, 0) != 0)
        {
            if (g_pfnKeRemoveQueueApc && g_pfnKeRemoveQueueApc(&g_KernelApcSlots[i]))
            {
                InterlockedExchange(&g_KernelApcQueued[i], 0);
            }
        }
        if (InterlockedCompareExchange(&g_UserApcQueued[i], 0, 0) != 0)
        {
            if (g_pfnKeRemoveQueueApc && g_pfnKeRemoveQueueApc(&g_UserApcSlots[i]))
            {
                InterlockedExchange(&g_UserApcQueued[i], 0);
            }
        }
    }

    BOOLEAN hadActive = FALSE;
    for (ULONG spin = 0; spin < 1000000; ++spin)
    {
        LONG active = 0;
        for (ULONG i = 0; i < MAPLE_MAX_APC_SLOTS; ++i)
        {
            active |= InterlockedCompareExchange(&g_KernelApcQueued[i], 0, 0);
            active |= InterlockedCompareExchange(&g_UserApcQueued[i], 0, 0);
        }
        if (active == 0)
            break;
        hadActive = TRUE;
        _mm_pause();
    }

    if (hadActive && g_pGlobalUserVar && g_pGlobalUserVar->Func.KeDelayExecutionThread)
    {
        LARGE_INTEGER shortDelay = {};
        shortDelay.QuadPart = -100000LL; // 10ms 确保并发核上的 APC 回调指令完全退栈
        g_pGlobalUserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &shortDelay);
    }
}

// 从独立 C++ 项目 MapleRxPayload 编译产出的 PE 映像中解析 SubclassInitEntry 与 CustomWndProc 导出 RVA
NTSTATUS MapleSubclassThunk::ResolvePayloadExports(PULONG OutInitEntryRva, PULONG OutCustomWndProcRva)
{
    if (!OutInitEntryRva || !OutCustomWndProcRva)
        return STATUS_INVALID_PARAMETER;

    *OutInitEntryRva = g_MapleRxPayloadSubclassInitRva;
    *OutCustomWndProcRva = g_MapleRxPayloadCustomWndProcRva;

    if (*OutInitEntryRva == 0 || *OutCustomWndProcRva == 0)
        return STATUS_PROCEDURE_NOT_FOUND;

    DBG("[+] [MapleThunk] ResolvePayloadExports: C++ MapleRxPayload.dll exports (SubclassInitEntry=+0x%lX, "
        "CustomWndProc=+0x%lX)",
        *OutInitEntryRva, *OutCustomWndProcRva);
    return STATUS_SUCCESS;
}

// 解析目标进程已加载 user32.dll 的 SetWindowLongPtrW / CallWindowProcW / PostMessageW / GetWindowThreadProcessId
NTSTATUS MapleSubclassThunk::ResolveUser32Exports(ULONG64 TargetCr3, PEPROCESS TargetProcess,
                                                  PULONG64 OutSetWindowLongPtrW, PULONG64 OutCallWindowProcW,
                                                  PULONG64 OutPostMessageW, PULONG64 OutGetWindowThreadProcessId)
{
    if (!TargetCr3 || !TargetProcess || !OutSetWindowLongPtrW || !OutCallWindowProcW || !OutPostMessageW ||
        !OutGetWindowThreadProcessId)
        return STATUS_INVALID_PARAMETER;

    *OutSetWindowLongPtrW = 0;
    *OutCallWindowProcW = 0;
    *OutPostMessageW = 0;
    *OutGetWindowThreadProcessId = 0;

    PFN_PsGetProcessPeb pfnPsGetProcessPeb = NULL;
    if (!ResolveKernelExportByName("PsGetProcessPeb", reinterpret_cast<PVOID *>(&pfnPsGetProcessPeb)) ||
        !pfnPsGetProcessPeb)
        return STATUS_NOT_SUPPORTED;

    const ULONG64 pebAddr = reinterpret_cast<ULONG64>(pfnPsGetProcessPeb(TargetProcess));
    if (!pebAddr)
        return STATUS_NOT_FOUND;

    ULONG64 ldrAddr = 0;
    if (!MapleMemory::Read(pebAddr + 0x18, &ldrAddr) || !ldrAddr)
        return STATUS_NOT_FOUND;

    // PEB_LDR_DATA.InLoadOrderModuleList (+0x10)
    ULONG64 listHead = ldrAddr + 0x10;
    ULONG64 flink = 0;
    if (!MapleMemory::Read(listHead, &flink) || !flink)
        return STATUS_NOT_FOUND;

    ULONG64 user32Base = 0;
    for (ULONG i = 0; i < 256 && flink && flink != listHead; ++i)
    {
        ULONG64 dllBase = 0;
        USHORT baseNameLen = 0;
        ULONG64 baseNameBuf = 0;
        MapleMemory::Read(flink + 0x30, &dllBase);
        MapleMemory::Read(flink + 0x58, &baseNameLen);
        MapleMemory::Read(flink + 0x60, &baseNameBuf);

        if (dllBase && baseNameBuf && baseNameLen >= 20 && baseNameLen <= 64)
        {
            WCHAR nameBuf[33] = {};
            if (MapleMemory::ReadBuffer(baseNameBuf, nameBuf, baseNameLen))
            {
                if (Utils::HashStringW(nameBuf, baseNameLen / sizeof(WCHAR), TRUE) ==
                    Utils::HashStringW(const_cast<PWCHAR>(L"user32.dll"), 10, TRUE))
                {
                    user32Base = dllBase;
                    break;
                }
            }
        }

        if (!MapleMemory::Read(flink, &flink))
            break;
    }

    if (!user32Base)
    {
        DBG("[-] [MapleThunk] ResolveUser32Exports: user32.dll not found in target PEB");
        return STATUS_NOT_FOUND;
    }

    IMAGE_DOS_HEADER dos = {};
    IMAGE_NT_HEADERS64 nt = {};
    if (!MapleMemory::ReadBuffer(user32Base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        !MapleMemory::ReadBuffer(user32Base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    const IMAGE_DATA_DIRECTORY expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress || !expDir.Size)
        return STATUS_NOT_FOUND;

    IMAGE_EXPORT_DIRECTORY exp = {};
    if (!MapleMemory::ReadBuffer(user32Base + expDir.VirtualAddress, &exp, sizeof(exp)))
        return STATUS_NOT_FOUND;

    const ULONG hashSetWndLong = Utils::HashStringA(const_cast<PCHAR>("SetWindowLongPtrW"), 17, TRUE);
    const ULONG hashCallWndProc = Utils::HashStringA(const_cast<PCHAR>("CallWindowProcW"), 15, TRUE);
    const ULONG hashPostMsg = Utils::HashStringA(const_cast<PCHAR>("PostMessageW"), 12, TRUE);
    const ULONG hashGetWndTid = Utils::HashStringA(const_cast<PCHAR>("GetWindowThreadProcessId"), 24, TRUE);

    for (ULONG i = 0; i < exp.NumberOfNames && i < 4096; ++i)
    {
        ULONG nameRva = 0;
        USHORT ordinalIdx = 0;
        if (!MapleMemory::Read(user32Base + exp.AddressOfNames + i * sizeof(ULONG), &nameRva) || !nameRva ||
            !MapleMemory::Read(user32Base + exp.AddressOfNameOrdinals + i * sizeof(USHORT), &ordinalIdx))
        {
            continue;
        }

        CHAR fnName[64] = {};
        if (!MapleMemory::ReadBuffer(user32Base + nameRva, fnName, sizeof(fnName) - 1))
            continue;

        const ULONG fnHash = Utils::HashStringA(fnName, SafeStrlen(fnName), TRUE);
        if (fnHash == hashSetWndLong || fnHash == hashCallWndProc || fnHash == hashPostMsg || fnHash == hashGetWndTid)
        {
            ULONG fnRva = 0;
            if (ordinalIdx < exp.NumberOfFunctions &&
                MapleMemory::Read(user32Base + exp.AddressOfFunctions + ordinalIdx * sizeof(ULONG), &fnRva) && fnRva)
            {
                const ULONG64 fnVa = user32Base + fnRva;
                if (fnHash == hashSetWndLong)
                    *OutSetWindowLongPtrW = fnVa;
                else if (fnHash == hashCallWndProc)
                    *OutCallWindowProcW = fnVa;
                else if (fnHash == hashPostMsg)
                    *OutPostMessageW = fnVa;
                else if (fnHash == hashGetWndTid)
                    *OutGetWindowThreadProcessId = fnVa;
            }
        }

        if (*OutSetWindowLongPtrW && *OutCallWindowProcW && *OutPostMessageW && *OutGetWindowThreadProcessId)
            break;
    }

    if (!*OutSetWindowLongPtrW || !*OutCallWindowProcW)
    {
        DBG("[-] [MapleThunk] ResolveUser32Exports: Failed to resolve SetWindowLongPtrW/CallWindowProcW");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    DBG("[+] [MapleThunk] ResolveUser32Exports: user32=0x%llX SetWindowLongPtrW=0x%llX CallWindowProcW=0x%llX "
        "PostMessageW=0x%llX GetWindowThreadProcessId=0x%llX",
        user32Base, *OutSetWindowLongPtrW, *OutCallWindowProcW, *OutPostMessageW, *OutGetWindowThreadProcessId);
    return STATUS_SUCCESS;
}

// 1. 驱动将独立 C++ 项目编译产出的 MapleRxPayload.dll 以 SEC_IMAGE (PAGE_EXECUTE_READ) 映射进目标，同时创建独立 RW
// 共享节双端映射
NTSTATUS MapleSubclassThunk::MapSectionsIntoTarget(HANDLE TargetPid, PULONG64 OutRxUserBase, PULONG64 OutRwUserBase)
{
    if (!TargetPid || !OutRxUserBase || !OutRwUserBase || !g_pGlobalUserVar)
        return STATUS_INVALID_PARAMETER;

    *OutRxUserBase = 0;
    *OutRwUserBase = 0;

    PFN_ZwCreateSection pfnZwCreateSection = NULL;
    if (!ResolveKernelExportByName("ZwCreateSection", reinterpret_cast<PVOID *>(&pfnZwCreateSection)) ||
        !pfnZwCreateSection)
        return STATUS_NOT_SUPPORTED;

    // 1. 打开目标进程句柄并创建 RW 共享节，借用 0x20000 视图探测一块连续空闲的 128KB (64KB RX + 64KB RW) 64KB 对齐地址区间
    OBJECT_ATTRIBUTES procOa = {};
    InitializeObjectAttributes(&procOa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    CLIENT_ID cid = {};
    cid.UniqueProcess = TargetPid;
    HANDLE hProcess = NULL;
    NTSTATUS status = g_pGlobalUserVar->Func.ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &procOa, &cid);
    if (!NT_SUCCESS(status) || !hProcess)
        return status;

    LARGE_INTEGER rwMaxSize = {};
    rwMaxSize.QuadPart = 0x20000;
    status = pfnZwCreateSection(&g_hRwSection, SECTION_ALL_ACCESS, NULL, &rwMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status) || !g_hRwSection)
    {
        g_pGlobalUserVar->Func.ZwClose(hProcess);
        return status;
    }

    PVOID probeBase = NULL;
    SIZE_T probeSize = 0x20000;
    status = g_pGlobalUserVar->Func.ZwMapViewOfSection(g_hRwSection, hProcess, &probeBase, 0, 0x20000, NULL, &probeSize,
                                                       ViewUnmap, 0, PAGE_READWRITE);
    if (NT_SUCCESS(status) && probeBase)
    {
        g_pGlobalUserVar->Func.ZwUnmapViewOfSection(hProcess, probeBase);
    }
    else
    {
        probeBase = reinterpret_cast<PVOID>(0x00007FF580000000ULL);
    }

    // 2. 将探测到的空闲基址写入 PE OptionalHeader.ImageBase 并清除 DYNAMIC_BASE (0x0040)，确保 SEC_IMAGE 映射基址与 +0x10000 邻接节零冲突
    static UCHAR peImageBuf[sizeof(g_MapleRxPayloadBytes)];
    RtlCopyMemory(peImageBuf, g_MapleRxPayloadBytes, sizeof(g_MapleRxPayloadBytes));
    const ULONG peOffset = *reinterpret_cast<const ULONG *>(peImageBuf + 0x3C);
    if (peOffset + 96 <= sizeof(peImageBuf))
    {
        *reinterpret_cast<ULONG64 *>(peImageBuf + peOffset + 48) = reinterpret_cast<ULONG64>(probeBase);
        *reinterpret_cast<USHORT *>(peImageBuf + peOffset + 94) &= static_cast<USHORT>(~0x0040U);
    }

    // 3. 轮询独立槽位写出微型 PE 并先关闭写句柄，再以纯只读打开创建 SEC_IMAGE，规避 0xC0000043 (STATUS_SHARING_VIOLATION)
    WCHAR filePathBuf[64] = L"\\SystemRoot\\System32\\drivers\\mswsk_rx_00.dll";
    static const WCHAR kHexChars[] = L"0123456789ABCDEF";
    status = STATUS_SHARING_VIOLATION;

    for (ULONG slot = 0; slot < 64; ++slot)
    {
        if (slot == 0)
        {
            RtlCopyMemory(filePathBuf, L"\\SystemRoot\\System32\\drivers\\mswsk_rx.dll",
                          sizeof(L"\\SystemRoot\\System32\\drivers\\mswsk_rx.dll"));
        }
        else
        {
            RtlCopyMemory(filePathBuf, L"\\SystemRoot\\System32\\drivers\\mswsk_rx_00.dll",
                          sizeof(L"\\SystemRoot\\System32\\drivers\\mswsk_rx_00.dll"));
            filePathBuf[38] = kHexChars[(slot >> 4) & 0xF];
            filePathBuf[39] = kHexChars[slot & 0xF];
        }

        UNICODE_STRING uFilePath = {};
        SafeInitUnicodeString(&uFilePath, filePathBuf);
        OBJECT_ATTRIBUTES fileOa = {};
        InitializeObjectAttributes(&fileOa, &uFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        IO_STATUS_BLOCK iosb = {};
        HANDLE hWriteFile = NULL;

        status = g_pGlobalUserVar->Func.ZwCreateFile(
            &hWriteFile, GENERIC_WRITE | SYNCHRONIZE, &fileOa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status) || !hWriteFile)
            continue;

        LARGE_INTEGER byteOffset = {};
        status = g_pGlobalUserVar->Func.ZwWriteFile(hWriteFile, NULL, NULL, NULL, &iosb, peImageBuf,
                                                    g_MapleRxPayloadSize, &byteOffset, NULL);
        g_pGlobalUserVar->Func.ZwClose(hWriteFile);
        if (!NT_SUCCESS(status))
            continue;

        HANDLE hReadFile = NULL;
        status = g_pGlobalUserVar->Func.ZwCreateFile(
            &hReadFile, GENERIC_READ | SYNCHRONIZE, &fileOa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (NT_SUCCESS(status) && hReadFile)
        {
            status = pfnZwCreateSection(&g_hRxSection, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_QUERY, NULL,
                                        NULL, PAGE_EXECUTE_READ, SEC_IMAGE, hReadFile);
            g_pGlobalUserVar->Func.ZwClose(hReadFile);
            if (NT_SUCCESS(status) && g_hRxSection)
                break;
        }
    }

    if (!NT_SUCCESS(status) || !g_hRxSection)
    {
        DBG("[-] [MapleThunk] MapSectionsIntoTarget: SEC_IMAGE section creation failed (0x%08X)", status);
        g_pGlobalUserVar->Func.ZwClose(g_hRwSection);
        g_hRwSection = NULL;
        g_pGlobalUserVar->Func.ZwClose(hProcess);
        return status;
    }

    // 4. 视图 1：映射 RW 共享节到当前 System 内核进程空间 (0x4000 字节)
    PVOID kernelRwBase = NULL;
    SIZE_T kernelRwSize = 0x4000;
    status = g_pGlobalUserVar->Func.ZwMapViewOfSection(g_hRwSection, ZwCurrentProcess(), &kernelRwBase, 0, 0x4000, NULL,
                                                       &kernelRwSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status) || !kernelRwBase)
    {
        g_pGlobalUserVar->Func.ZwClose(g_hRwSection);
        g_hRwSection = NULL;
        g_pGlobalUserVar->Func.ZwClose(hProcess);
        g_pGlobalUserVar->Func.ZwClose(g_hRxSection);
        g_hRxSection = NULL;
        return status;
    }

    // 视图 2：成对映射 SEC_IMAGE RX (probeBase) 与紧邻 +0x10000 的 RW 共享节
    PVOID rxBase = NULL;
    SIZE_T rxViewSize = 0;
    status = g_pGlobalUserVar->Func.ZwMapViewOfSection(g_hRxSection, hProcess, &rxBase, 0, 0, NULL, &rxViewSize,
                                                       ViewUnmap, 0, PAGE_EXECUTE_READ);
    PVOID userRwBase = NULL;
    if (NT_SUCCESS(status) && rxBase)
    {
        userRwBase = reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(rxBase) + MapleLayout::RxToRwSectionOffset);
        SIZE_T userRwSize = 0x4000;
        status = g_pGlobalUserVar->Func.ZwMapViewOfSection(g_hRwSection, hProcess, &userRwBase, 0, 0x4000, NULL,
                                                           &userRwSize, ViewUnmap, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(status) || !userRwBase)
        {
            g_pGlobalUserVar->Func.ZwUnmapViewOfSection(hProcess, rxBase);
            rxBase = NULL;
            userRwBase = NULL;
        }
    }

    if (!NT_SUCCESS(status) || !rxBase || !userRwBase)
    {
        DBG("[-] [MapleThunk] MapSectionsIntoTarget: Paired RX/RW view mapping failed (0x%08X)", status);
        g_pGlobalUserVar->Func.ZwClose(hProcess);
        g_pGlobalUserVar->Func.ZwUnmapViewOfSection(ZwCurrentProcess(), kernelRwBase);
        g_pGlobalUserVar->Func.ZwClose(g_hRwSection);
        g_hRwSection = NULL;
        g_pGlobalUserVar->Func.ZwClose(g_hRxSection);
        g_hRxSection = NULL;
        return status;
    }

    // 为 SEC_IMAGE RX 映像节注册 CFG (Control Flow Guard) 合法调用目标位图，防止 ntdll!KiUserApcDispatcher 与 user32!DispatchMessageW 触发 int 29h (FAST_FAIL_GUARD_ICALL_CHECK_FAILURE)
    PFN_ZwSetInformationVirtualMemory pfnZwSetInfoVm = NULL;
    if (ResolveKernelExportByName("ZwSetInformationVirtualMemory", reinterpret_cast<PVOID *>(&pfnZwSetInfoVm)) &&
        pfnZwSetInfoVm)
    {
        MAPLE_VM_RANGE_ENTRY rangeEntry = {};
        rangeEntry.VirtualAddress = rxBase;
        rangeEntry.NumberOfBytes = rxViewSize ? rxViewSize : 0x4000;

        const ULONG off0 = (g_MapleRxPayloadSubclassInitRva <= g_MapleRxPayloadCustomWndProcRva)
                               ? (g_MapleRxPayloadSubclassInitRva & ~0xFU)
                               : (g_MapleRxPayloadCustomWndProcRva & ~0xFU);
        const ULONG off1 = (g_MapleRxPayloadSubclassInitRva <= g_MapleRxPayloadCustomWndProcRva)
                               ? (g_MapleRxPayloadCustomWndProcRva & ~0xFU)
                               : (g_MapleRxPayloadSubclassInitRva & ~0xFU);

        MAPLE_CFG_CALL_TARGET_INFO callTargets[2] = {};
        callTargets[0].Offset = off0;
        callTargets[0].Flags = 0x1; // CFG_CALL_TARGET_VALID
        callTargets[1].Offset = off1;
        callTargets[1].Flags = 0x1; // CFG_CALL_TARGET_VALID

        ULONG numOffsets = 0;
        MAPLE_VM_CFG_TARGET_INFORMATION cfgInfo = {};
        cfgInfo.NumberOfTargets = 2;
        cfgInfo.Flags = 0;
        cfgInfo.NumberOfOffsetsSuccessfullyProcessed = &numOffsets;
        cfgInfo.CallTargets = callTargets;
        cfgInfo.Section = NULL;
        cfgInfo.FileOffset = 0;

        NTSTATUS cfgSt = pfnZwSetInfoVm(hProcess, 2 /* VmCfgCallTargetInformation */, 1, &rangeEntry, &cfgInfo,
                                        sizeof(MAPLE_VM_CFG_TARGET_INFORMATION));
        DBG("[+] [MapleThunk] MapSectionsIntoTarget: Registered CFG CallTargets for RX Section (status=0x%08X, Applied=%lu)",
            cfgSt, numOffsets);
    }

    g_pGlobalUserVar->Func.ZwClose(hProcess);

    g_RxSectionUserBase = reinterpret_cast<ULONG64>(rxBase);
    g_RwSectionUserBase = reinterpret_cast<ULONG64>(userRwBase);
    g_SharedKernelView = static_cast<PMAPLE_SHARED_THUNK_DATA>(kernelRwBase);
    RtlZeroMemory(g_SharedKernelView, sizeof(MAPLE_SHARED_THUNK_DATA));

    *OutRxUserBase = g_RxSectionUserBase;
    *OutRwUserBase = g_RwSectionUserBase;
    DBG("[+] [MapleThunk] Mapped C++ Image-Backed RX=0x%llX and Shared RW=0x%llX (KernelView=0x%p)",
        g_RxSectionUserBase, g_RwSectionUserBase, g_SharedKernelView);
    return STATUS_SUCCESS;
}

// 2. 单次切入窗口主线程执行 SubclassInitEntry 初始化函数，完成后立即回收全部未决 KAPC，不再劫持线程
NTSTATUS MapleSubclassThunk::QueueSingleWindowThreadInit(HANDLE TargetPid, ULONG64 EntryPointVa, ULONG64 SharedDataVa,
                                                         ULONG64 TargetHwnd, ULONG64 CustomWndProcVa)
{
    PFN_PsLookupThreadByThreadId pfnLookupThread = NULL;
    PFN_PsGetThreadProcessId pfnGetThreadPid = NULL;
    PFN_PsGetThreadWin32Thread pfnGetWin32Thread = NULL;
    PFN_KeInitializeApc pfnInitApc = NULL;
    PFN_KeInsertQueueApc pfnInsertApc = NULL;

    if (!ResolveKernelExportByName("PsLookupThreadByThreadId", reinterpret_cast<PVOID *>(&pfnLookupThread)) ||
        !ResolveKernelExportByName("PsGetThreadProcessId", reinterpret_cast<PVOID *>(&pfnGetThreadPid)) ||
        !ResolveKernelExportByName("KeInitializeApc", reinterpret_cast<PVOID *>(&pfnInitApc)) ||
        !ResolveKernelExportByName("KeInsertQueueApc", reinterpret_cast<PVOID *>(&pfnInsertApc)) ||
        !ResolveKernelExportByName("KeRemoveQueueApc", reinterpret_cast<PVOID *>(&g_pfnKeRemoveQueueApc)) ||
        !ResolveKernelExportByName("KeTestAlertThread", reinterpret_cast<PVOID *>(&g_pfnKeTestAlertThread)))
    {
        return STATUS_NOT_SUPPORTED;
    }
    ResolveKernelExportByName("PsGetThreadWin32Thread", reinterpret_cast<PVOID *>(&pfnGetWin32Thread));

    CancelAllPendingApcs();
    RtlZeroMemory(g_UserApcSlots, sizeof(g_UserApcSlots));
    RtlZeroMemory(g_KernelApcSlots, sizeof(g_KernelApcSlots));

    ULONG queuedCount = 0;
    for (ULONG tid = 4; tid <= 0x40000 && queuedCount < MAPLE_MAX_APC_SLOTS; tid += 4)
    {
        PETHREAD pThread = NULL;
        if (!NT_SUCCESS(pfnLookupThread(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(tid)), &pThread)) || !pThread)
            continue;

        if (pfnGetThreadPid(pThread) == TargetPid)
        {
            const BOOLEAN isGuiThread = (!pfnGetWin32Thread || pfnGetWin32Thread(pThread) != NULL);
            if (isGuiThread)
            {
                PKAPC userApc = &g_UserApcSlots[queuedCount];
                pfnInitApc(userApc, reinterpret_cast<PRKTHREAD>(pThread), OriginalApcEnvironment,
                           MapleUserApcKernelRoutine, MapleUserApcRundownRoutine,
                           reinterpret_cast<PKNORMAL_ROUTINE>(EntryPointVa), UserMode,
                           reinterpret_cast<PVOID>(SharedDataVa));

                InterlockedExchange(&g_UserApcQueued[queuedCount], 1);
                if (pfnInsertApc(userApc, reinterpret_cast<PVOID>(TargetHwnd), reinterpret_cast<PVOID>(CustomWndProcVa),
                                 0))
                {
                    // 伴随投递 KernelMode Booster APC：切入目标线程调用 KeTestAlertThread(UserMode) 强制置位 UserApcPendingAll |= 2
                    PKAPC kernApc = &g_KernelApcSlots[queuedCount];
                    pfnInitApc(kernApc, reinterpret_cast<PRKTHREAD>(pThread), OriginalApcEnvironment,
                               MapleKernelBoosterRoutine, MapleKernelBoosterRundownRoutine,
                               reinterpret_cast<PKNORMAL_ROUTINE>(MapleKernelBoosterRoutine), KernelMode, NULL);

                    InterlockedExchange(&g_KernelApcQueued[queuedCount], 1);
                    if (!pfnInsertApc(kernApc, NULL, NULL, 0))
                    {
                        InterlockedExchange(&g_KernelApcQueued[queuedCount], 0);
                    }
                    queuedCount++;
                }
                else
                {
                    InterlockedExchange(&g_UserApcQueued[queuedCount], 0);
                }
            }
        }

        if (g_pGlobalUserVar->Func.ObfDereferenceObject)
            g_pGlobalUserVar->Func.ObfDereferenceObject(pThread);
    }

    if (queuedCount == 0)
        return STATUS_NOT_FOUND;

    // 等待窗口主线程完成 SubclassInitEntry (InitState == 2 或卸载还原 InitState == 3)，随后立即撤除其余非主线程上挂起的 KAPC，杜绝卸载时 0xCE 蓝屏
    if (g_pGlobalUserVar && g_pGlobalUserVar->Func.KeDelayExecutionThread && g_SharedKernelView)
    {
        for (ULONG waitStep = 0; waitStep < 50; ++waitStep)
        {
            const LONG state = InterlockedCompareExchange(&g_SharedKernelView->InitState, 0, 0);
            if (state == 2 || state == 3)
                break;
            LARGE_INTEGER delay = {};
            delay.QuadPart = -100000LL; // 10ms
            g_pGlobalUserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    CancelAllPendingApcs();

    DBG("[+] [MapleThunk] Queued & drained init APCs on %lu GUI thread(s) (InitState=%ld, Entry=0x%llX, Shared=0x%llX)",
        queuedCount, g_SharedKernelView ? g_SharedKernelView->InitState : -1, EntryPointVa, SharedDataVa);
    return STATUS_SUCCESS;
}

NTSTATUS MapleSubclassThunk::Initialize(ULONG64 TargetCr3, ULONG64 ImageBase, ULONG64 ClientSocket)
{
    if (!TargetCr3 || !ImageBase || !ClientSocket || !g_pGlobalUserVar)
        return STATUS_INVALID_PARAMETER;

    ULONG initEntryRva = 0;
    ULONG customWndProcRva = 0;
    NTSTATUS status = ResolvePayloadExports(&initEntryRva, &customWndProcRva);
    if (!NT_SUCCESS(status))
        return status;

    ULONG64 hWnd = 0;
    ULONG64 nativeSocket = 0;
    if (!MapleMemory::Read(ClientSocket + MapleLayout::ClientSocketHwndOffset, &hWnd) || !hWnd ||
        !MapleMemory::Read(ClientSocket + MapleLayout::ClientSocketNativeSocketOffset, &nativeSocket))
    {
        DBG("[-] [MapleThunk] Initialize: Failed to read ClientSocket->m_hWnd / m_sock");
        return STATUS_NOT_FOUND;
    }

    // 定位目标进程 EPROCESS 与 PID
    PEPROCESS targetProcess = NULL;
    ULONG foundPid = 0;
    for (ULONG pid = 4; pid <= 0x10000; pid += 4)
    {
        PEPROCESS pProc = NULL;
        if (NT_SUCCESS(g_pGlobalUserVar->Func.PsLookupProcessByProcessId(
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &pProc)) &&
            pProc)
        {
            const ULONG64 procCr3 = *(const ULONG64 *)((const UCHAR *)pProc + 0x28);
            if (procCr3 == TargetCr3)
            {
                targetProcess = pProc;
                foundPid = pid;
                break;
            }
            if (g_pGlobalUserVar->Func.ObfDereferenceObject)
                g_pGlobalUserVar->Func.ObfDereferenceObject(pProc);
        }
    }

    if (!targetProcess || !foundPid)
        return STATUS_NOT_FOUND;

    ULONG64 pfnSetWindowLongPtrW = 0;
    ULONG64 pfnCallWindowProcW = 0;
    ULONG64 pfnPostMessageW = 0;
    ULONG64 pfnGetWindowThreadProcessId = 0;
    status = ResolveUser32Exports(TargetCr3, targetProcess, &pfnSetWindowLongPtrW, &pfnCallWindowProcW,
                                  &pfnPostMessageW, &pfnGetWindowThreadProcessId);
    if (g_pGlobalUserVar->Func.ObfDereferenceObject)
        g_pGlobalUserVar->Func.ObfDereferenceObject(targetProcess);

    if (!NT_SUCCESS(status))
        return status;

    ULONG64 rxUserBase = 0;
    ULONG64 rwUserBase = 0;
    status =
        MapSectionsIntoTarget(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(foundPid)), &rxUserBase, &rwUserBase);
    if (!NT_SUCCESS(status) || !g_SharedKernelView)
        return status;

    const ULONG64 initEntryVa = rxUserBase + initEntryRva;
    const ULONG64 customWndProcVa = rxUserBase + customWndProcRva;

    // 填充独立 RW 共享节上下文
    g_SharedKernelView->pfnSetWindowLongPtrW = pfnSetWindowLongPtrW;
    g_SharedKernelView->pfnCallWindowProcW = pfnCallWindowProcW;
    g_SharedKernelView->pfnPostMessageW = pfnPostMessageW;
    g_SharedKernelView->pfnGetWindowThreadProcessId = pfnGetWindowThreadProcessId;
    g_SharedKernelView->pfnOrigWndProc = ImageBase + MapleLayout::WndProcRva;
    g_SharedKernelView->pfnCustomWndProc = customWndProcVa;
    g_SharedKernelView->TargetHwnd = hWnd;

    g_SharedKernelView->pfnOnRead = ImageBase + MapleLayout::OnReadRva;
    g_SharedKernelView->pfnAppendBuffer = ImageBase + MapleLayout::AppendBufferRva;
    g_SharedKernelView->pfnCopyFrom = ImageBase + MapleLayout::CopyFromRva;
    g_SharedKernelView->pfnDecryptData = ImageBase + MapleLayout::DecryptDataRva;
    g_SharedKernelView->pfnInnoHash = ImageBase + MapleLayout::InnoHashRva;
    g_SharedKernelView->pfnProcessPacket = ImageBase + MapleLayout::ProcessPacketRva;
    g_SharedKernelView->pfnDestroyInPacket = ImageBase + MapleLayout::DestroyInPacketRva;
    g_SharedKernelView->pfnFlush = ImageBase + MapleLayout::FlushRva;
    g_SharedKernelView->pfnSendPacket = ImageBase + MapleLayout::SendPacketRva;
    g_SharedKernelView->pfnSendPacketNative = ImageBase + MapleLayout::SendPacketNativeRva;
    g_SharedKernelView->pfnOutPacketInit = ImageBase + MapleLayout::OutPacketInitRva;
    g_SharedKernelView->pfnOutPacketEncodeBuffer = ImageBase + MapleLayout::OutPacketEncodeBufferRva;

    g_SharedKernelView->pClientSocketSlot = ImageBase + MapleLayout::ClientSocketSlotRva;
    g_SharedKernelView->RealSocketHandle = nativeSocket;
    g_SharedKernelView->InitState = 0;
    g_SharedKernelView->GateControlActive = 1;

    // 单次切入窗口主线程执行 C++ SubclassInitEntry -> SetWindowLongPtrW(hWnd, GWLP_WNDPROC, CustomWndProc)
    status = QueueSingleWindowThreadInit(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(foundPid)), initEntryVa,
                                         rwUserBase, hWnd, customWndProcVa);
    if (!NT_SUCCESS(status))
    {
        Cleanup();
        return status;
    }

    g_TargetCr3 = TargetCr3;
    g_ImageBase = ImageBase;
    g_ClientSocket = ClientSocket;
    g_TargetHwnd = hWnd;
    g_TargetPid = foundPid;
    g_IsInstalled = TRUE;

    DBG("[+] [MapleThunk] Installed via C++ MapleRxPayload SEC_IMAGE (0x%llX) + Shared RW (0x%llX) + "
        "SetWindowLongPtrW(GWLP_WNDPROC)",
        rxUserBase, rwUserBase);
    return STATUS_SUCCESS;
}

VOID MapleSubclassThunk::Cleanup()
{
    CancelAllPendingApcs();

    // 若目标进程存活且已完成 GWLP_WNDPROC 挂接 (InitState == 2)，先在主线程原子还原 pfnOrigWndProc，再解除 RX/RW 视图映射
    if (g_IsInstalled && g_SharedKernelView && g_TargetPid && g_RxSectionUserBase && g_RwSectionUserBase)
    {
        if (InterlockedCompareExchange(&g_SharedKernelView->InitState, 4, 2) == 2)
        {
            QueueSingleWindowThreadInit(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(g_TargetPid)),
                                        g_RxSectionUserBase + g_MapleRxPayloadSubclassInitRva, g_RwSectionUserBase,
                                        g_TargetHwnd, g_RxSectionUserBase + g_MapleRxPayloadCustomWndProcRva);
            if (g_pGlobalUserVar && g_pGlobalUserVar->Func.KeDelayExecutionThread)
            {
                LARGE_INTEGER drainDelay = {};
                drainDelay.QuadPart = -200000LL; // 20ms 排空正在执行的窗口过程栈帧
                g_pGlobalUserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &drainDelay);
            }
        }
    }

    if (g_SharedKernelView)
    {
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.ZwUnmapViewOfSection)
        {
            g_pGlobalUserVar->Func.ZwUnmapViewOfSection(ZwCurrentProcess(), g_SharedKernelView);
        }
        g_SharedKernelView = NULL;
    }

    if (g_TargetPid && (g_RxSectionUserBase || g_RwSectionUserBase) && g_pGlobalUserVar)
    {
        OBJECT_ATTRIBUTES procOa = {};
        InitializeObjectAttributes(&procOa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        CLIENT_ID cid = {};
        cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(g_TargetPid));
        HANDLE hProcess = NULL;
        if (NT_SUCCESS(g_pGlobalUserVar->Func.ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &procOa, &cid)) && hProcess)
        {
            if (g_RwSectionUserBase)
                g_pGlobalUserVar->Func.ZwUnmapViewOfSection(hProcess, reinterpret_cast<PVOID>(g_RwSectionUserBase));
            if (g_RxSectionUserBase)
                g_pGlobalUserVar->Func.ZwUnmapViewOfSection(hProcess, reinterpret_cast<PVOID>(g_RxSectionUserBase));
            g_pGlobalUserVar->Func.ZwClose(hProcess);
        }
    }

    if (g_hRwSection && g_pGlobalUserVar && g_pGlobalUserVar->Func.ZwClose)
    {
        g_pGlobalUserVar->Func.ZwClose(g_hRwSection);
        g_hRwSection = NULL;
    }
    if (g_hRxSection && g_pGlobalUserVar && g_pGlobalUserVar->Func.ZwClose)
    {
        g_pGlobalUserVar->Func.ZwClose(g_hRxSection);
        g_hRxSection = NULL;
    }

    g_RxSectionUserBase = 0;
    g_RwSectionUserBase = 0;
    g_TargetCr3 = 0;
    g_ImageBase = 0;
    g_ClientSocket = 0;
    g_TargetHwnd = 0;
    g_TargetPid = 0;
    g_IsInstalled = FALSE;
}

BOOLEAN MapleSubclassThunk::IsInstalled()
{
    return g_IsInstalled;
}

static VOID LogCapturedPacket(PCSTR Source, PMAPLE_CAPTURED_PACKET Packet)
{
    if (!Packet)
        return;

    CHAR hexStr[128] = {};
    const ULONG maxDump = Packet->DataLength > 32 ? 32 : Packet->DataLength;
    static const char hexDigits[] = "0123456789ABCDEF";

    ULONG pos = 0;
    for (ULONG i = 0; i < maxDump && pos + 3 < sizeof(hexStr); ++i)
    {
        UCHAR b = Packet->Payload[i];
        hexStr[pos++] = hexDigits[(b >> 4) & 0x0F];
        hexStr[pos++] = hexDigits[b & 0x0F];
        hexStr[pos++] = ' ';
    }
    if (pos > 0 && pos < sizeof(hexStr))
        hexStr[pos - 1] = '\0';

    DBG("[*] [MapleThunk] [%s] %s | Opcode=0x%04X | Len=%lu | Data: [ %s%s ]", Source,
        Packet->Direction == MaplePacketDirectionReceive ? "RECV" : "SEND", Packet->Opcode, Packet->DataLength, hexStr,
        Packet->DataLength > 32 ? " ..." : "");
}

NTSTATUS MapleSubclassThunk::PopCapturedPacket(PMAPLE_CAPTURED_PACKET Packet)
{
    if (!Packet || !g_IsInstalled || !g_SharedKernelView)
        return STATUS_DEVICE_NOT_READY;

    const ULONG writeIdx = g_SharedKernelView->WriteIndex;
    const ULONG readIdx = g_SharedKernelView->ReadIndex;
    if (readIdx == writeIdx)
        return STATUS_NO_MORE_ENTRIES;

    MemoryBarrier();
    const ULONG slot = readIdx & (MAPLE_THUNK_RING_CAPACITY - 1);
    RtlCopyMemory(Packet, &g_SharedKernelView->RingBuffer[slot], sizeof(MAPLE_CAPTURED_PACKET));
    MemoryBarrier();
    InterlockedExchange(reinterpret_cast<volatile LONG *>(&g_SharedKernelView->ReadIndex),
                        static_cast<LONG>(readIdx + 1));

    LogCapturedPacket("WndProcRx", Packet);
    return STATUS_SUCCESS;
}

ULONG MapleSubclassThunk::DrainHijackedPackets()
{
    if (!g_IsInstalled || !g_SharedKernelView)
        return 0;

    ULONG count = 0;
    MAPLE_CAPTURED_PACKET pkt = {};
    while (PopCapturedPacket(&pkt) == STATUS_SUCCESS)
    {
        count++;
    }
    return count;
}

NTSTATUS MapleSubclassThunk::DispatchSendPacket(USHORT Opcode, const UCHAR *Payload, ULONG Length)
{
    if (!g_IsInstalled || !g_SharedKernelView || !g_TargetHwnd)
        return STATUS_DEVICE_NOT_READY;

    if (Length > MAPLE_THUNK_MAX_PAYLOAD || (!Payload && Length > 0))
        return STATUS_INVALID_BUFFER_SIZE;

    g_SharedKernelView->PendingSendOpcode = Opcode;
    if (Length > 0 && Payload)
        RtlCopyMemory(g_SharedKernelView->PendingSendPayload, Payload, Length);
    MemoryBarrier();
    InterlockedExchange(reinterpret_cast<volatile LONG *>(&g_SharedKernelView->PendingSendLength),
                        static_cast<LONG>(Length));

    DBG("[+] [MapleThunk] DispatchSendPacket: Queued Opcode=0x%04X (Len=%lu) in Shared RW Section for HWND=0x%llX",
        Opcode, Length, g_TargetHwnd);
    return STATUS_SUCCESS;
}
