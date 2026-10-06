#include "pte_hijack.h"
#include <intrin.h>

static ULONG64 g_PteBase = 0;

static KIRQL _DisableWP(VOID)
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    ULONG64 cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);
    _disable();
    return irql;
}

static VOID _EnableWP(KIRQL irql)
{
    ULONG64 cr0 = __readcr0();
    __writecr0(cr0 | 0x10000ULL);
    _enable();
    KeLowerIrql(irql);
}

static ULONG64 _ScanPteBase(VOID)
{
    UNICODE_STRING usMmAV;
    RtlInitUnicodeString(&usMmAV, L"MmAllocateContiguousMemory");
    PUCHAR pScan = (PUCHAR)MmGetSystemRoutineAddress(&usMmAV);
    if (!pScan)
        return 0;

    PUCHAR pBase = (PUCHAR)((ULONG64)pScan & ~0xFFFULL);
    for (INT i = 0; i < 0x2000; i++, pBase -= 0x1000)
    {
        __try
        {
            if (*(PUSHORT)pBase == 0x5A4D)
                break;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }
    if (*(PUSHORT)pBase != 0x5A4D)
        return 0;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    PUCHAR pText = NULL;
    ULONG cbText = 0;

    for (USHORT s = 0; s < pNt->FileHeader.NumberOfSections; s++, pSec++)
    {
        if (RtlCompareMemory(pSec->Name, ".text", 5) == 5)
        {
            pText = pBase + pSec->VirtualAddress;
            cbText = pSec->Misc.VirtualSize;
            break;
        }
    }
    if (!pText)
        return 0;

    static const UCHAR pattern[] = {0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB8};
    for (ULONG i = 0; i + 14 < cbText; i++)
    {
        __try
        {
            if (RtlCompareMemory(pText + i, pattern, sizeof(pattern)) == sizeof(pattern))
            {
                ULONG64 candidate = *(PULONG64)(pText + i + 6);
                if ((candidate >> 48) == 0xFFFF)
                {
                    DbgPrint("[PteHijack] Found PteBase = 0x%016llX at offset +%u\n", candidate, i);
                    return candidate;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
    }
    return 0;
}

static PMMPTE_HW _GetPteVa(ULONG64 Va)
{
    return (PMMPTE_HW)(g_PteBase + ((Va >> 9) & 0x7FFFFFFFFFFFF8ULL));
}

NTSTATUS PteHijack_Init(VOID)
{
    if (g_PteBase)
        return STATUS_SUCCESS;

    g_PteBase = _ScanPteBase();
    if (!g_PteBase)
    {
        DbgPrint("[PteHijack] Failed to locate PteBase\n");
        return STATUS_NOT_FOUND;
    }
    DbgPrint("[PteHijack] PteBase = 0x%016llX\n", g_PteBase);
    return STATUS_SUCCESS;
}

static ULONG_PTR _IpiFlushCallback(ULONG_PTR Context)
{
    PVOID va = (PVOID)Context;
    _mm_mfence();
    __invlpg(va);
    _mm_mfence();
    return 0;
}

VOID PteHijack_FlushTlb(ULONG64 Va)
{
    PVOID pageVa = (PVOID)(Va & ~0xFFFULL);
    KeIpiGenericCall(_IpiFlushCallback, (ULONG_PTR)pageVa);
}

NTSTATUS PteHijack_Remap(_In_ ULONG64 UserVa, _In_ ULONG64 KernelVa, _Out_ PULONG64 OldPte)
{
    if (!g_PteBase)
        return STATUS_UNSUCCESSFUL;
    if (!OldPte)
        return STATUS_INVALID_PARAMETER;

    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)(KernelVa & ~0xFFFULL));
    if (!pa.QuadPart)
    {
        DbgPrint("[PteHijack] MmGetPhysicalAddress failed for KernelVa=0x%llX\n", KernelVa);
        return STATUS_INVALID_ADDRESS;
    }
    ULONG64 pfn = pa.QuadPart >> 12;

    PMMPTE_HW pPte = _GetPteVa(UserVa & ~0xFFFULL);
    DbgPrint("[PteHijack] UserVa=0x%llX -> PTE_VA=0x%llX PTE=0x%016llX\n", UserVa, (ULONG64)pPte, pPte->u64);

    if (!pPte->Valid)
    {
        DbgPrint("[PteHijack] User PTE not present, touch the page first\n");
        return STATUS_INVALID_ADDRESS;
    }

    *OldPte = pPte->u64;

    MMPTE_HW newPte = {0};
    newPte.Valid = 1;
    newPte.Write = 1;
    newPte.Owner = 1;
    newPte.Accessed = 1;
    newPte.Dirty = 1;
    newPte.PageFrameNumber = pfn;
    newPte.NoExecute = 0;
    newPte.Global = 0;

    KIRQL irql = _DisableWP();
    InterlockedExchange64((volatile LONG64 *)pPte, (LONG64)newPte.u64);
    _EnableWP(irql);

    PteHijack_FlushTlb(UserVa & ~0xFFFULL);

    DbgPrint("[PteHijack] PTE hijacked: 0x%016llX -> 0x%016llX (PFN=%llX)\n", *OldPte, newPte.u64, pfn);
    return STATUS_SUCCESS;
}

NTSTATUS PteHijack_Restore(ULONG64 UserVa, ULONG64 OriginalPte)
{
    if (!g_PteBase)
        return STATUS_UNSUCCESSFUL;

    PMMPTE_HW pPte = _GetPteVa(UserVa & ~0xFFFULL);

    KIRQL irql = _DisableWP();
    InterlockedExchange64((volatile LONG64 *)pPte, (LONG64)OriginalPte);
    _EnableWP(irql);

    PteHijack_FlushTlb(UserVa & ~0xFFFULL);

    DbgPrint("[PteHijack] PTE restored: 0x%016llX\n", OriginalPte);
    return STATUS_SUCCESS;
}
