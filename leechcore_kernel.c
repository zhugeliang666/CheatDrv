#include "leechcore_kernel.h"
#include "Common.h"
#include "Utils.h"
#include "MachenikeString.h"
#include <intrin.h>

#ifdef ExAcquireFastMutex
#undef ExAcquireFastMutex
#endif
#define ExAcquireFastMutex(m) do { if (g_ctx.UserVar && g_ctx.UserVar->Func.ExAcquireFastMutex) g_ctx.UserVar->Func.ExAcquireFastMutex(m); } while(0)

#ifdef ExReleaseFastMutex
#undef ExReleaseFastMutex
#endif
#define ExReleaseFastMutex(m) do { if (g_ctx.UserVar && g_ctx.UserVar->Func.ExReleaseFastMutex) g_ctx.UserVar->Func.ExReleaseFastMutex(m); } while(0)

LC_MAIN_CONTEXT g_ctx = {0};

// ============================================================================
// ?PTE ???????????????? (PTE Remap + __invlpg)
// ???? ZwMapViewOfSection????? PFN ???????????????

// ============================================================================
#define LC_PTE_SLOT_COUNT 16

typedef struct _LC_PTE_SLOT
{
    PVOID pMappedPage;
    ULONG64 *pPteVa;
    ULONG64 OriginalPte;
    volatile LONG inUse;
} LC_PTE_SLOT, *PLC_PTE_SLOT;

typedef struct _LC_PTE_ENGINE
{
    ULONG64 PteBase;
    BOOLEAN fInitialized;
    LC_PTE_SLOT Slots[LC_PTE_SLOT_COUNT];
} LC_PTE_ENGINE, *PLC_PTE_ENGINE;
static LC_PTE_ENGINE g_PteEngine = {0};
static ULONG64 _ScanPteBase(VOID)
{
    // 方法 1 (首选)：ACE 函数 96 (sub_140031EF0) 动态 PML4 自引用槽位扫描
    // 兼容 Windows 10/11 全版本 KASLR 随机化页表基址，基于纯硬件页表结构，无特征码失效风险
    __try
    {
        ULONG64 cr3 = __readcr3();
        PHYSICAL_ADDRESS pml4Phys;
        pml4Phys.QuadPart = (LONGLONG)(cr3 & 0xFFFFFFFFFFFFF000ULL);
        PULONG64 pml4Virt = (PULONG64)((g_ctx.UserVar && g_ctx.UserVar->Func.MmGetVirtualForPhysical) ?
                                        g_ctx.UserVar->Func.MmGetVirtualForPhysical(pml4Phys) :
                                        NULL);
        if (pml4Virt) {
            ULONG64 selfPfn = (ULONG64)pml4Phys.QuadPart & 0xFFFFFFFFF000ULL;
            // 遍历 PML4 高 256 个内核条目 (256 ~ 511)
            for (ULONG slot = 256; slot < 512; slot++)
            {
                if ((pml4Virt[slot] & 0xFFFFFFFFF000ULL) == selfPfn) {
                    // 命中自引用槽位！推导 PTE 虚拟基地址 (PteBase)
                    // 公式：((slot + 0x1FFFE00ULL) << 39)，其中 0x1FFFE00LL = 33553920LL
                    ULONG64 candidate = ((ULONG64)slot + 0x1FFFE00ULL) << 39;
                    if ((candidate >> 48) == 0xFFFF) {
                        DBG("LcPteEngine: Located PteBase via ACE PML4 Self-Ref Slot [%lu] -> 0x%016llX", slot,
                            candidate);
                        return candidate;
                    }
                }
            }
        }
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 捕获异常，继续回退到备用方法
    }

    // 方法 2 (备用)：从内核导出函数 MmGetVirtualForPhysical 提取动态重定位修补的 PteBase
    // 指令特征：movabs rdx, <PteBase>; shl rdx, 0x19 (48 BA <8 bytes> 48 C1 E2 19)
    PUCHAR pMmGVP = (PUCHAR)((g_ctx.UserVar && g_ctx.UserVar->Func.MmGetVirtualForPhysical) ?
                             (PVOID)g_ctx.UserVar->Func.MmGetVirtualForPhysical : NULL);
    if (pMmGVP) {
        __try
        {
            for (ULONG i = 0; i < 48; i++)
            {
                if (pMmGVP[i] == 0x48 && pMmGVP[i + 1] == 0xBA && pMmGVP[i + 10] == 0x48 && pMmGVP[i + 11] == 0xC1 &&
                    pMmGVP[i + 12] == 0xE2 && pMmGVP[i + 13] == 0x19) {
                    ULONG64 candidate = *(PULONG64)(pMmGVP + i + 2);
                    if ((candidate >> 48) == 0xFFFF) {
                        DBG("LcPteEngine: Located PteBase via MmGetVirtualForPhysical+0x%X -> 0x%016llX", i + 2,
                            candidate);
                        return candidate;
                    }
                }
            }

            // 直接校验偏移 +0x22 处（标准 Windows 10/11 编译偏移）
            ULONG64 candidate22 = *(PULONG64)(pMmGVP + 0x22);
            if ((candidate22 >> 48) == 0xFFFF) {
                DBG("LcPteEngine: Located PteBase via MmGetVirtualForPhysical direct +0x22 -> 0x%016llX", candidate22);
                return candidate22;
            }
        }

        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    // 方法 3 (历史低版本兜底，Win10 1607 之前未随机化固定基址)
    return 0xFFFFF68000000000ULL;
}

typedef PVOID (*PFN_MmAllocateMappingAddress)(SIZE_T NumberOfBytes, ULONG PoolTag);
typedef VOID (*PFN_MmFreeMappingAddress)(PVOID BaseAddress, ULONG PoolTag);
static PFN_MmAllocateMappingAddress g_pfnMmAllocateMappingAddress = NULL;
static PFN_MmFreeMappingAddress g_pfnMmFreeMappingAddress = NULL;
static PVOID g_pReservedSystemVa = NULL;
static NTSTATUS LcPteEngine_Init(VOID)
{
    if (g_PteEngine.fInitialized)
        return STATUS_SUCCESS;
    g_PteEngine.PteBase = _ScanPteBase();
    if (!g_PteEngine.PteBase) {
        DBG("LcPteEngine: Failed to locate PteBase");
        return STATUS_NOT_FOUND;
    }

    DBG("LcPteEngine: Found PteBase = 0x%016llX", g_PteEngine.PteBase);
    if (!g_pfnMmAllocateMappingAddress || !g_pfnMmFreeMappingAddress) {
        if (g_ctx.UserVar && g_ctx.UserVar->KernelBase.QuadPart) {
            Utils_GetModuleExport((ULONG_PTR)g_ctx.UserVar->KernelBase.QuadPart, str_MmAllocateMappingAddress,
                                  (PULONG_PTR)&g_pfnMmAllocateMappingAddress);
            Utils_GetModuleExport((ULONG_PTR)g_ctx.UserVar->KernelBase.QuadPart, str_MmFreeMappingAddress,
                                  (PULONG_PTR)&g_pfnMmFreeMappingAddress);
        }
        if (!g_pfnMmAllocateMappingAddress || !g_pfnMmFreeMappingAddress) {
            DBG("[-] LcPteEngine: Failed to resolve MmAllocateMappingAddress/MmFreeMappingAddress");
            return STATUS_NOT_FOUND;
        }
    }

    SIZE_T totalBytes = LC_PTE_SLOT_COUNT * PAGE_SIZE;
    g_pReservedSystemVa = g_pfnMmAllocateMappingAddress(totalBytes, LC_POOL_TAG);
    if (!g_pReservedSystemVa) {
        DBG("[-] LcPteEngine: MmAllocateMappingAddress failed (size=%zu)", totalBytes);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (INT i = 0; i < LC_PTE_SLOT_COUNT; i++)
    {
        PLC_PTE_SLOT slot = &g_PteEngine.Slots[i];
        slot->pMappedPage = (PUCHAR)g_pReservedSystemVa + (i * PAGE_SIZE);
        slot->pPteVa = (ULONG64 *)(g_PteEngine.PteBase + (((ULONG64)slot->pMappedPage >> 9) & 0x7FFFFFFFF8ULL));
        slot->OriginalPte = *slot->pPteVa;
        slot->inUse = 0;
        DBG("[+] LcPteEngine: Slot [%d]: PageVa=%p, PteVa=%p, OrigPte=0x%016llX (Valid=%d)", i, slot->pMappedPage,
            slot->pPteVa, slot->OriginalPte, (int)(slot->OriginalPte & 1));
    }

    g_PteEngine.fInitialized = TRUE;
    DBG("[+] LcPteEngine: Successfully initialized %d slots via System PTEs (BaseVa=%p)", LC_PTE_SLOT_COUNT,
        g_pReservedSystemVa);
    return STATUS_SUCCESS;
}

static VOID LcPteEngine_Cleanup(VOID)
{
    if (!g_PteEngine.fInitialized)
        return;
    for (INT i = 0; i < LC_PTE_SLOT_COUNT; i++)
    {
        PLC_PTE_SLOT slot = &g_PteEngine.Slots[i];
        if (slot->pMappedPage && slot->pPteVa) {
            *slot->pPteVa = slot->OriginalPte;
            __invlpg(slot->pMappedPage);
        }

        slot->pMappedPage = NULL;
        slot->pPteVa = NULL;
        slot->inUse = 0;
    }

    if (g_pReservedSystemVa && g_pfnMmFreeMappingAddress) {
        g_pfnMmFreeMappingAddress(g_pReservedSystemVa, LC_POOL_TAG);
        g_pReservedSystemVa = NULL;
    }

    g_PteEngine.fInitialized = FALSE;
    DBG("LcPteEngine: Cleaned up");
}

static BOOLEAN LcPte_CopyPhysical(_In_ ULONG64 PhysAddr, _Inout_ PVOID Buffer, _In_ ULONG Size, _In_ BOOLEAN fWrite)
{
    if (!g_PteEngine.fInitialized || !Buffer || Size == 0) {
        DBG("[-] LcPte_CopyPhysical: Invalid parameters or engine not initialized (init=%d, buf=%p, size=%lu)",
            g_PteEngine.fInitialized, Buffer, Size);
        return FALSE;
    }

    INT slotIndex = -1;
    for (ULONG retry = 0; retry < 1000; retry++)
    {
        for (INT i = 0; i < LC_PTE_SLOT_COUNT; i++)
        {
            if (_InterlockedCompareExchange(&g_PteEngine.Slots[i].inUse, 1, 0) == 0) {
                slotIndex = i;
                break;
            }
        }

        if (slotIndex != -1)
            break;
        for (int p = 0; p < 100; p++) {
            _mm_pause();
        }
    }

    if (slotIndex == -1) {
        DBG("[-] LcPte_CopyPhysical: Timeout acquiring PTE slot for PA=0x%016llX (fWrite=%d)", PhysAddr, fWrite);
        return FALSE;
    }

    PLC_PTE_SLOT slot = &g_PteEngine.Slots[slotIndex];
    _disable();
    KIRQL oldIrql = (g_ctx.UserVar && g_ctx.UserVar->Func.KfRaiseIrql) ?
                        g_ctx.UserVar->Func.KfRaiseIrql(DISPATCH_LEVEL) :
                        0;
    // 0x103: Valid(1) | Write(2) | Global(0x100)，显式清掉 bit 9 保留位
    // 写操作使用 0x1EB (ForceWrite)
    ULONG64 flags = fWrite ? 0x1EBULL : 0x103ULL;
    ULONG64 newPte = (PhysAddr & 0xFFFFFFFFFF000ULL) | (flags & ~(1ULL << 9));
    *slot->pPteVa = newPte;
    __invlpg(slot->pMappedPage);
    PUCHAR pTarget = (PUCHAR)slot->pMappedPage + (PhysAddr & 0xFFFULL);
    __try
    {
        if (!fWrite) {
            __movsb((PUCHAR)Buffer, pTarget, Size);
        }

        else {
            __movsb(pTarget, (PUCHAR)Buffer, Size);
        }
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG("[-] LcPte_CopyPhysical: Exception during __movsb (PA=0x%016llX, Size=%lu, fWrite=%d)", PhysAddr, Size,
            fWrite);
    }

    *slot->pPteVa = slot->OriginalPte;
    __invlpg(slot->pMappedPage);
    if (g_ctx.UserVar && g_ctx.UserVar->Func.KeLowerIrql) {
        g_ctx.UserVar->Func.KeLowerIrql(oldIrql);
    }
    _enable();
    _InterlockedExchange(&slot->inUse, 0);
    return TRUE;
}

static ULONG LcPte_ReadPhysicalContiguous(LARGE_INTEGER physAddr, PUCHAR buf, ULONG count)
{
    if (!buf || count == 0)
        return 0;

    ULONG uReadOffset = 0;
    while (uReadOffset < count)
    {
        ULONG64 currentPa = (ULONG64)physAddr.QuadPart + uReadOffset;
        ULONG pageOffset = (ULONG)(currentPa & 0xFFFULL);
        ULONG toRead = min(PAGE_SIZE - pageOffset, count - uReadOffset);
        if (!LcPte_CopyPhysical(currentPa, buf + uReadOffset, toRead, FALSE)) {
            DBG("[-] LcPte_ReadPhysical: Failed at PA=0x%016llX (offset=%lu/%lu)", currentPa, uReadOffset, count);
            break;
        }

        uReadOffset += toRead;
    }

    if (uReadOffset < count) {
        DBG("[-] LcPte_ReadPhysical: Incomplete read PA=0x%016llX, Read=%lu/%lu", physAddr.QuadPart, uReadOffset, count);
    }

    return uReadOffset;
}

static ULONG LcPte_WritePhysicalContiguous(LARGE_INTEGER physAddr, PUCHAR buf, ULONG count)
{
    if (!buf || count == 0)
        return 0;

    ULONG uWriteOffset = 0;
    while (uWriteOffset < count)
    {
        ULONG64 currentPa = (ULONG64)physAddr.QuadPart + uWriteOffset;
        ULONG pageOffset = (ULONG)(currentPa & 0xFFFULL);
        ULONG toWrite = min(PAGE_SIZE - pageOffset, count - uWriteOffset);
        if (!LcPte_CopyPhysical(currentPa, buf + uWriteOffset, toWrite, TRUE)) {
            DBG("[-] LcPte_WritePhysical: Failed at PA=0x%016llX (offset=%lu/%lu)", currentPa, uWriteOffset, count);
            break;
        }

        uWriteOffset += toWrite;
    }

    if (uWriteOffset < count) {
        DBG("[-] LcPte_WritePhysical: Incomplete write PA=0x%016llX, Written=%lu/%lu", physAddr.QuadPart, uWriteOffset, count);
    }

    return uWriteOffset;
}

_IRQL_requires_max_(PASSIVE_LEVEL) ULONG
    PhysicalMemoryPartialRead(IN MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ LARGE_INTEGER physAddr, _Inout_ PUCHAR buf,
                              _In_ ULONG count)
{
    UNREFERENCED_PARAMETER(UserVar);
    return LcPte_ReadPhysicalContiguous(physAddr, buf, count);
}

_IRQL_requires_max_(PASSIVE_LEVEL) ULONG
    PhysicalMemoryPartialWrite(IN MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ LARGE_INTEGER PhysicalAddress,
                               _In_ PUCHAR lpBuffer, _In_ SIZE_T Length)
{
    UNREFERENCED_PARAMETER(UserVar);
    return LcPte_WritePhysicalContiguous(PhysicalAddress, lpBuffer, (ULONG)Length);
}

static ULONG KernelReadPhysContiguous(IN MACHENIKE_KERNEL_INTERFACE *UserVar, LARGE_INTEGER physAddr, PUCHAR buf,
                                      ULONG count)
{
    UNREFERENCED_PARAMETER(UserVar);
    return LcPte_ReadPhysicalContiguous(physAddr, buf, count);
}

static ULONG KernelWritePhysContiguous(IN MACHENIKE_KERNEL_INTERFACE *UserVar, LARGE_INTEGER physAddr, PUCHAR buf,
                                       ULONG count)
{
    UNREFERENCED_PARAMETER(UserVar);
    return LcPte_WritePhysicalContiguous(physAddr, buf, count);
}

static ULONG DeviceKernel_ReadPhys(_In_ PLC_CONTEXT ctxLC, _In_ LARGE_INTEGER physAddr,
                                   _Out_writes_bytes_(count) PUCHAR buf, _In_ ULONG count)
{
    UNREFERENCED_PARAMETER(ctxLC);
    return LcPte_ReadPhysicalContiguous(physAddr, buf, count);
}

static VOID DeviceKernel_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ ULONG cpMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!ctxLC) {
        return;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    for (ULONG i = 0; i < cpMEMs; i++)
    {
        PMEM_SCATTER pMEM = ppMEMs[i];
        if (!pMEM || !pMEM->pb || pMEM->cb == 0) {
            if (pMEM) {
                pMEM->f = FALSE;
            }

            continue;
        }

        LARGE_INTEGER pa;
        pa.QuadPart = pMEM->qwA;
        ULONG nRead = DeviceKernel_ReadPhys(ctxLC, pa, pMEM->pb, pMEM->cb);
        if (nRead == pMEM->cb) {
            pMEM->f = TRUE;
        }

        else {
            pMEM->f = FALSE;
            DBG("[-] DeviceKernel_ReadScatter: Read failed at PA=0x%016llX, Size=%lu", pMEM->qwA, pMEM->cb);
            if (UserVar) {
                UserVar->Func.RtlZeroMemory(pMEM->pb, pMEM->cb);
            }

            else {
                RtlZeroMemory(pMEM->pb, pMEM->cb);
            }
        }
    }
}

static VOID DeviceKernel_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ ULONG cpMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!ctxLC) {
        return;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    for (ULONG i = 0; i < cpMEMs; i++)
    {
        PMEM_SCATTER pMEM = ppMEMs[i];
        if (!pMEM || !pMEM->pb || pMEM->cb == 0) {
            if (pMEM) {
                pMEM->f = FALSE;
            }

            continue;
        }

        LARGE_INTEGER pa;
        pa.QuadPart = pMEM->qwA;
        ULONG nWritten = KernelWritePhysContiguous(UserVar, pa, pMEM->pb, pMEM->cb);
        pMEM->f = (nWritten == pMEM->cb);
        if (!pMEM->f) {
            DBG("[-] DeviceKernel_WriteScatter: Write failed at PA=0x%016llX, Size=%lu", pMEM->qwA, pMEM->cb);
        }
    }
}

static ULONG64 _GetSystemDirectoryTableBase(VOID)
{
    ULONG64 cr3 = 0;
    if (g_ctx.UserVar && g_ctx.UserVar->Func.pPsInitialSystemProcess && *g_ctx.UserVar->Func.pPsInitialSystemProcess) {
        PEPROCESS pSysProc = *g_ctx.UserVar->Func.pPsInitialSystemProcess;
        cr3 = *(PULONG64)((PUCHAR)pSysProc + 0x28);
    }

    if (cr3 == 0) {
        cr3 = __readcr3() & 0xFFFFFFFFFFFFF000ULL;
    }

    return cr3;
}

static ULONG64 _GetKernelBase(VOID)
{
    PVOID pBase = NULL;
    PVOID pRefFunc = (g_ctx.UserVar && g_ctx.UserVar->Func.IoCreateDevice) ?
                         (PVOID)g_ctx.UserVar->Func.IoCreateDevice :
                         (PVOID)g_ctx.UserVar;
    if (g_ctx.UserVar && g_ctx.UserVar->Func.RtlPcToFileHeader && pRefFunc) {
        if (g_ctx.UserVar->Func.RtlPcToFileHeader(pRefFunc, &pBase) && pBase) {
            return (ULONG64)pBase;
        }
    }

    if (pRefFunc) {
        ULONG_PTR addr = ((ULONG_PTR)pRefFunc) & ~0xFFFULL;
        for (ULONG i = 0; i < 0x20000; i++, addr -= PAGE_SIZE)
        {
            BOOLEAN bAddrValid = (g_ctx.UserVar && g_ctx.UserVar->Func.MmIsAddressValid) ?
                                     g_ctx.UserVar->Func.MmIsAddressValid((PVOID)addr) :
                                     FALSE;
            if (bAddrValid) {
                PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)addr;
                if (pDos->e_magic == IMAGE_DOS_SIGNATURE && pDos->e_lfanew > 0 && pDos->e_lfanew < 0x1000) {
                    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(addr + pDos->e_lfanew);
                    BOOLEAN bNtValid = (g_ctx.UserVar && g_ctx.UserVar->Func.MmIsAddressValid) ?
                                           g_ctx.UserVar->Func.MmIsAddressValid(pNt) :
                                           FALSE;
                    if (bNtValid && pNt->Signature == IMAGE_NT_SIGNATURE) {
                        return (ULONG64)addr;
                    }
                }
            }
        }
    }

    return 0;
}

static BOOLEAN DeviceKernel_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if (!ctxLC || !pqwValue) {
        return FALSE;
    }

    if (fOption == LC_OPT_CORE_ADDR_MAX) {
        *pqwValue = ctxLC->Config.paMax;
        return TRUE;
    }

    if (fOption == LC_OPT_MEMORYINFO_VALID) {
        *pqwValue = 1;
        return TRUE;
    }

    switch (fOption)
    {
    case LC_OPT_MEMORYINFO_ARCH:
        *pqwValue = 3; // LC_ARCH_X64 (0:NA, 1:X86, 2:X86PAE, 3:X64, 4:ARM64)
        return TRUE;
    case LC_OPT_MEMORYINFO_FLAG_32BIT:
        *pqwValue = 0;
        return TRUE;
    case LC_OPT_MEMORYINFO_FLAG_PAE:
        *pqwValue = 0;
        return TRUE;
    case LC_OPT_MEMORYINFO_OS_DTB:
        if (ctxLC->MemInfo.CR3.QuadPart == 0) {
            ctxLC->MemInfo.CR3.QuadPart = _GetSystemDirectoryTableBase();
        }

        *pqwValue = ctxLC->MemInfo.CR3.QuadPart;
        return TRUE;
    case LC_OPT_MEMORYINFO_OS_KERNELBASE:
        if (ctxLC->MemInfo.KernBase.QuadPart == 0) {
            ctxLC->MemInfo.KernBase.QuadPart = _GetKernelBase();
        }

        *pqwValue = ctxLC->MemInfo.KernBase.QuadPart;
        return TRUE;
    case LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP:
        *pqwValue = 0x8664; // IMAGE_FILE_MACHINE_AMD64 (Intel 64 和 AMD64 统一标准码)
        return TRUE;
    case LC_OPT_MEMORYINFO_OS_VERSION_MAJOR:
        *pqwValue = 10;
        return TRUE;
    case LC_OPT_MEMORYINFO_OS_VERSION_MINOR:
        *pqwValue = 0;
        return TRUE;
    }

    *pqwValue = 0;
    return FALSE;
}

static __forceinline VOID LcFormatHex(char *dst, ULONG64 val, int digits)
{
    static const char hexChars[] = "0123456789abcdef";
    for (int i = digits - 1; i >= 0; i--) {
        dst[i] = hexChars[val & 0xF];
        val >>= 4;
    }
}

BOOLEAN LcMemMap_GetRangesAsText(_In_ PLC_CONTEXT ctxLC, _Out_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!ctxLC || !ppbDataOut || !ctxLC->UserVar) {
        return FALSE;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    if (ctxLC->cMemMap == 0 || ctxLC->cMemMap > 1024) {
        return FALSE;
    }

    ULONG cb = ctxLC->cMemMap * 64 + 1;
    PCHAR pb = (PCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cb, LC_POOL_TAG);
    if (!pb) {
        return FALSE;
    }

    UserVar->Func.RtlZeroMemory(pb, cb);
    ULONG o = 0;
    for (ULONG i = 0; i < ctxLC->cMemMap && o < cb - 64; i++) {
        ULONG64 paStart = ctxLC->pMemMap[i].pa;
        ULONG64 paEnd = ctxLC->pMemMap[i].pa + ctxLC->pMemMap[i].cb - 1;
        ULONG64 paRemap = ctxLC->pMemMap[i].paRemap;

        LcFormatHex(pb + o, i, 4);
        o += 4;
        pb[o++] = ' ';
        LcFormatHex(pb + o, paStart, 16);
        o += 16;
        pb[o++] = ' ';
        pb[o++] = '-';
        pb[o++] = ' ';
        LcFormatHex(pb + o, paEnd, 16);
        o += 16;
        pb[o++] = ' ';
        pb[o++] = '-';
        pb[o++] = '>';
        pb[o++] = ' ';
        LcFormatHex(pb + o, paRemap, 16);
        o += 16;
        pb[o++] = '\n';
    }

    pb[cb - 1] = '\0';
    *ppbDataOut = (PUCHAR)pb;
    if (pcbDataOut) {
        *pcbDataOut = o + 1;
    }

    return TRUE;
}

static BOOLEAN DeviceKernel_SetOption(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    UNREFERENCED_PARAMETER(ctxLC);
    UNREFERENCED_PARAMETER(fOption);
    UNREFERENCED_PARAMETER(qwValue);
    return TRUE;
}

static BOOLEAN DeviceKernel_Command(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _In_ ULONG cbDataIn,
                                    _In_reads_opt_(cbDataIn) PUCHAR pbDataIn, _Out_opt_ PUCHAR *ppbDataOut,
                                    _Out_opt_ PULONG pcbDataOut)
{
    UNREFERENCED_PARAMETER(ctxLC);
    UNREFERENCED_PARAMETER(fOption);
    UNREFERENCED_PARAMETER(cbDataIn);
    UNREFERENCED_PARAMETER(pbDataIn);
    if (ppbDataOut) {
        *ppbDataOut = NULL;
    }

    if (pcbDataOut) {
        *pcbDataOut = 0;
    }

    return FALSE;
}

static VOID DeviceKernel_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    UNREFERENCED_PARAMETER(ctxLC);
}

BOOLEAN LcMemMap_AddRange(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 pa, _In_ ULONG64 cb, _In_ ULONG64 paRemap)
{
    if (!ctxLC || !ctxLC->pMemMap || !ctxLC->UserVar) {
        return FALSE;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    if ((cb & 0xfff) == 1) {
        cb--;
    }

    if ((pa & 0xfff) || (cb & 0xfff)) {
        return FALSE;
    }

    if (ctxLC->cMemMap >= 0x00100000) {
        return FALSE;
    }

    if (ctxLC->cMemMap == ctxLC->cMemMapMax) {
        ULONG newMax = ctxLC->cMemMapMax * 2;
        PLC_MEMMAP_ENTRY pNew = (PLC_MEMMAP_ENTRY)UserVar->Func.ExAllocatePoolWithTag(
            NonPagedPool, newMax * sizeof(LC_MEMMAP_ENTRY), LC_POOL_TAG);
        if (!pNew) {
            return FALSE;
        }

        UserVar->Func.RtlCopyMemory(pNew, ctxLC->pMemMap, ctxLC->cMemMap * sizeof(LC_MEMMAP_ENTRY));
        UserVar->Func.ExFreePoolWithTag(ctxLC->pMemMap, LC_POOL_TAG);
        ctxLC->pMemMap = pNew;
        ctxLC->cMemMapMax = newMax;
    }

    ctxLC->pMemMap[ctxLC->cMemMap].pa = pa;
    ctxLC->pMemMap[ctxLC->cMemMap].cb = cb;
    ctxLC->pMemMap[ctxLC->cMemMap].paRemap = paRemap ? paRemap : pa;
    ctxLC->cMemMap++;
    return TRUE;
}

ULONG64 LcMemMap_GetMaxAddress(_In_ PLC_CONTEXT ctxLC)
{
    if (ctxLC->cMemMap == 0) {
        return 0x0000ffffffffffffULL;
    }

    return ctxLC->pMemMap[ctxLC->cMemMap - 1].pa + ctxLC->pMemMap[ctxLC->cMemMap - 1].cb;
}

BOOLEAN LcMemMap_GetRangesAsStruct(_In_ PLC_CONTEXT ctxLC, _Out_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!ctxLC || !ppbDataOut || !ctxLC->UserVar) {
        return FALSE;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    ULONG cb = ctxLC->cMemMap * sizeof(LC_MEMMAP_ENTRY);
    PUCHAR pb =
        (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cb ? cb : sizeof(LC_MEMMAP_ENTRY), LC_POOL_TAG);
    if (!pb) {
        return FALSE;
    }

    if (cb > 0) {
        UserVar->Func.RtlCopyMemory(pb, ctxLC->pMemMap, cb);
    }

    *ppbDataOut = pb;
    if (pcbDataOut) {
        *pcbDataOut = cb;
    }

    return TRUE;
}

NTSTATUS LcCore_Initialize(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    g_ctx.UserVar = UserVar;
    DBG("LcCore_Initialize: Initializing LeechCore engine...");
    if (!g_ctx.fInitialized) {
        g_ctx.Lock.Count = 1;
        g_ctx.Lock.Owner = NULL;
        g_ctx.Lock.Contention = 0;
        if (UserVar && UserVar->Func.KeInitializeEvent) {
            UserVar->Func.KeInitializeEvent(&g_ctx.Lock.Event, SynchronizationEvent, FALSE);
        }
        g_ctx.FLink = NULL;
        // 彻底启用硬件 PTE 跳板读写
        NTSTATUS status = LcPteEngine_Init();
        if (!NT_SUCCESS(status)) {
            DBG("LcCore_Initialize: LcPteEngine_Init failed with status 0x%08X", status);
            return status;
        }

        g_ctx.fInitialized = TRUE;
    }

    return STATUS_SUCCESS;
}

VOID LcCore_Cleanup(VOID)
{
    DBG("LcCore_Cleanup: Cleaning up LeechCore engine...");
    if (!g_ctx.fInitialized) {
        return;
    }

    ExAcquireFastMutex(&g_ctx.Lock);
    PLC_CONTEXT pCur = g_ctx.FLink;
    while (pCur)
    {
        PLC_CONTEXT pNext = pCur->FLink;
        MACHENIKE_KERNEL_INTERFACE *UserVar = pCur->UserVar;
        if (pCur->pfnClose) {
            pCur->pfnClose(pCur);
        }

        if (pCur->pMemMap && UserVar) {
            UserVar->Func.ExFreePoolWithTag(pCur->pMemMap, LC_POOL_TAG);
        }

        if (UserVar) {
            UserVar->Func.ExFreePoolWithTag(pCur, LC_POOL_TAG);
        }

        pCur = pNext;
    }

    g_ctx.FLink = NULL;
    ExReleaseFastMutex(&g_ctx.Lock);
    // ?? PTE ??
    LcPteEngine_Cleanup();
    g_ctx.fInitialized = FALSE;
    DBG("LcCore_Cleanup: Cleanup completed");
}

HANDLE LcCreateEx(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Inout_ PLC_CONFIG pLcCreateConfig,
                  _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    DBG("LcCreateEx: Creating new LeechCore context...");
    if (ppLcCreateErrorInfo) {
        *ppLcCreateErrorInfo = NULL;
    }

    if (!pLcCreateConfig || pLcCreateConfig->dwVersion != LC_CONFIG_VERSION) {
        DBG("LcCreateEx: Invalid config or version mismatch (Got=0x%08X, Expected=0x%08X)",
            pLcCreateConfig ? pLcCreateConfig->dwVersion : 0, LC_CONFIG_VERSION);
        return NULL;
    }

    if (!UserVar) {
        DBG("LcCreateEx: UserVar is NULL");
        return NULL;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sizeof(LC_CONTEXT), LC_POOL_TAG);
    if (!ctxLC) {
        return NULL;
    }

    UserVar->Func.RtlZeroMemory(ctxLC, sizeof(LC_CONTEXT));
    ctxLC->UserVar = UserVar;
    ctxLC->version = LC_CONTEXT_VERSION;
    ctxLC->Lock.Count = 1;
    ctxLC->Lock.Owner = NULL;
    ctxLC->Lock.Contention = 0;
    if (UserVar->Func.KeInitializeEvent) {
        UserVar->Func.KeInitializeEvent(&ctxLC->Lock.Event, SynchronizationEvent, FALSE);
    }
    pLcCreateConfig->fRemote = TRUE;
    pLcCreateConfig->fVolatile = TRUE;
    pLcCreateConfig->fWritable = TRUE;
    pLcCreateConfig->fRemoteDisableCompress = TRUE;
    UserVar->Func.RtlCopyMemory(pLcCreateConfig->szDeviceName, "MachenikeKernel", sizeof("MachenikeKernel"));
    UserVar->Func.RtlCopyMemory(&ctxLC->Config, pLcCreateConfig, sizeof(LC_CONFIG));
    ctxLC->pfnReadScatter = DeviceKernel_ReadScatter;
    ctxLC->pfnWriteScatter = DeviceKernel_WriteScatter;
    ctxLC->pfnGetOption = DeviceKernel_GetOption;
    ctxLC->pfnSetOption = DeviceKernel_SetOption;
    ctxLC->pfnCommand = DeviceKernel_Command;
    ctxLC->pfnClose = DeviceKernel_Close;
    ctxLC->cMemMapMax = 64;
    ctxLC->pMemMap = (PLC_MEMMAP_ENTRY)UserVar->Func.ExAllocatePoolWithTag(
        NonPagedPool, ctxLC->cMemMapMax * sizeof(LC_MEMMAP_ENTRY), LC_POOL_TAG);
    if (ctxLC->pMemMap) {
        UserVar->Func.RtlZeroMemory(ctxLC->pMemMap, ctxLC->cMemMapMax * sizeof(LC_MEMMAP_ENTRY));
    }

    PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange = UserVar->Func.MmGetPhysicalMemoryRanges();
    if (MmPhysicalMemoryRange) {
        int number_of_runs = 0;
        for (number_of_runs = 0; (MmPhysicalMemoryRange[number_of_runs].BaseAddress.QuadPart) ||
                                 (MmPhysicalMemoryRange[number_of_runs].NumberOfBytes.QuadPart);
             number_of_runs++)
            ;
        if (number_of_runs <= 100) {
            ctxLC->MemInfo.NumberOfRuns.QuadPart = number_of_runs;
            UserVar->Func.memmove(&ctxLC->MemInfo.Run[0], MmPhysicalMemoryRange,
                                  number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));
            if (ctxLC->pMemMap) {
                for (int r = 0; r < number_of_runs; r++)
                {
                    LcMemMap_AddRange(ctxLC, (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart,
                                      (ULONG64)MmPhysicalMemoryRange[r].NumberOfBytes.QuadPart,
                                      (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart);
                    ULONG64 runMax = (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart +
                                     (ULONG64)MmPhysicalMemoryRange[r].NumberOfBytes.QuadPart;
                    if (runMax > ctxLC->Config.paMax) {
                        ctxLC->Config.paMax = runMax;
                    }
                }
            }
        }
    }

    if (ctxLC->Config.paMax == 0) {
        ctxLC->Config.paMax = 0x1000000000ULL; // 兜底 64GB
    }
    pLcCreateConfig->paMax = ctxLC->Config.paMax;

    ExAcquireFastMutex(&g_ctx.Lock);
    ctxLC->FLink = g_ctx.FLink;
    g_ctx.FLink = ctxLC;
    ExReleaseFastMutex(&g_ctx.Lock);
    ctxLC->MemInfo.KernBase.QuadPart = _GetKernelBase();
    DBG("LcCreateEx: Initialized MemInfo: KernelBase=0x%llX", ctxLC->MemInfo.KernBase.QuadPart);
    DBG("LcCreateEx: LeechCore context created successfully (hLC=%p)", ctxLC);
    return (HANDLE)ctxLC;
}

VOID LcClose(_In_opt_ HANDLE hLC)
{
    if (!hLC) {
        return;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    ExAcquireFastMutex(&g_ctx.Lock);
    PLC_CONTEXT *ppCur = &g_ctx.FLink;
    while (*ppCur)
    {
        if (*ppCur == ctxLC) {
            *ppCur = ctxLC->FLink;
            break;
        }

        ppCur = &(*ppCur)->FLink;
    }

    ExReleaseFastMutex(&g_ctx.Lock);
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    if (ctxLC->pfnClose) {
        ctxLC->pfnClose(ctxLC);
    }

    if (ctxLC->pMemMap && UserVar) {
        UserVar->Func.ExFreePoolWithTag(ctxLC->pMemMap, LC_POOL_TAG);
    }

    if (UserVar) {
        UserVar->Func.ExFreePoolWithTag(ctxLC, LC_POOL_TAG);
    }
}

VOID LcReadScatter(_In_ HANDLE hLC, _In_ ULONG cMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!hLC || !ppMEMs || cMEMs == 0) {
        return;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->pfnReadScatter) {
        ctxLC->pfnReadScatter(ctxLC, cMEMs, ppMEMs);
    }
}

VOID LcWriteScatter(_In_ HANDLE hLC, _In_ ULONG cMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!hLC || !ppMEMs || cMEMs == 0) {
        return;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->pfnWriteScatter) {
        ctxLC->pfnWriteScatter(ctxLC, cMEMs, ppMEMs);
    }
}

BOOLEAN LcCommand(_In_ HANDLE hLC, _In_ ULONG64 fCommand, _In_ ULONG cbDataIn, _In_reads_opt_(cbDataIn) PUCHAR pbDataIn,
                  _Out_opt_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!hLC) {
        return FALSE;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->pfnCommand) {
        return ctxLC->pfnCommand(ctxLC, fCommand, cbDataIn, pbDataIn, ppbDataOut, pcbDataOut);
    }

    return FALSE;
}

BOOLEAN LcGetOption(_In_ HANDLE hLC, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if (!hLC) {
        return FALSE;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->pfnGetOption) {
        return ctxLC->pfnGetOption(ctxLC, fOption, pqwValue);
    }

    return FALSE;
}

BOOLEAN LcSetOption(_In_ HANDLE hLC, _In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    if (!hLC) {
        return FALSE;
    }

    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->pfnSetOption) {
        return ctxLC->pfnSetOption(ctxLC, fOption, qwValue);
    }

    return FALSE;
}