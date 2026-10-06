#include "leechcore_kernel.h"
#include "Common.h"

LC_MAIN_CONTEXT g_ctx = {0};





_IRQL_requires_max_(PASSIVE_LEVEL) ULONG
    PhysicalMemoryPartialRead(IN MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ LARGE_INTEGER physAddr, _Inout_ PUCHAR buf,
                              _In_ ULONG count)
{
    if (!UserVar || !UserVar->hPhysicalMemory || !buf || count == 0)
    {
        return 0;
    }

    ULONG page_offset = (ULONG)(physAddr.QuadPart % PAGE_SIZE);
    ULONG to_read = min(PAGE_SIZE - page_offset, count);
    PVOID mapped_buffer = NULL;
    SIZE_T ViewSize = PAGE_SIZE;
    LARGE_INTEGER offset = {0};
    offset.QuadPart = physAddr.QuadPart - page_offset;

    NTSTATUS status = UserVar->Func.ZwMapViewOfSection(
        UserVar->hPhysicalMemory, ZwCurrentProcess(), &mapped_buffer, 0L, PAGE_SIZE, &offset, &ViewSize, ViewUnmap, 0,
        PAGE_READONLY);

    if (!NT_SUCCESS(status) || !mapped_buffer)
    {
        MachenikePrint("PhysicalMemoryPartialRead failed: status=0x%08X, pa=0x%llX", status, physAddr.QuadPart);
        return 0;
    }

    ULONG result = 0;
    __try
    {
        UserVar->Func.memmove(buf, (PUCHAR)mapped_buffer + page_offset, to_read);
        result = to_read;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result = 0;
    }

    if (mapped_buffer)
    {
        UserVar->Func.ZwUnmapViewOfSection(ZwCurrentProcess(), mapped_buffer);
    }

    return result;
}

_IRQL_requires_max_(PASSIVE_LEVEL) ULONG
    PhysicalMemoryPartialWrite(IN MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ LARGE_INTEGER PhysicalAddress,
                               _In_ PUCHAR lpBuffer, _In_ SIZE_T Length)
{
    if (!UserVar || !UserVar->hPhysicalMemory || !lpBuffer || Length == 0)
    {
        return 0;
    }

    PVOID mapped_buffer = NULL;
    ULONG result = 0;
    ULONG page_offset = (ULONG)(PhysicalAddress.QuadPart % PAGE_SIZE);
    SIZE_T ViewSize = PAGE_SIZE;
    LARGE_INTEGER offset = {0};
    offset.QuadPart = PhysicalAddress.QuadPart - page_offset;

    NTSTATUS status = UserVar->Func.ZwMapViewOfSection(
        UserVar->hPhysicalMemory, ZwCurrentProcess(), &mapped_buffer, 0, Length, &offset, &ViewSize, ViewShare, 0,
        PAGE_READWRITE);

    if (!NT_SUCCESS(status) || !mapped_buffer)
    {
        MachenikePrint("Error %08x: ZwMapViewOfSection failed. physAddr was 0x%llX", status, PhysicalAddress.QuadPart);
        return 0;
    }

    __try
    {
        UserVar->Func.memmove((PUCHAR)mapped_buffer + page_offset, lpBuffer, Length);
        result = (ULONG)Length;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        result = 0;
    }

    if (mapped_buffer)
    {
        UserVar->Func.ZwUnmapViewOfSection(ZwCurrentProcess(), mapped_buffer);
    }

    return result;
}

static ULONG KernelReadPhysContiguous(IN MACHENIKE_KERNEL_INTERFACE *UserVar, LARGE_INTEGER physAddr, PUCHAR buf, ULONG count)
{
    if (!UserVar || !buf || count == 0)
    {
        return 0;
    }

    ULONG uReadOffset = 0;
    PUCHAR pCurrentOut = buf;
    LARGE_INTEGER currentPa = physAddr;

    while (uReadOffset < count)
    {
        ULONG uCurrentReadWindow = min(PAGE_SIZE, count - uReadOffset);
        ULONG uReadLength = PhysicalMemoryPartialRead(UserVar, currentPa, pCurrentOut, uCurrentReadWindow);
        if (uReadLength == 0)
        {
            break;
        }
        currentPa.QuadPart += uReadLength;
        pCurrentOut += uReadLength;
        uReadOffset += uReadLength;
    }

    return uReadOffset;
}

static ULONG KernelWritePhysContiguous(IN MACHENIKE_KERNEL_INTERFACE *UserVar, LARGE_INTEGER physAddr, PUCHAR buf, ULONG count)
{
    if (!UserVar || !buf || count == 0)
    {
        return 0;
    }

    ULONG uWriteOffset = 0;
    PUCHAR pCurrentIn = buf;
    LARGE_INTEGER currentPa = physAddr;

    while (uWriteOffset < count)
    {
        ULONG uCurrentWriteWindow = min(PAGE_SIZE, count - uWriteOffset);
        ULONG uWritten = PhysicalMemoryPartialWrite(UserVar, currentPa, pCurrentIn, uCurrentWriteWindow);
        if (uWritten == 0)
        {
            break;
        }
        currentPa.QuadPart += uWritten;
        pCurrentIn += uWritten;
        uWriteOffset += uWritten;
    }

    return uWriteOffset;
}





static ULONG DeviceKernel_ReadPhys(
    _In_ PLC_CONTEXT ctxLC,
    _In_ LARGE_INTEGER physAddr,
    _Out_writes_bytes_(count) PUCHAR buf,
    _In_ ULONG count)
{
    if (!ctxLC || !ctxLC->UserVar || !ctxLC->UserVar->hPhysicalMemory || !buf || count == 0)
    {
        return 0;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    ULONG uReadOffset = 0;

    while (uReadOffset < count)
    {
        LARGE_INTEGER curPa;
        curPa.QuadPart = physAddr.QuadPart + uReadOffset;
        ULONG windowOffset = (ULONG)(curPa.QuadPart & LC_PAGE_WINDOW_MASK);
        ULONG to_read = (ULONG)min((ULONG64)(LC_PAGE_WINDOW_SIZE - windowOffset), (ULONG64)(count - uReadOffset));
        ULONG64 targetWindowBase = curPa.QuadPart - windowOffset;


        ULONG slotIndex = (ULONG)((targetWindowBase >> 16) & (LC_PAGE_CACHE_SLOTS - 1));


        if (ctxLC->PageCache[slotIndex].pMappedVa == NULL || ctxLC->PageCache[slotIndex].PhysWindowBase != targetWindowBase)
        {

            if (ctxLC->PageCache[slotIndex].pMappedVa != NULL)
            {
                UserVar->Func.ZwUnmapViewOfSection(ZwCurrentProcess(), ctxLC->PageCache[slotIndex].pMappedVa);
                ctxLC->PageCache[slotIndex].pMappedVa = NULL;
                ctxLC->PageCache[slotIndex].PhysWindowBase = (ULONG64)-1;
            }

            PVOID mapped_buffer = NULL;
            SIZE_T ViewSize = LC_PAGE_WINDOW_SIZE;
            LARGE_INTEGER offset;
            offset.QuadPart = targetWindowBase;

            NTSTATUS status = UserVar->Func.ZwMapViewOfSection(
                UserVar->hPhysicalMemory, ZwCurrentProcess(), &mapped_buffer, 0L, LC_PAGE_WINDOW_SIZE, &offset, &ViewSize, ViewUnmap, 0,
                PAGE_READONLY);

            if (!NT_SUCCESS(status) || !mapped_buffer)
            {
                break;
            }

            ctxLC->PageCache[slotIndex].pMappedVa = mapped_buffer;
            ctxLC->PageCache[slotIndex].PhysWindowBase = targetWindowBase;
        }

        __try
        {
            UserVar->Func.memmove(buf + uReadOffset, (PUCHAR)ctxLC->PageCache[slotIndex].pMappedVa + windowOffset, to_read);
            uReadOffset += to_read;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }
    }

    return uReadOffset;
}

static VOID DeviceKernel_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ ULONG cpMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!ctxLC || !ctxLC->UserVar)
    {
        return;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;

    for (ULONG i = 0; i < cpMEMs; i++)
    {
        PMEM_SCATTER pMEM = ppMEMs[i];
        if (!pMEM || !pMEM->pb || pMEM->cb == 0)
        {
            if (pMEM)
            {
                pMEM->f = FALSE;
            }
            continue;
        }
        LARGE_INTEGER pa;
        pa.QuadPart = pMEM->qwA;
        ULONG nRead = DeviceKernel_ReadPhys(ctxLC, pa, pMEM->pb, pMEM->cb);
        if (nRead == pMEM->cb)
        {
            pMEM->f = TRUE;
        }
        else
        {
            pMEM->f = FALSE;
            UserVar->Func.RtlZeroMemory(pMEM->pb, pMEM->cb);
        }
    }
}

static VOID DeviceKernel_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ ULONG cpMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!ctxLC || !ctxLC->UserVar)
    {
        return;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;

    for (ULONG i = 0; i < cpMEMs; i++)
    {
        PMEM_SCATTER pMEM = ppMEMs[i];
        if (!pMEM || !pMEM->pb || pMEM->cb == 0)
        {
            if (pMEM)
            {
                pMEM->f = FALSE;
            }
            continue;
        }
        LARGE_INTEGER pa;
        pa.QuadPart = pMEM->qwA;
        ULONG nWritten = KernelWritePhysContiguous(UserVar, pa, pMEM->pb, pMEM->cb);
        pMEM->f = (nWritten == pMEM->cb);
    }
}

static BOOLEAN DeviceKernel_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if (!ctxLC || !pqwValue)
    {
        return FALSE;
    }
    if (fOption == LC_OPT_CORE_ADDR_MAX)
    {
        *pqwValue = ctxLC->Config.paMax;
        return TRUE;
    }
    *pqwValue = 0;
    return TRUE;
}

BOOLEAN LcMemMap_GetRangesAsText(_In_ PLC_CONTEXT ctxLC, _Out_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!ctxLC || !ppbDataOut || !ctxLC->UserVar)
    {
        return FALSE;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;

    if (ctxLC->cMemMap == 0 || ctxLC->cMemMap > 1024)
    {
        return FALSE;
    }

    ULONG cb = ctxLC->cMemMap * 64 + 1;
    PCHAR pb = (PCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cb, LC_POOL_TAG);
    if (!pb)
    {
        return FALSE;
    }
    UserVar->Func.RtlZeroMemory(pb, cb);

    ULONG o = 0;
    for (ULONG i = 0; i < ctxLC->cMemMap && o < cb - 64; i++)
    {
        ULONG64 paStart = ctxLC->pMemMap[i].pa;
        ULONG64 paEnd = ctxLC->pMemMap[i].pa + ctxLC->pMemMap[i].cb - 1;
        ULONG64 paRemap = ctxLC->pMemMap[i].paRemap;

        int written = sprintf_s(pb + o, cb - o, "%04x %016llx - %016llx -> %016llx\n",
                                i, paStart, paEnd, paRemap);
        if (written > 0)
        {
            o += (ULONG)written;
        }
    }

    pb[cb - 1] = '\0';
    *ppbDataOut = (PUCHAR)pb;
    if (pcbDataOut)
    {
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
    if (ppbDataOut)
    {
        *ppbDataOut = NULL;
    }
    if (pcbDataOut)
    {
        *pcbDataOut = 0;
    }
    return FALSE;
}

static VOID DeviceKernel_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    if (!ctxLC)
    {
        return;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;
    if (UserVar)
    {
        for (ULONG i = 0; i < LC_PAGE_CACHE_SLOTS; i++)
        {
            if (ctxLC->PageCache[i].pMappedVa)
            {
                UserVar->Func.ZwUnmapViewOfSection(ZwCurrentProcess(), ctxLC->PageCache[i].pMappedVa);
                ctxLC->PageCache[i].pMappedVa = NULL;
                ctxLC->PageCache[i].PhysWindowBase = (ULONG64)-1;
            }
        }
    }
}





BOOLEAN LcMemMap_AddRange(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 pa, _In_ ULONG64 cb, _In_ ULONG64 paRemap)
{
    if (!ctxLC || !ctxLC->pMemMap || !ctxLC->UserVar)
    {
        return FALSE;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;

    if ((cb & 0xfff) == 1)
    {
        cb--;
    }
    if ((pa & 0xfff) || (cb & 0xfff))
    {
        return FALSE;
    }
    if (ctxLC->cMemMap >= 0x00100000)
    {
        return FALSE;
    }

    if (ctxLC->cMemMap == ctxLC->cMemMapMax)
    {
        ULONG newMax = ctxLC->cMemMapMax * 2;
        PLC_MEMMAP_ENTRY pNew = (PLC_MEMMAP_ENTRY)UserVar->Func.ExAllocatePoolWithTag(
            NonPagedPool, newMax * sizeof(LC_MEMMAP_ENTRY), LC_POOL_TAG);
        if (!pNew)
        {
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
    if (ctxLC->cMemMap == 0)
    {
        return 0x0000ffffffffffffULL;
    }
    return ctxLC->pMemMap[ctxLC->cMemMap - 1].pa + ctxLC->pMemMap[ctxLC->cMemMap - 1].cb;
}

BOOLEAN LcMemMap_GetRangesAsStruct(_In_ PLC_CONTEXT ctxLC, _Out_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!ctxLC || !ppbDataOut || !ctxLC->UserVar)
    {
        return FALSE;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;

    ULONG cb = ctxLC->cMemMap * sizeof(LC_MEMMAP_ENTRY);
    PUCHAR pb = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, cb ? cb : sizeof(LC_MEMMAP_ENTRY),
                                                           LC_POOL_TAG);
    if (!pb)
    {
        return FALSE;
    }
    if (cb > 0)
    {
        UserVar->Func.RtlCopyMemory(pb, ctxLC->pMemMap, cb);
    }
    *ppbDataOut = pb;
    if (pcbDataOut)
    {
        *pcbDataOut = cb;
    }
    return TRUE;
}





NTSTATUS LcCore_Initialize(VOID)
{
    MachenikePrint("LcCore_Initialize: Initializing LeechCore engine...");
    if (!g_ctx.fInitialized)
    {
        ExInitializeFastMutex(&g_ctx.Lock);
        g_ctx.FLink = NULL;
        g_ctx.fInitialized = TRUE;
    }
    return STATUS_SUCCESS;
}

VOID LcCore_Cleanup(VOID)
{
    MachenikePrint("LcCore_Cleanup: Cleaning up LeechCore engine...");
    if (!g_ctx.fInitialized)
    {
        return;
    }

    ExAcquireFastMutex(&g_ctx.Lock);
    PLC_CONTEXT pCur = g_ctx.FLink;
    while (pCur)
    {
        PLC_CONTEXT pNext = pCur->FLink;
        MACHENIKE_KERNEL_INTERFACE *UserVar = pCur->UserVar;

        if (pCur->pfnClose)
        {
            pCur->pfnClose(pCur);
        }
        if (pCur->pMemMap && UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pCur->pMemMap, LC_POOL_TAG);
        }
        if (UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pCur, LC_POOL_TAG);
        }
        pCur = pNext;
    }
    g_ctx.FLink = NULL;
    ExReleaseFastMutex(&g_ctx.Lock);

    g_ctx.fInitialized = FALSE;
    MachenikePrint("LcCore_Cleanup: Cleanup completed");
}

HANDLE LcCreateEx(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Inout_ PLC_CONFIG pLcCreateConfig, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    MachenikePrint("LcCreateEx: Creating new LeechCore context...");
    if (ppLcCreateErrorInfo)
    {
        *ppLcCreateErrorInfo = NULL;
    }
    if (!pLcCreateConfig || pLcCreateConfig->dwVersion != LC_CONFIG_VERSION)
    {
        MachenikePrint("LcCreateEx: Invalid config or version mismatch (Got=0x%08X, Expected=0x%08X)",
                       pLcCreateConfig ? pLcCreateConfig->dwVersion : 0, LC_CONFIG_VERSION);
        return NULL;
    }
    if (!UserVar)
    {
        MachenikePrint("LcCreateEx: UserVar is NULL");
        return NULL;
    }


    PLC_CONTEXT ctxLC =
        (PLC_CONTEXT)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sizeof(LC_CONTEXT), LC_POOL_TAG);
    if (!ctxLC)
    {
        return NULL;
    }

    UserVar->Func.RtlZeroMemory(ctxLC, sizeof(LC_CONTEXT));
    ctxLC->UserVar = UserVar;
    ctxLC->version = LC_CONTEXT_VERSION;
    ctxLC->dwHandleCount = 1;
    for (ULONG i = 0; i < LC_PAGE_CACHE_SLOTS; i++)
    {
        ctxLC->PageCache[i].PhysWindowBase = (ULONG64)-1;
    }
    ExInitializeFastMutex(&ctxLC->Lock);


    pLcCreateConfig->fRemote = TRUE;
    pLcCreateConfig->fVolatile = TRUE;
    pLcCreateConfig->fWritable = TRUE;
    pLcCreateConfig->fRemoteDisableCompress = TRUE;
    strcpy_s(pLcCreateConfig->szDeviceName, sizeof(pLcCreateConfig->szDeviceName), "MachenikeKernel");
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
    if (ctxLC->pMemMap)
    {
        UserVar->Func.RtlZeroMemory(ctxLC->pMemMap, ctxLC->cMemMapMax * sizeof(LC_MEMMAP_ENTRY));
    }

    PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange = UserVar->Func.MmGetPhysicalMemoryRanges();
    if (MmPhysicalMemoryRange)
    {
        int number_of_runs = 0;
        for (number_of_runs = 0; (MmPhysicalMemoryRange[number_of_runs].BaseAddress.QuadPart) ||
                                 (MmPhysicalMemoryRange[number_of_runs].NumberOfBytes.QuadPart);
             number_of_runs++)
            ;

        if (number_of_runs <= 100)
        {
            ctxLC->MemInfo.NumberOfRuns.QuadPart = number_of_runs;
            UserVar->Func.memmove(&ctxLC->MemInfo.Run[0], MmPhysicalMemoryRange,
                                 number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));

            if (ctxLC->pMemMap)
            {
                for (int r = 0; r < number_of_runs; r++)
                {
                    LcMemMap_AddRange(ctxLC, (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart,
                                      (ULONG64)MmPhysicalMemoryRange[r].NumberOfBytes.QuadPart,
                                      (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart);
                    ULONG64 runMax = (ULONG64)MmPhysicalMemoryRange[r].BaseAddress.QuadPart +
                                     (ULONG64)MmPhysicalMemoryRange[r].NumberOfBytes.QuadPart;
                    if (runMax > ctxLC->Config.paMax)
                    {
                        ctxLC->Config.paMax = runMax;
                    }
                }
            }
        }
        UserVar->Func.ExFreePoolWithTag(MmPhysicalMemoryRange, 0);
    }


    ctxLC->MemInfo.CR3.QuadPart = UserVar->Cr3.QuadPart;
    ctxLC->MemInfo.NtBuildNumber.QuadPart = UserVar->NtBuildNumber.QuadPart;
    ctxLC->MemInfo.NtBuildNumberAddr.QuadPart = UserVar->NtBuildNumberAddr.QuadPart;
    ctxLC->MemInfo.KernBase.QuadPart = UserVar->KernelBase.QuadPart;

    SIZE_T ActiveProcessors = UserVar->Func.KeQueryActiveProcessors();
    UserVar->Func.RtlZeroMemory(ctxLC->MemInfo.KPCR, sizeof(ctxLC->MemInfo.KPCR));
    for (SIZE_T i = 0; i < ActiveProcessors && i < 64; i++)
    {
        GROUP_AFFINITY Affinity = {0};
        Affinity.Group = 0;
        Affinity.Mask = (KAFFINITY)1 << i;
        PROCESSOR_NUMBER ProcNum;
        if (KeGetProcessorNumberFromIndex((ULONG)i, &ProcNum) == STATUS_SUCCESS)
        {
            UserVar->Func.KeSetSystemAffinityThread((SIZE_T)1 << i);
            ctxLC->MemInfo.KPCR[i].QuadPart = __readgsqword(0x18);
            UserVar->Func.KeRevertToUserAffinityThread();
        }
    }

    ctxLC->Config.paMax = LcMemMap_GetMaxAddress(ctxLC);
    pLcCreateConfig->paMax = ctxLC->Config.paMax;


    ExAcquireFastMutex(&g_ctx.Lock);
    ctxLC->FLink = g_ctx.FLink;
    g_ctx.FLink = ctxLC;
    ExReleaseFastMutex(&g_ctx.Lock);

    MachenikePrint("LcCreateEx: Context created successfully! Handle = %p", ctxLC);
    return (HANDLE)ctxLC;
}

VOID LcClose(_In_opt_ HANDLE hLC)
{
    if (!hLC)
    {
        return;
    }
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;

    ExAcquireFastMutex(&ctxLC->Lock);
    ctxLC->dwHandleCount--;
    if (ctxLC->dwHandleCount > 0)
    {
        ExReleaseFastMutex(&ctxLC->Lock);
        return;
    }
    ExReleaseFastMutex(&ctxLC->Lock);

    ExAcquireFastMutex(&g_ctx.Lock);


    PLC_CONTEXT *ppCur = &g_ctx.FLink;
    while (*ppCur)
    {
        if (*ppCur == ctxLC)
        {
            *ppCur = ctxLC->FLink;
            break;
        }
        ppCur = &((*ppCur)->FLink);
    }
    ExReleaseFastMutex(&g_ctx.Lock);

    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;


    if (ctxLC->pfnClose)
    {
        ctxLC->pfnClose(ctxLC);
    }
    if (ctxLC->pMemMap && UserVar)
    {
        UserVar->Func.ExFreePoolWithTag(ctxLC->pMemMap, LC_POOL_TAG);
        ctxLC->pMemMap = NULL;
    }
    if (UserVar)
    {
        UserVar->Func.ExFreePoolWithTag(ctxLC, LC_POOL_TAG);
    }
}

VOID LcReadScatter(_In_ HANDLE hLC, _In_ ULONG cMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!hLC || cMEMs == 0 || !ppMEMs)
    {
        return;
    }
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if (ctxLC->pfnReadScatter)
    {
        ctxLC->pfnReadScatter(ctxLC, cMEMs, ppMEMs);
    }
}

VOID LcWriteScatter(_In_ HANDLE hLC, _In_ ULONG cMEMs, _Inout_ PMEM_SCATTER *ppMEMs)
{
    if (!hLC || cMEMs == 0 || !ppMEMs)
    {
        return;
    }
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    ExAcquireFastMutex(&ctxLC->Lock);
    if (ctxLC->pfnWriteScatter)
    {
        ctxLC->pfnWriteScatter(ctxLC, cMEMs, ppMEMs);
    }
    ExReleaseFastMutex(&ctxLC->Lock);
}

BOOLEAN LcCommand(_In_ HANDLE hLC, _In_ ULONG64 fCommand, _In_ ULONG cbDataIn, _In_reads_opt_(cbDataIn) PUCHAR pbDataIn,
                  _Out_opt_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut)
{
    if (!hLC)
    {
        return FALSE;
    }
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    MACHENIKE_KERNEL_INTERFACE *UserVar = ctxLC->UserVar;

    ExAcquireFastMutex(&ctxLC->Lock);
    BOOLEAN result = FALSE;
    switch (fCommand)
    {
    case LC_CMD_MEMMAP_GET:
        result = LcMemMap_GetRangesAsText(ctxLC, ppbDataOut, pcbDataOut);
        break;

    case LC_CMD_MEMMAP_GET_STRUCT:
        result = LcMemMap_GetRangesAsStruct(ctxLC, ppbDataOut, pcbDataOut);
        break;

    case LC_CMD_WINPMEM_GET_INFO:

        if (ppbDataOut && pcbDataOut && UserVar)
        {
            *pcbDataOut = sizeof(WINPMEM_MEMORY_INFO);
            *ppbDataOut = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(
                NonPagedPool, sizeof(WINPMEM_MEMORY_INFO), LC_POOL_TAG);
            if (*ppbDataOut)
            {
                UserVar->Func.RtlCopyMemory(*ppbDataOut, &ctxLC->MemInfo, sizeof(WINPMEM_MEMORY_INFO));
                result = TRUE;
            }
        }
        break;

    case LC_CMD_STATISTICS_GET:
        if (ppbDataOut && pcbDataOut && UserVar)
        {
            *pcbDataOut = sizeof(LC_STATISTICS);
            *ppbDataOut = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPool, sizeof(LC_STATISTICS),
                                                                                 LC_POOL_TAG);
            if (*ppbDataOut)
            {
                UserVar->Func.RtlZeroMemory(*ppbDataOut, sizeof(LC_STATISTICS));
                result = TRUE;
            }
        }
        break;

    default:
        if (ctxLC->pfnCommand)
        {
            result = ctxLC->pfnCommand(ctxLC, fCommand, cbDataIn, pbDataIn, ppbDataOut, pcbDataOut);
        }
        break;
    }
    ExReleaseFastMutex(&ctxLC->Lock);
    return result;
}

BOOLEAN LcGetOption(_In_ HANDLE hLC, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if (!hLC)
    {
        return FALSE;
    }
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    ExAcquireFastMutex(&ctxLC->Lock);
    BOOLEAN result = FALSE;
    if (ctxLC->pfnGetOption)
    {
        result = ctxLC->pfnGetOption(ctxLC, fOption, pqwValue);
    }
    ExReleaseFastMutex(&ctxLC->Lock);
    return result;
}

BOOLEAN LcSetOption(_In_ HANDLE hLC, _In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    if (!hLC)
    {
        return FALSE;
    }
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    ExAcquireFastMutex(&ctxLC->Lock);
    BOOLEAN result = FALSE;
    if (ctxLC->pfnSetOption)
    {
        result = ctxLC->pfnSetOption(ctxLC, fOption, qwValue);
    }
    ExReleaseFastMutex(&ctxLC->Lock);
    return result;
}
