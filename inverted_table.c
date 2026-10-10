#include "inverted_table.h"

static PRTL_INVERTED_FUNCTION_TABLE g_pInvertedTable = NULL;

PRTL_INVERTED_FUNCTION_TABLE InvertedTable_Locate(_In_ PVOID NtoskrnlBase)
{
    if (g_pInvertedTable)
        return g_pInvertedTable;

    if (!NtoskrnlBase)
        return NULL;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)NtoskrnlBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((PUCHAR)NtoskrnlBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    PUCHAR pData = NULL;
    ULONG cbData = 0;

    for (USHORT i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++)
    {
        if (RtlCompareMemory(pSec->Name, ".data", 5) == 5)
        {
            pData = (PUCHAR)NtoskrnlBase + pSec->VirtualAddress;
            cbData = pSec->Misc.VirtualSize;
            break;
        }
    }

    if (!pData || cbData < sizeof(RTL_INVERTED_FUNCTION_TABLE))
        return NULL;

    // 启发式结构指纹扫描（Heuristic Table Structural Scan）
    // 在 ntoskrnl.exe 的 .data 节中按 8 字节步长搜索全系统唯一的表特征
    for (ULONG off = 0; off + sizeof(RTL_INVERTED_FUNCTION_TABLE) + 4 * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY) < cbData; off += 8)
    {
        PRTL_INVERTED_FUNCTION_TABLE pCandidate = (PRTL_INVERTED_FUNCTION_TABLE)(pData + off);

        // 1. 容量与计数约束验证
        if (pCandidate->Count < 30 || pCandidate->Count > 2000)
            continue;

        if (pCandidate->MaxCount != 0x200 && pCandidate->MaxCount != 0x400 && pCandidate->MaxCount != 0x100)
            continue;

        if (pCandidate->Overflow != 0)
            continue;

        // 2. 验证条目单调递增性与内核地址属性
        BOOLEAN bValid = TRUE;
        ULONG_PTR prevBase = 0;

        for (ULONG k = 0; k < 4; k++)
        {
            PRTL_INVERTED_FUNCTION_TABLE_ENTRY pEntry = &pCandidate->TableEntry[k];
            ULONG_PTR curBase = (ULONG_PTR)pEntry->ImageBase;

            // 必须为合法 64 位内核地址空间
            if (curBase < 0xFFFF800000000000ULL)
            {
                bValid = FALSE;
                break;
            }

            // 镜像大小必须合规 (4KB ~ 512MB)
            if (pEntry->ImageSize < 0x1000 || pEntry->ImageSize > 0x20000000)
            {
                bValid = FALSE;
                break;
            }

            // 数组必须按 ImageBase 升序严格排列
            if (curBase <= prevBase)
            {
                bValid = FALSE;
                break;
            }

            prevBase = curBase;
        }

        if (bValid)
        {
            g_pInvertedTable = pCandidate;
            DBG("InvertedTable: Successfully located nt!PsInvertedFunctionTable at 0x%p (Count=%lu, MaxCount=%lu)",
                (PVOID)pCandidate, pCandidate->Count, pCandidate->MaxCount);
            return pCandidate;
        }
    }

    DBG("InvertedTable: Failed to locate PsInvertedFunctionTable in .data section");
    return NULL;
}

NTSTATUS InvertedTable_HookHost(
    _In_  PVOID NtoskrnlBase,
    _In_  PVOID HostImageBase,
    _In_  PVOID MergedPdataVa,
    _In_  ULONG MergedPdataCount,
    _Out_ PINVERTED_TABLE_BACKUP Backup
)
{
    if (!HostImageBase || !MergedPdataVa || !MergedPdataCount || !Backup)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Backup, sizeof(INVERTED_TABLE_BACKUP));

    PRTL_INVERTED_FUNCTION_TABLE pTable = InvertedTable_Locate(NtoskrnlBase);
    if (!pTable)
        return STATUS_NOT_FOUND;

    // 二分搜索或线性遍历定位宿主模块条目
    for (ULONG i = 0; i < pTable->Count; i++)
    {
        PRTL_INVERTED_FUNCTION_TABLE_ENTRY pEntry = &pTable->TableEntry[i];
        if (pEntry->ImageBase == HostImageBase)
        {
            // 备份原始状态以支持原子回滚
            Backup->TargetEntry               = pEntry;
            Backup->OriginalExceptionDirectory = pEntry->ExceptionDirectory;
            Backup->OriginalSizeOfTable        = pEntry->SizeOfTable;

            // 原子替换 ExceptionDirectory 指针并更新元素数量
            // 此时无论反作弊 NMI 何时抓栈，展开器均能精准找到补全后的 RUNTIME_FUNCTION
            InterlockedExchangePointer(&pEntry->ExceptionDirectory, MergedPdataVa);
            InterlockedExchange((volatile LONG *)&pEntry->SizeOfTable, (LONG)MergedPdataCount);

            DBG("InvertedTable: Hooked host 0x%p entry! .pdata: 0x%p -> 0x%p (Count: %lu -> %lu)",
                HostImageBase,
                Backup->OriginalExceptionDirectory, MergedPdataVa,
                Backup->OriginalSizeOfTable, MergedPdataCount);

            return STATUS_SUCCESS;
        }
    }

    DBG("InvertedTable: Host 0x%p not found in PsInvertedFunctionTable", HostImageBase);
    return STATUS_NOT_FOUND;
}

NTSTATUS InvertedTable_Restore(_In_ PINVERTED_TABLE_BACKUP Backup)
{
    if (!Backup || !Backup->TargetEntry)
        return STATUS_INVALID_PARAMETER;

    PRTL_INVERTED_FUNCTION_TABLE_ENTRY pEntry = Backup->TargetEntry;

    // 原子恢复宿主原始异常表指针与数量
    InterlockedExchangePointer(&pEntry->ExceptionDirectory, Backup->OriginalExceptionDirectory);
    InterlockedExchange((volatile LONG *)&pEntry->SizeOfTable, (LONG)Backup->OriginalSizeOfTable);

    DBG("InvertedTable: Restored host entry to original .pdata 0x%p (Count: %lu)",
        Backup->OriginalExceptionDirectory, Backup->OriginalSizeOfTable);

    RtlZeroMemory(Backup, sizeof(INVERTED_TABLE_BACKUP));
    return STATUS_SUCCESS;
}
