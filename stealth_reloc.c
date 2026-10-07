#include "stealth_reloc.h"

#define MK_STEALTH_TAG 'lsMF'

/* ============================================================
 * Fake LDR Entry 全局状态
 * ============================================================ */
static PMK_FAKE_LDR_BLOCK     g_pFakeLdrBlock = NULL;
static PKLDR_DATA_TABLE_ENTRY g_pRealLdrEntry = NULL;

/*
 * Stealth_InsertFakeLdrEntry — 原子原地替换 + 伪造 LDR 项挂入
 *
 * 模块隐藏三层防线：
 *   层 1 (链表)：将真实 KLDR_DATA_TABLE_ENTRY 与伪造项原子交换——
 *           ACE 枚举 PsLoadedModuleList 时只能看到伪造项
 *   层 2 (RtlVirtualUnwind)：伪造项 DllBase/SizeOfImage 与真实片段对应，
 *           ExceptionTable 指向真实 .pdata——
 *           栈回溯能找到正确的 RUNTIME_FUNCTION 并成功展开
 *   层 3 (名称)：BaseDllName/FullDllName 伪装为合法系统驱动名
 */
NTSTATUS Stealth_InsertFakeLdrEntry(
    IN MACHENIKE_KERNEL_INTERFACE *UserVar,
    IN PDRIVER_OBJECT pDriverObj,
    IN OPTIONAL PVOID pActualImageBase,
    IN PCWSTR pFakeBaseName,
    IN PCWSTR pFakeFullPath
)
{
    if (!UserVar || !pDriverObj || !pDriverObj->DriverStart || !pFakeBaseName || !pFakeFullPath)
        return STATUS_INVALID_PARAMETER;

    /* Step 1: 获取真实宿主 KLDR_DATA_TABLE_ENTRY */
    PKLDR_DATA_TABLE_ENTRY pRealEntry =
        (PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;
    if (!pRealEntry)
        return STATUS_NOT_FOUND;

    /* 确定目标镜像基址：若显式传入 pActualImageBase (例如内存池基址) 则使用之，否则使用 DriverStart */
    PVOID pTargetImageBase = pActualImageBase ? pActualImageBase : pDriverObj->DriverStart;

    /* Step 2: 在 PsLoadedModuleList 中验证宿主项存在 */
    BOOLEAN bFound = FALSE;
    if (pRealEntry->DllBase == pDriverObj->DriverStart)
    {
        bFound = TRUE;
    }
    else
    {
        PLIST_ENTRY pHead = &pRealEntry->InLoadOrderLinks;
        PLIST_ENTRY pCurr = pHead->Flink;
        for (int i = 0; i < 512; i++)
        {
            if (pCurr == pHead) break;
            PKLDR_DATA_TABLE_ENTRY pE =
                CONTAINING_RECORD(pCurr, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (pE->DllBase == pDriverObj->DriverStart)
            {
                bFound     = TRUE;
                pRealEntry = pE;
                break;
            }
            pCurr = pCurr->Flink;
        }
    }

    if (!bFound)
    {
        DBG("[-] Stealth_InsertFakeLdrEntry: DllBase not found in PsLoadedModuleList");
        return STATUS_NOT_FOUND;
    }

    /* Step 3: 解析 PE 头 —— 获取 SizeOfImage 与 .pdata 异常展开表 */
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pTargetImageBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_NT_HEADERS64 pNt =
        (PIMAGE_NT_HEADERS64)((PCHAR)pTargetImageBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;

    ULONG checkSum    = pNt->OptionalHeader.CheckSum;

    /* .pdata 节 (IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3) */
    PVOID pExTable    = NULL;
    ULONG exTableSize = 0;
    if (pNt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
    {
        IMAGE_DATA_DIRECTORY exDir =
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exDir.VirtualAddress && exDir.Size)
        {
            pExTable    = (PVOID)((PCHAR)pTargetImageBase + exDir.VirtualAddress);
            exTableSize = exDir.Size;
            DBG("[*] Stealth_InsertFakeLdrEntry: ExceptionTable=0x%p Size=0x%X",
                pExTable, exTableSize);
        }
    }

    /* Step 4: 计算名称长度（手工 wcslen，不依赖 CRT） */
    ULONG baseLen = 0, fullLen = 0;
    while (pFakeBaseName[baseLen]) baseLen++;
    while (pFakeFullPath[fullLen]) fullLen++;

    if (baseLen >= MK_FAKE_LDR_BASE_NAME_MAX || fullLen >= MK_FAKE_LDR_FULL_NAME_MAX)
    {
        DBG("[-] Stealth_InsertFakeLdrEntry: name too long");
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Step 5: 分配 MK_FAKE_LDR_BLOCK（LdrEntry + 嵌入式名称缓冲区） */
    PMK_FAKE_LDR_BLOCK pBlock = (PMK_FAKE_LDR_BLOCK)UserVar->Func.ExAllocatePoolWithTag(
        NonPagedPool, sizeof(MK_FAKE_LDR_BLOCK), MK_STEALTH_TAG);
    if (!pBlock)
        return STATUS_INSUFFICIENT_RESOURCES;

    UserVar->Func.RtlZeroMemory(pBlock, sizeof(MK_FAKE_LDR_BLOCK));

    /* Step 6: 填充 KLDR_DATA_TABLE_ENTRY 字段 —— 完全克隆宿主真实属性与签名，防止双重 DllBase 与重名审计 */
    PKLDR_DATA_TABLE_ENTRY pFakeEntry = &pBlock->LdrEntry;

    /* 
     * 关键对齐：DllBase 严格设为宿主 DriverStart，
     * 避免系统中出现两个同名模块或指向未决内存池的双重 DllBase 暴露点。
     * 若宿主经过尾部节区扩展，DriverSize 将大于原 SizeOfImage，此处优先使用扩展后的尺寸。
     */
    pFakeEntry->DllBase            = pDriverObj->DriverStart;
    pFakeEntry->EntryPoint         = pRealEntry->EntryPoint;
    ULONG effectiveHostSize        = pRealEntry->SizeOfImage;
    if (pDriverObj->DriverSize > effectiveHostSize)
        effectiveHostSize = pDriverObj->DriverSize;
    pFakeEntry->SizeOfImage        = effectiveHostSize;
    /* 优先使用宿主已有的（或经过 loader 合并扩展的）ExceptionTable，确保宿主与扩展代码均可正常堆栈展开 */
    pFakeEntry->ExceptionTable     = pRealEntry->ExceptionTable ? pRealEntry->ExceptionTable : pExTable;
    pFakeEntry->ExceptionTableSize = pRealEntry->ExceptionTableSize ? pRealEntry->ExceptionTableSize : exTableSize;

    /* 完整克隆宿主签名属性与内核系统加载标识 */
    pFakeEntry->Flags              = pRealEntry->Flags;
    pFakeEntry->LoadCount          = pRealEntry->LoadCount;
    pFakeEntry->CheckSum           = pRealEntry->CheckSum ? pRealEntry->CheckSum : checkSum;
    pFakeEntry->GpValue            = pRealEntry->GpValue;
    pFakeEntry->NonPagedDebugInfo  = pRealEntry->NonPagedDebugInfo;
    pFakeEntry->SectionPointer     = pRealEntry->SectionPointer;
    pFakeEntry->LoadedImports      = pRealEntry->LoadedImports;
    pFakeEntry->PatchInformation   = pRealEntry->PatchInformation;

    /* Step 7: 填充嵌入式名称缓冲区（优先沿用宿主原始名称或调用方伪装名） */
    if (pRealEntry->BaseDllName.Buffer && pRealEntry->BaseDllName.Length > 0)
    {
        ULONG copyChars = pRealEntry->BaseDllName.Length / sizeof(WCHAR);
        if (copyChars >= MK_FAKE_LDR_BASE_NAME_MAX) copyChars = MK_FAKE_LDR_BASE_NAME_MAX - 1;
        for (ULONG i = 0; i < copyChars; i++)
            pBlock->BaseName[i] = pRealEntry->BaseDllName.Buffer[i];
        pBlock->BaseName[copyChars] = L'\0';
        pFakeEntry->BaseDllName.Buffer        = pBlock->BaseName;
        pFakeEntry->BaseDllName.Length        = (USHORT)(copyChars * sizeof(WCHAR));
        pFakeEntry->BaseDllName.MaximumLength = (USHORT)((copyChars + 1) * sizeof(WCHAR));
    }
    else
    {
        for (ULONG i = 0; i <= baseLen; i++)
            pBlock->BaseName[i] = pFakeBaseName[i];
        pFakeEntry->BaseDllName.Buffer        = pBlock->BaseName;
        pFakeEntry->BaseDllName.Length        = (USHORT)(baseLen * sizeof(WCHAR));
        pFakeEntry->BaseDllName.MaximumLength = (USHORT)((baseLen + 1) * sizeof(WCHAR));
    }

    if (pRealEntry->FullDllName.Buffer && pRealEntry->FullDllName.Length > 0)
    {
        ULONG copyChars = pRealEntry->FullDllName.Length / sizeof(WCHAR);
        if (copyChars >= MK_FAKE_LDR_FULL_NAME_MAX) copyChars = MK_FAKE_LDR_FULL_NAME_MAX - 1;
        for (ULONG i = 0; i < copyChars; i++)
            pBlock->FullName[i] = pRealEntry->FullDllName.Buffer[i];
        pBlock->FullName[copyChars] = L'\0';
        pFakeEntry->FullDllName.Buffer        = pBlock->FullName;
        pFakeEntry->FullDllName.Length        = (USHORT)(copyChars * sizeof(WCHAR));
        pFakeEntry->FullDllName.MaximumLength = (USHORT)((copyChars + 1) * sizeof(WCHAR));
    }
    else
    {
        for (ULONG i = 0; i <= fullLen; i++)
            pBlock->FullName[i] = pFakeFullPath[i];
        pFakeEntry->FullDllName.Buffer        = pBlock->FullName;
        pFakeEntry->FullDllName.Length        = (USHORT)(fullLen * sizeof(WCHAR));
        pFakeEntry->FullDllName.MaximumLength = (USHORT)((fullLen + 1) * sizeof(WCHAR));
    }

    /* Step 8: 原子原地替换 (In-Place Atomic Replacement)
     * 1. 摘除宿主真实条目：将 pRealEntry 从 PsLoadedModuleList 中脱链并自指隔离
     * 2. 伪造条目接管 pRealEntry 原有的前驱与后继位置，确保整个链表中仅存一份宿主条目
     * 3. 驱动对象的 DriverSection 指向伪造条目，彻底消除双重 DllBase 与重名驱动审计风险
     */
    PLIST_ENTRY pPrev = pRealEntry->InLoadOrderLinks.Blink;
    PLIST_ENTRY pNext = pRealEntry->InLoadOrderLinks.Flink;

    pFakeEntry->InLoadOrderLinks.Flink = pNext;
    pFakeEntry->InLoadOrderLinks.Blink = pPrev;
    pPrev->Flink = &pFakeEntry->InLoadOrderLinks;
    pNext->Blink = &pFakeEntry->InLoadOrderLinks;

    /* 宿主真实 LDR 项自指隔离，防止意外遍历 */
    pRealEntry->InLoadOrderLinks.Flink = &pRealEntry->InLoadOrderLinks;
    pRealEntry->InLoadOrderLinks.Blink = &pRealEntry->InLoadOrderLinks;

    /* 将驱动对象的 DriverSection 挂到新条目 */
    pDriverObj->DriverSection = pFakeEntry;

    /* 保存全局指针以便卸载时清理与恢复 */
    g_pFakeLdrBlock = pBlock;
    g_pRealLdrEntry = pRealEntry;

    DBG("[+] Stealth_InsertFakeLdrEntry: Host LDR in-place replaced at [0x%p] with cloned props",
                   pFakeEntry->DllBase);

    return STATUS_SUCCESS;
}

/*
 * Stealth_CleanupFakeLdrEntry — 卸载时移除伪造 LDR 项并恢复宿主真实 LDR 项
 * 必须在驱动卸载前调用，恢复链表原貌，防止系统访问悬空链表项导致 BSOD
 */
VOID Stealth_CleanupFakeLdrEntry(
    IN MACHENIKE_KERNEL_INTERFACE *UserVar
)
{
    PMK_FAKE_LDR_BLOCK pBlock = g_pFakeLdrBlock;
    PKLDR_DATA_TABLE_ENTRY pRealEntry = g_pRealLdrEntry;
    if (!pBlock || !UserVar)
        return;

    PLIST_ENTRY pFakeLink = &pBlock->LdrEntry.InLoadOrderLinks;
    PLIST_ENTRY pPrev = pFakeLink->Blink;
    PLIST_ENTRY pNext = pFakeLink->Flink;

    /* 验证伪造项仍在双向链表中 */
    if (pPrev && pNext && pPrev != pFakeLink && pNext != pFakeLink)
    {
        if (pRealEntry)
        {
            /* 将宿主真实 LDR 项无缝恢复接回链表原位 */
            pRealEntry->InLoadOrderLinks.Flink = pNext;
            pRealEntry->InLoadOrderLinks.Blink = pPrev;
            pPrev->Flink = &pRealEntry->InLoadOrderLinks;
            pNext->Blink = &pRealEntry->InLoadOrderLinks;
            DBG("[+] Stealth_CleanupFakeLdrEntry: Host real LDR restored to PsLoadedModuleList");
        }
        else
        {
            /* 若无宿主则直接摘除 */
            pPrev->Flink = pNext;
            pNext->Blink = pPrev;
        }

        /* 安全自指隔离伪造项 */
        pFakeLink->Flink = pFakeLink;
        pFakeLink->Blink = pFakeLink;
    }

    /* 释放伪造内存块 */
    UserVar->Func.ExFreePoolWithTag(pBlock, MK_STEALTH_TAG);
    g_pFakeLdrBlock = NULL;
    g_pRealLdrEntry = NULL;
}
