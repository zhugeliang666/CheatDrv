#pragma once
#include "Common.h"

// ----------------------------------------------------------------
// Windows x64 内核反转函数表（Inverted Function Table）内部结构
// 负责系统异常展开与反作弊 RtlVirtualUnwind 堆栈回溯查表
// ----------------------------------------------------------------
#pragma pack(push, 8)
typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY
{
    PVOID ExceptionDirectory;  // 指向 .pdata (RUNTIME_FUNCTION 表)
    PVOID ImageBase;           // 驱动基地址
    ULONG ImageSize;           // 驱动镜像大小
    ULONG SizeOfTable;         // RUNTIME_FUNCTION 个数
} RTL_INVERTED_FUNCTION_TABLE_ENTRY, *PRTL_INVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _RTL_INVERTED_FUNCTION_TABLE
{
    ULONG Count;               // 已注册模块数量
    ULONG MaxCount;            // 最大容量 (通常为 0x200 或 0x400)
    ULONG Epoch;               // 版本/同步计数
    ULONG Overflow;            // 溢出标记
    RTL_INVERTED_FUNCTION_TABLE_ENTRY TableEntry[1];
} RTL_INVERTED_FUNCTION_TABLE, *PRTL_INVERTED_FUNCTION_TABLE;
#pragma pack(pop)

// 备份节点，用于支持安全卸载与原子回滚
typedef struct _INVERTED_TABLE_BACKUP
{
    PRTL_INVERTED_FUNCTION_TABLE_ENTRY TargetEntry;
    PVOID OriginalExceptionDirectory;
    ULONG OriginalSizeOfTable;
} INVERTED_TABLE_BACKUP, *PINVERTED_TABLE_BACKUP;

// ----------------------------------------------------------------
// 核心接口
// ----------------------------------------------------------------

// 启发式定位内核全局 nt!PsInvertedFunctionTable
PRTL_INVERTED_FUNCTION_TABLE InvertedTable_Locate(_In_ PVOID NtoskrnlBase);

// 无侵入接管宿主驱动（如显卡驱动）的展开表，实现零修改 PE 头下的完美堆栈回溯
NTSTATUS InvertedTable_HookHost(
    _In_  PVOID NtoskrnlBase,
    _In_  PVOID HostImageBase,
    _In_  PVOID MergedPdataVa,
    _In_  ULONG MergedPdataCount,
    _Out_ PINVERTED_TABLE_BACKUP Backup
);

// 原子恢复原始宿主表项
NTSTATUS InvertedTable_Restore(_In_ PINVERTED_TABLE_BACKUP Backup);
