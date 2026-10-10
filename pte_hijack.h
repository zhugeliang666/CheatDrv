#pragma once
#include "Common.h"

// ----------------------------------------------------------------
// x64 Hardware PTE 结构（Windows，4KB 页）
// ----------------------------------------------------------------
typedef union _MMPTE_HW {
    ULONG64 u64;
    struct {
        ULONG64 Valid        : 1;   // P
        ULONG64 Write        : 1;   // R/W
        ULONG64 Owner        : 1;   // U/S: 0=kernel-only, 1=user可访问
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed     : 1;
        ULONG64 Dirty        : 1;
        ULONG64 LargePage    : 1;
        ULONG64 Global       : 1;
        ULONG64 CopyOnWrite  : 1;
        ULONG64 Prototype    : 1;
        ULONG64 _reserved0   : 1;
        ULONG64 PageFrameNumber : 36; // PFN
        ULONG64 _reserved1   : 4;
        ULONG64 SoftwareWsIdx: 11;
        ULONG64 NoExecute    : 1;   // NX: 1=禁止执行
    };
} MMPTE_HW, *PMMPTE_HW;

NTSTATUS PteHijack_Init(VOID);

// 标准映射（向后兼容：默认创建不可执行映射，规避常驻扫描）
NTSTATUS PteHijack_Remap(
    _In_  ULONG64   UserVa,
    _In_  ULONG64   KernelVa,
    _Out_ PULONG64  OldPte
);

// 高阶映射：支持指定初始 NX 状态（推荐 InitialExecutable = FALSE）
NTSTATUS PteHijack_RemapEx(
    _In_  ULONG64   UserVa,
    _In_  ULONG64   KernelVa,
    _In_  BOOLEAN   InitialExecutable,
    _Out_ PULONG64  OldPte
);

// 按需特权翻转（JIT / On-Demand PTE Flip）：在执行窗口期动态置 0，执行完毕置 1
NTSTATUS PteHijack_SetExecution(
    _In_ ULONG64 Va,
    _In_ BOOLEAN EnableExecute
);

NTSTATUS PteHijack_Restore(
    _In_ ULONG64 UserVa,
    _In_ ULONG64 OriginalPte
);

// 本地单核隐蔽刷新（零 IPI，杜绝系统性能监控捕捉，推荐搭配 KeSetSystemAffinityThread）
VOID PteHijack_FlushTlbLocal(_In_ ULONG64 Va);

// 全局广播刷新（向所有 CPU 发送 IPI）
VOID PteHijack_FlushTlbBroadcast(_In_ ULONG64 Va);

// 兼容旧接口（定向到局部隐蔽刷新）
VOID PteHijack_FlushTlb(_In_ ULONG64 Va);

// ----------------------------------------------------------------
// 高阶规避进阶原语 (Advanced ACE Evasion Primitives)
// ----------------------------------------------------------------

// 申请游离物理页（脱离内核虚拟池链表，杜绝 Double Mapping 与 Pool Tag 审计）
PHYSICAL_ADDRESS PteHijack_AllocHeadlessPhysicalPage(VOID);

// 释放游离物理页
VOID PteHijack_FreeHeadlessPhysicalPage(_In_ PHYSICAL_ADDRESS Pa);

// 内存页休眠态原地加扰/解扰（在休眠期抹除任何汇编特征码）
VOID PteHijack_ObfuscatePage(_In_ ULONG64 Va, _In_ ULONG64 Key);
