#pragma once
#include <ntddk.h>
#include <wdm.h>

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

NTSTATUS PteHijack_Remap(
    _In_  ULONG64   UserVa,
    _In_  ULONG64   KernelVa,
    _Out_ PULONG64  OldPte
);

NTSTATUS PteHijack_Restore(
    _In_ ULONG64 UserVa,
    _In_ ULONG64 OriginalPte
);

VOID PteHijack_FlushTlb(_In_ ULONG64 Va);
