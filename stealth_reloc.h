#pragma once
#include "Common.h"
#include "Struct.h"

/* ============================================================
 * ACE 对抗开关配置：
 * MK_ENABLE_FAKE_LDR: 控制是否启用伪造/顶替 LDR 链表项对抗模块扫描。
 *   - 1: 启用（模块列表审计合规，隐藏非法内存池模块，但独立内存池时栈回溯可能判定 RIP 不在模块内）
 *   - 0: 禁用（保留宿主原生状态或配合 Code Cave 驻留使用，不进行 LDR 链表摘除与伪造）
 * ============================================================ */
#ifndef MK_ENABLE_FAKE_LDR
#define MK_ENABLE_FAKE_LDR          0
#endif

#define MK_FAKE_LDR_BASE_NAME_MAX   32    /* WCHAR 个数，含 L'\0' */
#define MK_FAKE_LDR_FULL_NAME_MAX   128   /* WCHAR 个数，含 L'\0' */

typedef struct _MK_FAKE_LDR_BLOCK {
    KLDR_DATA_TABLE_ENTRY   LdrEntry;                        /* 必须位于首部 */
    WCHAR                   BaseName[MK_FAKE_LDR_BASE_NAME_MAX];  /* BaseDllName 缓冲区 */
    WCHAR                   FullName[MK_FAKE_LDR_FULL_NAME_MAX];  /* FullDllName 缓冲区 */
} MK_FAKE_LDR_BLOCK, *PMK_FAKE_LDR_BLOCK;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stealth_InsertFakeLdrEntry — 原子原地替换 + 伪造 LDR 项挂入
 *
 * 核心能力：
 *   1. 解析真实 PE 的 .pdata (IMAGE_DIRECTORY_ENTRY_EXCEPTION) 填充 ExceptionTable，使 RtlVirtualUnwind 正常展开。
 *   2. 原子原地替换：将真实 KLDR_DATA_TABLE_ENTRY 从 PsLoadedModuleList 摘除，由 1:1 克隆宿主属性的伪造项无缝顶替。
 *   3. 消除双重 DllBase 与重名驱动审计风险。
 */
NTSTATUS Stealth_InsertFakeLdrEntry(
    IN MACHENIKE_KERNEL_INTERFACE *UserVar,
    IN PDRIVER_OBJECT pDriverObj,
    IN OPTIONAL PVOID pActualImageBase,
    IN PCWSTR pFakeBaseName,       /* 短名，如 L"Machenike.sys" */
    IN PCWSTR pFakeFullPath        /* 完整路径，如 L"\\SystemRoot\\System32\\drivers\\Machenike.sys" */
);

/*
 * Stealth_CleanupFakeLdrEntry — 卸载时移除伪造 LDR 项并恢复宿主真实 LDR 项
 */
VOID Stealth_CleanupFakeLdrEntry(
    IN MACHENIKE_KERNEL_INTERFACE *UserVar
);

#ifdef __cplusplus
}
#endif
