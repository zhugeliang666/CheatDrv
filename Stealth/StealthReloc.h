#pragma once
#include "Common.h"
#include "Struct.h"

#ifndef MK_ENABLE_FAKE_LDR
#define MK_ENABLE_FAKE_LDR 0
#endif

#define MK_FAKE_LDR_BASE_NAME_MAX 32  /* WCHAR 个数，含 L'\0' */
#define MK_FAKE_LDR_FULL_NAME_MAX 128 /* WCHAR 个数，含 L'\0' */

typedef struct _MK_FAKE_LDR_BLOCK
{
    KLDR_DATA_TABLE_ENTRY LdrEntry;            /* 必须位于首部 */
    WCHAR BaseName[MK_FAKE_LDR_BASE_NAME_MAX]; /* BaseDllName 缓冲区 */
    WCHAR FullName[MK_FAKE_LDR_FULL_NAME_MAX]; /* FullDllName 缓冲区 */
} MK_FAKE_LDR_BLOCK, *PMK_FAKE_LDR_BLOCK;

#ifdef __cplusplus
// ============================================================
// StealthReloc: 宿主驱动隐蔽重定位与 LDR 项管理类 (纯静态类)
// ============================================================
class StealthReloc
{
  public:
    static NTSTATUS InsertFakeLdrEntry(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN PDRIVER_OBJECT pDriverObj,
                                       IN OPTIONAL PVOID pActualImageBase, IN PCWSTR pFakeBaseName, IN PCWSTR pFakeFullPath);

    static VOID CleanupFakeLdrEntry(IN MACHENIKE_KERNEL_INTERFACE *UserVar);
};
#endif
