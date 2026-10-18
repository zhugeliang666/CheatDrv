#pragma once
#include "Common.h"
#include "Struct.h"

#ifdef __cplusplus
// ============================================================
// ApiMonitor: 内核高危敏感函数与系统表只读 Hook 监控引擎 (纯静态类)
// 聚焦 28 个核心高危敏感 API：覆盖 EAT 篡改、入口/深层 Inline Hook、
// 32B 字节流基线、Zw*->SSDT Nt* 双端校验及核心通信驱动 IAT 劫持
// ============================================================
class ApiMonitor
{
  public:
    static NTSTATUS Init(
        _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
        _In_ PKLDR_DATA_TABLE_ENTRY DriverSection);

    static VOID ScanAll(VOID);

    static ULONG CheckSensitiveApiHooks(VOID);
    static ULONG CheckSsdtZwHooks(VOID);
    static ULONG CheckSystemDriverIatHooks(VOID);

    static VOID ResetReportState(VOID);
};
#endif
