#pragma once
#include "Common.h"

#ifdef __cplusplus
// ============================================================
// EtwMonitor: 内核 ETW 安全监控引擎类 (纯静态类)
// 100% 纯只读巡检，0 写操作，杜绝修改系统 ETW 结构触发 PatchGuard
// ============================================================
class EtwMonitor
{
  public:
    /* 初始化 ETW 监控引擎 (动态解算 EtwpGuidHashTable 全局散列表) */
    static NTSTATUS Init(VOID);
    static VOID SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);

    /* 周期性执行 ETW 全局注册项与 ACE 监控 (60秒周期) */
    static ULONG ScanAll(VOID);

    /* 扫描全局 EtwpGuidHashTable，检测是否存在 ACE 注册的 Provider 与 Callback */
    static ULONG CheckAceEtwProviders(VOID);

    /* 重置上报去重指纹缓存 */
    static VOID ResetReportState(VOID);
};
#endif
