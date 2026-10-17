#pragma once
#include "Common.h"

#ifdef __cplusplus
// ============================================================
// UsbMonitor: 内核 USB 链路安全监控引擎类 (纯静态类)
// 100% 只读审计，0 写操作，杜绝修改第三方驱动指针触发 PatchGuard
// ============================================================
class UsbMonitor
{
  public:
    /* 初始化 USB 监控引擎 */
    static NTSTATUS Init(VOID);
    static VOID SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);

    /* 周期性执行 USB 全栈只读 Hook 扫描 (10秒周期) */
    static ULONG ScanAll(VOID);

    /* 扫描核心 USB 驱动分发例程 (MajorFunction 指针 Hook 与入口 Inline Hook) */
    static ULONG CheckUsbHooks(VOID);

    /* 扫描 USB 设备栈是否存在 ACE 附加过滤设备 (AttachedDevice 链) */
    static ULONG CheckUsbAttached(VOID);

    /* 重置上报去重位图（反作弊模块卸载重载时调用） */
    static VOID ResetReportState(VOID);
};
#endif
