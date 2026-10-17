#pragma once
#include "Common.h"

#ifdef __cplusplus
// ============================================================
// NetMonitor: 内核网络全栈多维安全监控引擎类 (纯静态类)
// ============================================================
class NetMonitor
{
  public:
    /* 初始化网络监控引擎 */
    static NTSTATUS Init(VOID);
    static VOID SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);

    /* 设置 ndis.sys 模块基址与范围，供 NDIS 过滤驱动链表定位 */
    static VOID SetNdisModule(ULONG_PTR Base, ULONG_PTR End);

    /* 执行全栈安全扫描（通常在后台心跳监控 WorkItem 中周期性调用） */
    static VOID ScanAll(VOID);

    /* 单独扫描网络驱动分发例程 (指针 Hook + Inline Hook + FastIo) */
    static ULONG CheckTcpipHooks(VOID);

    /* 单独扫描设备栈是否存在 ACE 附加过滤设备 (包含 \Device\Afd) */
    static ULONG CheckTdiAttached(VOID);

    /* 单独扫描 NDIS 过滤驱动链表中是否存在 ACE 注册的过滤驱动或回调 */
    static ULONG CheckNdisFilters(VOID);

    /* 单独自检 WSK Provider Dispatch 是否被篡改 */
    static ULONG CheckWskDispatch(VOID);

    /* 单独巡检 WFP 核心 Callout 状态（防止 ACE 动态重挂钩或还原） */
    static ULONG CheckWfpCallouts(VOID);

    /* 重置上报去重位图（反作弊模块卸载重载时调用） */
    static VOID ResetReportState(VOID);
};
#endif
