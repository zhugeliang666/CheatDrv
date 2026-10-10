#pragma once
#include "Common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * NetMonitor: 内核网络全栈多维安全监控引擎
 * 针对除 WFP Callout 之外的反作弊常见网络拦截面实施全方位主动探测与告警：
 * 
 * 1. 核心网络/套接字设备分发例程监控（\Device\Afd, Tcp, Udp, RawIp, Ip）
 *    - 指针替换 Hook（Pointer Hook）
 *    - 函数入口内联跳板 Hook（Inline Jmp/Call Hook）
 *    - 快速 I/O 分发例程 Hook（FastIoDispatch）
 * 2. TDI / 设备栈附加过滤设备监控（AttachedDevice 链，包含 \Device\Afd）
 * 3. NDIS LWF 轻量级网络过滤驱动链表监控（ndisFilterDriverList）
 * 4. 通讯驱动自身的 WSK Provider Dispatch 函数表完整性自检
 * ============================================================================
 */

/* 初始化网络监控引擎 */
NTSTATUS NetMonitor_Init(VOID);
VOID NetMonitor_SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);

/* 设置 ndis.sys 模块基址与范围，供 NDIS 过滤驱动链表定位 */
VOID NetMonitor_SetNdisModule(ULONG_PTR Base, ULONG_PTR End);

/* 执行全栈安全扫描（通常在后台心跳监控 WorkItem 中周期性调用） */
VOID NetMonitor_ScanAll(VOID);

/* 单独扫描网络驱动分发例程 (指针 Hook + Inline Hook + FastIo) */
ULONG NetMonitor_CheckTcpipHooks(VOID);

/* 单独扫描设备栈是否存在 ACE 附加过滤设备 (包含 \Device\Afd) */
ULONG NetMonitor_CheckTdiAttached(VOID);

/* 单独扫描 NDIS 过滤驱动链表中是否存在 ACE 注册的过滤驱动或回调 */
ULONG NetMonitor_CheckNdisFilters(VOID);

/* 单独自检 WSK Provider Dispatch 是否被篡改 */
ULONG NetMonitor_CheckWskDispatch(VOID);

#ifdef __cplusplus
}
#endif
