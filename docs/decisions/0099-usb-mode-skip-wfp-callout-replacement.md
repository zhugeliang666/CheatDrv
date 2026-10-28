# ADR-0099: USB 传输模式下免除 WFP Callout 替换与误报规避规范

- **状态**: 已采纳
- **日期**: 2026-10-28
- **核心领域**: 网络监控 / 反作弊对抗 / 传输层架构

---

## 上下文与痛点

1. **协议层物理隔离**：
   - 驱动支持 WSK TCP (`DRV_TRANSPORT_TCP` / `MK_SERVER_MODE_WSK_TCP`)、WSK UDP (`DRV_TRANSPORT_UDP` / `MK_SERVER_MODE_WSK_UDP`) 与物理硬件 USB 管道 (`DRV_TRANSPORT_USB` / `MK_SERVER_MODE_USB`)。
   - 网络模式下，通信数据流必然经过操作系统 NDIS、TCP/IP 协议栈与 WFP（Windows Filtering Platform）网络过滤层，反作弊（ACE）驱动注册了 ALE/Transport 过滤层 Callout（`classifyFn`），驱动必须通过 DKOM 替换为放行 Wrapper。
   - 相比之下，USB 模式下数据通信完全基于物理 USB 总线（USB 3.0 / USBHUB3 PDO 硬件端点）直接通信，100% 脱离操作系统 TCP/IP 协议栈和 WFP 网络过滤层。
2. **现存暴露面与误报隐患**：
   - 原常驻安全工作项（`SecurityWorkerRoutine` -> `NetMonitor::ScanAll()` -> `NetMonitor::CheckWfpCallouts()`）在检测到反作弊（ACE）驱动在内存中时，无条件调用 `WfpBypass::Init` 扫描系统 `gCalloutTable` 并 CAS 篡改 ACE 的 `classifyFn`。
   - 在 USB 模式下触碰系统 WFP Callout 属于无用多余操作，不仅面临修改内核全局表与多核原子争用的稳定性隐患，还会触发 ACE 看门狗对自身网络回调被篡改的完整性报警；更会导致在 ACE 未挂接完成时误报 `NetMonitor::WfpUnprotected` (0xC0000424) 虚假安全告警。

---

## 技术决策与规范

1. **传输模式原子查询接口 (`TransportManager`)**：
   - 在纯静态类 `TransportManager` 暴露 `SetActiveMode(MK_SERVER_MODE Mode)`、`GetActiveMode()` 与 `IsUsbMode()`。
   - 在 `DriverCore::ApplyBootConfigAndStart` 与 `DriverEntry_ManualMap` 解析 `BootConfig->TransportMode` 阶段提前原子同步，确保从冷启动到运行期全生命周期可随时无锁判定。
2. **WFP 巡检前置门禁收紧 (`NetMonitor::CheckWfpCallouts`)**：
   - 在 `NetMonitor::CheckWfpCallouts` 入口增设 `TransportManager::IsUsbMode()` 短路判定；若当前处于 USB 模式，立即重置 `s_ReportedWfpUnprotectedAlarm = FALSE` 并直接返回 0，严禁调用 `WfpBypass::Init`，杜绝一切虚假告警。
3. **WFP 绕过执行体深度防御 (`WfpBypass::Init`)**：
   - 在 `WfpBypass::Init` 入口增设 `TransportManager::IsUsbMode()` 双重保险；若处于 USB 模式，直接短路返回 `STATUS_NOT_SUPPORTED`，坚决不解引用或修改 `gCalloutTable`。
4. **端口隐藏防御规避 (`DriverCore.cpp`)**：
   - 在启动网络服务后，仅在 `srvParams.Mode != MK_SERVER_MODE_USB` 时调用 `WfpBypass::SetHiddenLocalPort((USHORT)srvParams.Port)`，防止向 WFP 绕过层传入非法端口 0。

---

## 已知约束与避坑

1. **严禁在未确认模式前过早触发 WFP 替换**：模式同步必须优先于工作项轮询调度完成，杜绝冷启动竞态。
2. **严禁在 USB 模式下向外报送 WfpUnprotected 告警**：USB 模式下系统不存在 WFP 保护需求，报送视为严重误报。
3. **代码与文件编码规范**：所有涉及的源码与文档必须通过 `convert_bom.py` 维持 UTF-8 BOM 编码规范。
