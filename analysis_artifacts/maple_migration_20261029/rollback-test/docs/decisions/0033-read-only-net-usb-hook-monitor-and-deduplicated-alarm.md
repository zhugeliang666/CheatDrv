# ADR-0033: 网络与 USB 全链路 10 秒只读 Hook 审计、去中和化与单次去重上报引擎

- **状态**: 已采纳
- **日期**: 2026-10-17
- **上下文与痛点**:
  - 驱动原有的网络与 USB 监控存在以下隐患：
    1. 原 `usb_hub.c` 包含试图通过 `InterlockedExchangePointer` 修改第三方驱动函数指针的“脱钩中和”逻辑，违背了现代 Windows 内核只读原则，极易触发 PatchGuard `0x109`（CRITICAL_STRUCTURE_CORRUPTION）或被反作弊检测到驱动指针被篡改；
    2. 网络层监控遗漏了 WFP Callout 动态重挂钩巡检、QoS 调度器驱动（`\Driver\pacer`）以及高级 ROP/双 Push 跳板 Inline Hook；
    3. USB 监控缺失常驻 10 秒定时巡检机制，未覆盖 xHCI 主机控制器（`\Driver\USBXHCI`）、复合父驱动（`\Driver\usbccgp`）以及设备栈附加过滤驱动（`AttachedDevice`）；
    4. 缺乏异常去重防抖机制：在 10 秒定时周期下，若未对已捕获的 Hook 状态进行记忆，将导致高频向服务端发起重复的 WSK+TLS 出网上报风暴。

- **技术决策与规范**:
  1. **零中和纯只读原则（100% Read-Only Auditing）**:
     - 彻底废除并删除 `usb_hub.c` 中的 `UsbHub_NeutralizeHooks` 及其调用链；
     - 全流程严禁任何写驱动指针操作，仅读取驱动对象（`MajorFunction`）、函数入口前 16 字节指令及设备栈 `AttachedDevice` 链。
  2. **网络全栈主动防御增强 (`NetMonitor`)**:
     - 扩展 `GetInlineHookTarget` 跳板解码器，支持 ROP 栈平衡（`50 48 B8...48 87 04 24 C3`）、双 Push 绝对跳转（`68...C7 44 24 04...C3`）以及短跳二级跳板（`EB` -> `E9`）；
     - 将 `\Driver\pacer`（QoS 数据包调度器）纳入驱动对象扫描范围；
     - 新增 `CheckWfpCallouts`，对 `gCalloutTable` 实施 10 秒周期核验，防止 ACE 动态重挂钩或还原。
  3. **独立 USB 全链路只读审计引擎 (`UsbMonitor`)**:
     - 创建纯静态类 `UsbMonitor`，覆盖 `\Driver\USBHUB3`, `\Driver\USBXHCI`, `\Driver\WINUSB`, `\Driver\usbccgp`, `\Driver\usbhub`；
     - 巡检 28 个 `MajorFunction` 指针及入口 16 字节 Inline Hook；
     - 深度遍历 USB 设备栈 `AttachedDevice` 链（上限 16 层），审查是否存在属于反作弊模块的未认证过滤驱动。
  4. **单次去重防抖上报机制 (Report-Once Deduplication)**:
     - 引入纯静态 32 位位图（`s_ReportedNetMajorMask`、`s_ReportedUsbMajorMask` 等），零动态大池分配；
     - 首次检测到 Hook 槽位时触发内核日志输出并调用 `ExceptionReporter::ReportFormat` 异步出网上报；
     - 上报后原子置位，后续 10 秒周期巡检命中相同槽位时保持静默，消灭上报风暴；
     - 在反作弊卸载/游戏退出时（`g_bAceDetected` 由 `TRUE` 变 `FALSE`）统一调用 `ResetReportState()`，支持游戏重开时重新生效。
  5. **10 秒周期严格节拍调度**:
     - 在 `DriverCore.cpp` 后台工作项中通过 5 轮（2s * 5 = 10s）严格节拍器驱动 `NetMonitor::ScanAll()` 与 `UsbMonitor::ScanAll()`。
  6. **Worker 线程调度职责解耦（零 PsCreateSystemThread 暴露）**:
     - 坚决杜绝调用 `PsCreateSystemThread`，完全复用 Windows 原生工作队列（`DelayedWorkQueue`，执行体位于合法的 `nt!ExpWorkerThread` 栈底），免除反作弊线程创建监控与无符号入口点审查；
     - 将原本堆叠在 `AceMonitorWorkRoutine` 里的代码严格解耦为 `ScanAceModuleState`（2s 高频轮询）与 `ExecuteDeepSecurityScans`（10s 低频深度审计挂载点），通过 `SecurityWorkerRoutine` 管道统一分流，实现清晰的高内聚与可扩展性。
  7. **清除死条件宏与无包装启动（Zero-Wrapper Inlining）**:
     - 彻底清除 `ENABLE_ACE_MONITOR_ENGINE` 与 `ENABLE_WFP_BYPASS` 宏开关，使安全扫描调度与 WFP Bypass 防护成为内核核心默认常驻组件；
     - 彻底废除单行包装函数 `StartAceMonitorEngine`，启动逻辑直接内联至 `DriverCore::Init`，杜绝一切冗余胶水垫片函数。

- **已知约束与避坑**:
  - **IRQL 约束**: 所有设备与驱动对象遍历（`ObReferenceObjectByName` / `IoGetDeviceObjectPointer`）必须限定在 `PASSIVE_LEVEL` 系统工作线程下执行，严禁在 DPC 中执行对象查找导致 `0x0A` 蓝屏；
  - **引用计数与异常保护**: 所有驱动/设备对象解引用必须置于 `__try / __except` 中，并在退出作用域前调用 `ObfDereferenceObject` 保证引用平衡，严禁对象句柄悬挂泄漏。
