# ADR-0053: 驱动内核异常上报全链路降噪、全局去重频控与高直观度视觉看板卡片规范
- **状态**: 已采纳
- **日期**: 2026-10-23
- **上下文与痛点**:
  - 原异常上报系统在发生启动或连接故障时，存在父子调用链级联二次上报问题（如 `StartTransportByIo` 报错后，上层 `DispatchCreate` 再次重复上报 `Token valid but ApplyBootConfig failed`）；
  - `ExceptionReporter` 缺乏全局频控与滑动时间窗口机制，用户连续重试会导致 TG 机器人收到大量重复报文刷屏；
  - `AuditHardwareBreakpoints` 因多核线程调度与断点寄存器状态抖动，造成单次会话内反复清零并重新上报断点；
  - 原报文字段采用生硬的 XML 闭合标签（`[CardKey]...[/CardKey]`），在 TG 客户端呈现极其杂乱、无法快速抓取核心错误码与具体子步骤根因。

- **技术决策与规范**:
  1. **调用链级联去重（Eliminate Cascading Reports）**：
     - 确立“底层报根因，上层只传码”原则；
     - 在 [Core/DriverCore.cpp](file:///e:/Project/Drv/CheatDrv/Core/DriverCore.cpp) 的 `DispatchCreate` 阶段彻底移除冗余二次上报，收敛至单一第一现场报警。
  2. **ExceptionReporter 全局滑动时间窗口与指纹去重引擎**：
     - 在 [Diagnostics/ExceptionReporter.cpp](file:///e:/Project/Drv/CheatDrv/Diagnostics/ExceptionReporter.cpp) 内置 16 槽位非分页指纹缓存表；
     - 实施“相同故障指纹 60 秒冷却”与“同卡密 10 秒全局频控”，彻底阻断并发重试轰炸与高频刷屏。
  3. **安全审计项状态机单次固化（Sticky Latch）**：
     - 在 [Security/DrvSecurity.cpp](file:///e:/Project/Drv/CheatDrv/Security/DrvSecurity.cpp) 中废除断点解除即清零的脆弱逻辑，单驱动会话内检测到断点后单次锁定，杜绝因线程轮转导致的周期性报文骚扰。
  4. **全链路详细子步骤错误透传机制**：
     - 在 [Transport/TransportManager.h](file:///e:/Project/Drv/CheatDrv/Transport/TransportManager.h) 引入 `SetLastErrorFormat` / `GetLastErrorDesc`；
     - 在 `usb_server.c`、`usb_hub.c` 的关键失败点（如 AutoDetect、ScanPipe、PenetrateHub3）注入精准子步骤前缀（如 `[USB:HubInit] PenetrateToHub3Pdo failed`），由 `StartTransportByIo` 透传至上报体。
  5. **TG 视觉看板卡片化重构**：
     - 彻底淘汰 `[xxx]yyy[/xxx]` 标签，改用结构化看板块与分隔线；
     - 状态码引入 `ExceptionReporter_GetStatusSemantic` 自动翻译为中文语义（如 `0xC0000225 -> STATUS_NOT_FOUND (未找到目标设备/穿透失败)`）；
     - Emoji 使用标准十六进制 UTF-8 字节常量表示，规避 MSVC C4566 警告并确保移动端/桌面端完美呈现。

- **已知约束与避坑**:
  - 去重表必须在非分页内存无锁运行，严禁在 `Report` 热路径引入阻塞自旋锁或大池申请；
  - 字符串格式化缓冲区需严格受限于 512 字节以内，防止溢出 1024 字节加密载荷上限；
  - 严禁在源码中直接写 4 字节原始 Emoji 字符，必须转义为 UTF-8 字节序列防止跨平台/代码页编译截断。
