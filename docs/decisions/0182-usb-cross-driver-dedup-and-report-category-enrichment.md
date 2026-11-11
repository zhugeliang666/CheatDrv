# ADR-0182: USB 跨驱动/跨例程威胁级去重闭环与异常上报类型正文字段补齐规范

- **状态**: 已采纳
- **日期**: 2026-11-09
- **上下文与痛点**:
  1. **USB 协议栈分层挂钩导致告警重复刷屏**:
     - Windows USB 驱动子系统由多层拓扑结构组成（从物理控制器驱动 `USBXHCI`、集线器驱动 `USBHUB3` 到通用复合父设备 `usbccgp`）；
     - ACE 反作弊（`ACE-BASE.sys`）部署 USB 外设输入监控过滤驱动时，常挂接到多个 USB 节点上；原 `UsbMonitor` 仅按照单个驱动索引 `s_ReportedUsbAttached[d]` 维护去重标志，且未记录已报 Handler 函数地址；
     - 导致同一次扫描周期中，同一 ACE 过滤例程（如 `Handler[27]=0xFFFFF80281F96870`）在 `usbccgp` 与 `USBHUB3` 分别触发一次上报，同时其 MajorFunction 指针挂钩与下层 `USBXHCI AttachedHandler`（`0xFFFFF80281F962C0`）再次重复触发，导致 CrashDumpBot 连续弹出 4 条重复报警，严重干扰诊断。
  2. **机器人告警通知缺失“上报类型”字段**:
     - 异常上报原设计仅在 `plainData` 头部第一行输出 `%s\r\n`（分类标题，如 `🔌 【USB硬件安全告警】`）；
     - 监控机器人服务端格式化模板在接入时将第 1 行直接替换为群消息机器人前缀（`CrashDumpBot: 版本[xxx]`），导致头部标题被覆盖；
     - `plainData` 的键值对列表（`🎮 目标游戏`、`🏷️ 客户端版本` ... `📍 触发例程`、`🛑 状态代码`）中并未包含独立的“上报类型”行，且 HTTP POST 查询参数中也未附带 `category`，致使终端最终呈现的告警卡片无法识别具体分类。

- **技术决策与规范**:
  1. **跨驱动全局 AttachedDevice 锁存去重 (`s_ReportedUsbAttachedGlobal`)**:
     - 在 `UsbMonitor.cpp` 中引入全局静态原子锁存标志 `s_ReportedUsbAttachedGlobal`；
     - 只要在任意 USB 驱动（`usbccgp`、`USBHUB3`、`USBXHCI` 等）设备栈上发现 ACE 过滤设备，全局会话只上报首次捕获的代表性威胁，后续其他驱动设备栈的相同附着直接静默，彻底杜绝驱动对象遍历逐个告警。
  2. **跨检测项/跨驱动已报 Handler 缓存池 (`s_ReportedUsbHandlers[16]`)**:
     - 维护 16 槽静态 Handler 地址缓存池；
     - 在 `CheckUsbHooks`（MajorFunction 指针 Hook / Inline Hook）与 `CheckUsbAttached`（AttachedHandler）中：在触发 `ExceptionReporter::ReportFormat` 前，强制校验 `IsHandlerAlreadyReported(fn)`；
     - 若该 Handler 例程已被上报过，直接跳过本次上报，彻底解决同一钩子例程地址在多个驱动或在不同检测项中重复报警的问题。
  3. **单轮巡检上报频控门禁 (`s_UsbScanRoundReported`)**:
     - 在 10 秒定时巡检 `ScanAll()` 周期中，单轮扫描开始前重置 `s_UsbScanRoundReported = FALSE`；
     - 单轮扫描内最多放行 1 条 USB Hook 告警，彻底阻断同轮并发多路告警造成的机器人通知轰炸。
  4. **全端补齐上报类型（正文键值对 + HTTP 参数）**:
     - 在 `ExceptionReporter.cpp` 中新增 `GetReportCategoryName()`（纯中文语义名称，如 `"USB硬件安全告警"`、`"安全防御拦截告警"` 等）与 `GetReportCategoryTag()`（英文标签，如 `"UsbSecurity"`、`"SecIntercept"` 等）；
     - 在 `plainData` 模板正文字段列表中新增显式键值对：`"\xF0\x9F\x94\x94 上报类型：%s\r\n"`（传入 `categoryName`）；
     - 在明文与密文 HTTP POST `httpBody` 参数列表中同步追加 `&category=%s`（传入 `categoryTag`），保证明文、密文及 URL 参数三端均能准确获取上报类型。
  5. **生命周期复位闭环**:
     - 在反作弊卸载或游戏重开（调用 `ResetReportState`）时，同步重置 `s_ReportedUsbAttachedGlobal`、`s_ReportedUsbHandlers` 与计数器，确保全新游戏运行周期内能够重新有效监控。

- **已知约束与避坑**:
  - **只读性与零大池铁律**: 缓存池必须为固定大小静态栈/BSS 结构，严禁在中断或巡检热路径调用 `ExAllocatePoolWithTag`；
  - **编码规范**: 所有修改必须通过 `convert_bom.py` 维持 UTF-8 BOM 编码。
