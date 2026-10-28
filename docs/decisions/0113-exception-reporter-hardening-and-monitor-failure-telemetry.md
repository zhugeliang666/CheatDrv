# ADR-0113: ExceptionReporter 可靠性加固与全监控引擎失败/异常遥测闭环规范

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**:
  1. **手动映射（ManualMap）漏设 `ApiUrl` 导致上报永久失效**：`DriverCore::Initialize` 在 ManualMap 模式下解析 `pBootConfigEx` 时，仅设置了 `SetCardKey`，漏调用了 `ExceptionReporter::SetApiUrl`、`SetBrandVersion`、`SetSelectedGame`、`SetClientVersion`，且早期初始化阶段（`NetMonitor::Init` / `UsbMonitor::Init` / `ApiMonitor::Init` / `EtwMonitor::Init`）在 `SetApiUrl` 之前运行，所有早期告警均因 `s_ApiUrl[0] == '\0'` 被直接静默丢弃。
  2. **10 秒全局单条限流器与永久去重位图（`s_Reported*Mask`）耦合引发告警黑洞**：原 `ExceptionReporter::Report` 使用 `s_LastCardKeyTime` 对同一卡密执行 10 秒 1 条的全局硬限流，而 `UsbMonitor`、`ApiMonitor`、`NetMonitor` 等在首次检测到多处 Hook 时会在同一毫秒内先把各自的永久去重位（`s_Reported*Mask`）置 1 再调用 `ReportFormat`；这导致同一轮巡检中第 2 条及之后的所有异构告警被 `s_LastCardKeyTime` 丢弃，且因去重位已永久置 1，后续巡检周期也永不再报。
  3. **去重哈希忽略 `extraMsg` 导致同函数名异构告警互相抑制**：`ComputeReportFingerprint` 原本只哈希 `cardKey + functionName + status`，导致同一 `functionName`（如 `"UsbMonitor::CheckDeviceStackHooks"` 或 `"ApiMonitor::CheckInlineHooks"`）下针对不同驱动、不同 IRP_MJ 槽位或不同 API 的告警计算出完全相同的指纹而被误判为重复项丢弃。
  4. **`ntoskrnl!_vsnprintf` 截断返回 `-1` 缺陷与 TLS 分片重算哈希 Bug**：Windows CRT `_vsnprintf` 在缓冲区不足时返回 `-1` 且不保证末尾置 `'\0'`，原代码 `if (len <= 0) return;` 会导致长告警直接丢弃或拼接 JSON 时指针回退越界；此外 `PerformTlsHandshakeAndSendHttp` 在服务端握手跨多次 `WskSyncRecv` 分片到达时，每次重头（`cursor = 0`）遍历 `recvBuf` 并重复调用 `BCryptHashData`，导致 `transcriptHash` 被重复累加而破坏 TLS 1.2 Handshake Finished 校验。
  5. **监控引擎自身初始化失败与运行期异常缺乏遥测**：`UsbMonitor`、`ApiMonitor`、`NetMonitor`、`WfpBypass`、`EtwMonitor` 及 `DriverCore` 在关键内核符号解析失败、模块基址缺失、内核指针越界或 SEH `__except` 捕获异常时仅输出 `DBG` 日志，缺乏云端异常上报，导致在目标反作弊环境或新系统版本上监控静默失效时无从感知。

- **技术决策与规范**:
  1. **`ExceptionReporter` 管道全链路加固（`Diagnostics/ExceptionReporter.cpp`）**：
     - **64 位全字段去重指纹**：`ComputeReportFingerprint` 将 `cardKey`、`functionName`、`status` 与 `extraMsg` 全部纳入 FNV-1a 64 位哈希，去重表扩容至 32 槽位（`REPORT_DEDUP_SLOTS = 32`），单指纹冷却期 60 秒；
     - **滑动突发窗口替代单条全局锁死**：废除单条 10 秒锁死逻辑，改为 10 秒窗口允许最多 `8` 条不同指纹告警并发入队（`REPORT_BURST_MAX_PER_WINDOW = 8`），彻底消除同轮多点检测被静默吞噬的问题；
     - **8 槽无锁早期暂存环（Early Staging Ring）**：在 `s_ApiUrl` 尚未就绪前产生的告警自动暂存至 `s_EarlyStageTable[8]`，一旦 `ExceptionReporter::SetApiUrl` 完成配置，立即调用 `FlushEarlyStagedReports()` 异步冲刷出网；
     - **安全格式化与缓冲区扩容**：封装 `SafeVsnprintf` / `SafeSnprintf` 强制末尾 `'\0'` 截断保护并在截断时返回正数有效长度；`ExtraMsg` 与 `ReportFormat` 缓冲区扩容至 `256` 字节，`PerformHttp` `plainData` 扩容至 `768` 字节；补齐 `0xC0000428`、`0xC000007A`、`0xC0000005` 语义映射；
     - **TLS 握手增量哈希游标与资源防泄漏**：`PerformTlsHandshakeAndSendHttp` 引入 `processedCursor` 保证跨 TCP 分片接收时每条 TLS Record 仅执行一次 `BCryptHashData`，并校验 `hCursor + 4 + hLen <= hEnd`；修复 `ExQueueWorkItem == NULL` 及 `WskGetAddressInfo` 空地址分支的内存泄漏。
  2. **双模式启动配置全量对齐（`Core/DriverCore.cpp`）**：
     - 在调用所有 `Monitor::Init()` 前先行注入 `ExceptionReporter::SetUserVar(UserVar)`；
     - 修复 ManualMap `pBootConfigEx` 与常规 IOCTL `ApplyBootConfigAndStart` 路径，确保 `SetBrandVersion`、`SetSelectedGame`、`SetClientVersion`、`SetCardKey` 先于 `SetApiUrl` 完成设置，并在 `g_ApiUrl` 为空时自动回退使用 `g_ReportUrl`。
  3. **全监控模块失败与异常遥测闭环（`UsbMonitor` / `ApiMonitor` / `NetMonitor` / `WfpBypass` / `EtwMonitor` / `DriverCore`）**：
     - 所有监控模块初始化缺失符号/驱动对象、关键内核表（`KeServiceDescriptorTable`、`HalDispatchTable`、`KiPageFault`、`ndisMiniDriverList`、`gCalloutTable`、`EtwpGuidHashTable`、`PsLoadedModuleList`）定位失败、对象范围校验不合法、后台监控线程创建失败以及运行期 `__except` 捕获异常时，一律通过原子单次标志位触发 `ExceptionReporter::ReportFormat` 上报精确上下文。

- **已知约束与避坑**:
  1. `ExceptionReporter::Report` / `ReportFormat` 可在任意 `<= DISPATCH_LEVEL` 下安全调用（内部僅做无锁指纹去重、早期暂存或非分页池分配 + `ExQueueWorkItem`），严禁在 `Report` 同步路径内直接发起 WSK 网络 I/O。
  2. 所有监控模块的失败/异常上报必须配合 `InterlockedCompareExchange` 单次标志位或位图掩码，严禁在周期性扫描循环中无状态裸调造成云端告警洪泛。
