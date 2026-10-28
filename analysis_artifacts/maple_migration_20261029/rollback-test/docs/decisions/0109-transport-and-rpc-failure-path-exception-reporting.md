# ADR-0109: 传输层与 RPC 协议全失败路径异常上报闭环规范

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**:
  在 TCP、USB 传输模式及 VMM 客户端联调过程中，偶发出现客户端断联、重试或假死卡顿。经逆向与代码审查排查，底层 `wsk_server.c`、`usb_server.c`、`RpcDispatcher.cpp` 及 `DrvSecurity.cpp` 中存在大量仅输出 `DBG()` 调试宏或静默 `break`/`goto Cleanup`/返回错误的失败分支。在非调试器或生产环境下，这些故障路径完全静默丢包或拒绝，云端监控平台与上层管理链路无法捕获任何有效错误上下文，导致排查困难。

- **技术决策与规范**:
  1. **C/C++ 混编桥接与直连**:
     - `ExceptionReporter.h` 增加 `extern "C"` 导出的 `ExceptionReporter_Report` 与 `ExceptionReporter_ReportFormat`，并受 `#ifdef __cplusplus` 保护，使纯 C 模块（`wsk_server.c`, `usb_server.c`, `usb_hub.c`）可直接包含并无缝直连；
     - `TransportManager.cpp` 在 `SetLastErrorDesc` 与 `SetLastErrorFormat` 中自动触发 `ExceptionReporter::Report`，保证全传输层错误统一沉淀。
  2. **TCP 服务栈 (`wsk_server.c`) 异常可观测性**:
     - `WskServer_Init`：WskRegister 失败、ProviderNPI 捕获失败、Socket/Bind 失败及系统线程创建失败均完整上报错误码；
     - `WskServerThread`：`WskSyncAccept` 异常中断（非正常注销）时上报端口与状态码；
     - `WskProcessClientSession`：大帧内存申请失败、大包接收超时、异步流水线槽位排空超时、非优雅异常断开等全路径上报。
  3. **USB 传输栈 (`usb_server.c` & `usb_hub.c`) 异常可观测性**:
     - `UsbServer_AutoDetectDeviceAndPipes`：系统未发现活动 WinUSB MI_05 候选接口时明确上报 `STATUS_DEVICE_NOT_CONNECTED`；
     - `UsbServer_WorkerThread`：ReadPipe 异常、有效载荷长度非法越界、报文 Header Magic 错位（指出密钥失配）、`MkRpc_DispatchCommandEx` 执行失败均精确定位上报。
  4. **RPC 协议分发栈 (`RpcDispatcher.cpp`) 异常可观测性**:
     - 请求包体长度不足 `sizeof(LEECHRPC_MSG_HDR)` 上报 `STATUS_BUFFER_TOO_SMALL`；
     - 解密后 `pHdr->dwMagic != LEECHRPC_MSGMAGIC` 上报（附带接收魔数、期望魔数、当前持有会话密钥 `CurKey`）；
     - 心跳存活门禁失败被重置密钥上报；
     - `OPEN_REQ` 长度异常与 `hLC` 句柄查找失败上报；
     - 压缩请求解压失败与未知 `tpMsg` 命令上报。
  5. **安全校验栈 (`DrvSecurity.cpp`) 异常熔断感知**:
     - 代码段 Adler32 完整性校验失败时上报故障函数索引与哈希；
     - 控制流数学不变量破坏时上报参数状态；
     - 心跳 30 秒超时熔断时上报超时间隔；
     - 握手挑战应答不匹配时上报期望与实际应答。

- **已知约束与避坑**:
  1. **防洪泛与去重契约**: 继承 ADR-0053 规约，`ExceptionReporter` 内部维持基于哈希与时间戳的 `s_DedupTable` 降频门禁，同一故障 5 秒内仅出网一次，避免极端网络死循环风暴引发系统工作项堆积；
  2. **IRQL 约束**: 所有异常上报动作均通过 `ExInitializeWorkItem` 与 `ExQueueWorkItem` 交由 `DelayedWorkQueue` 在 `PASSIVE_LEVEL` 执行原生 WSK/TLS 出网，绝不阻塞网络驱动热路径与 `DISPATCH_LEVEL`；
  3. **零胶水透传 (Zero Pass-through Wrappers)**: 模块调用点直达目标静态函数或 C 桥接原语，不构造无意义中间垫片。
