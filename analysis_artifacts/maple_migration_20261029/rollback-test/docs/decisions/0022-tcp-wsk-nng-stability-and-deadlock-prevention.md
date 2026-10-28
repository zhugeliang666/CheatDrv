# ADR-0022: TCP (WSK/NNG) 传输层半开死锁根除与优雅退出防挂起闭环

- **状态**: 已采纳
- **日期**: 2026-10-15
- **关联文件**:
  * 驱动端: `CheatDrv/wsk_server.c`, `CheatDrv/wsk_server.h`
  * 客户端: `leechcore/leechrpcclient.c`, `leechcore/leechnng.c`

---

## 一、 背景与系统痛点 (Context & Problem Statement)

在高压并发读写、网络丢包或客户端进程突发崩溃/退出的场景下，TCP 传输通道暴露了 4 个致命的功能与稳定性缺陷：
1. **Bug 1 (功能失效)**: `leechrpcclient.c` 中 `LeechRPC_SetOption` 仅打包了请求报文，却遗漏了 `LeechRPC_SubmitCommand` 调用，导致所有上层 SetOption 设置静默失效；
2. **Bug 2 (TLS 重连失效与句柄泄漏)**: `leechnng.c` 中每个线程在 TLS 中缓存了 nng 拨号上下文 `TLS_NNG_CTX`，但在断线重连后旧的 `ctx->nng.sock` 已被销毁，TLS 上下文仍持有无效的旧 socket 导致请求全部返回失效；且在 `LeechRPC_NngClose` 中粗暴调用 `TlsFree(g_dwTlsNngCtxIndex)`，导致其他并发线程访问释放后的 TLS 槽位引发应用崩溃；
3. **Bug 3 (半开连接导致驱动端永久假死)**: 驱动服务端 `wsk_server.c` 在读取完整 NNG 帧的 Body 载荷及握手协议时，调用了无超时的 `WskSyncReceive`；若网络异常中断、客户端未发送 TCP FIN 且停止发送后续分片（半开连接 Half-Open），内核线程将在 `KeWaitForSingleObject` 中无限期阻塞，导致常驻服务端 worker 线程永久假死，后续任何重连请求均无法被 Accept 处理；
4. **Bug 4 (退出时未决 IRP 挂起导致驱动死锁)**: 在 `WskProcessClientSession` 的 `Cleanup` 退出路径中，原逻辑先调用 `WskDrainPendingSend` 等待所有槽位完成，后关闭 Socket。当网络异常中断时，底层协议栈中的发送 IRP 因未收到 ACK 处于 `STATUS_PENDING` 挂起状态；此时先行调用 `KeWaitForSingleObject(SendEvent, ..., NULL)` 就会陷入永久死锁，导致会话无法注销、驱动无法卸载。

---

## 二、 架构决策与技术规约 (Decision & Architecture)

### 1. 客户端功能与 TLS 线程上下文闭环
- **SetOption 提交补全**: 在 `leechrpcclient.c` 的 `LeechRPC_SetOption` 序列化完成后，补齐 `LeechRPC_SubmitCommand(ctx, pbReq, cbReq, pbRsp, cbRsp, &cbRspActual)` 调用；
- **TLS Socket ID 绑定与动态重建**: 在 `TLS_NNG_CTX` 中绑定 `uint32_t sockId`。在 `LeechRPC_GetOrCreateThreadContext` 中，每次获取上下文时校验 `ctx->sockId == nngCtx->nng.sock.id`。若底层 socket 已发生重连变更，则原子关闭旧上下文并重新调用 `nng_ctx_open` 重建上下文；
- **禁止粗暴释放全局 TLS 槽位**: 在 `LeechRPC_NngClose` 中移除 `TlsFree(g_dwTlsNngCtxIndex)`，仅重置全局 socket 与状态，TLS 槽位全进程生命周期保留复用。

### 2. 驱动端接收超时检测与半开连接防御
- **全链路超时保护 (WskSyncReceiveTimed)**:
  * 握手阶段: `WskSyncReceiveExact` 内部全面启用带 10 秒超时（`-100000000LL`）的 `WskSyncReceiveTimed`，客户端若建立 TCP 连接但不发握手包，10 秒后自动断开；
  * 帧头碎片阶段: 主循环中若已接收到部分帧头字节（`cbRecvTail > cbRecvHead`），等待剩余帧头字节同样启用 10 秒超时；
  * 帧载荷 Body 阶段: 常规帧（<=1MB）及超大帧（>1MB）在拼包读取剩余载荷时，全部强制启用 10 秒超时；
  * 超时后立即安全跳转 `Cleanup`，优雅注销当前会话并释放资源，驱动主线程无缝回到 Accept 监听，彻底消灭半开假死。

### 3. 优雅退出时序铁律与未决 IRP 取消保障
- **先 Close 后 Drain 铁律**:
  * 在 `Cleanup` 阶段，必须**先调用 `WskSyncCloseSocket` 关闭 Socket**；
  * 底层 WSK 协议栈在 Socket 关闭瞬间，会自动取消挂载在该 Socket 上的所有未决 IRP 并标记完成；
  * 随后再调用 `WskDrainPendingSend` 排空异步发送槽位，所有飞行中的 IRP 会瞬间以取消状态退出，绝无阻塞风险；
- **WskDrainPendingSend 内建 5 秒防御性超时与取消兜底**:
  * 在 `WskDrainPendingSend` 内部，将 `KeWaitForSingleObject` 的无超时等待替换为 5 秒相对超时（`-50000000LL`）；
  * 若超时未返回，立即主动执行 `IoCancelIrp(pSendIrp[SlotIdx])`，并再次等待完成例程退出，形成双重防卡死防护；
- **超大包同步发送前严格排空流水线**:
  * 在单帧回包体积超过 1MB 必须使用 `WskSyncSendAll` 发送前，强制遍历排空所有正在进行的异步发送槽位，杜绝异步与同步发送交错并发导致的 TCP 乱序或竞争。

---

## 三、 负向知识总结与系统防线

1. **WSK 网络驱动退出时序严禁“先 Drain 后 Close”**：网络 IRP 的完成高度依赖对端网络状态与 ACK 确认；无超时的 Drain 会直接受制于对端，必须先 Close Socket 强制触发内核 IRP 取消。
2. **长连接协议分包读取严禁无超时阻塞**：一旦客户端在帧传输中途被 `taskkill` 或断网，没有超时的分包接收就是系统级死锁定时炸弹。
