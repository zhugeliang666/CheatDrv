# ADR-0024: UDP 传输层 Flat-Combining 组提交与 MTU 安全聚合发车架构

- **状态**: 已采纳
- **日期**: 2026-10-15
- **影响范围**: 客户端 [`leechudp_client.c`](file:///E:/Project/Machenike/leech_vmm/leechCore/leechcore/leechudp_client.c)、服务端 [`udp_server.c`](file:///e:/Project/Drv/CheatDrv/udp_server.c)、[`udp_server.h`](file:///e:/Project/Drv/CheatDrv/udp_server.h)

---

## 一、 上下文与痛点

在 VMMDLL / LeechCore 高并发内存读写场景中（例如 8 线程并发各读取 4 字节小变量）：
1. **网络往返停等瓶颈 (Stop-and-Wait Serialization)**：
   若每个线程各发起一次独立的 UDP Request-Response，8 线程在 `ctx->udp.Lock` 下将产生 8 次独立的 `sendto` 与 8 次独立的 `recvfrom`。每个网络往返（RTT 约 0.2~0.5ms）都被串行化，导致整体吞吐受限于单个网络往返延迟（吞吐约 2,000~4,000 Ops/s）。
2. **末班车孤儿死锁 (Orphaned Leader Deadlock)**：
   若采用朴素的组提交，当第一任 Leader 发车并完成当前批次后，若队列中恰好在发车瞬间新入队了 Follower，该 Follower 将永远处于 `WaitForSingleObject` 状态直至 3 秒超时，造成突发性假死卡顿。

---

## 二、 技术决策与架构规范

### 1. 客户端 64 槽位 Flat-Combining 组提交
客户端定义全局静态 `UDP_GROUP_COMMIT` 队列与 64 个 `UDP_BATCH_SLOT`：
- 小包（$\le 1024$ 字节）入队进入组提交槽位；
- 探测活跃线程并发度（`g_udp_cActiveThreads`），在微聚拢窗口（最多 2000 次 `_mm_pause`）内快速聚拢当前并发请求；
- **MTU 严格硬限制**：Leader 聚合的多请求帧总长度累计绝对不超过 `MK_UDP_SAFE_MTU_PAYLOAD`（1400 字节），杜绝触发网络层 IP 分片；
- 通过单次 `sendto` 将包含多个 `[Nonce][Length][Encrypted Payload]` 帧的数据报发出。

### 2. 驱动端多帧流水线连续收割与合并回传
驱动端 `udp_server.c` 的工作线程通过循环：
```c
while ((BytesReceived - cbRecvOffset) >= UDP_SERVER_HEADER_SIZE) { ... }
```
原位连续消费收到的每个请求帧，并将响应连续写入 `g_UdpServer.pSendBuf`。当所有响应总长度 $\le 1400$ 字节时，单次 `WskSendTo` 聚拢回传；若超过 1400 字节则回退切片（`'UDPS'`）发送。

### 3. 客户端批量解包与 Nonce 精准匹配
Leader 在单个 `recvfrom` 回包中连续解出所有响应帧：
- 取出各帧中的 `qwRspNonce`；
- 在当前批次中精准匹配 `s->qwNonce == qwRspNonce && s->fState == UDP_SLOT_IN_FLIGHT` 的槽位；
- 原位解密并交付结果，调用 `SetEvent(s->hEvent)` 唤醒对应的 Follower 线程。

### 4. Leader 平滑交接 (Leader Handoff) 根除孤儿死锁
Leader 在完成当前批次并释放物理 Socket 锁后，在 `QueueLock` 保护下检查 `cQueuedCount`：
- 若队列中存在后续排队的槽位，挑选第一个槽位将其状态置为 `UDP_SLOT_BECOME_LEADER` 并 `SetEvent`；
- 该槽位醒来后直接晋升为新 Leader，接力拉起下一班聚合发车；
- 彻底根除末班车孤儿死锁。

### 5. 双通道隔离 (Dual-Path Isolation)
- **小包通道（$\le 1024$ 字节）**：走组提交聚合发车，大幅消灭 RTT；
- **大包通道（$> 1024$ 字节或散列跨页读取）**：直接绕过组提交队列，走独占单包/切片重组通道，确保大块物理读取带宽与线速性能零退化。

---

## 三、 已知约束与避坑指南

1. **MTU 约束**：客户端聚合发车与驱动端聚合回传的单数据报大小必须严格 $\le 1400$ 字节，严禁溢出导致链路丢包；
2. **ABA 与迟到包防范**：必须严格依赖每请求独立的 64 位 Nonce 进行响应帧与槽位的一对一校验，绝对禁止仅凭包顺序做隐式匹配。
