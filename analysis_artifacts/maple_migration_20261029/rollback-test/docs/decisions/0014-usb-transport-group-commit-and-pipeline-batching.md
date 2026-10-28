# ADR-0014: USB 传输层 Flat-Combining 组提交与流水线批处理合并回包架构 (Group Commit & Pipeline Batching)

- **状态**: 已采纳
- **日期**: 2026-10-14
- **影响范围**: `CheatDrv\usb_server.c`, `CheatDrv\usb_hub.c`, `leechcore\leechusb_client.c`
- **关联决策**: 继承并泛化 [ADR-0009](0009-wsk-nng-async-worker-pool-and-multiplexing.md) (WSK NNG 流水线批处理与双缓冲异步发送) 与 [ADR-0010](0010-transport-layer-unified-optimization-udp-usb.md) (全传输层高性能统一)

---

## 1. 上下文与核心痛点 (Context & Problem)

在 `CheatDrv` 与 `leechcore` 进行 USB 通信压测时，出现严重的性能两极分化：
1. **大包吞吐极快**：100 页（400KB）连续物理页读取带宽达到 **157.25 MB/s**；
2. **小包多线程严重劣化**：8 线程并发读取 8,000 次 4 字节（`ReadEx<ULONG>`）耗时高达 **2045 ms**（仅 3,911.98 Ops/sec），性能比 TCP (NNG) 慢了近 10 倍。

### 根因深度解构
- **硬件停等限制**：USB 3.x xHCI 控制器以 $125\ \mu\text{s}$ 微帧（Microframe）为物理传输调度周期。一次 Bulk OUT（发送）并在设备端响应后完成一次 Bulk IN（接收），在硬件总线上至少跨越 2 个微帧：
  $$\text{单次往返延迟 (RTT)} \approx 2 \times 125\ \mu\text{s} = 250\ \mu\text{s}$$
- **客户端全局大锁死锁并发**：原有 `leechusb_client.c` 在 `EnterCriticalSection(&g_usb_client.Lock)` 保护下调用 `WinUsb_ReadPipe` 阻塞等待 USB 硬件回包，导致 8 个线程完全无法并发，100% 退化为单线程 Stop-and-Wait 串行停等：
  $$8000\ \text{次} \times 250\ \mu\text{s} = 2,000,000\ \mu\text{s} = 2000\ \text{ms}$$
- **驱动单包截断**：原有 `usb_server.c` 每次只读取并响应 1 个帧，未支持滑动游标多帧收割，多帧同时到达时后续帧被截断丢弃。

---

## 2. 核心架构决策与设计 (Architecture Decisions)

为彻底消灭 250 微秒串行停等气泡，同时保持大包 157 MB/s 零退化与内核反作弊零暴露，采纳 **方案 A：客户端 Flat-Combining 组提交 + 驱动端流水线连续收割与合并回包**。

### 2.1 协议零破坏复用 (qwNonce 契约)
- USB 12 字节帧头：`[8B qwNonce][4B cbPayload][Payload]`；
- 驱动端由原先写入随机 `__rdtsc()` 改为**原样回传请求方的 `qwReqNonce`**；
- 客户端利用 `qwNonce` 在多包并发时将合并回包 1:1 准确分发并唤醒对应线程，完全向下兼容单包与旧版驱动。

### 2.2 客户端 Flat-Combining 组提交 (leechusb_client.c)
- **静态槽位与 Zero-List 铁律**：定义静态定长槽位 `BatchSlots[64]`，彻底摒弃动态双向链表，遵循 [ADR-0011](0011-zero-list-permanent-thread-and-corrupt-entry-bsod.md)；
- **Leader-Follower 动态选举**：
  * 首个到达的线程成为 **Leader**，其余并发线程作为 **Follower** 在其各自的轻量级事件 `hEvent` 上休眠等待；
  * **Leader 一次性收割**：Leader 将当前队列中所有就绪槽位打包拼接，**仅调用 1 次 `WinUsb_WritePipe`** 推上 USB；
  * **一次性批量读回与分发**：Leader 读回全部合并响应，按 `qwNonce` 匹配槽位并调用 `SetEvent` 一次性唤醒全部 Follower；
  * **大包直通旁路**：`cbIn >= 64KB` 时自动绕过组提交，独占硬件通道，确保 157 MB/s 零退化。

### 2.3 驱动端流水线连续收割与合并回包 (usb_server.c)
- **双指针滑动游标与残片回填**：维护 `cbRemain` 与 `cbRecvTail`，未完整的尾部半包帧通过 `RtlMoveMemory` 移位到缓冲区首部继续补齐，彻底杜绝粘包与截断；
- **DirectOut 原位直写连续追加**：在 1MB 发送槽位内紧凑连续写入各请求的响应，智能预估 `cbEstNeeded`，若槽位溢出则触发前置冲刷翻转槽位；
- **合并异步发送**：整批请求处理完毕后，**仅调用 1 次 `UsbHub_BulkWriteAsync`** 合并发出，将 8 次 URB 往返压缩为 1 次。

### 2.4 驱动端 IRP 栈深度纵深防御 (usb_hub.c)
- 对齐 [ADR-0012](0012-wsk-transport-context-corruption-and-stack-underflow-bsod-0xa.md)，将 IRP `stackSize` 最小安全下限由 `1` 提升至 `max(stackSize, 4)`，彻底杜绝下层过滤驱动展开栈下溢蓝屏。

---

## 3. 性能预期与验证指标

| 评估指标 | 优化前 (Stop-and-Wait) | 优化后 (Group Commit + Batching) | 改善幅度 |
| :--- | :--- | :--- | :--- |
| **8 线程 8000 次 4B 读取** | 2045 ms (3,911 Ops/s) | **~200 ms (35,000+ Ops/s)** | **提速 9~10 倍** |
| **单次物理往返次数** | 8000 次 | 约 1000 次 (折叠 8 倍) | 硬件微帧利用率大幅提升 |
| **100 页大跨页连续读取** | 157.25 MB/s | **157.25+ MB/s** | 100% 保持，零性能回退 |
| **内核态系统线程开销** | 1 个常驻线程 | **1 个常驻线程 (0 新增)** | 100% 免疫反作弊线程审计 |
| **内核态内存动态申请** | 0 动态池分配 | **0 动态池分配 (100% DirectOut)** | 0 池锁争用 |

---

## 4. 已知约束与避坑铁律 (Negative Knowledge)

1. **严禁在组提交中使用动态内存分配或链表**：客户端 `Slots[64]` 必须采用静态数组，多线程争用仅在获取/归还槽位时持有毫秒级 `QueueLock`，严禁在持有 `QueueLock` 时执行任何物理 I/O；
2. **严禁破坏大包直通通道**：超大报文（`>= 64KB`）必须走直接通道，不得尝试将其与小包拼接，否则会破坏单次传输窗口与 DirectOut 原位直写连续性；
3. **驱动端 Nonce 必须严格回传**：驱动必须将请求帧头的 `qwReqNonce` 完整无损地拷入响应帧头，严禁填充随机数或静态常数，否则客户端无法完成多路复用响应解算。
