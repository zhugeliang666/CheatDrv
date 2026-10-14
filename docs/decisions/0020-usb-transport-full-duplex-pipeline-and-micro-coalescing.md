# ADR-0020: USB 传输层全双工读写双锁流水线、单趟自适应微聚拢与静态 MDL 物理偏移修复

- **状态**: 已采纳
- **日期**: 2026-10-15
- **上下文与痛点**:
  1. **吞吐卡在 9,650 Ops/s (829 ms) 的四大瓶颈**:
     - 在初步引入 Flat-Combining 组提交（[ADR-0014](0014-usb-transport-group-commit-and-pipeline-batching.md)）后，8 线程 8,000 次内存读取耗时由 2,045 ms 降至 829 ms（提升 2.5 倍），但相较理论极速（~200 ms / 35,000+ Ops/s）仍有 3~4 倍压榨空间；
     - **瓶颈 1（批次碎裂为 2.46 个/批）**: Leader 线程在第 1 轮 0 微秒抢跑，且处理完自身请求后被困在 `while(TRUE)` 循环继续替别人拉货，无法返回上层发起下一轮，有效并发线程由 8 降为 7；在调用 `SetEvent` 唤醒 Follower（需 5~15 微秒）后，Leader 仅隔 0.1 微秒就再次收割队列，导致每批只能抓取跑得最快的 1~2 个请求，将 8 线程波次切碎；
     - **瓶颈 2（全双工硬件被单锁锁死）**: 客户端使用单一全局 `g_usb_client.Lock` 贯穿发送与接收，在 `WinUsb_ReadPipe` 等待回包的 200 微秒期间，发送管道（`bEpOut`）完全闲置，驱动端 `UsbHub_BulkWriteAsync` 异步全双工能力未被喂满；
     - **瓶颈 3（高频内核态切换与堆锁争用）**: 槽位入队与唤醒产生上万次 `ResetEvent` / `SetEvent` 系统调用；`LeechRPC_ReadScatter_Impl` 每次小包（88 字节）均高频调用 `LocalAlloc(LMEM_ZEROINIT)` 争用进程全局堆锁；
     - **瓶颈 4（驱动端 DMA 覆写严重隐患）**: 在 [usb_server.c](file:///e:/Project/Drv/CheatDrv/usb_server.c) 中，当出现跨 URB 残片（`cbRemain > 0`）时，仍向 `UsbHub_BulkReadFast` 传递基址为 0 的静态 `pFastRecvMdl`，底层 xHCI DMA 硬件直接从 MDL 起始物理页写入，导致前 `cbRemain` 字节数据被冲毁覆盖。

---

- **技术决策与规范**:
  1. **驱动端 MDL 基址一致性校验与残片安全回退 (DMA Safety Gate)**:
     - 在 [usb_server.c](file:///e:/Project/Drv/CheatDrv/usb_server.c) 中，当且仅当 `cbRemain == 0` 时走常驻 `pFastRecvMdl` 零分配极速直读；
     - 当 `cbRemain > 0` 时安全走 `UsbServer_ReadPipe`（内部调用 `UsbHub_BulkRead` 动态构建带偏移的独立 MDL）；并在 [usb_hub.c](file:///e:/Project/Drv/CheatDrv/usb_hub.c) 的 `UsbHub_BulkReadFast` 中增加 `pBuf != MmGetMdlVirtualAddress(pMdl)` 防御性兜底，彻底杜绝底层 DMA 覆写残片。
  2. **收割即交棒（Harvest-Time Leader Handoff）与 4+4 双波次 Ping-Pong 全双工流水线**:
     - 若 Leader 直到 `WinUsb_ReadPipe` 结束后才置零 `fLeaderRunning`，则 `RecvLock` 等待期间（250µs）后续线程无法选出新 Leader，导致 `SendLock` / `RecvLock` 双锁退化为半双工停等（耗时 450 ms）；
     - **核心改进**：Leader 在 `QueueLock` 内将当前波次从 `USB_SLOT_QUEUED` 切换为 `USB_SLOT_IN_FLIGHT` 后，**在同一临界区内立即置位 `fLeaderRunning = 0`**；
     - 当并发线程 $\ge 6$（如 8 线程）时，自动切分为 **4+4 双波次 Ping-Pong 流水线**：Wave A（前 4 线程）收割后立即释放选举权并进入 `SendLock` $\rightarrow$ `RecvLock`；Wave B（后 4 线程）立刻选出第二个 Leader，在 Wave A 等待 USB IN 硬件回包的 250µs 空档期内，**并发完成 Wave B 的打包与 `WinUsb_WritePipe` 发送**，实现 USB OUT 与 USB IN 管道 100% 硬件重叠；
     - 在 `RecvLock` 中匹配全局所有 `USB_SLOT_IN_FLIGHT` 槽位（通过 `s->qwNonce == batchNonces[i] && s->fState == USB_SLOT_IN_FLIGHT` 防范 ABA 复用），支持多波次互助收割。
  3. **无锁原子计数微聚拢（Lock-Free Micro-Coalescing）**:
     - 引入原子计数器 `cQueuedCount` 与 `cInFlightCount`；
     - Leader 在微聚拢窗口内**完全不加 `QueueLock`**，仅通过无锁读取 `cQueuedCount >= targetWave` 配合 `_mm_pause()` 自旋（至多 1200 次 $\approx 6\text{ }\mu\text{s}$），彻底消除 Leader 对正在入队的 Follower 线程的锁阻塞。
  4. **纯用户态零系统调用唤醒（User-Mode Spin-Wake + `fKernelWaiting` 按需 `SetEvent`）**:
     - Follower 用户态自旋上限提升至 `80,000` 次 `_mm_pause()`（约 `350 µs`，完整覆盖单次 USB RTT），99.9% 的请求在 Ring 3 纳秒级直接检测到 `USB_SLOT_DONE` 返回；
     - 引入原子标志 `fKernelWaiting`（Dekker 双重检查），仅当 Follower 真正超时陷入 `WaitForSingleObject` 时才置 `1`，Leader 仅在 `InterlockedExchange(&s->fKernelWaiting, 0) == 1` 时调用 `SetEvent`，消灭每轮 7 次 `NtSetEvent` + 7 次 `NtWaitForSingleObject` 内核切换开销。

---

- **已知约束与避坑**:
  - **静态 MDL 偏移禁忌**: 任何使用常驻/静态 MDL 的底层 DMA I/O，严禁向其传入带有正向偏移的虚拟地址缓冲，必须保证 `pBuf == MmGetMdlVirtualAddress(pMdl)`；
  - **双波次 ABA 防御契约**: 收割即释放 `fLeaderRunning = 0` 后，判定本波次是否完成必须同时校验 `s->fState == USB_SLOT_IN_FLIGHT && s->qwNonce == batchNonces[i]`，并采用轮询游标 `rrCursor` 分配空闲槽位，杜绝槽位快速复用引发的 ABA 误判。
