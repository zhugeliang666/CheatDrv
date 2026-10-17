# ADR-0028: TCP 传输层原生 WinSock2 组提交重构、WSK 滑动窗口尾部枯竭根治与常驻 IRP 超时重用

- **状态**: 已采纳
- **日期**: 2026-10-16
- **上下文与痛点**:
  在 TCP (`nng://`) 传输模式下，运行多线程高频物理/虚拟内存读取（如 `DeltaForceVMMInterface.exe` 8 线程并发散列读）时，偶发出现线程帧数骤降 2~3 倍的周期性抖动。经全栈深度排查，定位出三大核心瓶颈：
  1. **驱动端 `FastRecvBuf` 双指针滑动窗口尾部空间枯竭与常驻 IRP 旁路风暴 (`wsk_server.c`)**：
     - 当 TCP 流出现粘包/拆包导致单轮批处理结束后仍有未消费残片（`cbRecvHead < cbRecvTail`）时，双游标不会归零而是持续向 1MB `FastRecvBuf` 尾部推进；
     - 一旦残留的半包长度 $\ge 12$ 字节（已包含 NNG 帧头但帧体尚未收全），将直接跳过 Step 1 的 `< 12` 字节循环及其内部的 `< 64KB` 归一化检查，进入 Step 2；
     - Step 2 仅当尾部可用空间 `cbAvail < FrameSize - cbValid` 时才执行 `memmove`，导致 `cbAvail` 在接近 1MB 缓冲区末端时萎缩至几 KB，引发单次大批量粘包被切碎为数十次微型 `WskReceive`；
     - 更致命的是，`WskSyncReceiveTimed` 原本限制 `if (!pTimeout && pClient->pRecvIrp)` 才使用常驻 IRP，而 Step 2 传入了 `&BodyTimeout` (`pTimeout != NULL`)，导致每次分片补齐都退化为 `WskAllocateSyncIrp`（高频动态调用 `IoAllocateIrp` + `IoFreeIrp`），引发内核池锁争用与调度抖动。
  2. **客户端 `leechnng.c` 依赖 `nng.lib` 逐包串行状态机与高频堆分配**：
     - 不同于 USB/UDP 的 64 槽位 Flat-Combining 组提交，原 `leechnng.c` 依赖第三方 `nng.lib` 的 `nng_ctx_sendmsg` / `nng_ctx_recvmsg`，每个线程请求必须经过 NNG 内部 `nni_taskq` 异步工作线程切换并逐包调用 `WSASend`，导致驱动端 `wsk_server.c` 无法在单次 `WskReceive` 中批量收割多帧，且每笔请求伴随 3~4 次动态堆分配（`nng_msg_alloc` × 2 + `LocalAlloc` × 1~2）。
  3. **单页散列读快路径漏压缩与内核压缩槽冗余锁开销 (`RpcDispatcher.cpp`)**：
     - `ReadEx<ULONG>(..., VMMDLL_FLAG_NOCACHE)` 底层转化为 `cMEMs = 1`（4096 字节整页）散列读请求，原 `cMEMs == 1` 快路径完全跳过 `LeechRPC_CompressMsg`，导致 8000 次请求在千兆网上传输 `33.76 MB` 裸数据（纯物理线耗时 ~300ms），而 R3 `leechagent` 对 `> 0x600` 响应均执行 XPRESS 压缩（降至 ~8.5 MB）；同时 `LeechRPC_CompressMsg` 内部在单通信线程架构下仍冗余调用 `ExAcquireFastMutex` / `ExReleaseFastMutex`。

- **技术决策与规范**:
  1. **驱动端 `WskSyncReceiveTimed` 全量常驻 IRP 复用 (`WskServer.cpp`)**：
     - 移除 `!pTimeout` 限制，无论是否指定超时参数，100% 复用预分配的 `pClient->pRecvIrp` 与 `pClient->pFastRecvMdl`；
     - 当 `pTimeout != NULL` 且 `KeWaitForSingleObject` 返回 `STATUS_TIMEOUT` 时，执行 `IoCancelIrp(Irp)` 并二次无限期等待 `Sync.pEvent` 完成信号，确保底层 WSK 完成例程安全退出并完全归还常驻 IRP 所有权，彻底消灭分片接收时的动态 IRP 分配。
  2. **驱动端 `FastRecvBuf` 循环首部无条件前置归一化 (`WskServer.cpp`)**：
     - 在 `while (g_WskServer.fRunning && pClient->fActive)` 的 `fIsNng` 分支首部（Step 0）以及 Step 1 / Step 2 循环内部，只要检测到 `cbRecvHead == cbRecvTail` 立即归零游标；只要尾部剩余空间 `sizeof(FastRecvBuf) - cbRecvTail < 256KB`，无论当前残片是否 $\ge 12$ 字节，无条件执行 `memmove` 将残片归一化至偏移 0，确保每次 `WskReceive` 始终拥有 $\ge 768\text{KB}$ 的充裕接收窗口。
  3. **驱动端无锁 XPRESS 压缩与单页快路径全覆盖 (`RpcDispatcher.cpp`)**：
     - 移除 `LeechRPC_CompressMsg` 内部多余的 `ExAcquireFastMutex` / `ExReleaseFastMutex`（驱动端为单传输线程串行调用）；
     - 在 `cMEMs == 1` 快路径与多页路径统一对 `pRspBin->cb >= 0x1000` (4KB) 启用无锁 XPRESS 压缩，将 4KB 单页响应压缩至 ~1KB，使 8 线程 8000 次小包压测网络载荷降低 75%。
  4. **客户端 `leechnng.c` 原生 WinSock2 + `leechrpcclient.c` 双波次跨线程散列读 RPC 合并重构，彻底剥离 `nng.lib` / `mbedtls`**：
     - 在 `leechnng.c` 中基于 `lc_winapi.h` 无导入表 WinSock2 原语直接实现 NNG SP `REQ0/REP0` 线协议（8 字节握手 `\x00SP\x00\x00\x30\x00\x00` $\leftrightarrow$ `\x00SP\x00\x00\x31\x00\x00`，以及 20 字节帧头 `[8B Big-Endian TotalLen][4B RequestId (0x80000000 | slotIdx)][8B Nonce]`）；
     - **跨线程散列读双波次 RPC 合并器 (`LeechRPC_ReadScatter_CombineNng`)**：针对 `cValidMEMs <= 8` 的多线程小包散列读，在 `leechrpcclient.c` 层将 8 个并发线程自动切分为 **Wave A (4 线程) + Wave B (4 线程)** 两个全双工乒乓波次，由 Wave Leader 在栈上将同一波次的 `MEM_SCATTER` 直接合并为 **1 个** `READSCATTER_REQ` 报文提交，收到响应并解压后原位填充各 Follower 的 `ppMEMs`（Follower 零 `LocalAlloc`、零解压、零网络调用直接返回），同时使 Wave A 与 Wave B 在网络与驱动端 100% 全双工重叠；
     - 引入 **64 槽位单轨 Flat-Combining Group Commit + 全双工 `SendLock`/`RecvLock` 流水线**：
       * **滑动窗口并发峰值水位 (`g_nng_cPeakThreads`)**：追踪 4.5ms 时间窗内的真实并发线程峰值，根除每轮结束时 `g_nng_cActiveThreads` 瞬时归零导致下一轮首个到达的 Leader 误判为单线程（`activeNow == 1`）零自旋发单包的问题；
       * **Follower `~400µs` TSC 用户态无锁自旋**：在小包低延迟场景下 100% 在用户态命中完成状态，消除 `SetEvent` / `WaitForSingleObject` 内核态上下文切换开销；
       * **无条件全双工交接 + `NngClient_FlushReadySlots` 原子批量扣减 `cInFlightCount`**：`SendLock` 后立即交接保证 100 页大包发送与接收 100% 全双工重叠（`147.56 MB/s`）；
     - 从 `leechcore.vcxproj` 中彻底移除 `nng.lib;mbedcrypto.lib;mbedtls.lib;mbedx509.lib` 静态库依赖。

- **已知约束与避坑**:
  - 常驻 IRP 在带超时等待触发 `STATUS_TIMEOUT` 后，**严禁**不经 `IoCancelIrp` + `KeWaitForSingleObject(..., NULL)` 同步回收就进入下一轮 `IoReuseIrp`，否则底层异步完成时必引发 BugCheck 蓝屏；
  - 严禁仅依赖瞬时 `g_nng_cActiveThreads` 判断微聚拢目标水位（每轮批次交替间隙该值会瞬时跌至 1 造成单包抢跑碎裂），必须结合滑动时间窗峰值 `g_nng_cPeakThreads` 与 `cQueuedCount + cInFlightCount >= target` 守恒条件；
  - 保持 `LeechRPC_NngThreadCleanup()` 空桩函数导出以兼容 `DllMain` (`DLL_THREAD_DETACH`) 既有调用链。
