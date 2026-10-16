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
  3. **中小包散列读过度触发 XPRESS 压缩 (`rpc_dispatch.c`)**：
     - `MkRpc_HandleReadScatter` 原阈值 `pRspBin->cb >= 0x1000`（4KB，仅 1 页）即触发 XPRESS 压缩，导致 2~15 页的高频中小包散列读频繁争用内核 4 槽位 `FAST_MUTEX` 并在客户端触发二次 `LocalAlloc` 解压拷贝。

- **技术决策与规范**:
  1. **驱动端 `WskSyncReceiveTimed` 全量常驻 IRP 复用 (`wsk_server.c`)**：
     - 移除 `!pTimeout` 限制，无论是否指定超时参数，100% 复用预分配的 `pClient->pRecvIrp` 与 `pClient->pFastRecvMdl`；
     - 当 `pTimeout != NULL` 且 `KeWaitForSingleObject` 返回 `STATUS_TIMEOUT` 时，执行 `IoCancelIrp(Irp)` 并二次无限期等待 `Sync.pEvent` 完成信号，确保底层 WSK 完成例程安全退出并完全归还常驻 IRP 所有权，彻底消灭分片接收时的动态 IRP 分配。
  2. **驱动端 `FastRecvBuf` 循环首部无条件前置归一化 (`wsk_server.c`)**：
     - 在 `while (g_WskServer.fRunning && pClient->fActive)` 的 `fIsNng` 分支首部（Step 0）以及 Step 1 / Step 2 循环内部，只要检测到 `cbRecvHead == cbRecvTail` 立即归零游标；只要尾部剩余空间 `sizeof(FastRecvBuf) - cbRecvTail < 256KB`，无论当前残片是否 $\ge 12$ 字节，无条件执行 `memmove` 将残片归一化至偏移 0，确保每次 `WskReceive` 始终拥有 $\ge 768\text{KB}$ 的充裕接收窗口。
  3. **驱动端自适应压缩阈值上调 (`rpc_dispatch.c`)**：
     - 将 `MkRpc_HandleReadScatter` 的 XPRESS 压缩触发阈值由 `0x1000` (4KB) 上调至 `0x10000` (64KB / 16 页)，使中小尺寸散列读 100% 走零压缩直通路径，仅在 $\ge 64\text{KB}$ 大批量跨页读取时启用压缩突破千兆网卡线速。
  4. **客户端 `leechnng.c` 原生 WinSock2 + 64 槽位 Flat-Combining 组提交重构，彻底剥离 `nng.lib` / `mbedtls`**：
     - 在 `leechnng.c` 中基于 `lc_winapi.h` 无导入表 WinSock2 原语直接实现 NNG SP `REQ0/REP0` 线协议（8 字节握手 `\x00SP\x00\x00\x30\x00\x00` $\leftrightarrow$ `\x00SP\x00\x00\x31\x00\x00`，以及 20 字节帧头 `[8B Big-Endian TotalLen][4B RequestId (0x80000000 | slotIdx)][8B Nonce]`）；
     - 引入与 USB 传输层同构的 **64 槽位单轨 Flat-Combining Group Commit + 全双工 `SendLock`/`RecvLock` 流水线**：Leader 线程微聚拢收割并发槽位（受限于单批响应预算 `MAX_BATCH_EST_RSP = 0xE0000` 与发送预算 `256KB`），在预分配的 2MB 常驻缓冲内完成整批打包加密与 **单次 `send()`** 系统调用；接收端通过流式滑动窗口与 `RequestId` $O(1)$ 索引 + `Nonce` 强校验直接解密分发至各槽位并支持断线自动重连；
     - 从 `leechcore.vcxproj` 中彻底移除 `nng.lib;mbedcrypto.lib;mbedtls.lib;mbedx509.lib` 静态库依赖。

- **已知约束与避坑**:
  - 常驻 IRP 在带超时等待触发 `STATUS_TIMEOUT` 后，**严禁**不经 `IoCancelIrp` + `KeWaitForSingleObject(..., NULL)` 同步回收就进入下一轮 `IoReuseIrp`，否则底层异步完成时必引发 BugCheck 蓝屏；
  - 保持 `LeechRPC_NngThreadCleanup()` 空桩函数导出以兼容 `DllMain` (`DLL_THREAD_DETACH`) 既有调用链。
