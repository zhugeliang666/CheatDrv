# ADR-0009: WSK NNG 流水线批处理与合并冲刷机制 (Pipeline Batching & 0-Thread AC-Evasion)

- **状态**: 已采纳（演进替代原并发多线程提案）
- **日期**: 2026-10-13
- **涉及组件**: `wsk_server.h`, `wsk_server.c`, `rpc_dispatch.c`

---

## 1. 上下文与痛点

在多线程内存读取压测（如 `ReadEx<ULONG>` 8 线程并发，总量 8000 请求）实测对比中发现：
- **单线程测试**：驱动方案与原版 `leechagent.exe` 耗时几乎完全一致（~32 ms），底层纳秒级物理内存直读性能正常；
- **8 线程并发测试**：
  * 原版 `leechagent.exe`：总耗时 **261 ms**，吞吐量 **30,651.34 Ops/sec**；
  * 历史驱动方案：总耗时 **1310 ms**，吞吐量仅 **6,106.87 Ops/sec**（慢了足足 5 倍）。

### 根本原因剖析 (Root Cause)
1. **客户端连接复用特性**：客户端无论派生多少工作线程，底层均共用**单个 TCP 连接**，通过 NNG 上下文（`nng_ctx`）在 TCP 流上多路复用发送带有独立 `RequestId` 的帧；
2. **TCP 往返时延与 Delayed ACK 瓶颈**：
   客户端 8 个线程并发推送请求，这些请求在内核 TCP 接收缓冲区中几乎同时到达。旧驱动代码只读出第 1 个包便立刻调用 `WskSyncSendAll` 阻塞发送一个 56 字节的微型回包。这在 TCP 协议栈中触发了 TCP Delayed ACK 与往返 RTT 开销，导致客户端的 8 个并发请求在驱动侧被活生生“串行化”处理。
3. **反作弊审计红线 (Anti-Cheat Redlines)**：
   若采用原版方案在内核中创建 10~20 个子工作线程（`PsCreateSystemThread`），会致命触碰反作弊系统（ACE / EAC / Vanguard）的核心审计机制：
   - 同步触发 `PsSetCreateThreadNotifyRoutine` 线程创建回调，反作弊逆向回溯 `StartAddress` 发现落在未签名的 Manual Map / System PTE 驱动内存中，直接判定作弊封号；
   - `System` 进程突然多出 20 个常驻匿名系统线程，触发反作弊启发式威胁告警；
   - 线程调度切换与栈回溯开销显著增大。

---

## 2. 技术决策与规范 (方案 A：流水线批处理与合并冲刷)

为彻底消灭 TCP 延迟与串行化阻塞，同时**100% 保持 0 额外系统线程（绝对免疫反作弊线程审计）**，实施全异步事件驱动与合并出包（Pipeline Batching & Coalesced Flush）架构：

### 2.1 架构模型：零额外线程合并冲刷管道

```text
       TCP Stream (Single Connection, 8 并发请求已积压在接收缓冲)
                     │
                     ▼
          [WskSyncReceive 批量收取] (单次收取多个完整 NNG 帧)
                     │
                     ▼
       ┌────────────────────────────────────────────────────────┐
       │ 方案 A 批处理循环: while (cbBuffered >= 12)            │
       │                                                        │
       │  - 第 1 帧: 提取 ReqId 1 -> 原位解密 -> DirectOut 读内存 │
       │  - 第 2 帧: 提取 ReqId 2 -> 原位解密 -> DirectOut 读内存 │
       │  - ...                                                 │
       │  - 第 8 帧: 提取 ReqId 8 -> 原位解密 -> DirectOut 读内存 │
       │                                                        │
       │  (所有响应连续原位写入 256KB FastSendBuf，0 堆内存分配)  │
       └────────────────────────────────────────────────────────┘
                     │
                     ▼
           [WskSyncSendAll 合并冲刷] (Coalesced Flush)
                     │ (仅调用 1 次发送，将 8 个响应一次性送回)
                     ▼
        客户端 TCP 栈一次性收到全部 8 个响应，8 个线程同时解阻塞！
```

### 2.2 核心机制规范

1. **零额外系统线程 (Zero-Worker Model)**：
   - 彻底废除 `WskClientSubWorkerThread` 与 `PsCreateSystemThread`，驱动内只保留单客户端的主通信线程 `WskClientWorkerThread`；
   - 彻底规避 `PsSetCreateThreadNotifyRoutine` 监测和线程调用栈检查，在反作弊视角下没有任何异常线程活动。
2. **流水线帧收割与原位 DirectOut (Zero Allocation & Zero Copy)**：
   - 在接收主循环中，`WskSyncReceive` 往往能一次性收取包含多个 NNG 帧的数据流；
   - 启动内部批处理循环 `while (cbBuffered >= 12)`，针对缓冲区内已到达的所有完整请求帧，直接利用预分配的 256KB `FastSendBuf` 当前空闲偏移（`pClient->FastSendBuf + cbSendTotal + 20`）作为 `pbDirectOutTarget` 传入 `MkRpc_DispatchCommandEx`；
   - 命中 DirectOut 时，应答数据原位就地直写直读并调用 `WskNngFastCrypt` 加密，彻底抹除每秒上万次 `ExAllocatePoolWithTag(NonPagedPoolNx)`、`ExFreePoolWithTag` 以及二次 `memcpy`；
   - 物理内存读取（ADR-0004）耗时仅数十纳秒，8 个请求在微秒级内即可全部就绪，全程**零堆内存分配、零二次拷贝、零池自旋锁争用**。
3. **Client 级 Cached_hLC 无锁直通通道 (Lockless Handle FastPath)**：
   - 在 `MK_WSK_CLIENT` 结构体中直接维护 `Cached_hLC` 与 `Cached_dwRpcClientID`；
   - 单连接分发时若命中当前客户端缓存的句柄，直接穿透执行分发，**彻底消灭每秒上万次 `ExAcquireFastMutex(&ctxLeechRpc.LockClientList)` 与 `ExReleaseFastMutex` 造成的 APC_LEVEL 提升、互斥锁争用与内存屏障开销**（8000 次请求消除 16,000 次 FastMutex 进出）。
4. **单散列项 (cMEMs == 1) 物理读直通通道 (Direct System PTE Scatter)**：
   - 针对 99.9% 的单页/4 字节 `cMEMs == 1` 读取请求，在 `MkRpc_HandleReadScatter` 中直接穿透调用 `LcPte_ReadPhysicalContiguous`，剥离 4 层函数包装与动态指针数组开销，数十纳秒内完成物理直读。
5. **合并冲刷 (Coalesced Flush)**：
   - 内层批处理循环处理完当前缓冲区中所有到达的请求后，**仅调用 1 次 `WskSyncSendAll`** 将整批响应合并送入 TCP 发送队列；
   - 客户端一次性收到全部响应，并发线程瞬间全数释放进入下一轮迭代，彻底消灭 TCP Delayed ACK 与往返 RTT 开销。

---

## 3. 已知约束与避坑防崩溃铁律 (Negative Knowledge)

1. **严禁在内核态引入 `PsCreateSystemThread` 工作线程池**：
   内核态不能盲目套用应用层多线程模型。反作弊看门狗对系统线程有极为严格的特征码、模块归属及栈回溯审计。单连接高频吞吐必须优先采用批处理合并冲刷（Coalesced I/O），而非盲目开辟线程。
2. **FastSendBuf 溢出防御与大包 Fallback**：
   若批处理累积响应大小接近 `MK_WSK_FAST_BUF_SIZE (1MB)`，必须立即触发中间冲刷，清空缓冲后优先复用清空后的缓冲区头部继续处理；对于单包超过 1MB 的特殊巨型响应，独立动态分配并单独发送，防止缓冲区越界写入；分配 Tag 必须严格配对为 `LC_POOL_TAG`。
3. **帧头边界防御与未收全帧回滚**：
   在批处理循环中，若检测到尾部帧的 `cbBuffered < FrameSize`，必须立即中断批处理循环，将已累积的响应合并送出，然后将剩余未收全的数据通过 `memmove` 滑动归一化至接收缓冲区头部，等待下一轮 `WskSyncReceive` 拼包。
4. **大包动态分配退避与严禁传入 Length=0 (Buffer Starvation BSOD/Disconnect)**：
   若客户端下发的请求帧大于预分配静态缓冲（`FrameSize > sizeof(FastRecvBuf)`），接收循环严禁死循环等待静态缓冲填充；一旦小缓冲区填满导致 `sizeof(FastRecvBuf) - cbWriteOffset == 0`，向底层 `WskSyncReceive` 传入 `Length = 0` 会直接返回 `Status = STATUS_SUCCESS, BytesReceived = 0`，进而被误判为客户端正常断开连接（Graceful TCP Disconnect）而强行销毁会话。对于超过 1MB 的请求与响应帧，必须提供平滑的 `ExAllocatePoolWithTag(NonPagedPoolNx)` 动态退避机制。
5. **强制开启 `TCP_NODELAY` 消灭 Delayed ACK 延迟陷阱**：
   NNG 客户端基于单 Socket 的多线程并发模式中，若驱动未在 ClientSocket 上通过 `WskSetOption(SO_SNDBUF/TCP_NODELAY)` 显式关闭 Nagle 算法，内核协议栈会自动将微型请求/应答挂起等待 40ms~200ms 的 Delayed ACK，导致吞吐量劣化 5~8 倍。每个客户端建立后必须同步调用 `WskSyncSetTcpNoDelay` 和 `WskSyncSetSocketBuffers(4MB)`。
6. **禁止高频进出全局 FastMutex (Client List Contention)**：
   长连接高吞吐读写中，严禁在每次分发时遍历全局客户端链表并获取 `ExAcquireFastMutex`；必须基于连接结构体本身缓存已解析的 `hLC`，仅在连接初始化与销毁时操作全局链表。
7. **MEM_SCATTER 单项快路径必须全量拷贝描述符 (version=0xc0fe0002)**：
   优化 `cMEMs == 1` 单散列项直读时，必须通过 `RtlCopyMemory(pMEM_Dst, pReqMEM, sizeof(MEM_SCATTER))` 完整保留全部元数据字段；严禁漏拷导致 `pMEM_Dst->version == 0`，否则会触发客户端 `leechrpcclient.c` 内置的 `pMEM_Src->version != MEM_SCATTER_VERSION` sanity check 严格校验失败，导致客户端误判通信数据损坏而直接放弃连接并发送 `CLOSE_REQ`。
8. **严禁在单连接无锁句柄缓存中使引用计数失衡 (cActiveRequests Self-Deadlock)**：
   在单连接 Worker 线程模型中，每个连接独立串行处理自身请求。若在句柄查找中使用了增加活跃计数的机制（`cActiveRequests++`），但因命中无锁缓存分支跳过了归还操作（`LeechRPC_LcHandle_Return`），会导致 `cActiveRequests` 永久停留在 `> 0`。随后客户端发送 `CLOSE_REQ` 或退出时，`LeechRPC_LcHandle_Close` 会在内核中陷入 `while (cActiveRequests > 0)` 永无止境的睡眠死循环，导致客户端线程无法响应、无法退出，并在驱动卸载时永久挂起 `Waiting for active clients to disconnect`。必须采用只读查找（Lookup）且在 Close 中设置带超时上限的保护性退避（最多 200ms）。
9. **WSK 套接字关闭生命周期必须采用原子置空防范二次 Close (Double-Close Deadlock)**：
   当卸载线程调用 `WskServer_Stop` 主动关闭所有活动客户端套接字以唤醒挂起的 `WskReceive` 时，Worker 线程唤醒后会迅速进入退出清理流程（`Cleanup:`）。若两端均尝试调用 `WskCloseSocket`，会对已释放的套接字对象发生二次关闭，引发底层 WSK/NetIO IRP 挂起死锁或 UAF。两端必须统一通过 `InterlockedExchangePointer((PVOID*)&pClient->Socket, NULL)` 原子提取套接字句柄，确保每个套接字全生命周期仅关闭一次；同时卸载等待循环必须配备 2 秒超时兜底，杜绝驱动卸载挂起。
10. **工作线程池性能测试开关 (`MK_WSK_USE_WORKER_POOL`)**：
   在多线程并发大块读取（如 8~12 线程并发下发 400KB 大块请求）场景下，客户端在服务端产生大量并发等待。为了兼顾极限并发压测吞吐量（对标原版 10 线程并行架构）与实战反作弊对抗隐匿性，架构设计了双通道可配置宏开关：
   - `MK_WSK_USE_WORKER_POOL 1`：启用 8 个内核系统 Worker 线程池并发执行解密与物理直读，主通信线程专职收包入队，彻底释放多线程并发性能瓶颈；
   - `MK_WSK_USE_WORKER_POOL 0`：纯单线程流水线批处理模式（0 额外系统线程），对反作弊线程枚举与 `PsSetCreateThreadNotifyRoutine` 完全免疫。
11. **多工作线程并发回包必须使用 KMUTEX 互斥体，严禁使用自旋锁包围 I/O 阻塞等待 (BSOD 0x0A IRQL_NOT_LESS_OR_EQUAL)**：
   多 Worker 线程并发向同一 TCP 套接字发送 NNG 响应帧时，必须保证整帧原子发送，防止多线程数据交错破坏 NNG 帧结构。
   **严禁使用自旋锁（`KeAcquireSpinLockRaiseToDpc`）**！因为 `WskSyncSendAll` 内部包含 `KeWaitForSingleObject` 等待 IRP 完成，以及数毫秒级别的网络 I/O 传输。在 `DISPATCH_LEVEL`（自旋锁持有状态）下调用可阻塞例程会瞬间触发 BugCheck `0x0A` (IRQL_NOT_LESS_OR_EQUAL) 或引发 `0x101` Watchdog 超时；**必须使用 `KMUTEX`（`KeInitializeMutex` / `KeWaitForSingleObject` / `KeReleaseMutex`）**，在 `PASSIVE_LEVEL` 下安全互斥并支持线程优雅让出时间片。

12. **大块连续虚拟内存压测必须由静态高速缓冲全覆盖 (Big Pool Spinlock Contention Elimination)**：
    多线程并发 100 页（400KB）连续大块读取时，静态缓冲必须无痕扩容至 1MB（`MK_WSK_FAST_BUF_SIZE = 1MB`），确保 400KB 响应 100% 命中 DirectOut 原位直写并支持多帧合并冲刷。严禁高频触发非分页大池分配（`ExpAllocateBigPool`），彻底消除多核并发抢占全局大池自旋锁导致的吞吐断崖；同时在 `DeviceKernel_ReadScatter` 中接入相邻物理页突发合并读取（Contiguous PFN Burst），大幅缩减虚实转换开销。
13. **工作线程池事件折叠陷阱与独享 DirectOut 缓冲规范 (SynchronizationEvent Collapse & Worker DirectOut)**：
    - **严禁使用 `SynchronizationEvent`（自动重置）作为多工作线程派发事件**：当主线程快速入队多个请求时，多次 `KeSetEvent` 会被内核折叠为 1 次信号，仅唤醒 1 个 Worker 线程，而其余工作线程仍停留在 `KeWaitForSingleObject` 超时睡眠中，导致 10 线程池名存实亡、被彻底退化为单线程串行处理（8000 次请求压测总耗时停留在 1184ms，与单线程耗时完全相同）。必须采用 `NotificationEvent`（手动重置）广播唤醒所有 Worker，并在队列任务被取空时由最后出队的 Worker 原子调用 `KeClearEvent`；
    - **Worker 独享高速 DirectOut 发送缓冲 (0 动态池分配、0 动态 MDL)**：每个 Worker 结构体必须独立配置 64KB 发送缓冲及预构建 MDL（`pWorker->pSendMdl`），小包分发直写直发，彻底消灭每个小请求在热路径上触发的 4 次 `ExAllocatePool/Free` 与 1 次 `IoAllocateMdl/Free` 开销。
14. **工作线程池网络发送串行化与异步合并响应队列冲刷规范 (Coalescing Flush Responder)**：
    - **禁止 Worker 线程持有互斥锁同步等待网络 IRP**：若每个 Worker 在计算完成后各自持有 `SendMutex` 并调用 `WskSend` + `WskWaitForIrp` 同步等待网卡完成，由于网络微报文往返时延（~160 微秒），10 个 Worker 线程会被锁强制排成单行道，导致 8000 次请求耗时停留在 1311 ms，多线程并发度实质降为 0；
    - **异步响应合并入队与零阻塞计算**：Worker 线程仅执行解密与物理直读，将生成的响应帧直接保存在 `pItem->RspBuf`（512 字节空间，0 动态内存分配），随后推入 `pClient->ResponseHead` 队列（自旋锁持有耗时 < 20 纳秒），Worker 立即返回继续拉取下一个任务，绝不同步阻塞等待网络；
    - **原子 Try-Flush 批量出包引擎**：入队后通过 `InterlockedCompareExchange(&pClient->FlushActive, 1, 0)` 抢占冲刷执行权。抢占成功的 Worker 一次性原子摘取 `ResponseHead` 中积压的所有响应帧，连续聚合写入 `FastSendBuf`，**仅调用 1 次底层 `WskSyncSendAll` 合并冲刷出网**；未抢到锁的 Worker 绝不等待，正在冲刷的线程在发完上一批后会自动顺便带走新入队的所有响应。多核计算与网络 I/O 达到完美的流水线重叠；
    - **预分配静态对象池与整批入队 (Zero-Alloc WorkItem Pool & Batch Enqueue)**：严禁在请求分发热路径高频调用 `ExAllocatePoolWithTag` / `ExFreePoolWithTag`（8000 次请求引发 16000 次内核非分页池全局自旋锁争用与单帧入队开销，使耗时阻滞在 433ms）。必须在客户端预分配 64 槽位的静态 `ItemPool`（各含 512 字节静态 `ReqBuf` 与 `RspBuf`），主线程连续收割多个帧后以 `LocalBatch` 整批仅获取 1 次自旋锁插入 `QueueHead` 并仅触发 1 次 `KeSetEvent` 广播唤醒，冲刷发完后整批 1 次自旋锁归还对象池，热路径彻底实现 0 内存池分配与 87.5% 锁开销减免。
15. **内核态 KeWaitForSingleObject 微秒时钟分辨率陷阱 (Negative Knowledge: Clock Tick Delay BSOD/Stall)**：
    - **实测复盘与 16 秒性能雪崩根因**：若试图在接收循环中加入“25 微秒微超时非阻塞排空（`KeWaitForSingleObject` 传入 `-10 * 25`）”，实测 8000 次请求总耗时会从 433 ms **断崖式暴跌至 16,118 ms (16.1秒)**，QPS 跌至 496 Ops/sec；
    - **根本物理机理**：Windows 内核的 `KeWaitForSingleObject` 基于硬件时钟节拍（Clock Interrupt Tick），其最小调度粒度受限于系统定时器分辨率（标准 15.6ms，高精度下为 1~2ms），**绝对无法实现微秒级的精确超时**。任何微秒级等待在底层都会被扩展为一个完整的系统时钟节拍（~2ms）。8000 次请求每次超时 2ms，8000 * 2ms = 16,000 ms，数学上完全吻合；
    - **铁律结论**：内核网络接收热路径中**严禁在缺少数据时使用超微超时主动轮询或探测**。必须依托 WSK 自身的批量接收缓冲区（传满 1MB `FastRecvBuf` 空间），让底层 AFD/TCPIP 驱动在数据到达时自然批量交付，杜绝人工超时探测。





