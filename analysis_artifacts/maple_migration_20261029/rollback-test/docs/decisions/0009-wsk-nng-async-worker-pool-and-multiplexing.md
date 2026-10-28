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
10. **彻底废除内核多工作线程池 (`MK_WSK_USE_WORKER_POOL` 彻底移除)**：
   经过实测与对抗评估，驱动彻底废除了在内核中派生 10 个系统 Worker 线程的多线程池方案（包含废除相关的任务队列自旋锁、惊群事件与多线程回包互斥体）：
   - **反作弊高危靶点**：在内核态调用 `PsCreateSystemThread` 派生匿名系统线程会被 `PsSetCreateThreadNotifyRoutine` 深度审计 StartAddress 归属，极易暴露驱动代码载体；
   - **全面固化方案 A（纯单线程极致常驻 IRP 流水线）**：驱动只保留 1 条主通信线程，0 额外工作线程；基于 1MB `FastSendBuf` DirectOut 原位直写（0 动态池分配、0 memcpy）、常驻 `pRecvIrp` / `pSendIrp`（`IoReuseIrp` 消除 16000 次 IRP 堆分配开销）以及单次 `WskSyncSendAll` 合并冲刷（Coalesced Flush），兼具极致吞吐与 100% 反作弊免杀隐匿性。

11. **多工作线程并发回包必须使用 KMUTEX 互斥体，严禁使用自旋锁包围 I/O 阻塞等待 (BSOD 0x0A IRQL_NOT_LESS_OR_EQUAL)**：
   多 Worker 线程并发向同一 TCP 套接字发送 NNG 响应帧时，必须保证整帧原子发送，防止多线程数据交错破坏 NNG 帧结构。
   **严禁使用自旋锁（`KeAcquireSpinLockRaiseToDpc`）**！因为 `WskSyncSendAll` 内部包含 `KeWaitForSingleObject` 等待 IRP 完成，以及数毫秒级别的网络 I/O 传输。在 `DISPATCH_LEVEL`（自旋锁持有状态）下调用可阻塞例程会瞬间触发 BugCheck `0x0A` (IRQL_NOT_LESS_OR_EQUAL) 或引发 `0x101` Watchdog 超时；**必须使用 `KMUTEX`（`KeInitializeMutex` / `KeWaitForSingleObject` / `KeReleaseMutex`）**，在 `PASSIVE_LEVEL` 下安全互斥并支持线程优雅让出时间片。*(注：多线程池已在第 10 条被全面废除)*

12. **大块连续虚拟内存压测必须由静态高速缓冲全覆盖 (Big Pool Spinlock Contention Elimination)**：
    多线程并发 100 页（400KB）连续大块读取时，静态缓冲必须无痕扩容至 1MB（`MK_WSK_FAST_BUF_SIZE = 1MB`），确保 400KB 响应 100% 命中 DirectOut 原位直写并支持多帧合并冲刷。严禁高频触发非分页大池分配（`ExpAllocateBigPool`），彻底消除多核并发抢占全局大池自旋锁导致的吞吐断崖；同时在 `DeviceKernel_ReadScatter` 中接入相邻物理页突发合并读取（Contiguous PFN Burst），大幅缩减虚实转换开销。

13. **工作线程池事件折叠陷阱与独享 DirectOut 缓冲规范 (SynchronizationEvent Collapse & Worker DirectOut)**：
    - **严禁使用 `SynchronizationEvent`（自动重置）作为多工作线程派发事件**：当主线程快速入队多个请求时，多次 `KeSetEvent` 会被内核折叠为 1 次信号，仅唤醒 1 个 Worker 线程，而其余工作线程仍停留在 `KeWaitForSingleObject` 超时睡眠中，导致 10 线程池名存实亡、被彻底退化为单线程串行处理。*(注：已随多线程池一同废除)*；
    - **单线程常驻 IRP 与 DirectOut 零拷贝**：彻底消灭每个小请求在热路径上触发的多次 `ExAllocatePool/Free` 与 `IoAllocateIrp/Free` 开销。

14. **工作线程池网络发送串行化与异步合并响应队列冲刷规范 (Coalescing Flush Responder)**：
    - **禁止 Worker 线程持有互斥锁同步等待网络 IRP**：若每个 Worker 在计算完成后各自持有 `SendMutex` 并调用 `WskSend` + `WskWaitForIrp` 同步等待网卡完成，由于网络微报文往返时延（~160 微秒），10 个 Worker 线程会被锁强制排成单行道，导致 8000 次请求耗时停留在 1311 ms，多线程并发度实质降为 0；
    - **单线程就地贪婪收割与合并冲刷胜出**：实测证实，单线程在 `FastRecvBuf` 中连续就地解包直写 `FastSendBuf`，并在批次收割完毕后单次调用 `WskSyncSendAll` 合并出网，吞吐性能大幅提升，同时消灭全部跨线程调度、自旋锁争用与堆分配开销。

15. **内核态 KeWaitForSingleObject 微秒时钟分辨率陷阱 (Negative Knowledge: Clock Tick Delay BSOD/Stall)**：
    - **实测复盘与 16 秒性能雪崩根因**：若试图在接收循环中加入“25 微秒微超时非阻塞排空（`KeWaitForSingleObject` 传入 `-10 * 25`）”，实测 8000 次请求总耗时会从 433 ms **断崖式暴跌至 16,118 ms (16.1秒)**，QPS 跌至 496 Ops/sec；
    - **根本物理机理**：Windows 内核的 `KeWaitForSingleObject` 基于硬件时钟节拍（Clock Interrupt Tick），其最小调度粒度受限于系统定时器分辨率（标准 15.6ms，高精度下为 1~2ms），**绝对无法实现微秒级的精确超时**。任何微秒级等待在底层都会被扩展为一个完整的系统时钟节拍（~2ms）。8000 次请求每次超时 2ms，8000 * 2ms = 16,000 ms，数学上完全吻合；
    - **铁律结论**：内核网络接收热路径中**严禁在缺少数据时使用超微超时主动轮询或探测**。必须依托 WSK 自身的批量接收缓冲区（传满 1MB `FastRecvBuf` 空间），让底层 AFD/TCPIP 驱动在数据到达时自然批量交付，杜绝人工超时探测。

16. **全双工异步双缓冲发送流水线规范 (Double-Buffered Async Send Pipeline & WSK_FLAG_NODELAY)**：
    - **痛点与 150 微秒延迟解构**：单线程批处理下，虽以 0 额外系统线程满足了反作弊要求，但使用 `WskSyncSendAll` 会导致主线程在发出应答后进入 `KeWaitForSingleObject` 阻塞等待发送 IRP 完成（平均耗时 100~150 微秒）。在此等待窗口内，客户端多线程并发到达的新请求无法被读取，导致 8 线程并发被半双工串行化限制在 18,800 Ops/s（均延 0.42 ms）；
    - **全双工双缓冲 (Double-Buffering)**：在 `MK_WSK_CLIENT` 中预分配 2 套发送槽位 `FastSendBuf[2]`、`pFastSendMdl[2]`、`pSendIrp[2]`。主线程在将当前批次数据写入当前槽位后，直接调用 `WskSend(..., WSK_FLAG_NODELAY, Irp)`，底层返回 `STATUS_PENDING` 时仅标记 `InFlight`，主线程**不调用 `KeWaitForSingleObject` 睡眠**，翻转槽位后立即无缝返回顶层 `WskSyncReceive`；
    - **发送与接收 100% 时间重叠**：底层网络 DMA 异步发送的时间被完全隐藏在网络 RTT 和下一轮数据接收等待中，彻底消灭 150 微秒发送阻塞停顿，兼具 0 额外系统线程的隐匿性与全双工并发吞吐。

17. **异步 IRP 完成例程严禁传入局部栈变量上下文 (Negative Knowledge: BSOD 0xD1 DRIVER_IRQL_NOT_LESS_OR_EQUAL)**：
    - **崩溃复盘 (BugCheck 0xD1)**：
      在构建双缓冲全双工异步发送流水线（`WskAsyncSendSlot`）时，若将完成例程上下文 `WSK_SYNC_CONTEXT Sync` 声明为发送函数的局部栈变量并挂入 `IoSetCompletionRoutine(Irp, WskSyncCompletionRoutine, &Sync, ...)`；由于 `WskSend` 返回 `STATUS_PENDING` 时主函数立即 `return` 退栈，导致栈内存被后续调用帧覆写。底层 AFD/TCPIP 协议栈在微秒后（DPC / `DISPATCH_LEVEL`）回调 `WskSyncCompletionRoutine` 时，从已失效的栈地址中读取到脏数据 `rax = 0x300`，执行 `call qword ptr [rax+140h]`（即 `call [0x440]`）瞬间触发 BugCheck `0xD1`（Arg1=`0x440`, Arg2=`0x2`, Arg3=`0x0`, Arg4=`WskSyncCompletionRoutine+0x1f`）；
    - **常驻生命周期铁律**：
      内核态所有异步 IRP（无论是否立即返回）的完成例程上下文指针，其生命周期必须严格覆盖整个 IRP 执行周期。**严禁使用任何局部栈变量作为异步 I/O 的 Completion Context**；必须将其收纳至宿主堆结构体（如 `MK_WSK_CLIENT.SendSync[4]`）中进行静态常驻分配，并在客户端连接生命周期内预绑定完成。

18. **4 槽位深度环形流水线与常驻接收 IRP 规范 (4-Slot Pipeline Ring Buffer & Persistent Recv IRP)**：
    - **双缓冲退化痛点**：实测表明，在 8 线程并发满速读取下，双缓冲（2 槽位）容易因底层网卡出网耗时（~100 微秒）大于主线程处理 2 个微型帧耗时（~2 微秒），导致槽位轮转迅速撞墙，`WskDrainPendingSend` 频发 `KeWaitForSingleObject` 阻塞，平均延迟被拉大至 0.41 ms；同时常驻接收 IRP（`pRecvIrp`）若漏初始化，会导致每秒发生数万次 `IoAllocateIrp`/`IoFreeIrp` 动态申请；
    - **4 槽位环形流水线**：将发送槽位扩充为 4 槽位（每个槽位 512KB，共 2MB，加上 1MB 接收缓冲总共 3MB 紧凑非分页内存），采用 `(SlotIdx + 1) % 4` 环形无缝推进。为主线程和底层 DMA 出网提供 3 倍充裕的重叠时间窗口，实现 0 等待穿透；
    - **常驻接收 IRP 全生命周期绑定**：在客户端连接建立时一次性预分配 `pClient->pRecvIrp`，接收主循环全量基于 `WskPreparePersistentIrp` 循环重用，彻底抹平系统 IRP 池分配争用；
    - **实测成果里程碑 (67.1 万次满载压测)**：
      * 累计请求：671,014 次 | 成功率：100.00% | 蓝屏/崩溃：0 次；
      * 平均吞吐：**25,120.26 Ops/sec**（较双缓冲的 19,391 Ops/sec 提升 **+29.5%**，峰值达 **26,188 Ops/sec**）；
      * 平均延迟：由 0.41 ms 骤降至 **0.32 ms**（净压缩 90 微秒，距离原版应用层多线程 0.27 ms 仅差 50 微秒）；
      * 最高延迟：由 40.57 ms 暴跌至 **17.47 ms**（彻底削平 40ms Delayed ACK 停顿毛刺）。

19. **8 槽位深度环形流水线与双指针零拷贝滑动接收规范 (8-Slot Pipeline & Two-Pointer Recv Buffer)**：
    - **极速冲刺痛点剖析**：在吞吐量冲上 2.51 万 Ops/s 后，热路径上每一次微秒级开销都直接决定能否追平原版应用层 0.27 ms 延迟。排查发现两大微瓶颈：
      1. 每次批处理结束调用 `memmove` 将残余字节挪回 0 偏移，在数十万次压测下引发了数十万次无谓的 CPU 缓存行冲刷；
      2. 4 槽位在底层网卡偶发网络抖动时仍有概率打满，最高延迟仍残留 17.47 ms。
    - **8 槽位环形流水线 (8-Slot Pipeline)**：
      将发送槽位深度从 4 扩展到 8（每个槽位 256KB，总内存依然保持 2MB 零膨胀），采用 `(SlotIdx + 1) % 8`。为主线程与底层 DMA 出网留出足足 7 个周期的充裕排空窗口，彻底消灭队列抖动与尾部等待；
    - **双指针滑动接收缓冲区 (Two-Pointer Recv Buffer)**：
      在 `MK_WSK_CLIENT` 中维护 `cbRecvHead`（读偏移）与 `cbRecvTail`（写偏移）。接收追加写入尾部，解析消费直接向前移动游标；消费完毕时双指针归零。仅当尾部剩余空间不足 64KB 时才触发一次极速归一化，**消灭 99.99% 的 `memmove` 内存拷贝**；
    - **热路径内联与内存操作优化**：
      `WskDrainPendingSend` 与 `WskAsyncSendSlot` 采用 `__forceinline` 强制内联；`cMEMs == 1` 单散列项直读路径去除冗余 `RtlZeroMemory`，极致压榨每一纳秒。

20. **连续大跨页虚拟内存压测瓶颈解构与 1MB 单槽位 DirectOut 前置冲刷架构规范 (Large Scatter Read & 1MB Pre-Dispatch Flush)**：
    - **实测性能断崖现象与对比复盘**：
      * **压测场景**：8 线程并发满速读取目标进程 100 个连续虚拟页（400KB 数据，单响应帧 404KB / 413,668 字节）；
      * **原版表现**：均延 21.17 ms（最高 32.27 ms），吞吐 377.60 Ops/sec，带宽 **147.50 MB/s**；
      * **驱动原表现**：均延 29.99 ms（最高 69.34 ms），吞吐 266.23 Ops/sec，带宽 **104.00 MB/s**（较原版落后 29.5%，均延高出 8.8 ms）。
    - **性能断崖三大物理根因定位**：
      1. **DirectOut 零拷贝 100% 击穿**：单发送槽位 `MK_WSK_SEND_SLOT_SIZE` 此前为 256KB，而 100 页大跨页响应帧（20 字节 NNG 头 + 48 字节 MsgBin 头 + 4000 字节散列项 + 409600 字节数据 = 404KB）远超 256KB 阈值，DirectOut 原位直写通道完全失效；
      2. **高频引发非分页大池 (BigPool) 锁风暴与二次 memcpy**：分发器被迫每次调用 `ExAllocatePoolWithTag(NonPagedPoolNx, 404KB)`，网络层由于槽位放不下又调用第二次 `ExAllocatePoolWithTag(NonPagedPoolNx, 404KB)` 并执行全量 404KB `memcpy`。单次请求经历 2 次大池申请与释放，7 秒内发生 3,782 次大池分配，高频争用 `nt!ExpAllocateBigPool` 全局自旋锁并引发系统 TLB 抖动；
      3. **异步流水线彻底归零退化为同步阻塞出网**：超出单槽位后落入超大包 fallback 分支，执行 `WskSyncSendAll`，使驱动主线程进入 `KeWaitForSingleObject` 睡眠等待！全双工异步流水线在 100 页压测下被完全绕过，8 线程并发被完全串行化排队，引发高达 69.34 ms 的长尾延迟毛刺。
    - **核心架构改造方案**：
      1. **单发送槽位扩容至 1MB (MK_WSK_SEND_SLOT_SIZE = 1024 * 1024)**：单槽位 1MB 完美覆盖连续 100~240 个页面（400KB~1MB）大跨页读取，100% 命中 DirectOut 直读直写，0 动态大池分配，0 内存拷贝；
      2. **4 槽位深度全双工环形流水线 (4-Slot Pipeline)**：4 槽位提供 4MB 飞行中网络缓冲窗口，大块数据由底层网卡 DMA 全异步出网，主线程 0 阻塞睡眠；
      3. **分发前智能预估与前置异步冲刷 (Pre-Dispatch Proactive Flush)**：在解密请求后先预估其最大所需空间 `cbEstNeeded`。若当前槽位已累积数据且剩余空间不足以容纳当前请求，在调用分发器前**主动触发 `WskAsyncSendSlot` 将已累积数据送入全双工异步发送并轮转槽位**，确保每个大请求进入分发器时都拥有完整的 1MB 干净空间，100% 锁定 DirectOut 原位直写通道。

