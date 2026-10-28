# ADR-0011: 零链表架构、常驻单线程模型与彻底根除 BugCheck 0x139 (FAST_FAIL_CORRUPT_LIST_ENTRY)

- **状态**: 已采纳
- **日期**: 2026-10-14
- **核心领域**: 网络通信架构 / 系统崩溃根治 / 反作弊对抗规避

---

## 一、 上下文与痛点分析 (Context & BugCheck 0x139)

在 `drv_wsk.sys` 内核网络通信服务运行过程中，当外部客户端（如控制机 `192.168.4.13`）发生断线重连或重新初始化连接时，系统发生致命内核崩溃：
- **BugCheck 代码**: `0x139` (`KERNEL_SECURITY_CHECK_FAILURE`)
- **崩溃参数 1**: `0x3` (`FAST_FAIL_CORRUPT_LIST_ENTRY`)
- **崩溃指令**: `int 29h` (Fast Fail 断言)
- **崩溃调用栈**: 发生于 `WskAcceptThread` 执行 `InsertTailList(&Server->ClientListHead, &pClient->ListEntry)` 处。

### 根因深度剖析
1. **多客户端模型与双向链表断裂隐患**:
   - 历史架构沿用了传统的类 Web 多客户端并发模型：每次客户端套接字连接通过 `WskSyncAccept` 接入时，服务端动态分配 `MK_WSK_CLIENT` 结构体，并将其作为节点调用 `InsertTailList` 插入全局双向链表 `Server->ClientListHead`；
   - 当客户端异常断开连接时，旧的客户端工作线程（`WskClientWorkerThread`）负责清理自身并调用 `RemoveEntryList` 摘除节点；
   - 当客户端频繁断开并重连时，断开清理与新连接接入发生多核并发交织。旧节点在断开清理时其链表指针发生状态不一致，导致 `ClientListHead.Blink` 指向已失效节点；当新节点尝试插入时，内核的 `InsertTailList` 宏执行安全性校验：
     ```c
     if (ListHead->Blink->Flink != ListHead) {
         __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY); // 触发 BugCheck 0x139 (Arg1=0x3)
     }
     ```
   - 硬件级断言直接导致系统蓝屏崩溃。
2. **高频创建系统线程触碰反作弊深度审计**:
   - 历史架构每次 accept 客户端均调用 `PsCreateSystemThread` 动态派生工作线程。
   - 测试机当前活跃腾讯反作弊（`ACE_BOOT`, `ACE_CORE`），高频派生匿名系统线程会持续触发其 `PsSetCreateThreadNotifyRoutine` 回调监控，导致模块落点与线程起点被深度溯源审计。
3. **高频申请与释放 5.2MB 内存池导致碎片与锁争用**:
   - 每次连接动态申请 1MB 接收缓冲与 4MB 发送流水线缓冲，断线时释放；频繁向内核大池申请内存引发内核堆碎片和全局自旋锁争用。

---

## 二、 核心架构重构决策 (Zero-List, Permanent Single-Thread Model)

为从微架构层面物理消灭 `BugCheck 0x139`，并彻底规避反作弊线程创建审计，实施以下核心重构：

### 1. 彻底废除 LIST_ENTRY 链表（零链表架构）
- 作为单一客户端通信控制通道（DMA/LeechCore 控制端仅存在单一宿主控制机连接），无需多客户端并发链表；
- **从 `MK_WSK_CLIENT` 中彻底删除 `LIST_ENTRY ListEntry;`**；
- **从 `MK_WSK_SERVER` 中彻底删除 `KSPIN_LOCK ClientListLock;` 和 `LIST_ENTRY ClientListHead;`**；
- 源码中 100% 剔除 `InsertTailList`、`RemoveEntryList` 与链表遍历逻辑；
- **数学与架构级根除**：由于双向链表操作已彻底从代码中抹去，`FAST_FAIL_CORRUPT_LIST_ENTRY` 硬件断言的触发条件被物理消除。

### 2. 常驻单例 5.2MB 预分配（零动态申请，重连秒级复用）
- 在驱动初始化 `WskServer_Init` 期间，一次性预分配单例客户端上下文 `g_WskServer.pClient`（约 5.2MB），包含：
  * 1MB 接收端零拷贝缓冲 `FastRecvBuf`；
  * 4 槽位 × 1MB 全双工深度环形流水线发送缓冲 `FastSendBuf`；
  * 预构建的常驻非分页内存 MDL 与预分配常驻 IRP。
- 客户端断开连接时，**绝不释放此 5.2MB 预分配资源**，仅重置游标与会话状态，留待下一次重连秒级原位复用；
- 驱动完全卸载（`WskServer_Stop`）时，统一步骤化释放常驻资源与内存，杜绝内核大池频繁震荡。

### 3. 常驻单通信引擎线程（零额外线程派生）
- 驱动全生命周期中，仅在 `WskServer_Init` 创建唯一一个系统线程 `WskServerThread`；
- 连接处理循环重构为单线程串行模式：
  ```c
  while (Server->fRunning) {
      // 1. 阻塞等待新客户端连接
      Status = WskSyncAccept(Server, Server->ListenSocket, &ClientSocket, ...);
      if (!NT_SUCCESS(Status)) continue;

      // 2. 绑定持久化上下文并直接在当前线程就地执行会话处理主循环
      WskProcessClientSession(pClient);

      // 3. 客户端断开后自动回到循环顶部，继续阻塞等待下一次 Accept
  }
  ```
- **反作弊免疫**：断线重连全过程零系统线程创建，彻底规避反作弊 `PsSetCreateThreadNotifyRoutine` 线程审计；
- **零锁化与零竞态**：网络 I/O 接收与 RPC 分发在同一线程内顺序调度，消灭了多线程自旋锁争用与跨核竞态。

---

## 三、 负向知识与避坑铁律 (Negative Knowledge)

1. **BugCheck 0x139 (Arg1=0x3 FAST_FAIL_CORRUPT_LIST_ENTRY)**：
   - 严禁在驱动网络断线重连等高频异构生命周期中使用裸 `LIST_ENTRY` 双向链表管理单实例或少实例会话；
   - Windows 8 及以上内核对 `LIST_ENTRY` 实施硬件级完整性自检（`int 29h`），任何弱同步保护的并发增删、未清零悬挂或自环指针均会引发不可拦截的蓝屏。
2. **反作弊针对系统线程的深度审计**：
   - 严禁在驱动接收到网络请求或客户端连接时动态调用 `PsCreateSystemThread`；必须采用常驻单线程架构或流水线批处理模型。
3. **大尺寸结构体的静态化与预分配**：
   - 超过 1MB 的缓冲结构体严禁在会话创建/销毁循环中高频申请释放；必须在驱动初始化阶段一次性预分配，并复用至模块完全卸载。
