# ADR-0103: 规避工作项未排空导致 BugCheck 0xCE 的原子中止与卸载同步规范

- **状态**: 已采纳
- **日期**: 2026-10-28
- **核心领域**: 系统级负向知识 / 蓝屏踩坑闭环 / 生命周期治理 / 线程安全

---

## 上下文与痛点

1. **BugCheck 0xCE 现场根因**：
   - 故障转储 `102826-40453-01.dmp` 记录系统崩溃为 `0xCE` (`DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS`)，Arg1/Arg3 指向 `<Unloaded_mswsk.sys>+0x1548`，Arg2 为 `0x10`（执行/取指违例）。
   - 现场栈分析表明系统后台工作线程（`nt!ExpWorkerThread`）正在执行 `AsyncDeleteHostLoaderWorkRoutine` 中的 `KeDelayExecutionThread`（5 秒延时或 1 秒重试休眠）。
   - 当上层服务或 SCM 触发驱动卸载（`DriverUnload`）时，原卸载函数仅针对 ACE 与 MapleWorker 进行了排空，未对自删除工作项进行任何中止通知或等待，驱动内存镜像（`.text` 段）随之被系统释放。
   - 随后系统工作线程从休眠中唤醒并尝试返回至驱动已释放的代码地址继续执行，直接引发取指违例 `#PF`，内核判决为 0xCE 蓝屏停机。

---

## 技术决策与规范

1. **分片休眠与即时响应 (Sliced Sleep with Abort Checking)**：
   - 废除单次无界 `KeDelayExecutionThread(5s)`，在 `AsyncDeleteHostLoaderWorkRoutine` 内部改为 50ms 片段化循环休眠（`100 * 50ms = 5000ms`）。
   - 每一轮循环首部均通过原子操作检测全局中止信号 `s_DeleteLoaderAbort`，一旦检测到驱动正在卸载，立即短路跳出并执行清理退出。
2. **重试循环全路径 Abort 检测**：
   - 在等待进程退出的 `maxProcessWaitRounds` 循环以及自删除重试的 `maxRetries` 循环中，全部注入 `s_DeleteLoaderAbort` 快速短路判定。
3. **工作项生命周期状态标记**：
   - 引入 `s_DeleteLoaderRunning` 与 `s_DeleteLoaderAbort` 原子标志：
     - 工作项入口显式置位 `s_DeleteLoaderRunning = 1`；
     - 工作项无论是正常完成还是中止退出（`CleanupAndExit`），在安全释放上下文内存后置位 `s_DeleteLoaderRunning = 0`。
4. **DriverUnload 阶段双重排空屏障**：
   - 在 `DriverCore::DriverUnload` 例程中，首部立即向工作项发送中止广播：`InterlockedExchange(&s_DeleteLoaderAbort, 1)`；
   - 在原有的 ACE 与 MapleWorker 排空循环中，同步加入对 `s_DeleteLoaderRunning == 0` 的 CAS 自旋等待；
   - 工作项清零后保留 20ms 的 CPU 流水线排空屏障（`drainDelay`），确保工作线程彻底完成 `ret` 指令离开驱动代码页后，才继续释放驱动内存。
5. **手动映射生命周期门禁与入队状态**：
   - 增加 `s_DeleteLoaderQueued`，在 `ExQueueWorkItem` 前后维护入队状态，卸载条件同时要求 `queued == 0` 与 `running == 0`。
   - 增加 `s_ManualMapMode`；手动映射模式不再由即将释放的 `mswsk.sys` 自身排队 HostLoader 删除回调，避免 `ExpWorkerThread` 在映像释放后取旧回调地址。
   - 工作项分配失败、函数表缺失和重复触发路径均复位入队状态并释放上下文，避免状态永久卡死。
6. **卸载入队关闭闸门与上下文日志顺序**：
   - 增加 `s_DeleteLoaderClosing`；`DriverUnload` 首先关闭入队闸门并清空 Pending 路径，`ScheduleDeleteHostLoader`、`SetPendingHostLoaderCleanup` 与 `TriggerPendingHostLoaderCleanup` 在每个竞态窗口重新校验该状态。
   - `ExQueueWorkItem` 前完成日志记录，禁止队列提交后继续读取可能已被工作线程释放的 `DELETE_LOADER_WORK_CONTEXT`，消除日志路径自身的 UAF。

---

## 已知约束与避坑

1. **严禁在未排空时释放代码页**：驱动内部任何在系统工作线程（`ExpWorkerThread`）中运行的例程，其宿主模块在卸载前必须通过同步原语或原子等待确保执行流已彻底离开该模块。
2. **长延时切忌单次阻塞**：内核工作项内的任何秒级延时，必须拆解为毫秒级（<=50ms）分片判定，防止阻塞系统 SCM 卸载超时或引发关机蓝屏挂起。
3. **手动映射清理回调归属**：手动映射映像释放前不得保留指向自身 `.text` 的系统工作项；清理动作必须由常驻模块承载，或在映像仍驻留期间完成同步排空。
4. **卸载关闭顺序**：必须先关闭所有新入队路径，再发送中止信号和排空已有工作项；仅轮询 `queued/running` 而不关闭入队会留下最后一次检查后的重入窗口。
