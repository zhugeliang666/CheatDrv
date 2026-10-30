# ADR-0157: 异常上报组件卸载排空屏障与彻底根除 WSK 完成例程 UAF 引发的 BugCheck 0xD1

- **状态**: 已采纳
- **日期**: 2026-10-31
- **核心领域**: 系统级负向知识 / 蓝屏踩坑闭环 / 跨环网络通信 / 生命周期治理 / 线程安全

---

## 上下文与痛点

1. **BugCheck 0xD1 现场根因**：
   - 故障转储 `103126-5000-01.dmp` 记录系统崩溃为 `0xD1` (`DRIVER_IRQL_NOT_LESS_OR_EQUAL`)：
     - `Arg1` = `0xFFFFF806D6CE52E6`（访问内存地址）
     - `Arg2` = `0x00000002`（`IRQL = DISPATCH_LEVEL`）
     - `Arg3` = `0x00000008`（操作类型：取指执行违例）
     - `Arg4` = `0xFFFFF806D6CE52E6`（指令指针）
   - 系统未加载模块列表（`Unloaded modules`）显示 `mswsk.sys` 基址位于 `0xFFFFF806D6CB0000`，偏移 `+0x352E6` 经 `mswsk_llvm.map` 符号反查精确对齐 `ExceptionReporter.cpp` 中的静态完成例程 `SyncCompletion`。
   - 现场栈回溯表明系统进程 `System` (`PID=4`) 中 `tcpip.sys` / `afd!WskProTLConnectComplete` 触发 `IofCompleteRequest` $\rightarrow$ `nt!IopfCompleteRequest` 回调已卸载驱动的 `Stack->CompletionRoutine`。
   - 根本诱因：驱动在 `DriverEntry` 启动失败（如 `Transport server failed to start`、`IoCreateDevice failed` 等）或 SCM 触发正常卸载时，`ExceptionReporter::Report` 将上报任务异步提交给 `DelayedWorkQueue`。而在 `DriverCore::DriverUnload` 中**完全缺乏对 `ExceptionReporter` 的排空与等待机制**，导致驱动镜像被系统立即卸载并释放物理页；随后后台 WSK 异步套接字连接（`WskConnect`）在 DPC 级别完成时，`IopfCompleteRequest` 跳转至已释放的代码段，因高 IRQL 缺页无法换入直接触发 0xD1 蓝屏停机。

---

## 技术决策与规范

1. **引入生命周期关闭闸门与活动在途计数器**：
   - 在 `ExceptionReporter.cpp` 中定义全局原子状态：
     - `s_ReporterClosing`：原子关闭闸门标志。在驱动开始卸载或执行清理时置 1，所有后续 `Report`、`ReportFormat` 与 `QueueReportWorkItemInternal` 调用立即静默短路阻断，严禁在卸载期向系统队列投递新任务。
     - `s_ActiveReportsCount`：记录当前正在工作队列中排队或正在执行网络 I/O 的任务总数。在 `ExQueueWorkItem` 前原子递增，在 `AsyncWorkRoutine` 彻底退出并释放 `pItem` 前原子递减。
2. **显式实现 `ExceptionReporter::Cleanup` 排空屏障**：
   - 首部立即置位 `s_ReporterClosing = 1`；
   - 清空 `s_EarlyStageTable` 冷启动暂存槽位，阻止卸载后滞后冲刷；
   - 循环轮询 `s_ActiveReportsCount == 0`，配合 `KeDelayExecutionThread(50ms)`，最大等待 5000ms（覆盖 WSK Connect 的 3000ms 内部超时），确保后台系统工作线程彻底退出并完成 `ret` 返回；
   - 追加 20ms 流水线排空屏障（`drainDelay`），随后将 `s_pUserVar` 安全置空。
3. **在 `DriverCore::DriverUnload` 首部前置挂接排空**：
   - 在 `DriverCore::DriverUnload` 最前沿，先于停止传输服务、RPC 与 VT 引擎，强制调用 `ExceptionReporter::Cleanup(UserVar)`，确保代码镜像释放前 100% 消除所有指向本驱动 `.text` 段的未决 WSK IRP 完成例程。
4. **C/C++ 混编桥接兼容**：
   - 在 `ExceptionReporter.h` 暴露 `extern "C" void ExceptionReporter_Cleanup(MACHENIKE_KERNEL_INTERFACE *UserVar);`，满足驱动纯 C 模块直接调用的规范。

---

## 已知约束与避坑

1. **严禁在未排空异步 IRP 时卸载驱动**：任何涉及向系统底层驱动（如 AFD、TCPIP、USBHUB）传递本模块内部完成例程（`CompletionRoutine`）的异步 IRP，卸载前必须通过同步事件确保 IRP 彻底被唤醒回收，严禁遗留悬空回调地址。
2. **错误自愈与卸载顺序**：在 `DriverEntry` 失败降级分支中调用 `ExceptionReporter::Report` 后，若立即调用 `DriverCore::DriverUnload`，必须依赖 `ExceptionReporter::Cleanup` 保证该报错完整送出或被安全取消排空，不得粗暴直接 `return` 导致模块被瞬时抹除。
3. **卸载闸门必须前置**：必须在执行任何等待之前立即置位 `s_ReporterClosing = 1`，防止后续清理逻辑（如 `TransportManager::StopServer`）在反初始化报错时产生重入竞争。
