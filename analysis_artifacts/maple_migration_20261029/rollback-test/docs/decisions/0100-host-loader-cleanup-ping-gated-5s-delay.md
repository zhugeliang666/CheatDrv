# ADR-0100: 宿主加载器(HostLoader)仅在 Ping 成功后延迟 5 秒粉碎规范

- **状态**: 已采纳
- **日期**: 2026-10-28
- **核心领域**: 痕迹清理 / 跨环契约 / 生命周期治理

---

## 上下文与痛点

1. **提前粉碎导致调试与状态回读截断**：
   - 原 `DriverCore.cpp` 在手动映射入口（`DriverEntry_ManualMap`）末尾直接调用了 `ScheduleDeleteHostLoader`，导致只要置位了清理标志，驱动刚映射完成就直接发起异步工作项粉碎 Loader 文件并强杀进程。
   - 这会导致客户端尚未完成 TCP/UDP/USB 网络链路探测、未收到第一帧握手 Ping 应答前，宿主进程便被强制终止，且文件丢失，阻断故障诊断与正常交互。
2. **非 Ping 业务指令误触触发**：
   - 原 `RpcDispatcher.cpp` 在处理所有指令解密后均无差别调用 `TriggerPendingHostLoaderCleanup()`，缺乏对指令类型的严格过滤。

---

## 技术决策与规范

1. **废除 ManualMap 阶段盲删，收敛至 Pending 状态**：
   - 在 `DriverCore.cpp` 的 `DriverEntry_ManualMap` 中，删除直接调用 `ScheduleDeleteHostLoader` 的逻辑，改为调用 `DriverCore::SetPendingHostLoaderCleanup(pBootConfigEx->HostLoaderPath, callerPid)`，仅暂存清理上下文。
2. **Ping 成功后严格单次触发**：
   - 移除 `RpcDispatcher.cpp` 解密后的全局触发点，仅在 `pHdr->tpMsg == LEECHRPC_MSGTYPE_PING_REQ || pHdr->tpMsg == LEECHRPC_MSGTYPE_KEEPALIVE_REQ` 且 `MkRpc_HandleHeartbeat` 处理成功（返回 `STATUS_SUCCESS`）时，才调用 `DriverCore::TriggerPendingHostLoaderCleanup()`。
3. **工作项例程前置安全延时 5 秒**：
   - 在 `AsyncDeleteHostLoaderWorkRoutine` 入口处，通过 `KeDelayExecutionThread(KernelMode, FALSE, &preDelay)`（`preDelay = -50000000LL`）前置休眠等待 5 秒，待客户端与宿主完成所有握手响应与资源完全解绑后，再执行进程终止与文件强制粉碎。

---

## 已知约束与避坑

1. **线程上下文契约**：延时必须在系统工作线程 `PASSIVE_LEVEL` 执行，严禁在 RPC 派遣主线程或自旋锁临界区休眠。
2. **原子防重入**：`s_CleanupTriggered` 必须维持 CAS 原子状态翻转，确保多次 Ping 仅触发一次清理工作项。
