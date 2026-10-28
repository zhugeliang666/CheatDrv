# ADR-0085: FULL_UNLOAD 扩展内核栈与双视图卸载时序

- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: 两个驱动的 `.text` 双视图同时启用时，`loader --force` 通过 `MAPCTL_IOCTL_FULL_UNLOAD` 进入 `mapdriver_full_unload_runtime_locked`。WinDbg 现场为 `BugCheck 0x7F, Arg1=8`，栈回溯经过 `KiDoubleFaultAbort -> KiDebugServiceTrap -> DbgPrintEx -> VtBootstrapDriver`；本地映像对应卸载函数约 `0x21A0` 字节动态栈帧，并叠加多核 VMCALL、SEH 与日志临时对象，普通 IOCTL 栈在调试输出阶段耗尽。
- **技术决策与规范**: `mapdriver_full_unload_runtime` 只负责生命周期锁和参数门禁，使用 `KeExpandKernelStackAndCalloutEx` 提供 48 KiB 扩展栈，并通过 `noinline` callout 调用原卸载主体；当前 IRQL 高于 `APC_LEVEL` 或扩展栈申请失败时返回 `PAYLOAD_RESULT_INVALID_CONTEXT`，保持 Hypervisor、Payload、Machenike 与控制面存活，交由 Loader 重试。双视图删除、多核亲和性切换、VMCALL、DriverUnload 和日志全部在扩展栈阶段完成，之后才允许进入映像隔离与 PoolManager 处置。
- **已知约束与避坑**: 禁止为 FULL_UNLOAD 增加普通栈 inline fallback；禁止在扩展失败后继续释放映像或删除控制设备；禁止把 `DbgPrintEx` 最后可见帧当作首要故障指令。后续若增加卸载诊断结构，优先放入 scratch/nonpaged 缓冲区并保持每阶段独立栈帧；实机验证必须覆盖双驱动 `.text` 双视图、AMD/Intel、多核 VMCALL 和 `--force` 重试路径。
