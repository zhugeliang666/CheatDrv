# ADR-0143: 通用维护工作项与 Notepad RuntimeSlot 轮询解耦
- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: `VtEngine::PollNotepadShellcodeState` 原先复用 `SecurityWorkerRoutine`，导致 `ENABLE_SECURITY_MONITOR=0` 时状态失败路径完全不执行；同时该轮询与 ACE 安全扫描职责耦合，无法承载其他低频 PASSIVE_LEVEL 业务。
- **技术决策与规范**: 新增独立的 `GenericMaintenanceWorker` 定时器/DPC/系统工作项调度器；DPC 只负责投递，实际任务在 PASSIVE_LEVEL 的 `RunGenericMaintenanceTasks` 中串行执行。启动成功后先投递一次初始工作项，再由 2 秒周期定时器持续投递，避免首次状态结果依赖定时器/DPC时序。Notepad RuntimeSlot 轮询迁移到该分发点，后续低频维护任务继续在同一上下文扩展；不新增 `PsCreateSystemThread`，保持系统线程数量约束。
- **已知约束与避坑**: 卸载时必须先置停机标志、取消定时器、以 DPC 自旋锁建立屏障并排空已投递工作项，再执行 `VtEngine::Cleanup`；禁止在 DPC 或 VM-Exit 快路径执行轮询/Hook 清理；`RunGenericMaintenanceTasks` 仅运行 PASSIVE_LEVEL、可控耗时的维护任务；维护工作项必须输出进入、完成及轮询跳过原因，区分“调度未发生”和“轮询前置条件不满足”。`KeSetTimerEx` 的返回值是定时器旧信号状态，不能按 NTSTATUS 解释或以 `FALSE` 判定启动失败。
