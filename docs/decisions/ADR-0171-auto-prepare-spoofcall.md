# ADR-0171: SpoofCall 自动准备运行时上下文
- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: 业务调用点虽然已经通过 `SpoofMessageBoxW(userVar, ...)` 或 `VT_SPOOF_CALL(userVar, target, ...)` 隐藏了汇编细节，但仍需在每次调用前显式传递 `RuntimeSlot` 并调用 `PrepareSpoofCallContext`，容易遗漏准备步骤，也无法保持统一的失败返回语义。
- **技术决策与规范**: 在 `GENERIC_RUNTIME_CONTEXT` 增加 `SpoofSlot`，由 `RuntimeInitDispatch` 将当前 `RuntimeSlot` 绑定到 `UserVar`；`SpoofCall` 获取 `SpoofContextBusy` 后自动调用单参数 `PrepareSpoofCallContext(userVar)`，准备失败释放 Busy 并返回类型安全的零值；`RuntimeMessageBoxDispatch` 只保留消息编排并通过现有宏调用。
- **已知约束与避坑**: `SpoofSlot` 必须在所属 Slot 生命周期内有效，释放上下文前原子清空；当前一对一 `UserVar/RuntimeSlot` 绑定不允许多个 Slot 并发复用同一 UserVar，未来多挂钩必须改为每槽独立上下文或恢复显式 Slot 参数；`GENERIC_RUNTIME_CONTEXT` 布局变化后必须重新嵌入 Shellcode、构建并签名驱动。
