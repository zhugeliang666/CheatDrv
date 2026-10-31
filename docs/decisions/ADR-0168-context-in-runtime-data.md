# ADR-0168: 将 SpoofCall 上下文绑定到 UserVar 运行时数据
- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: 业务调用点需要同时维护独立的 `SPOOF_CALL_CONTEXT*` 和 `UserVar`，容易遗漏模式字段初始化；希望便捷宏只接收 `UserVar`，统一使用其运行时数据中的上下文。
- **技术决策与规范**: 将保持既有字段偏移的 `vt_debug_shellcode::SPOOF_CALL_CONTEXT` 放入 `GENERIC_RUNTIME_DATA::SpoofContext`，新增 `SpoofContextBusy` 原子占用标志；`SpoofCall(userVar, target, ...)` 自动取得上下文，调用结束后清理上下文并释放占用，`SpoofMessageBoxW` 只接收 `userVar`。
- **已知约束与避坑**: 上下文是共享状态，禁止并发复用；`PrepareSpoofCallContext(userVar, slot)` 在每次实际调用前清零并设置 Native/Ghost/Deep 模式字段；`RuntimeMessageBoxDispatch` 只负责调用该集中准备函数，`SpoofCall` 不得在模式字段设置前清零；`SPOOF_CALL_CONTEXT` 汇编偏移必须保持不变。结构体布局变化后必须重新嵌入 Shellcode 并重新构建、签名驱动。
