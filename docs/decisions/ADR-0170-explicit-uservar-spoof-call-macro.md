# ADR-0170: 恢复显式 UserVar 的 SpoofCall 调用宏
- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: 绑定作用域对象虽然可以隐藏 UserVar，但增加了 `SpoofCallScope`、绑定函数对象和额外的调用语法；当前 Shellcode 调用点更需要显式、可审计且接近普通函数的调用形式。
- **技术决策与规范**: 保留通用 `SpoofCall(userVar, target, ...)` 变参模板；删除 `BoundSpoofFunction`、`SpoofCallScope` 及其绑定宏；使用无运行时包装层的函数式宏 `SpoofMessageBoxW(userVar, hWnd, text, caption, type)`，直接展开到 `userVar->Func->MessageBoxW` 与 `SpoofCall`。
- **已知约束与避坑**: `userVar` 必须是有效的 `PGENERIC_RUNTIME_CONTEXT` 左值或无副作用表达式；宏只负责调用语法，不改变 `SpoofCall` 的 `SpoofContextBusy`、模式校验和临时现场清理；通用游戏函数继续使用 `VT_SPOOF_CALL(userVar, target, ...)`；修改后必须重新嵌入 Shellcode 并重新构建、签名驱动。
