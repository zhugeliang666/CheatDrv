# ADR-0166: SpoofCall 便捷调用宏
- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: 业务调用点直接展开函数指针、上下文和参数时可读性较差；需要在不增加运行时包装层的前提下提供类似普通函数调用的入口。
- **技术决策与规范**: 新增 `VT_SPOOF_CALL(context, target, ...)` 通用表达式宏和 `SpoofMessageBoxW(context, userVar, hWnd, text, caption, type)` 类型化宏；宏只展开到现有 `SpoofCall` 变参模板，方案选择仍由模板内的编译期开关完成。
- **已知约束与避坑**: 不重定义系统 `MessageBoxW`，不引入纯透传运行时函数；宏参数必须是无副作用或只求值一次的表达式，目标函数指针从 `userVar->Func->MessageBoxW` 绑定。宏仅改善调用语法，不代表已完成目标进程实机回归。
