# ADR-0169: 绑定作用域的通用 SpoofCall 函数对象

- **状态**: 被 ADR-0170 替代
- **日期**: 2026-10-31
- **上下文与痛点**: 业务调用既需要支持 `MessageBoxW`，也需要支持预先解析的游戏函数指针；调用点不应重复传递 `SPOOF_CALL_CONTEXT` 或 `UserVar`，同时不能使用跨线程共享的全局当前上下文。
- **技术决策与规范**: `VT_SPOOF_SCOPE(userVar)` 在当前调用作用域创建 `SpoofCallScope`，并绑定 `SpoofMessageBoxW`；`VT_SPOOF_BIND_FUNCTION(name, target)` 将任意已声明函数指针绑定为可调用对象。绑定对象内部仍统一进入现有 C++14 变参 `SpoofCall` 模板。初始化阶段写入固定 Native Gadget 配置；`FixupRip`、`SavedRbx`、`SavedRetAddr`、`TargetFunc`、`ArgumentFrame` 等保持为单次调用临时字段，由汇编入口写入、返回后清理。
- **已知约束与避坑**: 禁止使用全局或跨线程 TLS 当前 `UserVar`；绑定对象只在对应 `UserVar` 生命周期内有效；`SPOOF_CALL_CONTEXT` 汇编偏移不得改变；结构体/大型聚合体按值传递仍不在当前标量 ABI 支持范围内；Ghost/Deep 的动态栈字段必须在目标调用前完成有效性校验。
