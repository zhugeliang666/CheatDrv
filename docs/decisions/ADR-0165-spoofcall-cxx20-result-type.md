# ADR-0165: SpoofCall 返回类型推导兼容 C++20
- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: `DebugShellcode.vcxproj` 的 Debug/Release C++ 配置包含 C++17/C++20，而 `std::result_of` 在 C++20 中不可用，导致变参 `SpoofCall` 的尾置返回类型被解析为一串级联语法错误。
- **技术决策与规范**: 使用 `decltype(std::declval<TTarget>()(std::declval<TArgs>()...))` 推导目标调用返回类型；该表达式同时兼容项目的 C++14 模板测试和 C++20 MSVC 构建，不改变 `SPOOF_CALL_FRAME`、汇编入口或调用 ABI。
- **已知约束与避坑**: 不再使用 `std::result_of`；目标仍必须是可调用函数指针，返回值类型继续受 `SpoofCallResultCast` 支持集合限制。修复后必须重新生成嵌入 Shellcode 并重新构建、签名驱动。
