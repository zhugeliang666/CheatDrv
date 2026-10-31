# ADR-0162: 统一堆栈伪造一键调用宏命名为 `SpoofCall`

- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: `VT_SHELLCODE_INVOKE_4` 已能直接接收目标函数指针，但名称过度暴露具体参数数量和编译配置，业务调用点不够简洁。
- **技术决策与规范**: 将公开调用宏重命名为 `SpoofCall(context, target, arg0, arg1, arg2, arg3)`，内部选择器改为 `SpoofCallSelected4`；宏仍写入 `TargetFunc (+0x28)`，并继续由 `VT_SHELLCODE_SPOOF_MODE` 与 `VT_SHELLCODE_DEEP_UNWIND` 选择现有汇编入口。
- **已知约束与避坑**: `SpoofCall` 仍固定为四参数 ABI；不得新增变参透传；目标指针必须先校验；不得改变 `SPOOF_CALL_CONTEXT`、RuntimeSlot 或汇编入口符号；不保留旧宏别名，避免双重接口漂移。
