# ADR-0161: 堆栈伪造调用宏直接接收目标函数指针

- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: 业务调用点原先需要先手动写入 `SPOOF_CALL_CONTEXT::TargetFunc`，再通过方案选择分支调用 Native 或 Ghost 汇编入口，容易出现目标函数指针与调用模式选择分离的问题。
- **技术决策与规范**: 新增 `VT_SHELLCODE_INVOKE_4(context, target, arg0, arg1, arg2, arg3)`；宏在同一表达式中把目标函数指针写入 `TargetFunc (+0x28)`，再依据 `VT_SHELLCODE_SPOOF_MODE` 与 `VT_SHELLCODE_DEEP_UNWIND` 选择现有四参数入口。Native 深层继续复用 `SpoofCallNativeInvoke`，Ghost 深层继续使用 `SpoofCallGhostDeepInvoke`，不新增汇编透传层。
- **已知约束与避坑**: 目标函数必须先完成非空和合法地址校验；宏固定支持当前 Windows x64 四参数调用契约，不接受变参；不得把目标指针当作第五个栈参数传入；Ghost 模式仍禁止静默回退 Native；`SPOOF_CALL_CONTEXT` 布局保持不变。
