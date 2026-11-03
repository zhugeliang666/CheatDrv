# ADR-0180: X2 中段挂钩的原生栈锚点与返回地址诊断修复
- **状态**: 已采纳
- **日期**: 2026-11-03
- **上下文与痛点**: x64dbg 已确认 X2 入口和 `CustomHookDispatch2` 均实际命中，但 `VT_SHELLCODE_DEEP_UNWIND=1` 时 `OriginalRsp` 被按 X1 入口的 `+0x180` 规则计算。X2 位于 WndProc 序言后的恢复地址，实测该锚点为 `0 mod 16` 且指向局部栈槽，`PrepareSpoofCallContext` 因此拒绝后续 `SpoofCall`，`DbgPrintW` 与 `MessageBoxW` 均无输出。
- **技术决策与规范**: `CustomHookDispatch2` 仅对 X2 副槽修正锚点：未写入时使用 `cpuCtx + 0x1C8`，已写入但为 `0 mod 16` 时增加 `0x48`，使锚点落到实际 WndProc 调用者返回槽并满足深层调用对齐；`RuntimeReleaseContext` 同步清零 `EntryReserved`。日志同时扫描私有 Dispatch 栈和 `OriginalRsp` 原生栈，原生栈最多输出 5 个已提交可执行返回地址。
- **已知约束与避坑**: `0x48` 是当前 Notepad WndProc X2 恢复点的已验证中段栈帧偏移，不得直接泛化到其他中段挂钩；新增挂钩点必须提供独立的入口栈偏移契约。修复后必须重新构建 DebugShellcode、刷新驱动嵌入镜像，并在新目标进程中复测日志、目标调用和返回栈。
