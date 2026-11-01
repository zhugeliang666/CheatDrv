# ADR-0173: Shellcode Native 当前栈路径 ABI 对齐修复
- **状态**: 已采纳
- **日期**: 2026-11-01
- **上下文与痛点**: x64dbg 在方案1（`mode=1 flags=0`）进入 `MessageBoxW` 时观察到目标入口 `RSP % 16 == 0`，随后在 user32 的 `movaps [rsp+30h], xmm0` 处触发异常。根因是当前栈路径在压入合法返回 Gadget 后只执行 `sub rsp, 28h`，未补偿当前入口栈的 8 字节相位。
- **技术决策与规范**: `SpoofNativeUseCurrentStack` 与 `SpoofNativeFrameUseCurrentStack` 在压入 Gadget 前额外 `sub rsp, 8`；对应 Fixup 仅在 `OriginalRsp == 0` 的当前栈路径执行 `add rsp, 8`，深层私有栈路径不执行该恢复。Native Gadget 的 `add rsp, 28h; ret`、`JmpRbxGadget`、RuntimeSlot 布局和 Deep Pivot 路径保持不变。目标函数入口恢复为 Windows x64 ABI 所需的 `RSP % 16 == 8`。
- **已知约束与避坑**: 该补偿只适用于当前栈分支，不能叠加到已按 `OriginalRsp/JmpFrameSize` 计算过的深层 Pivot；修改后必须重新装配 shellcode、更新嵌入镜像并重新构建驱动。静态验证不能替代目标进程实测，后续必须在新进程中确认 `MessageBoxW` 入口对齐且不再命中 `movaps` 异常。驱动构建仍需保留签名后置步骤。
