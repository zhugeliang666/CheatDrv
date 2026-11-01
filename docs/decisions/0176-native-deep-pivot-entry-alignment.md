# ADR-0176: Native Deep 目标入口栈对齐修复
- **状态**: 已采纳
- **日期**: 2026-11-01
- **上下文与痛点**: x64dbg 实测 Native Deep 调用 `MessageBoxW` 时，`OriginalRsp=0xFDB319F778`、`JmpFrameSize=0x1278`，目标入口 `RSP=0xFDB319E4C0`，其低四位为 `0`，随后目标链触发 `0xC0000409` / `int 29`。原因是深层 Pivot 路径落入当前栈路径的共享 `sub rsp, 8`，额外消耗了一个 8 字节相位。
- **技术决策与规范**: `SpoofNativePivotReady` 与 `SpoofNativeFramePivotReady` 写入 Pivot 栈后分别直接跳到共享压栈准备标签；仅 `SpoofNativeUseCurrentStack` 与 `SpoofNativeFrameUseCurrentStack` 执行 `sub rsp, 8`。以 `OriginalRsp - JmpFrameSize` 为基准时，Native Deep 及 Native Frame Deep 目标入口均恢复为 `RSP % 16 == 8`，`JmpQwordPtrRbx` 的 `.pdata` 帧展开后仍落回 `OriginalRsp`。
- **已知约束与避坑**: 该补偿不能再次加到 Native Deep 或 Native Frame Deep 路径；`OriginalRsp % 16` 必须为 8，`JmpFrameSize` 低位只允许 0/8。汇编变更后必须重新生成 `DebugShellcodeImage.h`、重建并签名驱动；静态验证不能替代新驱动/新 Notepad 的 x64dbg 实测。
