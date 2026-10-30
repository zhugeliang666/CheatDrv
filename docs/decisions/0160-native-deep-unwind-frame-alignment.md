# ADR-0160: 方案1深层 Native Gadget 的 8 字节帧对齐修复

- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: CE 实测 Notepad 合法 `jmp [rbx]` Gadget 所在 `.pdata` 函数帧为 `0x1278`，入口原生 `RSP % 16 == 8`。旧门禁只接受 `JmpFrameSize % 16 == 0`，导致方案1+`VT_SHELLCODE_DEEP_UNWIND` 在调用 `MessageBoxW` 前失败关闭，`MessageShown` 回滚为 0，目标函数从未执行。
- **技术决策与规范**: Native 深层路径接受帧大小低四位为 `0` 或 `8`；汇编栈嫁接保留真实 `.pdata` 帧值，帧低位为 `0` 时额外减 `8` 字节，帧低位为 `8` 时不再重复减 `8`，使 Gadget 调用前 `RSP % 16 == 0`、目标函数入口 `RSP % 16 == 8`。RuntimeSlot 布局、Gadget 地址和 `JmpFrameSize` ABI 不变。
- **已知约束与避坑**: `OriginalRsp` 必须保持 `RSP % 16 == 8`；帧低位只允许 `0/8`，其余值继续失败关闭；禁止直接删除对齐门禁或把 `0x1278` 改写成伪造帧值；修改后必须重建 DebugShellcode、刷新 `Stealth/DebugShellcodeImage.h`，再重建并签名驱动。
