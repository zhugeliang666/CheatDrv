# ADR-0174: Shellcode Deep Unwind 返回路径栈帧恢复修复
- **状态**: 已采纳
- **日期**: 2026-11-01
- **上下文与痛点**: Native Gadget 深层模式在 X1/X2 私有栈中完成 `RuntimeDispatch` 后，返回路径直接执行 `mov rsp, r12` 再进入公共 `add rsp, 20h` 清理。这样会把恢复指针推进到保存帧基址 `+0x20`，导致 XMM、非易失寄存器和后续返回地址从错位位置读取并触发用户态崩溃。
- **技术决策与规范**: `X1PrivateStackReady` 和 `X2CopyFromPrivate` 在跳转 `X1DispatchDone/X2DispatchDone` 前统一执行 `mov rsp, r12; sub rsp, 20h`，使公共清理恰好恢复到保存帧基址。X1 的 `r12` 是私有保存帧基址，X2 的 `r12` 是已回写的原始保存帧基址；两者均保持既有寄存器恢复顺序和 Deep Native 调用 ABI 不变。
- **已知约束与避坑**: `sub rsp,20h` 必须只添加到私有栈调用返回后的两个分支，不能修改 `X1UseOriginalStack/X2UseOriginalStack` 的既有 `sub rsp,20h`；修改后必须重新装配 DebugShellcode、刷新嵌入镜像并重建签名驱动。静态验证通过不等于运行时回归通过，需在新目标进程中复测 Native Gadget + Deep Unwind 的返回路径。
