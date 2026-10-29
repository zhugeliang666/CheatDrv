# ADR-0141: R3 Shellcode 方案1真实 call-reg Gadget 调用链

- **状态**: 部分被 ADR-0145 替代
- **日期**: 2026-10-30
- **上下文与痛点**: DebugShellcode 原先直接通过函数指针调用 `MessageBoxW`，返回地址落在 Shellcode 调用点；方案1需要在不新增 VT 退出点的前提下，保留 Windows x64 ABI 对齐并让目标函数经合法模块内的 `call rax; add rsp, 28h; ret` Gadget 返回。
- **技术决策与规范**: 初始化阶段只在已加载 PE 的可执行节内扫描 `FF D0 48 83 C4 28 C3` 与 `FF 23`，保存两个固定宽度地址；MASM 通过 `SpoofCallNativeInvoke` 整理 `MessageBoxW` 的四个寄存器参数，核心桩在当前线程原生栈上保存返回地址和 `rbx`，使用二级 Gadget 回到 Shellcode 修复点，再跳转至原调用方。
- **已知约束与避坑**: 仅支持当前四寄存器参数调用；Gadget 扫描必须受 PE `SizeOfImage` 与可执行节边界限制；上下文必须位于调用期间仍有效的原生线程栈；目标模块缺失 Gadget 时按 ADR-0145 使用嵌入 `.text` 的精确兜底，不得使用近似序列；不得把该 R3 调用链扩展为内核入口、堆栈切换或跨进程内存写入；修改后必须重建 Shellcode 并刷新 `Stealth/DebugShellcodeImage.h`。
