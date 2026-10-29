# ADR-0135: Notepad Hook 被覆盖指令回放跳板
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: 原 X1 入口执行 RuntimeDispatch 后直接跳到 `HookVa + HookPatchSize`，跳过了被覆盖的函数序言；WndProc 的栈帧建立指令未执行，Hook 首次触发即可能破坏栈并崩溃。
- **技术决策与规范**: Shellcode `.text` 增加固定标记槽位；安装前读取目标入口的完整指令边界，将被覆盖字节复制到槽位，并在槽位末尾写入 `mov rax, ResumeVa; jmp rax`。X1 在 RuntimeDispatch 返回后进入该槽位，先回放原始指令再跳到继续地址。
- **已知约束与避坑**: 仅复制完整指令边界；当前 Notepad 调试入口要求回放区域不含需重定位的 RIP-relative/相对分支指令；槽位容量与写入长度必须校验，失败时不安装 Hook。
