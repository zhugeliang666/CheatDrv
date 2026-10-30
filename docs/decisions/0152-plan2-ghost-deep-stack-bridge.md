# ADR-0152: 方案2 GhostRet 原生栈嫁接与深层展开闭合

- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: 方案2已通过硬编码 `notepad.exe` GhostRet RVA `image + 0x28D3` 验证，但基础 `push GhostRetVa; jmp TargetFunc` 仍会把 Shellcode/RuntimeDispatch 的调用链留在原生线程栈上，深层 `.pdata` 展开或原始栈扫描仍可见。
- **技术决策与规范**: 保留 `VT_SHELLCODE_PLAN2_GHOST_RET_RVA` 硬编码配置；驱动从目标映像 `.pdata` 读取 GhostRet 所在 `RUNTIME_FUNCTION` 的 `UNWIND_INFO`，计算 `GhostFrameSize`，要求不小于 `0x28` 且低四位为 `8`。方案2升级时，X1 保存 `OriginalRsp` 并切换数据页私有栈；Ghost 调用桩将目标调用期间的 `RSP` 设置为 `OriginalRsp - GhostFrameSize - 8`，在该位置写入 GhostRetVa，目标函数返回后由影子执行视图中的 `FF 23` 跳回修复桩，随后恢复私有栈和非易失寄存器。
- **已知约束与避坑**: `GhostRetVa` 必须位于合法模块冷分支真实 `E8/FF 15` call 的下一条指令且 `FF 23` 不得跨页；NPT 读取 PE 头、节表和 `.pdata` 前必须在目标进程上下文预取对应页面，否则未驻留的只读页可能导致 CR3 直读短读并误报 PE/GhostFrame 查询失败；必须先完成 `.pdata`、栈范围和 `RSP % 16` 校验，失败关闭不得回退方案1；卸载必须先移除 Ghost 双视图再释放运行时页。硬件 USER_CET 开启时，`push + jmp` 路径仍需单独验证影子栈策略。
