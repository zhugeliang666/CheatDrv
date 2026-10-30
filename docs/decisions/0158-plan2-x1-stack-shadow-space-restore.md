# ADR-0158: 方案2 X1 私有栈恢复与公共影子空间补偿
- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: x64dbg 现场确认方案2安装后执行流能够回到 `notepad.exe+0xA373`，但 X1 退出时主线程 `RSP` 比 `RuntimeSlot::OriginalRsp` 高 `0x20`，`ret` 从错误槽位取出 `0x5068E` 并跳入无效地址。根因是方案2私有栈路径已经恢复保存区指针，随后又落入公共 `add rsp, 20h`，重复消费 Windows x64 影子空间。
- **技术决策与规范**: `DebugShellcodeAsm.asm` 的 X1 私有栈分支将 `mov r12, rsp` 改为 `lea r12, [rsp-20h]`。调用结束后保留公共 `add rsp, 20h`，使其与私有栈调用前的影子空间补偿抵消，XMM保存区、非易失寄存器和被覆盖指令回放均从原始保存位置恢复。修改后必须重新构建 DebugShellcode、重新生成 `Stealth\DebugShellcodeImage.h`，再构建并签名驱动。
- **已知约束与避坑**: 该补偿只适用于 `X1UsePrivateStack` 路径；不得删除或重复增加 `X1UseOriginalStack` 的 `sub/add rsp,20h`。方案2的 `OriginalRsp` 必须保持 `rsp+178h` 的入口锚点，GhostRet 的 `.pdata` 帧大小仍由现有运行时校验提供。修改后需要用相同输入复核 BASELINE、MODIFIED、ROLLBACK，并确认恢复副本哈希等于基线。
