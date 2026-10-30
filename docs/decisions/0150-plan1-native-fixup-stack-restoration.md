# ADR-0150: 方案1恢复合法 Gadget 原生栈收敛路径
- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: 参考提交 `af540e649666bf4c76c150b598395424584dafb0` 的方案1可正常运行；后续方案3引入的 X1 原生栈记录和 `SpoofNativeFixup` 无条件恢复逻辑会改变方案1原有的 Gadget 返回栈状态，Notepad Hook 触发后可能崩溃。
- **技术决策与规范**: 方案1保留原有 `SpoofCallNativeAsm` 的 Gadget 返回栈；仅当 `RuntimeSlot::SpoofPlan == 3` 时记录 `OriginalRsp`，并仅当 `SPOOF_CALL_CONTEXT::OriginalRsp` 非零时在 `SpoofNativeFixup` 恢复私有栈。方案1的 `X1` 不写入 `RuntimeSlot::OriginalRsp`。方案2/3的入口与上下文字段继续保留，使用独立运行时分支。
- **已知约束与避坑**: `RuntimeSlot::state` 仍为 `+0x10`，`SpoofPlan` 为 `+0x34`；任何修改必须同步重新生成 `Stealth/DebugShellcodeImage.h`。不要让方案1执行方案3的 RSP 恢复；不要使用旧嵌入镜像覆盖当前源码生成的镜像。该修复已完成 Debug|x64 完整构建及签名，尚未在目标机重新加载后完成实机回归。
