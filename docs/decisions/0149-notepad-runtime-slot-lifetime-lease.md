# ADR-0149: Notepad RuntimeSlot 轮询与清理的生命周期租约
- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: WinDbg KDNET 实时现场在 `ExpWorkerThread`、附加 `notepad.exe` 的上下文中连续捕获二次机会 `0xC0000005` 读异常。寄存器显示 `RSI=0x0000014585C40010`、访问地址为 `0x0000014585C40013`，而 `!pte 0x0000014585C40000` 返回 `not valid`；该地址正是 `s_NotepadShellcodeDataBase + 0x10` 的 RuntimeSlot::state。原实现先读取 state=2 和 dataBase，再允许清理路径将目标页释放，轮询随后使用失效地址读 4 字节，形成 use-after-free。
- **技术决策与规范**: `PollNotepadShellcodeState` 在读取目标进程 RuntimeSlot 前获取原子生命周期租约，并在 `VtReadProcessPrivate` 返回后释放租约；`CleanupNotepadNptTest` 先以 `2 -> 3` 原子切换阻止新租约，再等待已有租约归零，最后执行恢复 Hook、移除视图、释放目标页和解除进程引用。方案1保持默认开启；同时修正方案3汇编中 `JmpFrameSize` 的字段访问从 `[r10+40h]` 为真实 ABI 偏移 `[r10+48h]`。所有等待发生在 PASSIVE_LEVEL 维护/清理路径，数据页释放前不得存在活动租约。
- **已知约束与避坑**: 不得恢复“先快照指针、后直接读、并发释放”的旧顺序；不得在租约归零前调用 `VtEmbeddedFree`；`!analyze -v` 未形成正式 BugCheck 时，必须保留 `.exr`、寄存器、`!pte` 和线程附加上下文作为证据。当前候选已完成 DebugShellcode 与完整 Debug 驱动离线构建，驱动输出观察到 `Signature success!`；未执行本地加载或实机回归。
