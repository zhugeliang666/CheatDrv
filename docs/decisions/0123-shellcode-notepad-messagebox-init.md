# ADR-0123: DebugShellcode Notepad 消息框初始化与动态解析
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: 现有 DebugShellcode 只完成 DeltaForceDecrypt 风格的 UserVar 初始化，Notepad 测试需要由初始化参数传入正文和标题，并在目标进程上下文中调用 USER32 的 MessageBoxW；同时必须保持现有 X1 保存/恢复现场、双视图和旧函数表 ABI。
- **技术决策与规范**: 在 `DELTAFORCE_PFN` 表尾追加 `MessageBoxW`，使用 `str_MessageBoxW` 哈希和 PEB/Ldr 导出解析；新增 `XUserVarMessageBoxInput`，由 `XUserVarSlot::input` 传入目标进程地址、字符数和按钮类型；`XInternalDecrypt` 首次调用时完成初始化和消息文本拷贝，`XMessageBoxDispatch` 独立负责一次性弹框；ASM X1 增加第三个 imm64 槽位，补丁器通过 `PatchXMessageBox` 写入复制后的 dispatch 地址。消息正文、标题、UserVar 和函数表保持普通可读页，只有 shellcode `.text` 进入执行影子页/读取零页双视图。
- **已知约束与避坑**: `MessageText` 最多 4096 个宽字符，标题最多 512 个宽字符；输入结构体的指针必须是目标进程地址；不在 VM-Exit 快路径中直接调用 USER32；调用遵循 x64 32 字节 shadow space 和 16 字节栈对齐；`MessageShown` 使用原子门控防止重复弹框；Notepad 模式通过 `wstr_notepad_exe` 识别宿主模块；卸载前必须等待消息框返回并按 Hook、双视图、UserVar 的逆序清理。
