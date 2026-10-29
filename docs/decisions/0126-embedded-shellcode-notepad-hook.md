# ADR-0126: Notepad 调试用 Shellcode.exe 内嵌与直接 Hook
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: `VT_DEBUG_NOTEPAD_NPT_TEST` 需要在不依赖本地文件加载的条件下验证 AMD NPT/Intel EPT 的双视图、R3 Shellcode 入口和 Hook 路径。原测试只对目标映像页安装观测视图，无法验证 Shellcode 映像、运行时初始化和直接跳转 Hook 的完整链路。
- **技术决策与规范**: 将 `bin/DebugShellcode/Debug/shellcode.exe` 转换为 `Stealth/DebugShellcodeImage.h` 的只读静态 PE 字节数组并编译进 Machenike 驱动；`RunNotepadNptTest` 通过动态解析的 `ZwAllocateVirtualMemory`、`KeStackAttachProcess` 与 `KeUnstackDetachProcess` 在目标进程中分配代码页和数据页，按原始 RVA 复制 `.text/.rdata/.data/.xinit`，由 `RuntimeSlot`/`RuntimeMessageBoxInput` 写入调试消息数据，并补丁化 ASM 的 Slot/Dispatch immediate；对 `.text/.xinit` 全页安装执行影子/读取零页视图，构造 `mov rcx, slot; mov rax, ShellcodeEntryVa; jmp rax` 的 24 字节入口跳转，再调用现有 EH Hook 原语。清理顺序先恢复入口影子页，再移除 Hook、双视图、目标进程代码/数据页和进程引用。新增四个动态内核函数指针及对应哈希，保持 `FunctionArray` 与 `MACHENIKE_PFN` 顺序一致。
- **已知约束与避坑**: 仅在 `VT_DEBUG_NOTEPAD_NPT_TEST` 调试路径编译和调用，不在本地加载驱动测试；代码页当前使用调试用 `PAGE_EXECUTE_READWRITE`，生产路径不复用；目标入口补丁必须位于单页剩余空间内，Hook 恢复必须在 `EhRemove` 前完成；Shellcode 数据页不安装读取零页视图；嵌入镜像更新后必须重新生成头文件并与驱动同批构建。
