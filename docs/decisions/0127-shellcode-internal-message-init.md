# ADR-0127: Shellcode 内部完成调试消息初始化
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: `RunNotepadNptTest` 原先在驱动侧申请输入、正文和标题区域，并逐段复制到目标进程；这增加了外层数据页写入、ABI 结构体和生命周期分支，而初始化逻辑本来已经位于 Shellcode 的 `RuntimeInitWithInput`。
- **技术决策与规范**: `RuntimeInitWithInput` 使用栈数组并通过逐字符数值写入构造固定调试正文和标题，不在源代码或最终 PE 中保留这两段 UTF-16 字符串字面量；随后通过 Shellcode 内动态解析的 `malloc/memcpy` 复制到运行时堆，设置字符数、消息框类型和显示状态，并继续动态解析 `USER32!MessageBoxW`。`RuntimeInitDispatch` 忽略 `RuntimeSlot::input`，只使用目标进程中由 `ZwAllocateVirtualMemory` 清零得到的 Slot 页；驱动侧仅分配 Slot 页、复制代码节、补丁化 Slot/Dispatch 地址和安装 Hook，不再写入 `RuntimeMessageBoxInput`、正文或标题缓冲区。Shellcode 工程 x64 配置统一使用 `/MERGE:.data=.xconst /MERGE:.rdata=.xconst /SECTION:.xconst,R`，最终 PE 不含 `.data` 与 `.rdata` 节，驱动复制 `.xconst` 但不对其安装双视图。保留 `RuntimeSlot` 的双指针布局以维持 X1 ABI。
- **已知约束与避坑**: Shellcode `.rdata` 必须随原始 RVA 一并复制且保持可读；Slot 页必须保持 `PAGE_READWRITE` 并依赖提交页的零初始化；消息内容变更必须重新构建 Shellcode、重新生成 `DebugShellcodeImage.h` 并重建驱动；生产路径不调用该调试初始化分支。
