# ADR-0117: R3 Hook 与 shellcode 的 EPT 双视图接口
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: R3 Hook 页和 R3 shellcode 页需要保持原始读取不可见，同时让取指使用独立影子页；原 EH 接口只有两态布尔参数，无法表达“读取零页”。
- **技术决策与规范**: 将既有单字节 `is_fake_page` ABI 槽位解释为 `view_mode`：0=执行影子/读原页，1=执行原页/读影子页，2=执行影子/读零页。双视图流程拆成 `InstallShellcodeDualView(Process, ShellcodeEntryVa)`、`InstallHookToShellcodeEntry(Process, HookVa, ShellcodeEntryVa, HookPatchSize)`、`RemoveHookToShellcode` 和 `RemoveShellcodeDualView`；旧的合并重载保留为兼容入口。Intel EPT 使用独立 R/W/X 权限；AMD NPT 模式 2 使用普通 NPT 根的 dummy PFN+NX 读视图，在取指 NPF 后切换 `N_CR3` 到执行影子根，离开页面时恢复普通根。独立 `DebugShellcode` 静态库提供无 CRT 的可复制 `X1` ASM 入口和项目专用 `XUserVarInit` 初始化镜像；入口使用两个 `mov imm64` 槽位分别传入 `XUserVarSlot` 与复制后的初始化入口，初始化按 DeltaForceDecrypt 的 PEB/Ldr、导出哈希和 Func/Offset/Data/Param/UserVar 分配方式建立运行时状态，业务调用由上层负责。
- **已知约束与避坑**: AMD NPT 没有独立的 execute/read 权限位，模式 2 依赖 NPF 取指判别，执行窗口内同页数据读取看到执行影子页；不得把该语义描述为硬件级同时 R=0/X=1。`X1` 与 `XUserVarInit` 镜像必须在安装双视图前复制并分别通过 `PatchXUserVarSlot` 与 `PatchXUserVarInit` 改写；UserVar 页、输入页和上下文页由调用方单独申请并保持普通可读映射，只有 ASM 入口和初始化代码页调用 `InstallShellcodeDualView`。初始化镜像不调用 CRT、TLS、导入表或业务函数；补丁长度限制为 64 字节且不得跨页；卸载先恢复原始补丁，再移除 Hook 页与 shellcode 页，最后清空接口状态。既有诊断结构偏移与 ABI 版本保持不变。
