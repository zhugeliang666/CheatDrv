# ADR-0115: Machenike Notepad NPT/EPT 双视图调试用例
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: 需要在不改写目标代码的前提下验证 AMD NPT 与 Intel EPT 的进程页钩子路径，现有工程缺少可重复的最小目标。
- **技术决策与规范**: Machenike 项目在 `Core/Common.h` 增加独立宏 `VT_DEBUG_NOTEPAD_NPT_TEST`（默认 0）。宏开启后，驱动初始化完成时通过动态解析的进程 API 定位 `notepad.exe`，读取其 PE 节表，优先选择可读、非执行的 `.rdata`/`.data` 页，查询目标 CR3 与物理地址，再调用既有 `VtEngine::EhInstall(process, va, TRUE, TRUE)`。`is_fake_page=TRUE` 与 `full_zero=TRUE` 固定为“执行原页、读取零页”；AMD 由 NPT 后端承载，Intel 由 EPT 后端承载。测试不写目标代码，驱动卸载前调用 `EhRemove` 并释放进程引用。
- **已知约束与避坑**: 默认不执行，且不绑定 Debug/Release；notepad 未运行、VT 未激活、PE 头或非执行数据节解析失败时只记录失败并退出。钩子状态只保留一个引用，卸载必须先移除 EH 条目再释放 `PEPROCESS`；本用例只用于隔离测试，不接入生产隐藏链路。
