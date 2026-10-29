# ADR-0132: Notepad Hook 点双视图独立开关

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: Notepad 调试 Hook 需要分别控制目标 Hook 页和 Shellcode 页双视图，便于关闭全部双视图进行原始页检查，或单独验证某一类视图。
- **技术决策与规范**: 在 `Core/Common.h` 增加 `VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW` 与 `VT_DEBUG_NOTEPAD_SHELLCODE_DUAL_VIEW` 两个独立宏，默认值均为 `0`。Hook 宏关闭时通过目标进程 CR3 直接写入/恢复原始页；开启时使用 `VT_EH_VIEW_EXEC_SHADOW_READ_ZERO`。Shellcode 宏关闭时使用原始执行/读取页；开启时为 `.text/.xinit` 安装 `VT_EH_VIEW_EXEC_SHADOW_READ_ZERO`。
- **已知约束与避坑**: 两个宏只影响 Notepad 调试路径；Shellcode 宏关闭时不调用 Shellcode 页 `EhInstall/EhRemove`，Hook 宏关闭时不调用 Hook 页 `EhInstall/EhRemove/EhWrite`；修改宏后必须同时重建 Release/Debug，验证只编译和签名，不执行驱动加载。
