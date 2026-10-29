# ADR-0134: Notepad Hook 进程私有 COW 写入隔离
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: `VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW=0` 旧路径使用 Hypervisor `WriteVirtualMemory` 直接按目标 CR3 写物理页，绕过 Windows 映像节 Copy-on-Write；修改共享 `.text` PFN 后，原 Notepad 退出，新进程仍会映射污染页并立即崩溃。
- **技术决策与规范**: 关闭 Hook 双视图时，Hook 安装/恢复统一在目标进程上下文中动态解析并调用 `ZwProtectVirtualMemory`，临时切换为 `PAGE_EXECUTE_READWRITE`，完成进程私有 COW 写入后恢复原保护；Hook 双视图开启时继续使用 EH/NPT/EPT 影子页写入。禁止在关闭双视图路径对映像代码页调用 Hypervisor 直接虚拟写。
- **已知约束与避坑**: 写入和恢复必须成对执行并检查保护恢复状态；目标进程终止后只允许失败关闭，不得用失效 CR3 写物理页；旧版本已经污染的共享映像页需重启清除后再验证；该逻辑仅属于 Notepad 调试用例。
