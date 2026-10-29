# ADR-0144: Notepad 私有进程视图写入与回读校验
- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: CE 观察到 Notepad Hook 地址仍保持原始序言、嵌入 `.text` 入口不可读，而驱动日志仅报告 Hypervisor CR3 写入成功。目标页由 `ZwAllocateVirtualMemory` 在目标进程上下文创建，使用 `_KPROCESS.DirectoryTableBase` 读取的 CR3 写入时可能落入不同的用户地址视图，无法证明 COW 私有页已被修改。
- **技术决策与规范**: Notepad 调试路径中，嵌入 `.text` 复制、运行时槽位/分发/Resume/被窃取指令补丁以及 `RuntimeSlot::state` 读取统一绑定 `PEPROCESS`，通过 `KeStackAttachProcess` 进入目标进程私有地址空间；写入仍动态解析 `ZwProtectVirtualMemory`、临时放宽页保护、`RtlCopyMemory` 后在同一视图执行 `RtlCompareMemory` 回读校验，再恢复原保护。状态轮询通过同一目标进程视图读取，不再以 Hypervisor CR3 读写替代。普通映像扫描和指令解码仍保留 CR3 只读路径。
- **已知约束与避坑**: 仅在 PASSIVE_LEVEL 调用；所有目标地址访问保留 `__try/__except`、进程引用和页保护恢复；写入或回读失败必须终止安装并走统一清理。禁止将该调试路径的目标进程私有页重新切回不匹配的内核 CR3 写入。该修复只解决地址视图/写回可见性问题，不放宽 ADR-0141 的方案1 Gadget 完整性门禁。
