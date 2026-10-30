# ADR-0153: Notepad PE 预取改用安全跨进程复制

- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: 方案2为解决 PE 头、节表和 `.pdata` 未驻留导致的 CR3 短读而增加了目标进程地址直接解引用。蓝屏现场确认手工映射代码中的异常保护无法可靠承接无效用户页访问，最终在 `VtPrefaultNotepadRange` 的字节读取处触发 `0xC0000005`。
- **技术决策与规范**: 预取不再使用附加进程后的裸指针解引用，统一动态解析 `MmCopyVirtualMemory`，以目标 `PEPROCESS` 为源、当前进程内核缓冲区为目标、`KernelMode` 复制一个字节验证每个页面；预取过程持有 `PsAcquireProcessExitSynchronization` 生命周期租约，并覆盖首尾完整页。Notepad 候选在安装前必须通过 `PsGetProcessExitStatus == STATUS_PENDING` 检查；租约获取失败时由维护工作项重新枚举候选，而不是绕过生命周期门禁。
- **已知约束与避坑**: 禁止在手工映射代码中把 `__try/__except` 当作用户地址访问的唯一安全边界；复制失败必须返回状态并失败关闭，不得继续 CR3 解析。`MmCopyVirtualMemory` 哈希为 `0xD63B7937`，变更解析方式时必须同步验证目标系统导出。`PsAcquireProcessExitSynchronization` 失败必须记录租约状态与进程退出状态；不得对正在退出的 `PEPROCESS` 做用户地址访问、Hook、释放或恢复。
