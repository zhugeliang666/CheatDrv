# ADR-0145: 方案1本地 Gadget 兜底与 Hook 私有视图回读门禁
- **状态**: 已采纳，部分替代 ADR-0141 的“无 Gadget 即失败”处理
- **日期**: 2026-10-30
- **上下文与痛点**: CE 在 Notepad、ntdll、KERNELBASE、USER32 和 KERNEL32 中均未找到完整的 `call rax; add rsp, 28h; ret` 与 `jmp [rbx]` Gadget 对；同时驱动日志报告 Hook 写入成功，但 CE 可见视图仍读取到原始 WndProc 序言，缺少安装后的目标进程视图回读证据。
- **技术决策与规范**: 方案1优先扫描目标可执行节中的原生 Gadget；缺少任一成员时，回退到同一份嵌入 `.text` 中的精确本地 Gadget，仍保持原始 Windows x64 ABI、`28h` 影子空间和 `jmp [rbx]` 返回链，不使用宽泛的近似序列。Hook 私有 COW 写入完成后，必须重新进入目标 `PEPROCESS` 视图读取并比较完整补丁字节；回读不一致立即报告失败并恢复原始 Hook 字节。
- **已知约束与避坑**: 本地 Gadget 必须随 `.text` 一起复制并保持相对布局，禁止把绝对地址写入目标进程。回读与恢复只能在 PASSIVE_LEVEL、目标进程引用有效且 `ZwProtectVirtualMemory` 保护恢复成功时执行；该兜底只解决 Gadget 缺失，不改变 RuntimeSlot `state==3` 的统一清理路径。
