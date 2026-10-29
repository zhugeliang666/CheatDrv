# ADR-0131: Notepad Shellcode Hook 关键阶段诊断日志

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: Notepad 调试 Hook 在“嵌入 Shellcode 复制/补丁”阶段失败时只有一条汇总日志，无法区分目标解析、进程内存分配、节区复制、运行时槽位补丁或双视图安装失败。
- **技术决策与规范**: 在 `Stealth/VtEngine.cpp` 为 WndProc 解析、指令边界解码、目标内存分配/释放、目标页逐页 prefault、PE 节区复制、Runtime 槽位扫描与写入、Shellcode 双视图安装/移除、Hook 字节安装/恢复和清理状态增加阶段性 `DBG` 日志；日志仅在 `VT_DEBUG_NOTEPAD_NPT_TEST` 调试路径生效，不进入高频 VM-Exit 快路径。
- **已知约束与避坑**: 日志必须记录地址、大小、NTSTATUS、已写入字节数和页计数，但不得在日志中打印用户缓冲区内容；Release/Debug 均需编译验证；验证只编译和签名，不执行驱动加载。
