# ADR-0137: Shellcode 仅复制 `.text` 并以 TextBase 作为首地址
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: 旧流程把目标分配地址当作 PE 映像基址，按 `Base + Text.Rva` 写入多个节区；Shellcode 的运行时代码位于 `.xinit`，导致目标进程同时接收 `.xconst`/`.xinit` 等非 `.text` 节区。需求是目标内存只写入 `.text`，并让分配首地址直接成为 `.text` 首地址。
- **技术决策与规范**: DebugShellcode 链接器将 `.xinit` 合并到 `.text`；生成器输出 `.text` 的 RVA、原始偏移、原始大小、有效跨度、入口偏移和 RuntimeDispatch 偏移。Machenike 以 `TextBase` 分配 `AlignUp(max(VirtualSize, RawSize))`，直接把 `.text.RawSize` 写到 `TextBase`，入口和分发地址使用 `TextBase + (Rva - TextRva)`；运行时补丁与双视图仅覆盖 `.text`。
- **已知约束与避坑**: 不能只删除 `+ Text.Rva` 而保留旧入口 RVA；所有入口/分发 RVA 必须经过 `.text` 范围校验。链接合并后 RawSize 可能大于 VirtualSize，分配和视图范围必须使用二者最大值。RuntimeSlot 控制页和 Hook 目标页仍是独立写入，不属于 Shellcode 映像节区。构建验证只进行离线编译和签名，不执行本地驱动加载。
