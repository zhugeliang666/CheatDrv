# ADR-0133: Notepad WndProc 运行时签名解析
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: CE MCP 对本地 Notepad 的实际窗口过程解析结果为 `notepad.exe + 0xA360`，而旧调试宏固定为 `0x9362`，导致 Hook 落在无关代码位置且 UI 消息不触发。
- **技术决策与规范**: 删除 `VT_DEBUG_NOTEPAD_WNDPROC_RVA`。驱动通过目标进程 CR3 读取 PE 节表，仅扫描可执行 `.text`（无 `.text` 时回退到其他可执行节），使用窗口过程入口序列与 `WM_COMMAND (0x0111)` 参数准备序列进行双段签名匹配；扫描前在目标进程上下文逐页预取选定节，避免 NPT/EPT `gva2hva` 对未驻留源页返回 0；匹配数必须严格为 1，返回 `ImageBase + CandidateRva`，随后继续执行 HDE64 指令边界校验和 Hook 安装。日志输出动态 VA、RVA、节名和匹配数。
- **已知约束与避坑**: 预取只针对已通过 PE 节表边界检查的可执行节，并在 `KeStackAttachProcess` 作用域内使用 SEH；扫描按 4KB 页读取，禁止越界读取目标映像；读取失败、签名多匹配或无匹配均失败关闭；不得扫描或写入非执行节；该解析仅用于 `VT_DEBUG_NOTEPAD_NPT_TEST`，不接入生产隐藏链路，不在本机加载驱动。
