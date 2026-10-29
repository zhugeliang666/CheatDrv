# ADR-0129: Notepad 调试 Hook 目标切换为窗口过程
- **状态**: 部分被 ADR-0133 替代
- **日期**: 2026-10-29
- **上下文与痛点**: 原方案把 CE 验证出的 `0x9362` 固定为 RVA；当前本地 CE 解析到同版本窗口过程为映像 RVA `0xA360`，固定值落在错误位置，导致 Hook 不触发。
- **技术决策与规范**: 保留窗口过程作为调试目标，但由 `VtResolveNotepadWndProc` 在目标 `notepad.exe` 的 `.text` 节中扫描带校验尾部的窗口过程签名，要求唯一匹配后返回运行时 VA；`RunNotepadNptTest` 继续执行 HDE64 指令边界检查并记录动态 RVA。入口参数保持 `RCX=HWND`、`EDX=消息号`、`R8=WParam`、`R9=LParam`；消息过滤由 Shellcode 负责。
- **已知约束与避坑**: 禁止恢复硬编码 WndProc RVA；签名匹配数必须等于 1，节表/页读取/签名扫描失败时关闭测试路径；不得把共享 `COMCTL32!Edit` 过程作为主 Hook 点。卸载仍先恢复窗口过程入口，再移除 Hook 和双视图。
