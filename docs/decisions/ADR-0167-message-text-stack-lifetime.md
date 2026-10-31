# ADR-0167: MessageBox 文本与类型改为调用栈局部状态
- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: `GENERIC_RUNTIME_DATA` 中保存 `MessageText`、`MessageCaption`、长度和 `MessageBoxType` 会扩大持久化运行时结构，并引入文本缓冲区的堆分配与释放路径；这些值只服务于一次消息框调用。
- **技术决策与规范**: 从 `GENERIC_RUNTIME_DATA` 删除五个消息字段；`RuntimeInitWithInput` 不再分配/复制文本，`RuntimeMessageBoxDispatch` 在获得并发调用占位后创建局部栈数组、局部 `UINT messageBoxType`，填充固定文本并直接传给 `SpoofMessageBoxW`。
- **已知约束与避坑**: 局部文本缓冲区必须覆盖整个 `MessageBoxW` 调用生命周期；`MessageShown` 仍保留在共享数据中用于并发门禁。修改后必须同步重新生成嵌入 Shellcode，不能让旧布局的嵌入镜像继续使用。
