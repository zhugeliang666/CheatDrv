# ADR-0147: MessageBoxW 调用的并发重入门禁
- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: `RuntimeMessageBoxDispatch` 原先先读取 `MessageShown`，在可阻塞的 `MessageBoxW` 返回后才写入标志。多个 WndProc/线程可在首个调用返回前同时看到 0，重复进入 MessageBoxW。
- **技术决策与规范**: 使用 `InterlockedCompareExchange(MessageShown, 1, 0)` 把 0→1 作为“调用进行中”占位；其他并发调用直接返回。调用成功后写入 2，调用失败写回 0 允许重试。状态约定为 0=未调用/可重试，1=调用进行中，2=已完成。
- **已知约束与避坑**: 不得恢复“调用后才置位”的窗口；初始化必须将状态设为 0。修改后必须重建 DebugShellcode 并刷新嵌入镜像，当前环境未完成该构建验证。
