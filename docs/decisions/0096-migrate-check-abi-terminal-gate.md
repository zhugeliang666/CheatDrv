# ADR-0096: MigrateCheck ABI 不匹配终止重试
- **状态**: 已采纳
- **日期**: 2026-10-27
- **上下文与痛点**: 旧版 VtBootstrapDriver 返回诊断 ABI 26，而 Loader 已使用 ABI 27 时，迁移检查每 50ms 重试，产生大量重复日志并延迟失败；旧映像不能继续进入 Machenike 加载门禁。
- **技术决策与规范**: `MigrateCheck` 增加可选 ABI 不匹配输出标志；`EnsureVtOneKeyActive` 在首次检测到 `driver_diag != MAPCTL_HV_DIAG_LAYOUT_VERSION` 后立即关闭控制句柄并终止迁移，不再进入 100 次 Pre-Switch 重试。Loader 仍只接受 ABI 27，Bootstrap 必须从 `bin\\vt\\VtBootstrapDriver.sys` 同批构建部署。
- **已知约束与避坑**: ABI 不匹配是部署错误而非暂态就绪状态；不得通过扩大输出缓冲或继续重试兼容旧映像。测试机若只存在兼容路径副本，必须替换为当前构建产物后再启动服务。
