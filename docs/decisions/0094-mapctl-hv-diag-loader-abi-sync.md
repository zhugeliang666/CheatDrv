# ADR-0094: MAPCTL HV 诊断布局与 Loader 构建同步
- **状态**: 已采纳
- **日期**: 2026-10-26
- **上下文与痛点**: AMD NPT 诊断布局从 26 升级到 27 后，`mapctl_hv_diag` 与 `mapctl_migration_check` 各增加 16 字节。若只更新 VtBootstrapDriver 而继续使用旧 Loader，`MAPCTL_IOCTL_MIGRATE_CHECK` 的输出缓冲区会短于驱动要求，迁移门禁失败，Loader 在发送 `MAPCTL_IOCTL_LOAD_MACHENIKE` 前提前退出，表现为 Machenike 未加载。
- **技术决策与规范**: Loader 与 VtBootstrapDriver 统一包含 `mapctl_ioctl.h`；编译期固定校验 `MAPCTL_HV_DIAG_LAYOUT_VERSION == 27`、`sizeof(mapctl_hv_diag) == 0x650`、`sizeof(mapctl_migration_check) == 0x2728`。`VtLoader::MigrateCheck` 对 IOCTL 失败、短回复、魔数错误和诊断版本不匹配分别记录错误。变更 MAPCTL 结构后必须重建 Loader 与 Bootstrap，并通过嵌入映像布局验证。
- **已知约束与避坑**: 不得跨版本混用 `loader.exe` 与 `VtBootstrapDriver.sys`；部署前检查两者构建时间和 ABI 版本。`MigrateCheck` 未成功时禁止继续发送 Machenike 加载 IOCTL；本修复只更新构建与诊断门禁，不自动加载或测试驱动。
