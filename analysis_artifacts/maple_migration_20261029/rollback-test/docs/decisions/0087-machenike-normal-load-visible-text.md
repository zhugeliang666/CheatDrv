# ADR-0087: Machenike 正常加载保持 `.text` 可见
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: Machenike 同时支持正常加载与手动映射。正常加载时启用 `.text` 双视图会改变可读视图，增加常规 DriverEntry/运行时路径的不确定性；Payload 的 `.text` 隐藏仍需独立保持。
- **技术决策与规范**: `mapdriver_load_machenike` 仅在 `isManualMap == TRUE` 且 `VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED` 开启时调用 `InstallMachenikeTextDualView`；正常加载（mode=1）跳过 Machenike `.text` 双视图并保持原始可读页。Payload `.text` 隐藏继续由 `VT_PAYLOAD_IMAGE_HIDE_ENABLED`、`VT_HIDE_PAYLOAD_ENABLED` 与 `VT_HIDE_PAYLOAD_IMAGE` 独立控制。
- **已知约束与避坑**: 重复加载路径按 `Utils::machenikeMode == 2` 恢复手动映射双视图；卸载仍调用幂等的 `RemoveMachenikeTextDualView`；不得用 Machenike 的 mode 或开关覆盖 Payload 隐藏开关。
