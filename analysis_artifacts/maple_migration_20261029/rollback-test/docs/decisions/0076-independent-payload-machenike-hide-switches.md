# ADR-0076: Payload 与 Machenike 映像隐藏独立开关
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: 原 `VT_IMAGE_HIDE_ENABLED` 同时关闭 VtResidentPayload 与 Machenike 的隐藏路径，无法单独验证某一驱动的双视图、PFN/EPT 映像隐藏和相关清理行为。
- **技术决策与规范**:
  - 使用 `VT_PAYLOAD_IMAGE_HIDE_ENABLED` 独立控制 VtResidentPayload 的隐藏细分开关。
  - 使用 `VT_MACHENIKE_IMAGE_HIDE_ENABLED` 独立控制 Machenike 的整映像隐藏、`.text` 双视图和 Machenike 映像擦除路径。
  - 删除统一 `VT_IMAGE_HIDE_ENABLED` 门控；`VT_IMAGE_WIPE_ENABLED` 继续作为通用擦除策略的独立开关。
  - `VT_PAYLOAD_IMAGE_HIDE_ENABLED=0` 不修改 Machenike 开关；`VT_MACHENIKE_IMAGE_HIDE_ENABLED=0` 不修改 Payload 开关。
- **已知约束与避坑**: 修改宏后必须完整重编 `VtBootstrapDriver`、`VtResidentPayload` 与 Machenike；关闭 Machenike 隐藏时仍需按既有 Lookaside quarantine、全核 EH 移除和引用计数路径卸载；关闭 Payload 隐藏不改变 Hypervisor 自身映像策略。
