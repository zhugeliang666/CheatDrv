# ADR-0069: 驱动映像隐藏统一关闭开关

- **状态**: 被 ADR-0076 替代
- **日期**: 2026-10-25
- **上下文与痛点**: VtResidentPayload 与 Machenike 的映像擦除、PFN/EPT 隐藏和痕迹清理路径分散在多个编译单元，调试与稳定性验证时难以保证两侧同时保持可见。
- **技术决策与规范**: 历史方案使用 `VT_IMAGE_HIDE_ENABLED` 统一控制两类驱动；现由 ADR-0076 的 `VT_PAYLOAD_IMAGE_HIDE_ENABLED` 与 `VT_MACHENIKE_IMAGE_HIDE_ENABLED` 分别控制。
- **已知约束与避坑**: 修改宏后必须完整重编 `VtBootstrapDriver`、`VtResidentPayload` 与 Machenike；运行态不通过热切换改变映像可见性；卸载仍需沿现有引用计数与全核停止路径执行。
