# ADR-0091: Payload 双视图前缓存 `.text` 范围
- **状态**: 已采纳
- **日期**: 2026-10-26
- **上下文与痛点**: AMD ResidentPayload 安装执行原页/读取零页双视图后，memcheck 仍从 `g_image_base` 读取 PE 头以解析 `.text`。读取视图已变为全零页，`PayloadBridgeCollectImageTextRange()` 在首个范围前返回 `false`，最终日志出现 `checked=0`、`STATUS_INVALID_PARAMETER`，DROPCTL 保留控制设备。
- **技术决策与规范**: 在 `PayloadCaptureBootContext()`、双视图安装前解析并缓存对齐后的 `.text` `base/size`；memcheck 与 RIP 范围判断优先使用缓存，不再依赖隐藏后的 PE 头读取。缓存仅记录完整 4KB 页，首尾混合页继续跳过。
- **已知约束与避坑**: 缓存必须在任何 `.text` 双视图安装前完成；不得把读零页当作 PE 头解析输入；范围校验保留 `image_base/image_size`、节表边界、整数回绕和异常保护；未获取有效范围时继续 fail-closed。
