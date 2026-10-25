# ADR-0080: Payload 映像与 PoolManager 隐藏范围隔离
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: Payload 映像由 `PoolManagertAllocation` 记录在 resident pool manifest 中。Handoff 后的 resident-pool PFN→dummy 扫描若再次处理该映像，会覆盖 `.text` 的 EH 双视图；AMD NPT 随后让 Guest 直接从零页取指，现场表现为 `0xC0000005`/`0x1E` 和 `add [rax],al`。
- **技术决策与规范**: `mapdriver_hide_payload_resident_pool_blocks` 对与 `payload_status.image_base/image_size` 重叠的 block 直接跳过；arena、direct、host-stack 隐藏路径同样在与映像重叠时跳过整个范围。Payload `.text` 只由 ADR-0079 的全核 `hypercall_eh_install(flags=3)` 管理，映像数据节保持普通映射。
- **已知约束与避坑**: 重叠判断使用溢出保护后的半开区间；不对映像 block 做部分切分，避免边界页再次进入 PFN→dummy。卸载 PFN 清单同步跳过映像 block，先移除 EH，再恢复其他范围。
