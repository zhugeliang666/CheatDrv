# ADR-0078: Payload 仅隐藏 `.text` 页并保持数据节可读
- **状态**: 被 ADR-0079 替代
- **日期**: 2026-10-25
- **上下文与痛点**: 全映像 PFN→dummy 会同时影响 `.data/.rdata/.pdata`，其中活动 `ERESOURCE`、常量与异常元数据仍需由 Guest 正常读取。仅保留 Payload `.text` 隐藏可以降低代码页读取可见性，同时避免再次破坏运行时数据。
- **技术决策与规范**: 删除 `VT_PAYLOAD_IMAGE_HIDE_FULL_ENABLED`；`VT_HIDE_PAYLOAD_IMAGE` 固定表示仅处理 PE 中名称以 `.text` 开头且带执行属性的完整 4KB 页。Bootstrap 与 ResidentPayload memcheck 使用同一 PE 节解析规则；首尾混合页跳过，`.data/.rdata/.pdata/.xdata` 不进入图像页集合；Payload PE 头与嵌入 blob 不再擦除。arena/direct/pool 仍由独立宏控制。原先对 `.text` 直接执行 PFN→dummy 的实现已由 ADR-0079 的 EH 双视图替代。
- **已知约束与避坑**: PFN 映射只能按页生效，`.text` 与相邻节共享的边界页必须保持可见；PE 头必须在隐藏前后保持可读，以便 Bootstrap 与 ResidentPayload 解析节表；memcheck 的 `MAPCTL_MEMCHECK_FLAG_IMAGE` 现在校验 `.text` 页集合而非整个映像。直接将活动代码页改成 dummy PFN 会让取指也看到全零并触发 BugCheck 0x1E，禁止再次采用。
