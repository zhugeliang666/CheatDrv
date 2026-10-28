# ADR-0108: Bootstrap 重载接管 ResidentPayload 跟踪记录

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: Bootstrap 重载时从 ResidentPayload 状态恢复 `payloadBase/payloadSize`，但新 Bootstrap 实例拥有独立的 PoolManager 链表。完整卸载调用 `PoolManagerDetachPool(payloadBase)` 找不到旧实例记录，连续返回 `0xC000000D`，造成 Payload active record 长时间保留。
- **技术决策与规范**: 状态恢复完成后调用 `PoolManagerAdoptResidentImage`，在当前实例的 ActiveList 中幂等登记 Payload 映像；登记项标记为 quarantine-only，不允许新实例释放旧映像后备页。重复恢复同一地址只返回成功，不创建重复链表项。
- **已知约束与避坑**: 接管只修复跟踪所有权，不清零、不释放仍可能被 CRT/WDF Lookaside 引用的映像；必须在 PASSIVE_LEVEL 使用 `FAST_MUTEX` 保护链表；完整卸载仍需先确认 HV 已停止，再执行 Payload stop、arena 处置和 PoolManager 反初始化。
