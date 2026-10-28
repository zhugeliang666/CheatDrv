# ADR-0077: Payload 全映像隐藏与活跃 ERESOURCE 链表冲突的稳定门禁
- **状态**: 被 ADR-0078 替代
- **日期**: 2026-10-25
- **上下文与痛点**: WinDbg 现场出现 `KERNEL_SECURITY_CHECK_FAILURE (0x139)` / `CORRUPT_LIST_ENTRY (Arg1=3)`，故障点位于 `CcAllocateInitializeBcb -> ExInitializeResourceLite`。`ExpSystemResourcesList` 的活动 ERESOURCE 地址落在 VtResidentPayload 映像尾部；全映像 PFN 读零后，系统读取到全零链表项并触发完整性检查。
- **技术决策与规范**: 历史方案曾新增 `VT_PAYLOAD_IMAGE_HIDE_FULL_ENABLED`，默认值为 0，以关闭 Payload 全映像 PFN 隐藏。
- **已知约束与避坑**: `ExInitializeResourceLite` 会把资源挂入 `nt!ExpSystemResourcesList`；活动资源所在页不能映射为读零页。禁止在资源仍活动时启用全映像隐藏或头部擦除；启用完整隐藏前必须通过 KD 检查链表、引用计数与卸载顺序。
