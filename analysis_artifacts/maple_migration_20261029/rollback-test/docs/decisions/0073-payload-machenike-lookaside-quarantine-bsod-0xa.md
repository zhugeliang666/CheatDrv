# ADR-0073: Payload 与 Machenike 映像 Lookaside 链隔离
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: WinDbg 现场再次出现 `0xA`，故障位于 `nt!ExpScanGeneralLookasideList+0x40`，`r8=0`。`ExNPagedLookasideListHead` 链仍指向 `ffff967e`c315b980`，该节点的 `Flink/Blink` 为零，而 PTE 有效、页面内容全零。此前仅隔离 VtHypervisor 映像，Payload 与 Machenike 的清理路径仍会清零并释放手动映像。
- **技术决策与规范**: `UnloadPayload()` 在调用停止入口后只摘除 PoolManager 跟踪记录，保留 Payload 完整映像；`UnloadMachenike()` 在回调后保留完整映像，不再执行 `RtlSecureZeroMemory`、`MmFreeIndependentPages` 或 `ExFreePoolWithTag`。三类手动映像统一采用延迟回收 quarantine，新增独立计数日志。
- **已知约束与避坑**: 任何仍可能被 `nt!ExNPagedLookasideListHead` 异步扫描的映像页禁止清零或释放；PoolManager 摘除失败时保留活动记录并终止该清理分支；quarantine 页在重启前持续占用，测试循环结束后重启回收；后续若要真实释放，必须先完成 CRT/WDF Lookaside 注销、引用计数归零和全核停止确认。
