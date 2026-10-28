# ADR-0072: 手动映像延迟回收与 CRT Lookaside 链隔离

- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: 远程 AMD 实机使用 `--force` 重载后触发 BugCheck `0xA`。WinDbg 将故障定位到 `nt!ExpScanGeneralLookasideList+0x40`，故障线程在 `DISPATCH_LEVEL` 读取 `r8-0x28`，而 `r8=0`。现场存在多个已卸载的 `VtBootstrapDriver.sys` 映像；源码原先在 CRT/WDF 卸载后立即清零并释放手动映射的 `VtHypervisor` 映像，导致仍挂在系统 Lookaside 链上的条目被清零。
- **技术决策与规范**: `Utils::UnloadDriverEx(TRUE)` 不再对 `VtHypervisor` 映像执行 `RtlSecureZeroMemory` 或立即释放；先通过 `Util::PoolManagerDetachPool` 从活动跟踪表摘除，再将映像页保留为延迟回收 quarantine，清空当前运行时句柄并允许下一次映射。保留页直到重启，避免 `KeBalanceSetManager` 异步扫描 CRT/UCXXRT Lookaside 条目时访问无效 `Flink`。PoolManager 的其它活动资源仍由原有 `PoolManagerUninitialize` 回收。
- **已知约束与避坑**: quarantine 映像严禁再次写入、清零或交给 `MmFreeIndependentPages`；`PoolManagerDetachPool` 失败时保持活动记录并停止后续释放。重复 `--force` 会按映像大小累计驻留页，必须在实机日志中监测 `quarantine count`，并在重启后回收。只有 `VCPU_COUNT=0`、VM-exit 引用归零且 CRT 卸载回调完成后才允许进入 quarantine。
