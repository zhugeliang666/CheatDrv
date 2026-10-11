# ADR-0004: 轻量级 System PTE 驻留窗口缓存与 CR3 页表分级缓存架构

- **状态**: 已采纳
- **日期**: 2026-10-11
- **上下文与痛点**:
  - 在 commit `ba7b865` 中，为规避反作弊对 `\Device\PhysicalMemory` 句柄的扫描审计，驱动将底层内存访问切换为基于 System PTE 的动态重映射。
  - 然而原始重映射模型缺乏缓存机制，每次物理内存读取（哪怕仅 8 字节）均硬性执行 `_disable()` 关中断、`KfRaiseIrql(DISPATCH_LEVEL)` 提升中断优先级、两次写 PTE 属性以及两次硬件强序列化指令 `__invlpg`（刷新 TLB）。
  - 在高频 ScatterRead 与多线程并发测试场景下，16 个 Slot 剧烈竞争自旋锁，CPU 流水线被频繁击穿，导致 2000 次内存读取耗时由原始的 ~80ms 灾难性暴增至 9240ms（性能劣变逾 100 倍），且引发 CPU 微架构 PMU 计数器和中断延迟异常。

- **技术决策与规范**:
  1. **64 槽 Direct-Mapped 驻留窗口缓存 (PTE-Cache)**：
     - 将 System PTE 预留映射空间扩充至 64 槽（`LC_PTE_SLOT_COUNT 64`，仅需 256KB 连续虚拟地址，`'Mmdl'` Tag 伪装）。
     - 槽位映射物理页帧（`PFN = PhysAddr >> 12`）后**长期驻留**，不执行悲观复原。
     - **Fast-Path 内存直读**：当读取请求命中已驻留槽位时，直接通过内核虚拟地址执行 `__movsb`，彻底消除 `__invlpg`、`_disable()`、IRQL 升降级与锁争抢开销，实现纳秒级指针寻址吞吐。
  2. **细粒度槽位级排他原子锁**：
     - 每个 Slot 维护独立的 `volatile LONG Lock`，仅在 Cache Miss 换页时自旋重定向，64 个槽位彼此完全独立并发，彻底打破多线程并发线性锁死（Sequential Locking Bounds）。
  3. **硬件级 ACE 反作弊防御规范**：
     - **强制 NX 标志位**：重写 PTE 时，硬件最高位 Bit 63（No-Execute，`0x8000000000000000ULL`）强制置 1，严格声明为禁止执行的数据缓冲区，彻底杜绝 W+X（可写又可执行）内核页扫描违规。
     - **读写权限分离**：读操作 PTE 标志为只读（`LC_PTE_FLAGS_READ = 0x8000000000000101ULL`，RW=0），仅写操作赋予写属性（`LC_PTE_FLAGS_WRITE = 0x8000000000000103ULL`）。

- **已知约束与避坑**:
  - **卸载原子复原**：驱动停止或清理（`LcPteEngine_Cleanup`）时，必须严格遍历 64 个 Slot 写回 `OriginalPte` 并逐槽执行 `__invlpg`，随后调用 `MmFreeMappingAddress`，严禁遗留篡改页表项。
  - **IRQL 规范**：驻留缓存 Fast-Path 处于普通内核虚拟内存解引用模式，完全支持 PASSIVE_LEVEL 与 DISPATCH_LEVEL 安全并发访问。
