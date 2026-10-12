# ADR-0004: 轻量级 System PTE 驻留窗口缓存与 CR3 页表分级缓存架构

- **状态**: 已采纳 (2026-10-12 升级优化：4096 槽 + 斐波那契散列 + 序列锁读读并发 + 零拷贝原位直读)
- **日期**: 2026-10-11 (更新于 2026-10-12)
- **上下文与痛点**:
  - 在 commit `ba7b865` 中，为规避反作弊对 `\Device\PhysicalMemory` 句柄的扫描审计，驱动将底层内存访问切换为基于 System PTE 的动态重映射。
  - 然而原始重映射模型缺乏缓存机制，每次物理内存读取（哪怕仅 8 字节）均硬性执行 `_disable()` 关中断、`KfRaiseIrql(DISPATCH_LEVEL)` 提升中断优先级、两次写 PTE 属性以及两次硬件强序列化指令 `__invlpg`（刷新 TLB）。
  - 在多线程高频并发（如游戏 Prepare/Decrypt 线程以 200+ FPS 密集读取）场景下，暴露出四大微架构级瓶颈：
    1. **慢路径自旋锁退避过重**：原自旋锁循环上限达 50000 次且附带内核全局 `DBG()` 打印，单次争用耗时可达 50ms+，导致帧率断崖式骤降至 50~60 FPS；
    2. **512 槽容量与 2MB 周期性碰撞**：普通低位取模哈希导致游戏物理堆频繁在 2MB/4MB 边界发生碰撞击穿，Slot 反复互相踢出触发 TLB 清空；
    3. **读读互斥阻塞**：原快路径要求 `slot->Lock == 0`，只要有一线程因换页加锁，并发直读该页的其它线程全部被阻断；
    4. **RPC 每次动态分配临时池内存**：`ReadScatter` 每次动态申请并释放 `pbData` 临时缓冲，引发内核 NonPagedPool 全局锁争用。

- **技术决策与规范**:
  1. **4096 槽 System PTE 驻留窗口 + 斐波那契黄金分割散列**：
     - 将 System PTE 预留映射空间扩充至 4096 槽（`LC_PTE_SLOT_COUNT 4096`，需 16MB 连续系统虚拟空间，`'Mmdl'` Tag 伪装，零大池登记）。
     - 引入斐波那契黄金分割散列函数 `((pfn ^ (pfn >> 12)) * 11400714819323198485ULL) & 4095`，彻底打碎跨 2MB/4MB 物理内存对齐，消灭周期性缓存颠簸。
  2. **基于 Sequence Lock (版本序列锁) 的读读全并发无锁直读**：
     - 每个 Slot 维护 `volatile LONG Sequence`（偶数代表稳定就绪态，奇数代表换页进行中）。
     - **快路径无锁并发**：读线程读取前检验 `(seq1 & 1) == 0 && CachedPfn == targetPfn`，执行 `__movsb` 后再次比对 `Sequence == seq1 && CachedPfn == targetPfn`。读读之间完全无锁并发，零自旋开销。
     - **换页状态原子切换**：换页前递增 Sequence 为奇数 -> 清空 CachedPfn -> 修改硬件 PTE 与 `__invlpg` -> 恢复 CachedPfn -> 递增 Sequence 为偶数。
  3. **阶梯式轻量退避 (Ladder Backoff) 与 DBG 移除**：
     - 自旋上限缩减为 4000 次，前 32 次单 pause，中等 4 pause，高冲突调用 `YieldProcessor()`；
     - 彻底清除慢路径自旋失败与初始化循环中的所有 `DBG()` 打印，消灭全局 `DbgPrint` 内部互斥锁造成的级联卡顿。
  4. **RPC 响应端原位直读 (In-Place Read) 与零拷贝 (Zero-Copy)**：
     - 废除 `ExAllocatePoolWithTag(pbData)` 动态分配；
     - 让每个散列项的 `pb` 目标地址直接指向响应包体数据区 `pRspBin->pb + cMEMs * sizeof(MEM_SCATTER)`；
     - 常态下 100% 成功页实现零拷贝直出；仅当极罕见情况下存在失败页时，就地进行 `RtlMoveMemory` 向前对齐，彻底根除高频内核池锁争用。
  5. **硬件级 ACE 反作弊防御规范**：
     - **强制 NX 标志位**：重写 PTE 时，硬件最高位 Bit 63（No-Execute，`0x8000000000000000ULL`）强制置 1，严格声明为禁止执行的数据缓冲区，彻底杜绝 W+X（可写又可执行）内核页扫描违规。
     - **读写权限分离与无 Global 标志**：读操作 PTE 标志为只读（`LC_PTE_FLAGS_READ = 0x8000000000000001ULL`，RW=0），严禁置位 Bit 8 Global (0x100) 标志，防止多核 TLB 在进程调度时永久锁定残留映射导致跨核脏读；仅写操作赋予写属性（`LC_PTE_FLAGS_WRITE = 0x8000000000000003ULL`）。

- **已知约束与避坑**:
  - **卸载原子复原**：驱动停止或清理（`LcPteEngine_Cleanup`）时，必须严格遍历 4096 个 Slot 写回 `OriginalPte` 并逐槽执行 `__invlpg`，随后调用 `MmFreeMappingAddress`，严禁遗留篡改页表项。
  - **严禁无锁裸读且不设双重校验**：快路径必须通过 Sequence Lock 进行版本前后一致性校验，慢路径换页前必须清空 PFN 缓存，杜绝物理页串页脏读；
  - **严禁使用 Global 属性**：System PTE 作为物理读写动态窗口，禁止标记为 Global 页，防止硬件 MMU 跨核脏读；
  - **IRQL 规范**：驻留缓存 Fast-Path 处于普通内核虚拟内存解引用模式，完全支持 PASSIVE_LEVEL 与 DISPATCH_LEVEL 安全并发访问。
