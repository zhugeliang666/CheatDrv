# ADR-0006: 全面废弃 ExAllocatePool 机制与纯游离物理页(MDL)架构决策

- **状态**: 已采纳
- **日期**: 2026-10-12
- **上下文与痛点**:
  在 ADR-0002 的早期实现中，当宿主驱动内部空闲物理页不足时，系统通过微型探针在内核态调用 `ExAllocatePoolWithTag(NonPagedPool)` 申请缓冲区，并通过将原虚拟地址（`sourcePoolVA`）对应的 PTE 清零解绑（Ghost Pool）以避免双重映射。
  经反作弊（ACE / EAC / Vanguard）深度底层审计，此模式存在两大致命缺陷：
  1. **PoolBigPageTable 痕迹常驻**：大于 4KB 的非分页池分配必定被系统登记在 `nt!PoolBigPageTable` 哈希表中，反作弊遍历大池表比对驱动归属时，该独立池条目无法自圆其说；
  2. **MmPfnDatabase 孤儿页特征暴露**：Windows 内核物理页数据库 `nt!MmPfnDatabase[pfn].PteAddress` 在分配时已与原 Pool VA 绑定。强行清零源 PTE 会导致该物理页成为 `PteAddress` 失效的孤儿物理页（Orphan Page），反作弊启发式 PFN 遍历可秒级捕获；若强行修改 `_MMPFN` 结构，则直接触碰 PatchGuard（KPP）触发 `0x109: CRITICAL_STRUCTURE_CORRUPTION` 蓝屏。

- **技术决策与规范**:
  1. **彻底废除 `ExAllocatePoolWithTag` 及其相关实现**：
     - 从 Loader 与内核注入链路中彻底剔除 `AllocKernelPoolViaWhql`、`PteRemapHostDriver`（带源 PTE 清零解绑）等函数；
     - 严禁在宿主驱动注入链路中调用任何 `ExAllocatePool*` 族系例程，坚决不在系统通用池大表 (`PoolBigPageTable`) 留下任何登记条目。
  2. **引入纯游离物理页原语（MmAllocatePagesForMdl Headless Physical Allocation）**：
     - 当宿主原生空间不足时，统一且唯一采用微型探针调用 `ntoskrnl!MmAllocatePagesForMdl(Low=0, High=0xFFFFFFFFFF, Skip=0, TotalBytes)`（或自适应解析 `MmAllocatePagesForMdlEx`）；
     - 该例程向系统申请的是脱离虚拟内存空间（无 Pool VA）的游离物理页集合，直接读取 `pMdl->pfnArray` 提取纯物理地址列表 (`pagePAs`)；
     - 采用 `PteRemapHostDriverHeadless` 直接将游离物理页挂接入宿主驱动的目标虚拟地址，**从源头上彻底不存在源虚拟地址（Source VA），完全免除任何源 PTE 清零解绑动作**。
  3. **宿主原生常驻物理页原位复用（Priority 1: Native Resident Cave）**：
     - 在执行任何物理内存申请前，优先在宿主驱动的 `INIT` 节或带 `IMAGE_SCN_MEM_DISCARDABLE` (0x02000000) 属性的节区中寻找现成常驻物理页；
     - 必须通过 `ArePagesPresent` 逐页验证物理页是否真实常驻；若验证通过，直接通过物理地址将 Payload 原位写入，实现**零内存申请、零 PTE 属性修改**的最高隐匿性加载。
  4. **单核亲和性绑定防护（ScopedThreadAffinity RAII）**：
     - 在进入微型探针触发、PTE 页表翻转与 Shellcode 执行的全生命周期中，必须通过 `ScopedThreadAffinity` RAII 机制将当前触发线程硬性锁定在单一 CPU 核心上；
     - 彻底杜绝从 PTE 修改到平栈返回期间发生操作系统线程跨核迁移，消除多核 TLB 视图不同步与竞态崩溃隐患。
  5. **全页权限解除规范**：
     - 挂接目标虚拟页时，必须通过 `EnsureKernelPageExecutable` 确保设置 `PTE.RW = 1` 且清除 `PTE.NX`（置 0），防止执行展开代码或 DriverEntry 时触发硬件 DEP / `0xFC: ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` 蓝屏。

- **已知约束与避坑**:
  - **严禁向 PatchGuard 保护的内核结构（如 MmPfnDatabase）进行物理写**：绝不可试图强行修改 `_MMPFN` 的 `PteAddress` 字段伪装归属，必须通过纯游离物理页原语在架构层面规避冲突。
  - **严禁向通用系统池申请用于代码执行的内存**：现代 Windows 10/11 默认开启 HVCI/MBEC，从系统池分配的物理内存若在无合法签名模块视图下直接执行，会引发 Hypervisor 级拦截。
  - **宿主节区选型铁律**：严禁侵入 `.rsrc` 节；严禁寄生于 `tcpip.sys`；必须优先选择 `INIT` / `.reloc` 或大型显卡驱动（`nvlddmkm.sys`）。
