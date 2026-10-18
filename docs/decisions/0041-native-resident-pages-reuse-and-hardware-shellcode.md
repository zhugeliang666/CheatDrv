# ADR-0041: 废除内核 MmMapIoSpace 限制、宿主原生物理页复用与纯硬件级 214 字节直拷 Shellcode 架构

- **状态**: 已采纳
- **日期**: 2026-10-19
- **上下文与痛点**:
  在 ADR-0015 的 Branch 2B 设计中，系统尝试在内核态 Shellcode 内部调用 `ntoskrnl!MmAllocatePagesForMdl` 申请游离物理页，并调用 `ntoskrnl!MmMapIoSpace` 将宿主驱动目标节区的 PTE 物理基址（`firstPtePA`）临时映射至非分页系统空间，以便翻转 PFN 并重映射。
  经真机实操与底层逆向验证（`status=0xC0000772`），该方案存在系统级不可逾越的硬性障碍：
  1. **Win10 1803+ 限制拦截（`0xC0000772`）**：微软自 Windows 10 1803 起，在 `ntoskrnl!MiMapIoSpace` 中强化了内核安全沙箱，对请求映射的物理地址执行严格的系统物理 RAM 白名单校验（`MiIsIoSpacePhysicalAddress`）。若目标地址属于常规内存（Standard RAM，如页表所在的 RAM 物理页），`MmMapIoSpace` 坚决拒绝映射并直接返回 NULL，导致驱动注入直接在内核层被拦截。
  2. **过度工程与冗余物理页申请**：宿主驱动（如 `amdkmdag.sys` 的 `.reloc` / `INIT` 节区）在系统加载驱动时，其 52 个 4KB 页面（320KB）本来就已经在物理内存中真实分配并常驻，重复分配新物理页与翻转 PFN 违背了 [ADR-0006](0006-headless-mdl-pages-and-pool-removal.md) 的「Priority 1: Native Resident Cave 原生常驻物理页原位复用」第一准则。

- **技术决策与规范**:
  1. **遵循 ADR-0006 Priority 1：宿主原生常驻物理页原位复用**：
     - 在 Loader 阶段遍历页表获取目标节区首个 PTE 物理地址（`firstPtePA`），通过单次读物理内存校验所有 52 个页面的 `PTE_PRESENT` 状态；
     - 通过单次写物理内存（416 字节，仅 1 次 IOCTL）将这 52 个原生常驻 PTE 批量标记为可写可执行（`PTE_RW = 1, PTE_NX = 0`）；
     - 彻底免除在内核中调用 `MmAllocatePagesForMdl` 分配新物理页的开销与隐患。
  2. **全面移除内核 API 依赖，精简为 214 字节纯硬件级直拷 Shellcode**：
     - 彻底从汇编执行流中剔除 `MmAllocatePagesForMdl`、`MmMapIoSpace`、`MmUnmapIoSpace` 等不可控系统例程；
     - 仅利用 CPU 原生硬件原语与指令闭环：
       - `invlpg` 逐 4KB 页面瞬时刷新目标 VA 的 CPU 硬件 TLB；
       - `rep movsb` 利用当前 CR3 原生直读特权，3 微秒瞬时硬件级直拷 216KB 驱动镜像；
       - 写入 Canary 头部，构造伪 `DRIVER_OBJECT`，直调 `DriverEntry`；
       - 平栈恢复现场并安全跳回宿主驱动 default 分支完成 IRP。
     - 汇编代码从 340 字节极限精简至 **214 字节**（余量扩充至 129 字节，严格受限于 463 字节 Code Cave 空间）。

- **已知约束与避坑**:
  - **严禁使用 `MmMapIoSpace` 映射系统 RAM**：Windows 内核禁止驱动将常规物理 RAM 当作 MMIO 映射，凡涉及物理页表或 RAM 访问必须通过页表自映射或底层硬件读写原语。
  - **单次 IOCTL 416 字节绝对安全**：更新 52 个 PTE 属性仅产生 1 次 416 字节的物理写，相比旧方案（Plan A）上百次高频物理写镜像，写频率降低 99%，完全不触碰反作弊行为监控阈值。
