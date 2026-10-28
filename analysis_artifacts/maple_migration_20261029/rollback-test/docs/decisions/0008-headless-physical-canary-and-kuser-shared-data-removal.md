# ADR-0008: 纯游离物理页(MDL)防重复加载暗桩与废除KUSER_SHARED_DATA写入架构决策

- **状态**: 已采纳
- **日期**: 2026-10-13
- **上下文与痛点**:
  - 在早期版本实现中，为实现内核驱动（`drv_wsk.sys`）跨进程、跨环的防重复加载感知（Canary），驱动向 Windows 全局固定虚拟地址 `KUSER_SHARED_DATA`（`0xFFFFF78000000000`）的偏移 `0x800` 处写入了标记（`DRV_WSK_CANARY_MAGIC = "WSK_LOAD"`）。
  - **蓝屏事故（BugCheck 0x109）**：
    在 Windows 10 19041（20H1/20H2及以后版本）运行约 20 分钟后，PatchGuard（KPP）的周期性 DPC 校验机制随机触发，检出 `0xFFFFF78000000720`（`_KUSER_SHARED_DATA` 合法数据边界）之后的页面数据被篡改，触发蓝屏：
    ```text
    BugCheck 109 (CRITICAL_STRUCTURE_CORRUPTION)
    Arg1: a39ffa663d6f056a, Arg2: b3b706ec8ff1434e
    Arg3: fffff78000000720 (Corruption Address), Arg4: 0000000000000000 (Type 0: generic data)
    ```
  - 核心痛点：`KUSER_SHARED_DATA` 被 PatchGuard 纳入整页哈希校验体系，严禁内核写入任何非系统数据；同时修改宿主白驱动 PE 头（DOS Header 0x28）又会触发反作弊（ACE / EAC）的 PE 头对拍校验。

- **技术决策与规范 (方案 5 落地)**:
  1. **彻底废除 `KUSER_SHARED_DATA` 的任何写入行为**：
     - 从 `Main.cpp`、`Common.h`、`loader/loader_common.h` 和 `loader/shellcode_builder.h` 中彻底剔除 `KUSER_SHARED_DATA_R0_VA`、`KUSER_SHARED_DATA_CANARY_OFF` 宏及相关读写原语。
  2. **引入纯游离物理页 GUID 签名防重复加载机制 (Headless Physical Page Canary)**：
     - 驱动初始化时通过 `ntoskrnl!MmAllocatePagesForMdl(Low=0x10000000, High=0x20000000, Skip=0, TotalBytes=PAGE_SIZE)` 分配 1 页纯游离物理页；
     - 该物理页**无系统大池登记（`PoolBigPageTable` 为空）**，仅在写入初始数据时映射极短瞬间的内核临时 VA，写完立即调用 `MmUnmapLockedPages` 撤销映射；
     - 物理页完全脱离内核虚拟地址空间（Headless），**PatchGuard 与反作弊模块在虚拟地址巡检中完全不可见**。
  3. **限定物理内存窗口高速特征探测规范**：
     - 分配窗口限定在 `[256MB ~ 512MB]`（`0x10000000 ~ 0x20000000`）的物理内存范围内，总计仅 64K 个物理页；
     - 暗桩头部写入 128 位高熵全局唯一 GUID 签名（`{57534B5F-4C4F-4144-B899-A1B2C3D4E5F6}`）与 `DRV_WSK_CANARY_MAGIC`；
     - Loader 在加载前利用底层物理内存读取原语（`WhqlReadPhys`）按 4KB 步长快速检索此窗口，检索耗时控制在数十毫秒内，检出后即判定驱动在线存活并跳过重复注入。
  4. **原生生命周期自动闭环**：
     - 驱动在 `DriverUnload` 卸载路径中调用 `MmFreePagesFromMdl(g_pHeadlessCanaryMdl)` 与 `ExFreePool`，物理页安全归还系统，零内存泄漏。

- **已知约束与避坑**:
  - **严禁向 `0xFFFFF78000000000`（KUSER_SHARED_DATA）写入任何数据**：哪怕写入偏移超出结构体定义范围（如 `0x800`），PatchGuard 会在 5~20 分钟内随机周期性检出并触发 `BugCheck 0x109` 强行蓝屏；
  - **游离物理页必须维持无常驻内核 VA 映射**：临时映射写入后必须立刻 `MmUnmapLockedPages`，防止常驻内核映射被反作弊扫描驱动模块边界外的孤立映射页；
  - **物理扫描步长与边界防御**：Loader 探测物理页时必须严格按 `PAGE_SIZE`（4KB）对齐偏移，读取长度必须严格为 `sizeof(DRV_WSK_CANARY)`，严禁越界访问。
