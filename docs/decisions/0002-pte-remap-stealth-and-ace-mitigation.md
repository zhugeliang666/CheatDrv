# ADR-0002: PTE Remap 驱动高隐匿性架构改造与反作弊(ACE)规避规范

- **状态**: 已采纳
- **日期**: 2026-10-11
- **上下文与痛点**:
  原 PTE Remap 实现中，映射目标物理页时直接赋予 `NoExecute = 0`（可执行）与 `Write = 1` 权限，导致页面在宿主只读驱动（如 `.rdata`/`.rsrc`）中长时间呈现异常 W+X / 可执行状态。主流反作弊引擎（如 ACE/EAC）通过内核周期性内存扫描比对驱动 PE 头 `Characteristics` 与底层 PTE 属性，可瞬间判定为 Code Cave 挂接。同时，每次修改页表时调用 `KeIpiGenericCall` 广播 IPI 刷新，会产生严重的系统性能抖动并被内核性能计数器（PMU）及反作弊钩子捕捉。

- **技术决策与规范**:
  1. **按需特权切换（JIT / On-Demand PTE Flip）**：
     - `PteHijack_Remap` / `PteHijack_RemapEx` 默认以 `NoExecute = 1`（数据只读/不可执行态）完成映射，页面完全伪装为正常只读数据。
     - 引入 `PteHijack_SetExecution(Va, EnableExecute)` 机制：仅在执行 Payload 的微秒级窗口期原子翻转 `NX = 0`，调用完成平栈后立即原子翻转回 `NX = 1`，将暴露时间窗口缩减 99.999% 以上。
  2. **轻量化本地单核 TLB 刷新**：
     - 新增 `PteHijack_FlushTlbLocal(Va)`，使用 `_mm_mfence() + __invlpg + _mm_mfence()` 本地核心单次刷新，彻底摒弃常规调用中全局广播的 `KeIpiGenericCall`。
     - 结合调度线程通过 `KeSetSystemAffinityThread` 绑核运行，消除全系统 IPI 中断风暴与异常特征。
  3. **零 PE 头侵入与免 SEH 设计**：
     - Payload 严格遵循纯 C / 扁平化汇编规范，禁止依赖 C++ 异常与 SEH，彻底废弃修改宿主 PE 头 `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]` 指向动态合并 `.pdata` 的高危做法，确保宿主 PE 文件头 100% 匹配磁盘原始 Hash。
  4. **扩展 IOCTL 协议**：
     - 新增 `IOCTL_PTE_HIJACK_SET_EXEC` (`0x8000200C`) 控制码及 `SET_EXEC_REQUEST` 协议，向应用层受控暴露 JIT 特权切换接口。
  5. **特权属性智能纠偏 (Owner / SMEP 兼容)**：
     - 根据目标虚拟地址动态判定：内核空间（`Va >= 0xFFFF800000000000`）强制锁定 `Owner = 0`（Supervisor 权限），用户空间才允许 `Owner = 1`。杜绝因内核页出现 User 标志而触发反作弊特权错位扫描及硬件 SMEP 崩溃。
  6. **脱链游离物理内存（Headless Physical Memory）**：
     - 引入 `PteHijack_AllocHeadlessPhysicalPage` 原语：通过 `MmAllocatePagesForMdl` 分配物理页并立即销毁虚拟映射与 MDL，切断内核池（NonPagedPool）关联与 Pool Tag 追踪，彻底消除了 Double Mapping（双重映射）与 PFN 异常引用计数特征。
  7. **休眠期原地微混淆（In-Place Ephemeral Obfuscation）**：
     - 引入 `PteHijack_ObfuscatePage`：在休眠期对页面数据执行轻量流加扰，使内存呈现高熵随机态，破坏反作弊特征码比对与指令模式扫描。

- **已知约束与避坑**:
  - `_WritePteAtomic` 必须严守 `MmMapIoSpace` 或 MDL 双重映射机制，严禁在现代 Windows 10/11（开启 VBS/HVCI）环境下尝试修改 `CR0.WP` 寄存器，否则必定触发 Hypervisor 级 BugCheck `0x1E` (`0xC0000096`)。
  - 在翻转 `NoExecute` 位时必须通过原子读写（`InterlockedExchange64`），防止多核并发上下文竞争导致脏写。
  - 游离物理页释放时必须通过预分配的临时 MDL 与 `MmFreePagesFromMdl` 正规归还系统物理链表，严禁直接丢弃导致物理内存泄露。
