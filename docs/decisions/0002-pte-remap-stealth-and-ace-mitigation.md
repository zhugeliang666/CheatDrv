# ADR-0002: PTE Remap 驱动高隐匿性架构改造与反作弊(ACE)规避规范

- **状态**: 部分被替代（第 6 条已被 ADR-0006 替代）
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
  3. **方案 2：纯叶子平栈中继与零 PE 头侵入（彻底删除 .pdata 注入）**：
     - **平栈中继标准（Flat Trampoline / Leaf Only）**：入口中继器严格不分配局部栈帧（零 `sub rsp`，不破坏非易失寄存器），执行完毕后直接调用 `IofCompleteRequest` 并 `ret` 原地平栈返回。x64 展开器查不到 `.pdata` 时默认作为标准 Leaf 函数平滑展开，不发生栈损坏崩溃；
     - **彻底移除 .pdata 合并与注入**：完全裁撤 loader 中拼接 `RUNTIME_FUNCTION` 与合并追加异常表的代码，从根本上杜绝修改宿主 PE 头的 `DataDirectory[EXCEPTION]`，确保宿主 PE 文件头 100% 匹配磁盘原始 Hash；
     - **废弃 tcpip.sys 核心驱动寄生**：默认宿主驱动切回自带 WHQL 签名的合法第三方硬件驱动（`Machenike.sys`），摆脱微软系统网络核心栈的严格审计。
  4. **扩展 IOCTL 协议**：
     - 新增 `IOCTL_PTE_HIJACK_SET_EXEC` (`0x8000200C`) 控制码及 `SET_EXEC_REQUEST` 协议，向应用层受控暴露 JIT 特权切换接口。
  5. **特权属性智能纠偏 (Owner / SMEP 兼容)**：
     - 根据目标虚拟地址动态判定：内核空间（`Va >= 0xFFFF800000000000`）强制锁定 `Owner = 0`（Supervisor 权限），用户空间才允许 `Owner = 1`。杜绝因内核页出现 User 标志而触发反作弊特权错位扫描及硬件 SMEP 崩溃。
  6. **方案 3：切断双重映射与 PFN 伪装（Ghost Pool / Unlink Double Mapping）[已废弃，被 ADR-0006 替代]**：
     - *注：该方式由于在系统大池表 `nt!PoolBigPageTable` 留下常驻分配记录，且清零源 PTE 会导致 `nt!MmPfnDatabase` 产生孤儿页被反作弊启发式扫描检出，已被 [ADR-0006](0006-headless-mdl-pages-and-pool-removal.md) 全面废弃，改由 `MmAllocatePagesForMdl` 纯游离物理页与宿主原生常驻物理页原位复用替代。*
  7. **方案 5：宿主宿位选型优化（首选显卡/DirectX驱动，弃用 .rsrc，借用 Discardable / INIT 节）**：
     - **显卡大驱动寄生机制**：首选独立显卡驱动（NVIDIA `nvlddmkm.sys` 50~110MB / AMD `amdkmdag.sys` 30~80MB）、核显驱动（Intel `igdkmd64.sys`）以及 DirectX 内核图形引擎（`dxgkrnl.sys` 10~20MB）。显卡驱动体积极其庞大，反作弊引擎因性能 KPI 限制绝不敢对其执行全盘周期性哈希深扫；
     - **节区搜索策略**：优先寻找 `INIT` 节或带有 `IMAGE_SCN_MEM_DISCARDABLE` (`0x02000000`) 属性的可丢弃节区。由于系统在驱动初始化完毕后原生回收 `INIT` 节，反作弊引擎对可丢弃节豁免磁盘比对（规避海量误报）；
     - **彻底拉黑 .rsrc**：彻底摒弃 `.rsrc` 节，杜绝污染白驱动资源目录树引发 ACE 资源完整性审计告警。
  8. **休眠期原地微混淆（In-Place Ephemeral Obfuscation）**：
     - 引入 `PteHijack_ObfuscatePage`：在休眠期对页面数据执行轻量流加扰，使内存呈现高熵随机态，破坏反作弊特征码比对与指令模式扫描。
  9. **系统级反转函数表无侵入接管（nt!PsInvertedFunctionTable Hooking）**：
     - **核心目的**：真正达成“零改动磁盘/PE头，又能完美支持深层堆栈回溯”；
     - **定位算法**：摒弃易碎的机器码特征码，采用启发式内存结构指纹扫描（Heuristic Structural Scan），利用单调递增性与内核地址属性在 `ntoskrnl.exe` 的 `.data` 节全版本精准定位；
     - **挂接机制**：通过 `InvertedTable_HookHost` 原子替换宿主驱动节点的 `ExceptionDirectory` 指向合并后的 `.pdata`。ACE/系统 NMI 抓栈时直接沿内核全局反转表平滑回溯，杜绝任何 Corrupted Stack 告警，且宿主 PE 头保持 100% 原始未篡改状态。

- **已知约束与避坑**:
  - `_WritePteAtomic` 必须严守 `MmMapIoSpace` 或 MDL 双重映射机制，严禁在现代 Windows 10/11（开启 VBS/HVCI）环境下尝试修改 `CR0.WP` 寄存器，否则必定触发 Hypervisor 级 BugCheck `0x1E` (`0xC0000096`)。
  - 在翻转 `NoExecute` 位时必须通过原子读写（`InterlockedExchange64`），防止多核并发上下文竞争导致脏写。
  - 游离物理页释放时必须通过预分配的临时 MDL 与 `MmFreePagesFromMdl` 正规归还系统物理链表，严禁直接丢弃导致物理内存泄露。
  - 严禁对含有数字签名或有效资源目录的 `.rsrc` 节执行任何 PTE Remap 操作。
  - 严禁将 `tcpip.sys` 作为常规 Remap 宿主，系统核心网络驱动受到 PatchGuard 与反作弊内核哈希扫描器的双重交叉监控。
