# ADR-0042: 游离物理页(MDL)挂接宿主节区与彻底根除 BugCheck 0x1E (STATUS_ILLEGAL_INSTRUCTION #UD) 蓝屏

- **状态**: 已采纳
- **日期**: 2026-10-19
- **上下文与痛点**:
  在分析 `101926-7656-01.dmp` 蓝屏转储文件时，捕获到 BugCheck `0x1E (KMODE_EXCEPTION_NOT_HANDLED)`，异常状态码为 `0xC000001D (STATUS_ILLEGAL_INSTRUCTION)`。
  故障地址发生在宿主驱动节区内 (`amdkmdag.sys + 0x614100E`，即 `payloadTargetVA + 0x100E`)。
  现场 TrapFrame 与调用栈取证分析确认：
  - 白驱动现场保护、Code Cave 挂接、用户态缓冲区直读以及入口调用全链路完全顺畅；
  - 但操作系统在驱动初始化完成后，会将 `.reloc` / `INIT` 等 Discardable 节区卸载，其对应的 PTE 处于全零（未映射）或未 Present 状态 (`PFN == 0`)；
  - 原代码在检测到 `allPresent = false` 时，粗暴执行 `PTE |= (PTE_PRESENT | PTE_RW)`，导致 PFN 被硬生生写入 `0`（指向系统物理内存地址 `0x00000000` 保留区/全零页）；
  - 内核 Shellcode 执行 `rep movsb` 将镜像写入物理地址 `0x0`（不可持久写入或为全零），CPU 随后跳转到 DriverEntry（`0xFFFFF803C2DC1000`）执行全零操作码（`00 00` = `add [rax], al`），累加执行至 `+0x0E` 时由于操作码冲突触发 `#UD`（非法指令异常），引发 BugCheck `0x1E`。

- **技术决策与规范**:
  1. **放弃“假设宿主 Discardable 节区自带常驻物理页”的逻辑**，引入纯游离物理页分配原语 (`MmAllocatePagesForMdl`)。
  2. **81 字节微型探针 Shellcode (`scAllocMdlProbe`)**：
     - 利用白驱动默认分支单次触发调用 `MmAllocatePagesForMdl(0, 0xFFFFFFFFFF, 0, imageSize)`；
     - 申请脱离系统虚拟地址池（NonPagedPool）的纯净物理内存页，在系统大池表（`PoolBigPageTable`）与内核全局 Pool 链表中 100% 零登记痕迹；
     - 探针将分配到的 `pMdl` 存入参数块，恢复全部非易失性寄存器，设置白驱动状态码 `ebx = 0 (STATUS_SUCCESS)`，平稳跳回白驱动默认分支完成 IRP。
  3. **用户态页表缝合 (`InjectPayloadIntoHost`)**：
     - 从 `pMdl + 0x30` 读取 52 个由系统内核分配的合法物理页帧号（`PFN`）；
     - 遍历目标节区的 52 个虚拟页，按页调用 `GetPtePhysAddr` 定位对应的 PTE 物理地址（防御性避开跨 2MB PDE 边界问题）；
     - 写入合法 PFN 与属性：`newPte = (pagePA & PTE_PFN_MASK) | PTE_PRESENT | PTE_RW | PTE_ACCESSED | PTE_DIRTY | PTE_GLOBAL`；
     - 调用 `ArePagesPresent` 强校验 52 个页全部呈现（Present = 1，PFN != 0）。
  4. **极简硬件 Shellcode 极速直拷**：
     - 结合 ADR-0041 的 214 字节纯硬件 Shellcode，`invlpg` 逐页刷新这 52 个页的本地 TLB 缓存；
     - `rep movsb` 3 微秒瞬时将用户态已锁定的镜像直拷进这 52 个合法物理页；
     - 构造伪 `DRIVER_OBJECT` 并直调 DriverEntry，启动核心驱动。

- **已知约束与避坑**:
  1. **严禁对 PFN 为 0 的 PTE 盲目置位 Present**：Windows 对丢弃节区的 PTE 往往置 0，盲目 `PTE |= 0x3` 会直接映射到物理地址 0，导致执行全零指令或总线写丢弃，触发 `#UD` 蓝屏。
  2. **页表定位必须逐页解算**：驱动载荷通常跨越数十个页（约 200KB），可能跨越 2MB PDE 页目录边界；必须逐页通过 `GetPtePhysAddr` 获取真实 PTE 物理地址，严禁基于首个 PTE 物理地址做无界连续内存覆盖。
  3. **微型探针平栈与寄存器契约**：调用内核 API 前后必须严格保持 16 字节栈对齐，保留 32 字节 Shadow Space，成对恢复 `r15..r12, rdi, rsi, rbx`，跳回白驱动原位时必须传递合法状态码（`ebx = 0`）。
  4. **fakeDriverObj 模块链表指针 (DriverSection) 严禁为 NULL**：在分析 `101926-6765-01.dmp` 时捕获到 BugCheck `0x1E (STATUS_ACCESS_VIOLATION 0xC0000005)`，根因为 `BuildShellcodeParams` 漏赋 `whqlLdrEntryVA`，导致 `fakeDriverObj->DriverSection == NULL`，驱动入口在 `MachenikeUserVarInit` 遍历双向链表时解引用 `[r15] (0x0)` 崩溃。修复方案为显式传递 `whqlLdrEntryVA`，并以 `triggerLdrEntryVA` 与 `psLoadedModList` 双重兜底，且在驱动端加入非空强校验阻断裸解引用。
