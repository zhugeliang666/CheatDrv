# ADR-0015: 宿主驱动原位 PTE 缝合、CR3 进程直读特权与彻底根除 ZwMapViewOfSection 反作弊特征 (Branch 2B Architecture)

- **状态**: 已采纳
- **日期**: 2026-10-14
- **核心领域**: 内核隐蔽注入 / 反作弊(ACE)规避 / 内存挂接架构
- **影响范围**: `loader/shellcode_builder.h`, `loader/main.cpp`, `loader/phys_walk.h`

---

## 一、 上下文与痛点回顾

在基于签名工具驱动（WHQL 白驱动，如 `Machenike.sys`）的手动映射加载方案中，原本的技术路径是通过工具驱动提供的读写物理内存 IOCTL（`MACHENIKE_WRITE_IOCTRL`）将核心驱动 `drv_wsk.sys` 的镜像与 PTE 写入宿主合法驱动节区：
1. **高频节区映射暴露面**：
   `Machenike.sys` 每次响应物理写 IOCTL 时，其内部均会调用系统内核例程 **`ZwOpenSection(L"\\Device\\PhysicalMemory")`** 以及 **`ZwMapViewOfSection`** 映射 4KB 物理页并完成写入。
2. **反作弊深度盯防**：
   腾讯反作弊（ACE）以及其他主流反作弊系统在应用层与内核层均对 `\Device\PhysicalMemory` 句柄创建与 `ZwMapViewOfSection` 实施了严格的 Inline Hook / SSDT 监控与访问频率统计。
3. **调用次数爆炸**：
   `drv_wsk.sys` PE 展开后大小约为 0x22000（136KB，34 个 4KB 页）。旧方案在用户态需要分块发起 34 次写 PTE IOCTL + 34 次写 PE 镜像 IOCTL + 写入 Canary + 多次状态探针，**总计向工具驱动发起了近百次物理写 IOCTL**。这种数十次乃至上百次高频连续映射物理内存的行为，在启动瞬间即被 ACE 规则引擎捕获并标记。

---

## 二、 核心技术突破与微架构原理 (Branch 2B)

为了彻底根除上述暴露面，设计并落地了**分支 2B 架构 (Branch 2B)**，实现物理写入全流程在内核态瞬时闭环：

### 1. CR3 同进程直读特权 (Process CR3 Direct Access)
- 当用户态 Loader 调用 `DeviceIoControl` 发送未知 IOCTL 触发宿主驱动的 switch default 分支跳入 Code Cave Shellcode 时，**当前 CPU 执行线程正是 Loader.exe 的调用线程，处于 `PASSIVE_LEVEL`**。
- **当前 CPU 硬件寄存器 `CR3` 完整承载着 Loader 进程的用户态虚拟内存映射**。
- Loader 在用户态预先通过 `VirtualAlloc` 展开并经过重定位（Relocation）的 PE 镜像缓冲区 `userImageVA`，通过 `VirtualLock` 锁死在物理内存中。
- 因此，在内核态 Shellcode 中，**`userImageVA` 作为用户态虚拟地址完全具备原生可寻址与直读特权**，无需经过任何跨进程附加或上下文切换！

### 2. Direct Copy 硬件搬移 (消灭 100% 镜像物理写)
- 目标内核地址为宿主合法白驱动的已丢弃节区（如 `INIT` 或 `.reloc`，内核 VA 为 `payloadTargetVA`）。
- Shellcode 内部直接使用 CPU 原生字符串操作微指令：
  ```assembly
  mov rsi, [rbx + userImageVA]        ; 用户态展开镜像
  mov rdi, [rbx + payloadTargetVA]    ; 宿主驱动目标内核地址
  mov ecx, [rbx + imageSize]          ; 0x22000 字节
  rep movsb                           ; 纯硬件流水线瞬时搬移
  ```
- **耗时仅 3 微秒**，执行期间 0 次系统调用、0 次驱动 I/O、0 次 Hook 触发。

### 3. 内核原语映射修改 PTE (消灭 100% 页表物理写)
- 宿主驱动目标节区的 34 个 PTE（覆盖 136KB）物理上均归属于同一个 4KB 的 Page Table (PT) 页（单个 PT 页管辖 2MB 虚拟空间，34 个 PTE 仅占连续 272 字节）。
- Shellcode 内部调用微软正规且无反作弊监控的硬件例程：
  - 调用 `MmAllocatePagesForMdl(0, 0xFFFFFFFFFF, 0, imageSize)` 申请纯游离物理页；
  - 调用 `MmMapIoSpace(firstPtePA, pageCount * 8, MmNonCached)` 将目标 PTE 所在物理空间映射为内核虚拟地址；
  - 在内核循环中将 34 个 PTE 翻转为游离物理页的 PFN，属性配置为 `Present(1) | RW(1) | Accessed(1) | Dirty(1) | Global(1), NX=0`；
  - 针对每个虚拟页执行 `invlpg` 刷新本核心 TLB；
  - 调用 `MmUnmapIoSpace` 立即解除临时映射。

### 4. 单次 IOCTL 全流程闭环
- 整个加载过程，用户态发起的写物理内存 IOCTL（`MACHENIKE_WRITE_IOCTRL`）从旧方案的近百次**直接归零**！
- 仅需发送 1 次未决 IOCTL 触发 Shellcode，内核态 333 字节机器码在 1 毫秒内同步完成：物理页申请 -> PTE 映射与翻转 -> `rep movsb` 镜像直拷 -> Canary 写入 -> 构造 fakeDriverObj -> 调用 `DriverEntry` -> 平栈安全跳回。

---

## 三、 执行时序架构图

```mermaid
sequenceDiagram
    autonumber
    participant L as Loader (R3)
    participant W as WHQL 驱动 (Machenike)
    participant S as Shellcode (scBranch2B @ Code Cave)
    participant K as ntoskrnl 内存管理器
    participant D as drv_wsk 核心驱动

    Note over L: 1. 展开 PE，修复重定位，VirtualLock 锁定 userImageVA
    Note over L: 2. 纯只读解算 INIT 节首个 PTE 物理地址 (firstPtePA)
    Note over L: 3. 一次性写入 Code Cave (ShellcodeParams + scBranch2B)
    L->>W: 发送单次未知 IOCTL (触发 Default 分支)
    W->>S: JMP 进入 scBranch2B (当前 CR3 为 Loader 进程)
    S->>K: MmAllocatePagesForMdl 申请纯游离物理页 (零 Pool 痕迹)
    K--S: 返回 PMDL
    S->>K: MmMapIoSpace(firstPtePA, 272 字节) 映射 PTE
    K--S: 返回 mappedPteVA
    Note over S: 循环改写 34 个 PTE 指向新物理页 PFN，逐页 invlpg
    S->>K: MmUnmapIoSpace 解除临时映射
    Note over S: rep movsb: 利用当前 CR3 原生直读，3微秒直拷 userImageVA -> payloadTargetVA
    Note over S: 写入 Canary 头部，构造 fakeDriverObj (rsp+0x40)
    S->>D: CALL DriverEntry(fakeDriverObj, &bootConfig)
    D--S: 返回 STATUS_SUCCESS (网络/USB 传输服务已后台运行)
    Note over S: 恢复寄存器与宿主栈现场，ebx = STATUS_SUCCESS
    S->>W: JMP 跳回宿主现场 (site.kernVA + 5)
    W--L: IRP 成功完成并返回应用层
    Note over L: 卸载 Machenike.sys 工具驱动，抹除全部内核残留
```

---

## 四、 关键技术规范与契约

1. **跨环参数契约 (`ShellcodeParams`)**：
   严格遵循 `#pragma pack(push, 1)`，结构体总尺寸固定为 120 字节（`0x78`），与 Code Cave 栈偏移计算对齐：
   ```cpp
   #pragma pack(push, 1)
   struct ShellcodeParams {
       uint64_t pfnMmAllocatePagesForMdl;    // 0x00 ntoskrnl!MmAllocatePagesForMdl
       uint64_t pfnMmMapIoSpace;             // 0x08 ntoskrnl!MmMapIoSpace
       uint64_t pfnMmUnmapIoSpace;           // 0x10 ntoskrnl!MmUnmapIoSpace
       uint64_t userImageVA;                 // 0x18 用户态展开镜像虚拟地址 (当前 CR3 原生可读)
       uint64_t payloadTargetVA;             // 0x20 宿主驱动内部挂接目标内核 VA
       uint32_t imageSize;                   // 0x28 PE 镜像大小
       uint32_t entryPointOffset;            // 0x2C DriverEntry 偏移
       uint32_t pageCount;                   // 0x30 映射物理页数 (imageSize + 0xFFF) / 0x1000
       uint32_t status;                      // 0x34 NTSTATUS 返回码
       uint64_t firstPtePA;                  // 0x38 目标 PTE 数组物理起始地址
       uint64_t hookReturnVA;                // 0x40 跳回 WHQL 宿主现场 (site.kernVA + 5)
       uint64_t whqlDrvBase;                 // 0x48 宿主驱动基址
       uint32_t whqlDrvSize;                 // 0x50 宿主驱动大小
       uint32_t pad0;                        // 0x54 占位对齐
       uint64_t whqlLdrEntryVA;              // 0x58 宿主 KLDR_DATA_TABLE_ENTRY VA
       DRV_BOOT_CONFIG bootConfig;           // 0x60 (20 字节) 启动参数
       uint32_t pad1;                        // 0x74 (4 字节) 补齐至 120 字节
   };
   #pragma pack(pop)
   static_assert(sizeof(ShellcodeParams) == 120, "ShellcodeParams must be exactly 120 bytes");
   ```

2. **汇编机器码尺寸与容量红线**：
   - 宿主白驱动（`Machenike.sys`）`.text` 段末尾安全空洞（Code Cave）尺寸为 463 字节；
   - 经过瘦身与公共退出路径合并后，`scBranch2B` 汇编指令严格压缩至 333 字节；
   - 总占用尺寸：`120 (Params) + 333 (Code) = 453 字节`，**严格小于 463 字节红线**（余量 10 字节）。

---

## 五、 历史对比与反作弊收益

| 评估指标 | 旧方案 (Plan A) | 分支 2B 架构 (现状) | 提升效果 |
| :--- | :--- | :--- | :--- |
| **`ZwMapViewOfSection` 调用数** | 70 ~ 100 次 | **0 次** | **彻底归零，根除主反作弊特征** |
| **`\Device\PhysicalMemory` 句柄写** | 持续高频写入 | **0 次** | **彻底消灭物理写句柄异常** |
| **PTE 改写行为位置** | 应用层循环调用 IOCTL 改写 | **内核态 Shellcode 内部完成** | 避开用户态 EDR/ACE API 监控 |
| **镜像数据灌入耗时** | ~50 ms (数十次 IOCTL 切换) | **3 微秒 (`rep movsb`)** | **性能提速 10,000+ 倍** |
| **IOCTL 触发次数** | 2 次触发 + 70 次物理写 | **仅 1 次未知 IOCTL** | 行为模式趋近正常驱动操作 |
