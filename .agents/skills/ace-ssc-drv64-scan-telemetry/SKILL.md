---
name: ace-ssc-drv64-scan-telemetry
description: >
  ACE (Anti-Cheat Expert) 核心驱动 ACE-SSC-DRV64.sys 全量原生代码函数 (.text/PAGE/INIT 共 102 个实体函数) 逆向解构与反编译分析。
  包含 RDTSC 时钟差 EPT 影子页探测 (sub_1400164E5)、ETW/ETW-TI 内核事件追踪与遥测、自旋锁工作队列、Slab 内存池调度、MDL 写保护穿透、MmMapIoSpace 物理映射、CR3 页表蓝屏校验、ObReferenceObjectByName 对象审计、多版本 EPROCESS 解析、PAGE 段低频业务与 DriverEntry 的全量代码逆向与对抗规避规范。
---

# ACE-SSC-DRV64.sys 扫描与遥测核心驱动全量原生函数 (.text / PAGE / INIT) 深度逆向与规避指南

## 1. 模块总架构与节区拓扑

`ACE-SSC-DRV64.sys` 是腾讯 ACE 反作弊体系中负责**内核态态势感知、底层威胁扫描、未导出句柄审计、硬件虚拟化对抗与系统级 ETW 遥测上报**的核心执行体。模块基址 `0x140000000`。
全驱动代码严格划分为两大部分：
1. **`.tvm0` 虚拟化混淆段**：采用 TVM 虚拟机保护的核心加固逻辑；
2. **原生代码段（`.text` / `PAGE` / `INIT`）**：共 **307 个原生代码条目**，其中 **102 个实质性业务与防护逻辑函数**、150 余个 Native-to-TVM 跳转跳板（5 字节 `jmp .tvm0:xxx`）及 50 余个 `int 3` 调试对齐陷阱。

```
                       [ 驱动加载入口 DriverEntry (0x14001F000) ]
                                         │
                                         ▼
                [ .tvm0 虚拟机主调度入口 DriverEntry_0 (0x1400852B3) ]
                                         │
            ┌────────────────────────────┼────────────────────────────┐
            ▼                            ▼                            ▼
  [ .tvm0 核心解释器 ]          [ 150+ Native-to-TVM 跳板 ]   [ 原生 102 个实体业务函数 ]
     sub_1400B50C8                  sub_140001000...            .text (67个) / PAGE (34个) / INIT (1个)
  (810KB 字节码解释引擎)         (5字节 jmp 蹦床桩)             (EPT时钟差/ETW/自旋锁/内存池/句柄审计)
```

---

## 2. 原生函数总体分布

| 节区 | 虚拟地址范围 | 实质性逻辑函数 | 跳转跳板 (Stubs) | 核心功能定位 |
| :--- | :--- | :---: | :---: | :--- |
| **`.text`** | `0x140001000 - 0x140016F1D` | **67 个** | 150 余个 | 常驻非分页高频防护：EPT 时钟差探测、ETW 遥测、自旋锁队列、内存池、对象审计、加解密 |
| **`PAGE`** | `0x14001D000 - 0x14001EC43` | **34 个** | 0 个 | 可分页低频业务：设备对象配置、IRP 低频控制、注册表/文件环境交互、系统服务包装 |
| **`INIT`** | `0x14001F000 - 0x140020222` | **1 个** | 0 个 | 初始化丢弃段：驱动主入口 `DriverEntry`，构建设备对象与启动安全哨兵 |

---

## 3. 核心功能子系统深度解构与反编译源码

### 3.1 硬件虚拟化与 EPT / 影子页表对抗子系统（王牌检测）
这是 ACE 对抗 VT-x / SVM Hypervisor、影子页表及 EPT Hook 的最核心底层例程：

* **`sub_1400164E5` (0x1400164E5, 57 字节) —— RDTSC 时钟差 EPT 违例探测**
  ```x86asm
  sub_1400164E5 proc near
      push    rbp
      mov     rbp, rsp
      push    rbx
      cli                     ; 1. 关中断，阻断线程调度引起的时钟抖动
      invlpg  byte ptr [rcx]  ; 2. 强制失效目标页面的 TLB 映射
      lfence                  ; 3. 内存屏障，序列化 CPU 指令流水线
      rdtsc                   ; 4. 读取起始 CPU 周期时间戳
      lfence
      shl     rdx, 20h
      or      rax, rdx
      mov     rbx, rax        ; rbx 保存进入时钟
      mov     rax, [rcx]
      call    rcx             ; 5. 调用目标函数 (若被 EPT 影子页分离挂钩，将强行触发硬件 VM-Exit)
      lfence
      rdtsc                   ; 6. 读取退出 CPU 周期时间戳
      lfence
      shl     rdx, 20h
      or      rax, rdx
      sub     rax, rbx        ; 7. rax = 执行消耗的时钟周期 Delta
      sti                     ; 8. 开中断
      pop     rbx
      mov     rsp, rbp
      pop     rbp
      ret
  sub_1400164E5 endp
  ```
  * **对抗原理**：在裸机上执行 `call rcx` 仅耗时数十周期；而当 Hypervisor 对 `rcx` 所在页设置了 EPT Violation（如执行页与读写页分离）时，CPU 必须触发 **VM-Exit**。VM-Exit 进出硬件切换消耗 1,500 ~ 3,000 周期。函数通过周期差阈值，100% 精确检测目标页是否存在 EPT 影子页劫持。
* **`sub_14001651E` (0x14001651E, 16 字节) —— 裸调用执行跳板**
  构建干净的微型栈帧，为 EPT 时钟差探测提供纯净执行环境，阻断调用栈回溯污染。

---

### 3.2 ETW / ETW-TI 内核事件追踪与威胁遥测子系统
直接采用未虚拟化原生函数实现，确保在高 IRQL 及异常崩溃时能够无阻碍地向 Windows ETW 通道发送遥测：

* **`sub_140002B90` (0x140002B90, 16 字节) —— `EtwRegister` 封装**
  向内核注册 ACE 专属 ETW Provider GUID，绑定内核追踪回调：
  ```c
  NTSTATUS __fastcall sub_140002B90(const GUID *ProviderGuid, ETWENABLECALLBACK EnableCallback, void *CallbackContext, REGHANDLE *RegHandle) {
      if (*RegHandle != 0) return STATUS_SUCCESS;
      return EtwRegister(ProviderGuid, EnableCallback, CallbackContext, RegHandle);
  }
  ```
* **`sub_140002BA0` (0x140002BA0, 44 字节) —— `EtwUnregister` 封装**
  注销内核事件追踪 Provider，安全释放注册句柄：
  ```c
  NTSTATUS __fastcall sub_140002BA0(REGHANDLE *pRegHandle) {
      REGHANDLE hReg = *pRegHandle;
      if (hReg == 0) return STATUS_SUCCESS;
      NTSTATUS status = EtwUnregister(hReg);
      *pRegHandle = 0;
      return status;
  }
  ```
* **`sub_140002A80` (0x140002A80, 270 字节) —— 事件数据描述符构建器**
  将搜集到的进程上下文、作弊特征码、时间戳等组装打包为 `EVENT_DATA_DESCRIPTOR`。
* **`sub_140002BD0` (0x140002BD0, 84 字节) —— `EtwWrite` 遥测推送器**
  向 Windows 安全审计事件流写入安全事件。
* **`sub_140002C30` (0x140002C30, 72 字节) —— `EtwWriteTransfer` 关联链路追踪**
  向 ETW 发送附带 ActivityId 的事件包，将内核态拦截动作与用户态上报进程进行链路串联。

---

### 3.3 多核同步与自旋锁安全工作队列
* **`sub_140001680` (0x140001680, 176 字节) —— 自旋锁安全单链表入队器**
  ```c
  void __fastcall sub_140001680(_QWORD *ListHead, __int64 ContextData, KSPIN_LOCK *SpinLock) {
      _QWORD *Node = ExAllocatePoolWithTag(NonPagedPoolNx, 0x20u, 'EcaS');
      if (Node) {
          Node[1] = ContextData;
          KIRQL OldIrql = KeAcquireSpinLockRaiseToDpc(SpinLock); // 提升至 DISPATCH_LEVEL
          *Node = *ListHead;
          *ListHead = Node;
          KeReleaseSpinLock(SpinLock, OldIrql);
      }
  }
  ```
* **`sub_140006F40` (0x140006F40, 59 字节) —— 自旋锁安全释放与 IRQL 恢复**
  原子清除锁标志并恢复进入临界区前的原始 IRQL。

---

### 3.4 动态安全内存池调度器 (原生最大函数)
* **`sub_140002C80` (0x140002C80, 1031 字节)**：
  * 实现专用的轻量级安全 Slab 内存池切片调度算法；
  * 调用 `ExAllocatePoolWithTag` 申请非分页内存块，并在内部进行分块切片与位图标记；
  * **对抗目的**：规避频繁调用系统内存分配 API 在 BigPool 审计链表中留下过多分配特征与 Tag 痕迹。

---

### 3.5 内存写保护穿透与物理映射子系统
* **`sub_140015BE0` (0x140015BE0, 205 字节) —— MDL 强写内核只读内存**
  不修改 `CR0.WP`，原生兼容 HVCI/VBS 的写保护穿透原语：
  ```c
  struct _MDL *__fastcall sub_140015BE0(void *TargetVa, char ByteVal) {
      struct _MDL *pMdl = IoAllocateMdl(TargetVa, 0x1000u, 0, 0, nullptr);
      if (pMdl) {
          MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
          PVOID pWritable = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, nullptr, 0, 0x10u);
          if (pWritable) {
              *(_BYTE *)pWritable = ByteVal; // 建立无缓存物理映射覆写目标内存
              MmUnmapLockedPages(pWritable, pMdl);
          }
          MmUnlockPages(pMdl);
          IoFreeMdl(pMdl);
      }
      return pMdl;
  }
  ```
* **`sub_14000A370` (0x14000A370, 635 字节) —— 物理内存直接映射 (MmMapIoSpace)**
  校验目标物理地址有效性，调用 `MmMapIoSpace` 直接对系统物理 RAM 进行底层页表巡检。

---

### 3.6 CR3 页表异常校验与主动蓝屏惩罚
* **`sub_140011B60` (0x140011B60, 612 字节) —— CR3 与物理地址一致性核验**
  比对当前进程 CR3/PML4 物理地址基准。若检测到异常页表篡改、影子 CR3 或非法 Hook，调用 `KeBugCheckEx(0xDEADDEAD, ...)` 强行崩溃停机。
* **`sub_140016780` (45 字节) / `sub_1400167C0` (47 字节)**：`KeBugCheckEx` 致命违规停机调度入口。

---

### 3.7 进程、线程与对象拓扑审计
* **`sub_140006570` (0x140006570, 206 字节) —— `PsLookupProcessByProcessId` 封装**
  安全将外部 PID 解析为 `PEPROCESS`，动态适配 Win7/Win8/Win10/Win11 各版本偏移，提取退出状态后自动解引用。
* **`sub_1400064C0` (0x1400064C0, 168 字节) —— 进程退出同步与链表校验**
  配合 `PsAcquireProcessExitSynchronization` 校验目标进程生命周期安全。
* **`sub_140010250` (0x140010250, 595 字节) —— `ObReferenceObjectByName` 驱动对象审计**
  动态提取底层驱动对象（如 `\Driver\Disk`、`\Device\PhysicalMemory`），比对 `MajorFunction` 派遣表是否指向异常未认证模块。
* **`sub_1400071C0` (0x1400071C0, 107 字节)**：严格内存指针校验，封装 `MmIsAddressValid` 与高位非规范地址探测。

---

### 3.8 PAGE 节区 34 个分页函数架构
`PAGE` 节区（`0x14001D000 - 0x14001EC43`）包含 34 个低频管理函数：
1. **设备与符号链接管理**：配置驱动对外暴露的命名管道与设备对象，设置安全描述符 (SDDL)；
2. **IRP 低频分发与清理**：处理 `IRP_MJ_CREATE`、`IRP_MJ_CLEANUP` 与 `IRP_MJ_CLOSE` 生命周期；
3. **注册表与配置持久化**：调用 `ZwOpenKey` / `ZwQueryValueKey` 查询反作弊策略与游戏黑名单。

---

### 3.9 INIT 节区 DriverEntry (0x14001F000)
驱动原生主入口点，执行基础系统初始化：
1. 配置 `MajorFunction` 基础调度数组；
2. 创建内核同步自旋锁与互斥体；
3. 跳转移交控制权至 `.tvm0` 虚拟机主调度入口 `DriverEntry_0`（`0x1400852B3`）。

---

## 4. 全量 102 个实质性原生函数检索矩阵

| 序号 | 虚拟地址 (VA) | 函数名 | 节区 | 代码大小 | 功能归属 | 核心功能定位与实现摘要 |
| :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| 1 | `0x140001390` | `nullsub_1` | `.text` | 3 B | 辅助存根 | 空操作返回存根，为默认未实现分支返回 STATUS_SUCCESS |
| 2 | `0x140001680` | `sub_140001680` | `.text` | 176 B | 多核同步 | 自旋锁保护的非分页安全异步事件节点入队分配器 |
| 3 | `0x140002a80` | `sub_140002A80` | `.text` | 270 B | ETW 遥测 | 构建 `EVENT_DATA_DESCRIPTOR` 并封装上下文数据 |
| 4 | `0x140002b90` | `sub_140002B90` | `.text` | 16 B | ETW 遥测 | 调用 `EtwRegister` 注册 ACE 内核事件追踪提供者 |
| 5 | `0x140002ba0` | `sub_140002BA0` | `.text` | 44 B | ETW 遥测 | 调用 `EtwUnregister` 注销内核事件追踪 Provider |
| 6 | `0x140002bd0` | `sub_140002BD0` | `.text` | 84 B | ETW 遥测 | 调用 `EtwWrite` 向安全审计通道提交违规事件 |
| 7 | `0x140002c30` | `sub_140002C30` | `.text` | 72 B | ETW 遥测 | 调用 `EtwWriteTransfer` 发送带 ActivityId 链路事件 |
| 8 | `0x140002c80` | `sub_140002C80` | `.text` | 1031 B | 内存池 | 驱动核心 Slab 内存池切片调度与大块分配器 |
| 9 | `0x1400064c0` | `sub_1400064C0` | `.text` | 168 B | 进程线程 | 进程/线程双向链表拓扑与魔数完整性校验 |
| 10 | `0x140006570` | `sub_140006570` | `.text` | 206 B | 进程线程 | `PsLookupProcessByProcessId` 安全获取并引用目标进程 |
| 11 | `0x140006df0` | `sub_140006DF0` | `.text` | 186 B | 安全校验 | 内核特征段 CRC/循环位移哈希校验算法 |
| 12 | `0x140006f40` | `sub_140006F40` | `.text` | 59 B | 多核同步 | 执行体自旋锁释放与原始 IRQL 恢复 |
| 13 | `0x1400071c0` | `sub_1400071C0` | `.text` | 107 B | 对象句柄 | `ObDereferenceObject` 安全解引用封装与空指针阻断 |
| 14 | `0x140007780` | `sub_140007780` | `.text` | 38 B | 硬件状态 | 读取处理器控制块 (KPCR) 获取当前 CPU 编号与上下文 |
| 15 | `0x14000a370` | `sub_14000A370` | `.text` | 635 B | 物理内存 | `MmMapIoSpace` 物理 RAM 映射与页表特征深度巡检 |
| 16 | `0x140010250` | `sub_140010250` | `.text` | 595 B | 对象审计 | `ObReferenceObjectByName` 动态审计驱动派遣例程 |
| 17 | `0x140011b60` | `sub_140011B60` | `.text` | 612 B | 页表校验 | CR3 与 PML4 物理基准比对，异常触发 BugCheck 蓝屏 |
| 18 | `0x140015be0` | `sub_140015BE0` | `.text` | 205 B | 内存写入 | `IoAllocateMdl` + `MmMapLockedPages` 穿透只读内存写代码 |
| 19 | `0x1400164e5` | `sub_1400164E5` | `.text` | 57 B | EPT 对抗 | `cli -> invlpg -> rdtsc -> call -> rdtsc -> sti` 时钟差探测 |
| 20 | `0x14001651e` | `sub_14001651E` | `.text` | 16 B | EPT 对抗 | EPT 探测专属裸执行栈跳板例程 |
| 21 | `0x140016780` | `sub_140016780` | `.text` | 45 B | 崩溃惩罚 | 致命安全违规 `KeBugCheckEx` 停机入口 A |
| 22 | `0x1400167c0` | `sub_1400167C0` | `.text` | 47 B | 崩溃惩罚 | 致命安全违规 `KeBugCheckEx` 停机入口 B |
| 23 | `0x14001f000` | `DriverEntry` | `INIT` | 260 B | 生命周期 | 驱动原生初始化主入口点与设备对象构建 |
| ... | ... | ... | ... | ... | ... | *(全部 102 个函数已在 NON_VM_FUNCTIONS_COMPLETE_ANALYSIS.md 中逐行收录)* |

---

## 5. 对抗与规避工程实践指南

| 检测点 (ACE 原生例程) | 底层检测机制 | 规避加固策略 |
| :--- | :--- | :--- |
| **`sub_1400164E5`** | `rdtsc` 测量 VM-Exit 时钟差探测 EPT Hook | 1. 拦截 `RDTSC` / `RDTSCP` 的 VM-Exit 并补偿时间差；<br>2. 调整 VMCS 中 `RDTSC_OFFSET` 抵消 VM-Exit 损耗；<br>3. 或在执行阶段采用硬件执行页重映射（无须触发时钟差异常）。 |
| **`sub_140011B60`** | CR3 与 PML4 物理基址比对蓝屏 | 严禁在 Guest 内部直接修改 CR3，必须在 Hypervisor EPT/NPT 层面透明重映射。 |
| **`sub_140015BE0`** | MDL 无缓存映射强制覆写内核代码 | 在 EPT 层面配置只读或无写权限，捕获其非法写入操作。 |
| **`sub_140002BD0`** | ETW 内核遥测威胁事件推送 | 通过挂接 ETW 过滤层拦截特定 Provider GUID 发送的敏感作弊告警包。 |
| **`sub_140010250`** | `ObReferenceObjectByName` 驱动派遣表审计 | 严禁直接 Hook `\Driver\Disk` 等核心驱动的 MajorFunction，改用底层硬件直连或过滤设备挂接。 |
