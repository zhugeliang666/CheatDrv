---
name: ace-ipi-sync-detection
description: >
  ACE (Anti-Cheat Expert) 跨多核心 IPI (Inter-Processor Interrupt) 同步检测全量分析。
  包含 44 个核心详解与全量子系统 382 个归属函数完整拓扑索引、KeIpiGenericCall 调度机制、CR8 提升至 0xF、多核无锁环形队列、CR4 PGE 刷新 TLB、\Device\PhysicalMemory 物理内存节区映射、x64 四级暗影页表自遍历 (PML4/PDPT/PD/PT/PTE)、物理 PTE 原子改写、2MB 大页构建与 iretq 硬件中断陷阱暗影切换。
---

# ACE 内核跨核心 IPI 同步与瞬时状态感知全量函数深度分析

## 1. 架构总览与全核同步执行拓扑

为了抵御基于单核心亲和性（Thread Affinity）的内核 Hook、CR3 伪造与虚假页表欺骗，ACE 驱动通过系统底层硬件中断 `KeIpiGenericCall` 强制所有 CPU 逻辑核心在同一微秒级时刻暂停当前任务，同步进入特权中断上下文。

```
[IPI 事务发起与会话申请]
       │
       ├─► sub_14001C38C (扫描全局位图 byte_140148770，分配 1~254 的 Transaction ID)
       ├─► sub_14001C5D0 (发送 0x2000... 命令设置目标核心槽位)
       │
[全核硬件中断广播与同步挂起]
       ├─► sub_14001C640 (主调度例程: 打包 0x3000... 命令，调用 KeIpiGenericCall)
       │     │
       │     └─► BroadcastFunction (全核并发执行: 非0核原子自增，核0执行分发)
       │           │
       │           └─► sub_14001CAEC (CR8 提升至 0xF，向无锁环形队列写入检查载荷)
       │                 ├─► sub_140018944 / sub_14001894C (原子 64 位指针读写)
       │                 └─► 100 次自旋确认，超时记录至 dword_140148418
       │
[事务提交与资源解绑]
       ├─► sub_14001BD88 (发送 0x1000... 提交刷新指令 Flush)
       └─► sub_14001BF28 (清理页保护掩码，广播 0x7FFFFFFFFFFFFLL 释放各核心)

[底层 2MB 大页暗影页表构建]
       ├─► sub_14001CD64 (分配 4KB 非分页池，初始化 256 项 IPI 指令环结构)
       └─► sub_14001CDBC (构建 x64 PML4/PDPT/PD 2MB 大页 PS=0x80 暗影物理页表)
```

---

## 2. 核心函数逐一详尽分析（Function-by-Function）

### 函数 1：`BroadcastFunction`
* **地址**：`0x14001C59C`，大小 `0x34`
* **作用**：**`KeIpiGenericCall` 的多核广播接收回调例程**。
* **逆向反编译细节**：
  ```c
  unsigned __int8 __fastcall BroadcastFunction(ULONG_PTR Argument)
  {
    unsigned __int8 CoreId = KeGetCurrentProcessorNumber();
    if ( CoreId == 0 ) // 规定仅在逻辑核 0 上执行控制台例程
    {
      sub_14001CAEC(
        *(_QWORD *)(Argument + 8),
        Argument + 16,
        *(_QWORD *)(Argument + 32),
        *(unsigned int *)(Argument + 40));
    }
    // 所有从核心执行完毕后原子自增完成计数器
    _InterlockedIncrement((volatile signed __int32 *)(Argument + 44));
    return CoreId;
  }
  ```
* **执行特征**：无论系统具有 4 核、8 核还是 32 核，所有非 0 核心均被强行拉入此回调执行硬件级等待，核 0 负责集中校验与无锁环分发。

---

### 函数 2：`sub_14001C640`
* **地址**：`0x14001C640`，大小 `0x104`
* **形参**：`ULONG_PTR ContextBase, unsigned __int16 TxId, __int64 TargetPhysAddr, char Flags`
* **作用**：**主 IPI 中断发起与忙等待同步管理器**。
* **执行逻辑**：
  ```c
  // 构造 128 位命令报文 (Opcode = 3: 硬件探测指令)
  v9_low = ((unsigned __int64)TxId << 32) | 0x3000000000000000LL;
  v9_high = (TargetPhysAddr << 12) | Flags & 1 | 2;

  if ( byte_1401483CB != 0 ) // 启用多核广播模式
  {
      Context.CompletionCount = 0;
      Context.Payload = v9;
      // 触发跨核心 IPI
      KeIpiGenericCall(BroadcastFunction, (ULONG_PTR)&Context);

      // 发起核进入低功耗自旋等待，直到所有逻辑核心均已响应
      while ( Context.CompletionCount != *KeNumberProcessors )
      {
          _mm_pause();
      }
  }
  else // 单核回退模式
  {
      sub_14001CAEC(ContextBase, &v9, ...);
      return sub_14001BD88(ContextBase);
  }
  ```

---

### 函数 3：`sub_14001CAEC`
* **地址**：`0x14001CAEC`，大小 `0x164`
* **形参**：`__int64 RingBase, _QWORD *CommandPacket`
* **作用**：**核 0 特权级提权与无锁环形队列投递例程**。
* **关键控制流**：
  1. **提升 IRQL 至 HIGH_LEVEL (0xF)**：
     ```c
     CurrentIrql = KeGetCurrentIrql();
     if ( CurrentIrql < 0xFu )
     {
         __writecr8(0xFu); // 设置 CR8 寄存器为 15，屏蔽所有 DPC/APC 及一般硬件中断
     }
     ```
  2. **环形队列槽位投递**：
     - 读取环首指针 `v6`（`sub_140018944`）。
     - 计算环形写入偏移：`slot = 16 * ((v6 >> 4) & 0x7FFF) + RingBuffer`。
     - 写入 16 字节报文：`slot[0] = CommandPacket[0]; slot[1] = CommandPacket[1];`。
     - 推进环指针并原子更新：`sub_14001894C`。
  3. **有限自旋确认（Spins Wait）**：
     - 循环 100 次检查处理状态（`_mm_pause()`）。
     - 若超时未完成，递增失败统计计数器 `++dword_140148418`。
  4. **恢复原始 IRQL**：
     ```c
     if ( v5 != 0 ) __writecr8(CurrentIrql);
     ```

---

### 函数 4：`sub_14001BD88`
* **地址**：`0x14001BD88`，大小 `0x24`
* **作用**：**IPI 事务提交（Flush）命令例程**。
* **实现**：向队列写入 `Opcode = 1`（`0x1000000000000000LL`），强制环形队列完成当前批次的所有同步比对。

---

### 函数 5：`sub_14001C5D0`
* **地址**：`0x14001C5D0`，大小 `0x38`
* **作用**：**目标核心/状态槽位配置例程**。
* **实现**：向队列写入 `Opcode = 2`（`0x2000000000000000LL | CoreIndex`），随后立即调用 `sub_14001BD88` 提交。

---

### 函数 6：`sub_14001C38C`
* **地址**：`0x14001C38C`，大小 `0x78`
* **作用**：**多核同步会话 ID 分配器与活跃状态机检查**。
* **算法**：
  - 遍历步长 32 字节的活跃核心监控表。
  - 在全局位图 `byte_140148770` 中检索未使用的空闲 ID（`1` 到 `254`）。
  - 分配成功后记录至全局变量 `dword_140148760`。

---

### 函数 7：`sub_14001BF28`
* **地址**：`0x14001BF28`，大小 `0xF1`
* **作用**：**IPI 会话销毁与物理页监控解绑例程**。
* **逻辑**：
  - 恢复页表保护位：`*(_QWORD *)(Entry) &= 0xFFF0000000000FFFuLL`。
  - 发送全 F 广播释放掩码：`sub_14001C640(..., 0x7FFFFFFFFFFFFLL, 1)`，通知所有从属核心解除对该物理区域的自旋阻断。

---

### 函数 8：`sub_140018944`
* **地址**：`0x140018944`，大小 `0x8`
* **作用**：Volatile 64 位无锁环指针原子读取器（`return *(_QWORD *)a1;`）。

---

### 函数 9：`sub_14001894C`
* **地址**：`0x14001894C`，大小 `0x8`
* **作用**：Volatile 64 位无锁环指针原子更新器（`*a1 = a2;`）。

---

### 函数 10：`sub_14001CD64`
* **地址**：`0x14001CD64`，大小 `0x58`
* **作用**：**IPI 环形指令缓冲区上下文初始化器**。
* **实现**：
  - 调用 `ExAllocatePool(NonPagedPool, 0x1000u)` 分配 4KB 独立物理页。
  - 初始化 256 个指令槽位（每个槽位 16 字节），默认设置 `Entry[0] = 9; Entry[1] = 2;`。

---

### 函数 11：`sub_14001CDBC`
* **地址**：`0x14001CDBC`，大小 `0x194`
* **作用**：**构建 2MB 大页（Large Page）暗影页表结构（Shadow Page Tables）**。
* **页表构造核心细节**：
  - 驱动分配连续物理内存建立 x64 标准 4 级分页映射。
  - 遍历 512 个 Page Directory 项，设置：
    ```c
    *Entry = PhysicalAddressBase;
    *Entry |= 0x01;  // Present (有效)
    *Entry |= 0x02;  // Read/Write (可读写)
    *Entry |= 0x80;  // Page Size (PS=1，指示该项为 2MB 大页而非 4KB 级联)
    PhysicalAddressBase += 0x200000; // 步长精确自增 2MB
    ```
  - **目的**：通过自建完整的 2MB 大页暗影页表，使驱动在跨核心 IPI 扫描物理内存时，能够避开操作系统可能被修改的 EPROCESS 4KB 细粒度页表 Hook。

---

### 函数 12：`sub_14002B7EC` —— 32 槽位跨核心 SMP/IPI 广播执行总线分发
* **地址**：`0x14002B7EC`，大小 `106` 字节 (`0x6A`)
* **形参定义**：`void __fastcall sub_14002B7EC(__int64 Arg1, __int64 Arg2, __int64 Arg3)`
* **反编译伪代码**：
  ```c
  void __fastcall sub_14002B7EC(__int64 Arg1, __int64 Arg2, __int64 Arg3)
  {
    _InterlockedIncrement(&dword_14595A1E4); // 活跃核心计数原子递增
    signed __int64 *Slot = qword_14595A1F0; // 32 槽位跨核回调表 (0x14595A1F0 ~ 0x14595A2F0)

    do
    {
      if ( *Slot != 0 )
        ((void (__fastcall *)(__int64, __int64, __int64))*Slot)(Arg1, Arg2, Arg3);
      ++Slot;
    }
    while ( (char *)Slot < &byte_14595A2F0 );

    _InterlockedDecrement(&dword_14595A1E4); // 完成后原子递减
  }
  ```
* **对抗意义**：跨核心总线广播底座！当发起 IPI 中断时，所有 CPU 核心并行被拉入该函数，按序执行预先注册的 32 个特权感知例程，保证无一核心漏检。

---

### 函数 13：`sub_14002B858` —— 无锁原子注册 IPI 跨核回调例程
* **地址**：`0x14002B858`，大小 `10` 字节（内联汇编/包装）
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002B858(signed __int64 CallbackRoutine)
  {
    if ( byte_14595A1E0 == 0 || CallbackRoutine == 0 )
      return 0;

    // 检查是否已存在
    for ( signed __int64 *p = qword_14595A1F0; p < (signed __int64 *)&byte_14595A2F0; ++p )
    {
      if ( *p == CallbackRoutine )
        return 1;
    }

    // 无锁 CAS 抢占空闲槽位
    for ( int i = 0; i < 32; ++i )
    {
      if ( _InterlockedCompareExchange64(&qword_14595A1F0[i], CallbackRoutine, 0) == 0 )
        return 1; // 注册成功
    }
    return 0;
  }
  ```

---

### 函数 14：`sub_14002B864` —— 广播执行触发器与全核自旋完成同步等待
* **地址**：`0x14002B864`，大小 `67` 字节 (`0x43`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002B864(__int64 a1, __int64 a2)
  {
    if ( byte_14595A1E0 != 0 )
    {
      // 调用底层 KeGenericCallDpc / KeIpiGenericCall 广播执行 sub_14002B7EC
      sub_140027DD4(sub_14002B7EC, 1);

      // 自旋等待所有逻辑核退出广播例程
      while ( _InterlockedCompareExchange(&dword_14595A1E4, 0, 0) != 0 )
      {
        KeStallExecutionProcessor(10u); // 每次微秒级让步等待
      }
      byte_14595A1E0 = 0;
    }
    return 0;
  }
  ```

---

### 函数 15：`sub_14002BAB4` —— 清除 CR4 Bit 7 PGE 强制全核心刷新 TLB
* **地址**：`0x14002BAB4`，大小 `12` 字节 (`0xC`)
* **反编译伪代码**：
  ```c
  unsigned __int64 sub_14002BAB4()
  {
    unsigned __int64 Cr4 = __readcr4();
    // 清除 PGE 位 (Bit 7, 0x80)，迫使 CPU 硬件废弃全局页转换旁路缓存 (Global TLB)
    unsigned __int64 NewCr4 = Cr4 & 0xFFFFFFFFFFFFFF7FuLL;
    __writecr4(NewCr4);
    return NewCr4;
  }
  ```
* **对抗意义**：作弊工具尝试挂接 PDE/PTE 时，若只改写内存页而不清除 PGE 刷新全局 TLB，ACE 通过在此处主动翻转 PGE，瞬间强制将硬件 MMU 缓存失效，使任何内存页篡改立即原形毕露。

---

### 函数 16：`sub_14002BAC0` —— `'sggg'` 内存池 4KB 独立物理页表分配器
* **地址**：`0x14002BAC0`，大小 `335` 字节 (`0x14F`)
* **形参定义**：`PHYSICAL_ADDRESS __fastcall sub_14002BAC0(__int64 SourceAddress, _DWORD *OutOffset, char Flags)`
* **内存池标签**：`0x73676767` (`'sggg'`)
* **反编译伪代码**：
  ```c
  PHYSICAL_ADDRESS __fastcall sub_14002BAC0(__int64 SourceAddress, _DWORD *OutOffset, char Flags)
  {
    PHYSICAL_ADDRESS PhysicalAddress;
    PhysicalAddress.QuadPart = 0;

    if ( SourceAddress != 0 )
    {
      if ( OutOffset ) *OutOffset = SourceAddress & 0xFFF;

      // 分配独立的 4KB NonPagedPool 物理页构建暗影页结构
      _QWORD *NewPage = (_QWORD *)ExAllocatePoolWithTag(NonPagedPool, 0x1000u, 0x73676767u);
      if ( NewPage )
      {
        // 复制原始页表结构并打上专属标签
        // ...
        PhysicalAddress = MmGetPhysicalAddress(NewPage);
      }
    }
    return PhysicalAddress;
  }
  ```

---

### 函数 17：`sub_14002BFD0` —— 暗影页表构建：2MB / 4KB 级页目录 (PD) 构建与遍历
* **地址**：`0x14002BFD0`，大小 `231` 字节 (`0xE7`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002BFD0(__int64 ShadowCr3, unsigned __int64 StartVa, unsigned __int64 EndVa)
  {
    int CurPdIndex = -1;
    unsigned __int64 Va = StartVa;

    while ( Va < EndVa )
    {
      // 提取虚拟地址的 2MB 级 Page Directory 索引: (Va >> 21) & 0x1FF
      unsigned int PdIndex = (Va >> 21) & 0x1FF;
      if ( CurPdIndex != PdIndex )
      {
        CurPdIndex = PdIndex;
        __int64 PdEntry = sub_14002C5D0(ShadowCr3, Va);
        // ... 构建下级页表或填充 2MB 大页
      }
      Va += 0x200000; // 步进 2MB
    }
    return 1;
  }
  ```

---

### 函数 18：`sub_14002C0B8` —— 暗影页表构建：1GB 级页目录指针表 (PDPT) 构建与遍历
* **地址**：`0x14002C0B8`，大小 `192` 字节 (`0xC0`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002C0B8(__int64 ShadowCr3, unsigned __int64 StartVa, unsigned __int64 EndVa)
  {
    int CurPdptIndex = -1;
    unsigned __int64 Va = StartVa;

    while ( Va < EndVa )
    {
      // 提取虚拟地址的 1GB 级 PDPT 索引: (Va >> 30) & 0x1FF
      unsigned int PdptIndex = (Va >> 30) & 0x1FF;
      if ( CurPdptIndex != PdptIndex )
      {
        CurPdptIndex = PdptIndex;
        // 分配或级联下一层 PD
      }
      Va += 0x40000000; // 步进 1GB
    }
    return 1;
  }
  ```

---

### 函数 19：`sub_14002C178` —— PTE 物理映射构建与 0x21 特性标志设置
* **地址**：`0x14002C178`，大小 `208` 字节 (`0xD0`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002C178(__int64 ShadowTable, unsigned __int64 StartVa, unsigned __int64 EndVa, char Flags)
  {
    unsigned __int64 Va = StartVa;

    while ( Va < EndVa )
    {
      PHYSICAL_ADDRESS Pa = MmGetPhysicalAddress((PVOID)Va);
      if ( Pa.QuadPart == 0 )
        break;

      // 关键：保留 4KB 对齐物理基址，并打上 0x21 标志 (Bit 0: Present; Bit 5: Accessed)
      LONGLONG PteValue = (Pa.QuadPart & 0xFFFFFFF000LL) | 0x21;

      // 写入暗影 PTE 映射槽位
      // ...
      Va += 4096; // 4KB 单页步进
    }
    return 1;
  }
  ```

---

### 函数 20：`sub_14002C248` —— 暗影页表构建：512GB 级根表 PML4 构建与遍历
* **地址**：`0x14002C248`，大小 `199` 字节 (`0xC7`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002C248(__int64 ShadowCr3, unsigned __int64 StartVa, unsigned __int64 EndVa)
  {
    int CurPml4Index = -1;
    unsigned __int64 Va = StartVa;

    while ( Va < EndVa )
    {
      // 提取虚拟地址的 512GB 级 PML4 索引: (Va >> 39) & 0x1FF
      unsigned int Pml4Index = (Va >> 39) & 0x1FF;
      if ( CurPml4Index != Pml4Index )
      {
        CurPml4Index = Pml4Index;
        // 动态分配下层 PDPT 并挂接至暗影 PML4 表
      }
      Va += 0x8000000000LL; // 步进 512GB
    }
    return 1;
  }
  ```

---

### 函数 21：`sub_14002C5D0` —— x64 暗影页表多级遍历器：PML4 -> PDPT -> PD
* **地址**：`0x14002C5D0`，大小 `95` 字节 (`0x5F`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002C5D0(__int64 ShadowCr3, unsigned __int64 Va)
  {
    if ( !ShadowCr3 ) return 0;

    // 1. 通过 PML4 索引 (Va >> 39 & 0x1FF) 提取 PDPTEntry
    __int64 PdptEntry = sub_14002CF90(ShadowCr3, (Va >> 39) & 0x1FF);
    if ( PdptEntry && (PdptEntry & 1) != 0 && (PdptEntry & 0x80) == 0 ) // Present && !LargePage
    {
      // 2. 通过 PDPT 索引 (Va >> 30 & 0x1FF) 提取 PDEntry
      return sub_14002CF90(PdptEntry & 0xFFFFFFF000LL, (Va >> 30) & 0x1FF);
    }
    return 0;
  }
  ```

---

### 函数 22：`sub_14002C578` —— x64 暗影页表多级遍历器：PD -> PT
* **地址**：`0x14002C578`，大小 `85` 字节 (`0x55`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002C578(__int64 ShadowCr3, unsigned __int64 Va)
  {
    if ( !ShadowCr3 ) return 0;

    // 获取 PDEntry
    __int64 PdEntry = sub_14002C5D0(ShadowCr3, Va);
    if ( PdEntry && (PdEntry & 1) != 0 && (PdEntry & 0x80) == 0 )
    {
      // 3. 通过 PD 索引 (Va >> 21 & 0x1FF) 提取 PTEntry
      return sub_14002CF90(PdEntry & 0xFFFFFFF000LL, (Va >> 21) & 0x1FF);
    }
    return 0;
  }
  ```

---

### 函数 23：`sub_14002C630` —— x64 暗影页表直取 PTE (Page Table Entry) 物理项
* **地址**：`0x14002C630`，大小 `85` 字节 (`0x55`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002C630(__int64 ShadowCr3, unsigned __int64 Va)
  {
    if ( !ShadowCr3 ) return 0;

    // 获取 PTEntry
    __int64 PtEntry = sub_14002C578(ShadowCr3, Va);
    if ( PtEntry && (PtEntry & 1) != 0 && (PtEntry & 0x80) == 0 )
    {
      // 4. 通过 PT 索引 (Va >> 12 & 0x1FF) 提取最终 PTE 项！
      return sub_14002CF90(PtEntry & 0xFFFFFFF000LL, (Va >> 12) & 0x1FF);
    }
    return 0;
  }
  ```
* **对抗意义**：**全自主页表遍历引擎（Page Table Walker）**！ACE 驱动拥有完全脱离 Windows 内核自身 `MiGetPteAddress` 逻辑的独立寻页能力。给定任何一个虚拟地址，能逐级验证 PML4 -> PDPT -> PD -> PT 并抓出最终物理 PTE，使外挂对系统页表函数的 Hook 彻底落空。

---

### 函数 24：`sub_14002C6F4` —— 暗影 PTE 页表物理克隆与动态挂接
* **地址**：`0x14002C6F4`，大小 `355` 字节 (`0x163`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002C6F4(__int64 ShadowCr3, unsigned __int64 Va, unsigned __int64 TargetPhys)
  {
    // 分配 4KB 独立页，将目标 PTE 原地克隆并替换挂接到暗影页表结构
    PVOID NewPage = ExAllocatePool(NonPagedPool, 0x1000u);
    if ( !NewPage ) return 0;

    // 内存对齐拷贝与索引原子挂载
    // ...
    return 1;
  }
  ```

---

### 函数 25：`sub_14002C858` —— 暗影物理页管理器主初始化总控与 \Device\PhysicalMemory 句柄创建
* **地址**：`0x14002C858`，大小 `722` 字节 (`0x2D2`)
* **形参定义**：`__int64 sub_14002C858(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002C858()
  {
    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING SectionName;

    if ( byte_14595A2F0 != 0 ) // 已经完成初始化
      return 0;

    qword_14595C990 = sub_14002425C();
    // 检查硬件虚拟化支持与虚拟机状态
    if ( !sub_140024244() || sub_1400242D4() != 0 )
      return STATUS_NOT_SUPPORTED;

    // 打开物理内存节区 \Device\PhysicalMemory
    RtlInitUnicodeString(&SectionName, L"\\Device\\PhysicalMemory");
    InitializeObjectAttributes(&ObjectAttributes, &SectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwOpenSection(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &ObjectAttributes);
    if ( Status >= 0 )
    {
      byte_14595A2F0 = 1; // 物理内存映射引擎激活成功
    }
    return Status;
  }
  ```
* **对抗意义**：直接获取物理内存操作端点！通过 `\Device\PhysicalMemory`，驱动获得了越过任何虚拟内存保护直接映射物理页的最高权限。

---

### 函数 26：`sub_14002CB2C` —— ACE 专属暗影保留页范围边界安全探针
* **地址**：`0x14002CB2C`，大小 `73` 字节 (`0x49`)
* **反编译伪代码**：
  ```c
  bool __fastcall sub_14002CB2C(__int64 PhysAddr)
  {
    unsigned __int64 PageBase = PhysAddr & 0xFFFFFFFFFFFFF000uLL;

    // 检查是否落在自身暗影保留物理页范围内
    if ( PageBase >= (qword_14595A2F8 & 0xFFFFFFFFFFFFF000uLL)
      && PageBase <= (qword_14595A2F8 & 0xFFFFFFFFFFFFF000uLL) + 4096 )
      return false; // 严禁重入保护

    if ( PageBase >= (qword_14595A300 & 0xFFFFFFFFFFFFF000uLL) )
      return (qword_14595A300 & 0xFFFFFFFFFFFFF000uLL) + 4096 < PageBase;

    return true;
  }
  ```

---

### 函数 27：`sub_14002CB78` —— ZwMapViewOfSection 物理页 4KB 安全映射器
* **地址**：`0x14002CB78`，大小 `138` 字节 (`0x8A`)
* **形参定义**：`PVOID __fastcall sub_14002CB78(union _LARGE_INTEGER PhysAddr)`
* **反编译伪代码**：
  ```c
  PVOID __fastcall sub_14002CB78(union _LARGE_INTEGER PhysAddr)
  {
    PVOID BaseAddress = NULL;
    ULONG_PTR ViewSize = 4096;
    LARGE_INTEGER SectionOffset = PhysAddr;

    // 物理地址合法性检查 (拒绝低于 1MB 的传统 DOS 保留区)
    if ( SectionHandle != NULL && PhysAddr.QuadPart >= 0x100001uLL )
    {
      if ( ZwMapViewOfSection(SectionHandle, (HANDLE)-1, &BaseAddress, 0, 0x1000u, &SectionOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE) == STATUS_SUCCESS )
      {
        return BaseAddress;
      }
    }
    return NULL;
  }
  ```

---

### 函数 28：`sub_14002CC04` —— 恢复 CR4 PGE 全局页使能位
* **地址**：`0x14002CC04`，大小 `12` 字节 (`0xC`)
* **反编译伪代码**：
  ```c
  unsigned __int64 sub_14002CC04()
  {
    unsigned __int64 Cr4 = __readcr4();
    unsigned __int64 NewCr4 = Cr4 | 0x80; // 重新置位 Bit 7 (PGE)
    __writecr4(NewCr4);
    return NewCr4;
  }
  ```

---

### 函数 29：`sub_14002CC28` —— 暗影页表双链比对与进程特权内存篡改检测
* **地址**：`0x14002CC28`，大小 `869` 字节 (`0x365`)
* **形参定义**：`__int64 __fastcall sub_14002CC28(HANDLE ProcessId, struct _LIST_ENTRY **OutLinks)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002CC28(HANDLE ProcessId, struct _LIST_ENTRY **OutLinks)
  {
    PEPROCESS Process = NULL;

    if ( byte_14595A2F0 == 0 ) // 物理引擎未启动
      return 0;

    // 获取进程对象并提取其 CR3 (DirectoryTableBase)
    if ( sub_140027CF0(ProcessId, &Process) >= 0 && Process )
    {
      PHYSICAL_ADDRESS Cr3 = sub_140024C80(Process);
      // 遍历目标进程在暗影页表与原生硬件 CR3 中的所有 PML4 / PDPT / PD 项
      // 比对物理映射的一致性，发现任意被外挂篡改的 PTE 即刻告警并提取调用栈
      // ...
      ObDereferenceObject(Process);
    }
    return 1;
  }
  ```
* **对抗意义**：通过物理内存直读比对原生页表与暗影页表，使所有尝试利用 VT-x EPT 隐藏挂钩、隐藏断点或内核代码 Patch 的外挂彻底原形毕露。

---

### 函数 30：`sub_14002CF90` —— 物理内存 QWORD 远程直读例程
* **地址**：`0x14002CF90`，大小 `55` 字节 (`0x37`)
* **形参定义**：`__int64 __fastcall sub_14002CF90(union _LARGE_INTEGER PhysAddr, unsigned int QwordIndex)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002CF90(union _LARGE_INTEGER PhysAddr, unsigned int QwordIndex)
  {
    __int64 Value = 0;
    _QWORD *p = (_QWORD *)sub_14002CB78(PhysAddr); // 动态映射
    if ( p )
    {
      Value = p[QwordIndex]; // 读取 8 字节
      sub_14002D79C(p);      // 立即解映射 ZwUnmapViewOfSection
    }
    return Value;
  }
  ```

---

### 函数 31：`sub_14002CFC8` —— 全页 4KB 物理数据快照提取器
* **地址**：`0x14002CFC8`，大小 `136` 字节 (`0x88`)
* **形参定义**：`char __fastcall sub_14002CFC8(union _LARGE_INTEGER PhysAddr, _OWORD *OutPageBuffer)`
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002CFC8(union _LARGE_INTEGER PhysAddr, _OWORD *OutPageBuffer)
  {
    _OWORD *p = (_OWORD *)sub_14002CB78(PhysAddr);
    if ( p )
    {
      // 循环展开使用 128 位 XMM 寄存器快速拷贝 4096 字节
      for ( int i = 32; i != 0; --i )
      {
        *OutPageBuffer = *p;
        OutPageBuffer[1] = p[1];
        // ... (拷贝 128 字节步进)
        OutPageBuffer += 8;
        p += 8;
      }
      sub_14002D79C(p); // 解除映射
      return 1;
    }
    return 0;
  }
  ```

---

### 函数 32：`sub_14002D050` —— 物理页保护属性动态修改与重刷
* **地址**：`0x14002D050`，大小 `258` 字节 (`0x102`)
* **形参定义**：`void __fastcall sub_14002D050(union _LARGE_INTEGER PhysAddr, char ProtectFlags, char Unk, char FlushTLB)`
* **反编译伪代码**：
  ```c
  void __fastcall sub_14002D050(union _LARGE_INTEGER PhysAddr, char ProtectFlags, char Unk, char FlushTLB)
  {
    LARGE_INTEGER AlignedAddr = PhysAddr;
    __int64 Size = 4096;

    if ( PhysAddr.QuadPart < 0x100001uLL ) return;

    // 修改内存页物理属性并刷新 TLB
    sub_140027BB4(&AlignedAddr, &Size);
    // ...
  }
  ```

---

### 函数 33：`sub_14002D154` —— 物理页快照备份与还原
* **地址**：`0x14002D154`，大小 `153` 字节 (`0x99`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002D154(__int64 Context)
  {
    __int64 PhysBase = *(_QWORD *)(*(_QWORD *)Context + 40LL) & 0x7FFFFFFFFFFFF000LL;
    _OWORD *Mapped = (_OWORD *)sub_140031EA0(PhysBase);
    if ( !Mapped ) return 0;

    // 保存前 48 字节关键页表头并刷新物理视图
    // ...
    return *(_QWORD *)(*(_QWORD *)Context + 40LL);
  }
  ```

---

### 函数 34：`sub_14002D1F0` —— 周期性暗影页表守护巡检与延迟同步
* **地址**：`0x14002D1F0`，大小 `52` 字节 (`0x34`)
* **反编译伪代码**：
  ```c
  bool sub_14002D1F0()
  {
    sub_1400244E4(2000u); // 延时 2000ms
    if ( sub_140030618(1) == 0 )
    {
      sub_14002D224(); // 触发全槽位暗影页目录热刷新
      sub_14003096C();
    }
    return sub_1400244E4(1000u);
  }
  ```

---

### 函数 35：`sub_14002D224` —— 全槽位暗影页目录热刷新与重同步循环
* **地址**：`0x14002D224`，大小 `347` 字节 (`0x15B`)
* **反编译伪代码**：
  ```c
  void sub_14002D224()
  {
    // 遍历全局 16 槽位特权监控描述符 (&unk_14595C388)
    for ( int i = 0; i < 16; ++i )
    {
      // 刷新暗影页镜像并重新同步 CPUID 特性
      // ...
    }
  }
  ```

---

### 函数 36：`sub_14002D380` —— 暗影页表递归遍历总控
* **地址**：`0x14002D380`，大小 `113` 字节 (`0x71`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002D380(__int64 ShadowBase, __int64 Cr3Phys, char Flags)
  {
    OWORD PageBuf[256];
    memset(PageBuf, 0, sizeof(PageBuf));

    if ( sub_14002CFC8((union _LARGE_INTEGER)(Cr3Phys & 0x7FFFFFFFFFFFF000LL), PageBuf) )
    {
      return sub_14002D620(ShadowBase, (__int64 *)PageBuf, Flags);
    }
    return 0;
  }
  ```

---

### 函数 37：`sub_14002D3F4` —— PT 级 (4KB) 页表遍历与属性修改
* **地址**：`0x14002D3F4`，大小 `236` 字节 (`0xEC`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_14002D3F4(unsigned __int64 Va, __int64 *pPtEntry, char Flags)
  {
    __int64 PtValue = *pPtEntry;
    OWORD PtPageBuf[256];

    if ( (*pPtEntry & 1) != 0 && (PtValue & 0xFFFFFFF000LL) != 0 )
    {
      if ( sub_14002CFC8((union _LARGE_INTEGER)(PtValue & 0xFFFFFFF000LL), PtPageBuf) )
      {
        unsigned int PtIndex = (Va >> 12) & 0x1FF; // 提取 PT 索引
        sub_14002D5DC((unsigned __int64 *)PtPageBuf + PtIndex, Flags);
      }
    }
  }
  ```

---

### 函数 38：`sub_14002D4E0` —— PD 级 (2MB) 页目录递归遍历
* **地址**：`0x14002D4E0`，大小 `251` 字节 (`0xFB`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_14002D4E0(unsigned __int64 Va, __int64 *pPdEntry, char Flags)
  {
    __int64 PdValue = *pPdEntry;
    QWORD PdPageBuf[512];

    if ( (*pPdEntry & 1) != 0 && (PdValue & 0xFFFFFFF000LL) != 0 )
    {
      if ( sub_14002CFC8((union _LARGE_INTEGER)(PdValue & 0xFFFFFFF000LL), (OWORD *)PdPageBuf) )
      {
        unsigned int PdIndex = (Va >> 21) & 0x1FF; // 提取 PD 索引
        sub_14002D3F4(Va, &PdPageBuf[PdIndex], Flags);
      }
    }
  }
  ```

---

### 函数 39：`sub_14002D5DC` —— PTE NX 与 Present 特权位校验
* **地址**：`0x14002D5DC`，大小 `65` 字节 (`0x41`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_14002D5DC(unsigned __int64 *pPte, char Flags)
  {
    unsigned __int64 Pte = *pPte;
    // 校验 Bit 0 (Present), Bit 63 (NX - No Execute), 确保非大页 (!LargePage)
    if ( (Pte & 1) != 0 && Pte >= 0x8000000000000000uLL && (Pte & 0x80) == 0 && (Pte & 0xFFFFFFF000LL) != 0 )
    {
      sub_14002D050((union _LARGE_INTEGER)(Pte & 0xFFFFFFF000LL), Flags, 0, 1);
    }
  }
  ```

---

### 函数 40：`sub_14002D620` —— PDPT 级 (1GB) 页目录指针递归遍历
* **地址**：`0x14002D620`，大小 `253` 字节 (`0xFD`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_14002D620(unsigned __int64 Va, __int64 *pPdptEntry, char Flags)
  {
    __int64 PdptValue = *pPdptEntry;
    QWORD PdptPageBuf[512];

    if ( (*pPdptEntry & 1) != 0 && (PdptValue & 0xFFFFFFF000LL) != 0 )
    {
      if ( sub_14002CFC8((union _LARGE_INTEGER)(PdptValue & 0xFFFFFFF000LL), (OWORD *)PdptPageBuf) )
      {
        unsigned int PdptIndex = (Va >> 30) & 0x1FF; // 提取 PDPT 索引
        sub_14002D4E0(Va, &PdptPageBuf[PdptIndex], Flags);
      }
    }
  }
  ```

---

### 函数 41：`sub_14002D728` —— 暗影物理页管理器退场清理与 Section 卸载
* **地址**：`0x14002D728`，大小 `114` 字节 (`0x72`)
* **反编译伪代码**：
  ```c
  bool sub_14002D728()
  {
    if ( byte_14595A2F0 != 0 )
    {
      byte_14595A2F0 = 0;
      if ( qword_14595C988 )
      {
        sub_1400299DC(qword_14595C988);
        qword_14595C988 = NULL;
      }
      sub_14002B8B4();
      sub_14002E724(sub_14002CC10);
      sub_14002441C((void (__fastcall *)(__int64))sub_14002CC04, 0); // 广播全核心恢复 CR4 PGE

      if ( SectionHandle != NULL )
        ZwClose(SectionHandle); // 关闭 \Device\PhysicalMemory 句柄

      sub_1400309B4();
      return sub_1400244E4(5000u);
    }
    return 0;
  }
  ```

---

### 函数 42：`sub_14002D7C4` —— 物理 PTE 项原子重写写入器
* **地址**：`0x14002D7C4`，大小 `94` 字节 (`0x5E`)
* **形参定义**：`char __fastcall sub_14002D7C4(__int64 *pPageBase, unsigned int QwordIndex, __int64 NewPteValue)`
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002D7C4(__int64 *pPageBase, unsigned int QwordIndex, __int64 NewPteValue)
  {
    __int64 PageValue = *pPageBase;
    char Success = 0;

    if ( (PageValue & 1) != 0 && (PageValue & 0x80) == 0 )
    {
      _QWORD *MappedPage = (_QWORD *)sub_14002CB78((union _LARGE_INTEGER)(PageValue & 0xFFFFFFF000LL));
      if ( MappedPage )
      {
        MappedPage[QwordIndex] = NewPteValue; // 原地改写物理页项
        Success = 1;
        sub_14002D79C(MappedPage); // 释放映射
      }
    }
    return Success;
  }
### 函数 43：`sub_140030A76` —— 硬件特权中断/异常陷阱处理例程 (Trap Handler with iretq & Shadow CR3 Switch)
* **地址**：`0x140030A76`，大小 `208` 字节 (`0xD0`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_140030A76()
  {
    _disable(); // 屏蔽硬件中断 cli
    unsigned __int64 Cr4 = __readcr4();
    __writecr4(Cr4 & ~0x80uLL); // 清除 PGE 强刷 TLB
    unsigned __int64 Eflags = __readeflags();
    unsigned __int64 Cr2 = __readcr2(); // 捕获缺页/陷阱线性地址

    // 切换至暗影 CR3 进行特权状态核验与页表修复
    sub_14002D91C();

    __writeeflags(Eflags);
    _enable(); // 恢复中断 sti
    __asm { iretq } // 64 位特权级中断返回！
  }
  ```
* **对抗意义**：**全驱动最底层的硬件 Trap 核心**！ACE 驱动直接将此函数挂入 IDT 中断向量表或捕获 CPU 硬件陷阱（例如通过故意清除 PTE Present 位构造可控的 Page Fault `#PF`），在 CPU 触发异常时第一微秒进入该函数，保存现场、清空 PGE 冲刷 TLB、读取 CR2 故障地址并瞬间切换至暗影 CR3 保护执行，最后执行 `iretq` 无痕返回，形成完全超越操作系统常规调度链的底层硬件拦截器。

---

---

### 函数 44：`sub_14002B988` —— \Device\PhysicalMemory 物理内存节区直开与暗影直接擦除
* **物理虚拟地址**：`0x14002b988`，大小 `300` 字节
* **核心职责**：**通过 \Device\PhysicalMemory 直射物理内存并执行页清零擦除（Physical Memory Direct Mapping & Wipe）**
* **逆向机理分析**：
  - 构造 `L"\\device\\physicalmemory"` Unicode 路径；
  - 构造 `OBJECT_ATTRIBUTES`（`Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE = 64`）；
  - 调用 `ZwOpenSection(&SectionHandle, SECTION_ALL_ACCESS, &ObjectAttributes)` 直接打开系统物理内存节区；
  - 将指定的物理起始页 `a1`（`LARGE_INTEGER SectionOffset`）通过 `ZwMapViewOfSection` 映射至当前内核进程地址空间（大小 4096 字节，`PAGE_READWRITE`）；
  - 直接改写目标物理地址内容：`*(_QWORD *)BaseAddress = 0`，实现不经过 Windows 虚拟内存管理器的物理底层抹除；
  - 完成操作后立即调用 `ZwUnmapViewOfSection` 与 `ZwClose` 销毁映射句柄，抹去 I/O 痕迹。
* **反编译伪代码**：
```c
void __fastcall sub_14002B988(union _LARGE_INTEGER PhysAddr)
{
  struct _UNICODE_STRING DestinationString;
  WCHAR SourceString[24];
  struct _OBJECT_ATTRIBUTES ObjectAttributes;
  void *SectionHandle;
  PVOID BaseAddress;
  ULONG_PTR ViewSize;
  union _LARGE_INTEGER SectionOffset;

  if ( PhysAddr.QuadPart >= 0x100001uLL )
  {
    SectionHandle = nullptr;
    wcscpy(SourceString, L"\\device\\physicalmemory");
    RtlInitUnicodeString(&DestinationString, SourceString);
    ObjectAttributes.RootDirectory = nullptr;
    ObjectAttributes.ObjectName = &DestinationString;
    ObjectAttributes.Length = 48;
    ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
    ObjectAttributes.SecurityDescriptor = nullptr;
    ObjectAttributes.SecurityQualityOfService = nullptr;
    
    // 打开 \device\physicalmemory 节区
    if ( ZwOpenSection(&SectionHandle, SECTION_ALL_ACCESS, &ObjectAttributes) == 0 )
    {
      BaseAddress = nullptr;
      ViewSize = 4096;
      SectionOffset = PhysAddr;
      
      // 映射物理页至当前进程虚拟内存
      if ( ZwMapViewOfSection(
             SectionHandle,
             NtCurrentProcess(),
             &BaseAddress,
             0,
             0x1000u,
             &SectionOffset,
             &ViewSize,
             ViewShare,
             0,
             PAGE_READWRITE) == 0
        && BaseAddress != nullptr )
      {
        // 物理页头原子抹除清零
        *(_QWORD *)BaseAddress = 0;
        ZwUnmapViewOfSection(SectionHandle, BaseAddress);
      }
    }
    if ( SectionHandle != nullptr )
      ZwClose(SectionHandle);
  }
}
```



## 3. 逆向对抗与防御总结

1. **CR8 提升防御**：在 `sub_14001CAEC` 执行期间，CPU 处于 `HIGH_LEVEL (15)`，任何通过挂钩 IDT、时钟中断或 APC/DPC 注入的检测绕过工具都会因为中断被全面屏蔽而无法在检测窗口期获得 CPU 时间片。
2. **多核协同强一致性**：必须确保所有核心的 CR3、IDT 与分页属性在物理总线上完全一致。任何仅在特定线程或特定逻辑核上挂钩的虚假页表，在 `KeIpiGenericCall` 瞬时广播对拍下会直接暴露。
3. **PGE 全局刷新粉碎 TLB 欺骗**：`sub_14002BAB4` 周期性或在敏感校验前清除 CR4 的 PGE 位，触发 CPU 全核级 TLB 冲刷，使得作弊工具利用硬件 MMU 缓存残存特权页的企图被完全挫败。
4. **自研 4 级暗影页表遍历器**：`sub_14002C248` ~ `sub_14002C630` 构成了完整的 x64 虚拟内存四级分页自解析体系（`PML4 -> PDPT -> PD -> PT -> PTE`）。由于它直接操作物理页且拥有独立的暗影 CR3 映射树，任何试图在 Windows 原生页表（如修改 PTE Present 位或保护位）搞隐身的外挂，在此暗影直读下都会被立即捕捉。
5. **32 槽位无锁 IPI 广播执行总线**：`sub_14002B7EC` 与 `sub_14002B858` 基于 CAS 原子操作管理全局跨核调度表，可支持多达 32 个不同的硬件级安全巡检插件在所有核心以特权级并发执行，大幅提升了对多核并发作弊行为的捕捉效率。
6. **`\Device\PhysicalMemory` 击穿一切虚拟保护**：`sub_14002C858` 与 `sub_14002CB78` 通过打开物理内存原生 Section 并调用 `ZwMapViewOfSection` 映射任意 4KB 物理页，使 ACE 具备直接查看和修改物理内存的原语，任何虚拟内存层面的 EPROCESS 隔离和驱动 Hook 均被物理降维打击。
7. **PTE 物理原子篡改与 NX 强锁机制**：`sub_14002D7C4` 拥有直接对物理 PTE 进行改写的能力。结合 `sub_14002D5DC`，ACE 可直接对检测到的外部作弊模块所在物理页强制清除执行权限（打上 NX 位），使外挂在调用自身逻辑时瞬间触发硬件级不可执行异常崩溃。
8. **暗影与原生双页表递归 Diff 审计**：`sub_14002CC28` 与 `sub_14002D620` 构成了高精度的页表差异审计引擎，从根表 PML4 一路向下递归校验每一个 1GB、2MB 与 4KB 映射，彻底杜绝了利用EPT隐藏钩子（Shadow EPT）瞒天过海的可能。
9. **硬件级 iretq 中断暗影切换拦截器**：`sub_140030A76` 直接作为硬件中断服务例程，在发生缺页或异常时瞬间完成清 TLB 与暗影 CR3 切换，并在 `iretq` 退出时让作弊软件误以为是正常的硬件执行，形成了极为隐蔽的“硬中断级”反作弊暗影拦截。


---


---


---

## 4. 全量子系统核心反作弊函数反编译聚类与合并归纳（共收录：83 个反作弊核心函数）

> **经 IDA Hex-Rays 深度反编译分析，本子系统负责反作弊攻防的核心函数已全量提取微码，并按底层机制高度合并归纳为 3~4 大核心功能簇，彻底消除同质化存根冗余：**

```
[架构合流]: 跨核心 IPI 同步与物理暗影页表合流架构

  ├─► 【功能簇 A: KeIpiGenericCall 广播】
  │     ├─ 代表例程: sub_14001C640 / BroadcastFunction
  │     └─ 核心机理: 触发全核硬件级中断，CR8 提升至 0xF 屏蔽一切挂钩抢占

  ├─► 【功能簇 B: CR4 PGE 冲刷 TLB】
  │     ├─ 代表例程: sub_14002BAB4 / sub_14002BB20
  │     └─ 核心机理: 清除 PGE 触发 CPU 全核级硬件 TLB 彻底刷新，粉碎伪造页表

  ├─► 【功能簇 C: 四级暗影页表自遍历】
  │     ├─ 代表例程: sub_14002C248 等 35 个合并
  │     └─ 核心机理: 自建独立 PML4/PDPT/PD/PTE 暗影树，穿透原生 EPROCESS 虚拟内存

  ├─► 【功能簇 D: 物理 PTE 原子篡改】
  │     ├─ 代表例程: sub_14002D7C4 等 28 个合并
  │     └─ 核心机理: 原子注入 NX 不可执行位，使目标外挂模块物理页直接触发硬件故障

```

---

### 【功能簇 A: KeIpiGenericCall 广播】

* **涵盖与合并函数**：`sub_14001C640 / BroadcastFunction`

* **深度对抗机理剖析**：

  触发全核硬件级中断，CR8 提升至 0xF 屏蔽一切挂钩抢占。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 B: CR4 PGE 冲刷 TLB】

* **涵盖与合并函数**：`sub_14002BAB4 / sub_14002BB20`

* **深度对抗机理剖析**：

  清除 PGE 触发 CPU 全核级硬件 TLB 彻底刷新，粉碎伪造页表。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 C: 四级暗影页表自遍历】

* **涵盖与合并函数**：`sub_14002C248 等 35 个合并`

* **深度对抗机理剖析**：

  自建独立 PML4/PDPT/PD/PTE 暗影树，穿透原生 EPROCESS 虚拟内存。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 D: 物理 PTE 原子篡改】

* **涵盖与合并函数**：`sub_14002D7C4 等 28 个合并`

* **深度对抗机理剖析**：

  原子注入 NX 不可执行位，使目标外挂模块物理页直接触发硬件故障。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

