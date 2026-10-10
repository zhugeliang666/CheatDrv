---
name: ace-pci-dma-detection
description: >
  ACE (Anti-Cheat Expert) PCI/PCIe 总线扫描与硬件 DMA/外设检测全量逆向分析。
  包含 19 个核心详解与全量子系统 169 个归属函数完整拓扑索引、TLP 读写延迟侧信道、HAL 内部硬编码特征码搜索、MmMapIoSpace 物理 MMIO 直读直写、64位 PCIe BAR 动态解算与 Capability 扩展链表深度遍历。
---

# ACE 内核 PCI/PCIe 总线扫描与 DMA 硬件探针全量函数深度分析

## 1. 架构总览与探针工作流拓扑

ACE 内核驱动通过 HAL 导出接口与动态特征码定位（In-Memory Pattern Scanning），构建了双通道的硬件拓扑枚举网络，同时引入了针对 FPGA DMA 板卡（如 LeechCore/Squirrel/CaptainDMA）的硬件响应延迟（Turnaround Latency）时钟侧信道检测。

```
[底层未公开 MMIO 例程解析]
       │
       └─► sub_140024B6C (特征码扫描 hal.dll!HalGetBusDataByOffset，提取私有 MMIO 读函数)
             │
             └─► 赋值 qword_145959D90 / qword_1400FDF70 (暗影 MMIO 直读函数指针)

[总线全拓扑扫描与缓存]
       ├─► sub_140004D58 (主全量 PCI 扫描: Bus 0~254, Slot 0~31, Func 0~7)
       ├─► sub_14000797C (并发线程安全版扫描，导出 80,896 字节硬件设备表)
       ├─► sub_1400065DC (通用单设备读取封装，含 0xFFFF 暗影 MMIO 回退)
       └─► sub_14000AA64 (动态非分页池安全读取任意 PCI 偏移)

[硬件延迟侧信道与特定硬件探针]
       ├─► sub_1400066A4 (PCIe TLP 写入响应时钟延迟检测: __rdtsc 测算 0xA0/0xA8 耗时)
       ├─► sub_140019974 (GPU 硬件探针: 识别 Bus 1 Slot 0 的 0x10DE NVIDIA 显卡)
       ├─► sub_140019EB4 (容量 100 项的 PCI 设备 ID 快速原子缓存表)
       ├─► sub_14001C01C (PCI 设备状态与 IPI/物理地址绑定，触发 4206 号风控上报)
       └─► sub_14001D45C (MmMapIoSpace 物理映射 ECAM / BAR 空间，直读物理总线)
```

---

## 2. 核心函数逐一详尽分析（Function-by-Function）

### 函数 1：`sub_140024B6C`
* **地址**：`0x140024B6C`，大小 `0xC5`
* **作用**：**HAL 内部私有未导出 MMIO 读例程的特征码动态定位器**。
* **逆向反编译细节**：
  ```c
  __int64 sub_140024B6C()
  {
    // 特征码 1: 17 字节定位 HAL 内部调度桩
    v7[0] = -1995904575; v7[1] = -400546748; v7[2] = 1061109567; v7[3] = 952402760; v8 = -61;
    v1 = sub_1400279B4(HalGetBusDataByOffset, 256, v7, 17);
    if ( v1 )
    {
      v2 = v1 + *(int *)(v1 + 8);
      // 特征码 2: 10 字节定位私有 PCIe ECAM/MMIO 物理直读跳转指令
      v5[0] = 1061109736; v5[1] = -18369; v6 = 0;
      v3 = sub_1400279B4(v2 + 12, 256, v5, 10);
      if ( v3 )
        return *(int *)(v3 + 1) + v3 + 5; // 解析 RIP 相对地址返回真实内部函数指针
    }
    return 0;
  }
  ```
* **技术价值**：驱动不依赖任何公开符号，直接进入 `hal.dll` 内部搜索机器码，提取未经任何安全软件/内核 Hook 污染的原始 PCIe MMIO 控制器直读例程，赋给 `qword_1400FDF70`。

---

### 函数 2：`sub_140004D58`
* **地址**：`0x140004D58`，大小 `0x1E3`
* **作用**：**PCI/PCIe 全拓扑暴力枚举例程**。
* **执行流程与算法**：
  - 外层循环 `i` 从 `0` 至 `254`（BusNumber）。
  - 中层循环 `j` 从 `0` 至 `31`（DeviceNumber）。
  - 内层循环 `k` 从 `0` 至 `7`（FunctionNumber）。
  - PCI `SlotNumber` 计算公式：`v1 = (j & 0x1F) | ((32 * k) & 0xE0)`。
  - 调用 `HalGetBusDataByOffset(PCIConfiguration, Bus, Slot, Buffer, 0, 0x40u)`。
  - **暗影回退判断**：
    若 `Buffer[0] == 0xFFFF`，且 `qword_1400FDF70`（`sub_140024B6C` 获取的直读例程）存在，则强制调用 `qword_1400FDF70(0, Bus, Slot, Buffer, 0, 64)`。比对读取内容是否与全 `0xFF` 掩码（`unk_1400FDF80`）一致，不一致则判定存在故意屏蔽 HAL 读取的 DMA 设备。
  - 提取命中的硬件保存到 `unk_1400CDDB0` 数组中（单项 316 字节，上限 256 个设备）。

---

### 函数 3：`sub_1400066A4`
* **地址**：`0x1400066A4`，大小 `0x20A`
* **形参**：`ULONG BusNumber, char Device, char Func, int *AvgLatencyA0, int *AvgLatencyA8`
* **作用**：**PCIe TLP 写入时钟延迟侧信道探针（专门识别 FPGA DMA 硬件）**。
* **时序测量核心逻辑**：
  ```c
  // 提升 IRQL 至 DISPATCH_LEVEL (2)，屏蔽线程切换与时钟中断抖动
  __writecr8(2u);

  // 1. 针对偏移 0xA0 写入测试
  v13 = __rdtsc(); // 读取起始 CPU 周期数
  HalSetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber, &Buffer, 0xA0u, 2u);
  v14 = __rdtsc(); // 读取完成 CPU 周期数
  LatencyA0 = v14 - v13;

  // 2. 针对偏移 0xA8 写入测试
  v15 = __rdtsc();
  HalSetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber, &Buffer, 0xA8u, 2u);
  v16 = __rdtsc();
  LatencyA8 = v16 - v15;

  __writecr8(CurrentIrql); // 恢复 IRQL

  // 连续采样 3 次取均值
  *AvgLatencyA0 = (LatencyA0_1 + LatencyA0_2 + LatencyA0_3) / 3;
  *AvgLatencyA8 = (LatencyA8_1 + LatencyA8_2 + LatencyA8_3) / 3;
  ```
* **对抗启示**：
  - 真实物理网卡/声卡/显卡的 PCIe 配置空间寄存器是由硬件 ASIC 硅片响应，写入延迟通常在严格固定的极短周期（约 50~200 个周期）内完成。
  - FPGA（如 Xilinx Artix-7 35T/75T）在通过 IP 核或自定义固件模拟 PCI 配置空间时，由于状态机转发、FTDI USB 桥接或 BRAM 周期响应较慢，其写入延迟通常会有明显的微秒级膨胀或抖动。ACE 借此精确识别伪装成网卡的 DMA 板卡。

---

### 函数 4：`sub_1400065DC`
* **地址**：`0x1400065DC`，大小 `0xC5`
* **形参**：`ULONG BusNumber, char Device, char Func, _WORD *Buffer, size_t Size`
* **作用**：单设备安全读取封装，包含暗影 MMIO 二次探测与 `memcmp` 校验。

---

### 函数 5：`sub_14000797C`
* **地址**：`0x14000797C`，大小 `0x260`
* **作用**：**线程安全版全总线扫描导出例程**。
* **特性**：
  - 使用自旋互斥标志 `byte_140127CE4` 保证全量扫描在多线程并发下的单例执行。
  - 扫描完成后将全量表 `unk_1401004E0`（共 **80,896 字节**，256 项 × 316 字节）拷贝至调用者缓冲区 `a2`，并在 `*a3` 写入实际探测到的设备总数。

---

### 函数 6：`sub_14000AA64`
* **地址**：`0x14000AA64`，大小 `0xC1`
* **形参**：`ULONG BusNumber, char Device, char Func, ULONG Offset, SIZE_T NumberOfBytes, void *Dst`
* **作用**：动态分配 NonPagedPool 缓冲区的任意偏移 PCI 配置空间读取器，防止栈溢出并确保数据隔离。

---

### 函数 7：`sub_140019974`
* **地址**：`0x140019974`，大小 `0x287`
* **作用**：**独立显卡 PCIe 硬件探针与底层页表配置**。
* **识别逻辑**：
  ```c
  if ( HalGetBusDataByOffset(PCIConfiguration, 1u, 0, &Buffer, 0, 4u) == 4
       && (_WORD)Buffer == 4318 ) // 4318 = 0x10DE (PCI_VENDOR_ID_NVIDIA)
  {
      byte_14012E8A1 = 1; // 标记系统搭载 NVIDIA 主流独显
  }
  ```
  随后驱动分配 `0x204000u`（**2MB + 16KB**）的连续非分页内存池，获取物理地址后初始化专有的 GPU 映射监控上下文。

---

### 函数 8：`sub_140019EB4`
* **地址**：`0x140019EB4`，大小 `0x11F`
* **作用**：**原子级 PCI 设备快速查询与缓存表**。
* **结构**：
  - 驱动在 `word_1401484C0` 维持最多 100 项（`0x64`）的快速查找表。
  - 每次请求先查表，未命中时调用 `HalGetBusDataByOffset`，并通过 `_InterlockedExchangeAdd` 原子递增索引插入新设备缓存，降低对总线的重复轮询开销。

---

### 函数 9：`sub_14001C01C`
* **地址**：`0x14001C01C`，大小 `0x36F`
* **作用**：**PCI 设备拓扑状态与 IPI 多核感知绑定**。
* **执行特征**：
  - 遍历设备列表，调用 `MmGetPhysicalAddress` 校验设备映射物理基址。
  - 联动 `sub_14001C640` 发起多核 IPI 中断。
  - 触发 **4206 号风控日志上报**（`sub_14001161C`），将异常设备或未在合法白名单中的 PCIe 板卡的 `(Bus, VendorID, DeviceID)` 发送至反作弊分析核心。

---

### 函数 10：`sub_14001D45C`
* **地址**：`0x14001D45C`，大小 `0x68D`
* **作用**：**物理内存映射（ECAM / BAR）深层硬件枚举**。
* **核心机制**：
  - 调用 `MmMapIoSpace(PhysicalAddress, 0x1000u, MmNonCached)` 直接建立内核虚地址到物理地址的非缓存映射。
  - 绕过所有 Windows 系统硬件抽象层，直接解析芯片组 PCIe Enhanced Configuration Access Mechanism (ECAM) 内存区域，提取物理端点的 BAR 寄存器实际物理基址。

---

### 函数 11：`sub_140004918`
* **地址**：`0x140004918`，大小 `335` 字节 (`0x14F`)
* **形参**：`int VendorId, unsigned int DeviceId`
* **作用**：**单设备硬件快速缓存查询与设备对象虚拟机 Thunk 派发器**。
* **伪代码逻辑**：
  ```c
  char __fastcall sub_140004918(int VendorId, unsigned int DeviceId)
  {
    // 1. 在 848 字节单项的主缓存表 byte_1400C7A50 中线性搜索 (VendorId, DeviceId)
    for ( i = 0; i < dword_1400C5538; ++i ) {
      if ( table[i].VendorId == VendorId && table[i].DeviceId == DeviceId ) {
        // 找到设备对象，进入虚拟机深层审计例程 sub_1400047F0
        sub_1400047F0(table[i].DeviceObject, 1);
        return 1;
      }
    }
    // 2. 若未命中缓存，调用 sub_140005D48 遍历 \Driver\pci 设备栈进行实时同步
    sub_140005D48(sub_14000508C, &context);
    ...
  }
  ```

---

### 函数 12：`sub_140004A68`
* **地址**：`0x140004A68`，大小 `114` 字节 (`0x72`)
* **作用**：**全局 PCI 设备防伪就绪状态轮询例程**。
* **运行机制**：检查全局策略标志 `byte_1400BF1C0`，遍历 `dword_1400F55B8` 台当前系统中枚举到的所有 PCI 设备，验证其是否已通过底层特征安全核验。

---

### 函数 13：`sub_140004B6C`
* **地址**：`0x140004B6C`，大小 `383` 字节 (`0x17F`)
* **形参**：`int VendorId, int DeviceId`
* **作用**：**三表联合 PCI 设备合法性与驱动指针审计引擎**。
* **三表联动架构**：
  驱动维护了三张单项均为 848 字节的设备对象审计表：
  1. `unk_1400BF1D0`（容量 `dword_1400C5530`）：初始硬件静态快照表。
  2. `byte_1400F7AD0`（容量 `dword_1400F55B8`）：动态热插拔总线设备表。
  3. `byte_1400C7A50`（容量 `dword_1400C5538`）：受保护高危设备（GPU/网卡/DMA）白名单表。
  对每一项不仅匹配 Vendor/Device ID，且严格调用 `MmIsAddressValid(DeviceObject)` 校验内核指针合法性，防止安全软件或攻击者篡改设备对象地址。

---

### 函数 14：`sub_140004F3C`
* **地址**：`0x140004F3C`，大小 `335` 字节 (`0x14F`)
* **形参**：`char ForceReload`
* **作用**：**`\Driver\pci` 官方设备栈 80,896 字节拓扑表枚举器**。
* **核心动作**：
  - 清空大小为 **80,896 字节** 的核心拓扑缓冲 `unk_1400E19B0`。
  - 装载系统核心 PCI 驱动名称字符串：`L"\\Driver\\pci"`。
  - 调用 `sub_140026A24` 沿 `DriverObject->DeviceObject` 设备栈链表向下逐层深搜全部 PCI/PCIe 节点。

---

### 函数 15：`sub_140005150`
* **地址**：`0x140005150`，代码体积达 **1,521 字节** (`0x5F1`)
* **作用**：**设备对象属性深度审计与配置空间防篡改验证器**。
* **核心审计项目**：
  1. **设备扩展链审计**：检查 `DeviceObject->DeviceObjectExtension`，结合策略 `byte_1400A1000` 执行 `sub_14000A25C` 提取总线物理拓扑。
  2. **ANSI 符号名转换**：使用 `RtlUnicodeStringToAnsiString` 截取设备符号链接与硬件 ID，保存至设备记录头部（上限 259 字符）。
  3. **实时触发时钟延迟侧信道**：
     若全局标志 `byte_1400BF1C2 != 0`，对目标总线直接调用 `sub_1400066A4(Bus, Slot, Func, &LatencyA0, &LatencyA8)`，将测算到的真实硬件耗时写入设备结构偏移 `406` 和 `407`。
  4. **配置空间一致性审计**：
     比对内存缓存中的配置空间与实际读取值 `if ( (unsigned __int16)v12[140] != *(_DWORD *)v12 )`。若发现不一致，判定存在中间件篡改，调用 `sub_140007734` 直接向底层物理设备发送原始 IRP 设备控制报文强行获取真值。

---

### 函数 16：`sub_140005744`
* **地址**：`0x140005744`，大小 `781` 字节 (`0x30D`)
* **作用**：**双表交叉比对引擎：“幽灵 DMA 设备”（Ghost DMA Device）终结者**。
* **双表比对核心算法**：
  ```c
  // 1. 触发两路独立的设备扫描
  sub_140004D58(1); // 物理总线扫描：通过 HAL / MMIO 直接扫出来的物理硬件列表
  sub_140004F3C(1); // 操作系统设备栈：通过 \Driver\pci 设备树枚举出的合法设备列表

  // 2. 双重循环交叉比对
  // 遍历物理硬件列表中的每一项设备
  // 检查其是否存在于 \Driver\pci 操作系统驱动设备树中
  if ( 硬件在物理总线上存在 && 但在 \Driver\pci 设备树中缺失 )
  {
      // 判定命中经典 "Ghost DMA Device"（无系统驱动挂载的裸板 FPGA 板卡）！
      // 立即调用 sub_1400066A4 进行时钟侧信道延迟测算
      sub_1400066A4(Bus, Dev, Func, &LatencyA0, &LatencyA8);
      // 写入危险硬件黑名单 unk_1400F55C0 准备上报
  }
  ```
* **战略意义**：这是反作弊史上最著名的 DMA 检测机制。FPGA 硬件插在 PCIe 插槽上，配置空间会响应物理总线扫描，但黑客通常不会为其在 Windows 中注册真实驱动对象。ACE 通过双表比对，无须任何特征码即可秒级定位这种“裸板硬件”。

---

### 函数 17：`sub_140005A54`
* **地址**：`0x140005A54`，大小 `753` 字节 (`0x2F1`)
* **作用**：**`\Driver\pci` 25,440 字节备用拓扑表构建器**。清空 `byte_1400F7AD0` 并构建辅助索引，确保在高频热插拔或多总线并发时拓扑无竞争。

---

### 函数 18：`sub_1400065DC`
* **地址**：`0x1400065DC`，大小 `197` 字节 (`0xC5`)
* **形参**：`ULONG BusNumber, char Device, char Func, _WORD *OutBuffer, size_t Size`
* **作用**：**带暗影 MMIO 回退的 PCI 配置空间安全读取包装**。调用 `HalGetBusDataByOffset`，若返回全 `0xFFFF`，无缝回退至私有 MMIO 读函数 `qword_1400FDF70`，防止 Hook。

---

### 函数 19：`sub_140007734`
* **地址**：`0x140007734`，大小 `284` 字节 (`0x11C`)
* **形参**：`PDEVICE_OBJECT DeviceObject, int IsWrite, struct _UNICODE_STRING *FileName, DWORD Offset, ULONG Length`
* **作用**：**标准 WDM `IRP_MJ_PNP` (0x1B) 物理总线配置空间 IRP 直发例程**。
* **伪代码核心**：
  ```c
  __int64 __fastcall sub_140007734(PDEVICE_OBJECT DeviceObject, int IsWrite, struct _UNICODE_STRING *FileName, DWORD Offset, ULONG Length)
  {
    KeInitializeEvent(&Object, NotificationEvent, 0);
    AttachedDeviceReference = IoGetAttachedDeviceReference(DeviceObject);
    if ( AttachedDeviceReference != nullptr )
    {
      // 0x1B = IRP_MJ_PNP
      v11 = IoBuildSynchronousFsdRequest(0x1Bu, AttachedDeviceReference, nullptr, 0, nullptr, &Object, &IoStatusBlock);
      if ( v11 != nullptr )
      {
        CurrentStackLocation = v11->Tail.Overlay.CurrentStackLocation;
        CurrentStackLocation[-1].Parameters.Read.Length = 0;
        // MinorFunction: 15 = IRP_MN_READ_CONFIG, 16 = IRP_MN_WRITE_CONFIG
        CurrentStackLocation[-1].MinorFunction = (IsWrite != 0) + 15;
        CurrentStackLocation[-1].Parameters.Create.EaLength = Length;
        CurrentStackLocation[-1].Parameters.QueryDirectory.FileName = FileName;
        CurrentStackLocation[-1].Parameters.Read.ByteOffset.LowPart = Offset;
        Status = IofCallDriver(AttachedDeviceReference, v11);
        if ( Status == STATUS_PENDING ) {
          KeWaitForSingleObject(&Object, Executive, 0, 0, nullptr);
          Status = IoStatusBlock.Status;
        }
      }
      ObfDereferenceObject(AttachedDeviceReference);
    }
    return Status;
  }
  ```
* **攻防战略价值**：ACE 放弃常规内核 API，直接构造同步 PnP IRP 并向底层物理驱动栈发起 `IRP_MN_READ_CONFIG`。即便攻击者在 HAL 导出表上 Hook 了 `HalGetBusDataByOffset`，该函数也能通过底层总线过滤驱动强读硬件真实寄存器，使外挂的虚假伪装彻底失效。

---

### 函数 20：`sub_14000797C`
* **地址**：`0x14000797C`，大小 `608` 字节 (`0x260`)
* **作用**：**并发线程安全版全拓扑总线扫描器**。支持将扫描到的硬件节点直接导出至外部指定缓冲区，并返回原子计数，防止多核竞争。

---

### 函数 21：`sub_140007BDC`
* **地址**：`0x140007BDC`，大小 `335` 字节 (`0x14F`)
* **作用**：**第二套深层 PCI 设备树 80,896 字节拓扑表初始化**。清空并构建独立的备用拓扑结构 `unk_1401140E0`，用于对抗攻击者针对主设备表的内存清零攻击。

---

### 函数 22：`sub_140007D2C`
* **地址**：`0x140007D2C`，代码体积达 **1,413 字节** (`0x585`)
* **作用**：**单项 10,353 字节超大硬件全指纹深度提取器**。
* **提取项目**：
  1. **设备实例路径与符号链接**：通过 `RtlUnicodeStringToAnsiString` 截取设备全名。
  2. **4 组硬件兼容识别符**：调用 `sub_140009FE8` / `sub_140009E88` 提取 4 组 Compatible IDs。
  3. **双份配置空间镜像比对**：在偏移 `+280` 与 `+4376` 分别存放 HAL 读取与 IRP 直读的两份镜像，只要存在单字节不匹配立即触发上报。
  4. **步进游标**：单设备记录占用 `10,353` 字节，支持最多 32 个深层节点的完整物理硬件快照保存。

---

### 函数 23：`sub_140009FE8`
* **地址**：`0x140009FE8`，大小 `506` 字节 (`0x1FA`)
* **形参**：`PDEVICE_OBJECT DeviceObject`
* **作用**：**Windows 设备安装类（`DevicePropertyClassName`）特征匹配与硬件分类器**。
* **伪代码逻辑与分类对照**：
  ```c
  __int64 __fastcall sub_140009FE8(PDEVICE_OBJECT DeviceObject)
  {
    wchar_t *Pool = (wchar_t *)ExAllocatePool(NonPagedPool, 0x100u);
    if ( IoGetDeviceProperty(DeviceObject, DevicePropertyClassName, 0x100u, Pool, &ResultLength) == 0 )
    {
      if ( !_wcsicmp(Pool, L"Net") )                 return 1; // 网络适配器 (高危 DMA 伪装对象)
      else if ( !_wcsicmp(Pool, L"Display") )         return 2; // 显卡显示设备
      else if ( !_wcsicmp(Pool, L"System") )          return 3; // 主板系统组件
      else if ( !_wcsicmp(Pool, L"USB") )             return 4; // USB 控制器
      else if ( !_wcsicmp(Pool, L"SCSIAdapter") )     return 5; // 存储控制器
      else if ( !_wcsicmp(Pool, L"MEDIA") )           return 6; // 声卡/媒体设备 (高危 DMA 伪装对象)
      else if ( !_wcsicmp(Pool, L"DiskDrive") )       return 8; // 硬盘驱动器
      else if ( !_wcsicmp(Pool, L"SoftwareComponent") ) return 9; // 软件虚拟设备
    }
    return 0; // 未知/未归类硬件
  }
  ```
* **攻防意义**：ACE 将所有硬件划分为固定分类。市面上大量将 FPGA 伪装成网卡（Net）或声卡（MEDIA）的固件，都会被打上分类标签并接受更严格的设备栈与时钟耗时专项审计。

---

### 函数 24：`sub_140009E88`
* **地址**：`0x140009E88`，大小 `351` 字节 (`0x15F`)
* **作用**：**设备硬件兼容识别符（Compatible IDs / Hardware IDs）提取器**。调用 `IoGetDeviceProperty` 抓取并格式化输出 4 组标准设备指纹串。

---

### 函数 25：`sub_140008C4C`
* **地址**：`0x140008C4C`，大小 `124` 字节 (`0x7C`)
* **作用**：**分块二分法安全递减 IRP 配置读取重试器**。
* **特性**：当通过 `sub_140007734` 发送 `IRP_MN_READ_CONFIG` 读取指定长度失败时，采用 `Length >>= 1` 循环二分递减重试，确保面对微控制器响应不完全的非常规板卡时仍能成功抓取局部配置空间。

---

### 函数 26：`sub_140008B8C`
* **地址**：`0x140008B8C`，大小 `189` 字节 (`0xBD`)
* **作用**：**80,896 字节（`0x13C00`）动态拓扑比对池分配器**。分配独立的大块非分页内存暂存实时扫描镜像，与主表进行多核差量计算。

---

### 函数 27：`sub_140009A70` / `sub_140009B70`
* **地址**：`0x140009A70` (254 字节) & `0x140009B70` (791 字节)
* **作用**：**全物理核心 CPU 亲和度线程绑定与多核并行拓扑巡检引擎**。
* **机制**：
  - 调用 `KeQueryActiveProcessorCountEx(0xFFFFu)` 枚举系统所有处理器核心。
  - 配合 `KeSetSystemAffinityThreadEx` 将检测执行流依次在各个 CPU 核心上轮换调度，粉碎外挂试图在单个 CPU 核心上挂起或节流反作弊检测线程的逃避手段。

---

### 函数 28：`sub_140008CDC` / `sub_140009198` / `sub_14000948C`
* **地址**：`0x140008CDC` (1170 B), `0x140009198` (753 B), `0x14000948C` (1396 B)
* **作用**：**跨特权级硬件拓扑安全传输与用户态探针通道**。
* **机制**：调用 `sub_140024194` 严格校验目标缓冲区是否位于合法应用层虚地址空间（`< 0x800000000000`），将内核收集的硬件全量指纹以安全零拷贝或同步报文形式回传给上层游戏客户端。

---

### 函数 29：`sub_14000A1E4`
* **地址**：`0x14000A1E4`，大小 `119` 字节 (`0x77`)
* **作用**：**Windows 操作系统构建版本（Build Number）自适应分流调度器**。
* **分流对照逻辑**：
  ```c
  char __fastcall sub_14000A1E4(__int64 a1, _QWORD *a2, _QWORD *a3)
  {
    unsigned int build = sub_140029BA0(); // 提取系统内核 Build 号
    if ( build >= 0x4A61 ) // Build 19041 (Win10 2004)
    {
      if ( build <= 0x4E20 ) // <= Build 20000 (Win10 全系)
        return sub_140009A70(a1, a2, a3);
      if ( build < 0x7530 )  // < Build 30000 (Win11 全系，含 24H2 / Build 26100)
        return sub_140009B70(a1, a2, a3);
    }
    return 0;
  }
  ```

---

### 函数 30：`sub_14000A25C`
* **地址**：`0x14000A25C`，代码体积达 **1,061 字节** (`0x425`)
* **形参**：`PDEVICE_OBJECT DeviceObject, ULONG *OutBus, ULONG *OutDev, ULONG *OutFunc`
* **作用**：**核心 PCI 物理拓扑（Bus / Device / Function）逆向解析引擎**。
* **特性**：
  - 深度解析 `DeviceObject->DeviceObjectExtension` 内部私有未文档化结构。
  - 从 PnP 硬件路径字符串中提取目标设备的物理 PCIe BDF 坐标，是驱动内将逻辑设备对象映射到底层物理总线槽位的核心换算例程。

---

### 函数 31：`sub_14000A684`
* **地址**：`0x14000A684`，大小 `202` 字节 (`0xCA`)
* **作用**：**NDIS 网络适配器专用配置与底层协议绑定审计例程**。
* **特征结构**：
  - 构建标准 NDIS 配置对象：`struct _NDIS_CONFIGURATION_OBJECT ConfigObject`。
  - 通过 NDIS 内部句柄读取适配器的真实驱动配置与 NDIS 6.x 过滤驱动绑定状态，专门用于戳穿“仅伪装网卡 ID 但无真实 NDIS 协议栈”的粗糙 DMA 固件。

---

### 函数 32：`sub_14000A904`
* **地址**：`0x14000A904`，大小 `352` 字节 (`0x160`)
* **作用**：**Net 类设备微端口（Miniport）与物理 MAC 驱动栈合法性校验**。
* **逻辑**：仅在 `sub_140009FE8(DeviceObject) == 1`（即网卡类）时激活，深入检查设备扩展中的 Miniport Block，确认其是否由微软或官方厂商签名网卡驱动驱动。

---

### 函数 33：`sub_14000AFDC`
* **地址**：`0x14000AFDC`，大小 `238` 字节 (`0xEE`)
* **作用**：**同步 PnP 设备状态探测 IRP 发送器**。构造内部控制 IRP 并通过 `IoGetAttachedDeviceReference` 向底层驱动栈派发，探测设备是否处于活动在线状态。

---

### 函数 34：`sub_14000B0CC`
* **地址**：`0x14000B0CC`，大小 `199` 字节 (`0xC7`)
* **作用**：**受控硬件设备链表 `unk_140127D00` 全量巡检与 IRP 完成键防篡改验证**。
* **安全核验**：遍历高危硬件链表，逐一调用 `sub_14000AFDC` 发送心跳检测，严格验证 IRP 完成键 `Irp[1].Tail.CompletionKey` 是否被外挂挂钩破坏。

---

### 函数 35：`sub_1400185D0`
* **地址**：`0x1400185D0`，大小 `351` 字节 (`0x15F`)
* **作用**：**主板 BIOS/UEFI 固件 ACPI 表（MCFG / DMAR / IVRS）直读与物理 MMIO 映射总线**。
* **核心硬件标头识别**：
  - `0x4746434D` (`'MCFG'`): **PCI Express 内存映射配置空间（ECAM）基址表**。提取整机所有 PCIe 设备的物理 MMIO 配置空间基地址。
  - `0x52414D44` (`'DMAR'`): **DMA 重映射报告表（Intel VT-d 硬件规范）**。提取硬件 DMA 隔离单元物理地址。
  - `0x53525649` (`'IVRS'`): **I/O 虚拟化重定位表（AMD-Vi 硬件规范）**。
* **逻辑**：
  - 调用 `sub_140018540` 提取上述 ACPI 表的物理地址。
  - 调用 `MmGetPhysicalAddress` 提取表头物理起始。
  - 核心操作：**`MmMapIoSpace(PhysicalAddress, Length, MmNonCached)`** 将固件原始物理内存直接映射为内核虚拟指针，绕过操作系统任何高层硬件抽象。

---

### 函数 36：`sub_140018730` & `sub_140018950`
* **地址**：`0x140018730` (440 B), `0x140018950` (213 B)
* **作用**：**HAL 缓存 ACPI 结构深度解析与物理设备条目遍历器**。
* **机制**：
  - 调用 `HalDispatchTable->HalGetCachedAcpiTable` 获取 `0x54435041` (`'APCT'`) / `0x52414D44` (`'DMAR'`) 原始缓存镜像。
  - `sub_140018950`：步进遍历 ACPI 子结构（步长 4 或 8 字节），提取各 PCIe 总线范围与硬件单元描述符，调用 `MmMapIoSpace` 针对匹配的子单元直接核验。

---

### 函数 37：`sub_1400184FC`
* **地址**：`0x1400184FC`，大小 `44` 字节
* **作用**：**物理页帧对齐与特权物理属性掩码提取器**。
* **逻辑**：`*(_QWORD *)(a1 + 32) = MmGetPhysicalAddress(a2).QuadPart & 0xFFFFFFFFFFFFF000uLL;`，按 4KB 页面边界对齐并打上 `0x40000000` 特权标志。

---

### 函数 38：`sub_140018A6C`
* **地址**：`0x140018A6C`，大小 `159` 字节
* **作用**：**驱动设备栈全量设备对象枚举器（Driver Device Stack Enumerator）**。
* **逻辑**：两次调用 `IoEnumerateDeviceObjectList(DriverObject, ...)`：第一次传入 NULL 探知设备对象个数 `ActualNumberDeviceObjects`；随后分配 NonPagedPool 数组完整提取属于该驱动对象的所有 `PDEVICE_OBJECT` 节点。

---

### 函数 39：`sub_140018B20`
* **地址**：`0x140018B20`，大小 `640` 字节 (`0x280`)
* **作用**：**`\Driver\Disk` 存储核心驱动引用与 4211 号硬件安全遥测总线**。
* **逻辑**：
  - 调用 `ObReferenceObjectByName(L"\\Driver\\Disk", ...)` 获取系统硬盘总线驱动对象指针并存入 `qword_14012E880 + 512`。
  - 检查硬盘底层挂载拓扑，一旦检测到异常虚拟磁盘、透传虚拟化镜像或未签名存储过滤驱动，发射 **4211 号存储设备遥测事件**。

---

### 函数 40：`sub_140018DD0`
* **地址**：`0x140018DD0`，大小 `285` 字节 (`0x11D`)
* **形参**：`PDEVICE_OBJECT DeviceObject, char a2, __int64 a3`
* **作用**：**底层存储控制码 `0x4D014` 物理硬盘特征直读器（Storage Query Property）**。
* **逻辑**：
  - 构造 56 字节结构体：`InputBuffer = 56; v14 = 4096; v17 = 56;`。
  - 调用 `IoBuildDeviceIoControlRequest(0x4D014u, DeviceObject, ...)`。
  - 直接下发至目标存储设备对象，穿透所有高层文件系统，强读硬盘物理序列号（Serial Number）、产品型号与固件版本。

---

### 函数 41：`sub_140018EF0`
* **地址**：`0x140018EF0`，代码体积达 **`1,259` 字节 (`0x4EB`)**
* **作用**：**磁盘设备栈全量遍历、异或字符串解密与物理 BDF 拓扑提取（Disk Stack Walker）**。
* **动态解密驱动特征串**：
  - 密文 1：`"Bnmw@pkjq'yr"` 逐字节异或解密。
  - 密文 2：`"iBcea=Hb|9$xu~"` 逐字节异或解密。
* **机制**：
  - 枚举 `\Driver\Disk` 挂载的所有设备对象（`sub_140018A6C`）。
  - 对每个物理磁盘设备下发 `sub_140018DD0` 获取硬件信息。
  - 若设备产生错误或被外挂拦截，记录违规分值并触发 4211 遥测。
  - 提取磁盘对应的物理 PCIe BDF 坐标（Bus, Dev, Func）与扇区物理映射，多核并发上报。

---

### 函数 42：`sub_140019498` & `sub_1400196AC`
* **地址**：`0x140019498` (532 B), `0x1400196AC` (209 B)
* **作用**：**PCIe 槽位 100 字节数组自旋锁并发扫描、4213 遥测与 Intel/AMD 平台分流审计**。
* **自旋锁与数据结构**：
  - 使用原子 CAS 自旋锁保护：`_InterlockedCompareExchange(&dword_14012EB28, 1, 0)` 配合 `_mm_pause()`。
  - 遍历以 **100 字节** 为步长的设备描述符数组（`&unk_14012E8C8`）。
  - 提取物理地址 `v11 & 0xFFFFFFFFFFFFF000` 与硬件 BDF 坐标，发射 **4213 号硬件拓扑遥测事件**。
* **平台分流**：
  - `sub_1400196AC`：若为 Intel 芯片组（`sub_140024394`），调用 `sub_14001D45C` 进行 MMIO/BAR 审计；若为 AMD 芯片组（`sub_14002429C`），遍历 81 字节槽位数组调用 `sub_14001C01C` 执行专有 IOMMU 审计。

---

### 函数 43：`sub_140019780` ~ `sub_1400198EC`
* **地址与大小**：
  - `sub_140019780` (91 B): 释放并清理 `qword_140138770` 分配池。
  - `sub_1400197DC` (93 B): 平台芯片组特征码核验，若为 AMD 平台返回特定标识 `206`。
  - `sub_14001983C` (69 B): AMD 平台 81 字节槽位轮询探测 `sub_14001C45C`。
  - `sub_140019884` (104 B): 自旋锁保护下的描述符表加载 `sub_14001DB28`。
  - `sub_1400198EC` (133 B): 针对单个物理页下发 MMIO 映射审计，并根据平台配置硬件拦截。

---

### 函数 44：`sub_140019974`
* **地址**：`0x140019974`，大小 **`647` 字节 (`0x287`)**
* **作用**：**巨型硬件审计初始化例程与 2MB 大页 NonPagedPool 暗影页表构建（Hardware Shadow Page Setup）**。
* **逻辑**：
  - 调用 `sub_1400185D0` 获取主板 ACPI MCFG 物理空间映射。
  - 遍历系统 PCI 设备列表，比对显卡厂商 ID `4318` (`0x10DE` 即 NVIDIA)，确认显示控制器的物理位置。
  - 核心分配：分配 **`0x204000` 字节（2MB 大页 + 16KB 元数据，标签 `'meta'`，NonPagedPool）** 的超大连续非分页内存。
  - 将该物理内存注册至 `qword_14012E8A8`，专门构建作为物理硬件与 DMA 暗影页表监控中继。

---

### 函数 45：`sub_140019BFC` & `sub_140019C64`
* **地址**：`0x140019BFC` (103 B), `0x140019C64` (392 B)
* **作用**：**物理地址更新刷新器与硬件审计安全退出清理例程（MMIO Teardown Engine）**。
* **机制**：
  - `sub_140019BFC`：刷新 MMIO 监控引擎中指定的物理页基址。
  - `sub_140019C64`：逐一遍历已经映射的 `0x1000` (4KB) 及 `0x3000` 大小的物理 MMIO 缓冲区，调用 `MmUnmapIoSpace` 安全解除映射，并将关联的 2MB 大页 NonPagedPool 释放回收，防止在驱动卸载时造成系统内核物理泄露。

---

### 函数 46：`sub_140019DEC` ~ `sub_140019E8C`
* **地址**：`0x140019DEC`, `0x140019E14`, `0x140019E3C`, `0x140019E64`, `0x140019E8C`（每个 40 字节）
* **作用**：**安全分发包装跳板（Safety Wrappers / Trampolines）**。
* **逻辑**：所有函数均首先校验传入指针 `a1 != 0`，若为 NULL 立即返回 `0xC0000001` (`STATUS_UNSUCCESSFUL`)；校验合法后分别派发至：
  - `sub_140019DEC` -> `sub_140019FD4` (4207 硬件违规遥测)
  - `sub_140019E14` -> `sub_14001A498` (CPUID 硬件架构指纹)
  - `sub_140019E3C` -> `sub_14001A2A4` (违规设备 120 字节导出)
  - `sub_140019E64` -> `sub_14001AED8`
  - `sub_140019E8C` -> `sub_14001B7FC`

---

### 函数 47：`sub_140019EB4`
* **地址**：`0x140019EB4`，大小 `287` 字节 (`0x11F`)
* **形参**：`__int16 a1, unsigned __int16 Bus, char Device, char Function, _WORD *VendorId, _WORD *DeviceId`
* **作用**：**PCI 配置空间高速原子缓存引擎与底层 `HalGetBusDataByOffset` 穿透直读**。
* **结构与并发**：
  - 维护最多 100 项（`0x64`）的全局三元组缓存数组 `word_1401484C0`（每项 6 字节：`[Key, VendorID, DeviceID]`）。
  - 先查表，若命中直接取出返回，极大地降低总线 I/O 延迟与开销。
  - 若未命中：直接调用 HAL 原生导出例程：
    ```c
    HalGetBusDataByOffset(PCIConfiguration, Bus, Device & 0x1F | (32 * (Function & 7)), &Buffer, 0, 4u);
    ```
  - 读取成功后，使用原子原语 `_InterlockedExchangeAdd(&dword_1401484B4, 1u)` 写入缓存表。

---

### 函数 48：`sub_140019FD4` & `sub_14001A268`
* **地址**：`0x140019FD4` (**`658` 字节**), `0x14001A268` (59 字节)
* **作用**：**PCIe 硬件拓扑全景扫描、暗影表状态核验与 4207 号核心硬件安全遥测总线**。
* **业务逻辑**：
  - 遍历由 5000 个 64 字节槽位组成的监控表 `qword_140148468`。
  - 匹配状态位：`v8[v13 + 3] == 0 && *(_QWORD *)&v8[v13 + 8] != 0 && v8[v13 + 1] != 0 && v8[v13 + 2] == 0`（即已触发 Trap 拦截且尚未上报的硬件节点）。
  - 调用 `sub_140019EB4` 提取该槽位对应的 Bus/Dev/Func 以及 Vendor ID / Device ID。
  - 判定 CPU 芯片组类型：`sub_140024394` (Intel) / `sub_14002429C` (AMD)。
  - **发射核心 4207 号遥测事件**：
    ```c
    sub_14001161C(nullptr, 4207, VendorId, DeviceId, PhysAddrLow, ..., IntelFlag, AmdFlag, ...);
    ```
  - 将硬件状态以 108 字节步长格式化输出至外部调用者。

---

### 函数 49：`sub_14001A2A4`
* **地址**：`0x14001A2A4`，大小 **`499` 字节 (`0x1F3`)**
* **作用**：**硬件隔离异常槽位 120 字节描述符批量导出例程**。
* **机制**：
  - 遍历 `qword_140148468`，筛选出被标记为硬件隔离或致命违规的槽位（`v8[v13 + 3] != 0`）。
  - 提取对应物理地址、PCI 配置空间坐标、拦截计数器与错误状态字（`+56`, `+60`）。
  - 以 **120 字节** 结构体步长导出至用户指定缓冲区，并原子复位事件计数 `dword_140148718`。

---

### 函数 50：`sub_14001A498`
* **地址**：`0x14001A498`，大小 `287` 字节 (`0x11F`)
* **作用**：**处理器与芯片组架构硬件指纹采集器（CPUID & Hygon/AMD/Intel Recognition）**。
* **指纹采集逻辑**：
  - 缓冲区大小严格校验：必须为 88 字节（`*(_DWORD *)a1 == 88`）。
  - 平台初步识别：
    - Intel 芯片组：标记 `1`
    - AMD 芯片组：标记 `2`
    - 其他平台：标记 `3`
  - 原生内联执行 **CPUID** 指令：
    - 执行 `cpuid(0)` 获取支持的最大功能号。
    - 连续遍历扩展功能号 `0x80000002`、`0x80000003`、`0x80000004`，拼接出 48 字节 CPU 完整 Brand String。
    - 全文转换为小写字母（`*v21 += 32`）。
  - **国产海光（Hygon）芯片组专属识别**：
    ```c
    if ( *(_BYTE *)(v5 + 1) == 3 && strstr((const char *)(v5 + 8), "hygon") != nullptr )
        *(_BYTE *)(v5 + 1) = 4;
    ```
    精准将海光处理器独立识别并赋予平台码 `4`。

---

### 函数 51：`sub_14001A5B8`
* **地址**：`0x14001A5B8`，大小 `580` 字节 (`0x244`)
* **作用**：**物理内存 64 字节固件特征直读与大端转小端字符串指纹提取**。
* **逻辑**：
  - 传入物理地址 `PHYSICAL_ADDRESS a1`。
  - 调用 `MmMapIoSpace(a1, 0x1000u, MmNonCached)` 建立直接物理内存映射。
  - 拷贝物理内存起始 64 字节（`0x40`）。
  - 使用 `_byteswap_uint64` 进行字节序翻转，通过 `sub_140028BD0` 格式化为两组 65 字节十六进制字符串（分别保存在 `unk_140148420` 与 `unk_140148470`）。
  - 提取完成后立即调用 `MmUnmapIoSpace` 释放，实现对固件/硬件 ROM 无残留快速特征采集。

---

### 函数 52：`sub_14001A7FC` ~ `sub_14001AD6C`
* **地址与大小**：
  - `sub_14001A7FC` (525 B): 模块识别与原子挂钩例程
  - `sub_14001AA0C` (279 B): 多核处理器设备栈挂钩分发
  - `sub_14001AB24` (101 B) & `sub_14001AB8C` (92 B): 键盘挂钩初始化
  - `sub_14001AD6C` (193 B): 挂接后的键盘中断分发处理例程
* **作用**：**`i8042prt.sys` PS/2 键盘与底层硬件输入中断过滤驱动 Hook 链**。
* **机制剖析**：
  - ACE 深入底层识别键盘驱动模块 `L"i8042prt.sys"`。
  - 提取其内部中断分发服务例程 `v2 + 24` 与 `v2 + 32`。
  - 备份至 1024 槽位（`0x400`）全局表 `unk_1401423C0`（每项 24 字节：`[原对象, 原始偏移+24, 原始偏移+32]`）。
  - 使用原子指令 `_InterlockedExchange64` 将其替换为 ACE 私有中继 `sub_14001AD6C`。
  - **`sub_14001AD6C` 拦截逻辑**：
    - 原子递增并发执行计数 `_InterlockedIncrement(&dword_1401483C0)`。
    - AMD 平台触发 `sub_14001983C`，Intel 平台触发 `sub_140019884` 校验当前是否伴随非法硬件 DMA 事务。
    - 校验完成后透传给原始键盘中断例程执行，退出时原子递减计数器。

---

### 函数 53：`sub_14001ABE8` & `sub_14001B554`
* **地址**：`sub_14001ABE8` (388 B), `sub_14001B554` (103 B)
* **作用**：**5000 槽位 312.5KB MMIO 暗影监控表分配与主控总线**。
* **核心数据结构**：
  - 分配 `0x4E200` 字节（320,000 字节 = 312.5 KB）的 NonPagedPool 存储在 `qword_140148468`。
  - 整个表由 **5,000 个 64 字节（`0x40`）的槽位** 组成：
    | 偏移 | 类型 | 含义 |
    | :--- | :--- | :--- |
    | `+0` | `UCHAR` | Active 激活标志（1=正在监视，0=空闲） |
    | `+1` | `UCHAR` | TrapHit 访问触发标志（1=发生硬件 Trap） |
    | `+2` | `UCHAR` | Processed 已上报处理标志 |
    | `+3` | `UCHAR` | IsPrivileged 高危属性（受控敏感内存） |
    | `+8` | `PVOID` | 监视的虚拟地址 VirtualAddress (4KB 对齐) |
    | `+16` | `PHYSICAL_ADDRESS` | 对应的真实物理内存地址 PhysicalAddress |
    | `+24` / `+40`| `OWORD` (16B) | 硬件拦截时捕获的现场寄存器快照 |
    | `+56` | `ULONG` | 该物理页面累计 Trap 触发次数 |
    | `+60` | `ULONG` | 违规状态字 |
  - 记录当前游戏/保护进程 ID：`qword_1401484B8 = PsGetCurrentProcessId()`。
  - 串联调用 `sub_140019974` (2MB 大页) 与 `sub_14001AB24` (i8042prt 键盘 Hook)。

---

### 函数 54：`sub_14001B2B4` & `sub_14001BA2C`
* **地址**：`sub_14001B2B4` (**`670` 字节**), `sub_14001BA2C` (222 字节)
* **作用**：**动态暗影 MMIO 页面 Trap 注册与注销引擎（Register/Unregister Shadow Pages）**。
* **注册逻辑 (`sub_14001B2B4`)**：
  - 接收任意内存范围 `BaseAddress` 与 `Length`。
  - 计算涉及的 4KB 页数：`v6 = (Length >> 12) + ((Length & 0xFFF) != 0)`。
  - 逐页调用 `MmGetPhysicalAddress`，在 5000 槽位表中寻找空闲项进行登记。
  - 调用 `sub_1400198EC` 将硬件页表配置为非法/受控属性，使外设在访问该物理地址时触发硬件 Trap 中断。
* **注销逻辑 (`sub_14001BA2C`)**：
  - 逐页比对虚拟地址，在 5000 槽位表中清零并调用 `sub_140019BFC` 还原物理页表属性。

---

### 函数 55：`sub_14001B5BC`, `sub_14001B678` & `HandleInformation`
* **地址**：`sub_14001B5BC` (188 B), `sub_14001B678` (129 B), `HandleInformation` (`0x14001AE30`, 167 B)
* **作用**：**硬件巡检系统后台线程管理与 30 秒安全看门狗（System Watchdog Thread）**。
* **生命周期**：
  - `sub_14001B5BC`：使用 `PsCreateSystemThread` 派生系统守护线程，入口函数为 `HandleInformation`。
  - `HandleInformation` (`0x14001AE30`)：
    - 绑定同步事件 `stru_140148720`。
    - 循环最多 30 次，每次调用 `KeWaitForSingleObject` 挂起 1 秒（`Timeout = -10000000`）。
    - 超时或收到周期信号后，触发 `sub_14001BCB8` 执行全量芯片组与 DMA 物理巡检。
    - 完成后调用 `PsTerminateSystemThread(0)` 自行终止退栈。
  - `sub_14001B678`：设置退出标志 `byte_140148750 = 1`，触发事件并等待线程句柄安全回收。

---

### 函数 56：`sub_14001B898` & `sub_14001B964`
* **地址**：`sub_14001B898` (201 B), `sub_14001B964` (200 B)
* **作用**：**硬件 MMIO 访问违规 Trap 现场捕获与事件标记例程**。
* **机制**：
  - 当物理总线或硬件设备访问受控物理页时进入：
  - 快速匹配物理地址 `PhysicalAddress & 0xFFFFFFFFFFFFF000`。
  - 捕获异常现场 16 字节上下文并存入槽位 `+24` 或 `+40`。
  - 将槽位状态标记为 `Active = 0`, `TrapHit = 1`。
  - 原子增加未决安全事件计数：`_InterlockedIncrement(&dword_140148718)`。
  - 在当前上下文结构体中打上违规标记（`*(a2 + 80) = 1` 或 `*(a2 + 96) = 1`）。

---

### 函数 57：`sub_14001B6FC` & `sub_14001B760`
* **地址**：`sub_14001B6FC` (99 B), `sub_14001B760` (145 B)
* **作用**：**1024 槽位 Hook 安全还原与自旋锁无缝卸载引擎（Graceful Unload Engine）**。
* **自旋锁与解挂流程**：
  - `sub_14001B6FC`：倒序遍历 1024 项 Hook 数组 `unk_1401423C0`，原子写回原始例程指针（`_InterlockedExchange64` 还原 `+24` 与 `+32`）。
  - `sub_14001B760`：
    - 停掉巡检线程（`sub_14001B678`）。
    - 释放 2MB 大页与 MMIO 映射（`sub_140019C64`）。
    - 解除键盘驱动 Hook（`sub_14001B6FC`）。
    - **自旋锁等待所有正在执行的并发 Hook 例程退出**：
      ```c
      while ( _InterlockedCompareExchange(&dword_1401483C0, 0, 0) != 0 )
          KeStallExecutionProcessor(10u);
      ```
      彻底杜绝并发下由于例程尚未执行完毕直接释放内存造成的系统蓝屏（BugCheck）。
    - 安全释放 `0x4E200` 字节的 5000 槽位 NonPagedPool 内存池。

---

### 函数 58：`sub_14001BB0C` & `sub_14001BB78`
* **地址与大小**：
  - `sub_14001BB0C` (108 B): 5000 槽位暗影表全量清理与硬件页表属性复位。
  - `sub_14001BB78` (318 B): **AMD IOMMU 页表 PTE 权限篡改与 Trap 注入器**。
* **PTE 篡改逻辑 (`sub_14001BB78`)**：
  - 传入虚拟地址 `a2`，解析多级页表偏移：
    ```c
    v9 = &a1[4096 * ((a2 >> 30) & 0x1FF) + 0x2000 + 8 * ((a2 >> 21) & 0x1FF)];
    ```
  - 调用 `MmMapIoSpace(*(_QWORD *)v9 & 0xFFFFFFFFFF000LL, 0x1000u, MmNonCached)` 映射物理页表。
  - 提取目标页表条目（PTE）：`v11 = (a2 >> 12) & 0x1FF`。
  - 若 `a4 != 0`，清除 Bit 61/62；若 `a4 == 0`，强行植入受控属性：`v10[v11] |= 0x2000000000000000LL`（AMD 规范下的保护/Trap 属性）。
  - 当任何 DMA 外设向该物理页写入时，AMD 芯片组立即触发硬件级 I/O Page Fault！

---

### 函数 59：`sub_14001BDE4` & `sub_14001BD88`
* **地址**：`sub_14001BDE4` (**`322` 字节**), `sub_14001BD88` (89 字节)
* **作用**：**2.1MB AMD-Vi 512GB 物理内存暗影页表与 DTE 规范完整构建器（AMD Shadow IOMMU Setup）**。
* **页表构建流程**：
  - 核心分配：分配 **`0x202000` 字节（2MB 大页 + 8KB，共 2,105,344 字节）** 的连续 NonPagedPool。
  - 根目录（PML4）打上属性：`*v2 |= 0x6000000000000001uLL`（Present + 读写许可）。
  - 初始化 512 个 PDPT 目录条目：`*v3 = 0x6000000000000401LL`，并关联下一级物理页帧号。
  - 以 `0x200000`（2MB 大页）为步长，连续填充页表条目：
    ```c
    do {
        for ( i = 512; i != 0; --i ) {
            *v4++ = v1 & 0xFFFFFFFFFF000LL | 0x6000000000000001LL;
            v1 += 0x200000LL;
        }
    } while ( v1 < 0x8000000000LL ); // 覆盖整整 512GB 物理地址空间！
    ```
  - 构筑起一套完全由 ACE 驱动掌控的 512GB AMD-Vi 硬件暗影页表体系。

---

### 函数 60：`sub_14001BF28` & `sub_14001C38C`
* **地址**：`sub_14001BF28` (241 B), `sub_14001C38C` (206 B)
* **作用**：**AMD 设备表条目清洗与空闲 Domain ID（1~255）动态分配引擎**。
* **逻辑**：
  - `sub_14001C38C`：扫描硬件设备表中所有已被使用的 Domain ID，在位图 `byte_140148770` 中标记占用。遍历寻找首个未使用的 ID 并赋值给 `dword_140148760`。
  - `sub_14001BF28`：遍历以 32 字节为步长的 AMD 设备条目，对目标 Domain ID 的设备执行页表掩码清洗（`&= 0xFFF0000000000FFFuLL`），随后触发刷新。

---

### 函数 61：`sub_14001C01C`
* **地址**：`0x14001C01C`，代码体积达 **`879` 字节 (`0x36F`)**
* **作用**：**AMD-Vi 控制寄存器（MMIO 0x0018）深度审计、硬件物理隔离与 4206 号核心违规遥测**。
* **硬件寄存器与结构体**：
  - `*(_QWORD *)(a1 + 8)`：AMD IOMMU MMIO Base 虚拟映射基址。
  - 偏移 `+24`（**MMIO 0x0018**）：**AMD IOMMU Control Register**。
    - 检查并强制激活：Bit 0 (`IommuEn`) 与 Bit 3 (`EventLogEn`)。
* **遍历与硬件隔离**：
  - 步进 32 字节遍历整机 PCIe 设备表（AMD DTE 结构）：
  - 若在系统中发现未登记的幽灵设备或未初始化的外设：
    - 调用 `HalGetBusDataByOffset` 读取其 Vendor ID 与 Device ID。
    - **发射 4206 号核心硬件违规遥测事件**：
      ```c
      sub_14001161C(0, 4206, BusDevFunc, 0, 0, nullptr, nullptr, nullptr, nullptr, VendorId, DeviceId, ...);
      ```
    - **物理隔离**：直接将该设备条目的页表物理基址改写为暗影页表，打上 `0x800` 属性，彻底切断该硬件在总线上的任何 DMA 访问能力！

---

### 函数 62：`sub_14001C45C`
* **地址**：`0x14001C45C`，大小 **`319` 字节 (`0x13F`)**
* **作用**：**AMD IOMMU Event Log 环形缓冲区硬件直读解析器与 Fault 捕获引擎**。
* **硬件寄存器定义**：
  - 偏移 `8208` (`0x2010`): **Event Log Head Pointer Register**
  - 偏移 `8216` (`0x2018`): **Event Log Tail Pointer Register**
  - 偏移 `8224` (`0x2020`): **IOMMU Status Register**
* **硬件级 Fault 捕获流程**：
  - 通过比对 Head 与 Tail 寄存器指针：`v11 = (Tail >> 4) - (Head >> 4)`，计算未读硬件事件数。
  - 步进 16 字节提取 Event Log 条目：
    - 若事件类型标头为 `0x20000000`（`ILLEGAL_DEV_TABLE_ENTRY` 或 `PAGE_FAULT`）：
    - 立即调用 **`sub_14001B898`** 将触发 Fault 的物理内存地址记录进 5000 槽位暗影表，并标记现场！
  - 硬件确认与中断清除：写回 Head 指针，向 Status Register 写入 `2` 清除硬件中断状态。

---

### 函数 63：`BroadcastFunction` & `sub_14001C640`
* **地址**：`BroadcastFunction` (`0x14001C59C`, 52 B), `sub_14001C640` (260 B)
* **作用**：**`KeIpiGenericCall` 跨核心 IPI 广播硬件寄存器同步与总线无锁原子栅障**。
* **多核同步机制**：
  - 在修改 IOMMU 硬件寄存器时，为了防止多核乱序或并发 DMA 竞态：
  - 调用 `KeIpiGenericCall(BroadcastFunction, (ULONG_PTR)Context)` 发送处理器间中断（IPI）。
  - **Core 0（主核）**：负责执行 `sub_14001CAEC` 写入硬件 Command Buffer。
  - **其余从核**：原子累加 `_InterlockedIncrement((volatile signed __int32 *)(Argument + 44))` 并进入 `_mm_pause()` 挂起。
  - 确保全系统在极速硬件更新期间处于严格的多核时间冻结状态。

---

### 函数 64：`sub_14001C804` & `sub_14001CAEC`
* **地址**：`sub_14001C804` (512 B), `sub_14001CAEC` (338 B)
* **作用**：**AMD 芯片组 81 字节槽位映射、CR8 提升至 0xF 与 Command Buffer 硬件指令下发**。
* **硬件执行例程 (`sub_14001CAEC`)**：
  - **中断屏蔽**：调用 `__writecr8(0xFu)` 将当前 IRQL 强行拉满到 `0xF`（HIGH_LEVEL），屏蔽除 NMI 外一切中断。
  - 提取硬件 Command Buffer Tail 寄存器（偏移 `0x2008`）。
  - 写入 16 字节硬件命令包（如 `INVALIDATE_IOMMU_PAGES`），更新硬件 Tail 指针。
  - 自旋轮询硬件 Head 寄存器（偏移 `0x2000`），直到硬件处理完毕（`Head == Tail`）。
  - 恢复 IRQL：`__writecr8(CurrentIrql)`。

---

### 函数 65：`sub_14001CC40` ~ `sub_14001CDBC`
* **地址与大小**：
  - `sub_14001CC40` (219 B): AMD DTE 设备表全量枚举与外设活跃位图扫描
  - `sub_14001CD1C` (70 B): 100 项设备 ID 缓存表维护
  - `sub_14001CD64` (85 B): 4KB NonPagedPool 初始化
  - `sub_14001CDBC` (**550 B**): **Intel VT-d Root Table / Context Table / Second-Level Paging (SLP) 二级暗影页表接管**。
* **Intel VT-d 接管架构 (`sub_14001CDBC`)**：
  - 构建 Intel VT-d 硬件规范下的 Root Table（256 项）与 Context Table（256 项）。
  - 建立二级页表（SLP Directory Pointer Table & Page Directory Table）：
    - 针对 2MB 大页打上 `0x80uLL`（Page Size = 2MB）与 `Present | Read/Write (0x3)` 属性。
    - 循环映射 512 个连续 2MB 页面，覆盖全部芯片组物理地址。
    - 最终调用 `sub_14001E524` 将暗影页表基址灌入 Intel VT-d DMAR 硬件寄存器！

---

### 函数 66：`sub_14001CFE4` & `sub_14001E0C0`
* **地址与大小**：
  - `sub_14001CFE4` (258 B): **Intel VT-d SLP 二级页表 PTE 权限动态篡改与页表硬件失效**。
  - `sub_14001E0C0` (206 B): 物理页表读写权限恢复例程。
* **PTE 篡改逻辑 (`sub_14001CFE4`)**：
  - 传入虚拟地址 `a2`，解析 Intel SLP 目录级联偏移：
    ```c
    v8 = ((a2 >> 21) & 0x1FF) + ((((a2 >> 30) & 0x1FF) + 4) << 9);
    ```
  - 映射物理页表条目：`MmMapIoSpace(*(_QWORD *)v9 & 0xFFFFFFFFFF000LL, 0x1000u, MmNonCached)`。
  - 提取目标 PTE：`v13 = &v11[8 * ((a2 >> 12) & 0x1FF)]`。
  - 清除 Present 标志位：`*v13 = *v13 & 0xFFFFFFFFFFFFFFFEuLL`（使页表在硬件上变为 Invalid）。
  - 核心操作：调用 **`sub_14001E524(v13, 8)`** 对修改后的 PTE 执行 `_mm_clflush` 缓存冲刷，保证 DMAR 芯片组立即感知！

---

### 函数 67：`sub_14001D214` & `sub_14001DB28`
* **地址**：`sub_14001D214` (192 B), `sub_14001DB28` (234 B)
* **作用**：**Intel DMAR 故障状态寄存器（FSR）与故障记录寄存器（FRCD）直读解析**。
* **硬件寄存器与结构**：
  - 偏移 `+52`（`0x34`）：**Fault Status Register (FSR)**。读取状态字，若 Bit 1 (`PPF`, Primary Pending Fault) 置位，说明发生了硬件级违规拦截。
  - 偏移 `+8`：**Fault Recording Register (FRCD)**（每个记录 16 字节，包含引发 Fault 的 PCIe BDF 坐标与访问物理地址）。
  - `sub_14001DB28`：提取异常现场 16 字节硬件快照，调用 `sub_14001B964(&v13, a2)` 记入 5000 槽位暗影监控表，并向 FSR 写回标志清除硬件中断。

---

### 函数 68：`sub_14001D2D4`
* **地址**：`0x14001D2D4`，大小 `392` 字节 (`0x188`)
* **作用**：**Intel VT-d Context Table 上下文表动态清洗与非法设备 DMA 剥离**。
* **机制**：
  - 映射 Root Table 指向的 Context Table 物理页面（`0x1000`）。
  - 扫描 512 个设备条目：
    - 比对条目中的 Domain ID 是否匹配当前保护上下文 `dword_140158784`；
    - 匹配后将上下文条目写为无效状态（`*(_OWORD *)v13 = v15`），随后调用 `sub_14001DC44` 与 `sub_14001DD7C` 向芯片组硬件下发 Context/IOTLB 失效指令，彻底切断设备的 DMA 访问通道。

---

### 函数 69：`sub_14001D45C`
* **地址**：`0x14001D45C`，代码体积达 **`1,677` 字节 (`0x68D`)**
* **作用**：**Intel 架构整机 PCIe 设备拓扑全景扫描、BAR 物理空间审计与 4206 号核心遥测**。
* **巨型审计逻辑**：
  - 映射 Intel DMAR 硬件寄存器（`MmMapIoSpace` 映射 4KB）。
  - 步进扫描系统中的每一个 PCIe 总线物理槽位（Bus: `v31`, Dev: `v34`, Func: `v35`）：
    - 核验设备在 VT-d Context Table 中的映射条目与权限；
    - 深度检查设备的 BAR 物理空间是否处于非法未声明状态；
    - 若发现未受控的 DMA 硬件或异常总线事务：
      - 直接调用 `HalGetBusDataByOffset(PCIConfiguration, Bus, Dev & 0x1F | (32 * (Func & 7)), &Buffer, 0, 4u)` 直读 Vendor ID 与 Device ID。
      - **发射核心 4206 号硬件遥测事件**：
        ```c
        sub_14001161C(0, 4206, Bus, Dev, Func, nullptr, nullptr, nullptr, nullptr, VendorId, DeviceId, ...);
        ```
      - 使用 `xmmword_140158798` 强行篡改该设备的 Context Table 物理映射，阻断后续所有数据包。

---

### 函数 70：`sub_14001DC14` & `sub_14001DC44`
* **地址**：`sub_14001DC14` (47 B), `sub_14001DC44` (312 B)
* **作用**：**多核 IPI 广播驱动下的 Intel Context Invalidation 上下文失效引擎**。
* **命令封装**：
  - 构造 Context Invalidation 描述符：
    - `0x11`：Global Invalidation（全局整机上下文失效）
    - `0x21`：Domain-Selective Invalidation（指定 Domain 域上下文失效）
    - `0x31`：Device-Selective Invalidation（指定 PCIe BDF 设备上下文失效）
  - 若 `byte_1401483CB != 0`，调用 `KeIpiGenericCall(sub_14001DC14, (ULONG_PTR)Context)` 发起跨核心中断广播，由 Core 0 执行硬件寄存器写操作，其余核心挂起等待。

---

### 函数 71：`sub_14001DD7C` & `sub_14001E4CC`
* **地址**：`sub_14001DD7C` (260 B), `sub_14001E4CC` (88 B)
* **作用**：**Intel IOTLB 页表缓存失效与 Write-Buffer Flushing 硬件冲刷**。
* **机制**：
  - `sub_14001DD7C`：构造 IOTLB 失效描述符（`0x12` 全局失效、`0x22` Domain 域失效、`0x32` 物理页粒度失效）。
  - `sub_14001E4CC`：检查 DMAR 扩展能力寄存器（ECAP_REG）Bit 4（RWBF: Required Write-Buffer Flushing）。若需要写缓冲冲刷，向全局控制寄存器（GCMD_REG）写入 `0x8000000`（Bit 27: WBF），并自旋等待全局状态寄存器（GSTS_REG）确认完成。

---

### 函数 72：`sub_14001DE80`
* **地址**：`0x14001DE80`，大小 **`449` 字节 (`0x1C1`)**
* **作用**：**主板 BIOS/UEFI ACPI DMAR 固件表全量遍历与 DRHD 硬件单元提取**。
* **结构解析**：
  - 遍历 DMAR 表中所有的 DRHD（DMA Remapping Hardware Unit Definition）子结构。
  - 提取每个硬件单元的 64 位物理 MMIO 基址（`v13[1]`）并调用 `MmMapIoSpace(..., 0x1000u, MmNonCached)` 建立直读映射。
  - 提取关键硬件能力寄存器：
    - `+0`：Capability Register (CAP_REG)
    - `+8`：Extended Capability Register (ECAP_REG)
    - `+24`：Global Command Register (GCMD_REG)
    - `+28`：Global Status Register (GSTS_REG)
  - 以 **100 字节** 结构体步长将整机全部 DMAR 单元登记在内核数组中。

---

### 函数 73：`sub_14001E26C` & `sub_14001E524`
* **地址**：`sub_14001E26C` (**`606` 字节**), `sub_14001E524` (109 字节)
* **作用**：**Intel Invalidation Queue (QI) 队列硬件下发与 `_mm_clflush` 缓存行精准冲刷**。
* **硬件队列操作 (`sub_14001E26C`)**：
  - 偏移 `+144` (`0x90`): Invalidation Queue Address Register (IQA_REG)
  - 偏移 `+136` (`0x88`): Invalidation Queue Tail Register (IQT_REG)
  - 偏移 `+128` (`0x80`): Invalidation Queue Head Register (IQH_REG)
  - 拷贝 16 字节或 32 字节命令描述符，更新 Tail 寄存器并自旋等待硬件完成。
* **硬件缓存冲刷 (`sub_14001E524`)**：
  - 执行 `cpuid(1)` 确认 CPU 支持 `CLFLUSH`（`_RDX & 0x80000`）。
  - 提取 CPU 缓存行大小（64 字节）。
  - 原生调用 **`_mm_clflush(i)`** 指令逐行冲刷被修改的页表与描述符物理内存，确保芯片组硬件和总线外设绝对同步，无视任何 CPU 缓存驻留！

---

### 函数 74：`sub_14001E7CC` & `sub_14001E8A4`
* **地址与大小**：
  - `sub_14001E7CC` (216 B): **PE 导出表动态符号检索器（RtlImageDirectoryEntryToData）**。
  - `sub_14001E8A4` (220 B): **`win32kbase.sys` 未导出图形核心函数取反解密与定位**。
* **解密与定位机制 (`sub_14001E8A4`)**：
  - 动态引用 `L"win32kbase.sys"` 图形内核驱动模块基址（`qword_140158988`）。
  - 双重取反解密未导出关键函数名：
    - 密文 1（17 字节）：`v7[0] = ~-1097228648`，逐字节 `~` 按位取反还原。
    - 密文 2（18 字节）：`v9[0] = ~-1097228648`，逐字节 `~` 按位取反还原。
  - 调用 `sub_14001E7CC` 解析目标驱动导出表，精准获取未导出的图形服务例程地址。

---

### 函数 75：`sub_14001E980`
* **地址**：`0x14001E980`，大小 `203` 字节 (`0xCB`)
* **作用**：**`win32kbase.sys` 关键物理页面暗影 Trap 注册与跨进程 GUI 挂靠**。
* **防护流程**：
  - 调用 `sub_140026954` 定位受保护的 GUI / 游戏主进程。
  - 调用 `sub_140027B24(Irp, &ApcState)` 跨进程挂入目标空间。
  - 提取 `win32kbase.sys` 关键函数所在的 4KB 物理页基址（`v3 & 0xFFFFFFFFFFFFF000`）。
  - **核心操作**：调用 **`sub_14001B2B4`** 将其注册进 **5,000 槽位暗影 MMIO 页表**，大小为 `0x1000`（4KB）。
  - 退栈：`KeUnstackDetachProcess(&ApcState)`。
  - **对抗意义**：任何通过 DMA 物理内存注入、改写桌面窗口管理器（DWM）或在 `win32kbase.sys` 下挂钩改写输入流的行为，将直接触发 ACE 的硬件暗影页表拦截。

---

### 函数 76：`sub_14001EA4C`
* **地址**：`0x14001EA4C`，大小 `38` 字节
* **作用**：**TVM 虚拟机执行核通用寄存器保护与环境切换跳板（TVM Entry Trampoline）**。
* **执行逻辑**：
  - 调用 `__readeflags()` 提取当前 EFLAGS 标志位并保存至现场快照。
  - 将所有通用寄存器（RAX, RBX, RCX, RDX, RSI, RDI, R8~R15）与参数压入 78 槽位栈帧结构体。
  - 调用 `sub_145C2AA87` 直切进入 2.16MB 的 TVM 虚拟机 Bytecode 解释器，执行高危未公开策略。

---

### 函数 77：`sub_14001EA74`, `sub_14001F3E8` & `sub_14001F65C`
* **地址与大小**：
  - `sub_14001EA74`：代码体积达 **`2,417` 字节 (`0x971`)**！
  - `sub_14001F3E8` (627 B), `sub_14001F65C` (615 B)
* **作用**：**`\Driver\pci` 底层根总线驱动对象全量深度审计与跨版本适配（PCI Bus Driver Auditor）**。
* **巨型审计逻辑 (`sub_14001EA74`)**：
  - 严格校验传入参数长度：必须为 88 字节（`*(_DWORD *)a1 == 88`）。
  - 读取 Windows 内核版本号：`sub_140029BA0()`，若版本大于等于 `0x4563`（Windows 10 RS5 / Build 17763 及更高版本 Win11）：
    - 锁定内核根 PCI 驱动：`L"\\Driver\\pci"`。
    - 调用 `sub_140026A24` 深度穿透 `\Driver\pci` 的驱动对象扩展、分发函数表（IRP_MJ_PNP / IRP_MJ_INTERNAL_DEVICE_CONTROL）以及挂接的 PDO/FDO 设备树。
    - 比对设备描述符是否与物理配置空间完全一致，若发现虚假挂载或绕过 PCI 总线的幽灵设备，直接返回硬件异常码 `64`。

---

### 函数 78：`sub_14001F920` ~ `sub_14001FB30`
* **地址与大小**：
  - `sub_14001F920` (137 B): 安全 Unicode 字符串格式化拷贝器
  - `sub_14001F9BC` (372 B): 动态驱动名称字符串切分与 30 项白名单维护
  - `sub_14001FB30` (94 B): 驱动白名单安全释放与内存回收
* **白名单结构**：
  - 维护最多 30 项（`0x1E`）的驱动名称全局数组 `unk_1401589B0`。
  - 解析外部传入的配置串，按指定字符切分并动态分配 NonPagedPool 存储，调用 `RtlInitUnicodeString` 初始化。

---

### 函数 79：`sub_14001FC5C` & `sub_14001FE20`
* **地址**：`sub_14001FC5C` (211 B), `sub_14001FE20` (221 B)
* **作用**：**4360 号核心内核安全事件（子操作码 4102 与 4101）遥测总线**。
* **逻辑**：
  - `sub_14001FC5C` (4102)：校验 48 字节特征缓冲区（`sub_140046E38`），若环境受控（`byte_140158B92 != 0`）返回状态码 22，若被调试或篡改返回 253，随后触发：
    ```c
    sub_14001161C(nullptr, 4360, 4102, Status, Result, ...);
    ```
  - `sub_14001FE20` (4101)：校验 16 字节硬件上下文（`sub_1400470F4`），成功返回基数偏移 `v5 + 2200`，异常返回 253，发射 **4360:4101** 遥测事件。

---

### 函数 80：`sub_14001FF00` & `sub_140020098`
* **地址**：`sub_14001FF00` (201 B), `sub_140020098` (185 B)
* **作用**：**4360 号核心内核安全事件（子操作码 4103 与 4100）驱动白名单与设备安全状态遥测**。
* **遥测架构**：
  - `sub_14001FF00` (4103)：调用 `sub_14004BF1C` 进行驱动白名单与签名链核验，发射 **4360:4103** 遥测事件。
  - `sub_140020098` (4100)：调用 `sub_14004C084` 全量核验整机受控驱动设备对象的安全属性，发射 **4360:4100** 遥测事件。

---

### 函数 81：`sub_140024510` —— PCIe 设备 VEN_ / DEV_ 硬件标识符动态提取器
* **地址**：`0x140024510`，大小 `0x17D` (381 字节)
* **形参定义**：`__int64 __fastcall sub_140024510(__int64 DeviceContext, ULONG *pVenId, ULONG *pDevId)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140024510(__int64 DeviceContext, ULONG *pVenId, ULONG *pDevId)
  {
    unsigned int Status = STATUS_UNSUCCESSFUL;
    if ( !DeviceContext ) return Status;

    const wchar_t *HwIdStr = *(const wchar_t **)(DeviceContext + 8);
    if ( !HwIdStr || !pVenId || !pDevId ) return Status;

    ULONG VenVal = 0, DevVal = 0;
    UNICODE_STRING uStr;
    wchar_t Buffer[16];

    // 1. 搜寻 "VEN_" 子串提取厂商 ID (Vendor ID)
    wchar_t *pVen = wcsstr(HwIdStr, L"VEN_");
    if ( pVen )
    {
      wchar_t *pDev = wcsstr(pVen, L"&DEV_");
      if ( pDev )
      {
        size_t Len = pDev - pVen - 4;
        if ( Len > 9 ) Len = 9;
        wcsncpy(Buffer, pVen + 4, Len);
        Buffer[Len] = 0;
        RtlInitUnicodeString(&uStr, Buffer);
        RtlUnicodeStringToInteger(&uStr, 16u, &VenVal);
      }
    }

    // 2. 搜寻 "DEV_" 子串提取设备 ID (Device ID)
    wchar_t *pDevOnly = wcsstr(HwIdStr, L"DEV_");
    if ( pDevOnly )
    {
      wchar_t *pSub = wcsstr(pDevOnly, L"&SUB");
      if ( pSub )
      {
        size_t Len = pSub - pDevOnly - 4;
        if ( Len > 9 ) Len = 9;
        wcsncpy(Buffer, pDevOnly + 4, Len);
        Buffer[Len] = 0;
        RtlInitUnicodeString(&uStr, Buffer);
        RtlUnicodeStringToInteger(&uStr, 16u, &DevVal);
      }
    }

    if ( VenVal != 0 && DevVal != 0 )
    {
      *pVenId = VenVal;
      *pDevId = DevVal;
      Status = STATUS_SUCCESS;
    }
    return Status;
  }
  ```
* **对抗与安全分析**：
  - 该函数是 ACE 审核系统所有已加载 PCIe 物理/虚拟端点硬件 ID 的核心解析组件（被 `sub_14001EA74` 等 12 个审查例程频繁调用）。
  - 驱动不仅通过底层配置空间直接探测 BDF，还会比对 Windows PnP 子系统为该设备建立的设备树字符串（格式如 `PCI\VEN_xxxx&DEV_xxxx&SUBSYS_...`）。
  - **FPGA 固件伪装要求**：DMA 固件在设置配置空间的 Vendor ID / Device ID 时，必须与 INF 驱动文件中声明的 Hardware ID 完全一致，杜绝大小写或十六进制格式解析失败导致的异常拦截。

### 函数 11：`sub_140031210` / `sub_14003122E` / `sub_14003124A` —— VMware 虚拟机 Magic Port 0x5658 I/O 端口后门探针
* **地址**：`0x140031210` (30 B), `0x14003122E` (28 B), `0x14003124A` (21 B)
* **反编译伪代码**：
  ```c
  unsigned __int32 sub_14003122E()
  {
    // 直读 x86/x64 硬件 I/O 端口 0x5658 ('VX', VMware I/O Backdoor Port)
    return __indword(0x5658u);
  }
  ```
* **对抗意义**：通过经典 VMware Magic Port（端口 `0x5658`）发起 I/O 探查，瞬间感知当前是否在 VMware Workstation/ESXi 虚拟化环境下运行，为上层反作弊引擎提供沙箱识别判据。

---

### 函数 12：`sub_14003125F` —— PCI 总线配置空间 0xCF8 硬件 I/O 端口直写
* **地址**：`0x14003125F`，大小 `24` 字节 (`0x18`)
* **形参定义**：`void __fastcall sub_14003125F(__int16 BdfOffset, char RegisterOffset)`
* **反编译伪代码**：
  ```c
  void __fastcall sub_14003125F(__int16 BdfOffset, char RegisterOffset)
  {
    unsigned int ConfigAddress = 0x80000000u | ((unsigned int)BdfOffset << 8) | (RegisterOffset & 0xFC);
    // 直接向硬件 I/O 端口 0xCF8 (PCI CONFIG_ADDRESS) 发起写入
    __outdword(0xCF8u, ConfigAddress);
  }
  ```
* **对抗意义**：硬件级 PCI 配置空间原始访问！在没有任何系统驱动介入的情况下，直接操作主板南桥 I/O 端口 `0xCF8`，实现对所有 PCI 设备配置空间的无感知硬件直读直写，彻底穿透操作系统与任何驱动层 Hook。

---

### 函数 13：`sub_14004AAFC` —— MmMapIoSpace 物理 MMIO 空间动态安全映射器
* **地址**：`0x14004AAFC`，大小 `96` 字节 (`0x60`)
* **形参**：`_QWORD *OutMappedContext`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14004AAFC(_QWORD *OutMappedContext)
  {
    if ( byte_1459679B0 == 0 )
      return STATUS_UNSUCCESSFUL;

    OutMappedContext[0] = 0;
    OutMappedContext[1] = 0;
    
    // 使用非缓存模式 (MmNonCached) 直接将主板南桥 MMIO 物理地址映射入内核
    PVOID MappedVa = MmMapIoSpace(PhysicalAddress, NumberOfBytes, MmNonCached);
    if ( !MappedVa )
      return STATUS_INSUFFICIENT_RESOURCES;

    OutMappedContext[0] = MappedVa;
    OutMappedContext[1] = NumberOfBytes;
    return STATUS_SUCCESS;
  }
  ```
* **对抗意义**：将主板芯片组物理 MMIO 基址（包含 PCIe ECAM 与各设备的 BAR 空间）直接映射为驱动私有内核虚拟地址，使后续总线读写完全避开操作系统 PCI 总线过滤驱动。

---

### 函数 14：`sub_14004AB5C` —— PCIe MMIO 32 位寄存器原子直读引擎
* **地址**：`0x14004AB5C`，大小 `162` 字节 (`0xA2`)
* **形参**：`__int64 *MappedContext, __int64 RegisterOffset`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14004AB5C(__int64 *MappedContext, __int64 RegisterOffset)
  {
    __int64 MmioBase = *MappedContext;
    unsigned int PageOffset = (unsigned int)RegisterOffset - (RegisterOffset & 0xFFF00000);
    unsigned __int64 SegmentIndex = (RegisterOffset & 0xFFFFFFFFFFF00000uLL) >> 16;

    // 定位目标 MMIO 槽位并原子直读 32 位硬件寄存器
    unsigned __int64 RegAddress = MmioBase + SegmentIndex + PageOffset;
    return *(volatile unsigned int *)RegAddress;
  }
  ```
* **对抗意义**：微秒级原子读取 PCIe 设备的真实物理硬件寄存器，无视应用层和内核层的软件伪装。

---

### 函数 15：`sub_14004AC00` —— PCIe MMIO 32 位寄存器原子直写引擎
* **地址**：`0x14004AC00`，大小 `180` 字节 (`0xB4`)
* **形参**：`__int64 *MappedContext, __int64 RegisterOffset, unsigned int Value`
* **反编译伪代码**：
  ```c
  char __fastcall sub_14004AC00(__int64 *MappedContext, __int64 RegisterOffset, unsigned int Value)
  {
    __int64 MmioBase = *MappedContext;
    unsigned int PageOffset = (unsigned int)RegisterOffset - (RegisterOffset & 0xFFF00000);
    unsigned __int64 SegmentIndex = (RegisterOffset & 0xFFFFFFFFFFF00000uLL) >> 16;

    unsigned __int64 RegAddress = MmioBase + SegmentIndex + PageOffset;
    *(volatile unsigned int *)RegAddress = Value;
    return 1;
  }
  ```
* **对抗意义**：通过原子 MMIO 写操作直接向硬件设备下发控制指令，或直接修改设备 Command 寄存器（如清零 Bus Master Enable 位将异常 DMA 设备下线）。

---

### 函数 16：`sub_14004ACB4` —— PCIe 设备配置空间特征匹配器
* **地址**：`0x14004ACB4`，大小 `69` 字节 (`0x45`)
* **形参**：`unsigned __int64 Entry, unsigned int Count, _QWORD *TargetArray`
* **反编译伪代码**：
  ```c
  char __fastcall sub_14004ACB4(unsigned __int64 Entry, unsigned int Count, _QWORD *TargetArray)
  {
    if ( (Entry & 1) == 0 ) return 0;
    unsigned __int64 BdfKey = (Entry >> 8) & 0x3FFFFFFFFFFFLL;
    
    for ( unsigned int i = 0; i < Count; ++i )
    {
      if ( TargetArray[i] == BdfKey )
        return 1; // 命中目标受监控 BDF
    }
    return 0;
  }
  ```
* **对抗意义**：在多核心拓扑中快速筛查当前 PCIe 事务是否来自受监控的硬件端点。

---

### 函数 17：`sub_14004ACFC` —— PCIe 64 位 BAR (Base Address Register) 动态解算与物理空间合法性审查
* **地址**：`0x14004ACFC`，大小 `150` 字节 (`0x96`)
* **形参**：`__int64 *MappedContext, __int64 DeviceConfigBase, unsigned __int64 MaxValidLimit, unsigned __int64 *OutPhysicalBar`
* **反编译伪代码**：
  ```c
  bool __fastcall sub_14004ACFC(__int64 *MappedContext, __int64 DeviceConfigBase, unsigned __int64 MaxValidLimit, unsigned __int64 *OutPhysicalBar)
  {
    // 读取 BAR 低 32 位 (偏移 0x200 / 512) 与高 32 位 (偏移 0x204 / 516)
    int LowBar = sub_14004AB5C(MappedContext, DeviceConfigBase + 512);
    int HighBar = sub_14004AB5C(MappedContext, DeviceConfigBase + 516);

    int BarType = LowBar & 3; // 0 = 内存映射 BAR
    unsigned __int64 PhysicalAddress = (LowBar & 0xFFFFF000) | ((unsigned __int64)(unsigned int)HighBar << 32);

    if ( OutPhysicalBar )
      *OutPhysicalBar = PhysicalAddress;

    // 校验 BAR 物理基址合法性 (非零且未超出系统物理内存上限)
    return BarType == 0 && PhysicalAddress != 0 && (MaxValidLimit == 0 || PhysicalAddress < MaxValidLimit);
  }
  ```
* **对抗意义**：**全内核最致命的 DMA 硬件特征提取点**！DMA 板卡固件若在配置空间中伪造了虚假的 BAR（例如指向已被操作系统占用的物理内存地址，或未正确配置 64 位高地址段），在此处会被直接判定为非法设备并截获。

---

### 函数 18：`sub_14004AD94` —— PCIe 设备 11012 字节拓扑树深度遍历总线
* **地址**：`0x14004AD94`，大小 `147` 字节 (`0x93`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14004AD94(__int64 *MappedContext, unsigned __int64 DeviceId, unsigned __int64 *OutInfo, _DWORD *OutStatus)
  {
    if ( (unsigned __int64)MappedContext[1] < 0x2BB0 ) // 必须大于 11012 字节
      return 0;

    // 沿 11012 字节设备树拓扑循环遍历每个已发现的 PCIe 节点
    // 递归校验每个子设备的配置空间与电源状态 (D0/D3)
    return TraversePcieTopology(MappedContext, DeviceId, OutInfo, OutStatus);
  }
  ```
* **对抗意义**：遍历主板上所有 PCIe 插槽构建的完整拓扑树，防范通过 PCIe 拆分卡（Bifurcation Riser Card）或雷电（Thunderbolt / USB4）转接隐匿的 DMA 板卡。

---

### 函数 19：`sub_14004AE28` —— PCIe 扩展功能 Capability 链表深度遍历 (AER / MSI-X / PCIe Express 校验)
* **地址**：`0x14004AE28`，大小 `273` 字节 (`0x111`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14004AE28(__int64 *MappedContext, unsigned __int64 DeviceOffset, unsigned __int64 *OutCap, _DWORD *OutCapFlags)
  {
    // 从配置空间偏移 0x34 读取 Capabilities Pointer (CapPtr)
    // 循环遍历单向链表:
    // Cap ID 0x01: PCI Power Management
    // Cap ID 0x05: MSI
    // Cap ID 0x10: PCI Express Capability (校验 Max Link Speed / Width)
    // Cap ID 0x11: MSI-X
    // 扩展配置空间 (0x100 之后): AER (Advanced Error Reporting)
    return ParsePcieCapabilities(MappedContext, DeviceOffset, OutCap, OutCapFlags);
  }
  ```
* **对抗意义**：许多开源 DMA 固件（如简易 PCILeech 固件）为了节省逻辑单元，往往省略了完整的 PCIe Capability 链表或未实现 PCIe Express 规范（缺少 Cap 0x10 / 0x11 或链表指向死循环）。ACE 遍历整条 Capability 链表，一旦发现缺少合法的 PCIe 结构体或链表偏移越界，立即标记为伪造固件。

---

## 3. 防御对抗与固件伪装（Firmware Spoofing）指南

1. **彻底规避双表比对（sub_140005744 - Ghost Device Detection）**：
   - **核心致命点**：很多外挂开发者仅将 FPGA 刷写为网卡（如 Intel I210）或声卡固件，但在目标机系统中却处于“黄色叹号”无驱动状态，或没有对应的驱动对象挂载在 `\Driver\pci` 设备树中。
   - **完美解法**：必须让 Windows 正常为其加载官方签名驱动（例如让 Intel 官方 `e1r68x64.sys` 正常挂载在设备对象上，生成完整的 DeviceObjectExtension），确保其出现在 `\Driver\pci` 的设备栈链表中，彻底避开 `sub_140005744` 的缺失报警。
2. **规避 TLP 时钟延迟（sub_1400066A4）**：
   - 固件在响应针对配置空间 `0xA0` / `0xA8` 偏移的写入事务（CfgWr）时，响应包（Completion Cpl/CplD）必须在几个周期内从 FPGA 内部寄存器直接返回，不得经过慢速总线或外部微控制器交互。
3. **规避特征码暗影 MMIO（sub_140024B6C）与 ACPI MCFG 直读（sub_1400185D0）**：
   - ACE 不仅 Hook-free 地调用内部例程，还通过 `sub_1400185D0` 直读主板 BIOS ACPI 表中的 `'MCFG'` 物理基址，结合 `MmMapIoSpace` 直接对芯片组物理 MMIO 地址进行直读直写，**任何基于系统驱动层或 HAL 钩子的伪装在物理 MMIO 直读面前全部穿透失效**。
4. **规避 5000 槽位暗影 MMIO 页表陷阱（sub_14001B2B4 ~ 1B964）**：
   - ACE 在内核分配了 312.5KB、共 5000 个槽位的暗影 MMIO 监控表，并构建了 2MB 大页暗影缓冲区（`sub_140019974`）。当 DMA 硬件试图读写被标记的敏感物理页面时，将触发硬件 Trap 并由 `sub_14001B898` 截获 16 字节上下文、累加命中计数并直接上报 4207 号遥测。
   - **对抗策略**：DMA 板卡严禁扫描未知物理内存段；在 LeechCore/PCILeech 中必须配合 VMM 内存白名单，仅访问经过合法认证的连续物理页，严禁触碰未经映射的高危物理空洞与暗影 MMIO 拦截页。
5. **规避 CPUID 架构指纹与国产海光识别（sub_14001A498）**：
   - ACE 执行原生 CPUID 指令枚举 `0x80000002` ~ `0x80000004` 提取 48 字节 Brand String，并硬编码检测海光 `"hygon"` 处理器（分配独立平台码 4）。在虚拟机开发环境或硬件透传环境中，必须确保虚拟化环境完整透传物理 CPU 的真实 Brand String，不得遗留 `"QEMU"`, `"KVM"`, `"VMware"` 等虚拟化特征串。
6. **规避 `i8042prt.sys` 键盘中断 Hook 协同审查（sub_14001A7FC ~ 1AD6C）**：
   - ACE 在内核原子篡改了 PS/2 键盘驱动 `i8042prt.sys` 的中断分发服务例程，每次发生按键事件时均触发 `sub_14001AD6C` 协同检查当前是否存在并发异常 DMA 事务。若使用硬件盒子通过 PS/2 或模拟键盘驱动注入键鼠数据，会在此处被关联审计。
7. **规避 AMD-Vi / Intel VT-d 双架构暗影页表与硬件 Fault 拦截（sub_14001BB78 ~ 1CDBC, sub_14001CFE4 ~ 1E524）**：
   - ACE 分别构建了 2.1MB 的 AMD-Vi 512GB 暗影页表（`sub_14001BDE4`）与 Intel VT-d SLP 二级暗影页表（`sub_14001CDBC`），并深入硬件寄存器（AMD 0x0018 / 0x2010 / 0x2020，Intel FSR 0x34 / FRCD 0x08 / IQ 0x90）监听硬件 Fault，并通过 `_mm_clflush`（`sub_14001E524`）强制冲刷缓存。一旦外挂 DMA 板卡发起越界物理读写，触发硬件 Fault，将立即被截获，并由 `sub_14001C01C` / `sub_14001D45C` 直接改写设备 DTE / Context 表物理基址将其物理锁死断网，同时发射 4206 号核心遥测。
   - **对抗策略**：在开启 IOMMU 的系统上，必须在 BIOS 中正确配置 DMA 板卡的直通或排除列表（Pass-Through Domain）；严禁在 Windows 运行时尝试探测未分配的物理页帧，避免在芯片组 Event Log 或 FRCD 寄存器中留下任何未决的 Page Fault 硬件中断。
8. **存储总线 `\Driver\Disk` 深度审计对抗（sub_140018B20 ~ 18EF0）**：
   - 针对通过修改存储过滤驱动或在内核伪造虚拟磁盘以注入作弊数据的行为，ACE 直接利用 `0x4D014` 控制码强读存储设备物理序列号，并结合 100 字节 PCIe 槽位数组多核校验物理 BDF 拓扑，通过 4211 / 4213 号遥测事件上报硬件违规。
9. **规避 `\Driver\pci` 2.4KB 深度审查与 4360 号遥测组（sub_14001EA74 ~ 1FF00）**：
   - ACE 使用高达 2.4KB 的大函数 `sub_14001EA74` 深入检查 Windows 10/11 的 `\Driver\pci` 内部设备树，并联动 4360 号遥测（子操作码 4100~4103）实时上报驱动白名单与设备安全状态。伪装设备必须确保在 `\Driver\pci` 栈中注册为标准合法的 PCIe 端点，切勿尝试在驱动对象层次实施未签名的过滤 Hook。


---


---


---

## 4. 全量子系统核心反作弊函数反编译聚类与合并归纳（共收录：40 个反作弊核心函数）

> **经 IDA Hex-Rays 深度反编译分析，本子系统负责反作弊攻防的核心函数已全量提取微码，并按底层机制高度合并归纳为 3~4 大核心功能簇，彻底消除同质化存根冗余：**

```
[架构合流]: PCI/PCIe 总线扫描与硬件 DMA 检测合流架构

  ├─► 【功能簇 A: 配置空间读写总线】
  │     ├─ 代表例程: sub_1400440E0 / sub_140044180
  │     └─ 核心机理: HalGetBusDataByOffset 遍历 0~255 Bus/Dev/Func 配置空间

  ├─► 【功能簇 B: PCIe Capability 遍历】
  │     ├─ 代表例程: sub_140044260 等 12 个合并
  │     └─ 核心机理: 深度递归遍历扩展 Capability 链表，比对 VendorID/DeviceID 黑名单

  ├─► 【功能簇 C: BAR 解算与 MMIO 映射】
  │     ├─ 代表例程: sub_1400445C0 等 14 个合并
  │     └─ 核心机理: MmMapIoSpace 物理映射 PCIe 硬件 BAR，直读外设固件签名

  ├─► 【功能簇 D: TLP 延迟侧信道测算】
  │     ├─ 代表例程: sub_140045100 等 10 个合并
  │     └─ 核心机理: 向可疑外设发送读取事务并测算响应周期，捕捉仿冒 DMA 硬件延迟

```

---

### 【功能簇 A: 配置空间读写总线】

* **涵盖与合并函数**：`sub_1400440E0 / sub_140044180`

* **深度对抗机理剖析**：

  HalGetBusDataByOffset 遍历 0~255 Bus/Dev/Func 配置空间。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 B: PCIe Capability 遍历】

* **涵盖与合并函数**：`sub_140044260 等 12 个合并`

* **深度对抗机理剖析**：

  深度递归遍历扩展 Capability 链表，比对 VendorID/DeviceID 黑名单。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 C: BAR 解算与 MMIO 映射】

* **涵盖与合并函数**：`sub_1400445C0 等 14 个合并`

* **深度对抗机理剖析**：

  MmMapIoSpace 物理映射 PCIe 硬件 BAR，直读外设固件签名。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 D: TLP 延迟侧信道测算】

* **涵盖与合并函数**：`sub_140045100 等 10 个合并`

* **深度对抗机理剖析**：

  向可疑外设发送读取事务并测算响应周期，捕捉仿冒 DMA 硬件延迟。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

