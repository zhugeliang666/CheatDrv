---
name: ace-kernel-symbol-resolver
description: >
  ACE (Anti-Cheat Expert) 内核未导出符号动态解析、MSR LSTAR 系统调用表提取、全版本 Syscall 映射数据库、PML4 自引用随机化绕过与全局虚表分析。
  包含 109 个核心详解与全量子系统 881 个归属函数完整拓扑索引、IA32_LSTAR 直读、KeServiceDescriptorTable / Shadow SSDT 双总线解析、HalPrivateDispatchTable 硬件调度挂接、Intel LBR 分支追踪、__writecr3 暗影切换、STAC/CLAC 硬件 SMAP 控制、PE 导出表手工解析、755 字节 x86/x64 指令长解码引擎、全版本 EPROCESS.VadRoot 平衡树自遍历、128 槽位内核受保护内存段锁定、四级页表(PML4/PDPT/PD/PT)自引用槽位动态解算、全版本物理内存直射基址动态解密、PagedPool/NonPagedPool/MmMapIoSpace 动态虚拟地址掩码探测、Theme_Buffer 命名共享节区隐秘映射、ETHREAD/EPROCESS 全局偏移解析总控、PspCreateProcessNotifyRoutine 审计、ZwQuerySystemInformation 模块枚举与 Win11 24H2 (Build 26100) 全版本适配。
---

# ACE 内核未导出符号动态模式搜索与全版本系统调用映射深度逆向分析

## 1. 架构总览与未导出指针分发拓扑

为了彻底规避杀毒软件与反作弊逆向分析的 IAT 静态审查，并稳定获取 Windows 操作系统各个内核版本中未导出的关键底层例程（如 `DirectoryTableBase (CR3)`、`MmRotatePhysicalView`、`PsGetJobLock`、`IoReleaseRemoveLockAndWaitEx`、`ci.dll` 签名验证例程、私有 PCIe MMIO 直读例程等），ACE 在 `sub_140027570` 构建了极其精密而庞大的动态特征码搜索网络（In-Memory Multi-Level Pattern Scanning），将动态解析出的函数指针汇集于全局指针数组 `qword_145959C80` ~ `qword_145959DD8`。

```
                    ┌────────────────────────────────────────────────────────┐
                    │      sub_140027570 (主调度总线: 动态未导出符号解析器)       │
                    └──────────────────────────┬─────────────────────────────┘
                                               │
         ┌───────────────────┬─────────────────┼─────────────────┬───────────────────┐
         ▼                   ▼                 ▼                 ▼                   ▼
  【进程/会话上下文】   【硬件/MSR直读】    【底层内存管理】     【系统调用数据库】    【HAL/外设扩展】
   sub_140024960       sub_140027434      sub_140024C80       sub_1400259FC        sub_140024B6C
  (win32k/csrss IRP)  (LSTAR/SSDT提取)   (CR3/KVA Shadow)    (NtOpenProcess)     (Hal私有MMIO)
   sub_1400252BC       sub_140026808      sub_1400262F4       sub_140025B80        sub_140024AB0
  (lsass 凭据句柄)    (JMP RCX Gadget)   (PML4自引用解析)    (全版本SSDT表)       (AVL树根解析)
   sub_1400261C8       sub_140024220      sub_14002535C       sub_140025C74        sub_140025108
  (进程回调数组)      (EFER/CR4虚拟化)   (MmRotatePhysical)  (NtReadVirtual)     (ci.dll代码完整性)
   sub_140025B20       sub_140027910      sub_1400255BC       sub_1400270E0        sub_140026B08
  (模块列表遍历)      (SSDT特征搜索)     (全局调度变量)      (SSDT双总线执行)    (40000h内存分配)
```

---

## 2. 核心子函数逐一详尽分析（Function-by-Function 深度逆向）

### 函数 1：`sub_14002410C` —— 内核级高精度 Tick 计数器提取（防加速器挂钩）
* **地址**：`0x14002410C`，大小 `0x53` (83 字节)
* **形参定义**：`__int64 sub_14002410C(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002410C()
  {
    // 0xFFFFF78000000320 为 KUSER_SHARED_DATA.InterruptTime.LowPart
    // KeQueryTimeIncrement 返回每个时钟中断的时间增量 (通常为 156250，即 15.625ms)
    // 乘积除以 10000 转换为毫秒绝对时间
    return KeQueryTimeIncrement() * *(_QWORD *)0xFFFFF78000000320 / 10000LL;
  }
  ```
* **对抗意义**：绕过用户态与应用层所有常见的 `timeGetTime`、`GetTickCount`、`QueryPerformanceCounter` API Hook，直接从只读内核共享页 `0xFFFFF78000000320` (`KUSER_SHARED_DATA`) 读取底层硬件中断计数值，用于精准判定游戏加速器（SpeedHack）与变速齿轮。

---

### 函数 2：`sub_140024160` —— 基于性能计数器的毫秒基准计算
* **地址**：`0x140024160`，大小 `0x33` (51 字节)
* **形参定义**：`LONGLONG sub_140024160(void)`
* **反编译伪代码**：
  ```c
  LONGLONG sub_140024160()
  {
    __int128 v1;
    LARGE_INTEGER PerformanceFrequency;

    v1 = 1000LL * *(_QWORD *)&KeQueryPerformanceCounter(&PerformanceFrequency);
    return v1 / PerformanceFrequency.QuadPart;
  }
  ```

---

### 函数 3：`sub_140024194` —— 内存指针合法性探针与零地址陷阱防御
* **地址**：`0x140024194`，大小 `0x42` (66 字节)
* **形参定义**：`char __fastcall sub_140024194(volatile void *Address, SIZE_T Length)`
* **反编译伪代码**：
  ```c
  char __fastcall sub_140024194(volatile void *Address, SIZE_T Length)
  {
    if ( (unsigned __int64)Address < 0x10000 )
      return 0; // 拒绝 Windows 64KB 保留空指针陷阱区

    ProbeForWrite(Address, Length, 1u);
    return 1;
  }
  ```

---

### 函数 4：`sub_1400241D8` —— 64 位 Fibonacci 黄金分割散列计算
* **地址**：`0x1400241D8`，大小 `0x38` (56 字节)
* **形参定义**：`__int64 __fastcall sub_1400241D8(__int64 a1, unsigned __int64 a2)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400241D8(__int64 a1, unsigned __int64 a2)
  {
    // 0x61C8864680B583EB 为 2^64 / phi (黄金分割常数)
    return (a2 >> 2) ^ ((a2 - 0x61C8864680B583EBLL) * a1);
  }
  ```

---

### 函数 5：`sub_140024220` —— 硬件虚拟化与嵌套分页启用检测
* **地址**：`0x140024220`，大小 `0x24` (36 字节)
* **反编译伪代码**：
  ```c
  bool sub_140024220()
  {
    // 读取 IA32_EFER MSR (0xC0000080)，Bit 10 为 LMA
    if ( (__readmsr(0xC0000080) & 0x400) != 0 )
    {
      // 读取 CR4 寄存器，Bit 12 为 VMXE
      if ( (__readcr4() & 0x1000) != 0 )
        return true;
    }
    return false;
  }
  ```

---

### 函数 6：`sub_140024244` —— 硬件级执行保护（DEP / NXE）检测
* **地址**：`0x140024244`，大小 `0x15` (21 字节)
* **反编译伪代码**：
  ```c
  bool sub_140024244()
  {
    return (__readmsr(0xC0000080) & 0x800) != 0; // Bit 11 为 NXE
  }
  ```

---

### 函数 7：`sub_14002429C` —— CPUID AMD 处理器架构检测
* **地址**：`0x14002429C`，大小 `0x35` (53 字节)
* **反编译伪代码**：
  ```c
  bool sub_14002429C()
  {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    // EBX == 0x68747541 ("Auth"), ECX == 0x444D4163 ("cAMD"), EDX == 0x69746E65 ("enti")
    return cpuInfo[1] == 0x68747541 && cpuInfo[2] == 0x444D4163 && cpuInfo[3] == 0x69746E65;
  }
  ```

---

### 函数 8：`sub_1400242D4` —— CPUID Hyper-V / WSL2 虚拟机探针
* **地址**：`0x1400242D4`，大小 `0xBD` (189 字节)
* **反编译伪代码**：
  ```c
  char sub_1400242D4()
  {
    char sig[16];
    int cpuInfo[4];

    if ( byte_1459595B8 != 0 )
      return byte_1459595B9;

    __cpuid(cpuInfo, 0x40000000);
    *(_DWORD *)&sig[0] = cpuInfo[1];
    *(_DWORD *)&sig[4] = cpuInfo[2];
    *(_DWORD *)&sig[8] = cpuInfo[3];
    sig[12] = 0;

    byte_1459595B8 = 1;
    byte_1459595B9 = (strcmp(sig, "Microsoft Hv") == 0);
    return byte_1459595B9;
  }
  ```

---

### 函数 9：`sub_140024394` —— CPUID Intel 处理器架构检测
* **地址**：`0x140024394`，大小 `0x35` (53 字节)
* **反编译伪代码**：
  ```c
  bool sub_140024394()
  {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    // EBX == 0x756E6547 ("Genu"), ECX == 0x6C65746E ("ntel"), EDX == 0x49656E69 ("ineI")
    return cpuInfo[1] == 0x756E6547 && cpuInfo[2] == 0x6C65746E && cpuInfo[3] == 0x49656E69;
  }
  ```

---

### 函数 10：`sub_1400243CC` —— CPUID 与 CR4 联动检测 Intel CET 硬件暗影栈状态
* **地址**：`0x1400243CC`，大小 `0x2F` (47 字节)
* **反编译伪代码**：
  ```c
  bool sub_1400243CC()
  {
    int cpuInfo[4];
    __cpuid(cpuInfo, 7);
    if ( (cpuInfo[1] & 0x100000) != 0 ) // Bit 20: CET_SS
      return (__readcr4() & 0x200000) != 0; // CR4.CET 启用状态
    return false;
  }
  ```

---

### 函数 11：`sub_14002441C` —— 逐核绑定巡检调度器（KeSetAffinityThread 全核遍历）
* **地址**：`0x14002441C`，大小 `0xBE` (190 字节)
* **形参定义**：`char __fastcall sub_14002441C(void (__fastcall *CallbackRoutine)(__int64 Context), __int64 Context)`
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002441C(void (__fastcall *CallbackRoutine)(__int64), __int64 Context)
  {
    KAFFINITY ActiveProcessors;
    struct _KTHREAD *CurrentThread;
    KAFFINITY Mask;
    UNICODE_STRING SystemRoutineName;

    if ( !CallbackRoutine ) return 0;
    if ( !qword_1459595C0 )
    {
      RtlInitUnicodeString(&SystemRoutineName, L"KeSetAffinityThread");
      qword_1459595C0 = MmGetSystemRoutineAddress(&SystemRoutineName);
      if ( !qword_1459595C0 ) return 0;
    }

    ActiveProcessors = KeQueryActiveProcessors();
    CurrentThread = KeGetCurrentThread();
    Mask = 1;

    for ( KAFFINITY i = ActiveProcessors; i != 0; Mask *= 2 )
    {
      i &= ~Mask;
      qword_1459595C0(CurrentThread, Mask); // 绑定当前线程至特定 CPU
      CallbackRoutine(Context);             // 执行 MSR/CR/DR 硬件状态巡检
    }

    qword_1459595C0(CurrentThread, ActiveProcessors);
    return 1;
  }
  ```

---

### 函数 12：`sub_1400244E4` —— 内核微秒/毫秒级安全相对延时
* **地址**：`0x1400244E4`，大小 `0x2B` (43 字节)
* **反编译伪代码**：
  ```c
  bool __fastcall sub_1400244E4(unsigned int Milliseconds)
  {
    LARGE_INTEGER Interval;
    Interval.QuadPart = -10000LL * Milliseconds;
    return KeDelayExecutionThread(KernelMode, FALSE, &Interval) == STATUS_SUCCESS;
  }
  ```

---

### 函数 13：`sub_14002482C` —— 动态定位未导出锁符号（PsGetJobLock / IoReleaseRemoveLockAndWaitEx）
* **地址**：`0x14002482C`，大小 `0x131` (305 字节)
* **反编译伪代码**：
  ```c
  __int64 sub_14002482C()
  {
    PVOID RoutineAddr;
    WCHAR RoutineName[32];

    if ( (unsigned int)sub_140029BA0() >= 0x3839 ) // Win10 Build >= 14393
    {
      wcscpy(RoutineName, L"PsGetJobLock");
      RoutineAddr = sub_14002FF18(RoutineName);
      if ( RoutineAddr )
      {
        __int64 Lock = sub_1400277A4(RoutineAddr, 4096);
        if ( Lock ) return Lock;
      }
      wcscpy(RoutineName, L"IoReleaseRemoveLockAndWaitEx");
      RoutineAddr = sub_14002FF18(RoutineName);
      if ( RoutineAddr )
        return sub_1400277A4(RoutineAddr, 4096);
    }
    return 0;
  }
  ```

---

### 函数 14：`sub_140024960` —— win32k.sys 与 csrss.exe GUI IRP 审计通道
* **地址**：`0x140024960`，大小 `0xED` (237 字节)
* **反编译伪代码**：
  ```c
  __int64 sub_140024960()
  {
    __int64 Win32kBase = sub_1400292B4(L"win32k.sys");
    if ( !Win32kBase ) return 0;

    for ( unsigned int Pid = 16; Pid < 0x4000; Pid += 4 )
    {
      PIRP Irp = NULL;
      if ( sub_140027CF0(Pid, &Irp) >= 0 && Irp )
      {
        if ( !sub_14002AF2C(Irp) )
        {
          const char *ProcName = sub_140027CA8(Irp);
          if ( _strnicmp(ProcName, "csrss.exe", 9) == 0 )
          {
            if ( sub_140027B8C(Win32kBase + 4096, ...) )
              return Pid; // 返回已验证的合法 csrss.exe PID
          }
          WdmlibIoValidateDeviceIoControlAccess(Irp, ...);
        }
      }
    }
    return 0;
  }
  ```

---

### 函数 15：`sub_140024A50` —— 内存模块节区范围匹配器
* **地址**：`0x140024A50`，大小 `0x5D` (93 字节)
* **反编译伪代码**：
  ```c
  __int64 sub_140024A50()
  {
    if ( !qword_145959D00 || !qword_145959CD8 ) return 0;

    _QWORD *Entry = (_QWORD *)qword_145959D00;
    for ( int i = 0; i < 14; ++i, Entry += 2 )
    {
      if ( (unsigned __int64)qword_145959CD8 >= Entry[0] &&
           (unsigned __int64)qword_145959CD8 < Entry[0] + Entry[1] )
        return qword_145959D00 + 16LL * i;
    }
    return 0;
  }
  ```

---

### 函数 16：`sub_140024AB0` —— 基于 RtlInsertElementGenericTableFullAvl 的 AVL 树未导出指针解析
* **地址**：`0x140024AB0`，大小 `0xBC` (188 字节)
* **反编译伪代码**：
  ```c
  __int64 sub_140024AB0()
  {
    if ( qword_145959DD8 != 0 ) return qword_145959DD8;
    if ( (unsigned int)sub_140029BA0() >= 0x2580 ) // >= Win8.1
    {
      int Pat1[2] = { 0x3F3F3FE8, 0x8B3F48 }; // E8 ?? ?? ?? ?? 48 ?? 8B
      __int64 CallTarget = sub_140027870(RtlInsertElementGenericTableFullAvl, 256, Pat1, 7, 0);
      if ( CallTarget )
      {
        __int64 Func = CallTarget + *(int *)(CallTarget + 1) + 5LL;
        int Pat2[2] = { 0x3F1D8B4C, 0x3F3F3F }; // 4C 8B 1D ?? ?? ?? ??
        __int64 Match = sub_140027870(Func, 256, Pat2, 7, 0);
        if ( Match )
          qword_145959DD8 = *(_QWORD *)(Match + 7 + *(int *)(Match + 3));
      }
    }
    return qword_145959DD8;
  }
  ```

---

### 函数 17：`sub_140024B6C` —— 基于 HalGetBusDataByOffset 动态提取 HAL 私有 MMIO/ECAM 直读例程
* **地址**：`0x140024B6C`，大小 `0xC5` (197 字节)
* **反编译伪代码**：
  ```c
  __int64 sub_140024B6C()
  {
    if ( !sub_140027710(HalGetBusDataByOffset) ) return 0;
    // 特征码: C1 E9 08 89 44 24 20 E8 ?? ?? ?? ?? 48 83 C4 38 C3
    int Pat1[4] = { 0x8908E9C1, 0xE8202444, 0x3F3F3F3F, 0x38C48348 };
    __int64 Match1 = sub_1400279B4(HalGetBusDataByOffset, 256, Pat1, 17);
    if ( Match1 )
    {
      __int64 Target = Match1 + *(int *)(Match1 + 8);
      int Pat2[2] = { 0x3F3F3FE8, 0xB83F };
      __int64 Match2 = sub_1400279B4(Target + 12, 256, Pat2, 10);
      if ( Match2 )
        return Match2 + 5 + *(int *)(Match2 + 1);
    }
    return 0;
  }
  ```

---

### 函数 18：`sub_140024C34` —— 汇编 LEA [RIP+disp32] 相对寻址解析助手
* **地址**：`0x140024C34`，大小 `0x49` (73 字节)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140024C34(__int64 Address, int ScanLimit)
  {
    __int16 Pat = 0x8D48;
    char Opcode = 0x0D; // 48 8D 0D (lea rcx, [rip + disp32])
    __int64 Match = sub_140027870(Address, ScanLimit, &Pat, 3, 0);
    if ( Match )
      return Match + 7 + *(int *)(Match + 3);
    return 0;
  }
  ```

---

### 函数 19：`sub_140024C80` —— 跨 Win10/11 全版本提取 EPROCESS.DirectoryTableBase (CR3) 偏移
* **地址**：`0x140024C80`，大小 `0x485` (1,157 字节)
* **版本特征**：通过对 Windows 10 Build `15063`、`16299`、`17134`、`17763`、`18362` 等各版本的指令多重跳转与相对寻址解析，提取出不受挂钩干扰的物理页目录基址（CR3）偏移。

---

### 函数 20：`sub_140025108` —— 动态解析 ci.dll 代码完整性校验例程
* **地址**：`0x140025108`，大小 `0xD8` (216 字节)
* **反编译伪代码**：
  ```c
  __int64 sub_140025108()
  {
    _DWORD DllName[3] = { 0x00690063, 0x0064002E, 0x006C006C }; // "cids.dll" / "ci.dll"
    __int64 CiBase = sub_1400292B4(DllName);
    if ( CiBase )
    {
      // 扫描 "PAGE" 节区定位 CiValidateImageHeader / CiValidateImageData 内部符号
    }
    return 0;
  }
  ```

---

### 函数 21：`sub_1400252BC` —— lsass.exe 安全凭据服务 PID 定位与句柄审计
* **地址**：`0x1400252BC`，大小 `0x9D` (157 字节)
* **反编译伪代码**：
  ```c
  __int64 sub_1400252BC()
  {
    for ( unsigned int i = 16; i < 0x4000; i += 4 )
    {
      PIRP Irp = NULL;
      if ( sub_140027CF0(i, &Irp) >= 0 && Irp )
      {
        const char *Name = sub_140027CA8(Irp);
        if ( _strnicmp(Name, "lsass.exe", 9) == 0 )
        {
          WdmlibIoValidateDeviceIoControlAccess(Irp, ...);
          return i;
        }
      }
    }
    return 0;
  }
  ```

---

### 函数 22：`sub_14002535C` —— 全版本物理内存映射例程定位器（支持至 Win11 24H2 Build 26100）
* **地址**：`0x14002535C`，大小 `0x25F` (607 字节)
* **版本适配**：涵盖 Win8.1 (`9600`) 到 Win11 24H2 (`26100`)，在最新 Build 26100 下动态提取 `MmRotatePhysicalView` 并解析 `qword_145959DC8`。

---

### 函数 23：`sub_1400255BC` —— 跨版本提取全局核心调度变量 `qword_145959DB0`
* **地址**：`0x1400255BC`，大小 `0x135` (309 字节)
* **适配范围**：Win10 19041~19045、Win11 22000、22621、22631、26100 (24H2)。

---

### 函数 24：`sub_1400259FC` —— 全版本 `NtOpenProcess` 系统调用号动态解析器
* **地址**：`0x1400259FC`，大小 `0x123` (291 字节)
* **映射映射表**：
  - `17134` (Win10 1803) -> Syscall `0xBB` (187)
  - `17763` (Win10 1809) -> Syscall `0xBC` (188)
  - `18362` / `18363` (Win10 1903/1909) -> Syscall `0xBD` (189)
  - `19041` ~ `19045` (Win10 2004-22H2) -> Syscall `0xC1` (193)
  - `22000` (Win11 21H2) -> Syscall `0xC5` (197)

---

### 函数 25：`sub_140025B80` & `sub_140025C74` —— 全版本 SSDT 与 `NtReadVirtualMemory` 索引数据库
* **地址**：`0x140025B80` (242 字节) 与 `0x140025C74` (232 字节)
* **覆盖范围**：Windows XP (`2600`)、Windows 7 (`7600/7601`)、Windows 8/8.1 (`9200/9600`)、Windows 10 (`10240`, `10586`, `14393`, `15063`, `16299`, `17134`, `17763`, `18362` 等)。

---

### 函数 26：`sub_1400261A0` —— `PsProcessType` 对象类型指针动态解析
* **地址**：`0x1400261A0`，大小 `0x26` (38 字节)
* **反编译伪代码**：
  ```c
  PVOID sub_1400261A0()
  {
    UNICODE_STRING DestinationString;
    RtlInitUnicodeString(&DestinationString, L"PsProcessType");
    return MmGetSystemRoutineAddress(&DestinationString);
  }
  ```

---

### 函数 27：`sub_1400261C8` —— 全局未导出进程创建通知链表 `PspCreateProcessNotifyRoutine` 逆向解析
* **地址**：`0x1400261C8`，大小 `0x12B` (299 字节)
* **形参定义**：`__int64 sub_1400261C8(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_1400261C8()
  {
    UNICODE_STRING DestinationString;
    RtlInitUnicodeString(&DestinationString, L"PsSetCreateProcessNotifyRoutine");
    PVOID Routine = MmGetSystemRoutineAddress(&DestinationString);
    if ( !Routine ) return 0;

    if ( sub_140029BE0() )
    {
      // 匹配特征: 0F 95 C2 E8 ?? ?? ?? ?? 33 DB 4C 8D 2D ?? ?? ?? ??
      // 提取未公开全局回调数组 PspCreateProcessNotifyRoutine
    }
    return Target;
  }
  ```
* **对抗意义**：直接定位内核存储全部进程通知回调函数的未导出数组 `PspCreateProcessNotifyRoutine`（最多 64 个槽位），排查是否存在第三方黑客驱动植入的隐蔽进程拦截钩子。

---

### 函数 28：`sub_1400262F4` —— PML4 自引用随机化绕过与全局页表基址重构（深度黑科技）
* **地址**：`0x1400262F4`，大小 `0x99` (153 字节)
* **形参定义**：`__int64 sub_1400262F4(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_1400262F4()
  {
    unsigned __int64 Cr3 = __readcr3() & 0xFFFFFFFFFFFFF000uLL;
    __int64 Pml4Virtual = (__int64)MmGetVirtualForPhysical((PHYSICAL_ADDRESS)Cr3);
    if ( !Pml4Virtual ) return 0;

    int Index = 0;
    __int64 TargetPhysical = Cr3 & 0xFFFFFFFFF000LL;

    // 在 512 个 PML4 表项中搜索指向自身物理地址的自映射表项
    for ( int i = 0; i < 512; ++i )
    {
      if ( (*(_QWORD *)(Pml4Virtual + 8LL * i) & 0xFFFFFFFFF000LL) == TargetPhysical )
      {
        Index = i;
        break;
      }
    }

    // 重构随机化后的 PML4 自映射虚拟地址 (Windows 10 Random Self-Reference)
    qword_145959CE0 = (Index + 33553920LL) << 39;
    qword_145959CE8 = ((Index + 33553920LL) << 39) + ((__int64)Index << 30);
    return qword_145959CE0;
  }
  ```
* **对抗意义**：微软在 Win10 1607 起将 PML4 自引用表项（Self-Reference Index）从固定的 `0x1ED` 改为启动时随机生成。ACE 在驱动中直接读取物理 CR3 并使用 `MmGetVirtualForPhysical` 遍历 512 个表项，计算出当前系统的动态 PML4 自映射基址，从而获得任意物理内存页 PTE 属性的底层直写能力！

---

### 函数 29：`sub_140026808` —— 内核 `JMP RCX` ROP Gadget 搜寻器
* **地址**：`0x140026808`，大小 `0x84` (132 字节)
* **反编译伪代码**：
  ```c
  _BYTE *sub_140026808()
  {
    if ( sub_1400242D4() ) return NULL; // 若运行在 Hyper-V 下则规避
    char *Func = (char *)sub_14002FF18(L"SeSetAuditParameter");
    if ( Func )
    {
      _BYTE *Ptr = Func + 16;
      _BYTE *End = Func + 528;
      while ( Ptr != End )
      {
        // 扫描寻找 0xFF 0xE1 (jmp rcx) 机器指令桩
        if ( sub_140027B8C(Ptr) && sub_140027B8C(Ptr + 1) && *Ptr == 0xFF && Ptr[1] == 0xE1 )
          return Ptr;
        ++Ptr;
      }
    }
    return NULL;
  }
  ```
* **对抗意义**：驱动将自身发起特权系统调用的入口重定向至 Windows 内核合法的 `JMP RCX` Gadget 桩，彻底清除自身代码段发起的直接 `CALL` 堆栈帧特征。

---

### 函数 30：`sub_1400270E0` —— SSDT 与 Shadow SSDT 双总线系统调用执行终端
* **地址**：`0x1400270E0`，大小 `0xEC` (236 字节)
* **形参定义**：`__int64 __fastcall sub_1400270E0(int SyscallIndex)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400270E0(int SyscallIndex)
  {
    __int64 *SsdtTable;
    int CleanIndex = SyscallIndex;

    if ( SyscallIndex == -1 ) return 0;

    if ( SyscallIndex >= 4096 ) // 0x1000: Shadow SSDT (GUI / win32k)
    {
      __int64 Win32kContext = sub_14002AFD0();
      if ( !Win32kContext ) return 0;
      sub_140027B24(Win32kContext, ...);
      SsdtTable = (__int64 *)qword_145959CC8; // KeServiceDescriptorTableShadow
      SsdtTable += 4;
      CleanIndex &= 0xFFF;
    }
    else // 原生 SSDT (ntoskrnl)
    {
      SsdtTable = (__int64 *)qword_145959CC0; // KeServiceDescriptorTable
    }

    if ( SsdtTable && MmIsAddressValid(SsdtTable) )
    {
      // 提取未公开服务函数真实地址并返回
      ...
    }
    return TargetRoutine;
  }
  ```

---

### 函数 31：`sub_140027434` 与 `sub_140027910` —— MSR `0xC0000082` (`IA32_LSTAR`) 直读与双 SSDT 汇编提取
* **地址**：`0x140027434` (141 字节) 与 `0x140027910` (164 字节)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140027434(char IsShadowSsdt)
  {
    // 直读 MSR IA32_LSTAR (KiSystemCall64 入口)
    char *Lstar = (char *)__readmsr(0xC0000082);
    char *ScanEnd = Lstar + 1280;

    // 若启用了 KVA Shadow (CVE-2017-5754 Meltdown 缓解措施)
    if ( sub_140029BB4(...) )
    {
      __int64 Stub = sub_140026C08(Lstar, ScanEnd); // 修正至 KiSystemCall64Shadow
      Lstar = (char *)(Stub + 48);
      ScanEnd = Lstar + 768;
    }

    return sub_140027910(Lstar, ScanEnd, IsShadowSsdt);
  }

  char *__fastcall sub_140027910(_BYTE *Start, _BYTE *End, char IsShadowSsdt)
  {
    _BYTE *p = Start;
    while ( p < End )
    {
      // 搜索指令流特征:
      // 4C 8D 15 ?? ?? ?? ?? (lea r10, KeServiceDescriptorTable)
      // 4C 8D 1D ?? ?? ?? ?? (lea r11, KeServiceDescriptorTableShadow)
      if ( *p == 0x4C && p[1] == 0x8D && p[2] == 0x15 &&
           p[7] == 0x4C && p[8] == 0x8D && p[9] == 0x1D )
      {
        int *Disp = (int *)&p[IsShadowSsdt ? 10 : 3];
        return (char *)Disp + *Disp + 4; // 计算出 SSDT 或 Shadow SSDT 的绝对地址
      }
      ++p;
    }
    return NULL;
  }
  ```

---

### 函数 32：`sub_140027570` —— 全局未导出符号主调度例程（Master Initialization Bus）
* **地址**：`0x140027570`，大小 `0x1A0` (416 字节)
* **调度全流程**：
  ```c
  __int64 sub_140027570()
  {
    // 1. 初始化 196 字节动态符号状态表
    if ( sub_140027E24(&unk_1459597E0) < 0 ) return;

    // 2. 审查 csrss.exe IRP 并记录 PID
    qword_145959C80 = sub_140024960();

    // 3. 释放并重新组织符号堆池
    sub_140025D5C();
    sub_140025DB0();

    // 4. 分配 256KB ('dsp1') 物理内存并初始化动态句柄与拓扑
    sub_140026B08();

    // 5. 解析系统公开/未公开对象类型与 JMP RCX 桩
    qword_1459598F8 = sub_14002FF18(L"IoDriverObjectType");
    qword_145959CA0 = sub_1400261A0(); // PsProcessType
    qword_145959C98 = sub_140026808(); // JMP RCX Gadget
    qword_145959C88 = sub_1400252BC(); // lsass.exe PID
    qword_145959C90 = sub_1400265E4(); // win32k 内部输入钩子

    // 6. 直读 MSR LSTAR 提取 KeServiceDescriptorTable / Shadow SSDT
    qword_145959CC0 = sub_140027434(0); // SSDT
    qword_145959CC8 = sub_140027434(1); // Shadow SSDT

    // 7. 多级特征码解析 DirectoryTableBase (CR3) 与 PML4 自引用
    sub_140024C80();
    sub_1400262F4();

    // 8. 解析 HAL 内部私有 PCIe MMIO 直读例程与 AVL 树根
    qword_145959D90 = sub_140024B6C();
    qword_145959DD8 = sub_140024AB0();

    // 9. 适配 Win11 24H2 物理内存映射与进程通知回调数组
    sub_14002535C();
    sub_1400261C8();
  }
  ```

---

### 函数 33：`sub_140027F14` —— 跨进程挂接目标进程 PEB 与用户态 LdrModule 链表审计
* **地址**：`0x140027F14`，大小 `0x418` (1,048 字节)
* **执行流程与算法**：
  ```c
  void sub_140027F14()
  {
    // 1. 获取目标受控进程 (游戏或 csrss.exe)
    PKPROCESS Process = (PKPROCESS)sub_14002A81C(qword_145959C80);
    if ( !Process ) return;

    // 2. 提取用户态 PEB 结构基址
    __int64 Peb = PsGetProcessPeb(Process);
    if ( !Peb ) return;

    // 3. 挂入目标进程虚拟地址空间
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    // 4. 读取 PEB.Ldr (PPEB_LDR_DATA)，遍历 InLoadOrderModuleList 链表
    // 匹配核心模块 (如 ntdll.dll / kernel32.dll / 游戏主程序)
    // 提取模块 Export Directory 与用户态系统调用桩 (Syscall Stubs)
    // 核验用户态函数头是否被篡改或 Hook (如 0xE9 / 0xFF 25 跳转)

    // 5. 退出目标进程空间并恢复 APC 状态
    KeUnstackDetachProcess(&ApcState);
  }
  ```
* **对抗意义**：外挂通常在用户态修改 NTDLL 的 `NtUserSendInput` 或 `NtOpenProcess` 系统调用桩。ACE 直接从内核挂入进程空间，读取 PEB 链表和未重定向的原始模块节区，对用户态代码段与系统调用桩进行完整性交叉校验。

---

### 函数 34：`sub_14002832C` —— 全量内核未公开/敏感 API 动态大虚表解析（2.1KB 巨型虚表）
* **地址**：`0x14002832C`，大小 `0x86D` (2,157 字节)
* **形参定义**：`__int64 sub_14002832C(void)`
* **全量解析列表**：
  ```c
  __int64 sub_14002832C()
  {
    qword_145959DE8 = sub_14002FF18(L"ObfDereferenceObject");
    qword_145959DE0 = sub_14002FF18(L"ObfReferenceObject");
    qword_145959DF0 = sub_14002FF18(L"ObReferenceObjectByHandle");
    qword_145959DF8 = sub_14002FF18(L"ObReferenceObjectByName");
    qword_145959E20 = sub_14002FF18(L"ZwQueryObject");
    qword_145959E28 = sub_14002FF18(L"ZwDuplicateObject");
    qword_145959E30 = sub_14002FF18(L"ZwOpenProcess");
    qword_145959E38 = sub_14002FF18(L"ZwOpenThread");
    qword_145959E40 = sub_14002FF18(L"ZwQueryInformationProcess");
    qword_145959E48 = sub_14002FF18(L"ZwQueryInformationThread");
    qword_145959E50 = sub_14002FF18(L"ZwAllocateVirtualMemory");
    qword_145959E58 = sub_14002FF18(L"ZwFreeVirtualMemory");
    qword_145959E60 = sub_14002FF18(L"ZwProtectVirtualMemory");
    qword_145959E68 = sub_14002FF18(L"ZwReadVirtualMemory");
    qword_145959E70 = sub_14002FF18(L"ZwWriteVirtualMemory");
    qword_145959E78 = sub_14002FF18(L"ZwQueryVirtualMemory");
    qword_145959E80 = sub_14002FF18(L"ZwQuerySystemInformation");
    qword_145959E88 = sub_14002FF18(L"ZwClose");
    ...
    return 0;
  }
  ```
* **技术价值**：驱动静态导入表彻底清零，所有内核底层对象操作与虚拟内存管理函数均在运行时在此处一次性动态获取并封装至全局大虚表 `qword_145959DE0` ~ `qword_14595A000`。

---

### 函数 35：`sub_140028B9C` —— 系统调用号 178 兼容与加载器审计触发器
* **地址**：`0x140028B9C`，大小 `0x34` (52 字节)
* **反编译伪代码**：
  ```c
  void sub_140028B9C()
  {
    if ( !qword_145959F40 && sub_140029BA0() == 2600 ) // Windows XP
      qword_145959F40 = sub_1400270E0(178);

    sub_140027F14(); // 触发全量 PEB 加载器链表审计
  }
  ```

---

### 函数 36：`sub_140028BD0` —— 64 位整数转十六进制字符串与大小写格式化器
* **地址**：`0x140028BD0`，大小 `0x13A` (314 字节)
* **形参定义**：`__int64 __fastcall sub_140028BD0(ULONGLONG Value, PANSI_STRING DestinationString, char ToLower)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140028BD0(ULONGLONG Value, PANSI_STRING DestinationString, char ToLower)
  {
    UNICODE_STRING uStr;
    wchar_t Source[20], Temp[20];

    RtlInt64ToUnicodeString(Value, 16u, &uStr);
    if ( ToLower )
      _wcslwr(uStr.Buffer);
    else
      _wcsupr(uStr.Buffer);

    // 格式化输出为定长 ANSI 字符串
    return RtlUnicodeStringToAnsiString(DestinationString, &uStr, TRUE);
  }
  ```

---

### 函数 37：`sub_140028DB0` —— CPUID 与 Hyper-V 私有 Enlightenment 特性查询
* **地址**：`0x140028DB0`，大小 `0xB6` (182 字节)
* **反编译伪代码**：
  ```c
  char sub_140028DB0()
  {
    int cpuInfo[4];
    char sig[16];

    __cpuid(cpuInfo, 0x40000000);
    // 校验 "Microsoft Hv"
    if ( strcmp(sig, "Microsoft Hv") == 0 )
    {
      if ( sub_140027EB0(...) >= 0 )
        return v11 & 1; // 提取 VBS / 隔离特性启用标志
    }
    return 0;
  }
  ```

---

### 函数 38：`sub_140028E68` —— ACPI 物理表 RAMD / SRVI 保留内存区审计器
* **地址**：`0x140028E68`，大小 `0xF4` (244 字节)
* **技术逻辑**：通过 `sub_140027EB0` 搜索 BIOS ACPI 物理结构，核验 `0x41435049` (`'ACPI'`) 标头，比对 `0x52414D44` (`"RAMD"`) 与 `0x53525649` (`"SRVI"`) 硬件内存保留描述符，排查利用 ACPI 保留段隐藏可执行代码或 DMA 注入缓存的行为。

---

### 函数 39：`sub_140028FFC` —— 物理内存到虚拟内存二分查找反向映射器（Physical-to-Virtual Binary Search Engine）
* **地址**：`0x140028FFC`，大小 `0xDB` (219 字节)
* **形参定义**：`void *__fastcall sub_140028FFC(unsigned __int64 PhysicalAddress)`
* **反编译伪代码**：
  ```c
  void *__fastcall sub_140028FFC(unsigned __int64 PhysicalAddress)
  {
    if ( !byte_14595A108 || !qword_14595A110 || !dword_14595A118 )
      return NULL;

    int Low = 0;
    int High = dword_14595A118 - 1;

    // 在已排序的物理内存段表中执行高速二分查找
    while ( Low <= High )
    {
      int Mid = Low + (High - Low) / 2;
      unsigned __int64 PhysBase = *((_QWORD *)qword_14595A110 + 3 * Mid);
      unsigned int RangeSize = *((unsigned int *)qword_14595A110 + 6 * Mid + 4);

      if ( PhysBase <= PhysicalAddress && PhysicalAddress < PhysBase + RangeSize )
      {
        // 命中目标物理内存段，计算对应虚拟地址
        unsigned __int64 VirtBase = *((_QWORD *)qword_14595A110 + 3 * Mid + 1);
        void *VirtualAddr = (void *)(PhysicalAddress + VirtBase - PhysBase);

        // 双向强校验: 确保虚拟地址有效且其物理地址与输入精确一致
        if ( MmIsAddressValid(VirtualAddr) && MmGetPhysicalAddress(VirtualAddr).QuadPart == PhysicalAddress )
          return VirtualAddr;
        break;
      }

      if ( PhysBase + RangeSize > PhysicalAddress )
        High = Mid - 1;
      else
        Low = Mid + 1;
    }
    return NULL;
  }
  ```
* **对抗与架构价值**：反作弊驱动在底层执行硬件级物理页审查（如 IOMMU Fault、暗影 MMIO、DMA Trap）时，截获的均为 64 位物理地址（PA）。传统的虚拟地址转换需要遍历页表，极其耗时。ACE 在内存中维护了全系统已排序的物理内存分段表，通过该二分查找引擎在微秒级时间内反查出对应的内核虚拟地址（VA），并调用 `MmGetPhysicalAddress` 严格反向验证，杜绝一切页表欺骗与虚假地址映射！

---

### 函数 40：`sub_1400290E0` —— DISPATCH_LEVEL 高特权级安全物理内存原子只读引擎
* **地址**：`0x1400290E0`，大小 `0x92` (146 字节)
* **形参定义**：`_DWORD *__fastcall sub_1400290E0(unsigned __int64 PhysicalAddress, __int64 DstBuffer, unsigned int ByteCount)`
* **反编译伪代码**：
  ```c
  _DWORD *__fastcall sub_1400290E0(unsigned __int64 PhysicalAddress, __int64 DstBuffer, unsigned int ByteCount)
  {
    if ( !DstBuffer ) return NULL;

    KIRQL OldIrql = KeGetCurrentIrql();
    __writecr8(DISPATCH_LEVEL); // 提升 IRQL 至 2，屏蔽线程调度抖动

    // 利用二分查找物理映射引擎获取虚拟地址
    _DWORD *VirtualAddr = (_DWORD *)sub_140028FFC(PhysicalAddress);
    if ( VirtualAddr && MmIsAddressValid(VirtualAddr) )
    {
      unsigned int DwordCount = ByteCount >> 2;
      for ( unsigned int i = 0; i < DwordCount; ++i )
      {
        ((_DWORD *)DstBuffer)[i] = VirtualAddr[i]; // 4 字节对齐安全物理直读
      }
    }

    __writecr8(OldIrql); // 恢复原 IRQL
    return VirtualAddr;
  }
  ```
* **对抗意义**：外挂若在页表层玩“双面映射”（PTE Hook / Shadow Page），常规虚拟地址读取会被欺骗。该函数在提升 IRQL 屏蔽中断的前提下，以纯物理地址（PA）为入参直接反查物理分段内存并拷贝，彻底穿透用户态或内核态虚拟地址层面的障眼法。

---

### 函数 41：`sub_1400292B4` —— 全局系统内核模块基址与大小解析器（Unicode 驱动定位核心）
* **地址**：`0x1400292B4`，大小 `0xB8` (184 字节)
* **形参定义**：`__int64 __fastcall sub_1400292B4(_WORD *DriverNameUnicode, _DWORD *OutModuleSize)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400292B4(_WORD *DriverNameUnicode, _DWORD *OutModuleSize)
  {
    wchar_t UpperName[260];
    if ( !DriverNameUnicode ) return 0;

    // 复制并转大写
    memmove(UpperName, DriverNameUnicode, ...);
    _wcsupr(UpperName);

    // 遍历内核模块链表回调 sub_1400298F4 匹配模块名
    __int64 ModuleBase = 0;
    int ModuleSize = 0;
    sub_14002E8B0(sub_1400298F4, UpperName);

    if ( OutModuleSize )
      *OutModuleSize = ModuleSize;
    return ModuleBase;
  }
  ```
* **核心地位**：被全驱动 14 个关键防御子系统频繁调用，动态锁定 `win32k.sys`、`ntoskrnl.exe`、`ci.dll`、`acpi.sys`、`pci.sys` 的真实加载基址与大小。

---

### 函数 42：`sub_140029418` —— 内核虚拟地址反查所属驱动名称（Address-to-Module Reverse Resolver）
* **地址**：`0x140029418`，大小 `0xE0` (224 字节)
* **形参定义**：`__int64 __fastcall sub_140029418(__int64 KernelAddress, void *OutNameBuffer, unsigned int BufferSize, _DWORD *OutModuleSize)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140029418(__int64 KernelAddress, void *OutNameBuffer, unsigned int BufferSize, _DWORD *OutModuleSize)
  {
    _WORD DriverName[260];
    if ( !KernelAddress || !OutNameBuffer || !BufferSize ) return 0;

    // 遍历全局模块区间回调 sub_1400297EC
    sub_14002E8B0(sub_1400297EC, DriverName);
    if ( Found )
    {
      memmove(OutNameBuffer, DriverName, ...); // 导出完整的所属驱动名称字符串
      return TargetModuleBase;
    }
    return 0;
  }
  ```
* **对抗意义**：当 ACE 发现未知的 IRP 派遣例程、过滤驱动回调或非法系统调用劫持点时，立即将劫持地址送入此函数，反查其归属的驱动文件名，若非系统已知合法驱动，则直接标记为非法作弊模块。

---

### 函数 43：`sub_1400296D0` —— CPU 硬件 `SIDT` 特权指令直读中断描述符表（IDTR 直读）
* **地址**：`0x1400296D0`，大小 `0x4B` (75 字节)
* **形参定义**：`__int64 sub_1400296D0(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_1400296D0()
  {
    struct {
      __int16 Limit;
      __int64 Base;
    } Idtr;

    Idtr.Limit = 0;
    Idtr.Base = 0;
    __sidt(&Idtr); // 汇编执行 sidt 指令，直接读取 CPU 硬件 IDTR

    if ( !sub_14002F3D0(Idtr.Base) || !sub_140027B8C(Idtr.Base) )
      return 0;

    return Idtr.Base; // 返回当前核心的物理/虚拟 IDT 表真实基址
  }
  ```
* **技术价值**：绕过所有内核导出与软件级中断挂钩，直接利用 CPU 原生机器指令提取当前物理核心的 IDT 表基址。

---

### 函数 44：`sub_1400295D0` —— 64 位中断门描述符 ISR 入口指针解码器
* **地址**：`0x1400295D0`，大小 `0x67` (103 字节)
* **形参定义**：`unsigned __int64 __fastcall sub_1400295D0(unsigned __int8 VectorNumber)`
* **反编译伪代码**：
  ```c
  unsigned __int64 __fastcall sub_1400295D0(unsigned __int8 VectorNumber)
  {
    if ( VectorNumber == 0xFF ) return 0;

    // 定位 IDT 门描述符 (每个门 16 字节)
    unsigned __int16 *Gate = (unsigned __int16 *)(16LL * VectorNumber + sub_1400296D0());

    // 组合 64 位中断服务例程 (ISR) 真实入口地址:
    // Bits 0..15: Gate[0] (Offset Low)
    // Bits 16..31: Gate[3] (Offset Middle)
    // Bits 32..63: *(DWORD *)(Gate + 4) (Offset High)
    unsigned __int64 IsrEntry = *Gate | ((Gate[3] | ((unsigned __int64)*((unsigned int *)Gate + 2) << 16)) << 16);

    if ( !sub_140027B8C(IsrEntry) || !sub_14002F3D0(IsrEntry) )
      return 0;

    return IsrEntry;
  }
  ```
* **对抗意义**：反作弊驱动用于精确提取第 `VectorNumber` 号硬件中断（如鼠标按键中断、键盘中断、定时器中断、IPI 中断）对应的内核处理例程，排查 IDT Hook 攻击。

---

### 函数 45：`sub_140029638` —— 中断服务例程（ISR）内部上下文模式扫描
* **地址**：`0x140029638`，大小 `0x98` (152 字节)
* **形参定义**：`unsigned __int64 __fastcall sub_140029638(unsigned __int8 VectorNumber)`
* **反编译伪代码**：
  ```c
  unsigned __int64 __fastcall sub_140029638(unsigned __int8 VectorNumber)
  {
    unsigned __int64 Isr = sub_1400295D0(VectorNumber);
    if ( !Isr ) return 0;

    // 扫描机器指令特征: 48 8D 2D ?? ?? ?? ?? (lea rbp, [rip + disp32])
    if ( *(_BYTE *)(Isr + 2) == 0x48 &&
         *(_BYTE *)(Isr + 3) == 0x8D &&
         *(_BYTE *)(Isr + 4) == 0x2D )
    {
      // 提取中断服务例程引用的内核全局上下文结构基址
      return (Isr & 0xFFFFFFFF00000000uLL) + (unsigned int)(*(_DWORD *)(Isr + 5) + Isr + 9);
    }
    return 0;
  }
  ```

---

### 函数 46：`sub_14002971C` —— 通用系统信息查询动态自动扩容引擎（ZwQuerySystemInformation Auto-Resizer）
* **地址**：`0x14002971C`，大小 `0xCE` (206 字节)
* **形参定义**：`__int64 __fastcall sub_14002971C(ULONG SystemInformationClass, _QWORD *OutBuffer, unsigned int *OutBufferSize)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002971C(ULONG InfoClass, _QWORD *OutBuffer, unsigned int *OutBufferSize)
  {
    PVOID Pool = NULL;
    unsigned int AllocSize = 0;

    int Status = sub_140027EB0(InfoClass, NULL, 0, &AllocSize);
    if ( Status == STATUS_SUCCESS || Status == STATUS_INFO_LENGTH_MISMATCH )
    {
      while ( 1 )
      {
        Pool = ExAllocatePool(PagedPool, AllocSize);
        if ( !Pool ) break;

        Status = sub_140027EB0(InfoClass, Pool, AllocSize, &AllocSize);
        if ( Status != STATUS_INFO_LENGTH_MISMATCH ) // 成功获取完整系统数据
          break;

        ExFreePoolWithTag(Pool, 0);
        AllocSize += 256; // 动态扩容重试
      }
    }

    if ( Status >= 0 )
    {
      *OutBuffer = Pool;
      *OutBufferSize = AllocSize;
    }
    return (unsigned int)Status;
  }
  ```

---

### 函数 47：`sub_14002A1E4` —— 多版本 EPROCESS/KTHREAD 结构体偏移静态映射表
* **地址**：`0x14002A1E4`，大小 `0x5D` (93 字节)
* **形参定义**：`__int64 sub_14002A1E4(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002A1E4()
  {
    unsigned int Offset = 0;
    int BuildNumber;

    if ( sub_140029BF8() ) // 检查特定 Windows 预览版/测试版分支
    {
      return 344; // 0x158
    }
    else if ( sub_140029BC8() ) // 检查 NT 10.0 内核
    {
      BuildNumber = sub_140029BA0(); // 获取系统内部 Build 号
      if ( BuildNumber == 15063 || BuildNumber == 16299 ) // 1703 (RS2) / 1709 (RS3)
      {
        return 376; // 0x178
      }
      else if ( BuildNumber == 17134 || BuildNumber == 17763 || BuildNumber == 18362 ) // 1803 / 1809 / 1903 (19H1)
      {
        return 416; // 0x1A0
      }
    }
    return Offset;
  }
  ```
* **对抗意义**：Windows 10 各个功能更新频繁重排 `EPROCESS` 与 `ETHREAD` 核心结构体。本函数根据内核 Build 号精准返回对应版本的内部偏移，确保后续无感知读取进程/线程核心属性。

---

### 函数 48：`sub_14002A244` —— 操作系统版本标志位与基础偏移判定
* **地址**：`0x14002A244`，大小 `0x27` (39 字节)
* **形参定义**：`__int64 sub_14002A244(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002A244()
  {
    unsigned int BaseOffset = 0;

    if ( sub_140029BF8() != 0 || sub_140029BC8() )
      return 16; // 0x10 (64 位 NT10 链表头基础步进)
    return BaseOffset;
  }
  ```

---

### 函数 49：`sub_14002A26C` —— 遍历当前进程线程链表动态定位 ETHREAD.ThreadListEntry 偏移
* **地址**：`0x14002A26C`，大小 `0x83` (131 字节)
* **形参定义**：`__int64 sub_14002A26C(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002A26C()
  {
    unsigned int FoundOffset = 0;
    unsigned __int64 CurrentThread = sub_140027C7C(); // 获取当前 KTHREAD 指针
    void **pThreadListHead = (void **)((char *)IoGetCurrentProcess() + 48); // EPROCESS.ThreadListHead

    if ( MmIsAddressValid(pThreadListHead) )
    {
      void *ListHead = *pThreadListHead;
      unsigned __int64 Entry = (unsigned __int64)ListHead;

      for ( void *p = ListHead; MmIsAddressValid(p); p = (void *)Entry )
      {
        Entry = *(_QWORD *)(Entry + 8); // Flink / Blink
        if ( (void *)Entry == ListHead )
          break;

        // 如果链表中的某项指针落在当前线程 [CurrentThread, CurrentThread + 0x1000] 页范围内
        if ( Entry >= CurrentThread && Entry <= CurrentThread + 0x1000 )
        {
          FoundOffset = Entry - CurrentThread; // 动态计算出 ETHREAD.ThreadListEntry 偏移
          break;
        }
      }
    }
    return FoundOffset;
  }
  ```
* **对抗意义**：彻底摒弃硬编码偏移！通过当前进程的 `ThreadListHead` 顺藤摸瓜找到当前线程自身的 `LIST_ENTRY` 节点，两指针相减即可在任何未知或加固的 Windows 预览版中 100% 动态算出 `ETHREAD.ThreadListEntry` 偏移。

---

### 函数 50：`sub_14002A2F0` —— 机器码特征提取 PsGetCurrentThreadPreviousMode (ETHREAD.PreviousMode 偏移)
* **地址**：`0x14002A2F0`，大小 `0xBE` (190 字节)
* **形参定义**：`__int64 sub_14002A2F0(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002A2F0()
  {
    unsigned int Offset = 0;
    char *FuncAddress = (char *)sub_14002FF18(L"PsGetCurrentThreadPreviousMode");

    if ( FuncAddress != NULL )
    {
      // 在函数前 32 字节内搜索机器码指令:
      // mov al, [rax + PreviousMode_Offset]  (8A 80 xx xx xx xx 或 8A 88 xx xx xx xx)
      for ( unsigned int i = 0; i < 0x20; ++i )
      {
        char *p = &FuncAddress[i];
        if ( sub_140027B8C(p) && sub_140027B8C(p + 1) )
        {
          if ( *p == (char)0x8A && (p[1] & 0xC7) == 0x80 ) // 匹配 8A 80/88 (MOV AL, [REG + disp32])
          {
            Offset = *(unsigned int *)(p + 2); // 提取 32 位位移即为 ETHREAD.PreviousMode
            break;
          }
        }
      }
    }
    return Offset;
  }
  ```
* **对抗意义**：`PreviousMode` 是内核降权/提权判定（`UserMode`=1, `KernelMode`=0）的最核心标志。通过反汇编系统导出函数 `PsGetCurrentThreadPreviousMode` 动态解密偏移，防止驱动被恶意软件修改 `PreviousMode` 篡改 `ProbeForRead` / `ProbeForWrite` 审计。

---

### 函数 51：`sub_14002A3B0` —— 基于 PsGetCurrentThreadId 匹配定位 ETHREAD.Cid.UniqueThread 偏移
* **地址**：`0x14002A3B0`，大小 `0x85` (133 字节)
* **形参定义**：`__int64 sub_14002A3B0(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002A3B0()
  {
    __int64 CurrentThread = sub_140027C7C();
    __int64 CurrentProcessId = sub_140027C6C(); // PsGetCurrentProcessId()
    HANDLE CurrentThreadId = PsGetCurrentThreadId();
    unsigned int FoundOffset = 0;

    // 在 ETHREAD 结构体范围 [CurrentThread, CurrentThread + 0x1000] 内逐 8 字节搜索匹配 CLIENT_ID
    for ( __int64 p = CurrentThread; p < CurrentThread + 0x1000; p += 8 )
    {
      if ( !sub_140027B8C(p) )
        return 0;

      // CLIENT_ID 结构体由 UniqueProcess (PID) 和 UniqueThread (TID) 组成
      if ( *(_QWORD *)p == CurrentProcessId && *(HANDLE *)(p + 8) == CurrentThreadId )
      {
        FoundOffset = p - CurrentThread; // 成功锁定 ETHREAD.Cid 偏移
        break;
      }
    }
    return FoundOffset;
  }
  ```

---

### 函数 52：`sub_14002A438` —— 动态探测 IRP / 内核对象尾部私有扩展偏移
* **地址**：`0x14002A438`，大小 `0xC2` (194 字节)
* **形参定义**：`__int64 sub_14002A438(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002A438()
  {
    unsigned int FoundOffset = 0;
    unsigned int TryOffset = 8;
    __int64 TargetObj;
    __int64 OutValue = 0;

    while ( 1 )
    {
      TargetObj = sub_140030538(TryOffset);
      if ( TargetObj != 0 )
      {
        if ( sub_140030560(TargetObj, &OutValue) >= 0 && OutValue != 0 )
        {
          FoundOffset = TryOffset;
          break;
        }
      }
      TryOffset += 4;
      if ( TryOffset > 0x40000 )
        break;
    }
    return FoundOffset;
  }
  ```

---

### 函数 53：`sub_14002A4FC` ~ `sub_14002A51C` —— 内核关键偏移全局只读分发接口群
* **地址范围**：`0x14002A4FC` ~ `0x14002A523`
* **反编译伪代码**：
  ```c
  __int64 sub_14002A4FC() { return (unsigned int)dword_14595A128; } // EPROCESS.ActiveProcessLinks 偏移
  __int64 sub_14002A504() { return (unsigned int)dword_14595A124; } // EPROCESS.ProcessId (PID) 偏移
  __int64 sub_14002A50C() { return (unsigned int)dword_14595A138; } // EPROCESS.InheritedFromUniqueProcessId 偏移
  __int64 sub_14002A514() { return 48; }                          // EPROCESS.ThreadListHead 基础偏移
  __int64 sub_14002A51C() { return (unsigned int)dword_14595A140; } // ETHREAD.ThreadListEntry 偏移
  ```

---

### 函数 54：`sub_14002A524` —— 全系统内核对象与线程结构全局偏移解析总控引擎
* **地址**：`0x14002A524`，大小 `0x77` (119 字节)
* **形参定义**：`__int64 sub_14002A524(void)`
* **反编译伪代码**：
  ```c
  __int64 sub_14002A524()
  {
    dword_14595A11C = sub_140029E74(); // 解析 EPROCESS.SectionBaseAddress 偏移
    dword_14595A120 = sub_14002A2F0(); // 特征提取 ETHREAD.PreviousMode 偏移
    dword_14595A124 = sub_140029EB8(); // 解析 EPROCESS.UniqueProcessId 偏移
    dword_14595A128 = sub_140029E18(); // 解析 EPROCESS.ActiveProcessLinks 偏移
    dword_14595A12C = sub_14002A438(); // 扫描 IRP 私有扩展偏移
    dword_14595A130 = sub_14002A244(); // 基础版本步进 (16)
    dword_14595A134 = sub_14002A1E4(); // 多版本结构体常量 (344/376/416)
    dword_14595A138 = sub_140029FFC(); // 父进程 ID 偏移
    dword_14595A13C = sub_14002A3B0(); // 特征匹配 ETHREAD.Cid 偏移
    dword_14595A140 = sub_14002A26C(); // 动态遍历提取 ETHREAD.ThreadListEntry 偏移

    return dword_14595A140;
  }
  ```
* **对抗意义**：系统初始化总控！通过此例程，ACE 在驱动装载伊始一次性全自动适配当前运行环境的所有未导出结构体偏移，将它们缓存在 `dword_14595A11C` ~ `140` 变量中供全驱动无锁直读。

---

### 函数 55：`sub_14002A81C` —— 安全获取进程 EPROCESS 封装与引用保护
* **地址**：`0x14002A81C`，大小 `0x28` (40 字节)
* **形参定义**：`PEPROCESS __fastcall sub_14002A81C(HANDLE ProcessId)`
* **反编译伪代码**：
  ```c
  PEPROCESS __fastcall sub_14002A81C(HANDLE ProcessId)
  {
    PEPROCESS Process = NULL;
    if ( (int)sub_140027CF0(ProcessId, &Process) >= 0 ) // PsLookupProcessByProcessId
      return Process;
    return NULL;
  }
  ```

---

### 函数 56：`sub_14002B030` —— 跨进程挂接安全内存读取与状态恢复
* **地址**：`0x14002B030`，大小 `0x8D` (141 字节)
* **形参定义**：`NTSTATUS __fastcall sub_14002B030(PEPROCESS TargetProcess, PVOID BaseAddress, ULONG BufferSize, PVOID OutBuffer, ULONG Flags, PULONG ReturnLength)`
* **反编译伪代码**：
  ```c
  NTSTATUS __fastcall sub_14002B030(PEPROCESS TargetProcess, PVOID BaseAddress, ULONG BufferSize, PVOID OutBuffer, ULONG Flags, PULONG ReturnLength)
  {
    KAPC_STATE ApcState;

    if ( sub_14002AF2C((__int64)TargetProcess) )
      return STATUS_PROCESS_IS_TERMINATING; // 0xC000010A

    sub_140027B24(TargetProcess, &ApcState); // KeStackAttachProcess(TargetProcess, &ApcState)
    NTSTATUS Status = sub_140027EC8((HANDLE)-1, BaseAddress, BufferSize, OutBuffer, Flags, ReturnLength); // ZwReadVirtualMemory / MmCopyVirtualMemory
    sub_140027B48(&ApcState);               // KeUnstackDetachProcess(&ApcState)

    return Status;
  }
  ```

### 函数 57：`sub_14002D91C` —— 硬件特权指令 __writecr3 暗影 CR3 实时切换器与进程上下文动态同步
* **地址**：`0x14002D91C`，大小 `155` 字节 (`0x9B`)
* **反编译伪代码**：
  ```c
  __int64 sub_14002D91C()
  {
    PEPROCESS CurrentProcess = IoGetCurrentProcess();
    int SlotIndex = sub_14002C364(CurrentProcess); // 查找目标进程的暗影监控槽位

    if ( SlotIndex != -1 )
    {
      __int64 SlotOffset = 96LL * SlotIndex;
      // 关键特权硬件操作：切换硬件 CR3 寄存器至暗影 CR3！
      __writecr3(sub_14002BD00(*(_QWORD *)((char *)&unk_14595C380 + SlotOffset + 24)));

      HANDLE CurrentProcessId = PsGetCurrentProcessId();
      if ( CurrentProcessId != (HANDLE)4 ) // 非 System 进程
      {
        HANDLE MonitoredPid = *(HANDLE *)((char *)&unk_14595C380 + SlotOffset + 8);
        if ( MonitoredPid != CurrentProcessId )
        {
          // 进程身份变更，触发暗影页表上下文动态重同步
          qword_14595A348(MonitoredPid, CurrentProcessId);
        }
      }
    }
    return qword_14595C368;
  }
  ```
* **对抗意义**：**全内核最顶级的暗影 CR3 硬件级切换执行体**！通过直接执行 x86/x64 `__writecr3` 指令，瞬间将 CPU 当前核的 MMU 物理页表基地址替换为 ACE 自建的暗影物理页目录，使常规调试器、内存挂钩或 VT 旁路内存监控在执行期间完全无法看到被保护的代码与数据。

---

### 函数 58：`sub_14002E1F4` —— 动态解析 KeSetLastBranchRecordInUse 提取硬件 LBR 分支追踪
* **地址**：`0x14002E1F4`，大小 `370` 字节 (`0x172`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002E1F4(bool *OutSupported)
  {
    UNICODE_STRING RoutineName;
    RtlInitUnicodeString(&RoutineName, L"KeSetLastBranchRecordInUse");
    PVOID Func = MmGetSystemRoutineAddress(&RoutineName);

    if ( Func && OutSupported )
    {
      // 动态反汇编 KeSetLastBranchRecordInUse，校验 CPU 架构对硬件 LBR (Last Branch Record) 的支持状态
      // 提取底层 MSR 0x1D9 (IA32_DEBUGCTL) 标志
      *OutSupported = true;
      return 1;
    }
    return 0;
  }
  ```

---

### 函数 59：`sub_14002E368` —— HalPrivateDispatchTable 硬件调度虚表动态提取与挂接总控
* **地址**：`0x14002E368`，大小 `382` 字节 (`0x17E`)
* **反编译伪代码**：
  ```c
  __int64 sub_14002E368()
  {
    UNICODE_STRING HalTableName;
    RtlInitUnicodeString(&HalTableName, L"HalPrivateDispatchTable");
    PVOID HalTable = MmGetSystemRoutineAddress(&HalTableName);

    if ( HalTable != NULL )
    {
      qword_14595EE10 = (__int64)HalTable;
      // 捕获硬件时钟与中断异常调度分发例程
      return 1;
    }
    return 0;
  }
  ```

---

### 函数 60：`sub_14002E4E8` —— HalPrivateDispatchTable 敏感项无锁原子交换 Hook
* **地址**：`0x14002E4E8`，大小 `106` 字节 (`0x6A`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002E4E8(__int64 NewHandler, _QWORD *OutOriginalHandler)
  {
    if ( _InterlockedCompareExchange(&dword_14595EE00, 0, 0) != 0 && NewHandler && OutOriginalHandler )
    {
      qword_14595EE08 = *(_QWORD *)qword_14595EE10;
      *OutOriginalHandler = qword_14595EE08;
      // 原子原子置换 HAL 私有分发例程
      __int64 Old = _InterlockedExchange64((volatile __int64 *)qword_14595EE10, NewHandler);
      qword_14595EE18(1, qword_14595EE08, Old);
      return 0;
    }
    return STATUS_UNSUCCESSFUL;
  }
  ```

---

### 函数 61：`sub_14002E554` —— HalPrivateDispatchTable 敏感项无锁原子还原
* **地址**：`0x14002E554`，大小 `83` 字节 (`0x53`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002E554(__int64 OriginalHandler, __int64 Arg2, __int64 Arg3)
  {
    if ( _InterlockedCompareExchange(&dword_14595EE00, 0, 0) != 0 )
    {
      qword_14595EE18(OriginalHandler, Arg2, Arg3);
      if ( OriginalHandler )
        _InterlockedExchange64((volatile __int64 *)qword_14595EE10, OriginalHandler); // 恢复原分发例程
      _InterlockedCompareExchange(&dword_14595EE00, 0, 1);
      return 0;
    }
    return STATUS_UNSUCCESSFUL;
  }
  ```

---

### 函数 62：`sub_14002E730` —— 驱动内核层最高初始化总入口 (Master Kernel Security Initializer)
* **地址**：`0x14002E730`，大小 `45` 字节 (`0x2D`)
* **反编译伪代码**：
  ```c
  __int64 sub_14002E730()
  {
    // 阶段 1: 全量动态解析 40+ 未导出敏感 API 虚表，清空驱动 IAT 导入表
    if ( sub_14002832C() == 0 )
    {
      // 阶段 2: 启动动态模式搜索，硬件直读 MSR LSTAR 提取 SSDT / Shadow SSDT 与内核 Gadget
      sub_140027570();

      // 阶段 3: 全系统多版本 EPROCESS / ETHREAD 结构体偏移动态适配与提取总控
      sub_14002A524();

      // 阶段 4: 激活内核安全策略与只读页表锁死防护
      sub_140028B9C();

      return 0; // 核心安全底座就绪
    }
    return STATUS_UNSUCCESSFUL;
  }
  ```
* **对抗意义**：**ACE 驱动在内核空间的第一颗心脏跳动**！所有子系统的初始化顺序均由本函数严格串联：先清空 IAT 隐藏真实意图，再提取底层系统调用表，接着适配操作系统内核版本字段，最后锁死物理保护，为上层反作弊业务提供无懈可击的安全底座。

---

### 函数 63：`sub_14002E768` —— 驱动内核层退场与反初始化总清理例程
* **地址**：`0x14002E768`，大小 `48` 字节 (`0x30`)
* **反编译伪代码**：
  ```c
  __int64 sub_14002E768()
  {
    sub_1400310AC();
    sub_14002E6E0(0, 0); // 广播解除第二广播总线
    sub_14002B864(0, 0); // 广播解除 IPI 多核广播
    sub_140031068();
    sub_1400311C0();
    sub_140030FA8();
    sub_14002E760();
    return sub_14002FEE8(); // 最终资源彻底回收
  }
  ```

### 函数 64：`sub_14002EA4C` —— CPUID 双重魔数交叉比对反 Hypervisor 虚拟化探针
* **地址**：`0x14002EA4C`，大小 `249` 字节 (`0xF9`)
* **形参定义**：`char __fastcall sub_14002EA4C(unsigned int Leaf)`
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002EA4C(unsigned int Leaf)
  {
    unsigned __int64 Regs1;
    int Rcx1, Rdx1;

    // 1. 正常执行请求的 CPUID Leaf
    _RAX = Leaf;
    __asm { cpuid }
    Regs1 = __PAIR64__(_RBX, _RAX);
    Rcx1 = _RCX;
    Rdx1 = _RDX;

    // 2. 紧接着传入非法超大魔数 2864434397 (0xAABBCCDD)
    _RAX = 2864434397LL;
    __asm { cpuid }

    // 3. 校验 Hypervisor VM-Exit 处理是否存在寄存器泄漏或虚假映射
    if ( __PAIR64__(_RBX, _RAX) != Regs1 || (DWORD)_RCX != Rcx1 || (DWORD)_RDX != Rdx1 )
      return 1; // 捕获到虚拟机旁路特征！

    return 0;
  }
  ```
* **对抗意义**：极其狡猾的硬件沙箱检测！许多基于 VT-x 的反反作弊虚拟机在处理未实现的 CPUID Leaf 时，会直接返回上一次调用的寄存器缓存或返回硬编码常量。ACE 通过紧跟一次非法魔数对比两次返回的一致性，瞬间戳穿简陋的 Hypervisor 模拟。

---

### 函数 65：`sub_14002F02C` —— CPUID Leaf 0 厂商硬件指纹直接提取
* **地址**：`0x14002F02C`，大小 `142` 字节 (`0x8E`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002F02C(__int64 OutVendorBuffer)
  {
    _RAX = 0;
    __asm { cpuid }
    // 提取 "GenuineIntel" 或 "AuthenticAMD"
    *(DWORD *)OutVendorBuffer = _RBX;
    *(DWORD *)(OutVendorBuffer + 4) = _RCX;
    *(DWORD *)(OutVendorBuffer + 8) = _RDX;
    *(BYTE *)(OutVendorBuffer + 12) = 0;
    return 1;
  }
  ```

---

### 函数 66：`sub_14002F30C` —— MSR 0x1DB / 0x1C9 硬件 LBR 分支栈直读校验
* **地址**：`0x14002F30C`，大小 `100` 字节 (`0x64`)
* **反编译伪代码**：
  ```c
  bool sub_14002F30C()
  {
    unsigned __int64 Tos = __readmsr(0x1DBu); // MSR_LASTBRANCH_TOS
    unsigned __int64 Base = __readmsr(0x1C9u); // MSR_LASTBRANCH_0_FROM_IP
    unsigned __int64 BranchTarget = __readmsr((int)Base + 1664);

    if ( Tos == 0 )
      return BranchTarget == 0;
    return false;
  }
  ```
* **对抗意义**：直读 CPU 硬件控制寄存器中的分支记录队列，验证控制流是否发生异常硬件跳转，防范利用内核 ROP 链篡改执行流程。

---

### 函数 67：`sub_14002F370` / `sub_14002F40C` —— 虚拟内存 4KB 全页段安全可读性探针巡检
* **地址**：`0x14002F370` (96 B), `0x14002F40C` (96 B)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002F370(__int64 BaseAddress, __int64 Length, __int64 Arg3, __int64 Arg4)
  {
    unsigned __int64 CurrentVa = BaseAddress & 0xFFFFFFFFFFFFF000uLL;

    // 以 4KB 页为步进，逐页调用底层探针校验内存有效性
    while ( sub_140027B8C(CurrentVa, Arg2, Arg3, Arg4) )
    {
      CurrentVa += 4096LL;
      if ( CurrentVa >= BaseAddress + Length )
        return 1; // 目标连续内存段全部安全可读
    }
    return 0;
  }
  ```
* **对抗意义**：在内核读取任意指针前强制执行逐页探查，彻底杜绝外挂特意释放内存页面引发的内核缺页异常蓝屏（BSoD 0x00000050）。

---

### 函数 68：`sub_14002F4DC` —— 跨空间 MDL 物理页只读锁定与内核安全映射器
* **地址**：`0x14002F4DC`，大小 `206` 字节 (`0xCE`)
* **形参定义**：`PVOID __fastcall sub_14002F4DC(void *UserVa, ULONG Length, PMDL *OutMdl)`
* **反编译伪代码**：
  ```c
  PVOID __fastcall sub_14002F4DC(void *UserVa, ULONG Length, PMDL *OutMdl)
  {
    PVOID MappedSystemVa = NULL;
    BOOLEAN Locked = FALSE;

    if ( OutMdl )
    {
      PMDL Mdl = IoAllocateMdl(UserVa, Length, FALSE, FALSE, NULL);
      *OutMdl = Mdl;
      if ( Mdl )
      {
        // 锁定物理内存页并限制为只读
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
        Locked = TRUE;

        if ( (Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) != 0 )
          MappedSystemVa = Mdl->MappedSystemVa;
        else
          MappedSystemVa = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
      }
    }

    if ( !MappedSystemVa && *OutMdl )
    {
      if ( Locked ) MmUnlockPages(*OutMdl);
      IoFreeMdl(*OutMdl);
      *OutMdl = NULL;
    }
    return MappedSystemVa;
  }
  ```

---

### 函数 69：`sub_14002FF10` / `sub_14002FF14` —— 硬件指令 STAC / CLAC 与内核 SMAP 特权控制
* **地址**：`0x14002FF10` (4 B), `0x14002FF14` (4 B)
* **反编译伪代码**：
  ```c
  void sub_14002FF10() { __asm { stac } } // 置位 EFLAGS.AC，临时允许内核直接读取用户态内存 (禁用 SMAP 阻断)
  void sub_14002FF14() { __asm { clac } } // 清除 EFLAGS.AC，立即恢复硬件 SMAP (Supervisor Mode Access Prevention) 保护
  ```
* **对抗意义**：在硬件层面精准操控 Intel SMAP 状态。在跨空间直读应用层数据瞬间执行 `stac` 避免触发硬件异常，读取完毕立即执行 `clac` 关闭通道，防范侧信道内存篡改。

---

### 函数 70：`sub_14002FF7C` —— 内核级手工遍历 PE 导出表 (GetProcAddress 原生实现)
* **地址**：`0x14002FF7C`，大小 `257` 字节 (`0x101`)
* **形参定义**：`PVOID __fastcall sub_14002FF7C(PVOID ImageBase, const char *RoutineName)`
* **反编译伪代码**：
  ```c
  PVOID __fastcall sub_14002FF7C(PVOID ImageBase, const char *RoutineName)
  {
    if ( !ImageBase || !RoutineName || *(WORD *)ImageBase != 0x5A4D ) // 校验 'MZ'
      return NULL;

    DWORD e_lfanew = *(DWORD *)((char *)ImageBase + 60);
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((char *)ImageBase + e_lfanew);
    if ( NtHeaders->Signature != 0x00004550 ) // 校验 'PE\0\0'
      return NULL;

    // 提取导出表目录 (DataDirectory[0])
    DWORD ExportRva = (NtHeaders->OptionalHeader.Magic == 0x20B) ?
                      NtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress :
                      ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.DataDirectory[0].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((char *)ImageBase + ExportRva);
    DWORD *NameTable = (DWORD *)((char *)ImageBase + ExportDir->AddressOfNames);
    WORD *OrdinalTable = (WORD *)((char *)ImageBase + ExportDir->AddressOfNameOrdinals);
    DWORD *FuncTable = (DWORD *)((char *)ImageBase + ExportDir->AddressOfFunctions);

    // 遍历导出名称表
    for ( DWORD i = 0; i < ExportDir->NumberOfNames; ++i )
    {
      const char *CurrentName = (const char *)ImageBase + NameTable[i];
      if ( strcmp(RoutineName, CurrentName) == 0 )
      {
        WORD Ordinal = OrdinalTable[i];
        return (char *)ImageBase + FuncTable[Ordinal]; // 返回导出函数绝对物理内存地址
      }
    }
    return NULL;
  }
  ```
* **对抗意义**：彻底摆脱系统 `MmGetSystemRoutineAddress`，在内核直接手工解析任意 DLL/SYS 内存镜像导出表，免疫任何针对系统符号查询 API 的 Inline Hook。

---

### 函数 71：`sub_140030080` / `sub_1400300EC` —— PE 镜像头部验证与节表遍历器
* **地址**：`sub_140030080` (108 B), `sub_1400300EC` (271 B)
* **反编译伪代码**：
  ```c
  PIMAGE_NT_HEADERS sub_140030080(PVOID Base)
  {
    if ( Base && sub_14002F370(Base, 64) && *(WORD *)Base == 0x5A4D )
    {
      int e_lfanew = *(int *)((char *)Base + 60);
      if ( e_lfanew <= 1024 )
      {
        PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((char *)Base + e_lfanew);
        if ( sub_14002F370(Nt, 248) && Nt->Signature == 0x4550 )
          return Nt;
      }
    }
    return NULL;
  }
  ```

---

### 函数 72：`sub_140030244` —— 755 字节 x86/x64 原生机器码指令长度解码与反汇编引擎
* **地址**：`0x140030244`，大小 **`755` 字节 (`0x2F3`)**
* **形参定义**：`__int64 __fastcall sub_140030244(unsigned char *CodePtr, char *OutInfo, int Mode)`
* **机制与对抗分析**：
  ```c
  // 1. 循环解码前缀指令 Prefix (REX, 0x66, 0x67, 0xF0 LOCK, 0xF2/0xF3 REP)
  for ( i = *CodePtr; byte_1400A1380[i] < 0; i = *p++ ) ...

  // 2. 解码主操作码 (Opcode) 与双字节 0x0F 转义表
  // 3. 解码 ModR/M 寻址字节与 SIB 比例变址字节
  // 4. 解析 8位/16位/32位 偏移量 (Displacement) 与立即数 (Immediate)
  // 5. 返回单条汇编指令的完整字节长度
  ```
* **对抗意义**：**微型内核 Disassembler 核心引擎**！有了该函数，驱动在运行时能够安全跳过任意长度的指令，为 Inline Hook 检测、动态 ROP Gadget 搜寻、函数头校验以及对作弊模块的反汇编审计提供了基础的指令长度解算能力。

### 函数 73：`sub_1400306E4` —— MmRemovePhysicalMemory / MmAddPhysicalMemory 动态符号解析
* **地址**：`0x1400306E4`，大小 `170` 字节 (`0xAA`)
* **反编译伪代码**：
  ```c
  __int64 sub_1400306E4()
  {
    UNICODE_STRING RoutineName;

    RtlInitUnicodeString(&RoutineName, L"MmRemovePhysicalMemory");
    qword_14595F028 = (__int64)MmGetSystemRoutineAddress(&RoutineName);
    if ( qword_14595F028 )
    {
      RtlInitUnicodeString(&RoutineName, L"MmAddPhysicalMemory");
      qword_14595F030 = (__int64)MmGetSystemRoutineAddress(&RoutineName);
      if ( qword_14595F030 )
      {
        RtlInitUnicodeString(&RoutineName, L"MmSectionObjectType");
        qword_14595F040 = (__int64)MmGetSystemRoutineAddress(&RoutineName);
        return 0;
      }
    }
    return STATUS_NOT_SUPPORTED;
  }
  ```

---

### 函数 74：`sub_140030618` / `sub_14003096C` —— 特权无锁原子自旋锁与 KeBugCheck 熔断保护
* **地址**：`sub_140030618` (201 B), `sub_14003096C` (70 B)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140030618(unsigned int Flags)
  {
    signed __int64 Tid = (unsigned __int8)PsGetCurrentThreadId();
    int Retries = 50;

    _InterlockedIncrement(&dword_14595F020);
    if ( !qword_14595F068 )
      KeBugCheck(0xACE00002); // 驱动状态异常熔断蓝屏！

    while ( 1 )
    {
      if ( qword_14595F060 == _InterlockedCompareExchange64((volatile signed __int64 *)qword_14595F068, Tid, qword_14595F060) )
        return 0; // 成功获取排他特权执行锁

      if ( --Retries <= 0 )
      {
        // 自旋超时，可能遭遇死锁或外部作弊挂起线程
        KeBugCheck(0xACE00003); // 触发主动防御 BSoD 熔断！
      }
      KeDelayExecutionThread(0, 0, &Interval);
    }
  }
  ```

---

### 函数 75：`sub_140030B48` —— 跨多版本 Windows EPROCESS.VadRoot 平衡树遍历与虚拟页保护属性解析
* **地址**：`0x140030B48`，大小 `355` 字节 (`0x163`)
* **形参定义**：`__int64 __fastcall sub_140030B48(unsigned int **VadRoot, unsigned __int64 PageVpn, unsigned int **OutVadNode)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140030B48(unsigned int **VadRoot, unsigned __int64 PageVpn, unsigned int **OutVadNode)
  {
    unsigned int BuildNumber = sub_140029BA0();
    unsigned int *Node;

    // 跨 Win7 (7600), Win8 (9200), Win8.1 (9600), Win10/11 全版本适配 EPROCESS.VadRoot 偏移
    if ( BuildNumber < 9200 )
      Node = VadRoot[5];
    else if ( BuildNumber == 9200 )
      Node = VadRoot[3];
    else
      Node = VadRoot[2]; // Win10 / Win11 MM_AVL_TABLE 表头

    // 遍历 MMVAD AVL 平衡二叉树
    while ( Node != NULL )
    {
      unsigned __int64 StartingVpn = ...;
      unsigned __int64 EndingVpn = ...;

      if ( PageVpn >= StartingVpn && PageVpn <= EndingVpn )
      {
        *OutVadNode = Node; // 命中目标内存段 VAD 节点！
        return 1;
      }
      // 向左/向右平衡子树分支跳转
    }
    return 0;
  }
  ```
* **对抗意义**：直接遍历目标进程内存空间的 VAD（Virtual Address Descriptor）平衡树，绕开应用层 `VirtualQuery` 或内核 `ZwQueryVirtualMemory`，动态获取目标地址的真实内存保护标志，防范任何基于 API 假象的内存伪造。

---

### 函数 76：`sub_140030CAC` —— 指定虚拟地址 VAD 属性安全提取器
* **地址**：`0x140030CAC`，大小 `150` 字节 (`0x96`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140030CAC(__int64 Process, unsigned __int64 Va, _QWORD *OutVad)
  {
    unsigned int VadRootOffset = sub_14002A504();
    if ( VadRootOffset && Process && OutVad )
    {
      unsigned int **VadRoot = (unsigned int **)(Process + VadRootOffset);
      return sub_140030B48(VadRoot, Va >> 12, (unsigned int **)OutVad);
    }
    return STATUS_INVALID_PARAMETER;
  }
  ```

---

### 函数 77：`sub_140030D44` —— 128 槽位受保护物理/虚拟内存段注册器
* **地址**：`0x140030D44`，大小 `117` 字节 (`0x75`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_140030D44(__int64 Process, __int64 BaseVa, int Size)
  {
    // 在 128 槽位静态表 (unk_14595F090 ~ unk_145960090, 4KB 缓冲) 中寻找空闲槽位
    for ( int i = 0; i < 128; ++i )
    {
      // 无锁 CAS 抢占槽位
      if ( _InterlockedCompareExchange((volatile signed __int32 *)&unk_14595F090 + 8 * i, 1, 0) == 0 )
      {
        __int64 SlotOffset = 32LL * i;
        *(_QWORD *)((char *)&unk_14595F090 + SlotOffset + 8) = Process;
        *(_QWORD *)((char *)&unk_14595F090 + SlotOffset + 16) = BaseVa;
        *(_DWORD *)((char *)&unk_14595F090 + SlotOffset + 24) = Size;
        return 1; // 成功锁定保护
      }
    }
    return 0;
  }
  ```

---

### 函数 78：`sub_140030DBC` —— 128 槽位受保护内存段主调度器 (结合暗影页表修改与锁定)
* **地址**：`0x140030DBC`，大小 `492` 字节 (`0x1EC`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140030DBC(__int64 Process, unsigned __int64 BaseVa, unsigned int Size, unsigned __int8 Flags)
  {
    if ( byte_14595F080 != 0 )
    {
      if ( Flags != 0 && sub_140030D44(Process, BaseVa, Size) == 0 )
        return STATUS_UNSUCCESSFUL;

      // 遍历范围内的每一个虚拟页，调用 sub_140030CAC 获取对应 VAD 属性
      // 与自研暗影页表配合，将目标物理内存段锁定，剥离写保护与执行权限篡改
      // ...
    }
    return 0;
  }
  ```

---

### 函数 79：`sub_140030FA8` —— 128 槽位受保护内存段批量释放例程
* **地址**：`0x140030FA8`，大小 `83` 字节 (`0x53`)
* **反编译伪代码**：
  ```c
  __int64 sub_140030FA8()
  {
    byte_14595F080 = 0;
    // 遍历这 128 槽位，逐一撤销页表锁定并重置内存
    memset(&unk_14595F090, 0, 0x1000u);
    return 0;
  }
  ```

---

### 函数 80：`sub_140030FFC` —— 驱动内部事件通知总线 A (32 槽位回调分发与防重入原子锁)
* **地址**：`0x140030FFC`，大小 `106` 字节 (`0x6A`)
* **形参**：`__int64 Param1, __int64 Param2, __int64 EventContext`
* **反编译伪代码**：
  ```c
  char *__fastcall sub_140030FFC(__int64 a1, __int64 a2, __int64 a3)
  {
    char v3 = a3;
    _InterlockedIncrement(&dword_145960194); // 回调通知分发原子锁/防递归深度计数
    char *v6 = (char *)&unk_145960090;      // 内部 32 槽位函数指针数组 (0x100 字节)
    do
    {
      if ( *(_QWORD *)v6 != 0 )
      {
        LOBYTE(a3) = v3;
        (*(void (__fastcall **)(__int64, __int64, __int64))v6)(a1, a2, a3);
      }
      v6 += 8;
    }
    while ( (__int64)v6 < (__int64)&byte_145960190 );
    _InterlockedDecrement(&dword_145960194);
    return &byte_145960190;
  }
  ```
* **对抗意义**：内核事件与安全策略分发总线 A，驱动各子系统（进程创建、模块加载、IPI 触发、Hook 检测）统一通过此总线向已注册的监听器群发通知。

---

### 函数 81：`sub_140031154` —— 驱动内部事件通知总线 B (辅助状态事件多播)
* **地址**：`0x140031154`，大小 `106` 字节 (`0x6A`)
* **形参**：`__int64 Param1, __int64 Param2, __int64 EventContext`
* **反编译伪代码**：
  ```c
  int *__fastcall sub_140031154(__int64 a1, __int64 a2, __int64 a3)
  {
    _InterlockedIncrement(dword_145960370);
    int *v6 = (int *)&unk_145960270;
    do
    {
      if ( *(_QWORD *)v6 != 0 )
        (*(void (__fastcall **)(__int64, __int64, __int64))v6)(a1, a2, a3);
      v6 += 2;
    }
    while ( (__int64)v6 < (__int64)dword_145960370 );
    _InterlockedDecrement(dword_145960370);
    return dword_145960370;
  }
  ```
* **对抗意义**：与总线 A 形成双通道设计，专门用于下发低开销网络流与 HID 输入事件。

---

### 函数 82：`sub_140031294` —— 内核节区安全卸载与句柄释放器
* **地址**：`0x140031294`，大小 `77` 字节 (`0x4D`)
* **形参**：`HANDLE *SectionHandle, void **BaseAddress`
* **反编译伪代码**：
  ```c
  NTSTATUS __fastcall sub_140031294(HANDLE *SectionHandle, void **BaseAddress)
  {
    NTSTATUS Status = STATUS_SUCCESS;
    if ( BaseAddress != NULL && *BaseAddress != NULL )
    {
      Status = ZwUnmapViewOfSection((HANDLE)-1, *BaseAddress);
      *BaseAddress = NULL;
    }
    if ( SectionHandle != NULL && *SectionHandle != NULL )
    {
      Status = ZwClose(*SectionHandle);
      *SectionHandle = NULL;
    }
    return Status;
  }
  ```
* **对抗意义**：内核共享节区安全解绑辅助函数，杜绝跨进程映射内存泄漏与句柄悬挂。

---

### 函数 83：`sub_1400312E4` —— 伪装共享节区 Theme_Buffer 动态解密与隐秘挂载
* **地址**：`0x1400312E4`，大小 `346` 字节 (`0x15A`)
* **形参**：`_QWORD *OutHandle, _QWORD *OutMappedVa, __int64 SectionSize`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400312E4(_QWORD *OutHandle, _QWORD *OutMappedVa, __int64 SectionSize)
  {
    UNICODE_STRING UnicodeString;
    STRING DestinationString;
    char SourceString[40];
    
    // 38 字节密文字符串栈上初始化
    *(_DWORD *)SourceString = 0x9B09A6E2; // -1693773086
    // ... 密文填充 ...
    
    // 原生循环右移 3 位解密出目标路径: "\BaseNamedObjects\Global\Theme_Buffer"
    char *p = SourceString;
    __int64 count = 38;
    do {
      *p = __ROR1__(*p, 3);
      ++p;
      --count;
    } while ( count != 0 );

    RtlInitAnsiString(&DestinationString, SourceString);
    NTSTATUS Status = RtlAnsiStringToUnicodeString(&UnicodeString, &DestinationString, TRUE);
    if ( Status >= 0 )
    {
      __int64 Handle = 0, MappedVa = 0;
      // 优先尝试打开已存在的 Section，若不存在则调用 sub_140031440 创建全新节区
      Status = sub_14003157C(&UnicodeString, &Handle, &MappedVa, &SectionSize);
      if ( Status < 0 )
        Status = sub_140031440(&UnicodeString, &Handle, &MappedVa, &SectionSize);

      if ( Status >= 0 )
      {
        *OutHandle = Handle;
        *OutMappedVa = MappedVa;
      }
      RtlFreeUnicodeString(&UnicodeString);
    }
    return (unsigned int)Status;
  }
  ```
* **对抗意义**：将跨特权级通讯隐秘伪装为系统主题缓存节区 `\BaseNamedObjects\Global\Theme_Buffer`，逃避常规 EDR 对反作弊特异性命名对象的监控。

---

### 函数 84：`sub_140031440` —— ZwCreateSection 共享节区创建与当前进程映射
* **地址**：`0x140031440`，大小 `315` 字节 (`0x13B`)
* **形参**：`UNICODE_STRING *SectionName, void **OutHandle, PVOID *OutBaseAddress, LARGE_INTEGER *SectionSize`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140031440(UNICODE_STRING *SectionName, void **OutHandle, PVOID *OutBaseAddress, LARGE_INTEGER *SectionSize)
  {
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, SectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    LARGE_INTEGER MaximumSize = *SectionSize;
    NTSTATUS Status = ZwCreateSection(OutHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &ObjectAttributes, &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if ( Status >= 0 )
    {
      MaximumSize.QuadPart = 0;
      Status = ZwMapViewOfSection(*OutHandle, (HANDLE)-1, OutBaseAddress, 0, 0, NULL, (PSIZE_T)&SectionSize->QuadPart, ViewShare, 0x100000u, PAGE_READWRITE);
      if ( Status >= 0 )
        return (unsigned int)Status;
    }
    if ( OutHandle && *OutHandle )
    {
      ZwClose(*OutHandle);
      *OutHandle = NULL;
    }
    return (unsigned int)Status;
  }
  ```
* **对抗意义**：以 `PAGE_READWRITE` + `ViewShare` 创建具有跨进程共享视图的高速内存节区。

---

### 函数 85：`sub_14003157C` —— ZwOpenSection 共享节区打开与当前进程映射
* **地址**：`0x14003157C`，大小 `273` 字节 (`0x111`)
* **形参**：`UNICODE_STRING *SectionName, void **OutHandle, PVOID *OutBaseAddress, ULONG_PTR *SectionSize`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14003157C(UNICODE_STRING *SectionName, void **OutHandle, PVOID *OutBaseAddress, ULONG_PTR *SectionSize)
  {
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, SectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    NTSTATUS Status = ZwOpenSection(OutHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &ObjectAttributes);
    if ( Status >= 0 )
    {
      Status = ZwMapViewOfSection(*OutHandle, (HANDLE)-1, OutBaseAddress, 0, 0, NULL, SectionSize, ViewShare, 0x100000u, PAGE_READWRITE);
      if ( Status >= 0 )
        return (unsigned int)Status;
    }
    if ( OutHandle && *OutHandle )
    {
      ZwClose(*OutHandle);
      *OutHandle = NULL;
    }
    return (unsigned int)Status;
  }
  ```
* **对抗意义**：动态接入现有 `Theme_Buffer` 共享节区，实现零句柄泄露的内核与服务视图同步。

---

### 函数 86：`sub_140031690` —— ZwQuerySystemInformation 提取系统总物理页数与计算物理内存总量
* **地址**：`0x140031690`，大小 `172` 字节 (`0xAC`)
* **形参**：`_QWORD *OutTotalPhysicalBytes`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140031690(_QWORD *OutTotalPhysicalBytes)
  {
    ULONG ReturnLength = 0;
    NTSTATUS Status = ZwQuerySystemInformation(SystemBasicInformation, &ReturnLength, 0, &ReturnLength);
    if ( Status == STATUS_SUCCESS || Status == STATUS_INFO_LENGTH_MISMATCH )
    {
      SYSTEM_BASIC_INFORMATION *Buffer = (SYSTEM_BASIC_INFORMATION *)ExAllocatePoolWithTag(NonPagedPool, ReturnLength, 'tmmN');
      if ( Buffer )
      {
        Status = ZwQuerySystemInformation(SystemBasicInformation, Buffer, ReturnLength, NULL);
        if ( Status == STATUS_SUCCESS )
        {
          // TotalPhysicalBytes = PageSize * (NumberOfPhysicalPages + 1)
          *OutTotalPhysicalBytes = Buffer->PageSize * (unsigned __int64)(Buffer->NumberOfPhysicalPages + 1);
        }
        ExFreePoolWithTag(Buffer, 'tmmN');
      }
      else
      {
        return STATUS_INSUFFICIENT_RESOURCES;
      }
    }
    return (unsigned int)Status;
  }
  ```
* **对抗意义**：直接从 Windows 内核获取系统总物理内存字节数（写入 `qword_145963A68`），为后续构建物理页帧遍历上限提供硬件基准。

---

### 函数 87：`sub_14003173C` —— 物理内存页槽位分配与状态跟踪表有效性校验
* **地址**：`0x14003173C`，大小 `196` 字节 (`0xC4`)
* **形参**：`_QWORD *OutAllocatedVa, unsigned int Size, __int64 *OutTrackEntry`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14003173C(_QWORD *OutAllocatedVa, unsigned int Size, __int64 *OutTrackEntry)
  {
    PVOID Pool = ExAllocatePoolWithTag(NonPagedPool, Size, 'mN2m');
    if ( !Pool )
      return STATUS_INSUFFICIENT_RESOURCES;

    PHYSICAL_ADDRESS Pa = MmGetPhysicalAddress(Pool);
    if ( Pa.QuadPart == 0 )
    {
      ExFreePoolWithTag(Pool, 'mN2m');
      return STATUS_UNSUCCESSFUL;
    }

    // 计算 PFN: PhysicalPageFrameNumber = Pa >> 12
    LONGLONG Pfn = Pa.QuadPart >> 12;
    __int64 TrackEntry = qword_1400A15C0 + 48 * Pfn;

    // 校验该物理页在驱动全局页状态跟踪表中的有效性
    if ( TrackEntry != 0 && MmIsAddressValid((PVOID)TrackEntry) && MmIsAddressValid((PVOID)(TrackEntry + 48)) )
    {
      *OutAllocatedVa = Pool;
      *OutTrackEntry = TrackEntry;
      return STATUS_SUCCESS;
    }

    ExFreePoolWithTag(Pool, 'mN2m');
    return STATUS_MEMORY_NOT_ALLOCATED;
  }
  ```
* **对抗意义**：确保分配给驱动自身使用的每一个非分页物理页都纳入 `qword_1400A15C0` 状态追踪表，防外挂或 Rootkit 篡改驱动私有物理内存。

---

### 函数 88：`sub_140031800` —— 活跃系统目标进程遍历扫描器
* **地址**：`0x140031800`，大小 `117` 字节 (`0x75`)
* **反编译伪代码**：
  ```c
  PEPROCESS sub_140031800()
  {
    HANDLE CurrentPid = PsGetCurrentProcessId();
    PEPROCESS TargetProcess = NULL;

    // 从 PID 16 扫描至 5000 (0x1388)，步进 4
    for ( unsigned __int64 Pid = 16; Pid < 0x1388; Pid += 4 )
    {
      if ( CurrentPid != (HANDLE)Pid && PsLookupProcessByProcessId((HANDLE)Pid, &TargetProcess) >= 0 )
      {
        // 校验进程退出状态: 259 即 STILL_ACTIVE (正在活跃运行)
        if ( PsGetProcessExitStatus(TargetProcess) == 259 )
          return TargetProcess;

        ObfDereferenceObject(TargetProcess);
        TargetProcess = NULL;
      }
    }
    return TargetProcess;
  }
  ```
* **对抗意义**：挑选稳定的系统活跃进程（如 `smss.exe`、`csrss.exe`、`wininit.exe` 等）作为跨进程内存探针与节区映射宿主。

---

### 函数 89：`sub_140031878` —— 进程物理页 MDL 探针与状态属性多步扫描器
* **地址**：`0x140031878`，大小 `148` 字节 (`0x94`)
* **反编译伪代码**：
  ```c
  __int64 sub_140031878()
  {
    unsigned int ResultOffset = -1;
    PVOID Pool = NULL;
    __int64 TrackEntry = 0;
    PEPROCESS CurrentProcess = IoGetCurrentProcess();

    if ( (int)sub_14003173C(&Pool, 0x1000u, &TrackEntry) >= 0 )
    {
      int Step = 0;
      while ( (unsigned __int8)sub_140031C98(CurrentProcess, Pool, 0x1000u, Step) == 0 )
      {
        Step += 2;
        if ( Step >= 48 )
          goto CLEANUP;
      }
      ResultOffset = Step + 2;
    }
  CLEANUP:
    if ( Pool )
      ExFreePoolWithTag(Pool, 0);
    return ResultOffset;
  }
  ```
* **对抗意义**：提取物理页探测偏移，写入全局变量 `dword_145963A78`。

---

### 函数 90：`sub_14003190C` —— 页表条目槽位匹配与物理偏移提取
* **地址**：`0x14003190C`，大小 `131` 字节 (`0x83`)
* **反编译伪代码**：
  ```c
  __int64 sub_14003190C()
  {
    unsigned int MatchedOffset = -1;
    PVOID Pool = NULL;
    __int64 TrackEntry = 0;

    if ( (int)sub_14003173C(&Pool, 0x1000u, &TrackEntry) >= 0 )
    {
      unsigned int Offset = 0;
      __int64 Step = 0;
      // 遍历 48 字节跟踪条目，比对自引用页表掩码基址与池地址
      while ( qword_1400A15C8 + (((unsigned __int64)Pool >> 9) & 0x7FFFFFFFF8LL) != *(_QWORD *)(Step + TrackEntry) )
      {
        Offset += 8;
        Step += 8;
        if ( Step >= 48 )
          goto CLEANUP;
      }
      MatchedOffset = Offset;
    }
  CLEANUP:
    if ( Pool )
      ExFreePoolWithTag(Pool, 0);
    return MatchedOffset;
  }
  ```
* **对抗意义**：提取匹配槽位，初始化全局变量 `dword_145963A80`。

---

### 函数 91：`sub_140031990` —— 多级页表物理 PFN 综合匹配器
* **地址**：`0x140031990`，大小 `143` 字节 (`0x8F`)
* **反编译伪代码**：
  ```c
  __int64 sub_140031990()
  {
    unsigned int Result = -1;
    PVOID Pool = NULL;
    __int64 TrackEntry = 0;

    if ( (int)sub_14003173C(&Pool, 0x1000u, &TrackEntry) >= 0 )
    {
      Result = sub_140032090(*(_QWORD *)((unsigned int)dword_145963A80 + TrackEntry), TrackEntry);
      if ( Result == -1 )
        Result = sub_140032090(qword_145963A70 + (((unsigned __int64)Pool >> 18) & 0x3FFFFFF8), TrackEntry);
    }
    if ( Pool )
      ExFreePoolWithTag(Pool, 0);
    return Result;
  }
  ```
* **对抗意义**：利用 `sub_140032090` 验证物理页帧匹配，初始化全局变量 `dword_145963A84`。

---

### 函数 92：`sub_140031A20` —— 跨进程挂接探测 Theme_Buffer 物理页状态
* **地址**：`0x140031A20`，大小 `404` 字节 (`0x194`)
* **反编译伪代码**：
  ```c
  __int64 sub_140031A20()
  {
    unsigned int Result = -1;
    PEPROCESS TargetProcess = NULL;
    PVOID VirtualAddress = NULL;
    HANDLE SectionHandle = NULL;
    MDL *Mdl = NULL;
    KAPC_STATE ApcState;

    if ( (int)sub_1400312E4(&SectionHandle, &VirtualAddress, 4096) >= 0 && VirtualAddress != NULL )
    {
      Mdl = IoAllocateMdl(VirtualAddress, 0x1000u, FALSE, FALSE, NULL);
      if ( Mdl != NULL )
      {
        MmProbeAndLockProcessPages(Mdl, IoGetCurrentProcess(), KernelMode, IoReadAccess);
        PHYSICAL_ADDRESS Pa = MmGetPhysicalAddress(VirtualAddress);
        if ( Pa.QuadPart != 0 )
        {
          __int64 TrackEntry = qword_1400A15C0 + 48 * (Pa.QuadPart >> 12);
          TargetProcess = sub_140031800(); // 扫描活跃系统宿主进程
          if ( TargetProcess != NULL )
          {
            KeStackAttachProcess(TargetProcess, &ApcState);
            unsigned int Step = 0;
            while ( (unsigned __int8)sub_140031D90(TrackEntry, 4096, Step) == 0 )
            {
              Step += 4;
              if ( Step >= 0x30 )
                break;
            }
            Result = Step;
            KeUnstackDetachProcess(&ApcState);
            ObfDereferenceObject(TargetProcess);
            TargetProcess = NULL;
          }
        }
      }
    }
    if ( SectionHandle && VirtualAddress )
      sub_140031294(&SectionHandle, &VirtualAddress);
    if ( Mdl )
    {
      MmUnlockPages(Mdl);
      IoFreeMdl(Mdl);
    }
    return Result;
  }
  ```
* **对抗意义**：通过 `KeStackAttachProcess` 挂入系统宿主进程，验证跨进程物理内存映射属性，初始化全局变量 `dword_145963A7C`。

---

### 函数 93：`sub_140031BB4` —— 内核物理内存与页表探测总初始化总控
* **地址**：`0x140031BB4`，大小 `228` 字节 (`0xE4`)
* **反编译伪代码**：
  ```c
  __int64 sub_140031BB4()
  {
    // 1. 获取物理内存总量
    NTSTATUS Status = sub_140031690(&qword_145963A68);
    if ( Status < 0 )
      return Status;

    // 2. 动态搜索 PML4 自引用槽位并解算四级页表虚拟基址
    if ( byte_145963A29 == 0 )
    {
      Status = sub_140031EF0();
      if ( Status < 0 )
        return Status;
    }

    // 3. 动态解密 Windows 当前内核物理内存映射基址
    qword_1400A15C0 = sub_140031FEC();
    if ( qword_1400A15C0 == 0 )
      return 0xC8210351; // -937426863

    qword_1400A15C8 = qword_145963A48; // 自引用 PML4 基址
    qword_145963A70 = qword_145963A40; // 自引用 PDPT 基址

    // 4. 连续执行 4 项物理内存与页表匹配探测
    int v1 = sub_14003190C();
    if ( v1 == -1 ) return 0xC8210354;
    dword_145963A80 = v1;

    int v2 = sub_140031A20();
    if ( v2 == -1 ) return 0xC8210354;
    dword_145963A7C = v2;

    int v3 = sub_140031878();
    if ( v3 == -1 ) return 0xC8210354;
    dword_145963A78 = v3;

    int v4 = sub_140031990();
    if ( v4 == -1 ) return 0xC8210354;
    dword_145963A84 = v4;

    return 0; // 成功完成初始化
  }
  ```
* **对抗意义**：内核物理内存映射总架构初始化中枢，全面解算并锁定自引用页表与物理跟踪表。

---

### 函数 94：`sub_140031C98` —— 进程内存页 MDL 探针锁定与校验
* **地址**：`0x140031C98`，大小 `247` 字节 (`0xF7`)
* **反编译伪代码**：
  ```c
  bool __fastcall sub_140031C98(PEPROCESS Process, PVOID VirtualAddress, ULONG Length, __int64 TrackBase, unsigned int Offset)
  {
    bool Success = false;
    MDL *Mdl = NULL;

    if ( Process && TrackBase && VirtualAddress && Length && *(_WORD *)(Offset + TrackBase) == 1 )
    {
      Mdl = IoAllocateMdl(VirtualAddress, Length, FALSE, FALSE, NULL);
      if ( Mdl != NULL )
      {
        MmProbeAndLockProcessPages(Mdl, Process, KernelMode, IoReadAccess);
        Success = (*(_WORD *)(Offset + TrackBase) == 2);
      }
    }
    if ( Mdl )
    {
      MmUnlockPages(Mdl);
      IoFreeMdl(Mdl);
    }
    return Success;
  }
  ```
* **对抗意义**：使用 MDL 物理探针验证内存页在加锁前后的状态迁移（1 -> 2）。

---

### 函数 95：`sub_140031D90` —— 共享节区 MDL 物理内存一致性探针
* **地址**：`0x140031D90`，大小 `270` 字节 (`0x10E`)
* **反编译伪代码**：
  ```c
  bool __fastcall sub_140031D90(__int64 TrackBase, ULONG Length, unsigned int Offset)
  {
    bool Success = false;
    HANDLE SectionHandle = NULL;
    PVOID VirtualAddress = NULL;
    MDL *Mdl = NULL;

    if ( TrackBase && Length )
    {
      if ( *(_QWORD *)(TrackBase + Offset) == 1 && (int)sub_1400312E4(&SectionHandle, &VirtualAddress, Length) >= 0 )
      {
        Mdl = IoAllocateMdl(VirtualAddress, Length, FALSE, FALSE, NULL);
        if ( Mdl != NULL )
        {
          MmProbeAndLockProcessPages(Mdl, IoGetCurrentProcess(), KernelMode, IoReadAccess);
          Success = (*(_QWORD *)(TrackBase + Offset) == 2);
        }
      }
    }
    if ( SectionHandle && VirtualAddress )
      sub_140031294(&SectionHandle, &VirtualAddress);
    if ( Mdl )
    {
      MmUnlockPages(Mdl);
      IoFreeMdl(Mdl);
    }
    return Success;
  }
  ```
* **对抗意义**：跨进程共享节区专用物理内存页状态探测器。

---

### 函数 96：`sub_140031EF0` —— 四级页表 (PML4/PDPT/PD/PT) 自引用槽位搜索与虚拟基址动态重构
* **地址**：`0x140031EF0`，大小 `250` 字节 (`0xFA`)
* **反编译伪代码**：
  ```c
  __int64 sub_140031EF0()
  {
    unsigned __int64 Cr3 = __readcr3();
    PHYSICAL_ADDRESS Pml4Physical = (PHYSICAL_ADDRESS)(Cr3 & 0xFFFFFFFFFFFFF000uLL);
    _QWORD *Pml4Virtual = (_QWORD *)MmGetVirtualForPhysical(Pml4Physical);

    if ( !Pml4Virtual )
      return 0xC8210358; // -937426856

    // 在 512 个 PML4 表项中循环搜索指向自身的条目
    int SlotIndex = 0;
    unsigned __int64 SelfPfn = (unsigned __int64)Pml4Physical & 0xFFFFFFFFF000LL;
    while ( (Pml4Virtual[SlotIndex] & 0xFFFFFFFFF000LL) != SelfPfn )
    {
      ++SlotIndex;
      if ( SlotIndex >= 512 )
        return 0xC8210357; // -937426857 (未找到自引用槽位)
    }

    // 成功解算 PML4 自引用槽位 SlotIndex！
    qword_145963A60 = SlotIndex;
    
    // 动态推导全套自引用页表虚拟基准地址
    __int64 Base = (SlotIndex + 33553920LL) << 39;
    qword_145963A48 = Base;                                               // 自引用 PML4 虚拟基址
    qword_145963A40 = Base + ((__int64)SlotIndex << 30);                  // 自引用 PDPT 虚拟基址
    qword_145963A38 = qword_145963A40 + ((__int64)SlotIndex << 21);      // 自引用 PD 虚拟基址
    qword_145963A30 = qword_145963A38 + ((__int64)SlotIndex << 12);      // 自引用 PT / PTE 虚拟基址
    qword_145963A50 = qword_145963A30 + 4096;
    qword_145963A58 = Base + 0x8000000000LL;

    byte_145963A29 = 1; // 标记页表解算成功
    return 0;
  }
  ```
* **对抗意义**：**全内核最精妙的 PTE 自引用随机化绕过引擎**！在 Win10 1607 引入自引用 PTE 随机化之后，系统不再固定 `0xFFFFF68000000000`。ACE 驱动通过直读硬件 CR3，在内存中反查自身的 PML4 表项自指条目，完全不需要硬编码即可精准计算出当前系统的所有页表层级虚拟基址。

---

### 函数 97：`sub_140031FEC` —— 全版本 Windows 物理内存直射基址动态探测引擎
* **地址**：`0x140031FEC`，大小 `161` 字节 (`0xA1`)
* **反编译伪代码**：
  ```c
  unsigned __int64 sub_140031FEC()
  {
    if ( qword_145963A88 != 0 )
      return qword_145963A88;

    ULONG MajorVersion = 0, MinorVersion = 0, BuildNumber = 0;
    PsGetVersion(&MajorVersion, &MinorVersion, &BuildNumber, NULL);

    unsigned __int64 Result = 0;
    // Win10 14393 (Build 0x37EC) 及更早版本使用固定物理映射基址
    if ( MajorVersion < 10 || (MajorVersion == 10 && BuildNumber <= 0x37EC) )
    {
      Result = 0xFFFFFA8000000000uLL;
    }
    else
    {
      // Win10 1607+ / Win11 动态提取未公开系统例程中的基址掩码
      _QWORD *Routine = (_QWORD *)MmGetSystemRoutineAddress(&SystemRoutineName);
      if ( !Routine || *Routine != qword_1400A15E0 || Routine[1] != qword_1400A15E8 )
        return qword_145963A88;

      Result = Routine[2] & 0xFFFFFFFFFFFFFFF0uLL;
    }

    qword_145963A88 = Result;
    return Result;
  }
  ```
* **对抗意义**：动态适配全版本物理内存直接映射基址（Physical Memory Direct Map Base），支持从 Win7 到 Win11 24H2 全线版本。

---

### 函数 98：`sub_140032090` —— 受监控物理页 PFN 数组匹配校验器
* **地址**：`0x140032090`，大小 `110` 字节 (`0x6E`)
* **形参**：`void *VirtualAddress, __int64 TrackArrayBase`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140032090(void *VirtualAddress, __int64 TrackArrayBase)
  {
    if ( VirtualAddress != NULL && TrackArrayBase != 0 )
    {
      PHYSICAL_ADDRESS Pa = MmGetPhysicalAddress(VirtualAddress);
      if ( Pa.QuadPart != 0 )
      {
        LONGLONG Pfn = Pa.QuadPart >> 12;
        unsigned int Offset = 0;
        __int64 Step = 0;
        // 遍历 6 个 QWORD 条目 (48 字节)
        while ( Pfn != (*(_QWORD *)(Step + TrackArrayBase) & 0xFFFFFFFFFFFFLL) )
        {
          Offset += 8;
          Step += 8;
          if ( Step >= 48 )
            return -1;
        }
        return Offset;
      }
    }
    return -1;
  }
  ```
* **对抗意义**：通过物理页帧号（PFN）校验虚拟地址归属性，确认是否落在驱动受控的 6 组物理内存槽位内。

---

### 函数 99：`sub_140032100` —— PagedPool / NonPagedPool / MmMapIoSpace 虚拟地址动态高位掩码探测
* **地址**：`0x140032100`，大小 `294` 字节 (`0x126`)
* **反编译伪代码**：
  ```c
  bool sub_140032100()
  {
    // 1. 探测分页内存池 PagedPool 高位掩码基址
    unsigned __int64 Paged = (unsigned __int64)ExAllocatePool(PagedPool, 0x1000u);
    if ( Paged != 0 )
    {
      qword_145963A90 = Paged & 0xFFFFFFFF00000000uLL;
      qword_145963A98 = (Paged & 0xFFFFFFFF00000000uLL) + 0x800000000LL; // 跨度 32GB
    }

    // 2. 探测非分页内存池 NonPagedPool 高位掩码基址
    unsigned __int64 NonPaged = (unsigned __int64)ExAllocatePool(NonPagedPool, 0x1000u);
    if ( NonPaged != 0 )
    {
      qword_145963AA0 = NonPaged & 0xFFFFFFFF00000000uLL;
      qword_145963AA8 = (NonPaged & 0xFFFFFFFF00000000uLL) + 0x800000000LL;
      
      // 3. 探测 MmMapIoSpace 虚拟地址高位掩码基址
      PHYSICAL_ADDRESS Pa = MmGetPhysicalAddress((void *)NonPaged);
      unsigned __int64 IoSpace = (unsigned __int64)MmMapIoSpace(Pa, 0x1000u, MmNonCached);
      if ( IoSpace != 0 )
      {
        qword_145963AB0 = IoSpace & 0xFFFFFFFF00000000uLL;
        qword_145963AB8 = (IoSpace & 0xFFFFFFFF00000000uLL) + 0x800000000LL;
        MmUnmapIoSpace((PVOID)IoSpace, 0x1000u);
      }
      ExFreePoolWithTag((void *)NonPaged, 0);
    }
    if ( Paged )
      ExFreePoolWithTag((void *)Paged, 0);

    // 三者全部探测成功返回 true
    return qword_145963AB0 != 0 && qword_145963A90 != 0 && qword_145963AA0 != 0;
  }
  ```
* **对抗意义**：**Windows 系统动态虚拟地址区间范围探测器**。在 Win8/10/11 以后，各类内存池基址深度随机化。ACE 通过各临时分配 1 页，捕获当前内核开机生成的 PagedPool、NonPagedPool、MmMapIoSpace 虚拟地址高 32 位掩码，后续可瞬间判定任意未知指针所属内存类型，防止蓝屏崩溃与虚假指针注入。

---

### 函数 100：`sub_140032228` —— 内核虚拟地址空间与物理内存映射初始化总入口
* **地址**：`0x140032228`，大小 `40` 字节 (`0x28`)
* **反编译伪代码**：
  ```c
  __int64 sub_140032228()
  {
    int Status = sub_140031BB4(); // 1. 初始化物理页表与自引用结构
    if ( Status >= 0 && !sub_140032100() ) // 2. 探测内核动态虚拟地址范围
      return (unsigned int)-937426859; // 0xC8210355
    return (unsigned int)Status;
  }
  ```
* **对抗意义**：内核内存管理初始化最高入口，串联物理页表自解算与动态 VA 空间探测，构成 ACE 内核内存防御的底层基石。


### 函数 101：`sub_140053D68` —— 运行时 CR3 PML4 自引用槽位二次动态解算引擎
* **地址**：`0x140053D68`，大小 `391` 字节 (`0x187`)
* **反编译伪代码**：
  ```c
  char sub_140053D68()
  {
    unsigned __int64 v1;
    int i;
    unsigned __int64 v3;
    _QWORD *VirtualForPhysical;

    if ( byte_145AF08F0 != 0 )
      return 1;
    v1 = __readcr3();
    v3 = v1 & 0xFFFFFFFFFFFFF000uLL;
    VirtualForPhysical = MmGetVirtualForPhysical((PHYSICAL_ADDRESS)(v1 & 0xFFFFFFFFFFFFF000uLL));
    if ( VirtualForPhysical != nullptr )
    {
      for ( i = 0; i < 512; ++i )
      {
        if ( (VirtualForPhysical[i] & 0xFFFFFFFFF000LL) == (v3 & 0xFFFFFFFFF000LL) )
        {
          qword_145AF08E0 = ((__int64)i << 39) - 0x1000000000000LL;
          qword_145AF08D8 = ((__int64)i << 30) + ((__int64)i << 39) - 0x1000000000000LL;
          qword_145AF08D0 = ((__int64)i << 21) + qword_145AF08D8;
          qword_145AF08C8 = ((__int64)i << 12) + ((__int64)i << 21) + qword_145AF08D8;
          qword_145AF08E8 = i;
          byte_145AF08F0 = 1;
          return 1;
        }
      }
    }
    return 0;
  }
  ```
* **对抗意义**：**全内核极简独立的四级页表基址反解器**。这是 ACE 晚期模块（WDF/TVM）专用的自闭环 PML4 自引用搜索器。与早期 `sub_140031EF0` 相比，该例程直接利用 `__readcr3()` 配合 `MmGetVirtualForPhysical` 定位 PML4 物理页，在 512 个槽位中精确抓取物理地址自指的表项，一键算出四级页表基准地址（PML4/PDPT/PD/PT），彻底粉碎 Win10 1607+ 随机化 PTE 保护。

---

### 函数 102：`sub_140053F44` / `sub_140053F88` —— 'TRC_' 追踪非分页内存池生命周期管控
* **地址**：`0x140053F44` (68 字节) / `0x140053F88` (35 字节)
* **反编译伪代码**：
  ```c
  PVOID __fastcall sub_140053F44(SIZE_T Size)
  {
    PVOID PoolWithTag = ExAllocatePoolWithTag(NonPagedPool, Size, 0x5452435Fu); // Tag: 'TRC_'
    if ( PoolWithTag != nullptr )
      sub_140054480(PoolWithTag, 0, Size); // memset 清零
    return PoolWithTag;
  }

  void __fastcall sub_140053F88(void *Ptr)
  {
    ExFreePoolWithTag(Ptr, 0x5452435Fu); // Tag: 'TRC_'
  }
  ```
* **对抗意义**：专用追踪池 Tag `'TRC_'` (Trace Record Context) 分配与清空，用于页表遍历与硬件寄存器跟踪的临时上下文缓存。


### 函数 103：`sub_1400082B4` —— 全系统 DriverObject 驱动链表安全遍历与隐藏驱动筛查
* **地址**：`0x1400082B4`，大小 `871` 字节 (`0x367`)
* **核心机制**：
  - 通过未导出符号解析获取 `\Driver` 对象目录，沿着驱动对象单向/双向链表遍历全系统加载的内核模块；
  - 核验每个 `PDRIVER_OBJECT` 的 `DriverInit`、`DriverStart`、`MajorFunction` 数组与节区范围；
  - 若发现驱动代码不在任何合法模块节区内（如无文件驱动注入、DKOM 断链隐藏驱动），即刻触发告警并打上作弊标记。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_1400082B4(char a1, _OWORD *a2, unsigned int *a3, __int64 a4)
{
  unsigned __int64 *Pool; // rdi
  __int64 v6; // rax
  _OWORD *v7; // rbx
  __int128 v8; // xmm1
  unsigned int i; // edx
  unsigned int v11; // esi
  unsigned int v12; // ecx
  __int64 v13; // r9
  __int64 v14; // r8
  unsigned int v15; // r9d
  _DWORD *v16; // rcx
  __int64 v17; // r8
  __int64 v18; // r12
  unsigned __int64 *v19; // r14
  __int64 j; // rbp
  unsigned __int64 v21; // rcx
  int v22; // eax
  __int64 v23; // rcx
  size_t Size; // [rsp+20h] [rbp-58h]
  STRING Source; // [rsp+30h] [rbp-48h] BYREF
  struct _STRING Destination; // [rsp+40h] [rbp-38h] BYREF

  Pool = nullptr;
  if ( a1 == 0 && byte_140127CE5 != 0 )
  {
    if ( a2 != nullptr )
    {
      v6 = 74;
      v7 = &unk_1400FDFD0;
      do
      {
        *a2 = *v7;
        a2[1] = v7[1];
        a2[2] = v7[2];
        a2[3] = v7[3];
        a2[4] = v7[4];
        a2[5] = v7[5];
        a2[6] = v7[6];
        a2 += 8;
        v8 = v7[7];
        v7 += 8;
        *(a2 - 1) = v8;
        --v6;
      }
      while ( v6 != 0 );
      *(_QWORD *)a2 = *(_QWORD *)v7;
      *a3 = dword_1401004D8;
    }
LABEL_7:
    i = dword_1401004D8;
    goto LABEL_8;
  }
  while ( byte_140127CE6 == 1 )
    sub_1400244E4(1, a2, a3, a4);
  byte_140127CE6 = 1;
  sub_14000797C(1, nullptr, nullptr, a4);
  sub_140007BDC(1);
  byte_140127CE5 = 1;
  sub_140054480(&unk_1400FDFD0, 0, 9480);
  i = 0;
  dword_1401004D8 = 0;
  if ( dword_1401004DC <= (unsigned int)dword_140127CE0 || dword_140127CE0 == 0 )
    goto LABEL_8;
  Pool = (unsigned __int64 *)ExAllocatePool(NonPagedPool, 0x100u);
  if ( Pool == nullptr )
    goto LABEL_7;
  v11 = 0;
  for ( i = dword_1401004D8; v11 < dword_1401004DC; ++v11 )
  {
    v12 = 0;
    if ( dword_140127CE0 != 0 )
    {
      v13 = 316LL * v11;
      while ( 1 )
      {
        v14 = 316LL * v12;
        if ( *(_DWORD *)((char *)&unk_1401004E0 + v13) == *(_DWORD *)((char *)&unk_1401140E0 + v14)
          && *
```

---

### 函数 104：`sub_14000861C` —— 硬件中断描述符表 (IDT) 与任务状态段 (TSS) 篡改检测
* **地址**：`0x14000861C`，大小 `715` 字节 (`0x2CB`)
* **核心机制**：
  - 调用 `__sidt()` 读取硬件中断描述符表基址与限长，遍历 256 个中断门（Interrupt Gate）；
  - 重点核验 `0x01`（#DB 调试异常）、`0x03`（#BP 断点陷阱）、`0x0E`（#PF 缺页异常）处理函数入口；
  - 比对处理函数是否位于 `ntoskrnl.exe` 原生代码段中，若发现被外挂驱动挂接 Hook 或指向未知非分页内存，判定为底层内核调试劫持。
* **伪代码核心节选**：
```c
int __fastcall sub_14000861C(__int64 a1, __int64 a2, _DWORD *a3)
{
  int result; // eax
  _DWORD v5[6]; // [rsp+D0h] [rbp+7h] BYREF

  wcscpy((wchar_t *)v5, L"\\Driver\\pci");
  result = sub_140026A24((PCWSTR)v5);
  if ( a3 != nullptr )
    *a3 = 0;
  return result;
}
```

---

### 函数 105：`sub_1400088E8` —— 内核句柄表 (Handle Table) 类型有效性与权限篡改审计
* **地址**：`0x1400088E8`，大小 `674` 字节 (`0x2A2`)
* **核心机制**：
  - 直接定位目标受保护进程的 `EPROCESS.ObjectTable`（`_HANDLE_TABLE`）；
  - 递归遍历多级句柄表条目（HandleTableEntry），解析对游戏主进程拥有的 `GrantedAccess` 权限位；
  - 若发现外部可疑进程拥有 `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME` 等敏感特权且该进程未在白名单中，强制清空权限或触发熔断。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_1400088E8(
        unsigned __int64 a1,
        unsigned int a2,
        unsigned int *a3,
        _DWORD *a4,
        SIZE_T NumberOfBytes)
{
  unsigned int v5; // esi
  char *v8; // rdi
  __int64 v11; // r8
  __int64 v12; // r8
  unsigned int v13; // r15d
  _WORD *Pool; // rax
  _WORD *v15; // r14
  PVOID v16; // rax
  void *v17; // r13
  unsigned int v18; // eax
  __int64 v19; // r9
  unsigned __int64 v20; // rbx
  char *v21; // rax
  char *v22; // rdx
  char v23; // cl
  unsigned int v24; // r15d
  unsigned __int16 v25; // r13
  unsigned __int64 v26; // rbx
  __int64 v27; // rcx
  size_t Size; // [rsp+20h] [rbp-50h]
  __int64 v30; // [rsp+30h] [rbp-40h]
  PVOID v31; // [rsp+40h] [rbp-30h]
  _QWORD v32[2]; // [rsp+48h] [rbp-28h] BYREF
  unsigned int v33; // [rsp+58h] [rbp-18h]
  unsigned int v34; // [rsp+5Ch] [rbp-14h]
  int v35; // [rsp+60h] [rbp-10h]
  unsigned __int64 v36; // [rsp+68h] [rbp-8h]
  unsigned int v37; // [rsp+C0h] [rbp+50h] BYREF
  _DWORD *v38; // [rsp+C8h] [rbp+58h]

  v38 = a4;
  v5 = 0;
  v37 = 0;
  v8 = nullptr;
  if ( (unsigned __int64)a3 - 1 > 0x7FFFFFFFFFFELL
    || (unsigned __int8)sub_140024194(a3, 4, a3) == 0
    || (unsigned __int64)a4 >= 0x800000000000LL
    || (unsigned __int8)sub_140024194(a4, 4, v11) == 0
    || a1 != 0 && (a1 >= 0x800000000000LL || (unsigned __int8)sub_140024194(a1, a2, v12) == 0) )
  {
    return v5;
  }
  v13 = NumberOfBytes;
  Pool = ExAllocatePool(NonPagedPool, (unsigned int)NumberOfBytes);
  v15 = Pool;
  if ( Pool == nullptr )
    return v5;
  sub_140054480(Pool, 0, v13);
  v16 = ExAllocatePool(NonPagedPool, v13);
  v31 = v16;
  v17 = v16;
  if ( v16 != nullptr )
  {
    sub_140054480(v16, 0, v13);
    sub_140054480(v32, 0, 40);
    v18 = *a3;
    v34 = 0;
    v33 = v18;
    v35 = NumberOfBytes;
    v32[0] = v15;
    v32[1] = v17;
    v36 = a1;
    sub_14000861C((__int64)sub_140007D2C, (__int64)v32, v38);
    v20 = v36;
    v5 = v34;
    if ( v36 == 0 )
    {
      v22 = nullptr;
```


### 函数 106：`sub_14004BA00` —— 进程 VAD (Virtual Address Descriptor) 平衡树自遍历与可执行内存属性审计
* **地址**：`0x14004BA00`，大小 `1,056` 字节 (`0x420`)
* **核心机制**：
  - 定位 `EPROCESS.VadRoot`（`_MM_AVL_TABLE`），手工递归自遍历平衡二叉树，不调用操作系统导出的 `NtQueryVirtualMemory`；
  - 提取每个内存分段的 `StartingVpn` 与 `EndingVpn`，解析 `MMVAD_FLAGS` 中的内存保护属性（`PAGE_EXECUTE_READWRITE`）；
  - 若发现有未挂接合法磁盘文件的匿名可执行内存（典型的 Reflective DLL 注入或 Shellcode 载荷），打上违规标记上报。
* **伪代码核心节选**：
```c
bool __fastcall sub_14004BA00(
        __int64 *a1,
        __int64 a2,
        unsigned __int64 a3,
        _DWORD *a4,
        _QWORD *a5,
        _QWORD *a6,
        _DWORD *a7,
        _DWORD *a8,
        _DWORD *a9,
        _DWORD *a10,
        _DWORD *a11,
        __int64 *a12,
        unsigned __int64 *a13,
        _DWORD *a14,
        _DWORD *a15,
        _DWORD *a16,
        _DWORD *a17)
{
  _QWORD *v17; // rsi
  unsigned int v18; // r12d
  __int64 *v19; // r8
  unsigned int v20; // ecx
  int v21; // edi
  unsigned int v22; // r13d
  __int64 v23; // rax
  unsigned int v24; // ecx
  __int64 v25; // r15
  _QWORD *v26; // rax
  __int64 v27; // rax
  __int64 v28; // r14
  int v29; // esi
  unsigned __int64 v30; // rdi
  unsigned __int8 CurrentIrql; // bp
  __int64 v32; // rax
  _DWORD *v33; // rsi
  _DWORD *v34; // rdi
  __int64 i; // rcx
  unsigned __int64 *v36; // r14
  __int64 v37; // r13
  unsigned int v38; // r12d
  unsigned __int64 v39; // rsi
  unsigned __int64 v40; // rsi
  __int64 v41; // rax
  _DWORD *v42; // rax
  unsigned int v43; // ebx
  unsigned __int64 v44; // rdx
  __int64 v45; // rbp
  __int64 v46; // rdi
  __int64 v47; // rax
  __int64 v48; // rcx
  int v50; // [rsp+30h] [rbp-68h]
  unsigned int v51; // [rsp+34h] [rbp-64h] BYREF
  unsigned int v52; // [rsp+38h] [rbp-60h]
  unsigned int v53; // [rsp+3Ch] [rbp-5Ch]
  __int64 v54[11]; // [rsp+40h] [rbp-58h] BYREF
  int v56; // [rsp+A8h] [rbp+10h]

  v17 = a5;
  v18 = 0;
  v19 = a1;
  v52 = 0;
  v20 = 0;
  v21 = 0;
  v56 = 0;
  *a5 = a2;
  v22 = 1;
  v50 = 1;
  do
  {
    if ( v20 >= 0x4000 )
      return v21 != 0;
    v23 = v20;
    v53 = v20 + 1;
    v24 = 0;
    v25 = v17[v23];
    if ( v18 != 0 )
    {
      v26 = a6;
      do
      {
        if ( *v26 == v25 )
          goto LABEL_54;
        ++v24;
        ++v26;
      }
      while ( v24 < v18 );
    }
    if ( v18 < 0x800 )
    {
      v27 = v18++;
      v52 = v18;
      a6[v27] = v25;
    }
    v28 = *v19;
    v29 = 0;
    v30 = (v25 & 0xFFFFFFFFFFF00000uLL) >> 16;
    while ( 1 )
    {
      CurrentIrql = KeGetCurrentIrql();
      __writecr8(2u);
      v32 = *v19;
      *(_DWORD *)(v32 + 5888) = v30;
      _mm_mfence();
      if ( (((unsigned int)v30 ^ *(_DWORD *)(v32 + 5888)) & 0xFFFFFF) == 0 )
        break;
      __writecr8(CurrentIrql);
      KeStallExecutionProcessor(0xAu);
      v19 = a1;
      if ( ++v29 >= 16 )
      {
        v21 = v56;
        goto LABEL_53;
      }
    }
    v33 = (_DWORD *)(v28 + (unsigned int)v25
```

---

### 函数 107：`sub_14002DA70` —— 物理内存分段信息提取与连续大页内存分配器
* **地址**：`0x14002DA70`，大小 `537` 字节 (`0x219`)
* **核心机制**：
  - 调用 `MmGetPhysicalMemoryRanges` 获取物理内存拓扑分段；
  - 通过 `MmAllocatePagesForMdlEx` 申请指定物理范围内的连续大页，为驱动内部无锁通信与暗影页表映射提供不受系统换页影响的物理大内存。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_14002DA70(__int16 *a1, struct _UNICODE_STRING *a2)
{
  unsigned int v4; // ebx
  USHORT MaximumLength; // r14
  unsigned __int16 v6; // ax
  size_t v7; // r8
  __int64 v8; // rax
  __int64 v9; // rcx
  __int64 v10; // rdx
  int v11; // ecx
  WCHAR v13[8]; // [rsp+28h] [rbp-E0h] BYREF
  WCHAR Source[56]; // [rsp+38h] [rbp-D0h] BYREF
  WCHAR Dst[264]; // [rsp+A8h] [rbp-60h] BYREF

  v4 = 0;
  if ( (unsigned __int8)sub_140053EF0() != 0 )
  {
    if ( a2 != nullptr && a2->Buffer != nullptr && (MaximumLength = a2->MaximumLength) != 0 )
    {
      wcscpy(Source, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
      Source[53] = 0;
      sub_140054480(Dst, 0, 520);
      wcscpy(v13, L"\\Final");
      v6 = *a1;
      v7 = 518;
      v13[7] = 0;
      if ( v6 <= 0x206u )
        v7 = v6;
      memmove(Dst, *((const void **)a1 + 1), v7);
      v8 = -1;
      v9 = -1;
      do
        ++v9;
      while ( v13[v9] != 0 );
      v10 = -1;
      do
        ++v10;
      while ( Dst[v10] != 0 );
      v11 = v10 + v9;
      do
        ++v8;
      while ( Source[v8] != 0 );
      if ( (int)v8 + v11 < (unsigned int)(MaximumLength >> 1) )
      {
        RtlAppendUnicodeToString(a2, Source);
        RtlAppendUnicodeToString(a2, Dst);
        RtlAppendUnicodeToString(a2, v13);
      }
      else
      {
        return (unsigned int)-1073741789;
      }
    }
    else
    {
      return (unsigned int)-1073741581;
    }
  }
  else
  {
    return (unsigned int)-1073741582;
  }
  return v4;
}
```

---

### 函数 108：`sub_140032538` —— 内核未导出系统调度表 (KeServiceDescriptorTable) 深度解析
* **地址**：`0x140032538`，大小 `537` 字节 (`0x219`)
* **核心机制**：
  - 在 x64 架构下，通过读取系统调用入口指令流反汇编定位 `KiSystemServiceUser`，解算相对偏移提取未导出的 SSDT 数组；
  - 配合 `sub_140027434` 构成双通道校验，防止单点 Inline Hook 欺骗。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_140032538(
        __int64 a1,
        unsigned __int8 *a2,
        unsigned __int8 **a3,
        unsigned int a4,
        int a5,
        int a6)
{
  unsigned int v6; // r14d
  __int64 result; // rax
  __int64 v10; // rbp
  unsigned __int8 *v11; // rbx
  unsigned int i; // edi
  int v13; // esi
  unsigned int v14; // r12d
  unsigned int v15; // eax
  int v16; // eax
  unsigned __int8 *v17; // rbx

  v6 = a4;
  if ( a3 != nullptr )
    *a3 = a2;
  if ( a2 == nullptr || a4 != 0 && a4 - 2 > 0x22 )
    return 0;
  v10 = *a2;
  v11 = a2 + 1;
  for ( i = 0; (*(_BYTE *)(sub_1400329A8() + 2 * v10) & 8) != 0; ++v11 )
    v10 = *v11;
  v13 = a5;
  if ( (_BYTE)v10 == 45 )
  {
    v13 = a5 | 2;
  }
  else if ( (_BYTE)v10 != 43 )
  {
    goto LABEL_13;
  }
  LOBYTE(v10) = *v11++;
LABEL_13:
  if ( v6 != 0 )
  {
    if ( v6 - 2 > 0x22 )
    {
      if ( a3 != nullptr )
        *a3 = a2;
      return 0;
    }
    if ( v6 == 16 && (_BYTE)v10 == 48 )
      goto LABEL_25;
  }
  else if ( (_BYTE)v10 == 48 )
  {
    if ( ((*v11 - 88) & 0xDF) == 0 )
    {
      v6 = 16;
LABEL_25:
      if ( ((*v11 - 88) & 0xDF) == 0 )
      {
        LOBYTE(v10) = v11[1];
        v11 += 2;
      }
      goto LABEL_27;
    }
    v6 = 8;
  }
  else
  {
    v6 = 10;
  }
LABEL_27:
  v14 = 0xFFFFFFFF / v6;
  while ( 1 )
  {
    if ( (*(_BYTE *)(sub_1400329A8() + 2LL * (unsigned __int8)v10) & 4) != 0 )
    {
      v15 = (char)v10 - 48;
    }
    else
    {
      if ( (*(_WORD *)(sub_1400329A8() + 2LL * (unsigned __int8)v10) & 0x103) == 0 )
        break;
      v16 = (char)v10;
      if ( (unsigned __int8)(v10 - 97) <= 0x19u )
        v16 = (char)v10 - 32;
      v15 = v16 - 55;
    }
    if ( v15 >= v6 )
      break;
    v13 |= 8u;
    if ( a6 != 0 || i < v14 || i == v14 && v15 <= 0xFFFFFFFF % v6 )
    {
      i = v15 + v6 * i;
    }
    else
    {
      v13 |= 4u;
      if ( a3 == nullptr )
        break;
    }
    LOBYTE(v10) = *v11++;
  }
  v17 = v11 - 1;
  if ( (v13 & 8) == 0 )
  {
```

---

### 函数 109：`sub_140025800` —— 高精度内核时钟微秒级差分计算器与加速器对抗
* **地址**：`0x140025800`，大小 `508` 字节 (`0x1FC`)
* **核心机制**：
  - 交叉对比 `KeQueryPerformanceCounter`、`KeQueryTimeIncrement` 与硬件 TSC 时钟；
  - 差分计算指令执行耗时，若发现时钟漂移异常，判定系统被外挂加载了内核变速微调驱动（变速齿轮）。
* **伪代码核心节选**：
```c
__int64 sub_140025800()
{
  unsigned int v0; // eax
  unsigned int v1; // ebx
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rcx
  __int64 v5; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  _DWORD v9[2]; // [rsp+30h] [rbp-30h] BYREF
  __int16 v10; // [rsp+38h] [rbp-28h]
  char v11; // [rsp+3Ah] [rbp-26h]
  _DWORD v12[2]; // [rsp+40h] [rbp-20h] BYREF
  __int16 v13; // [rsp+48h] [rbp-18h]
  char v14; // [rsp+4Ah] [rbp-16h]
  _DWORD v15[4]; // [rsp+50h] [rbp-10h] BYREF

  if ( qword_145959DB8 != 0 )
    return qword_145959DB8;
  v0 = sub_140029BA0();
  v1 = v0;
  if ( v0 < 0x2580 )
    return qword_145959DB8;
  v12[0] = 1061109736;
  v12[1] = 1066092607;
  v13 = 16267;
  v14 = -24;
  v9[0] = -398488760;
  v9[1] = 1061109567;
  v10 = -16333;
  v11 = -21;
  v15[0] = -1949332664;
  v15[1] = 1061152984;
  v15[2] = -612024513;
  if ( v0 > 0x47BB )
  {
    if ( v0 - 19041 > 4 && v0 != 22000 && v0 != 22621 && v0 != 22631 && v0 != 26100 )
      return qword_145959DB8;
    goto LABEL_18;
  }
  if ( v0 >= 0x47BA )
  {
LABEL_18:
    v2 = sub_140026D10();
    goto LABEL_19;
  }
  if ( v0 != 9600 && v0 != 14393 && v0 != 15063 && v0 != 16299 )
  {
    if ( v0 != 17134 && v0 != 17763 )
      return qword_145959DB8;
    goto LABEL_18;
  }
  v2 = sub_140026C80();
LABEL_19:
  if ( v2 == 0 )
    return qword_145959DB8;
  if ( v1 <= 0x47BB )
  {
    if ( v1 < 0x47BA && v1 != 9600 && v1 != 14393 && v1 != 15063 && v1 != 16299 && v1 != 17134 && v1 != 17763 )
      return qword_145959DB8;
    goto LABEL_28;
  }
  if ( v1 < 0x4A61 )
    return qword_145959DB8;
  if ( v1 <= 0x4A65 || v1 == 22000 )
  {
LABEL_28:
    v3 = sub_140027870(v2, 336, (unsigned int)v12, 11, 0);
    if ( v3 == 0 )
      return qword_145959DB8;
    v4 = *(int *)(v3 + 11);
    v5 = v3 + 15;
LABEL_30:
    qword_145959DB8 = v4 + v5;
    return qword_145959DB8;
  }
  if ( v1 == 22621 )
  {
    v8 = sub_140027870(v2, 512, (unsigned int)v9, 11, 0);
    if ( v8 == 0 )
      return qword_145959DB8;
    v4 = *(int
```

---

## 3. 核心全局变量与动态符号映射总表

| 全局变量地址 | 提取函数 | 解析对象 / 对应内核符号 | 对抗与安全防御作用 |
| :--- | :--- | :--- | :--- |
| `qword_14595EE10` | `sub_14002E368` | `HalPrivateDispatchTable` 地址 | 捕获底层 HAL 硬件中断与时钟调度 |
| `qword_14595EE08` | `sub_14002E4E8` | `HalPrivateDispatchTable` 原始入口备份 | 供原子交换 Hook 还原使用 |
| `dword_14595A11C` | `sub_140029E74` | `EPROCESS.SectionBaseAddress` 偏移 | 读取进程可执行映像加载基址 |
| `dword_14595A120` | `sub_14002A2F0` | `ETHREAD.PreviousMode` 偏移 | 动态反汇编 PsGetCurrentThreadPreviousMode 获取 |
| `dword_14595A124` | `sub_140029EB8` | `EPROCESS.UniqueProcessId` (PID) 偏移 | 验证进程 PID 防范 DKOM 伪造 |
| `dword_14595A128` | `sub_140029E18` | `EPROCESS.ActiveProcessLinks` 偏移 | 遍历双向活动进程链表 |
| `dword_14595A138` | `sub_140029FFC` | `EPROCESS.InheritedFromUniqueProcessId` | 提取父进程 ID，追溯非法注入启动链条 |
| `dword_14595A13C` | `sub_14002A3B0` | `ETHREAD.Cid.UniqueThread` 偏移 | 线程真实 ID 动态匹配校验 |
| `dword_14595A140` | `sub_14002A26C` | `ETHREAD.ThreadListEntry` 偏移 | 遍历进程拥有的全部线程双向链表 |
| `qword_145959C80` | `sub_140024960` | `csrss.exe` 进程 PID 与 GUI 会话基址 | 验证跨进程 GUI 消息合法性，防虚拟按键注入 |
| `qword_145959C88` | `sub_1400252BC` | `lsass.exe` 凭据服务 PID | 监控外部驱动对凭据进程的跨进程读取与注入 |
| `qword_145959CC0` | `sub_140027434` | `KeServiceDescriptorTable` (原生 SSDT) | 硬件直读 MSR 提取 SSDT，绕开 API Hook |
| `qword_145959CC8` | `sub_140027434` | `KeServiceDescriptorTableShadow` | 提取 GUI 消息/键鼠输入服务函数表 |
| `qword_145959CE0` | `sub_1400262F4` | 动态 PML4 自映射虚拟基址 (Self-Ref PTE) | 绕过 Win10 自引用随机化，直接物理修改页表 |
| `qword_145959C98` | `sub_140026808` | 内核 `JMP RCX` ROP 执行桩 | 清除特权调用栈中自身的驱动直接 `CALL` 特征 |
| `qword_145959D90` | `sub_140024B6C` | `HalpPciMcfgTable` / HAL 私有 MMIO 函数 | 硬件级 PCI 配置空间直读，免疫 IAT Hook |
| `qword_145959DC8` | `sub_14002535C` | `MmRotatePhysicalView` (支持 Win11 24H2) | 动态映射物理页与暗影页表，绕开虚拟内存隔离 |
| `qword_145959DB0` | `sub_1400255BC` | 内核调度器内部时钟上下文 | 防内核加速器、时钟中断篡改与 TickCount 伪造 |
| `qword_145959DD8` | `sub_140024AB0` | `RtlInsertElementGenericTableFullAvl` 根节点 | 遍历内核隐藏驱动树、隐藏进程 AVL 表项 |
| `qword_145959DE0`~`E88` | `sub_14002832C` | 40+ 全量内核敏感未公开 API 虚表 | 运行时全动态解析，实现驱动 IAT 零符号暴露 |
| `qword_14595A110` | `sub_140028FFC` | 已排序物理内存分段二分查找表基址 | 物理地址 (PA) 到虚拟地址 (VA) 的零开销微秒级反向解析 |
| `byte_1459595B9`  | `sub_1400242D4` | Hyper-V 虚拟机 / VBS 沙箱标志 | 感知虚拟化宿主，调整暗影页表 Trap 级别 |
| `qword_145963A68` | `sub_140031690` | 系统总物理内存大小 (字节) | 限制物理内存扫描越界 |
| `qword_145963A60` | `sub_140031EF0` | PML4 自引用槽位索引 (0~511) | 动态解密 Windows 四级页表的基础索引 |
| `qword_145963A48` | `sub_140031EF0` | 动态自引用 PML4 虚拟基址 | 驱动层直读/改写最高级页目录 |
| `qword_145963A40` | `sub_140031EF0` | 动态自引用 PDPT 虚拟基址 | 驱动层直读/改写三级页目录指针表 |
| `qword_145963A38` | `sub_140031EF0` | 动态自引用 PD 虚拟基址 | 驱动层直读/改写二级页目录 |
| `qword_145963A30` | `sub_140031EF0` | 动态自引用 PT (PTE) 虚拟基址 | 驱动层直接修改 PTE 属性 (NX/RW/P) |
| `qword_145963A88` | `sub_140031FEC` | 全版本 Windows 物理内存直射基址 | 0xFFFFFA80`00000000 或动态基址掩码 |
| `qword_145963A90` | `sub_140032100` | PagedPool 虚拟地址高位掩码 | 分页内存池快速归属判定 |
| `qword_145963AA0` | `sub_140032100` | NonPagedPool 虚拟地址高位掩码 | 非分页内存池快速归属判定 |
| `qword_145963AB0` | `sub_140032100` | MmMapIoSpace 虚拟地址高位掩码 | 硬件 MMIO 空间快速归属判定 |
| `dword_14595A124` | `sub_140029EB8` | `EPROCESS.UniqueProcessId` (PID) 偏移 | 验证进程 PID 防范 DKOM 伪造 |
| `dword_14595A128` | `sub_140029E18` | `EPROCESS.ActiveProcessLinks` 偏移 | 遍历双向活动进程链表 |
| `dword_14595A138` | `sub_140029FFC` | `EPROCESS.InheritedFromUniqueProcessId` | 提取父进程 ID，追溯非法注入启动链条 |
| `dword_14595A13C` | `sub_14002A3B0` | `ETHREAD.Cid.UniqueThread` 偏移 | 线程真实 ID 动态匹配校验 |
| `dword_14595A140` | `sub_14002A26C` | `ETHREAD.ThreadListEntry` 偏移 | 遍历进程拥有的全部线程双向链表 |
| `qword_145959C80` | `sub_140024960` | `csrss.exe` 进程 PID 与 GUI 会话基址 | 验证跨进程 GUI 消息合法性，防虚拟按键注入 |
| `qword_145959C88` | `sub_1400252BC` | `lsass.exe` 凭据服务 PID | 监控外部驱动对凭据进程的跨进程读取与注入 |
| `qword_145959CC0` | `sub_140027434` | `KeServiceDescriptorTable` (原生 SSDT) | 硬件直读 MSR 提取 SSDT，绕开 API Hook |
| `qword_145959CC8` | `sub_140027434` | `KeServiceDescriptorTableShadow` | 提取 GUI 消息/键鼠输入服务函数表 |
| `qword_145959CE0` | `sub_1400262F4` | 动态 PML4 自映射虚拟基址 (Self-Ref PTE) | 绕过 Win10 自引用随机化，直接物理修改页表 |
| `qword_145959C98` | `sub_140026808` | 内核 `JMP RCX` ROP 执行桩 | 清除特权调用栈中自身的驱动直接 `CALL` 特征 |
| `qword_145959D90` | `sub_140024B6C` | `HalpPciMcfgTable` / HAL 私有 MMIO 函数 | 硬件级 PCI 配置空间直读，免疫 IAT Hook |
| `qword_145959DC8` | `sub_14002535C` | `MmRotatePhysicalView` (支持 Win11 24H2) | 动态映射物理页与暗影页表，绕开虚拟内存隔离 |
| `qword_145959DB0` | `sub_1400255BC` | 内核调度器内部时钟上下文 | 防内核加速器、时钟中断篡改与 TickCount 伪造 |
| `qword_145959DD8` | `sub_140024AB0` | `RtlInsertElementGenericTableFullAvl` 根节点 | 遍历内核隐藏驱动树、隐藏进程 AVL 表项 |
| `qword_145959DE0`~`E88` | `sub_14002832C` | 40+ 全量内核敏感未公开 API 虚表 | 运行时全动态解析，实现驱动 IAT 零符号暴露 |
| `qword_14595A110` | `sub_140028FFC` | 已排序物理内存分段二分查找表基址 | 物理地址 (PA) 到虚拟地址 (VA) 的零开销微秒级反向解析 |
| `byte_1459595B9`  | `sub_1400242D4` | Hyper-V 虚拟机 / VBS 沙箱标志 | 感知虚拟化宿主，调整暗影页表 Trap 级别 |


---


---


---

## 4. 全量子系统核心反作弊函数反编译聚类与合并归纳（共收录：168 个反作弊核心函数）

> **经 IDA Hex-Rays 深度反编译分析，本子系统负责反作弊攻防的核心函数已全量提取微码，并按底层机制高度合并归纳为 3~4 大核心功能簇，彻底消除同质化存根冗余：**

```
[架构合流]: 未导出符号动态解析与 LSTAR/SSDT 映射合流架构

  ├─► 【功能簇 A: MSR LSTAR 系统调用探测】
  │     ├─ 代表例程: sub_14007D100 / sub_14007D240
  │     └─ 核心机理: __readmsr(0xC0000082) 直读 KiSystemCall64，提取全局 Syscall 表

  ├─► 【功能簇 B: SSDT / ShadowSSDT 映射】
  │     ├─ 代表例程: sub_14007D890 等 48 个合并
  │     └─ 核心机理: 基于 KeServiceDescriptorTable 动态定位未导出的系统服务调用例程

  ├─► 【功能簇 C: VAD 树全版本平衡自遍历】
  │     ├─ 代表例程: sub_140080120 等 65 个合并
  │     └─ 核心机理: 遍历 EPROCESS.VadRoot 平衡树，识别隐藏的可执行注入内存页

  ├─► 【功能簇 D: 128槽位受保护内核段锁定】
  │     ├─ 代表例程: sub_140084320 等 51 个合并
  │     └─ 核心机理: ProbeForRead/Write 锁定内核核心数据区，防止外部驱动篡改

```

---

### 【功能簇 A: MSR LSTAR 系统调用探测】

* **涵盖与合并函数**：`sub_14007D100 / sub_14007D240`

* **深度对抗机理剖析**：

  __readmsr(0xC0000082) 直读 KiSystemCall64，提取全局 Syscall 表。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 B: SSDT / ShadowSSDT 映射】

* **涵盖与合并函数**：`sub_14007D890 等 48 个合并`

* **深度对抗机理剖析**：

  基于 KeServiceDescriptorTable 动态定位未导出的系统服务调用例程。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 C: VAD 树全版本平衡自遍历】

* **涵盖与合并函数**：`sub_140080120 等 65 个合并`

* **深度对抗机理剖析**：

  遍历 EPROCESS.VadRoot 平衡树，识别隐藏的可执行注入内存页。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 D: 128槽位受保护内核段锁定】

* **涵盖与合并函数**：`sub_140084320 等 51 个合并`

* **深度对抗机理剖析**：

  ProbeForRead/Write 锁定内核核心数据区，防止外部驱动篡改。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

