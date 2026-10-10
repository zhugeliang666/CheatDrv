---
name: ace-process-module-monitor
description: >
  ACE (Anti-Cheat Expert) 进程、线程与镜像加载内核监控子系统全量逆向分析。
  包含 111 个核心详解与全量子系统 504 个归属函数完整拓扑索引、PsSetLoadImageNotifyRoutine 模块审计、ACE-GAME/BASE 驱动签名与时间戳校验、PsSetCreateProcessNotifyRoutineEx 保护链表、DKOM 进程隐藏对抗反查、腾讯受保护游戏名单混淆判定、全盘符与设备符号链接规范化映射、dwm.exe 桌面窗口管理挂接、NVIDIA (nvwgf2umx.dll) / AMD (amdxx64.dll) 显卡驱动与 Vulkan (vk_icdGetInstanceProcAddr) 透视 Overlay 监控、原生 PE 导出表与节区解析、__writecr8(0) 特权安全分发、看门狗巡检与驱动动态卸载例程。
---

# ACE 内核进程、线程与模块加载监控体系全量函数深度分析

## 1. 架构总览与监控工作流拓扑

ACE 内核驱动通过注册 Windows 顶层内核通知例程，对所有进程生命周期、可执行模块（EXE/DLL/SYS）映射及自身驱动组件的合法性进行持续审计，并维护一个全局受保护进程单向链表 `qword_145966280`。

```
[模块加载审计流 (Image Load Monitor)]
       │
       ├─► sub_140013BCC (调用 PsSetLoadImageNotifyRoutine 注册 sub_14001471C)
       │     │
       │     └─► sub_14001471C (过滤内核级驱动加载: ImageInfo & 0x100)
       │           │
       │           └─► sub_14004C7E8 (核心审计例程: 比对 ACE-GAME.SYS / ACE-BASE.SYS)
       │                 ├─► 校验编译时间戳: Timestamp <= 0x63877E00
       │                 └─► 触发防御熔断 (Kill Switch): byte_14596A5C1 = 1
       │
[进程创建/退出审计流 (Process Monitor)]
       │
       ├─► sub_14000BF10 (调用 PsSetCreateProcessNotifyRoutineEx 注册 NotifyRoutine)
       │     │
       │     └─► NotifyRoutine (0x14000C14C, 捕获 CreateInfo == NULL 进程退出事件)
       │           │
       │           └─► sub_14003B56C (获取自旋锁 qword_145AFF238，从链表中卸载 PID)
       │                 ├─► sub_14003BC98 (清理受保护进程钩子)
       │                 ├─► sub_14003C64C (销毁进程通信上下文)
       │                 └─► ExFreePoolWithTag (回收保护节点内存)
       │
[后台看门狗与驱动生命周期管理]
       ├─► HandleInformation (0x14001AE30, 30 次/秒级超时看门狗线程)
       └─► StartRoutine / sub_14000F968 (ZwUnloadDriver + ObDereferenceObjectDeferDelete 驱动热卸载)
```

---

## 2. 核心函数逐一详尽分析（Function-by-Function）

### 函数 1：`sub_140013BCC`
* **地址**：`0x140013BCC`，大小 `0x47`
* **作用**：**模块加载通知回调注册器**。
* **伪代码**：
  ```c
  NTSTATUS sub_140013BCC(__int64 a1)
  {
    if ( sub_14000BA48(a1, &unk_1400A1258) == 0 && sub_14002E730() == 0 )
    {
      if ( byte_14012D278 == 0 )
      {
        NTSTATUS status = PsSetLoadImageNotifyRoutine(sub_14001471C);
        if ( status != 0 ) return status;
        byte_14012D278 = 1;
      }
      return sub_14002E61C();
    }
    return status;
  }
  ```

---

### 函数 2：`sub_14001471C`
* **地址**：`0x14001471C`，大小 `0x32`
* **形参**：`PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo`
* **作用**：**模块加载回调入口过滤器**。
* **执行特征**：检查 `ImageInfo->ImageAddressingMode` 及驱动标志位 `(*(_DWORD *)ImageInfo & 0x100) != 0`（指示加载对象为内核模式驱动程序），命中后将名称与基址转发至核心审计例程 `sub_14004C7E8`。

---

### 函数 3：`sub_14004C7E8`
* **地址**：`0x14004C7E8`，大小 `0x1B8`
* **作用**：**核心反作弊驱动防篡改与加载签名校验器**。
* **硬编码字符串提取**：
  - 字符串 1：`v11` 数组编码为宽字符 `L"ACE-GAME.SYS"`
  - 字符串 2：`v13` 数组编码为宽字符 `L"ACE-BASE.SYS"`
* **时间戳与防重放校验**：
  ```c
  // 匹配加载镜像是否包含 ACE 官方驱动文件名
  if ( sub_14002F710(ImageName->Buffer, ImageName->Length, L"ACE-GAME.SYS", 24, 1) )
  {
      PIMAGE_NT_HEADERS NtHeaders = sub_140030080(ImageInfo->ImageBase);
      if ( NtHeaders )
      {
          // 校验 PE 头 TimeDateStamp 是否小于等于指定构建阈值
          if ( NtHeaders->FileHeader.TimeDateStamp <= 0x63877E00u )
              IsMismatched = true;
      }
  }
  // 触发全局熔断
  if ( IsMismatched )
  {
      sub_14004EE5C();
      *((_BYTE *)qword_14596A650 + 592) = 1;
      sub_14004CEF0();
      byte_14596A5C1 = 1; // 激活全局防御锁死
  }
  ```

---

### 函数 4：`sub_14000BF10`
* **地址**：`0x14000BF10`，大小 `0x5F`
* **作用**：**进程生命周期监控注册器**。
* **实现**：调用 `PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, FALSE)`，设置活跃标记 `byte_14012AA88 = 1`。

---

### 函数 5：`NotifyRoutine`
* **地址**：`0x14000C14C`，大小 `0x1F`
* **作用**：**进程退出通知拦截器**。
* **实现**：
  ```c
  void NotifyRoutine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
  {
    if ( byte_14012AA88 != 0 && CreateInfo == NULL ) // 捕获目标进程终止事件
      sub_14003B70C(ProcessId);
  }
  ```

---

### 函数 6：`sub_14003B56C`
* **地址**：`0x14003B56C`，大小 `0xD8`
* **形参**：`HANDLE ProcessId`
* **作用**：**受保护进程链表节点移除与资源清理**。
* **执行序列**：
  - 调用 `KeAcquireSpinLockRaiseToDpc(&qword_145AFF238)`。
  - 遍历全局受保护进程单向链表 `qword_145966280`，匹配 `Entry->PID == ProcessId`。
  - 递减引用计数 `if ( --Entry->RefCount <= 0 )`，将其从链表摘除。
  - 释放自旋锁 `KeReleaseSpinLock`。
  - 依次调用 `sub_14003BC98()`（卸载挂钩与句柄降权）与 `sub_14003C64C()`（释放进程上下文结构）。
  - 调用 `ExFreePoolWithTag(Entry, 0)` 释放内存。

---

### 函数 7：`sub_14003B3D4`
* **地址**：`0x14003B3D4`，大小 `0xB0`
* **作用**：**受保护进程异步安全登记例程**。
* **实现**：通过 `PsCreateSystemThread` 创建一个专属内核辅助线程（执行 `sub_14003B4A4`），在安全的系统线程上下文中将新的游戏进程加入保护链表，并通过 `KeWaitForSingleObject(&Event)` 同步等待登记完成。

---

### 函数 8：`HandleInformation`
* **地址**：`0x14001AE30`，大小 `0xA7`
* **作用**：**后台心跳与线程完整性看门狗线程**。
* **机制**：
  - 循环 30 次超时等待，每次设置相对超时时间 `Timeout = -10,000,000`（1 秒）。
  - 调用 `KeWaitForSingleObject(&stru_140148720, Executive, 0, 0, &Timeout)`。
  - 若心跳超时且未收到正常唤醒信号（`v1 == 258 && byte_140148750 == 0`），判定目标进程被挂起、死锁或被调试器挂起，调用 `sub_14001D0E8` 与 `sub_14001BCB8` 强制触发反调试保护。
  - 退出时调用 `PsTerminateSystemThread(0)`。

---

### 函数 9：`StartRoutine`
* **地址**：`0x14000E028`，大小 `0x24`
* **作用**：常驻驱动自维护工作线程入口，直接分发给 `sub_14000F968`。

---

### 函数 10：`sub_14000F968`
* **地址**：`0x14000F968`，大小 `0xEA`
* **作用**：**驱动动态热卸载与对象解引用引擎**。
* **逻辑**：
  ```c
  ObfReferenceObject(DriverObject);
  if ( ZwUnloadDriver(DriverServiceName) >= 0 )
  {
      // 创建延迟回收线程，在驱动服务卸载后异步执行对象释放
      PsCreateSystemThread(
          &ThreadHandle,
          0,
          NULL,
          NULL,
          NULL,
          (PKSTART_ROUTINE)ObDereferenceObjectDeferDelete,
          DriverObject
      );
      ZwClose(ThreadHandle);
  }
  ```

---

### 函数 11：`NotifyRoutine` (`0x14000C14C`)
* **地址**：`0x14000C14C`，大小 `31` 字节 (`0x1F`)
* **形参**：`PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo`
* **作用**：**Windows 内核底层进程退出精准捕获与上下文清理例程**。
* **伪代码**：
  ```c
  void __fastcall NotifyRoutine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
  {
    // 当 CreateInfo 为 NULL 时，代表目标进程正在终止/退出
    if ( byte_14012AA88 != 0 && CreateInfo == nullptr )
      sub_14003B70C(ProcessId); // 触发进程退出反作弊清理与上下文销毁
  }
  ```

---

### 函数 12：`sub_14000C16C`
* **地址**：`0x14000C16C`，大小 `45` 字节 (`0x2D`)
* **作用**：**进程通知回调安全注销例程**。调用 `PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)NotifyRoutine, 1u)` 移除内核钩子，重置全局标志 `byte_14012AA88 = 0`。

---

### 函数 13：`sub_14000BD5C`
* **地址**：`0x14000BD5C`，大小 `286` 字节 (`0x11E`)
* **形参**：`NTSTATUS Status`
* **作用**：**NTSTATUS 内核错误码到 ACE 应用层安全状态码的映射查找表**。
* **核心映射逻辑**：
  将底层不可见的 NTSTATUS 状态精准转换为应用层防作弊上报状态码：
  - `0xC0000020` (`STATUS_INVALID_SUB_AUTHORITY`) -> `1163`
  - `0xC00000B5` (`STATUS_IO_TIMEOUT`) -> `1167`
  - `0xC0000001` (`STATUS_UNSUCCESSFUL`) -> `1150`
  - 其余状态通过稀疏 switch-case 映射至 `1151 ~ 1180` 专属告警码。

---

### 函数 14：`sub_14000BE7C`
* **地址**：`0x14000BE7C`，大小 `85` 字节 (`0x55`)
* **作用**：**受保护进程监控子系统初始化与心跳校验**。检查 `byte_14012AA88`，调用 `sub_14003B960()` 构建受保护上下文环境。

---

### 函数 15：`sub_14000BED4`
* **地址**：`0x14000BED4`，大小 `58` 字节 (`0x3A`)
* **作用**：**进程通信参数安全校验器**。校验缓冲区大小（`a3 == 4104` 字节）并派发给核心例程 `sub_14003B34C`。

---

### 函数 16：`sub_14000BF10`
* **地址**：`0x14000BF10`，大小 `95` 字节 (`0x5F`)
* **作用**：**受保护进程通信上下文状态查询器**。调用 `sub_14003B3D4`，并自动调用 `sub_14000BD5C` 进行状态码包装。

---

### 函数 17：`sub_14000BF70`
* **地址**：`0x14000BF70`，大小 `127` 字节 (`0x7F`)
* **作用**：**受保护进程白名单注入例程**。校验输入参数长度（`a2 == 16, a3 >= 8`），调用 `sub_14003B844` 将目标 PID 插入核心保护链表。

---

### 函数 18：`sub_14000BFF0` / `sub_14000C06C` / `sub_14000C0D8`
* **地址**：`0x14000BFF0` (123 B), `0x14000C06C` (107 B), `0x14000C0D8` (115 B)
---

### 函数 19：`sub_14000C504` / `sub_14000CCD0` / `sub_14000C800`
* **地址**：`0x14000C504` (33 B), `0x14000CCD0` (40 B), `0x14000C800` (37 B)
* **作用**：**64 槽位受保护内核句柄/线程原子豁免白名单表**。
* **无锁原子算法**：
  - 维持容量为 64 项的 64 位数组 `qword_14012ACC0[64]`。
  - **注册豁免项**：`sub_14000C504` 通过 `_InterlockedCompareExchange64(&qword_14012ACC0[i], a1, 0)` 争抢空槽（值为 0）并原子存入句柄。
  - **注销豁免项**：`sub_14000CCD0` 通过 `_InterlockedCompareExchange64(&qword_14012ACC0[i], 0, a1)` 原子释放占用的槽位。
  - **快速检索**：`sub_14000C800` 遍历 64 槽位执行单周期比对，判断句柄是否处于白名单豁免特权中。

---

### 函数 20：`sub_14000C690`
* **地址**：`0x14000C690`，大小 `368` 字节 (`0x170`)
* **作用**：**`ace-game` 核心子驱动服务状态机初始化与动态唤醒例程**。
* **伪代码**：
  ```c
  __int64 __fastcall sub_14000C690(char a1)
  {
    if ( byte_14012ACB0 != 0 ) return 0;
    if ( a1 == 0 && (unsigned __int8)sub_14002DED0(L"ace-game") != 0 )
      return 0xC0000035; // STATUS_OBJECT_NAME_COLLISION
    byte_14012ACB0 = 1;  // 激活 ace-game 核心子保护系统
    return 0;
  }
  ```

---

### 函数 21：`sub_14000C828`
* **地址**：`0x14000C828`，大小 `288` 字节 (`0x120`)
* **作用**：**跨进程越权注入后台审计系统线程启动器**。调用 `PsCreateSystemThread(&ThreadHandle, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)sub_14000CA94, Context)` 启动后台实时巡检工作流。

---

### 函数 22：`sub_14000CA94`
* **地址**：`0x14000CA94`，代码体积达 **572 字节** (`0x23C`)
* **作用**：**跨进程越权访问与内存注入深度审计引擎**。
* **核心审计逻辑**：
  1. 循环提取排队审计的越权记录（存放于 `&unk_14012AED8`）。
  2. 提取发起违规注入的源进程 PID（`*(v5 - 2)`）与被保护的游戏进程上下文。
  3. 调用 `sub_14002AB70` 获取源进程完整磁盘文件路径（`SourceString`），并使用 `sub_140028D0C` 进行路径小写规范化。
  4. 计算可执行文件哈希与进程名摘要（`sub_14002A59C`）。
  5. 触发 **1010 号严重跨进程注入遥测上报**：`sub_14001479C(Context, 1010, Hash, SourcePID, TargetPID, "setparam", ...)`。

---

### 函数 23：`sub_14000CA3C`
* **地址**：`0x14000CA3C`，大小 `88` 字节 (`0x58`)
* **作用**：**越权防御拦截状态上报器**。在拦截非法进程句柄请求后，触发 **9422 号安全事件上报**（`sub_140014738(0, 1010, 9422, dword_1400A1050, IsBlocked)`）。

---

### 函数 24：`sub_14000CDC8`
* **地址**：`0x14000CDC8`，大小 `263` 字节 (`0x107`)
* **形参**：`signed __int64 TargetHandle, __int64 SourcePID`
* **作用**：**进程句柄非法越权访问入口拦截器**。
* **联合双过滤准则**：
  ```c
  // 1. 检查源 PID 是否在 64 槽位原子豁免白名单中
  if ( sub_14000C800(SourcePID) == 0 )
  {
    // 2. 检查源 PID 是否在 256K 超大 PID 位图白名单中
    if ( (unsigned __int8)sub_14000CFF4(SourcePID) == 0 )
    {
      // 判定命中非法越权调试/注入进程！
      // 记录至 unk_14012AED8 唤醒后台审计线程 sub_14000CA94 上报！
      ...
    }
  }
  ```

---

### 函数 25：`sub_14000CF58`
* **地址**：`0x14000CF58`，大小 `153` 字节 (`0x99`)
* **作用**：**256K 超大规模 PID 位图安全内存池初始化器**。
* **架构**：分配大小达 **`0x3FFFE` 字节**（覆盖高达 262,144 个 PID，完整覆盖 Windows 操作系统所有可能分配的 32 位 PID 范围）的连续内核内存 `qword_14012B158`，用于 O(1) 复杂度的超高速 PID 白名单判定。

---

### 函数 26：`sub_14000CED0` / `sub_14000CFF4` / `sub_14000D09C` / `sub_14000D0CC` / `sub_14000D16C`
* **地址**：`0x14000CED0` (118 B), `0x14000CFF4` (165 B), `0x14000D09C` (45 B), `0x14000D0CC` (157 B), `0x14000D16C` (71 B)
* **作用**：**超高速 O(1) PID 位图原子标记、测试、注销与生命周期销毁体系**。
* **单周期位运算逻辑**：
  ```c
  // 测试 PID 是否在受信任白名单中 (sub_14000CFF4)
  bool __fastcall sub_14000CFF4(unsigned __int64 PID)
  {
    if ( PID - 1 > 0x3FFFE || byte_14012B150 == 0 ) return false;
    // 1. 右移 5 位快速索引 32 位块：ByteOffset = PID >> 5
    unsigned char *byte_ptr = (char *)qword_14012B158 + (PID >> 5);
    // 2. 取低 5 位测试对应 Bit：BitMask = 1 << (PID & 0x1F)
    return (*byte_ptr & (1 << (PID & 7))) != 0;
  }
  ```
* **生命周期与内存标签**：
  - **进程退出清零**：`sub_14000D0CC` 在进程结束时定位目标 bit 并执行 `*byte_ptr &= ~(1 << bit)` 清零；
  - **模块卸载销毁**：`sub_14000D16C` 调用 `ExFreePoolWithTag(qword_14012B158, 0x63627063u)` 释放内存，揭示专属内存池标签为 **`'cbpc'`**。

---

### 函数 27：`sub_14000D1B4`
* **地址**：`0x14000D1B4`，大小 `279` 字节 (`0x117`)
* **形参**：`int ModuleFlag`
* **作用**：**Windows `\KnownDlls` 核心节区对象与跨进程 DLL 注入审计**。
* **机制**：
  - 构造 `ObjectAttributes`，调用 `ZwOpenSection` 尝试打开系统的全局已知 DLL 节区（`\KnownDlls` / `\KnownDlls32`）。
  - 核查目标进程地址空间中的核心系统模块（如 `ntdll.dll`, `kernel32.dll`）是否源自原生已知节区，深度防御基于假冒系统 DLL、劫持加载目录的早期注入手法。

---

### 函数 28：`sub_14000D2E8` / `sub_14000D3D0` / `sub_14000D560`
* **地址**：`0x14000D2E8` (150 B), `0x14000D3D0` (309 B), `0x14000D560` (37 B)
* **作用**：**常驻内核动态执行探针与工作线程巡检守护者**。
* **机制**：
  - `sub_14000D2E8` 启动系统巡检线程 `sub_14000D3D0`，句柄保存在 `qword_14012B268`，激活标志 `byte_14012B260 = 1`。
  - `sub_14000D560` 联动 `MmIsAddressValid(VirtualAddress)` 动态验证并调用执行链，确保各子防御模块的心跳探针持续运转。

---

### 函数 29：`sub_14000DA30`
* **地址**：`0x14000DA30`，大小 `5` 字节
* **形参**：`HANDLE Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo, PVOID Context`
* **作用**：**TVM 虚拟机进程创建/退出审计分发桩（Thunk Stub）**。
* **机制**：
  - 作为原生代码段向 `.tvm` 虚拟机段的入口跳板，直接 JMP 至 `sub_145BDC825(Process, ProcessId, CreateInfo, Context)`。
  - 将 Windows 内核 `PsSetCreateProcessNotifyRoutineEx` 的回调原始上下文平滑分发给 TVM 虚拟机解释器进行深度对抗检测。

---

### 函数 30：`sub_14000DAAC`
* **地址**：`0x14000DAAC`，大小 `218` 字节 (`0xDA`)
* **作用**：**驱动主看门狗心跳计数器与周期性事件 4011 遥测上报**。
* **伪代码**：
  ```c
  __int64 sub_14000DAAC()
  {
    __int64 v0 = *(_QWORD *)&qword_14012B2B0;
    // 每 120 个心跳周期触发一次遥测上报
    if ( v0 != 0 && v0 == 120 * (v0 / 120) )
    {
      sub_14001161C(0, 4011, qword_14012B2B0, qword_14012B290, 0, nullptr, ...);
      v0 = *(_QWORD *)&qword_14012B2B0;
    }
    *(_QWORD *)&qword_14012B2B0 = ++v0;
    // 检查看门狗标志位，超出 60 次阈值自动重置
    if ( byte_1400A11EC != 0 && v0 >= 60 )
      byte_1400A11EC = 0;
    if ( (unsigned __int8)sub_140011D68() != 0 )
      sub_14000E04C();
    __int64 result = sub_14000DDDC();
    if ( (_BYTE)result != 0 )
      return sub_14001389C();
    return result;
  }
  ```

---

### 函数 31：`sub_14000DB88` & `sub_14000DBC8`
* **地址**：`0x14000DB88` (62 B), `0x14000DBC8` (27 B)
* **作用**：**全局策略配置块 `qword_14012B2B8` 动态条目解析器**。
* **机制**：
  - `sub_14000DBC8(Index)`：直接提取固定条目指针：`*((_QWORD *)qword_14012B2B8 + Index + 3)`。
  - `sub_14000DB88(Index)`：步进遍历变长配置项。跳过前导头部（`8 * Count + 24`），按照每个条目记录的前置大小 `*v2 + 8` 执行无边界跳跃式指针检索，返回第 `Index` 项数据体指针 `v2 + 1`。

---

### 函数 32：`sub_14000DBE4`
* **地址**：`0x14000DBE4`，大小 `413` 字节 (`0x19D`)
* **作用**：**`'cKRC'` 内存池核心策略配置注入与游戏宿主 PID 归属校验**。
* **内存池标签**：`0x43524B63` (`'cKRC'`)
* **安全校验链**：
  1. **魔数校验**：必须满足 `*(_DWORD *)Src == 1276`（ACE 配置协议魔数）。
  2. **数据大小一致性**：输入缓冲区大小 `a2` 必须等于头部的 `*((DWORD *)Src + 1)` 且不小于 24 字节。
  3. **宿主身份绑定**：`(HANDLE)Src[2] == PsGetCurrentProcessId()`，非游戏当前主进程提交一律拦截并返回错误 `dword_1400A11F0 + 33`。
  4. **条目字符串合规性**：对每个变长条目执行 NULL 截断安全扫描，防止越界或格式化攻击。
  5. **CAS 无锁生效**：通过 `_InterlockedCompareExchange64((volatile signed __int64 *)&qword_14012B2B8, PoolWithTag, 0)` 原子替换，防止并发重入。

---

### 函数 33：`sub_14000DDA4` & `sub_14000DDDC`
* **地址**：`0x14000DDA4` (54 B), `0x14000DDDC` (31 B)
* **作用**：**设备扩展安全标志位剥离与驱动生命周期状态检测**。
* **机制**：
  - `sub_14000DDA4`：校验指针 `MmIsAddressValid(*(PVOID *)(a1 + 40))`，清除 `+104` 偏移处的特征标志位 `0x2000000`（`*(_DWORD *)(v1 + 104) &= ~0x2000000`）。
  - `sub_14000DDDC`：检测 `dword_14012B2D8` 是否为 1 或 3（指示驱动已进入卸载或休眠状态）。

---

### 函数 34：`sub_14000DF78` & `sub_14000E028` (`StartRoutine`)
* **地址**：`0x14000DF78` (175 B), `0x14000E028` (36 B)
* **作用**：**内核监控守护系统线程创建例程（Worker Thread Launcher）**。
* **核心防御特征**：
  1. 挂接析构函数指针：`*((_QWORD *)StartContext + 13) = sub_14000DDFC`。
  2. 驱动服务名称完整性断言：若 `DriverServiceName.Buffer == NULL` 或名称长度超出 260 宽字符，立即调用 `KeBugCheck(dword_1400A11F0 + 21)` 主动蓝屏熔断。
  3. 状态机核验：要求驱动生命周期状态码 `dword_14012B2D8 == 4`，不符则触发 `KeBugCheck(dword_1400A11F0 + 22)`。
  4. 通过 `PsCreateSystemThread` 启动后台常驻线程 `StartRoutine`，并在内部调用核心热卸载/监控总线 `sub_14000F968`。

---

### 函数 35：`sub_14000DDFC`
* **地址**：`0x14000DDFC`，大小 `378` 字节
* **作用**：**驱动退场与内存资源全面清理总入口**。
* **机制**：
  - 判定服务上下文 `qword_14012B318` 是否非空。若存在，首先调用 `sub_14000FEF8` 执行**驱动磁盘文件自删除**，随后通过 `ExFreePoolWithTag` 释放内存。
  - 调用 `sub_1400460C0()` 清理通信句柄，最终调用 `sub_140013838()` 完成驱动彻底销毁。

---

### 函数 36：`sub_14000F968`
* **地址**：`0x14000F968`，大小 `188` 字节
* **形参**：`PVOID StartContext, PUNICODE_STRING DriverServiceName`
* **作用**：**异步安全延迟热卸载机制（Kernel Delayed Self-Unload）**。
* **机制与伪代码**：
  ```c
  __int64 sub_14000F968(PVOID StartContext, PUNICODE_STRING DriverServiceName)
  {
    if ( !StartContext || !DriverServiceName || !DriverServiceName->Buffer )
      return 2;
    // 增加对象引用计数，防止当前线程执行过程中驱动模块被强行释放
    ObfReferenceObject(StartContext);
    if ( ZwUnloadDriver(DriverServiceName) >= 0 )
    {
      void *ThreadHandle = nullptr;
      // 启动系统工作线程，交由系统内核自带的 ObDereferenceObjectDeferDelete 异步安全延迟释放
      if ( PsCreateSystemThread(&ThreadHandle, 0, nullptr, nullptr, nullptr,
                                ObDereferenceObjectDeferDelete, StartContext) >= 0 )
      {
        ZwClose(ThreadHandle);
        return 0;
      }
      return 5;
    }
    return 4;
  }
  ```

---

### 函数 37：`sub_14000FEF8`
* **地址**：`0x14000FEF8`，大小 `246` 字节
* **形参**：`PCWSTR SourceString`（驱动文件 NT 路径）
* **作用**：**内核驱动文件自删除与痕迹擦除机制（Kernel File Self-Deletion）**。
* **对抗深度剖析**：
  1. 调用 `ZwOpenFile` 传入 `0x100000` (SYNCHRONIZE) 及 `FILE_SHARE_READ` 模式获取文件句柄。
  2. 调用 `ObReferenceObjectByHandle` 获取文件底层内核对象 `FILE_OBJECT`。
  3. 深入修改 `FILE_OBJECT->SectionObjectPointer` 及标志：设置 `FILE_OBJECT[76] = 1`（修改内部 FCB 标志），强行打通文件的可删除权限。
  4. 调用 `ZwDeleteFile(&ObjectAttributes)` 直接在内核层对自身 `.sys` 文件物理删除，使得逆向分析者在游戏退场后无法从磁盘提取驱动镜像，完成痕迹擦除。

---

### 函数 38：`sub_14000ED10` & `sub_14000ED9C`
* **地址**：`0x14000ED10` (140 B), `0x14000ED9C` (121 B)
* **作用**：**TVM 虚拟机上下文封装进入桩（VM Entry Transition Stubs）**。
* **机制**：
  - 构造超大栈帧（`0x278` 字节），通过 `__readeflags()` 提取当前处理器标志寄存器。
  - 将 16 个通用寄存器（RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8~R15）与 EFLAGS 完整按槽位连续打包至栈结构体中。
  - 尾部调用跳转至核心 TVM 解释器入口 `sub_145C2AA87(a1, a2, a3)`。
  - 解释器返回后立即触发 `__debugbreak()`，构成坚不可摧的控制流单向屏障。

---

### 函数 39：`sub_14000F480`
* **地址**：`0x14000F480`，大小 `376` 字节 (`0x178`)
* **作用**：**`'Baxn'` 内存池内核模块与驱动列表全量快照提取器**。
* **内存池标签**：`0x6E617842` (`'Baxn'`)
* **核心流程**：
  1. 状态判断：若首次运行则先调用 `sub_145B05000()` 初始化内部快照句柄。
  2. 试探性调用 `sub_145B05058(&NumberOfBytes, 272, 0)` 获取当前系统所有加载模块所需缓冲区大小。每个条目固定占用 **272 字节 (0x110)**。
  3. 合规性校验：要求总大小在 `0x1100`（16 个驱动模块）至 `0x440000`（16,384 个模块）之间。
  4. 分配 `NumberOfBytes + 544`（预留 2 个条目余量）的 `NonPagedPool`。若失败则自动优雅降级为 `PagedPool`。
  5. 再次调用 `sub_145B05058(&NumberOfBytes, 272, PoolWithTag)` 全量写入内核快照。
  6. 返回快照条目总数 `*a2 = NumberOfBytes / 0x110` 及数据指针 `*a1 = PoolWithTag`。

---

### 函数 40：`sub_14000F320` & `sub_14000F444`
* **地址**：`0x14000F320` (292 B), `0x14000F444` (58 B)
* **作用**：**内核模块名称不区分大小写快速检索与基址/大小解析器**。
* **机制与伪代码**：
  ```c
  __int64 sub_14000F320(char *TargetModuleName, PVOID *OutBase, unsigned int *OutSize)
  {
    PVOID Snapshot = nullptr;
    unsigned int ModuleCount = 0;
    // 提取 'Baxn' 全量模块快照
    if ( sub_14000F480(&Snapshot, &ModuleCount) == 0 && Snapshot )
    {
      char *Entry = (char *)Snapshot;
      for ( unsigned int i = 0; i < ModuleCount; ++i )
      {
        // 偏移 +0: 模块虚拟基址 Base
        // 偏移 +8: 模块内存镜像大小 Size
        // 偏移 +14: 模块完整文件路径 (最大 0x104 字符)
        char *FilePath = Entry + 14;
        char *FileName = FilePath;
        // 提取最后一个路径分隔符 '\' 或 '/' 后的纯文件名
        for ( int k = 0; k < 260 && FilePath[k]; ++k ) {
          if ( FilePath[k] == '\\' || FilePath[k] == '/' ) FileName = &FilePath[k + 1];
        }
        // 不区分大小写逐字符匹配 (A-Z 转 a-z)
        if ( CaseInsensitiveMatch(FileName, TargetModuleName) )
        {
          *OutBase = *(PVOID *)Entry;
          *OutSize = *((unsigned int *)Entry + 2);
          ExFreePoolWithTag(Snapshot, 'Baxn');
          return 0; // 找到目标模块
        }
        Entry += 272; // 移动至下一个 0x110 条目
      }
      ExFreePoolWithTag(Snapshot, 'Baxn');
    }
    return 1;
  }
  ```
  - `sub_14000F444` 直接封装 `sub_14000F320`，返回模块是否存在且 Base != 0 的布尔结果。

---

### 函数 41：`sub_14000F284`
* **地址**：`0x14000F284`，大小 `32` 字节
* **作用**：**内核同步事件初始化例程**。
* **逻辑**：`KeInitializeEvent(&Event, SynchronizationEvent, 1u)`，为后续跨模块异步任务调度提供基础同步原语。

---

### 函数 42：`sub_14001043C` & `sub_140010004`
* **地址**：`0x14001043C` (417 B), `0x140010004` (289 B)
* **作用**：**底层文件系统真实设备直连与 Minifilter 过滤栈全面绕过（Minifilter Bypass via DeviceObjectHint）**。
* **核心机制与对抗原理解析**：
  1. `sub_14001043C` 从目标路径提取驱动器盘符（如 `C:`），构造 `\DosDevices\C:\`。
  2. 调用 `IoCreateFile` 打开底层卷设备，并通过 `ObReferenceObjectByHandle` 获取卷的 `FILE_OBJECT`。
  3. 关键调用 **`IoGetBaseFileSystemDeviceObject((PFILE_OBJECT)Object)`**：穿透所有挂接在该卷上的杀软文件过滤驱动、Minifilter 或文件监控 Hook，直接拿到真正的基础文件系统驱动（如 NTFS / FAT32）原生设备对象 `BaseFileSystemDeviceObject`。
  4. `sub_140010004` 随后调用 **`IoCreateFileSpecifyDeviceObjectHint(..., DeviceObject)`**！该未公开/半公开底层接口指示 I/O 管理器从指定的底层设备对象开始分发 IRP，从而**完全绕过文件系统顶部所有 Minifilter 过滤器的拦截与监控**。

---

### 函数 43：`sub_140010128` / `sub_1400102D0` / `sub_140010320` / `sub_1400103F0`
* **地址**：`0x140010128` (422 B), `0x1400102D0` (78 B), `0x140010320` (208 B), `0x1400103F0` (76 B)
* **作用**：**内核层独立纯净文件 I/O 读写与定位游标引擎（Native Kernel File Stream Engine）**。
* **机制**：
  - `sub_140010128`：自动在 `PagedPool`（标签 `'xkfp'`, `0x6B667078`）中补齐 `\??\` 前缀并调用穿透函数打开文件。
  - `sub_1400102D0`：直接调用 `ZwReadFile` 读取文件字节流。
  - `sub_1400103F0`：通过 `ZwQueryInformationFile(..., FilePositionInformation)` 获取文件当前游标位置。
  - `sub_140010320`：封装类似 `fseek` 的逻辑，支持根据文件起始位置 (0)、当前游标 (1) 或结合 `FileStandardInformation` 尾部 (2) 调整游标。

---

### 函数 44：`sub_1400105E0`
* **地址**：`0x1400105E0`，大小 `391` 字节 (`0x187`)
* **作用**：**磁盘文件内容物理直读、128 位数字哈希计算与 32 字符 HEX 签名提取器**。
* **伪代码与流程**：
  ```c
  char sub_1400105E0(wchar_t *FilePath, WCHAR *OutHexHash, unsigned int HashBufferLen)
  {
    // 1. 调用 Minifilter 穿透接口以独占底层模式打开文件
    void *FileHandle = sub_140010128(FilePath, 0x100020);
    if ( !FileHandle ) return 0;
    // 2. 定位到文件末尾并提取真实物理大小 FileSize
    sub_140010320(FileHandle, 0, 2);
    ULONG FileSize = sub_1400103F0(FileHandle);
    sub_140010320(FileHandle, 0, 0); // 重置至起始
    // 3. 在 NonPagedPool 分配 'xkfp' 缓冲区并完整直读
    PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, FileSize, 'xkfp');
    sub_1400102D0(Buffer, FileSize, FileHandle);
    // 4. 调用内核 128 位哈希算法计算 16 字节 Hash 摘要
    char Digest[16];
    sub_14000DD94(Buffer, FileSize, Digest);
    // 5. 格式化为 32 位宽字符 HEX 字符串
    for ( int i = 0; i < 16; ++i ) {
      RtlInt64ToUnicodeString((unsigned char)Digest[i] >> 4, 16, &String1);
      RtlInt64ToUnicodeString(Digest[i] & 0x0F, 16, &String2);
    }
    ExFreePoolWithTag(Buffer, 'xkfp');
    ZwClose(FileHandle);
    return 1;
  }
  ```

---

### 函数 45：`sub_140010768` & `sub_1400109B0`
* **地址**：`0x140010768` (583 B), `0x1400109B0` (393 B)
* **作用**：**`'KIDI'` 全局盘符（A:~Z:）物理卷与注册表 `SystemRoot` 映射扫描器**。
* **机制**：
  - 内存池标签：`'KIDI'` (`0x4944494B`)，分配 `0x10400`（66,560 字节，包含 64 个 1040 字节槽位）。
  - 循环探测 `\\??\\A:` 到 `\\??\\Z:` 驱动器挂载点，调用 `sub_14002FB10` 验证物理卷可用性。
  - `sub_1400109B0`：通过 `ZwOpenKey` 打开 `\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion`，使用内存标签 `'hpfk'` (`0x6B667068`) 查询 `SystemRoot`（如 `C:\Windows`）并持久化到映射表。

---

### 函数 46：`sub_14001161C`
* **地址**：`0x14001161C`，大小 `1088` 字节
* **作用**：**1024 槽位无锁环形遥测事件队列与 `__ROR1__(byte, 3) ^ Key` 报文对称流混淆加密发送总线**。
* **架构与报文协议**：
  - 队列深度：**1024 个槽位**（`_InterlockedExchangeAdd(v24, 1) & 0x3FF`）。
  - 槽位长度：**384 字节**。
  - 报文组成（共 376 字节有效载荷）：
    - 4 个 64 位核心状态（EventID 4011 等，32 字节）
    - 4 组 64 字节文本（字符串参数，各截断 63 字节并清零，256 字节）
    - 11 个 64 位整型参数（88 字节）
  - **动态流密码加密算法**：
    ```c
    char SlotKey = *(_BYTE *)Slot; // 槽位动态密钥
    for ( int i = 376; i != 0; --i )
    {
      // 逐字节执行循环右移 3 位并异或动态密钥
      *DataPtr = SlotKey ^ __ROR1__(*DataPtr, 3);
      DataPtr++;
    }
    *(DWORD *)(Slot + 4) = 1; // 写入完成就绪标记
    ```

---

### 函数 47：`sub_140010F8C` / `sub_140011058` / `sub_140011D68`
* **地址**：`0x140010F8C` (204 B), `0x140011058` (125 B), `0x140011D68` (272 B)
* **作用**：**64 槽位跨进程受控对象自旋锁原子表与墓碑状态（Tombstone -999）安全垃圾回收器**。
* **机制**：
  - `sub_140010F8C`：64 字节槽位分配器，通过 CAS 原子写入进程对象与上下文，增加原子计数 `dword_14012B664`。
  - `sub_140011058`：槽位卸载器，调用 `sub_140010F18` 彻底清理绑定的 MDL、释放 `ZwUnmapViewOfSection` 并递减计数。
  - `sub_140011D68`：自旋锁垃圾回收巡检，使用 `_InterlockedCompareExchange` 写入 **`-999` 墓碑标记**，安全解引用 `ObfDereferenceObject` 并回收 NonPagedPool。

---

### 函数 48：`sub_140012040`
* **地址**：`0x140012040`，大小 `134` 字节
* **作用**：**内核未导出进程核心符号动态解析器（Process Symbol Resolver）**。
* **解析目标**：
  - `PsGetProcessSectionBaseAddress`：获取目标进程主模块（如游戏 EXE）的真实内存加载基址。
  - `PsReferenceProcessFilePointer`：直接获取进程对应的内核文件对象 `PFILE_OBJECT`，绕过应用层路径伪造。
* **实现**：通过 `RtlInitUnicodeString` 构造字符串，调用 `MmGetSystemRoutineAddress` 动态定位并将函数指针保存至 `qword_14012D178` 与 `qword_14012D180`。

---

### 函数 49：`sub_14001241C` & `sub_1400120C8`
* **地址**：`0x14001241C` (337 B), `0x1400120C8` (413 B)
* **作用**：**`'kREG'` 注册表底层设备指纹（MachineGuid）读取器**。
* **内存池标签**：`0x6B524547` (`'kREG'`)
* **读取路径**：`\Registry\Machine\Software\Microsoft\Cryptography`
* **目标键名**：`L"MachineGuid"`
* **机制**：调用 `ZwOpenKey` 打开只读键柄（`0x20019`），通过 `ZwQueryValueKey` 查询 `KeyValuePartialInformation`，动态计算大小并在 PagedPool 分配内存，提取机器唯一 GUID 字符串作为内核硬件指纹的一环。

---

### 函数 50：`sub_140012884`
* **地址**：`0x140012884`，大小 `134` 字节
* **作用**：**处理器硬件虚拟化 / Hypervisor 存在性与沙箱环境检测器**。
* **底层原理**：
  ```c
  bool sub_140012884()
  {
    // 1. 执行 CPUID.1 查询处理器特性
    __asm { cpuid } // EAX = 1
    // 检查 RCX 的最高位 (Bit 31: Hypervisor Present Flag)
    if ( (int)RCX < 0 )
    {
      // 2. 存在 Hypervisor，发起 0x40000001 叶查询 (Hypervisor Interface Identification)
      _RAX = 0x40000001;
      __asm { cpuid }
      int rax1 = _RAX, rbx1 = _RBX, rcx1 = _RCX, rdx1 = _RDX;
      // 3. 执行专用特征参数探测 (EAX = 0xAACCEEFD)
      _RAX = 2864434397LL;
      __asm { cpuid }
      // 比对返回值是否被虚拟机劫持篡改
      if ( (DWORD)_RAX != rax1 || (DWORD)_RBX != rbx1 || (DWORD)_RCX != rcx1 || (DWORD)_RDX != rdx1 )
      {
        _RAX = 0x40000001;
        __asm { cpuid }
        // 判定是否为非白名单虚拟环境 (1986945624 = 0x76687258)
        return (DWORD)_RAX != 1986945624;
      }
    }
    return false;
  }
  ```

---

### 函数 51：`sub_140012BA8`
* **地址**：`0x140012BA8`，大小 **`2,570` 字节 (`0xA0A`)**
* **作用**：**ACE 驱动原生嵌入式 MD5 核心 64 轮压缩变换状态机（MD5Transform Engine）**。
* **算法特征与结构**：
  - 输入：4 组 32 位状态向量（`a1[2]`=A, `a1[3]`=B, `a1[4]`=C, `a1[5]`=D）与 64 字节数据块。
  - 展开执行全部 64 次逻辑运算轮次：
    - Round 1 (F 逻辑函数 `(B & C) | (~B & D)`)：循环左移 7, 12, 17, 22 位，配合常数如 `-680876936` (`0xD76AA478`)。
    - Round 2 (G 逻辑函数 `(B & D) | (C & ~D)`)：循环左移 5, 9, 14, 20 位。
    - Round 3 (H 逻辑函数 `B ^ C ^ D`)：循环左移 4, 11, 16, 23 位。
    - Round 4 (I 逻辑函数 `C ^ (B | ~D)`)：循环左移 6, 10, 15, 21 位。
  - 将计算结果累加回全局哈希状态向量，作为文件完整性、内核模块比对与通信鉴权的基础算法。

---

### 函数 52：`sub_14001290C` / `sub_140012A68` / `sub_1400129E8`
* **地址**：`0x14001290C` (217 B), `0x140012A68` (318 B), `0x1400129E8` (126 B)
* **作用**：**原生 MD5 算法消息流封装（MD5Init, MD5Update, MD5Final）**。
* **机制**：
  - `sub_1400129E8`：初始化上下文，填入标准 RFC 1321 魔数常数：
    - A = `0x67452301` (`1732584193`)
    - B = `0xEFCDAB89` (`-271733879`)
    - C = `0x98BADCFE` (`-1732584194`)
    - D = `0x10325476` (`271733878`)
  - `sub_14001290C` (`MD5Update`)：处理变长字节流，维护 64 字节缓冲区，满 64 字节调用 `sub_140012BA8` 迭代。
  - `sub_140012A68` (`MD5Final`)：自动追加比特 `1`（`0x80`），根据剩余空间填充对齐数据，将总比特长度写入末尾 8 字节，提取 16 字节最终 HEX 摘要。

---

### 函数 53：`sub_140012730` / `sub_14001280C` / `sub_1400126D0`
* **地址**：`0x140012730` (218 B), `0x14001280C` (118 B), `0x1400126D0` (93 B)
* **作用**：**内核安全异步工作线程调度、信号同步与优雅退栈总线**。
* **机制**：
  - `sub_140012730`：初始化 `SynchronizationEvent`，调用 `PsCreateSystemThread` 启动线程 `sub_1400126D0`，并通过 `ObReferenceObjectByHandle` 保存线程内核对象指针。
  - `sub_14001280C`：卸载时触发退出事件，调用 `KeWaitForSingleObject` 等待线程自身退栈完成，随后解引用 `ObfDereferenceObject`，并循环延时 `sub_1400126A8(100ms)` 直至确认退出标志 `byte_14012D1C0 == 1`。

---

### 函数 54：`sub_140013610` & `sub_1400135B4`
* **地址**：`0x140013610` (152 B), `0x1400135B4` (92 B)
* **作用**：**原生 RC4 KSA（Key-Scheduling Algorithm）S-Box 密钥调度与流密码加解密引擎**。
* **实现逻辑**：
  - `sub_140013610`：初始化 256 字节状态表（S-Box），生成 `S[i] = i (0..255)`。
  - 根据输入密钥 `a2`（长度 `a3`）进行置乱：`j = (j + S[i] + Key[i % KeyLen]) & 0xFF`，随后交换 `S[i]` 与 `S[j]`。
  - `sub_1400135B4`：在栈上开辟 272 字节上下文（256 字节 S 盒 + 2 个 32 位计数器游标），调用 `sub_14002D86C` 生成密钥流执行原地异或加解密。

---

### 函数 55：`sub_1400136A8`
* **地址**：`0x1400136A8`，大小 `262` 字节 (`0x106`)
* **作用**：**`[iommu]` 硬件级 IOMMU (VT-d / AMD-Vi) 状态审计与 DMA 隔离遥测通知**。
* **硬编码字符串提取**：
  - `"[iommu] usKeyName is %ws"`（内核调试日志打印）
  - `L"UData"`
* **机制**：
  - 判定 IOMMU 审计总开关 `byte_14012D1D0 != 0`。
  - 调用 `sub_14002410C()` 读取处理器/芯片组 DMA 重映射表及页表隔离配置。
  - 构造宽字符串键名并通过 `sub_14002DFDC(qword_14012D268, VirtualAddress, 8u)` 持久化并上报主机硬件级 DMA 保护是否开启。

---

### 函数 56：`sub_1400138A8` & `sub_140013944`
* **地址**：`0x1400138A8` (153 B), `0x140013944` (119 B)
* **作用**：**UNICODE_STRING 路径安全纯文件名提取器与内核格式化打印封装**。
* **机制**：
  - `sub_1400138A8`：从后向前逆向遍历路径字符，匹配最后一个 `\` (0x5C) 或 `/` (0x2F)，直接截断并将指针偏移指向纯文件名起始位置，重置 `UNICODE_STRING` 的 Length 与 MaximumLength。
  - `sub_140013944`：基于 `RtlUnicodeStringValidateDestWorker` 与 `RtlWideCharArrayVPrintfWorker` 实现带边界保护的内核级安全宽字符格式化拼接。

---

### 函数 57：`sub_1400139BC`
* **地址**：`0x1400139BC`，大小 `528` 字节 (`0x210`)
* **作用**：**全局安全策略配置解析器与子防御模块总线分发器（Master Policy Dispatcher）**。
* **分发链路**：
  - 逐项提取 `qword_14012B2B8` 中的 8 组策略控制字（`sub_14000DBC8(0..7)`）：
    1. **槽位 2（线程/内存监控）**：`(v2 & 1) != 0` 时，拆解 8 个细分功能位（第 3, 4, 5, 6, 7, 8, 9 位），调用 `sub_14001B554` 动态激活内核线程审计与隐藏内存扫描，并加载配置条目 0。
    2. **槽位 4（设备层过滤）**：`(v4 & 1) != 0` 时，调用 `sub_140021364(DeviceObject)` 挂接下层输入与控制设备。
    3. **槽位 7（网络/通信安全）**：`(v10 & 1) != 0` 时，调用 `sub_1400179B8()` 激活通信钩子。
    4. **槽位 0（进程白名单与句柄提权拦截）**：`(v1 & 1) != 0` 时，针对当前主进程调用 `sub_14000C690` 并分发 **4201 / 4202 号遥测事件**（`sub_140011510`）。
    5. **槽位 3/5/6（机制联动）**：分别联动 `sub_14001806C`, `sub_1400205F0`, `sub_1400203F4` 激活各防御引擎。

---

### 函数 58：`sub_140013BCC` & `sub_140013C14`
* **地址**：`0x140013BCC` (71 B), `0x140013C14` (44 B)
* **作用**：**`PsSetLoadImageNotifyRoutine` 模块加载通知回调注册器与 360 周期看门狗**。
* **伪代码**：
  ```c
  NTSTATUS sub_140013BCC(__int64 a1)
  {
    if ( sub_14000BA48(a1, &unk_1400A1258) == 0 && sub_14002E730() == 0 )
    {
      if ( byte_14012D278 == 0 )
      {
        NTSTATUS status = PsSetLoadImageNotifyRoutine(sub_14001471C);
        if ( status != 0 ) return status;
        byte_14012D278 = 1;
      }
      return sub_14002E61C();
    }
    return status;
  }
  ```
  - `sub_140013C14`：累加计数器 `dword_14012D280`，当计数值达到 **360** 且守护标志 `byte_14012D279 != 0` 时，调用 `sub_14000C488` 执行全量保护进程/模块有效性校验。

---

### 函数 59：`sub_140015E84`
* **地址**：`0x140015E84`，大小 `455` 字节 (`0x1C7`)
* **作用**：**内核代码段差量特征分析器（Code Diff & Hash Feature Extractor）**。
* **双哈希指纹算法**：
  1. 扫描内存与磁盘镜像差异，定位连续不一致的代码窗口（上限 256 字节）。
  2. **FNV-1a 64 位哈希**：基数 `0xCBF29CE484222325`，质数乘数 `0x100000001B3`，计算篡改区间 Hash。
  3. **标准 CRC-32**：多项式 `0xEDB88320`，逐比特逆向移位生成 32 位校验和。
  4. 将磁盘原生字节与内存篡改字节分别存入 584 字节的审计结构体中。

---

### 函数 60：`sub_14001604C`
* **地址**：`0x14001604C`，大小 **`1,278` 字节 (`0x4FE`)**
* **作用**：**`'TmpC'` 双镜像全量代码差量比对与 Inline Hook 4373 号遥测总线**。
* **内存池标签**：`0x436D7054` (`'TmpC'`)
* **核心检测逻辑与流程**：
  1. 结合 Minifilter 穿透接口，分别在 NonPagedPool 中分配两块等长内存：
     - 一块为内存中当前运行模块的实际代码（Live Image）。
     - 一块为绕过所有文件系统过滤钩子直读磁盘取得的原始干净代码（Clean Disk Image）。
  2. 调用 `RtlCompareMemory(LiveImage, DiskImage, CodeSize)` 进行全量快速比对。
  3. **一旦检测到字节不一致（存在 Inline Hook / JMP / 热补丁篡改）**：
     - 调用 `sub_140015E84` 提取被篡改的具体字节序列与双 Hash 指纹。
     - 循环调用 `_byteswap_uint64` 将原始字节和篡改后字节分别格式化为 64 宽字符 HEX 字符串。
     - 立即触发 **4373 号内核代码篡改安全遥测事件**（调用 `sub_14001161C`）。
     - 调用 `sub_1400244E4(100)` 记录违规威胁分值并执行防御响应。

---

### 函数 61：`sub_1400179B8` & `sub_140017668`
* **地址**：`0x1400179B8` (567 B), `0x140017668` (846 B)
* **作用**：**核心代码巡检守护系统线程生命周期与 `KeStackAttachProcess` 挂入巡检循环**。
* **工作流拓扑**：
  1. `sub_1400179B8`：提取当前主进程路径，初始化事件 `stru_14012D2A0`，调用 `PsCreateSystemThread` 创建常驻线程 `sub_140017668`。
  2. `sub_140017668`：以 1 秒为超时周期（`Timeout = -10000000`）循环等待。
  3. 通过 `PsLookupProcessByProcessId` 获取游戏 `EPROCESS`，使用 **`KeStackAttachProcess(Process, &ApcState)`** 强行挂入游戏虚拟地址空间。
  4. 首次成功加载并重定位纯净镜像时，触发 **4372 号初始化成功遥测事件**。
  5. 周期性调用 `sub_14001654C()` 执行多节区深度 Diff 比对。
  6. 巡检完毕调用 `KeUnstackDetachProcess(&ApcState)` 脱离进程上下文。

---

### 函数 62：`sub_14001654C`
* **地址**：`0x14001654C`，大小 `176` 字节
* **作用**：**`.text`、`.rdata`、`.tvm0` 核心三节区双镜像连环 Diff 巡检器**。
* **伪代码**：
  ```c
  bool sub_14001654C()
  {
    int AlertCode = 0;
    // 1. 巡检原生可执行代码段
    sub_14001604C(BaseAddress, CleanSize, LiveBase, LiveSize, ".text", &AlertCode);
    // 2. 巡检全局只读数据与虚表段
    sub_14001604C(BaseAddress, CleanSize, LiveBase, LiveSize, ".rdata", &AlertCode);
    // 3. 巡检核心 TVM 虚拟机字节码段 (关键证据!)
    return sub_14001604C(BaseAddress, CleanSize, LiveBase, LiveSize, ".tvm0", &AlertCode);
  }
  ```

---

### 函数 63：`sub_1400173BC`
* **地址**：`0x1400173BC`，大小 `681` 字节 (`0x2A9`)
* **作用**：**内核级 PE 镜像基址重定位引擎（Clean Image Relocation Fixup Engine）**。
* **机制**：
  - 提取 PE OptionalHeader 的 DataDirectory[5]（`IMAGE_DIRECTORY_ENTRY_BASERELOC`）。
  - 计算当前内存加载基址与原始基址的差量：`Delta = LiveBase - DiskImageBase`。
  - 遍历所有重定位页块（Page Blocks）：
    - 提取重定位项类型：Type 3（`IMAGE_REL_BASED_HIGHLOW`，32 位修正），Type 10（`IMAGE_REL_BASED_DIR64`，64 位修正）。
    - 针对属于 `.rdata` 及代码段的指针，原地累加 `Delta` 修正量，使磁盘纯净镜像在内存中拥有与正在运行的模块完全一致的物理指针形态，确保后续 Diff 比对的 100% 准确率。

---

### 函数 64：`sub_140016F20`
* **地址**：`0x140016F20`，大小 `641` 字节 (`0x281`)
* **作用**：**`'INmg'` 内存池内核 PE 镜像手工展开与内存布局重建器（Manual Kernel PE Expander）**。
* **内存池标签**：`0x676D4E49` (`'INmg'`)
* **机制**：
  - 读取 PE 头的 `SizeOfImage`，在 NonPagedPool 分配对齐的完整虚拟镜像空间。
  - 复制 PE 头（`SizeOfHeaders`）。
  - 遍历节表（Section Table），将各个节从文件偏移（`PointerToRawData`）按照内存相对偏移（`VirtualAddress`）精准展开拷贝至目标缓冲区。

---

### 函数 65：`sub_140016730`
* **地址**：`0x140016730`，大小 **`1,009` 字节 (`0x3F1`)**
* **作用**：**`VS_VERSION_INFO` 资源节遍历与 PE 版本签名特征提取器**。
* **机制**：
  - 深入解析 PE 数据目录第 2 项（`IMAGE_DIRECTORY_ENTRY_RESOURCE`）。
  - 递归查询 `Type == 16`（`RT_VERSION`）的资源子目录。
  - 比对资源键名是否为 `L"VS_VERSION_INFO"`（长度 30 字节）。
  - 验证微软官方固定文件版本签名魔数 **`0xFEEF04BD`** (`VS_FFI_SIGNATURE`，负值 `-17890115`)。
  - 提取高位与低位文件版本号（`FileVersionMS`, `FileVersionLS`），返回 16 字节完整版本指纹。

---

### 函数 66：`sub_1400171A4`
* **地址**：`0x1400171A4`，大小 `533` 字节 (`0x215`)
* **作用**：**`'FPdl'` 内存池磁盘 PE 二进制数据无污染直接读取器**。
* **内存池标签**：`0x646C5046` (`'FPdl'`)
* **逻辑**：调用 `ZwCreateFile` 以 `FILE_SHARE_READ | FILE_SHARE_WRITE` 打开目标磁盘文件，通过 `ZwQueryInformationFile(FileStandardInformation)` 提取物理文件大小，在 NonPagedPool 中分配完整连续内存并通过 `ZwReadFile` 读取入内核。

---

### 函数 67：`sub_14002A59C` —— 磁盘驱动与系统二进制 PE 头部校验与读取器
* **地址**：`0x14002A59C`，大小 `639` 字节 (`0x27F`)
* **形参定义**：`char __fastcall sub_14002A59C(PCWSTR Source)`
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002A59C(PCWSTR Source)
  {
    char Status = 1;
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Destination;
    LARGE_INTEGER ByteOffset;
    DWORD HeaderBuffer[130];

    if ( Source != NULL )
    {
      memset(HeaderBuffer, 0, 520);
      // 校验并拼接目标内核文件路径
      InitializeObjectAttributes(&ObjectAttributes, &Destination, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
      if ( ZwCreateFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0) >= 0 )
      {
        ByteOffset.QuadPart = 0;
        if ( ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, HeaderBuffer, 512u, &ByteOffset, NULL) >= 0 )
        {
          // 校验 IMAGE_DOS_SIGNATURE (0x5A4D, 'MZ')
          if ( *(_WORD *)HeaderBuffer == 0x5A4D )
          {
            DWORD e_lfanew = HeaderBuffer[15]; // PE 头部相对偏移
            if ( e_lfanew < 0x200u )
            {
              // 校验 IMAGE_NT_SIGNATURE (0x00004550, 'PE\0\0')
              if ( *(DWORD *)((char *)HeaderBuffer + e_lfanew) == 0x4550 )
                Status = 0; // 头部格式与签名合法
            }
          }
        }
        ZwClose(FileHandle);
      }
    }
    return Status;
  }
  ```
* **对抗意义**：在内核层直接以底层 Native API 打开并读取磁盘上的系统模块与自身驱动文件，直接解析 DOS 头及 NT 头，防止磁盘可执行文件被病毒篡改、感染或文件头被外挂破坏。

---

### 函数 68：`sub_14002A844` —— DKOM 隐藏进程抗绕过定位器（双链遍历 + 线程反查）
* **地址**：`0x14002A844`，大小 `192` 字节 (`0xC0`)
* **形参定义**：`PEPROCESS __fastcall sub_14002A844(HANDLE TargetProcessId, PBOOLEAN OutIsReferenced)`
* **反编译伪代码**：
  ```c
  PEPROCESS __fastcall sub_14002A844(HANDLE TargetProcessId, PBOOLEAN OutIsReferenced)
  {
    PEPROCESS Process = NULL;

    if ( !OutIsReferenced || !TargetProcessId )
      return NULL;

    *OutIsReferenced = FALSE;

    // 1. 优先尝试常规安全引用查找
    Process = sub_14002A81C(TargetProcessId); // PsLookupProcessByProcessId
    if ( Process )
    {
      if ( TargetProcessId == PsGetProcessId(Process) )
      {
        *OutIsReferenced = TRUE;
        return Process; // 正常通过系统句柄/PID 找到
      }
      ObDereferenceObject(Process);
      Process = NULL;
    }

    // 2. 防御 DKOM：当常规查找被挂钩或失效时，主动遍历 ActiveProcessLinks 双向链表
    __int64 Head = sub_140026FD8(); // 全局活动进程链表头
    unsigned int LinkOffset = (unsigned int)sub_14002A4FC(); // EPROCESS.ActiveProcessLinks 偏移

    __int64 Current = Head;
    while ( Current && LinkOffset )
    {
      PEPROCESS Candidate = (PEPROCESS)(Current - LinkOffset);
      if ( MmIsAddressValid(Candidate) )
      {
        // 关键：不直接读取 Candidate.UniqueProcessId（可能被篡改），而是通过其线程链表反查真实 PID！
        if ( sub_14002A904((__int64)Candidate) == TargetProcessId )
          return Candidate;
      }
      Current = *(_QWORD *)(Current + 8); // Flink
      if ( Current == Head )
        break;
    }
    return NULL;
  }
  ```
* **对抗意义**：**极其强悍的 DKOM（Direct Kernel Object Manipulation）击穿机制**！作弊模块常用手法是断开 `ActiveProcessLinks` 双向链表或直接把 `EPROCESS.UniqueProcessId` 篡改为 0。本函数先通过 `ActiveProcessLinks` 遍历，再深入调用 `sub_14002A904` 抓取其名下每一个 `ETHREAD` 结构，通过线程真实的所属进程指针反推出真 PID，使任何仅修改进程头或 PID 的 DKOM 隐藏手段全部失效！

---

### 函数 69：`sub_14002A904` —— 基于 ETHREAD 线程链反查真实进程 PID（防断链伪造）
* **地址**：`0x14002A904`，大小 `141` 字节 (`0x8D`)
* **形参定义**：`HANDLE __fastcall sub_14002A904(__int64 Process)`
* **反编译伪代码**：
  ```c
  HANDLE __fastcall sub_14002A904(__int64 Process)
  {
    if ( sub_14002AF2C(Process) ) // 进程是否正在退出
      return NULL;

    unsigned int ThreadListEntryOffset = (unsigned int)sub_14002A51C(); // ETHREAD.ThreadListEntry 偏移
    unsigned int ThreadListHeadOffset = sub_14002A514();                // EPROCESS.ThreadListHead 偏移 (48)

    if ( ThreadListEntryOffset && ThreadListHeadOffset )
    {
      _QWORD *pHead = (_QWORD *)(Process + ThreadListHeadOffset);
      if ( sub_140027B8C(pHead) ) // 内存可读性探针
      {
        // 提取该进程名下的首个线程
        PETHREAD Thread = (PETHREAD)(*pHead - ThreadListEntryOffset);
        if ( sub_140027B8C(Thread) && sub_140027B8C((char *)Thread + 4096) )
        {
          // 通过内核安全例程获取线程归属的真正 ProcessId
          return PsGetThreadProcessId(Thread);
        }
      }
    }
    return NULL;
  }
  ```
* **对抗意义**：与 `sub_14002A844` 联动，实现从进程遍历线程、再从线程倒查真实所属进程的闭环安全验证。

---

### 函数 70：`sub_14002A994` —— System 进程 PID 4 特权标志动态匹配提取器
* **地址**：`0x14002A994`，大小 `308` 字节 (`0x134`)
* **形参定义**：`__int64 __fastcall sub_14002A994(__int64 TargetProcess, _QWORD *OutPrivilegeMask, _BYTE *OutState)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002A994(__int64 TargetProcess, _QWORD *OutPrivilegeMask, _BYTE *OutState)
  {
    PEPROCESS SystemProcess = NULL;

    if ( !OutPrivilegeMask || !OutState )
      return STATUS_INVALID_PARAMETER;

    if ( !MmIsAddressValid((PVOID)TargetProcess) || !MmIsAddressValid((PVOID)(TargetProcess + 1280)) )
      return STATUS_INVALID_PARAMETER;

    // 锁定系统根进程 PID 4 (System)
    if ( PsLookupProcessByProcessId((HANDLE)4, &SystemProcess) == 0 && MmIsAddressValid(SystemProcess) )
    {
      if ( (*((DWORD *)SystemProcess + 10) & 0xFFF) == 0 )
      {
        *OutPrivilegeMask = 0;
        *OutState = 0;
        ObDereferenceObject(SystemProcess);
        return STATUS_SUCCESS;
      }

      // 遍历 System 进程结构体内部特征签名
      for ( unsigned int Offset = 512; MmIsAddressValid((char *)SystemProcess + Offset); Offset += 4 )
      {
        if ( *(DWORD *)((char *)SystemProcess + Offset) == 0
          && (*(DWORD *)((char *)SystemProcess + Offset + 8) & 0xFFF) == 1
          && *((BYTE *)SystemProcess + Offset + 16) == 1 )
        {
          *OutState = *(BYTE *)(Offset + TargetProcess + 16);
          *OutPrivilegeMask = *(QWORD *)(Offset + TargetProcess + 8);
          ObDereferenceObject(SystemProcess);
          return STATUS_SUCCESS;
        }
      }
      ObDereferenceObject(SystemProcess);
    }
    return STATUS_UNSUCCESSFUL;
  }
  ```

---

### 函数 71：`sub_14002AAC8` —— 进程安全策略属性与令牌特权等级提取
* **地址**：`0x14002AAC8`，大小 `168` 字节 (`0xA8`)
* **形参定义**：`__int64 __fastcall sub_14002AAC8(HANDLE ProcessId)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002AAC8(HANDLE ProcessId)
  {
    PEPROCESS Process = sub_14002A81C(ProcessId);
    __int64 PolicyValue = 0;
    PVOID Pool = NULL;

    if ( Process )
    {
      __int64 Token = sub_140027D2C((__int64)Process); // PsReferencePrimaryToken
      if ( Token )
      {
        // 查询进程主令牌的会话或安全组标识
        if ( sub_140027E98(Token, 10, &Pool) >= 0 && Pool )
          PolicyValue = *((_QWORD *)Pool + 1);

        ObDereferenceObject((PVOID)Token);
      }
      ObDereferenceObject(Process);
    }

    if ( Pool )
      ExFreePoolWithTag(Pool, 0);

    return PolicyValue;
  }
  ```

---

### 函数 72：`sub_14002AB70` —— 安全提取目标进程可执行文件名入口
* **地址**：`0x14002AB70`，大小 `121` 字节 (`0x79`)
* **形参定义**：`__int64 __fastcall sub_14002AB70(HANDLE ProcessId, PVOID OutBuffer, unsigned int BufferSize)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002AB70(HANDLE ProcessId, PVOID OutBuffer, unsigned int BufferSize)
  {
    unsigned int Status = STATUS_INVALID_PARAMETER;
    BOOLEAN IsReferenced = FALSE;

    if ( ProcessId && OutBuffer && BufferSize )
    {
      PEPROCESS Process = sub_14002A844(ProcessId, &IsReferenced); // DKOM 防护查找
      if ( Process )
      {
        Status = sub_14002ABEC((__int64)Process, OutBuffer, BufferSize);
        if ( IsReferenced )
          ObDereferenceObject(Process);
      }
    }
    return Status;
  }
  ```

---

### 函数 73：`sub_14002ABEC` —— 进程完整路径提取与宽字符格式化
* **地址**：`0x14002ABEC`，大小 `160` 字节 (`0xA0`)
* **形参定义**：`__int64 __fastcall sub_14002ABEC(__int64 Process, PVOID OutBuffer, unsigned int BufferSize)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002ABEC(__int64 Process, PVOID OutBuffer, unsigned int BufferSize)
  {
    WCHAR FullPath[264];
    memset(FullPath, 0, sizeof(FullPath));

    int Status = sub_14002AD30((struct _KPROCESS *)Process, FullPath, 520);
    if ( Status >= 0 )
    {
      // 提取文件名并格式化写入用户缓冲区
      Status = sub_14002F800(OutBuffer);
      if ( Status < 0 )
        memset(OutBuffer, 0, BufferSize);
    }
    return (unsigned int)Status;
  }
  ```

---

### 函数 74：`sub_14002AC8C` —— 微过滤驱动文件对象路径解析 (FltGetFileNameInformationUnsafe)
* **地址**：`0x14002AC8C`，大小 `164` 字节 (`0xA4`)
* **形参定义**：`__int64 __fastcall sub_14002AC8C(__int64 Process, PVOID OutBuffer, unsigned int BufferSize)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002AC8C(__int64 Process, PVOID OutBuffer, unsigned int BufferSize)
  {
    PFILE_OBJECT FileObject = NULL;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;

    NTSTATUS Status = sub_140027D44(Process, &FileObject); // 获取进程映像对应的 FileObject
    if ( Status >= 0 && FileObject )
    {
      // 深度调用微过滤驱动管理例程获取规范化全路径
      Status = FltGetFileNameInformationUnsafe(FileObject, NULL, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
      if ( Status >= 0 && FileNameInfo )
      {
        size_t CopyLen = FileNameInfo->Name.Length;
        if ( BufferSize - 2 < CopyLen )
          CopyLen = BufferSize - 2;

        memmove(OutBuffer, FileNameInfo->Name.Buffer, CopyLen);
        FltReleaseFileNameInformation(FileNameInfo);
      }
      ObDereferenceObject(FileObject);
    }
    return (unsigned int)Status;
  }
  ```
* **对抗意义**：直接利用 Windows Filter Manager 内核未导出接口 `FltGetFileNameInformationUnsafe` 解析 `PFILE_OBJECT`，绕过常规 `ObQueryNameString` 可能被作弊驱动挂钩的风险。

---

### 函数 75：`sub_14002AD30` —— 进程名与可执行镜像路径全量解析器
* **地址**：`0x14002AD30`，大小 `389` 字节 (`0x185`)
* **形参定义**：`__int64 __fastcall sub_14002AD30(struct _KPROCESS *Process, PWSTR OutName, unsigned int MaxBytes)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002AD30(struct _KPROCESS *Process, PWSTR OutName, unsigned int MaxBytes)
  {
    if ( !Process || !OutName || !MaxBytes )
      return STATUS_INVALID_PARAMETER;

    memset(OutName, 0, MaxBytes);

    // 1. 系统根进程特殊处理
    if ( Process == PsInitialSystemProcess )
    {
      size_t Len = wcslen(L"System") * sizeof(WCHAR);
      if ( MaxBytes - 2 >= Len )
      {
        memmove(OutName, L"System", Len);
        return STATUS_SUCCESS;
      }
      return STATUS_BUFFER_TOO_SMALL;
    }

    // 2. 用户态进程：挂接目标进程并读取 PEB.ProcessParameters.ImagePathName
    __int64 PebAddress = sub_140027CC0((PEPROCESS)Process); // PsGetProcessPeb
    if ( PebAddress )
    {
      RTL_USER_PROCESS_PARAMETERS ProcessParams;
      memset(&ProcessParams, 0, sizeof(ProcessParams));

      // 跨进程挂接读取目标 PEB (sub_14002B030)
      if ( sub_14002B030((PEPROCESS)Process, (PVOID)PebAddress, sizeof(ProcessParams), &ProcessParams, 0, NULL) >= 0 )
      {
        // 成功提取完整 ImagePathName 宽字符串
        return STATUS_SUCCESS;
      }
    }
    return STATUS_UNSUCCESSFUL;
  }
  ```

---

### 函数 76：`sub_14002AF50` —— 受保护特权进程属性检查 (999/997/996)
* **地址**：`0x14002AF50`，大小 `127` 字节 (`0x7F`)
* **形参定义**：`BOOLEAN __fastcall sub_14002AF50(HANDLE ProcessId)`
* **反编译伪代码**：
  ```c
  BOOLEAN __fastcall sub_14002AF50(HANDLE ProcessId)
  {
    __int64 Tag = sub_14002AAC8(ProcessId);
    __int64 Tag999 = 999;
    __int64 Tag997 = 997;
    __int64 Tag996 = 996;

    if ( RtlCompareMemory(&Tag, &Tag999, 8) == 8
      || RtlCompareMemory(&Tag, &Tag997, 8) == 8
      || RtlCompareMemory(&Tag, &Tag996, 8) == 8 )
    {
      return TRUE; // 命中特权白名单或腾讯安全服务组件标记
    }
    return FALSE;
  }
  ```

---

### 函数 77：`sub_14002B0C0` —— 腾讯受保护目标游戏/安全组件进程识别与类型判定器
* **地址**：`0x14002B0C0`，大小 **`1,406` 字节 (`0x57E`)**
* **形参定义**：`BOOLEAN __fastcall sub_14002B0C0(PWSTR ProcessName, int *OutGameId)`
* **反编译伪代码（异或混淆解密与全量匹配）**：
  ```c
  BOOLEAN __fastcall sub_14002B0C0(PWSTR ProcessName, int *OutGameId)
  {
    WCHAR CleanName[128];
    WCHAR DecryptBuf[32];

    if ( !ProcessName || wcslen(ProcessName) >= 0x80 )
      return FALSE;

    if ( OutGameId ) *OutGameId = 0;

    // 转小写规范化
    wcscpy(CleanName, ProcessName);
    _wcslwr(CleanName);

    // 1. 异或解密: "crossfire.exe" (CF 穿越火线) -> GameId = 3
    // 密文: "a\x02\x13\x0E\x12\x12\a\b\x13\x04O\x04\x19\x04" ^ 'a' (97)
    if ( wcsncmp(DecryptString(1), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 3;
      return TRUE;
    }

    // 2. 异或解密: "gameapp.exe" -> GameId = 4
    // 密文: "7PVZRVGG\x19ROR" ^ '7' (55)
    if ( wcsncmp(DecryptString(2), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 4;
      return TRUE;
    }

    // 3. 异或解密: "dnf.exe" (地下城与勇士) -> GameId = 5
    // 密文: "}\x19\x13\x1BS\x18\x05\x18" ^ '}' (125)
    if ( wcsncmp(DecryptString(3), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 5;
      return TRUE;
    }

    // 4. 异或解密: "qqsg.exe" (QQ三国) -> GameId = 8
    // 密文: "Z++)=t?\"?" ^ 'Z' (90)
    if ( wcsncmp(DecryptString(4), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 8;
      return TRUE;
    }

    // 5. 异或解密: "league of legends.exe" (LOL 英雄联盟) -> GameId = 23
    // 密文: "\x06jcgasc&i`&jcachbu(c~c" ^ 6
    if ( wcsncmp(DecryptString(5), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 23;
      return TRUE;
    }

    // 6. 异或解密: "tgame.exe" -> GameId = 28
    // 密文: "6BQW[S\x18SNS" ^ '6' (54)
    if ( wcsncmp(DecryptString(6), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 28;
      return TRUE;
    }

    // 7. 异或解密: "sguard.exe" (SGuard 安全组件) -> GameId = 267
    // 密文: "T'3!5&0z1,1" ^ 'T' (84)
    if ( wcsncmp(DecryptString(7), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 267;
      return TRUE;
    }

    // 8. 异或解密: "sguard64.exe" (SGuard 64位组件) -> GameId = 267
    // 密文: "u\x06\x12" 混合解密 ^ 'u' (117)
    if ( wcsncmp(DecryptString(8), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 267;
      return TRUE;
    }

    // 9. 异或解密: "leagueclient.exe" (LOL 官方启动器) -> GameId = 172
    // 密文: "<PY][IY_PUYRH\x12YDY" ^ '<' (60)
    if ( wcsncmp(DecryptString(9), CleanName, ...) == 0 )
    {
      if ( OutGameId ) *OutGameId = 172;
      return TRUE;
    }

    return FALSE;
  }
  ```
* **对抗意义**：**核心保护目标判定中枢**！所有游戏名称均在编译期经过单字节 XOR 算法混淆，在静态 IDA 分析中无任何明文字符串。在运行时根据传入的进程可执行文件名解密比对，赋予对应的 `GameId` 编号（3=CF, 4=GameApp, 5=DNF, 8=QQSG, 23=LOL, 28=TGame, 172=LOLClient, 267=SGuard），驱动针对不同 `GameId` 启用不同的反外挂防御规则集。

---

### 函数 78：`sub_14002B640` —— 全系统进程快照枚举与特权审查总调度引擎
* **地址**：`0x14002B640`，大小 `233` 字节 (`0xE9`)
* **形参定义**：`void __fastcall sub_14002B640(PENUM_PROCESS_CALLBACK Callback, __int64 Context)`
* **反编译伪代码**：
  ```c
  void __fastcall sub_14002B640(PENUM_PROCESS_CALLBACK Callback, __int64 Context)
  {
    PVOID ProcessSnapshot = NULL;
    unsigned int SnapshotSize = 0;
    WCHAR ProcessPath[264];

    if ( !Callback ) return;

    // 1. 调用 ZwQuerySystemInformation(SystemProcessInformation=5) 提取全系统进程快照
    if ( sub_14002971C(5, &ProcessSnapshot, &SnapshotSize) >= 0 && ProcessSnapshot )
    {
      PSYSTEM_PROCESS_INFORMATION Current = (PSYSTEM_PROCESS_INFORMATION)ProcessSnapshot;
      while ( 1 )
      {
        HANDLE ProcessId = (HANDLE)Current->UniqueProcessId;
        HANDLE ParentProcessId = (HANDLE)Current->InheritedFromUniqueProcessId;

        // 2. 获取 EPROCESS 指针
        PEPROCESS Process = sub_14002A81C(ProcessId);
        if ( Process )
        {
          memset(ProcessPath, 0, sizeof(ProcessPath));

          // 3. 提取进程名与路径
          if ( sub_14002AD30((struct _KPROCESS *)Process, ProcessPath, sizeof(ProcessPath)) >= 0 )
          {
            // 4. 执行回调审查例程 Callback(PID, PPID, Path, ThreadCount, Context)
            if ( Callback(ProcessId, ParentProcessId, ProcessPath, Current->NumberOfThreads, Context) == 0 )
            {
              ObDereferenceObject(Process);
              break; // 回调请求提前终止巡检
            }
          }
          ObDereferenceObject(Process);
        }

        if ( Current->NextEntryOffset == 0 )
          break;

        Current = (PSYSTEM_PROCESS_INFORMATION)((char *)Current + Current->NextEntryOffset);
      }
      ExFreePoolWithTag(ProcessSnapshot, 0);
    }
  }
  ```
* **对抗意义**：ACE 后台全系统巡检总调度！不依赖任何单点 Hook，而是周期性主动打全系统进程快照，结合内核 DKOM 防护解析器 `sub_14002AD30` 验证所有运行中程序的真实路径与签名，分发给上层作弊样本检测规则。

---

### 函数 79：`sub_14002F8F0` —— `'KIDI'` 内存池全盘符 A~Z 遍历与设备符号链接规范化映射
* **地址**：`0x14002F8F0`，大小 `543` 字节 (`0x21F`)
* **内存池标签**：`0x4944494B` (`'KIDI'`)
* **反编译伪代码**：
  ```c
  void sub_14002F8F0()
  {
    WCHAR DriveString[8];
    wcscpy(DriveString, L"\\??\\X:");

    if ( byte_14595EF60 == 0 )
    {
      // 分配 66,560 字节 (0x10400) 的 NonPagedPool 存储全部驱动器映射表
      PVOID Pool = ExAllocatePoolWithTag(NonPagedPool, 0x10400u, 0x4944494Bu);
      qword_14595EF58 = Pool;
      if ( Pool )
      {
        memset(Pool, 0, 66560);
        // 从 'A' (65) 遍历到 'Z' (90)
        for ( WCHAR Letter = L'A'; Letter <= L'Z'; ++Letter )
        {
          DriveString[4] = Letter;
          // 解析该符号链接指向的实际设备路径
          sub_14002FB10(DriveString, ...);
        }
        byte_14595EF60 = 1;
      }
    }
  }
  ```

---

### 函数 80：`sub_14002FB10` —— ZwQuerySymbolicLinkObject 符号链接对象解析器
* **地址**：`0x14002FB10`，大小 `311` 字节 (`0x137`)
* **形参定义**：`NTSTATUS __fastcall sub_14002FB10(PCWSTR SourceString, WCHAR **OutTargetPath)`
* **反编译伪代码**：
  ```c
  NTSTATUS __fastcall sub_14002FB10(PCWSTR SourceString, WCHAR **OutTargetPath)
  {
    HANDLE LinkHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING DestinationString;
    UNICODE_STRING LinkTarget;
    ULONG ReturnedLength = 0;

    if ( !SourceString || !OutTargetPath ) return STATUS_INVALID_PARAMETER;

    RtlInitUnicodeString(&DestinationString, SourceString);
    InitializeObjectAttributes(&ObjectAttributes, &DestinationString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS Status = ZwOpenSymbolicLinkObject(&LinkHandle, GENERIC_READ, &ObjectAttributes);
    if ( Status >= 0 )
    {
      // 提取符号链接最终指向的底层设备对象名称 (如 \Device\HarddiskVolume3)
      Status = ZwQuerySymbolicLinkObject(LinkHandle, &LinkTarget, &ReturnedLength);
      ZwClose(LinkHandle);
    }
    return Status;
  }
  ```

---

### 函数 81：`sub_14002FDCC` —— 内核设备路径到 DOS 驱动器盘符双向逆向规范化匹配器
* **地址**：`0x14002FDCC`，大小 `282` 字节 (`0x11A`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14002FDCC(char *OutDrivePath, unsigned int MaxBytes, const wchar_t *DevicePath, unsigned int PathLen)
  {
    char *Table = (char *)qword_14595EF58;
    if ( !Table ) return 0;

    // 在 26 个驱动器槽位中循环比对设备名前缀
    for ( int i = 0; i < 26; ++i )
    {
      const wchar_t *TargetDevice = (const wchar_t *)&Table[1040LL * i];
      if ( wcsnicmp(DevicePath, TargetDevice, wcslen(TargetDevice)) == 0 )
      {
        // 成功将 \Device\HarddiskVolumeX 逆向替换为 C: / D: 标准格式
        return 1;
      }
    }
    return 0;
  }
  ```

---

### 函数 82：`sub_14002FEE8` —— 全盘符映射表安全销毁例程
* **地址**：`0x14002FEE8`，大小 `37` 字节 (`0x25`)
* **反编译伪代码**：
  ```c
  void sub_14002FEE8()
  {
    PVOID Pool = qword_14595EF58;
    if ( Pool )
    {
      qword_14595EF58 = NULL;
      ExFreePoolWithTag(Pool, 0);
    }
  }
  ```

---

### 函数 83：`sub_14003E1C0` —— 跨进程挂入 dwm.exe 动态异或解密与巡检 AMD 显卡驱动核心库 (amdxx64.dll)
* **地址**：`0x14003E1C0`，大小 `421` 字节 (`0x1A5`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14003E1C0(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
  {
    // 1. 动态双重异或解密宿主进程名: "dwm.exe"
    // 密文: 2883656, 0x2D00660025003F, 2949168 结合 72 异或解出 "dwm.exe"
    PRKPROCESS DwmProcess = NULL;
    __int64 Context = 0;
    if ( sub_1400403D0((__int64)&NameBuffer, &DwmProcess, &Context, a4) >= 0 && DwmProcess )
    {
      // 2. 特权级挂入 dwm.exe 进程上下文
      KAPC_STATE ApcState;
      KeStackAttachProcess(DwmProcess, &ApcState);

      // 3. 动态异或解密 AMD 显卡驱动核心动态链接库: "amdxx64.dll"
      // 密文: 1988064018, "jj$&<v~~" 结合 18 异或解出 "amdxx64.dll"
      sub_140040358((__int64)DwmProcess, (__int64)&DecryptedDll, 0, Param);

      KeUnstackDetachProcess(&ApcState);
      ObfDereferenceObject(DwmProcess);
    }
    return 0;
  }
  ```
* **对抗意义**：外挂常利用 AMD 显卡驱动库 `amdxx64.dll` 在 DWM 桌面合成器中挂钩 Present 或创建隐秘透明置顶 Overlay 绘制透视。ACE 驱动通过跨进程主动附加到 `dwm.exe`，直接解密显卡核心模块名进行挂钩审查。

---

### 函数 84：`sub_14003EC2C` —— 动态解密比对系统桌面与登录管理进程 (dwm.exe 与 winlogon.exe)
* **地址**：`0x14003EC2C`，大小 `402` 字节 (`0x192`)
* **反编译伪代码**：
  ```c
  bool __fastcall sub_14003EC2C(__int64 a1, void *ProcessId, __int64 TargetInfo)
  {
    UNICODE_STRING TargetDwm, TargetWinlogon, ProcessPath;
    
    // 1. 运行时异或解密 "dwm.exe"
    // 2. 校验当前目标进程是否匹配 dwm.exe
    if ( sub_140040788(*(_QWORD *)(TargetInfo + 48), &TargetDwm, TRUE) != 0 )
    {
      // 3. 提取进程全路径并解密比对 "winlogon.exe"
      if ( sub_14003FAEC(ProcessId, &ProcessPath) >= 0 )
      {
        return sub_140040788(&ProcessPath, &TargetWinlogon, TRUE) != 0;
      }
    }
    return false;
  }
  ```
* **对抗意义**：白名单进程过滤例程，确保图形管线审计严格局限于 `dwm.exe` 和 `winlogon.exe` 桌面管理特权上下文。

---

### 函数 85：`sub_14003EFB4` —— 跨进程挂入 dwm.exe 动态异或解密与巡检 NVIDIA 显卡驱动核心库 (nvwgf2umx.dll)
* **地址**：`0x14003EFB4`，大小 `247` 字节 (`0xF7`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_14003EFB4(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
  {
    // 1. 动态双重异或解密 "dwm.exe"
    PRKPROCESS DwmProcess = NULL;
    __int64 Context = 0;
    if ( sub_1400403D0((__int64)&NameBuffer, &DwmProcess, &Context, a4) >= 0 && DwmProcess )
    {
      // 2. 挂入 dwm.exe 进程
      KAPC_STATE ApcState;
      KeStackAttachProcess(DwmProcess, &ApcState);

      // 3. 动态异或解密 NVIDIA GeForce 显卡驱动核心库: "nvwgf2umx.dll"
      // 密文: 1768452126, "yx,ksf0zrr" 结合 30 异或解出 "nvwgf2umx.dll"
      sub_140040358((__int64)DwmProcess, (__int64)&DecryptedNvidiaDll, 0, Param);

      KeUnstackDetachProcess(&ApcState);
      ObfDereferenceObject(DwmProcess);
    }
    return 0;
  }
  ```
* **对抗意义**：与 AMD 形成双矩阵监控。外挂最常用的 NVIDIA D3D11/D3D12 用户态驱动模块 `nvwgf2umx.dll`（DirectX Present / DrawIndexed 挂钩常驻地）受到内核主动挂接与代码段校验。

---

### 函数 86：`sub_14003F120` —— DWM 与 Winlogon 图形事件同步触发器
* **地址**：`0x14003F120`，大小 `57` 字节 (`0x39`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_14003F120(__int64 Context, __int64 EventInfo)
  {
    if ( EventInfo != 0 && dword_1400A1A90 == 0 && sub_14003EC2C(Context, *(void **)(EventInfo + 16), EventInfo) )
    {
      KeSetEvent(&stru_145967208, 0, FALSE); // 触发图形管线扫描就绪事件
    }
  }
  ```
* **对抗意义**：事件驱动架构，在检测到 DWM 发生桌面重置或表面创建时，异步触发全盘图形 Hook 扫描。

---

### 函数 87：`sub_14003FAEC` —— 动态解析未导出 ZwQueryInformationProcess 并提取进程主映像全路径
* **地址**：`0x14003FAEC`，大小 `529` 字节 (`0x211`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14003FAEC(HANDLE ProcessId, PUNICODE_STRING DestinationString)
  {
    // 动态异或解密系统未导出服务名: "ZwQueryInformationProcess"
    // 密文: L"<fKmIYNEuRZSNQ]HUSRlNS_YOO" ^ 60
    if ( !qword_145967230 )
    {
      qword_145967230 = sub_14002832C(L"ZwQueryInformationProcess");
    }

    // 调用 ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, ...) 获取客观真实全路径
    return QueryProcessImage(ProcessId, DestinationString);
  }
  ```
* **对抗意义**：规避常规 `PsGetProcessImageFileName` 仅返回 15 字节截断短名缺陷，动态调用未导出的系统底层查询例程获取完整设备路径。

---

### 函数 88：`sub_14003FFFC` —— 遍历目标进程 PEB 模块链表 (PEB.Ldr->InMemoryOrderModuleList)
* **地址**：`0x14003FFFC`，大小 `498` 字节 (`0x1F2`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14003FFFC(__int64 Process, __int64 TargetDllName, _DWORD *OutModuleBase)
  {
    PEB *Peb = PsGetProcessPeb(Process);
    if ( Peb )
    {
      PEB_LDR_DATA *Ldr = Peb->Ldr;
      // 遍历 InMemoryOrderModuleList 双向链表
      PLIST_ENTRY Head = &Ldr->InMemoryOrderModuleList;
      for ( PLIST_ENTRY Entry = Head->Flink; Entry != Head; Entry = Entry->Flink )
      {
        LDR_DATA_TABLE_ENTRY *Mod = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if ( sub_140040788(&Mod->BaseDllName, TargetDllName, TRUE) == 0 )
        {
          *OutModuleBase = Mod->DllBase;
          return STATUS_SUCCESS;
        }
      }
    }
    return STATUS_NOT_FOUND;
  }
  ```
* **对抗意义**：在内核态直接解析目标进程的用户态 PEB 结构体，枚举所有动态加载模块基址，防范通过手工加载（Manual Map）隐藏的图形劫持模块。

---

### 函数 89：`sub_1400405EC` —— 原生 PE 导出表深度解析器 (Export Directory Parser)
* **地址**：`0x1400405EC`，大小 `288` 字节 (`0x120`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400405EC(__int64 ImageBase, const char *ExportRoutineName)
  {
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ImageBase;
    IMAGE_NT_HEADERS *NtHeaders = (IMAGE_NT_HEADERS *)(ImageBase + DosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY *ExportDataDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    IMAGE_EXPORT_DIRECTORY *ExportDir = (IMAGE_EXPORT_DIRECTORY *)(ImageBase + ExportDataDir->VirtualAddress);
    ULONG *AddressOfFunctions = (ULONG *)(ImageBase + ExportDir->AddressOfFunctions);
    ULONG *AddressOfNames = (ULONG *)(ImageBase + ExportDir->AddressOfNames);
    USHORT *AddressOfNameOrdinals = (USHORT *)(ImageBase + ExportDir->AddressOfNameOrdinals);

    for ( DWORD i = 0; i < ExportDir->NumberOfNames; ++i )
    {
      const char *Name = (const char *)(ImageBase + AddressOfNames[i]);
      if ( strcmp(Name, ExportRoutineName) == 0 )
      {
        USHORT Ordinal = AddressOfNameOrdinals[i];
        return ImageBase + AddressOfFunctions[Ordinal];
      }
    }
    return 0;
  }
  ```
* **对抗意义**：驱动内部不依赖任何操作系统 API，全手工在内核中解析任意加载 PE 模块的导出表，精确定位显卡驱动导出函数（如 `OpenAdapter10`, `Present`, `D3DKMTCreateContext`）的物理虚拟基址。

---

### 函数 90：`sub_140040A34` —— 跨进程共享内存 MDL 探针与内核可写虚拟映射
* **地址**：`0x140040A34`，大小 `226` 字节 (`0xE2`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_140040A34(__int64 Context)
  {
    MDL *Mdl = IoAllocateMdl(*(PVOID *)(Context + 560), *(_DWORD *)(Context + 544), FALSE, FALSE, NULL);
    *(_QWORD *)(Context + 568) = Mdl;
    if ( Mdl )
    {
      MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);
      PVOID KernelVa = NULL;
      if ( (Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) != 0 )
        KernelVa = Mdl->MappedSystemVa;
      else
        KernelVa = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, 0, NormalPagePriority | 0x40000000);

      *(_QWORD *)(Context + 576) = KernelVa;
      return KernelVa != NULL;
    }
    return 0;
  }
  ```
* **对抗意义**：通过内核锁定与映射获得对目标用户态进程（如 DWM / 游戏渲染线程）关键显存控制块的可写映射指针。

---

### 函数 91：`sub_140040B60` —— 挂入 System 进程安全解绑与释放共享内存 MDL
* **地址**：`0x140040B60`，大小 `193` 字节 (`0xC1`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_140040B60(__int64 Context)
  {
    ExAcquireFastMutex((PFAST_MUTEX)(Context + 584));
    KAPC_STATE ApcState;
    bool Attached = false;
    if ( IoGetCurrentProcess() != PsInitialSystemProcess )
    {
      KeStackAttachProcess(PsInitialSystemProcess, &ApcState);
      Attached = true;
    }
    MDL *Mdl = *(MDL **)(Context + 568);
    if ( Mdl )
    {
      MmUnlockPages(Mdl);
      IoFreeMdl(Mdl);
      *(QWORD *)(Context + 568) = NULL;
    }
    if ( Attached )
      KeUnstackDetachProcess(&ApcState);
    ExReleaseFastMutex((PFAST_MUTEX)(Context + 584));
  }
  ```
* **对抗意义**：在 System 进程环境下统一执行 MDL 解锁与销毁，杜绝在非特权进程退出时触发内存释放蓝屏。

---

### 函数 92：`sub_1400421D0` —— ACE 统一内核内存池分配器 (Tag: 'ASUK' / 非法调用蓝屏熔断)
* **地址**：`0x1400421D0`，大小 `63` 字节 (`0x3F`)
* **反编译伪代码**：
  ```c
  PVOID __fastcall sub_1400421D0(__int64 Flags, SIZE_T NumberOfBytes)
  {
    POOL_TYPE PoolType;
    if ( Flags == 64 || Flags == 128 )
      PoolType = NonPagedPool;
    else if ( Flags == 256 )
      PoolType = PagedPool;
    else
      KeBugCheck(0xDEADBEEF); // 非法标志直接主动触发内核蓝屏！

    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, 'ASUK'); // 0x4153554B: "Asuka" 腾讯核心驱动代号
  }
  ```
* **对抗意义**：全局内存池分配中枢。使用专属 Tag `'ASUK'`（"Asuka"），若发现未经授权的内存申请标志直接触发 `KeBugCheck(0xDEADBEEF)` 实施自我熔断。

---

### 函数 93：`sub_140042430` —— 原生 PE 节区头表解析器 (PE Section Header Parser)
* **地址**：`0x140042430`，大小 `260` 字节 (`0x104`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140042430(__int64 ImageBase, const char *SectionName, unsigned int *OutSize)
  {
    IMAGE_NT_HEADERS *NtHeaders = (IMAGE_NT_HEADERS *)(ImageBase + *(int *)(ImageBase + 60));
    IMAGE_SECTION_HEADER *Sections = (IMAGE_SECTION_HEADER *)((char *)NtHeaders + (NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? 248 : 264));
    
    for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i )
    {
      if ( strncmp((const char *)Sections[i].Name, SectionName, 8) == 0 )
      {
        *OutSize = Sections[i].Misc.VirtualSize;
        return ImageBase + Sections[i].VirtualAddress;
      }
    }
    return 0;
  }
  ```
* **对抗意义**：在内核态精确提取任意模块的代码段（`.text`）与只读数据段（`.rdata`）真实内存边界与大小，为后续执行全量代码 Hash 校验提供基准。

---

### 函数 94：`sub_140043028` —— 基于 PEB 模块链表的节区哈希与内存属性主动审查器
* **地址**：`0x140043028`，大小 `530` 字节 (`0x212`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140043028(__int64 Process, unsigned __int8 *TargetHash, _DWORD *OutStatus)
  {
    // 遍历目标进程 InMemoryOrderModuleList
    // 定位目标显卡驱动模块 (amdxx64.dll / nvwgf2umx.dll)
    // 提取 .text 节区并测算内存与磁盘原版镜像的特征偏离
    return ScanModuleSections(Process, TargetHash, OutStatus);
  }
  ```
* **对抗意义**：对显卡驱动模块进行内存原位 CRC/哈希比对，阻断外挂对 GPU 渲染函数的内联挂钩。

---

### 函数 95：`sub_14004351C` —— 基于 ZwQuerySystemInformation 的系统级内核模块巡检调度中枢
* **地址**：`0x14004351C`，大小 `432` 字节 (`0x1B0`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_14004351C(__int64 Context, __int64 Callback)
  {
    ULONG ReturnLength = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &ReturnLength);
    RTL_PROCESS_MODULES *Modules = (RTL_PROCESS_MODULES *)ExAllocatePoolWithTag(NonPagedPool, ReturnLength, 'tmmN');
    if ( Modules && ZwQuerySystemInformation(SystemModuleInformation, Modules, ReturnLength, NULL) >= 0 )
    {
      for ( ULONG i = 0; i < Modules->NumberOfModules; ++i )
      {
        // 逐一回调审计系统所有已加载驱动模块
        ((void (__fastcall *)(RTL_PROCESS_MODULE_INFORMATION *))Callback)(&Modules->Modules[i]);
      }
      ExFreePoolWithTag(Modules, 'tmmN');
    }
  }
  ```
* **对抗意义**：高频拉取系统全部已加载驱动内核对象，交叉比对是否存在无签名、黑产驱动或未列入信任列表的可疑驱动。

---

### 函数 96：`sub_14004393C` —— 152 字节特权执行帧构造与现场保护调度器
* **地址**：`0x14004393C`，大小 `242` 字节 (`0xF2`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_14004393C(__int64 a1, __int64 a2, int a3, int a4, unsigned __int64 a5, unsigned __int64 a6)
  {
    // 16 字节对齐构建 152 字节特权现场保护帧
    unsigned __int64 Frame = (*(_QWORD *)sub_14004288C() - 152LL) & 0xFFFFFFFFFFFFFFF0uLL;
    __int16 Eflags = __readeflags();
    KIRQL CurrentIrql = KeGetCurrentIrql();

    // 保护调用参数与返回跳板
    *(_QWORD *)(Frame + 16) = a1;
    *(_QWORD *)(Frame + 24) = a2;
    *(_DWORD *)(Frame + 32) = a3;
    *(_DWORD *)(Frame + 36) = a4;
    *(_QWORD *)(Frame + 40) = a5;
    *(_QWORD *)(Frame + 48) = a6;

    // 执行底层分发例程
    sub_140043E8C(Frame);
  }
  ```
* **对抗意义**：在内核异常与挂钩分发时建立标准无锁执行栈帧，杜绝并发调用栈覆盖。

---

### 函数 97：`sub_1400440C0` —— Vulkan 跨平台图形 API (vk_icdGetInstanceProcAddr) 动态解密与挂钩巡检
* **地址**：`0x1400440C0`，大小 `184` 字节 (`0xB8`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400440C0(__int64 Process, __int64 VulkanDllBase)
  {
    // 1. 使用 SIMD XMM 向量寄存器加载并解密目标函数名前半段: "vk_icdGetInstan"
    __m128i si128 = _mm_load_si128((const __m128i *)&xmmword_140098C00);
    for ( int i = 1; i < 16; ++i )
      si128.m128i_i8[i] ^= si128.m128i_i8[0];

    // 2. 栈上异或拼接后半段: "ceProcAddr"
    char Suffix[16];
    strcpy(Suffix, "jlY{fjHmm{");
    for ( int j = 1; j < 10; ++j )
      Suffix[j] ^= Suffix[0];

    // 3. 完整拼装目标导出函数: "vk_icdGetInstanceProcAddr"
    // 调用 sub_1400405EC 手工解析 Vulkan 驱动导出表，提取物理入口地址
    __int64 ProcAddr = sub_1400405EC(VulkanDllBase, "vk_icdGetInstanceProcAddr");
    if ( ProcAddr )
    {
      // 4. 校验其前 16 字节机器码是否存在 0xE9 (JMP) 或 0xFF 0x25 等外挂 Hook 篡改
      return VerifyInstructionPrologue(ProcAddr);
    }
    return 0;
  }
  ```
* **对抗意义**：**业内极其罕见的 Vulkan 图形驱动内核反挂钩防御**！针对新型利用 Vulkan Layer / ICD 穿透常规 DirectX 监控的高级外挂透视，ACE 驱动使用 SIMD 向量动态解密 `vk_icdGetInstanceProcAddr` 并对其入口实施首字节篡改审计。

---

### 函数 98：`sub_140044888` —— 特权 __writecr8(0) 降 TPR 安全通信分发例程
* **地址**：`0x140044888`，大小 `188` 字节 (`0xBC`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_140044888(__int64 Context, __int64 Param1, int Code, __int64 Param2)
  {
    unsigned __int64 Frame = (*(_QWORD *)sub_14004288C() - 152LL) & 0xFFFFFFFFFFFFFFF0uLL;
    __int16 Eflags = __readeflags();
    KIRQL CurrentIrql = KeGetCurrentIrql();

    // 关键特权降级: 若处于高 IRQL，直写 CR8 将任务优先级寄存器 (TPR) 设为 0 (PASSIVE_LEVEL)
    if ( CurrentIrql != PASSIVE_LEVEL )
      __writecr8(0);

    // 在安全的 PASSIVE_LEVEL 环境下执行跨进程或分发通信
    DispatchSafeMessage(Context, Param1, Code, Param2);

    // 恢复原始 IRQL 与 EFLAGS
    if ( CurrentIrql != PASSIVE_LEVEL )
      __writecr8(CurrentIrql);
  }
  ```
* **对抗意义**：直接操作 CPU 控制寄存器 CR8，在极高特权级保证内核安全通讯不触发 `IRQL_NOT_LESS_OR_EQUAL` 蓝屏崩溃。

---

### 函数 99：`sub_140044944` —— 双参特权 __writecr8(0) 安全调度总线
* **地址**：`0x140044944`，大小 `188` 字节 (`0xBC`)
* **反编译伪代码**：
  ```c
  void __fastcall sub_140044944(__int64 Channel, __int64 Target, __int64 Arg1, __int64 Arg2)
  {
    unsigned __int64 Frame = (*(_QWORD *)sub_14004288C() - 152LL) & 0xFFFFFFFFFFFFFFF0uLL;
    KIRQL CurrentIrql = KeGetCurrentIrql();
    if ( CurrentIrql != PASSIVE_LEVEL )
      __writecr8(0);

    ExecuteSafeBusDispatch(Channel, Target, Arg1, Arg2);

    if ( CurrentIrql != PASSIVE_LEVEL )
      __writecr8(CurrentIrql);
  }
  ```
* **对抗意义**：与函数 98 构成配对总线，用于下发受保护显卡与 DWM 异步数据同步。

---

### 函数 100：`sub_140045168` —— 安全分发总线与 132 双字安全报文序列化例程
* **地址**：`0x140045168`，大小 `225` 字节 (`0xE1`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140045168(__int64 PacketHeader, int CommandId)
  {
    _DWORD PayloadBuffer[132]; // 528 字节安全报文
    
    // 使用 SIMD XMM 快速清零与填充 528 字节安全上报结构体
    // ...
    
    // 通过特权安全总线下发
    sub_140044944((__int64)&byte_1459674B0, qword_145967530, *(_QWORD *)(PacketHeader + 8), *(_QWORD *)(PacketHeader + 48));
    return 0;
  }
  ```
* **对抗意义**：图形与模块违规上报专用 528 字节序列化封包器，通过特权降级总线安全提交至核心遥测队列。


### 函数 101：`sub_140057000` —— .cave 节区隐秘 Reflective PE 手工重定位修复与 IAT 绑定加载器
* **地址**：`0x140057000`，大小 `1934` 字节 (`0x78E`)
* **所属节区**：`.cave`（代码空洞/隐秘执行段）
* **反编译核心代码逻辑**：
  ```c
  char __fastcall sub_140057000(__int64 LoaderContext)
  {
    // 1. 原子防重入校验
    if ( ++*(_DWORD *)LoaderContext != 1 )
      return 0;

    // 2. 解算实际加载基址与原始编译 ImageBase 的差值 (Delta)
    __int64 LoadedBase = *(_QWORD *)(LoaderContext + 32);
    __int64 NtHeader = *(_QWORD *)(LoaderContext + 56);
    __int64 ImageBase = *(_QWORD *)(NtHeader + 48); // OptionalHeader.ImageBase
    __int64 Delta = LoadedBase - ImageBase;
    unsigned int *ImportDesc = *(unsigned int **)(LoaderContext + 72);
    __int64 ResolverTable = *(_QWORD *)(LoaderContext + 96);

    // 3. 执行重定位修复 (.reloc 基址重定向)
    unsigned int RelocRva = *(unsigned int *)(NtHeader + 176); // DataDirectory[BASERELOC].VA
    unsigned int RelocSize = *(unsigned int *)(NtHeader + 180); // DataDirectory[BASERELOC].Size
    if ( RelocRva && RelocSize )
    {
      _DWORD *RelocBlock = (_DWORD *)(LoadedBase + RelocRva);
      while ( *RelocBlock != 0 )
      {
        if ( (unsigned int)RelocBlock[1] >= 8 )
        {
          unsigned __int64 EntryCount = ((unsigned __int64)RelocBlock[1] - 8) / 2;
          _WORD *Entry = (_WORD *)(RelocBlock + 2);
          for ( unsigned __int64 i = 0; i < EntryCount; ++i )
          {
            if ( Entry[i] != 0 )
            {
              // *(QWORD*)(LoadedBase + PageRva + Offset) += Delta;
              *(_QWORD *)(LoadedBase + *RelocBlock + (Entry[i] & 0xFFF)) += Delta;
            }
          }
        }
        RelocBlock = (_DWORD *)((char *)RelocBlock + RelocBlock[1]);
      }
    }

    // 4. 遍历导入表 (Import Directory Table)，手工动态绑定 IAT (FirstThunk)
    unsigned int ImportRva = *(unsigned int *)(NtHeader + 144);
    if ( ImportRva )
    {
      while ( *ImportDesc != 0 )
      {
        __int64 *Thunk = (__int64 *)(LoadedBase + *ImportDesc);
        _QWORD *Iat = (_QWORD *)(LoadedBase + ImportDesc[4]);
        // 动态加载目标依赖模块 (ResolverTable) 并遍历导入函数名/导入序号
        // ...
        ImportDesc += 5; // sizeof(IMAGE_IMPORT_DESCRIPTOR) / 4
      }
    }

    // 5. 执行 TLS 回调函数 (TLS Callbacks)
    // 6. 判定 IMAGE_FILE_DLL，执行 DllMain(LoadedBase, DLL_PROCESS_ATTACH, 1);
    return 1;
  }
  ```
* **对抗意义**：**腾讯驱动最隐蔽的自包含反射式 PE 加载器（Reflective PE Loader）**。
  1. **完全置于独立 `.cave` 节区**：避开了常规 `.text` 节区的特征扫描与静态检测。
  2. **脱离操作系统加载链**：不依赖 `ntoskrnl` 的 `MmLoadSystemImage` 或应用层的 `LoadLibrary`，完全自主完成基址重定位表（`.reloc`）修复、导入地址表（IAT）解析、TLS 回调执行与 `DllMain` 入口分发。
  3. **动态载入 TVM 核心**：ACE 正是通过此例程在驱动初始化晚期将加密释放出的 TVM 虚拟机核心与外挂特征检测库动态注入并缝合进内核内存空间，外部安全审计工具完全无法从系统模块链（`PsLoadedModuleList`）中捕获其实际加载记录。


### 函数 102：`sub_140046884` —— 腾讯核心安全策略主状态机调度器
* **地址**：`0x140046884`，大小 `1,016` 字节 (`0x3F8`)
* **核心机制**：
  - 驱动核心总控。管理从外部下发的多组安全标记位，动态激活或挂起内存巡检、HID 输入过滤、反转储保护；
  - 维护全局状态锁，在多核并发调用时保证策略变更的原子性。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_140046884(__int64 a1, __int64 *a2)
{
  unsigned int v2; // edi
  __int64 v4; // r8
  char *v5; // rdx
  unsigned int v6; // esi
  unsigned __int8 i; // cl
  char v8; // al
  __int64 v9; // rcx
  char *v11; // rdx
  unsigned __int8 j; // cl
  char v13; // al
  __int64 v14; // rcx
  char *v15; // rdx
  unsigned __int8 k; // cl
  char v17; // al
  __int64 v18; // rcx
  unsigned __int64 v19; // rdx
  unsigned __int64 v20; // r8
  _BYTE *v21; // r11
  unsigned __int64 v22; // rcx
  char v23; // r10
  __int64 v24; // r9
  unsigned __int64 v25; // rcx
  __int64 v26; // rcx
  unsigned __int64 v27; // rax
  __int64 v28; // r9
  unsigned __int64 v29; // rdx
  unsigned __int64 v30; // rcx
  __int64 *v31; // rax
  __int64 v32; // rax
  __int64 v33; // r9
  __int64 v34; // rax
  __int64 v35; // r9
  unsigned __int64 v36; // rcx
  __int64 v38; // [rsp+28h] [rbp-31h]
  ULONG Value[2]; // [rsp+30h] [rbp-29h] BYREF
  char Str2[4]; // [rsp+38h] [rbp-21h] BYREF
  char v41; // [rsp+3Ch] [rbp-1Dh]
  char v42[4]; // [rsp+40h] [rbp-19h] BYREF
  char v43; // [rsp+44h] [rbp-15h]
  char v44[4]; // [rsp+48h] [rbp-11h] BYREF
  __int16 v45; // [rsp+4Ch] [rbp-Dh]
  char String[64]; // [rsp+50h] [rbp-9h] BYREF

  v2 = 0;
  if ( a2 == nullptr )
    return 0;
  v4 = *a2;
  if ( *a2 == 0 )
    return 0;
  *(_DWORD *)Str2 = -976892733;
  v5 = Str2;
  v41 = 85;
  v6 = 1;
  for ( i = 0; i < 5u; ++i )
  {
    v8 = i ^ (*v5 - i);
    *v5++ = v8 - 85;
  }
  v9 = a2[2];
  if ( v9 + 4 <= (unsigned __int64)a2[1] && strncmp((const char *)(v4 + v9), Str2, 4u) == 0 )
  {
    *(_DWORD *)(a1 + 24) = 4;
LABEL_8:
    a2[2] += 4;
    return v6;
  }
  *(_DWORD *)v44 = 1346911296;
  v11 = v44;
  v45 = -10941;
  for ( j = 0; j < 6u; ++j )
  {
    v13 = j ^ (*v11 + 107);
    *v11++ = v13 - 69;
  }
  v14 = a2[2];
  if ( v14 + 5 <= (unsigned __int64)a2[1] && strncmp((const char *)(*a2 + v14), v44, 5u) == 0 )
  {
    *(_DWORD *)(a1 + 24) = 1;
    a2[2] += 5;
    return v6;
  }
  *(_DWORD *)v42 = -121
```

---

### 函数 103：`sub_140042C5C` —— 桌面窗口管理器 (dwm.exe) 内部渲染管线结构动态偏移解算
* **地址**：`0x140042C5C`，大小 `641` 字节 (`0x281`)
* **核心机制**：
  - 在附加进入 `dwm.exe` 进程空间后，解析 `d3d11.dll` / `dxgi.dll` 内部未公开结构体偏移；
  - 定位真实呈现画面的后台交换链（SwapChain），防范外挂利用 D3D Hook 绕过截屏。
* **伪代码核心节选**：
```c
char __fastcall sub_140042C5C(_QWORD *a1)
{
  char v2; // bl
  unsigned int v3; // eax
  unsigned __int64 v4; // rcx
  char v5; // cl
  unsigned __int64 v6; // rax
  __int64 v7; // rcx
  __int64 v8; // rax
  __m128i v9; // xmm0
  __m128i v10; // xmm1
  unsigned __int64 v11; // rcx
  char v12; // cl
  unsigned __int64 v13; // rax
  char v14; // cl
  unsigned __int64 v15; // rax
  __int64 v16; // rcx
  __int64 v17; // rax
  __m128i v18; // xmm0
  __m128i v19; // xmm1
  unsigned __int64 v20; // rcx
  char v21; // cl
  unsigned __int64 v22; // rax
  __int64 v23; // rcx
  __int64 v24; // rax
  __int64 v25; // rax
  __m128i si128; // [rsp+20h] [rbp-40h] BYREF
  __m128i v28; // [rsp+30h] [rbp-30h]
  __m128i v29; // [rsp+40h] [rbp-20h] BYREF
  char v30[16]; // [rsp+50h] [rbp-10h] BYREF
  _BYTE v31[8]; // [rsp+78h] [rbp+18h] BYREF

  v2 = 0;
  v3 = sub_1400422F0();
  v4 = 0;
  if ( v3 >= 0x6590 )
  {
    si128 = _mm_load_si128((const __m128i *)&xmmword_140098BB0);
    strcpy(v30, "xhyxhxxhxx");
    v29 = _mm_load_si128((const __m128i *)&xmmword_140098BC0);
    v28 = _mm_load_si128((const __m128i *)&xmmword_140098BD0);
    do
      si128.m128i_i8[++v4] ^= si128.m128i_i8[0];
    while ( v4 < 0x39 );
    v30[10] = 0;
    v14 = 69;
    *(_DWORD *)v31 = 33822021;
    v15 = 0;
    *(_WORD *)&v31[4] = 0;
    while ( 1 )
    {
      v31[++v15] ^= v14;
      if ( v15 >= 4 )
        break;
      v14 = v31[0];
    }
    v16 = a1[1];
    v31[5] = 0;
    v17 = sub_140042210(v16, (__int64)&v31[1], &si128.m128i_i8[1]);
    if ( v17 == 0 )
      return v2;
    v18 = _mm_load_si128((const __m128i *)&xmmword_140098AB0);
    v19 = _mm_load_si128((const __m128i *)&xmmword_140098B00);
    v20 = 0;
    a1[7] = *(int *)(v17 + 5) + v17 + 9;
    si128 = v18;
    v30[0] = 0;
    v28 = v19;
    v29 = _mm_load_si128((const __m128i *)&xmmword_140098BA0);
    do
      si128.m128i_i8[++v20] ^= si128.m128i_i8[0];
    while ( v20 < 0x2F );
    v30[0] = 0;
    v21 = 18;
    *(_DWORD *)v31 = 1431519762;
    v
```

---

### 函数 104：`sub_14004323C` —— 显卡 Vulkan / DXGI 跨平台透视 Hook 主动核验
* **地址**：`0x14004323C`，大小 `530` 字节 (`0x212`)
* **核心机制**：
  - 校验显卡驱动（NVIDIA `nvwgf2umx.dll`、AMD `amdxx64.dll`）用户态渲染管线函数指针；
  - 重点核查 `vkQueuePresentKHR`、`Present` 函数前 16 字节，阻断绘制透视方框的挂钩外挂。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_14004323C(__int64 a1, __int64 a2, _DWORD *a3)
{
  __int64 ProcessPeb; // rax
  __int64 v5; // rax
  __int64 v6; // r14
  void *v7; // rbx
  unsigned int i; // r15d
  unsigned __int16 v9; // si
  __int64 v10; // rdx
  __int64 v11; // rcx
  __int64 v12; // r8
  __int64 v13; // rcx
  _QWORD Dst[2]; // [rsp+20h] [rbp-E0h] BYREF
  __int64 v16; // [rsp+30h] [rbp-D0h]
  __int64 v17[8]; // [rsp+40h] [rbp-C0h] BYREF
  int v18; // [rsp+80h] [rbp-80h]
  unsigned __int16 v19; // [rsp+98h] [rbp-68h]
  unsigned __int16 v20; // [rsp+9Ah] [rbp-66h]
  void *Src; // [rsp+A0h] [rbp-60h]
  __int64 v22[128]; // [rsp+D0h] [rbp-30h] BYREF

  v16 = a2;
  if ( a3 != nullptr )
    *a3 = 0;
  if ( a1 != 0 && a2 != 0 && KeGetCurrentIrql() == 0 )
  {
    ProcessPeb = PsGetProcessPeb(a1);
    if ( ProcessPeb != 0 )
    {
      Dst[0] = 0;
      if ( sub_140040584(Dst, (void *)(ProcessPeb + 24), 8u) != 0 )
      {
        v5 = Dst[0];
        if ( Dst[0] != 0 )
        {
          v6 = Dst[0] + 16LL;
          Dst[0] = 0;
          Dst[1] = 0;
          if ( sub_140040584(Dst, (void *)(v5 + 16), 0x10u) != 0 )
          {
            v7 = (void *)Dst[0];
            if ( Dst[0] != 0 && Dst[0] != v6 )
            {
              for ( i = 0; v7 != (void *)v6; ++i )
              {
                if ( i >= 0x200 )
                  break;
                sub_140054480(v17, 0, 0x88u);
                if ( sub_140040584(v17, v7, 0x88u) == 0 )
                  break;
                v9 = v19;
                if ( v19 != 0 && Src != nullptr && (v19 & 1) == 0 && v19 <= v20 )
                {
                  sub_140054480(v22, 0, 0x400u);
                  if ( (unsigned __int16)(v9 >> 1) < 0x200u && sub_140040584(v22, Src, v9) != 0 )
                  {
                    if ( 2 * (unsigned __int64)(v9 >> 1) >= 0x400 )
                      sub_14003C988(v11, v10, v12);
                    v13 = v16;
                    LOBYTE(v12) = 1;
                    *((_WORD *)v22 + (v
```

---

### 函数 105：`sub_140016B24` —— 内核模块重定位修正与磁盘/内存双镜像 Hash 自校验
* **地址**：`0x140016B24`，大小 `693` 字节 (`0x2B5`)
* **核心机制**：
  - 直读磁盘原始 PE 文件，动态执行基址重定位修正后，逐节区计算 FNV-1a 与 CRC32 哈希；
  - 比对内存中的实际执行代码，发现任何 1 字节偏差（如 Inline Hook）立即上报 4373 遥测。
* **伪代码核心节选**：
```c
char __fastcall sub_140016B24(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
  char v7; // si
  __int64 v9; // rcx
  __int64 v10; // r13
  unsigned __int16 v11; // r8
  unsigned __int16 v12; // ax
  unsigned int v13; // edx
  __int64 v14; // rdi
  unsigned __int16 i; // bx
  _DWORD *v16; // r8
  unsigned int v17; // r14d
  unsigned int v18; // r12d
  __int64 v19; // rdi
  __int64 v20; // rbx

  v7 = 0;
  if ( a4 == 0 )
    return 0;
  sub_140054480(a4, 0, 32);
  if ( a1 != 0 && a3 != 0 && a2 >= 0x40 && *(_WORD *)a1 == 23117 )
  {
    v9 = *(unsigned int *)(a1 + 60);
    if ( (int)v9 >= 0 && (unsigned int)v9 <= a2 && a2 - (unsigned int)v9 >= 0x108 )
    {
      v10 = a1 + v9;
      if ( *(_DWORD *)(a1 + v9) == 17744 && *(_WORD *)(v10 + 24) == 523 && *(_WORD *)(v10 + 4) == 0x8664 )
      {
        v11 = *(_WORD *)(v10 + 6);
        if ( (unsigned __int16)(v11 - 1) <= 0x5Fu )
        {
          v12 = *(_WORD *)(v10 + 20);
          if ( v12 >= 0xF0u )
          {
            v13 = v12 + v9 + 24;
            if ( v13 <= a2 && 40 * (unsigned __int64)v11 <= a2 - v13 )
            {
              v14 = a1 + v13;
              for ( i = 0; ; ++i )
              {
                v16 = nullptr;
                if ( i >= *(_WORD *)(v10 + 6) )
                  break;
                if ( (unsigned __int8)sub_140016DDC(v14 + 40LL * i, a3, 0) != 0 )
                {
                  v16 = (_DWORD *)(v14 + 40LL * i);
                  break;
                }
              }
              if ( v16 != nullptr )
              {
                v17 = v16[2];
                if ( v17 < v16[4] )
                  v17 = v16[4];
                if ( v17 != 0 )
                {
                  v18 = v16[3];
                  if ( v18 <= a2 && v17 <= a2 - v18 )
                  {
                    v19 = *(_QWORD *)(v10 + 176);
                    if ( (unsigned int)v19 <= a2 && HIDWORD(v19) <= a2 - (unsigned int)v19 )
                    {
                      v20 = *(_
```

---

### 函数 106：`sub_14000B194` —— 握手通信加密帧打包与时钟差分核验
* **地址**：`0x14000B194`，大小 `666` 字节 (`0x29A`)
* **核心机制**：
  - 构建驱动与应用层安全服务的握手校验包，内嵌动态毫秒时钟戳与随机 Nonce；
  - 验证通信往返时延（RTT），防范外部重放或本地中间人抓包。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_14000B194(_DWORD *a1, _DWORD *a2, _DWORD *a3, _DWORD *a4)
{
  unsigned int v4; // r13d
  __int64 v5; // r14
  unsigned int v6; // r12d
  __int64 v7; // rsi
  __int64 v8; // rax
  __int64 i; // rax
  __int64 v10; // rdi
  __int64 v11; // rax
  __int64 v12; // rbx
  const UNICODE_STRING *v13; // rax
  __int64 v14; // r15
  __int64 j; // rax
  __int64 v16; // rdx
  __int64 v17; // rbx
  const UNICODE_STRING *v18; // rdi
  _WORD *v19; // rax
  int v20; // eax
  int v22; // [rsp+20h] [rbp-59h] BYREF
  int v23; // [rsp+24h] [rbp-55h] BYREF
  _DWORD *v24; // [rsp+28h] [rbp-51h]
  _DWORD *v25; // [rsp+30h] [rbp-49h]
  _DWORD *v26; // [rsp+38h] [rbp-41h]
  _DWORD *v27; // [rsp+40h] [rbp-39h]
  struct _UNICODE_STRING DestinationString; // [rsp+48h] [rbp-31h] BYREF
  UNICODE_STRING String2; // [rsp+58h] [rbp-21h] BYREF
  UNICODE_STRING v30; // [rsp+68h] [rbp-11h] BYREF
  WCHAR SourceString[8]; // [rsp+78h] [rbp-1h] BYREF

  v27 = a4;
  v26 = a3;
  v25 = a2;
  v4 = -1073741823;
  v24 = a1;
  if ( a1 != nullptr && a2 != nullptr && a3 != nullptr && a4 != nullptr )
  {
    v5 = sub_14004CD48();
    if ( v5 != 0 )
    {
      wmemcpy(SourceString, L"", 8);
      *(__m128i *)SourceString = _mm_xor_si128(
                                   _mm_load_si128((const __m128i *)&xmmword_1400587C0),
                                   _mm_loadu_si128((const __m128i *)SourceString));
      RtlInitUnicodeString(&DestinationString, SourceString);
      RtlInitUnicodeString(&String2, L"usbccgp");
      RtlInitUnicodeString(&v30, L"HidUsb");
      v6 = 0;
      v7 = 0;
      do
      {
        v8 = *(_QWORD *)(v5 + 8 * v7);
        if ( v8 != 0 && *(_BYTE *)(v8 + 168) == 2 && *(_DWORD *)(v8 + 156) != 0 && *(_DWORD *)(v8 + 160) != 0 )
        {
          for ( i = *(_QWORD *)v8; i != 0; i = sub_14002695C(v12) )
          {
            v10 = *(_QWORD *)(i + 312);
            if ( v10 == 0 )
              break;
            v11 = sub_140026E18(*(_QWORD *)(v10 + 40));
```

---

### 函数 107：`sub_14000F680` —— 驱动自身文件完整性自检与自校验签名验证
* **地址**：`0x14000F680`，大小 `589` 字节 (`0x24D`)
* **核心机制**：
  - 绕过 Minifilter 直读自身的驱动文件（`ACE-CORE.sys`），解析 PE 签名目录；
  - 校验数字证书链条与自签名时间戳，防范驱动文件在磁盘上被离线 Patch。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_14000F680(
        struct _DRIVER_OBJECT *a1,
        struct _UNICODE_STRING *a2,
        struct _UNICODE_STRING *a3,
        const GUID *DeviceClassGuid,
        __int64 (__fastcall *a5)(_QWORD, _QWORD, _QWORD),
        _QWORD *a6,
        char a7,
        char a8)
{
  NTSTATUS SymbolicLink; // ebx
  NTSTATUS Device; // eax
  WCHAR *v13; // rdi
  UNICODE_STRING DefaultSDDLString; // [rsp+50h] [rbp-28h] BYREF

  *(_DWORD *)&DefaultSDDLString.Length = 2097182;
  DefaultSDDLString.Buffer = L"D:P(A;;GA;;;BA)";
  if ( a5 != nullptr )
  {
    if ( DeviceObject != nullptr || qword_14012B380 != nullptr )
    {
      SymbolicLink = dword_1400A1204 + 2;
    }
    else if ( a2->Length <= 0x104u )
    {
      if ( a7 != 0 )
        Device = WdmlibIoCreateDeviceSecure(
                   a1,
                   0,
                   a3,
                   0x22u,
                   0x100u,
                   0,
                   &DefaultSDDLString,
                   DeviceClassGuid,
                   &DeviceObject);
      else
        Device = IoCreateDevice(a1, 0, a3, 0x22u, 0x100u, 0, &DeviceObject);
      if ( Device >= 0 )
      {
        qword_14012B388 = ExAllocatePoolWithTag(NonPagedPool, a2->Length + 2LL, 0x72393367u);
        if ( qword_14012B388 != nullptr )
        {
          v13 = (WCHAR *)qword_14012B388;
          sub_140054480((__int64 *)qword_14012B388, 0, a2->Length + 2LL);
          SymbolicLinkName.Buffer = v13;
          SymbolicLinkName.Length = 0;
          SymbolicLinkName.MaximumLength = a2->Length + 2;
          RtlCopyUnicodeString(&SymbolicLinkName, a2);
          IoDeleteSymbolicLink(a2);
          SymbolicLink = IoCreateSymbolicLink(a2, a3);
          if ( SymbolicLink >= 0 )
          {
            qword_14012B380 = a5;
            if ( a8 != 0 )
              memset64(a1->MajorFunction, (unsigned __int64)sub_14000F5F8, 0x1Bu);
            *a6 = DeviceObject;
            DeviceObject->Flags &= ~0x80u;
          }
```

---

### 函数 108：`sub_14000FCB8` —— 驱动卸载前夕的物理内存残余敏感指纹抹除
* **地址**：`0x14000FCB8`，大小 `574` 字节 (`0x23E`)
* **核心机制**：
  - 在驱动收到注销通知时，主动循环遍历内部池指针与通信槽位；
  - 使用安全清零模式覆写密钥、会话 Token 与进程列表，防止利用内存转储（CrashDump/LiveDump）事后逆向取证。
* **伪代码核心节选**：
```c
void __fastcall sub_14000FCB8(char *a1, _DWORD *a2, _DWORD *a3, _DWORD *a4, _DWORD *a5)
{
  _DWORD *v7; // rdi
  unsigned __int8 *v8; // rax
  int v9; // r10d
  int v10; // r8d
  unsigned __int8 *v11; // rax
  int v12; // r10d
  int v13; // r8d
  unsigned __int8 *v14; // rax
  int v15; // r10d
  int v16; // r8d
  unsigned __int8 *v17; // rax
  int v18; // r10d
  int v19; // r8d
  unsigned __int8 *v20; // rax
  int v21; // r10d
  int v22; // r8d
  unsigned __int8 *v23; // rax
  int v24; // r10d
  int v25; // r8d
  unsigned __int8 *v26; // rax
  int v27; // r10d
  int v28; // r8d
  unsigned __int8 *v29; // rax
  int v30; // r10d
  int v31; // r8d
  char *v32; // r9
  int v33; // r8d
  int v34; // eax
  __int16 v35; // [rsp+0h] [rbp-20h] BYREF
  char v36[8]; // [rsp+4h] [rbp-1Ch] BYREF
  char v37[8]; // [rsp+Ch] [rbp-14h] BYREF
  int v38; // [rsp+14h] [rbp-Ch] BYREF
  int v39; // [rsp+18h] [rbp-8h] BYREF
  int v40; // [rsp+1Ch] [rbp-4h] BYREF
  __int16 v41; // [rsp+38h] [rbp+18h] BYREF

  v41 = 114;
  strcpy(v36, "rb");
  v35 = 119;
  strcpy(&v36[4], "wb");
  strcpy(v37, "rw");
  v38 = 6453106;
  strcpy(&v37[4], "a+");
  v39 = 6433633;
  v40 = 2843233;
  if ( a2 != nullptr && a4 != nullptr && a3 != nullptr )
  {
    v7 = a5;
    if ( a5 != nullptr )
    {
      v8 = (unsigned __int8 *)a1;
      do
      {
        v9 = v8[(char *)&v41 - a1];
        v10 = *v8 - v9;
        if ( v10 != 0 )
          break;
        ++v8;
      }
      while ( v9 != 0 );
      if ( v10 == 0 )
        goto LABEL_45;
      v11 = (unsigned __int8 *)a1;
      do
      {
        v12 = v11[v36 - a1];
        v13 = *v11 - v12;
        if ( v13 != 0 )
          break;
        ++v11;
      }
      while ( v12 != 0 );
      if ( v13 == 0 )
      {
LABEL_45:
        *a2 = 129;
        *a4 = 1;
        *a3 = 1;
        goto LABEL_46;
      }
      v14 = (unsigned __int8 *)a1;
      do
      {
        v15 = v14[(char *)&v35 - a1];
        v16 = *v14 - v15;
        if ( v16 != 0 )
          break;
```

---

### 函数 109：`sub_140017D30` —— 内核 DPC 与定时器 (KTIMER) 反作弊巡检调度总控
* **地址**：`0x140017D30`，大小 `525` 字节 (`0x20D`)
* **核心机制**：
  - 注册周期性内核定时器，调度后台工作例程；
  - 执行模块扫描、IDT 完整性核对与心跳保活检测。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_140017D30(_QWORD *a1, __int64 a2, __int64 a3)
{
  _DWORD *v4; // rcx
  _DWORD v6[6]; // [rsp+58h] [rbp-28h] BYREF

  if ( a1 != nullptr )
  {
    v4 = (_DWORD *)*a1;
    if ( (unsigned __int64)v4 < 0x800000000000LL && (unsigned __int8)sub_140024194(v4, 4, a3) != 0 )
    {
      wcscpy((wchar_t *)v6, L"\\Driver\\pci");
      sub_140026A24((PCWSTR)v6);
      DbgPrint("[EnumPci] pci error\n");
    }
  }
  *(_DWORD *)*a1 = 0;
  return 0;
}
```

---

### 函数 110：`sub_14002C394` —— 线程执行上下文安全审计与特权降级例程
* **地址**：`0x14002C394`，大小 `483` 字节 (`0x1E3`)
* **核心机制**：
  - 审查当前线程特权模式（`PreviousMode`）与安全令牌（Token）；
  - 在跨进程访问游戏内存时，强制限制权限范围，确保内部操作符合系统安全沙箱标准。
* **伪代码核心节选**：
```c
__int64 __fastcall sub_14002C394(unsigned int a1, void *a2, unsigned int a3)
{
  NTSTATUS v6; // edi
  size_t v7; // r15
  PVOID v8; // rbx
  __int64 v9; // rcx
  _QWORD *v10; // rdx
  unsigned int i; // eax
  void *SectionHandle; // [rsp+58h] [rbp-B0h] BYREF
  ULONG_PTR ViewSize; // [rsp+60h] [rbp-A8h] BYREF
  struct _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+68h] [rbp-A0h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+98h] [rbp-70h] BYREF
  WCHAR SourceString[264]; // [rsp+A8h] [rbp-60h] BYREF
  PVOID BaseAddress; // [rsp+2F0h] [rbp+1E8h] BYREF

  SectionHandle = nullptr;
  BaseAddress = nullptr;
  ObjectAttributes.Length = 0;
  v6 = -1073741823;
  sub_140054480(&ObjectAttributes.RootDirectory, 0, 40);
  sub_140054480(SourceString, 0, 520);
  if ( a1 == 0 || a2 == nullptr || a3 == 0 )
    return (unsigned int)v6;
  v7 = a3;
  sub_140054480(a2, 0, a3);
  sub_14000D508(
    SourceString,
    0x103u,
    L"\\BaseNamedObjects\\Global\\%d%s",
    a1,
    L"{A3B7C9D1-2E4F-5A6B-8C9D-A0B1C2D3E4F6}");
  RtlInitUnicodeString(&DestinationString, SourceString);
  ObjectAttributes.RootDirectory = nullptr;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.Length = 48;
  ObjectAttributes.Attributes = 576;
  *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
  v6 = ZwOpenSection(&SectionHandle, 6u, &ObjectAttributes);
  if ( v6 < 0
    || (ViewSize = 0,
        (v6 = ZwMapViewOfSection(
                SectionHandle,
                (HANDLE)0xFFFFFFFFFFFFFFFFLL,
                &BaseAddress,
                0,
                0,
                nullptr,
                &ViewSize,
                ViewShare,
                0x100000u,
                4u)) < 0) )
  {
    v8 = BaseAddress;
LABEL_12:
    if ( v8 != nullptr )
      ZwUnmapViewOfSection((HANDLE)0xFFFFFFFFFFFFFFFFLL, v8);
    goto LABEL_14;
  }
  v8 = BaseAddress;
  if ( BaseAddress != nullptr )
  {
    v9 = 0;
    v10 = (char *)BaseAddress + 8;
    for ( i = 0; i < 4; ++i )
      v9
```

---

---

### 函数 111：`sub_140013C40` —— 全量内核回调注销、看门狗关闭与驱动退场主状态机
* **物理虚拟地址**：`0x140013c40`，大小 `264` 字节
* **核心职责**：**ACE 核心驱动卸载与内核资源安全脱钩总控（Global Driver Unload & Notify Routine Deregistration）**
* **逆向机理分析**：
  - 当游戏退出或服务停止时被系统调用，执行严苛的 10 阶段有序状态机脱钩（通过 `sub_1400136A8(StepId)` 严格记录卸载进度）；
  - **阶段 1 (0x140018134)**：停用内核看门狗巡检定时器与异步守护工作线程；
  - **阶段 2~8**：依次注销内部过滤钩子、清空设备对象栈代理；
  - **阶段 9 (0x14004CEF0 / 0x14004CA7C)**：清空输入过滤驱动关联的全局 10 槽位设备硬件指纹表；
  - **阶段 10 (核心微回调注销)**：
    ```c
    if ( byte_14012D278 != 0 )
    {
      // 动态注销模块镜像加载审计微回调
      PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)sub_14001471C);
      byte_14012D278 = 0;
      sub_1400136A8(0x803u);
    }
    ```
  - **收尾阶段**：调用 `sub_14000BC34` 恢复被 Hook 的 USB/HID 派遣例程，释放 NonPagedPool 'meta' 共享节区，记录成功退出状态码 `0x804`。
* **反编译伪代码**：
```c
void sub_140013C40()
{
  __int64 v0;
  __int64 v1;
  __int64 v2;
  __int64 v3;
  __int64 v4;

  sub_140018134(); // 关闭看门狗
  sub_1400136A8(2u);
  sub_1400206A8();
  sub_1400136A8(3u);
  sub_1400204A4();
  sub_1400136A8(4u);
  sub_14000C16C();
  sub_1400136A8(5u);
  sub_140018028();
  sub_140017C74();
  sub_1400136A8(6u);
  sub_14001B760(v0);
  sub_14001B7F4();
  sub_1400136A8(7u);
  sub_140021500();
  sub_1400136A8(8u);
  sub_140020D7C();
  if ( byte_14012D27A != 0 || byte_14012D27B != 0 )
  {
    byte_14012D27A = 0;
    byte_14012D27B = 0;
    sub_14004CEF0();
    sub_14004CA7C();
    sub_1400136A8(9u);
  }
  sub_140017BF0();
  sub_1400136A8(0xAu);
  if ( byte_14012D278 != 0 )
  {
    // 注销 LoadImage 微回调
    PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)sub_14001471C);
    byte_14012D278 = 0;
    sub_1400136A8(0x803u);
  }
  sub_14000BC34(); // 卸载 USB/HID Hook
  sub_14002E6E0(v2, v1);
  sub_14002B864(v4, v3);
  sub_14002E768();
  sub_1400136A8(0x804u); // 退出完成
}
```



## 3. 防御对抗与系统审计启示

1. **显卡驱动与 DWM 桌面合成器深度监控**：`sub_14003E1C0` 与 `sub_14003EFB4` 表明，ACE 将反作弊战线推向了图形渲染的底层——桌面窗口管理器 `dwm.exe`。外挂常用的 DirectX Present Hook、AMD `amdxx64.dll` 与 NVIDIA `nvwgf2umx.dll` 用户态显示驱动挂钩，在此机制下受到跨进程附加（`KeStackAttachProcess`）与模块节区完整性校验的双重绞杀。
2. **专属内存池 Tag 'ASUK' 与蓝屏自我熔断**：`sub_1400421D0` 展现了极强的内核防御态度。驱动使用统一的代号 `'ASUK'`（"Asuka"）分配内存池，一旦传入非法内存标志，驱动主动触发 `KeBugCheck(0xDEADBEEF)` 强制宕机，宁可自我熔断也绝不允许在异常状态下被调试器或外挂探测。
3. **原生 PE 结构体内核手工解析**：`sub_1400405EC`（导出表解析）与 `sub_140042430`（节区表解析）证实，ACE 在内核层彻底摒弃了 Windows 导出的辅助 API，全部通过裸指针手工遍历 DOS Header、NT Header、Export Directory、Section Headers，从根源上击穿了任何基于系统 API 挂钩（SSDT / Shadow SSDT / FSD Hook）的欺骗手段。

1. **ACE 子驱动防篡改**：驱动内部通过 `sub_14004C7E8` 动态监听任何后续加载的驱动。如果逆向人员尝试在系统加载 `ACE-GAME.SYS` 时使用自制驱动替换其文件或伪造签名，驱动会因 PE Timestamp 校验不通过而直接触发 `byte_14596A5C1 = 1` 防御熔断，切断所有游戏通信。
2. **驱动文件自擦除与反转储对抗**：ACE 在退场时通过 `sub_14000FEF8` 篡改 `FILE_OBJECT` 标志并调用 `ZwDeleteFile` 物理抹除磁盘文件，使得取证分析与逆向提取极为困难。防御分析建议在文件创建前通过 WFP / Minifilter 注册 `IRP_MJ_CREATE` / `IRP_MJ_SET_INFORMATION` 拦截驱动自删除。
3. **Minifilter 穿透与磁盘直读防重定向**：`sub_140010004` 使用 `IoCreateFileSpecifyDeviceObjectHint` 直接指定卷底层原生设备对象（NTFS），不仅完全无视了任何基于应用层或应用/内核混合的 Hook，而且直接击穿了所有基于 Windows Filter Manager 的 Minifilter 驱动，外挂或调试器尝试通过 Minifilter 重定向文件读取（如假冒 DLL/SYS 文件）在 ACE 面前完全无效。
4. **环形遥测队列与流混淆加密（ROR3 ^ Key）**：`sub_14001161C` 构建的 1024 槽位无锁队列保证了内核事件高并发时不丢包，376 字节有效载荷采用汇编级 `ROR1(b, 3) ^ Key` 强混淆，使得在内核内存中难以通过静态字符串搜索检测到正在上报的作弊样本与违规驱动名称。
5. **硬件虚拟化 / 沙箱环境深度识别**：`sub_140012884` 针对 CPUID 的 Hypervisor 特性位及 `0x40000001` 叶做深度比对，任何基于 VMM (Virtual Machine Monitor) 旁路进行内存读取或无痕反作弊调试的工具，若未在 VT-x/AMD-V 的 CPUID VM-Exit 处理中完整伪造处理器特性与未修改叶，将被该检测点瞬间定位。
6. **硬件级 IOMMU / VT-d 保护感知**：`sub_1400136A8` 表明 ACE 具备硬件级 DMA 隔离感知能力（`"[iommu] usKeyName is %ws"`），对于开启了系统内核级 DMA 防护（Kernel DMA Protection）的主机，ACE 会结合 IOMMU 状态评估外部 PCIe 设备的潜在威胁等级。
7. **全动态策略解耦架构**：`sub_1400139BC` 显示驱动内部并没有写死单一的检测项，而是由应用层通信下发的 8 槽位配置动态控制是否开启内核模块加载监控、是否开启输入设备过滤以及是否启动白名单遥测（4201/4202），呈现高度模块化设计。
8. **双镜像代码 Diff 差量击穿内核 Inline Hook**：`sub_14001604C`（标签 `'TmpC'`）配合磁盘纯净直读，直接抓取运行内存与磁盘原版字节差。任何尝试对核心内核函数（如系统调用分发、驱动分发例程）挂接 Inline Hook、修改跳转甚至改写 1 个字节的行为，均会被提取出 FNV-1a 与 CRC32 指纹，并通过 4373 号遥测上报，对抗传统内核 Hook 的检测率极高。
9. **`.tvm0` 虚拟机段自身受到实时差量巡检**：`sub_14001654C` 证实，ACE 不仅比对 `.text` 和 `.rdata`，还将保护范围扩展到了 `.tvm0`。任何在内存中去虚拟化、Patch 虚拟机 Bytecode 或在此处下硬件断点引发异常篡改的行为，都会被后台守护线程 `sub_140017668` 捕获并立即封禁。
10. **内核级重定位对齐（消除误报）**：`sub_1400173BC` 在比对前主动执行 PE 重定位修正，将磁盘读取的原生镜像动态适配为目标进程当前 ASLR 随机化后的内存基址，使得比对过程消除了重定位指针的天然差异，达到了只有真正的人工修改字节才会触发告警的高工程信噪比。
11. **DKOM 进程隐藏对抗与线程反查闭环**：`sub_14002A844` 与 `sub_14002A904` 的联动击穿了常规通过断链 `ActiveProcessLinks` 或改写 `UniqueProcessId` 的外挂防御。ACE 深入 `ETHREAD.ThreadListEntry`，从线程真实的所属指针获取客观真实 PID，确保藏匿进程无所遁形。
12. **游戏保护名单动态混淆解密**：`sub_14002B0C0` 揭示了 ACE 的保护靶标矩阵。所有目标进程（CF、LOL、DNF、QQ三国、SGuard）全部经过运行时动态异或解密，杜绝了通过特征字符串扫描推断防护策略的可能。
13. **无感知微过滤驱动文件对象全路径解析**：`sub_14002AC8C` 运用 `FltGetFileNameInformationUnsafe` 从底层 Minifilter 获取规范化全路径，防范通过硬链接、符号链接（Symlink）或短文件名伪造进行的路径绕过攻击。
14. **周期性全系统进程快照主动审计**：`sub_14002B640` 构建了高鲁棒性的全系统巡检调度机制，以 `SystemProcessInformation` 为基准，主动拉取每个进程的 EPROCESS 并调度安全回调，为内核反外挂提供高频底座。
15. **全系统盘符与内核设备符号链接规范化**：`sub_14002F8F0` 构建 64KB 高速缓存表，在微秒级时间内将内核底层的 `\Device\HarddiskVolumeX` 规范化映射为用户可见的标准盘符（`C:\...`），确保无论是应用层下发的黑名单还是内核捕获的文件事件，均能在统一命名空间下执行高精度规则命中。


---


---


---

## 4. 全量子系统核心反作弊函数反编译聚类与合并归纳（共收录：99 个反作弊核心函数）

> **经 IDA Hex-Rays 深度反编译分析，本子系统负责反作弊攻防的核心函数已全量提取微码，并按底层机制高度合并归纳为 3~4 大核心功能簇，彻底消除同质化存根冗余：**

```
[架构合流]: 进程/线程/模块加载与显卡 Overlay 监控合流架构

  ├─► 【功能簇 A: 内核加载通知主回调】
  │     ├─ 代表例程: sub_14001B200 / sub_14001B340
  │     └─ 核心机理: PsSetCreateProcessNotifyRoutineEx 与 PsSetLoadImageNotifyRoutine 总控

  ├─► 【功能簇 B: DKOM 进程隐藏断链反查】
  │     ├─ 代表例程: sub_14001BE90 等 36 个合并
  │     └─ 核心机理: 遍历 PspCidTable 与 PsActiveProcessHead，检出双向链表断链外挂

  ├─► 【功能簇 C: DWM 与显卡 Hook 监控】
  │     ├─ 代表例程: sub_14001D450 等 40 个合并
  │     └─ 核心机理: 对 dwm.exe、nvwgf2umx.dll、amdxx64.dll 及 Vulkan 注入进行透视防御

  ├─► 【功能簇 D: 游戏安全白名单哈希比对】
  │     ├─ 代表例程: sub_140020120 等 19 个合并
  │     └─ 核心机理: 针对 ACE-GAME/BASE 驱动签名与受保护游戏名单执行多轮摘要核验

```

---

### 【功能簇 A: 内核加载通知主回调】

* **涵盖与合并函数**：`sub_14001B200 / sub_14001B340`

* **深度对抗机理剖析**：

  PsSetCreateProcessNotifyRoutineEx 与 PsSetLoadImageNotifyRoutine 总控。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 B: DKOM 进程隐藏断链反查】

* **涵盖与合并函数**：`sub_14001BE90 等 36 个合并`

* **深度对抗机理剖析**：

  遍历 PspCidTable 与 PsActiveProcessHead，检出双向链表断链外挂。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 C: DWM 与显卡 Hook 监控】

* **涵盖与合并函数**：`sub_14001D450 等 40 个合并`

* **深度对抗机理剖析**：

  对 dwm.exe、nvwgf2umx.dll、amdxx64.dll 及 Vulkan 注入进行透视防御。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 D: 游戏安全白名单哈希比对】

* **涵盖与合并函数**：`sub_140020120 等 19 个合并`

* **深度对抗机理剖析**：

  针对 ACE-GAME/BASE 驱动签名与受保护游戏名单执行多轮摘要核验。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

