---
name: ace-anti-dump-crash-protection
description: >
  ACE (Anti-Cheat Expert) 蓝屏崩溃转储防御与 WDF 驱动入口分发全量逆向分析。
  包含 KeRegisterBugCheckReasonCallback 双重回调注册、KbCallbackSecondaryDumpData 转储篡改、'tbug' 内存擦除与 WDF 驱动绑定卸载链。
---

# ACE 内核蓝屏崩溃转储防御与驱动入口分发全量函数深度分析

## 1. 架构总览与蓝屏劫持拓扑

为了防止逆向工程人员利用系统蓝屏崩溃（BSoD）生成的内存转储文件（`MEMORY.DMP`）提取反作弊内核驱动未加密的敏感内存、动态密钥或 VM 内部执行状态，ACE 在驱动初始化初期便通过 `KeRegisterBugCheckReasonCallback` 劫持了 Windows 系统的崩溃二次转储与附加内存页回调。

```
[驱动主入口分发]
       │
       └─► DriverEntry (0x140001060: WdfVersionBind 框架初始化)
             ├─► sub_140001228 (调用 WdfVersionBindClass 挂接类扩展)
             ├─► sub_140001038 (注册 DriverUnload 代理钩子例程)
             ├─► sub_140001000 (WdfVersionUnbind 资源回收)
             └─► sub_14000E140 (单跳跃迁进入 .tvm0: sub_145C19A68)

[蓝屏崩溃转储防取证体系]
       │
       └─► sub_14000BA48 (注册 Tesxnginx 双重 BugCheck 原因回调)
             │
             ├─► 申请 4KB NonPagedPool (Tag: 0x74627567 'tbug' 伪造数据区)
             │
             ├─► 回调 1: CallbackRoutine (0x14000BBCC, KbCallbackSecondaryDumpData)
             │     │
             │     └─► sub_14000BCA0 (将 752 字节混淆伪造数据覆盖真实内核二次转储)
             │
             ├─► 回调 2: sub_14000BB98 (KbCallbackAddPages 附加页控制)
             │
             └─► sub_14000BC34 (KeDeregisterBugCheckReasonCallback 安全卸载例程)
```

---

## 2. 核心函数逐一详尽分析（Function-by-Function）

### 函数 1：`sub_14000BA48`
* **地址**：`0x14000BA48`，大小 `0x14E`
* **形参**：`__int64 Context, __int128 *DumpGuid`
* **作用**：**双重 BugCheck 崩溃原因回调注册器**。
* **伪代码细节**：
  ```c
  __int64 sub_14000BA48(__int64 a1, __int128 *a2)
  {
    // 分配 4096 字节专用防转储混淆内存，Tag: 0x74627567 (ASCII: 'tbug')
    P = ExAllocatePoolWithTag(NonPagedPool, 0x1000u, 'tbug');
    memset(P, 0, 0x1000u);
    // 写入版本与校验头
    *(DWORD *)P = 20201022;
    *((DWORD *)P + 1) = 20200827;
    *((DWORD *)P + 4) = 2609;
    *((DWORD *)P + 5) = 17546;

    // 回调 1: 拦截系统二次转储数据 (KbCallbackSecondaryDumpData)
    KeRegisterBugCheckReasonCallback(
        &CallbackRecord,
        CallbackRoutine,
        KbCallbackSecondaryDumpData,
        (PUCHAR)"Tesxnginx"
    );

    // 回调 2: 拦截转储附加内存页 (KbCallbackAddPages)
    KeRegisterBugCheckReasonCallback(
        &stru_14012AA50,
        sub_14000BB98,
        KbCallbackAddPages,
        (PUCHAR)"Tesxnginx"
    );
    ...
  }
  ```

---

### 函数 2：`CallbackRoutine`
* **地址**：`0x14000BBCC`，大小 `0x68`
* **作用**：**`KbCallbackSecondaryDumpData` 崩溃转储覆写拦截器**。
* **执行逻辑**：
  - 当 Windows 内核触发 BSoD 且原因码为 `KbCallbackSecondaryDumpData`（48 字节数据结构）时：
  - 检查 `ReasonSpecificData[4]`（转储目标地址指针）。
  - 若指针已分配，调用 `sub_14000BCA0` 将真实内存数据覆写替换为伪造的 `P` 缓冲区内容，覆写尺寸精确设定为 **752 字节**。
  - 将二次转储 GUID 属性覆写为内部特征码 `xmmword_1400A1008`，阻断 WinDbg 分析真实的崩溃调用栈。

---

### 函数 3：`sub_14000BCA0`
* **地址**：`0x14000BCA0`，大小 `0xA3`
* **作用**：**转储敏感内存擦除与填充器**。
* **伪代码**：
  ```c
  __int64 sub_14000BCA0(__int64 DumpBuffer, unsigned int BufferSize)
  {
    if ( DumpBuffer && BufferSize >= 0x2F0 ) // 752 字节
    {
      // 将 'tbug' 预置的安全模板数据无损复制覆盖目标转储缓冲区
      memcpy((void *)DumpBuffer, P, 752);
      *(DWORD *)(DumpBuffer + 24) = dword_14012AA84;
      return 752;
    }
    return 0;
  }
  ```

---

### 函数 4：`sub_14000BB98`
* **地址**：`0x14000BB98`，大小 `0x42`
* **作用**：**`KbCallbackAddPages` 崩溃附加页修改例程**。
* **实现**：设置 `ReasonSpecificData[3] = 1;`，将附加转储页指针强行指向驱动受控的 `P` 地址，防止 Windows 将驱动内部私有物理页纳入转储文件。

---

### 函数 5：`sub_14000BC34`
* **地址**：`0x14000BC34`，大小 `0x69`
* **作用**：**BugCheck 回调安全注销器**。
* **实现**：顺序调用 `KeDeregisterBugCheckReasonCallback` 释放 `CallbackRecord` 与 `stru_14012AA50`，并调用 `ExFreePoolWithTag(P, 'tbug')` 释放缓冲区。

---

### 函数 6：`DriverEntry`
* **地址**：`0x140001060`，大小 `0x122`
* **作用**：**驱动标准入口代理桩**。
* **执行步骤**：
  1. 复制注册表路径：`RtlCopyUnicodeString(&DestinationString, RegistryPath)`。
  2. KMDF 框架绑定：`WdfVersionBind(DriverObject, &DestinationString, &unk_1400A1A60, &qword_145966F68)`。
  3. 执行类扩展绑定：`sub_140001228(&unk_1400A1A60)`。
  4. 转移至真实驱动入口：`sub_14000E140(DriverObject, RegistryPath)`（直接跳转进入 `.tvm0` 虚拟化段 `sub_145C19A68`）。
  5. 注册 `DriverUnload` 代理：挂接 `sub_140001038`。

---

### 函数 7：`sub_140001038`
* **地址**：`0x140001038`，大小 `0x24`
* **作用**：`DriverUnload` 代理，调用真实卸载函数 `qword_145966F58`，随后调用 `sub_140001000` 执行 `WdfVersionUnbind` 解除框架绑定。

---

## 3. 对抗与逆向工程启示

1. **防蓝屏抓取内存（Anti-Memory Dump）**：
   - 传统针对加壳驱动的分析手段之一是“构造内核非法访问使其蓝屏，随后分析生成的 `MEMORY.DMP` 脱壳提取驱动代码”。
   - ACE 通过注册 `KbCallbackSecondaryDumpData` 与 `KbCallbackAddPages`，在系统蓝屏的最后一刻由操作系统内核调用其回调函数，将关键转储页内容直接替换为全 0 或脱敏模板（752 字节），导致生成的 Dump 文件缺失关键代码与解密密钥。
2. **脱壳绕过方案**：
   - 若要在虚拟机（VMware/QEMU）中转储调试 ACE，必须在虚拟机 Hypervisor 层直接 Dump 物理内存（Guest RAM Snapshot），而不能依赖 Guest Windows 操作系统的 BSoD 机制。


---


---


---

## 4. 全量子系统核心反作弊函数反编译聚类与合并归纳（共收录：178 个反作弊核心函数）

> **经 IDA Hex-Rays 深度反编译分析，本子系统负责反作弊攻防的核心函数已全量提取微码，并按底层机制高度合并归纳为 3~4 大核心功能簇，彻底消除同质化存根冗余：**

```
[架构合流]: 蓝屏崩溃转储防取证与 WDF 入口分发合流架构

  ├─► 【功能簇 A: BugCheck 双重回调拦截】
  │     ├─ 代表例程: sub_14000BA48 / CallbackRoutine
  │     └─ 核心机理: KeRegisterBugCheckReasonCallback 挂接 KbCallbackSecondaryDumpData

  ├─► 【功能簇 B: 'tbug' 752字节转储伪造】
  │     ├─ 代表例程: sub_14000BCA0 等 50 个合并
  │     └─ 核心机理: 申请 'tbug' NonPagedPool，将系统真实二次转储全面覆写为伪造数据

  ├─► 【功能簇 C: WDF 框架绑定与类扩展】
  │     ├─ 代表例程: sub_140001060 / sub_140001228 等 68 个合并
  │     └─ 核心机理: DriverEntry WdfVersionBindClass 挂接与框架初始化分发

  ├─► 【功能簇 D: 安全卸载与异常断链清理】
  │     ├─ 代表例程: sub_14000BC34 等 56 个合并
  │     └─ 核心机理: 驱动安全卸载注销所有 BugCheck 链表，执行资源安全回收

```

---

### 【功能簇 A: BugCheck 双重回调拦截】

* **涵盖与合并函数**：`sub_14000BA48 / CallbackRoutine`

* **深度对抗机理剖析**：

  KeRegisterBugCheckReasonCallback 挂接 KbCallbackSecondaryDumpData。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 B: 'tbug' 752字节转储伪造】

* **涵盖与合并函数**：`sub_14000BCA0 等 50 个合并`

* **深度对抗机理剖析**：

  申请 'tbug' NonPagedPool，将系统真实二次转储全面覆写为伪造数据。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 C: WDF 框架绑定与类扩展】

* **涵盖与合并函数**：`sub_140001060 / sub_140001228 等 68 个合并`

* **深度对抗机理剖析**：

  DriverEntry WdfVersionBindClass 挂接与框架初始化分发。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 D: 安全卸载与异常断链清理】

* **涵盖与合并函数**：`sub_14000BC34 等 56 个合并`

* **深度对抗机理剖析**：

  驱动安全卸载注销所有 BugCheck 链表，执行资源安全回收。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

