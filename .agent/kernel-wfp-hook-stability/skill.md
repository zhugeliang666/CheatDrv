---
name: kernel-wfp-hook-stability
description: >
  Use when hooking or modifying Windows Filtering Platform (WFP / netio.sys) Callouts in kernel space, 
  evading anti-cheat detection (such as ACE / EAC), handling driver initialization race conditions, 
  diagnosing BugCheck 0x1A (subcode 0x4477) crashes, and designing resilient KTIMER/WorkItem background scan engines.
---

# 内核 WFP Hook 稳定性、时序竞态防护与 0x1A 蓝屏排查实战指南

## 概述

在内核态对 Windows Filtering Platform（WFP / `netio.sys`）执行 DKOM 数组替换或对第三方反作弊驱动（如 ACE、EAC、BattlEye）的 Callout 回调进行过滤劫持时，最大的稳定性威胁并非 Hook 算法本身，而是**目标驱动加载时序竞态（Race Condition）**与**未完成初始化的内存踩踏**。

本指南总结了在无设备对象隐蔽驱动工程中，实现安全无蓝屏 WFP Callout 替换、彻底去除 IOCTL 通信、诊断 `BugCheck 0x1A (Subcode 0x4477)` 以及设计抗审计后台扫描引擎的核心经验。

---

## 1. 核心崩溃诊断：BugCheck 0x1A (Subcode 0x4477) 根因与机理

### 1.1 蓝屏参数解析
* **BugCheck Code**：`0x1A: MEMORY_MANAGEMENT`
* **Arg1 = `0x0000000000004477`**：
  > *"A driver tried to write to an unallocated address in the user space of the system process."*
  > （某个内核驱动尝试在 `System` 进程（PID 4）上下文中向未分配的用户态地址写入数据）。
* **Arg2**：尝试写入的目标非法地址（例如 `0x0000000100000001`）。
* **典型调用栈**：
  ```text
  nt!KeBugCheckEx
  nt!MiInPagePageTable
  nt!MiUserFault
  nt!MmAccessFault
  nt!KiPageFault
  fwpkclnt!FwpmEngineOpen0+0x8 (或 fwpkclnt!FwppSessionCreate)
  TargetAntiCheatDriver+0xXXXX
  ```

### 1.2 触发时序与竞态本质
1. **模块映射与执行的间隙**：
   `nt!IopLoadDriver` 在加载目标驱动时，先将 PE 展开并插入全局模块表 `PsLoadedModuleList`，**随后**才调度执行其 `DriverEntry`。
2. **激进扫描的危害**：
   若 Hook 驱动通过模块链表循环轮询，只要检测到目标驱动基址就立刻触发 WFP 表遍历与替换，极可能在目标驱动**刚进入 DriverEntry 甚至正在初始化 BFE 引擎会话时**介入。
3. **内存踩踏导致野指针**：
   并发无锁读写 WFP 全局结构会导致目标驱动与系统 `fwpkclnt` 的交互事务被打乱。当目标驱动调用 `FwpmEngineOpen0(NULL, ..., &hEngine)` 时，其栈上未就绪的出参指针被污染为脏值（如 `0x0000000100000001`）。
4. **系统进程缺页保护**：
   `FwppSessionCreate` 执行 `and qword ptr [rsi], 0` 尝试清空输出句柄。由于运行于 `System` 进程，该用户态地址未映射，内存管理器判定为驱动野指针非法写，直接触发 `0x1A_4477` 蓝屏崩溃。

---

## 2. 内核 Hook 引擎设计范式：防抖等待与完备校验

为彻底杜绝加载撞车与半初始化状态，必须严格遵循以下三层防护模式：

### 2.1 模块发现防抖延迟（Debounce Delay）
探测到模块基址时，**严禁立即执行替换**，必须记录首次发现时间戳，强制保证完整的初始化窗口期（≥ 3000ms）：

```c
static LARGE_INTEGER g_TargetFirstSeenTime = { 0 };

VOID WfpBypass_SetTargetInfo(ULONG_PTR base, ULONG_PTR end)
{
    if (g_TargetBase != base)
    {
        g_TargetBase = base;
        g_TargetEnd  = end;
        KeQuerySystemTime(&g_TargetFirstSeenTime);
        DBG("[+] Target module detected [0x%p-0x%p], timestamp recorded", (PVOID)base, (PVOID)end);
    }
}

NTSTATUS WfpBypass_Init(MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    // ... 前置参数检查 ...

    /* 防抖等待：目标驱动刚加载时可能正在执行 DriverEntry，必须等待至少 3 秒 */
    if (g_TargetFirstSeenTime.QuadPart != 0)
    {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        LONGLONG elapsedMs = (now.QuadPart - g_TargetFirstSeenTime.QuadPart) / 10000LL;
        if (elapsedMs < 3000)
        {
            DBG("[*] Target recently loaded (%lld ms < 3000 ms), waiting for complete init...", elapsedMs);
            InterlockedExchange(&g_W2Init, 0);
            return STATUS_DEVICE_NOT_READY;
        }
    }

    // ... 执行实际扫描与替换 ...
}
```

### 2.2 原子 CAS 替换与 Slot 安全回滚
严禁使用非原子赋值或无条件强行覆盖。使用 `InterlockedCompareExchangePointer` 保证指针在未被系统或其它并发修改的前提下原子替换；若发生竞态，自动回滚：

```c
static BOOLEAN WfpBypass_InstallSlot(PVOID *pField, PVOID cur)
{
    LONG idx = InterlockedIncrement(&g_SlotCount) - 1;
    if (idx >= WFP_MAX_CALLOUTS)
    {
        InterlockedDecrement(&g_SlotCount);
        return FALSE;
    }

    g_Slots[idx].bUsed           = TRUE;
    g_Slots[idx].pClassifyFnField = pField;
    g_Slots[idx].origClassifyFn   = (FWPS_CALLOUT_CLASSIFY_FN2)cur;

    /* 原子 CAS 替换：仅当槽位当前值严格等于 cur 时才替换为 wrapper */
    PVOID old = InterlockedCompareExchangePointer(pField, (PVOID)g_ClassifyWrappers[idx], cur);
    if (old != cur)
    {
        DBG("[-] Slot %ld CAS failed (expected 0x%p, got 0x%p)", idx, cur, old);
        g_Slots[idx].bUsed = FALSE;
        InterlockedDecrement(&g_SlotCount);
        return FALSE;
    }
    _mm_sfence();
    return TRUE;
}
```

### 2.3 有效 Callout 计数校验（避免假成功与永久失效）
若 `WfpBypass_DoReplace` 替换数为 0，说明目标驱动虽然已分配内存，但尚未向系统注册 Callout。此时**绝不能**置成功标志（`g_Init = 1`），必须回滚并返回未就绪错误，由定时器后续重试：

```c
LONG replaced = WfpBypass_DoReplace(pTableVar, count, g_TargetBase, g_TargetEnd);
if (replaced <= 0)
{
    DBG("[*] Found 0 matching Callouts, target may still be initializing, retrying later");
    InterlockedExchange(&g_W2Init, 0);
    return STATUS_NOT_FOUND;
}

DBG("[+] Successfully replaced %ld Callouts", replaced);
return STATUS_SUCCESS;
```

---

## 3. 规避反作弊审计的后台调度架构

### 3.1 寄生系统共享工作项（ExpWorkerThread）
* **反作弊手段**：反作弊会遍历所有 `ETHREAD` 并检查其 `StartAddress`。若线程入口落在未签名驱动池或代码洞中，直接告警。
* **规避机制**：采用 `KTIMER` + `KDPC` + `ExQueueWorkItem(DelayedWorkQueue)` 代替裸系统线程。扫描逻辑在 `nt!ExpWorkerThread` 中执行，天然具备微软合法系统线程签名。

```c
typedef struct _ACE_SCAN_WORK_CONTEXT
{
    WORK_QUEUE_ITEM WorkItem; /* 必须位于结构体首部 */
    PKLDR_DATA_TABLE_ENTRY pDriverSection;
    KTIMER Timer;
    KDPC Dpc;
    volatile LONG fStopped;
    volatile LONG fWorkItemQueued;
} ACE_SCAN_WORK_CONTEXT, *PACE_SCAN_WORK_CONTEXT;

// DPC 回调防重入队
static VOID Main_ScanDpc(IN PKDPC Dpc, IN PVOID Context, IN PVOID Arg1, IN PVOID Arg2)
{
    PACE_SCAN_WORK_CONTEXT pCtx = (PACE_SCAN_WORK_CONTEXT)Context;
    if (!pCtx || InterlockedCompareExchange(&pCtx->fStopped, 0, 0) != 0)
        return;

    if (InterlockedCompareExchange(&pCtx->fWorkItemQueued, 1, 0) == 0)
    {
        ExQueueWorkItem(&pCtx->WorkItem, DelayedWorkQueue);
    }
}
```

### 3.2 驱动加载入口（DriverEntry）的激进性剥离
* 驱动入口切勿同步执行侵入式 Hook（`WfpBypass_Init`）。
* 入口仅负责设置基础参数与配置（如端口隐身配置），将安装完全托付给后台周期定时器。
* 一旦 `WfpBypass_IsInstalled()` 成功，自动调用 `KeCancelTimer` 并置停止标志退出线程，将 CPU 开销与特征暴露降为零。

---

## 4. 通信重构与网络发现避坑

### 4.1 彻底去除 IOCTL 与设备对象
* **反作弊检测点**：`IoCreateDevice` / `IoCreateSymbolicLink` 会在内核对象目录暴露具名设备或未命名设备对象，被对象扫描算法抓取。
* **无设备对象方案**：通过 Loader 在 `DriverEntry` 传入启动配置结构（BootConfig，指定通信模式为 TCP / UDP / USB）。驱动初始化对应传输后端（如 WSK 或 USB Hub），不再挂载 `IRP_MJ_DEVICE_CONTROL`。

### 4.2 UDP 发现超时与错误码映射（GLE=1167）
* **错误映射**：Win32 错误码 `1167` 对应内核 `STATUS_DEVICE_NOT_CONNECTED (0xC000009E)`。
* **根因**：若驱动在拉起 TCP/UDP 服务前需要 UDP 广播发现客户端，当客户端未开启或防火墙拦截时，5000ms 超时将导致驱动返回该状态并自卸载。
* **工程最佳实践**：提供宏开关 `ENABLE_UDP_CLIENT_DISCOVERY`，在开发调试或固定网络端口阶段旁路握手，直启服务端。

---

## 5. 传输模式按需触发与宏开关架构

### 5.1 核心原则：非网络通信模式不触碰 WFP
* 在支持多传输介质（TCP / UDP / USB）的无签名内核通信体系中，**WFP 过滤与 Callout 表替换仅对网络数据流（TCP/UDP）有意义**；
* 若当前激活的通信载体为 USB 硬件通道（如复合设备或 USB 虚拟串口），数据包根本不流经 NDIS / `netio.sys` / WFP 过滤分发链路；
* 此时若依然去挂接 WFP、启动定时器扫描或探测 `netio.sys`，纯属徒增被反作弊（ACE / EAC）感知与时序碰撞的风险。

### 5.2 双层控制架构
1. **编译期总开关宏**：`ENABLE_WFP_BYPASS`（默认 `1`，置 `0` 时完全剔除或跳过 WFP 相关例程）；
2. **运行期传输模式校验**：在 `DriverEntry` 解析 `pBootConfig->TransportMode`，仅在 `Mode == TCP || Mode == UDP` 时才启动后台扫描定时器并执行隐藏端口与模块探测；USB 模式下直接跳过，零后台开销，零 WFP 干扰。

