# ADR-0012: 传输层通用直通上下文强类型化与彻底根除 BugCheck 0xA (IRQL_NOT_LESS_OR_EQUAL)

- **状态**: 已采纳
- **日期**: 2026-10-14
- **核心领域**: 跨环网络通信 / 系统崩溃根治 / 类型安全防御

---

## 一、 上下文与崩溃现场剖析 (Context & BugCheck Forensics)

### 1. 故障现场与转储数据
在长时间或高频 RPC 通信压测场景下，系统触发了严重的蓝屏崩溃 `BugCheck 0xA: IRQL_NOT_LESS_OR_EQUAL`：
```text
BugCheck 0xA, {0000000000000018, 0000000000000002, 0000000000000000, fffff8002300ee5a}
Arg1: 0000000000000018 (访问无效内存)
Arg2: 0000000000000002 (当前 IRQL 为 DISPATCH_LEVEL)
Arg3: 0000000000000000 (读内存操作)
Arg4: fffff8002300ee5a (执行缺页指令地址: nt!PoRegisterDeviceForIdleDetection+0x4a)
```

崩溃调用栈如下：
```text
# Child-SP          RetAddr               Call Site
00 fffffe06`4a6cf078 fffff800`2320e229     nt!KeBugCheckEx
01 fffffe06`4a6cf080 fffff800`23209de3     nt!KiBugCheckDispatch+0x69
02 fffffe06`4a6cf1c0 fffff800`2300ee5a     nt!KiPageFault+0x463
03 fffffe06`4a6cf350 fffff800`2300f0eb     nt!PoRegisterDeviceForIdleDetection+0x4a
04 fffffe06`4a6cf390 fffff800`2300efeb     nt!PoRunDownDeviceObject+0x23
05 fffffe06`4a6cf3c0 fffff800`9014abac     nt!IoDeleteDevice+0x7b
06 fffffe06`4a6cf3f0 00000000`00000000     nvlddmkm+0x734abac (drv_wsk.sys 基址 + RVA 0x2BAC)
```

### 2. 深度反汇编与致命根因追踪 (The Smoking Gun)
通过在内核调试器 (`cdb`) 与 PE 反汇编器中联合逆向解密发现：
1. **指令精确锚定**:
   `0x140002BAC` 正好对应于 `WskAsyncSendSlot` 内联在 `WskProcessClientSession` 中的调用返回点：
   ```asm
   mov  rcx, r15           ; r15 理论上应为 pClient->Socket
   mov  rax, qword ptr [r15] ; rax 理论上应为 Socket->Dispatch
   call qword ptr [rax+30h]; 理论上应为 ((PWSK_PROVIDER_CONNECTION_DISPATCH)Dispatch)->WskSend
   cmp  eax, 103h          ; STATUS_PENDING (0x140002BAC)
   ```
2. **结构体强转与内存错位 (Struct Miscast Corruption)**:
   - 在 `rpc_dispatch.h` 中，`MkRpc_DispatchCommandEx` 定义的第 1 个参数为裸指针 `_In_opt_ PVOID pTransportContext`，其内部将其无条件强转为 `(PMK_TRANSPORT_CONTEXT)pTransportContext`。
   - `MK_TRANSPORT_CONTEXT` 的定义如下：
     ```c
     typedef struct _MK_TRANSPORT_CONTEXT {
         HANDLE Cached_hLC;           // 偏移 0x00
         ULONG Cached_dwRpcClientID;  // 偏移 0x08
     } MK_TRANSPORT_CONTEXT;
     ```
   - 然而在 `wsk_server.c` 中，调用方直接传入了会话上下文裸指针：`MkRpc_DispatchCommandEx(pClient, ...)`！
   - 而 `MK_WSK_CLIENT` 的头部定义为：
     ```c
     typedef struct _MK_WSK_CLIENT {
         PWSK_SOCKET Socket;          // 偏移 0x00 ！！！！！！！！！！！！
         SOCKADDR_IN RemoteAddr;      // 偏移 0x08 ！！！！！！！！！！！！
         ...
     ```
   - 当 `MkRpc_DispatchCommandEx` 执行 `pTransCtx->Cached_hLC = hLC;` 时，**将 `hLC`（即 `LC_CONTEXT*`，值如 `0xffff9d04ad3c3000`）强行写到了 `pClient->Socket` 的位置，直接将合法套接字对象覆灭踩踏**！
3. **连锁崩溃路径 (The Domino Effect)**:
   - 被踩踏后的 `pClient->Socket` 变成了 `LC_CONTEXT` 结构体指针。
   - `LC_CONTEXT` 的偏移 `+0x00` 正好是 `MACHENIKE_KERNEL_INTERFACE *UserVar`！
   - 于是 `WskAsyncSendSlot` 中的 `rax = Socket->Dispatch` 实际上读取到了 `UserVar`！
   - `UserVar->Func` 结构体的偏移 `+0x30` 处正是系统函数 `IoDeleteDevice`！
   - 汇编执行 `call qword ptr [rax+30h]`，实际上直接调用了 `nt!IoDeleteDevice`，并把传入的伪 Socket（实际上是 `LC_CONTEXT` 指针）作为 `DeviceObject` 传了进去！
   - `IoDeleteDevice` 解引用非法的 `DeviceObjectExtension`（全 0），在 `PoRegisterDeviceForIdleDetection` 中访问 `[0x0 + 0x18]` 导致 DISPATCH_LEVEL 缺页异常，最终瞬间触发蓝屏 `BugCheck 0xA`！

---

## 二、 技术决策与加固规范 (Technical Decisions)

### 1. 传输层通用直通上下文强类型化
- 彻底废除 `MkRpc_DispatchCommand` 与 `MkRpc_DispatchCommandEx` 中使用 `PVOID` 作为直通上下文的弱类型设计。
- 显式声明 `_In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext`，利用 MSVC 编译期强类型检查，从源头杜绝任何不同结构体指针的误传。
- 在 `MK_WSK_CLIENT` 中原生嵌入 `MK_TRANSPORT_CONTEXT TransportCtx;`（通过匿名联合体与原有访问模式完全兼容），所有网络子模块在下发 RPC 调度时统一传入 `&pClient->TransportCtx`。

### 2. IRP 栈深度升级 (StackSize = 4)
- 放弃处于理论危险极限的 `StackSize = 1` 分配模式；
- 在 `WskAllocateSyncIrp` 与 `WskClient_InitPersistentResources` 中，统一将 `IoAllocateIrp` 栈大小指定为 4（`StackSize = 4`），为 Windows 复杂环境下底层的 TDI/WFP 过滤驱动、网络安全组件及多层协议栈转发提供充足的余量，杜绝 IRP 栈下溢越界踩踏（Stack Location Underflow）。

### 3. 指针空间防御性规范 (Kernel Pointer Sanity Check)
- 在任何高频网络派遣（`WskSend`、`WskReceive`）及异步槽位出网前，强制执行 Canonical Address 内核高半区指针合法性校验：
  ```c
  if (!Socket || !Socket->Dispatch ||
      (ULONG_PTR)Socket < 0xFFFF800000000000ULL ||
      (ULONG_PTR)Socket->Dispatch < 0xFFFF800000000000ULL)
  {
      return STATUS_INVALID_PARAMETER;
  }
  ```

---

## 三、 系统级负向知识与避坑铁律 (Negative Knowledge & Hard Rules)

1. **结构体强转与跨层多态必须 100% 强类型化**：
   - 严禁在驱动多子系统交互时使用 `PVOID` 传递包含可写成员的私有状态上下文；
   - 必须通过具名类型（如 `PMK_TRANSPORT_CONTEXT`）显式传递，杜绝隐式强转篡改相邻对象首字段。
2. **IRP 栈位置绝不使用 StackSize = 1**：
   - 在任何可能穿透至下层未知过滤驱动栈的 IRP 分配中，栈大小必须至少为 4，防范完成例程设置后下层二次转发引发栈溢出。
3. **蓝屏 BugCheck 0xA (IRQL_NOT_LESS_OR_EQUAL) 负向知识登记**：
   - 现象：`IoDeleteDevice` 被非预期调用，且参数为包含内核常驻对象的池指针。
   - 根因：套接字指针 `Socket` 头部被跨层结构体强转踩踏，误将 `UserVar` 作为虚表调入 `+0x30 (IoDeleteDevice)`。
