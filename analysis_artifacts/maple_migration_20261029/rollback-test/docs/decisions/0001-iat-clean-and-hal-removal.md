# ADR-0001: 驱动 IAT 导入表极致净化与 HAL 依赖彻底剥离

- **状态**: 已采纳
- **日期**: 2026-10-11
- **上下文与痛点**:
  驱动此前存在 17 个外部静态导入符号（包括 `HAL.dll!KeStallExecutionProcessor`、`IoAllocateIrp`、`IoFreeIrp`、`ExAllocatePoolWithTag`、`ObfDereferenceObject`、`KeInitializeEvent` 等）。静态导入表直接暴露了网络、内存申请和事件等待特征，在反作弊（如 ACE/BE）的 IAT 审计中极易被标记为高危异常驱动；同时 `HAL.dll` 的导入段破坏了驱动的隐蔽性。

- **技术决策与规范**:
  1. **剥离 HAL.dll**：禁止在内核读写中使用 `KeStallExecutionProcessor`，统一替换为 CPU 原生自旋退避指令 `_mm_pause()`，使链接器 `/OPT:REF` 自动移除 `HAL.dll` 导入段。
  2. **内存分配动态化**：`rpc_dispatch.c` 中禁止直接调用 `ExAllocatePoolWithTag` / `ExFreePoolWithTag`，统一宏重定向至 `g_pRpcUserVar->Func.*` 动态指针。
  3. **IRP 与事件全量动态化**：`usb_hub.c` 中创建、释放 IRP 和事件同步均通过 `UserVar->Func.*`，杜绝任何静态导入。
  4. **宏展开陷阱处理**：内核宏 `ExInitializeFastMutex` 内部会静默展开调用 `KeInitializeEvent`，在 `rpc_dispatch.c` 和 `leechcore_kernel.c` 中手动展开赋值 `Count=1, Owner=NULL, Contention=0` 并通过动态函数指针初始化内部事件，杜绝静态符号泄露。
  5. **IRQL 读取优化**：在 x64 平台下 `KeGetCurrentIrql` 统一使用编译器 intrinsic `(KIRQL)__readcr8()` 代替函数调用，零指令开销且不产生外部符号。
  6. **弃用 PhysicalMemory 句柄**：彻底移除 `HANDLE hPhysicalMemory;` 以及 `ZwOpenSection/ZwMapViewOfSection`，全量采用基于 PTE Remap 的物理内存映射引擎。

- **已知约束与避坑**:
  - 严禁在驱动源码中全局 `#define ObfDereferenceObject` 或 `#define IoAllocateIrp`，此类宏会污染随后的 WDK 系统头文件并导致结构体声明语法崩溃；必须在函数体内显式调用 `UserVar->Func.xxx`。
  - 最终编译产物 `drv_wsk.sys` 的 IAT 仅允许保留 SEH 异常处理必需的 `__C_specific_handler`。
