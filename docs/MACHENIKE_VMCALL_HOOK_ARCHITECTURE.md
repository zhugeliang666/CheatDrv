# Machenike VMCALL Hook 驱动接口与内核回调架构设计规范

- **状态**: 设计就绪 (Ready for Implementation)
- **目标模块**: `Core/DriverCore`、`Stealth/VtEngine`、`vt/VtResidentPayload/hooks/vtcall-hook`
- **对齐架构**: x64 (AMD SVM / Intel VT-x)

---

## 1. 架构定位与分层总览

本方案旨在为 **Machenike 驱动业务层（Ring 0）** 建立直接调度 **Hypervisor（Host Ring -1）** 的影子页执行钩子（VMCALL Hook）服务。通过改写硬件 VMCS/VMCB 控制块与执行流原位重定向，使得目标函数触发 Hook 后，能无缝回弹执行驱动层注册的 C/C++ 内核回调函数。

```
┌────────────────────────────────────────────────────────┐
│             Machenike 驱动层 (Guest Ring 0)             │
│                                                        │
│  [业务逻辑] ──> VtEngine::VmcallHook::Install(...)      │
│      ▲                                                 │
│      │ 回弹执行 (同线程、同 IRQL、零线程开销)              │
│  [内核回调] MyKernelHookCallback(PHOOK_CONTEXT Ctx)     │
└──────┬─────────────────────────────────────────────────┘
       │ Hypercall (VT_HC_ADD_VMCALL_HOOK)
       ▼
┌────────────────────────────────────────────────────────┐
│             Hypervisor 宿主层 (Host Ring -1)            │
│                                                        │
│  1. 申请 Hook 槽位 (vt_hook_slot)                       │
│  2. 在 EPT/NPT 物理影子页写入 3 字节打桩 (0F 01 C1)        │
│  3. 拦截 VM-Exit (VMCALL)，执行原位上下文重定向            │
│  4. 捕获回调 ret 命中 ReturnStub，恢复原函数现场         │
└────────────────────────────────────────────────────────┘
```

---

## 2. 跨环通信协议与数据结构契约

通信结构体严格遵循 **8 字节固定宽度对齐** 与 **显式 `#pragma pack(push, 8)`** 规范，杜绝裸指针与平台歧义类型。

```cpp
#pragma once
#include <ntddk.h>

#pragma pack(push, 8)

// 钩子操作子功能码
enum VT_VMCALL_HOOK_OP : UINT32
{
    VT_HOOK_OP_INSTALL   = 1,
    VT_HOOK_OP_UNINSTALL = 2,
    VT_HOOK_OP_ENABLE    = 3,
    VT_HOOK_OP_DISABLE   = 4
};

// 驱动与 Hypervisor 交互的载荷结构体
struct VT_VMCALL_HOOK_REQUEST
{
    UINT32 Op;                  // 操作码 (VT_VMCALL_HOOK_OP)
    UINT32 Type;                // 钩子业务编号 (1 ~ 32)
    UINT64 Process;             // 目标 PEPROCESS (0 表示当前/系统进程)
    UINT64 TargetVa;            // 目标挂钩虚地址
    UINT64 CallbackVa;          // 触发时要执行的 Ring 0 内核回调函数 VA
    UINT64 ReturnStubVa;        // 回调返回时命中的 VMCALL 陷阱桩 VA
    UINT32 SwitchCr3;           // 是否在硬件层切换至目标进程 CR3 (1/0)
    UINT32 FilterByProcess;     // 是否仅在目标进程上下文中拦截 (1/0)
    UINT64 CustomData;          // 业务自定义透传字段
    UINT64 Status;              // 输出：执行状态码 (NTSTATUS)
};

// 传递给内核回调的寄存器上下文快照
struct HOOK_REGISTER_CONTEXT
{
    // 通用寄存器快照
    ULONG64 R15, R14, R13, R12, R11, R10, R9, R8;
    ULONG64 Rdi, Rsi, Rbp, Rbx, Rdx, Rcx, Rax;
    ULONG64 Rflags;

    // 执行流控制
    ULONG64 OriginalRip;        // 触发 Hook 处的原始指令 VA
    ULONG64 OriginalRsp;        // 触发 Hook 处的原始栈指针
    ULONG64 HookType;           // 业务钩子编号
    ULONG64 CustomData;         // 安装时绑定的自定义参数

    // 行为决策标记
    BOOLEAN SkipOriginal;       // [输出控制] 置 TRUE 则阻断原函数，直接跳到原函数 ret
    BOOLEAN Modified;           // [输出控制] 置 TRUE 则将当前结构体寄存器同步回硬件
};
typedef HOOK_REGISTER_CONTEXT *PHOOK_REGISTER_CONTEXT;

// Machenike 内核回调函数原型
typedef VOID (*PFN_MACHENIKE_HOOK_CALLBACK)(_Inout_ PHOOK_REGISTER_CONTEXT Ctx);

#pragma pack(pop)
```

---

## 3. Machenike 驱动层接口（纯静态类封装）

遵循**第七节纯静态类**原则，在 `Stealth/VtEngine.h` 中提供业务直接调用的聚合接口：

```cpp
class VtEngine
{
public:
    class VmcallHook
    {
    public:
        // 安装 VMCALL 影子钩子并绑定内核回调
        static NTSTATUS Install(
            _In_opt_ PEPROCESS Process,
            _In_ ULONG64 TargetVa,
            _In_ UINT32 HookType,
            _In_ PFN_MACHENIKE_HOOK_CALLBACK Callback,
            _In_ BOOLEAN SwitchCr3 = FALSE,
            _In_ BOOLEAN FilterByProcess = TRUE,
            _In_ ULONG64 CustomData = 0);

        // 卸载钩子并还原影子页
        static NTSTATUS Uninstall(_In_ ULONG64 TargetVa);

        // 动态启停拦截 (零内存修改，纯 Host 状态翻转)
        static NTSTATUS SetState(_In_ ULONG64 TargetVa, _In_ BOOLEAN Enable);
    };
};
```

---

## 4. Host-to-Guest 执行流原位回弹核心实现

### 4.1 完整执行时序与堆栈变换

```
1. 目标函数命中影子页: 0F 01 C1 (vmcall)
2. CPU 触发 VM-Exit 陷入 Host Ring -1
3. Host 保存原始上下文，并在 Guest 当前内核栈构建调用帧:

   Guest Kernel Stack Layout:
   [ 高地址 ]
   ──────────────────────────────────────────────────
   ... 原函数栈帧 (Caller Stack Frame) ...
   ────────────────────────────────────────────────── <── Original RSP
   HOOK_REGISTER_CONTEXT 结构体 (由 Host 写入寄存器快照)
   ────────────────────────────────────────────────── <── 传给回调的 RCX
   0x20 字节 Shadow Space (Windows x64 ABI 保留区)
   ──────────────────────────────────────────────────
   ReturnStubVa (8 字节: 回调 ret 时的返回地址)
   ────────────────────────────────────────────────── <── New RSP (满足 16 字节对齐)
   [ 低地址 ]

4. Host 设置 VMCS_GUEST_RIP = CallbackVa, VMCS_GUEST_RSP = New RSP
5. VMRESUME 退出虚拟化，CPU 直接以 Ring 0 运行用户的 MyKernelHookCallback
6. 回调执行完毕 ret，直接跳到 ReturnStub 触发第二次 VMCALL 陷入 Host
7. Host 恢复原始执行现场，无缝继续跑原函数指令
```

### 4.2 Hypervisor 宿主层调度伪代码 (Host Ring -1)

```cpp
// 阶段 1：捕获钩子命中，重定向执行流至内核回调
VOID HandleVmcallHookHit(
    _In_ ULONG CpuIndex,
    _Inout_ PGUEST_REGS Regs,
    _In_ const vt_hook_slot* Slot)
{
    ULONG_PTR guestRsp = __vmx_vmread(VMCS_GUEST_RSP);
    ULONG_PTR guestRip = __vmx_vmread(VMCS_GUEST_RIP);

    // 1. 在当前 Guest 内核栈保留上下文并计算 16 字节对齐栈顶
    // 计算公式: NewRsp 满足 (NewRsp % 16) == 8，ret 后进入函数时变为 (RSP % 16) == 0
    ULONG_PTR ctxAddr = (guestRsp - sizeof(HOOK_REGISTER_CONTEXT)) & ~0xFull;
    ULONG_PTR newRsp  = ctxAddr - 0x28; // 0x20 shadow space + 0x08 return address

    // 2. 构造上下文快照并写入 Guest 栈
    HOOK_REGISTER_CONTEXT ctx = {};
    ctx.Rax = Regs->rax; ctx.Rbx = Regs->rbx; ctx.Rcx = Regs->rcx; ctx.Rdx = Regs->rdx;
    ctx.Rsi = Regs->rsi; ctx.Rdi = Regs->rdi; ctx.Rbp = Regs->rbp;
    ctx.R8  = Regs->r8;  ctx.R9  = Regs->r9;  ctx.R10 = Regs->r10; ctx.R11 = Regs->r11;
    ctx.R12 = Regs->r12; ctx.R13 = Regs->r13; ctx.R14 = Regs->r14; ctx.R15 = Regs->r15;
    ctx.Rflags = __vmx_vmread(VMCS_GUEST_RFLAGS);
    ctx.OriginalRip = guestRip;
    ctx.OriginalRsp = guestRsp;
    ctx.HookType    = Slot->data.type;
    ctx.CustomData  = Slot->data.custom_data;
    ctx.SkipOriginal = FALSE;
    ctx.Modified     = FALSE;

    // 写入 Guest 内核栈内存
    PayloadCopyHostToGuest(ctxAddr, &ctx, sizeof(ctx));
    // 写入返回地址 [newRsp] = ReturnStubVa
    PayloadCopyHostToGuest(newRsp, &Slot->data.return_stub_va, sizeof(ULONG64));

    // 3. 改写执行流目标
    __vmx_vmwrite(VMCS_GUEST_RIP, Slot->data.callback_va);
    __vmx_vmwrite(VMCS_GUEST_RSP, newRsp);
    Regs->rcx = ctxAddr; // 第一参数 RCX 指向栈上的上下文

    // VMRESUME 即刻进入 Ring 0 回调
}

// 阶段 2：内核回调 ret 命中 ReturnStub，第二次陷入 Host 恢复现场
VOID HandleCallbackReturnTrap(
    _In_ ULONG CpuIndex,
    _Inout_ PGUEST_REGS Regs,
    _In_ const vt_hook_slot* Slot)
{
    ULONG_PTR ctxAddr = Regs->rcx; // 回调执行期间保留或从保存链表索引
    HOOK_REGISTER_CONTEXT ctx = {};
    PayloadCopyGuestToHost(&ctx, ctxAddr, sizeof(ctx));

    // 1. 若回调篡改了寄存器，同步更新至当前通用寄存器
    if (ctx.Modified) {
        Regs->rax = ctx.Rax; Regs->rcx = ctx.Rcx; Regs->rdx = ctx.Rdx;
        Regs->r8  = ctx.R8;  Regs->r9  = ctx.R9;
    }

    // 2. 还原原始栈指针
    __vmx_vmwrite(VMCS_GUEST_RSP, ctx.OriginalRsp);

    // 3. 判定是否阻断原函数
    if (ctx.SkipOriginal) {
        // 直接跳至原调用者的返回地址 (读取 [OriginalRsp])
        ULONG_PTR callerRetAddr = 0;
        PayloadCopyGuestToHost(&callerRetAddr, ctx.OriginalRsp, sizeof(ULONG_PTR));
        __vmx_vmwrite(VMCS_GUEST_RIP, callerRetAddr);
        __vmx_vmwrite(VMCS_GUEST_RSP, ctx.OriginalRsp + 8); // 弹出返回地址
    } else {
        // 恢复执行原函数打桩指令之后的下一条指令
        __vmx_vmwrite(VMCS_GUEST_RIP, ctx.OriginalRip + Slot->data.size);
    }
}
```

---

## 5. 业务使用示例（Machenike 驱动端）

```cpp
// 1. 实现自定义内核回调
VOID MyNetworkPacketCallback(_Inout_ PHOOK_REGISTER_CONTEXT Ctx)
{
    // 读取拦截点参数
    PVOID packetBuffer = (PVOID)Ctx->Rdx;
    ULONG packetSize   = (ULONG)Ctx->R8;

    DBG("[*] 拦截到网络分发: Buffer=%p Size=%lu", packetBuffer, packetSize);

    // 修改参数示例：强制重写数据长度
    // Ctx->R8 = 0;
    // Ctx->Modified = TRUE;

    // 阻断原函数示例：强制返回 STATUS_ACCESS_DENIED
    // Ctx->Rax = STATUS_ACCESS_DENIED;
    // Ctx->SkipOriginal = TRUE;
}

// 2. 注册并激活 VMCALL 钩子
NTSTATUS StartPacketHook(ULONG64 TargetFunctionVa)
{
    return VtEngine::VmcallHook::Install(
        NULL,                   // 系统内核函数
        TargetFunctionVa,       // 目标挂钩 VA
        1,                      // 业务钩子编号 (HookType)
        MyNetworkPacketCallback,// 绑定的内核回调
        FALSE,                  // 无需切换 CR3
        FALSE                   // 全局内核生效
    );
}
```

---

## 6. 避坑准则与防御性铁律

1. **IRQL 与栈空间安全性**：
   - 钩子回弹借用的是原线程当前的内核栈。Windows 内核栈默认为 24KB（大栈为 28KB）。
   - 回调函数内部**严禁分配巨大的局部数组（如 `UCHAR buf[4096]`）**，以防在深层调用链下引发栈溢出内核蓝屏（BugCheck `0x7F`）。
2. **多核影子页原子同步**：
   - 安装或卸载钩子改写物理影子页时，必须通过 IPI 广播驱动所有逻辑核心执行 `INVEPT`（Intel）或同步刷新 `VMCB.N_CR3`（AMD），确保无缓存脏指令残留。
3. **Intel CET（影子栈）相容**：
   - 若目标函数启用了 CET，修改栈上的返回地址可能触发 `#CP` 异常。在压入 `ReturnStubVa` 前，Hypervisor 需临时保存并在退出前屏蔽 Guest CR4 的 CET 控制位，处理完毕后透明恢复。
