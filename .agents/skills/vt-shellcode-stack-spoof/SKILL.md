---
name: vt-shellcode-stack-spoof
description: >-
  R3 Shellcode 调用目标进程函数时的堆栈伪造（Call Stack Spoofing）、深层栈回溯隐匿、反 Call-Site 指令审计及多挂钩点（Multi-Hook）扩展工程规范。
  包含纯 R3 双级真 call Gadget 方案（兼容 CFG FF 15 与裸 FF D0）、基于 VT
  EXEC_SHADOW_READ_ORIGINAL 双视图的“幽灵 call 点”方案、全进程通用的 OriginalRsp 原生栈嫁接 +
  .pdata (UNWIND_INFO) 动态栈帧对齐方案，以及已注入 Shellcode 新增多挂钩点（X1/X2... 埋点拦截 + 寄存器现场读写 + 多槽位并发隔离）标准架构。当在 DebugShellcode 或 R3 注入模块中需要调用游戏/系统 R3
  函数、隐藏返回地址、或新增额外 Hook 跳入 Shellcode 内部函数时使用此技能。
---

# R3 Shellcode 函数调用与反审计堆栈伪造规范 (VT & Pure R3 Stack Spoofing)

本技能沉淀了在 [`DebugShellcode`](../../../DebugShellcode/DebugShellcode.cpp) 与 [`VtEngine`](../../../Stealth/VtEngine.h) 架构下，从无模块/双视图 Shellcode 安全调用 R3 目标函数并绕过反作弊（ACE / EAC / Vanguard / BattlEye）栈回溯、深层栈扫描與 **`Call-Site` 前置指令审计（`call xxx` 校验）** 的三套核心方案。

---

## 一、 反作弊栈审计的四大核心检测面

1. **一阶：栈顶 `_ReturnAddress()` 内存归属与可读性审计**
   - 直接在 Shellcode 中执行 `call TargetFunc` 会将 `MEM_PRIVATE` 无模块地址压入 `[rsp]`；
   - 若 Shellcode 开启了 `VT_EH_VIEW_EXEC_SHADOW_READ_ZERO (2)`，反作弊读取 `[rsp]` 指向的代码页会读到全 `0x00`，立即触发异常执行流判定。
2. **二阶：`Call-Site` 前置指令合法性审计（`call xxx` 校验）与 Gadget 特征码审计**
   - **向后看（`RetAddr - 2 ~ RetAddr - 6`）**：检查返回地址紧邻的前一条指令是否为真实 `CALL`（如 `E8 rel32` [5B]、`FF 15 disp32` [6B]、`FF D0..D7` [2B]、`FF 50..57 disp8` [3B]）；若为 `E8 rel32`，还会解算相对偏移校验目标地址是否为被调用函数。
   - **向前看（`RetAddr` 本身）**：扫描 `RetAddr` 处是否为公开 Spoofer 常见的裸 `FF 23` (`jmp qword ptr [rbx]`) / `FF 27` (`jmp qword ptr [rdi]`)。
3. **三阶：`RtlVirtualUnwind` (`.pdata`) 异常展开与硬件 `USER_CET` 影子栈**
   - 通过 `RtlLookupFunctionEntry` 查验每一层 `RetAddr` 所在函数的 `UNWIND_INFO` 栈帧大小（`FrameSize`），机械执行 `NextRsp = CurrentRsp + FrameSize` 逐层向上展开；
   - 开启硬件用户态影子栈（`CR4.CET` / `IA32_U_CET`）时，用 `push + jmp` 伪造调用会导致目标函数 `ret` 时触发 `#CP` 异常。
4. **四阶：深层栈帧展开与线程栈暴力扫描（Deep Unwind & Raw Stack Walk）**
   - 即便伪造了栈顶第 0~1 层，若 `X1` 与 `RuntimeDispatch` 直接运行在当前线程栈上，向高地址继续展开（或从 `RSP` 到 `TEB->StackBase` 暴力逐 QWORD 扫描）仍会扫出压在栈底的 `X1` / `RuntimeDispatch` (`0x2E69A7Bxxxx`) 返回地址。

---

## 二、 方案一：纯 R3 “真 `call` + 尾声退栈”双级 Gadget 方案（兼容 CFG / 0 VM-Exit / 原生过 CET）

### 1. 适用场景与优势
- **不占用额外 EPT/NPT 钩子槽位**，100% 在 R3 [`DebugShellcode`](../../../DebugShellcode/DebugShellcode.cpp) 内闭环；
- **真正执行合法模块内的 `call` 指令**：
  * 兼容裸 `FF D0` (`call rax`, 2B) 与现代 Win10/Win11 开启 CFG (`/guard:cf`) 后的 **`FF 15 disp32` (`call cs:__guard_dispatch_icall_fptr`, 6B，同样以 `rax` 为目标地址）**；
  * `RetAddr` 处是正常的函数尾声 `add rsp, 28h; ret`（`48 83 C4 28 C3`），无 `FF 23` 特征；
  * 由 CPU 硬件真正执行 `call` 与 `ret`，**原生通过硬件 `USER_CET` 影子栈校验**。

### 2. Gadget 扫描算法（支持跨模块累积 + CFG `FF 15` 兼容 + 严禁本地回退）
> [!CAUTION]
> **踩坑红线**：
> 1. **严禁在 `ScanTextForSpoofGadgets` 开头清零 `OutGadgets`**：必须允许 `CallRaxAddRsp28Ret` 与 `JmpQwordPtrRbx` 分别来自不同合法模块（如 `ntdll.dll` + `kernel32.dll`）；
> 2. **严禁回退（Fallback）到 Shellcode 自身内部的汇编标签**：若回退到 Shellcode 内部的 `SpoofPlan1CallRaxGadget`，`call rax` 压入的返回地址将直接落在 Shellcode `.text`（如 `+0x3CF6`），导致伪造完全失效。

```cpp
struct SPOOF_GADGET_PAIR {
    ULONG64 CallRaxAddRsp28Ret; // 指向 `FF D0 48 83 C4 28 C3` 或 `FF 15 .. .. .. .. 48 83 C4 28 C3` 首地址
    ULONG64 JmpQwordPtrRbx;     // 指向 `FF 23` 首地址
};

// 校验 FF 15 disp32 (call qword ptr [rip+disp32]) 指向的目标指针是否可读且指向同模块或合法代码(如 __guard_dispatch_icall_fptr)
static BOOLEAN IsValidCfgIndirectCallRet28(
    _In_ ULONG_PTR ModuleBase,
    _In_ ULONG ImageSize,
    _In_ const UCHAR* Insn)
{
    // FF 15 xx xx xx xx 48 83 C4 28 C3 (共 11 字节)
    if (Insn[0] != 0xFF || Insn[1] != 0x15 ||
        Insn[6] != 0x48 || Insn[7] != 0x83 || Insn[8] != 0xC4 || Insn[9] != 0x28 || Insn[10] != 0xC3)
    {
        return FALSE;
    }
    const INT32 disp = *reinterpret_cast<const INT32*>(Insn + 2);
    const ULONG_PTR ptrSlot = reinterpret_cast<ULONG_PTR>(Insn + 6) + static_cast<INT_PTR>(disp);
    if (ptrSlot < ModuleBase || ptrSlot + sizeof(ULONG_PTR) > ModuleBase + ImageSize)
        return FALSE;
    return (*reinterpret_cast<const ULONG_PTR*>(ptrSlot) != 0);
}

static BOOLEAN ScanTextForSpoofGadgets(
    _In_ ULONG_PTR ModuleBase,
    _Inout_ SPOOF_GADGET_PAIR* OutGadgets)
{
    if (!ModuleBase || !OutGadgets)
        return FALSE;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    const ULONG imageSize = nt->OptionalHeader.SizeOfImage;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; ++s)
    {
        if ((sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        const ULONG size = sec[s].Misc.VirtualSize ? sec[s].Misc.VirtualSize : sec[s].SizeOfRawData;
        const UCHAR* base = reinterpret_cast<const UCHAR*>(ModuleBase + sec[s].VirtualAddress);

        for (ULONG i = 0; i + 11 <= size; ++i)
        {
            if (!OutGadgets->CallRaxAddRsp28Ret)
            {
                // 优先匹配裸 call rax; add rsp, 28h; ret (7B)
                if (base[i] == 0xFF && base[i + 1] == 0xD0 &&
                    base[i + 2] == 0x48 && base[i + 3] == 0x83 &&
                    base[i + 4] == 0xC4 && base[i + 5] == 0x28 && base[i + 6] == 0xC3)
                {
                    OutGadgets->CallRaxAddRsp28Ret = reinterpret_cast<ULONG64>(base + i);
                }
                // 兼容 Win10/Win11 CFG 间接调用: call cs:[__guard_dispatch_icall_fptr]; add rsp, 28h; ret (11B)
                else if (IsValidCfgIndirectCallRet28(ModuleBase, imageSize, base + i))
                {
                    OutGadgets->CallRaxAddRsp28Ret = reinterpret_cast<ULONG64>(base + i);
                }
            }
            if (!OutGadgets->JmpQwordPtrRbx &&
                base[i] == 0xFF && base[i + 1] == 0x23)
            {
                OutGadgets->JmpQwordPtrRbx = reinterpret_cast<ULONG64>(base + i);
            }
            if (OutGadgets->CallRaxAddRsp28Ret && OutGadgets->JmpQwordPtrRbx)
                return TRUE;
        }
    }
    return (OutGadgets->CallRaxAddRsp28Ret && OutGadgets->JmpQwordPtrRbx);
}
```

### 3. MASM 汇编桩实现（支持前 4 寄存器参数 + 栈参数自动对齐）
```asm
; struct SPOOF_CALL_CONTEXT {
;     ULONG64 FixupRip;           // +0x00: 指向 SpoofNativeFixup (供二级 jmp [rbx] 解引用)
;     ULONG64 SavedRbx;           // +0x08: 备份原非易失性 rbx
;     ULONG64 SavedRetAddr;       // +0x10: 备份 C++ 调用点真实返回地址
;     ULONG64 CallRaxGadget;      // +0x18: 指向合法模块 `call rax; add rsp, 28h; ret`
;     ULONG64 JmpRbxGadget;       // +0x20: 指向合法模块 `jmp qword ptr [rbx]`
;     ULONG64 TargetFunc;         // +0x28: 目标 R3 函数地址
; };
; 传入约定: rcx, rdx, r8, r9 = 前 4 参数, r10 = &SPOOF_CALL_CONTEXT

PUBLIC SpoofCallNativeAsm
SpoofCallNativeAsm PROC
    pop rax                         ; 弹出 C++ 包装器的返回地址 (此时 RSP % 16 == 0)
    mov [r10 + 08h], rbx            ; 保存原 rbx
    mov [r10 + 10h], rax            ; 保存 C++ 真实返回地址
    lea rax, SpoofNativeFixup
    mov [r10 + 00h], rax            ; [r10] = SpoofNativeFixup

    mov rbx, r10                    ; rbx = &SPOOF_CALL_CONTEXT (Callee-saved)
    push qword ptr [r10 + 20h]      ; 压入二级返回地址 JmpRbxGadget (RSP - 8 -> RSP % 16 == 8)
    sub rsp, 28h                    ; 分配 28h 匹配 `add rsp, 28h` (RSP - 28h -> RSP % 16 == 0)
    mov rax, [r10 + 28h]            ; rax = TargetFunc
    jmp qword ptr [r10 + 18h]       ; 跳入合法模块执行 `call rax` (压栈后进入 TargetFunc 时 RSP % 16 == 8)

SpoofNativeFixup LABEL BYTE
    mov r10, rbx                    ; 从 `add rsp, 28h; ret` -> `jmp [rbx]` 回到此处
    mov rbx, [r10 + 08h]            ; 恢复原 rbx
    jmp qword ptr [r10 + 10h]       ; 返回 C++ 调用方
SpoofCallNativeAsm ENDP
```

---

## 三、 方案二：基于 VT `EXEC_SHADOW_READ_ORIGINAL` 的“幽灵 `call` 点”方案（极致隐蔽）

### 1. 核心原理与降维打击优势
利用本项目 [`VtEngine::EhInstall`](../../../Stealth/VtEngine.cpp) 原生支持的 **模式 0 双视图（`VT_EH_VIEW_EXEC_SHADOW_READ_ORIGINAL = 0`：执行走影子页 `fake_pfn`，读取走原始页 `orig_pfn`）**：
1. 在目标进程合法模块（如游戏主模块或 `user32.dll`）中，选取一处处于冷分支（正常逻辑不触发）的真实 `CALL` 指令 `CallSiteVa`（可以是 `FF 15 disp32` 6B 间接调用，甚至是原本就调用目标函数的 `E8 rel32` 5B 直接调用）。
2. 计算其紧邻的返回落点 `GhostRetVa = CallSiteVa + CallInstLen`。
3. 驱动通过 `VtEngine::EhInstall(Process, GhostRetVa, FALSE, VT_EH_VIEW_EXEC_SHADOW_READ_ORIGINAL)` 安装双视图，并通过 `VtEngine::EhWrite` **仅在影子执行页** 的 `GhostRetVa` 处写入 2 字节 `FF 23` (`jmp qword ptr [rbx]`)。
4. **效果**：
   - **反作弊读取校验时（触发 EPT/NPT Read 视图）**：读到的是 100% 原装未改动的物理页——`GhostRetVa` 前方是真实的 `call` 指令（若选 `E8` 则连调用目标偏移都 100% 匹配），`GhostRetVa` 处是原装后续指令，**内存中完全不存在 `FF 23` 字节**，CRC/完整性校验与 `.pdata` 栈展开 100% 完美通过。
   - **目标函数 `ret` 返回时（触发 EPT/NPT Execute 视图）**：CPU 从影子页取指执行 `FF 23` (`jmp qword ptr [rbx]`)，**0 次 VM-Exit** 直接跳回 Shellcode！

### 2. 驱动侧（`VtEngine`）安装与清理模板
```cpp
// 安装幽灵返回点（在选定的合法模块冷分支 call 指令下一条指令地址 GhostRetVa 上挂载）
static BOOLEAN InstallGhostCallReturnSite(
    _In_ ULONG64 Process,
    _In_ ULONG64 GhostRetVa)
{
    // 严禁跨页：FF 23 共 2 字节
    if ((GhostRetVa & (PAGE_SIZE - 1)) > PAGE_SIZE - 2)
        return FALSE;

    if (!VtEngine::EhInstall(Process, GhostRetVa, FALSE, VT_EH_VIEW_EXEC_SHADOW_READ_ORIGINAL))
        return FALSE;

    const UCHAR kJmpRbx[2] = { 0xFF, 0x23 }; // jmp qword ptr [rbx]
    if (!VtEngine::EhWrite(Process, GhostRetVa, kJmpRbx, sizeof(kJmpRbx)))
    {
        VtEngine::EhRemove(Process, GhostRetVa);
        return FALSE;
    }
    return TRUE;
}

// 卸载清理时成对移除
static BOOLEAN RemoveGhostCallReturnSite(
    _In_ ULONG64 Process,
    _In_ ULONG64 GhostRetVa)
{
    return VtEngine::EhRemove(Process, GhostRetVa);
}
```

### 3. Shellcode 侧汇编桩与 C++ 变参调用模板（零栈位移，支持任意 `0~N` 参数）
由于 `GhostRetVa` 在影子页直接是 `FF 23`，采用 `pop rax` + `push GhostRetVa` + `jmp TargetFunc` 构造调用，**栈指针 `RSP` 与标准 `call` 指令完全重合**，第 5 个及以上的栈参数（`[rsp+0x28]` 起）无需任何拷贝搬运！

```asm
; struct GHOST_SPOOF_CONTEXT {
;     ULONG64 FixupRip;      // +0x00: 指向 SpoofGhostFixup
;     ULONG64 SavedRbx;      // +0x08: 备份原 rbx
;     ULONG64 SavedRetAddr;  // +0x10: 备份 C++ 调用方真实返回地址
;     ULONG64 GhostRetVa;    // +0x18: 驱动已安装双视图的合法模块 `call` 后地址
;     ULONG64 TargetFunc;    // +0x20: 目标 R3 函数地址
; };

PUBLIC SpoofCallGhostAsm
SpoofCallGhostAsm PROC
    pop rax                         ; 弹出真实返回地址
    mov [r10 + 08h], rbx            ; 保存原 rbx
    mov [r10 + 10h], rax            ; 保存真实返回地址
    lea rax, SpoofGhostFixup
    mov [r10 + 00h], rax            ; [r10] = SpoofGhostFixup

    mov rbx, r10                    ; rbx = &GHOST_SPOOF_CONTEXT
    mov r11, [r10 + 20h]            ; r11 = TargetFunc
    push qword ptr [r10 + 18h]      ; 压入 GhostRetVa (保持 RSP % 16 == 8，且第 5+ 参数偏移不变)
    jmp r11                         ; 跳入目标 R3 函数

SpoofGhostFixup LABEL BYTE
    mov r10, rbx                    ; 目标函数 ret -> GhostRetVa (影子页 FF 23) -> 跳回此处
    mov rbx, [r10 + 08h]            ; 恢复原 rbx
    jmp qword ptr [r10 + 10h]       ; 返回 C++ 调用方
SpoofCallGhostAsm ENDP
```

---

## 四、 方案三：全进程通用的深层栈回溯（Deep Unwind & Raw Stack Scan）彻底隐匿架构

当反作弊或调试器沿着 `UNWIND_INFO` 展开第 2 层以上的深层栈帧，或对线程栈 `RSP ~ TEB->StackBase` 进行暴力扫描（Raw Stack Scan）时，仅靠栈顶双层 Gadget 仍会暴露压在栈底的 `X1` 与 `RuntimeDispatch` 返回地址。通过 **「入口 `OriginalRsp` 锚点 + 私有数据页栈切换 + `.pdata` 动态算帧嫁接」** 可实现 **100% 跨进程、跨挂钩点通用** 的全栈隐匿。

### 1. 为什么 `OriginalRsp` 锚点在任何进程/挂钩点下都 100% 通用？
无论通过 `InstallHookToShellcode` 挂钩的是什么进程（游戏、办公软件、浏览器）或什么函数（`WndProc`、DX11/12 `Present`、游戏主循环 `Tick`）：
- 在被挂钩函数首指令跳入 [`X1`](../../../DebugShellcode/DebugShellcodeAsm.asm) 的瞬间，当时的硬件 `RSP`（记为 **`OriginalRsp`**）永远指向**目标线程原本 100% 合法、可被 `.pdata` 完整展开到 `RtlUserThreadStart` 的原生调用栈顶**；
- 通用模块获取同样无需写死进程名：直接通过 `NtCurrentTeb()->ProcessEnvironmentBlock->ImageBaseAddress`（`PEB + 0x10`）获取当前宿主主模块 `.exe` 基址，配合每个进程必载的 `ntdll.dll` 与 `kernel32.dll` 即可完成全通用 Gadget 扫描。

### 2. 双栈隔离与原生栈顶嫁接流程（线程栈 0 字节 Shellcode 残留）
利用已分配的 `.data` 读写页（`0x1000` 字节，[`SHELLCODE_RUNTIME_DATA`](../../../DebugShellcode/Common.h) 仅占前 `0x180` 字节，尾部预留 `data_base + 0xFA0` 作为 Shellcode 私有运行栈）：

1. **进入 `X1` 时（切入私有栈跑 C++ 逻辑）**：
   - 首指令将入口 `RSP` 存入 `RuntimeSlot->OriginalRsp`；
   - 保存现场寄存器后，将 `RSP` 切换至私有数据页栈顶（`RuntimeSlot + 0xFA0`）再去 `call RuntimeDispatch`；
   - **效果**：`X1`、`RuntimeDispatch` 产生的所有局部栈帧与 `0x2E69A7Bxxxx` 返回地址**全部落在私有数据页中，线程真实栈（`TEB->StackLimit ~ OriginalRsp`）上连 1 字节的 Shellcode 地址都不会写入**。
2. **调用 R3 目标函数时（切回 `OriginalRsp` 原生栈顶嫁接）**：
   - 在 `SpoofCallNativeInvoke` 发起 R3 调用前，将当前私有栈 `RSP` 暂存至 `Context.SavedPrivateRsp`；
   - 将硬件 `RSP` 切回 **`OriginalRsp` 正下方**，压入二级 `JmpQwordPtrRbx` 与一级 `CallRaxAddRsp28Ret` 帧后跳入目标 R3 函数；
   - **效果**：当目标 R3 函数执行期间，硬件 `RSP` 严格处于 `TEB` 原生合法栈界内，且上方紧挨着的就是 `[OriginalRsp]` 原生调用链，彻底跳过 `X1` 与 `RuntimeDispatch`！
3. **R3 函数返回后（切回私有栈继续执行）**：
   - 二级 `jmp qword ptr [rbx]` 跳回 `SpoofNativeFixup` 后，立即从 `Context.SavedPrivateRsp` 恢复私有栈 `RSP`，继续跑完 `RuntimeDispatch` 剩余逻辑，最终退出 `X1` 时恢复 `OriginalRsp` 并跳回 `ResumeAddress`。

### 3. 动态解析 PE `.pdata` (`UNWIND_INFO`) 实现深层 `RtlVirtualUnwind` 严丝合缝拼接
为了让 `RtlVirtualUnwind` 展开二级 `JmpQwordPtrRbx` 时不多不少**恰好落回 `[OriginalRsp]`**，在初始化扫描 `JmpQwordPtrRbx` (`FF 23`) 时，直接读取所在模块的 `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (`.pdata`) 计算其真实栈帧大小 `JmpFrameSize`：

```cpp
#pragma pack(push, 1)
struct UNWIND_CODE_ENTRY {
    UCHAR CodeOffset;
    UCHAR UnwindOp : 4;
    UCHAR OpInfo   : 4;
};

struct UNWIND_INFO_HEADER {
    UCHAR Version : 3;
    UCHAR Flags   : 5;
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameRegister : 4;
    UCHAR FrameOffset   : 4;
    UNWIND_CODE_ENTRY UnwindCode[1];
};
#pragma pack(pop)

// 动态计算指定指令地址 Va 在 .pdata 中的静态栈帧大小 (返回 TRUE 表示可干净展开，OutFrameSize 为字节数)
static BOOLEAN QueryInstructionUnwindFrameSize(
    _In_ ULONG_PTR ModuleBase,
    _In_ ULONG64 Va,
    _Out_ ULONG* OutFrameSize)
{
    *OutFrameSize = 0;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBase);
    auto* nt  = reinterpret_cast<PIMAGE_NT_HEADERS64>(ModuleBase + dos->e_lfanew);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || !dir.Size)
        return FALSE;

    const ULONG rva = static_cast<ULONG>(Va - ModuleBase);
    auto* funcs = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(ModuleBase + dir.VirtualAddress);
    const ULONG count = dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

    // 二分查找覆盖 rva 的 RUNTIME_FUNCTION
    ULONG lo = 0, hi = count;
    const IMAGE_RUNTIME_FUNCTION_ENTRY* hit = nullptr;
    while (lo < hi)
    {
        const ULONG mid = lo + (hi - lo) / 2;
        if (rva < funcs[mid].BeginAddress)
            hi = mid;
        else if (rva >= funcs[mid].EndAddress)
            lo = mid + 1;
        else { hit = &funcs[mid]; break; }
    }

    // 叶子函数 (不在 .pdata 中)：FrameSize = 0，RtlVirtualUnwind 直接从 [RSP] 取返回地址
    if (!hit)
        return TRUE;

    // 排除位于 Prolog 内部或含 FrameRegister (UWOP_SET_FPREG) / Chained Unwind 的复杂函数
    auto* uw = reinterpret_cast<const UNWIND_INFO_HEADER*>(ModuleBase + (hit->UnwindInfoAddress & ~1u));
    if ((hit->UnwindInfoAddress & 1u) || uw->FrameRegister != 0 || (rva - hit->BeginAddress) < uw->SizeOfProlog)
        return FALSE;

    ULONG frameSize = 0;
    for (UCHAR i = 0; i < uw->CountOfCodes; ++i)
    {
        const UCHAR op   = uw->UnwindCode[i].UnwindOp;
        const UCHAR info = uw->UnwindCode[i].OpInfo;
        if (op == 0) { // UWOP_PUSH_NONVOL
            frameSize += 8;
        } else if (op == 1) { // UWOP_ALLOC_LARGE
            if (info == 0) {
                frameSize += static_cast<ULONG>(*reinterpret_cast<const USHORT*>(&uw->UnwindCode[i + 1])) * 8;
                i += 1;
            } else {
                frameSize += *reinterpret_cast<const ULONG*>(&uw->UnwindCode[i + 1]);
                i += 2;
            }
        } else if (op == 2) { // UWOP_ALLOC_SMALL
            frameSize += (static_cast<ULONG>(info) * 8) + 8;
        } else if (op == 4) { // UWOP_SAVE_NONVOL
            i += 1;
        } else if (op == 5) { // UWOP_SAVE_NONVOL_FAR
            i += 2;
        } else if (op == 8) { // UWOP_SAVE_XMM128
            i += 1;
        } else if (op == 9) { // UWOP_SAVE_XMM128_FAR
            i += 2;
        } else {
            return FALSE; // 拒绝 UWOP_SET_FPREG (3) 或 UWOP_PUSH_MACHFRAME (10)
        }
    }
    *OutFrameSize = frameSize;
    return TRUE;
}
```
- **栈帧对齐闭合公式**：
  若选出 `JmpFrameSize == 0` 的叶子函数内（或函数 `ret` 后对齐区）的 `FF 23`，则在 `OriginalRsp` 正下方直接压入 `JmpQwordPtrRbx`（`[OriginalRsp - 8] = JmpQwordPtrRbx`），展开完 `JmpQwordPtrRbx` 后 `NextRsp = (OriginalRsp - 8) + 0 + 8 = OriginalRsp`，**零误差接上 `[OriginalRsp]` 原生返回地址**；
  若选出 `JmpFrameSize > 0` 的函数内 `FF 23`，则将 `JmpQwordPtrRbx` 放置在 `[OriginalRsp - JmpFrameSize - 8]`，并在 `[OriginalRsp - JmpFrameSize]` 处垫入 `JmpFrameSize` 字节空间，展开后同样精准落回 `[OriginalRsp]`！

### 4. 终极组合：方案二（VT 幽灵 `call` 点）+ 方案三（`OriginalRsp` 单层深层全伪造）
相比「方案一 + 方案三」需要构造 2 层 Gadget 栈帧，「方案二 + 方案三」由于 `GhostRetVa` 在读取视图下自带合法前置 `call`、在执行视图下直接为 `FF 23` (`jmp qword ptr [rbx]`)，**只需在 `TargetFunc` 与 `[OriginalRsp]` 之间构造 1 层栈帧即可完成全深度隐匿**：

1. **选点与 `.pdata` 算帧**：
   调用 [`QueryInstructionUnwindFrameSize`](SKILL.md#L285) 计算所选冷分支 `GhostRetVa` 所在函数的静态栈帧大小 `GhostFrameSize`（需满足 `GhostFrameSize >= 0x28` 且 `GhostFrameSize % 16 == 8`，如常见的 `sub rsp, 28h` 或 `push rbx; sub rsp, 20h`）。
2. **单层嫁接栈内存布局**：
   ```text
   高地址 (TEB->StackBase)
     |  ntdll!RtlUserThreadStart
     |  kernel32!BaseThreadInitThunk
     |  HostExe!Main / user32!DispatchMessageWorker
     |  [OriginalRsp]                        ---> 挂钩点原生调用者返回地址 (100% 原装)
     |  ... (间隔 GhostFrameSize 字节，匹配 GhostRetVa 的 .pdata 栈帧大小) ...
     |  [OriginalRsp - GhostFrameSize - 8]   ---> GhostRetVa (跳入 TargetFunc 时的硬件 RSP)
   低地址
   ```
   - **第 0 层审计（栈顶 `[RSP] = GhostRetVa`）**：反作弊读取 `GhostRetVa - 5` / `GhostRetVa - 6` 触发 EPT/NPT Read 原始页，看到 100% 原装 `call` 指令；读取 `GhostRetVa` 看到原装后续指令（内存中无 `FF 23`）。
   - **第 1 层展开（`RtlVirtualUnwind`）**：系统查 `.pdata` 获取 `GhostFrameSize`，执行 `NextRsp = (OriginalRsp - GhostFrameSize - 8) + 8 + GhostFrameSize = OriginalRsp`，**仅经 1 次展开即零误差落回 `[OriginalRsp]` 原生调用栈顶**，并一路干净展开至 `RtlUserThreadStart`！
3. **MASM 汇编桩实现（单层嫁接 + 私有栈切换）**：
   ```asm
   ; struct GHOST_DEEP_SPOOF_CONTEXT {
   ;     ULONG64 FixupRip;         // +0x00: 指向 SpoofGhostDeepFixup (供影子页 FF 23 解引用)
   ;     ULONG64 SavedRbx;         // +0x08: 备份原非易失性 rbx
   ;     ULONG64 SavedRetAddr;     // +0x10: 备份 C++ 调用方返回地址
   ;     ULONG64 SavedPrivateRsp;  // +0x18: 备份 Shellcode 私有栈 RSP
   ;     ULONG64 PivotRsp;         // +0x20: 预算好的 OriginalRsp - GhostFrameSize - 8
   ;     ULONG64 GhostRetVa;       // +0x28: 挂载了双视图 FF 23 的合法模块 call 后地址
   ;     ULONG64 TargetFunc;       // +0x30: 目标 R3 函数地址
   ; };

   PUBLIC SpoofCallGhostDeepAsm
   SpoofCallGhostDeepAsm PROC
       pop rax                         ; 弹出私有栈上的 C++ 返回地址
       mov [r10 + 08h], rbx            ; 保存原 rbx
       mov [r10 + 10h], rax            ; 保存 C++ 返回地址
       mov [r10 + 18h], rsp            ; 保存当前私有栈 RSP
       lea rax, SpoofGhostDeepFixup
       mov [r10 + 00h], rax            ; [r10] = SpoofGhostDeepFixup

       mov rbx, r10                    ; rbx = &GHOST_DEEP_SPOOF_CONTEXT
       mov rsp, [r10 + 20h]            ; RSP 直接切回原生线程栈 (OriginalRsp - GhostFrameSize - 8)
       mov rax, [r10 + 28h]            ; rax = GhostRetVa
       mov [rsp], rax                  ; 栈顶写入 GhostRetVa (向上展开 +8+GhostFrameSize 即达 OriginalRsp)
       jmp qword ptr [r10 + 30h]       ; 跳入目标 R3 函数

   SpoofGhostDeepFixup LABEL BYTE
       mov r10, rbx                    ; 目标函数 ret -> GhostRetVa (影子页 FF 23) -> 跳回此处
       mov rsp, [r10 + 18h]            ; 恢复回 Shellcode 私有栈 RSP
       mov rbx, [r10 + 08h]            ; 恢复原 rbx
       jmp qword ptr [r10 + 10h]       ; 返回 C++ 调用方
   SpoofCallGhostDeepAsm ENDP
   ```

---

## 五、 硬性防崩溃与反检测红线（Mandatory Guardrails）

1. **x64 ABI 16 字节栈对齐铁律**：
   - 进入 `TargetFunc` 第一条指令时，必须严格保证 `RSP % 16 == 8`（因为内部函数执行 `sub rsp, 20h` 等奇数倍 8 字节分配后，调用 SSE 指令 `movaps [rsp+...], xmm0` 要求 16 字节对齐，错位 8 字节必触发 `#GP / 0xC0000005`）。
   - **方案一**若需传递 $\ge 5$ 个参数，必须在 `sub rsp, 28h` 构成的帧内将第 5+ 参数拷入 `[rsp + 20h]` 起始槽位；**方案二**因 `pop + push` 原位替换，天然支持任意数量参数而无需拷贝。
2. **调用 R3 函数期间 `RSP` 必须处于线程原生 `TEB` 栈界内**：
   - 反作弊普遍校验 `RSP >= NtCurrentTeb()->NtTib.StackLimit && RSP < NtCurrentTeb()->NtTib.StackBase`；
   - Shellcode 内部逻辑可运行在 `.data` 私有栈页上以防线程栈残留，但**在跳入外部 R3 API 的瞬间，硬件 `RSP` 必须切回 `OriginalRsp` 正下方的原生线程栈区间**。
3. **方案二冷分支选点铁律**：
   - 方案二所选的 `GhostRetVa` 必须位于合法模块中**正常业务流不会执行到的冷分支 `call` 之后**（如异常崩溃导出函数、死代码分支），防止正常线程在 `rbx` 非 `GHOST_SPOOF_CONTEXT` 时落入影子页 `FF 23` 引发崩溃。
4. **方案二与硬件 `USER_CET` 协同**：
   - 若目标进程启用了硬件影子栈（`CR4.CET` 且 `MSR_IA32_U_CET & 1`），使用方案二（`push + jmp`）时，需由 VT 在目标进程上下文屏蔽 `IA32_U_CET (0x6A0)` 的 `SH_STK_EN (bit 0)`（参见 `vt/business_backup/pmo/runtime/user_call.inl` 中的 `PayloadPmoSuspendGuestCetShadowStack`），或优先采用原生执行 `call` 的方案一与方案三。
5. **深层模式原生栈现场防踩踏铁律（Stack Clobbering Prevention）**：
   - **严禁在 `OriginalRsp` 下方保留 `X1` 寄存器保存区的同时，将 `RSP` 切回 `OriginalRsp - FrameSize - 8` 调用外部 R3 函数**：否则外部 R3 函数（如 `MessageBoxW`）向下生长的数 KB 栈帧会直接覆盖 `[OriginalRsp - 0x178 ~ OriginalRsp]` 处的 `rcx~r15` / `xmm0~xmm15` 保存区，导致退出 `X1` 时恢复出被污染的寄存器。
   - **正确做法**：进入 `X1` 时必须先将寄存器保存区直接落入 `dataBase` 私有数据页（或先切到 `PrivateStackTop` 再压入保存区），或者在切回 `OriginalRsp` 前将保存区备份至私有栈、返回后再拷回，确保原生线程栈在 `OriginalRsp` 下方可供外部函数任意深度向下生长。
6. **`X1` 入口原子重入与并发门禁铁律（Reentrancy Gate）**：
   - 由于 `OriginalRsp` 与 `PrivateStackTop`（`dataBase + 0xFA0`）在单个 `RuntimeSlot` 中为全局唯一槽位，若挂钩点为 `WndProc` 且内部调用模态 API（如 `MessageBoxW` 内部消息泵再次派发窗口消息重入 `WndProc` -> `X1`）或多线程同时命中 Hook，后进入的执行流会直接覆写 `OriginalRsp` 并将 `RSP` 重置回 `PrivateStackTop`，瞬间踩毁正在执行的前序私有栈帧。
   - **正确做法**：`X1` 在写 `OriginalRsp` 与切换 `PrivateStackTop` 之前，必须通过 `lock bts` / `lock cmpxchg` 抢占 `RuntimeSlot::EntryBusy` 原子锁（并检查 `state != 3`）；抢锁失败（重入或并发）时必须立即短路跳至 `X1StolenBytes` 原样透传执行。

---

## 六、 Shellcode 框架隐蔽性与通用化进阶规范

1. **消灭 `MEM_PRIVATE | PAGE_EXECUTE_READWRITE` 裸 VAD 暴露面**：
   - 避免直接使用 `ZwAllocateVirtualMemory(..., PAGE_EXECUTE_READWRITE)` 长期驻留 `codeBase`（易被内核遍历 `EPROCESS->VadRoot` 抓出私有 RWX 页）；
   - 打桩完成后至少降权为 `PAGE_EXECUTE_READ`，或优先采用 **合法冷门模块 `.text` 节寄生（Module Stomping）+ `VT_EH_VIEW_EXEC_SHADOW_READ_ORIGINAL` 双视图**，将 Shellcode 仅写入合法 `MEM_IMAGE` 页的影子执行视图中，实现 0 私有可执行 VAD。
2. **脱离目标进程 CRT 堆（`ucrtbase!malloc`），上下文收敛至私有数据页**：
   - 避免在 `RuntimeInitWithInput` 中使用目标进程 `ucrtbase!malloc` 分配 `GENERIC_FUNCTION_TABLE` 等含大量明文系统 API 指针的结构体（防范 `RtlWalkHeap` 进程堆特征扫描）；
   - 直接复用 `dataBase`（`0x1000` 字节）中 `RuntimeSlot`（`0x00~0x38`）与私有栈（`0x800~0xFA0`）之间的空闲区域（`0x40~0x7FF`）静态承载 `GENERIC_RUNTIME_CONTEXT` 及子表，实现进程堆 0 分配。
3. **全进程通用自举与动态冷分支选点**：
   - 获取宿主主模块基址统一读取 `pPeb->ImageBaseAddress`（`PEB + 0x10`），严禁写死特定宿主进程名哈希（如 `wstr_notepad_exe`）；
   - 方案二的 `GhostRetVa` 优先由驱动在装载期结合 `hde64_disasm` 与 `.pdata` 算帧函数自动扫描目标模块冷分支中的 `E8 rel32` / `FF 15 disp32` 动态选点，替代跨版本脆弱的硬编码 RVA。
4. **深层 Native 模式多栈参数（`StackArgCount > 1`）扩展准则**：
   - 扫描 `CallRaxGadgets[stackArgCount]`（`call rax; add rsp, cleanup; ret`）时，同步通过 `QueryInstructionUnwindFrameSize` 校验一级 Gadget 所在函数自身的 `.pdata` `UnwindFrameSize == CleanupBytes`，即可让一级 Gadget 展开后精确跨过任意数量的栈参数落入二级 `JmpQwordPtrRbx`，解除深层 Native 模式对栈参数个数的限制。
5. **统一采用参数帧汇编桩（`*FrameInvoke` / `*FrameAsm`）**：
   - 全量收敛至支持 `0~12` 参数（含浮点 `XMM0~XMM3` 与 `ReturnXmm0`）的 `SpoofCallNativeFrameInvoke` / `SpoofCallGhostFrameInvoke` / `SpoofCallGhostDeepFrameInvoke`，及时清理废弃的旧版固定 4 参数汇编桩与重复的 R0/R3 `.pdata` 解析代码以缩减 `.text` 体积。

---

## 七、 已注入 Shellcode 新增多挂钩点扩展规范（形态 A：埋点拦截 + 现场读写 + 多槽位隔离）

在已完成 `DebugShellcode` `.text` 映射、双视图保护与主槽位（`Slot[0]`）初始化的前提下，若需在目标进程中**新增第 $2 \sim N$ 个挂钩点**（如挂钩游戏内部函数、指令中段寄存器采集点或第二周期函数）并跳入 Shellcode 内部自定义 C++ 函数，统一采用 **「MASM 宏生成独立入口桩（`X1`/`X2`...）+ `HOOK_CPU_CONTEXT*` 寄存器现场传入 + 多槽位 `RuntimeSlot` 隔离」** 方案（0 额外代码页分配，直接复用已有 `.text` 双视图）。

### 1. 核心架构约束
1. **严禁多个挂钩点共用同一个汇编入口 `X1`**：每个挂钩点拥有独立的被覆盖指令（`StolenBytes`）和返回地址（`ResumeVa`），必须各自绑定专属入口桩（`X1`, `X2`, `X3`...）。
2. **共享全局只读 `UserVar`，隔离动态栈与并发状态**：
   - **`Slot[0]`（主槽）**：执行一次性的 `RuntimeInitDispatch`，持有初始化完毕的 `PGENERIC_RUNTIME_CONTEXT value`（内含 `Func` API 表、`Offset` 表、`SpoofCallGadgets` 表）；
   - **`Slot[k]`（副槽，$k \ge 1$）**：复用 `Slot[0].value`（或在初始化完成后将 `UserVar` 指针同步填入 `Slot[k].value`），但每个 `Slot[k]` 拥有**独立的 `EntryBusy` 原子锁、独立的 `OriginalRsp`、独立的 `PrivateStackTop` 以及独立的 `SPOOF_CALL_CONTEXT`**，彻底杜绝多线程并发触发不同 Hook 时互相踩栈。

### 2. 寄存器现场结构体契约（`HOOK_CPU_CONTEXT`）
汇编入口桩将保存完 `xmm0~xmm15`、`r15~rcx`、`rflags` 后的栈顶指针作为第 2 个参数（`rdx`）传入 C++ 处理函数，支持在 C++ 中直接读取或修改被挂钩点的寄存器与原始栈：

```cpp
#pragma pack(push, 16)
struct HOOK_CPU_CONTEXT {
    M128A   Xmm[16];     // +0x000 ~ +0x0FF: xmm0 ~ xmm15
    ULONG64 R15;         // +0x100
    ULONG64 R14;         // +0x108
    ULONG64 R13;         // +0x110
    ULONG64 R12;         // +0x118
    ULONG64 R11;         // +0x120
    ULONG64 R10;         // +0x128
    ULONG64 R9;          // +0x130
    ULONG64 R8;          // +0x138
    ULONG64 Rsi;         // +0x140
    ULONG64 Rbp;         // +0x148
    ULONG64 Rbx;         // +0x150
    ULONG64 Rdx;         // +0x158
    ULONG64 Rdi;         // +0x160
    ULONG64 RFlags;      // +0x168
    ULONG64 Rcx;         // +0x170
    ULONG64 Rax;         // +0x178 (若入口压入 rax)
};
#pragma pack(pop)

// C++ 挂钩分发函数统一签名：
// rcx = 当前挂钩点专属的 RuntimeSlot* (Slot[k])
// rdx = 挂钩瞬间的完整 CPU 寄存器现场指针 (可读可写，修改字段即直接改变恢复后的寄存器值)
EXTERN_C __declspec(dllexport) bool __fastcall CustomHookDispatch_2(
    ShellCodeSpoof::RuntimeSlot* slot,
    HOOK_CPU_CONTEXT* cpuCtx);
```

### 3. MASM 多入口跳板宏模板（`DEFINE_SHELLCODE_HOOK_ENTRY`）
在 [`DebugShellcodeAsm.asm`](../../../DebugShellcode/DebugShellcodeAsm.asm) 中使用宏统一生成 `X1`、`X2`...，每个入口具有唯一的 64 位立即数打桩标记（通过 `SlotTag`、`DispatchTag`、`ResumeTag` 区分），并将 `HOOK_CPU_CONTEXT*` 装入 `rdx` 传入 C++ 函数：

```asm
DEFINE_SHELLCODE_HOOK_ENTRY MACRO EntryName, EndName, SlotImm, DispatchImm, ResumeImm, StolenFillByte
PUBLIC EntryName
PUBLIC EndName

EntryName PROC
    push rax
    push rcx
    pushfq
    push rdi
    push rdx
    push rbx
    push rbp
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp, 100h
    movups [rsp+0*10h], xmm0
    movups [rsp+1*10h], xmm1
    movups [rsp+2*10h], xmm2
    movups [rsp+3*10h], xmm3
    movups [rsp+4*10h], xmm4
    movups [rsp+5*10h], xmm5
    movups [rsp+6*10h], xmm6
    movups [rsp+7*10h], xmm7
    movups [rsp+8*10h], xmm8
    movups [rsp+9*10h], xmm9
    movups [rsp+10*10h], xmm10
    movups [rsp+11*10h], xmm11
    movups [rsp+12*10h], xmm12
    movups [rsp+13*10h], xmm13
    movups [rsp+14*10h], xmm14
    movups [rsp+15*10h], xmm15

    mov r11, SlotImm                    ; 驱动打桩: 当前挂钩点专属 &Slot[k]
    mov r10, DispatchImm                ; 驱动打桩: 当前挂钩点目标 C++ 函数地址
    mov r13, rsp                        ; r13 = HOOK_CPU_CONTEXT* (指向当前保存区首地址)

    ; 原子重入与失败门禁：若 state == 3 或当前 Slot[k] 正在执行，直接走 StolenBytes 透传
    cmp dword ptr [r11+10h], 3
    je EntryName&_SkipDispatch
    lock bts dword ptr [r11+38h], 0     ; RuntimeSlot::EntryBusy 原子占位
    jc EntryName&_SkipDispatch

    ; 检查是否开启深层栈隔离
    mov eax, dword ptr [r11+34h]
    cmp eax, 1
    je EntryName&_CheckDeep
    cmp eax, 2
    jne EntryName&_UseOrigStack
EntryName&_CheckDeep:
    test dword ptr [r11+14h], 1
    je EntryName&_UseOrigStack

    ; 记录进入 Entry 瞬间的原生栈锚点 OriginalRsp (位于保存区上方 180h 字节)
    lea rax, [rsp+180h]
    mov [r11+18h], rax

    ; 切换至当前 Slot[k] 专属的私有数据页栈顶 (Slot[k] + 0FA0h)
    lea r12, [rsp-20h]
    mov rax, [r11+20h]
    test rax, rax
    jnz EntryName&_PrivReady
    lea rax, [r11+0FA0h]
    mov [r11+20h], rax
EntryName&_PrivReady:
    mov rsp, rax
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 20h
    mov rcx, r11                        ; 参数 1 (rcx) = &Slot[k]
    mov rdx, r13                        ; 参数 2 (rdx) = HOOK_CPU_CONTEXT*
    call r10
    mov rsp, r12
    jmp EntryName&_ReleaseBusy

EntryName&_UseOrigStack:
    sub rsp, 20h
    mov rcx, r11                        ; 参数 1 (rcx) = &Slot[k]
    mov rdx, r13                        ; 参数 2 (rdx) = HOOK_CPU_CONTEXT*
    call r10

EntryName&_ReleaseBusy:
    add rsp, 20h
    mov dword ptr [r11+38h], 0          ; 释放当前 Slot[k] 的 EntryBusy 锁

EntryName&_SkipDispatch:
    movups xmm0, [rsp+0*10h]
    movups xmm1, [rsp+1*10h]
    movups xmm2, [rsp+2*10h]
    movups xmm3, [rsp+3*10h]
    movups xmm4, [rsp+4*10h]
    movups xmm5, [rsp+5*10h]
    movups xmm6, [rsp+6*10h]
    movups xmm7, [rsp+7*10h]
    movups xmm8, [rsp+8*10h]
    movups xmm9, [rsp+9*10h]
    movups xmm10, [rsp+10*10h]
    movups xmm11, [rsp+11*10h]
    movups xmm12, [rsp+12*10h]
    movups xmm13, [rsp+13*10h]
    movups xmm14, [rsp+14*10h]
    movups xmm15, [rsp+15*10h]
    add rsp, 100h
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rdi
    popfq
    pop rcx
    pop rax
EntryName&_StolenBytes LABEL BYTE
    db 32 dup (0F1h, 0CEh, 0FAh, StolenFillByte)
    mov rax, ResumeImm                  ; 驱动打桩: ResumeVa_k (注意若需无损 rax 可改用 jmp qword ptr [rip+0])
    jmp rax
EntryName ENDP
EndName LABEL BYTE
ENDM
```
> [!TIP]
> **无损 `RAX` 跳回技巧**：若被挂钩点处于函数中间且后续指令依赖 `rax` 的值，跳回 `ResumeVa` 时严禁使用 `mov rax, ResumeVa; jmp rax` 破坏 `rax`，应将 `StolenBytes` 尾部跳回指令替换为 **14 字节 RIP 相对间接跳转** `FF 25 00 00 00 00 <8字节 ResumeVa>`（`jmp qword ptr [rip+0]`），实现 **100% 全寄存器零污染跳回**。

### 4. C++ 副槽处理函数与 `Slot[0]` 上下文共享范式
在 [`DebugShellcode.cpp`](../../../DebugShellcode/DebugShellcode.cpp) 中编写第 $k$ 个挂钩点的 C++ 函数时，通过 `Slot[k]->input`（驱动在安装副槽时指向主槽 `&Slot[0]`）直接共享已初始化的 `UserVar`：

```cpp
EXTERN_C __declspec(dllexport) bool __fastcall CustomHookDispatch_2(
    IN ShellCodeSpoof::RuntimeSlot* slot,
    IN HOOK_CPU_CONTEXT* cpuCtx)
{
    if (!slot || !cpuCtx)
        return false;

    // 若当前副槽尚未绑定 UserVar，从 input 指向的主槽 Slot[0] 继承已就绪的 UserVar
    PGENERIC_RUNTIME_CONTEXT userVar = slot->value;
    if (!userVar && slot->input)
    {
        const auto* primarySlot = static_cast<const ShellCodeSpoof::RuntimeSlot*>(slot->input);
        if (primarySlot->state == 2 && primarySlot->value)
        {
            userVar = primarySlot->value;
            slot->value = userVar;
            _InterlockedExchange(&slot->state, 2);
        }
    }
    if (!userVar || slot->state != 2)
        return false;

    // 1. 直接读取/修改挂钩点的寄存器现场（例如提取 rcx 中的对象指针或 rdx 中的参数）
    const ULONG64 hookedObjectPtr = cpuCtx->Rcx;

    // 2. 如需调用外部 R3 API，同样先调用 PrepareSpoofCallContext(userVar, slot) 再调 SpoofCall
    // ...
    return true;
}
```

### 5. 驱动侧（`VtEngine`）多挂钩点槽位管理流程
1. **数据区按槽分页分配**：
   - 主装阶段一次分配 `N * PAGE_SIZE` 的 `dataBase`（每个 `Slot[k]` 独占一个 `4KB` 页：`SlotVa_k = dataBase + k * PAGE_SIZE`），`Slot[k]` 页首存放 `RuntimeSlot` 结构体，私有栈顶按 `kPrivateStackTopOffset` 动态写入 `RuntimeSlot::PrivateStackTop`（`+0x20`）。
2. **安装新增 Hook 点（`InstallAdditionalShellcodeHook`）**：
   - 使用 `hde64_disasm`（`VtDecodeHookPatchSize`）解算新挂钩点 `HookVa_k` 的指令边界与 `OriginalBytes_k`；
   - 在已映射的 `codeBase` 中定位 `X{k}` 入口桩偏移与目标导出函数 `CustomHookDispatch_{k}` 偏移；
   - 将 `SlotVa_k`（且设置 `Slot[k].input = dataBase` 指向 `Slot[0]`）、`DispatchVa_k`、`OriginalBytes_k` 以及 14 字节无损跳回指令 `FF 25 00 00 00 00 + ResumeVa_k` 打桩写入 `X{k}`（若 `codeBase` 已开启双视图，通过 `VtEngine::EhWrite` 同步写入影子执行页）；
   - 调用 `InstallHookToShellcode` 将 `HookVa_k` 导向 `X{k}`，并记入 `s_ActiveHooks[k]` 槽位表以便卸载时逆序原子恢复。

---

## 八、 单页 `dataBase` 静态化布局、`1KB` 私有栈编译断言与指针表零膨胀异或规范

当把原本通过目标进程 `ucrtbase!malloc` 动态分配的运行时结构体（`UserVar`、`Func`、`Offset`、`Param`、`Data`）全部迁移至单页 `dataBase`（`0x1000 = 4096` 字节）时，必须遵循 **「高地址静态 Arena + 中部向下生长私有栈 + `static_assert` 锁死最低 `1KB` 栈红线 + 8 字节零膨胀按槽位加盐异或」** 标准架构。

### 1. 防踩踏反转内存布局（Stack Grows Away from Arena）
由于 x64 硬件栈（`RSP`）向低地址生长，必须将迁移后的静态上下文区（`SHELLCODE_STATIC_ARENA`）放置在单页 `dataBase` 的**最高地址端（`ArenaOffset ~ 0x1000`）**，将私有栈顶 `PrivateStackTop` 设在其正下方（预留 `0x20` Shadow Space），使私有栈向低地址（`0x0080`）生长时**永远背离 `Func` 函数表与 `SpoofContext`**，杜绝栈生长覆写函数指针。

```text
高地址 dataBase + 0x1000 (4096)
+-------------------------------------------------------------------+ 0x1000
| 【第 3 区：静态上下文区 (SHELLCODE_STATIC_ARENA)】                 |
|   包含 Context(UserVar) / Func / Offset / Param / Data            |
|   随后期新增函数或字段自动向低地址扩展（按 16 字节对齐）            |
+-------------------------------------------------------------------+ kArenaOffset
|   TopShadow (0x20 B): 供入口 call r10 使用的 ABI Shadow Space      |
| - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - | kPrivateStackTopOffset
|                                                                   | (写入 RuntimeSlot::PrivateStackTop)
| 【第 2 区：自适应私有运行栈 (PrivateStack)】                        |
|   编译期 static_assert 强制保证净空间 >= 0x400 (1KB)               |
|                    |                                              |
|                    v  RSP 向低地址生长（背离上方静态 Arena！）      |
|                                                                   |
+-------------------------------------------------------------------+ 0x0080 (kPrivateStackLimitOffset)
|   GuardMargin (0x40 B): 栈底安全缓冲隔离带                         |
+-------------------------------------------------------------------+ 0x0040
| 【第 1 区：RuntimeSlot 控制头】 (0x38 B + EntryBusy 0x04 B + Pad)  |
|   固定在 +0x000，100% 保持驱动端既有字段偏移 ABI 兼容              |
+-------------------------------------------------------------------+ 0x0000
低地址 dataBase
```

### 2. 编译期自适应偏移推导与 `1KB` 私有栈硬断言模板
无需手动计算填充字节，后期任意向 `GENERIC_FUNCTION_TABLE` 或 `GENERIC_OFFSET_TABLE` 添加成员时，编译器自动重算 `kPrivateStackTopOffset` 并校验 `1KB (0x400)` 最低容量红线：

```cpp
namespace ShellCodeSpoof {

// 1. 纯业务静态上下文区：后期任意增删字段，无需手算 Reserved
struct SHELLCODE_STATIC_ARENA {
    GENERIC_RUNTIME_CONTEXT  Context;
    GENERIC_FUNCTION_TABLE   Func;
    GENERIC_OFFSET_TABLE     Offset;
    GENERIC_RUNTIME_PARAMS   Param;
    GENERIC_RUNTIME_DATA     Data;
};

// 2. 编译期自动对齐与容量推导常量
constexpr std::size_t kDataPageSize          = 0x1000; // 单页固定 4KB
constexpr std::size_t kSlotHeaderAlignedSize = 0x0040; // RuntimeSlot(0x38) + EntryBusy(0x04) + Pad(0x04)
constexpr std::size_t kStackGuardMarginSize  = 0x0040; // 栈底与 RuntimeSlot 之间的 64B 安全隔离带
constexpr std::size_t kTopCallShadowSize     = 0x0020; // 栈顶预留 32B Windows x64 ABI Shadow Space
constexpr std::size_t kMinPrivateStackSize   = 0x0400; // 【硬红线】私有栈至少保留 1KB (1024 B)

constexpr std::size_t kArenaAlignedSize =
    (sizeof(SHELLCODE_STATIC_ARENA) + 0x0Fu) & ~static_cast<std::size_t>(0x0Fu);

static_assert(
    kSlotHeaderAlignedSize + kStackGuardMarginSize + kTopCallShadowSize + kArenaAlignedSize <= kDataPageSize,
    "编译阻断：SHELLCODE_STATIC_ARENA 已超出单页 4KB (0x1000) 容量上限！");

constexpr std::size_t kPrivateStackSize =
    kDataPageSize - kSlotHeaderAlignedSize - kStackGuardMarginSize - kTopCallShadowSize - kArenaAlignedSize;

constexpr std::size_t kPrivateStackLimitOffset = kSlotHeaderAlignedSize + kStackGuardMarginSize; // 0x0080
constexpr std::size_t kPrivateStackTopOffset   = kPrivateStackLimitOffset + kPrivateStackSize;   // 动态栈顶
constexpr std::size_t kArenaOffset             = kPrivateStackTopOffset + kTopCallShadowSize;    // 动态 Arena 起点

// 3. 【核心编译期门禁】：一旦后期添加过多函数导致私有栈被挤压到 < 1KB，编译立即报错阻断！
static_assert(
    kPrivateStackSize >= kMinPrivateStackSize,
    "编译阻断：SHELLCODE_STATIC_ARENA 膨胀超限，导致私有栈剩余空间不足 1KB (0x400)！");

static_assert(
    (kPrivateStackTopOffset & 0x0Fu) == 0,
    "编译阻断：推导出的 kPrivateStackTopOffset 必须严格 16 字节对齐！");

// 4. 整页内存映射结构体（自动适配剩余栈空间，总大小恒为 0x1000）
#pragma pack(push, 1)
struct SHELLCODE_DATA_PAGE {
    RuntimeSlot            Slot;                             // +0x000 (0x38)
    volatile LONG          EntryBusy;                        // +0x038 (0x04)
    ULONG                  SlotPad;                          // +0x03C (0x04)
    UCHAR                  GuardMargin[kStackGuardMarginSize]; // +0x040 ~ 0x07F
    UCHAR                  PrivateStack[kPrivateStackSize];  // +0x080 ~ kPrivateStackTopOffset (自动伸缩)
    UCHAR                  TopShadow[kTopCallShadowSize];    // kPrivateStackTopOffset ~ kArenaOffset (0x20)
    alignas(16) SHELLCODE_STATIC_ARENA Arena;                // kArenaOffset ~ 0x1000
};
#pragma pack(pop)

static_assert(sizeof(SHELLCODE_DATA_PAGE) == kDataPageSize, "SHELLCODE_DATA_PAGE 总大小必须严格为 0x1000");
static_assert(offsetof(SHELLCODE_DATA_PAGE, Arena) == kArenaOffset, "Arena 偏移推导不一致");

} // namespace ShellCodeSpoof
```
- **汇编层零改动配合**：驱动或初始化逻辑直接将 `dataBase + kPrivateStackTopOffset` 写入 `RuntimeSlot::PrivateStackTop`（`[r11+20h]`），汇编桩 `mov rax, [r11+20h]` 自动读取动态栈顶，无需修改 `.asm` 中的常数。
- **强制禁用编译器 `__chkstk` 栈探测（防 `gs:[0x10]` 越界探测崩溃）**：
  在 `DebugShellcode.vcxproj` 中必须配置 `/Gs9999999`（ClangCL 附加 `-mno-stack-arg-probe`），防止单函数局部栈帧（或 OLLVM 平坦化溢出槽）$\ge 4\text{KB}$ 时触发 `__chkstk` 从原生线程栈底 `gs:[0x10]` 向下循环摸页至 `dataBase` 引发 `0xC0000005` 崩溃。

### 3. 指针表 8 字节零膨胀「按槽位加盐异或（Per-Slot Salted XOR）」规范
- **严禁使用 24 字节的 `_EncryptedU64` 存储函数表**：避免结构体体积膨胀 3 倍挤压私有栈空间，同时保留 `GENERIC_FUNCTION_TABLE` 中 `FuncTypeDef_*` 的原始 C++ 函数指针类型签名以支持 `SpoofCall` 模板自动推导。
- **按槽位派生独立子密钥（消除同模块高 48 位相同特征）**：
  对第 `slotIndex` 个指针混入黄金分割常数与循环移位，使同一模块（如 `ntdll.dll`）的多个导出函数在内存中呈现完全不相关的伪随机分布：

```cpp
namespace SpoofCallDetail {

// 第 slotIndex 槽位子密钥派生（0 额外内存占用）
__forceinline ULONG64 DeriveSlotXorKey(ULONG64 masterKey, std::size_t slotIndex) noexcept {
    const ULONG64 salt = (static_cast<ULONG64>(slotIndex) + 1ULL) * 0x9E3779B97F4A7C15ULL;
    const int shift = static_cast<int>((slotIndex * 7u) & 63u);
    const ULONG64 rotated = shift ? ((masterKey << shift) | (masterKey >> (64 - shift))) : masterKey;
    return rotated ^ salt;
}

__forceinline ULONG_PTR CryptIndexedPtr(ULONG_PTR value, ULONG64 masterKey, std::size_t slotIndex) noexcept {
    return value ? static_cast<ULONG_PTR>(value ^ DeriveSlotXorKey(masterKey, slotIndex)) : 0;
}

// 强类型解密获取函数指针：保留 FuncTypeDef_* 原始类型，完美对接 SpoofCall
template <typename TFuncPtr>
__forceinline TFuncPtr DecryptFuncSlot(
    const PGENERIC_RUNTIME_CONTEXT userVar,
    const TFuncPtr* memberAddr,
    std::size_t slotIndex) noexcept {
    const ULONG_PTR cipher = *reinterpret_cast<const volatile ULONG_PTR*>(memberAddr);
    return reinterpret_cast<TFuncPtr>(CryptIndexedPtr(cipher, userVar->u->XorKey, slotIndex));
}

} // namespace SpoofCallDetail

// 零开销强类型取函数宏：通过 offsetof 在编译期直接算出槽位索引 i
#define XOR_FN(userVar, MemberName) \
    (::SpoofCallDetail::DecryptFuncSlot( \
        (userVar), \
        &((userVar)->Func->MemberName), \
        offsetof(GENERIC_FUNCTION_TABLE, MemberName) / sizeof(ULONG_PTR)))

// 一步到位：解密函数指针 + 走 SpoofCall 伪造调用栈
#define VT_SPOOF_FN(userVar, MemberName, ...) \
    (::SpoofCall((userVar), XOR_FN((userVar), MemberName), __VA_ARGS__))
```

- **解析期原位加密落盘（零明文窗口）**：
  1. 在 `RuntimeInitWithInput` 开头先通过 `__rdtsc() ^ ((ULONG64)CurrentPid << 16) ^ *(volatile ULONG64*)0x7FFE0008ULL`（读取 `KUSER_SHARED_DATA.InterruptTime`，无需依赖任何 API）生成高熵 `seed |= 0x8000000000000001ULL` 存入 `Arena.Data.XorKey`；
  2. 遍历 `PEB->Ldr` 调用 `Utils_GetModuleExport` 解析出 `rawFn` 的当场，立即调用 `CryptIndexedPtr(rawFn, seed, i)` 直接写入 `Arena.Func` 对应槽位（不在栈上构造明文 `pfnTable` 临时表）；
  3. `Arena.Param` 中的 `SpoofCallRaxAddRsp28Ret`、`SpoofJmpQwordPtrRbx` 与 `SpoofCallGadgets[0..8].Address` 同样异或加密存储，仅在 `PrepareSpoofCallContext` 发起调用前瞬时解密填入 `SpoofContext`，调用返回后由 `ClearSpoofCallTransient` 立即清零。
