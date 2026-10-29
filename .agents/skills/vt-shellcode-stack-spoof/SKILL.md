---
name: vt-shellcode-stack-spoof
description: >-
  R3 Shellcode 调用目标进程函数时的堆栈伪造（Call Stack Spoofing）、深层栈回溯隐匿与反 Call-Site 指令审计工程规范。
  包含纯 R3 双级真 call Gadget 方案（兼容 CFG FF 15 与裸 FF D0）、基于 VT
  EXEC_SHADOW_READ_ORIGINAL 双视图的“幽灵 call 点”方案，以及全进程通用的 OriginalRsp 原生栈嫁接 +
  .pdata (UNWIND_INFO) 动态栈帧对齐方案。当在 DebugShellcode 或 R3 注入模块中需要调用游戏/系统 R3
  函数并隐藏返回地址、绕过 _ReturnAddress() / RtlVirtualUnwind / Raw Stack Scan /
  前置 call xxx 指令校验及硬件 CET 影子栈时使用此技能。
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
