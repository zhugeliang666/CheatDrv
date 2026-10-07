---
name: pte-remap-shellcode-stability
description: 用于 Windows 内核无签名驱动 PTE Remap 挂接（方案 A）、白驱动（如 Machenike.sys）Code Cave Shellcode 自闭环设计、排查 BugCheck 0x3B/0x1E，以及合并 .pdata 零动态链表规避 ACE/EAC 检测的核心工程规范与稳定性避坑指南。
---

# 内核 PTE Remap 挂接与 Code Cave Shellcode 自闭环稳定性规范

## 1. 核心架构：PTE Remap（方案 A）与宿主内执行

### 1.1 隐匿核心诉求与演进
- **传统 Manual Map（方案 C）缺陷**：通过 `ExAllocatePoolWithTag` 分配独立 NonPagedPool 块，并在内核中注册 `RtlAddFunctionTable`。反作弊系统（ACE / EAC）通过扫描未受信任模块池标签（Pool Tag）、未受信任内核代码执行页（RIP 不在合法驱动模块内）或遍历异常表链表，能瞬间捕获异常驱动。
- **PTE Remap（方案 A）最强隐匿体系**：
  1. 通过 WHQL 探针分配小块 NonPagedPool 或复用物理页；
  2. 使用物理页表读写原语修改页表项（PTE），将物理页重新映射到合法白名单驱动（如 `tcpip.sys` 的 `.rsrc` 节，偏移 `+0x261000`）；
  3. 将通讯驱动 `drv_wsk.sys`（92KB）及合并 `.pdata` 整体写入宿主 `.rsrc` 物理页内；
  4. 修改宿主 PE 头的 `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]` 指向合并异常表，实现 **零动态链表、零新增模块、100% 宿主合法虚拟地址执行**。

---

## 2. Shellcode 设计两大蓝屏陷阱与根因剖析

### 2.1 陷阱一：BugCheck 0x3B（SYSTEM_SERVICE_EXCEPTION）—— 跳回宿主分支崩溃
- **现象**：微探针或 DirectExec 执行完毕后，若使用 `jmp site.kernVA + 5` 跳回宿主驱动（如 `Machenike.sys`）未文档化的默认分支继续执行，必定在退出例程蓝屏（如 `Machenike+0x17fc` 或 `Machenike+0x1800`）。
- **根因**：
  1. 宿主驱动分发函数中，`default` 分支存在上下文未初始化缺陷（如漏赋 `r15 = [rsp+0xB8]`），导致在 `0x17fc` 处执行 `mov [r15+0x30], ebx` 触发空指针写入；
  2. 宿主驱动并未显式导入 `IofCompleteRequest`，而是试图通过 `DeviceExtension`（`rdi`）函数表间接调用，但在无缓冲区的异常 IOCTL 触发下 `DeviceExtension` 未初始化（`rdi == 0`），导致解引用崩溃。
- **铁律**：**彻底切断对残缺白驱动内部分支的依赖，Shellcode 必须原地自闭环完成 IRP 并直接平栈返回！**

### 2.2 陷阱二：BugCheck 0x1E（KMODE_EXCEPTION_NOT_HANDLED）—— 易失性寄存器被踩
- **现象**：调用 `DriverEntry` 或 `ExAllocatePoolWithTag` 返回后，执行 `call qword ptr [r11 + 8]` 发生 `rip = 0x8` 或 `rip = 0x2C` 非法跳转。
- **根因（x64 ABI 规范）**：
  - **`r11`、`r10`、`rax`、`rcx`、`rdx`、`r8`、`r9` 是 Volatile（易失性寄存器）**！
  - 任何内核子函数（包括系统 API 或自定义 `DriverEntry`）在内部都会自由篡改 `r11`；
  - 若使用 `r11` 保存 `ShellcodeParams` 指针，函数返回后 `r11` 已被破坏为内核其他地址；
  - 解引用 `[r11 + 8]` 读出垃圾值（如 `0x8`、`0x2C`），`call` 指令跳转到不可执行的低地址空间引发硬件页面错误（Page Fault）。
  - **过早 `pop rbx`**：在调用完 `DriverEntry` 后过早恢复了 `rbx`，导致无法使用非易失寄存器寻址函数指针表。

---

## 3. 标准自闭环退出模板（Self-Complete IRP & Flat Ret）

### 3.1 核心设计规范
1. **寄存器保护**：入口使用非易失性寄存器 `rbx` 保存 `ShellcodeParams` 指针（`mov rbx, r11`），子函数绝不会破坏 `rbx`；
2. **真实 IRP 寻址**：由于进入 Shellcode 时额外执行了一次 `push rbx`（8 字节），原宿主入口位于 `[rsp_host + 0xB8]` 的 `pIrp` 精确映射到 `[rsp + 0xC0]`；
3. **自完成 IRP**：直接原地填充 `IoStatus.Status = 0` 与 `Information = 0`，调用内核导出函数 `IofCompleteRequest(pIrp, 0)`；
4. **平整栈帧（Flat Ret）**：恢复调用者 `rbx`，平掉宿主分发函数入口分配的局部栈帧（如 `add rsp, 0x70`），恢复宿主压栈的 7 个非易失性寄存器，直接 `ret` 平稳返回 `nt!IofCallDriver`。

### 3.2 经过验证的标准汇编与机器码
```x86asm
; -------------------------------------------------------------
; 1. 子函数执行完毕（如 call rax 调用 DriverEntry 返回）
; -------------------------------------------------------------
mov dword ptr [rbx + 0x3C], eax         ; 89 43 3C (记录返回值)
add rsp, 0x1B8                          ; 48 81 C4 B8 01 00 00 (释放局部伪对象)
pop r15                                 ; 41 5F
pop r14                                 ; 41 5E
pop r13                                 ; 41 5D
pop r12                                 ; 41 5C
pop rdi                                 ; 5F
pop rsi                                 ; 5E (保留 rbx 保存 params)

; -------------------------------------------------------------
; 2. 原地自闭环完成 IRP
; -------------------------------------------------------------
mov rcx, qword ptr [rsp + 0xC0]         ; 48 8B 8C 24 C0 00 00 00 (精确取 pIrp)
mov dword ptr [rcx + 0x30], 0           ; C7 41 30 00 00 00 00 (Status = STATUS_SUCCESS)
mov qword ptr [rcx + 0x38], 0           ; 48 C7 41 38 00 00 00 00 (Information = 0)
xor edx, edx                            ; 31 D2 (PriorityBoost = 0)
sub rsp, 0x28                           ; 48 83 EC 28 (Shadow Space + 16字节栈对齐)
call qword ptr [rbx + 8]                ; FF 53 08 (IofCompleteRequest，稳定安全)
add rsp, 0x28                           ; 48 83 C4 28

; -------------------------------------------------------------
; 3. 平栈并直接返回调用方 (Flat Ret)
; -------------------------------------------------------------
pop rbx                                 ; 5B (恢复 rbx，此时 rsp 完全回到 rsp_host)
xor eax, eax                            ; 31 C0 (返回 STATUS_SUCCESS)
add rsp, 0x70                           ; 48 83 C4 70 (平掉宿主入口分配的 0x70 栈帧)
pop r15                                 ; 41 5F
pop r14                                 ; 41 5E
pop r13                                 ; 41 5D
pop r12                                 ; 41 5C
pop rdi                                 ; 5F
pop rsi                                 ; 5E
pop rbx                                 ; 5B (恢复宿主入口压栈的 7 个寄存器)
ret                                     ; C3 (平稳返回 nt!IofCallDriver 调用方)
```

---

## 4. 落地核对清单（Checklist）

- [ ] **是否依赖易失性寄存器跨函数调用？**
  - 严禁在 `call` 之后继续使用 `r11`、`r10`、`rax`。跨子函数传参或寻址必须使用 `rbx`、`rsi`、`rdi`、`r12-r15` 等非易失性寄存器。
- [ ] **IRP 栈偏移是否绝对精准？**
  - 宿主入口偏移为 `0xB8`。Shellcode 入口每多 `push` 一个 8 字节寄存器，偏移必须相应累加（如 1 个 push 为 `0xC0`）。
- [ ] **栈对齐是否满足 x64 ABI 规范？**
  - 任何 `call` 执行瞬间，`rsp` 必须满足 `rsp % 16 == 0`（即在执行 `call` 前 `rsp % 16 == 8`，因为 `call` 会再压入 8 字节返回地址）。
- [ ] **是否已规避宿主白驱动残缺分支？**
  - 不得 `jmp` 回任何上下文不全的宿主代码，直接在 Shellcode 内调用 `IofCompleteRequest` 并 `ret`。
- [ ] **PTE Remap 物理内存容量是否完整涵盖合并 `.pdata`？**
  - 严禁假定异常表仅占几个 KB。大型宿主驱动（如 `tcpip.sys`）自身的 `.pdata` 就有数十 KB（如 78.5 KB），合并后的异常表总大小为 `hostExSize + plExSize`。
  - `needRemapBytes` 必须动态计算为 `(payloadSize + mergedPdataSize + 0x1000 + 0xFFF) & ~0xFFF`，否则会导致写入截断且无法更新宿主 PE 头的 `DataDirectory[EXCEPTION]`！

