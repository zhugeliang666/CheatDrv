OPTION CASEMAP:NONE
OPTION DOTNAME

.code

PUBLIC X1
PUBLIC X1End

X1 PROC
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

    mov r11, 1122334455667788h
    mov r10, 8877665544332211h
    mov eax, dword ptr [r11+34h]
    cmp eax, 1
    je X1CheckDeepUnwind
    cmp eax, 2
    jne X1UseOriginalStack
X1CheckDeepUnwind:
    test dword ptr [r11+14h], 1
    je X1UseOriginalStack

X1RecordOriginalStack:
    ; 深层模式入口时 RSP 位于当前保存区上方 178h 字节，记录原生栈锚点。
    lea rax, [rsp+178h]
    mov [r11+18h], rax

X1UsePrivateStack:
    lea r12, [rsp-20h]
    mov rax, [r11+20h]
    test rax, rax
    jnz X1PrivateStackReady
    lea rax, [r11+0FA0h]
    mov [r11+20h], rax
X1PrivateStackReady:
    mov rsp, rax
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 20h
    mov rcx, r11
    call r10
    mov rsp, r12
    jmp X1DispatchDone

X1UseOriginalStack:
    sub rsp, 20h
    mov rcx, r11
    call r10
X1DispatchDone:
    movzx eax, al
    add rsp, 20h

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
X1StolenBytes LABEL BYTE
    db 32 dup (0F1h, 0CEh, 0FAh, 0CEh)
X1StolenBytesEnd LABEL BYTE

    mov rax, 0AABBCCDDEEFF0011h
    jmp rax
X1 ENDP

X1End LABEL BYTE

.xinit$m SEGMENT READ EXECUTE

PUBLIC SpoofCallNativeAsm
PUBLIC SpoofCallNativeInvoke
PUBLIC SpoofCallGhostAsm
PUBLIC SpoofCallGhostInvoke
PUBLIC SpoofCallGhostDeepAsm
PUBLIC SpoofCallGhostDeepInvoke

; RCX=context, RDX=hWnd, R8=text, R9=caption, [rsp+28h]=uType.
; 将四个目标参数整理到 Windows x64 ABI 后进入无透传的核心桩。
SpoofCallNativeInvoke PROC
    mov r10, rcx
    mov rcx, rdx
    mov rdx, r8
    mov r8, r9
    mov r9d, dword ptr [rsp+28h]
    jmp SpoofCallNativeAsm
SpoofCallNativeInvoke ENDP

; r10=context；目标函数返回时经过合法模块 Gadget 回到 SpoofNativeFixup。
SpoofCallNativeAsm PROC
    pop rax
    mov [r10+08h], rbx
    mov [r10+10h], rax
    mov [r10+38h], rsp
    lea rax, SpoofNativeFixup
    mov [r10+00h], rax

    mov rbx, r10
    mov rax, [r10+30h]
    test rax, rax
    jz SpoofNativeUseCurrentStack
    mov r11, rax
    mov rax, [r10+48h]
    sub r11, rax
    ; OriginalRsp % 16 == 8。帧大小为 0 mod 16 时补 8 字节；
    ; 帧大小为 8 mod 16 时，减去帧后已满足目标 call 的入口对齐。
    test al, 8
    jnz SpoofNativePivotReady
    sub r11, 8
SpoofNativePivotReady:
    mov rsp, r11
SpoofNativeUseCurrentStack:
    push qword ptr [r10+20h]
    sub rsp, 28h
    mov rax, [r10+28h]
    jmp qword ptr [r10+18h]

SpoofNativeFixup LABEL BYTE
    mov r10, rbx
    cmp qword ptr [r10+30h], 0
    je SpoofNativeKeepCurrentStack
    mov rsp, [r10+38h]
SpoofNativeKeepCurrentStack:
    mov rbx, [r10+08h]
    jmp qword ptr [r10+10h]
SpoofCallNativeAsm ENDP

; 方案2：目标函数 ret 到已安装 VT 幽灵返回点，影子执行页上的 FF 23 再回到这里。
SpoofCallGhostInvoke PROC
    mov r10, rcx
    mov rcx, rdx
    mov rdx, r8
    mov r8, r9
    mov r9d, dword ptr [rsp+28h]
    jmp SpoofCallGhostAsm
SpoofCallGhostInvoke ENDP

SpoofCallGhostAsm PROC
    pop rax
    mov [r10+08h], rbx
    mov [r10+10h], rax
    lea rax, SpoofGhostFixup
    mov [r10+00h], rax

    mov rbx, r10
    mov r11, [r10+40h]
    push r11
    jmp qword ptr [r10+28h]

SpoofGhostFixup LABEL BYTE
    mov r10, rbx
    mov rbx, [r10+08h]
    jmp qword ptr [r10+10h]
SpoofCallGhostAsm ENDP

; 方案2升级：GhostRet + OriginalRsp 原生栈嫁接。
; 进入目标函数时 RSP = OriginalRsp - GhostFrameSize - 8，
; 目标函数 ret 到 GhostRet 后由影子执行页 FF 23 跳回修复桩。
SpoofCallGhostDeepInvoke PROC
    mov r10, rcx
    mov rcx, rdx
    mov rdx, r8
    mov r8, r9
    mov r9d, dword ptr [rsp+28h]
    jmp SpoofCallGhostDeepAsm
SpoofCallGhostDeepInvoke ENDP

SpoofCallGhostDeepAsm PROC
    pop rax
    mov [r10+08h], rbx
    mov [r10+10h], rax
    mov [r10+38h], rsp
    lea rax, SpoofGhostDeepFixup
    mov [r10+00h], rax

    mov rbx, r10
    mov rax, [r10+30h]
    test rax, rax
    jz SpoofGhostDeepFail
    mov r11, rax
    and r11, 0Fh
    cmp r11, 8
    jne SpoofGhostDeepFail

    mov r11, [r10+48h]
    cmp r11, 28h
    jb SpoofGhostDeepFail
    mov rax, r11
    and rax, 0Fh
    cmp rax, 8
    jne SpoofGhostDeepFail

    mov rax, [r10+30h]
    sub rax, r11
    jc SpoofGhostDeepFail
    sub rax, 8
    jc SpoofGhostDeepFail

    ; 目标函数执行期间必须仍处于当前线程原生栈范围内。
    mov r11, gs:[10h]                 ; NtTib.StackLimit
    cmp rax, r11
    jb SpoofGhostDeepFail
    mov r11, gs:[08h]                 ; NtTib.StackBase
    cmp rax, r11
    jae SpoofGhostDeepFail

    mov rsp, rax
    mov rax, [r10+40h]
    test rax, rax
    jz SpoofGhostDeepFail
    mov [rsp], rax
    mov r11, [r10+28h]
    test r11, r11
    jz SpoofGhostDeepFail
    jmp r11

SpoofGhostDeepFail:
    xor eax, eax
    mov r10, rbx
    mov rsp, [r10+38h]
    mov rbx, [r10+08h]
    jmp qword ptr [r10+10h]

SpoofGhostDeepFixup:
    mov r10, rbx
    mov rsp, [r10+38h]
    mov rbx, [r10+08h]
    jmp qword ptr [r10+10h]
SpoofCallGhostDeepAsm ENDP

.xinit$m ENDS

END

