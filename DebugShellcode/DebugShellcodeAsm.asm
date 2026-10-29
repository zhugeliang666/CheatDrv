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
    sub rsp, 20h
    mov rcx, r11
    call r10
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
PUBLIC SpoofPlan1CallRaxGadget
PUBLIC SpoofPlan1JmpRbxGadget

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
    lea rax, SpoofNativeFixup
    mov [r10+00h], rax

    mov rbx, r10
    push qword ptr [r10+20h]
    sub rsp, 28h
    mov rax, [r10+28h]
    jmp qword ptr [r10+18h]

SpoofNativeFixup LABEL BYTE
    mov r10, rbx
    mov rbx, [r10+08h]
    jmp qword ptr [r10+10h]
SpoofCallNativeAsm ENDP

; 方案1本地兜底 Gadget：保持与目标模块扫描使用的精确字节序列一致。
SpoofPlan1CallRaxGadget PROC
    call rax
    add rsp, 28h
    ret
SpoofPlan1CallRaxGadget ENDP

SpoofPlan1JmpRbxGadget PROC
    jmp qword ptr [rbx]
SpoofPlan1JmpRbxGadget ENDP

.xinit$m ENDS

END

