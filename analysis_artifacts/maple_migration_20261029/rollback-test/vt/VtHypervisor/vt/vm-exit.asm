.code
; defined in guest-上下文.h
guest_context struct
  ; general-purpose registers
  $rax qword ?
  $rcx qword ?
  $rdx qword ?
  $rbx qword ?
  qword ? ; padding
  $rbp qword ?
  $rsi qword ?
  $rdi qword ?
  $r8  qword ?
  $r9  qword ?
  $r10 qword ?
  $r11 qword ?
  $r12 qword ?
  $r13 qword ?
  $r14 qword ?
  $r15 qword ?

  ; 控制寄存器s
  $cr2 qword ?
  $cr8 qword ?

  ; debug registers
  $dr0 qword ?
  $dr1 qword ?
  $dr2 qword ?
  $dr3 qword ?
  $dr6 qword ?

  ; SSE registers
  $xmm0 oword ?
  $xmm1 oword ?
  $xmm2 oword ?
  $xmm3 oword ?
  $xmm4 oword ?
  $xmm5 oword ?
  $xmm6 oword ?
  $xmm7 oword ?
  $xmm8 oword ?
  $xmm9 oword ?
  $xmm10 oword ?
  $xmm11 oword ?
  $xmm12 oword ?
  $xmm13 oword ?
  $xmm14 oword ?
  $xmm15 oword ?
  $SegCs qword ?;
	$SegDs qword ?;
	$SegEs qword ?;
	$SegFs qword ?;
	$SegGs qword ?;
	$SegSs qword ?;
	$eflags qword ?;

guest_context ends

extern ?handle_vm_exit@hv@@YA_NQEAUguest_context@1@@Z : proc

; execution starts here after a vm-exit
?vm_exit@hv@@YAXXZ proc
  ; 分配 space on the stack to store the guest 上下文
  sub rsp, 200h

  ; general-purpose registers
  mov guest_context.$rax[rsp], rax
  mov guest_context.$rcx[rsp], rcx
  mov guest_context.$rdx[rsp], rdx
  mov guest_context.$rbx[rsp], rbx
  mov guest_context.$rbp[rsp], rbp
  mov guest_context.$rsi[rsp], rsi
  mov guest_context.$rdi[rsp], rdi
  mov guest_context.$r8[rsp],  r8
  mov guest_context.$r9[rsp],  r9
  mov guest_context.$r10[rsp], r10
  mov guest_context.$r11[rsp], r11
  mov guest_context.$r12[rsp], r12
  mov guest_context.$r13[rsp], r13
  mov guest_context.$r14[rsp], r14
  mov guest_context.$r15[rsp], r15

  ; 控制寄存器s
  mov rax, cr2
  mov guest_context.$cr2[rsp], rax
  mov rax, cr8
  mov guest_context.$cr8[rsp], rax

  ; debug registers
  mov rax, dr0
  mov guest_context.$dr0[rsp], rax
  mov rax, dr1
  mov guest_context.$dr1[rsp], rax
  mov rax, dr2
  mov guest_context.$dr2[rsp], rax
  mov rax, dr3
  mov guest_context.$dr3[rsp], rax
  mov rax, dr6
  mov guest_context.$dr6[rsp], rax

  ; SSE registers
  movaps guest_context.$xmm0[rsp], xmm0
  movaps guest_context.$xmm1[rsp], xmm1
  movaps guest_context.$xmm2[rsp], xmm2
  movaps guest_context.$xmm3[rsp], xmm3
  movaps guest_context.$xmm4[rsp], xmm4
  movaps guest_context.$xmm5[rsp], xmm5
  movaps guest_context.$xmm6[rsp], xmm6
  movaps guest_context.$xmm7[rsp], xmm7
  movaps guest_context.$xmm8[rsp], xmm8
  movaps guest_context.$xmm9[rsp], xmm9
  movaps guest_context.$xmm10[rsp], xmm10
  movaps guest_context.$xmm11[rsp], xmm11
  movaps guest_context.$xmm12[rsp], xmm12
  movaps guest_context.$xmm13[rsp], xmm13
  movaps guest_context.$xmm14[rsp], xmm14
  movaps guest_context.$xmm15[rsp], xmm15


  ; first argument is the guest 上下文
  mov rcx, rsp

  ; call handle_vm_exit
  sub rsp, 28h
  call ?handle_vm_exit@hv@@YA_NQEAUguest_context@1@@Z
  add rsp, 28h

  ; SSE registers
  movaps xmm0, guest_context.$xmm0[rsp]
  movaps xmm1, guest_context.$xmm1[rsp]
  movaps xmm2, guest_context.$xmm2[rsp]
  movaps xmm3, guest_context.$xmm3[rsp]
  movaps xmm4, guest_context.$xmm4[rsp]
  movaps xmm5, guest_context.$xmm5[rsp]
  movaps xmm6, guest_context.$xmm6[rsp]
  movaps xmm7, guest_context.$xmm7[rsp]
  movaps xmm8, guest_context.$xmm8[rsp]
  movaps xmm9, guest_context.$xmm9[rsp]
  movaps xmm10, guest_context.$xmm10[rsp]
  movaps xmm11, guest_context.$xmm11[rsp]
  movaps xmm12, guest_context.$xmm12[rsp]
  movaps xmm13, guest_context.$xmm13[rsp]
  movaps xmm14, guest_context.$xmm14[rsp]
  movaps xmm15, guest_context.$xmm15[rsp]

  ; handle_vm_exit returns true if we should stop virtualization
  mov r15, rax

  ; debug registers
  mov rax, guest_context.$dr0[rsp]
  mov dr0, rax
  mov rax, guest_context.$dr1[rsp]
  mov dr1, rax
  mov rax, guest_context.$dr2[rsp]
  mov dr2, rax
  mov rax, guest_context.$dr3[rsp]
  mov dr3, rax
  mov rax, guest_context.$dr6[rsp]
  mov dr6, rax

  ; 控制寄存器s
  mov rax, guest_context.$cr2[rsp]
  mov cr2, rax
  mov rax, guest_context.$cr8[rsp]
  mov cr8, rax

  ; general-purpose registers
  mov rax, guest_context.$rax[rsp]
  mov rcx, guest_context.$rcx[rsp]
  mov rdx, guest_context.$rdx[rsp]
  mov rbx, guest_context.$rbx[rsp]
  mov rbp, guest_context.$rbp[rsp]
  mov rsi, guest_context.$rsi[rsp]
  mov rdi, guest_context.$rdi[rsp]
  mov r8,  guest_context.$r8[rsp]
  mov r9,  guest_context.$r9[rsp]
  mov r10, guest_context.$r10[rsp]
  mov r11, guest_context.$r11[rsp]
  mov r12, guest_context.$r12[rsp]
  mov r13, guest_context.$r13[rsp]
  mov r14, guest_context.$r14[rsp]

  ; 检查校验 the return 值 of handle_vm_exit() to see if we should terminate
  ; the virtual machine
  test r15b, r15b
  mov r15, guest_context.$r15[rsp]
  jnz stop_virtualization

  ; if handle_exit returned false, perform a vm-enter as usual
  vmresume

stop_virtualization:
  ; we'll be dirtying these registers in order to setup the
  ; stack so we need to store and 恢复 them before we can use them.
  ; also note that we're not allocating any stack space for the trap
  ; frame since we can just reuse the space allocated for the guest
  ; 上下文.
  push rax
  push rdx
  push rbp
  lea rbp, [rsp + 38h]

  ; push SS
  mov rdx, 0804h; VMCS_GUEST_SS_SELECTOR
  vmread rax, rdx
  mov [rbp - 00h], rax

  ; push RSP
  mov rdx, 681Ch; VMCS_GUEST_RSP
  vmread rax, rdx
  mov [rbp - 08h], rax

  ; push RFLAGS
  mov rdx, 6820h; VMCS_GUEST_RFLAGS
  vmread rax, rdx
  mov [rbp - 10h], rax

  ; push CS
  mov rdx, 0802h; VMCS_GUEST_CS_SELECTOR
  vmread rax, rdx
  mov [rbp - 18h], rax

  ; push RIP
  mov rdx, 681Eh; VMCS_GUEST_RIP
  vmread rax, rdx
  mov [rbp - 20h], rax

  ; the C++ exit-handler needs to ensure that the 控制寄存器 shadows
  ; contain the 当前 guest 控制寄存器 values (even the guest-owned
  ; bits!) before returning.

  ; store cr0 in rax
  mov rax, 6004h ; VMCS_CTRL_CR0_READ_SHADOW
  vmread rax, rax

  ; store cr4 in rdx
  mov rdx, 6006h ; VMCS_CTRL_CR4_READ_SHADOW
  vmread rdx, rdx

  ; 执行 vmxoff before we 恢复 cr0 and cr4
  vmxoff

  ; 恢复 cr0 and cr4
  mov cr0, rax
  mov cr4, rdx

  ; 恢复 the dirty registers
  pop rbp
  pop rdx
  pop rax

  ; we use iretq in order to do the following all in one instruction:
  ;
  ;   pop RIP
  ;   pop CS
  ;   pop RFLAGS
  ;   pop RSP
  ;   pop SS
  ;
  iretq

?vm_exit@hv@@YAXXZ endp



vt_call_entry proc


 ;����VT����
  sub rsp, 200h
  mov guest_context.$rax[rsp], rax
  mov guest_context.$rcx[rsp], rcx
  mov guest_context.$rdx[rsp], rdx
  mov guest_context.$rbx[rsp], rbx
  mov guest_context.$rbp[rsp], rbp
  mov guest_context.$rsi[rsp], rsi
  mov guest_context.$rdi[rsp], rdi
  mov guest_context.$r8[rsp],  r8
  mov guest_context.$r9[rsp],  r9
  mov guest_context.$r10[rsp], r10
  mov guest_context.$r11[rsp], r11
  mov guest_context.$r12[rsp], r12
  mov guest_context.$r13[rsp], r13
  mov guest_context.$r14[rsp], r14
  mov guest_context.$r15[rsp], r15

    ; ����μĴ���
  mov rax, cs
  mov guest_context.$SegCs[rsp], rax
  mov rax, ds
  mov guest_context.$SegDs[rsp], rax
  mov rax, es
  mov guest_context.$SegEs[rsp], rax
  mov rax, fs
  mov guest_context.$SegFs[rsp], rax
  mov rax, gs
  mov guest_context.$SegGs[rsp], rax
  mov rax, ss
  mov guest_context.$SegSs[rsp], rax

  ; ����RFLAGS
  pushfq
  pop rax
  mov guest_context.$eflags[rsp], rax

    ; 控制寄存器s
  mov rax, cr2
  mov guest_context.$cr2[rsp], rax
  mov rax, cr8
  mov guest_context.$cr8[rsp], rax

  ; debug registers
  mov rax, dr0
  mov guest_context.$dr0[rsp], rax
  mov rax, dr1
  mov guest_context.$dr1[rsp], rax
  mov rax, dr2
  mov guest_context.$dr2[rsp], rax
  mov rax, dr3
  mov guest_context.$dr3[rsp], rax
  mov rax, dr6
  mov guest_context.$dr6[rsp], rax

  ; SSE registers
  movaps guest_context.$xmm0[rsp], xmm0
  movaps guest_context.$xmm1[rsp], xmm1
  movaps guest_context.$xmm2[rsp], xmm2
  movaps guest_context.$xmm3[rsp], xmm3
  movaps guest_context.$xmm4[rsp], xmm4
  movaps guest_context.$xmm5[rsp], xmm5
  movaps guest_context.$xmm6[rsp], xmm6
  movaps guest_context.$xmm7[rsp], xmm7
  movaps guest_context.$xmm8[rsp], xmm8
  movaps guest_context.$xmm9[rsp], xmm9
  movaps guest_context.$xmm10[rsp], xmm10
  movaps guest_context.$xmm11[rsp], xmm11
  movaps guest_context.$xmm12[rsp], xmm12
  movaps guest_context.$xmm13[rsp], xmm13
  movaps guest_context.$xmm14[rsp], xmm14
  movaps guest_context.$xmm15[rsp], xmm15
  mov qword ptr[rdx],rsp
  mov rsp,rcx


  ; SSE registers
  ;movaps xmm0, guest_context.$xmm0[rsp]
  ;movaps xmm1, guest_context.$xmm1[rsp]
  ;movaps xmm2, guest_context.$xmm2[rsp]
  ;movaps xmm3, guest_context.$xmm3[rsp]
  movss xmm0,dword ptr[r8]
  movss xmm2,dword ptr[r8+10h]
  movss xmm1,dword ptr[r8+8h]
  movss xmm3,dword ptr[r8+18h]
  movaps xmm4, guest_context.$xmm4[rsp]
  movaps xmm5, guest_context.$xmm5[rsp]
  movaps xmm6, guest_context.$xmm6[rsp]
  movaps xmm7, guest_context.$xmm7[rsp]
  movaps xmm8, guest_context.$xmm8[rsp]
  movaps xmm9, guest_context.$xmm9[rsp]
  movaps xmm10, guest_context.$xmm10[rsp]
  movaps xmm11, guest_context.$xmm11[rsp]
  movaps xmm12, guest_context.$xmm12[rsp]
  movaps xmm13, guest_context.$xmm13[rsp]
  movaps xmm14, guest_context.$xmm14[rsp]
  movaps xmm15, guest_context.$xmm15[rsp]
  ; debug registers
  mov rax, guest_context.$dr0[rsp]
  mov dr0, rax
  mov rax, guest_context.$dr1[rsp]
  mov dr1, rax
  mov rax, guest_context.$dr2[rsp]
  mov dr2, rax
  mov rax, guest_context.$dr3[rsp]
  mov dr3, rax
  mov rax, guest_context.$dr6[rsp]
  mov dr6, rax

  ; 控制寄存器s
  mov rax, guest_context.$cr2[rsp]
  mov cr2, rax
  mov rax, guest_context.$cr8[rsp]
  mov cr8, rax

  

  ; general-purpose registers
  mov rax, guest_context.$rax[rsp]
  mov rcx, guest_context.$rcx[rsp]
  mov rdx, guest_context.$rdx[rsp]
  mov rbx, guest_context.$rbx[rsp]
  mov rbp, guest_context.$rbp[rsp]
  mov rsi, guest_context.$rsi[rsp]
  mov rdi, guest_context.$rdi[rsp]
  mov r8,  guest_context.$r8[rsp]
  mov r9,  guest_context.$r9[rsp]
  mov r10, guest_context.$r10[rsp]
  mov r11, guest_context.$r11[rsp]
  mov r12, guest_context.$r12[rsp]
  mov r13, guest_context.$r13[rsp]
  mov r14, guest_context.$r14[rsp]
  mov r15, guest_context.$r15[rsp]
  add rsp, 200h
  vmresume

vt_call_entry endp



vt_call_exit proc
	
  mov rsp,rdx
  movaps xmm0, guest_context.$xmm0[rsp]
  movaps xmm1, guest_context.$xmm1[rsp]
  movaps xmm2, guest_context.$xmm2[rsp]
  movaps xmm3, guest_context.$xmm3[rsp]
  movaps xmm4, guest_context.$xmm4[rsp]
  movaps xmm5, guest_context.$xmm5[rsp]
  movaps xmm6, guest_context.$xmm6[rsp]
  movaps xmm7, guest_context.$xmm7[rsp]
  movaps xmm8, guest_context.$xmm8[rsp]
  movaps xmm9, guest_context.$xmm9[rsp]
  movaps xmm10, guest_context.$xmm10[rsp]
  movaps xmm11, guest_context.$xmm11[rsp]
  movaps xmm12, guest_context.$xmm12[rsp]
  movaps xmm13, guest_context.$xmm13[rsp]
  movaps xmm14, guest_context.$xmm14[rsp]
  movaps xmm15, guest_context.$xmm15[rsp]

  ; handle_vm_exit returns true if we should stop virtualization
  mov r15, rax

  ; debug registers
 mov rax, guest_context.$dr0[rsp]
 mov dr0, rax
 mov rax, guest_context.$dr1[rsp]
 mov dr1, rax
 mov rax, guest_context.$dr2[rsp]
 mov dr2, rax
 mov rax, guest_context.$dr3[rsp]
 mov dr3, rax
 mov rax, guest_context.$dr6[rsp]
 mov dr6, rax

  ; 控制寄存器s
  mov rax, guest_context.$cr2[rsp]
  mov cr2, rax
  mov rax, guest_context.$cr8[rsp]
  mov cr8, rax

  ; �ָ��μĴ�����CS/SS���⣩
  mov rax, guest_context.$SegDs[rsp]
  mov ds, rax
  mov rax, guest_context.$SegEs[rsp]
  mov es, rax
  mov rax, guest_context.$SegFs[rsp]
  mov fs, rax
  mov rax, guest_context.$SegGs[rsp]
  mov gs, rax

  ; RFLAGS 恢复 disabled: vt_call_exit returns to host C++ code, host
  ; RFLAGS does not need to be restored from the guest_context snapshot.
  ; The snapshot taken in vt_call_entry can be stale (IF=0 observed in #BP
  ; path) and popfq with bad 标志位集合 either crashes host or hangs interrupts.
  ;mov rax, guest_context.$eflags[rsp]
  ;push rax
  ;popfq

  ; general-purpose registers
  mov rax, guest_context.$rax[rsp]
  mov rcx, guest_context.$rcx[rsp]
  mov rdx, guest_context.$rdx[rsp]
  mov rbx, guest_context.$rbx[rsp]
  mov rbp, guest_context.$rbp[rsp]
  mov rsi, guest_context.$rsi[rsp]
  mov rdi, guest_context.$rdi[rsp]
  mov r8,  guest_context.$r8[rsp]
  mov r9,  guest_context.$r9[rsp]
  mov r10, guest_context.$r10[rsp]
  mov r11, guest_context.$r11[rsp]
  mov r12, guest_context.$r12[rsp]
  mov r13, guest_context.$r13[rsp]
  mov r14, guest_context.$r14[rsp]
  mov r15, guest_context.$r15[rsp]
  add rsp, 200h
  ret
vt_call_exit endp


end

