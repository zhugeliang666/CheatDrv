PUBLIC PayloadVmxVmcall
PUBLIC PayloadInvept
PUBLIC PayloadInvvpid
PUBLIC PayloadXsetbv
PUBLIC PayloadXsetbvSafe
PUBLIC PayloadInvd
PUBLIC PayloadVmExitTrampoline
PUBLIC PayloadVmExitBridge
PUBLIC PayloadVtCallEntry
PUBLIC PayloadVtCallExit
PUBLIC PayloadRdmsrSafe
PUBLIC PayloadWrmsrSafe
PUBLIC PayloadMemcpySafe
PUBLIC PayloadTriggerHostGp
PUBLIC PayloadTriggerHostUd2
PUBLIC PayloadHostInterrupt0
PUBLIC PayloadHostInterrupt1
PUBLIC PayloadHostInterrupt2
PUBLIC PayloadHostInterrupt3
PUBLIC PayloadHostInterrupt4
PUBLIC PayloadHostInterrupt5
PUBLIC PayloadHostInterrupt6
PUBLIC PayloadHostInterrupt7
PUBLIC PayloadHostInterrupt8
PUBLIC PayloadHostInterrupt10
PUBLIC PayloadHostInterrupt11
PUBLIC PayloadHostInterrupt12
PUBLIC PayloadHostInterrupt13
PUBLIC PayloadHostInterrupt14
PUBLIC PayloadHostInterrupt16
PUBLIC PayloadHostInterrupt17
PUBLIC PayloadHostInterrupt18
PUBLIC PayloadHostInterrupt19
PUBLIC PayloadHostInterrupt20
PUBLIC PayloadHostInterrupt30
PUBLIC PayloadHostPanicLanding
PUBLIC PayloadWriteDs
PUBLIC PayloadWriteEs
PUBLIC PayloadWriteFs
PUBLIC PayloadWriteGs
PUBLIC PayloadWriteTr
PUBLIC PayloadWriteLdtr
PUBLIC PayloadLoadGdtr
PUBLIC PayloadLoadIdtr

EXTERN g_payload_vmexit_target:QWORD
EXTERN g_payload_vmexit_hits:QWORD
EXTERN g_payload_vmexit_bridge_target:QWORD
EXTERN g_payload_vmexit_bridge_hits:QWORD
EXTERN g_payload_vmexit_old_handler_call_count:QWORD
EXTERN g_payload_vmexit_old_handler_active_count:QWORD
EXTERN g_payload_legacy_released:QWORD
EXTERN g_payload_unload_quiesce:QWORD
EXTERN PayloadBridgeObserve:PROC
EXTERN PayloadBridgeTryHandle:PROC
EXTERN PayloadBridgeNoTarget:PROC
EXTERN PayloadBridgeSyncLegacyVcpuContext:PROC
EXTERN PayloadBridgeProcessPendingVtcallRestore:PROC
EXTERN PayloadBridgeProcessPendingVtcallRelease:PROC
EXTERN PayloadBridgeRunLegacyPreDispatchPillars:PROC
EXTERN PayloadBridgePostDispatchTraceScrub:PROC
EXTERN PayloadHandleHostInterrupt:PROC
EXTERN g_payload_host_panic_resume_rsp:QWORD
EXTERN g_payload_host_panic_resume_rip:QWORD

guest_context struct
  $rax qword ?
  $rcx qword ?
  $rdx qword ?
  $rbx qword ?
  qword ?
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
  $cr2 qword ?
  $cr8 qword ?
  $dr0 qword ?
  $dr1 qword ?
  $dr2 qword ?
  $dr3 qword ?
  $dr6 qword ?
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
  $SegCs qword ?
  $SegDs qword ?
  $SegEs qword ?
  $SegFs qword ?
  $SegGs qword ?
  $SegSs qword ?
  $eflags qword ?
guest_context ends

payload_trap_frame struct
  $rax qword ?
  $rcx qword ?
  $rdx qword ?
  $rbx qword ?
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
  $vector qword ?
  $error  qword ?
  $rip    qword ?
  $cs     qword ?
  $rflags qword ?
  $rsp    qword ?
  $ss     qword ?
payload_trap_frame ends

.code

PayloadWriteDs PROC
    mov ds, cx
    ret
PayloadWriteDs ENDP

PayloadWriteEs PROC
    mov es, cx
    ret
PayloadWriteEs ENDP

PayloadWriteFs PROC
    mov fs, cx
    ret
PayloadWriteFs ENDP

PayloadWriteGs PROC
    mov gs, cx
    ret
PayloadWriteGs ENDP

PayloadWriteTr PROC
    ltr cx
    ret
PayloadWriteTr ENDP

PayloadWriteLdtr PROC
    lldt cx
    ret
PayloadWriteLdtr ENDP

PayloadLoadGdtr PROC
    lgdt fword ptr [rcx]
    ret
PayloadLoadGdtr ENDP

PayloadLoadIdtr PROC
    lidt fword ptr [rcx]
    ret
PayloadLoadIdtr ENDP

PayloadRdmsrSafe PROC
    mov r10, payload_rdmsr_safe_ehandler
    mov r11, rcx
    mov byte ptr [rcx], 0
    mov ecx, edx
    rdmsr
    shl rdx, 32
    or rax, rdx
payload_rdmsr_safe_ehandler:
    ret
PayloadRdmsrSafe ENDP

PayloadWrmsrSafe PROC
    mov r10, payload_wrmsr_safe_ehandler
    mov r11, rcx
    mov byte ptr [rcx], 0
    mov ecx, edx
    mov eax, r8d
    mov rdx, r8
    shr rdx, 32
    wrmsr
payload_wrmsr_safe_ehandler:
    ret
PayloadWrmsrSafe ENDP

PayloadXsetbvSafe PROC
    mov r10, payload_xsetbv_safe_ehandler
    mov r11, rcx
    mov byte ptr [rcx], 0
    mov ecx, edx
    mov rax, r8
    mov rdx, r8
    shr rdx, 32
    xsetbv
payload_xsetbv_safe_ehandler:
    ret
PayloadXsetbvSafe ENDP

PayloadMemcpySafe PROC
    mov r10, payload_memcpy_safe_ehandler
    mov r11, rcx
    mov byte ptr [rcx], 0

    push rsi
    push rdi

    ; rcx = exception_info, rdx = dst, r8 = src, r9 = size
    mov rsi, r8
    mov rdi, rdx
    mov rcx, r9
    rep movsb

payload_memcpy_safe_ehandler:
    pop rdi
    pop rsi
    ret
PayloadMemcpySafe ENDP

PayloadTriggerHostGp PROC
    xor r10, r10
    xor r11, r11
    mov ecx, 0FFFFFFFFh
    rdmsr
    ret
PayloadTriggerHostGp ENDP

PayloadTriggerHostUd2 PROC
    xor r10, r10
    xor r11, r11
    ud2
    ret
PayloadTriggerHostUd2 ENDP

PayloadGenericHostInterrupt PROC
    sub rsp, 78h

    mov payload_trap_frame.$rax[rsp], rax
    mov payload_trap_frame.$rcx[rsp], rcx
    mov payload_trap_frame.$rdx[rsp], rdx
    mov payload_trap_frame.$rbx[rsp], rbx
    mov payload_trap_frame.$rbp[rsp], rbp
    mov payload_trap_frame.$rsi[rsp], rsi
    mov payload_trap_frame.$rdi[rsp], rdi
    mov payload_trap_frame.$r8[rsp],  r8
    mov payload_trap_frame.$r9[rsp],  r9
    mov payload_trap_frame.$r10[rsp], r10
    mov payload_trap_frame.$r11[rsp], r11
    mov payload_trap_frame.$r12[rsp], r12
    mov payload_trap_frame.$r13[rsp], r13
    mov payload_trap_frame.$r14[rsp], r14
    mov payload_trap_frame.$r15[rsp], r15

    mov rcx, rsp
    sub rsp, 20h
    call PayloadHandleHostInterrupt
    add rsp, 20h

    mov rax, payload_trap_frame.$rax[rsp]
    mov rcx, payload_trap_frame.$rcx[rsp]
    mov rdx, payload_trap_frame.$rdx[rsp]
    mov rbx, payload_trap_frame.$rbx[rsp]
    mov rbp, payload_trap_frame.$rbp[rsp]
    mov rsi, payload_trap_frame.$rsi[rsp]
    mov rdi, payload_trap_frame.$rdi[rsp]
    mov r8,  payload_trap_frame.$r8[rsp]
    mov r9,  payload_trap_frame.$r9[rsp]
    mov r10, payload_trap_frame.$r10[rsp]
    mov r11, payload_trap_frame.$r11[rsp]
    mov r12, payload_trap_frame.$r12[rsp]
    mov r13, payload_trap_frame.$r13[rsp]
    mov r14, payload_trap_frame.$r14[rsp]
    mov r15, payload_trap_frame.$r15[rsp]

    add rsp, 78h
    add rsp, 8
    add rsp, 8
    iretq
PayloadGenericHostInterrupt ENDP

PayloadHostPanicLanding PROC
    xor edx, edx
    vmread rax, rdx
    jc payload_host_panic_landing_fail
    jz payload_host_panic_landing_fail
    test rax, rax
    jz payload_host_panic_landing_fail
    dec rax
    cmp rax, 64
    jae payload_host_panic_landing_fail

    lea r10, g_payload_host_panic_resume_rsp
    mov rsp, qword ptr [r10 + rax * 8]
    test rsp, rsp
    jz payload_host_panic_landing_fail

    lea r10, g_payload_host_panic_resume_rip
    mov r11, qword ptr [r10 + rax * 8]
    test r11, r11
    jz payload_host_panic_landing_fail

    jmp r11

payload_host_panic_landing_fail:
    pause
    jmp payload_host_panic_landing_fail
PayloadHostPanicLanding ENDP

PAYLOAD_DEFINE_ISR MACRO interrupt_vector:req, proc_name:req
proc_name PROC
    push interrupt_vector
    jmp PayloadGenericHostInterrupt
proc_name ENDP
ENDM

PAYLOAD_DEFINE_ISR_NO_ERROR MACRO interrupt_vector:req, proc_name:req
proc_name PROC
    push 0
    push interrupt_vector
    jmp PayloadGenericHostInterrupt
proc_name ENDP
ENDM

PAYLOAD_DEFINE_ISR_NO_ERROR 0,  PayloadHostInterrupt0
PAYLOAD_DEFINE_ISR_NO_ERROR 1,  PayloadHostInterrupt1
PAYLOAD_DEFINE_ISR_NO_ERROR 2,  PayloadHostInterrupt2
PAYLOAD_DEFINE_ISR_NO_ERROR 3,  PayloadHostInterrupt3
PAYLOAD_DEFINE_ISR_NO_ERROR 4,  PayloadHostInterrupt4
PAYLOAD_DEFINE_ISR_NO_ERROR 5,  PayloadHostInterrupt5
PAYLOAD_DEFINE_ISR_NO_ERROR 6,  PayloadHostInterrupt6
PAYLOAD_DEFINE_ISR_NO_ERROR 7,  PayloadHostInterrupt7
PAYLOAD_DEFINE_ISR          8,  PayloadHostInterrupt8
PAYLOAD_DEFINE_ISR          10, PayloadHostInterrupt10
PAYLOAD_DEFINE_ISR          11, PayloadHostInterrupt11
PAYLOAD_DEFINE_ISR          12, PayloadHostInterrupt12
PAYLOAD_DEFINE_ISR          13, PayloadHostInterrupt13
PAYLOAD_DEFINE_ISR          14, PayloadHostInterrupt14
PAYLOAD_DEFINE_ISR_NO_ERROR 16, PayloadHostInterrupt16
PAYLOAD_DEFINE_ISR          17, PayloadHostInterrupt17
PAYLOAD_DEFINE_ISR_NO_ERROR 18, PayloadHostInterrupt18
PAYLOAD_DEFINE_ISR_NO_ERROR 19, PayloadHostInterrupt19
PAYLOAD_DEFINE_ISR_NO_ERROR 20, PayloadHostInterrupt20
PAYLOAD_DEFINE_ISR          30, PayloadHostInterrupt30

PayloadVmxVmcall PROC
    mov rax, [rcx]       ; flags: low 8 bits = hypercall code, high 56 bits = key
    mov rdx, [rcx + 10h] ; args[1]
    mov r8,  [rcx + 18h] ; args[2]
    mov r9,  [rcx + 20h] ; args[3]
    mov r10, [rcx + 28h] ; args[4]
    mov r11, [rcx + 30h] ; args[5]
    mov rcx, [rcx + 08h] ; args[0]
    vmcall
    ret
PayloadVmxVmcall ENDP

PayloadInvept PROC
    invept rcx, oword ptr [rdx]
    ret
PayloadInvept ENDP

PayloadInvvpid PROC
    invvpid rcx, oword ptr [rdx]
    ret
PayloadInvvpid ENDP

PayloadXsetbv PROC
    mov r8, rdx
    mov eax, r8d
    shr r8, 32
    mov edx, r8d
    xsetbv
    ret
PayloadXsetbv ENDP

PayloadInvd PROC
    invd
    ret
PayloadInvd ENDP

PayloadVtCallEntry PROC
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

    pushfq
    pop rax
    mov guest_context.$eflags[rsp], rax

    mov rax, cr2
    mov guest_context.$cr2[rsp], rax
    mov rax, cr8
    mov guest_context.$cr8[rsp], rax

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

    mov qword ptr [rdx], rsp
    mov rsp, rcx

    movss xmm0, dword ptr [r8]
    movss xmm2, dword ptr [r8+10h]
    movss xmm1, dword ptr [r8+8h]
    movss xmm3, dword ptr [r8+18h]
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

    mov rax, guest_context.$cr2[rsp]
    mov cr2, rax
    mov rax, guest_context.$cr8[rsp]
    mov cr8, rax

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
PayloadVtCallEntry ENDP

PayloadVtCallExit PROC
    mov rsp, rdx

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

    mov r15, rax

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

    mov rax, guest_context.$cr2[rsp]
    mov cr2, rax
    mov rax, guest_context.$cr8[rsp]
    mov cr8, rax

    mov rax, guest_context.$SegDs[rsp]
    mov ds, rax
    mov rax, guest_context.$SegEs[rsp]
    mov es, rax
    mov rax, guest_context.$SegFs[rsp]
    mov fs, rax
    mov rax, guest_context.$SegGs[rsp]
    mov gs, rax

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
PayloadVtCallExit ENDP

PayloadVmExitTrampoline PROC
    pushfq
    lock inc qword ptr [g_payload_vmexit_hits]
    popfq
    jmp qword ptr [g_payload_vmexit_target]
PayloadVmExitTrampoline ENDP

PayloadVmExitBridge PROC
    pushfq
    lock inc qword ptr [g_payload_vmexit_bridge_hits]
    popfq

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

    mov rax, cr2
    mov guest_context.$cr2[rsp], rax
    mov rax, cr8
    mov guest_context.$cr8[rsp], rax

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

    xor edx, edx
    vmread rax, rdx
    jc payload_bridge_skip_panic_landing_record
    jz payload_bridge_skip_panic_landing_record
    test rax, rax
    jz payload_bridge_skip_panic_landing_record
    dec rax
    cmp rax, 64
    jae payload_bridge_skip_panic_landing_record
    lea r10, g_payload_host_panic_resume_rsp
    mov qword ptr [r10 + rax * 8], rsp
    lea r10, g_payload_host_panic_resume_rip
    lea r11, payload_bridge_panic_landing
    mov qword ptr [r10 + rax * 8], r11

payload_bridge_skip_panic_landing_record:
    mov rcx, rsp
    sub rsp, 28h
    call PayloadBridgeSyncLegacyVcpuContext
    add rsp, 28h

    mov rcx, rsp
    sub rsp, 28h
    call PayloadBridgeProcessPendingVtcallRestore
    add rsp, 28h

    mov rcx, rsp
    sub rsp, 28h
    call PayloadBridgeRunLegacyPreDispatchPillars
    add rsp, 28h

    mov rcx, rsp
    sub rsp, 28h
    call PayloadBridgeObserve
    add rsp, 28h

    mov rcx, rsp
    sub rsp, 28h
    call PayloadBridgeTryHandle
    add rsp, 28h
    test rax, rax
    jz payload_bridge_forward_old
    cmp rax, 2
    je payload_bridge_dispatch_done
    xor eax, eax
    jmp payload_bridge_dispatch_done

payload_bridge_forward_old:
    cmp qword ptr [g_payload_legacy_released], 0
    jne payload_bridge_no_target
    cmp qword ptr [g_payload_unload_quiesce], 0
    jne payload_bridge_no_target
    mov rax, qword ptr [g_payload_vmexit_bridge_target]
    test rax, rax
    jz payload_bridge_no_target
    ; Close the freetest/quarantine TOCTOU window.  A release can clear the
    ; target on another CPU after the first load above; take an in-flight
    ; reference only while the target is still current, then re-check before
    ; calling the legacy TestDriver handler.
    cmp qword ptr [g_payload_legacy_released], 0
    jne payload_bridge_no_target
    cmp qword ptr [g_payload_unload_quiesce], 0
    jne payload_bridge_no_target
    cmp rax, qword ptr [g_payload_vmexit_bridge_target]
    jne payload_bridge_no_target
    lock inc qword ptr [g_payload_vmexit_old_handler_active_count]
    cmp qword ptr [g_payload_legacy_released], 0
    jne payload_bridge_old_handler_cancel
    cmp qword ptr [g_payload_unload_quiesce], 0
    jne payload_bridge_old_handler_cancel
    cmp rax, qword ptr [g_payload_vmexit_bridge_target]
    jne payload_bridge_old_handler_cancel
    lock inc qword ptr [g_payload_vmexit_old_handler_call_count]
    mov rcx, rsp
    sub rsp, 28h
    call rax
    add rsp, 28h
    lock dec qword ptr [g_payload_vmexit_old_handler_active_count]
    ; If the legacy TestDriver handler returns stop=true, its C++ path has
    ; already restored guest CR3/GDTR/IDTR/segments for VMXOFF; do not execute
    ; payload C++ postlude in that state.  Non-stop fallbacks still run the
    ; payload release/scrub postlude so payload-owned pending restore nodes are
    ; not leaked.
    test rax, rax
    jnz payload_bridge_restore_context
    jmp payload_bridge_dispatch_done

payload_bridge_old_handler_cancel:
    lock dec qword ptr [g_payload_vmexit_old_handler_active_count]
    jmp payload_bridge_no_target

payload_bridge_no_target:
    mov rcx, rsp
    sub rsp, 28h
    call PayloadBridgeNoTarget
    add rsp, 28h
    test rax, rax
    jz payload_bridge_dispatch_done
    cmp rax, 2
    je payload_bridge_dispatch_done
    xor eax, eax

payload_bridge_panic_landing:
    mov rax, 1
    jmp payload_bridge_dispatch_done

payload_bridge_dispatch_done:
    mov rbx, rax
    mov rcx, rsp
    sub rsp, 28h
    call PayloadBridgeProcessPendingVtcallRelease
    add rsp, 28h

    mov rcx, rsp
    sub rsp, 28h
    call PayloadBridgePostDispatchTraceScrub
    add rsp, 28h

    mov rax, rbx

payload_bridge_restore_context:
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

    mov r15, rax

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

    mov rax, guest_context.$cr2[rsp]
    mov cr2, rax
    mov rax, guest_context.$cr8[rsp]
    mov cr8, rax

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

    test r15b, r15b
    mov r15, guest_context.$r15[rsp]
    jnz payload_bridge_stop_virtualization

    vmresume

payload_bridge_stop_virtualization:
    push rax
    push rdx
    push rbp
    lea rbp, [rsp + 38h]

    mov rdx, 0804h
    vmread rax, rdx
    mov [rbp - 00h], rax

    mov rdx, 681Ch
    vmread rax, rdx
    mov [rbp - 08h], rax

    mov rdx, 6820h
    vmread rax, rdx
    mov [rbp - 10h], rax

    mov rdx, 0802h
    vmread rax, rdx
    mov [rbp - 18h], rax

    mov rdx, 681Eh
    vmread rax, rdx
    mov [rbp - 20h], rax

    mov rax, 6004h
    vmread rax, rax

    mov rdx, 6006h
    vmread rdx, rdx

    vmxoff

    mov cr0, rax
    mov cr4, rdx

    pop rbp
    pop rdx
    pop rax

    iretq
PayloadVmExitBridge ENDP

END
