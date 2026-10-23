.code

; uint64_t __cdecl svm_vmmcall_asm(hv::hypercall_input* input)
;
; Register ABI intentionally matches hv::vmx_vmcall:
;   rax = input.flags  (code/key)
;   rcx = input.args[0]
;   rdx = input.args[1]
;   r8  = input.args[2]
;   r9  = input.args[3]
;   r10 = input.args[4]
;   r11 = input.args[5]
;
; AMD VMMCALL opcode is 0F 01 D9. The wrapper is not called until SVM has
; launched and the VMCB intercepts VMMCALL; executing this outside SVM raises
; #UD on real AMD hardware.
PUBLIC svm_vmmcall_asm
svm_vmmcall_asm PROC
  mov rax, [rcx]
  mov rdx, [rcx + 10h]
  mov r8,  [rcx + 18h]
  mov r9,  [rcx + 20h]
  mov r10, [rcx + 28h]
  mov r11, [rcx + 30h]
  mov rcx, [rcx + 08h]

  db 0fh, 01h, 0d9h ; vmmcall

  ret
svm_vmmcall_asm ENDP

; void __cdecl svm_clgi_asm()
PUBLIC svm_clgi_asm
svm_clgi_asm PROC
  db 0fh, 01h, 0ddh ; clgi
  ret
svm_clgi_asm ENDP

; void __cdecl svm_stgi_asm()
PUBLIC svm_stgi_asm
svm_stgi_asm PROC
  db 0fh, 01h, 0dch ; stgi
  ret
svm_stgi_asm ENDP

; void __cdecl svm_vmsave_asm(uint64_t pa)
PUBLIC svm_vmsave_asm
svm_vmsave_asm PROC
  mov rax, rcx
  db 0fh, 01h, 0dbh ; vmsave rax
  ret
svm_vmsave_asm ENDP

; void __cdecl svm_vmload_asm(uint64_t pa)
PUBLIC svm_vmload_asm
svm_vmload_asm PROC
  mov rax, rcx
  db 0fh, 01h, 0dah ; vmload rax
  ret
svm_vmload_asm ENDP

; void __cdecl svm_invlpga_asm(uint64_t va, uint32_t asid)
PUBLIC svm_invlpga_asm
svm_invlpga_asm PROC
  ; INVLPGA uses RAX=linear address and ECX=ASID.
  mov rax, rcx
  mov ecx, edx
  db 0fh, 01h, 0dfh ; invlpga
  ret
svm_invlpga_asm ENDP

; Keep this layout in sync with vt/guest-context.h and vt/vm-exit.asm.
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

SVM_FRAME_CONTEXT       equ 000h
SVM_FRAME_CPU           equ 200h
SVM_FRAME_VMCB_VA       equ 208h
SVM_FRAME_VMCB_PA       equ 210h
SVM_FRAME_HOSTSAVE_PA   equ 218h
SVM_FRAME_GUEST_RSP     equ 220h
SVM_FRAME_STOP          equ 228h
SVM_FRAME_HOST_CR3      equ 230h
SVM_FRAME_HOST_GDTR     equ 238h
SVM_FRAME_HOST_IDTR     equ 248h
SVM_FRAME_SIZE          equ 260h

VMCB_RIP_OFFSET         equ 578h
VMCB_RFLAGS_OFFSET      equ 570h
VMCB_RSP_OFFSET         equ 5d8h
VMCB_CS_SELECTOR_OFFSET equ 410h
VMCB_SS_SELECTOR_OFFSET equ 420h

extern svm_handle_vmexit_c : proc
extern svm_prepare_stop_c : proc
extern KeBugCheckEx : proc

; void __cdecl hv_bugcheck_on_stack_asm(
;     uint64_t new_rsp,        ; rcx
;     uint64_t bugcheck_code,  ; rdx
;     uint64_t param1,         ; r8
;     uint64_t param2,         ; r9
;     uint64_t param3,         ; [rsp + 28h]
;     uint64_t param4)         ; [rsp + 30h]
PUBLIC hv_bugcheck_on_stack_asm
hv_bugcheck_on_stack_asm PROC
  mov r10, qword ptr [rsp + 28h]
  mov r11, qword ptr [rsp + 30h]

  and rcx, -16
  sub rcx, 30h
  mov rsp, rcx

  mov eax, 400000
@drain_other_cores:
  pause
  dec eax
  jnz @drain_other_cores

  mov ecx, edx
  mov rdx, r8
  mov r8,  r9
  mov r9,  r10
  mov qword ptr [rsp + 20h], r11

  call KeBugCheckEx
  int 3
hv_bugcheck_on_stack_asm ENDP

; bool __cdecl svm_launch_asm(svm::vmcb* vmcb,
;                             uint64_t vmcb_pa,
;                             uint64_t host_save_pa,
;                             uint64_t host_rsp,
;                             hv::vcpu* cpu,
;                             uint64_t host_cr3)
;
; The first guest entry lands on svm_successful_launch with the caller's
; original stack, mirroring vt/vm-launch.asm.  Later #VMEXITs return after the
; VMRUN instruction on the dedicated host stack frame below.
PUBLIC svm_launch_asm
svm_launch_asm PROC
  ; rcx=vmcb_va, rdx=vmcb_pa, r8=host_save_pa, r9=host_rsp,
  ; [rsp+28h]=cpu, [rsp+30h]=host_cr3
  mov r10, rsp
  mov qword ptr [rcx + VMCB_RSP_OFFSET], r10
  mov r11, OFFSET svm_successful_launch
  mov qword ptr [rcx + VMCB_RIP_OFFSET], r11

  mov r11, qword ptr [rsp + 28h] ; cpu
  mov rsp, r9
  ; Keep the frame base 8 mod 16, matching vt/vm-exit.asm.  The
  ; guest_context XMM fields are then 16-byte aligned and sub rsp,28h before
  ; C calls gives the Windows x64 ABI-required call alignment.
  sub rsp, SVM_FRAME_SIZE

  mov qword ptr [rsp + SVM_FRAME_CPU], r11
  mov qword ptr [rsp + SVM_FRAME_VMCB_VA], rcx
  mov qword ptr [rsp + SVM_FRAME_VMCB_PA], rdx
  mov qword ptr [rsp + SVM_FRAME_HOSTSAVE_PA], r8
  mov qword ptr [rsp + SVM_FRAME_GUEST_RSP], r10
  mov qword ptr [rsp + SVM_FRAME_STOP], 0
  mov rax, qword ptr [r10 + 30h] ; host_cr3 from the original call stack
  mov qword ptr [rsp + SVM_FRAME_HOST_CR3], rax
  sgdt fword ptr [rsp + SVM_FRAME_HOST_GDTR]
  sidt fword ptr [rsp + SVM_FRAME_HOST_IDTR]

  ; Match the Intel backend: VM-exit host code runs on ghv.host_page_tables,
  ; which contains the direct physical map used by hv::gva2hva/read helpers.
  mov cr3, rax

svm_vmrun_enter:
  mov rax, qword ptr [rsp + SVM_FRAME_VMCB_PA]
  db 0fh, 01h, 0dah ; vmload guest aux state
  db 0fh, 01h, 0d8h ; vmrun rax (hardware sets GIF=1 atomically)

  ; #VMEXIT resumes here in host context.
  db 0fh, 01h, 0ddh ; clgi
  mov rax, qword ptr [rsp + SVM_FRAME_VMCB_PA]
  db 0fh, 01h, 0dbh ; vmsave guest aux state

  mov rax, qword ptr [rsp + SVM_FRAME_HOSTSAVE_PA]
  db 0fh, 01h, 0dah ; vmload host aux state
  lgdt fword ptr [rsp + SVM_FRAME_HOST_GDTR]
  lidt fword ptr [rsp + SVM_FRAME_HOST_IDTR]

  mov guest_context.$rax[rsp + SVM_FRAME_CONTEXT], rax
  mov guest_context.$rcx[rsp + SVM_FRAME_CONTEXT], rcx
  mov guest_context.$rdx[rsp + SVM_FRAME_CONTEXT], rdx
  mov guest_context.$rbx[rsp + SVM_FRAME_CONTEXT], rbx
  mov guest_context.$rbp[rsp + SVM_FRAME_CONTEXT], rbp
  mov guest_context.$rsi[rsp + SVM_FRAME_CONTEXT], rsi
  mov guest_context.$rdi[rsp + SVM_FRAME_CONTEXT], rdi
  mov guest_context.$r8[rsp + SVM_FRAME_CONTEXT],  r8
  mov guest_context.$r9[rsp + SVM_FRAME_CONTEXT],  r9
  mov guest_context.$r10[rsp + SVM_FRAME_CONTEXT], r10
  mov guest_context.$r11[rsp + SVM_FRAME_CONTEXT], r11
  mov guest_context.$r12[rsp + SVM_FRAME_CONTEXT], r12
  mov guest_context.$r13[rsp + SVM_FRAME_CONTEXT], r13
  mov guest_context.$r14[rsp + SVM_FRAME_CONTEXT], r14
  mov guest_context.$r15[rsp + SVM_FRAME_CONTEXT], r15

  movaps guest_context.$xmm0[rsp + SVM_FRAME_CONTEXT], xmm0
  movaps guest_context.$xmm1[rsp + SVM_FRAME_CONTEXT], xmm1
  movaps guest_context.$xmm2[rsp + SVM_FRAME_CONTEXT], xmm2
  movaps guest_context.$xmm3[rsp + SVM_FRAME_CONTEXT], xmm3
  movaps guest_context.$xmm4[rsp + SVM_FRAME_CONTEXT], xmm4
  movaps guest_context.$xmm5[rsp + SVM_FRAME_CONTEXT], xmm5
  movaps guest_context.$xmm6[rsp + SVM_FRAME_CONTEXT], xmm6
  movaps guest_context.$xmm7[rsp + SVM_FRAME_CONTEXT], xmm7
  movaps guest_context.$xmm8[rsp + SVM_FRAME_CONTEXT], xmm8
  movaps guest_context.$xmm9[rsp + SVM_FRAME_CONTEXT], xmm9
  movaps guest_context.$xmm10[rsp + SVM_FRAME_CONTEXT], xmm10
  movaps guest_context.$xmm11[rsp + SVM_FRAME_CONTEXT], xmm11
  movaps guest_context.$xmm12[rsp + SVM_FRAME_CONTEXT], xmm12
  movaps guest_context.$xmm13[rsp + SVM_FRAME_CONTEXT], xmm13
  movaps guest_context.$xmm14[rsp + SVM_FRAME_CONTEXT], xmm14
  movaps guest_context.$xmm15[rsp + SVM_FRAME_CONTEXT], xmm15

  mov rcx, qword ptr [rsp + SVM_FRAME_CPU]
  lea rdx, [rsp + SVM_FRAME_CONTEXT]
  sub rsp, 28h
  call svm_handle_vmexit_c
  add rsp, 28h
  movzx eax, al
  mov qword ptr [rsp + SVM_FRAME_STOP], rax

  movaps xmm0, guest_context.$xmm0[rsp + SVM_FRAME_CONTEXT]
  movaps xmm1, guest_context.$xmm1[rsp + SVM_FRAME_CONTEXT]
  movaps xmm2, guest_context.$xmm2[rsp + SVM_FRAME_CONTEXT]
  movaps xmm3, guest_context.$xmm3[rsp + SVM_FRAME_CONTEXT]
  movaps xmm4, guest_context.$xmm4[rsp + SVM_FRAME_CONTEXT]
  movaps xmm5, guest_context.$xmm5[rsp + SVM_FRAME_CONTEXT]
  movaps xmm6, guest_context.$xmm6[rsp + SVM_FRAME_CONTEXT]
  movaps xmm7, guest_context.$xmm7[rsp + SVM_FRAME_CONTEXT]
  movaps xmm8, guest_context.$xmm8[rsp + SVM_FRAME_CONTEXT]
  movaps xmm9, guest_context.$xmm9[rsp + SVM_FRAME_CONTEXT]
  movaps xmm10, guest_context.$xmm10[rsp + SVM_FRAME_CONTEXT]
  movaps xmm11, guest_context.$xmm11[rsp + SVM_FRAME_CONTEXT]
  movaps xmm12, guest_context.$xmm12[rsp + SVM_FRAME_CONTEXT]
  movaps xmm13, guest_context.$xmm13[rsp + SVM_FRAME_CONTEXT]
  movaps xmm14, guest_context.$xmm14[rsp + SVM_FRAME_CONTEXT]
  movaps xmm15, guest_context.$xmm15[rsp + SVM_FRAME_CONTEXT]

  cmp qword ptr [rsp + SVM_FRAME_STOP], 0
  jne svm_vmrun_stop

  mov rcx, guest_context.$rcx[rsp + SVM_FRAME_CONTEXT]
  mov rdx, guest_context.$rdx[rsp + SVM_FRAME_CONTEXT]
  mov rbx, guest_context.$rbx[rsp + SVM_FRAME_CONTEXT]
  mov rbp, guest_context.$rbp[rsp + SVM_FRAME_CONTEXT]
  mov rsi, guest_context.$rsi[rsp + SVM_FRAME_CONTEXT]
  mov rdi, guest_context.$rdi[rsp + SVM_FRAME_CONTEXT]
  mov r8,  guest_context.$r8[rsp + SVM_FRAME_CONTEXT]
  mov r9,  guest_context.$r9[rsp + SVM_FRAME_CONTEXT]
  mov r10, guest_context.$r10[rsp + SVM_FRAME_CONTEXT]
  mov r11, guest_context.$r11[rsp + SVM_FRAME_CONTEXT]
  mov r12, guest_context.$r12[rsp + SVM_FRAME_CONTEXT]
  mov r13, guest_context.$r13[rsp + SVM_FRAME_CONTEXT]
  mov r14, guest_context.$r14[rsp + SVM_FRAME_CONTEXT]
  mov r15, guest_context.$r15[rsp + SVM_FRAME_CONTEXT]
  jmp svm_vmrun_enter

svm_vmrun_stop:
  mov rcx, qword ptr [rsp + SVM_FRAME_CPU]
  lea rdx, [rsp + SVM_FRAME_CONTEXT]
  sub rsp, 28h
  call svm_prepare_stop_c
  add rsp, 28h

  lea rdi, [rsp + SVM_FRAME_CONTEXT]
  mov rbx, qword ptr [rsp + SVM_FRAME_VMCB_VA]
  mov rax, qword ptr [rbx + VMCB_RSP_OFFSET]
  sub rax, 28h

  mov rcx, qword ptr [rbx + VMCB_RIP_OFFSET]
  mov qword ptr [rax + 00h], rcx
  movzx ecx, word ptr [rbx + VMCB_CS_SELECTOR_OFFSET]
  mov qword ptr [rax + 08h], rcx
  mov rcx, qword ptr [rbx + VMCB_RFLAGS_OFFSET]
  mov qword ptr [rax + 10h], rcx
  mov rcx, qword ptr [rbx + VMCB_RSP_OFFSET]
  mov qword ptr [rax + 18h], rcx
  movzx ecx, word ptr [rbx + VMCB_SS_SELECTOR_OFFSET]
  mov qword ptr [rax + 20h], rcx

  mov rsp, rax
  mov rax, guest_context.$rax[rdi]
  mov rcx, guest_context.$rcx[rdi]
  mov rdx, guest_context.$rdx[rdi]
  mov rbx, guest_context.$rbx[rdi]
  mov rbp, guest_context.$rbp[rdi]
  mov rsi, guest_context.$rsi[rdi]
  mov r8,  guest_context.$r8[rdi]
  mov r9,  guest_context.$r9[rdi]
  mov r10, guest_context.$r10[rdi]
  mov r11, guest_context.$r11[rdi]
  mov r12, guest_context.$r12[rdi]
  mov r13, guest_context.$r13[rdi]
  mov r14, guest_context.$r14[rdi]
  mov r15, guest_context.$r15[rdi]
  mov rdi, guest_context.$rdi[rdi]
  iretq

svm_successful_launch:
  mov al, 1
  ret
svm_launch_asm ENDP

END
