.code

vm segment

?vmx_vmcall@hv@@YA_KAEAUhypercall_input@1@@Z proc
  push rbx
  mov r10, rcx
  xor eax, eax
  cpuid
  cmp ebx, 68747541h   ; 'Auth' (AuthenticAMD)
  pop rbx
  mov rcx, r10
  je short do_amd_vmmcall

  mov rax, [rcx]       ; code
  mov rdx, [rcx + 10h] ; args[1]
  mov r8,  [rcx + 18h] ; args[2]
  mov r9,  [rcx + 20h] ; args[3]
  mov r10, [rcx + 28h] ; args[4]
  mov r11, [rcx + 30h] ; args[5]
  mov rcx, [rcx + 08h] ; args[0]
  vmcall
  ret

do_amd_vmmcall:
  mov rax, [rcx]       ; code
  mov rdx, [rcx + 10h] ; args[1]
  mov r8,  [rcx + 18h] ; args[2]
  mov r9,  [rcx + 20h] ; args[3]
  mov r10, [rcx + 28h] ; args[4]
  mov r11, [rcx + 30h] ; args[5]
  mov rcx, [rcx + 08h] ; args[0]
  db 0fh, 01h, 0d9h    ; vmmcall
  ret
?vmx_vmcall@hv@@YA_KAEAUhypercall_input@1@@Z endp

?vmx_vmcall_preserve_nonvol@hv@@YA_KAEAUhypercall_input@1@@Z proc
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15

  mov r12, rcx
  xor eax, eax
  cpuid
  cmp ebx, 68747541h   ; 'Auth' (AuthenticAMD)
  mov rcx, r12
  je short do_amd_vmmcall_preserve

  mov rax, [rcx]       ; code
  mov rdx, [rcx + 10h] ; args[1]
  mov r8,  [rcx + 18h] ; args[2]
  mov r9,  [rcx + 20h] ; args[3]
  mov r10, [rcx + 28h] ; args[4]
  mov r11, [rcx + 30h] ; args[5]
  mov rcx, [rcx + 08h] ; args[0]
  vmcall
  jmp short done_preserve

do_amd_vmmcall_preserve:
  mov rax, [rcx]       ; code
  mov rdx, [rcx + 10h] ; args[1]
  mov r8,  [rcx + 18h] ; args[2]
  mov r9,  [rcx + 20h] ; args[3]
  mov r10, [rcx + 28h] ; args[4]
  mov r11, [rcx + 30h] ; args[5]
  mov rcx, [rcx + 08h] ; args[0]
  db 0fh, 01h, 0d9h    ; vmmcall

done_preserve:
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
  ret
?vmx_vmcall_preserve_nonvol@hv@@YA_KAEAUhypercall_input@1@@Z endp

vm ends

end
