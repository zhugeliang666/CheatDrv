PUBLIC hv_memcpy_safe_raw
PUBLIC hv_memcpy_safe_fault_begin
PUBLIC hv_memcpy_safe_fault_end
PUBLIC hv_memcpy_safe_ehandler

PUBLIC hv_xsetbv_safe_raw
PUBLIC hv_xsetbv_safe_fault_begin
PUBLIC hv_xsetbv_safe_fault_end
PUBLIC hv_xsetbv_safe_ehandler

PUBLIC hv_wrmsr_safe_raw
PUBLIC hv_wrmsr_safe_fault_begin
PUBLIC hv_wrmsr_safe_fault_end
PUBLIC hv_wrmsr_safe_ehandler

PUBLIC hv_rdmsr_safe_raw
PUBLIC hv_rdmsr_safe_fault_begin
PUBLIC hv_rdmsr_safe_fault_end
PUBLIC hv_rdmsr_safe_ehandler

.code
hv_memcpy_safe_raw proc
  mov r10, hv_memcpy_safe_ehandler
  mov r11, rcx
  mov byte ptr [rcx], 0

  ; store RSI and RDI
  push rsi
  push rdi

  mov rsi, r8
  mov rdi, rdx
  mov rcx, r9

hv_memcpy_safe_fault_begin::
  rep movsb
hv_memcpy_safe_fault_end::

hv_memcpy_safe_ehandler::
  ; Restore RDI and RSI
  pop rdi
  pop rsi
  xor r10d, r10d
  xor r11d, r11d
  ret
hv_memcpy_safe_raw endp

hv_xsetbv_safe_raw proc
  mov r10, hv_xsetbv_safe_ehandler
  mov r11, rcx
  mov byte ptr [rcx], 0

  ; idx
  mov ecx, edx

  ; value (low part)
  mov eax, r8d

  ; value (high part)
  mov rdx, r8
  shr rdx, 32

hv_xsetbv_safe_fault_begin::
  xsetbv
hv_xsetbv_safe_fault_end::

hv_xsetbv_safe_ehandler::
  xor r10d, r10d
  xor r11d, r11d
  ret
hv_xsetbv_safe_raw endp

hv_wrmsr_safe_raw proc
  mov r10, hv_wrmsr_safe_ehandler
  mov r11, rcx
  mov byte ptr [rcx], 0

  ; msr
  mov ecx, edx

  ; value
  mov eax, r8d
  mov rdx, r8
  shr rdx, 32

hv_wrmsr_safe_fault_begin::
  wrmsr
hv_wrmsr_safe_fault_end::

hv_wrmsr_safe_ehandler::
  xor r10d, r10d
  xor r11d, r11d
  ret
hv_wrmsr_safe_raw endp

hv_rdmsr_safe_raw proc
  mov r10, hv_rdmsr_safe_ehandler
  mov r11, rcx
  mov byte ptr [rcx], 0

  ; msr
  mov ecx, edx
  xor eax, eax
  xor edx, edx

hv_rdmsr_safe_fault_begin::
  rdmsr
hv_rdmsr_safe_fault_end::

  ; return value
  shl rdx, 32
  or rax, rdx

hv_rdmsr_safe_ehandler::
  xor r10d, r10d
  xor r11d, r11d
  ret
hv_rdmsr_safe_raw endp
end

