.code
; bool __vm_launch();
?vm_launch@hv@@YA_NXZ proc
  ; 设置 VMCS_GUEST_RSP to the 当前 值 of RSP
  mov rax, 681Ch
  vmwrite rax, rsp

  ; 设置 VMCS_GUEST_RIP to the 地址 of <执行成功ful_launch>
  mov rax, 681Eh
  mov rdx, successful_launch
  vmwrite rax, rdx

  vmlaunch

  ; if we reached here, then we 执行失败 to launch
  xor al, al
  ret

successful_launch:
  mov al, 1
  ret
?vm_launch@hv@@YA_NXZ endp

end

