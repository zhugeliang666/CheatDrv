# ADR-0068: AMD-SVM 常驻状态 Per-vCPU Scratch 回写与受保护异常探针描述符契约 (BugCheck 0xDEAD000E @ 0x5B 根因闭环)

- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**:
  1. **直接故障根因（Host CR3 直写未映射 Guest VA）**：AMD-SVM 常驻交接完成后，`MAPCTL_IOCTL_STATUS` (`0x222280`) 发起 `hypercall_get_payload_status` (`91 / 0x5B`)。`svm-exit.cpp` 在 SVM Root / Host CR3 (`g_ghv->host_page_tables.pml4_pfn`) 下直接把调用方传入的 Guest VA (`ctx->rcx`, 如 `ffffe781bfe89068`) 传给 `PayloadAmdControlDispatch` -> `PayloadGetStatus` 写入。该缓冲区在 System/Guest CR3 中有效，但在 Host CR3 中 PTE 为 0，导致 `PayloadGetStatus` 首次状态写入（`out->abi_version = 0x57`）触发 Host `#PF`。
  2. **二次故障放大（陈旧 `r10/r11` 伪异常恢复）**：`PayloadGetStatus` 在首次写输出缓冲区前先调用 `PayloadQueryEptSplitUsage` -> `PayloadReadHostU64` -> `PayloadMemcpySafe`；`PayloadMemcpySafe` 设置了 `r10 = payload_memcpy_safe_ehandler` 与 `r11 = rcx`，但其成功路径未清零 `r10/r11`。随后首次写入输出缓冲区触发 Host `#PF` 时，Host 异常处理器 `hv::handle_host_interrupt` 仅凭 `r10/r11 != 0` 判定“受保护探针”，误将陈旧 `r10/r11` 当作当前恢复上下文，跳转到 `payload_memcpy_safe_ehandler` (`pop rdi; pop rsi; ret`)，在 `PayloadGetStatus` 不匹配的栈帧上弹出两个槽位并返回到栈上的 hypercall 编号 `0x5B`，引发 `0x5B` 取指 `#PF` (`PFEC=0x10`)，最终触发 `BugCheck 0xDEAD000E` (`RIP/CR2 = 0x5B`) 掩盖了首次写故障。

- **技术决策与规范**:
  1. **方案 A：Root-local / Per-vCPU 状态缓冲 + `copy_to_guest`**：
     - 在 `hv::vcpu`（已在 Host CR3 常驻映射）与 `VtResidentPayload` 中建立每 CPU 独立的 `status_scratch`（`0x20B8` 字节），包含首尾 Canary (`STATCNR1` / `STATCNR2`)、奇偶 `generation`、`active_cpu` 与 `in_use` 互斥标记。
     - `svm-exit.cpp` 处理 `hypercall_get_payload_status` 时，`PayloadAmdControlDispatch` 仅写入当前 vCPU 的 `cpu->status_scratch.status_bytes`，并在写入前后校验首尾 Canary 与奇偶 `generation`。
     - 填充完成后由 `svm-exit.cpp` 调用逐页翻译的 `copy_to_guest(v, ctx->rcx, scratch.status_bytes, sizeof(scratch.status_bytes), &fault_va)` 回写 Guest VA；若 Guest VA 未映射或跨页缺页，立即调用 `inject_page_fault(v, ctx, fault_va, true)` 向 Guest 注入 `#PF` 并直接 `return`（不推进 Guest RIP）。
     - `PayloadAmdControlDispatch` 对 `case 91` 同步实施 Host 映射范围强校验；Intel VMX `PayloadBridgeHandlePayloadStatus` 同步切换为 per-vCPU `g_payload_vcpu_status_scratch[64]`，消除全局共享 `g_payload_control_status_scratch` 的并发撕裂。
  2. **受保护探针 Active Probe Descriptor 与寄存器清理纵深防御**：
     - 废除仅凭 `r10/r11 != 0` 的异常恢复判据。在 `hv::vcpu` 与 `VtResidentPayload` 中建立每 vCPU 的 `active_probe` 描述符（`magic = 'PROBDSC1'`、`active`、`fault_rip_start`、`fault_rip_end`、`recovery_rip`、`exception_info_va`、`expected_rsp_low`、`expected_rsp_high`）。
     - `hv::memcpy_safe` / `rdmsr_safe` / `wrmsr_safe` / `xsetbv_safe` 与 `PayloadMemcpySafe` / `PayloadRdmsrSafe` / `PayloadWrmsrSafe` / `PayloadXsetbvSafe` 在进入汇编指令前登记 `active_probe`，正常退出时注销，且汇编返回路径显式执行 `xor r10d, r10d; xor r11d, r11d`。
     - `handle_host_interrupt` 与 `PayloadHandleHostInterrupt` 处理异常时，必须同时校验：`active == 1`、故障 `RIP` 严格落在 `[fault_rip_start, fault_rip_end)` 受保护指令区间、`recovery_rip` 位于当前模块 `.text` 可执行代码节、`exception_info` 位于当前 Host 栈且 8 字节对齐、故障 `RSP` 位于 `[expected_rsp_low, expected_rsp_high]`。
  3. **首次 Host 异常确定性诊断落盘与 AMD Host IDT 交接重绑**：
     - 首个 Host 异常的 `vector`、`error` (`PFEC`)、`rip`、`cr2`、`rsp` 在任何恢复尝试或二次故障前原子写入每 vCPU 的 `host_exception_diag` (`first_*`)；若发生未恢复异常或二次故障，`trigger_host_crash_dump` 强制上报首次故障现场。
     - `svm_ack_resident_loop_c` 在 AMD 常驻交接时初始化 `cpu->status_scratch` Canary，并将 `cpu->host_idt` 重绑至 `VtResidentPayload` 内部中断处理桩并重新 `__lidt`。

- **已知约束与避坑**:
  - 严禁在 Root / Host CR3 下直接解引用或写入仅在 Guest/System CR3 中映射的调用方虚拟地址；
  - 严禁仅凭通用寄存器 `r10/r11` 非零作为 Host 异常恢复凭据；
  - 新增 `hv::vcpu` 诊断与缓冲字段必须置于结构体尾部，严禁改变 `resident_hv_diag_record` (`0x640` 字节) 与 `payload_status` (`0x20B8` 字节) 的 ABI 布局。
