# ADR-0051: VT/SVM 硬件虚拟化框架全量集成、三合一单驱动内嵌打包、重复加载防护与逆序卸载规范

- **状态**: 已采纳
- **日期**: 2026-10-22
- **上下文与痛点**:
  1. 在反作弊（如 ACE / Vanguard / EAC）高强度内核页表与物理内存审计场景下，传统 Guest Ring 0 的 System PTE 重映射虽具备高性能，但仍处于 Guest OS 层级。
  2. 项目已有完整打磨的 Intel VT-x / AMD SVM 硬件虚拟化与常驻载荷工程，具备全核 EPT/NPT 隐藏（`hide_physical_page` / `hide_pfn_list`）、Host 映射直拷贝物理/虚拟内存读写（`read_phys_mem` / `write_phys_mem` / `read_virt_mem` / `write_virt_mem`）、`System CR3` 页表 `NX=1` 伪装（`PTE_SEAL`）、`CallUser` / `CallKernel` 合法栈回溯返回桩、TSC 时序补偿以及 0~95 号完整 Hypercall 协议。
  3. 需要将三大 VT 子项目 **100% 零遗漏迁移** 至 `CheatDrv` 主仓库，并将 `Machenike` (`mswsk.sys`) 一并内嵌至 `VtBootstrapDriver.sys`（实现 **三合一单驱动不落地链式映射**：`VtBootstrapDriver.sys` 内嵌 `VtHypervisor`、`VtResidentPayload` 与 `Machenike`），支持**重复加载检测**与**逆序安全卸载**，同时规范 VT 调试日志宏（`VT_DBG`）与 `Machenike` 的 `DBG` 宏解耦，并补齐针对非法 `VMCALL` 探针、`IA32_FEATURE_CONTROL` (MSR `0x3A`) 与 `CPUID` 虚拟化特征的闭环伪装。

- **技术决策与规范**:
  1. **三合一单驱动自动内嵌打包与内核态链式映射体系**:
     - 将三大 VT 工程规范化命名为 `VtHypervisor`（`vt/vtcall-driver-main/VtHypervisor.vcxproj`）、`VtResidentPayload`（`vt/vt-call-pyaload-main/VtResidentPayload.vcxproj`）与 `VtBootstrapDriver`（`vt/vt-call-mapdriver-main/VtBootstrapDriver.vcxproj`），移除冗余无引用的 `VtHvCore.vcxproj`。
     - 通过 `VtBootstrapDriver.vcxproj` 的 `<ProjectReference>`（包含 `VtHypervisor`、`VtResidentPayload`、`Machenike`）与 MSBuild `BeforeTargets="ClCompile"` 自动调用 `vt/pack_embedded_vt.py`：每次生成 `VtBootstrapDriver` 时自动先行编译并经过 XPRESS 压缩 + 流加密生成 `common/testDriver.h`（`VtHypervisor.sys`）、`common/resident_payload.h`（`VtResidentPayload.sys`）与 `common/machenike_payload.h`（`mswsk.sys`），磁盘仅需单一驱动文件。
     - **Machenike 双模按需加载 (`MAPCTL_IOCTL_LOAD_MACHENIKE`：`1=正常加载驱动` / `2=内存映射驱动`)**:
       * **模式 1 (`MAPCTL_MK_MODE_NORMAL`，正常加载驱动)**：创建 `\Device\MsNetEndpoint` 设备对象与 `\DosDevices\MsNetEndpoint` 符号链接，在 `VtBootstrapDriver` 派遣函数中按 `DeviceObject != g_control_device` 多路转发 IRP，**不擦除、不隐藏 `Machenike` 驱动内存**。
       * **模式 2 (`MAPCTL_MK_MODE_MANUAL_MAP`，内存映射驱动)**：**不创建符号链接与设备对象**，由 `MAPCTL_IOCTL_LOAD_MACHENIKE` 将 `DRV_BOOT_CONFIG_EX` 直接传入 `Machenike` 的 `DriverEntry` 启动通信服务（TCP/UDP/USB），并抹除 `Machenike` 的 PE 头/`INIT`/`.reloc` 节、施加 W^X 权限且调用 `VtEngine::HideVirtualRange` 隐藏 `Machenike` 驱动内存。
  2. **重复加载防护与逆序安全卸载闭环**:
     - **内核态幂等防重 (`Utils.cpp` & `main.cpp`)**：`Utils::LoadDriver`、`Utils::LoadPayload` 与 `Utils::LoadMachenike` 均内置原子状态检查與 `hc::ping()` 探针；若检测到已加载则直接复用现有基址返回成功，严禁重复分配或二次挂接。
     - **应用层前置探测 (`loader/vt_loader.h` & `loader/main.cpp`)**：`VtLoader::IsAlreadyLoaded` 通过打开 `\\.\MapCtlDrv` 发送 `MAPCTL_IOCTL_STATUS` 校验 `vt_ping_ok && payload_loaded && machenike_loaded`；若已激活且未指定 `--force`，直接跳过驱动重映射并下发最新通信配置；若指定 `--force` 则先执行完整卸载再重新加载。
     - **逆序安全卸载 (`Machenike` -> `VtResidentPayload` -> `VtHypervisor`)**：在 `DriverCore::DriverUnload` 中新增对 `g_SecCtx.fWorkItemQueued` 与 `g_MapleCtx.fWorkItemQueued` 的排空等待（且工作项在函数末尾清零标志），确保无 `ExpWorkerThread` 残留执行后，由 `Utils::UnloadMachenike` 调用 `Machenike` 的 `DriverUnload` 并释放其独立物理页，随后依次卸载 `VtResidentPayload`（还原 `System CR3` 的 `NX` 位并从 `MmPfnDatabase` 恢复被摘除的 PFN）与 `VtHypervisor`（全核 `vmxoff`/`svm_off`）。
     - **加载失败防设备泄漏与孤儿设备免重启接管 (`vt/vt-call-mapdriver-main/main.cpp` & `loader/vt_loader.h`)**：
       * `DriverMain` 若返回非 `STATUS_SUCCESS`，必须在退出前调用 `mapdriver_delete_control_device()` 销毁 `\Device\MapPayloadCtl` 与符号链接，并将 `DriverObject->DriverUnload` 置空，严禁遗留未决 `DEVICE_OBJECT` 导致 `nt!IopLoadDriver` 无法释放驱动镜像及锁定磁盘 `.sys` 文件；
       * `mapdriver_create_control_device` 遇到 `STATUS_OBJECT_NAME_COLLISION` 时，自动调用 `mapdriver_reclaim_orphaned_control_device`：通过 `IoGetDeviceObjectPointer` 定位残留孤儿 `DEVICE_OBJECT`，清除其 `DriverObject->DriverUnload` 后执行 `IoDeleteDevice`，免重启释放旧 `DRIVER_OBJECT` 引用计数并解除旧 `.sys` 文件占用；
       * `VtBootstrapDriver.vcxproj` 修正 `ucxxrt.props` 相对路径，确保 `ucxxrt.lib` 的 `DriverEntry` 正确执行 C++ 全局对象初始化后再进入 `DriverMain`。
     - **离线内核符号解析与 `.text` 节区特征扫描兜底 (`ntutils.cpp` & `symbol_resolver.cpp`)**：
       * 补齐宿主机 `ntoskrnl.exe`（Win10 22H2 19045.6466，`TimeDateStamp=0x1C62BEE3`）全量 28 项内核符号硬编码 RVA 与 Win10 `19041..19045` 全量 48 项内核结构体字段偏移，彻底消除对本地 `127.0.0.1:9090` `query_pdb_server.exe` 的强依赖；
       * `VtBootstrapDriver` 在硬编码表与 PDB 服务均未命中时，在 `ntoskrnl.exe` `.text` 节区内通过 `HvlpInitializeHvCrashdump` 特征对扫描定位 `MmAllocateIndependentPages` / `MmFreeIndependentPages` 及 `MmSetPageProtection`，并在 `assign_ntapi_kernel_symbols` 中保留 `yvt_boot_context` 已解析非空函数指针不被清零。
  3. **独立日志宏规范 (`VT_DBG`) 与双端编译期开关**:
     - VT 框架内部（`VtHypervisor`、`VtResidentPayload`、`VtBootstrapDriver`）统一使用独立的 `VT_DBG` 宏，不与 `Machenike` 的 `DBG` 宏耦合。
     - 在 `Core/Common.h` 与 `loader/loader_common.h` 同步引入 `#define ENABLE_VT_FRAMEWORK 1`（及别名 `MK_ENABLE_VT_FRAMEWORK`），复用 `DRV_BOOT_CONFIG.Flags` 新增 `#define DRV_BOOT_FLAG_ENABLE_VT 0x00000002`（保持 120 字节对齐不变）。
  4. **驱动端纯静态类 `VtEngine` (`Stealth/VtEngine.h` & `Stealth/VtEngine.cpp`)**:
     - 严格遵循 `ADR-0030`（纯静态类，0 虚函数，0 vtable）与 `ADR-0034`（Zero IAT）。
     - 同时支持 Intel VT-x（`s_VmCallStub`：`vmcall 0F 01 C1`）与 AMD SVM（`s_VmmCallStub`：`vmmcall 0F 01 D9`）双平台动态分发。
     - **内存引擎双模融合 (`Memory/LeechCoreEngine.cpp`)**：支持通过 `VT_PREFER_HYPERCALL_MEM_RW` 切换主辅策略（默认 `0` 采用 `System PTE` 为主 + `VtEngine` 失败兜底以兼顾百万级散列读吞吐量；置 `1` 强制 `<= 4096B` 优先走 `VtEngine` Hypercall）。
     - **生命周期与 PE 头无模块页隐藏 (`Core/DriverCore.cpp`)**：对手动映射擦除后的 PE 头物理页自动执行 `VtEngine::HideVirtualRange` 全核 EPT 替换为 `dummy_pfn`；卸载时成对调用 `VtEngine::Cleanup` 还原。
  5. **反作弊虚拟化探针闭环防御 (`exit-handlers.cpp` & `VtResidentPayload`)**:
     - **非法 `VMCALL` 探针拦截**：在 `VtHypervisor` 与 `VtResidentPayload` 中，凡未携带合法 `hypercall_key` 且未命中已注册 Hook 表的 `VMCALL`，若 `CPL > 0`（来自 R3 反作弊探针）强制注入 `#UD` (`invalid_opcode`)；若 `CPL == 0`（来自 R0 探针）对齐 Hyper-V TLFS 规范返回 `0x0002` (`HV_STATUS_INVALID_HYPERCALL_CODE`)，根除静默 `RAX=0` 暴露私服 VT 的侧信道。
     - **`CPUID` 与 `IA32_FEATURE_CONTROL` (MSR `0x3A`) 一致性伪装**：拦截 `MSR 0x3A` 返回 `lock_bit=1, enable_vmx=0` 伪装值，并在 `CPUID(1).ECX[5]` (VMX) 与 `CPUID(0x80000001).ECX[2]` (SVM) 中清除硬件虚拟化能力位，与 `CPUID(0x40000000)` 伪装的 `Microsoft Hv` Root Partition 行为 100% 闭合。
     - **加载器服务名伪装 (`loader/vt_loader.h`)**：移除 `"MapPayloadDrv"` 敏感命名，默认伪装为系统平台监控服务 `L"MsPmtSvc"`。

- **已知约束与避坑**:
  1. **严禁对仍在 Guest Ring 0 直接执行的驱动活跃代码页（`.text`）或栈/数据页（`.data`）盲目调用 `HidePhysicalPage` 或置位 `System CR3` `NX=1`**：
     - `HidePhysicalPage` 会将全核 EPT 叶子 PFN 替换为全零 `dummy_pfn`，仅适用于完全驻留在 Host 页表执行或已擦除不再访问的页面（如 ManualMap 擦除后的 PE 头部页 `[kernBase, kernBase + PAGE_SIZE)`）。
  2. **卸载顺序与工作项排空铁律**：
     - 卸载时必须严格遵循 `Machenike` -> `VtResidentPayload` -> `VtHypervisor` 逆序：因为 `Machenike` 卸载 (`DriverCore::DriverUnload`) 需要调用 `VtEngine::Cleanup` 执行 `vmcall` 还原 EPT 隐藏页，必须在 VT 仍处于激活态时先行完成；且释放 `Machenike` 独立物理页前必须等待所有 `ExQueueWorkItem` 工作项执行完毕归零，严禁在工作项未排空时释放代码页引发 `0x50` 蓝屏。
  3. **无 VT 环境防 `#UD (0xC000001D)` 铁律**：
     - **发起任何 `vmcall`/`vmmcall` 前必须校验硬件虚拟化使能位并包裹在 `__try / __except` 中，确保在未开启 VT 的环境下平滑降级至 System PTE 引擎**；且 `VtHypervisor` (`vt/vmx.asm`) 与 `VtResidentPayload` (`src/vmcall.asm`) 必须通过 `CPUID(0).EBX == 'Auth'` (`0x68747541`) 动态区分 Intel `vmcall` (`0F 01 C1`) 与 AMD `vmmcall` (`0F 01 D9`)，杜绝在 AMD SVM 宿主上触发 `#UD` (`0xC000001D`)。
  4. **Host 页表深拷贝 PML4 克隆与防 `BugCheck 0x4E (PFN_LIST_CORRUPT, Arg1=0x99)` 铁律 (`page-tables.cpp` & `amd/npt.cpp`)**：
     - `prepare_host_page_tables` 末尾执行 `copy_page_table` 后，Host 的 `pt.pml4` 高半区条目直接共享了 `System CR3` 的真实内核 PDPT 物理页（`pml4->page_frame_number == page_entry.pml4.page_frame_number`）；后续任何调用 `map_host_virtual_range` -> `map_page` 的路径（如 AMD SVM `create_vcpu_state` 映射 `vmcb`、`npt_data`），必须在 PML4 层校验 `pml4->page_frame_number == page_entry.pml4.page_frame_number` 并先行克隆私有 Host PDPT 页，严禁顺着共享 PML4E 直接覆写 Windows 真实内核 PDPT/PDE 条目导致 `pages_max` 爆仓与 `ExFreePool` 触发 `BugCheck 0x4E (0x99)`；
     - AMD NPT 在 `#VMEXIT` (`host_cr3`, `IF=0`) 上下文内（`split_2mb_pde`、`get_npt_pte`、`activate_npt_exec_view`）严禁调用 `MmGetPhysicalAddress` 或 `MmGetVirtualForPhysical`，必须在 `prepare_npt` (`PASSIVE_LEVEL`) 阶段预计算 `free_pt_pfns`、`pd_pfn`、`pt_pfn` 并通过 `hv::host_physical_to_virtual` 访问物理页。
  5. **AMD SVM 启动/退出时序 (`CLGI`/`STGI`/`VMSAVE`/`IDTR`)、NPT 按需动态映射与 `#VMEXIT` 零内核 API 铁律 (`amd/svm.cpp`、`amd/svm-exit.cpp`、`amd/npt.cpp`、`vt/page-tables.cpp`)**：
     - **前置预分配防跨核页表并发竞争**：全核 SVM 状态（`vmcb`、`host_save`、`msrpm`、`npt`）必须在 `hv::create()` 的 `prepare_host_page_tables()` 之前一次性完成分配并映射至 `host_page_tables`，严禁在 `virtualize_cpu` 逐核循环中边运行 `vCPU 0` 边修改 `host_page_tables`；`npt_data` 直接由 `ExAllocatePoolWithTag(NonPagedPoolNx, ...)` 分配（依赖 `copy_page_table` 映射），不进入 `PoolManager` 链表亦不调用 `map_host_virtual_range`；
     - **严禁在 `VMRUN` 前开启中断 (`_enable`) 或覆盖 Guest `IDTR`**：`launch_vcpu` 必须在修改 `IDTR` 与 `_disable()` 前先调用 `setup_vmcb_for_current_guest` 捕获真实 Windows `IDTR` 与 `RFLAGS.IF=1`，随后在 `_disable()` + `CLGI` (`GIF=0`) 保护下执行 `svm_vmsave_asm(vmcb_pa)` 与 `svm_vmsave_asm(host_save_pa)` 硬件同步隐藏段寄存器，再加载 `host_idt` 并直接进入 `svm_launch_asm`（由 `VMRUN` 原子恢复 Guest `GIF=1` 与 `IF=1`）；卸载退出（`svm_prepare_stop_c`）清除 `EFER.SVME` 前必须执行 `svm_stgi_asm()` (`STGI`) 恢复 `GIF=1`，防止 CPU 永久屏蔽全局中断导致系统死锁且无法生成转储文件（`.dmp`）；
     - **动态 `#NPF` 高位 MMIO 映射与防跨页指令死锁**：`handle_npf` 遇到 `!err.present`（如 `>= 512GB` 的 PCIe ReBAR / GPU MMIO 空间）时，必须通过 `ensure_npt_mapped` 从 `free_pts` 动态分配 PDPT/2MB PD 建立恒等映射，严禁盲目注入 `#GP(0)`；且 AMD SVM 下跳过仅用于 Intel EPT Execute-Only 的 `dwm::bootstrap_tramp_pool(ntoskrnl)`，同时在 `activate_npt_exec_view` 中放行未挂钩的相邻下一页（`pt_idx + 1`）执行权限，根除跨 4KB 页边界指令在 `normal_npt` 与 `exec_view` 之间无限 `#NPF` 乒乓死锁；
     - **`#VMEXIT` 零 `DbgPrintEx` 与零 `MmGetVirtualForPhysical`**：`svm-exit.cpp` 所有 `#VMEXIT` 路径严禁调用 `LOG_DEBUG` (`DbgPrintEx`)；`page-tables.cpp` 在 `host_cr3` 下执行 `hypercall_map_host_range` 时必须通过 `is_executing_on_host_cr3()` 走 `host_physical_to_virtual` 与预计算的 `pages_pfns`，严禁在 Host CR3 下调用 `MmGetVirtualForPhysical` 或 `MmGetPhysicalAddress`。
     - **废除 Host 异常 Triple Fault，回退 Guest 态触发 `KeBugCheckEx` 生成 `.dmp` (`vt/vcpu.cpp`、`amd/svm-exit.cpp`、`amd/svm-asm.asm`)**：在 `handle_host_interrupt` 捕获未处理的 Host 异常或 `handle_vmexit` 遇到 `vmexit_invalid` / `vmexit_shutdown` 时，严禁加载空 `IDTR` 触发三重故障硬重启；必须先通过 `svm_prepare_stop_c` / `vmx_vmxoff` 恢复 `GIF=1`、关闭 `EFER.SVME`/VMX、切回内核 `CR3`、恢复 Windows `GDTR`/`IDTR`/`TR` 与 Ring 0 `KPCR` (`GSBase`)，再经 `hv_bugcheck_on_stack_asm` 切换至有效内核栈调用 `KeBugCheckEx(0xDEAD0000 | vector, fault_rip, rip_rva, fault_cr2, (error_code << 32) | exitcode)`，确保 Windows 正常落盘 `.dmp` 转储文件。
  6. **AMD 首次 `VMRUN` 的 GIF 恢复、启动看门狗与内核转储闭环（2026-10-22）**：
     - AMD APM 规定 `#VMEXIT` 会清除 GIF；`VMRUN` 不负责恢复宿主 GIF。旧路径在 `launch_vcpu` 进入汇编前执行 `CLGI`，但在第一次及后续 `VMRUN` 前均没有执行 `STGI`，导致 Guest 即使恢复 `RFLAGS.IF=1` 也收不到物理中断，系统会在 `StartServiceW` 内表现为整机冻结且没有机会进入 Windows BugCheck/转储路径。
     - `svm_vmrun_enter` 必须在 `VMLOAD guest` 后、每次 `VMRUN` 前执行 `STGI`，并保持宿主 `RFLAGS.IF=0`；`VMRUN` 原子加载 Guest RFLAGS 后中断才对 Guest 生效。`#VMEXIT` 后显式 `CLGI` 仅用于把宿主状态约束写清楚，不能用它替代下一次 `VMRUN` 前的 `STGI`。
     - `hv::start` 在 AMD 创建阶段、处理器亲和阶段和 `VMRUN` 阶段分别设置跨处理器一次性 DPC 看门狗；30 秒未完成时调用 `KeBugCheckEx(0xE2000A01, stage, target_cpu, watchdog_cpu, cr3)`，其中 `stage=1/2/3` 分别表示 create/affinity/vmrun。成功或失败离开阶段时必须取消定时器并移除排队 DPC，防止迟到 BugCheck。
     - 加载器在启动服务前幂等配置 `CrashControl`：`CrashDumpEnabled=2`、`DumpFile=%SystemRoot%\\MEMORY.DMP`、`AlwaysKeepMemoryDump=1`、`AutoReboot=0`。首次改变转储类型后必须重启一次，并保证系统卷分页文件足以承载 kernel dump；否则即使看门狗成功触发 BugCheck 也可能没有落盘文件。
  7. **无分页文件主机的 DedicatedDumpFile 与外层引导看门狗（2026-10-22 二次闭环）**：
     - 仅设置 `CrashDumpEnabled=2` 不能证明转储后端已就绪；禁用系统管理分页文件或页面文件大小为零时，BugCheck 仍可能没有 `MEMORY.DMP`。加载器同时设置 `DedicatedDumpFile=<SystemDrive>:\\DedicatedDump.sys`、`DumpFileSize=物理内存MiB+512`、`IgnorePagefileSize=1`，首次变更后停止加载并要求重启；重启后的下一次运行必须实际观察到不小于该配置容量的 dedicated dump backing file，否则拒绝进入 VT。
     - `mapDriver.sys` 与 `VtBootstrapDriver.sys` 同时存在时固定选择规范名 `VtBootstrapDriver.sys`，不再依据时间戳选择可能陈旧的 legacy 映像；启动服务前输出实际路径、文件大小与最后写入时间作为二进制身份凭据。
     - 内层 `hv::start` 看门狗不能覆盖手动映射器、C++ 初始化或进入 `hv::start` 之前的冻结。`VtBootstrapDriver` 因此在 `KeExpandKernelStackAndCalloutEx -> Utils::LoadDriver` 外层再设置 20 秒跨处理器 DPC 看门狗，超时调用 `KeBugCheckEx(0xE2000A02, 0x10, target_cpu, watchdog_cpu, image_base)`；返回路径必须取消 timer 并移除已排队 DPC。
     - 加载器同时为 `i8042prt` 与 `kbdhid` 配置 `CrashOnCtrlScroll=1`。重启后若界面冻结但键盘中断仍可交付，按住右 Ctrl 并连续按两次 Scroll Lock，可手动触发 `MANUALLY_INITIATED_CRASH (0xE2)`，使用同一 dedicated dump backing file 落盘。
  8. **DedicatedDump.sys 独占锁语义与 legacy 映像拒绝（2026-10-22 三次闭环）**：
     - Crash dump stack 在启动阶段成功接管 `DedicatedDump.sys` 后可能保持独占句柄；此时 `GetFileAttributesExW` 返回 `ERROR_SHARING_VIOLATION (32)`，该结果表示文件已存在且被转储栈占用，必须作为“armed”成功证据，而不是把它误判为文件缺失。`ERROR_FILE_NOT_FOUND`、`ERROR_PATH_NOT_FOUND` 等其他错误仍然失败关闭。
     - 仅存在 `mapDriver.sys` 时，加载器不再继续使用无法关联构建身份的 legacy 映像，而是要求部署同一交付包中的 `VtBootstrapDriver.sys`。该门禁避免新 loader 搭配旧 bootstrap，导致修复后的外层看门狗与内嵌 Hypervisor 实际没有运行。
  9. **VtHypervisor 入口全旁路二分诊断（2026-10-22）**：
     - `YVT_ENTRY_BISECT_BYPASS=1` 时，`VtHypervisor::DriverMain` 在 `VMB`、boot context 解引用、符号解析、内存分配、`hv::start`、Hook 和后台工作之前立即返回 `STATUS_NOT_SUPPORTED`。
     - 旁路必须返回失败而不是伪造成功；伪造成功会让 `VtBootstrapDriver` 在没有活动 Hypervisor 的状态下继续加载 resident payload，使测试结果混入后续链路。
     - 判定契约：旁路版本仍硬冻结，故障位于 `DriverMain` 之前（解包、PE 手动映射、重定位/导入、C++ 初始化或调用入口本身）；旁路版本正常返回服务错误，则故障位于被旁路的 `DriverMain` 流程，下一轮按 `boot context -> symbols -> hv::start` 逐段恢复。
  10. **入口二分阶段 2：仅 boot context（2026-10-22）**：
     - 用户实机确认空入口测试不再冻结；将 `YVT_ENTRY_BISECT_BYPASS` 设置为 `2`，只执行原有 boot magic/size 校验、flags/status 初始化、`yvt_apply_boot_kernel_alloc_api`、`yvt_try_activate_external_state`，随后无条件返回 `STATUS_NOT_SUPPORTED`。
     - 不恢复 VMB、符号解析、hv::start、Hook、卸载注册和后台任务。无效 boot context 也直接返回同一诊断失败状态，不进入普通启动。
     - 本轮重新构建 VtHypervisor，并重新压缩内嵌到 VtBootstrapDriver；实机返回 0xC00000BB 为预期结果，是否冻结由用户测试确认。回滚至本轮原始文件，或阶段 1 空入口用于对照。
  11. **入口二分阶段 3：仅追加符号初始化（2026-10-22）**：
     - 用户实机确认阶段 2 不冻结；当前 `YVT_ENTRY_BISECT_BYPASS=3`，复用阶段 2 boot context 校验、alloc API 和 external state 初始化后，仅调用一次 `yvt_init_symbols_expanded()`，立即返回 `STATUS_NOT_SUPPORTED`。
     - VMB、CPU 探测、卸载注册、hv::start、Hook 和其他后续流程仍关闭。函数内部原有 expanded-stack 与 InitNtSymbol 行为保持原样，不添加其他阶段操作。
     - 预期入口仍返回 0xC00000BB；若此轮冻结，优先定位 expanded-stack/symbol 初始化内部；若不冻结，下一轮再由用户指定恢复范围。回滚恢复阶段 2 的原始源码快照。
  12. **入口二分阶段 4：厂商探测与映像元数据（2026-10-22）**：
     - 用户实机确认阶段 3 不冻结；本轮 `YVT_ENTRY_BISECT_BYPASS=4`，保留阶段 3，仅追加 CPUID(0) CPU vendor、CPUID(0x40000000) Hypervisor vendor 与原 VMware 判定，以及 `__ImageBase` / PE `SizeOfImage` 记录，随后立即返回 `STATUS_NOT_SUPPORTED`。
     - CPU vendor 按 EBX/EDX/ECX 拼接；Hypervisor vendor 按 EBX/ECX/EDX 拼接。两者日志分别输出，避免把 Hypervisor leaf 当作 CPU 厂商。仅进行探测与状态记录，不启动虚拟化。
     - VMB、DriverUnload 注册、hv::start、Hook 和后台任务继续关闭。增加 `[YVT-BISECT4]` 三条阶段日志，最后一条用于确认已完成映像元数据读取；0xC00000BB 仍为预期结果。
     - 回滚恢复阶段 3 源码快照；本轮仅构建与静态/打包验证，是否冻结待目标 AMD 实机确认。
  13. **批量诊断阶段 5：完整 create，禁止 VMRUN（2026-10-22）**：
     - 用户要求减少测试次数，改为大块恢复。比较路径 A：完整 hv::start，会同时引入逐核亲和、SVM 状态切换和 VMRUN，故障界限较模糊；路径 B：仅执行完整 create 并清理，覆盖同一批准备工作但不切换 CPU 执行模式。本轮选 B。
     - `YVT_ENTRY_BISECT_BYPASS=5`：保留阶段 4；调用 hv::start 的 create-only 诊断分支。原 create 流程包含资源/Host 栈分配、offsets、Host 可见缓冲预分配、AMD SVM/NPT 状态、Host 页表与链表/调试表初始化，按 1/6～6/6 输出边界日志。
     - 不调用 virtualize_cpu，不进入亲和逐核启动，不执行 VMRUN；VMB、卸载注册、实际 Hook 安装和后台工作仍关闭。初始化 Hook 表不等于安装 Hook。
     - 失败与成功路径均先逐 vCPU 销毁独立 SVM 分配，再排空 PoolManager，清零 ghv 内资源引用；hv::start 返回 false，入口仍返回 STATUS_NOT_SUPPORTED，不让 Bootstrap 进入 resident payload。create 的早期失败可能已经释放部分 SVM 对象，destroy_vcpu_state 的清零字段使再次清理幂等。
     - 本阶段仍使用现有分配/页表实现，其硬件兼容性和真实运行结果待 AMD 实机日志确认；不把构建成功等同运行通过。create result=0 与正常诊断失败必须通过日志区分。回滚恢复阶段 4 源码与原始哈希。
  14. **批量诊断阶段 6：AMD 逐核启动/停止闭环（2026-10-22）**：
     - 用户实机确认阶段 5 的完整 create 与清理正常；本轮 `YVT_ENTRY_BISECT_BYPASS=6`，保留入口前置流程，复用 create、亲和绑定、virtualize_cpu、VMMCALL ping/unload，全部启动后逆序停止。部分启动失败也停止此前实际 launched 的 CPU。
     - 比较路径 A：复用通用 stop() 的位图 ACK；当前 AMD unload 分支未更新 stop_ack_bitmap，不具备可靠成功判定。路径 B：诊断局部确认 Guest continuation 返回签名、svm.launched=false、原始 EFER.SVME 与 VM_HSAVE_PA 恢复。选 B，不改公共协议、不修改其他平台 stop 语义。
     - 当前诊断仅接受 AMD SVM、PASSIVE_LEVEL 上下文与 1～64 逻辑处理器；64 位位图在移位前复核 create 后 CPU 数量。绑定后核验实际 CPU 索引。每核输出 affinity before/after、virtualize before/after、ping 检查、stop hypercall before/after 与 confirmed。
     - started_mask 与 stopped_mask 必须完全一致，所有 vCPU launched 标志均为 false，才销毁 SVM 分配、排空 PoolManager、清零 ghv。禁止用 hv::stop 不完整后简单返回失败，让 Bootstrap 释放仍被 Host RIP 引用的映像。
     - 无法确认停止时不释放任何运行资源，触发 0xE2000A03：P1=1停止绑定失败、2实际CPU错误、3停止状态核验失败、4位图不一致、5仍有launched；P2=CPU/数量，P3=started_mask，P4=stopped_mask。短时诊断看门狗 stop stage=4，返回后取消。
     - Hook 安装、ResidentPayload、VMB、卸载注册和业务后台任务继续关闭；启动/停止日志仅在 Guest 驱动上下文，不在 VMEXIT 热路径添加日志。全部释放后仍返回 0xC00000BB，日志中的 launch_ok 决定完整启动是否通过。实机 VMRUN 与停止是否正常尚待测试，构建与静态/状态机验证不代表硬件验证。

     - 所有 vCPU 停止后，取消并排空诊断 watchdog DPC（KeFlushQueuedDpcs）再释放运行资源/返回入口，避免失败卸载后残留 DPC 执行已释放映像。
  15. **阶段 6 首次 VMRUN 内部诊断标记（2026-10-22）**：
     - 用户实机确认阶段 6 仍在逐核启动期间整机冻结且没有转储；保持 Hook、ResidentPayload、VMB、卸载注册和后台任务关闭，不扩大执行流程，只细化 `virtualize_cpu()` 与 `svm::launch_vcpu()` 的启动观测边界。
     - `virtualize_cpu()` 在 cache、SVM capability、state create、launch 和 ping 前后输出 CPU/结果日志；`launch_vcpu()` 仅在仍处于正常 Windows 执行环境时输出入口、VMCB 准备和 critical-enter 日志。
     - `_disable()` 之后、GIF 清除、Host IDT 装载及 `svm_launch_asm()` 内部边界严禁调用 `DbgPrintEx`。该区间改用每 CPU 固定非分页 `volatile unsigned long` 阶段标记（51～59）；跨核 watchdog 在 BugCheck 前读取并输出 `launch_marker`，避免诊断本身在 IF/GIF/IDTR 临界区引入内核服务调用。
     - 标记 50 表示即将关中断，51/52/53/54 表示 IF/EFER/HSAVE/GIF 已切换，55/56 表示 Guest/Host `VMSAVE` 已完成，57 表示 Host IDT 已装载，58 表示进入汇编，59 表示汇编返回，60 表示失败路径完整恢复，61 表示启动成功。标记只用于定位，不作为同步、成功确认或资源释放依据。
     - 当前构建与静态检查仅证明日志边界和二进制产物；首次 VMRUN 停在哪一标记仍待 AMD 实机串口/DbgView/转储证据确认。
  16. **阶段 6 AMD SVM 硬件契约与 Triple Fault 根因闭环修复（2026-10-22）**：
     - 双机调试实机日志显示 `cpu=0` 完成 `VMRUN` 并通过两次 `hypercall_ping`，但在切换到 `cpu=1` 进入 `launch-before` 时整机无转储重启。对标 AMD64 APM Vol.2 与 `MistyFir/SVMHypervisor-Preview` 定位并修复 6 处底层硬件违规：
       1. **`MSR_VM_HSAVE_PA` 与 `HostVmcb` 物理页隔离**：AMD64 APM Vol.2 15.5.1 严禁对 `MSR_VM_HSAVE_PA` 指向页执行 `VMSAVE`/`VMLOAD`；新增独立 4KB 页 `host_vmcb` (`host_vmcb_pa`) 专供 `VMSAVE`/`VMLOAD` 保存恢复 Host 辅助状态，`host_save_pa` 独占交给 `MSR_VM_HSAVE_PA`。
       2. **移除 `VMRUN` 前错误的 `STGI` 及 `CR8`/`DR6`/`CR2` 覆写**：`VMRUN` 指令微码自动原子置 `GIF=1`；在 `vmload guest` 后、`vmrun` 前提前执行 `stgi` 会使 CPU 在 Host 模式 + Guest `GS.base` 下暴露中断/NMI 窗口；同时移除 `svm-asm.asm` 中将 Host `CR8=0` 误读回写及覆盖 VMCB `CR2`/`DR6` 的 VMX 遗留代码。
       3. **修复 `svm_prepare_stop_c` 中 Busy TSS `LTR` 引发的 `#GP` Triple Fault**：对已处于 Busy (`0xB`) 的 Windows GDT TSS 执行 `hv::write_tr` (`ltr`) 必触发 `#GP`，且此前 `write_gs` 已清零 `GS.base`，导致 `trigger_host_crash_dump` 和停止路径 100% 触发 Triple Fault 重启；改为在 `SVME=1, GIF=0` 下调用 `svm_vmload_asm(vmcb_pa)` 免检原子恢复 `FS/GS/TR/LDTR` 与系统 MSR，最后切换 `CR3`、`STGI` 并还原 `HSAVE_PA`/`EFER`。
       4. **修复 `#BP` (`vmexit_excp3`) 重注入 `RIP` 偏移与精简指令拦截**：AMD `EVENTINJ` 不自动递增 `VMCB.RIP`，反射未命中 `#BP` 前必须执行 `advance_guest_ip(v, 1)`；移除 NPT 下无需拦截的 `INVLPG`/`RDTSCP`/`XSETBV`/`WBINVD`/`INVD`，并在 `handle_host_interrupt` 的 NMI 分支屏蔽 AMD 下对 `inject_nmi()`（含 `vmread`）的调用，同时在 `prepare_host_page_tables` 补齐 `host_vmcb` 与 `svm.npt` 映射。
       5. **彻底修复多核运行与崩溃转储路径的 Triple Fault**：
          - **补齐 `g_vt_hook_table` 的 `host_page_tables` 映射**：外部常驻 arena 中 `g_vt_hook_table` 紧随 `g_ghv` 之后，必须在 `prepare_host_page_tables` 中显式调用 `map_memory((uint64_t)g_vt_hook_table, sizeof(vt_hook_slot) * VMCALL_HOOK_MAX)`；
          - **修复崩溃转储路径 (`trigger_host_crash_dump` / `bugcheck_from_svm_vmexit`) 的 `CR3` 与 `KPCR` 顺序**：崩溃转储路径传入 `svm_prepare_stop_c(cpu, nullptr)`，优先从 `host_vmcb->gs.base` 提取当前核内核 `KPCR`，在 `vmload(vmcb_pa)` 后立即将内核 `KPCR` 写回 `MSR_GS_BASE` 再恢复 Windows `IDTR`，并在 `host_cr3` 下解析完 `guest_krsp` 后强制切回 `system_cr3`（严禁切入可能未懒同步 `MmAllocateIndependentPages` 顶层 PML4E 的任意进程 `v->cr3`）；
          - **消除循环覆盖 `host_vmcb`、全量 TLB 冲刷风暴与按需异常拦截**：移除 `svm_vmrun_enter` 循环内的 `vmsave [host_vmcb_pa]`；在 `clear_event` 中重置 `v->tlb_control = 0`；在 `handle_vmexit` 末尾补齐非 NPF 退出的 `reinject_exitintinfo_if_valid(v)`，并仅在 `pending_restore` / `tramp_pool` / `probe_table` 激活时按需置位 `#DB`/`#BP` 异常拦截；
          - **`#VMEXIT` 强制恢复 Host `GDTR` 与 `IDTR`（`amd/svm-asm.asm` & `amd/svm.cpp`）**：AMD APM Vol.2 15.5.1/15.6 规定 `VMRUN` / `#VMEXIT` 与 `VMLOAD` / `VMSAVE` 均不保存也不恢复 Host 的 `GDTR` 和 `IDTR`。首次 `VMRUN` 加载 Guest 的 `GDTR`/`IDTR` 后，后续所有 `#VMEXIT` 若不显式执行 `lgdt`/`lidt`，CPU 在 Host 模式下仍持有 Guest 的 `IDTR`，一旦 `rdmsr_safe` / `wrmsr_safe`（如 `MSRPM` 范围外扩展 MSR 探测）或 `memcpy_safe` 触发受控异常，将直接跳入 Guest IDT 而非 `cpu->host_idt` 引发 Triple Fault 硬重启。因此在 `svm_launch_asm` 中将当前核 `HOST_GDTR` 与 `HOST_IDTR` 存入 `SVM_FRAME`，在每次 `#VMEXIT` 入口（`vmload [host_vmcb_pa]` 后）强制执行 `lgdt` 与 `lidt` 恢复，并在 `launch_vcpu` 中将每核 `GDTR` 与 `KPCR` 映射进 `host_page_tables`。
