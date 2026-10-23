# ADR-0051: VT/SVM 硬件虚拟化框架全量集成、三合一单驱动内嵌打包、重复加载防护与逆序卸载规范

- **状态**: 已采纳
- **日期**: 2026-10-22
- **上下文与痛点**:
  1. 在反作弊（如 ACE / Vanguard / EAC）高强度内核页表与物理内存审计场景下，传统 Guest Ring 0 的 System PTE 重映射虽具备高性能，但仍处于 Guest OS 层级。
  2. 项目已有完整打磨的 Intel VT-x / AMD SVM 硬件虚拟化与常驻载荷工程，具备全核 EPT/NPT 隐藏（`hide_physical_page` / `hide_pfn_list`）、Host 映射直拷贝物理/虚拟内存读写（`read_phys_mem` / `write_phys_mem` / `read_virt_mem` / `write_virt_mem`）、`System CR3` 页表 `NX=1` 伪装（`PTE_SEAL`）、`CallUser` / `CallKernel` 合法栈回溯返回桩、TSC 时序补偿以及 0~95 号完整 Hypercall 协议。
  3. 需要将三大 VT 子项目 **100% 零遗漏迁移** 至 `CheatDrv` 主仓库，并将 `Machenike` (`mswsk.sys`) 一并内嵌至 `VtBootstrapDriver.sys`（实现 **三合一单驱动不落地链式映射**：`VtBootstrapDriver.sys` 内嵌 `VtHypervisor`、`VtResidentPayload` 与 `Machenike`），支持**重复加载检测**与**逆序安全卸载**，同时规范 VT 调试日志宏（`VT_DBG`）与 `Machenike` 的 `DBG` 宏解耦，并补齐针对非法 `VMCALL` 探针、`IA32_FEATURE_CONTROL` (MSR `0x3A`) 与 `CPUID` 虚拟化特征的闭环伪装。

- **技术决策与规范**:
  1. **三合一单驱动自动内嵌打包与内核态链式映射体系**:
     - 将三大 VT 工程规范化命名为 `VtHypervisor`（`vt/VtHypervisor/VtHypervisor.vcxproj`）、`VtResidentPayload`（`vt/VtResidentPayload/VtResidentPayload.vcxproj`）与 `VtBootstrapDriver`（`vt/VtBootstrapDriver/VtBootstrapDriver.vcxproj`），移除冗余无引用的 `VtHvCore.vcxproj`。
     - 通过 `VtBootstrapDriver.vcxproj` 的 `<ProjectReference>`（包含 `VtHypervisor`、`VtResidentPayload`、`Machenike`）与 MSBuild `BeforeTargets="ClCompile"` 自动调用 `vt/pack_embedded_vt.py`：每次生成 `VtBootstrapDriver` 时自动先行编译并经过 XPRESS 压缩 + 流加密生成 `common/testDriver.h`（`VtHypervisor.sys`）、`common/resident_payload.h`（`VtResidentPayload.sys`）与 `common/machenike_payload.h`（`mswsk.sys`），磁盘仅需单一驱动文件。
     - **Machenike 双模按需加载 (`MAPCTL_IOCTL_LOAD_MACHENIKE`：`1=正常加载驱动` / `2=内存映射驱动`)**:
       * **模式 1 (`MAPCTL_MK_MODE_NORMAL`，正常加载驱动)**：创建 `\Device\MsNetEndpoint` 设备对象与 `\DosDevices\MsNetEndpoint` 符号链接，在 `VtBootstrapDriver` 派遣函数中按 `DeviceObject != g_control_device` 多路转发 IRP，**不擦除、不隐藏 `Machenike` 驱动内存**。
       * **模式 2 (`MAPCTL_MK_MODE_MANUAL_MAP`，内存映射驱动)**：**不创建符号链接与设备对象**，由 `MAPCTL_IOCTL_LOAD_MACHENIKE` 将 `DRV_BOOT_CONFIG_EX` 直接传入 `Machenike` 的 `DriverEntry` 启动通信服务（TCP/UDP/USB），并抹除 `Machenike` 的 PE 头/`INIT`/`.reloc` 节、施加 W^X 权限且调用 `VtEngine::HideVirtualRange` 隐藏 `Machenike` 驱动内存。
  2. **重复加载防护与逆序安全卸载闭环**:
     - **内核态幂等防重 (`Utils.cpp` & `main.cpp`)**：`Utils::LoadDriver`、`Utils::LoadPayload` 与 `Utils::LoadMachenike` 均内置原子状态检查與 `hc::ping()` 探针；若检测到已加载则直接复用现有基址返回成功，严禁重复分配或二次挂接。
     - **应用层前置探测 (`loader/vt_loader.h` & `loader/main.cpp`)**：`VtLoader::IsAlreadyLoaded` 通过打开 `\\.\MapCtlDrv` 发送 `MAPCTL_IOCTL_STATUS` 校验 `vt_ping_ok && payload_loaded && machenike_loaded`；若已激活且未指定 `--force`，直接跳过驱动重映射并下发最新通信配置；若指定 `--force` 则先执行完整卸载再重新加载。
     - **逆序安全卸载 (`Machenike` -> `VtResidentPayload` -> `VtHypervisor`)**：在 `DriverCore::DriverUnload` 中新增对 `g_SecCtx.fWorkItemQueued` 与 `g_MapleCtx.fWorkItemQueued` 的排空等待（且工作项在函数末尾清零标志），确保无 `ExpWorkerThread` 残留执行后，由 `Utils::UnloadMachenike` 调用 `Machenike` 的 `DriverUnload` 并释放其独立物理页，随后依次卸载 `VtResidentPayload`（还原 `System CR3` 的 `NX` 位并从 `MmPfnDatabase` 恢复被摘除的 PFN）与 `VtHypervisor`（全核 `vmxoff`/`svm_off`）。
     - **加载失败防设备泄漏与孤儿设备免重启接管 (`vt/VtBootstrapDriver/main.cpp` & `loader/vt_loader.h`)**：
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
  17. **嵌入映像身份闭环与 SVM 双页物理地址证据（2026-10-23）**：
     - 现场日志在 `cpu=0` 完成 `VMRUN`/ping 后、`cpu=1 cache-after` 处硬重启，但其 `TestDriver unpack` 尺寸为 `0x7CBF8`，与当前修复源码构建出的 `VtHypervisor.sys` 以及 `testDriver.h` 元数据不一致；该证据说明测试机实际执行的是修复前的旧内嵌 Hypervisor，不能据此否定第 16 条修复。
     - `pack_embedded_vt.py` 必须把输入 `VtHypervisor.sys` 的 SHA-256 写入 `TEST_SYS_SHA256`；`VtBootstrapDriver` 必须在解密、解压和任何 SVM 状态切换前记录该 SHA-256、unpacked size 与 packed size。实机日志中的三项必须与交付目录中的构建产物一致，尺寸或散列不一致时不得进入硬件结论分析。
     - `amd/svm.cpp` 的预分配与首次启动日志必须同时输出 `host_save_pa` 和 `host_vmcb_pa`。两者必须非零、4KB 对齐且互不相等；该日志字段用于直接证明 `MSR_VM_HSAVE_PA` 专页与 `VMSAVE/VMLOAD HostVmcb` 专页已经分离。
     - 回滚路径：恢复 `pack_embedded_vt.py`、`VtBootstrapDriver/main.cpp`、`amd/svm.cpp` 与生成的 `common/testDriver.h`，重新完整构建 `VtBootstrapDriver`。验证必须包含生成头 SHA-256 与输入 `VtHypervisor.sys` SHA-256 相等、Release x64 全量构建通过，以及独立副本回滚后四个文件散列恢复。
  18. **阶段 7 生产启动/停止生命周期与 AMD stop ACK 对齐（2026-10-23）**：
     - 阶段 6 实机证据确认 8/8 个 AMD vCPU 均完成 `VMRUN`、ping、逆序 unload，`started=stopped=0xFF`，且所有 `host_save_pa` 与 `host_vmcb_pa` 非零、页对齐并互不相等；首次多核启动硬重启根因闭环完成。
     - 比较路径 A：直接切换 `YVT_ENTRY_BISECT_BYPASS=0`，同时引入生产生命周期、Hook 初始化、ResidentPayload 和后续业务，若失败无法区分层级。路径 B：新增阶段 7，仅运行生产 `hv::start()`、全局 ping、生产 `hv::stop()` 和资源排空，继续隔离 Hook/ResidentPayload/VMB/后台任务。本轮选择路径 B。
     - AMD `hypercall_unload` 必须在 Host 上下文、`g_ghv` 与 vCPU 数组仍有效时，按 `cpu - g_ghv->vcpus` 设置 `stop_ack_bitmap`；该契约与 VMX `hc::unload()` 对齐。旧 AMD 分支只设置 `should_stop`，Guest continuation 虽成功返回，生产 `hv::stop()` 仍固定观察到 `ack=0` 并拒绝释放运行时。
     - 生产 stop 的每核 unload 必须受 stage=4 跨核 DPC 看门狗保护，并输出 result、launched、ack 以及最终 expected/before/after/ack/exception 位图。只有 `after==ack==expected` 时才释放 vCPU 栈、vCPU 数组和 CR3 map；阶段 7 若检测到任意 vCPU 仍 launched 或生产 stop 失败，则触发 `0xE2000A04`，禁止失败返回后由 Bootstrap 释放仍被 Host 引用的映像。
     - 阶段 7 成功后排空 DPC、调用 `PoolManagerUninitialize()`、清零 `g_ghv` 并返回 `STATUS_NOT_SUPPORTED`，保持本轮只验证生产生命周期。回滚恢复 `base.h`、`main.cpp`、`hv.cpp`、`svm-exit.cpp` 与生成的 `testDriver.h`；实机准出条件为 `start=1 ping=1 stop=1`、`expected=after=ack=cleanup=0xFF`、`exc=0`。
  19. **阶段 8 启动后初始化隔离验证（2026-10-23）**：
     - 阶段 7 实机证据确认生产 `hv::start()`、全局 ping 与生产 `hv::stop()` 在 8/8 个 AMD vCPU 上完整闭环：逐核 unload 返回签名，`expected=before=after=ack=cleanup=0xFF`、`exc=0`，因此生产生命周期契约准出。
     - 比较路径 A：直接恢复普通入口并返回成功，会同时引入 DriverUnload 注册、ResidentPayload、实际 Hook 安装和长期驻留，失败边界过大。路径 B：阶段 8 保留阶段 7 的启动/停止闭环，只在 Hypervisor 活动期间追加普通入口的无 Hook 启动后初始化。本轮选择路径 B。
     - 阶段 8 依序执行 `mouse::init_mouse`、空操作 `epthook::hook_init`、`hv::init_vmcall_handlers` 和 `fake_data` 种子复制；每一步输出 begin/end、状态或结果。该阶段不调用任何 `hook_install`，不启动 ResidentPayload、VMB 或后台任务。
     - `mouse::init_mouse` 的失败状态只作为环境诊断记录，保持与普通入口忽略该返回值的现状一致；Hypervisor 启动失败时跳过全部启动后初始化。`fake_data` 复制继续使用异常保护并显式记录是否成功。
     - `yvt_init_symbols_expanded` 可能建立 WSK 注册；阶段 8 在停止和释放诊断映像前调用 `khttp::shutdown()`，避免网络栈保留指向已释放映像的回调。随后仍必须满足生产 stop 全位图收敛，排空 DPC、释放 PoolManager、清零 `g_ghv` 并返回 `STATUS_NOT_SUPPORTED`。
     - 回滚恢复 `base.h`、`main.cpp`、ADR 和生成的 `testDriver.h`。实机准出条件为 post-start 四个边界日志均完成，并继续满足 `start=1 ping=1 stop=1`、`expected=after=ack=cleanup=0xFF`、`exc=0`。
  20. **阶段 9 成功交接与生产 DriverUnload 往返（2026-10-23）**：
     - 阶段 8 实机证据确认 `mouse::init_mouse` 返回成功且解析到有效 device/callback，`epthook::hook_init`、VMCALL handler 表和 `fake_data` 初始化完成；随后生产 stop 继续满足 `expected=before=after=ack=cleanup=0xFF`、`exc=0`。
     - 比较路径 A：直接恢复普通成功入口，让 Bootstrap 继续加载 ResidentPayload 并进入隐藏/Hook 链，会同时引入长期驻留、跨映像函数指针和卸载依赖。路径 B：TestDriver 首次返回成功并短暂保持 Hypervisor，Bootstrap 立即调用其生产 `DriverUnload`，确认停止后再释放映像；ResidentPayload 继续关闭。本轮选择路径 B。
     - `YVT_ENTRY_BISECT_BYPASS=9` 复用阶段 8 的 start/ping/init，在 `DriverObject` 有效且签名匹配时登记 `Driver_Unload`、清除本地 `KEEP_HV_ON_UNLOAD` 位并返回 `STATUS_SUCCESS`。启动或 ping 失败时不交接，仍走本地 stop/清理和诊断失败返回。
     - Bootstrap 的 `MAPDRIVER_VT_STAGE9_HANDOFF_ROUNDTRIP=1` 分支在 TestDriver 成功后跳过 hide/lock、ResidentPayload、Machenike 和所有后续 Hook。先以 `UnloadDriverEx(FALSE)` 调用卸载回调并保留映像，再以异常保护的 `mapdriver_hv_ready()` 证明 Hypervisor 已停止；确认后才以第二次 `UnloadDriverEx(TRUE)` 擦除并释放映像。
     - 生产 `Driver_Unload` 在 `hv::stop()` 成功后必须先 `KeFlushQueuedDpcs()`，再释放 PoolManager 并清零外部 `g_ghv`。如果 Bootstrap 在卸载回调后仍检测到 Hypervisor 存活，则触发 `0xE2000A05` 并保留隔离映像，禁止释放 Host 仍在执行的代码。
     - 阶段 9 最终仍让 Bootstrap 返回 `STATUS_NOT_SUPPORTED`，但准出证据必须包含 TestDriver `STATUS_SUCCESS` 交接、卸载回调返回、`stopped=1`、最终 `image=null/size=0`，以及生产 stop 的完整位图收敛。
  21. **阶段 10 ResidentPayload 纯生命周期批量验证（2026-10-23）**：
     - 阶段 9 实机证据确认 TestDriver 成功交接后，生产 `DriverUnload` 在 8/8 个 AMD vCPU 上完成 `expected=before=after=ack=0xFF`、`exc=0`，Bootstrap 观察到 `stopped=1` 并在二阶段释放后得到 `image=null/size=0`。该结果准出“短暂保持 VT -> 回调停止 -> 确认后释放映像”的生命周期边界。
     - 比较路径 A：直接恢复完整 resident 路径，同时执行 `set_vmexit_target`、`set_vmexit_bridge_target`、`set_hv_diag`、隐藏、Hook 和 one-key 迁移；该路径一次引入跨映像 VM-exit 指针、Host 栈映射、EPT/NPT 变更及长期驻留，失败边界过大。路径 B：一次批量恢复 ResidentPayload 的解包/RAWPACK 映射、ABI/export 校验、start、ping、status、stop、重复 stop 与映像释放，但显式跳过 VM-exit target/bridge/diag 配置和全部隐藏/Hook；随后复用阶段 9 的 TestDriver/HV 二阶段卸载。本轮选择路径 B。
     - `YVT_ENTRY_BISECT_BYPASS=10` 复用阶段 8 的 start/ping/init 与阶段 9 的成功交接契约；`MAPDRIVER_VT_STAGE10_PAYLOAD_ROUNDTRIP=1` 且 stage9 gate 关闭。`mapdriver_load_resident_payload(false)` 仍验证 payload magic、ABI 85、export 必选函数、nonce/pong 和启动状态，但不把任何 payload 函数写入活动 VM-exit 路径。
     - Bootstrap 首次读取状态必须观察 `PAYLOAD_STATE_STARTED`；显式 `PayloadStop` 后必须观察 `PAYLOAD_RESULT_STOPPED`、`PAYLOAD_STATE_STOPPED=1` 且 `PAYLOAD_STATE_STARTED=0`。随后 `Utils::UnloadPayload()` 再次调用 `PayloadStop` 以验证幂等停止，并仅在回调返回后擦除/释放 payload 映像。
     - Payload 完成后 Hypervisor 必须仍可 ping；Bootstrap 再调用 `UnloadDriverEx(FALSE)` 执行生产 `hv::stop()`，确认 `mapdriver_hv_ready()==false` 后才调用 `UnloadDriverEx(TRUE)` 释放 TestDriver。若回调返回后 Hypervisor 仍活动，触发 `0xE2000A06`，禁止释放 Host 仍引用的映像。
     - 本阶段仍不执行 `mapdriver_apply_testdriver_hide_lock`、Machenike、resident control、后台 worker、VM-exit 切换、内存隐藏和 one-key。实机准出条件为 `payload load=1 started=1 stopped=1 released=1`、第二次 stop 正常返回、`hv_ready=1` 保持到 payload 释放完成、随后 TestDriver `stopped=1`、最终 `payload=null/test=null/test_size=0`，且 SVM stop 位图继续完整收敛。
  22. **Bootstrap 无 HV 探测的 `0x7F/DOUBLE_FAULT` 根因闭环（2026-10-23）**：
     - WinDbg 双机现场确认 BugCheck 为 `0x7F (Arg1=8)`；首个异常位于 `VtBootstrapDriver+0x34EDE` 的 AMD `vmmcall`，发生在 trace cleanup 完成后、TestDriver 解包前的 `mapdriver_hv_ready()`。此时 Hypervisor 尚未启动，`#UD` 属于探测的预期失败，不是 Stage10 Payload 或 VMRUN 故障。
     - 故障线程的栈范围为 `Base=FFFFDC8E789B3000`、`Limit=FFFFDC8E789AC000`，`#UD` 时 `RSP=FFFFDC8E789AD978`，只剩 `0x1978` 字节；SEH 展开进入 `RtlpxVirtualUnwind` 时 `RSP=FFFFDC8E789ABFE0`，越过栈下界 `0x20` 字节，最终把可处理的 `#UD` 放大为双重故障。
     - 比较路径 A：删除启动前 stale-HV 探测，虽可避开本次异常，但会破坏重复加载与残留 Hypervisor 回收契约。路径 B：保留探测语义，将 `hv::ping()` 和 `__try/__except` 移入 `KeExpandKernelStackAndCalloutEx` 的 24 KiB 扩展栈，并在 `IRQL <= APC_LEVEL` 时执行；本轮选择路径 B。
     - `mapdriver_hv_ready()` 不再在调用方剩余栈上直接执行 `VMCALL/VMMCALL`。启动前日志与 stale-HV 分支必须复用同一次初始探测结果，停止后才允许再次探测确认，避免无意义的连续两次 `#UD`。
     - 回滚恢复 `vt/VtBootstrapDriver/main.cpp` 与本 ADR；静态回归必须证明 ping 只存在于扩展栈 callout、callout 内仍有 SEH、早期路径只执行一次初始探测。Release x64 构建通过只证明静态闭环，实机准出仍需观察 `pre-load cleanup done hv_ready=0` 后继续进入 `TestDriver unpack ok`，且不再出现 `0x7F`。
  23. **Stage10 ResidentPayload 映射的 `0x50`/次生 Double Fault 栈耗尽根因闭环（2026-10-23）**：
     - WinDbg 双机现场确认主故障为 `PAGE_FAULT_IN_NONPAGED_AREA (0x50)`，访问地址 `FFFFDC0EA6C08000`，故障指令为 `VtBootstrapDriver+0x31B26` 的 `__chkstk` 页探测 `test byte ptr [r11],r11b`。对应 Trap Frame 中 `RAX=0x2B70`、`RSP=FFFFDC0EA6C0A9D8`、`R10=FFFFDC0EA6C07000`、`R11=FFFFDC0EA6C08000`；线程栈 `Base=FFFFDC0EA6C10000`、`Limit=FFFFDC0EA6C09000`，目标页 PTE 为零。
     - 调用点 `VtBootstrapDriver+0x22D28` 在 `ECX=0` 后进入 `mapdriver_load_resident_payload(false)`；其固定栈帧为 `0x2B70`，外层 `DriverMain` 固定栈帧为 `0x4770`，二者相加已达 `0x72E0`，未计保存寄存器、异常帧及内部调用即超过现场约 `0x7000` 的可用内核栈。异常分发期间再次越界形成的 `0x7F/Arg1=8` 与 `nvlddmkm.sys` 上下文属于次生 Double Fault，不是 GPU 驱动根因。
     - 比较路径 A：仅减少 Stage10 局部变量或删除诊断日志，能够降低当前编译产物的栈帧，但 `_XOR_` 临时字符串、RAWPACK 映射与后续生产路径仍可能随编译布局再次越界。路径 B：将所有 ResidentPayload 映射入口统一放入 `KeExpandKernelStackAndCalloutEx`，并把栈扩展失败视为加载失败；本轮选择路径 B，同时保留后续削减超大固定栈帧的构建门禁任务。
     - `mapdriver_load_resident_payload_expanded()` 只允许在 `PASSIVE_LEVEL` 执行，在 48 KiB 扩展栈中调用实际映射函数；Stage10 与生产 ResidentPayload 路径必须共同使用该包装。扩展 API 返回失败或 callout 未完成时严禁回退到调用方已耗尽的小栈。
     - 当前修复不改变 Payload ABI、启动/停止顺序或 VM-exit 配置语义。回滚恢复 `vt/VtBootstrapDriver/main.cpp`、本 ADR 与决策索引；静态回归必须证明两个 Payload 入口都使用 48 KiB 扩展栈且没有 inline fallback。Release x64 构建成功仅证明静态闭环，实机准出仍需观察 Stage10 出现 `[payload] loading image`、payload lifecycle 完整结果及后续 TestDriver stop 位图收敛。
  24. **Stage10.5 external arena 所有权与释放时序隔离（2026-10-23）**：
     - Stage10 实机完整通过后仍观察到 32 MiB `payloadArena` 被隔离泄漏。原实现把 arena 的释放/清空放在 `Utils::UnloadPayload()` 内，而该时刻 TestDriver/Hypervisor 尚未执行生产 stop；arena 同时承载外部 `g_ghv`、vCPU 与 VT hook 等状态，因此在此处调用 `MmFreeIndependentPages` 会释放仍被活动 vCPU 引用的页，历史 `PFN_LIST_CORRUPT` 不能证明分配器错误。
     - 比较路径 A：直接打开 `MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD`，继续在 Payload 卸载阶段释放，测试成本低但违反跨组件所有权顺序。路径 B：Payload 卸载只停止 worker、释放 payload 自有 direct allocations 和映像；arena 身份一直保留到 `PayloadStop -> PayloadUnload -> hv::stop 全核 ACK -> TestDriver 映像释放` 完成后，再进入单独的 arena disposition。本轮选择路径 B。
     - `MAPDRIVER_VT_STAGE10_5_ARENA_OWNERSHIP_AUDIT=1`、Stage10 gate 关闭。审计必须验证 payload stop 后 `external_ref_flags=NONE`、`direct_alloc=0`、`owned_alloc_count/bytes=0`、payload 状态中的 arena 与 Bootstrap 捕获的 base/size 一致；并在 payload unload 前后及 HV stop 后验证 arena 首尾页有效、物理地址非零且身份不变。
     - `Utils::UnloadPayload()` 严禁释放或清空 arena；`Utils::FreePayloadArena()` 是唯一 disposition 入口，只能由已确认 Hypervisor 停止的调用方触发。当前 `MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD=0` 保持 quarantine 基线，先验证所有权边界；后续独立实机阶段才允许打开实际 free gate。
     - 回滚恢复 `base.h`、`Utils.cpp`、`main.cpp`、本 ADR 与索引。静态准出包括 Release x64 构建通过和独立副本反向补丁恢复；实机准出必须观察三个 arena audit 均 `ok=1`、payload `quiesced=1`、全核 stop 位图完整且 `stage10.5 batch complete=1`。构建成功不等同于实际 `MmFreeIndependentPages` 已验证。
  25. **Stage10.5 尾部 trace cleanup 的 `0x7F/DOUBLE_FAULT` 栈耗尽闭环（2026-10-23）**：
     - 双机 WinDbg 现场显示 BugCheck `0x7F (Arg1=8)`；外层 trap 的 `RSP` 精确等于线程 `StackLimit`，下一个栈页 PTE 为空。内层 trap 位于 `nt!DebugPrint -> nt!DbgPrintEx -> trace::clear_wdfilter_runtime_drivers`，说明 `kdcom!WaitForRxPacket` 只是发送最后一条调试日志时耗尽剩余栈，并非 KDNET 根因。
     - Stage10.5 在崩溃前已经报告 payload quiesced、三次 arena audit 成功、全核 stop ACK 完整及 `batch complete=1`，因此 arena 生命周期和 Hypervisor stop 不属于本次故障链。当前 `DriverMain` 固定栈帧约 `0x4870`，再叠加 `mapdriver_clear_traces`、WdFilter helper 与 DbgPrint/KD 调用链后超过约 `0x7000` 的普通内核栈预算。
     - 比较路径 A：只把最终 `mapdriver_clear_traces` 放入 callout 或禁用 WdFilter 日志，能规避已观察点，但其他早退/清理分支仍从同一超大 `DriverMain` 栈帧调用深层例程。路径 B：保留现有功能与顺序，把完整 DriverMain 实现移入 48 KiB `KeExpandKernelStackAndCalloutEx` callout，导出入口只保留小上下文和返回值。本轮选择路径 B。
     - 扩展栈只允许在 `PASSIVE_LEVEL` 进入；扩展失败直接返回失败状态，严禁回退到原始 loader 栈。实现体使用 `__declspec(noinline)` 保持 wrapper 的小栈边界，所有早退、Stage10.5 诊断、最终 trace cleanup 和 `DriverMain leave` 日志均在扩展栈内完成。
     - 回滚恢复 `vt/VtBootstrapDriver/main.cpp`、本 ADR 与索引。静态准出必须证明导出 `DriverMain` 仅调用扩展栈 callout、实现体 noinline、无 inline fallback；Release x64 构建与签名成功不等同实机准出。实机应观察到 `trace::clear_wdfilter` 后继续出现 `DriverMain leave final_status=0xC00000BB`，且不再触发 `0x7F`。
  26. **Stage10.6 external arena 实际释放验证（2026-10-23）**：
     - Stage10.5 实机日志已经证明 payload stop 后 `external_ref=0`、`direct_alloc=0`、`owned_alloc_count/bytes=0`，三次 arena audit 均 `ok=1`，8 个 vCPU 的 stop 位图满足 `expected=before=after=ack=0xFF` 且 `exc=0`；扩展栈修复后最终 trace cleanup 与 `DriverMain leave` 也已正常返回。
     - 比较路径 A：继续 quarantine，稳定但无法验证 32 MiB `MmAllocateIndependentPages` arena 的真实释放契约。路径 B：保持完全相同的隔离流程，只在 `PayloadStop -> PayloadUnload -> hv::stop 全核 ACK -> TestDriver 映像释放` 后打开既有 `MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD`，调用唯一的 `Utils::FreePayloadArena()`。本轮选择路径 B。
     - `MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD=1` 时诊断名改为 `stage10.6`；释放前输出 arena disposition 边界，`FreePayloadArena` 仅允许在 `PASSIVE_LEVEL` 且 `MmFreeIndependentPages` 已解析时执行，随后将 `payloadArenaBase=nullptr`、`payloadArenaSize=0`。不改变 Payload ABI、Hypervisor stop、TestDriver 二阶段释放或 trace cleanup 顺序。
     - 实机准出必须同时观察三个 pre-free audit 为 `ok=1`、完整 stop ACK、`payload arena freed after payload/HV quiesce`、最终 `stage10.6 batch complete=1 ... arena=0/0 disposition=1` 以及 `DriverMain leave final_status=0xC00000BB`；若 `MmFreeIndependentPages` 内触发 BugCheck，则保留转储并以释放前最后一条边界日志作为取证锚点。
     - 回滚恢复 `base.h`、`main.cpp`、本 ADR 与索引，重新关闭实际 free gate 并恢复 stage10.5 quarantine 行为；Release x64 构建、签名和静态顺序检查仅证明可部署，不代替实机释放验证。
  27. **Stage11 VM-exit target/bridge/diag 配置往返（2026-10-23）**：
     - Stage10.6 实机已经完成 payload 引用归零、Hypervisor 全核停止、TestDriver 映像释放和 32 MiB external arena 的 `MmFreeIndependentPages`，最终得到 `arena=0/0 disposition=1` 与正常 `DriverMain leave`，因此生命周期和实际释放边界准出。
     - 比较路径 A：直接恢复完整 one-key 流程，会同时切换 HOST_RIP/HOST_RSP、安装 Hook、隐藏内存并引入长期驻留，失败边界过大。路径 B：只恢复 `set_vmexit_target`、`set_vmexit_bridge_target` 与 `set_hv_diag` 的配置和状态核验，不执行任何 Host RIP/RSP 切换、Hook、hide、Machenike 或 one-key。本轮选择路径 B。
     - `MAPDRIVER_VT_STAGE11_VMEXIT_CONFIG_ROUNDTRIP=1`，Stage10.5 gate 关闭；ResidentPayload 仍通过 48 KiB expanded-stack mapper 加载，但 `configure_vmexit=true`。配置后重新获取 Hypervisor diag，并要求 payload status 中 trampoline/bridge 非零、target 精确等于 `diag.vm_exit`、bridge target 精确等于 `diag.handle_vm_exit`、`hv_diag_cache_ready!=0`。
     - 本阶段只缓存跨映像目标，不把 Hypervisor 的活动 HOST_RIP 指向 payload；因此停止顺序仍为 `PayloadStop -> PayloadUnload -> hv::stop -> TestDriver free -> arena free`。`PayloadStop` 后继续要求 external refs、direct allocations 和 owned allocations 全部归零，防止配置缓存掩盖真正的在途引用。
     - 实机准出必须观察 `VT stage11 vmexit config ok=1`，payload lifecycle 中 `vmexit_cfg=1`，三个 arena audit 成功、全核 stop ACK 完整、arena 实际释放、`stage11 batch complete=1` 与最终 `DriverMain leave final_status=0xC00000BB`。回滚恢复 Stage10.6 配置和原始 SHA-256；构建与静态检查不代替实机 VM-exit 配置验证。
## Stage12：EPT-only Hook 与完整隐藏合并验证（2026-10-23）

- Stage11 的 VM-exit target/bridge/diag 往返已经通过实机验证，后续不再逐项拆分 DWM、Hook、隐藏和迁移阶段。
- Stage12 直接启用同步 one-key 迁移链：legacy detach、HOST_RSP、HOST bridge、cutover、TestDriver 释放、payload image/direct/host-stack/resident-pools/full-arena 隐藏。
- Hook 契约固定为 `hook_mode=OBSERVE`、`ept_mode=HANDLE_TRAMP`；DWM 初始化与 Present/GetBuffer 路径由 `YVT_DWM_HOOK_ENABLED=0` 明确关闭。
- 隐藏完成后必须自动执行 `MAPCTL_MEMCHECK_FLAG_ALL`，仅当所有已检查页面均为 hidden，且 visible/unknown/translate_fail/verify_fail 全部为 0 时 Stage12 才成功。
- `MAPDRIVER_AUTO_LOAD_MACHENIKE_ON_BOOT=0`；Machenike 保留为 Stage12 通过后的唯一最终集成测试，避免与 EPT/隐藏首轮合并验证混杂。
- 验证构建保留 mapDriver 控制设备，供 status/memcheck 和失败定位使用；Machenike 最终阶段再决定是否关闭控制面。
- 首次 Stage12 实机日志证明源码门禁没有生效：`VtBootstrapDriver.vcxproj` 通过命令行 `/D MAPDRIVER_AUTO_ONEKEY_LOAD=0` 覆盖了 `base.h` 的默认值，因此日志在 payload load 后直接返回，且 loader 随后发送 `MAPCTL_IOCTL_LOAD_MACHENIKE`。修复后工程默认属性 `MapDriverAutoOneKey=1`，并由 loader 的 `VT_STAGE12_SKIP_MACHENIKE=1` 分支只执行 `EnsureVtOneKeyActive`，不再发送 Machenike IOCTL。
- 第二次 Stage12 AMD 实机日志确认 `diag.flags=2` 且 `vmcs_host_rip=0`：SVM 的 `#VMEXIT` 从 `VMRUN` 后固定汇编循环恢复，不存在 Intel VMCS `HOST_RIP` 字段。one-key 预切换等待遇到该组合必须立即记录 `backend=AMD-SVM reason=no-host-rip` 并终止，禁止把零值当作瞬态条件反复等待，更禁止调用 Intel `hypercall_set_host_rip` 路径。AMD 活动入口迁移须另行设计并验证软件分发 ABI 后方可启用。

## Stage13：AMD 固定 VMRUN 兼容准出与 Machenike 最终集成（2026-10-23）

- 比较路径 A：把 AMD `svm_vmrun_enter` 循环整体迁入 ResidentPayload，再释放 `VtHypervisor.sys`。该路径必须重新证明 Host GDTR/IDTR、HSAVE、展开信息、全核切换和部分失败回滚，当前变更面过大。路径 B：AMD 保留已验证的固定 VMRUN 循环及其所属 `VtHypervisor` 映像，只把 Payload/HV 配置往返、EPT 模式、ping、smoke 和 Machenike 加载作为最终准出门禁；Intel 仍执行原 HOST_RIP/HOST_RSP resident bridge。本轮选择路径 B。
- `mapdriver_onekey_execute` 在 AMD `diag.flags & 2` 且 `vmcs_host_rip==0` 时不再把硬件语义差异映射成 `STATUS_DEVICE_NOT_READY`。它要求 payload barrier、完整 HV diag、8/实际 vCPU 数对应的 host-stack descriptor、VM-exit target/bridge 精确往返、HV ping 及 `hook_mode=OBSERVE`、`ept_mode=HANDLE_TRAMP` 全部成功后返回兼容准出；AMD 路径不得执行 Intel HOST_RIP hypercall，也不得释放承载固定 VMRUN 循环的 `VtHypervisor` 映像。
- loader 关闭 `VT_STAGE12_SKIP_MACHENIKE`。在发送 `MAPCTL_IOCTL_LOAD_MACHENIKE` 前，`ValidateRuntimeForMachenike` 必须通过 status、HV/Payload 双 ping、migration/AMD 固定循环契约和 smoke；加载后 `ValidateMachenikeLoaded` 必须核验 mode、base、size 与 `machenike_loaded`。任一门禁失败即停止后续集成。
- VT 目录与工程统一为生成物同名：`vt/VtHypervisor/VtHypervisor.vcxproj`、`vt/VtResidentPayload/VtResidentPayload.vcxproj`、`vt/VtBootstrapDriver/VtBootstrapDriver.vcxproj`；独立解决方案更名为 `VtHypervisor.sln`，并移除其中失效的 `mapDriver/newdriver` 项目项。所有 ProjectReference、include、打包输出和主解决方案路径同步更新。
- 回滚通过 `artifacts/vt-finalize-20261023/ROLLBACK.sh` 从原始快照恢复。静态准出要求重命名后 `Machenike.sln Release|x64` 完整构建成功、三个 SYS 生成物与 loader 存在、旧目录/旧工程引用为零、独立副本执行回滚后原始路径与 SHA-256 全部恢复。实机准出仍以最终日志中的 `onekey AMD resident validation ok=1`、`Final runtime validation: ok=1`、`Machenike validation: ok=1` 及目标传输握手成功为准。


## Stage14：Bootstrap 唯一部署路径与离线回归（2026-10-23）

- 新实机日志仍记录旧嵌入身份 `B49D...` 并走到 `onekey pre-switch blocked`，而当前构建产物内嵌身份已经为 `2461...`，证明执行的是旧部署副本而不是当前 `bin/vt/VtBootstrapDriver.sys`。
- 比较路径 A：继续把同一 SYS 复制到 `bin/VtBootstrapDriver.sys`、`bin/mapDriver.sys` 与 `bin/vt/VtBootstrapDriver.sys`，由时间戳或名称猜测；并行构建或单项目重建后副本可能漂移。路径 B：loader 固定优先选择 MSBuild 唯一输出 `bin/vt/VtBootstrapDriver.sys`，根目录副本只作兼容回退，构建完成后删除两个旧别名。本轮选择路径 B。
- `SelectBootstrapDriverPath` 必须先检查 `vt\\VtBootstrapDriver.sys`，只有该文件缺失时才回退同名根目录副本，且继续拒绝仅有 `mapDriver.sys` 的部署。`--vt-cmd load` 必须检查选择结果，禁止把缺失路径继续传入 SCM。
- `VtBootstrapDriver.vcxproj` 不再生成根目录 `VtBootstrapDriver.sys` 或 `mapDriver.sys`，并在 Release|x64 Build 后清理遗留别名。静态验证必须证明唯一输出存在、loader 的选择顺序正确、旧别名消失、嵌入的 Hypervisor/Payload/Machenike 哈希与最终 SYS 一致。
- 用户要求后续不在本机加载测试；本阶段只执行编译、静态检查、生成物一致性和独立副本回滚。此前已启动的测试实例先通过 `full_unload` 停止并移除服务，随后不再调用 load/onekey 或 Machenike IOCTL。

## Stage15：AMD Machenike Payload Ping 非法指令闭环（2026-10-23）

- KDNET 现场确认当前并非已落地 BugCheck，而是 `loader.exe` 发起 `MAPCTL_IOCTL_LOAD_MACHENIKE (0x2222EC)` 后，手动映射的 `mswsk.sys` 在 `VtEngine::Initialize -> PingPayload -> RawHypercall` 执行 `VMMCALL` 时收到第二次机会 `0xC000001D`。现场 `RAX=0x000885544668855D` 精确对应合法 key 与 `hypercall_payload_ping=93`，`RCX=0x1337C0DE55AA1234` 对应 Machenike 固定探测 nonce。
- 比较路径 A：在 AMD legacy handler 中直接伪造 `nonce ^ PAYLOAD_PONG_MAGIC`，可让 Machenike 把 payload 标记为 resident，但 Hypervisor 没有可验证的 payload 生命周期状态，可能在 payload 不存在时误报成功。路径 B：与 VMX legacy handler 保持一致，对 `get_payload_status/set_payload_mode/payload_ping` 返回 `RAX=0` 并推进 Guest RIP，使 Machenike 保留 `HvPing=1`、`ResidentPayload=0` 的可降级状态。本轮选择路径 B。
- `amd/svm-exit.cpp::emulate_vmmcall` 必须显式消费三个 payload-owned hypercall，禁止落入默认 `inject_exception(amd64_invalid_opcode)`。其他未知合法代码仍保持 `#UD`，非法 key 的 CPL0/CPL3 行为不变。
- 手动映射 Machenike 未注册运行时函数表，WinDbg 对 `RawHypercall` 与 `PingPayload` 地址均报告 `No function entry`；因此不能依赖映像内 `__try/__except` 跨越异常。主修复必须在 VMEXIT 边界消除预期的 `#UD`，而不是扩大 SEH 或吞掉未知异常。
- 静态准出包括：三个 payload-owned case 连续 fail-closed、公共尾部写回 `VMCB.RAX` 并 `advance_guest_ip(v, 3)`、Release x64 构建成功、生成物重新打包，以及独立副本回滚恢复原始 SHA-256。遵循用户要求，本阶段不执行本机驱动加载、`onekey` 或 Machenike IOCTL；实机准出仍需后续目标机观察 Machenike 初始化越过 `PingPayload` 并完成最终验证。
