# ADR-0051: VT/SVM 硬件虚拟化框架全量集成与编译期宏开关治理规范

- **状态**: 已采纳
- **日期**: 2026-10-22
- **上下文与痛点**:
  1. 在反作弊（如 ACE / Vanguard / EAC）高强度内核页表与物理内存审计场景下，传统 Guest Ring 0 的 System PTE 重映射虽具备高性能，但仍处于 Guest OS 层级。
  2. 项目已有完整打磨的 Intel VT-x / AMD SVM 硬件虚拟化与常驻载荷工程（`vtcall-driver-main`、`vt-call-pyaload-main`、`vt-call-mapdriver-main`），具备全核 EPT/NPT 隐藏（`hide_physical_page` / `hide_pfn_list`）、Host 映射直拷贝物理/虚拟内存读写（`read_phys_mem` / `write_phys_mem` / `read_virt_mem` / `write_virt_mem`）、`System CR3` 页表 `NX=1` 伪装（`PTE_SEAL`）、`CallUser` / `CallKernel` 合法栈回溯返回桩、TSC 时序补偿以及 0~95 号完整 Hypercall 协议。
  3. 需要将上述三大 VT 子项目 **100% 零遗漏迁移** 至 `CheatDrv` 主仓库，在驱动端（`CheatDrv`）与加载器端（`loader`）实现无缝集成，并提供统一的编译期总开关宏 `ENABLE_VT_FRAMEWORK` 与运行期标志 `DRV_BOOT_FLAG_ENABLE_VT`，确保开启时优先走 VMX Root 硬件虚拟化快路径，未安装或关闭时 100% 自动平滑降级至原生 System PTE 引擎。

- **技术决策与规范**:
  1. **工程源码与构建体系 100% 迁移**:
     - 将 `vtcall-driver-main`（Hypervisor 核心 `hv.lib` + `TestDriver`）、`vt-call-pyaload-main`（常驻载荷 `payloadRuntime.sys`）与 `vt-call-mapdriver-main`（控制与映射驱动 `mapDriver.sys`）全量迁移至 `CheatDrv/vt/` 目录，并统一注册进 `Machenike.sln`。
     - 预编译与构建产物 `mapDriver.sys`、`payloadRuntime.sys` 统一同步至 `CheatDrv/bin/`。
  2. **双端统一编译期宏开关与启动标志契约**:
     - 在 `Core/Common.h` 与 `loader/loader_common.h` 同步引入 `#define ENABLE_VT_FRAMEWORK 1`（及别名 `MK_ENABLE_VT_FRAMEWORK`）。
     - 在不改变 `DRV_BOOT_CONFIG` 结构体字节大小（保持 120 字节对齐契约）的前提下，复用 `Flags` 字段新增位掩码 `#define DRV_BOOT_FLAG_ENABLE_VT 0x00000002`。
  3. **驱动端纯静态类 `VtEngine` (`Stealth/VtEngine.h` & `Stealth/VtEngine.cpp`)**:
     - 严格遵循 `ADR-0030`（纯静态类，0 虚函数，0 vtable）与 `ADR-0034`（Zero IAT）。
     - 采用 `.text` 代码节原生可执行静态机器码数组 `s_VmCallStub` 实现 `[rsp+28h..40h] -> r10/r11/r12 + vmcall` 的 6 参数寄存器传参约定，通过 `CR4.VMXE (bit 13)` 硬件预检与 `__try / __except` 守护避免无 VT 环境触发 `#UD`。
     - 100% 迁移 `0..95` 号全部 Hypercall 原语，包括 `PingHv`、`PingPayload`、`GetPayloadStatus`、`GetResidentHvDiag`、`SetPayloadMode`、物理/虚拟内存读写、进程 CR3 查询、EPT 物理页单页/批量隐藏与恢复、`System CR3` `PTE_SEAL`、EPT Hook (`Eh*`)、VMCALL Hook (`Vh*`)、MMR 监控及 `DbgDispatch` 全子命令。
     - **内存引擎快路径融合 (`Memory/LeechCoreEngine.cpp`)**：在 `LcPte_ReadPhysical`、`LcPte_WritePhysical` 与 `LcFast_CopyProcessMemory` 中接入 `VtEngine` 快路径，当 `VtEngine::IsActive()` 为真且单次跨度 `<= 4096` 字节时直接通过 Host 页表直读直写，失败或未启用时零损耗自动回退至 `LcPte_CopyPhysical`。
     - **生命周期与 PE 头无模块页隐藏 (`Core/DriverCore.cpp`)**：在 `DriverCore::Initialize` 中激活 `VtEngine`，对手动映射擦除后的 PE 头物理页自动执行 `VtEngine::HideVirtualRange` 全核 EPT 替换为 `dummy_pfn`；在 `DriverCore::DriverUnload` 中成对调用 `VtEngine::Cleanup` 还原全部自隐藏物理页。
  4. **加载器端纯静态类 `VtLoader` (`loader/vt_loader.h` & `loader/main.cpp`)**:
     - 100% 迁入原 `mapctl.exe` 的 27 项 `MAPCTL_IOCTL_*` 结构体契约、SCM 服务自动装配与一键式 `EnsureVtOneKeyActive`（`onekey` / `onekey_dropctl`）、`FullUnloadVt` 及全指令 CLI 分发器 `RunCliCommand`。
     - `loader.exe` 默认在 `ENABLE_VT_FRAMEWORK=1` 时自动引导常驻 VT Hypervisor 与 `payloadRuntime.sys`，同时支持命令行 `--vt`、`--no-vt` 与 `--vt-cmd <cmd>` 独立运维指令。

- **已知约束与避坑**:
  1. **严禁对仍在 Guest Ring 0 直接执行的驱动活跃代码页（`.text`）或栈/数据页（`.data`）盲目调用 `HidePhysicalPage` 或置位 `System CR3` `NX=1`**：
     - `HidePhysicalPage` 会将全核 EPT 叶子 PFN 替换为全零 `dummy_pfn`，僅适用于完全驻留在 Host 页表执行或已擦除不再访问的页面（如 ManualMap 擦除后的 PE 头部页 `[kernBase, kernBase + PAGE_SIZE)`）。若对 Guest Ring 0 正在执行的 `CheatDrv` `.text` 页直接替换 EPT PFN 为全零或置 `System CR3` `NX=1`，会导致 Guest 自身取指变成 `00 00` 或触发 `#PF (Instruction Fetch)` 蓝屏。
  2. **无 VT 环境防 `#UD (0xC000001D)` 铁律**：
     - 发起任何 `vmcall` 前必须校验 `__readcr4() & (1ULL << 13)` 或包裹在 `__try / __except` 中，确保在未开启 VT 或 AMD 环境下平滑降级至 System PTE 引擎而不发生崩溃。
