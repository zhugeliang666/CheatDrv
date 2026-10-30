# ADR-0156: 游戏进程存活计时 (Delta Time)、DWM 截图链路与硬件 VT 状态只读监控规范

- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**:
  1. 在反作弊对抗与遥测诊断中，需要明确每次告警触发时距离目标游戏进程（`DeltaForceClient-Win64-Shipping.exe`）开启已运行时长，并在进程退出时自动清空计时；同时不应对常规 ACE 模块加载做冗余上报。
  2. ACE 具备通过用户态 `dwm.exe` 内部组件（`dwmcore.dll`、`dxgi.dll`、`d3d11.dll`、`udwm.dll`、`win32u.dll`）或内核图形栈（`dxgkrnl.sys`、`\Driver\dxgkrnl`）挂接合成/Present 管线实现反 Overlay 截图取证的能力，传统仅针对 `ntoskrnl.exe` 的监控存在盲区。
  3. 需要实时感知目标机器与 ACE 是否开启或动态切换了 CPU 硬件虚拟化（Intel VT-x `CR4.VMXE`、AMD-V `EFER.SVME`/`VM_HSAVE_PA`、`CPUID` Hypervisor 叶及 `ACE_ADVT.sys`）。
- **技术决策与规范**:
  1. **游戏进程存活计时与自动 `[dt=%llu小时%02u分%02u秒]` 注入 (`Core/Common.h`, `Core/DriverCore.cpp`, `Diagnostics/ExceptionReporter.cpp`)**：
      - 全局维护 `volatile LONGLONG g_GameProcessStartTime` 与静态 `s_CachedGamePid`。
      - 在常驻工作项 `SecurityWorkerRoutine`（2s 周期，`PASSIVE_LEVEL`）中调用 `UpdateGameProcessStartTime`：通过 `s_CachedGamePid` 执行 `O(1)` 快路径存活校验（`PsGetProcessExitStatus == STATUS_PENDING` 且 `_EPROCESS.ImageFileName` 前 14 字节匹配 `"DeltaForceClie"`）；检测到进程开启时记录 `KeQuerySystemTime`，检测到进程退出时立即清空 `s_CachedGamePid` 并将 `g_GameProcessStartTime` 归零。
      - `ExceptionReporter::Report` 在计算完去重指纹后（`ComputeReportFingerprint` 自动剥离 `[dt=` 后缀确保 60s 冷却去重不受动态时长干扰），用当前系统时间戳减去 `g_GameProcessStartTime`，格式化追加 `[dt=%llu小时%02u分%02u秒]`。
  2. **硬件虚拟化 (VT / Hypervisor) 状态监控 (`ApiMonitor::CheckHardwareVtState`)**：
      - 10s 周期只读采集 `CR4.VMXE`、`MSR_EFER.SVME` (`0xC0000080`)、`MSR_VM_HSAVE_PA` (`0xC0010117`)、`CPUID(1).ECX[31]`、`CPUID(0x40000000)` 12 字节厂商签名及 `g_AceModules` 中的 `ACE_ADVT` 模块，当状态掩码变化或 ACE 激活期间存在 VT 时去重上报 `ApiMonitor::HardwareVtState`。
  3. **DWM 截图 Hook 双栈只读监控 (`ApiMonitor::CheckDwmAndGraphicsHooks`)**：
      - **R0 内核图形栈**：监控 `dxgkrnl.sys` 6 个核心导出函数（`DxgkPresent`/`DxgkOutputDuplPresent` 等）入口跳板与 32B Adler32 基线、`dxgkrnl.sys` IAT 以及 `\Driver\dxgkrnl` 的 `MajorFunction`/`AttachedDevice`。
      - **R3 `dwm.exe` 进程空间**：在 `PASSIVE_LEVEL` 下通过 `PsAcquireProcessExitSynchronization` + 动态解析的 `MmCopyVirtualMemory` 与 `PsGetProcessPeb`（零 `KeStackAttachProcess`）遍历 `PEB->Ldr->InLoadOrderModuleList`，检测可疑注入模块，并对 `dwmcore.dll`、`dxgi.dll`、`d3d11.dll`、`udwm.dll`、`win32u.dll` 的 IAT、导出表入口以及 `.text` 节前 64 页（256KB）执行 4KB 页级 Adler32 基线比对与基于 `.pdata`（`IMAGE_DIRECTORY_ENTRY_EXCEPTION`）真实函数入口 `BeginAddress` 游标的跨模块 Trampoline 扫描，并通过 `IsMappedDwmTrampoline` 校验跳板目标页可读性。
- **已知约束与避坑**:
  - 严禁在扫描 `dwm.exe` 用户态内存时使用 `KeStackAttachProcess` 后裸指针解引用；必须全程通过 `PsAcquireProcessExitSynchronization` + `MmCopyVirtualMemory` 安全拷贝读取，杜绝因页面换出或进程退出竞态引发蓝屏。
  - **严禁在 `.text` 节按固定 `off += 16` 步长盲扫单字节 `0xE9` 跳转**：函数体内部指令的立即数/位移尾字节落在 16 字节对齐边界且恰好为 `0xE9` 时（如 `E9 48 8B DA 48`、`E9 F3 0F 5C E0`），会将后续正常指令误解析为 `disp32` 引发 100% 误报；必须严格基于 PE `.pdata` 异常目录表（`BeginAddress`）定位真实函数入口并验证 `candTarget` 为已映射可读跳板页。
  - `ComputeReportFingerprint` 必须在遇到 `[dt=` 时停止哈希计算，防止动态递增的运行时长击穿 `s_DedupTable` 冷却去重表。
