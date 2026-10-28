# ADR-0036: ZwMapViewOfSection 动态接入与 28 项高危敏感函数四维只读 Hook 监控引擎

- **状态**: 已采纳
- **日期**: 2026-10-18
- **上下文与痛点**:
  1. 驱动需要新增 `ZwMapViewOfSection`（及配对 `ZwUnmapViewOfSection`）动态解析支持，同时此前散落在 `LeechCoreEngine.cpp` 与 `DriverCore.cpp` 内部的局部函数指针（`MmAllocateMappingAddress`、`MmFreeMappingAddress`、`PsLookupProcessByProcessId`、`ZwOpenProcess`、`ZwTerminateProcess`）尚未统一收敛至 `MACHENIKE_PFN`。
  2. 主流内核反作弊（ACE `sguard64.sys`/`ace-base.sys`、Vanguard、EAC）会对物理内存映射、对象句柄打开、网络/IRP 派发、线程/工作项调度及系统信息查询等**核心敏感内核函数**实施 EAT 篡改、Inline Hook（含 `FF 25`、`48 B8 ... FF E0`、ROP `push+ret`、深层偏移 Patch 及 `CC`/`0F 0B` 异常断点）、SSDT `Nt*` 派遣表替换或底层系统驱动（`netio.sys`、`tcpip.sys`、`ndis.sys`、`usbxhci.sys`、`usbhub3.sys`）IAT 劫持。若盲目监控全部 88 个基础/CRT 函数不仅会产生性能损耗，还存在无关告警噪音。
- **技术决策与规范**:
  1. **Zero-IAT 动态函数收敛**：
     - 基于项目原生乘法哈希（`Utils::HashStringA`，因子 `0x1003f` 小写归一化）新增 `str_ZwMapViewOfSection (0xDE252B2A)` 与 `str_ZwUnmapViewOfSection (0x6E5975E3)`；
     - 将 `ZwMapViewOfSection`、`ZwUnmapViewOfSection`、`MmAllocateMappingAddress`、`MmFreeMappingAddress`、`PsLookupProcessByProcessId`、`ZwOpenProcess`、`ZwTerminateProcess` 统一纳入 `MACHENIKE_PFN` 并在 `MachenikeUserVarInit` 中一次性动态解析，彻底消除局部重复解析代码。
  2. **28 项高危敏感函数精选监控矩阵（`Stealth/ApiMonitor.h` & `Stealth/ApiMonitor.cpp`）**：
     - 剥离 60 个零风险纯计算/锁/自旋/BCrypt 函数，仅聚焦反作弊真正在内核下钩的 **28 个核心高危敏感函数**（5 个物理/虚拟内存映射、5 个进程/对象打开与枚举、6 个设备栈与 IRP 派发、3 个线程/工作项/系统查询、5 个内核文件/设备 I/O、4 个 `netio.sys` WSK 网络通信函数）。
  3. **四维 100% 只读 Hook 监控闭环**：
     - **维度 1（EAT 导出表篡改监控）**：重走 `ntoskrnl.exe` / `netio.sys` PE EAT 实时解析并与 `UserVar->Func` 缓存地址及导出所在模块区间 `[ModBase, ModEnd)` 比对；
     - **维度 2（函数首部 32B 深度 Inline Hook 与 Adler32 基线校验）**：扫描前 16 字节特征跳板（`E9`/`E8`、`FF 25`、`48 B8`/`49 BB` 寄存器跳、ROP `68 ... C3`、`EB` 短跳及 `CC`/`CD 03`/`0F 0B` 硬件/异常挂钩）并与初始化时的 32B Adler32 哈希基线比对；
     - **维度 3（SSDT `Zw* -> Nt*` 双端穿透校验）**：针对 7 个高危 `Zw*` 函数提取 SSN，结合 `__readmsr(0xC0000082)` (`IA32_LSTAR`) 定位 `KeServiceDescriptorTable` 还原真实 `Nt*` 内核实现地址，同步验证其模块归属与前 16 字节 Inline Hook；
     - **维度 4（5 大核心通信/USB 系统驱动 IAT 靶向巡检）**：仅针对 `netio.sys`、`tcpip.sys`、`ndis.sys`、`usbxhci.sys`、`usbhub3.sys` 的导入表（IAT）核验上述高危函数槽位是否被篡改指向 `ntoskrnl.exe` / `hal.dll` / `netio.sys` 以外。
  4. **单次位图去重与 10s 周期调度**：
     - 挂载于 `ExecuteDeepSecurityScans`（每 10 秒在 `PASSIVE_LEVEL` 执行一次），通过 `s_ReportedEatMask`、`s_ReportedInlineMask`、`s_ReportedPatchMask`、`s_ReportedSsdtMask`、`s_ReportedIatDrvMask` 原子位图实现单次告警上报（`ExceptionReporter::ReportExceptionAsync`），并在 ACE 卸载时通过 `ApiMonitor::ResetReportState()` 同步复位。
- **已知约束与避坑**:
  1. **严禁扫描 `INIT` 一次性节区**：内核驱动的 `INIT` 节区在启动后即被系统回收释放（Non-resident），遍历模块或扫描 `KiSystemCall64` 时必须限定在常驻 `.text` / `PAGE` 节区并校验 `MmIsAddressValid`，否则必触发 `BugCheck 0x50` (`PAGE_FAULT_IN_NONPAGED_AREA`)。
  2. **100% 只读铁律**：检测到任何 EAT/IAT/SSDT/Inline Hook 仅允许采集目标模块归属并异步上报，严禁尝试在内核中强写恢复 `ntoskrnl.exe` 或系统驱动只读页，防止触发 PatchGuard (`0x109`) 或 HVCI (`0xBE`) 蓝屏。
