# ADR-0017: 驱动体系化伪装、原生 WSK 符号链接契约与特征脱节消除

- **状态**: 已采纳
- **日期**: 2026-10-15
- **上下文与痛点**:
  1. **“内外脱节”的严重特征暴露面**：
     - 在正常服务加载模式（`driver_mode == 1`）下，宿主端将驱动落地为 `drv_wsk.sys`（Winsock Kernel 网络子系统原生驱动名称），注册的 SCM 服务名为 `drv_wsk`；
     - 但在内核驱动内部与通信激活端，仍使用历史遗留名称 `\Device\MachenikeIo` 和 `\DosDevices\MachenikeIo`（应用层 `\\.\MachenikeIo`）；
     - 反作弊系统（ACE / Vanguard / EAC / BE）在遍历 `\Device` 与 `\GLOBAL??` 对象目录时，极易识破“服务叫网络驱动 `drv_wsk`，内核挂接设备却叫 `MachenikeIo`”的白加黑不匹配特征，导致直接被特征库拉黑；
  2. **冗余白驱动依赖清除**：
     - 宿主加载器中仍残留 `ComputerZ_x64.sys` 辅助驱动的变量与磁盘释放代码，增大了不必要的文件落地风险。

- **技术决策与规范**:
  1. **统一原生 WSK 命名体系 (Winsock Kernel Subsystem Disguise)**：
     - **磁盘驱动文件名**: `System32\drivers\mswsk.sys`；
     - **SCM 服务注册名**: `mswsk`；
     - **内核设备对象名 (`\Device`)**: `L"\\Device\\MsNetEndpoint"`；
     - **系统符号链接名 (`\DosDevices`)**: `L"\\DosDevices\\MsNetEndpoint"`；
     - **R3 打开路径 (`CreateFile`)**: `L"\\\\.\\MsNetEndpoint"`；
     - **四者保持高度一致的 Windows 原生网络语义**，消除任何外挂/品牌暴露痕迹，彻底规避与系统既有 WskIoProvider 对象的重名冲突（`0xC0000035` / Win32 `183`）。
  2. **驱动端例程规范重命名**:
     - 将 [Main.cpp](file:///e:/Project/Drv/CheatDrv/Main.cpp) 中的分发例程重构为 `WskIoCreateClose` 与 `WskIoDeviceControl`，消除所有静态暴露符号。
  3. **宿主 Loader 通信激活链路同步切换**:
     - [utils.cpp](file:///e:/Project/Drv/CheatFrameWork/host_loader/LeechLoader/utils.cpp) 中的 `VerifyAndActivateDriver` 探测路径全面切换为 `\\\\.\\MsNetEndpoint`，并同步更新 [socket.cpp](file:///e:/Project/Drv/CheatFrameWork/host_loader/LeechLoader/socket.cpp) 中的指纹校验注释。
  4. **彻底清理 ComputerZ 释放逻辑**:
     - 清除 `computerzDriver_path` 变量及相关磁盘检测/释放逻辑，精简代码执行路径。

- **已知约束与避坑**:
  - **跨端符号一致性铁律**: 驱动端 `MK_USER_DEVICE_NAME` 与应用层 `CreateFileW` 必须严格一致（`\\.\MsNetEndpoint`），任何一处拼写失步都将导致 `VerifyAndActivateDriver` 探测超时（3 秒）报 `error.driver_activate_failed`；
  - **对象清理闭环**: 驱动卸载或异常退出时，必须成对调用 `IoDeleteSymbolicLink(&g_SymbolicLinkName)` 与 `IoDeleteDevice(g_pDeviceObject)`，防止留下悬挂对象导致系统蓝屏或二次加载冲突。
