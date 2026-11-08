# ADR-0184: Win10/11 NDIS NetworkSetup2 动态协议绑定、后台引擎延迟启动与失败卸载安全闭环

- **状态**: 已采纳
- **日期**: 2026-11-08
- **关联代码**: `Transport/eth_server.cpp`、`Core/DriverCore.cpp`、`Diagnostics/ExceptionReporter.cpp`、`loader/scm_loader.h`、`host_loader/LeechLoader/utils.cpp`

## 1. 上下文与痛点

在 Win10 22H2 (Build 19045.4355) 环境下，使用 SCM 标准服务加载（服务名与协议名统一为 `i225v`）并激活 `RawEthernet (0x8844)` 传输时，触发以下故障：
1. **NDIS 协议 0 网卡绑定 (`0xC00000A3`, `bindCalls=0`)**：
   - 原逻辑尝试卸载 `lltdio` / `rspndr` / `ndisuio` 并伪装其协议名，或在 `Services\i225v\Linkage\Bind` 写入网卡列表后调用 `NdisReEnumerateProtocolBindings`。
   - 对 `C:\Windows\System32\drivers\ndis.sys` (10.0.19041.4355) 反汇编取证表明：
     * Windows 10/11 引入 `NetworkSetup2` 绑定引擎后，`ndis.sys` 中已完全不存在对 `Services\<Proto>\Linkage\Bind` 的读取；`ndisUpdateMiniportBindings` (`0x108d08` -> `0x10a94c` -> `0x10aa48`) 实际打开 `\Registry\Machine\System\CurrentControlSet\Control\NetworkSetup2\Interfaces\{AdapterGuid}\Kernel`（或 StateSeparation 下的 `\Registry\Machine\DEVICES\Networking\NetAdapters\{AdapterGuid}\Kernel`），读取 `REG_MULTI_SZ` 类型的 `ProtocolList` 值。
     * `NdisReEnumerateProtocolBindings` (`0x99170`) 内部在 `0x991be` 处检查 `test dword ptr [ProtocolBlock + 0x40], 0x20000000`：仅当 `ProtChars.Flags` 包含 `0x20000000` (`NDIS_PROTOCOL_DRIVER_DYNAMIC_BINDING`) 时，才调用 `ndisReEnumerateRefreshBindings` (`0x976f8`) 遍历 `ndisMiniportDriverList` 对每个 `_NDIS_MINIPORT_BLOCK` 执行 `ndisUpdateMiniportBindings` (`0x108d08`)。
     * 当 `ProtChars.Flags == 0` 时，`NdisReEnumerateProtocolBindings` 直接跳过 `0x976f8`，仅遍历 `[ProtocolBindObject + 0x08]` 既有绑定链，导致新注册的 `i225v` 协议 `bindCalls=0`。
2. **`DispatchCreate` 失败路径提前销毁设备与卸载死锁隐患**：
   - `DriverCore::Initialize` (`DriverEntry`) 若在传输层尚未激活前提前启动 2s 周期后台安全监控定时器与 DPC，一旦 `DispatchCreate` 激活失败触发 SCM 停止服务，后台工作项与卸载流程易发生竞态；
   - `DispatchCreate` 失败分支若删除符号链接与设备对象，会导致后续卸载或重连状态异常；
   - `ExceptionReporter::Cleanup` 置位 `s_ReporterClosing = 1` 后，若 `AsyncWorkRoutine` 直接丢弃已在队列中的异常工作项，会导致 `EthServer_Init` 失败根因上报在 `DriverUnload` 排空阶段被吞没。

## 2. 技术决策与规范

### 2.1 唯一协议名 `i225v` 与 `NetworkSetup2\Interfaces\{GUID}\Kernel\ProtocolList` 瞬时动态绑定
1. **彻底移除内置协议名抢占**：删除 `LLTDIO`、`RSPNDR`、`NDISUIO`、`mswsk` 候选名及 `ZwUnloadDriver` 调用，仅使用本驱动自身已激活的服务名 `i225v`，与 `ndisProtocolList` 内置协议零冲突。
2. **置位 `ProtChars.Flags = 0x20000000`**：
   - 在 `EthServer_Init` 中显式设置 `ProtChars.Flags = 0x20000000`（`NdisRegisterProtocolDriver` 在 `0x2e4b0` 处通过 `and eax, 0xf0000000` 为 NDIS 6.30 保留该标志位至 `ProtocolBlock->Flags`）。
3. **瞬时注入并无痕还原 `ProtocolList`**：
   - `EthBackupAndApplyProtocolLinkage` 从 `Tcpip\Linkage\Bind`、`Tcpip6\Linkage\Bind`、`Ndisuio\Linkage\Bind` 提取全部活跃网卡 `{GUID}`（覆盖禁用 IPv4 的专用直连雷达网卡）；
   - 以内核态 `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` 打开 `NetworkSetup2\Interfaces\{GUID}\Kernel`，快照备份原 `ProtocolList` (`REG_MULTI_SZ`) 至非分页池 `PMK_LINKAGE_BACKUP`（严禁将 `sizeof(MK_LINKAGE_BACKUP)` 置于 24KB 内核栈上），将 `i225v` 追加写入 `ProtocolList`；
   - 调用 `NdisRegisterProtocolDriver` 与 `NdisReEnumerateProtocolBindings`：此时 `0x991be` 触发 `0x976f8` -> `0x108d08` 将 `i225v` 的 `ProtocolBindObject` 挂入各 Miniport，`0x991d9` 置位 `ProtocolBindObject->Ready = 1`，随后 `0x991fa` 同步在当前线程回调 `EthProtocolBindAdapterEx` 完成 802.3 网卡绑定与 `DirectMiniport` 槽位接管；
   - `NdisReEnumerateProtocolBindings` 返回的同一毫秒内，立即调用 `EthRestoreProtocolLinkage` 将所有网卡的 `ProtocolList` 与 `Services\i225v\Linkage` 精确还原为原始字节流，实现注册表零残留。

### 2.2 后台监控延迟启动、设备对象生命周期与卸载排空闭环
1. **后台监控引擎延迟启动**：将 `StartBackgroundEngines` 从 `DriverCore::Initialize` (`DriverEntry`) 移至传输服务成功激活之后（`StartTransportByIo` / `DispatchCreate` 成功分支及 ManualMap 启动成功分支），确保激活失败时零后台定时器/DPC 干扰卸载。
2. **失败路径严禁删除设备对象与符号链接**：`DriverCore::DispatchCreate` 所有错误返回路径一律保留 `g_SymbolicLinkName` 与 `g_pDeviceObject`，仅在 `DriverCore::DriverUnload` 中成对销毁，确保 SCM 随时可正常停止并卸载驱动。
3. **加载器单次激活与失败自动卸载**：`loader` 与 `host_loader` 在 `CreateFileW` 激活失败时自动调用 `StopAndRemoveService` / `StopAndRemoveDriverService` 清理内核服务。
4. **卸载期在途异常上报完整投递**：`ExceptionReporter::AsyncWorkRoutine` 不因 `s_ReporterClosing` 提前丢弃已入队并持有 `s_ActiveReportsCount` 计数的告警项，确保 `Cleanup` 排空屏障等待在途告警完整发送完毕后再退出 `DriverUnload`。

## 3. 已知约束与避坑
- **严禁将 `MK_LINKAGE_BACKUP` 分配在内核栈上**：`MK_LINKAGE_BACKUP` 含 32 个网卡路径备份槽位（约 13KB），必须通过 `ExAllocatePoolWithTag(NonPagedPoolNx, ...)` 离栈分配，防止击穿 24KB 内核栈触发 `BugCheck 0x7F`。
- **严禁遗漏 `ProtChars.Flags = 0x20000000`**：若 `Flags` 为 0，`NdisReEnumerateProtocolBindings` 不会触发 `ndisReEnumerateRefreshBindings` 重读 `NetworkSetup2` 的 `ProtocolList`。
- **严禁在 `DispatchCreate` 失败分支调用 `IoDeleteSymbolicLink` 或 `IoDeleteDevice`**：设备与符号链接的销毁必须唯一收敛在 `DriverUnload`。
