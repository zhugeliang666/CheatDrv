# ADR-0065: 保留 UCXXRT/WDF DriverUnload 包装器链与 Bootstrap 轻量退出根除 BugCheck 0xD4

- **状态**: 已采纳
- **日期**: 2026-10-25
- **影响模块**: `vt/VtBootstrapDriver/main.cpp`

## 上下文与痛点

在实机完成 `VtHypervisor`、`VtResidentPayload` 与 `Machenike` 常驻交接并由 `loader.exe` 调用 `ReleaseResidentBootstrap()`（发送 `MAPCTL_IOCTL_HANDOFF_DROPCTL` 后通过 SCM 卸载 `VtBootstrapDriver.sys`）后，系统运行至约 52.521 秒时在 `lsass.exe` 线程触发蓝屏：
- **BugCheck**: `0xD4` (`SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD`)
- **Arg1**: `fffff801'4439af78`（位于已卸载的 `VtBootstrapDriver.sys` `.data` 节 RVA `0x36AF78`）
- **Arg2**: `2` (`DISPATCH_LEVEL`)
- **Arg4**: `nt!ExDeleteResourceLite+0xaa` (`cmp qword ptr [rdx+8], rbx`，其中 `rdx = fffff801'4439af70`)

### 二进制与运行时根因闭环
1. 本地同版 `VtBootstrapDriver.sys` 反汇编确认：RVA `0x36AF70` 是 `UCXXRT` 静态 `ERESOURCE`。
   - `UCXXRT` 在 `DriverEntry` 包装器（RVA `0x3C674`）中保存 `DriverMain` 设置的业务 `unload_driver`，将 `DriverObject->DriverUnload` 替换为 `UCXXRT` 卸载包装器（RVA `0x3C640`），并在 RVA `0x3CF00` 对 RVA `0x36AF70` 调用 `ExInitializeResourceLite` 挂入内核全局 `nt!ExpSystemResourcesList`；
   - `WDF` 外层包装器再将 `DriverObject->DriverUnload` 包装为 RVA `0x3C2E0`。
2. 原 `mapdriver_install_resident_bootstrap_unload()` 直接执行：
   ```cpp
   InterlockedExchangePointer(
       &g_host_driver_object->DriverUnload,
       Utils::payloadExports->release_bootstrap);
   ```
   这导致 SCM 卸载 `VtBootstrapDriver` 时直接跳入 `ResidentPayload` 的空叶函数 `PayloadReleaseBootstrap`，**绕过了 WDF (`0x3C2E0`) 与 UCXXRT (`0x3C640`) 两层卸载包装器**。
3. 由于 `__vcrt_uninitialize_locks` / `__acrt_uninitialize_locks` -> `ExDeleteResourceLite(0x36AF70)` 未执行，`VtBootstrapDriver.sys` 映像卸载后，位于 RVA `0x36AF70` 的静态 `ERESOURCE` 节点仍滞留在 `nt!ExpSystemResourcesList` 全局双向链表中。随后 `lsass.exe` 释放无关 Token 的 `ERESOURCE` 时，`ExDeleteResourceLite` 在 `DISPATCH_LEVEL` 遍历/解链相邻的陈旧 `VtBootstrapDriver` 节点，立即触发 `BugCheck 0xD4`。

---

## 技术决策与规范

1. **严禁覆盖 `DriverObject->DriverUnload` 包装器指针**：
   - `mapdriver_install_resident_bootstrap_unload()` 彻底废除 `InterlockedExchangePointer(&g_host_driver_object->DriverUnload, ...)`，完整保留 `WDF -> UCXXRT -> unload_driver` 卸载包装器调用链；
   - 引入原子状态位 `g_bootstrap_lightweight_unload_armed`，在迁移与屏障校验通过后执行 `_InterlockedExchange(&g_bootstrap_lightweight_unload_armed, 1)`。
2. **`unload_driver` 驻留态轻量退出**：
   - 当 `(g_bootstrap_lightweight_unload_armed != 0 || g_payload_detached != 0) && mapdriver_hv_ready()` 成立时，`unload_driver` 仅执行 `mapdriver_delete_control_device()` 删除控制设备与符号链接，**不卸载常驻 `Machenike`、不停止驻留 HV、不释放 `VtResidentPayload` 与 `payloadArena`**；
   - `unload_driver` 自然 `return` 回到 `UCXXRT` 包装器（`0x3C640`），由其配对执行 `__vcrt_uninitialize_locks`、`__acrt_uninitialize_locks` 及 `ExDeleteResourceLite(0x36AF70)`，再由 `WDF` 包装器（`0x3C2E0`）完成 framework unbind，最后由 I/O Manager 安全卸载 `VtBootstrapDriver.sys` 映像。
3. **二次拉起宿主（防重探测/热重载）状态对齐**：
   - 当 `VtBootstrapDriver` 在 `pre_load_hv_ready` 分支恢复常驻状态时，同步置位 `g_payload_detached = 1` 与 `g_bootstrap_lightweight_unload_armed = 1`；若随后收到 `MAPCTL_IOCTL_FULL_UNLOAD`（`--force` 热重载），在 `mapdriver_full_unload_runtime_locked` 中清零该标志并执行完整逆序卸载。

---

## 已知约束与避坑

- **严禁在 `HANDOFF_DROPCTL` IOCTL 内提前调用 CRT uninitialize**：IOCTL 返回路径、日志输出和 WDF 框架在 IOCTL 完成乃至 `DriverUnload` 期间仍可能访问 CRT 锁或 WDF 状态，提前清理会引入 UAF 或重复 `ExDeleteResourceLite` 崩溃。
- **严禁在链接了 `UCXXRT` / `WDF` 的驱动中运行期直接覆写 `DriverObject->DriverUnload`**：任何业务卸载状态切换必须在 `DriverMain` 注册的原始业务 `unload_driver` 函数内部完成分支分发，确保外层 CRT 与框架解绑包装器成对执行。
