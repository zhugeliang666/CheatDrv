# ADR-0171: USB 传输层零 IOCTL 内存管道扫描与 WinUsb 句柄电源状态机修正
- **状态**: 已修订 (2026-11-02 实机逆向修正)
- **日期**: 2026-11-02
- **上下文与实机负向知识**:
  1. **逆向 `WinUsb.sys` 实锤提前关闭 `hDev` 导致设备挂起与断联**：
     - `WinUsb!EvtDeviceFileCreate` (`0x1C00175D0`) 在打开句柄时调用 `WdfFunctions[0x558]` (`WdfDeviceStopIdle`) 将 `MI_05` 接口锁定在 D0 工作态。
     - 若在探测后立即调用 `ZwClose(hDev)`，I/O 管理器将下发 `IRP_MJ_CLEANUP` 触发 `WinUsb!EvtFileCleanup` (`0x1C0017A60`)：该函数在 `0x1C0017B61` 调用 `WdfFunctions[0x560]` (`WdfDeviceResumeIdle`) 并调用 `WdfIoQueuePurgeSynchronously` 清空管道队列；随后 KMDF 触发 `WinUsb!EvtDeviceD0Exit` (`0x1C0019580`)，遍历所有管道调用 `WdfIoTargetStop(..., WdfIoTargetCancelSentIo)` 中止在飞 URB 并使 `MI_05` 接口进入 D2/D3 Selective Suspend（选择性挂起），导致副机无法连接。
  2. **逆向 `UsbHub3.sys` 与 `ucx01000.sys` 实锤 `0x1E` 重置管道与二跳路径**：
     - `ucx01000!Urb_USBPORTStyle_ProcessURB` 中 `0x1E` (`URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL`) 固定指向 `0x1C001CB30` 并返回 `STATUS_NOT_SUPPORTED` (`0xC00000BB`)；仅向 EP0 发送 `0x11` (`CLEAR_FEATURE_TO_ENDPOINT`) 不会执行 `0x49102F` (`IOCTL_INTERNAL_USB_ENDPOINT_RESET`) 重置 xHCI 主控 Endpoint Ring 与 Data Toggle。
     - `UsbHub3!HUBPDO_EvtDeviceWdmIrpPreprocess` (`0x1C0016F20`) 在处理 `0x09` (Bulk) 时通过 `WdfFunctions[0x2E0]` (`WdfIoTargetWdmGetTargetDeviceObject`) 直接发往 `\Driver\USBXHCI` RootHub PDO，不会二次进入 `\Driver\USBHUB3->MajorFunction`，且原生支持 `0x1E` 完整重置 xHCI 端点环与设备 Stall。
- **技术决策与规范**:
  1. **保留零 IOCTL 内存直扫 (`UsbHub_AutoScanBulkPipes`) 与 `UCXUSBDEVICE` 提取**：无需发送 `IOCTL_WINUSB_GET_DESCRIPTOR`，直接从 `WinUsb` 的 `FxUsbPipe (0x1203)` 提取 `EpIn`/`EpOut` 与 `USBD_PIPE_HANDLE`。
  2. **生命周期内保持赢家 `hDev` 与 `pFileObj` 打开**：仅在候选探测失败、断线重连释放旧句柄或 `UsbServer_Stop` 时调用 `ZwClose(hDev)`，确保服务运行期间 `WinUsb` 维持 D0 唤醒与 `WDFUSBPIPE` Started 状态。
  3. **绑定 `g_pHubPdo` 纯净 `Wdf01000` 网关并恢复启动期 `UsbServer_ResetPipe`**：统一通过 `g_pHubPdo` 的未挂钩 `Wdf01000` 分发入口提交 URB，并在 `UsbServer_WorkerThread` 启动与重连时执行 `UsbServer_ResetPipe` + `UsbServer_FlushPipe`。
  4. **移除 R3 冗余 `IOCTL_MK_START_TRANSPORT` 二次激活**：`VerifyAndActivateDriver` 通过 `CreateFileW` 内存锚点激活驱动后直接关闭句柄返回；`TransportManager::StartServer` 在确认非同模式复用后再执行 `MkRpc_Init`。
