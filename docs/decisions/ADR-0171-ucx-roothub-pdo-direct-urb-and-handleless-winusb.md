# ADR-0171: USB 传输层直穿 ucx01000/USBXHCI RootHub PDO 与零 IOCTL 无句柄 WinUSB 探针
- **状态**: 已采纳 (部分替代 ADR-0052)
- **日期**: 2026-10-31
- **上下文与痛点**:
  1. 逆向 `USBHUB3!HUBPDO_EvtDeviceWdmIrpPreprocess` 证实：此前向 `g_pHubPdo` (`\Driver\USBHUB3`) 发送 `IOCTL_INTERNAL_USB_SUBMIT_URB` 时，`USBHUB3` 仅在 `[urb + 0x08]` 填入 `UsbdDeviceHandle` (`UCXUSBDEVICE`)，随后通过标准 `IofCallDriver` 二跳转发至下层设备。若存在级联 Hub 或过滤驱动，二跳 `IofCallDriver` 仍会命中 `USBHUB3` 的 `MajorFunction` Hook。
  2. 逆向 `ucx01000!Urb_USBPORTStyle_ProcessURB` 解开了 ADR-0052 中底层直发返回 `0xC000000D` 的真正原因：一是误发往 `\Driver\USBXHCI` 的 PCI 控制器 FDO 而非 **RootHub PDO**；二是未填充 `urb.Hdr.UsbdDeviceHandle` (`mov rdx, [r8+8]; test rdx, rdx; je 0xC000000D`)。
  3. 原 `UsbServer_QueryDeviceEndpoints` 发送两次 `IOCTL_WINUSB_GET_DESCRIPTOR` (`0x0350C004`) 并分配带 Tag 池内存查询端点，且 `g_UsbServer.hDevice` 常驻暴露在 `System` 内核句柄表 (`ObpKernelHandleTable`) 中。
- **技术决策与规范**:
  1. **从 `PipeHandle` 零偏移风险提取 `UCXUSBDEVICE`**：在 `UsbHub_ExtractUcxDeviceHandle` 中，依据 `ucx01000!UcxEndpointCreate` 与 `UcxUsbDeviceCreate` 结构，校验 `[PipeHandle - 0x10] == 'Endp'` (`0x70646E45`)，读取 `[PipeHandle + 0x38]` (`PUCXUSBDEVICE_PRIVCONTEXT`)，交叉校验 `[pUsbDevCtx + 0x00] == 'Devi'` (`0x69766544`) 及 `+0x18` Controller Context 一致性后，提取 `[pUsbDevCtx + 0x10]` 填入所有 URB 的 `Hdr.UsbdDeviceHandle`。
  2. **直穿 `\Driver\USBXHCI` RootHub PDO**：在 `UsbHub_PenetrateToUcxRootHubPdo` 中，通过 PnP `_DEVICE_NODE` 树向上回溯及 `USBHUB3` 根集线器 FDO 栈底 `IoGetLowerDeviceObject` 双路径定位 `AttachedDevice` 链含 `USBHUB3` 的 `\Driver\USBXHCI` RootHub PDO，使 `BulkReadFast` / `BulkWriteAsync` / `AbortPipe` 一跳直达 `ucx01000!RootHub_Pdo_EvtInternalDeviceControlIrpPreprocessCallback`，全程 0 次经过 `WinUsb.sys`、`usbccgp.sys` 与 `USBHUB3.sys`。
  3. **冷路径端点重置适配**：因 `URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL` (`0x001E`) 在 `ucx01000` 中为 `UrbHandler_NotSupported`，在直连 RootHub PDO 模式下，`UsbHub_ResetPipe` 改为发送 UCX 原生支持的 `URB_FUNCTION_ABORT_PIPE` (`0x0002`) + `URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT` (`0x0011`, `ENDPOINT_HALT`)。
  4. **废除 `UsbServer_QueryDeviceEndpoints` 与即刻销毁 `hDevice`**：新增 `UsbHub_AutoScanBulkPipes` 直接从 `WinUsb` 的 `FxUsbPipe (0x1203)` / `WINUSB_PIPE_ENTRY` 内存同时提取双向 Bulk 端点号与 `USBD_PIPE_HANDLE`；穿透完成后在 `UsbServer_AutoDetectDeviceAndPipes` 内立即调用 `ZwClose(hDev)` 与 `ObfDereferenceObject(pFileObj)`，实现 `ObpKernelHandleTable` 零句柄暴露。
- **已知约束与避坑**:
  - 严禁向 `\Driver\USBXHCI` 的 PCI 控制器 FDO 发送 URB，必须通过 `UsbHub_IsUcxRootHubPdo` 校验其 `AttachedDevice` 链上存在 `USBHUB3` 根集线器 FDO。
  - 关闭 `hDev` 前必须由 `UsbHub_Init` 持有 `ObfReferenceObject(pTargetFdo)` 及底层 PDO 引用，防止设备栈引用归零。
