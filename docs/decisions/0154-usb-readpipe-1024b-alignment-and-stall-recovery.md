# ADR-0154: USB 残片续读 1024B 对齐恢复、xHCI 端点 Stall 自愈与连续错误重连闭环

- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**:
  1. **残片续读 512B 对齐引发 USB 3.0 SuperSpeed `USBD_STATUS_BABBLE_DETECTED` (`0xC0000001`)**：`Transport/usb_server.c` 在 `cbRemain > 0` 的续读分支中曾将 `cbReadReq` 对齐掩码退化为 `& ~0x1FFU`（512B 对齐，兜底 `512`）。在 USB 3.0 SuperSpeed 下 Bulk 端点 `wMaxPacketSize = 1024B`，当请求长度为 512 奇数倍且对端发来 1024B 满包时，xHCI 硬件检测到 Babble 溢出并将 `0x89` 端点置为 Halted，返回 `0xC0000001 (STATUS_UNSUCCESSFUL)`。
  2. **裸 URB 直发模式缺失 `ResetPipe` 导致端点永久锁死**：`fHubMode = TRUE` 绕过 `WinUSB.sys` 直发 `USBHUB3` PDO，不触发 `AUTO_CLEAR_STALL`；`ReadPipe` 失败后仅延迟 2ms 重试而未下发 `URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL`，导致 Halted 端点每次读取均立即返回 `0xC0000001`。
  3. **物理拔插/掉线早期连续 `0xC0000001` 未进入热插拔重连**：线缆松动或桥接芯片复位初期常连续返回 `0xC0000001`，且 `urb.Hdr.Status` 未透传至异常上报。

- **技术决策与规范**:
  1. **强制恢复 1024B (`& ~0x3FFU`) 读取长度对齐**：`usb_server.c` 残片续读长度统一按 `((USB_SERVER_SLOT_SIZE - cbRemain) & ~0x3FFU)` 对齐，最小兜底 `1024`（`pFastRecvBuf` 已预留 `+ PAGE_SIZE` 裕量确保不越界）。
  2. **非超时错误即时 `ResetPipe + FlushPipe` 自愈与 16 次阈值降级重连**：捕获非超时/非取消错误时立即调用 `UsbServer_ResetPipe` 与 `UsbServer_FlushPipe` 清除 xHCI Halted 状态；累计连续失败达 16 次时自动释放旧句柄并转入 1s 热插拔重连轮询，读取成功则归零计数。
  3. **直连透传 `g_UsbHubLastUsbdStatus`**：`usb_hub.c` 在 `UsbHub_BulkRead` 与 `UsbHub_BulkReadFast` 完成时记录 `urb.Hdr.Status`，上报报文附带 `usbd=0x%08X` 精确区分硬件错误码。

- **已知约束与避坑**:
  1. 严禁在 USB 3.0 Bulk IN 管道上提交非 `1024B` 整数倍的 `TransferBufferLength`；
  2. `USBHUB3` 裸 URB 模式遭遇非超时错误后必须配对执行 `ResetPipe` 恢复 xHCI Transfer Ring。

## 2026-10-30 补充闭环 (`USBD_STATUS_XACT_ERROR 0xC0000011` 自愈时序与拔线去抖抑制)
- 实测诊断捕获 `status=0xC0000001, usbd=0xC0000011 (USBD_STATUS_XACT_ERROR)`：对应副机拔线/重启前 Windows PnP 去抖窗口（~200-400ms）内 xHCI 硬件无响应，或总线瞬态失步。
- 修复措施：
  1. 恢复顺序严格遵循 Windows USB 栈规范：先 `UsbServer_FlushPipe` (`URB_FUNCTION_ABORT_PIPE` 排空队列)，再 `UsbServer_ResetPipe` (`URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL` 清除 Halted 与 Data Toggle)；
  2. `consecErrors < 16` 自愈期间退避提升至 `25ms`（总计 `400ms` 覆盖 USB 3.0 LTSSM 恢复与 PnP 拔线去抖）且静默不发远端告警；
  3. 转入热插拔重连时，对 `usbd == 0xC0000011 (USBD_STATUS_XACT_ERROR)` 与 `0xC0000030 (USBD_STATUS_DEVICE_GONE)` 归类为物理断线等待热插拔重连，抑制误报。
