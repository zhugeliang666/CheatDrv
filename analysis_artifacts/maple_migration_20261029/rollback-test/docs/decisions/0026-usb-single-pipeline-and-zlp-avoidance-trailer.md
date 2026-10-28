# ADR-0026: USB 传输层单轨组提交流水线、ZLP-Avoidance 尾标与周期性假死挂起彻底根除

- **状态**: 已采纳
- **日期**: 2026-10-16
- **上下文与痛点**:
  1. **“正常 1~2 秒 $\to$ 突然卡住 5~6 秒 $\to$ 恢复 1~2 秒 $\to$ 再次卡住” 周期性假死现象**:
     - 在 [ADR-0020](0020-usb-transport-full-duplex-pipeline-and-micro-coalescing.md) 引入 `SendLock` / `RecvLock` 双锁分离与 `fLargeReq` 直通分支后，系统在多线程高频读取（尤其是骨骼矩阵大跨页散列读）下，出现无任何报错输出的周期性卡死定格；
  2. **根因 1（`SendLock`/`RecvLock` 双锁分离 + `fLargeReq` 双轨制吞包）**:
     - 直通线程绕过 `Slots[64]` 直接发包并进入 `RecvLock` 等待回包；
     - 组提交 Leader 线程在 `RecvLock` 中一次性通过 2MB `WinUsb_ReadPipe` 收割到粘连的直通包响应，在遍历 64 槽位未命中 Nonce 时，执行 `cbConsumed += cbFrameTotal` 直接将直通响应静默吞弃；
     - 直通线程在 `RecvLock` 门内陷入死等，后续 Leader 阻塞于 `RecvLock` 门外，全场人物显示冻结，直至超时释放锁；
  3. **根因 2（驱动端裸发 URB 缺失 Short Packet / ZLP 导致 xHCI 挂起）**:
     - 驱动端使用 `UsbHub_BulkWriteAsync` 向 Host 提交裸 Bulk IN URB，Windows `USBXHCI.SYS` 对 Bulk OUT 不自动追加 ZLP；
     - 当紧凑打包后的应答报文长度恰为 512 或 1024 字节整数倍时，总线上所有数据包均为满包，无短包（Short Packet）；
     - 客户端 xHCI 硬件将 2MB 接收 URB 挂起等待后续数据，导致 `WinUsb_ReadPipe` 物理停滞，直到后台其它线程发出下一个报文将其“顶出”才能解冻；
  4. **根因 3（无上限批量收割引发双端管道满载死锁与非 1024B 对齐 `USBD_STATUS_BABBLE_DETECTED`）**:
     - 移除 `fLargeReq` 后若对 8 线程 $\times 100$ 页散列读无上限合并发车（单批预估回包达 $3.38\text{MB}$，远超驱动端单个发送槽 `0x110000`），驱动在处理到第 5 个请求时会因双槽满载阻塞于 `UsbHub_WaitWriteSlot`，当大请求跨硬件 FIFO 拆包时形成双端互等死锁（`Sec #003 -> 0 Ops/s`）；
     - 同时，客户端或驱动端在存在未消费残片（`cbBufTotal > 0` / `cbRemain > 0`）时，若向 `WinUsb_ReadPipe` / `UsbServer_ReadPipe` 传入非 1024B (`wMaxPacketSize`) 整数倍的剩余缓冲长度，xHCI 硬件会在收到满包时直接报 `USBD_STATUS_BABBLE_DETECTED` 终止传输。

---

- **技术决策与规范**:
  1. **废除 `fLargeReq` 旁路双轨制，所有请求 100% 走单轨组提交流水线 + 单槽水位受控发车**:
     - 彻底移除客户端 [leechusb_client.c](file:///E:/Project/Machenike/leech_vmm/leechCore/leechcore/leechusb_client.c) 的 `fLargeReq` 独立直通分支与两次同步 IOCTL `WinUsb_SetPipePolicy` 调用；
     - 所有请求无论数据大小，统一在 `g_usb_group.Slots[0..63]` 中按轮询游标（`rrCursor`）分配槽位；
     - Leader 收割时**强制优先收割自身 `mySlotIdx`**，随后按轮询顺序收割其余排队槽位，并施加**单槽预估响应水位上限（`MAX_BATCH_EST_RSP = 0xE0000` / 896KB < 驱动单槽 `0x110000`）与发送窗口上限（`MAX_BATCH_SEND_BYTES = 32768` / 32KB）**，确保任意单个批次 100% 装入驱动端单个异步发送槽位，零中途阻塞；
     - `Leader Handoff` 同样采用基于 `(mySlotIdx + step) & 63` 的轮询交接，根除高并发下槽位饥饿。
  2. **驱动端 12 字节全零短包尾标 (ZLP-Avoidance Trailer) 物理消除挂起**:
     - 驱动端 [usb_server.c](file:///e:/Project/Drv/CheatDrv/usb_server.c) 在异步槽位发送前检测：若待发送总字节数满足 `(cbSendTotal & 0x1FF) == 0`（即 512 或 1024 字节整数倍），直接在发送缓冲区末尾追加 12 字节全零哑元帧头 `[qwNonce = 0ULL][cbPayload = 0UL]`，`cbSendTotal += 12`；
     - 加和后长度为 $512 \times K + 12$，对 512 与 1024 取模恒不为 0，硬件最后一个 USB Packet 长度为 12 字节（$< 1024$ 字节），100% 触发 xHCI 硬件短包中断唤醒，零延迟完成传输；
     - 客户端 `bEpOut` 已开启硬件级 `SHORT_PACKET_TERMINATE = TRUE`，无需冗余追加软件尾标；接收端在帧头解析循环首部检查 `if (qwNonce == 0 && cbPayload == 0) { cbConsumed += 12; continue; }`，零开销安全跳过哑元帧。
  3. **接收缓冲区扩容至 `2MB + 64KB` 且强制 1024B (`wMaxPacketSize`) 读取长度对齐**:
     - 客户端 `cbRecvFastBufAlloc` 扩容至 `2 * 1024 * 1024 + 65536`，所有 `WinUsb_ReadPipe` 与驱动端 `UsbServer_ReadPipe` 的请求长度强制按 `& ~0x3FFU` 对齐至 1024 字节整数倍，彻底根除 `USBD_STATUS_BABBLE_DETECTED` 硬件溢出报错。

---

- **已知约束与避坑**:
  - **槽位统一与单槽水位原则**: 严禁开辟绕过全局槽位的独立收发旁路；Leader 必须首先收割自身 `mySlotIdx`，且单批次预估回包总长不得超过驱动端单槽容量 `0x110000`；
  - **读取长度 1024B 对齐铁律**: 任何带有首部残片偏移（`cbBufTotal > 0` 或 `cbRemain > 0`）的 USB Bulk IN 读取请求，传入的 `BufferLength` 必须向下对齐至 `1024`（`wMaxPacketSize`）的整数倍，严禁直接传入非对齐的 `cbMax - cbOffset`；
  - **哑元帧前置过滤**: 接收端必须在进行有效性校验（`cbPayload < sizeof(LEECHRPC_MSG_HDR)`）之前先行匹配全零哑元尾标并步进游标，防止将其误判为非法畸形帧导致管道被错误 Flush；
  - **USB 半双工整波聚拢与禁止提前交接 Leader**: 由于驱动端 `UsbServer_WorkerThread` 为单线程半双工循环（`UsbHub_BulkReadFast` $\to$ 分发 $\to$ `UsbHub_BulkWriteAsync`），客户端在 `LeechRPC_ReadScatter_CombineNng` 中针对 USB 必须维持整波满载聚拢（`targetWave = peakNow`，严禁拆分为半波），且在 `leechusb_client.c` 中必须在 `RecvLock` 收齐响应后方可调用 `UsbClient_HandoffLeader`，严禁在 `SendLock` 后提前交接导致波次碎裂翻倍。

