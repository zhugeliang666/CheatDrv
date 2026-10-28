# ADR-0095: USB 传输栈无头 MDL 物理页缓冲改造与 Ucx01000 / Wdf01000 监控闭环

- **状态**: 已采纳
- **日期**: 2026-10-27
- **上下文与痛点**:
  1. **USB 常驻缓冲区的大池（`PoolBigPageTable`）暴露风险**：`Transport/usb_server.c` 原先通过 `ExAllocatePoolWithTag(NonPagedPoolNx, USB_SERVER_FAST_BUF_SIZE, 'mNoI')` 分配 `pFastRecvBuf` 与 `pFastSendBuf`（各 `0x220000` 字节，约 2.125MB），以及超大回包临时缓冲。这会在 `nt!PoolBigPageTable` 中留下两条伪装为 `'mNoI'` 但尺寸高度特异（`0x220000`）的大池登记项；反作弊可通过 `ZwQuerySystemInformation(SystemBigPoolInformation)` 定位 VA 并扫描内部未加密的 `LEECHRPC_MSG_HDR` 魔数（`0x66778899`）。
  2. **USB 底层总线扩展与 KMDF 框架层监控盲区**：`USBHUB3.sys` 与 `USBXHCI.sys` 均为 KMDF 驱动，且 `USBXHCI.sys` 的端点队列与 RootHub 路由完全托管于 `Ucx01000.sys`（USB Controller Extension）与 `Wdf01000.sys`（KMDF Runtime）。原先 `UsbMonitor` 与 `ApiMonitor` 仅覆盖 `USBHUB3` 和 `USBXHCI`，若反作弊下沉挂接 `ucx01000.sys` 或 `Wdf01000.sys` 的导入表、`MajorFunction` 或入口函数将产生漏报。

- **技术决策与规范**:
  1. **USB 传输缓冲全面切换为无头 MDL 物理页（Zero `PoolBigPageTable`）**：
     - 在 `MACHENIKE_PFN` 与 `FunctionArray`（`Core/Common.h`、`Core/DriverCore.cpp`）中同步新增动态解析项 `MmAllocatePagesForMdl` (`0x1AA46793`) 与 `MmUnmapLockedPages` (`0x8ED81937`)，并将 `InitHeadlessCanary` 同步纳入 `UserVar->Func.*` 调用，保持 100% Zero IAT。
     - `usb_server.c` 新增 `UsbServer_AllocHeadlessBuffer` / `UsbServer_FreeHeadlessBuffer`，使用 `MmAllocatePagesForMdl` 分配纯游离物理页，并通过 `MmMapLockedPagesSpecifyCache(..., KernelMode, MmCached, ...)` 映射至 System PTE 区间，彻底绕过 `ExAllocatePoolWithTag` 与 `nt!PoolBigPageTable`。
     - **MDL 头部尺寸压制在 `< 4KB`（Small Pool）与 DMA 传输 MDL 解耦**：将接收缓冲 `pFastRecvBuf`（`USB_SERVER_SLOT_SIZE + PAGE_SIZE` = 273 页，MDL 头 `2232` 字节）与两个发送槽位 `pSendBufSlot[0..1]`（各 `USB_SERVER_SLOT_SIZE` = 272 页，MDL 头 `2224` 字节）拆分为 3 个独立单槽分配，使所有 MDL 头部结构本身均 `< 4096` 字节，落入普通小池而绝不进入 `PoolBigPageTable`；同时将物理页所有权 MDL（`pFastRecvPagesMdl`、`pSendPagesMdlSlot[0..1]`）与供 `USBXHCI` 散列 DMA 使用的传输 MDL（`pFastRecvMdl`、`pSendMdlSlot[0..1]`，经 `IoAllocateMdl` + `MmBuildMdlForNonPagedPool` 构建以提供合法 `StartVa`）严格物理分离。
  2. **将 `Ucx01000.sys` 与 `Wdf01000.sys` 纳入双引擎只读监控**：
     - `Stealth/ApiMonitor.cpp`：`CORE_SYS_DRV_COUNT` 扩展至 `7`，在 `s_CachedSysDrvs` 中新增 `wstr_Ucx01000` (`0x38979924`) 与 `wstr_Wdf01000` (`0x414DE3B5`)，Init 阶段单次缓存模块基址，周期性只读巡检其 IAT 槽位及目标函数首部 Inline Hook。
     - `Stealth/UsbMonitor.cpp`：在 `g_MonitoredUsbDrivers` 中新增 `L"\\Driver\\ucx01000"` 与 `L"\\Driver\\Wdf01000"`，只读巡检其 `MajorFunction[0..27]` 分发指针、入口指令跳板及 `AttachedDevice` 过滤设备挂载。
  3. **修复 `usb_hub.c` 管道句柄伪指针误判与多复合设备 PDO 串扰引发的 `ReadPipe 0xC000000D` 故障**：
     - **根因 1（`WINUSB_PIPE_ENTRY` 内部 `LIST_ENTRY` 越界盲扫伪造 `USBD_PIPE_HANDLE`）**：逆向 `winusb.sys` (`0x1c0006b27..0x1c0006ff7`) 证实 `WINUSB_PIPE_ENTRY` 大小为 `0xF0` 字节，其 `+0x88` 为自引用 `LIST_ENTRY`（`Flink == self`），而真实的 `WDFUSBPIPE` 句柄位于 `+0xA0`。原 `UsbHub_ResolvePipeHandleFromObject` 在扫描 `hOff = 0x20..0xD0` 时先于 `0xA0` 命中 `+0x88` 的 `LIST_ENTRY`，并向后盲扫 `+0x10..+0x150` 越界进入相邻池块，将野指针当作 `USBD_PIPE_HANDLE` 返回；当 URB 提交至 `ucx01000!Urb_USBPORTStyle_ProcessURB` (`0x1c0002f0d`) 时，因不满足 `*(PVOID *)(PipeHandle + 0x20) == PipeHandle`（自引用）及 `[PipeHandle - 0x10] == 'Endp'` (`0x70646E45`) 校验，立即被判为 `USBD_STATUS_INVALID_PIPE_HANDLE (0x80000600)` 并返回 `0xC000000D` (`STATUS_INVALID_PARAMETER`)。现重构为：`raw < 0xFFFF800000000000ULL` 走 `FxUsbPipe` (`Type == 0x1203`) + 端点号精确匹配解算，`raw >= 0xFFFF800000000000ULL` 强制通过 `UsbHub_IsValidUcxPipeHandle` 校验 `+0x20` 自指针与 `'Endp'` 签名，且优先提取 `WINUSB_PIPE_ENTRY + 0xA0`。
     - **根因 2（`usbccgp` 全局设备链盲扫引发跨复合设备 `USBHUB3` PDO 串扰）**：逆向 `usbccgp.sys` (`0x1c00266df` & `0x1c0029574`) 证实子 PDO 扩展（`'UsbC'` + `'PdoC'`）在 `+0xF0` 处直接持有所属父 FDO 扩展 `ParentFdoExt`（`'UsbC'` + `'FdoC'`），其中 `ParentFdoExt + 0x18` 为对应的物理 `USBHUB3` PDO，`+0x20` 为 `ParentFdo`。`UsbHub_PenetrateToHub3Pdo` 优先通过 `'FdoC'` 签名精确提取当前 `MI_05` 接口所属的唯一 `USBHUB3` PDO，避免机器存在键鼠/耳机等多个复合设备时误绑其他设备的 `USBHUB3` PDO。

- **已知约束与避坑**:
  1. **严禁直接将 `MmAllocatePagesForMdl` 返回的 MDL 传给 `UrbBulkOrInterruptTransfer`**：`MmAllocatePagesForMdl` 创建的 MDL 仅包含 PFN 数组且 `Mdl->StartVa == NULL`（`MmMapLockedPagesSpecifyCache` 仅填充 `MappedSystemVa`），直接作为 URB `TransferBufferMDL` 会导致 `MmGetMdlVirtualAddress` 返回 `NULL` 且 `USBXHCI` 完成路径修改 `MdlFlags` 破坏物理页释放。必须使用独立的传输 MDL，并在 URB 中同时填写 `TransferBuffer = pBuf` 与 `TransferBufferMDL = pMdl`。
  2. **严禁将任意非自引用内核指针盲判为 `USBD_PIPE_HANDLE`**：在 USB 3.0 (`ucx01000.sys`) 栈下，`USBD_PIPE_HANDLE` 必须满足 `*(PVOID *)(hPipe + 0x20) == hPipe` 且 `*(PULONG)(hPipe + 0x0C) == 2` (`UsbdPipeTypeBulk`)，任何未验证此契约的扫描必将在 `Urb_USBPORTStyle_ProcessURB` 触发 `0xC000000D`。
  3. **释放顺序铁律**：卸载或停止服务时，必须在 `UsbHub_Cleanup` 排空所有在飞 URB 并先调用 `IoFreeMdl` 销毁传输 MDL 后，再依次调用 `MmUnmapLockedPages` -> `MmFreePagesFromMdl` -> `ExFreePoolWithTag(pPagesMdl, 0)` 回收底层物理页。
