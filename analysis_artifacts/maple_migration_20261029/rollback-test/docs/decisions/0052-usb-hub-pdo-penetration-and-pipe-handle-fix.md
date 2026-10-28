# ADR-0052: USB 传输层严格穿透直达 USBHUB3 物理 PDO 与 WDF 原生网关直发规范

- **状态**: 已采纳
- **日期**: 2026-10-23
- **上下文与痛点**:
  在 USB 传输模式启动与热路径收发演进中，针对反作弊(ACE)规避与设备栈直达进行了多轮推演与实机检验：
  1. **PCI 控制器 FDO (USBXHCI) 参数拒绝 (0xC000000D)**：
     向 PCI 控制器 FDO 发送带外设端点 `PipeHandle` 的 URB 会因主控不管理端点上下文而必然返回参数非法。
  2. **复合设备中间层 (usbccgp) 排除需求**：
     中间层 `usbccgp` 存在子 PDO 与父 FDO 的句柄映射壁垒；为实现最彻底的硬件总线穿透与隐匿性，用户明确要求**彻底排除 `usbccgp` 等一切中间驱动，通信必须且只能穿透直达底层 USB 总线设备 `\Driver\usbhub3` 的物理 PDO**。
  3. **反作弊(ACE)派遣拦截防线**：
     直发目标驱动必须具备无 Hook 的纯净分发能力，维持 `USBHUB3_STRICT_MODE = 1` 绝对红线。

- **技术决策与规范**:
  1. **严格硬件总线穿透直达 \Driver\usbhub3 (`UsbHub_PenetrateToHub3Pdo`)**:
     - 排除 `usbccgp`、`WINUSB` 等一切中间驱动，发包目标设备强校验必须属于 `\Driver\usbhub3`；
     - 结合垂直设备栈递归下探、复合设备 Parent FDO 关联以及内核直接引用 `\Driver\usbhub3` 驱动实例（`ObReferenceObjectByName`）获取物理硬件 PDO，确保 100% 锁定真实总线设备。
  2. **Wdf01000 原生分发网关无缝衔接**:
     - `usbhub3` 作为纯 KMDF 驱动，其 `MajorFunction` 100% 落在 `Wdf01000.sys` 内存边界内，`UsbHub_ResolveOriginalDispatch` 能够直接提取未被篡改的微软原生网关（`Wdf01000!FxDevice::DispatchWithLock`），彻底根除外部 Hook 拦截。
  3. **URB 单次传输安全钳制**:
     - `UsbServer_WorkerThread` 中单次 Bulk Read 请求安全限制在单槽大小 `USB_SERVER_SLOT_SIZE`（`0x110000` = 1MB + 64KB），且残片读取保持 512 字节硬件满包对齐，根除控制器 2MB 限制溢出。
  4. **全链路严格直通防御 (`USBHUB3_STRICT_MODE = 1`)**:
     - 驱动端严禁通过常规 Dispatch 派遣函数读写，所有 USB 通信 100% 必须直达 `usbhub3` 提交原生 URB。

- **已知约束与避坑**:
  1. **引用计数平衡**：在沿着设备栈下探时，调用 `IoGetLowerDeviceObject` 会增加目标对象引用计数，若中途未命中必须调用 `ObDereferenceObject` 平衡计数，防止设备对象泄漏。
  2. **派遣函数防 Hook 红线**：严禁在 `USBHUB3_STRICT_MODE` 下开启普通 WinUSB 读写回退，所有通信必须受限于底层纯净 WDF 网关。
