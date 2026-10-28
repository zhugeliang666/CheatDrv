# ADR-0048: 传输模式禁用态(ENABLE_TRANSPORT_MODES=0)平滑准出与会话密钥无条件派生

- **状态**: 已采纳
- **日期**: 2026-10-20
- **上下文与痛点**: 
  - 当驱动配置 `ENABLE_TRANSPORT_MODES = 0` 或客户端下发 `TransportMode = 0` (纯本地设备 IOCTL 交互) 时，`StartTransportByIo` 原先在宏分支下直接返回 `STATUS_NOT_SUPPORTED` (`0xC00000BB`)。
  - 该非成功状态导致 `DriverCore::ApplyBootConfigAndStart` 失败，进而在 `DispatchCreate` 拦截了客户端的设备句柄创建请求并高频触发异常上报，阻断了本地 IOCTL 模式的正常运行。
  - 此外，原先宏分支将 `SessionToken` 密钥派生逻辑错误地嵌套在 `#if ENABLE_TRANSPORT_MODES` 内，导致禁用独立服务端时驱动未初始化 `SessionCryptKey` 与 `AuthStateInvariant`，后续安全状态校验失效。

- **技术决策与规范**:
  1. **SessionToken 派生解耦**: 将动态密钥派生提取至 `StartTransportByIo` 最前置无条件执行，确保全模式下 `SessionCryptKey` 与安全态防伪校验均正常完成。
  2. **禁用态与 Mode=0 平滑放行**:
     - 当 `ENABLE_TRANSPORT_MODES == 0` 时，打印跳过日志并直接返回 `STATUS_SUCCESS`；
     - 当 `ENABLE_TRANSPORT_MODES == 1` 但客户端传入 `TransportMode == 0` (纯 IOCTL 模式) 时，跳过 WSK/USB 服务端启动并返回 `STATUS_SUCCESS`；
  3. **设备创建与 IOCTL 契约**: `DispatchCreate` 成功准出，允许用户态无缝打开设备句柄并使用 IOCTL 通信。

- **已知约束与避坑**:
  - 严禁在 `ENABLE_TRANSPORT_MODES = 0` 时返回任何错误码阻断 `CreateFile`；
  - 纯 IOCTL 模式下的所有通信均依赖 `SessionCryptKey`，必须确保密钥派生先于任何状态返回。
