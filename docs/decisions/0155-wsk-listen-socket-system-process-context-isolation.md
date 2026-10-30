# ADR-0155: WSK 监听套接字在 System (PID=4) 线程上下文隔离创建与防加载器 PID 污染

- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**:
  1. 当宿主加载器 `LeechLoader.exe` 通过 `CreateFileW("\\\\.\\MsNetEndpoint")` 或 `IOCTL_MK_START_TRANSPORT` 激活驱动时，`DriverCore::DispatchCreate` / `WskIoDeviceControl` 直接运行在调用方用户态线程（即 `LeechLoader.exe` 进程上下文）中。
  2. 先前实现中，`WskServer_Init` 在创建 `WskServerThread` 系统线程之前，直接在当前 IRP 调用线程上下文同步执行了 `WskRegister`、`WskCaptureProviderNPI`、`WskSyncSocket(..., WSK_FLAG_LISTEN_SOCKET)` 与 `WskSyncBind`。
  3. Windows `tcpip.sys` 在创建与绑定 `TCP_ENDPOINT` 时，会通过 `IoGetCurrentProcess()` 捕获当前调用线程所属进程并将其记录为该端口的 `OwningProcess`。这导致资源监视器（`resmon.exe`）、`netstat -ano` 以及反作弊通过 `GetExtendedTcpTable` / `NSI` 枚举本地 TCP 监听表时，将驱动的 WSK 监听端口（如 `60817`）直接归属在 `LeechLoader.exe` 的 PID 名下，暴露加载器进程与通信端口的关联。
- **技术决策与规范**:
  1. **System (PID=4) 上下文隔离绑定**：在 [`MK_WSK_SERVER`](file:///e:/Project/Drv/MainDrv/Transport/wsk_server.h#L74-L94) 中增加 `KEVENT InitEvent` 与 `volatile NTSTATUS InitStatus`；[`WskServer_Init`](file:///e:/Project/Drv/MainDrv/Transport/wsk_server.c#L1208-L1329) 先启动 `PsCreateSystemThread(..., ProcessHandle=NULL, ..., WskServerThread)`，将 `WskRegister`、`WskCaptureProviderNPI`、`WskSyncSocket` 与 `WskSyncBind` 全部移入 [`WskServerThread`](file:///e:/Project/Drv/MainDrv/Transport/wsk_server.c#L1147-L1220) 系统线程入口处执行。
  2. **同步握手与失败回滚**：`WskServer_Init` 通过 `KeWaitForSingleObject(&g_WskServer.InitEvent)` 等待 `WskServerThread` 完成端口绑定；若绑定失败，`WskServerThread` 记录 `InitStatus`、置位 `InitEvent` 并安全退出，`WskServer_Init` 调用 `WskServer_Stop` 完整回收资源并向调用方返回精确错误码。
- **已知约束与避坑**:
  1. **严禁在 IRP Dispatch 线程上下文中直接调用 `WskSocket` / `WskBind`**：任何在用户态进程 IRP 上下文中创建的内核 WSK Socket 都会被 `tcpip.sys` 永久标记为该用户态进程 PID 所有，必须统一在 `PsCreateSystemThread(ProcessHandle=NULL)` 创建的 `System (PID=4)` 线程或 `System` 工作项上下文中创建与绑定。
  2. **零 `KeStackAttachProcess` 耦合**：直接复用 `ADR-0009` 既有单常驻系统线程 `WskServerThread` 的原生 `System` 上下文，无需引入 `KeStackAttachProcess` 切换进程。
