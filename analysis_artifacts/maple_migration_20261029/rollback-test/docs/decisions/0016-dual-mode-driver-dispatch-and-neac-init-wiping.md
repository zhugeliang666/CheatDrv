# ADR-0016: 跨机双模驱动分发、自适应加载决策与 NEAC 级 INIT 节区擦除生命周期闭环

- **状态**: 已采纳
- **日期**: 2026-10-14
- **上下文与痛点**:
  1. 过去驱动加载流程僵化，`host_loader` 在宿主机上无条件释放 `Machenike.sys` 白驱动，无法区分正常系统服务模式（受信任签名直载）与白驱动 PTE 原位内存映射模式，导致不必要的磁盘文件落地和反病毒/EDR 审计特征；
  2. 核心驱动 `CheatDrv` 缺乏统一的云端分发通道与动态灰度策略，且加载进入内核后遗留完整的 `INIT` 代码段与 PE 头部结构，容易被内核转储（Dump）与静态哈希扫描捕获；
  3. `host_loader` 作为一个暂存 Staging 进程，在驱动就绪后长期常驻应用层进程列表中，为反作弊系统提供了持续的用户态进程扫描靶点。

- **技术决策与规范**:
  1. **云端核心驱动与模式下发契约**:
     - `keySaleSystem` 的 `getShellcodeDownload` 与 `getSettingCheatFiles` 统一纳管 `core_driver` 类型载荷；
     - 登录鉴权接口 `/api/key/info` 动态下发 `driver_mode`（`1`: 正常系统服务加载, `2`: 白驱动 PTE 原位内存映射）；
  2. **双机跨机方案 A 全聚合复合二进制流 (One-Shot Streaming Pipeline)**:
     - 彻底废除历史架构中 `Leech_Shellcode`、`Core_Driver`、`White_Driver` 三次独立短连接与两倍 Hex 文本明文传输；
     - 升级为 `HSTV_CMD_DRIVER_INIT_REQ`（40 字节复合头，包含 `LeechCoreSize`、`CoreDriverSize`、`WhiteDriverSize`、`SessionToken` 及 `PayloadCRC32`）；
     - 控制端与宿主端仅建立单次 TCP 会话，一次性连续流式泵送裸二进制流，端到端延迟降低 70%，内存开销降低 75%；宿主端校验整体 CRC32 后就地按偏移分发；
  3. **宿主端自适应分支与白驱动隔离**:
     - 当 `driver_mode == 2`（内存映射）：按需释放 `Machenike.sys` 与 `ComputerZ_x64.sys`，执行 PTE 劫持映射；映射完成后停止并清理白驱动；
     - 当 `driver_mode == 1`（正常加载）：**绝对严禁**向磁盘释放任何白驱动文件，直接释放并注册受信任服务；
  4. **NEAC 风格 Discardable INIT 节区与 PE 头部擦除**:
     - 驱动在 `DriverEntry` 尾部，遍历所有以 `INIT` 命名的代码/数据节区，使用 `RtlSecureZeroMemory` 强力密码学清零；
     - 顺带将 DOS 头（`MZ`）与 NT 头的 `SizeOfHeaders` 区域完全覆写清零，从物理内存层面破坏 PE 格式，阻断一切内存 Dump 与反汇编还原；
  5. **加载器生命周期自终止与双重文件粉碎闭环**:
     - `host_loader` 在确认收到内核就绪信号并成功向 B 机回传 ACK 包后，延时 500ms 保证网络数据出网，启动后台隐藏进程通过 `cmd.exe /c ping 127.0.0.1 -n 2 >nul & del /f /q ...` 彻底粉碎删除自身；随后调用 `TerminateProcess(GetCurrentProcess(), 0)` 立即自我终结退出；
     - 核心驱动在 `WskServerThread` 启动时顺道执行内核级 `ZwCreateFile(FILE_DELETE_ON_CLOSE)` 作为第二道保险粉碎磁盘文件；
  6. **驱动与 host_loader 专属双向防伪验签与激活契约**:
     - 宿主端通过 `CreateFileW("\\\\.\\MachenikeIo")` 发送 `IOCTL_MK_START_TRANSPORT`，将 B 机下发的 16 字节随机熵 `SessionToken` 传入内核；
     - 内核驱动接收到请求后，核验 `DRV_BOOT_CONFIG_MAGIC`，使用内核私钥计算 `DriverSignature = Utils_SipHash24(s_DrvAuthKey, SessionToken, 16)`，启动通信服务并回传 `DRV_BOOT_RESPONSE`；
     - `host_loader` 本地对等计算预期指纹并强校验：若指纹不匹配（遭遇 Fake Driver 拦截或 Hook 欺骗）或驱动返回错误，坚决阻断并向控制端报崩溃错误；只有验签 100% 吻合才准出就绪回执。

- **已知约束与避坑**:
  - **网络半关闭与 RST 避坑**：`host_loader` 发完 ACK 必须保留足够的网络缓冲时间（500ms），严禁在发包瞬间直接 Kill 进程导致 TCP 栈发出 `RST` 报文使 B 机报 `10054 (WSAECONNRESET)`；
  - **INIT 擦除边界**：擦除范围严格限制在 `IMAGE_SECTION_HEADER` 的 `Misc.VirtualSize` 且必须经过 `MmIsAddressValid` 探测；
  - **防 Fake Driver 审计**：严禁无校验轻信驱动加载状态；必须基于 `SessionToken` 的内核双向 HMAC/SipHash 握手，杜绝逆向者通过 Fake Driver 截获真实业务通讯；
  - **驱动模式隔离铁律**：正常加载模式（Mode 1）下严禁产生白驱动释放或注册行为，确保与标准驱动规范 100% 吻合。
