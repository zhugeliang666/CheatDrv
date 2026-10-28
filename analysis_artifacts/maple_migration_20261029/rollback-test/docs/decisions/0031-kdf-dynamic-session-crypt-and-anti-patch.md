# ADR-0031: 鉴权因子强绑定 KDF 动态通信密钥与去分支化抗 Patch 架构

- **状态**: 已采纳
- **日期**: 2026-10-16
- **上下文与痛点**:
  - 此前驱动的授权门禁仅在入口点（`DriverCore::DispatchCreate` / `DriverEntry`）进行校验，而后端网络（TCP/WSK、UDP）与 USB 传输层 FastCrypt 加密全链路写死了静态常量密钥 `0x8899AABBCCDDEEFFULL`。
  - 这种“守门人式”检查存在单点脆弱性：逆向攻击者一旦通过内存 Patch 入口函数（如将校验跳转改为 `jmp` 或清零错误码），驱动直接启动传输服务，攻击者直接以写死的静态密钥连接即可调用全部内核读写原语，导致防线全线崩溃。

- **技术决策与规范**:
  1. **全链路去静态化与零硬编码密钥 (Zero Hardcoded Static Key)**:
     - 彻底废除全工程中所有写死的静态 `0x8899AABBCCDDEEFFULL` 常量与默认回退逻辑。
     - 若未注入合法动态会话密钥，初始密钥严格为 `0`；`FastCrypt` 与 `NngFastCrypt` 检测到密钥为 0 时直接阻断解密流程，确保未授权状态下报文无法被解析。
  2. **端到端动态密钥下发与闭环传递链 (Cloud Key Pipeline)**:
     - **云端生成 (`keySaleSystem`)**: 客户端登录时，云端基于卡密、HWID 与过期时间动态计算 64 位 HMAC 安全熵：`$responseData["driver_crypt_key"] = EncryptUtilsService::generateAuthEntropy(...)` 并随鉴权结果加密下发。
     - **控制端接收与注入 (`DeltaForceVMMInterface`)**: 客户端解析云端下发的 `auth_entropy` / `driver_crypt_key`，并通过 `LcSetSessionCryptKey` 注入 `leechcore.dll` 本地会话，同时在发起连接串（`tcp://` / `usb://`）中附带 `,k=0x...` 参数。
     - **跨机 TCP 转发 (`host_loader`)**: 客户端调用 `host_internal_send_driver_start` 向 A 机 `host_loader` 发送 `HSTV_DRIVER_START_REQ` 时，将该 64 位云端密钥作为 `SessionToken` 透传。
     - **宿主注入内核驱动 (`mswsk.sys`)**:
       * 模式 1（服务加载）：`host_loader` 将 `SessionToken` 写入 `cfgEx.Base.SessionToken`，通过加密内存锚点注入驱动；
       * 模式 2（PTE 映射）：`host_loader` 将 `SessionToken` 写入 `bootConfig.SessionToken`，直接通过内核 Shellcode 传入驱动入口。
     - **驱动激活动态加解密 (`CheatDrv`)**: 驱动 `StartTransportByIo` 与 `DriverEntry_ManualMap` 提取 `SessionToken` 前 8 字节并原子设置 `TransportManager::SetSessionCryptKey`。
  3. **去分支化抗 Patch 效应 (Silent Breakage)**:
     - 逆向攻击者即便 Patch 绕过应用层或驱动入口跳转，但因缺失向云端发起鉴权获取的专属动态密钥，驱动与客户端协商密钥必然为 0 或错位，导致后续所有物理读写 RPC 报文头部乱码，直接静默失效瘫痪。

- **已知约束与避坑**:
  - **IRQL 约束**: `TransportManager::SetSessionCryptKey` 与 `Transport_GetSessionCryptKey` 必须支持在任意 IRQL（`PASSIVE_LEVEL` 至 `DISPATCH_LEVEL`）下被 WSK/UDP/USB 回调与工作线程无锁并发读取，内部采用 volatile / 原子读写。
  - **零静态回退铁律**: 严禁在驱动或 `leechcore` 内部保留任何诸如 `0x8899...` 的默认静态密钥回退代码；缺失密钥时必须保持未初始化/无效状态。
