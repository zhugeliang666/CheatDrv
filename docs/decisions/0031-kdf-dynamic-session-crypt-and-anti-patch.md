# ADR-0031: 鉴权因子强绑定 KDF 动态通信密钥与去分支化抗 Patch 架构

- **状态**: 已采纳
- **日期**: 2026-10-16
- **上下文与痛点**:
  - 此前驱动的授权门禁仅在入口点（`DriverCore::DispatchCreate` / `DriverEntry`）进行校验，而后端网络（TCP/WSK、UDP）与 USB 传输层 FastCrypt 加密全链路写死了静态常量密钥 `0x8899AABBCCDDEEFFULL`。
  - 这种“守门人式”检查存在单点脆弱性：逆向攻击者一旦通过内存 Patch 入口函数（如将校验跳转改为 `jmp` 或清零错误码），驱动直接启动传输服务，攻击者直接以写死的静态密钥连接即可调用全部内核读写原语，导致防线全线崩溃。

- **技术决策与规范**:
  1. **去静态化与动态密钥导出 (Dynamic Session Key KDF)**:
     - 彻底废除各模块独立的静态 `NNG_CRYPT_KEY` 常量，统一改造为动态由 `TransportManager` 管理的会话密钥。
     - 在启动传输服务（`StartTransportByIo` 及 Manual Map 初始化）时，驱动基于传入的合法 `SessionToken`（16 字节鉴权因子）通过 `DrvSecurity::SipHash24(s_DrvAuthKey, pBootConfig->SessionToken, 16)` 实时推导出专属通信密钥 `SessionCryptKey`，并原子注入 `TransportManager::SetSessionCryptKey`。
  2. **传输层全链路去分支化加解密**:
     - `wsk_server.c`、`udp_server.c`、`usb_server.c` 与底层 `FastCrypt` 统一调用 `Transport_GetSessionCryptKey()` 获取当前密钥，与每个报文自带的 Nonce 异或混合：`QWORD key = cryptKey ^ qwNonce;`。
     - 若攻击者 Patch 绕过入口但未提供合法的 `SessionToken`，驱动推导出的 `SessionCryptKey` 必然与合法客户端不匹配，导致后续所有解密出来的 RPC 报文头部与载荷彻底乱码，物理读写无法触发，实现“静默暗桩瘫痪”。
  3. **客户端适配与协议扩展**:
     - `leechcore.h` 与 `leechrpcclient.c` 扩展 URL 解析逻辑，支持在连接串中传入 `k=0x...` 或 `key=0x...`（例如 `tcp://127.0.0.1:port=10001,k=0x...`），并导出 `LcSetSessionCryptKey(QWORD qwKey)` 供上层 Loader/SDK 动态下发推导出的密钥。
     - 未配置动态密钥时安全回退至 `NNG_CRYPT_KEY_DEFAULT`，保证向下兼容性。

- **已知约束与避坑**:
  - **IRQL 约束**: `TransportManager::SetSessionCryptKey` 与 `Transport_GetSessionCryptKey` 必须支持在任意 IRQL（`PASSIVE_LEVEL` 至 `DISPATCH_LEVEL`）下被 WSK/UDP/USB 回调与工作线程无锁并发读取，内部采用 volatile / 原子读写。
  - **空 Token 防御**: 当传入全零或无效 SessionToken 时，派生出的密钥绝不应命中默认值，确保未授权状态下加密链路彻底错乱。
