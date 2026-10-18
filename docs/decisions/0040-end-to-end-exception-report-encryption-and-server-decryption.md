# ADR-0040: 全端异常上报统一端到端二进制加密与服务端解密规范
- **状态**: 已采纳
- **日期**: 2026-10-18
- **上下文与痛点**:
  - 原驱动端 `DrvSecurity::EncryptReportData` 在加密前冗余执行了 `Security_BytesToHex`，将明文字符串转成了十六进制 ASCII 串（`plainHex`），然后再对该十六进制串进行流异或加密；
  - 服务端后台（`/api/tg`）解密后还原出来的是这串十六进制 ASCII 字符（如 `5B66756E...`，即 `[functionName]...` 的 Hex 码），直接展示导致内容呈现为未经二次解码的 Hex 字符串，给排错和日志监控带来极高阅读与解析成本；
  - 客户端（`DeltaForceVMMInterface`）与驱动端的上报协议、默认目标端口及参数字段存在脱节，未形成全端统一的端到端安全传输规范。

- **技术决策与规范**:
  1. **全端对齐 9 字节加密密钥与动态 Nonce 机制**：
     - 密钥固化为 `REPORT_SECRET_KEY` = `{ 0x13, 0x5D, 0x03, 0x09, 0x5D, 0x27, 0x43, 0x44, 0x5D }`（十六进制 `"135D03095D2743445D"`）；
     - 传输载荷头部固化 8 字节随机 Nonce（4B `A` + 4B `B`），杜绝重放攻击与固定密文特征；
     - 流密钥推导：`AndValue = ~(A ^ B)`, `KeyTime = B`, `TimeKey[i] = KeyTime[i] ^ AndValue`, `finalKeyXor = sum(KeyCopy[i] ^ KeyTime[i % 4])`。
  2. **驱动端直连原始明文字节流加密**：
     - `DrvSecurity::EncryptReportData` 彻底剔除中间层 `plainHex`，直接读取 `plainStr` 的原始 UTF-8 字节进行异或流加密；
     - 密文输出体积直接减半为 `(8 + plainLen) * 2`，显著降低 WSK/TLS 发送载荷。
  3. **客户端与驱动端异常上报闭环**：
     - `DeltaForceVMMInterface.cpp` 中所有 API 导出入口（`frontend_*`）统一受 `_set_se_translator(SeTranslator)` 与 `try/catch` 保护；
     - 捕获异常后统一调用 `HandleException`，内部经 `EncryptDataHex` 算法打包为 `h=` 参数，由独立异步工作线程 POST 投递至 `/api/tg`，默认端口对齐 4000。
  4. **服务端（PHP/Python）通用解密算法规范**：
     - 服务端读取 `$_POST['h']` 并 `hex2bin`；
     - 提取 8 字节 Nonce 推导解密密钥流；
     - 异或解密后直接还原出 `[functionName]...[/status]` 等原始 UTF-8 标签文本，兼容旧版双重 Hex 容错。

- **已知约束与避坑**:
  - 严禁在加密前引入多次 Hex 转换导致解密后依然为 Hex 字符；
  - 驱动与客户端异步上报线程中若发生异常，严禁递归调用自身引发死循环崩溃。
