# ADR-0172: dxgkrnl 导出表数值哈希解算与会话密钥失步根因规约

- **状态**: 已采纳
- **日期**: 2026-11-01
- **上下文与痛点**:
  1. **Dxgk 导出函数动态解算失败**: 在 `ReleaseLLVM` 编译模式及 VT / 内存读写执行分离环境下，`ApiMonitor` 监控 `dxgkrnl.sys` 导出函数入口与基线时，`s_DxgkExports` 使用了全局指针数组 `const char *Name`。LLVM 优化将字符串常量合并归入 `.text` 可执行节区；在 VT 读零/执行原页视图下，运行时读取字符串指针返回空字节，导致哈希计算结果为 0，`Utils::GetModuleExport` 解析 6 个目标例程全部失败，触发 `ApiMonitor::DxgkExportResolveFailed (0xC000007A)` 告警，且原代码 `s_DxgkExportsResolved = TRUE` 导致首次失败后永久锁死无法自愈。
  2. **跨会话重连魔数校验失败**: 用户在客户端重新登录后重新建立 TCP 连接，触发 `MkRpc_DispatchCommand (0xC000007B: Magic mismatch)`。
- **技术决策与规范**:
  1. **纯数值哈希解算**: 在 `Core/MachenikeString.h` 中显式定义 `str_DxgkPresent (0xC3A33243)`、`str_DxgkOutputDuplPresent (0xE4AEF935)`、`str_DxgkOutputDuplGetFrameInfo (0xDB43AA8B)`、`str_DxgkSubmitCommand (0x2E7F7D5B)`、`str_DxgkGetSharedPrimaryHandle (0x1347D3A7)`、`str_DxgkLock2 (0x5B83D5CF)` 等 6 大导出函数编译期哈希常量。
  2. **消除动态指针与哈希计算**: 将 `ApiMonitor.cpp` 中的 `s_DxgkExports` 结构体成员彻底由 `const char *Name` 改为 `ULONG Hash`。解算时直接传值给 `Utils::GetModuleExport`，彻底消除运行期对 `.text` 节区字符指针的解引用与动态 `HashStringA` 计算。
  3. **去重告警与自愈重试**: 仅在 `resolvedDxgkCount > 0` 时将 `s_DxgkExportsResolved` 置为 `TRUE`；若首次未解析成功（处于分页延迟换入期），通过 `s_ReportedDxgkResolveFail` 单次去重上报，保留后续巡检轮次的自愈解析能力。
  4. **会话密钥失步根因与后端解耦**: 客户端重新登录时刷新了本地加解密会话密钥（$K_2$），但内核驱动存在常驻运行机制，导致跳过了驱动重新加载，内核 `g_SessionCryptKey` 仍持有上一轮会话密钥（$K_1$）。NNG SP 协议建立仅使用固定明文 8 字节握手（`00 'S' 'P' 00`），TCP 能正常连接，但随后客户端用 $K_2$ 加密控制报文，内核用 $K_1$ 解密导致 `dwMagic` 错乱（数学异或差值严格等于 $K_1 \oplus K_2$）。落地采用**后端会话密钥解耦方案**：在 `EncryptUtilsService::generateDriverCryptKey` 中移除动态变动的 `$expiredTime`，使同卡密同机器生成的会话密钥稳定恒定，彻底根除客户端重登后直连驱动导致的魔数校验失败。
- **已知约束与避坑**:
  - 严禁在内核只读/监控表中使用指向 `.text` 代码节的字符串指针并在运行期发起数据读取；所有 API 目标表一律采用预编译 `ULONG Hash` 常量。
  - 客户端若支持无缝重登，必须在建立连接后的首包协议中支持重新鉴权/更新会话密钥，或者在重登后显式通知驱动更新 `SessionCryptKey`。
