# ADR-0032: 内核深度防御四重门禁（代码自完整性、控制流数学不变量、DR0-DR7硬件断点自检与双向心跳保活）

- **状态**: 已采纳
- **日期**: 2026-10-16
- **上下文与痛点**:
  - 在完成 ADR-0031 会话密钥去静态化后，驱动入口仍面临高级逆向对抗风险：攻击者可能使用硬件断点（DR0~DR3）拦截 `DispatchCreate` 与 Shellcode 提取内存密钥；或者在内存中将 `ValidateToken` / `DispatchCreate` 的分支直接修改为 `NOP` (0x90) 或 `JMP` (0xEB)；或者通过伪造单次初始化调用后脱机滥用驱动。
  - 单一的布尔标志 `bAuthorized` 极易被 1 字节 Patch 攻破，必须在内核层构建纵深防御体系。

- **技术决策与规范**:
  1. **方案二：内存代码自完整性交叉校验 (In-Memory .text Hash Check)**:
     - 驱动启动时针对 `ValidateToken`、`ScanAndDecryptUserPayload`、`DispatchCreate`、`GetSessionCryptKey` 四大核心例程采样前 64 字节计算 Adler32 散列基准；
     - 在分发处理（`DispatchCommandEx`）与设备派遣入口动态比对；若发现任何字节被篡改（如 INT3 0xCC, NOP 0x90, JMP, RET），立即清零会话密钥 `TransportManager::SetSessionCryptKey(0)` 并拒绝访问。
  2. **方案三：控制流数学不变量 (Invariants Verification)**:
     - 彻底废除简单的单字节布尔标志；
     - 基于代数线性同余模型构建状态不变量：`((s_AuthInvariantA * 0x5DEECE66DULL + 0xBULL) ^ s_AuthInvariantB) == 0xC001CAFEF00D1122ULL`；
     - 仅在 Token 验证且解密有效载荷成功后方能动态建立合法的代数对 `(A, B)`；在 RPC 处理阶段校验不变量，失配即断言失败并清零密钥。
  3. **方案四：内核硬件断点自检 (DR0-DR7 Hardware Breakpoint Auditing)**:
     - 在分发主干线通过 MSVC 内核内联原语 `__readdr(7)` 审查调试控制寄存器（低 8 位 L0~L3, G0~G3 断点使能位），以及通过 `__readdr(0..3)` 审查硬件断点地址；
     - 发现断点激活立即毒化密钥并返回 `STATUS_ACCESS_DENIED`。
  4. **方案五：双向动态心跳挑战应答与超时阻断 (Mutual Challenge-Response Handshake)**:
     - 扩展心跳协议为 40 字节结构体 `LEECHRPC_MSG_HEARTBEAT`，挂载 64 位 Nonce 挑战值 `qwChallenge` 与应答值 `qwResponse`；
     - 基于不可逆的 SipHash-2-4 单向轮函数算法 `ComputeChallengeResponse(qwChallenge, qwSessionCryptKey)` 派生响应；
     - 客户端周期性（15s）发送心跳挑战，驱动校验客户端应答是否与当前密钥一致；失配立即毒化密钥并拒绝访问；
     - 驱动端生成新 Nonce 并计算对客户端挑战的应答，客户端校验驱动应答，双向免疫协议模拟、中间人劫持与重放攻击；
     - **热路径解耦决策**：高频散列读写（`READSCATTER`/`WRITESCATTER`）仅保留轻量级无锁时间戳比对 `VerifyHeartbeatAlive()`（60s 超时判定），重度断点自检与代码自完整性哈希计算收敛至低频的 `PING_REQ`/`KEEPALIVE_REQ` 心跳包内执行，消灭高频热路径的微秒级延迟与流水线停顿。

- **已知约束与避坑**:
  - **IRQL 约束**: 所有自检例程（`__readdr`、采样 Adler32、原子不变量计算、时间戳比对）均为无锁、纯计算原语，无系统大池分配，保证在 `PASSIVE_LEVEL` 至 `DISPATCH_LEVEL` 下安全稳定执行，绝不触发死锁或 `0xD1` 蓝屏。
  - **采样边界安全**: 采样必须严格受控在非分页只读代码段内部（64 字节），严禁越界盲扫引发缺页异常。
