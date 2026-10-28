# ADR-0058: 全局 ETW Provider 哈希表启发式巡检与 ACE 注册回调只读监控引擎
- **状态**: 已采纳
- **日期**: 2026-10-23
- **上下文与痛点**:
  - 腾讯反作弊（ACE / TP）在内核驱动中可能通过 `EtwRegister` 注册专有 Provider 或 ETW-TI 接收例程，用于隐蔽通道通信与系统遥测；
  - 针对 ETW 结构的强写或脱钩会直接触发 PatchGuard（`BugCheck 0x109`），必须实施 100% 只读审计；
  - `ntoskrnl.exe` 的全局散列表 `EtwpGuidHashTable`（`64` 桶 `_ETW_HASH_BUCKET`）属于未导出符号，且 Win10/11 单桶结构为 `LIST_ENTRY[3] + EX_PUSH_LOCK`（步长 `0x38`），严禁假定为 `0x10` 步长或使用脆弱的硬编码偏移。

- **技术决策与规范**:
  1. **纯静态类架构与 60 秒自适应节拍 (`EtwMonitor`)**:
     - 在 [Stealth/EtwMonitor.h](file:///e:/Project/Drv/CheatDrv/Stealth/EtwMonitor.h) 与 [Stealth/EtwMonitor.cpp](file:///e:/Project/Drv/CheatDrv/Stealth/EtwMonitor.cpp) 实现纯静态类 `EtwMonitor`，0 虚函数、0 实例；
     - 挂载至 [Core/DriverCore.cpp](file:///e:/Project/Drv/CheatDrv/Core/DriverCore.cpp) 的 `ExecuteDeepSecurityScans`（类型 6）：未检测到 ACE 时重置节拍并零开销短路返回；检测到 ACE 时立即执行首次扫描，随后严格按 **60 秒周期（10s × 6）** 低频巡检。
  2. **双轨符号定位与多布局自适应验证 (Multi-Layout Self-Validation)**:
     - 路径 A: 使用预计算哈希（`str_EtwRegister` / `str_EtwEventRegister` / `str_EtwUnregister`）解析导出例程，支持最多 3 层 `E8` 子调用递归与 `0x48/0x4C` REX 前缀 `lea reg64, [rip + disp32]` 解码；
     - 路径 B: 解析 `ntoskrnl` PE 节表，仅在常驻非分页 `.data` 节区范围内精准扫描；
     - 自适应探测 `_ETW_HASH_BUCKET` 步长（`0x38` 含 3 链表 + PushLock、`0x18` 含 1 链表 + PushLock、`0x10` 紧凑表），定位失败后置位 `s_EtwLocateAttempted` 熔断，严禁在周期任务中重复盲扫。
  3. **偏移自学习缓存、跨页防护与 128 槽永久去重（仅报新增）**:
     - 首次命中合法 `_ETW_REG_ENTRY` 后，自动将 `s_CachedRegListOffset` 与 `s_CachedBackPtrOffset` 缓存固化，后续节点直接 O(1) 定位，消除 `6 × 4` 内层试探循环，并将空桶桶头 `MmIsAddressValid` 降至 0 次（单次全表扫描仅需 ~60µs）；
     - 强制使用 `Utils::IsValidKernelRange(ptr, size)` 校验结构体首尾跨页有效性，根除 `BugCheck 0x50`；
     - 采用绑定 `(ModuleHash << 32) | aceRva` 的 128 槽位只增不覆写永久去重表，已上报过的回调在驱动全生命周期内绝不重复上报，仅当出现全新回调时才触发告警。

- **已知约束与避坑**:
  - 严禁将 `EtwpGuidHashTable` 当作步长 `0x10` 的裸 `LIST_ENTRY[64]` 遍历（Win10/11 真实步长为 `0x38`）；
  - 严禁向 `Utils::HashStringA` 传入 `Length = 0`（会导致直接返回 `0` 致使导出查找失效）；
  - 严禁仅校验结构体首地址 `MmIsAddressValid(ptr)` 后直接解引用 `+0x08 ~ +0x48` 偏移（跨页边界必须校验尾字节）；
  - 严禁覆盖去重表槽位或清空已上报 ETW 指纹导致周期重报。
