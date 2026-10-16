# ADR-0029: 用户态内存锚点加密传输、动态 Tag 直读与 Hex 路径彻底淘汰规范

- **状态**: 已采纳
- **日期**: 2026-10-16
- **涉及组件**: `CheatDrv (Main.cpp, Utils.cpp, Utils.h, Common.h)` / `host_loader (LeechLoader/utils.cpp, protocol.h)` / `loader (loader_common.h)` / `DeltaForceVMMInterface (VerifyLib)`

---

## 上下文与痛点
1. **文件过滤与 MiniFilter 暴露风险**：此前通过 `CreateFileW` 路径拼接长达数百字节的 HexPayload（`\\.\MsNetEndpoint\<HexPayload>`）在 Windows 内核文件系统中属于极度异常的路径模式（Anomalous Path Pattern），极易被反作弊（如 ACE、Vanguard、EAC）或 EDR 系统的 MiniFilter 回调捕获并触发遥测警报。
2. **内存明文残留与取证风险**：配置信息以 Hex 字符串形式驻留在用户态栈、堆和 I/O 缓冲中，容易被逆向内存 Dump 提取关键鉴权 Token、游戏名、品牌版本与服务端 API 列表。
3. **老旧路径解析代码冗余**：双端存在两套复杂的 Hex 字符串编解码逻辑，违反 Ponytail 极简原则。

---

## 技术决策与规范

### 1. 用户态加密内存锚点协议 (`DRV_USER_PAYLOAD_ANCHOR`)
- 用户态在 `.data` 节区声明 16 字节对齐的静态全局锚点结构体：
  ```cpp
  #pragma pack(push, 1)
  typedef struct _DRV_USER_PAYLOAD_ANCHOR
  {
      uint64_t Tag0;       // 动态哈希 Tag0 (由动态 Token 派生)
      uint64_t Tag1;       // 动态哈希 Tag1 (~Tag0 ^ 0xA5A5A5A55A5A5A5AULL)
      uint32_t Nonce;      // 随机 Nonce 动态盐
      uint32_t CipherLen;  // 密文长度 (sizeof(DRV_BOOT_CONFIG_EX))
      uint32_t Checksum;   // 明文 Adler32 校验和
      uint32_t Reserved;   // 对齐填充
      uint8_t  CipherData[sizeof(DRV_BOOT_CONFIG_EX)]; // RC4 密文载荷
  } DRV_USER_PAYLOAD_ANCHOR;
  #pragma pack(pop)
  ```
- **消灭静态特征码**：`Tag0` 与 `Tag1` 由当次调用的动态时间戳 Token 结合 `g_SipHashKey` 实时计算派生，内存中不存在任何固定的静态 GUID 或魔数特征，阻断反作弊特征扫描。
- **全载荷加密**：使用轻量级流密码（RC4），密钥由 `g_SipHashKey (16B) + devToken (4B) + Nonce (4B)` 动态派生，杜绝进程内存明文残留。

### 2. 驱动端进程上下文直读与“阅后即焚”抹除
- **自然上下文直读**：用户态发起 `CreateFileW(L"\\\\.\\MsNetEndpoint\\%08X", devToken)` 时，驱动 `MachenikeDispatchCreate` 同步运行在调用者线程与调用者进程虚拟地址空间（`PASSIVE_LEVEL`，当前 `CR3` 即为调用者）。
- **节区定位扫描**：驱动通过 `PsGetProcessSectionBaseAddress(PsGetCurrentProcess())` 获取调用者可执行模块基址，检索 `.data` 读写节区，根据已通过校验的 `devToken` 匹配动态 `Tag0/Tag1`。
- **解密与强校验**：使用动态派生密钥解密载荷，核验 `Adler32 Checksum` 与 `Base.Magic == DRV_BOOT_CONFIG_MAGIC`。
- **阅后即焚 (Zero Trace)**：校验成功后，驱动内核态直接执行 `RtlZeroMemory(pAnchor, sizeof(DRV_USER_PAYLOAD_ANCHOR))`，彻底物理清零用户态锚点与密文，实现用完即焚。

### 3. 彻底淘汰老旧 HexPayload 路径格式
- 彻底移除驱动与加载器中的 `EncodeCreatePayloadHex`、`Utils_ParseCreatePayloadFromFileName` 以及 `DRV_CREATE_PARAM_HEADER`。
- 打开驱动设备路径恢复为纯净的标准 8 字符动态 Token 路径（`\\.\MsNetEndpoint\1A2B3C4D`），消灭任何异常路径后缀。

---

## 已知约束与避坑
1. **IRQL 约束**：节区扫描与解密必须严格限定在 `PASSIVE_LEVEL` 执行，且必须置于 `__try / __except (EXCEPTION_EXECUTE_HANDLER)` 异常捕获块中，防范非法用户态页引发 BugCheck。
2. **多线程/对齐约束**：用户态结构体必须声明为静态全局或 `__declspec(align(16))`，确保其驻留在 `.data` 节并具备 8 字节边界对齐。
3. **UTF-8 BOM 约束**：修改后必须执行 `python convert_bom.py`。
