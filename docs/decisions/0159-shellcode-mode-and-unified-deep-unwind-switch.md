# ADR-0159: Shellcode 调用模式与统一深层展开开关
- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: 原有编译宏同时表达基础调用模式、方案编号和深层展开，导致方案1与方案3重复建模，方案2还拥有独立的深层宏。需要保留 Native Gadget 与 Ghost 两种基础模式，同时用一个开关统一控制私有栈隔离和原生栈嫁接。
- **技术决策与规范**: 基础模式统一使用 `VT_SHELLCODE_SPOOF_MODE`，取 `NATIVE_GADGET` 或 `GHOST_CALL`；深层行为统一由 `VT_SHELLCODE_DEEP_UNWIND` 控制。`RuntimeSlot::Reserved0` 改名为 `RuntimeFlags`，复用原有 `+0x14` ABI 位置，以 `VT_SHELLCODE_RUNTIME_FLAG_DEEP_UNWIND` 标记 X1 是否记录 `OriginalRsp` 并切换私有栈。方案1开启深层开关时即为原方案1与方案3融合，继续使用 `SpoofCallNativeInvoke`；方案2继续使用 Ghost 基础/深层调用桩。
- **已知约束与避坑**: `RuntimeSlot` 尺寸和既有偏移不得改变；基础模式只能为 1 或 2，禁止恢复独立的模式3；Ghost 模式仍必须校验并安装 `VT_SHELLCODE_GHOST_RET_RVA`；切换宏后必须重新构建 DebugShellcode、更新内嵌镜像、构建并签名驱动。深层模式必须继续满足原生 Gadget 或 Ghost 的 `.pdata` 栈帧对齐校验。
