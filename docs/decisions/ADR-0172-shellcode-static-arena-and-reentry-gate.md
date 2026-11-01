# ADR-0172: Shellcode 单页静态 Arena、深层保存区隔离与按槽位函数表加密

- **状态**: 已采纳
- **日期**: 2026-10-31
- **上下文与痛点**: 原运行时上下文通过目标 CRT 多次分配，深层调用时 X1 的非易失寄存器保存区仍位于原生栈，模态 API 重入还会覆盖同一槽位；函数表以明文指针落盘，且 Native Frame 深层路径人为限制最多一个栈参数。
- **技术决策与规范**: 将 `RuntimeSlot`、`GENERIC_RUNTIME_CONTEXT`、函数表、参数表、偏移表、运行时数据和 `Vector` 对象收敛至单个 4KB `SHELLCODE_DATA_PAGE`；Arena 位于高地址，私有栈向低地址生长，编译期保证至少 1KB；X1 在所有模式使用 `EntryBusy` 原子门禁，深层路径把完整保存区复制到私有栈后再进入分发；宿主基址取 PEB `ImageBaseAddress`；函数表按槽位加盐 XOR，调用点通过 `XOR_FN`/`VT_SPOOF_FN` 解密；Native Gadget 表按扫描得到的 `StackArgCount` 支持 0~8 个栈参数；开启 `/Gs9999999` 禁止大栈帧触发 `__chkstk`。
- **已知约束与避坑**: `RuntimeSlot` 的既有字段偏移 `value/input/state/flags/OriginalRsp/PrivateStackTop/GhostRetVa/JmpFrameSize/SpoofMode` 必须保持；首次深层 Hook 仅完成静态 Arena 自举，下一次 Hook 才进入外部 R3 调用；`dataBase` 必须至少为 4KB 且按页对齐；驱动回收 dataBase 前必须先停止 Hook、排空 RuntimeSlot 读取租约；GhostRet 仍必须由 VT 安装合法模块冷分支双视图返回点，不得回退 Native；跨多挂钩槽位时不得共享 `SPOOF_CALL_CONTEXT` 或私有栈。

## 多挂钩扩展
- X2 使用独立 MASM 入口、独立打桩标记和独立 `HOOK_CPU_CONTEXT`；深度模式先复制完整现场到副槽私有栈，回调返回后写回现场。
- 驱动分配第二个 4KB 槽页，`input` 指向 X1 主槽；`InstallAdditionalShellcodeHook` / `RemoveAdditionalShellcodeHook` 负责打桩、安装、恢复和生命周期清理。

## 后续修订（2026-11-01）
- 删除未使用的 `RuntimeTransform`、`Vector` 模板、`TransformCacheStorage` 及其初始化/释放状态字段。
- `SHELLCODE_STATIC_ARENA` 不再携带 Transform 缓存，`GENERIC_RUNTIME_DATA` 不再保留 Transform 指针或构造状态；Arena 继续保持单页边界与私有栈容量断言。
- 该清理不改变 `RuntimeSlot`、`SPOOF_CALL_CONTEXT`、调用入口或外部导出 ABI。
