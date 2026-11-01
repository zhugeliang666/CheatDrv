# ADR-0175: X1/X2 私有栈保存区复制长度修复
- **状态**: 已采纳
- **日期**: 2026-11-01
- **上下文与痛点**: x64dbg 现场显示 Native Deep 执行期间 `GENERIC_RUNTIME_CONTEXT::u` 被覆盖为低地址 `0x30882`。X1/X2 保存区的 `HOOK_CPU_CONTEXT` 实际大小为 `0x180` 字节，但私有栈复制循环使用 `0x60` 个 QWORD（`0x300` 字节），越过私有栈顶并覆盖静态 Arena，导致 `RuntimeMessageBoxDispatch` 解引用无效上下文后崩溃。
- **技术决策与规范**: X1 的保存区复制、X2 的复制到私有栈以及复制回原保存区统一使用 `mov ecx, 30h`，即复制 `0x30` 个 QWORD（`0x180` 字节）。私有栈目标仍从 `PrivateStackTop - 0x180` 开始，确保复制结束不越过私有栈顶、不触碰 `TopShadow` 和静态 Arena。
- **已知约束与避坑**: 禁止恢复 `0x60` 或按当前编译器输出猜测保存区长度；`HOOK_CPU_CONTEXT::Rax` 固定位于 `+0x178`，其完整尺寸为 `0x180`。修改汇编后必须重新构建 DebugShellcode、重新生成 `Stealth/DebugShellcodeImage.h`，再构建并签名驱动；多槽位仍必须使用独立 RuntimeSlot、上下文和私有栈。
