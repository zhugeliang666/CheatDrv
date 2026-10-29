# ADR-0122: Shellcode EXE 产物命名
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: 参考配置仍使用 `DebugShellcode`、`DeltaForceDecryptRelease` 和 `DeltaForceDecryptLLVM` 作为不同配置的目标名，部署端需要统一产物名称。
- **技术决策与规范**: Debug、Release、XRelease、XLLVMRelease 的 `TargetName` 统一为 `shellcode`，输出文件统一为 `shellcode.exe`；输出目录仍按配置隔离。
- **已知约束与避坑**: 入口保持已有 ASM `X1`，不恢复 C/C++ `Main`；不同配置的同名产物位于各自配置目录，禁止交叉覆盖。
