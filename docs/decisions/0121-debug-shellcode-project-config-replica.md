# ADR-0121: DebugShellcode 项目配置对齐 DeltaForceDecrypt
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: `DebugShellcode` 的工程配置与 `DeltaForceDecrypt` 的平台矩阵、MASM 扩展、编译优化和过滤器布局不一致，导致同一份初始化镜像在不同配置下生成差异。
- **技术决策与规范**: 复制参考项目的 Debug/Release/XRelease/XLLVMRelease Win32/x64 配置矩阵、PropertySheet、MARMASM/MASM 扩展、编译器与链接器选项、过滤器 GUID/扩展及 `.vcxproj.user`。所有配置统一为 `Application`/EXE，删除 C/C++ `Main` 依赖，链接入口统一使用已有 ASM `X1` 符号；仅保留 DebugShellcode 源文件列表和本地输出目录这两个产物适配项；Release 的 MFC 选项设为 `false`，因为当前目标不使用 MFC。
- **已知约束与避坑**: `X1` 是现有汇编入口，不能删除；不得再配置 `EntryPointSymbol=Main`。不执行 `XLLVMRelease` 的本地构建除非 ClangCL 777 工具链存在；Release 使用 `MultiThreaded` 时，外部验证程序必须使用 `/MT` 保持 CRT ABI 一致。
