# ADR-0121: DebugShellcode 项目配置对齐 DeltaForceDecrypt
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: `DebugShellcode` 的工程配置与 `DeltaForceDecrypt` 的平台矩阵、MASM 扩展、编译优化和过滤器布局不一致，导致同一份初始化镜像在不同配置下生成差异。
- **技术决策与规范**: 复制参考项目的 Debug/Release/XRelease/XLLVMRelease Win32/x64 配置矩阵、PropertySheet、MARMASM/MASM 扩展、编译器与链接器选项、过滤器 GUID/扩展及 `.vcxproj.user`。所有配置统一为 `Application`/EXE，删除 C/C++ `Main` 依赖，链接入口统一使用已有 ASM `X1` 符号；仅保留 DebugShellcode 源文件列表和本地输出目录这两个产物适配项；Release 的 MFC 选项设为 `false`，因为当前目标不使用 MFC。
- **已知约束与避坑**: `X1` 是现有汇编入口，不能删除；不得再配置 `EntryPointSymbol=Main`。不执行 `XLLVMRelease` 的本地构建除非 ClangCL 777 工具链存在；Release 使用 `MultiThreaded` 时，外部验证程序必须使用 `/MT` 保持 CRT ABI 一致。

## 当前 Shellcode 配置规范（2026-11-01）

### 配置矩阵

| 配置 | 工具链 | WPO/`/GL` | 字符集 | 关键预处理定义 | 备注 |
|---|---|---|---|---|---|
| `Debug|x64` | MSVC `v143` | 未启用 | `Unicode` | `_DEBUG;_CONSOLE` | 调试入口使用 `X1`，Console 子系统 |
| `Release|x64` | MSVC `v143` | **关闭** | `MultiByte` | `NRELEASE;NDEBUG;_CONSOLE` | 稳定发布基线；禁止 `/GL`/`/LTCG` |
| `XRelease|x64` | MSVC `v143` | 启用 | `MultiByte` | `NDEBUG;_CONSOLE;_DYNAMIC_XOR_VAR_USER_` | 仅在工具链与源码兼容时使用 |
| `XLLVMRelease|x64` | `ClangCL`，LLVM `777` | 启用 | `MultiByte` | `NDEBUG;_CONSOLE;_DYNAMIC_XOR_VAR_USER_` | 需要本机存在对应 ClangCL 工具链 |

### 所有 x64 配置的共同规则

1. 工程类型固定为 `Application`，入口固定为 ASM `X1`；不得引入 C/C++ `main` 或把入口改成 `Main`。
2. 运行库使用 `MultiThreaded`（`/MT`），关闭 C++ 异常和栈安全检查；编译附加选项保留 `/Gs9999999`，避免生成 `__chkstk` 调用。
3. 链接器使用 `X1` 入口；Release 系列使用 Windows 子系统、COMDAT 折叠和引用优化，默认库按当前工程规则处理。
4. 代码/常量布局保持：`.data -> .xconst`、`.rdata -> .xconst`、`.xinit -> .text`，并以 `/SECTION:.xconst,R` 生成最终镜像；MASM 与 MARMASM 的 props/targets 必须同时保留。
5. 输出目标名统一为 `shellcode.exe`，输出目录为 `$(ProjectDir)..\\bin\\DebugShellcode\\$(Configuration)\\`，中间目录为 `$(ProjectDir)..\\x64\\DebugShellcode\\$(Configuration)\\`。

### `/GL` 库帮助器兼容约束

`Release|x64` 必须显式设置 `<WholeProgramOptimization>false</WholeProgramOptimization>`。该配置曾在 `DebugShellcode.cpp` 使用 `memset` 时产生 MSVC `C2268`（编译器预定义库帮助器不支持 `/GL`），随后链接阶段产生 `LNK1257`；因此当前稳定基线禁止在该配置隐式开启 `/GL` 或 `/LTCG`。如未来重新启用，必须先完成同一工具链下的全量编译验证，并确认编译命令和链接命令分别不再触发库帮助器限制。

### 构建验收顺序

1. 先执行 `MSBuild DebugShellcode\\DebugShellcode.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64 /m /nologo`，确认退出码为 0，且命令行不含 `/GL`、`/LTCG`。
2. 再执行 `Machenike.sln` 的 `Release|x64` 构建；成功后才允许刷新 `Stealth\\DebugShellcodeImage.h` 并继续宿主/驱动产物构建。
3. 生成新的驱动产物后必须完成既定签名校验；构建失败不得使用旧的嵌入 Shellcode 镜像继续打包。
