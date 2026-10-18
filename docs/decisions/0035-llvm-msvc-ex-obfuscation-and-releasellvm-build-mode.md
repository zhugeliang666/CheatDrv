# ADR-0035: LLVM-MSVC 混淆编译工具链深度整合与 ReleaseLLVM 编译模式规范

- **状态**: 已采纳
- **日期**: 2026-10-18
- **上下文与痛点**:
  反作弊系统（如 ACE、Vanguard 等）与安全研究人员在逆向分析内核驱动时，通过 IDA Pro / Ghidra 的反编译（Decompiler）可以轻松还原驱动的核心业务逻辑、函数调用链及敏感算法控制流。为了最大化提升静态与动态逆向破译成本，需要将驱动代码经由高阶控制流平坦化（-fla）、虚假控制流注入（-bcf）、指令替换（-sub）、MBA 混合布尔代数替换（-mba-subs）、常量混淆（-const-obfus）及字符串加密（-string-obfus）进行全量深度混淆，同时必须保持与原生 WDK 驱动打包签名、DriverEntry 导出及 Zero IAT 契约的 100% 相容。

- **技术决策与规范**:
  1. **构建工具链与自定义编译器注入**:
     - 在 `Machenike.vcxproj` 中新增 `<ProjectConfiguration Include="ReleaseLLVM|x64">` 专属配置；
     - 保持 WDK 平台工具集 `<PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>` 保证内核系统宏与驱动打包签名流程不变；
     - 通过设置 `<CLToolExe>clang-cl.exe</CLToolExe>` 与 `<CLToolPath>E:\Project\llvm-msvc-ex\install-release-64\bin</CLToolPath>` 将编译前端重定向至定制版 LLVM-MSVC (v777.2.9)；
     - 通过设置 `<LinkToolExe>lld-link.exe</LinkToolExe>` 与 `<LinkToolPath>E:\Project\llvm-msvc-ex\install-release-64\bin</LinkToolPath>` 彻底根除 MSVC `link.exe` 链接混淆 COMDAT 符号节区时触发的 `LNK1143` 致命错误；
  2. **混淆参数矩阵与防护优化**:
     - 编译选项统一注入：
       ```text
       -mllvm --string-obfus -mllvm --const-obfus -mllvm --sub -mllvm --bcf -mllvm --bcf_prob=70 -mllvm --mba-subs -mllvm --mba-prob=80 -mllvm --bcf_loop=1
       ```
     - 注入 `-Wno-missing-field-initializers -Wno-unused-but-set-variable` 清除 Clang 严格语法告警；
  3. **Zero IAT 与栈探针防御兼容**:
     - 针对 Clang 默认栈探测例程，追加 `-Xclang -mno-stack-arg-probe -mstack-probe-size=9999999`，配合 `/Gs9999999` 彻底消除 `ntoskrnl.exe!__chkstk` 导入；
     - 在 `Common.h` 中实现内联 `SafeStrlen` 原语并重定向 `strlen`，消除外部 `ntoskrnl.exe!strlen` 导入，确保混淆后的产物维持绝对的 100% 0 导入表（Import Directory 与 IAT Directory 均为 0 [0]）；
  4. **工程自删除逻辑防御闭环**:
     - 在 `DriverCore.cpp` 中自建基于 `UserVar->Func.ZwCreateFile(..., FILE_DELETE_ON_CLOSE)` 与 `ZwClose` 的 `ForceDeleteFile` 静态函数，彻底清除未声明标识符隐患，杜绝任何外部未决符号。

- **已知约束与避坑**:
  1. **链接器选型铁律**: 严禁在 LLVM 混淆模式下使用 MSVC 原生 `link.exe`（必触发 `LNK1143`），必须通过 `lld-link.exe` 完成符号解析与代码节区合并；
  2. **栈探针双重抑制**: 必须同时保留 `/Gs9999999` 与 `-Xclang -mno-stack-arg-probe`，防止大尺寸局部变量或混淆展开后的状态机触发系统栈探测函数；
  3. **双模式兼容**: 确保标准 `Release` 模式（MSVC 原生极速构建）与 `ReleaseLLVM` 模式（深度混淆生产构建）并行无冲突，且产物均为 0 导入表。
