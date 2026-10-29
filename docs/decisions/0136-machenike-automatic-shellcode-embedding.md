# ADR-0136: Machenike 编译前自动更新内嵌 DebugShellcode 镜像
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: DebugShellcode 变更后，手工重新生成 `Stealth/DebugShellcodeImage.h` 容易造成驱动继续使用旧字节数组、入口 RVA 或镜像大小。Machenike 的编译过程需要与 VT 框架的嵌入更新链一致，在编译驱动前先获得当前 shellcode 产物并刷新头文件。
- **技术决策与规范**: `Machenike.vcxproj` 增加 `UpdateEmbeddedDebugShellcode`，在 x64 `PrepareForBuild` 前增量构建 `DebugShellcode\DebugShellcode.vcxproj` 的 `Debug|x64` 产物，再调用 `DebugShellcode\generate_embed.py` 解析 PE 导出、入口 thunk、运行时分发 RVA、镜像大小和 SHA-256，原子更新 `Stealth\DebugShellcodeImage.h`。头文件保持静态字节数组，驱动运行时不读取 shellcode 文件；生成器内容不变时报告 `Up-to-date`，失败则终止 Machenike 编译，禁止继续使用陈旧数组。
- **已知约束与避坑**: 仅对 x64 配置启用，当前内嵌 ABI 固定取 DebugShellcode Debug 输出；生成器要求 x64 PE、`X1ImageSize`/`RuntimeDispatch` 导出和预期 thunk，所有 RVA/节区范围均做边界校验。构建验证只执行离线 MSBuild 与签名，不执行本地驱动加载；产物生成后仍必须执行固定签名命令并确认 `Signature success!`。
