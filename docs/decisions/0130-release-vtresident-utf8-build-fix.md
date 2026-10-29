# ADR-0130: Release VtResidentPayload UTF-8 编译选项修复

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: Release 配置未显式指定 MSVC `/utf-8`，而 `VtResidentPayload` 源文件含有无 BOM 的 UTF-8 中文注释。编译器错误解释注释后的声明，导致 `pte_helpers.inl`、`bridge_entry.inl` 和 `payload.cpp` 出现级联的 C2065/C1075/C2601 错误；Debug 配置因已有 `/utf-8` 未复现。
- **技术决策与规范**: 在 `vt/VtResidentPayload/VtResidentPayload.vcxproj` 的 Release `ClCompile` 节点将 `AdditionalOptions` 固定为 `/utf-8 /guard:cf- %(AdditionalOptions)`。Debug 与 Release 保持独立但均使用 UTF-8 源编码；全量 x64 构建继续由 MSBuild 后置签名脚本签署四个驱动产物。
- **已知约束与避坑**: 本修复只改变编译器源编码解析，不改变运行时逻辑；必须同时验证 Release/Debug 构建无 error/fatal error，允许现有 warning；验证阶段只编译和签名，禁止调用 `sc`、`StartService`、`NtLoadDriver` 或加载任何本地驱动。
