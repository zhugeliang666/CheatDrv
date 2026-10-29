# ADR-0124: DebugShellcode 运行时结构通用命名与 XOR 依赖清理
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: DebugShellcode 已完成从业务项目命名向通用运行时命名的迁移，但遗留的 `XorValInternal`、`XorVal` 与 `DynamicXor.h` 只服务于旧业务模板，继续保留会增加无效依赖和命名噪声。
- **技术决策与规范**: 统一使用 `GENERIC_FUNCTION_TABLE`、`GENERIC_OFFSET_TABLE`、`GENERIC_RUNTIME_PARAMS`、`GENERIC_RUNTIME_DATA`、`GENERIC_RUNTIME_CONTEXT`、`RuntimeTransform`、`HostImageBase`、`RuntimeSlot`、`RuntimeMessageBoxInput`；初始化、dispatch、patch 和 offset 导出统一使用 `Runtime*` 名称。删除未引用的 `XorValInternal`/`XorVal` 和 `DynamicXor.h`，同步移除工程及过滤器引用；保留 `X1` 机器码入口、字段顺序、占位字节和无 CRT ABI。
- **已知约束与避坑**: 不改变结构体字段顺序、函数表槽位顺序、imm64 占位字节或 shellcode 镜像布局；禁止恢复业务专用名称和未引用 XOR 层；不加载驱动、不执行目标进程注入，仅使用四组 x64 配置编译验证。
