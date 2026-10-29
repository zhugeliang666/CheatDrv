# ADR-0125: Shellcode 统一 dispatch 入口
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: X1 汇编入口同时 patch 并调用初始化与消息框两个 dispatch，导致入口承担业务编排、额外槽位和分支判断。
- **技术决策与规范**: X1 仅保留 `RuntimeSlot*` 与单个 `RuntimeDispatch` 槽位；C++ shellcode 内的 `RuntimeDispatch` 依次调用 `RuntimeInitDispatch` 与 `RuntimeMessageBoxDispatch`，由统一函数负责初始化结果判断和消息框调用。删除 `PatchRuntimeMessageBox`、`RuntimeMessageBoxOffset`、`RuntimeInitDispatchOffset`、`RuntimeInitFunctionOffset`，新增 `PatchRuntimeDispatch` 与 `RuntimeDispatchOffset`。
- **已知约束与避坑**: 保持 `RuntimeSlot` ABI、imm64 占位字节、X1 保存/恢复序列和 `.xinit` 镜像布局；初始化失败时不调用消息框；汇编只做现场保存、单次 dispatch 调用和恢复，不加载驱动或执行目标进程。
