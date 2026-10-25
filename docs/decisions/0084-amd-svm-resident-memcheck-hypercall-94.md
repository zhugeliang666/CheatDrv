# ADR-0084: AMD SVM Resident memcheck Hypercall 94 路由闭环

- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: AMD SVM Resident 路径未在 VM-exit 分派 `hypercall_verify_hide_pfn_list`（94），隐藏验证请求直接返回 `STATUS_INVALID_PARAMETER (0xC000000D)`，导致 `resident hide verify` 的 `checked/hidden/visible` 均为 0。Intel/VMX 路径已有同一 memcheck 处理，AMD 需要与现有 91/92/93 Resident ABI 保持对称。
- **技术决策与规范**: AMD SVM 在 94 号分支使用每 vCPU `status_scratch` 作为 Host CR3 已映射的暂存区；先逐页复制 Guest `mapctl_memcheck` 入暂存区，再调用 ResidentPayload `PayloadAmdControlDispatch(94, ...)`，由 `PayloadBridgeHandleMemcheck` 完成验证，最后使用 `copy_to_guest` 写回并在失败时注入 Guest `#PF`。ResidentPayload 对 94 号请求强制校验规范内核指针、完整 vCPU scratch 范围和结构体长度；校验通过后复用既有 memcheck 核心，避免新增全局临时缓冲。
- **已知约束与避坑**: 不得在 Host CR3 上下文直接解引用 Guest VA；不得把 94 号请求落入默认分支并推进 Guest RIP；暂存区必须使用 canary、`in_use` 和 generation 防止跨核撕裂；scratch 范围缓存无效时 fail-closed。新增或调整 Hypercall 时必须同步核验 VMX 与 AMD Resident 分派，并完成 ResidentPayload、VtHypervisor 两个 Release 构建。
