# ADR-0089: AMD Resident memcheck scratch 已知 Host 范围校验
- **状态**: 已采纳
- **日期**: 2026-10-26
- **上下文与痛点**: HANDOFF_DROPCTL 的 AMD 94 号 memcheck 在请求尚未进入 `PayloadBridgeHandleMemcheck` 前返回 `PAYLOAD_RESULT_INVALID_CONTEXT`，日志表现为 `done=0/checked=0/hidden=0`。原实现只接受 `g_cached_hv_diag.vcpus + vcpu_stride` 区间；交接后 per-vCPU `status_scratch` 可能只能通过 resident arena 或其他已知 Host 映射区确认，导致合法请求被提前拒绝。
- **技术决策与规范**: 统一 `PayloadKnownHostRange` 校验，保留内核指针和整数乘法溢出检查，并允许 vCPU、resident image、arena、host-stack、direct allocation、host-state 六类已知 Host 区间。Hypercall 91 与 94 共用该入口；94 仍只接受固定 `mapctl_memcheck` 大小并继续由 `PayloadBridgeHandleMemcheck` 执行 canary、generation、逐页范围及结果门禁。
- **已知约束与避坑**: 不接受未登记的 Guest VA 或任意内核地址；不得删除 `PayloadIsKernelPointer`、区间边界和 `PayloadRangeInside` 的检查；修改后必须重新打包 ResidentPayload，并用全范围 memcheck 验证 `done=1`、`checked>0`、`hidden==checked`、`visible/unknown/translate/verify==0`。
