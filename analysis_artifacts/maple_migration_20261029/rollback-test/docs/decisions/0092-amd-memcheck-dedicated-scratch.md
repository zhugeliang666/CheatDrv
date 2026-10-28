# ADR-0092: AMD Resident memcheck 使用独立扩展 Scratch 缓冲
- **状态**: 已采纳
- **日期**: 2026-10-26
- **上下文与痛点**: `mapctl_memcheck` 为 `0x2258` 字节，而 per-vCPU `status_scratch.status_bytes` 仅为 `0x20B8` 字节。AMD Hypercall 94 仍把完整 memcheck 请求拷入 status 缓冲，尾部写越界覆盖 canary，导致 `HANDOFF_DROPCTL` 回读 `checked=0` 并返回 `STATUS_INVALID_PARAMETER`。
- **技术决策与规范**: 保留 `payload_status` 的 `0x20B8` status 缓冲及其 ABI，新增每 vCPU `memcheck_bytes[0x2258]` 专用缓冲；Hypercall 94 的输入、ResidentPayload 分发和回写全部使用专用缓冲；以 `static_assert(sizeof(mapctl_memcheck) == vcpu_memcheck_scratch_bytes)` 固定跨环尺寸契约。
- **已知约束与避坑**: Hypercall 91 继续使用 status 缓冲和原有长度门禁；Hypercall 94 不得复用 status 缓冲；扩展缓冲必须与 vCPU Host CR3 映射同寿命，仍受 canary、`in_use`、generation 和 Guest 拷贝失败注入 `#PF` 保护；修改后必须重建 VtHypervisor 并复测 handoff memcheck。
