# ADR-0110: AMD ResidentPayload 迁移与旧 Hypervisor 映像释放门禁

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: AMD SVM 的 VMEXIT/VMRUN 入口由 ResidentPayload 接管后，旧 VtHypervisor 映像仍可能被错误地当作已迁移完成，导致 Loader 在旧映像仍有引用时继续加载 Machenike，或在诊断不足时释放旧映像。
- **技术决策与规范**: `VtBootstrapDriver` 在 AMD resident handoff 完成后，必须同时验证 Payload 屏障、Resident SVM 诊断、8 个 VCPU Ping、旧映像 quarantine 状态；Release 配置还必须验证旧映像 `base/size=0` 后才准出。Loader 使用同一 `vt_config.h` 门禁，拒绝未完成旧映像释放的运行态。`VT_DEBUG_RELOAD_MODE=1` 只关闭隐藏/双视图并保留控制面，供反复 FullUnload/Reload 调试。
- **已知约束与避坑**: `host_rip=0` 是 AMD 固定 VMRUN 后端的正常值，不得套用 Intel HOST_RIP 门禁；迁移验证失败时不得释放旧映像或继续进入 Machenike；Payload 的 VMEXIT 核心、VCPU 状态与 Host Stack 必须保持驻留；任何释放前都必须在 PASSIVE_LEVEL 完成引用扫描和全核 ACK。
