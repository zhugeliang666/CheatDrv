# ADR-0116: 删除旧 VMCALL Hook Hypercall 接口
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: VTCall 已由 `VhInstall/VhEnable/VhDisable/VhRemove` 统一托管，旧的 `Add/Enable/Disable/RemoveVMCALLHook` 仍残留在 Hypercall 枚举、Resident 分派和备份包装器中，造成重复入口与 ABI 维护风险。
- **技术决策与规范**: 删除旧 52-55 号 VMCALL Hook 名称、Resident 处理器、Hypervisor fail-closed 分支和备份包装器；通过显式指定 `hypercall_eh_install = 56` 保持现有 EPT/VTCall 及后续 Hypercall 编号不变。活动路径只保留 `VhInstall/VhEnable/VhDisable/VhRemove/VhUninit`。
- **已知约束与避坑**: 禁止压缩枚举后让 56-97 号 ABI 发生位移；Bootstrap、VtHypervisor、ResidentPayload 必须同步重建；删除后旧 52-55 请求按未知 Hypercall 处理，不再进入兼容逻辑。
