# ADR-0112: Debug 控制面保留与生产隐藏功能同开

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: Debug 重载原先通过关闭 Payload 隐藏、Machenike `.text` 双视图和 Resident Pool 隐藏来降低卸载风险，导致调试路径与生产隐藏路径不一致，隐藏相关故障无法在可重载流程中复现。
- **技术决策与规范**: `VT_DEBUG_RELOAD_MODE=1` 只覆盖 `VT_BOOT_KEEP_CONTROL_DEVICE=1`、`VT_BOOT_DROP_CONTROL_DEVICE=0`，不再关闭任何 Payload/Machenike 隐藏宏；Payload 映像、`.text` 双视图、Direct、Arena、Host Stack、Resident Pool 隐藏均保持默认开启。Debug `FULL_UNLOAD` 同时强制 `VT_FULL_UNLOAD_PRE_UNHIDE_ENABLED=1`，在仍有 Hypervisor 全核 VMCALL 能力时解除隐藏，随后完成 VCPU stop ACK、引用归零并释放 Payload、Arena 和控制设备。
- **已知约束与避坑**: 控制设备是唯一保留入口，必须在隐藏验证完成后保留到 `--unload`；卸载顺序固定为停止 Machenike、在 VT 仍活跃时解除 Payload/EH/Pool 映射、停止全核 VCPU、释放引用、删除控制设备；任何 unhide、stop ACK、引用归零或控制设备消失验证失败都必须保持运行态并返回失败。生产模式宏值与 handoff 行为不变。
