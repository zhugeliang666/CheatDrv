# ADR-0081: PoolManager 分配跟踪与 resident 隐藏开关解耦
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: Payload 映像隐藏开关关闭时，PoolManager 仍必须继续承担手动映像分配、resident 清单、quarantine 与卸载释放；若将 PoolManager 生命周期直接绑定到隐藏宏，容易造成释放路径缺失或隐藏关闭后仍发出 PFN/EPT/NPT 操作。
- **技术决策与规范**: `VT_POOLMANAGER_ENABLED`、`VT_POOLMANAGER_TRACK_RESIDENT_BLOCKS` 控制分配与清单能力；`VT_POOLMANAGER_HIDE_RESIDENT_BLOCKS` 仅在 `VT_PAYLOAD_IMAGE_HIDE_ENABLED && VT_HIDE_PAYLOAD_ENABLED && VT_HIDE_RESIDENT_POOLS_AFTER_HANDOFF` 全部满足时启用 PFN 隐藏；`VT_POOLMANAGER_HOSTMAP_RESIDENT_BLOCKS` 同步控制 Host 映射；`VT_POOLMANAGER_EXCLUDE_PAYLOAD_IMAGE=1` 强制排除映像 block。Machenike 独立隐藏宏不参与 PoolManager 判定。
- **已知约束与避坑**: 隐藏关闭时仍初始化和释放 PoolManager，禁止调用 `vmcall_hide_pfn_list`/`vmcall_unhide_pfn_list`；隐藏开启时 resident 快照失败必须阻断交接验证；Payload `.text` 只由 EH 双视图处理，不能再次进入 PoolManager PFN→dummy 路径。
