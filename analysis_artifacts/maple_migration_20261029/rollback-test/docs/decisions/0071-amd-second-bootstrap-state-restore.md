# ADR-0071: AMD 第二次 Bootstrap 加载的 Resident 状态恢复与模式配置顺序

- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: DROPCTL 删除 Bootstrap 后再次加载时，ResidentPayload 仍在运行，但新 Bootstrap 在 `g_payload_detached` 尚未恢复阶段优先走 Root-mode 查询，失败后未回退到本地导出；同时 AMD EPT/Hook 模式在 Host 映射建立前配置，导致 `STATUS_INVALID_PARAMETER`、`no-host-rip` 和 `STATUS_DEVICE_NOT_READY`。
- **技术决策与规范**: Resident HV 可用时先尝试 `vmcall_get_payload_status`，失败后回退 `payloadExports->get_status`；AMD 一键流程先完成状态/诊断校验、legacy detach 与 Host 映射，再写入 EPT/Hook 模式并激活 VMRUN；Machenike 状态从 ResidentPayload 恢复后跳过重复映射。
- **已知约束与避坑**: AMD 不使用 Intel HOST_RIP 作为就绪条件；Root-mode 查询失败不得遮蔽可用的本地导出查询；模式配置必须位于 Host 映射之后；失败启动必须返回明确状态并保留可重试控制路径。

