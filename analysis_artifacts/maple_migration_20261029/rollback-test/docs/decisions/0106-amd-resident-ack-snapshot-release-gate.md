# ADR-0106: AMD Resident ACK 快照与 DROPCTL 释放门禁

- **状态**: 已采纳
- **日期**: 2026-10-28
- **上下文与痛点**: AMD 常驻迁移阶段已经完成逐 vCPU `ack=8/8`，但旧 VtHypervisor 映像进入 freetest/quarantine 后，DROPCTL 最终再次调用 `PayloadActivateAmdSvm(QUERY)` 可能得到 `ack=0`。该查询结果依赖已进入释放流程的可变旧诊断字段，导致隐藏验证全部通过后仍返回 `STATUS_DEVICE_NOT_READY (0xC00000A3)`，控制设备无法删除。
- **技术决策与规范**: 在 Bootstrap 侧保存迁移成功时的 `ack/vcpu_count/ghv/vcpus` 快照；最终释放门禁仅在当前 `mapdriver_hv_ready()` 重新 Ping 成功且诊断中的 `ghv/vcpus/vcpu_count` 与快照完全一致时，才用已验证快照恢复 ACK。每次新的 AMD 交接开始前清空快照；直接查询成功仍优先使用实时值。
- **已知约束与避坑**: 快照不是独立成功条件，必须同时满足 Hypervisor Ping、身份一致、旧映像已卸载或隔离以及既有隐藏/迁移门禁。禁止按固定 vCPU 数量或仅凭 `ack=8/8` 放行；Intel 路径不使用该快照。
