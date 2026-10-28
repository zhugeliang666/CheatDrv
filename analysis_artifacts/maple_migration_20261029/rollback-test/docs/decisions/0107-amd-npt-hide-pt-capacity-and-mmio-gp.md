# ADR-0107: AMD NPT 隐藏页表容量与高地址 MMIO #GP 修复

- **状态**: 已采纳
- **日期**: 2026-10-28
- **上下文与痛点**: WinDbg 捕获 `SYSTEM_SERVICE_EXCEPTION (0x3B)`，现场为 `nt!KiGeneralProtectionFault -> nvlddmkm+0x85b4b9`。故障虚拟地址映射到 NVIDIA 高物理地址 BAR/MMIO 区域；AMD NPF 映射失败路径注入 `#GP(0)`。同批隐藏操作提交约 31507 个 PFN，而每个 vCPU 原先仅有 0x400 个可用于 2MiB 分裂的 PT 页，离散物理页可能耗尽容量。
- **技术决策与规范**: AMD NPT 每个 vCPU 的 PT 页池扩展到 `0x1000`；`split_2mb_pde` 与高物理地址 `ensure_npt_mapped` 在容量耗尽时递增尾部诊断计数并返回失败，禁止越界使用页表池。既有动态 PML4/PDPT/PD 建立与 TLB 刷新契约保持不变；修改后必须同批重建 VtHypervisor、ResidentPayload 与 Bootstrap。
- **已知约束与避坑**: PT 页池属于每个 vCPU 的非分页内存，扩容会增加常驻内存；不能在 VM-exit 路径动态分配分页内存。高地址 MMIO 不是 PFN 数据页，不能交给 Host 512GiB 线性窗口读取；复测时必须检查 `num_used_free_pts`、`split_failures`、`dynamic_map_failures` 与 `diag_hide_pte_null`，并验证 NVIDIA `DdiEscape` 不再进入 `KiGeneralProtectionFault`。
