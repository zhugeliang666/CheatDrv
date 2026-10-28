# ADR-0101: AMD NPT 高 PFN 强制分裂前置映射
- **状态**: 已采纳
- **日期**: 2026-10-28
- **上下文与痛点**: WinDbg 再次捕获 `BugCheck 0x7E`。`nvlddmkm+0xDD917E` 的读取地址对应 PFN `0xF8002A0`（物理地址约 992 GiB），现场日志在 `handoff dropctl hide host-stack enter` 后停止。AMD 隐藏 PFN 路径直接调用 `get_npt_pte(..., true)`，当对应动态 PML4/PDPT/PD 尚未建立时返回空指针；Guest 首次访问该页触发 NPF，映射失败路径注入 `#GP(0)`，系统线程随即进入 `0x7E`。
- **技术决策与规范**: `get_npt_pte` 在 `force_split=true` 且页表项缺失或未 present 时，先校验物理地址不超过 52 位，再调用 `ensure_npt_mapped` 建立动态页表路径，重新取得 PDE 后执行 2 MiB 分裂与 PTE 返回。`force_split=false` 保持查询语义，不隐式创建页表。隐藏 PFN、挂钩和单步路径统一复用该前置映射契约。
- **已知约束与避坑**: Host 物理线性窗口仍为 512 GiB，不能作为完整物理内存视图；高 PFN 不能直接交给 `host_physical_to_virtual`；`ensure_npt_mapped` 失败时必须跳过隐藏/挂钩并递增诊断计数，禁止把普通 NPF 转换为未区分来源的 `#GP(0)`；修改后必须同批重建 VtHypervisor、Bootstrap 与嵌入载荷，并进行 AMD 实机 `handoff-dropctl` 复测。
