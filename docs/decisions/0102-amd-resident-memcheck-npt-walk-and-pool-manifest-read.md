# ADR-0102: AMD Resident memcheck NPT 页表遍历与 Pool Manifest 稳定读取
- **状态**: 已采纳
- **日期**: 2026-10-28
- **上下文与痛点**: AMD-SVM 交接后的 Resident hide 验证日志出现 `checked=1024, unknown=1024`，原因是验证路径仍按 Intel EPT/VMCS 读取；同时 PoolManager 快照报告 `count=50, valid=0`，直接 Host VA 读取在交接后的 Host CR3/NPT 视图下不稳定。
- **技术决策与规范**: `PayloadDbgWatchLocatePteForVcpu` 按诊断 `flags & 2` 分流到只读 AMD NPT PML4/PDPT/PD/PT 遍历，使用 `vcpu_off_svm_npt` 和固定 `npt_data` 布局读取叶项，返回 Host physical window 中的 PTE 地址；大页分裂仍由 Host-side NPT hide 路径完成。Resident pool manifest 优先通过 `g_system_cr3` 翻译到物理页读取，失败再回退受保护 Host VA 读取，并对 `va/bytes` 做非零校验后回写 Guest。
- **已知约束与避坑**: Resident VM-exit 只读定位路径不得在 `force_split` 下修改 NPT；所有 NPT 物理页读取必须经过 Host physical window；不得将 `PayloadVmread` 用作 AMD VMCB 状态源；Pool manifest 记录为零时不得把无效块交给释放路径；构建必须同步重新嵌入 ResidentPayload 与 Bootstrap。
