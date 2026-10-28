# ADR-0090: AMD NPT 高物理地址页表页解析
- **状态**: 已采纳
- **日期**: 2026-10-26
- **上下文与痛点**: WinDbg 现场出现 BugCheck 0x7E，`nvlddmkm+0xDD917E` 访问的页对应 PFN `0xF8002A0`（物理地址约 992 GiB）。AMD NPT 的动态页表遍历仍通过 512 GiB Host 物理线性窗口解析自身页表页，`host_physical_to_virtual()` 返回空指针后 `handle_npf()` 注入 `#GP(0)`，导致正常内核线程崩溃。
- **技术决策与规范**: NPT 页表页优先依据 `npt_data::free_pt_pfns[]` 回查到本 vCPU 的 Host 虚拟地址，再回退到 Host 物理窗口；该回查仅覆盖 NPT 自有页表元数据，不放宽任意物理页访问。AMD NPF 继续保留 `ensure_npt_mapped()` 的边界检查和 TLB 刷新契约。
- **已知约束与避坑**: Host 物理线性窗口仍不应被当作完整物理内存视图；高物理地址数据页必须通过 NPT identity leaf 映射访问。禁止在 VM-exit 路径调用可能返回未映射系统 VA 的 `MmGetVirtualForPhysical()`；页表池 PFN 与虚拟地址必须保持同步，`num_used_free_pts` 超界时必须拒绝回查。
