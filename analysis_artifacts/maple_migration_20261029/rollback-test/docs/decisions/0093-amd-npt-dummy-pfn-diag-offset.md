# ADR-0093: AMD NPT dummy PFN 通过诊断偏移显式描述
- **状态**: 已采纳
- **日期**: 2026-10-26
- **上下文与痛点**: AMD Resident memcheck 在 Scratch 修复后仍返回 `checked=0`、`verify_fail=1`。AMD 诊断记录沿用了 Intel `vcpu.ept.dummy_page_pfn` 偏移，但 AMD dummy 页位于 `vcpu.svm.npt->dummy_page_pfn`，缺少指针间接寻址。
- **技术决策与规范**: 将 `mapctl_hv_diag` 布局版本升级为 27，追加 `vcpu_off_svm_npt` 与 `svm_npt_off_dummy_page_pfn`；AMD/Intel 记录结构同步为 `0x650`。ResidentPayload 统一通过 `PayloadReadDummyPfnForVcpu()` 按后端读取 dummy PFN，AMD 先读取 vCPU 内的 NPT 指针再读取 NPT 成员，Intel 保持原 EPT 路径。
- **已知约束与避坑**: 不得把 AMD NPT 指针当作 PFN；所有偏移加法执行回绕检查并校验规范内核指针；Hypercall 91/94 的现有 Scratch、canary 和结果门禁保持不变；诊断布局变更必须同步 AMD/Intel record、Payload ABI、嵌入映像并通过 `verify_vt_layout.py`。
