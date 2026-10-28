# ADR-0097: AMD Resident 诊断版本使用 ABI 宏
- **状态**: 已采纳
- **日期**: 2026-10-27
- **上下文与痛点**: `mapctl_ioctl.h` 已将诊断 ABI 升级为 27，但 AMD SVM Resident 的 `hypercall_get_resident_hv_diag` 仍硬编码写入版本 26，导致 Loader 在驱动已成功启动后仍拒绝 `MigrateCheck`，Machenike 无法进入加载阶段。
- **技术决策与规范**: `vt/VtHypervisor/amd/svm-exit.cpp` 的 `resident_hv_diag_record::version` 改为 `MAPCTL_HV_DIAG_LAYOUT_VERSION`。诊断版本只能来自共享 ABI 头文件，禁止在后端路径写死数值；Bootstrap、Hypervisor 与 Loader 必须同批重建和部署。
- **已知约束与避坑**: 仅替换 Loader 不会修复 AMD SVM 返回值；必须重建 `VtHypervisor.sys` 并重新嵌入 `VtBootstrapDriver.sys`。目标机若仍显示 `driver_diag=26`，说明兼容路径副本或已加载服务映像未被替换。
