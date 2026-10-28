# ADR-0086: AMD-SVM 交接路径 VMX 指令防护与 BugCheck 0xDEAD0006
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: WinDbg 现场在 `ReleaseResidentBootstrap -> HANDOFF_DROPCTL` 路径捕获 `0xDEAD0006`。诊断参数显示异常向量为 `#UD`，故障 RIP 为 `VtResidentPayload+0x11B6C`，指令为 `VMREAD`；低 32 位退出码为 `0x81`（AMD `VMMCALL`）。AMD-SVM 没有 VMCS，ResidentPayload 的共享 VMX 诊断路径仍可能进入 `PayloadVmread`，导致 Root 模式非法指令。
- **技术决策与规范**: `PayloadVmread` 与 `PayloadVmwrite` 在执行 VMX 指令前统一调用 `PayloadIsAmdSvmBackend`；该判定优先读取 Resident HV diag 的 AMD 标志，并在诊断缓存尚未就绪时缓存 CPUID 厂商结果。AMD 后端直接失败关闭，不执行 `__vmx_vmread/__vmx_vmwrite`；Intel 后端保持原有 VMCS 读写路径。VMX 桥接调用方必须接受 false 返回并转入 SVM 专用诊断或状态缓冲路径。
- **已知约束与避坑**: 不得在 AMD Root/VMEXIT 上下文执行 VMREAD/VMWRITE；不得用 `0xDEAD0006` 当作普通页错误处理；AMD 状态查询、memcheck 与释放交接继续使用 per-vCPU scratch、VMCB 字段和 Guest 拷贝契约；修改后必须通过 `verify_vt_layout.py`、Release 编译和 WinDbg 实机交接复测。
