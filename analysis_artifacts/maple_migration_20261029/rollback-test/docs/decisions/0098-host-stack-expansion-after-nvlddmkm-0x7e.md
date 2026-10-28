# ADR-0098: Host Stack 扩容与 nvlddmkm 异常分发双重故障隔离
- **状态**: 已采纳
- **日期**: 2026-10-27
- **上下文与痛点**: WinDbg 现场首个异常位于 `nvlddmkm!nvDumpConfig+0xDD917E`，读取值为 `0xFFFFFFFFFFFFFFFF`；异常分发期间 `nt!_chkstk` 探测 `ffffcd000b24f000`，该页位于 64 KiB 自定义 Host Stack 下界之外，随后形成 `0x7F/Arg1=8` 双重故障并破坏首个异常现场。
- **技术决策与规范**: `hv::host_stack_size` 与 `PAYLOAD_HOST_STACK_SLOT_SIZE` 统一从 `0x10000` 扩大到 `0x40000`，保持页对齐；VtHypervisor、ResidentPayload、Bootstrap 与 Loader 必须同批重建并重新嵌入运行时映像。Host Stack 只承载 VM-Exit/桥接处理，普通 Windows/NVIDIA 执行流继续使用原始线程栈。
- **已知约束与避坑**: 扩容只能阻断二次栈耗尽，不能把 `nvlddmkm` 的 `-1` 指针读取误判为已修复；若首个异常仍复现，继续沿 AMD NPT 高物理页映射与双视图读路径取证。禁止恢复 64 KiB 旧常数，禁止只重建 Hypervisor 而复用旧 Bootstrap 嵌入副本；卸载前必须恢复 Host RSP 并完成全核确认。
