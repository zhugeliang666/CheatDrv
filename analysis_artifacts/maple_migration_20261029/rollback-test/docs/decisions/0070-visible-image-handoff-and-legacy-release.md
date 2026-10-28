# ADR-0070: 可见映像模式下释放 VtHypervisor 与卸载 VtBootstrapDriver

- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: 历史 `VT_IMAGE_HIDE_ENABLED=0` 会同时影响两类映像；`HANDOFF_DROPCTL` 需要根据 Payload 独立开关决定是否执行 Resident 隐藏验证，同时 ADR-0067 的默认隔离策略令 AMD 旧 VtHypervisor 映像保持 `retained=1`。
- **技术决策与规范**: 将 `VT_AMD_RELEASE_LEGACY_IMAGE_AFTER_HANDOFF` 默认值改为 `1`，仅在全核 Resident ACK、RELEASE finalizer、CRT 卸载包装器和零引用扫描全部通过后释放旧 VtHypervisor 映像。`HANDOFF_DROPCTL` 仅在 `VT_PAYLOAD_IMAGE_HIDE_ENABLED=1` 时执行 Payload 隐藏与隐藏证明；可见模式直接进入 `mapdriver_install_resident_bootstrap_unload()`，保留 WDF/UCXXRT 包装器链并由 SCM 卸载 VtBootstrapDriver。
- **已知约束与避坑**: Resident ACK 不完整、引用扫描非零、RELEASE 失败或轻量卸载门禁未安装时必须失败关闭；严禁覆盖 `DriverObject->DriverUnload`，严禁绕过 UCXXRT/WDF 清理链；VtHypervisor 释放后由 VtResidentPayload 继续承载 AMD VMRUN/VMEXIT 闭环。
