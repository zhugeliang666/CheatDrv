# ADR-0111: VT_DEBUG_RELOAD_MODE 专用卸载与重载命令

- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: 生产 handoff 会删除 Bootstrap 控制设备并让 ResidentPayload 独立驻留，后续 Loader 没有可验证的停止入口。调试阶段需要反复验证 VtHypervisor、ResidentPayload 和 Machenike 的完整卸载/重载，但不能改变生产模式的一次性隐藏流程。
- **技术决策与规范**: 仅当 `VT_DEBUG_RELOAD_MODE=1` 时启用 `loader.exe --unload`、`loader.exe --reload` 及 `--force` 重载路径。Debug 加载完成后保留 Bootstrap 控制设备和服务；`--unload` 复用 `UnloadAllDrivers()`，要求 `FULL_UNLOAD` 返回成功、全 VCPU stop ACK、旧映像/Payload 地址归零、控制设备消失及已知服务停止；`--reload` 只有在完整卸载验证通过后才重新进入一键加载。生产构建继续执行 `ReleaseResidentBootstrap()`，不提供重载入口。
- **已知约束与避坑**: `--force`/`--reload` 的卸载失败必须失败关闭，禁止继续加载造成重复 VMRUN 或旧映像引用；`FULL_UNLOAD` 保持 48 KiB 扩展内核栈与 WDF/UCXXRT `DriverUnload` 包装链；所有组件必须使用同一份 VT 配置和诊断 ABI；本地验证仅执行静态检查和编译，不在生产或开发机加载驱动。
