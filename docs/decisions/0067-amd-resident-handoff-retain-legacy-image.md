# ADR-0067：AMD Resident Handoff 默认保留旧 Hypervisor 映像

- 状态：已采纳（稳定性隔离）
- 日期：2026-10-25
- 关联：ADR-0055、ADR-0066

## 现场证据

最新实机日志证明 8 个 vCPU 全部完成 Resident VMRUN 切换，`ack=8/8`；旧映像随后
通过引用扫描并被释放，记录 `phase=4`、`test=... -> 0/0`、`refs=0`。Bootstrap
继续正常返回 `DriverMain leave final_status=0x00000000`，但系统随后直接硬复位，未进入
Windows BugCheck 路径，也未生成转储。

因此 ADR-0066 的诊断记录跨页写修复已经越过其原故障点；当前最高证据边界转移到
“Resident VMRUN 已 ACK、旧映像已释放、后续 VMEXIT/控制 Hypercall”区间。数据引用
扫描只能证明已枚举对象中没有旧映像地址，不能证明延迟控制流、未枚举函数指针或
Root-mode 异常返回路径已全部脱离旧映像。

## 方案比较

1. **继续自动释放并增加延时**：不能改变潜在延迟执行引用的有效性，硬复位仍可能发生。
2. **完成 Resident ACK，但默认保留 unloaded/quarantined 旧映像**：不改变活动 VMCB、
   NPT、Host Stack 或 Hypercall ABI；仅撤销自动回收，使潜在旧代码地址继续可执行，
   并保留手动 RELEASE 用于后续二分。

选择方案 2。复杂度和热路径开销为零，代价是保留约 `0x18B4000` 字节旧映像虚拟空间。

## 技术决策与契约

- 新增 `VT_AMD_RELEASE_LEGACY_IMAGE_AFTER_HANDOFF`，默认值为 `0`。
- AMD 路径仍执行 legacy detach、Pool adoption、Host mapping、全核 Resident ARM/ACK、
  `unload_common(... keep_payload=true ...)` 与 cutover clear。
- 默认分支不再自动调用 `mapdriver_free_test_image_control`；成功必须同时满足旧映像
  `base/size != 0`、`testDriverUnloaded != 0`、`testDriverImageQuarantined != 0`。
- Loader 的 AMD 门禁接受两种状态：完整 released，或完整 retained-quarantine；两种
  状态都必须完成 detach、提供 resident-loop/ack 偏移并清零旧 VM-exit targets。
- Intel 路径、`resident_hv_diag_record` 的 `0x640` ABI、Hypercall 编号和手动 RELEASE
  IOCTL 保持不变。

## 回滚与验证

回滚恢复 `vt/common/vt_config.h`、`vt/VtBootstrapDriver/main.cpp`、
`loader/vt_loader.h`、`vt/verify_vt_layout.py`、决策索引并删除本 ADR。静态验证必须证明
默认宏为 0、AMD retained 分支可观测、Loader 同时接受 released/retained 且 Intel 门禁
不变。Release|x64 完整构建及嵌入映像校验通过后，实机应出现：

`AMD legacy image retained after resident handoff ... retained=1`

以及：

`onekey AMD resident transfer ok=1 retain_test=1 host_rip=0`

目标机稳定运行和后续 Machenike Ping/Smoke 才构成运行准出；构建成功不替代实机验证。

## 首轮实机反馈

同日首轮 retained 构建已观察到 `ack=8/8` 后输出
`AMD legacy image retained ... retained=1` 与 `retain_test=1`，随后
`DriverMain leave final_status=0x00000000`。Loader 的 Payload Ping (`0x222290`)、
HV Ping (`0x222294`) 和 Smoke (`0x2222E8`) 均进入并以 `STATUS_SUCCESS` 返回，证明
执行边界已经越过此前的旧映像释放点。日志在后续静默的 migration-check/加载阶段前
结束，因此本证据准出 retained 分支与三项控制调用，不扩展为长期稳定性结论。
