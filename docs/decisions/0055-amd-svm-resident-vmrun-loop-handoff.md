# ADR-0055：AMD-SVM 固定 VMRUN/VMEXIT 闭环迁移至 VtResidentPayload

- 状态：已实现；AMD 多核迁移与旧映像释放已实机验证，Bootstrap 最终卸载待实机验证
- 日期：2026-10-23
- 关联：ADR-0051（其中“AMD 必须永久保留 VtHypervisor 映像”的 Stage13/15 结论由本 ADR 定向替代）

## 上下文

AMD 后端原先由 `VtHypervisor` 映像中的 `svm_launch_asm` 永久承载固定 `VMRUN -> #VMEXIT -> handler -> VMRUN` 闭环。即使 `ghv`、vCPU、VMCB、NPT、MSRPM、Host Save Area 与 Host Stack 已位于 external arena 或独立页，活动 RIP 仍落在旧映像，因而旧映像不能清零、释放，`VtBootstrapDriver` 也不能完成最终交接。

本次变更不修改 VMCB/NPT 的物理身份，不在 Root-mode 搬运活动大对象；它只在完整保存 Guest GPR/XMM 后，把每个 vCPU 的固定循环控制流一次性切换到 `VtResidentPayload` 内同源编译的 SVM 汇编与 VMEXIT handler。

## 方案比较

### 方案 A：保留旧映像固定循环

- 优点：没有活动栈帧跨映像切换，既有 AMD 路径风险最低。
- 缺点：永久保留 `VtHypervisor` RX/RW 映像；无法满足映像清零、释放和 Bootstrap 最终卸载目标。
- 延迟/吞吐：无新增 VMEXIT 成本。
- 回滚：天然保留旧路径。

### 方案 B：每 vCPU 一次性 live-frame 跳转（采用）

- 在 `hv::svm_vcpu_state` 尾部增加 8 字节对齐的 `resident_loop` 与 `resident_ack`。
- Bootstrap 通过 ABI 86 和 HV diag layout 26 取得 vCPU 数组、步长及两个字段的显式偏移；ResidentPayload 严格校验本地 `sizeof/offsetof`、计数、对齐、乘加溢出、`ghv->vcpus` 与 `vcpu_count`。
- ARM 阶段把 ResidentPayload 内 `svm_resident_continue_asm` 写入每个 vCPU 的一次性目标；Bootstrap 逐逻辑处理器发起 `ping` 产生 VMEXIT。
- 旧汇编在保存全部 Guest GPR/XMM 后原子消费目标并跳转。`resident_ack` 不由旧映像写入，而由目的映像入口写入；观察到 ACK 时，当前 RIP 与返回路径均已脱离旧映像。
- ResidentPayload 内同源链接完整 AMD SVM handler/runtime，并把其 `hv::g_ghv`、`hv::g_vt_hook_table` 绑定到 arena-resident 对象；VMCB/NPT/MSRPM/Host Save Area/Host Stack 的地址和所有权不变。
- AMD 的 payload-owned 91/92/93 hypercall 由 ResidentPayload 内 handler 直接分派，不依赖 VMX HOST_RIP bridge。

该方案每 CPU 仅增加一次 ARM/ACK 迁移成本；迁移后热路径与原固定循环一致。ARM、查询和重复触发均为幂等操作。

## 接口契约

- `PAYLOAD_ABI_VERSION = 87`；`payload_exports` 尾部包含 `activate_amd_svm(mode)`，并追加 `release_bootstrap(DriverObject)`。
- `MAPCTL_HV_DIAG_LAYOUT_VERSION = 26`；`mapctl_hv_diag` 尾部追加：
  - `vcpu_off_svm_resident_loop`
  - `vcpu_off_svm_resident_ack`
- ARM 仅在 legacy detach 已完成且 `ghv`/VT hook table 与 arena-resident 副本身份一致时开放。
- 完整 ACK 是释放 `VtHypervisor` 的硬门禁；部分成功、超时、布局不一致或非法指针均保留旧映像并失败关闭。

## 执行上下文与同步

- ARM/QUERY 与逐 CPU 触发在 PASSIVE_LEVEL 的 Bootstrap one-key 路径执行；跨组绑核使用 `KeSetSystemGroupAffinityThread`，每次均成对恢复。
- VMEXIT 迁移发生于 Root-mode、GIF=0 的现有固定栈帧；目标解析调用遵守 x64 shadow space/16 字节对齐，并且位于 Guest 全寄存器保存之后。
- `InterlockedExchange64` 消费目标并发布 ACK；ACK 的发布点位于 ResidentPayload 代码内，阻断“旧映像 ACK 后仍在旧 RIP 上被释放”的竞态。
- 不在 VMEXIT 热路径分配、阻塞、打印或调用分页例程。

## 生命周期与失败回滚

1. 完成 payload barrier、HV diag、legacy detach、PoolManager 块接管和 Host CR3 映射。
2. 对所有 vCPU ARM，逐处理器触发 VMEXIT，等待 `ack == vcpu_count`。
3. 仅在完整 ACK 后隔离旧 TestDriver，执行两阶段 RELEASE、旧 CRT unload wrapper、全引用扫描。
4. 扫描为零后清零并释放 `VtHypervisor` 映像；ResidentPayload 继续独立处理 VMRUN/VMEXIT 与控制 hypercall。
5. Bootstrap 把自身 `DriverObject->DriverUnload` 原子切换到 ResidentPayload 的驻留叶函数，删除控制设备后由 SCM 解除 Bootstrap 映像。

Bootstrap 最终卸载不得调用原 `unload_driver`，因为该路径会执行完整
`PayloadStop/hv::stop`。ABI 87 由 ResidentPayload 导出纯叶函数
`release_bootstrap`；`HANDOFF_DROPCTL` 只有在 payload barrier、detach、HV
存活以及 AMD 全核 ACK/旧映像已释放（Intel 则 HOST_RIP/RSP 均已迁移）全部
成立时，才安装该驻留入口。IOCTL 完成并删除控制设备后，SCM 调用驻留入口
并只解除 Bootstrap 映像，不停止 ResidentPayload 持有的运行状态。

回滚时反向应用本 ADR 对应补丁即可恢复 ADR-0051 的旧映像固定循环。运行时若 ARM 未达到完整 ACK，禁止释放任一映像；重新触发是幂等恢复路径。

## 已知约束

- 需要 AMD SVM/NPT 实机完成多核与处理器组验证；本次仅完成离线 Release x64 构建和 PE/ABI 静态验证。
- VtResidentPayload 同源链接完整 Hypervisor handler，映像虚拟尺寸与原 VtHypervisor 同量级；映射仍依赖 `MmAllocateIndependentPages`。
- ResidentPayload 必须经 UCXXRT `DriverEntry -> DriverMain` 启动，以执行静态初始化并在 PayloadUnload 时成对执行析构；禁止直接把 PE entry 指向 `PayloadEntry`。

## 验证证据

- Release x64：`VtHypervisor;VtResidentPayload;VtBootstrapDriver` 三目标构建。
- ResidentPayload PE entry 通过 UCXXRT `DriverEntry`，`.CRT` 初始化警告已消除。
- 汇编检查：迁移目标在 Guest GPR/XMM 保存之后消费；ACK 在目的映像入口发布。
- 回滚：在独立 worktree 应用补丁后执行 `ROLLBACK.sh`，工作树恢复到原始 HEAD。
