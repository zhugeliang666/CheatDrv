# ADR-0063: AMD Resident PFN 显现 Hypercall 95 与内核 `#UD` 根因闭环

- **状态**: 已采纳
- **日期**: 2026-10-25
- **影响模块**: `vt/VtHypervisor/vt/hypercalls.h`, `vt/VtHypervisor/amd/svm-exit.cpp`, `vt/VtBootstrapDriver/main.cpp`

## 上下文与现场证据

`MAPCTL_IOCTL_HANDOFF_DROPCTL` 的单页显现门禁部署后，KDNET 在 CPU 0、
`loader.exe` 线程、IRQL 0 捕获第二次机会内核异常 `0xC000001D`。系统尚未写入
BugCheck，`.bugcheck` 与 `nt!KiBugCheckData` 均为零。

故障 RIP 指向 `vmmcall`。现场 `RAX=0x000885544668855f`，其中 key 为
`0x88554466885`，低 8 位 code 为 `95`；参数数量为 1。参数 PFN `0x20d216`
与 `release_bootstrap` 入口页的 `!pte` 结果完全一致，证明调用方目标页计算正确。

Resident AMD 的 SVM 分派只覆盖 90..93，合法的 95 落入默认分支并向 Guest 注入
`#UD`。VMX Resident bridge 已有 95 分派，因此根因是跨厂商 Resident ABI 不对称。

## 路径比较

1. 把 Bootstrap 改回逐页 Hypercall 13：改动最小，但会绕开已经建立的批量 ABI，
   继续保留 AMD/VMX Resident 编号漂移，并且无法为后续批量释放提供精确完成计数。
2. 在 AMD Resident SVM 分派实现 Hypercall 95：复用现有 NPT PTE 操作和 Guest VA
   转换，保持调用方逐 CPU 门禁不变，返回当前 vCPU 的真实完成数量。

选择路径 2。该路径修复 ABI 根因，不改变 IOCTL、跨环结构或调用顺序。

## 技术决策与接口契约

- 共享 `hypercall_code` 明确加入 94、95，并以 `static_assert` 固定编号。
- 95 的 `RCX` 是 Guest PFN 数组 GVA，`RDX` 是元素数量；数量上限为
  `pending_hide_capacity`。
- 分派在做指针加法前校验回绕，并按 Guest 页边界分块转换，绝不裸跨页读取。
- PFN 左移前校验溢出；无法转换、PTE 不存在或 PFN 无效时不得计入完成数。
- 仅恢复当前 vCPU 的 NPT PTE。Bootstrap 已逐活动处理器调用，并要求每个处理器
  返回完整数量；部分成功继续失败关闭。
- 至少一个 PTE 修改后才更新 NPT generation、设置 `VMCB.TLB_CONTROL=1` 并标记
  VMCB dirty。
- 返回值是实际恢复的 PFN 数量，不允许仅消费 VMMCALL 后伪造成功。

## 首次实机复测与幂等语义修正

首次部署 95 分派后不再出现内核 `#UD` 或蓝屏，但 `HANDOFF_DROPCTL` 记录
`cpus=0/8` 并以 `STATUS_DEVICE_NOT_READY (0xC00000A3)` 失败关闭。现场同时证明
Machenike 已成功加载，Payload image 在交接前仍保持 Guest 可见。

根因是 `get_npt_pte(..., false)` 对 2 MB large leaf 按契约返回空。原实现把“不存在
4 KB PTE”等同于“目标 PFN 不可见”，漏掉了 2 MB identity leaf 已经覆盖并允许执行
该 PFN 的幂等成功状态。

修正后的 95 先检查目标 GPA 所属 2 MB leaf：当 leaf present、large、基址 PFN 与
`pfn >> 9` 一致且 NX 未置位时，直接把该 PFN 计入完成数，不拆分大页、不写页表、
不刷新 TLB。只有 4 KB leaf 的 PFN 或 NX 实际发生变化时，才累计 changed 并执行
NPT generation 更新与 `VMCB.TLB_CONTROL` invalidation。不存在、非 identity 或不可执行
的大页仍失败关闭。

同轮诊断确认 Machenike 的日志并未被编译掉：`ENABLE_DBG_LOG=1` 且产物包含 `[DBG]`
字符串；其 `SafeDbgPrint` 使用 DEFAULT/INFO 通道，而 Bootstrap 使用 IHVDRIVER/ERROR。
统一改用 `DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, ...)`，避免 WinDbg 默认
组件过滤掩盖 Machenike 启动日志。

## 已知约束

- 本次只闭环现场命中的 95。94 已加入共享 ABI，但 AMD Resident 的 memcheck 请求
  仍需单独实现与验证，不能把其 Guest 指针直接交给 Payload 当作 Host 指针使用。
- Release x64 构建和静态分支检查不等于实机运行验证；目标机仍需复测
  `0x2222CC`、确认 VMMCALL 返回、DriverUnload 安装与控制设备删除完成。

## 回滚

删除 AMD 95 分派以及共享 enum 的 94/95 项，并恢复 ADR 索引。该回滚会重新引入
已经由 KDNET 直接证明的合法 Hypercall 95 注入 `#UD`，只允许在独立副本验证。

## 验证要求

1. Release x64 全量构建为 0 error。
2. 静态检查确认共享 ABI 94/95 的断言存在，且 AMD switch 包含 95、Guest 边界读取、
   PFN 溢出校验、真实 PTE 恢复、TLB invalidation 与精确返回值。
3. 独立副本运行回滚后，相关文件 SHA256 必须恢复为修改前快照。
4. 实机复测前不得声称蓝屏或硬复位已经根除。
5. 实机复测必须同时观察 `release page unhide ... cpus=8/8 ok=1`、控制设备删除以及
   Machenike `[DBG]` 初始化日志；编译通过不替代该运行证据。
