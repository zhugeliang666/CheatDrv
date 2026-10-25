# ADR-0062: Bootstrap HANDOFF_DROPCTL 大结构离栈与 BugCheck 0x50 根因闭环

- **状态**: 已采纳
- **日期**: 2026-10-25
- **影响模块**: `vt/VtBootstrapDriver/main.cpp`, `bin/vt/VtBootstrapDriver.sys`

## 上下文与现场证据

KDNET 现场在 `loader.exe` 发起 `MAPCTL_IOCTL_HANDOFF_DROPCTL (0x2222CC)` 时触发
`PAGE_FAULT_IN_NONPAGED_AREA (0x50)`。TrapFrame 显示故障指令为
`VtBootstrapDriver+0x3A266` 的 `__chkstk` 页探测，`RAX=0x4830`，访问地址
`FFFFDB0708420000` 位于线程 `StackLimit=FFFFDB0708421000` 下方且 PTE 为零。

运行映像的 TimeDateStamp `0x6ADD4C55`、SizeOfImage `0x36B000`、Checksum
`0xD9B48` 与本地构建完全一致。精确反汇编确认 `+0x161C8` 入口执行
`mov eax,4830h; call __chkstk`；其调用点属于 `0x2222CC` 分发分支，对应
`mapdriver_install_resident_bootstrap_unload()`。

第一次修复部署后的第二次实机复测再次在同一 `0x2222CC` 路径触发 `0x50`，但旧
`0x4830` 栈帧已经从调用链消失。新现场的线程栈范围为
`FFFFDC01`8F324000..FFFFDC01`8F32B000`，TrapFrame 显示 `RAX=0x2140`，
`__chkstk` 读取 `FFFFDC01`8F323000` 时命中零 PTE。运行映像
TimeDateStamp `0x6ADD4EB3`、SizeOfImage `0x36B000`、Checksum `0xE17B4`
与第一次修复后的构建元数据一致。

同版本反汇编进一步确认新的耗尽链由三个固定大帧叠加：

- `mapdriver_ctl_device_control()`：`0x21E0`，源于 STATUS 分支栈上
  `mapctl_status`（内嵌 `payload_status`）；
- `mapdriver_unhide_payload_memory()`：`0x2208`，源于栈上 `payload_status`；
- `mapdriver_collect_payload_pfns()`：`0x2140`，源于第二份栈上
  `payload_status`，其函数序言的 `__chkstk` 最终越过 StackLimit。

## 路径比较

1. **仅使用扩展内核栈**：在 PASSIVE_LEVEL 通过
   `KeExpandKernelStackAndCalloutEx` 隔离调用，改动较小，但保留了 18 KiB 级固定
   栈帧，且分配失败时必须新增失败路径；该方案只能隔离症状。
2. **大结构离栈**：复用项目现有 scratch allocator 将 `mapctl_migration_check`
   放入栈外缓冲，并复用其内嵌 `payload` 完成前置屏障检查；所有退出路径统一清零
   释放。该方案直接删除固定大栈帧，不改变 IOCTL、Payload ABI、迁移判定或
   DriverUnload 交换顺序。

选择路径 2。该路径只在 IOCTL 的 PASSIVE_LEVEL 慢路径分配一次，并继承项目现有
scratch allocator 的 Independent Pages/配置化池策略，既消除 `__chkstk` 越界，也
避免把约 18 KiB 长生命周期对象留在普通内核栈上。

第二次现场继续采用同一决策：STATUS 响应对象和 unhide 状态对象复用 scratch
allocator 离栈；`mapdriver_collect_payload_pfns()` 改为直接填充调用方提供的状态对象，
删除重复副本。未采用扩展栈，也未改变 IOCTL 或 Payload ABI。

## 技术决策与契约

- `mapdriver_install_resident_bootstrap_unload()` 复用
  `mapdriver_alloc_scratch_buffer()` 分配 `mapctl_migration_check`，不得另建专用分配器。
- 分配失败时 fail-closed 返回 `false`，不得安装 ResidentPayload 的卸载入口。
- 前置 `payload_status` 检查直接使用 `check->payload`，不再另建栈上副本。
- 成功与失败路径均通过 `mapdriver_free_scratch_buffer()` 清零并释放。
- 不改变 `MAPCTL_IOCTL_HANDOFF_DROPCTL` 数值、任何跨环结构布局、AMD ACK 条件或
  Intel active-mask 条件。
- `mapdriver_ctl_device_control()` 的 STATUS 分支必须使用栈外 `mapctl_status`，分配
  失败返回 `STATUS_INSUFFICIENT_RESOURCES`。
- `mapdriver_unhide_payload_memory()` 的状态缓冲必须在 PFN 缓冲之后分配；失败时先
  释放 PFN 缓冲并失败关闭。
- `mapdriver_collect_payload_pfns()` 不再拥有 `payload_status`，只接受、清零并填充
  非空的调用方缓冲。

## 已知约束

- Release x64 构建和反汇编只证明固定大栈帧已消失，不等于目标机运行验证成功。
- 实机仍需复测 `0x2222CC`，确认 IOCTL 正常返回且 ResidentPayload 接管
  `DriverUnload` 后 Bootstrap 控制设备完成释放。

## 回滚

恢复 `mapdriver_install_resident_bootstrap_unload()` 原有两个栈上局部结构，并删除本
ADR 及索引项；该回滚会重新引入已确认的 `0x4830` 固定栈帧，仅用于独立副本验证。

## 验证要求

1. Release x64 全量构建必须为 0 error。
2. 编译产物中原 `mov eax,4830h; call __chkstk` 函数序言必须消失。
3. 静态检查必须确认唯一分配与清理标签配对，且所有失败分支汇聚到 `cleanup`。
4. 目标机复测前不得把编译成功描述为蓝屏已实机根除。
5. 第二次修复的 Release x64 对象级反汇编应确认：control dispatch 固定帧
   `0xD0`、unhide 固定帧 `0x188`、collect 固定帧 `0xB0`，三者均不调用
   `__chkstk`。

## 无 BugCheck 硬复位后的第三阶段收敛（2026-10-25）

第二次大结构离栈后的实机日志已经越过 `DriverMain`、Machenike 加载及多个控制
IOCTL，并在 `MAPCTL_IOCTL_HANDOFF_DROPCTL` 中记录
`Bootstrap DriverUnload transferred to ResidentPayload`。随后 KDNET 报告目标未通知
调试器即重启，`nt!KeBugCheckEx` 断点未命中。最后可见边界位于卸载入口安装完成、
原全量 `mapdriver_unhide_payload_memory()` 尚未输出完成日志之间。

本阶段比较两条路径：

1. 保留全量 unhide，并只增加阶段日志。该路径仍会为了一个空的卸载叶函数遍历
   payload image、完整 arena、host stack 与全部 adopted pool PFN，然后逐 CPU 发起
   Hypercall，之后又立即隐藏其中的大部分页面，故障面与延迟均过大。
2. 仅显现 `release_bootstrap` 所在代码页，并要求所有活动 CPU 返回成功后才原子安装
   `DriverUnload`；随后保持 host stack、resident pools 与 arena 的隐藏流程。该路径把
   交接前的 Guest 可执行契约缩小到唯一实际入口页，并对部分成功失败关闭。

选择路径 2。`mapdriver_unhide_resident_release_page()` 在安装卸载入口前解析真实 PFN，
逐处理器执行单 PFN unhide，并要求 `done_count == cpu_count`。任一处理器失败时保留原
`DriverUnload`，`HANDOFF_DROPCTL` 返回 `STATUS_DEVICE_NOT_READY`。删除控制设备前不再
调用全量 `mapdriver_unhide_payload_memory()`；host stack、resident pool 和 arena
隐藏调用增加成对 enter/leave 日志，以便下一轮将无 BugCheck 复位定位到首个未返回
边界。

该变更不修改 IOCTL、Payload ABI、VMCB/NPT 布局或 Hypercall 编号。Release 构建与
静态检查只能证明单页门禁和失败关闭已落地；目标机仍需验证 `0x2222CC` 正常返回、
SCM 调用 ResidentPayload 卸载叶函数后 Bootstrap 映像解除且驻留 SVM 继续响应。
