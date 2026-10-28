# ADR-0105: HANDOFF_DROPCTL memcheck 大结构离栈与 BugCheck 0x50 修复

- **状态**: 已采纳
- **日期**: 2026-10-28
- **影响模块**: `vt/VtBootstrapDriver/main.cpp`

## 上下文与现场证据

远程 WinDbg 现场在 `loader!VtLoader::ReleaseResidentBootstrap` 发送
`MAPCTL_IOCTL_HANDOFF_DROPCTL (0x002222CC)` 后触发 `PAGE_FAULT_IN_NONPAGED_AREA (0x50)`。
TrapFrame 中 `RAX=0x44E0`，故障指令是 `__chkstk` 的页探测，访问地址位于当前
KTHREAD 的 `StackLimit` 下方一页。反汇编对应
`mapdriver_memcheck_control_complete()` 的两个栈上 `mapctl_memcheck` 对象：
`aggregate` 与 `page` 各为 `0x2258` 字节。

## 技术决策

1. `mapdriver_memcheck_control_complete()` 的 `aggregate` 和分页工作对象 `page`
   统一通过现有 `mapdriver_alloc_scratch_buffer()` 分配，成功与失败路径均通过
   `mapdriver_free_scratch_buffer()` 清零释放。
2. 分配失败时返回 `PAYLOAD_RESULT_INVALID_CONTEXT`、递增 `verify_fail` 并置
   `done=1`，保持 DROPCTL 失败关闭，不删除控制设备。
3. `mapdriver_unload_common()` 的迁移检查拆为
   `mapdriver_validate_handoff_migration()`，其 `mapctl_migration_check` 也使用
   scratch 缓冲区；函数标记 `noinline`，避免编译器重新合并大对象栈帧。
4. 不修改 IOCTL 数值、`mapctl_memcheck`/`mapctl_migration_check` ABI、双视图语义、
   AMD/Intel 迁移条件或卸载顺序。

## 已知约束与验证

- 这些分配只发生在 PASSIVE_LEVEL 的 DROPCTL 慢路径；任何失败均保留控制面。
- Release x64 基线与修改版 `VtBootstrapDriver.vcxproj` 构建退出码均为 `0`，仅保留
  既有 `LNK4254` 节合并警告。
- 修改版反汇编中 memcheck 函数固定帧为 `sub rsp,78h`，原 `mov eax,44E0h` 序言
  已消失；`verify_vt_layout.py` 全部检查通过。
- 目标机仍需复测 `0x2222CC`，确认 DROPCTL 返回、ResidentPayload 接管卸载入口及
  控制设备删除均正常完成。

## 回滚

使用本次交付目录的 `ROLLBACK.sh` 将 `main.cpp` 恢复为记录的基线 SHA-256；独立
副本回滚测试已验证恢复为 `63ED41953DAB605A6FA442DA27C0370CCB96CC060D6214B0D2F70D0C13F05301`。
