# ADR-0179：VMCALL Hook 延迟事件回调到 Machenike 驱动

- 状态：已采纳
- 日期：2026-11-02
- 适用范围：VtResidentPayload 的 VM-Exit Hook 事件与 Machenike 驱动侧回调

## 上下文与痛点

VM-Exit/VMRESUME 处理位于虚拟机监控器的 Ring -1/host-root 执行环境。让该路径直接调用驱动 C/C++ 函数指针会把调用约定、IRQL、栈、卸载生命周期和跨 CPU 同步耦合在一起，回调地址失效时还可能导致宿主或客户机崩溃。设计目标是让 Ring -1 只记录事件，由驱动在既有低频维护工作项中回调。

## 技术决策

1. ResidentPayload 只向现有固定宽度 debug event ring 写入 `PAYLOAD_DBG_EVT_HOOK`（类型值 6），不保存或执行驱动函数指针。
2. 新增调试子命令 `0x5004`/`0x5005`：分别启停 Hook 事件生产者、轮询 Hook 事件。轮询的消费标志只删除 Hook 类型事件，不干扰其它诊断事件。
3. 事件 ABI 使用固定宽度字段：序号、TSC、CPU、CallbackId、Guest CR3/RIP/RSP、目标地址、Trampoline、Resume 地址以及 RAX/RCX/RDX/R8/R9。
4. Machenike 侧以固定容量静态表注册 `CallbackId -> callback/context`，仅允许 `PASSIVE_LEVEL` 注册、注销和轮询；现有 `GenericMaintenanceWorker` 调用 `PollVmcallHookEvents`，再在驱动上下文调用静态回调。
5. 第一个注册者启用事件生产者，最后一个注销者及清理路径关闭生产者；不跨 ABI 传递 PEPROCESS、原始函数指针或等待对象。

## 已知约束与避坑

- VM-Exit 路径不得分配内存、等待、触发驱动回调或依赖驱动卸载后的代码；事件环满时遵循既有丢弃计数。
- 回调必须在注销前停止生产者并确保维护工作项不再使用表项；回调本身不得假定运行在 VM-Exit 上下文。
- 回调表、轮询缓冲区和事件字段固定上限，避免由外部请求改变内核栈或静态对象边界。
- 该接口是通知接口，不改变现有 Hook 的执行流，也不实现“Host 直接 VMRESUME 到 Guest Ring0 回调”的跨特权级调用。

## 验证

- `verify_interface.py`：7 个接口标记全部存在，缺失为 0。
- Debug|x64 解决方案构建成功；`Machenike`、`VtHypervisor`、`VtResidentPayload`、`VtBootstrapDriver` 均生成并签名。
