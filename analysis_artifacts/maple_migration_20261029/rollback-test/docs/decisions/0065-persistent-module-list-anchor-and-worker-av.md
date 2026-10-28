# ADR-0065：持久模块链表锚点与后台工作项访问异常根因闭环

- **状态**：已采纳
- **日期**：2026-10-25
- **影响模块**：`Core/DriverCore.cpp`

## 上下文与现场证据

KDNET 现场停在 `System` 进程的 `ExpWorkerThread`，当前异常为内核读访问冲突，尚未
形成正式 BugCheck（`.bugcheck == 0`）：

```text
RIP = ffff8201`dfe70716
RDI = 000000ff`03e706ff
指令 = cmp qword ptr [rdi+30h], rbx
读取地址 = 000000ff`03e7072f（PTE not valid）
```

通过运行时字符串 RVA 与本地 `mswsk.map` 对齐，映像基址为
`ffff8201`dfe6d000`，故障 RVA 为 `0x3716`，精确对应
`ScanAceModuleState+0x5A`。从固定帧尾部恢复的返回地址为
`SecurityWorkerRoutine+0x48`，下一层为 `nt!ExpWorkerThread+0x105`。

`ScanAceModuleState` 的第一个参数为 `ffffab08`0cbf19a0`，其 `Flink` 已变为
`000000ff`03e706ff`，`Blink` 也不是规范内核链表地址。该参数来自
`g_AceMonitorCtx.pDriverSection`；初始化代码把 Bootstrap/宿主驱动的
`DriverObject->DriverSection` 长期保存在周期工作项中。宿主完成 handoff 或卸载后，
对应 `KLDR_DATA_TABLE_ENTRY` 生命周期结束并被复用，后台工作项随后解引用陈旧链表
锚点。

## 路径比较

1. **只用 SEH 包裹旧宿主指针**：能够把访问异常转为失败关闭，但继续依赖已经结束
   生命周期的对象，无法消除 UAF 根因。
2. **改为系统生命周期锚点并增加有限遍历门禁**：在解析 `ntoskrnl` 导出时保存其
   `KLDR_DATA_TABLE_ENTRY`；该加载项与系统同寿命。工作项只原子读取该锚点，并对
   链表节点、双向链接、名称长度及地址执行有限步数校验，异常时立即停止本轮。
3. **每轮调用模块快照 API**：所有权最清晰，但当前零 IAT/低分配架构需要新增 API
   解析、持久缓冲与卸载契约，改动面明显大于本次根因。

选择路径 2；路径 3 保留为后续完全移除未公开加载项布局依赖的演进方向。

## 技术决策

- `MachenikeUserVarInit` 识别 `ntoskrnl` 时保存
  `g_pPersistentModuleListAnchor`。
- `StartBackgroundEngines`、`ApiMonitor::Init` 与初始旁路扫描统一使用该持久锚点，
  不再把宿主 `DriverSection` 交给周期后台任务。
- 工作项通过 `InterlockedCompareExchangePointer` 获取锚点；初始化与卸载分别通过
  `InterlockedExchangePointer` 发布和清空上下文指针。
- `ScanAceModuleState` 最多遍历 1024 个节点，并校验：节点首尾地址、`Flink/Blink`
  双向一致性、偶数字节名称长度、`Length <= MaximumLength <= 512` 及名称缓冲首尾地址。
- 任一结构化异常或链表失配均失败关闭当前扫描，不继续追逐未知指针。
- 不改变定时周期、ACE 模块匹配规则、跨环 ABI 或网络协议。

## 已知约束

- `KLDR_DATA_TABLE_ENTRY` 仍属于未公开内核布局；该方案消除了宿主卸载 UAF，并把并发
  失配限制为失败关闭，但不等价于公开的模块快照 API。
- 构建与静态验证只能证明锚点和门禁已经落地；目标机仍需完成 handoff 后至少运行
  多个 2 秒扫描周期，确认后台线程持续存活。

## 回滚

恢复 `Core/DriverCore.cpp` 原始副本并删除本 ADR 与索引项。回滚会重新引入已由
WinDbg 证实的宿主 `DriverSection` 生命周期越界，仅允许在独立副本验证。

## 验证要求

1. Release x64 构建为 0 warning、0 error。
2. 静态检查确认旧赋值 `pCtx->pDriverSection = pHostDriverSection` 消失。
3. 静态检查确认持久内核锚点、原子上下文指针与有限遍历三项同时存在。
4. 在独立副本执行回滚后，`Core/DriverCore.cpp` SHA-256 必须恢复为修改前哈希。
5. 实机复测不得仅以 `.bugcheck == 0` 判断成功；必须确认 `SecurityWorkerRoutine`
   连续完成多个周期且没有再次停在 `ScanAceModuleState`。

