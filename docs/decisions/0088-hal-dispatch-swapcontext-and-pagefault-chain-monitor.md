# ADR-0088: HalDispatchTable / HalPrivateDispatchTable 二级指针穿透、SwapContext 切换标志与 #PF 异常链只读监控规范

- **状态**: 已采纳
- **日期**: 2026-10-26
- **上下文与痛点**:
  反作弊系统为实现动态 CR3 替换（Shadow PML4）与按需页表解密（将 `PDE/PTE.Present` 置 0 并加密 PFN），常通过以下必经落点接管内核执行流：
  1. 篡改 `HalDispatchTable` 或 `HalPrivateDispatchTable` 一级表槽位（如 LBR/PMC/QoS/Hv 辅助切换回调，配合线程 `_KTHREAD.Header.DebugActive` 慢路径触发）；
  2. 为规避 Win10 1903+ PatchGuard 对一级表的校验，转而篡改 `HalPrivateDispatchTable` 槽位函数或 `KeQueryPerformanceCounter` 内部引用的二级 `.data` / 计数器对象函数指针（InfinityHook 变种）；
  3. 置位 `PerfGlobalGroupMask` 中的 `PERF_CONTEXT_SWITCH` (`0x20000004`) 拦截 `SwapContext`；
  4. 劫持 `IDT[0x0E]` $\to$ `KiPageFault` $\to$ `MmAccessFault` 缺页异常链按需解密 PTE。
  需要在不关联特定游戏进程、不遍历线程链表的前提下，以微秒级零开销将上述四大内核终点全部纳入 10 秒周期只读巡检。

- **技术决策与规范**:
  1. **直接扩展 `ApiMonitor`（路径 A）**：
     - 在 `ApiMonitor::Init` 阶段单次完成全部导出表解析、二级 `.data` 指针反汇编提取、`IDT[0x0E]` 门描述符读取、`KiPageFault` 内层 `E8 call`（含 `MmAccessFault`）提取以及 `PerfGlobalGroupMask` 特征扫描，固化至静态数组。
  2. **10 秒周期纯 O(1) 缓存比对（`< 15 µs`）**：
     - `ApiMonitor::CheckHalAndSwapContextHooks`：巡检 `HalDispatchTable`（前 16 槽）与 `HalPrivateDispatchTable`（前 48 槽）一级指针归属、入口跳板与 32B `Adler32` 基线，并穿透校验最多 16 个二级 `.data`/对象函数指针槽位；
     - `ApiMonitor::CheckPageFaultAndCswitchState`：核验当前核 `IDT[0x0E]`、`KiPageFault` 及其内层 `MmAccessFault` 调用偏移与 32B 基线，并在 ACE 在线时监测 `PerfGlobalGroupMask` 的 `PERF_CONTEXT_SWITCH` 标志位。
  3. **位图单次去重上报**：
     - 新增 `s_ReportedHalPtrMask`、`s_ReportedHalInlineMask`、`s_ReportedHalSecMask`、`s_ReportedPfChainMask`、`s_ReportedIdt0E` 与 `s_ReportedPerfCswitch`，同一异常槽位仅上报一次。

- **已知约束与避坑**:
  - 严格保持 100% 只读巡检，严禁对 HAL 表、IDT 或二级指针执行写还原（防 PatchGuard `0x109` 与 HVCI `0xBE`）；
  - 解引用任何二级指针或 IDT 表项前必须经 `Utils::IsValidKernelRange` 校验（防 `BugCheck 0x50`）；
  - 严禁在 10 秒定时循环中遍历进程/线程链表或重复执行全节区特征扫描。
