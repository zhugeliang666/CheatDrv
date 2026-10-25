# ADR-0060: WFP Callout 零注册静默巡检与未受保护精确告警门禁规范

- **状态**: 已采纳
- **日期**: 2026-10-25
- **影响范围**: `Stealth/WfpBypass.h`, `Stealth/WfpBypass.cpp`, `Stealth/NetMonitor.cpp`

---

## 一、 上下文与痛点

在《三角洲行动》(delta_force v8.4) 等接入 ACE 反作弊的游戏环境中，反作弊模块采用多阶段链式加载策略。在游戏启动初期，系统内核首先加载引导过滤驱动 `ACE-BOOT.sys`，该驱动仅导入文件过滤管理器（`FLTMGR.SYS`）与内核基础例程，**绝不调用任何 WFP 注册 API（`FwpsCalloutRegister`/`FwpmCalloutAdd` 为 0）**。真正的网络过滤与 ALE 鉴权 Callout 由后续动态加载的 `ACE-CORE302706.sys` 主驱动注册。

然而在历史实现（[ADR-0054](0054-wfp-callout-self-healing-and-upstream-port-sync.md)）中，`NetMonitor::CheckWfpCallouts` 存在判定盲区：
- 盲区：只要内核检测到 `g_bAceDetected == TRUE`（即使仅有 `ACE-BOOT.sys`），且 5 秒防抖期已过，一旦 `!WfpBypass::IsInstalled()` 成立，直接盲目判定反作弊存在未受保护网络过滤，向用户端抛出告警：
  ```text
  NetMonitor::WfpUnprotected (0xC0000424 / STATUS_SECURITY_CHECKS_FAILED)
  "WFP Alarm: 1 Active ACE Mods [ACE-BOOT.sys] Callouts NOT bypassed/protected!"
  ```
- 根因：系统 Callout 表中根本没有任何属于 `ACE-BOOT.sys` 的 Callout 条目（未注册），但原逻辑误将“未匹配到 Callout”等同于“存在 Callout 且未被替换”，引发虚假告警。

---

## 二、 方案权衡与抉择

- **方案 A（已采纳，方案 1）**：
  保持对所有驱动（无论是 BOOT 还是其它任何前缀）的统一全局追踪；在底层 `WfpBypass` DKOM 扫描中引入真实未受保护回调计数器 `g_UnprotectedCalloutCount`。当且仅当系统 Callout 表中真实扫描到指向 ACE 驱动范围的指针且 CAS 替换失败（或槽位溢出）时才判定为未保护；若全表扫描匹配数为 0（目标未注册 Callout），则判定为预期内静默等待状态，坚决不触发 `WfpUnprotected` 告警。
- **方案 B（明确否决，方案 2）**：
  在 `IsAceModuleName` 中增加名称黑白名单跳过 `ACE-BOOT.sys`。
  - **否决原因**：反作弊模块命名随时动态演进，且用户明确要求“全部驱动都需要监控”，硬编码跳过特定驱动会破坏全量驱动审计完整性。

---

## 三、 技术规范与核心实现

1. **未受保护状态原子追踪 (`WfpBypass`)**：
   - 维护静态原子计数 `static volatile LONG g_UnprotectedCalloutCount`；
   - 在 `DoReplace`（涵盖 Track-1 KfdGetRefCallout、Track-2 扁平结构体/指针数组、Track-3 辅助字段识别、Track-4 暴力指针宽扫）遍历过程中：
     * 若指针命中 `IsAddressInAceModules(fn)` 且非自身 Wrapper：尝试 `InstallSlot`；
     * 若 `InstallSlot` 失败（CAS 竞态未中或槽位已满），原子递增 `g_UnprotectedCalloutCount`；
   - 暴露只读静态查询接口 `WfpBypass::GetUnprotectedCalloutCount()`；并在 `ResetState`、`Cleanup` 与扫描起点原子清零。
2. **巡检门禁精准重构 (`NetMonitor::CheckWfpCallouts`)**：
   - 冷启动/未安装路径下：
     * 处于 5 秒防抖期（`STATUS_DEVICE_NOT_READY`）：静默返回 0；
     * 超过 5 秒防抖期：检查 `WfpBypass::GetUnprotectedCalloutCount()`；
     * 仅当 `unprotectedCount > 0`（系统内真实存在敌方 Callout 且拦截失败）：触发 `wfpAlarms++` 并向外派发 `NetMonitor::WfpUnprotected` 告警；
     * 若 `unprotectedCount == 0`（表中无任何属于受监控模块的未保护回调）：静默巡检，零虚假告警。
3. **接管成功事件全量上报 (`NetMonitor::WfpSlotBypassed` 与 `NetMonitor::WfpBypassed`)**：
   - **槽位级微粒上报 (`InstallSlot`)**：每个槽位通过 CAS 原子替换敌方 Callout 成功后，提取该槽位原函数所属 ACE 驱动模块名、基址、ClassifyFn 虚地址及 RVA，派发 `NetMonitor::WfpSlotBypassed`；
   - **批次级汇总上报 (`WfpBypass::Init`)**：扫描替换完成（`replaced > 0`）后，派发 `NetMonitor::WfpBypassed` (状态码 `STATUS_SUCCESS`)；在探测模式下派发 `NetMonitor::WfpDetected`；
   - 形成 WFP 监控闭环：`NetMonitor::WfpSlotBypassed` / `NetMonitor::WfpBypassed` (成功接管) / `NetMonitor::WfpUnprotected` (接管失败告警) / `NetMonitor::WfpReverted` (被恢复自愈告警)。

---

## 四、 已知约束与避坑指南

1. **严禁粗暴以 `IsInstalled()` 作为告警条件**：`IsInstalled()` 为假代表“当前未接管任何 Callout”，在目标驱动未注册网络回调时属于安全常态，严禁误报；
2. **多驱动动态演进兼容**：当后续 `ACE-CORE` 驱动加载时，模块聚合指纹自动变化，自适应重置防抖期并自动完成接管，无需任何上层干预；
3. **频控与缓冲区契约**：接管成功采用单条汇总上报（含替换数、主模块名、基址、RVA 与尝试轮次），严格控制在 128 字节缓冲区以内，且规避 `ExceptionReporter` 10 秒同卡密全局频控对循环并发调用的静默丢弃。
