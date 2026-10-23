# ADR-0054: WFP Callout 防逆向还原自愈、精确模块取证上报与上游动态端口同步规范

- **状态**: 已采纳
- **日期**: 2026-10-23
- **上下文与痛点**:
  在反作弊对抗巡检中，原有的 `NetMonitor::CheckWfpCallouts` 存在三大核心缺陷与断点：
  1. **单向假死与重挂钩漏防**：原逻辑以 `!WfpBypass::IsInstalled()` 作为前置条件，一旦冷启动接管 1 个 Callout 后即永久置位，若 ACE 后台看门狗线程恢复 `classifyFn` 或游戏动态注册新过滤层，巡检将彻底短路跳过，形成假死态；
  2. **告警取证颗粒度缺失**：异常上报仅输出静态无特征文本，缺乏具体的 ACE 驱动模块名、函数绝对地址 (VA)、模块内相对偏移 (RVA) 及槽位字段，无法快速辅助排查；
  3. **上游端口联动脱节**：Loader 通过 `DRV_BOOT_CONFIG_EX` 下发了通信端口，驱动成功解析并启动了 TCP/UDP 服务，但从未下发给 `WfpBypass`，导致 WFP 拦截放行始终写死默认 10001 端口，真实业务端口流量完全暴露给反作弊。

- **技术决策与规范**:
  1. **上游端口动态原子同步**：
     - 在 `DriverCore.cpp` 启动网络服务成功后（`StartTransportByIo` 及 `DriverCore::Initialize`），必须成对调用 `WfpBypass::SetHiddenLocalPort((USHORT)srvParams.Port)`；
     - `WfpBypass` 将 `g_HiddenPort` 重构为 `volatile LONG`，采用 `InterlockedExchange` 实现多核原子下发与 `DISPATCH_LEVEL` 下无锁直读。
  2. **槽位完整性核验与原子自愈 (VerifyAndRepairSlots)**：
     - 巡检分为未安装路径与已安装路径；已安装路径下遍历 `g_Slots`，核验各有效字段 `*pClassifyFnField` 是否依然指向 `g_ClassifyWrappers[i]`；
     - 一旦发现被 ACE 还原，原子调用 `InterlockedCompareExchangePointer` 强制夺回控制权（自愈），并触发报警。
  3. **精确符号与地址反解取证模型 (WFP_ALARM_DETAIL)**：
     - 引入 `WFP_ALARM_DETAIL` 结构体，结合 `g_AceModules` 数组反解目标函数所属的 ACE 模块名（如 `102706.sys`）、模块基址及 RVA 偏移；
     - 通过 `ExceptionReporter::ReportFormat` 分级输出精确取证日志（`NetMonitor::WfpReverted` 与 `NetMonitor::WfpUnprotected`）。

- **已知约束与避坑**:
  1. **IRQL 约束**：`WFP` 过滤回调执行在 `DISPATCH_LEVEL`，端口读取与 Wrapper 转发必须严格无锁、不可调用阻塞例程、不可分配分页内存；
  2. **指针解引用防御 (ADR-0046)**：巡检时访问 `pClassifyFnField` 及内部函数指针必须强制先过 `WfpBypass_IsValidKernelPtr` 校验；
  3. **编码后置处理**：修改后自动执行 `python convert_bom.py`，保持 UTF-8 BOM 规范。
