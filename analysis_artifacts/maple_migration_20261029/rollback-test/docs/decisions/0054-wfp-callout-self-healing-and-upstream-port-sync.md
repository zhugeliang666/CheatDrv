# ADR-0054: WFP Callout 防逆向还原自愈、精确模块取证上报与上游动态端口同步规范

- **状态**: 已采纳
- **日期**: 2026-10-23
- **上下文与痛点**:
  在反作弊对抗巡检中，原有的 `NetMonitor::CheckWfpCallouts` 与 `WfpBypass` 存在四大核心缺陷与断点：
  1. **单向假死与重挂钩漏防**：原逻辑以 `!WfpBypass::IsInstalled()` 作为前置条件，一旦冷启动接管 1 个 Callout 后即永久置位，若 ACE 后台看门狗线程恢复 `classifyFn` 或游戏动态注册新过滤层，巡检将彻底短路跳过，形成假死态；
  2. **告警取证颗粒度缺失与防抖窗口误报**：异常上报缺乏具体的 ACE 驱动模块名、函数绝对地址 (VA)、模块内相对偏移 (RVA) 及槽位字段；且未识别 `WfpBypass::Init` 5 秒防抖等待期返回值（`STATUS_DEVICE_NOT_READY`），导致冷启动必触发虚假 `WfpUnprotected` 误报；
  3. **上游端口联动脱节**：Loader 通过 `DRV_BOOT_CONFIG_EX` 下发了通信端口，驱动成功解析并启动了 TCP/UDP 服务，但从未下发给 `WfpBypass`，导致 WFP 拦截放行始终写死默认 10001 端口，真实业务端口流量完全暴露给反作弊；
  4. **子模块分批加载触发 `ResetState` 抹除 `origClassifyFn` 引发断网与卸载蓝屏 (`0x50` / `0xCE`)**：当 ACE 后续子驱动加载触发 `WfpBypass::ResetState()` 时，若未先将 `netio.sys` Callout 表中的 Wrapper 还原即直接清零 `g_Slots`，会导致运行期丢失 `origClassifyFn` 且驱动卸载后 `netio.sys` 跳入已释放内存崩溃。

- **技术决策与规范**:
  1. **上游端口动态原子同步**：
     - 在 `DriverCore.cpp` 启动网络服务成功后（`StartTransportByIo` 及 `DriverCore::Initialize`），必须成对调用 `WfpBypass::SetHiddenLocalPort((USHORT)srvParams.Port)`；
     - `WfpBypass` 将 `g_HiddenPort` 重构为 `volatile LONG`，采用 `InterlockedExchange` 实现多核原子下发与 `DISPATCH_LEVEL` 下无锁直读。
  2. **槽位完整性核验与原子自愈 (VerifyAndRepairSlots)**：
     - 巡检分为未安装路径与已安装路径；未安装路径下若 `WfpBypass::Init` 返回 `STATUS_DEVICE_NOT_READY`（5 秒防抖等待期）静默返回零误报；
     - 已安装路径下遍历 `g_Slots`，核验各有效字段 `*pClassifyFnField` 是否依然指向 `g_ClassifyWrappers[i]`，一旦被还原立即通过 `InterlockedCompareExchangePointer` 夺回控制权并告警；
     - `WfpBypass::ResetState()` 在清零 `g_Slots` 前必须遍历并原子还原所有仍指向 `g_ClassifyWrappers[i]` 的有效槽位。
  3. **全监控链路收敛与跨页边界防护 (`Utils::IsValidKernelRange` & `Utils::DecodeInlineHookTarget`)**：
     - 统一收敛 `NetMonitor`、`UsbMonitor`、`ApiMonitor` 的跳板解码器至 `Utils::DecodeInlineHookTarget`，并全量接入 `Utils::IsValidKernelRange(ptr, size)` 跨页首尾校验；
     - 针对仅检测 ACE 归属的巡检函数前置 `!g_bAceDetected || g_AceModuleCount == 0` 零开销短路，且 `ApiMonitor::Init` 预缓存 5 大系统驱动基址，移除 `ApiMonitor::ScanAll` 内重复的完整性与硬件断点调用。

- **已知约束与避坑**:
  1. **IRQL 约束**：`WFP` 过滤回调执行在 `DISPATCH_LEVEL`，端口读取与 Wrapper 转发必须严格无锁、不可调用阻塞例程、不可分配分页内存；
  2. **`ResetState` 还原铁律**：严禁在未将 Callout 表中的 `g_ClassifyWrappers[i]` CAS 还原回 `origClassifyFn` 的情况下直接清零 `g_Slots`；
  3. **指针与跨页解引用防御 (ADR-0046)**：巡检遍历 `ndisFilterDriverList`、`FastIoDispatch`、`AttachedDevice` 及 PE/IAT 结构前必须强制通过 `Utils::IsValidKernelRange` 校验首尾字节。
