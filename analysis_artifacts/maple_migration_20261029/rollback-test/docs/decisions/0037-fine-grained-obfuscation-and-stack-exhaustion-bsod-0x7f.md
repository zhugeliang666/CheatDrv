# ADR-0037: 精细化分级混淆架构、反作弊与热路径原生豁免及彻底根除 BugCheck 0x7F (#DF Double Fault)

- **状态**: 已采纳
- **日期**: 2026-10-18
- **上下文与痛点**:
  在全工程全局启用 OLLVM（BCF 虚假控制流、MBA 混合布尔代数替换、常量替换）后，高频微秒级物理内存读写例程（如 `LcPte_CopyPhysical`、`LeechRPC` 散列读）及网络分发管道被深度膨胀（`LcPte_CopyPhysical` 从数百字节激增至 118KB）。
  由于 OLLVM 在展开复杂控制流和局部状态机时插入动态栈分配（`sub rsp, rax`），在内核线程仅有的 24KB 栈空间内，瞬间越过栈底 Guard Page，引发不可拦截的双重错误硬件异常 `#DF`（BugCheck `0x7F`, Arg1=`0x8`），导致内核蓝屏崩溃。此外，反作弊模块防御逻辑（ACE 监控、Hook 巡检、只读自检）及高频加密哈希原语若被混淆，不仅会大幅增加 DPC / 延迟开销，还会改变指令序列与执行时序特征。

- **技术决策与规范**:
  1. **全局与模块级混淆解耦配置 (`Machenike.vcxproj`)**:
     - 全局 `ReleaseLLVM|x64` 降噪：移除全局 `--bcf`、`--mba-subs`、`--const-obfus`、`--sub`，**仅保留全局字符串加密 `-mllvm --string-obfus`**；
     - 守门人与核心主动对抗机制重度混淆：通过 `<ClCompile Include="...">` 局部追加 `--bcf`、`--mba-subs`、`--const-obfus`、`--sub`，覆盖：
       * 驱动初始化与派遣 (`Core\DriverCore.cpp`)
       * 动态令牌与四重自检深度防御 (`Security\DrvSecurity.cpp`)
       * WFP 核心旁路拦截机制 (`Stealth\WfpBypass.cpp`) 与隐蔽挂接 (`Stealth\StealthReloc.cpp`)
     - **反作弊 Monitor 扫描器全量豁免混淆**：
       * 三大只读巡检扫描器（`Stealth\ApiMonitor.cpp`、`Stealth\NetMonitor.cpp`、`Stealth\UsbMonitor.cpp`）完全免除控制流混淆，恢复至 99~134KB 轻量原生执行，彻底杜绝巡检过程中的 DPC 延迟尖刺（DPC Latency Spike）与多重堆栈开销；
     - 所有微秒级物理读写模块（`Memory\LeechCoreEngine.cpp`、`Memory\RpcDispatcher.cpp`）及跨机/跨环通信协议栈（`Transport\*`）**100% 免除代码控制流混淆**，杜绝 0x7F 栈击穿并确保线速吞吐。
  2. **高频巡检与微秒级算力原语细粒度豁免机制 (`NO_OBFUS`)**:
     - 在 `Core\Common.h` 中抽象 Clang 特性宏 `#define NO_OBFUS __attribute__((optnone))`；
     - 混淆源文件内部的巡检与调度例程全部打标 `NO_OBFUS` 豁免混淆：
       * `DriverCore.cpp`：`ScanBypassModules`、`ResetAllScanStates`、`ScanAceModuleState`、`ExecuteDeepSecurityScans`、`SecurityWorkerRoutine`、`AceMonitorDpc`（保证 DPC 与工作项高频浅栈执行）；
       * `DrvSecurity.cpp`：`SipHash24`、`CalcAdler32`、`Rc4Encrypt`、`Rc4Decrypt`（纯微秒级基础算法原语浅栈执行）。
  3. **鉴权核心与控制流代数闭环保持重度防护**:
     - `ValidateToken`、`ParseTokenFromFileName`、`ScanAndDecryptUserPayload`、`SetAuthStateInvariant` 等鉴权守门人例程维持 BCF+MBA 重度混淆，消灭单字节静态 Patch 点，保护动态令牌派生逻辑。
  4. **全链路 Zero IAT 动态函数全量初始化收敛契约 (GetModuleExport 运行态清零)**:
     - 彻底清除此前散落在 `RpcDispatcher.cpp`（`RtlGetCompressionWorkSpaceSize`, `RtlCompressBuffer`, `RtlDecompressBuffer`）与 `WfpBypass.cpp`（`KfdGetRefCallout`, `KfdDeRefCallout`）中的运行态临时 `GetModuleExport` 解析；
     - 将上述例程全量收敛至 `MACHENIKE_PFN` 结构体，在驱动入口 `DriverCore::MachenikeUserVarInit` 阶段一次性批量解析完成并完成 100% 结构体字段 1:1 严格对齐；
     - 旁路模块探测 `ScanBypassModules` 前置至 `DriverCore::Initialize` 立即执行，消灭后台工作项的延迟初始化隐患。

- **已知约束与避坑**:
  1. **内核 24KB 栈红线**: 严禁对包含多层嵌套调用、递归或高频循环微秒级读写函数开启 BCF / MBA 混淆，防止动态下调栈指针击穿栈底 Guard Page 触发 `BugCheck 0x7F`；
  2. **反作弊模块原生执行铁律**: 反作弊 Hook 审计、DPC 巡检例程严禁混淆，确保其具备微秒级浅栈执行能力，避免产生可被反作弊检测的异常长时延迟（DPC Latency Spike）与栈展开断裂；
  3. **optnone 覆盖原则**: 凡在混淆源文件中新引入的性能敏感辅助例程或底层硬件寄存器读取（如 `__readdr`），必须及时补全 `NO_OBFUS`。
