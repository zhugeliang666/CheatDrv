# ADR-0043: 常驻安全工作项硬件断点自检与代码段动态完整性周期巡检规范

- **状态**: 已采纳
- **日期**: 2026-10-19
- **上下文与痛点**:
  此前，驱动硬件断点审计（`AuditHardwareBreakpoints`）与代码段只读完整性哈希校验（`VerifyTextIntegrity`）仅在应用层首次发起 `IRP_MJ_CREATE`（`MachenikeDispatchCreate`）时被动触发一次。在远程 TCP/UDP/USB 网络通信或内存映射常驻运行模式下，只要不再重复调用 `CreateFile`，该校验逻辑将永久失效。逆向破解人员或反作弊沙箱可在驱动启动后任意挂接硬件断点（DR0~DR3 / DR7）或下断内存断点（Patch/Hook），原有机制完全失去感知与防御能力。

- **技术决策与规范**:
  1. **防御逻辑全面迁移至常驻系统安全工作项**:
     - 彻底从 `MachenikeDispatchCreate` 剥离单次执行的防御校验，消除派遣热路径冗余开销与代码膨胀；
     - 复用系统原生 `ExpWorkerThread`（`SecurityWorkerRoutine`），保持零新增 `PsCreateSystemThread` 暴露（严格继承 ADR-0011 与 ADR-0018 隐蔽性标准）；
  2. **深度安全周期巡检调度**:
     - **低频深度流（10 秒节拍）**: 统一收敛至 `ExecuteDeepSecurityScans` 中执行，每 10 秒轮询比对：
       1. `DrvSecurity::AuditHardwareBreakpoints()`：单条机器指令直读 CPU `DR0~DR7` 调试寄存器；
       2. `DrvSecurity::VerifyTextIntegrity()`：对非分页核心 `.text` 代码段执行 Adler32 哈希动态比对；
  3. **违规响应分级策略 (上报与熔断解耦)**:
     - **代码段完整性损坏（VerifyTextIntegrity 失败）**: 维持严重违规即时熔断，调用 `TransportManager::SetSessionCryptKey(0)` 并上报服务端，使通信链路瞬间错乱瘫痪；
     - **硬件断点自检（AuditHardwareBreakpoints 检出）**: 调整为**仅去重异步上报，不置零 SessionCryptKey**。避免立即断连引发打草惊蛇（让逆向或分析人员二分定位检测点），由 `ExceptionReporter::ReportFormat` 将命中 DR 寄存器状态上报服务端，驱动业务链路保持正常运行；
  4. **基线单次固化**:
     - 统一在 `DriverCore::Initialize` 与 `DriverEntry_ManualMap` 初始化末尾调用一次 `DrvSecurity::InitTextIntegrity()` 固化哈希基准，杜绝动态重复重置导致基线失效。

- **已知约束与避坑**:
  1. **IRQL 契约**: 该后台巡检工作项必须运行在 `PASSIVE_LEVEL`，确保可安全调用内存探针与 `__try/__except` 结构化异常处理；
  2. **零分配与无锁执行**: `AuditHardwareBreakpoints` 严禁分配动态内存，仅执行只读硬件状态寄存器读取；
  3. **编码规范**: 修改代码后必须执行 `python convert_bom.py` 维持全工程 UTF-8 BOM 一致性。
