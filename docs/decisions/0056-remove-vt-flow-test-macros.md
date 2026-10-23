# ADR-0056：删除 VT 流程测试宏并固化常驻业务路径

- 状态：已采纳
- 日期：2026-10-23
- 关联：ADR-0051、ADR-0055

## 上下文

VT 三个工程长期保留了 Stage、Bisect、Selftest、Stability 等编译期流程门。这些宏曾用于逐段排查启动、VMEXIT、EPT、PMO 和卸载问题，但在 AMD-SVM 常驻闭环迁移完成后继续保留会产生多套互斥生命周期：同一份源码可能编译为诊断往返、旧映像回退或正式交接，代码审查无法从运行态状态判断真实所有权。

## 决策

1. 删除 `MAPDRIVER_VT_STAGE*`、`YVT_ENTRY_BISECT_BYPASS`、`PAYLOAD_BISECT_*`、`PAYLOAD_STABILITY_*`、VMEXIT 自测和 GetBuffer 分段测试宏。
2. 按删除前启用的路径固化控制流，保持二进制行为不因本次清理发生策略切换。
3. 继续保留真正的业务宏，例如日志、部署清理策略、内存分配策略、DWM 构建归属和公开 ABI 常量。
4. 把 `TEST_SYS_*`、`MMTEST`、`FREE_TEST`、`HOSTEX_TEST` 等协议宏改为 Hypervisor payload、内存审计、旧映像释放和 Host 异常探针等业务语义；IOCTL 数值、Magic 数值和结构体布局不变。
5. Windows `CODEINTEGRITY_OPTION_TESTSIGN/TEST_BUILD` 是平台定义，不属于工程流程门，保持原名和数值。

## 生命周期契约

- Bootstrap 始终执行正式一键交接路径；AMD 使用逐 vCPU `resident_loop/resident_ack`，Intel 使用 resident bridge。
- 旧映像释放仍以完整 ACK、引用扫描和两阶段 RELEASE 为硬门禁。
- ResidentPayload 的 Hook、EPT、PMO 与内存过滤采用固定业务配置；不再通过测试阶段宏改变所有权。
- 任一初始化、ARM、ACK 或引用检查失败都保留资源并返回可诊断错误，不通过编译宏退回另一套生命周期。

## 已知约束

- 本次只删除流程测试宏和死分支，不改变 IOCTL 编号、Magic、结构体尺寸或 AMD-SVM ABI 86 / HV diag layout 26。
- `CODEINTEGRITY_OPTION_TESTSIGN` 与 `CODEINTEGRITY_OPTION_TEST_BUILD` 来自 Windows Code Integrity 契约，必须保留。
- 硬件运行效果仍需 AMD 多核实机验证；离线构建只能证明编译、链接和静态契约一致。

## 回滚

反向应用本次补丁可恢复原流程门。回滚验证必须在独立副本执行，不能在最终工作副本上覆盖已固化的业务路径。
