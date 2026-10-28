# ADR-0044: 宿主自粉碎标记动态解耦与安全监控扫描引擎编译开关宏规范

- **状态**: 已采纳
- **日期**: 2026-10-19
- **核心领域**: 跨环协议契约 / 痕迹清理控制 / 性能与调试治理

---

## 一、 上下文与痛点

1. **宿主自粉碎逻辑与 `NO_AUTH` 宏耦合死锁**：
   - 历史方案（ADR-0019）中，宿主加载器自删除调度逻辑被 `#if !(NO_AUTH || ENABLE_NO_AUTH)` 粗暴包裹；
   - 当启用 `NO_AUTH=1` 调试时，自删除例程直接被编译器剔除为桩函数；而当关闭 `NO_AUTH` 进入安全模式时，驱动又无视宿主意图，只要路径非空便无条件执行异步粉碎；
   - 导致无法由宿主端（`host_loader`）根据运行环境（单机自动化测试、联调排障 vs 生产对抗交付）动态决定是否执行删除自毁。

2. **安全监控扫描引擎不可控开销**：
   - 驱动常驻安全监控引擎（`SecurityWorkerRoutine` 与 2s 周期 DPC 定时器）包含 ACE 驱动探测、网络/USB/高危API Hook 检测、代码段完整性 Adler32 校验与 DR0-DR7 硬件断点自检；
   - 在基准性能压测、纯通信吞吐带宽测算或极简单机调试场景下，缺乏一个全局开关宏，无法一键阻断周期性 DPC 与系统工作项投递。

---

## 二、 技术决策与规范

1. **跨环自删除开关标志位动态解耦**：
   - 在跨环启动配置结构体 `DRV_BOOT_CONFIG.Flags` 中新增专用特性位掩码：
     ```c
     #define DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP  0x00000001 // 允许驱动异步粉碎删除宿主 Loader 进程与文件
     #define DRV_BOOT_FLAG_DELETE_LOADER               DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP
     ```
   - 彻底废除驱动端 `DriverCore.cpp` 中围绕 `ScheduleDeleteHostLoader`、`SetPendingHostLoaderCleanup` 和 `AsyncDeleteHostLoaderWorkRoutine` 的 `#if !(NO_AUTH || ENABLE_NO_AUTH)` 编译期门禁；
   - 驱动端统一通过动态位掩码判定：
     ```cpp
     if ((pCfg->Flags & DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP) && HostLoaderPath[0] != L'\0') { ... }
     ```
   - 宿主端（`LeechLoader`）在 `global_var` 中增加 `enable_delete_loader`，支持命令行 `-delete-loader` / `--delete-loader` 动态开启，默认设为 `0`（不粉碎），保障本地开发与测试安全。

2. **安全监控扫描引擎全局编译控制宏**：
   - 在核心公共头文件 `Common.h` 开关控制台中定义：
     ```c
     #ifndef ENABLE_SECURITY_MONITOR
     #define ENABLE_SECURITY_MONITOR 1
     #endif
     #ifndef MK_ENABLE_SECURITY_MONITOR
     #define MK_ENABLE_SECURITY_MONITOR ENABLE_SECURITY_MONITOR
     #endif
     ```
   - 当 `ENABLE_SECURITY_MONITOR == 0` 时：
     1. 初始化阶段跳过 `KeSetTimerEx`，完全不启动后台 2s 周期性 DPC 定时器；
     2. `SecurityWorkerRoutine` 入口直接截断返回，消除一切未预期投递的工作项执行；
     3. 彻底避免无意义的内核 DPC 调度开销与多核上下文切换。

---

## 三、 已知约束与避坑

1. **协议结构体向下兼容性**：
   - `Flags` 字段位于 `DRV_BOOT_CONFIG` 固有偏移内，属于已分配字段，未改变结构体大小（`sizeof(DRV_BOOT_CONFIG) == 36`），与历史客户端网络封包严格兼容。
2. **多进程并发保护**：
   - 即使通过 `Flags` 开启自删除，清理路径依旧遵循原子单次触发门禁（`InterlockedCompareExchange(&s_CleanupTriggered, 1, 0)`），并在首个业务网络包到达后方才异步调度，严禁在握手未完成前提前关闭宿主。
