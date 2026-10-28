# ADR-0018: 废除常驻线程硬编码盲删、宿主加载器自路径透传与驱动入口系统工作项精准粉碎

- **状态**: 已采纳
- **日期**: 2026-10-15
- **核心领域**: 反作弊对抗 / 痕迹清理 / 跨环契约 / 系统稳定性

---

## 一、 上下文与痛点

1. **常驻通信线程盲删隐患**：
   过去的实现中，在 `WskServerThread`（常驻通信引擎单线程）启动时，硬编码枚举了 `C:\host_loader.exe`、`C:\LeechLoader.exe` 等 6 个固定路径，并执行 `ZwCreateFile(..., FILE_DELETE_ON_CLOSE)` 盲删。这种设计存在严重弊端：
   - 宿主加载器在实战中通常是由局域网下发随机命名（如 `sdxxxxx.exe`）或放置于用户自定义目录、下载文件夹等，固定路径命中率极低；
   - 盲删行为在网络服务启动阶段产生毫无意义的多余文件打开失败审计，容易被反作弊或 EDR 行为监控系统捕获；
   - 违背了常驻线程职责单一原则（网络单通信引擎不应混杂文件系统巡检操作）。

2. **进程生命周期与文件句柄占用死锁**：
   若在 `host_loader` 正在与驱动通信时进行文件删除，由于 Windows PE 加载器持有当前可执行文件的镜像执行映射句柄，尝试删除必将返回 `STATUS_CANNOT_DELETE` 或 `STATUS_SHARING_VIOLATION`。

---

## 二、 技术决策与规范

1. **彻底清理通信线程盲删逻辑**：
   - 从 `wsk_server.c` 中彻底删除 `WskServer_TryDeleteHostLoader` 函数及其固定候选路径数组 `Candidates`；
   - 消除 `WskServerThread` 中开头的删除调用，确保常驻通信线程纯粹专注于 TCP/WSK 数据分发。

2. **跨环契约扩展 (`DRV_BOOT_CONFIG_EX`)**：
   - 为避免破坏内存映射模式下严格对齐的 120 字节 `ShellcodeParams` 静态断言（`sizeof(ShellcodeParams) == 120`），保持原有 `DRV_BOOT_CONFIG`（36 字节）定义与布局绝对不变；
   - 定义扩展结构体 `DRV_BOOT_CONFIG_EX`，包含宿主端传入的自定位真实完整路径：
     ```c
     typedef struct _DRV_BOOT_CONFIG_EX
     {
         DRV_BOOT_CONFIG Base;
         WCHAR HostLoaderPath[260]; // 宿主加载器自身绝对路径
     } DRV_BOOT_CONFIG_EX, *PDRV_BOOT_CONFIG_EX;
     ```

3. **宿主端自身路径精准自提取**：
   - 在宿主端 `host_loader` 激活驱动启动的入口（[`utils.cpp`](file:///e:/Project/Drv/CheatFrameWork/host_loader/LeechLoader/utils.cpp) 中的 `VerifyAndActivateDriver`）中，调用 `GetModuleFileNameW(NULL, cfgEx.HostLoaderPath, 260)` 获取自身进程可执行文件的绝对物理路径，并随 `IOCTL_MK_START_TRANSPORT` 下发给内核驱动。

4. **驱动入口挂靠系统工作线程异步执行 (System Worker Item)**：
   - 在驱动入口（`IOCTL_MK_START_TRANSPORT` 及 `DriverEntry` 启动分发逻辑）处判断：若传入数据长度符合扩展配置且包含有效路径（`HostLoaderPath[0] != L'\0'`），通过 `ExInitializeWorkItem` 与 `ExQueueWorkItem(..., DelayedWorkQueue)` 将删除任务投递至系统工作线程；
   - **执行上下文**：工作项运行在 Windows 核心系统工作者线程（System Worker Thread）中，上下文天然归属于 `System` 进程（PID 4），IRQL = `PASSIVE_LEVEL`，绝不阻塞应用层调用线程；
   - **调用方 PID 记录与进程生命周期状态探测**：调度删除任务时同时捕获记录调用方宿主加载器进程 PID；工作项运行后，首先通过动态解析导出的 `PsLookupProcessByProcessId`（哈希 `0xB1E34721`）以 200ms 为步长轮询探测该进程是否仍存活：
     * 若进程仍在运行（存活），持续等待其主动终止释放可执行文件镜像句柄；
     * 若进程已退出（不存在），立即跳出等待循环并进入下一步文件粉碎；
     * 若超过最大超时等待阈值（50 轮 * 200ms = 10 秒）目标进程依然存活，为避免阻塞系统工作线程或引发死锁，主动放弃删除并安全退出工作线程；
   - **句柄防抖与共享冲突重试**：退出等待后加入 100ms 防抖，打开文件时若遇到瞬时句柄共享冲突（`STATUS_SHARING_VIOLATION` 0xC0000043 或 `STATUS_CANNOT_DELETE` 0xC0000121），以 200ms 间隔自动重试至多 5 次；
   - **NT 符号路径标准化与强制粉碎**：自动补齐 `\??\` 前缀，使用系统特权（`OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE`）配合 `FILE_DELETE_ON_CLOSE` 标志打开文件并立即调用 `ZwClose`，完成精准无痕粉碎，随后主动释放工作项内存。

---

## 三、 已知约束与避坑铁律

1. **严禁在通信热路径或通信线程中直接删除文件**：
   所有文件清理操作必须与网络数据通道彻底解耦，仅在驱动初始化启动入口一次性挂靠系统工作项触发。
2. **严禁破坏 Shellcode 120 字节结构对齐**：
   必须通过 `DRV_BOOT_CONFIG_EX` 派生扩展，严禁直接在 `DRV_BOOT_CONFIG` 头部或中间插入路径字段导致白驱动原位映射 Shellcode 机器码偏移错位。
3. **句柄属性强制为 OBJ_KERNEL_HANDLE**：
   工作项虽在 `System` 进程运行，但打开文件句柄必须强制附加 `OBJ_KERNEL_HANDLE`，确保句柄进入内核私有句柄表，防止句柄泄露至应用层可见句柄表。
