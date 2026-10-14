# ADR-0019: 驱动 NoAuth 免认证与免删 Loader 调试开关规范

- **状态**: 已采纳
- **日期**: 2026-10-15
- **核心领域**: 跨环通信契约 / 调试模式治理 / 痕迹清理控制

---

## 一、 上下文与痛点

1. **单机与本地开发调试阻塞**：
   - 生产模式下，驱动实施了严格的双向防伪认证：应用层打开设备对象需由 SipHash Token 鉴权（`MachenikeDispatchCreate`），下发启动配置需带 `DRV_BOOT_CONFIG_MAGIC` 与云端 SessionToken，否则立即拒绝访问；
   - 生产模式下驱动入口在收到配置后，会立即挂靠系统工作线程（System Worker Item）对宿主 `host_loader.exe` 实施 2 秒延时针对性粉碎删除（`FILE_DELETE_ON_CLOSE`）；
   - 在本地单机开发、逆向分析、断点调试以及 CI/CD 单元测试时，开发者需要频繁反复运行 `host_loader`，若驱动强制执行鉴权校验与粉碎删除，会导致：
     1. 缺少云端鉴权服务器或特定 Token 时无法直接与驱动通讯；
     2. 每次运行后 `host_loader.exe` 均被内核粉碎，必须重新编译或从备份中拷回，严重降低研发排障效率。

---

## 二、 技术决策与规范

1. **集中式开关宏定义与别名兼容**：
   - 在核心公共头文件 [`Common.h`](file:///e:/Project/Drv/CheatDrv/Common.h) 的 `【驱动全局调试与功能开关控制台】` 区域提供专用的 NoAuth 宏开关：
     ```c
     #ifndef NO_AUTH
     #define NO_AUTH 0
     #endif

     #ifndef ENABLE_NO_AUTH
     #define ENABLE_NO_AUTH NO_AUTH
     #endif

     #if defined(NOAUTH) && (NOAUTH)
     #undef NO_AUTH
     #define NO_AUTH 1
     #undef ENABLE_NO_AUTH
     #define ENABLE_NO_AUTH 1
     #endif
     ```
   - 默认值设为 `0`（保持生产安全环境下的全套鉴权与粉碎自毁机制）；在工程配置或本地调试时只需将 `NO_AUTH`（或 `ENABLE_NO_AUTH` / `NOAUTH`）设为 `1`，即可一键切入调试免鉴权模式。

2. **跨环认证免检旁路 (NoAuth Bypass)**：
   - **设备打开句柄放行 (`MachenikeDispatchCreate`)**：开启 `NO_AUTH` 时，直接略过文件名中 SipHash Token 的解析与时间步长计算，无条件向调用进程授予 `STATUS_SUCCESS` 访问权限；
   - **启动控制码魔数放行 (`IOCTL_MK_START_TRANSPORT`)**：开启 `NO_AUTH` 时，若传入未对齐或测试用的魔数，驱动予以告警放行并不拒绝服务；驱动仍照常计算并回填合法 `DriverSignature`，确保向上完全兼容已有的应用层指纹校验；
   - **手动映射缺省模式兜底 (`DriverEntry`)**：在手动映射模式下，若未提供或提供了无效模式参数，`NO_AUTH` 开启时自动降级启动默认 `WSK_TCP`（端口 10001），避免驱动自我卸载退出。

3. **保留 Loader 现场与免删旁路 (Loader Preservation)**：
   - **例程级防御**：在 `Main_ScheduleDeleteHostLoader` 内部直接置入 `#if NO_AUTH || ENABLE_NO_AUTH` 判定，若宏开启则打印跳过日志并直接 `return`；
   - **调用端双重隔离**：在 `WskIoDeviceControl` 与手动映射入口的调用点处统一包覆条件编译，宏开启时不申请 `DELETE_LOADER_WORK_CONTEXT` 内核池内存，不投递系统工作项，彻底杜绝文件删除行为。

---

## 三、 已知约束与避坑

1. **生产发布环境严禁使能**：
   - 正式发布至生产对抗环境的 Release 构建必须确保 `NO_AUTH == 0`，以防止驱动暴露公开免鉴权 IOCTL 接口被反作弊样本沙箱枚举或利用。
2. **签名回传逻辑保持透明**：
   - `NO_AUTH` 宏仅用于驱动端放宽对客户端的合法性验证与跳过自身删除逻辑，驱动仍必须正确返回 `DRV_BOOT_RESPONSE` 中的 `DriverSignature`，避免破坏应用层既有的签名校验链。
