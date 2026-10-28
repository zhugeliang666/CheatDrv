# ADR-0045: 跨环穿透 CardKey 与驱动启动配置扩展规范

- **状态**: 已采纳
- **日期**: 2026-10-19
- **核心领域**: 跨环协议契约 / 鉴权穿透 / 结构体对齐治理

---

## 一、 上下文与痛点

1. **驱动端授权上下文缺失**：
   - 历史架构中，控制端（VerifyLib/前端 UI）在 `HSTV_LOGIN_REQ` 登录阶段将 `req->CardKey` 传至宿主端（`host_loader`），并保存在 `gVar.slogin_data.card_key`；
   - 但宿主端通过 IOCTL / 用户态内存锚点向内核驱动下发配置（`DRV_BOOT_CONFIG_EX`）以及控制端发送 `HSTV_DRIVER_START_REQ` 启动驱动时，均未携带 `CardKey`；
   - 内核驱动（`CheatDrv`）仅接收了 `ApiUrl`、`LoginUrl`、`ReportUrl` 及三项版本标识，未包含任何用户授权卡密上下文，导致驱动在发生内核级事件、日志上报或需联动二次鉴权时无法获取到有效的 CardKey。

2. **跨环契约对齐与防蓝屏铁律**：
   - 根据 ADR-0018 与 ADR-0005，严禁在基础结构体 `DRV_BOOT_CONFIG` 头部或中间插入字段，否则会破坏白驱动原位映射机器码中的 `ShellcodeParams` 120 字节严格断言偏移，引发系统崩溃。

---

## 二、 技术决策与规范

1. **跨环配置尾部安全扩展 (`DRV_BOOT_CONFIG_EX`)**：
   - 在扩展结构体 `DRV_BOOT_CONFIG_EX` 尾部追加 `CardKey[64]` 字段（位于 `ClientVersion[32]` 之后）：
     ```cpp
     typedef struct _DRV_BOOT_CONFIG_EX
     {
         DRV_BOOT_CONFIG Base;
         wchar_t HostLoaderPath[260];
         char ApiUrl[128];
         char LoginUrl[128];
         char ReportUrl[128];
         char BrandVersion[32];
         char SelectedGame[32];
         char ClientVersion[32];
         char CardKey[64]; // 卡密字符串
     } DRV_BOOT_CONFIG_EX, *PDRV_BOOT_CONFIG_EX;
     ```
   - 同步更新 `CheatDrv/Core/Common.h`、`CheatDrv/loader/loader_common.h`、`host_loader/LeechLoader/protocol.h` 和 `DeltaForceVMMInterface/VerifyLib/protocol.h`，确保驱动端与宿主端内存锚点（`DRV_USER_PAYLOAD_ANCHOR`）的 `sizeof(DRV_BOOT_CONFIG_EX)` 计算严格一致。

2. **双机启动协议扩展 (`HSTV_DRIVER_START_REQ`)**：
   - 在控制端发往宿主端的 `HSTV_DRIVER_START_REQ` 结构体尾部追加 `char CardKey[64]` 字段；
   - 控制端（`VerifyLib/socket.cpp`）在发送启动命令时自动注入 `gVar.slogin_data.card_key`；
   - 宿主端（`host_loader/socket.cpp`）在解析 `HSTV_DRIVER_START_REQ` 时若收到非空卡密，自动更新并兜底至 `gVar.slogin_data.card_key`。

3. **宿主下发与驱动内核接收闭环**：
   - 宿主端在 `VerifyAndActivateDriver` 中将当前有效卡密拷贝至 `cfgEx.CardKey`；
   - 内核驱动端 `DriverCore.cpp` 增加全局变量 `CHAR g_CardKey[64] = {0};`，在 `ApplyBootConfigAndStart` 及 IOCTL 处理中校验非空并拷贝至 `g_CardKey`，形成完整的内核卡密链路。

---

## 三、 已知约束与避坑

1. **严禁修改 `DRV_BOOT_CONFIG` 基础头**：
   - 基础 `DRV_BOOT_CONFIG` 严格保持不变，所有新字段必须追加在 `DRV_BOOT_CONFIG_EX` 尾部。
2. **多端定义必须全局同步**：
   - 因用户态内存锚点（`DRV_USER_PAYLOAD_ANCHOR`）依赖 `sizeof(DRV_BOOT_CONFIG_EX)` 作为 RC4 加密密文长度，若某一模块定义遗漏将导致长度校验不匹配（`CipherLen mismatch`），使驱动拒绝解密启动。
