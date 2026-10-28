# ADR-0027: 驱动 CreateFile 阶段 Token 与参数复合透传及 IOCTL 彻底消除规范

- **状态**: 已采纳
- **日期**: 2026-10-16
- **涉及组件**: `CheatDrv (Main.cpp)` / `loader (loader_common.h, scm_loader.h)`

---

## 上下文与痛点
1. **未校验 Token 越权风险**：此前驱动端 `MachenikeDispatchCreate` 优先匹配纯 HexPayload 分支，导致携带 HexPayload 的请求直接绕过了时间戳 Token 鉴权，破坏了动态防伪机制。
2. **两阶段交互繁琐与控制码暴露**：加载器此前在 `CreateFile` 打开句柄后，仍需发起 `IOCTL_MK_START_TRANSPORT` 与 `IOCTL_MK_GET_STATUS` 两轮 `DeviceIoControl` 调用下发参数与查询状态，存在多余的 R3/R0 上下文切换与控制码审计特征。
3. **重复解析与路径失配**：加载器先前默认构造未带 Token 的纯 HexPayload 路径，导致带 Token 鉴权与参数下发逻辑脱节。

---

## 技术决策与规范

### 1. 驱动端 DispatchCreate 极简鉴权与启动闭环
- **统一准入校验**：严格先提取并校验动态时间戳 Token（基于 `Utils_ParseTokenFromFileName` 与 `MachenikeCalcToken`，容差 `[-1, 0, 1]` 窗口）。未通过者一律直接拒绝 (`STATUS_ACCESS_DENIED`)。
- **复合参数直读拉起**：Token 校验通过后，直接尝试从文件名解析 HexPayload 载荷（`Utils_ParseCreatePayloadFromFileName`）。若存在启动参数，直接就地调用 `Main_ApplyBootConfigAndStart` 拉起指定传输协议（TCP/UDP/USB），失败则直接向 IRP 赋回错误状态码。

### 2. 加载器默认复合路径直传
- 在 `OpenDriverDeviceCompatible` 中：
  - 默认计算当前时间戳 Token 并优先构造形如 `\\.\MsNetEndpoint\<TokenHex>_<HexPayload>` 的复合路径；
  - 驱动在 `IRP_MJ_CREATE` 处理期间即完成身份鉴权与服务拉起；
  - 保留纯 Token、纯 HexPayload 与裸路径的向下兼容降级逻辑（支持 `NO_AUTH` 调试模式）。

### 3. 彻底消除 SCM Loader 端的 IOCTL 发送
- 将原 `SendBootConfigViaIOCTL` 重构精简为 `ActivateDriverTransport`：
  - 仅需执行一次 `OpenDriverDeviceCompatible` 打开设备即完成了内核服务的配置与启动；
  - 打开成功后直接 `CloseHandle` 关闭句柄；
  - 彻底移除 `IOCTL_MK_START_TRANSPORT` 与 `IOCTL_MK_GET_STATUS` 的发送，消除不必要的 I/O 交互与代码冗余。

---

## 已知约束与避坑
1. **UTF-8 BOM 约束**：完成修改后必须执行 `python convert_bom.py`，确保所有文件编码统一。
2. **错误状态对齐**：若驱动端服务启动失败，`DispatchCreate` 必须返回对应 NTSTATUS，防止客户端误判服务启动成功。
