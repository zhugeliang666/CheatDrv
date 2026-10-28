# ADR-0025: 驱动端 IRP_MJ_CREATE 动态 Token 防伪接入与加载器全链路协同

- **状态**: 已采纳
- **日期**: 2026-10-15
- **涉及组件**: `CheatDrv` / `scm_loader` / `host_loader` / `front_loader_ui`

---

## 上下文与痛点
1. **设备句柄缺乏访问控制**：此前正常加载模式下 `IRP_MJ_CREATE` 直接注册为通用的 `WskIoCreateClose`，无条件放行任意进程的 `CreateFile` 请求，任何低权限应用或对抗进程均可直接打开 `\\.\MsNetEndpoint` 句柄下发控制指令。
2. **缺乏全链路防伪契约**：驱动内部虽具备 `MachenikeDispatchCreate` 动态时间戳 Token 计算算法，但加载器端（SCM Loader 与 Host Loader）未统一适配该打开契约，导致驱动一旦启用鉴权，加载器立即遭遇 `STATUS_ACCESS_DENIED` (0xC0000022)。
3. **前端模式选择盲目连机**：`front_loader_ui` 在用户切换/选择连接模式时，曾短路调用快速自动连接盲目尝试历史 IP，引发长时间超时卡顿与错误弹窗。

---

## 技术决策与规范

### 1. 驱动端注册与空指针防御
- 在 `DriverEntry` 正常加载模式下，将派发例程挂接至带鉴权的专用处理函数：
  ```c
  pDriverObj->MajorFunction[IRP_MJ_CREATE] = MachenikeDispatchCreate;
  pDriverObj->MajorFunction[IRP_MJ_CLOSE] = MachenikeDispatchClose;
  ```
- **空指针防御**：在 `MachenikeDispatchCreate` 与 `MachenikeDispatchClose` 中，优先提取 `pDevObj->DeviceExtension`，若未就绪则回退至全局上下文 `g_pGlobalUserVar`；若两者均为空则安全完成 IRP 并返回 `STATUS_DEVICE_NOT_READY`。

### 2. 动态时间戳 Token 契约与时间窗口容差
- **算法契约**：采用 SipHash-2-4 算法结合预置私钥、30 秒步长的时间戳 Counter、客户端 PID 与魔数 Salt4 生成 32 位 Token，以 `\\.\MsNetEndpoint\<TokenHex>` 形式作为文件名传递。
- **时间窗口容差**：驱动端比对 `[-1, 0, 1]` 范围内的 Counter，应对跨机/跨进程微秒级时钟偏差；匹配成功方可授予设备句柄。

### 3. 加载器全链路兼容打开例程
- 在 `loader_common.h` 与 `host_loader/utils.cpp` 中提取公共的 `OpenDriverDeviceCompatible` / `VerifyAndActivateDriver` 逻辑：
  1. 优先执行 `[-1, 0, 1]` 窗口计算 Token，构造 `\\.\MsNetEndpoint\%08X` 打开；
  2. 若打开失败，自动平滑回退尝试无 Token 的裸路径 `\\.\MsNetEndpoint`，完全向下兼容 `NO_AUTH` 调试模式。

### 4. 前端交互体验解耦
- 在 `front_loader_ui` 的 `useAppController.ts` 中移除 `handleSelectMode` 内部的快速自动盲连逻辑，用户切换模式仅作为配置设定与分步引导流程启动，杜绝历史 IP 阻塞导致 25 秒卡顿。

---

## 已知约束与避坑
1. **UTF-8 BOM 规范**：修改涉及头文件与代码后，必须强制运行 `python convert_bom.py`，防止 MSVC 在代码页 936 下因汉字末尾 `0x5C` 引发语法拼接崩溃。
2. **模式与依赖清晰化**：生产环境构建由宏 `NO_AUTH 0` 统一收拢，免认证调试模式由 `NO_AUTH 1` 支持，确保逻辑边界清晰无残留。
