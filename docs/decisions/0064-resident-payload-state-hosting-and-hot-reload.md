# ADR-0064: 载荷状态常驻托管 (Resident State Hosting)、手动映射防重与免重启热重载规范

- **状态**: 已采纳
- **日期**: 2026-10-25
- **影响模块**: `vt/VtBootstrapDriver/common/payload_abi.h`, `vt/VtBootstrapDriver/vt/hv.h`, `vt/VtHypervisor/vt/hypercalls.h`, `vt/VtHypervisor/amd/svm-exit.cpp`, `vt/VtResidentPayload/payload.cpp`, `vt/VtResidentPayload/bridge/entry/bridge_entry.inl`, `vt/VtResidentPayload/bridge/hypercall/resident_commands.inl`, `vt/VtBootstrapDriver/Utils.h`, `vt/VtBootstrapDriver/Utils.cpp`, `vt/VtBootstrapDriver/main.cpp`, `loader/main.cpp`, `loader/vt_loader.h`

## 上下文与痛点

在 VT 硬件虚拟化三合一架构中，驱动加载模式若选择「手动映射 (ManualMap, mode=2)」，首次加载末尾 `loader.exe` 会调用 `ReleaseResidentBootstrap()` 执行 `dropctl` 卸载 `VtBootstrapDriver` 宿主，并销毁 `\\.\MapPayloadCtl` 控制设备。同时，ManualMap 模式下为保持极致隐匿，**故意不创建 `\\.\MsNetEndpoint` 设备和符号链接**。

这引发了严重问题：
1. **状态丢失与二次探测失效**：记录旧 `Machenike` 映射基址、镜像大小与 `DriverUnload` 例程指针的变量（`Utils::machenike*`）均位于临时宿主 `VtBootstrapDriver` 的数据区。宿主被卸载后，第二次运行 `loader.exe` 时打不开控制设备，也打不开业务符号链接，防重探测误判为未加载。
2. **误杀旧 VT 与双重实例冲突**：误判后，`loader.exe` 重新拉起 `VtBootstrapDriver.sys`。内核入口检测到 `pre_load_hv_ready == true`，粗暴调用 `mapdriver_stop_resident_hv_without_testdriver` 强行停止正在运行的旧 VT，而旧 `Machenike` 仍驻留内存中（后台工作项和 WSK 端口处于活跃状态），导致新驱动二次加载绑定端口失败或并发崩溃。
3. **无法免重启热重载**：由于旧驱动的 `DriverUnload` 已经丢失，开发调试期间无法干净卸载旧实例，任何代码修改后重新部署都必须依赖重启操作系统。
4. **硬性安全约束**：严禁通过探测本地通信端口（如 10001）来判断是否运行，必须基于内核与 Hypervisor 原生状态机制判定。

---

## 技术决策与规范

采用「方案 B：状态托管至常驻 `VtResidentPayload`」架构：

### 1. 寄存器级轻量 Hypercall 契约扩展 (Zero Memory Overhead)
在统一 Hypercall 体系中扩展 96 与 97 号指令，Intel VMX 与 AMD SVM 双架构全量对称支持：
- **`PAYLOAD_HYPERCALL_SET_MACHENIKE_STATUS` (96)**：
  - `RCX` (`args[0]`): `machenike_base` (UINT64)
  - `RDX` (`args[1]`): `machenike_size` (UINT64)
  - `R8`  (`args[2]`): `flags` (UINT64)（低 32 位为 `mode`，第 32 位为 `used_indep`，第 40 位为 `loaded`）
  - `R9`  (`args[3]`): `driver_unload` (UINT64)
  - 返回值: `1`
- **`PAYLOAD_HYPERCALL_GET_MACHENIKE_STATUS` (97)**：
  - `RCX` (`args[0]`): 可选输出缓冲区 GVA（若 $\ge 48$ 字节则填入 6 个 UINT64 字段）
  - `RDX` (`args[1]`): 缓冲区长度
  - 返回值 (`RAX`): `loaded` 状态（1 或 0），无缓冲时可作为单寄存器极速探测。

### 2. `payload_status` 常驻结构体安全扩展
在 `payload_status` 结构体最末尾（`vmexit_ring` 之后）扩展 6 个 64 位字段：
`payload_machenike_base`、`payload_machenike_size`、`payload_machenike_mode`、`payload_machenike_used_indep`、`payload_machenike_driver_unload`、`payload_machenike_loaded`。
- 在现有的 91 号 Hypercall (`PAYLOAD_HYPERCALL_GET_PAYLOAD_STATUS`) 中一并同步回填，保障全量状态查询的一致性；
- 尾部扩容不破坏前置任何既有字段的字节偏移，100% 免疫历史结构体偏移错位。

### 3. 内核入口原生感知与阻断盲目停止 VT
- 当 `VtBootstrapDriver` 重新拉起且 `pre_load_hv_ready == true` 时，优先通过 Hypercall 91/97 查验常驻 `payload_status`；
- 若检测到 `payload_machenike_loaded != 0 && payload_machenike_base != 0`，内核自动反哺恢复 `Utils::machenike*` 全局变量，**阻断对旧 VT 的强行停止例程**；
- 立即建立 `\\.\MapPayloadCtl` 控制设备并向 SCM/Loader 返回 `STATUS_SUCCESS`。

### 4. Loader 闭环与 `--force` 免重启热重载全流程
- **防重复加载**：`loader.exe` 连上控制设备后，若 `QueryStatus(&st)` 发现 `st.machenike_loaded != 0` 且未传 `--force`，输出常驻运行提示，跳过重映射，并调用 `ReleaseResidentBootstrap()` 再次卸载临时宿主驱动，系统恢复无宿主常驻状态。
- **免重启热重载 (`--force`)**：
  1. `loader.exe` 向 `\\.\MapPayloadCtl` 发送 `MAPCTL_IOCTL_FULL_UNLOAD`；
  2. `VtBootstrapDriver` 调用已恢复的 `Utils::UnloadMachenike`，执行旧 `Machenike` 的 `DriverUnload`，优雅注销通信端口、还原隐藏物理页并释放独立页内存；
  3. 执行 `mapdriver_stop_resident_hv_without_testdriver` 停止旧 VT 并释放旧 `VtResidentPayload`；
  4. `loader.exe` 重新调用 `EnsureVtOneKeyActive` 部署新 VT + 新 Payload，并载入新编译的 `Machenike.sys`；
  5. 整个热重载过程耗时 $< 2$ 秒，无需重启操作系统。

---

## 验证与门禁

1. **零外部网络端口依赖**：全流程杜绝任何针对 10001 本地网络套接字的探测逻辑，100% 依赖内核与 Hypervisor 寄存器契约交互。
2. **全平台架构对齐**：AMD SVM 与 Intel VMX 均已实现 96/97 号 Hypercall 派发，并通过 `static_assert` 刚性约束。
3. **工程布局断言**：运行 `python vt/verify_vt_layout.py`，全量 38 项布局断言与 PE/SHA-256 镜像完整性检测全部通过 (`[PASS]`)。

---

## 实机 `BugCheck 0x3B (0xC000001D)` 根因闭环与纵深防御加固

1. **现场证据与第一根因（AMD `svm-exit.cpp` 漏挂接 96/97 分支）**：
   - 首次部署后，WinDbg MCP 捕获 `SYSTEM_SERVICE_EXCEPTION (0x3B)`（`Arg1=0xC000001D`，`RIP=VtBootstrapDriver+0x1512e` `vmmcall`，`RAX=0x0008855446688560` 即 Hypercall 96 `hypercall_set_machenike_status`）。
   - 虽然 `VtResidentPayload/payload.cpp` 的 `PayloadAmdControlDispatch` 已实现 `case 96/97`，但同源编译进 ResidentPayload 的 `vt/VtHypervisor/amd/svm-exit.cpp` (`vmexit_vmmcall`) switch 仅列出了 `91/92/93`，导致 AMD SVM 在收到 `0x60` (96) 时落入 `default: inject_exception(v, amd64_invalid_opcode)` 向 Guest 注入 `#UD`。
   - **修复**：在 `vt/VtHypervisor/amd/svm-exit.cpp` 的 `vmexit_vmmcall` 中补齐 `case hv::hypercall_set_machenike_status` 与 `case hv::hypercall_get_machenike_status`，在 `YVT_RESIDENT_PAYLOAD_COPY` 下转发至 `PayloadAmdControlDispatch`（97 号输出通过栈缓冲 + `copy_to_guest` 安全写回），legacy 分支返回 0 并推进 RIP。
2. **全核 HV 就绪门禁 (`Utils::VerifyAllCpusHvReady`)**：
   - 在 `MAPCTL_IOCTL_LOAD_MACHENIKE` 入口、`mapdriver_load_machenike`、`Utils::LoadMachenike` 状态发布前以及 `Utils::UnloadMachenike` 状态清零前，强制逐逻辑处理器验证 `hv::try_ping()` 位图（`expected_mask == pong_mask`），杜绝单核检查遗漏多核虚拟化状态不一致。
3. **SEH 保护 (`hv::try_vmcall`) 与发布失败逆序回滚**：
   - `vt/VtBootstrapDriver/vt/hv.h` 新增带 `__try/__except` 保护的 `try_vmcall` / `try_ping` / `try_vmcall_set_machenike_status`，拦截任何潜在 `#UD`。
   - `Utils::LoadMachenike` 在最终状态发布或全核校验失败时，严格执行逆序回滚：调用 `Machenike` `DriverUnload` -> 清零全局状态 -> 恢复页面保护为 `PAGE_READWRITE` -> `RtlSecureZeroMemory` 并释放映像 -> 返回 `FALSE`（`MAPCTL_IOCTL_LOAD_MACHENIKE` 返回 `PAYLOAD_RESULT_INVALID_CONTEXT`）。
4. **生命周期并发互斥 (`g_mapdriver_lifecycle_busy`)**：
   - 引入 `mapdriver_lifecycle_guard` 原子互斥锁，阻止 `mapdriver_load_machenike` 与 `mapdriver_full_unload_runtime` 并发执行。
