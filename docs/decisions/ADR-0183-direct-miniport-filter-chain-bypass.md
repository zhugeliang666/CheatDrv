# ADR-0183：方案 B —— Direct Miniport 直连与 NDIS 底层指示槽位接管

- 状态：已实现（Debug x64 编译通过，待真机验证）
- 日期：2026-11-06
- 关联代码：`Transport/miniport_direct.{h,cpp}`、`Transport/NdisOffsets.h`、`Transport/eth_server.cpp`
- 取证工具：`analysis/ndis_symbols/{offsets_dump.cpp,build_offsets.cmd,disasm_ndis.py}`

## 1. 背景

EthServer 通过 NDIS 协议驱动（协议名伪装 `NDISUIO`）收发自定义以太网类型 0x8844 的分片帧。
该路径位于 **过滤器链之上**：所有 NBL 都要穿过 Npcap（`npcap.sys` LWF）等轻量过滤驱动，
抓包工具与本机安全软件都能完整重建本通道的上下行流量，暴露面过高。

方案 A（自建 LWF）被否决：需要 INF + `FilterType/FilterClass` 注册，会在
`Get-NetAdapterBinding` / `fltmc` / 服务表中留下持久可见项，反而放大暴露面。

## 2. 决策

采用内核数据指针级旁路，不新增任何注册项、不写 `ndis.sys` 代码页：

1. **发送直连**：用本协议 `NdisOpenAdapterEx` 返回的 OpenBlock 解析出目标网卡的
   `_NDIS_MINIPORT_BLOCK`，直接调用 Miniport 的 `SendNetBufferListsHandler`，
   NBL 不再经过任何 FilterModule。
2. **接收接管**：改写该 MiniportBlock 的两个"底层指示"槽位，插入签名帧节流器：
   - `Next`（`_NDIS_MINIPORT_HANDLERS`）节点，NDIS 迭代数据通路实际取用处；
   - `TopIndicateNetBufferListsHandler` 老链头槽位。
   签名帧在 Miniport 边界被截留直投传输层，帧不出现在上行链 → 过滤器全链失明。
3. **全量黑屏模式**：透传目标改为 `NoFilter` 节点的指示处理器，
   协议栈（Tcpip）正常收包，过滤器链看不到该网卡任何上行帧。
4. **不做物理链摘除**：不 unlink `_NDIS_FILTER_BLOCK` 链表。理由见 §6。
5. **无标准发送兜底 + 失败标志交由 R3 处置（2026-11-06 修订）**：删除 `NdisSendNetBufferLists` 回落路径。
   任何一环失败（`ndis.sys` 解析 / OpenBlock→MiniportBlock→Handler 校验 / 指示槽位接管 /
   槽位被外部改写且无法重挂 / 发送时通道不可用）都走同一条致命路径：

   ```
   MkDmReportFatal(reason, status)
     └─ EthServer_DmFatal
          ├─ 置 fChannelFatal + FailReason/FailStatus（模块级静态，Stop 后仍可读）
          ├─ DBG("[x] ... FAILED") + ExceptionReporter 上报
          └─ ExQueueWorkItem → EthServer_Stop：只拆传输通道（停 worker / 解绑 / 回滚槽位）
   ```

   **保留设备对象、不调用 `DriverCore::TriggerUnload()`**：卸载时机交给 loader ——
   loader 通过 `IOCTL_MK_GET_STATUS`(0x902) 读到 `fChannelFatal` 后，自己执行
   `SendStopTransportViaIOCTL()` + `StopAndRemoveService()`（`scm_loader.h::HandleChannelFailureIfAny`），
   支持 `--watch` 秒级轮询。理由：R3 需要在卸载前拿到失败原因（reason/status/计数器），
   而"半隐身"比"不存在"危险得多——回落标准发送等于主动把包送进 Npcap 的捕获链。

## 3. 事实依据（禁止凭记忆改偏移）

全部字段经 `ndis.pdb` 离线导出并与 `ndis.sys` 反汇编交叉验证（Win10 22H2 / 10.0.19041.4522）：

| 结构 | 字段 | 偏移 | 证据 |
|---|---|---|---|
| `_NDIS_COMMON_OPEN_BLOCK` | `MiniportHandle` | `+0x10` | `NdisSendNetBufferLists` 首条指令 `mov rsi,[rcx+10h]` |
| `_NDIS_MINIPORT_BLOCK` | `MiniportAdapterContext` | `+0x18` | PDB |
| | `MediaType` | `+0x1D0` | PDB |
| | `LowestFilter` / `HighestFilter` | `+0x7F8` / `+0x800` | PDB |
| | `TopIndicateNetBufferListsHandler` | `+0x858` | PDB |
| | `NoFilter`（`_NDIS_MINIPORT_HANDLERS`） | `+0x8F8` | PDB |
| | `Next`（`_NDIS_MINIPORT_HANDLERS`） | `+0x9B0` | PDB |
| | `DriverHandle` | `+0xEB0` | PDB |
| | `IfIndex` | `+0xFD8` | PDB |
| `_NDIS_MINIPORT_HANDLERS` | `SendNetBufferListsHandler` | `+0xA8` | PDB |
| | `ReturnNetBufferListsHandler` | `+0xA0` | PDB |
| | `IndicateNetBufferListsHandler` | `+0x90` | PDB |
| `_NDIS_M_DRIVER_BLOCK` | `MiniportDriverCharacteristics` | `+0x70` | PDB |
| `_NDIS_MINIPORT_DRIVER_CHARACTERISTICS` | `SendNetBufferListsHandler` / `Return…` | `+0x48` / `+0x50` | PDB |
| `_NDIS_FILTER_BLOCK` | `NextFilter` / `FilterDriver` / `ModuleContext` / `Miniport` / `Lower` / `Higher` | `+0x08`/`+0x10`/`+0x18`/`+0x20`/`+0x70`/`+0x78` | PDB |

`NdisMIndicateReceiveNetBufferLists` 反汇编（`analysis/ndis_symbols/disasm_ndis.py`）：

```
mov rdi, rcx                       ; rdi = MiniportAdapterHandle（即 MiniportBlock）
mov r9d, esi                       ; flags
mov r8d, ebp                       ; count
mov edx, r14d                      ; port
mov rcx, r15                       ; NBL 链
mov rax, [rdi+0x9C0]               ; Next.IndicateContext      → arg（栈）
mov [rsp+0x28], rax
mov rax, [rdi+0x9D0]               ; Next.IndicateObject       → arg（栈）
mov [rsp+0x20], rax
mov rax, [rdi+0xA40]               ; Next.IndicateHandler = 0x9B0+0x90
mov [rsp+0x30], rax
call ndis!迭代数据通路转发器
```

结论：**迭代路径真正使用的是 `Next` 节点（0x9B0+0x90 / +0x10 / +0x20）**，
只改 `0x858` 在 19041 上不会生效；两个槽位都要接管。

## 4. 发送完成路径

`NdisMSendNetBufferListsComplete` 依据 `NBL->SourceHandle` 定位发起者。
直连发送前把链上每个 NBL 的 `SourceHandle` 指向本协议 OpenBlock，
Miniport 完成后 NDIS 直接回调 `EthProtocolSendNetBufferListsComplete`，
既不需要 hook 完成路径，也不会被过滤器看到。

## 5. 接收截留与归还

- `NDIS_RECEIVE_FLAGS_RESOURCES` 置位：Miniport 保有 NBL 所有权，节流器只拷贝数据、不归还、不上行；
- 未置位：截留帧用 `NoFilter.ReturnNetBufferListsHandler`（或其 context）归还 Miniport，
  与过滤器调用 `NdisFReturnNetBufferLists` 的语义等价；
- 帧数据在 `DISPATCH_LEVEL` 直接进入 `EthServer_ConsumeFrame` 分片重组（与协议上行路径共用同一实现）。

## 6. 为什么不做物理 Filter 链摘除

`LowestFilter/HighestFilter`、`LowerFilter/HigherFilter`、`NextFilter` 三套链接互相约束，
且 NDIS 在 filter attach/detach、`NdisFRestartFilter`、miniport reset 时会遍历并**重建**，
unlink 而不释放引用会留下：

- Npcap 卸载时 `FilterDetach` 不再被调用 → 模块卸载后链表残留野指针 → 0xD1/0x50；
- 协议 unbind / 网卡禁用重建链时读到被摘除的节点 → 0x7E。

因此"摘除"用**等效的槽位重定向**实现（`NoFilter` 节点直投），
可逆、无引用计数风险、随时 CAS 回滚。

## 7. 防御体系相容性

| 项 | 结论 |
|---|---|
| HVCI / VBS (MBEC) | 只改写 NDIS 非分页池中的 8 字节数据槽位，不触碰任何代码页，W^X 无冲突 |
| PatchGuard | 不修改 ntoskrnl/ndis `.text`、不碰 IDT/GDT/MSR/EPROCESS，KPP 校验面无变化 |
| Driver Verifier | NBL 由本驱动池分配、`SourceHandle` 合法，`Special Pool` 可通过；`NDIS Verifier` 的 NBL tracker 可能对非常规入链路径告警，验证机需关闭 NDIS verifier |
| BigPool 审计 | 不新增池分配标签，无新增注册表/对象 |

## 8. 负向证伪（Pre-Mortem）

| 触发条件 | 后果 | 缓解 |
|---|---|---|
| 偏移表与运行版本不符 | 读到错误槽位 → 误改随机指针 | 多级校验：OBJECT_HEADER 合理性、DriverHandle→DRIVER_OBJECT→映像范围、handler 必须落在网卡驱动映像内；任一失败 → `MK_DM_FAIL_RESOLVE`：置失败标志 + 拆通道 + 等 R3 DeleteService（不回落标准发送） |
| 指示槽位接管失败（如槽位值为空/非内核指针）| 通道无法做到过滤器不可见 | `MkDmArmLocked` 返回 FALSE → `MK_DM_FAIL_ARM`：同上 |
| 已接管槽位被 NDIS 改写且重挂失败 | 后续帧重新被过滤器看到 | `MkDm_Refresh` 复检→重挂；重挂失败 → `MK_DM_FAIL_RX_LOST`：同上 |
| 发送时通道不可用 | 业务包无路可走 | `MK_DM_FAIL_TX`：回收本批 NBL（`EthServer_ReclaimBatch`）→ 置失败标志 + 拆通道，绝不退化成标准发送 |
| R3 未及时 DeleteService | 设备对象在，通道已拆，无隐身数据面 | 设备仍可查询失败原因；`fChannelFatal` 每轮都可读，loader `--watch` 会持续重试删服务 |
| 网卡解绑/重挂 | MiniportBlock 释放后槽位仍是我们的函数 → 野指针 | unbind 前 `MkDm_DetachBinding` 先 CAS 回滚 + 排空在途计数 |
| 多网卡同时绑定 | 单目标设计只接管第一张 | 非 802.3 介质在 `BindAdapterEx` 入口即跳过；第二张及以后不接管但正常绑定 |
| 卸载竞态 | 节流器仍在执行时释放模块 | `fArmed=FALSE` → CAS 回滚 → `InFlight` 排空（500ms 上限）→ 再释放 |

## 9. 验证与回滚

1. `Driver Verifier`（除 NDIS verifier）+ 快照，加载驱动，`EthServer_Init` 后看 DBG：
   `DirectMiniport: mp=… send=+0x… filters=N` —— `filters` 应等于该网卡上 LWF 数量（Npcap 在位时可作可见性证据）。
2. Npcap 抓包：本通道 0x8844 帧应完全消失，同时 `ping`/业务流量正常。
3. `MkDm_SetRxMode(MK_DM_RX_BLACKOUT)` 后，该网卡所有上行帧在 Npcap 中消失，Tcpip 仍正常。
4. 回滚：`EthServer_Stop` 或 `MkDm_Shutdown` 完成 CAS 回滚；异常场景直接卸载驱动即可，槽位已还原。
5. **失败注入验证（无兜底 + R3 处置路径）**：人为破坏一处（把 `MK_NDIS_LAYOUT_19041` 的 `Mp_ChainNode` 改成错误偏移、
   或在 attach 后手工把槽位写回 NDIS 原值），预期观察：
   - 内核日志出现 `[-] DirectMiniport: ...` 与 `[x] EthServer: DirectMiniport channel FAILED (reason=N, status=...)`；
   - `ExceptionReporter` 收到一条 `EthServer::DirectMiniportFatal` 上报；
   - **设备对象仍在**（`\Device\...` 可打开），`IOCTL_MK_GET_STATUS` 返回 `fChannelFatal=1` + 失败原因/状态码；
   - loader 侧 `HandleChannelFailureIfAny()` 打印 `DirectMiniport channel FATAL: reason=...` 后
     `StopAndRemoveService('i225v')` 成功，服务与设备在数秒内消失；
   - **全程不出现任何走标准路径的 0x8844 出站帧**（判定"确实没有兜底"的关键证据）。

## 11. 失败上报 ABI（MK_SERVER_STATUS v2）

`IOCTL_MK_GET_STATUS`(0x902) 返回的 `MK_SERVER_STATUS` 在尾部追加（前缀保持兼容）：

| 字段 | 含义 |
|---|---|
| `fChannelReady` / `fChannelArmed` | 结构解析完成 / 指示槽位已接管 |
| `fChannelFatal` | 通道已判死：R3 读到后应 `DeleteService` |
| `ChannelFailReason` | `MK_DM_FAIL_INIT/RESOLVE/ARM/RX_LOST/TX` |
| `ChannelFailStatus` | 失败时 NTSTATUS |
| `ChannelFilterCount` / `ChannelIfIndex` | 目标网卡过滤器数量（Npcap 在位证据）/ IfIndex |
| `ChannelTxDirect` / `ChannelTxFailed` / `ChannelRxStolen` | 直连发送数 / 失败数 / 截留帧数 |

loader 侧镜像结构为 `MK_SERVER_STATUS_R3`（`loader/scm_loader.h`），通过
`QueryChannelStatus()` 读取、`HandleChannelFailureIfAny()` 处置；`--watch` 开启 1s 轮询守护。

## 10. 后续

- 对 22000 / 22621 / 26100 各采样一次 `ndis.pdb`，用 `offsets_dump.exe` 重生成 `MK_NDIS_LAYOUT_*`；
  未采样档位沿用 19041 布局，靠 §8 的运行时校验兜底。
- 若后续需要 EVP/加固版（`HVCI + Kernel DMA Protection`）平台，可把槽位改写升级为
  `VtEngine` EPT 写保护影子页方案，避免与 NDIS 自身的热路径写冲突。
