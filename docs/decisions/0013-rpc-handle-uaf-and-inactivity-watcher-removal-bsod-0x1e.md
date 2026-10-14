# ADR-0013: 废除 RPC 后台超时看门狗线程、句柄槽位双向强校验与彻底根除 BugCheck 0x1E (Use-After-Free)

- **状态**: 已采纳
- **日期**: 2026-10-14
- **核心领域**: 跨环网络通信 / 生命周期管理 / 系统崩溃根治

---

## 一、 上下文与崩溃现场剖析 (Context & BugCheck Forensics)

### 1. 故障现场与转储数据
在客户端连接并持续进行高频内存读取约 **30 秒** 后，内核触发蓝屏崩溃 `BugCheck 0x1E: KMODE_EXCEPTION_NOT_HANDLED`（转储文件 `k-192_168_4_44-134363954023190412.dmp`）：
```text
BugCheck 0x1E, {ffffffffc0000005, fffff804cbbcf77e, 0000000000000000, ffffffffffffffff}
Arg1: ffffffffc0000005 (STATUS_ACCESS_VIOLATION / General Protection Fault #GP)
Arg2: fffff804cbbcf77e (崩溃指令地址: nvlddmkm+0x734f77e -> drv_wsk!LcReadScatter+0x1e, RVA 0x777E)
Arg3: 0000000000000000
Arg4: ffffffffffffffff (x64 下跳转/解引用非规范地址 Non-Canonical Address 的硬件 #GP 特征)
```

完整调用栈如下：
```text
#00 nt!KeBugCheckEx
#01 nt!KiDispatchException+0x1c5a6b
#02 nt!KiExceptionDispatch+0x12c
#03 nt!KiGeneralProtectionFault+0x31a               (TrapFrame @ ffffa500`91c4ed30)
#04 drv_wsk!LcReadScatter+0x1e                      (nvlddmkm+0x734f77e, RVA 0x777E)
#05 drv_wsk!MkRpc_HandleReadScatter+0x3a0           (nvlddmkm+0x734d710, RVA 0x5710)
#06 drv_wsk!MkRpc_DispatchCommandEx+0x4d0           (nvlddmkm+0x734cde4, RVA 0x4DE4)
#07 drv_wsk!WskProcessClientSession+0x6a4           (nvlddmkm+0x734a550, RVA 0x2550)
#08 drv_wsk!WskServerThread+0x124                   (nvlddmkm+0x734b1ec, RVA 0x31EC)
#09 nt!PspSystemThreadStartup
#10 nt!KiStartSystemThread+0x28
```

### 2. 内存取证与致命根因追踪 (The Smoking Gun)
1. **指令与寄存器锚定**：
   崩溃发生在 `drv_wsk!LcReadScatter+0x1e`：
   ```asm
   mov  rax, qword ptr [rcx+398h]  ; rcx = hLC (0xffffde074dad3000), 读取 ctxLC->pfnReadScatter
   test rax, rax
   je   +0x02
   call rax                        ; rax = 0x402024548d48284f (非规范地址，触发 #GP)
   ```
2. **被释放重用的 `LC_CONTEXT` (Use-After-Free)**：
   检视 `rcx` (`0xffffde074dad3000`) 内存发现：
   - 偏移 `+0x08` 处仍残留 `0xc0e10004` (`LC_CONTEXT_VERSION`)；
   - 偏移 `+0x00` 已被内核覆写为新的池头 `POOL_HEADER`（Tag `jayc`），偏移 `+0x10` 起已被其它内核模块代码/池数据覆写，导致 `+0x398` (`pfnReadScatter`) 变成机器码字节 `0x402024548d48284f`。
3. **30 秒必现 UAF 触发机理**：
   - 在 `MkRpc_DispatchCommandEx` 中，为消除互斥锁争用引入了传输层直通缓存：`if (pTransCtx && pTransCtx->Cached_dwRpcClientID == pHdr->dwRpcClientID && pTransCtx->Cached_hLC)`。
   - 客户端完成 `OPEN_REQ` 后，后续所有请求（包括 `READSCATTER_REQ` 与 `KEEPALIVE_REQ`）100% 命中该直通快路径，**完全绕过了 `LeechRPC_LcHandle_Lookup`**，导致 `ctxLeechRpc.ClientList[i].qwLastTickCount64` 永远停留在 `OPEN_REQ` 时的初始时间戳。
   - 会话持续满 **30 秒**（`LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS = 30000`）时，后台线程 `LeechRPC_LcHandle_InactivityWatcherThread` 误判客户端超时，调用 `LeechRPC_LcHandle_Close` $\rightarrow$ `LcClose(hLC)` 将 `ctxLC` 释放回非分页池，但 **`pTransCtx->Cached_hLC` 未被清空，沦为悬垂指针（Dangling Pointer）**。
   - 释放后单页请求（`cMEMs == 1`）因走 `LcPte_ReadPhysicalContiguous` 快路径未解引用 `hLC` 而暂时幸存；一旦收到多页散列读请求（如本次 `cMEMs = 11`），进入 `LcReadScatter(hLC, 11, ppMEMs)` 解引用已释放重用的 `[rcx+0x398]`，立即触发 `#GP` 导致 `BugCheck 0x1E`。

---

## 二、 技术决策与加固规范 (Technical Decisions)

### 1. 彻底废除后台 `LeechRPC_LcHandle_InactivityWatcherThread` 线程
- 移除 `MkRpc_Init` 中的 `PsCreateSystemThread(..., LeechRPC_LcHandle_InactivityWatcherThread, ...)`：
  1. **根除异步抢占释放竞态**：杜绝后台线程在传输工作线程不知情的情况下跨核异步调用 `ExFreePoolWithTag(ctxLC)`；
  2. **收敛反作弊线程暴露面**：减少 1 个内核系统线程，严格契合 ADR-0009 / ADR-0011 零冗余系统线程原则。
- 句柄回收改为 **100% 确定性同步生命周期管理**：
  - TCP 会话断开时（`WskProcessClientSession` `Cleanup:`）由常驻通信线程同步调用 `LeechRPC_LcHandle_Close`；
  - 同一传输通道收到新 `OPEN_REQ` 且存在旧 `Cached_dwRpcClientID` 时，先同步关闭旧句柄再创建新句柄；
  - `LeechRPC_LcHandle_New` 在 16 槽位全满时，按 `qwLastTickCount64` 自动执行 LRU 淘汰。

### 2. 传输层直通缓存槽位绑定与无锁时间戳刷新
- `MK_TRANSPORT_CONTEXT` 增设 `ULONG Cached_SlotIndex`（利用 x64 结构体尾部 4 字节对齐空隙，结构体总大小仍为 16 字节）。
- 快路径不仅比对 `Cached_dwRpcClientID` 与 `Cached_hLC`，还强制无锁核验：
  1. `ctxLeechRpc.ClientList[SlotIndex].dwRpcClientID == pHdr->dwRpcClientID` 且 `ClientList[SlotIndex].hLC == pTransCtx->Cached_hLC`；
  2. `((PLC_CONTEXT)Cached_hLC)->version == LC_CONTEXT_VERSION`（`0xc0e10004`）；
  3. 核验通过后，通过 `(SharedUserData->TickCountQuad * SharedUserData->TickCountMultiplier) >> 24` 零调用开销无锁刷新 `qwLastTickCount64`。

### 3. `LC_CONTEXT` 销毁前抹除签名与函数指针规范性校验
- `LcClose` 在释放内存前，立即将 `ctxLC->version = 0`、所有 `pfn*` 置 `NULL`，并执行 `RtlZeroMemory(ctxLC, sizeof(LC_CONTEXT))`；
- `LcReadScatter`、`LcWriteScatter`、`LcCommand`、`LcGetOption`、`LcSetOption` 调用前强制校验 `(ULONG_PTR)ctxLC >= 0xFFFF800000000000ULL`、`ctxLC->version == LC_CONTEXT_VERSION` 以及目标函数指针 `>= 0xFFFF800000000000ULL`。

---

## 三、 已知约束与避坑铁律 (Negative Knowledge & Hard Rules)

1. **严禁引入绕过保活计时的旁路缓存而不刷新状态**：
   - 任何带超时淘汰或 LRU 机制的资源表，在引入 Fast-Path 缓存时，必须在快路径中同步无锁刷新活跃时间戳，并双向校验全局表槽位有效性。
2. **严禁后台看门狗线程无同步释放正被传输层缓存的上下文指针**：
   - 跨线程异步 `ExFreePoolWithTag` 极易制造悬垂指针（UAF），引发延迟数秒至数十秒后在随机多页请求处爆雷的 `BugCheck 0x1E` (`0xC0000005` #GP)。
