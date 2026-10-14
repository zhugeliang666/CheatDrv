# ADR-0021: TCP 传输层槽位扩容、消灭 1MB 溢槽雪崩与散列读请求零分配加速

- **状态**: 已采纳
- **日期**: 2026-10-15
- **上下文与痛点**:
  1. **读取满 1MB（256 页）内存时的 10KB 溢槽雪崩**:
     - 上层组件（如 VMMDLL / 大型内存分析框架）极度偏好以 256 页（整 1MB 数据）为单位发起散列读取；
     - 256 页的完整 RPC 响应包体积为：`20B (NNG) + 48B (BIN) + 256 * 40B (MEM_SCATTER) + 1,048,576B (数据) = 1,058,884 字节`；
     - 原驱动端单发送槽位 `MK_WSK_SEND_SLOT_SIZE` 与压缩缓冲 `pbCompBuffer` 被硬编码定死在精确的 `1024 * 1024 (1,048,576)` 字节；
     - 仅仅多出的 10.3KB 描述符头，导致 `DirectOut` 判定失败（`cbMaxRspTotal > cbDirectOutMax`），在内核态连续触发两次 1.05MB `ExAllocatePoolWithTag(NonPagedPoolNx)` 大池自旋锁争用，XPRESS 压缩被跳过，全双工环形流水线彻底退化为 `WskSyncSendAll` 同步阻塞，吞吐量断崖式暴跌；
  2. **cMEMs >= 103 页请求头压缩导致驱动端高频动态池分配**:
     - 客户端对 `READSCATTER_REQ` 请求在尺寸 $\ge 4096$ 字节时调用了 `LeechRPC_Compress`；
     - 但请求体仅为定长地址描述符，压缩率极低，更严重的是驱动端每次收到读取 $\ge 103$ 页的请求，都被迫在 `MkRpc_DispatchCommandEx` 中调用 `LeechRPC_DecompressMsg` 动态分配非分页池并解压，破坏了请求分发路径的原位零分配契约；
  3. **热路径残留高频 DBG 打印引发 DbgPrintEx 全局自旋锁风暴**:
     - `LcPte_ReadPhysicalContiguous` 在物理页读取失败（如 MMIO 空洞或无效物理地址）时连续输出 2 条 `DBG()`，触发内核全局调试打印自旋锁风暴；
     - `DeviceKernel_ReadScatter` 对失败页执行冗余 4KB `RtlZeroMemory`，而上层紧凑打包根本不回传失败页。

---

- **技术决策与规范**:
  1. **驱动端发送槽位与压缩缓冲扩容至 0x110000 (1MB + 64KB)**:
     - 在 [wsk_server.h](file:///e:/Project/Drv/CheatDrv/wsk_server.h) 中将 `MK_WSK_SEND_SLOT_SIZE` 扩容至 `0x110000`（1,114,112 字节）；
     - 在 [rpc_dispatch.c](file:///e:/Project/Drv/CheatDrv/rpc_dispatch.c) 中将 `LeechRPC_CompressInit` 的 `pbCompBuffer` 分配大小与 `LeechRPC_CompressMsg` 的单帧保护上限同步提升至 `0x110000`；
     - 256 页读取响应（1.058MB）**100% 命中 DirectOut 原位直写与 4 槽位全双工异步发送**，彻底杜绝大池分配与同步阻塞。
  2. **客户端 READSCATTER_REQ 彻底剥离无谓压缩**:
     - 在 [leechrpcclient.c](file:///E:/Project/Machenike/leech_vmm/leechCore/leechcore/leechrpcclient.c) 的 `LeechRPC_SubmitCommand` 中，将 `READSCATTER_REQ` 独立分支，仅设置长度，严禁调用 `LeechRPC_Compress`；
     - 驱动端收到读散列请求实现 **100% 原位零分配分发**。
  3. **物理读热路径净化与冗余清零移除**:
     - 移除 `LcPte_ReadPhysicalContiguous` 失败路径的 2 处高频 `DBG()`；
     - 移除 `DeviceKernel_ReadScatter` 失败页的 4KB `RtlZeroMemory`。

---

- **已知约束与避坑**:
  - **DirectOut 槽位边界对齐**: 任何跨机通信单帧最大有效载荷计算时，必须计入传输层协议头（如 NNG 20B、BIN 48B）以及散列描述符元数据（`cMEMs * sizeof(MEM_SCATTER)`），严禁将槽位尺寸等同于纯数据有效尺寸。
