# ADR-0023: UDP 传输层协议断层修复、零拷贝分片重组器与防串包闭环

- **状态**: 已采纳
- **日期**: 2026-10-15
- **关联文件**:
  * 驱动端: `CheatDrv/udp_server.c`, `CheatDrv/udp_server.h`, `CheatDrv/udp_discovery.c`
  * 客户端: `leechcore/leechudp_client.c`, `leechcore/leechrpcclient.c`

---

## 一、 背景与系统痛点 (Context & Problem Statement)

在跨机/跨环 UDP 传输层深度审计中，发现了 4 个严重阻断大包通信与威胁系统稳定性的重大问题：
1. **严重协议断层 Bug (大包 100% 失败)**：驱动端在响应包 $> 1400\text{ 字节}$（安全 MTU）时，会自动启用带有 `MK_UDP_SLICE_HDR`（魔数 `'UDPS' = 0x55445053`）的切片协议拆包分发。然而客户端 `leechudp_client.c` 却完全没有实现分片重组逻辑，直接把首个 1400B 分片当成常规包，将分片头部字段误判为净荷长度，导致大包（包括单页 4KB 读取）通信 100% 校验失败并不停重传；
2. **ABA 串包错位 Bug**：驱动端在生成响应报文时写了随机 Nonce `__rdtsc()`，而非严格回填请求 Nonce `qwReqNonce`；客户端未校验响应 Nonce，一旦发生网络抖动或超时重传，上一次迟到的旧响应包会被误认作当前请求的响应，导致返回错误的内存数据；
3. **内核栈下溢蓝屏隐患 (违背 ADR-0012)**：`udp_discovery.c:39` 中调用了 `IoAllocateIrp(1, FALSE)` 分配仅有 1 层栈的 IRP，在系统存在 TDI/NDIS/WFP 多层网络过滤驱动时极易引发 `0x35` 或 `0xA` 蓝屏；
4. **客户端栈探测开销与窄栈溢出风险**：客户端 `LeechRPC_UdpSubmitCommand` 每次调用都在局部栈上分配 `2 × 64KB = 128KB` 的数组，触发编译器逐页触摸 32 个页面（`__chkstk`），开销巨大且在窄栈线程下存在栈溢出风险。

---

## 二、 架构决策与技术规约 (Decision & Architecture)

### 1. 客户端 `MK_UDP_SLICE_HDR` 零拷贝分片重组器
- **协议结构体与常量对齐**：
  ```c
  #pragma pack(push, 1)
  typedef struct _MK_UDP_SLICE_HDR
  {
      ULONG dwMagic;          // 'UDPS' (0x55445053)
      ULONG dwSequence;       // 序列号: (ULONG)(qwReqNonce ^ (qwReqNonce >> 32))
      USHORT SliceIndex;      // 分片索引 (0-based)
      USHORT TotalSlices;     // 总分片数
      ULONG cbOriginalTotal;  // 原始总长度
      ULONG cbSliceData;      // 当前分片字节数
  } MK_UDP_SLICE_HDR, *PMK_UDP_SLICE_HDR;
  #pragma pack(pop)
  ```
- **原位拼装与序列号校验**：
  * 客户端以当前请求 Nonce 衍生的 `dwExpectedSeq` 作为分片匹配标识，自动丢弃旧序列号的迟到分片；
  * 首次收到切片时按 `cbOriginalTotal` 一次性分配重组缓冲，按 `SliceIndex * 1384` 偏移原位写入切片净荷（Zero-Copy Assembly）；
  * 收齐所有分片后，执行校验、`NngFastCrypt` 解密并交付上层，完美支持最大 16MB 响应，使散列读单次容量由 12 页（48KB）提升至 128 页（512KB）。

### 2. 响应 Nonce 严格回传与 ABA 串包免疫
- 驱动端在 `udp_server.c` 中强制将响应头中的 `qwRspNonce` 赋值为 `qwReqNonce`；
- 客户端在接收单包及切片重组包时，强制断言 `qwRspNonce == qwNonce`，彻底解决超时重传下的串包错位问题。

### 3. 内核 IRP 栈空间升级 (StackSize = 4)
- 将 `udp_discovery.c:39` 中的 `IoAllocateIrp(1, FALSE)` 修改为 `IoAllocateIrp(4, FALSE)`，与全驱动保持完全一致，严格遵守 ADR-0012 的 4 栈空间规约。

### 4. 消除栈上 128KB 数组开销
- 鉴于客户端 UDP 收发全过程均处于 `ctx->udp.Lock` 临界区保护之下，将原局部栈数组移至静态预分配持久化缓冲 `g_udp_buffers`，彻底消除 128KB 栈分配与 `__chkstk` 触摸。

### 5. 开启 UDP 硬件线速压缩 (XPRESS)
- 客户端在 `leechrpcclient.c` 中将 `ctxLC->Rpc.fCompress` 解除硬编码 `FALSE`，配置为 `!ctxLC->Config.fRemoteDisableCompress`，大跨页读取数据在内核态压缩后传输，分片包数锐减 60%~80%。

---

## 三、 负向知识总结

14. **无连接协议 (UDP) 切片传输中客户端严禁缺失重组协议**：驱动端一旦使能基于 MTU 的应用层切片，客户端必须严格按照序列号与分片索引实现对等重组器，否则切片包会被误读为净荷长度引发全量通信瘫痪。
15. **UDP RPC 传输严禁使用随机 Nonce 回包**：无连接通道缺乏 TCP 序号确认，必须回传请求原 Nonce；客户端必须严格过滤非本轮 Nonce 的响应，否则网络抖动重传时必发 ABA 串包导致读写错位。
