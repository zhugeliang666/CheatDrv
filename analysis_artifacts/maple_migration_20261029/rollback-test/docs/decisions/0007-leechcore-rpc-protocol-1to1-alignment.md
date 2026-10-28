# ADR-0007: LeechCore RPC 服务端协议一比一对齐与防错位规范

- **状态**: 已采纳
- **日期**: 2026-10-12
- **上下文与痛点**:
  - 驱动端实现的 LeechRPC 服务端（`rpc_dispatch.c`）在处理分散读写（Scatter R/W）时，存在两处与 LeechCore 客户端（`leechrpcclient.c`）原版二进制协议契约严重冲突的致命缺陷：
    1. **`WriteScatter` 响应类型严重错位**：驱动原先在响应体中拷贝了 `cMEMs * sizeof(MEM_SCATTER)` 全量结构体，而客户端期望的数据结构是 `cMEMs * sizeof(BOOL)`。客户端遍历时将结构体成员偏移（如 `qwA` 的低 32 位）误判为写入布尔值，导致写操作被频繁误判为失败。
    2. **`ReadScatter` 数据偏移错位（Offset Shift）**：驱动原先将所有页（包括读取失败的页）的数据区全额打包。但客户端解包原语仅在 `pMEM->f == TRUE` 时才累加 `cbOffset`，导致一旦某个物理页读取失败，后续所有原本读取成功的页面数据在客户端解包时全部发生偏移错位，解析为全量乱码。
    3. **服务端压缩功能未接入**：原版 LeechCore 服务端对上行请求支持自动解包（`cbDecompress > 0`），对大于等于 4KB 的分散读写及命令应答具备 XPRESS 自适应压缩能力。驱动服务端若未开启压缩管道，会导致网络传输吞吐量受限，且在客户端协商开启压缩时通信受阻。

- **技术决策与规范**:
  1. **`WriteScatter` 响应协议 1:1 对齐**：
     - 响应体大小计算：`cbRspPayload = cMEMs * sizeof(BOOL)`，`cbRspTotal = sizeof(LEECHRPC_MSG_BIN) + cbRspPayload`；
     - 负载区域 `pRspBin->pb` 格式化为 `BOOL` 数组，循环写入各页执行结果：`pfRsp[i] = ppMEMs[i]->f ? TRUE : FALSE;`；
     - 入参严格校验每个项 `pMEM->cb <= 0x1000`，杜绝单项越界。
  2. **`ReadScatter` 两阶段紧密打包协议 1:1 对齐**：
     - 调用底层读取后，先遍历统计成功页总长度：`if (ppMEMs[i]->f) cbReadTotal += ppMEMs[i]->cb;`；
     - 响应包大小：`sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_SCATTER) + cbReadTotal`；
     - 描述符区域拷贝更新后的 `cMEMs * sizeof(MEM_SCATTER)`（包含各页最新的 `f` 标志）；
     - 数据区域仅紧密追加 `f == TRUE` 的有效数据：
       ```c
       PUCHAR pbDataDst = pRspBin->pb + cMEMs * sizeof(MEM_SCATTER);
       for (ULONG i = 0; i < cMEMs; i++) {
           if (pMEM_Dst[i].f) {
               RtlCopyMemory(pbDataDst, ppMEMs[i]->pb, pMEM_Dst[i].cb);
               pbDataDst += pMEM_Dst[i].cb;
           }
       }
       ```
  3. **底层读写原语继承与不动产**：
     - 严格继承 ADR-0004 规范，底层的物理内存读写继续完全采用 64 槽 Direct-Mapped System PTE 驻留窗口（`LcPte_ReadPhysicalContiguous` / `LcPte_WritePhysicalContiguous`），绝不改动 System PTE 机制。
  4. **XPRESS 压缩引擎管道对齐与下行直通策略**:
     - **动态符号解析**：通过模块导出表 Hash 算法动态定位 `ntoskrnl.exe` 的 `RtlGetCompressionWorkSpaceSize`、`RtlCompressBuffer`、`RtlDecompressBuffer`，彻底规避静态 IAT 导入；
     - **并发工作区资源池**：初始化时调用 `RtlGetCompressionWorkSpaceSize` 动态查询工作区尺寸（约 32KB），预分配 4 槽细粒度互斥锁工作区（`Slots[4]`，总内存约 128KB），严禁分配大池内存；
     - **自动解包上行流**：在 `MkRpc_DispatchCommandEx` 头部检测 `cbDecompress > 0`，调用 `LeechRPC_DecompressMsg` 还原请求后分发，执行完毕后严格释放临时缓冲区；
     - **下行流纯净直通（严禁下行强制压缩）**：在 `MkRpc_HandleOpen` 中显式协商 `fRemoteDisableCompress = TRUE`，回包响应中显式置位 `pRspBin->flags = LEECHRPC_FLAG_NOCOMPRESS;`，杜绝因客户端未初始化解压（如 UDP 客户端）导致的解包硬性失败与数据漂移。

- **已知约束与避坑**:
  - **严禁返回 MEM_SCATTER 数组作为 WriteScatter 响应**：必须严格保证为 `sizeof(BOOL)` 数组；
  - **严禁包含失败页面的数据空洞**：ReadScatter 响应中只允许存在成功页面的紧凑数据流，彻底根除客户端由于未增加 `cbOffset` 引发的数据移位；
  - **严禁对下行响应强制实施 XPRESS 压缩**：UDP 模式客户端（`ctx->Compress.fValid == FALSE`）遇到压缩包会硬性报错丢弃并触发轮询重试风暴，且多页合并压缩流存在 Chunk 偏移风险，下行响应必须采用原生明文流；
  - **UDP 模式下的单包 48KB 限制**：客户端在 UDP 模式下限制单批最大 12 个 4KB 页面（约 48KB），服务端单次处理的 `cbMax` 和 `cMEMs` 必须在此安全上限内；
  - **严禁无界解压缩**：客户端上传的 `cbDecompress` 超过 `0x04000000`（64MB）必须强制拦截，防止恶意溢出；
  - **严禁硬编码工作区体积**：必须基于 `RtlGetCompressionWorkSpaceSize` 动态获取，释放时遍历清理所有 Slot 工作区，杜绝泄漏。
