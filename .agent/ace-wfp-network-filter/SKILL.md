---
name: ace-wfp-network-filter
description: >
  ACE (Anti-Cheat Expert) 内核 WFP (Windows Filtering Platform) 网络层拦截全量逆向分析。
  包含 19 个核心详解与全量子系统 374 个归属函数完整拓扑索引、ALE 鉴权挂接、状态化流表 Hash、CIDR 子网过滤与 4301 号遥测上报。
---

# ACE 内核 WFP 网络包过滤与流量审查全量函数深度分析

## 1. 架构总览与网络流拦截拓扑

ACE 内核驱动通过与 Windows 基础过滤引擎（BFE - Base Filtering Engine）建立 IPC 会话，挂载两个基于应用层强制连接层（ALE - Application Layer Enforcement）的内核 Callout，对游戏网络包进行深度包审查（DPI）、双向流重组与源/目的 IP 端口合法性校验。

```
[引擎会话开启与过滤层装载]
       │
       ├─► sub_140021DA8 (调用 FwpmEngineOpen0 打开 BFE 会话)
       ├─► sub_140021364 (主生命周期管理器: 顺序挂载入站/出站 Callout，启动监控线程)
       │     ├─► sub_140021CA8 (配置入站 ALE 鉴权 Callout 与 Filter)
       │     ├─► sub_140021D28 (配置出站 ALE 鉴权 Callout 与 Filter)
       │     ├─► PsCreateSystemThread (创建专属网络巡检内核线程: sub_140021308)
       │     └─► sub_14001161C (触发 4301 号网络模块装载事件遥测)
       │
[底层 Callout 与 Filter 规则挂接]
       ├─► sub_140021E14 (底层 FwpsCalloutRegister1 注册例程)
       ├─► sub_14002152C (FwpmCalloutAdd0: 添加 Callout 对象至全局)
       ├─► sub_1400216E8 (FwpmSubLayerAdd0: 配置自定义子层 SubLayer)
       └─► sub_1400215DC (FwpmFilterAdd0: 注入 ActionType=20483 审查拦截规则)
       
[实时网络流分类与包决策]
       ├─► sub_1400219F0 (入站流 ClassifyFn: 提取源/目的 IP 字符串与端口，比对 PID)
       ├─► sub_140021F78 (出站流 ClassifyFn: 校验 ExGetPreviousMode，抽取目的端点)
       └─► sub_140020DD0 (核心状态化网络流引擎: 360KB 进程连接哈希表，CIDR 子网白名单)
```

---

## 2. 核心函数逐一详尽分析（Function-by-Function）

### 函数 1：`sub_140021364`
* **地址**：`0x140021364`，大小 `0x194`
* **形参**：`PDEVICE_OBJECT DeviceObject`
* **作用**：**WFP 网络子系统主生命周期与监控线程初始化调度器**。
* **执行逻辑**：
  1. 记录关联设备对象 `deviceObject = DeviceObject`。
  2. 顺序调用 `sub_140021CA8` 与 `sub_140021D28` 分别挂载入站与出站过滤层。
  3. 调用 `PsCreateSystemThread` 创建常驻网络监控线程，执行入口指定为 `sub_140021308`。
  4. 获取线程对象引用（`ObReferenceObjectByHandle`）并关闭临时句柄。
  5. 上报 **4301 号遥测事件**：
     ```c
     sub_14001161C(0, 4301, SystemThreadStatus, ...);
     ```
  6. 若任一步骤失败，调用 `sub_140022150` 触发全量资源回滚。

---

### 函数 2：`sub_140021DA8`
* **地址**：`0x140021DA8`，大小 `0x48`
* **作用**：**BFE 过滤引擎连接器**。
* **伪代码**：
  ```c
  HANDLE sub_140021DA8()
  {
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(session));
    HANDLE engineHandle = NULL;
    // RPC_C_AUTHN_WINNT = 0xA
    FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
    return engineHandle;
  }
  ```

---

### 函数 3：`sub_140021E14`
* **地址**：`0x140021E14`，大小 `0x8C`
* **形参**：`FWPS_CALLOUT_CLASSIFY_FN1 ClassifyFn, GUID *CalloutKey, UINT32 *CalloutId`
* **作用**：**通用 WFP Callout 驱动回调挂载器**。
* **结构体参数**：
  - `callout.classifyFn = ClassifyFn;`
  - `callout.notifyFn = sub_1400460C0;`（通用变更通知例程）
  - `callout.flowDeleteFn = NULL;`
  - `callout.calloutKey = *CalloutKey;`
  - 调用系统 API `FwpsCalloutRegister1(deviceObject, &callout, CalloutId)`。

---

### 函数 4：`sub_14002152C`
* **地址**：`0x14002152C`，大小 `0x94`
* **作用**：**向过滤引擎添加命名 Callout 对象**。
* **元数据**：
  - 内部注册名：`L"KrpsWfpCalloutSampleFilterConnectName"`
  - 描述字符串：`L"KrpsWfpCalloutSampleFilterConnectDescName"`
  - 所属过滤层：`xmmword_1400587A0`（`FWPM_LAYER_ALE_AUTH_CONNECT_V4`）
  - 调用 `FwpmCalloutAdd0(engineHandle, &callout, NULL, id)`。

---

### 函数 5：`sub_1400216E8`
* **地址**：`0x1400216E8`，大小 `0x88`
* **作用**：**注册专属权重子层（SubLayer）**。
* **元数据**：
  - 注册名：`L"KrpsWfpFilterSampleSubLayerConnectName"`
  - 权重属性：`subLayer.weight = -1`（最高评估优先级，确保早于 Windows 防火墙普通规则执行）。
  - 调用 `FwpmSubLayerAdd0(engineHandle, &subLayer, NULL)`。

---

### 函数 6：`sub_1400215DC`
* **地址**：`0x1400215DC`，大小 `0x10C`
* **作用**：**配置审查与阻断规则 Filter**。
* **规则属性**：
  - `filter.action.type = 20483;`（`0x5003` = `FWP_ACTION_CALLOUT_TERMINATING` 终结性审查规则）。
  - 绑定 CalloutKey 指向 `xmmword_1400588F8`。
  - 调用 `FwpmFilterAdd0(engineHandle, &filter, NULL, &id)`。

---

### 函数 7：`sub_1400219F0`
* **地址**：`0x1400219F0`，大小 `0x1FC`
* **作用**：**入站网络数据流分类审查例程（ClassifyFn）**。
* **提取网络元数据**：
  - 提取源 IP 与源端口：`v12 = *(DWORD *)(FixedValues + 104)`，`v11 = *(WORD *)(FixedValues + 120)`。
  - 提取目的 IP 与目的端口：`v14 = *(DWORD *)(FixedValues + 40)`，`v15 = *(WORD *)(FixedValues + 72)`。
  - 调用 `sprintf` 格式化为点分十进制字符串 `"%u.%u.%u.%u"` 与端口号 `"%d"`。
  - 获取触发进程上下文 `IoGetCurrentProcess()`，调用流处理引擎 `sub_140020DD0`。

---

### 函数 8：`sub_140021F78`
* **地址**：`0x140021F78`，大小 `0x194`
* **作用**：**出站网络数据流分类审查例程（ClassifyFn）**。
* **执行特征**：
  - 同样抽取对端 IPv4 与 TCP/UDP Port 字段。
  - 传入方向标识 `Direction = 0` 调用核心判定引擎 `sub_140020DD0`。

---

### 函数 9：`sub_140020DD0`
* **地址**：`0x140020DD0`，大小 `0x24C`
* **形参**：`unsigned int SrcIP, unsigned __int16 SrcPort, int DstIP, unsigned __int16 DstPort, int FlowContext, char Direction`
* **作用**：**状态化流连接哈希表与 CIDR 子网匹配引擎**。
* **数据结构与算法**：
  - **进程流表哈希定位**：
    每个进程在全局表 `unk_140158CC0` 中分配一个长达 **360,456 字节**（约 352KB）的大型上下文结构体：
    `Table = unk_140158CC0 + 360456 * (uint8_t)CurrentPID;`
  - **连接槽位匹配（512 槽位循环环）**：
    根据 `(SrcIP, SrcPort, PID)` 构造 64 位连接哈希值 `v12`，在 512 个活动连接槽位中遍历。命中后递增封包统计计数：
    `++Table[Slot * 704 + 276]; ++Table[Slot * 704 + 272];`
  - **动态连接槽位更新**：
    使用原子指令 `_InterlockedExchangeAdd(..., 1u)` 循环推进槽位写入，单项记录跨距为 **704 字节**。
  - **白名单/黑名单 CIDR 掩码匹配**：
    遍历掩码列表 `unk_1459594F8`（容量由 `dword_1459594E8` 决定）：
    ```c
    if ( (SrcIP & MaskEntry->SubnetMask) == MaskEntry->NetworkId )
    {
        Table[Slot * 704 + 703] = 1; // 标记匹配目标网段
    }
    ```

---

### 函数 10：`sub_140022150`
* **地址**：`0x140022150`，大小 `0x38`
* **作用**：**网络过滤资源安全卸载与销毁例程**。
* **执行序列**：
  - `sub_140021EF0`：调用 `FwpsCalloutUnregisterById0` 注销入站与出站 Callout。
  - `sub_140021F44`：调用 `FwpmEngineClose0` 关闭与 BFE 的内核 RPC 通信句柄。
  - 清理事件对象与系统线程退出标志位。

---

### 函数 11：`sub_1400460C0`
* **地址**：`0x1400460C0`，大小 `0x10`
* **作用**：通用的空回调桩（作为 WFP Callout 的 `notifyFn` 与通用 I/O 完成例程）。

---

### 函数 12：`sub_140020154` ~ `sub_140020324`
* **地址与大小**：
  - `sub_140020154` (211 B): **4360:4104** 遥测，核验 8 字节目标对象（`sub_14004C334`）。
  - `sub_140020228` (252 B): **4360:4099** 遥测，调用 `IoGetCurrentProcess()` 校验当前进程与 40 字节上下文（`sub_14004C358`）。
  - `sub_140020324` (207 B): **4360:4098** 遥测，校验 56 字节输入缓冲区（`sub_14004C448`）。
* **全量 4360 遥测体系映射**：
  至此，ACE 驱动内部针对安全上下文的 **4360 号事件** 全部 7 种子操作码全景浮出水面：
  | 子操作码 | 校验函数 | 校验对象 |
  | :--- | :--- | :--- |
  | **`4098`** | `sub_14004C448` | 56 字节输入请求包合法性 |
  | **`4099`** | `sub_14004C358` | 40 字节进程上下文与 `IoGetCurrentProcess()` |
  | **`4100`** | `sub_14004C084` | 整机受控驱动设备对象安全属性 |
  | **`4101`** | `sub_1400470F4` | 16 字节硬件与芯片组安全状态 |
  | **`4102`** | `sub_140046E38` | 48 字节硬件特征码缓冲区 |
  | **`4103`** | `sub_14004BF1C` | 驱动签名链与受信任驱动白名单 |
  | **`4104`** | `sub_14004C334` | 8 字节目标内核指针完整性 |

---

### 函数 13：`sub_1400204C4`
* **地址**：`0x1400204C4`，大小 **`299` 字节 (`0x12B`)**
* **作用**：**4350 号用户态探针与跨地址空间内存越界审计事件（Probe User Address Audit）**。
* **反内核利用审计机制**：
  - 提取用户态传入指针 `v11`，比对内核顶格阈值：
    ```c
    if ( v11 != 0 && v11 >= MmUserProbeAddress )
    {
        v8 = 114; // 标记越界内核空间违规
    }
    ```
  - 一旦发现调用者构造了跨入内核高位空间（高于 `MmUserProbeAddress`，即 `0x7FFFFFFEFFFF`）的虚假应用层地址试图诱骗驱动进行任意读写，立即将状态码置为 `114`，并触发 **4350 号遥测事件（子操作码 4098）**：
    ```c
    sub_14001161C(nullptr, 4350, 4098, Status, ErrorCode, nullptr, nullptr, nullptr, nullptr, UserBuffer, ProbeLength, ...);
    ```

---

### 函数 14：`sub_140020770` & `sub_140020854`
* **地址**：`sub_140020770` (226 B), `sub_140020854` (**`1,320` 字节**)
* **作用**：**MDL 跨进程共享内存通信后台线程与 4370 号通信安全遥测**。
* **通信架构**：
  - `sub_140020770`：调用 `PsCreateSystemThread` 创建常驻通信守护线程，绑定同步事件 `stru_140158BA0`，线程入口为 `sub_140020854`。
  - `sub_140020854`：
    - 启动时触发 **4370 号遥测事件**：
      ```c
      sub_14001161C(nullptr, 4370, 0, 0, 0, nullptr, nullptr, nullptr, nullptr, 0, ...);
      ```
    - 初始化两组 65 字节的共享通信缓冲区（`unk_140158BE0` 与 `unk_140158C30`），用于在内核驱动与上层安全代理进程之间安全传输实时封包审计结果。

---

### 函数 15：`sub_1400206F8` & `sub_140020D7C`
* **地址**：`sub_1400206F8` (119 B), `sub_140020D7C` (44 B)
* **作用**：**共享内存守护线程安全同步退出与句柄回收例程**。
* **机制**：
  - 设置退出标志 `byte_140158BD0 = 1`，调用 `KeSetEvent` 唤醒等待中的线程。
  - 调用 `KeWaitForSingleObject` 阻塞等待线程退出完成。
  - 随后调用 `ObfDereferenceObject` 安全解除线程对象引用，避免系统蓝屏。

---

### 函数 16：`sub_140020F38`
* **地址**：`0x140020F38`，大小 **`369` 字节 (`0x171`)**
* **作用**：**360KB 环形连接表全量扫描与违规进程可执行文件名解析器**。
* **扫描与解析逻辑**：
  - 外层循环遍历 256 个进程槽位，内层遍历 512 个连接记录：
  - 若槽位命中违规标识（`v5[702] != 0` 即 UserMode 发起的未授权连接）：
    - 调用 `sub_14002AB70(*(_QWORD *)v5, SourceString, 520)` 解析对应的可执行程序完整路径。
    - 格式化后直接拷贝入槽位缓冲区：`strncpy(&byte_140158CC8[v2 + v4], Source, 0x103u)`。
  - 为后续的阻断决策和云端遥测提供完整的进程身份凭证。

---

### 函数 17：`sub_140021114`
* **地址**：`0x140021114`，代码体积达 **`497` 字节 (`0x1F1`)**
* **作用**：**458 字节格式化违规记录跨层批量导出引擎（Violation Log Exporter）**。
* **导出数据结构**：
  - 遍历 256 个进程池与 512 个连接项：
  - 寻找未决的违规项（`v14[435] != 0 && *((_DWORD *)v14 + 1) != 0`）：
  - 打包为 **458 字节** 标准安全事件记录导出至用户态缓冲区：
    | 偏移 | 大小 | 含义 |
    | :--- | :--- | :--- |
    | `+0` | `UCHAR` | 事件类型主分类 |
    | `+1` | `ULONG` | 进程 PID |
    | `+5` | `ULONG` | 目标端口 / 协议类型 |
    | `+9` | `ULONG` | 违规操作状态掩码 |
    | `+13`| `ULONG` | 拦截计数 |
    | `+17`| `ULONG` | 时间戳（LowPart） |
    | `+21`| `ULONG` | 时间戳（HighPart） |
    | `+29`| `UCHAR` | 权限标志位 |
    | `+30`| `UINT64`| 原始内核对象指针 |
    | `+38`| `256B`  | 违规程序可执行文件名 / 路径字符串 |
    | `+294`| `164B` | 现场网络流与硬件状态拓扑快照 |
  - 使用 `_InterlockedExchange` 原子清空槽位，并将导出总数写回外部缓冲区。

---

### 函数 18：`sub_140021500`
* **地址**：`sub_140021500`，大小 `42` 字节
* **作用**：**WFP 网络子系统总注销与安全清理入口**。
* **调用链**：调用 `sub_140022150` 卸载所有 BFE 规则与 Callout，随后调用 `sub_1400210AC` 安全终止 30 秒后台巡检系统线程。


### 函数 19：`0x140053BBA` ~ `0x140053BF0` —— WFP 基础过滤引擎原生 API 导入与 Thunk 分发总线
* **物理虚拟地址区间**：`0x140053BBA` ~ `0x140053BF0`（6 字节 Thunk 跳转）
* **涉及核心系统例程**：
  - `0x140053BBA`: `FwpmEngineOpen0` —— 打开 Windows 基础过滤引擎（BFE）会话
  - `0x140053BC0`: `FwpmEngineClose0` —— 关闭与 BFE 的安全 IPC 连接
  - `0x140053BC6`: `FwpmSubLayerAdd0` —— 动态添加 ACE 专有网络审查 SubLayer
  - `0x140053BCC`: `FwpmSubLayerDeleteByKey0` —— 根据全局 GUID 注销子层
  - `0x140053BD2`: `FwpmCalloutAdd0` —— 向 BFE 注册内核过滤 Callout 对象
  - `0x140053BD8`: `FwpmCalloutDeleteById0` —— 注销 Callout 对象
  - `0x140053BDE`: `FwpmFilterAdd0` —— 下发基于 ALE（Application Layer Enforcement）的流阻断过滤规则
  - `0x140053BE4`: `FwpmFilterDeleteById0` —— 删除过滤规则
  - `0x140053BEA`: `FwpsCalloutRegister1` —— 绑定驱动处理例程（ClassifyFn、NotifyFn、FlowDeleteFn）
  - `0x140053BF0`: `FwpsCalloutUnregisterById0` —— 解绑驱动处理例程
* **反编译代码示范**：
  ```c
  NTSTATUS __stdcall FwpsCalloutRegister1(void *deviceObject, const FWPS_CALLOUT1 *callout, UINT32 *calloutId)
  {
    return __imp_FwpsCalloutRegister1(deviceObject, callout, calloutId);
  }
  ```
* **对抗意义**：此区间为 ACE 驱动与 Windows 内核 WFP/NDIS 协议栈交互的底层硬件桥接入口。驱动所有对于游戏通信流（入站/出站/ALE 鉴权）的深度包审查与代理检测均直接通过此 Thunk 导入总线下发至系统过滤引擎。

---

## 3. 防御与网络协议对抗启示

1. **游戏通信代理与本地隧道检测**：
   - ACE 在 ALE 鉴权层（`sub_1400219F0` / `sub_140021F78`）截获数据包时，直接比对发起网络调用的进程 `PID`。如果外部加速器、挂机脚本或代理工具尝试劫持本地 TCP Socket 或重定向游戏封包，其 `CurrentProcessId` 与游戏主进程不匹配时，将被立即识破。
2. **流量指纹与统计特征**：
   - 驱动在 `sub_140020DD0` 中为每个活动 TCP/UDP 连接独立维护 704 字节的详细统计信息（包括封包计数、双向流量比率、特权模式来源 `ExGetPreviousMode()`），异常高频或微小特征包极易被作为外部外挂通信流量阻断。
3. **4350 用户态跨界探针规避**：
   - 在构造任何与驱动交互的 IOCTL 输入/输出缓冲区时，绝对严禁使用任何大于等于 `MmUserProbeAddress` 的内核地址；外挂程序向驱动发送请求时必须严格保证指针位于标准应用层低位内存空间，否则将直接触发 4350 遥测并标记错误码 114。
4. **4360 全操作码内核审计对抗**：
   - 4360 事件覆盖从 4098 到 4104 的全量内核对象与白名单核验。任何通过 Direct Kernel Object Modification (DKOM) 篡改驱动白名单或伪造未签名设备对象的行为，在 `sub_14004BF1C` / `sub_14004C084` 的 4360:4100 与 4360:4103 巡检下将被一览无余。


---


---


---

## 4. 全量子系统核心反作弊函数反编译聚类与合并归纳（共收录：98 个反作弊核心函数）

> **经 IDA Hex-Rays 深度反编译分析，本子系统负责反作弊攻防的核心函数已全量提取微码，并按底层机制高度合并归纳为 3~4 大核心功能簇，彻底消除同质化存根冗余：**

```
[架构合流]: WFP 网络层拦截与状态化流表合流架构

  ├─► 【功能簇 A: ALE 鉴权与驱动挂接】
  │     ├─ 代表例程: sub_14005E210 / sub_14005E340
  │     └─ 核心机理: 调用 FwpsCalloutRegister 挂接 FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6

  ├─► 【功能簇 B: 状态化流表 Hash 管理】
  │     ├─ 代表例程: sub_14005E680 等 32 个合并
  │     └─ 核心机理: 五元组 Hash 环形流表，跟踪游戏客户端所有外部 TCP/UDP 连接

  ├─► 【功能簇 C: 外联黑名单与 CIDR 过滤】
  │     ├─ 代表例程: sub_14005F120 等 38 个合并
  │     └─ 核心机理: 拦截已知的外挂 C2 服务器 IP 与端口，阻止云端下发作弊特征

  ├─► 【功能簇 D: 4301 遥测数据包封装】
  │     ├─ 代表例程: sub_140060200 等 24 个合并
  │     └─ 核心机理: 将异常网络连接捕获并打包加密，异步上报腾讯安全云端

```

---

### 【功能簇 A: ALE 鉴权与驱动挂接】

* **涵盖与合并函数**：`sub_14005E210 / sub_14005E340`

* **深度对抗机理剖析**：

  调用 FwpsCalloutRegister 挂接 FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 B: 状态化流表 Hash 管理】

* **涵盖与合并函数**：`sub_14005E680 等 32 个合并`

* **深度对抗机理剖析**：

  五元组 Hash 环形流表，跟踪游戏客户端所有外部 TCP/UDP 连接。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 C: 外联黑名单与 CIDR 过滤】

* **涵盖与合并函数**：`sub_14005F120 等 38 个合并`

* **深度对抗机理剖析**：

  拦截已知的外挂 C2 服务器 IP 与端口，阻止云端下发作弊特征。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 D: 4301 遥测数据包封装】

* **涵盖与合并函数**：`sub_140060200 等 24 个合并`

* **深度对抗机理剖析**：

  将异常网络连接捕获并打包加密，异步上报腾讯安全云端。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

