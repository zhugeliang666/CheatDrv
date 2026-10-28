# ADR-0030: 驱动全模块纯静态类封装与功能子目录架构解耦规范

- **状态**: 已采纳
- **日期**: 2026-10-16
- **核心领域**: 架构重构 / 纯静态类 / 模块化解耦 / 代码整洁

---

## 一、 上下文与痛点

1. **根目录扁平混乱与职责失焦**：
   - 驱动早期源码全量扁平堆叠在根目录中，混合存在大量 `.c`、`.cpp` 与 `.h` 文件；
   - 模块间职责边界不清，入口调度、加解密、异常上报、内存读写引擎与传输协议直接交织，缺乏系统性分层与工程目录规划。
2. **面向对象与虚函数反作弊特征风险**：
   - 传统 C++ 面向对象封装极易引入虚函数（`virtual`），导致编译器在 `.rdata` 节区生成虚函数表（vtable）与 RTTI 结构；
   - 此类特征极易成为反作弊系统与逆向工程的静态交叉引用靶点；同时内核态缺失 CRT 动态初始化机制，全局对象构造/析构链存在隐患。
3. **冗余胶水层与死代码沉积**：
   - 历次迭代中残留了部分单行透传垫片函数与未引用的死代码（如 `KernelReadPhysContiguous`、未引用参数警告），违背 Ponytail 极简契约。

---

## 二、 架构决策与规范

### 1. 六大高内聚功能子目录规划

将扁平驱动工程全面按系统职责划分为 6 大子目录，彻底清晰各层依赖边界：

```text
CheatDrv/
├── Core/              # 核心生命周期与主控调度
│   ├── DriverCore.h / .cpp    # 驱动主控静态类（生命周期、设备派发、初始化）
│   ├── Common.h / Struct.h    # 内核数据结构与基础宏定义
│   └── DynamicXor.h / FrameWork.h / MachenikeString.h
├── Security/          # 安全认证、加解密与底层导出解析
│   ├── DrvSecurity.h / .cpp   # 鉴权防伪、内存锚点直读、加解密纯静态类
│   └── Utils.h / .cpp         # 内核导出表解析、内存比对纯静态工具类
├── Diagnostics/       # 异常捕获与独立网络遥测
│   └── ExceptionReporter.h / .cpp # 纯静态类：独立 WSK + TLS 1.2 异常异步出网
├── Memory/            # 核心物理内存读写与 LeechCore RPC 协议栈
│   ├── LeechCoreEngine.h / .cpp   # 纯静态类：CR3 分级缓存、PTE 映射、物理页读写引擎
│   ├── RpcDispatcher.h / .cpp     # 纯静态类：LeechCore RPC 服务端协议分发与打包
│   └── leechrpc_types.h           # RPC 通信线协议结构体
├── Stealth/           # 反反调试、隐匿性增强与流量旁路
│   ├── StealthReloc.h / .cpp  # 纯静态类：基址重定位、PE 头部擦除与 INIT 节区粉碎
│   ├── WfpBypass.h / .cpp     # 纯静态类：WFP 过滤层旁路与协议栈规则刺穿
│   └── NetMonitor.h / .cpp    # 纯静态类：内核网络监控与异常流量防御
├── Transport/         # 传输层服务治理与跨机通信
│   ├── TransportManager.h / .cpp # 纯静态类：多模传输治理与生命周期纳管
│   ├── wsk_server.h / .c      # TCP (WSK/NNG) 传输栈实现
│   ├── udp_server.h / .c      # UDP 传输栈与切片重组协议
│   ├── udp_discovery.h / .c   # UDP 局域网广播自发现协议
│   └── usb_server.h / usb_hub.h / .c # USB WinUsb / 组提交管道实现
└── Main.cpp           # 驱动标准导出入口（仅直调 DriverCore::Initialize）
```

### 2. 纯静态类（Pure Static Class）封装核心铁律

全栈驱动核心功能一律遵循纯静态类架构：

1. **零虚函数与零对象实例化（Zero-Overhead Static Abstraction）**：
   - 所有服务类成员方法与状态一律为 `static`；
   - 严禁声明或使用 `virtual` 虚函数，`.rdata` 节区虚函数表特征严格为 0；
   - 严禁类实例化或全局对象构造，杜绝 CRT 初始化依赖与堆分配开销。
2. **断绝胶水中间层（Zero Pass-through Wrappers）**：
   - 彻底剔除为了“包装”而存在的单行透传函数；业务调用方直接调用目标类底层静态例程；
   - 彻底清除历史未引用函数（如已废弃的旧物理读接口），保持编译 0 警告（`C4505`、`C4100` 等完全根除）。
3. **C/C++ 混编兼容桥接**：
   - 头文件中的 `class` 定义严格包裹于 `#ifdef __cplusplus` 内，确保纯 C 源文件（如 `wsk_server.c`, `udp_server.c`）直接包含时不触发 `C2061` 语法错误；
   - 提供必要的 `extern "C"` 桥接，保证 C 模块与 C++ 纯静态类互通无阻。

### 3. 入口极致收敛契约

`Main.cpp` 彻底精简为纯粹的系统导出入口点，业务逻辑全部收敛由 `DriverCore` 托管：

```cpp
#include "DriverCore.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryPath)
{
    return DriverCore::Initialize(pDriverObj, pRegistryPath);
}
```

---

## 三、 已知约束与避坑指南

1. **工程头文件包含目录（Include Directories）**：
   - 为避免深层目录之间出现错综复杂的 `../../` 相对路径引用，在 MSBuild 工程配置（`Machenike.vcxproj`）中统一向 `<AdditionalIncludeDirectories>` 注入 `$(ProjectDir)` 及 6 个子目录；
   - 各模块可保持简短明确的文件名包含。
2. **UTF-8 BOM 与 MSVC 兼容性**：
   - MSVC (代码页 936) 对未包含 BOM 的多字节源码极易产生字符截断或解析错误；
   - 每次代码生成或重构后，必须强制执行 `python convert_bom.py`，保持全量源码 UTF-8 BOM + CRLF 格式一致性。
3. **状态初始化原子性**：
   - 纯静态类不具备构造函数，其内部依赖的状态（如 `UserVar` 接口指针）通过统一的 `Init(...)` 或驱动启动参数显式传入就绪，严禁在未初始化前解引用私有静态指针。
