# ADR-0034: 驱动全链路 Zero IAT 架构设计、全量动态 API 解析与本地 SEH 转发桩

- **状态**: 已采纳
- **日期**: 2026-10-18
- **上下文与痛点**:
  反作弊系统（如 ACE、Vanguard、BE、EAC）与 EDR 引擎在内核模块加载或内存扫描时，会对目标 `.sys` 镜像的 PE 导入表（IAT）进行深度启发式审计与特征提取。若驱动 IAT 中存在敏感内核例程（如 `ExAllocatePool2`, `ExFreePoolWithTag`, `IoCallDriver`, `ObReferenceObjectByName`, `BCrypt*` 等），将直接暴露模块的底层行为特征，招致针对性的交叉引用分析与封禁。此前 `ADR-0001` 虽剥离了 `HAL.dll`，但仍残留 `ntoskrnl.exe` 与 `cng.sys` 的部分静态符号，未能达到真正的 100% 0 导入表（Zero IAT）。

- **技术决策与规范**:
  1. **全量哈希与跨环函数指针契约拓展**:
     - 在 `MachenikeString.h` 中扩展全部新增 `ntoskrnl.exe` 与 `cng.sys`（13 个 BCrypt 核心加密函数）的动态哈希常量，算法必须严格与 `Utils::HashStringA(s, len, TRUE)`（`0x1003f` 乘法哈希且忽略大小写）对齐；
     - 在 `Common.h` 中定义强类型函数指针 `MACHENIKE_PFN` 与 `MACHENIKE_CNG_PFN`，收敛于 `MACHENIKE_KERNEL_INTERFACE` 统一纳管，严格保持加载器与驱动跨环结构体 1:1 对齐；
  2. **DriverCore 阶段模块自枚举与动态解算**:
     - 驱动入口通过已获取的 `RtlPcToFileHeader` 获取系统模块基地址，自解析导出表动态解析所有 `ntoskrnl` 和 `cng.sys` API；
  3. **CRT 与安全字符串零依赖重构**:
     - 彻底清除对 MSVCRT 的依赖，实现零依赖的 `SafeStrncpy`, `SafeStrnicmp`, `SafeCompareMemory` 原语，并通过 C++ 模板重载 `SafeStrncpyS` 适配变参与固定数组拷贝；
  4. **Zero IAT 本地 SEH 异常分发桩**:
     - 在 `SEHHandler.cpp` 中本地定义 `__C_specific_handler` 符号，运行时通过全局 `g_pGlobalUserVar->Func.pfnCSpecificHandler` 安全中继转调真实内核例程，阻断 MSVC 编译器向 `ntoskrnl.lib` 发起静态导入依赖；
  5. **编译选项与栈探针消除**:
     - `Machenike.vcxproj` 彻底移除 `cng.lib;ksecdd.lib;` 依赖，编译命令行注入 `/Gs9999999` 彻底消除大于 4KB 局部变量触发的编译器 `__chkstk` 静态链接；
     - 内存管理全面切换为 `TlsAlloc` / `TlsFree` 动态指针，杜绝类函数宏（如 `#define ExAllocatePool2`）对结构体字段调用的预处理错位。

- **已知约束与避坑**:
  1. **宏污染防护**: 严禁在驱动任何头文件编写与系统 API 同名的无作用域宏（如 `#define ExAllocatePool2`），防范宏展开破坏 `UserVar->Func.ExAllocatePool2` 成员调用；
  2. **全局上下文生命周期**: `g_pGlobalUserVar` 必须在 `DriverEntry` 首要阶段初始化，并在驱动完全停用卸载时原子解绑；`__C_specific_handler` 本地桩必须做判空与 `ExceptionContinueSearch` 安全兜底；
  3. **产物验证硬门禁**: 编译后必须通过 `dumpbin /HEADERS` 与 `dumpbin /IMPORTS` 双重验证，断言 `Import Directory`、`Bound Import Directory`、`Import Address Table Directory` 的 RVA 与 Size 均为 0；
  4. **哈希算法严格对齐约束**: 动态解析哈希必须严格基于项目原生乘法哈希（`Utils::HashStringA(name, len, TRUE)`，乘法因子 `0x1003f` 且统一转换为小写）进行预计算；严禁混用 Jenkins、FNV-1a 或区分大小写算法，防范运行时动态解析因哈希不一致导致 `STATUS_NOT_FOUND`（如 `Index:[75] KeSetTimerEx` 查找失败）。
