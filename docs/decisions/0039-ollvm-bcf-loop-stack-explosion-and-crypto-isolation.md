# ADR-0039: 彻底根除 OLLVM BCF 虚假基本块循环累加减栈 (BugCheck 0x7F #DF) 与密码学/验证三层混淆隔离架构规范

- **状态**: 已采纳
- **日期**: 2026-10-18
- **上下文与痛点**:
  在启用 `ReleaseLLVM` 定制混淆编译器构建 `mswsk.sys` 时，驱动在用户态调用 `CreateFile` 触发 `DriverCore::DispatchCreate` $\to$ `DrvSecurity::ScanAndDecryptUserPayload` 时，连续触发 `BugCheck 0x7F (Arg1 = 8, EXCEPTION_DOUBLE_FAULT)` 蓝屏死机。
  现场逆向转储文件（`101826-6656-01.dmp` 与 `101826-6843-01.dmp`）表明：
  在包含用户态大跨度扫描（`for offset ... offset += sizeof(ULONG_PTR)`，数千次迭代）的函数中挂载 `-mllvm --bcf` 或 `--mba-subs` 时，Goron/OLLVM 会为虚假基本块与中间代数变量注入连续的 `AllocaInst`（反汇编中连续串联 `sub rsp, reg`）。
  由于 C/LLVM 规范下 `alloca` 申请的栈空间无法在循环单次迭代中回收，导致 `sub rsp` 随循环迭代被反复执行，单帧吞噬栈空间高达 **22,864 字节 (0x5950)**，直接跌破 Windows x64 内核 28KB 线程栈底 `Limit (ffff...d9000)`，写入未映射警戒页触发 `#PF` 缺页异常，最终硬件升级为不可恢复的 Double Fault (`#DF`) 蓝屏死机。

- **技术决策与规范（三层物理隔离架构）**:
  1. **核心验证与自检逻辑全量顶配混淆 (`DrvSecurity.cpp`)**:
     - `DrvSecurity.cpp` 收敛全部关键鉴权与反逆向函数：`CalcToken` / `ValidateToken`、`EncryptReportData`、`InitTextIntegrity` / `VerifyTextIntegrity`、`SetAuthStateInvariant` / `VerifyAuthStateInvariant`、`AuditHardwareBreakpoints` (DR0-DR7)、双向心跳挑战应答；
     - 这些函数**无任何长扫描循环，全是纯寄存器计算与极小栈帧**。配置全套顶配混淆：
       `-mllvm --const-obfus -mllvm --sub -mllvm --bcf -mllvm --bcf_prob=70 -mllvm --mba-subs -mllvm --mba-prob=80 -mllvm --bcf_loop=1`；
     - 实测反汇编单函数栈深均严格在 **48 ~ 280 字节**以内，控制流与判断逻辑深度平坦化与虚假分支混淆，100% 免疫栈累加。
  2. **用户态内存扫描与载荷解密隔离混淆 (`PayloadDecryptor.cpp`)**:
     - 将含数千次循环扫描的 `DrvSecurity::ScanAndDecryptUserPayload` 独立提取至 [`Security\PayloadDecryptor.cpp`](../../Security/PayloadDecryptor.cpp)；
     - 剔除会产生动态 `AllocaInst` 的 `--bcf` 与 `--mba-subs`，配置为**指令替换与字符串加密矩阵**：
       `-mllvm --sub -mllvm --string-obfus`；
     - 实测反汇编显示其单帧栈深严格固定在 **1,224 字节 (0x4C8)**，整函数无任何动态 `subq %reg, %rsp`，彻底根除循环累加泄露；同时逻辑算术运算与调试字符串 100% 混淆加密。
  3. **核心密码学算力原语物理隔离 (`CryptoPrimitives.cpp`)**:
     - 将敏感底层算法（`SipHash24`、`CalcAdler32`、`Rc4Encrypt`、`Rc4Decrypt`）收敛至 [`Security\CryptoPrimitives.cpp`](../../Security/CryptoPrimitives.cpp)；
     - 无字符串字面量、无大局部变量、无 SEH，开启全套混淆（`-mllvm --const-obfus -mllvm --sub -mllvm --bcf -mllvm --bcf_prob=70 -mllvm --mba-subs -mllvm --mba-prob=80 -mllvm --bcf_loop=1`），实测单函数栈帧仅 64 ~ 304 字节，彻底实现“强混淆抗逆向”与“0 爆栈风险”的完美平衡。
  4. **底层字符串与导出表工具原生纯净 (`Utils.cpp`)**:
     - [`Security\Utils.cpp`](../../Security/Utils.cpp) 仅保留 `HashStringA/W`、`GetModuleExport`、`HexCharToNibble` 等底层高频工具例程，100% 原生零混淆，确保微秒级执行性能与零副作用。

- **已知约束与避坑**:
  1. **长循环与动态 Alloca 互斥铁律**: 凡迭代次数超过 100 次的长跨度循环（如节区线性扫描），绝对严禁开启 Goron/OLLVM 的 `--bcf`、`--mba-subs` 与 `--const-obfus`，防止动态 `alloca` 在循环体内累加击穿内核 28KB 栈底；
  2. **混淆细分选型准则**:
     - 需平坦化与分支爆炸：仅限无长循环的业务验证函数（`DrvSecurity.cpp`）；
     - 需加解密数学对抗：纯算力原语无字符串文件（`CryptoPrimitives.cpp`）；
     - 包含长循环扫描：必须使用 `-mllvm --sub` 纯指令替换 + `--string-obfus`，确保固定栈分配；
  3. **实测校验门禁**: 每次对混淆配置调整后，必须使用 `llvm-objdump -d` 审查 `.obj` 中的 `subq` 指令，确保无循环内 `subq %reg, %rsp` 且单帧栈深严格控制在 `< 1.5KB`。
