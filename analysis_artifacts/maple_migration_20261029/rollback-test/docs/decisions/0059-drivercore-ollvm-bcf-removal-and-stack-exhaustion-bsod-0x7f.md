# ADR-0059: 彻底根除 DriverCore.cpp 混淆虚假控制流(--bcf)累加减栈与 BugCheck 0x7F (#DF) 闭环规范

- **状态**: 已采纳
- **日期**: 2026-10-25
- **影响模块**: `Machenike.vcxproj`, `Core\DriverCore.cpp`, `bin\mswsk_llvm.sys`

---

## 一、 背景与崩溃现场取证 (`102526-10453-01.dmp`)

在 Windows 内核加载 `ReleaseLLVM|x64` 编译生成的 `mswsk_llvm.sys` 驱动时，系统在初始化阶段触发致命双重错误停机：

```text
UNEXPECTED_KERNEL_MODE_TRAP (7f)
Arg1: 0000000000000008 (EXCEPTION_DOUBLE_FAULT)
Arg2: fffff8072c6c5e70 (TrapFrame)
Arg3: fffffa01474c3ff0 (Faulting Address / Illegal RSP)
Arg4: fffff807a7f09fdb (Faulting RIP @ mswsk.sys + 0x59fdb)

PROCESS_NAME:  System (PID 4)
STACK_LIMIT:   fffffa01474c4000
FAULTING_RSP:  fffffa01474c3ff0 (低于 Limit 16 字节，击穿 Guard Page)
FAULTING_RBP:  fffffa01474ca6a0 (单帧消耗 26,288 字节 / 25.67 KB)
```

### 1. 故障汇编与硬件升级链
- 反汇编显示崩溃落入 OLLVM `--bcf` 插入的虚假基本块：
  ```assembly
  mswsk+0x59fc3: 4989e0            mov     r8, rsp
  mswsk+0x59fdb: 458808            mov     byte ptr [r8], r9b  <-- 写入 [fffffa01474c3ff0] 触发 #PF
  ...
  mswsk+0x5a003: 4c29c4            sub     rsp, r8
  mswsk+0x5a037: 4c29c4            sub     rsp, r8
  ```
- 当前线程为系统工作线程 `nt!ExpWorkerThread`（总栈空间 28 KB：Base `0xfffffa01474cb000`，Limit `0xfffffa01474c4000`）；
- `DriverCore::Initialize` 单帧吞噬 25.67 KB 栈空间，导致 RSP 跌穿 Limit 进入未映射保护页；
- 写入保护页触发缺页中断 `#PF`，CPU 尝试压栈时因无可用栈空间再次缺页，直接硬件升级为 **Double Fault (`#DF`, Exception 8)**，内核调用 BugCheck 0x7F 蓝屏停机。

---

## 二、 根因定位与 ADR 负向知识对照

1. **工程配置违例**：
   在 `Machenike.vcxproj` 中，包含 2300 行代码及多处线性扫描循环（模块遍历、节区扫描、字符串展开）的 `Core\DriverCore.cpp` 被错误挂载了全套混淆选项：
   `-mllvm --const-obfus -mllvm --sub -mllvm --bcf -mllvm --bcf_prob=70 -mllvm --mba-subs -mllvm --mba-prob=80 -mllvm --bcf_loop=1`；
2. **机制冲突**：
   OLLVM `--bcf` 为不透明谓词生成连续的动态 `AllocaInst`（`sub rsp, reg`）。由于 `alloca` 分配的栈空间无法在循环迭代内回收，循环迭代导致栈指针持续递减；编译产物 `DriverCore.obj` 内部散落了多达 **3,793** 条 `sub.*rsp` 指令，体积暴增至 1,020 KB；
3. **负向知识继承**：
   此事故再次触犯 **ADR-0039**“长循环与动态 Alloca 互斥铁律”。

---

## 三、 技术决策与修复落地 (Decisions)

1. **彻底剥离 `DriverCore.cpp` 的 `--bcf` 选项**：
   在 `Machenike.vcxproj` 中将 `Core\DriverCore.cpp` 的独立混淆指令彻底删除，使其回归项目默认的 `-mllvm --string-obfus` 全局配置：
   ```diff
   -    <ClCompile Include="Core\DriverCore.cpp">
   -      <AdditionalOptions Condition="'$(Configuration)|$(Platform)'=='ReleaseLLVM|x64'">-mllvm --const-obfus -mllvm --sub -mllvm --bcf -mllvm --bcf_prob=70 -mllvm --mba-subs -mllvm --mba-prob=80 -mllvm --bcf_loop=1 %(AdditionalOptions)</AdditionalOptions>
   -    </ClCompile>
   +    <ClCompile Include="Core\DriverCore.cpp" />
   ```
2. **构建与栈深实测验证**：
   - `DriverCore.obj` 体积由 **1,020 KB** 骤降至 **162 KB**；
   - `sub.*rsp` 指令总数由 **3,793** 骤降至 **19** 条；
   - 单函数栈深压缩至 `< 1 KB`，彻底根除 Double Fault (0x7F) 隐患。
