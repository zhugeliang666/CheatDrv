# ADR-0046: WFP Callout DKOM 指针扫描边界收紧与根除 BugCheck 0x50 蓝屏规范

- **状态**: 已采纳
- **日期**: 2026-10-19
- **上下文与痛点**:
  在分析内核崩溃转储文件（`101926-5718-01.dmp`）时，系统在系统工作线程 `nt!ExpWorkerThread` 执行网络安全监控周期巡检中触发 `BugCheck 0x50 (PAGE_FAULT_IN_NONPAGED_AREA)`，故障指令落于 `WfpBypass::DoReplace()` 模式 2（指针数组扫描）的 `*pField` 解引用指令（`mov rax, qword ptr [rax]`）。
  深入分析揭示系统级三重根因：
  1. **指针有效性边界判定漏洞**：代码仅简单使用 `(ULONG_PTR)pObj <= 0xFFFF800000000000ULL` 过滤无效指针。当扫描数组中包含 32 位句柄、魔数或已释放槽位脏数据符号扩展生成的值（如 `0xFFFFFFFF00000001`）时，因其无符号数值大于 `0xFFFF800000000000`，被错误判定为有效内核指针；加上偏移 `0x10` 后形成 `0xFFFFFFFF00000011`；
  2. **内核态 SEH 局限性铁律（关键负向知识）**：开发者误以为外层包裹的 `__try / __except (EXCEPTION_EXECUTE_HANDLER)` 能拦截解引用异常。然而 Windows 内存管理器（`nt!MiSystemFault`）规定，对系统内核空间（`VA >= 0xFFFF800000000000`）的未映射页访问属于不可恢复的系统级违规，直接触发 `KeBugCheckEx(0x50)` 停机，绝不会向驱动的 SEH 分发异常；
  3. **解引用前缺失物理页探针**：在访问内部指针 `pField` 前未执行 `MmIsAddressValid` 校验。

- **技术决策与规范**:
  1. **统一引入严格内核指针判别原语**：
     在 `WfpBypass.cpp` 中定义内联判别函数 `WfpBypass_IsValidKernelPtr(const void *ptr)`：
     ```cpp
     static inline BOOLEAN WfpBypass_IsValidKernelPtr(const void *ptr)
     {
         ULONG_PTR u = (ULONG_PTR)ptr;
         if (u <= 0xFFFF800000000000ULL || u >= 0xFFFFFF0000000000ULL)
             return FALSE;
         return MmIsAddressValid((PVOID)ptr);
     }
     ```
     严格限定内核地址处于合法的规范高半区范围，剔除 `0xFFFFFF0000000000` 以上的异常符号扩展地址，并通过 `MmIsAddressValid` 确保物理页表存在有效映射。
  2. **全链路全轨道深度加固**：
     在 `WfpBypass_FindCalloutTable` 及 `DoReplace` 所有扫描轨道（扁平结构体模式 1、指针数组模式 2、辅助字段 Track-3、暴力宽扫 Track-4）中，所有各级对象与字段指针（`pTbl`、`subTable`、`pEntry`、`pField`、`pSlot`、`val`）在读取或解引用前，必须强制通过 `WfpBypass_IsValidKernelPtr` 校验，未通过即刻跳过。

- **已知约束与避坑**:
  1. **内核态 SEH 铁律**：内核态驱动严禁试图使用 `__try / __except` 探测未知的内核系统空间指针（`VA >= 0xFFFF800000000000`），必须在解引用前调用 `MmIsAddressValid` 探针；
  2. **指针高半区范围防御**：进行指针合法性初筛时，严禁仅使用单向 `> 0xFFFF800000000000`，必须设立上限（`< 0xFFFFFF0000000000`）阻断符号扩展伪指针；
  3. **编码后置处理**：修改内核驱动源文件后必须执行 `python convert_bom.py`，保持全工程 UTF-8 BOM 编码一致性。
