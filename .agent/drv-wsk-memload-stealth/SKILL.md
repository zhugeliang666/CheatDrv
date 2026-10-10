---
name: drv-wsk-memload-stealth
description: Use when loading drv_wsk (or any unsigned kernel driver) via memory mapping through an existing WHQL physical memory driver, without modifying the WHQL driver, and needing to evade ACE kernel-level detection including PsLoadedModuleList enumeration, IPI physical memory scan, and call stack backtrace auditing.
---

# drv_wsk 无签名内存加载与 ACE 对抗工程实践指南

## 概述

**核心原则**：利用已有 WHQL 物理读写驱动的固定原语（READ / WRITE / GET_INFO），在纯用户态完成 Manual Map（PE 展开、重定位修复、IAT 动态绑定）+ Shellcode 极简注入 + 执行触发与自修复，彻底规避 ACE 的内核检测链路。

---

## 1. 架构总览与模块职责划分

为最大程度降低内核代码复杂度与蓝屏（BSoD）风险，工程采用 **“用户态重载预处理，内核态极简拷贝启动”** 的架构思想：

| 模块文件 | 角色与职责 | 核心实现细节 |
|---|---|---|
| `loader/loader_common.h` | 结构体与常量定义 | WHQL 通信 IOCTL、SipHash Token 认证、WINPMEM_MEMORY_INFO 映射、CR3/PML4 结构、KLDR_DATA_TABLE_ENTRY 镜像定义 |
| `loader/whql_io.h` | WHQL 原语封装层 | SipHash-2-4 握手鉴权、物理内存分页读取、物理内存 ≤4KB 分块循环写入、未知 IOCTL 触发执行 |
| `loader/phys_walk.h` | 用户态物理页表遍历器 | 基于 CR3 的四级页表遍历（PML4→PDPT→PD→PT）、4KB/2MB/1GB 页大小自动适配、内核 VA 安全读写、ntoskrnl EAT 物理导出表解析 |
| `loader/manual_map.h` | 纯用户态 PE 映射引擎 | 节区按 SectionAlignment 展开、64 位重定位表（DIR64）修复、物理读取内核导出函数直接填补 IAT、MZ/PE 头物理擦除 |
| `loader/shellcode_builder.h` | 内核 Shellcode 生成与注入器 | 特征码扫描定位 WHQL default 分支（`B8 0D 00 00 C0`）、参数与跳转指令紧凑布局、内核态内存拷贝与入口调用、原始指令自修复 |
| `drv_wsk` | 目标业务驱动（无设备对象） | 彻底去除 `IoCreateDevice`/`IoCreateSymbolicLink`，入口初始化 WSK/WFP 并挂起工作线程，完成即返回 |

---

## 2. WHQL 物理 I/O 原语工程避坑指南

### 2.1 SipHash-2-4 Token 认证机制
- 驱动设备打开时需附带动态生成的 Token：
  - 由 `SipHash-2-4` 计算哈希值：`Hash(Key, Seed)`。
  - 用户态与驱动侧保持相同的 128 位硬编码密钥或动态协商机制，确保认证通过。

### 2.2 物理写操作的 4KB 硬性限制
- **坑点**：WHQL 驱动的 `MACHENIKE_WRITE_IOCTRL` 内部对写入长度做了一次性检查，单次写入长度不能超过一个物理页（`0x1000` / 4096 字节）。若单次请求传递大缓冲区，将直接触发 `STATUS_INVALID_PARAMETER` 或驱动截断。
- **解决方案**：在用户态封装 `WhqlWritePhys`，严格按照 `chunk = min(0x1000, len - done)` 进行分块循环写入：
  ```cpp
  while (done < len) {
      size_t chunk = min((size_t)0x1000, len - done);
      LARGE_INTEGER pa;
      pa.QuadPart = (LONGLONG)(physAddr + done);
      DeviceIoControl(hDev, MACHENIKE_WRITE_IOCTRL, &pa, sizeof(pa),
                      (PVOID)(src + done), (DWORD)chunk, &dwOut, NULL);
      done += chunk;
  }
  ```

---

## 3. 用户态 CR3 四级页表遍历（VA → PA）实战经验

### 3.1 四级页表索引解算
64 位虚拟地址（48位有效 Canonical 地址）划分为四个 9 位索引加 12 位页内偏移：
- `PML4 Index`: `(va >> 39) & 0x1FF`
- `PDPT Index`: `(va >> 30) & 0x1FF`
- `PD Index`:   `(va >> 21) & 0x1FF`
- `PT Index`:   `(va >> 12) & 0x1FF`

### 3.2 大页（Large Page）与巨页（Huge Page）的坑点
内核中大量代码段和池内存使用了 2MB 大页（甚至 1GB 巨页）。如果遍历器未处理 `PS (Page Size, Bit 7)` 标志，将会把页目录条目当作下一级页表物理地址读取，导致解析出的物理地址完全错误。
- **PDPT 巨页 (1GB)**：
  - 检查 `(pdptEntry & 0x80) != 0`（PS=1）。
  - 物理地址解算：`PA = (pdptEntry & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL)`。
- **PD 大页 (2MB)**：
  - 检查 `(pdEntry & 0x80) != 0`（PS=1）。
  - 物理地址解算：`PA = (pdEntry & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL)`。
- **PT 常规页 (4KB)**：
  - 物理地址解算：`PA = (ptEntry & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL)`。
- **有效性检查**：每一级必须校验 `entry & 1`（Present 位），若为 0 说明页面已换出或无效，立即终止返回 0。

### 3.3 物理读取内核 ntoskrnl EAT
- 避免依赖用户态 `LoadLibraryEx` 加载的 ntoskrnl 与真实运行的内核存在补丁或小版本差异。
- 直接利用 `GET_INFO` 获取的真实 `KernelBase`，通过页表遍历读取物理内存中的 `IMAGE_EXPORT_DIRECTORY`：
  - 解析 `AddressOfNames`、`AddressOfNameOrdinals` 与 `AddressOfFunctions`。
  - 在物理内存中直接比对函数名，获取准确的真实内核虚拟地址。

---

## 4. 纯用户态 Manual Map PE 预处理实践

为使内核 Shellcode 保持极致微型化，所有繁重的 PE 展开、重定位、导入表修复均在用户态内存中计算完成：

```
[磁盘中的 drv_wsk.sys]
        │
        ▼ (用户态预处理)
1. 申请 SizeOfImage 连续缓冲区
2. 按 SectionHeaders 将节区写入对应 VirtualAddress
3. 遍历 BaseRelocation 表，根据目标内核虚拟基址修复 DIR64 重定位
4. 遍历 ImportDirectory，通过内核 EAT 查找真实函数 VA，填入 IAT
        │
        ▼ (物理直写)
通过 WhqlWritePhys 将已完全装配就绪的 PE 内存块直接写入内核池/物理页
```

### 4.1 物理抹除 MZ/PE 头对抗 ACE 物理扫描
- **ACE 检测点**：`ace-ipi-sync-detection` 与物理内存全盘巡检会扫描非模块边界的 `IMAGE_DOS_SIGNATURE` (`"MZ"` / `0x5A4D`) 与 `IMAGE_NT_SIGNATURE` (`"PE\0\0"` / `0x00004550`)。
- **工程应对**：
  - 在驱动映射完成并调用 `DriverEntry` 之后，将映射内存的前 `0x1000` 字节（即 DOS Header、NT Header 及节表头部）全部覆写为 `0x00`。
  - 擦除后，即便物理内存扫描引擎直接扫到该页面，也只能看到空白垃圾数据，无法命中 PE 特征签名。

---

## 5. WHQL default 分支劫持与执行触发

### 5.1 物理扫描特征码定位
- WHQL 驱动的 `DispatchDeviceControl` 处理例程中，`switch(uIoControlCode)` 的 `default` 分支固定包含无效参数返回指令：
  - 特征机器码：`B8 0D 00 00 C0` (`mov eax, 0xC000000D` / `STATUS_INVALID_PARAMETER`)。
- 加载器扫描 WHQL 驱动代码段的物理内存，定位该 5 字节指令的具体物理地址 `site.physAddr`。

### 5.2 参数块与 JMP 跳转编排
- 由于 `default` 分支所在空间有限，且需要将内核函数地址、物理源地址等参数传递给内核 Shellcode：
  1. 在 `site.physAddr` 处写入 5 字节相对跳转指令 `E9 xx xx xx xx`，直接跳到紧随参数块之后的 Shellcode 代码执行体。
  2. 紧随其后写入 `ShellcodeParams` 结构体（存放分配的池地址、原始 5 字节指令、函数指针等）。
  3. 紧随参数块写入 Shellcode 汇编执行逻辑。

### 5.3 栈环境天然合法性（规避 CET 与 8 层栈回溯）
- **ACE 栈回溯与 CET 机制**（见 `ace-callstack-hijack-cet`）：
  - 传统 JMP Gadget 仅能伪造栈帧顶层，深层回溯仍会暴露裸内存。
  - 本方案的 Shellcode 是直接替换了合法 WHQL 驱动的代码，通过标准 `DeviceIoControl` 发送未知 IOCTL 触发。
  - **调用栈状态**：
    - `Thread Stack`：`ntoskrnl.exe!IofCallDriver` → `WHQL_Driver.sys!DispatchDeviceControl` → `WHQL_Driver.sys!Shellcode`。
    - 所有栈帧均落在合法已签名的 WHQL 驱动模块内存范围内，`RtlVirtualUnwind` 8 层回溯完全正常。
    - Intel CET 影子栈记录的返回地址与正常内核栈完全吻合，绝不触发 `#CP` 异常。

### 5.4 零痕迹自修复机制
- Shellcode 执行完成 `drv_wsk` 的初始化后，必须在返回前执行自我抹除：
  1. 将备份的原始 5 字节指令（`B8 0D 00 00 C0`）原子写回 `default` 分支入口。
  2. 将自身 Shellcode 占用的内存空间全部写零。
  3. 返回 `STATUS_INVALID_PARAMETER`，使发起触发的 `DeviceIoControl` 正常接收预期错误码返回用户态。

---

## 6. 目标驱动 `drv_wsk` 改造落地准则

1. **彻底剥离设备对象**：
   - 严禁调用 `IoCreateDevice` 与 `IoCreateSymbolicLink`，不创建任何命名管道或设备对象。
   - 避免在 `\Driver\` 或 `\Device\` 对象目录中留下未挂钩签名的对象节点。
2. **异步驻留设计**：
   - `DriverEntry` 仅作为初始化引导器，完成 WSK Socket、WFP Callout 注册或通过 `PsCreateSystemThread` 启动内核后台工作线程。
   - `DriverEntry` 必须在数毫秒内完成并返回 `STATUS_SUCCESS`，不得阻塞 WHQL 驱动的 IOCTL 分发线程。
3. **动态函数解析与接口表**：
   - 复用 `MACHENIKE_KERNEL_INTERFACE` 动态导入结构，避免在驱动静态导入表中直接硬编码非常规 API，减少 IAT 解析依赖。

---

## 7. ACE 核心对抗检查清单

| 检测机制 | 规避判定条件 | 实战验证方法 |
|---|---|---|
| `PsSetLoadImageNotifyRoutine` 模块加载审计 | ✅ 完全不调用 `NtLoadDriver`，纯物理内存复制，不触发事件 | 监控事件日志与 ACE 遥测上报，无加载日志 |
| `ZwQuerySystemInformation` 驱动枚举 | ✅ 手动构造 `KLDR_DATA_TABLE_ENTRY` 伪装合法系统驱动（如 `acpiex.sys`） | WinDbg `!lm` 检查伪装模块名与基址 |
| IPI 物理内存 MZ 签名扫描 | ✅ 驱动入口调用完成后，物理抹除前 `0x1000` 字节 PE 头 | WinDbg `db <BaseAddress>` 验证头部全为 0 |
| `RtlVirtualUnwind` 调用栈回溯 | ✅ 执行流源于合法 WHQL 驱动的 IOCTL 分发上下文，非裸内存跳入 | WinDbg `k` / `kn` 检查调用栈每一帧均为合法模块 |
| CET 影子栈校验 | ✅ 无修改返回地址，RETQ 目标与硬件影子栈完美对应 | 在支持 CET 的硬件（Intel 11代+）上稳定运行无 BSoD |
| Pool Tag 异常扫描 | ✅ 内存池分配使用系统通用白名单 Tag（如 `'FMsl'`, `'MmSt'`） | WinDbg `!poolfind` 检查 Tag 归属常规系统组件 |
