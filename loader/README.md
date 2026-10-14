# mswsk 内存加载器

## 项目概述

本项目实现了一个 **零文件落地** 的内核驱动内存加载器，通过 **WHQL 驱动 switch default 分支注入** 技术，将 `mswsk.sys`（WSK 内核网络驱动）以物理内存 Shellcode 的方式加载到内核空间。

### 核心特性

- **WHQL 白名单绕过**：利用已签名的 `Machenike.sys` WHQL 驱动作为物理内存读写原语
- **default 分支注入**：扫描驱动 `switch` 语句的 `default` case 物理地址，写入 Shellcode
- **位置无关代码**：Shellcode 使用 x64 position-independent 汇编，无需运行时重定位
- **自修复机制**：执行完成后自动恢复原始字节，不留痕迹
- **PE 头抹除**：加载后清空 MZ/PE 特征，对抗物理内存扫描
- **伪装模块名**：在 `PsLoadedModuleList` 中伪装为 `acpiex.sys`

---

## 目录结构

```
loader/
├── main.cpp                  # 主程序（权限检查、参数解析、加载入口）
├── loader_common.h           # 通用结构定义（WINPMEM_MEMORY_INFO、KLDR_ENTRY_K）
├── whql_io.h                 # WHQL 驱动 I/O 封装（SipHash 认证、READ/WRITE/TRIGGER）
├── phys_walk.h               # 用户态页表遍历（VA→PA 转换、FindKernelExport）
├── manual_map.h              # PE 手动映射（展开镜像、修复 IAT、抹除 PE 头）
├── shellcode_builder.h       # Shellcode 构造器（扫描 default 分支、注入、等待完成）
├── shellcode.asm             # x64 汇编 Shellcode（ExAllocatePoolWithTag、MmCopyMemory、DriverEntry）
├── extract_shellcode.py      # 从 shellcode.obj 提取字节码的 Python 脚本
├── shellcode.obj             # 编译后的 COFF 目标文件（需手动生成）
└── CMakeLists.txt            # CMake 构建脚本
```

---

## 构建步骤

### 1. 编译 Shellcode（需 MASM x64）

```cmd
cd loader
ml64 /c /Fo shellcode.obj shellcode.asm
```

提取字节码到 `shellcode_builder.h`（已自动嵌入，无需手动操作）：

```cmd
python extract_shellcode.py shellcode.obj
```

### 2. 编译 loader.exe

#### 方法 A：使用 CMake

```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

输出：`build\bin\Release\loader.exe`

#### 方法 B：使用 Visual Studio

1. 打开 `loader\CMakeLists.txt`（VS 2019+ 支持 CMake 工程）
2. 选择 `x64-Release` 配置
3. 生成解决方案（Ctrl+Shift+B）

---

## 使用方法

### 前置条件

1. **管理员权限**（必须）
2. **WHQL 驱动已加载**  
   确认 `Machenike.sys` 已通过合法途径加载到内核（如 Service 方式）
3. **mswsk.sys 文件**  
   放置在与 `loader.exe` 同目录，或通过命令行参数指定路径

### 基本用法

```cmd
# 默认加载同目录下的 mswsk.sys
loader.exe

# 指定驱动路径
loader.exe C:\path\to\mswsk.sys
```

### 执行流程

1. **权限检查**：检测管理员权限，若无则自动 UAC 提升
2. **打开 WHQL 设备**：计算 SipHash Token，打开 `\\.\Machenike\{Token}`
3. **获取系统信息**：通过 `GET_INFO_IOCTL` 获取 CR3、KernBase、PsLoadedModuleList
4. **扫描 default 分支**：在 WHQL 驱动物理内存中搜索 `mov eax, 0xC000000D` 特征码
5. **PE 展开与修复**：读取 `mswsk.sys`，完成节区映射、IAT 修复、PE 头抹除
6. **注入 Shellcode**：将参数块、Shellcode 字节码、展开镜像写入 default 分支物理地址
7. **触发执行**：发送无效 IOCTL 码（`0xDEADBEEF`），命中 default 分支执行 Shellcode
8. **等待完成**：轮询 `params.completed` 物理字段（超时 5 秒）
9. **自修复**：恢复 default 分支原始字节
10. **验证结果**：检查 `params.status`（0 = 成功，非 0 = NT 错误码）

---

## 技术细节

### Shellcode 执行流程（shellcode.asm）

1. **分配内核池**：`ExAllocatePoolWithTag(NonPagedPoolNx=0x200, ImageSize, 'wskD')`
2. **物理复制镜像**：`MmCopyMemory(pKernelImage, &ImagePhysAddr, ImageSize, MM_COPY_MEMORY_PHYSICAL)`
3. **调用 DriverEntry**：`DriverEntry(pKernelImage, NULL)`（简化版，未构造 DRIVER_OBJECT）
4. **标记完成**：`params->completed = 1; params->status = STATUS_SUCCESS;`
5. **返回伪装**：`mov eax, 0xC000000D; ret`（伪装成正常 default 分支返回 `STATUS_INVALID_PARAMETER`）

### 内存布局（方案 C 工业级架构）

```
WHQL 驱动代码段 (Machenike.sys):
  [default 分支 (0x140001683)]:
    - 5 字节 JMP rel32 → 跳到 Code Cave 入口
    - 执行后自动恢复原始指令 (BB 0D 00 00 C0)

  [.text 末尾 Code Cave (0x140002840)]:
    - ShellcodeParams（72 字节紧凑参数块）
    - Shellcode 机器码（278 字节，内置 PE 重定位引擎）
    - 执行完毕后自动清零抹除

内核池 (NonPagedPoolNx):
  - 由 ExAllocatePoolWithTag(NonPagedPoolNx, SizeOfImage, 'wskD') 合法分配
  - 通过 MmCopyMemory(MM_COPY_MEMORY_VIRTUAL) 直接将用户态镜像虚拟拷贝入内核池
  - 内置重定位引擎自动遍历修复全部 DIR64 重定位项
```

### 核心优势与技术突破

1. **已完整支持 PE 64 位基址重定位循环 (Base Relocation Loop)**  
   Shellcode 内置完整的 PE `.reloc` 遍历修复引擎，自动计算 `delta = pKernelImage - OriginalImageBase` 并遍历修复所有 `IMAGE_REL_BASED_DIR64` 项，支持任意开启 `/DYNAMICBASE`（ASLR）的驱动！无需依赖未导出的内核 API。

2. **零代码段踩踏与零物理连续性假设（方案 C）**  
   摒弃了“展开镜像写在 default 分支后方”的脆弱假设，不侵占任何既有业务代码。参数与 Shellcode 仅驻留驱动空闲 Code Cave（463 字节空白），展开镜像通过内核池合法分配。

3. **DRIVER_OBJECT 简化说明**  
   `DriverEntry` 接收的第一个参数为内核池基址（`pKernelImage`），可用于 WSK 等不依赖 `DriverUnload` 导出的自给自足型网络驱动。

4. **单次加载保护**  
   加载并初始化完成后，自动恢复 default 分支指令并清零 Code Cave，不留内存痕迹。

---

## 故障排查

### 1. `WhqlOpen: all token attempts failed`

**原因**：SipHash Token 计算错误或 WHQL 驱动未加载  
**解决**：
- 确认 `Machenike.sys` 已加载（`sc query Machenike` 或 `DriverView`）
- 检查 `g_SipHashKey`、`g_Salt4`、`g_Step` 是否与驱动端一致

### 2. `FindWhqlDefaultBranch: signature not found`

**原因**：WHQL 驱动版本变化，default 分支特征码不匹配  
**解决**：
- 用 IDA/Ghidra 打开 `Machenike.sys`，定位 `DeviceControl` 函数中的 `switch` 语句
- 找到 `default: return STATUS_INVALID_PARAMETER;` 对应的机器码
- 更新 `WHQL_DEFAULT_SIG[]` 数组

### 3. `WaitShellcodeComplete: 超时`

**原因**：Shellcode 执行失败，未置 `completed` 标志  
**可能原因**：
- 内核函数地址解析错误（`FindKernelExport` 失败）
- 展开镜像物理地址无效（未正确写入或被覆盖）
- `MmCopyMemory` 返回错误（源物理地址不可访问）

**调试**：
- 在内核调试器中对 default 分支下断点，单步跟踪 Shellcode
- 检查 `params.status`（通过 `!db <paramsPA+0x154> L4` 查看）

### 4. `FixIAT: 'XXX' not found in ntoskrnl!`

**原因**：`mswsk.sys` 依赖的函数在当前 Windows 版本不存在  
**解决**：
- 检查 `mswsk.sys` 的目标 Windows 版本与实际运行版本是否匹配
- 使用 `dumpbin /IMPORTS mswsk.sys` 查看导入表

---

## 安全建议

- **仅在授权环境使用**：本工具涉及内核内存修改，仅供安全研究与测试
- **备份系统**：操作前务必备份系统，错误操作可能导致 BSoD
- **ACE 对抗**：现代反作弊（EAC/BE）会扫描 PsLoadedModuleList 和物理内存，需额外对抗措施：
  - 从 PsLoadedModuleList 摘链（但需注意 KPTI 页表完整性检查）
  - 使用 EPT Hook 隐藏内存区域（需 VMM 支持）
  - 伪装 PE 头为合法驱动（如复制 `acpiex.sys` 的头部结构）

---

## 许可声明

本项目仅供学习研究，使用者需遵守当地法律法规。作者不对任何滥用行为负责。

---

## 参考资料

- [Manual Mapping Drivers](https://www.unknowncheats.me/wiki/Manual_Mapping)
- [Physical Memory Primitives via WHQL Drivers](https://github.com/memN0ps/arsenal)
- [Bypassing Driver Signature Enforcement](https://www.securityjoes.com/post/bypass-driver-signature-enforcement)

---

## 联系方式

问题反馈：提交 Issue 到本项目仓库  
技术交流：QQ群 1057540028 / 1077074552
