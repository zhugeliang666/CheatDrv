# 动态获取导入表 API 设计规范 (精简版 Design Spec)

## 1. 目标 (Objective)
在 `LeechLoader` 项目中引入并实现基于 `lc_winapi` 架构的动态 API 解析机制。
**区别于全量拷贝**，本项目将采取**精准分析 + 按需新建**的策略：只对 `LeechLoader` 实际调用的 API 进行包装与宏拦截，从而减少二进制冗余并规避绝大部分宏冲突问题。

## 2. API 使用统计分析 (Analyzed APIs)
通过对 `LeechLoader` 全部源文件（`LeechLoader.cpp`, `utils.cpp`, `socket.cpp`, `lsp_utils.cpp` 等）的分析，本项目实际依赖的 WinAPI 列表如下：

### Kernel32.dll / KernelBase.dll
- `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`
- `CloseHandle`, `OpenProcess`, `GetCurrentProcess`, `GetCurrentProcessId`
- `GetModuleHandleW`, `GetModuleFileNameW`, `GetSystemDirectoryW`
- `Sleep`, `TerminateProcess`, `CreateProcessW`
- `WideCharToMultiByte`, `MultiByteToWideChar`
- `QueryFullProcessImageNameW`, `CreateFileW`, `CreateFileA`
- `GetLastError`, `SetLastError`, `LocalAlloc`, `LocalFree`, `GlobalAlloc`, `GlobalFree`
- `OutputDebugStringA`, `OutputDebugStringW`, `SetConsoleOutputCP`, `SetConsoleCP`

### Advapi32.dll
- `OpenProcessToken`, `GetTokenInformation`
- `OpenSCManagerW`, `OpenServiceW`, `ControlService`, `QueryServiceStatus`, `DeleteService`, `CloseServiceHandle`
- `RegQueryValueExW`, `RegCloseKey`

### Ws2_32.dll
- `WSAStartup`, `WSACleanup`, `WSAGetLastError`
- `socket`, `bind`, `listen`, `accept`, `connect`, `closesocket`, `send`, `sendto`, `recv`, `recvfrom`
- `setsockopt`, `getsockopt`, `htons`, `htonl`, `ntohs`, `ntohl`, `inet_ntop`, `inet_addr`, `select`
- `WSCEnumProtocols`, `WSCInstallProvider`, `WSCDeinstallProvider`, `WSCWriteProviderOrder`

### Iphlpapi.dll
- `GetAdaptersAddresses`, `GetExtendedTcpTable`

### Shell32.dll
- `SHGetKnownFolderPath`, `ShellExecuteExW`

### Shlwapi.dll
- `PathRemoveFileSpecW`

### Setupapi.dll & Winusb.dll
- `SetupDiGetClassDevsW`, `SetupDiEnumDeviceInfo`, `SetupDiGetDeviceRegistryPropertyW`, `SetupDiOpenDevRegKey`, `SetupDiEnumDeviceInterfaces`, `SetupDiGetDeviceInterfaceDetailW`, `SetupDiDestroyDeviceInfoList`
- `WinUsb_Initialize`, `WinUsb_QueryInterfaceSettings`, `WinUsb_QueryPipe`, `WinUsb_Free`

### Rpcrt4.dll
- `UuidCreate`

---

## 3. 架构设计与新建模块 (Architecture & Implementation)

1. **新建底层动态解析头文件 `lc_winapi.h`**：
   - 提取 `leechcore/lc_winapi.h` 中的 PEB/TEB 查找算法、导出表解析（EAT）、转发解析（Forwarder Resolve）以及 `LdrLoadDll` 动态加载模块机制。
   - 只针对上文列举的 API 编写 `LC_WINAPI_PROC` 和宏定义。

2. **新建全局导入代理文件 `lc_winapi_import.c`**：
   - 编写针对上述 API 的 `LC_WINAPI_IMPORT` 代理存根（Stub）。
   - 防止 CRT 或静态库引入固定导入表。

3. **项目关联与导入清理**：
   - 在 `common.h` 底部添加 `#define LC_WINAPI_NO_IMPORT_TABLE` 与 `#include "lc_winapi.h"`。
   - 清理 `common.h` 和 `lsp_utils.cpp` / `socket.cpp` 中不必要的 `#pragma comment(lib, "xxx.lib")`。
   - 在 Visual Studio 工程文件 `LeechLoader.vcxproj` 中引入 `lc_winapi_import.c` 和 `lc_winapi.h`。

## 4. 验证与测试 (Verification)
- 验证 MSBuild 能够成功编译。
- 使用 PE 分析工具（如 Dependency Walker / PEview）确认生成文件的 IAT 中对应 API 已经消失。
