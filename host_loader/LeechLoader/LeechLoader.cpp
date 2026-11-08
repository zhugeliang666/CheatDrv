// LeechLoader.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "common.h"
#include "protocol.h"


using namespace std;


namespace Environment
{
// 定义不同版本的配置
// const ServerConfig Dev = { "http://127.0.0.1/api", "http://127.0.0.1/report"
// }; const ServerConfig Test = { "http://117.24.12.241:1233/backend",
//						   "http://117.24.12.241:1234/report"
//}; const ServerConfig Default = { "http://117.24.12.241:1234/backend",
//							  "http://117.24.12.241:1234/report"
//}; const ServerConfig LieJiu = { "http://117.24.12.241:2345/backend",
//							 "http://117.24.12.241:1234/report"
//};
#ifdef _DEBUG
ServerConfig Current = {"https://112.5.37.106:4000", ""};
#else
ServerConfig Current = {"", ""};
#endif

} // namespace Environment

global_var gVar = {};
BOOL InitConfig();

#ifdef __cplusplus
#define DLL_EXPORT extern "C" __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllexport)
#endif

std::string GetLocalIPv4()
{
    std::string lastIP = "";
    ULONG bufLen = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, nullptr, &bufLen);

    std::vector<BYTE> buffer(bufLen);
    IP_ADAPTER_ADDRESSES *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, adapters, &bufLen) != NO_ERROR)
    {
        return "";
    }

    for (auto p = adapters; p; p = p->Next)
    {
        if (p->OperStatus != IfOperStatusUp)
            continue;
        if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        for (auto u = p->FirstUnicastAddress; u; u = u->Next)
        {
            SOCKADDR_IN *sa = reinterpret_cast<SOCKADDR_IN *>(u->Address.lpSockaddr);
            char ip[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            std::string ipStr = ip;
            ConsoleLog(L10N("system.found_local_ip") + ipStr, Log_Info);
            lastIP = ipStr;
        }
    }

    return lastIP;
}

// 1. 检查当前进程是否已经拥有管理员权限
bool IsProcessElevated()
{
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
        {
            fRet = elevation.TokenIsElevated;
        }
    }
    if (hToken)
        CloseHandle(hToken);
    return fRet;
}

// 2. 提权并重新启动自身，将命令行参数透传给提权后的进程
void RelaunchAsAdmin(int argc, wchar_t *argv[])
{
    if (IsProcessElevated())
    {
        return; // 已经是管理员，直接退出
    }

    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);

    std::wstring params;
    for (int i = 1; i < argc; ++i)
    {
        if (!params.empty())
        {
            params += L" ";
        }
        std::wstring arg = argv[i];
        if (arg.find(L' ') != std::wstring::npos)
        {
            params += L"\"" + arg + L"\"";
        }
        else
        {
            params += arg;
        }
    }

    SHELLEXECUTEINFOW sei = {sizeof(sei)};
    std::wstring _sei_lpVerb = strTowStr("runas");
    sei.lpVerb = _sei_lpVerb.c_str(); // 关键：触发 UAC 提权提示（混淆后）
    sei.lpFile = szPath;              // 重新启动程序自身
    if (!params.empty())
    {
        sei.lpParameters = params.c_str();
    }
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if (ShellExecuteExW(&sei))
    {
        exit(0); // 提权后的新进程成功启动，当前进程退出
    }
    else
    {
        // 用户可能点击了“否”，或者提权失败
        DWORD dwError = GetLastError();
        if (dwError == ERROR_CANCELLED)
        {
            std::cout << L10N("error.user_declined_elevation") << std::endl;
        }
    }
}

int wmain(int argc, wchar_t *argv[])
{
    DBG("[Init] LeechLoader starting...");
    if (!IsProcessElevated())
    {
        DBG("[Init] Process is not elevated. Requesting UAC elevation...");
        RelaunchAsAdmin(argc, argv);
        return 1;
    }
    DBG("[Init] Process running with administrative privileges.");
    // ────────────────────────────────────────────────────────────

    char strKey[] = {'f', 'u', 'c', 'k', 'n', 'a', 'r', 'a', 'k', 'a', 'e', 'v', 'e', 'r', 'y', 'd', 'a', 'y', '\0'};
    gVar.encrypted_key_static = strKey;
    gVar.bLogged = false;
    gVar.app_id = GenerateRandomID16();
    DBG("[Init] Generated AppId: %s", gVar.app_id.c_str());

    // 默认初始模式，后续在 TCP 握手时动态接收配置
    if (gVar.connection_mode == 0)
    {
        gVar.connection_mode = 1; // 默认 DMA / 正常连接模式
    }
    DBG("[Config] Default connection_mode initialized to: %d (Dynamic TCP configuration enabled)", gVar.connection_mode);

    if (InitConfig() == FALSE)
    {
        system("pause");
        return FALSE;
    }
    return TRUE;
}

// ============================================================
// 内核物理暗桩（Canary）防重复加载检测定义
// 与 CheatDrv\loader\loader_common.h 及 shellcode_builder.h 完全一致
// ============================================================
#define DRV_CANARY_WINDOW_LOW   0x10000000ULL // 256MB 起
#define DRV_CANARY_WINDOW_HIGH  0x40000000ULL // 1GB 止
#define DRV_WSK_CANARY_MAGIC    0x57534B5F4C4F4144ULL // ASCII: "WSK_LOAD"

#define DRV_CANARY_GUID_D1 0x57534B5FUL
#define DRV_CANARY_GUID_D2 0x4C4F
#define DRV_CANARY_GUID_D3 0x4144
#define DRV_CANARY_GUID_D4 { 0xB8, 0x99, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6 }

#define MACHENIKE_READ_IOCTRL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x504, METHOD_NEITHER, 3)

#pragma pack(push, 1)
typedef struct _DRV_WSK_CANARY
{
    GUID     Signature;       // 16 字节全局唯一 GUID
    uint64_t Magic;           // DRV_WSK_CANARY_MAGIC
    uint64_t KernelImageVA;   // 映射的目标核心驱动基址
    uint32_t ImageSize;       // 核心驱动镜像大小
    uint32_t ProtocolVersion; // 协议版本
    uint64_t CanaryPhysAddr;  // 该物理页自身的 PA
    uint64_t Timestamp;       // 加载时间戳
    uint64_t Reserved;        // 保留填充
} DRV_WSK_CANARY, *PDRV_WSK_CANARY;
#pragma pack(pop)

// 白驱动 Token 计算
static inline uint64_t SipHash24_Whql(const uint8_t key[16], const uint8_t *msg, size_t msgLen)
{
    uint64_t k0, k1;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

#define ROTL64_WHQL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND_WHQL                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        v0 += v1;                                                                                                      \
        v1 = ROTL64_WHQL(v1, 13);                                                                                      \
        v1 ^= v0;                                                                                                      \
        v0 = ROTL64_WHQL(v0, 32);                                                                                      \
        v2 += v3;                                                                                                      \
        v3 = ROTL64_WHQL(v3, 16);                                                                                      \
        v3 ^= v2;                                                                                                      \
        v0 += v3;                                                                                                      \
        v3 = ROTL64_WHQL(v3, 21);                                                                                      \
        v3 ^= v0;                                                                                                      \
        v2 += v1;                                                                                                      \
        v1 = ROTL64_WHQL(v1, 17);                                                                                      \
        v1 ^= v2;                                                                                                      \
        v2 = ROTL64_WHQL(v2, 32);                                                                                      \
    } while (0)

    size_t i = 0;
    while (i + 8 <= msgLen)
    {
        uint64_t m;
        memcpy(&m, msg + i, 8);
        v3 ^= m;
        SIPROUND_WHQL;
        SIPROUND_WHQL;
        v0 ^= m;
        i += 8;
    }
    uint64_t b = ((uint64_t)msgLen) << 56;
    size_t left = msgLen & 7;
    for (size_t j = left - 1; j < left; j--)
        b |= ((uint64_t)msg[i + j]) << (j * 8);
    v3 ^= b;
    SIPROUND_WHQL;
    SIPROUND_WHQL;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND_WHQL;
    SIPROUND_WHQL;
    SIPROUND_WHQL;
    SIPROUND_WHQL;
    return v0 ^ v1 ^ v2 ^ v3;
#undef SIPROUND_WHQL
#undef ROTL64_WHQL
}

static inline uint32_t CalcWhqlToken(uint64_t counter, uint32_t pid)
{
    static const uint8_t s_WhqlKey[16] = {
        0x3F, 0x7B, 0x9A, 0x1C, 0x5D, 0xE2, 0x48, 0x60,
        0x81, 0x05, 0xB4, 0xC7, 0xD3, 0xEA, 0xF9, 0x26
    };
    static const uint32_t s_Salt4 = 0x4D43484EU; // 'MCHN'

    uint8_t msg[16] = {};
    memcpy(msg, &counter, 8);
    memcpy(msg + 8, &pid, 4);
    memcpy(msg + 12, &s_Salt4, 4);
    uint64_t h = SipHash24_Whql(s_WhqlKey, msg, sizeof(msg));
    return (uint32_t)(h ^ (h >> 32));
}

// 尝试打开已运行的白驱动句柄（无服务则返回 INVALID_HANDLE_VALUE）
static HANDLE OpenWhqlDeviceQuick()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t ft64 = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t sec = ft64 / 10000000ULL;
    if (sec >= 11644473600ULL) sec -= 11644473600ULL;
    uint64_t counter = sec / 30ULL;
    uint32_t pid = GetCurrentProcessId();

    for (int d = -1; d <= 1; d++)
    {
        uint32_t token = CalcWhqlToken((uint64_t)((int64_t)counter + d), pid);
        wchar_t path[128];
        swprintf_s(path, L"\\\\.\\Machenike\\%08X", token);
        HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            return h;
        }
    }
    return INVALID_HANDLE_VALUE;
}

static bool WhqlReadPhysQuick(HANDLE hDev, uint64_t physAddr, void *buf, size_t len)
{
    uint8_t *dst = (uint8_t *)buf;
    size_t done = 0;
    while (done < len)
    {
        size_t chunk = (len - done < 0x1000) ? (len - done) : 0x1000;
        LARGE_INTEGER pa;
        pa.QuadPart = (LONGLONG)(physAddr + done);
        DWORD dwOut = 0;
        BOOL ok = DeviceIoControl(hDev, MACHENIKE_READ_IOCTRL,
                                  &pa, sizeof(pa),
                                  dst + done, (DWORD)chunk,
                                  &dwOut, NULL);
        if (!ok)
        {
            return false;
        }
        done += (dwOut > 0) ? dwOut : chunk;
    }
    return true;
}

// 核心检测：对应 shellcode_builder.h:361 CheckDriverCanary 方案 5 纯游离物理页暗桩扫描
static bool CheckDriverCanary(uint64_t *outCanaryPA = nullptr)
{
    HANDLE hDev = OpenWhqlDeviceQuick();
    bool needUnloadWhql = false;

    if (hDev == INVALID_HANDLE_VALUE)
    {
        // 若驱动句柄未直接打开，尝试启动已存在的 Machenike 服务
        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCM)
        {
            SC_HANDLE hSvc = OpenServiceW(hSCM, L"Machenike", SERVICE_START | SERVICE_QUERY_STATUS);
            if (hSvc)
            {
                StartServiceW(hSvc, 0, NULL);
                CloseServiceHandle(hSvc);
                needUnloadWhql = true;
            }
            CloseServiceHandle(hSCM);
        }
        hDev = OpenWhqlDeviceQuick();
    }

    if (hDev == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    static const GUID targetGuid = { DRV_CANARY_GUID_D1, DRV_CANARY_GUID_D2, DRV_CANARY_GUID_D3, DRV_CANARY_GUID_D4 };
    uint8_t probeBuf[sizeof(DRV_WSK_CANARY)] = {};
    bool canaryFound = false;

    for (uint64_t pa = DRV_CANARY_WINDOW_LOW; pa < DRV_CANARY_WINDOW_HIGH; pa += 0x1000)
    {
        if (WhqlReadPhysQuick(hDev, pa, probeBuf, sizeof(probeBuf)))
        {
            PDRV_WSK_CANARY pProbe = (PDRV_WSK_CANARY)probeBuf;
            if (pProbe->Magic == DRV_WSK_CANARY_MAGIC &&
                memcmp(&pProbe->Signature, &targetGuid, sizeof(GUID)) == 0)
            {
                canaryFound = true;
                if (outCanaryPA) *outCanaryPA = pa;
                DBG("CheckDriverCanary: Found kernel canary at PA=0x%llX, VA=0x%llX, Size=0x%X",
                    pa, pProbe->KernelImageVA, pProbe->ImageSize);
                break;
            }
        }
    }

    CloseHandle(hDev);

    if (needUnloadWhql)
    {
        // 探测完成后立即注销临时白驱动
        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCM)
        {
            SC_HANDLE hSvc = OpenServiceW(hSCM, L"Machenike", SERVICE_STOP | DELETE);
            if (hSvc)
            {
                SERVICE_STATUS status = {};
                ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
                DeleteService(hSvc);
                CloseServiceHandle(hSvc);
            }
            CloseServiceHandle(hSCM);
        }
    }

    return canaryFound;
}

enum class DriverRunningMode
{
    NotRunning = 0,
    NormalService = 1,   // 正常加载驱动 (i225v 服务)
    MemoryMapped = 2     // 内存映射驱动 (MK_ENABLE_MANUAL_MAP 物理暗桩)
};

static DriverRunningMode CheckDriverRunningState()
{
    DBG("[DriverCheck] Checking for existing active kernel driver instances...");
    // 1. 检查 Windows 服务管理器中是否存在正常服务模式下的 i225v (或旧版 mswsk) 驱动
    bool isNormalServiceRunning = false;
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        const wchar_t *checkServices[] = { DRIVER_SPOOF_SERVICE_NAME, L"mswsk" };
        for (const wchar_t *sName : checkServices)
        {
            SC_HANDLE hSvc = OpenServiceW(hSCM, sName, SERVICE_QUERY_STATUS);
            if (hSvc)
            {
                SERVICE_STATUS status = {};
                if (QueryServiceStatus(hSvc, &status))
                {
                    if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING)
                    {
                        isNormalServiceRunning = true;
                    }
                }
                CloseServiceHandle(hSvc);
            }
            if (isNormalServiceRunning) break;
        }
        CloseServiceHandle(hSCM);
    }

    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    namespace fs = std::filesystem;
    std::string i225vPath = (fs::path(sysDir) / L"drivers" / DRIVER_SPOOF_FILENAME).string();
    std::string mswskPath = (fs::path(sysDir) / L"drivers" / L"mswsk.sys").string();

    if (isNormalServiceRunning || IsFileInUseA(i225vPath) || IsFileInUseA(mswskPath))
    {
        DBG("[DriverCheck] Detected running service or locked file: %s", IsFileInUseA(i225vPath) ? i225vPath.c_str() : mswskPath.c_str());
        return DriverRunningMode::NormalService;
    }

    // 2. 检查内存映射驱动：MK_ENABLE_MANUAL_MAP 模式下驱动不会创建符号链接，
    //    基于 shellcode_builder.h:361 CheckDriverCanary 探测纯游离物理页 GUID 暗桩 (DRV_WSK_CANARY_MAGIC)
    DBG("[DriverCheck] Scanning physical memory canary for manual-mapped driver...");
    if (CheckDriverCanary())
    {
        DBG("[DriverCheck] Memory-mapped driver canary found in physical memory.");
        return DriverRunningMode::MemoryMapped;
    }

    DBG("[DriverCheck] Driver check passed: No residual driver found.");
    return DriverRunningMode::NotRunning;
}

static void StopAndCleanupDriver(DriverRunningMode mode)
{
    if (mode == DriverRunningMode::NormalService)
    {
        DBG("[Cleanup] Stopping and removing existing %ls (and mswsk) services...", DRIVER_SPOOF_SERVICE_NAME);
        // 停止并删除 i225v 与旧版 mswsk 服务
        SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (hSCManager)
        {
            const wchar_t *servicesToClean[] = { DRIVER_SPOOF_SERVICE_NAME, L"mswsk" };
            for (const wchar_t *sName : servicesToClean)
            {
                SC_HANDLE hExisting = OpenServiceW(hSCManager, sName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
                if (hExisting)
                {
                    SERVICE_STATUS svcStatus = {};
                    ControlService(hExisting, SERVICE_CONTROL_STOP, &svcStatus);
                    for (int i = 0; i < 30; ++i)
                    {
                        Sleep(100);
                        if (QueryServiceStatus(hExisting, &svcStatus) && svcStatus.dwCurrentState == SERVICE_STOPPED)
                            break;
                    }
                    DeleteService(hExisting);
                    CloseServiceHandle(hExisting);
                }
            }
            CloseServiceHandle(hSCManager);
        }

        // 删除 drivers\i225v.sys 及旧版 drivers\mswsk.sys
        wchar_t sysBuffer[MAX_PATH] = {0};
        if (GetSystemDirectoryW(sysBuffer, MAX_PATH))
        {
            namespace fs = std::filesystem;
            fs::path pI225 = fs::path(sysBuffer) / L"drivers" / DRIVER_SPOOF_FILENAME;
            try { if (fs::exists(pI225)) fs::remove(pI225); } catch (...) {}
            fs::path pMswsk = fs::path(sysBuffer) / L"drivers" / L"mswsk.sys";
            try { if (fs::exists(pMswsk)) fs::remove(pMswsk); } catch (...) {}
        }
        DBG("[Cleanup] Driver service and binary file cleaned up.");
    }
}

BOOL InitConfig()
{
    DBG("[InitConfig] Checking driver running state...");
    // 检查驱动是否已经加载运行（区分正常加载驱动与内存映射驱动）
    DriverRunningMode driverMode = CheckDriverRunningState();
    if (driverMode == DriverRunningMode::MemoryMapped)
    {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        ConsoleLog("Driver service is already running in memory. Please restart computer and retry.", Log_Error);
        Reporter::Report("InitConfig", 0xC0000035, "检测到内存中已有活动的驱动实例 (MemoryMapped)，需重启电脑");
        return FALSE;
    }
    else if (driverMode == DriverRunningMode::NormalService)
    {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        StopAndCleanupDriver(driverMode);
        DBG("[InitConfig] Automatically stopped and cleaned up residual driver service.");
    }

    if (!IsProcessElevated())
    {
        ConsoleLog(L10NC("error.run_as_admin"), Log_Error);
        Reporter::Report("InitConfig", 0xC0000022, "进程缺少管理员权限且提权未成功");
        return FALSE;
    }

    std::string localIP = GetLocalIPv4();
    DBG("[InitConfig] Local network address: %s", localIP.c_str());

    // 关闭 Windows 防火墙（域、专用、公用三个配置文件）
    DBG("[InitConfig] Disabling Windows Firewall profiles (domain, private, public)...");
    {
        const char *fwCmds[] = {"netsh advfirewall set domainprofile state off", "netsh advfirewall set privateprofile state off", "netsh advfirewall set publicprofile state off"};
        for (const char *cmd : fwCmds)
        {
            STARTUPINFOA si = {sizeof(si)};
            PROCESS_INFORMATION pi = {};
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            char cmdBuf[256];
            strncpy_s(cmdBuf, cmd, _TRUNCATE);
            if (CreateProcessA(NULL, cmdBuf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            {
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
        DBG("[InitConfig] Windows Firewall profiles disabled successfully.");
    }

    gVar.dynamic_key = GenerateRandomHexKey(32);
    DBG("[InitConfig] Generated session dynamic key: %s", gVar.dynamic_key.c_str());

    DBG("[InitConfig] Initializing TCP server thread (port 10004) and UDP discovery...");
    std::thread serverThread(tcp_server_create);
    serverThread.join();
    ConsoleLog(L10NC("system.init_success"), Log_Success);

    return TRUE;
}

DLL_EXPORT const char *GetApiUrl()
{
    const char *ret = Environment::Current.api.c_str();
    return ret;
}

DLL_EXPORT int getConnectMode()
{
    int ret = gVar.connection_mode;
    return ret;
}
