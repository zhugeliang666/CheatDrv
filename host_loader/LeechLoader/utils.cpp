#include "common.h"
#include "protocol.h"
#include "cave_mapper.h"
#include <random>
#include <cstdarg>

// ============================================================
// 1. 字符串、编码与 Hex 工具函数
// ============================================================

std::string BytesToHex_char(const uint8_t *p, size_t n)
{
    static const char *H = "0123456789ABCDEF";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        s[2 * i + 0] = H[(p[i] >> 4) & 0xF];
        s[2 * i + 1] = H[(p[i]) & 0xF];
    }
    return s;
}

std::vector<uint8_t> HexToBytes(const std::string &hex)
{
    if (hex.length() % 2 != 0)
    {
        throw std::runtime_error("Hex string must have an even length");
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);

    auto hexCharToInt = [](char c) -> int
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (size_t i = 0; i < hex.length(); i += 2)
    {
        int high = hexCharToInt(hex[i]);
        int low = hexCharToInt(hex[i + 1]);
        if (high == -1 || low == -1)
        {
            throw std::runtime_error("Invalid character in hex string");
        }
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

std::string BytesToHex(const std::vector<uint8_t> &data)
{
    if (data.empty())
    {
        return "";
    }
    std::string hex;
    hex.resize(data.size() * 2);
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < data.size(); ++i)
    {
        hex[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    return hex;
}

std::wstring strTowStr(const std::string &utf8)
{
    if (utf8.empty())
    {
        return L"";
    }
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), nullptr, 0);
    if (wlen <= 0)
    {
        return L"";
    }
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), &w[0], wlen);
    return w;
}

std::string wStrToStr(std::wstring wstr)
{
    if (wstr.empty())
    {
        return "";
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0)
    {
        return "";
    }
    std::string str(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &str[0], len, nullptr, nullptr);
    return str;
}

void StrlTrimCrlf(std::string &s)
{
    size_t pos = s.find_first_not_of("\r\n");
    if (pos != std::string::npos)
        s.erase(0, pos);
}

bool isHexString(const std::string &s)
{
    if (s.empty())
    {
        return false;
    }
    for (char c : s)
    {
        if (!std::isxdigit(static_cast<unsigned char>(c)))
        {
            return false;
        }
    }
    return true;
}

// ============================================================
// 2. 随机数与数据流加解密
// ============================================================

uint32_t Rand32()
{
    static std::random_device rd;
    static std::mt19937 rng(rd());
    uint32_t ret = std::uniform_int_distribution<uint32_t>(0, 0xFFFFFFFFu)(rng);
    return ret;
}

std::string GenerateRandomID16()
{
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
    std::string id;
    id.reserve(16);
    for (int i = 0; i < 16; ++i)
    {
        id.push_back(charset[dist(rng)]);
    }
    return id;
}

std::string GenerateRandomHexKey(size_t hexLen)
{
    static const char hexChars[] = "0123456789ABCDEF";
    std::string key;
    key.reserve(hexLen);
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, 15);
    for (size_t i = 0; i < hexLen; ++i)
    {
        key.push_back(hexChars[dist(rng)]);
    }
    return key;
}

std::vector<uint8_t> EncryptDataRaw(const std::vector<uint8_t> &plain, std::string key)
{
    std::vector<uint8_t> Key = HexToBytes(key);
    const size_t KeyLen = Key.size();
    const size_t PlainLen = plain.size();

    uint32_t A = Rand32();
    uint32_t B = Rand32();
    uint32_t AndValue = ~(A ^ B);

    std::vector<uint8_t> out(8 + PlainLen);
    memcpy(&out[0], &A, 4);
    memcpy(&out[4], &B, 4);

    uint8_t KeyTime[4];
    memcpy(KeyTime, &B, 4);

    uint8_t TimeKey[4];
    for (int i = 0; i < 4; ++i)
        TimeKey[i] = static_cast<uint8_t>(KeyTime[i] ^ static_cast<uint8_t>(AndValue));

    uint8_t finalKeyXor = 0;
    uint32_t currentIdx = 0;
    for (size_t i = 0; i < KeyLen; ++i)
    {
        if (currentIdx >= 4) currentIdx = 0;
        Key[i] ^= KeyTime[currentIdx];
        finalKeyXor ^= Key[i];
        currentIdx++;
    }

    const uint8_t *pPlain = plain.data();
    uint8_t *pOut = &out[8];

    for (size_t i = 0; i < PlainLen; ++i)
    {
        if (currentIdx >= 4) currentIdx = 0;
        pOut[i] = pPlain[i] ^ TimeKey[currentIdx] ^ finalKeyXor;
        currentIdx++;
    }

    return out;
}

std::string EncryptDataHex(const std::string &plainHex, std::string key)
{
    std::vector<uint8_t> plain = HexToBytes(plainHex);
    std::vector<uint8_t> enc = EncryptDataRaw(plain, key);
    std::string ret = BytesToHex(enc);
    return ret;
}

std::vector<uint8_t> DecryptDataRaw(const std::vector<uint8_t> &enc, std::string key)
{
    if (enc.size() < 8)
    {
        return {};
    }

    uint32_t A, B;
    memcpy(&A, &enc[0], 4);
    memcpy(&B, &enc[4], 4);

    uint32_t AndValue = ~(A ^ B);
    uint8_t KeyTime[4];
    memcpy(KeyTime, &B, 4);

    uint8_t TimeKey[4];
    for (int i = 0; i < 4; ++i)
        TimeKey[i] = static_cast<uint8_t>(KeyTime[i] ^ static_cast<uint8_t>(AndValue));

    std::vector<uint8_t> Key = HexToBytes(key);
    const size_t KeyLen = Key.size();
    uint8_t finalKeyXor = 0;

    for (size_t i = 0; i < KeyLen; ++i)
    {
        Key[i] ^= KeyTime[i % 4];
        finalKeyXor ^= Key[i];
    }

    uint32_t idx = static_cast<uint32_t>(KeyLen % 4);
    const size_t ct_len = enc.size() - 8;
    std::vector<uint8_t> plain(ct_len);

    const uint8_t *pSrc = &enc[8];
    uint8_t *pDst = &plain[0];

    for (size_t i = 0; i < ct_len; ++i)
    {
        if (idx >= 4) idx = 0;
        pDst[i] = pSrc[i] ^ finalKeyXor ^ TimeKey[idx++];
    }

    return plain;
}

std::string DecryptDataHex(const std::string &encHex, std::string key)
{
    std::vector<uint8_t> enc = HexToBytes(encHex);
    std::vector<uint8_t> plain = DecryptDataRaw(enc, key);
    std::string ret = BytesToHex(plain);
    return ret;
}

// ============================================================
// 3. 进程权限与文件安全操作
// ============================================================

bool EnablePrivilege(LPCSTR privName)
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return false;
    }
    if (!LookupPrivilegeValueA(NULL, privName, &luid))
    {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    bool ret = result && (GetLastError() == ERROR_SUCCESS);
    return ret;
}

bool EnableDebugPrivilege()
{
    bool hasDebug = EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_LOAD_DRIVER_NAME);
    return hasDebug;
}

bool IsFileInUseA(const std::string &filePath)
{
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();
        if (error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED)
        {
            return true;
        }
        return false;
    }
    CloseHandle(hFile);
    return false;
}

std::wstring WriteFileToDirectory(const std::wstring &targetDir, const std::wstring &filename, const std::vector<uint8_t> &data)
{
    namespace fs = std::filesystem;
    try
    {
        if (!fs::exists(targetDir))
        {
            fs::create_directories(targetDir);
        }
        fs::path fullPath = fs::path(targetDir) / filename;
        FILE *fp = nullptr;
        if (_wfopen_s(&fp, fullPath.c_str(), L"wb") != 0 || !fp)
        {
            return L"";
        }
        if (!data.empty())
        {
            fwrite(data.data(), 1, data.size(), fp);
        }
        fclose(fp);
        std::wstring ret = fullPath.wstring();
        return ret;
    }
    catch (const std::exception &)
    {
        return L"";
    }
}

// ============================================================
// 4. 内核驱动服务部署与激活 (DeployKernelDriver)
// ============================================================

static void StopAndRemoveDriverService(const wchar_t *serviceName)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
        return;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (hService)
    {
        SERVICE_STATUS status = {};
        ControlService(hService, SERVICE_CONTROL_STOP, &status);
        for (int i = 0; i < 30; ++i)
        {
            if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_STOPPED)
                break;
            Sleep(100);
        }
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCM);
}

bool LoadKernelDriverService(const std::wstring &serviceName, const std::wstring &driverPath, std::string &failReason)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    }
    if (!hSCM)
    {
        DWORD dwErr = GetLastError();
        failReason = "OpenSCManager Failed: " + std::to_string(dwErr);
        DBG("OpenSCManager failed err=%lu", dwErr);
        return false;
    }

    const wchar_t *displayName = (serviceName == DRIVER_SPOOF_SERVICE_NAME) ? DRIVER_SPOOF_DISPLAY_NAME : serviceName.c_str();
    const wchar_t *loadGroup = (serviceName == DRIVER_SPOOF_SERVICE_NAME) ? DRIVER_SPOOF_LOAD_GROUP : nullptr;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!hService)
    {
        hService = CreateServiceW(
            hSCM,
            serviceName.c_str(),
            displayName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath.c_str(),
            loadGroup,
            nullptr, nullptr, nullptr, nullptr
        );

        if (!hService)
        {
            DWORD dwErr = GetLastError();
            failReason = "CreateService Failed: " + std::to_string(dwErr);
            DBG("CreateService %ls failed err=%lu", serviceName.c_str(), dwErr);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    else
    {
        ChangeServiceConfigW(
            hService,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath.c_str(),
            loadGroup,
            nullptr, nullptr, nullptr, nullptr,
            displayName
        );
    }

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
    {
        if (ssp.dwCurrentState == SERVICE_RUNNING)
        {
            // 若为 Machenike 白驱动且已在运行，可直接复用；若为核心驱动服务，必须确保重启以重建自毁过的 \Device\MsNetEndpoint
            if (serviceName == L"Machenike")
            {
                DBG("Service %ls already running", serviceName.c_str());
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCM);
                return true;
            }
            SERVICE_STATUS stopSt = {};
            ControlService(hService, SERVICE_CONTROL_STOP, &stopSt);
            for (int i = 0; i < 30; ++i)
            {
                if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded) &&
                    ssp.dwCurrentState == SERVICE_STOPPED)
                {
                    break;
                }
                Sleep(100);
            }
        }
    }

    if (!StartServiceW(hService, 0, nullptr))
    {
        DWORD dwErr = GetLastError();
        if (dwErr != ERROR_SERVICE_ALREADY_RUNNING)
        {
            failReason = "StartService Failed: " + std::to_string(dwErr);
            DBG("StartService %ls failed err=%lu", serviceName.c_str(), dwErr);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    DBG("[DriverService] SCM kernel service loaded and started successfully: %ls", serviceName.c_str());
    return true;
}

bool DeployKernelDriver(std::string &failReason, int connectMode, int driverMode, uint16_t port, const uint8_t token[16])
{
    VMProtectBeginUltra("DeployKernelDriver");
    DBG("[DriverDeploy] Starting kernel driver deployment (DriverMode=%d, 1=Service, 2=PTE-Remap, ConnectMode=%d, Port=%u)...", driverMode, connectMode, port);

    if (!EnableDebugPrivilege())
    {
        failReason = "error.privilege_escalation_failed";
        DBG("[DriverDeploy] Failed to enable SeDebugPrivilege!");
        // Unified reporting at ProcessDriverStart
        VMProtectEnd();
        return false;
    }
    DBG("[DriverDeploy] SeDebugPrivilege acquired successfully");

    std::vector<uint8_t> shellcode = HexToBytes(gVar.leech_shellcode_hex);
    if (shellcode.empty())
    {
        failReason = "error.restart_host_and_program";
        DBG("[DriverDeploy] Leech core driver payload is empty!");
        // Unified reporting at ProcessDriverStart
        VMProtectEnd();
        return false;
    }

    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    namespace fs = std::filesystem;
    fs::path driverDir = fs::path(sysDir) / L"drivers";

    // ==== 核心驱动模式判断：1=正常服务加载(只释放核心驱动), 2=内存映射(核心驱动不落地纯内存映射，只释放白驱动) ====
    if (driverMode == 1)
    {
        // 先停止并移除可能残留的旧服务实例（防止上次激活已自毁 \Device\MsNetEndpoint 导致重试时 Error 3）
        StopAndRemoveDriverService(L"mswsk");
        StopAndRemoveDriverService(DRIVER_SPOOF_SERVICE_NAME);

        // 模式 1 (正常加载)：优先释放核心驱动 i225v.sys；若宿主主板存在真实 Intel I225-V 网卡占用 i225v.sys，自动回退至 mswsk.sys
        std::wstring targetServiceName = DRIVER_SPOOF_SERVICE_NAME;
        std::wstring targetFileName = DRIVER_SPOOF_FILENAME;
        fs::path coreDriverPath = driverDir / targetFileName;

        if (fs::exists(coreDriverPath) && IsFileInUseA(coreDriverPath.string()))
        {
            DBG("[DriverDeploy] %ls is locked by active system driver (real Intel I225-V NIC), falling back to mswsk.sys",
                coreDriverPath.wstring().c_str());
            targetServiceName = L"mswsk";
            targetFileName = L"mswsk.sys";
            coreDriverPath = driverDir / targetFileName;
        }

        DBG("[DriverDeploy] Mode 1 (NormalService): Writing core driver: %ls (size: %zu bytes)", coreDriverPath.wstring().c_str(), shellcode.size());
        if (!fs::exists(coreDriverPath) || !IsFileInUseA(coreDriverPath.string()))
        {
            try { fs::remove(coreDriverPath); } catch (...) {}
            WriteFileToDirectory(driverDir.wstring(), targetFileName, shellcode);
        }

        if (!LoadKernelDriverService(targetServiceName, coreDriverPath.wstring(), failReason))
        {
            SecureWipeContainer(shellcode);
            DBG("[DriverDeploy] Failed to load %ls service: %s", targetServiceName.c_str(), failReason.c_str());
            // Unified reporting at ProcessDriverStart
            VMProtectEnd();
            return false;
        }
    }
    else
    {
        // 模式 2 (内存映射)：核心驱动不落地磁盘 (纯内存映射)，只释放白驱动 Machenike.sys
        DBG("[DriverDeploy] Mode %d (MemoryMapped): Core driver will be mapped purely in memory (no disk drop).", driverMode);

        std::vector<uint8_t> shellcode_driver = HexToBytes(gVar.leech_driver_shellcode_hex);
        if (shellcode_driver.empty())
        {
            failReason = "error.restart_host_and_program";
            DBG("[DriverDeploy] White driver payload is empty for Mode %d!", driverMode);
            // Unified reporting at ProcessDriverStart
            VMProtectEnd();
            return false;
        }

        // 仅释放并加载 Machenike.sys 白驱动
        fs::path whiteDriverPath = driverDir / L"Machenike.sys";
        DBG("[DriverDeploy] Mode %d (MemoryMapped): Writing white driver only: %ls (size: %zu bytes)", driverMode, whiteDriverPath.wstring().c_str(), shellcode_driver.size());
        if (!fs::exists(whiteDriverPath) || !IsFileInUseA(whiteDriverPath.string()))
        {
            try { fs::remove(whiteDriverPath); } catch (...) {}
            WriteFileToDirectory(driverDir.wstring(), L"Machenike.sys", shellcode_driver);
        }

        if (!LoadKernelDriverService(L"Machenike", whiteDriverPath.wstring(), failReason))
        {
            DBG("[DriverDeploy] Failed to load Machenike service: %s", failReason.c_str());
            // Unified reporting at ProcessDriverStart
            VMProtectEnd();
            return false;
        }

        // 执行核心驱动纯内存映射 (Code Cave & Kernel PTE Remap, 0 次磁盘落地)
        DBG("[DriverDeploy] Mode %d: Initiating in-memory Code Cave manual mapping for core driver (%zu bytes)...", driverMode, shellcode.size());

        DRV_BOOT_CONFIG bootConfig = {};
        bootConfig.Magic = DRV_BOOT_CONFIG_MAGIC;
        bootConfig.TransportMode = (connectMode == DRV_TRANSPORT_RAW_ETH) ? DRV_TRANSPORT_RAW_ETH : ((connectMode == DRV_TRANSPORT_USB) ? DRV_TRANSPORT_USB : ((connectMode == DRV_TRANSPORT_UDP) ? DRV_TRANSPORT_UDP : DRV_TRANSPORT_TCP));
        bootConfig.Port = port;
        bootConfig.AuthToken = 0;
        bootConfig.Flags = gVar.enable_delete_loader ? DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP : 0;
        if (token)
        {
            memcpy(bootConfig.SessionToken, token, 16);
        }

        DBG("[DriverDeploy] Mode %d: Resolved transport config from parameters: Mode=%u, Port=%u",
            driverMode, bootConfig.TransportMode, bootConfig.Port);

        bool mapOk = MapDriverViaCave(shellcode, L"Machenike.sys", L"nvlddmkm.sys", false, &bootConfig, &failReason);
        if (!mapOk)
        {
            SecureWipeContainer(shellcode);
            SecureWipeContainer(shellcode_driver);
            DBG("[DriverDeploy] Mode %d: MapDriverViaCave failed! Reason: %s", driverMode, failReason.c_str());
            // Unified reporting at ProcessDriverStart
            VMProtectEnd();
            return false;
        }

        SecureWipeContainer(shellcode_driver);
        DBG("[DriverDeploy] Mode %d: Core driver successfully mapped and initialized in kernel.", driverMode);
    }

    SecureWipeContainer(shellcode);

    DBG("[DriverDeploy] Kernel driver deployed successfully (mode=%d)", driverMode);
    VMProtectEnd();
    return true;
}

#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        v0 += v1;                                                                                                      \
        v1 = ROTL64(v1, 13);                                                                                           \
        v1 ^= v0;                                                                                                      \
        v0 = ROTL64(v0, 32);                                                                                           \
        v2 += v3;                                                                                                      \
        v3 = ROTL64(v3, 16);                                                                                           \
        v3 ^= v2;                                                                                                      \
        v0 += v3;                                                                                                      \
        v3 = ROTL64(v3, 21);                                                                                           \
        v3 ^= v0;                                                                                                      \
        v2 += v1;                                                                                                      \
        v1 = ROTL64(v1, 17);                                                                                           \
        v1 ^= v2;                                                                                                      \
        v2 = ROTL64(v2, 32);                                                                                           \
    } while (0)

uint64_t CalculateExpectedDriverSignature(const uint8_t token[16])
{
    volatile uint64_t maskA = 0x55AA55AA55AA55AAULL;
    volatile uint64_t maskB = 0xAA55AA55AA55AA55ULL;
    uint64_t k0 = 0x72446C656E72654BULL ^ maskA;
    uint64_t k1 = 0x79654B6874754176ULL ^ maskB;
    k0 ^= maskA;
    k1 ^= maskB;
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    RtlSecureZeroMemory(&k0, sizeof(k0));
    RtlSecureZeroMemory(&k1, sizeof(k1));
    const uint8_t *end = token + 16;
    uint64_t m = 0;
    for (const uint8_t *p = token; p != end; p += 8)
    {
        m = *(const uint64_t *)(p);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }
    uint64_t b = ((uint64_t)16) << 56;
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static inline uint64_t SipHash24_Loader(const uint8_t key[16], const uint8_t *msg, size_t msgLen)
{
    uint64_t k0 = *(const uint64_t *)(key);
    uint64_t k1 = *(const uint64_t *)(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    size_t i = 0;
    while (i + 8 <= msgLen)
    {
        uint64_t m = *(const uint64_t *)(msg + i);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
        i += 8;
    }
    uint64_t b = ((uint64_t)msgLen) << 56;
    size_t left = msgLen & 7;
    for (size_t j = left - 1; j < left; j--)
        b |= ((uint64_t)msg[i + j]) << (j * 8);
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

// 计算用于通过驱动 MachenikeDispatchCreate 动态鉴权的 Token（对齐 drv/Main.cpp MachenikeCalcToken）
static inline uint32_t CalcDeviceToken(uint64_t counter, uint32_t pid)
{
    static const uint8_t s_SipHashKey[16] = {
        0x21, 0x7A, 0xA9, 0x3C, 0x10, 0x55, 0xD2, 0x6F,
        0x9B, 0x4E, 0x01, 0x88, 0xC7, 0x33, 0xFA, 0x90
    };
    static const uint32_t s_Salt4 = 0x4D43484EU; // 'MCHN'

    uint8_t msg[16] = {};
    memcpy(msg, &counter, 8);
    memcpy(msg + 8, &pid, 4);
    memcpy(msg + 12, &s_Salt4, 4);
    uint64_t h = SipHash24_Loader(s_SipHashKey, msg, sizeof(msg));
    return (uint32_t)(h ^ (h >> 32));
}

__declspec(align(16)) static DRV_USER_PAYLOAD_ANCHOR g_UserAnchor = {};

static void Host_Rc4Crypt(uint8_t *data, uint32_t len, const uint8_t *key, uint32_t keyLen)
{
    uint8_t S[256];
    for (uint32_t i = 0; i < 256; i++) S[i] = (uint8_t)i;
    uint32_t j = 0;
    for (uint32_t i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) & 0xFF;
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    uint32_t i = 0;
    j = 0;
    for (uint32_t k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

static uint32_t Host_CalcAdler32(const uint8_t *data, size_t len)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

static void SetupUserPayloadAnchor(uint32_t devToken, const DRV_BOOT_CONFIG_EX &cfgEx)
{
    static const uint8_t s_SipHashKey[16] = {
        0x21, 0x7A, 0xA9, 0x3C, 0x10, 0x55, 0xD2, 0x6F,
        0x9B, 0x4E, 0x01, 0x88, 0xC7, 0x33, 0xFA, 0x90
    };
    g_UserAnchor.Tag0 = SipHash24_Loader(s_SipHashKey, (const uint8_t *)&devToken, sizeof(devToken));
    g_UserAnchor.Tag1 = ~g_UserAnchor.Tag0 ^ 0xA5A5A5A55A5A5A5AULL;
    g_UserAnchor.Nonce = (uint32_t)__rdtsc();
    g_UserAnchor.CipherLen = sizeof(DRV_BOOT_CONFIG_EX);
    g_UserAnchor.Checksum = Host_CalcAdler32((const uint8_t *)&cfgEx, sizeof(DRV_BOOT_CONFIG_EX));
    g_UserAnchor.Reserved = 0;

    uint8_t key[24];
    memcpy(&key[0], s_SipHashKey, 16);
    memcpy(&key[16], &devToken, 4);
    memcpy(&key[20], &g_UserAnchor.Nonce, 4);

    memcpy(g_UserAnchor.CipherData, &cfgEx, sizeof(DRV_BOOT_CONFIG_EX));
    Host_Rc4Crypt(g_UserAnchor.CipherData, sizeof(DRV_BOOT_CONFIG_EX), key, sizeof(key));
}

bool VerifyAndActivateDriver(std::string &failReason, int transportMode, int port, const uint8_t token[16], uint16_t &outPort)
{
    VMProtectBeginUltra("VerifyAndActivateDriver");
    DBG("[DriverActivation] Connecting to device \\\\.\\MsNetEndpoint (transportMode=%d, port=%d)...", transportMode, port);
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    uint32_t pid = GetCurrentProcessId();

    DRV_BOOT_CONFIG_EX cfgEx = {};
    cfgEx.Base.Magic = DRV_BOOT_CONFIG_MAGIC;
    cfgEx.Base.TransportMode = (transportMode >= 2 && transportMode <= 5) ? (uint32_t)transportMode : DRV_TRANSPORT_TCP; // 默认 2: WSK_TCP
    cfgEx.Base.Port = (uint16_t)port;
    cfgEx.Base.Flags = gVar.enable_delete_loader ? DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP : 0;
    if (token)
    {
        memcpy(cfgEx.Base.SessionToken, token, 16);
    }
    GetModuleFileNameW(NULL, cfgEx.HostLoaderPath, 260);
    if (!gVar.api_url.empty())
        strncpy_s(cfgEx.ApiUrl, gVar.api_url.c_str(), _TRUNCATE);
    else if (!Environment::Current.api.empty())
        strncpy_s(cfgEx.ApiUrl, Environment::Current.api.c_str(), _TRUNCATE);
    else
        strncpy_s(cfgEx.ApiUrl, "https://112.5.37.106:1234", _TRUNCATE);

    if (!gVar.login_url.empty())
        strncpy_s(cfgEx.LoginUrl, gVar.login_url.c_str(), _TRUNCATE);
    else if (!Environment::Current.login_url.empty())
        strncpy_s(cfgEx.LoginUrl, Environment::Current.login_url.c_str(), _TRUNCATE);
    else
        strncpy_s(cfgEx.LoginUrl, "https://112.5.37.106:1234", _TRUNCATE);

    if (!gVar.report_url.empty())
        strncpy_s(cfgEx.ReportUrl, gVar.report_url.c_str(), _TRUNCATE);
    else if (!Environment::Current.report.empty())
        strncpy_s(cfgEx.ReportUrl, Environment::Current.report.c_str(), _TRUNCATE);
    else
        strncpy_s(cfgEx.ReportUrl, "https://112.5.37.106:1236", _TRUNCATE);

    if (!gVar.brand_version.empty())
        strncpy_s(cfgEx.BrandVersion, gVar.brand_version.c_str(), _TRUNCATE);
    if (!gVar.selected_game.empty())
        strncpy_s(cfgEx.SelectedGame, gVar.selected_game.c_str(), _TRUNCATE);
    if (!gVar.client_version.empty())
        strncpy_s(cfgEx.ClientVersion, gVar.client_version.c_str(), _TRUNCATE);
    if (!gVar.slogin_data.card_key.empty())
        strncpy_s(cfgEx.CardKey, gVar.slogin_data.card_key.c_str(), _TRUNCATE);

    // 1. 根据系统时间计算动态 Token，并建立加密用户态内存锚点（单次打开：内核 ValidateToken 已自带 ±1 容差，禁止循环重试多次打开驱动）
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t ft64 = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t sec = ft64 / 10000000ULL;
    if (sec >= 11644473600ULL)
        sec -= 11644473600ULL;
    uint64_t counter = sec / 30ULL;

    uint32_t devToken = CalcDeviceToken(counter, pid);
    SetupUserPayloadAnchor(devToken, cfgEx);

    DWORD lastErr = ERROR_PATH_NOT_FOUND;
    wchar_t pathSym[128];
    swprintf_s(pathSym, L"\\\\.\\MsNetEndpoint\\%08X", devToken);
    hDevice = CreateFileW(pathSym, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        lastErr = GetLastError();
        // 仅当 DosDevices 符号链接本身不存在 (ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND / ERROR_INVALID_NAME) 时，
        // 才回退尝试 GLOBALROOT\Device 原始路径（此时先前请求尚未进入驱动 DispatchCreate）
        if (lastErr == ERROR_FILE_NOT_FOUND || lastErr == ERROR_PATH_NOT_FOUND || lastErr == ERROR_INVALID_NAME)
        {
            SetupUserPayloadAnchor(devToken, cfgEx);
            wchar_t pathPlain[128];
            swprintf_s(pathPlain, L"\\\\?\\GLOBALROOT\\Device\\MsNetEndpoint\\%08X", devToken);
            hDevice = CreateFileW(pathPlain, GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (hDevice == INVALID_HANDLE_VALUE)
            {
                lastErr = GetLastError();
            }
        }
    }
    else
    {
        DBG("[DriverActivation] Opened with encrypted memory anchor successfully (token: 0x%08X)", devToken);
    }

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        DBG("[DriverActivation] Failed to open \\\\.\\MsNetEndpoint with token, GetLastError=%lu -> stopping & removing driver service", lastErr);
        StopAndRemoveDriverService(DRIVER_SPOOF_SERVICE_NAME);
        StopAndRemoveDriverService(L"mswsk");
        failReason = "OpenDevice Failed: " + std::to_string(lastErr);
        VMProtectEnd();
        return false;
    }

    CloseHandle(hDevice);
    outPort = (port > 0) ? (uint16_t)port : 44560;
    DBG("[DriverActivation] Driver transport layer activated via CreateFile memory anchor! BoundPort: %u", outPort);
    VMProtectEnd();
    return true;
}

// ============================================================
// 5. 控制台日志与界面高亮
// ============================================================

static void SetColor(WORD color)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

static void PrintErrorTag()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(h, &info);
    WORD old = info.wAttributes;
    WORD color = BACKGROUND_RED | BACKGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    SetColor(color);
    std::cout << "[ERROR]";
    SetColor(old);
}

static void PrintInfoTag()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(h, &info);
    WORD old = info.wAttributes;
    WORD color = BACKGROUND_BLUE | BACKGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    SetColor(color);
    std::cout << "[INFO]";
    SetColor(old);
}

static void PrintSuccessTag()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(h, &info);
    WORD old = info.wAttributes;
    WORD color = BACKGROUND_GREEN | BACKGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    SetColor(color);
    std::cout << "[SUCCESS]";
    SetColor(old);
}

static void PrintDebugTag()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(h, &info);
    WORD old = info.wAttributes;
    WORD color = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; // 亮青色
    SetColor(color);
    std::cout << "[DEBUG]";
    SetColor(old);
}

std::string getCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    if (localtime_s(&tm, &now_time_t) != 0)
    {
        return "";
    }
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    std::string ret = oss.str();
    return ret;
}

void ConsoleLog(std::string text, ULONG level)
{
    static bool consoleInitialized = false;
    if (!consoleInitialized)
    {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        consoleInitialized = true;
    }

    std::cout << "\r\n" << "[" + getCurrentTime() + "]  ";
    switch (level)
    {
    case Log_Success:
        PrintSuccessTag();
        break;
    case Log_Error:
        PrintErrorTag();
        break;
    case Log_Info:
        PrintInfoTag();
        break;
    case Log_Debug:
        PrintDebugTag();
        break;
    default:
        break;
    }
    std::cout << "  " << text << std::endl;
}

void DbgLog(const char *fmt, ...)
{
#if ENABLE_LOADER_DBG
    char _buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(_buf, sizeof(_buf), fmt, args);
    va_end(args);

    OutputDebugStringA(_buf);
    ConsoleLog(_buf, Log_Debug);
#endif
}

std::string GetHostPhysicalMacAddresses()
{
    std::vector<std::string> macList;
    HMODULE hIpHlp = LoadLibraryA("iphlpapi.dll");
    if (!hIpHlp)
    {
        return "";
    }

    typedef ULONG(WINAPI *fn_GetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
    fn_GetAdaptersAddresses pGetAdaptersAddresses = (fn_GetAdaptersAddresses)GetProcAddress(hIpHlp, "GetAdaptersAddresses");

    if (pGetAdaptersAddresses)
    {
        ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        ULONG outBufLen = 15000;
        PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
        if (pAddresses)
        {
            DWORD dwRet = pGetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
            if (dwRet == ERROR_BUFFER_OVERFLOW)
            {
                free(pAddresses);
                pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
                if (pAddresses)
                {
                    dwRet = pGetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
                }
            }

            if (dwRet == NO_ERROR && pAddresses)
            {
                for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr; pCurr = pCurr->Next)
                {
                    if (pCurr->PhysicalAddressLength != 6)
                        continue;

                    if (pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK || pCurr->IfType == IF_TYPE_TUNNEL)
                        continue;

                    if (pCurr->IfType != IF_TYPE_ETHERNET_CSMACD && pCurr->IfType != IF_TYPE_IEEE80211)
                        continue;

                    const BYTE *mac = pCurr->PhysicalAddress;
                    if ((mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0) ||
                        (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF && mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF) ||
                        (mac[0] & 1))
                    {
                        continue;
                    }

                    std::wstring desc = pCurr->Description ? pCurr->Description : L"";
                    std::wstring friendly = pCurr->FriendlyName ? pCurr->FriendlyName : L"";
                    std::string combo = wStrToStr(desc + L" " + friendly);
                    std::transform(combo.begin(), combo.end(), combo.begin(), ::tolower);

                    static const char *virtualKeywords[] = {
                        "virtual", "vmware", "hyper-v", "vbox", "virtualbox",
                        "wsl", "tap-", "wintun", "zerotier", "npcap",
                        "loopback", "vpn", "pseudo", "bluetooth", "wan miniport",
                        "teredo", "isatap", "ndiswan", "tailscale", "wireguard",
                        "clash", "veth", "docker", "pcap", "host-only", "sangfor"
                    };

                    bool isVirtual = false;
                    for (const char *kw : virtualKeywords)
                    {
                        if (combo.find(kw) != std::string::npos)
                        {
                            isVirtual = true;
                            break;
                        }
                    }
                    if (isVirtual) continue;

                    char szMac[32];
                    sprintf_s(szMac, "%02X:%02X:%02X:%02X:%02X:%02X",
                              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    std::string macStr(szMac);

                    if (std::find(macList.begin(), macList.end(), macStr) == macList.end())
                    {
                        if (pCurr->IfType == IF_TYPE_ETHERNET_CSMACD && pCurr->OperStatus == IfOperStatusUp)
                        {
                            macList.insert(macList.begin(), macStr);
                        }
                        else
                        {
                            macList.push_back(macStr);
                        }
                    }
                }
            }

            if (pAddresses) free(pAddresses);
        }
    }

    FreeLibrary(hIpHlp);

    std::string result;
    for (size_t i = 0; i < macList.size(); ++i)
    {
        if (i > 0) result += ",";
        result += macList[i];
    }
    return result;
}

