#pragma once

// ============================================================
// 宿主加载器版本号宏 (异常上报时自动附带此版本号，便于区分线上客户端加载器构建版本)
// ============================================================
#ifndef HOST_LOADER_VERSION
#define HOST_LOADER_VERSION "1.0.2"
#endif
#ifndef LOADER_VERSION_STR
#define LOADER_VERSION_STR HOST_LOADER_VERSION
#endif

// ============================================================
// 调试日志总开关与宏定义 (DBG 开关宏)
// 1 = 启用详细流程调试日志（同时输出至控制台与 DebugView）
// 0 = 关闭调试日志（完全静默调试输出，仅保留关键业务日志）
// ============================================================
#ifndef ENABLE_LOADER_DBG
#define ENABLE_LOADER_DBG 0
#endif

#define Log_Success 1
#define Log_Error 0
#define Log_Info 2
#define Log_Debug 3

void DbgLog(const char *fmt, ...);

#if ENABLE_LOADER_DBG
#define DBG(fmt, ...) DbgLog(fmt, ##__VA_ARGS__)
#else
#define DBG(...)                                                                                                                                                                                       \
    do                                                                                                                                                                                                 \
    {                                                                                                                                                                                                  \
    } while (0)
#endif

// 若有头文件间接包含 winsock.h，阻止它（确保只用 winsock2）
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#ifndef NOMINMAX
#define NOMINMAX // 避免 <windows.h> 定义 min/max 宏
#endif

#define cheat_version 1.0
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS

// ---------- Intel 网卡驱动伪装规范常量 (对齐 MainDrv) ----------
#define DRIVER_SPOOF_SERVICE_NAME    L"i225v"
#define DRIVER_SPOOF_DISPLAY_NAME    L"Intel I225-V/I226 NDIS Miniport Driver"
#define DRIVER_SPOOF_LOAD_GROUP      L"NDIS"
#define DRIVER_SPOOF_FILENAME        L"i225v.sys"

// ---------- C++ Standard Library ----------
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// ---------- Sockets / Networking ----------
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

// ---------- Windows Base ----------
#include <psapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winioctl.h>


#undef max

// ---------- Third-party & Utils ----------
#include "byte_utils.hpp"
#include "json.hpp"
#include "language.h"
#include "VMProtectSDK.h"


// ---------- Pragmas: link libraries removed for zero IAT ----------

// ============================================================
// 核心数据模型与上下文
// ============================================================

struct login_data
{
    ULONGLONG expired_time = 0;
    std::string client_signature;
    std::string card_key;
    std::string encrypt_key;
    std::string encrypted_hex;
};

struct global_var
{
    bool bLogged = false;
    std::string app_id;
    std::string dynamic_key;
    std::string clientIP;
    std::string curAppVersion;
    std::string brand_version;
    std::string selected_game;
    std::string client_version;
    std::string encrypted_key_static;

    login_data slogin_data;

    // 驱动与载荷
    std::string game_shellcode_hex;
    std::string leech_shellcode_hex;
    std::string leech_driver_shellcode_hex;
    std::string shellcode_extra_data;

    int driver_mode = 1;     // 驱动模式: 1=正常服务加载(i225v), 2=白驱动PTE原位内存映射(Machenike)
    int connection_mode = 1; // 连接模式: 1=DMA, 2=TCP, 3=UDP, 4=USB
    std::string connection_port;

    std::string api_url;
    std::string login_url;
    std::string report_url;

    bool enable_delete_loader = true; // 传入驱动的启动特性开关：是否在上线后自粉碎删除宿主 Loader
};

extern global_var gVar;

struct ServerConfig
{
    std::string api;
    std::string report;
    std::string api_url;
    std::string login_url;
    std::string report_url;
};

namespace Environment
{
extern ServerConfig Current;
}

// ============================================================
// 工具函数声明 (精简纯净)
// ============================================================

// 1. 字符串与编解码
std::string BytesToHex_char(const uint8_t *p, size_t n);
std::vector<uint8_t> HexToBytes(const std::string &hex);
std::string BytesToHex(const std::vector<uint8_t> &data);
std::wstring strTowStr(const std::string &utf8);
std::string wStrToStr(std::wstring wstr);
void StrlTrimCrlf(std::string &s);
bool isHexString(const std::string &s);

// 2. 随机数与数据流加解密
uint32_t Rand32();
std::string GenerateRandomID16();
std::string GenerateRandomHexKey(size_t hexLen = 32);
std::vector<uint8_t> EncryptDataRaw(const std::vector<uint8_t> &plain, std::string key);
std::string EncryptDataHex(const std::string &plainHex, std::string key);
std::vector<uint8_t> DecryptDataRaw(const std::vector<uint8_t> &enc, std::string key);
std::string DecryptDataHex(const std::string &encHex, std::string key);

// 3. 进程权限与文件安全操作
bool EnablePrivilege(LPCSTR privName);
bool EnableDebugPrivilege();
bool IsFileInUseA(const std::string &filePath);
std::wstring WriteFileToDirectory(const std::wstring &targetDir, const std::wstring &filename, const std::vector<uint8_t> &data);

template <typename T> inline void SecureWipeContainer(T &container)
{
    if (!container.empty())
    {
        RtlSecureZeroMemory(&container[0], container.size() * sizeof(container[0]));
        container.clear();
    }
}

// 4. 内核驱动服务部署与激活 (DeployKernelDriver)
bool LoadKernelDriverService(const std::wstring &serviceName, const std::wstring &driverPath, std::string &failReason);
bool DeployKernelDriver(std::string &failReason, int connectMode = 0, int driverMode = 1, uint16_t port = 0, const uint8_t token[16] = nullptr);
uint64_t CalculateExpectedDriverSignature(const uint8_t token[16]);
bool VerifyAndActivateDriver(std::string &failReason, int transportMode, int port, const uint8_t token[16], uint16_t &outPort);

// 5. 控制台日志
std::string getCurrentTime();
void ConsoleLog(std::string text, ULONG level);
std::string GetHostPhysicalMacAddresses();

#include "report.h"

#define LC_WINAPI_NO_IMPORT_TABLE
#include "lc_winapi.h"
