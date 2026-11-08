#include "common.h"
#include "report.h"
#include "protocol.h"
#include <winhttp.h>
#include <mutex>
#include <thread>
#include <cstdarg>

// 标准上报通信加解密密钥 (与 CheatDrv / keySaleSystem /api/tg 契约完全对齐)
static const char *const REPORT_SECRET_KEY = "135D03095D2743445D";

// WinHTTP 动态 API 函数指针定义 (保持 Zero IAT 隐蔽性与跨平台免依赖)
typedef HINTERNET(WINAPI *pfnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI *pfnWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI *pfnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL(WINAPI *pfnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI *pfnWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL(WINAPI *pfnWinHttpCloseHandle)(HINTERNET);
typedef BOOL(WINAPI *pfnWinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI *pfnWinHttpSetTimeouts)(HINTERNET, int, int, int, int);
typedef BOOL(WINAPI *pfnWinHttpCrackUrl)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);

// 去重频控表 (对齐 CheatDrv 16 槽循环指纹去重机制)
#define REPORT_DEDUP_SLOTS 16
struct DEDUP_ENTRY
{
    uint64_t Hash;
    ULONGLONG LastTimeMs;
};
static DEDUP_ENTRY s_DedupTable[REPORT_DEDUP_SLOTS] = {};
static std::mutex s_DedupMutex;
static uint32_t s_DedupSlotIndex = 0;

uint64_t Reporter::ComputeFingerprint(const char *cardKey, const char *functionName, uint32_t status)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    if (cardKey)
    {
        for (const char *p = cardKey; *p; ++p)
        {
            h ^= static_cast<uint8_t>(*p);
            h *= 0x100000001b3ULL;
        }
    }
    if (functionName)
    {
        for (const char *p = functionName; *p; ++p)
        {
            h ^= static_cast<uint8_t>(*p);
            h *= 0x100000001b3ULL;
        }
    }
    h ^= status;
    h *= 0x100000001b3ULL;
    return h;
}

bool Reporter::ShouldReport(uint64_t fingerprint, uint32_t intervalMs)
{
    std::lock_guard<std::mutex> lock(s_DedupMutex);
    ULONGLONG now = GetTickCount64();

    for (int i = 0; i < REPORT_DEDUP_SLOTS; i++)
    {
        if (s_DedupTable[i].Hash == fingerprint)
        {
            if (now - s_DedupTable[i].LastTimeMs < intervalMs)
            {
                return false;
            }
            s_DedupTable[i].LastTimeMs = now;
            return true;
        }
    }

    uint32_t slot = (s_DedupSlotIndex++) & (REPORT_DEDUP_SLOTS - 1);
    s_DedupTable[slot].Hash = fingerprint;
    s_DedupTable[slot].LastTimeMs = now;
    return true;
}

const char *Reporter::GetStatusSemantic(uint32_t status)
{
    const char *result = "未分类状态代码";
    switch (status)
    {
    case 0x00000000: result = "STATUS_SUCCESS (成功)"; break;
    case 0xC0000001: result = "STATUS_UNSUCCESSFUL (未指定系统错误/操作失败)"; break;
    case 0xC0000005: result = "STATUS_ACCESS_VIOLATION (内存访问违规)"; break;
    case 0xC0000008: result = "STATUS_INVALID_HANDLE (无效句柄)"; break;
    case 0xC000000D: result = "STATUS_INVALID_PARAMETER (参数无效)"; break;
    case 0xC0000022: result = "STATUS_ACCESS_DENIED (访问被拒绝/权限不足)"; break;
    case 0xC0000034: result = "STATUS_OBJECT_NAME_NOT_FOUND (对象路径未找到)"; break;
    case 0xC0000035: result = "STATUS_OBJECT_NAME_COLLISION (对象名称冲突)"; break;
    case 0xC0000043: result = "STATUS_SHARING_VIOLATION (设备或文件独占冲突)"; break;
    case 0xC000009A: result = "STATUS_INSUFFICIENT_RESOURCES (系统资源耗尽)"; break;
    case 0xC000009D: result = "STATUS_DEVICE_NOT_READY (设备未就绪)"; break;
    case 0xC00000B5: result = "STATUS_IO_TIMEOUT (通信超时)"; break;
    case 0xC00000BA: result = "STATUS_FILE_IS_A_DIRECTORY (文件类型不匹配)"; break;
    case 0xC00000BB: result = "STATUS_NOT_SUPPORTED (不支持的操作)"; break;
    case 0xC0000186: result = "STATUS_PORT_DISCONNECTED (端口未连接/断开)"; break;
    case 0xC0000225: result = "STATUS_NOT_FOUND (未找到目标项)"; break;
    case 0x80000003: result = "STATUS_BREAKPOINT (触发调试断点)"; break;
    case 0xC000007A: result = "STATUS_PROCEDURE_NOT_FOUND (未找到内核导出例程)"; break;
    case 0xC000007B: result = "STATUS_INVALID_IMAGE_FORMAT (无效的映像格式)"; break;
    case 0xC0000428: result = "STATUS_INVALID_IMAGE_HASH (驱动签名被阻止/HVCI阻止)"; break;
    default:
        switch (status)
        {
        case ERROR_SUCCESS: result = "NO_ERROR (成功)"; break;
        case ERROR_FILE_NOT_FOUND: result = "ERROR_FILE_NOT_FOUND (系统找不到指定文件)"; break;
        case ERROR_PATH_NOT_FOUND: result = "ERROR_PATH_NOT_FOUND (系统找不到指定路径)"; break;
        case ERROR_ACCESS_DENIED: result = "ERROR_ACCESS_DENIED (拒绝访问)"; break;
        case ERROR_INVALID_HANDLE: result = "ERROR_INVALID_HANDLE (无效句柄)"; break;
        case ERROR_SERVICE_ALREADY_RUNNING: result = "ERROR_SERVICE_ALREADY_RUNNING (驱动服务实例已在运行)"; break;
        case ERROR_SERVICE_DOES_NOT_EXIST: result = "ERROR_SERVICE_DOES_NOT_EXIST (指定的服务未安装)"; break;
        case 577: result = "ERROR_INVALID_IMAGE_HASH (Windows 无法验证驱动数字签名)"; break;
        case 1058: result = "ERROR_SERVICE_DISABLED (驱动服务已被禁用，无法启动)"; break;
        case 1275: result = "ERROR_DRIVER_BLOCKED (驱动被系统阻止加载/HVCI阻止)"; break;
        default: result = "未分类状态代码"; break;
        }
        break;
    }
    return result;
}

std::string Reporter::FormatFailReason(const std::string &failReason, uint32_t &inOutStatusCode)
{
    if (failReason.empty())
    {
        return "未知错误原因";
    }

    // 1. 服务管理器 SCM 相关错误解析
    if (failReason.find("StartService Failed:") != std::string::npos)
    {
        size_t pos = failReason.find(":");
        std::string errStr = (pos != std::string::npos) ? failReason.substr(pos + 1) : "";
        while (!errStr.empty() && (errStr.front() == ' ' || errStr.front() == '\t')) errStr.erase(errStr.begin());
        DWORD dwErr = 0;
        try { dwErr = std::stoul(errStr); } catch (...) {}

        std::string desc = "启动驱动内核服务失败 [Win32错误码: " + std::to_string(dwErr) + "]";
        switch (dwErr)
        {
        case 1275:
            desc += " - 驱动被系统安全机制阻止加载 (系统已开启 HVCI/内核代码完整性隔离或驱动签名被阻止)";
            inOutStatusCode = 0xC0000428; // STATUS_INVALID_IMAGE_HASH
            break;
        case 577:
            desc += " - Windows 无法验证此文件的数字签名";
            inOutStatusCode = 0xC0000428;
            break;
        case 1058:
            desc += " - 驱动服务已被禁用，无法启动";
            inOutStatusCode = 0xC0000022;
            break;
        case 2:
            desc += " - 系统找不到指定的驱动文件 (文件落地释放失败或被杀毒软件拦截删除)";
            inOutStatusCode = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
            break;
        case 1056:
            desc += " - 驱动服务的实例已在运行";
            inOutStatusCode = 0xC0000043;
            break;
        default:
            if (inOutStatusCode == 0 || inOutStatusCode == 0xC0000001) inOutStatusCode = 0xC0000001;
            break;
        }
        return desc;
    }

    if (failReason.find("CreateService Failed:") != std::string::npos)
    {
        size_t pos = failReason.find(":");
        std::string errStr = (pos != std::string::npos) ? failReason.substr(pos + 1) : "";
        while (!errStr.empty() && (errStr.front() == ' ' || errStr.front() == '\t')) errStr.erase(errStr.begin());
        DWORD dwErr = 0;
        try { dwErr = std::stoul(errStr); } catch (...) {}

        std::string desc = "创建驱动内核服务失败 [Win32错误码: " + std::to_string(dwErr) + "]";
        if (dwErr == 1073 || dwErr == 183)
        {
            desc += " - 指定的驱动服务已存在 (服务对象重名冲突)";
            inOutStatusCode = 0xC0000035; // STATUS_OBJECT_NAME_COLLISION
        }
        else if (dwErr == 5)
        {
            desc += " - 权限不足，拒绝访问 (未以管理员权限运行)";
            inOutStatusCode = 0xC0000022;
        }
        return desc;
    }

    if (failReason.find("OpenSCManager Failed:") != std::string::npos)
    {
        inOutStatusCode = 0xC0000022;
        return "打开系统服务管理器 (SCM) 失败，权限不足";
    }

    // 2. 内存映射 (Code Cave / PTE Remap) 相关错误
    if (failReason == "error.privilege_escalation_failed")
    {
        inOutStatusCode = 0xC0000022; // STATUS_ACCESS_DENIED
        return "提升管理员调试特权 (SeDebugPrivilege) 失败，请以管理员身份运行";
    }
    if (failReason == "error.restart_host_and_program" || failReason == "error.driver_payload_empty")
    {
        inOutStatusCode = 0xC000009A; // STATUS_INSUFFICIENT_RESOURCES
        return "驱动二进制载荷为空或已被释放，请重新同步数据并重启程序";
    }
    if (failReason == "error.open_whql_device_failed")
    {
        inOutStatusCode = 0xC000009D; // STATUS_DEVICE_NOT_READY
        return "打开白驱动内核设备句柄失败 (白驱动设备未就绪/服务未启动)";
    }
    if (failReason == "error.query_system_info_failed")
    {
        inOutStatusCode = 0xC0000001;
        return "获取系统内核物理内存布局 (CR3/KernBase) 失败";
    }
    if (failReason == "error.trigger_driver_not_found")
    {
        inOutStatusCode = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
        return "在内核已加载模块链表中未找到白驱动模块 (Machenike.sys)";
    }
    if (failReason == "error.signature_not_found")
    {
        inOutStatusCode = 0xC0000225; // STATUS_NOT_FOUND
        return "白驱动特征代码扫描未匹配 (DefaultBranch 特征码失效)";
    }
    if (failReason == "error.section_map_failed")
    {
        inOutStatusCode = 0xC0000005; // STATUS_ACCESS_VIOLATION
        return "核心驱动 PE 节区展开映射失败";
    }
    if (failReason == "error.fix_iat_failed")
    {
        inOutStatusCode = 0xC000007B; // STATUS_INVALID_IMAGE_FORMAT
        return "修复核心驱动内核导入表 (IAT) 失败";
    }
    if (failReason == "error.code_cave_not_found")
    {
        inOutStatusCode = 0xC000009A; // STATUS_INSUFFICIENT_RESOURCES
        return "白驱动中未找到可供跳板注入的代码空洞 (Code Cave 未命中)";
    }
    if (failReason == "error.no_host_driver_available")
    {
        inOutStatusCode = 0xC0000225; // STATUS_NOT_FOUND
        return "未找到可供穿透映射的目标显卡驱动 (nvlddmkm/amdkmdag/igdkmd64)";
    }
    if (failReason == "error.kernel_exports_unresolved")
    {
        inOutStatusCode = 0xC000007A; // STATUS_PROCEDURE_NOT_FOUND
        return "解析内核内存管理导出例程 (MmAllocatePagesForMdl/MmMapIoSpace) 失败";
    }
    if (failReason.find("OpenDevice Failed:") != std::string::npos)
    {
        size_t pos = failReason.find(":");
        std::string errStr = (pos != std::string::npos) ? failReason.substr(pos + 1) : "";
        while (!errStr.empty() && (errStr.front() == ' ' || errStr.front() == '\t')) errStr.erase(errStr.begin());
        DWORD dwErr = 0;
        try { dwErr = std::stoul(errStr); } catch (...) {}
        inOutStatusCode = (dwErr == 5) ? 0xC0000022 : ((dwErr == 2) ? 0xC0000034 : 0xC000009D);
        return "打开驱动设备句柄 (\\\\.\\MsNetEndpoint) 失败 [Win32错误码: " + std::to_string(dwErr) + "]";
    }
    if (failReason.find("StartTransport IOCTL Failed:") != std::string::npos)
    {
        size_t pos = failReason.find(":");
        std::string errStr = (pos != std::string::npos) ? failReason.substr(pos + 1) : "";
        while (!errStr.empty() && (errStr.front() == ' ' || errStr.front() == '\t')) errStr.erase(errStr.begin());
        DWORD dwErr = 0;
        try { dwErr = std::stoul(errStr); } catch (...) {}
        inOutStatusCode = 0xC0000001;
        return "发送 IOCTL_MK_START_TRANSPORT 激活驱动传输层失败 [Win32错误码: " + std::to_string(dwErr) + "]";
    }
    if (failReason.find("DriverStatus Failed:") != std::string::npos)
    {
        size_t pos = failReason.find(":");
        std::string errStr = (pos != std::string::npos) ? failReason.substr(pos + 1) : "";
        while (!errStr.empty() && (errStr.front() == ' ' || errStr.front() == '\t')) errStr.erase(errStr.begin());
        try { inOutStatusCode = static_cast<uint32_t>(std::stoul(errStr, nullptr, 16)); } catch (...) { inOutStatusCode = 0xC0000001; }
        return "驱动启动激活返回内核错误状态码 (" + errStr + ")";
    }
    if (failReason == "VerifyAndActivateDriver failed")
    {
        inOutStatusCode = 0xC000000D; // STATUS_INVALID_PARAMETER
        return "驱动双向防伪验签或 IOCTL 通信激活失败 (驱动未响应或指纹不匹配)";
    }

    return failReason;
}

bool Reporter::SendWinHttpPost(const std::string &url, const std::string &postData, uint32_t timeoutMs)
{
    HMODULE hWinHttp = LoadLibraryW(L"winhttp.dll");
    if (!hWinHttp)
    {
        return false;
    }

    auto pOpen = reinterpret_cast<pfnWinHttpOpen>(GetProcAddress(hWinHttp, "WinHttpOpen"));
    auto pConnect = reinterpret_cast<pfnWinHttpConnect>(GetProcAddress(hWinHttp, "WinHttpConnect"));
    auto pOpenRequest = reinterpret_cast<pfnWinHttpOpenRequest>(GetProcAddress(hWinHttp, "WinHttpOpenRequest"));
    auto pSendRequest = reinterpret_cast<pfnWinHttpSendRequest>(GetProcAddress(hWinHttp, "WinHttpSendRequest"));
    auto pReceiveResponse = reinterpret_cast<pfnWinHttpReceiveResponse>(GetProcAddress(hWinHttp, "WinHttpReceiveResponse"));
    auto pCloseHandle = reinterpret_cast<pfnWinHttpCloseHandle>(GetProcAddress(hWinHttp, "WinHttpCloseHandle"));
    auto pSetOption = reinterpret_cast<pfnWinHttpSetOption>(GetProcAddress(hWinHttp, "WinHttpSetOption"));
    auto pSetTimeouts = reinterpret_cast<pfnWinHttpSetTimeouts>(GetProcAddress(hWinHttp, "WinHttpSetTimeouts"));
    auto pCrackUrl = reinterpret_cast<pfnWinHttpCrackUrl>(GetProcAddress(hWinHttp, "WinHttpCrackUrl"));

    if (!pOpen || !pConnect || !pOpenRequest || !pSendRequest || !pReceiveResponse || !pCloseHandle || !pSetOption || !pSetTimeouts || !pCrackUrl)
    {
        FreeLibrary(hWinHttp);
        return false;
    }

    std::wstring wUrl = strTowStr(url);
    URL_COMPONENTSW urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[256] = {};
    wchar_t urlPath[1024] = {};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = ARRAYSIZE(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = ARRAYSIZE(urlPath);

    if (!pCrackUrl(wUrl.c_str(), static_cast<DWORD>(wUrl.length()), 0, &urlComp))
    {
        FreeLibrary(hWinHttp);
        return false;
    }

    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = (urlComp.nPort != 0) ? urlComp.nPort : (isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);

    HINTERNET hSession = pOpen(L"HostLoader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
    {
        FreeLibrary(hWinHttp);
        return false;
    }

    pSetTimeouts(hSession, static_cast<int>(timeoutMs), static_cast<int>(timeoutMs), static_cast<int>(timeoutMs), static_cast<int>(timeoutMs));

    HINTERNET hConnect = pConnect(hSession, hostName, port, 0);
    if (!hConnect)
    {
        pCloseHandle(hSession);
        FreeLibrary(hWinHttp);
        return false;
    }

    DWORD dwOpenFlags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = pOpenRequest(hConnect, L"POST", urlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwOpenFlags);
    if (!hRequest)
    {
        pCloseHandle(hConnect);
        pCloseHandle(hSession);
        FreeLibrary(hWinHttp);
        return false;
    }

    if (isHttps)
    {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        pSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
    }

    LPCWSTR headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    BOOL sent = pSendRequest(hRequest, headers, static_cast<DWORD>(-1),
                             const_cast<char *>(postData.data()),
                             static_cast<DWORD>(postData.size()),
                             static_cast<DWORD>(postData.size()), 0);

    BOOL received = FALSE;
    if (sent)
    {
        received = pReceiveResponse(hRequest, NULL);
    }

    pCloseHandle(hRequest);
    pCloseHandle(hConnect);
    pCloseHandle(hSession);
    FreeLibrary(hWinHttp);

    bool result = (sent && received);
    return result;
}

bool Reporter::PostToBackend(const std::string &plainText, const std::string &functionName, uint32_t statusCode, uint32_t timeoutMs)
{
    try
    {
        std::string cardKey = !gVar.slogin_data.card_key.empty() ? gVar.slogin_data.card_key : "N/A";
        std::string brandVer = !gVar.brand_version.empty() ? gVar.brand_version : "DEFAULT";
        std::string gameName = !gVar.selected_game.empty() ? gVar.selected_game : "DEFAULT";
        std::string appVer = !gVar.client_version.empty() ? gVar.client_version : (!gVar.curAppVersion.empty() ? gVar.curAppVersion : "1.0");

        std::string hexStr = bytes::StrToHex(plainText);
        std::string encHex = EncryptDataHex(hexStr, REPORT_SECRET_KEY);

        char hexStatus[32] = {0};
        snprintf(hexStatus, sizeof(hexStatus), "0x%08X", statusCode);

        std::string postData = "h=" + encHex +
                               "&functionName=" + functionName +
                               "&status=" + hexStatus +
                               "&CardKey=" + cardKey +
                               "&brand=" + brandVer +
                               "&game=" + gameName +
                               "&version=" + appVer +
                               "&loaderVer=" + HOST_LOADER_VERSION;

        std::string baseUrl = Environment::Current.api_url;
        if (baseUrl.empty())
        {
            return false;
        }

        while (!baseUrl.empty() && (baseUrl.back() == '/' || baseUrl.back() == '\\'))
        {
            baseUrl.pop_back();
        }
        std::string targetUrl = baseUrl + "/api/tg";

        DBG("[Reporter] Posting exception to: %s (fn: %s, status: %s)", targetUrl.c_str(), functionName.c_str(), hexStatus);
        bool ret = SendWinHttpPost(targetUrl, postData, timeoutMs);
        return ret;
    }
    catch (...)
    {
        return false;
    }
}

void Reporter::Report(const char *functionName, uint32_t statusCode, const char *extraDetail)
{
    const char *fn = functionName ? functionName : "UnknownRoutine";
    const char *cardKey = !gVar.slogin_data.card_key.empty() ? gVar.slogin_data.card_key.c_str() : "N/A";

    uint64_t fp = ComputeFingerprint(cardKey, fn, statusCode);
    if (!ShouldReport(fp, 60000))
    {
        return;
    }

    std::string brandVer = !gVar.brand_version.empty() ? gVar.brand_version : "DEFAULT";
    std::string gameName = !gVar.selected_game.empty() ? gVar.selected_game : "DEFAULT";
    std::string appVer = !gVar.client_version.empty() ? gVar.client_version : (!gVar.curAppVersion.empty() ? gVar.curAppVersion : "1.0");
    const char *statusDesc = GetStatusSemantic(statusCode);
    const char *detail = (extraDetail && extraDetail[0] != '\0') ? extraDetail : "无详细错误描述";

    // ★★★ 对齐 CheatDrv 驱动排版规范 ★★★
    char plainData[1024] = {0};
    snprintf(plainData, sizeof(plainData),
             "\xF0\x9F\x9A\xA8 【宿主加载器异常告警】\r\n"
             "------------------------------------\r\n"
             "\xF0\x9F\x8E\xAE 目标游戏：%s (v%s)\r\n"
             "\xF0\x9F\x8F\xB7\xEF\xB8\x8F 客户端版本：%s\r\n"
             "\xF0\x9F\x93\xA6 加载器版本：%s\r\n"
             "\xF0\x9F\x94\x91 用户卡密：%s\r\n"
             "\xF0\x9F\x93\x8D 触发例程：%s\r\n"
             "\xF0\x9F\x9B\x91 状态代码：0x%08X (%s)\r\n"
             "------------------------------------\r\n"
             "\xF0\x9F\x93\x8B 诊断详情：\r\n"
             "%s",
             gameName.c_str(), appVer.c_str(),
             brandVer.c_str(),
             HOST_LOADER_VERSION,
             cardKey,
             fn,
             statusCode, statusDesc,
             detail);

    std::string formattedText = plainData;
    std::string fnStr = fn;

    try
    {
        std::thread([formattedText, fnStr, statusCode]() {
            PostToBackend(formattedText, fnStr, statusCode, 5000);
        }).detach();
    }
    catch (...)
    {
    }
}

void Reporter::Report(const std::string &functionName, uint32_t statusCode, const std::string &extraDetail)
{
    Report(functionName.c_str(), statusCode, extraDetail.c_str());
}

void Reporter::Report(const std::string &functionName, const std::string &errorMessage)
{
    Report(functionName.c_str(), 0xC0000001, errorMessage.c_str());
}

void Reporter::Report(const char *functionName, const char *errorMessage)
{
    Report(functionName, 0xC0000001, errorMessage);
}

void Reporter::ReportFormat(const char *functionName, uint32_t statusCode, const char *format, ...)
{
    if (!format)
    {
        Report(functionName, statusCode, nullptr);
        return;
    }

    char buffer[256] = {0};
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    Report(functionName, statusCode, buffer);
}

void Reporter::ReportSync(const char *functionName, uint32_t statusCode, const char *extraDetail, uint32_t timeoutMs)
{
    const char *fn = functionName ? functionName : "UnknownRoutine";
    const char *cardKey = !gVar.slogin_data.card_key.empty() ? gVar.slogin_data.card_key.c_str() : "N/A";
    std::string brandVer = !gVar.brand_version.empty() ? gVar.brand_version : "DEFAULT";
    std::string gameName = !gVar.selected_game.empty() ? gVar.selected_game : "DEFAULT";
    std::string appVer = !gVar.client_version.empty() ? gVar.client_version : (!gVar.curAppVersion.empty() ? gVar.curAppVersion : "1.0");
    const char *statusDesc = GetStatusSemantic(statusCode);
    const char *detail = (extraDetail && extraDetail[0] != '\0') ? extraDetail : "无详细错误描述";

    char plainData[1024] = {0};
    snprintf(plainData, sizeof(plainData),
             "\xF0\x9F\x9A\xA8 【宿主加载器异常告警】\r\n"
             "------------------------------------\r\n"
             "\xF0\x9F\x8E\xAE 目标游戏：%s (v%s)\r\n"
             "\xF0\x9F\x8F\xB7\xEF\xB8\x8F 客户端版本：%s\r\n"
             "\xF0\x9F\x93\xA6 加载器版本：%s\r\n"
             "\xF0\x9F\x94\x91 用户卡密：%s\r\n"
             "\xF0\x9F\x93\x8D 触发例程：%s\r\n"
             "\xF0\x9F\x9B\x91 状态代码：0x%08X (%s)\r\n"
             "------------------------------------\r\n"
             "\xF0\x9F\x93\x8B 诊断详情：\r\n"
             "%s",
             gameName.c_str(), appVer.c_str(),
             brandVer.c_str(),
             HOST_LOADER_VERSION,
             cardKey,
             fn,
             statusCode, statusDesc,
             detail);

    PostToBackend(plainData, fn, statusCode, timeoutMs);
}

extern "C" void HandleException(const char *functionName, const char *errorMessage)
{
    Reporter::Report(functionName, 0xC0000001, errorMessage);
}

extern "C" void HandleExceptionWithStatus(const char *functionName, uint32_t statusCode, const char *errorMessage)
{
    Reporter::Report(functionName, statusCode, errorMessage);
}
