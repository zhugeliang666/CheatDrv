// ============================================================
// main.cpp — drv_wsk 内存加载器主程序
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

    // ---- 2. 解析命令行参数并确定 drv_wsk.sys 路径与宿主驱动及通信配置 ----
    wchar_t drvPath[MAX_PATH] = {};
    wchar_t hostDrvName[MAX_PATH] = L"tcpip.sys";
    bool hostExplicit = false;

    DRV_BOOT_CONFIG bootConfig = {};
    bootConfig.Magic         = DRV_BOOT_MAGIC;
    bootConfig.TransportMode = DRV_TRANSPORT_TCP; // 默认 TCP 通信
    bootConfig.Port          = 10001;             // 默认 10001 端口
    bootConfig.AuthToken     = 0;
    bootConfig.Flags         = 0;

    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"-h") == 0 || _wcsicmp(argv[i], L"--host") == 0) {
            if (i + 1 < argc) {
                wcscpy_s(hostDrvName, argv[++i]);
                hostExplicit = true;
            }
        } else if (_wcsicmp(argv[i], L"--tcp") == 0) {
            bootConfig.TransportMode = DRV_TRANSPORT_TCP;
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                int p = _wtoi(argv[++i]);
                if (p > 0 && p <= 65535) bootConfig.Port = (uint16_t)p;
            } else if (bootConfig.Port == 0 || bootConfig.Port == 10002) {
                bootConfig.Port = 10001;
            }
        } else if (_wcsicmp(argv[i], L"--udp") == 0) {
            bootConfig.TransportMode = DRV_TRANSPORT_UDP;
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                int p = _wtoi(argv[++i]);
                if (p > 0 && p <= 65535) bootConfig.Port = (uint16_t)p;
            } else {
                bootConfig.Port = 10002;
            }
        } else if (_wcsicmp(argv[i], L"--usb") == 0) {
            bootConfig.TransportMode = DRV_TRANSPORT_USB;
            bootConfig.Port = 0;
        } else if (_wcsicmp(argv[i], L"-p") == 0 || _wcsicmp(argv[i], L"--port") == 0) {
            if (i + 1 < argc) {
                int p = _wtoi(argv[++i]);
                if (p > 0 && p <= 65535) bootConfig.Port = (uint16_t)p;
            }
        } else if (_wcsicmp(argv[i], L"-t") == 0 || _wcsicmp(argv[i], L"--token") == 0) {
            if (i + 1 < argc) {
                bootConfig.AuthToken = (uint32_t)wcstoul(argv[++i], nullptr, 0);
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
    if (drvPath[0] == 0) {
        wchar_t exeDir[MAX_PATH] = {};
        GetModuleFileNameW(NULL, exeDir, MAX_PATH);
        wchar_t* lastSlash = wcsrchr(exeDir, L'\\');
        if (lastSlash) *(lastSlash + 1) = 0;
        swprintf_s(drvPath, L"%sdrv_wsk.sys", exeDir);
    }
    LOG_INFO("drv_wsk.sys path: %ls", drvPath);
    LOG_INFO("Target host driver: %ls", hostDrvName);

    const wchar_t* modeStr = L"TCP";
    if (bootConfig.TransportMode == DRV_TRANSPORT_UDP) modeStr = L"UDP";
    else if (bootConfig.TransportMode == DRV_TRANSPORT_USB) modeStr = L"USB";

    LOG_INFO("Boot Transport: %ls (Port=%u, Token=0x%08X)",
             modeStr, bootConfig.Port, bootConfig.AuthToken);

    // ---- 3. 检查文件是否存在 ----
    DWORD attr = GetFileAttributesW(drvPath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        LOG_ERR("drv_wsk.sys not found: %ls (GLE=%lu)", drvPath, GetLastError());
        printf("\nUsage: loader.exe [drv_wsk.sys] [-h host.sys] [--tcp [port] | --udp [port] | --usb] [-t token] [--force] [--non-interactive]\n");
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
    bool ok = LoadDrvWskViaCave(drvPath, L"Machenike.sys", hostDrvName, forceReload, &bootConfig);
#elif MODE_MANUAL_MAP
    LOG_INFO("Pipeline Mode: [ManualMap] (Kernel Allocated Pool Memory)");
    bool ok = LoadDrvWskViaPool(drvPath, L"Machenike.sys", forceReload, &bootConfig);
#else
    LOG_INFO("Pipeline Mode: [Normal SCM] (Standard Windows Service Control Manager)");
    bool ok = LoadDrvWskViaSCM(drvPath, L"drv_wsk", forceReload);
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
