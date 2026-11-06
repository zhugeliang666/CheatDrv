#pragma once
#include "loader_common.h"
#include <winsvc.h>

// ============================================================
// scm_loader.h — Windows 原生服务控制管理器 (SCM) 驱动加载实现
//
// 适用场景：
//   当 MODE_MANUAL_MAP_CAVE 与 MODE_MANUAL_MAP 均未开启时，
//   直接调用系统原生 SCM API (CreateService / StartService) 正常加载驱动。
//   全模式统一伪装为 Intel I225-V/I226 NDIS Miniport Driver (i225v.sys)。
// ============================================================

#define SPOOF_I225_SERVICE_NAME    L"i225v"
#define SPOOF_I225_DISPLAY_NAME    L"Intel I225-V/I226 NDIS Miniport Driver"
#define SPOOF_I225_LOAD_GROUP      L"NDIS"
#define SPOOF_I225_DRIVER_FILENAME L"i225v.sys"

inline void SetupI225EventLogRegistry()
{
    HKEY hKey = NULL;
    const wchar_t* regPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System\\i225v";
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        const wchar_t* msgFile = L"%SystemRoot%\\System32\\netevent.dll";
        DWORD typesSupported = 7;
        RegSetValueExW(hKey, L"EventMessageFile", 0, REG_EXPAND_SZ, (const BYTE*)msgFile, (DWORD)((wcslen(msgFile) + 1) * sizeof(wchar_t)));
        RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD, (const BYTE*)&typesSupported, sizeof(DWORD));
        RegCloseKey(hKey);
    }
}

inline bool StopAndRemoveService(SC_HANDLE hSCManager, const wchar_t* serviceName)
{
    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_STOP | DELETE);
    if (!hService) return false;

    SERVICE_STATUS status = {};
    ControlService(hService, SERVICE_CONTROL_STOP, &status);
    DeleteService(hService);
    CloseServiceHandle(hService);
    return true;
}

inline bool ActivateDriverTransport(const DRV_BOOT_CONFIG* pBootConfig, const DRV_BOOT_CONFIG_EX* pBootConfigEx = nullptr)
{
    if (!pBootConfig && !pBootConfigEx) {
        LOG_ERR("ActivateDriverTransport: pBootConfig is null!");
        return false;
    }

    const DRV_BOOT_CONFIG* pEffectiveConfig = pBootConfig ? pBootConfig : (pBootConfigEx ? &pBootConfigEx->Base : nullptr);
    if (!pEffectiveConfig) return false;

    const wchar_t* modeStr = L"TCP";
    if (pEffectiveConfig->TransportMode == DRV_TRANSPORT_UDP) modeStr = L"UDP";
    else if (pEffectiveConfig->TransportMode == DRV_TRANSPORT_USB) modeStr = L"USB";
    else if (pEffectiveConfig->TransportMode == DRV_TRANSPORT_RAW_ETH) modeStr = L"RawEthernet (0x8844)";

    LOG_INFO("ActivateDriverTransport: Opening driver device '%ls' with dynamic Token & BootConfig payload...", MK_USER_DEVICE_NAME);

    HANDLE hDevice = OpenDriverDeviceCompatible(
        MK_USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        25,
        100,
        pBootConfigEx
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        LOG_ERR("ActivateDriverTransport: Failed to open '%ls' and activate transport (GLE=%lu)", MK_USER_DEVICE_NAME, gle);
        return false;
    }

    LOG_OK("ActivateDriverTransport: Successfully started [%ls] transport in kernel driver via CreateFile!", modeStr);
    CloseHandle(hDevice);
    return true;
}

inline bool SendBootConfigViaIOCTL(const DRV_BOOT_CONFIG* pBootConfig, const DRV_BOOT_CONFIG_EX* pBootConfigEx = nullptr)
{
    return ActivateDriverTransport(pBootConfig, pBootConfigEx);
}

inline bool SendStopTransportViaIOCTL()
{
    HANDLE hDevice = OpenDriverDeviceCompatible(
        MK_USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        5,
        50
    );
    if (hDevice == INVALID_HANDLE_VALUE) {
        LOG_ERR("SendStopTransportViaIOCTL: Failed to open device '%ls' with compatible Token algorithm (GLE=%lu)", MK_USER_DEVICE_NAME, GetLastError());
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL ioOk = DeviceIoControl(
        hDevice,
        IOCTL_MK_STOP_TRANSPORT,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    CloseHandle(hDevice);
    if (!ioOk) {
        LOG_ERR("SendStopTransportViaIOCTL: IOCTL_MK_STOP_TRANSPORT failed (GLE=%lu)", GetLastError());
        return false;
    }
    LOG_OK("SendStopTransportViaIOCTL: Successfully stopped transport service.");
    return true;
}

// ---------------------------------------------------------------------------
// 方案 B：DirectMiniport 通道健康度查询（布局与内核 MK_SERVER_STATUS v2 一致）
// 通道致命失败后驱动只置失败标志并保留设备对象，由 loader 读到后自行 DeleteService，
// 卸载时机完全交给 R3。
// ---------------------------------------------------------------------------
typedef struct _MK_SERVER_STATUS_R3
{
    unsigned long Mode;
    unsigned long Port;
    long ActiveConnections;
    unsigned char fRunning;
    unsigned char fChannelReady;
    unsigned char fChannelArmed;
    unsigned char fChannelFatal;
    unsigned long ChannelFailReason;
    unsigned long ChannelFailStatus;
    unsigned long ChannelFilterCount;
    unsigned long ChannelIfIndex;
    long ChannelTxDirect;
    long ChannelTxFailed;
    long ChannelRxStolen;
} MK_SERVER_STATUS_R3;

inline bool QueryChannelStatus(MK_SERVER_STATUS_R3& st)
{
    ZeroMemory(&st, sizeof(st));

    HANDLE hDevice = OpenDriverDeviceCompatible(
        MK_USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        5,
        50);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        LOG_WARN("QueryChannelStatus: device '%ls' not openable (GLE=%lu)", MK_USER_DEVICE_NAME, GetLastError());
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL ioOk = DeviceIoControl(
        hDevice,
        IOCTL_MK_GET_STATUS,
        NULL,
        0,
        &st,
        (DWORD)sizeof(st),
        &bytesReturned,
        NULL);

    CloseHandle(hDevice);
    if (!ioOk || bytesReturned < sizeof(st))
    {
        LOG_WARN("QueryChannelStatus: IOCTL_MK_GET_STATUS failed (GLE=%lu, bytes=%lu)", GetLastError(), bytesReturned);
        return false;
    }
    return true;
}

// 读状态 → 若已致命：停传输 + DeleteService，返回 true 表示已处置
inline bool HandleChannelFailureIfAny(const wchar_t* serviceName = SPOOF_I225_SERVICE_NAME)
{
    MK_SERVER_STATUS_R3 st;
    if (!QueryChannelStatus(st))
    {
        return false;
    }

    if (!st.fChannelFatal)
    {
        LOG_OK("DirectMiniport channel healthy (ready=%u armed=%u filters=%lu txDirect=%ld rxStolen=%ld)",
               (unsigned)st.fChannelReady, (unsigned)st.fChannelArmed, st.ChannelFilterCount, st.ChannelTxDirect,
               st.ChannelRxStolen);
        return false;
    }

    LOG_ERR("DirectMiniport channel FATAL: reason=%lu status=0x%08lX (txDirect=%ld txFailed=%ld)",
            st.ChannelFailReason, st.ChannelFailStatus, st.ChannelTxDirect, st.ChannelTxFailed);

    SendStopTransportViaIOCTL();

    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager)
    {
        if (StopAndRemoveService(hSCManager, serviceName))
        {
            LOG_OK("HandleChannelFailureIfAny: service '%ls' stopped & deleted", serviceName);
        }
        else
        {
            LOG_ERR("HandleChannelFailureIfAny: StopAndRemoveService('%ls') failed (GLE=%lu)", serviceName,
                    GetLastError());
        }
        CloseServiceHandle(hSCManager);
    }
    else
    {
        LOG_ERR("HandleChannelFailureIfAny: OpenSCManager failed (GLE=%lu)", GetLastError());
    }
    return true;
}

inline bool LoadDrvWskViaSCM(const wchar_t* drvPath, const wchar_t* serviceName = SPOOF_I225_SERVICE_NAME, bool forceReload = false, const DRV_BOOT_CONFIG* pBootConfig = nullptr, const DRV_BOOT_CONFIG_EX* pBootConfigEx = nullptr)
{
    (void)serviceName;
    const wchar_t* effectiveSvcName = SPOOF_I225_SERVICE_NAME;

    LOG_INFO("LoadDrvWskViaSCM: Using standard Windows Service Control Manager pipeline (Spoofed as %ls)...", SPOOF_I225_DISPLAY_NAME);

    wchar_t fullPath[MAX_PATH] = {};
    if (!GetFullPathNameW(drvPath, MAX_PATH, fullPath, NULL)) {
        LOG_ERR("LoadDrvWskViaSCM: GetFullPathNameW failed for '%ls' (GLE=%lu)", drvPath, GetLastError());
        return false;
    }

    DWORD fileAttr = GetFileAttributesW(fullPath);
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        LOG_ERR("LoadDrvWskViaSCM: Driver file not found at '%ls'", fullPath);
        return false;
    }

    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        DWORD gle = GetLastError();
        LOG_ERR("LoadDrvWskViaSCM: OpenSCManagerW failed (GLE=%lu, check admin privileges)", gle);
        return false;
    }

    // 清理旧版遗留的 mswsk 服务
    StopAndRemoveService(hSCManager, L"mswsk");

    if (forceReload) {
        LOG_WARN("LoadDrvWskViaSCM: Force reload requested, stopping and removing existing service '%ls'...", effectiveSvcName);
        StopAndRemoveService(hSCManager, effectiveSvcName);
        Sleep(200);
    }

    // 将驱动文件同步部署到 System32\drivers\i225v.sys，1:1 对齐 Intel I225/I226 官方驱动路径
    wchar_t sysDir[MAX_PATH] = {};
    wchar_t targetSysPath[MAX_PATH] = {};
    if (GetSystemDirectoryW(sysDir, MAX_PATH)) {
        swprintf_s(targetSysPath, L"%s\\drivers\\%s", sysDir, SPOOF_I225_DRIVER_FILENAME);
        if (_wcsicmp(fullPath, targetSysPath) != 0) {
            if (CopyFileW(fullPath, targetSysPath, FALSE)) {
                wcscpy_s(fullPath, targetSysPath);
            }
        }
    }

    SetupI225EventLogRegistry();

    SC_HANDLE hService = OpenServiceW(hSCManager, effectiveSvcName, SERVICE_ALL_ACCESS);
    if (!hService) {
        LOG_INFO("LoadDrvWskViaSCM: Creating new kernel service '%ls' (%ls) -> '%ls'...", effectiveSvcName, SPOOF_I225_DISPLAY_NAME, fullPath);
        hService = CreateServiceW(
            hSCManager,
            effectiveSvcName,
            SPOOF_I225_DISPLAY_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            fullPath,
            SPOOF_I225_LOAD_GROUP,
            NULL, NULL, NULL, NULL
        );

        if (!hService) {
            DWORD gle = GetLastError();
            LOG_ERR("LoadDrvWskViaSCM: CreateServiceW failed (GLE=%lu)", gle);
            CloseServiceHandle(hSCManager);
            return false;
        }
    } else {
        LOG_INFO("LoadDrvWskViaSCM: Service '%ls' already exists, updating binary path...", effectiveSvcName);
        ChangeServiceConfigW(
            hService,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            fullPath,
            SPOOF_I225_LOAD_GROUP,
            NULL, NULL, NULL, NULL,
            SPOOF_I225_DISPLAY_NAME
        );
    }

    // 检查服务当前状态
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    bool alreadyRunning = false;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            LOG_OK("LoadDrvWskViaSCM: Service '%ls' is already in running state.", effectiveSvcName);
            alreadyRunning = true;
        }
    }

    if (!alreadyRunning) {
        LOG_INFO("LoadDrvWskViaSCM: Starting kernel service '%ls'...", effectiveSvcName);
        if (!StartServiceW(hService, 0, NULL)) {
            DWORD gle = GetLastError();
            if (gle == ERROR_SERVICE_ALREADY_RUNNING) {
                LOG_OK("LoadDrvWskViaSCM: Service is already running.");
            } else {
                LOG_ERR("LoadDrvWskViaSCM: StartServiceW failed (GLE=%lu)", gle);
                if (gle == 577) { // ERROR_INVALID_IMAGE_HASH
                    LOG_ERR("LoadDrvWskViaSCM: GLE=577 (Windows driver signature verification failed, please enable test signing or disable driver signature enforcement)");
                }
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return false;
            }
        } else {
            LOG_OK("LoadDrvWskViaSCM: Kernel service '%ls' successfully started via SCM!", effectiveSvcName);
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    // 若指定了启动配置，通过 Create 阶段透传动态 Token 与参数载荷直接激活内核服务（无需额外发送 IO）
    if (pBootConfig || pBootConfigEx) {
        LOG_INFO("LoadDrvWskViaSCM: Activating kernel transport via CreateFile payload (Token + BootConfig)...");
        return ActivateDriverTransport(pBootConfig, pBootConfigEx);
    }

    return true;
}
