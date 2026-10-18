#pragma once
#include "loader_common.h"
#include <winsvc.h>

// ============================================================
// scm_loader.h — Windows 原生服务控制管理器 (SCM) 驱动加载实现
//
// 适用场景：
//   当 MODE_MANUAL_MAP_CAVE 与 MODE_MANUAL_MAP 均未开启时，
//   直接调用系统原生 SCM API (CreateService / StartService) 正常加载驱动。
//   无需漏洞利用驱动，无需 Shellcode，符合 Windows 原生驱动安装启动规范。
// ============================================================

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

    LOG_INFO("ActivateDriverTransport: Opening driver device '%ls' with dynamic Token & BootConfig payload...", MK_USER_DEVICE_NAME);

    // 默认带 Token 和参数传入：在 CreateFile 阶段通过路径透传 Token 与 HexPayload 载荷，
    // 驱动端 DispatchCreate 内部自动完成鉴权并拉起传输服务，无需额外发送 IO 控制码。
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

inline bool LoadDrvWskViaSCM(const wchar_t* drvPath, const wchar_t* serviceName = L"mswsk", bool forceReload = false, const DRV_BOOT_CONFIG* pBootConfig = nullptr, const DRV_BOOT_CONFIG_EX* pBootConfigEx = nullptr)
{
    LOG_INFO("LoadDrvWskViaSCM: Using standard Windows Service Control Manager pipeline...");

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

    if (forceReload) {
        LOG_WARN("LoadDrvWskViaSCM: Force reload requested, stopping and removing existing service '%ls'...", serviceName);
        StopAndRemoveService(hSCManager, serviceName);
        Sleep(200);
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_ALL_ACCESS);
    if (!hService) {
        LOG_INFO("LoadDrvWskViaSCM: Creating new kernel service '%ls' -> '%ls'...", serviceName, fullPath);
        hService = CreateServiceW(
            hSCManager,
            serviceName,
            serviceName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            fullPath,
            NULL, NULL, NULL, NULL, NULL
        );

        if (!hService) {
            DWORD gle = GetLastError();
            LOG_ERR("LoadDrvWskViaSCM: CreateServiceW failed (GLE=%lu)", gle);
            CloseServiceHandle(hSCManager);
            return false;
        }
    } else {
        LOG_INFO("LoadDrvWskViaSCM: Service '%ls' already exists, updating binary path...", serviceName);
        ChangeServiceConfigW(
            hService,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            fullPath,
            NULL, NULL, NULL, NULL, NULL, NULL
        );
    }

    // 检查服务当前状态
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    bool alreadyRunning = false;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            LOG_OK("LoadDrvWskViaSCM: Service '%ls' is already in running state.", serviceName);
            alreadyRunning = true;
        }
    }

    if (!alreadyRunning) {
        LOG_INFO("LoadDrvWskViaSCM: Starting kernel service '%ls'...", serviceName);
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
            LOG_OK("LoadDrvWskViaSCM: Kernel service '%ls' successfully started via SCM!", serviceName);
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
