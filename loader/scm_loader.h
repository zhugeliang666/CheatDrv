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

inline bool SendBootConfigViaIOCTL(const DRV_BOOT_CONFIG* pBootConfig)
{
    if (!pBootConfig) {
        LOG_ERR("SendBootConfigViaIOCTL: pBootConfig is null!");
        return false;
    }

    LOG_INFO("SendBootConfigViaIOCTL: Opening driver device '%ls'...", MK_USER_DEVICE_NAME);

    // 驱动刚启动注册符号链接可能有短暂延迟，执行安全重试
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    for (int retry = 0; retry < 25; ++retry) {
        hDevice = CreateFileW(
            MK_USER_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hDevice != INVALID_HANDLE_VALUE) {
            break;
        }
        Sleep(100);
    }

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        LOG_ERR("SendBootConfigViaIOCTL: Failed to open '%ls' (GLE=%lu)", MK_USER_DEVICE_NAME, gle);
        return false;
    }

    const wchar_t* modeStr = L"TCP";
    if (pBootConfig->TransportMode == DRV_TRANSPORT_UDP) modeStr = L"UDP";
    else if (pBootConfig->TransportMode == DRV_TRANSPORT_USB) modeStr = L"USB";

    LOG_INFO("SendBootConfigViaIOCTL: Sending IOCTL_MK_START_TRANSPORT (Mode=%ls, Port=%u, Token=0x%08X)...",
             modeStr, pBootConfig->Port, pBootConfig->AuthToken);

    DWORD bytesReturned = 0;
    BOOL ioOk = DeviceIoControl(
        hDevice,
        IOCTL_MK_START_TRANSPORT,
        (LPVOID)pBootConfig,
        sizeof(DRV_BOOT_CONFIG),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!ioOk) {
        DWORD gle = GetLastError();
        LOG_ERR("SendBootConfigViaIOCTL: DeviceIoControl(IOCTL_MK_START_TRANSPORT) failed (GLE=%lu)", gle);
        CloseHandle(hDevice);
        return false;
    }

    LOG_OK("SendBootConfigViaIOCTL: Successfully started [%ls] service in kernel driver!", modeStr);

    // 查询当前运行状态以校验
    ULONG status = 0;
    if (DeviceIoControl(hDevice, IOCTL_MK_GET_STATUS, NULL, 0, &status, sizeof(status), &bytesReturned, NULL)) {
        LOG_INFO("SendBootConfigViaIOCTL: Driver transport status verified (code=%lu)", status);
    }

    CloseHandle(hDevice);
    return true;
}

inline bool SendStopTransportViaIOCTL()
{
    HANDLE hDevice = CreateFileW(
        MK_USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hDevice == INVALID_HANDLE_VALUE) {
        LOG_ERR("SendStopTransportViaIOCTL: Failed to open device '%ls' (GLE=%lu)", MK_USER_DEVICE_NAME, GetLastError());
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

inline bool LoadDrvWskViaSCM(const wchar_t* drvPath, const wchar_t* serviceName = L"drv_wsk", bool forceReload = false, const DRV_BOOT_CONFIG* pBootConfig = nullptr)
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
                    LOG_ERR("LoadDrvWskViaSCM: GLE=577 (Windows 驱动数字签名校验失败，请开启测试签名模式或禁用驱动强制签名)");
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

    // 若指定了启动配置，则通过 IO 控制码向驱动发送启动指令
    if (pBootConfig) {
        LOG_INFO("LoadDrvWskViaSCM: Configuring and starting kernel transport via IOCTL...");
        return SendBootConfigViaIOCTL(pBootConfig);
    }

    return true;
}
