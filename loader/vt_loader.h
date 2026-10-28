#pragma once
// ============================================================
// vt_loader.h — VT 框架 (mapDriver.sys + payloadRuntime.sys) R3 编排与控制引擎
//
// 严格遵循：
// 1. 纯静态类 (Pure Static Class) 规范：0 虚函数、0 vtable、0 胶水包装层
// 2. 100% 完整迁移 mapctl_ioctl.h 全部 27 个 IOCTL 控制命令与一键驻留移交 (onekey) 状态机
// 3. 支持宏 ENABLE_VT_FRAMEWORK 编译期开关 + 命令行 (--vt / --no-vt / --vt-cmd) 动态调度
// ============================================================

#include "loader_common.h"
#include "../vt/VtBootstrapDriver/common/payload_abi.h"
#include "../vt/VtBootstrapDriver/common/mapctl_ioctl.h"

static_assert(MAPCTL_HV_DIAG_LAYOUT_VERSION == 27ull,
              "loader and VtBootstrapDriver must use the same HV diagnostic ABI");
static_assert(sizeof(mapctl_hv_diag) == 0x650,
              "mapctl_hv_diag layout drifted; rebuild loader and bootstrap together");
static_assert(sizeof(mapctl_migration_check) == 0x2728,
              "mapctl_migration_check layout drifted; rebuild loader and bootstrap together");

class VtLoader
{
  public:
    // 打开控制设备 (优先 \\.\MapPayloadCtl，回退 \\.\PayloadResidentCtl)
    static HANDLE OpenControlDevice(bool quiet = false)
    {
        HANDLE hDev = CreateFileW(MAPCTL_USER_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
        if (hDev != INVALID_HANDLE_VALUE)
        {
            return hDev;
        }
        hDev = CreateFileW(PAYLOADCTL_USER_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hDev == INVALID_HANDLE_VALUE && !quiet)
        {
            LOG_WARN("[VT] Control device not open yet (GLE=%lu)", GetLastError());
        }
        return hDev;
    }

    // A failed CreateFile is not, by itself, proof that the control device is
    // gone (ACCESS_DENIED, sharing violations, and transient teardown errors
    // are all possible).  Keep the three outcomes separate so FullUnloadVt()
    // cannot turn an unobservable device into a successful unload.
    enum class ControlDeviceState
    {
        Present,
        Gone,
        Unknown,
    };

    static bool IsControlDeviceMissingError(DWORD error)
    {
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
               error == ERROR_INVALID_NAME || error == ERROR_BAD_PATHNAME;
    }

    static ControlDeviceState ProbeControlDevice(DWORD *outError = nullptr)
    {
        const wchar_t *const names[] = {MAPCTL_USER_DEVICE_NAME, PAYLOADCTL_USER_DEVICE_NAME};
        DWORD lastError = ERROR_SUCCESS;
        bool unknown = false;
        for (const wchar_t *name : names)
        {
            HANDLE const h = CreateFileW(name,
                                         GENERIC_READ | GENERIC_WRITE,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         nullptr,
                                         OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL,
                                         nullptr);
            if (h != INVALID_HANDLE_VALUE)
            {
                CloseHandle(h);
                if (outError)
                    *outError = ERROR_SUCCESS;
                return ControlDeviceState::Present;
            }

            DWORD const error = GetLastError();
            lastError = error;
            if (!IsControlDeviceMissingError(error))
                unknown = true;
        }

        if (outError)
            *outError = lastError;
        return unknown ? ControlDeviceState::Unknown : ControlDeviceState::Gone;
    }

    // Prefer the actual MSBuild output under bin\vt.  A compatibility copy may
    // also exist beside loader.exe, but it can lag behind the signed project
    // output when parallel project instances finish in a different order.
    static bool SelectBootstrapDriverPath(const wchar_t *exeDir, wchar_t (&outPath)[MAX_PATH])
    {
        wchar_t pathBuild[MAX_PATH] = {};
        wchar_t pathVt[MAX_PATH] = {};
        wchar_t pathMap[MAX_PATH] = {};
        swprintf_s(pathBuild, L"%svt\\VtBootstrapDriver.sys", exeDir);
        swprintf_s(pathVt, L"%sVtBootstrapDriver.sys", exeDir);
        swprintf_s(pathMap, L"%smapDriver.sys", exeDir);

        WIN32_FILE_ATTRIBUTE_DATA fadBuild = {};
        WIN32_FILE_ATTRIBUTE_DATA fadVt = {};
        WIN32_FILE_ATTRIBUTE_DATA fadMap = {};
        BOOL hasBuild = GetFileAttributesExW(pathBuild, GetFileExInfoStandard, &fadBuild);
        BOOL hasVt = GetFileAttributesExW(pathVt, GetFileExInfoStandard, &fadVt);
        BOOL hasMap = GetFileAttributesExW(pathMap, GetFileExInfoStandard, &fadMap);

        if (hasBuild && hasVt)
        {
            if (CompareFileTime(&fadVt.ftLastWriteTime, &fadBuild.ftLastWriteTime) > 0)
            {
                wcscpy_s(outPath, pathVt);
                LOG_INFO("[VT] SelectBootstrapDriverPath: newer root copy selected: %ls", outPath);
                return true;
            }
        }
        if (hasBuild)
        {
            wcscpy_s(outPath, pathBuild);
            LOG_INFO("[VT] SelectBootstrapDriverPath: canonical MSBuild output selected: %ls", outPath);
            return true;
        }
        if (hasVt)
        {
            wcscpy_s(outPath, pathVt);
            LOG_WARN("[VT] SelectBootstrapDriverPath: build output missing; compatibility copy selected: %ls", outPath);
            return true;
        }
        if (hasMap)
        {
            wcscpy_s(outPath, pathBuild);
            LOG_ERR("[VT] SelectBootstrapDriverPath: refusing legacy-only image %ls; deploy the matching %ls",
                    pathMap, pathBuild);
            return false;
        }
        wcscpy_s(outPath, pathBuild);
        return false;
    }

    // 通过 SCM 加载 mapDriver.sys
    static bool LoadMapDriverService(const wchar_t *driverPath, const wchar_t *serviceName = L"MsPmtSvc")
    {

        WIN32_FILE_ATTRIBUTE_DATA driverData = {};
        if (!GetFileAttributesExW(driverPath, GetFileExInfoStandard, &driverData))
        {
            LOG_ERR("[VT] Bootstrap image metadata query failed: %ls (GLE=%lu)", driverPath, GetLastError());
            return false;
        }
        ULARGE_INTEGER driverBytes = {};
        driverBytes.HighPart = driverData.nFileSizeHigh;
        driverBytes.LowPart = driverData.nFileSizeLow;
        LOG_INFO("[VT] Bootstrap image identity: path=%ls size=%llu write=%08lX:%08lX",
                 driverPath,
                 driverBytes.QuadPart,
                 driverData.ftLastWriteTime.dwHighDateTime,
                 driverData.ftLastWriteTime.dwLowDateTime);

        SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!hScm)
        {
            LOG_ERR("[VT] OpenSCManagerW failed (GLE=%lu)", GetLastError());
            return false;
        }

        const wchar_t *candidates[2] = {serviceName, L"MsPmtDrv"};
        DWORD lastStartErr = 0;

        for (int idx = 0; idx < 2; ++idx)
        {
            const wchar_t *curName = candidates[idx];
            LOG_INFO("[VT] Trying service candidate #%d: '%ls' -> %ls", idx + 1, curName, driverPath);
            SC_HANDLE hSvc = CreateServiceW(hScm, curName, curName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath, nullptr, nullptr,
                                            nullptr, nullptr, nullptr);
            if (!hSvc)
            {
                DWORD gle = GetLastError();
                LOG_INFO("[VT] CreateServiceW('%ls') returned GLE=%lu, attempting OpenServiceW...", curName, gle);
                if (gle == ERROR_SERVICE_EXISTS || gle == ERROR_DUPLICATE_SERVICE_NAME ||
                    gle == ERROR_SERVICE_MARKED_FOR_DELETE)
                {
                    hSvc = OpenServiceW(hScm, curName, SERVICE_ALL_ACCESS);
                    if (hSvc)
                    {
                        SERVICE_STATUS ss = {};
                        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
                        if (!ChangeServiceConfigW(hSvc, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                                  SERVICE_ERROR_NORMAL, driverPath, nullptr, nullptr, nullptr, nullptr,
                                                  nullptr, curName))
                        {
                            LOG_WARN("[VT] ChangeServiceConfigW('%ls') failed (GLE=%lu), switching to fallback service name...",
                                     curName, GetLastError());
                            DeleteService(hSvc);
                            CloseServiceHandle(hSvc);
                            hSvc = nullptr;
                            continue;
                        }
                        LOG_INFO("[VT] Updated existing service '%ls' image path to %ls", curName, driverPath);
                    }
                }
                if (!hSvc)
                {
                    lastStartErr = gle;
                    continue;
                }
            }

            LOG_INFO("[VT] Calling StartServiceW('%ls')...", curName);
            BOOL started = StartServiceW(hSvc, 0, nullptr);
            DWORD startErr = started ? ERROR_SUCCESS : GetLastError();
            if (!started && startErr != ERROR_SERVICE_ALREADY_RUNNING)
            {
                LOG_WARN("[VT] StartServiceW('%ls') failed with GLE=%lu", curName, startErr);
                lastStartErr = startErr;
                SERVICE_STATUS ss = {};
                ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
                DeleteService(hSvc);
                CloseServiceHandle(hSvc);
                if (startErr == ERROR_FILE_NOT_FOUND || startErr == ERROR_PATH_NOT_FOUND ||
                    startErr == ERROR_SERVICE_MARKED_FOR_DELETE || startErr == ERROR_SERVICE_DISABLED)
                {
                    continue;
                }
                break;
            }

            CloseServiceHandle(hSvc);
            CloseServiceHandle(hScm);
            LOG_OK("[VT] mapDriver service '%ls' started (%ls)", curName, driverPath);
            return true;
        }

        CloseServiceHandle(hScm);
        LOG_ERR("[VT] StartServiceW(%ls) failed (GLE=%lu)", driverPath, lastStartErr);
        return false;
    }

    // 通过 SCM 停止并移除 mapDriver.sys 服务
    static bool UnloadMapDriverService(const wchar_t *serviceName = L"MsPmtSvc")
    {
        SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!hScm)
        {
            return false;
        }

        SC_HANDLE hSvc = OpenServiceW(hScm, serviceName, SERVICE_ALL_ACCESS);
        if (!hSvc)
        {
            DWORD gle = GetLastError();
            CloseServiceHandle(hScm);
            return gle == ERROR_SERVICE_DOES_NOT_EXIST;
        }

        SERVICE_STATUS ss = {};
        BOOL stopIssued = ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        DWORD stopError = stopIssued ? ERROR_SUCCESS : GetLastError();
        bool stopped = stopIssued || stopError == ERROR_SERVICE_NOT_ACTIVE;
        if (stopIssued)
        {
            for (unsigned retry = 0; retry < 50; ++retry)
            {
                SERVICE_STATUS_PROCESS ssp = {};
                DWORD needed = 0;
                if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp),
                                          &needed))
                {
                    stopped = false;
                    break;
                }
                if (ssp.dwCurrentState == SERVICE_STOPPED)
                {
                    stopped = true;
                    break;
                }
                stopped = false;
                Sleep(100);
            }
        }

        BOOL deleteIssued = DeleteService(hSvc);
        DWORD deleteError = deleteIssued ? ERROR_SUCCESS : GetLastError();
        bool deleted = deleteIssued || deleteError == ERROR_SERVICE_MARKED_FOR_DELETE;
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        if (!stopped || !deleted)
            LOG_ERR("[VT] Service unload incomplete (stop=%d err=%lu delete=%d err=%lu)", stopped ? 1 : 0,
                    stopError, deleted ? 1 : 0, deleteError);
        return stopped && deleted;
    }

    static bool IsMapDriverServiceStoppedOrMissing(const wchar_t *serviceName)
    {
        SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hScm)
            return false;

        SC_HANDLE hSvc = OpenServiceW(hScm, serviceName, SERVICE_QUERY_STATUS);
        if (!hSvc)
        {
            DWORD const gle = GetLastError();
            CloseServiceHandle(hScm);
            return gle == ERROR_SERVICE_DOES_NOT_EXIST;
        }

        SERVICE_STATUS_PROCESS status = {};
        DWORD needed = 0;
        bool const stopped =
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed) != FALSE &&
            status.dwCurrentState == SERVICE_STOPPED;
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return stopped;
    }

    // 完成驻留交接后删除控制设备并通过 SCM 解除 Bootstrap 映像。
    // 两个服务名都处理，覆盖 LoadMapDriverService 的回退候选。
    static bool ReleaseResidentBootstrap(HANDLE existingDevice = INVALID_HANDLE_VALUE)
    {
        HANDLE hDev = existingDevice;
        if (hDev == INVALID_HANDLE_VALUE)
        {
            hDev = OpenControlDevice(true);
            if (hDev == INVALID_HANDLE_VALUE)
            {
                // 没有控制设备时无法证明驻留卸载入口已经安装；只接受服务本来
                // 就已停止/不存在，绝不盲目触发旧 Bootstrap DriverUnload。
                bool const primaryGone = IsMapDriverServiceStoppedOrMissing(L"MsPmtSvc");
                bool const fallbackGone = IsMapDriverServiceStoppedOrMissing(L"MsPmtDrv");
                return primaryGone && fallbackGone;
            }
        }

        DWORD bytesRet = 0;
        BOOL const handedOff = DeviceIoControl(
            hDev,
            MAPCTL_IOCTL_HANDOFF_DROPCTL,
            nullptr,
            0,
            nullptr,
            0,
            &bytesRet,
            nullptr);
        DWORD const handoffError = handedOff ? ERROR_SUCCESS : GetLastError();
        CloseHandle(hDev);
        if (!handedOff)
        {
            LOG_ERR("[VT] Resident Bootstrap release handoff failed (GLE=%lu)", handoffError);
            return false;
        }

        bool const primaryGone = UnloadMapDriverService(L"MsPmtSvc");
        bool const fallbackGone = UnloadMapDriverService(L"MsPmtDrv");
        HANDLE const verify = OpenControlDevice(true);
        bool const controlGone = verify == INVALID_HANDLE_VALUE;
        if (verify != INVALID_HANDLE_VALUE)
            CloseHandle(verify);

        bool const ok = primaryGone && fallbackGone && controlGone;
        LOG_INFO("[VT] Resident Bootstrap release: ok=%d primary=%d fallback=%d control_gone=%d",
                 ok ? 1 : 0,
                 primaryGone ? 1 : 0,
                 fallbackGone ? 1 : 0,
                 controlGone ? 1 : 0);
        return ok;
    }

    // 查询状态 (MAPCTL_IOCTL_STATUS)
    static bool QueryStatus(HANDLE hDev, mapctl_status *outStatus)
    {
        if (!outStatus || hDev == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        ZeroMemory(outStatus, sizeof(*outStatus));
        DWORD bytesRet = 0;
        if (!DeviceIoControl(hDev, MAPCTL_IOCTL_STATUS, nullptr, 0, outStatus, sizeof(*outStatus), &bytesRet, nullptr))
        {
            return false;
        }
        return (bytesRet >= sizeof(payload_u64) && outStatus->magic == MAPCTL_STATUS_MAGIC);
    }

    static bool QueryStatus(mapctl_status *outStatus)
    {
        HANDLE hDev = OpenControlDevice(true);
        if (hDev == INVALID_HANDLE_VALUE)
            return false;
        bool ok = QueryStatus(hDev, outStatus);
        CloseHandle(hDev);
        return ok;
    }

    // 打印详细状态
    static void PrintStatus(const mapctl_status &st)
    {
        printf("=======================================================\n");
        printf(" [VT Status] magic=0x%llX hv_ready=%llu payload_detached=%llu\n", st.magic, st.hv_ready,
               st.payload_detached);
        printf("   VtHypervisor : base=0x%llX size=0x%llX unloaded=%llu quarantined=%llu\n", st.test_base, st.test_size,
               st.test_unloaded, st.test_quarantined);
        printf("   Payload    : base=0x%llX size=0x%llX independent=%llu barrier_ok=%llu\n", st.payload_base,
               st.payload_size, st.payload_independent, st.payload_barrier_ok);
        printf("   Runtime    : phase=%llu flags=0x%llX gen=%llu arena=0x%llX (used=0x%llX/0x%llX)\n",
               st.payload.runtime_phase, st.payload.runtime_flags, st.payload.runtime_generation, st.payload.arena_base,
               st.payload.arena_used, st.payload.arena_size);
        printf("   Bridge     : bridge=0x%llX target=0x%llX hits=%llu self_hc=%llu\n", st.payload.vmexit_bridge,
               st.payload.vmexit_bridge_target, st.payload.vmexit_bridge_hits, st.payload.vmexit_bridge_self_count);
        const char *mkModeStr = (st.machenike_mode == MAPCTL_MK_MODE_MANUAL_MAP)
                                    ? "ManualMap/NoSymlink/Hidden"
                                    : ((st.machenike_mode == MAPCTL_MK_MODE_NORMAL) ? "Normal/Symlink/Visible" : "None");
        printf("   Machenike  : loaded=%llu mode=%llu (%s) base=0x%llX size=0x%llX\n", st.machenike_loaded,
               st.machenike_mode, mkModeStr, st.machenike_base, st.machenike_size);
        printf("=======================================================\n");
    }

    // 按指定模式加载内嵌 Machenike 驱动:
    //   loadMode = MAPCTL_MK_MODE_NORMAL (1): 正常加载驱动（创建符号链接，不隐藏 Machenike 内存）
    //   loadMode = MAPCTL_MK_MODE_MANUAL_MAP (2): 内存映射驱动（不创建符号链接，直接启动服务并隐藏 Machenike 内存）
    static bool LoadEmbeddedMachenike(payload_u64 loadMode, const DRV_BOOT_CONFIG_EX *bootConfigEx = nullptr)
    {
        HANDLE hDev = OpenControlDevice(false);
        if (hDev == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        mapctl_load_machenike req = {};
        req.magic = MAPCTL_LOAD_MK_MAGIC;
        req.size = sizeof(req);
        req.arm = MAPCTL_LOAD_MK_ARM;
        req.load_mode = loadMode;
        if (bootConfigEx)
        {
            size_t copyLen = sizeof(*bootConfigEx) < sizeof(req.boot_config) ? sizeof(*bootConfigEx) : sizeof(req.boot_config);
            memcpy(req.boot_config, bootConfigEx, copyLen);
        }

        LOG_INFO("[VT] Sending MAPCTL_IOCTL_LOAD_MACHENIKE (mode=%llu, hasBootCfg=%d)...", loadMode, bootConfigEx ? 1 : 0);
        DWORD bytesRet = 0;
        BOOL ioOk = DeviceIoControl(hDev, MAPCTL_IOCTL_LOAD_MACHENIKE, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                                    nullptr);
        SecureZeroMemory(&req.boot_config, sizeof(req.boot_config));
        CloseHandle(hDev);

        if (!ioOk || bytesRet < sizeof(req) || req.result != PAYLOAD_RESULT_OK)
        {
            LOG_ERR("[VT] LoadEmbeddedMachenike(mode=%llu) failed (ioOk=%d, result=0x%llX, GLE=%lu)", loadMode, ioOk,
                    req.result, GetLastError());
            return false;
        }

        LOG_OK("[VT] Machenike loaded in %s mode (base=0x%llX, size=0x%llX)",
               (req.load_mode == MAPCTL_MK_MODE_MANUAL_MAP)
                   ? "ManualMap (No SymbolicLink, Memory Hidden)"
                   : "Normal (SymbolicLink Created, Memory Not Hidden)",
               req.machenike_base, req.machenike_size);
        return true;
    }

    // 检测三合一驱动 (VT + VtResidentPayload + Machenike) 是否已加载运行（防重复加载）
    static bool IsAlreadyLoaded(mapctl_status *outStatus = nullptr)
    {
        mapctl_status localSt = {};
        HANDLE hDev = OpenControlDevice(true);
        if (hDev != INVALID_HANDLE_VALUE)
        {
            bool ok = QueryStatus(hDev, &localSt);
            CloseHandle(hDev);
            if (ok)
            {
                if (outStatus)
                    *outStatus = localSt;
                if (localSt.hv_ready != 0 && localSt.machenike_loaded != 0)
                    return true;
            }
        }

        // 兜底探测：若已执行 dropctl 删除了 MapPayloadCtl，探测 \\.\MsNetEndpoint 是否存在
        HANDLE hMk = CreateFileW(MK_USER_DEVICE_NAME, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hMk != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hMk);
            if (outStatus)
                outStatus->machenike_loaded = 1;
            return true;
        }
        DWORD gle = GetLastError();
        if (gle == ERROR_ACCESS_DENIED)
        {
            if (outStatus)
                outStatus->machenike_loaded = 1;
            return true;
        }
        return false;
    }

    // 执行 HV Ping 与 Payload Ping
    static bool PingAll(HANDLE hDev)
    {
        mapctl_ping hvPing = {};
        hvPing.nonce = 0x1122334455667788ULL;
        DWORD bytesRet = 0;
        bool hvOk = DeviceIoControl(hDev, MAPCTL_IOCTL_HV_PING, &hvPing, sizeof(hvPing), &hvPing, sizeof(hvPing),
                                    &bytesRet, nullptr) &&
                    hvPing.result == PAYLOAD_RESULT_OK;

        mapctl_ping plPing = {};
        plPing.nonce = 0x1337C0DE55AA1234ULL;
        bool plOk = DeviceIoControl(hDev, MAPCTL_IOCTL_PAYLOAD_PING, &plPing, sizeof(plPing), &plPing, sizeof(plPing),
                                    &bytesRet, nullptr) &&
                    plPing.result == PAYLOAD_RESULT_OK;

        LOG_INFO("[VT] Ping result: HV=%s (pong=0x%llX), Payload=%s (pong=0x%llX)", hvOk ? "OK" : "FAIL", hvPing.pong,
                 plOk ? "OK" : "FAIL", plPing.pong);
        return hvOk && plOk;
    }

    // 执行迁移就绪检查 (MAPCTL_IOCTL_MIGRATE_CHECK)
    static bool MigrateCheck(HANDLE hDev, mapctl_migration_check *outCheck, bool *outAbiMismatch = nullptr)
    {
        if (outAbiMismatch)
            *outAbiMismatch = false;
        if (!outCheck || hDev == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        ZeroMemory(outCheck, sizeof(*outCheck));
        DWORD bytesRet = 0;
        BOOL const ioOk = DeviceIoControl(hDev, MAPCTL_IOCTL_MIGRATE_CHECK, nullptr, 0, outCheck, sizeof(*outCheck),
                                          &bytesRet, nullptr);
        if (!ioOk)
        {
            LOG_ERR("[VT] MigrateCheck failed (GLE=%lu, expected=%zu bytes, diag_layout=%llu)",
                    GetLastError(), sizeof(*outCheck), MAPCTL_HV_DIAG_LAYOUT_VERSION);
            return false;
        }
        if (bytesRet < sizeof(*outCheck))
        {
            LOG_ERR("[VT] MigrateCheck short reply (bytes=%lu/%zu, diag_layout=%llu)",
                    bytesRet, sizeof(*outCheck), MAPCTL_HV_DIAG_LAYOUT_VERSION);
            return false;
        }
        if (outCheck->magic != MAPCTL_MIGRATE_CHECK_MAGIC)
        {
            LOG_ERR("[VT] MigrateCheck bad magic (0x%llX, expected=0x%llX)",
                    outCheck->magic, MAPCTL_MIGRATE_CHECK_MAGIC);
            return false;
        }
        if (outCheck->diag.version != MAPCTL_HV_DIAG_LAYOUT_VERSION)
        {
            if (outAbiMismatch)
                *outAbiMismatch = true;
            LOG_ERR("[VT] MigrateCheck ABI mismatch (driver_diag=%llu loader_diag=%llu)",
                    outCheck->diag.version, MAPCTL_HV_DIAG_LAYOUT_VERSION);
            return false;
        }
        return true;
    }

    // Machenike 启动前的后端感知门禁。Intel 必须完成 HOST_RIP/RSP 驻留桥
    // 迁移；AMD 不存在 VMCS HOST_RIP，必须确认 VMRUN 闭环已经迁入 Payload。
    // 无转储硬复位闭环前允许旧 VtHypervisor 映像保持 unloaded+quarantined，
    // 自动释放重新成为显式配置，而不是 Machenike 启动的必要条件。
    static bool ValidateRuntimeForMachenike()
    {
        HANDLE hDev = OpenControlDevice(false);
        if (hDev == INVALID_HANDLE_VALUE)
        {
            LOG_ERR("[VT] Runtime validation failed: control device is unavailable.");
            return false;
        }

        mapctl_status st = {};
        mapctl_migration_check check = {};
        bool const statusOk = QueryStatus(hDev, &st);
        bool const pingOk = PingAll(hDev);
        bool const checkOk = MigrateCheck(hDev, &check);

        mapctl_smoke smoke = {};
        DWORD bytesRet = 0;
        bool const smokeOk =
            DeviceIoControl(hDev, MAPCTL_IOCTL_SMOKE, &smoke, sizeof(smoke),
                            &smoke, sizeof(smoke), &bytesRet, nullptr) != FALSE &&
            bytesRet >= sizeof(smoke) &&
            smoke.magic == MAPCTL_SMOKE_MAGIC &&
            smoke.result == PAYLOAD_RESULT_OK &&
            smoke.marker == MAPCTL_SMOKE_MARKER;

        bool const commonOk =
            statusOk &&
            st.hv_ready != 0 &&
            st.payload_base != 0 &&
            st.payload_size != 0 &&
            st.payload_independent != 0 &&
            st.payload_barrier_ok != 0 &&
            checkOk &&
            check.diag.vcpu_count != 0 &&
            check.diag.ghv != 0 &&
            check.diag.vmcs_host_rsp != 0 &&
            check.payload.hv_diag_cache_ready != 0;

        bool const amd = (check.diag.flags & 2ull) != 0;
        payload_u64 const intelActiveMask =
            MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_BRIDGE |
            MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD;
        // AMD 的 released 与 retained-quarantine 都是受支持的稳定状态。
        // 两者都必须完成 legacy detach、保留 resident-loop/ack 布局证据，
        // 并清零只属于旧映像的两个 VM-exit 目标。
        bool const amdLegacyDetached =
            st.payload_detached != 0 &&
            st.test_unloaded != 0 &&
            st.test_quarantined != 0 &&
            check.payload.legacy_detached != 0 &&
            check.payload.legacy_detach_result == PAYLOAD_RESULT_OK &&
            (check.payload.legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) != 0 &&
            check.diag.vcpu_off_svm_resident_loop != 0 &&
            check.diag.vcpu_off_svm_resident_ack != 0 &&
            check.payload.vmexit_target == 0 &&
            check.payload.vmexit_bridge_target == 0;
        bool const amdLegacyReleased =
            amdLegacyDetached &&
            st.test_base == 0 &&
            st.test_size == 0;
        bool const amdLegacyRetained =
            amdLegacyDetached &&
            st.test_base != 0 &&
            st.test_size != 0;
        bool const intelTargetsReady =
            check.payload.vmexit_target != 0 &&
            check.payload.vmexit_target == check.diag.vm_exit &&
            check.payload.vmexit_bridge_target != 0 &&
            check.payload.vmexit_bridge_target == check.diag.handle_vm_exit;
        bool const backendOk = amd
            ? (check.diag.vmcs_host_rip == 0 && (amdLegacyReleased || amdLegacyRetained))
            : (check.result == PAYLOAD_RESULT_OK &&
               (check.flags & intelActiveMask) == intelActiveMask &&
               check.payload.legacy_detached != 0 &&
               intelTargetsReady);

        bool const ok = commonOk && backendOk && pingOk && smokeOk;
        LOG_INFO("[VT] Final runtime validation: ok=%d backend=%s status=%d common_gate=%d ping=%d backend_gate=%d smoke=%d vcpus=%llu flags=0x%llX test=0x%llX/%llu unloaded=%llu quarantined=%llu payload=0x%llX vmexit=0x%llX/0x%llX bridge=0x%llX/0x%llX diag_cache=%llu",
                 ok ? 1 : 0,
                 amd ? "AMD-SVM/resident-vmrun" : "Intel-VMX/resident-bridge",
                 statusOk ? 1 : 0,
                 commonOk ? 1 : 0,
                 pingOk ? 1 : 0,
                 backendOk ? 1 : 0,
                 smokeOk ? 1 : 0,
                 check.diag.vcpu_count,
                 check.flags,
                 st.test_base,
                 st.test_size,
                 st.test_unloaded,
                 st.test_quarantined,
                 st.payload_base,
                 check.payload.vmexit_target,
                 check.diag.vm_exit,
                 check.payload.vmexit_bridge_target,
                 check.diag.handle_vm_exit,
                 check.payload.hv_diag_cache_ready);
        CloseHandle(hDev);
        return ok;
    }

    static bool ValidateMachenikeLoaded(payload_u64 expectedMode)
    {
        HANDLE hDev = OpenControlDevice(false);
        if (hDev == INVALID_HANDLE_VALUE)
        {
            LOG_ERR("[VT] Machenike validation failed: control device is unavailable.");
            return false;
        }

        mapctl_status st = {};
        bool const queried = QueryStatus(hDev, &st);
        CloseHandle(hDev);
        bool const ok =
            queried &&
            st.hv_ready != 0 &&
            st.machenike_loaded != 0 &&
            st.machenike_mode == expectedMode &&
            st.machenike_base != 0 &&
            st.machenike_size != 0;
        LOG_INFO("[VT] Machenike validation: ok=%d queried=%d mode=%llu/%llu base=0x%llX size=0x%llX",
                 ok ? 1 : 0,
                 queried ? 1 : 0,
                 st.machenike_mode,
                 expectedMode,
                 st.machenike_base,
                 st.machenike_size);
        return ok;
    }

    // 执行内存隐藏校验 (MAPCTL_IOCTL_MEMCHECK)
    static bool RunMemCheck(HANDLE hDev, payload_u64 flags = MAPCTL_MEMCHECK_FLAG_ALL, bool repair = false)
    {
        if (hDev == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        mapctl_memcheck req = {};
        req.magic = MAPCTL_MEMCHECK_MAGIC;
        req.size = sizeof(req);
        req.flags = flags | (repair ? MAPCTL_MEMCHECK_FLAG_REPAIR : 0ULL);

        DWORD bytesRet = 0;
        if (!DeviceIoControl(hDev, MAPCTL_IOCTL_MEMCHECK, &req, sizeof(req), &req, sizeof(req), &bytesRet, nullptr))
        {
            LOG_ERR("[VT] MAPCTL_IOCTL_MEMCHECK failed (GLE=%lu)", GetLastError());
            return false;
        }

        LOG_INFO("[VT] MemCheck: result=0x%llX checked=%llu hidden=%llu visible=%llu unknown=%llu (dummy_pfn=0x%llX)",
                 req.result, req.checked_pages, req.hidden_pages, req.visible_pages, req.unknown_pages, req.dummy_pfn);
        return req.result == PAYLOAD_RESULT_OK;
    }

    // 执行内存管理过滤链审计，验证驻留载荷接管后的业务路径。
    static bool RunMemoryAudit(HANDLE hDev, payload_u64 flags = MAPCTL_MEMORY_AUDIT_OP_ALL)
    {
        if (hDev == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        mapctl_mmtest req = {};
        req.magic = MAPCTL_MEMORY_AUDIT_MAGIC;
        req.size = sizeof(req);
        req.flags = flags;
        req.target_kind = MAPCTL_MEMORY_AUDIT_KIND_AUTO;

        DWORD bytesRet = 0;
        if (!DeviceIoControl(hDev, MAPCTL_IOCTL_MEMORY_AUDIT, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                             nullptr))
        {
            LOG_ERR("[VT] MAPCTL_IOCTL_MEMORY_AUDIT failed (GLE=%lu)", GetLastError());
            return false;
        }

        LOG_INFO("[VT] MmTest: result=0x%llX target_va=0x%llX mmcm_qword=0x%llX mmisav=%llu mmgpa=0x%llX", req.result,
                 req.target_va, req.mmcopy_virtual_qword, req.mmisav_result, req.mmgpa_pa);
        return req.result == PAYLOAD_RESULT_OK;
    }

    // 一键完整驻留化移交 (onekey):
    //   1. 检查或加载 mapDriver.sys
    //   2. 若已处于 Resident Bridge 态则直接复用
    //   3. 否则依次执行: migrate_check -> legacy_detach -> switch_rsp -> switch_bridge -> migrate_check -> handoff -> cutover
    static bool EnsureVtOneKeyActive(const wchar_t *exeDir, bool dropControlDevice = false)
    {
        HANDLE hDev = OpenControlDevice(true);
        if (hDev != INVALID_HANDLE_VALUE)
        {
            mapctl_status preSt = {};
            bool statusOk = QueryStatus(hDev, &preSt);
            LOG_INFO("[VT] Existing control device detected: statusOk=%d hv_ready=%llu payload_detached=%llu mk_loaded=%llu",
                     statusOk ? 1 : 0, preSt.hv_ready, preSt.payload_detached, preSt.machenike_loaded);
            if (!statusOk || !preSt.hv_ready)
            {
                LOG_WARN("[VT] Stale/orphaned control device detected (hv_ready=0), closing and reloading bootstrap driver...");
                CloseHandle(hDev);
                hDev = INVALID_HANDLE_VALUE;
            }
        }
        if (hDev == INVALID_HANDLE_VALUE)
        {
            wchar_t mapDrvPath[MAX_PATH] = {};
            if (!SelectBootstrapDriverPath(exeDir, mapDrvPath))
            {
                LOG_WARN("[VT] VtBootstrapDriver.sys / mapDriver.sys not found at %ls", mapDrvPath);
                return false;
            }
            LOG_INFO("[VT] Loading mapDriver.sys from %ls...", mapDrvPath);
            if (!LoadMapDriverService(mapDrvPath))
            {
                return false;
            }
            wchar_t oldDrvPath[MAX_PATH] = {};
            swprintf_s(oldDrvPath, L"%sVtBootstrapDriver.sys.old", exeDir);
            DeleteFileW(oldDrvPath);
            for (int retry = 0; retry < 20; ++retry)
            {
                hDev = OpenControlDevice(true);
                if (hDev != INVALID_HANDLE_VALUE)
                {
                    break;
                }
                Sleep(100);
            }
            if (hDev == INVALID_HANDLE_VALUE)
            {
                LOG_ERR("[VT] Failed to open %ls after loading mapDriver.sys", MAPCTL_USER_DEVICE_NAME);
                return false;
            }
        }

        // 检查是否已经完成 Resident Bridge 接管
        mapctl_migration_check check = {};
        bool abiMismatch = false;
        if (MigrateCheck(hDev, &check, &abiMismatch))
        {
            if (check.diag.flags == 2 && check.diag.vcpu_count > 0)
            {
                LOG_OK("[VT] AMD SVM Hypervisor active (vcpus=%llu, ghv=0x%llX)",
                       check.diag.vcpu_count, check.diag.ghv);
                if (dropControlDevice)
                    return ReleaseResidentBootstrap(hDev);
                CloseHandle(hDev);
                return true;
            }
            const payload_u64 activeMask =
                MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_BRIDGE | MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD;
            if ((check.flags & activeMask) == activeMask && check.payload.legacy_detached)
            {
                LOG_OK("[VT] Resident VT Hypervisor already active (flags=0x%llX, host_rip=0x%llX)", check.flags,
                       check.diag.vmcs_host_rip);
                if (dropControlDevice)
                    return ReleaseResidentBootstrap(hDev);
                CloseHandle(hDev);
                return true;
            }
        }
        if (abiMismatch)
        {
            LOG_ERR("[VT] Bootstrap/Loader ABI mismatch is terminal; replace the compatibility image with the current bin\\vt\\VtBootstrapDriver.sys.");
            CloseHandle(hDev);
            return false;
        }

        // Step 1: 等待 Pre-Switch 就绪
        const payload_u64 preSwitchMask =
            MAPCTL_MIGRATE_CHECK_PAYLOAD_READY | MAPCTL_MIGRATE_CHECK_HV_DIAG_READY |
            MAPCTL_MIGRATE_CHECK_OLD_RIP_IS_VMEXIT | MAPCTL_MIGRATE_CHECK_OLD_RSP_IN_STACK |
            MAPCTL_MIGRATE_CHECK_PAYLOAD_STACK_READY | MAPCTL_MIGRATE_CHECK_VCPU_COUNT_FITS |
            MAPCTL_MIGRATE_CHECK_VMEXIT_TRAMP_READY | MAPCTL_MIGRATE_CHECK_VMEXIT_BRIDGE_READY;

        bool preReady = false;
        for (int waitIdx = 0; waitIdx < 100; ++waitIdx)
        {
            abiMismatch = false;
            if (MigrateCheck(hDev, &check, &abiMismatch) && (check.flags & preSwitchMask) == preSwitchMask)
            {
                preReady = true;
                break;
            }
            if (abiMismatch)
            {
                LOG_ERR("[VT] Pre-switch migration stopped: Bootstrap/Loader ABI mismatch; no retry will be issued.");
                break;
            }
            Sleep(50);
        }
        if (!preReady)
        {
            LOG_ERR("[VT] Pre-switch migration check timeout (flags=0x%llX, result=0x%llX)", check.flags, check.result);
            CloseHandle(hDev);
            return false;
        }

        DWORD bytesRet = 0;

        // Step 2: Legacy Detach (迁移 ghv / vt_hook_table / pool manifest 到 Resident Arena)
        mapctl_legacy_detach legacy = {};
        legacy.magic = MAPCTL_LEGACY_DETACH_MAGIC;
        legacy.size = sizeof(legacy);
        legacy.arm = MAPCTL_LEGACY_DETACH_ARM;
        legacy.mode = PAYLOAD_LEGACY_DETACH_MODE_ARM;
        if (!DeviceIoControl(hDev, MAPCTL_IOCTL_LEGACY_DETACH, &legacy, sizeof(legacy), &legacy, sizeof(legacy),
                             &bytesRet, nullptr) ||
            legacy.result != PAYLOAD_RESULT_OK || (legacy.new_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0)
        {
            LOG_ERR("[VT] Legacy detach failed (result=0x%llX, stage=%llu, flags=0x%llX)", legacy.result, legacy.stage,
                    legacy.new_flags);
            CloseHandle(hDev);
            return false;
        }
        LOG_OK("[VT] Step 1/5 Legacy detach complete (ghv=0x%llX, vt_hook=0x%llX)", legacy.ghv_copy,
               legacy.vt_hook_copy);

        // Step 3: 切换全核 VMCS_HOST_RSP 至 Payload 独立宿主栈
        mapctl_host_rsp_switch rspSwitch = {};
        rspSwitch.magic = MAPCTL_HOST_RSP_SWITCH_MAGIC;
        rspSwitch.size = sizeof(rspSwitch);
        rspSwitch.arm = MAPCTL_HOST_RSP_SWITCH_ARM;
        if (!DeviceIoControl(hDev, MAPCTL_IOCTL_HOST_RSP_SWITCH, &rspSwitch, sizeof(rspSwitch), &rspSwitch,
                             sizeof(rspSwitch), &bytesRet, nullptr) ||
            rspSwitch.result != PAYLOAD_RESULT_OK)
        {
            LOG_ERR("[VT] Host RSP switch failed (result=0x%llX, switched=%llu/%llu)", rspSwitch.result,
                    rspSwitch.switched_count, rspSwitch.requested_count);
            CloseHandle(hDev);
            return false;
        }
        LOG_OK("[VT] Step 2/5 Host RSP switched (%llu/%llu vCPUs -> 0x%llX)", rspSwitch.switched_count,
               rspSwitch.requested_count, rspSwitch.last_new_rsp);

        // Step 4: 切换全核 VMCS_HOST_RIP 至 PayloadVmExitBridge
        mapctl_host_rip_switch bridgeSwitch = {};
        bridgeSwitch.magic = MAPCTL_HOST_RIP_SWITCH_MAGIC;
        bridgeSwitch.size = sizeof(bridgeSwitch);
        bridgeSwitch.arm = MAPCTL_HOST_RIP_SWITCH_ARM;
        if (!DeviceIoControl(hDev, MAPCTL_IOCTL_HOST_BRIDGE_SWITCH, &bridgeSwitch, sizeof(bridgeSwitch), &bridgeSwitch,
                             sizeof(bridgeSwitch), &bytesRet, nullptr) ||
            bridgeSwitch.result != PAYLOAD_RESULT_OK)
        {
            LOG_ERR("[VT] Host RIP bridge switch failed (result=0x%llX, switched=%llu/%llu)", bridgeSwitch.result,
                    bridgeSwitch.switched_count, bridgeSwitch.requested_count);
            CloseHandle(hDev);
            return false;
        }
        LOG_OK("[VT] Step 3/5 Host RIP switched to PayloadVmExitBridge (%llu/%llu vCPUs -> 0x%llX)",
               bridgeSwitch.switched_count, bridgeSwitch.requested_count, bridgeSwitch.last_new_rip);

        // Step 5: Handoff & Cutover
        // 最终 DROPCTL 由 ReleaseResidentBootstrap 在仍持有句柄时完成；先做
        // 普通 handoff，避免删除设备后失去安装驻留 DriverUnload 的确认通道。
        const DWORD handoffIoctl = MAPCTL_IOCTL_HANDOFF;
        if (!DeviceIoControl(hDev, handoffIoctl, nullptr, 0, nullptr, 0, &bytesRet, nullptr))
        {
            LOG_ERR("[VT] Handoff IOCTL failed (GLE=%lu)", GetLastError());
            CloseHandle(hDev);
            return false;
        }
        LOG_OK("[VT] Step 4/5 Handoff complete (dropctl=%d)", dropControlDevice ? 1 : 0);

        if (!dropControlDevice)
        {
            mapctl_cutover cut = {};
            cut.magic = MAPCTL_CUTOVER_MAGIC;
            cut.size = sizeof(cut);
            cut.arm = MAPCTL_CUTOVER_ARM;
            cut.mode = PAYLOAD_CUTOVER_MODE_RESTORE;
            if (DeviceIoControl(hDev, MAPCTL_IOCTL_CUTOVER, &cut, sizeof(cut), &cut, sizeof(cut), &bytesRet, nullptr) &&
                cut.result == PAYLOAD_RESULT_OK)
            {
                LOG_OK("[VT] Step 5/5 Cutover verified (old=0x%llX, new=0x%llX)", cut.old_target, cut.new_target);
            }
        }

        if (dropControlDevice)
        {
            return ReleaseResidentBootstrap(hDev);
        }
        CloseHandle(hDev);
        return true;
    }

    // 完整卸载 VT Hypervisor (MAPCTL_IOCTL_FULL_UNLOAD + SCM 服务移除)。
    //
    // 必须 fail closed：如果控制设备已经被 resident handoff 删除，就没有
    // 证据证明 hv::stop() 在所有处理器上完成。旧实现把 runtimeStopped 初始
    // 设为 true，导致“控制设备不存在 + 服务已删除”被误报为完整卸载成功。
    // 同样，FULL_UNLOAD 失败时不能继续卸载 Bootstrap 服务，否则会丢失重试
    // 和诊断通道，同时把仍在运行的 Hypervisor 留在内核中。
    static bool FullUnloadVt()
    {
        HANDLE hDev = OpenControlDevice(true);
        if (hDev == INVALID_HANDLE_VALUE)
        {
            DWORD const gle = GetLastError();
            LOG_ERR("[VT] FullUnload UNCONFIRMED: no control device is available (GLE=%lu). "
                    "Runtime stop is unverified; service removal was not attempted.",
                    gle);
            return false;
        }

        mapctl_full_unload req = {};
        req.magic = MAPCTL_FULL_UNLOAD_MAGIC;
        req.size = sizeof(req);
        req.arm = MAPCTL_FULL_UNLOAD_ARM;
        req.flags = MAPCTL_FULL_UNLOAD_DELETE_CONTROL;
        DWORD bytesRet = 0;
        BOOL const ioOk = DeviceIoControl(hDev, MAPCTL_IOCTL_FULL_UNLOAD,
                                          &req, sizeof(req), &req, sizeof(req),
                                          &bytesRet, nullptr);
        DWORD const ioError = ioOk ? ERROR_SUCCESS : GetLastError();
        CloseHandle(hDev);

        bool const replyComplete = bytesRet >= sizeof(req);
        bool const stopEvidence = req.hv_before == 0 || req.stop_result != 0 || req.selfstop_result == PAYLOAD_RESULT_OK;
        bool const runtimeStopped =
            ioOk &&
            replyComplete &&
            req.result == PAYLOAD_RESULT_OK &&
            req.hv_after == 0 &&
            stopEvidence &&
            req.test_after == 0 &&
            req.payload_after == 0;

        LOG_INFO("[VT] FullUnload IOCTL ok=%d gle=%lu bytes=%lu/%zu result=0x%llX "
                 "hv=%llu->%llu stop_evidence=%d delete_ctl=%llu test=0x%llX->0x%llX payload=0x%llX->0x%llX unhide_pfns=%llu",
                 ioOk ? 1 : 0,
                 ioError,
                 bytesRet,
                 sizeof(req),
                 req.result,
                 req.hv_before,
                 req.hv_after,
                 stopEvidence ? 1 : 0,
                 req.control_delete_queued,
                 req.test_before,
                 req.test_after,
                 req.payload_before,
                 req.payload_after,
                 req.unhide_pfns);

        if (!runtimeStopped)
        {
            LOG_ERR("[VT] FullUnload UNCONFIRMED: runtime teardown is incomplete; "
                    "Bootstrap services were intentionally kept for retry/diagnostics.");
            return false;
        }

        bool const primaryStopped = UnloadMapDriverService(L"MsPmtSvc");
        bool const fallbackStopped = UnloadMapDriverService(L"MsPmtDrv");
        DWORD controlProbeError = ERROR_SUCCESS;
        ControlDeviceState controlState = ControlDeviceState::Unknown;
        // Device deletion is queued by the IOCTL and may complete just after
        // the service stop returns.  Give it a bounded observation window, but
        // never convert Present/Unknown into Gone.
        for (unsigned retry = 0; retry < 20; ++retry)
        {
            controlState = ProbeControlDevice(&controlProbeError);
            if (controlState != ControlDeviceState::Present)
                break;
            Sleep(50);
        }
        bool const controlGone = controlState == ControlDeviceState::Gone;
        bool const controlPresent = controlState == ControlDeviceState::Present;
        bool const controlVerified = controlGone || controlPresent;

        // Service removal is only bookkeeping.  Hypervisor shutdown was
        // already proven by hv_after=0 in the FULL_UNLOAD reply; the control
        // device probe is an independent post-stop proof.  ACCESS_DENIED or
        // any other non-missing error is explicitly reported as unconfirmed.
        bool const complete = primaryStopped && fallbackStopped && controlGone;
        LOG_INFO("[VT] FullUnload final verification: ok=%d service_primary=%d service_fallback=%d "
                 "hv_after_zero=%d control_gone=%d control_present=%d control_verified=%d probe_gle=%lu",
                 complete ? 1 : 0,
                 primaryStopped ? 1 : 0,
                 fallbackStopped ? 1 : 0,
                 req.hv_after == 0 ? 1 : 0,
                 controlGone ? 1 : 0,
                 controlPresent ? 1 : 0,
                 controlVerified ? 1 : 0,
                 controlProbeError);
        if (!controlVerified)
        {
            LOG_ERR("[VT] FullUnload UNCONFIRMED: control device state could not be verified (GLE=%lu); "
                    "Hypervisor result was hv_after=%llu. Treating unload as failure.",
                    controlProbeError,
                    req.hv_after);
        }
        else if (controlPresent)
        {
            LOG_ERR("[VT] FullUnload failed: control device is still present after service stop; "
                    "hv_after=%llu was verified, but teardown is not complete.",
                    req.hv_after);
        }
        return complete;
    }

    // 一键卸载全部已知驱动服务。
    // 先完成 VT 全核停止并验证控制面已经消失，再处理独立 SCM 服务；
    // 控制设备缺失时只清理可观测的服务，并返回失败，避免把仍运行的 Resident
    // Hypervisor 误报为已卸载。
    static bool UnloadAllDrivers()
    {
        DWORD probeError = ERROR_SUCCESS;
        ControlDeviceState const controlState = ProbeControlDevice(&probeError);
        bool vtComplete = false;
        if (controlState == ControlDeviceState::Present)
        {
            vtComplete = FullUnloadVt();
        }
        else
        {
            LOG_ERR("[VT] UnloadAll: control device is not observable (state=%d, GLE=%lu); "
                    "Resident VT teardown cannot be proven.",
                    static_cast<int>(controlState), probeError);
        }

        bool servicesComplete = false;
        if (vtComplete || controlState == ControlDeviceState::Gone)
        {
            bool const pmtSvc = UnloadMapDriverService(L"MsPmtSvc");
            bool const pmtDrv = UnloadMapDriverService(L"MsPmtDrv");
            bool const mswsk = UnloadMapDriverService(L"mswsk");
            bool const machenike = UnloadMapDriverService(L"Machenike");
            servicesComplete = pmtSvc && pmtDrv && mswsk && machenike;
            LOG_INFO("[VT] UnloadAll services: MsPmtSvc=%d MsPmtDrv=%d mswsk=%d Machenike=%d",
                     pmtSvc ? 1 : 0,
                     pmtDrv ? 1 : 0,
                     mswsk ? 1 : 0,
                     machenike ? 1 : 0);
        }
        else
        {
            LOG_ERR("[VT] UnloadAll: service removal skipped because VT teardown was not verified.");
        }

        bool const complete = vtComplete && servicesComplete;
        LOG_INFO("[VT] UnloadAll result: ok=%d vt=%d services=%d",
                 complete ? 1 : 0,
                 vtComplete ? 1 : 0,
                 servicesComplete ? 1 : 0);
        return complete;
    }

    // 命令行子命令完整分发器 (--vt-cmd <cmd>)，覆盖原 mapctl.exe 100% 指令集
    static bool RunCliCommand(const wchar_t *exeDir, const wchar_t *cmd, const wchar_t *arg = nullptr)
    {
        if (!cmd || !cmd[0])
        {
            return false;
        }
        if (_wcsicmp(cmd, L"onekey") == 0)
        {
            return EnsureVtOneKeyActive(exeDir, false);
        }
        if (_wcsicmp(cmd, L"onekey_dropctl") == 0)
        {
            return EnsureVtOneKeyActive(exeDir, true);
        }
        if (_wcsicmp(cmd, L"unload") == 0 || _wcsicmp(cmd, L"full_unload") == 0)
        {
            return FullUnloadVt();
        }
        if (_wcsicmp(cmd, L"unload-all") == 0 || _wcsicmp(cmd, L"full-unload-all") == 0)
        {
            return UnloadAllDrivers();
        }
        if (_wcsicmp(cmd, L"load") == 0)
        {
            wchar_t mapDrvPath[MAX_PATH] = {};
            if (!SelectBootstrapDriverPath(exeDir, mapDrvPath))
            {
                LOG_ERR("[VT] Canonical VtBootstrapDriver.sys not found: %ls", mapDrvPath);
                return false;
            }
            return LoadMapDriverService(mapDrvPath);
        }

        HANDLE hDev = OpenControlDevice(false);
        if (hDev == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        DWORD bytesRet = 0;
        bool result = false;

        if (_wcsicmp(cmd, L"status") == 0)
        {
            mapctl_status st = {};
            result = QueryStatus(hDev, &st);
            if (result)
                PrintStatus(st);
        }
        else if (_wcsicmp(cmd, L"ping") == 0 || _wcsicmp(cmd, L"hvping") == 0)
        {
            result = PingAll(hDev);
        }
        else if (_wcsicmp(cmd, L"diag") == 0)
        {
            mapctl_hv_diag diag = {};
            result = DeviceIoControl(hDev, MAPCTL_IOCTL_HV_DIAG, nullptr, 0, &diag, sizeof(diag), &bytesRet, nullptr) !=
                     FALSE;
            if (result)
            {
                printf("[VT Diag] vcpu_count=%llu ghv=0x%llX (0x%llX) host_rip=0x%llX host_rsp=0x%llX vt_hook=0x%llX\n",
                       diag.vcpu_count, diag.ghv, diag.ghv_size, diag.vmcs_host_rip, diag.vmcs_host_rsp,
                       diag.vt_hook_table_ptr);
            }
        }
        else if (_wcsicmp(cmd, L"migrate_check") == 0)
        {
            mapctl_migration_check chk = {};
            result = MigrateCheck(hDev, &chk);
            if (result)
            {
                printf("[VT MigrateCheck] result=0x%llX flags=0x%llX host_rip=0x%llX host_rsp=0x%llX\n", chk.result,
                       chk.flags, chk.diag.vmcs_host_rip, chk.diag.vmcs_host_rsp);
            }
        }
        else if (_wcsicmp(cmd, L"legacy_detach") == 0)
        {
            mapctl_legacy_detach req = {MAPCTL_LEGACY_DETACH_MAGIC, sizeof(req), MAPCTL_LEGACY_DETACH_ARM,
                                        PAYLOAD_LEGACY_DETACH_MODE_ARM};
            result = DeviceIoControl(hDev, MAPCTL_IOCTL_LEGACY_DETACH, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                                     nullptr) &&
                     req.result == PAYLOAD_RESULT_OK;
            printf("[VT LegacyDetach] result=0x%llX stage=%llu flags=0x%llX\n", req.result, req.stage, req.new_flags);
        }
        else if (_wcsicmp(cmd, L"switch_rsp") == 0 || _wcsicmp(cmd, L"restore_rsp") == 0)
        {
            const DWORD code =
                (_wcsicmp(cmd, L"switch_rsp") == 0) ? MAPCTL_IOCTL_HOST_RSP_SWITCH : MAPCTL_IOCTL_HOST_RSP_RESTORE;
            mapctl_host_rsp_switch req = {MAPCTL_HOST_RSP_SWITCH_MAGIC, sizeof(req), MAPCTL_HOST_RSP_SWITCH_ARM};
            result = DeviceIoControl(hDev, code, &req, sizeof(req), &req, sizeof(req), &bytesRet, nullptr) &&
                     req.result == PAYLOAD_RESULT_OK;
            printf("[VT HostRsp] result=0x%llX switched=%llu/%llu new=0x%llX old=0x%llX\n", req.result,
                   req.switched_count, req.requested_count, req.last_new_rsp, req.last_old_rsp);
        }
        else if (_wcsicmp(cmd, L"switch_rip") == 0 || _wcsicmp(cmd, L"restore_rip") == 0 ||
                 _wcsicmp(cmd, L"switch_bridge") == 0 || _wcsicmp(cmd, L"restore_bridge") == 0)
        {
            DWORD code = MAPCTL_IOCTL_HOST_BRIDGE_SWITCH;
            if (_wcsicmp(cmd, L"switch_rip") == 0)
                code = MAPCTL_IOCTL_HOST_RIP_SWITCH;
            else if (_wcsicmp(cmd, L"restore_rip") == 0)
                code = MAPCTL_IOCTL_HOST_RIP_RESTORE;
            else if (_wcsicmp(cmd, L"restore_bridge") == 0)
                code = MAPCTL_IOCTL_HOST_BRIDGE_RESTORE;

            mapctl_host_rip_switch req = {MAPCTL_HOST_RIP_SWITCH_MAGIC, sizeof(req), MAPCTL_HOST_RIP_SWITCH_ARM};
            result = DeviceIoControl(hDev, code, &req, sizeof(req), &req, sizeof(req), &bytesRet, nullptr) &&
                     req.result == PAYLOAD_RESULT_OK;
            printf("[VT HostRip] result=0x%llX switched=%llu/%llu new=0x%llX old=0x%llX\n", req.result,
                   req.switched_count, req.requested_count, req.last_new_rip, req.last_old_rip);
        }
        else if (_wcsicmp(cmd, L"handoff") == 0)
        {
            result = DeviceIoControl(hDev, MAPCTL_IOCTL_HANDOFF, nullptr, 0, nullptr, 0, &bytesRet, nullptr) != FALSE;
        }
        else if (_wcsicmp(cmd, L"handoff_dropctl") == 0)
        {
            result = DeviceIoControl(hDev, MAPCTL_IOCTL_HANDOFF_DROPCTL, nullptr, 0, nullptr, 0, &bytesRet, nullptr) !=
                     FALSE;
        }
        else if (_wcsicmp(cmd, L"cutover") == 0)
        {
            payload_u64 mode = arg ? _wcstoui64(arg, nullptr, 0) : PAYLOAD_CUTOVER_MODE_CLEAR;
            mapctl_cutover req = {MAPCTL_CUTOVER_MAGIC, sizeof(req), MAPCTL_CUTOVER_ARM, mode};
            result = DeviceIoControl(hDev, MAPCTL_IOCTL_CUTOVER, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                                     nullptr) &&
                     req.result == PAYLOAD_RESULT_OK;
            printf("[VT Cutover] mode=%llu result=0x%llX old=0x%llX new=0x%llX\n", req.mode, req.result, req.old_target,
                   req.new_target);
        }
        else if (_wcsicmp(cmd, L"free_test") == 0)
        {
            // 兼容旧命令名；实际执行的是释放旧 Hypervisor 映像的业务操作。
            mapctl_free_test req = {MAPCTL_RELEASE_LEGACY_IMAGE_MAGIC, sizeof(req),
                                    MAPCTL_RELEASE_LEGACY_IMAGE_ARM};
            result = DeviceIoControl(hDev, MAPCTL_IOCTL_RELEASE_LEGACY_IMAGE, &req, sizeof(req), &req, sizeof(req),
                                     &bytesRet, nullptr) &&
                     req.result == PAYLOAD_RESULT_OK;
            printf("[VT FreeTest] result=0x%llX phase=%llu test_before=0x%llX test_after=0x%llX\n", req.result,
                   req.free_phase, req.test_before, req.test_after);
        }
        else if (_wcsicmp(cmd, L"memcheck") == 0)
        {
            bool repair = (arg && _wcsicmp(arg, L"repair") == 0);
            result = RunMemCheck(hDev, MAPCTL_MEMCHECK_FLAG_ALL, repair);
        }
        else if (_wcsicmp(cmd, L"mmtest") == 0)
        {
            // 兼容旧命令名；调用驻留载荷的内存审计业务接口。
            result = RunMemoryAudit(hDev, MAPCTL_MEMORY_AUDIT_OP_ALL);
        }
        else if (_wcsicmp(cmd, L"smoke") == 0)
        {
            mapctl_smoke req = {};
            result = DeviceIoControl(hDev, MAPCTL_IOCTL_SMOKE, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                                     nullptr) &&
                     req.result == PAYLOAD_RESULT_OK;
            printf("[VT Smoke] result=0x%llX marker=0x%llX\n", req.result, req.marker);
        }
        else if (_wcsicmp(cmd, L"vtret_mode") == 0 || _wcsicmp(cmd, L"tramp_mode") == 0 ||
                 _wcsicmp(cmd, L"hook_mode") == 0 || _wcsicmp(cmd, L"ept_mode") == 0)
        {
            payload_u64 mode = arg ? _wcstoui64(arg, nullptr, 0) : 1ULL;
            if (_wcsicmp(cmd, L"vtret_mode") == 0)
            {
                mapctl_vtret_mode req = {MAPCTL_VTRET_MODE_MAGIC, sizeof(req), MAPCTL_VTRET_MODE_ARM, mode};
                result = DeviceIoControl(hDev, MAPCTL_IOCTL_VTRET_MODE, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                                         nullptr) &&
                         req.result == PAYLOAD_RESULT_OK;
            }
            else if (_wcsicmp(cmd, L"tramp_mode") == 0)
            {
                mapctl_tramp_mode req = {MAPCTL_TRAMP_MODE_MAGIC, sizeof(req), MAPCTL_TRAMP_MODE_ARM, mode};
                result = DeviceIoControl(hDev, MAPCTL_IOCTL_TRAMP_MODE, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                                         nullptr) &&
                         req.result == PAYLOAD_RESULT_OK;
            }
            else if (_wcsicmp(cmd, L"hook_mode") == 0)
            {
                mapctl_hook_mode req = {MAPCTL_HOOK_MODE_MAGIC, sizeof(req), MAPCTL_HOOK_MODE_ARM, mode};
                result = DeviceIoControl(hDev, MAPCTL_IOCTL_HOOK_MODE, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                                         nullptr) &&
                         req.result == PAYLOAD_RESULT_OK;
            }
            else
            {
                mapctl_ept_mode req = {MAPCTL_EPT_MODE_MAGIC, sizeof(req), MAPCTL_EPT_MODE_ARM, mode};
                result = DeviceIoControl(hDev, MAPCTL_IOCTL_EPT_MODE, &req, sizeof(req), &req, sizeof(req), &bytesRet,
                                         nullptr) &&
                         req.result == PAYLOAD_RESULT_OK;
            }
        }
        else
        {
            LOG_ERR("[VT] Unknown --vt-cmd '%ls'", cmd);
        }

        CloseHandle(hDev);
        return result;
    }
};
