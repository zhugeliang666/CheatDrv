#include "common.h"
#include "protocol.h"
using namespace std;
#include <chrono>
#include <random>

#include <SetupAPI.h>
#include <winusb.h>

bool CheckUsbDeviceMI05()
{
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA devInfoData;
    DWORD i;
    bool found = false;

    hDevInfo = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++)
    {
        DWORD dataType;
        WCHAR serviceBuffer[256];
        DWORD bufferSize;
        WCHAR classBuffer[256];
        HKEY hDeviceKey;
        WCHAR guidString[256];
        DWORD guidSize;
        BOOL foundGuid;
        GUID deviceGuid;
        HDEVINFO hGuidDevInfo;
        SP_DEVICE_INTERFACE_DATA interfaceData;
        DWORD k;

        bufferSize = sizeof(serviceBuffer);
        if (!SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_SERVICE, &dataType, (PBYTE)serviceBuffer, bufferSize, &bufferSize))
            continue;
        if (_wcsicmp(serviceBuffer, L"WINUSB") != 0 && _wcsicmp(serviceBuffer, L"winusb") != 0)
            continue;

        bufferSize = sizeof(classBuffer);
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_CLASS, &dataType, (PBYTE)classBuffer, bufferSize, &bufferSize))
        {
            if (_wcsicmp(classBuffer, L"Mouse") == 0 || _wcsicmp(classBuffer, L"Keyboard") == 0 || _wcsicmp(classBuffer, L"HIDClass") == 0)
                continue;
        }

        hDeviceKey = SetupDiOpenDevRegKey(hDevInfo, &devInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (hDeviceKey == INVALID_HANDLE_VALUE)
            continue;

        foundGuid = FALSE;
        guidSize = sizeof(guidString);
        if (RegQueryValueExW(hDeviceKey, L"DeviceInterfaceGUID", NULL, NULL, (LPBYTE)guidString, &guidSize) == ERROR_SUCCESS)
            foundGuid = TRUE;
        else
        {
            guidSize = sizeof(guidString);
            if (RegQueryValueExW(hDeviceKey, L"DeviceInterfaceGUIDs", NULL, NULL, (LPBYTE)guidString, &guidSize) == ERROR_SUCCESS)
                foundGuid = TRUE;
        }
        RegCloseKey(hDeviceKey);
        if (!foundGuid)
            continue;

        for (k = 0; k < guidSize / sizeof(WCHAR) && k < 256; k++)
        {
            if (guidString[k] == L'\0')
                break;
        }

        if (CLSIDFromString(guidString, &deviceGuid) != S_OK)
            continue;

        hGuidDevInfo = SetupDiGetClassDevsW(&deviceGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (hGuidDevInfo == INVALID_HANDLE_VALUE)
            continue;

        interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
        if (SetupDiEnumDeviceInterfaces(hGuidDevInfo, NULL, &deviceGuid, 0, &interfaceData))
        {
            DWORD requiredLength = 0;
            SetupDiGetDeviceInterfaceDetailW(hGuidDevInfo, &interfaceData, NULL, 0, &requiredLength, NULL);
            if (requiredLength > 0)
            {
                PSP_DEVICE_INTERFACE_DETAIL_DATA_W pDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)LocalAlloc(LMEM_FIXED, requiredLength);
                if (pDetail)
                {
                    pDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
                    if (SetupDiGetDeviceInterfaceDetailW(hGuidDevInfo, &interfaceData, pDetail, requiredLength, NULL, NULL))
                    {
                        HANDLE hDevice = CreateFileW(pDetail->DevicePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
                        if (hDevice != INVALID_HANDLE_VALUE)
                        {
                            WINUSB_INTERFACE_HANDLE winUsbHandle;
                            if (WinUsb_Initialize(hDevice, &winUsbHandle))
                            {
                                USB_INTERFACE_DESCRIPTOR ifaceDescriptor;
                                if (WinUsb_QueryInterfaceSettings(winUsbHandle, 0, &ifaceDescriptor))
                                {
                                    BOOL hasBulkIn = FALSE;
                                    BOOL hasBulkOut = FALSE;
                                    for (UCHAR j = 0; j < ifaceDescriptor.bNumEndpoints; j++)
                                    {
                                        WINUSB_PIPE_INFORMATION pipeInfo;
                                        if (WinUsb_QueryPipe(winUsbHandle, 0, j, &pipeInfo))
                                        {
                                            if (pipeInfo.PipeType == UsbdPipeTypeBulk)
                                            {
                                                if (USB_ENDPOINT_DIRECTION_IN(pipeInfo.PipeId))
                                                    hasBulkIn = TRUE;
                                                else
                                                    hasBulkOut = TRUE;
                                            }
                                        }
                                    }
                                    if (hasBulkIn && hasBulkOut)
                                    {
                                        if (wcsstr(pDetail->DevicePath, L"mi_05") != NULL || wcsstr(pDetail->DevicePath, L"MI_05") != NULL)
                                        {
                                            found = true;
                                        }
                                    }
                                }
                                WinUsb_Free(winUsbHandle);
                            }
                            CloseHandle(hDevice);
                        }
                    }
                    LocalFree(pDetail);
                }
            }
        }
        SetupDiDestroyDeviceInfoList(hGuidDevInfo);
        if (found)
            break;
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return found;
}

#define DISCOVER_PORT 10000
#define AUTH_PORT 10004
#define DISCOVER_BUFFER_SIZE 1024

int FindUnusedPort(int startPort)
{
    // 1. 优先尝试真随机探测空闲端口
    uint32_t seed = 0;
    try
    {
        std::random_device rd;
        seed = rd() ^ static_cast<uint32_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    }
    catch (...)
    {
        // 兜底：如果 random_device
        // 抛出异常（部分沙盒/精简系统无熵源），纯时间戳与随机数混淆作为种子
        seed = static_cast<uint32_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()) ^ 0x5F3759DFu;
    }
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> distrib(startPort, 65535);

    // 最大进行 500 次随机碰撞，保证效率与防重复
    for (int i = 0; i < 500; ++i)
    {
        int port = distrib(gen);
        SOCKET tempSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tempSock == INVALID_SOCKET)
        {
            continue;
        }
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (::bind(tempSock, (sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
        {
            closesocket(tempSock);
            return port;
        }
        closesocket(tempSock);
    }

    // 2. 兜底方案：如果随机寻找失败，顺序遍历可用端口，保证可用性
    for (int port = startPort; port < 65535; ++port)
    {
        SOCKET tempSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tempSock == INVALID_SOCKET)
        {
            continue;
        }
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (::bind(tempSock, (sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
        {
            closesocket(tempSock);
            return port;
        }
        closesocket(tempSock);
    }
    return 0;
}

bool blogged_packet, game_shellcode_packet, leech_shellcode_packet, game_inject_packet;

void handle_client(SOCKET clientSock, sockaddr_in clientAddr);
typedef bool(__stdcall *ConnectLeech)(std::string serverIP);
uint32_t CalcCRC32(const uint8_t *data, size_t len)
{
    static uint32_t table[256];
    static bool init = false;

    if (!init)
    {
        for (uint32_t i = 0; i < 256; ++i)
        {
            uint32_t c = i;
            for (int j = 0; j < 8; ++j)
            {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        init = true;
    }

    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
    {
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    uint32_t ret = crc ^ 0xFFFFFFFFu;
    return ret;
}

bool RecvAll(SOCKET sock, uint8_t *buf, size_t totalBytes)
{
    DWORD timeout = 1000 * 60; // 10 秒
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    size_t received = 0;
    while (received < totalBytes)
    {
        int ret = recv(sock, reinterpret_cast<char *>(buf + received), static_cast<int>(totalBytes - received), 0);

        if (ret <= 0)
        { // 连接关闭或错误
            return false;
        }
        received += static_cast<size_t>(ret);
    }
    return true;
}

bool discvoer_service()
{
    // 1. 初始化与 Socket 创建 (合并定义)
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    char clientIP[INET_ADDRSTRLEN], buffer[DISCOVER_BUFFER_SIZE];

    SOCKET serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // 允许重用地址，防止服务重启时 bind 失败
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    sockaddr_in serverAddr = {AF_INET, htons(DISCOVER_PORT)};
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // 2. 配置接收超时
    DWORD timeout = 2000;
    setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    ConsoleLog(L10N("device.waiting_discovery"), Log_Info);
    DBG("[UDP-Discovery] UDP discovery listening on port %d...", DISCOVER_PORT);

    if (::bind(serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        ConsoleLog("Failed to bind UDP discovery port. Please check firewall permissions.", Log_Error);
        DBG("[UDP-Discovery] Failed to bind port %d, error: %d", DISCOVER_PORT, WSAGetLastError());
        goto _UDP_EXIT;
    }
    // 3. 发现循环
    while (true)
    {
        sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        int recvLen = recvfrom(serverSocket, buffer, DISCOVER_BUFFER_SIZE - 1, 0, (sockaddr *)&clientAddr, &clientAddrLen);

        if (recvLen > 0)
        {
            buffer[recvLen] = '\0';
            if (strcmp(buffer, "DISCOVER_REQUEST") == 0)
            {
                inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
                DBG("[UDP-Discovery] Received DISCOVER_REQUEST from %s:%d", clientIP, ntohs(clientAddr.sin_port));

                // 扫描本地端口，找一个 10000 以后的未使用端口
                int freePort = FindUnusedPort(10010);
                if (freePort == 0)
                {
                    ConsoleLog(L10N("device.scan_port_fail"), Log_Error);
                    DBG("[UDP-Discovery] Failed to find available port for client %s", clientIP);
                }
                std::string hostMacs = GetHostPhysicalMacAddresses();
                std::string reply = "DISCOVER_RESPONSE|" + std::to_string(freePort) + "|" + gVar.dynamic_key;
                if (!hostMacs.empty())
                {
                    reply += "|" + hostMacs;
                }
                sendto(serverSocket, reply.c_str(), (int)strlen(reply.c_str()), 0, (sockaddr *)&clientAddr, clientAddrLen);

                std::string logMsg = L10N("device.secondary_prefix") + std::string(clientIP) + L10N("device.discovered_suffix");
                if (!hostMacs.empty())
                {
                    logMsg += " [MAC: " + hostMacs + "]";
                }
                ConsoleLog(logMsg, Log_Success);
                DBG("[UDP-Discovery] Assigned port %d, MAC(s): %s, responded to client %s", freePort, hostMacs.c_str(), clientIP);
                gVar.clientIP = std::string(clientIP);
                continue;
            }
        }
    }

_UDP_EXIT:
    if (serverSocket != INVALID_SOCKET)
        closesocket(serverSocket);
    return true;
}

bool SendAll(SOCKET sock, const uint8_t *buf, size_t totalBytes)
{
    DWORD timeout = 5000; // 5 秒
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    size_t sent = 0;
    while (sent < totalBytes)
    {
        int ret = send(sock, reinterpret_cast<const char *>(buf + sent), static_cast<int>(totalBytes - sent), 0);

        if (ret <= 0)
        {
            DBG("[Socket] Send failed or socket closed, ret=%d, WSAGetLastError=%d", ret, WSAGetLastError());
            return false;
        }
        sent += static_cast<size_t>(ret);
    }
    return true;
}

SOCKET accept_with_timeout(SOCKET serverSock, struct sockaddr *addr, int *addrLen, int timeout_ms)
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(serverSock, &readfds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(0, &readfds, NULL, NULL, &tv);

    if (ret == SOCKET_ERROR)
    {
        return INVALID_SOCKET;
    }

    if (ret == 0)
    {
        // 正常超时：在指定时间内没有任何连接请求
        return INVALID_SOCKET;
    }

    SOCKET clientSock = accept(serverSock, addr, addrLen);
    return clientSock;
}

bool tcp_server_create()
{
    // 1. 初始化状态与 Winsock (合并赋值减少换行)
    blogged_packet = game_shellcode_packet = leech_shellcode_packet = false;
    game_inject_packet = false;

    if (gVar.dynamic_key.empty())
    {
        gVar.dynamic_key = GenerateRandomHexKey(32);
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 2. 配置 TCP Socket
    DBG("[TCP-Server] Creating TCP server socket on port %d...", AUTH_PORT);
    SOCKET serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // 设置地址重用，允许程序崩溃重启后立即绑定
    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    sockaddr_in serverAddr = {AF_INET, htons(AUTH_PORT)};
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(serverSock, (SOCKADDR *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        ConsoleLog("Failed to bind TCP server port. Please check firewall configuration.", Log_Error);
        DBG("[TCP-Server] bind failed on port %d, error: %d", AUTH_PORT, WSAGetLastError());
        goto _SERVER_CLEANUP;
    }
    listen(serverSock, 5);
    ConsoleLog(L10N("deploy.host_success"), Log_Success);
    DBG("[TCP-Server] Server successfully listening on port %d, ready for connections", AUTH_PORT);

    // 3. 启动后台 UDP 发现服务
    DBG("[TCP-Server] Spawning background UDP discovery thread...");
    std::thread(discvoer_service).detach();

    // 4. 主监听循环
    while (true)
    {
        sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);

        SOCKET clientSock = accept_with_timeout(serverSock, (SOCKADDR *)&clientAddr, &addrLen, 5000);

        if (clientSock == INVALID_SOCKET)
        {
            Sleep(100);
            continue;
        }

        char clientIpStr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIpStr, sizeof(clientIpStr));
        DBG("[TCP-Server] Accepted incoming connection from %s:%d, spawning worker thread", clientIpStr, ntohs(clientAddr.sin_port));

        // 为每个客户端开启独立处理线程
        std::thread(handle_client, clientSock, clientAddr).detach();
    }

_SERVER_CLEANUP:
    if (serverSock != INVALID_SOCKET)
        closesocket(serverSock);
    WSACleanup();
    bool ret = (serverSock != INVALID_SOCKET);
    return ret;
}

// 宿主端无痕自删除：等待进程退出释放句柄后，静默粉碎落盘二进制
static void ScheduleSelfDelete()
{
    wchar_t selfPath[MAX_PATH] = {0};
    if (GetModuleFileNameW(NULL, selfPath, MAX_PATH))
    {
        std::wstring cmd = L"cmd.exe /c ping 127.0.0.1 -n 2 >nul & del /f /q \"" + std::wstring(selfPath) + L"\"";
        STARTUPINFOW si = {sizeof(si)};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

/**
 * @brief 方案2纯二进制包加密发送函数 (统一外层加密封包)
 */
bool SendBinaryPacket(SOCKET clientSock, const void *data, size_t size, const std::string &dynamicKey)
{
    try
    {
        // 1. 将二进制数据转为 Hex -> EncryptHex -> Bytes
        std::string hexStr = BytesToHex_char(reinterpret_cast<const uint8_t *>(data), size);
        std::string encrypted_hex = EncryptDataHex(hexStr, dynamicKey);
        std::vector<uint8_t> sendBody = HexToBytes(encrypted_hex);

        // 2. 构造外层协议头
        PacketHeader header{};
        header.magic = PACKET_MAGIC;
        header.version = PACKET_VERSION;
        header.flags = FLAG_ENCRYPT;
        header.bodySize = static_cast<uint32_t>(sendBody.size());
        header.crc32 = CalcCRC32(sendBody.data(), sendBody.size());

        // 3. 发送协议头与加密正文
        if (!SendAll(clientSock, reinterpret_cast<const uint8_t *>(&header), sizeof(header)))
        {
            ConsoleLog(L10N("transfer.header_failed"), Log_Error);
            return false;
        }
        if (!SendAll(clientSock, sendBody.data(), sendBody.size()))
        {
            ConsoleLog(L10N("transfer.content_failed"), Log_Error);
            return false;
        }
        return true;
    }
    catch (...)
    {
        ConsoleLog(L10N("transfer.unknown_exception"), Log_Error);
        return false;
    }
}

/**
 * @brief 方案2发送标准二进制通用应答帧 (HSTV_COMMON_ACK)
 */
bool SendBinaryAck(SOCKET clientSock, uint16_t cmd, uint32_t status, const char *reason = nullptr, uint32_t extraValue = 0)
{
    HSTV_COMMON_ACK ack{};
    ack.Magic = HSTV_FRAME_MAGIC;
    ack.Cmd = cmd;
    ack.Status = status;
    ack.ExtraValue = extraValue;
    if (reason && reason[0] != '\0')
    {
        strncpy_s(ack.Reason, reason, _TRUNCATE);
    }
    else
    {
        strncpy_s(ack.Reason, status == 0 ? "success" : "error", _TRUNCATE);
    }
    bool ret = SendBinaryPacket(clientSock, &ack, sizeof(ack), gVar.dynamic_key);
    return ret;
}

/**
 * @brief 方案2纯二进制命令帧分发处理中心 (彻底抹除明文伪 XML 标签字符串)
 */
static bool HandleBinaryCommand(SOCKET clientSock, sockaddr_in clientAddr, const uint8_t *data, size_t size)
{
    VMProtectBeginUltra("HandleBinaryCommand");
    if (!data || size < sizeof(HSTV_HEADER))
    {
        DBG("[Protocol] HandleBinaryCommand error: buffer is null or size too small (%zu < %zu)", size, sizeof(HSTV_HEADER));
        VMProtectEnd();
        return false;
    }

    const auto *hdr = reinterpret_cast<const HSTV_HEADER *>(data);
    if (hdr->Magic != HSTV_FRAME_MAGIC)
    {
        DBG("[Protocol] HandleBinaryCommand error: Magic mismatch! Expected: 0x%08X ('HSTV'), Got: 0x%08X, Cmd: 0x%04X, Size: %zu", HSTV_FRAME_MAGIC, hdr->Magic, hdr->Cmd, size);
        VMProtectEnd();
        return false;
    }

    switch (hdr->Cmd)
    {
    case HSTV_CMD_LOGIN_REQ:
    {
        if (size < sizeof(HSTV_LOGIN_REQ))
        {
            ConsoleLog(L10N("auth.data_error"), Log_Error);
            SendBinaryAck(clientSock, HSTV_CMD_LOGIN_ACK, 1, "auth.data_error");
            VMProtectEnd();
            return true;
        }
        const auto *req = reinterpret_cast<const HSTV_LOGIN_REQ *>(data);
        gVar.slogin_data.card_key = req->CardKey;
        gVar.slogin_data.client_signature = req->Hwid;
        gVar.brand_version = req->BrandVersion;
        gVar.selected_game = req->SelectedGame;
        gVar.client_version = req->ClientVersion;
        gVar.curAppVersion = req->ClientVersion;
        gVar.connection_port = std::to_string(req->ConnectPort);

        if (req->ConnectMode > 0)
        {
            gVar.connection_mode = req->ConnectMode;
        }
        if (req->DriverMode > 0)
        {
            gVar.driver_mode = req->DriverMode;
        }
        if (req->ApiUrl[0] != '\0')
        {
            Environment::Current.api = req->ApiUrl;
            Environment::Current.api_url = req->ApiUrl;
            gVar.api_url = req->ApiUrl;
        }
        if (req->LoginUrl[0] != '\0')
        {
            Environment::Current.login_url = req->LoginUrl;
            gVar.login_url = req->LoginUrl;
        }
        if (req->ReportUrl[0] != '\0')
        {
            Environment::Current.report = req->ReportUrl;
            Environment::Current.report_url = req->ReportUrl;
            gVar.report_url = req->ReportUrl;
        }

        std::string mode_str = "Unknown";
        if (gVar.connection_mode == 1)
            mode_str = "DMA";
        else if (gVar.connection_mode == 2)
            mode_str = "TCP";
        else if (gVar.connection_mode == 3)
            mode_str = "UDP";
        else if (gVar.connection_mode == 4)
            mode_str = "USB";
        else if (gVar.connection_mode == 5)
            mode_str = "ETH";
        ConsoleLog("Connection Mode: [" + mode_str + "]", Log_Info);

        DBG("[LoginReq] CardKey: %s, Hwid: %s, Brand: %s, Game: %s, ClientVer: %s, Port: %u, ConnMode: %u, DrvMode: %u, ApiUrl: %s, LoginUrl: %s, ReportUrl: %s",
            req->CardKey, req->Hwid, req->BrandVersion, req->SelectedGame, req->ClientVersion, req->ConnectPort, req->ConnectMode, req->DriverMode,
            req->ApiUrl, req->LoginUrl, req->ReportUrl);

        if (req->ConnectPort == 0)
        {
            ConsoleLog(L10N("auth.connect_mode_fail"), Log_Error);
            SendBinaryAck(clientSock, HSTV_CMD_LOGIN_ACK, 1, "auth.connect_mode_fail");
            VMProtectEnd();
            return true;
        }
        if (gVar.connection_mode == 4)
        {
            if (!CheckUsbDeviceMI05())
            {
                ConsoleLog(L10N("auth.usb_discover_fail"), Log_Error);
                SendBinaryAck(clientSock, HSTV_CMD_LOGIN_ACK, 1, "auth.usb_discover_fail");
                Reporter::Report("ProcessLoginReq", 0xC000009D, "USB连接模式未发现指定USB设备 (CheckUsbDeviceMI05 failed)");
                VMProtectEnd();
                return true;
            }
        }
        ConsoleLog(L10N("auth.deployed_success"), Log_Success);
        SendBinaryAck(clientSock, HSTV_CMD_LOGIN_ACK, 0, "success");
        blogged_packet = true;
        VMProtectEnd();
        return true;
    }
    case HSTV_CMD_CLOSE_LOADER_REQ:
    {
        ConsoleLog(L10N("system.preparing_close"), Log_Success);
        SendBinaryAck(clientSock, HSTV_CMD_CLOSE_LOADER_ACK, 0, "success");
        Sleep(2000);
        TerminateProcess(GetCurrentProcess(), 0);
        VMProtectEnd();
        return true;
    }
    case HSTV_CMD_MANUAL_CONNECT_REQ:
    {
        char clientIp[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
        gVar.clientIP = std::string(clientIp);
        std::string hostMacs = GetHostPhysicalMacAddresses();
        std::string reply = gVar.dynamic_key;
        if (!hostMacs.empty())
        {
            reply += "|" + hostMacs;
        }
        SendBinaryAck(clientSock, HSTV_CMD_MANUAL_CONNECT_ACK, 0, reply.c_str());
        VMProtectEnd();
        return true;
    }
    case HSTV_CMD_SHELLCODE_DATA_REQ:
    {
        if (size < sizeof(HSTV_CMD_SHELLCODE_REQ))
        {
            SendBinaryAck(clientSock, HSTV_CMD_SHELLCODE_DATA_ACK, 1, "data too small");
            VMProtectEnd();
            return true;
        }
        const auto *scReq = reinterpret_cast<const HSTV_CMD_SHELLCODE_REQ *>(data);
        const uint8_t *payload = data + sizeof(HSTV_CMD_SHELLCODE_REQ);
        size_t payloadSize = size - sizeof(HSTV_CMD_SHELLCODE_REQ);
        if (payloadSize < scReq->CodeSize + scReq->ExtraSize)
        {
            SendBinaryAck(clientSock, HSTV_CMD_SHELLCODE_DATA_ACK, 1, "payload truncated");
            VMProtectEnd();
            return true;
        }

        std::string hexData = BytesToHex_char(payload, scReq->CodeSize);
        if (scReq->ShellcodeType == 1) // Game
        {
            gVar.game_shellcode_hex = hexData;
            if (scReq->ExtraSize > 0)
            {
                gVar.shellcode_extra_data = std::string(reinterpret_cast<const char *>(payload + scReq->CodeSize), scReq->ExtraSize);
            }
            game_shellcode_packet = true;
            ConsoleLog(L10N("deploy.program_data"), Log_Success);
        }
        else if (scReq->ShellcodeType == 2) // Leech
        {
            gVar.leech_shellcode_hex = hexData;
            ConsoleLog(L10N("deploy.dual_data1"), Log_Success);
        }
        else if (scReq->ShellcodeType == 3) // LeechDriver
        {
            gVar.leech_driver_shellcode_hex = hexData;
            leech_shellcode_packet = true;
            ConsoleLog(L10N("deploy.dual_data2"), Log_Success);
        }
        SendBinaryAck(clientSock, HSTV_CMD_SHELLCODE_DATA_ACK, 0, "success");
        VMProtectEnd();
        return true;
    }
    case HSTV_CMD_INJECT_GAME_REQ:
    {
        ConsoleLog(L10N("game.injection_success"), Log_Success);
        SendBinaryAck(clientSock, HSTV_CMD_INJECT_GAME_ACK, 0, "success");
        VMProtectEnd();
        return true;
    }
    case HSTV_CMD_LEECHAGENT_PING_REQ:
    {
        SendBinaryAck(clientSock, HSTV_CMD_LEECHAGENT_PING_ACK, 0, "success");
        VMProtectEnd();
        return true;
    }
    case HSTV_CMD_LEECHAGENT_CLOSE_REQ:
    {
        SendBinaryAck(clientSock, HSTV_CMD_LEECHAGENT_CLOSE_ACK, 0, "success");
        Sleep(1000);
        TerminateProcess(GetCurrentProcess(), 0);
        VMProtectEnd();
        return true;
    }
    case HSTV_CMD_HEARTBEAT_REQ:
    {
        SendBinaryAck(clientSock, HSTV_CMD_HEARTBEAT_ACK, 0, "success");
        VMProtectEnd();
        return true;
    }
    case HSTV_CMD_DECRYPT_DLL_CHECK_REQ:
    {
        SendBinaryAck(clientSock, HSTV_CMD_DECRYPT_DLL_CHECK_ACK, 0, "success");
        VMProtectEnd();
        return true;
    }
    break;
    default:
        break;
    }
    VMProtectEnd();
    return false;
}

void handle_client(SOCKET clientSock, sockaddr_in clientAddr)
{
    // ====== 0️⃣ 结构化二进制指令帧嗅探分发 (HSTV_FRAME_MAGIC) ======
    HSTV_HEADER peekHdr{};
    int peekBytes = recv(clientSock, reinterpret_cast<char *>(&peekHdr), sizeof(peekHdr), MSG_PEEK);
    if (peekBytes >= static_cast<int>(sizeof(peekHdr)) && peekHdr.Magic == HSTV_FRAME_MAGIC)
    {
        // 步骤 1: 接收双机驱动数据包 (HSTV_CMD_DRIVER_DATA_REQ)
        if (peekHdr.Cmd == HSTV_CMD_DRIVER_DATA_REQ)
        {
            HSTV_DRIVER_DATA_REQ req{};
            if (!RecvAll(clientSock, reinterpret_cast<uint8_t *>(&req), sizeof(req)))
            {
                closesocket(clientSock);
                return;
            }

            // 1. 接收 Leech (原始核心驱动) 二进制流
            std::vector<uint8_t> leechBytes(req.LeechCoreSize);
            if (req.LeechCoreSize > 0 && !RecvAll(clientSock, leechBytes.data(), req.LeechCoreSize))
            {
                closesocket(clientSock);
                return;
            }

            // 2. 接收白驱动 (Machenike.sys) 二进制流 (Mode 2 PTE 映射模式下有效)
            std::vector<uint8_t> whiteDriverBytes(req.WhiteDriverSize);
            if (req.WhiteDriverSize > 0 && !RecvAll(clientSock, whiteDriverBytes.data(), req.WhiteDriverSize))
            {
                closesocket(clientSock);
                return;
            }

            // 3. 聚合负载 CRC32 强校验
            if (req.PayloadCRC32 != 0)
            {
                uint32_t calcCrc = 0;
                if (req.LeechCoreSize > 0)
                    calcCrc ^= CalcCRC32(leechBytes.data(), req.LeechCoreSize);
                if (req.WhiteDriverSize > 0)
                    calcCrc ^= CalcCRC32(whiteDriverBytes.data(), req.WhiteDriverSize);
                if (calcCrc != req.PayloadCRC32)
                {
                    ConsoleLog(L10N("auth.data_error2"), Log_Error);
                    HSTV_COMMON_ACK ack{};
                    ack.Magic = HSTV_FRAME_MAGIC;
                    ack.Cmd = HSTV_CMD_DRIVER_DATA_ACK;
                    ack.Status = 1;
                    strncpy_s(ack.Reason, "auth.data_error2", _TRUNCATE);
                    SendAll(clientSock, reinterpret_cast<const uint8_t *>(&ack), sizeof(ack));
                    Reporter::Report("ProcessDriverData", 0xC000000D, "双机驱动数据包 CRC32 校验失败 (auth.data_error2)");
                    closesocket(clientSock);
                    return;
                }
            }

            // 写入全局变量缓存供步骤 2 加载驱动使用
            if (!leechBytes.empty())
            {
                gVar.leech_shellcode_hex = BytesToHex(leechBytes);
            }
            if (!whiteDriverBytes.empty())
            {
                gVar.leech_driver_shellcode_hex = BytesToHex(whiteDriverBytes);
            }
            else if (req.DriverMode == 1)
            {
                // 正常加载模式：清空白驱动缓存，确保不落地白驱动
                SecureWipeContainer(gVar.leech_driver_shellcode_hex);
            }
            gVar.driver_mode = req.DriverMode;
            gVar.connection_mode = req.ConnectMode;

            ConsoleLog(L10N("deploy.dual_data1"), Log_Success);
            HSTV_COMMON_ACK ack{};
            ack.Magic = HSTV_FRAME_MAGIC;
            ack.Cmd = HSTV_CMD_DRIVER_DATA_ACK;
            ack.Status = 0;
            strncpy_s(ack.Reason, "success", _TRUNCATE);
            SendAll(clientSock, reinterpret_cast<const uint8_t *>(&ack), sizeof(ack));
            closesocket(clientSock);
            return;
        }

        // 步骤 2: 驱动加载启动请求包 (HSTV_CMD_DRIVER_START_REQ)
        if (peekHdr.Cmd == HSTV_CMD_DRIVER_START_REQ)
        {
            HSTV_DRIVER_START_REQ req{};
            constexpr size_t baseLen = offsetof(HSTV_DRIVER_START_REQ, CardKey);
            if (!RecvAll(clientSock, reinterpret_cast<uint8_t *>(&req), baseLen))
            {
                DBG("[DriverStart] Failed to receive HSTV_DRIVER_START_REQ base header (%zu bytes)", baseLen);
                closesocket(clientSock);
                return;
            }
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(clientSock, &readSet);
            timeval tv{0, 50000}; // 50ms 探测兼容是否附带 CardKey[64] 尾帧
            if (select(0, &readSet, nullptr, nullptr, &tv) > 0)
            {
                RecvAll(clientSock, reinterpret_cast<uint8_t *>(req.CardKey), sizeof(req.CardKey));
            }

            if (gVar.leech_shellcode_hex.empty())
            {
                ConsoleLog(L10N("auth.data_error"), Log_Error);
                HSTV_CMD_DRIVER_INIT_ACK errAck{};
                errAck.Magic = HSTV_FRAME_MAGIC;
                errAck.Cmd = HSTV_CMD_DRIVER_START_ACK;
                errAck.StatusCode = 0xC000000D; // STATUS_INVALID_PARAMETER
                SendAll(clientSock, reinterpret_cast<const uint8_t *>(&errAck), sizeof(errAck));
                closesocket(clientSock);
                return;
            }

            gVar.driver_mode = req.DriverMode;
            gVar.connection_mode = req.ConnectMode;
            if (req.ApiUrl[0] != '\0')
            {
                Environment::Current.api = req.ApiUrl;
                Environment::Current.api_url = req.ApiUrl;
                gVar.api_url = req.ApiUrl;
            }
            if (req.LoginUrl[0] != '\0')
            {
                Environment::Current.login_url = req.LoginUrl;
                gVar.login_url = req.LoginUrl;
            }
            if (req.ReportUrl[0] != '\0')
            {
                Environment::Current.report = req.ReportUrl;
                Environment::Current.report_url = req.ReportUrl;
                gVar.report_url = req.ReportUrl;
            }
            if (req.CardKey[0] != '\0')
            {
                gVar.slogin_data.card_key = req.CardKey;
            }
            DBG("[DriverStart] Starting deployment with DriverMode=%u, ConnectMode=%u, ApiUrl=%s, LoginUrl=%s, ReportUrl=%s, CardKey=%.16s...",
                req.DriverMode, req.ConnectMode, req.ApiUrl, req.LoginUrl, req.ReportUrl, gVar.slogin_data.card_key.c_str());

            // 解析登录时从控制端传入的指定通信端口
            uint16_t targetPort = 0;
            try
            {
                targetPort = static_cast<uint16_t>(gVar.connection_port.empty() ? 0 : std::stoi(gVar.connection_port));
            }
            catch (...)
            {
                targetPort = 0;
            }

            std::string failReason = "";
            bool success = DeployKernelDriver(failReason, req.ConnectMode, req.DriverMode, targetPort, req.SessionToken);

            // ★★★ 核心突破：执行驱动与 host_loader 专属双向防伪验签与 IOCTL 激活 ★★★
            uint16_t activePort = 0;
            if (success && req.DriverMode == 1)
            {
                DBG("[DriverStart] Activating transport via IOCTL on \\\\.\\MsNetEndpoint with targetPort=%u...", targetPort);
                success = VerifyAndActivateDriver(failReason, req.ConnectMode, targetPort, req.SessionToken, activePort);
                if (success && activePort > 0)
                {
                    gVar.connection_port = std::to_string(activePort);
                    DBG("[DriverStart] Transport activated, bound to port: %u", activePort);
                }
            }
            else if (success && req.DriverMode == 2)
            {
                // In Mode 2, DriverEntry has already been triggered by kernel shellcode and bound to targetPort
                activePort = targetPort;
                gVar.connection_port = std::to_string(activePort);
                DBG("[DriverStart] Mode 2: Core driver active and listening on port: %u", activePort);
            }

            HSTV_CMD_DRIVER_INIT_ACK ack{};
            ack.Magic = HSTV_FRAME_MAGIC;
            ack.Cmd = HSTV_CMD_DRIVER_START_ACK;
            ack.StatusCode = success ? 0 : 0xC0000001; // STATUS_UNSUCCESSFUL
            ack.ConnectMode = req.ConnectMode;
            try
            {
                ack.BoundDataPort = static_cast<uint16_t>(gVar.connection_port.empty() ? 0 : std::stoi(gVar.connection_port));
            }
            catch (...)
            {
                ack.BoundDataPort = 0;
            }
            ack.WipedInitBytes = 0x1000;

            // 回发 ACK 就绪包
            SendAll(clientSock, reinterpret_cast<const uint8_t *>(&ack), sizeof(ack));

            if (!success)
            {
                // 失败分支：绝不自删除、绝不退出进程，保持 host_loader 继续存活并提供排查
                ConsoleLog(L10N("deploy.failed"), Log_Error);
                DBG("[-] [DriverStart] Driver deployment failed (StatusCode=0x%08X). Preserving host_loader (no exit, no self-deletion).", ack.StatusCode);

                uint32_t reportStatus = ack.StatusCode;
                std::string reasonChinese = Reporter::FormatFailReason(failReason, reportStatus);
                std::string modeStr = (req.DriverMode == 1) ? "模式1 (标准内核服务加载)" : "模式2 (白驱动PTE原位内存映射)";
                std::string connStr = (req.ConnectMode == 1) ? "DMA" : ((req.ConnectMode == 2) ? "TCP" : ((req.ConnectMode == 3) ? "UDP" : ((req.ConnectMode == 5) ? "ETH" : "USB")));

                std::string detail = "驱动部署激活失败：\r\n"
                                     "【中文根因】" + reasonChinese + "\r\n"
                                     "【原始描述】" + (failReason.empty() ? "无" : failReason) + "\r\n"
                                     "【运行参数】" + modeStr + "，通信协议: " + connStr;

                Reporter::Report("ProcessDriverStart", reportStatus, detail);
                closesocket(clientSock);
                return;
            }

            // 成功分支：延时确保对端接收完成，然后关闭套接字并安全退出
            ConsoleLog(L10N("system.preparing_close"), Log_Success);
            Sleep(500); // 等待对端 TCP 接收完成
            closesocket(clientSock);

            // 密码学清零敏感载荷缓冲区
            SecureWipeContainer(gVar.leech_shellcode_hex);
            SecureWipeContainer(gVar.leech_driver_shellcode_hex);
            SecureWipeContainer(gVar.game_shellcode_hex);
            SecureWipeContainer(gVar.shellcode_extra_data);

            // 保持进程存活，等待对端客户端与驱动首个 Ping 握手成功后，由驱动内核工作项延时 5 秒统一终止并粉碎文件
            // 严禁在此处抢先自删除，以确保对端 Ping 链路连通与状态确证
            DBG("[DriverStart] Driver activated. Waiting for client ping handshake to trigger kernel-side delayed purge...");
            while (true)
            {
                Sleep(1000);
            }
            return;
        }
    }

    // ====== 1️⃣ 传统协议包头处理 ======
    PacketHeader header{};
    if (!RecvAll(clientSock, reinterpret_cast<uint8_t *>(&header), sizeof(header)))
    {
        DBG("[Protocol] Failed to receive PacketHeader");
        closesocket(clientSock);
        WSACleanup();
        return;
    }

    // ====== 2️⃣ 校验协议头 ======
    if (header.magic != PACKET_MAGIC || header.version != PACKET_VERSION || header.bodySize <= 0 || header.bodySize > 100 * 1024 * 1024) // 10MB 上限
    {
        ConsoleLog(L10N("auth.data_error"), Log_Error);
        DBG("[Protocol] Header validation failed: magic=0x%08X, version=%u, bodySize=%u", header.magic, header.version, header.bodySize);
        closesocket(clientSock);
        WSACleanup();
        return;
    }

    // ====== 3️⃣ 接收数据体 ======
    std::vector<uint8_t> body(header.bodySize);
    if (!RecvAll(clientSock, body.data(), body.size()))
    {
        DBG("[Protocol] Failed to receive packet body (%u bytes)", header.bodySize);
        closesocket(clientSock);
        WSACleanup();
        return;
    }

    // ====== 4️⃣ CRC 强校验（对加密后的数据）======
    if (header.crc32 != 1)
    {
        uint32_t crc = CalcCRC32(body.data(), body.size());
        if (crc != header.crc32)
        {
            ConsoleLog(L10N("auth.data_error2"), Log_Error);
            DBG("[Protocol] Packet CRC mismatch! Expected: 0x%08X, Calculated: 0x%08X", header.crc32, crc);
            closesocket(clientSock);
            WSACleanup();
            return;
        }
    }
    std::string encrypted_hex = BytesToHex(body);
    std::string str = DecryptDataHex(encrypted_hex, gVar.dynamic_key);

    // 方案2：纯二进制帧强类型分发，消除明文字符串与 XML 伪标签
    std::vector<uint8_t> decryptedBytes = HexToBytes(str);
    DBG("[Protocol] Successfully decrypted packet body (%zu bytes), dispatching command...", decryptedBytes.size());
    if (HandleBinaryCommand(clientSock, clientAddr, decryptedBytes.data(), decryptedBytes.size()))
    {
        return;
    }

    // 未知或非法协议包，记录日志并安全关闭
    ConsoleLog(L10N("auth.data_error"), Log_Error);
    DBG("[Protocol] Unhandled or invalid command packet received");
    closesocket(clientSock);
}
