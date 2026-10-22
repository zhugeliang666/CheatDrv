#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <psapi.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <winioctl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")

// ============================================================
// WHQL 驱动通信参数（与 drv\Common.h 保持一致）
// ============================================================
#define DEVICE_PATH L"\\\\.\\Machenike"

// SipHash Key（与 drv\Main.cpp 中硬编码一致）
static const uint8_t g_SipHashKey[16] = {0x21, 0x7A, 0xA9, 0x3C, 0x10, 0x55, 0xD2, 0x6F,
                                         0x9B, 0x4E, 0x01, 0x88, 0xC7, 0x33, 0xFA, 0x90};
static const uint32_t g_Salt4 = 0x4D43484EU; // 'MCHN'
static const uint64_t g_Step = 30;

// IOCTL 码（METHOD_NEITHER, FILE_ANY_ACCESS，与 drv\FrameWork.h 及 device_pmem.c 保持完全一致）
#define MACHENIKE_GET_INFO_IOCTRL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x503, METHOD_NEITHER, 3)
#define MACHENIKE_READ_IOCTRL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x504, METHOD_NEITHER, 3)
#define MACHENIKE_WRITE_IOCTRL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x505, METHOD_NEITHER, 3)

// 触发 default 分支：发一个驱动不认识的 IOCTL 码即可
#define MACHENIKE_TRIGGER_IOCTRL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x50F, METHOD_NEITHER, 3)

// ============================================================
// 【内核纯游离物理页 GUID 签名防重复加载暗桩】(方案 5: Headless Physical Canary)
// 彻底废除 KUSER_SHARED_DATA 写入（彻底杜绝 PatchGuard 0x109 蓝屏）
// 基于 MmAllocatePagesForMdl 申请纯游离物理页，无 Pool 登记、无内核 VA 映射
// ============================================================
#define DRV_CANARY_WINDOW_LOW 0x10000000ULL        // 256MB 起
#define DRV_CANARY_WINDOW_HIGH 0x20000000ULL       // 512MB 止
#define DRV_WSK_CANARY_MAGIC 0x57534B5F4C4F4144ULL // ASCII: "WSK_LOAD"

// 128 位高熵全局唯一特征签名: {57534B5F-4C4F-4144-B899-A1B2C3D4E5F6}
#define DRV_CANARY_GUID_D1 0x57534B5FUL
#define DRV_CANARY_GUID_D2 0x4C4F
#define DRV_CANARY_GUID_D3 0x4144
#define DRV_CANARY_GUID_D4 {0xB8, 0x99, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6}

#pragma pack(push, 1)
typedef struct _DRV_WSK_CANARY
{
    GUID Signature;           // 16 字节全局唯一 GUID
    uint64_t Magic;           // DRV_WSK_CANARY_MAGIC (8 字节)
    uint64_t KernelImageVA;   // 映射的目标核心驱动基址 (8 字节)
    uint32_t ImageSize;       // 核心驱动镜像大小 (4 字节)
    uint32_t ProtocolVersion; // 协议版本 (4 字节)
    uint64_t CanaryPhysAddr;  // 该物理页自身的 PA (8 字节)
    uint64_t Timestamp;       // 加载时间戳 (8 字节)
    uint64_t Reserved;        // 保留填充 (8 字节)
} DRV_WSK_CANARY, *PDRV_WSK_CANARY;
#pragma pack(pop)

// ============================================================
// Loader 注入启动配置参数（由 Loader 在 DriverEntry rdx 传入）
// ============================================================
#define DRV_BOOT_CONFIG_MAGIC 0x57534B43U // 'WSKC'
#define DRV_BOOT_MAGIC DRV_BOOT_CONFIG_MAGIC
#define DRV_TRANSPORT_TCP 2
#define DRV_TRANSPORT_UDP 3
#define DRV_TRANSPORT_USB 4

// 启动特性开关位掩码 (DRV_BOOT_CONFIG.Flags)
#define DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP 0x00000001 // 允许驱动异步粉碎删除宿主 Loader 进程与文件
#define DRV_BOOT_FLAG_DELETE_LOADER DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP
#define DRV_BOOT_FLAG_ENABLE_VT 0x00000002

#pragma pack(push, 1)
typedef struct _DRV_BOOT_CONFIG_CORE
{
    uint32_t Magic;         // DRV_BOOT_CONFIG_MAGIC ('WSKC')
    uint32_t TransportMode; // 2 = WSK_TCP, 3 = WSK_UDP, 4 = USB
    uint16_t Port;          // 通信端口 (如 10001 / 10002)
    uint16_t Reserved;
    uint32_t AuthToken; // 握手认证 Token
    uint32_t Flags;     // 特性开关
} DRV_BOOT_CONFIG_CORE, *PDRV_BOOT_CONFIG_CORE;
static_assert(sizeof(DRV_BOOT_CONFIG_CORE) == 20, "DRV_BOOT_CONFIG_CORE must be 20 bytes");

typedef struct _DRV_BOOT_CONFIG
{
    uint32_t Magic;         // DRV_BOOT_CONFIG_MAGIC ('WSKC')
    uint32_t TransportMode; // 2 = WSK_TCP, 3 = WSK_UDP, 4 = USB
    uint16_t Port;          // 通信端口 (如 10001 / 10002)
    uint16_t Reserved;
    uint32_t AuthToken;       // 握手认证 Token
    uint32_t Flags;           // 特性开关
    uint8_t SessionToken[16]; // 云端下发的随机鉴权熵 (扩展防伪校验)
} DRV_BOOT_CONFIG, *PDRV_BOOT_CONFIG;

typedef struct _DRV_BOOT_CONFIG_EX
{
    DRV_BOOT_CONFIG Base;
    wchar_t HostLoaderPath[260]; // 宿主加载器自身绝对路径
    char ApiUrl[128];            // 业务 API 地址
    char LoginUrl[128];          // 鉴权 API 地址
    char ReportUrl[128];         // 上报 API 地址
    char BrandVersion[32];       // 品牌版本
    char SelectedGame[32];       // 所选游戏标识
    char ClientVersion[32];      // 客户端版本
    char CardKey[64];            // 卡密字符串
} DRV_BOOT_CONFIG_EX, *PDRV_BOOT_CONFIG_EX;

#pragma pack(push, 1)
typedef struct _DRV_USER_PAYLOAD_ANCHOR
{
    uint64_t Tag0;                                  // 动态哈希 Tag0 (由动态 Token 派生)
    uint64_t Tag1;                                  // 动态哈希 Tag1 (~Tag0 ^ 0xA5A5A5A55A5A5A5AULL)
    uint32_t Nonce;                                 // 随机 Nonce 动态盐
    uint32_t CipherLen;                             // 密文长度 (sizeof(DRV_BOOT_CONFIG_EX))
    uint32_t Checksum;                              // 明文 Adler32 校验和
    uint32_t Reserved;                              // 对齐填充
    uint8_t CipherData[sizeof(DRV_BOOT_CONFIG_EX)]; // RC4 密文载荷
} DRV_USER_PAYLOAD_ANCHOR, *PDRV_USER_PAYLOAD_ANCHOR;
#pragma pack(pop)

// ============================================================
// 正常加载模式下的 IOCTL 通信控制码与设备名称定义
// 供 Loader / R3 应用程序通过 DeviceIoControl 动态下发参数并启动不同传输模式
// ============================================================
#include <winioctl.h>
#define IOCTL_MK_START_TRANSPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_STOP_TRANSPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_DISCOVER_CLIENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MK_USER_DEVICE_NAME L"\\\\.\\MsNetEndpoint"

// ============================================================
// Loader 驱动加载模式开关配置
// ============================================================
// 1. MODE_MANUAL_MAP_CAVE: 当前模式（利用宿主驱动 Code Cave + PTE Remap 挂接）
// 2. MODE_MANUAL_MAP:      分页内存映射模式（向内核申请独立 Pool 内存并展开映射）
// 3. 两个宏均为 0:          Windows 原生服务加载流程（SCM: CreateService / StartService）
// ============================================================
// [CAVE DISABLED] MODE_MANUAL_MAP_CAVE 代码已全部注释禁用
#ifndef MODE_MANUAL_MAP_CAVE
#define MODE_MANUAL_MAP_CAVE 0 // 强制置 0，彻底禁用 Code Cave 挂接
#endif

#ifndef MODE_MANUAL_MAP
#define MODE_MANUAL_MAP 0 // 独立申请分页内存 ManualMap 映射模式
#endif

#if (MODE_MANUAL_MAP_CAVE && MODE_MANUAL_MAP)
#error "MODE_MANUAL_MAP_CAVE 与 MODE_MANUAL_MAP 不能同时开启，请仅开启其一！"
#endif

// ============================================================
// 微信联系人与群聊内存解析单测开关
// 1 = 启用微信联系人/群聊解析测试模块 (支持命令行 --test-wx 或独立测试)
// 0 = 关闭该单测模块 (完全不引入测试代码)
// ============================================================
#ifndef ENABLE_WECHAT_PARSER_TEST
#define ENABLE_WECHAT_PARSER_TEST 0
#endif

// ============================================================
// 通信传输模式 (TCP / UDP / USB) 开关配置
// 1 = 编译并启用 TCP / UDP / USB 模式选择、参数解析与交互式配置
// 0 = 关闭相关传输模式代码编译（免网络/免USB模式）
// ============================================================
#ifndef ENABLE_TRANSPORT_MODES
#define ENABLE_TRANSPORT_MODES 1

// ============================================================
// 全局 VT (VMX-Root Hypervisor) 框架加载与一键迁移开关
// 1 = 编译并启用 VT 底座一键部署 (mapDriver -> TestDriver -> payloadRuntime) 及全部 mapctl 控制指令
// 0 = 关闭 VT 底座加载，仅执行原有 CheatDrv 加载流程
// ============================================================
#ifndef ENABLE_VT_FRAMEWORK
#define ENABLE_VT_FRAMEWORK 0 // 关闭基于 Code Cave 迁移的 3-in-1 劫持，走正常 Pool 内存手动映射
#endif
#ifndef MK_ENABLE_VT_FRAMEWORK
#define MK_ENABLE_VT_FRAMEWORK ENABLE_VT_FRAMEWORK
#endif
#endif

// ============================================================
// 纯 Flat 架构规范：彻底移除 .pdata 侵入与宿主 PE 头改写
// ============================================================
// 100% 保持宿主驱动原始 PE 头干净，杜绝被反作弊磁盘文件比对检出。
// 驱动 Shellcode 采用平栈中继（Flat Trampoline / Leaf Only）退出模式。
// ============================================================
// WINPMEM_MEMORY_INFO（与 drv\Struct.h 一致）
// ============================================================
#pragma pack(push, 8)
typedef struct _MK_PHYS_RANGE
{
    LARGE_INTEGER BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} MK_PHYS_RANGE;

typedef struct _WINPMEM_MEMORY_INFO
{
    LARGE_INTEGER CR3;
    LARGE_INTEGER NtBuildNumber;
    LARGE_INTEGER KernBase;
    LARGE_INTEGER KDBG;
    LARGE_INTEGER KPCR[64];
    LARGE_INTEGER PfnDataBase;
    LARGE_INTEGER PsLoadedModuleList;
    LARGE_INTEGER PsActiveProcessHead;
    LARGE_INTEGER NtBuildNumberAddr;
    LARGE_INTEGER Padding[0xfe];
    LARGE_INTEGER NumberOfRuns;
    MK_PHYS_RANGE Run[100];
} WINPMEM_MEMORY_INFO;
#pragma pack(pop)

// ============================================================
// 内核结构用户态镜像（仅做解析用，地址为内核 VA）
// ============================================================
#pragma pack(push, 8)
typedef struct _UNICODE_STRING_K
{
    USHORT Length;
    USHORT MaximumLength;
    uint32_t _pad;
    uint64_t Buffer; // 内核 VA
} UNICODE_STRING_K;

typedef struct _KLDR_ENTRY_K
{
    uint64_t Flink; // 内核 VA
    uint64_t Blink;
    uint64_t ExceptionTable;
    uint32_t ExceptionTableSize;
    uint32_t _pad0;
    uint64_t GpValue;
    uint64_t NonPagedDebugInfo;
    uint64_t DllBase; // 内核 VA - 模块基址
    uint64_t EntryPoint;
    uint32_t SizeOfImage;
    uint32_t _pad1;
    UNICODE_STRING_K FullDllName;
    UNICODE_STRING_K BaseDllName;
    uint32_t Flags;
    uint16_t LoadCount;
    uint16_t __Unused5;
    uint64_t SectionPointer;
    uint32_t CheckSum;
    uint32_t _pad2;
    uint64_t LoadedImports;
    uint64_t PatchInformation;
} KLDR_ENTRY_K;
#pragma pack(pop)

// ============================================================
// 日志输出总开关 (1: 开启调试输出, 0: 完全关闭调试输出)
// ============================================================
#ifndef ENABLE_DBG_LOG
#define ENABLE_DBG_LOG 1
#endif

#if ENABLE_DBG_LOG

__declspec(noinline) static inline void SafeLoaderPrint(FILE *stream, const char *prefix, const char *fmt, ...)
{
    char buffer[1024];
    va_list args;
    va_start(args, fmt);

    __try
    {
        buffer[0] = '\0';
        int ret = vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args);
        if (ret >= 0 || ret == -1)
        {
            buffer[sizeof(buffer) - 1] = '\0';
            fprintf(stream ? stream : stdout, "%s%s\n", prefix ? prefix : "", buffer);
            fflush(stream ? stream : stdout);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 捕获非法指针解引用/不可访问内存等异常，防止 Loader 进程崩溃闪退
    }

    va_end(args);
}

#ifdef DBG
#undef DBG
#endif

#define LOG_INFO(fmt, ...) SafeLoaderPrint(stdout, "[*] ", fmt, ##__VA_ARGS__)
#define LOG_OK(fmt, ...) SafeLoaderPrint(stdout, "[+] ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) SafeLoaderPrint(stdout, "[!] ", fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) SafeLoaderPrint(stderr, "[-] ", fmt, ##__VA_ARGS__)
#define LOG_HEX(fmt, ...) SafeLoaderPrint(stdout, "[~] ", fmt, ##__VA_ARGS__)
#define DBG(fmt, ...) SafeLoaderPrint(stdout, "[DBG] ", fmt, ##__VA_ARGS__)

#else

#ifdef DBG
#undef DBG
#endif

#define LOG_INFO(...) ((void)0)
#define LOG_OK(...) ((void)0)
#define LOG_WARN(...) ((void)0)
#define LOG_ERR(...) ((void)0)
#define LOG_HEX(...) ((void)0)
#define DBG(...) ((void)0)
#endif
static inline uint64_t rotl64(uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}
// ---- SipHash-2-4（用于生成 Token，与驱动端 Main.cpp MachenikeCalcToken 保持完全一致）----
static inline uint64_t SipHash24(const uint8_t key[16], const uint8_t *msg, size_t msgLen)
{
    uint64_t k0, k1;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

#define SIPROUND                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        v0 += v1;                                                                                                      \
        v1 = rotl64(v1, 13);                                                                                           \
        v1 ^= v0;                                                                                                      \
        v0 = rotl64(v0, 32);                                                                                           \
        v2 += v3;                                                                                                      \
        v3 = rotl64(v3, 16);                                                                                           \
        v3 ^= v2;                                                                                                      \
        v0 += v3;                                                                                                      \
        v3 = rotl64(v3, 21);                                                                                           \
        v3 ^= v0;                                                                                                      \
        v2 += v1;                                                                                                      \
        v1 = rotl64(v1, 17);                                                                                           \
        v1 ^= v2;                                                                                                      \
        v2 = rotl64(v2, 32);                                                                                           \
    } while (0)

    size_t i = 0;
    while (i + 8 <= msgLen)
    {
        uint64_t m;
        memcpy(&m, msg + i, 8);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
        i += 8;
    }
    // 末尾处理
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
#undef SIPROUND
}

// ---- Token 计算（与 drv\Main.cpp MachenikeCalcToken 一致）----
static inline uint32_t CalcToken(uint64_t counter, uint32_t pid)
{
    uint8_t msg[16] = {};
    memcpy(msg, &counter, 8);
    memcpy(msg + 8, &pid, 4);
    memcpy(msg + 12, &g_Salt4, 4);
    uint64_t h = SipHash24(g_SipHashKey, msg, sizeof(msg));
    return (uint32_t)(h ^ (h >> 32));
}

__declspec(align(16)) static DRV_USER_PAYLOAD_ANCHOR g_UserAnchor = {};

static inline void Rc4Crypt(uint8_t *data, uint32_t len, const uint8_t *key, uint32_t keyLen)
{
    uint8_t S[256];
    for (uint32_t i = 0; i < 256; i++)
        S[i] = (uint8_t)i;
    uint32_t j = 0;
    for (uint32_t i = 0; i < 256; i++)
    {
        j = (j + S[i] + key[i % keyLen]) & 0xFF;
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    uint32_t i = 0;
    j = 0;
    for (uint32_t k = 0; k < len; k++)
    {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

static inline uint32_t CalcAdler32(const uint8_t *data, size_t len)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++)
    {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

static inline void SetupUserPayloadAnchor(uint32_t token, const DRV_BOOT_CONFIG_EX &cfgEx)
{
    g_UserAnchor.Tag0 = SipHash24(g_SipHashKey, (const uint8_t *)&token, sizeof(token));
    g_UserAnchor.Tag1 = ~g_UserAnchor.Tag0 ^ 0xA5A5A5A55A5A5A5AULL;
    g_UserAnchor.Nonce = (uint32_t)__rdtsc();
    g_UserAnchor.CipherLen = sizeof(DRV_BOOT_CONFIG_EX);
    g_UserAnchor.Checksum = CalcAdler32((const uint8_t *)&cfgEx, sizeof(DRV_BOOT_CONFIG_EX));
    g_UserAnchor.Reserved = 0;

    uint8_t key[24];
    memcpy(&key[0], g_SipHashKey, 16);
    memcpy(&key[16], &token, 4);
    memcpy(&key[20], &g_UserAnchor.Nonce, 4);

    memcpy(g_UserAnchor.CipherData, &cfgEx, sizeof(DRV_BOOT_CONFIG_EX));
    Rc4Crypt(g_UserAnchor.CipherData, sizeof(DRV_BOOT_CONFIG_EX), key, sizeof(key));
}

// ---- 统一打开驱动设备（支持内存锚点加密直读、动态 Token 校验与 NoAuth 降级）----
static inline HANDLE OpenDriverDeviceCompatible(const wchar_t *baseDeviceName = MK_USER_DEVICE_NAME,
                                                DWORD dwDesiredAccess = GENERIC_READ | GENERIC_WRITE,
                                                DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                int maxRetries = 25, int retryDelayMs = 100,
                                                const DRV_BOOT_CONFIG_EX *pBootConfigEx = nullptr)
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    uint32_t pid = GetCurrentProcessId();

    for (int retry = 0; retry < maxRetries; ++retry)
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        uint64_t ft64 = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        uint64_t sec = ft64 / 10000000ULL;
        if (sec >= 11644473600ULL)
            sec -= 11644473600ULL;
        uint64_t counter = sec / g_Step;

        for (int d = -1; d <= 1; ++d)
        {
            uint32_t token = CalcToken((uint64_t)((int64_t)counter + d), pid);
            if (pBootConfigEx)
            {
                SetupUserPayloadAnchor(token, *pBootConfigEx);
            }
            wchar_t devPath[128] = {};
            swprintf_s(devPath, L"%ls\\%08X", baseDeviceName, token);

            hDevice =
                CreateFileW(devPath, dwDesiredAccess, dwShareMode, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDevice != INVALID_HANDLE_VALUE)
            {
                LOG_OK("OpenDriverDeviceCompatible: Successfully opened driver with Token 0x%08X (%ls)", token,
                       devPath);
                return hDevice;
            }
        }

        if (retryDelayMs > 0 && retry + 1 < maxRetries)
        {
            Sleep(retryDelayMs);
        }
    }

    return INVALID_HANDLE_VALUE;
}

// ============================================================
// ScopedThreadAffinity: 单核绑定防核间调度迁移保护 (RAII)
// 确保从 PTE.RW 修改、Shellcode 写入、default 分支触发到清理还原全程
// 严格在同一个 CPU 逻辑核心上执行，彻底消除单核 TLB 刷新滞留与核间缓存不一致。
// ============================================================
class ScopedThreadAffinity
{
public:
    explicit ScopedThreadAffinity(DWORD_PTR preferredCoreMask = 0)
    {
        DWORD_PTR procMask = 0, sysMask = 0;
        if (GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask) && procMask != 0)
        {
            DWORD_PTR targetMask = preferredCoreMask;
            if (targetMask == 0 || (targetMask & procMask) == 0)
            {
                // 默认选择当前进程可用的最低编号物理/逻辑核心 (Lowest available core)
                targetMask = procMask & (-static_cast<int64_t>(procMask));
            }
            m_oldMask = SetThreadAffinityMask(GetCurrentThread(), targetMask);
            if (m_oldMask != 0)
            {
                m_isBound = true;
                // 让步一次以让操作系统调度器立刻生效线程核绑定
                Sleep(0);
            }
        }
    }

    ~ScopedThreadAffinity()
    {
        if (m_isBound && m_oldMask != 0)
        {
            SetThreadAffinityMask(GetCurrentThread(), m_oldMask);
        }
    }

    bool isBound() const
    {
        return m_isBound;
    }

private:
    DWORD_PTR m_oldMask = 0;
    bool m_isBound = false;
};
