#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <winioctl.h>
#include <shellapi.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <vector>
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
#define DRV_CANARY_WINDOW_LOW   0x10000000ULL // 256MB 起
#define DRV_CANARY_WINDOW_HIGH  0x20000000ULL // 512MB 止
#define DRV_WSK_CANARY_MAGIC    0x57534B5F4C4F4144ULL // ASCII: "WSK_LOAD"

// 128 位高熵全局唯一特征签名: {57534B5F-4C4F-4144-B899-A1B2C3D4E5F6}
#define DRV_CANARY_GUID_D1 0x57534B5FUL
#define DRV_CANARY_GUID_D2 0x4C4F
#define DRV_CANARY_GUID_D3 0x4144
#define DRV_CANARY_GUID_D4 { 0xB8, 0x99, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6 }

#pragma pack(push, 1)
typedef struct _DRV_WSK_CANARY
{
    GUID     Signature;       // 16 字节全局唯一 GUID
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
#define DRV_TRANSPORT_TCP 1
#define DRV_TRANSPORT_UDP 2
#define DRV_TRANSPORT_USB 3

typedef struct _DRV_BOOT_CONFIG
{
    uint32_t Magic;         // DRV_BOOT_CONFIG_MAGIC ('WSKC')
    uint32_t TransportMode; // 1 = WSK_TCP, 2 = WSK_UDP, 3 = USB
    uint16_t Port;          // 通信端口 (如 10001 / 10002)
    uint16_t Reserved;
    uint32_t AuthToken; // 握手认证 Token
    uint32_t Flags;     // 特性开关
} DRV_BOOT_CONFIG, *PDRV_BOOT_CONFIG;

// ============================================================
// 正常加载模式下的 IOCTL 通信控制码与设备名称定义
// 供 Loader / R3 应用程序通过 DeviceIoControl 动态下发参数并启动不同传输模式
// ============================================================
#include <winioctl.h>
#define IOCTL_MK_START_TRANSPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_STOP_TRANSPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_DISCOVER_CLIENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MK_USER_DEVICE_NAME L"\\\\.\\MachenikeIo"

// ============================================================
// Loader 驱动加载模式开关配置
// ============================================================
// 1. MODE_MANUAL_MAP_CAVE: 当前模式（利用宿主驱动 Code Cave + PTE Remap 挂接）
// 2. MODE_MANUAL_MAP:      分页内存映射模式（向内核申请独立 Pool 内存并展开映射）
// 3. 两个宏均为 0:          Windows 原生服务加载流程（SCM: CreateService / StartService）
// ============================================================
#ifndef MODE_MANUAL_MAP_CAVE
#define MODE_MANUAL_MAP_CAVE 0 // 默认模式：Code Cave + PTE Remap 挂接
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
#define ENABLE_WECHAT_PARSER_TEST 1
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

// ============================================================
// ScopedThreadAffinity: 单核绑定防核间调度迁移保护 (RAII)
// 确保从 PTE.RW 修改、Shellcode 写入、default 分支触发到清理还原全程
// 严格在同一个 CPU 逻辑核心上执行，彻底消除单核 TLB 刷新滞留与核间缓存不一致。
// ============================================================
class ScopedThreadAffinity {
public:
    explicit ScopedThreadAffinity(DWORD_PTR preferredCoreMask = 0) {
        DWORD_PTR procMask = 0, sysMask = 0;
        if (GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask) && procMask != 0) {
            DWORD_PTR targetMask = preferredCoreMask;
            if (targetMask == 0 || (targetMask & procMask) == 0) {
                // 默认选择当前进程可用的最低编号物理/逻辑核心 (Lowest available core)
                targetMask = procMask & (-static_cast<int64_t>(procMask));
            }
            m_oldMask = SetThreadAffinityMask(GetCurrentThread(), targetMask);
            if (m_oldMask != 0) {
                m_isBound = true;
                // 让步一次以让操作系统调度器立刻生效线程核绑定
                Sleep(0);
            }
        }
    }

    ~ScopedThreadAffinity() {
        if (m_isBound && m_oldMask != 0) {
            SetThreadAffinityMask(GetCurrentThread(), m_oldMask);
        }
    }

    bool isBound() const { return m_isBound; }

private:
    DWORD_PTR m_oldMask = 0;
    bool      m_isBound = false;
};
