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
#define DEVICE_PATH         L"\\\\.\\Machenike"

// SipHash Key（与 drv\Main.cpp 中硬编码一致）
static const uint8_t g_SipHashKey[16] = {
    0x21, 0x7A, 0xA9, 0x3C, 0x10, 0x55, 0xD2, 0x6F,
    0x9B, 0x4E, 0x01, 0x88, 0xC7, 0x33, 0xFA, 0x90
};
static const uint32_t  g_Salt4 = 0x4D43484EU;   // 'MCHN'
static const uint64_t  g_Step  = 30;

// IOCTL 码（METHOD_NEITHER, FILE_ANY_ACCESS，与 drv\FrameWork.h 及 device_pmem.c 保持完全一致）
#define MACHENIKE_GET_INFO_IOCTRL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x503, METHOD_NEITHER, 3)
#define MACHENIKE_READ_IOCTRL       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x504, METHOD_NEITHER, 3)
#define MACHENIKE_WRITE_IOCTRL      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x505, METHOD_NEITHER, 3)

// 触发 default 分支：发一个驱动不认识的 IOCTL 码即可
#define MACHENIKE_TRIGGER_IOCTRL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x50F, METHOD_NEITHER, 3)

// ============================================================
// 方案 1：内核物理暗桩标记（Canary Magic）
// 记录在宿主/触发驱动 DOS 头部保留区 (e_res2[0..3], 偏移 0x28-0x37)
// 完全基于物理内存读写原语，零网络交互，零内核命名对象
// ============================================================
#define DRV_WSK_CANARY_MAGIC        0x57534B5F4C4F4144ULL   // ASCII: "WSK_LOAD"

#pragma pack(push, 1)
typedef struct _DRV_WSK_CANARY {
    uint64_t Magic;         // 偏移 0x28-0x2F: DRV_WSK_CANARY_MAGIC (8 字节)
    uint64_t KernelImageVA; // 偏移 0x30-0x37: 映射的目标核心驱动基址 (8 字节)
    uint32_t ImageSize;     // 偏移 0x38-0x3B: 核心驱动镜像大小 (4 字节)
    // 严格限制为 20 字节（精确占用 e_res2[10] 范围 0x28-0x3B，绝不覆盖 0x3C 处的 e_lfanew）
} DRV_WSK_CANARY;

// ============================================================
// Loader 注入启动配置参数（由 Loader 在 DriverEntry rdx 传入）
// ============================================================
#define DRV_BOOT_CONFIG_MAGIC       0x57534B43U // 'WSKC'
#define DRV_BOOT_MAGIC              DRV_BOOT_CONFIG_MAGIC
#define DRV_TRANSPORT_TCP           1
#define DRV_TRANSPORT_UDP           2
#define DRV_TRANSPORT_USB           3

typedef struct _DRV_BOOT_CONFIG {
    uint32_t Magic;          // DRV_BOOT_CONFIG_MAGIC ('WSKC')
    uint32_t TransportMode;  // 1 = WSK_TCP, 2 = WSK_UDP, 3 = USB
    uint16_t Port;           // 通信端口 (如 10001 / 10002)
    uint16_t Reserved;
    uint32_t AuthToken;      // 握手认证 Token
    uint32_t Flags;          // 特性开关
} DRV_BOOT_CONFIG, *PDRV_BOOT_CONFIG;
#pragma pack(pop)

// ============================================================
// Loader 驱动加载模式开关配置
// ============================================================
// 1. MODE_MANUAL_MAP_CAVE: 当前模式（利用宿主驱动 Code Cave + PTE Remap 挂接）
// 2. MODE_MANUAL_MAP:      分页内存映射模式（向内核申请独立 Pool 内存并展开映射）
// 3. 两个宏均为 0:          Windows 原生服务加载流程（SCM: CreateService / StartService）
// ============================================================
#ifndef MODE_MANUAL_MAP_CAVE
#define MODE_MANUAL_MAP_CAVE    1   // 默认模式：Code Cave + PTE Remap 挂接
#endif

#ifndef MODE_MANUAL_MAP
#define MODE_MANUAL_MAP         0   // 独立申请分页内存 ManualMap 映射模式
#endif

#if (MODE_MANUAL_MAP_CAVE && MODE_MANUAL_MAP)
#error "MODE_MANUAL_MAP_CAVE 与 MODE_MANUAL_MAP 不能同时开启，请仅开启其一！"
#endif

// ============================================================
// 方案 A 异常表（.pdata）合并挂载开关宏
// ============================================================
// 1 = 启用合并挂载：将宿主与 payload 的 .pdata 合并追加至宿主内部，
//     Remap 足够物理内存，并更新宿主 PE 头的 DataDirectory[EXCEPTION]，实现零动态链表。
// 0 = 禁用合并挂载：仅 Remap payload 自身所需物理内存，不修改宿主 PE 头与异常目录。
#ifndef CFG_ENABLE_MERGED_PDATA
#define CFG_ENABLE_MERGED_PDATA 1
#endif

// ============================================================
// WINPMEM_MEMORY_INFO（与 drv\Struct.h 一致）
// ============================================================
#pragma pack(push, 8)
typedef struct _MK_PHYS_RANGE {
    LARGE_INTEGER BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} MK_PHYS_RANGE;

typedef struct _WINPMEM_MEMORY_INFO {
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
typedef struct _UNICODE_STRING_K {
    USHORT Length;
    USHORT MaximumLength;
    uint32_t _pad;
    uint64_t Buffer;   // 内核 VA
} UNICODE_STRING_K;

typedef struct _KLDR_ENTRY_K {
    uint64_t Flink;            // 内核 VA
    uint64_t Blink;
    uint64_t ExceptionTable;
    uint32_t ExceptionTableSize;
    uint32_t _pad0;
    uint64_t GpValue;
    uint64_t NonPagedDebugInfo;
    uint64_t DllBase;          // 内核 VA - 模块基址
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

__declspec(noinline)
static inline void SafeLoaderPrint(FILE* stream, const char* prefix, const char* fmt, ...)
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

#define LOG_INFO(fmt, ...)  SafeLoaderPrint(stdout, "[*] ", fmt, ##__VA_ARGS__)
#define LOG_OK(fmt, ...)    SafeLoaderPrint(stdout, "[+] ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  SafeLoaderPrint(stdout, "[!] ", fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   SafeLoaderPrint(stderr, "[-] ", fmt, ##__VA_ARGS__)
#define LOG_HEX(fmt, ...)   SafeLoaderPrint(stdout, "[~] ", fmt, ##__VA_ARGS__)
#define DBG(fmt, ...)       SafeLoaderPrint(stdout, "[DBG] ", fmt, ##__VA_ARGS__)

#else

#ifdef DBG
#undef DBG
#endif

#define LOG_INFO(...)  ((void)0)
#define LOG_OK(...)    ((void)0)
#define LOG_WARN(...)  ((void)0)
#define LOG_ERR(...)   ((void)0)
#define LOG_HEX(...)   ((void)0)
#define DBG(...)       ((void)0)

#endif

static inline uint64_t rotl64(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}
