#pragma once

#include "FrameWork.h"
#include <wsk.h>
#include "leechrpc_types.h"

// ACE对抗：伪装为 tcpip.sys TCP 连接分配 Tag，规避 BigPool 枚举审计
#define MK_WSK_POOL_TAG 'ApcT'
#define MK_WSK_DEFAULT_PORT 10001
#define MK_WSK_MAX_CLIENTS 10

#include "Common.h"

struct _MK_WSK_SERVER;
struct _MK_WSK_CLIENT;

// ============================================================================
// 工作线程池性能开关 (Worker Pool Toggle)
// 1: 启用多工作线程池 (方案 A 异步响应队列模式)
// 0: 纯单线程贪婪非阻塞流水线模式 (0 额外系统线程，绝对免疫反作弊线程回调审计，极速贪婪排空)
// ============================================================================
#define MK_WSK_USE_WORKER_POOL 0
#define MK_WSK_WORKER_COUNT    10

#define MK_WSK_WORK_ITEM_POOL_SIZE 64

typedef struct _MK_WSK_WORK_ITEM {
    LIST_ENTRY ListEntry;
    ULONG RequestId;
    ULONG64 Nonce;
    ULONG cbRpcDataRaw;
    PUCHAR pbRpcDataRaw;
    PUCHAR pbAllocatedFrame;

    // 方案 A: 零分配双向静态缓冲 (0 额外池分配、彻底消灭 16000 次小池锁争用)
    ULONG cbRspFrame;
    PUCHAR pbLargeRsp;        // 超大包响应独立指针 (<= 512 字节走 RspBuf)
    UCHAR ReqBuf[512];        // 静态请求缓冲 (常规 56 字节请求零动态分配)
    UCHAR RspBuf[512];        // 静态响应缓冲 (常规 64 字节响应零动态分配)
} MK_WSK_WORK_ITEM, *PMK_WSK_WORK_ITEM;

#define MK_WSK_WORKER_BUF_SIZE (64 * 1024) // 64KB 独享高速发送缓冲与预构建 MDL (0 动态池分配、0 动态 MDL)

typedef struct _MK_WSK_WORKER {
    HANDLE hThread;
    PETHREAD pThread;
    struct _MK_WSK_CLIENT *Client;
    ULONG WorkerId;
    PUCHAR SendBuf;
    PMDL pSendMdl;
} MK_WSK_WORKER, *PMK_WSK_WORKER;

#define MK_WSK_FAST_BUF_SIZE (1024 * 1024) // 1MB 零拷贝与常驻 IRP FastPath 缓冲 (完整覆盖250页/1MB散列连续大块读，支持双帧合并冲刷)

typedef struct _MK_WSK_CLIENT
{
    LIST_ENTRY ListEntry;
    PWSK_SOCKET Socket;
    SOCKADDR_IN RemoteAddr;
    HANDLE hThread;
    PETHREAD pThread;
    volatile BOOLEAN fActive;
    ULONG ClientId;
    struct _MK_WSK_SERVER *Server;

    UCHAR FastRecvBuf[MK_WSK_FAST_BUF_SIZE];
    UCHAR FastSendBuf[MK_WSK_FAST_BUF_SIZE];

    // 优化：预构建 MDL，消灭热路径动态 IoAllocateMdl 开销
    PMDL pFastRecvMdl;
    PMDL pFastSendMdl;

    // 优化：常驻同步 IRP 与事件，消灭热路径动态 IoAllocateIrp / IoFreeIrp 开销
    PIRP pRecvIrp;
    KEVENT RecvEvent;
    PIRP pSendIrp;
    KEVENT SendEvent;

    // 性能优化：Client 级 hLC 句柄直通缓存，消灭高频 ExAcquireFastMutex 锁争用
    HANDLE Cached_hLC;
    ULONG Cached_dwRpcClientID;

    // 并发工作线程池支持
    KSPIN_LOCK QueueLock;
    LIST_ENTRY QueueHead;
    KEVENT QueueEvent;
    volatile BOOLEAN fTerminateWorkers;
    KMUTEX SendMutex;
    MK_WSK_WORKER Workers[MK_WSK_WORKER_COUNT];
    LONG ActiveWorkerCount;

    // 方案 A: 异步合并响应队列与无锁 Try-Flush 冲刷引擎
    KSPIN_LOCK ResponseLock;
    LIST_ENTRY ResponseHead;
    volatile LONG FlushActive;

    // 方案 A 极致优化：预分配工作项对象池 (彻底消灭 16000 次 ExAllocatePool/Free)
    KSPIN_LOCK ItemPoolLock;
    LIST_ENTRY FreeItemHead;
    MK_WSK_WORK_ITEM ItemPool[MK_WSK_WORK_ITEM_POOL_SIZE];
} MK_WSK_CLIENT, *PMK_WSK_CLIENT;


typedef struct _MK_WSK_SERVER
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    WSK_REGISTRATION Registration;
    WSK_PROVIDER_NPI ProviderNpi;
    BOOLEAN fRegistered;
    BOOLEAN fCapturedNpi;

    PWSK_SOCKET ListenSocket;
    HANDLE hAcceptThread;
    PETHREAD pAcceptThread;
    volatile BOOLEAN fRunning;

    USHORT Port;

    KSPIN_LOCK ClientListLock;
    LIST_ENTRY ClientListHead;
    volatile LONG ActiveClientCount;
} MK_WSK_SERVER, *PMK_WSK_SERVER;

#ifdef __cplusplus
extern "C"
{
#endif

    extern MK_WSK_SERVER g_WskServer;


    NTSTATUS WskServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, USHORT Port);
    VOID WskServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);

#ifdef __cplusplus
}
#endif
