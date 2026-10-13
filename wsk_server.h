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

struct _MK_WSK_SERVER;

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


#define MK_WSK_FAST_BUF_SIZE (1024 * 1024) // 1MB 零拷贝与常驻 IRP FastPath 缓冲 (完整覆盖250页/1MB散列连续大块读，支持双帧合并冲刷)

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
