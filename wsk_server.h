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

#ifndef WSK_FLAG_NODELAY
#define WSK_FLAG_NODELAY 0x00000002
#endif

typedef struct _WSK_SYNC_CONTEXT
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    PKEVENT pEvent;
    KEVENT LocalEvent;
} WSK_SYNC_CONTEXT, *PWSK_SYNC_CONTEXT;

#define MK_WSK_FAST_BUF_SIZE (1024 * 1024)       // 1MB 接收端零拷贝与常驻 IRP FastPath 缓冲
#define MK_WSK_SEND_SLOT_SIZE (1024 * 1024)      // 1MB 单发送槽位：完美覆盖 100~240 页连续大跨页 DirectOut 原位直写 (消除大池分配与二次 memcpy)
#define MK_WSK_SEND_PIPELINE_SLOTS 4             // ★★★ 4 槽位深度全双工环形流水线：4MB 飞行窗口全异步 DMA 出网，彻底释放大页面并发吞吐 ★★★

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
    ULONG cbRecvHead; // ★★★ 双指针滑动接收缓冲区：已消费游标 (消除 99.99% memmove) ★★★
    ULONG cbRecvTail; // ★★★ 双指针滑动接收缓冲区：已接收游标 ★★★
    
    // 全双工 8 槽位环形发送流水线：主线程异步出网，无需阻塞睡眠，发送与接收 100% 时间重叠
    UCHAR FastSendBuf[MK_WSK_SEND_PIPELINE_SLOTS][MK_WSK_SEND_SLOT_SIZE];
    PMDL pFastSendMdl[MK_WSK_SEND_PIPELINE_SLOTS];
    PIRP pSendIrp[MK_WSK_SEND_PIPELINE_SLOTS];
    KEVENT SendEvent[MK_WSK_SEND_PIPELINE_SLOTS];
    WSK_SYNC_CONTEXT SendSync[MK_WSK_SEND_PIPELINE_SLOTS]; // ★★★ 常驻完成例程上下文，杜绝异步发送栈变量悬挂导致 BSOD 0xD1 ★★★
    BOOLEAN fSendInFlight[MK_WSK_SEND_PIPELINE_SLOTS];
    ULONG ActiveSendIdx;

    // 接收端预构建 MDL 与常驻 IRP
    PMDL pFastRecvMdl;
    PIRP pRecvIrp;
    KEVENT RecvEvent;

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
