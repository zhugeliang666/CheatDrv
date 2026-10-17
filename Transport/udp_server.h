#pragma once

#include "Common.h"
#include "FrameWork.h"
#include "RpcDispatcher.h"
#include <wsk.h>

#define MK_UDP_SERVER_DEFAULT_PORT 10003
#define MK_UDP_SERVER_MAX_PACKET_SIZE (1024 * 1024) // 升级至 1MB：完美容纳 100~240 页大跨页 DirectOut 原位直写 (消除大池分配与二次 memcpy)
#define MK_UDP_SAFE_MTU_PAYLOAD 1400                // 安全 MTU 净荷大小，杜绝网络层 IP 分片雪崩
#define MK_UDP_SLICE_MAGIC 0x55445053               // 'UDPS'

#pragma pack(push, 1)
typedef struct _MK_UDP_SLICE_HDR
{
    ULONG dwMagic;         // 'UDPS'
    ULONG dwSequence;      // 序列号
    USHORT SliceIndex;     // 分片索引 (0-based)
    USHORT TotalSlices;    // 总分片数
    ULONG cbOriginalTotal; // 原始总长度
    ULONG cbSliceData;     // 当前分片字节数
} MK_UDP_SLICE_HDR, *PMK_UDP_SLICE_HDR;
#pragma pack(pop)

// ACE对抗：伪装为 NDIS/tcpip UDP 数据分配 Tag，规避 BigPool 审计
#define MK_UDP_SERVER_POOL_TAG 'UdpA'
#define UDP_SERVER_HEADER_SIZE 12

typedef struct _MK_UDP_SERVER
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    volatile BOOLEAN fRunning;
    BOOLEAN fRegistered;
    BOOLEAN fCapturedNpi;
    BOOLEAN fOwnRegistration;
    USHORT Port;
    PWSK_SOCKET pSocket;
    WSK_REGISTRATION Registration;
    WSK_PROVIDER_NPI ProviderNpi;
    HANDLE hWorkerThread;
    PETHREAD pWorkerThread;
    PUCHAR pRecvBuf;
    PUCHAR pSendBuf;
    PMDL pRecvMdl;
    PMDL pSendMdl;
    volatile LONG ActivePackets;

    // 优化：常驻 IRP 与事件，杜绝热路径高频分配与销毁
    PIRP pRecvIrp;
    KEVENT RecvEvent;
    PIRP pSendIrp;
    KEVENT SendEvent;

    // ★★★ 统一传输层句柄直通缓存：消灭每秒数万次 ExAcquireFastMutex 锁争用 ★★★
    union
    {
        MK_TRANSPORT_CONTEXT TransportCtx;
        struct
        {
            HANDLE Cached_hLC;
            ULONG Cached_dwRpcClientID;
            ULONG Cached_SlotIndex;
        };
    };

    // ★★★ 常驻分片发送缓冲与预构建 MDL：消灭分片热路径 100% 动态池分配与动态 MDL ★★★
    PUCHAR pSliceBuf;
    PMDL pSliceMdl;
} MK_UDP_SERVER, *PMK_UDP_SERVER;

#ifdef __cplusplus
extern "C"
{
#endif
    extern MK_UDP_SERVER g_UdpServer;
    NTSTATUS UdpServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ USHORT Port);
    VOID UdpServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    VOID UdpServer_GetStatus(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PBOOLEAN pfRunning, _Out_ PUSHORT pPort,
                             _Out_ PLONG pActivePackets);

#ifdef __cplusplus
}
#endif
