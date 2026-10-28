#pragma once

#include "Common.h"
#include "RpcDispatcher.h"
#include "usb_hub.h"

struct _MK_SERVER_START_PARAMS;
typedef struct _MK_SERVER_START_PARAMS *PMK_SERVER_START_PARAMS;

// ACE对抗：伪装为 I/O Manager 通用 Tag，规避 BigPool 枚举审计
#define MK_USB_POOL_TAG 'mNoI'
#define USB_SERVER_DEFAULT_EP_IN 0x84
#define USB_SERVER_DEFAULT_EP_OUT 0x02
#define USB_SERVER_MAX_MSG_SIZE (64 * 1024 * 1024)
#define USB_SERVER_SLOT_SIZE 0x110000 // 1MB + 64KB 双缓冲单槽大小，100% DirectOut 容纳 256 页 (1MB) 满载散列读及描述符头
#define USB_SERVER_FAST_BUF_SIZE (2 * USB_SERVER_SLOT_SIZE)
#define USB_SERVER_HEADER_SIZE 12
#define USBHUB3_STRICT_MODE 1

typedef struct _MK_USB_SERVER
{
    volatile BOOLEAN fRunning;
    HANDLE hDevice;
    PFILE_OBJECT pFileObj;
    HANDLE hWorkerThread;
    PVOID pWorkerThread;
    KEVENT StopEvent;
    UCHAR PipeIn;
    UCHAR PipeOut;
    LONG ActiveConnections;
    ULONG64 TotalRequestsHandled;
    WCHAR DevicePath[260];

    PUCHAR pFastRecvBuf;
    PUCHAR pFastSendBuf;

    // ★★★ 全双工重叠 I/O 常驻 MDL 与双缓冲槽位（0 动态池分配、0 动态 MDL、0 BigPool 暴露）★★★
    PMDL pFastRecvPagesMdl;
    PMDL pSendPagesMdlSlot[2];
    PMDL pFastRecvMdl;
    PUCHAR pSendBufSlot[2];
    PMDL pSendMdlSlot[2];

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

    BOOLEAN fHubMode;
} MK_USB_SERVER, *PMK_USB_SERVER;

#ifdef __cplusplus
extern "C"
{
#endif

    extern MK_USB_SERVER g_UsbServer;

    NTSTATUS UsbServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_opt_ PMK_SERVER_START_PARAMS pParams);
    VOID UsbServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    VOID UsbServer_GetStatus(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PULONG pActiveConnections, _Out_ PBOOLEAN pfRunning);
    const char *Transport_GetLastErrorDesc(VOID);
    VOID Transport_SetLastErrorDesc(const char *desc);
    VOID Transport_SetLastErrorFormat(const char *fmt, ...);

#ifdef __cplusplus
}
#endif
