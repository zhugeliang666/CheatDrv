#pragma once

#include "Common.h"
#include "FrameWork.h"
#include "RpcDispatcher.h"

#ifndef NDIS_WDM
#define NDIS_WDM 1
#endif

#ifndef NDIS630
#define NDIS630 1
#endif

#include <ndis.h>

#define MK_ETH_SERVER_DEFAULT_ETHERTYPE 0x8844
#define MK_ETH_SERVER_MAX_PACKET_SIZE   (1024 * 1024)
#define MK_ETH_SAFE_MTU_PAYLOAD         1400
#define MK_ETH_SLICE_MAGIC              0x53485445    // 'ETHS'
#define MK_ETH_POOL_TAG                 'MthE'
#define MK_ETH_TX_POOL_COUNT            512
#define MK_ETH_FRAME_BUF_STRIDE         2048
#define MK_ETH_SEND_BATCH_SIZE          16

#define MK_ETH_FLAG_REQUEST             0x0001
#define MK_ETH_FLAG_RESPONSE            0x0002

#pragma pack(push, 1)
typedef struct _MK_ETH_FRAME_HDR
{
    UCHAR DstMac[6];
    UCHAR SrcMac[6];
    USHORT EtherType;
} MK_ETH_FRAME_HDR, *PMK_ETH_FRAME_HDR;

typedef struct _MK_ETH_PACKET_HDR
{
    ULONG dwMagic;          // 'ETHS'
    ULONG dwSequence;
    USHORT SliceIndex;
    USHORT TotalSlices;
    ULONG cbOriginalTotal;
    ULONG cbSliceData;
    UCHAR ClientMac[6];
    USHORT Reserved;        // MK_ETH_FLAG_REQUEST (1) / MK_ETH_FLAG_RESPONSE (2)
} MK_ETH_PACKET_HDR, *PMK_ETH_PACKET_HDR;
#pragma pack(pop)

#define MK_ETH_MAX_SLICE_PAYLOAD (MK_ETH_SAFE_MTU_PAYLOAD - sizeof(MK_ETH_PACKET_HDR))
#define MK_ETH_MAX_SLICES        2048

typedef struct _MK_ETH_ADAPTER_BINDING
{
    LIST_ENTRY Link;
    NDIS_HANDLE BindingHandle;
    UCHAR LocalMac[6];
    BOOLEAN fActive;
    KEVENT OpenCompleteEvent;
    NDIS_STATUS OpenStatus;
    KEVENT CloseCompleteEvent;
    KEVENT OidCompleteEvent;
    NDIS_STATUS OidStatus;
} MK_ETH_ADAPTER_BINDING, *PMK_ETH_ADAPTER_BINDING;

typedef struct _MK_ETH_TX_SLOT
{
    volatile LONG fInUse;
    PUCHAR pFrameBuf;
    PMDL pMdl;
} MK_ETH_TX_SLOT, *PMK_ETH_TX_SLOT;

typedef struct _MK_ETH_SERVER
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    volatile BOOLEAN fRunning;
    volatile BOOLEAN fProcessing;
    volatile BOOLEAN fWorkerSpinning;
    NDIS_HANDLE ProtocolHandle;
    NDIS_HANDLE NblPoolHandle;
    LIST_ENTRY AdapterList;
    KSPIN_LOCK AdapterLock;

    USHORT EtherType;
    UCHAR TargetClientMac[6];
    BOOLEAN fTargetMacLearned;
    PMK_ETH_ADAPTER_BINDING pTargetAdapter;

    KEVENT WorkerExitEvent;
    KEVENT WorkerWakeEvent;
    PVOID pWorkerThread;

    PUCHAR pRecvAssembleBuf;
    ULONG cbRecvExpectedTotal;
    ULONG cbRecvCurrent;
    ULONG cbRecvSliceStride;
    ULONG dwLastRecvSequence;
    ULONG cRecvSlicesReceived;
    USHORT cRecvSlicesExpected;
    ULONG64 RecvSliceBitmap[MK_ETH_MAX_SLICES / 64];

    PUCHAR pDirectOutBuf;
    KSPIN_LOCK RecvLock;

    ULONG TxSlotCursor;
    PUCHAR pTxFrameMemory;
    MK_ETH_TX_SLOT TxSlots[MK_ETH_TX_POOL_COUNT];

    volatile LONG ActiveConnections;
} MK_ETH_SERVER, *PMK_ETH_SERVER;

extern MK_ETH_SERVER g_EthServer;

/* 通道健康度快照：致命失败后仍可读（信息存放在模块级静态区，不随 EthServer_Stop 清空） */
typedef struct _MK_ETH_CHANNEL_INFO
{
    BOOLEAN fReady;
    BOOLEAN fArmed;
    BOOLEAN fFatal;
    UCHAR Reserved;
    ULONG FailReason;
    ULONG FailStatus;
    ULONG FilterCount;
    ULONG IfIndex;
    LONG TxDirect;
    LONG TxFailed;
    LONG RxStolen;
} MK_ETH_CHANNEL_INFO, *PMK_ETH_CHANNEL_INFO;

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS EthServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ USHORT EtherType, _In_opt_ PCWSTR TargetAdapterName);
VOID EthServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
VOID EthServer_GetStatus(_Out_ PBOOLEAN pfRunning, _Out_ PULONG pActiveConnections);
PMK_TRANSPORT_CONTEXT EthServer_GetTransportContext(VOID);
NTSTATUS EthServer_GetChannelInfo(_Out_ PMK_ETH_CHANNEL_INFO pInfo);

#ifdef __cplusplus
}
#endif
