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

typedef struct _MK_ETH_SERVER
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    volatile BOOLEAN fRunning;
    volatile BOOLEAN fProcessing;
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
    ULONG dwLastRecvSequence;

    PUCHAR pDirectOutBuf;
    KSPIN_LOCK RecvLock;

    volatile LONG ActiveConnections;
} MK_ETH_SERVER, *PMK_ETH_SERVER;

extern MK_ETH_SERVER g_EthServer;

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS EthServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ USHORT EtherType, _In_opt_ PCWSTR TargetAdapterName);
VOID EthServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
VOID EthServer_GetStatus(_Out_ PBOOLEAN pfRunning, _Out_ PULONG pActiveConnections);
PMK_TRANSPORT_CONTEXT EthServer_GetTransportContext(VOID);

#ifdef __cplusplus
}
#endif
