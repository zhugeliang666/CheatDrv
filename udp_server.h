#pragma once

#include "FrameWork.h"
#include <wsk.h>
#include "Common.h"

#define MK_UDP_SERVER_DEFAULT_PORT 10003
#define MK_UDP_SERVER_MAX_PACKET_SIZE 65536
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
} MK_UDP_SERVER, *PMK_UDP_SERVER;

extern MK_UDP_SERVER g_UdpServer;

#ifdef __cplusplus
extern "C" {
#endif


NTSTATUS UdpServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ USHORT Port);


VOID UdpServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);


VOID UdpServer_GetStatus(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PBOOLEAN pfRunning, _Out_ PUSHORT pPort, _Out_ PLONG pActivePackets);

#ifdef __cplusplus
}
#endif
