#pragma once

#include "FrameWork.h"
#include <wsk.h>
#include "Common.h"

#define MK_UDP_DISCOVERY_PORT_DEFAULT 10002
#define MK_UDP_MAGIC_REQ "MCH_DISCOVER_REQ"
#define MK_UDP_MAGIC_ACK "MCH_DISCOVER_ACK"

#pragma pack(push, 1)


typedef struct _MK_UDP_DISCOVERY_PACKET
{
    CHAR Magic[32];
    ULONG Version;
    ULONG ClientId;
    ULONG TcpPort;
    ULONG Reserved;
} MK_UDP_DISCOVERY_PACKET, *PMK_UDP_DISCOVERY_PACKET;


typedef struct _MK_DISCOVERY_PARAMS
{
    ULONG TimeoutMs;
    USHORT ListenPort;
    USHORT ServerTcpPort;
} MK_DISCOVERY_PARAMS, *PMK_DISCOVERY_PARAMS;


typedef struct _MK_DISCOVERY_RESULT
{
    ULONG ClientIp;
    USHORT ClientPort;
    USHORT ServerTcpPort;
    CHAR ClientIpStr[16];
    BOOLEAN fFound;
} MK_DISCOVERY_RESULT, *PMK_DISCOVERY_RESULT;

#pragma pack(pop)

#ifdef __cplusplus
extern "C"
{
#endif


    NTSTATUS UdpDiscovery_DiscoverClient(
        _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
        _In_opt_ PMK_DISCOVERY_PARAMS pParams,
        _Out_ PMK_DISCOVERY_RESULT pResult);


    ULONG UdpDiscovery_GetDiscoveredIp(VOID);


    VOID UdpDiscovery_FormatIp(ULONG IpNetOrder, _Out_writes_(16) PCHAR szIpOut);

#ifdef __cplusplus
}
#endif
