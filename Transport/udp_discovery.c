#include "udp_discovery.h"
#include "wsk_server.h"
#include <stdio.h>

// ACE对抗：伪装为 NDIS 缓冲区分配 Tag，规避 BigPool 审计
#define MK_DISCOVERY_POOL_TAG 'uBdN'


static volatile ULONG g_DiscoveredClientIp = 0;

static const WSK_CLIENT_DISPATCH g_WskClientDispatchUdp = {MAKE_WSK_VERSION(1, 0), 0, NULL};

typedef struct _UDP_SYNC_CONTEXT
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    KEVENT Event;
} UDP_SYNC_CONTEXT, *PUDP_SYNC_CONTEXT;

static NTSTATUS UdpSyncCompletionRoutine(_In_ PDEVICE_OBJECT Reserved, _In_ PIRP Irp, _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    PUDP_SYNC_CONTEXT pSync = (PUDP_SYNC_CONTEXT)Context;
    if (pSync && pSync->UserVar)
    {
        pSync->UserVar->Func.KeSetEvent(&pSync->Event, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static PIRP UdpAllocateSyncIrp(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PUDP_SYNC_CONTEXT pSync)
{
    if (!UserVar || !pSync)
    {
        return NULL;
    }
    pSync->UserVar = UserVar;
    UserVar->Func.KeInitializeEvent(&pSync->Event, SynchronizationEvent, FALSE);
    PIRP Irp = UserVar->Func.IoAllocateIrp(4, FALSE);
    if (!Irp)
    {
        return NULL;
    }
    IoSetCompletionRoutine(Irp, UdpSyncCompletionRoutine, pSync, TRUE, TRUE, TRUE);
    return Irp;
}

static NTSTATUS UdpWaitForIrp(
    _In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PIRP Irp,
    _Inout_ PUDP_SYNC_CONTEXT pSync,
    _In_ NTSTATUS Status,
    _Out_opt_ PULONG_PTR pInformation)
{
    if (Status == STATUS_PENDING && UserVar && pSync)
    {
        UserVar->Func.KeWaitForSingleObject(&pSync->Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }
    if (pInformation)
    {
        *pInformation = NT_SUCCESS(Status) ? Irp->IoStatus.Information : 0;
    }
    if (UserVar && Irp)
    {
        UserVar->Func.IoFreeIrp(Irp);
    }
    return Status;
}

VOID UdpDiscovery_FormatIp(ULONG IpNetOrder, _Out_writes_(16) PCHAR szIpOut)
{
    if (!szIpOut) {
        return;
    }
    PUCHAR p = (PUCHAR)&IpNetOrder;
    PCHAR dst = szIpOut;
    for (int i = 0; i < 4; i++) {
        UCHAR val = p[i];
        if (val >= 100) {
            *dst++ = '0' + (val / 100);
            val %= 100;
            *dst++ = '0' + (val / 10);
            val %= 10;
        } else if (val >= 10) {
            *dst++ = '0' + (val / 10);
            val %= 10;
        }
        *dst++ = '0' + val;
        if (i < 3) {
            *dst++ = '.';
        }
    }
    *dst = '\0';
}

ULONG UdpDiscovery_GetDiscoveredIp(VOID)
{
    return g_DiscoveredClientIp;
}

static __forceinline BOOLEAN UdpDiscovery_IsMagicEqual(const char *s1, const char *s2, SIZE_T len)
{
    for (SIZE_T i = 0; i < len; i++) {
        if (s1[i] != s2[i]) {
            return FALSE;
        }
        if (s1[i] == '\0') {
            break;
        }
    }
    return TRUE;
}


NTSTATUS UdpDiscovery_DiscoverClient(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_opt_ PMK_DISCOVERY_PARAMS pParams,
    _Out_ PMK_DISCOVERY_RESULT pResult)
{
    if (!UserVar || !pResult)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG TimeoutMs = (pParams && pParams->TimeoutMs > 0) ? pParams->TimeoutMs : 5000;
    USHORT ListenPort = (pParams && pParams->ListenPort > 0) ? pParams->ListenPort : MK_UDP_DISCOVERY_PORT_DEFAULT;
    USHORT ServerTcpPort = (pParams && pParams->ServerTcpPort > 0) ? pParams->ServerTcpPort : 10001;

    UserVar->Func.RtlZeroMemory(pResult, sizeof(MK_DISCOVERY_RESULT));

    DBG("UdpDiscovery: Starting auto-discovery on UDP port %u (Timeout=%u ms)...", ListenPort, TimeoutMs);


    BOOLEAN fLocalRegistration = FALSE;
    WSK_REGISTRATION LocalRegistration = {0};
    WSK_PROVIDER_NPI LocalProviderNpi = {0};
    PWSK_PROVIDER_NPI pProviderNpi = NULL;

    if (g_WskServer.fCapturedNpi)
    {
        pProviderNpi = &g_WskServer.ProviderNpi;
    }
    else
    {
        WSK_CLIENT_NPI ClientNpi;
        ClientNpi.ClientContext = NULL;
        ClientNpi.Dispatch = &g_WskClientDispatchUdp;

        if (!UserVar || !UserVar->Func.WskRegister)
        {
            DBG("UdpDiscovery: WskRegister function pointer is NULL");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        NTSTATUS regStatus = UserVar->Func.WskRegister(&ClientNpi, &LocalRegistration);
        if (!NT_SUCCESS(regStatus))
        {
            DBG("UdpDiscovery: WskRegister failed, status=0x%08X", regStatus);
            return regStatus;
        }

        if (!UserVar->Func.WskCaptureProviderNPI)
        {
            DBG("UdpDiscovery: WskCaptureProviderNPI function pointer is NULL");
            if (UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        regStatus = UserVar->Func.WskCaptureProviderNPI(&LocalRegistration, WSK_INFINITE_WAIT, &LocalProviderNpi);
        if (!NT_SUCCESS(regStatus))
        {
            if (UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
            DBG("UdpDiscovery: WskCaptureProviderNPI failed, status=0x%08X", regStatus);
            return regStatus;
        }

        pProviderNpi = &LocalProviderNpi;
        fLocalRegistration = TRUE;
    }


    UDP_SYNC_CONTEXT Sync;
    PIRP Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (!Irp)
    {
        if (fLocalRegistration)
        {
            if (UserVar && UserVar->Func.WskReleaseProviderNPI)
            {
                UserVar->Func.WskReleaseProviderNPI(&LocalRegistration);
            }
            if (UserVar && UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PWSK_SOCKET pSocket = NULL;
    NTSTATUS Status = ((PWSK_PROVIDER_DISPATCH)pProviderNpi->Dispatch)->WskSocket(
        pProviderNpi->Client,
        AF_INET,
        SOCK_DGRAM,
        IPPROTO_UDP,
        WSK_FLAG_DATAGRAM_SOCKET,
        NULL, NULL, NULL, NULL, NULL,
        Irp);

    ULONG_PTR Information = 0;
    Status = UdpWaitForIrp(UserVar, Irp, &Sync, Status, &Information);
    if (!NT_SUCCESS(Status))
    {
        DBG("UdpDiscovery: WskSocket failed, status=0x%08X", Status);
        if (fLocalRegistration)
        {
            if (UserVar && UserVar->Func.WskReleaseProviderNPI)
            {
                UserVar->Func.WskReleaseProviderNPI(&LocalRegistration);
            }
            if (UserVar && UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
        }
        return Status;
    }
    pSocket = (PWSK_SOCKET)Information;


    ULONG EnableBroadcast = 1;
    Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (Irp)
    {
        Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)pSocket->Dispatch)->WskControlSocket(
            pSocket,
            WskSetOption,
            SO_BROADCAST,
            SOL_SOCKET,
            sizeof(ULONG),
            &EnableBroadcast,
            0, NULL, NULL,
            Irp);
        UdpWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
    }


    SOCKADDR_IN LocalAddr = {0};
    LocalAddr.sin_family = AF_INET;
    LocalAddr.sin_addr.s_addr = INADDR_ANY;
    LocalAddr.sin_port = RtlUshortByteSwap(ListenPort);

    Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (!Irp)
    {

        Irp = UdpAllocateSyncIrp(UserVar, &Sync);
        if (Irp)
        {
            ((PWSK_PROVIDER_BASIC_DISPATCH)pSocket->Dispatch)->WskCloseSocket(pSocket, Irp);
            UdpWaitForIrp(UserVar, Irp, &Sync, STATUS_PENDING, NULL);
        }
        if (fLocalRegistration)
        {
            if (UserVar && UserVar->Func.WskReleaseProviderNPI)
            {
                UserVar->Func.WskReleaseProviderNPI(&LocalRegistration);
            }
            if (UserVar && UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)pSocket->Dispatch)->WskBind(
        pSocket,
        (PSOCKADDR)&LocalAddr,
        0,
        Irp);
    Status = UdpWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
    if (!NT_SUCCESS(Status))
    {
        DBG("UdpDiscovery: WskBind to UDP port %u failed, status=0x%08X", ListenPort, Status);
        Irp = UdpAllocateSyncIrp(UserVar, &Sync);
        if (Irp)
        {
            ((PWSK_PROVIDER_BASIC_DISPATCH)pSocket->Dispatch)->WskCloseSocket(pSocket, Irp);
            UdpWaitForIrp(UserVar, Irp, &Sync, STATUS_PENDING, NULL);
        }
        if (fLocalRegistration)
        {
            if (UserVar && UserVar->Func.WskReleaseProviderNPI)
            {
                UserVar->Func.WskReleaseProviderNPI(&LocalRegistration);
            }
            if (UserVar && UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
        }
        return Status;
    }


    typedef struct _UDP_DISCOVERY_WORK_CONTEXT
    {
        UCHAR RecvBuf[512];
        SOCKADDR_IN RemoteAddr;
        MK_UDP_DISCOVERY_PACKET AckPkt;
    } UDP_DISCOVERY_WORK_CONTEXT, *PUDP_DISCOVERY_WORK_CONTEXT;

    PUDP_DISCOVERY_WORK_CONTEXT pWorkCtx = (PUDP_DISCOVERY_WORK_CONTEXT)UserVar->Func.ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(UDP_DISCOVERY_WORK_CONTEXT), MK_DISCOVERY_POOL_TAG);
    if (!pWorkCtx)
    {
        Irp = UdpAllocateSyncIrp(UserVar, &Sync);
        if (Irp)
        {
            ((PWSK_PROVIDER_BASIC_DISPATCH)pSocket->Dispatch)->WskCloseSocket(pSocket, Irp);
            UdpWaitForIrp(UserVar, Irp, &Sync, STATUS_PENDING, NULL);
        }
        if (fLocalRegistration)
        {
            if (UserVar && UserVar->Func.WskReleaseProviderNPI)
            {
                UserVar->Func.WskReleaseProviderNPI(&LocalRegistration);
            }
            if (UserVar && UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    UserVar->Func.RtlZeroMemory(pWorkCtx, sizeof(UDP_DISCOVERY_WORK_CONTEXT));


    WSK_BUF WskBuf;
    WskBuf.Offset = 0;
    WskBuf.Length = sizeof(pWorkCtx->RecvBuf);
    WskBuf.Mdl = UserVar->Func.IoAllocateMdl(pWorkCtx->RecvBuf, sizeof(pWorkCtx->RecvBuf), FALSE, FALSE, NULL);
    if (!WskBuf.Mdl)
    {
        UserVar->Func.ExFreePoolWithTag(pWorkCtx, MK_DISCOVERY_POOL_TAG);
        Irp = UdpAllocateSyncIrp(UserVar, &Sync);
        if (Irp)
        {
            ((PWSK_PROVIDER_BASIC_DISPATCH)pSocket->Dispatch)->WskCloseSocket(pSocket, Irp);
            UdpWaitForIrp(UserVar, Irp, &Sync, STATUS_PENDING, NULL);
        }
        if (fLocalRegistration)
        {
            if (UserVar && UserVar->Func.WskReleaseProviderNPI)
            {
                UserVar->Func.WskReleaseProviderNPI(&LocalRegistration);
            }
            if (UserVar && UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    UserVar->Func.MmBuildMdlForNonPagedPool(WskBuf.Mdl);

    Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (!Irp)
    {
        UserVar->Func.IoFreeMdl(WskBuf.Mdl);
        UserVar->Func.ExFreePoolWithTag(pWorkCtx, MK_DISCOVERY_POOL_TAG);
        Irp = UdpAllocateSyncIrp(UserVar, &Sync);
        if (Irp)
        {
            ((PWSK_PROVIDER_BASIC_DISPATCH)pSocket->Dispatch)->WskCloseSocket(pSocket, Irp);
            UdpWaitForIrp(UserVar, Irp, &Sync, STATUS_PENDING, NULL);
        }
        if (fLocalRegistration)
        {
            if (UserVar && UserVar->Func.WskReleaseProviderNPI)
            {
                UserVar->Func.WskReleaseProviderNPI(&LocalRegistration);
            }
            if (UserVar && UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&LocalRegistration);
            }
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG ControlLength = 0;
    Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)pSocket->Dispatch)->WskReceiveFrom(
        pSocket,
        &WskBuf,
        0,
        (PSOCKADDR)&pWorkCtx->RemoteAddr,
        &ControlLength,
        NULL,
        NULL,
        Irp);

    if (Status == STATUS_PENDING)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10000LL * TimeoutMs;
        NTSTATUS waitStatus = UserVar->Func.KeWaitForSingleObject(&Sync.Event, Executive, KernelMode, FALSE, &Timeout);
        if (waitStatus == STATUS_TIMEOUT)
        {
            DBG("UdpDiscovery: Waiting for client UDP broadcast timed out (%u ms)", TimeoutMs);
            if (UserVar && UserVar->Func.IoCancelIrp)
            {
                UserVar->Func.IoCancelIrp(Irp);
            }
            UserVar->Func.KeWaitForSingleObject(&Sync.Event, Executive, KernelMode, FALSE, NULL);
            Status = STATUS_TIMEOUT;
        }
        else
        {
            Status = Irp->IoStatus.Status;
        }
    }

    ULONG BytesReceived = NT_SUCCESS(Status) ? (ULONG)Irp->IoStatus.Information : 0;
    UserVar->Func.IoFreeIrp(Irp);
    UserVar->Func.IoFreeMdl(WskBuf.Mdl);

    if (NT_SUCCESS(Status) && BytesReceived >= sizeof(MK_UDP_DISCOVERY_PACKET))
    {
        PMK_UDP_DISCOVERY_PACKET pReq = (PMK_UDP_DISCOVERY_PACKET)pWorkCtx->RecvBuf;
        if (UdpDiscovery_IsMagicEqual(pReq->Magic, MK_UDP_MAGIC_REQ, sizeof(pReq->Magic))) {
            ULONG DiscoveredIp = pWorkCtx->RemoteAddr.sin_addr.s_addr;
            USHORT DiscoveredPort = RtlUshortByteSwap(pWorkCtx->RemoteAddr.sin_port);


            g_DiscoveredClientIp = DiscoveredIp;

            pResult->ClientIp = DiscoveredIp;
            pResult->ClientPort = DiscoveredPort;
            pResult->ServerTcpPort = ServerTcpPort;
            pResult->fFound = TRUE;
            UdpDiscovery_FormatIp(DiscoveredIp, pResult->ClientIpStr);

            DBG("UdpDiscovery: [MATCHED] Discovered Client IP: %s:%u (ClientId=%u)",
                           pResult->ClientIpStr, DiscoveredPort, pReq->ClientId);


            UserVar->Func.RtlCopyMemory(pWorkCtx->AckPkt.Magic, MK_UDP_MAGIC_ACK, sizeof(MK_UDP_MAGIC_ACK));
            pWorkCtx->AckPkt.Version = 1;
            pWorkCtx->AckPkt.ClientId = pReq->ClientId;
            pWorkCtx->AckPkt.TcpPort = ServerTcpPort;

            WSK_BUF AckWskBuf;
            AckWskBuf.Offset = 0;
            AckWskBuf.Length = sizeof(pWorkCtx->AckPkt);
            AckWskBuf.Mdl = UserVar->Func.IoAllocateMdl(&pWorkCtx->AckPkt, sizeof(pWorkCtx->AckPkt), FALSE, FALSE, NULL);
            if (AckWskBuf.Mdl)
            {
                UserVar->Func.MmBuildMdlForNonPagedPool(AckWskBuf.Mdl);
                UDP_SYNC_CONTEXT AckSync;
                PIRP AckIrp = UdpAllocateSyncIrp(UserVar, &AckSync);
                if (AckIrp)
                {
                    NTSTATUS sendStatus = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)pSocket->Dispatch)->WskSendTo(
                        pSocket,
                        &AckWskBuf,
                        0,
                        (PSOCKADDR)&pWorkCtx->RemoteAddr,
                        0,
                        NULL,
                        AckIrp);
                    UdpWaitForIrp(UserVar, AckIrp, &AckSync, sendStatus, NULL);
                    DBG("UdpDiscovery: Sent MCH_DISCOVER_ACK to client %s:%u",
                                   pResult->ClientIpStr, DiscoveredPort);
                }
                UserVar->Func.IoFreeMdl(AckWskBuf.Mdl);
            }
        }
        else
        {
            DBG("UdpDiscovery: Received UDP packet but magic mismatch");
            Status = STATUS_NOT_FOUND;
        }
    }
    else
    {
        if (Status != STATUS_TIMEOUT)
        {
            DBG("UdpDiscovery: Receive failed, status=0x%08X, bytes=%u", Status, BytesReceived);
        }
    }

    UserVar->Func.ExFreePoolWithTag(pWorkCtx, MK_DISCOVERY_POOL_TAG);


    Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (Irp)
    {
        ((PWSK_PROVIDER_BASIC_DISPATCH)pSocket->Dispatch)->WskCloseSocket(pSocket, Irp);
        UdpWaitForIrp(UserVar, Irp, &Sync, STATUS_PENDING, NULL);
    }

    if (fLocalRegistration)
    {
        if (UserVar && UserVar->Func.WskReleaseProviderNPI)
        {
            UserVar->Func.WskReleaseProviderNPI(&LocalRegistration);
        }
        if (UserVar && UserVar->Func.WskDeregister)
        {
            UserVar->Func.WskDeregister(&LocalRegistration);
        }
    }

    return pResult->fFound ? STATUS_SUCCESS : (Status == STATUS_TIMEOUT ? STATUS_TIMEOUT : STATUS_NOT_FOUND);
}
