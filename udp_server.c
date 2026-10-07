#include "udp_server.h"
#include "Common.h"
#include "rpc_dispatch.h"
#include "leechcore_kernel.h"
#include "wsk_server.h"
#include "stealth_reloc.h"

#define NNG_CRYPT_KEY 0x8899AABBCCDDEEFFULL

MK_UDP_SERVER g_UdpServer = {0};

static const WSK_CLIENT_DISPATCH g_WskClientDispatchUdpServer = {MAKE_WSK_VERSION(1, 0), 0, NULL};




static __forceinline VOID UdpNngFastCrypt(PUCHAR pbData, ULONG cbData, ULONG64 qwNonce)
{
    ULONG64 key = NNG_CRYPT_KEY ^ qwNonce;
    ULONG64 *pQ = (ULONG64 *)pbData;
    ULONG numQwords = cbData / 8;
    for (ULONG i = 0; i < numQwords; i++)
    {
        pQ[i] ^= key;
    }
    PUCHAR pB = (PUCHAR)&pQ[numQwords];
    ULONG rem = cbData % 8;
    for (ULONG i = 0; i < rem; i++)
    {
        pB[i] ^= (UCHAR)(key >> (i * 8));
    }
}




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
    PIRP Irp = UserVar->Func.IoAllocateIrp(1, FALSE);
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







static VOID UdpServer_WorkerThread(_In_ PVOID Context)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = (MACHENIKE_KERNEL_INTERFACE *)Context;
    if (!UserVar)
    {
        return;
    }

    DBG("UdpServer_WorkerThread: Started, listening on UDP port %u", g_UdpServer.Port);

    while (g_UdpServer.fRunning && g_UdpServer.pSocket)
    {
        UDP_SYNC_CONTEXT RecvSync;
        PIRP RecvIrp = UdpAllocateSyncIrp(UserVar, &RecvSync);
        if (!RecvIrp)
        {
            if (!g_UdpServer.fRunning)
            {
                break;
            }
            LARGE_INTEGER Timeout;
            Timeout.QuadPart = -10 * 1000 * 5;
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
            continue;
        }

        WSK_BUF RecvWskBuf;
        RecvWskBuf.Offset = 0;
        RecvWskBuf.Length = MK_UDP_SERVER_MAX_PACKET_SIZE;
        RecvWskBuf.Mdl = g_UdpServer.pRecvMdl;

        SOCKADDR_IN RemoteAddr = {0};
        ULONG ControlLength = 0;

        NTSTATUS status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)g_UdpServer.pSocket->Dispatch)->WskReceiveFrom(
            g_UdpServer.pSocket,
            &RecvWskBuf,
            0,
            (PSOCKADDR)&RemoteAddr,
            &ControlLength,
            NULL,
            NULL,
            RecvIrp);

        ULONG_PTR BytesReceived = 0;
        status = UdpWaitForIrp(UserVar, RecvIrp, &RecvSync, status, &BytesReceived);

        if (!g_UdpServer.fRunning)
        {
            break;
        }

        if (!NT_SUCCESS(status) || BytesReceived < (UDP_SERVER_HEADER_SIZE + sizeof(LEECHRPC_MSG_HDR)))
        {
            if (status != STATUS_SUCCESS)
            {
                LARGE_INTEGER Timeout;
                Timeout.QuadPart = -10 * 1000 * 1;
                UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
            }
            continue;
        }

        InterlockedIncrement(&g_UdpServer.ActivePackets);

        ULONG64 qwReqNonce = *(PULONG64)(g_UdpServer.pRecvBuf + 0);
        ULONG cbPayload = *(PULONG)(g_UdpServer.pRecvBuf + 8);

        if (cbPayload < sizeof(LEECHRPC_MSG_HDR) || (UDP_SERVER_HEADER_SIZE + cbPayload) != (ULONG)BytesReceived)
        {
            continue;
        }

        PUCHAR pbPayload = g_UdpServer.pRecvBuf + UDP_SERVER_HEADER_SIZE;

        UdpNngFastCrypt(pbPayload, cbPayload, qwReqNonce);

        PLEECHRPC_MSG_HDR pHdr = (PLEECHRPC_MSG_HDR)pbPayload;
        if (pHdr->dwMagic != LEECHRPC_MSGMAGIC)
        {
            continue;
        }

        PUCHAR pbDirectOut = g_UdpServer.pSendBuf + UDP_SERVER_HEADER_SIZE;
        ULONG cbDirectOutMax = MK_UDP_SERVER_MAX_PACKET_SIZE - UDP_SERVER_HEADER_SIZE;
        PUCHAR pbRsp = NULL;
        ULONG cbRsp = 0;

        status = MkRpc_DispatchCommandEx(NULL, pbPayload, pHdr->cbMsg, &pbRsp, &cbRsp, pbDirectOut, cbDirectOutMax);

        if (NT_SUCCESS(status) && pbRsp && cbRsp > 0)
        {
            ULONG64 qwRspNonce = __rdtsc();
            ULONG cbTotalSend = UDP_SERVER_HEADER_SIZE + cbRsp;

            if (pbRsp == pbDirectOut)
            {
                *(PULONG64)(g_UdpServer.pSendBuf + 0) = qwRspNonce;
                *(PULONG)(g_UdpServer.pSendBuf + 8) = cbRsp;
                UdpNngFastCrypt(g_UdpServer.pSendBuf + UDP_SERVER_HEADER_SIZE, cbRsp, qwRspNonce);
            }
            else
            {
                if (cbTotalSend <= MK_UDP_SERVER_MAX_PACKET_SIZE)
                {
                    *(PULONG64)(g_UdpServer.pSendBuf + 0) = qwRspNonce;
                    *(PULONG)(g_UdpServer.pSendBuf + 8) = cbRsp;
                    UserVar->Func.RtlCopyMemory(g_UdpServer.pSendBuf + UDP_SERVER_HEADER_SIZE, pbRsp, cbRsp);
                    UdpNngFastCrypt(g_UdpServer.pSendBuf + UDP_SERVER_HEADER_SIZE, cbRsp, qwRspNonce);
                }
                UserVar->Func.ExFreePoolWithTag(pbRsp, LC_POOL_TAG);
            }

            if (cbTotalSend <= MK_UDP_SERVER_MAX_PACKET_SIZE)
            {
                WSK_BUF SendWskBuf;
                SendWskBuf.Offset = 0;
                SendWskBuf.Length = cbTotalSend;
                SendWskBuf.Mdl = g_UdpServer.pSendMdl;

                UDP_SYNC_CONTEXT SendSync;
                PIRP SendIrp = UdpAllocateSyncIrp(UserVar, &SendSync);
                if (SendIrp)
                {
                    NTSTATUS sendStatus = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)g_UdpServer.pSocket->Dispatch)->WskSendTo(
                        g_UdpServer.pSocket,
                        &SendWskBuf,
                        0,
                        (PSOCKADDR)&RemoteAddr,
                        0,
                        NULL,
                        SendIrp);

                    sendStatus = UdpWaitForIrp(UserVar, SendIrp, &SendSync, sendStatus, NULL);
                    UNREFERENCED_PARAMETER(sendStatus);
                }
            }
        }
    }

    DBG("UdpServer_WorkerThread: Exited");
    UserVar->Func.PsTerminateSystemThread(STATUS_SUCCESS);
}





NTSTATUS UdpServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ USHORT Port)
{
    if (!UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_UdpServer.fRunning)
    {
        DBG("UdpServer_Init: UDP Server already running");
        return STATUS_ALREADY_COMMITTED;
    }

    UserVar->Func.RtlZeroMemory(&g_UdpServer, sizeof(MK_UDP_SERVER));
    g_UdpServer.UserVar = UserVar;
    g_UdpServer.Port = (Port == 0) ? MK_UDP_SERVER_DEFAULT_PORT : Port;


    if (g_WskServer.fCapturedNpi)
    {
        g_UdpServer.ProviderNpi = g_WskServer.ProviderNpi;
        g_UdpServer.fCapturedNpi = TRUE;
        g_UdpServer.fOwnRegistration = FALSE;
    }
    else
    {
        WSK_CLIENT_NPI ClientNpi;
        ClientNpi.ClientContext = NULL;
        ClientNpi.Dispatch = &g_WskClientDispatchUdpServer;

        NTSTATUS regStatus = WskRegister(&ClientNpi, &g_UdpServer.Registration);
        if (!NT_SUCCESS(regStatus))
        {
            DBG("UdpServer_Init: WskRegister failed, status=0x%08X", regStatus);
            return regStatus;
        }
        g_UdpServer.fRegistered = TRUE;

        regStatus = WskCaptureProviderNPI(&g_UdpServer.Registration, WSK_INFINITE_WAIT, &g_UdpServer.ProviderNpi);
        if (!NT_SUCCESS(regStatus))
        {
            WskDeregister(&g_UdpServer.Registration);
            g_UdpServer.fRegistered = FALSE;
            DBG("UdpServer_Init: WskCaptureProviderNPI failed, status=0x%08X", regStatus);
            return regStatus;
        }
        g_UdpServer.fCapturedNpi = TRUE;
        g_UdpServer.fOwnRegistration = TRUE;
    }


    UDP_SYNC_CONTEXT Sync;
    PIRP Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (!Irp)
    {
        UdpServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PWSK_SOCKET pSocket = NULL;
    NTSTATUS status = ((PWSK_PROVIDER_DISPATCH)g_UdpServer.ProviderNpi.Dispatch)->WskSocket(
        g_UdpServer.ProviderNpi.Client,
        AF_INET,
        SOCK_DGRAM,
        IPPROTO_UDP,
        WSK_FLAG_DATAGRAM_SOCKET,
        NULL, NULL, NULL, NULL, NULL,
        Irp);

    ULONG_PTR Information = 0;
    status = UdpWaitForIrp(UserVar, Irp, &Sync, status, &Information);
    if (!NT_SUCCESS(status))
    {
        DBG("UdpServer_Init: WskSocket failed, status=0x%08X", status);
        UdpServer_Stop(UserVar);
        return status;
    }
    pSocket = (PWSK_SOCKET)Information;
    g_UdpServer.pSocket = pSocket;


    SOCKADDR_IN LocalAddr = {0};
    LocalAddr.sin_family = AF_INET;
    LocalAddr.sin_addr.s_addr = INADDR_ANY;
    LocalAddr.sin_port = RtlUshortByteSwap(g_UdpServer.Port);

    Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (!Irp)
    {
        UdpServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)pSocket->Dispatch)->WskBind(
        pSocket,
        (PSOCKADDR)&LocalAddr,
        0,
        Irp);
    status = UdpWaitForIrp(UserVar, Irp, &Sync, status, NULL);
    if (!NT_SUCCESS(status))
    {
        DBG("UdpServer_Init: WskBind to UDP port %u failed, status=0x%08X", g_UdpServer.Port, status);
        UdpServer_Stop(UserVar);
        return status;
    }


    ULONG BufferSize = 4 * 1024 * 1024;
    Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (Irp)
    {
        NTSTATUS optStatus = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)pSocket->Dispatch)->WskControlSocket(
            pSocket,
            WskSetOption,
            SO_RCVBUF,
            SOL_SOCKET,
            sizeof(BufferSize),
            &BufferSize,
            0,
            NULL,
            NULL,
            Irp);
        UdpWaitForIrp(UserVar, Irp, &Sync, optStatus, NULL);
    }
    Irp = UdpAllocateSyncIrp(UserVar, &Sync);
    if (Irp)
    {
        NTSTATUS optStatus = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)pSocket->Dispatch)->WskControlSocket(
            pSocket,
            WskSetOption,
            SO_SNDBUF,
            SOL_SOCKET,
            sizeof(BufferSize),
            &BufferSize,
            0,
            NULL,
            NULL,
            Irp);
        UdpWaitForIrp(UserVar, Irp, &Sync, optStatus, NULL);
    }

    g_UdpServer.pRecvBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, MK_UDP_SERVER_MAX_PACKET_SIZE, MK_UDP_SERVER_POOL_TAG);
    g_UdpServer.pSendBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, MK_UDP_SERVER_MAX_PACKET_SIZE, MK_UDP_SERVER_POOL_TAG);

    if (!g_UdpServer.pRecvBuf || !g_UdpServer.pSendBuf)
    {
        DBG("UdpServer_Init: Failed to allocate packet buffers");
        UdpServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_UdpServer.pRecvMdl = UserVar->Func.IoAllocateMdl(g_UdpServer.pRecvBuf, MK_UDP_SERVER_MAX_PACKET_SIZE, FALSE, FALSE, NULL);
    g_UdpServer.pSendMdl = UserVar->Func.IoAllocateMdl(g_UdpServer.pSendBuf, MK_UDP_SERVER_MAX_PACKET_SIZE, FALSE, FALSE, NULL);

    if (!g_UdpServer.pRecvMdl || !g_UdpServer.pSendMdl)
    {
        DBG("UdpServer_Init: Failed to allocate MDLs");
        UdpServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(g_UdpServer.pRecvMdl);
    MmBuildMdlForNonPagedPool(g_UdpServer.pSendMdl);



    g_UdpServer.fRunning = TRUE;
    status = UserVar->Func.PsCreateSystemThread(
        &g_UdpServer.hWorkerThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        UdpServer_WorkerThread,
        (PVOID)UserVar);

    if (!NT_SUCCESS(status))
    {
        DBG("UdpServer_Init: Failed to create worker thread, status=0x%08X", status);
        UdpServer_Stop(UserVar);
        return status;
    }

    UserVar->Func.ObReferenceObjectByHandle(
        g_UdpServer.hWorkerThread,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID *)&g_UdpServer.pWorkerThread,
        NULL);

    DBG("UdpServer_Init: UDP Server successfully started on port %u", g_UdpServer.Port);
    return STATUS_SUCCESS;
}

VOID UdpServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        return;
    }

    g_UdpServer.fRunning = FALSE;

    if (g_UdpServer.pSocket)
    {
        UDP_SYNC_CONTEXT Sync;
        PIRP Irp = UdpAllocateSyncIrp(UserVar, &Sync);
        if (Irp)
        {
            ((PWSK_PROVIDER_BASIC_DISPATCH)g_UdpServer.pSocket->Dispatch)->WskCloseSocket(g_UdpServer.pSocket, Irp);
            UdpWaitForIrp(UserVar, Irp, &Sync, STATUS_PENDING, NULL);
        }
        g_UdpServer.pSocket = NULL;
    }

    if (g_UdpServer.pWorkerThread)
    {
        UserVar->Func.KeWaitForSingleObject(g_UdpServer.pWorkerThread, Executive, KernelMode, FALSE, NULL);
        UserVar->Func.ObDereferenceObject(g_UdpServer.pWorkerThread);
        g_UdpServer.pWorkerThread = NULL;
    }
    if (g_UdpServer.hWorkerThread)
    {
        UserVar->Func.ZwClose(g_UdpServer.hWorkerThread);
        g_UdpServer.hWorkerThread = NULL;
    }




    if (g_UdpServer.pRecvMdl)
    {
        UserVar->Func.IoFreeMdl(g_UdpServer.pRecvMdl);
        g_UdpServer.pRecvMdl = NULL;
    }
    if (g_UdpServer.pSendMdl)
    {
        UserVar->Func.IoFreeMdl(g_UdpServer.pSendMdl);
        g_UdpServer.pSendMdl = NULL;
    }
    if (g_UdpServer.pRecvBuf)
    {
        UserVar->Func.ExFreePoolWithTag(g_UdpServer.pRecvBuf, MK_UDP_SERVER_POOL_TAG);
        g_UdpServer.pRecvBuf = NULL;
    }
    if (g_UdpServer.pSendBuf)
    {
        UserVar->Func.ExFreePoolWithTag(g_UdpServer.pSendBuf, MK_UDP_SERVER_POOL_TAG);
        g_UdpServer.pSendBuf = NULL;
    }


    if (g_UdpServer.fOwnRegistration)
    {
        if (g_UdpServer.fCapturedNpi)
        {
            WskReleaseProviderNPI(&g_UdpServer.Registration);
            g_UdpServer.fCapturedNpi = FALSE;
        }
        if (g_UdpServer.fRegistered)
        {
            WskDeregister(&g_UdpServer.Registration);
            g_UdpServer.fRegistered = FALSE;
        }
        g_UdpServer.fOwnRegistration = FALSE;
    }

    DBG("UdpServer_Stop: UDP Server stopped successfully");
}

VOID UdpServer_GetStatus(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PBOOLEAN pfRunning, _Out_ PUSHORT pPort, _Out_ PLONG pActivePackets)
{
    UNREFERENCED_PARAMETER(UserVar);
    if (pfRunning)
    {
        *pfRunning = g_UdpServer.fRunning;
    }
    if (pPort)
    {
        *pPort = g_UdpServer.Port;
    }
    if (pActivePackets)
    {
        *pActivePackets = g_UdpServer.ActivePackets;
    }
}
