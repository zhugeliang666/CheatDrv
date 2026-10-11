#include "wsk_server.h"
#include "Common.h"
#include "rpc_dispatch.h"

MK_WSK_SERVER g_WskServer = {0};

static const WSK_CLIENT_DISPATCH g_WskClientDispatch = {MAKE_WSK_VERSION(1, 0), 0, NULL};





typedef struct _WSK_SYNC_CONTEXT
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    PKEVENT pEvent;
    KEVENT LocalEvent;
} WSK_SYNC_CONTEXT, *PWSK_SYNC_CONTEXT;

static NTSTATUS WskSyncCompletionRoutine(_In_ PDEVICE_OBJECT Reserved, _In_ PIRP Irp, _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    PWSK_SYNC_CONTEXT pSync = (PWSK_SYNC_CONTEXT)Context;
    if (pSync && pSync->UserVar && pSync->pEvent)
    {
        pSync->UserVar->Func.KeSetEvent(pSync->pEvent, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static PIRP WskAllocateSyncIrp(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _Out_ PWSK_SYNC_CONTEXT pSync)
{
    if (!UserVar || !pSync)
    {
        return NULL;
    }
    pSync->UserVar = UserVar;
    pSync->pEvent = &pSync->LocalEvent;
    UserVar->Func.KeInitializeEvent(&pSync->LocalEvent, SynchronizationEvent, FALSE);
    PIRP Irp = UserVar->Func.IoAllocateIrp(1, FALSE);
    if (!Irp)
    {
        return NULL;
    }
    IoSetCompletionRoutine(Irp, WskSyncCompletionRoutine, pSync, TRUE, TRUE, TRUE);
    return Irp;
}

static NTSTATUS WskWaitForIrp(
    _In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PIRP Irp,
    _Inout_ PWSK_SYNC_CONTEXT pSync,
    _In_ NTSTATUS Status,
    _Out_opt_ PULONG_PTR pInformation)
{
    if (Status == STATUS_PENDING && UserVar && pSync && pSync->pEvent)
    {
        UserVar->Func.KeWaitForSingleObject(pSync->pEvent, Executive, KernelMode, FALSE, NULL);
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

static PIRP WskPreparePersistentIrp(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PIRP Irp,
    _In_ PKEVENT pEvent,
    _Out_ PWSK_SYNC_CONTEXT pSync)
{
    if (!UserVar || !Irp || !pEvent || !pSync)
    {
        return NULL;
    }
    pSync->UserVar = UserVar;
    pSync->pEvent = pEvent;
    if (UserVar->Func.KeClearEvent)
    {
        UserVar->Func.KeClearEvent(pEvent);
    }
    else
    {
        UserVar->Func.KeInitializeEvent(pEvent, SynchronizationEvent, FALSE);
    }
    IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(Irp, WskSyncCompletionRoutine, pSync, TRUE, TRUE, TRUE);
    return Irp;
}

static NTSTATUS WskWaitForPersistentIrp(
    _In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PIRP Irp,
    _Inout_ PWSK_SYNC_CONTEXT pSync,
    _In_ NTSTATUS Status,
    _Out_opt_ PULONG_PTR pInformation)
{
    if (Status == STATUS_PENDING && UserVar && pSync && pSync->pEvent)
    {
        UserVar->Func.KeWaitForSingleObject(pSync->pEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }
    if (pInformation)
    {
        *pInformation = NT_SUCCESS(Status) ? Irp->IoStatus.Information : 0;
    }
    // 常驻 IRP 决不在此处释放，供下次热路径重用
    return Status;
}


static NTSTATUS WskSyncSocket(
    _In_ PMK_WSK_SERVER Server,
    _In_ ADDRESS_FAMILY AddressFamily,
    _In_ USHORT SocketType,
    _In_ ULONG Protocol,
    _In_ ULONG Flags,
    _Out_ PWSK_SOCKET *ppSocket)
{
    *ppSocket = NULL;
    if (!Server || !Server->UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = WskAllocateSyncIrp(Server->UserVar, &Sync);
    if (!Irp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS Status = ((PWSK_PROVIDER_DISPATCH)Server->ProviderNpi.Dispatch)
                          ->WskSocket(Server->ProviderNpi.Client, AddressFamily, SocketType, Protocol, Flags, NULL,
                                      NULL, NULL, NULL, NULL, Irp);

    ULONG_PTR Information = 0;
    Status = WskWaitForIrp(Server->UserVar, Irp, &Sync, Status, &Information);
    if (NT_SUCCESS(Status))
    {
        *ppSocket = (PWSK_SOCKET)Information;
        if (!*ppSocket)
        {
            Status = STATUS_UNSUCCESSFUL;
        }
    }
    return Status;
}


static NTSTATUS WskSyncCloseSocket(
    _In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PWSK_SOCKET Socket)
{
    if (!Socket)
    {
        return STATUS_SUCCESS;
    }
    if (!UserVar)
    {
        UserVar = g_WskServer.UserVar;
    }
    if (!UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = WskAllocateSyncIrp(UserVar, &Sync);
    if (!Irp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS Status = ((PWSK_PROVIDER_BASIC_DISPATCH)Socket->Dispatch)->WskCloseSocket(Socket, Irp);

    return WskWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
}


static NTSTATUS WskSyncSetTcpNoDelay(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PWSK_SOCKET Socket)
{
    if (!Socket || !Socket->Dispatch || !UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = WskAllocateSyncIrp(UserVar, &Sync);
    if (!Irp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG NoDelay = 1;
    NTSTATUS Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskControlSocket(
        Socket,
        WskSetOption,
        1,
        6,
        sizeof(ULONG),
        &NoDelay,
        0,
        NULL,
        NULL,
        Irp);

    return WskWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
}


static VOID WskSyncSetSocketBuffers(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PWSK_SOCKET Socket,
    _In_ ULONG BufferSize)
{
    if (!Socket || !Socket->Dispatch || !UserVar)
    {
        return;
    }

    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = WskAllocateSyncIrp(UserVar, &Sync);
    if (Irp)
    {
        NTSTATUS Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskControlSocket(
            Socket,
            WskSetOption,
            SO_RCVBUF,
            SOL_SOCKET,
            sizeof(BufferSize),
            &BufferSize,
            0,
            NULL,
            NULL,
            Irp);
        WskWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
    }

    Irp = WskAllocateSyncIrp(UserVar, &Sync);
    if (Irp)
    {
        NTSTATUS Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskControlSocket(
            Socket,
            WskSetOption,
            SO_SNDBUF,
            SOL_SOCKET,
            sizeof(BufferSize),
            &BufferSize,
            0,
            NULL,
            NULL,
            Irp);
        WskWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
    }
}


static NTSTATUS WskSyncBind(
    _In_ PMK_WSK_SERVER Server,
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR LocalAddress)
{
    if (!Socket || !Socket->Dispatch || !Server || !Server->UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = WskAllocateSyncIrp(Server->UserVar, &Sync);
    if (!Irp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS Status = ((PWSK_PROVIDER_LISTEN_DISPATCH)Socket->Dispatch)->WskBind(Socket, LocalAddress, 0, Irp);

    return WskWaitForIrp(Server->UserVar, Irp, &Sync, Status, NULL);
}


static NTSTATUS WskSyncAccept(
    _In_ PMK_WSK_SERVER Server,
    _In_ PWSK_SOCKET ListenSocket,
    _Out_ PWSK_SOCKET *ppAcceptSocket,
    _Out_opt_ PSOCKADDR LocalAddress,
    _Out_opt_ PSOCKADDR RemoteAddress)
{
    *ppAcceptSocket = NULL;
    if (!ListenSocket || !ListenSocket->Dispatch || !Server || !Server->UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = WskAllocateSyncIrp(Server->UserVar, &Sync);
    if (!Irp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS Status = ((PWSK_PROVIDER_LISTEN_DISPATCH)ListenSocket->Dispatch)
                          ->WskAccept(ListenSocket, 0, NULL, NULL, LocalAddress, RemoteAddress, Irp);

    ULONG_PTR Information = 0;
    Status = WskWaitForIrp(Server->UserVar, Irp, &Sync, Status, &Information);
    if (NT_SUCCESS(Status))
    {
        *ppAcceptSocket = (PWSK_SOCKET)Information;
        if (!*ppAcceptSocket)
        {
            Status = STATUS_UNSUCCESSFUL;
        }
    }
    return Status;
}


static NTSTATUS WskSyncReceive(
    _In_ PMK_WSK_CLIENT pClient,
    _In_ PWSK_SOCKET Socket,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG pBytesReceived)
{
    *pBytesReceived = 0;
    if (Length == 0)
    {
        return STATUS_SUCCESS;
    }
    if (!Socket || !Socket->Dispatch || !pClient || !pClient->Server || !pClient->Server->UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = pClient->Server->UserVar;

    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = NULL;
    BOOLEAN fPersistentIrp = FALSE;

    if (pClient->pRecvIrp)
    {
        Irp = WskPreparePersistentIrp(UserVar, pClient->pRecvIrp, &pClient->RecvEvent, &Sync);
        fPersistentIrp = TRUE;
    }
    else
    {
        Irp = WskAllocateSyncIrp(UserVar, &Sync);
    }

    if (!Irp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WSK_BUF WskBuf;
    BOOLEAN fCustomMdl = FALSE;
    if (pClient->pFastRecvMdl &&
        (PUCHAR)Buffer >= pClient->FastRecvBuf &&
        (PUCHAR)Buffer + Length <= pClient->FastRecvBuf + sizeof(pClient->FastRecvBuf))
    {
        WskBuf.Offset = (ULONG)((PUCHAR)Buffer - pClient->FastRecvBuf);
        WskBuf.Length = Length;
        WskBuf.Mdl = pClient->pFastRecvMdl;
    }
    else
    {
        WskBuf.Offset = 0;
        WskBuf.Length = Length;
        WskBuf.Mdl = UserVar->Func.IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
        if (!WskBuf.Mdl)
        {
            if (!fPersistentIrp)
            {
                UserVar->Func.IoFreeIrp(Irp);
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        UserVar->Func.MmBuildMdlForNonPagedPool(WskBuf.Mdl);
        fCustomMdl = TRUE;
    }

    NTSTATUS Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskReceive(Socket, &WskBuf, 0, Irp);

    ULONG_PTR Information = 0;
    if (fPersistentIrp)
    {
        Status = WskWaitForPersistentIrp(UserVar, Irp, &Sync, Status, &Information);
    }
    else
    {
        Status = WskWaitForIrp(UserVar, Irp, &Sync, Status, &Information);
    }

    if (NT_SUCCESS(Status))
    {
        *pBytesReceived = (ULONG)Information;
    }
    if (fCustomMdl)
    {
        UserVar->Func.IoFreeMdl(WskBuf.Mdl);
    }
    return Status;
}


static NTSTATUS WskSyncReceiveExact(
    _In_ PMK_WSK_CLIENT pClient,
    _In_ PWSK_SOCKET Socket,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length)
{
    ULONG BytesTotal = 0;
    PUCHAR pCur = (PUCHAR)Buffer;

    while (BytesTotal < Length)
    {
        ULONG BytesRecv = 0;
        ULONG BytesToRecv = Length - BytesTotal;
        NTSTATUS Status = WskSyncReceive(pClient, Socket, pCur + BytesTotal, BytesToRecv, &BytesRecv);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
        if (BytesRecv == 0)
        {

            return STATUS_CONNECTION_DISCONNECTED;
        }
        BytesTotal += BytesRecv;
    }
    return STATUS_SUCCESS;
}


static NTSTATUS WskSyncSendAll(
    _In_ PMK_WSK_CLIENT pClient,
    _In_ PWSK_SOCKET Socket,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length)
{
    if (!Socket || !Socket->Dispatch || !pClient || !pClient->Server || !pClient->Server->UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = pClient->Server->UserVar;
    ULONG BytesTotal = 0;
    PUCHAR pCur = (PUCHAR)Buffer;

    BOOLEAN fFastPath = FALSE;
    if (pClient->pFastSendMdl &&
        (PUCHAR)Buffer >= pClient->FastSendBuf &&
        (PUCHAR)Buffer + Length <= pClient->FastSendBuf + sizeof(pClient->FastSendBuf))
    {
        fFastPath = TRUE;
    }

    while (BytesTotal < Length)
    {
        ULONG BytesToSend = Length - BytesTotal;

        WSK_SYNC_CONTEXT Sync;
        PIRP Irp = NULL;
        BOOLEAN fPersistentIrp = FALSE;

        if (pClient->pSendIrp)
        {
            Irp = WskPreparePersistentIrp(UserVar, pClient->pSendIrp, &pClient->SendEvent, &Sync);
            fPersistentIrp = TRUE;
        }
        else
        {
            Irp = WskAllocateSyncIrp(UserVar, &Sync);
        }

        if (!Irp)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        WSK_BUF WskBuf;
        BOOLEAN fCustomMdl = FALSE;

        if (fFastPath)
        {
            WskBuf.Offset = (ULONG)((PUCHAR)Buffer + BytesTotal - pClient->FastSendBuf);
            WskBuf.Length = BytesToSend;
            WskBuf.Mdl = pClient->pFastSendMdl;
        }
        else
        {
            WskBuf.Offset = 0;
            WskBuf.Length = BytesToSend;
            WskBuf.Mdl = UserVar->Func.IoAllocateMdl(pCur + BytesTotal, BytesToSend, FALSE, FALSE, NULL);
            if (!WskBuf.Mdl)
            {
                if (!fPersistentIrp)
                {
                    UserVar->Func.IoFreeIrp(Irp);
                }
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            UserVar->Func.MmBuildMdlForNonPagedPool(WskBuf.Mdl);
            fCustomMdl = TRUE;
        }

        NTSTATUS Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskSend(Socket, &WskBuf, 0, Irp);

        ULONG_PTR Information = 0;
        if (fPersistentIrp)
        {
            Status = WskWaitForPersistentIrp(UserVar, Irp, &Sync, Status, &Information);
        }
        else
        {
            Status = WskWaitForIrp(UserVar, Irp, &Sync, Status, &Information);
        }

        ULONG SentThisTime = (ULONG)Information;
        if (fCustomMdl)
        {
            UserVar->Func.IoFreeMdl(WskBuf.Mdl);
        }

        if (!NT_SUCCESS(Status) || SentThisTime == 0)
        {
            return NT_SUCCESS(Status) ? STATUS_CONNECTION_DISCONNECTED : Status;
        }
        BytesTotal += SentThisTime;
    }
    return STATUS_SUCCESS;
}





#define NNG_CRYPT_KEY 0x8899AABBCCDDEEFFULL

static __forceinline ULONG64 WskSwapU64(ULONG64 Val)
{
    return (((Val & 0x00000000000000FFULL) << 56) |
            ((Val & 0x000000000000FF00ULL) << 40) |
            ((Val & 0x0000000000FF0000ULL) << 24) |
            ((Val & 0x00000000FF000000ULL) << 8)  |
            ((Val & 0x000000FF00000000ULL) >> 8)  |
            ((Val & 0x0000FF0000000000ULL) >> 24) |
            ((Val & 0x00FF000000000000ULL) >> 40) |
            ((Val & 0xFF00000000000000ULL) >> 56));
}

static VOID WskNngFastCrypt(_Inout_updates_bytes_(cbData) PUCHAR pbData, _In_ ULONG cbData, _In_ ULONG64 qwNonce)
{
    if (!pbData || !cbData)
    {
        return;
    }
    ULONG64 key = NNG_CRYPT_KEY ^ qwNonce;
    PULONG64 pQ = (PULONG64)pbData;
    ULONG cQ = cbData / 8;
    for (ULONG i = 0; i < cQ; i++)
    {
        pQ[i] ^= key;
    }
    PUCHAR pB = (PUCHAR)&pQ[cQ];
    ULONG cB = cbData % 8;
    for (ULONG i = 0; i < cB; i++)
    {
        pB[i] ^= (UCHAR)(key >> (i * 8));
    }
}





static VOID WskClientWorkerThread(_In_ PVOID Context)
{
    PMK_WSK_CLIENT pClient = (PMK_WSK_CLIENT)Context;
    if (!pClient || !pClient->Server || !pClient->Server->UserVar)
    {
        return;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = pClient->Server->UserVar;
    PUCHAR pbReq = NULL;
    PUCHAR pbRsp = NULL;
    ULONG cbRsp = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN fIsNng = FALSE;

    DBG("WskClientWorkerThread: Started for ClientId=%u", pClient->ClientId);


    pClient->pFastRecvMdl = UserVar->Func.IoAllocateMdl(pClient->FastRecvBuf, sizeof(pClient->FastRecvBuf), FALSE, FALSE, NULL);
    if (pClient->pFastRecvMdl)
    {
        UserVar->Func.MmBuildMdlForNonPagedPool(pClient->pFastRecvMdl);
    }

    pClient->pFastSendMdl = UserVar->Func.IoAllocateMdl(pClient->FastSendBuf, sizeof(pClient->FastSendBuf), FALSE, FALSE, NULL);
    if (pClient->pFastSendMdl)
    {
        UserVar->Func.MmBuildMdlForNonPagedPool(pClient->pFastSendMdl);
    }

    // 优化：常驻同步 IRP 与事件，消灭热路径动态 IoAllocateIrp / IoFreeIrp 开销
    if (UserVar->Func.IoAllocateIrp)
    {
        pClient->pRecvIrp = UserVar->Func.IoAllocateIrp(1, FALSE);
        UserVar->Func.KeInitializeEvent(&pClient->RecvEvent, SynchronizationEvent, FALSE);
        pClient->pSendIrp = UserVar->Func.IoAllocateIrp(1, FALSE);
        UserVar->Func.KeInitializeEvent(&pClient->SendEvent, SynchronizationEvent, FALSE);
    }

    WskSyncSetTcpNoDelay(UserVar, pClient->Socket);

    WskSyncSetSocketBuffers(UserVar, pClient->Socket, 4 * 1024 * 1024);

    UCHAR InitBuf[8] = {0};
    Status = WskSyncReceiveExact(pClient, pClient->Socket, InitBuf, sizeof(InitBuf));
    if (!NT_SUCCESS(Status))
    {
        DBG("WskClientWorkerThread [ClientId=%u]: Initial handshake recv failed, status=0x%08X",
                       pClient->ClientId, Status);
        goto Cleanup;
    }

    if (InitBuf[0] == 0x00 && InitBuf[1] == 'S' && InitBuf[2] == 'P' && InitBuf[3] == 0x00)
    {
        fIsNng = TRUE;

        UCHAR RepHandshake[8] = {0x00, 'S', 'P', 0x00, 0x00, 0x31, 0x00, 0x00};
        Status = WskSyncSendAll(pClient, pClient->Socket, RepHandshake, sizeof(RepHandshake));
        if (!NT_SUCCESS(Status))
        {
            DBG("WskClientWorkerThread [ClientId=%u]: Send NNG REP handshake failed, status=0x%08X",
                           pClient->ClientId, Status);
            goto Cleanup;
        }
        DBG("WskClientWorkerThread [ClientId=%u]: NNG SP Handshake completed successfully!",
                       pClient->ClientId);
    }
    else
    {
        DBG("WskClientWorkerThread [ClientId=%u]: Non-NNG connection, falling back to raw TCP",
                       pClient->ClientId);
    }

    ULONG cbReadOffset = 0;
    ULONG cbWriteOffset = 0;
    ULONG cbBuffered = 0;

    while (g_WskServer.fRunning && pClient->fActive)
    {
        if (fIsNng)
        {
            while (cbBuffered < 12)
            {
                ULONG cbTailSpace = (ULONG)(sizeof(pClient->FastRecvBuf) - cbWriteOffset);
                if (cbTailSpace < 12)
                {
                    if (cbReadOffset > 0)
                    {
                        if (cbBuffered > 0)
                        {
                            UserVar->Func.memmove(pClient->FastRecvBuf, pClient->FastRecvBuf + cbReadOffset, cbBuffered);
                        }
                        cbReadOffset = 0;
                        cbWriteOffset = cbBuffered;
                    }
                }

                ULONG cbRecvThisTime = 0;
                Status = WskSyncReceive(pClient, pClient->Socket,
                                        pClient->FastRecvBuf + cbWriteOffset,
                                        (ULONG)(sizeof(pClient->FastRecvBuf) - cbWriteOffset),
                                        &cbRecvThisTime);
                if (!NT_SUCCESS(Status) || cbRecvThisTime == 0)
                {
                    goto Cleanup;
                }
                cbWriteOffset += cbRecvThisTime;
                cbBuffered = cbWriteOffset - cbReadOffset;
            }

            ULONG64 TotalLen = WskSwapU64(*(PULONG64)(pClient->FastRecvBuf + cbReadOffset + 0));

            if (TotalLen < 4 || TotalLen > (64 * 1024 * 1024))
            {
                DBG("WskClientWorkerThread [ClientId=%u]: Invalid NNG total length (%llu)",
                               pClient->ClientId, TotalLen);
                break;
            }

            ULONG RequestId = *(PULONG)(pClient->FastRecvBuf + cbReadOffset + 8);
            ULONG cbPayload = (ULONG)(TotalLen - 4);
            ULONG64 FrameSize = 8 + TotalLen;

            BOOLEAN fAllocPayload = FALSE;
            PUCHAR pbPayload = NULL;

            if (FrameSize <= sizeof(pClient->FastRecvBuf))
            {
                while (cbBuffered < FrameSize)
                {
                    ULONG cbTailSpace = (ULONG)(sizeof(pClient->FastRecvBuf) - cbWriteOffset);
                    if (cbTailSpace < (FrameSize - cbBuffered))
                    {
                        if (cbReadOffset > 0)
                        {
                            if (cbBuffered > 0)
                            {
                                UserVar->Func.memmove(pClient->FastRecvBuf, pClient->FastRecvBuf + cbReadOffset, cbBuffered);
                            }
                            cbReadOffset = 0;
                            cbWriteOffset = cbBuffered;
                        }
                    }

                    ULONG cbRecvThisTime = 0;
                    Status = WskSyncReceive(pClient, pClient->Socket,
                                            pClient->FastRecvBuf + cbWriteOffset,
                                            (ULONG)(sizeof(pClient->FastRecvBuf) - cbWriteOffset),
                                            &cbRecvThisTime);
                    if (!NT_SUCCESS(Status) || cbRecvThisTime == 0)
                    {
                        goto Cleanup;
                    }
                    cbWriteOffset += cbRecvThisTime;
                    cbBuffered = cbWriteOffset - cbReadOffset;
                }
                pbPayload = pClient->FastRecvBuf + cbReadOffset + 12;
            }
            else
            {
                PUCHAR pbLargeFrame = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)FrameSize, MK_WSK_POOL_TAG);
                if (!pbLargeFrame)
                {
                    break;
                }
                UserVar->Func.memcpy(pbLargeFrame, pClient->FastRecvBuf + cbReadOffset, cbBuffered);
                ULONG cbCurLarge = cbBuffered;
                while (cbCurLarge < FrameSize)
                {
                    ULONG cbRecvThisTime = 0;
                    Status = WskSyncReceive(pClient, pClient->Socket,
                                            pbLargeFrame + cbCurLarge,
                                            (ULONG)(FrameSize - cbCurLarge),
                                            &cbRecvThisTime);
                    if (!NT_SUCCESS(Status) || cbRecvThisTime == 0)
                    {
                        UserVar->Func.ExFreePoolWithTag(pbLargeFrame, MK_WSK_POOL_TAG);
                        goto Cleanup;
                    }
                    cbCurLarge += cbRecvThisTime;
                }
                pbPayload = pbLargeFrame + 12;
                fAllocPayload = TRUE;
            }

            if (cbPayload == 0)
            {

                UCHAR emptyRsp[12];
                *(PULONG64)emptyRsp = WskSwapU64(4);
                *(PULONG)(emptyRsp + 8) = RequestId;
                WskSyncSendAll(pClient, pClient->Socket, emptyRsp, sizeof(emptyRsp));
            }
            else if (cbPayload <= 8)
            {

                UCHAR emptyRsp[12];
                *(PULONG64)emptyRsp = WskSwapU64(4);
                *(PULONG)(emptyRsp + 8) = RequestId;
                WskSyncSendAll(pClient, pClient->Socket, emptyRsp, sizeof(emptyRsp));
            }
            else
            {

                ULONG64 qwNonce = *(PULONG64)pbPayload;
                PUCHAR pbRpcData = pbPayload + 8;
                ULONG cbRpcData = cbPayload - 8;

                WskNngFastCrypt(pbRpcData, cbRpcData, qwNonce);


                PLEECHRPC_MSG_HDR pHdr = (PLEECHRPC_MSG_HDR)pbRpcData;
                if (cbRpcData < sizeof(LEECHRPC_MSG_HDR) || pHdr->dwMagic != LEECHRPC_MSGMAGIC)
                {
                    DBG("WskClientWorkerThread [ClientId=%u]: Invalid LeechRPC magic=0x%08X",
                                   pClient->ClientId, (cbRpcData >= 4) ? pHdr->dwMagic : 0);
                    UCHAR emptyRsp[12];
                    *(PULONG64)emptyRsp = WskSwapU64(4);
                    *(PULONG)(emptyRsp + 8) = RequestId;
                    WskSyncSendAll(pClient, pClient->Socket, emptyRsp, sizeof(emptyRsp));
                }
                else
                {

                    pbRsp = NULL;
                    cbRsp = 0;
                    PUCHAR pbDirectOut = pClient->FastSendBuf + 20;
                    ULONG cbDirectOutMax = sizeof(pClient->FastSendBuf) - 20;

                    Status = MkRpc_DispatchCommandEx(pClient, pbRpcData, pHdr->cbMsg, &pbRsp, &cbRsp, pbDirectOut, cbDirectOutMax);

                    if (!NT_SUCCESS(Status) || !pbRsp || cbRsp == 0)
                    {
                        DBG("WskClientWorkerThread [ClientId=%u]: Command dispatch failed, status=0x%08X",
                                       pClient->ClientId, Status);
                        if (pbRsp && pbRsp != pbDirectOut)
                        {
                            UserVar->Func.ExFreePoolWithTag(pbRsp, MK_WSK_POOL_TAG);
                        }
                        pbRsp = NULL;
                        UCHAR emptyRsp[12];
                        *(PULONG64)emptyRsp = WskSwapU64(4);
                        *(PULONG)(emptyRsp + 8) = RequestId;
                        WskSyncSendAll(pClient, pClient->Socket, emptyRsp, sizeof(emptyRsp));
                    }
                    else
                    {

                        ULONG64 qwRspNonce = __rdtsc();
                        ULONG cbTotalSend = 8 + 4 + 8 + cbRsp;
                        BOOLEAN fAllocSend = FALSE;
                        PUCHAR pSendBuf = NULL;

                        if (pbRsp == pbDirectOut)
                        {
                            pSendBuf = pClient->FastSendBuf;
                            *(PULONG64)pSendBuf = WskSwapU64((ULONG64)(4 + 8 + cbRsp));
                            *(PULONG)(pSendBuf + 8) = RequestId;
                            *(PULONG64)(pSendBuf + 12) = qwRspNonce;
                            WskNngFastCrypt(pSendBuf + 20, cbRsp, qwRspNonce);
                        }
                        else
                        {
                            if (cbTotalSend <= sizeof(pClient->FastSendBuf))
                            {
                                pSendBuf = pClient->FastSendBuf;
                            }
                            else
                            {
                                pSendBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, cbTotalSend, MK_WSK_POOL_TAG);
                                fAllocSend = TRUE;
                            }

                            if (pSendBuf)
                            {
                                *(PULONG64)pSendBuf = WskSwapU64((ULONG64)(4 + 8 + cbRsp));
                                *(PULONG)(pSendBuf + 8) = RequestId;
                                *(PULONG64)(pSendBuf + 12) = qwRspNonce;
                                UserVar->Func.RtlCopyMemory(pSendBuf + 20, pbRsp, cbRsp);
                                WskNngFastCrypt(pSendBuf + 20, cbRsp, qwRspNonce);
                            }
                            UserVar->Func.ExFreePoolWithTag(pbRsp, MK_WSK_POOL_TAG);
                        }
                        pbRsp = NULL;

                        if (pSendBuf)
                        {
                            Status = WskSyncSendAll(pClient, pClient->Socket, pSendBuf, cbTotalSend);
                            if (fAllocSend)
                            {
                                UserVar->Func.ExFreePoolWithTag(pSendBuf, MK_WSK_POOL_TAG);
                            }
                            if (!NT_SUCCESS(Status))
                            {
                                DBG("WskClientWorkerThread [ClientId=%u]: Send NNG response failed, status=0x%08X",
                                               pClient->ClientId, Status);
                                if (fAllocPayload && pbPayload)
                                {
                                    UserVar->Func.ExFreePoolWithTag((PUCHAR)pbPayload - 12, MK_WSK_POOL_TAG);
                                }
                                break;
                            }
                        }
                    }
                }
            }


            if (fAllocPayload && pbPayload)
            {
                UserVar->Func.ExFreePoolWithTag((PUCHAR)pbPayload - 12, MK_WSK_POOL_TAG);
                cbReadOffset = 0;
                cbWriteOffset = 0;
                cbBuffered = 0;
            }
            else
            {
                cbReadOffset += (ULONG)FrameSize;
                cbBuffered = cbWriteOffset - cbReadOffset;
                if (cbBuffered == 0)
                {
                    cbReadOffset = 0;
                    cbWriteOffset = 0;
                }
            }
        }
        else
        {

            LEECHRPC_MSG_HDR Hdr;
            UserVar->Func.RtlZeroMemory(&Hdr, sizeof(Hdr));
            Status = WskSyncReceiveExact(pClient, pClient->Socket, &Hdr, sizeof(Hdr));
            if (!NT_SUCCESS(Status))
            {
                break;
            }
            if (Hdr.dwMagic != LEECHRPC_MSGMAGIC || Hdr.cbMsg < sizeof(Hdr) || Hdr.cbMsg > (64 * 1024 * 1024))
            {
                break;
            }
            pbReq = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, Hdr.cbMsg, MK_WSK_POOL_TAG);
            if (!pbReq)
            {
                break;
            }
            UserVar->Func.RtlCopyMemory(pbReq, &Hdr, sizeof(Hdr));
            ULONG cbRemaining = Hdr.cbMsg - sizeof(Hdr);
            if (cbRemaining > 0)
            {
                Status = WskSyncReceiveExact(pClient, pClient->Socket, pbReq + sizeof(Hdr), cbRemaining);
                if (!NT_SUCCESS(Status))
                {
                    UserVar->Func.ExFreePoolWithTag(pbReq, MK_WSK_POOL_TAG);
                    break;
                }
            }

            pbRsp = NULL;
            cbRsp = 0;
            Status = MkRpc_DispatchCommand(pClient, pbReq, Hdr.cbMsg, &pbRsp, &cbRsp);
            UserVar->Func.ExFreePoolWithTag(pbReq, MK_WSK_POOL_TAG);

            if (!NT_SUCCESS(Status) || !pbRsp || cbRsp == 0)
            {
                if (pbRsp)
                {
                    UserVar->Func.ExFreePoolWithTag(pbRsp, MK_WSK_POOL_TAG);
                }
                break;
            }

            Status = WskSyncSendAll(pClient, pClient->Socket, pbRsp, cbRsp);
            UserVar->Func.ExFreePoolWithTag(pbRsp, MK_WSK_POOL_TAG);
            if (!NT_SUCCESS(Status))
            {
                break;
            }
        }
    }

Cleanup:
    DBG("WskClientWorkerThread: Exiting for ClientId=%u", pClient->ClientId);

    pClient->fActive = FALSE;
    if (pClient->Socket)
    {
        WskSyncCloseSocket(UserVar, pClient->Socket);
        pClient->Socket = NULL;
    }

    PMK_WSK_SERVER Server = pClient->Server ? pClient->Server : &g_WskServer;
    MACHENIKE_KERNEL_INTERFACE *pUserVar = Server->UserVar ? Server->UserVar : g_WskServer.UserVar;
    KIRQL OldIrql = 0;
    if (pUserVar && pUserVar->Func.KeAcquireSpinLockRaiseToDpc)
    {
        OldIrql = pUserVar->Func.KeAcquireSpinLockRaiseToDpc(&Server->ClientListLock);
    }
    if (pClient->ListEntry.Flink != NULL && pClient->ListEntry.Blink != NULL &&
        pClient->ListEntry.Flink != &pClient->ListEntry)
    {
        RemoveEntryList(&pClient->ListEntry);
        InitializeListHead(&pClient->ListEntry);
    }
    if (pUserVar && pUserVar->Func.KeReleaseSpinLock)
    {
        pUserVar->Func.KeReleaseSpinLock(&Server->ClientListLock, OldIrql);
    }

    InterlockedDecrement(&Server->ActiveClientCount);

    if (pClient->pFastRecvMdl)
    {
        UserVar->Func.IoFreeMdl(pClient->pFastRecvMdl);
        pClient->pFastRecvMdl = NULL;
    }
    if (pClient->pFastSendMdl)
    {
        UserVar->Func.IoFreeMdl(pClient->pFastSendMdl);
        pClient->pFastSendMdl = NULL;
    }

    if (pClient->pRecvIrp)
    {
        UserVar->Func.IoFreeIrp(pClient->pRecvIrp);
        pClient->pRecvIrp = NULL;
    }
    if (pClient->pSendIrp)
    {
        UserVar->Func.IoFreeIrp(pClient->pSendIrp);
        pClient->pSendIrp = NULL;
    }

    if (pClient->pThread)
    {
        UserVar->Func.ObDereferenceObject(pClient->pThread);
        pClient->pThread = NULL;
    }
    UserVar->Func.ZwClose(pClient->hThread);
    UserVar->Func.ExFreePoolWithTag(pClient, MK_WSK_POOL_TAG);

    UserVar->Func.PsTerminateSystemThread(STATUS_SUCCESS);
}






static VOID WskAcceptThread(_In_ PVOID Context)
{
    PMK_WSK_SERVER Server = (PMK_WSK_SERVER)Context;
    if (!Server || !Server->UserVar)
    {
        return;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = Server->UserVar;
    static ULONG s_ClientIdGen = 1000;

    while (Server->fRunning)
    {
        PWSK_SOCKET ClientSocket = NULL;
        SOCKADDR_IN RemoteAddr = {0};

        NTSTATUS Status = WskSyncAccept(Server, Server->ListenSocket, &ClientSocket, NULL, (PSOCKADDR)&RemoteAddr);

        if (!NT_SUCCESS(Status) || !ClientSocket)
        {
            if (!Server->fRunning)
            {
                break;
            }

            LARGE_INTEGER Timeout;
            Timeout.QuadPart = -10 * 1000 * 100;
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
            continue;
        }


        if (Server->ActiveClientCount >= MK_WSK_MAX_CLIENTS)
        {
            DBG("WskAcceptThread: Max clients (%u) reached, rejecting connection", MK_WSK_MAX_CLIENTS);
            WskSyncCloseSocket(UserVar, ClientSocket);
            continue;
        }


        PMK_WSK_CLIENT pClient =
            (PMK_WSK_CLIENT)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(MK_WSK_CLIENT), MK_WSK_POOL_TAG);
        if (!pClient)
        {
            DBG("WskAcceptThread: Failed to allocate client context");
            WskSyncCloseSocket(UserVar, ClientSocket);
            continue;
        }

        UserVar->Func.RtlZeroMemory(pClient, sizeof(MK_WSK_CLIENT));
        InitializeListHead(&pClient->ListEntry);
        pClient->Socket = ClientSocket;
        pClient->RemoteAddr = RemoteAddr;
        pClient->fActive = TRUE;
        pClient->ClientId = InterlockedIncrement((volatile LONG *)&s_ClientIdGen);
        pClient->Server = Server;

        DBG("WskAcceptThread: Accepted client %u from %u.%u.%u.%u:%u", pClient->ClientId,
                       ((PUCHAR)&RemoteAddr.sin_addr.s_addr)[0], ((PUCHAR)&RemoteAddr.sin_addr.s_addr)[1],
                       ((PUCHAR)&RemoteAddr.sin_addr.s_addr)[2], ((PUCHAR)&RemoteAddr.sin_addr.s_addr)[3],
                       RtlUshortByteSwap(RemoteAddr.sin_port));

        KIRQL OldIrql = 0;
        if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
        {
            OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&Server->ClientListLock);
        }
        if (Server->ClientListHead.Flink == NULL || Server->ClientListHead.Blink == NULL)
        {
            InitializeListHead(&Server->ClientListHead);
        }
        InsertTailList(&Server->ClientListHead, &pClient->ListEntry);
        if (UserVar && UserVar->Func.KeReleaseSpinLock)
        {
            UserVar->Func.KeReleaseSpinLock(&Server->ClientListLock, OldIrql);
        }

        InterlockedIncrement(&Server->ActiveClientCount);


        Status = UserVar->Func.PsCreateSystemThread(
            &pClient->hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WskClientWorkerThread, pClient);

        if (NT_SUCCESS(Status))
        {
            POBJECT_TYPE pThreadType = (UserVar && UserVar->Func.pPsThreadType) ? *UserVar->Func.pPsThreadType : NULL;
            UserVar->Func.ObReferenceObjectByHandle(
                pClient->hThread, THREAD_ALL_ACCESS, pThreadType, KernelMode, (PVOID *)&pClient->pThread, NULL);
        }
        else
        {
            DBG("WskAcceptThread: PsCreateSystemThread failed for client %u, status=0x%08X",
                           pClient->ClientId, Status);
            pClient->fActive = FALSE;
            if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
            {
                OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&Server->ClientListLock);
            }
            if (pClient->ListEntry.Flink != NULL && pClient->ListEntry.Blink != NULL &&
                pClient->ListEntry.Flink != &pClient->ListEntry)
            {
                RemoveEntryList(&pClient->ListEntry);
                InitializeListHead(&pClient->ListEntry);
            }
            if (UserVar && UserVar->Func.KeReleaseSpinLock)
            {
                UserVar->Func.KeReleaseSpinLock(&Server->ClientListLock, OldIrql);
            }
            InterlockedDecrement(&Server->ActiveClientCount);
            WskSyncCloseSocket(UserVar, ClientSocket);
            UserVar->Func.ExFreePoolWithTag(pClient, MK_WSK_POOL_TAG);
        }
    }

    UserVar->Func.PsTerminateSystemThread(STATUS_SUCCESS);
}





NTSTATUS WskServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, USHORT Port)
{
    if (!UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_WskServer.fRunning)
    {
        DBG("WskServer_Init: WSK TCP server is already running on port %u", g_WskServer.Port);
        return STATUS_ALREADY_COMMITTED;
    }

    NTSTATUS Status;

    UserVar->Func.RtlZeroMemory(&g_WskServer, sizeof(g_WskServer));
    g_WskServer.UserVar = UserVar;
    g_WskServer.Port = (Port == 0) ? MK_WSK_DEFAULT_PORT : Port;
    if (UserVar->Func.KeInitializeSpinLock)
    {
        UserVar->Func.KeInitializeSpinLock(&g_WskServer.ClientListLock);
    }
    else
    {
        g_WskServer.ClientListLock = 0;
    }
    InitializeListHead(&g_WskServer.ClientListHead);

    DBG("WskServer_Init: Initializing WSK on port %u...", g_WskServer.Port);


    WSK_CLIENT_NPI ClientNpi;
    ClientNpi.ClientContext = NULL;
    ClientNpi.Dispatch = &g_WskClientDispatch;

    if (!UserVar->Func.WskRegister)
    {
        DBG("WskServer_Init: WskRegister function pointer is NULL");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    Status = UserVar->Func.WskRegister(&ClientNpi, &g_WskServer.Registration);
    if (!NT_SUCCESS(Status))
    {
        DBG("WskServer_Init: WskRegister failed, status=0x%08X", Status);
        return Status;
    }
    g_WskServer.fRegistered = TRUE;


    if (!UserVar->Func.WskCaptureProviderNPI)
    {
        DBG("WskServer_Init: WskCaptureProviderNPI function pointer is NULL");
        if (UserVar->Func.WskDeregister)
        {
            UserVar->Func.WskDeregister(&g_WskServer.Registration);
        }
        g_WskServer.fRegistered = FALSE;
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    Status = UserVar->Func.WskCaptureProviderNPI(&g_WskServer.Registration, WSK_INFINITE_WAIT, &g_WskServer.ProviderNpi);
    if (!NT_SUCCESS(Status))
    {
        DBG("WskServer_Init: WskCaptureProviderNPI failed, status=0x%08X", Status);
        if (UserVar->Func.WskDeregister)
        {
            UserVar->Func.WskDeregister(&g_WskServer.Registration);
        }
        g_WskServer.fRegistered = FALSE;
        return Status;
    }
    g_WskServer.fCapturedNpi = TRUE;


    Status = WskSyncSocket(&g_WskServer, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_LISTEN_SOCKET,
                           &g_WskServer.ListenSocket);
    if (!NT_SUCCESS(Status))
    {
        DBG("WskServer_Init: WskSyncSocket (Listen) failed, status=0x%08X", Status);
        WskServer_Stop(UserVar);
        return Status;
    }


    SOCKADDR_IN BindAddr = {0};
    BindAddr.sin_family = AF_INET;
    BindAddr.sin_addr.s_addr = INADDR_ANY;
    BindAddr.sin_port = RtlUshortByteSwap(g_WskServer.Port);

    Status = WskSyncBind(&g_WskServer, g_WskServer.ListenSocket, (PSOCKADDR)&BindAddr);
    if (!NT_SUCCESS(Status))
    {
        DBG("WskServer_Init: WskSyncBind to port %u failed, status=0x%08X", g_WskServer.Port, Status);
        WskServer_Stop(UserVar);
        return Status;
    }


    g_WskServer.fRunning = TRUE;
    Status = UserVar->Func.PsCreateSystemThread(
        &g_WskServer.hAcceptThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WskAcceptThread, (PVOID)&g_WskServer);

    if (NT_SUCCESS(Status))
    {
        POBJECT_TYPE pThreadType = UserVar->Func.pPsThreadType ? *UserVar->Func.pPsThreadType : NULL;
        UserVar->Func.ObReferenceObjectByHandle(
            g_WskServer.hAcceptThread, THREAD_ALL_ACCESS, pThreadType, KernelMode,
            (PVOID *)&g_WskServer.pAcceptThread, NULL);
        DBG("WskServer_Init: WSK Server listening on port %u successfully", g_WskServer.Port);
    }
    else
    {
        DBG("WskServer_Init: Failed to create Accept thread, status=0x%08X", Status);
        WskServer_Stop(UserVar);
        return Status;
    }

    return STATUS_SUCCESS;
}

VOID WskServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        return;
    }

    DBG("WskServer_Stop: Stopping WSK server...");
    g_WskServer.fRunning = FALSE;


    if (g_WskServer.ListenSocket)
    {
        WskSyncCloseSocket(UserVar, g_WskServer.ListenSocket);
        g_WskServer.ListenSocket = NULL;
    }


    if (g_WskServer.pAcceptThread)
    {
        if (UserVar)
        {
            UserVar->Func.KeWaitForSingleObject(g_WskServer.pAcceptThread, Executive, KernelMode, FALSE, NULL);
            UserVar->Func.ObDereferenceObject(g_WskServer.pAcceptThread);
        }
        g_WskServer.pAcceptThread = NULL;
    }
    if (g_WskServer.hAcceptThread)
    {
        if (UserVar)
        {
            UserVar->Func.ZwClose(g_WskServer.hAcceptThread);
        }
        g_WskServer.hAcceptThread = NULL;
    }


    KIRQL OldIrql = 0;
    PWSK_SOCKET clientSockets[MK_WSK_MAX_CLIENTS] = {0};
    ULONG clientSocketCount = 0;

    if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
    {
        OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&g_WskServer.ClientListLock);
    }
    if (g_WskServer.ClientListHead.Flink != NULL && g_WskServer.ClientListHead.Blink != NULL)
    {
        PLIST_ENTRY pEntry = g_WskServer.ClientListHead.Flink;
        while (pEntry != &g_WskServer.ClientListHead && pEntry != NULL)
        {
            PMK_WSK_CLIENT pClient = CONTAINING_RECORD(pEntry, MK_WSK_CLIENT, ListEntry);
            pClient->fActive = FALSE;
            if (pClient->Socket && clientSocketCount < MK_WSK_MAX_CLIENTS)
            {
                clientSockets[clientSocketCount++] = pClient->Socket;
            }
            pEntry = pEntry->Flink;
        }
    }
    if (UserVar && UserVar->Func.KeReleaseSpinLock)
    {
        UserVar->Func.KeReleaseSpinLock(&g_WskServer.ClientListLock, OldIrql);
    }

    for (ULONG i = 0; i < clientSocketCount; i++)
    {
        if (clientSockets[i])
        {
            WskSyncCloseSocket(UserVar, clientSockets[i]);
        }
    }


    if (g_WskServer.ActiveClientCount > 0)
    {
        DBG("WskServer_Stop: Waiting for %d active clients to disconnect...", g_WskServer.ActiveClientCount);
    }
    while (g_WskServer.ActiveClientCount > 0)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10 * 1000 * 10;
        if (UserVar)
        {
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
        }
    }


    if (g_WskServer.fCapturedNpi)
    {
        if (UserVar && UserVar->Func.WskReleaseProviderNPI)
        {
            UserVar->Func.WskReleaseProviderNPI(&g_WskServer.Registration);
        }
        g_WskServer.fCapturedNpi = FALSE;
    }
    if (g_WskServer.fRegistered)
    {
        if (UserVar && UserVar->Func.WskDeregister)
        {
            UserVar->Func.WskDeregister(&g_WskServer.Registration);
        }
        g_WskServer.fRegistered = FALSE;
    }
    DBG("WskServer_Stop: WSK server stopped completely");
}
