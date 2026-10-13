#include "wsk_server.h"
#include "Common.h"
#include "rpc_dispatch.h"
#include "leechcore_kernel.h"

MK_WSK_SERVER g_WskServer = {0};

static const WSK_CLIENT_DISPATCH g_WskClientDispatch = {MAKE_WSK_VERSION(1, 0), 0, NULL};





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

    Status = WskWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
    DBG("WskSyncSetTcpNoDelay: Status=0x%08X", Status);
    return Status;
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
        Status = WskWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
        DBG("WskSyncSetSocketBuffers [SO_RCVBUF]: Status=0x%08X", Status);
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
        Status = WskWaitForIrp(UserVar, Irp, &Sync, Status, NULL);
        DBG("WskSyncSetSocketBuffers [SO_SNDBUF]: Status=0x%08X", Status);
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


static NTSTATUS WskSyncReceiveTimed(
    _In_ PMK_WSK_CLIENT pClient,
    _In_ PWSK_SOCKET Socket,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG pBytesReceived,
    _In_opt_ PLARGE_INTEGER pTimeout)
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

    BOOLEAN fPersistentIrp = FALSE;
    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = NULL;

    if (!pTimeout && pClient->pRecvIrp)
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

    if (fPersistentIrp)
    {
        Status = WskWaitForPersistentIrp(UserVar, Irp, &Sync, Status, NULL);
    }
    else if (Status == STATUS_PENDING && UserVar)
    {
        NTSTATUS WaitStatus = UserVar->Func.KeWaitForSingleObject(Sync.pEvent, Executive, KernelMode, FALSE, pTimeout);
        if (pTimeout && WaitStatus == STATUS_TIMEOUT)
        {
            // 超时取消探测 IRP 并等待完成例程退出
            IoCancelIrp(Irp);
            UserVar->Func.KeWaitForSingleObject(Sync.pEvent, Executive, KernelMode, FALSE, NULL);
            // 防御性校验：若取消瞬间底层恰好接收完成，则保留成功状态与接收长度，杜绝数据静默丢失
            if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information > 0)
            {
                Status = STATUS_SUCCESS;
            }
            else
            {
                Status = STATUS_TIMEOUT;
            }
        }
        else
        {
            Status = Irp->IoStatus.Status;
        }
    }

    if (NT_SUCCESS(Status))
    {
        *pBytesReceived = (ULONG)Irp->IoStatus.Information;
    }

    if (!fPersistentIrp && UserVar && Irp)
    {
        UserVar->Func.IoFreeIrp(Irp);
    }

    if (fCustomMdl)
    {
        UserVar->Func.IoFreeMdl(WskBuf.Mdl);
    }
    return Status;
}

static __forceinline NTSTATUS WskSyncReceive(
    _In_ PMK_WSK_CLIENT pClient,
    _In_ PWSK_SOCKET Socket,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG pBytesReceived)
{
    return WskSyncReceiveTimed(pClient, Socket, Buffer, Length, pBytesReceived, NULL);
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


static __forceinline NTSTATUS WskDrainPendingSend(
    _In_ PMK_WSK_CLIENT pClient,
    _In_ ULONG SlotIdx)
{
    if (!pClient || SlotIdx >= MK_WSK_SEND_PIPELINE_SLOTS)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!pClient->fSendInFlight[SlotIdx])
    {
        return STATUS_SUCCESS;
    }
    MACHENIKE_KERNEL_INTERFACE *UserVar = pClient->Server ? pClient->Server->UserVar : g_WskServer.UserVar;
    if (UserVar)
    {
        UserVar->Func.KeWaitForSingleObject(&pClient->SendEvent[SlotIdx], Executive, KernelMode, FALSE, NULL);
    }
    NTSTATUS Status = pClient->pSendIrp[SlotIdx]->IoStatus.Status;
    pClient->fSendInFlight[SlotIdx] = FALSE;
    return Status;
}

static __forceinline NTSTATUS WskAsyncSendSlot(
    _In_ PMK_WSK_CLIENT pClient,
    _In_ PWSK_SOCKET Socket,
    _In_ ULONG SlotIdx,
    _In_ ULONG Length)
{
    if (!Socket || !Socket->Dispatch || !pClient || !pClient->Server || !pClient->Server->UserVar || SlotIdx >= MK_WSK_SEND_PIPELINE_SLOTS)
    {
        return STATUS_INVALID_PARAMETER;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = pClient->Server->UserVar;
    PIRP Irp = pClient->pSendIrp[SlotIdx];
    PKEVENT pEvent = &pClient->SendEvent[SlotIdx];

    // 防御性：若此槽位仍在飞行中，等待其完成
    if (pClient->fSendInFlight[SlotIdx])
    {
        UserVar->Func.KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
        pClient->fSendInFlight[SlotIdx] = FALSE;
    }

    PWSK_SYNC_CONTEXT pSync = &pClient->SendSync[SlotIdx];
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

    WSK_BUF WskBuf;
    WskBuf.Offset = 0;
    WskBuf.Length = Length;
    WskBuf.Mdl = pClient->pFastSendMdl[SlotIdx];

    // 关键优化：显式指定 WSK_FLAG_NODELAY，消灭协议栈小包延迟
    NTSTATUS Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskSend(
        Socket,
        &WskBuf,
        WSK_FLAG_NODELAY,
        Irp);

    if (Status == STATUS_PENDING)
    {
        // 核心突破：异步发出，主线程不调用 KeWaitForSingleObject 睡眠！直接放行并标记飞行中！
        pClient->fSendInFlight[SlotIdx] = TRUE;
        return STATUS_SUCCESS;
    }
    else
    {
        // 同步完成
        pClient->fSendInFlight[SlotIdx] = FALSE;
        return Status;
    }
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

    while (BytesTotal < Length)
    {
        ULONG BytesToSend = Length - BytesTotal;

        WSK_SYNC_CONTEXT Sync;
        PIRP Irp = WskAllocateSyncIrp(UserVar, &Sync);
        if (!Irp)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        WSK_BUF WskBuf;
        WskBuf.Offset = 0;
        WskBuf.Length = BytesToSend;
        WskBuf.Mdl = UserVar->Func.IoAllocateMdl(pCur + BytesTotal, BytesToSend, FALSE, FALSE, NULL);
        if (!WskBuf.Mdl)
        {
            UserVar->Func.IoFreeIrp(Irp);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        UserVar->Func.MmBuildMdlForNonPagedPool(WskBuf.Mdl);

        NTSTATUS Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskSend(
            Socket, &WskBuf, WSK_FLAG_NODELAY, Irp);

        ULONG_PTR Information = 0;
        Status = WskWaitForIrp(UserVar, Irp, &Sync, Status, &Information);

        ULONG SentThisTime = (ULONG)Information;
        UserVar->Func.IoFreeMdl(WskBuf.Mdl);

        if (!NT_SUCCESS(Status) || SentThisTime == 0)
        {
            return NT_SUCCESS(Status) ? STATUS_CONNECTION_DISCONNECTED : Status;
        }
        BytesTotal += SentThisTime;
    }
    return STATUS_SUCCESS;
}





#define NNG_CRYPT_KEY 0x8899AABBCCDDEEFFULL

#define WskSwapU64(Val) RtlUlonglongByteSwap(Val)

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
    pClient->pRecvIrp = UserVar->Func.IoAllocateIrp(1, FALSE);
    if (pClient->pRecvIrp)
    {
        UserVar->Func.KeInitializeEvent(&pClient->RecvEvent, SynchronizationEvent, FALSE);
    }

    for (ULONG i = 0; i < MK_WSK_SEND_PIPELINE_SLOTS; i++)
    {
        pClient->pFastSendMdl[i] = UserVar->Func.IoAllocateMdl(pClient->FastSendBuf[i], sizeof(pClient->FastSendBuf[i]), FALSE, FALSE, NULL);
        if (pClient->pFastSendMdl[i])
        {
            UserVar->Func.MmBuildMdlForNonPagedPool(pClient->pFastSendMdl[i]);
        }
        pClient->pSendIrp[i] = UserVar->Func.IoAllocateIrp(1, FALSE);
        if (pClient->pSendIrp[i])
        {
            UserVar->Func.KeInitializeEvent(&pClient->SendEvent[i], SynchronizationEvent, FALSE);
        }
        pClient->SendSync[i].UserVar = UserVar;
        pClient->SendSync[i].pEvent = &pClient->SendEvent[i];
        pClient->fSendInFlight[i] = FALSE;
    }
    pClient->ActiveSendIdx = 0;
    pClient->cbRecvHead = 0;
    pClient->cbRecvTail = 0;
    pClient->Cached_hLC = NULL;
    pClient->Cached_dwRpcClientID = 0;

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
        DBG("WskClientWorkerThread [ClientId=%u]: NNG SP Handshake completed successfully (Pipeline Batching Mode)!",
            pClient->ClientId);
    }
    else
    {
        DBG("WskClientWorkerThread [ClientId=%u]: Non-NNG connection, falling back to raw TCP",
            pClient->ClientId);
    }

    while (g_WskServer.fRunning && pClient->fActive)
    {
        if (fIsNng)
        {
            // 步骤 1: 确保至少接收到 12 字节的 NNG 帧头
            while ((pClient->cbRecvTail - pClient->cbRecvHead) < 12)
            {
                // 双指针空间管理：若尾部可用空间不足 64KB，执行一次极速归一化搬移 (消灭 99.99% memmove)
                ULONG cbAvail = (ULONG)(sizeof(pClient->FastRecvBuf) - pClient->cbRecvTail);
                if (cbAvail < (64 * 1024))
                {
                    ULONG cbValid = pClient->cbRecvTail - pClient->cbRecvHead;
                    if (cbValid > 0 && pClient->cbRecvHead > 0)
                    {
                        UserVar->Func.memmove(pClient->FastRecvBuf, pClient->FastRecvBuf + pClient->cbRecvHead, cbValid);
                    }
                    pClient->cbRecvHead = 0;
                    pClient->cbRecvTail = cbValid;
                    cbAvail = (ULONG)(sizeof(pClient->FastRecvBuf) - pClient->cbRecvTail);
                }

                ULONG cbRecvThisTime = 0;
                Status = WskSyncReceive(pClient, pClient->Socket,
                                        pClient->FastRecvBuf + pClient->cbRecvTail,
                                        cbAvail,
                                        &cbRecvThisTime);
                if (!NT_SUCCESS(Status) || cbRecvThisTime == 0)
                {
                    DBG("WskClientWorkerThread [ClientId=%u]: Header Recv failed/closed (Status=0x%08X, cbRecv=%u, Line=%d)",
                        pClient->ClientId, Status, cbRecvThisTime, __LINE__);
                    goto Cleanup;
                }
                pClient->cbRecvTail += cbRecvThisTime;
            }

            PUCHAR pCurFrame = pClient->FastRecvBuf + pClient->cbRecvHead;
            ULONG64 TotalLen = WskSwapU64(*(PULONG64)(pCurFrame + 0));
            if (TotalLen < 4 || TotalLen > (64 * 1024 * 1024))
            {
                DBG("WskClientWorkerThread [ClientId=%u]: Invalid NNG total length (%llu, Line=%d)",
                    pClient->ClientId, TotalLen, __LINE__);
                break;
            }

            ULONG RequestId = *(PULONG)(pCurFrame + 8);
            ULONG cbPayload = (ULONG)(TotalLen - 4);
            ULONG64 FrameSize = 8 + TotalLen;

            // 步骤 2: 确保至少第 1 个帧完整收全
            if (FrameSize <= sizeof(pClient->FastRecvBuf))
            {
                while ((pClient->cbRecvTail - pClient->cbRecvHead) < FrameSize)
                {
                    ULONG cbAvail = (ULONG)(sizeof(pClient->FastRecvBuf) - pClient->cbRecvTail);
                    if (cbAvail < (FrameSize - (pClient->cbRecvTail - pClient->cbRecvHead)))
                    {
                        ULONG cbValid = pClient->cbRecvTail - pClient->cbRecvHead;
                        if (cbValid > 0 && pClient->cbRecvHead > 0)
                        {
                            UserVar->Func.memmove(pClient->FastRecvBuf, pClient->FastRecvBuf + pClient->cbRecvHead, cbValid);
                        }
                        pClient->cbRecvHead = 0;
                        pClient->cbRecvTail = cbValid;
                        cbAvail = (ULONG)(sizeof(pClient->FastRecvBuf) - pClient->cbRecvTail);
                    }

                    ULONG cbRecvThisTime = 0;
                    Status = WskSyncReceive(pClient, pClient->Socket,
                                            pClient->FastRecvBuf + pClient->cbRecvTail,
                                            cbAvail,
                                            &cbRecvThisTime);
                    if (!NT_SUCCESS(Status) || cbRecvThisTime == 0)
                    {
                        DBG("WskClientWorkerThread [ClientId=%u]: Body Recv failed/closed (Status=0x%08X, cbRecv=%u, Line=%d)",
                            pClient->ClientId, Status, cbRecvThisTime, __LINE__);
                        goto Cleanup;
                    }
                    pClient->cbRecvTail += cbRecvThisTime;
                }
            }
            else
            {
                // 超大包 (> 1MB) 独立动态分配接收处理
                PUCHAR pbLargeFrame = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)FrameSize, MK_WSK_POOL_TAG);
                if (!pbLargeFrame)
                {
                    DBG("WskClientWorkerThread [ClientId=%u]: Failed to allocate large frame (%llu bytes)",
                        pClient->ClientId, FrameSize);
                    break;
                }
                ULONG cbCurValid = pClient->cbRecvTail - pClient->cbRecvHead;
                UserVar->Func.memcpy(pbLargeFrame, pClient->FastRecvBuf + pClient->cbRecvHead, cbCurValid);
                ULONG cbCurLarge = cbCurValid;
                while (cbCurLarge < FrameSize)
                {
                    ULONG cbRecvThisTime = 0;
                    Status = WskSyncReceive(pClient, pClient->Socket,
                                            pbLargeFrame + cbCurLarge,
                                            (ULONG)(FrameSize - cbCurLarge),
                                            &cbRecvThisTime);
                    if (!NT_SUCCESS(Status) || cbRecvThisTime == 0)
                    {
                        DBG("WskClientWorkerThread [ClientId=%u]: Large Body Recv failed (Status=0x%08X, cbRecv=%u)",
                            pClient->ClientId, Status, cbRecvThisTime);
                        UserVar->Func.ExFreePoolWithTag(pbLargeFrame, MK_WSK_POOL_TAG);
                        goto Cleanup;
                    }
                    cbCurLarge += cbRecvThisTime;
                }

                // 处理大包单帧并发送
                if (cbPayload > 8)
                {
                    ULONG64 qwNonce = *(PULONG64)(pbLargeFrame + 12);
                    PUCHAR pbRpcDataRaw = pbLargeFrame + 20;
                    ULONG cbRpcDataRaw = cbPayload - 8;
                    WskNngFastCrypt(pbRpcDataRaw, cbRpcDataRaw, qwNonce);

                    PUCHAR pbRspOut = NULL;
                    ULONG cbRspOut = 0;
                    Status = MkRpc_DispatchCommand(pClient, pbRpcDataRaw, cbRpcDataRaw, &pbRspOut, &cbRspOut);
                    if (NT_SUCCESS(Status) && pbRspOut && cbRspOut > 0)
                    {
                        ULONG cbTotalSend = 20 + cbRspOut;
                        PUCHAR pbSendLarge = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, cbTotalSend, MK_WSK_POOL_TAG);
                        if (pbSendLarge)
                        {
                            *(PULONG64)(pbSendLarge + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                            *(PULONG)(pbSendLarge + 8) = RequestId;
                            *(PULONG64)(pbSendLarge + 12) = qwNonce;
                            UserVar->Func.memcpy(pbSendLarge + 20, pbRspOut, cbRspOut);
                            WskNngFastCrypt(pbSendLarge + 20, cbRspOut, qwNonce);
                            Status = WskSyncSendAll(pClient, pClient->Socket, pbSendLarge, cbTotalSend);
                            UserVar->Func.ExFreePoolWithTag(pbSendLarge, MK_WSK_POOL_TAG);
                        }
                        UserVar->Func.ExFreePoolWithTag(pbRspOut, LC_POOL_TAG);
                    }
                }
                UserVar->Func.ExFreePoolWithTag(pbLargeFrame, MK_WSK_POOL_TAG);
                pClient->cbRecvHead = 0;
                pClient->cbRecvTail = 0;
                continue;
            }


            // 步骤 3: ★★★ 全双工异步流水线 —— 连续收割并原位直写当前活跃槽位 ★★★
            ULONG SlotIdx = pClient->ActiveSendIdx;
            Status = WskDrainPendingSend(pClient, SlotIdx);
            if (!NT_SUCCESS(Status))
            {
                DBG("WskClientWorkerThread [ClientId=%u]: DrainPendingSend failed (Status=0x%08X)", pClient->ClientId, Status);
                goto Cleanup;
            }
            PUCHAR pCurrentSendBuf = pClient->FastSendBuf[SlotIdx];
            ULONG cbSendBufSize = sizeof(pClient->FastSendBuf[SlotIdx]);

            ULONG cbOffset = pClient->cbRecvHead;
            ULONG cbSendTotal = 0;

            while ((pClient->cbRecvTail - cbOffset) >= 12)
            {
                ULONG64 CurTotalLen = WskSwapU64(*(PULONG64)(pClient->FastRecvBuf + cbOffset + 0));
                if (CurTotalLen < 4 || CurTotalLen > (64 * 1024 * 1024))
                {
                    break;
                }
                ULONG64 CurFrameSize = 8 + CurTotalLen;
                if ((pClient->cbRecvTail - cbOffset) < CurFrameSize)
                {
                    // 当前尾部帧尚未完整到达，退出批处理，留至下一轮接收
                    break;
                }

                ULONG CurRequestId = *(PULONG)(pClient->FastRecvBuf + cbOffset + 8);
                ULONG CurPayload = (ULONG)(CurTotalLen - 4);
                PUCHAR pbPayloadRaw = pClient->FastRecvBuf + cbOffset + 12;

                if (CurPayload == 0 || CurPayload <= 8)
                {
                    if (cbSendTotal + 12 <= cbSendBufSize)
                    {
                        PUCHAR pRsp = pCurrentSendBuf + cbSendTotal;
                        *(PULONG64)pRsp = WskSwapU64(4);
                        *(PULONG)(pRsp + 8) = CurRequestId;
                        cbSendTotal += 12;
                    }
                }
                else
                {
                    ULONG64 qwNonce = *(PULONG64)pbPayloadRaw;
                    PUCHAR pbRpcDataRaw = pbPayloadRaw + 8;
                    ULONG cbRpcDataRaw = CurPayload - 8;

                    // 原位解密载荷
                    WskNngFastCrypt(pbRpcDataRaw, cbRpcDataRaw, qwNonce);

                    // 步骤 3.1: 智能预估当前请求最大应答体积 (动态 DirectOut 槽位对齐)
                    ULONG cbEstNeeded = 256;
                    if (cbRpcDataRaw >= sizeof(LEECHRPC_MSG_BIN))
                    {
                        PLEECHRPC_MSG_BIN pBinPeek = (PLEECHRPC_MSG_BIN)pbRpcDataRaw;
                        if (pBinPeek->dwMagic == LEECHRPC_MSGMAGIC && pBinPeek->tpMsg == LEECHRPC_MSGTYPE_READSCATTER_REQ)
                        {
                            ULONG cMEMs = (ULONG)pBinPeek->qwData[0];
                            ULONG cbMax = (ULONG)pBinPeek->qwData[1];
                            if (cMEMs <= 0x2000 && cbMax <= (cMEMs << 12))
                            {
                                cbEstNeeded = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_SCATTER) + cbMax + 32;
                            }
                        }
                    }

                    // 关键前置冲刷：若当前槽位已累积数据且剩余空间不足以 DirectOut 容纳当前请求，
                    // 立即将已累积数据送入全双工异步发送，并推进至下一个干净的 1MB 槽位！
                    // ★★★ 确保 100% 命中 DirectOut 直写，从微架构根源消灭大池分配与二次 memcpy ★★★
                    if (cbSendTotal > 0 && (cbSendTotal + 20 + cbEstNeeded > cbSendBufSize))
                    {
                        Status = WskAsyncSendSlot(pClient, pClient->Socket, SlotIdx, cbSendTotal);
                        if (!NT_SUCCESS(Status))
                        {
                            goto Cleanup;
                        }
                        SlotIdx = (SlotIdx + 1) % MK_WSK_SEND_PIPELINE_SLOTS;
                        pClient->ActiveSendIdx = SlotIdx;
                        Status = WskDrainPendingSend(pClient, SlotIdx);
                        if (!NT_SUCCESS(Status))
                        {
                            goto Cleanup;
                        }
                        pCurrentSendBuf = pClient->FastSendBuf[SlotIdx];
                        cbSendBufSize = sizeof(pClient->FastSendBuf[SlotIdx]);
                        cbSendTotal = 0;
                    }

                    // 计算当前发送槽位剩余可用空间 (DirectOut 零拷贝通道)
                    ULONG cbDirectAvail = 0;
                    PUCHAR pbDirectTarget = NULL;
                    if (cbSendTotal + 20 < cbSendBufSize)
                    {
                        pbDirectTarget = pCurrentSendBuf + cbSendTotal + 20;
                        cbDirectAvail = (ULONG)(cbSendBufSize - (cbSendTotal + 20));
                    }

                    PUCHAR pbRspOut = NULL;
                    ULONG cbRspOut = 0;
                    Status = MkRpc_DispatchCommandEx(
                        pClient,
                        pbRpcDataRaw,
                        cbRpcDataRaw,
                        &pbRspOut,
                        &cbRspOut,
                        (cbDirectAvail >= 256) ? pbDirectTarget : NULL,
                        (cbDirectAvail >= 256) ? cbDirectAvail : 0);

                    if (NT_SUCCESS(Status) && pbRspOut && cbRspOut > 0)
                    {
                        ULONG RspFrameSize = 20 + cbRspOut;

                        if (pbRspOut == pbDirectTarget)
                        {
                            // ★★★ 命中 DirectOut 原位直写：零内存池分配、零内存拷贝 ★★★
                            PUCHAR pRsp = pCurrentSendBuf + cbSendTotal;
                            *(PULONG64)(pRsp + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                            *(PULONG)(pRsp + 8) = CurRequestId;
                            *(PULONG64)(pRsp + 12) = qwNonce;
                            WskNngFastCrypt(pbDirectTarget, cbRspOut, qwNonce);
                            cbSendTotal += RspFrameSize;
                        }
                        else
                        {
                            // Fallback：未命中 DirectOut (如大包或剩余空间不足时由分发器独立分配的非分页内存)
                            if (cbSendTotal + RspFrameSize <= cbSendBufSize)
                            {
                                PUCHAR pRsp = pCurrentSendBuf + cbSendTotal;
                                *(PULONG64)(pRsp + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                                *(PULONG)(pRsp + 8) = CurRequestId;
                                *(PULONG64)(pRsp + 12) = qwNonce;
                                UserVar->Func.memcpy(pRsp + 20, pbRspOut, cbRspOut);
                                WskNngFastCrypt(pRsp + 20, cbRspOut, qwNonce);
                                cbSendTotal += RspFrameSize;
                            }
                            else
                            {
                                // 若当前批处理槽位已满，异步发送已积攒的批次数据，切换至另一槽位继续
                                if (cbSendTotal > 0)
                                {
                                    Status = WskAsyncSendSlot(pClient, pClient->Socket, SlotIdx, cbSendTotal);
                                    if (!NT_SUCCESS(Status))
                                    {
                                        UserVar->Func.ExFreePoolWithTag(pbRspOut, LC_POOL_TAG);
                                        goto Cleanup;
                                    }
                                    SlotIdx = (SlotIdx + 1) % MK_WSK_SEND_PIPELINE_SLOTS;
                                    pClient->ActiveSendIdx = SlotIdx;
                                    Status = WskDrainPendingSend(pClient, SlotIdx);
                                    if (!NT_SUCCESS(Status))
                                    {
                                        UserVar->Func.ExFreePoolWithTag(pbRspOut, LC_POOL_TAG);
                                        goto Cleanup;
                                    }
                                    pCurrentSendBuf = pClient->FastSendBuf[SlotIdx];
                                    cbSendBufSize = sizeof(pClient->FastSendBuf[SlotIdx]);
                                    cbSendTotal = 0;
                                }

                                if (RspFrameSize <= cbSendBufSize)
                                {
                                    PUCHAR pRsp = pCurrentSendBuf;
                                    *(PULONG64)(pRsp + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                                    *(PULONG)(pRsp + 8) = CurRequestId;
                                    *(PULONG64)(pRsp + 12) = qwNonce;
                                    UserVar->Func.memcpy(pRsp + 20, pbRspOut, cbRspOut);
                                    WskNngFastCrypt(pRsp + 20, cbRspOut, qwNonce);
                                    cbSendTotal = RspFrameSize;
                                }
                                else
                                {
                                    // 仅当单帧体积超过 1MB 物理上限时，独立分配大包并单独发送
                                    PUCHAR pbSendLarge = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, RspFrameSize, MK_WSK_POOL_TAG);
                                    if (pbSendLarge)
                                    {
                                        *(PULONG64)(pbSendLarge + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                                        *(PULONG)(pbSendLarge + 8) = CurRequestId;
                                        *(PULONG64)(pbSendLarge + 12) = qwNonce;
                                        UserVar->Func.memcpy(pbSendLarge + 20, pbRspOut, cbRspOut);
                                        WskNngFastCrypt(pbSendLarge + 20, cbRspOut, qwNonce);
                                        Status = WskSyncSendAll(pClient, pClient->Socket, pbSendLarge, RspFrameSize);
                                        UserVar->Func.ExFreePoolWithTag(pbSendLarge, MK_WSK_POOL_TAG);
                                        if (!NT_SUCCESS(Status))
                                        {
                                            UserVar->Func.ExFreePoolWithTag(pbRspOut, LC_POOL_TAG);
                                            goto Cleanup;
                                        }
                                    }
                                }
                            }

                            UserVar->Func.ExFreePoolWithTag(pbRspOut, LC_POOL_TAG);
                        }
                    }
                    else
                    {
                        if (cbSendTotal + 12 <= cbSendBufSize)
                        {
                            PUCHAR pRsp = pCurrentSendBuf + cbSendTotal;
                            *(PULONG64)pRsp = WskSwapU64(4);
                            *(PULONG)(pRsp + 8) = CurRequestId;
                            cbSendTotal += 12;
                        }
                    }
                }

                cbOffset += (ULONG)CurFrameSize;
            }

            // 步骤 4: ★★★ 全双工异步冲刷：将已累积的全部响应帧异步发出，不阻塞主线程！ ★★★
            if (cbSendTotal > 0)
            {
                Status = WskAsyncSendSlot(pClient, pClient->Socket, SlotIdx, cbSendTotal);
                if (!NT_SUCCESS(Status))
                {
                    DBG("WskClientWorkerThread [ClientId=%u]: Async Send failed (Status=0x%08X)", pClient->ClientId, Status);
                    goto Cleanup;
                }
                // 翻转槽位供下一次 DirectOut 写入，当前槽位在底层网卡 DMA 异步出网
                pClient->ActiveSendIdx = (SlotIdx + 1) % MK_WSK_SEND_PIPELINE_SLOTS;
            }

            // 步骤 5: ★★★ 双指针滑动接收游标推进：消灭 99.99% memmove 拷贝与缓存污染 ★★★
            pClient->cbRecvHead = cbOffset;
            if (pClient->cbRecvHead == pClient->cbRecvTail)
            {
                pClient->cbRecvHead = 0;
                pClient->cbRecvTail = 0;
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
    DBG("WskClientWorkerThread: Exiting for ClientId=%u, final Status=0x%08X", pClient->ClientId, Status);

    pClient->fActive = FALSE;

    if (pClient->Cached_dwRpcClientID != 0)
    {
        LeechRPC_LcHandle_Close(pClient->Cached_dwRpcClientID, FALSE);
        pClient->Cached_dwRpcClientID = 0;
        pClient->Cached_hLC = NULL;
    }

    for (ULONG i = 0; i < MK_WSK_SEND_PIPELINE_SLOTS; i++)
    {
        if (pClient->fSendInFlight[i])
        {
            WskDrainPendingSend(pClient, i);
        }
    }

    PWSK_SOCKET SocketToClose = (PWSK_SOCKET)InterlockedExchangePointer((PVOID *)&pClient->Socket, NULL);
    if (SocketToClose)
    {
        WskSyncCloseSocket(UserVar, SocketToClose);
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
    for (ULONG i = 0; i < MK_WSK_SEND_PIPELINE_SLOTS; i++)
    {
        if (pClient->pFastSendMdl[i])
        {
            UserVar->Func.IoFreeMdl(pClient->pFastSendMdl[i]);
            pClient->pFastSendMdl[i] = NULL;
        }
    }

    if (pClient->pRecvIrp)
    {
        UserVar->Func.IoFreeIrp(pClient->pRecvIrp);
        pClient->pRecvIrp = NULL;
    }
    for (ULONG i = 0; i < MK_WSK_SEND_PIPELINE_SLOTS; i++)
    {
        if (pClient->pSendIrp[i])
        {
            UserVar->Func.IoFreeIrp(pClient->pSendIrp[i]);
            pClient->pSendIrp[i] = NULL;
        }
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
            PWSK_SOCKET s = (PWSK_SOCKET)InterlockedExchangePointer((PVOID *)&pClient->Socket, NULL);
            if (s && clientSocketCount < MK_WSK_MAX_CLIENTS)
            {
                clientSockets[clientSocketCount++] = s;
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
    ULONG waitLoops = 0;
    while (g_WskServer.ActiveClientCount > 0 && waitLoops < 200)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10 * 1000 * 10; // 10ms
        if (UserVar)
        {
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
        }
        waitLoops++;
    }
    if (g_WskServer.ActiveClientCount > 0)
    {
        DBG("WskServer_Stop: Warning, %d active clients still pending after timeout", g_WskServer.ActiveClientCount);
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
