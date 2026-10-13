#include "wsk_server.h"
#include "Common.h"
#include "rpc_dispatch.h"
#include "leechcore_kernel.h"

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

    WSK_SYNC_CONTEXT Sync;
    PIRP Irp = WskAllocateSyncIrp(UserVar, &Sync);
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
            UserVar->Func.IoFreeIrp(Irp);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        UserVar->Func.MmBuildMdlForNonPagedPool(WskBuf.Mdl);
        fCustomMdl = TRUE;
    }

    NTSTATUS Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskReceive(Socket, &WskBuf, 0, Irp);

    if (Status == STATUS_PENDING && UserVar)
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

    if (UserVar && Irp)
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







#if MK_WSK_USE_WORKER_POOL

static __forceinline PMK_WSK_WORK_ITEM WskPopFreeWorkItem(
    _In_ PMK_WSK_CLIENT pClient,
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    PMK_WSK_WORK_ITEM pItem = NULL;
    KIRQL OldIrql = 0;
    if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
        OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->ItemPoolLock);

    if (!IsListEmpty(&pClient->FreeItemHead))
    {
        PLIST_ENTRY pEntry = RemoveHeadList(&pClient->FreeItemHead);
        pItem = CONTAINING_RECORD(pEntry, MK_WSK_WORK_ITEM, ListEntry);
    }

    if (UserVar && UserVar->Func.KeReleaseSpinLock)
        UserVar->Func.KeReleaseSpinLock(&pClient->ItemPoolLock, OldIrql);

    return pItem;
}

// ============================================================================
// 方案 A: 异步合并响应队列冲刷引擎 (Coalescing Flush Responder)
// 1. 彻底消灭 SendMutex 同步等待网卡 IRP 的排队瓶颈，Worker 算完即走零阻塞
// 2. 采用原子 Try-Flush 机制，单线程批量收割已就绪响应并仅调用 1 次发送
// 3. 多核 100% 并发执行内存读取，回包多帧自动合并消除 TCP RTT 延迟
// ============================================================================
static VOID WskTryFlushResponses(_In_ PMK_WSK_CLIENT pClient, _In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!pClient || !UserVar)
    {
        return;
    }

    // 原子抢占冲刷执行权 (0 -> 1)
    if (InterlockedCompareExchange(&pClient->FlushActive, 1, 0) != 0)
    {
        // 已有线程正在冲刷，当前线程直接返回（该冲刷线程发完后会顺便带走新入队的所有响应）
        return;
    }

    while (!pClient->fTerminateWorkers && pClient->fActive)
    {
        LIST_ENTRY LocalBatch;
        InitializeListHead(&LocalBatch);

        // 步骤 1: 原子摘下当前 ResponseHead 中积压的所有响应（耗时 < 30 纳秒）
        KIRQL OldIrql = 0;
        if (UserVar->Func.KeAcquireSpinLockRaiseToDpc)
            OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->ResponseLock);

        if (!IsListEmpty(&pClient->ResponseHead))
        {
            LocalBatch.Flink = pClient->ResponseHead.Flink;
            LocalBatch.Blink = pClient->ResponseHead.Blink;
            LocalBatch.Flink->Blink = &LocalBatch;
            LocalBatch.Blink->Flink = &LocalBatch;
            InitializeListHead(&pClient->ResponseHead);
        }

        if (UserVar->Func.KeReleaseSpinLock)
            UserVar->Func.KeReleaseSpinLock(&pClient->ResponseLock, OldIrql);

        // 若队列已空，尝试退出冲刷状态
        if (IsListEmpty(&LocalBatch))
        {
            InterlockedExchange(&pClient->FlushActive, 0);

            // Double Check: 释放后瞬间是否有新项目刚好入队？
            BOOLEAN bHasMore = FALSE;
            if (UserVar->Func.KeAcquireSpinLockRaiseToDpc)
                OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->ResponseLock);
            bHasMore = !IsListEmpty(&pClient->ResponseHead);
            if (UserVar->Func.KeReleaseSpinLock)
                UserVar->Func.KeReleaseSpinLock(&pClient->ResponseLock, OldIrql);

            if (bHasMore)
            {
                // 若刚好有新项目入队且尚未有人处理，重新抢锁继续冲刷
                if (InterlockedCompareExchange(&pClient->FlushActive, 1, 0) == 0)
                {
                    continue;
                }
            }
            break;
        }

        // 步骤 2: 将 LocalBatch 中的所有响应合并推入 FastSendBuf
        ULONG cbSendTotal = 0;
        PLIST_ENTRY pEntry = LocalBatch.Flink;

        while (pEntry != &LocalBatch)
        {
            PMK_WSK_WORK_ITEM pItem = CONTAINING_RECORD(pEntry, MK_WSK_WORK_ITEM, ListEntry);
            pEntry = pEntry->Flink;

            PUCHAR pbSrc = pItem->pbLargeRsp ? pItem->pbLargeRsp : pItem->RspBuf;
            ULONG cbSrc = pItem->cbRspFrame;

            if (cbSrc > 0 && pbSrc)
            {
                // 如果当前 FastSendBuf 累积将超过容量上限，先冲刷已有数据
                if (cbSendTotal > 0 && (cbSendTotal + cbSrc > sizeof(pClient->FastSendBuf)))
                {
                    if (pClient->Socket && pClient->fActive)
                    {
                        WskSyncSendAll(pClient, pClient->Socket, pClient->FastSendBuf, cbSendTotal);
                    }
                    cbSendTotal = 0;
                }

                if (cbSrc <= sizeof(pClient->FastSendBuf))
                {
                    UserVar->Func.memcpy(pClient->FastSendBuf + cbSendTotal, pbSrc, cbSrc);
                    cbSendTotal += cbSrc;
                }
                else
                {
                    // 巨型超大帧（> 1MB）单独发送
                    if (pClient->Socket && pClient->fActive)
                    {
                        WskSyncSendAll(pClient, pClient->Socket, pbSrc, cbSrc);
                    }
                }
            }
        }

        // 步骤 3: ★★★ 仅调用 1 次发送，将整批合并的响应送入 TCP 协议栈 ★★★
        if (cbSendTotal > 0 && pClient->Socket && pClient->fActive)
        {
            WskSyncSendAll(pClient, pClient->Socket, pClient->FastSendBuf, cbSendTotal);
        }

        // 步骤 4: 发送完成后，统一批量归还整批 LocalBatch 中的 WorkItem 资源至 FreeItemHead (0 堆释放，仅 1 次自旋锁！)
        OldIrql = 0;
        if (UserVar->Func.KeAcquireSpinLockRaiseToDpc)
            OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->ItemPoolLock);

        while (!IsListEmpty(&LocalBatch))
        {
            pEntry = RemoveHeadList(&LocalBatch);
            PMK_WSK_WORK_ITEM pItem = CONTAINING_RECORD(pEntry, MK_WSK_WORK_ITEM, ListEntry);
            if (pItem->pbLargeRsp)
            {
                UserVar->Func.ExFreePoolWithTag(pItem->pbLargeRsp, MK_WSK_POOL_TAG);
                pItem->pbLargeRsp = NULL;
            }
            if (pItem->pbAllocatedFrame)
            {
                UserVar->Func.ExFreePoolWithTag(pItem->pbAllocatedFrame, MK_WSK_POOL_TAG);
                pItem->pbAllocatedFrame = NULL;
            }

            if (pItem >= &pClient->ItemPool[0] && pItem < &pClient->ItemPool[MK_WSK_WORK_ITEM_POOL_SIZE])
            {
                InsertTailList(&pClient->FreeItemHead, &pItem->ListEntry);
            }
            else
            {
                UserVar->Func.ExFreePoolWithTag(pItem, MK_WSK_POOL_TAG);
            }
        }

        if (UserVar->Func.KeReleaseSpinLock)
            UserVar->Func.KeReleaseSpinLock(&pClient->ItemPoolLock, OldIrql);
    }
}

static VOID WskSubWorkerThread(_In_ PVOID Context)
{
    PMK_WSK_WORKER pWorker = (PMK_WSK_WORKER)Context;
    if (!pWorker || !pWorker->Client || !pWorker->Client->Server)
    {
        return;
    }
    PMK_WSK_CLIENT pClient = pWorker->Client;
    MACHENIKE_KERNEL_INTERFACE *UserVar = pClient->Server->UserVar;

    while (!pClient->fTerminateWorkers && pClient->fActive)
    {
        PMK_WSK_WORK_ITEM pItem = NULL;
        KIRQL OldIrql = 0;

        if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
            OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->QueueLock);

        if (!IsListEmpty(&pClient->QueueHead))
        {
            PLIST_ENTRY pEntry = RemoveHeadList(&pClient->QueueHead);
            pItem = CONTAINING_RECORD(pEntry, MK_WSK_WORK_ITEM, ListEntry);
        }

        if (IsListEmpty(&pClient->QueueHead))
        {
            // 队列已取空，原子清除 NotificationEvent 信号
            if (UserVar && UserVar->Func.KeClearEvent)
                UserVar->Func.KeClearEvent(&pClient->QueueEvent);
        }

        if (UserVar && UserVar->Func.KeReleaseSpinLock)
            UserVar->Func.KeReleaseSpinLock(&pClient->QueueLock, OldIrql);

        if (!pItem)
        {
            LARGE_INTEGER Timeout;
            Timeout.QuadPart = -10 * 1000 * 50; // 50ms
            if (UserVar)
            {
                UserVar->Func.KeWaitForSingleObject(&pClient->QueueEvent, Executive, KernelMode, FALSE, &Timeout);
            }
            continue;
        }

        pItem->cbRspFrame = 0;
        pItem->pbLargeRsp = NULL;

        if (pItem->cbRpcDataRaw == 0)
        {
            // 响应空心跳或 0 载荷请求
            *(PULONG64)(pItem->RspBuf + 0) = WskSwapU64(4);
            *(PULONG)(pItem->RspBuf + 8) = pItem->RequestId;
            pItem->cbRspFrame = 12;
        }
        else
        {
            // 1. 原位解密载荷
            WskNngFastCrypt(pItem->pbRpcDataRaw, pItem->cbRpcDataRaw, pItem->Nonce);

            // 2. 检查 DirectOut 发送缓冲 (优先直写 pItem->RspBuf，512 字节空间)
            PUCHAR pbDirectTarget = pItem->RspBuf + 20;
            ULONG cbDirectAvail = sizeof(pItem->RspBuf) - 20;

            PUCHAR pbRspOut = NULL;
            ULONG cbRspOut = 0;
            NTSTATUS Status = MkRpc_DispatchCommandEx(
                pClient,
                pItem->pbRpcDataRaw,
                pItem->cbRpcDataRaw,
                &pbRspOut,
                &cbRspOut,
                pbDirectTarget,
                cbDirectAvail);

            if (NT_SUCCESS(Status) && pbRspOut && cbRspOut > 0)
            {
                ULONG RspFrameSize = 20 + cbRspOut;

                if (pbRspOut == pbDirectTarget)
                {
                    // ★★★ 命中 RspBuf DirectOut 原位直写：0 内存池分配、0 内存拷贝 ★★★
                    *(PULONG64)(pItem->RspBuf + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                    *(PULONG)(pItem->RspBuf + 8) = pItem->RequestId;
                    *(PULONG64)(pItem->RspBuf + 12) = pItem->Nonce;
                    WskNngFastCrypt(pbDirectTarget, cbRspOut, pItem->Nonce);
                    pItem->cbRspFrame = RspFrameSize;
                }
                else
                {
                    // 超大包或未命中 DirectOut
                    if (RspFrameSize <= sizeof(pItem->RspBuf))
                    {
                        *(PULONG64)(pItem->RspBuf + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                        *(PULONG)(pItem->RspBuf + 8) = pItem->RequestId;
                        *(PULONG64)(pItem->RspBuf + 12) = pItem->Nonce;
                        UserVar->Func.memcpy(pItem->RspBuf + 20, pbRspOut, cbRspOut);
                        WskNngFastCrypt(pItem->RspBuf + 20, cbRspOut, pItem->Nonce);
                        pItem->cbRspFrame = RspFrameSize;
                    }
                    else
                    {
                        PUCHAR pbSendBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, RspFrameSize, MK_WSK_POOL_TAG);
                        if (pbSendBuf)
                        {
                            *(PULONG64)(pbSendBuf + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                            *(PULONG)(pbSendBuf + 8) = pItem->RequestId;
                            *(PULONG64)(pbSendBuf + 12) = pItem->Nonce;
                            UserVar->Func.memcpy(pbSendBuf + 20, pbRspOut, cbRspOut);
                            WskNngFastCrypt(pbSendBuf + 20, cbRspOut, pItem->Nonce);
                            pItem->pbLargeRsp = pbSendBuf;
                            pItem->cbRspFrame = RspFrameSize;
                        }
                    }
                    UserVar->Func.ExFreePoolWithTag(pbRspOut, LC_POOL_TAG);
                }
            }
            else
            {
                *(PULONG64)(pItem->RspBuf + 0) = WskSwapU64(4);
                *(PULONG)(pItem->RspBuf + 8) = pItem->RequestId;
                pItem->cbRspFrame = 12;
            }
        }

        // 3. 将已生成响应的 pItem 挂入 ResponseHead (零阻塞入队，自旋锁持有耗时 < 20 纳秒)
        if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
            OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->ResponseLock);

        InsertTailList(&pClient->ResponseHead, &pItem->ListEntry);

        if (UserVar && UserVar->Func.KeReleaseSpinLock)
            UserVar->Func.KeReleaseSpinLock(&pClient->ResponseLock, OldIrql);

        // 4. ★★★ 非阻塞尝试批量合并冲刷 (Coalesced Flush) ★★★
        WskTryFlushResponses(pClient, UserVar);
    }

    InterlockedDecrement(&pClient->ActiveWorkerCount);
    if (UserVar)
    {
        UserVar->Func.PsTerminateSystemThread(STATUS_SUCCESS);
    }
}

static VOID WskStartWorkerPool(_In_ PMK_WSK_CLIENT pClient)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = pClient->Server->UserVar;
    if (UserVar && UserVar->Func.KeInitializeSpinLock)
    {
        UserVar->Func.KeInitializeSpinLock(&pClient->QueueLock);
        UserVar->Func.KeInitializeSpinLock(&pClient->ResponseLock);
        UserVar->Func.KeInitializeSpinLock(&pClient->ItemPoolLock);
    }
    if (UserVar && UserVar->Func.KeInitializeMutex)
    {
        UserVar->Func.KeInitializeMutex(&pClient->SendMutex, 0);
    }
    InitializeListHead(&pClient->QueueHead);
    InitializeListHead(&pClient->ResponseHead);
    InitializeListHead(&pClient->FreeItemHead);
    pClient->FlushActive = 0;

    // 预填充静态工作项对象池 (彻底抹杀热路径 16000 次 ExAllocatePool/Free)
    for (ULONG i = 0; i < MK_WSK_WORK_ITEM_POOL_SIZE; i++)
    {
        pClient->ItemPool[i].pbAllocatedFrame = NULL;
        pClient->ItemPool[i].pbLargeRsp = NULL;
        pClient->ItemPool[i].cbRspFrame = 0;
        InsertTailList(&pClient->FreeItemHead, &pClient->ItemPool[i].ListEntry);
    }

    if (UserVar && UserVar->Func.KeInitializeEvent)
    {
        UserVar->Func.KeInitializeEvent(&pClient->QueueEvent, NotificationEvent, FALSE);
    }
    pClient->fTerminateWorkers = FALSE;
    pClient->ActiveWorkerCount = 0;

    POBJECT_TYPE pThreadType = (UserVar && UserVar->Func.pPsThreadType) ? *UserVar->Func.pPsThreadType : NULL;
    for (ULONG i = 0; i < MK_WSK_WORKER_COUNT; i++)
    {
        pClient->Workers[i].Client = pClient;
        pClient->Workers[i].WorkerId = i + 1;
        pClient->Workers[i].hThread = NULL;
        pClient->Workers[i].pThread = NULL;
        pClient->Workers[i].SendBuf = NULL;
        pClient->Workers[i].pSendMdl = NULL;

        if (UserVar && UserVar->Func.ExAllocatePoolWithTag && UserVar->Func.IoAllocateMdl && UserVar->Func.MmBuildMdlForNonPagedPool)
        {
            pClient->Workers[i].SendBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, MK_WSK_WORKER_BUF_SIZE, MK_WSK_POOL_TAG);
            if (pClient->Workers[i].SendBuf)
            {
                pClient->Workers[i].pSendMdl = UserVar->Func.IoAllocateMdl(pClient->Workers[i].SendBuf, MK_WSK_WORKER_BUF_SIZE, FALSE, FALSE, NULL);
                if (pClient->Workers[i].pSendMdl)
                {
                    UserVar->Func.MmBuildMdlForNonPagedPool(pClient->Workers[i].pSendMdl);
                }
            }
        }

        NTSTATUS Status = UserVar->Func.PsCreateSystemThread(
            &pClient->Workers[i].hThread,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            WskSubWorkerThread,
            &pClient->Workers[i]);

        if (NT_SUCCESS(Status))
        {
            InterlockedIncrement(&pClient->ActiveWorkerCount);
            if (UserVar && UserVar->Func.ObReferenceObjectByHandle)
            {
                UserVar->Func.ObReferenceObjectByHandle(
                    pClient->Workers[i].hThread,
                    THREAD_ALL_ACCESS,
                    pThreadType,
                    KernelMode,
                    (PVOID *)&pClient->Workers[i].pThread,
                    NULL);
            }
        }
    }
    DBG("WskStartWorkerPool: Started %d worker threads for ClientId=%u", pClient->ActiveWorkerCount, pClient->ClientId);
}

static VOID WskStopWorkerPool(_In_ PMK_WSK_CLIENT pClient)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = pClient->Server ? pClient->Server->UserVar : g_WskServer.UserVar;
    pClient->fTerminateWorkers = TRUE;

    if (UserVar && UserVar->Func.KeSetEvent)
    {
        UserVar->Func.KeSetEvent(&pClient->QueueEvent, IO_NO_INCREMENT, FALSE);
    }

    for (ULONG i = 0; i < MK_WSK_WORKER_COUNT; i++)
    {
        if (pClient->Workers[i].pThread)
        {
            if (UserVar && UserVar->Func.KeWaitForSingleObject)
            {
                UserVar->Func.KeWaitForSingleObject(pClient->Workers[i].pThread, Executive, KernelMode, FALSE, NULL);
            }
            if (UserVar && UserVar->Func.ObfDereferenceObject)
            {
                UserVar->Func.ObfDereferenceObject(pClient->Workers[i].pThread);
            }
            pClient->Workers[i].pThread = NULL;
        }
        if (pClient->Workers[i].hThread)
        {
            if (UserVar && UserVar->Func.ZwClose)
            {
                UserVar->Func.ZwClose(pClient->Workers[i].hThread);
            }
            pClient->Workers[i].hThread = NULL;
        }
        if (pClient->Workers[i].pSendMdl && UserVar && UserVar->Func.IoFreeMdl)
        {
            UserVar->Func.IoFreeMdl(pClient->Workers[i].pSendMdl);
            pClient->Workers[i].pSendMdl = NULL;
        }
        if (pClient->Workers[i].SendBuf && UserVar && UserVar->Func.ExFreePoolWithTag)
        {
            UserVar->Func.ExFreePoolWithTag(pClient->Workers[i].SendBuf, MK_WSK_POOL_TAG);
            pClient->Workers[i].SendBuf = NULL;
        }
    }

    KIRQL OldIrql = 0;
    if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
        OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->QueueLock);

    while (!IsListEmpty(&pClient->QueueHead))
    {
        PLIST_ENTRY pEntry = RemoveHeadList(&pClient->QueueHead);
        PMK_WSK_WORK_ITEM pItem = CONTAINING_RECORD(pEntry, MK_WSK_WORK_ITEM, ListEntry);
        if (pItem->pbAllocatedFrame && UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pItem->pbAllocatedFrame, MK_WSK_POOL_TAG);
            pItem->pbAllocatedFrame = NULL;
        }
        if (!(pItem >= &pClient->ItemPool[0] && pItem < &pClient->ItemPool[MK_WSK_WORK_ITEM_POOL_SIZE]))
        {
            if (UserVar)
                UserVar->Func.ExFreePoolWithTag(pItem, MK_WSK_POOL_TAG);
        }
    }

    if (UserVar && UserVar->Func.KeReleaseSpinLock)
        UserVar->Func.KeReleaseSpinLock(&pClient->QueueLock, OldIrql);

    // 清理 ResponseHead 中未发送的残留响应
    if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
        OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->ResponseLock);

    while (!IsListEmpty(&pClient->ResponseHead))
    {
        PLIST_ENTRY pEntry = RemoveHeadList(&pClient->ResponseHead);
        PMK_WSK_WORK_ITEM pItem = CONTAINING_RECORD(pEntry, MK_WSK_WORK_ITEM, ListEntry);
        if (pItem->pbLargeRsp && UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pItem->pbLargeRsp, MK_WSK_POOL_TAG);
            pItem->pbLargeRsp = NULL;
        }
        if (pItem->pbAllocatedFrame && UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pItem->pbAllocatedFrame, MK_WSK_POOL_TAG);
            pItem->pbAllocatedFrame = NULL;
        }
        if (!(pItem >= &pClient->ItemPool[0] && pItem < &pClient->ItemPool[MK_WSK_WORK_ITEM_POOL_SIZE]))
        {
            if (UserVar)
                UserVar->Func.ExFreePoolWithTag(pItem, MK_WSK_POOL_TAG);
        }
    }

    if (UserVar && UserVar->Func.KeReleaseSpinLock)
        UserVar->Func.KeReleaseSpinLock(&pClient->ResponseLock, OldIrql);

    // 清理可能动态分配的残留缓冲
    for (ULONG i = 0; i < MK_WSK_WORK_ITEM_POOL_SIZE; i++)
    {
        if (pClient->ItemPool[i].pbLargeRsp && UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pClient->ItemPool[i].pbLargeRsp, MK_WSK_POOL_TAG);
            pClient->ItemPool[i].pbLargeRsp = NULL;
        }
        if (pClient->ItemPool[i].pbAllocatedFrame && UserVar)
        {
            UserVar->Func.ExFreePoolWithTag(pClient->ItemPool[i].pbAllocatedFrame, MK_WSK_POOL_TAG);
            pClient->ItemPool[i].pbAllocatedFrame = NULL;
        }
    }

    DBG("WskStopWorkerPool: All worker threads stopped successfully for ClientId=%u", pClient->ClientId);
}

#endif

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

    // 保证 WSK 协议栈纯净性：统一走稳定原生的 WskAllocateSyncIrp 同步 IRP 流程，避免 IoReuseIrp 底层状态残留
    pClient->pRecvIrp = NULL;
    pClient->pSendIrp = NULL;
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
#if MK_WSK_USE_WORKER_POOL
        WskStartWorkerPool(pClient);
#endif
    }
    else
    {
        DBG("WskClientWorkerThread [ClientId=%u]: Non-NNG connection, falling back to raw TCP",
            pClient->ClientId);
    }

    ULONG cbBuffered = 0;

    while (g_WskServer.fRunning && pClient->fActive)
    {
        if (fIsNng)
        {
            // 步骤 1: 确保至少接收到 12 字节的 NNG 帧头
            while (cbBuffered < 12)
            {
                ULONG cbRecvThisTime = 0;
                Status = WskSyncReceive(pClient, pClient->Socket,
                                        pClient->FastRecvBuf + cbBuffered,
                                        (ULONG)(sizeof(pClient->FastRecvBuf) - cbBuffered),
                                        &cbRecvThisTime);
                if (!NT_SUCCESS(Status) || cbRecvThisTime == 0)
                {
                    DBG("WskClientWorkerThread [ClientId=%u]: Header Recv failed/closed (Status=0x%08X, cbRecv=%u, Line=%d)",
                        pClient->ClientId, Status, cbRecvThisTime, __LINE__);
                    goto Cleanup;
                }
                cbBuffered += cbRecvThisTime;
            }

            ULONG64 TotalLen = WskSwapU64(*(PULONG64)(pClient->FastRecvBuf + 0));
            if (TotalLen < 4 || TotalLen > (64 * 1024 * 1024))
            {
                DBG("WskClientWorkerThread [ClientId=%u]: Invalid NNG total length (%llu, Line=%d)",
                    pClient->ClientId, TotalLen, __LINE__);
                break;
            }

            ULONG RequestId = *(PULONG)(pClient->FastRecvBuf + 8);
            ULONG cbPayload = (ULONG)(TotalLen - 4);
            ULONG64 FrameSize = 8 + TotalLen;

            // 步骤 2: 确保至少第 1 个帧完整收全
            if (FrameSize <= sizeof(pClient->FastRecvBuf))
            {
                while (cbBuffered < FrameSize)
                {
                    ULONG cbRecvThisTime = 0;
                    Status = WskSyncReceive(pClient, pClient->Socket,
                                            pClient->FastRecvBuf + cbBuffered,
                                            (ULONG)(sizeof(pClient->FastRecvBuf) - cbBuffered),
                                            &cbRecvThisTime);
                    if (!NT_SUCCESS(Status) || cbRecvThisTime == 0)
                    {
                        DBG("WskClientWorkerThread [ClientId=%u]: Body Recv failed/closed (Status=0x%08X, cbRecv=%u, Line=%d)",
                            pClient->ClientId, Status, cbRecvThisTime, __LINE__);
                        goto Cleanup;
                    }
                    cbBuffered += cbRecvThisTime;
                }
            }
            else
            {
                // 超大包 (> 256KB) 独立动态分配接收处理
                PUCHAR pbLargeFrame = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)FrameSize, MK_WSK_POOL_TAG);
                if (!pbLargeFrame)
                {
                    DBG("WskClientWorkerThread [ClientId=%u]: Failed to allocate large frame (%llu bytes)",
                        pClient->ClientId, FrameSize);
                    break;
                }
                UserVar->Func.memcpy(pbLargeFrame, pClient->FastRecvBuf, cbBuffered);
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
                cbBuffered = 0;
                continue;
            }

#if MK_WSK_USE_WORKER_POOL
            // 步骤 3 (多工作线程并发模式): 将 FastRecvBuf 中所有已完整收齐的帧打包为 WorkItem 入队，由 Worker 线程池并发执行与发送
            ULONG cbOffset = 0;
            LIST_ENTRY LocalBatch;
            InitializeListHead(&LocalBatch);
            ULONG cBatchItems = 0;

            while ((cbBuffered - cbOffset) >= 12)
            {
                ULONG64 CurTotalLen = WskSwapU64(*(PULONG64)(pClient->FastRecvBuf + cbOffset + 0));
                if (CurTotalLen < 4 || CurTotalLen > (64 * 1024 * 1024))
                {
                    break;
                }
                ULONG64 CurFrameSize = 8 + CurTotalLen;
                if ((cbBuffered - cbOffset) < CurFrameSize)
                {
                    // 当前尾部帧尚未完整到达，退出批处理，留至下一轮接收
                    break;
                }

                ULONG CurRequestId = *(PULONG)(pClient->FastRecvBuf + cbOffset + 8);
                ULONG CurPayload = (ULONG)(CurTotalLen - 4);

                // 优先从预分配对象池弹取空闲槽位 (0 堆分配、耗时 5 纳秒！)
                PMK_WSK_WORK_ITEM pItem = WskPopFreeWorkItem(pClient, UserVar);
                if (!pItem)
                {
                    // 若并发极端打满 64 槽位，退避动态分配
                    pItem = (PMK_WSK_WORK_ITEM)UserVar->Func.ExAllocatePoolWithTag(
                        NonPagedPoolNx, sizeof(MK_WSK_WORK_ITEM), MK_WSK_POOL_TAG);
                }

                if (pItem)
                {
                    pItem->RequestId = CurRequestId;
                    pItem->pbAllocatedFrame = NULL;
                    pItem->cbRspFrame = 0;
                    pItem->pbLargeRsp = NULL;

                    PUCHAR pbFrameDst = NULL;
                    if (CurFrameSize <= sizeof(pItem->ReqBuf))
                    {
                        pbFrameDst = pItem->ReqBuf;
                    }
                    else
                    {
                        pbFrameDst = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)CurFrameSize, MK_WSK_POOL_TAG);
                        pItem->pbAllocatedFrame = pbFrameDst;
                    }

                    if (pbFrameDst)
                    {
                        UserVar->Func.memcpy(pbFrameDst, pClient->FastRecvBuf + cbOffset, (size_t)CurFrameSize);

                        if (CurPayload > 8)
                        {
                            pItem->Nonce = *(PULONG64)(pbFrameDst + 12);
                            pItem->pbRpcDataRaw = pbFrameDst + 20;
                            pItem->cbRpcDataRaw = CurPayload - 8;
                        }
                        else
                        {
                            pItem->Nonce = 0;
                            pItem->pbRpcDataRaw = NULL;
                            pItem->cbRpcDataRaw = 0;
                        }

                        InsertTailList(&LocalBatch, &pItem->ListEntry);
                        cBatchItems++;
                    }
                    else
                    {
                        // 动态分配失败归还
                        if (pItem >= &pClient->ItemPool[0] && pItem < &pClient->ItemPool[MK_WSK_WORK_ITEM_POOL_SIZE])
                        {
                            KIRQL OldIrql = 0;
                            if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
                                OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->ItemPoolLock);
                            InsertTailList(&pClient->FreeItemHead, &pItem->ListEntry);
                            if (UserVar && UserVar->Func.KeReleaseSpinLock)
                                UserVar->Func.KeReleaseSpinLock(&pClient->ItemPoolLock, OldIrql);
                        }
                        else
                        {
                            UserVar->Func.ExFreePoolWithTag(pItem, MK_WSK_POOL_TAG);
                        }
                    }
                }

                cbOffset += (ULONG)CurFrameSize;
            }

            // ★★★ 仅获取 1 次自旋锁，将整批就绪帧一次性挂入 QueueHead 尾部！★★★
            if (cBatchItems > 0)
            {
                KIRQL OldIrql = 0;
                if (UserVar && UserVar->Func.KeAcquireSpinLockRaiseToDpc)
                    OldIrql = UserVar->Func.KeAcquireSpinLockRaiseToDpc(&pClient->QueueLock);

                LocalBatch.Flink->Blink = pClient->QueueHead.Blink;
                pClient->QueueHead.Blink->Flink = LocalBatch.Flink;
                LocalBatch.Blink->Flink = &pClient->QueueHead;
                pClient->QueueHead.Blink = LocalBatch.Blink;

                if (UserVar && UserVar->Func.KeReleaseSpinLock)
                    UserVar->Func.KeReleaseSpinLock(&pClient->QueueLock, OldIrql);

                // 仅调用 1 次广播唤醒 Worker 线程池！
                if (UserVar && UserVar->Func.KeSetEvent)
                    UserVar->Func.KeSetEvent(&pClient->QueueEvent, IO_NO_INCREMENT, FALSE);
            }

            // 安全滑动窗口：将未消费的残余字节安全移回 0 偏移
            ULONG cbRemaining = cbBuffered - cbOffset;
            if (cbRemaining > 0 && cbOffset > 0)
            {
                UserVar->Func.memmove(pClient->FastRecvBuf, pClient->FastRecvBuf + cbOffset, cbRemaining);
            }
            cbBuffered = cbRemaining;

            // 顺便尝试一次合并冲刷，消灭队列滞留
            WskTryFlushResponses(pClient, UserVar);

#else
            // 步骤 3: ★★★ 贪婪批处理循环 —— 连续收割 FastRecvBuf 中所有已就绪的完整帧 ★★★
            ULONG cbOffset = 0;
            ULONG cbSendTotal = 0;

            while ((cbBuffered - cbOffset) >= 12)
            {
                ULONG64 CurTotalLen = WskSwapU64(*(PULONG64)(pClient->FastRecvBuf + cbOffset + 0));
                if (CurTotalLen < 4 || CurTotalLen > (64 * 1024 * 1024))
                {
                    break;
                }
                ULONG64 CurFrameSize = 8 + CurTotalLen;
                if ((cbBuffered - cbOffset) < CurFrameSize)
                {
                    // 当前尾部帧尚未完整到达，退出批处理，留至下一轮接收
                    break;
                }

                ULONG CurRequestId = *(PULONG)(pClient->FastRecvBuf + cbOffset + 8);
                ULONG CurPayload = (ULONG)(CurTotalLen - 4);
                PUCHAR pbPayloadRaw = pClient->FastRecvBuf + cbOffset + 12;

                if (CurPayload == 0 || CurPayload <= 8)
                {
                    if (cbSendTotal + 12 <= sizeof(pClient->FastSendBuf))
                    {
                        PUCHAR pRsp = pClient->FastSendBuf + cbSendTotal;
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

                    // 步骤 3.1: 计算 FastSendBuf 剩余可用空间 (DirectOut 零拷贝通道)
                    ULONG cbDirectAvail = 0;
                    PUCHAR pbDirectTarget = NULL;
                    if (cbSendTotal + 20 < sizeof(pClient->FastSendBuf))
                    {
                        pbDirectTarget = pClient->FastSendBuf + cbSendTotal + 20;
                        cbDirectAvail = (ULONG)(sizeof(pClient->FastSendBuf) - (cbSendTotal + 20));
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
                            // 数据已原位直接写入 FastSendBuf，无需分配池内存或二次 memcpy！
                            PUCHAR pRsp = pClient->FastSendBuf + cbSendTotal;
                            *(PULONG64)(pRsp + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                            *(PULONG)(pRsp + 8) = CurRequestId;
                            *(PULONG64)(pRsp + 12) = qwNonce;
                            WskNngFastCrypt(pbDirectTarget, cbRspOut, qwNonce);
                            cbSendTotal += RspFrameSize;
                        }
                        else
                        {
                            // Fallback：未命中 DirectOut (如大包或剩余空间不足时由分发器独立分配的非分页内存)
                            if (cbSendTotal + RspFrameSize <= sizeof(pClient->FastSendBuf))
                            {
                                PUCHAR pRsp = pClient->FastSendBuf + cbSendTotal;
                                *(PULONG64)(pRsp + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                                *(PULONG)(pRsp + 8) = CurRequestId;
                                *(PULONG64)(pRsp + 12) = qwNonce;
                                UserVar->Func.memcpy(pRsp + 20, pbRspOut, cbRspOut);
                                WskNngFastCrypt(pRsp + 20, cbRspOut, qwNonce);
                                cbSendTotal += RspFrameSize;
                            }
                            else
                            {
                                // 若当前批处理缓冲区已满，先冲刷已积攒的批次数据
                                if (cbSendTotal > 0)
                                {
                                    Status = WskSyncSendAll(pClient, pClient->Socket, pClient->FastSendBuf, cbSendTotal);
                                    cbSendTotal = 0;
                                    if (!NT_SUCCESS(Status))
                                    {
                                        UserVar->Func.ExFreePoolWithTag(pbRspOut, LC_POOL_TAG);
                                        goto Cleanup;
                                    }
                                }

                                if (RspFrameSize <= sizeof(pClient->FastSendBuf))
                                {
                                    // 冲刷后 FastSendBuf 已清空，直接写入 FastSendBuf 头部，杜绝大池动态分配！
                                    PUCHAR pRsp = pClient->FastSendBuf;
                                    *(PULONG64)(pRsp + 0) = WskSwapU64((ULONG64)(4 + 8 + cbRspOut));
                                    *(PULONG)(pRsp + 8) = CurRequestId;
                                    *(PULONG64)(pRsp + 12) = qwNonce;
                                    UserVar->Func.memcpy(pRsp + 20, pbRspOut, cbRspOut);
                                    WskNngFastCrypt(pRsp + 20, cbRspOut, qwNonce);
                                    cbSendTotal = RspFrameSize;
                                }
                                else
                                {
                                    // 仅当单帧体积超过 1MB 物理上限时，才真正回退到大包动态分配
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
                        if (cbSendTotal + 12 <= sizeof(pClient->FastSendBuf))
                        {
                            PUCHAR pRsp = pClient->FastSendBuf + cbSendTotal;
                            *(PULONG64)pRsp = WskSwapU64(4);
                            *(PULONG)(pRsp + 8) = CurRequestId;
                            cbSendTotal += 12;
                        }
                    }
                }

                cbOffset += (ULONG)CurFrameSize;
            }

            // 步骤 4: ★★★ 一次性合并冲刷已累积的全部响应帧 (Coalesced Flush) ★★★
            if (cbSendTotal > 0)
            {
                Status = WskSyncSendAll(pClient, pClient->Socket, pClient->FastSendBuf, cbSendTotal);
                if (!NT_SUCCESS(Status))
                {
                    DBG("WskClientWorkerThread [ClientId=%u]: Coalesced Send failed (Status=0x%08X)", pClient->ClientId, Status);
                    goto Cleanup;
                }
            }

            // 步骤 5: ★★★ 安全滑动窗口：将未消费的残余字节安全移回 0 偏移，永远不产生 Length=0 假死 ★★★
            ULONG cbRemaining = cbBuffered - cbOffset;
            if (cbRemaining > 0 && cbOffset > 0)
            {
                UserVar->Func.memmove(pClient->FastRecvBuf, pClient->FastRecvBuf + cbOffset, cbRemaining);
            }
            cbBuffered = cbRemaining;
#endif
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

#if MK_WSK_USE_WORKER_POOL
    WskStopWorkerPool(pClient);
#endif

    if (pClient->Cached_dwRpcClientID != 0)
    {
        LeechRPC_LcHandle_Close(pClient->Cached_dwRpcClientID, FALSE);
        pClient->Cached_dwRpcClientID = 0;
        pClient->Cached_hLC = NULL;
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
