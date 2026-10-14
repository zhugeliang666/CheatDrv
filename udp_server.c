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
    PKEVENT pEvent;
    KEVENT LocalEvent;
} UDP_SYNC_CONTEXT, *PUDP_SYNC_CONTEXT;

static NTSTATUS UdpSyncCompletionRoutine(_In_ PDEVICE_OBJECT Reserved, _In_ PIRP Irp, _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    PUDP_SYNC_CONTEXT pSync = (PUDP_SYNC_CONTEXT)Context;
    if (pSync && pSync->UserVar && pSync->pEvent)
    {
        pSync->UserVar->Func.KeSetEvent(pSync->pEvent, IO_NO_INCREMENT, FALSE);
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
    pSync->pEvent = &pSync->LocalEvent;
    UserVar->Func.KeInitializeEvent(&pSync->LocalEvent, SynchronizationEvent, FALSE);
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

static PIRP UdpPreparePersistentIrp(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PIRP Irp,
    _In_ PKEVENT pEvent,
    _Out_ PUDP_SYNC_CONTEXT pSync)
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
    IoSetCompletionRoutine(Irp, UdpSyncCompletionRoutine, pSync, TRUE, TRUE, TRUE);
    return Irp;
}

static NTSTATUS UdpWaitForPersistentIrp(
    _In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PIRP Irp,
    _Inout_ PUDP_SYNC_CONTEXT pSync,
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
        PIRP RecvIrp = g_UdpServer.pRecvIrp ?
            UdpPreparePersistentIrp(UserVar, g_UdpServer.pRecvIrp, &g_UdpServer.RecvEvent, &RecvSync) :
            UdpAllocateSyncIrp(UserVar, &RecvSync);

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
        if (g_UdpServer.pRecvIrp)
        {
            status = UdpWaitForPersistentIrp(UserVar, RecvIrp, &RecvSync, status, &BytesReceived);
        }
        else
        {
            status = UdpWaitForIrp(UserVar, RecvIrp, &RecvSync, status, &BytesReceived);
        }

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

        // ★★★ 核心升级：多帧流水线连续收割循环，支持单数据报内聚合的多个请求帧 ★★★
        ULONG cbRecvOffset = 0;
        ULONG cbSendTotal = 0;

        while ((BytesReceived - cbRecvOffset) >= UDP_SERVER_HEADER_SIZE)
        {
            ULONG64 qwReqNonce = *(PULONG64)(g_UdpServer.pRecvBuf + cbRecvOffset + 0);
            ULONG cbPayload = *(PULONG)(g_UdpServer.pRecvBuf + cbRecvOffset + 8);

            if (cbPayload < sizeof(LEECHRPC_MSG_HDR) || (cbRecvOffset + UDP_SERVER_HEADER_SIZE + cbPayload) > (ULONG)BytesReceived)
            {
                break;
            }

            PUCHAR pbPayload = g_UdpServer.pRecvBuf + cbRecvOffset + UDP_SERVER_HEADER_SIZE;
            UdpNngFastCrypt(pbPayload, cbPayload, qwReqNonce);

            PLEECHRPC_MSG_HDR pHdr = (PLEECHRPC_MSG_HDR)pbPayload;
            if (pHdr->dwMagic != LEECHRPC_MSGMAGIC)
            {
                cbRecvOffset += (UDP_SERVER_HEADER_SIZE + cbPayload);
                continue;
            }

            PUCHAR pbCurSendSlot = g_UdpServer.pSendBuf + cbSendTotal;
            PUCHAR pbCurDirectOut = pbCurSendSlot + UDP_SERVER_HEADER_SIZE;
            ULONG cbDirectOutAvail = (cbSendTotal + UDP_SERVER_HEADER_SIZE < MK_UDP_SERVER_MAX_PACKET_SIZE) ?
                                     (MK_UDP_SERVER_MAX_PACKET_SIZE - (cbSendTotal + UDP_SERVER_HEADER_SIZE)) : 0;

            PUCHAR pbRsp = NULL;
            ULONG cbRsp = 0;

            status = MkRpc_DispatchCommandEx(&g_UdpServer.TransportCtx, pbPayload, pHdr->cbMsg, &pbRsp, &cbRsp, pbCurDirectOut, cbDirectOutAvail);

            if (NT_SUCCESS(status) && pbRsp && cbRsp > 0)
            {
                ULONG64 qwRspNonce = qwReqNonce; // 严格回传请求 Nonce，杜绝重传迟到包 ABA 串包错位
                ULONG cbCurFrameTotal = UDP_SERVER_HEADER_SIZE + cbRsp;

                if (pbRsp == pbCurDirectOut)
                {
                    *(PULONG64)(pbCurSendSlot + 0) = qwRspNonce;
                    *(PULONG)(pbCurSendSlot + 8) = cbRsp;
                    UdpNngFastCrypt(pbCurSendSlot + UDP_SERVER_HEADER_SIZE, cbRsp, qwRspNonce);
                    cbSendTotal += cbCurFrameTotal;
                }
                else
                {
                    if (cbSendTotal + cbCurFrameTotal <= MK_UDP_SERVER_MAX_PACKET_SIZE)
                    {
                        *(PULONG64)(pbCurSendSlot + 0) = qwRspNonce;
                        *(PULONG)(pbCurSendSlot + 8) = cbRsp;
                        UserVar->Func.RtlCopyMemory(pbCurSendSlot + UDP_SERVER_HEADER_SIZE, pbRsp, cbRsp);
                        UdpNngFastCrypt(pbCurSendSlot + UDP_SERVER_HEADER_SIZE, cbRsp, qwRspNonce);
                        cbSendTotal += cbCurFrameTotal;
                    }
                    UserVar->Func.ExFreePoolWithTag(pbRsp, LC_POOL_TAG);
                }
            }

            cbRecvOffset += (UDP_SERVER_HEADER_SIZE + cbPayload);
        }

        // 处理完所有收割的帧后统一发送
        if (cbSendTotal > 0)
        {
            if (cbSendTotal <= MK_UDP_SAFE_MTU_PAYLOAD)
            {
                // 安全 MTU 范围以内的常规报文或聚合小包，直接单包合并回传
                WSK_BUF SendWskBuf;
                SendWskBuf.Offset = 0;
                SendWskBuf.Length = cbSendTotal;
                SendWskBuf.Mdl = g_UdpServer.pSendMdl;

                UDP_SYNC_CONTEXT SendSync;
                PIRP SendIrp = g_UdpServer.pSendIrp ?
                    UdpPreparePersistentIrp(UserVar, g_UdpServer.pSendIrp, &g_UdpServer.SendEvent, &SendSync) :
                    UdpAllocateSyncIrp(UserVar, &SendSync);

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

                    if (g_UdpServer.pSendIrp)
                        sendStatus = UdpWaitForPersistentIrp(UserVar, SendIrp, &SendSync, sendStatus, NULL);
                    else
                        sendStatus = UdpWaitForIrp(UserVar, SendIrp, &SendSync, sendStatus, NULL);
                    UNREFERENCED_PARAMETER(sendStatus);
                }
            }
            else if (cbSendTotal <= MK_UDP_SERVER_MAX_PACKET_SIZE)
            {
                // 超大单帧响应（如散列读跨页扫描）：切片为 MTU 友好型 UDP 小包，杜绝 IP 分片丢包
                // ★★★ 优化：复用初始化时常驻预分配的 pSliceBuf 与 pSliceMdl，彻底消除高频池申请与 MDL 分配开销 ★★★
                const ULONG cbMaxSlicePayload = MK_UDP_SAFE_MTU_PAYLOAD - sizeof(MK_UDP_SLICE_HDR);
                USHORT totalSlices = (USHORT)((cbSendTotal + cbMaxSlicePayload - 1) / cbMaxSlicePayload);
                PUCHAR pSliceBuf = g_UdpServer.pSliceBuf;
                PMDL pSliceMdl = g_UdpServer.pSliceMdl;

                if (pSliceBuf && pSliceMdl)
                {
                    ULONG cbSentSoFar = 0;
                    ULONG64 qwFirstNonce = *(PULONG64)(g_UdpServer.pSendBuf + 0);
                    ULONG dwSeq = (ULONG)(qwFirstNonce ^ (qwFirstNonce >> 32));

                    for (USHORT sliceIdx = 0; sliceIdx < totalSlices && g_UdpServer.fRunning; sliceIdx++)
                    {
                        ULONG cbCurSliceData = min(cbSendTotal - cbSentSoFar, cbMaxSlicePayload);
                        PMK_UDP_SLICE_HDR pSliceHdr = (PMK_UDP_SLICE_HDR)pSliceBuf;
                        pSliceHdr->dwMagic = MK_UDP_SLICE_MAGIC;
                        pSliceHdr->dwSequence = dwSeq;
                        pSliceHdr->SliceIndex = sliceIdx;
                        pSliceHdr->TotalSlices = totalSlices;
                        pSliceHdr->cbOriginalTotal = cbSendTotal;
                        pSliceHdr->cbSliceData = cbCurSliceData;

                        UserVar->Func.RtlCopyMemory(pSliceBuf + sizeof(MK_UDP_SLICE_HDR),
                                                   g_UdpServer.pSendBuf + cbSentSoFar,
                                                   cbCurSliceData);

                        ULONG cbPacketSize = (ULONG)(sizeof(MK_UDP_SLICE_HDR) + cbCurSliceData);
                        WSK_BUF SliceWskBuf;
                        SliceWskBuf.Offset = 0;
                        SliceWskBuf.Length = cbPacketSize;
                        SliceWskBuf.Mdl = pSliceMdl;

                        UDP_SYNC_CONTEXT SliceSync;
                        PIRP SliceIrp = g_UdpServer.pSendIrp ?
                            UdpPreparePersistentIrp(UserVar, g_UdpServer.pSendIrp, &g_UdpServer.SendEvent, &SliceSync) :
                            UdpAllocateSyncIrp(UserVar, &SliceSync);

                        if (SliceIrp)
                        {
                            NTSTATUS sliceStatus = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)g_UdpServer.pSocket->Dispatch)->WskSendTo(
                                g_UdpServer.pSocket,
                                &SliceWskBuf,
                                0,
                                (PSOCKADDR)&RemoteAddr,
                                0,
                                NULL,
                                SliceIrp);

                            if (g_UdpServer.pSendIrp)
                                sliceStatus = UdpWaitForPersistentIrp(UserVar, SliceIrp, &SliceSync, sliceStatus, NULL);
                            else
                                sliceStatus = UdpWaitForIrp(UserVar, SliceIrp, &SliceSync, sliceStatus, NULL);
                            UNREFERENCED_PARAMETER(sliceStatus);
                        }
                        cbSentSoFar += cbCurSliceData;
                    }
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

        if (!UserVar || !UserVar->Func.WskRegister)
        {
            DBG("UdpServer_Init: WskRegister function pointer is NULL");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        NTSTATUS regStatus = UserVar->Func.WskRegister(&ClientNpi, &g_UdpServer.Registration);
        if (!NT_SUCCESS(regStatus))
        {
            DBG("UdpServer_Init: WskRegister failed, status=0x%08X", regStatus);
            return regStatus;
        }
        g_UdpServer.fRegistered = TRUE;

        if (!UserVar->Func.WskCaptureProviderNPI)
        {
            DBG("UdpServer_Init: WskCaptureProviderNPI function pointer is NULL");
            if (UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&g_UdpServer.Registration);
            }
            g_UdpServer.fRegistered = FALSE;
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        regStatus = UserVar->Func.WskCaptureProviderNPI(&g_UdpServer.Registration, WSK_INFINITE_WAIT, &g_UdpServer.ProviderNpi);
        if (!NT_SUCCESS(regStatus))
        {
            if (UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&g_UdpServer.Registration);
            }
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

    UserVar->Func.MmBuildMdlForNonPagedPool(g_UdpServer.pRecvMdl);
    UserVar->Func.MmBuildMdlForNonPagedPool(g_UdpServer.pSendMdl);

    // ★★★ 常驻分片发送缓冲与预构建 MDL：消灭分片热路径 100% 动态池分配与动态 MDL ★★★
    g_UdpServer.pSliceBuf = (PUCHAR)UserVar->Func.ExAllocatePoolWithTag(NonPagedPoolNx, MK_UDP_SAFE_MTU_PAYLOAD, MK_UDP_SERVER_POOL_TAG);
    if (!g_UdpServer.pSliceBuf)
    {
        DBG("UdpServer_Init: Failed to allocate slice buffer");
        UdpServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_UdpServer.pSliceMdl = UserVar->Func.IoAllocateMdl(g_UdpServer.pSliceBuf, MK_UDP_SAFE_MTU_PAYLOAD, FALSE, FALSE, NULL);
    if (!g_UdpServer.pSliceMdl)
    {
        DBG("UdpServer_Init: Failed to allocate slice MDL");
        UdpServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    UserVar->Func.MmBuildMdlForNonPagedPool(g_UdpServer.pSliceMdl);

    // 优化：常驻 IRP 与事件，消灭 UDP 热路径动态分配开销
    if (UserVar->Func.IoAllocateIrp)
    {
        g_UdpServer.pRecvIrp = UserVar->Func.IoAllocateIrp(4, FALSE);
        UserVar->Func.KeInitializeEvent(&g_UdpServer.RecvEvent, SynchronizationEvent, FALSE);
        g_UdpServer.pSendIrp = UserVar->Func.IoAllocateIrp(4, FALSE);
        UserVar->Func.KeInitializeEvent(&g_UdpServer.SendEvent, SynchronizationEvent, FALSE);
    }

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

    POBJECT_TYPE pThreadType = (UserVar && UserVar->Func.pPsThreadType) ? *UserVar->Func.pPsThreadType : NULL;
    UserVar->Func.ObReferenceObjectByHandle(
        g_UdpServer.hWorkerThread,
        THREAD_ALL_ACCESS,
        pThreadType,
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
            NTSTATUS closeStatus = ((PWSK_PROVIDER_BASIC_DISPATCH)g_UdpServer.pSocket->Dispatch)->WskCloseSocket(g_UdpServer.pSocket, Irp);
            UdpWaitForIrp(UserVar, Irp, &Sync, closeStatus, NULL);
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

    if (g_UdpServer.pRecvIrp)
    {
        UserVar->Func.IoFreeIrp(g_UdpServer.pRecvIrp);
        g_UdpServer.pRecvIrp = NULL;
    }
    if (g_UdpServer.pSendIrp)
    {
        UserVar->Func.IoFreeIrp(g_UdpServer.pSendIrp);
        g_UdpServer.pSendIrp = NULL;
    }

    if (g_UdpServer.pSliceMdl)
    {
        UserVar->Func.IoFreeMdl(g_UdpServer.pSliceMdl);
        g_UdpServer.pSliceMdl = NULL;
    }
    if (g_UdpServer.pSliceBuf)
    {
        UserVar->Func.ExFreePoolWithTag(g_UdpServer.pSliceBuf, MK_UDP_SERVER_POOL_TAG);
        g_UdpServer.pSliceBuf = NULL;
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

    g_UdpServer.Cached_hLC = NULL;
    g_UdpServer.Cached_dwRpcClientID = 0;


    if (g_UdpServer.fOwnRegistration)
    {
        if (g_UdpServer.fCapturedNpi)
        {
            if (UserVar && UserVar->Func.WskReleaseProviderNPI)
            {
                UserVar->Func.WskReleaseProviderNPI(&g_UdpServer.Registration);
            }
            g_UdpServer.fCapturedNpi = FALSE;
        }
        if (g_UdpServer.fRegistered)
        {
            if (UserVar && UserVar->Func.WskDeregister)
            {
                UserVar->Func.WskDeregister(&g_UdpServer.Registration);
            }
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
