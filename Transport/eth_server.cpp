#include "eth_server.h"
#include "Common.h"
#include "DbgLog.h"
#include "TransportManager.h"
#include "RpcDispatcher.h"
#include "DrvSecurity.h"

#pragma comment(lib, "ndis.lib")

MK_ETH_SERVER g_EthServer = {0};
static MK_TRANSPORT_CONTEXT g_EthTransportContext = {0};

// NDIS 6.x 协议回调前置声明
static NDIS_STATUS EthProtocolSetOptions(
    _In_ NDIS_HANDLE NdisDriverHandle,
    _In_ NDIS_HANDLE DriverContext);

static NDIS_STATUS EthProtocolBindAdapterEx(
    _In_ NDIS_HANDLE ProtocolDriverContext,
    _In_ NDIS_HANDLE BindContext,
    _In_ PNDIS_BIND_PARAMETERS BindParameters);

static NDIS_STATUS EthProtocolUnbindAdapterEx(
    _In_ NDIS_HANDLE UnbindContext,
    _In_ NDIS_HANDLE ProtocolBindingContext);

static VOID EthProtocolOpenAdapterCompleteEx(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ NDIS_STATUS Status);

static VOID EthProtocolCloseAdapterCompleteEx(
    _In_ NDIS_HANDLE ProtocolBindingContext);

static NDIS_STATUS EthProtocolNetPnPEvent(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification);

static VOID EthProtocolUninstall(VOID);

static VOID EthProtocolOidRequestComplete(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ PNDIS_OID_REQUEST OidRequest,
    _In_ NDIS_STATUS Status);

static VOID EthProtocolDirectOidRequestComplete(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ PNDIS_OID_REQUEST OidRequest,
    _In_ NDIS_STATUS Status);

static VOID EthProtocolReceiveNetBufferLists(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG NumberOfNetBufferLists,
    _In_ ULONG ReceiveFlags);

static VOID EthProtocolSendNetBufferListsComplete(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG SendCompleteFlags);

static VOID EthProtocolStatusEx(
    _In_ NDIS_HANDLE ProtocolBindingContext,
    _In_ PNDIS_STATUS_INDICATION StatusIndication);

static VOID EthWorkerThreadRoutine(_In_ PVOID Context);
static NTSTATUS EthServer_SendReply(_In_ PMK_ETH_ADAPTER_BINDING pAdapter, _In_ PUCHAR pDstMac, _In_ ULONG dwSequence, _In_ PUCHAR pData, _In_ ULONG cbData);

PMK_TRANSPORT_CONTEXT EthServer_GetTransportContext(VOID)
{
    return &g_EthTransportContext;
}

VOID EthServer_GetStatus(_Out_ PBOOLEAN pfRunning, _Out_ PULONG pActiveConnections)
{
    if (pfRunning)
    {
        *pfRunning = g_EthServer.fRunning;
    }
    if (pActiveConnections)
    {
        *pActiveConnections = (ULONG)g_EthServer.ActiveConnections;
    }
}

static NDIS_STATUS EthSetPacketFilter(_In_ PMK_ETH_ADAPTER_BINDING pBinding, _In_ ULONG PacketFilter)
{
    NDIS_OID_REQUEST OidReq;
    NDIS_STATUS Status;
    ULONG FilterVal = PacketFilter;

    if (!pBinding || !pBinding->BindingHandle)
    {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    NdisZeroMemory(&OidReq, sizeof(NDIS_OID_REQUEST));
    OidReq.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    OidReq.Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    OidReq.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
    OidReq.RequestType = NdisRequestSetInformation;
    OidReq.DATA.SET_INFORMATION.Oid = OID_GEN_CURRENT_PACKET_FILTER;
    OidReq.DATA.SET_INFORMATION.InformationBuffer = &FilterVal;
    OidReq.DATA.SET_INFORMATION.InformationBufferLength = sizeof(ULONG);

    KeClearEvent(&pBinding->OidCompleteEvent);
    Status = NdisOidRequest(pBinding->BindingHandle, &OidReq);
    if (Status == NDIS_STATUS_PENDING)
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -20000000LL; // 2 秒超时保护，防止异常虚拟网卡挂死绑定线程
        if (KeWaitForSingleObject(&pBinding->OidCompleteEvent, Executive, KernelMode, FALSE, &Timeout) == STATUS_TIMEOUT)
        {
            NdisCancelOidRequest(pBinding->BindingHandle, &OidReq);
            KeWaitForSingleObject(&pBinding->OidCompleteEvent, Executive, KernelMode, FALSE, NULL);
        }
        Status = pBinding->OidStatus;
    }
    return Status;
}

static VOID EthEnsureProtocolLinkage(_In_ PCWSTR TargetLinkageKeyPath)
{
    UNICODE_STRING uSrcKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Linkage");
    UNICODE_STRING uDstKey;
    OBJECT_ATTRIBUTES oaSrc, oaDst;
    HANDLE hSrc = NULL, hDst = NULL;

    RtlInitUnicodeString(&uDstKey, TargetLinkageKeyPath);
    InitializeObjectAttributes(&oaSrc, &uSrcKey, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    InitializeObjectAttributes(&oaDst, &uDstKey, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwOpenKey(&hSrc, KEY_READ, &oaSrc)))
    {
        return;
    }

    if (NT_SUCCESS(ZwCreateKey(&hDst, KEY_ALL_ACCESS, &oaDst, 0, NULL, REG_OPTION_NON_VOLATILE, NULL)))
    {
        static const PCWSTR s_ValueNames[] = { L"Bind", L"Export", L"Route" };
        ULONG cbBuf = 16384;
        PKEY_VALUE_PARTIAL_INFORMATION pInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, cbBuf, MK_ETH_POOL_TAG);
        if (pInfo)
        {
            for (ULONG i = 0; i < ARRAYSIZE(s_ValueNames); ++i)
            {
                UNICODE_STRING uVal;
                ULONG cbRes = 0;
                RtlInitUnicodeString(&uVal, s_ValueNames[i]);
                if (NT_SUCCESS(ZwQueryValueKey(hSrc, &uVal, KeyValuePartialInformation, pInfo, cbBuf, &cbRes)))
                {
                    ZwSetValueKey(hDst, &uVal, 0, pInfo->Type, pInfo->Data, pInfo->DataLength);
                }
            }
            ExFreePoolWithTag(pInfo, MK_ETH_POOL_TAG);
        }
        ZwClose(hDst);
    }
    ZwClose(hSrc);
}

static NDIS_STATUS EthProtocolSetOptions(NDIS_HANDLE NdisDriverHandle, NDIS_HANDLE DriverContext)
{
    UNREFERENCED_PARAMETER(NdisDriverHandle);
    UNREFERENCED_PARAMETER(DriverContext);
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS EthProtocolBindAdapterEx(
    NDIS_HANDLE ProtocolDriverContext,
    NDIS_HANDLE BindContext,
    PNDIS_BIND_PARAMETERS BindParameters)
{
    UNREFERENCED_PARAMETER(ProtocolDriverContext);
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    NDIS_OPEN_PARAMETERS OpenParams;
    NDIS_MEDIUM MediumArray[] = { NdisMedium802_3 };
    UINT SelectedMediumIndex = 0;
    PMK_ETH_ADAPTER_BINDING pBinding = NULL;

    if (!g_EthServer.fRunning)
    {
        return NDIS_STATUS_FAILURE;
    }

    pBinding = (PMK_ETH_ADAPTER_BINDING)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(MK_ETH_ADAPTER_BINDING), MK_ETH_POOL_TAG);
    if (!pBinding)
    {
        return NDIS_STATUS_RESOURCES;
    }
    RtlZeroMemory(pBinding, sizeof(MK_ETH_ADAPTER_BINDING));
    KeInitializeEvent(&pBinding->OpenCompleteEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&pBinding->CloseCompleteEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&pBinding->OidCompleteEvent, NotificationEvent, FALSE);

    if (BindParameters->MacAddressLength >= 6)
    {
        RtlCopyMemory(pBinding->LocalMac, BindParameters->CurrentMacAddress, 6);
    }

    NdisZeroMemory(&OpenParams, sizeof(NDIS_OPEN_PARAMETERS));
    OpenParams.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
    OpenParams.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
    OpenParams.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVISION_1;
    OpenParams.AdapterName = BindParameters->AdapterName;
    OpenParams.MediumArray = MediumArray;
    OpenParams.MediumArraySize = ARRAYSIZE(MediumArray);
    OpenParams.SelectedMediumIndex = &SelectedMediumIndex;
    OpenParams.FrameTypeArray = NULL;
    OpenParams.FrameTypeArraySize = 0;

    Status = NdisOpenAdapterEx(
        g_EthServer.ProtocolHandle,
        (NDIS_HANDLE)pBinding,
        &OpenParams,
        BindContext,
        &pBinding->BindingHandle);

    if (Status == NDIS_STATUS_PENDING)
    {
        KeWaitForSingleObject(&pBinding->OpenCompleteEvent, Executive, KernelMode, FALSE, NULL);
        Status = pBinding->OpenStatus;
    }

    if (Status == NDIS_STATUS_SUCCESS)
    {
        pBinding->fActive = TRUE;

        // 开启网卡数据包接收过滤 (优先尝试混杂+广播+单播，若不支持混杂则回退单播+广播+多播)
        ULONG ulFilter = NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST | NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_PROMISCUOUS;
        NDIS_STATUS FilterStatus = EthSetPacketFilter(pBinding, ulFilter);
        if (FilterStatus != NDIS_STATUS_SUCCESS)
        {
            ulFilter = NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST | NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_ALL_LOCAL;
            FilterStatus = EthSetPacketFilter(pBinding, ulFilter);
        }

        ExInterlockedInsertTailList(&g_EthServer.AdapterList, &pBinding->Link, &g_EthServer.AdapterLock);
        DBG("[EthServer] Bound adapter: %wZ (MAC=%02X:%02X:%02X:%02X:%02X:%02X, FilterStatus=0x%08X)",
            BindParameters->AdapterName,
            pBinding->LocalMac[0], pBinding->LocalMac[1], pBinding->LocalMac[2],
            pBinding->LocalMac[3], pBinding->LocalMac[4], pBinding->LocalMac[5],
            FilterStatus);
    }
    else
    {
        DBG("[EthServer] NdisOpenAdapterEx failed on %wZ: 0x%08X", BindParameters->AdapterName, Status);
        ExFreePoolWithTag(pBinding, MK_ETH_POOL_TAG);
    }

    return Status;
}

static VOID EthProtocolOpenAdapterCompleteEx(
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_STATUS Status)
{
    PMK_ETH_ADAPTER_BINDING pBinding = (PMK_ETH_ADAPTER_BINDING)ProtocolBindingContext;
    if (!pBinding) return;

    pBinding->OpenStatus = Status;
    KeSetEvent(&pBinding->OpenCompleteEvent, IO_NO_INCREMENT, FALSE);
}

static NDIS_STATUS EthProtocolUnbindAdapterEx(
    NDIS_HANDLE UnbindContext,
    NDIS_HANDLE ProtocolBindingContext)
{
    UNREFERENCED_PARAMETER(UnbindContext);
    PMK_ETH_ADAPTER_BINDING pBinding = (PMK_ETH_ADAPTER_BINDING)ProtocolBindingContext;
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;

    if (!pBinding) return NDIS_STATUS_SUCCESS;

    pBinding->fActive = FALSE;
    if (g_EthServer.pTargetAdapter == pBinding)
    {
        g_EthServer.pTargetAdapter = NULL;
    }

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_EthServer.AdapterLock, &lockHandle);
    RemoveEntryList(&pBinding->Link);
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    KeClearEvent(&pBinding->CloseCompleteEvent);
    Status = NdisCloseAdapterEx(pBinding->BindingHandle);
    if (Status == NDIS_STATUS_PENDING)
    {
        KeWaitForSingleObject(&pBinding->CloseCompleteEvent, Executive, KernelMode, FALSE, NULL);
    }

    ExFreePoolWithTag(pBinding, MK_ETH_POOL_TAG);
    return NDIS_STATUS_SUCCESS;
}

static VOID EthProtocolCloseAdapterCompleteEx(NDIS_HANDLE ProtocolBindingContext)
{
    PMK_ETH_ADAPTER_BINDING pBinding = (PMK_ETH_ADAPTER_BINDING)ProtocolBindingContext;
    if (pBinding)
    {
        KeSetEvent(&pBinding->CloseCompleteEvent, IO_NO_INCREMENT, FALSE);
    }
}

static NDIS_STATUS EthProtocolNetPnPEvent(
    NDIS_HANDLE ProtocolBindingContext,
    PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    if (NetPnPEventNotification && NetPnPEventNotification->NetPnPEvent.NetEvent == NetEventBindsComplete)
    {
        DBG("[EthServer] NetEventBindsComplete received");
    }
    return NDIS_STATUS_SUCCESS;
}

static VOID EthProtocolUninstall(VOID)
{
}

static VOID EthProtocolOidRequestComplete(
    NDIS_HANDLE ProtocolBindingContext,
    PNDIS_OID_REQUEST OidRequest,
    NDIS_STATUS Status)
{
    UNREFERENCED_PARAMETER(OidRequest);
    PMK_ETH_ADAPTER_BINDING pBinding = (PMK_ETH_ADAPTER_BINDING)ProtocolBindingContext;
    if (pBinding)
    {
        pBinding->OidStatus = Status;
        KeSetEvent(&pBinding->OidCompleteEvent, IO_NO_INCREMENT, FALSE);
    }
}

static VOID EthProtocolDirectOidRequestComplete(
    NDIS_HANDLE ProtocolBindingContext,
    PNDIS_OID_REQUEST OidRequest,
    NDIS_STATUS Status)
{
    EthProtocolOidRequestComplete(ProtocolBindingContext, OidRequest, Status);
}

static VOID EthProtocolReceiveNetBufferLists(
    NDIS_HANDLE ProtocolBindingContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags)
{
    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

    PMK_ETH_ADAPTER_BINDING pBinding = (PMK_ETH_ADAPTER_BINDING)ProtocolBindingContext;

    if (g_EthServer.fRunning && pBinding && pBinding->fActive)
    {
        PNET_BUFFER_LIST pCurrNbl = NetBufferLists;

        while (pCurrNbl != NULL)
        {
            PNET_BUFFER pNb = NET_BUFFER_LIST_FIRST_NB(pCurrNbl);
            while (pNb != NULL)
            {
                ULONG DataLength = NET_BUFFER_DATA_LENGTH(pNb);
                if (DataLength >= sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR))
                {
                    UCHAR FrameBuffer[128];
                    PVOID pData = NdisGetDataBuffer(pNb, sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR), FrameBuffer, 1, 0);
                    if (pData)
                    {
                        PMK_ETH_FRAME_HDR pFrame = (PMK_ETH_FRAME_HDR)pData;
                        USHORT ethType = (USHORT)((pFrame->EtherType >> 8) | (pFrame->EtherType << 8));

                        if (ethType == g_EthServer.EtherType &&
                            !RtlEqualMemory(pFrame->SrcMac, pBinding->LocalMac, 6))
                        {
                            PMK_ETH_PACKET_HDR pPkt = (PMK_ETH_PACKET_HDR)((PUCHAR)pData + sizeof(MK_ETH_FRAME_HDR));
                            if (pPkt->dwMagic == MK_ETH_SLICE_MAGIC &&
                                pPkt->Reserved != MK_ETH_FLAG_RESPONSE &&
                                pPkt->cbSliceData <= (DataLength - sizeof(MK_ETH_FRAME_HDR) - sizeof(MK_ETH_PACKET_HDR)))
                            {
                                KLOCK_QUEUE_HANDLE lockHandle;
                                KeAcquireInStackQueuedSpinLock(&g_EthServer.RecvLock, &lockHandle);

                                if (!g_EthServer.fProcessing)
                                {
                                    static const UCHAR s_ZeroMac[6] = {0};
                                    if (!RtlEqualMemory(pFrame->SrcMac, s_ZeroMac, 6))
                                    {
                                        RtlCopyMemory(g_EthServer.TargetClientMac, pFrame->SrcMac, 6);
                                    }
                                    else if (!RtlEqualMemory(pPkt->ClientMac, s_ZeroMac, 6))
                                    {
                                        RtlCopyMemory(g_EthServer.TargetClientMac, pPkt->ClientMac, 6);
                                    }
                                    else
                                    {
                                        RtlFillMemory(g_EthServer.TargetClientMac, 6, 0xFF);
                                    }
                                    g_EthServer.fTargetMacLearned = TRUE;
                                    g_EthServer.pTargetAdapter = pBinding;

                                    if (pPkt->SliceIndex == 0 || pPkt->dwSequence != g_EthServer.dwLastRecvSequence)
                                    {
                                        g_EthServer.dwLastRecvSequence = pPkt->dwSequence;
                                        g_EthServer.cbRecvExpectedTotal = pPkt->cbOriginalTotal;
                                        g_EthServer.cbRecvCurrent = 0;
                                    }

                                    ULONG dstOffset = (ULONG)pPkt->SliceIndex * MK_ETH_MAX_SLICE_PAYLOAD;
                                    if (pPkt->dwSequence == g_EthServer.dwLastRecvSequence &&
                                        (dstOffset + pPkt->cbSliceData) <= MK_ETH_SERVER_MAX_PACKET_SIZE)
                                    {
                                        ULONG copyOffset = sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR);
                                        ULONG totalNeeded = copyOffset + pPkt->cbSliceData;
                                        PUCHAR pContig = (PUCHAR)NdisGetDataBuffer(pNb, totalNeeded, NULL, 1, 0);
                                        if (pContig)
                                        {
                                            RtlCopyMemory(g_EthServer.pRecvAssembleBuf + dstOffset,
                                                          pContig + copyOffset,
                                                          pPkt->cbSliceData);
                                            g_EthServer.cbRecvCurrent = dstOffset + pPkt->cbSliceData;
                                        }
                                        else
                                        {
                                            UCHAR BounceBuf[MK_ETH_SAFE_MTU_PAYLOAD + 64];
                                            if (totalNeeded <= sizeof(BounceBuf))
                                            {
                                                pContig = (PUCHAR)NdisGetDataBuffer(pNb, totalNeeded, BounceBuf, 1, 0);
                                                if (pContig)
                                                {
                                                    RtlCopyMemory(g_EthServer.pRecvAssembleBuf + dstOffset,
                                                                  pContig + copyOffset,
                                                                  pPkt->cbSliceData);
                                                    g_EthServer.cbRecvCurrent = dstOffset + pPkt->cbSliceData;
                                                }
                                            }
                                        }

                                        if ((pPkt->SliceIndex + 1) >= pPkt->TotalSlices &&
                                            g_EthServer.cbRecvCurrent >= g_EthServer.cbRecvExpectedTotal &&
                                            g_EthServer.cbRecvExpectedTotal > 0)
                                        {
                                            g_EthServer.fProcessing = TRUE;
                                            InterlockedExchange(&g_EthServer.ActiveConnections, 1);
                                            KeSetEvent(&g_EthServer.WorkerWakeEvent, IO_NO_INCREMENT, FALSE);
                                        }
                                    }
                                }

                                KeReleaseInStackQueuedSpinLock(&lockHandle);
                            }
                        }
                    }
                }
                pNb = NET_BUFFER_NEXT_NB(pNb);
            }
            pCurrNbl = NET_BUFFER_LIST_NEXT_NBL(pCurrNbl);
        }
    }

    if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags) && pBinding && pBinding->BindingHandle)
    {
        ULONG ReturnFlags = 0;
        if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
        {
            NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
        }
        NdisReturnNetBufferLists(pBinding->BindingHandle, NetBufferLists, ReturnFlags);
    }
}

static VOID EthProtocolSendNetBufferListsComplete(
    NDIS_HANDLE ProtocolBindingContext,
    PNET_BUFFER_LIST NetBufferLists,
    ULONG SendCompleteFlags)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(SendCompleteFlags);

    PNET_BUFFER_LIST pCurr = NetBufferLists;
    while (pCurr != NULL)
    {
        PNET_BUFFER_LIST pNext = NET_BUFFER_LIST_NEXT_NBL(pCurr);
        PMDL pMdl = NET_BUFFER_FIRST_MDL(NET_BUFFER_LIST_FIRST_NB(pCurr));
        if (pMdl)
        {
            PVOID pBuffer = MmGetMdlVirtualAddress(pMdl);
            IoFreeMdl(pMdl);
            if (pBuffer)
            {
                ExFreePoolWithTag(pBuffer, MK_ETH_POOL_TAG);
            }
        }
        NdisFreeNetBufferList(pCurr);
        pCurr = pNext;
    }
}

static VOID EthProtocolStatusEx(
    NDIS_HANDLE ProtocolBindingContext,
    PNDIS_STATUS_INDICATION StatusIndication)
{
    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(StatusIndication);
}

static NTSTATUS EthServer_SendReply(
    _In_ PMK_ETH_ADAPTER_BINDING pAdapter,
    _In_ PUCHAR pDstMac,
    _In_ ULONG dwSequence,
    _In_ PUCHAR pData,
    _In_ ULONG cbData)
{
    if (!pAdapter || !pAdapter->fActive || !pAdapter->BindingHandle || !pData || cbData == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    USHORT totalSlices = (USHORT)((cbData + MK_ETH_MAX_SLICE_PAYLOAD - 1) / MK_ETH_MAX_SLICE_PAYLOAD);
    if (totalSlices == 0) totalSlices = 1;

    ULONG cbRemaining = cbData;
    ULONG cbOffset = 0;

    for (USHORT sliceIdx = 0; sliceIdx < totalSlices; ++sliceIdx)
    {
        ULONG cbSlice = (cbRemaining > MK_ETH_MAX_SLICE_PAYLOAD) ? MK_ETH_MAX_SLICE_PAYLOAD : cbRemaining;
        ULONG cbFrameTotal = sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR) + cbSlice;
        if (cbFrameTotal < 60)
        {
            cbFrameTotal = 60; // 以太网最小帧长 60 字节 (不含 FCS)
        }

        PUCHAR pFrameBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, cbFrameTotal, MK_ETH_POOL_TAG);
        if (!pFrameBuf)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (cbFrameTotal == 60)
        {
            RtlZeroMemory(pFrameBuf, 60);
        }

        PMK_ETH_FRAME_HDR pEthHdr = (PMK_ETH_FRAME_HDR)pFrameBuf;
        RtlCopyMemory(pEthHdr->DstMac, pDstMac, 6);
        RtlCopyMemory(pEthHdr->SrcMac, pAdapter->LocalMac, 6);
        pEthHdr->EtherType = (USHORT)((g_EthServer.EtherType >> 8) | (g_EthServer.EtherType << 8)); // htons

        PMK_ETH_PACKET_HDR pPktHdr = (PMK_ETH_PACKET_HDR)(pFrameBuf + sizeof(MK_ETH_FRAME_HDR));
        pPktHdr->dwMagic = MK_ETH_SLICE_MAGIC;
        pPktHdr->dwSequence = dwSequence;
        pPktHdr->SliceIndex = sliceIdx;
        pPktHdr->TotalSlices = totalSlices;
        pPktHdr->cbOriginalTotal = cbData;
        pPktHdr->cbSliceData = cbSlice;
        RtlCopyMemory(pPktHdr->ClientMac, pDstMac, 6);
        pPktHdr->Reserved = MK_ETH_FLAG_RESPONSE;

        RtlCopyMemory(pFrameBuf + sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR), pData + cbOffset, cbSlice);

        PMDL pMdl = IoAllocateMdl(pFrameBuf, cbFrameTotal, FALSE, FALSE, NULL);
        if (!pMdl)
        {
            ExFreePoolWithTag(pFrameBuf, MK_ETH_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        MmBuildMdlForNonPagedPool(pMdl);

        PNET_BUFFER_LIST pNbl = NdisAllocateNetBufferAndNetBufferList(
            g_EthServer.NblPoolHandle,
            0,
            0,
            pMdl,
            0,
            cbFrameTotal);

        if (!pNbl)
        {
            IoFreeMdl(pMdl);
            ExFreePoolWithTag(pFrameBuf, MK_ETH_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        pNbl->SourceHandle = pAdapter->BindingHandle;
        // SendFlags 传 0（不带 NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK），避免 NDIS 向本机上层 LWF 过滤器回环广播
        NdisSendNetBufferLists(pAdapter->BindingHandle, pNbl, NDIS_DEFAULT_PORT_NUMBER, 0);

        cbRemaining -= cbSlice;
        cbOffset += cbSlice;

        // 大包突发流控：每发送 16 个分片微延时 5us，防止客户端消费级网卡 RX Ring 溢出丢包
        if (totalSlices > 16 && ((sliceIdx + 1) & 0x0F) == 0)
        {
            KeStallExecutionProcessor(5);
        }
    }

    return STATUS_SUCCESS;
}

static VOID EthWorkerThreadRoutine(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    PVOID WaitObjects[2];
    WaitObjects[0] = &g_EthServer.WorkerExitEvent;
    WaitObjects[1] = &g_EthServer.WorkerWakeEvent;

    DBG("[EthServer] Worker thread entered execution loop");

    while (g_EthServer.fRunning)
    {
        NTSTATUS WaitStatus = KeWaitForMultipleObjects(2, WaitObjects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
        if (WaitStatus == STATUS_WAIT_0 || !g_EthServer.fRunning)
        {
            break;
        }

        KLOCK_QUEUE_HANDLE lockHandle;
        KeAcquireInStackQueuedSpinLock(&g_EthServer.RecvLock, &lockHandle);

        ULONG cbIn = g_EthServer.cbRecvExpectedTotal;
        ULONG dwSeq = g_EthServer.dwLastRecvSequence;
        UCHAR clientMac[6];
        RtlCopyMemory(clientMac, g_EthServer.TargetClientMac, 6);
        PMK_ETH_ADAPTER_BINDING pRecvAdapter = g_EthServer.pTargetAdapter;

        g_EthServer.cbRecvCurrent = 0;
        g_EthServer.cbRecvExpectedTotal = 0;

        KeReleaseInStackQueuedSpinLock(&lockHandle);

        if (cbIn > 0 && cbIn <= MK_ETH_SERVER_MAX_PACKET_SIZE && g_EthServer.pRecvAssembleBuf)
        {
            PUCHAR pbOut = NULL;
            ULONG cbOut = 0;

            NTSTATUS RpcStatus = RpcDispatcher::DispatchCommandEx(
                &g_EthTransportContext,
                g_EthServer.pRecvAssembleBuf,
                cbIn,
                &pbOut,
                &cbOut,
                g_EthServer.pDirectOutBuf,
                MK_ETH_SERVER_MAX_PACKET_SIZE);

            // 命令执行完毕，立即释放接收缓冲区锁标记，允许后续请求进入组装
            InterlockedExchange8(( volatile CHAR* )&g_EthServer.fProcessing, FALSE);

            if (NT_SUCCESS(RpcStatus) && cbOut > 0 && pbOut != NULL)
            {
                PMK_ETH_ADAPTER_BINDING pTargetAdapter = NULL;
                KLOCK_QUEUE_HANDLE listLock;
                KeAcquireInStackQueuedSpinLock(&g_EthServer.AdapterLock, &listLock);

                if (pRecvAdapter && pRecvAdapter->fActive)
                {
                    pTargetAdapter = pRecvAdapter;
                }
                else if (!IsListEmpty(&g_EthServer.AdapterList))
                {
                    PLIST_ENTRY pEntry = g_EthServer.AdapterList.Flink;
                    pTargetAdapter = CONTAINING_RECORD(pEntry, MK_ETH_ADAPTER_BINDING, Link);
                }

                KeReleaseInStackQueuedSpinLock(&listLock);

                if (pTargetAdapter && pTargetAdapter->fActive)
                {
                    EthServer_SendReply(pTargetAdapter, clientMac, dwSeq, pbOut, cbOut);
                }
            }

            if (pbOut && pbOut != g_EthServer.pDirectOutBuf)
            {
                ExFreePool(pbOut);
            }
        }
        else
        {
            InterlockedExchange8(( volatile CHAR* )&g_EthServer.fProcessing, FALSE);
        }
    }

    DBG("[EthServer] Worker thread exited successfully");
}

NTSTATUS EthServer_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ USHORT EtherType, _In_opt_ PCWSTR TargetAdapterName)
{
    UNREFERENCED_PARAMETER(TargetAdapterName);
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    NDIS_PROTOCOL_DRIVER_CHARACTERISTICS ProtChars;
    NET_BUFFER_LIST_POOL_PARAMETERS PoolParams;

    if (g_EthServer.fRunning)
    {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_EthServer, sizeof(MK_ETH_SERVER));
    g_EthServer.UserVar = UserVar;
    g_EthServer.EtherType = (EtherType == 0) ? MK_ETH_SERVER_DEFAULT_ETHERTYPE : EtherType;
    InitializeListHead(&g_EthServer.AdapterList);
    KeInitializeSpinLock(&g_EthServer.AdapterLock);
    KeInitializeSpinLock(&g_EthServer.RecvLock);
    KeInitializeEvent(&g_EthServer.WorkerExitEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_EthServer.WorkerWakeEvent, SynchronizationEvent, FALSE);

    g_EthServer.pRecvAssembleBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, MK_ETH_SERVER_MAX_PACKET_SIZE, MK_ETH_POOL_TAG);
    g_EthServer.pDirectOutBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, MK_ETH_SERVER_MAX_PACKET_SIZE, MK_ETH_POOL_TAG);
    if (!g_EthServer.pRecvAssembleBuf || !g_EthServer.pDirectOutBuf)
    {
        EthServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NdisZeroMemory(&PoolParams, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
    PoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    PoolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    PoolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    PoolParams.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    PoolParams.fAllocateNetBuffer = TRUE;
    PoolParams.PoolTag = MK_ETH_POOL_TAG;
    PoolParams.DataSize = 0;

    g_EthServer.NblPoolHandle = NdisAllocateNetBufferListPool(NULL, &PoolParams);
    if (!g_EthServer.NblPoolHandle)
    {
        EthServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 尝试卸载可能正在占位的系统闲置 ndisuio.sys，确保 NDISUIO 协议名 100% 可被本驱动接管并自动绑定全网卡
    {
        UNICODE_STRING uNdisuioSvc = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ndisuio");
        ZwUnloadDriver(&uNdisuioSvc);
    }

    // 同步拷贝 Tcpip\Linkage 到 Ndisuio\Linkage 及后备协议名，确保无 INF 场景下 NDIS 自动枚举绑定所有物理网卡
    EthEnsureProtocolLinkage(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Ndisuio\\Linkage");
    EthEnsureProtocolLinkage(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\i225v\\Linkage");

    NdisZeroMemory(&ProtChars, sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS));
    ProtChars.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
    ProtChars.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
    ProtChars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
    ProtChars.MajorNdisVersion = 6;
    ProtChars.MinorNdisVersion = 30;
    ProtChars.MajorDriverVersion = 0;
    ProtChars.MinorDriverVersion = 2;

    ProtChars.SetOptionsHandler = EthProtocolSetOptions;
    ProtChars.BindAdapterHandlerEx = EthProtocolBindAdapterEx;
    ProtChars.UnbindAdapterHandlerEx = EthProtocolUnbindAdapterEx;
    ProtChars.OpenAdapterCompleteHandlerEx = EthProtocolOpenAdapterCompleteEx;
    ProtChars.CloseAdapterCompleteHandlerEx = EthProtocolCloseAdapterCompleteEx;
    ProtChars.NetPnPEventHandler = EthProtocolNetPnPEvent;
    ProtChars.UninstallHandler = EthProtocolUninstall;
    ProtChars.OidRequestCompleteHandler = EthProtocolOidRequestComplete;
    ProtChars.StatusHandlerEx = EthProtocolStatusEx;
    ProtChars.ReceiveNetBufferListsHandler = EthProtocolReceiveNetBufferLists;
    ProtChars.SendNetBufferListsCompleteHandler = EthProtocolSendNetBufferListsComplete;
    ProtChars.DirectOidRequestCompleteHandler = EthProtocolDirectOidRequestComplete;

    // 必须在 NdisRegisterProtocolDriver 之前置 fRunning = TRUE，因为 NdisRegisterProtocolDriver 内部可能同步回调 BindAdapterHandlerEx
    g_EthServer.fRunning = TRUE;

    static const WCHAR s_szPrimaryName[] = L"NDISUIO";
    ProtChars.Name.Buffer = (PWCH)s_szPrimaryName;
    ProtChars.Name.Length = sizeof(s_szPrimaryName) - sizeof(WCHAR);
    ProtChars.Name.MaximumLength = sizeof(s_szPrimaryName);

    Status = NdisRegisterProtocolDriver(
        (NDIS_HANDLE)&g_EthServer,
        &ProtChars,
        &g_EthServer.ProtocolHandle);

    if (Status != NDIS_STATUS_SUCCESS)
    {
        static const WCHAR s_szFallbackName[] = L"NDISTEST6";
        ProtChars.Name.Buffer = (PWCH)s_szFallbackName;
        ProtChars.Name.Length = sizeof(s_szFallbackName) - sizeof(WCHAR);
        ProtChars.Name.MaximumLength = sizeof(s_szFallbackName);

        Status = NdisRegisterProtocolDriver(
            (NDIS_HANDLE)&g_EthServer,
            &ProtChars,
            &g_EthServer.ProtocolHandle);
    }

    if (Status != NDIS_STATUS_SUCCESS)
    {
        g_EthServer.fRunning = FALSE;
        DBG("[EthServer] NdisRegisterProtocolDriver failed: 0x%08X", Status);
        EthServer_Stop(UserVar);
        return Status;
    }

    // 主动触发 NDIS 重新枚举协议绑定，确保所有已就绪网卡立即回调 EthProtocolBindAdapterEx
    NdisReEnumerateProtocolBindings(g_EthServer.ProtocolHandle);

    HANDLE hThread = NULL;
    NTSTATUS ThreadStatus = PsCreateSystemThread(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        EthWorkerThreadRoutine,
        NULL);

    if (NT_SUCCESS(ThreadStatus))
    {
        ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &g_EthServer.pWorkerThread, NULL);
        ZwClose(hThread);
    }
    else
    {
        DBG("[EthServer] Failed to create worker thread: 0x%08X", ThreadStatus);
        EthServer_Stop(UserVar);
        return ThreadStatus;
    }

    DBG("[EthServer] Ethernet Server started successfully (EtherType=0x%04X)", g_EthServer.EtherType);
    return STATUS_SUCCESS;
}

VOID EthServer_Stop(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);
    if (!g_EthServer.fRunning && !g_EthServer.ProtocolHandle && !g_EthServer.NblPoolHandle)
    {
        return;
    }

    g_EthServer.fRunning = FALSE;

    KeSetEvent(&g_EthServer.WorkerExitEvent, IO_NO_INCREMENT, FALSE);
    if (g_EthServer.pWorkerThread)
    {
        KeWaitForSingleObject(g_EthServer.pWorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_EthServer.pWorkerThread);
        g_EthServer.pWorkerThread = NULL;
    }

    if (g_EthServer.ProtocolHandle)
    {
        NdisDeregisterProtocolDriver(g_EthServer.ProtocolHandle);
        g_EthServer.ProtocolHandle = NULL;
    }

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_EthServer.AdapterLock, &lockHandle);
    while (!IsListEmpty(&g_EthServer.AdapterList))
    {
        PLIST_ENTRY pEntry = RemoveHeadList(&g_EthServer.AdapterList);
        PMK_ETH_ADAPTER_BINDING pBinding = CONTAINING_RECORD(pEntry, MK_ETH_ADAPTER_BINDING, Link);
        ExFreePoolWithTag(pBinding, MK_ETH_POOL_TAG);
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (g_EthServer.NblPoolHandle)
    {
        NdisFreeNetBufferListPool(g_EthServer.NblPoolHandle);
        g_EthServer.NblPoolHandle = NULL;
    }

    if (g_EthServer.pRecvAssembleBuf)
    {
        ExFreePoolWithTag(g_EthServer.pRecvAssembleBuf, MK_ETH_POOL_TAG);
        g_EthServer.pRecvAssembleBuf = NULL;
    }

    if (g_EthServer.pDirectOutBuf)
    {
        ExFreePoolWithTag(g_EthServer.pDirectOutBuf, MK_ETH_POOL_TAG);
        g_EthServer.pDirectOutBuf = NULL;
    }

    DBG("[EthServer] Ethernet Server stopped and cleaned up");
}
