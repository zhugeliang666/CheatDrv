#include "eth_server.h"
#include "Common.h"
#include "DbgLog.h"
#include "TransportManager.h"
#include "RpcDispatcher.h"
#include "DrvSecurity.h"
#include "miniport_direct.h"
#include "ExceptionReporter.h"

// ---------------------------------------------------------------------------
// Zero-IAT 桥接：将所有裸调用重定向至 UserVar->Func / UserVar->Ndis (杜绝静态 IAT)
// ---------------------------------------------------------------------------
#define ETH_USER_VAR (g_EthServer.UserVar ? g_EthServer.UserVar : g_pGlobalUserVar)

#ifdef ExAllocatePoolWithTag
#undef ExAllocatePoolWithTag
#endif
#define ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag) \
    (ETH_USER_VAR ? (ETH_USER_VAR->Func.ExAllocatePoolWithTag)(PoolType, NumberOfBytes, Tag) : NULL)

#ifdef ExFreePoolWithTag
#undef ExFreePoolWithTag
#endif
#define ExFreePoolWithTag(P, Tag) \
    do { if (ETH_USER_VAR) (ETH_USER_VAR->Func.ExFreePoolWithTag)(P, Tag); } while (0)

#ifdef IoAllocateMdl
#undef IoAllocateMdl
#endif
#define IoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp) \
    (ETH_USER_VAR ? (ETH_USER_VAR->Func.IoAllocateMdl)(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp) : NULL)

#ifdef IoFreeMdl
#undef IoFreeMdl
#endif
#define IoFreeMdl(Mdl) \
    do { if (ETH_USER_VAR) (ETH_USER_VAR->Func.IoFreeMdl)(Mdl); } while (0)

#ifdef MmBuildMdlForNonPagedPool
#undef MmBuildMdlForNonPagedPool
#endif
#define MmBuildMdlForNonPagedPool(MemoryDescriptorList) \
    do { if (ETH_USER_VAR) (ETH_USER_VAR->Func.MmBuildMdlForNonPagedPool)(MemoryDescriptorList); } while (0)

#ifdef KeInitializeSpinLock
#undef KeInitializeSpinLock
#endif
#define KeInitializeSpinLock(SpinLock) \
    do { if (ETH_USER_VAR) (ETH_USER_VAR->Func.KeInitializeSpinLock)(SpinLock); } while (0)

#ifdef KeInitializeEvent
#undef KeInitializeEvent
#endif
#define KeInitializeEvent(Event, Type, State) \
    do { if (ETH_USER_VAR) (ETH_USER_VAR->Func.KeInitializeEvent)(Event, Type, State); } while (0)

#ifdef KeSetEvent
#undef KeSetEvent
#endif
#define KeSetEvent(Event, Increment, Wait) \
    (ETH_USER_VAR ? (ETH_USER_VAR->Func.KeSetEvent)(Event, Increment, Wait) : 0)

#ifdef KeClearEvent
#undef KeClearEvent
#endif
#define KeClearEvent(Event) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Func.KeClearEvent) (ETH_USER_VAR->Func.KeClearEvent)(Event); } while (0)

#ifdef KeWaitForSingleObject
#undef KeWaitForSingleObject
#endif
#define KeWaitForSingleObject(Object, WaitReason, WaitMode, Alertable, Timeout) \
    (ETH_USER_VAR ? (ETH_USER_VAR->Func.KeWaitForSingleObject)(Object, WaitReason, WaitMode, Alertable, Timeout) : STATUS_UNSUCCESSFUL)

#ifdef KeWaitForMultipleObjects
#undef KeWaitForMultipleObjects
#endif
#define KeWaitForMultipleObjects(Count, Object, WaitType, WaitReason, WaitMode, Alertable, Timeout, WaitBlockArray) \
    (ETH_USER_VAR && ETH_USER_VAR->Func.KeWaitForMultipleObjects ? (ETH_USER_VAR->Func.KeWaitForMultipleObjects)(Count, (PVOID*)(Object), WaitType, WaitReason, WaitMode, Alertable, Timeout, WaitBlockArray) : STATUS_UNSUCCESSFUL)

#ifdef ObReferenceObjectByHandle
#undef ObReferenceObjectByHandle
#endif
#define ObReferenceObjectByHandle(Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation) \
    (ETH_USER_VAR ? (ETH_USER_VAR->Func.ObReferenceObjectByHandle)(Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation) : STATUS_UNSUCCESSFUL)

#ifdef ObDereferenceObject
#undef ObDereferenceObject
#endif
#define ObDereferenceObject(Object) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Func.ObfDereferenceObject) (ETH_USER_VAR->Func.ObfDereferenceObject)(Object); } while (0)

#ifdef ObfDereferenceObject
#undef ObfDereferenceObject
#endif
#define ObfDereferenceObject(Object) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Func.ObfDereferenceObject) (ETH_USER_VAR->Func.ObfDereferenceObject)(Object); } while (0)

#ifdef PsCreateSystemThread
#undef PsCreateSystemThread
#endif
#define PsCreateSystemThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, StartRoutine, StartContext) \
    (ETH_USER_VAR && ETH_USER_VAR->Func.PsCreateSystemThread ? (ETH_USER_VAR->Func.PsCreateSystemThread)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, StartRoutine, StartContext) : STATUS_NOT_IMPLEMENTED)

#ifdef ZwUnloadDriver
#undef ZwUnloadDriver
#endif
#define ZwUnloadDriver(DriverServiceName) \
    (ETH_USER_VAR && ETH_USER_VAR->Func.ZwUnloadDriver ? (ETH_USER_VAR->Func.ZwUnloadDriver)(DriverServiceName) : STATUS_NOT_IMPLEMENTED)

#ifdef PsThreadType
#undef PsThreadType
#endif
#define PsThreadType (ETH_USER_VAR && ETH_USER_VAR->Func.pPsThreadType ? ETH_USER_VAR->Func.pPsThreadType : NULL)

#ifdef RtlInitUnicodeString
#undef RtlInitUnicodeString
#endif
#define RtlInitUnicodeString SafeInitUnicodeString

#ifdef ExQueueWorkItem
#undef ExQueueWorkItem
#endif
#define ExQueueWorkItem(w, q) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Func.ExQueueWorkItem) (ETH_USER_VAR->Func.ExQueueWorkItem)(w, q); } while (0)

#ifdef KeAcquireInStackQueuedSpinLock
#undef KeAcquireInStackQueuedSpinLock
#endif
#define KeAcquireInStackQueuedSpinLock(SpinLock, LockHandle) \
    do { \
        (LockHandle)->LockQueue.Lock = (SpinLock); \
        KeAcquireSpinLock((SpinLock), &((LockHandle)->OldIrql)); \
    } while (0)

#ifdef KeReleaseInStackQueuedSpinLock
#undef KeReleaseInStackQueuedSpinLock
#endif
#define KeReleaseInStackQueuedSpinLock(LockHandle) \
    KeReleaseSpinLock((LockHandle)->LockQueue.Lock, (LockHandle)->OldIrql)

#ifdef ExInterlockedInsertTailList
#undef ExInterlockedInsertTailList
#endif
#define ExInterlockedInsertTailList(ListHead, ListEntry, Lock) \
    do { \
        KIRQL _irql; \
        KeAcquireSpinLock((Lock), &_irql); \
        InsertTailList((ListHead), (ListEntry)); \
        KeReleaseSpinLock((Lock), _irql); \
    } while (0)

#ifdef KeSetPriorityThread
#undef KeSetPriorityThread
#endif
#define KeSetPriorityThread(Thread, Priority) \
    ((ETH_USER_VAR && ETH_USER_VAR->Func.KeSetPriorityThread) ? (ETH_USER_VAR->Func.KeSetPriorityThread)(Thread, Priority) : 0)

#ifdef ZwClose
#undef ZwClose
#endif
#define ZwClose(Handle) \
    ((ETH_USER_VAR && ETH_USER_VAR->Func.ZwClose) ? (ETH_USER_VAR->Func.ZwClose)(Handle) : STATUS_SUCCESS)

#ifdef ZwCreateKey
#undef ZwCreateKey
#endif
#define ZwCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition) \
    ((ETH_USER_VAR && ETH_USER_VAR->Func.ZwCreateKey) ? (ETH_USER_VAR->Func.ZwCreateKey)(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition) : STATUS_NOT_IMPLEMENTED)

#ifdef ZwOpenKey
#undef ZwOpenKey
#endif
#define ZwOpenKey(KeyHandle, DesiredAccess, ObjectAttributes) \
    ((ETH_USER_VAR && ETH_USER_VAR->Func.ZwOpenKey) ? (ETH_USER_VAR->Func.ZwOpenKey)(KeyHandle, DesiredAccess, ObjectAttributes) : STATUS_NOT_IMPLEMENTED)

#ifdef ZwQueryValueKey
#undef ZwQueryValueKey
#endif
#define ZwQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength) \
    ((ETH_USER_VAR && ETH_USER_VAR->Func.ZwQueryValueKey) ? (ETH_USER_VAR->Func.ZwQueryValueKey)(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength) : STATUS_NOT_IMPLEMENTED)

#ifdef ZwSetValueKey
#undef ZwSetValueKey
#endif
#define ZwSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize) \
    ((ETH_USER_VAR && ETH_USER_VAR->Func.ZwSetValueKey) ? (ETH_USER_VAR->Func.ZwSetValueKey)(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize) : STATUS_NOT_IMPLEMENTED)

// NDIS 函数动态重定向 (Zero-IAT)
#define NdisRegisterProtocolDriver(ProtocolDriverContext, ProtocolCharacteristics, NdisProtocolHandle) \
    (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisRegisterProtocolDriver ? (ETH_USER_VAR->Ndis.NdisRegisterProtocolDriver)(ProtocolDriverContext, ProtocolCharacteristics, NdisProtocolHandle) : NDIS_STATUS_FAILURE)

#define NdisDeregisterProtocolDriver(NdisProtocolHandle) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisDeregisterProtocolDriver) (ETH_USER_VAR->Ndis.NdisDeregisterProtocolDriver)(NdisProtocolHandle); } while (0)

#define NdisOpenAdapterEx(NdisProtocolHandle, ProtocolBindingContext, OpenParameters, BindContext, NdisBindingHandle) \
    (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisOpenAdapterEx ? (ETH_USER_VAR->Ndis.NdisOpenAdapterEx)(NdisProtocolHandle, ProtocolBindingContext, OpenParameters, BindContext, NdisBindingHandle) : NDIS_STATUS_FAILURE)

#define NdisCloseAdapterEx(NdisBindingHandle) \
    (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisCloseAdapterEx ? (ETH_USER_VAR->Ndis.NdisCloseAdapterEx)(NdisBindingHandle) : NDIS_STATUS_FAILURE)

#define NdisAllocateNetBufferListPool(NdisHandle, Parameters) \
    (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisAllocateNetBufferListPool ? (NDIS_HANDLE)(ETH_USER_VAR->Ndis.NdisAllocateNetBufferListPool)(NdisHandle, Parameters) : NULL)

#define NdisFreeNetBufferListPool(PoolHandle) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisFreeNetBufferListPool) (ETH_USER_VAR->Ndis.NdisFreeNetBufferListPool)(PoolHandle); } while (0)

#define NdisAllocateNetBufferAndNetBufferList(PoolHandle, ContextSize, ContextBackFill, MdlChain, DataOffset, DataLength) \
    (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisAllocateNetBufferAndNetBufferList ? (PNET_BUFFER_LIST)(ETH_USER_VAR->Ndis.NdisAllocateNetBufferAndNetBufferList)(PoolHandle, ContextSize, ContextBackFill, MdlChain, DataOffset, DataLength) : NULL)

#define NdisFreeNetBufferList(NetBufferList) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisFreeNetBufferList) (ETH_USER_VAR->Ndis.NdisFreeNetBufferList)(NetBufferList); } while (0)

#define NdisSendNetBufferLists(NdisBindingHandle, NetBufferLists, PortNumber, SendFlags) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisSendNetBufferLists) (ETH_USER_VAR->Ndis.NdisSendNetBufferLists)(NdisBindingHandle, NetBufferLists, PortNumber, SendFlags); } while (0)

#define NdisReturnNetBufferLists(NdisBindingHandle, NetBufferLists, ReturnFlags) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisReturnNetBufferLists) (ETH_USER_VAR->Ndis.NdisReturnNetBufferLists)(NdisBindingHandle, NetBufferLists, ReturnFlags); } while (0)

#define NdisOidRequest(NdisBindingHandle, OidRequest) \
    (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisOidRequest ? ETH_USER_VAR->Ndis.NdisOidRequest(NdisBindingHandle, OidRequest) : NDIS_STATUS_FAILURE)

#define NdisCancelOidRequest(NdisBindingHandle, RequestId) \
    do { if (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisCancelOidRequest) ETH_USER_VAR->Ndis.NdisCancelOidRequest(NdisBindingHandle, RequestId); } while (0)

#define NdisReEnumerateProtocolBindings(NdisProtocolHandle) \
    (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisReEnumerateProtocolBindings ? ETH_USER_VAR->Ndis.NdisReEnumerateProtocolBindings(NdisProtocolHandle) : NDIS_STATUS_FAILURE)

#define NdisGetDataBuffer(NetBuffer, BytesNeeded, Storage, AlignMultiple, AlignOffset) \
    (ETH_USER_VAR && ETH_USER_VAR->Ndis.NdisGetDataBuffer ? ETH_USER_VAR->Ndis.NdisGetDataBuffer(NetBuffer, BytesNeeded, Storage, AlignMultiple, AlignOffset) : NULL)

MK_ETH_SERVER g_EthServer = {0};
static MK_TRANSPORT_CONTEXT g_EthTransportContext = {0};

// 通道致命失败状态：放在文件级，EthServer_Stop 之后依然可读（供 R3 状态查询）
static volatile LONG g_ChannelFatalLatched = 0;
static volatile LONG g_ChannelFailReason = 0;
static volatile LONG g_ChannelFailStatus = 0;

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

/*
 * 通道健康度查询：R3 通过 IOCTL_MK_GET_STATUS 读取。
 * 即使通道已判死、传输层已被拆掉，失败原因/状态码仍然可读（模块级静态区）。
 */
NTSTATUS EthServer_GetChannelInfo(_Out_ PMK_ETH_CHANNEL_INFO pInfo)
{
    if (!pInfo)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(pInfo, sizeof(*pInfo));

    MK_DM_STATUS DmStatus;
    RtlZeroMemory(&DmStatus, sizeof(DmStatus));
    MkDm_GetStatus(&DmStatus);

    pInfo->fReady = DmStatus.fReady;
    pInfo->fArmed = DmStatus.fArmed;
    pInfo->fFatal = (InterlockedCompareExchange(&g_ChannelFatalLatched, 0, 0) != 0) ? TRUE : FALSE;
    pInfo->FailReason = (ULONG)InterlockedCompareExchange(&g_ChannelFailReason, 0, 0);
    pInfo->FailStatus = (ULONG)InterlockedCompareExchange(&g_ChannelFailStatus, 0, 0);
    pInfo->FilterCount = DmStatus.FilterCount;
    pInfo->IfIndex = DmStatus.IfIndex;
    pInfo->TxDirect = DmStatus.Stats.TxDirect;
    pInfo->TxFailed = DmStatus.Stats.TxFailed;
    pInfo->RxStolen = DmStatus.Stats.RxStolen;
    return STATUS_SUCCESS;
}

static NDIS_STATUS EthSetPacketFilter(_In_ PMK_ETH_ADAPTER_BINDING pBinding, _In_ ULONG PacketFilter)
{
    NDIS_OID_REQUEST OidReq;
    NDIS_STATUS Status;
    ULONG FilterVal = PacketFilter;

    if (!pBinding || !pBinding->BindingHandle)
    {
        ExceptionReporter::Report("EthSetPacketFilter", NDIS_STATUS_INVALID_PARAMETER, "Null binding or BindingHandle");
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
            ExceptionReporter::ReportFormat("EthSetPacketFilter", STATUS_TIMEOUT,
                                            "OID_GEN_CURRENT_PACKET_FILTER timed out (filter=0x%08X)", PacketFilter);
            NdisCancelOidRequest(pBinding->BindingHandle, &OidReq);
            KeWaitForSingleObject(&pBinding->OidCompleteEvent, Executive, KernelMode, FALSE, NULL);
        }
        Status = pBinding->OidStatus;
    }
    if (Status != NDIS_STATUS_SUCCESS)
    {
        ExceptionReporter::ReportFormat("EthSetPacketFilter", Status,
                                        "OID_GEN_CURRENT_PACKET_FILTER failed: status=0x%08X filter=0x%08X",
                                        Status, PacketFilter);
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

    NTSTATUS OpenKeyStatus = ZwOpenKey(&hSrc, KEY_READ, &oaSrc);
    if (!NT_SUCCESS(OpenKeyStatus))
    {
        ExceptionReporter::ReportFormat("EthEnsureProtocolLinkage", OpenKeyStatus,
                                        "ZwOpenKey(Tcpip\\Linkage) failed: status=0x%08X", OpenKeyStatus);
        return;
    }

    NTSTATUS CreateKeyStatus = ZwCreateKey(&hDst, KEY_ALL_ACCESS, &oaDst, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (NT_SUCCESS(CreateKeyStatus))
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
        else
        {
            ExceptionReporter::Report("EthEnsureProtocolLinkage", STATUS_INSUFFICIENT_RESOURCES,
                                      "ExAllocatePoolWithTag failed for KEY_VALUE_PARTIAL_INFORMATION");
        }
        ZwClose(hDst);
    }
    else
    {
        ExceptionReporter::ReportFormat("EthEnsureProtocolLinkage", CreateKeyStatus,
                                        "ZwCreateKey(target Linkage) failed: status=0x%08X", CreateKeyStatus);
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
        ExceptionReporter::Report("EthProtocolBindAdapterEx", NDIS_STATUS_FAILURE,
                                  "BindAdapterEx invoked while EthServer is not running");
        return NDIS_STATUS_FAILURE;
    }

    // 只在 802.3 介质上工作；其它介质（WAN Miniport / 隧道虚拟网卡）在开适配器之前就跳过，
    // 避免"开了又关"的资源浪费与绑定噪音
    if (BindParameters->MediaType != NdisMedium802_3)
    {
        DBG("[EthServer] Skip non-802.3 adapter %wZ (media=%u)", BindParameters->AdapterName,
            (ULONG)BindParameters->MediaType);
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    pBinding = (PMK_ETH_ADAPTER_BINDING)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(MK_ETH_ADAPTER_BINDING), MK_ETH_POOL_TAG);
    if (!pBinding)
    {
        ExceptionReporter::Report("EthProtocolBindAdapterEx", NDIS_STATUS_RESOURCES,
                                  "ExAllocatePoolWithTag failed for MK_ETH_ADAPTER_BINDING");
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

        // 方案 B：先解析 MiniportBlock 并接管底层指示槽位，通过后才纳入管理链表。
        // 没有标准发送兜底 —— 通道拿不到就直接失败并卸载（致命回调已在该模块内触发）。
        NTSTATUS DmStatus = MkDm_AttachBinding(pBinding, pBinding->BindingHandle);
        if (!NT_SUCCESS(DmStatus))
        {
            DBG("[x] EthServer: DirectMiniport attach FAILED on %wZ: 0x%08X -> close + fail bind",
                BindParameters->AdapterName, DmStatus);
            ExceptionReporter::ReportFormat("EthProtocolBindAdapterEx", DmStatus,
                                            "MkDm_AttachBinding failed on 802.3 adapter (MAC=%02X:%02X:%02X:%02X:%02X:%02X, status=0x%08X)",
                                            pBinding->LocalMac[0], pBinding->LocalMac[1], pBinding->LocalMac[2],
                                            pBinding->LocalMac[3], pBinding->LocalMac[4], pBinding->LocalMac[5],
                                            DmStatus);

            pBinding->fActive = FALSE;
            KeClearEvent(&pBinding->CloseCompleteEvent);
            NDIS_STATUS CloseStatus = NdisCloseAdapterEx(pBinding->BindingHandle);
            if (CloseStatus == NDIS_STATUS_PENDING)
            {
                KeWaitForSingleObject(&pBinding->CloseCompleteEvent, Executive, KernelMode, FALSE, NULL);
            }
            pBinding->BindingHandle = NULL;
            ExFreePoolWithTag(pBinding, MK_ETH_POOL_TAG);
            return DmStatus;
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
        ExceptionReporter::ReportFormat("EthProtocolBindAdapterEx", Status,
                                        "NdisOpenAdapterEx failed (MAC=%02X:%02X:%02X:%02X:%02X:%02X, status=0x%08X)",
                                        pBinding->LocalMac[0], pBinding->LocalMac[1], pBinding->LocalMac[2],
                                        pBinding->LocalMac[3], pBinding->LocalMac[4], pBinding->LocalMac[5],
                                        Status);
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

    // 先摘除底层指示槽位，避免 unbind 释放后仍有帧流入消费逻辑
    MkDm_DetachBinding(pBinding);

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

/*
 * 分片重组核心：既被 NDIS 协议上行路径调用，也被 DirectMiniport 的
 * 底层指示节流器（miniport 边界截留）调用，保证两条路径语义一致。
 */
static VOID EthServer_ConsumeFrame(
    _In_ PMK_ETH_ADAPTER_BINDING pBinding,
    _In_reads_bytes_(cbFrame) const UCHAR *pFrame,
    _In_ ULONG cbFrame)
{
    if (!g_EthServer.fRunning || !pBinding || !pBinding->fActive || !pFrame)
    {
        return;
    }
    if (cbFrame < sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR))
    {
        return;
    }

    PMK_ETH_FRAME_HDR pEth = (PMK_ETH_FRAME_HDR)pFrame;
    USHORT ethType = (USHORT)((pEth->EtherType >> 8) | (pEth->EtherType << 8));

    if (ethType != g_EthServer.EtherType || RtlEqualMemory(pEth->SrcMac, pBinding->LocalMac, 6))
    {
        return;
    }

    PMK_ETH_PACKET_HDR pPkt = (PMK_ETH_PACKET_HDR)((PUCHAR)pFrame + sizeof(MK_ETH_FRAME_HDR));
    ULONG cbPayloadRoom = cbFrame - sizeof(MK_ETH_FRAME_HDR) - sizeof(MK_ETH_PACKET_HDR);

    if (pPkt->dwMagic != MK_ETH_SLICE_MAGIC || pPkt->Reserved == MK_ETH_FLAG_RESPONSE ||
        pPkt->cbSliceData > cbPayloadRoom)
    {
        return;
    }

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_EthServer.RecvLock, &lockHandle);

    if (!g_EthServer.fProcessing)
    {
        static const UCHAR s_ZeroMac[6] = {0};
        if (!RtlEqualMemory(pEth->SrcMac, s_ZeroMac, 6))
        {
            RtlCopyMemory(g_EthServer.TargetClientMac, pEth->SrcMac, 6);
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
            g_EthServer.cbRecvSliceStride = (pPkt->TotalSlices > 1 && pPkt->cbSliceData > 0)
                                                ? pPkt->cbSliceData
                                                : MK_ETH_MAX_SLICE_PAYLOAD;
        }

        ULONG stride = g_EthServer.cbRecvSliceStride ? g_EthServer.cbRecvSliceStride : MK_ETH_MAX_SLICE_PAYLOAD;
        ULONG dstOffset = (ULONG)pPkt->SliceIndex * stride;
        if (pPkt->dwSequence == g_EthServer.dwLastRecvSequence &&
            (dstOffset + pPkt->cbSliceData) <= MK_ETH_SERVER_MAX_PACKET_SIZE)
        {
            ULONG copyOffset = sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR);
            if (g_EthServer.pRecvAssembleBuf)
            {
                RtlCopyMemory(g_EthServer.pRecvAssembleBuf + dstOffset, (PUCHAR)pFrame + copyOffset, pPkt->cbSliceData);
                g_EthServer.cbRecvCurrent = dstOffset + pPkt->cbSliceData;

                if ((pPkt->SliceIndex + 1) >= pPkt->TotalSlices &&
                    g_EthServer.cbRecvCurrent >= g_EthServer.cbRecvExpectedTotal &&
                    g_EthServer.cbRecvExpectedTotal > 0)
                {
                    InterlockedExchange8((volatile CHAR *)&g_EthServer.fProcessing, TRUE);
                    InterlockedExchange(&g_EthServer.ActiveConnections, 1);
                    if (!g_EthServer.fWorkerSpinning)
                    {
                        KeSetEvent(&g_EthServer.WorkerWakeEvent, IO_NETWORK_INCREMENT, FALSE);
                    }
                }
            }
            else
            {
                ExceptionReporter::Report("EthServer_ConsumeFrame", STATUS_INVALID_BUFFER_SIZE,
                                          "pRecvAssembleBuf is NULL during slice reassembly");
            }
        }
        else if (pPkt->dwSequence == g_EthServer.dwLastRecvSequence &&
                 (dstOffset + pPkt->cbSliceData) > MK_ETH_SERVER_MAX_PACKET_SIZE)
        {
            ExceptionReporter::ReportFormat("EthServer_ConsumeFrame", STATUS_BUFFER_OVERFLOW,
                                            "Slice reassembly overflow: seq=%u slice=%u/%u dstOffset=%u sliceLen=%u max=%u",
                                            pPkt->dwSequence, (ULONG)pPkt->SliceIndex, (ULONG)pPkt->TotalSlices,
                                            dstOffset, pPkt->cbSliceData, (ULONG)MK_ETH_SERVER_MAX_PACKET_SIZE);
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

/*
 * 底层指示节流器回调：在 NDIS Miniport 边界（过滤器链之下）判定帧归属。
 * 返回 TRUE → 本通道已消费，帧不会再上行 → Npcap/Wireshark 全链不可见。
 */
static BOOLEAN EthServer_TapSink(
    _In_reads_bytes_(cbFrame) const UCHAR *pFrame,
    _In_ ULONG cbFrame)
{
    if (!g_EthServer.fRunning || !pFrame || cbFrame < sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR))
    {
        return FALSE;
    }

    PMK_ETH_FRAME_HDR pEth = (PMK_ETH_FRAME_HDR)pFrame;
    USHORT ethType = (USHORT)((pEth->EtherType >> 8) | (pEth->EtherType << 8));
    if (ethType != g_EthServer.EtherType)
    {
        return FALSE;
    }

    PMK_ETH_PACKET_HDR pPkt = (PMK_ETH_PACKET_HDR)((PUCHAR)pFrame + sizeof(MK_ETH_FRAME_HDR));
    if (pPkt->dwMagic != MK_ETH_SLICE_MAGIC || pPkt->Reserved == MK_ETH_FLAG_RESPONSE)
    {
        return FALSE;
    }

    PMK_ETH_ADAPTER_BINDING pBinding = (PMK_ETH_ADAPTER_BINDING)MkDm_GetCurrentRxBinding();
    if (!pBinding || !pBinding->fActive)
    {
        pBinding = NULL;
        KLOCK_QUEUE_HANDLE listLock;
        KeAcquireInStackQueuedSpinLock(&g_EthServer.AdapterLock, &listLock);
        for (PLIST_ENTRY pEntry = g_EthServer.AdapterList.Flink; pEntry != &g_EthServer.AdapterList; pEntry = pEntry->Flink)
        {
            PMK_ETH_ADAPTER_BINDING pCur = CONTAINING_RECORD(pEntry, MK_ETH_ADAPTER_BINDING, Link);
            if (pCur->fActive && RtlEqualMemory(pCur->LocalMac, pEth->DstMac, 6))
            {
                pBinding = pCur;
                break;
            }
        }
        if (!pBinding && !IsListEmpty(&g_EthServer.AdapterList))
        {
            pBinding = CONTAINING_RECORD(g_EthServer.AdapterList.Flink, MK_ETH_ADAPTER_BINDING, Link);
        }
        KeReleaseInStackQueuedSpinLock(&listLock);
    }

    if (!pBinding)
    {
        pBinding = g_EthServer.pTargetAdapter;
    }
    if (!pBinding)
    {
        return FALSE;
    }

    EthServer_ConsumeFrame(pBinding, pFrame, cbFrame);
    return TRUE;
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
        for (PNET_BUFFER_LIST pCurrNbl = NetBufferLists; pCurrNbl != NULL; pCurrNbl = NET_BUFFER_LIST_NEXT_NBL(pCurrNbl))
        {
            for (PNET_BUFFER pNb = NET_BUFFER_LIST_FIRST_NB(pCurrNbl); pNb != NULL; pNb = NET_BUFFER_NEXT_NB(pNb))
            {
                ULONG DataLength = NET_BUFFER_DATA_LENGTH(pNb);
                if (DataLength >= sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR) && DataLength <= 9216)
                {
                    UCHAR FrameBuffer[1600];
                    PUCHAR pData = (PUCHAR)NdisGetDataBuffer(pNb, DataLength, NULL, 1, 0);
                    if (pData == NULL && DataLength <= sizeof(FrameBuffer))
                    {
                        pData = (PUCHAR)NdisGetDataBuffer(pNb, DataLength, FrameBuffer, 1, 0);
                    }
                    if (pData)
                    {
                        EthServer_ConsumeFrame(pBinding, pData, DataLength);
                    }
                }
            }
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
        NET_BUFFER_LIST_NEXT_NBL(pCurr) = NULL;
        PMK_ETH_TX_SLOT pSlot = (PMK_ETH_TX_SLOT)pCurr->ProtocolReserved[0];
        if (pSlot)
        {
            pCurr->ProtocolReserved[0] = NULL;
            NdisFreeNetBufferList(pCurr);
            InterlockedExchange(&pSlot->fInUse, 0);
        }
        else
        {
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
        }
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

static PMK_ETH_TX_SLOT EthAcquireTxSlot(VOID)
{
    if (!g_EthServer.pTxFrameMemory)
    {
        return NULL;
    }
    ULONG startIdx = g_EthServer.TxSlotCursor;
    for (ULONG step = 0; step < 64; ++step)
    {
        ULONG idx = (startIdx + step) & (MK_ETH_TX_POOL_COUNT - 1);
        PMK_ETH_TX_SLOT pSlot = &g_EthServer.TxSlots[idx];
        if (pSlot->pMdl && pSlot->pFrameBuf &&
            InterlockedCompareExchange(&pSlot->fInUse, 1, 0) == 0)
        {
            g_EthServer.TxSlotCursor = (idx + 1) & (MK_ETH_TX_POOL_COUNT - 1);
            return pSlot;
        }
    }
    return NULL;
}

/*
 * 未送达的发送批次回收：直连失败时 NBL 从未进入 Miniport，必须自行释放，
 * 否则卸载前会留下 NBL 池块（MDL 与池缓冲随批一起放掉）。
 */
static VOID EthServer_ReclaimBatch(_In_ PNET_BUFFER_LIST pBatchHead)
{
    PNET_BUFFER_LIST pCurr = pBatchHead;
    while (pCurr != NULL)
    {
        PNET_BUFFER_LIST pNext = NET_BUFFER_LIST_NEXT_NBL(pCurr);
        NET_BUFFER_LIST_NEXT_NBL(pCurr) = NULL;

        PMK_ETH_TX_SLOT pSlot = (PMK_ETH_TX_SLOT)pCurr->ProtocolReserved[0];
        if (pSlot)
        {
            pCurr->ProtocolReserved[0] = NULL;
            NdisFreeNetBufferList(pCurr);
            InterlockedExchange(&pSlot->fInUse, 0);
        }
        else
        {
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
        }
        pCurr = pNext;
    }
}

/*
 * 通道致命失败的"失败标志 + 通知 R3"实现：
 *   1) 置致命标志与失败原因（模块级静态，EthServer_Stop 之后仍然可读）；
 *   2) 异步拆掉传输通道（停 worker / 解绑 / 回滚槽位），但**保留设备对象**；
 *   3) 不调用 DriverCore::TriggerUnload()，由 loader 读到状态后自己
 *      DeleteService / ControlService(STOP)，卸载时机交给 R3 决定。
 */
static volatile BOOLEAN g_fFatalTeardownQueued = FALSE;
static WORK_QUEUE_ITEM g_FatalTeardownItem;

static VOID EthServer_FatalTeardownRoutine(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    DBG("[*] EthServer: fatal teardown -> stop transport channel, keep device object for R3 status query");
    EthServer_Stop(g_EthServer.UserVar);
    DBG("[*] EthServer: fatal teardown done (device object alive, waiting for loader DeleteService)");
}

static VOID EthServer_DmFatal(_In_ ULONG Reason, _In_ NTSTATUS Status)
{
    // 单次闸门：失败标志与拆链工作项都只允许一次
    if (InterlockedExchange(&g_ChannelFatalLatched, 1) != 0)
    {
        return;
    }

    InterlockedExchange(&g_ChannelFailReason, (LONG)Reason);
    InterlockedExchange(&g_ChannelFailStatus, (LONG)Status);

    DBG("[x] EthServer: DirectMiniport channel FAILED (reason=%u, status=0x%08X) -> fail flag set, R3 must DeleteService",
        Reason, Status);
    ExceptionReporter::ReportFormat("EthServer::DirectMiniportFatal", Status,
                                    "DirectMiniport channel unavailable: reason=%u status=0x%08X; device kept, "
                                    "waiting for loader to delete service",
                                    Reason, Status);

    if (!InterlockedExchange8((volatile CHAR *)&g_fFatalTeardownQueued, TRUE))
    {
        ExInitializeWorkItem(&g_FatalTeardownItem, EthServer_FatalTeardownRoutine, NULL);
        ExQueueWorkItem(&g_FatalTeardownItem, DelayedWorkQueue);
    }
}

/*
 * 发送批次：只走 Miniport 直连（绕过整条 NDIS 过滤器链）。
 * 没有 NdisSendNetBufferLists 兜底 —— 直连不可用即判死并卸载。
 */
static VOID EthServer_TransmitBatch(_In_ PMK_ETH_ADAPTER_BINDING pAdapter, _In_ PNET_BUFFER_LIST pBatchHead)
{
    if (!pBatchHead || !pAdapter || !pAdapter->BindingHandle)
    {
        ExceptionReporter::ReportFormat("EthServer_TransmitBatch", STATUS_INVALID_PARAMETER,
                                        "Invalid batch parameters (pBatchHead=0x%p, pAdapter=0x%p)",
                                        pBatchHead, pAdapter);
        if (pBatchHead)
        {
            EthServer_ReclaimBatch(pBatchHead);
        }
        return;
    }

    BOOLEAN fHandled = FALSE;
    NTSTATUS Status = MkDm_Send(pBatchHead, 0, &fHandled);
    if (!NT_SUCCESS(Status) || !fHandled)
    {
        DBG("[x] EthServer: direct send rejected (status=0x%08X, handled=%u) -> reclaim + fatal", Status, fHandled);
        ExceptionReporter::ReportFormat("EthServer_TransmitBatch",
                                        NT_SUCCESS(Status) ? STATUS_UNSUCCESSFUL : Status,
                                        "MkDm_Send rejected batch (status=0x%08X, handled=%u)",
                                        Status, (ULONG)fHandled);
        EthServer_ReclaimBatch(pBatchHead);
        EthServer_DmFatal(MK_DM_FAIL_TX, Status);
    }
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
        ExceptionReporter::ReportFormat("EthServer_SendReply", STATUS_INVALID_PARAMETER,
                                        "Invalid parameters (pAdapter=0x%p, active=%u, pData=0x%p, cbData=%u)",
                                        pAdapter, pAdapter ? (ULONG)pAdapter->fActive : 0, pData, cbData);
        return STATUS_INVALID_PARAMETER;
    }

    USHORT totalSlices = (USHORT)((cbData + MK_ETH_MAX_SLICE_PAYLOAD - 1) / MK_ETH_MAX_SLICE_PAYLOAD);
    if (totalSlices == 0) totalSlices = 1;

    ULONG cbRemaining = cbData;
    ULONG cbOffset = 0;
    USHORT etherTypeNet = (USHORT)((g_EthServer.EtherType >> 8) | (g_EthServer.EtherType << 8));

    PNET_BUFFER_LIST pBatchHead = NULL;
    PNET_BUFFER_LIST pBatchTail = NULL;
    ULONG cBatchCount = 0;

    for (USHORT sliceIdx = 0; sliceIdx < totalSlices; ++sliceIdx)
    {
        ULONG cbSlice = (cbRemaining > MK_ETH_MAX_SLICE_PAYLOAD) ? MK_ETH_MAX_SLICE_PAYLOAD : cbRemaining;
        ULONG cbRawLen = sizeof(MK_ETH_FRAME_HDR) + sizeof(MK_ETH_PACKET_HDR) + cbSlice;
        ULONG cbFrameTotal = (cbRawLen < 60) ? 60 : cbRawLen;

        PUCHAR pFrameBuf = NULL;
        PNET_BUFFER_LIST pNbl = NULL;
        PMK_ETH_TX_SLOT pSlot = EthAcquireTxSlot();

        if (pSlot)
        {
            pFrameBuf = pSlot->pFrameBuf;
            pNbl = NdisAllocateNetBufferAndNetBufferList(
                g_EthServer.NblPoolHandle,
                0,
                0,
                pSlot->pMdl,
                0,
                cbFrameTotal);
            if (!pNbl)
            {
                InterlockedExchange(&pSlot->fInUse, 0);
                pSlot = NULL;
            }
            else
            {
                NET_BUFFER_LIST_NEXT_NBL(pNbl) = NULL;
                pNbl->ProtocolReserved[0] = pSlot;
            }
        }
        if (!pSlot)
        {
            pFrameBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, cbFrameTotal, MK_ETH_POOL_TAG);
            if (!pFrameBuf)
            {
                ExceptionReporter::ReportFormat("EthServer_SendReply", STATUS_INSUFFICIENT_RESOURCES,
                                                "ExAllocatePoolWithTag failed for fallback TX frame (slice=%u/%u, cbFrameTotal=%u)",
                                                (ULONG)sliceIdx, (ULONG)totalSlices, cbFrameTotal);
                break;
            }
            PMDL pMdl = IoAllocateMdl(pFrameBuf, cbFrameTotal, FALSE, FALSE, NULL);
            if (!pMdl)
            {
                ExceptionReporter::ReportFormat("EthServer_SendReply", STATUS_INSUFFICIENT_RESOURCES,
                                                "IoAllocateMdl failed for fallback TX frame (slice=%u/%u, cbFrameTotal=%u)",
                                                (ULONG)sliceIdx, (ULONG)totalSlices, cbFrameTotal);
                ExFreePoolWithTag(pFrameBuf, MK_ETH_POOL_TAG);
                break;
            }
            MmBuildMdlForNonPagedPool(pMdl);

            pNbl = NdisAllocateNetBufferAndNetBufferList(
                g_EthServer.NblPoolHandle,
                0,
                0,
                pMdl,
                0,
                cbFrameTotal);
            if (!pNbl)
            {
                ExceptionReporter::ReportFormat("EthServer_SendReply", STATUS_INSUFFICIENT_RESOURCES,
                                                "NdisAllocateNetBufferAndNetBufferList failed (slice=%u/%u, cbFrameTotal=%u)",
                                                (ULONG)sliceIdx, (ULONG)totalSlices, cbFrameTotal);
                IoFreeMdl(pMdl);
                ExFreePoolWithTag(pFrameBuf, MK_ETH_POOL_TAG);
                break;
            }
            NET_BUFFER_LIST_NEXT_NBL(pNbl) = NULL;
            pNbl->ProtocolReserved[0] = NULL;
        }

        if (cbRawLen < 60)
        {
            RtlZeroMemory(pFrameBuf + cbRawLen, 60 - cbRawLen);
        }

        PMK_ETH_FRAME_HDR pEthHdr = (PMK_ETH_FRAME_HDR)pFrameBuf;
        RtlCopyMemory(pEthHdr->DstMac, pDstMac, 6);
        RtlCopyMemory(pEthHdr->SrcMac, pAdapter->LocalMac, 6);
        pEthHdr->EtherType = etherTypeNet;

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

        pNbl->SourceHandle = pAdapter->BindingHandle;
        if (!pBatchHead)
        {
            pBatchHead = pNbl;
            pBatchTail = pNbl;
        }
        else
        {
            NET_BUFFER_LIST_NEXT_NBL(pBatchTail) = pNbl;
            pBatchTail = pNbl;
        }
        cBatchCount++;

        cbRemaining -= cbSlice;
        cbOffset += cbSlice;

        if (cBatchCount >= MK_ETH_SEND_BATCH_SIZE)
        {
            EthServer_TransmitBatch(pAdapter, pBatchHead);
            pBatchHead = NULL;
            pBatchTail = NULL;
            cBatchCount = 0;
            if (cbRemaining > 0 && totalSlices > 16)
            {
                KeStallExecutionProcessor(2);
            }
        }
    }

    if (pBatchHead)
    {
        EthServer_TransmitBatch(pAdapter, pBatchHead);
    }

    return STATUS_SUCCESS;
}

static VOID EthWorkerThreadRoutine(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    PVOID WaitObjects[2];
    WaitObjects[0] = &g_EthServer.WorkerExitEvent;
    WaitObjects[1] = &g_EthServer.WorkerWakeEvent;

    KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);
    DBG("[EthServer] Worker thread entered execution loop");

    while (g_EthServer.fRunning)
    {
        if (!g_EthServer.fProcessing)
        {
            InterlockedExchange8((volatile CHAR *)&g_EthServer.fWorkerSpinning, TRUE);
            ULONG maxSpin = (g_EthServer.ActiveConnections != 0) ? 2500000 : 200000;
            for (ULONG spin = 0; spin < maxSpin; ++spin)
            {
                if (g_EthServer.fProcessing || !g_EthServer.fRunning)
                {
                    break;
                }
                YieldProcessor();
            }
            InterlockedExchange8((volatile CHAR *)&g_EthServer.fWorkerSpinning, FALSE);

            if (!g_EthServer.fProcessing)
            {
                MkDm_Refresh();
            }
        }

        if (!g_EthServer.fProcessing)
        {
            NTSTATUS WaitStatus = KeWaitForMultipleObjects(2, WaitObjects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
            if (WaitStatus == STATUS_WAIT_0 || !g_EthServer.fRunning)
            {
                break;
            }
        }
        else
        {
            KeClearEvent(&g_EthServer.WorkerWakeEvent);
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
                else
                {
                    ExceptionReporter::ReportFormat("EthWorkerThreadRoutine", STATUS_DEVICE_NOT_CONNECTED,
                                                    "No active target adapter to send RPC reply (seq=%u, cbOut=%u)",
                                                    dwSeq, cbOut);
                }
            }
            else
            {
                ExceptionReporter::ReportFormat("EthWorkerThreadRoutine",
                                                NT_SUCCESS(RpcStatus) ? STATUS_UNSUCCESSFUL : RpcStatus,
                                                "DispatchCommandEx failed or returned empty reply (status=0x%08X, seq=%u, cbIn=%u, cbOut=%u)",
                                                RpcStatus, dwSeq, cbIn, cbOut);
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

    // 方案 B：初始化 NDIS 底层直连模块（ndis.sys 范围/偏移表）。
    // 先挂致命回调再初始化：Init 自身失败也必须能"提示失败 + 自动卸载"。
    MkDm_SetFatalHandler(EthServer_DmFatal);
    NTSTATUS DmInitStatus = MkDm_Init(UserVar);
    if (!NT_SUCCESS(DmInitStatus))
    {
        DBG("[x] EthServer: DirectMiniport init FAILED: 0x%08X (channel unavailable, auto-unload)", DmInitStatus);
        ExceptionReporter::ReportFormat("EthServer_Init", DmInitStatus,
                                        "MkDm_Init failed: status=0x%08X", DmInitStatus);
        EthServer_Stop(UserVar);
        return DmInitStatus;
    }

    g_EthServer.pRecvAssembleBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, MK_ETH_SERVER_MAX_PACKET_SIZE, MK_ETH_POOL_TAG);
    g_EthServer.pDirectOutBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, MK_ETH_SERVER_MAX_PACKET_SIZE, MK_ETH_POOL_TAG);
    if (!g_EthServer.pRecvAssembleBuf || !g_EthServer.pDirectOutBuf)
    {
        ExceptionReporter::ReportFormat("EthServer_Init", STATUS_INSUFFICIENT_RESOURCES,
                                        "ExAllocatePoolWithTag failed for assemble/direct buffers (recv=0x%p, out=0x%p, size=%u)",
                                        g_EthServer.pRecvAssembleBuf, g_EthServer.pDirectOutBuf,
                                        (ULONG)MK_ETH_SERVER_MAX_PACKET_SIZE);
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
        ExceptionReporter::Report("EthServer_Init", STATUS_INSUFFICIENT_RESOURCES,
                                  "NdisAllocateNetBufferListPool failed");
        EthServer_Stop(UserVar);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_EthServer.cbRecvSliceStride = MK_ETH_MAX_SLICE_PAYLOAD;
    g_EthServer.pTxFrameMemory = (PUCHAR)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        (SIZE_T)MK_ETH_TX_POOL_COUNT * MK_ETH_FRAME_BUF_STRIDE,
        MK_ETH_POOL_TAG);
    if (g_EthServer.pTxFrameMemory)
    {
        RtlZeroMemory(g_EthServer.pTxFrameMemory, (SIZE_T)MK_ETH_TX_POOL_COUNT * MK_ETH_FRAME_BUF_STRIDE);
        for (ULONG i = 0; i < MK_ETH_TX_POOL_COUNT; ++i)
        {
            PMK_ETH_TX_SLOT pSlot = &g_EthServer.TxSlots[i];
            pSlot->fInUse = 0;
            pSlot->pFrameBuf = g_EthServer.pTxFrameMemory + (SIZE_T)i * MK_ETH_FRAME_BUF_STRIDE;
            pSlot->pMdl = IoAllocateMdl(pSlot->pFrameBuf, MK_ETH_FRAME_BUF_STRIDE, FALSE, FALSE, NULL);
            if (pSlot->pMdl)
            {
                MmBuildMdlForNonPagedPool(pSlot->pMdl);
            }
            else
            {
                ExceptionReporter::ReportFormat("EthServer_Init", STATUS_INSUFFICIENT_RESOURCES,
                                                "IoAllocateMdl failed for preallocated TX slot %u", i);
            }
        }
    }
    else
    {
        ExceptionReporter::ReportFormat("EthServer_Init", STATUS_INSUFFICIENT_RESOURCES,
                                        "ExAllocatePoolWithTag failed for pTxFrameMemory (count=%u, stride=%u)",
                                        (ULONG)MK_ETH_TX_POOL_COUNT, (ULONG)MK_ETH_FRAME_BUF_STRIDE);
    }

    // 尝试卸载可能正在占位的系统闲置 ndisuio.sys，确保 NDISUIO 协议名 100% 可被本驱动接管并自动绑定全网卡
    {
        UNICODE_STRING uNdisuioSvc = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ndisuio");
        ZwUnloadDriver(&uNdisuioSvc);
    }

    // 同步拷贝 Tcpip\Linkage 到 Ndisuio\Linkage 及后备协议名，确保无 INF 场景下 NDIS 自动绑定所有物理网卡
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

    // 注册底层截留判定回调（miniport 边界签名帧消费）
    MkDm_SetRxSink(EthServer_TapSink);

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
        ExceptionReporter::ReportFormat("EthServer_Init", Status,
                                        "NdisRegisterProtocolDriver(NDISUIO) failed (0x%08X), trying fallback NDISTEST6",
                                        Status);
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
        ExceptionReporter::ReportFormat("EthServer_Init", Status,
                                        "NdisRegisterProtocolDriver failed on both NDISUIO and NDISTEST6: status=0x%08X",
                                        Status);
        EthServer_Stop(UserVar);
        return Status;
    }

    // 主动触发 NDIS 重新枚举协议绑定，确保所有已就绪网卡立即回调 EthProtocolBindAdapterEx
    NdisReEnumerateProtocolBindings(g_EthServer.ProtocolHandle);

    if (!MkDm_IsReady())
    {
        DBG("[x] EthServer: No 802.3 adapter attached to DirectMiniport after binding enumeration!");
        ExceptionReporter::Report("EthServer_Init", STATUS_DEVICE_NOT_READY,
                                  "No 802.3 adapter attached to DirectMiniport after NdisReEnumerateProtocolBindings");
        EthServer_DmFatal(MK_DM_FAIL_RESOLVE, STATUS_DEVICE_NOT_READY);
        EthServer_Stop(UserVar);
        return STATUS_DEVICE_NOT_READY;
    }

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
        ExceptionReporter::ReportFormat("EthServer_Init", ThreadStatus,
                                        "PsCreateSystemThread failed: status=0x%08X", ThreadStatus);
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

    // 1) 先切断 RX Sink 并停止 Worker 线程，确保不再产生任何新的直连发送（MkDm_Send）
    MkDm_SetRxSink(NULL);
    KeSetEvent(&g_EthServer.WorkerExitEvent, IO_NO_INCREMENT, FALSE);
    if (g_EthServer.pWorkerThread)
    {
        KeWaitForSingleObject(g_EthServer.pWorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_EthServer.pWorkerThread);
        g_EthServer.pWorkerThread = NULL;
    }

    // 2) 在摘除 MkDmSendCompleteThunk 之前排空所有在途 TX NBL，防止尾包完成时流入 wfplwf 导致计数下溢
    for (ULONG i = 0; i < MK_ETH_TX_POOL_COUNT; ++i)
    {
        for (ULONG wait = 0; wait < 2000 && InterlockedCompareExchange(&g_EthServer.TxSlots[i].fInUse, 0, 0) != 0; ++wait)
        {
            KeStallExecutionProcessor(50);
        }
    }

    // 3) 摘除 RX/TXComplete 底层槽位并排空在途 Thunk 调用
    MkDm_Shutdown(UserVar);

    // 4) 注销协议驱动（此时 wfplwf 等 LWF 的 In-Flight 计数严格为 0，PauseFilter 瞬时完成）
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

    for (ULONG i = 0; i < MK_ETH_TX_POOL_COUNT; ++i)
    {
        for (ULONG wait = 0; wait < 1000 && InterlockedCompareExchange(&g_EthServer.TxSlots[i].fInUse, 0, 0) != 0; ++wait)
        {
            KeStallExecutionProcessor(10);
        }

        if (g_EthServer.TxSlots[i].pMdl)
        {
            IoFreeMdl(g_EthServer.TxSlots[i].pMdl);
            g_EthServer.TxSlots[i].pMdl = NULL;
        }
        g_EthServer.TxSlots[i].pFrameBuf = NULL;
        g_EthServer.TxSlots[i].fInUse = 0;
    }

    if (g_EthServer.pTxFrameMemory)
    {
        ExFreePoolWithTag(g_EthServer.pTxFrameMemory, MK_ETH_POOL_TAG);
        g_EthServer.pTxFrameMemory = NULL;
    }

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
