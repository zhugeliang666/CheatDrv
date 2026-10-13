#include "rpc_dispatch.h"
#include "Common.h"
#include "leechcore_kernel.h"
#include "Utils.h"
#include "MachenikeString.h"
#include "wsk_server.h"

#ifndef BOOL
typedef int BOOL;
typedef int *PBOOL;
#endif

typedef NTSTATUS(NTAPI *PFN_RtlGetCompressionWorkSpaceSize)(
    _In_ USHORT CompressionFormatAndEngine,
    _Out_ PULONG CompressBufferWorkSpaceSize,
    _Out_ PULONG CompressFragmentWorkSpaceSize);

typedef NTSTATUS(NTAPI *PFN_RtlCompressBuffer)(
    _In_ USHORT CompressionFormatAndEngine,
    _In_reads_bytes_(SourceBufferLength) PUCHAR SourceBuffer,
    _In_ ULONG SourceBufferLength,
    _Out_writes_bytes_to_(DestinationBufferLength, *FinalCompressedSize) PUCHAR DestinationBuffer,
    _In_ ULONG DestinationBufferLength,
    _In_ ULONG ChunkSize,
    _Out_ PULONG FinalCompressedSize,
    _In_ PVOID WorkSpace);

typedef NTSTATUS(NTAPI *PFN_RtlDecompressBuffer)(
    _In_ USHORT CompressionFormatAndEngine,
    _Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize,
    _In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize,
    _Out_ PULONG FinalUncompressedSize);

#define LEECHRPC_COMPRESS_MAXTHREADS 4

typedef struct _LEECHRPC_COMPRESS_SLOT
{
    FAST_MUTEX Lock;
    PVOID pbWorkspace;
} LEECHRPC_COMPRESS_SLOT, *PLEECHRPC_COMPRESS_SLOT;

typedef struct _LEECHRPC_COMPRESS_CONTEXT
{
    BOOLEAN fValid;
    volatile LONG iCompress;
    ULONG cbWorkspace;
    PFN_RtlGetCompressionWorkSpaceSize pfnRtlGetCompressionWorkSpaceSize;
    PFN_RtlCompressBuffer pfnRtlCompressBuffer;
    PFN_RtlDecompressBuffer pfnRtlDecompressBuffer;
    LEECHRPC_COMPRESS_SLOT Slots[LEECHRPC_COMPRESS_MAXTHREADS];
} LEECHRPC_COMPRESS_CONTEXT, *PLEECHRPC_COMPRESS_CONTEXT;

static LEECHRPC_COMPRESS_CONTEXT g_CompressCtx = {0};

#define LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS 16
#define LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS (30 * 1000)

typedef struct _LEECHRPC_CLIENT_ENTRY
{
    ULONG dwRpcClientID;
    HANDLE hLC;
    LONG cActiveRequests;
    ULONG64 qwLastTickCount64;
} LEECHRPC_CLIENT_ENTRY, *PLEECHRPC_CLIENT_ENTRY;

typedef struct _LEECHRPC_SERVER_CONTEXT
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    BOOLEAN fValid;
    FAST_MUTEX LockClientList;
    LEECHRPC_CLIENT_ENTRY ClientList[LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS];
    volatile BOOLEAN fInactivityWatcherThread;
    volatile BOOLEAN fInactivityWatcherThreadIsRunning;
    HANDLE hWatcherThread;
    PVOID pWatcherThread;
} LEECHRPC_SERVER_CONTEXT, *PLEECHRPC_SERVER_CONTEXT;

static LEECHRPC_SERVER_CONTEXT ctxLeechRpc = {0};


static MACHENIKE_KERNEL_INTERFACE *g_pRpcUserVar = NULL;

#ifdef ExAcquireFastMutex
#undef ExAcquireFastMutex
#endif
#define ExAcquireFastMutex(m) do { if (g_pRpcUserVar && g_pRpcUserVar->Func.ExAcquireFastMutex) g_pRpcUserVar->Func.ExAcquireFastMutex(m); } while(0)

#ifdef ExReleaseFastMutex
#undef ExReleaseFastMutex
#endif
#define ExReleaseFastMutex(m) do { if (g_pRpcUserVar && g_pRpcUserVar->Func.ExReleaseFastMutex) g_pRpcUserVar->Func.ExReleaseFastMutex(m); } while(0)

#ifdef ExAllocatePoolWithTag
#undef ExAllocatePoolWithTag
#endif
#define ExAllocatePoolWithTag(t, s, tag) ((g_pRpcUserVar && g_pRpcUserVar->Func.ExAllocatePoolWithTag) ? g_pRpcUserVar->Func.ExAllocatePoolWithTag(t, s, tag) : NULL)

#ifdef ExFreePoolWithTag
#undef ExFreePoolWithTag
#endif
#define ExFreePoolWithTag(p, tag) do { if (g_pRpcUserVar && g_pRpcUserVar->Func.ExFreePoolWithTag) { g_pRpcUserVar->Func.ExFreePoolWithTag(p, tag); } } while(0)


static ULONG64 MkGetTickCount64(VOID)
{
    LARGE_INTEGER TickCount;
    KeQueryTickCount(&TickCount);
    ULONG TimeInc = (g_pRpcUserVar && g_pRpcUserVar->Func.KeQueryTimeIncrement)
                        ? g_pRpcUserVar->Func.KeQueryTimeIncrement()
                        : 156250;
    return (TickCount.QuadPart * TimeInc) / 10000;
}





static HANDLE LeechRPC_LcHandle_Lookup(_In_ ULONG dwRpcClientID)
{
    HANDLE hLC = NULL;
    if (!ctxLeechRpc.fValid || !dwRpcClientID)
    {
        return NULL;
    }
    ExAcquireFastMutex(&ctxLeechRpc.LockClientList);
    for (ULONG i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++)
    {
        if (ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID)
        {
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = MkGetTickCount64();
            hLC = ctxLeechRpc.ClientList[i].hLC;
            break;
        }
    }
    ExReleaseFastMutex(&ctxLeechRpc.LockClientList);
    return hLC;
}

static BOOLEAN LeechRPC_LcHandle_New(_In_ ULONG dwRpcClientID, _In_ HANDLE hLC)
{
    if (!ctxLeechRpc.fValid)
    {
        return FALSE;
    }
    ExAcquireFastMutex(&ctxLeechRpc.LockClientList);
    for (ULONG i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++)
    {
        if (!ctxLeechRpc.ClientList[i].dwRpcClientID)
        {
            ctxLeechRpc.ClientList[i].hLC = hLC;
            ctxLeechRpc.ClientList[i].dwRpcClientID = dwRpcClientID;
            ctxLeechRpc.ClientList[i].cActiveRequests = 0;
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = MkGetTickCount64();
            ExReleaseFastMutex(&ctxLeechRpc.LockClientList);
            return TRUE;
        }
    }
    ExReleaseFastMutex(&ctxLeechRpc.LockClientList);
    return FALSE;
}

static VOID LeechRPC_LcHandle_Return(_In_opt_ HANDLE hLC, _In_ ULONG dwRpcClientID)
{
    if (!ctxLeechRpc.fValid || !hLC || !dwRpcClientID)
    {
        return;
    }
    ExAcquireFastMutex(&ctxLeechRpc.LockClientList);
    for (ULONG i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++)
    {
        if ((ctxLeechRpc.ClientList[i].hLC == hLC) && (ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID))
        {
            if (ctxLeechRpc.ClientList[i].cActiveRequests > 0)
            {
                ctxLeechRpc.ClientList[i].cActiveRequests--;
            }
            break;
        }
    }
    ExReleaseFastMutex(&ctxLeechRpc.LockClientList);
}

VOID LeechRPC_LcHandle_Close(_In_ ULONG dwRpcClientID, _In_ BOOLEAN fReasonTimeout)
{
    if (!ctxLeechRpc.fValid || !dwRpcClientID)
    {
        return; // 引擎未初始化时直接跳过，防止空指针互斥体崩溃
    }

    if (fReasonTimeout)
    {
        DBG("LeechRPC_LcHandle_Close [RpcClientId=0x%08X (%u)]: Handle closed due to inactivity TIMEOUT",
            dwRpcClientID, dwRpcClientID);
    }
    HANDLE hLC = NULL;

    ExAcquireFastMutex(&ctxLeechRpc.LockClientList);
    for (ULONG i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++)
    {
        if (ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID)
        {
            // 防御性超时等待未决请求完成（最多等待 200ms），绝不陷入无休止死循环
            ULONG waitAttempts = 0;
            while (ctxLeechRpc.ClientList[i].cActiveRequests > 0 && waitAttempts < 40)
            {
                ExReleaseFastMutex(&ctxLeechRpc.LockClientList);
                LARGE_INTEGER Delay;
                Delay.QuadPart = -10 * 1000 * 5; // 5ms
                if (ctxLeechRpc.UserVar)
                    ctxLeechRpc.UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Delay);
                waitAttempts++;
                ExAcquireFastMutex(&ctxLeechRpc.LockClientList);
            }
            hLC = ctxLeechRpc.ClientList[i].hLC;
            ctxLeechRpc.ClientList[i].hLC = NULL;
            ctxLeechRpc.ClientList[i].dwRpcClientID = 0;
            ctxLeechRpc.ClientList[i].cActiveRequests = 0;
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = 0;
            break;
        }
    }
    ExReleaseFastMutex(&ctxLeechRpc.LockClientList);

    if (hLC)
    {
        LcClose(hLC);
    }
}

static VOID LeechRPC_LcHandle_CloseAll(VOID)
{
    if (!ctxLeechRpc.fValid)
    {
        return;
    }

    for (ULONG i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++)
    {
        if (ctxLeechRpc.ClientList[i].dwRpcClientID)
        {
            LeechRPC_LcHandle_Close(ctxLeechRpc.ClientList[i].dwRpcClientID, FALSE);
        }
    }
}





static VOID LeechRPC_LcHandle_InactivityWatcherThread(_In_ PVOID Context)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = (MACHENIKE_KERNEL_INTERFACE *)Context;
    if (!UserVar)
    {
        UserVar = ctxLeechRpc.UserVar;
    }

    DBG("InactivityWatcherThread: Started");
    ctxLeechRpc.fInactivityWatcherThreadIsRunning = TRUE;

    while (ctxLeechRpc.fInactivityWatcherThread)
    {

        LARGE_INTEGER Interval;
        Interval.QuadPart = -10 * 1000 * 1000;
        if (UserVar)
            UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Interval);

        if (!ctxLeechRpc.fInactivityWatcherThread)
        {
            break;
        }

        ULONG64 CurrentTick = MkGetTickCount64();

        for (ULONG i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++)
        {
            if (ctxLeechRpc.ClientList[i].dwRpcClientID && ctxLeechRpc.ClientList[i].qwLastTickCount64 &&
                (ctxLeechRpc.ClientList[i].qwLastTickCount64 + LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS < CurrentTick))
            {
                ULONG timedOutClientId = ctxLeechRpc.ClientList[i].dwRpcClientID;
                DBG(
                    "InactivityWatcherThread: RpcClientId=0x%08X (%u) timed out (inactive for %llu ms), closing handle",
                    timedOutClientId, timedOutClientId, CurrentTick - ctxLeechRpc.ClientList[i].qwLastTickCount64);
                LeechRPC_LcHandle_Close(timedOutClientId, TRUE);
            }
        }
    }

    ctxLeechRpc.fInactivityWatcherThreadIsRunning = FALSE;
    DBG("InactivityWatcherThread: Exited");
    if (UserVar)
        UserVar->Func.PsTerminateSystemThread(STATUS_SUCCESS);
}





static VOID LeechRPC_CompressCleanup(VOID)
{
    g_CompressCtx.fValid = FALSE;
    for (ULONG i = 0; i < LEECHRPC_COMPRESS_MAXTHREADS; i++)
    {
        if (g_CompressCtx.Slots[i].pbWorkspace)
        {
            ExFreePoolWithTag(g_CompressCtx.Slots[i].pbWorkspace, LC_POOL_TAG);
            g_CompressCtx.Slots[i].pbWorkspace = NULL;
        }
    }
}

static BOOLEAN LeechRPC_CompressInit(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    LeechRPC_CompressCleanup();
    if (!UserVar || !UserVar->KernelBase.QuadPart)
    {
        return FALSE;
    }

    ULONG_PTR kBase = (ULONG_PTR)UserVar->KernelBase.QuadPart;
    if (!Utils_GetModuleExport(kBase, str_RtlGetCompressionWorkSpaceSize, (PULONG_PTR)&g_CompressCtx.pfnRtlGetCompressionWorkSpaceSize) ||
        !Utils_GetModuleExport(kBase, str_RtlCompressBuffer, (PULONG_PTR)&g_CompressCtx.pfnRtlCompressBuffer) ||
        !Utils_GetModuleExport(kBase, str_RtlDecompressBuffer, (PULONG_PTR)&g_CompressCtx.pfnRtlDecompressBuffer))
    {
        DBG("[-] LeechRPC_CompressInit: Failed to resolve compression routines from ntoskrnl");
        return FALSE;
    }

    ULONG cbWorkSpace = 0;
    ULONG cbFragment = 0;
    NTSTATUS status = g_CompressCtx.pfnRtlGetCompressionWorkSpaceSize(
        COMPRESSION_FORMAT_XPRESS | COMPRESSION_ENGINE_STANDARD,
        &cbWorkSpace,
        &cbFragment);

    if (!NT_SUCCESS(status) || cbWorkSpace == 0)
    {
        DBG("[-] LeechRPC_CompressInit: RtlGetCompressionWorkSpaceSize failed (status=0x%08X)", status);
        return FALSE;
    }

    g_CompressCtx.cbWorkspace = cbWorkSpace;
    for (ULONG i = 0; i < LEECHRPC_COMPRESS_MAXTHREADS; i++)
    {
        g_CompressCtx.Slots[i].Lock.Count = 1;
        g_CompressCtx.Slots[i].Lock.Owner = NULL;
        g_CompressCtx.Slots[i].Lock.Contention = 0;
        if (UserVar->Func.KeInitializeEvent)
        {
            UserVar->Func.KeInitializeEvent(&g_CompressCtx.Slots[i].Lock.Event, SynchronizationEvent, FALSE);
        }
        g_CompressCtx.Slots[i].pbWorkspace = ExAllocatePoolWithTag(NonPagedPoolNx, cbWorkSpace, LC_POOL_TAG);
        if (!g_CompressCtx.Slots[i].pbWorkspace)
        {
            DBG("[-] LeechRPC_CompressInit: Failed to allocate workspace [%u]", i);
            LeechRPC_CompressCleanup();
            return FALSE;
        }
        RtlZeroMemory(g_CompressCtx.Slots[i].pbWorkspace, cbWorkSpace);
    }

    g_CompressCtx.fValid = TRUE;
    DBG("[+] LeechRPC_CompressInit: Initialized successfully with workspace=%lu bytes, slots=%u",
        cbWorkSpace, LEECHRPC_COMPRESS_MAXTHREADS);
    return TRUE;
}

static VOID LeechRPC_CompressMsg(_Inout_ PLEECHRPC_MSG_BIN pMsg, _In_ BOOLEAN fCompressDisable)
{
    if (!g_CompressCtx.fValid || !pMsg || pMsg->cb < 0x1000 || fCompressDisable)
    {
        return;
    }

    PUCHAR pbComp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, pMsg->cb, LC_POOL_TAG);
    if (!pbComp)
    {
        return;
    }

    ULONG slotIdx = (ULONG)(InterlockedIncrement(&g_CompressCtx.iCompress) & (LEECHRPC_COMPRESS_MAXTHREADS - 1));
    PLEECHRPC_COMPRESS_SLOT pSlot = &g_CompressCtx.Slots[slotIdx];

    ExAcquireFastMutex(&pSlot->Lock);
    ULONG cbCompActual = 0;
    NTSTATUS nt = g_CompressCtx.pfnRtlCompressBuffer(
        COMPRESSION_FORMAT_XPRESS | COMPRESSION_ENGINE_STANDARD,
        pMsg->pb,
        pMsg->cb,
        pbComp,
        pMsg->cb,
        4096,
        &cbCompActual,
        pSlot->pbWorkspace);
    ExReleaseFastMutex(&pSlot->Lock);

    // 状态 0x00000117L 为 STATUS_BUFFER_ALL_ZEROS (全零缓冲区被高效压缩)
    if ((NT_SUCCESS(nt) || nt == 0x00000117L) && (cbCompActual < pMsg->cb))
    {
        RtlCopyMemory(pMsg->pb, pbComp, cbCompActual);
        pMsg->cbDecompress = pMsg->cb;
        pMsg->cb = cbCompActual;
        pMsg->cbMsg = sizeof(LEECHRPC_MSG_BIN) + cbCompActual;
    }

    ExFreePoolWithTag(pbComp, LC_POOL_TAG);
}

static BOOLEAN LeechRPC_DecompressMsg(_In_ PLEECHRPC_MSG_BIN pMsgIn, _Out_ PLEECHRPC_MSG_BIN *ppMsgOut)
{
    *ppMsgOut = NULL;
    if (!pMsgIn || !pMsgIn->cbDecompress)
    {
        return FALSE;
    }

    if (!g_CompressCtx.fValid || (pMsgIn->cbDecompress > 0x04000000))
    {
        return FALSE;
    }

    ULONG cbAlloc = sizeof(LEECHRPC_MSG_BIN) + pMsgIn->cbDecompress;
    PLEECHRPC_MSG_BIN pMsgOut = (PLEECHRPC_MSG_BIN)ExAllocatePoolWithTag(NonPagedPoolNx, cbAlloc, LC_POOL_TAG);
    if (!pMsgOut)
    {
        return FALSE;
    }

    RtlCopyMemory(pMsgOut, pMsgIn, sizeof(LEECHRPC_MSG_BIN));

    ULONG cbDecompActual = 0;
    NTSTATUS nt = g_CompressCtx.pfnRtlDecompressBuffer(
        COMPRESSION_FORMAT_XPRESS,
        pMsgOut->pb,
        pMsgIn->cbDecompress,
        pMsgIn->pb,
        pMsgIn->cb,
        &cbDecompActual);

    if (!NT_SUCCESS(nt) || cbDecompActual != pMsgIn->cbDecompress)
    {
        ExFreePoolWithTag(pMsgOut, LC_POOL_TAG);
        return FALSE;
    }

    pMsgOut->cb = cbDecompActual;
    pMsgOut->cbMsg = sizeof(LEECHRPC_MSG_BIN) + cbDecompActual;
    pMsgOut->cbDecompress = 0;
    *ppMsgOut = pMsgOut;
    return TRUE;
}

NTSTATUS MkRpc_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DBG("MkRpc_Init: Initializing RPC dispatch engine...");
    ctxLeechRpc.UserVar = UserVar;
    g_pRpcUserVar = UserVar;

    LeechRPC_CompressInit(UserVar);

    if (!ctxLeechRpc.fValid)
    {
        ctxLeechRpc.LockClientList.Count = 1;
        ctxLeechRpc.LockClientList.Owner = NULL;
        ctxLeechRpc.LockClientList.Contention = 0;
        if (UserVar->Func.KeInitializeEvent) {
            UserVar->Func.KeInitializeEvent(&ctxLeechRpc.LockClientList.Event, SynchronizationEvent, FALSE);
        }
        RtlZeroMemory(ctxLeechRpc.ClientList, sizeof(ctxLeechRpc.ClientList));
        ctxLeechRpc.fValid = TRUE;


        ctxLeechRpc.fInactivityWatcherThread = TRUE;
        ctxLeechRpc.fInactivityWatcherThreadIsRunning = FALSE;
        NTSTATUS threadStatus = UserVar->Func.PsCreateSystemThread(
            &ctxLeechRpc.hWatcherThread, THREAD_ALL_ACCESS, NULL, NULL, NULL,
            LeechRPC_LcHandle_InactivityWatcherThread, (PVOID)UserVar);

        if (NT_SUCCESS(threadStatus))
        {
            POBJECT_TYPE pThreadType = (UserVar && UserVar->Func.pPsThreadType) ? *UserVar->Func.pPsThreadType : NULL;
            UserVar->Func.ObReferenceObjectByHandle(
                ctxLeechRpc.hWatcherThread, THREAD_ALL_ACCESS, pThreadType, KernelMode,
                (PVOID *)&ctxLeechRpc.pWatcherThread, NULL);
            DBG("MkRpc_Init: InactivityWatcherThread started successfully");
        }
        else
        {
            ctxLeechRpc.fInactivityWatcherThread = FALSE;
            ctxLeechRpc.hWatcherThread = NULL;
            ctxLeechRpc.pWatcherThread = NULL;
            DBG("MkRpc_Init: Failed to create InactivityWatcherThread, status=0x%08X", threadStatus);
        }
    }
    NTSTATUS status = LcCore_Initialize(UserVar);
    DBG("MkRpc_Init: Engine init completed with status=0x%08X", status);
    if (!NT_SUCCESS(status))
    {
        DBG("MkRpc_Init: LcCore_Initialize failed, cleaning up RPC resources...");
        MkRpc_Cleanup(UserVar);
        return status;
    }
    return status;
}

VOID MkRpc_Cleanup(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        UserVar = ctxLeechRpc.UserVar;
    }

    DBG("MkRpc_Cleanup: Cleaning up RPC clients and watcher thread...");
    if (ctxLeechRpc.fValid)
    {

        ctxLeechRpc.fInactivityWatcherThread = FALSE;
        if (ctxLeechRpc.pWatcherThread)
        {
            if (UserVar)
            {
                UserVar->Func.KeWaitForSingleObject(ctxLeechRpc.pWatcherThread, Executive, KernelMode, FALSE, NULL);
                UserVar->Func.ObDereferenceObject(ctxLeechRpc.pWatcherThread);
            }
            ctxLeechRpc.pWatcherThread = NULL;
        }
        if (ctxLeechRpc.hWatcherThread)
        {
            if (UserVar)
                UserVar->Func.ZwClose(ctxLeechRpc.hWatcherThread);
            ctxLeechRpc.hWatcherThread = NULL;
        }


        LeechRPC_LcHandle_CloseAll();
        ctxLeechRpc.fValid = FALSE;
    }
    LeechRPC_CompressCleanup();
    LcCore_Cleanup();
    DBG("MkRpc_Cleanup: Cleaned up successfully");
}





static NTSTATUS MkRpc_HandlePing(_In_ PLEECHRPC_MSG_HDR pReq, _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut,
                                 _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
                                 _In_ ULONG cbDirectOutMax)
{
    DBG("MkRpc_HandlePing: Ping received from ClientId=%u", pReq->dwRpcClientID);
    PLEECHRPC_MSG_HDR pRsp = NULL;
    if (pbDirectOut && cbDirectOutMax >= sizeof(LEECHRPC_MSG_HDR))
    {
        pRsp = (PLEECHRPC_MSG_HDR)pbDirectOut;
    }
    else
    {
        pRsp = (PLEECHRPC_MSG_HDR)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_HDR), LC_POOL_TAG);
    }
    if (!pRsp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
    pRsp->tpMsg = LEECHRPC_MSGTYPE_PING_RSP;
    pRsp->fMsgResult = TRUE;
    pRsp->dwRpcClientID = pReq->dwRpcClientID;
    pRsp->flags = 0;

    *ppbOut = (PUCHAR)pRsp;
    *pcbOut = sizeof(LEECHRPC_MSG_HDR);
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleOpen(_In_ PLEECHRPC_MSG_OPEN pReqOpen, _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut)
{
    DBG("MkRpc_HandleOpen: Open request from ClientId=%u", pReqOpen->dwRpcClientID);
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    HANDLE hLC = LcCreateEx(ctxLeechRpc.UserVar, &pReqOpen->cfg, &pLcErrorInfo);

    if (hLC && !LeechRPC_LcHandle_New(pReqOpen->dwRpcClientID, hLC))
    {
        DBG("MkRpc_HandleOpen: Failed to register hLC into client list (max clients reached)");
        LcClose(hLC);
        hLC = NULL;
    }
    DBG("MkRpc_HandleOpen: ClientId=%u opened with hLC=%p", pReqOpen->dwRpcClientID, hLC);

    ULONG cbErrorInfo = pLcErrorInfo ? pLcErrorInfo->cbStruct : sizeof(LC_CONFIG_ERRORINFO);
    ULONG cbRsp = sizeof(LEECHRPC_MSG_OPEN) +
                  (cbErrorInfo > sizeof(LC_CONFIG_ERRORINFO) ? cbErrorInfo - sizeof(LC_CONFIG_ERRORINFO) : 0);

    PLEECHRPC_MSG_OPEN pRspOpen = (PLEECHRPC_MSG_OPEN)ExAllocatePoolWithTag(NonPagedPoolNx, cbRsp, LC_POOL_TAG);
    if (!pRspOpen)
    {
        if (pLcErrorInfo)
        {
            ExFreePool(pLcErrorInfo);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pRspOpen, cbRsp);
    pRspOpen->dwMagic = LEECHRPC_MSGMAGIC;
    pRspOpen->cbMsg = cbRsp;
    pRspOpen->tpMsg = LEECHRPC_MSGTYPE_OPEN_RSP;
    pRspOpen->fMsgResult = TRUE;
    pRspOpen->fValidOpen = (hLC != NULL);
    pRspOpen->dwRpcClientID = pReqOpen->dwRpcClientID;

    if (pRspOpen->fValidOpen)
    {
        PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
        if (ctxLC)
        {
            RtlCopyMemory(&pRspOpen->cfg, &ctxLC->Config, sizeof(LC_CONFIG));
        }
        else
        {
            RtlCopyMemory(&pRspOpen->cfg, &pReqOpen->cfg, sizeof(LC_CONFIG));
        }
        pRspOpen->cfg.fRemoteDisableCompress = TRUE;
        pRspOpen->flags = LEECHRPC_FLAG_FNEXIST_ReadScatterMEM | LEECHRPC_FLAG_FNEXIST_WriteScatterMEM |
                          LEECHRPC_FLAG_FNEXIST_Close | LEECHRPC_FLAG_FNEXIST_Command |
                          LEECHRPC_FLAG_FNEXIST_GetOption | LEECHRPC_FLAG_FNEXIST_SetOption;
    }

    if (pLcErrorInfo)
    {
        RtlCopyMemory(&pRspOpen->errorinfo, pLcErrorInfo, pLcErrorInfo->cbStruct);
        ExFreePool(pLcErrorInfo);
    }
    else
    {
        pRspOpen->errorinfo.dwVersion = LC_CONFIG_ERRORINFO_VERSION;
        pRspOpen->errorinfo.cbStruct = sizeof(LC_CONFIG_ERRORINFO);
    }

    *ppbOut = (PUCHAR)pRspOpen;
    *pcbOut = cbRsp;
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleClose(_In_ PLEECHRPC_MSG_HDR pReq, _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut,
                                  _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
                                  _In_ ULONG cbDirectOutMax)
{
    DBG("MkRpc_HandleClose: Closing ClientId=%u", pReq->dwRpcClientID);
    LeechRPC_LcHandle_Close(pReq->dwRpcClientID, FALSE);

    PLEECHRPC_MSG_HDR pRsp = NULL;
    if (pbDirectOut && cbDirectOutMax >= sizeof(LEECHRPC_MSG_HDR))
    {
        pRsp = (PLEECHRPC_MSG_HDR)pbDirectOut;
    }
    else
    {
        pRsp = (PLEECHRPC_MSG_HDR)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_HDR), LC_POOL_TAG);
    }
    if (!pRsp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
    pRsp->tpMsg = LEECHRPC_MSGTYPE_CLOSE_RSP;
    pRsp->fMsgResult = TRUE;
    pRsp->dwRpcClientID = pReq->dwRpcClientID;
    pRsp->flags = 0;

    *ppbOut = (PUCHAR)pRsp;
    *pcbOut = sizeof(LEECHRPC_MSG_HDR);
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleGetOption(_In_ HANDLE hLC, _In_opt_ PLEECHRPC_MSG_DATA pReqData, _Out_ PUCHAR *ppbOut,
                                      _Out_ PULONG pcbOut,
                                      _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
                                      _In_ ULONG cbDirectOutMax)
{
    PLEECHRPC_MSG_DATA pRspData = NULL;
    if (pbDirectOut && cbDirectOutMax >= sizeof(LEECHRPC_MSG_DATA))
    {
        pRspData = (PLEECHRPC_MSG_DATA)pbDirectOut;
    }
    else
    {
        pRspData = (PLEECHRPC_MSG_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_DATA), LC_POOL_TAG);
    }
    if (!pRspData)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pRspData, sizeof(LEECHRPC_MSG_DATA));
    pRspData->dwMagic = LEECHRPC_MSGMAGIC;
    pRspData->cbMsg = sizeof(LEECHRPC_MSG_DATA);
    pRspData->tpMsg = LEECHRPC_MSGTYPE_GETOPTION_RSP;
    pRspData->dwRpcClientID = pReqData ? pReqData->dwRpcClientID : 0;
    pRspData->qwData[0] = 0;
    pRspData->fMsgResult = TRUE;

    if (pReqData && hLC)
    {
        LcGetOption(hLC, pReqData->qwData[0], &pRspData->qwData[0]);
    }

    DBG("MkRpc_HandleGetOption [ClientId=%u]: Option=0x%llX, result=%d, val=0x%llX",
                   pReqData ? pReqData->dwRpcClientID : 0,
                   pReqData ? pReqData->qwData[0] : 0,
                   pRspData->fMsgResult,
                   pRspData->qwData[0]);

    *ppbOut = (PUCHAR)pRspData;
    *pcbOut = sizeof(LEECHRPC_MSG_DATA);
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleSetOption(_In_ HANDLE hLC, _In_opt_ PLEECHRPC_MSG_DATA pReqData, _Out_ PUCHAR *ppbOut,
                                      _Out_ PULONG pcbOut,
                                      _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
                                      _In_ ULONG cbDirectOutMax)
{
    PLEECHRPC_MSG_HDR pRsp = NULL;
    if (pbDirectOut && cbDirectOutMax >= sizeof(LEECHRPC_MSG_HDR))
    {
        pRsp = (PLEECHRPC_MSG_HDR)pbDirectOut;
    }
    else
    {
        pRsp = (PLEECHRPC_MSG_HDR)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_HDR), LC_POOL_TAG);
    }
    if (!pRsp)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pRsp, sizeof(LEECHRPC_MSG_HDR));
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
    pRsp->tpMsg = LEECHRPC_MSGTYPE_SETOPTION_RSP;
    pRsp->dwRpcClientID = pReqData ? pReqData->dwRpcClientID : 0;

    if (pReqData)
    {
        pRsp->fMsgResult = LcSetOption(hLC, pReqData->qwData[0], pReqData->qwData[1]);
    }
    else
    {
        pRsp->fMsgResult = FALSE;
    }

    *ppbOut = (PUCHAR)pRsp;
    *pcbOut = sizeof(LEECHRPC_MSG_HDR);
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleReadScatter(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReqBin, _Out_ PUCHAR *ppbOut,
                                        _Out_ PULONG pcbOut,
                                        _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
                                        _In_ ULONG cbDirectOutMax,
                                        _In_ BOOLEAN fCompressDisable)
{
    UNREFERENCED_PARAMETER(fCompressDisable);
    ULONG cMEMs = (ULONG)pReqBin->qwData[0];
    ULONG cbMax = (ULONG)pReqBin->qwData[1];

    if (pReqBin->cb != cMEMs * sizeof(MEM_SCATTER) || cMEMs == 0 || cMEMs > 0x2000 || cbMax > (cMEMs << 12))
    {
        DBG("[-] MkRpc: HandleReadScatter invalid param (cb=%lu, cMEMs=%lu, cbMax=%lu)",
            pReqBin->cb, cMEMs, cbMax);
        return STATUS_INVALID_PARAMETER;
    }

    if (pReqBin->cbDecompress != 0)
    {
        DBG("[-] MkRpc: HandleReadScatter compression not supported (cbDecompress=%lu)", pReqBin->cbDecompress);
        return STATUS_NOT_SUPPORTED;
    }

    ULONG cbMaxRspPayload = cMEMs * sizeof(MEM_SCATTER) + cbMax;
    ULONG cbMaxRspTotal = sizeof(LEECHRPC_MSG_BIN) + cbMaxRspPayload;
    BOOLEAN fDirectOut = (pbDirectOut && cbMaxRspTotal <= cbDirectOutMax);
    PLEECHRPC_MSG_BIN pRspBin = NULL;

    if (fDirectOut)
    {
        pRspBin = (PLEECHRPC_MSG_BIN)pbDirectOut;
    }
    else
    {
        pRspBin = (PLEECHRPC_MSG_BIN)ExAllocatePoolWithTag(NonPagedPoolNx, cbMaxRspTotal, LC_POOL_TAG);
        if (!pRspBin)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    RtlZeroMemory(pRspBin, sizeof(LEECHRPC_MSG_BIN));

    if (cMEMs == 1)
    {
        PMEM_SCATTER pReqMEM = (PMEM_SCATTER)pReqBin->pb;
        if (pReqMEM->cb > cbMax)
        {
            if (!fDirectOut)
            {
                ExFreePoolWithTag(pRspBin, LC_POOL_TAG);
            }
            return STATUS_INVALID_PARAMETER;
        }

        PMEM_SCATTER pMEM_Dst = (PMEM_SCATTER)pRspBin->pb;
        // 1. 完整拷贝描述符：必须保留 version (0xc0fe0002)、qwA、cb、iStack、vStack 等全部元数据，
        // 严禁字段漏拷导致客户端 sanity check 校验 version 失败而直接抛弃连接并调用 Close！
        RtlCopyMemory(pMEM_Dst, pReqMEM, sizeof(MEM_SCATTER));
        pMEM_Dst->f = FALSE;

        // ★★★ 极速单散列项物理直读快路径 (Direct System PTE Cache) ★★★
        LARGE_INTEGER pa;
        pa.QuadPart = pReqMEM->qwA;
        PUCHAR pbTargetDst = pRspBin->pb + sizeof(MEM_SCATTER);
        ULONG cbRead = LcPte_ReadPhysicalContiguous(pa, pbTargetDst, pReqMEM->cb);
        if (cbRead == pReqMEM->cb)
        {
            pMEM_Dst->f = TRUE;
        }
        else
        {
            // 若直读失败，安全退避至标准 LcReadScatter 兜底
            pMEM_Dst->pb = pbTargetDst;
            PMEM_SCATTER single_pMEM = pMEM_Dst;
            LcReadScatter(hLC, 1, &single_pMEM);
            pMEM_Dst->pb = pReqMEM->pb;
        }

        ULONG cbReadTotal = pMEM_Dst->f ? pReqMEM->cb : 0;
        ULONG cbRspPayload = sizeof(MEM_SCATTER) + cbReadTotal;
        ULONG cbRspTotal = sizeof(LEECHRPC_MSG_BIN) + cbRspPayload;

        pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
        pRspBin->tpMsg = LEECHRPC_MSGTYPE_READSCATTER_RSP;
        pRspBin->fMsgResult = TRUE;
        pRspBin->dwRpcClientID = pReqBin->dwRpcClientID;
        pRspBin->flags = LEECHRPC_FLAG_NOCOMPRESS;
        pRspBin->qwData[0] = 1;
        pRspBin->qwData[1] = cbReadTotal;
        pRspBin->cbDecompress = 0;
        pRspBin->cb = cbRspPayload;
        pRspBin->cbMsg = cbRspTotal;

        *ppbOut = (PUCHAR)pRspBin;
        *pcbOut = cbRspTotal;
        return STATUS_SUCCESS;
    }

    PMEM_SCATTER stack_ppMEMs[128];
    PMEM_SCATTER *ppMEMs = stack_ppMEMs;
    if (cMEMs > 128)
    {
        ppMEMs = (PMEM_SCATTER *)ExAllocatePoolWithTag(NonPagedPoolNx, cMEMs * sizeof(PMEM_SCATTER), LC_POOL_TAG);
        if (!ppMEMs)
        {
            if (!fDirectOut)
            {
                ExFreePoolWithTag(pRspBin, LC_POOL_TAG);
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    // 1: 直接将请求体中的描述符复制到应答缓冲区头部
    PMEM_SCATTER pMEM_Dst = (PMEM_SCATTER)pRspBin->pb;
    RtlCopyMemory(pMEM_Dst, pReqBin->pb, cMEMs * sizeof(MEM_SCATTER));

    // 2: 零内存池分配 (Zero-Allocation) 原位直读设计：
    // 让每个散列项的 pb 直接指向响应包内部的数据承载区 (pRspBin->pb + cMEMs * sizeof(MEM_SCATTER))
    // 彻底根除每秒数千次动态 ExAllocatePoolWithTag(pbData) 引发的内核内存池全局自旋锁竞争与延迟毛刺！
    PUCHAR pbDataDst = pRspBin->pb + cMEMs * sizeof(MEM_SCATTER);
    ULONG cbDataOffset = 0;

    for (ULONG i = 0; i < cMEMs; i++)
    {
        pMEM_Dst[i].pb = pbDataDst + cbDataOffset;
        pMEM_Dst[i].f = FALSE; // 防御性清零：杜绝客户端请求包中残留脏 f 导致跳过读取
        ppMEMs[i] = &pMEM_Dst[i];
        cbDataOffset += pMEM_Dst[i].cb;
    }

    if (cbDataOffset > cbMax)
    {
        if (ppMEMs != stack_ppMEMs)
        {
            ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
        }
        if (!fDirectOut)
        {
            ExFreePoolWithTag(pRspBin, LC_POOL_TAG);
        }
        return STATUS_INVALID_PARAMETER;
    }

    // 3: 执行底层物理内存分散读取（数据直接灌入 pRspBin，常态下 100% 零拷贝）
    LcReadScatter(hLC, cMEMs, ppMEMs);

    // 4: 统计成功读取的数据总字节数，并检查是否存在罕见读取失败页
    ULONG cbReadTotal = 0;
    BOOLEAN hasHoles = FALSE;
    for (ULONG i = 0; i < cMEMs; i++)
    {
        if (pMEM_Dst[i].f)
        {
            cbReadTotal += pMEM_Dst[i].cb;
        }
        else
        {
            hasHoles = TRUE;
        }
    }

    // 5: 若存在罕见失败页，执行就地紧凑对齐 (In-Place Compaction)，杜绝客户端 Offset Shift
    if (hasHoles && cbReadTotal > 0)
    {
        PUCHAR pWritePtr = pbDataDst;
        for (ULONG i = 0; i < cMEMs; i++)
        {
            if (pMEM_Dst[i].f)
            {
                if (pWritePtr != pMEM_Dst[i].pb)
                {
                    RtlMoveMemory(pWritePtr, pMEM_Dst[i].pb, pMEM_Dst[i].cb);
                }
                pWritePtr += pMEM_Dst[i].cb;
            }
        }
    }

    // 6: 关键安全与协议对齐：将 pMEM_Dst[i].pb 还原为客户端请求体传入的原始 pb 指针！
    // 彻底杜绝内核虚拟地址泄露 (KASLR Leak)，并防止破坏客户端解包时可能引用的自身用户态地址指针
    PMEM_SCATTER pMEM_Req = (PMEM_SCATTER)pReqBin->pb;
    for (ULONG i = 0; i < cMEMs; i++)
    {
        pMEM_Dst[i].pb = pMEM_Req[i].pb;
    }

    ULONG cbRspPayload = cMEMs * sizeof(MEM_SCATTER) + cbReadTotal;
    ULONG cbRspTotal = sizeof(LEECHRPC_MSG_BIN) + cbRspPayload;

    pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
    pRspBin->tpMsg = LEECHRPC_MSGTYPE_READSCATTER_RSP;
    pRspBin->fMsgResult = TRUE;
    pRspBin->dwRpcClientID = pReqBin->dwRpcClientID;
    pRspBin->flags = LEECHRPC_FLAG_NOCOMPRESS;
    pRspBin->qwData[0] = cMEMs;
    pRspBin->qwData[1] = cbReadTotal;
    pRspBin->cbDecompress = 0;
    pRspBin->cb = cbRspPayload;
    pRspBin->cbMsg = cbRspTotal;

    if (ppMEMs != stack_ppMEMs)
    {
        ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
    }

    // 协议直通保障：下行流严禁压缩，防止破坏 UDP 客户端或导致 Chunk 错位
    pRspBin->cbDecompress = 0;

    *ppbOut = (PUCHAR)pRspBin;
    *pcbOut = pRspBin->cbMsg;
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleWriteScatter(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReqBin, _Out_ PUCHAR *ppbOut,
                                         _Out_ PULONG pcbOut,
                                         _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
                                         _In_ ULONG cbDirectOutMax,
                                         _In_ BOOLEAN fCompressDisable)
{
    UNREFERENCED_PARAMETER(fCompressDisable);
    ULONG cMEMs = (ULONG)pReqBin->qwData[0];
    ULONG cbMax = (ULONG)pReqBin->qwData[1];

    if (cMEMs == 0 || cMEMs > 0x2000 || cbMax > (cMEMs << 12) || pReqBin->cb < cMEMs * sizeof(MEM_SCATTER))
    {
        DBG("[-] MkRpc: HandleWriteScatter invalid param (cMEMs=%lu, cbMax=%lu, cb=%lu)",
            cMEMs, cbMax, pReqBin->cb);
        return STATUS_INVALID_PARAMETER;
    }

    if (pReqBin->cbDecompress != 0)
    {
        DBG("[-] MkRpc: HandleWriteScatter compression not supported (cbDecompress=%lu)", pReqBin->cbDecompress);
        return STATUS_NOT_SUPPORTED;
    }

    PMEM_SCATTER stack_ppMEMs[128];
    PMEM_SCATTER *ppMEMs = stack_ppMEMs;
    if (cMEMs > 128)
    {
        ppMEMs = (PMEM_SCATTER *)ExAllocatePoolWithTag(NonPagedPoolNx, cMEMs * sizeof(PMEM_SCATTER), LC_POOL_TAG);
        if (!ppMEMs)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    PMEM_SCATTER pMEMs = (PMEM_SCATTER)pReqBin->pb;
    PUCHAR pbData = pReqBin->pb + cMEMs * sizeof(MEM_SCATTER);
    ULONG cbDataAvail = pReqBin->cb - cMEMs * sizeof(MEM_SCATTER);
    ULONG cbDataOffset = 0;

    for (ULONG i = 0; i < cMEMs; i++)
    {
        PMEM_SCATTER pMEM = &pMEMs[i];
        if (pMEM->cb > 0x1000 || (cbDataOffset + pMEM->cb > cbDataAvail))
        {
            DBG("[-] MkRpc: HandleWriteScatter entry %lu out of bounds (cb=%lu, offset=%lu, avail=%lu)",
                i, pMEM->cb, cbDataOffset, cbDataAvail);
            if (ppMEMs != stack_ppMEMs)
            {
                ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
            }
            return STATUS_INVALID_PARAMETER;
        }

        pMEM->pb = pbData + cbDataOffset;
        ppMEMs[i] = pMEM;
        cbDataOffset += pMEM->cb;
    }

    // 执行底层物理内存分散写入
    LcWriteScatter(hLC, cMEMs, ppMEMs);

    // 对齐原版协议契约：应答包负载为 BOOL 数组（cMEMs * sizeof(BOOL)），严禁返回 MEM_SCATTER 结构体
    ULONG cbRspPayload = cMEMs * sizeof(BOOL);
    ULONG cbRspTotal = sizeof(LEECHRPC_MSG_BIN) + cbRspPayload;
    PLEECHRPC_MSG_BIN pRspBin = NULL;

    if (pbDirectOut && cbRspTotal <= cbDirectOutMax)
    {
        pRspBin = (PLEECHRPC_MSG_BIN)pbDirectOut;
    }
    else
    {
        pRspBin = (PLEECHRPC_MSG_BIN)ExAllocatePoolWithTag(NonPagedPoolNx, cbRspTotal, LC_POOL_TAG);
    }

    if (!pRspBin)
    {
        if (ppMEMs != stack_ppMEMs)
        {
            ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pRspBin, cbRspTotal);
    pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
    pRspBin->tpMsg = LEECHRPC_MSGTYPE_WRITESCATTER_RSP;
    pRspBin->fMsgResult = TRUE;
    pRspBin->dwRpcClientID = pReqBin->dwRpcClientID;
    pRspBin->flags = LEECHRPC_FLAG_NOCOMPRESS;
    pRspBin->qwData[0] = cMEMs;
    pRspBin->qwData[1] = 0;
    pRspBin->cbDecompress = 0;
    pRspBin->cb = cbRspPayload;
    pRspBin->cbMsg = cbRspTotal;

    PBOOL pfRsp = (PBOOL)pRspBin->pb;
    for (ULONG i = 0; i < cMEMs; i++)
    {
        pfRsp[i] = ppMEMs[i]->f ? TRUE : FALSE;
    }

    if (ppMEMs != stack_ppMEMs)
    {
        ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
    }

    *ppbOut = (PUCHAR)pRspBin;
    *pcbOut = pRspBin->cbMsg;
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleCommand(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReqBin, _Out_ PUCHAR *ppbOut,
                                    _Out_ PULONG pcbOut,
                                    _In_ BOOLEAN fCompressDisable)
{
    UNREFERENCED_PARAMETER(fCompressDisable);
    ULONG64 fCommand = pReqBin->qwData[0];
    PUCHAR pbDataOut = NULL;
    ULONG cbDataOut = 0;


    BOOLEAN fResult = LcCommand(hLC, fCommand, pReqBin->cb, pReqBin->pb, &pbDataOut, &cbDataOut);
    DBG("MkRpc_HandleCommand [ClientId=%u]: Cmd=0x%llX, result=%d, cbOut=%u", pReqBin->dwRpcClientID,
                   fCommand, fResult, cbDataOut);

    ULONG cbAlloc = sizeof(LEECHRPC_MSG_BIN) + cbDataOut;
    PLEECHRPC_MSG_BIN pRspBin = (PLEECHRPC_MSG_BIN)ExAllocatePoolWithTag(NonPagedPoolNx, cbAlloc, LC_POOL_TAG);
    if (!pRspBin)
    {
        if (pbDataOut)
        {
            ExFreePoolWithTag(pbDataOut, LC_POOL_TAG);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pRspBin, cbAlloc);
    pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
    pRspBin->tpMsg = LEECHRPC_MSGTYPE_COMMAND_RSP;
    pRspBin->fMsgResult = fResult ? 1 : 0;
    pRspBin->dwRpcClientID = pReqBin->dwRpcClientID;
    pRspBin->flags = LEECHRPC_FLAG_NOCOMPRESS;
    pRspBin->qwData[0] = fCommand;
    pRspBin->qwData[1] = 0;
    pRspBin->cbDecompress = 0;
    pRspBin->cb = cbDataOut;

    if (cbDataOut > 0 && pbDataOut)
    {
        RtlCopyMemory(pRspBin->pb, pbDataOut, cbDataOut);
        ExFreePoolWithTag(pbDataOut, LC_POOL_TAG);
    }

    pRspBin->cbMsg = sizeof(LEECHRPC_MSG_BIN) + pRspBin->cb;

    *ppbOut = (PUCHAR)pRspBin;
    *pcbOut = pRspBin->cbMsg;
    return STATUS_SUCCESS;
}





NTSTATUS MkRpc_DispatchCommandEx(
    _In_opt_ PVOID pTransportContext,
    _In_ PUCHAR pbIn,
    _In_ ULONG cbIn,
    _Out_ PUCHAR *ppbOut,
    _Out_ PULONG pcbOut,
    _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
    _In_ ULONG cbDirectOutMax)
{
    PMK_WSK_CLIENT pWskClient = (PMK_WSK_CLIENT)pTransportContext;
    *ppbOut = NULL;
    *pcbOut = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN fFreeReqBin = FALSE;
    PLEECHRPC_MSG_BIN pReqBin = NULL;

    if (!pbIn || cbIn < sizeof(LEECHRPC_MSG_HDR))
    {
        return STATUS_INVALID_PARAMETER;
    }

    PLEECHRPC_MSG_HDR pHdr = (PLEECHRPC_MSG_HDR)pbIn;
    if (pHdr->dwMagic != LEECHRPC_MSGMAGIC || pHdr->cbMsg != cbIn)
    {
        DBG("MkRpc_DispatchCommand: Invalid magic=0x%08X (exp=0x%08X) or cbMsg=%u != cbIn=%u",
                       pHdr->dwMagic, LEECHRPC_MSGMAGIC, pHdr->cbMsg, cbIn);
        return STATUS_INVALID_PARAMETER;
    }





    if (pHdr->tpMsg == LEECHRPC_MSGTYPE_PING_REQ)
    {
        return MkRpc_HandlePing(pHdr, ppbOut, pcbOut, pbDirectOut, cbDirectOutMax);
    }
    if (pHdr->tpMsg == LEECHRPC_MSGTYPE_OPEN_REQ)
    {
        if (pWskClient)
        {
            pWskClient->Cached_hLC = NULL;
            pWskClient->Cached_dwRpcClientID = 0;
        }
        if (cbIn < sizeof(LEECHRPC_MSG_OPEN))
        {
            DBG("MkRpc_DispatchCommand: OPEN_REQ cbIn=%u < sizeof(LEECHRPC_MSG_OPEN)=%llu", cbIn,
                           (ULONGLONG)sizeof(LEECHRPC_MSG_OPEN));
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS StatusOpen = MkRpc_HandleOpen((PLEECHRPC_MSG_OPEN)pbIn, ppbOut, pcbOut);
        if (NT_SUCCESS(StatusOpen) && pWskClient && *ppbOut)
        {
            PLEECHRPC_MSG_OPEN pRspOpen = (PLEECHRPC_MSG_OPEN)*ppbOut;
            if (pRspOpen->fValidOpen)
            {
                pWskClient->Cached_dwRpcClientID = pRspOpen->dwRpcClientID;
                pWskClient->Cached_hLC = LeechRPC_LcHandle_Lookup(pRspOpen->dwRpcClientID);
            }
        }
        return StatusOpen;
    }
    if (pHdr->tpMsg == LEECHRPC_MSGTYPE_CLOSE_REQ)
    {
        if (pWskClient)
        {
            pWskClient->Cached_hLC = NULL;
            pWskClient->Cached_dwRpcClientID = 0;
        }
        return MkRpc_HandleClose(pHdr, ppbOut, pcbOut, pbDirectOut, cbDirectOutMax);
    }

    HANDLE hLC = NULL;

    // ★★★ Client 级 hLC 句柄直通缓存：彻底消灭每秒上万次 ExAcquireFastMutex 锁争用 ★★★
    if (pWskClient && pWskClient->Cached_dwRpcClientID == pHdr->dwRpcClientID && pWskClient->Cached_hLC)
    {
        hLC = pWskClient->Cached_hLC;
    }
    else
    {
        hLC = LeechRPC_LcHandle_Lookup(pHdr->dwRpcClientID);
        if (pWskClient && hLC)
        {
            pWskClient->Cached_dwRpcClientID = pHdr->dwRpcClientID;
            pWskClient->Cached_hLC = hLC;
        }
    }

    if (!hLC)
    {
        DBG("MkRpc_DispatchCommand: No active hLC found for ClientId=%u, MsgType=0x%08X",
                       pHdr->dwRpcClientID, pHdr->tpMsg);
        Status = STATUS_DEVICE_NOT_CONNECTED;
        goto handle_error_rsp;
    }

    // 1: 处理 BIN 类请求消息的解压缩（对齐原版 leechrpcserver.c 第 3861 行）
    if (pHdr->tpMsg == LEECHRPC_MSGTYPE_READSCATTER_REQ ||
        pHdr->tpMsg == LEECHRPC_MSGTYPE_WRITESCATTER_REQ ||
        pHdr->tpMsg == LEECHRPC_MSGTYPE_COMMAND_REQ)
    {
        if (cbIn < sizeof(LEECHRPC_MSG_BIN))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto handle_error_rsp;
        }

        pReqBin = (PLEECHRPC_MSG_BIN)pbIn;
        if (pReqBin->cbDecompress != 0)
        {
            if (!LeechRPC_DecompressMsg(pReqBin, &pReqBin))
            {
                DBG("[-] MkRpc_DispatchCommand: Failed to decompress incoming request (tpMsg=0x%08X, cbDecompress=%lu)",
                    pHdr->tpMsg, ((PLEECHRPC_MSG_BIN)pbIn)->cbDecompress);
                Status = STATUS_INVALID_PARAMETER;
                goto handle_error_rsp;
            }
            fFreeReqBin = TRUE;
        }
    }

    BOOLEAN fNoCompress = (pHdr->flags & LEECHRPC_FLAG_NOCOMPRESS) != 0;

    switch (pHdr->tpMsg)
    {
    case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
    {
        DBG("MkRpc_DispatchCommand: KeepAlive from ClientId=%u", pHdr->dwRpcClientID);
        PLEECHRPC_MSG_HDR pRsp = NULL;
        if (pbDirectOut && cbDirectOutMax >= sizeof(LEECHRPC_MSG_HDR))
        {
            pRsp = (PLEECHRPC_MSG_HDR)pbDirectOut;
        }
        else
        {
            pRsp = (PLEECHRPC_MSG_HDR)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_HDR), LC_POOL_TAG);
        }
        if (pRsp)
        {
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->tpMsg = LEECHRPC_MSGTYPE_KEEPALIVE_RSP;
            pRsp->fMsgResult = TRUE;
            pRsp->dwRpcClientID = pHdr->dwRpcClientID;
            pRsp->flags = 0;
            *ppbOut = (PUCHAR)pRsp;
            *pcbOut = sizeof(LEECHRPC_MSG_HDR);
        }
        else
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    }

    case LEECHRPC_MSGTYPE_READSCATTER_REQ:
        Status = MkRpc_HandleReadScatter(hLC, pReqBin, ppbOut, pcbOut, pbDirectOut, cbDirectOutMax, fNoCompress);
        break;

    case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
        Status = MkRpc_HandleWriteScatter(hLC, pReqBin, ppbOut, pcbOut, pbDirectOut, cbDirectOutMax, fNoCompress);
        break;

    case LEECHRPC_MSGTYPE_COMMAND_REQ:
        Status = MkRpc_HandleCommand(hLC, pReqBin, ppbOut, pcbOut, fNoCompress);
        break;

    case LEECHRPC_MSGTYPE_GETOPTION_REQ:
        Status = MkRpc_HandleGetOption(
            hLC, (cbIn >= sizeof(LEECHRPC_MSG_DATA)) ? (PLEECHRPC_MSG_DATA)pbIn : NULL, ppbOut, pcbOut, pbDirectOut, cbDirectOutMax);
        break;

    case LEECHRPC_MSGTYPE_SETOPTION_REQ:
        Status = MkRpc_HandleSetOption(
            hLC, (cbIn >= sizeof(LEECHRPC_MSG_DATA)) ? (PLEECHRPC_MSG_DATA)pbIn : NULL, ppbOut, pcbOut, pbDirectOut, cbDirectOutMax);
        break;

    default:
        Status = STATUS_NOT_SUPPORTED;
        break;
    }

handle_error_rsp:
    if (fFreeReqBin && pReqBin)
    {
        ExFreePoolWithTag(pReqBin, LC_POOL_TAG);
        pReqBin = NULL;
    }

    // 若处理失败或未能生成应答包，构造标准的负向确认包 (fMsgResult = FALSE)，防止客户端阻塞超时 5 秒
    if ((!NT_SUCCESS(Status) || !*ppbOut || *pcbOut == 0) && pHdr->tpMsg != LEECHRPC_MSGTYPE_CLOSE_REQ)
    {
        ULONG cbMinRsp = sizeof(LEECHRPC_MSG_HDR);
        PLEECHRPC_MSG_HDR pErrRsp = NULL;
        if (pbDirectOut && cbDirectOutMax >= cbMinRsp)
        {
            pErrRsp = (PLEECHRPC_MSG_HDR)pbDirectOut;
        }
        else
        {
            pErrRsp = (PLEECHRPC_MSG_HDR)ExAllocatePoolWithTag(NonPagedPoolNx, cbMinRsp, LC_POOL_TAG);
        }
        if (pErrRsp)
        {
            RtlZeroMemory(pErrRsp, cbMinRsp);
            pErrRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pErrRsp->cbMsg = cbMinRsp;
            pErrRsp->tpMsg = (pHdr->tpMsg & 1) ? (pHdr->tpMsg + 1) : pHdr->tpMsg;
            pErrRsp->fMsgResult = FALSE;
            pErrRsp->dwRpcClientID = pHdr->dwRpcClientID;
            *ppbOut = (PUCHAR)pErrRsp;
            *pcbOut = cbMinRsp;
            Status = STATUS_SUCCESS;
        }
    }

    return Status;
}
