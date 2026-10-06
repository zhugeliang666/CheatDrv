#include "rpc_dispatch.h"
#include "Common.h"
#include "leechcore_kernel.h"

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


static ULONG64 MkGetTickCount64(VOID)
{
    LARGE_INTEGER TickCount;
    KeQueryTickCount(&TickCount);
    ULONG TimeInc = KeQueryTimeIncrement();
    return (TickCount.QuadPart * TimeInc) / 10000;
}





static HANDLE LeechRPC_LcHandle_GetExisting(_In_ ULONG dwRpcClientID)
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
            ctxLeechRpc.ClientList[i].cActiveRequests++;
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
            ctxLeechRpc.ClientList[i].cActiveRequests--;
            break;
        }
    }
    ExReleaseFastMutex(&ctxLeechRpc.LockClientList);
}

static VOID LeechRPC_LcHandle_Close(_In_ ULONG dwRpcClientID, _In_ BOOLEAN fReasonTimeout)
{
    if (!ctxLeechRpc.fValid)
    {
        return; // 引擎未初始化时直接跳过，防止空指针互斥体崩溃
    }

    if (fReasonTimeout)
    {
        MachenikePrint("LeechRPC_LcHandle_Close [RpcClientId=0x%08X (%u)]: Handle closed due to inactivity TIMEOUT",
                       dwRpcClientID, dwRpcClientID);
    }
    HANDLE hLC = NULL;

    ExAcquireFastMutex(&ctxLeechRpc.LockClientList);
    for (ULONG i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++)
    {
        if (ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID)
        {

            while (ctxLeechRpc.ClientList[i].cActiveRequests > 0)
            {
                ExReleaseFastMutex(&ctxLeechRpc.LockClientList);
                LARGE_INTEGER Delay;
                Delay.QuadPart = -10 * 1000 * 5;
                if (ctxLeechRpc.UserVar)
                    ctxLeechRpc.UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Delay);
                ExAcquireFastMutex(&ctxLeechRpc.LockClientList);
            }
            hLC = ctxLeechRpc.ClientList[i].hLC;
            ctxLeechRpc.ClientList[i].hLC = NULL;
            ctxLeechRpc.ClientList[i].dwRpcClientID = 0;
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

    MachenikePrint("InactivityWatcherThread: Started");
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
                MachenikePrint(
                    "InactivityWatcherThread: RpcClientId=0x%08X (%u) timed out (inactive for %llu ms), closing handle",
                    timedOutClientId, timedOutClientId, CurrentTick - ctxLeechRpc.ClientList[i].qwLastTickCount64);
                LeechRPC_LcHandle_Close(timedOutClientId, TRUE);
            }
        }
    }

    ctxLeechRpc.fInactivityWatcherThreadIsRunning = FALSE;
    MachenikePrint("InactivityWatcherThread: Exited");
    if (UserVar)
        UserVar->Func.PsTerminateSystemThread(STATUS_SUCCESS);
}





NTSTATUS MkRpc_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        return STATUS_INVALID_PARAMETER;
    }

    MachenikePrint("MkRpc_Init: Initializing RPC dispatch engine...");
    ctxLeechRpc.UserVar = UserVar;

    if (!ctxLeechRpc.fValid)
    {
        ExInitializeFastMutex(&ctxLeechRpc.LockClientList);
        RtlZeroMemory(ctxLeechRpc.ClientList, sizeof(ctxLeechRpc.ClientList));
        ctxLeechRpc.fValid = TRUE;


        ctxLeechRpc.fInactivityWatcherThread = TRUE;
        ctxLeechRpc.fInactivityWatcherThreadIsRunning = FALSE;
        NTSTATUS threadStatus = UserVar->Func.PsCreateSystemThread(
            &ctxLeechRpc.hWatcherThread, THREAD_ALL_ACCESS, NULL, NULL, NULL,
            LeechRPC_LcHandle_InactivityWatcherThread, (PVOID)UserVar);

        if (NT_SUCCESS(threadStatus))
        {
            UserVar->Func.ObReferenceObjectByHandle(
                ctxLeechRpc.hWatcherThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
                (PVOID *)&ctxLeechRpc.pWatcherThread, NULL);
            MachenikePrint("MkRpc_Init: InactivityWatcherThread started successfully");
        }
        else
        {
            ctxLeechRpc.fInactivityWatcherThread = FALSE;
            ctxLeechRpc.hWatcherThread = NULL;
            ctxLeechRpc.pWatcherThread = NULL;
            MachenikePrint("MkRpc_Init: Failed to create InactivityWatcherThread, status=0x%08X", threadStatus);
        }
    }
    NTSTATUS status = LcCore_Initialize();
    MachenikePrint("MkRpc_Init: Engine init completed with status=0x%08X", status);
    return status;
}

VOID MkRpc_Cleanup(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        UserVar = ctxLeechRpc.UserVar;
    }

    MachenikePrint("MkRpc_Cleanup: Cleaning up RPC clients and watcher thread...");
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
    LcCore_Cleanup();
    MachenikePrint("MkRpc_Cleanup: Cleaned up successfully");
}





static NTSTATUS MkRpc_HandlePing(_In_ PLEECHRPC_MSG_HDR pReq, _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut)
{
    MachenikePrint("MkRpc_HandlePing: Ping received from ClientId=%u", pReq->dwRpcClientID);
    PLEECHRPC_MSG_HDR pRsp =
        (PLEECHRPC_MSG_HDR)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_HDR), LC_POOL_TAG);
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
    MachenikePrint("MkRpc_HandleOpen: Open request from ClientId=%u", pReqOpen->dwRpcClientID);
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    HANDLE hLC = LcCreateEx(ctxLeechRpc.UserVar, &pReqOpen->cfg, &pLcErrorInfo);

    if (hLC && !LeechRPC_LcHandle_New(pReqOpen->dwRpcClientID, hLC))
    {
        MachenikePrint("MkRpc_HandleOpen: Failed to register hLC into client list (max clients reached)");
        LcClose(hLC);
        hLC = NULL;
    }
    MachenikePrint("MkRpc_HandleOpen: ClientId=%u opened with hLC=%p", pReqOpen->dwRpcClientID, hLC);

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
        RtlCopyMemory(&pRspOpen->cfg, &pReqOpen->cfg, sizeof(LC_CONFIG));
        pRspOpen->cfg.fRemoteDisableCompress = TRUE;
        pRspOpen->flags = LEECHRPC_FLAG_FNEXIST_ReadScatterMEM | LEECHRPC_FLAG_FNEXIST_WriteScatterMEM |
                          LEECHRPC_FLAG_FNEXIST_Close | LEECHRPC_FLAG_FNEXIST_Command;
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

static NTSTATUS MkRpc_HandleClose(_In_ PLEECHRPC_MSG_HDR pReq, _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut)
{
    MachenikePrint("MkRpc_HandleClose: Closing ClientId=%u", pReq->dwRpcClientID);
    LeechRPC_LcHandle_Close(pReq->dwRpcClientID, FALSE);

    PLEECHRPC_MSG_HDR pRsp =
        (PLEECHRPC_MSG_HDR)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_HDR), LC_POOL_TAG);
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
                                      _Out_ PULONG pcbOut)
{
    PLEECHRPC_MSG_DATA pRspData =
        (PLEECHRPC_MSG_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_DATA), LC_POOL_TAG);
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

    if (pReqData)
    {
        pRspData->fMsgResult = LcGetOption(hLC, pReqData->qwData[0], &pRspData->qwData[0]);
    }
    else
    {
        pRspData->fMsgResult = FALSE;
    }

    MachenikePrint("MkRpc_HandleGetOption [ClientId=%u]: Option=0x%llX, result=%d, val=0x%llX",
                   pReqData ? pReqData->dwRpcClientID : 0,
                   pReqData ? pReqData->qwData[0] : 0,
                   pRspData->fMsgResult,
                   pRspData->qwData[0]);

    *ppbOut = (PUCHAR)pRspData;
    *pcbOut = sizeof(LEECHRPC_MSG_DATA);
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleSetOption(_In_ HANDLE hLC, _In_opt_ PLEECHRPC_MSG_DATA pReqData, _Out_ PUCHAR *ppbOut,
                                      _Out_ PULONG pcbOut)
{
    PLEECHRPC_MSG_HDR pRsp =
        (PLEECHRPC_MSG_HDR)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(LEECHRPC_MSG_HDR), LC_POOL_TAG);
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
                                        _In_ ULONG cbDirectOutMax)
{
    ULONG cMEMs = (ULONG)pReqBin->qwData[0];
    ULONG cbMax = (ULONG)pReqBin->qwData[1];

    if (pReqBin->cb != cMEMs * sizeof(MEM_SCATTER) || cMEMs > 0x2000 || cbMax > (cMEMs << 12))
    {
        return STATUS_INVALID_PARAMETER;
    }


    PMEM_SCATTER stack_ppMEMs[64];
    PMEM_SCATTER *ppMEMs = stack_ppMEMs;
    if (cMEMs > 64)
    {
        ppMEMs = (PMEM_SCATTER *)ExAllocatePoolWithTag(NonPagedPoolNx, cMEMs * sizeof(PMEM_SCATTER), LC_POOL_TAG);
        if (!ppMEMs)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    ULONG cbAlloc = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_SCATTER) + cbMax;
    PLEECHRPC_MSG_BIN pRspBin = NULL;

    if (pbDirectOut && cbAlloc <= cbDirectOutMax)
    {
        pRspBin = (PLEECHRPC_MSG_BIN)pbDirectOut;
    }
    else
    {
        pRspBin = (PLEECHRPC_MSG_BIN)ExAllocatePoolWithTag(NonPagedPoolNx, cbAlloc, LC_POOL_TAG);
    }

    if (!pRspBin)
    {
        if (ppMEMs != stack_ppMEMs)
        {
            ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pRspBin, sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_SCATTER));

    PMEM_SCATTER pMEM_Src = (PMEM_SCATTER)pReqBin->pb;
    PMEM_SCATTER pMEM_Dst = (PMEM_SCATTER)pRspBin->pb;
    RtlCopyMemory(pMEM_Dst, pMEM_Src, cMEMs * sizeof(MEM_SCATTER));

    PUCHAR pbData = pRspBin->pb + cMEMs * sizeof(MEM_SCATTER);
    ULONG cbDataOffset = 0;

    for (ULONG i = 0; i < cMEMs; i++)
    {
        pMEM_Dst[i].pb = pbData + cbDataOffset;
        ppMEMs[i] = &pMEM_Dst[i];
        cbDataOffset += pMEM_Dst[i].cb;
    }

    LcReadScatter(hLC, cMEMs, ppMEMs);

    pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
    pRspBin->tpMsg = LEECHRPC_MSGTYPE_READSCATTER_RSP;
    pRspBin->fMsgResult = TRUE;
    pRspBin->dwRpcClientID = pReqBin->dwRpcClientID;
    pRspBin->flags = LEECHRPC_FLAG_NOCOMPRESS;
    pRspBin->qwData[0] = cMEMs;
    pRspBin->qwData[1] = cbDataOffset;
    pRspBin->cbDecompress = 0;
    pRspBin->cb = cMEMs * sizeof(MEM_SCATTER) + cbDataOffset;
    pRspBin->cbMsg = sizeof(LEECHRPC_MSG_BIN) + pRspBin->cb;

    if (ppMEMs != stack_ppMEMs)
    {
        ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
    }

    *ppbOut = (PUCHAR)pRspBin;
    *pcbOut = pRspBin->cbMsg;
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleWriteScatter(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReqBin, _Out_ PUCHAR *ppbOut,
                                         _Out_ PULONG pcbOut,
                                         _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
                                         _In_ ULONG cbDirectOutMax)
{
    ULONG cMEMs = (ULONG)pReqBin->qwData[0];
    ULONG cbMax = (ULONG)pReqBin->qwData[1];

    if (cMEMs > 0x2000 || cbMax > (cMEMs << 12))
    {
        return STATUS_INVALID_PARAMETER;
    }

    PMEM_SCATTER stack_ppMEMs[64];
    PMEM_SCATTER *ppMEMs = stack_ppMEMs;
    if (cMEMs > 64)
    {
        ppMEMs = (PMEM_SCATTER *)ExAllocatePoolWithTag(NonPagedPoolNx, cMEMs * sizeof(PMEM_SCATTER), LC_POOL_TAG);
        if (!ppMEMs)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    ULONG cbAlloc = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_SCATTER);
    PLEECHRPC_MSG_BIN pRspBin = NULL;

    if (pbDirectOut && cbAlloc <= cbDirectOutMax)
    {
        pRspBin = (PLEECHRPC_MSG_BIN)pbDirectOut;
    }
    else
    {
        pRspBin = (PLEECHRPC_MSG_BIN)ExAllocatePoolWithTag(NonPagedPoolNx, cbAlloc, LC_POOL_TAG);
    }

    if (!pRspBin)
    {
        if (ppMEMs != stack_ppMEMs)
        {
            ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pRspBin, cbAlloc);

    PMEM_SCATTER pMEM_Src = (PMEM_SCATTER)pReqBin->pb;
    PMEM_SCATTER pMEM_Dst = (PMEM_SCATTER)pRspBin->pb;
    RtlCopyMemory(pMEM_Dst, pMEM_Src, cMEMs * sizeof(MEM_SCATTER));

    PUCHAR pbData = pReqBin->pb + cMEMs * sizeof(MEM_SCATTER);
    ULONG cbDataOffset = 0;

    for (ULONG i = 0; i < cMEMs; i++)
    {
        pMEM_Dst[i].pb = pbData + cbDataOffset;
        ppMEMs[i] = &pMEM_Dst[i];
        cbDataOffset += pMEM_Dst[i].cb;
    }

    LcWriteScatter(hLC, cMEMs, ppMEMs);

    pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
    pRspBin->tpMsg = LEECHRPC_MSGTYPE_WRITESCATTER_RSP;
    pRspBin->fMsgResult = TRUE;
    pRspBin->dwRpcClientID = pReqBin->dwRpcClientID;
    pRspBin->flags = LEECHRPC_FLAG_NOCOMPRESS;
    pRspBin->qwData[0] = cMEMs;
    pRspBin->qwData[1] = 0;
    pRspBin->cbDecompress = 0;
    pRspBin->cb = cMEMs * sizeof(MEM_SCATTER);
    pRspBin->cbMsg = sizeof(LEECHRPC_MSG_BIN) + pRspBin->cb;

    if (ppMEMs != stack_ppMEMs)
    {
        ExFreePoolWithTag(ppMEMs, LC_POOL_TAG);
    }

    *ppbOut = (PUCHAR)pRspBin;
    *pcbOut = pRspBin->cbMsg;
    return STATUS_SUCCESS;
}

static NTSTATUS MkRpc_HandleCommand(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReqBin, _Out_ PUCHAR *ppbOut,
                                    _Out_ PULONG pcbOut)
{
    ULONG64 fCommand = pReqBin->qwData[0];
    PUCHAR pbDataOut = NULL;
    ULONG cbDataOut = 0;


    BOOLEAN fResult = LcCommand(hLC, fCommand, pReqBin->cb, pReqBin->pb, &pbDataOut, &cbDataOut);
    MachenikePrint("MkRpc_HandleCommand [ClientId=%u]: Cmd=0x%llX, result=%d, cbOut=%u", pReqBin->dwRpcClientID,
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
    UNREFERENCED_PARAMETER(pTransportContext);
    *ppbOut = NULL;
    *pcbOut = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!pbIn || cbIn < sizeof(LEECHRPC_MSG_HDR))
    {
        return STATUS_INVALID_PARAMETER;
    }

    PLEECHRPC_MSG_HDR pHdr = (PLEECHRPC_MSG_HDR)pbIn;
    if (pHdr->dwMagic != LEECHRPC_MSGMAGIC || pHdr->cbMsg != cbIn)
    {
        MachenikePrint("MkRpc_DispatchCommand: Invalid magic=0x%08X (exp=0x%08X) or cbMsg=%u != cbIn=%u",
                       pHdr->dwMagic, LEECHRPC_MSGMAGIC, pHdr->cbMsg, cbIn);
        return STATUS_INVALID_PARAMETER;
    }





    if (pHdr->tpMsg == LEECHRPC_MSGTYPE_PING_REQ)
    {
        return MkRpc_HandlePing(pHdr, ppbOut, pcbOut);
    }
    if (pHdr->tpMsg == LEECHRPC_MSGTYPE_OPEN_REQ)
    {
        if (cbIn < sizeof(LEECHRPC_MSG_OPEN))
        {
            MachenikePrint("MkRpc_DispatchCommand: OPEN_REQ cbIn=%u < sizeof(LEECHRPC_MSG_OPEN)=%llu", cbIn,
                           (ULONGLONG)sizeof(LEECHRPC_MSG_OPEN));
            return STATUS_INVALID_PARAMETER;
        }
        return MkRpc_HandleOpen((PLEECHRPC_MSG_OPEN)pbIn, ppbOut, pcbOut);
    }
    if (pHdr->tpMsg == LEECHRPC_MSGTYPE_CLOSE_REQ)
    {
        return MkRpc_HandleClose(pHdr, ppbOut, pcbOut);
    }


    HANDLE hLC = LeechRPC_LcHandle_GetExisting(pHdr->dwRpcClientID);
    if (!hLC)
    {
        MachenikePrint("MkRpc_DispatchCommand: No active hLC found for ClientId=%u, MsgType=0x%08X",
                       pHdr->dwRpcClientID, pHdr->tpMsg);
        Status = STATUS_DEVICE_NOT_CONNECTED;
        goto handle_error_rsp;
    }

    switch (pHdr->tpMsg)
    {
    case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
    {
        MachenikePrint("MkRpc_DispatchCommand: KeepAlive from ClientId=%u", pHdr->dwRpcClientID);
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
        if (cbIn < sizeof(LEECHRPC_MSG_BIN))
        {
            Status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            Status = MkRpc_HandleReadScatter(hLC, (PLEECHRPC_MSG_BIN)pbIn, ppbOut, pcbOut, pbDirectOut, cbDirectOutMax);
        }
        break;

    case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
        if (cbIn < sizeof(LEECHRPC_MSG_BIN))
        {
            Status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            Status = MkRpc_HandleWriteScatter(hLC, (PLEECHRPC_MSG_BIN)pbIn, ppbOut, pcbOut, pbDirectOut, cbDirectOutMax);
        }
        break;

    case LEECHRPC_MSGTYPE_COMMAND_REQ:
        if (cbIn < sizeof(LEECHRPC_MSG_BIN))
        {
            Status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            Status = MkRpc_HandleCommand(hLC, (PLEECHRPC_MSG_BIN)pbIn, ppbOut, pcbOut);
        }
        break;

    case LEECHRPC_MSGTYPE_GETOPTION_REQ:
        Status = MkRpc_HandleGetOption(
            hLC, (cbIn >= sizeof(LEECHRPC_MSG_DATA)) ? (PLEECHRPC_MSG_DATA)pbIn : NULL, ppbOut, pcbOut);
        break;

    case LEECHRPC_MSGTYPE_SETOPTION_REQ:
        Status = MkRpc_HandleSetOption(
            hLC, (cbIn >= sizeof(LEECHRPC_MSG_DATA)) ? (PLEECHRPC_MSG_DATA)pbIn : NULL, ppbOut, pcbOut);
        break;

    default:
        Status = STATUS_NOT_SUPPORTED;
        break;
    }

handle_error_rsp:
    if (hLC)
    {
        LeechRPC_LcHandle_Return(hLC, pHdr->dwRpcClientID);
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
