#include "TransportManager.h"
#include "Common.h"
#include "wsk_server.h"
#include "usb_server.h"
#include "udp_server.h"
#include "RpcDispatcher.h"

static MK_SERVER_MODE g_ActiveMode = MK_SERVER_MODE_NONE;
static KMUTEX g_TransportMutex;
static BOOLEAN g_fTransportMutexInit = FALSE;
static MACHENIKE_KERNEL_INTERFACE *g_pTransportUserVar = NULL;

static VOID EnsureLockInit(VOID)
{
    if (!g_fTransportMutexInit)
    {
        if (g_pTransportUserVar && g_pTransportUserVar->Func.KeInitializeMutex)
        {
            g_pTransportUserVar->Func.KeInitializeMutex(&g_TransportMutex, 0);
        }
        g_fTransportMutexInit = TRUE;
    }
}

static VOID AcquireLock(VOID)
{
    EnsureLockInit();
    if (g_pTransportUserVar && g_pTransportUserVar->Func.KeWaitForSingleObject)
    {
        g_pTransportUserVar->Func.KeWaitForSingleObject(&g_TransportMutex, Executive, KernelMode, FALSE, NULL);
    }
}

static VOID ReleaseLock(VOID)
{
    if (g_pTransportUserVar && g_pTransportUserVar->Func.KeReleaseMutex)
    {
        g_pTransportUserVar->Func.KeReleaseMutex(&g_TransportMutex, FALSE);
    }
}

VOID TransportManager::Init(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (UserVar)
    {
        g_pTransportUserVar = UserVar;
    }
    EnsureLockInit();
}

static VOID StopServerLocked(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        return;
    }

    if (g_ActiveMode == MK_SERVER_MODE_WSK_TCP)
    {
        DBG("Transport_StopServer: Stopping WSK TCP Server...");
        WskServer_Stop(UserVar);
        DBG("Transport_StopServer: WSK TCP Server stopped");
    }
    else if (g_ActiveMode == MK_SERVER_MODE_USB)
    {
        DBG("Transport_StopServer: Stopping USB Server...");
        UsbServer_Stop(UserVar);
        DBG("Transport_StopServer: USB Server stopped");
    }
    else if (g_ActiveMode == MK_SERVER_MODE_WSK_UDP)
    {
        DBG("Transport_StopServer: Stopping WSK UDP Server...");
        UdpServer_Stop(UserVar);
        DBG("Transport_StopServer: WSK UDP Server stopped");
    }

    g_ActiveMode = MK_SERVER_MODE_NONE;
}

NTSTATUS TransportManager::StartServer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PMK_SERVER_START_PARAMS pParams)
{
    if (!UserVar || !pParams)
    {
        DBG("Transport_StartServer: Invalid parameter");
        return STATUS_INVALID_PARAMETER;
    }

    MkRpc_Init(UserVar);

    AcquireLock();

    if (g_ActiveMode != MK_SERVER_MODE_NONE)
    {
        if ((ULONG)g_ActiveMode == pParams->Mode)
        {
            DBG("Transport_StartServer: Server already running in mode=%u, reuse existing server", g_ActiveMode);
            ReleaseLock();
            return STATUS_SUCCESS;
        }
        else
        {
            DBG("Transport_StartServer: Server already running in different mode=%u, stopping it automatically...", g_ActiveMode);
            StopServerLocked(UserVar);
            DBG("Transport_StartServer: Previous mode stopped, switching to new mode=%u", pParams->Mode);
        }
    }

    NTSTATUS Status = STATUS_SUCCESS;

    switch (pParams->Mode)
    {
    case MK_SERVER_MODE_WSK_TCP:
    {
        USHORT port = (pParams->Port == 0) ? MK_WSK_DEFAULT_PORT : (USHORT)pParams->Port;
        DBG("Transport_StartServer: Starting WSK TCP Server on port %u...", port);
        Status = WskServer_Init(UserVar, port);
        if (NT_SUCCESS(Status))
        {
            g_ActiveMode = MK_SERVER_MODE_WSK_TCP;
            DBG("Transport_StartServer: WSK TCP Server started successfully on port %u", port);
        }
        else
        {
            DBG("Transport_StartServer: Failed to start WSK TCP Server, status=0x%08X", Status);
        }
        break;
    }

    case MK_SERVER_MODE_USB:
    {
        DBG("Transport_StartServer: Starting USB Server (Auto-detecting device and endpoints)...");
        Status = UsbServer_Init(UserVar, pParams);
        if (NT_SUCCESS(Status))
        {
            g_ActiveMode = MK_SERVER_MODE_USB;
            DBG("Transport_StartServer: USB Server started successfully (Device=%ws, PipeIn=0x%02X, PipeOut=0x%02X)",
                           g_UsbServer.DevicePath, g_UsbServer.PipeIn, g_UsbServer.PipeOut);
        }
        else
        {
            DBG("Transport_StartServer: Failed to start USB Server, status=0x%08X", Status);
        }
        break;
    }

    case MK_SERVER_MODE_WSK_UDP:
    {
        USHORT port = (pParams->Port == 0) ? MK_UDP_SERVER_DEFAULT_PORT : (USHORT)pParams->Port;
        DBG("Transport_StartServer: Starting WSK UDP Server on port %u...", port);
        Status = UdpServer_Init(UserVar, port);
        if (NT_SUCCESS(Status))
        {
            g_ActiveMode = MK_SERVER_MODE_WSK_UDP;
            DBG("Transport_StartServer: WSK UDP Server started successfully on port %u", port);
        }
        else
        {
            DBG("Transport_StartServer: Failed to start WSK UDP Server, status=0x%08X", Status);
        }
        break;
    }

    default:
        DBG("Transport_StartServer: Unknown mode requested: %u", pParams->Mode);
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    ReleaseLock();
    return Status;
}

VOID TransportManager::StopServer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        return;
    }

    AcquireLock();
    StopServerLocked(UserVar);
    ReleaseLock();
}

VOID TransportManager::GetStatus(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PMK_SERVER_STATUS pStatus)
{
    if (!pStatus || !UserVar)
    {
        return;
    }

    AcquireLock();

    pStatus->Mode = (ULONG)g_ActiveMode;
    pStatus->fRunning = (g_ActiveMode != MK_SERVER_MODE_NONE);

    if (g_ActiveMode == MK_SERVER_MODE_WSK_TCP)
    {
        pStatus->Port = (ULONG)g_WskServer.Port;
        pStatus->ActiveConnections = g_WskServer.ActiveClientCount;
    }
    else if (g_ActiveMode == MK_SERVER_MODE_USB)
    {
        pStatus->Port = 0;
        BOOLEAN fUsbRunning = FALSE;
        UsbServer_GetStatus(UserVar, (PULONG)&pStatus->ActiveConnections, &fUsbRunning);
        pStatus->fRunning = fUsbRunning;
    }
    else if (g_ActiveMode == MK_SERVER_MODE_WSK_UDP)
    {
        BOOLEAN fUdpRunning = FALSE;
        USHORT udpPort = 0;
        LONG activePackets = 0;
        UdpServer_GetStatus(UserVar, &fUdpRunning, &udpPort, &activePackets);
        pStatus->Port = (ULONG)udpPort;
        pStatus->fRunning = fUdpRunning;
        pStatus->ActiveConnections = activePackets;
    }
    else
    {
        pStatus->Port = 0;
        pStatus->ActiveConnections = 0;
    }

    ReleaseLock();
}

ULONG TransportManager::GetDiscoveredClientIp(VOID)
{
    return UdpDiscovery_GetDiscoveredIp();
}


// Dynamic Session Crypt Key (Zero Hardcoded Static Key)
static volatile ULONG64 g_SessionCryptKey = 0;

VOID TransportManager::SetSessionCryptKey(ULONG64 CryptKey)
{
    InterlockedExchange64((volatile LONG64 *)&g_SessionCryptKey, (LONG64)CryptKey);
}

ULONG64 TransportManager::GetSessionCryptKey(VOID)
{
    return (ULONG64)InterlockedCompareExchange64((volatile LONG64 *)&g_SessionCryptKey, 0, 0);
}

extern "C" ULONG64 Transport_GetSessionCryptKey(VOID)
{
    return TransportManager::GetSessionCryptKey();
}

extern "C" VOID Transport_SetSessionCryptKey(ULONG64 CryptKey)
{
    TransportManager::SetSessionCryptKey(CryptKey);
}
