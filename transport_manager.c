#include "transport_manager.h"
#include "Common.h"
#include "wsk_server.h"
#include "usb_server.h"
#include "udp_server.h"
#include "rpc_dispatch.h"

static MK_SERVER_MODE g_ActiveMode = MK_SERVER_MODE_NONE;
static KMUTEX g_TransportMutex;
static BOOLEAN g_fTransportMutexInit = FALSE;

static VOID EnsureLockInit(VOID)
{
    if (!g_fTransportMutexInit)
    {
        KeInitializeMutex(&g_TransportMutex, 0);
        g_fTransportMutexInit = TRUE;
    }
}

static VOID Transport_AcquireLock(VOID)
{
    EnsureLockInit();
    KeWaitForSingleObject(&g_TransportMutex, Executive, KernelMode, FALSE, NULL);
}

static VOID Transport_ReleaseLock(VOID)
{
    KeReleaseMutex(&g_TransportMutex, FALSE);
}

VOID Transport_Init(VOID)
{
    EnsureLockInit();
}

NTSTATUS Transport_StartServer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PMK_SERVER_START_PARAMS pParams)
{
    if (!UserVar || !pParams)
    {
        MachenikePrint("Transport_StartServer: Invalid parameter");
        return STATUS_INVALID_PARAMETER;
    }

    MkRpc_Init(UserVar);

    Transport_AcquireLock();

    if (g_ActiveMode != MK_SERVER_MODE_NONE)
    {
        if ((ULONG)g_ActiveMode == pParams->Mode)
        {
            MachenikePrint("Transport_StartServer: Server already running in mode=%u, reuse existing server", g_ActiveMode);
            Transport_ReleaseLock();
            return STATUS_SUCCESS;
        }
        else
        {
            MachenikePrint("Transport_StartServer: Server already running in different mode=%u, stop it first", g_ActiveMode);
            Transport_ReleaseLock();
            return STATUS_ALREADY_COMMITTED;
        }
    }

    NTSTATUS Status = STATUS_SUCCESS;

    switch (pParams->Mode)
    {
    case MK_SERVER_MODE_WSK_TCP:
    {
        USHORT port = (pParams->Port == 0) ? MK_WSK_DEFAULT_PORT : (USHORT)pParams->Port;
        MachenikePrint("Transport_StartServer: Starting WSK TCP Server on port %u...", port);
        Status = WskServer_Init(UserVar, port);
        if (NT_SUCCESS(Status))
        {
            g_ActiveMode = MK_SERVER_MODE_WSK_TCP;
            MachenikePrint("Transport_StartServer: WSK TCP Server started successfully on port %u", port);
        }
        else
        {
            MachenikePrint("Transport_StartServer: Failed to start WSK TCP Server, status=0x%08X", Status);
        }
        break;
    }

    case MK_SERVER_MODE_USB:
    {
        MachenikePrint("Transport_StartServer: Starting USB Server (Auto-detecting device and endpoints)...");
        Status = UsbServer_Init(UserVar, pParams);
        if (NT_SUCCESS(Status))
        {
            g_ActiveMode = MK_SERVER_MODE_USB;
            MachenikePrint("Transport_StartServer: USB Server started successfully (Device=%ws, PipeIn=0x%02X, PipeOut=0x%02X)",
                           g_UsbServer.DevicePath, g_UsbServer.PipeIn, g_UsbServer.PipeOut);
        }
        else
        {
            MachenikePrint("Transport_StartServer: Failed to start USB Server, status=0x%08X", Status);
        }
        break;
    }

    case MK_SERVER_MODE_WSK_UDP:
    {
        USHORT port = (pParams->Port == 0) ? MK_UDP_SERVER_DEFAULT_PORT : (USHORT)pParams->Port;
        MachenikePrint("Transport_StartServer: Starting WSK UDP Server on port %u...", port);
        Status = UdpServer_Init(UserVar, port);
        if (NT_SUCCESS(Status))
        {
            g_ActiveMode = MK_SERVER_MODE_WSK_UDP;
            MachenikePrint("Transport_StartServer: WSK UDP Server started successfully on port %u", port);
        }
        else
        {
            MachenikePrint("Transport_StartServer: Failed to start WSK UDP Server, status=0x%08X", Status);
        }
        break;
    }

    default:
        MachenikePrint("Transport_StartServer: Unknown mode requested: %u", pParams->Mode);
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    Transport_ReleaseLock();
    return Status;
}

VOID Transport_StopServer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (!UserVar)
    {
        return;
    }

    Transport_AcquireLock();

    if (g_ActiveMode == MK_SERVER_MODE_WSK_TCP)
    {
        MachenikePrint("Transport_StopServer: Stopping WSK TCP Server...");
        WskServer_Stop(UserVar);
        MachenikePrint("Transport_StopServer: WSK TCP Server stopped");
    }
    else if (g_ActiveMode == MK_SERVER_MODE_USB)
    {
        MachenikePrint("Transport_StopServer: Stopping USB Server...");
        UsbServer_Stop(UserVar);
        MachenikePrint("Transport_StopServer: USB Server stopped");
    }
    else if (g_ActiveMode == MK_SERVER_MODE_WSK_UDP)
    {
        MachenikePrint("Transport_StopServer: Stopping WSK UDP Server...");
        UdpServer_Stop(UserVar);
        MachenikePrint("Transport_StopServer: WSK UDP Server stopped");
    }

    g_ActiveMode = MK_SERVER_MODE_NONE;
    Transport_ReleaseLock();
}

VOID Transport_GetStatus(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PMK_SERVER_STATUS pStatus)
{
    if (!pStatus || !UserVar)
    {
        return;
    }

    Transport_AcquireLock();

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

    Transport_ReleaseLock();
}

ULONG Transport_GetDiscoveredClientIp(VOID)
{
    return UdpDiscovery_GetDiscoveredIp();
}
