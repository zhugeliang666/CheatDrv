#include "Common.h"
#include "ExceptionReporter.h"
#include "RpcDispatcher.h"
#include "TransportManager.h"

#if ENABLE_TRANSPORT_MODES
#include "udp_server.h"
#include "usb_server.h"
#include "wsk_server.h"
#include "eth_server.h"
#include "udp_discovery.h"
#endif

static MK_SERVER_MODE g_ActiveMode = MK_SERVER_MODE_NONE;
static MK_SERVER_MODE g_ConfiguredMode = MK_SERVER_MODE_NONE;
static KMUTEX g_TransportMutex;
static BOOLEAN g_fTransportMutexInit = FALSE;
static MACHENIKE_KERNEL_INTERFACE *g_pTransportUserVar = NULL;
static CHAR g_szTransportLastError[160] = {0};

const char *TransportManager::GetLastErrorDesc(VOID)
{
    return g_szTransportLastError[0] ? g_szTransportLastError : "Transport start failed";
}

VOID TransportManager::SetLastErrorDesc(const char *desc)
{
    if (desc)
    {
        SafeStrncpy(g_szTransportLastError, sizeof(g_szTransportLastError), desc);
        ExceptionReporter::Report("TransportManager::SetLastErrorDesc", STATUS_UNSUCCESSFUL, desc);
    }
    else
    {
        g_szTransportLastError[0] = '\0';
    }
}

VOID TransportManager::SetLastErrorFormat(const char *fmt, ...)
{
    if (!fmt)
    {
        g_szTransportLastError[0] = '\0';
        return;
    }
    va_list args;
    va_start(args, fmt);
    if (g_pTransportUserVar && g_pTransportUserVar->Func.pfn_vsnprintf)
        g_pTransportUserVar->Func.pfn_vsnprintf(g_szTransportLastError, sizeof(g_szTransportLastError), fmt, args);
    else if (g_pGlobalUserVar && g_pGlobalUserVar->Func.pfn_vsnprintf)
        g_pGlobalUserVar->Func.pfn_vsnprintf(g_szTransportLastError, sizeof(g_szTransportLastError), fmt, args);
    va_end(args);

    ExceptionReporter::Report("TransportManager::SetLastErrorFormat", STATUS_UNSUCCESSFUL, g_szTransportLastError);
}

extern "C" const char *Transport_GetLastErrorDesc(VOID)
{
    return TransportManager::GetLastErrorDesc();
}

extern "C" VOID Transport_SetLastErrorDesc(const char *desc)
{
    TransportManager::SetLastErrorDesc(desc);
}

extern "C" VOID Transport_SetLastErrorFormat(const char *fmt, ...)
{
    if (!fmt)
    {
        g_szTransportLastError[0] = '\0';
        return;
    }
    va_list args;
    va_start(args, fmt);
    if (g_pTransportUserVar && g_pTransportUserVar->Func.pfn_vsnprintf)
        g_pTransportUserVar->Func.pfn_vsnprintf(g_szTransportLastError, sizeof(g_szTransportLastError), fmt, args);
    else if (g_pGlobalUserVar && g_pGlobalUserVar->Func.pfn_vsnprintf)
        g_pGlobalUserVar->Func.pfn_vsnprintf(g_szTransportLastError, sizeof(g_szTransportLastError), fmt, args);
    va_end(args);

    ExceptionReporter::Report("Transport_SetLastErrorFormat", STATUS_UNSUCCESSFUL, g_szTransportLastError);
}

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
#if ENABLE_TRANSPORT_MODES
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
    else if (g_ActiveMode == MK_SERVER_MODE_RAW_ETH)
    {
        DBG("Transport_StopServer: Stopping Ethernet Server...");
        EthServer_Stop(UserVar);
        DBG("Transport_StopServer: Ethernet Server stopped");
    }

    g_ActiveMode = MK_SERVER_MODE_NONE;
#else
    UNREFERENCED_PARAMETER(UserVar);
#endif
}

NTSTATUS TransportManager::StartServer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PMK_SERVER_START_PARAMS pParams)
{
#if ENABLE_TRANSPORT_MODES
    if (!UserVar || !pParams)
    {
        DBG("Transport_StartServer: Invalid parameter");
        return STATUS_INVALID_PARAMETER;
    }
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
    MkRpc_Init(UserVar);

    NTSTATUS Status = STATUS_SUCCESS;

    g_szTransportLastError[0] = '\0';
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
            if (g_szTransportLastError[0] == '\0')
                SetLastErrorFormat("[TCP:WskInit] Failed to start WSK TCP server on port %u", port);
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
            if (g_szTransportLastError[0] == '\0')
                SetLastErrorFormat("[USB:Init] UsbServer_Init failed (status=0x%08X)", Status);
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
            if (g_szTransportLastError[0] == '\0')
                SetLastErrorFormat("[UDP:UdpInit] Failed to start WSK UDP server on port %u", port);
        }
        break;
    }

    case MK_SERVER_MODE_RAW_ETH:
    {
        USHORT ethType = (pParams->Port == 0) ? MK_ETH_SERVER_DEFAULT_ETHERTYPE : (USHORT)pParams->Port;
        PCWSTR pAdapter = (pParams->DevicePath[0] != L'\0') ? pParams->DevicePath : NULL;
        DBG("Transport_StartServer: Starting Ethernet Server (EtherType=0x%04X)...", ethType);
        Status = EthServer_Init(UserVar, ethType, pAdapter);
        if (NT_SUCCESS(Status))
        {
            g_ActiveMode = MK_SERVER_MODE_RAW_ETH;
            DBG("Transport_StartServer: Ethernet Server started successfully (EtherType=0x%04X)", ethType);
        }
        else
        {
            DBG("Transport_StartServer: Failed to start Ethernet Server, status=0x%08X", Status);
            if (g_szTransportLastError[0] == '\0')
                SetLastErrorFormat("[ETH:Init] Failed to start Ethernet server (0x%08X)", Status);
        }
        break;
    }

    default:
        DBG("Transport_StartServer: Unknown mode requested: %u", pParams->Mode);
        SetLastErrorFormat("[Transport:Param] Unknown transport mode %u requested", pParams->Mode);
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    ReleaseLock();
    return Status;
#else
    UNREFERENCED_PARAMETER(UserVar);
    UNREFERENCED_PARAMETER(pParams);
    DBG("TransportManager::StartServer: Transport modes disabled (ENABLE_TRANSPORT_MODES=0)");
    return STATUS_NOT_SUPPORTED;
#endif
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

#if ENABLE_TRANSPORT_MODES
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
#else
    pStatus->Port = 0;
    pStatus->ActiveConnections = 0;
#endif

#if ENABLE_TRANSPORT_MODES
    /* 方案 B 通道健康度：失败后仍需可读，供 R3 决定是否 DeleteService */
    {
        MK_ETH_CHANNEL_INFO ChannelInfo;
        RtlZeroMemory(&ChannelInfo, sizeof(ChannelInfo));
        if (NT_SUCCESS(EthServer_GetChannelInfo(&ChannelInfo)))
        {
            pStatus->fChannelReady = ChannelInfo.fReady;
            pStatus->fChannelArmed = ChannelInfo.fArmed;
            pStatus->fChannelFatal = ChannelInfo.fFatal;
            pStatus->ChannelFailReason = ChannelInfo.FailReason;
            pStatus->ChannelFailStatus = ChannelInfo.FailStatus;
            pStatus->ChannelFilterCount = ChannelInfo.FilterCount;
            pStatus->ChannelIfIndex = ChannelInfo.IfIndex;
            pStatus->ChannelTxDirect = ChannelInfo.TxDirect;
            pStatus->ChannelTxFailed = ChannelInfo.TxFailed;
            pStatus->ChannelRxStolen = ChannelInfo.RxStolen;
        }
    }
#endif

    ReleaseLock();
}

ULONG TransportManager::GetDiscoveredClientIp(VOID)
{
#if ENABLE_TRANSPORT_MODES
    return UdpDiscovery_GetDiscoveredIp();
#else
    return 0;
#endif
}

VOID TransportManager::SetConfiguredMode(MK_SERVER_MODE Mode)
{
    g_ConfiguredMode = Mode;
}

MK_SERVER_MODE TransportManager::GetActiveMode(VOID)
{
    return (g_ActiveMode != MK_SERVER_MODE_NONE) ? g_ActiveMode : g_ConfiguredMode;
}

BOOLEAN TransportManager::IsUsbMode(VOID)
{
    return (g_ActiveMode == MK_SERVER_MODE_USB || g_ConfiguredMode == MK_SERVER_MODE_USB);
}

// Dynamic Session Crypt Key (Zero Hardcoded Static Key)
#if NO_AUTH || ENABLE_NO_AUTH
static volatile ULONG64 g_SessionCryptKey = 0x8899AABBCCDDEEFFULL;
#else
static volatile ULONG64 g_SessionCryptKey = 0;
#endif

VOID TransportManager::SetSessionCryptKey(ULONG64 CryptKey)
{
    InterlockedExchange64((volatile LONG64 *)&g_SessionCryptKey, (LONG64)CryptKey);
}

ULONG64 TransportManager::GetSessionCryptKey(VOID)
{
    return (ULONG64)InterlockedCompareExchange64((volatile LONG64 *)&g_SessionCryptKey, 0, 0);
}

extern "C" ULONG64 Transport_GetSessionCryptKey(VOID) { return TransportManager::GetSessionCryptKey(); }
extern "C" VOID Transport_SetSessionCryptKey(ULONG64 CryptKey) { TransportManager::SetSessionCryptKey(CryptKey); }