path_cpp = r'E:\Project\Drv\MainDrv\Transport\TransportManager.cpp'
with open(path_cpp, 'r', encoding='utf-8') as f:
    text = f.read()

# 1. include eth_server.h if not present
if '#include "eth_server.h"' not in text:
    text = text.replace('#include "wsk_server.h"', '#include "wsk_server.h"\n#include "eth_server.h"')

# 2. StopServerLocked
stop_target = '''    else if (g_ActiveMode == MK_SERVER_MODE_WSK_UDP)
    {
        DBG("Transport_StopServer: Stopping WSK UDP Server...");
        UdpServer_Stop(UserVar);
        DBG("Transport_StopServer: WSK UDP Server stopped");
    }'''

stop_repl = '''    else if (g_ActiveMode == MK_SERVER_MODE_WSK_UDP)
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
    }'''

text = text.replace(stop_target, stop_repl)

# 3. StartServer switch case
start_target = '''        break;
    }

    default:
        DBG("Transport_StartServer: Unknown mode requested: %u", pParams->Mode);'''

start_repl = '''        break;
    }

    case MK_SERVER_MODE_RAW_ETH:
    {
        USHORT ethType = (pParams->Port == 0) ? MK_ETH_SERVER_DEFAULT_ETHERTYPE : (USHORT)pParams->Port;
        PCWSTR pAdapter = (pParams->DevicePath[0] != L'\\0') ? pParams->DevicePath : NULL;
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
            if (g_szTransportLastError[0] == '\\0')
                SetLastErrorFormat("[ETH:Init] Failed to start Ethernet server (0x%08X)", Status);
        }
        break;
    }

    default:
        DBG("Transport_StartServer: Unknown mode requested: %u", pParams->Mode);'''

text = text.replace(start_target, start_repl)

# 4. GetStatus
status_target = '''        pStatus->Port = udpPort;
        pStatus->ActiveConnections = activePackets;
        pStatus->fRunning = fUdpRunning;
    }'''

status_repl = '''        pStatus->Port = udpPort;
        pStatus->ActiveConnections = activePackets;
        pStatus->fRunning = fUdpRunning;
    }
    else if (g_ActiveMode == MK_SERVER_MODE_RAW_ETH)
    {
        BOOLEAN fEthRunning = FALSE;
        ULONG activeConn = 0;
        EthServer_GetStatus(&fEthRunning, &activeConn);
        pStatus->Port = MK_ETH_SERVER_DEFAULT_ETHERTYPE;
        pStatus->ActiveConnections = activeConn;
        pStatus->fRunning = fEthRunning;
    }'''

text = text.replace(status_target, status_repl)

with open(path_cpp, 'w', encoding='utf-8') as f:
    f.write(text)

print('TransportManager.cpp successfully updated!')
