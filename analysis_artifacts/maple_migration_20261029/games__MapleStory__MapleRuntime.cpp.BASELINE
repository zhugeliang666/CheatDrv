#include "MapleRuntime.h"
#include "../../Core/DriverCore.h"

static MAPLE_RUNTIME_SNAPSHOT g_MapleRuntime = {};
static volatile ULONG g_TargetPid = 0;

NTSTATUS MapleRuntime::Initialize()
{
    DBG("[*] [Maple] MapleRuntime::Initialize: Starting subsystem self-tests...");
    RtlZeroMemory(&g_MapleRuntime, sizeof(g_MapleRuntime));
    InterlockedExchange((volatile LONG *)&g_TargetPid, 0);
    MapleMemory::Reset();

    if (!MaplePacketCrypto::SelfTest())
    {
        DBG("[-] [Maple] MapleRuntime::Initialize: MaplePacketCrypto::SelfTest failed!");
        return STATUS_DATA_ERROR;
    }

    if (!MaplePacketCodec::SelfTest())
    {
        DBG("[-] [Maple] MapleRuntime::Initialize: MaplePacketCodec::SelfTest failed!");
        return STATUS_DATA_ERROR;
    }

    DBG("[+] [Maple] MapleRuntime::Initialize: Subsystem successfully initialized and self-tested");
    return STATUS_SUCCESS;
}

VOID MapleRuntime::Cleanup()
{
    DBG("[*] [Maple] MapleRuntime::Cleanup: Cleaning up subsystem runtime...");
    UninstallThunk();
    RtlZeroMemory(&g_MapleRuntime, sizeof(g_MapleRuntime));
    MapleMemory::Reset();
    InterlockedExchange((volatile LONG *)&g_TargetPid, 0);
    DBG("[+] [Maple] MapleRuntime::Cleanup: Subsystem cleanup complete");
}

NTSTATUS MapleRuntime::BindTarget(ULONG64 TargetCr3, ULONG64 ImageBase)
{
    DBG("[*] [Maple] MapleRuntime::BindTarget: Binding target (CR3=0x%llX, ImageBase=0x%llX)...", TargetCr3, ImageBase);
    NTSTATUS status = MapleMemory::BindTarget(TargetCr3, ImageBase);
    if (!NT_SUCCESS(status))
    {
        DBG("[-] [Maple] MapleRuntime::BindTarget: MapleMemory::BindTarget failed (status=0x%08X)", status);
        return status;
    }

    g_MapleRuntime.TargetCr3 = TargetCr3;
    g_MapleRuntime.ImageBase = ImageBase;

    status = Refresh();
    if (status == STATUS_NOT_FOUND)
    {
        DBG("[*] [Maple] MapleRuntime::BindTarget: Target bound, waiting for ClientSocket creation...");
        return STATUS_PENDING;
    }
    else if (!NT_SUCCESS(status))
    {
        DBG("[-] [Maple] MapleRuntime::BindTarget: Initial Refresh failed (status=0x%08X), rolling back bind", status);
        Cleanup();
        return status;
    }

    DBG("[+] [Maple] MapleRuntime::BindTarget: Successfully bound and synchronized with target process");
    return STATUS_SUCCESS;
}

NTSTATUS MapleRuntime::Refresh()
{
    const ULONG64 imageBase = MapleMemory::GetImageBase();
    if (!imageBase)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    const ULONG64 slotAddress = imageBase + MapleLayout::ClientSocketSlotRva;
    ULONG64 clientSocket = 0;
    if (!MapleMemory::Read(slotAddress, &clientSocket))
    {
        return STATUS_NOT_FOUND;
    }

    if (!clientSocket)
    {
        return STATUS_NOT_FOUND;
    }

    if (!MapleMemory::IsUserRange(clientSocket, 0xF0))
    {
        DBG("[-] [Maple] Refresh: ClientSocket pointer (0x%llX) out of user range", clientSocket);
        return STATUS_NOT_FOUND;
    }

    ULONG64 vtable = 0;
    ULONG64 windowHandle = 0;
    ULONG64 nativeSocket = 0;
    ULONG isLoginServer = 0;
    ULONG sendSequence = 0;
    ULONG receiveSequence = 0;

    const ULONG64 expectedVtable = imageBase + MapleLayout::ClientSocketVtableRva;
    if (!MapleMemory::Read(clientSocket, &vtable))
    {
        DBG("[-] [Maple] Refresh: Failed to read vtable at 0x%llX", clientSocket);
        return STATUS_DATA_ERROR;
    }

    if (vtable != expectedVtable)
    {
        DBG("[-] [Maple] Refresh: Vtable mismatch! Read=0x%llX, Expected=0x%llX (slot=0x%llX, obj=0x%llX)",
            vtable, expectedVtable, slotAddress, clientSocket);
        return STATUS_DATA_ERROR;
    }

    if (!MapleMemory::Read(clientSocket + MapleLayout::ClientSocketHwndOffset, &windowHandle) ||
        !MapleMemory::Read(clientSocket + MapleLayout::ClientSocketNativeSocketOffset, &nativeSocket) ||
        !MapleMemory::Read(clientSocket + MapleLayout::ClientSocketCryptoModeOffset, &isLoginServer) ||
        !MapleMemory::Read(clientSocket + MapleLayout::ClientSocketSendSequenceOffset, &sendSequence) ||
        !MapleMemory::Read(clientSocket + MapleLayout::ClientSocketReceiveSequenceOffset, &receiveSequence))
    {
        DBG("[-] [Maple] Refresh: Failed to read fields of ClientSocket at 0x%llX", clientSocket);
        return STATUS_DATA_ERROR;
    }

    const ULONG mode = (isLoginServer != 0) ? MapleCryptoModeAes256Ofb : MapleCryptoModeSimple;

    UCHAR shufflePrefix[8] = {};
    const ULONG64 shuffleAddress = imageBase + MapleLayout::InnoShuffleRva;
    if (!MapleMemory::ReadBuffer(shuffleAddress, shufflePrefix, sizeof(shufflePrefix)) ||
        !MaplePacketCrypto::ValidateShufflePrefix(shufflePrefix, sizeof(shufflePrefix)))
    {
        DBG("[-] [Maple] Refresh: InnoShuffle table validation failed at 0x%llX", shuffleAddress);
        return STATUS_REVISION_MISMATCH;
    }

    if (g_MapleRuntime.ClientSocket != clientSocket)
    {
        ++g_MapleRuntime.Generation;
        DBG("[*] [Maple] MapleRuntime::Refresh: ClientSocket online! (Addr=0x%llX, Vtable=0x%llX, Sock=0x%llX, Hwnd=0x%llX, Mode=%lu, Gen=%lu)",
            clientSocket, vtable, nativeSocket, windowHandle, mode, g_MapleRuntime.Generation);
    }

    g_MapleRuntime.TargetCr3 = MapleMemory::GetTargetCr3();
    g_MapleRuntime.ImageBase = imageBase;
    g_MapleRuntime.ClientSocket = clientSocket;
    g_MapleRuntime.Vtable = vtable;
    g_MapleRuntime.WindowHandle = windowHandle;
    g_MapleRuntime.NativeSocket = nativeSocket;
    g_MapleRuntime.SendSequence = sendSequence;
    g_MapleRuntime.ReceiveSequence = receiveSequence;
    g_MapleRuntime.CryptoMode = mode;
    g_MapleRuntime.Bound = TRUE;

    return STATUS_SUCCESS;
}

BOOLEAN MapleRuntime::GetSnapshot(PMAPLE_RUNTIME_SNAPSHOT Snapshot)
{
    if (!Snapshot || !g_MapleRuntime.Bound)
        return FALSE;
    RtlCopyMemory(Snapshot, &g_MapleRuntime, sizeof(*Snapshot));
    return TRUE;
}

NTSTATUS MapleRuntime::AutoAttachAndInstall()
{
    if (MapleSubclassThunk::IsInstalled())
    {
        return STATUS_SUCCESS;
    }

    // 若已经绑定目标进程且进程存活，优先直接探测 ClientSocket 初始化状态，避免重复遍历 PID
    if (g_MapleRuntime.TargetCr3 && IsTargetAlive())
    {
        NTSTATUS refStatus = Refresh();
        if (NT_SUCCESS(refStatus))
        {
            NTSTATUS instStatus = InstallThunk();
            if (NT_SUCCESS(instStatus))
            {
                DBG("[+] [Maple] AutoAttach: ClientSocket online; Image-Backed RX + Shared RW + GWLP_WNDPROC installed");
                return STATUS_SUCCESS;
            }
            else
            {
                DBG("[-] [Maple] AutoAttach: InstallThunk failed (0x%08X)", instStatus);
                return instStatus;
            }
        }
        return refStatus;
    }

    if (!g_pGlobalUserVar || !g_pGlobalUserVar->Func.PsLookupProcessByProcessId)
    {
        return STATUS_NOT_SUPPORTED;
    }

    ULONG targetPid = 0;
    ULONG64 targetCr3 = 0;
    ULONG64 imageBase = 0;

    // 遍历活动 PID 寻找 MapleStory.exe
    for (ULONG pid = 4; pid <= 0x10000; pid += 4)
    {
        PEPROCESS pProcess = NULL;
        if (NT_SUCCESS(g_pGlobalUserVar->Func.PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &pProcess)) && pProcess)
        {
            BOOLEAN matched = FALSE;
            // 扫描 EPROCESS 中的 ImageFileName 字符串 (Windows 跨版本滑动窗口)
            for (ULONG off = 0x400; off <= 0x680; off += 1)
            {
                if (RtlCompareMemory((PUCHAR)pProcess + off, "MapleStory", 10) == 10)
                {
                    matched = TRUE;
                    break;
                }
            }

            if (matched)
            {
                targetPid = pid;
                // DirectoryTableBase 在 x64 Windows 上稳定位于 EPROCESS + 0x28
                targetCr3 = *(PULONG64)((PUCHAR)pProcess + 0x28);

                if (g_pGlobalUserVar->Func.PsGetProcessSectionBaseAddress)
                {
                    imageBase = (ULONG64)g_pGlobalUserVar->Func.PsGetProcessSectionBaseAddress(pProcess);
                }

                if (!imageBase)
                {
                    imageBase = 0x0000000140000000ULL;
                }

                if (g_pGlobalUserVar->Func.ObfDereferenceObject)
                {
                    g_pGlobalUserVar->Func.ObfDereferenceObject(pProcess);
                }
                break;
            }

            if (g_pGlobalUserVar->Func.ObfDereferenceObject)
            {
                g_pGlobalUserVar->Func.ObfDereferenceObject(pProcess);
            }
        }
    }

    if (!targetPid || !targetCr3)
    {
        return STATUS_NOT_FOUND;
    }

    DBG("[+] [Maple] AutoAttach: Found MapleStory.exe (PID=%lu, CR3=0x%llX, Base=0x%llX)",
        targetPid, targetCr3, imageBase);

    InterlockedExchange((volatile LONG *)&g_TargetPid, static_cast<LONG>(targetPid));

    NTSTATUS status = BindTarget(targetCr3, imageBase);
    if (status == STATUS_PENDING)
    {
        // 目标进程成功绑定 CR3，正在等待游戏初始化网络 ClientSocket
        return STATUS_PENDING;
    }
    else if (!NT_SUCCESS(status))
    {
        DBG("[-] [Maple] AutoAttach: BindTarget failed (0x%08X)", status);
        InterlockedExchange((volatile LONG *)&g_TargetPid, 0);
        return status;
    }

    status = InstallThunk();
    if (!NT_SUCCESS(status))
    {
        DBG("[-] [Maple] AutoAttach: InstallThunk failed (0x%08X)", status);
        InterlockedExchange((volatile LONG *)&g_TargetPid, 0);
        return status;
    }

    DBG("[+] [Maple] AutoAttach: Successfully attached with zero target image writes");
    return STATUS_SUCCESS;
}

NTSTATUS MapleRuntime::InstallThunk()
{
    if (!g_MapleRuntime.Bound || !g_MapleRuntime.ClientSocket)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    return MapleSubclassThunk::Initialize(g_MapleRuntime.TargetCr3, g_MapleRuntime.ImageBase, g_MapleRuntime.ClientSocket);
}

VOID MapleRuntime::UninstallThunk()
{
    MapleSubclassThunk::Cleanup();
}

BOOLEAN MapleRuntime::IsTargetAlive()
{
    const ULONG pid = static_cast<ULONG>(InterlockedCompareExchange((volatile LONG *)&g_TargetPid, 0, 0));
    if (!pid || !g_pGlobalUserVar || !g_pGlobalUserVar->Func.PsLookupProcessByProcessId)
        return FALSE;

    PEPROCESS pProcess = NULL;
    NTSTATUS st = g_pGlobalUserVar->Func.PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &pProcess);
    if (!NT_SUCCESS(st) || !pProcess)
    {
        return FALSE;
    }

    ULONG64 currentCr3 = *(PULONG64)((PUCHAR)pProcess + 0x28);
    if (g_pGlobalUserVar->Func.ObfDereferenceObject)
    {
        g_pGlobalUserVar->Func.ObfDereferenceObject(pProcess);
    }

    const ULONG64 boundCr3 = MapleMemory::GetTargetCr3();
    return (currentCr3 != 0 && currentCr3 == boundCr3);
}

ULONG MapleRuntime::GetTargetPid()
{
    return static_cast<ULONG>(InterlockedCompareExchange((volatile LONG *)&g_TargetPid, 0, 0));
}

NTSTATUS MapleRuntime::PopCapturedPacket(PMAPLE_CAPTURED_PACKET Packet)
{
    return MapleSubclassThunk::PopCapturedPacket(Packet);
}

ULONG MapleRuntime::DrainHijackedPackets()
{
    if (!IsTargetAlive())
    {
        DBG("[*] [Maple] Target process (PID=%lu) terminated or exited, cleaning up NoText state", GetTargetPid());
        Cleanup();
        return 0;
    }
    return MapleSubclassThunk::DrainHijackedPackets();
}

NTSTATUS MapleRuntime::SendPacket(USHORT Opcode, const UCHAR *Payload, ULONG Length)
{
    return MapleSubclassThunk::DispatchSendPacket(Opcode, Payload, Length);
}

