#include "MapleRuntime.h"

static MAPLE_RUNTIME_SNAPSHOT g_MapleRuntime = {};

NTSTATUS MapleRuntime::Initialize()
{
    RtlZeroMemory(&g_MapleRuntime, sizeof(g_MapleRuntime));
    DBG("[*] [Maple] target mapping and packet injection runtime disabled");
    return STATUS_SUCCESS;
}

VOID MapleRuntime::Cleanup()
{
    MapleSubclassThunk::Cleanup();
    RtlZeroMemory(&g_MapleRuntime, sizeof(g_MapleRuntime));
}

NTSTATUS MapleRuntime::BindTarget(ULONG64 TargetCr3, ULONG64 ImageBase)
{
    UNREFERENCED_PARAMETER(TargetCr3);
    UNREFERENCED_PARAMETER(ImageBase);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS MapleRuntime::Refresh()
{
    return STATUS_NOT_SUPPORTED;
}

BOOLEAN MapleRuntime::GetSnapshot(PMAPLE_RUNTIME_SNAPSHOT Snapshot)
{
    if (Snapshot)
        RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    return FALSE;
}

NTSTATUS MapleRuntime::AutoAttachAndInstall()
{
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS MapleRuntime::InstallThunk()
{
    return STATUS_NOT_SUPPORTED;
}

VOID MapleRuntime::UninstallThunk()
{
    MapleSubclassThunk::Cleanup();
}

BOOLEAN MapleRuntime::IsTargetAlive()
{
    return FALSE;
}

ULONG MapleRuntime::GetTargetPid()
{
    return 0;
}

NTSTATUS MapleRuntime::PopCapturedPacket(PMAPLE_CAPTURED_PACKET Packet)
{
    return MapleSubclassThunk::PopCapturedPacket(Packet);
}

ULONG MapleRuntime::DrainHijackedPackets()
{
    return 0;
}

NTSTATUS MapleRuntime::SendPacket(USHORT Opcode, const UCHAR *Payload, ULONG Length)
{
    return MapleSubclassThunk::DispatchSendPacket(Opcode, Payload, Length);
}
