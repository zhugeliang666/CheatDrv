#include "MapleSubclassThunk.h"

#ifndef _MAPLE_USER_PAYLOAD_BUILD
NTSTATUS MapleSubclassThunk::Initialize(ULONG64 TargetCr3, ULONG64 ImageBase, ULONG64 ClientSocket)
{
    UNREFERENCED_PARAMETER(TargetCr3);
    UNREFERENCED_PARAMETER(ImageBase);
    UNREFERENCED_PARAMETER(ClientSocket);
    DBG("[*] [Maple] target mapping chain disabled; use NestedPageInstrumentation for read-only events");
    return STATUS_NOT_SUPPORTED;
}

VOID MapleSubclassThunk::Cleanup()
{
}

BOOLEAN MapleSubclassThunk::IsInstalled()
{
    return FALSE;
}

NTSTATUS MapleSubclassThunk::PopCapturedPacket(PMAPLE_CAPTURED_PACKET Packet)
{
    if (Packet)
        RtlZeroMemory(Packet, sizeof(*Packet));
    return STATUS_DEVICE_NOT_READY;
}

ULONG MapleSubclassThunk::DrainHijackedPackets()
{
    return 0;
}

NTSTATUS MapleSubclassThunk::DispatchSendPacket(USHORT Opcode, const UCHAR *Payload, ULONG Length)
{
    UNREFERENCED_PARAMETER(Opcode);
    UNREFERENCED_PARAMETER(Payload);
    UNREFERENCED_PARAMETER(Length);
    return STATUS_NOT_SUPPORTED;
}
#endif
