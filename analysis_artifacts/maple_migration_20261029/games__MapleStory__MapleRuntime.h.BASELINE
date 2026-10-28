#pragma once

#include "MapleMemory.h"
#include "MaplePacketCodec.h"
#include "MapleSubclassThunk.h"

class MapleRuntime
{
  public:
    static NTSTATUS Initialize();
    static VOID Cleanup();
    static NTSTATUS BindTarget(_In_ ULONG64 TargetCr3, _In_ ULONG64 ImageBase);
    static NTSTATUS Refresh();
    static BOOLEAN GetSnapshot(_Out_ PMAPLE_RUNTIME_SNAPSHOT Snapshot);

    // 第四节：无痕子类化截获与主线程发包契约
    static NTSTATUS AutoAttachAndInstall();
    static NTSTATUS InstallThunk();
    static VOID UninstallThunk();
    static BOOLEAN IsTargetAlive();
    static ULONG GetTargetPid();
    static NTSTATUS PopCapturedPacket(_Out_ PMAPLE_CAPTURED_PACKET Packet);
    static ULONG DrainHijackedPackets();
    static NTSTATUS SendPacket(_In_ USHORT Opcode, _In_reads_bytes_(Length) const UCHAR *Payload, _In_ ULONG Length);
};
