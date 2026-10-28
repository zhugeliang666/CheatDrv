#pragma once

#include "MaplePacketTypes.h"
#include "MapleSubclassThunk.h"

class MapleRuntime
{
  public:
    // 保留最小兼容接口；不再扫描、绑定、写入或注入任何目标进程。
    static NTSTATUS Initialize();
    static VOID Cleanup();
    static NTSTATUS BindTarget(_In_ ULONG64 TargetCr3, _In_ ULONG64 ImageBase);
    static NTSTATUS Refresh();
    static BOOLEAN GetSnapshot(_Out_ PMAPLE_RUNTIME_SNAPSHOT Snapshot);
    static NTSTATUS AutoAttachAndInstall();
    static NTSTATUS InstallThunk();
    static VOID UninstallThunk();
    static BOOLEAN IsTargetAlive();
    static ULONG GetTargetPid();
    static NTSTATUS PopCapturedPacket(_Out_ PMAPLE_CAPTURED_PACKET Packet);
    static ULONG DrainHijackedPackets();
    static NTSTATUS SendPacket(_In_ USHORT Opcode, _In_reads_bytes_(Length) const UCHAR *Payload, _In_ ULONG Length);
};
