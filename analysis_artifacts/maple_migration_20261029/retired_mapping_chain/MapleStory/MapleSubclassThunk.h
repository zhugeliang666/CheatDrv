#pragma once

#ifndef _MAPLE_USER_PAYLOAD_BUILD
#include "../../Core/Common.h"
#endif

#define MAPLE_THUNK_RING_CAPACITY 16
#define MAPLE_THUNK_MAX_PAYLOAD 128

#pragma pack(push, 8)
typedef struct _MAPLE_CAPTURED_PACKET
{
    ULONG Direction;
    ULONG DataLength;
    ULONG Sequence;
    USHORT Opcode;
    UCHAR Reserved[2];
    UCHAR Payload[MAPLE_THUNK_MAX_PAYLOAD];
} MAPLE_CAPTURED_PACKET, *PMAPLE_CAPTURED_PACKET;
#pragma pack(pop)

#ifndef _MAPLE_USER_PAYLOAD_BUILD
class MapleSubclassThunk
{
  public:
    // 映射、APC、窗口子类化和目标进程写入链已移除；该接口仅保留 ABI 兼容性。
    static NTSTATUS Initialize(_In_ ULONG64 TargetCr3, _In_ ULONG64 ImageBase, _In_ ULONG64 ClientSocket);
    static VOID Cleanup();
    static BOOLEAN IsInstalled();
    static NTSTATUS PopCapturedPacket(_Out_ PMAPLE_CAPTURED_PACKET Packet);
    static ULONG DrainHijackedPackets();
    static NTSTATUS DispatchSendPacket(_In_ USHORT Opcode,
                                       _In_reads_bytes_(Length) const UCHAR *Payload,
                                       _In_ ULONG Length);
};
#endif
