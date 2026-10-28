#pragma once

#include "MaplePacketTypes.h"

class MaplePacketCrypto
{
  public:
    static ULONG AdvanceSequence(_In_ ULONG Sequence);
    static VOID TransformMode2(_Inout_updates_bytes_(Size) PUCHAR Buffer, _In_ ULONG Size, _In_ ULONG Sequence,
                               _In_ BOOLEAN Encrypt);
    static BOOLEAN ValidateShufflePrefix(_In_reads_bytes_(Size) const UCHAR *Table, _In_ ULONG Size);
    static BOOLEAN SelfTest();
};
