#pragma once

#include "MaplePacketCrypto.h"

class MaplePacketCodec
{
  public:
    static NTSTATUS DecodeHeader(_In_ ULONG Sequence, _In_reads_bytes_(InputSize) const UCHAR *Input, _In_ ULONG InputSize,
                                 _Out_ PMAPLE_PACKET_HEADER_INFO HeaderInfo);
    static NTSTATUS EncodeHeader(_In_ ULONG Sequence, _In_ ULONG PayloadSize, _Out_writes_bytes_(OutputCapacity) UCHAR *Output,
                                 _In_ ULONG OutputCapacity, _Out_ PULONG HeaderSize);
    static NTSTATUS TransformMode2Payload(_Inout_updates_bytes_(PayloadSize) PUCHAR Payload, _In_ ULONG PayloadSize,
                                          _In_ ULONG Sequence, _In_ BOOLEAN Encrypt, _Out_opt_ PULONG NextSequence);
    static NTSTATUS BuildFrame(_In_ ULONG Sequence, _In_reads_bytes_opt_(PayloadSize) const UCHAR *Payload,
                               _In_ ULONG PayloadSize, _Out_writes_bytes_(OutputCapacity) UCHAR *Output,
                               _In_ ULONG OutputCapacity, _Out_ PULONG TotalFrameSize, _Out_opt_ PULONG NextSequence);
    static ULONG GetFragmentPayloadSize(_In_ ULONG HeaderSize, _In_ ULONG PayloadSize, _In_ ULONG PayloadOffset);
    static BOOLEAN SelfTest();
};
