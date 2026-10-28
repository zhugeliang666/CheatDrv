#include "MaplePacketCodec.h"

static __forceinline USHORT MapleReadU16(const UCHAR *Buffer)
{
    return static_cast<USHORT>(Buffer[0] | (static_cast<USHORT>(Buffer[1]) << 8));
}

static __forceinline ULONG MapleReadU32(const UCHAR *Buffer)
{
    return static_cast<ULONG>(Buffer[0]) | (static_cast<ULONG>(Buffer[1]) << 8) | (static_cast<ULONG>(Buffer[2]) << 16) |
           (static_cast<ULONG>(Buffer[3]) << 24);
}

static __forceinline VOID MapleWriteU16(UCHAR *Buffer, USHORT Value)
{
    Buffer[0] = static_cast<UCHAR>(Value);
    Buffer[1] = static_cast<UCHAR>(Value >> 8);
}

static __forceinline VOID MapleWriteU32(UCHAR *Buffer, ULONG Value)
{
    Buffer[0] = static_cast<UCHAR>(Value);
    Buffer[1] = static_cast<UCHAR>(Value >> 8);
    Buffer[2] = static_cast<UCHAR>(Value >> 16);
    Buffer[3] = static_cast<UCHAR>(Value >> 24);
}

NTSTATUS MaplePacketCodec::DecodeHeader(ULONG Sequence, const UCHAR *Input, ULONG InputSize, PMAPLE_PACKET_HEADER_INFO HeaderInfo)
{
    if (!Input || !HeaderInfo || InputSize < MapleLayout::ShortHeaderSize)
        return STATUS_BUFFER_TOO_SMALL;

    RtlZeroMemory(HeaderInfo, sizeof(*HeaderInfo));
    const USHORT sequenceBase = MapleReadU16(Input);
    if (static_cast<USHORT>(sequenceBase ^ static_cast<USHORT>(Sequence >> 16)) != MapleLayout::ProtocolVersionCheck)
    {
        DBG("[-] [Maple] DecodeHeader: Protocol version mismatch (Seq=0x%08X, Base=0x%04X, Result=0x%04X, Expected=0x%04X)",
            Sequence, sequenceBase, (USHORT)(sequenceBase ^ (USHORT)(Sequence >> 16)), MapleLayout::ProtocolVersionCheck);
        return STATUS_DATA_ERROR;
    }

    const USHORT length16 = static_cast<USHORT>(MapleReadU16(Input + 2) ^ sequenceBase);
    ULONG payloadSize = length16;
    ULONG headerSize = MapleLayout::ShortHeaderSize;
    BOOLEAN extended = FALSE;

    if (length16 == MapleLayout::ExtendedLengthMarker)
    {
        if (InputSize < MapleLayout::ExtendedHeaderSize)
            return STATUS_BUFFER_TOO_SMALL;
        payloadSize = MapleReadU32(Input + 4) ^ static_cast<ULONG>(sequenceBase);
        headerSize = MapleLayout::ExtendedHeaderSize;
        extended = TRUE;
    }

    if (payloadSize > MapleLayout::MaximumPayloadSize)
    {
        DBG("[-] [Maple] DecodeHeader: Payload size %lu exceeds maximum limit %lu", payloadSize, MapleLayout::MaximumPayloadSize);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    HeaderInfo->HeaderSize = headerSize;
    HeaderInfo->PayloadSize = payloadSize;
    HeaderInfo->SequenceBase = sequenceBase;
    HeaderInfo->Extended = extended;
    return STATUS_SUCCESS;
}

NTSTATUS MaplePacketCodec::EncodeHeader(ULONG Sequence, ULONG PayloadSize, UCHAR *Output, ULONG OutputCapacity, PULONG HeaderSize)
{
    if (!Output || !HeaderSize || PayloadSize > MapleLayout::MaximumPayloadSize)
        return STATUS_INVALID_PARAMETER;

    const USHORT sequenceBase = static_cast<USHORT>(MapleLayout::ProtocolVersionCheck ^ static_cast<USHORT>(Sequence >> 16));
    const BOOLEAN extended = PayloadSize >= MapleLayout::ExtendedLengthMarker;
    const ULONG required = extended ? MapleLayout::ExtendedHeaderSize : MapleLayout::ShortHeaderSize;
    if (OutputCapacity < required)
        return STATUS_BUFFER_TOO_SMALL;

    MapleWriteU16(Output, sequenceBase);
    if (extended)
    {
        MapleWriteU16(Output + 2, static_cast<USHORT>(MapleLayout::ExtendedLengthMarker ^ sequenceBase));
        MapleWriteU32(Output + 4, PayloadSize ^ static_cast<ULONG>(sequenceBase));
    }
    else
    {
        MapleWriteU16(Output + 2, static_cast<USHORT>(PayloadSize) ^ sequenceBase);
    }

    *HeaderSize = required;
    return STATUS_SUCCESS;
}

NTSTATUS MaplePacketCodec::TransformMode2Payload(PUCHAR Payload, ULONG PayloadSize, ULONG Sequence, BOOLEAN Encrypt,
                                                  PULONG NextSequence)
{
    if ((!Payload && PayloadSize != 0) || PayloadSize > MapleLayout::MaximumPayloadSize)
        return STATUS_INVALID_PARAMETER;

    MaplePacketCrypto::TransformMode2(Payload, PayloadSize, Sequence, Encrypt);
    if (NextSequence)
        *NextSequence = MaplePacketCrypto::AdvanceSequence(Sequence);
    return STATUS_SUCCESS;
}

NTSTATUS MaplePacketCodec::BuildFrame(ULONG Sequence, const UCHAR *Payload, ULONG PayloadSize,
                                      UCHAR *Output, ULONG OutputCapacity, PULONG TotalFrameSize, PULONG NextSequence)
{
    if ((!Payload && PayloadSize != 0) || !Output || !TotalFrameSize || PayloadSize > MapleLayout::MaximumPayloadSize)
        return STATUS_INVALID_PARAMETER;

    const BOOLEAN extended = PayloadSize >= MapleLayout::ExtendedLengthMarker;
    const ULONG headerSize = extended ? MapleLayout::ExtendedHeaderSize : MapleLayout::ShortHeaderSize;
    const ULONG totalNeeded = headerSize + PayloadSize;
    if (OutputCapacity < totalNeeded)
        return STATUS_BUFFER_TOO_SMALL;

    ULONG writtenHeader = 0;
    NTSTATUS status = EncodeHeader(Sequence, PayloadSize, Output, headerSize, &writtenHeader);
    if (!NT_SUCCESS(status))
    {
        DBG("[-] [Maple] BuildFrame: EncodeHeader failed (0x%08X)", status);
        return status;
    }

    if (PayloadSize > 0)
    {
        RtlCopyMemory(Output + headerSize, Payload, PayloadSize);
        MaplePacketCrypto::TransformMode2(Output + headerSize, PayloadSize, Sequence, TRUE);
    }

    *TotalFrameSize = totalNeeded;
    if (NextSequence)
    {
        *NextSequence = MaplePacketCrypto::AdvanceSequence(Sequence);
    }

    DBG("[+] [Maple] BuildFrame: %lu bytes assembled (Header=%lu, Payload=%lu, Seq=0x%08X -> Next=0x%08X)",
        totalNeeded, headerSize, PayloadSize, Sequence, NextSequence ? *NextSequence : 0);
    return STATUS_SUCCESS;
}

ULONG MaplePacketCodec::GetFragmentPayloadSize(ULONG HeaderSize, ULONG PayloadSize, ULONG PayloadOffset)
{
    if (PayloadOffset >= PayloadSize)
        return 0;

    const ULONG remaining = PayloadSize - PayloadOffset;
    ULONG capacity = MapleLayout::TcpFragmentSize;
    if (PayloadOffset == 0)
    {
        if (HeaderSize != MapleLayout::ShortHeaderSize && HeaderSize != MapleLayout::ExtendedHeaderSize)
            return 0;
        capacity -= HeaderSize;
    }
    return remaining < capacity ? remaining : capacity;
}

BOOLEAN MaplePacketCodec::SelfTest()
{
    static const ULONG lengths[] = {0, 1, 1455, 1456, 1457, 0xFEFF, 0xFF00, 0x10000};
    const ULONG sequence = 0xE1D292E3UL;

    for (ULONG i = 0; i < RTL_NUMBER_OF(lengths); ++i)
    {
        UCHAR header[MapleLayout::ExtendedHeaderSize] = {};
        ULONG headerSize = 0;
        if (!NT_SUCCESS(EncodeHeader(sequence, lengths[i], header, sizeof(header), &headerSize)))
        {
            DBG("[-] [Maple] PacketCodec::SelfTest: EncodeHeader failed on length %lu", lengths[i]);
            return FALSE;
        }

        MAPLE_PACKET_HEADER_INFO info = {};
        if (!NT_SUCCESS(DecodeHeader(sequence, header, headerSize, &info)))
        {
            DBG("[-] [Maple] PacketCodec::SelfTest: DecodeHeader failed on length %lu", lengths[i]);
            return FALSE;
        }
        if (info.PayloadSize != lengths[i] || info.HeaderSize != headerSize)
        {
            DBG("[-] [Maple] PacketCodec::SelfTest: Header info mismatch on length %lu", lengths[i]);
            return FALSE;
        }
    }

    const BOOLEAN fragCheck = GetFragmentPayloadSize(MapleLayout::ShortHeaderSize, 1457, 0) == 1456 &&
                              GetFragmentPayloadSize(MapleLayout::ShortHeaderSize, 1457, 1456) == 1 &&
                              GetFragmentPayloadSize(MapleLayout::ExtendedHeaderSize, 1453, 0) == 1452;
    if (!fragCheck)
    {
        DBG("[-] [Maple] PacketCodec::SelfTest: Fragment calculation check failed");
        return FALSE;
    }

    DBG("[+] [Maple] PacketCodec::SelfTest: All encode/decode and fragmentation tests passed");
    return TRUE;
}
