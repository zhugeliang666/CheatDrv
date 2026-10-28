#pragma once

#include "MapleLayout.h"

typedef enum _MAPLE_CRYPTO_MODE
{
    MapleCryptoModeSimple = 0,
    MapleCryptoModeAes256Ofb = 1,
} MAPLE_CRYPTO_MODE;

typedef enum _MAPLE_PACKET_DIRECTION
{
    MaplePacketDirectionSend = 1,
    MaplePacketDirectionReceive = 2,
} MAPLE_PACKET_DIRECTION;

typedef struct _MAPLE_PACKET_HEADER_INFO
{
    ULONG HeaderSize;
    ULONG PayloadSize;
    USHORT SequenceBase;
    BOOLEAN Extended;
    UCHAR Reserved;
} MAPLE_PACKET_HEADER_INFO, *PMAPLE_PACKET_HEADER_INFO;

typedef struct _MAPLE_ZLIST_SNAPSHOT
{
    ULONG Reserved;
    ULONG Count;
    ULONG64 Head;
    ULONG64 Tail;
} MAPLE_ZLIST_SNAPSHOT, *PMAPLE_ZLIST_SNAPSHOT;

static_assert(sizeof(MAPLE_ZLIST_SNAPSHOT) == 0x18, "Unexpected Maple ZList layout");

typedef struct _MAPLE_RUNTIME_SNAPSHOT
{
    ULONG64 TargetCr3;
    ULONG64 ImageBase;
    ULONG64 ClientSocket;
    ULONG64 Vtable;
    ULONG64 WindowHandle;
    ULONG64 NativeSocket;
    ULONG SendSequence;
    ULONG ReceiveSequence;
    ULONG CryptoMode;
    ULONG Generation;
    BOOLEAN Bound;
    UCHAR Reserved[7];
} MAPLE_RUNTIME_SNAPSHOT, *PMAPLE_RUNTIME_SNAPSHOT;
