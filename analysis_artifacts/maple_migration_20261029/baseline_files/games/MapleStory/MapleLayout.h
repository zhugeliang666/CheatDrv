#pragma once

#ifndef _MAPLE_USER_PAYLOAD_BUILD
#include "../../Core/Common.h"
#else
#include <windows.h>
#endif

namespace MapleLayout
{
    static const ULONG64 UserAddressMin = 0x0000000000010000ULL;
    static const ULONG64 UserAddressMax = 0x00007FFFFFFFFFFFULL;

    static const ULONG64 ClientSocketSlotRva = 0x03B63C80ULL;
    static const ULONG64 ClientSocketVtableRva = 0x03454FE8ULL;
    static const ULONG64 AesKeySourceRva = 0x03B297F0ULL;
    static const ULONG64 InnoShuffleRva = 0x03B29970ULL;

    static const ULONG64 ClientSocketHwndOffset = 0x18ULL;
    static const ULONG64 ClientSocketNativeSocketOffset = 0x20ULL;
    static const ULONG64 ClientSocketCryptoModeOffset = 0x48ULL;
    static const ULONG64 ClientSocketReceiveQueueOffset = 0x70ULL;
    static const ULONG64 ClientSocketSendQueueOffset = 0x88ULL;
    static const ULONG64 ClientSocketReceivePacketOffset = 0xB0ULL;
    static const ULONG64 ClientSocketSendSequenceOffset = 0xE8ULL;
    static const ULONG64 ClientSocketReceiveSequenceOffset = 0xECULL;

    // 原生函数 RVA (根据 SKILL.md 与逆向确证)
    static const ULONG64 WndProcRva = 0x02CEAA90ULL;
    static const ULONG64 OnReadRva = 0x01639380ULL;
    static const ULONG64 ManipulatePacketRva = 0x01639BC0ULL;
    // ManipulatePacket 中已完成 CopyFrom/DecryptData/innoHash 后调用 ProcessPacket 的 E8 callsite。
    static const ULONG64 ProcessPacketCallSiteRva = 0x01639E41ULL;
    static const ULONG64 ProcessPacketRva = 0x0163C5E0ULL;
    static const ULONG64 FlushRva = 0x0163BA10ULL;
    static const ULONG64 CopyFromRva = 0x007424E0ULL;
    static const ULONG64 DestroyInPacketRva = 0x007425F0ULL;
    static const ULONG64 AppendBufferRva = 0x00743140ULL;
    static const ULONG64 DecryptDataRva = 0x00743670ULL;
    static const ULONG64 InnoHashRva = 0x00CC69D0ULL;
    static const ULONG64 MakeBufferListRva = 0x00748060ULL;
    static const ULONG64 SendPacketRva = 0x00749170ULL;
    static const ULONG64 SendPacketNativeRva = 0x01639E90ULL;
    static const ULONG64 OutPacketInitRva = 0x007471B0ULL;
    static const ULONG64 OutPacketEncodeBufferRva = 0x00747AB0ULL;

    // 消息拦截与主线程调度常量
    static const ULONG MsgClientSocketRead = 0x0401;      // WM_USER + 1 (FD_READ)
    static const ULONG MsgClientSocketDispatch = 0x0777;  // 自定义主线程发包消息
    static const ULONG MsgClientSocketUninstall = 0x0778; // 主线程还原 GWLP_WNDPROC 消息

    // 独立 Image-Backed RX 映像节与独立 RW 共享节布局常量
    static const ULONG RxSectionHeaderSize = 0x0400;
    static const ULONG RxSectionTextRva = 0x1000;
    static const ULONG RxSectionCustomWndProcOffset = 0x0080;
    static const ULONG RxSectionCustomWndProcRva = RxSectionTextRva + RxSectionCustomWndProcOffset;
    static const ULONG RxSectionRelocRva = 0x2000;
    static const ULONG RxSectionImageSize = 0x3000;
    static const ULONG64 RxToRwSectionOffset = 0x10000ULL; // 64KB 分配粒度边界对齐偏移
    static const LONG GwlpWndProcIndex = -4;               // GWLP_WNDPROC

    // 默认保底基线代码洞与数据洞 (仅作兼容保留，独立 Section 架构下不再写入目标主模块)
    static const ULONG64 DefaultCodeCaveRva = 0x032DD690ULL;
    static const ULONG64 DefaultDataCaveRva = 0x03B7C000ULL;

    static const ULONG ShortHeaderSize = 4;
    static const ULONG ExtendedHeaderSize = 8;
    static const ULONG TcpFragmentSize = 1460;
    static const ULONG ShortHeaderFirstPayloadSize = TcpFragmentSize - ShortHeaderSize;
    static const ULONG ExtendedHeaderFirstPayloadSize = TcpFragmentSize - ExtendedHeaderSize;
    static const ULONG ExtendedLengthMarker = 0xFF00;
    static const USHORT ProtocolVersionCheck = 0xFFFE;
    static const ULONG MaximumPayloadSize = 16 * 1024 * 1024;
}
