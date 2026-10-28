#pragma once

#ifndef _MAPLE_USER_PAYLOAD_BUILD
#include "../../Core/Common.h"
#endif
#include "MapleLayout.h"
#include "MaplePacketTypes.h"

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

// 驻留于独立 PAGE_READWRITE 共享节 (双端映射：驱动内核视图 + 目标进程用户视图)
typedef struct _MAPLE_SHARED_THUNK_DATA
{
    // Win32 窗口子类化与消息转发函数指针 (解析自目标进程 user32.dll)
    ULONG64 pfnSetWindowLongPtrW;
    ULONG64 pfnCallWindowProcW;
    ULONG64 pfnPostMessageW;
    ULONG64 pfnGetWindowThreadProcessId;

    // 窗口实例原始 GWLP_WNDPROC 指针 (由 SubclassInitEntry 调用 SetWindowLongPtrW 返回并保存)
    ULONG64 pfnOrigWndProc;
    ULONG64 pfnCustomWndProc;
    ULONG64 TargetHwnd;

    // 游戏原生网络与封包处理函数指针
    ULONG64 pfnOnRead;
    ULONG64 pfnAppendBuffer;
    ULONG64 pfnCopyFrom;
    ULONG64 pfnDecryptData;
    ULONG64 pfnInnoHash;
    ULONG64 pfnProcessPacket;
    ULONG64 pfnDestroyInPacket;
    ULONG64 pfnFlush;
    ULONG64 pfnSendPacket;
    ULONG64 pfnSendPacketNative;
    ULONG64 pfnOutPacketInit;
    ULONG64 pfnOutPacketEncodeBuffer;

    // CClientSocket 单例槽位与原始套接字
    ULONG64 pClientSocketSlot;
    ULONG64 RealSocketHandle;

    // 单次主线程初始化状态机: 0=未执行, 1=执行中, 2=SetWindowLongPtrW完成, 3=已卸载还原, -1=失败
    volatile LONG InitState;
    volatile LONG GateControlActive;

    // 独立 RW 共享节无锁环形队列索引与统计
    volatile ULONG WriteIndex;
    volatile ULONG ReadIndex;
    volatile ULONG TotalRecvPackets;
    volatile ULONG TotalSendPackets;

    // 主线程主动发包共享载荷区 (供 WM_USER + 0x0777 消费)
    volatile ULONG PendingSendLength;
    USHORT PendingSendOpcode;
    UCHAR PendingSendReserved[2];
    UCHAR PendingSendPayload[MAPLE_THUNK_MAX_PAYLOAD];

    // 供主线程构造 COutPacket 的预留静态对象区 (>= 1100 字节，避免局部栈溢出)
    UCHAR StaticOutPacket[0x600];

    // 封包捕获环形缓冲区
    MAPLE_CAPTURED_PACKET RingBuffer[MAPLE_THUNK_RING_CAPACITY];
} MAPLE_SHARED_THUNK_DATA, *PMAPLE_SHARED_THUNK_DATA;
#pragma pack(pop)

#ifndef _MAPLE_USER_PAYLOAD_BUILD
class MapleSubclassThunk
{
  public:
    static NTSTATUS Initialize(_In_ ULONG64 TargetCr3, _In_ ULONG64 ImageBase, _In_ ULONG64 ClientSocket);
    static VOID Cleanup();
    static BOOLEAN IsInstalled();
    static NTSTATUS PopCapturedPacket(_Out_ PMAPLE_CAPTURED_PACKET Packet);
    static ULONG DrainHijackedPackets();
    static NTSTATUS DispatchSendPacket(_In_ USHORT Opcode,
                                       _In_reads_bytes_(Length) const UCHAR *Payload,
                                       _In_ ULONG Length);

  private:
    static NTSTATUS ResolvePayloadExports(_Out_ PULONG OutInitEntryRva, _Out_ PULONG OutCustomWndProcRva);
    static NTSTATUS MapSectionsIntoTarget(_In_ HANDLE TargetPid,
                                          _Out_ PULONG64 OutRxUserBase,
                                          _Out_ PULONG64 OutRwUserBase);
    static NTSTATUS ResolveUser32Exports(_In_ ULONG64 TargetCr3,
                                         _In_ PEPROCESS TargetProcess,
                                         _Out_ PULONG64 OutSetWindowLongPtrW,
                                         _Out_ PULONG64 OutCallWindowProcW,
                                         _Out_ PULONG64 OutPostMessageW,
                                         _Out_ PULONG64 OutGetWindowThreadProcessId);
    static NTSTATUS QueueSingleWindowThreadInit(_In_ HANDLE TargetPid,
                                                _In_ ULONG64 EntryPointVa,
                                                _In_ ULONG64 SharedDataVa,
                                                _In_ ULONG64 TargetHwnd,
                                                _In_ ULONG64 CustomWndProcVa);
};
#endif
