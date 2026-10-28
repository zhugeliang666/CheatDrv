#define _MAPLE_USER_PAYLOAD_BUILD 1
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include "../MapleSubclassThunk.h"

extern "C" IMAGE_DOS_HEADER __ImageBase;

// 游戏原生函数与 Win32 子类化函数指针类型定义
typedef void(__fastcall *PFN_OnRead)(void *pClientSocket, int bError);
typedef void(__fastcall *PFN_AppendBuffer)(void *pInPacket, void *pRecvBuffList, int *pbCompleted);
typedef int(__fastcall *PFN_DecryptData)(void *pInPacket, ULONG uSeqRcv);
typedef ULONG(__fastcall *PFN_InnoHash)(ULONG *pSeq, int nLen, ULONG *pKey);
typedef void(__fastcall *PFN_ProcessPacket)(void *pClientSocket, void *pInPacket);
typedef void(__fastcall *PFN_DestroyInPacket)(void *pInPacket);
typedef void(__fastcall *PFN_OutPacketInit)(void *pOutPacket, USHORT uOpcode);
typedef void(__fastcall *PFN_OutPacketEncodeBuffer)(void *pOutPacket, const void *pBuf, ULONG uLen);
typedef void(__fastcall *PFN_SendPacket)(void *pClientSocket, void *pOutPacket);
typedef LONG_PTR(WINAPI *PFN_SetWindowLongPtrW)(HWND hWnd, int nIndex, LONG_PTR dwNewLong);
typedef LRESULT(WINAPI *PFN_CallWindowProcW)(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef DWORD(WINAPI *PFN_GetWindowThreadProcessId)(HWND hWnd, LPDWORD lpdwProcessId);

// 零全局变量、零内存写入：利用链接器 __ImageBase 伪符号生成 RIP 相对寻址指令，直接定位紧邻的独立 RW 共享节 (+0x10000)
static __forceinline PMAPLE_SHARED_THUNK_DATA GetSharedData()
{
    return reinterpret_cast<PMAPLE_SHARED_THUNK_DATA>(
        reinterpret_cast<ULONG64>(&__ImageBase) + MapleLayout::RxToRwSectionOffset);
}

// ============================================================================
// 1. SubclassInitEntry — 单次切入窗口主线程执行的初始化函数 (由内核 User APC 触发一次)
//    仅调用 SetWindowLongPtrW(TargetHwnd, GWLP_WNDPROC, CustomWndProc) 修改窗口实例指针
//    完成后立即返回，不再劫持线程
// ============================================================================
#pragma code_seg(".text$a_init")
extern "C" __declspec(dllexport) VOID NTAPI SubclassInitEntry(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PMAPLE_SHARED_THUNK_DATA pShared = reinterpret_cast<PMAPLE_SHARED_THUNK_DATA>(NormalContext);
    if (!pShared)
    {
        pShared = GetSharedData();
    }

    if (!pShared->pfnSetWindowLongPtrW || !pShared->TargetHwnd || !pShared->pfnCustomWndProc)
    {
        return;
    }

    // 校验当前执行 APC 的线程是否确为创建目标窗口的线程 (TEB+0x48 ClientId.UniqueThread == GetWindowThreadProcessId)
    if (pShared->pfnGetWindowThreadProcessId)
    {
        PFN_GetWindowThreadProcessId pfnGetWndTid =
            reinterpret_cast<PFN_GetWindowThreadProcessId>(pShared->pfnGetWindowThreadProcessId);
        const DWORD wndTid = pfnGetWndTid(reinterpret_cast<HWND>(pShared->TargetHwnd), nullptr);
        const DWORD curTid = static_cast<DWORD>(__readgsqword(0x48));
        if (wndTid != 0 && curTid != wndTid)
        {
            return;
        }
    }

    // 若内核请求卸载 (InitState == 4)，在窗口所属主线程原子还原原始 GWLP_WNDPROC
    if (_InterlockedCompareExchange(&pShared->InitState, 4, 4) == 4)
    {
        if (pShared->pfnOrigWndProc)
        {
            reinterpret_cast<PFN_SetWindowLongPtrW>(pShared->pfnSetWindowLongPtrW)(
                reinterpret_cast<HWND>(pShared->TargetHwnd),
                MapleLayout::GwlpWndProcIndex,
                static_cast<LONG_PTR>(pShared->pfnOrigWndProc));
        }
        _InterlockedExchange(&pShared->InitState, 3);
        return;
    }

    // 原子状态门禁：确保仅单次在窗口所属主线程执行初始化
    if (_InterlockedCompareExchange(&pShared->InitState, 1, 0) != 0)
    {
        return;
    }

    PFN_SetWindowLongPtrW pfnSetWindowLongPtrW =
        reinterpret_cast<PFN_SetWindowLongPtrW>(pShared->pfnSetWindowLongPtrW);

    LONG_PTR prevWndProc = pfnSetWindowLongPtrW(
        reinterpret_cast<HWND>(pShared->TargetHwnd),
        MapleLayout::GwlpWndProcIndex, // GWLP_WNDPROC (-4)
        static_cast<LONG_PTR>(pShared->pfnCustomWndProc));

    if (prevWndProc != 0)
    {
        pShared->pfnOrigWndProc = static_cast<ULONG64>(prevWndProc);
        _WriteBarrier();
        _InterlockedExchange(&pShared->InitState, 2);
    }
    else
    {
        // 若当前线程非窗口创建线程，还原 InitState=0 供真正的窗口主线程执行
        _InterlockedExchange(&pShared->InitState, 0);
    }
}

// ============================================================================
// 2. CustomWndProc — 独立 Image-Backed RX 映像节中的自定义窗口过程
//    后续全部收发包与还原逻辑 100% 由正常窗口消息驱动
// ============================================================================
#pragma code_seg(".text$b_wndproc")
extern "C" __declspec(dllexport) LRESULT CALLBACK CustomWndProc(
    HWND hWnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
    PMAPLE_SHARED_THUNK_DATA pShared = GetSharedData();

    // [分支 1]: 优雅卸载消息 (0x0778) -> 在窗口主线程还原 GWLP_WNDPROC 原始指针
    if (uMsg == MapleLayout::MsgClientSocketUninstall)
    {
        PFN_SetWindowLongPtrW pfnSetWindowLongPtrW =
            reinterpret_cast<PFN_SetWindowLongPtrW>(pShared->pfnSetWindowLongPtrW);
        if (pfnSetWindowLongPtrW && pShared->pfnOrigWndProc)
        {
            pfnSetWindowLongPtrW(
                hWnd,
                MapleLayout::GwlpWndProcIndex,
                static_cast<LONG_PTR>(pShared->pfnOrigWndProc));
        }
        _InterlockedExchange(&pShared->InitState, 3);
        return 0;
    }

    // [分支 2]: 主线程主动发包消息 (0x0777) -> 在窗口主线程构造 COutPacket 并调用 SendPacket
    if (uMsg == MapleLayout::MsgClientSocketDispatch)
    {
        UCHAR *pSocket = pShared->pClientSocketSlot
                             ? *reinterpret_cast<UCHAR **>(pShared->pClientSocketSlot)
                             : nullptr;
        if (pSocket && pShared->pfnOutPacketInit && pShared->pfnSendPacket)
        {
            reinterpret_cast<PFN_OutPacketInit>(pShared->pfnOutPacketInit)(
                pShared->StaticOutPacket,
                pShared->PendingSendOpcode);

            const ULONG sendLen = pShared->PendingSendLength;
            if (sendLen > 0 && sendLen <= MAPLE_THUNK_MAX_PAYLOAD && pShared->pfnOutPacketEncodeBuffer)
            {
                reinterpret_cast<PFN_OutPacketEncodeBuffer>(pShared->pfnOutPacketEncodeBuffer)(
                    pShared->StaticOutPacket,
                    pShared->PendingSendPayload,
                    sendLen);
            }

            reinterpret_cast<PFN_SendPacket>(pShared->pfnSendPacket)(
                pSocket,
                pShared->StaticOutPacket);

            _InterlockedExchange(reinterpret_cast<volatile LONG *>(&pShared->PendingSendLength), 0);
            _InterlockedIncrement(reinterpret_cast<volatile LONG *>(&pShared->TotalSendPackets));
        }
        return 0;
    }

    // [分支 3]: 网络接收消息 (uMsg == 0x0401 且 LOWORD(lParam) == FD_READ(1) 且 HIWORD(lParam) == 0)
    if (uMsg == MapleLayout::MsgClientSocketRead && static_cast<ULONG>(lParam) == 1)
    {
        UCHAR *pSocket = pShared->pClientSocketSlot
                             ? *reinterpret_cast<UCHAR **>(pShared->pClientSocketSlot)
                             : nullptr;
        if (pSocket && pShared->pfnOnRead && pShared->pfnAppendBuffer &&
            pShared->pfnDecryptData && pShared->pfnInnoHash &&
            pShared->pfnProcessPacket && pShared->pfnDestroyInPacket)
        {
            // 调用原生 OnRead(pSocket, 0) 将网络分片收入 m_lpRecvBuff (+0x70)
            reinterpret_cast<PFN_OnRead>(pShared->pfnOnRead)(pSocket, 0);

            UCHAR *pInPacket = pSocket + MapleLayout::ClientSocketReceivePacketOffset; // +0xB0
            UCHAR *pRecvQueue = pSocket + MapleLayout::ClientSocketReceiveQueueOffset; // +0x70
            ULONG *pSeqRcv = reinterpret_cast<ULONG *>(
                pSocket + MapleLayout::ClientSocketReceiveSequenceOffset); // +0xEC

            for (;;)
            {
                int bCompleted = 0;
                reinterpret_cast<PFN_AppendBuffer>(pShared->pfnAppendBuffer)(
                    pInPacket,
                    pRecvQueue,
                    &bCompleted);
                if (!bCompleted)
                {
                    break;
                }

                // 解密当前 CInPacket
                reinterpret_cast<PFN_DecryptData>(pShared->pfnDecryptData)(
                    pInPacket,
                    *pSeqRcv);

                // 提取明文写入独立 RW 共享节中的 RingBuffer
                const UCHAR *pRecvBuff = *reinterpret_cast<UCHAR **>(pInPacket + 0x10);
                const ULONG dataLen = *reinterpret_cast<ULONG *>(pInPacket + 0x20);
                const ULONG writeIdx = pShared->WriteIndex;
                const ULONG readIdx = pShared->ReadIndex;

                if (pRecvBuff && dataLen >= 2 && (writeIdx - readIdx) < MAPLE_THUNK_RING_CAPACITY)
                {
                    const ULONG copyLen = (dataLen > MAPLE_THUNK_MAX_PAYLOAD)
                                              ? MAPLE_THUNK_MAX_PAYLOAD
                                              : dataLen;
                    MAPLE_CAPTURED_PACKET *slot =
                        &pShared->RingBuffer[writeIdx & (MAPLE_THUNK_RING_CAPACITY - 1)];

                    slot->Direction = MaplePacketDirectionReceive;
                    slot->DataLength = copyLen;
                    slot->Sequence = *reinterpret_cast<USHORT *>(pInPacket + 0x1C);
                    slot->Opcode = *reinterpret_cast<const USHORT *>(pRecvBuff + 4);
                    __movsb(slot->Payload, pRecvBuff + 4, copyLen);

                    _InterlockedIncrement(reinterpret_cast<volatile LONG *>(&pShared->TotalRecvPackets));
                    _WriteBarrier();
                    _InterlockedIncrement(reinterpret_cast<volatile LONG *>(&pShared->WriteIndex));
                }

                // InnoHash 步进接收序号 -> ProcessPacket 分发 -> DestroyInPacket 销毁
                *pSeqRcv = reinterpret_cast<PFN_InnoHash>(pShared->pfnInnoHash)(pSeqRcv, 4, nullptr);
                reinterpret_cast<PFN_ProcessPacket>(pShared->pfnProcessPacket)(pSocket, pInPacket);
                reinterpret_cast<PFN_DestroyInPacket>(pShared->pfnDestroyInPacket)(pInPacket);
            }
            return 0;
        }
    }

    // [分支 4]: 其它所有窗口消息 -> CallWindowProcW 原生透传
    PFN_CallWindowProcW pfnCallWindowProcW =
        reinterpret_cast<PFN_CallWindowProcW>(pShared->pfnCallWindowProcW);
    return pfnCallWindowProcW(
        reinterpret_cast<WNDPROC>(pShared->pfnOrigWndProc),
        hWnd,
        uMsg,
        wParam,
        lParam);
}
