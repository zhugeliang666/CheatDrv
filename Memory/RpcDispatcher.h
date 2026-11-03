#pragma once

#include "Common.h"
#include "FrameWork.h"
#include "leechrpc_types.h"

#define MK_PERF_TRANSPORT_TCP 1
#define MK_PERF_TRANSPORT_USB 2

// 传输层10分钟活跃时间片性能统计与微架构瓶颈拆解上下文（零锁、零浮点）
typedef struct _MK_TRANSPORT_PERF
{
    ULONG TransportTag;        // 1 = TCP, 2 = USB
    ULONG64 WindowStartTickMs; // 10分钟统计窗口起点 (ms)
    ULONG64 SliceStartTickMs;  // 当前1秒采样时间片起点 (ms)
    ULONG64 LastPktTickMs;     // 上一包活跃时间戳 (ms，用于精准裁剪 >500ms 空闲断层)

    // 当前 1 秒切片累加器
    ULONG64 SliceWireBytes;
    ULONG64 SliceRawReadBytes;
    ULONG SliceReqs;
    ULONG SlicePagesReq;
    ULONG SlicePagesFail;
    ULONG64 SliceRecvWaitTsc;
    ULONG64 SliceReadTsc;
    ULONG64 SliceCompTsc;
    ULONG64 SliceSendWaitTsc;

    // 10 分钟有效活跃窗口累加器（仅计入达标活跃切片，剔除空闲与低流量心跳期）
    ULONG64 ActiveTimeMs;
    ULONG ActiveSlices;
    ULONG IdleSlices;
    ULONG64 TotalWireBytes;
    ULONG64 TotalRawReadBytes;
    ULONG64 TotalReqs;
    ULONG64 TotalPagesReq;
    ULONG64 TotalPagesFail;
    ULONG64 TotalRecvWaitTsc;
    ULONG64 TotalReadTsc;
    ULONG64 TotalCompTsc;
    ULONG64 TotalSendWaitTsc;

    // 10 分钟内速率趋势追踪 (KB/s)
    ULONG PeakRawKBps;
    ULONG MinRawKBps;
    ULONG FirstSamplesCount;
    ULONG64 FirstSamplesKBpsSum;
    ULONG LastActiveRawKBps;
    ULONG FallbackCount;
} MK_TRANSPORT_PERF, *PMK_TRANSPORT_PERF;

// 传输层通用直通上下文：为 TCP/UDP/USB 提供统一的零锁句柄直通与会话缓存
typedef struct _MK_TRANSPORT_CONTEXT
{
    HANDLE Cached_hLC;
    ULONG Cached_dwRpcClientID;
    ULONG Cached_SlotIndex;
    MK_TRANSPORT_PERF Perf;
} MK_TRANSPORT_CONTEXT, *PMK_TRANSPORT_CONTEXT;

#ifdef __cplusplus
// ============================================================
// RpcDispatcher: LeechRPC 协议分发器类 (纯静态类)
// ============================================================
class RpcDispatcher
{
  public:
    static NTSTATUS Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    static VOID Cleanup(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    static VOID CloseHandle(_In_ ULONG dwRpcClientID, _In_ BOOLEAN fReasonTimeout);

    static NTSTATUS DispatchCommand(_In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext, _In_ PUCHAR pbIn, _In_ ULONG cbIn,
                                    _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut);

    static NTSTATUS DispatchCommandEx(_In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext, _In_ PUCHAR pbIn, _In_ ULONG cbIn,
                                      _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut,
                                      _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut, _In_ ULONG cbDirectOutMax);
};
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    NTSTATUS MkRpc_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    VOID MkRpc_Cleanup(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    VOID LeechRPC_LcHandle_Close(_In_ ULONG dwRpcClientID, _In_ BOOLEAN fReasonTimeout);

    NTSTATUS MkRpc_DispatchCommandEx(_In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext, _In_ PUCHAR pbIn, _In_ ULONG cbIn,
                                     _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut,
                                     _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut, _In_ ULONG cbDirectOutMax);

    static __forceinline NTSTATUS MkRpc_DispatchCommand(_In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext, _In_ PUCHAR pbIn, _In_ ULONG cbIn,
                                                        _Out_ PUCHAR *ppbOut, _Out_ PULONG pcbOut)
    {
        return MkRpc_DispatchCommandEx(pTransportContext, pbIn, cbIn, ppbOut, pcbOut, NULL, 0);
    }

#if ENABLE_TRANSPORT_PERF_TELEMETRY
    VOID MkRpc_PerfRecordIo(_Inout_opt_ PMK_TRANSPORT_CONTEXT pTransCtx, _In_ ULONG TransportTag, _In_ ULONG cbWireRecv,
                            _In_ ULONG cbWireSend, _In_ ULONG64 tscRecvWait, _In_ ULONG64 tscSendWait, _In_ BOOLEAN fFallback);
#define MK_PERF_RDTSC() __rdtsc()
#else
#define MkRpc_PerfRecordIo(pTransCtx, TransportTag, cbWireRecv, cbWireSend, tscRecvWait, tscSendWait, fFallback) ((void)0)
#define MK_PERF_RDTSC() (0ULL)
#endif

#ifdef __cplusplus
}
#endif
