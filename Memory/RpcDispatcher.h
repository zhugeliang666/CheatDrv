#pragma once

#include "FrameWork.h"
#include "Common.h"
#include "leechrpc_types.h"

// 传输层通用直通上下文：为 TCP/UDP/USB 提供统一的零锁句柄直通与会话缓存
typedef struct _MK_TRANSPORT_CONTEXT
{
    HANDLE Cached_hLC;
    ULONG Cached_dwRpcClientID;
    ULONG Cached_SlotIndex;
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

    static NTSTATUS DispatchCommand(
        _In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext,
        _In_ PUCHAR pbIn,
        _In_ ULONG cbIn,
        _Out_ PUCHAR *ppbOut,
        _Out_ PULONG pcbOut);

    static NTSTATUS DispatchCommandEx(
        _In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext,
        _In_ PUCHAR pbIn,
        _In_ ULONG cbIn,
        _Out_ PUCHAR *ppbOut,
        _Out_ PULONG pcbOut,
        _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
        _In_ ULONG cbDirectOutMax);
};
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    NTSTATUS MkRpc_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    VOID MkRpc_Cleanup(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    VOID LeechRPC_LcHandle_Close(_In_ ULONG dwRpcClientID, _In_ BOOLEAN fReasonTimeout);

    NTSTATUS MkRpc_DispatchCommandEx(
        _In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext,
        _In_ PUCHAR pbIn,
        _In_ ULONG cbIn,
        _Out_ PUCHAR *ppbOut,
        _Out_ PULONG pcbOut,
        _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
        _In_ ULONG cbDirectOutMax);

    static __forceinline NTSTATUS MkRpc_DispatchCommand(
        _In_opt_ PMK_TRANSPORT_CONTEXT pTransportContext,
        _In_ PUCHAR pbIn,
        _In_ ULONG cbIn,
        _Out_ PUCHAR *ppbOut,
        _Out_ PULONG pcbOut)
    {
        return MkRpc_DispatchCommandEx(pTransportContext, pbIn, cbIn, ppbOut, pcbOut, NULL, 0);
    }

#ifdef __cplusplus
}
#endif
