#pragma once

#include "FrameWork.h"
#include "Common.h"
#include "leechrpc_types.h"

#ifdef __cplusplus
extern "C"
{
#endif


    NTSTATUS MkRpc_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);


    VOID MkRpc_Cleanup(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);

    VOID LeechRPC_LcHandle_Close(_In_ ULONG dwRpcClientID, _In_ BOOLEAN fReasonTimeout);



    NTSTATUS MkRpc_DispatchCommandEx(
        _In_opt_ PVOID pTransportContext,
        _In_ PUCHAR pbIn,
        _In_ ULONG cbIn,
        _Out_ PUCHAR *ppbOut,
        _Out_ PULONG pcbOut,
        _Inout_updates_bytes_opt_(cbDirectOutMax) PUCHAR pbDirectOut,
        _In_ ULONG cbDirectOutMax);

    static __forceinline NTSTATUS MkRpc_DispatchCommand(
        _In_opt_ PVOID pTransportContext,
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
