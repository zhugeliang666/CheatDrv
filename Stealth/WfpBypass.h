#pragma once
#include "Common.h"

#ifdef __cplusplus
// ============================================================
// WfpBypass: ACE WFP Callout DKOM 绕过组件类 (纯静态类)
// ============================================================
class WfpBypass
{
  public:
    static VOID SetNetioInfo(_In_ ULONG_PTR netioBase, _In_ ULONG_PTR netioEnd, _In_ PVOID pFwpsReg2);

    static NTSTATUS Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    static VOID Cleanup(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    static VOID SetHiddenLocalPort(_In_ USHORT portHostOrder);
    static VOID ResetState(VOID);
    static BOOLEAN IsInstalled(VOID);
    static USHORT GetHiddenLocalPort(VOID);
};
#endif
