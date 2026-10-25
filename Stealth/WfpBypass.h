#pragma once
#include "Common.h"

typedef struct _WFP_ALARM_DETAIL
{
    WCHAR ModuleName[32];
    ULONG_PTR ModuleBase;
    ULONG_PTR ClassifyFn;
    ULONG_PTR Rva;
    PVOID *pClassifyField;
    ULONG SlotIndex;
    BOOLEAN IsReverted;
} WFP_ALARM_DETAIL, *PWFP_ALARM_DETAIL;

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
    static ULONG GetUnprotectedCalloutCount(VOID);
    static USHORT GetHiddenLocalPort(VOID);
    static ULONG VerifyAndRepairSlots(_Out_opt_ PWFP_ALARM_DETAIL pOutAlarm);
};
#endif
