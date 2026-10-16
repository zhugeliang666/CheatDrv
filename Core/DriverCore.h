#pragma once
#include "Common.h"
#include "Struct.h"

#ifdef __cplusplus
// ============================================================
// DriverCore: 驱动全局生命周期、设备派遣与核心初始化 (纯静态类)
// ============================================================
class DriverCore
{
public:
    static NTSTATUS Initialize(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryPath);
    static NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp);
    static NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp);
    static VOID DriverUnload(PDRIVER_OBJECT pDriverObj);
    static VOID TriggerUnload(VOID);
    static VOID ScanBypassModules(PKLDR_DATA_TABLE_ENTRY DriverSection);
    static NTSTATUS ApplyBootConfigAndStart(MACHENIKE_KERNEL_INTERFACE *UserVar, const DRV_BOOT_CONFIG_EX *pCfgEx, ULONG callerPid);
};
#endif
