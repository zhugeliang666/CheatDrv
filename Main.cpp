#include "Common.h"
#include "MachenikeString.h"
#include "Struct.h"
#include "Utils.h"
#include "rpc_dispatch.h"
#include "transport_manager.h"
#include "wsk_server.h"
#include "udp_discovery.h"
#include "stealth_reloc.h"
#include "wfp_bypass.h"
#include "usb_hub.h"

static PDEVICE_OBJECT g_pControlDevObj = NULL;
static PDRIVER_OBJECT g_pDriverObj = NULL;
static PMACHENIKE_KERNEL_INTERFACE g_pGlobalUserVar = NULL;

/*
 * ACE 对抗：用 KTIMER + KDPC + WORK_QUEUE_ITEM 替代裸系统线程
 * 扫描逻辑寄生在系统共享工作线程 (ExpWorkerThread) 中，
 * 隐藏自定义线程入口，规避 ACE ETHREAD.StartAddress 审计
 */
typedef struct _ACE_SCAN_WORK_CONTEXT
{
    WORK_QUEUE_ITEM WorkItem; /* 必须位于结构体首部 */
    PKLDR_DATA_TABLE_ENTRY pDriverSection;
    KTIMER Timer;
    KDPC Dpc;
    volatile LONG fStopped;
    volatile LONG fWorkItemQueued;
} ACE_SCAN_WORK_CONTEXT, *PACE_SCAN_WORK_CONTEXT;

static ACE_SCAN_WORK_CONTEXT g_AceScanCtx;
static BOOLEAN g_AceScanStop = FALSE;
static BOOLEAN g_AceScanTimerStarted = FALSE;


static BOOLEAN Main_ContainsSubstrCaseless(PCWSTR pszStr, ULONG cchStr, PCWSTR pszSub)
{
    if (!pszStr || !pszSub || cchStr == 0)
        return FALSE;
    ULONG subLen = 0;
    while (pszSub[subLen] != L'\0')
        subLen++;
    if (subLen == 0 || subLen > cchStr)
        return FALSE;

    for (ULONG i = 0; i <= cchStr - subLen; i++)
    {
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < subLen; j++)
        {
            WCHAR c1 = pszStr[i + j];
            WCHAR c2 = pszSub[j];
            if (c1 >= L'a' && c1 <= L'z')
                c1 -= 32;
            if (c2 >= L'a' && c2 <= L'z')
                c2 -= 32;
            if (c1 != c2)
            {
                match = FALSE;
                break;
            }
        }
        if (match)
            return TRUE;
    }
    return FALSE;
}

VOID MachenikeScanBypassModules(IN PKLDR_DATA_TABLE_ENTRY DriverSection)
{
    if (!DriverSection)
        return;

    ULONG_PTR targetBase = 0;
    ULONG_PTR targetEnd = 0;
    ULONG_PTR targetFn = 0;

    for (PLIST_ENTRY pListEntry = DriverSection->InLoadOrderLinks.Flink; pListEntry != &DriverSection->InLoadOrderLinks;
         pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!pEntry->DllBase || !pEntry->BaseDllName.Buffer)
            continue;

        ULONG cchName = pEntry->BaseDllName.Length / sizeof(WCHAR);
        ULONG U32ModuleName = Utils_HashStringImulMagicExW(pEntry->BaseDllName.Buffer, cchName, TRUE);

        if (U32ModuleName == wstr_Netio || Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"netio"))
        {
            ULONG_PTR netioBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR netioEnd = netioBase + pEntry->SizeOfImage;
            ULONG_PTR fnAddr = 0;

            if (Utils_GetModuleExport(netioBase, str_KfdAddCalloutEntry, &fnAddr) && fnAddr)
            {
                targetBase = netioBase;
                targetEnd = netioEnd;
                targetFn = fnAddr;
                MachenikePrint("[+] netio [0x%p-0x%p] KfdAddCalloutEntry=0x%p", (PVOID)netioBase, (PVOID)netioEnd,
                               (PVOID)fnAddr);
            }
            else if (Utils_GetModuleExport(netioBase, str_FwpsCalloutRegister2, &fnAddr) && fnAddr)
            {
                targetBase = netioBase;
                targetEnd = netioEnd;
                targetFn = fnAddr;
                MachenikePrint("[+] netio [0x%p-0x%p] FwpsCalloutRegister2=0x%p", (PVOID)netioBase, (PVOID)netioEnd,
                               (PVOID)fnAddr);
            }
        }
        else if (U32ModuleName == wstr_Fwpkclnt ||
                 Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"fwpkclnt"))
        {
            ULONG_PTR fwpBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR fwpEnd = fwpBase + pEntry->SizeOfImage;
            ULONG_PTR fnAddr = 0;

            if (Utils_GetModuleExport(fwpBase, str_FwpsCalloutRegister2, &fnAddr) && fnAddr)
            {
                MachenikePrint("[+] fwpkclnt [0x%p-0x%p] FwpsCalloutRegister2=0x%p", (PVOID)fwpBase, (PVOID)fwpEnd,
                               (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
            else if (Utils_GetModuleExport(fwpBase, str_FwpsCalloutRegister1, &fnAddr) && fnAddr)
            {
                MachenikePrint("[+] fwpkclnt FwpsCalloutRegister1=0x%p", (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
            else if (Utils_GetModuleExport(fwpBase, str_FwpsCalloutRegister0, &fnAddr) && fnAddr)
            {
                MachenikePrint("[+] fwpkclnt FwpsCalloutRegister0=0x%p", (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
        }
        else if (U32ModuleName == wstr_AceCore302706 || U32ModuleName == wstr_AceCore102706 ||
                 Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"ace-core") ||
                 Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"ace_core") ||
                 Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"mockace") ||
                 Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"mock_ace"))
        {
            ULONG_PTR aceBase = (ULONG_PTR)pEntry->DllBase;
            ULONG_PTR aceEnd = aceBase + pEntry->SizeOfImage;
            WfpBypass_SetAceInfo(aceBase, aceEnd);
            UsbHub_SetAceInfo(aceBase, aceEnd);
            MachenikePrint("[+] Target ACE/Mock driver detected: %wZ [0x%p-0x%p]", &pEntry->BaseDllName, (PVOID)aceBase,
                           (PVOID)aceEnd);
        }
    }

    if (targetBase && targetEnd && targetFn)
    {
        WfpBypass_SetNetioInfo(targetBase, targetEnd, (PVOID)targetFn);
    }
}

/*
 * MachenikeReadMsrSafe — 安全读取 CPU MSR 寄存器 (仿照 ComputerZ_x64.sys sub_12404)
 * 使用 __try / __except 捕获 #GP 异常，防止读取未实现/保留的 MSR 寄存器导致内核崩溃
 */
static BOOLEAN MachenikeReadMsrSafe(ULONG MsrIndex, PULONG64 pValue)
{
    if (!pValue)
        return FALSE;

    __try
    {
        *pValue = __readmsr(MsrIndex);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *pValue = 0;
        return FALSE;
    }
}

static VOID Main_FillBypassStatus(MACHENIKE_KERNEL_INTERFACE *UserVar, PMK_BYPASS_STATUS pBypassStatus)
{
    UserVar->Func.memset(pBypassStatus, 0, sizeof(MK_BYPASS_STATUS));
    pBypassStatus->WfpBypassInstalled = WfpBypass_IsInstalled();
    pBypassStatus->WfpHiddenPort = (ULONG)WfpBypass_GetHiddenLocalPort();
    if (pBypassStatus->WfpBypassInstalled)
    {
        pBypassStatus->Flags |= MK_BYPASS_FLAG_WFP_DKOM;
    }
}

NTSTATUS MachenikeDispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG uInputBufferLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG uOutputBufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);

    if (UserVar->Func.KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        status = STATUS_SUCCESS;
        goto MachenikeIoEnd;
    }

    switch (uIoControlCode)
    {
    case MACHENIKE_START_SERVER_IOCTL:
    {
        PVOID pSystemBuf = pIrp->AssociatedIrp.SystemBuffer;
        if (uInputBufferLength < sizeof(MK_SERVER_START_PARAMS) || !pSystemBuf)
        {
            MachenikePrint("IOCTL START_SERVER: Invalid parameter (inLen=%u)", uInputBufferLength);
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        MK_SERVER_START_PARAMS *pParams = (MK_SERVER_START_PARAMS *)pSystemBuf;
        MachenikePrint("IOCTL START_SERVER: mode=%u, port=%u", pParams->Mode, pParams->Port);
        status = Transport_StartServer(UserVar, pParams);
        MachenikePrint("IOCTL START_SERVER completed with status=0x%08X", status);
        pIrp->IoStatus.Information = NT_SUCCESS(status) ? sizeof(MK_SERVER_START_PARAMS) : 0;
        break;
    }
    case MACHENIKE_STOP_SERVER_IOCTL:
    {
        MachenikePrint("IOCTL STOP_SERVER requested");
        Transport_StopServer(UserVar);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }
    case MACHENIKE_GET_STATUS_IOCTL:
    {
        PVOID pSystemBuf = pIrp->AssociatedIrp.SystemBuffer;
        if (uOutputBufferLength < sizeof(MK_SERVER_STATUS) || !pSystemBuf)
        {
            MachenikePrint("IOCTL GET_STATUS: buffer too small (outLen=%u)", uOutputBufferLength);
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        Transport_GetStatus(UserVar, (MK_SERVER_STATUS *)pSystemBuf);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = sizeof(MK_SERVER_STATUS);
        break;
    }
    case MACHENIKE_DISCOVER_DEVICE_IOCTL:
    {
        PVOID pSystemBuf = pIrp->AssociatedIrp.SystemBuffer;
        if (uOutputBufferLength < sizeof(MK_DISCOVERY_RESULT) || !pSystemBuf)
        {
            MachenikePrint("IOCTL DISCOVER_DEVICE: buffer too small (outLen=%u)", uOutputBufferLength);
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PMK_DISCOVERY_PARAMS pParams =
            (uInputBufferLength >= sizeof(MK_DISCOVERY_PARAMS)) ? (PMK_DISCOVERY_PARAMS)pSystemBuf : NULL;
        PMK_DISCOVERY_RESULT pResult = (PMK_DISCOVERY_RESULT)pSystemBuf;

        status = UdpDiscovery_DiscoverClient(UserVar, pParams, pResult);
        pIrp->IoStatus.Information = NT_SUCCESS(status) ? sizeof(MK_DISCOVERY_RESULT) : 0;
        break;
    }
    case MACHENIKE_INSTALL_BYPASS_IOCTL:
    {
        PKLDR_DATA_TABLE_ENTRY pDriverSection = NULL;
        if (pDevObj && pDevObj->DriverObject && pDevObj->DriverObject->DriverSection)
        {
            pDriverSection = (PKLDR_DATA_TABLE_ENTRY)pDevObj->DriverObject->DriverSection;
        }
        else if (g_pDriverObj && g_pDriverObj->DriverSection)
        {
            pDriverSection = (PKLDR_DATA_TABLE_ENTRY)g_pDriverObj->DriverSection;
        }

        if (pDriverSection)
        {
            MachenikeScanBypassModules(pDriverSection);
        }

        PVOID pSystemBuf = pIrp->AssociatedIrp.SystemBuffer;
        ULONG wfpPort = 0;
        if (uInputBufferLength >= sizeof(MK_BYPASS_PARAMS) && pSystemBuf)
        {
            PMK_BYPASS_PARAMS pParams = (PMK_BYPASS_PARAMS)pSystemBuf;
            wfpPort = pParams->WfpHiddenPort;
        }

        if (wfpPort != 0)
        {
            WfpBypass_SetHiddenLocalPort((USHORT)wfpPort);
        }
        status = WfpBypass_Init(UserVar);
        MachenikePrint("IOCTL INSTALL_BYPASS: WfpPort=%u status=0x%08X", wfpPort, status);

        if (uOutputBufferLength >= sizeof(MK_BYPASS_STATUS) && pSystemBuf)
        {
            Main_FillBypassStatus(UserVar, (PMK_BYPASS_STATUS)pSystemBuf);
            pIrp->IoStatus.Information = sizeof(MK_BYPASS_STATUS);
        }
        else
        {
            pIrp->IoStatus.Information = 0;
        }
        break;
    }
    case MACHENIKE_REMOVE_BYPASS_IOCTL:
    {
        WfpBypass_Cleanup(UserVar);
        MachenikePrint("IOCTL REMOVE_BYPASS: WFP DKOM removed");
        status = STATUS_SUCCESS;

        PVOID pSystemBuf = pIrp->AssociatedIrp.SystemBuffer;
        if (uOutputBufferLength >= sizeof(MK_BYPASS_STATUS) && pSystemBuf)
        {
            Main_FillBypassStatus(UserVar, (PMK_BYPASS_STATUS)pSystemBuf);
            pIrp->IoStatus.Information = sizeof(MK_BYPASS_STATUS);
        }
        else
        {
            pIrp->IoStatus.Information = 0;
        }
        break;
    }
    case MACHENIKE_GET_BYPASS_STATUS_IOCTL:
    {
        PVOID pSystemBuf = pIrp->AssociatedIrp.SystemBuffer;
        if (uOutputBufferLength < sizeof(MK_BYPASS_STATUS) || !pSystemBuf)
        {
            MachenikePrint("IOCTL GET_BYPASS_STATUS: buffer too small (outLen=%u)", uOutputBufferLength);
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        Main_FillBypassStatus(UserVar, (PMK_BYPASS_STATUS)pSystemBuf);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = sizeof(MK_BYPASS_STATUS);
        break;
    }
    case MACHENIKE_READ_MSR_IOCTL:
    case COMPUTERZ_READ_MSR_IOCTL:
    {
        PVOID pSystemBuf = pIrp->AssociatedIrp.SystemBuffer;
        if (uInputBufferLength < sizeof(ULONG) || uOutputBufferLength < sizeof(ULONG64) || !pSystemBuf)
        {
            MachenikePrint("IOCTL READ_MSR: Invalid buffer size (inLen=%u, outLen=%u)",
                           uInputBufferLength, uOutputBufferLength);
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG msrIndex = *(ULONG *)pSystemBuf;
        ULONG64 msrValue = 0;
        BOOLEAN bSuccess = MachenikeReadMsrSafe(msrIndex, &msrValue);

        *(ULONG64 *)pSystemBuf = bSuccess ? msrValue : 0;
        if (uOutputBufferLength >= sizeof(MK_MSR_DATA))
        {
            PMK_MSR_DATA pMsrData = (PMK_MSR_DATA)pSystemBuf;
            pMsrData->ReturnCode = (uIoControlCode == COMPUTERZ_READ_MSR_IOCTL) ? COMPUTERZ_READ_MSR_IOCTL : 0;
            pIrp->IoStatus.Information = sizeof(MK_MSR_DATA);
        }
        else
        {
            pIrp->IoStatus.Information = sizeof(ULONG64);
        }

        if (bSuccess)
        {
            status = STATUS_SUCCESS;
            MachenikePrint("IOCTL READ_MSR: MSR 0x%08X = 0x%016llX", msrIndex, msrValue);
        }
        else
        {
            status = (uIoControlCode == COMPUTERZ_READ_MSR_IOCTL) ? (NTSTATUS)0xE0000001 : STATUS_UNSUCCESSFUL;
            MachenikePrint("IOCTL READ_MSR: Failed to read MSR 0x%08X (Exception caught)", msrIndex);
        }
        break;
    }
    default:
    {
        MachenikePrint("IOCTL Unknown code: 0x%08X", uIoControlCode);
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    }

MachenikeIoEnd:
    pIrp->IoStatus.Status = status;
    UserVar->Func.IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

ULONGLONG MachenikeGetUnixTimeSeconds(IN MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    LARGE_INTEGER CurrentTime = {};
    UserVar->Func.KeQuerySystemTimePrecise(&CurrentTime);
    ULONGLONG sec = (ULONGLONG)CurrentTime.QuadPart / 10000000ULL;
    return (sec >= 11644473600ULL) ? (sec - 11644473600ULL) : 0;
}

ULONG MachenikeCalcToken(IN MACHENIKE_KERNEL_INTERFACE *UserVar, IN ULONGLONG Counter, IN ULONG ProcessId)
{
    UCHAR msg[16] = {0};

    UserVar->Func.memcpy(&msg[0], &Counter, 8);
    UserVar->Func.memcpy(&msg[8], &ProcessId, 4);
    UserVar->Func.memcpy(&msg[12], &UserVar->Salt4, 4);
    UINT64 Hash = Utils_SipHash24(UserVar->SipHashKey, msg, sizeof(msg));
    return (ULONG)(Hash ^ (Hash >> 32));
}

NTSTATUS MachenikeDispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS status = STATUS_SUCCESS;
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG CurrentToken = 0;
    ULONG CurrentProcessId = HandleToULong(UserVar->Func.PsGetCurrentProcessId());
    ULONGLONG Counter = MachenikeGetUnixTimeSeconds(UserVar) / UserVar->Step;
    BOOLEAN ok = FALSE;
    status = Utils_ParseTokenFromFileName(&pIrpStack->FileObject->FileName, &CurrentToken);
    if (!NT_SUCCESS(status))
    {
        MachenikePrint("DispatchCreate: Invalid token format in filename (status=0x%08X)", status);
        pIrp->IoStatus.Status = STATUS_ACCESS_DENIED;
        pIrp->IoStatus.Information = 0;
        UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }
    for (LONGLONG i = -1; i <= 1; i++)
    {
        if (MachenikeCalcToken(UserVar, (ULONGLONG)((LONGLONG)Counter + i), CurrentProcessId) == CurrentToken)
        {
            ok = TRUE;
            break;
        }
    }
    MachenikePrint("DispatchCreate: Client PID=%u, Token=0x%08X, Access=%s", CurrentProcessId, CurrentToken,
                   ok ? "GRANTED" : "DENIED");
    pIrp->IoStatus.Status = ok ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    pIrp->IoStatus.Information = 0;
    UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    return pIrp->IoStatus.Status;
}

NTSTATUS MachenikeDispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);
    MachenikePrint("DispatchClose: Device handle closed");
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * Main_AceScanWorkRoutine — WorkItem 回调，运行于 ExpWorkerThread
 * ACE 审计线程 StartAddress 时看到的是 nt!ExpWorkerThread，而非内核池中的自定义地址
 */
static VOID Main_AceScanWorkRoutine(IN PVOID Parameter)
{
    PACE_SCAN_WORK_CONTEXT pCtx = (PACE_SCAN_WORK_CONTEXT)Parameter;
    if (!pCtx)
        return;

    /* 清除已入队标志，允许下一个 DPC 周期重新入队 */
    InterlockedExchange(&pCtx->fWorkItemQueued, 0);

    if (InterlockedCompareExchange(&pCtx->fStopped, 0, 0) != 0)
        return;

    /* 如果 ACE 信息已就位则任务完成，停止定时器 */
    if (UsbHub_HasAceInfo())
    {
        MachenikePrint("[+] AceScanWork: ACE info acquired, stopping timer");
        KeCancelTimer(&pCtx->Timer);
        InterlockedExchange(&pCtx->fStopped, 1);
        return;
    }

    /* 重新扫描模块列表 */
    MachenikeScanBypassModules(pCtx->pDriverSection);

    if (UsbHub_HasAceInfo())
    {
        MachenikePrint("[+] AceScanWork: ACE info acquired after scan, stopping timer");
        KeCancelTimer(&pCtx->Timer);
        InterlockedExchange(&pCtx->fStopped, 1);
    }
}

/*
 * Main_AceScanDpc — DPC 回调，由 KTIMER 周期触发
 * 不在 DPC 中直接扫描（DISPATCH_LEVEL 过高），而是提交到系统工作队列
 */
static VOID Main_AceScanDpc(IN PKDPC Dpc, IN PVOID Context, IN PVOID SystemArg1, IN PVOID SystemArg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArg1);
    UNREFERENCED_PARAMETER(SystemArg2);

    PACE_SCAN_WORK_CONTEXT pCtx = (PACE_SCAN_WORK_CONTEXT)Context;
    if (!pCtx || InterlockedCompareExchange(&pCtx->fStopped, 0, 0) != 0)
        return;

    /* CAS 防重入队：上一个 WorkItem 尚未运行完成时不再入队 */
    if (InterlockedCompareExchange(&pCtx->fWorkItemQueued, 1, 0) == 0)
    {
        ExQueueWorkItem(&pCtx->WorkItem, DelayedWorkQueue);
    }
}

VOID MachenikeDriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
    MachenikePrint("DriverUnload: Stopping server and cleaning up...");

    /* 优先从已明确记录的主控制设备对象获取 UserVar，避免被动态附加的 FilterDO（位于 pDriverObj->DeviceObject
     * 链表头）干扰 */
    PDEVICE_OBJECT pCtrlDO = g_pControlDevObj;
    if (!pCtrlDO && pDriverObj)
    {
        pCtrlDO = pDriverObj->DeviceObject;
    }

    MACHENIKE_KERNEL_INTERFACE *UserVar = pCtrlDO ? GetActiveUserVar(pCtrlDO) : NULL;
    if (!UserVar)
    {
        UserVar = g_pGlobalUserVar;
    }
    if (!UserVar)
    {
        MachenikePrint("[-] DriverUnload: CRITICAL - Failed to obtain valid UserVar!");
        return;
    }

    /* ACE 对抗：停止周期定时器，在 WorkItem 当前循环结束前等待完成 */
    g_AceScanStop = TRUE;
    InterlockedExchange(&g_AceScanCtx.fStopped, 1);
    if (g_AceScanTimerStarted)
    {
        KeCancelTimer(&g_AceScanCtx.Timer);
        /* 等待当前可能正在运行的 WorkItem 完成（最多等 1s） */
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -(LONGLONG)(1ULL * 1000 * 10000);
        UserVar->Func.KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
        g_AceScanTimerStarted = FALSE;
    }

    WfpBypass_Cleanup(UserVar);
    Transport_StopServer(UserVar);
    MkRpc_Cleanup(UserVar);

#if defined(MANUAL_MAP_MODE) && (MK_ENABLE_FAKE_LDR)
    /* ACE 对抗：在启用伪造 LDR 模式下清理并恢复宿主真实 LDR 项，防止驱动卸载后悬空指针导致 BSOD */
    Stealth_CleanupFakeLdrEntry(UserVar);
#endif


    if (UserVar->MmPhysicalMemoryRange)
        UserVar->Func.ExFreePoolWithTag(UserVar->MmPhysicalMemoryRange, 0);
    if (UserVar->hPhysicalMemory)
        UserVar->Func.ZwClose(UserVar->hPhysicalMemory);

    if (pCtrlDO)
    {
        UNICODE_STRING ustrLink;
        UserVar->Func.RtlInitUnicodeString(&ustrLink, LINK_NAME);
        UserVar->Func.IoDeleteSymbolicLink(&ustrLink);
        UserVar->Func.IoDeleteDevice(pCtrlDO);
        g_pControlDevObj = NULL;
    }

    if (g_pGlobalUserVar)
    {
        UserVar->Func.ExFreePoolWithTag(g_pGlobalUserVar, MK_POOL_TAG);
        g_pGlobalUserVar = NULL;
    }

    MachenikePrint("DriverUnload: Successfully unloaded");
}

NTSTATUS MachenikeUserVarInit(IN PKLDR_DATA_TABLE_ENTRY DriverSection, OUT MACHENIKE_KERNEL_INTERFACE **pUserVar)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG FunctionArray[] = {
        str_RtlGetVersion,
        str_RtlInitUnicodeString,
        str_IoAllocateMdl,
        str_IoFreeMdl,
        str_IoCreateDevice,
        str_IoCreateSymbolicLink,
        str_IoDeleteDevice,
        str_IoDeleteSymbolicLink,
        str_IofCompleteRequest,
        str_DbgPrint,
        str_ProbeForRead,
        str_ProbeForWrite,
        str_ExAllocatePoolWithTag,
        str_ExFreePoolWithTag,
        str_ZwOpenSection,
        str_ZwMapViewOfSection,
        str_ZwUnmapViewOfSection,
        str_ZwClose,
        str_MmProbeAndLockPages,
        str_MmUnlockPages,
        str_MmMapLockedPagesSpecifyCache,

        str_MmGetPhysicalMemoryRanges,
        str_KeGetCurrentIrql,
        str_KeQueryActiveProcessors,
        str_KeSetSystemAffinityThread,
        str_KeRevertToUserAffinityThread,
        str_KeQuerySystemTimePrecise,
        str_PsGetCurrentProcessId,
        str_memset,
        str_memcpy,
        str_memmove,
        str_strlen,
        str_RtlCopyMemory,
        str_RtlZeroMemory,
        str_KeDelayExecutionThread,
        str_PsTerminateSystemThread,
        str_PsCreateSystemThread,
        str_KeQueryPerformanceCounter,
        str_IoAllocateIrp,
        str_IoFreeIrp,
        str_KeInitializeEvent,
        str_KeWaitForSingleObject,
        str_KeSetEvent,
        str_ZwCreateFile,
        str_ZwReadFile,
        str_ZwWriteFile,
        str_ZwDeviceIoControlFile,
        str_IoGetDeviceInterfaces,
        str_ObReferenceObjectByHandle,
        str_ObfDereferenceObject,
        str_MmAllocateContiguousMemorySpecifyCache,
        str_MmFreeContiguousMemory,
        /* ACE Bypass 新增函数 */
        str_IoGetDeviceObjectPointer,
        str_IoAttachDeviceToDeviceStack,
        str_IoDetachDevice,
        str_IoCallDriver,
        str_ExAcquireFastMutex,
        str_ExReleaseFastMutex,
    };

    MACHENIKE_PFN pfnTable = {};
    MACHENIKE_KERNEL_INTERFACE *UserVar = NULL;
    BOOLEAN bNtoskrnlFound = FALSE;

    for (PLIST_ENTRY pListEntry = DriverSection->InLoadOrderLinks.Flink; pListEntry != &DriverSection->InLoadOrderLinks;
         pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!pEntry->DllBase || !pEntry->BaseDllName.Buffer)
            continue;

        ULONG cchName = pEntry->BaseDllName.Length / sizeof(WCHAR);
        ULONG U32ModuleName = Utils_HashStringImulMagicExW(pEntry->BaseDllName.Buffer, cchName, TRUE);

        if (!bNtoskrnlFound && (U32ModuleName == wstr_Ntoskrnl ||
                                Main_ContainsSubstrCaseless(pEntry->BaseDllName.Buffer, cchName, L"ntoskrnl")))
        {
            ULONG_PTR *TableAsArray = (ULONG_PTR *)&pfnTable;
            for (size_t i = 0; i < ARRAY_SIZE(FunctionArray); i++)
            {
                if (!Utils_GetModuleExport((ULONG_PTR)pEntry->DllBase, FunctionArray[i], &TableAsArray[i]))
                {
                    // 若目标为 KeQueryPerformanceCounter，从链表中寻找 hal.dll 进行兜底解析
                    if (FunctionArray[i] == str_KeQueryPerformanceCounter)
                    {
                        BOOLEAN bHalFound = FALSE;
                        for (PLIST_ENTRY pHalEntry = DriverSection->InLoadOrderLinks.Flink;
                             pHalEntry != &DriverSection->InLoadOrderLinks;
                             pHalEntry = pHalEntry->Flink)
                        {
                            PKLDR_DATA_TABLE_ENTRY pHal = CONTAINING_RECORD(pHalEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                            if (pHal->DllBase && pHal->BaseDllName.Buffer)
                            {
                                ULONG cchHal = pHal->BaseDllName.Length / sizeof(WCHAR);
                                if (Main_ContainsSubstrCaseless(pHal->BaseDllName.Buffer, cchHal, L"hal"))
                                {
                                    if (Utils_GetModuleExport((ULONG_PTR)pHal->DllBase, str_KeQueryPerformanceCounter, &TableAsArray[i]))
                                    {
                                        MachenikePrint("[+] Resolved KeQueryPerformanceCounter from hal.dll Addr:[0x%p]", (PVOID)TableAsArray[i]);
                                        bHalFound = TRUE;
                                        break;
                                    }
                                }
                            }
                        }
                        if (bHalFound)
                        {
                            continue;
                        }
                    }

                    MachenikePrint("[-] Failed to find Index:[%02lld] U32Hash:[0x%08X]", i, FunctionArray[i]);
                    return STATUS_NOT_FOUND;
                }
                MachenikePrint("[+] Resolved Index:[%02lld] U32Hash:[0x%08X] Addr:[0x%p]", i, FunctionArray[i],
                               (PVOID)TableAsArray[i]);
            }
            MachenikePrint("[+] Successfully resolved all %lld kernel functions from ntoskrnl!",
                           (LONGLONG)ARRAY_SIZE(FunctionArray));
            if (!pfnTable.ExAllocatePoolWithTag || !pfnTable.memset || !pfnTable.memcpy || !pfnTable.RtlCopyMemory ||
                !pfnTable.RtlZeroMemory)
                return STATUS_NOT_FOUND;

            UserVar = (MACHENIKE_KERNEL_INTERFACE *)pfnTable.ExAllocatePoolWithTag(
                NonPagedPool, sizeof(MACHENIKE_KERNEL_INTERFACE), MK_POOL_TAG);
            if (!UserVar)
                return STATUS_INSUFFICIENT_RESOURCES;
            pfnTable.memset(UserVar, 0, sizeof(MACHENIKE_KERNEL_INTERFACE));
            pfnTable.memcpy(&UserVar->Func, &pfnTable, sizeof(MACHENIKE_PFN));

            OBJECT_ATTRIBUTES MemoryAttributes;
            UNICODE_STRING ustrPhysicalMemory = {};
            UserVar->Func.RtlInitUnicodeString(&ustrPhysicalMemory, L"\\Device\\PhysicalMemory");
            InitializeObjectAttributes(&MemoryAttributes, &ustrPhysicalMemory, OBJ_KERNEL_HANDLE, (HANDLE)NULL,
                                       (PSECURITY_DESCRIPTOR)NULL);
            status = UserVar->Func.ZwOpenSection(&UserVar->hPhysicalMemory, SECTION_MAP_READ, &MemoryAttributes);
            if (!NT_SUCCESS(status))
            {
                UserVar->hPhysicalMemory = NULL;
                MachenikePrint("[-] ZwOpenSection PhysicalMemory optional open bypassed (status=0x%08X)", status);
            }
            RTL_OSVERSIONINFOW VersInfo = {};
            pfnTable.memset(&VersInfo, 0, sizeof(RTL_OSVERSIONINFOW));
            VersInfo.dwOSVersionInfoSize = sizeof(VersInfo);
            status = UserVar->Func.RtlGetVersion(&VersInfo);
            if (!NT_SUCCESS(status))
            {
                UserVar->Func.ExFreePoolWithTag(UserVar, MK_POOL_TAG);
                return status;
            }
            UserVar->NtBuildNumber.QuadPart = (LONGLONG)VersInfo.dwBuildNumber;
            UserVar->NtBuildNumberAddr.QuadPart = (LONGLONG)&UserVar->NtBuildNumber.QuadPart;
            UserVar->Cr3.QuadPart = __readcr3();
            UserVar->KernelBase.QuadPart = (LONGLONG)pEntry->DllBase;

            UserVar->SipHashKey[0] = 0x21;
            UserVar->SipHashKey[1] = 0x7A;
            UserVar->SipHashKey[2] = 0xA9;
            UserVar->SipHashKey[3] = 0x3C;
            UserVar->SipHashKey[4] = 0x10;
            UserVar->SipHashKey[5] = 0x55;
            UserVar->SipHashKey[6] = 0xD2;
            UserVar->SipHashKey[7] = 0x6F;
            UserVar->SipHashKey[8] = 0x9B;
            UserVar->SipHashKey[9] = 0x4E;
            UserVar->SipHashKey[10] = 0x01;
            UserVar->SipHashKey[11] = 0x88;
            UserVar->SipHashKey[12] = 0xC7;
            UserVar->SipHashKey[13] = 0x33;
            UserVar->SipHashKey[14] = 0xFA;
            UserVar->SipHashKey[15] = 0x90;
            UserVar->Step = 30;
            UserVar->Salt4 = 0x4D43484EU;
            *pUserVar = UserVar;
            bNtoskrnlFound = TRUE;
            break;
        }
    }

    if (!bNtoskrnlFound || !UserVar)
    {
        return STATUS_NOT_FOUND;
    }

    MachenikeScanBypassModules(DriverSection);
    return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegisterPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNREFERENCED_PARAMETER(pRegisterPath);
    if (pDriverObj)
    {
        g_pDriverObj = pDriverObj;
        MACHENIKE_KERNEL_INTERFACE *UserVar = NULL;
        status = MachenikeUserVarInit((PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection, &UserVar);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        g_pGlobalUserVar = UserVar;

        /* 无论何种模式均挂接 DriverUnload，确保任何异常路径或外部卸载均可安全释放资源 */
        pDriverObj->DriverUnload = MachenikeDriverUnload;

        /* 读取 shellcode 暂存的实际内核池基址并立即复位 DeviceObject 为 NULL，消除对象表审计风险 */
        PVOID pActualPoolBase = pDriverObj->DeviceObject;
        pDriverObj->DeviceObject = NULL;
        UNREFERENCED_PARAMETER(pActualPoolBase);

#if defined(MANUAL_MAP_MODE) && (MK_ENABLE_FAKE_LDR)
        /* ACE 对抗阶段 3：宿主真实 LDR 原子原地替换 + 全量克隆签名与属性伪装
         * 能力三层合一：
         *   1. 解决双重 DllBase 与重名驱动审计：链表中剔除宿主真实项并由伪造项无缝顶替，DllBase 指向宿主驱动基址
         *   2. ExceptionTable 指向真实 .pdata => RtlVirtualUnwind 堆栈回溯正常展开
         *   3. Flags/CheckSum/SectionPointer/LoadedImports/名称等全部 1:1 克隆宿主合法驱动
         * 受 MK_ENABLE_FAKE_LDR 宏开关控制（默认 1 启用；设为 0 时不进行 LDR 链表伪造与顶替）。
         */
        static const WCHAR g_SpoofBaseName[] = L"Machenike.sys";
        static const WCHAR g_SpoofFullPath[] = L"\\SystemRoot\\System32\\drivers\\Machenike.sys";

        NTSTATUS hideStatus = Stealth_InsertFakeLdrEntry(
            UserVar,
            pDriverObj,
            pActualPoolBase,
            g_SpoofBaseName,
            g_SpoofFullPath
        );
        MachenikePrint("[*] Stealth_InsertFakeLdrEntry status=0x%08X", hideStatus);
        UNREFERENCED_PARAMETER(hideStatus);
#endif /* MANUAL_MAP_MODE && MK_ENABLE_FAKE_LDR */

        /* 默认启动通讯服务 (尝试顺序：WSK TCP -> WSK UDP -> USB)
         * 若 TCP、UDP、USB 全部启动失败，则自动卸载驱动并退出，防止空跑 */
        MkRpc_Init(UserVar);
        Transport_Init();

        NTSTATUS srvStatus = STATUS_UNSUCCESSFUL;
        MK_SERVER_START_PARAMS srvParams = {};

        /* 1. 首选：尝试启动 WSK TCP 服务（默认端口 10001） */
        srvParams.Mode = MK_SERVER_MODE_WSK_TCP;
        srvParams.Port = MK_WSK_DEFAULT_PORT;
        srvStatus = Transport_StartServer(UserVar, &srvParams);
        MachenikePrint("[*] Auto-start WSK TCP server status=0x%08X (port=%u)", srvStatus, MK_WSK_DEFAULT_PORT);

        /* 2. 次选：若 TCP 启动失败，尝试降级启动 WSK UDP 服务（默认端口 10002） */
        if (!NT_SUCCESS(srvStatus))
        {
            MachenikePrint("[-] WSK TCP server start failed (0x%08X), falling back to WSK UDP server...", srvStatus);
            RtlZeroMemory(&srvParams, sizeof(srvParams));
            srvParams.Mode = MK_SERVER_MODE_WSK_UDP;
            srvParams.Port = MK_UDP_SERVER_DEFAULT_PORT;
            srvStatus = Transport_StartServer(UserVar, &srvParams);
            MachenikePrint("[*] Auto-start WSK UDP server status=0x%08X (port=%u)", srvStatus, MK_UDP_SERVER_DEFAULT_PORT);
        }

        /* 3. 再次选：若 UDP 启动也失败，尝试降级启动 USB 通信服务（自动探测端点） */
        if (!NT_SUCCESS(srvStatus))
        {
            MachenikePrint("[-] WSK UDP server start failed (0x%08X), falling back to USB server...", srvStatus);
            RtlZeroMemory(&srvParams, sizeof(srvParams));
            srvParams.Mode = MK_SERVER_MODE_USB;
            srvStatus = Transport_StartServer(UserVar, &srvParams);
            MachenikePrint("[*] Auto-start USB server status=0x%08X", srvStatus);
        }

        /* 4. 关键自愈防护：若 TCP、UDP、USB 全部启动失败，自动卸载驱动并返回错误码 */
        if (!NT_SUCCESS(srvStatus))
        {
            MachenikePrint("[-] CRITICAL: All transport servers (TCP, UDP, USB) failed to start (last status=0x%08X). Auto-unloading driver!", srvStatus);
            MachenikeDriverUnload(pDriverObj);
            return srvStatus;
        }

        MachenikePrint("[+] Transport server online successfully (Mode=%u)", srvParams.Mode);

        /* ACE 对抗：启动 KTIMER+KDPC+WorkItem 周期扫描代替裸系统线程
         * 扫描逻辑寄生在 ExpWorkerThread，隐藏 ETHREAD.StartAddress
         */
        if (!UsbHub_HasAceInfo())
        {
            PKLDR_DATA_TABLE_ENTRY pSec = (PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;
            PACE_SCAN_WORK_CONTEXT pCtx = &g_AceScanCtx;

            /* 初始化工作元素与状态 */
            ExInitializeWorkItem(&pCtx->WorkItem, Main_AceScanWorkRoutine, pCtx);
            pCtx->pDriverSection = pSec;
            InterlockedExchange(&pCtx->fStopped, 0);
            InterlockedExchange(&pCtx->fWorkItemQueued, 0);

            /* 初始化 DPC，由它将工作项压入内核工作队列 */
            KeInitializeDpc(&pCtx->Dpc, Main_AceScanDpc, pCtx);

            /* 初始化 10s 周期定时器 */
            KeInitializeTimerEx(&pCtx->Timer, SynchronizationTimer);
            LARGE_INTEGER DueTime;
            DueTime.QuadPart = -(LONGLONG)(1ULL * 1000 * 10000); /* 首次 10s 后触发 */
            KeSetTimerEx(&pCtx->Timer, DueTime, 10000 /* 周期 10s=10000ms */, &pCtx->Dpc);
            g_AceScanTimerStarted = TRUE;

            MachenikePrint("[+] AceScan: Timer+DPC+WorkItem scan engine started (10s period)");
        }
        status = STATUS_SUCCESS;
    }

    return status;
}
