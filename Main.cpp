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

/*
 * UDP 客户端发现开关 (1: 开启启动前 UDP 发现握手; 0: 跳过发现直接启动服务，便于调试测试)
 */
#ifndef ENABLE_UDP_CLIENT_DISCOVERY
#define ENABLE_UDP_CLIENT_DISCOVERY 0
#endif

static PDEVICE_OBJECT g_pControlDevObj = NULL;
static PDRIVER_OBJECT g_pDriverObj = NULL;
static PMACHENIKE_KERNEL_INTERFACE g_pGlobalUserVar = NULL;
static PVOID g_pDriverActualPoolBase = NULL;
static PKLDR_DATA_TABLE_ENTRY g_pHostDriverSection = NULL;

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
                DBG("[+] netio [0x%p-0x%p] KfdAddCalloutEntry=0x%p", (PVOID)netioBase, (PVOID)netioEnd,
                               (PVOID)fnAddr);
            }
            else if (Utils_GetModuleExport(netioBase, str_FwpsCalloutRegister2, &fnAddr) && fnAddr)
            {
                targetBase = netioBase;
                targetEnd = netioEnd;
                targetFn = fnAddr;
                DBG("[+] netio [0x%p-0x%p] FwpsCalloutRegister2=0x%p", (PVOID)netioBase, (PVOID)netioEnd,
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
                DBG("[+] fwpkclnt [0x%p-0x%p] FwpsCalloutRegister2=0x%p", (PVOID)fwpBase, (PVOID)fwpEnd,
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
                DBG("[+] fwpkclnt FwpsCalloutRegister1=0x%p", (PVOID)fnAddr);
                if (!targetFn)
                {
                    targetBase = fwpBase;
                    targetEnd = fwpEnd;
                    targetFn = fnAddr;
                }
            }
            else if (Utils_GetModuleExport(fwpBase, str_FwpsCalloutRegister0, &fnAddr) && fnAddr)
            {
                DBG("[+] fwpkclnt FwpsCalloutRegister0=0x%p", (PVOID)fnAddr);
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
            DBG("[+] Target ACE/Mock driver detected: %wZ [0x%p-0x%p]", &pEntry->BaseDllName, (PVOID)aceBase,
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
extern "C" BOOLEAN MachenikeReadMsrSafe(ULONG MsrIndex, PULONG64 pValue)
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
        DBG("DispatchCreate: Invalid token format in filename (status=0x%08X)", status);
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
    DBG("DispatchCreate: Client PID=%u, Token=0x%08X, Access=%s", CurrentProcessId, CurrentToken,
                   ok ? "GRANTED" : "DENIED");
    pIrp->IoStatus.Status = ok ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    pIrp->IoStatus.Information = 0;
    UserVar->Func.IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    return pIrp->IoStatus.Status;
}

NTSTATUS MachenikeDispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    MACHENIKE_KERNEL_INTERFACE *UserVar = GetActiveUserVar(pDevObj);
    DBG("DispatchClose: Device handle closed");
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

    /* 若已安装成功则任务完成，停止定时器 */
    if (WfpBypass_IsInstalled())
    {
        DBG("[+] AceScanWork: Bypass already installed, stopping timer");
        KeCancelTimer(&pCtx->Timer);
        InterlockedExchange(&pCtx->fStopped, 1);
        return;
    }

    /* 重新扫描模块列表并尝试初始化安装 */
    MachenikeScanBypassModules(pCtx->pDriverSection);

    if (g_pGlobalUserVar)
    {
        WfpBypass_Init(g_pGlobalUserVar);
    }

    if (WfpBypass_IsInstalled())
    {
        DBG("[+] AceScanWork: Bypass installed after scan, stopping timer");
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
    UNREFERENCED_PARAMETER(pDriverObj);
    DBG("DriverUnload: Stopping server and cleaning up...");

    MACHENIKE_KERNEL_INTERFACE *UserVar = g_pGlobalUserVar;
    if (!UserVar)
    {
        DBG("[-] DriverUnload: CRITICAL - Failed to obtain valid UserVar!");
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

#if ENABLE_WFP_BYPASS
    WfpBypass_Cleanup(UserVar);
#endif
    Transport_StopServer(UserVar);
    MkRpc_Cleanup(UserVar);

#if (MK_ENABLE_FAKE_LDR)
    /* ACE 对抗：在启用伪造 LDR 模式下清理并恢复宿主真实 LDR 项，防止驱动卸载后悬空指针导致 BSOD */
    Stealth_CleanupFakeLdrEntry(UserVar);
#endif

    if (UserVar->MmPhysicalMemoryRange)
        UserVar->Func.ExFreePoolWithTag(UserVar->MmPhysicalMemoryRange, 0);
    if (UserVar->hPhysicalMemory)
        UserVar->Func.ZwClose(UserVar->hPhysicalMemory);

    if (g_pGlobalUserVar)
    {
        UserVar->Func.ExFreePoolWithTag(g_pGlobalUserVar, MK_POOL_TAG);
        g_pGlobalUserVar = NULL;
    }

    DBG("[+] DriverUnload: Cleanup completed successfully.");
}

/*
 * 异步卸载工作项例程：在独立系统工作线程中安全停止服务并清理驱动
 */
static VOID Main_UnloadWorkRoutine(IN PVOID Parameter)
{
    PWORK_QUEUE_ITEM pWorkItem = (PWORK_QUEUE_ITEM)Parameter;
    DBG("[*] Main_UnloadWorkRoutine: Executing async driver unload...");

    MachenikeDriverUnload(g_pDriverObj);

    DBG("[+] Main_UnloadWorkRoutine: Driver cleanup finished.");
    if (pWorkItem)
    {
        ExFreePoolWithTag(pWorkItem, MK_POOL_TAG);
    }
}

EXTERN_C VOID Main_TriggerUnload(VOID)
{
    DBG("[*] Main_TriggerUnload: Scheduling driver unload work item...");
    MACHENIKE_KERNEL_INTERFACE *UserVar = g_pGlobalUserVar;
    if (UserVar)
    {
        PWORK_QUEUE_ITEM pWorkItem = (PWORK_QUEUE_ITEM)UserVar->Func.ExAllocatePoolWithTag(
            NonPagedPool, sizeof(WORK_QUEUE_ITEM), MK_POOL_TAG);
        if (pWorkItem)
        {
            ExInitializeWorkItem(pWorkItem, Main_UnloadWorkRoutine, pWorkItem);
            ExQueueWorkItem(pWorkItem, DelayedWorkQueue);
            return;
        }
    }

    /* 降级为同步卸载 */
    MachenikeDriverUnload(g_pDriverObj);
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
                                        DBG("[+] Resolved KeQueryPerformanceCounter from hal.dll Addr:[0x%p]", (PVOID)TableAsArray[i]);
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

                    DBG("[-] Failed to find Index:[%02lld] U32Hash:[0x%08X]", i, FunctionArray[i]);
                    return STATUS_NOT_FOUND;
                }
                DBG("[+] Resolved Index:[%02lld] U32Hash:[0x%08X] Addr:[0x%p]", i, FunctionArray[i],
                               (PVOID)TableAsArray[i]);
            }
            DBG("[+] Successfully resolved all %lld kernel functions from ntoskrnl!",
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
                DBG("[-] ZwOpenSection PhysicalMemory optional open bypassed (status=0x%08X)", status);
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

    return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PVOID pContextOrBootConfig)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (pDriverObj)
    {
        PKLDR_DATA_TABLE_ENTRY pHostDriverSection = (PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;
        g_pHostDriverSection = pHostDriverSection;
        g_pDriverObj = pDriverObj;

        MACHENIKE_KERNEL_INTERFACE *UserVar = NULL;
        status = MachenikeUserVarInit(pHostDriverSection, &UserVar);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        g_pGlobalUserVar = UserVar;

        /* 读取 shellcode 暂存的实际内核池基址并立即复位 DeviceObject 为 NULL，消除对象表审计风险 */
        g_pDriverActualPoolBase = pDriverObj->DeviceObject;
        pDriverObj->DeviceObject = NULL;

        /* 注意：Manual Map 到 tcpip.sys 时切勿挂接 pDriverObj->DriverUnload！
         * 1. tcpip.sys 核心驱动原生不可卸载，微软官方驱动的 DriverUnload 始终为 NULL。
         * 2. 反作弊（ACE / EAC / BE）遍历驱动对象时，一旦发现 DriverUnload
         *    指向合法模块范围外的未签名内存，将立即触发拦截报警。
         * 卸载统一由内部自愈机制或远程 RPC 命令 (LC_CMD_AGENT_UNLOAD_DRIVER) 异步调用 Main_TriggerUnload 执行。
         */

        /* 启动通讯服务：由 Loader 传入的 BootConfig 决定启动模式 (TCP / UDP / USB) 及端口 */
        MkRpc_Init(UserVar);
        Transport_Init();

        NTSTATUS srvStatus = STATUS_UNSUCCESSFUL;
        MK_SERVER_START_PARAMS srvParams = {};

        PDRV_BOOT_CONFIG pBootConfig = (PDRV_BOOT_CONFIG)pContextOrBootConfig;
        if (pBootConfig && pBootConfig->Magic == DRV_BOOT_CONFIG_MAGIC)
        {
            DBG("[+] Received BootConfig from Loader: Mode=%u Port=%u",
                pBootConfig->TransportMode, pBootConfig->Port);
            if (pBootConfig->TransportMode == DRV_TRANSPORT_TCP)
            {
                srvParams.Mode = MK_SERVER_MODE_WSK_TCP;
                srvParams.Port = pBootConfig->Port ? pBootConfig->Port : MK_WSK_DEFAULT_PORT;
            }
            else if (pBootConfig->TransportMode == DRV_TRANSPORT_UDP)
            {
                srvParams.Mode = MK_SERVER_MODE_WSK_UDP;
                srvParams.Port = pBootConfig->Port ? pBootConfig->Port : MK_UDP_SERVER_DEFAULT_PORT;
            }
            else if (pBootConfig->TransportMode == DRV_TRANSPORT_USB)
            {
                srvParams.Mode = MK_SERVER_MODE_USB;
            }
        }

        /* 若没传入模式或模式无效，则返回失败并卸载驱动 */
        if (srvParams.Mode == 0)
        {
            DBG("[-] CRITICAL: No valid transport mode provided. Auto-unloading driver!");
            MachenikeDriverUnload(NULL);
            RtlZeroMemory(pDriverObj, 0x200);
            g_pDriverObj = NULL;
            return STATUS_INVALID_PARAMETER;
        }

        /* 若为 TCP 或 UDP 模式，先根据宏开关判断是否调用 UdpDiscovery_DiscoverClient 发现设备 */
        if (srvParams.Mode == MK_SERVER_MODE_WSK_TCP || srvParams.Mode == MK_SERVER_MODE_WSK_UDP)
        {
#if ENABLE_UDP_CLIENT_DISCOVERY
            MK_DISCOVERY_RESULT discResult = {0};
            MK_DISCOVERY_PARAMS discParams = {0};
            discParams.TimeoutMs = 5000;
            discParams.ServerTcpPort = (USHORT)srvParams.Port;

            DBG("[*] DriverEntry: Discovering client before starting %s server (Port=%u)...",
                (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "WSK TCP" : "WSK UDP", srvParams.Port);

            NTSTATUS discStatus = UdpDiscovery_DiscoverClient(UserVar, &discParams, &discResult);
            if (NT_SUCCESS(discStatus) && discResult.fFound)
            {
                DBG("[+] DriverEntry: Client discovered at %s:%u, starting server...",
                    discResult.ClientIpStr, discResult.ClientPort);
                srvStatus = Transport_StartServer(UserVar, &srvParams);
                DBG("[*] DriverEntry: Start %s server status=0x%08X (port=%u)",
                    (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP", srvStatus, srvParams.Port);
            }
            else
            {
                DBG("[-] DriverEntry: Client discovery failed (status=0x%08X, fFound=%d), abort starting server",
                    discStatus, discResult.fFound);
                srvStatus = NT_SUCCESS(discStatus) ? STATUS_DEVICE_NOT_CONNECTED : discStatus;
            }
#else
            DBG("[*] DriverEntry: ENABLE_UDP_CLIENT_DISCOVERY=0, skipping discovery and starting %s server directly (Port=%u)...",
                (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP", srvParams.Port);
            srvStatus = Transport_StartServer(UserVar, &srvParams);
            DBG("[*] DriverEntry: Start %s server status=0x%08X (port=%u)",
                (srvParams.Mode == MK_SERVER_MODE_WSK_TCP) ? "TCP" : "UDP", srvStatus, srvParams.Port);
#endif
        }
        else
        {
            /* USB 或其他模式直接启动 */
            srvStatus = Transport_StartServer(UserVar, &srvParams);
            DBG("[*] DriverEntry: Start server status=0x%08X (Mode=%u)", srvStatus, srvParams.Mode);
        }

        /* 关键自愈防护：若指定服务启动失败，自动卸载驱动并返回错误码 */
        if (!NT_SUCCESS(srvStatus))
        {
            DBG("[-] CRITICAL: Transport server failed to start (status=0x%08X). Auto-unloading driver!", srvStatus);
            MachenikeDriverUnload(NULL);
            RtlZeroMemory(pDriverObj, 0x200);
            g_pDriverObj = NULL;
            return srvStatus;
        }

        DBG("[+] Transport server online successfully (Mode=%u)", srvParams.Mode);

#if ENABLE_WFP_BYPASS
        /* 仅在 TCP 或 UDP 网络通信模式下才执行 WFP Bypass 过滤绕过 */
        if (srvParams.Mode == MK_SERVER_MODE_WSK_TCP || srvParams.Mode == MK_SERVER_MODE_WSK_UDP)
        {
            /* 设置隐藏端口（若已配置） */
            if (srvParams.Port != 0)
            {
                WfpBypass_SetHiddenLocalPort((USHORT)srvParams.Port);
            }

            /* 首次预扫描模块基址（记录首次探测时间戳，不进行激进同步替换） */
            if (g_pHostDriverSection)
            {
                MachenikeScanBypassModules(g_pHostDriverSection);
            }

            /* 启动 KTIMER+KDPC+WorkItem 周期扫描，等待目标驱动彻底就绪后安全替换并停止 */
            if (!WfpBypass_IsInstalled())
            {
                PACE_SCAN_WORK_CONTEXT pCtx = &g_AceScanCtx;

                /* 初始化工作元素与状态 */
                ExInitializeWorkItem(&pCtx->WorkItem, Main_AceScanWorkRoutine, pCtx);
                pCtx->pDriverSection = g_pHostDriverSection;
                InterlockedExchange(&pCtx->fStopped, 0);
                InterlockedExchange(&pCtx->fWorkItemQueued, 0);

                /* 初始化 DPC，由它将工作项压入内核工作队列 */
                KeInitializeDpc(&pCtx->Dpc, Main_AceScanDpc, pCtx);

                /* 初始化 2s 周期定时器，第一次 2s 后触发，紧跟 ACE WFP Callout 注册窗口 */
                KeInitializeTimerEx(&pCtx->Timer, SynchronizationTimer);
                LARGE_INTEGER DueTime;
                DueTime.QuadPart = -(LONGLONG)(2ULL * 1000 * 10000); /* 首次 2s 后触发 */
                KeSetTimerEx(&pCtx->Timer, DueTime, 2000 /* 周期 2s=2000ms */, &pCtx->Dpc);
                g_AceScanTimerStarted = TRUE;

                DBG("[+] AceScan: Timer+DPC+WorkItem scan engine started (2s period, 5s WFP debounce after ACE appears)");
            }
            else
            {
                DBG("[+] Bypass already installed successfully, background scan omitted");
            }
        }
        else
        {
            DBG("[*] Current transport mode (%u) is not TCP/UDP, skipping WFP bypass engine.", srvParams.Mode);
        }
#else
        DBG("[*] ENABLE_WFP_BYPASS=0, WFP bypass engine disabled by configuration macro.");
#endif

        /* ACE 对抗防护：清空擦除内存池尾部的伪造 DRIVER_OBJECT 结构体（0x200 字节）
         * 1. 彻底抹除未注册且非对齐的伪驱动对象特征，规避反作弊（ACE 等）Object 扫描
         * 2. 避免内核池中暴露宿主模块基址等敏感指针
         */
        RtlZeroMemory(pDriverObj, 0x200);
        g_pDriverObj = NULL;

        status = STATUS_SUCCESS;
    }

    return status;
}
