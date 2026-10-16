#include "NetMonitor.h"
#include "Utils.h"
#include "wsk_server.h"

/*
 * ============================================================================
 * NetMonitor: 内核网络全栈多维安全监控引擎
 * 
 * 针对除 WFP Callout 之外的反作弊常见网络拦截面实施全方位主动探测与告警：
 * 
 * 1. 核心网络/套接字设备分发例程监控（\Device\Afd, Tcp, Udp, RawIp, Ip）
 *    - 指针替换 Hook（Pointer Hook）
 *    - 函数入口内联跳板 Hook（Inline Jmp/Call Hook: E9/FF 25/48 B8/49 BB）
 *    - 快速 I/O 分发例程 Hook（FastIoDispatch）
 * 2. TDI / 设备栈附加过滤设备监控（AttachedDevice 链，包含 \Device\Afd）
 * 3. NDIS LWF 轻量级网络过滤驱动链表监控（ndisFilterDriverList）
 * 4. 通讯驱动自身的 WSK Provider Dispatch 函数表完整性自检
 * ============================================================================
 */

static MACHENIKE_KERNEL_INTERFACE *g_pNetMonUserVar = NULL;

VOID NetMonitor::SetUserVar(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    g_pNetMonUserVar = UserVar;
}

#ifdef MmIsAddressValid
#undef MmIsAddressValid
#endif
#define MmIsAddressValid(va) ((g_pNetMonUserVar && g_pNetMonUserVar->Func.MmIsAddressValid) ? g_pNetMonUserVar->Func.MmIsAddressValid((PVOID)(va)) : FALSE)

static ULONG_PTR g_NdisBase          = 0;
static ULONG_PTR g_NdisEnd           = 0;
static PVOID    *g_pFilterDriverList = NULL;
static BOOLEAN   g_bNdisScanned      = FALSE;

/*
 * 监控的核心网络/套接字设备名称列表
 * 特别注意: 加入 \Device\Afd！所有用户态 socket 调用均经由 AFD 网关进入内核。
 */
static const PCWSTR g_MonitoredDevices[] = {
    L"\\Device\\Afd",
    L"\\Device\\Tcp",
    L"\\Device\\Udp",
    L"\\Device\\RawIp",
    L"\\Device\\Ip"
};

#define MONITORED_DEVICE_COUNT (sizeof(g_MonitoredDevices) / sizeof(g_MonitoredDevices[0]))

VOID NetMonitor::SetNdisModule(ULONG_PTR Base, ULONG_PTR End)
{
    g_NdisBase = Base;
    g_NdisEnd  = End;
    g_bNdisScanned = FALSE;
}

/*
 * ============================================================================
 * 辅助函数: 解码函数入口前 16 字节中的绝对/相对跳转指令目标地址 (Inline Hook)
 * ============================================================================
 */
static ULONG_PTR GetInlineHookTarget(ULONG_PTR fnAddr)
{
    if (!fnAddr || !MmIsAddressValid((PVOID)fnAddr))
        return 0;

    __try
    {
        PUCHAR p = (PUCHAR)fnAddr;

        /* 1. E9 xx xx xx xx  (jmp rel32) */
        if (p[0] == 0xE9)
        {
            LONG disp = *(PLONG)(p + 1);
            return (ULONG_PTR)(p + 5 + disp);
        }

        /* 2. E8 xx xx xx xx  (call rel32 劫持前置) */
        if (p[0] == 0xE8)
        {
            LONG disp = *(PLONG)(p + 1);
            return (ULONG_PTR)(p + 5 + disp);
        }

        /* 3. FF 25 xx xx xx xx  (jmp qword ptr [rip + disp32]) */
        if (p[0] == 0xFF && p[1] == 0x25)
        {
            LONG disp = *(PLONG)(p + 2);
            ULONG_PTR pTargetSlot = (ULONG_PTR)(p + 6 + disp);
            if (MmIsAddressValid((PVOID)pTargetSlot))
            {
                return *(PULONG_PTR)pTargetSlot;
            }
        }

        /* 4. 48 FF 25 xx xx xx xx  (rex.W jmp qword ptr [rip + disp32]) */
        if (p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25)
        {
            LONG disp = *(PLONG)(p + 3);
            ULONG_PTR pTargetSlot = (ULONG_PTR)(p + 7 + disp);
            if (MmIsAddressValid((PVOID)pTargetSlot))
            {
                return *(PULONG_PTR)pTargetSlot;
            }
        }

        /* 5. 48 B8 [imm64] FF E0  (mov rax, imm64; jmp rax) */
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0)
        {
            return *(PULONG_PTR)(p + 2);
        }

        /* 6. 49 BB [imm64] 41 FF E3  (mov r11, imm64; jmp r11) */
        if (p[0] == 0x49 && p[1] == 0xBB && p[10] == 0x41 && p[11] == 0xFF && p[12] == 0xE3)
        {
            return *(PULONG_PTR)(p + 2);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }

    return 0;
}

/*
 * ============================================================================
 * 监控面 1: 网络驱动分发例程 Hook 监控 (Pointer Hook + Inline Hook + FastIo)
 * ============================================================================
 */
ULONG NetMonitor::CheckTcpipHooks(VOID)
{
    ULONG hookCount = 0;

    for (ULONG d = 0; d < MONITORED_DEVICE_COUNT; d++)
    {
        UNICODE_STRING devName;
        RtlInitUnicodeString(&devName, g_MonitoredDevices[d]);

        PFILE_OBJECT   pFileObj   = NULL;
        PDEVICE_OBJECT pDevObj    = NULL;

        NTSTATUS status = IoGetDeviceObjectPointer(&devName, FILE_READ_DATA, &pFileObj, &pDevObj);
        if (!NT_SUCCESS(status) || !pDevObj)
            continue;

        __try
        {
            PDRIVER_OBJECT pDrv = pDevObj->DriverObject;
            if (pDrv)
            {
                /* 1. 扫描 IRP MajorFunction 表 (指针 Hook 与函数头部 Inline Hook) */
                for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                {
                    ULONG_PTR fn = (ULONG_PTR)pDrv->MajorFunction[i];
                    if (!fn)
                        continue;

                    /* 1.1 指针 Hook 检测 */
                    if (IsAddressInAceModules(fn))
                    {
                        DBG("[!] [NETMON ALARM-1] %ws MajorFunction[%u] POINTER HOOKED by ACE! Handler=0x%p",
                            g_MonitoredDevices[d], i, (PVOID)fn);
                        hookCount++;
                    }

                    /* 1.2 函数入口 Inline Hook 检测 (JMP 跳转至 ACE) */
                    ULONG_PTR inlineTarget = GetInlineHookTarget(fn);
                    if (inlineTarget && IsAddressInAceModules(inlineTarget))
                    {
                        DBG("[!] [NETMON ALARM-1] %ws MajorFunction[%u] (0x%p) INLINE HOOKED -> ACE Target=0x%p",
                            g_MonitoredDevices[d], i, (PVOID)fn, (PVOID)inlineTarget);
                        hookCount++;
                    }
                }

                /* 2. 扫描 FastIoDispatch 快速通道 Hook */
                PFAST_IO_DISPATCH pFastIo = pDrv->FastIoDispatch;
                if (pFastIo && MmIsAddressValid(pFastIo))
                {
                    ULONG_PTR *pFastIoArr = (ULONG_PTR *)pFastIo;
                    ULONG totalEntries = (pFastIo->SizeOfFastIoDispatch > 0 && pFastIo->SizeOfFastIoDispatch <= 512)
                                             ? (pFastIo->SizeOfFastIoDispatch / sizeof(PVOID))
                                             : 24;

                    for (ULONG j = 1; j < totalEntries; j++)
                    {
                        ULONG_PTR fn = pFastIoArr[j];
                        if (!fn)
                            continue;

                        if (IsAddressInAceModules(fn))
                        {
                            DBG("[!] [NETMON ALARM-1] %ws FastIoDispatch[%u] POINTER HOOKED by ACE! Handler=0x%p",
                                g_MonitoredDevices[d], j, (PVOID)fn);
                            hookCount++;
                        }

                        ULONG_PTR inlineTarget = GetInlineHookTarget(fn);
                        if (inlineTarget && IsAddressInAceModules(inlineTarget))
                        {
                            DBG("[!] [NETMON ALARM-1] %ws FastIoDispatch[%u] INLINE HOOKED -> ACE Target=0x%p",
                                g_MonitoredDevices[d], j, (PVOID)inlineTarget);
                            hookCount++;
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] NetMonitor: Exception while checking hooks on %ws", g_MonitoredDevices[d]);
        }

        if (pFileObj) {
            if (g_pNetMonUserVar && g_pNetMonUserVar->Func.ObfDereferenceObject) {
                g_pNetMonUserVar->Func.ObfDereferenceObject(pFileObj);
            }
        }
    }

    return hookCount;
}

/*
 * ============================================================================
 * 监控面 2: TDI / 设备栈附加过滤设备监控 (AttachedDevice 链，包含 \Device\Afd)
 * ============================================================================
 */
ULONG NetMonitor::CheckTdiAttached(VOID)
{
    ULONG attachedCount = 0;

    for (ULONG d = 0; d < MONITORED_DEVICE_COUNT; d++)
    {
        UNICODE_STRING devName;
        RtlInitUnicodeString(&devName, g_MonitoredDevices[d]);

        PFILE_OBJECT   pFileObj   = NULL;
        PDEVICE_OBJECT pDevObj    = NULL;

        NTSTATUS status = IoGetDeviceObjectPointer(&devName, FILE_READ_DATA, &pFileObj, &pDevObj);
        if (!NT_SUCCESS(status) || !pDevObj)
            continue;

        __try
        {
            PDEVICE_OBJECT pCurr = pDevObj->AttachedDevice;
            ULONG depth = 0;

            while (pCurr && depth < 16)
            {
                if (pCurr->DriverObject)
                {
                    ULONG_PTR drvStart = (ULONG_PTR)pCurr->DriverObject->DriverStart;
                    if (IsAddressInAceModules(drvStart))
                    {
                        DBG("[!] [NETMON ALARM-2] ACE AttachedDevice found on %ws stack! Driver=0x%p (%wZ)",
                            g_MonitoredDevices[d], (PVOID)drvStart, &pCurr->DriverObject->DriverName);
                        attachedCount++;
                    }

                    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
                    {
                        ULONG_PTR fn = (ULONG_PTR)pCurr->DriverObject->MajorFunction[i];
                        if (fn && IsAddressInAceModules(fn))
                        {
                            DBG("[!] [NETMON ALARM-2] AttachedDevice on %ws has ACE Handler[%u]=0x%p",
                                g_MonitoredDevices[d], i, (PVOID)fn);
                            attachedCount++;
                            break;
                        }
                    }
                }

                pCurr = pCurr->AttachedDevice;
                depth++;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG("[-] NetMonitor: Exception while checking attached devices on %ws", g_MonitoredDevices[d]);
        }

        if (pFileObj) {
            if (g_pNetMonUserVar && g_pNetMonUserVar->Func.ObfDereferenceObject) {
                g_pNetMonUserVar->Func.ObfDereferenceObject(pFileObj);
            }
        }
    }

    return attachedCount;
}

/*
 * ============================================================================
 * 监控面 3: NDIS LWF 轻量级网络过滤驱动链表监控 (ndisFilterDriverList)
 * ============================================================================
 */
static PVOID *NetMonitor_LocateNdisFilterDriverList(VOID)
{
    if (g_pFilterDriverList)
        return g_pFilterDriverList;

    if (!g_NdisBase || !g_NdisEnd || g_NdisEnd <= g_NdisBase)
        return NULL;

    PUCHAR pStart  = (PUCHAR)g_NdisBase;
    ULONG  scanLen = (ULONG)(g_NdisEnd - g_NdisBase);

    if (scanLen > 0x300000)
    {
        scanLen = 0x300000;
    }

    __try
    {
        for (ULONG i = 0; i + 14 < scanLen; i++)
        {
            if (pStart[i] == 0x48 && pStart[i + 1] == 0x8B && pStart[i + 2] == 0x0D &&
                pStart[i + 7] == 0x48 && pStart[i + 8] == 0x8D && pStart[i + 9] == 0x15)
            {
                LONG d1 = *(PLONG)(pStart + i + 3);
                LONG d2 = *(PLONG)(pStart + i + 10);

                if (d1 - d2 == 7)
                {
                    ULONG_PTR target = (ULONG_PTR)(pStart + i + 7 + d1);
                    if (target >= g_NdisBase && target < g_NdisEnd)
                    {
                        g_pFilterDriverList = (PVOID *)target;
                        DBG("[+] NetMonitor: Resolved ndisFilterDriverList @ 0x%p (offset +0x%X in ndis.sys)",
                            (PVOID)target, i);
                        return g_pFilterDriverList;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG("[-] NetMonitor: Exception scanning for ndisFilterDriverList");
    }

    return NULL;
}

ULONG NetMonitor::CheckNdisFilters(VOID)
{
    ULONG fltMatchCount = 0;

    PVOID *pList = NetMonitor_LocateNdisFilterDriverList();
    if (!pList)
    {
        if (!g_bNdisScanned)
        {
            g_bNdisScanned = TRUE;
            DBG("[*] NetMonitor: ndis.sys information pending or pattern not found yet");
        }
        return 0;
    }

    __try
    {
        PVOID pBlock = *pList;
        ULONG count = 0;

        while (pBlock && count < 64)
        {
            PDRIVER_OBJECT pFltDrv = *(PDRIVER_OBJECT *)((PUCHAR)pBlock + 0x10);
            PUNICODE_STRING pImageName = (PUNICODE_STRING)((PUCHAR)pBlock + 0x160);

            if (pFltDrv && MmIsAddressValid(pFltDrv))
            {
                ULONG_PTR drvBase = (ULONG_PTR)pFltDrv->DriverStart;
                if (IsAddressInAceModules(drvBase))
                {
                    DBG("[!] [NETMON ALARM-3] ACE NDIS Filter Driver detected! Driver=0x%p (ImageName=%wZ)",
                        (PVOID)drvBase, pImageName);
                    fltMatchCount++;
                }
            }

            /* 扫描该过滤驱动注册的接收/发送/请求回调 (含 Inline Hook 检测) */
            PUCHAR pChars = (PUCHAR)pBlock + 0x60;
            for (ULONG k = 0; k < 0x80; k += sizeof(PVOID))
            {
                ULONG_PTR fn = *(ULONG_PTR *)(pChars + k);
                if (!fn)
                    continue;

                if (IsAddressInAceModules(fn))
                {
                    DBG("[!] [NETMON ALARM-3] ACE NDIS Filter Callback detected! Handler=0x%p (FilterBlock=0x%p)",
                        (PVOID)fn, pBlock);
                    fltMatchCount++;
                    break;
                }

                ULONG_PTR inlineTarget = GetInlineHookTarget(fn);
                if (inlineTarget && IsAddressInAceModules(inlineTarget))
                {
                    DBG("[!] [NETMON ALARM-3] ACE NDIS Filter Callback (0x%p) INLINE HOOKED -> ACE Target=0x%p",
                        (PVOID)fn, (PVOID)inlineTarget);
                    fltMatchCount++;
                    break;
                }
            }

            pBlock = *(PVOID *)((PUCHAR)pBlock + 0x08);
            count++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG("[-] NetMonitor: Exception traversing ndisFilterDriverList");
    }

    return fltMatchCount;
}

/*
 * ============================================================================
 * 监控面 4: 通讯驱动自身 WSK Provider Dispatch 函数表完整性自检
 * ============================================================================
 */
ULONG NetMonitor::CheckWskDispatch(VOID)
{
    ULONG alarmCount = 0;

    if (!g_WskServer.fCapturedNpi || !g_WskServer.ProviderNpi.Dispatch)
        return 0;

    __try
    {
        const WSK_PROVIDER_DISPATCH *pDisp = g_WskServer.ProviderNpi.Dispatch;
        if (!MmIsAddressValid((PVOID)pDisp))
            return 0;

        /* WSK_PROVIDER_DISPATCH 内含 Version, Reserved, WskSocket, WskSocketConnect, WskControlSocket, WskGetLocalAddress */
        ULONG_PTR *pFuncArray = (ULONG_PTR *)pDisp;
        for (ULONG i = 1; i <= 6; i++)
        {
            ULONG_PTR fn = pFuncArray[i];
            if (!fn)
                continue;

            /* 4.1 指针是否指向 ACE */
            if (IsAddressInAceModules(fn))
            {
                DBG("[!] [NETMON ALARM-4] WSK ProviderDispatch[%u] (0x%p) POINTER POINTS TO ACE!", i, (PVOID)fn);
                alarmCount++;
            }

            /* 4.2 函数入口是否被 Inline Hook 到 ACE */
            ULONG_PTR target = GetInlineHookTarget(fn);
            if (target && IsAddressInAceModules(target))
            {
                DBG("[!] [NETMON ALARM-4] WSK ProviderDispatch[%u] (0x%p) INLINE HOOKED -> ACE Target=0x%p",
                    i, (PVOID)fn, (PVOID)target);
                alarmCount++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBG("[-] NetMonitor: Exception during WSK Dispatch audit");
    }

    return alarmCount;
}

/*
 * ============================================================================
 * 全栈主动扫描入口
 * ============================================================================
 */
VOID NetMonitor::ScanAll(VOID)
{
    static ULONG s_scanRound = 0;
    s_scanRound++;

    ULONG hooks    = CheckTcpipHooks();
    ULONG attached = CheckTdiAttached();
    ULONG ndis     = CheckNdisFilters();
    ULONG wskDisp  = CheckWskDispatch();

    ULONG totalAlarms = hooks + attached + ndis + wskDisp;

    if (totalAlarms > 0)
    {
        DBG("[!] NetMonitor [Round #%lu]: >>> THREAT DETECTED! Total=%u (TCP/AFD Hooks=%u, AttachedDevices=%u, NDIS Filters=%u, WSK Tamper=%u) <<<",
            s_scanRound, totalAlarms, hooks, attached, ndis, wskDisp);
    }
    else
    {
        /* 仅每 5 轮或前 3 轮输出一次心跳正常日志，避免刷屏 */
        if (s_scanRound <= 3 || (s_scanRound % 5) == 0)
        {
            DBG("[+] NetMonitor [Round #%lu]: All clean — AFD/TCP/IP MajorFunctions intact (no pointer/inline hooks), no AttachedDevices, NDIS filters clean, WSK dispatch intact",
                s_scanRound);
        }
    }
}

NTSTATUS NetMonitor::Init(VOID)
{
    DBG("[+] NetMonitor: Network Full-Stack Security Monitoring Engine Initialized");
    return STATUS_SUCCESS;
}
