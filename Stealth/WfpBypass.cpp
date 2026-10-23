/*
 * wfp_bypass.c  [W2 — DKOM netio.sys Callout 表替换]
 *
 * 核心思路（W2）：
 *   ACE 比 Machenike 先加载，Hook FwpsCalloutRegister2 无效（W1 废弃）。
 *   W2 在驱动初始化后直接扫描 netio.sys 内存中的 Callout 表（gCalloutTable），
 *   将 classifyFn 地址落在 ACE 驱动 PE 范围内的条目原子替换为 wrapper。
 *
 * 定位 gCalloutTable：
 *   扫描 FwpsCalloutRegister2 函数体前 512 字节的 RIP 相对引用，
 *   找到指向 netio 数据段（非代码段）的指针变量，即 gCalloutTable 地址。
 *
 * 多核安全：
 *   classifyFn 替换使用 InterlockedExchangePointer（8 字节对齐原子写）。
 *   Callout 表位于 NonPagedPool，无需关闭 CR0.WP。
 *   _mm_sfence() 保证写操作对所有核心可见。
 *
 * FWPCALLOUT 结构（Win10 1507 ~ Win11 24H2，偏移稳定）：
 *   +0x000  GUID     calloutKey
 *   +0x010  UINT32   flags
 *   +0x014  UINT32   reserved0
 *   +0x018  PVOID    classifyFn   <- 替换目标
 *   +0x020  PVOID    notifyFn
 *   +0x028  PVOID    flowDeleteFn
 *   +0x030  UINT16   layerId
 *   +0x032  UINT16   reserved1
 *   +0x034  UINT32   calloutId
 *   +0x038  UINT64   reserved2
 *   (条目总大小 = 0x40 字节)
 */

#include "MachenikeString.h"
#include "Utils.h"
#include "WfpBypass.h"

/* ======================================================================
 * 模式开关
 * ====================================================================== */

#ifndef WFP_ENABLE_CALLOUT_REPLACE
#define WFP_ENABLE_CALLOUT_REPLACE 1
#endif

/* ======================================================================
 * 常量
 * ====================================================================== */

#define WFP_POOL_TAG 'tNeN'
#define WFP_MAX_ACE_CALLOUTS 16
#define WFP_CALLOUT_ENTRY_SIZE 0x40
#define WFP_CLASSIFY_FN_OFFSET 0x18
#define WFP_SCAN_FUNC_BYTES 512
#define WFP_MAX_CALLOUT_COUNT 512

/* ======================================================================
 * 内部类型
 * ====================================================================== */

typedef VOID(NTAPI *FWPS_CALLOUT_CLASSIFY_FN2)(_In_ const void *inFixedValues, _In_ const void *inMetaValues, _Inout_opt_ void *layerData,
                                               _In_opt_ const void *classifyContext, _In_ const void *filter, _In_ UINT64 flowContext,
                                               _Inout_ void *classifyOut);

typedef struct _ACE_CALLOUT_SLOT
{
    BOOLEAN bUsed;
    PVOID *pClassifyFnField;
    FWPS_CALLOUT_CLASSIFY_FN2 origClassifyFn;
} ACE_CALLOUT_SLOT;

/* ======================================================================
 * WFP 固定值解析辅助（提取端口）
 * ====================================================================== */

#define FWP_TYPE_UINT16 2
#define WFP_DEFAULT_TARGET_PORT 10001

typedef struct _WFP_VALUE_MINI
{
    UINT32 type;
    UINT32 padding;
    union
    {
        UINT16 uint16;
        UINT32 uint32;
        UINT64 uint64;
    } u;
} WFP_VALUE_MINI;

typedef struct _WFP_INCOMING_VALUE_MINI
{
    WFP_VALUE_MINI value;
} WFP_INCOMING_VALUE_MINI;

typedef struct _WFP_INCOMING_VALUES_MINI
{
    UINT16 layerId;
    UINT32 incomingValuesCount;
    const WFP_INCOMING_VALUE_MINI *incomingValue;
} WFP_INCOMING_VALUES_MINI;

/* ======================================================================
 * 全局状态
 * ====================================================================== */

static volatile LONG g_W2Init = 0;
static MACHENIKE_KERNEL_INTERFACE *g_WfpUserVar = NULL;
/* 默认初始化为 10001 端口（网络字节序 0x1127），volatile LONG 保证原子多核读取与更新 */
static volatile LONG g_HiddenPort = (LONG)(((WFP_DEFAULT_TARGET_PORT & 0xFF) << 8) | ((WFP_DEFAULT_TARGET_PORT >> 8) & 0xFF));

static ULONG_PTR g_NetioBase = 0;
static ULONG_PTR g_NetioEnd = 0;
static ULONG_PTR g_FwpsReg2Addr = 0;

static ACE_CALLOUT_SLOT g_Slots[WFP_MAX_ACE_CALLOUTS];
static volatile LONG g_SlotCount = 0;

/* WfpBypass_Init 历史尝试次数（全局，SetAceInfo 检测到 ACE 重新出现时清零） */
static volatile LONG g_WfpAttemptCount = 0;

typedef struct _FWPS_CLASSIFY_OUT_MINI
{
    UINT32 actionType;
    UINT32 padding;
    UINT64 outContext;
    UINT64 filterId;
    UINT32 rights;
    UINT32 flags;
    UINT32 reserved;
} FWPS_CLASSIFY_OUT_MINI;

#define FWP_ACTION_PERMIT 0x00000001

/*
 * 检查当前流量的本地端口或远程端口是否匹配目标端口
 */
static BOOLEAN IsTargetPort(_In_opt_ const void *inFixedValues)
{
    if (!inFixedValues)
        return FALSE;

    USHORT targetPortNet = (USHORT)g_HiddenPort;
    USHORT targetPortHost = (USHORT)((targetPortNet >> 8) | (targetPortNet << 8));

    if (targetPortNet == 0 && targetPortHost == 0)
        return FALSE;

    const WFP_INCOMING_VALUES_MINI *vals = (const WFP_INCOMING_VALUES_MINI *)inFixedValues;
    if (vals->incomingValuesCount > 64 || !vals->incomingValue)
        return FALSE;

    for (UINT32 i = 0; i < vals->incomingValuesCount; i++)
    {
        if (vals->incomingValue[i].value.type == FWP_TYPE_UINT16)
        {
            USHORT port = vals->incomingValue[i].value.u.uint16;
            if (port == targetPortHost || port == targetPortNet)
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* ======================================================================
 * WfpBypass_ClassifyWrapper
 * 在 DISPATCH_LEVEL 执行，不可阻塞，不可分配内存。
 * ====================================================================== */

/* ======================================================================
 * ClassifyCommon
 * 在 DISPATCH_LEVEL 执行，不可阻塞，不可分配内存。
 * ====================================================================== */

static VOID NTAPI ClassifyCommon(_In_ LONG slotIndex, _In_ const void *inFixedValues, _In_ const void *inMetaValues,
                                 _Inout_opt_ void *layerData, _In_opt_ const void *classifyContext, _In_ const void *filter,
                                 _In_ UINT64 flowContext, _Inout_ void *classifyOut)
{
    /* 核心拦截：对命中目标隐藏端口（10001 / g_HiddenPort）的流量进行彻底隐藏与放行 */
    if (IsTargetPort(inFixedValues))
    {
        /* 直接放行网络包并返回，绝不调用目标 ACE/Mock 驱动的原 classifyFn！
         * 使得目标驱动完全无法捕获或统计该端口的流量，彻底实现流量静默隐身。
         */
        if (classifyOut)
        {
            FWPS_CLASSIFY_OUT_MINI *pOut = (FWPS_CLASSIFY_OUT_MINI *)classifyOut;
            pOut->actionType = FWP_ACTION_PERMIT;
        }
        return;
    }

    /* 非目标端口流量：精准一对一转发对应 Slot 自身的原 classifyFn，确保游戏和系统的正常网络通讯完全不受影响 */
    if (slotIndex >= 0 && slotIndex < WFP_MAX_ACE_CALLOUTS)
    {
        FWPS_CALLOUT_CLASSIFY_FN2 origFn = g_Slots[slotIndex].origClassifyFn;
        if (origFn)
        {
            origFn(inFixedValues, inMetaValues, layerData, classifyContext, filter, flowContext, classifyOut);
        }
    }
}

#define DEFINE_CLASSIFY_WRAPPER(N)                                                                                                         \
    static VOID NTAPI WfpBypass_ClassifyWrapper_##N(_In_ const void *inFixedValues, _In_ const void *inMetaValues,                         \
                                                    _Inout_opt_ void *layerData, _In_opt_ const void *classifyContext,                     \
                                                    _In_ const void *filter, _In_ UINT64 flowContext, _Inout_ void *classifyOut)           \
    {                                                                                                                                      \
        ClassifyCommon(N, inFixedValues, inMetaValues, layerData, classifyContext, filter, flowContext, classifyOut);                      \
    }

DEFINE_CLASSIFY_WRAPPER(0)
DEFINE_CLASSIFY_WRAPPER(1)
DEFINE_CLASSIFY_WRAPPER(2)
DEFINE_CLASSIFY_WRAPPER(3)
DEFINE_CLASSIFY_WRAPPER(4)
DEFINE_CLASSIFY_WRAPPER(5)
DEFINE_CLASSIFY_WRAPPER(6)
DEFINE_CLASSIFY_WRAPPER(7)
DEFINE_CLASSIFY_WRAPPER(8)
DEFINE_CLASSIFY_WRAPPER(9)
DEFINE_CLASSIFY_WRAPPER(10)
DEFINE_CLASSIFY_WRAPPER(11)
DEFINE_CLASSIFY_WRAPPER(12)
DEFINE_CLASSIFY_WRAPPER(13)
DEFINE_CLASSIFY_WRAPPER(14)
DEFINE_CLASSIFY_WRAPPER(15)

static const FWPS_CALLOUT_CLASSIFY_FN2 g_ClassifyWrappers[WFP_MAX_ACE_CALLOUTS] = {
    WfpBypass_ClassifyWrapper_0,  WfpBypass_ClassifyWrapper_1,  WfpBypass_ClassifyWrapper_2,  WfpBypass_ClassifyWrapper_3,
    WfpBypass_ClassifyWrapper_4,  WfpBypass_ClassifyWrapper_5,  WfpBypass_ClassifyWrapper_6,  WfpBypass_ClassifyWrapper_7,
    WfpBypass_ClassifyWrapper_8,  WfpBypass_ClassifyWrapper_9,  WfpBypass_ClassifyWrapper_10, WfpBypass_ClassifyWrapper_11,
    WfpBypass_ClassifyWrapper_12, WfpBypass_ClassifyWrapper_13, WfpBypass_ClassifyWrapper_14, WfpBypass_ClassifyWrapper_15};

static BOOLEAN IsOurWrapper(PVOID pFn)
{
    if (!pFn)
        return FALSE;
    for (LONG i = 0; i < WFP_MAX_ACE_CALLOUTS; i++)
    {
        if (pFn == (PVOID)g_ClassifyWrappers[i])
            return TRUE;
    }
    return FALSE;
}

static inline BOOLEAN WfpBypass_IsValidKernelPtr(const void *ptr)
{
    ULONG_PTR u = (ULONG_PTR)ptr;
    if (u <= 0xFFFF800000000000ULL || u >= 0xFFFFFF0000000000ULL)
        return FALSE;
    return MmIsAddressValid((PVOID)ptr);
}

/* ======================================================================
 * 内部：从 FwpsCalloutRegister2 函数体扫描 RIP 相对引用
 * 定位 gCalloutTable（PVOID* 类型的全局变量）
 * ====================================================================== */

static PVOID *WfpBypass_FindCalloutTable(_In_ ULONG_PTR funcAddr, _In_ ULONG_PTR netioBase, _In_ ULONG_PTR netioEnd, _Out_ LONG *pCount)
{
    *pCount = 0;
    if (!funcAddr || netioBase >= netioEnd)
        return NULL;

    const UCHAR *p = (const UCHAR *)funcAddr;
    const UCHAR *pEnd = p + WFP_SCAN_FUNC_BYTES;

    PVOID *pTable = NULL;
    LONG *pCnt = NULL;

    for (; p + 7 <= pEnd; p++)
    {
        INT32 disp = 0;
        ULONG ilen = 0;

        if (p[0] == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x05)
        {
            disp = *(const INT32 *)(p + 3);
            ilen = 7;
        }
        else if (p[0] == 0x48 && p[1] == 0x8D && (p[2] & 0xC7) == 0x05)
        {
            disp = *(const INT32 *)(p + 3);
            ilen = 7;
        }
        else if (p[0] == 0x8B && p[1] == 0x05)
        {
            disp = *(const INT32 *)(p + 2);
            ilen = 6;
        }
        else if (p[0] == 0x8B && p[1] == 0x0D)
        {
            disp = *(const INT32 *)(p + 2);
            ilen = 6;
        }
        else
            continue;

        ULONG_PTR rip = (ULONG_PTR)(p + ilen);
        ULONG_PTR target = rip + (ULONG_PTR)(LONG_PTR)disp;

        if (target < netioBase || target + 8 > netioEnd)
            continue;

        ULONG_PTR ptrVal = *(ULONG_PTR *)target;
        UINT32 u32Val = *(UINT32 *)target;

        if (!pTable && (target & 7) == 0 && WfpBypass_IsValidKernelPtr((PVOID)ptrVal) && (ptrVal < netioBase || ptrVal >= netioEnd))
        {
            ULONG_PTR pEngine = ptrVal;
            ULONG_PTR subTable = 0;
            ULONG subCount = 0;

            if (WfpBypass_IsValidKernelPtr((PVOID)(pEngine + 0x198)) && WfpBypass_IsValidKernelPtr((PVOID)(pEngine + 0x190)))
            {
                __try
                {
                    subTable = *(ULONG_PTR *)(pEngine + 0x198);
                    subCount = *(ULONG *)(pEngine + 0x190);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    subTable = 0;
                    subCount = 0;
                }
            }

            DBG("WfpBypass W2: Inspecting target=0x%p pEngine=0x%p subTable=0x%p subCount=%u", (PVOID)target, (PVOID)pEngine,
                (PVOID)subTable, subCount);

            if (WfpBypass_IsValidKernelPtr((PVOID)subTable))
            {
                pTable = (PVOID *)(pEngine + 0x198);
                *pCount = (subCount >= 1 && subCount <= 65536) ? (LONG)subCount : 2048;
                DBG("WfpBypass W2: EngineContext CalloutTable @ 0x%p -> 0x%p count=%ld", (PVOID)pTable, (PVOID)subTable, *pCount);
                return pTable;
            }

            pTable = (PVOID *)target;
        }

        if (!pCnt && (target & 3) == 0 && u32Val >= 1 && u32Val <= 65536)
        {
            pCnt = (LONG *)target;
        }

        if (pTable && pCnt)
            break;
    }

    if (!pTable)
    {
        DBG("WfpBypass W2: gCalloutTable not found");
        return NULL;
    }

    *pCount = pCnt ? *pCnt : 2048;
    DBG("WfpBypass W2: gCalloutTable @ 0x%p -> 0x%p count=%ld", (PVOID)pTable, *pTable, *pCount);
    return pTable;
}

static LARGE_INTEGER g_AceFirstSeenTime = {0};

static BOOLEAN InstallSlot(PVOID *pField, PVOID cur)
{
#if (WFP_ENABLE_CALLOUT_REPLACE == 0)
    UNREFERENCED_PARAMETER(pField);
    UNREFERENCED_PARAMETER(cur);
    DBG("WfpBypass W2: [DETECT ONLY] Matched ACE callback 0x%p, replace skipped", cur);
    return TRUE;
#else
    LONG idx = InterlockedIncrement(&g_SlotCount) - 1;
    if (idx >= WFP_MAX_ACE_CALLOUTS)
    {
        InterlockedDecrement(&g_SlotCount);
        DBG("WfpBypass W2: Slots full, stopped");
        return FALSE;
    }

    g_Slots[idx].bUsed = TRUE;
    g_Slots[idx].pClassifyFnField = pField;
    g_Slots[idx].origClassifyFn = (FWPS_CALLOUT_CLASSIFY_FN2)cur;

    PVOID old = InterlockedCompareExchangePointer(pField, (PVOID)g_ClassifyWrappers[idx], cur);
    if (old != cur)
    {
        DBG("WfpBypass W2: Slot %ld CAS failed (expected 0x%p, got 0x%p)", idx, cur, old);
        g_Slots[idx].bUsed = FALSE;
        InterlockedDecrement(&g_SlotCount);
        return FALSE;
    }
    _mm_sfence();

    DBG("WfpBypass W2: Callout 0x%p -> wrapper[%ld]", cur, idx);
    return TRUE;
#endif
}

/*
 * 第 1 轨：使用 netio.sys 导出的官方 KfdGetRefCallout API 进行全量 Callout 检索
 */
static LONG TryKfdApi(_In_ ULONG_PTR netioBase, _In_ LONG count)
{
    UNREFERENCED_PARAMETER(netioBase);
    if (!g_pGlobalUserVar || !g_pGlobalUserVar->Func.KfdGetRefCallout)
    {
        return 0;
    }

    FuncTypeDef_KfdGetRefCallout pfnGetRef = g_pGlobalUserVar->Func.KfdGetRefCallout;
    FuncTypeDef_KfdDeRefCallout pfnDeRef = g_pGlobalUserVar->Func.KfdDeRefCallout;

    DBG("WfpBypass W2: Track-1 (KfdGetRefCallout=0x%p, KfdDeRefCallout=0x%p) active, scanning 1..%ld...", (PVOID)pfnGetRef,
        (PVOID)pfnDeRef, count);

    LONG n = 0;
    LONG activeCount = 0;
    ULONG fnOffsets[] = {0x10, 0x28, 0x18, 0x20};

    for (UINT32 id = 1; id <= (UINT32)count && id <= 2048; id++)
    {
        PVOID pEntry = NULL;
        __try
        {
            pfnGetRef(id, &pEntry);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            pEntry = NULL;
        }

        if (!pEntry || (ULONG_PTR)pEntry <= 0xFFFF800000000000ULL)
            continue;

        /* netio!KfdGetRefCallout 在 ID 未使用时返回全局固定 Dummy Entry (其 state == 0)
         * 必须严格检查 activeState != 0，避免在假条目上空转 */
        UINT32 entryState = 0;
        __try
        {
            entryState = *(UINT32 *)((PUCHAR)pEntry + 4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            entryState = 0;
        }
        if (entryState == 0)
        {
            if (pfnDeRef)
            {
                __try
                {
                    pfnDeRef(pEntry);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                }
            }
            continue;
        }

        activeCount++;
        PUCHAR pEntryBytes = (PUCHAR)pEntry;

        for (ULONG f = 0; f < 4; f++)
        {
            PVOID *pField = (PVOID *)(pEntryBytes + fnOffsets[f]);
            PVOID cur = NULL;
            __try
            {
                cur = *pField;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                cur = NULL;
            }
            if (!cur || (ULONG_PTR)cur <= 0xFFFF800000000000ULL || IsOurWrapper(cur))
                continue;

            ULONG_PTR fn = (ULONG_PTR)cur;

            if (activeCount <= 5 && f == 0)
            {
                DBG("WfpBypass W2: Track-1 Active CalloutId=%u Entry=0x%p state=%u classifyFn=0x%p", id, pEntry, entryState, (PVOID)fn);
            }

            if (IsAddressInAceModules(fn))
            {
                DBG("WfpBypass W2: Track-1 MATCH! CalloutId=%u Entry=0x%p Offset=0x%X Fn=0x%p", id, pEntry, fnOffsets[f], (PVOID)fn);
                if (InstallSlot(pField, cur))
                {
                    n++;
                    break;
                }
            }
        }

        if (pfnDeRef)
        {
            __try
            {
                pfnDeRef(pEntry);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }
    }

    DBG("WfpBypass W2: Track-1 scanned %ld active Callouts from official API, matched %ld targets", activeCount, n);
    return n;
}

static LONG DoReplace(_In_ PVOID *pTableVar, _In_ LONG count)
{
    if (!pTableVar || !*pTableVar || count <= 0)
        return 0;

    /* 优先尝试第 1 轨：使用 netio.sys 导出的官方 KfdGetRefCallout API */
    if (g_NetioBase)
    {
        LONG nApi = TryKfdApi(g_NetioBase, count);
        if (nApi > 0)
        {
            return nApi;
        }
    }

    /* 第 2 轨：原生 DKOM 内存数组深度扫描与全量诊断 */
    PUCHAR pTbl = (PUCHAR)*pTableVar;

    /* 自适应解引用保护：仅当 pTbl 传入的是 pEngine 结构且其 +0x190 呈现有效 Count 时才解引用，
     * 严禁对已经是 CalloutTable 堆数组的指针再次执行 +0x198 解引用 */
    if (WfpBypass_IsValidKernelPtr(pTbl) && WfpBypass_IsValidKernelPtr(pTbl + 0x198) && WfpBypass_IsValidKernelPtr(pTbl + 0x190))
    {
        __try
        {
            ULONG subCount = *(ULONG *)(pTbl + 0x190);
            ULONG_PTR subTable = *(ULONG_PTR *)(pTbl + 0x198);
            if (subCount >= 1 && subCount <= 65536 && WfpBypass_IsValidKernelPtr((PVOID)subTable) && subTable != (ULONG_PTR)pTbl)
            {
                DBG("WfpBypass W2: Dereferencing pEngine(0x%p)+0x198 -> 0x%p (count=%lu)", (PVOID)pTbl, (PVOID)subTable, subCount);
                pTbl = (PUCHAR)subTable;
                if (count > (LONG)subCount)
                    count = (LONG)subCount;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    LONG n = 0;
    ULONG entrySizes[] = {0x50, 0x40};
    ULONG fnOffsets[] = {0x10, 0x18, 0x20, 0x28, 0x30, 0x38};
    LONG totalActiveDkom = 0;

    // 模式 1：扁平结构体数组扫描（Win10/11 原生 0x50 / 0x40 字节）
    for (ULONG s = 0; s < 2; s++)
    {
        ULONG entrySize = entrySizes[s];
        LONG activeInMode = 0;
        for (LONG i = 0; i < count && i < 2048; i++)
        {
            PUCHAR pEntry = pTbl + (i * entrySize);
            if (!WfpBypass_IsValidKernelPtr(pEntry) || !WfpBypass_IsValidKernelPtr(pEntry + 4))
                continue;

            UINT32 version = 0;
            UINT32 activeState = 0;
            __try
            {
                version = *(UINT32 *)(pEntry);
                activeState = *(UINT32 *)(pEntry + 4);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                activeState = 0;
            }

            for (ULONG f = 0; f < 5; f++)
            {
                PVOID *pField = (PVOID *)(pEntry + fnOffsets[f]);
                if (!WfpBypass_IsValidKernelPtr(pField))
                    continue;

                PVOID cur = NULL;
                __try
                {
                    cur = *pField;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    cur = NULL;
                }
                if (!WfpBypass_IsValidKernelPtr(cur))
                    continue;
                activeInMode++;
                if (IsOurWrapper(cur))
                    continue;
                ULONG_PTR fn = (ULONG_PTR)cur;
                if (totalActiveDkom < 3 && f == 0)
                {
                    DBG("WfpBypass W2: Track-2 DKOM Active Callout[%ld] id=%ld ver=%u state=%u offset=0x%X fn=0x%p", totalActiveDkom, i,
                        version, activeState, fnOffsets[f], (PVOID)fn);
                    totalActiveDkom++;
                }

                if (IsAddressInAceModules(fn))
                {
                    DBG("WfpBypass W2: Track-2 DKOM MATCH! id=%ld Offset=0x%X Fn=0x%p", i, fnOffsets[f], (PVOID)fn);
                    if (!InstallSlot(pField, cur))
                        return n;
                    n++;
                    break;
                }
            }
        }
        if (n > 0)
        {
            DBG("WfpBypass W2: Track-2 replaced %ld Callouts using entrySize 0x%X (active=%ld)", n, entrySize, activeInMode);
            return n;
        }
    }

    // 模式 2：指针数组扫描（每个元素为独立 Callout 对象的内核指针）
    PVOID *pPtrArray = (PVOID *)pTbl;
    for (LONG i = 0; i < count && i < 2048; i++)
    {
        if (!WfpBypass_IsValidKernelPtr(&pPtrArray[i]))
            break;

        PVOID pObj = NULL;
        __try
        {
            pObj = pPtrArray[i];
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            pObj = NULL;
        }
        if (!WfpBypass_IsValidKernelPtr(pObj))
            continue;

        PUCHAR pEntry = (PUCHAR)pObj;
        for (ULONG f = 0; f < 5; f++)
        {
            PVOID *pField = (PVOID *)(pEntry + fnOffsets[f]);
            if (!WfpBypass_IsValidKernelPtr(pField))
                continue;

            PVOID cur = NULL;
            __try
            {
                cur = *pField;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                cur = NULL;
            }
            if (!WfpBypass_IsValidKernelPtr(cur) || IsOurWrapper(cur))
                continue;

            ULONG_PTR fn = (ULONG_PTR)cur;
            if (IsAddressInAceModules(fn))
            {
                DBG("WfpBypass W2: Track-2 Pointer-Array MATCH! id=%ld Offset=0x%X Fn=0x%p", i, fnOffsets[f], (PVOID)fn);
                if (!InstallSlot(pField, cur))
                    return n;
                n++;
                break;
            }
        }
    }

    DBG("WfpBypass W2: Track-2 finished. Total entries=%ld, active sampled=%ld, matches=%ld", count, totalActiveDkom, n);

    if (n > 0)
        return n;

    /*
     * Track-3：扩展回调字段扫描
     * 场景：MockAceMonitor 通过 fwpkclnt.sys 中转 stub 注册 classifyFn，
     *       导致 classifyFn 地址落在 fwpkclnt 范围而非 ACE 范围。
     *       但 notifyFn (+0x20) / flowDeleteFn (+0x28) 通常直接指向 ACE 驱动本体。
     *       此轨道通过这两个字段确认归属，再精准替换 classifyFn (+0x10 / +0x18)。
     */
    {
        ULONG auxOffsets[] = {0x20, 0x28};
        ULONG classifyOffsets[] = {0x10, 0x18};

        LONG t3matches = 0;
        for (LONG i = 0; i < count && i < 2048; i++)
        {
            for (ULONG s = 0; s < 2; s++)
            {
                ULONG entrySize = entrySizes[s];
                PUCHAR pEntry = pTbl + (ULONG_PTR)((ULONG64)i * entrySize);
                if (!WfpBypass_IsValidKernelPtr(pEntry))
                    continue;

                BOOLEAN aceOwned = FALSE;
                for (ULONG a = 0; a < 2; a++)
                {
                    PVOID *pAuxField = (PVOID *)(pEntry + auxOffsets[a]);
                    if (!WfpBypass_IsValidKernelPtr(pAuxField))
                        continue;

                    PVOID aux = NULL;
                    __try
                    {
                        aux = *pAuxField;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        aux = NULL;
                    }
                    if (WfpBypass_IsValidKernelPtr(aux) && IsAddressInAceModules((ULONG_PTR)aux))
                    {
                        aceOwned = TRUE;
                        break;
                    }
                }

                if (!aceOwned)
                    continue;

                for (ULONG c = 0; c < 2; c++)
                {
                    PVOID *pField = (PVOID *)(pEntry + classifyOffsets[c]);
                    if (!WfpBypass_IsValidKernelPtr(pField))
                        continue;

                    PVOID cur = NULL;
                    __try
                    {
                        cur = *pField;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        cur = NULL;
                    }
                    if (!WfpBypass_IsValidKernelPtr(cur) || IsOurWrapper(cur))
                        continue;

                    DBG("WfpBypass W2: Track-3 ACE-owned Callout[%ld] via aux field, classifyFn=0x%p -> replacing", i, cur);
                    if (InstallSlot(pField, cur))
                        t3matches++;
                    break;
                }
            }
        }

        if (t3matches > 0)
        {
            DBG("WfpBypass W2: Track-3 replaced %ld ACE Callouts via aux-field ownership detection", t3matches);
            n += t3matches;
        }
    }

    if (n > 0)
        return n;

    /*
     * Track-4：全字段暴力宽扫（Brute-force pointer sweep）
     *
     * 前三轨均失败时说明：ACE 使用了非标准 Callout Entry 布局（v0/v1 API、
     * 或 classifyFn/notify 均通过 stub 间接注册，所有标准偏移均无法命中）。
     *
     * 策略：以 0x50 步长遍历前 2048 个 Entry，在每个 Entry 的
     *   [+0x00, +0x08, ..., +0x78] 共 16 个 8 字节对齐槽位中，
     *   检查任意一个指针是否落在 ACE 范围。
     *   找到后将该槽位作为 classifyFn 替换目标。
     *
     * 诊断：对前 3 个已激活（slot 不全零）且任意字段非零的 Entry，
     *   打印全部 8 字节槽位内容，帮助离线分析实际偏移布局。
     */
    {
        /* Track-4 Entry 总大小：取 0x60（96B）以覆盖 v0/v1/v2 所有已知布局 */
        const ULONG T4_ENTRY_SIZE = 0x60;
        const ULONG T4_SCAN_QWORDS = T4_ENTRY_SIZE / 8; /* 12 个 8B 槽位 */

        LONG t4matches = 0;
        LONG diagPrinted = 0; /* 最多打印 3 个 Entry 的全字段诊断日志 */

        for (LONG i = 0; i < count && i < 2048; i++)
        {
            PUCHAR pEntry = pTbl + (ULONG_PTR)((ULONG64)i * T4_ENTRY_SIZE);
            if (!WfpBypass_IsValidKernelPtr(pEntry))
                continue;

            /* ---- 第一遍：全字段扫描是否命中 ACE ---- */
            BOOLEAN hit = FALSE;
            ULONG hitOffset = 0;
            PVOID hitVal = NULL;

            for (ULONG q = 0; q < T4_SCAN_QWORDS; q++)
            {
                ULONG_PTR *pSlot = (ULONG_PTR *)(pEntry + q * 8);
                if (!WfpBypass_IsValidKernelPtr(pSlot))
                    continue;

                ULONG_PTR val = 0;
                __try
                {
                    val = *pSlot;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    val = 0;
                }

                if (WfpBypass_IsValidKernelPtr((PVOID)val) && IsAddressInAceModules(val))
                {
                    hit = TRUE;
                    hitOffset = q * 8;
                    hitVal = (PVOID)val;
                    break;
                }
            }

            /* ---- 诊断：打印前 3 个"活跃"Entry 的全部字段 ---- */
            if (!hit && diagPrinted < 3)
            {
                /* 判断 Entry 是否"活跃"：至少有一个槽位是合法内核指针 */
                BOOLEAN hasKernelPtr = FALSE;
                for (ULONG q = 0; q < T4_SCAN_QWORDS; q++)
                {
                    ULONG_PTR *pSlot = (ULONG_PTR *)(pEntry + q * 8);
                    if (!WfpBypass_IsValidKernelPtr(pSlot))
                        continue;

                    ULONG_PTR val = 0;
                    __try
                    {
                        val = *pSlot;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        val = 0;
                    }
                    if (val > 0xFFFF800000000000ULL && val < 0xFFFFFF0000000000ULL && MmIsAddressValid((PVOID)val))
                    {
                        hasKernelPtr = TRUE;
                        break;
                    }
                }

                if (hasKernelPtr)
                {
                    /* 分两次打印：+0x00~+0x38 和 +0x40~+0x58 */
                    ULONG_PTR f0 = 0, f8 = 0, f10 = 0, f18 = 0, f20 = 0, f28 = 0, f30 = 0, f38 = 0;
                    ULONG_PTR f40 = 0, f48 = 0, f50 = 0, f58 = 0;
                    __try
                    {
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x00)) f0 = *(ULONG_PTR *)(pEntry + 0x00);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x08)) f8 = *(ULONG_PTR *)(pEntry + 0x08);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x10)) f10 = *(ULONG_PTR *)(pEntry + 0x10);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x18)) f18 = *(ULONG_PTR *)(pEntry + 0x18);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x20)) f20 = *(ULONG_PTR *)(pEntry + 0x20);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x28)) f28 = *(ULONG_PTR *)(pEntry + 0x28);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x30)) f30 = *(ULONG_PTR *)(pEntry + 0x30);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x38)) f38 = *(ULONG_PTR *)(pEntry + 0x38);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x40)) f40 = *(ULONG_PTR *)(pEntry + 0x40);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x48)) f48 = *(ULONG_PTR *)(pEntry + 0x48);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x50)) f50 = *(ULONG_PTR *)(pEntry + 0x50);
                        if (WfpBypass_IsValidKernelPtr(pEntry + 0x58)) f58 = *(ULONG_PTR *)(pEntry + 0x58);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                    }

                    DBG("WfpBypass W2: Track-4 DIAG Entry[%ld]@0x%p", i, (PVOID)pEntry);
                    DBG("  +00=0x%016llX +08=0x%016llX +10=0x%016llX +18=0x%016llX", (ULONG64)f0, (ULONG64)f8, (ULONG64)f10, (ULONG64)f18);
                    DBG("  +20=0x%016llX +28=0x%016llX +30=0x%016llX +38=0x%016llX", (ULONG64)f20, (ULONG64)f28, (ULONG64)f30,
                        (ULONG64)f38);
                    DBG("  +40=0x%016llX +48=0x%016llX +50=0x%016llX +58=0x%016llX", (ULONG64)f40, (ULONG64)f48, (ULONG64)f50,
                        (ULONG64)f58);
                    diagPrinted++;
                }
            }

            if (!hit)
                continue;

            /* ---- 命中：将该 ACE 指针字段作为 classifyFn 替换 ---- */
            DBG("WfpBypass W2: Track-4 MATCH Entry[%ld]@0x%p offset=+0x%X aceVal=0x%p", i, (PVOID)pEntry, hitOffset, hitVal);

            PVOID *pField = (PVOID *)(pEntry + hitOffset);
            if (!IsOurWrapper(hitVal))
            {
                if (InstallSlot(pField, hitVal))
                    t4matches++;
            }
        }

        if (t4matches > 0)
        {
            DBG("WfpBypass W2: Track-4 Brute-force replaced %ld ACE Callouts", t4matches);
            n += t4matches;
        }
        else
        {
            DBG("WfpBypass W2: Track-4 finished with 0 matches across %lu ACE modules", g_AceModuleCount);
        }
    }

    return n;
}

/* ======================================================================
 * 公开接口
 * ====================================================================== */

VOID WfpBypass::SetNetioInfo(_In_ ULONG_PTR netioBase, _In_ ULONG_PTR netioEnd, _In_ PVOID pFwpsReg2)
{
    g_NetioBase = netioBase;
    g_NetioEnd = netioEnd;
    g_FwpsReg2Addr = (ULONG_PTR)pFwpsReg2;
    DBG("WfpBypass W2: netio [0x%p-0x%p] FwpsReg2=0x%p", (PVOID)netioBase, (PVOID)netioEnd, pFwpsReg2);
}

NTSTATUS WfpBypass::Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (InterlockedCompareExchange(&g_W2Init, 1, 0) != 0)
        return STATUS_ALREADY_COMPLETE;

    g_WfpUserVar = UserVar;

    if (!g_FwpsReg2Addr || !g_NetioBase || !g_NetioEnd)
    {
        DBG("WfpBypass W2: netio info missing (base=0x%p, end=0x%p, reg2=0x%p), skipped", (PVOID)g_NetioBase, (PVOID)g_NetioEnd,
            (PVOID)g_FwpsReg2Addr);
        InterlockedExchange(&g_W2Init, 0);
        return STATUS_NOT_FOUND;
    }

    /* 严格模式：未指定或未找到目标 ACE 范围时坚决不替换任何 Callout，防止破坏系统 TCPIP/NDIS 路由造成 BSoD */
    if (!g_bAceDetected || g_AceModuleCount == 0)
    {
        DBG("WfpBypass W2: Target ACE module not found in memory, refusing to hook system callouts");
        InterlockedExchange(&g_W2Init, 0);
        return STATUS_NOT_FOUND;
    }

    /* 计算当前所有被追踪 ACE 模块的全局聚合指纹（防抖判定，涵盖所有模块数量/基址/范围/哈希变动） */
    ULONG_PTR curModulesFingerprint = (ULONG_PTR)g_AceModuleCount;
    for (ULONG i = 0; i < g_AceModuleCount && i < ACE_MAX_TRACKED_MODULES; i++)
    {
        curModulesFingerprint ^= (g_AceModules[i].Base + g_AceModules[i].End + ((ULONG_PTR)i << 12) + (ULONG_PTR)g_AceModules[i].Hash);
    }

    static ULONG_PTR s_lastKnownFingerprint = 0;
    if (g_AceFirstSeenTime.QuadPart == 0 || s_lastKnownFingerprint != curModulesFingerprint)
    {
        s_lastKnownFingerprint = curModulesFingerprint;
        KeQuerySystemTime(&g_AceFirstSeenTime);
        InterlockedExchange(&g_WfpAttemptCount, 0);
        DBG("WfpBypass W2: Detected %lu active ACE modules (fingerprint=0x%p), attempt counter reset, ready to scan",
            g_AceModuleCount, (PVOID)curModulesFingerprint);
    }

    /* 防抖等待：目标驱动刚加载时可能正在执行 DriverEntry / 建立 WFP 引擎会话，
     * 必须等待至少 3 秒，确保其彻底初始化并完成 Callout 注册后再进行扫描替换，
     * 避免与 FwpmEngineOpen0 / FwpsCalloutRegister 产生竞态导致蓝屏。
     */
    if (g_AceFirstSeenTime.QuadPart != 0)
    {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        LONGLONG elapsedMs = (now.QuadPart - g_AceFirstSeenTime.QuadPart) / 10000LL;
        /* 等待 5 秒：ACE 需要完成 FwpmEngineOpen0 -> FwpsCalloutRegister2 -> FwpmCalloutAdd0 全流程注册 */
        if (elapsedMs < 5000)
        {
            DBG("WfpBypass W2: ACE module recently loaded (%lld ms < 5000 ms), waiting for WFP Callout registration...", elapsedMs);
            InterlockedExchange(&g_W2Init, 0);
            return STATUS_DEVICE_NOT_READY;
        }
    }

    UserVar->Func.RtlZeroMemory(g_Slots, sizeof(g_Slots));
    InterlockedExchange(&g_SlotCount, 0);

    LONG count = 0;
    PVOID *pTableVar = WfpBypass_FindCalloutTable(g_FwpsReg2Addr, g_NetioBase, g_NetioEnd, &count);

    if (!pTableVar || !*pTableVar)
    {
        DBG("WfpBypass W2: Failed to locate gCalloutTable, Init failed");
        InterlockedExchange(&g_W2Init, 0);
        return STATUS_NOT_FOUND;
    }

    LONG curAttempt = InterlockedIncrement(&g_WfpAttemptCount);

#if WFP_ENABLE_CALLOUT_REPLACE
    LONG replaced = DoReplace(pTableVar, count);
    if (replaced <= 0)
    {
        /* 超过 30 次后仅每 5 次打印一条诊断日志，避免刷屏，但持续允许重试 */
        if (curAttempt <= 30 || (curAttempt % 5) == 0)
        {
            DBG("WfpBypass W2 [Attempt #%ld]: 0 ACE Callouts matched across %lu ACE modules (waiting for registration):", curAttempt,
                g_AceModuleCount);
            for (ULONG m = 0; m < g_AceModuleCount && m < ACE_MAX_TRACKED_MODULES; m++)
            {
                DBG("  -> [%lu] %ws [0x%p-0x%p]", m + 1, g_AceModules[m].Name, (PVOID)g_AceModules[m].Base, (PVOID)g_AceModules[m].End);
            }
        }
        /* 重置锁，允许下一个 WorkItem 周期继续尝试 */
        InterlockedExchange(&g_W2Init, 0);
        return STATUS_NOT_FOUND;
    }

    DBG("WfpBypass W2 [Attempt #%ld]: SUCCESS — replaced %ld ACE Callouts across %lu ACE modules", curAttempt, replaced, g_AceModuleCount);
    return STATUS_SUCCESS;
#else
    /* 【仅检测模式】只探测是否存在属于 ACE 的 WFP 回调，不修改任何内核系统内存 */
    LONG detected = DoReplace(pTableVar, count);
    if (detected <= 0)
    {
        if (curAttempt <= 30 || (curAttempt % 5) == 0)
        {
            DBG("WfpBypass W2 [DETECT Attempt #%ld]: 0 ACE Callouts found across %lu ACE modules, scanning targets:", curAttempt,
                g_AceModuleCount);
            for (ULONG m = 0; m < g_AceModuleCount && m < ACE_MAX_TRACKED_MODULES; m++)
            {
                DBG("  -> [%lu] %ws [0x%p-0x%p]", m + 1, g_AceModules[m].Name, (PVOID)g_AceModules[m].Base, (PVOID)g_AceModules[m].End);
            }
        }
        InterlockedExchange(&g_W2Init, 0);
        return STATUS_NOT_FOUND;
    }

    DBG("WfpBypass W2 [DETECT Attempt #%ld]: SUCCESS — FOUND %ld ACE Callouts across %lu ACE modules! (Replace skipped by macro)",
        curAttempt, detected, g_AceModuleCount);
    for (ULONG m = 0; m < g_AceModuleCount && m < ACE_MAX_TRACKED_MODULES; m++)
    {
        DBG("  -> Active Target: [%lu] %ws [0x%p-0x%p]", m + 1, g_AceModules[m].Name, (PVOID)g_AceModules[m].Base,
            (PVOID)g_AceModules[m].End);
    }
    /* 仅检测模式下重置锁，允许后台工作项继续周期性心跳探测 */
    InterlockedExchange(&g_W2Init, 0);
    return STATUS_SUCCESS;
#endif
}

VOID WfpBypass::Cleanup(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (InterlockedCompareExchange(&g_W2Init, 0, 1) != 1)
        return;

    LONG cnt = g_SlotCount;
    for (LONG i = 0; i < cnt && i < WFP_MAX_ACE_CALLOUTS; i++)
    {
        if (!g_Slots[i].bUsed || !g_Slots[i].pClassifyFnField || !g_Slots[i].origClassifyFn)
            continue;
        InterlockedExchangePointer(g_Slots[i].pClassifyFnField, (PVOID)g_Slots[i].origClassifyFn);
        _mm_sfence();
        DBG("WfpBypass W2: Restored Callout[%ld] origFn=0x%p", i, (PVOID)g_Slots[i].origClassifyFn);
    }

    UserVar->Func.RtlZeroMemory(g_Slots, sizeof(g_Slots));
    InterlockedExchange(&g_SlotCount, 0);
    g_WfpUserVar = NULL;
    DBG("WfpBypass W2: Cleanup completed");
}

VOID WfpBypass::SetHiddenLocalPort(_In_ USHORT portHostOrder)
{
    USHORT netPort = (USHORT)(((portHostOrder & 0xFF) << 8) | ((portHostOrder >> 8) & 0xFF));
    InterlockedExchange(&g_HiddenPort, (LONG)netPort);
    DBG("WfpBypass W2: Hidden port updated -> Host=%u Net=0x%04X", portHostOrder, netPort);
}

BOOLEAN WfpBypass::IsInstalled(VOID) { return (g_W2Init != 0 && g_SlotCount > 0); }

VOID WfpBypass::ResetState(VOID)
{
    InterlockedExchange(&g_W2Init, 0);
    InterlockedExchange(&g_SlotCount, 0);
    InterlockedExchange(&g_WfpAttemptCount, 0);
    for (LONG i = 0; i < WFP_MAX_ACE_CALLOUTS; i++)
    {
        if (!g_Slots[i].bUsed || !g_Slots[i].pClassifyFnField || !g_Slots[i].origClassifyFn)
            continue;
        if (WfpBypass_IsValidKernelPtr(g_Slots[i].pClassifyFnField) &&
            WfpBypass_IsValidKernelPtr((PVOID)g_Slots[i].origClassifyFn))
        {
            InterlockedCompareExchangePointer(g_Slots[i].pClassifyFnField, (PVOID)g_Slots[i].origClassifyFn,
                                              (PVOID)g_ClassifyWrappers[i]);
            _mm_sfence();
        }
    }
    RtlZeroMemory(g_Slots, sizeof(g_Slots));
    g_AceFirstSeenTime.QuadPart = 0;
    DBG("WfpBypass W2: State reset for next ACE launch/reload");
}

USHORT WfpBypass::GetHiddenLocalPort(VOID)
{
    USHORT netPort = (USHORT)g_HiddenPort;
    return (USHORT)((netPort >> 8) | (netPort << 8));
}

ULONG WfpBypass::VerifyAndRepairSlots(_Out_opt_ PWFP_ALARM_DETAIL pOutAlarm)
{
    if (pOutAlarm)
        RtlZeroMemory(pOutAlarm, sizeof(WFP_ALARM_DETAIL));

    if (g_W2Init == 0 || g_SlotCount <= 0)
        return 0;

    ULONG revertCount = 0;
    LONG cnt = g_SlotCount;

    for (LONG i = 0; i < cnt && i < WFP_MAX_ACE_CALLOUTS; i++)
    {
        if (!g_Slots[i].bUsed || !g_Slots[i].pClassifyFnField || !g_Slots[i].origClassifyFn)
            continue;

        if (!WfpBypass_IsValidKernelPtr(g_Slots[i].pClassifyFnField))
            continue;

        PVOID curFn = NULL;
        __try
        {
            curFn = *g_Slots[i].pClassifyFnField;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            curFn = NULL;
        }

        if (!WfpBypass_IsValidKernelPtr(curFn))
            continue;

        // 如果字段值不再是对应槽位的 Wrapper，说明被 ACE 后台看门狗恢复了
        if (curFn != (PVOID)g_ClassifyWrappers[i])
        {
            revertCount++;

            if (pOutAlarm && revertCount == 1)
            {
                pOutAlarm->SlotIndex = (ULONG)i;
                pOutAlarm->pClassifyField = g_Slots[i].pClassifyFnField;
                pOutAlarm->ClassifyFn = (ULONG_PTR)g_Slots[i].origClassifyFn;
                pOutAlarm->IsReverted = TRUE;
                ResolveAceModuleInfo(pOutAlarm->ClassifyFn, pOutAlarm->ModuleName, &pOutAlarm->ModuleBase, &pOutAlarm->Rva);
            }

            // 原子重挂钩（CAS 强行夺回接管权）
            PVOID old = InterlockedCompareExchangePointer(g_Slots[i].pClassifyFnField, (PVOID)g_ClassifyWrappers[i], curFn);
            _mm_sfence();
            DBG("WfpBypass W2: Slot[%ld] REVERTED by ACE (cur=0x%p, orig=0x%p) -> repaired (CAS result=0x%p)", i, curFn,
                (PVOID)g_Slots[i].origClassifyFn, old);
        }
    }

    return revertCount;
}

