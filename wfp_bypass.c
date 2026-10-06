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

#include "wfp_bypass.h"
#include "MachenikeString.h"
#include "Utils.h"

/* ======================================================================
 * 常量
 * ====================================================================== */

#define WFP_POOL_TAG             'tNeN'
#define WFP_MAX_ACE_CALLOUTS     16
#define WFP_CALLOUT_ENTRY_SIZE   0x40
#define WFP_CLASSIFY_FN_OFFSET   0x18
#define WFP_SCAN_FUNC_BYTES      512
#define WFP_MAX_CALLOUT_COUNT    512

/* ======================================================================
 * 内部类型
 * ====================================================================== */

typedef VOID (NTAPI *FWPS_CALLOUT_CLASSIFY_FN2)(
    _In_        const void *inFixedValues,
    _In_        const void *inMetaValues,
    _Inout_opt_ void       *layerData,
    _In_opt_    const void *classifyContext,
    _In_        const void *filter,
    _In_        UINT64      flowContext,
    _Inout_     void       *classifyOut);


typedef struct _ACE_CALLOUT_SLOT {
    BOOLEAN                   bUsed;
    PVOID                    *pClassifyFnField;
    FWPS_CALLOUT_CLASSIFY_FN2 origClassifyFn;
} ACE_CALLOUT_SLOT;

/* ======================================================================
 * WFP 固定值解析辅助（提取端口）
 * ====================================================================== */

#define FWP_TYPE_UINT16 2
#define WFP_DEFAULT_TARGET_PORT 10001

typedef struct _WFP_VALUE_MINI {
    UINT32 type;
    UINT32 padding;
    union {
        UINT16 uint16;
        UINT32 uint32;
        UINT64 uint64;
    } u;
} WFP_VALUE_MINI;

typedef struct _WFP_INCOMING_VALUE_MINI {
    WFP_VALUE_MINI value;
} WFP_INCOMING_VALUE_MINI;

typedef struct _WFP_INCOMING_VALUES_MINI {
    UINT16 layerId;
    UINT32 incomingValuesCount;
    const WFP_INCOMING_VALUE_MINI *incomingValue;
} WFP_INCOMING_VALUES_MINI;

/* ======================================================================
 * 全局状态
 * ====================================================================== */

static volatile LONG            g_W2Init          = 0;
static MACHENIKE_KERNEL_INTERFACE *g_WfpUserVar   = NULL;
/* 默认初始化为 10001 端口（网络字节序 0x1127） */
static USHORT                   g_HiddenPort      = (USHORT)(((WFP_DEFAULT_TARGET_PORT & 0xFF) << 8) | ((WFP_DEFAULT_TARGET_PORT >> 8) & 0xFF));

static ULONG_PTR                g_NetioBase        = 0;
static ULONG_PTR                g_NetioEnd         = 0;
static ULONG_PTR                g_FwpsReg2Addr     = 0;

static ULONG_PTR                g_AceBase          = 0;
static ULONG_PTR                g_AceEnd           = 0;

static ACE_CALLOUT_SLOT         g_Slots[WFP_MAX_ACE_CALLOUTS];
static volatile LONG            g_SlotCount        = 0;

typedef struct _FWPS_CLASSIFY_OUT_MINI {
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
static BOOLEAN WfpBypass_IsTargetPort(_In_opt_ const void *inFixedValues)
{
    if (!inFixedValues) return FALSE;

    USHORT targetPortNet  = g_HiddenPort;
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
 * WfpBypass_ClassifyCommon
 * 在 DISPATCH_LEVEL 执行，不可阻塞，不可分配内存。
 * ====================================================================== */

static VOID NTAPI WfpBypass_ClassifyCommon(
    _In_        LONG        slotIndex,
    _In_        const void *inFixedValues,
    _In_        const void *inMetaValues,
    _Inout_opt_ void       *layerData,
    _In_opt_    const void *classifyContext,
    _In_        const void *filter,
    _In_        UINT64      flowContext,
    _Inout_     void       *classifyOut)
{
    /* 核心拦截：对命中目标隐藏端口（10001 / g_HiddenPort）的流量进行彻底隐藏与放行 */
    if (WfpBypass_IsTargetPort(inFixedValues))
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
            origFn(inFixedValues, inMetaValues, layerData,
                   classifyContext, filter, flowContext, classifyOut);
        }
    }
}

#define DEFINE_CLASSIFY_WRAPPER(N) \
static VOID NTAPI WfpBypass_ClassifyWrapper_##N( \
    _In_        const void *inFixedValues, \
    _In_        const void *inMetaValues, \
    _Inout_opt_ void       *layerData, \
    _In_opt_    const void *classifyContext, \
    _In_        const void *filter, \
    _In_        UINT64      flowContext, \
    _Inout_     void       *classifyOut) \
{ \
    WfpBypass_ClassifyCommon(N, inFixedValues, inMetaValues, layerData, \
                            classifyContext, filter, flowContext, classifyOut); \
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
    WfpBypass_ClassifyWrapper_0,  WfpBypass_ClassifyWrapper_1,
    WfpBypass_ClassifyWrapper_2,  WfpBypass_ClassifyWrapper_3,
    WfpBypass_ClassifyWrapper_4,  WfpBypass_ClassifyWrapper_5,
    WfpBypass_ClassifyWrapper_6,  WfpBypass_ClassifyWrapper_7,
    WfpBypass_ClassifyWrapper_8,  WfpBypass_ClassifyWrapper_9,
    WfpBypass_ClassifyWrapper_10, WfpBypass_ClassifyWrapper_11,
    WfpBypass_ClassifyWrapper_12, WfpBypass_ClassifyWrapper_13,
    WfpBypass_ClassifyWrapper_14, WfpBypass_ClassifyWrapper_15
};

static BOOLEAN WfpBypass_IsOurWrapper(PVOID pFn)
{
    if (!pFn) return FALSE;
    for (LONG i = 0; i < WFP_MAX_ACE_CALLOUTS; i++)
    {
        if (pFn == (PVOID)g_ClassifyWrappers[i])
            return TRUE;
    }
    return FALSE;
}

/* ======================================================================
 * 内部：从 FwpsCalloutRegister2 函数体扫描 RIP 相对引用
 * 定位 gCalloutTable（PVOID* 类型的全局变量）
 * ====================================================================== */

static PVOID *WfpBypass_FindCalloutTable(
    _In_  ULONG_PTR funcAddr,
    _In_  ULONG_PTR netioBase,
    _In_  ULONG_PTR netioEnd,
    _Out_ LONG      *pCount)
{
    *pCount = 0;
    if (!funcAddr || netioBase >= netioEnd) return NULL;

    const UCHAR *p    = (const UCHAR *)funcAddr;
    const UCHAR *pEnd = p + WFP_SCAN_FUNC_BYTES;

    PVOID *pTable = NULL;
    LONG  *pCnt   = NULL;

    for (; p + 7 <= pEnd; p++)
    {
        INT32  disp = 0;
        ULONG  ilen = 0;

        if (p[0]==0x48 && p[1]==0x8B && (p[2]&0xC7)==0x05)
        { disp=*(const INT32*)(p+3); ilen=7; }
        else if (p[0]==0x48 && p[1]==0x8D && (p[2]&0xC7)==0x05)
        { disp=*(const INT32*)(p+3); ilen=7; }
        else if (p[0]==0x8B && p[1]==0x05)
        { disp=*(const INT32*)(p+2); ilen=6; }
        else if (p[0]==0x8B && p[1]==0x0D)
        { disp=*(const INT32*)(p+2); ilen=6; }
        else continue;

        ULONG_PTR rip    = (ULONG_PTR)(p + ilen);
        ULONG_PTR target = rip + (ULONG_PTR)(LONG_PTR)disp;

        if (target < netioBase || target + 8 > netioEnd) continue;

        ULONG_PTR ptrVal = *(ULONG_PTR *)target;
        UINT32    u32Val = *(UINT32    *)target;

        if (!pTable && (target & 7) == 0 && ptrVal > 0xFFFF800000000000ULL
            && (ptrVal < netioBase || ptrVal >= netioEnd))
        {
            ULONG_PTR pEngine = ptrVal;
            ULONG_PTR subTable = 0;
            ULONG subCount = 0;

            __try {
                subTable = *(ULONG_PTR *)(pEngine + 0x198);
                subCount = *(ULONG *)(pEngine + 0x190);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                subTable = 0;
                subCount = 0;
            }

            MachenikePrint("WfpBypass W2: Inspecting target=0x%p pEngine=0x%p subTable=0x%p subCount=%u",
                           (PVOID)target, (PVOID)pEngine, (PVOID)subTable, subCount);

            if (subTable > 0xFFFF800000000000ULL)
            {
                pTable = (PVOID *)(pEngine + 0x198);
                *pCount = (subCount >= 1 && subCount <= 65536) ? (LONG)subCount : 2048;
                MachenikePrint("WfpBypass W2: EngineContext CalloutTable @ 0x%p -> 0x%p count=%ld",
                               (PVOID)pTable, (PVOID)subTable, *pCount);
                return pTable;
            }

            pTable = (PVOID *)target;
        }

        if (!pCnt && (target & 3) == 0
            && u32Val >= 1 && u32Val <= 65536)
        {
            pCnt = (LONG *)target;
        }

        if (pTable && pCnt) break;
    }

    if (!pTable)
    {
        MachenikePrint("WfpBypass W2: gCalloutTable not found");
        return NULL;
    }

    *pCount = pCnt ? *pCnt : 2048;
    MachenikePrint("WfpBypass W2: gCalloutTable @ 0x%p -> 0x%p count=%ld",
                   (PVOID)pTable, *pTable, *pCount);
    return pTable;
}

static BOOLEAN WfpBypass_InstallSlot(PVOID *pField, PVOID cur)
{
    LONG idx = InterlockedIncrement(&g_SlotCount) - 1;
    if (idx >= WFP_MAX_ACE_CALLOUTS)
    {
        InterlockedDecrement(&g_SlotCount);
        MachenikePrint("WfpBypass W2: Slots full, stopped");
        return FALSE;
    }

    g_Slots[idx].bUsed            = TRUE;
    g_Slots[idx].pClassifyFnField  = pField;
    g_Slots[idx].origClassifyFn    = (FWPS_CALLOUT_CLASSIFY_FN2)cur;

    InterlockedExchangePointer(pField, (PVOID)g_ClassifyWrappers[idx]);
    _mm_sfence();

    MachenikePrint("WfpBypass W2: Callout 0x%p -> wrapper[%ld]", cur, idx);
    return TRUE;
}

static LONG WfpBypass_DoReplace(
    _In_ PVOID  *pTableVar,
    _In_ LONG    count,
    _In_ ULONG_PTR aceBase,
    _In_ ULONG_PTR aceEnd)
{
    if (!pTableVar || !*pTableVar || count <= 0) return 0;

    PUCHAR pTbl = (PUCHAR)*pTableVar;

    // 自适应解引用：若 pTbl 是 pEngine 结构体自身，取其 +0x198 处的真实 CalloutTable 堆数组
    __try {
        ULONG_PTR sub = *(ULONG_PTR *)(pTbl + 0x198);
        if (sub > 0xFFFF800000000000ULL && sub != (ULONG_PTR)pTbl)
        {
            MachenikePrint("WfpBypass W2: Auto-dereferencing pEngine+0x198: 0x%p -> 0x%p", (PVOID)pTbl, (PVOID)sub);
            pTbl = (PUCHAR)sub;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    LONG n = 0;
    ULONG entrySizes[] = { 0x50, 0x40 };
    ULONG fnOffsets[]   = { 0x10, 0x18, 0x28, 0x30, 0x38 };

    // 模式 1：扁平结构体数组扫描（Win10/11 原生 0x50 / 0x40 字节）
    for (ULONG s = 0; s < 2; s++)
    {
        ULONG entrySize = entrySizes[s];
        for (LONG i = 0; i < count && i < 2048; i++)
        {
            PUCHAR pEntry = pTbl + (i * entrySize);
            for (ULONG f = 0; f < 5; f++)
            {
                PVOID *pField = (PVOID *)(pEntry + fnOffsets[f]);
                PVOID cur = NULL;
                __try { cur = *pField; } __except (EXCEPTION_EXECUTE_HANDLER) { cur = NULL; }
                if (!cur || WfpBypass_IsOurWrapper(cur)) continue;

                ULONG_PTR fn = (ULONG_PTR)cur;
                if (fn >= aceBase && fn < aceEnd)
                {
                    if (!WfpBypass_InstallSlot(pField, cur))
                        return n;
                    n++;
                    break;
                }
            }
        }
        if (n > 0) return n;
    }

    // 模式 2：指针数组扫描（每个元素为独立 Callout 对象的内核指针）
    PVOID *pPtrArray = (PVOID *)pTbl;
    for (LONG i = 0; i < count && i < 2048; i++)
    {
        PVOID pObj = NULL;
        __try { pObj = pPtrArray[i]; } __except (EXCEPTION_EXECUTE_HANDLER) { pObj = NULL; }
        if (!pObj || (ULONG_PTR)pObj <= 0xFFFF800000000000ULL) continue;

        PUCHAR pEntry = (PUCHAR)pObj;
        for (ULONG f = 0; f < 5; f++)
        {
            PVOID *pField = (PVOID *)(pEntry + fnOffsets[f]);
            PVOID cur = NULL;
            __try { cur = *pField; } __except (EXCEPTION_EXECUTE_HANDLER) { cur = NULL; }
            if (!cur || WfpBypass_IsOurWrapper(cur)) continue;

            ULONG_PTR fn = (ULONG_PTR)cur;
            if (fn >= aceBase && fn < aceEnd)
            {
                if (!WfpBypass_InstallSlot(pField, cur))
                    return n;
                n++;
                break;
            }
        }
    }

    return n;
}

/* ======================================================================
 * 公开接口
 * ====================================================================== */

VOID WfpBypass_SetNetioInfo(
    _In_ ULONG_PTR netioBase,
    _In_ ULONG_PTR netioEnd,
    _In_ PVOID     pFwpsReg2)
{
    g_NetioBase    = netioBase;
    g_NetioEnd     = netioEnd;
    g_FwpsReg2Addr = (ULONG_PTR)pFwpsReg2;
    MachenikePrint("WfpBypass W2: netio [0x%p-0x%p] FwpsReg2=0x%p",
                   (PVOID)netioBase, (PVOID)netioEnd, pFwpsReg2);
}

VOID WfpBypass_SetAceInfo(
    _In_ ULONG_PTR aceBase,
    _In_ ULONG_PTR aceEnd)
{
    g_AceBase = aceBase;
    g_AceEnd  = aceEnd;
    MachenikePrint("WfpBypass W2: ACE [0x%p-0x%p]",
                   (PVOID)aceBase, (PVOID)aceEnd);
}

NTSTATUS WfpBypass_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (InterlockedCompareExchange(&g_W2Init, 1, 0) != 0)
        return STATUS_ALREADY_COMPLETE;

    g_WfpUserVar = UserVar;

    if (!g_FwpsReg2Addr || !g_NetioBase || !g_NetioEnd)
    {
        MachenikePrint("WfpBypass W2: netio info missing (base=0x%p, end=0x%p, reg2=0x%p), skipped",
                       (PVOID)g_NetioBase, (PVOID)g_NetioEnd, (PVOID)g_FwpsReg2Addr);
        InterlockedExchange(&g_W2Init, 0);
        return STATUS_NOT_FOUND;
    }

    /* 严格模式：未指定或未找到目标 ACE 范围时坚决不替换任何 Callout，防止破坏系统 TCPIP/NDIS 路由造成 BSoD */
    if (!g_AceBase || !g_AceEnd || g_AceBase >= g_AceEnd)
    {
        MachenikePrint("WfpBypass W2: Target ACE module not found in memory, refusing to hook system callouts");
        InterlockedExchange(&g_W2Init, 0);
        return STATUS_NOT_FOUND;
    }

    UserVar->Func.RtlZeroMemory(g_Slots, sizeof(g_Slots));
    InterlockedExchange(&g_SlotCount, 0);

    LONG count = 0;
    PVOID *pTableVar = WfpBypass_FindCalloutTable(
        g_FwpsReg2Addr, g_NetioBase, g_NetioEnd, &count);

    if (!pTableVar || !*pTableVar)
    {
        MachenikePrint("WfpBypass W2: Failed to locate gCalloutTable, Init failed");
        InterlockedExchange(&g_W2Init, 0);
        return STATUS_NOT_FOUND;
    }

    LONG replaced = WfpBypass_DoReplace(pTableVar, count, g_AceBase, g_AceEnd);
    UNREFERENCED_PARAMETER(replaced);
    MachenikePrint("WfpBypass W2: Init completed, replaced %ld ACE Callouts", replaced);
    return STATUS_SUCCESS;
}

VOID WfpBypass_Cleanup(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (InterlockedCompareExchange(&g_W2Init, 0, 1) != 1) return;

    LONG cnt = g_SlotCount;
    for (LONG i = 0; i < cnt && i < WFP_MAX_ACE_CALLOUTS; i++)
    {
        if (!g_Slots[i].bUsed || !g_Slots[i].pClassifyFnField || !g_Slots[i].origClassifyFn)
            continue;
        InterlockedExchangePointer(
            g_Slots[i].pClassifyFnField,
            (PVOID)g_Slots[i].origClassifyFn);
        _mm_sfence();
        MachenikePrint("WfpBypass W2: Restored Callout[%ld] origFn=0x%p",
                       i, (PVOID)g_Slots[i].origClassifyFn);
    }

    UserVar->Func.RtlZeroMemory(g_Slots, sizeof(g_Slots));
    InterlockedExchange(&g_SlotCount, 0);
    g_WfpUserVar = NULL;
    MachenikePrint("WfpBypass W2: Cleanup completed");
}

VOID WfpBypass_SetHiddenLocalPort(_In_ USHORT portHostOrder)
{
    g_HiddenPort = (USHORT)((portHostOrder >> 8) | (portHostOrder << 8));
    MachenikePrint("WfpBypass W2: Hidden port = %u", portHostOrder);
}


BOOLEAN WfpBypass_IsInstalled(VOID)
{
    return (g_W2Init != 0 && g_SlotCount > 0);
}

USHORT WfpBypass_GetHiddenLocalPort(VOID)
{
    return (USHORT)((g_HiddenPort >> 8) | (g_HiddenPort << 8));
}
