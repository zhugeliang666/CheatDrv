// ============================================================================
// miniport_direct.cpp  —  方案 B 实现：NDIS 底层直连 / 过滤器链接管
//
// 关键事实（全部来自 ndis.pdb + ndis.sys 反汇编，勿凭记忆修改）：
//   * _NDIS_COMMON_OPEN_BLOCK.MiniportHandle @ +0x10
//       —— ndis!NdisSendNetBufferLists 首条指令即 mov rsi,[rcx+10h]
//   * _NDIS_MINIPORT_BLOCK.DriverHandle  @ +0xEB0 → _NDIS_M_DRIVER_BLOCK
//     _NDIS_M_DRIVER_BLOCK.MiniportDriverCharacteristics @ +0x70
//       → SendNetBufferListsHandler @ chars+0x48 / ReturnNetBufferListsHandler @ +0x50
//   * _NDIS_MINIPORT_BLOCK.NoFilter  (_NDIS_MINIPORT_HANDLERS) @ +0x8F8
//     _NDIS_MINIPORT_BLOCK.Next      (_NDIS_MINIPORT_HANDLERS) @ +0x9B0
//       —— NdisMIndicateReceiveNetBufferLists 反汇编：从 [mp+0x9B0+0x90] 取指示
//          处理器、[mp+0x9C0] 取 Context、[mp+0x9D0] 取 Object 交给迭代转发器
//       —— 老路径另有 [mp+0x858] TopIndicateNetBufferListsHandler 槽位，一并接管
//
// 因此"接收挂接"= 改写两个 8 字节数据槽位（不碰代码页，HVCI/VBS 相容），
// "发送直连"= 直接调用 Miniport 的 SendNetBufferListsHandler，完成路径由
// NBL->SourceHandle（指向本协议 OpenBlock）让 NDIS 直接回调协议完成例程。
// ============================================================================
#include "Common.h"
#include "FrameWork.h"
#include "Struct.h"
#include "Utils.h"
#include "NdisOffsets.h"
#include "miniport_direct.h"
#include "ExceptionReporter.h"

// 消除 ndis.lib 与内核静态导入，全部例程改由 g_pGlobalUserVar 动态解算 (Zero-IAT)
#ifdef MmIsAddressValid
#undef MmIsAddressValid
#endif
#define MmIsAddressValid(va) \
    ((g_pGlobalUserVar && g_pGlobalUserVar->Func.MmIsAddressValid) ? (g_pGlobalUserVar->Func.MmIsAddressValid)((PVOID)(va)) : FALSE)

#ifdef RtlGetVersion
#undef RtlGetVersion
#endif
#define RtlGetVersion(vi) \
    ((g_pGlobalUserVar && g_pGlobalUserVar->Func.RtlGetVersion) ? (g_pGlobalUserVar->Func.RtlGetVersion)(vi) : STATUS_UNSUCCESSFUL)

#ifdef NdisGetDataBuffer
#undef NdisGetDataBuffer
#endif
#define NdisGetDataBuffer(NetBuffer, BytesNeeded, Storage, AlignMultiple, AlignOffset) \
    ((g_pGlobalUserVar && g_pGlobalUserVar->Ndis.NdisGetDataBuffer) ? (g_pGlobalUserVar->Ndis.NdisGetDataBuffer)(NetBuffer, BytesNeeded, Storage, AlignMultiple, AlignOffset) : NULL)

#define MK_DM_POOL_TAG     'DmkM'
#define MK_DM_MAX_ADAPTERS 16

// NBL 完成路由：NDIS 依据 NBL->SourceHandle 找到发起该发送的 OpenBlock。
// 直连发送时把它指向本协议 OpenBlock，即可复用 EthProtocolSendNetBufferListsComplete。
#ifndef MK_DM_SEND_MAGIC
#define MK_DM_SEND_MAGIC 0x53444D4B // 'KMDS'
#endif

typedef VOID (*PFN_MK_MINIPORT_SEND_NBL)(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists,
                                         NDIS_PORT_NUMBER PortNumber, ULONG SendFlags);
typedef VOID (*PFN_MK_MINIPORT_RETURN_NBL)(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists,
                                           ULONG ReturnFlags);
typedef VOID (*PFN_MK_INDICATE_NBL)(PVOID Context, PNET_BUFFER_LIST NetBufferLists, NDIS_PORT_NUMBER PortNumber,
                                    ULONG NumberOfNetBufferLists, ULONG ReceiveFlags);
typedef VOID (*PFN_MK_SEND_COMPLETE_NBL)(PVOID Context, PNET_BUFFER_LIST NetBufferLists, ULONG SendCompleteFlags);

typedef struct _MK_DM_ADAPTER_SLOT
{
    volatile BOOLEAN fUsed;
    volatile BOOLEAN fArmed;
    PVOID pBinding;                // PMK_ETH_ADAPTER_BINDING
    PVOID Open;                    // 本协议 _NDIS_OPEN_BLOCK
    PVOID Mp;                      // _NDIS_MINIPORT_BLOCK
    PVOID SendHandler;             // 直连发送函数
    PVOID SendContext;             // 与之配套的 context
    PVOID ReturnHandler;           // 截留后归还 NBL 用
    PVOID ReturnContext;
    PVOID SavedChainIndicate;      // [mp+Next+Indicate]
    PVOID SavedChainIndicateCtx;   // [mp+Next+IndicateContext]
    PVOID SavedTopIndicate;        // [mp+TopIndicate]
    PVOID BlackoutIndicate;        // [mp+NoFilter+Indicate]
    PVOID BlackoutIndicateCtx;     // [mp+NoFilter+IndicateContext]
    PVOID SavedChainSendComplete;    // [mp+Next+SendComplete]
    PVOID SavedChainSendCompleteCtx; // [mp+Next+SendCompleteContext]
    PVOID NoFilterSendComplete;      // [mp+NoFilter+SendComplete]
    PVOID NoFilterSendCompleteCtx;   // [mp+NoFilter+SendCompleteContext]
    ULONG_PTR DriverStart;
    ULONG DriverSize;
    ULONG FilterCount;
    ULONG MediaType;
    ULONG IfIndex;
    ULONG TxHandlerRva;
} MK_DM_ADAPTER_SLOT, *PMK_DM_ADAPTER_SLOT;

typedef struct _MK_DM_STATE
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;

    volatile BOOLEAN fInited;
    volatile BOOLEAN fReady;          // 至少一张目标网卡 + 发送处理器已解析
    volatile BOOLEAN fArmed;          // 至少一张网卡接收槽位已接管
    volatile BOOLEAN fLayoutTrusted;  // 偏移表通过运行时验证
    volatile LONG InFlight;           // 节流器在途计数（卸载排空用）
    volatile LONG RxMode;
    PVOID volatile CurrentRxBinding;  // 当前正在执行 RX 截留回调的网卡绑定对象

    KSPIN_LOCK Lock;
    MK_NDIS_LAYOUT L;
    ULONG BuildNumber;
    ULONG_PTR NdisBase;
    ULONG_PTR NdisEnd;

    ULONG PrimarySlotIdx;
    MK_DM_ADAPTER_SLOT Slots[MK_DM_MAX_ADAPTERS];

    PFN_MK_DM_RX_SINK pSink;
    MK_DM_STATS Stats;
} MK_DM_STATE;

static MK_DM_STATE g_Dm;

// 致命回调与"只报一次"闸门独立存放：MkDm_Init 会整体清零 g_Dm，
// 而回调必须在 Init 之前就注册好（Init 失败本身也要能上报）
static PFN_MK_DM_FATAL g_pFatalHandler = NULL;
static volatile BOOLEAN g_fFatalReported = FALSE;

// ---------------------------------------------------------------------------
// 基础判定
// ---------------------------------------------------------------------------
static __forceinline BOOLEAN MkDmIsKernelPtr(_In_opt_ const VOID *p)
{
    ULONG_PTR v = (ULONG_PTR)p;
    return (v >= 0xFFFF800000000000ULL) && MmIsAddressValid((PVOID)v);
}

static __forceinline BOOLEAN MkDmIsAlignedPtr(_In_opt_ const VOID *p)
{
    ULONG_PTR v = (ULONG_PTR)p;
    return (v >= 0xFFFF800000000000ULL) && ((v & 0x7) == 0) && MmIsAddressValid((PVOID)v);
}

static __forceinline BOOLEAN MkDmInRange(_In_ const VOID *p, _In_ ULONG_PTR base, _In_ ULONG size)
{
    ULONG_PTR v = (ULONG_PTR)p;
    return (v >= base) && (v < base + (ULONG_PTR)size);
}

static __forceinline PVOID MkDmAt(_In_ PVOID base, _In_ ULONG off)
{
    return *(PVOID *)((PUCHAR)base + off);
}

static __forceinline ULONG MkDmU32(_In_ PVOID base, _In_ ULONG off)
{
    return *(ULONG *)((PUCHAR)base + off);
}

static __forceinline VOID MkDmStatInc(_In_ volatile LONG *pCounter)
{
    InterlockedIncrement(pCounter);
}

/*
 * 致命失败上报：本通道没有标准发送兜底。
 * 任何一处校验/接管/发送失败都意味着通道不可用，必须"提示失败 + 自动卸载"，
 * 绝不允许在半失效状态下继续运行（否则要么静默漏包，要么把包送进过滤器链）。
 */
static VOID MkDmReportFatal(_In_ ULONG Reason, _In_ NTSTATUS Status)
{
    if (InterlockedExchange8((volatile CHAR *)&g_fFatalReported, TRUE))
    {
        return;
    }

    MkDmStatInc(&g_Dm.Stats.Fatal);
    DBG("[x] DirectMiniport FATAL: reason=%u status=0x%08X (no standard-send fallback, unload requested)", Reason,
        Status);
    ExceptionReporter::ReportFormat("MkDmReportFatal", Status,
                                    "DirectMiniport fatal error: reason=%u status=0x%08X (build=%u)",
                                    Reason, Status, g_Dm.BuildNumber);

    PFN_MK_DM_FATAL pfn = g_pFatalHandler;
    if (pfn != NULL)
    {
        pfn(Reason, Status);
    }
}

// ---------------------------------------------------------------------------
// 布局选择 + 跨版本机器码动态自举 (Win10 1507 ~ Win11 24H2/25H2 全兼容)
// ---------------------------------------------------------------------------
static VOID MkDmSelectLayout(VOID)
{
    RTL_OSVERSIONINFOW vi = {0};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (NT_SUCCESS(RtlGetVersion(&vi)))
    {
        g_Dm.BuildNumber = vi.dwBuildNumber;
    }
    else
    {
        g_Dm.BuildNumber = 19041;
    }

    MK_NDIS_LAYOUT l19041 = MK_NDIS_LAYOUT_19041;
    g_Dm.L = l19041;
}

/*
 * 从 ndis!NdisMIndicateReceiveNetBufferLists 与 ndis!NdisSendNetBufferLists
 * 入口机器码动态提取当前内核精确的 Mp_ChainNode 与 Mp_NoFilterNode 偏移：
 *   1) NdisMIndicateReceiveNetBufferLists 连续读取 [reg + ChainNode + 0x90]、
 *      [reg + ChainNode + 0x10]、[reg + ChainNode + 0x20]
 *   2) NdisSendNetBufferLists 连续读取 [reg + ChainNode + 0xA8]、[reg + ChainNode + 0x48]
 */
static BOOLEAN MkDmCalibrateFromNdisCode(VOID)
{
    const PUCHAR pIndFn = (g_pGlobalUserVar && g_pGlobalUserVar->Ndis.NdisMIndicateReceiveNetBufferLists)
                              ? (const PUCHAR)g_pGlobalUserVar->Ndis.NdisMIndicateReceiveNetBufferLists
                              : NULL;
    const PUCHAR pSendFn = (g_pGlobalUserVar && g_pGlobalUserVar->Ndis.NdisSendNetBufferLists)
                               ? (const PUCHAR)g_pGlobalUserVar->Ndis.NdisSendNetBufferLists
                               : NULL;
    ULONG dispCandidates[64];
    ULONG candCount = 0;

    if (MkDmIsKernelPtr(pIndFn))
    {
        for (ULONG i = 0; i + 7 <= 384 && candCount < ARRAYSIZE(dispCandidates); ++i)
        {
            if (!MmIsAddressValid((PVOID)(pIndFn + i + 6)))
            {
                break;
            }
            UCHAR b0 = pIndFn[i];
            UCHAR b1 = pIndFn[i + 1];
            UCHAR b2 = pIndFn[i + 2];
            if ((b0 == 0x48 || b0 == 0x4C) && b1 == 0x8B && (b2 & 0xC0) == 0x80 && (b2 & 0x07) != 0x04)
            {
                ULONG disp = *(const ULONG *)(pIndFn + i + 3);
                if (disp >= 0x400 && disp <= 0x2000 && (disp & 0x7) == 0)
                {
                    dispCandidates[candCount++] = disp;
                }
            }
        }

        for (ULONG a = 0; a < candCount; ++a)
        {
            ULONG dIndH = dispCandidates[a];
            if (dIndH <= (MK_DM_NODE_INDICATE_H + MK_DM_NODE_SIZE))
            {
                continue;
            }
            ULONG candChain = dIndH - MK_DM_NODE_INDICATE_H;
            BOOLEAN bHasCtx = FALSE;
            BOOLEAN bHasObj = FALSE;
            for (ULONG b = 0; b < candCount; ++b)
            {
                if (dispCandidates[b] == candChain + MK_DM_NODE_INDICATE_CTX)
                {
                    bHasCtx = TRUE;
                }
                else if (dispCandidates[b] == candChain + MK_DM_NODE_INDICATE_OBJECT)
                {
                    bHasObj = TRUE;
                }
            }
            if (bHasCtx && bHasObj)
            {
                g_Dm.L.Mp_ChainNode = candChain;
                g_Dm.L.Mp_NoFilterNode = candChain - MK_DM_NODE_SIZE;
                if (candChain != 0x9B0)
                {
                    g_Dm.L.Mp_TopIndicate = 0;
                }
                DBG("[+] DirectMiniport: Code-calibrated Mp_ChainNode=0x%X Mp_NoFilterNode=0x%X (from IndicateNBL)",
                    g_Dm.L.Mp_ChainNode, g_Dm.L.Mp_NoFilterNode);
                return TRUE;
            }
        }
    }

    candCount = 0;
    if (MkDmIsKernelPtr(pSendFn))
    {
        for (ULONG i = 0; i + 7 <= 512 && candCount < ARRAYSIZE(dispCandidates); ++i)
        {
            if (!MmIsAddressValid((PVOID)(pSendFn + i + 6)))
            {
                break;
            }
            UCHAR b0 = pSendFn[i];
            UCHAR b1 = pSendFn[i + 1];
            UCHAR b2 = pSendFn[i + 2];
            if ((b0 == 0x48 || b0 == 0x4C) && b1 == 0x8B && (b2 & 0xC0) == 0x80 && (b2 & 0x07) != 0x04)
            {
                ULONG disp = *(const ULONG *)(pSendFn + i + 3);
                if (disp >= 0x400 && disp <= 0x2000 && (disp & 0x7) == 0)
                {
                    dispCandidates[candCount++] = disp;
                }
            }
        }

        for (ULONG a = 0; a < candCount; ++a)
        {
            ULONG dSendH = dispCandidates[a];
            if (dSendH <= (MK_DM_NODE_SEND_H + MK_DM_NODE_SIZE))
            {
                continue;
            }
            ULONG candChain = dSendH - MK_DM_NODE_SEND_H;
            for (ULONG b = 0; b < candCount; ++b)
            {
                if (dispCandidates[b] == candChain + MK_DM_NODE_SEND_CTX)
                {
                    g_Dm.L.Mp_ChainNode = candChain;
                    g_Dm.L.Mp_NoFilterNode = candChain - MK_DM_NODE_SIZE;
                    if (candChain != 0x9B0)
                    {
                        g_Dm.L.Mp_TopIndicate = 0;
                    }
                    DBG("[+] DirectMiniport: Code-calibrated Mp_ChainNode=0x%X Mp_NoFilterNode=0x%X (from SendNBL)",
                        g_Dm.L.Mp_ChainNode, g_Dm.L.Mp_NoFilterNode);
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

// ---------------------------------------------------------------------------
// ndis.sys 映像范围（用于偏移/指针合法性校验）
// 注意：MmGetSystemRoutineAddress 仅支持解析 ntoskrnl/hal，不能解析 ndis.sys！
// 因此这里直接使用已静态链接的 &NdisMIndicateReceiveNetBufferLists 结合 PsLoadedModuleList
// 与 PE 头回溯定位 ndis.sys 范围。
// ---------------------------------------------------------------------------
static NTSTATUS MkDmResolveNdisRange(VOID)
{
    ULONG_PTR exportHint = (g_pGlobalUserVar && g_pGlobalUserVar->Ndis.NdisMIndicateReceiveNetBufferLists)
                               ? (ULONG_PTR)g_pGlobalUserVar->Ndis.NdisMIndicateReceiveNetBufferLists
                               : 0;

    if (g_pPersistentModuleListAnchor && g_pPersistentModuleListAnchor->InLoadOrderLinks.Flink)
    {
        for (PLIST_ENTRY pLink = g_pPersistentModuleListAnchor->InLoadOrderLinks.Flink;
             pLink && pLink != &g_pPersistentModuleListAnchor->InLoadOrderLinks;
             pLink = pLink->Flink)
        {
            PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pLink, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (!pEntry || !pEntry->DllBase)
            {
                break;
            }
            ULONG_PTR base = (ULONG_PTR)pEntry->DllBase;
            ULONG size = pEntry->SizeOfImage;
            if (base == 0 || size == 0)
            {
                continue;
            }

            BOOLEAN bMatchAddr = (exportHint >= base && exportHint < base + (ULONG_PTR)size);
            BOOLEAN bMatchName = FALSE;
            if (!bMatchAddr && pEntry->BaseDllName.Buffer)
            {
                ULONG cch = pEntry->BaseDllName.Length / sizeof(WCHAR);
                if ((cch == 8 && SafeWcsnicmp(pEntry->BaseDllName.Buffer, L"ndis.sys", 8) == 0) ||
                    (cch == 4 && SafeWcsnicmp(pEntry->BaseDllName.Buffer, L"ndis", 4) == 0))
                {
                    bMatchName = TRUE;
                }
            }

            if (bMatchAddr || bMatchName)
            {
                g_Dm.NdisBase = base;
                g_Dm.NdisEnd = base + (ULONG_PTR)size;
                DBG("[+] DirectMiniport: ndis.sys located via module list [0x%p, 0x%p)",
                    (PVOID)g_Dm.NdisBase, (PVOID)g_Dm.NdisEnd);
                return STATUS_SUCCESS;
            }
        }
    }

    // 兜底：直接从 NdisMIndicateReceiveNetBufferLists 所在内核页向低地址回溯 MZ/PE 头
    if (MkDmIsKernelPtr((PVOID)exportHint))
    {
        ULONG_PTR page = exportHint & ~0xFFFULL;
        for (ULONG step = 0; step < 512; ++step, page -= 0x1000)
        {
            if (!MmIsAddressValid((PVOID)page))
            {
                break;
            }
            if (*(USHORT *)page == 0x5A4D) // 'MZ'
            {
                LONG lfanew = *(LONG *)(page + 0x3C);
                if (lfanew > 0 && lfanew < 0x800 && MmIsAddressValid((PVOID)(page + lfanew)))
                {
                    if (*(ULONG *)(page + lfanew) == 0x00004550) // 'PE\0\0'
                    {
                        ULONG sizeOfImage = *(ULONG *)(page + lfanew + 0x50);
                        if (sizeOfImage >= 0x10000 && sizeOfImage <= 0x2000000 &&
                            exportHint < page + (ULONG_PTR)sizeOfImage)
                        {
                            g_Dm.NdisBase = page;
                            g_Dm.NdisEnd = page + (ULONG_PTR)sizeOfImage;
                            DBG("[+] DirectMiniport: ndis.sys located via PE header scan [0x%p, 0x%p)",
                                (PVOID)g_Dm.NdisBase, (PVOID)g_Dm.NdisEnd);
                            return STATUS_SUCCESS;
                        }
                    }
                }
            }
        }
    }

    ExceptionReporter::ReportFormat("MkDmResolveNdisRange", STATUS_NOT_FOUND,
                                    "Failed to resolve ndis.sys image range (exportHint=0x%p, build=%u)",
                                    (PVOID)exportHint, g_Dm.BuildNumber);
    return STATUS_NOT_FOUND;
}

// ---------------------------------------------------------------------------
// 目标 Miniport 解析：OpenBlock → MiniportBlock → 驱动块 → 处理器
// ---------------------------------------------------------------------------
static NTSTATUS MkDmResolveTarget(_In_ PVOID pBinding, _In_ PVOID Open, _Out_ PMK_DM_ADAPTER_SLOT pOutSlot)
{
    const MK_NDIS_LAYOUT &L = g_Dm.L;
    RtlZeroMemory(pOutSlot, sizeof(*pOutSlot));

    if (!MkDmIsAlignedPtr(Open))
    {
        ExceptionReporter::ReportFormat("MkDmResolveTarget", STATUS_INVALID_PARAMETER,
                                        "Invalid or unaligned OpenBlock pointer: 0x%p", Open);
        return STATUS_INVALID_PARAMETER;
    }

    // 1) OpenBlock → MiniportBlock
    PVOID mp = MkDmAt(Open, L.Open_MiniportHandle);
    if (!MkDmIsAlignedPtr(mp))
    {
        DBG("[-] DirectMiniport: open+0x%X -> MiniportBlock invalid (0x%p)", L.Open_MiniportHandle, mp);
        ExceptionReporter::ReportFormat("MkDmResolveTarget", STATUS_INVALID_ADDRESS,
                                        "Open+0x%X -> MiniportBlock invalid (open=0x%p, mp=0x%p)",
                                        L.Open_MiniportHandle, Open, mp);
        MkDmStatInc(&g_Dm.Stats.VerifyFail);
        return STATUS_INVALID_ADDRESS;
    }

    // NDIS_OBJECT_HEADER 粗校验：Type 非 0、Size 落在合理区间、Revision <= 8
    UCHAR hdrType = *(PUCHAR)mp;
    UCHAR hdrRev = *(PUCHAR)((PUCHAR)mp + 1);
    USHORT hdrSize = *(USHORT *)((PUCHAR)mp + 2);
    if (hdrType == 0 || hdrRev == 0 || hdrRev > 8 || hdrSize < 0x400 || hdrSize > 0x3000)
    {
        DBG("[-] DirectMiniport: MiniportBlock header sanity failed (Type=%u Rev=%u Size=0x%X)", hdrType, hdrRev,
            hdrSize);
        ExceptionReporter::ReportFormat("MkDmResolveTarget", STATUS_REVISION_MISMATCH,
                                        "MiniportBlock header sanity failed (mp=0x%p, Type=%u, Rev=%u, Size=0x%X, build=%u)",
                                        mp, (ULONG)hdrType, (ULONG)hdrRev, (ULONG)hdrSize, g_Dm.BuildNumber);
        MkDmStatInc(&g_Dm.Stats.VerifyFail);
        return STATUS_REVISION_MISMATCH;
    }

    // 2) MiniportBlock → 驱动块 → DRIVER_OBJECT（静态偏移快径 + 跨版本结构特征动态搜索）
    PVOID drvBlk = NULL;
    PDRIVER_OBJECT drvObj = NULL;
    ULONG candDrvOff = L.Mp_DriverHandle;
    if (candDrvOff + sizeof(PVOID) <= hdrSize)
    {
        PVOID tryBlk = MkDmAt(mp, candDrvOff);
        if (MkDmIsAlignedPtr(tryBlk))
        {
            PDRIVER_OBJECT tryObj = (PDRIVER_OBJECT)MkDmAt(tryBlk, L.Mdrv_DriverObject);
            if (MkDmIsAlignedPtr(tryObj) && tryObj->Type == 4 &&
                tryObj->DriverStart != NULL && tryObj->DriverSize >= 0x1000)
            {
                drvBlk = tryBlk;
                drvObj = tryObj;
            }
        }
    }

    if (!drvBlk || !drvObj)
    {
        ULONG ndisSpan = (ULONG)(g_Dm.NdisEnd - g_Dm.NdisBase);
        ULONG scanMax = (hdrSize > 0x1800) ? 0x1800 : hdrSize;
        for (ULONG off = 0x400; off + sizeof(PVOID) <= scanMax; off += sizeof(PVOID))
        {
            if (!MmIsAddressValid((PUCHAR)mp + off))
            {
                continue;
            }
            PVOID tryBlk = MkDmAt(mp, off);
            if (!MkDmIsAlignedPtr(tryBlk) || !MmIsAddressValid((PUCHAR)tryBlk + L.Mdrv_Characteristics + MK_DM_CHARS_RETURN_NBL))
            {
                continue;
            }
            PDRIVER_OBJECT tryObj = (PDRIVER_OBJECT)MkDmAt(tryBlk, L.Mdrv_DriverObject);
            if (!MkDmIsAlignedPtr(tryObj) || tryObj->Type != 4 ||
                tryObj->DriverStart == NULL || tryObj->DriverSize < 0x1000)
            {
                continue;
            }
            PVOID trySendH = MkDmAt((PUCHAR)tryBlk + L.Mdrv_Characteristics, MK_DM_CHARS_SEND_NBL);
            // 兼容传统 Miniport 与 NetAdapterCx 类扩展网卡（SendNetBufferListsHandler 可能位于 NetAdapterCx.sys）
            if (MkDmIsKernelPtr(trySendH) &&
                (MkDmInRange(trySendH, (ULONG_PTR)tryObj->DriverStart, tryObj->DriverSize) ||
                 !MkDmInRange(trySendH, g_Dm.NdisBase, ndisSpan)))
            {
                drvBlk = tryBlk;
                drvObj = tryObj;
                g_Dm.L.Mp_DriverHandle = off;
                DBG("[+] DirectMiniport: Auto-discovered Mp_DriverHandle=0x%X", off);
                break;
            }
        }
    }

    if (!drvBlk || !drvObj)
    {
        ExceptionReporter::ReportFormat("MkDmResolveTarget", STATUS_INVALID_ADDRESS,
                                        "Failed to resolve MiniportDriverBlock/DriverObject (mp=0x%p, hdrSize=0x%X, build=%u)",
                                        mp, (ULONG)hdrSize, g_Dm.BuildNumber);
        MkDmStatInc(&g_Dm.Stats.VerifyFail);
        return STATUS_INVALID_ADDRESS;
    }

    ULONG_PTR drvStart = (ULONG_PTR)drvObj->DriverStart;
    ULONG drvSize = drvObj->DriverSize;
    ULONG media = 0; // 外层 EthProtocolBindAdapterEx 已通过 BindParameters->MediaType 严格校验 NdisMedium802_3

    // 3) 校验并动态校准 Mp_NoFilterNode / Mp_ChainNode（若机器码特征未命中则执行双节点同构扫描）
    PVOID chars = (PUCHAR)drvBlk + L.Mdrv_Characteristics;
    PVOID hChars = MkDmAt(chars, MK_DM_CHARS_SEND_NBL);
    PVOID adapterCtx = MkDmAt(mp, L.Mp_AdapterContext);

    ULONG noFilterOff = g_Dm.L.Mp_NoFilterNode;
    ULONG chainOff = g_Dm.L.Mp_ChainNode;
    ULONG ndisSize = (ULONG)(g_Dm.NdisEnd - g_Dm.NdisBase);

    BOOLEAN bNodesValid = FALSE;
    if (chainOff + MK_DM_NODE_SIZE <= hdrSize &&
        MmIsAddressValid((PUCHAR)mp + noFilterOff + MK_DM_NODE_SEND_H) &&
        MmIsAddressValid((PUCHAR)mp + chainOff + MK_DM_NODE_SEND_H))
    {
        PVOID tryNoFltInd = MkDmAt(mp, noFilterOff + MK_DM_NODE_INDICATE_H);
        PVOID tryChainInd = MkDmAt(mp, chainOff + MK_DM_NODE_INDICATE_H);
        PVOID tryNoFltSend = MkDmAt(mp, noFilterOff + MK_DM_NODE_SEND_H);
        if (MkDmIsKernelPtr(tryNoFltInd) && MkDmIsKernelPtr(tryChainInd) && MkDmIsKernelPtr(tryNoFltSend) &&
            MkDmInRange(tryNoFltInd, g_Dm.NdisBase, ndisSize))
        {
            bNodesValid = TRUE;
        }
    }

    if (!bNodesValid)
    {
        ULONG scanMax = (hdrSize > 0x1600) ? 0x1600 : hdrSize;
        for (ULONG off = 0x400; off + 2 * MK_DM_NODE_SIZE <= scanMax; off += sizeof(PVOID))
        {
            if (!MmIsAddressValid((PUCHAR)mp + off + 2 * MK_DM_NODE_SIZE - sizeof(PVOID)))
            {
                continue;
            }
            PVOID candIndA = MkDmAt(mp, off + MK_DM_NODE_INDICATE_H);
            PVOID candIndB = MkDmAt(mp, off + MK_DM_NODE_SIZE + MK_DM_NODE_INDICATE_H);
            PVOID candSendA = MkDmAt(mp, off + MK_DM_NODE_SEND_H);
            PVOID candSendCtxA = MkDmAt(mp, off + MK_DM_NODE_SEND_CTX);
            if (MkDmIsKernelPtr(candIndA) && MkDmInRange(candIndA, g_Dm.NdisBase, ndisSize) &&
                MkDmIsKernelPtr(candIndB) &&
                MkDmIsKernelPtr(candSendA) &&
                (candSendA == hChars || MkDmInRange(candSendA, drvStart, drvSize) || !MkDmInRange(candSendA, g_Dm.NdisBase, ndisSize)) &&
                (candSendCtxA == adapterCtx || candSendCtxA == mp))
            {
                noFilterOff = off;
                chainOff = off + MK_DM_NODE_SIZE;
                g_Dm.L.Mp_NoFilterNode = noFilterOff;
                g_Dm.L.Mp_ChainNode = chainOff;
                if (chainOff != 0x9B0)
                {
                    g_Dm.L.Mp_TopIndicate = 0;
                }
                bNodesValid = TRUE;
                DBG("[+] DirectMiniport: Dual-node scan calibrated Mp_NoFilterNode=0x%X Mp_ChainNode=0x%X",
                    noFilterOff, chainOff);
                break;
            }
        }
    }

    PVOID hNode = MkDmAt(mp, noFilterOff + MK_DM_NODE_SEND_H);
    PVOID cNode = MkDmAt(mp, noFilterOff + MK_DM_NODE_SEND_CTX);

    // 兼容传统 Miniport 与 NetAdapterCx（如 Realtek 2.5GbE rtcx21x64.sys / Intel I225-V NetAdapterCx.sys）
    BOOLEAN okChars = MkDmIsKernelPtr(hChars) &&
                      (MkDmInRange(hChars, drvStart, drvSize) || hChars == hNode || !MkDmInRange(hChars, g_Dm.NdisBase, ndisSize));
    BOOLEAN okNode = MkDmIsKernelPtr(hNode) &&
                     (MkDmInRange(hNode, drvStart, drvSize) || hNode == hChars ||
                      (!MkDmInRange(hNode, g_Dm.NdisBase, ndisSize) && (cNode == adapterCtx || cNode == mp)));

    if (!okChars && !okNode)
    {
        DBG("[-] DirectMiniport: no valid SendNetBufferListsHandler (chars=0x%p node=0x%p drv=[0x%p,0x%p))",
            hChars, hNode, (PVOID)drvStart, (PVOID)(drvStart + drvSize));
        ExceptionReporter::ReportFormat("MkDmResolveTarget", STATUS_NOT_FOUND,
                                        "No valid SendNetBufferListsHandler (chars=0x%p, node=0x%p, drv=[0x%p,0x%p), build=%u)",
                                        hChars, hNode, (PVOID)drvStart, (PVOID)(drvStart + drvSize), g_Dm.BuildNumber);
        MkDmStatInc(&g_Dm.Stats.VerifyFail);
        return STATUS_NOT_FOUND;
    }

    // 归还路径（截留帧必需）：优先 NoFilter 节点的 Return，其次驱动登记表
    PVOID hRetNode = MkDmAt(mp, L.Mp_NoFilterNode + MK_DM_NODE_RETURN_H);
    PVOID cRetNode = MkDmAt(mp, L.Mp_NoFilterNode + MK_DM_NODE_RETURN_CTX);
    PVOID hRetChars = MkDmAt(chars, MK_DM_CHARS_RETURN_NBL);
    PVOID hRet = NULL, cRet = NULL;
    if (MkDmIsKernelPtr(hRetNode) && (MkDmInRange(hRetNode, drvStart, drvSize) || hRetNode == hRetChars))
    {
        hRet = hRetNode;
        cRet = cRetNode;
    }
    else if (MkDmIsKernelPtr(hRetChars))
    {
        hRet = hRetChars;
        cRet = adapterCtx;
    }

    // 4) 接收与发送完成槽位快照
    PVOID savedChain = MkDmAt(mp, g_Dm.L.Mp_ChainNode + MK_DM_NODE_INDICATE_H);
    PVOID savedChainCtx = MkDmAt(mp, g_Dm.L.Mp_ChainNode + MK_DM_NODE_INDICATE_CTX);
    PVOID savedTop = (g_Dm.L.Mp_TopIndicate != 0) ? MkDmAt(mp, g_Dm.L.Mp_TopIndicate) : NULL;
    PVOID blackoutH = MkDmAt(mp, g_Dm.L.Mp_NoFilterNode + MK_DM_NODE_INDICATE_H);
    PVOID blackoutCtx = MkDmAt(mp, g_Dm.L.Mp_NoFilterNode + MK_DM_NODE_INDICATE_CTX);
    PVOID savedSendComp = MkDmAt(mp, g_Dm.L.Mp_ChainNode + MK_DM_NODE_SEND_COMPLETE_H);
    PVOID savedSendCompCtx = MkDmAt(mp, g_Dm.L.Mp_ChainNode + MK_DM_NODE_SEND_COMPLETE_CTX);
    PVOID noFltSendComp = MkDmAt(mp, g_Dm.L.Mp_NoFilterNode + MK_DM_NODE_SEND_COMPLETE_H);
    PVOID noFltSendCompCtx = MkDmAt(mp, g_Dm.L.Mp_NoFilterNode + MK_DM_NODE_SEND_COMPLETE_CTX);

    // 5) 过滤器链长度（仅当 LowestFilter 有效时统计）
    ULONG filterCount = 0;
    if (g_Dm.L.Mp_ChainNode == 0x9B0 && g_Dm.L.Mp_LowestFilter + sizeof(PVOID) <= hdrSize)
    {
        PVOID flt = MkDmAt(mp, g_Dm.L.Mp_LowestFilter);
        for (ULONG i = 0; i < 64 && MkDmIsAlignedPtr(flt); ++i)
        {
            filterCount++;
            flt = MkDmAt(flt, g_Dm.L.Flt_NextFilter);
        }
    }

    pOutSlot->fUsed = TRUE;
    pOutSlot->fArmed = FALSE;
    pOutSlot->pBinding = pBinding;
    pOutSlot->Open = Open;
    pOutSlot->Mp = mp;
    pOutSlot->SendHandler = okNode ? hNode : hChars;
    pOutSlot->SendContext = okNode ? cNode : adapterCtx;
    pOutSlot->ReturnHandler = hRet;
    pOutSlot->ReturnContext = cRet;
    pOutSlot->SavedChainIndicate = savedChain;
    pOutSlot->SavedChainIndicateCtx = savedChainCtx;
    pOutSlot->SavedTopIndicate = savedTop;
    pOutSlot->BlackoutIndicate = blackoutH;
    pOutSlot->BlackoutIndicateCtx = blackoutCtx;
    pOutSlot->SavedChainSendComplete = savedSendComp;
    pOutSlot->SavedChainSendCompleteCtx = savedSendCompCtx;
    pOutSlot->NoFilterSendComplete = noFltSendComp;
    pOutSlot->NoFilterSendCompleteCtx = noFltSendCompCtx;
    pOutSlot->DriverStart = drvStart;
    pOutSlot->DriverSize = drvSize;
    pOutSlot->FilterCount = filterCount;
    pOutSlot->MediaType = media;
    pOutSlot->IfIndex = MkDmU32(mp, L.Mp_IfIndex);
    pOutSlot->TxHandlerRva = ((ULONG_PTR)pOutSlot->SendHandler >= drvStart)
                                 ? (ULONG)((ULONG_PTR)pOutSlot->SendHandler - drvStart)
                                 : 0;

    DBG("[+] DirectMiniport: mp=0x%p drv=[0x%p+0x%X) send=+0x%X ctx=0x%p filters=%u ifIndex=%u",
        mp, (PVOID)drvStart, drvSize, pOutSlot->TxHandlerRva, pOutSlot->SendContext, filterCount, pOutSlot->IfIndex);
    DBG("[*] DirectMiniport: chars=0x%p node=0x%p ret=0x%p chain=0x%p top=0x%p",
        hChars, hNode, hRet, savedChain, savedTop);

    return STATUS_SUCCESS;
}

static __forceinline PMK_DM_ADAPTER_SLOT MkDmFindSlotByContext(_In_opt_ PVOID Context)
{
    for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
    {
        PMK_DM_ADAPTER_SLOT s = &g_Dm.Slots[i];
        if (s->fUsed && (s->SavedChainIndicateCtx == Context || s->SavedChainSendCompleteCtx == Context ||
                         s->Mp == Context || s->BlackoutIndicateCtx == Context || s->NoFilterSendCompleteCtx == Context))
        {
            return s;
        }
    }
    for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
    {
        if (g_Dm.Slots[i].fUsed)
        {
            return &g_Dm.Slots[i];
        }
    }
    return NULL;
}

static __forceinline PMK_DM_ADAPTER_SLOT MkDmFindSlotByOpen(_In_opt_ PVOID Open)
{
    if (Open != NULL)
    {
        for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
        {
            if (g_Dm.Slots[i].fUsed && g_Dm.Slots[i].Open == Open)
            {
                return &g_Dm.Slots[i];
            }
        }
    }
    if (g_Dm.PrimarySlotIdx < MK_DM_MAX_ADAPTERS && g_Dm.Slots[g_Dm.PrimarySlotIdx].fUsed)
    {
        return &g_Dm.Slots[g_Dm.PrimarySlotIdx];
    }
    for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
    {
        if (g_Dm.Slots[i].fUsed)
        {
            return &g_Dm.Slots[i];
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// 接收节流器：链头槽位（迭代路径）
// ---------------------------------------------------------------------------
static VOID MkDmReturnToMiniport(_In_ PMK_DM_ADAPTER_SLOT pSlot, _In_ PNET_BUFFER_LIST Head, _In_ ULONG Flags)
{
    if (!pSlot || !Head || !MkDmIsKernelPtr(pSlot->ReturnHandler))
    {
        return;
    }
    ((PFN_MK_MINIPORT_RETURN_NBL)pSlot->ReturnHandler)((NDIS_HANDLE)pSlot->ReturnContext, Head, Flags);
    MkDmStatInc(&g_Dm.Stats.RxReturned);
}

// 遍历 NBL 链：签名帧被 sink 认领后从链上摘除，其余保留
static VOID MkDmSplit(_In_ PMK_DM_ADAPTER_SLOT pSlot, _In_ PNET_BUFFER_LIST NetBufferLists, _In_ ULONG ReceiveFlags,
                      _Out_ PNET_BUFFER_LIST *pKeepHead, _Out_ ULONG *pKeepCount, _Out_ PNET_BUFFER_LIST *pStolen)
{
    PNET_BUFFER_LIST keepHead = NULL, keepTail = NULL, stolenHead = NULL, stolenTail = NULL;
    ULONG keepCount = 0;
    BOOLEAN bResources = (ReceiveFlags & NDIS_RECEIVE_FLAGS_RESOURCES) ? TRUE : FALSE;
    PFN_MK_DM_RX_SINK sink = g_Dm.pSink;

    PVOID prevBinding = InterlockedExchangePointer(&g_Dm.CurrentRxBinding, pSlot ? pSlot->pBinding : NULL);

    for (PNET_BUFFER_LIST nbl = NetBufferLists; nbl != NULL;)
    {
        PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(nbl);
        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

        BOOLEAN consumed = FALSE;
        if (sink != NULL)
        {
            PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            if (nb != NULL && NET_BUFFER_NEXT_NB(nb) == NULL)
            {
                ULONG len = NET_BUFFER_DATA_LENGTH(nb);
                if (len >= 14 && len <= 9216)
                {
                    UCHAR bounce[1600];
                    PUCHAR p = (PUCHAR)NdisGetDataBuffer(nb, len, NULL, 1, 0);
                    if (p == NULL && len <= sizeof(bounce))
                    {
                        p = (PUCHAR)NdisGetDataBuffer(nb, len, bounce, 1, 0);
                    }
                    if (p != NULL && sink(p, len))
                    {
                        consumed = TRUE;
                    }
                }
            }
        }

        if (consumed)
        {
            if (stolenTail)
            {
                NET_BUFFER_LIST_NEXT_NBL(stolenTail) = nbl;
            }
            else
            {
                stolenHead = nbl;
            }
            stolenTail = nbl;
            MkDmStatInc(&g_Dm.Stats.RxStolen);
        }
        else
        {
            if (keepTail)
            {
                NET_BUFFER_LIST_NEXT_NBL(keepTail) = nbl;
            }
            else
            {
                keepHead = nbl;
            }
            keepTail = nbl;
            keepCount++;
        }

        nbl = next;
    }

    InterlockedExchangePointer(&g_Dm.CurrentRxBinding, prevBinding);

    // RESOURCES 语义：NBL 所有权仍属 Miniport，NDIS 返回后即回收 —— 截留帧不得归还
    if (stolenHead && bResources)
    {
        stolenHead = NULL;
    }
    else if (stolenHead)
    {
        ULONG retFlags = 0;
        if (ReceiveFlags & NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL)
        {
            NDIS_SET_RETURN_FLAG(retFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
        }
        MkDmReturnToMiniport(pSlot, stolenHead, retFlags);
        stolenHead = NULL;
    }

    *pKeepHead = keepHead;
    *pKeepCount = keepCount;
    *pStolen = stolenHead;
}

// 迭代数据通路链头（[mp+Next+IndicateNetBufferListsHandler]）
static VOID MkDmChainThunk(_In_ PVOID Context, _In_ PNET_BUFFER_LIST NetBufferLists, _In_ NDIS_PORT_NUMBER PortNumber,
                           _In_ ULONG NumberOfNetBufferLists, _In_ ULONG ReceiveFlags)
{
    InterlockedIncrement(&g_Dm.InFlight);
    MkDmStatInc(&g_Dm.Stats.RxIndicated);

    PMK_DM_ADAPTER_SLOT pSlot = MkDmFindSlotByContext(Context);
    if (!pSlot)
    {
        InterlockedDecrement(&g_Dm.InFlight);
        return;
    }

    if (pSlot->fArmed == FALSE || NetBufferLists == NULL)
    {
        if (MkDmIsKernelPtr(pSlot->SavedChainIndicate))
        {
            ((PFN_MK_INDICATE_NBL)pSlot->SavedChainIndicate)(pSlot->SavedChainIndicateCtx, NetBufferLists, PortNumber,
                                                             NumberOfNetBufferLists, ReceiveFlags);
        }
        InterlockedDecrement(&g_Dm.InFlight);
        return;
    }

    MK_DM_RX_MODE mode = (MK_DM_RX_MODE)g_Dm.RxMode;
    if (mode == MK_DM_RX_BLACKOUT && MkDmIsKernelPtr(pSlot->BlackoutIndicate))
    {
        MkDmStatInc(&g_Dm.Stats.RxPassThrough);
        ((PFN_MK_INDICATE_NBL)pSlot->BlackoutIndicate)(pSlot->BlackoutIndicateCtx, NetBufferLists, PortNumber,
                                                       NumberOfNetBufferLists, ReceiveFlags);
        InterlockedDecrement(&g_Dm.InFlight);
        return;
    }

    PNET_BUFFER_LIST keepHead = NULL, stolen = NULL;
    ULONG keepCount = 0;
    MkDmSplit(pSlot, NetBufferLists, ReceiveFlags, &keepHead, &keepCount, &stolen);
    UNREFERENCED_PARAMETER(stolen);

    if (keepHead != NULL && MkDmIsKernelPtr(pSlot->SavedChainIndicate))
    {
        MkDmStatInc(&g_Dm.Stats.RxPassThrough);
        ((PFN_MK_INDICATE_NBL)pSlot->SavedChainIndicate)(pSlot->SavedChainIndicateCtx, keepHead, PortNumber, keepCount,
                                                         ReceiveFlags);
    }

    InterlockedDecrement(&g_Dm.InFlight);
}

// 老链头槽位（[mp+TopIndicateNetBufferListsHandler]）
static VOID MkDmTopThunk(_In_ PVOID Context, _In_ PNET_BUFFER_LIST NetBufferLists, _In_ NDIS_PORT_NUMBER PortNumber,
                         _In_ ULONG NumberOfNetBufferLists, _In_ ULONG ReceiveFlags)
{
    InterlockedIncrement(&g_Dm.InFlight);
    MkDmStatInc(&g_Dm.Stats.RxIndicated);

    PMK_DM_ADAPTER_SLOT pSlot = MkDmFindSlotByContext(Context);
    if (!pSlot)
    {
        InterlockedDecrement(&g_Dm.InFlight);
        return;
    }

    if (pSlot->fArmed == FALSE || NetBufferLists == NULL)
    {
        if (MkDmIsKernelPtr(pSlot->SavedTopIndicate))
        {
            ((PFN_MK_INDICATE_NBL)pSlot->SavedTopIndicate)(Context, NetBufferLists, PortNumber, NumberOfNetBufferLists,
                                                           ReceiveFlags);
        }
        InterlockedDecrement(&g_Dm.InFlight);
        return;
    }

    MK_DM_RX_MODE mode = (MK_DM_RX_MODE)g_Dm.RxMode;
    if (mode == MK_DM_RX_BLACKOUT && MkDmIsKernelPtr(pSlot->BlackoutIndicate))
    {
        MkDmStatInc(&g_Dm.Stats.RxPassThrough);
        ((PFN_MK_INDICATE_NBL)pSlot->BlackoutIndicate)(pSlot->BlackoutIndicateCtx, NetBufferLists, PortNumber,
                                                       NumberOfNetBufferLists, ReceiveFlags);
        InterlockedDecrement(&g_Dm.InFlight);
        return;
    }

    PNET_BUFFER_LIST keepHead = NULL, stolen = NULL;
    ULONG keepCount = 0;
    MkDmSplit(pSlot, NetBufferLists, ReceiveFlags, &keepHead, &keepCount, &stolen);
    UNREFERENCED_PARAMETER(stolen);

    if (keepHead != NULL && MkDmIsKernelPtr(pSlot->SavedTopIndicate))
    {
        MkDmStatInc(&g_Dm.Stats.RxPassThrough);
        ((PFN_MK_INDICATE_NBL)pSlot->SavedTopIndicate)(Context, keepHead, PortNumber, keepCount, ReceiveFlags);
    }

    InterlockedDecrement(&g_Dm.InFlight);
}

// 发送完成节流器（[mp+Next+SendNetBufferListsCompleteHandler]）：
// 直连发送（MkDm_Send）绕过了 wfplwf 等 LWF 的 FilterSendNetBufferListsHandler（未递增其 In-Flight 计数），
// 因此当底层 Miniport 调用 NdisMSendNetBufferListsComplete 时，必须在链头拦截属于本协议 OpenBlock 的 NBL，
// 直接经由 NoFilterSendComplete（ndisMSendCompleteNetBufferListsInternal）归还本协议，
// 严禁流入 wfplwf!FilterSendNetBufferListsCompleteHandler 导致其 [FilterModuleContext+0x148] 计数下溢而卡死卸载。
static VOID MkDmSendCompleteThunk(_In_ PVOID Context, _In_ PNET_BUFFER_LIST NetBufferLists, _In_ ULONG SendCompleteFlags)
{
    InterlockedIncrement(&g_Dm.InFlight);

    PMK_DM_ADAPTER_SLOT pCtxSlot = MkDmFindSlotByContext(Context);
    PNET_BUFFER_LIST keepHead = NULL, keepTail = NULL;
    PNET_BUFFER_LIST myHead = NULL, myTail = NULL;
    PMK_DM_ADAPTER_SLOT pMySlot = pCtxSlot;

    for (PNET_BUFFER_LIST nbl = NetBufferLists; nbl != NULL;)
    {
        PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(nbl);
        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

        PMK_DM_ADAPTER_SLOT pMatchSlot = NULL;
        PVOID srcOpen = nbl->SourceHandle;
        if (srcOpen != NULL)
        {
            for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
            {
                if (g_Dm.Slots[i].fUsed && g_Dm.Slots[i].Open == srcOpen)
                {
                    pMatchSlot = &g_Dm.Slots[i];
                    break;
                }
            }
        }

        if (pMatchSlot != NULL)
        {
            pMySlot = pMatchSlot;
            if (myTail)
            {
                NET_BUFFER_LIST_NEXT_NBL(myTail) = nbl;
            }
            else
            {
                myHead = nbl;
            }
            myTail = nbl;
        }
        else
        {
            if (keepTail)
            {
                NET_BUFFER_LIST_NEXT_NBL(keepTail) = nbl;
            }
            else
            {
                keepHead = nbl;
            }
            keepTail = nbl;
        }

        nbl = next;
    }

    if (myHead != NULL && pMySlot != NULL && MkDmIsKernelPtr(pMySlot->NoFilterSendComplete))
    {
        ((PFN_MK_SEND_COMPLETE_NBL)pMySlot->NoFilterSendComplete)(pMySlot->NoFilterSendCompleteCtx, myHead,
                                                                  SendCompleteFlags);
    }

    if (keepHead != NULL && pCtxSlot != NULL && MkDmIsKernelPtr(pCtxSlot->SavedChainSendComplete))
    {
        ((PFN_MK_SEND_COMPLETE_NBL)pCtxSlot->SavedChainSendComplete)(pCtxSlot->SavedChainSendCompleteCtx, keepHead,
                                                                     SendCompleteFlags);
    }

    InterlockedDecrement(&g_Dm.InFlight);
}

// ---------------------------------------------------------------------------
// 槽位接管 / 回滚
// ---------------------------------------------------------------------------
static BOOLEAN MkDmArmSlotLocked(_Inout_ PMK_DM_ADAPTER_SLOT pSlot)
{
    if (!pSlot || !pSlot->fUsed || pSlot->Mp == NULL)
    {
        return FALSE;
    }
    const MK_NDIS_LAYOUT &L = g_Dm.L;
    PVOID *pChain = (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_ChainNode + MK_DM_NODE_INDICATE_H);
    PVOID *pTop = (L.Mp_TopIndicate != 0) ? (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_TopIndicate) : NULL;
    PVOID *pSendComp = (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_ChainNode + MK_DM_NODE_SEND_COMPLETE_H);

    if (MkDmIsKernelPtr(*(PVOID *)pChain) && *(PVOID *)pChain != (PVOID)MkDmChainThunk)
    {
        pSlot->SavedChainIndicate = *(PVOID *)pChain;
        InterlockedExchangePointer((PVOID volatile *)pChain, (PVOID)MkDmChainThunk);
    }
    if (pTop && MkDmIsKernelPtr(*(PVOID *)pTop) &&
        MkDmInRange(*(PVOID *)pTop, g_Dm.NdisBase, (ULONG)(g_Dm.NdisEnd - g_Dm.NdisBase)) &&
        *(PVOID *)pTop != (PVOID)MkDmTopThunk)
    {
        pSlot->SavedTopIndicate = *(PVOID *)pTop;
        InterlockedExchangePointer((PVOID volatile *)pTop, (PVOID)MkDmTopThunk);
    }
    if (MkDmIsKernelPtr(*(PVOID *)pSendComp) && *(PVOID *)pSendComp != (PVOID)MkDmSendCompleteThunk)
    {
        pSlot->SavedChainSendComplete = *(PVOID *)pSendComp;
        InterlockedExchangePointer((PVOID volatile *)pSendComp, (PVOID)MkDmSendCompleteThunk);
    }

    BOOLEAN fChainTaken = (*(PVOID *)pChain == (PVOID)MkDmChainThunk);
    pSlot->fArmed = fChainTaken;

    if (fChainTaken)
    {
        g_Dm.fArmed = TRUE;
        DBG("[+] DirectMiniport: RX/TXComplete tap armed on ifIndex=%u (mode=%d, chain=0x%p sendComp=0x%p)",
            pSlot->IfIndex, g_Dm.RxMode, pSlot->SavedChainIndicate, pSlot->SavedChainSendComplete);
    }
    else
    {
        DBG("[-] DirectMiniport: RX chain slot takeover failed on ifIndex=%u (slot=0x%p)",
            pSlot->IfIndex, *(PVOID *)pChain);
        ExceptionReporter::ReportFormat("MkDmArmSlotLocked", STATUS_UNSUCCESSFUL,
                                        "RX chain slot takeover failed on ifIndex=%u (slotVal=0x%p, mp=0x%p, chainOff=0x%X)",
                                        pSlot->IfIndex, *(PVOID *)pChain, pSlot->Mp, L.Mp_ChainNode);
    }
    return fChainTaken;
}

static VOID MkDmDisarmSlotLocked(_Inout_ PMK_DM_ADAPTER_SLOT pSlot)
{
    if (!pSlot || !pSlot->fUsed || pSlot->Mp == NULL)
    {
        return;
    }
    const MK_NDIS_LAYOUT &L = g_Dm.L;
    PVOID *pChain = (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_ChainNode + MK_DM_NODE_INDICATE_H);
    PVOID *pTop = (L.Mp_TopIndicate != 0) ? (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_TopIndicate) : NULL;
    PVOID *pSendComp = (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_ChainNode + MK_DM_NODE_SEND_COMPLETE_H);

    pSlot->fArmed = FALSE;
    KeMemoryBarrier();

    if (*(PVOID *)pChain == (PVOID)MkDmChainThunk && pSlot->SavedChainIndicate != NULL)
    {
        InterlockedExchangePointer((PVOID volatile *)pChain, pSlot->SavedChainIndicate);
    }
    if (pTop && *(PVOID *)pTop == (PVOID)MkDmTopThunk && pSlot->SavedTopIndicate != NULL)
    {
        InterlockedExchangePointer((PVOID volatile *)pTop, pSlot->SavedTopIndicate);
    }
    if (*(PVOID *)pSendComp == (PVOID)MkDmSendCompleteThunk && pSlot->SavedChainSendComplete != NULL)
    {
        InterlockedExchangePointer((PVOID volatile *)pSendComp, pSlot->SavedChainSendComplete);
    }
}

static VOID MkDmDrainInFlight(_In_ ULONG TimeoutMs)
{
    for (ULONG waited = 0; waited < TimeoutMs; waited += 1)
    {
        if (InterlockedCompareExchange(&g_Dm.InFlight, 0, 0) == 0)
        {
            return;
        }
        KeStallExecutionProcessor(1000);
    }
    LONG remaining = InterlockedCompareExchange(&g_Dm.InFlight, 0, 0);
    DBG("[!] DirectMiniport: in-flight drain timeout (remaining=%ld)", remaining);
    ExceptionReporter::ReportFormat("MkDmDrainInFlight", STATUS_TIMEOUT,
                                    "In-flight NBL thunk drain timed out after %u ms (remaining=%ld)",
                                    TimeoutMs, remaining);
}

// ---------------------------------------------------------------------------
// 对外接口
// ---------------------------------------------------------------------------
NTSTATUS MkDm_Init(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    if (g_Dm.fInited)
    {
        return STATUS_SUCCESS;
    }

    g_fFatalReported = FALSE;
    RtlZeroMemory(&g_Dm, sizeof(g_Dm));
    KeInitializeSpinLock(&g_Dm.Lock);
    g_Dm.UserVar = UserVar;
    g_Dm.RxMode = MK_DM_RX_TAP;

    MkDmSelectLayout();

    NTSTATUS status = MkDmResolveNdisRange();
    if (!NT_SUCCESS(status))
    {
        DBG("[-] DirectMiniport: ndis.sys not resolved, channel unavailable");
        MkDmReportFatal(MK_DM_FAIL_INIT, status);
        return status;
    }

    MkDmCalibrateFromNdisCode();

    g_Dm.fInited = TRUE;
    DBG("[+] DirectMiniport: init (build=%u ndis=[0x%p,0x%p) layout-slot=%u)",
        g_Dm.BuildNumber, (PVOID)g_Dm.NdisBase, (PVOID)g_Dm.NdisEnd, g_Dm.L.Open_MiniportHandle);
    return STATUS_SUCCESS;
}

VOID MkDm_Shutdown(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Dm.Lock, &oldIrql);
    for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
    {
        if (g_Dm.Slots[i].fUsed)
        {
            MkDmDisarmSlotLocked(&g_Dm.Slots[i]);
            g_Dm.Slots[i].fUsed = FALSE;
        }
    }
    g_Dm.fArmed = FALSE;
    g_Dm.fReady = FALSE;
    KeReleaseSpinLock(&g_Dm.Lock, oldIrql);

    MkDmDrainInFlight(500);

    g_Dm.pSink = NULL;
    g_Dm.CurrentRxBinding = NULL;
    g_Dm.fInited = FALSE;
    DBG("[*] DirectMiniport: shutdown complete (tx=%ld rxSteal=%ld pass=%ld rearm=%ld)", g_Dm.Stats.TxDirect,
        g_Dm.Stats.RxStolen, g_Dm.Stats.RxPassThrough, g_Dm.Stats.Rearm);
}

NTSTATUS MkDm_AttachBinding(_In_ PVOID pBinding, _In_ NDIS_HANDLE OpenHandle)
{
    if (!g_Dm.fInited)
    {
        ExceptionReporter::Report("MkDm_AttachBinding", STATUS_DEVICE_NOT_READY,
                                  "MkDm_AttachBinding called before MkDm_Init");
        return STATUS_DEVICE_NOT_READY;
    }

    MK_DM_ADAPTER_SLOT tempSlot;
    NTSTATUS status = MkDmResolveTarget(pBinding, (PVOID)OpenHandle, &tempSlot);
    if (!NT_SUCCESS(status))
    {
        // 单张非目标/虚拟适配器不兼容时仅跳过该适配器，不在此刻触发全局 Fatal；
        // 由 EthServer_Init 在枚举完所有适配器后统一检查 MkDm_IsReady()。
        DBG("[*] DirectMiniport: skip adapter binding (status=0x%08X)", status);
        return status;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Dm.Lock, &oldIrql);

    PMK_DM_ADAPTER_SLOT pTargetSlot = NULL;
    ULONG chosenIdx = 0;
    for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
    {
        if (g_Dm.Slots[i].fUsed && g_Dm.Slots[i].Mp == tempSlot.Mp)
        {
            pTargetSlot = &g_Dm.Slots[i];
            chosenIdx = i;
            break;
        }
    }
    if (!pTargetSlot)
    {
        for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
        {
            if (!g_Dm.Slots[i].fUsed)
            {
                pTargetSlot = &g_Dm.Slots[i];
                chosenIdx = i;
                break;
            }
        }
    }

    BOOLEAN fArmed = FALSE;
    if (pTargetSlot)
    {
        *pTargetSlot = tempSlot;
        fArmed = MkDmArmSlotLocked(pTargetSlot);
        if (fArmed)
        {
            if (!g_Dm.fReady)
            {
                g_Dm.PrimarySlotIdx = chosenIdx;
            }
            g_Dm.fReady = TRUE;
            g_Dm.fLayoutTrusted = TRUE;
        }
        else
        {
            RtlZeroMemory(pTargetSlot, sizeof(*pTargetSlot));
        }
    }
    else
    {
        ExceptionReporter::ReportFormat("MkDm_AttachBinding", STATUS_INSUFFICIENT_RESOURCES,
                                        "No free MK_DM_ADAPTER_SLOT available (max=%u, ifIndex=%u)",
                                        (ULONG)MK_DM_MAX_ADAPTERS, tempSlot.IfIndex);
    }
    KeReleaseSpinLock(&g_Dm.Lock, oldIrql);

    return fArmed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

VOID MkDm_DetachBinding(_In_ PVOID pBinding)
{
    if (!g_Dm.fInited || !pBinding)
    {
        return;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Dm.Lock, &oldIrql);
    BOOLEAN bAnyReady = FALSE;
    BOOLEAN bAnyArmed = FALSE;
    for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
    {
        if (g_Dm.Slots[i].fUsed && g_Dm.Slots[i].pBinding == pBinding)
        {
            MkDmDisarmSlotLocked(&g_Dm.Slots[i]);
            RtlZeroMemory(&g_Dm.Slots[i], sizeof(g_Dm.Slots[i]));
        }
        else if (g_Dm.Slots[i].fUsed)
        {
            bAnyReady = TRUE;
            if (g_Dm.Slots[i].fArmed)
            {
                bAnyArmed = TRUE;
            }
        }
    }
    g_Dm.fReady = bAnyReady;
    g_Dm.fArmed = bAnyArmed;
    KeReleaseSpinLock(&g_Dm.Lock, oldIrql);

    MkDmDrainInFlight(100);
    DBG("[*] DirectMiniport: detached binding 0x%p", pBinding);
}

BOOLEAN MkDm_IsReady(VOID)
{
    return (g_Dm.fReady && g_Dm.fLayoutTrusted && g_Dm.fArmed);
}

PVOID MkDm_GetCurrentRxBinding(VOID)
{
    return g_Dm.CurrentRxBinding;
}

NTSTATUS MkDm_Send(_In_ PNET_BUFFER_LIST NetBufferLists, _In_ ULONG SendFlags, _Out_opt_ PBOOLEAN pfHandled)
{
    if (pfHandled)
    {
        *pfHandled = FALSE;
    }
    if (!MkDm_IsReady() || NetBufferLists == NULL)
    {
        MkDmStatInc(&g_Dm.Stats.TxFailed);
        ExceptionReporter::ReportFormat("MkDm_Send", STATUS_DEVICE_NOT_READY,
                                        "DirectMiniport not ready or NULL NBL (ready=%u, armed=%u, trusted=%u, nbl=0x%p)",
                                        (ULONG)g_Dm.fReady, (ULONG)g_Dm.fArmed, (ULONG)g_Dm.fLayoutTrusted, NetBufferLists);
        MkDmReportFatal(MK_DM_FAIL_TX, STATUS_DEVICE_NOT_READY);
        return STATUS_DEVICE_NOT_READY;
    }

    PMK_DM_ADAPTER_SLOT pSlot = MkDmFindSlotByOpen(NetBufferLists->SourceHandle);
    if (!pSlot || !MkDmIsKernelPtr(pSlot->SendHandler))
    {
        MkDmStatInc(&g_Dm.Stats.TxFailed);
        ExceptionReporter::ReportFormat("MkDm_Send", STATUS_DEVICE_NOT_READY,
                                        "Invalid adapter slot or SendHandler (pSlot=0x%p, sendHandler=0x%p)",
                                        pSlot, pSlot ? pSlot->SendHandler : NULL);
        MkDmReportFatal(MK_DM_FAIL_TX, STATUS_DEVICE_NOT_READY);
        return STATUS_DEVICE_NOT_READY;
    }

    // 完成路由：SourceHandle 指向该网卡协议 OpenBlock，NDIS 完成时直接回调协议完成例程
    for (PNET_BUFFER_LIST nbl = NetBufferLists; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
    {
        nbl->SourceHandle = pSlot->Open;
    }

    ((PFN_MK_MINIPORT_SEND_NBL)pSlot->SendHandler)((NDIS_HANDLE)pSlot->SendContext, NetBufferLists,
                                                   NDIS_DEFAULT_PORT_NUMBER, SendFlags);
    MkDmStatInc(&g_Dm.Stats.TxDirect);
    if (pfHandled)
    {
        *pfHandled = TRUE;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MkDm_SetRxMode(_In_ ULONG Mode)
{
    if (Mode > MK_DM_RX_BLACKOUT)
    {
        ExceptionReporter::ReportFormat("MkDm_SetRxMode", STATUS_INVALID_PARAMETER,
                                        "Invalid RX mode requested: %u", Mode);
        return STATUS_INVALID_PARAMETER;
    }
    if (Mode != MK_DM_RX_OFF && !MkDm_IsReady())
    {
        ExceptionReporter::ReportFormat("MkDm_SetRxMode", STATUS_DEVICE_NOT_READY,
                                        "SetRxMode(%u) called while DirectMiniport not ready", Mode);
        return STATUS_DEVICE_NOT_READY;
    }
    InterlockedExchange(&g_Dm.RxMode, (LONG)Mode);
    DBG("[*] DirectMiniport: rx mode -> %u", Mode);
    return STATUS_SUCCESS;
}

VOID MkDm_SetRxSink(_In_opt_ PFN_MK_DM_RX_SINK pSink)
{
    InterlockedExchangePointer((PVOID volatile *)&g_Dm.pSink, (PVOID)pSink);
}

VOID MkDm_SetFatalHandler(_In_opt_ PFN_MK_DM_FATAL pfn)
{
    InterlockedExchangePointer((PVOID volatile *)&g_pFatalHandler, (PVOID)pfn);
}

VOID MkDm_Refresh(VOID)
{
    if (g_Dm.fReady == FALSE)
    {
        return;
    }
    const MK_NDIS_LAYOUT &L = g_Dm.L;

    for (ULONG i = 0; i < MK_DM_MAX_ADAPTERS; ++i)
    {
        PMK_DM_ADAPTER_SLOT pSlot = &g_Dm.Slots[i];
        if (!pSlot->fUsed || pSlot->Mp == NULL)
        {
            continue;
        }

        PVOID *pChain = (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_ChainNode + MK_DM_NODE_INDICATE_H);
        PVOID *pTop = (L.Mp_TopIndicate != 0) ? (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_TopIndicate) : NULL;
        PVOID *pSendComp = (PVOID *)((PUCHAR)pSlot->Mp + L.Mp_ChainNode + MK_DM_NODE_SEND_COMPLETE_H);

        if (pSlot->fArmed && (*(PVOID *)pChain != (PVOID)MkDmChainThunk ||
                              *(PVOID *)pSendComp != (PVOID)MkDmSendCompleteThunk ||
                              (pTop != NULL && pSlot->SavedTopIndicate != NULL && *(PVOID *)pTop != (PVOID)MkDmTopThunk)))
        {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_Dm.Lock, &oldIrql);
            pSlot->fArmed = FALSE;
            BOOLEAN fRearmed = MkDmArmSlotLocked(pSlot);
            KeReleaseSpinLock(&g_Dm.Lock, oldIrql);

            if (fRearmed)
            {
                MkDmStatInc(&g_Dm.Stats.Rearm);
            }
            else
            {
                ExceptionReporter::ReportFormat("MkDm_Refresh", STATUS_UNSUCCESSFUL,
                                                "Failed to re-arm hijacked RX/TXComplete slot on ifIndex=%u (mp=0x%p)",
                                                pSlot->IfIndex, pSlot->Mp);
                MkDmReportFatal(MK_DM_FAIL_RX_LOST, STATUS_UNSUCCESSFUL);
            }
        }
        else if (pSlot->fArmed)
        {
            PVOID liveCtx = MkDmAt(pSlot->Mp, L.Mp_ChainNode + MK_DM_NODE_INDICATE_CTX);
            if (liveCtx != pSlot->SavedChainIndicateCtx)
            {
                pSlot->SavedChainIndicateCtx = liveCtx;
            }
            PVOID liveSendCompCtx = MkDmAt(pSlot->Mp, L.Mp_ChainNode + MK_DM_NODE_SEND_COMPLETE_CTX);
            if (liveSendCompCtx != pSlot->SavedChainSendCompleteCtx)
            {
                pSlot->SavedChainSendCompleteCtx = liveSendCompCtx;
            }
        }
    }
}

VOID MkDm_GetStatus(_Out_ PMK_DM_STATUS pStatus)
{
    if (pStatus == NULL)
    {
        return;
    }
    RtlZeroMemory(pStatus, sizeof(*pStatus));
    pStatus->fReady = g_Dm.fReady;
    pStatus->fArmed = g_Dm.fArmed;
    pStatus->fLayoutTrusted = g_Dm.fLayoutTrusted;
    pStatus->RxMode = (ULONG)g_Dm.RxMode;
    pStatus->BuildNumber = g_Dm.BuildNumber;

    PMK_DM_ADAPTER_SLOT pPrimary = MkDmFindSlotByOpen(NULL);
    if (pPrimary)
    {
        pStatus->FilterCount = pPrimary->FilterCount;
        pStatus->MediaType = pPrimary->MediaType;
        pStatus->IfIndex = pPrimary->IfIndex;
        pStatus->TxHandlerRva = pPrimary->TxHandlerRva;
    }

    pStatus->Stats.TxDirect = g_Dm.Stats.TxDirect;
    pStatus->Stats.TxFailed = g_Dm.Stats.TxFailed;
    pStatus->Stats.RxIndicated = g_Dm.Stats.RxIndicated;
    pStatus->Stats.RxStolen = g_Dm.Stats.RxStolen;
    pStatus->Stats.RxPassThrough = g_Dm.Stats.RxPassThrough;
    pStatus->Stats.RxReturned = g_Dm.Stats.RxReturned;
    pStatus->Stats.VerifyFail = g_Dm.Stats.VerifyFail;
    pStatus->Stats.Rearm = g_Dm.Stats.Rearm;
    pStatus->Stats.Fatal = g_Dm.Stats.Fatal;
}

// ---------------------------------------------------------------------------
// C 兼容包装 / DirectMiniport 静态类
// ---------------------------------------------------------------------------
extern "C" NTSTATUS MkDm_Init(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
extern "C" VOID MkDm_Shutdown(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
extern "C" NTSTATUS MkDm_AttachBinding(_In_ PVOID pBinding, _In_ NDIS_HANDLE OpenHandle);
extern "C" VOID MkDm_DetachBinding(_In_ PVOID pBinding);
extern "C" BOOLEAN MkDm_IsReady(VOID);
extern "C" NTSTATUS MkDm_Send(_In_ PNET_BUFFER_LIST NetBufferLists, _In_ ULONG SendFlags, _Out_opt_ PBOOLEAN pfHandled);
extern "C" NTSTATUS MkDm_SetRxMode(_In_ ULONG Mode);
extern "C" VOID MkDm_SetRxSink(_In_opt_ PFN_MK_DM_RX_SINK pSink);
extern "C" VOID MkDm_SetFatalHandler(_In_opt_ PFN_MK_DM_FATAL pfn);
extern "C" VOID MkDm_Refresh(VOID);
extern "C" VOID MkDm_GetStatus(_Out_ PMK_DM_STATUS pStatus);
extern "C" PVOID MkDm_GetCurrentRxBinding(VOID);

NTSTATUS DirectMiniport::Init(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar) { return MkDm_Init(UserVar); }
VOID DirectMiniport::Shutdown(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar) { MkDm_Shutdown(UserVar); }

NTSTATUS DirectMiniport::AttachBinding(_In_ PVOID pBinding, _In_ NDIS_HANDLE OpenHandle)
{
    return MkDm_AttachBinding(pBinding, OpenHandle);
}
VOID DirectMiniport::DetachBinding(_In_ PVOID pBinding) { MkDm_DetachBinding(pBinding); }
BOOLEAN DirectMiniport::IsReady(VOID) { return MkDm_IsReady(); }

NTSTATUS DirectMiniport::Send(_In_ PNET_BUFFER_LIST NetBufferLists, _In_ ULONG SendFlags, _Out_opt_ PBOOLEAN pfHandled)
{
    return MkDm_Send(NetBufferLists, SendFlags, pfHandled);
}
NTSTATUS DirectMiniport::SetRxMode(_In_ MK_DM_RX_MODE Mode) { return MkDm_SetRxMode((ULONG)Mode); }
VOID DirectMiniport::SetRxSink(_In_opt_ PFN_MK_DM_RX_SINK pSink) { MkDm_SetRxSink(pSink); }
VOID DirectMiniport::SetFatalHandler(_In_opt_ PFN_MK_DM_FATAL pfn) { MkDm_SetFatalHandler(pfn); }
VOID DirectMiniport::Refresh(VOID) { MkDm_Refresh(); }
VOID DirectMiniport::GetStatus(_Out_ PMK_DM_STATUS pStatus) { MkDm_GetStatus(pStatus); }
