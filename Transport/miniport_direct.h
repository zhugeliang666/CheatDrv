#pragma once
// ============================================================================
// miniport_direct.h  —  方案 B：Direct Miniport / Filter 链摘除
//
// 目标：
//   1) 发送：不再走 NdisSendNetBufferLists(open,...) 的过滤器链下行路径，
//      直接命中物理网卡 Miniport 的 SendNetBufferListsHandler，
//      上层任何 LWF（Npcap / Wireshark / ACE 网络探针）都拿不到该 NBL。
//   2) 接收：在 NDIS_MINIPORT_BLOCK 的底层指示指针（链头槽位）上挂接本模块
//      指示节流器，签名帧被截留直投传输层，剩余帧才继续上行；
//      BLACKOUT 模式直接把上行目标切到 NoFilter 节点，过滤器全链失明。
//
// 设计约束（见 ADR-0183）：
//   * 只做"数据指针改写"，不写 ndis.sys 代码页 → HVCI/VBS 相容、无 trampoline
//   * 所有偏移来自 ndis.pdb 离线导出 + 运行时多级交叉验证
//   * 无标准发送兜底：任一校验/接管/发送失败 → 致命上报，由上层"提示失败 + 自动卸载"
//   * 卸载时 CAS 回滚两个槽位 + 在途计数排空，杜绝野指针
// ============================================================================

#include "Common.h"
#include "FrameWork.h"

#ifndef NDIS_WDM
#define NDIS_WDM 1
#endif
#ifndef NDIS630
#define NDIS630 1
#endif
#include <ndis.h>

// 接收侧工作模式
typedef enum _MK_DM_RX_MODE
{
    MK_DM_RX_OFF = 0,      // 不接管接收（只做发送直连）
    MK_DM_RX_TAP = 1,      // 仅截留本通道签名帧，其余帧照常穿过滤器（默认）
    MK_DM_RX_BLACKOUT = 2, // 全部上行帧跳过过滤器链，直接投递协议栈（过滤器全失明）
} MK_DM_RX_MODE;

// 截留帧判定回调（DISPATCH_LEVEL 上下文，cbFrame 为以太网帧总长）
// 返回 TRUE 表示该帧属于本通道、已自行消费 → 不再上行（过滤器不可见）
// 返回 FALSE 表示与本通道无关 → 照常透传
typedef BOOLEAN (*PFN_MK_DM_RX_SINK)(_In_reads_bytes_(cbFrame) const UCHAR *pFrame, _In_ ULONG cbFrame);

// 致命失败原因：本通道没有标准发送兜底，出现即"提示失败 + 自动卸载"
typedef enum _MK_DM_FAIL_REASON
{
    MK_DM_FAIL_INIT = 1,    // ndis.sys 范围/偏移表解析失败
    MK_DM_FAIL_RESOLVE = 2, // OpenBlock→MiniportBlock→Handler 多级校验失败
    MK_DM_FAIL_ARM = 3,     // 底层指示槽位接管失败
    MK_DM_FAIL_RX_LOST = 4, // 已接管槽位被外部改写且无法重挂
    MK_DM_FAIL_TX = 5,      // 直连发送时通道不可用
} MK_DM_FAIL_REASON;

// 致命失败回调（DISPATCH_LEVEL 及以下均可能触发，回调内只允许排队，不做阻塞等待）
typedef VOID (*PFN_MK_DM_FATAL)(_In_ ULONG Reason, _In_ NTSTATUS Status);

// 运行统计
typedef struct _MK_DM_STATS
{
    volatile LONG TxDirect;      // 直连发送的 NBL 数
    volatile LONG TxFailed;      // 直连发送时通道不可用（无兜底，直接致命）
    volatile LONG RxIndicated;   // 节流器收到的指示调用数
    volatile LONG RxStolen;      // 被截留（未上行）的帧数
    volatile LONG RxPassThrough; // 透传给上层的帧数
    volatile LONG RxReturned;    // 归还给 Miniport 的 NBL 数
    volatile LONG VerifyFail;    // 结构验证失败次数
    volatile LONG Rearm;         // 槽位被 NDIS 重建后重新挂接次数
    volatile LONG Fatal;         // 致命失败上报次数（恒为 1，用于确认已触发卸载）
} MK_DM_STATS, *PMK_DM_STATS;

typedef struct _MK_DM_STATUS
{
    BOOLEAN fReady;        // 布局解析 + 目标网卡解析完成
    BOOLEAN fArmed;        // 接收节流器已挂接
    BOOLEAN fLayoutTrusted; // 偏移表命中且通过运行时验证
    ULONG RxMode;
    ULONG BuildNumber;
    ULONG FilterCount;     // 目标 Miniport 上挂的过滤器数量（Npcap 可见性证据）
    ULONG MediaType;
    ULONG IfIndex;
    ULONG TxHandlerRva;    // 解析到的 SendNetBufferListsHandler 相对网卡驱动基址偏移
    MK_DM_STATS Stats;
} MK_DM_STATUS, *PMK_DM_STATUS;

#ifdef __cplusplus
// ============================================================
// DirectMiniport: NDIS 底层直连通道（纯静态类）
// ============================================================
class DirectMiniport
{
  public:
    static NTSTATUS Init(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    static VOID Shutdown(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);

    // 绑定生命周期：NdisOpenAdapterEx 成功后调用
    static NTSTATUS AttachBinding(_In_ PVOID pBinding, _In_ NDIS_HANDLE OpenHandle);
    static VOID DetachBinding(_In_ PVOID pBinding);

    static BOOLEAN IsReady(VOID);
    static BOOLEAN IsArmed(VOID);

    // 直连发送：nbl 链的 SourceHandle 会被改写为本协议 OpenBlock，
    // 完成路径由 NDIS 直接回调 EthProtocolSendNetBufferListsComplete。
    static NTSTATUS Send(_In_ PNET_BUFFER_LIST NetBufferLists, _In_ ULONG SendFlags, _Out_opt_ PBOOLEAN pfHandled);

    static NTSTATUS SetRxMode(_In_ MK_DM_RX_MODE Mode);
    static VOID SetRxSink(_In_opt_ PFN_MK_DM_RX_SINK pSink);

    // 致命失败通知：上层负责"提示失败 + 自动卸载"（本模块自身不做卸载动作）
    static VOID SetFatalHandler(_In_opt_ PFN_MK_DM_FATAL pfn);

    // 看门狗：NDIS 在 filter attach/restart 后会重写链头槽位，需周期性复检
    static VOID Refresh(VOID);

    static VOID GetStatus(_Out_ PMK_DM_STATUS pStatus);
};
#endif

#ifdef __cplusplus
extern "C"
{
#endif
    NTSTATUS MkDm_Init(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    VOID MkDm_Shutdown(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    NTSTATUS MkDm_AttachBinding(_In_ PVOID pBinding, _In_ NDIS_HANDLE OpenHandle);
    VOID MkDm_DetachBinding(_In_ PVOID pBinding);
    BOOLEAN MkDm_IsReady(VOID);
    NTSTATUS MkDm_Send(_In_ PNET_BUFFER_LIST NetBufferLists, _In_ ULONG SendFlags, _Out_opt_ PBOOLEAN pfHandled);
    NTSTATUS MkDm_SetRxMode(_In_ ULONG Mode);
    VOID MkDm_SetRxSink(_In_opt_ PFN_MK_DM_RX_SINK pSink);
    VOID MkDm_SetFatalHandler(_In_opt_ PFN_MK_DM_FATAL pfn);
    VOID MkDm_Refresh(VOID);
    VOID MkDm_GetStatus(_Out_ PMK_DM_STATUS pStatus);
    PVOID MkDm_GetCurrentRxBinding(VOID);
#ifdef __cplusplus
}
#endif
