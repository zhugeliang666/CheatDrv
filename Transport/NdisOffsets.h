#pragma once
// ============================================================================
// NdisOffsets.h  —  ndis.sys 私有结构偏移表（按内核 Build 分档）
//
// 数据来源（可复现，勿手改）：
//   analysis/ndis_symbols/build_offsets.cmd   → 编译 offsets_dump.cpp
//   analysis/ndis_symbols/ndis_offsets_dump.exe ndis.sys <pdbdir> _NDIS_MINIPORT_BLOCK ...
//   ndis.pdb 从 https://msdl.microsoft.com/download/symbols/ndis.pdb/<CV_GUID><AGE>/ 拉取，
//   CV_GUID 由 dumpbin /headers C:\Windows\System32\drivers\ndis.sys 读出。
//
// 19041 档已用 10.0.19041.4522 (Win10 22H2, ndis.pdb 43EBB816-EDE3-30BE-7654-467D5767E2D0/1)
// 逐字段核对，并与 ndis!NdisSendNetBufferLists 反汇编的 [rcx+10h] 读取交叉验证。
// 其它档位保留占位：运行时校验不通过即 fail-closed，绝不盲调函数指针。
// ============================================================================

// _NDIS_MINIPORT_HANDLERS 内部相对偏移（各版本极稳定，独立于 Build）
#define MK_DM_NODE_INDICATE_CTX      0x010
#define MK_DM_NODE_INDICATE_TRACKER  0x018
#define MK_DM_NODE_INDICATE_OBJECT   0x020
#define MK_DM_NODE_RETURN_CTX        0x030
#define MK_DM_NODE_SEND_CTX          0x048
#define MK_DM_NODE_SEND_COMPLETE_CTX 0x060
#define MK_DM_NODE_SEND_COMPLETE_H   0x088
#define MK_DM_NODE_INDICATE_H        0x090
#define MK_DM_NODE_RETURN_H          0x0A0
#define MK_DM_NODE_SEND_H            0x0A8
#define MK_DM_NODE_SIZE              0x0B8

// _NDIS_MINIPORT_DRIVER_CHARACTERISTICS 内部相对偏移（公共结构，ndis.h 亦一致）
#define MK_DM_CHARS_SEND_NBL         0x048
#define MK_DM_CHARS_RETURN_NBL       0x050
#define MK_DM_CHARS_CANCEL_SEND      0x058

typedef struct _MK_NDIS_LAYOUT
{
    ULONG BuildNumber;                 // ntoskrnl build（19041 / 22000 / 22621 / 26100）
    ULONG ServicingHint;               // 记录采样 UBR，仅用于日志
    ULONG Open_MiniportHandle;         // _NDIS_COMMON_OPEN_BLOCK.MiniportHandle
    ULONG Open_AdapterContext;         // _NDIS_COMMON_OPEN_BLOCK.MiniportAdapterContext
    ULONG Open_BindDeviceName;         // _NDIS_COMMON_OPEN_BLOCK.BindDeviceName

    ULONG Mp_AdapterContext;           // _NDIS_MINIPORT_BLOCK.MiniportAdapterContext
    ULONG Mp_MediaType;                //   .MediaType
    ULONG Mp_IfIndex;                  //   .IfIndex
    ULONG Mp_MiniportName;             //   .MiniportName
    ULONG Mp_DriverHandle;             //   .DriverHandle (_NDIS_M_DRIVER_BLOCK*)
    ULONG Mp_LowestFilter;             //   .LowestFilter  (_NDIS_FILTER_BLOCK*)
    ULONG Mp_HighestFilter;            //   .HighestFilter (_NDIS_FILTER_BLOCK*)
    ULONG Mp_TopIndicate;              //   .TopIndicateNetBufferListsHandler（老链头槽位）
    ULONG Mp_TopIndicateLoopback;      //   .TopIndicateLoopbackNetBufferListsHandler
    ULONG Mp_NoFilterNode;             //   .NoFilter  (_NDIS_MINIPORT_HANDLERS)
    ULONG Mp_ChainNode;                //   .Next      (_NDIS_MINIPORT_HANDLERS，迭代链头)

    ULONG Mdrv_Characteristics;        // _NDIS_M_DRIVER_BLOCK.MiniportDriverCharacteristics
    ULONG Mdrv_DriverObject;           //   .DriverObject

    ULONG Flt_NextFilter;              // _NDIS_FILTER_BLOCK.NextFilter
    ULONG Flt_FilterDriver;            //   .FilterDriver
    ULONG Flt_ModuleContext;           //   .FilterModuleContext
    ULONG Flt_Miniport;                //   .Miniport
    ULONG Flt_InstanceName;            //   .FilterInstanceName (UNICODE_STRING)
    ULONG Flt_FriendlyName;            //   .FilterFriendlyName (UNICODE_STRING)
    ULONG Flt_LowerFilter;             //   .LowerFilter
    ULONG Flt_HigherFilter;            //   .HigherFilter
    ULONG Flt_State;                   //   .State
} MK_NDIS_LAYOUT, *PMK_NDIS_LAYOUT;

// ---------------------------------------------------------------------------
// Win10 22H2 / 19041-19045 档（PDB 逐字段验证）
// ---------------------------------------------------------------------------
#define MK_NDIS_LAYOUT_19041                                                                                          \
    {                                                                                                                 \
        19041, 4522,                                                                                                  \
            0x010, 0x038, 0x198,                                                                                      \
            0x018, 0x1D0, 0xFD8, 0xEE0, 0xEB0, 0x7F8, 0x800, 0x858, 0x860, 0x8F8, 0x9B0,                              \
            0x070, 0x028,                                                                                             \
            0x008, 0x010, 0x018, 0x020, 0x028, 0x030, 0x070, 0x078, 0x040                                             \
    }

// ---------------------------------------------------------------------------
// Win11 21H2 / 22000 档（未采样，仅沿用 19041 布局做探测；校验不过即回落）
// ---------------------------------------------------------------------------
#define MK_NDIS_LAYOUT_22000 MK_NDIS_LAYOUT_19041

// ---------------------------------------------------------------------------
// Win11 22H2-23H2 / 22621-22631 档（未采样）
// ---------------------------------------------------------------------------
#define MK_NDIS_LAYOUT_22621 MK_NDIS_LAYOUT_19041

// ---------------------------------------------------------------------------
// Win11 24H2 / 26100 档（未采样）
// ---------------------------------------------------------------------------
#define MK_NDIS_LAYOUT_26100 MK_NDIS_LAYOUT_19041
