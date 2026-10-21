#pragma once
#include "../Core/Common.h"
#include "../vt/vt-call-mapdriver-main/common/payload_abi.h"
#include "../vt/vt-call-mapdriver-main/common/mapctl_ioctl.h"

// ============================================================================
// VtEngine: VMX-Root Hypervisor (TestDriver + payloadRuntime) 全协议纯静态桥接引擎
// 遵循准则：
// 1. 零成本静态抽象 (ADR-0030)：0 虚函数、0 vtable、0 胶水透传层、0 静态导入表 (ADR-0034)
// 2. 100% 协议覆盖：完整迁移 hv::hypercall_code (0~95)、payload_status、mapctl_hv_diag、
//    EPT 读写执行分离 Hook、PFN 全核隐藏 + System CR3 NX=1 伪装、DBG_DISPATCH 调试与 PTE_SEAL
// ============================================================================

#define VT_HYPERCALL_KEY          0x88554466885ULL
#define VT_HYPERVISOR_SIGNATURE   0x73623F64ULL // 'sb?d'
#define VT_MAX_SELF_HIDDEN_PFNS   4096

#pragma pack(push, 8)

enum VT_HYPERCALL_CODE : ULONG64
{
    VT_HC_PING = 0,
    VT_HC_TEST = 1,
    VT_HC_UNLOAD = 2,
    VT_HC_READ_PHYS_MEM = 3,
    VT_HC_WRITE_PHYS_MEM = 4,
    VT_HC_READ_VIRT_MEM = 5,
    VT_HC_WRITE_VIRT_MEM = 6,
    VT_HC_QUERY_PROCESS_CR3 = 7,
    VT_HC_INSTALL_EPT_HOOK = 8,
    VT_HC_REMOVE_EPT_HOOK = 9,
    VT_HC_FLUSH_LOGS = 10,
    VT_HC_GET_PHYSICAL_ADDRESS = 11,
    VT_HC_HIDE_PHYSICAL_PAGE = 12,
    VT_HC_UNHIDE_PHYSICAL_PAGE = 13,
    VT_HC_GET_HV_BASE = 14,
    VT_HC_INSTALL_MMR = 15,
    VT_HC_REMOVE_MMR = 16,
    VT_HC_REMOVE_ALL_MMRS = 17,
    VT_HC_INSTALL_BREAKPOINT_HOOK = 18,
    VT_HC_REMOVE_BREAKPOINT_HOOK = 19,
    VT_HC_ADD_PROTECT_PROCESS = 20,
    VT_HC_REMOVE_PROTECT_PROCESS = 21,
    VT_HC_ADD_MMR_POINT = 22,
    VT_HC_DELETE_MMR_POINT = 23,
    VT_HC_ADD_CR3_MONITOR = 24,
    VT_HC_REMOVE_CR3_MONITOR = 25,
    VT_HC_OPEN_CR3_MONITOR_CHECK_THREAD = 26,
    VT_HC_CLOSE_CR3_MONITOR_CHECK_THREAD = 27,
    VT_HC_OPEN_CR3_MONITOR_CHECK_RIP = 28,
    VT_HC_CLOSE_CR3_MONITOR_CHECK_RIP = 29,
    VT_HC_END_CR3_MONITOR_HOOK = 30,
    VT_HC_ADD_CR3_MONITOR_THREAD = 31,
    VT_HC_REMOVE_CR3_MONITOR_THREAD = 32,
    VT_HC_ACTIVE_CR3_MONITOR_DATA_REGION = 33,
    VT_HC_ADD_CR3_MAP = 34,
    VT_HC_ADD_CR3_MAP_BY_USER_MODE = 35,
    VT_HC_REMOVE_CR3_MAP = 36,
    VT_HC_GET_INFO = 37,
    VT_HC_START_GET_GAME_CR3 = 38,
    VT_HC_START_GET_GAME_CR3_BY_PID = 39,
    VT_HC_GET_GAME_PATH = 40,
    VT_HC_GET_GAME_MODULE_BASE = 41,
    VT_HC_HIDE_HV = 42,
    VT_HC_UNHIDE_HV = 43,
    VT_HC_ADD_REAL_CR3 = 44,
    VT_HC_READ_GAME_MEM = 45,
    VT_HC_WRITE_GAME_MEM = 46,
    VT_HC_HIDE_CACHE_INFO = 47,
    VT_HC_UNHIDE_CACHE_INFO = 48,
    VT_HC_GET_GAMEVT_IMAGE_BASE = 49,
    VT_HC_SAVE_GAMEVT_IMAGE_BASE = 50,
    VT_HC_CALL_FUNCTION = 51,
    VT_HC_ADD_VMCALL_HOOK = 52,
    VT_HC_ENABLE_VMCALL_HOOK = 53,
    VT_HC_DISABLE_VMCALL_HOOK = 54,
    VT_HC_REMOVE_VMCALL_HOOK = 55,
    VT_HC_EH_INSTALL = 56,
    VT_HC_EH_REMOVE = 57,
    VT_HC_EH_ENABLE = 58,
    VT_HC_EH_DISABLE = 59,
    VT_HC_EH_WRITE = 60,
    VT_HC_EH_GET_VA = 61,
    VT_HC_EH_REMOVE_ALL_BY_PROCESS = 62,
    VT_HC_VH_INSTALL = 63,
    VT_HC_VH_INSTALL_RET_ABS = 64,
    VT_HC_VH_ENABLE = 65,
    VT_HC_VH_DISABLE = 66,
    VT_HC_VH_REMOVE = 67,
    VT_HC_VH_UNINIT = 68,
    VT_HC_VH_FIND_BLANK = 69,
    VT_HC_VH_FIND_BLANK_PAGE = 70,
    VT_HC_VH_INIT_TRAMP_POOL = 71,
    VT_HC_VH_TRAMP_ADD_PAGE = 72,
    VT_HC_VH_TRAMP_ADD_SLOT = 73,
    VT_HC_VH_TRAMP_SET_READY = 74,
    VT_HC_PREPARE_SELF_HIDE_ADD = 75,
    VT_HC_PREPARE_SELF_HIDE_COMMIT = 76,
    VT_HC_SET_AFFINITY_LOCK = 77,
    VT_HC_GET_POOL_BLOCKS = 78,
    VT_HC_GET_HIDE_DIAG = 79,
    VT_HC_HIDE_PFN_LIST = 80,
    VT_HC_EPT_PROBE_INSTALL = 81,
    VT_HC_EPT_PROBE_REMOVE = 82,
    VT_HC_EPT_PROBE_GET_HITS = 83,
    VT_HC_EPT_PROBE_CLEAR_HITS = 84,
    VT_HC_GET_RESIDENT_HV_DIAG = 85,
    VT_HC_SET_HOST_RSP = 86,
    VT_HC_MAP_HOST_RANGE = 87,
    VT_HC_SET_HOST_RIP = 88,
    VT_HC_SET_KEEP_HV_ON_UNLOAD = 89,
    VT_HC_DBG_DISPATCH = 90,
    VT_HC_GET_PAYLOAD_STATUS = 91,
    VT_HC_SET_PAYLOAD_MODE = 92,
    VT_HC_PAYLOAD_PING = 93,
    VT_HC_VERIFY_HIDE_PFN_LIST = 94,
    VT_HC_UNHIDE_PFN_LIST = 95,
};

static_assert(VT_HC_VH_FIND_BLANK_PAGE == 70, "VT hypercall ABI drift");
static_assert(VT_HC_PREPARE_SELF_HIDE_ADD == 75, "VT hypercall ABI drift");
static_assert(VT_HC_GET_HIDE_DIAG == 79, "VT hypercall ABI drift");
static_assert(VT_HC_HIDE_PFN_LIST == 80, "VT hypercall ABI drift");
static_assert(VT_HC_GET_RESIDENT_HV_DIAG == 85, "VT hypercall ABI drift");
static_assert(VT_HC_SET_HOST_RSP == 86, "VT hypercall ABI drift");
static_assert(VT_HC_MAP_HOST_RANGE == 87, "VT hypercall ABI drift");
static_assert(VT_HC_SET_HOST_RIP == 88, "VT hypercall ABI drift");
static_assert(VT_HC_SET_KEEP_HV_ON_UNLOAD == 89, "VT hypercall ABI drift");
static_assert(VT_HC_DBG_DISPATCH == 90, "VT hypercall ABI drift");
static_assert(VT_HC_GET_PAYLOAD_STATUS == 91, "VT hypercall ABI drift");
static_assert(VT_HC_SET_PAYLOAD_MODE == 92, "VT hypercall ABI drift");
static_assert(VT_HC_PAYLOAD_PING == 93, "VT hypercall ABI drift");
static_assert(VT_HC_VERIFY_HIDE_PFN_LIST == 94, "VT hypercall ABI drift");
static_assert(VT_HC_UNHIDE_PFN_LIST == 95, "VT hypercall ABI drift");

typedef struct _VT_HYPERCALL_INPUT
{
    ULONG64 Flags;   // ((VT_HYPERCALL_KEY << 8) | (Code & 0xFF))
    ULONG64 Args[6]; // rcx, rdx, r8, r9, r10, r11
} VT_HYPERCALL_INPUT, *PVT_HYPERCALL_INPUT;

// Resident Debug Dispatch (VT_HC_DBG_DISPATCH) 协议常量与结构
#define VT_DBG_MAGIC       0x56444247U // 'VDBG'
#define VT_DBG_ABI_VERSION 1

enum VT_DBG_SUBCMD : ULONG
{
    VT_DBG_SESSION_OPEN           = 0x1000,
    VT_DBG_SESSION_CLOSE          = 0x1001,
    VT_DBG_SESSION_HEARTBEAT      = 0x1002,
    VT_DBG_EVENT_STATS            = 0x1003,
    VT_DBG_TRANSLATE_VA           = 0x2000,
    VT_DBG_QUERY_PTE              = 0x2001,
    VT_DBG_READ_VA                = 0x2002,
    VT_DBG_READ_VA_BATCH          = 0x2003,
    VT_DBG_READ_PA                = 0x2004,
    VT_DBG_PTE_SEAL               = 0x2005,
    VT_DBG_DUMP_RANGE             = 0x3000,
    VT_DBG_WATCH_EXEC_ADD         = 0x4100,
    VT_DBG_WATCH_EXEC_REMOVE      = 0x4101,
    VT_DBG_WATCH_EXEC_POLL_COMPAT = 0x4102,
    VT_DBG_EVENT_POLL             = 0x5000,
    VT_DBG_EVENT_RING_STATS       = 0x5001,
    VT_DBG_CLEAR_EVENTS           = 0x5002,
    VT_DBG_EVENT_SELFTEST         = 0x5003,
    VT_DBG_WATCH_ADD              = 0x6000,
    VT_DBG_WATCH_REMOVE           = 0x6001,
    VT_DBG_WATCH_CLEAR_SESSION    = 0x6002,
    VT_DBG_WATCH_STATS            = 0x6003,
};

enum VT_DBG_PTE_SEAL_FLAGS : ULONG
{
    VT_DBG_PTE_SEAL_FLAG_SYSTEM_CR3 = (1U << 0),
    VT_DBG_PTE_SEAL_FLAG_SET_WRITE  = (1U << 1),
    VT_DBG_PTE_SEAL_FLAG_SET_NX     = (1U << 2),
    VT_DBG_PTE_SEAL_FLAG_DRY_RUN    = (1U << 3),
};

typedef struct _VT_DBG_PACKET_HEADER
{
    ULONG  Magic;
    USHORT Version;
    USHORT Size;
    ULONG  Subcmd;
    ULONG  Flags;
    ULONG64 Session;
    ULONG64 Seq;
} VT_DBG_PACKET_HEADER;

typedef struct _VT_DBG_RESULT_HEADER
{
    ULONG  Magic;
    USHORT Version;
    USHORT Size;
    ULONG  Status;
    ULONG  Flags;
    ULONG64 Session;
    ULONG64 Seq;
    ULONG64 BytesWritten;
} VT_DBG_RESULT_HEADER;

typedef struct _VT_DBG_PTE_SEAL_REQ
{
    VT_DBG_PACKET_HEADER Header;
    ULONG64 Cr3;
    ULONG64 Va;
    ULONG64 PageCount;
    ULONG   Kind;
    ULONG   Flags;
} VT_DBG_PTE_SEAL_REQ;

typedef struct _VT_DBG_PTE_SEAL_PAGE
{
    ULONG64 Va;
    ULONG64 Gpa;
    ULONG64 PtePa;
    ULONG64 Before;
    ULONG64 After;
    ULONG   Status;
    ULONG   PageSize;
} VT_DBG_PTE_SEAL_PAGE;

typedef struct _VT_DBG_PTE_SEAL_RSP
{
    VT_DBG_RESULT_HEADER Header;
    ULONG64 Cr3;
    ULONG64 Base;
    ULONG64 Requested;
    ULONG64 Done;
    ULONG64 Changed;
    ULONG64 Failed;
    ULONG64 LastVpid;
    ULONG   Kind;
    ULONG   Flags;
    VT_DBG_PTE_SEAL_PAGE First;
    VT_DBG_PTE_SEAL_PAGE Last;
} VT_DBG_PTE_SEAL_RSP;

#pragma pack(pop)

#ifdef __cplusplus
class VtEngine
{
  public:
    // 1. 生命周期与状态探测
    static BOOLEAN Initialize(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar, _In_ ULONG BootFlags);
    static VOID Cleanup(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar);
    static BOOLEAN IsActive(VOID);
    static BOOLEAN IsPayloadResident(VOID);

    // 2. 底层通用 VMCALL 陷入原语 (支持任意 0~95 号 Hypercall)
    static ULONG64 RawHypercall(_In_ VT_HYPERCALL_CODE Code,
                                _In_ ULONG64 Arg0 = 0,
                                _In_ ULONG64 Arg1 = 0,
                                _In_ ULONG64 Arg2 = 0,
                                _In_ ULONG64 Arg3 = 0,
                                _In_ ULONG64 Arg4 = 0,
                                _In_ ULONG64 Arg5 = 0);

    // 3. 探针与常驻诊断状态查询
    static BOOLEAN PingHv(VOID);
    static BOOLEAN PingPayload(_In_ ULONG64 Nonce, _Out_opt_ PULONG64 OutPong);
    static BOOLEAN GetPayloadStatus(_Out_ payload_status *OutStatus);
    static BOOLEAN GetResidentHvDiag(_Out_ mapctl_hv_diag *OutDiag);
    static BOOLEAN SetPayloadMode(_In_ ULONG64 Kind, _In_ ULONG64 Mode);

    // 4. 物理页/虚拟内存与进程 CR3 原语 (供 LeechCoreEngine 与业务模块直连调用)
    static ULONG64 GetPhysicalAddress(_In_ ULONG64 Cr3, _In_ ULONG64 Va);
    static ULONG64 QueryProcessCr3(_In_ ULONG64 TargetPid);
    static ULONG64 ReadPhysicalMemory(_In_ ULONG64 PhysAddr, _Out_writes_bytes_(Size) PVOID Buffer, _In_ ULONG Size);
    static ULONG64 WritePhysicalMemory(_In_ ULONG64 PhysAddr, _In_reads_bytes_(Size) const VOID *Buffer, _In_ ULONG Size);
    static ULONG64 ReadVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _Out_writes_bytes_(Size) PVOID Buffer, _In_ ULONG Size);
    static ULONG64 WriteVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _In_reads_bytes_(Size) const VOID *Buffer, _In_ ULONG Size);

    // 5. 驱动自身无模块内存 EPT 全核隐藏 + System CR3 NX=1 伪装
    static BOOLEAN HidePhysicalPage(_In_ ULONG64 Pfn);
    static BOOLEAN UnhidePhysicalPage(_In_ ULONG64 Pfn);
    static ULONG64 HidePfnList(_In_reads_(Count) PULONG64 Pfns, _In_ ULONG64 Count);
    static ULONG64 UnhidePfnList(_In_reads_(Count) PULONG64 Pfns, _In_ ULONG64 Count);
    static BOOLEAN HideVirtualRange(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar, _In_ PVOID BaseVa, _In_ SIZE_T Size);
    static VOID UnhideAllSelfPages(VOID);
    static BOOLEAN SealSystemCr3PagesNx(_In_ ULONG64 BaseVa, _In_ ULONG64 PageCount, _In_ BOOLEAN SetWrite, _In_ BOOLEAN SetNx);

    // 6. EPT Hook / VMCALL Hook / MMR / 进程保护全套管理接口
    static BOOLEAN EhInstall(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ BOOLEAN FullZero, _In_ BOOLEAN IsFakePage);
    static BOOLEAN EhRemove(_In_ ULONG64 Process, _In_ ULONG64 Va);
    static BOOLEAN EhEnable(_In_ ULONG64 Process, _In_ ULONG64 Va);
    static BOOLEAN EhDisable(_In_ ULONG64 Process, _In_ ULONG64 Va);
    static BOOLEAN EhWrite(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ const VOID *Buffer, _In_ ULONG64 Size);
    static ULONG64 EhGetFakeVa(_In_ ULONG64 Process, _In_ ULONG64 Va);
    static BOOLEAN EhRemoveAllByProcess(_In_ ULONG64 Process);

    static ULONG64 VhInstall(_In_ ULONG64 TargetVa, _In_ ULONG64 HookType, _In_ ULONG64 Process, _In_ BOOLEAN FilterByProcess);
    static BOOLEAN VhEnable(_In_ ULONG64 SlotIdx);
    static BOOLEAN VhDisable(_In_ ULONG64 SlotIdx);
    static BOOLEAN VhRemove(_In_ ULONG64 SlotIdx);

    static ULONG64 InstallMmr(_In_ ULONG64 PhysAddr, _In_ ULONG Size, _In_ UCHAR Mode);
    static BOOLEAN RemoveMmr(_In_ ULONG64 MmrHandle);
    static BOOLEAN RemoveAllMmrs(VOID);

    static ULONG64 DbgDispatch(_In_ ULONG Subcmd,
                               _In_opt_ const VOID *InBuf,
                               _In_ ULONG64 InSize,
                               _Out_opt_ PVOID OutBuf,
                               _In_ ULONG64 OutSize,
                               _In_ ULONG64 FlagsOrSession = 0);
};
#endif
