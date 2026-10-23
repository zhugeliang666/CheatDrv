// Split from payload_bridge.inl: vtret/vtret_types.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static constexpr payload_u64 PAYLOAD_GHV_OFF_KPCR_PRCB = 0x1218038ull;
static constexpr payload_u64 PAYLOAD_GHV_OFF_KPRCB_CURRENT_THREAD = 0x1218040ull;
static constexpr payload_u64 PAYLOAD_GHV_OFF_KTHREAD_APC_STATE = 0x1218048ull;
static constexpr payload_u64 PAYLOAD_GHV_OFF_KAPC_STATE_PROCESS = 0x1218050ull;
static constexpr payload_u64 PAYLOAD_GHV_VTCALL_LIST_OFFSET = 0x1218120ull;
static constexpr payload_u64 PAYLOAD_VTCALL_NODE_SIZE = 0x880ull;
static constexpr payload_u64 PAYLOAD_VTCALL_NODE_COUNT = 20ull;
static constexpr payload_u64 PAYLOAD_VTCALL_NODE_OFF_NEXT = 0x00ull;
static constexpr payload_u64 PAYLOAD_VTCALL_NODE_OFF_PROCESS = 0x08ull;
static constexpr payload_u64 PAYLOAD_VTCALL_NODE_OFF_THREAD = 0x10ull;
static constexpr payload_u64 PAYLOAD_VTCALL_NODE_OFF_RETRIP = 0x20ull;
static constexpr payload_u64 PAYLOAD_VTCALL_NODE_OFF_OLD_VT_RSP = 0x38ull;
static constexpr payload_u64 PAYLOAD_VTCALL_NODE_OFF_NEW_CONTEXT_PTR = 0x250ull;
static constexpr payload_u64 PAYLOAD_VTCALL_LIST_OFF_ACTIVE_HEAD =
    PAYLOAD_VTCALL_NODE_SIZE * PAYLOAD_VTCALL_NODE_COUNT;
static constexpr payload_u64 PAYLOAD_VTCALL_LIST_SEARCH_RADIUS = 0x8000ull;
static constexpr payload_u64 PAYLOAD_VTRET_HANDLE_WARMUP_MATCHES = 1ull;

enum payload_vtret_reason : payload_u64
{
    PAYLOAD_VTRET_REASON_NONE = 0,
    PAYLOAD_VTRET_REASON_NOT_SOFTWARE_BP = 1,
    PAYLOAD_VTRET_REASON_NO_DIAG = 2,
    PAYLOAD_VTRET_REASON_NO_GUEST_IDS = 3,
    PAYLOAD_VTRET_REASON_BAD_ACTIVE_HEAD = 4,
    PAYLOAD_VTRET_REASON_NO_MATCH = 5,
    PAYLOAD_VTRET_REASON_STRICT_MATCH = 0x101,
    PAYLOAD_VTRET_REASON_LOOSE_MATCH = 0x102,
};

struct payload_vtret_match
{
    payload_u64 node;
    payload_u64 old_vt_rsp;
    payload_u64 process;
    payload_u64 thread;
    payload_u64 list_base;
    payload_u64 active_head;
    bool strict;
};

static payload_u64 PayloadCurrentVcpuIndex();
static payload_u64 PayloadCurrentVcpuPtr();

