// Split from payload_bridge.inl: pmo/pmo_state.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static constexpr payload_u64 PAYLOAD_PMO_CALL_NODE_COUNT = 8ull;
static constexpr payload_u64 PAYLOAD_PMO_MAX_TRACKED_VCPUS = 64ull;
static constexpr payload_u64 PAYLOAD_PMO_GUEST_CONTEXT_SAVE_SIZE = 0x200ull;
static constexpr payload_u64 PAYLOAD_PMO_STACK_COPY_SIZE = 0x400ull;
static constexpr payload_u64 PAYLOAD_PMO_STACK_POS = 0x200ull;
static constexpr payload_u64 PAYLOAD_PMO_MAX_ARGS = 12ull;

enum payload_pmo_call_reason : payload_u64
{
    PAYLOAD_PMO_CALL_REASON_NONE = 0,
    PAYLOAD_PMO_CALL_REASON_BUSY = 1,
    PAYLOAD_PMO_CALL_REASON_NO_NODE = 2,
    PAYLOAD_PMO_CALL_REASON_NO_STACK = 3,
    PAYLOAD_PMO_CALL_REASON_NO_VMCS = 4,
    PAYLOAD_PMO_CALL_REASON_NO_IDS = 5,
    PAYLOAD_PMO_CALL_REASON_NO_BLANK = 6,
    PAYLOAD_PMO_CALL_REASON_STACK_COPY = 7,
    PAYLOAD_PMO_CALL_REASON_VMWRITE = 8,
    PAYLOAD_PMO_CALL_REASON_ENTRY_FELL_THROUGH = 9,
    PAYLOAD_PMO_CALL_REASON_READY = 0x101,
    PAYLOAD_PMO_CALL_REASON_RETURNED = 0x201,
    PAYLOAD_PMO_CALL_REASON_CROSS = 0x202,
};

enum payload_pmo_draw_stage : payload_u64
{
    PAYLOAD_PMO_DRAW_STAGE_NONE = 0,
    PAYLOAD_PMO_DRAW_STAGE_NOT_READY = 1,
    PAYLOAD_PMO_DRAW_STAGE_VFUNC_BEGIN = 2,
    PAYLOAD_PMO_DRAW_STAGE_BEGIN = 3,
    PAYLOAD_PMO_DRAW_STAGE_VFUNC_BRUSH = 4,
    PAYLOAD_PMO_DRAW_STAGE_BRUSH = 5,
    PAYLOAD_PMO_DRAW_STAGE_VFUNC_TEXT = 6,
    PAYLOAD_PMO_DRAW_STAGE_TEXT = 7,
    PAYLOAD_PMO_DRAW_STAGE_VFUNC_END = 8,
    PAYLOAD_PMO_DRAW_STAGE_END = 9,
    PAYLOAD_PMO_DRAW_STAGE_INIT_ALLOC = 0x20,
    PAYLOAD_PMO_DRAW_STAGE_INIT_D2D_FACTORY = 0x21,
    PAYLOAD_PMO_DRAW_STAGE_INIT_SURFACE = 0x22,
    PAYLOAD_PMO_DRAW_STAGE_INIT_RT = 0x23,
    PAYLOAD_PMO_DRAW_STAGE_INIT_BRUSH = 0x24,
    PAYLOAD_PMO_DRAW_STAGE_INIT_DWRITE = 0x25,
    PAYLOAD_PMO_DRAW_STAGE_INIT_TEXTFMT = 0x26,
    PAYLOAD_PMO_DRAW_STAGE_INIT_READY = 0x2F,
    PAYLOAD_PMO_DRAW_STAGE_DONE = 0x100,
};

static constexpr payload_u64 PAYLOAD_BUSINESS_TICK_FRAME_MASK = 0xFull;

enum payload_business_stage : payload_u64
{
    PAYLOAD_BUSINESS_STAGE_NONE = 0,
    PAYLOAD_BUSINESS_STAGE_NOT_READY = 1,
    PAYLOAD_BUSINESS_STAGE_THROTTLED = 2,
    PAYLOAD_BUSINESS_STAGE_SNAPSHOT = 3,
    PAYLOAD_BUSINESS_STAGE_READY = 0x100,
};

enum payload_business_reason : payload_u64
{
    PAYLOAD_BUSINESS_REASON_OK = 0,
    PAYLOAD_BUSINESS_REASON_NOT_READY = 1,
    PAYLOAD_BUSINESS_REASON_THROTTLED = 2,
    PAYLOAD_BUSINESS_REASON_VMREAD = 3,
};

struct payload_pmo_call_node
{
    volatile LONG state;
    payload_u64 process;
    payload_u64 thread;
    payload_u64 ret_rip;
    payload_u64 old_vt_rsp;
    payload_u64 old_rip;
    payload_u64 old_rsp;
    payload_u64 old_host_rsp;
    payload_u64 new_user_rsp;
    payload_u64 guest_cr3;
    payload_u64 entry_vcpu;
    payload_u64 stack_slot;
    payload_u64 new_context_ptr;
    payload_u64 saved_affinity;
    payload_u64 saved_user_affinity;
    payload_u64 saved_ideal_processor;
    payload_u64 saved_user_ideal_processor;
    payload_u64 affinity_applied;
    payload_u64 saved_u_cet;
    payload_u64 saved_s_cet;
    unsigned char u_cet_saved;
    unsigned char s_cet_saved;
    unsigned char cet_pad[6];
    unsigned char old_context[PAYLOAD_PMO_GUEST_CONTEXT_SAVE_SIZE];
    unsigned char stack_copy[PAYLOAD_PMO_STACK_COPY_SIZE];
};

static payload_pmo_call_node g_payload_pmo_call_nodes[PAYLOAD_PMO_CALL_NODE_COUNT] = {};
static volatile LONG g_payload_pmo_call_depth = 0;
static volatile LONG g_payload_pmo_stack_busy[PAYLOAD_HOST_STACK_SLOT_COUNT] = {};
static volatile unsigned char g_payload_pmo_pending_state[PAYLOAD_PMO_MAX_TRACKED_VCPUS] = {};
static volatile unsigned int g_payload_pmo_pending_delay[PAYLOAD_PMO_MAX_TRACKED_VCPUS] = {};
static volatile payload_u64 g_payload_pmo_pending_rsp[PAYLOAD_PMO_MAX_TRACKED_VCPUS] = {};
static volatile payload_u64 g_payload_pmo_pending_stack_slot[PAYLOAD_PMO_MAX_TRACKED_VCPUS] = {};
static volatile unsigned char g_payload_pmo_pending_stack_valid[PAYLOAD_PMO_MAX_TRACKED_VCPUS] = {};
