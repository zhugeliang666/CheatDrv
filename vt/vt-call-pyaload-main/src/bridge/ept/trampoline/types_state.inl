// Split from ept_trampoline.inl: trampoline/types_state.inl.
// Included through the wrapper; same translation unit.

static constexpr payload_u64 PAYLOAD_TRAMP_POOL_USER_PAGES_OFF = 0x208ull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_KERNEL_PAGES_OFF = 0x618ull;
static constexpr payload_u64 PAYLOAD_TRAMP_PAGE_SIZE = 0x20ull;
static constexpr payload_u64 PAYLOAD_TRAMP_PAGE_OFF_GUEST_PAGE = 0x00ull;
static constexpr payload_u64 PAYLOAD_TRAMP_PAGE_OFF_ORIG_PFN = 0x08ull;
static constexpr payload_u64 PAYLOAD_TRAMP_PAGE_OFF_EXEC_PFN = 0x10ull;
static constexpr payload_u64 PAYLOAD_TRAMP_PAGE_OFF_EXEC_HVA = 0x18ull;
static constexpr payload_u64 PAYLOAD_EPT_HANDLE_WARMUP_MATCHES = 1ull;
static constexpr payload_u64 PAYLOAD_EPT_PFN_MASK = 0x000FFFFFFFFFF000ull;
static constexpr payload_u64 PAYLOAD_EPT_PERM_MASK = 0x7ull;
static constexpr payload_u64 PAYLOAD_EPT_LARGE_PAGE = 1ull << 7;
static constexpr payload_u64 PAYLOAD_EPT_MAX_TRACKED_VCPUS = 64ull;
static constexpr payload_u64 PAYLOAD_VCPU_EPT_HOOK_NODE_MAX = 0x300ull;
static constexpr payload_u64 PAYLOAD_DBG_PENDING_KIND_WATCH_REARM = 1ull;
static constexpr payload_u64 PAYLOAD_DBG_PENDING_KIND_OFF = 0x00ull;
static constexpr payload_u64 PAYLOAD_LEGACY_DBG_WATCH_ACTIVE_PAGES_OFF = 0x1Cull;
static constexpr payload_u64 PAYLOAD_LEGACY_DBG_WATCH_PAGES_OFF = 0xA050ull;
static constexpr payload_u64 PAYLOAD_LEGACY_DBG_WATCH_PAGE_SIZE = 0x28ull;
static constexpr payload_u64 PAYLOAD_LEGACY_DBG_WATCH_PAGE_OFF_GPA_PAGE = 0x08ull;
static constexpr payload_u64 PAYLOAD_LEGACY_DBG_WATCH_PAGE_OFF_TRAP_MASK = 0x10ull;
static constexpr payload_u64 PAYLOAD_LEGACY_DBG_WATCH_PAGE_OFF_REF_COUNT = 0x14ull;
static constexpr payload_u64 PAYLOAD_LEGACY_DBG_WATCH_PAGE_OFF_ACTIVE = 0x1Bull;
static constexpr payload_u64 PAYLOAD_LEGACY_DBG_WATCH_PAGE_CAPACITY = 512ull;

static payload_u64 PayloadDiagVcpuEptHookActiveOffset()
{
    return g_cached_hv_diag.vcpu_off_ept_hook_active_list;
}

static bool PayloadDiagVcpuEptHookNodeLayout(payload_u64* next_off,
                                             payload_u64* orig_off,
                                             payload_u64* exec_off,
                                             payload_u64* is_fake_off)
{
    if (!g_cached_hv_diag.vcpu_ept_hook_node_off_orig_pfn ||
        !g_cached_hv_diag.vcpu_ept_hook_node_off_exec_pfn ||
        !g_cached_hv_diag.vcpu_ept_hook_node_off_is_fake_page)
    {
        return false;
    }

    if (next_off)
        *next_off = g_cached_hv_diag.vcpu_ept_hook_node_off_next;
    if (orig_off)
        *orig_off = g_cached_hv_diag.vcpu_ept_hook_node_off_orig_pfn;
    if (exec_off)
        *exec_off = g_cached_hv_diag.vcpu_ept_hook_node_off_exec_pfn;
    if (is_fake_off)
        *is_fake_off = g_cached_hv_diag.vcpu_ept_hook_node_off_is_fake_page;
    return true;
}

static payload_u64 PayloadDiagVcpuDbgPendingOffset()
{
    return g_cached_hv_diag.vcpu_off_dbg_pending;
}

static payload_u64 PayloadDiagDbgWatchBase()
{
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return 0;

    payload_u64 offset = g_cached_hv_diag.ghv_off_dbg_watch;
    if (!offset)
        return 0;
    payload_u64 base = g_cached_hv_diag.ghv + offset;
    return PayloadIsKernelPointer(base) ? base : 0;
}

enum payload_ept_tramp_reason : payload_u64
{
    PAYLOAD_EPT_TRAMP_REASON_NONE = 0,
    PAYLOAD_EPT_TRAMP_REASON_VMREAD_FAIL = 1,
    PAYLOAD_EPT_TRAMP_REASON_NO_DIAG = 2,
    PAYLOAD_EPT_TRAMP_REASON_NO_POOL = 3,
    PAYLOAD_EPT_TRAMP_REASON_NO_MATCH = 4,
    PAYLOAD_EPT_TRAMP_REASON_NO_PTE = 5,
    PAYLOAD_EPT_TRAMP_REASON_BAD_PTE = 6,
    PAYLOAD_EPT_TRAMP_REASON_NO_ACCESS = 7,
    PAYLOAD_EPT_TRAMP_REASON_BAD_VCPU = 8,
    PAYLOAD_EPT_TRAMP_REASON_WRITE_FAIL = 9,
    PAYLOAD_EPT_TRAMP_REASON_MTF_ARM_FAIL = 10,
    PAYLOAD_EPT_TRAMP_REASON_DBG_WATCH_FORWARD = 11,
    PAYLOAD_EPT_TRAMP_REASON_DBG_PENDING_FORWARD = 12,
    PAYLOAD_EPT_TRAMP_REASON_MATCH_USER = 0x101,
    PAYLOAD_EPT_TRAMP_REASON_MATCH_KERNEL = 0x102,
    PAYLOAD_EPT_TRAMP_REASON_MATCH_GENERIC = 0x103,
    PAYLOAD_EPT_TRAMP_REASON_MATCH_FAKE = 0x104,
    PAYLOAD_EPT_TRAMP_REASON_HANDLE_EXEC = 0x201,
    PAYLOAD_EPT_TRAMP_REASON_HANDLE_DATA = 0x202,
    PAYLOAD_EPT_TRAMP_REASON_HANDLE_SAME_PAGE = 0x203,
    PAYLOAD_EPT_TRAMP_REASON_MTF_RESTORE = 0x301,
    PAYLOAD_EPT_TRAMP_REASON_MTF_RESTORE_FAIL = 0x302,
};

struct payload_ept_tramp_match
{
    payload_u64 pool;
    payload_u64 page;
    payload_u64 guest_page;
    payload_u64 orig_pfn;
    payload_u64 exec_pfn;
    payload_u64 exec_hva;
    payload_u64 kind; // 1=user, 2=kernel
    payload_u64 is_fake_page;
};

static payload_u64 PayloadCurrentVcpuIndex()
{
    payload_u64 vpid = 0;
    if (PayloadVmread(PAYLOAD_VMCS_CTRL_VPID, &vpid) &&
        vpid &&
        vpid <= PAYLOAD_EPT_MAX_TRACKED_VCPUS)
    {
        return vpid - 1;
    }

    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.current_vcpu < PAYLOAD_EPT_MAX_TRACKED_VCPUS)
    {
        return g_cached_hv_diag.current_vcpu;
    }

    return ~0ull;
}

static payload_u64 PayloadCurrentVcpuPtr()
{
    payload_u64 index = PayloadCurrentVcpuIndex();
    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.vcpus &&
        g_hv_diag_vcpu_stride &&
        index < PAYLOAD_EPT_MAX_TRACKED_VCPUS)
    {
        payload_u64 ptr = g_cached_hv_diag.vcpus + index * g_hv_diag_vcpu_stride;
        if (PayloadIsKernelPointer(ptr))
            return ptr;
    }

    if (g_hv_diag_cache_ready && PayloadIsKernelPointer(g_cached_hv_diag.current_vcpu_ptr))
        return g_cached_hv_diag.current_vcpu_ptr;

    return 0;
}

static bool PayloadDbgWatchPendingActive()
{
    payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
    if (!vcpu_ptr)
        return false;

    payload_u64 off = PayloadDiagVcpuDbgPendingOffset();
    if (!off)
        return false;

    payload_u64 pending = vcpu_ptr + off;
    if (!PayloadIsKernelPointer(pending))
        return false;

    return PayloadReadHostU32(pending + PAYLOAD_DBG_PENDING_KIND_OFF) ==
           PAYLOAD_DBG_PENDING_KIND_WATCH_REARM;
}

static bool PayloadDbgWatchOwnsGpaPage(payload_u64 gpa_page)
{
    payload_u64 base = PayloadDiagDbgWatchBase();
    if (!base)
        return false;

    unsigned int active_pages = PayloadReadHostU32(base + PAYLOAD_LEGACY_DBG_WATCH_ACTIVE_PAGES_OFF);
    if (!active_pages)
        return false;

    payload_u64 pages = base + PAYLOAD_LEGACY_DBG_WATCH_PAGES_OFF;
    if (!PayloadIsKernelPointer(pages))
        return false;

    payload_u64 seen = 0;
    for (payload_u64 i = 0; i < PAYLOAD_LEGACY_DBG_WATCH_PAGE_CAPACITY; ++i)
    {
        payload_u64 page = pages + i * PAYLOAD_LEGACY_DBG_WATCH_PAGE_SIZE;
        if (!PayloadIsKernelPointer(page + PAYLOAD_LEGACY_DBG_WATCH_PAGE_SIZE - 1))
            break;

        unsigned char active = PayloadReadHostU8(page + PAYLOAD_LEGACY_DBG_WATCH_PAGE_OFF_ACTIVE);
        unsigned int ref_count = PayloadReadHostU32(page + PAYLOAD_LEGACY_DBG_WATCH_PAGE_OFF_REF_COUNT);
        unsigned int trap_mask = PayloadReadHostU32(page + PAYLOAD_LEGACY_DBG_WATCH_PAGE_OFF_TRAP_MASK);
        if (!active || !ref_count || !trap_mask)
            continue;

        ++seen;
        payload_u64 watched_gpa = PayloadReadHostU64(page + PAYLOAD_LEGACY_DBG_WATCH_PAGE_OFF_GPA_PAGE);
        if (watched_gpa == gpa_page)
            return true;

        if (seen >= active_pages)
            break;
    }

    return false;
}

