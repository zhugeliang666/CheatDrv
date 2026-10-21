// Split from payload_bridge.inl: tramp/tramp_dispatch.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static payload_u64 PayloadDiagTrampPoolBase()
{
    return PayloadDiagGhvField(
        g_cached_hv_diag.ghv_off_tramp_pool,
        PAYLOAD_GHV_TRAMP_POOL_OFFSET);
}

enum payload_tramp_reason : payload_u64
{
    PAYLOAD_TRAMP_REASON_NONE = 0,
    PAYLOAD_TRAMP_REASON_NOT_SOFTWARE_BP = 1,
    PAYLOAD_TRAMP_REASON_NO_DIAG = 2,
    PAYLOAD_TRAMP_REASON_BAD_POOL = 3,
    PAYLOAD_TRAMP_REASON_NO_MATCH = 4,
    PAYLOAD_TRAMP_REASON_MATCH_USER = 0x101,
    PAYLOAD_TRAMP_REASON_MATCH_KERNEL = 0x102,
    PAYLOAD_TRAMP_REASON_HANDLE_USER = 0x201,
    PAYLOAD_TRAMP_REASON_HANDLE_KERNEL = 0x202,
    PAYLOAD_TRAMP_REASON_HANDLE_FAIL = 0x301,
};

struct payload_tramp_match
{
    payload_u64 pool;
    payload_u64 slot;
    payload_u64 rip;
    payload_u64 tramp_va;
    payload_u64 target_resume;
    payload_u64 kind; // 1=user, 2=kernel
    payload_u64 user_slot_count;
    payload_u64 kernel_slot_count;
    payload_u64 user_ready;
    payload_u64 kernel_ready;
};

static bool PayloadTrampPoolLooksValid(payload_u64 pool, payload_tramp_match* meta)
{
    if (!PayloadIsKernelPointer(pool))
        return false;

    unsigned int user_count = PayloadReadHostU32(pool + PAYLOAD_TRAMP_POOL_USER_SLOT_COUNT_OFF);
    unsigned int user_pages = PayloadReadHostU32(pool + PAYLOAD_TRAMP_POOL_USER_PAGE_COUNT_OFF);
    unsigned int kernel_count = PayloadReadHostU32(pool + PAYLOAD_TRAMP_POOL_KERNEL_SLOT_COUNT_OFF);
    unsigned int kernel_pages = PayloadReadHostU32(pool + PAYLOAD_TRAMP_POOL_KERNEL_PAGE_COUNT_OFF);
    unsigned char user_ready = PayloadReadHostU8(pool + PAYLOAD_TRAMP_POOL_USER_READY_OFF);
    unsigned char kernel_ready = PayloadReadHostU8(pool + PAYLOAD_TRAMP_POOL_KERNEL_READY_OFF);

    if (user_count > PAYLOAD_TRAMP_MAX_SLOTS ||
        kernel_count > PAYLOAD_TRAMP_MAX_SLOTS ||
        user_pages > PAYLOAD_TRAMP_MAX_PAGES ||
        kernel_pages > PAYLOAD_TRAMP_MAX_PAGES ||
        user_ready > 1 ||
        kernel_ready > 1)
    {
        return false;
    }

    if (meta)
    {
        meta->pool = pool;
        meta->user_slot_count = user_count;
        meta->kernel_slot_count = kernel_count;
        meta->user_ready = user_ready;
        meta->kernel_ready = kernel_ready;
    }
    return true;
}

static bool PayloadTrampTrySlots(payload_u64 slots_base, payload_u64 count, payload_u64 rip, payload_u64 kind, payload_tramp_match* match)
{
    if (!slots_base || !rip || count > PAYLOAD_TRAMP_MAX_SLOTS)
        return false;

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 slot = slots_base + i * PAYLOAD_TRAMP_SLOT_SIZE;
        if (!PayloadReadHostU8(slot + PAYLOAD_TRAMP_SLOT_OFF_OCCUPIED))
            continue;

        payload_u64 bp_rip = PayloadReadHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_BP_RIP);
        if (bp_rip != rip)
            continue;

        payload_u64 tramp_va = PayloadReadHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TRAMP_VA);
        payload_u64 target = PayloadReadHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TARGET_RESUME);
        if (!PayloadIsCanonical(tramp_va) || !PayloadIsCanonical(target) || !target)
            return false;

        if (match)
        {
            match->slot = slot;
            match->rip = rip;
            match->tramp_va = tramp_va;
            match->target_resume = target;
            match->kind = kind;
        }
        return true;
    }

    return false;
}

static bool PayloadTrampTryPool(payload_u64 pool, payload_u64 rip, payload_tramp_match* match)
{
    payload_tramp_match meta = {};
    if (!PayloadTrampPoolLooksValid(pool, &meta))
        return false;

    if (PayloadTrampTrySlots(
            pool + PAYLOAD_TRAMP_POOL_USER_SLOTS_OFF,
            meta.user_slot_count,
            rip,
            1,
            &meta) ||
        PayloadTrampTrySlots(
            pool + PAYLOAD_TRAMP_POOL_KERNEL_SLOTS_OFF,
            meta.kernel_slot_count,
            rip,
            2,
            &meta))
    {
        if (match)
            *match = meta;
        return true;
    }

    if (match)
        *match = meta;
    return false;
}

static bool PayloadTrampFindByExpectedPool(payload_u64 rip, payload_tramp_match* match)
{
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return false;

    payload_u64 expected = PayloadDiagTrampPoolBase();
    if (!PayloadIsKernelPointer(expected))
        return false;

    payload_u64 cached = g_payload_tramp_pool_base;
    if (PayloadIsKernelPointer(cached))
    {
        payload_tramp_match cached_meta = {};
        bool cached_valid = PayloadTrampPoolLooksValid(cached, &cached_meta);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_scan_count);
        if (PayloadTrampTryPool(cached, rip, match) && match && match->slot)
            return true;
        if (cached_valid &&
            (cached_meta.user_slot_count ||
             cached_meta.kernel_slot_count ||
             cached_meta.user_ready ||
             cached_meta.kernel_ready))
        {
            if (match)
                *match = cached_meta;
            return false;
        }
    }

    payload_tramp_match expected_meta = {};
    bool expected_valid = PayloadTrampPoolLooksValid(expected, &expected_meta);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_scan_count);
    if (PayloadTrampTryPool(expected, rip, match) && match && match->slot)
    {
        g_payload_tramp_pool_base = expected;
        return true;
    }
    if (expected_valid &&
        (expected_meta.user_slot_count ||
         expected_meta.kernel_slot_count ||
         expected_meta.user_ready ||
         expected_meta.kernel_ready))
    {
        if (match)
            *match = expected_meta;
        return false;
    }

    for (payload_u64 delta = sizeof(payload_u64); delta <= PAYLOAD_TRAMP_POOL_SEARCH_RADIUS; delta += sizeof(payload_u64))
    {
        payload_u64 before = expected - delta;
        payload_u64 after = expected + delta;

        _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_scan_count);
        if (PayloadTrampTryPool(before, rip, match) && match && match->slot)
        {
            g_payload_tramp_pool_base = before;
            return true;
        }

        _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_scan_count);
        if (PayloadTrampTryPool(after, rip, match) && match && match->slot)
        {
            g_payload_tramp_pool_base = after;
            return true;
        }
    }

    return false;
}

static payload_u64 PayloadBridgeProbeTrampoline(payload_guest_context* ctx, payload_u64 reason)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(reason);

    payload_u64 info = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_VMEXIT_INTERRUPTION_INFORMATION, &info))
        return 0;

    payload_u64 vector = info & 0xFFull;
    payload_u64 type = (info >> 8) & 0x7ull;
    if (vector != 3 || type != 6)
    {
        g_payload_tramp_last_reason = PAYLOAD_TRAMP_REASON_NOT_SOFTWARE_BP;
        return 0;
    }

    payload_u64 rip = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &rip) || !rip)
        return 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_probe_count);
    g_payload_tramp_last_rip = rip;

    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
    {
        g_payload_tramp_last_reason = PAYLOAD_TRAMP_REASON_NO_DIAG;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_scan_fail_count);
        return 0;
    }

    payload_tramp_match match = {};
    if (!PayloadTrampFindByExpectedPool(rip, &match) || !match.slot)
    {
        g_payload_tramp_last_reason = PAYLOAD_TRAMP_REASON_NO_MATCH;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_scan_fail_count);
        return 0;
    }

    g_payload_tramp_last_pool = match.pool;
    g_payload_tramp_last_slot = match.slot;
    g_payload_tramp_last_rip = match.rip;
    g_payload_tramp_last_tramp_va = match.tramp_va;
    g_payload_tramp_last_target = match.target_resume;
    g_payload_tramp_last_kind = match.kind;
    g_payload_tramp_user_slot_count = match.user_slot_count;
    g_payload_tramp_kernel_slot_count = match.kernel_slot_count;
    g_payload_tramp_user_ready = match.user_ready;
    g_payload_tramp_kernel_ready = match.kernel_ready;
    g_payload_tramp_last_reason = (match.kind == 1)
        ? PAYLOAD_TRAMP_REASON_MATCH_USER
        : PAYLOAD_TRAMP_REASON_MATCH_KERNEL;

    payload_u64 matches = (payload_u64)_InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_match_count);
    if (match.kind == 1)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_user_match_count);
    else
        _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_kernel_match_count);

    if (g_payload_tramp_mode == PAYLOAD_TRAMP_MODE_HANDLE &&
        matches >= PAYLOAD_TRAMP_HANDLE_WARMUP_MATCHES)
    {
        if (PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, match.target_resume))
        {
            g_payload_tramp_last_reason = (match.kind == 1)
                ? PAYLOAD_TRAMP_REASON_HANDLE_USER
                : PAYLOAD_TRAMP_REASON_HANDLE_KERNEL;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_handle_count);
            return 1;
        }

        g_payload_tramp_last_reason = PAYLOAD_TRAMP_REASON_HANDLE_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_tramp_handle_fail_count);
    }

    return 0;
}

