// Split from ept_trampoline.inl: trampoline/pool_lookup.inl.
// Included through the wrapper; same translation unit.

static bool PayloadEptTrampTryPages(payload_u64 pages_base,
                                    payload_u64 count,
                                    payload_u64 gpa_pfn,
                                    payload_u64 kind,
                                    payload_ept_tramp_match* match)
{
    if (!pages_base || !gpa_pfn || count > PAYLOAD_TRAMP_MAX_PAGES)
        return false;

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 page = pages_base + i * PAYLOAD_TRAMP_PAGE_SIZE;
        payload_u64 guest_page = PayloadReadHostU64(page + PAYLOAD_TRAMP_PAGE_OFF_GUEST_PAGE);
        payload_u64 orig_pfn = PayloadReadHostU64(page + PAYLOAD_TRAMP_PAGE_OFF_ORIG_PFN);
        payload_u64 exec_pfn = PayloadReadHostU64(page + PAYLOAD_TRAMP_PAGE_OFF_EXEC_PFN);
        payload_u64 exec_hva = PayloadReadHostU64(page + PAYLOAD_TRAMP_PAGE_OFF_EXEC_HVA);

        if (orig_pfn != gpa_pfn)
            continue;
        if (!exec_pfn)
            continue;
        if (guest_page && !PayloadIsCanonical(guest_page))
            continue;

        if (match)
        {
            match->page = page;
            match->guest_page = guest_page;
            match->orig_pfn = orig_pfn;
            match->exec_pfn = exec_pfn;
            match->exec_hva = exec_hva;
            match->kind = kind;
        }
        return true;
    }

    return false;
}

static bool PayloadEptTrampTryPool(payload_u64 pool, payload_u64 gpa_pfn, payload_ept_tramp_match* match)
{
    payload_tramp_match meta = {};
    if (!PayloadTrampPoolLooksValid(pool, &meta))
        return false;

    payload_u64 user_pages = PayloadReadHostU32(pool + PAYLOAD_TRAMP_POOL_USER_PAGE_COUNT_OFF);
    payload_u64 kernel_pages = PayloadReadHostU32(pool + PAYLOAD_TRAMP_POOL_KERNEL_PAGE_COUNT_OFF);
    payload_ept_tramp_match local = {};
    local.pool = pool;

    if (PayloadEptTrampTryPages(
            pool + PAYLOAD_TRAMP_POOL_USER_PAGES_OFF,
            user_pages,
            gpa_pfn,
            1,
            &local) ||
        PayloadEptTrampTryPages(
            pool + PAYLOAD_TRAMP_POOL_KERNEL_PAGES_OFF,
            kernel_pages,
            gpa_pfn,
            2,
            &local))
    {
        local.pool = pool;
        if (match)
            *match = local;
        return true;
    }

    return false;
}

static bool PayloadEptTrampFindByPool(payload_u64 gpa_pfn, payload_ept_tramp_match* match)
{
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
    {
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_NO_DIAG;
        return false;
    }

    payload_u64 cached = g_payload_tramp_pool_base;
    if (PayloadIsKernelPointer(cached) &&
        PayloadEptTrampTryPool(cached, gpa_pfn, match))
    {
        return true;
    }

    payload_u64 expected = PayloadDiagTrampPoolBase();
    if (!PayloadIsKernelPointer(expected))
        return false;
    if (PayloadEptTrampTryPool(expected, gpa_pfn, match))
    {
        g_payload_tramp_pool_base = expected;
        return true;
    }

    for (payload_u64 delta = sizeof(payload_u64); delta <= PAYLOAD_TRAMP_POOL_SEARCH_RADIUS; delta += sizeof(payload_u64))
    {
        payload_u64 before = expected - delta;
        payload_u64 after = expected + delta;
        if (PayloadEptTrampTryPool(before, gpa_pfn, match))
        {
            g_payload_tramp_pool_base = before;
            return true;
        }
        if (PayloadEptTrampTryPool(after, gpa_pfn, match))
        {
            g_payload_tramp_pool_base = after;
            return true;
        }
    }

    g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_NO_POOL;
    return false;
}

static bool PayloadEptGenericFindByCurrentVcpu(payload_u64 gpa_pfn, payload_ept_tramp_match* match)
{
    payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
    if (!PayloadIsKernelPointer(vcpu_ptr))
        return false;

    payload_u64 active_head_off = PayloadDiagVcpuEptHookActiveOffset();
    if (!active_head_off)
        return false;
    payload_u64 node_next_off = 0;
    payload_u64 node_orig_off = 0;
    payload_u64 node_exec_off = 0;
    payload_u64 node_is_fake_off = 0;
    if (!PayloadDiagVcpuEptHookNodeLayout(
            &node_next_off,
            &node_orig_off,
            &node_exec_off,
            &node_is_fake_off))
    {
        return false;
    }

    payload_u64 head = PayloadReadHostU64(vcpu_ptr + active_head_off);
    payload_u64 node = head;
    for (payload_u64 i = 0; i < PAYLOAD_VCPU_EPT_HOOK_NODE_MAX && PayloadIsKernelPointer(node); ++i)
    {
        payload_u64 orig_pfn = PayloadReadHostU32(node + node_orig_off);
        payload_u64 exec_pfn = PayloadReadHostU32(node + node_exec_off);
        payload_u64 is_fake = PayloadReadHostU8(node + node_is_fake_off) ? 1ull : 0ull;

        if (orig_pfn == gpa_pfn && exec_pfn)
        {
            if (match)
            {
                match->pool = vcpu_ptr;
                match->page = node;
                match->guest_page = 0;
                match->orig_pfn = orig_pfn;
                match->exec_pfn = exec_pfn;
                match->exec_hva = 0;
                match->kind = is_fake ? 4ull : 3ull; // 3=generic EPT hook, 4=fake-page EPT hook
                match->is_fake_page = is_fake;
            }
            return true;
        }

        payload_u64 next = PayloadReadHostU64(node + node_next_off);
        if (next == node)
            break;
        node = next;
    }

    return false;
}

