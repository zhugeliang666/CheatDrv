// Split from memcheck_runtime.inl: runtime/verify_ranges.inl.
// Included through the wrapper; same translation unit.

static void PayloadBridgeMemcheckCountPage(mapctl_memcheck* req, payload_u64 kind)
{
    if (!req)
        return;

    switch (kind)
    {
    case MAPCTL_MEMCHECK_KIND_IMAGE:
        req->image_pages++;
        break;
    case MAPCTL_MEMCHECK_KIND_DIRECT:
        req->direct_pages++;
        break;
    case MAPCTL_MEMCHECK_KIND_ARENA_USED:
        req->arena_pages++;
        break;
    case MAPCTL_MEMCHECK_KIND_ARENA_FULL:
        req->arena_full_pages++;
        break;
    case MAPCTL_MEMCHECK_KIND_HOST_STACK:
        req->stack_pages++;
        break;
    case MAPCTL_MEMCHECK_KIND_POOL_BLOCK:
        req->pool_pages++;
        break;
    default:
        break;
    }
}

static void PayloadBridgeMemcheckCountResult(mapctl_memcheck* req,
                                             payload_u64 kind,
                                             bool hidden,
                                             bool visible,
                                             bool unknown)
{
    if (!req)
        return;

    if (hidden)
        req->hidden_pages++;
    if (visible)
        req->visible_pages++;
    if (unknown)
        req->unknown_pages++;

    switch (kind)
    {
    case MAPCTL_MEMCHECK_KIND_IMAGE:
        if (hidden) req->image_hidden++;
        if (visible) req->image_visible++;
        if (unknown) req->image_unknown++;
        break;
    case MAPCTL_MEMCHECK_KIND_DIRECT:
        if (hidden) req->direct_hidden++;
        if (visible) req->direct_visible++;
        if (unknown) req->direct_unknown++;
        break;
    case MAPCTL_MEMCHECK_KIND_ARENA_USED:
        if (hidden) req->arena_hidden++;
        if (visible) req->arena_visible++;
        if (unknown) req->arena_unknown++;
        break;
    case MAPCTL_MEMCHECK_KIND_ARENA_FULL:
        if (hidden) req->arena_full_hidden++;
        if (visible) req->arena_full_visible++;
        if (unknown) req->arena_full_unknown++;
        break;
    case MAPCTL_MEMCHECK_KIND_HOST_STACK:
        if (hidden) req->stack_hidden++;
        if (visible) req->stack_visible++;
        if (unknown) req->stack_unknown++;
        break;
    case MAPCTL_MEMCHECK_KIND_POOL_BLOCK:
        if (hidden) req->pool_hidden++;
        if (visible) req->pool_visible++;
        if (unknown) req->pool_unknown++;
        break;
    default:
        break;
    }
}

static void PayloadBridgeMemcheckFirstBad(mapctl_memcheck* req,
                                          payload_u64 kind,
                                          payload_u64 va,
                                          payload_u64 pfn,
                                          payload_u64 ept_pfn,
                                          payload_u64 pte)
{
    if (!req || req->first_bad_kind)
        return;

    req->first_bad_kind = kind ? kind : MAPCTL_MEMCHECK_KIND_NONE;
    req->first_bad_va = va;
    req->first_bad_pfn = pfn;
    req->first_bad_ept_pfn = ept_pfn;
    req->first_bad_pte = pte;
    req->first_bad_index = req->checked_pages + req->translate_fail + req->verify_fail;
}

static bool PayloadBridgeHideOnePfnAllVcpus(payload_u64 current_vcpu,
                                            payload_u64 default_dummy_pfn,
                                            payload_u64 pfn,
                                            payload_u64* pte_null);

static void PayloadBridgeMemcheckPage(mapctl_memcheck* req,
                                      payload_u64 kind,
                                      payload_u64 va,
                                      payload_u64 vcpu_ptr,
                                      payload_u64 dummy_pfn,
                                      bool repair)
{
    if (!req)
        return;

    PayloadBridgeMemcheckCountPage(req, kind);

    payload_u64 pa = 0;
    if (!PayloadKernelVaToPa(va, &pa) || (pa >> 12) == 0)
    {
        req->translate_fail++;
        PayloadBridgeMemcheckFirstBad(req, kind, va, 0, 0, 0);
        return;
    }

    payload_u64 pfn = pa >> 12;
    payload_u64 pte_va = 0;
    payload_u64 pte = 0;
    req->checked_pages++;

    if (repair)
    {
        payload_u64 pte_null = 0;
        PayloadBridgeHideOnePfnAllVcpus(vcpu_ptr, dummy_pfn, pfn, &pte_null);
    }

    if (!PayloadDbgWatchLocatePteForVcpu(vcpu_ptr, pfn << 12, false, &pte_va, &pte))
    {
        PayloadBridgeMemcheckCountResult(req, kind, false, false, true);
        PayloadBridgeMemcheckFirstBad(req, kind, va, pfn, 0, 0);
        return;
    }

    payload_u64 ept_pfn = (pte & PAYLOAD_EPT_PFN_MASK) >> 12;
    if (ept_pfn == dummy_pfn)
    {
        PayloadBridgeMemcheckCountResult(req, kind, true, false, false);
    }
    else
    {
        PayloadBridgeMemcheckCountResult(req, kind, false, true, false);
        PayloadBridgeMemcheckFirstBad(req, kind, va, pfn, ept_pfn, pte);
    }
}

static bool PayloadBridgeMemcheckRange(mapctl_memcheck* req,
                                       payload_u64 kind,
                                       payload_u64 base,
                                       payload_u64 bytes,
                                       payload_u64 vcpu_ptr,
                                       payload_u64 dummy_pfn,
                                       bool repair,
                                       payload_u64 start_page,
                                       payload_u64 max_pages,
                                       payload_u64* used_pages,
                                       payload_u64* next_page)
{
    if (!req || !base || !bytes)
        return true;

    payload_u64 begin = base & ~0xFFFull;
    payload_u64 limit = base + bytes;
    if (limit < base)
        limit = ~0ull;
    payload_u64 end = PayloadAlignUp(limit, PAGE_SIZE);
    if (end <= begin)
        return true;

    req->range_count++;
    payload_u64 total_pages = (end - begin) >> 12;
    if (start_page >= total_pages)
    {
        if (next_page)
            *next_page = total_pages;
        return true;
    }

    payload_u64 page = start_page;
    while (page < total_pages)
    {
        if (max_pages && used_pages && *used_pages >= max_pages)
        {
            if (next_page)
                *next_page = page;
            return false;
        }

        payload_u64 va = begin + (page << 12);
        PayloadBridgeMemcheckPage(req, kind, va, vcpu_ptr, dummy_pfn, repair);
        if (used_pages)
            ++(*used_pages);
        ++page;
    }

    if (next_page)
        *next_page = total_pages;
    return true;
}

static bool PayloadBridgeMemcheckPoolBlocks(mapctl_memcheck* req,
                                            payload_u64 vcpu_ptr,
                                            payload_u64 dummy_pfn,
                                            bool repair,
                                            payload_u64 start_index,
                                            payload_u64 start_page,
                                            payload_u64 max_pages,
                                            payload_u64* used_pages)
{
    if (!req || !g_resident_pool_manifest || !g_resident_pool_count)
        return true;

    payload_u64 count = g_resident_pool_count;
    if (g_resident_pool_capacity && count > g_resident_pool_capacity)
        count = g_resident_pool_capacity;
    if (count > 4096)
        count = 4096;
    if (start_index >= count)
        return true;

    payload_u64 block_size = sizeof(payload_pool_block);
    for (payload_u64 i = start_index; i < count; ++i)
    {
        payload_u64 entry = g_resident_pool_manifest + i * block_size;
        payload_u64 va = 0;
        payload_u64 bytes = 0;
        if (!PayloadReadSystemVa64(entry, &va) ||
            !PayloadReadSystemVa64(entry + sizeof(payload_u64), &bytes))
        {
            req->translate_fail++;
            PayloadBridgeMemcheckFirstBad(req, MAPCTL_MEMCHECK_KIND_POOL_BLOCK, entry, 0, 0, 0);
            continue;
        }

        if (!va || !bytes)
        {
            start_page = 0;
            continue;
        }

        req->pool_block_count++;
        payload_u64 next_page = 0;
        bool done_range = PayloadBridgeMemcheckRange(req,
            MAPCTL_MEMCHECK_KIND_POOL_BLOCK,
            va,
            bytes,
            vcpu_ptr,
            dummy_pfn,
            repair,
            start_page,
            max_pages,
            used_pages,
            &next_page);
        if (!done_range)
        {
            req->next_kind = MAPCTL_MEMCHECK_KIND_POOL_BLOCK;
            req->next_index = i;
            req->next_page = next_page;
            return false;
        }
        start_page = 0;
    }

    return true;
}

static payload_u64 PayloadBridgeHandleMemcheck(mapctl_memcheck* req,
                                               payload_u64 flags,
                                               payload_u64 max_pages,
                                               payload_u64 cursor_kind,
                                               payload_u64 cursor_index,
                                               payload_u64 cursor_page)
{
    if (!req)
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    if (!flags)
        flags = MAPCTL_MEMCHECK_FLAG_DATA_DEFAULT;
    bool repair = (flags & MAPCTL_MEMCHECK_FLAG_REPAIR) != 0;
    flags &= ~MAPCTL_MEMCHECK_FLAG_REPAIR;
    if (!max_pages)
        max_pages = 1024;
    if (max_pages > 4096)
        max_pages = 4096;

    PayloadZeroMemory(req, sizeof(*req));
    req->magic = MAPCTL_MEMCHECK_MAGIC;
    req->size = sizeof(*req);
    req->flags = flags;
    if (repair)
        req->flags |= MAPCTL_MEMCHECK_FLAG_REPAIR;
    req->max_pages = max_pages;
    req->cursor_kind = cursor_kind;
    req->cursor_index = cursor_index;
    req->cursor_page = cursor_page;
    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    PayloadGetStatus(&req->payload);

    payload_u64 current_vcpu = PayloadCurrentVcpuPtr();
    req->observed_vcpu = PayloadCurrentVcpuIndex();
    if (!PayloadIsKernelPointer(current_vcpu) ||
        !g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn ||
        !PayloadIsKernelPointer(current_vcpu + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn))
    {
        req->verify_fail++;
        req->done = 1;
        return req->result;
    }

    payload_u64 dummy_pfn = PayloadReadHostU64(
        current_vcpu + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn);
    req->dummy_pfn = dummy_pfn;
    if (!dummy_pfn)
    {
        req->verify_fail++;
        req->done = 1;
        return req->result;
    }

    payload_u64 used_pages = 0;

    auto run_range = [&](payload_u64 kind, payload_u64 base, payload_u64 size) -> bool
    {
        if (cursor_kind && cursor_kind != kind)
            return true;
        payload_u64 start = (cursor_kind == kind) ? cursor_page : 0;
        payload_u64 next = 0;
        bool done_range = PayloadBridgeMemcheckRange(
            req, kind, base, size, current_vcpu, dummy_pfn,
            repair,
            start, max_pages, &used_pages, &next);
        if (!done_range)
        {
            req->next_kind = kind;
            req->next_index = 0;
            req->next_page = next;
            return false;
        }
        if (cursor_kind == kind)
        {
            cursor_kind = 0;
            cursor_index = 0;
            cursor_page = 0;
        }
        return true;
    };

    if ((flags & MAPCTL_MEMCHECK_FLAG_IMAGE) &&
        !run_range(MAPCTL_MEMCHECK_KIND_IMAGE, g_image_base, g_image_size))
        goto memcheck_done_partial;
    if ((flags & MAPCTL_MEMCHECK_FLAG_DIRECT) &&
        !run_range(MAPCTL_MEMCHECK_KIND_DIRECT, g_direct_alloc_base, g_direct_alloc_size))
        goto memcheck_done_partial;
    if (flags & MAPCTL_MEMCHECK_FLAG_ARENA_FULL)
    {
        if (!run_range(MAPCTL_MEMCHECK_KIND_ARENA_FULL, g_arena_base, g_arena_size))
            goto memcheck_done_partial;
    }
    else if (flags & MAPCTL_MEMCHECK_FLAG_ARENA_USED)
    {
        payload_u64 arena_used = g_arena_used;
        if (g_arena_size && arena_used > g_arena_size)
            arena_used = g_arena_size;
        if (!run_range(MAPCTL_MEMCHECK_KIND_ARENA_USED, g_arena_base, arena_used))
            goto memcheck_done_partial;
    }
    if ((flags & MAPCTL_MEMCHECK_FLAG_HOST_STACK) &&
        !run_range(MAPCTL_MEMCHECK_KIND_HOST_STACK, g_host_stack_base, g_host_stack_size))
        goto memcheck_done_partial;
    if (flags & MAPCTL_MEMCHECK_FLAG_POOL_BLOCKS)
    {
        payload_u64 start_index = (cursor_kind == MAPCTL_MEMCHECK_KIND_POOL_BLOCK) ? cursor_index : 0;
        payload_u64 start_page = (cursor_kind == MAPCTL_MEMCHECK_KIND_POOL_BLOCK) ? cursor_page : 0;
        if (!PayloadBridgeMemcheckPoolBlocks(req, current_vcpu, dummy_pfn, repair, start_index, start_page, max_pages, &used_pages))
            goto memcheck_done_partial;
    }

    req->done = 1;
    req->next_kind = MAPCTL_MEMCHECK_KIND_NONE;
    req->next_index = 0;
    req->next_page = 0;

memcheck_done_partial:
    req->result =
        (req->checked_pages || req->done) &&
        !req->visible_pages &&
        !req->unknown_pages &&
        !req->translate_fail &&
        !req->verify_fail
            ? PAYLOAD_RESULT_OK
            : PAYLOAD_RESULT_INVALID_CONTEXT;
    return req->result;
}

static payload_u64 PayloadBridgeHandleMemcheckHypercall(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx || !ctx->rcx || ctx->rdx < sizeof(mapctl_memcheck))
        return PayloadBridgeCompleteHypercall(ctx, code, PAYLOAD_RESULT_INVALID_CONTEXT);

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return PayloadBridgeCompleteHypercall(ctx, code, PAYLOAD_RESULT_INVALID_CONTEXT);

    payload_u64 header[3];
    header[0] = 0;
    header[1] = 0;
    header[2] = 0;
    if (!PayloadGuestCopyToHostBuffer(guest_cr3, ctx->rcx, header, sizeof(header)))
        return PayloadBridgeCompleteHypercall(ctx, code, PAYLOAD_RESULT_INVALID_CONTEXT);

    payload_u64 flags = header[2] ? header[2] : MAPCTL_MEMCHECK_FLAG_DATA_DEFAULT;
    payload_u64 max_pages = 0;
    payload_u64 cursor_kind = 0;
    payload_u64 cursor_index = 0;
    payload_u64 cursor_page = 0;
    PayloadGuestCopyToHostBuffer(guest_cr3,
        ctx->rcx + (payload_u64)&(((mapctl_memcheck*)0)->max_pages),
        &max_pages,
        sizeof(max_pages));
    PayloadGuestCopyToHostBuffer(guest_cr3,
        ctx->rcx + (payload_u64)&(((mapctl_memcheck*)0)->cursor_kind),
        &cursor_kind,
        sizeof(cursor_kind));
    PayloadGuestCopyToHostBuffer(guest_cr3,
        ctx->rcx + (payload_u64)&(((mapctl_memcheck*)0)->cursor_index),
        &cursor_index,
        sizeof(cursor_index));
    PayloadGuestCopyToHostBuffer(guest_cr3,
        ctx->rcx + (payload_u64)&(((mapctl_memcheck*)0)->cursor_page),
        &cursor_page,
        sizeof(cursor_page));

    payload_u64 result = PayloadBridgeHandleMemcheck(
        &g_payload_memcheck_scratch,
        flags,
        max_pages,
        cursor_kind,
        cursor_index,
        cursor_page);
    if (!PayloadGuestCopyFromHostBuffer(guest_cr3, ctx->rcx, &g_payload_memcheck_scratch, sizeof(g_payload_memcheck_scratch)))
        return PayloadBridgeCompleteHypercall(ctx, code, PAYLOAD_RESULT_INVALID_CONTEXT);

    return PayloadBridgeCompleteHypercall(ctx, code, result);
}
