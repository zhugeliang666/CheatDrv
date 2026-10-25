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

struct payload_image_text_range
{
    payload_u64 base;
    payload_u64 size;
};

static bool PayloadBridgeReadImageBytes(payload_u64 va, void* out, unsigned long bytes)
{
    payload_u64 image_base = g_image_base;
    payload_u64 image_size = g_image_size;
    if (!out || !bytes || !image_base || !image_size || va < image_base)
        return false;

    payload_u64 offset = va - image_base;
    if (offset > image_size || (payload_u64)bytes > image_size - offset)
        return false;

    payload_host_exception_info e = {};
    PayloadMemcpySafe(&e, out, (const void*)va, bytes);
    return !e.exception_occurred;
}

static unsigned short PayloadBridgeReadLe16(const unsigned char* p)
{
    return (unsigned short)p[0] | (unsigned short)p[1] << 8;
}

static unsigned int PayloadBridgeReadLe32(const unsigned char* p)
{
    return (unsigned int)p[0] |
        ((unsigned int)p[1] << 8) |
        ((unsigned int)p[2] << 16) |
        ((unsigned int)p[3] << 24);
}

static bool PayloadBridgeCollectImageTextRange(payload_image_text_range* out)
{
    if (!out)
        return false;
    out->base = 0;
    out->size = 0;

    payload_u64 image_base = g_image_base;
    payload_u64 image_size = g_image_size;
    if (!image_base || !image_size || image_size < 0x1000ull)
        return false;

    unsigned short mz = 0;
    int lfanew = 0;
    if (!PayloadBridgeReadImageBytes(image_base, &mz, sizeof(mz)) || mz != 0x5A4Du ||
        !PayloadBridgeReadImageBytes(image_base + 0x3Cull, &lfanew, sizeof(lfanew)) ||
        lfanew < (int)sizeof(unsigned short))
        return false;

    payload_u64 nt_offset = (payload_u64)(unsigned int)lfanew;
    if (nt_offset > image_size - 0x18ull)
        return false;

    unsigned int signature = 0;
    unsigned short section_count = 0;
    unsigned short optional_size = 0;
    unsigned short optional_magic = 0;
    if (!PayloadBridgeReadImageBytes(image_base + nt_offset, &signature, sizeof(signature)) ||
        signature != 0x00004550u ||
        !PayloadBridgeReadImageBytes(image_base + nt_offset + 6ull, &section_count, sizeof(section_count)) ||
        !PayloadBridgeReadImageBytes(image_base + nt_offset + 20ull, &optional_size, sizeof(optional_size)) ||
        !PayloadBridgeReadImageBytes(image_base + nt_offset + 24ull, &optional_magic, sizeof(optional_magic)) ||
        optional_magic != 0x020Bu || !section_count || section_count > 96u)
        return false;

    payload_u64 section_offset = nt_offset + 24ull + optional_size;
    payload_u64 section_bytes = (payload_u64)section_count * 40ull;
    if (section_offset > image_size || section_bytes > image_size - section_offset)
        return false;

    for (unsigned short i = 0; i < section_count; ++i)
    {
        unsigned char section[40] = {};
        if (!PayloadBridgeReadImageBytes(
                image_base + section_offset + (payload_u64)i * 40ull,
                section,
                sizeof(section)))
            return false;

        if (section[0] != '.' || section[1] != 't' || section[2] != 'e' ||
            section[3] != 'x' || section[4] != 't' ||
            !(PayloadBridgeReadLe32(section + 36) & 0x20000000u))
            continue;

        unsigned int virtual_size = PayloadBridgeReadLe32(section + 8);
        unsigned int raw_size = PayloadBridgeReadLe32(section + 16);
        unsigned int virtual_address = PayloadBridgeReadLe32(section + 12);
        payload_u64 section_size = virtual_size ? virtual_size : raw_size;
        if (!section_size || virtual_address >= image_size ||
            section_size > image_size - virtual_address)
            return false;

        payload_u64 raw_begin = image_base + virtual_address;
        payload_u64 raw_end = raw_begin + section_size;
        if (raw_end < raw_begin || raw_begin > ~0ull - 0xFFFull)
            return false;

        // 4KB PFN 隐藏跳过首尾混合页，避免把 .data/.rdata 一起变成读零页。
        out->base = (raw_begin + 0xFFFull) & ~0xFFFull;
        payload_u64 range_end = raw_end & ~0xFFFull;
        if (range_end <= out->base)
            return false;

        out->size = range_end - out->base;
        return true;
    }

    return false;
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

    if (flags & MAPCTL_MEMCHECK_FLAG_IMAGE)
    {
        payload_image_text_range image_text = {};
        if (!PayloadBridgeCollectImageTextRange(&image_text))
        {
            req->verify_fail++;
            PayloadBridgeMemcheckFirstBad(req, MAPCTL_MEMCHECK_KIND_IMAGE, g_image_base, 0, 0, 0);
            goto memcheck_done_partial;
        }
        if (!run_range(MAPCTL_MEMCHECK_KIND_IMAGE, image_text.base, image_text.size))
            goto memcheck_done_partial;
    }
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
