// Split from payload_bridge.inl: hypercall/resident_commands.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static bool PayloadRangeInside(payload_u64 base, payload_u64 size, payload_u64 va, payload_u64 bytes)
{
    if (!base || !size || !va || !bytes)
        return false;
    if (va < base)
        return false;
    payload_u64 off = va - base;
    return off < size && bytes <= (size - off);
}

static payload_u64 PayloadBridgeHandleMapHostRange(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 va = ctx->rcx;
    payload_u64 bytes = ctx->rdx;
    if (!va || !bytes)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    bool known_resident_range =
        PayloadRangeInside(g_image_base, g_image_size, va, bytes) ||
        PayloadRangeInside(g_arena_base, g_arena_size, va, bytes) ||
        PayloadRangeInside(g_host_stack_base, g_host_stack_size, va, bytes) ||
        PayloadRangeInside(g_direct_alloc_base, g_direct_alloc_size, va, bytes) ||
        PayloadRangeInside(g_host_state_base, g_host_state_size, va, bytes);

    if (!known_resident_range)
        return 0;

    bool mapped = PayloadMapHostRangeSelf(va, bytes);
    return PayloadBridgeCompleteHypercall(ctx, code, mapped ? 1 : 0);
}

static payload_u64 PayloadBridgeHandleHvDiag(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    if (!g_hv_diag_cache_ready)
        return 0;

    if (!ctx->rcx || ctx->rdx < sizeof(mapctl_hv_diag))
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    mapctl_hv_diag diag = g_cached_hv_diag;
    diag.magic = MAPCTL_HV_DIAG_MAGIC;
    diag.size = sizeof(diag);
    diag.version = MAPCTL_HV_DIAG_LAYOUT_VERSION;

    payload_u64 vpid = 0;
    if (PayloadVmread(PAYLOAD_VMCS_CTRL_VPID, &vpid) && vpid)
    {
        diag.current_vcpu = vpid - 1;
        if (diag.vcpus && g_hv_diag_vcpu_stride)
            diag.current_vcpu_ptr = diag.vcpus + diag.current_vcpu * g_hv_diag_vcpu_stride;
    }

    PayloadVmread(PAYLOAD_VMCS_HOST_RIP, &diag.vmcs_host_rip);
    PayloadVmread(PAYLOAD_VMCS_HOST_RSP, &diag.vmcs_host_rsp);

    if (g_payload_vmexit_target)
        diag.vm_exit = g_payload_vmexit_target;
    if (g_payload_vmexit_bridge_target)
        diag.handle_vm_exit = g_payload_vmexit_bridge_target;
    if (g_payload_legacy_ptrs_finalized)
    {
        diag.vm_exit = 0;
        diag.handle_vm_exit = 0;
        diag.image_base = 0;
        diag.driver_unload = 0;
        PayloadRedirectLegacyDiagPointersToShadows(&diag);
    }
    diag.flags |= 0x2ull; // payload supplied diag

    payload_u64 guest_cr3 = 0;
    bool copied =
        PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) &&
        guest_cr3 &&
        PayloadGuestCopyFromHostBuffer(guest_cr3, ctx->rcx, &diag, sizeof(diag));
    if (!copied && g_system_cr3 && g_system_cr3 != guest_cr3)
        copied = PayloadGuestCopyFromHostBuffer(g_system_cr3, ctx->rcx, &diag, sizeof(diag));
    if (!copied)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_hv_diag_gva_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 handled = PayloadBridgeCompleteHypercall(ctx, code, sizeof(mapctl_hv_diag));
    if (handled)
        _InterlockedIncrement64((volatile LONG64*)&g_hv_diag_self_count);
    return handled;
}

static payload_u64 PayloadBridgeHandlePayloadStatus(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    if (!ctx->rcx || ctx->rdx < sizeof(payload_status))
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    payload_status* status = &g_payload_control_status_scratch;
    PayloadZeroMemory(status, sizeof(*status));
    payload_u64 result = PayloadGetStatus(status);
    if (result != PAYLOAD_RESULT_OK || status->magic != PAYLOAD_STATUS_MAGIC)
        return PayloadBridgeCompleteHypercall(ctx, code, result);

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    if (!PayloadGuestCopyFromHostBuffer(guest_cr3, ctx->rcx, status, sizeof(*status)))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_hv_diag_gva_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    return PayloadBridgeCompleteHypercall(ctx, code, PAYLOAD_RESULT_OK);
}

static payload_u64 PayloadBridgeHandleSetPayloadMode(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 result = PAYLOAD_RESULT_INVALID_CONTEXT;
    switch (ctx->rcx)
    {
    case PAYLOAD_MODE_KIND_VTRET:
        result = PayloadSetVtretMode(ctx->rdx);
        break;
    case PAYLOAD_MODE_KIND_TRAMP:
        result = PayloadSetTrampMode(ctx->rdx);
        break;
    case PAYLOAD_MODE_KIND_HOOK:
        result = PayloadSetHookMode(ctx->rdx);
        break;
    case PAYLOAD_MODE_KIND_EPT:
        result = PayloadSetEptMode(ctx->rdx);
        break;
    case PAYLOAD_MODE_KIND_CUTOVER:
        result = PayloadSetCutoverMode(ctx->rdx);
        break;
    case PAYLOAD_MODE_KIND_LEGACY_DETACH:
        // The legacy-data detach copies a very large ghv block and may allocate
        // independent pages.  Never do that from VM-exit/root context; the
        // direct IOCTL/export path must pre-complete it before handoff.
        result = (g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE)
            ? PAYLOAD_RESULT_OK
            : PAYLOAD_RESULT_INVALID_CONTEXT;
        break;
    case PAYLOAD_MODE_KIND_HOST_IDT:
        result = PayloadInstallHostIdt(ctx->rdx);
        break;
    case PAYLOAD_MODE_KIND_HOST_EXCEPTION:
        result = PayloadTriggerHostExceptionSelftest(ctx->rdx);
        break;
    default:
        break;
    }

    return PayloadBridgeCompleteHypercall(ctx, code, result);
}

static payload_u64 PayloadBridgeHandlePayloadPing(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    return PayloadBridgeCompleteHypercall(ctx, code, PayloadPing(ctx->rcx));
}

static payload_u64 PayloadBridgeHandleSetAffinityLock(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_affinity_lock_enabled, 0);
    if (!PayloadIsKernelPointer(field))
        return 0;

    PayloadWriteHostU8(field, ctx->rcx ? 1 : 0);
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static bool PayloadBridgeQueuePendingHidePfn(payload_u64 pfn)
{
    static constexpr payload_u64 kPendingHideCapacity = 256ull * 1024ull;

    if (!g_cached_hv_diag.ghv_off_pending_hide_pfns ||
        !g_cached_hv_diag.ghv_off_pending_hide_count)
    {
        return false;
    }

    payload_u64 pfns_base = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_pfns, 0);
    payload_u64 count_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_count, 0);
    if (!PayloadIsKernelPointer(pfns_base) ||
        !PayloadIsKernelPointer(count_field))
    {
        return false;
    }

    LONG idx = _InterlockedIncrement((volatile LONG*)count_field) - 1;
    if (idx < 0 || (payload_u64)idx >= kPendingHideCapacity)
    {
        PayloadWriteHostU32(count_field, (unsigned int)kPendingHideCapacity);
        return false;
    }

    PayloadWriteHostU64(pfns_base + (payload_u64)idx * sizeof(payload_u64), pfn);
    return true;
}

static bool PayloadBridgeAppendLegacyProtectRange(payload_u64 base, payload_u64 end)
{
    if (!base || end <= base ||
        !g_cached_hv_diag.ghv_off_prot_ranges ||
        !g_cached_hv_diag.ghv_off_prot_range_count ||
        !g_cached_hv_diag.ghv_prot_range_stride)
    {
        return false;
    }

    payload_u64 ranges = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_prot_ranges, 0);
    payload_u64 count_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_prot_range_count, 0);
    if (!PayloadIsKernelPointer(ranges) ||
        !PayloadIsKernelPointer(count_field))
    {
        return false;
    }

    payload_u64 capacity = g_cached_hv_diag.ghv_prot_range_capacity
        ? g_cached_hv_diag.ghv_prot_range_capacity
        : 128ull;
    if (capacity > 4096ull)
        capacity = 4096ull;

    unsigned int count = PayloadReadHostU32(count_field);
    if ((payload_u64)count >= capacity)
        return false;

    payload_u64 entry = ranges + (payload_u64)count * g_cached_hv_diag.ghv_prot_range_stride;
    PayloadWriteHostU64(entry + g_cached_hv_diag.ghv_prot_range_off_base, base);
    PayloadWriteHostU64(entry + g_cached_hv_diag.ghv_prot_range_off_end, end);
    PayloadWriteHostU32(count_field, count + 1);
    return true;
}

static payload_u64 PayloadBridgeQueueSystemVaRangePfns(payload_u64 base, payload_u64 bytes)
{
    if (!base || !bytes || !g_system_cr3)
        return 0;

    payload_u64 end = base + bytes;
    if (end <= base)
        return 0;

    payload_u64 first = base & ~0xFFFull;
    payload_u64 last = (end - 1) & ~0xFFFull;
    payload_u64 queued = 0;

    for (payload_u64 page = first;; page += PAGE_SIZE)
    {
        payload_u64 gpa = 0;
        payload_u64 left = 0;
        if (PayloadGvaToGpa(g_system_cr3, page, &gpa, &left) &&
            gpa &&
            PayloadBridgeQueuePendingHidePfn(gpa >> 12))
        {
            ++queued;
        }

        if (page == last || page > (last - PAGE_SIZE))
            break;
    }

    return queued;
}

static payload_u64 PayloadBridgeHandlePrepareSelfHideAdd(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 ok = PayloadBridgeQueuePendingHidePfn(ctx->rcx) ? 1ull : 0ull;
    return PayloadBridgeCompleteHypercall(ctx, code, ok);
}

static payload_u64 PayloadBridgeHandlePrepareSelfHideCommit(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    if (!g_hv_diag_cache_ready ||
        !PayloadIsKernelPointer(g_cached_hv_diag.ghv) ||
        !g_cached_hv_diag.ghv_off_pending_hide_count ||
        !g_cached_hv_diag.ghv_off_pending_hide_vcpu_bitmap ||
        !g_cached_hv_diag.ghv_off_pending_hide_tsc_threshold)
    {
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    // TestDriver commit auto-registers every PoolManager block in prot_ranges
    // and queues its PFNs.  After resident detach the adopted pool manifest is
    // the payload-owned mirror of that PoolManager active list.
    payload_u64 manifest = g_resident_pool_manifest;
    payload_u64 count = g_resident_pool_count;
    if (g_resident_pool_capacity && count > g_resident_pool_capacity)
        count = g_resident_pool_capacity;
    if (count > 4096ull)
        count = 4096ull;

    if (PayloadIsKernelPointer(manifest))
    {
        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_u64 entry = manifest + i * (payload_u64)sizeof(payload_pool_block);
            payload_u64 va = PayloadReadHostU64(entry + offsetof(payload_pool_block, va));
            payload_u64 bytes = PayloadReadHostU64(entry + offsetof(payload_pool_block, bytes));
            if (!va || !bytes)
                continue;

            payload_u64 end = va + bytes;
            if (end <= va)
                continue;

            PayloadBridgeAppendLegacyProtectRange(va, end);
            PayloadBridgeQueueSystemVaRangePfns(va, bytes);
        }
    }

    // Keep the resident payload image protected for the same lookup path that
    // TestDriver used for its image.  PFN queuing of the image itself remains
    // caller-driven, matching TestDriver's comment in prepare_self_hide_commit.
    if (g_image_base && g_image_size && (g_image_base + g_image_size) > g_image_base)
        PayloadBridgeAppendLegacyProtectRange(g_image_base, g_image_base + g_image_size);

    payload_u64 delay_us = ctx->rcx ? ctx->rcx : 100ull;
    payload_u64 threshold = (payload_u64)__rdtsc() + (3000000000ull * delay_us) / 1000000ull;

    payload_u64 threshold_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_tsc_threshold, 0);
    payload_u64 bitmap_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_vcpu_bitmap, 0);
    payload_u64 count_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_count, 0);
    if (!PayloadIsKernelPointer(threshold_field) ||
        !PayloadIsKernelPointer(bitmap_field) ||
        !PayloadIsKernelPointer(count_field))
    {
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    PayloadWriteHostU64(threshold_field, threshold);

    payload_u64 ncpus = g_cached_hv_diag.vcpu_count;
    payload_u64 bitmap = 0;
    if (ncpus >= 64ull)
        bitmap = ~0ull;
    else if (ncpus)
        bitmap = (1ull << ncpus) - 1ull;

    _InterlockedExchange64((volatile LONG64*)bitmap_field, (LONG64)bitmap);
    return PayloadBridgeCompleteHypercall(ctx, code, PayloadReadHostU32(count_field));
}

static payload_u64 PayloadBridgeHandleGetPoolBlocks(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 out_gva = ctx->rcx;
    payload_u64 max = ctx->rdx;
    if (!out_gva || !max)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    payload_u64 manifest = g_resident_pool_manifest;
    payload_u64 count = g_resident_pool_count;
    if (!PayloadIsKernelPointer(manifest) || !count)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    if (g_resident_pool_capacity && count > g_resident_pool_capacity)
        count = g_resident_pool_capacity;
    if (count > max)
        count = max;
    if (count > 4096ull)
        count = 4096ull;

    payload_u64 guest_cr3 = 0;
    PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3);

    payload_u64 written = 0;
    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_pool_block rec = {};
        payload_u64 entry = manifest + i * (payload_u64)sizeof(payload_pool_block);
        rec.va = PayloadReadHostU64(entry + offsetof(payload_pool_block, va));
        rec.bytes = PayloadReadHostU64(entry + offsetof(payload_pool_block, bytes));
        rec.tag = PayloadReadHostU32(entry + offsetof(payload_pool_block, tag));
        rec.flags = PayloadReadHostU32(entry + offsetof(payload_pool_block, flags));

        payload_u64 dst = out_gva + i * (payload_u64)sizeof(payload_pool_block);
        bool copied = guest_cr3 &&
            PayloadGuestCopyFromHostBuffer(guest_cr3, dst, &rec, sizeof(rec));
        if (!copied && g_system_cr3 && g_system_cr3 != guest_cr3)
            copied = PayloadGuestCopyFromHostBuffer(g_system_cr3, dst, &rec, sizeof(rec));
        if (!copied)
        {
            _InterlockedIncrement64((volatile LONG64*)&g_hv_diag_gva_fail);
            break;
        }

        ++written;
    }

    return PayloadBridgeCompleteHypercall(ctx, code, written);
}

static payload_u64 PayloadBridgeHandleGetHideDiag(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    if (!ctx->rcx)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    payload_u64 ghv = g_cached_hv_diag.ghv;
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(ghv))
        return 0;

    payload_u64 off_enter = g_cached_hv_diag.ghv_off_diag_hide_enter;
    payload_u64 off_total = g_cached_hv_diag.ghv_off_diag_hide_pte_total;
    payload_u64 off_null = g_cached_hv_diag.ghv_off_diag_hide_pte_null;
    payload_u64 off_done = g_cached_hv_diag.ghv_off_diag_hide_done_bitmap;
    payload_u64 off_ept_used = g_cached_hv_diag.vcpu_off_ept_num_used_free_pages;
    if (!off_enter || !off_total || !off_null || !off_done || !off_ept_used)
        return 0;

    auto out = (payload_u64*)PayloadGvaToHva(ctx->rcx, sizeof(payload_u64) * 6);
    if (!out)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_diag_fail);
        return 0;
    }

    payload_u64 max_used = 0;
    if (g_cached_hv_diag.vcpus && g_hv_diag_vcpu_stride)
    {
        payload_u64 count = g_cached_hv_diag.vcpu_count;
        if (count > PAYLOAD_EPT_MAX_TRACKED_VCPUS)
            count = PAYLOAD_EPT_MAX_TRACKED_VCPUS;

        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_u64 vcpu_ptr = g_cached_hv_diag.vcpus + i * g_hv_diag_vcpu_stride;
            if (!PayloadIsKernelPointer(vcpu_ptr + off_ept_used))
                continue;

            payload_u64 used = PayloadReadHostU64(vcpu_ptr + off_ept_used);
            if (used > max_used)
                max_used = used;
        }
    }

    out[0] = PayloadReadHostU64(ghv + off_enter);
    out[1] = PayloadReadHostU64(ghv + off_total);
    out[2] = PayloadReadHostU64(ghv + off_null);
    out[3] = PayloadReadHostU64(ghv + off_done);
    out[4] = max_used;
    out[5] = g_cached_hv_diag.ept_free_page_count ? g_cached_hv_diag.ept_free_page_count : 0x1000ull;
    g_bridge_self_hide_diag_max_used = max_used;

    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleGetPhysicalAddress(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 cr3 = ctx->rcx ? ctx->rcx : g_system_cr3;
    if (!cr3)
        PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &cr3);

    payload_u64 gva = ctx->rdx;
    payload_u64 gpa = 0;
    payload_u64 bytes_left = 0;
    bool ok = cr3 && PayloadGvaToGpa(cr3, gva, &gpa, &bytes_left);

    g_bridge_self_get_pa_last_cr3 = cr3;
    g_bridge_self_get_pa_last_gva = gva;
    g_bridge_self_get_pa_last_gpa = ok ? gpa : 0;
    if (!ok)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_get_pa_fail);

    return PayloadBridgeCompleteHypercall(ctx, code, ok ? gpa : 0);
}

static payload_u64 PayloadBridgeHandleReadPhysMem(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 copied = PayloadBridgeCopyPhysToGuest(ctx->rcx, ctx->rdx, ctx->r8);
    if (copied != ctx->r8)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_mem_fail);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_mem_bytes, (LONG64)copied);
    return PayloadBridgeCompleteHypercall(ctx, code, copied);
}

static payload_u64 PayloadBridgeHandleWritePhysMem(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 copied = PayloadBridgeCopyGuestToPhys(ctx->rcx, ctx->rdx, ctx->r8);
    if (copied != ctx->r8)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_mem_fail);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_mem_bytes, (LONG64)copied);
    return PayloadBridgeCompleteHypercall(ctx, code, copied);
}

static payload_u64 PayloadBridgeHandleReadVirtMem(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 cr3 = ctx->rcx ? ctx->rcx : g_system_cr3;
    payload_u64 copied = PayloadBridgeCopyVirtToGuest(cr3, ctx->r8, ctx->rdx, ctx->r9);
    if (copied != ctx->r9)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_mem_fail);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_mem_bytes, (LONG64)copied);
    return PayloadBridgeCompleteHypercall(ctx, code, copied);
}

static payload_u64 PayloadBridgeHandleWriteVirtMem(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 cr3 = ctx->rcx ? ctx->rcx : g_system_cr3;
    payload_u64 copied = PayloadBridgeCopyGuestToVirt(cr3, ctx->rdx, ctx->r8, ctx->r9);
    if (copied != ctx->r9)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_mem_fail);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_mem_bytes, (LONG64)copied);
    return PayloadBridgeCompleteHypercall(ctx, code, copied);
}

static payload_u64 PayloadBridgeHandleQueryProcessCr3(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 target_pid = ctx->rcx;
    payload_u64 result = 0;
    bool ok = false;

    g_bridge_self_query_cr3_last_pid = target_pid;

    if (target_pid == 4)
    {
        result = g_system_cr3;
        ok = result != 0;
    }
    else
    {
        payload_u64 system_eprocess = g_cached_hv_diag.system_eprocess;
        payload_u64 pid_off = g_cached_hv_diag.eprocess_unique_process_id_offset;
        payload_u64 dirbase_off = g_cached_hv_diag.kprocess_directory_table_base_offset;
        payload_u64 apl_off = pid_off + sizeof(payload_u64);

        if (g_system_cr3 &&
            PayloadIsKernelPointer(system_eprocess) &&
            pid_off &&
            dirbase_off &&
            pid_off < 0x4000ull &&
            dirbase_off < 0x4000ull)
        {
            payload_u64 head = system_eprocess + apl_off;
            payload_u64 curr = head;

            for (payload_u64 i = 0; i < 0x10000ull; ++i)
            {
                if (!PayloadReadSystemVa64(curr, &curr) || !PayloadIsKernelPointer(curr))
                    break;
                if (curr == head)
                    break;

                payload_u64 process = curr - apl_off;
                payload_u64 pid = 0;
                if (!PayloadReadSystemVa64(process + pid_off, &pid))
                    break;

                if (pid == target_pid)
                {
                    if (PayloadReadSystemVa64(process + dirbase_off, &result) && result)
                        ok = true;
                    break;
                }
            }
        }
    }

    g_bridge_self_query_cr3_last_cr3 = ok ? result : 0;
    if (!ok)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_query_cr3_fail);

    return PayloadBridgeCompleteHypercall(ctx, code, ok ? result : 0);
}

static payload_u64 PayloadBridgeHandleGetInfo(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    if (!ctx->rcx)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_get_info_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 real_cr3 = 0;
    if (PayloadIsKernelPointer(g_cached_hv_diag.ghv) &&
        g_cached_hv_diag.ghv_off_cr3_map_real_cr3)
    {
        real_cr3 = PayloadReadHostU64(g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_cr3_map_real_cr3);
    }
    g_payload_real_cr3 = real_cr3;

    auto out = (payload_u64*)PayloadGvaToHva(ctx->rcx, sizeof(payload_u64));
    if (!out)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_get_info_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    *out = real_cr3;
    return PayloadBridgeCompleteHypercall(ctx, code, sizeof(payload_u64));
}

static payload_u64 PayloadBridgeHandleSaveGameVtImageBase(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    if (g_payload_legacy_ptrs_finalized)
    {
        g_payload_gamevt_image_base = 0;
        g_payload_gamevt_driver_unload = 0;
        g_cached_hv_diag.image_base = 0;
        g_cached_hv_diag.driver_unload = 0;
        g_legacy_gamevt_image_base_shadow = 0;
        g_legacy_gamevt_driver_unload_shadow = 0;
        PayloadRedirectCachedLegacyPointersToShadows();
        return PayloadBridgeCompleteHypercall(ctx, code, 1);
    }

    g_payload_gamevt_image_base = ctx->rcx;
    g_payload_gamevt_driver_unload = ctx->rdx;
    g_cached_hv_diag.image_base = ctx->rcx;
    g_cached_hv_diag.driver_unload = ctx->rdx;

    if (PayloadIsKernelPointer(g_cached_hv_diag.gamevt_image_base_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.gamevt_image_base_ptr, ctx->rcx);
    if (PayloadIsKernelPointer(g_cached_hv_diag.gamevt_driver_unload_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.gamevt_driver_unload_ptr, ctx->rdx);

    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleGetGameVtImageBase(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    if (!ctx->rcx)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    auto out = (payload_u64*)PayloadGvaToHva(ctx->rcx, sizeof(payload_u64) * 2);
    if (!out)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_gamevt_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 image_base = g_payload_gamevt_image_base ? g_payload_gamevt_image_base : g_cached_hv_diag.image_base;
    payload_u64 driver_unload = g_payload_gamevt_image_base ? g_payload_gamevt_driver_unload : g_cached_hv_diag.driver_unload;
    out[0] = image_base;
    out[1] = driver_unload;

    return PayloadBridgeCompleteHypercall(ctx, code, sizeof(payload_u64) * 2);
}

static payload_u64 PayloadBridgeHandleSetKeepHvOnUnload(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    if (g_payload_legacy_ptrs_finalized)
    {
        payload_u64 flags = g_payload_keep_hv_flags;
        if (ctx->rcx)
        {
            g_payload_unload_quiesce = 0;
            flags |= PAYLOAD_YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
        }
        else
        {
            g_payload_unload_quiesce = 1;
            flags &= ~PAYLOAD_YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
        }

        g_payload_keep_hv_flags = flags;
        g_legacy_yvt_boot_flags_shadow = flags;
        PayloadRedirectCachedLegacyPointersToShadows();
        return PayloadBridgeCompleteHypercall(ctx, code, 1);
    }

    payload_u64 ptr = g_cached_hv_diag.yvt_boot_flags_ptr;
    if (!PayloadIsKernelPointer(ptr))
        return 0;

    payload_u64 flags = PayloadReadHostU64(ptr);
    if (ctx->rcx)
        g_payload_unload_quiesce = 0;
    else
    {
        g_payload_unload_quiesce = 1;
    }

    if (ctx->rcx)
        flags |= PAYLOAD_YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
    else
        flags &= ~PAYLOAD_YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;

    PayloadWriteHostU64(ptr, flags);
    g_payload_keep_hv_flags = flags;
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

// ---------------------------------------------------------------------------
// Payload-resident debug dispatch
//
// This is the generic debug framework layer, not sjz business logic.  It is
// intentionally self-contained in the resident payload: sessions, memory
// translation/read, event ring, and payload-owned EPT watch state.

static constexpr unsigned int PAYLOAD_DBG_MAGIC = 0x56444247u; // 'VDBG'
static constexpr unsigned short PAYLOAD_DBG_ABI_VERSION = 1;
static constexpr unsigned int PAYLOAD_DBG_MAX_SESSIONS = 8;
static constexpr unsigned int PAYLOAD_DBG_EVENT_RING_CAP = 256;
static constexpr unsigned int PAYLOAD_DBG_EVENT_POLL_MAX = 128;
static constexpr unsigned int PAYLOAD_DBG_MAX_READ_SIZE = 0x100000;
static constexpr unsigned int PAYLOAD_DBG_MAX_BATCH_ITEMS = 256;
static constexpr unsigned int PAYLOAD_DBG_MAX_BATCH_ITEM_SIZE = 0x4000;
static constexpr unsigned int PAYLOAD_DBG_MAX_BATCH_DATA_SIZE = 0x100000;
static constexpr unsigned int PAYLOAD_DBG_DUMP_DEFAULT_CHUNK = 0x10000;
static constexpr unsigned int PAYLOAD_DBG_WATCH_CAPACITY = 64;
static constexpr unsigned int PAYLOAD_DBG_WATCH_PAGE_CAPACITY = 512;
static constexpr unsigned int PAYLOAD_DBG_WATCH_MAX_PAGES = 64;
static constexpr unsigned int PAYLOAD_DBG_WATCH_MAX_EVENTS_PER_VIOLATION = 8;
static constexpr payload_u64 PAYLOAD_DBG_WATCH_DEFAULT_MAX_EVENTS = 100000;
static constexpr unsigned int PAYLOAD_DBG_WATCH_DEFAULT_MAX_EVENTS_PER_SEC = 2000;
static constexpr payload_u64 PAYLOAD_DBG_WATCH_RATE_WINDOW_TSC = 3000000000ull;
static constexpr unsigned int PAYLOAD_DBG_WATCH_UNLIMITED_EVENTS_PER_SEC = 0xFFFFFFFFu;
static constexpr unsigned int PAYLOAD_DBG_EXEC_PROBE_SLOT_COUNT = 16;
static constexpr unsigned int PAYLOAD_DBG_EXEC_PROBE_HIT_COUNT = 256;
static constexpr unsigned int PAYLOAD_DBG_EXEC_PROBE_STACK_QWORDS = 16;

