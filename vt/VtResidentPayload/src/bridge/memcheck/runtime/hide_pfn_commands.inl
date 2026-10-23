// Split from memcheck_runtime.inl: runtime/hide_pfn_commands.inl.
// Included through the wrapper; same translation unit.

static void PayloadBridgeAddGhvCounter(payload_u64 dynamic_offset, payload_u64 value)
{
    if (!value)
        return;

    payload_u64 field = PayloadDiagGhvField(dynamic_offset, 0);
    if (!PayloadIsKernelPointer(field))
        return;

    _InterlockedExchangeAdd64((volatile LONG64*)field, (LONG64)value);
}

static bool PayloadBridgeReadGuestU64(payload_u64 guest_cr3, payload_u64 gva, payload_u64* value)
{
    if (!value || !guest_cr3 || !gva)
        return false;

    payload_u64 left = 0;
    auto hva = (const payload_u64*)PayloadGvaToHvaCr3(guest_cr3, gva, &left);
    if (hva && left >= sizeof(payload_u64))
    {
        *value = *(volatile const payload_u64*)hva;
        return true;
    }

    payload_u64 tmp = 0;
    if (PayloadDbgCopyFromGuest(gva, &tmp, sizeof(tmp)) != sizeof(tmp))
        return false;

    *value = tmp;
    return true;
}

static bool PayloadBridgeHideOnePfn(payload_u64 vcpu_ptr,
                                    payload_u64 dummy_pfn,
                                    payload_u64 pfn,
                                    payload_u64* pte_null)
{
    if (!pfn)
        return false;

    g_bridge_self_hide_pfn_last_pfn = pfn;

    payload_u64 gpa = pfn << 12;
    if ((gpa >> 12) != pfn)
    {
        if (pte_null)
            ++(*pte_null);
        return false;
    }

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (!PayloadDbgWatchLocatePteForVcpu(vcpu_ptr, gpa, true, &pte_va, &before))
    {
        if (pte_null)
            ++(*pte_null);
        return false;
    }

    payload_u64 after = PayloadEptEntryWithPfnPerms(
        before,
        dummy_pfn,
        (before & 0x1ull) != 0,
        (before & 0x2ull) != 0,
        (before & 0x4ull) != 0);
    PayloadWriteHostU64(pte_va, after);

    g_bridge_self_hide_pfn_last_pte_va = pte_va;
    g_bridge_self_hide_pfn_last_pte_before = before;
    g_bridge_self_hide_pfn_last_pte_after = after;
    return true;
}

static bool PayloadBridgeUnhideOnePfn(payload_u64 vcpu_ptr,
                                      payload_u64 pfn,
                                      payload_u64* pte_null)
{
    if (!pfn)
        return false;

    g_bridge_self_hide_pfn_last_pfn = pfn;

    payload_u64 gpa = pfn << 12;
    if ((gpa >> 12) != pfn)
    {
        if (pte_null)
            ++(*pte_null);
        return false;
    }

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (!PayloadDbgWatchLocatePteForVcpu(vcpu_ptr, gpa, false, &pte_va, &before))
    {
        if (pte_null)
            ++(*pte_null);
        return false;
    }

    payload_u64 after = PayloadEptEntryWithPfnPerms(
        before,
        pfn,
        (before & 0x1ull) != 0,
        (before & 0x2ull) != 0,
        (before & 0x4ull) != 0);
    PayloadWriteHostU64(pte_va, after);

    g_bridge_self_hide_pfn_last_pte_va = pte_va;
    g_bridge_self_hide_pfn_last_pte_before = before;
    g_bridge_self_hide_pfn_last_pte_after = after;
    return true;
}

static bool PayloadBridgeSetSystemCr3PageNxForPfn(payload_u64 base,
                                                  payload_u64 size,
                                                  payload_u64 target_pfn,
                                                  bool set_nx)
{
#if PAYLOAD_WORKER_AUTOSTART || PAYLOAD_RESIDENT_CTL_ENABLED
    UNREFERENCED_PARAMETER(base);
    UNREFERENCED_PARAMETER(size);
    UNREFERENCED_PARAMETER(target_pfn);
    UNREFERENCED_PARAMETER(set_nx);
    return false;
#else
    if (!g_system_cr3 || !base || !size || !target_pfn)
        return false;

    payload_u64 begin = base & ~0xFFFull;
    payload_u64 end = (base + size + 0xFFFull) & ~0xFFFull;
    if (end <= begin)
        return false;

    payload_u64 pml4 = g_system_cr3 & 0x000FFFFFFFFFF000ull;
    bool modified = false;

    for (payload_u64 va = begin; va < end; va += PAGE_SIZE)
    {
        payload_u64 pml4_idx = (va >> 39) & 0x1FFull;
        payload_u64 pdpt_idx = (va >> 30) & 0x1FFull;
        payload_u64 pd_idx = (va >> 21) & 0x1FFull;
        payload_u64 pt_idx = (va >> 12) & 0x1FFull;

        payload_u64 pml4e = 0;
        if (!PayloadReadPhys64(pml4 + pml4_idx * sizeof(payload_u64), &pml4e) || !(pml4e & 1ull))
            continue;

        payload_u64 pdpt = pml4e & 0x000FFFFFFFFFF000ull;
        payload_u64 pdpte = 0;
        if (!PayloadReadPhys64(pdpt + pdpt_idx * sizeof(payload_u64), &pdpte) ||
            !(pdpte & 1ull) ||
            (pdpte & (1ull << 7)))
        {
            continue;
        }

        payload_u64 pd = pdpte & 0x000FFFFFFFFFF000ull;
        payload_u64 pde = 0;
        if (!PayloadReadPhys64(pd + pd_idx * sizeof(payload_u64), &pde) ||
            !(pde & 1ull) ||
            (pde & (1ull << 7)))
        {
            continue;
        }

        payload_u64 pt = pde & 0x000FFFFFFFFFF000ull;
        payload_u64 pte_pa = pt + pt_idx * sizeof(payload_u64);
        payload_u64 pte = 0;
        if (!PayloadReadPhys64(pte_pa, &pte) || !(pte & 1ull))
            continue;

        payload_u64 pte_pfn = (pte & 0x000FFFFFFFFFF000ull) >> 12;
        if (pte_pfn != target_pfn)
            continue;

        payload_u64 new_pte = set_nx ? (pte | (1ull << 63)) : (pte & ~(1ull << 63));
        if (new_pte != pte && PayloadWritePhys64(pte_pa, new_pte))
        {
            payload_u64 vpid = 0;
            if (PayloadVmread(PAYLOAD_VMCS_CTRL_VPID, &vpid) && vpid)
            {
                __declspec(align(16)) payload_invvpid_descriptor desc = {};
                desc.vpid_and_reserved = vpid & 0xFFFFull;
                desc.linear_address = va;
                PayloadInvvpid(PAYLOAD_INVVPID_INDIVIDUAL_ADDRESS, &desc);
            }
            modified = true;
        }
    }

    return modified;
#endif
}

static bool PayloadBridgeHideOnePfnAllVcpus(payload_u64 current_vcpu,
                                            payload_u64 default_dummy_pfn,
                                            payload_u64 pfn,
                                            payload_u64* pte_null)
{
    bool any_ok = false;
    if (!g_hv_diag_cache_ready ||
        !PayloadIsKernelPointer(g_cached_hv_diag.vcpus) ||
        !g_hv_diag_vcpu_stride ||
        !g_cached_hv_diag.vcpu_count)
    {
        any_ok = PayloadBridgeHideOnePfn(current_vcpu, default_dummy_pfn, pfn, pte_null);
    }
    else
    {
        payload_u64 vcpu_count = PayloadMinU64(g_cached_hv_diag.vcpu_count, PAYLOAD_EPT_MAX_TRACKED_VCPUS);
        for (payload_u64 i = 0; i < vcpu_count; ++i)
        {
            payload_u64 vcpu_ptr = PayloadDbgWatchVcpuPtrByIndex(i);
            if (!PayloadIsKernelPointer(vcpu_ptr))
                continue;

            payload_u64 dummy_pfn = default_dummy_pfn;
            if (g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn &&
                PayloadIsKernelPointer(vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn))
            {
                payload_u64 vcpu_dummy = PayloadReadHostU64(
                    vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn);
                if (vcpu_dummy)
                    dummy_pfn = vcpu_dummy;
            }

            if (PayloadBridgeHideOnePfn(
                    vcpu_ptr,
                    dummy_pfn,
                    pfn,
                    (vcpu_ptr == current_vcpu) ? pte_null : nullptr))
            {
                any_ok = true;
            }
        }
    }

    if (any_ok)
        PayloadBridgeSetSystemCr3PageNxForPfn(g_image_base, g_image_size, pfn, true);
    return any_ok;
}

static bool PayloadBridgeUnhideOnePfnAllVcpus(payload_u64 current_vcpu,
                                              payload_u64 pfn,
                                              payload_u64* pte_null)
{
    PayloadBridgeSetSystemCr3PageNxForPfn(g_image_base, g_image_size, pfn, false);

    if (!g_hv_diag_cache_ready ||
        !PayloadIsKernelPointer(g_cached_hv_diag.vcpus) ||
        !g_hv_diag_vcpu_stride ||
        !g_cached_hv_diag.vcpu_count)
    {
        return PayloadBridgeUnhideOnePfn(current_vcpu, pfn, pte_null);
    }

    payload_u64 vcpu_count = PayloadMinU64(g_cached_hv_diag.vcpu_count, PAYLOAD_EPT_MAX_TRACKED_VCPUS);
    bool any_ok = false;
    for (payload_u64 i = 0; i < vcpu_count; ++i)
    {
        payload_u64 vcpu_ptr = PayloadDbgWatchVcpuPtrByIndex(i);
        if (!PayloadIsKernelPointer(vcpu_ptr))
            continue;

        if (PayloadBridgeUnhideOnePfn(
                vcpu_ptr,
                pfn,
                (vcpu_ptr == current_vcpu) ? pte_null : nullptr))
        {
            any_ok = true;
        }
    }
    return any_ok;
}

static payload_u64 PayloadBridgeHandleUnhidePhysicalPage(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 pfn = ctx->rcx;
    g_bridge_self_hide_pfn_last_count = pfn ? 1 : 0;
    g_bridge_self_hide_pfn_last_hidden = 0;
    g_bridge_self_hide_pfn_last_vcpu = PayloadCurrentVcpuIndex();

    payload_u64 current_vcpu = PayloadCurrentVcpuPtr();
    if (!PayloadIsKernelPointer(current_vcpu) || !pfn)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 pte_null = 0;
    payload_u64 done = PayloadBridgeUnhideOnePfnAllVcpus(current_vcpu, pfn, &pte_null) ? 1 : 0;
    if (!done)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);

    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_requested, 1);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_hidden, (LONG64)done);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_null, (LONG64)pte_null);
    g_bridge_self_hide_pfn_last_hidden = done;

    PayloadDbgWatchInveptAll();
    return PayloadBridgeCompleteHypercall(ctx, code, done);
}

static payload_u64 PayloadBridgeHandleHidePhysicalPage(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    payload_u64 pfn = ctx->rcx;
    g_bridge_self_hide_pfn_last_count = pfn ? 1 : 0;
    g_bridge_self_hide_pfn_last_hidden = 0;
    g_bridge_self_hide_pfn_last_vcpu = PayloadCurrentVcpuIndex();

    payload_u64 current_vcpu = PayloadCurrentVcpuPtr();
    if (!PayloadIsKernelPointer(current_vcpu) ||
        !pfn ||
        !g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn ||
        !PayloadIsKernelPointer(current_vcpu + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 dummy_pfn = PayloadReadHostU64(
        current_vcpu + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn);
    if (!dummy_pfn)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 pte_null = 0;
    payload_u64 done = PayloadBridgeHideOnePfnAllVcpus(current_vcpu, dummy_pfn, pfn, &pte_null) ? 1 : 0;
    if (!done)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);

    _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_list);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_requested, 1);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_hidden, (LONG64)done);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_null, (LONG64)pte_null);
    g_bridge_self_hide_pfn_last_hidden = done;

    PayloadDbgWatchInveptAll();
    return PayloadBridgeCompleteHypercall(ctx, code, done);
}

static payload_u64 PayloadBridgeHandleHidePfnList(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_list);

    payload_u64 pfn_array_gva = ctx->rcx;
    payload_u64 count = ctx->rdx;
    if (!pfn_array_gva || !count)
    {
        g_bridge_self_hide_pfn_last_count = count;
        g_bridge_self_hide_pfn_last_hidden = 0;
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    static constexpr payload_u64 PAYLOAD_HIDE_PFN_MAX_COUNT = 256ull * 1024ull;
    if (count > PAYLOAD_HIDE_PFN_MAX_COUNT)
        count = PAYLOAD_HIDE_PFN_MAX_COUNT;

    g_bridge_self_hide_pfn_last_count = count;
    g_bridge_self_hide_pfn_last_hidden = 0;
    g_bridge_self_hide_pfn_last_vcpu = PayloadCurrentVcpuIndex();

    payload_u64 current_vcpu = PayloadCurrentVcpuPtr();
    if (!PayloadIsKernelPointer(current_vcpu) ||
        !g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn ||
        !PayloadIsKernelPointer(current_vcpu + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 dummy_pfn = PayloadReadHostU64(
        current_vcpu + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn);
    if (!dummy_pfn)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 hidden = 0;
    payload_u64 pte_null = 0;
    payload_u64 idx = 0;
    while (idx < count)
    {
        payload_u64 chunk_gva = pfn_array_gva + idx * sizeof(payload_u64);
        if (chunk_gva < pfn_array_gva)
            break;

        payload_u64 left = 0;
        auto chunk_hva = (const payload_u64*)PayloadGvaToHvaCr3(guest_cr3, chunk_gva, &left);
        if (!chunk_hva || !left)
        {
            _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
            break;
        }

        if (left < sizeof(payload_u64))
        {
            payload_u64 pfn = 0;
            if (!PayloadBridgeReadGuestU64(guest_cr3, chunk_gva, &pfn))
            {
                _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
                break;
            }

            if (PayloadBridgeHideOnePfnAllVcpus(current_vcpu, dummy_pfn, pfn, &pte_null))
                ++hidden;
            ++idx;
            continue;
        }

        payload_u64 room = left / sizeof(payload_u64);
        payload_u64 this_chunk = PayloadMinU64(count - idx, room);
        if (!this_chunk)
            break;

        for (payload_u64 k = 0; k < this_chunk; ++k)
        {
            payload_u64 pfn = *(volatile const payload_u64*)(chunk_hva + k);
            if (PayloadBridgeHideOnePfnAllVcpus(current_vcpu, dummy_pfn, pfn, &pte_null))
                ++hidden;
        }

        idx += this_chunk;
    }

    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_requested, (LONG64)count);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_hidden, (LONG64)hidden);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_null, (LONG64)pte_null);
    g_bridge_self_hide_pfn_last_hidden = hidden;

    PayloadBridgeAddGhvCounter(g_cached_hv_diag.ghv_off_diag_hide_pte_total, count);
    PayloadBridgeAddGhvCounter(g_cached_hv_diag.ghv_off_diag_hide_pte_null, pte_null);
    PayloadDbgWatchInveptAll();

    return PayloadBridgeCompleteHypercall(ctx, code, hidden);
}

static payload_u64 PayloadBridgeHandleUnhidePfnList(payload_guest_context* ctx, payload_u64 code)
{
    if (!ctx)
        return 0;

    _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_list);

    payload_u64 pfn_array_gva = ctx->rcx;
    payload_u64 count = ctx->rdx;
    if (!pfn_array_gva || !count)
    {
        g_bridge_self_hide_pfn_last_count = count;
        g_bridge_self_hide_pfn_last_hidden = 0;
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    static constexpr payload_u64 PAYLOAD_HIDE_PFN_MAX_COUNT = 256ull * 1024ull;
    if (count > PAYLOAD_HIDE_PFN_MAX_COUNT)
        count = PAYLOAD_HIDE_PFN_MAX_COUNT;

    g_bridge_self_hide_pfn_last_count = count;
    g_bridge_self_hide_pfn_last_hidden = 0;
    g_bridge_self_hide_pfn_last_vcpu = PayloadCurrentVcpuIndex();

    payload_u64 current_vcpu = PayloadCurrentVcpuPtr();
    if (!PayloadIsKernelPointer(current_vcpu))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 done = 0;
    payload_u64 pte_null = 0;
    payload_u64 idx = 0;
    while (idx < count)
    {
        payload_u64 chunk_gva = pfn_array_gva + idx * sizeof(payload_u64);
        if (chunk_gva < pfn_array_gva)
            break;

        payload_u64 left = 0;
        auto chunk_hva = (const payload_u64*)PayloadGvaToHvaCr3(guest_cr3, chunk_gva, &left);
        if (!chunk_hva || !left)
        {
            _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
            break;
        }

        if (left < sizeof(payload_u64))
        {
            payload_u64 pfn = 0;
            if (!PayloadBridgeReadGuestU64(guest_cr3, chunk_gva, &pfn))
            {
                _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_pfn_fail);
                break;
            }

            if (PayloadBridgeUnhideOnePfnAllVcpus(current_vcpu, pfn, &pte_null))
                ++done;
            ++idx;
            continue;
        }

        payload_u64 room = left / sizeof(payload_u64);
        payload_u64 this_chunk = PayloadMinU64(count - idx, room);
        if (!this_chunk)
            break;

        for (payload_u64 k = 0; k < this_chunk; ++k)
        {
            payload_u64 pfn = *(volatile const payload_u64*)(chunk_hva + k);
            if (PayloadBridgeUnhideOnePfnAllVcpus(current_vcpu, pfn, &pte_null))
                ++done;
        }

        idx += this_chunk;
    }

    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_requested, (LONG64)count);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_hidden, (LONG64)done);
    _InterlockedExchangeAdd64((volatile LONG64*)&g_bridge_self_hide_pfn_null, (LONG64)pte_null);
    g_bridge_self_hide_pfn_last_hidden = done;

    PayloadDbgWatchInveptAll();
    return PayloadBridgeCompleteHypercall(ctx, code, done);
}
