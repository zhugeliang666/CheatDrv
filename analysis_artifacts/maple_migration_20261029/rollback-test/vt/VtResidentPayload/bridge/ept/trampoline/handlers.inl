// Split from ept_trampoline.inl: trampoline/handlers.inl.
// Included through the wrapper; same translation unit.

static bool PayloadBridgeWriteLegacyMmrMtfState(payload_u64 pte_pa,
                                                payload_u64 mode,
                                                payload_u64 page_frame)
{
    payload_u64 vcpu = PayloadCurrentVcpuPtr();
    if (!PayloadIsKernelPointer(vcpu) ||
        !g_cached_hv_diag.vcpu_off_ept_mmr_mtf_pte ||
        !g_cached_hv_diag.vcpu_off_ept_mmr_mtf_mode ||
        !g_cached_hv_diag.vcpu_off_ept_mmr_mtf_page_frame)
    {
        return false;
    }

    payload_u64 pte_field = vcpu + g_cached_hv_diag.vcpu_off_ept_mmr_mtf_pte;
    payload_u64 mode_field = vcpu + g_cached_hv_diag.vcpu_off_ept_mmr_mtf_mode;
    payload_u64 frame_field = vcpu + g_cached_hv_diag.vcpu_off_ept_mmr_mtf_page_frame;
    if (!PayloadIsKernelPointer(pte_field) ||
        !PayloadIsKernelPointer(mode_field) ||
        !PayloadIsKernelPointer(frame_field))
    {
        return false;
    }

    payload_u64 pte_hva = pte_pa ? (PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pte_pa) : 0;
    if (pte_pa && !PayloadHostPhysicalRangeMapped(pte_pa, sizeof(payload_u64)))
        return false;

    PayloadWriteHostU64(pte_field, pte_hva);
    PayloadWriteHostU8(mode_field, (unsigned char)mode);
    PayloadWriteHostU64(frame_field, page_frame);
    return true;
}

static void PayloadBridgeClearLegacyMmrMtfState()
{
    PayloadBridgeWriteLegacyMmrMtfState(0, 0, 0);
}

static payload_u64 PayloadBridgeHandleEptMtf(payload_guest_context* ctx, payload_u64 reason)
{
    UNREFERENCED_PARAMETER(reason);

    if (PayloadDbgWatchPendingActive())
    {
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_DBG_PENDING_FORWARD;
        return 0;
    }

    payload_u64 vcpu_index = PayloadCurrentVcpuIndex();
    g_payload_ept_tramp_last_vcpu = vcpu_index;
    if (vcpu_index >= PAYLOAD_EPT_MAX_TRACKED_VCPUS ||
        !g_payload_ept_mtf_active[vcpu_index])
    {
        return 0;
    }

    payload_u64 pte_pa = g_payload_ept_mtf_pte_pa[vcpu_index];
    payload_u64 restore_entry = g_payload_ept_mtf_restore_entry[vcpu_index];
    g_payload_ept_tramp_last_pte_pa = pte_pa;
    g_payload_ept_tramp_last_mtf_restore = restore_entry;

    bool ok = PayloadWritePhys64(pte_pa, restore_entry);
    bool mtf_ok = PayloadEptSetMtf(vcpu_index, false);
    g_payload_ept_mtf_active[vcpu_index] = 0;
    g_payload_ept_mtf_pte_pa[vcpu_index] = 0;
    g_payload_ept_mtf_restore_entry[vcpu_index] = 0;

    if (ok && mtf_ok)
    {
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_MTF_RESTORE;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_mtf_count);
        return 1;
    }

    g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_MTF_RESTORE_FAIL;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_mtf_fail_count);
    if (PayloadBridgeScheduleGuestBugCheck(
        ctx,
        PAYLOAD_VTPANIC_REASON_EPT_MTF_RESTORE_FAIL,
        pte_pa,
        restore_entry,
        (ok ? 1ull : 0ull) | (mtf_ok ? 2ull : 0ull) | ((vcpu_index & 0xFFFFull) << 16)))
    {
        return 1;
    }
    PayloadVtPanicBugCheck(
        PAYLOAD_VTPANIC_REASON_EPT_MTF_RESTORE_FAIL,
        pte_pa,
        restore_entry,
        (ok ? 1ull : 0ull) | (mtf_ok ? 2ull : 0ull) | ((vcpu_index & 0xFFFFull) << 16));
    return 0;
}

static payload_u64 PayloadBridgeProbeEptTrampoline(payload_guest_context* ctx, payload_u64 reason)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(reason);

    _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_probe_count);

    payload_u64 gpa = 0;
    payload_u64 gla = 0;
    payload_u64 qualification = 0;
    payload_u64 rip = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_PHYSICAL_ADDRESS, &gpa) ||
        !PayloadVmread(PAYLOAD_VMCS_EXIT_QUALIFICATION, &qualification) ||
        !PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &rip))
    {
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_VMREAD_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_scan_fail_count);
        return 0;
    }

    if (!PayloadVmread(PAYLOAD_VMCS_EXIT_GUEST_LINEAR_ADDRESS, &gla))
        gla = 0;

    g_payload_ept_tramp_last_gpa = gpa;
    g_payload_ept_tramp_last_gla = gla;
    g_payload_ept_tramp_last_rip = rip;
    g_payload_ept_tramp_last_qualification = qualification;

    if (PayloadDbgWatchOwnsGpaPage(gpa >> 12))
    {
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_DBG_WATCH_FORWARD;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_scan_fail_count);
        return 0;
    }

    payload_u64 gpa_pfn = gpa >> 12;
    payload_ept_tramp_match active_match = {};
    bool active_matched =
        PayloadEptGenericFindByCurrentVcpu(gpa_pfn, &active_match) &&
        active_match.orig_pfn &&
        active_match.exec_pfn;

    payload_ept_tramp_match pool_match = {};
    bool pool_matched =
        PayloadEptTrampFindByPool(gpa_pfn, &pool_match) &&
        pool_match.orig_pfn &&
        pool_match.exec_pfn;

    payload_ept_tramp_match match = {};
    bool matched = false;
    if (pool_matched)
    {
        // TestDriver parity: handle_ept_violation() is authoritative only
        // after find_ept_hook(cpu->ept, gpa_pfn) succeeds on the 当前 vCPU.
        // The trampoline pool is global metadata and can outlive/drift from a
        // per-vCPU active EPT node during deferred 安装, teardown, or retry.
        // Use it for user/kernel classification only after the 当前 vCPU's
        // active hook list confirms the same orig/exec PFNs.
        if (active_matched &&
            active_match.orig_pfn == pool_match.orig_pfn &&
            active_match.exec_pfn == pool_match.exec_pfn)
        {
            match = pool_match;
            match.is_fake_page = active_match.is_fake_page;
            matched = true;
        }
    }

    if (!matched && active_matched)
    {
        match = active_match;
        matched = true;
    }

    if (!matched)
    {
        if (g_payload_ept_tramp_last_reason != PAYLOAD_EPT_TRAMP_REASON_NO_DIAG &&
            g_payload_ept_tramp_last_reason != PAYLOAD_EPT_TRAMP_REASON_NO_POOL)
        {
            g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_NO_MATCH;
        }
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_scan_fail_count);
        return 0;
    }

    if (match.kind == 1)
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_MATCH_USER;
    else if (match.kind == 2)
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_MATCH_KERNEL;
    else if (match.is_fake_page)
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_MATCH_FAKE;
    else
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_MATCH_GENERIC;
    g_payload_ept_tramp_last_orig_pfn = match.orig_pfn;
    g_payload_ept_tramp_last_exec_pfn = match.exec_pfn;
    g_payload_ept_tramp_last_guest_page = match.guest_page;
    g_payload_ept_tramp_last_kind = match.kind;
    g_payload_ept_last_hook_node = match.page;
    g_payload_ept_last_is_fake = match.is_fake_page;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_match_count);
    if (match.kind == 1)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_user_match_count);
    else if (match.kind == 2)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_kernel_match_count);
    else
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_generic_match_count);
    if (match.is_fake_page)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_fake_match_count);

    if (g_payload_ept_mode != PAYLOAD_EPT_MODE_HANDLE_TRAMP ||
        g_payload_ept_tramp_match_count < PAYLOAD_EPT_HANDLE_WARMUP_MATCHES)
    {
        return 0;
    }

    bool exec_access = (qualification & 0x4ull) != 0;
    bool data_access = (qualification & 0x3ull) != 0;
    if (!exec_access && !data_access)
    {
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_NO_ACCESS;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_fail_count);
        return 0;
    }

    payload_u64 pte_pa = 0;
    payload_u64 before = 0;
    if (!PayloadEptLocatePte(gpa, &pte_pa, &before))
    {
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_NO_PTE;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_fail_count);
        return 0;
    }

    payload_u64 current_pfn = (before & PAYLOAD_EPT_PFN_MASK) >> 12;
    if (current_pfn != match.orig_pfn && current_pfn != match.exec_pfn)
    {
        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_BAD_PTE;
        g_payload_ept_tramp_last_pte_pa = pte_pa;
        g_payload_ept_tramp_last_pte_before = before;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_fail_count);
        return 0;
    }

    payload_u64 after = 0;
    payload_u64 vcpu_index = PayloadCurrentVcpuIndex();
    g_payload_ept_tramp_last_vcpu = vcpu_index;

    if (exec_access)
    {
        payload_u64 exec_pfn = match.is_fake_page ? match.orig_pfn : match.exec_pfn;
        after = PayloadEptEntryWithPfnPerms(before, exec_pfn, false, false, true);
        if (!PayloadWritePhys64(pte_pa, after))
        {
            g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_WRITE_FAIL;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_fail_count);
            return 0;
        }

        g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_HANDLE_EXEC;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_exec_count);
    }
    else
    {
        bool same_page =
            PayloadIsCanonical(gla) &&
            PayloadIsCanonical(rip) &&
            ((gla >> 12) == (rip >> 12));

        if (same_page)
        {
            if (vcpu_index >= PAYLOAD_EPT_MAX_TRACKED_VCPUS)
            {
                g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_BAD_VCPU;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_fail_count);
                return 0;
            }

            payload_u64 same_pfn = match.is_fake_page ? match.orig_pfn : match.exec_pfn;
            after = PayloadEptEntryWithPfnPerms(before, same_pfn, true, true, true);
            payload_u64 restore = PayloadEptEntryWithPfnPerms(before, same_pfn, false, false, true);
            if (!PayloadWritePhys64(pte_pa, after))
            {
                g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_WRITE_FAIL;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_fail_count);
                return 0;
            }

            bool legacy_mtf_armed = PayloadBridgeWriteLegacyMmrMtfState(
                pte_pa,
                0x3ull, // TestDriver mmr_memory_mode_r | mmr_memory_mode_w
                same_pfn);
            if (!legacy_mtf_armed)
            {
                g_payload_ept_mtf_pte_pa[vcpu_index] = pte_pa;
                g_payload_ept_mtf_restore_entry[vcpu_index] = restore;
                g_payload_ept_mtf_active[vcpu_index] = 1;
            }
            if (!PayloadEptSetMtf(vcpu_index, true))
            {
                PayloadWritePhys64(pte_pa, restore);
                if (legacy_mtf_armed)
                {
                    PayloadBridgeClearLegacyMmrMtfState();
                }
                else
                {
                    g_payload_ept_mtf_active[vcpu_index] = 0;
                    g_payload_ept_mtf_pte_pa[vcpu_index] = 0;
                    g_payload_ept_mtf_restore_entry[vcpu_index] = 0;
                }
                g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_MTF_ARM_FAIL;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_fail_count);
                return 0;
            }

            g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_HANDLE_SAME_PAGE;
            g_payload_ept_tramp_last_mtf_restore = restore;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_same_count);
        }
        else
        {
            payload_u64 data_pfn = match.is_fake_page ? match.exec_pfn : match.orig_pfn;
            after = PayloadEptEntryWithPfnPerms(before, data_pfn, true, true, false);
            if (!PayloadWritePhys64(pte_pa, after))
            {
                g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_WRITE_FAIL;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_fail_count);
                return 0;
            }

            g_payload_ept_tramp_last_reason = PAYLOAD_EPT_TRAMP_REASON_HANDLE_DATA;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_data_count);
        }
    }

    g_payload_ept_tramp_last_pte_pa = pte_pa;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = after;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_count);
    return 1;
}

