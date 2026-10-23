// Split from payload_bridge.inl: entry/bridge_entry.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static bool PayloadBridgeGetCurrentVcpu(payload_u64* vcpu_out, payload_u64* index_out)
{
    if (!vcpu_out ||
        !g_hv_diag_cache_ready ||
        !g_cached_hv_diag.vcpus ||
        !g_hv_diag_vcpu_stride)
    {
        return false;
    }

    payload_u64 vpid = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_VPID, &vpid) || !vpid)
        return false;

    payload_u64 idx = vpid - 1;
    if (g_cached_hv_diag.vcpu_count && idx >= g_cached_hv_diag.vcpu_count)
        return false;

    payload_u64 vcpu = g_cached_hv_diag.vcpus + idx * g_hv_diag_vcpu_stride;
    if (!PayloadIsKernelPointer(vcpu))
        return false;

    *vcpu_out = vcpu;
    if (index_out)
        *index_out = idx;
    return true;
}

static bool PayloadBridgeGetCurrentVcpuForPending(payload_u64* vcpu_out, payload_u64* index_out)
{
    // Payload PMO CallUser owns its pending HOST_RSP restore state privately.
    // Do not depend on, or modify, TestDriver's vcpu::pending_* fields here:
    // those fields may still be used by forwarded legacy hv::Call paths.
    return PayloadBridgeGetCurrentVcpu(vcpu_out, index_out);
}

extern "C" void PayloadBridgeSyncLegacyVcpuContext(void* guest_context)
{
    payload_u64 enter_tsc = (payload_u64)__rdtsc();
    payload_u64 fast_idx = 0;
    if (PayloadBridgeCurrentVcpuIdx(&fast_idx))
    {
        g_payload_tsc_enter[fast_idx] = enter_tsc;
        g_payload_tsc_hide_overhead[fast_idx] = 0;
    }

    if (!guest_context || !g_cached_hv_diag.vcpu_off_ctx)
        return;

    payload_u64 vcpu = 0;
    payload_u64 idx = 0;
    if (!PayloadBridgeGetCurrentVcpu(&vcpu, &idx))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_ctx_set_fail_count);
        return;
    }

    payload_u64 ctx_ptr = vcpu + g_cached_hv_diag.vcpu_off_ctx;
    if (!PayloadIsKernelPointer(ctx_ptr))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_ctx_set_fail_count);
        return;
    }

    PayloadWriteHostU64(ctx_ptr, (payload_u64)guest_context);
    g_payload_vmexit_ctx_set_last_vcpu = idx;
    g_payload_vmexit_ctx_set_last_ptr = (payload_u64)guest_context;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_ctx_set_count);
}

static void PayloadBridgeResetLegacyVcpuFlagsForVcpu(payload_u64 vcpu)
{
    if (!PayloadIsKernelPointer(vcpu) ||
        !g_cached_hv_diag.vcpu_off_hide_vm_exit_overhead ||
        !g_cached_hv_diag.vcpu_off_stop_virtualization)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_vcpu_reset_fail_count);
        return;
    }

    payload_u64 hide_field = vcpu + g_cached_hv_diag.vcpu_off_hide_vm_exit_overhead;
    payload_u64 stop_field = vcpu + g_cached_hv_diag.vcpu_off_stop_virtualization;
    if (!PayloadIsKernelPointer(hide_field) ||
        !PayloadIsKernelPointer(stop_field))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_vcpu_reset_fail_count);
        return;
    }

    // TestDriver parity: handle_vm_exit() clears these one-exit flags before
    // dispatch.  A stale stop_virtualization/hide flag from a previous handler
    // must not leak into the resident bridge path.
    PayloadWriteHostU8(hide_field, 0);
    PayloadWriteHostU8(stop_field, 0);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_vcpu_reset_count);
}

static void PayloadBridgeIncrementLegacyPerVcpuVmexit(payload_u64 idx)
{
    if (idx >= 16 || !g_cached_hv_diag.ghv_off_diag_per_vcpu_vmexits)
        return;

    payload_u64 base = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_diag_per_vcpu_vmexits, 0);
    payload_u64 field = base + idx * sizeof(payload_u64);
    if (!PayloadIsKernelPointer(base) || !PayloadIsKernelPointer(field))
        return;

    _InterlockedIncrement64((volatile LONG64*)field);
}

static void PayloadBridgeDrainLegacyPendingInvept(payload_u64 idx)
{
    if (idx >= 64 || !g_cached_hv_diag.ghv_off_pending_ept_invept_bitmap)
        return;

    payload_u64 field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_ept_invept_bitmap, 0);
    if (!PayloadIsKernelPointer(field))
        return;

    payload_u64 bit = 1ull << idx;
    payload_u64 bitmap = PayloadReadHostU64(field);
    if (!(bitmap & bit))
        return;

    PayloadDbgWatchInveptAll();
    _InterlockedAnd64((volatile LONG64*)field, ~(LONG64)bit);
    g_payload_vmexit_legacy_invept_last_bitmap = bitmap;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_invept_count);
}

static void PayloadBridgeDrainLegacyPendingInstalls(payload_u64 vcpu, payload_u64 idx)
{
    if (idx >= 64 ||
        !PayloadIsKernelPointer(vcpu) ||
        !g_cached_hv_diag.ghv_off_pending_ept_install_bitmap ||
        !g_cached_hv_diag.ghv_off_pending_ept_install_entries)
    {
        return;
    }

    payload_u64 bitmap_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_ept_install_bitmap, 0);
    payload_u64 entries_base = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_ept_install_entries, 0);
    if (!PayloadIsKernelPointer(bitmap_field) || !PayloadIsKernelPointer(entries_base))
        return;

    payload_u64 bit = 1ull << idx;
    payload_u64 bitmap = PayloadReadHostU64(bitmap_field);
    if (!(bitmap & bit))
        return;

    payload_u64 capacity = g_cached_hv_diag.ghv_pending_install_capacity;
    if (!capacity || capacity > 256)
        capacity = 64;

    bool missing_layout =
        !g_cached_hv_diag.ept_hook_entry_off_orig_pfn ||
        !g_cached_hv_diag.ept_hook_entry_off_fake_pfn ||
        !g_cached_hv_diag.ept_hook_entry_off_is_fake_page ||
        !g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap;

    if (missing_layout)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_install_fail_count);
        _InterlockedAnd64((volatile LONG64*)bitmap_field, ~(LONG64)bit);
        return;
    }

    payload_u64 vcpu_count = g_cached_hv_diag.vcpu_count;
    payload_u64 full_mask = ~0ull;
    if (vcpu_count && vcpu_count < 64)
        full_mask = (1ull << vcpu_count) - 1ull;

    for (payload_u64 i = 0; i < capacity; ++i)
    {
        payload_u64 slot = entries_base + i * sizeof(payload_u64);
        if (!PayloadIsKernelPointer(slot))
            break;

        payload_u64 entry = PayloadReadHostU64(slot);
        if (!PayloadIsKernelPointer(entry))
            continue;

        payload_u64 active_field = entry + g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap;
        if (!PayloadIsKernelPointer(active_field))
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_install_fail_count);
            continue;
        }

        payload_u64 active = PayloadReadHostU64(active_field);
        if (active & bit)
            goto maybe_retire;

        {
            payload_u64 orig_field = entry + g_cached_hv_diag.ept_hook_entry_off_orig_pfn;
            payload_u64 fake_field = entry + g_cached_hv_diag.ept_hook_entry_off_fake_pfn;
            payload_u64 ifp_field = entry + g_cached_hv_diag.ept_hook_entry_off_is_fake_page;
            if (!PayloadIsKernelPointer(orig_field) ||
                !PayloadIsKernelPointer(fake_field) ||
                !PayloadIsKernelPointer(ifp_field))
            {
                _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_install_fail_count);
                continue;
            }

            payload_u64 orig_pfn = PayloadReadHostU64(orig_field);
            payload_u64 fake_pfn = PayloadReadHostU64(fake_field);
            bool is_fake_page = PayloadReadHostU8(ifp_field) != 0;
            if (!orig_pfn || !fake_pfn ||
                !PayloadEptNativeInstallForVcpu(vcpu, orig_pfn, fake_pfn, is_fake_page))
            {
                _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_install_fail_count);
                continue;
            }

            PayloadEptMarkLegacyEntryActive(entry, bit);
            active = PayloadReadHostU64(active_field);
        }

maybe_retire:
        if (full_mask && ((active & full_mask) == full_mask))
        {
            LONG64 old = _InterlockedCompareExchange64((volatile LONG64*)slot, 0, (LONG64)entry);
            if ((payload_u64)old == entry)
                _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_install_retire_count);
        }
    }

    _InterlockedAnd64((volatile LONG64*)bitmap_field, ~(LONG64)bit);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_install_count);
}

static void PayloadBridgeDrainLegacyPendingHide(payload_u64 vcpu, payload_u64 idx)
{
    if (idx >= 64 ||
        !PayloadIsKernelPointer(vcpu) ||
        !g_cached_hv_diag.ghv_off_pending_hide_pfns ||
        !g_cached_hv_diag.ghv_off_pending_hide_count ||
        !g_cached_hv_diag.ghv_off_pending_hide_vcpu_bitmap ||
        !g_cached_hv_diag.ghv_off_pending_hide_tsc_threshold)
    {
        return;
    }

    payload_u64 bitmap_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_vcpu_bitmap, 0);
    if (!PayloadIsKernelPointer(bitmap_field))
        return;

    payload_u64 bit = 1ull << idx;
    payload_u64 bitmap = PayloadReadHostU64(bitmap_field);
    if (!(bitmap & bit))
        return;

    payload_u64 threshold_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_tsc_threshold, 0);
    if (!PayloadIsKernelPointer(threshold_field))
        return;
    payload_u64 threshold = PayloadReadHostU64(threshold_field);
    if (threshold && (payload_u64)__rdtsc() < threshold)
        return;

    if (!g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_hide_fail_count);
        _InterlockedAnd64((volatile LONG64*)bitmap_field, ~(LONG64)bit);
        return;
    }

    payload_u64 dummy_field = vcpu + g_cached_hv_diag.vcpu_off_ept_dummy_page_pfn;
    payload_u64 count_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_count, 0);
    payload_u64 pfns_base = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_hide_pfns, 0);
    if (!PayloadIsKernelPointer(dummy_field) ||
        !PayloadIsKernelPointer(count_field) ||
        !PayloadIsKernelPointer(pfns_base))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_hide_fail_count);
        _InterlockedAnd64((volatile LONG64*)bitmap_field, ~(LONG64)bit);
        return;
    }

    payload_u64 dummy_pfn = PayloadReadHostU64(dummy_field);
    payload_u64 count = PayloadReadHostU32(count_field);
    static constexpr payload_u64 PAYLOAD_LEGACY_HIDE_MAX_COUNT = 256ull * 1024ull;
    if (count > PAYLOAD_LEGACY_HIDE_MAX_COUNT)
        count = PAYLOAD_LEGACY_HIDE_MAX_COUNT;

    if (!dummy_pfn)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_hide_fail_count);
        _InterlockedAnd64((volatile LONG64*)bitmap_field, ~(LONG64)bit);
        return;
    }

    PayloadBridgeAddGhvCounter(g_cached_hv_diag.ghv_off_diag_hide_enter, 1);

    payload_u64 hidden = 0;
    payload_u64 pte_null = 0;
    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 pfn_field = pfns_base + i * sizeof(payload_u64);
        if (!PayloadIsKernelPointer(pfn_field))
        {
            ++pte_null;
            break;
        }

        payload_u64 pfn = PayloadReadHostU64(pfn_field);
        if (PayloadBridgeHideOnePfn(vcpu, dummy_pfn, pfn, &pte_null))
        {
            PayloadBridgeSetSystemCr3PageNxForPfn(g_image_base, g_image_size, pfn, true);
            ++hidden;
        }
    }

    PayloadBridgeAddGhvCounter(g_cached_hv_diag.ghv_off_diag_hide_pte_total, count);
    PayloadBridgeAddGhvCounter(g_cached_hv_diag.ghv_off_diag_hide_pte_null, pte_null);
    PayloadDbgWatchInveptAll();

    payload_u64 done_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_diag_hide_done_bitmap, 0);
    if (PayloadIsKernelPointer(done_field))
        _InterlockedOr64((volatile LONG64*)done_field, (LONG64)bit);

    _InterlockedAnd64((volatile LONG64*)bitmap_field, ~(LONG64)bit);
    g_payload_vmexit_legacy_hide_last_hidden = hidden;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_hide_count);
}

static bool PayloadBridgeGuestCpl(payload_u64* cpl_out)
{
    if (!cpl_out)
        return false;

    payload_u64 ss_access = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_SS_ACCESS_RIGHTS, &ss_access))
        return false;

    *cpl_out = (ss_access >> 5) & 0x3ull;
    return true;
}

static bool PayloadBridgeScheduleGuestBugCheck(payload_guest_context* ctx,
                                               payload_u64 reason,
                                               payload_u64 param1,
                                               payload_u64 param2,
                                               payload_u64 param3)
{
#if PAYLOAD_VT_FATAL_BUGCHECK_ENABLED
    if (!ctx || !g_ke_bug_check_ex)
        return false;

    payload_u64 cpl = 3;
    payload_u64 cr3 = 0;
    payload_u64 rsp = 0;
    if (!PayloadBridgeGuestCpl(&cpl) || cpl != 0 ||
        !PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &cr3) || !cr3 ||
        !PayloadVmread(PAYLOAD_VMCS_GUEST_RSP, &rsp) || rsp < 0x100ull)
    {
        return false;
    }

    // Build the stack frame KeBugCheckEx expects at function entry:
    // [rsp] return address, [rsp+8..+0x27] home space, [rsp+0x28] arg5.
    // Align to the normal x64 callee-entry convention (rsp % 16 == 8).
    payload_u64 new_rsp = (rsp - 0x80ull) & ~0xFull;
    new_rsp -= 8ull;

    if (!PayloadGuestWriteU64(cr3, new_rsp + 0x00ull, 0) ||
        !PayloadGuestWriteU64(cr3, new_rsp + 0x08ull, 0) ||
        !PayloadGuestWriteU64(cr3, new_rsp + 0x10ull, 0) ||
        !PayloadGuestWriteU64(cr3, new_rsp + 0x18ull, 0) ||
        !PayloadGuestWriteU64(cr3, new_rsp + 0x20ull, 0) ||
        !PayloadGuestWriteU64(cr3, new_rsp + 0x28ull, param3))
    {
        return false;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_vtpanic_count);
    g_payload_vtpanic_last_reason = reason;
    g_payload_vtpanic_last_param1 = param1;
    g_payload_vtpanic_last_param2 = param2;
    g_payload_vtpanic_last_param3 = param3;
    PayloadVtPanicCaptureVmcs();
    _InterlockedExchange(&g_payload_vtpanic_active, 1);

    ULONG bugcheck_code = PAYLOAD_VTPANIC_BUGCHECK_CODE;
#if PAYLOAD_VTPANIC_VISIBLE_BUGCHECK_CODE_ENABLED
    if (reason == PAYLOAD_VTPANIC_REASON_MM_HOOK_FUSE)
    {
        bugcheck_code = 0xE2000800u | (ULONG)(param1 & 0xFFull);
    }
    else if (reason == PAYLOAD_VTPANIC_REASON_VMEXIT_STORM)
    {
        bugcheck_code = 0xE2000007u;
    }
#endif

    ctx->rcx = bugcheck_code;
    ctx->rdx = PAYLOAD_VTPANIC_PARAM_TAG | (reason & 0xFFFFFFFFull);
    ctx->r8 = param1;
    ctx->r9 = param2;

    return PayloadVmwrite(PAYLOAD_VMCS_GUEST_RSP, new_rsp) &&
        PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, g_ke_bug_check_ex);
#else
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(param1);
    UNREFERENCED_PARAMETER(param2);
    UNREFERENCED_PARAMETER(param3);
    return false;
#endif
}

static bool PayloadBridgeTryScheduleDeferredVtPanic(payload_guest_context* ctx)
{
    if (!ctx || !g_payload_vtpanic_deferred_pending || g_payload_vtpanic_active)
        return false;

    payload_u64 cpl = 3;
    if (!PayloadBridgeGuestCpl(&cpl) || cpl != 0)
        return false;

    if (_InterlockedCompareExchange(&g_payload_vtpanic_deferred_pending, 0, 1) != 1)
        return false;

    payload_u64 reason = g_payload_vtpanic_deferred_reason;
    payload_u64 param1 = g_payload_vtpanic_deferred_param1;
    payload_u64 param2 = g_payload_vtpanic_deferred_param2;
    payload_u64 param3 = g_payload_vtpanic_deferred_param3;
    if (PayloadBridgeScheduleGuestBugCheck(ctx, reason, param1, param2, param3))
        return true;

    g_payload_vtpanic_deferred_reason = reason;
    g_payload_vtpanic_deferred_param1 = param1;
    g_payload_vtpanic_deferred_param2 = param2;
    g_payload_vtpanic_deferred_param3 = param3;
    _InterlockedExchange(&g_payload_vtpanic_deferred_pending, 1);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vtpanic_selftest_schedule_fail);
    return false;
}

static bool PayloadBridgeIsStormCandidate(payload_u64 basic_reason)
{
    return basic_reason == PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI ||
        basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMCALL ||
        basic_reason == PAYLOAD_VMX_EXIT_REASON_MONITOR_TRAP_FLAG ||
        basic_reason == PAYLOAD_VMX_EXIT_REASON_EPT_VIOLATION ||
        basic_reason == PAYLOAD_VMX_EXIT_REASON_EPT_MISCONFIGURATION;
}

static bool PayloadBridgeForwardOnlyAllowsResidentExit(payload_u64 basic_reason)
{
    switch (basic_reason)
    {
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMCALL:
    case PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI:
    case PAYLOAD_VMX_EXIT_REASON_CPUID:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDMSR:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_WRMSR:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDTSC:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDTSCP:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVLPG:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVD:
    case PAYLOAD_VMX_EXIT_REASON_MOV_CR:
    case PAYLOAD_VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
    case PAYLOAD_VMX_EXIT_REASON_EPT_VIOLATION:
    case PAYLOAD_VMX_EXIT_REASON_EPT_MISCONFIGURATION:
    case PAYLOAD_VMX_EXIT_REASON_NMI_WINDOW:
    case PAYLOAD_VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
        return true;
    default:
        return false;
    }
}

static bool PayloadBridgeMaybeBreakVmexitStorm(payload_guest_context* ctx,
                                               payload_u64 idx,
                                               payload_u64 reason,
                                               payload_u64 basic_reason)
{
#if PAYLOAD_VTPANIC_STORM_BREAKER_ENABLED
    if (!ctx || idx >= 64 || g_payload_vtpanic_active ||
        !PayloadBridgeIsStormCandidate(basic_reason))
    {
        return false;
    }

    payload_u64 rip = 0;
    payload_u64 cr3 = 0;
    payload_u64 qualification = 0;
    payload_u64 gla = 0;
    payload_u64 gpa = 0;
    payload_u64 idt_info = 0;
    payload_u64 idt_error = 0;
    PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &rip);
    PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &cr3);
    PayloadVmread(PAYLOAD_VMCS_EXIT_QUALIFICATION, &qualification);
    PayloadVmread(PAYLOAD_VMCS_EXIT_GUEST_LINEAR_ADDRESS, &gla);
    PayloadVmread(PAYLOAD_VMCS_GUEST_PHYSICAL_ADDRESS, &gpa);
    PayloadVmread(PAYLOAD_VMCS_IDT_VECTORING_INFORMATION_FIELD, &idt_info);
    PayloadVmread(PAYLOAD_VMCS_IDT_VECTORING_ERROR_CODE, &idt_error);

    payload_u64 sig0 =
        (reason & 0xFFFFull) |
        ((rip & 0xFFFFFFFFFFFFull) << 16);
    payload_u64 sig1 =
        (cr3 & ~0xFFFull) ^
        (qualification << 7) ^
        (qualification >> 3) ^
        (gpa << 11) ^
        (gpa >> 5) ^
        (gla << 17) ^
        (ctx->rax << 29) ^
        (ctx->rax >> 13) ^
        (idt_info << 23) ^
        idt_error;

    payload_u64 seen = 1;
    if (g_payload_vtpanic_storm_sig0[idx] == sig0 &&
        g_payload_vtpanic_storm_sig1[idx] == sig1)
    {
        seen = g_payload_vtpanic_storm_seen[idx] + 1;
    }
    else
    {
        g_payload_vtpanic_storm_sig0[idx] = sig0;
        g_payload_vtpanic_storm_sig1[idx] = sig1;
    }
    g_payload_vtpanic_storm_seen[idx] = seen;

    if (seen < PAYLOAD_VTPANIC_STORM_BREAKER_THRESHOLD ||
        (seen % PAYLOAD_VTPANIC_STORM_BREAKER_THRESHOLD) != 0)
    {
        return false;
    }

    g_payload_vtpanic_storm_last_idx = idx;
    g_payload_vtpanic_storm_last_seen = seen;
    g_payload_vtpanic_storm_last_sig0 = sig0;
    g_payload_vtpanic_storm_last_sig1 = sig1;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vtpanic_storm_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vtpanic_storm_attempt[idx]);

    g_payload_vtpanic_last_reason = PAYLOAD_VTPANIC_REASON_VMEXIT_STORM;
    g_payload_vtpanic_last_param1 =
        (basic_reason & 0xFFFFull) |
        ((idx & 0xFFull) << 16) |
        ((seen & 0xFFFFFFFFull) << 32);
    g_payload_vtpanic_last_param2 = rip;
    g_payload_vtpanic_last_param3 = gpa ? gpa : (gla ^ qualification);
    PayloadVtPanicCaptureVmcs();

    return PayloadBridgeScheduleGuestBugCheck(
        ctx,
        PAYLOAD_VTPANIC_REASON_VMEXIT_STORM,
        g_payload_vtpanic_last_param1,
        rip,
        g_payload_vtpanic_last_param3);
#else
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(idx);
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(basic_reason);
    return false;
#endif
}

static bool PayloadBridgeMaybeRunVtPanicSelftest(payload_guest_context* ctx,
                                                payload_u64 vcpu,
                                                payload_u64 idx,
                                                payload_u64 basic_reason)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(idx);
    UNREFERENCED_PARAMETER(basic_reason);
    return false;
}

extern "C" void PayloadBridgeRunLegacyPreDispatchPillars(void* guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);


    payload_u64 vcpu = 0;
    payload_u64 idx = 0;
    if (!PayloadBridgeGetCurrentVcpu(&vcpu, &idx))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_vcpu_reset_fail_count);
        return;
    }

    PayloadBridgeResetLegacyVcpuFlagsForVcpu(vcpu);
    PayloadBridgeIncrementLegacyPerVcpuVmexit(idx);
    PayloadBridgeDrainLegacyPendingInvept(idx);
    PayloadBridgeDrainLegacyPendingInstalls(vcpu, idx);
    PayloadBridgeDrainLegacyPendingHide(vcpu, idx);
}

extern "C" void PayloadBridgeProcessPendingVtcallRestore(void* guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);


    payload_u64 vcpu = 0;
    payload_u64 idx = 0;
    if (!PayloadBridgeGetCurrentVcpuForPending(&vcpu, &idx))
        return;
    if (idx >= PAYLOAD_PMO_MAX_TRACKED_VCPUS)
        return;

    UNREFERENCED_PARAMETER(vcpu);

    unsigned char state = g_payload_pmo_pending_state[idx];
    if (state != 1)
        return;

    payload_u64 rsp = g_payload_pmo_pending_rsp[idx];
    g_payload_vmexit_pending_last_vcpu = idx;
    g_payload_vmexit_pending_last_state = state;
    g_payload_vmexit_pending_last_rsp = rsp;

    if (!rsp || !PayloadVmwrite(PAYLOAD_VMCS_HOST_RSP, rsp))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_pending_fail_count);
        return;
    }

    g_payload_pmo_pending_rsp[idx] = 0;
    _ReadWriteBarrier();
    g_payload_pmo_pending_state[idx] = 2;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_pending_restore_count);
}

extern "C" void PayloadBridgeProcessPendingVtcallRelease(void* guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);


    payload_u64 vcpu = 0;
    payload_u64 idx = 0;
    if (!PayloadBridgeGetCurrentVcpuForPending(&vcpu, &idx))
        return;
    if (idx >= PAYLOAD_PMO_MAX_TRACKED_VCPUS)
        return;

    UNREFERENCED_PARAMETER(vcpu);

    unsigned char state = g_payload_pmo_pending_state[idx];
    if (state != 2)
        return;

    g_payload_vmexit_pending_last_vcpu = idx;
    g_payload_vmexit_pending_last_state = state;

    unsigned int delay = g_payload_pmo_pending_delay[idx];
    if (delay > 0)
    {
        g_payload_pmo_pending_delay[idx] = delay - 1;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_pending_release_wait_count);
        return;
    }

    payload_u64 slot = g_payload_pmo_pending_stack_slot[idx];
    unsigned char have_slot = g_payload_pmo_pending_stack_valid[idx];
    g_payload_pmo_pending_stack_valid[idx] = 0;
    g_payload_pmo_pending_stack_slot[idx] = 0;
    g_payload_pmo_pending_delay[idx] = 0;
    _ReadWriteBarrier();
    g_payload_pmo_pending_state[idx] = 0;
    if (have_slot)
        PayloadPmoFreeStackSlot(slot);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_pending_release_count);
}

static unsigned short PayloadTraceLowerW(unsigned short ch)
{
    if (ch >= (unsigned short)'A' && ch <= (unsigned short)'Z')
        return (unsigned short)(ch + 0x20);
    return ch;
}

static unsigned short PayloadTraceReadHostU16(payload_u64 va)
{
    unsigned short value = 0;
    payload_host_exception_info e = {};
    PayloadMemcpySafe(&e, &value, (const void*)va, sizeof(value));
    if (e.exception_occurred)
    {
        g_payload_misc_exit_last_action = 0x786ull;
        g_payload_misc_exit_last_vector = e.vector;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
        return 0;
    }
    return value;
}

static bool PayloadTraceNameContains(payload_u64 hay_name, unsigned int hay_bytes)
{
    if (!PayloadIsKernelPointer(hay_name) || !hay_bytes || !g_trace_unload_name_bytes)
        return false;

    unsigned int needle_chars = (unsigned int)(g_trace_unload_name_bytes / sizeof(unsigned short));
    if (!needle_chars || needle_chars > (sizeof(g_trace_unload_name) / sizeof(g_trace_unload_name[0])))
        return false;

    unsigned int hay_chars = hay_bytes / sizeof(unsigned short);
    if (hay_chars > 260)
        hay_chars = 260;
    if (hay_chars < needle_chars)
        return false;

    for (unsigned int i = 0; i <= hay_chars - needle_chars; ++i)
    {
        bool match = true;
        for (unsigned int j = 0; j < needle_chars; ++j)
        {
            unsigned short a = PayloadTraceLowerW(PayloadTraceReadHostU16(hay_name + (payload_u64)(i + j) * sizeof(unsigned short)));
            unsigned short b = PayloadTraceLowerW(g_trace_unload_name[j]);
            if (a != b)
            {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }
    return false;
}

static void PayloadTraceZeroRemoteBuffer(payload_u64 va, unsigned int bytes)
{
    if (!PayloadIsKernelPointer(va) || !bytes)
        return;
    if (bytes > 512)
        bytes = 512;
    for (unsigned int i = 0; i < bytes; ++i)
        PayloadWriteHostU8(va + i, 0);
}

static volatile LONG g_trace_unload_scrub_busy = 0;
static volatile LONG g_trace_hash_scrub_busy = 0;

static bool PayloadTraceScrubUnloadedDriverOnce()
{
    static constexpr payload_u64 kEntrySize = 0x28ull;
    static constexpr payload_u64 kOffNameLength = 0x0ull;
    static constexpr payload_u64 kOffNameBuffer = 0x8ull;
    static constexpr payload_u64 kOffModuleStart = 0x10ull;
    static constexpr payload_u64 kOffModuleEnd = 0x18ull;
    static constexpr payload_u64 kOffUnloadTime = 0x20ull;

    if (_InterlockedCompareExchange(&g_trace_unload_scrub_busy, 1, 0) != 0)
        return false;

    bool cleaned = false;
    do
    {
        if (!PayloadIsKernelPointer(g_trace_unload_mm_unloaded_drivers) ||
            !PayloadIsKernelPointer(g_trace_unload_mm_last_unloaded_driver) ||
            !g_trace_unload_name_bytes)
        {
            g_trace_unload_last_result = 0x10ull;
            _InterlockedIncrement64((volatile LONG64*)&g_trace_unload_fail_count);
            break;
        }

        payload_u64 unloaders = PayloadReadHostU64(g_trace_unload_mm_unloaded_drivers);
        unsigned int count = PayloadReadHostU32(g_trace_unload_mm_last_unloaded_driver);
        if (count > 50)
            count = 50;
        g_trace_unload_last_count = count;

        if (!PayloadIsKernelPointer(unloaders) || !count)
        {
            g_trace_unload_last_result = 0x20ull;
            break;
        }

        for (unsigned int i = 0; i < count; ++i)
        {
            payload_u64 entry = unloaders + (payload_u64)i * kEntrySize;
            if (!PayloadIsKernelPointer(entry + kOffUnloadTime))
                continue;

            unsigned int name_len = PayloadReadHostU32(entry + kOffNameLength) & 0xFFFFu;
            payload_u64 name_buf = PayloadReadHostU64(entry + kOffNameBuffer);
            if (!name_len || !PayloadTraceNameContains(name_buf, name_len))
                continue;

            PayloadTraceZeroRemoteBuffer(name_buf, name_len);
            PayloadWriteHostU32(entry + kOffNameLength, 0);
            PayloadWriteHostU64(entry + kOffNameBuffer, 0);
            PayloadWriteHostU64(entry + kOffModuleStart, 0);
            PayloadWriteHostU64(entry + kOffModuleEnd, 0);
            PayloadWriteHostU64(entry + kOffUnloadTime, 0);

            g_trace_unload_last_index = i;
            g_trace_unload_last_result = 0x100ull | i;
            _InterlockedIncrement64((volatile LONG64*)&g_trace_unload_clean_count);
            cleaned = true;
            break;
        }

        if (!cleaned)
            g_trace_unload_last_result = 0x30ull;
    } while (false);

    _InterlockedExchange(&g_trace_unload_scrub_busy, 0);
    return cleaned;
}

static bool PayloadTraceScrubHashBucketOnce()
{
    static constexpr payload_u64 kMaxWalk = 4096ull;
    static constexpr payload_u64 kOffNext = 0x0ull;
    static constexpr payload_u64 kOffNameLength = 0x8ull;
    static constexpr payload_u64 kOffNameBuffer = 0x10ull;
    static constexpr payload_u64 kOffHash = 0x18ull;

    if (_InterlockedCompareExchange(&g_trace_hash_scrub_busy, 1, 0) != 0)
        return false;

    bool cleaned = false;
    do
    {
        if (!PayloadIsKernelPointer(g_trace_hash_bucket_list) || !g_trace_unload_name_bytes)
        {
            g_trace_hash_last_result = 0x10ull;
            _InterlockedIncrement64((volatile LONG64*)&g_trace_hash_fail_count);
            break;
        }

        if (PayloadIsKernelPointer(g_trace_hash_cache_lock) &&
            PayloadReadHostU64(g_trace_hash_cache_lock) != 0)
        {
            g_trace_hash_last_result = 0x15ull;
            break;
        }

        payload_u64 prev = g_trace_hash_bucket_list;
        payload_u64 current = PayloadReadHostU64(g_trace_hash_bucket_list + kOffNext);
        payload_u64 walked = 0;
        g_trace_hash_last_entry = current;
        g_trace_hash_last_count = 0;

        if (!current)
        {
            g_trace_hash_last_result = 0x20ull;
            break;
        }

        bool aborted = false;
        while (current && walked < kMaxWalk)
        {
            if (PayloadIsKernelPointer(g_trace_hash_cache_lock) &&
                PayloadReadHostU64(g_trace_hash_cache_lock) != 0)
            {
                g_trace_hash_last_result = 0x15ull;
                aborted = true;
                break;
            }

            if (!PayloadIsKernelPointer(current) ||
                !PayloadIsKernelPointer(current + kOffHash))
            {
                g_trace_hash_last_result = 0x21ull;
                g_trace_hash_last_entry = current;
                g_trace_hash_last_count = walked;
                _InterlockedIncrement64((volatile LONG64*)&g_trace_hash_fail_count);
                aborted = true;
                break;
            }

            payload_u64 next = PayloadReadHostU64(current + kOffNext);
            unsigned int name_len = PayloadReadHostU32(current + kOffNameLength) & 0xFFFFu;
            payload_u64 name_buf = PayloadReadHostU64(current + kOffNameBuffer);

            if (name_len && PayloadTraceNameContains(name_buf, name_len))
            {
                if ((PayloadIsKernelPointer(g_trace_hash_cache_lock) &&
                     PayloadReadHostU64(g_trace_hash_cache_lock) != 0) ||
                    !PayloadIsKernelPointer(prev) ||
                    PayloadReadHostU64(prev + kOffNext) != current)
                {
                    g_trace_hash_last_result = 0x15ull;
                    aborted = true;
                    break;
                }

                PayloadWriteHostU64(prev + kOffNext, next);

                PayloadTraceZeroRemoteBuffer(name_buf, name_len);
                PayloadWriteHostU32(current + kOffNameLength, 0);
                PayloadWriteHostU64(current + kOffNameBuffer, 0);
                PayloadWriteHostU32(current + kOffHash + 0x00ull, 1);
                PayloadWriteHostU32(current + kOffHash + 0x04ull, 1);
                PayloadWriteHostU32(current + kOffHash + 0x08ull, 1);
                PayloadWriteHostU32(current + kOffHash + 0x0Cull, 1);
                PayloadWriteHostU32(current + kOffHash + 0x10ull, 1);

                g_trace_hash_last_index = walked;
                g_trace_hash_last_count = walked + 1;
                g_trace_hash_last_entry = current;
                g_trace_hash_last_result = 0x100ull | walked;
                _InterlockedIncrement64((volatile LONG64*)&g_trace_hash_clean_count);
                cleaned = true;
                break;
            }

            if (next == current)
            {
                g_trace_hash_last_result = 0x22ull;
                g_trace_hash_last_entry = current;
                g_trace_hash_last_count = walked + 1;
                _InterlockedIncrement64((volatile LONG64*)&g_trace_hash_fail_count);
                aborted = true;
                break;
            }

            prev = current;
            current = next;
            ++walked;
        }

        if (!cleaned && !aborted)
        {
            g_trace_hash_last_entry = current;
            g_trace_hash_last_count = walked;
            g_trace_hash_last_result = (walked >= kMaxWalk) ? 0x23ull : 0x30ull;
            if (walked >= kMaxWalk)
                _InterlockedIncrement64((volatile LONG64*)&g_trace_hash_fail_count);
        }
    } while (false);

    _InterlockedExchange(&g_trace_hash_scrub_busy, 0);
    return cleaned;
}

static void PayloadBridgeMaybeScrubUnloadedDriverTrace()
{
    payload_u64 max_attempts = g_trace_unload_max_attempts ? g_trace_unload_max_attempts : 512ull;
    if (g_trace_unload_clean_count || g_trace_unload_probe_count > max_attempts)
        return;

    payload_u64 seen = (payload_u64)_InterlockedIncrement64((volatile LONG64*)&g_trace_unload_vmexit_seen);
    payload_u64 delay = g_trace_unload_delay_exits ? g_trace_unload_delay_exits : 8192ull;
    if (seen < delay)
        return;

    payload_u64 interval = g_trace_unload_interval_exits ? g_trace_unload_interval_exits : 4096ull;
    if (interval && ((seen - delay) % interval) != 0)
        return;

    payload_u64 attempt = (payload_u64)_InterlockedIncrement64((volatile LONG64*)&g_trace_unload_probe_count);
    if (attempt > max_attempts)
    {
        g_trace_unload_last_result = 0x40ull;
        return;
    }

    PayloadTraceScrubUnloadedDriverOnce();
}

static void PayloadBridgeMaybeScrubHashBucketTrace()
{
    payload_u64 max_attempts = g_trace_hash_max_attempts ? g_trace_hash_max_attempts : 512ull;
    if (g_trace_hash_clean_count || g_trace_hash_probe_count > max_attempts)
        return;

    payload_u64 seen = (payload_u64)_InterlockedIncrement64((volatile LONG64*)&g_trace_hash_vmexit_seen);
    payload_u64 delay = g_trace_hash_delay_exits ? g_trace_hash_delay_exits : 8192ull;
    if (seen < delay)
        return;

    payload_u64 interval = g_trace_hash_interval_exits ? g_trace_hash_interval_exits : 4096ull;
    if (interval && ((seen - delay) % interval) != 0)
        return;

    payload_u64 attempt = (payload_u64)_InterlockedIncrement64((volatile LONG64*)&g_trace_hash_probe_count);
    if (attempt > max_attempts)
    {
        g_trace_hash_last_result = 0x40ull;
        return;
    }

    PayloadTraceScrubHashBucketOnce();
}

extern "C" void PayloadBridgePostDispatchTraceScrub(void* guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);


    // TestDriver parity: handle_vm_exit() forces trace controls back to an
    // inert guest view after dispatch and pending vtcall release, on every
    // VM-exit (not only on RDMSR/WRMSR exits).  Keep it here so the payload
    // bridge preserves that root-mode hygiene after TestDriver quarantine.
    payload_u64 mask = PayloadBridgeScrubTraceVmcs();
    g_payload_vmexit_trace_scrub_last_mask = mask;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_trace_scrub_count);
    if (mask != 0x7ull)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_trace_scrub_fail_count);

    payload_u64 idle_bits = 0;
    if (!PayloadBridgeScrubTestDriverIdleExitControls(&idle_bits))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
    }
    else if (idle_bits)
    {
        // TestDriver VMCS parity: these controls are expected to stay clear.
        // Record the scrub compactly in existing misc diagnostics.
        g_payload_misc_exit_last_action = 0x512ull;
        g_payload_misc_exit_last_vector = idle_bits;
    }

    PayloadBridgeMaybeScrubUnloadedDriverTrace();
    PayloadBridgeMaybeScrubHashBucketTrace();

    payload_u64 tsc_idx = 0;
    if (PayloadBridgeCurrentVcpuIdx(&tsc_idx))
    {
        bool hide_overhead = g_payload_tsc_hide_overhead[tsc_idx] != 0;
        if (!hide_overhead && g_cached_hv_diag.vcpu_off_hide_vm_exit_overhead)
        {
            payload_u64 vcpu = 0;
            payload_u64 vcpu_idx = 0;
            if (PayloadBridgeGetCurrentVcpu(&vcpu, &vcpu_idx) && vcpu_idx == tsc_idx)
            {
                payload_u64 hide_field = vcpu + g_cached_hv_diag.vcpu_off_hide_vm_exit_overhead;
                if (PayloadIsKernelPointer(hide_field) && PayloadReadHostU8(hide_field) != 0)
                    hide_overhead = true;
            }
        }

        payload_u64 now = (payload_u64)__rdtsc();
        if (hide_overhead)
        {
            static constexpr payload_u64 kNativeCycles = 0x58ull;
            static constexpr payload_u64 kMaxPerExitOverhead = 0x2000ull;
            static constexpr payload_u64 kMaxTotalMagnitude = 0x40000ull;

            payload_u64 enter_tsc = g_payload_tsc_enter[tsc_idx];
            payload_u64 elapsed = (enter_tsc && now > enter_tsc) ? (now - enter_tsc) : 0;
            payload_u64 overhead = elapsed > kNativeCycles ? (elapsed - kNativeCycles) : 0;
            if (overhead > kMaxPerExitOverhead)
                overhead = kMaxPerExitOverhead;

            payload_u64 cur_mag = 0ull - g_payload_tsc_offset[tsc_idx];
            if (cur_mag > kMaxTotalMagnitude)
                cur_mag = 0;
            payload_u64 next_mag = cur_mag + overhead;
            if (next_mag > kMaxTotalMagnitude)
                next_mag = kMaxTotalMagnitude;

            payload_u64 new_offset = 0ull - next_mag;
            g_payload_tsc_offset[tsc_idx] = new_offset;
            g_payload_tsc_last_sensitive[tsc_idx] = now;

            if (!g_payload_tsc_ctrl_enabled[tsc_idx])
            {
                payload_u64 proc_ctrl = 0;
                if (PayloadVmread(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, &proc_ctrl))
                {
                    if ((proc_ctrl & PAYLOAD_VMX_PROCBASED_USE_TSC_OFFSETTING) ||
                        PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, proc_ctrl | PAYLOAD_VMX_PROCBASED_USE_TSC_OFFSETTING))
                    {
                        g_payload_tsc_ctrl_enabled[tsc_idx] = 1;
                    }
                }
            }
            PayloadVmwrite(PAYLOAD_VMCS_CTRL_TSC_OFFSET, new_offset);
        }
        else if (g_payload_tsc_offset[tsc_idx] != 0)
        {
            static constexpr payload_u64 kIdleResetWindow = 0x100000ull;
            payload_u64 last_sens = g_payload_tsc_last_sensitive[tsc_idx];
            if (!last_sens || (now > last_sens && (now - last_sens) > kIdleResetWindow))
            {
                g_payload_tsc_offset[tsc_idx] = 0;
                PayloadVmwrite(PAYLOAD_VMCS_CTRL_TSC_OFFSET, 0);
            }
        }
    }
}

static payload_u64 PayloadBridgeHandleLegacyMmrMtf(payload_guest_context* ctx, payload_u64 reason)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(reason);

    payload_u64 vcpu = 0;
    payload_u64 idx = 0;
    if (!PayloadBridgeGetCurrentVcpu(&vcpu, &idx) ||
        !g_cached_hv_diag.vcpu_off_ept_mmr_mtf_pte ||
        !g_cached_hv_diag.vcpu_off_ept_mmr_mtf_mode ||
        !g_cached_hv_diag.vcpu_off_ept_mmr_mtf_page_frame)
    {
        return 0;
    }

    payload_u64 pte_field = vcpu + g_cached_hv_diag.vcpu_off_ept_mmr_mtf_pte;
    payload_u64 mode_field = vcpu + g_cached_hv_diag.vcpu_off_ept_mmr_mtf_mode;
    payload_u64 frame_field = vcpu + g_cached_hv_diag.vcpu_off_ept_mmr_mtf_page_frame;
    if (!PayloadIsKernelPointer(pte_field) ||
        !PayloadIsKernelPointer(mode_field) ||
        !PayloadIsKernelPointer(frame_field))
    {
        return 0;
    }

    payload_u64 pte = PayloadReadHostU64(pte_field);
    bool pte_is_direct_map =
        pte >= PAYLOAD_HOST_PHYSICAL_MEMORY_BASE &&
        PayloadHostPhysicalRangeMapped(pte - PAYLOAD_HOST_PHYSICAL_MEMORY_BASE, sizeof(payload_u64));
    if (!PayloadIsKernelPointer(pte) && !pte_is_direct_map)
        return 0;

    payload_u64 before = PayloadReadHostU64(pte);
    payload_u64 mode = PayloadReadHostU8(mode_field);
    payload_u64 page_frame = PayloadReadHostU64(frame_field);

    bool read = (mode & 0x1ull) == 0;
    bool write = (mode & 0x2ull) == 0;
    bool execute = (mode & 0x4ull) == 0;
    if (write && !read)
        write = false;

    payload_u64 pfn = page_frame ? page_frame : ((before & PAYLOAD_EPT_PFN_MASK) >> 12);
    payload_u64 after = PayloadEptEntryWithPfnPerms(before, pfn, read, write, execute);
    PayloadWriteHostU64(pte, after);

    PayloadWriteHostU64(pte_field, 0);
    PayloadWriteHostU64(frame_field, 0);
    PayloadWriteHostU8(mode_field, 0);

    payload_u64 controls = 0;
    bool mtf_ok = PayloadVmread(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, &controls) &&
        PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, controls & ~PAYLOAD_VMX_PROCBASED_MTF);

    g_payload_ept_tramp_last_vcpu = idx;
    g_payload_ept_tramp_last_pte_pa = pte;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = after;
    g_payload_ept_tramp_last_mtf_restore = after;

    if (!mtf_ok)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_mtf_fail_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_legacy_mtf_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_MONITOR_TRAP_FLAG;
    g_payload_vmexit_bridge_self_last_result = mtf_ok ? 0x731ull : 0x73Full;
    return mtf_ok ? 1 : 0;
}

static payload_u64 PayloadBridgeHandleNmiException(payload_guest_context* ctx, payload_u64 reason)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(reason);

    payload_u64 info = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_VMEXIT_INTERRUPTION_INFORMATION, &info))
        return 0;

    bool valid = (info & (1ull << 31)) != 0;
    payload_u64 vector = info & 0xFFull;
    payload_u64 type = (info >> 8) & 0x7ull;
    if (!valid || vector != 2 || type != 2)
        return 0;

    payload_u64 controls = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, &controls) ||
        !PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, controls | PAYLOAD_VMX_PROCBASED_NMI_WINDOW))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
        return 0;
    }

    g_payload_misc_exit_last_reason = PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI;
    g_payload_misc_exit_last_action = 0x524ull; // NMI-window requested
    g_payload_misc_exit_last_vector = 2;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI;
    g_payload_vmexit_bridge_self_last_result = 0x524ull;
    return 1;
}

extern "C" payload_u64 PayloadBridgeNoTarget(void* guest_context)
{
    auto ctx = (payload_guest_context*)guest_context;
    payload_u64 reason = 0;
    payload_u64 basic_reason = 0;
    if (PayloadVmread(PAYLOAD_VMCS_EXIT_REASON, &reason))
        basic_reason = reason & 0xFFFFull;

    PayloadEptDrainNativePending();

    if (PayloadBridgeTryScheduleDeferredVtPanic(ctx))
        return 1;

    g_payload_misc_exit_last_reason = basic_reason;
    g_payload_misc_exit_last_action = 0x500ull; // no old bridge target
    _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_probe_count);

    if (ctx && basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMCALL)
    {
        payload_u64 code = ctx->rax & 0xFFull;
        payload_u64 key = ctx->rax >> 8;
        if (key != PAYLOAD_HYPERCALL_KEY)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_forward_bad_key);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_forward_unknown_code);
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    if (PayloadBridgeHandleSimpleExit(ctx, basic_reason))
        return 1;

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EPT_VIOLATION)
    {
#if PAYLOAD_EPT_TRAMP_HANDLER_ENABLED
        // Freetest parity: even without a TestDriver target, resident owners
        // must see the EPT violation before the final fail-open sanitize.
        // Otherwise a late hook/watch miss would silently unlock the leaf and
        // break the TestDriver EPT->MTF restoration loop we migrated.
        if (PayloadDbgWatchTryHandleEpt(ctx, reason))
            return 1;
        if (PayloadBridgeProbeEptTrampoline(ctx, reason))
            return 1;
#endif

        payload_u64 gpa = 0;
        payload_u64 qualification = 0;
        if (PayloadVmread(PAYLOAD_VMCS_GUEST_PHYSICAL_ADDRESS, &gpa) &&
            PayloadVmread(PAYLOAD_VMCS_EXIT_QUALIFICATION, &qualification))
        {
            if (PayloadEptSanitizeLeafForGpa(gpa, true))
            {
                // Fail-open after TestDriver image is gone.  If a late EPT exit
                // misses the resident hook/debug-watch owners, do not inject #GP
                // into an arbitrary guest thread.  Make the current leaf
                // permissive and resume at the same RIP.  This can drop a stale
                // hook view, but preserves system liveness after freetest.
                g_payload_misc_exit_last_action = 0x530ull;
                g_payload_misc_exit_last_vector = qualification;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
                _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
                return 1;
            }

            if (PayloadBridgeScheduleGuestBugCheck(
                ctx,
                PAYLOAD_VTPANIC_REASON_EPT_SANITIZE_FAIL,
                gpa,
                qualification,
                basic_reason))
            {
                return 1;
            }
            PayloadVtPanicBugCheck(
                PAYLOAD_VTPANIC_REASON_EPT_SANITIZE_FAIL,
                gpa,
                qualification,
                basic_reason);
        }
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_MONITOR_TRAP_FLAG)
    {
        if (
#if PAYLOAD_EPT_MTF_HANDLER_ENABLED
            PayloadDbgWatchHandleMtf(ctx, reason) ||
            PayloadBridgeHandleEptMtf(ctx, reason) ||
#endif
            PayloadBridgeHandleLegacyMmrMtf(ctx, reason))
        {
            return 1;
        }

        payload_u64 controls = 0;
        if (PayloadVmread(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, &controls) &&
            PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, controls & ~PAYLOAD_VMX_PROCBASED_MTF))
        {
            g_payload_misc_exit_last_action = 0x525ull;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
            return 1;
        }
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EPT_MISCONFIGURATION)
    {
        payload_u64 gpa = 0;
        PayloadVmread(PAYLOAD_VMCS_GUEST_PHYSICAL_ADDRESS, &gpa);
        g_payload_vmexit_ept_misconfig_last_gpa = gpa;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_ept_misconfig_count);
        if (gpa && PayloadEptSanitizeLeafForGpa(gpa, true))
        {
            g_payload_misc_exit_last_action = 0x531ull;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
            return 1;
        }
        if (gpa)
        {
            if (PayloadBridgeScheduleGuestBugCheck(
                ctx,
                PAYLOAD_VTPANIC_REASON_EPT_MISCONFIG_SANITIZE_FAIL,
                gpa,
                basic_reason,
                0))
            {
                return 1;
            }
            PayloadVtPanicBugCheck(
                PAYLOAD_VTPANIC_REASON_EPT_MISCONFIG_SANITIZE_FAIL,
                gpa,
                basic_reason,
                0);
        }
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI)
    {
        if (PayloadBridgeHandleNmiException(ctx, reason))
            return 1;

#if PAYLOAD_BP_HANDLER_ENABLED
        // Same owner-aware #BP order as the normal bridge path: resident
        // vtret/trampoline consumers first, then legitimate guest INT3
        // re-injection.  This prevents freetest from bouncing a payload-owned
        // breakpoint back into the guest after TestDriver is gone.
        g_payload_vtret_last_reason = PAYLOAD_VTRET_REASON_NONE;
        g_payload_tramp_last_reason = PAYLOAD_TRAMP_REASON_NONE;
        PayloadBridgeProbeVtRet(ctx, reason);
        payload_u64 vtret_reason = g_payload_vtret_last_reason;
        if (PayloadBridgeProbeTrampoline(ctx, reason))
            return 1;
        payload_u64 tramp_reason = g_payload_tramp_last_reason;
        if (PayloadBridgeTryReinjectBreakpoint(ctx, reason, vtret_reason, tramp_reason))
            return 1;
#endif

        if (PayloadBridgeTryReinjectExitException(ctx, reason))
            return 1;
    }

    if (PayloadBridgeInjectHardwareException(13, true, 0))
    {
        g_payload_misc_exit_last_action = 0x50Dull; // no-target #GP
        g_payload_misc_exit_last_vector = 13;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
        return 1;
    }

    g_payload_misc_exit_last_action = 0x5FFull;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
    return 0;
}

extern "C" payload_u64 PayloadBridgeTryHandle(void* guest_context)
{
    auto ctx = (payload_guest_context*)guest_context;
    if (!ctx)
    {
        PayloadBridgeRecordForward(0, 0, 0, PAYLOAD_BRIDGE_FORWARD_GENERIC);
        return 0;
    }

    payload_u64 reason = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_EXIT_REASON, &reason))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_vmread_fail);
        PayloadBridgeRecordForward(0, 0, 0, PAYLOAD_BRIDGE_FORWARD_GENERIC);
        return 0;
    }

    payload_u64 basic_reason = reason & 0xFFFFull;

    if (PayloadBridgeTryScheduleDeferredVtPanic(ctx))
        return 1;

    if (!PayloadBridgeForwardOnlyAllowsResidentExit(basic_reason))
    {
        PayloadBridgeRecordForward(basic_reason, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return 0;
    }

    PayloadEptDrainNativePending();

    payload_u64 selftest_vcpu = 0;
    payload_u64 selftest_idx = 0;
    if (PayloadBridgeGetCurrentVcpu(&selftest_vcpu, &selftest_idx) &&
        (PayloadBridgeMaybeBreakVmexitStorm(ctx, selftest_idx, reason, basic_reason) ||
         PayloadBridgeMaybeRunVtPanicSelftest(ctx, selftest_vcpu, selftest_idx, basic_reason)))
    {
        return 1;
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_CPUID)
    {
        return PayloadBridgeHandleCpuid(ctx);
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDTSC)
    {
        return PayloadBridgeHandleRdtsc(ctx);
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDTSCP)
    {
        return PayloadBridgeHandleRdtscp(ctx);
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVLPG)
    {
        return PayloadBridgeHandleInvlpg(ctx);
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV)
    {
        return PayloadBridgeHandleXsetbv(ctx);
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVD)
    {
        return PayloadBridgeHandleInvd(ctx);
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_MOV_CR)
    {
#if PAYLOAD_MOV_CR_HANDLER_ENABLED
        return PayloadBridgeHandleMovCr(ctx);
#else
        _InterlockedIncrement64((volatile LONG64*)&g_payload_cr_probe_count);
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_DISABLED, ctx);
#endif
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDMSR)
    {
        return PayloadBridgeHandleRdmsr(ctx);
    }

    if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXECUTE_WRMSR)
    {
        return PayloadBridgeHandleWrmsr(ctx);
    }

    if (PayloadBridgeHandleSimpleExit(ctx, basic_reason))
    {
        return 1;
    }

    if (basic_reason != PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMCALL)
    {
        if (basic_reason == PAYLOAD_VMX_EXIT_REASON_MONITOR_TRAP_FLAG &&
#if PAYLOAD_EPT_MTF_HANDLER_ENABLED
            (PayloadDbgWatchHandleMtf(ctx, reason) ||
             PayloadBridgeHandleEptMtf(ctx, reason) ||
             PayloadBridgeHandleLegacyMmrMtf(ctx, reason)))
#else
            PayloadBridgeHandleLegacyMmrMtf(ctx, reason))
#endif
        {
            return 1;
        }

        if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI)
        {
            if (PayloadBridgeHandleNmiException(ctx, reason))
                return 1;

#if PAYLOAD_BP_HANDLER_ENABLED
            g_payload_vtret_last_reason = PAYLOAD_VTRET_REASON_NONE;
            g_payload_tramp_last_reason = PAYLOAD_TRAMP_REASON_NONE;
            PayloadBridgeProbeVtRet(ctx, reason);
            payload_u64 vtret_reason = g_payload_vtret_last_reason;
            if (PayloadBridgeProbeTrampoline(ctx, reason))
                return 1;
            payload_u64 tramp_reason = g_payload_tramp_last_reason;
            if (PayloadBridgeTryReinjectBreakpoint(ctx, reason, vtret_reason, tramp_reason))
                return 1;
#endif
            if (!PayloadBridgeCanForwardOldHandler() &&
                PayloadBridgeTryReinjectExitException(ctx, reason))
                return 1;
        }
        else if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EPT_VIOLATION)
        {
#if PAYLOAD_EPT_TRAMP_HANDLER_ENABLED
            if (PayloadDbgWatchTryHandleEpt(ctx, reason))
                return 1;
            if (PayloadBridgeProbeEptTrampoline(ctx, reason))
                return 1;
#endif
        }
        else if (basic_reason == PAYLOAD_VMX_EXIT_REASON_EPT_MISCONFIGURATION)
        {
            payload_u64 gpa = 0;
            PayloadVmread(PAYLOAD_VMCS_GUEST_PHYSICAL_ADDRESS, &gpa);
            g_payload_vmexit_ept_misconfig_last_gpa = gpa;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_ept_misconfig_count);
            if (gpa && PayloadEptSanitizeLeafForGpa(gpa, true))
            {
                g_payload_misc_exit_last_reason = basic_reason;
                g_payload_misc_exit_last_action = 0x531ull;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
                _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
                return 1;
            }
            if (gpa)
            {
                if (PayloadBridgeScheduleGuestBugCheck(
                    ctx,
                    PAYLOAD_VTPANIC_REASON_EPT_MISCONFIG_SANITIZE_FAIL,
                    gpa,
                    basic_reason,
                    1))
                {
                    return 1;
                }
                PayloadVtPanicBugCheck(
                    PAYLOAD_VTPANIC_REASON_EPT_MISCONFIG_SANITIZE_FAIL,
                    gpa,
                    basic_reason,
                    1);
            }
        }
        PayloadBridgeRecordForward(basic_reason, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return 0;
    }

    auto const code = ctx->rax & 0xFFull;
    auto const key = ctx->rax >> 8;
    if (key != PAYLOAD_HYPERCALL_KEY)
    {
#if PAYLOAD_HOOK_DISPATCH_ENABLED
        if (PayloadBridgeProbeHookDispatch(ctx, key))
            return 1;
#endif
        if (!PayloadBridgeCanForwardOldHandler())
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_forward_bad_key);
            payload_u64 cpl = 0;
            if (PayloadBridgeGuestCpl(&cpl) && cpl > 0)
            {
                if (PayloadBridgeInjectHardwareException(6, false, 0))
                {
                    PayloadBridgeMarkHideVmExitOverhead();
                    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
                    return 1;
                }
            }
            return PayloadBridgeCompleteHypercall(ctx, code, 0x0002ull);
        }
        PayloadBridgeRecordForward(basic_reason, code, key, PAYLOAD_BRIDGE_FORWARD_BAD_KEY, ctx->rax);
        return 0;
    }

    switch (code)
    {
    case PAYLOAD_HYPERCALL_PING:
        return PayloadBridgeCompleteHypercall(ctx, code, PAYLOAD_HYPERVISOR_SIGNATURE);

    case PAYLOAD_HYPERCALL_TEST:
    case PAYLOAD_HYPERCALL_FLUSH_LOGS:
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    case PAYLOAD_HYPERCALL_UNLOAD:
        // Full teardown is special.  The old TestDriver handler already
        // restores guest state and returns true so the asm epilogue executes
        // VMXOFF/IRET.  If we fail-close this VMCALL, hv::stop() returns while
        // the vCPU is still virtualized and later frees live host stacks/EPT.
        if (PayloadBridgeCanForwardOldHandler())
        {
            PayloadBridgeRecordForward(basic_reason, code, key,
                                       PAYLOAD_BRIDGE_FORWARD_GENERIC,
                                       ctx ? ctx->rax : 0);
            return 0;
        }
        if (!PayloadBridgeCompleteHypercall(ctx, code, 0))
            return 0;
        PayloadBridgePrepareSelfStopGuestState();
        PayloadBridgeMarkSelfUnloadAck();
        // Special bridge return value: vmcall.asm preserves 2 as the
        // stop-virtualization signal instead of converting it to handled=0.
        return 2;

    case PAYLOAD_HYPERCALL_READ_PHYS_MEM:
        return PayloadBridgeHandleReadPhysMem(ctx, code);

    case PAYLOAD_HYPERCALL_WRITE_PHYS_MEM:
        return PayloadBridgeHandleWritePhysMem(ctx, code);

    case PAYLOAD_HYPERCALL_READ_VIRT_MEM:
        return PayloadBridgeHandleReadVirtMem(ctx, code);

    case PAYLOAD_HYPERCALL_WRITE_VIRT_MEM:
        return PayloadBridgeHandleWriteVirtMem(ctx, code);

    case PAYLOAD_HYPERCALL_QUERY_PROCESS_CR3:
        return PayloadBridgeHandleQueryProcessCr3(ctx, code);

    case PAYLOAD_HYPERCALL_INSTALL_EPT_HOOK:
        return PayloadBridgeHandleOldInstallEptHook(ctx, code);
    case PAYLOAD_HYPERCALL_REMOVE_EPT_HOOK:
        return PayloadBridgeHandleOldRemoveEptHook(ctx, code);
    case PAYLOAD_HYPERCALL_INSTALL_MMR:
        return PayloadBridgeHandleInstallMmr(ctx, code);
    case PAYLOAD_HYPERCALL_REMOVE_MMR:
        return PayloadBridgeHandleRemoveMmr(ctx, code);
    case PAYLOAD_HYPERCALL_REMOVE_ALL_MMRS:
        return PayloadBridgeHandleRemoveAllMmrs(ctx, code);
    case PAYLOAD_HYPERCALL_INSTALL_BREAKPOINT_HOOK:
        return PayloadBridgeHandleInstallBreakpointHook(ctx, code);
    case PAYLOAD_HYPERCALL_REMOVE_BREAKPOINT_HOOK:
        return PayloadBridgeHandleRemoveBreakpointHook(ctx, code);
    case PAYLOAD_HYPERCALL_ADD_VMCALL_HOOK:
        return PayloadBridgeHandleAddVmcallHook(ctx, code);
    case PAYLOAD_HYPERCALL_ENABLE_VMCALL_HOOK:
        return PayloadBridgeHandleEnableVmcallHook(ctx, code);
    case PAYLOAD_HYPERCALL_DISABLE_VMCALL_HOOK:
        return PayloadBridgeHandleDisableVmcallHook(ctx, code);
    case PAYLOAD_HYPERCALL_REMOVE_VMCALL_HOOK:
        return PayloadBridgeHandleRemoveVmcallHook(ctx, code);
    case PAYLOAD_HYPERCALL_EH_INSTALL:
        return PayloadBridgeHandleEhInstall(ctx, code);
    case PAYLOAD_HYPERCALL_EH_REMOVE:
        return PayloadBridgeHandleEhRemove(ctx, code);
    case PAYLOAD_HYPERCALL_EH_ENABLE:
        return PayloadBridgeHandleEhEnable(ctx, code);
    case PAYLOAD_HYPERCALL_EH_DISABLE:
        return PayloadBridgeHandleEhDisable(ctx, code);
    case PAYLOAD_HYPERCALL_EH_WRITE:
        return PayloadBridgeHandleEhWrite(ctx, code);
    case PAYLOAD_HYPERCALL_EH_GET_VA:
        return PayloadBridgeHandleEhGetVa(ctx, code);
    case PAYLOAD_HYPERCALL_EH_REMOVE_ALL_BY_PROCESS:
        return PayloadBridgeHandleEhRemoveAllByProcess(ctx, code);
    case PAYLOAD_HYPERCALL_VH_INSTALL:
        return PayloadBridgeHandleVhInstall(ctx, code);
    case PAYLOAD_HYPERCALL_VH_INSTALL_RET_ABS:
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    case PAYLOAD_HYPERCALL_VH_ENABLE:
        return PayloadBridgeHandleVhEnable(ctx, code);
    case PAYLOAD_HYPERCALL_VH_DISABLE:
        return PayloadBridgeHandleVhDisable(ctx, code);
    case PAYLOAD_HYPERCALL_VH_REMOVE:
        return PayloadBridgeHandleVhRemove(ctx, code);
    case PAYLOAD_HYPERCALL_VH_UNINIT:
        return PayloadBridgeHandleVhUninit(ctx, code);
    case PAYLOAD_HYPERCALL_VH_FIND_BLANK:
        return PayloadBridgeHandleVhFindBlank(ctx, code, false);
    case PAYLOAD_HYPERCALL_VH_FIND_BLANK_PAGE:
        return PayloadBridgeHandleVhFindBlank(ctx, code, true);
    case PAYLOAD_HYPERCALL_VH_TRAMP_ADD_PAGE:
        return PayloadBridgeHandleVhTrampAddPage(ctx, code);
    case PAYLOAD_HYPERCALL_VH_TRAMP_ADD_SLOT:
        return PayloadBridgeHandleVhTrampAddSlot(ctx, code);
    case PAYLOAD_HYPERCALL_VH_TRAMP_SET_READY:
        return PayloadBridgeHandleVhTrampSetReady(ctx, code);
    case PAYLOAD_HYPERCALL_HIDE_PHYSICAL_PAGE:
        return PayloadBridgeHandleHidePhysicalPage(ctx, code);
    case PAYLOAD_HYPERCALL_ADD_MMR_POINT:
    case PAYLOAD_HYPERCALL_DELETE_MMR_POINT:
        // TestDriver currently has enum IDs but no switch handlers for these
        // two legacy MMR-point commands, so rax=0 + skip is parity.
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    case PAYLOAD_HYPERCALL_PREPARE_SELF_HIDE_ADD:
        return PayloadBridgeHandlePrepareSelfHideAdd(ctx, code);
    case PAYLOAD_HYPERCALL_PREPARE_SELF_HIDE_COMMIT:
        return PayloadBridgeHandlePrepareSelfHideCommit(ctx, code);
    case PAYLOAD_HYPERCALL_GET_POOL_BLOCKS:
        return PayloadBridgeHandleGetPoolBlocks(ctx, code);

    case PAYLOAD_HYPERCALL_GET_PHYSICAL_ADDRESS:
        return PayloadBridgeHandleGetPhysicalAddress(ctx, code);

    case PAYLOAD_HYPERCALL_UNHIDE_PHYSICAL_PAGE:
        return PayloadBridgeHandleUnhidePhysicalPage(ctx, code);

    case PAYLOAD_HYPERCALL_UNHIDE_PFN_LIST:
        return PayloadBridgeHandleUnhidePfnList(ctx, code);

    case PAYLOAD_HYPERCALL_GET_HV_BASE:
        if (g_hv_diag_cache_ready && g_cached_hv_diag.image_base)
            return PayloadBridgeCompleteHypercall(ctx, code, g_cached_hv_diag.image_base);
        return PayloadBridgeUnhandledVmcall(ctx, basic_reason, code, key, ctx->rax, PAYLOAD_BRIDGE_FORWARD_GENERIC);

    case PAYLOAD_HYPERCALL_GET_GAMEVT_IMAGE_BASE:
        return PayloadBridgeHandleGetGameVtImageBase(ctx, code);

    case PAYLOAD_HYPERCALL_SAVE_GAMEVT_IMAGE_BASE:
        return PayloadBridgeHandleSaveGameVtImageBase(ctx, code);

    case PAYLOAD_HYPERCALL_GET_INFO:
        return PayloadBridgeHandleGetInfo(ctx, code);

    case PAYLOAD_HYPERCALL_VH_INIT_TRAMP_POOL:
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    case PAYLOAD_HYPERCALL_SET_AFFINITY_LOCK:
    {
        payload_u64 handled = PayloadBridgeHandleSetAffinityLock(ctx, code);
        if (handled)
            return handled;
        return PayloadBridgeUnhandledVmcall(ctx, basic_reason, code, key, ctx->rax, PAYLOAD_BRIDGE_FORWARD_GENERIC);
    }

    case PAYLOAD_HYPERCALL_HIDE_PFN_LIST:
        return PayloadBridgeHandleHidePfnList(ctx, code);

    case PAYLOAD_HYPERCALL_GET_HIDE_DIAG:
    {
        payload_u64 handled = PayloadBridgeHandleGetHideDiag(ctx, code);
        if (handled)
            return handled;
        return PayloadBridgeUnhandledVmcall(ctx, basic_reason, code, key, ctx->rax, PAYLOAD_BRIDGE_FORWARD_GENERIC);
    }

    case PAYLOAD_HYPERCALL_EPT_PROBE_INSTALL:
        return PayloadBridgeHandleEptProbeInstallRaw(ctx, code);

    case PAYLOAD_HYPERCALL_EPT_PROBE_REMOVE:
        return PayloadBridgeHandleEptProbeRemoveRaw(ctx, code);

    case PAYLOAD_HYPERCALL_EPT_PROBE_GET_HITS:
        return PayloadBridgeHandleEptProbeGetHitsRaw(ctx, code);

    case PAYLOAD_HYPERCALL_EPT_PROBE_CLEAR_HITS:
        return PayloadBridgeHandleEptProbeClearHitsRaw(ctx, code);

    case PAYLOAD_HYPERCALL_GET_RESIDENT_HV_DIAG:
    {
        payload_u64 handled = PayloadBridgeHandleHvDiag(ctx, code);
        if (handled)
            return handled;
        return PayloadBridgeUnhandledVmcall(ctx, basic_reason, code, key, ctx->rax, PAYLOAD_BRIDGE_FORWARD_GENERIC);
    }

    case PAYLOAD_HYPERCALL_MAP_HOST_RANGE:
    {
#if PAYLOAD_BRIDGE_SELF_MAP_ENABLED
        payload_u64 handled = PayloadBridgeHandleMapHostRange(ctx, code);
        if (handled)
            return handled;
#endif
        return PayloadBridgeUnhandledVmcall(ctx, basic_reason, code, key, ctx->rax, PAYLOAD_BRIDGE_FORWARD_GENERIC);
    }

    case PAYLOAD_HYPERCALL_SET_HOST_RSP:
    {
        payload_u64 old_rsp = 0;
        payload_u64 result = 0;
        if (ctx->rcx &&
            PayloadVmread(PAYLOAD_VMCS_HOST_RSP, &old_rsp) &&
            PayloadVmwrite(PAYLOAD_VMCS_HOST_RSP, ctx->rcx))
        {
            result = old_rsp;
        }
        return PayloadBridgeCompleteHypercall(ctx, code, result);
    }

    case PAYLOAD_HYPERCALL_SET_HOST_RIP:
    {
        payload_u64 old_rip = 0;
        payload_u64 result = 0;
        if (ctx->rcx &&
            PayloadVmread(PAYLOAD_VMCS_HOST_RIP, &old_rip) &&
            PayloadVmwrite(PAYLOAD_VMCS_HOST_RIP, ctx->rcx))
        {
            result = old_rip;
        }
        return PayloadBridgeCompleteHypercall(ctx, code, result);
    }

    case PAYLOAD_HYPERCALL_SET_KEEP_HV_ON_UNLOAD:
    {
        // While the VM-exit bridge is active, full unload must clear the
        // original TestDriver g_yvt_boot_flags, not only the payload shadow.
        // Forward this hypercall to the original handler exactly like unload;
        // otherwise DriverUnload sees KEEP_HV_ON_UNLOAD still set, hv::stop()
        // is skipped, and teardown can free/quarantine objects while CPUs are
        // still virtualized through the resident bridge.
        if (PayloadBridgeCanForwardOldHandler())
        {
            if (ctx)
            {
                if (ctx->rcx)
                {
                    g_payload_keep_hv_flags |= PAYLOAD_YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
                    g_payload_unload_quiesce = 0;
                }
                else
                {
                    g_payload_keep_hv_flags &= ~PAYLOAD_YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
                    // Do not set g_payload_unload_quiesce before forwarding
                    // SET_KEEP to the legacy handler.  The asm forwarding
                    // gate also checks that flag; setting it here cancels the
                    // very forward this branch requested, so the later
                    // hv::stop()/hypercall_unload path is forced onto the
                    // payload self-stop route instead of the known TestDriver
                    // stop handler.
                }
            }
            PayloadBridgeRecordForward(basic_reason, code, key,
                                       PAYLOAD_BRIDGE_FORWARD_GENERIC,
                                       ctx ? ctx->rax : 0);
            return 0;
        }

        payload_u64 handled = PayloadBridgeHandleSetKeepHvOnUnload(ctx, code);
        if (handled)
            return handled;
        return PayloadBridgeUnhandledVmcall(ctx, basic_reason, code, key, ctx->rax, PAYLOAD_BRIDGE_FORWARD_GENERIC);
    }

    case PAYLOAD_HYPERCALL_DBG_DISPATCH:
        return PayloadBridgeHandleDbgDispatch(ctx, code);

    case PAYLOAD_HYPERCALL_GET_PAYLOAD_STATUS:
        return PayloadBridgeHandlePayloadStatus(ctx, code);

    case PAYLOAD_HYPERCALL_SET_PAYLOAD_MODE:
        return PayloadBridgeHandleSetPayloadMode(ctx, code);

    case PAYLOAD_HYPERCALL_PAYLOAD_PING:
        return PayloadBridgeHandlePayloadPing(ctx, code);

    case PAYLOAD_HYPERCALL_VERIFY_HIDE_PFN_LIST:
        return PayloadBridgeHandleMemcheckHypercall(ctx, code);

    default:
        return PayloadBridgeUnhandledVmcall(ctx, basic_reason, code, key, ctx->rax, PAYLOAD_BRIDGE_FORWARD_UNKNOWN_CODE);
    }
}

