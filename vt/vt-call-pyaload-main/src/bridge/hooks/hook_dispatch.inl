// Resident hook dispatch helpers split out from payload_bridge.inl.
// Included by payload_bridge.inl; keep functions static/inlined in the same translation unit.

static constexpr payload_u64 PAYLOAD_HOOK_PASSTHROUGH_WARMUP_MATCHES = 1ull;

enum payload_hook_reason : payload_u64
{
    PAYLOAD_HOOK_REASON_NONE = 0,
    PAYLOAD_HOOK_REASON_NO_RIP = 1,
    PAYLOAD_HOOK_REASON_NO_DIAG = 2,
    PAYLOAD_HOOK_REASON_NO_MATCH = 3,
    PAYLOAD_HOOK_REASON_MATCH_USER = 0x101,
    PAYLOAD_HOOK_REASON_MATCH_KERNEL = 0x102,
    PAYLOAD_HOOK_REASON_PASS_USER = 0x201,
    PAYLOAD_HOOK_REASON_PASS_KERNEL = 0x202,
    PAYLOAD_HOOK_REASON_PASS_FAIL = 0x301,
    PAYLOAD_HOOK_REASON_PMO_FORWARD = 0x401,
    PAYLOAD_HOOK_REASON_PMO_HANDLE = 0x402,
    PAYLOAD_HOOK_REASON_PMO_HANDLE_FAIL = 0x403,
};

static bool PayloadHookTrySlots(payload_u64 slots_base, payload_u64 count, payload_u64 rip, payload_u64 kind, payload_tramp_match* match)
{
    if (!slots_base || !rip || count > PAYLOAD_TRAMP_MAX_SLOTS)
        return false;

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 slot = slots_base + i * PAYLOAD_TRAMP_SLOT_SIZE;
        if (!PayloadReadHostU8(slot + PAYLOAD_TRAMP_SLOT_OFF_OCCUPIED))
            continue;

        payload_u64 tramp_va = PayloadReadHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TRAMP_VA);
        payload_u64 bp_rip = PayloadReadHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_BP_RIP);
        payload_u64 target_resume = PayloadReadHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TARGET_RESUME);
        if (!PayloadIsCanonical(tramp_va) ||
            !PayloadIsCanonical(bp_rip) ||
            !PayloadIsCanonical(target_resume) ||
            bp_rip <= tramp_va)
        {
            continue;
        }

        payload_u64 copied_size = bp_rip - tramp_va;
        if (!copied_size || copied_size > 15 || target_resume < copied_size)
            continue;

        payload_u64 target_start = target_resume - copied_size;
        if (target_start != rip)
            continue;

        if (match)
        {
            match->slot = slot;
            match->rip = rip;
            match->tramp_va = tramp_va;
            match->target_resume = target_resume;
            match->kind = kind;
        }
        g_payload_hook_last_bp_rip = bp_rip;
        return true;
    }

    return false;
}

static bool PayloadHookTryPool(payload_u64 pool, payload_u64 rip, payload_tramp_match* match)
{
    payload_tramp_match meta = {};
    if (!PayloadTrampPoolLooksValid(pool, &meta))
        return false;

    if (PayloadHookTrySlots(
            pool + PAYLOAD_TRAMP_POOL_USER_SLOTS_OFF,
            meta.user_slot_count,
            rip,
            1,
            &meta) ||
        PayloadHookTrySlots(
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

static bool PayloadHookFindByTrampPool(payload_u64 rip, payload_tramp_match* match)
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
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_scan_count);
        if (PayloadHookTryPool(cached, rip, match) && match && match->slot)
            return true;

        // A valid-looking cached pool is not authoritative.  After a resident
        // reload or a weak false-positive from the radius scan, the cached base
        // can still contain sane counts/ready bits but not the current hook's
        // slot.  Only stop here when cached is the expected diag pool; otherwise
        // continue to the expected-base lookup below.
        if (cached_valid &&
            cached == expected &&
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

    _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_scan_count);
    if (PayloadHookTryPool(expected, rip, match) && match && match->slot)
    {
        g_payload_tramp_pool_base = expected;
        return true;
    }

    for (payload_u64 delta = sizeof(payload_u64); delta <= PAYLOAD_TRAMP_POOL_SEARCH_RADIUS; delta += sizeof(payload_u64))
    {
        payload_u64 before = expected - delta;
        payload_u64 after = expected + delta;

        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_scan_count);
        if (PayloadHookTryPool(before, rip, match) && match && match->slot)
        {
            g_payload_tramp_pool_base = before;
            return true;
        }

        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_scan_count);
        if (PayloadHookTryPool(after, rip, match) && match && match->slot)
        {
            g_payload_tramp_pool_base = after;
            return true;
        }
    }

    return false;
}

static bool PayloadHookFindLegacySlotByRip(payload_u64 rip, payload_u64* out_type)
{
    if (out_type)
        *out_type = 0;
    if (!rip ||
        !PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) ||
        !g_cached_hv_diag.vt_hook_slot_count ||
        !g_cached_hv_diag.vt_hook_slot_size ||
        !g_cached_hv_diag.vt_hook_slot_off_data_type ||
        !g_cached_hv_diag.vt_hook_slot_off_occupied)
    {
        return false;
    }

    payload_u64 count = g_cached_hv_diag.vt_hook_slot_count;
    if (count > 64)
        count = 64;

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 slot = g_cached_hv_diag.vt_hook_table_ptr +
            i * g_cached_hv_diag.vt_hook_slot_size;
        if (!PayloadIsKernelPointer(slot))
            break;
        if (!PayloadReadHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied))
            continue;
        payload_u64 address = PayloadReadHostU64(
            slot + g_cached_hv_diag.vt_hook_slot_off_data_address);
        if (address != rip)
            continue;

        payload_u64 type = PayloadReadHostU64(
            slot + g_cached_hv_diag.vt_hook_slot_off_data_type);
        if (out_type)
            *out_type = type;
        return true;
    }

    return false;
}

static void PayloadPmoIncrementGhvCounter(payload_u64 offset)
{
    if (!offset ||
        !g_hv_diag_cache_ready ||
        !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
    {
        return;
    }

    payload_u64 field = g_cached_hv_diag.ghv + offset;
    if (!PayloadIsKernelPointer(field))
        return;

    _InterlockedIncrement64((volatile LONG64*)field);
}

static payload_u64 PayloadReadKernelGlobalPointer(payload_u64 ptr_to_global)
{
    if (!PayloadIsKernelPointer(ptr_to_global))
        return 0;
    return PayloadReadHostU64(ptr_to_global);
}

#include "../pmo/pmo_runtime.inl"
#include "runtime/hook_handlers.inl"

static payload_u64 PayloadBridgeProbeHookDispatch(payload_guest_context* ctx, payload_u64 key)
{
    if (!ctx)
        return 0;

    payload_u64 rip = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &rip) || !rip)
    {
        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_NO_RIP;
        return 0;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_probe_count);
    g_payload_hook_last_rip = rip;
    g_payload_hook_last_key = key;
    g_payload_hook_last_rax = ctx->rax;

    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
    {
        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_NO_DIAG;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_scan_fail_count);
        return 0;
    }

    payload_legacy_hook_info direct_info = {};

#if PAYLOAD_DIRECT_SLOT_CLAIM_ALL
    // Claim every resident legacy slot directly from vt_hook_table before the
    // trampoline-pool search.  This is the root fix: the hook-site VMCALL RIP
    // is matched against slot.data.address, and the already-recorded
    // trampoline metadata is copied from the same slot.  GetBuffer/type3 is not
    // special here; it gets a normal match->tramp_va so any pass-through
    // fallback is deterministic.  PMO/type1 intentionally stays on the proven
    // PMO path below for now because its resident handler uses the transparent
    // PMO trampoline hit as the side-effect/install trigger.
    if (PayloadHookFindLegacySlotInfoByRip(rip, &direct_info) &&
        direct_info.type &&
        direct_info.type != 1)
    {
        payload_tramp_match direct_match = {};
        direct_match.slot = direct_info.slot;
        direct_match.rip = rip;
        direct_match.tramp_va = direct_info.tramp_va;
        direct_match.target_resume = direct_info.target_resume;
        direct_match.kind = PayloadIsKernelPointer(rip) ? 2ull : 1ull;
        if (direct_info.bp_rip)
            g_payload_hook_last_bp_rip = direct_info.bp_rip;

        g_payload_hook_last_rip = rip;
        g_payload_hook_last_tramp_va = direct_match.tramp_va;
        g_payload_hook_last_target = direct_match.target_resume;
        g_payload_hook_last_kind = direct_match.kind;
        g_payload_hook_last_reason = direct_match.kind == 2
            ? PAYLOAD_HOOK_REASON_MATCH_KERNEL
            : PAYLOAD_HOOK_REASON_MATCH_USER;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_match_count);
        if (direct_match.kind == 2)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_kernel_match_count);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_user_match_count);

        payload_u64 handled = PayloadBridgeHandleResidentHook(ctx, &direct_match, &direct_info);
        if (handled)
            return handled;

        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PASS_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_passthrough_fail_count);
        return 0;
    }
#endif

#if PAYLOAD_MM4_DIRECT_RIP_CLAIM
    if (PayloadHookFindLegacySlotInfoByRip(rip, &direct_info) &&
        direct_info.type == 20)
    {
        payload_tramp_match direct_match = {};
        direct_match.slot = direct_info.slot;
        direct_match.rip = rip;
        direct_match.tramp_va = direct_info.tramp_va;
        direct_match.target_resume = direct_info.target_resume;
        direct_match.kind = 2;
        if (direct_info.bp_rip)
            g_payload_hook_last_bp_rip = direct_info.bp_rip;

        g_payload_hook_last_rip = rip;
        g_payload_hook_last_tramp_va = direct_match.tramp_va;
        g_payload_hook_last_target = direct_match.target_resume;
        g_payload_hook_last_kind = 2;
        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_MATCH_KERNEL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_match_count);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_kernel_match_count);

        payload_u64 handled = PayloadBridgeHandleResidentHook(ctx, &direct_match, &direct_info);
        if (handled)
            return handled;

        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PASS_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_passthrough_fail_count);
        return 0;
    }
#endif

    payload_tramp_match match = {};
    if (!PayloadHookFindByTrampPool(rip, &match) || !match.slot)
    {
        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_NO_MATCH;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_scan_fail_count);
        return 0;
    }

    g_payload_hook_last_rip = rip;
    g_payload_hook_last_tramp_va = match.tramp_va;
    g_payload_hook_last_target = match.target_resume;
    g_payload_hook_last_kind = match.kind;
    g_payload_hook_last_reason = (match.kind == 1)
        ? PAYLOAD_HOOK_REASON_MATCH_USER
        : PAYLOAD_HOOK_REASON_MATCH_KERNEL;

    payload_u64 matches = (payload_u64)_InterlockedIncrement64((volatile LONG64*)&g_payload_hook_match_count);
    if (match.kind == 1)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_user_match_count);
    else
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_kernel_match_count);

    // PMO (legacy hook type 1) is now claimed by the resident payload.  Do not
    // return 0 here: return 0 would forward the hook back into TestDriver's
    // vmcall_hook_dispatch, which defeats the PMO migration boundary.
    payload_legacy_hook_info legacy_info = {};
    if (PayloadHookFindLegacySlotInfoByRip(rip, &legacy_info) && legacy_info.type == 1)
    {
#if PAYLOAD_STABILITY_FORWARD_LEGACY_HOOKS
        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PMO_FORWARD;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_pmo_forward_count);
        return 0;
#endif

        if (!legacy_info.enabled)
            return PayloadHookPassThroughTrampoline(&match, legacy_info.type) ? 1 : 0;

        if (legacy_info.filter_by_process && legacy_info.process)
        {
            payload_u64 process = 0;
            payload_u64 thread = 0;
            if (!PayloadCurrentGuestIds(&process, &thread) || process != legacy_info.process)
            {
                g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PMO_FORWARD;
                return PayloadHookPassThroughTrampoline(&match, legacy_info.type) ? 1 : 0;
            }
        }

        return PayloadBridgeHandlePmoResident(ctx, rip, &match);
    }
    if (legacy_info.type)
    {
#if PAYLOAD_STABILITY_FORWARD_LEGACY_HOOKS
        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PMO_FORWARD;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_pmo_forward_count);
        return 0;
#endif
#if PAYLOAD_STABILITY_PMO_DRAW_NO_INSTALL
        // This diagnostic stage owns only the PMO draw path.  Keep all other
        // already-installed legacy hooks in TestDriver so "no hook install" also
        // means no extra resident hook handler surface.
        return 0;
#endif

        payload_u64 handled = PayloadBridgeHandleResidentHook(ctx, &match, &legacy_info);
        if (handled)
            return handled;
    }

    if (g_payload_hook_mode == PAYLOAD_HOOK_MODE_PASSTHROUGH &&
        matches >= PAYLOAD_HOOK_PASSTHROUGH_WARMUP_MATCHES)
    {
        if (PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, match.tramp_va))
        {
            g_payload_hook_last_reason = (match.kind == 1)
                ? PAYLOAD_HOOK_REASON_PASS_USER
                : PAYLOAD_HOOK_REASON_PASS_KERNEL;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_passthrough_count);
            return 1;
        }

        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PASS_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_passthrough_fail_count);
    }

    return 0;
}

