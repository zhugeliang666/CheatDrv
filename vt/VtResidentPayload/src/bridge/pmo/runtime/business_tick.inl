// Split from pmo_runtime.inl: runtime/business_tick.inl.
// Included through the wrapper; same translation unit.

static void PayloadBusinessTick(payload_guest_context* ctx)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_business_probe_count);
    g_payload_business_last_stage = PAYLOAD_BUSINESS_STAGE_NONE;
    g_payload_business_last_reason = PAYLOAD_BUSINESS_REASON_OK;
    g_payload_business_last_swapchain = g_payload_pmo_last_swapchain;
    g_payload_business_last_draw_done = g_payload_pmo_draw_done_count;

    if (!ctx ||
        !g_payload_pmo_last_isfinish ||
        !g_payload_pmo_render_d2d_rt ||
        !g_payload_pmo_render_brush ||
        !g_payload_pmo_render_textfmt ||
        !g_payload_pmo_render_buf0 ||
        !g_payload_pmo_render_buf0_hva)
    {
        g_payload_business_last_stage = PAYLOAD_BUSINESS_STAGE_NOT_READY;
        g_payload_business_last_reason = PAYLOAD_BUSINESS_REASON_NOT_READY;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_business_skip_count);
        return;
    }

    payload_u64 draw_done = g_payload_pmo_draw_done_count;
    g_payload_business_last_draw_done = draw_done;
    if (!draw_done || (draw_done & PAYLOAD_BUSINESS_TICK_FRAME_MASK))
    {
        g_payload_business_last_stage = PAYLOAD_BUSINESS_STAGE_THROTTLED;
        g_payload_business_last_reason = PAYLOAD_BUSINESS_REASON_THROTTLED;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_business_skip_count);
        return;
    }

    payload_u64 guest_cr3 = 0;
    g_payload_business_last_stage = PAYLOAD_BUSINESS_STAGE_SNAPSHOT;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
    {
        g_payload_business_last_reason = PAYLOAD_BUSINESS_REASON_VMREAD;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_business_fail_count);
        return;
    }

    g_payload_business_last_guest_cr3 = guest_cr3;
    g_payload_business_last_vcpu = PayloadCurrentVcpuIndex();

    // Payload-owned business landing zone.
    //
    // Keep this first layer side-effect free: no guest writes, no user callouts,
    // no TestDriver callbacks.  sjz/game logic can now be migrated here in
    // small slices while embedded TestDriver remains a pure VT/bootstrap
    // carrier and can be freetest/unloaded independently.
    _InterlockedIncrement64((volatile LONG64*)&g_payload_business_tick_count);
    g_payload_business_last_stage = PAYLOAD_BUSINESS_STAGE_READY;
    g_payload_business_last_reason = PAYLOAD_BUSINESS_REASON_OK;
}

