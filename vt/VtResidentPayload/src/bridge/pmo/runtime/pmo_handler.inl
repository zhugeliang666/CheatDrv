// Split from pmo_runtime.inl: runtime/pmo_handler.inl.
// Included through the wrapper; same translation unit.

#ifndef PAYLOAD_ENABLE_PMO_DRAW_CALLOUT
#define PAYLOAD_ENABLE_PMO_DRAW_CALLOUT 1
#endif

#ifndef PAYLOAD_ENABLE_PMO_RENDER_INIT_CALLOUT
#define PAYLOAD_ENABLE_PMO_RENDER_INIT_CALLOUT 1
#endif


static void PayloadPmoMaybeInitRenderState(payload_guest_context* ctx)
{
    if (!ctx || !g_payload_pmo_last_swapchain)
        return;

    if (g_payload_pmo_last_isfinish &&
        g_payload_pmo_render_d2d_rt &&
        g_payload_pmo_render_brush &&
        g_payload_pmo_render_textfmt &&
        g_payload_pmo_render_buf0 &&
        g_payload_pmo_render_buf0_hva &&
        g_payload_pmo_fake_texture &&
        g_payload_pmo_marker_ready &&
        g_payload_pmo_marker_texture)
    {
        return;
    }

    // Keep the old "PMO draw off" stability baseline by not issuing the text /
    // rectangle overlay draw calls below, but still run the one-time render/D3D
    // initialization that marks the swapchain state ready.  GetBuffer install
    // gates on g_payload_pmo_last_isfinish and needs the fake texture prepared;
    // otherwise stage-15 EPT never gets exercised and status stays st=0x12.
    PayloadPmoTryInitRenderState(ctx);
}

static void PayloadPmoMaybeDraw(payload_guest_context* ctx)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_draw_probe_count);
    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_NONE;
    g_payload_pmo_draw_last_result = 0;

    if (g_payload_overlay_hide_until_tsc &&
        (payload_u64)__rdtsc() < g_payload_overlay_hide_until_tsc)
    {
        g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_NOT_READY;
        return;
    }

    if ((!g_payload_pmo_last_isfinish ||
         !g_payload_pmo_render_d2d_rt ||
         !g_payload_pmo_render_brush ||
         !g_payload_pmo_render_textfmt ||
         !g_payload_pmo_render_buf0 ||
         !g_payload_pmo_render_buf0_hva) &&
        g_payload_pmo_last_swapchain)
    {
        if (!PayloadPmoTryInitRenderState(ctx))
        {
            g_payload_pmo_draw_last_result = g_payload_pmo_call_last_reason;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_draw_fail_count);
            return;
        }
    }

    if (!ctx ||
        !g_payload_pmo_last_isfinish ||
        !g_payload_pmo_render_d2d_rt ||
        !g_payload_pmo_render_brush ||
        !g_payload_pmo_render_textfmt ||
        !g_payload_pmo_render_buf0 ||
        !g_payload_pmo_render_buf0_hva)
    {
        g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_NOT_READY;
        return;
    }

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
    {
        g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_NOT_READY;
        return;
    }

    payload_u64 begin_fn = 0;
    payload_u64 brush_fn = 0;
    payload_u64 text_fn = 0;
    payload_u64 end_fn = 0;
    payload_u64 fill_rect_fn = 0;
    payload_u64 ret = 0;
    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    payload_u64 end_args[3] = { g_payload_pmo_render_d2d_rt, 0, 0 };
    static const unsigned short kTitle[] = {
        'Y','V','T',' ','p','a','y','l','o','a','d',' ','P','M','O',0
    };
    unsigned short line1[160] = {};
    unsigned short line2[160] = {};

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_VFUNC_BEGIN;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_d2d_rt, 48, &begin_fn))
        goto draw_fail;
    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_VFUNC_BRUSH;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_brush, 8, &brush_fn))
        goto draw_fail;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_d2d_rt, 17, &fill_rect_fn))
        goto draw_fail;
    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_VFUNC_END;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_d2d_rt, 49, &end_fn))
        goto draw_fail;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_draw_ready_count);

    args[0] = g_payload_pmo_render_d2d_rt;
    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_BEGIN;
    if (!PayloadPmoCallUser(ctx, begin_fn, args, 1, &ret))
        goto draw_fail;


    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_BRUSH;
    if (!PayloadPmoSetBrushColor(
            ctx,
            brush_fn,
            0x3F800000u, // 1.0f red
            0x00000000u, // 0.0f
            0x00000000u, // 0.0f
            0x3F4CCCCDu, // 0.8f
            &ret))
    {
        PayloadPmoCallUser(ctx, end_fn, end_args, 3, &ret);
        goto draw_fail;
    }


    if (!PayloadPmoDrawFilledRect(
            ctx,
            fill_rect_fn,
            0x41600000u, // 14.0f
            0x00000000u, // 0.0f
            0x43D20000u, // 420.0f
            0x42500000u, // 52.0f
            &ret))
    {
        PayloadPmoCallUser(ctx, end_fn, end_args, 3, &ret);
        goto draw_fail;
    }

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_END;
    if (!PayloadPmoCallUser(ctx, end_fn, end_args, 3, &ret))
        goto draw_fail;
    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_DONE;
    g_payload_pmo_draw_last_result = ret;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_draw_done_count);
    return;

    if (!PayloadPmoSetBrushColor(
            ctx,
            brush_fn,
            0x00000000u, // 0.0f
            0x3F800000u, // 1.0f
            0x00000000u, // 0.0f
            0x3F800000u, // 1.0f
            &ret))
    {
        PayloadPmoCallUser(ctx, end_fn, end_args, 3, &ret);
        goto draw_fail;
    }

    PayloadPmoBuildCountersLine(line1, 160);
    PayloadPmoBuildVcpuLine(line2, 160);

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_TEXT;
    if (!PayloadPmoDrawTextLine(
            ctx,
            text_fn,
            0x41A00000u, // 20.0f
            0x40000000u, // 2.0f
            kTitle,
            PayloadPmoTextLength(kTitle),
            &ret) ||
        !PayloadPmoDrawTextLine(
            ctx,
            text_fn,
            0x41A00000u, // 20.0f
            0x41900000u, // 18.0f
            line1,
            PayloadPmoTextLength(line1),
            &ret) ||
        !PayloadPmoDrawTextLine(
            ctx,
            text_fn,
            0x41A00000u, // 20.0f
            0x42080000u, // 34.0f
            line2,
            PayloadPmoTextLength(line2),
            &ret))
    {
        PayloadPmoCallUser(ctx, end_fn, end_args, 3, &ret);
        goto draw_fail;
    }

    args[0] = g_payload_pmo_render_d2d_rt;
    args[1] = 0;
    args[2] = 0;
    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_END;
    if (!PayloadPmoCallUser(ctx, end_fn, args, 3, &ret))
        goto draw_fail;

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_DONE;
    g_payload_pmo_draw_last_result = ret;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_draw_done_count);
    return;

draw_fail:
    g_payload_pmo_draw_last_result = g_payload_pmo_call_last_reason;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_draw_fail_count);
}

static payload_u64 PayloadBridgeHandlePmoResident(payload_guest_context* ctx, payload_u64 rip, const payload_tramp_match* match)
{
    if (!ctx || !match || !match->tramp_va)
    {
        g_payload_pmo_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_fail_count);
        return 0;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_probe_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_match_count);
    g_payload_pmo_last_rip = rip;
    g_payload_pmo_last_tramp_va = match->tramp_va;
    g_payload_pmo_last_target = match->target_resume;
    g_payload_pmo_last_swapchain = ctx->rcx;

    if (g_payload_unload_quiesce)
    {
        if (!PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, match->tramp_va))
        {
            g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE_FAIL;
            g_payload_pmo_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE_FAIL;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_fail_count);
            return 0;
        }
        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE;
        g_payload_pmo_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_handle_count);
        return 1;
    }

    PayloadBridgeApplyPmoSideEffects(ctx);
#if PAYLOAD_ENABLE_PMO_RENDER_INIT_CALLOUT
    PayloadPmoMaybeInitRenderState(ctx);
#endif
#if PAYLOAD_ENABLE_PMO_DRAW_CALLOUT
    PayloadPmoMaybeDraw(ctx);
#endif
#if PAYLOAD_ENABLE_NATIVE_GETBUFFER_INSTALL
    PayloadPmoTryInstallGetBuffer(ctx);
#endif
#if PAYLOAD_ENABLE_NATIVE_SWAPCHAIN_EXTRA_INSTALL
    PayloadPmoTryInstallSwapchainExtraHooks(ctx);
#endif
#if PAYLOAD_ENABLE_NATIVE_COPY_DUP_INSTALL
    PayloadPmoTryInstallCopyDuplicateHooks(ctx);
#endif
#if PAYLOAD_ENABLE_NATIVE_NT_MEMORY_INSTALL
    PayloadPmoTryInstallNtMemoryHooks(ctx);
#endif
#if PAYLOAD_ENABLE_NATIVE_MM_FILTER_INSTALL
    PayloadPmoTryInstallMmFilterHooks(ctx);
#endif
    PayloadBusinessTick(ctx);

    if (!PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, match->tramp_va))
    {
        g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE_FAIL;
        g_payload_pmo_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_fail_count);
        return 0;
    }

    // PMO type=1 is now consumed by resident payload code.  For this migration
    // step we execute the original bytes via the trampoline and continue; the
    // render call-out body is intentionally a follow-up layer on top of this
    // resident dispatch, not a forward to TestDriver's old PMO handler.
    g_payload_hook_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE;
    g_payload_pmo_last_reason = PAYLOAD_HOOK_REASON_PMO_HANDLE;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_handle_count);
    return 1;
}

