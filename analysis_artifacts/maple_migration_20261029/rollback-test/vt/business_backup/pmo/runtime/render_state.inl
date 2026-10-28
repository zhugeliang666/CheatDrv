// Split from pmo_runtime.inl: runtime/render_state.inl.
// Included through the wrapper; same translation unit.

static void PayloadBridgeCapturePmoRenderState()
{
    if (g_payload_legacy_ptrs_finalized)
        PayloadRedirectCachedLegacyPointersToShadows();

    g_payload_pmo_render_d2d_rt =
        PayloadReadKernelGlobalPointer(g_cached_hv_diag.render_d2d_rt_ptr);
    g_payload_pmo_render_brush =
        PayloadReadKernelGlobalPointer(g_cached_hv_diag.render_color_brush_ptr);
    g_payload_pmo_render_textfmt =
        PayloadReadKernelGlobalPointer(g_cached_hv_diag.render_text_format_ptr);
    g_payload_pmo_render_buf0 =
        PayloadReadKernelGlobalPointer(g_cached_hv_diag.render_buffer0_ptr);
    g_payload_pmo_render_buf0_hva =
        PayloadReadKernelGlobalPointer(g_cached_hv_diag.render_buffer0_hva_ptr);
    g_payload_pmo_render_desc =
        PayloadReadKernelGlobalPointer(g_cached_hv_diag.render_desc_buffer_ptr);
    g_payload_pmo_render_desc_hva =
        PayloadReadKernelGlobalPointer(g_cached_hv_diag.render_desc_buffer_hva_ptr);
}

static void PayloadBridgeApplyPmoSideEffects(payload_guest_context* ctx)
{
    if (!ctx)
        return;

    if (g_payload_legacy_ptrs_finalized)
        PayloadRedirectCachedLegacyPointersToShadows();

    // Preserve the minimum observable side effects that the old TestDriver PMO
    // path provided before render::init/tick: DWM hit/handler counters and the
    // latest swapChain pointer.  This keeps the rest of the legacy state machine
    // from seeing a permanently empty swapChain while the handler body itself is
    // resident-owned.
    PayloadPmoIncrementGhvCounter(g_cached_hv_diag.ghv_off_dwm_hit_count);
    PayloadPmoIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_handler_count);

    payload_u64 swap_ptr = g_cached_hv_diag.render_swapchain_ptr;
    if (!PayloadIsKernelPointer(swap_ptr))
        return;

    payload_u64 old_swap = PayloadReadHostU64(swap_ptr);
    payload_u64 is_finish = 0;
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_isfinish_ptr))
        is_finish = PayloadReadHostU8(g_cached_hv_diag.render_isfinish_ptr) ? 1ull : 0ull;

    g_payload_pmo_last_old_swapchain = old_swap;
    g_payload_pmo_last_isfinish = is_finish;

    if (ctx->rcx && PayloadIsCanonical(ctx->rcx) && (!old_swap || !is_finish))
        PayloadWriteHostU64(swap_ptr, ctx->rcx);

    PayloadBridgeCapturePmoRenderState();
    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_side_effect_count);
}

static bool PayloadPmoGetVFunc(payload_u64 guest_cr3, payload_u64 object_gva, payload_u64 index, payload_u64* function_out)
{
    if (function_out)
        *function_out = 0;
    if (!function_out || !guest_cr3 || !PayloadIsCanonical(object_gva))
        return false;

    payload_u64 left = 0;
    auto object_hva = (payload_u64*)PayloadGvaToHvaCr3(guest_cr3, object_gva, &left);
    if (!object_hva || left < sizeof(payload_u64))
        return false;

    payload_u64 vtbl = *object_hva;
    if (!PayloadIsCanonical(vtbl))
        return false;

    auto fn_hva = (payload_u64*)PayloadGvaToHvaCr3(
        guest_cr3,
        vtbl + index * sizeof(payload_u64),
        &left);
    if (!fn_hva || left < sizeof(payload_u64))
        return false;

    payload_u64 fn = *fn_hva;
    if (!PayloadIsCanonical(fn))
        return false;

    *function_out = fn;
    return true;
}

