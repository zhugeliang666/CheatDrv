// Split from pmo_runtime.inl: runtime/render_init.inl.
// Included through the wrapper; same translation unit.

#ifndef PAYLOAD_FORCE_GETBUFFER_PURPLE
#define PAYLOAD_FORCE_GETBUFFER_PURPLE 1
#endif

static payload_u64 PayloadPmoTextLength(const unsigned short* text)
{
    payload_u64 len = 0;
    if (!text)
        return 0;
    while (text[len])
        ++len;
    return len;
}

static void PayloadPmoWriteWideString(void* dst, const unsigned short* text, payload_u64 max_chars)
{
    if (!dst || !text || !max_chars)
        return;

    auto out = (unsigned short*)dst;
    payload_u64 i = 0;
    for (; i + 1 < max_chars && text[i]; ++i)
        out[i] = text[i];
    out[i] = 0;
}

static bool PayloadPmoReadGuestU64(payload_u64 guest_cr3, payload_u64 gva, payload_u64* out)
{
    if (!out)
        return false;
    *out = 0;
    return PayloadGuestCopyToHostBuffer(guest_cr3, gva, out, sizeof(*out));
}

static bool PayloadPmoWriteGuest(payload_u64 guest_cr3, payload_u64 gva, const void* src, payload_u64 size)
{
    return PayloadGuestCopyFromHostBuffer(guest_cr3, gva, src, size);
}

static bool PayloadPmoResolveUserPage(payload_u64 guest_cr3, payload_u64 gva, payload_u64* hva_out)
{
    if (hva_out)
        *hva_out = 0;
    if (!hva_out || !guest_cr3 || !PayloadIsCanonical(gva))
        return false;

    payload_u64 left = 0;
    auto hva = PayloadGvaToHvaCr3(guest_cr3, gva, &left);
    if (!hva || left < 0x100)
        return false;

    *hva_out = (payload_u64)hva;
    return true;
}

static bool PayloadPmoAllocUserScratch(payload_guest_context* ctx,
                                       payload_u64 guest_cr3,
                                       payload_u64* gva_out,
                                       payload_u64* hva_out)
{
    if (gva_out)
        *gva_out = 0;
    if (hva_out)
        *hva_out = 0;
    if (!ctx || !gva_out || !hva_out ||
        !PayloadIsCanonical(g_cached_hv_diag.ntapi_virtual_alloc))
    {
        return false;
    }

    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    payload_u64 ret = 0;
    args[0] = 0;
    args[1] = 0x1000;
    args[2] = 0x3000; // MEM_COMMIT | MEM_RESERVE
    args[3] = 0x4;    // PAGE_READWRITE
    if (!PayloadPmoCallUser(ctx, g_cached_hv_diag.ntapi_virtual_alloc, args, 4, &ret) ||
        !PayloadIsCanonical(ret))
    {
        return false;
    }

    // Touch the page from the guest so demand-zero PTEs are materialized before
    // the payload writes through the host direct mapping.
    if (PayloadIsCanonical(g_cached_hv_diag.ntapi_read_process_memory))
    {
        payload_u64 rpm_args[PAYLOAD_PMO_MAX_ARGS] = {};
        payload_u64 rpm_ret = 0;
        rpm_args[0] = ~0ull; // current process pseudo handle
        rpm_args[1] = ret;
        rpm_args[2] = ret;
        rpm_args[3] = 1;
        rpm_args[4] = 0;
        PayloadPmoCallUser(ctx, g_cached_hv_diag.ntapi_read_process_memory, rpm_args, 5, &rpm_ret);
    }

    payload_u64 hva = 0;
    if (!PayloadPmoResolveUserPage(guest_cr3, ret, &hva))
        return false;

    PayloadZeroMemory((void*)hva, 0x1000);
    *gva_out = ret;
    *hva_out = hva;
    return true;
}

static bool PayloadPmoSucceeded(payload_u64 hr)
{
    return (hr & 0x80000000ull) == 0;
}

static void PayloadPmoPublishRenderState()
{
    if (g_payload_legacy_ptrs_finalized)
        PayloadRedirectCachedLegacyPointersToShadows();

    if (PayloadIsKernelPointer(g_cached_hv_diag.render_swapchain_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.render_swapchain_ptr, g_payload_pmo_last_swapchain);
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_isfinish_ptr))
        PayloadWriteHostU8(g_cached_hv_diag.render_isfinish_ptr, 1);
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_d2d_rt_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.render_d2d_rt_ptr, g_payload_pmo_render_d2d_rt);
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_color_brush_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.render_color_brush_ptr, g_payload_pmo_render_brush);
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_text_format_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.render_text_format_ptr, g_payload_pmo_render_textfmt);
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_buffer0_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.render_buffer0_ptr, g_payload_pmo_render_buf0);
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_buffer0_hva_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.render_buffer0_hva_ptr, g_payload_pmo_render_buf0_hva);
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_desc_buffer_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.render_desc_buffer_ptr, g_payload_pmo_render_desc);
    if (PayloadIsKernelPointer(g_cached_hv_diag.render_desc_buffer_hva_ptr))
        PayloadWriteHostU64(g_cached_hv_diag.render_desc_buffer_hva_ptr, g_payload_pmo_render_desc_hva);
}

enum payload_pmo_marker_stage : payload_u64
{
    PAYLOAD_PMO_MARKER_STAGE_NONE = 0,
    PAYLOAD_PMO_MARKER_STAGE_GET_DESC = 1,
    PAYLOAD_PMO_MARKER_STAGE_CREATE_TEXTURE = 2,
    PAYLOAD_PMO_MARKER_STAGE_CREATE_RTV = 3,
    PAYLOAD_PMO_MARKER_STAGE_CLEAR = 4,
    PAYLOAD_PMO_MARKER_STAGE_ADDREF = 5,
    PAYLOAD_PMO_MARKER_STAGE_DONE = 0x10,
};

static bool PayloadPmoTryInitMarkerTexture(payload_guest_context* ctx,
                                           payload_u64 guest_cr3,
                                           payload_u64 desc,
                                           payload_u64 desc_hva,
                                           payload_u64 entity,
                                           payload_u64 entity_hva)
{
    if (g_payload_pmo_marker_ready && g_payload_pmo_marker_texture)
        return true;
    if (!ctx || !guest_cr3 || !desc || !desc_hva || !entity || !entity_hva ||
        !g_payload_pmo_render_device ||
        !g_payload_pmo_render_context ||
        !g_payload_pmo_render_surface)
    {
        g_payload_pmo_marker_stage = PAYLOAD_PMO_MARKER_STAGE_NONE;
        return false;
    }

    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    payload_u64 ret = 0;
    payload_u64 fn = 0;
    payload_u64 texture = 0;
    payload_u64 rtv = 0;

    g_payload_pmo_marker_stage = PAYLOAD_PMO_MARKER_STAGE_GET_DESC;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_surface, 10, &fn))
        return false;
    PayloadZeroMemory((void*)desc_hva, 0x1000);
    PayloadZeroMemory((void*)entity_hva, 0x1000);
    args[0] = g_payload_pmo_render_surface;
    args[1] = desc;
    if (!PayloadPmoCallUser(ctx, fn, args, 2, &ret))
        return false;

    g_payload_pmo_marker_stage = PAYLOAD_PMO_MARKER_STAGE_CREATE_TEXTURE;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_device, 5, &fn))
        return false;
    PayloadZeroMemory((void*)entity_hva, 0x1000);
    args[0] = g_payload_pmo_render_device;
    args[1] = desc;
    args[2] = 0;
    args[3] = entity;
    if (!PayloadPmoCallUser(ctx, fn, args, 4, &ret) ||
        !PayloadPmoSucceeded(ret) ||
        !PayloadPmoReadGuestU64(guest_cr3, entity, &texture) ||
        !PayloadIsCanonical(texture))
    {
        return false;
    }
    g_payload_pmo_marker_texture = texture;

    g_payload_pmo_marker_stage = PAYLOAD_PMO_MARKER_STAGE_CREATE_RTV;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_device, 9, &fn))
        return false;
    PayloadZeroMemory((void*)entity_hva, 0x1000);
    args[0] = g_payload_pmo_render_device;
    args[1] = texture;
    args[2] = 0;
    args[3] = entity;
    if (!PayloadPmoCallUser(ctx, fn, args, 4, &ret) ||
        !PayloadPmoSucceeded(ret) ||
        !PayloadPmoReadGuestU64(guest_cr3, entity, &rtv) ||
        !PayloadIsCanonical(rtv))
    {
        return false;
    }

    g_payload_pmo_marker_stage = PAYLOAD_PMO_MARKER_STAGE_CLEAR;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_context, 50, &fn))
        return false;
    const unsigned int magenta_rgba[4] =
    {
        0x3F800000u, // 1.0f R
        0x00000000u, // 0.0f G
        0x3F800000u, // 1.0f B
        0x3F800000u, // 1.0f A
    };
    PayloadZeroMemory((void*)desc_hva, 0x1000);
    PayloadCopyMemory((void*)desc_hva, magenta_rgba, sizeof(magenta_rgba));
    args[0] = g_payload_pmo_render_context;
    args[1] = rtv;
    args[2] = desc;
    if (!PayloadPmoCallUser(ctx, fn, args, 3, &ret))
        return false;

    payload_u64 release_fn = 0;
    if (PayloadPmoGetVFunc(guest_cr3, rtv, 2, &release_fn))
    {
        payload_u64 rel_args[PAYLOAD_PMO_MAX_ARGS] = {};
        rel_args[0] = rtv;
        PayloadPmoCallUser(ctx, release_fn, rel_args, 1, &ret);
    }

    g_payload_pmo_marker_stage = PAYLOAD_PMO_MARKER_STAGE_ADDREF;
    if (PayloadPmoGetVFunc(guest_cr3, texture, 1, &fn))
    {
        args[0] = texture;
        for (payload_u64 i = 0; i < 100; ++i)
            PayloadPmoCallUser(ctx, fn, args, 1, &ret);
    }

    g_payload_pmo_marker_ready = 1;
    g_payload_pmo_marker_stage = PAYLOAD_PMO_MARKER_STAGE_DONE;
    return true;
}

static bool PayloadPmoCopyMarkerIntoFakeTexture(payload_guest_context* ctx,
                                                payload_u64 guest_cr3)
{
#if PAYLOAD_FORCE_GETBUFFER_PURPLE
    if (!ctx ||
        !guest_cr3 ||
        !g_payload_pmo_render_context ||
        !g_payload_pmo_fake_texture ||
        !g_payload_pmo_marker_texture)
    {
        return false;
    }

    payload_u64 fn = 0;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_context, 47, &fn))
        return false;

    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    payload_u64 ret = 0;
    args[0] = g_payload_pmo_render_context;
    args[1] = g_payload_pmo_fake_texture;
    args[2] = g_payload_pmo_marker_texture;
    return PayloadPmoCallUser(ctx, fn, args, 3, &ret);
#else
    (void)ctx;
    (void)guest_cr3;
    return false;
#endif
}

static void PayloadPmoTryInitD3DTexture(payload_guest_context* ctx,
                                        payload_u64 guest_cr3,
                                        payload_u64 desc,
                                        payload_u64 desc_hva,
                                        payload_u64 entity,
                                        payload_u64 entity_hva)
{
    if (!ctx || !guest_cr3 || !g_payload_pmo_last_swapchain ||
        !desc || !desc_hva || !entity || !entity_hva)
    {
        return;
    }

    struct payload_pmo_guid
    {
        unsigned int d1;
        unsigned short d2;
        unsigned short d3;
        unsigned char d4[8];
    };

    static const payload_pmo_guid kIID_ID3D11Device =
        { 0xdb6f6ddbu, 0xac77u, 0x4e88u, { 0x82, 0x53, 0x81, 0x9d, 0xf9, 0xbb, 0xf1, 0x40 } };
    static const payload_pmo_guid kIID_ID3D11Texture2D =
        { 0x6f15aaf2u, 0xd208u, 0x4e89u, { 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c } };

    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    payload_u64 ret = 0;
    payload_u64 fn = 0;

    if (!g_payload_pmo_render_device &&
        PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_last_swapchain, 7, &fn))
    {
        PayloadZeroMemory((void*)desc_hva, 0x1000);
        PayloadZeroMemory((void*)entity_hva, 0x1000);
        PayloadCopyMemory((void*)desc_hva, &kIID_ID3D11Device, sizeof(kIID_ID3D11Device));
        args[0] = g_payload_pmo_last_swapchain;
        args[1] = desc;
        args[2] = entity;
        payload_u64 device = 0;
        if (PayloadPmoCallUser(ctx, fn, args, 3, &ret) &&
            PayloadPmoSucceeded(ret) &&
            PayloadPmoReadGuestU64(guest_cr3, entity, &device))
        {
            g_payload_pmo_render_device = PayloadIsCanonical(device) ? device : 0;
        }
    }

    if (g_payload_pmo_render_device && !g_payload_pmo_render_context &&
        PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_device, 40, &fn))
    {
        PayloadZeroMemory((void*)entity_hva, 0x1000);
        args[0] = g_payload_pmo_render_device;
        args[1] = entity;
        payload_u64 context = 0;
        if (PayloadPmoCallUser(ctx, fn, args, 2, &ret) &&
            PayloadPmoReadGuestU64(guest_cr3, entity, &context))
        {
            g_payload_pmo_render_context = PayloadIsCanonical(context) ? context : 0;
        }
    }

    if (!g_payload_pmo_render_surface &&
        PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_last_swapchain, 9, &fn))
    {
        PayloadZeroMemory((void*)desc_hva, 0x1000);
        PayloadZeroMemory((void*)entity_hva, 0x1000);
        PayloadCopyMemory((void*)desc_hva, &kIID_ID3D11Texture2D, sizeof(kIID_ID3D11Texture2D));
        args[0] = g_payload_pmo_last_swapchain;
        args[1] = 0;
        args[2] = desc;
        args[3] = entity;
        payload_u64 surface = 0;
        if (PayloadPmoCallUser(ctx, fn, args, 4, &ret) &&
            PayloadPmoSucceeded(ret) &&
            PayloadPmoReadGuestU64(guest_cr3, entity, &surface))
        {
            g_payload_pmo_render_surface = PayloadIsCanonical(surface) ? surface : 0;
        }
    }

    if (!g_payload_pmo_fake_texture &&
        g_payload_pmo_render_device &&
        g_payload_pmo_render_context &&
        g_payload_pmo_render_surface)
    {
        payload_u64 texture = 0;
        if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_surface, 10, &fn))
            return;
        PayloadZeroMemory((void*)desc_hva, 0x1000);
        args[0] = g_payload_pmo_render_surface;
        args[1] = desc;
        if (!PayloadPmoCallUser(ctx, fn, args, 2, &ret))
            return;

        if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_device, 5, &fn))
            return;
        PayloadZeroMemory((void*)entity_hva, 0x1000);
        args[0] = g_payload_pmo_render_device;
        args[1] = desc;
        args[2] = 0;
        args[3] = entity;
        if (!PayloadPmoCallUser(ctx, fn, args, 4, &ret) ||
            !PayloadPmoSucceeded(ret) ||
            !PayloadPmoReadGuestU64(guest_cr3, entity, &texture) ||
            !PayloadIsCanonical(texture))
        {
            return;
        }

        if (PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_render_context, 47, &fn))
        {
            args[0] = g_payload_pmo_render_context;
            args[1] = texture;
            args[2] = g_payload_pmo_render_surface;
            PayloadPmoCallUser(ctx, fn, args, 3, &ret);
        }

        if (PayloadPmoGetVFunc(guest_cr3, texture, 1, &fn))
        {
            args[0] = texture;
            for (payload_u64 i = 0; i < 16; ++i)
                PayloadPmoCallUser(ctx, fn, args, 1, &ret);
        }

        g_payload_pmo_fake_texture = texture;
    }

    if (!g_payload_pmo_marker_ready || !g_payload_pmo_marker_texture)
    {
        PayloadPmoTryInitMarkerTexture(
            ctx,
            guest_cr3,
            desc,
            desc_hva,
            entity,
            entity_hva);
    }

    // For the purple validation build, keep the TestDriver-stable return
    // object class/lifetime (fakeTexture) and only make its contents magenta.
    // Returning the separate marker texture directly to capture clients can
    // drive dxgmms2 into the VidMm Lock/ZeroIfNeeded path with inconsistent
    // resource state on some screen-capture tools.
    PayloadPmoCopyMarkerIntoFakeTexture(ctx, guest_cr3);
}

static bool PayloadPmoTryInitRenderState(payload_guest_context* ctx)
{
    if (!ctx || !g_payload_pmo_last_swapchain)
        return false;
    if (g_payload_pmo_last_isfinish &&
        g_payload_pmo_render_d2d_rt &&
        g_payload_pmo_render_brush &&
        g_payload_pmo_render_textfmt &&
        g_payload_pmo_render_buf0 &&
        g_payload_pmo_render_buf0_hva)
    {
        if ((!g_payload_pmo_fake_texture ||
             !g_payload_pmo_marker_ready ||
             !g_payload_pmo_marker_texture) &&
            g_payload_pmo_render_desc &&
            g_payload_pmo_render_desc_hva &&
            g_payload_pmo_render_entity &&
            g_payload_pmo_render_entity_hva)
        {
            payload_u64 guest_cr3_retry = 0;
            if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3_retry) && guest_cr3_retry)
            {
                PayloadPmoTryInitD3DTexture(
                    ctx,
                    guest_cr3_retry,
                    g_payload_pmo_render_desc,
                    g_payload_pmo_render_desc_hva,
                    g_payload_pmo_render_entity,
                    g_payload_pmo_render_entity_hva);
            }
        }
        return true;
    }
    if (!PayloadIsCanonical(g_cached_hv_diag.ntapi_d2d1_create_factory) ||
        !PayloadIsCanonical(g_cached_hv_diag.ntapi_dwrite_create_factory))
    {
        return false;
    }

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return false;

    payload_u64 desc = g_payload_pmo_render_desc;
    payload_u64 desc_hva = g_payload_pmo_render_desc_hva;
    payload_u64 entity = g_payload_pmo_render_entity;
    payload_u64 entity_hva = g_payload_pmo_render_entity_hva;
    payload_u64 buf0 = g_payload_pmo_render_buf0;
    payload_u64 buf0_hva = g_payload_pmo_render_buf0_hva;

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_INIT_ALLOC;
    if (!desc || !desc_hva)
    {
        if (!PayloadPmoAllocUserScratch(ctx, guest_cr3, &desc, &desc_hva))
            return false;
    }
    if (!entity || !entity_hva)
    {
        if (!PayloadPmoAllocUserScratch(ctx, guest_cr3, &entity, &entity_hva))
            return false;
        g_payload_pmo_render_entity = entity;
        g_payload_pmo_render_entity_hva = entity_hva;
    }
    if (!buf0 || !buf0_hva)
    {
        if (!PayloadPmoAllocUserScratch(ctx, guest_cr3, &buf0, &buf0_hva))
            return false;
    }

    struct payload_pmo_guid
    {
        unsigned int d1;
        unsigned short d2;
        unsigned short d3;
        unsigned char d4[8];
    };
    struct payload_pmo_rt_props
    {
        unsigned int type;
        unsigned int format;
        unsigned int alpha;
        unsigned int dpi_x_bits;
        unsigned int dpi_y_bits;
        unsigned int usage;
        unsigned int min_level;
    };
    struct payload_pmo_color_bits
    {
        unsigned int r;
        unsigned int g;
        unsigned int b;
        unsigned int a;
    };

    static const payload_pmo_guid kIID_ID2D1Factory =
        { 0x06152247u, 0x6f50u, 0x465au, { 0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07 } };
    static const payload_pmo_guid kIID_IDXGISurface =
        { 0xcafcb56cu, 0x6ac3u, 0x4889u, { 0xbf, 0x47, 0x9e, 0x23, 0xbb, 0xd2, 0x60, 0xec } };
    static const payload_pmo_guid kIID_IDWriteFactory =
        { 0xb859ee5au, 0xd838u, 0x4b5bu, { 0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48 } };
    static const unsigned short kFontName[] = { 'S','e','g','o','e',' ','U','I',0 };
    static const unsigned short kLocaleName[] = { 'e','n','-','U','S',0 };

    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    payload_u64 ret = 0;
    payload_u64 d2d_factory = 0;
    payload_u64 d2d_surface = 0;
    payload_u64 d2d_rt = 0;
    payload_u64 brush = 0;
    payload_u64 dwrite_factory = 0;
    payload_u64 textfmt = 0;
    payload_u64 fn = 0;

    PayloadPmoTryInitD3DTexture(ctx, guest_cr3, desc, desc_hva, entity, entity_hva);

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_INIT_D2D_FACTORY;
    PayloadZeroMemory((void*)desc_hva, 0x1000);
    PayloadCopyMemory((void*)desc_hva, &kIID_ID2D1Factory, sizeof(kIID_ID2D1Factory));
    args[0] = 0;
    args[1] = desc;
    args[2] = 0;
    args[3] = entity;
    if (!PayloadPmoCallUser(ctx, g_cached_hv_diag.ntapi_d2d1_create_factory, args, 4, &ret) ||
        !PayloadPmoSucceeded(ret) ||
        !PayloadPmoReadGuestU64(guest_cr3, entity, &d2d_factory) ||
        !PayloadIsCanonical(d2d_factory))
    {
        return false;
    }

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_INIT_SURFACE;
    if (!PayloadPmoGetVFunc(guest_cr3, g_payload_pmo_last_swapchain, 9, &fn))
        return false;
    PayloadZeroMemory((void*)desc_hva, 0x1000);
    PayloadCopyMemory((void*)desc_hva, &kIID_IDXGISurface, sizeof(kIID_IDXGISurface));
    args[0] = g_payload_pmo_last_swapchain;
    args[1] = 0;
    args[2] = desc;
    args[3] = entity;
    if (!PayloadPmoCallUser(ctx, fn, args, 4, &ret) ||
        !PayloadPmoSucceeded(ret) ||
        !PayloadPmoReadGuestU64(guest_cr3, entity, &d2d_surface) ||
        !PayloadIsCanonical(d2d_surface))
    {
        return false;
    }

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_INIT_RT;
    if (!PayloadPmoGetVFunc(guest_cr3, d2d_factory, 15, &fn))
        return false;
    payload_pmo_rt_props props = {};
    props.alpha = 1; // D2D1_ALPHA_MODE_PREMULTIPLIED
    PayloadZeroMemory((void*)desc_hva, 0x1000);
    PayloadCopyMemory((void*)desc_hva, &props, sizeof(props));
    args[0] = d2d_factory;
    args[1] = d2d_surface;
    args[2] = desc;
    args[3] = entity;
    if (!PayloadPmoCallUser(ctx, fn, args, 4, &ret) ||
        !PayloadPmoSucceeded(ret) ||
        !PayloadPmoReadGuestU64(guest_cr3, entity, &d2d_rt) ||
        !PayloadIsCanonical(d2d_rt))
    {
        return false;
    }

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_INIT_BRUSH;
    if (!PayloadPmoGetVFunc(guest_cr3, d2d_rt, 8, &fn))
        return false;
    payload_pmo_color_bits red = { 0x3F800000u, 0, 0, 0x3F800000u };
    PayloadZeroMemory((void*)desc_hva, 0x1000);
    PayloadCopyMemory((void*)desc_hva, &red, sizeof(red));
    args[0] = d2d_rt;
    args[1] = desc;
    args[2] = 0;
    args[3] = entity;
    if (!PayloadPmoCallUser(ctx, fn, args, 4, &ret) ||
        !PayloadPmoSucceeded(ret) ||
        !PayloadPmoReadGuestU64(guest_cr3, entity, &brush) ||
        !PayloadIsCanonical(brush))
    {
        return false;
    }

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_INIT_DWRITE;
    PayloadZeroMemory((void*)desc_hva, 0x1000);
    PayloadCopyMemory((void*)desc_hva, &kIID_IDWriteFactory, sizeof(kIID_IDWriteFactory));
    args[0] = 0;
    args[1] = desc;
    args[2] = entity;
    if (!PayloadPmoCallUser(ctx, g_cached_hv_diag.ntapi_dwrite_create_factory, args, 3, &ret) ||
        !PayloadPmoSucceeded(ret) ||
        !PayloadPmoReadGuestU64(guest_cr3, entity, &dwrite_factory) ||
        !PayloadIsCanonical(dwrite_factory))
    {
        return false;
    }

    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_INIT_TEXTFMT;
    if (!PayloadPmoGetVFunc(guest_cr3, dwrite_factory, 15, &fn))
        return false;
    PayloadZeroMemory((void*)desc_hva, 0x1000);
    PayloadPmoWriteWideString((void*)desc_hva, kFontName, 64);
    PayloadPmoWriteWideString((void*)(desc_hva + 0x100), kLocaleName, 64);
    args[0] = dwrite_factory;
    args[1] = desc;
    args[2] = 0;
    args[3] = 400;
    args[4] = 0;
    args[5] = 3;
    args[6] = 0x41600000ull; // 14.0f
    args[7] = desc + 0x100;
    args[8] = entity;
    if (!PayloadPmoCallUser(ctx, fn, args, 9, &ret) ||
        !PayloadPmoSucceeded(ret) ||
        !PayloadPmoReadGuestU64(guest_cr3, entity, &textfmt) ||
        !PayloadIsCanonical(textfmt))
    {
        return false;
    }

    g_payload_pmo_render_desc = desc;
    g_payload_pmo_render_desc_hva = desc_hva;
    g_payload_pmo_render_buf0 = buf0;
    g_payload_pmo_render_buf0_hva = buf0_hva;
    g_payload_pmo_render_d2d_rt = d2d_rt;
    g_payload_pmo_render_brush = brush;
    g_payload_pmo_render_textfmt = textfmt;
    g_payload_pmo_last_isfinish = 1;
    g_payload_pmo_draw_last_stage = PAYLOAD_PMO_DRAW_STAGE_INIT_READY;
    PayloadPmoPublishRenderState();
    return true;
}
