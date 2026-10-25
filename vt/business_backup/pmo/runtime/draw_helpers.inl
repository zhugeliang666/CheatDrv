// Split from pmo_runtime.inl: runtime/draw_helpers.inl.
// Included through the wrapper; same translation unit.

static payload_u64 PayloadPmoAppendChar(unsigned short* out, payload_u64 pos, payload_u64 max, unsigned short ch)
{
    if (!out || !max || pos + 1 >= max)
        return pos;
    out[pos++] = ch;
    out[pos] = 0;
    return pos;
}

static payload_u64 PayloadPmoAppendLiteral(unsigned short* out, payload_u64 pos, payload_u64 max, const unsigned short* s)
{
    if (!out || !s)
        return pos;
    while (*s && pos + 1 < max)
        pos = PayloadPmoAppendChar(out, pos, max, *s++);
    return pos;
}

static payload_u64 PayloadPmoAppendU64Dec(unsigned short* out, payload_u64 pos, payload_u64 max, payload_u64 value)
{
    unsigned short tmp[24] = {};
    payload_u64 n = 0;
    if (!value)
    {
        return PayloadPmoAppendChar(out, pos, max, '0');
    }

    while (value && n < 24)
    {
        tmp[n++] = (unsigned short)('0' + (value % 10ull));
        value /= 10ull;
    }
    while (n && pos + 1 < max)
        pos = PayloadPmoAppendChar(out, pos, max, tmp[--n]);
    return pos;
}

static payload_u64 PayloadPmoBuildCountersLine(unsigned short* out, payload_u64 max)
{
    if (!out || !max)
        return 0;
    out[0] = 0;
    payload_u64 pos = 0;
    static const unsigned short kPrefix[] = { 'd','r','a','w','=',0 };
    static const unsigned short kCall[] = { ' ','c','a','l','l','=',0 };
    static const unsigned short kVtr[] = { ' ','v','t','r','=',0 };
    static const unsigned short kGb[] = { ' ','g','b','=',0 };
    static const unsigned short kMm[] = { ' ','m','m','=',0 };
    pos = PayloadPmoAppendLiteral(out, pos, max, kPrefix);
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_pmo_draw_done_count);
    pos = PayloadPmoAppendLiteral(out, pos, max, kCall);
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_pmo_call_return_count);
    pos = PayloadPmoAppendLiteral(out, pos, max, kVtr);
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_pmo_vtret_handle_count);
    pos = PayloadPmoAppendLiteral(out, pos, max, kGb);
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_getbuffer_hits);
    pos = PayloadPmoAppendChar(out, pos, max, '/');
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_getbuffer_alien);
    pos = PayloadPmoAppendLiteral(out, pos, max, kMm);
    pos = PayloadPmoAppendU64Dec(out, pos, max,
        g_payload_mmcm_blocked +
        g_payload_mmcvm_blocked +
        g_payload_mmisav_blocked +
        g_payload_ntqvm_blocked +
        g_payload_mmgpa_blocked);
    return pos;
}

static payload_u64 PayloadPmoBuildVcpuLine(unsigned short* out, payload_u64 max)
{
    if (!out || !max)
        return 0;
    out[0] = 0;
    payload_u64 pos = 0;
    static const unsigned short kVcpu[] = { 'v','c','p','u','=',0 };
    static const unsigned short kSame[] = { ' ','s','a','m','e','=',0 };
    static const unsigned short kBiz[] = { ' ','b','i','z','=',0 };
    static const unsigned short kSkip[] = { ' ','s','k','i','p','=',0 };
    pos = PayloadPmoAppendLiteral(out, pos, max, kVcpu);
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_pmo_call_last_vcpu);
    pos = PayloadPmoAppendLiteral(out, pos, max, kSame);
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_pmo_call_same_vcpu_count);
    pos = PayloadPmoAppendLiteral(out, pos, max, kBiz);
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_business_tick_count);
    pos = PayloadPmoAppendLiteral(out, pos, max, kSkip);
    pos = PayloadPmoAppendU64Dec(out, pos, max, g_payload_business_skip_count);
    return pos;
}

static bool PayloadPmoSetBrushColor(payload_guest_context* ctx,
                                    payload_u64 brush_fn,
                                    unsigned int r_bits,
                                    unsigned int g_bits,
                                    unsigned int b_bits,
                                    unsigned int a_bits,
                                    payload_u64* ret_out)
{
    if (!ctx || !brush_fn || !g_payload_pmo_render_buf0_hva || !g_payload_pmo_render_buf0 || !g_payload_pmo_render_brush)
        return false;

    struct payload_pmo_color_bits
    {
        unsigned int r;
        unsigned int g;
        unsigned int b;
        unsigned int a;
    };

    payload_pmo_color_bits color = { r_bits, g_bits, b_bits, a_bits };
    PayloadZeroMemory((void*)g_payload_pmo_render_buf0_hva, 0x400);
    PayloadCopyMemory((void*)g_payload_pmo_render_buf0_hva, &color, sizeof(color));

    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    args[0] = g_payload_pmo_render_brush;
    args[1] = g_payload_pmo_render_buf0;
    return PayloadPmoCallUser(ctx, brush_fn, args, 2, ret_out);
}

static bool PayloadPmoDrawFilledRect(payload_guest_context* ctx,
                                     payload_u64 fill_rect_fn,
                                     unsigned int left_bits,
                                     unsigned int top_bits,
                                     unsigned int right_bits,
                                     unsigned int bottom_bits,
                                     payload_u64* ret_out)
{
    if (!ctx || !fill_rect_fn || !g_payload_pmo_render_buf0_hva || !g_payload_pmo_render_buf0 ||
        !g_payload_pmo_render_d2d_rt || !g_payload_pmo_render_brush)
    {
        return false;
    }

    struct payload_pmo_rect_bits
    {
        unsigned int left;
        unsigned int top;
        unsigned int right;
        unsigned int bottom;
    };

    payload_pmo_rect_bits rect = { left_bits, top_bits, right_bits, bottom_bits };
    PayloadZeroMemory((void*)g_payload_pmo_render_buf0_hva, 0x400);
    PayloadCopyMemory((void*)g_payload_pmo_render_buf0_hva, &rect, sizeof(rect));

    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    args[0] = g_payload_pmo_render_d2d_rt;
    args[1] = g_payload_pmo_render_buf0;
    args[2] = g_payload_pmo_render_brush;
    return PayloadPmoCallUser(ctx, fill_rect_fn, args, 3, ret_out);
}

static bool PayloadPmoDrawTextLine(payload_guest_context* ctx,
                                   payload_u64 text_fn,
                                   unsigned int x_bits,
                                   unsigned int y_bits,
                                   const unsigned short* text,
                                   payload_u64 text_len,
                                   payload_u64* ret_out)
{
    if (!ctx || !text_fn || !text || !text_len ||
        !g_payload_pmo_render_buf0 ||
        !g_payload_pmo_render_buf0_hva ||
        !g_payload_pmo_render_d2d_rt ||
        !g_payload_pmo_render_textfmt ||
        !g_payload_pmo_render_brush)
    {
        return false;
    }

    struct payload_pmo_rect_bits
    {
        unsigned int left;
        unsigned int top;
        unsigned int right;
        unsigned int bottom;
    };

    payload_pmo_rect_bits rect = {
        x_bits,
        y_bits,
        0x7F7FFFFFu, // FLT_MAX
        0x7F7FFFFFu  // FLT_MAX
    };

    PayloadZeroMemory((void*)g_payload_pmo_render_buf0_hva, 0x400);
    PayloadPmoWriteWideString((void*)g_payload_pmo_render_buf0_hva, text, 256);
    PayloadCopyMemory((void*)(g_payload_pmo_render_buf0_hva + 0x300), &rect, sizeof(rect));

    payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
    args[0] = g_payload_pmo_render_d2d_rt;
    args[1] = g_payload_pmo_render_buf0;
    args[2] = text_len;
    args[3] = g_payload_pmo_render_textfmt;
    args[4] = g_payload_pmo_render_buf0 + 0x300;
    args[5] = g_payload_pmo_render_brush;
    args[6] = 0;
    args[7] = 0;
    return PayloadPmoCallUser(ctx, text_fn, args, 8, ret_out);
}
