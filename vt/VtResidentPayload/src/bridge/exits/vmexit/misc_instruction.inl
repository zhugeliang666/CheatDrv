// Split from vmexit_common.inl: vmexit/misc_instruction.inl.
// Included through the wrapper; same translation unit.

struct payload_invvpid_descriptor
{
    payload_u64 vpid_and_reserved;
    payload_u64 linear_address;
};

static payload_u64 PayloadBridgeHandleInvlpg(payload_guest_context* ctx)
{
    UNREFERENCED_PARAMETER(ctx);

    _InterlockedIncrement64((volatile LONG64*)&g_payload_invlpg_probe_count);

    payload_u64 gla = 0;
    payload_u64 vpid = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_EXIT_QUALIFICATION, &gla) ||
        !PayloadVmread(PAYLOAD_VMCS_CTRL_VPID, &vpid) ||
        !vpid)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_invlpg_fail_count);
        g_payload_invlpg_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVLPG, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return 0;
    }

    g_payload_invlpg_last_gla = gla;
    g_payload_invlpg_last_vpid = vpid;

    __declspec(align(16)) payload_invvpid_descriptor desc = {};
    desc.vpid_and_reserved = vpid & 0xFFFFull;
    desc.linear_address = gla;
    PayloadInvvpid(PAYLOAD_INVVPID_INDIVIDUAL_ADDRESS, &desc);

    if (!PayloadBridgeSkipInstruction())
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_invlpg_fail_count);
        g_payload_invlpg_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVLPG, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return 0;
    }

    g_payload_invlpg_last_result = 1;
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVLPG;
    g_payload_vmexit_bridge_self_last_result = gla;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_invlpg_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return 1;
}

enum payload_xsetbv_reason : payload_u64
{
    PAYLOAD_XSETBV_REASON_NONE = 0,
    PAYLOAD_XSETBV_REASON_NO_CONTEXT = 1,
    PAYLOAD_XSETBV_REASON_VMREAD_FAIL = 2,
    PAYLOAD_XSETBV_REASON_OSXSAVE_OFF = 3,
    PAYLOAD_XSETBV_REASON_BAD_INDEX = 4,
    PAYLOAD_XSETBV_REASON_UNSUPPORTED_BITS = 5,
    PAYLOAD_XSETBV_REASON_X87_CLEAR = 6,
    PAYLOAD_XSETBV_REASON_AVX_WITHOUT_SSE = 7,
    PAYLOAD_XSETBV_REASON_AVX512_WITHOUT_AVX = 8,
    PAYLOAD_XSETBV_REASON_MPX_PAIR_MISMATCH = 9,
    PAYLOAD_XSETBV_REASON_AVX512_PAIR_MISMATCH = 10,
    PAYLOAD_XSETBV_REASON_INJECT_FAIL = 11,
    PAYLOAD_XSETBV_REASON_SKIP_FAIL = 12,
    PAYLOAD_XSETBV_REASON_SAFE_EXCEPTION = 13,
    PAYLOAD_XSETBV_REASON_HANDLED = 0x101,
    PAYLOAD_XSETBV_REASON_INJECT_GP = 0x201,
    PAYLOAD_XSETBV_REASON_INJECT_UD = 0x202,
};

static bool PayloadBridgeReadEffectiveCr4(payload_u64* cr4_out)
{
    if (!cr4_out)
        return false;

    payload_u64 mask = 0;
    payload_u64 shadow = 0;
    payload_u64 guest = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_GUEST_HOST_MASK, &mask) ||
        !PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_READ_SHADOW, &shadow) ||
        !PayloadVmread(PAYLOAD_VMCS_GUEST_CR4, &guest))
    {
        return false;
    }

    *cr4_out = (shadow & mask) | (guest & ~mask);
    return true;
}

static payload_u64 PayloadBridgeXcr0UnsupportedMask()
{
    int regs[4] = {};
    __cpuidex(regs, 0x0D, 0);
    payload_u64 supported =
        ((payload_u64)(unsigned int)regs[3] << 32) |
        (payload_u64)(unsigned int)regs[0];
    return ~supported;
}

static payload_u64 PayloadBridgeFinishXsetbvException(payload_u64 vector, payload_u64 reason)
{
    bool has_error = (vector == 13);
    if (!PayloadBridgeInjectHardwareException(vector, has_error, 0))
    {
        g_payload_xsetbv_last_reason = PAYLOAD_XSETBV_REASON_INJECT_FAIL;
        g_payload_xsetbv_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_fail_count);
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return 0;
    }

    PayloadBridgeMarkHideVmExitOverhead();
    g_payload_xsetbv_last_reason = reason;
    g_payload_xsetbv_last_result = vector;
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV;
    g_payload_vmexit_bridge_self_last_result = reason;
    if (vector == 6)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_ud_count);
    else
        _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_gp_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return 1;
}

static payload_u64 PayloadBridgeHandleXsetbv(payload_guest_context* ctx)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_probe_count);

    if (!ctx)
    {
        g_payload_xsetbv_last_reason = PAYLOAD_XSETBV_REASON_NO_CONTEXT;
        g_payload_xsetbv_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_fail_count);
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return 0;
    }

    payload_u64 index = ctx->rcx & 0xFFFFFFFFull;
    payload_u64 value = ((ctx->rdx & 0xFFFFFFFFull) << 32) | (ctx->rax & 0xFFFFFFFFull);
    g_payload_xsetbv_last_index = index;
    g_payload_xsetbv_last_value = value;

    payload_u64 cr4 = 0;
    if (!PayloadBridgeReadEffectiveCr4(&cr4))
    {
        g_payload_xsetbv_last_reason = PAYLOAD_XSETBV_REASON_VMREAD_FAIL;
        g_payload_xsetbv_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_fail_count);
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL, ctx->rax);
        return 0;
    }
    g_payload_xsetbv_last_cr4 = cr4;

    if ((cr4 & (1ull << 18)) == 0) // CR4.OSXSAVE
        return PayloadBridgeFinishXsetbvException(6, PAYLOAD_XSETBV_REASON_OSXSAVE_OFF);

    if (index != 0)
        return PayloadBridgeFinishXsetbvException(13, PAYLOAD_XSETBV_REASON_BAD_INDEX);

    payload_u64 unsupported = PayloadBridgeXcr0UnsupportedMask();
    g_payload_xsetbv_last_unsupported_mask = unsupported;
    if (value & unsupported)
        return PayloadBridgeFinishXsetbvException(13, PAYLOAD_XSETBV_REASON_UNSUPPORTED_BITS);

    bool x87 = (value & (1ull << 0)) != 0;
    bool sse = (value & (1ull << 1)) != 0;
    bool avx = (value & (1ull << 2)) != 0;
    bool bndreg = (value & (1ull << 3)) != 0;
    bool bndcsr = (value & (1ull << 4)) != 0;
    bool opmask = (value & (1ull << 5)) != 0;
    bool zmm_hi256 = (value & (1ull << 6)) != 0;
    bool zmm_hi16 = (value & (1ull << 7)) != 0;

    if (!x87)
        return PayloadBridgeFinishXsetbvException(13, PAYLOAD_XSETBV_REASON_X87_CLEAR);

    if (avx && !sse)
        return PayloadBridgeFinishXsetbvException(13, PAYLOAD_XSETBV_REASON_AVX_WITHOUT_SSE);

    if (!avx && (opmask || zmm_hi256 || zmm_hi16))
        return PayloadBridgeFinishXsetbvException(13, PAYLOAD_XSETBV_REASON_AVX512_WITHOUT_AVX);

    if (bndreg != bndcsr)
        return PayloadBridgeFinishXsetbvException(13, PAYLOAD_XSETBV_REASON_MPX_PAIR_MISMATCH);

    if (opmask != zmm_hi256 || zmm_hi256 != zmm_hi16)
        return PayloadBridgeFinishXsetbvException(13, PAYLOAD_XSETBV_REASON_AVX512_PAIR_MISMATCH);

    payload_host_exception_info e = {};
    PayloadXsetbvSafe(&e, (unsigned long)(index & 0xFFFFFFFFull), value);
    if (e.exception_occurred)
        return PayloadBridgeFinishXsetbvException(13, PAYLOAD_XSETBV_REASON_SAFE_EXCEPTION);

    if (!PayloadBridgeSkipInstruction())
    {
        g_payload_xsetbv_last_reason = PAYLOAD_XSETBV_REASON_SKIP_FAIL;
        g_payload_xsetbv_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_fail_count);
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL, ctx->rax);
        return 0;
    }

    PayloadBridgeMarkHideVmExitOverhead();
    g_payload_xsetbv_last_reason = PAYLOAD_XSETBV_REASON_HANDLED;
    g_payload_xsetbv_last_result = 1;
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_XSETBV;
    g_payload_vmexit_bridge_self_last_result = value;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_xsetbv_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return 1;
}

static payload_u64 PayloadBridgeHandleInvd(payload_guest_context* ctx)
{
    UNREFERENCED_PARAMETER(ctx);

    _InterlockedIncrement64((volatile LONG64*)&g_payload_invd_probe_count);

    payload_u64 ss_access = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_SS_ACCESS_RIGHTS, &ss_access))
    {
        g_payload_invd_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_invd_fail_count);
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVD, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return 0;
    }

    payload_u64 dpl = (ss_access >> 5) & 0x3ull;
    g_payload_invd_last_dpl = dpl;

    if (dpl == 0)
    {
        PayloadInvd();

        if (!PayloadBridgeSkipInstruction())
        {
            g_payload_invd_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_invd_fail_count);
            PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVD, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
            return 0;
        }

        g_payload_invd_last_result = 1;
        g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVD;
        g_payload_vmexit_bridge_self_last_result = 1;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_invd_handle_count);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
        return 1;
    }

    if (!PayloadBridgeInjectHardwareException(13, true, 0))
    {
        g_payload_invd_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_invd_fail_count);
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVD, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return 0;
    }

    g_payload_invd_last_result = 13;
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVD;
    g_payload_vmexit_bridge_self_last_result = 13;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_invd_gp_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_invd_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return 1;
}

