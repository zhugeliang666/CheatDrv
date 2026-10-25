// Split from vmexit_common.inl: vmexit/msr_cpuid_tsc.inl.
// Included through the wrapper; same translation unit.

static bool PayloadBridgeIsRtitReadMsr(payload_u64 msr)
{
    switch (msr & 0xFFFFFFFFull)
    {
    case PAYLOAD_IA32_RTIT_OUTPUT_BASE:
    case PAYLOAD_IA32_RTIT_OUTPUT_MASK_PTRS:
    case PAYLOAD_IA32_RTIT_CTL:
    case PAYLOAD_IA32_RTIT_STATUS:
    case PAYLOAD_IA32_RTIT_CR3_MATCH:
        return true;
    default:
        return false;
    }
}

static bool PayloadBridgeIsTraceWriteMsr(payload_u64 msr)
{
    switch (msr & 0xFFFFFFFFull)
    {
    case PAYLOAD_IA32_RTIT_CTL:
    case PAYLOAD_IA32_DEBUGCTL:
        return true;
    default:
        return false;
    }
}

static payload_u64 PayloadBridgeScrubTraceVmcs()
{
    payload_u64 mask = 0;
    payload_u64 debugctl = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_DEBUGCTL, &debugctl))
        debugctl = __readmsr((unsigned long)PAYLOAD_IA32_DEBUGCTL);
    if (PayloadVmwrite(
        PAYLOAD_VMCS_GUEST_DEBUGCTL,
        debugctl & ~(PAYLOAD_IA32_DEBUGCTL_LBR_FLAG | PAYLOAD_IA32_DEBUGCTL_BTS_FLAG)))
    {
        mask |= 0x1ull;
    }
    if (PayloadVmwrite(PAYLOAD_VMCS_GUEST_RTIT_CTL, 0))
        mask |= 0x2ull;
    if (PayloadVmwrite(PAYLOAD_VMCS_GUEST_LBR_CTL, 0))
        mask |= 0x4ull;
    return mask;
}

static payload_u64 PayloadBridgeCompleteMsrExit(payload_guest_context* ctx, payload_u64 reason, payload_u64 msr, bool write)
{
    if (!ctx || !PayloadBridgeSkipInstruction())
    {
        g_payload_vmexit_bridge_self_last_code = reason;
        g_payload_vmexit_bridge_self_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        PayloadBridgeRecordForward(reason, msr, 0, PAYLOAD_BRIDGE_FORWARD_GENERIC, ctx ? ctx->rax : 0);
        return 0;
    }

    PayloadBridgeScrubTraceVmcs();
    PayloadBridgeMarkHideVmExitOverhead();
    g_bridge_self_msr_last = msr;
    g_payload_vmexit_bridge_self_last_code = reason;
    g_payload_vmexit_bridge_self_last_result = 1;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    if (write)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_wrmsr);
    else
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_rdmsr);
    return 1;
}

static payload_u64 PayloadBridgeHandleRdmsr(payload_guest_context* ctx)
{
    payload_u64 msr = ctx->rcx & 0xFFFFFFFFull;
    payload_u64 msr_value = 0;

    if (!PayloadBridgeIsRtitReadMsr(msr))
    {
        payload_host_exception_info e = {};
        msr_value = PayloadRdmsrSafe(&e, (unsigned long)msr);
        if (e.exception_occurred)
        {
            if (!PayloadBridgeInjectHardwareException(13, true, 0))
            {
                g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDMSR;
                g_payload_vmexit_bridge_self_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
                PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDMSR, msr, 0,
                                           PAYLOAD_BRIDGE_FORWARD_NON_VMCALL, ctx ? ctx->rax : 0);
                return 0;
            }

            PayloadBridgeMarkHideVmExitOverhead();
            g_bridge_self_msr_last = msr;
            g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDMSR;
            g_payload_vmexit_bridge_self_last_result = 13;
            _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_rdmsr);
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
            return 1;
        }

        if (msr == 0x3Aull) // IA32_FEATURE_CONTROL: spoof lock_bit=1, VMX/SMX disabled
        {
            msr_value = (msr_value & ~0xFFFEull) | 0x1ull;
        }
        else if (msr == PAYLOAD_IA32_VMX_EPT_VPID_CAP)
        {
            msr_value &= ~(1ull << 20); // INVEPT
            msr_value &= ~(1ull << 26); // INVEPT all-contexts
        }
    }

    if (!PayloadBridgeCompleteMsrExit(ctx, PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDMSR, msr, false))
        return 0;

    ctx->rax = msr_value & 0xFFFFFFFFull;
    ctx->rdx = (msr_value >> 32) & 0xFFFFFFFFull;
    return 1;
}

static payload_u64 PayloadBridgeHandleWrmsr(payload_guest_context* ctx)
{
    payload_u64 msr = ctx->rcx & 0xFFFFFFFFull;
    if (!PayloadBridgeIsTraceWriteMsr(msr))
    {
        payload_host_exception_info e = {};
        payload_u64 value = ((ctx->rdx & 0xFFFFFFFFull) << 32) | (ctx->rax & 0xFFFFFFFFull);
        PayloadWrmsrSafe(&e, (unsigned long)msr, value);
        if (e.exception_occurred)
        {
            if (!PayloadBridgeInjectHardwareException(13, true, 0))
            {
                g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_WRMSR;
                g_payload_vmexit_bridge_self_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
                PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_WRMSR, msr, 0,
                                           PAYLOAD_BRIDGE_FORWARD_NON_VMCALL, ctx ? ctx->rax : 0);
                return 0;
            }

            PayloadBridgeMarkHideVmExitOverhead();
            g_bridge_self_msr_last = msr;
            g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXECUTE_WRMSR;
            g_payload_vmexit_bridge_self_last_result = 13;
            _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_wrmsr);
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
            return 1;
        }

        if (PayloadEptIsMtrrMsr(msr))
        {
            payload_u64 cr0 = 0;
            if (PayloadBridgeReadEffectiveCr(0, &cr0) && !(cr0 & (1ull << 30)))
            {
                PayloadEptRefreshMemoryTypeForCurrentVcpu(false);
            }
            else
            {
                PayloadEptInveptAll();
            }
        }
    }

    return PayloadBridgeCompleteMsrExit(ctx, PAYLOAD_VMX_EXIT_REASON_EXECUTE_WRMSR, msr, true);
}

static payload_u64 PayloadBridgeHandleCpuid(payload_guest_context* ctx)
{
    if (!ctx)
        return 0;

    payload_u64 leaf = ctx->rax & 0xFFFFFFFFull;
    payload_u64 subleaf = ctx->rcx & 0xFFFFFFFFull;
    int regs[4] = {};

    if (leaf >= 0x40000000ull && leaf <= 0x4FFFFFFFull)
    {
        int feat[4] = {};
        __cpuidex(feat, 1, 0);
        if ((unsigned int)feat[2] & 0x80000000u)
        {
            __cpuidex(regs, (int)leaf, (int)subleaf);
            if (!regs[0] && !regs[1] && !regs[2] && !regs[3])
            {
                switch (leaf)
                {
                case 0x40000000ull:
                    regs[0] = 0x40000006;
                    regs[1] = 0x7263694D; // "Micr"
                    regs[2] = 0x666F736F; // "osof"
                    regs[3] = 0x76482074; // "t Hv"
                    break;
                case 0x40000001ull:
                    regs[0] = 0x31237648; // "Hv#1"
                    break;
                case 0x40000002ull:
                    regs[0] = 0x00001bbc;
                    regs[1] = 0x00060001;
                    break;
                default:
                    break;
                }
            }
        }
        else
        {
            __cpuidex(regs, (int)leaf, (int)subleaf);
        }
    }
    else
    {
        __cpuidex(regs, (int)leaf, (int)subleaf);

        if (leaf == 0x01ull)
            regs[2] &= ~(1 << 5); // hide Intel VMX capability

        if (leaf == 0x80000001ull)
            regs[2] &= ~(1 << 2); // hide AMD SVM capability

        if (leaf == 0x07ull && subleaf == 0)
            regs[1] &= ~(1 << 25); // hide Intel PT capability

        if (leaf == 0x14ull)
            regs[0] = regs[1] = regs[2] = regs[3] = 0;
    }

    ctx->rax = (payload_u64)(unsigned int)regs[0];
    ctx->rbx = (payload_u64)(unsigned int)regs[1];
    ctx->rcx = (payload_u64)(unsigned int)regs[2];
    ctx->rdx = (payload_u64)(unsigned int)regs[3];

    PayloadBridgeMarkHideVmExitOverhead();
    _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_cpuid);
    return PayloadBridgeCompleteExit(ctx, PAYLOAD_VMX_EXIT_REASON_CPUID, 1);
}

static payload_u64 PayloadBridgeCompleteTscExit(
    payload_guest_context* ctx,
    payload_u64 reason,
    payload_u64 tsc,
    payload_u64 aux,
    bool has_aux)
{
    if (!ctx || !PayloadBridgeSkipInstruction())
    {
        g_payload_vmexit_bridge_self_last_code = reason;
        g_payload_vmexit_bridge_self_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_tsc_fail);
        PayloadBridgeRecordForward(reason, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL, ctx ? ctx->rax : 0);
        return 0;
    }

    payload_u64 idx = 0;
    if (PayloadBridgeCurrentVcpuIdx(&idx))
        tsc += g_payload_tsc_offset[idx];
    PayloadBridgeMarkHideVmExitOverhead();

    ctx->rax = tsc & 0xFFFFFFFFull;
    ctx->rdx = (tsc >> 32) & 0xFFFFFFFFull;
    if (has_aux)
        ctx->rcx = aux & 0xFFFFFFFFull;

    g_bridge_self_tsc_last = tsc;
    if (has_aux)
        g_bridge_self_tsc_aux = aux & 0xFFFFFFFFull;
    g_payload_vmexit_bridge_self_last_code = reason;
    g_payload_vmexit_bridge_self_last_result = 1;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    if (has_aux)
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_rdtscp);
    else
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_rdtsc);
    return 1;
}

static payload_u64 PayloadBridgeHandleRdtsc(payload_guest_context* ctx)
{
    payload_u64 tsc = __rdtsc();
    return PayloadBridgeCompleteTscExit(ctx, PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDTSC, tsc, 0, false);
}

static payload_u64 PayloadBridgeHandleRdtscp(payload_guest_context* ctx)
{
    unsigned int aux = 0;
    payload_u64 tsc = __rdtscp(&aux);
    return PayloadBridgeCompleteTscExit(ctx, PAYLOAD_VMX_EXIT_REASON_EXECUTE_RDTSCP, tsc, aux, true);
}

