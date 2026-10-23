// Split from vmexit_common.inl: vmexit/control_register.inl.
// Included through the wrapper; same translation unit.

enum payload_cr_reason : payload_u64
{
    PAYLOAD_CR_REASON_NONE = 0,
    PAYLOAD_CR_REASON_VMREAD_FAIL = 1,
    PAYLOAD_CR_REASON_BAD_GPR = 2,
    PAYLOAD_CR_REASON_BAD_ACCESS = 3,
    PAYLOAD_CR_REASON_BAD_CR = 4,
    PAYLOAD_CR_REASON_UNSAFE_CR0_CACHE = 5,
    PAYLOAD_CR_REASON_SKIP_FAIL = 6,
    PAYLOAD_CR_REASON_INJECT_FAIL = 7,
    PAYLOAD_CR_REASON_DISABLED = 8,
    PAYLOAD_CR_REASON_HANDLED = 0x101,
    PAYLOAD_CR_REASON_INJECT_GP = 0x201,
};

static payload_u64* PayloadBridgeGprPtr(payload_guest_context* ctx, payload_u64 index)
{
    if (!ctx)
        return nullptr;

    switch (index & 0xFull)
    {
    case 0: return &ctx->rax;
    case 1: return &ctx->rcx;
    case 2: return &ctx->rdx;
    case 3: return &ctx->rbx;
    case 4: return &ctx->rsp_shadow;
    case 5: return &ctx->rbp;
    case 6: return &ctx->rsi;
    case 7: return &ctx->rdi;
    case 8: return &ctx->r8;
    case 9: return &ctx->r9;
    case 10: return &ctx->r10;
    case 11: return &ctx->r11;
    case 12: return &ctx->r12;
    case 13: return &ctx->r13;
    case 14: return &ctx->r14;
    case 15: return &ctx->r15;
    default: return nullptr;
    }
}

static bool PayloadBridgeReadGuestGpr(payload_guest_context* ctx, payload_u64 index, payload_u64* value)
{
    if (!ctx || !value)
        return false;

    if ((index & 0xFull) == 4)
        return PayloadVmread(PAYLOAD_VMCS_GUEST_RSP, value);

    auto reg = PayloadBridgeGprPtr(ctx, index);
    if (!reg)
        return false;
    *value = *reg;
    return true;
}

static bool PayloadBridgeWriteGuestGpr(payload_guest_context* ctx, payload_u64 index, payload_u64 value)
{
    if (!ctx)
        return false;

    if ((index & 0xFull) == 4)
        return PayloadVmwrite(PAYLOAD_VMCS_GUEST_RSP, value);

    auto reg = PayloadBridgeGprPtr(ctx, index);
    if (!reg)
        return false;
    *reg = value;
    return true;
}

static bool PayloadBridgeReadEffectiveCr(payload_u64 cr,
                                         payload_u64* value)
{
    if (!value)
        return false;

    payload_u64 guest = 0;
    payload_u64 mask = 0;
    payload_u64 shadow = 0;

    if (cr == 0)
    {
        if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR0, &guest) ||
            !PayloadVmread(PAYLOAD_VMCS_CTRL_CR0_GUEST_HOST_MASK, &mask) ||
            !PayloadVmread(PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW, &shadow))
        {
            return false;
        }
    }
    else if (cr == 4)
    {
        if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR4, &guest) ||
            !PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_GUEST_HOST_MASK, &mask) ||
            !PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_READ_SHADOW, &shadow))
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    *value = (shadow & mask) | (guest & ~mask);
    return true;
}

static payload_u64 PayloadBridgeMaxPhysAddrBits()
{
    int regs[4] = {};
    __cpuidex(regs, 0x80000000, 0);
    if ((payload_u64)(unsigned int)regs[0] >= 0x80000008ull)
    {
        __cpuidex(regs, 0x80000008, 0);
        payload_u64 bits = (payload_u64)((unsigned int)regs[0] & 0xFFu);
        if (bits >= 36 && bits <= 52)
            return bits;
    }
    return 48;
}

static payload_u64 PayloadBridgeCrForward(payload_u64 reason, payload_guest_context* ctx)
{
    g_payload_cr_last_reason = reason;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_cr_fail_count);
    PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_MOV_CR, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL, ctx ? ctx->rax : 0);
    return 0;
}

static payload_u64 PayloadBridgeCrInjectGp(payload_guest_context* ctx, payload_u64 reason)
{
    UNREFERENCED_PARAMETER(ctx);

    if (!PayloadBridgeInjectHardwareException(13, true, 0))
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_INJECT_FAIL, ctx);

    PayloadBridgeMarkHideVmExitOverhead();
    g_payload_cr_last_reason = reason;
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_MOV_CR;
    g_payload_vmexit_bridge_self_last_result = reason;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_cr_gp_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_cr_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return 1;
}

static bool PayloadBridgeCrSkipHandled(payload_u64 value)
{
    if (!PayloadBridgeSkipInstruction())
    {
        g_payload_cr_last_reason = PAYLOAD_CR_REASON_SKIP_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_cr_fail_count);
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_MOV_CR, 0, 0, PAYLOAD_BRIDGE_FORWARD_NON_VMCALL);
        return false;
    }

    PayloadBridgeMarkHideVmExitOverhead();
    g_payload_cr_last_reason = PAYLOAD_CR_REASON_HANDLED;
    g_payload_cr_last_value = value;
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_MOV_CR;
    g_payload_vmexit_bridge_self_last_result = value;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_cr_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return true;
}

static payload_u64 PayloadBridgeHandleMovToCr0(payload_guest_context* ctx, payload_u64 value)
{
    payload_u64 curr_cr0 = 0;
    payload_u64 curr_cr4 = 0;
    if (!PayloadBridgeReadEffectiveCr(0, &curr_cr0) ||
        !PayloadBridgeReadEffectiveCr(4, &curr_cr4))
    {
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
    }

    payload_u64 new_cr0 = value;
    new_cr0 &= ~(((0x3FFull) << 6) | (1ull << 17) | ((0x3FFull) << 19));
    new_cr0 |= (1ull << 4); // ET is architecturally fixed to 1.

    if (new_cr0 >> 32)
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    if ((new_cr0 & (1ull << 31)) && !(new_cr0 & 1ull))
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    if (!(new_cr0 & (1ull << 30)) && (new_cr0 & (1ull << 29)))
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    if (!(new_cr0 & (1ull << 31)))
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    if (!(new_cr0 & (1ull << 16)) && (curr_cr4 & (1ull << 23)))
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);

    if ((new_cr0 ^ curr_cr0) & ((1ull << 30) | (1ull << 29)))
    {
        // TestDriver parity: CR0.CD/NW changes require updating the current
        // vCPU's EPT memory type view before resuming the guest.  Forwarding
        // this path after freetest turns a normal cache-control sequence into a
        // no-target #GP or a stale EPT memory-type split.
        if (!PayloadEptRefreshMemoryTypeForCurrentVcpu((new_cr0 & (1ull << 30)) != 0))
            return PayloadBridgeCrForward(PAYLOAD_CR_REASON_UNSAFE_CR0_CACHE, ctx);
    }

    PayloadVmwrite(PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW, new_cr0);
    payload_u64 real_cr0 = new_cr0;
    real_cr0 |= __readmsr((unsigned long)PAYLOAD_IA32_VMX_CR0_FIXED0);
    real_cr0 &= __readmsr((unsigned long)PAYLOAD_IA32_VMX_CR0_FIXED1);
    if (!PayloadVmwrite(PAYLOAD_VMCS_GUEST_CR0, real_cr0))
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);

    return PayloadBridgeCrSkipHandled(new_cr0) ? 1 : 0;
}

static payload_u64 PayloadBridgeHandleMovToCr3(payload_guest_context* ctx, payload_u64 value)
{
    payload_u64 curr_cr4 = 0;
    payload_u64 vpid = 0;
    if (!PayloadBridgeReadEffectiveCr(4, &curr_cr4) ||
        !PayloadVmread(PAYLOAD_VMCS_CTRL_VPID, &vpid) ||
        !vpid)
    {
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
    }

    bool invalidate = true;
    payload_u64 new_cr3 = value;
    if ((curr_cr4 & (1ull << 17)) && (new_cr3 & (1ull << 63)))
    {
        invalidate = false;
        new_cr3 &= ~(1ull << 63);
    }

    payload_u64 max_phys = PayloadBridgeMaxPhysAddrBits();
    payload_u64 reserved_mask = max_phys >= 64 ? 0 : (~((1ull << max_phys) - 1ull));
    if (new_cr3 & reserved_mask)
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);

    if (invalidate)
    {
        __declspec(align(16)) payload_invvpid_descriptor desc = {};
        desc.vpid_and_reserved = vpid & 0xFFFFull;
        desc.linear_address = 0;
        PayloadInvvpid(PAYLOAD_INVVPID_SINGLE_CONTEXT_RETAINING_GLOBALS, &desc);
    }

    if (!PayloadVmwrite(PAYLOAD_VMCS_GUEST_CR3, new_cr3))
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);

    return PayloadBridgeCrSkipHandled(new_cr3) ? 1 : 0;
}

static payload_u64 PayloadBridgeHandleMovToCr4(payload_guest_context* ctx, payload_u64 value)
{
    payload_u64 curr_cr0 = 0;
    payload_u64 curr_cr3 = 0;
    payload_u64 curr_cr4 = 0;
    payload_u64 vpid = 0;
    if (!PayloadBridgeReadEffectiveCr(0, &curr_cr0) ||
        !PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &curr_cr3) ||
        !PayloadBridgeReadEffectiveCr(4, &curr_cr4) ||
        !PayloadVmread(PAYLOAD_VMCS_CTRL_VPID, &vpid) ||
        !vpid)
    {
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
    }

    payload_u64 new_cr4 = value;
    int cpuid1[4] = {};
    __cpuid(cpuid1, 1);
    if ((new_cr4 & (1ull << 14)) && !(cpuid1[2] & (1 << 6))) // SMXE without SMX
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    payload_u64 cr4_fixed1 = __readmsr((unsigned long)PAYLOAD_IA32_VMX_CR4_FIXED1);
    if (new_cr4 & ~cr4_fixed1)
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    if ((new_cr4 & (1ull << 17)) && !(curr_cr4 & (1ull << 17)) && (curr_cr3 & 0xFFFull))
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    if (!(new_cr4 & (1ull << 5)))
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    if (new_cr4 & (1ull << 12))
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);
    if ((new_cr4 & (1ull << 23)) && !(curr_cr0 & (1ull << 16)))
        return PayloadBridgeCrInjectGp(ctx, PAYLOAD_CR_REASON_INJECT_GP);

    if (((new_cr4 ^ curr_cr4) & (1ull << 7)) ||
        (!(new_cr4 & (1ull << 17)) && (curr_cr4 & (1ull << 17))) ||
        ((new_cr4 & (1ull << 20)) && !(curr_cr4 & (1ull << 20))))
    {
        __declspec(align(16)) payload_invvpid_descriptor desc = {};
        desc.vpid_and_reserved = vpid & 0xFFFFull;
        desc.linear_address = 0;
        PayloadInvvpid(PAYLOAD_INVVPID_SINGLE_CONTEXT, &desc);
    }

    PayloadVmwrite(PAYLOAD_VMCS_CTRL_CR4_READ_SHADOW, new_cr4);
    payload_u64 real_cr4 = new_cr4;
    real_cr4 |= __readmsr((unsigned long)PAYLOAD_IA32_VMX_CR4_FIXED0);
    real_cr4 &= cr4_fixed1;
    if (!PayloadVmwrite(PAYLOAD_VMCS_GUEST_CR4, real_cr4))
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);

    return PayloadBridgeCrSkipHandled(new_cr4) ? 1 : 0;
}

static payload_u64 PayloadBridgeHandleMovCr(payload_guest_context* ctx)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_cr_probe_count);

    payload_u64 qual = 0;
    if (!ctx || !PayloadVmread(PAYLOAD_VMCS_EXIT_QUALIFICATION, &qual))
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);

    payload_u64 cr = qual & 0xFull;
    payload_u64 access = (qual >> 4) & 0x3ull;
    payload_u64 gpr = (qual >> 8) & 0xFull;
    g_payload_cr_last_qualification = qual;
    g_payload_cr_last_access = access;
    g_payload_cr_last_register = cr;
    g_payload_cr_last_gpr = gpr;

    payload_u64 reg_value = 0;
    if (!PayloadBridgeReadGuestGpr(ctx, gpr, &reg_value))
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_BAD_GPR, ctx);

    switch (access)
    {
    case 0: // MOV CRn, GPR
        g_payload_cr_last_value = reg_value;
        if (cr == 0)
            return PayloadBridgeHandleMovToCr0(ctx, reg_value);
        if (cr == 3)
            return PayloadBridgeHandleMovToCr3(ctx, reg_value);
        if (cr == 4)
            return PayloadBridgeHandleMovToCr4(ctx, reg_value);
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_BAD_CR, ctx);

    case 1: // MOV GPR, CRn
        if (cr == 0 || cr == 4)
        {
            payload_u64 value = 0;
            if (!PayloadBridgeReadEffectiveCr(cr, &value))
                return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
            if (!PayloadBridgeWriteGuestGpr(ctx, gpr, value))
                return PayloadBridgeCrForward(PAYLOAD_CR_REASON_BAD_GPR, ctx);
            g_payload_cr_last_value = value;
            return PayloadBridgeCrSkipHandled(value) ? 1 : 0;
        }
        if (cr == 3)
        {
            payload_u64 value = 0;
            if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &value))
                return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
            if (!PayloadBridgeWriteGuestGpr(ctx, gpr, value))
                return PayloadBridgeCrForward(PAYLOAD_CR_REASON_BAD_GPR, ctx);
            g_payload_cr_last_value = value;
            return PayloadBridgeCrSkipHandled(value) ? 1 : 0;
        }
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_BAD_CR, ctx);

    case 2: { // CLTS
        payload_u64 shadow = 0;
        payload_u64 real = 0;
        if (!PayloadVmread(PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW, &shadow) ||
            !PayloadVmread(PAYLOAD_VMCS_GUEST_CR0, &real))
        {
            return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
        }
        shadow &= ~(1ull << 3);
        real &= ~(1ull << 3);
        if (!PayloadVmwrite(PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW, shadow) ||
            !PayloadVmwrite(PAYLOAD_VMCS_GUEST_CR0, real))
        {
            return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
        }
        g_payload_cr_last_value = shadow;
        return PayloadBridgeCrSkipHandled(shadow) ? 1 : 0;
    }

    case 3: { // LMSW
        payload_u64 source = (qual >> 16) & 0xFull;
        payload_u64 shadow = 0;
        payload_u64 real = 0;
        if (!PayloadVmread(PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW, &shadow) ||
            !PayloadVmread(PAYLOAD_VMCS_GUEST_CR0, &real))
        {
            return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
        }
        shadow = (shadow & ~0xFull) | source;
        real = (real & ~0xFull) | source;
        if (!PayloadVmwrite(PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW, shadow) ||
            !PayloadVmwrite(PAYLOAD_VMCS_GUEST_CR0, real))
        {
            return PayloadBridgeCrForward(PAYLOAD_CR_REASON_VMREAD_FAIL, ctx);
        }
        g_payload_cr_last_value = source;
        return PayloadBridgeCrSkipHandled(source) ? 1 : 0;
    }

    default:
        return PayloadBridgeCrForward(PAYLOAD_CR_REASON_BAD_ACCESS, ctx);
    }
}

