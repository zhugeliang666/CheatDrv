// Split from payload_bridge.inl: exits/misc_exits.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

enum payload_misc_exit_action : payload_u64
{
    PAYLOAD_MISC_EXIT_ACTION_NONE = 0,
    PAYLOAD_MISC_EXIT_ACTION_INJECT_GP = 1,
    PAYLOAD_MISC_EXIT_ACTION_INJECT_UD = 2,
    PAYLOAD_MISC_EXIT_ACTION_PREEMPT_NOOP = 3,
    PAYLOAD_MISC_EXIT_ACTION_INJECT_NMI = 4,
    PAYLOAD_MISC_EXIT_ACTION_RESTORE_IDLE_CONTROLS = 5,
};

static bool PayloadBridgeInjectHardwareException(payload_u64 vector, bool has_error, payload_u64 error)
{
    payload_u64 entry = 0;
    entry |= vector & 0xFFull;
    entry |= 0x3ull << 8; // hardware_exception
    if (has_error)
        entry |= 1ull << 11;
    entry |= 1ull << 31;

    if (has_error &&
        !PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error & 0xFFFFFFFFull))
    {
        return false;
    }

    return PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, entry);
}

static bool PayloadBridgeMiscReadEffectiveCr4(payload_u64* value)
{
    if (!value)
        return false;

    payload_u64 guest = 0;
    payload_u64 mask = 0;
    payload_u64 shadow = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR4, &guest) ||
        !PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_GUEST_HOST_MASK, &mask) ||
        !PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_READ_SHADOW, &shadow))
    {
        return false;
    }

    *value = (shadow & mask) | (guest & ~mask);
    return true;
}

static payload_u64 PayloadBridgeIdleExitControlBit(payload_u64 basic_reason)
{
    switch (basic_reason)
    {
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_HLT:
        return PAYLOAD_VMX_PROCBASED_HLT_EXITING;
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_MWAIT:
        return PAYLOAD_VMX_PROCBASED_MWAIT_EXITING;
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_MONITOR:
        return PAYLOAD_VMX_PROCBASED_MONITOR_EXITING;
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_PAUSE:
        return PAYLOAD_VMX_PROCBASED_PAUSE_EXITING;
    default:
        return 0;
    }
}

static bool PayloadBridgeScrubTestDriverIdleExitControls(payload_u64* cleared_bits)
{
    if (cleared_bits)
        *cleared_bits = 0;

    payload_u64 controls = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, &controls))
        return false;

    payload_u64 idle_bits = controls & PAYLOAD_VMX_PROCBASED_IDLE_EXIT_MASK;
    if (!idle_bits)
        return true;

    if (!PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC,
                        controls & ~PAYLOAD_VMX_PROCBASED_IDLE_EXIT_MASK))
    {
        return false;
    }

    if (cleared_bits)
        *cleared_bits = idle_bits;
    return true;
}

static bool PayloadBridgeRestoreIdleExitParity(payload_u64 basic_reason, payload_u64* cleared_bits)
{
    if (cleared_bits)
        *cleared_bits = 0;

    payload_u64 reason_bit = PayloadBridgeIdleExitControlBit(basic_reason);
    if (!reason_bit)
        return false;

    payload_u64 controls = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, &controls))
        return false;

    payload_u64 idle_bits = controls & PAYLOAD_VMX_PROCBASED_IDLE_EXIT_MASK;
    if ((controls & reason_bit) == 0)
        return false;

    // TestDriver does not enable legacy HLT/MONITOR/MWAIT/PAUSE exiting and
    // has no handlers for these reasons.  If payload sees one after handoff,
    // the safe parity action is to restore TestDriver's VMCS control invariant
    // and retry the same guest RIP, not to emulate or RIP-skip the instruction.
    if (!PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC,
                        controls & ~PAYLOAD_VMX_PROCBASED_IDLE_EXIT_MASK))
    {
        return false;
    }

    if (cleared_bits)
        *cleared_bits = idle_bits;
    return true;
}

static payload_u64 PayloadBridgeHandleSimpleExit(payload_guest_context* ctx, payload_u64 basic_reason)
{
    UNREFERENCED_PARAMETER(ctx);

    payload_u64 action = PAYLOAD_MISC_EXIT_ACTION_NONE;
    payload_u64 vector = 0;
    bool has_error = false;
    payload_u64 error = 0;

    switch (basic_reason)
    {
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_HLT:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_MWAIT:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_MONITOR:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_PAUSE:
        action = PAYLOAD_MISC_EXIT_ACTION_RESTORE_IDLE_CONTROLS;
        break;

    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_GETSEC:
        action = PAYLOAD_MISC_EXIT_ACTION_INJECT_GP;
        vector = 13; // #GP
        has_error = true;
        error = 0;
        break;

    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMXON:
    {
        payload_u64 cr4 = 0;
        if (!PayloadBridgeMiscReadEffectiveCr4(&cr4))
            return 0;

        if (cr4 & (1ull << 13)) // CR4.VMXE visible to guest: spoof FEATURE_CONTROL as VMX disabled.
        {
            action = PAYLOAD_MISC_EXIT_ACTION_INJECT_GP;
            vector = 13;
            has_error = true;
            error = 0;
        }
        else
        {
            action = PAYLOAD_MISC_EXIT_ACTION_INJECT_UD;
            vector = 6;
        }
        break;
    }

    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMCLEAR:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMPTRLD:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMPTRST:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMREAD:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMRESUME:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMWRITE:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMXOFF:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVEPT:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_INVVPID:
    case PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMFUNC:
        action = PAYLOAD_MISC_EXIT_ACTION_INJECT_UD;
        vector = 6; // #UD
        break;

    case PAYLOAD_VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
        action = PAYLOAD_MISC_EXIT_ACTION_PREEMPT_NOOP;
        break;

    case PAYLOAD_VMX_EXIT_REASON_NMI_WINDOW:
        action = PAYLOAD_MISC_EXIT_ACTION_INJECT_NMI;
        vector = 2; // NMI
        break;

    default:
        return 0;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_probe_count);
    g_payload_misc_exit_last_reason = basic_reason;
    g_payload_misc_exit_last_action = action;
    g_payload_misc_exit_last_vector = vector;

    if (action == PAYLOAD_MISC_EXIT_ACTION_PREEMPT_NOOP)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_preempt_count);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
        g_payload_vmexit_bridge_self_last_code = basic_reason;
        g_payload_vmexit_bridge_self_last_result = action;
        return 1;
    }

    if (action == PAYLOAD_MISC_EXIT_ACTION_RESTORE_IDLE_CONTROLS)
    {
        payload_u64 cleared_bits = 0;
        if (!PayloadBridgeRestoreIdleExitParity(basic_reason, &cleared_bits))
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
            return 0;
        }

        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
        g_payload_vmexit_bridge_self_last_code = basic_reason;
        g_payload_vmexit_bridge_self_last_result = action;
        g_payload_misc_exit_last_vector = cleared_bits;
        return 1;
    }

    if (action == PAYLOAD_MISC_EXIT_ACTION_INJECT_NMI)
    {
        payload_u64 entry = 0;
        entry |= 2ull;       // vector: NMI
        entry |= 2ull << 8;  // interruption_type: non-maskable interrupt
        entry |= 1ull << 31; // valid

        payload_u64 controls = 0;
        if (!PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, entry) ||
            !PayloadVmread(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, &controls) ||
            !PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, controls & ~(1ull << 22)))
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
            return 0;
        }

        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
        g_payload_vmexit_bridge_self_last_code = basic_reason;
        g_payload_vmexit_bridge_self_last_result = action;
        return 1;
    }

    if (!PayloadBridgeInjectHardwareException(vector, has_error, error))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
        return 0;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    g_payload_vmexit_bridge_self_last_code = basic_reason;
    g_payload_vmexit_bridge_self_last_result = action;
    return 1;
}

