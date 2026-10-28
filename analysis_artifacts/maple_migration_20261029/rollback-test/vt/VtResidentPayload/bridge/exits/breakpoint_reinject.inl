// Split from payload_bridge.inl: exits/breakpoint_reinject.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

enum payload_exbp_reason : payload_u64
{
    PAYLOAD_EXBP_REASON_NONE = 0,
    PAYLOAD_EXBP_REASON_NOT_BP = 1,
    PAYLOAD_EXBP_REASON_MODE_OFF = 2,
    PAYLOAD_EXBP_REASON_VMREAD_FAIL = 3,
    PAYLOAD_EXBP_REASON_BAD_INFO = 4,
    PAYLOAD_EXBP_REASON_VTRET_GUARD = 5,
    PAYLOAD_EXBP_REASON_TRAMP_GUARD = 6,
    PAYLOAD_EXBP_REASON_VMWRITE_FAIL = 7,
    PAYLOAD_EXBP_REASON_GENERIC_REINJECT = 8,
    PAYLOAD_EXBP_REASON_REINJECTED = 0x201,
};

static bool PayloadVtRetReasonOwnsBreakpoint(payload_u64 vtret_reason)
{
    return vtret_reason == PAYLOAD_VTRET_REASON_STRICT_MATCH ||
           vtret_reason == PAYLOAD_VTRET_REASON_LOOSE_MATCH;
}

static bool PayloadTrampReasonOwnsBreakpoint(payload_u64 tramp_reason)
{
    return tramp_reason == PAYLOAD_TRAMP_REASON_MATCH_USER ||
           tramp_reason == PAYLOAD_TRAMP_REASON_MATCH_KERNEL ||
           tramp_reason == PAYLOAD_TRAMP_REASON_HANDLE_FAIL;
}

static payload_u64 PayloadBridgeTryReinjectBreakpoint(
    payload_guest_context* ctx,
    payload_u64 reason,
    payload_u64 vtret_reason,
    payload_u64 tramp_reason)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(reason);

    if (g_payload_exbp_mode != PAYLOAD_EXBP_MODE_REINJECT)
    {
        g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_MODE_OFF;
        return 0;
    }

    payload_u64 info = 0;
    payload_u64 rip = 0;
    payload_u64 length = 0;
    payload_u64 error = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_VMEXIT_INTERRUPTION_INFORMATION, &info) ||
        !PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &rip) ||
        !PayloadVmread(PAYLOAD_VMCS_VMEXIT_INSTRUCTION_LENGTH, &length))
    {
        g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_VMREAD_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_reinject_fail_count);
        return 0;
    }
    PayloadVmread(PAYLOAD_VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, &error);

    g_payload_exbp_last_info = info;
    g_payload_exbp_last_rip = rip;
    g_payload_exbp_last_instruction_length = length;

    payload_u64 vector = info & 0xFFull;
    bool valid = (info & (1ull << 31)) != 0;
    if (vector != 3 || !valid || !length || length > 15)
    {
        g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_NOT_BP;
        return 0;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_probe_count);

    if (PayloadVtRetReasonOwnsBreakpoint(vtret_reason))
    {
        g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_VTRET_GUARD;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_guard_count);
        return 0;
    }

    if (PayloadTrampReasonOwnsBreakpoint(tramp_reason))
    {
        g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_TRAMP_GUARD;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_guard_count);
        return 0;
    }

    // Re-注入 a legitimate guest INT3/#BP.  VM-exit info can report the
    // interruption type as hardware exception; VM-条目项 must use software
    // exception for INT3 delivery, matching TestDriver's stable path.
    payload_u64 entry = info;
    entry &= ~(0x7ull << 8);
    entry |= (0x6ull << 8); // software_exception
    entry |= (1ull << 31);  // valid
    g_payload_exbp_last_entry_info = entry;

    if (!PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error) ||
        !PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, entry) ||
        !PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, length))
    {
        g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_VMWRITE_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_reinject_fail_count);
        return 0;
    }

    g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_REINJECTED;
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI;
    g_payload_vmexit_bridge_self_last_result = entry;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_reinject_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return 1;
}

static payload_u64 PayloadBridgeTryReinjectExitException(payload_guest_context* ctx, payload_u64 reason)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(reason);

    payload_u64 info = 0;
    payload_u64 length = 0;
    payload_u64 error = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_VMEXIT_INTERRUPTION_INFORMATION, &info) ||
        !PayloadVmread(PAYLOAD_VMCS_VMEXIT_INSTRUCTION_LENGTH, &length))
    {
        g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_VMREAD_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_reinject_fail_count);
        return 0;
    }
    PayloadVmread(PAYLOAD_VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, &error);

    bool valid = (info & (1ull << 31)) != 0;
    payload_u64 vector = info & 0xFFull;
    payload_u64 type = (info >> 8) & 0x7ull;
    if (!valid || vector == 2)
        return 0;

    payload_u64 entry = info;
    if (vector == 3)
    {
        // TestDriver parity: guest INT3/#BP must be re-entered as a software
        // exception even when VM-exit reports the source as hardware exception.
        entry &= ~(0x7ull << 8);
        entry |= (0x6ull << 8);
        type = 6;
    }
    entry |= (1ull << 31);

    bool ok = true;
    if (entry & (1ull << 11))
        ok = PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error);
    if (ok)
        ok = PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, entry);
    if (ok && (type == 4 || type == 6))
    {
        if (!length || length > 15)
            ok = false;
        else
            ok = PayloadVmwrite(PAYLOAD_VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, length);
    }

    if (!ok)
    {
        g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_VMWRITE_FAIL;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_reinject_fail_count);
        return 0;
    }

    g_payload_exbp_last_reason = PAYLOAD_EXBP_REASON_GENERIC_REINJECT;
    g_payload_exbp_last_info = info;
    g_payload_exbp_last_instruction_length = length;
    g_payload_exbp_last_entry_info = entry;
    g_payload_misc_exit_last_action = (vector == 3) ? 0x503ull : 0x540ull;
    g_payload_misc_exit_last_vector = vector;
    g_payload_vmexit_bridge_self_last_code = PAYLOAD_VMX_EXIT_REASON_EXCEPTION_OR_NMI;
    g_payload_vmexit_bridge_self_last_result = entry;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_exbp_reinject_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_handle_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return 1;
}
