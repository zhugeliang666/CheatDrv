// Split from vmexit_common.inl: vmexit/vmcall_common.inl.
// Included through the wrapper; same translation unit.

static void PayloadBridgeRecordForward(payload_u64 reason, payload_u64 code, payload_u64 key, payload_u64 kind, payload_u64 raw_rax = 0)
{
    g_payload_vmexit_bridge_forward_last_reason = reason;
    g_payload_vmexit_bridge_forward_last_code = code;
    g_payload_vmexit_bridge_forward_last_key = key;
    g_payload_vmexit_bridge_forward_last_rax = raw_rax;

    payload_u64 guest_rip = 0;
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &guest_rip))
    {
        g_payload_vmexit_bridge_forward_last_guest_rip = guest_rip;
        if (kind == PAYLOAD_BRIDGE_FORWARD_BAD_KEY)
        {
            g_payload_vmexit_forward_badkey_last_rip = guest_rip;
            PayloadRecordRipHistogram(
                guest_rip,
                g_payload_vmexit_badkey_rip_hist_addr,
                g_payload_vmexit_badkey_rip_hist_count,
                &g_payload_vmexit_badkey_rip_hist_next);
        }
        else if (kind == PAYLOAD_BRIDGE_FORWARD_NON_VMCALL)
        {
            g_payload_vmexit_forward_nonvm_last_rip = guest_rip;
            PayloadRecordRipHistogram(
                guest_rip,
                g_payload_vmexit_nonvm_rip_hist_addr,
                g_payload_vmexit_nonvm_rip_hist_count,
                &g_payload_vmexit_nonvm_rip_hist_next);
        }
    }

    payload_u64 qualification = 0;
    if (PayloadVmread(PAYLOAD_VMCS_EXIT_QUALIFICATION, &qualification))
        g_payload_vmexit_bridge_forward_last_qualification = qualification;

    payload_u64 basic_reason = reason & 0xFFFFull;
    if (basic_reason < 64)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_forward_reason_hist[basic_reason]);

    switch (kind)
    {
    case PAYLOAD_BRIDGE_FORWARD_BAD_KEY:
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_forward_bad_key);
        break;
    case PAYLOAD_BRIDGE_FORWARD_UNKNOWN_CODE:
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_forward_unknown_code);
        break;
    case PAYLOAD_BRIDGE_FORWARD_NON_VMCALL:
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_forward_non_vmcall);
        break;
    default:
        break;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_forward_count);
}

static bool PayloadBridgeCanForwardOldHandler()
{
    return !g_payload_legacy_released &&
           !g_payload_unload_quiesce &&
           g_payload_vmexit_bridge_target != 0;
}

static payload_u64 PayloadBridgeCompleteHypercall(payload_guest_context* ctx, payload_u64 code, payload_u64 result)
{
    if (!PayloadBridgeSkipInstruction())
    {
        g_payload_vmexit_bridge_self_last_code = code;
        g_payload_vmexit_bridge_self_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        PayloadBridgeRecordForward(PAYLOAD_VMX_EXIT_REASON_EXECUTE_VMCALL, code, PAYLOAD_HYPERCALL_KEY, PAYLOAD_BRIDGE_FORWARD_GENERIC);
        return 0;
    }

    ctx->rax = result;
    g_payload_vmexit_bridge_self_last_code = code;
    g_payload_vmexit_bridge_self_last_result = result;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    switch (code)
    {
    case PAYLOAD_HYPERCALL_PING:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_ping);
        break;
    case PAYLOAD_HYPERCALL_GET_RESIDENT_HV_DIAG:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_diag);
        break;
    case PAYLOAD_HYPERCALL_MAP_HOST_RANGE:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_map);
        break;
    case PAYLOAD_HYPERCALL_SET_HOST_RSP:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_rsp);
        break;
    case PAYLOAD_HYPERCALL_SET_HOST_RIP:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_rip);
        break;
    case PAYLOAD_HYPERCALL_GET_HV_BASE:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hv_base);
        break;
    case PAYLOAD_HYPERCALL_VH_INIT_TRAMP_POOL:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_vh_init_tramp_pool);
        break;
    case PAYLOAD_HYPERCALL_SET_AFFINITY_LOCK:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_affinity_lock);
        break;
    case PAYLOAD_HYPERCALL_GET_HIDE_DIAG:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_hide_diag);
        break;
    case PAYLOAD_HYPERCALL_GET_PHYSICAL_ADDRESS:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_get_pa);
        break;
    case PAYLOAD_HYPERCALL_GET_GAMEVT_IMAGE_BASE:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_gamevt_get);
        break;
    case PAYLOAD_HYPERCALL_SAVE_GAMEVT_IMAGE_BASE:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_gamevt_save);
        break;
    case PAYLOAD_HYPERCALL_SET_KEEP_HV_ON_UNLOAD:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_keep_hv);
        break;
    case PAYLOAD_HYPERCALL_QUERY_PROCESS_CR3:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_query_cr3);
        break;
    case PAYLOAD_HYPERCALL_GET_INFO:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_get_info);
        break;
    case PAYLOAD_HYPERCALL_READ_PHYS_MEM:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_read_phys);
        break;
    case PAYLOAD_HYPERCALL_WRITE_PHYS_MEM:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_write_phys);
        break;
    case PAYLOAD_HYPERCALL_READ_VIRT_MEM:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_read_virt);
        break;
    case PAYLOAD_HYPERCALL_WRITE_VIRT_MEM:
        _InterlockedIncrement64((volatile LONG64*)&g_bridge_self_write_virt);
        break;
    default:
        break;
    }
    return 1;
}

static payload_u64 PayloadBridgeUnhandledVmcall(payload_guest_context* ctx,
                                                payload_u64 basic_reason,
                                                payload_u64 code,
                                                payload_u64 key,
                                                payload_u64 raw_rax,
                                                payload_bridge_forward_kind kind)
{
#if PAYLOAD_FAIL_CLOSED_UNHANDLED_VMCALLS
    if (PayloadBridgeCanForwardOldHandler())
    {
        PayloadBridgeRecordForward(basic_reason, code, key, kind, raw_rax);
        return 0;
    }

    return PayloadBridgeCompleteHypercall(ctx, code, 0);
#else
    PayloadBridgeRecordForward(basic_reason, code, key, kind, raw_rax);
    return 0;
#endif
}

static payload_u64 PayloadBridgeCompleteExit(payload_guest_context* ctx, payload_u64 code, payload_u64 result)
{
    if (!ctx || !PayloadBridgeSkipInstruction())
    {
        g_payload_vmexit_bridge_self_last_code = code;
        g_payload_vmexit_bridge_self_last_result = PAYLOAD_RESULT_INVALID_CONTEXT;
        PayloadBridgeRecordForward(code, code, PAYLOAD_HYPERCALL_KEY, PAYLOAD_BRIDGE_FORWARD_GENERIC);
        return 0;
    }

    g_payload_vmexit_bridge_self_last_code = code;
    g_payload_vmexit_bridge_self_last_result = result;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_vmexit_bridge_self_count);
    return 1;
}

