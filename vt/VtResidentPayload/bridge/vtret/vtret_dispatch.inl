// Split from payload_bridge.inl: vtret/vtret_dispatch.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static bool PayloadVtRetNodeInBuffer(payload_u64 list_base, payload_u64 node)
{
    if (!PayloadIsKernelPointer(list_base) || !PayloadIsKernelPointer(node))
        return false;

    payload_u64 buffer_size = PAYLOAD_VTCALL_NODE_SIZE * PAYLOAD_VTCALL_NODE_COUNT;
    if (node < list_base || node >= (list_base + buffer_size))
        return false;

    return ((node - list_base) % PAYLOAD_VTCALL_NODE_SIZE) == 0;
}

static bool PayloadVtRetValidateNode(
    payload_u64 list_base,
    payload_u64 node,
    payload_u64 rip,
    payload_u64 process,
    payload_u64 thread,
    bool ids_ready,
    payload_vtret_match* match)
{
    if (!PayloadVtRetNodeInBuffer(list_base, node) || !rip)
        return false;

    payload_u64 ret_rip = PayloadReadHostU64(node + PAYLOAD_VTCALL_NODE_OFF_RETRIP);
    if (ret_rip != rip)
        return false;

    payload_u64 node_process = PayloadReadHostU64(node + PAYLOAD_VTCALL_NODE_OFF_PROCESS);
    payload_u64 node_thread = PayloadReadHostU64(node + PAYLOAD_VTCALL_NODE_OFF_THREAD);
    if (!PayloadIsKernelPointer(node_process) || !PayloadIsKernelPointer(node_thread))
        return false;

    bool strict = false;
    if (ids_ready)
    {
        if (node_process != process || node_thread != thread)
            return false;
        strict = true;
    }

    payload_u64 old_vt_rsp = PayloadReadHostU64(node + PAYLOAD_VTCALL_NODE_OFF_OLD_VT_RSP);
    if (!PayloadIsKernelPointer(old_vt_rsp) || (old_vt_rsp & 0x7ull) != 0)
        return false;

    if (match)
    {
        match->node = node;
        match->old_vt_rsp = old_vt_rsp;
        match->process = node_process;
        match->thread = node_thread;
        match->list_base = list_base;
        match->strict = strict;
    }
    return true;
}

static bool PayloadVtRetFindInListBase(
    payload_u64 list_base,
    payload_u64 rip,
    payload_u64 process,
    payload_u64 thread,
    bool ids_ready,
    payload_vtret_match* match)
{
    if (!PayloadIsKernelPointer(list_base))
        return false;

    payload_u64 active_head = PayloadReadHostU64(list_base + PAYLOAD_VTCALL_LIST_OFF_ACTIVE_HEAD);
    if (match)
    {
        match->list_base = list_base;
        match->active_head = active_head;
    }

    if (!active_head)
        return false;

    if (!PayloadVtRetNodeInBuffer(list_base, active_head))
    {
        g_payload_vtret_last_reason = PAYLOAD_VTRET_REASON_BAD_ACTIVE_HEAD;
        return false;
    }

    payload_u64 node = active_head;
    for (payload_u64 i = 0; i < PAYLOAD_VTCALL_NODE_COUNT && node; ++i)
    {
        if (PayloadVtRetValidateNode(list_base, node, rip, process, thread, ids_ready, match))
        {
            if (match)
                match->active_head = active_head;
            return true;
        }

        payload_u64 next = PayloadReadHostU64(node + PAYLOAD_VTCALL_NODE_OFF_NEXT);
        if (!next)
            break;
        if (!PayloadVtRetNodeInBuffer(list_base, next) || next == node)
            break;
        node = next;
    }

    return false;
}

static bool PayloadVtRetFindByExpectedList(
    payload_u64 rip,
    payload_u64 process,
    payload_u64 thread,
    bool ids_ready,
    payload_vtret_match* match)
{
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return false;

    payload_u64 expected = PayloadDiagVtCallListBase();
    if (!PayloadIsKernelPointer(expected))
        return false;
    if (PayloadVtRetFindInListBase(expected, rip, process, thread, ids_ready, match))
        return true;

    payload_u64 active_field = expected + PAYLOAD_VTCALL_LIST_OFF_ACTIVE_HEAD;
    payload_u64 start = active_field > PAYLOAD_VTCALL_LIST_SEARCH_RADIUS
        ? active_field - PAYLOAD_VTCALL_LIST_SEARCH_RADIUS
        : active_field;
    payload_u64 end = active_field + PAYLOAD_VTCALL_LIST_SEARCH_RADIUS;
    for (payload_u64 field = start; field <= end; field += sizeof(payload_u64))
    {
        if (field < PAYLOAD_VTCALL_LIST_OFF_ACTIVE_HEAD)
            continue;

        payload_u64 list_base = field - PAYLOAD_VTCALL_LIST_OFF_ACTIVE_HEAD;
        if ((list_base & 0xFull) != 0)
            continue;

        if (PayloadVtRetFindInListBase(list_base, rip, process, thread, ids_ready, match))
            return true;
    }

    return false;
}

static payload_u64 PayloadBridgeProbeVtRet(payload_guest_context* ctx, payload_u64 reason)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(reason);

    payload_u64 info = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_VMEXIT_INTERRUPTION_INFORMATION, &info))
        return 0;

    payload_u64 vector = info & 0xFFull;
    payload_u64 type = (info >> 8) & 0x7ull;
    if (vector != 3 || type != 6)
    {
        g_payload_vtret_last_reason = PAYLOAD_VTRET_REASON_NOT_SOFTWARE_BP;
        return 0;
    }

    payload_u64 rip = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &rip) || !rip)
        return 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_probe_count);
    g_payload_vtret_last_rip = rip;

    payload_u64 process = 0;
    payload_u64 thread = 0;
    bool ids_ready = PayloadCurrentGuestIds(&process, &thread);
    g_payload_vtret_last_process = process;
    g_payload_vtret_last_thread = thread;
    if (!ids_ready)
        g_payload_vtret_last_reason = PAYLOAD_VTRET_REASON_NO_GUEST_IDS;

    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
    {
        g_payload_vtret_last_reason = PAYLOAD_VTRET_REASON_NO_DIAG;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_scan_fail_count);
        return 0;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_scan_count);

    payload_vtret_match match = {};
    if (PayloadVtRetFindByExpectedList(rip, process, thread, ids_ready, &match))
    {
        g_payload_vtret_last_node = match.node;
        g_payload_vtret_last_old_vt_rsp = match.old_vt_rsp;
        g_payload_vtret_last_process = match.process;
        g_payload_vtret_last_thread = match.thread;
        g_payload_vtret_list_base = match.list_base;
        g_payload_vtret_active_head = match.active_head;
        g_payload_vtret_last_reason = match.strict
            ? PAYLOAD_VTRET_REASON_STRICT_MATCH
            : PAYLOAD_VTRET_REASON_LOOSE_MATCH;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_match_count);
        if (match.strict)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_strict_match_count);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_loose_match_count);

        if (match.strict &&
            g_payload_vtret_mode == PAYLOAD_VTRET_MODE_HANDLE_STRICT &&
            g_payload_vtret_strict_match_count >= PAYLOAD_VTRET_HANDLE_WARMUP_MATCHES)
        {
            PayloadWriteHostU64(
                match.node + PAYLOAD_VTCALL_NODE_OFF_NEW_CONTEXT_PTR,
                (payload_u64)ctx);
            g_payload_vtret_last_handle_result = 1;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_handle_count);
            PayloadVtCallExit(ctx, match.old_vt_rsp);

            // PayloadVtCallExit should return to TestDriver's hv::CallUser
            // continuation on the saved vt_call_entry stack.  If it ever
            // falls through, do not claim the exit; forward to old handler.
            g_payload_vtret_last_handle_result = PAYLOAD_RESULT_INVALID_CONTEXT;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_handle_fail_count);
            return 0;
        }
    }
    else
    {
        if (g_payload_vtret_last_reason != PAYLOAD_VTRET_REASON_BAD_ACTIVE_HEAD &&
            g_payload_vtret_last_reason != PAYLOAD_VTRET_REASON_NO_GUEST_IDS)
        {
            g_payload_vtret_last_reason = PAYLOAD_VTRET_REASON_NO_MATCH;
        }
        g_payload_vtret_list_base = PayloadDiagVtCallListBase();
        g_payload_vtret_active_head = PayloadIsKernelPointer(g_payload_vtret_list_base)
            ? PayloadReadHostU64(g_payload_vtret_list_base + PAYLOAD_VTCALL_LIST_OFF_ACTIVE_HEAD)
            : 0;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_vtret_scan_fail_count);
    }

    return 0;
}

static constexpr payload_u64 PAYLOAD_GHV_TRAMP_POOL_OFFSET = 0x146D1B8ull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_SEARCH_RADIUS = 0x4000ull;
static constexpr payload_u64 PAYLOAD_TRAMP_HANDLE_WARMUP_MATCHES = 1ull;
static constexpr payload_u64 PAYLOAD_TRAMP_SLOT_SIZE = 0x20ull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_USER_SLOTS_OFF = 0x008ull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_USER_SLOT_COUNT_OFF = 0x408ull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_USER_PAGE_COUNT_OFF = 0x40Cull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_USER_READY_OFF = 0x410ull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_KERNEL_SLOTS_OFF = 0x418ull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_KERNEL_SLOT_COUNT_OFF = 0x818ull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_KERNEL_PAGE_COUNT_OFF = 0x81Cull;
static constexpr payload_u64 PAYLOAD_TRAMP_POOL_KERNEL_READY_OFF = 0x820ull;
static constexpr payload_u64 PAYLOAD_TRAMP_SLOT_OFF_TRAMP_VA = 0x00ull;
static constexpr payload_u64 PAYLOAD_TRAMP_SLOT_OFF_BP_RIP = 0x08ull;
static constexpr payload_u64 PAYLOAD_TRAMP_SLOT_OFF_TARGET_RESUME = 0x10ull;
static constexpr payload_u64 PAYLOAD_TRAMP_SLOT_OFF_OCCUPIED = 0x1Dull;
static constexpr payload_u64 PAYLOAD_TRAMP_MAX_SLOTS = 16ull;
static constexpr payload_u64 PAYLOAD_TRAMP_MAX_PAGES = 16ull;

