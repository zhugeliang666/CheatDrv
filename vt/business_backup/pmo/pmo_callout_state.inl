// Split from payload_bridge.inl: pmo/pmo_callout_state.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static payload_pmo_call_node* PayloadPmoAllocCallNode()
{
    for (payload_u64 i = 0; i < PAYLOAD_PMO_CALL_NODE_COUNT; ++i)
    {
        if (_InterlockedCompareExchange(
                &g_payload_pmo_call_nodes[i].state,
                1,
                0) == 0)
        {
            PayloadZeroMemory(
                (void*)((payload_u64)&g_payload_pmo_call_nodes[i] + sizeof(g_payload_pmo_call_nodes[i].state)),
                sizeof(g_payload_pmo_call_nodes[i]) - sizeof(g_payload_pmo_call_nodes[i].state));
            return &g_payload_pmo_call_nodes[i];
        }
    }
    return nullptr;
}

static void PayloadPmoFreeCallNode(payload_pmo_call_node* node)
{
    if (!node)
        return;
    _ReadWriteBarrier();
    node->state = 0;
}

static bool PayloadPmoStackSlotContains(payload_u64 slot, payload_u64 rsp)
{
    if (!g_host_stack_base || !g_host_stack_slot_size || slot >= g_host_stack_slot_count)
        return false;

    payload_u64 base = g_host_stack_base + slot * g_host_stack_slot_size;
    payload_u64 limit = base + g_host_stack_slot_size;
    return rsp >= base && rsp < limit;
}

static bool PayloadPmoAllocStackSlot(payload_u64 old_host_rsp, payload_u64* slot_out, payload_u64* rsp_out)
{
    if (!slot_out || !rsp_out ||
        !g_host_stack_base ||
        !g_host_stack_slot_size ||
        !g_host_stack_slot_count)
    {
        return false;
    }

    payload_u64 count = g_host_stack_slot_count;
    if (count > PAYLOAD_HOST_STACK_SLOT_COUNT)
        count = PAYLOAD_HOST_STACK_SLOT_COUNT;

    // The first vcpu_count slots are the permanent VMCS_HOST_RSP stacks that
    // mapDriver installed during handoff.  TestDriver's vtcallstack pool is a
    // separate inline ghv buffer, so the payload must not reuse those permanent
    // per-vCPU stack slots for temporary PMO CallUser continuations.
    if (!g_hv_diag_cache_ready || !g_cached_hv_diag.vcpu_count)
        return false;
    payload_u64 first_transient_slot = g_cached_hv_diag.vcpu_count;
    if (first_transient_slot > count)
        return false;

    for (payload_u64 i = first_transient_slot; i < count; ++i)
    {
        if (PayloadPmoStackSlotContains(i, old_host_rsp))
            continue;

        if (_InterlockedCompareExchange(&g_payload_pmo_stack_busy[i], 1, 0) != 0)
            continue;

        payload_u64 base = g_host_stack_base + i * g_host_stack_slot_size;
        payload_u64 top = ((base + g_host_stack_slot_size) & ~0xFull) - 8ull;
        *slot_out = i;
        *rsp_out = top;
        return true;
    }
    return false;
}

static void PayloadPmoFreeStackSlot(payload_u64 slot)
{
    if (slot < PAYLOAD_HOST_STACK_SLOT_COUNT)
        g_payload_pmo_stack_busy[slot] = 0;
}

static payload_u64 PayloadPmoFindBlankMemory(payload_u64 preferred_type)
{
    if (!PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) ||
        !g_cached_hv_diag.vt_hook_slot_count ||
        !g_cached_hv_diag.vt_hook_slot_size ||
        !g_cached_hv_diag.vt_hook_slot_off_occupied ||
        !g_cached_hv_diag.vt_hook_slot_off_data_blank_memory)
    {
        return 0;
    }

    payload_u64 count = g_cached_hv_diag.vt_hook_slot_count;
    if (count > 64)
        count = 64;

    payload_u64 fallback = 0;
    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 slot = g_cached_hv_diag.vt_hook_table_ptr +
            i * g_cached_hv_diag.vt_hook_slot_size;
        if (!PayloadIsKernelPointer(slot))
            break;
        if (!PayloadReadHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied))
            continue;

        payload_u64 blank = PayloadReadHostU64(
            slot + g_cached_hv_diag.vt_hook_slot_off_data_blank_memory);
        if (!blank || !PayloadIsCanonical(blank))
            continue;

        if (!fallback)
            fallback = blank;

        if (g_cached_hv_diag.vt_hook_slot_off_data_type)
        {
            payload_u64 type = PayloadReadHostU64(
                slot + g_cached_hv_diag.vt_hook_slot_off_data_type);
            if (type == preferred_type)
                return blank;
        }
    }

    return fallback;
}

static bool PayloadPmoReadGhvSmallOffsetField(payload_u64 field_offset, payload_u64* value)
{
    if (!value || !field_offset)
        return false;
    return PayloadReadGhvOffsetSmall(field_offset, value);
}

static void PayloadPmoApplyAffinity(payload_pmo_call_node* node)
{
    if (!node || !PayloadIsKernelPointer(node->thread))
        return;
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return;

#if !VT_PMO_FORCE_AFFINITY_LOCK
    payload_u64 enabled_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_affinity_lock_enabled, 0);
    if (!PayloadIsKernelPointer(enabled_field) || !PayloadReadHostU8(enabled_field))
        return;
#endif

    payload_u64 affinity_off = 0;
    if (!PayloadPmoReadGhvSmallOffsetField(g_cached_hv_diag.ghv_off_kthread_affinity_offset, &affinity_off) ||
        !affinity_off ||
        node->entry_vcpu >= 64)
    {
        return;
    }

    payload_u64 mask = 1ull << node->entry_vcpu;
    payload_u64 kt = node->thread;

    payload_u64 affinity_ptr = kt + affinity_off;
    if (!PayloadIsKernelPointer(affinity_ptr))
        return;

    node->saved_affinity = PayloadReadHostU64(affinity_ptr);
    PayloadWriteHostU64(affinity_ptr, mask);
    node->affinity_applied = 1;

    payload_u64 user_affinity_off = 0;
    if (PayloadPmoReadGhvSmallOffsetField(g_cached_hv_diag.ghv_off_kthread_user_affinity_offset, &user_affinity_off) &&
        user_affinity_off)
    {
        payload_u64 ptr = kt + user_affinity_off;
        if (PayloadIsKernelPointer(ptr))
        {
            node->saved_user_affinity = PayloadReadHostU64(ptr);
            PayloadWriteHostU64(ptr, mask);
        }
    }

    payload_u64 ideal_off = 0;
    if (PayloadPmoReadGhvSmallOffsetField(g_cached_hv_diag.ghv_off_kthread_ideal_processor_offset, &ideal_off) &&
        ideal_off)
    {
        payload_u64 ptr = kt + ideal_off;
        if (PayloadIsKernelPointer(ptr))
        {
            node->saved_ideal_processor = PayloadReadHostU8(ptr);
            PayloadWriteHostU8(ptr, (unsigned char)node->entry_vcpu);
        }
    }

    payload_u64 user_ideal_off = 0;
    if (PayloadPmoReadGhvSmallOffsetField(g_cached_hv_diag.ghv_off_kthread_user_ideal_processor_offset, &user_ideal_off) &&
        user_ideal_off)
    {
        payload_u64 ptr = kt + user_ideal_off;
        if (PayloadIsKernelPointer(ptr))
        {
            node->saved_user_ideal_processor = PayloadReadHostU8(ptr);
            PayloadWriteHostU8(ptr, (unsigned char)node->entry_vcpu);
        }
    }

    _ReadWriteBarrier();
}

static void PayloadPmoRestoreAffinity(payload_pmo_call_node* node)
{
    if (!node || !node->affinity_applied || !PayloadIsKernelPointer(node->thread))
        return;

    payload_u64 kt = node->thread;
    payload_u64 affinity_off = 0;
    if (PayloadPmoReadGhvSmallOffsetField(g_cached_hv_diag.ghv_off_kthread_affinity_offset, &affinity_off) &&
        affinity_off)
    {
        payload_u64 ptr = kt + affinity_off;
        if (PayloadIsKernelPointer(ptr) && node->saved_affinity)
            PayloadWriteHostU64(ptr, node->saved_affinity);
    }

    payload_u64 user_affinity_off = 0;
    if (PayloadPmoReadGhvSmallOffsetField(g_cached_hv_diag.ghv_off_kthread_user_affinity_offset, &user_affinity_off) &&
        user_affinity_off)
    {
        payload_u64 ptr = kt + user_affinity_off;
        if (PayloadIsKernelPointer(ptr) && node->saved_user_affinity)
            PayloadWriteHostU64(ptr, node->saved_user_affinity);
    }

    payload_u64 ideal_off = 0;
    if (PayloadPmoReadGhvSmallOffsetField(g_cached_hv_diag.ghv_off_kthread_ideal_processor_offset, &ideal_off) &&
        ideal_off)
    {
        payload_u64 ptr = kt + ideal_off;
        if (PayloadIsKernelPointer(ptr))
            PayloadWriteHostU8(ptr, (unsigned char)node->saved_ideal_processor);
    }

    payload_u64 user_ideal_off = 0;
    if (PayloadPmoReadGhvSmallOffsetField(g_cached_hv_diag.ghv_off_kthread_user_ideal_processor_offset, &user_ideal_off) &&
        user_ideal_off)
    {
        payload_u64 ptr = kt + user_ideal_off;
        if (PayloadIsKernelPointer(ptr))
            PayloadWriteHostU8(ptr, (unsigned char)node->saved_user_ideal_processor);
    }
}

static bool PayloadPmoQueueCrossVcpuRspRestore(payload_pmo_call_node* node)
{
    if (!node ||
        node->entry_vcpu >= PAYLOAD_PMO_MAX_TRACKED_VCPUS)
    {
        return false;
    }

    volatile char* state = (volatile char*)&g_payload_pmo_pending_state[node->entry_vcpu];

    // Match TestDriver's mark_vtcall_cross_cpu_return() behavior: wait a short
    // bounded window for the entry vCPU to drain an older pending restore.  The
    // payload uses state 0xFF as a private "claimed but not yet published"
    // marker so the entry vCPU never observes state=1 before rsp/slot/delay are
    // fully written.
    constexpr payload_u64 timeout_cycles = 12500000ull;
    payload_u64 start_tsc = __rdtsc();
    for (;;)
    {
        if (_InterlockedCompareExchange8(state, (char)0xFF, 0) == 0)
        {
            g_payload_pmo_pending_rsp[node->entry_vcpu] = node->old_host_rsp;
            g_payload_pmo_pending_stack_slot[node->entry_vcpu] = node->stack_slot;
            g_payload_pmo_pending_stack_valid[node->entry_vcpu] = 1;
            // TestDriver parity: mark_vtcall_cross_cpu_return() gives the
            // entry CPU four full VM-exit cycles after HOST_RSP restore before
            // releasing the pending state.
            g_payload_pmo_pending_delay[node->entry_vcpu] = 4;
            _ReadWriteBarrier();
            g_payload_pmo_pending_state[node->entry_vcpu] = 1;
            _ReadWriteBarrier();
            return true;
        }

        if ((__rdtsc() - start_tsc) > timeout_cycles)
            return false;

        _mm_pause();
    }
}

static bool PayloadPmoLocalVtRetTryHandle(payload_guest_context* ctx, payload_u64 rip)
{
    if (!ctx || !rip)
        return false;

    payload_u64 process = 0;
    payload_u64 thread = 0;
    bool ids_ready = PayloadCurrentGuestIds(&process, &thread);

    for (payload_u64 i = 0; i < PAYLOAD_PMO_CALL_NODE_COUNT; ++i)
    {
        payload_pmo_call_node* node = &g_payload_pmo_call_nodes[i];
        if (node->state != 1 || node->ret_rip != rip)
            continue;
        if (ids_ready && (node->process != process || node->thread != thread))
            continue;

        node->new_context_ptr = (payload_u64)ctx;
        g_payload_pmo_vtret_last_node = (payload_u64)node;
        g_payload_pmo_vtret_last_rip = rip;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_vtret_match_count);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_vtret_handle_count);
        PayloadVtCallExit(ctx, node->old_vt_rsp);

        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_vtret_fail_count);
        return false;
    }

    return false;
}

