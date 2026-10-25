// Split from pmo_runtime.inl: runtime/user_call.inl.
// Included through the wrapper; same translation unit.

static payload_u64 PayloadPmoReadGhvFieldU64(payload_u64 offset)
{
    if (!offset || !g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return 0;
    payload_u64 field = g_cached_hv_diag.ghv + offset;
    return PayloadIsKernelPointer(field) ? PayloadReadHostU64(field) : 0;
}

static void PayloadPmoSuspendGuestCetShadowStack(payload_pmo_call_node* node)
{
    if (!node)
        return;

    payload_u64 cr4_guest = 0;
    payload_u64 cr4_mask = 0;
    payload_u64 cr4_shadow = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR4, &cr4_guest) ||
        !PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_GUEST_HOST_MASK, &cr4_mask) ||
        !PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_READ_SHADOW, &cr4_shadow))
    {
        return;
    }

    payload_u64 eff_cr4 = (cr4_shadow & cr4_mask) | (cr4_guest & ~cr4_mask);
    if ((eff_cr4 & (1ull << 23)) == 0) // CR4.CET
        return;

    payload_host_exception_info e = {};
    payload_u64 u_cet = PayloadRdmsrSafe(&e, (unsigned long)PAYLOAD_IA32_U_CET);
    if (!e.exception_occurred && (u_cet & 1ull))
    {
        node->saved_u_cet = u_cet;
        node->u_cet_saved = 1;
        e = {};
        PayloadWrmsrSafe(&e, (unsigned long)PAYLOAD_IA32_U_CET, u_cet & ~1ull);
    }

    e = {};
    payload_u64 s_cet = PayloadRdmsrSafe(&e, (unsigned long)PAYLOAD_IA32_S_CET);
    if (!e.exception_occurred && (s_cet & 1ull))
    {
        node->saved_s_cet = s_cet;
        node->s_cet_saved = 1;
        e = {};
        PayloadWrmsrSafe(&e, (unsigned long)PAYLOAD_IA32_S_CET, s_cet & ~1ull);
    }
}

static void PayloadPmoRestoreGuestCetShadowStack(payload_pmo_call_node* node)
{
    if (!node)
        return;

    if (node->u_cet_saved)
    {
        payload_host_exception_info e = {};
        PayloadWrmsrSafe(&e, (unsigned long)PAYLOAD_IA32_U_CET, node->saved_u_cet);
        node->u_cet_saved = 0;
    }

    if (node->s_cet_saved)
    {
        payload_host_exception_info e = {};
        PayloadWrmsrSafe(&e, (unsigned long)PAYLOAD_IA32_S_CET, node->saved_s_cet);
        node->s_cet_saved = 0;
    }
}

static bool PayloadPmoCallGuestWithReturn(payload_guest_context* ctx,
                                          payload_u64 function,
                                          const payload_u64* args,
                                          payload_u64 arg_count,
                                          payload_u64 ret_rip_override,
                                          payload_u64* ret_out)
{
    if (ret_out)
        *ret_out = 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_probe_count);
    g_payload_pmo_call_last_function = function;
    g_payload_pmo_call_last_reason = 0;
    if (!ctx || !function || !PayloadIsCanonical(function) || arg_count > PAYLOAD_PMO_MAX_ARGS)
    {
        g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_VMCS;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_fail_count);
        return false;
    }

    if (_InterlockedCompareExchange(&g_payload_pmo_call_depth, 1, 0) != 0)
    {
        g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_BUSY;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_fail_count);
        return false;
    }

    payload_pmo_call_node* node = PayloadPmoAllocCallNode();
    if (!node)
    {
        g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_NODE;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_fail_count);
        g_payload_pmo_call_depth = 0;
        return false;
    }

    bool stack_allocated = false;
    bool stack_saved = false;
    bool context_saved = false;
    bool ok = false;
    payload_u64 stack_slot = 0;
    payload_u64 new_host_rsp = 0;
    payload_u64 cdata[4] = {};
    bool is_cross_vcpu = false;

    do
    {
        if (!PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &node->old_rip) ||
            !PayloadVmread(PAYLOAD_VMCS_GUEST_RSP, &node->old_rsp) ||
            !PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &node->guest_cr3) ||
            !PayloadVmread(PAYLOAD_VMCS_HOST_RSP, &node->old_host_rsp))
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_VMCS;
            break;
        }

        node->entry_vcpu = PayloadCurrentVcpuIndex();
        g_payload_pmo_call_last_vcpu = node->entry_vcpu;
        if (node->entry_vcpu == ~0ull || node->entry_vcpu >= PAYLOAD_PMO_MAX_TRACKED_VCPUS)
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_VMCS;
            break;
        }

        if (!PayloadCurrentGuestIds(&node->process, &node->thread))
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_IDS;
            break;
        }

        node->ret_rip = ret_rip_override ? ret_rip_override : PayloadPmoFindBlankMemory(1);
        g_payload_pmo_call_last_blank = node->ret_rip;
        if (!node->ret_rip || !PayloadIsCanonical(node->ret_rip))
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_BLANK;
            break;
        }

        // Do not allocate/map page tables from the PMO VM-exit path.  The
        // stack slab must be pre-mapped from the passive setup path
        // (PayloadSetHvDiag -> MAP_HOST_RANGE) before a callout can point
        // VMCS_HOST_RSP at it; otherwise the next VM-exit loads an unmapped
        // host stack and triple-faults.
        if (!g_host_stack_mapped_in_host)
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_STACK;
            break;
        }

        if (!PayloadPmoAllocStackSlot(node->old_host_rsp, &stack_slot, &new_host_rsp))
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_STACK;
            break;
        }
        stack_allocated = true;
        node->stack_slot = stack_slot;

        node->new_user_rsp = ((node->old_rsp - PAYLOAD_PMO_STACK_POS) & ~0xFull) - 8ull;
        g_payload_pmo_call_last_new_rsp = node->new_user_rsp;
        if (!PayloadGuestCopyToHostBuffer(
                node->guest_cr3,
                node->new_user_rsp,
                node->stack_copy,
                PAYLOAD_PMO_STACK_COPY_SIZE))
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_STACK_COPY;
            break;
        }
        stack_saved = true;

        PayloadCopyMemory(node->old_context, ctx, PAYLOAD_PMO_GUEST_CONTEXT_SAVE_SIZE);
        context_saved = true;

        if (!PayloadGuestWriteU64(node->guest_cr3, node->new_user_rsp, node->ret_rip))
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_STACK_COPY;
            break;
        }

        for (payload_u64 i = 0; i < 4; ++i)
        {
            payload_u64 home_val = (i < arg_count && args) ? args[i] : 0;
            if (!PayloadGuestWriteU64(
                    node->guest_cr3,
                    node->new_user_rsp + 0x8ull + i * sizeof(payload_u64),
                    home_val))
            {
                g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_STACK_COPY;
                break;
            }
        }
        if (g_payload_pmo_call_last_reason == PAYLOAD_PMO_CALL_REASON_STACK_COPY)
            break;

        for (payload_u64 i = 4; i < arg_count; ++i)
        {
            if (!PayloadGuestWriteU64(
                    node->guest_cr3,
                    node->new_user_rsp + 0x28ull + (i - 4ull) * sizeof(payload_u64),
                    args ? args[i] : 0))
            {
                g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_STACK_COPY;
                break;
            }
        }
        if (g_payload_pmo_call_last_reason == PAYLOAD_PMO_CALL_REASON_STACK_COPY)
            break;

        ctx->rcx = (arg_count > 0 && args) ? args[0] : 0;
        ctx->rdx = (arg_count > 1 && args) ? args[1] : 0;
        ctx->r8 = (arg_count > 2 && args) ? args[2] : 0;
        ctx->r9 = (arg_count > 3 && args) ? args[3] : 0;

        if (!PayloadVmwrite(PAYLOAD_VMCS_GUEST_RSP, node->new_user_rsp) ||
            !PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, function) ||
            !PayloadVmwrite(PAYLOAD_VMCS_HOST_RSP, new_host_rsp))
        {
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_VMWRITE;
            break;
        }

        PayloadPmoApplyAffinity(node);
        PayloadPmoSuspendGuestCetShadowStack(node);

        g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_READY;
        PayloadVtCallEntry(ctx, &node->old_vt_rsp, cdata);

        PayloadPmoRestoreGuestCetShadowStack(node);

        payload_u64 return_vcpu = PayloadCurrentVcpuIndex();
        payload_guest_context* new_ctx = (payload_guest_context*)node->new_context_ptr;
        if (new_ctx)
        {
            g_payload_pmo_call_last_ret = new_ctx->rax;
            if (ret_out)
                *ret_out = new_ctx->rax;
        }

        if (return_vcpu == node->entry_vcpu)
        {
            PayloadVmwrite(PAYLOAD_VMCS_HOST_RSP, node->old_host_rsp);
            PayloadPmoFreeStackSlot(node->stack_slot);
            stack_allocated = false;
            _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_same_vcpu_count);
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_RETURNED;
        }
        else
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_cross_vcpu_count);
            g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_CROSS;
            // TestDriver queues mark_vtcall_cross_cpu_return() only after all
            // cleanup has completed on the return vCPU.  Keep the same order:
            // the return vCPU is still executing on this stack right now, so
            // publishing it to the entry-vCPU pending release path early can
            // allow the entry vCPU to restore/release it while cleanup below
            // is still touching the frame.
            is_cross_vcpu = true;
        }

        PayloadPmoRestoreAffinity(node);
        PayloadGuestCopyFromHostBuffer(
            node->guest_cr3,
            node->new_user_rsp,
            node->stack_copy,
            PAYLOAD_PMO_STACK_COPY_SIZE);
        PayloadVmwrite(PAYLOAD_VMCS_GUEST_RSP, node->old_rsp);
        PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, node->old_rip);
        PayloadCopyMemory(ctx, node->old_context, PAYLOAD_PMO_GUEST_CONTEXT_SAVE_SIZE);

        if (is_cross_vcpu)
        {
            if (PayloadPmoQueueCrossVcpuRspRestore(node))
                _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_cross_queue_count);
            else
                _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_cross_leak_count);

            // Do not free the stack slot on a cross-vCPU return.  The entry
            // VMCS may still load it until the queued lazy restore drains.  On
            // queue timeout we intentionally leak the slot, matching
            // TestDriver's "do not free a stack still referenced by VMCS"
            // fail-safe.
            stack_allocated = false;
        }

        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_return_count);
        ok = true;
    } while (false);

    if (!ok)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_fail_count);
        if (stack_saved && node->guest_cr3 && node->new_user_rsp)
        {
            PayloadGuestCopyFromHostBuffer(
                node->guest_cr3,
                node->new_user_rsp,
                node->stack_copy,
                PAYLOAD_PMO_STACK_COPY_SIZE);
        }
        if (node->old_rsp)
            PayloadVmwrite(PAYLOAD_VMCS_GUEST_RSP, node->old_rsp);
        if (node->old_rip)
            PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, node->old_rip);
        if (context_saved)
            PayloadCopyMemory(ctx, node->old_context, PAYLOAD_PMO_GUEST_CONTEXT_SAVE_SIZE);
    }

    if (stack_allocated)
        PayloadPmoFreeStackSlot(stack_slot);
    PayloadPmoFreeCallNode(node);
    g_payload_pmo_call_depth = 0;
    return ok;
}

static bool PayloadPmoCallUser(payload_guest_context* ctx,
                               payload_u64 function,
                               const payload_u64* args,
                               payload_u64 arg_count,
                               payload_u64* ret_out)
{
    return PayloadPmoCallGuestWithReturn(ctx, function, args, arg_count, 0, ret_out);
}

static bool PayloadPmoCallKernel(payload_guest_context* ctx,
                                 payload_u64 function,
                                 const payload_u64* args,
                                 payload_u64 arg_count,
                                 payload_u64* ret_out)
{
    payload_u64 kernel_blank = PayloadPmoReadGhvFieldU64(g_cached_hv_diag.ghv_off_kernel_blank_va);
    if (!PayloadIsKernelPointer(kernel_blank))
    {
        g_payload_pmo_call_last_reason = PAYLOAD_PMO_CALL_REASON_NO_BLANK;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_pmo_call_fail_count);
        return false;
    }
    return PayloadPmoCallGuestWithReturn(ctx, function, args, arg_count, kernel_blank, ret_out);
}
