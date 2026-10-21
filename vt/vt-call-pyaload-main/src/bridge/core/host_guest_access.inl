// Split from payload_bridge.inl: core/host_guest_access.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static bool PayloadIsCanonical(payload_u64 va)
{
    payload_u64 top = va >> 47;
    return top == 0 || top == 0x1FFFFull;
}

static bool PayloadIsKernelPointer(payload_u64 va)
{
    return PayloadIsCanonical(va) && (va >> 47) == 0x1FFFFull;
}

static payload_u64 PayloadReadHostU64(payload_u64 va)
{
    payload_u64 value = 0;
    payload_host_exception_info e = {};
    PayloadMemcpySafe(&e, &value, (const void*)va, sizeof(value));
    if (e.exception_occurred)
    {
        g_payload_misc_exit_last_action = 0x780ull;
        g_payload_misc_exit_last_vector = e.vector;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
        return 0;
    }
    return value;
}

static unsigned int PayloadReadHostU32(payload_u64 va)
{
    unsigned int value = 0;
    payload_host_exception_info e = {};
    PayloadMemcpySafe(&e, &value, (const void*)va, sizeof(value));
    if (e.exception_occurred)
    {
        g_payload_misc_exit_last_action = 0x781ull;
        g_payload_misc_exit_last_vector = e.vector;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
        return 0;
    }
    return value;
}

static unsigned char PayloadReadHostU8(payload_u64 va)
{
    unsigned char value = 0;
    payload_host_exception_info e = {};
    PayloadMemcpySafe(&e, &value, (const void*)va, sizeof(value));
    if (e.exception_occurred)
    {
        g_payload_misc_exit_last_action = 0x782ull;
        g_payload_misc_exit_last_vector = e.vector;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
        return 0;
    }
    return value;
}

static payload_u64 PayloadDiagOffset(payload_u64 dynamic_offset, payload_u64 fallback_offset)
{
    return dynamic_offset ? dynamic_offset : fallback_offset;
}

static payload_u64 PayloadDiagGhvField(payload_u64 dynamic_offset, payload_u64 fallback_offset)
{
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return 0;

    payload_u64 offset = PayloadDiagOffset(dynamic_offset, fallback_offset);
    if (!offset)
        return 0;

    return g_cached_hv_diag.ghv + offset;
}

static payload_u64 PayloadDiagVtCallListBase()
{
    return PayloadDiagGhvField(
        g_cached_hv_diag.ghv_off_vtcallstack_list,
        PAYLOAD_GHV_VTCALL_LIST_OFFSET);
}

static void PayloadWriteHostU64(payload_u64 va, payload_u64 value)
{
    payload_host_exception_info e = {};
    PayloadMemcpySafe(&e, (void*)va, &value, sizeof(value));
    if (e.exception_occurred)
    {
        g_payload_misc_exit_last_action = 0x783ull;
        g_payload_misc_exit_last_vector = e.vector;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
    }
}

static void PayloadWriteHostU32(payload_u64 va, unsigned int value)
{
    payload_host_exception_info e = {};
    PayloadMemcpySafe(&e, (void*)va, &value, sizeof(value));
    if (e.exception_occurred)
    {
        g_payload_misc_exit_last_action = 0x785ull;
        g_payload_misc_exit_last_vector = e.vector;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
    }
}

static void PayloadWriteHostU8(payload_u64 va, unsigned char value)
{
    payload_host_exception_info e = {};
    PayloadMemcpySafe(&e, (void*)va, &value, sizeof(value));
    if (e.exception_occurred)
    {
        g_payload_misc_exit_last_action = 0x784ull;
        g_payload_misc_exit_last_vector = e.vector;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_misc_exit_fail_count);
    }
}

static bool PayloadReadSystemVa64(payload_u64 va, payload_u64* value)
{
    if (!value || !g_system_cr3 || !PayloadIsCanonical(va))
        return false;

    payload_u64 pa = 0;
    payload_u64 bytes_left = 0;
    if (!PayloadGvaToGpa(g_system_cr3, va, &pa, &bytes_left) ||
        bytes_left < sizeof(payload_u64) ||
        !PayloadHostPhysicalRangeMapped(pa, sizeof(payload_u64)))
    {
        return false;
    }

    return PayloadReadPhys64(pa, value);
}

static bool PayloadReadGhvU64(payload_u64 field_offset, payload_u64* value)
{
    if (!value || !g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return false;

    *value = PayloadReadHostU64(g_cached_hv_diag.ghv + field_offset);
    return true;
}

static bool PayloadReadGhvOffsetSmall(payload_u64 field_offset, payload_u64* value)
{
    payload_u64 raw = 0;
    if (!PayloadReadGhvU64(field_offset, &raw) || raw > 0x4000ull)
        return false;

    *value = raw;
    return true;
}

static bool PayloadCurrentGuestIds(payload_u64* process_out, payload_u64* thread_out)
{
    if (!process_out || !thread_out)
        return false;

    *process_out = 0;
    *thread_out = 0;

    payload_u64 kpcr_prcb_off = 0;
    payload_u64 current_thread_off = 0;
    payload_u64 apc_state_off = 0;
    payload_u64 apc_process_off = 0;
    if (!PayloadReadGhvOffsetSmall(
            PayloadDiagOffset(g_cached_hv_diag.ghv_off_kpcr_prcb_offset, PAYLOAD_GHV_OFF_KPCR_PRCB),
            &kpcr_prcb_off) ||
        !PayloadReadGhvOffsetSmall(
            PayloadDiagOffset(g_cached_hv_diag.ghv_off_kprcb_current_thread_offset, PAYLOAD_GHV_OFF_KPRCB_CURRENT_THREAD),
            &current_thread_off) ||
        !PayloadReadGhvOffsetSmall(
            PayloadDiagOffset(g_cached_hv_diag.ghv_off_kthread_apc_state_offset, PAYLOAD_GHV_OFF_KTHREAD_APC_STATE),
            &apc_state_off) ||
        !PayloadReadGhvOffsetSmall(
            PayloadDiagOffset(g_cached_hv_diag.ghv_off_kapc_state_process_offset, PAYLOAD_GHV_OFF_KAPC_STATE_PROCESS),
            &apc_process_off))
    {
        return false;
    }

    payload_u64 ss_access = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_SS_ACCESS_RIGHTS, &ss_access))
        return false;

    payload_u64 kpcr = 0;
    payload_u64 cpl = (ss_access >> 5) & 0x3ull;
    if (cpl == 0)
    {
        if (!PayloadVmread(PAYLOAD_VMCS_GUEST_GS_BASE, &kpcr))
            return false;
    }
    else
    {
        kpcr = __readmsr((unsigned long)PAYLOAD_IA32_KERNEL_GS_BASE);
    }

    if (!PayloadIsKernelPointer(kpcr))
        return false;

    payload_u64 thread = 0;
    payload_u64 process = 0;
    if (!PayloadReadSystemVa64(kpcr + kpcr_prcb_off + current_thread_off, &thread) ||
        !PayloadIsKernelPointer(thread) ||
        !PayloadReadSystemVa64(thread + apc_state_off + apc_process_off, &process) ||
        !PayloadIsKernelPointer(process))
    {
        return false;
    }

    *process_out = process;
    *thread_out = thread;
    return true;
}

static bool PayloadGuestCopyToHostBuffer(payload_u64 cr3, payload_u64 gva, void* dst, payload_u64 size)
{
    if (!cr3 || !gva || !dst)
        return false;

    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 left = 0;
        auto src = PayloadGvaToHvaCr3(cr3, gva + done, &left);
        if (!src || !left)
            return false;

        payload_u64 chunk = PayloadMinU64(size - done, left);
        PayloadCopyMemory((unsigned char*)dst + done, src, chunk);
        done += chunk;
    }
    return true;
}

static bool PayloadGuestCopyFromHostBuffer(payload_u64 cr3, payload_u64 gva, const void* src, payload_u64 size)
{
    if (!cr3 || !gva || !src)
        return false;

    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 left = 0;
        auto dst = PayloadGvaToHvaCr3(cr3, gva + done, &left);
        if (!dst || !left)
            return false;

        payload_u64 chunk = PayloadMinU64(size - done, left);
        PayloadCopyMemory(dst, (const unsigned char*)src + done, chunk);
        done += chunk;
    }
    return true;
}

static bool PayloadGuestWriteU64(payload_u64 cr3, payload_u64 gva, payload_u64 value)
{
    return PayloadGuestCopyFromHostBuffer(cr3, gva, &value, sizeof(value));
}

static bool PayloadBridgeCurrentVcpuIdx(payload_u64* idx_out)
{
    if (!idx_out)
        return false;
    payload_u64 vpid = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_VPID, &vpid) || !vpid)
        return false;
    payload_u64 idx = vpid - 1;
    if (idx >= 64)
        return false;
    *idx_out = idx;
    return true;
}

static void PayloadBridgeMarkHideVmExitOverhead()
{
    payload_u64 idx = 0;
    if (PayloadBridgeCurrentVcpuIdx(&idx))
        g_payload_tsc_hide_overhead[idx] = 1;
}

