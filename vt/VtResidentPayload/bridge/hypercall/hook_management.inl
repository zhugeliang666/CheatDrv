// Resident TestDriver hook-management hypercall parity.
//
// This file intentionally mirrors the observable TestDriver control-plane
// handlers instead of consuming them as no-op.  Business handler bodies still
// live in the existing payload hook dispatcher; this layer recreates the
// management side effects: EPT hook nodes/PTE permissions, eh::* 表 bits,
// MMR entries, BP hook chains, vt_hook_slot bookkeeping, and trampoline pool
// registration.

#include "../hooks/hook_table_support.inl"

static volatile payload_u64 g_payload_vh_uninit_bitmap = 0;
static volatile LONG g_payload_mgmt_scratch_lock = 0;
static unsigned char g_payload_mgmt_scratch[PAGE_SIZE] = {};

static bool PayloadMgmtScratchLock()
{
    for (payload_u64 spin = 0; spin < 0x100000ull; ++spin)
    {
        if (_InterlockedCompareExchange(&g_payload_mgmt_scratch_lock, 1, 0) == 0)
            return true;
        _mm_pause();
    }
    return false;
}

static void PayloadMgmtScratchUnlock()
{
    _InterlockedExchange(&g_payload_mgmt_scratch_lock, 0);
}

static payload_u64 PayloadMgmtCurrentGuestCr3()
{
    payload_u64 cr3 = 0;
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &cr3))
        return cr3 & ~0xFFFull;
    return 0;
}

static bool PayloadMgmtReadGuestBuffer(payload_u64 gva, void* out, payload_u64 size)
{
    if (!gva || !out || !size)
        return false;
    payload_u64 cr3 = PayloadMgmtCurrentGuestCr3();
    if (cr3 && PayloadGuestCopyToHostBuffer(cr3, gva, out, size))
        return true;
    if (g_system_cr3 && (g_system_cr3 & ~0xFFFull) != cr3)
        return PayloadGuestCopyToHostBuffer(g_system_cr3 & ~0xFFFull, gva, out, size);
    return false;
}

static payload_u64 PayloadMgmtGuestVaToHva(payload_u64 gva)
{
    payload_u64 left = 0;
    payload_u64 cr3 = PayloadMgmtCurrentGuestCr3();
    if (cr3)
    {
        auto hva = (payload_u64)PayloadGvaToHvaCr3(cr3, gva, &left);
        if (hva)
            return hva;
    }
    if (g_system_cr3)
        return (payload_u64)PayloadGvaToHvaCr3(g_system_cr3 & ~0xFFFull, gva, &left);
    return 0;
}

static bool PayloadMgmtLocatePteForVcpuRelaxed(payload_u64 vcpu_ptr,
                                               payload_u64 gpa,
                                               bool force_split,
                                               payload_u64* pte_va,
                                               payload_u64* pte_value)
{
    if (pte_va) *pte_va = 0;
    if (pte_value) *pte_value = 0;
    if (!PayloadIsKernelPointer(vcpu_ptr) || !g_cached_hv_diag.vcpu_off_ept)
        return false;

    payload_u64 pml4_idx = (gpa >> 39) & 0x1FFull;
    payload_u64 pdpt_idx = (gpa >> 30) & 0x1FFull;
    payload_u64 pd_idx = (gpa >> 21) & 0x1FFull;
    payload_u64 pt_idx = (gpa >> 12) & 0x1FFull;
    if (pml4_idx != 0 || pdpt_idx >= 512)
        return false;

    payload_u64 ept_base = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept;
    payload_u64 pde_va = ept_base + 0x2000ull +
        ((pdpt_idx * 512ull) + pd_idx) * sizeof(payload_u64);
    if (!PayloadIsKernelPointer(pde_va))
        return false;

    payload_u64 pde = PayloadReadHostU64(pde_va);
    if (pde & PAYLOAD_EPT_LARGE_PAGE)
    {
        if (!force_split || !PayloadEptSplitPdeForVcpu(vcpu_ptr, pde_va, pde))
            return false;
        pde = PayloadReadHostU64(pde_va);
        if (pde & PAYLOAD_EPT_LARGE_PAGE)
            return false;
    }

    if (!(pde & PAYLOAD_EPT_PERM_MASK))
        return false;

    payload_u64 pt_pa = pde & PAYLOAD_EPT_PFN_MASK;
    payload_u64 leaf_pa = pt_pa + pt_idx * sizeof(payload_u64);
    if (leaf_pa < pt_pa || !PayloadHostPhysicalRangeMapped(leaf_pa, sizeof(payload_u64)))
        return false;

    payload_u64 leaf = PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + leaf_pa;
    payload_u64 entry = PayloadReadHostU64(leaf);
    if (pte_va) *pte_va = leaf;
    if (pte_value) *pte_value = entry;
    return true;
}

static bool PayloadMgmtEptUnlinkNode(payload_u64 vcpu_ptr, payload_u64 orig_pfn)
{
    payload_u64 active_head_off = PayloadDiagVcpuEptHookActiveOffset();
    if (!PayloadIsKernelPointer(vcpu_ptr) || !active_head_off || !orig_pfn)
        return false;
    payload_u64 node_next_off = 0;
    payload_u64 node_orig_off = 0;
    if (!PayloadDiagVcpuEptHookNodeLayout(&node_next_off, &node_orig_off, nullptr, nullptr))
        return false;

    payload_u64 active_field = vcpu_ptr + active_head_off;
    payload_u64 free_field = active_field + sizeof(payload_u64);
    payload_u64 node = PayloadReadHostU64(active_field);
    payload_u64 prev = 0;

    for (payload_u64 i = 0; i < PAYLOAD_VCPU_EPT_HOOK_NODE_MAX && PayloadIsKernelPointer(node); ++i)
    {
        payload_u64 node_orig = PayloadReadHostU32(node + node_orig_off);
        payload_u64 next = PayloadReadHostU64(node + node_next_off);
        if (node_orig == orig_pfn)
        {
            if (prev)
                PayloadWriteHostU64(prev + node_next_off, next);
            else
                PayloadWriteHostU64(active_field, next);

            payload_u64 old_free = PayloadReadHostU64(free_field);
            PayloadWriteHostU64(node + node_next_off, old_free);
            PayloadWriteHostU64(free_field, node);
            return true;
        }
        if (!next || next == node)
            break;
        prev = node;
        node = next;
    }
    return false;
}

static bool PayloadMgmtNativeRemoveEptHookForVcpu(payload_u64 vcpu_ptr, payload_u64 orig_pfn)
{
    if (!PayloadIsKernelPointer(vcpu_ptr) || !orig_pfn)
        return false;

    bool unlinked = PayloadMgmtEptUnlinkNode(vcpu_ptr, orig_pfn);
    if (!unlinked)
        return false;

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (!PayloadMgmtLocatePteForVcpuRelaxed(vcpu_ptr, orig_pfn << 12, false, &pte_va, &before))
        return true;

    payload_u64 after = PayloadEptEntryWithPfnPerms(before, orig_pfn, true, true, true);
    PayloadWriteHostU64(pte_va, after);
    PayloadEptInveptAll();
    g_payload_ept_tramp_last_pte_pa = pte_va;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = after;
    return true;
}

static payload_u64 PayloadMgmtCurrentVcpuBit()
{
    payload_u64 idx = PayloadCurrentVcpuIndex();
    if (idx >= PAYLOAD_EPT_MAX_TRACKED_VCPUS)
        return 0;
    return 1ull << idx;
}

static payload_u64 PayloadMgmtEhProcessCr3(payload_u64 process, payload_u64 va)
{
    payload_u64 fallback = PayloadMgmtCurrentGuestCr3();
    return PayloadPmoEffectiveCr3(process, va, fallback);
}

static bool PayloadMgmtEhInstallSelfEntry(payload_u64 entry, bool enable_sets_bit_first)
{
    payload_u64 bit = PayloadMgmtCurrentVcpuBit();
    payload_u64 vcpu = PayloadCurrentVcpuPtr();
    if (!entry || !bit || !PayloadIsKernelPointer(vcpu))
        return false;

    payload_u64 active_field = entry + g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap;
    payload_u64 bitmap = PayloadReadHostU64(active_field);
    if (bitmap & bit)
        return true;

    payload_u64 orig_pfn = PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_orig_pfn);
    payload_u64 fake_pfn = PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_fake_pfn);
    unsigned char view_mode = PayloadReadHostU8(entry + g_cached_hv_diag.ept_hook_entry_off_is_fake_page);

    if (enable_sets_bit_first)
        _InterlockedOr64((volatile LONG64*)active_field, (LONG64)bit);

    bool ok = PayloadEptNativeInstallForVcpu(vcpu, orig_pfn, fake_pfn, view_mode);
    if (ok && !enable_sets_bit_first)
        _InterlockedOr64((volatile LONG64*)active_field, (LONG64)bit);
    return ok;
}

static payload_u64 PayloadMgmtEhFindEntryByProcessVa(payload_u64 process, payload_u64 va, payload_u64* process_cr3_out = nullptr)
{
    if (process_cr3_out) *process_cr3_out = 0;
    payload_u64 process_cr3 = PayloadMgmtEhProcessCr3(process, va);
    if (!process_cr3 || !va)
        return 0;
    if (process_cr3_out) *process_cr3_out = process_cr3;

    payload_u64 table = PayloadEhTableBase();
    if (!table || !PayloadEhTableLock(table))
        return 0;
    payload_u64 entry = PayloadEhFindEntryLocked(table, process_cr3, va & ~0xFFFull);
    PayloadEhTableUnlock(table);
    return entry;
}

static bool PayloadMgmtEhReleaseCurrent(payload_u64 entry, bool free_on_zero, payload_u64* orig_pfn_out = nullptr)
{
    if (orig_pfn_out) *orig_pfn_out = 0;
    payload_u64 table = PayloadEhTableBase();
    payload_u64 bit = PayloadMgmtCurrentVcpuBit();
    if (!table || !entry || !bit || !PayloadEhTableLock(table))
        return false;

    payload_u64 active_field = entry + g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap;
    payload_u64 bitmap = PayloadReadHostU64(active_field);
    bool was_active = (bitmap & bit) != 0;
    payload_u64 orig_pfn = PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_orig_pfn);
    payload_u64 fake_pfn = PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_fake_pfn);
    if (was_active)
        PayloadWriteHostU64(active_field, bitmap & ~bit);
    payload_u64 after = PayloadReadHostU64(active_field);
    if (free_on_zero && after == 0)
        PayloadEptClearNativePending(entry, orig_pfn, fake_pfn);
    if (free_on_zero && after == 0)
        PayloadEhFreeEntryLocked(table, entry);
    PayloadEhTableUnlock(table);

    if (orig_pfn_out) *orig_pfn_out = orig_pfn;
    return was_active;
}

static payload_u64 PayloadBridgeHandleEhInstall(payload_guest_context* ctx, payload_u64 code)
{
    bool full_zero = (ctx->r8 & 1ull) != 0;
    unsigned char view_mode = (ctx->r8 & 4ull) ? 2u : ((ctx->r8 & 2ull) ? 1u : 0u);
    payload_u64 process_cr3 = PayloadMgmtEhProcessCr3(ctx->rcx, ctx->rdx);
    bool freshly = false;
    payload_u64 entry = PayloadEhPrepareEntry(ctx->rcx, process_cr3, ctx->rdx, full_zero, view_mode, &freshly);
    if (entry)
        PayloadMgmtEhInstallSelfEntry(entry, false);
    return PayloadBridgeCompleteHypercall(ctx, code, entry ? 1 : 0);
}

static payload_u64 PayloadBridgeHandleEhRemove(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 entry = PayloadMgmtEhFindEntryByProcessVa(ctx->rcx, ctx->rdx);
    if (!entry)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    payload_u64 orig = 0;
    bool was_active = PayloadMgmtEhReleaseCurrent(entry, true, &orig);
    if (was_active && orig)
        PayloadMgmtNativeRemoveEptHookForVcpu(PayloadCurrentVcpuPtr(), orig);
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleEhEnable(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 entry = PayloadMgmtEhFindEntryByProcessVa(ctx->rcx, ctx->rdx);
    if (!entry)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    PayloadMgmtEhInstallSelfEntry(entry, true);
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleEhDisable(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 entry = PayloadMgmtEhFindEntryByProcessVa(ctx->rcx, ctx->rdx);
    if (!entry)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    payload_u64 orig = 0;
    bool was_active = PayloadMgmtEhReleaseCurrent(entry, false, &orig);
    if (was_active && orig)
        PayloadMgmtNativeRemoveEptHookForVcpu(PayloadCurrentVcpuPtr(), orig);
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleEhWrite(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 process_cr3 = PayloadMgmtEhProcessCr3(ctx->rcx, ctx->rdx);
    payload_u64 size = ctx->r9;
    if (size > PAGE_SIZE)
        size = PAGE_SIZE;
    if (!process_cr3 || !ctx->rdx || !ctx->r8 || !size)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    if (!PayloadMgmtScratchLock())
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    if (!PayloadGuestCopyToHostBuffer(g_system_cr3 ? (g_system_cr3 & ~0xFFFull) : process_cr3,
                                      ctx->r8, g_payload_mgmt_scratch, size))
    {
        PayloadMgmtScratchUnlock();
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }

    payload_u64 table = PayloadEhTableBase();
    if (!table || !PayloadEhTableLock(table))
    {
        PayloadMgmtScratchUnlock();
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    }
    payload_u64 entry = PayloadEhFindEntryLocked(table, process_cr3, ctx->rdx & ~0xFFFull);
    bool ok = false;
    if (entry)
    {
        payload_u64 fake = PayloadEhFakePageBase(table, entry);
        payload_u64 off = ctx->rdx & 0xFFFull;
        if (fake && off < PAGE_SIZE)
        {
            payload_u64 n = PayloadMinU64(size, PAGE_SIZE - off);
            PayloadCopyMemory((void*)(fake + off), g_payload_mgmt_scratch, n);
            ok = true;
        }
    }
    PayloadEhTableUnlock(table);
    PayloadMgmtScratchUnlock();
    return PayloadBridgeCompleteHypercall(ctx, code, ok ? 1 : 0);
}

static payload_u64 PayloadBridgeHandleEhGetVa(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 entry = PayloadMgmtEhFindEntryByProcessVa(ctx->rcx, ctx->rdx);
    payload_u64 fake = entry ? PayloadEhGetFakeHvaForEntry(entry, ctx->rdx) : 0;
    return PayloadBridgeCompleteHypercall(ctx, code, fake);
}

static payload_u64 PayloadBridgeHandleEhRemoveAllByProcess(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 process_cr3 = PayloadPmoReadProcessCr3(ctx->rcx);
    payload_u64 table = PayloadEhTableBase();
    payload_u64 bit = PayloadMgmtCurrentVcpuBit();
    payload_u64 pfns[32] = {};
    payload_u64 count = 0;

    if (process_cr3 && table && bit && PayloadEhTableLock(table))
    {
        payload_u64 node = PayloadReadHostU64(table + g_cached_hv_diag.ept_hook_table_off_active_list_head);
        for (payload_u64 i = 0;
             i < g_cached_hv_diag.ept_hook_table_capacity && PayloadEhEntryInTable(table, node);
             ++i)
        {
            payload_u64 next = PayloadReadHostU64(node + g_cached_hv_diag.ept_hook_entry_off_next);
            if (PayloadReadHostU64(node + g_cached_hv_diag.ept_hook_entry_off_process_cr3) == process_cr3)
            {
                payload_u64 active_field = node + g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap;
                payload_u64 bitmap = PayloadReadHostU64(active_field);
                if ((bitmap & bit) && count < RTL_NUMBER_OF(pfns))
                {
                    payload_u64 orig_pfn = PayloadReadHostU64(node + g_cached_hv_diag.ept_hook_entry_off_orig_pfn);
                    payload_u64 fake_pfn = PayloadReadHostU64(node + g_cached_hv_diag.ept_hook_entry_off_fake_pfn);
                    pfns[count++] = orig_pfn;
                    PayloadWriteHostU64(active_field, bitmap & ~bit);
                    if (PayloadReadHostU64(active_field) == 0)
                    {
                        PayloadEptClearNativePending(node, orig_pfn, fake_pfn);
                        PayloadEhFreeEntryLocked(table, node);
                    }
                }
            }
            if (!next || next == node)
                break;
            node = next;
        }
        PayloadEhTableUnlock(table);
    }

    for (payload_u64 i = 0; i < count; ++i)
        if (pfns[i])
            PayloadMgmtNativeRemoveEptHookForVcpu(PayloadCurrentVcpuPtr(), pfns[i]);
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleOldInstallEptHook(payload_guest_context* ctx, payload_u64 code)
{
    bool ok = PayloadEptNativeInstallForVcpu(PayloadCurrentVcpuPtr(), ctx->rcx, ctx->rdx,
                                             (unsigned char)(ctx->r8 & 0xFFull));
    return PayloadBridgeCompleteHypercall(ctx, code, ok ? 1 : 0);
}

static payload_u64 PayloadBridgeHandleOldRemoveEptHook(payload_guest_context* ctx, payload_u64 code)
{
    PayloadMgmtNativeRemoveEptHookForVcpu(PayloadCurrentVcpuPtr(), ctx->rcx);
    return PayloadBridgeCompleteHypercall(ctx, code, 0);
}

static payload_u64 PayloadMgmtMmrBase(payload_u64 vcpu)
{
    static constexpr payload_u64 kMmrCount = 120ull;
    static constexpr payload_u64 kMmrEntrySize = 16ull;
    if (!PayloadIsKernelPointer(vcpu) || !g_cached_hv_diag.vcpu_off_ept_mmr_mtf_pte)
        return 0;
    return vcpu + g_cached_hv_diag.vcpu_off_ept_mmr_mtf_pte - kMmrCount * kMmrEntrySize;
}

static payload_u64 PayloadBridgeHandleInstallMmr(payload_guest_context* ctx, payload_u64 code)
{
    static constexpr payload_u64 kMmrCount = 120ull;
    static constexpr payload_u64 kMmrEntrySize = 16ull;
    payload_u64 vcpu = PayloadCurrentVcpuPtr();
    payload_u64 base = PayloadMgmtMmrBase(vcpu);
    payload_u64 result = 0;
    if (!base)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    payload_u64 entry = 0;
    for (payload_u64 i = 0; i < kMmrCount; ++i)
    {
        payload_u64 e = base + i * kMmrEntrySize;
        if (PayloadReadHostU32(e + 8ull) == 0)
        {
            entry = e;
            break;
        }
    }
    if (!entry)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    unsigned int size = (unsigned int)ctx->rdx;
    unsigned char mode = (unsigned char)(ctx->r8 & 0x7ull);
    PayloadWriteHostU64(entry + 0ull, ctx->rcx);
        *(volatile unsigned int*)(entry + 8ull) = (unsigned int)size;
    PayloadWriteHostU8(entry + 12ull, mode);

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (PayloadMgmtLocatePteForVcpuRelaxed(vcpu, ctx->rcx, true, &pte_va, &before))
    {
        bool r = (mode & 1) == 0;
        bool w = (mode & 2) == 0;
        bool x = (mode & 4) == 0;
        if (w && !r)
            w = false;
        payload_u64 pfn = (before & PAYLOAD_EPT_PFN_MASK) >> 12;
        payload_u64 after = PayloadEptEntryWithPfnPerms(before, pfn, r, w, x);
        PayloadWriteHostU64(pte_va, after);
        PayloadEptInveptAll();
        result = entry;
    }
    return PayloadBridgeCompleteHypercall(ctx, code, result);
}

static payload_u64 PayloadBridgeHandleRemoveMmr(payload_guest_context* ctx, payload_u64 code)
{
    static constexpr payload_u64 kMmrCount = 120ull;
    static constexpr payload_u64 kMmrEntrySize = 16ull;
    payload_u64 vcpu = PayloadCurrentVcpuPtr();
    payload_u64 base = PayloadMgmtMmrBase(vcpu);
    if (base)
    {
        for (payload_u64 i = 0; i < kMmrCount; ++i)
        {
            payload_u64 e = base + i * kMmrEntrySize;
            if (PayloadReadHostU32(e + 8ull) == 0)
                continue;
            if (PayloadReadHostU64(e) != ctx->rcx)
                continue;
            payload_u64 pte_va = 0;
            payload_u64 before = 0;
            if (PayloadMgmtLocatePteForVcpuRelaxed(vcpu, PayloadReadHostU64(e), true, &pte_va, &before))
            {
                payload_u64 pfn = (before & PAYLOAD_EPT_PFN_MASK) >> 12;
                PayloadWriteHostU64(pte_va, PayloadEptEntryWithPfnPerms(before, pfn, true, true, true));
                PayloadEptInveptAll();
            }
            *(volatile unsigned int*)(e + 8ull) = 0;
            break;
        }
    }
    return PayloadBridgeCompleteHypercall(ctx, code, 0);
}

static payload_u64 PayloadBridgeHandleRemoveAllMmrs(payload_guest_context* ctx, payload_u64 code)
{
    UNREFERENCED_PARAMETER(ctx);
    static constexpr payload_u64 kMmrCount = 120ull;
    static constexpr payload_u64 kMmrEntrySize = 16ull;
    payload_u64 vcpu = PayloadCurrentVcpuPtr();
    payload_u64 base = PayloadMgmtMmrBase(vcpu);
    if (base)
    {
        for (payload_u64 i = 0; i < kMmrCount; ++i)
        {
            payload_u64 e = base + i * kMmrEntrySize;
            if (PayloadReadHostU32(e + 8ull) == 0)
                continue;
            payload_u64 pte_va = 0;
            payload_u64 before = 0;
            if (PayloadMgmtLocatePteForVcpuRelaxed(vcpu, PayloadReadHostU64(e), true, &pte_va, &before))
            {
                payload_u64 pfn = (before & PAYLOAD_EPT_PFN_MASK) >> 12;
                PayloadWriteHostU64(pte_va, PayloadEptEntryWithPfnPerms(before, pfn, true, true, true));
            }
            *(volatile unsigned int*)(e + 8ull) = 0;
        }
        PayloadEptInveptAll();
    }
    return PayloadBridgeCompleteHypercall(ctx, code, 0);
}

static payload_u64 PayloadMgmtBpActiveField(payload_u64 vcpu)
{
    static constexpr payload_u64 kEptHooksActiveToBpActive = 0x6A0ull;
    payload_u64 ept_active = PayloadDiagVcpuEptHookActiveOffset();
    if (!PayloadIsKernelPointer(vcpu) || !ept_active)
        return 0;
    return vcpu + ept_active + kEptHooksActiveToBpActive;
}

static payload_u64 PayloadBridgeHandleInstallBreakpointHook(payload_guest_context* ctx, payload_u64 code)
{
    static constexpr payload_u64 kBpNodeSize = 0x38ull;
    static constexpr payload_u64 kBpCapacity = 30ull;
    payload_u64 active_field = PayloadMgmtBpActiveField(PayloadCurrentVcpuPtr());
    if (active_field)
    {
        payload_u64 free_field = active_field + sizeof(payload_u64);
        payload_u64 free_node = PayloadReadHostU64(free_field);
        payload_u64 buffer_start = active_field - kBpCapacity * kBpNodeSize;
        if (free_node >= buffer_start && free_node < active_field)
        {
            payload_u64 next_free = PayloadReadHostU64(free_node);
            payload_u64 old_head = PayloadReadHostU64(active_field);
            PayloadWriteHostU64(free_field, next_free);
            PayloadWriteHostU64(free_node + 0x00ull, old_head);
            PayloadWriteHostU64(free_node + 0x08ull, ctx->rcx);
            PayloadWriteHostU64(free_node + 0x10ull, ctx->rdx);
            PayloadWriteHostU64(free_node + 0x18ull, 0);
            PayloadWriteHostU64(free_node + 0x20ull, ctx->r8);
            PayloadWriteHostU64(free_node + 0x28ull, 0);
            PayloadWriteHostU8(free_node + 0x30ull, ctx->r9 ? 1 : 0);
            PayloadWriteHostU64(active_field, free_node);
        }
    }
    return PayloadBridgeCompleteHypercall(ctx, code, 0);
}

static payload_u64 PayloadBridgeHandleRemoveBreakpointHook(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 active_field = PayloadMgmtBpActiveField(PayloadCurrentVcpuPtr());
    if (active_field)
    {
        payload_u64 free_field = active_field + sizeof(payload_u64);
        payload_u64 node = PayloadReadHostU64(active_field);
        payload_u64 prev = 0;
        for (payload_u64 i = 0; i < 30 && PayloadIsKernelPointer(node); ++i)
        {
            payload_u64 next = PayloadReadHostU64(node);
            payload_u64 cr3 = PayloadReadHostU64(node + 0x08ull);
            payload_u64 va = PayloadReadHostU64(node + 0x10ull);
            if (va == ctx->rdx && cr3 == ctx->rcx)
            {
                if (prev)
                    PayloadWriteHostU64(prev, next);
                else
                    PayloadWriteHostU64(active_field, next);
                payload_u64 old_free = PayloadReadHostU64(free_field);
                PayloadWriteHostU64(node, old_free);
                PayloadWriteHostU64(free_field, node);
                break;
            }
            if (!next || next == node)
                break;
            prev = node;
            node = next;
        }
    }
    return PayloadBridgeCompleteHypercall(ctx, code, 0);
}

static bool PayloadMgmtSlotTableReady()
{
    return g_hv_diag_cache_ready &&
           PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) &&
           g_cached_hv_diag.vt_hook_slot_count &&
           g_cached_hv_diag.vt_hook_slot_size &&
           g_cached_hv_diag.vt_hook_slot_off_occupied &&
           g_cached_hv_diag.vt_hook_slot_off_data_type;
}

static payload_u64 PayloadMgmtFindSlotByAddress(payload_u64 target_va)
{
    if (!PayloadMgmtSlotTableReady() || !target_va)
        return 0;
    payload_u64 count = g_cached_hv_diag.vt_hook_slot_count;
    if (count > 64) count = 64;
    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 slot = g_cached_hv_diag.vt_hook_table_ptr + i * g_cached_hv_diag.vt_hook_slot_size;
        if (!PayloadReadHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied))
            continue;
        if (PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_address) == target_va)
            return slot;
    }
    return 0;
}

static void PayloadMgmtClearSlot(payload_u64 slot)
{
    if (PayloadIsKernelPointer(slot) && g_cached_hv_diag.vt_hook_slot_size <= 0x1000)
        PayloadZeroMemory((void*)slot, g_cached_hv_diag.vt_hook_slot_size);
}

static payload_u64 PayloadBridgeHandleVhInstall(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 packed = ctx->r9;
    bool auto_enable = (packed & 1ull) != 0;
    bool filter_by_process = (packed & 2ull) != 0;
    payload_u64 type = (packed >> 8) & 0xFFull;
    payload_u64 dispatch_mode = (packed >> 16) & 0xFFull;
    payload_native_hook_install_result r = {};
    bool ok = PayloadPmoInstallLegacyHookNative(
        ctx->rcx,
        ctx->rdx,
        ctx->r8,
        type,
        filter_by_process,
        auto_enable,
        PayloadMgmtCurrentGuestCr3(),
        &r);
    if (ok && r.slot && g_cached_hv_diag.vt_hook_slot_off_data_dispatch_mode)
        PayloadWriteHostU8(r.slot + g_cached_hv_diag.vt_hook_slot_off_data_dispatch_mode,
                           (unsigned char)dispatch_mode);
    return PayloadBridgeCompleteHypercall(ctx, code, ok ? 1 : 0);
}

static payload_u64 PayloadBridgeHandleVhEnable(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 slot = PayloadMgmtFindSlotByAddress(ctx->rdx);
    if (!slot)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    if (g_cached_hv_diag.vt_hook_slot_off_data_is_enable)
        PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_is_enable, 1);
    payload_u64 hva = PayloadReadHostU64(slot + PAYLOAD_VT_HOOK_OFF_FAKE_MEM_HVA);
    if (!hva)
    {
        payload_u64 fake_gva = PayloadReadHostU64(slot + PAYLOAD_VT_HOOK_DATA_OFF_FAKE_MEMORY);
        hva = PayloadMgmtGuestVaToHva(fake_gva);
        PayloadWriteHostU64(slot + PAYLOAD_VT_HOOK_OFF_FAKE_MEM_HVA, hva);
    }
    if (hva)
        PayloadEhApplyEnableTransition(hva);
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleVhDisable(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 slot = PayloadMgmtFindSlotByAddress(ctx->rdx);
    if (!slot)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);
    if (g_cached_hv_diag.vt_hook_slot_off_data_is_enable)
        PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_is_enable, 0);
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleVhRemove(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 slot = PayloadMgmtFindSlotByAddress(ctx->rdx);
    if (!slot)
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    payload_u64 target = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_address);
    payload_u64 process = g_cached_hv_diag.vt_hook_slot_off_data_process
        ? PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_process)
        : ctx->rcx;
    payload_u64 entry = PayloadMgmtEhFindEntryByProcessVa(process, target);
    payload_u64 orig = 0;
    bool was_active = entry ? PayloadMgmtEhReleaseCurrent(entry, true, &orig) : false;
    if (was_active && orig)
        PayloadMgmtNativeRemoveEptHookForVcpu(PayloadCurrentVcpuPtr(), orig);
    PayloadPmoFreeTrampoline(PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_trampoline_va));
    PayloadMgmtClearSlot(slot);
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadBridgeHandleVhUninit(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 idx = PayloadCurrentVcpuIndex();
    payload_u64 vc = g_cached_hv_diag.vcpu_count;
    if (vc > 64) vc = 64;
    payload_u64 full = vc >= 64 ? ~0ull : ((1ull << vc) - 1ull);
    if (!g_payload_vh_uninit_bitmap && full)
        _InterlockedCompareExchange64((volatile LONG64*)&g_payload_vh_uninit_bitmap, (LONG64)full, 0);

    if (PayloadMgmtSlotTableReady())
    {
        payload_u64 count = g_cached_hv_diag.vt_hook_slot_count;
        if (count > 64) count = 64;
        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_u64 slot = g_cached_hv_diag.vt_hook_table_ptr + i * g_cached_hv_diag.vt_hook_slot_size;
            if (!PayloadReadHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied))
                continue;
            payload_u64 target = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_address);
            payload_u64 process = g_cached_hv_diag.vt_hook_slot_off_data_process
                ? PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_process)
                : 0;
            payload_u64 entry = PayloadMgmtEhFindEntryByProcessVa(process, target);
            payload_u64 orig = 0;
            bool was_active = entry ? PayloadMgmtEhReleaseCurrent(entry, true, &orig) : false;
            if (was_active && orig)
                PayloadMgmtNativeRemoveEptHookForVcpu(PayloadCurrentVcpuPtr(), orig);
        }
    }

    payload_u64 remaining = 0;
    if (idx < 64)
        remaining = _InterlockedAnd64((volatile LONG64*)&g_payload_vh_uninit_bitmap,
                                      ~(LONG64)(1ull << idx)) & ~(1ull << idx);
    if (remaining == 0 && PayloadMgmtSlotTableReady())
    {
        payload_u64 count = g_cached_hv_diag.vt_hook_slot_count;
        if (count > 64) count = 64;
        for (payload_u64 i = 0; i < count; ++i)
            PayloadMgmtClearSlot(g_cached_hv_diag.vt_hook_table_ptr + i * g_cached_hv_diag.vt_hook_slot_size);
    }
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}

static payload_u64 PayloadMgmtFindBlank(payload_u64 start, payload_u64 max_scan, payload_u64 cr3)
{
    payload_u64 scanned = 0;
    if (!PayloadMgmtScratchLock())
        return 0;
    while (scanned < max_scan)
    {
        payload_u64 va = start + scanned;
        payload_u64 to_read = PayloadMinU64(PAGE_SIZE, max_scan - scanned);
        payload_u64 off = va & 0xFFFull;
        if (off + to_read > PAGE_SIZE)
            to_read = PAGE_SIZE - off;
        if (to_read < 4 || !PayloadPmoReadGuestBufferCr3(cr3, va, g_payload_mgmt_scratch, to_read))
        {
            scanned += PAGE_SIZE - off;
            continue;
        }
        for (payload_u64 i = 0; i + 3 < to_read; ++i)
        {
            if (g_payload_mgmt_scratch[i] == 0xCC &&
                g_payload_mgmt_scratch[i + 1] == 0xCC &&
                g_payload_mgmt_scratch[i + 2] == 0xCC &&
                g_payload_mgmt_scratch[i + 3] == 0xCC)
            {
                PayloadMgmtScratchUnlock();
                return va + i + 1;
            }
        }
        scanned += to_read;
    }
    PayloadMgmtScratchUnlock();
    return 0;
}

static payload_u64 PayloadMgmtFindBlankPage(payload_u64 start, payload_u64 max_scan, payload_u64 cr3)
{
    payload_u64 va = (start + 0xFFFull) & ~0xFFFull;
    payload_u64 end = start + max_scan;
    if (!PayloadMgmtScratchLock())
        return 0;
    while (va + PAGE_SIZE <= end)
    {
        if (PayloadPmoReadGuestBufferCr3(cr3, va, g_payload_mgmt_scratch, PAGE_SIZE))
        {
            bool all_cc = true;
            for (payload_u64 i = 0; i < PAGE_SIZE; ++i)
            {
                if (g_payload_mgmt_scratch[i] != 0xCC)
                {
                    all_cc = false;
                    break;
                }
            }
            if (all_cc)
            {
                PayloadMgmtScratchUnlock();
                return va;
            }
        }
        va += PAGE_SIZE;
    }
    PayloadMgmtScratchUnlock();
    return 0;
}

static payload_u64 PayloadBridgeHandleVhFindBlank(payload_guest_context* ctx, payload_u64 code, bool page)
{
    payload_u64 cr3 = PayloadPmoReadProcessCr3(ctx->rcx);
    payload_u64 result = 0;
    if (cr3)
        result = page
            ? PayloadMgmtFindBlankPage(ctx->rdx, ctx->r8, cr3)
            : PayloadMgmtFindBlank(ctx->rdx, ctx->r8, cr3);
    return PayloadBridgeCompleteHypercall(ctx, code, result);
}

static bool PayloadMgmtTrampPoolLock(payload_u64 pool)
{
    for (payload_u64 spin = 0; spin < 0x100000ull; ++spin)
    {
        if (_InterlockedCompareExchange((volatile LONG*)pool, 1, 0) == 0)
            return true;
        _mm_pause();
    }
    return false;
}

static void PayloadMgmtTrampPoolUnlock(payload_u64 pool)
{
    *(volatile LONG*)pool = 0;
}

static payload_u64 PayloadBridgeHandleVhTrampAddPage(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 pool = PayloadDiagTrampPoolBase();
    bool is_kernel = ctx->r10 != 0;
    if (!PayloadIsKernelPointer(pool) || !ctx->rcx || !ctx->rdx || !ctx->r8 || !ctx->r9 ||
        !PayloadHostPhysicalRangeMapped(ctx->rcx << 12, PAGE_SIZE) ||
        !PayloadHostPhysicalRangeMapped(ctx->rdx << 12, PAGE_SIZE) ||
        !PayloadMgmtTrampPoolLock(pool))
    {
        return PayloadBridgeCompleteHypercall(ctx, code, ~0ull);
    }

    payload_u64 count_off = is_kernel ? PAYLOAD_TRAMP_POOL_KERNEL_PAGE_COUNT_OFF : PAYLOAD_TRAMP_POOL_USER_PAGE_COUNT_OFF;
    payload_u64 pages_base = pool + (is_kernel ? PAYLOAD_TRAMP_POOL_KERNEL_PAGES_OFF : PAYLOAD_TRAMP_POOL_USER_PAGES_OFF);
    unsigned int count = PayloadReadHostU32(pool + count_off);
    if (count >= PAYLOAD_TRAMP_MAX_PAGES)
    {
        PayloadMgmtTrampPoolUnlock(pool);
        return PayloadBridgeCompleteHypercall(ctx, code, ~0ull);
    }
    payload_u64 idx = count;
        *(volatile unsigned int*)(pool + count_off) = count + 1;
    payload_u64 page_rec = pages_base + idx * PAYLOAD_TRAMP_PAGE_SIZE;
    PayloadWriteHostU64(page_rec + PAYLOAD_TRAMP_PAGE_OFF_GUEST_PAGE, ctx->r8);
    PayloadWriteHostU64(page_rec + PAYLOAD_TRAMP_PAGE_OFF_ORIG_PFN, ctx->rcx);
    PayloadWriteHostU64(page_rec + PAYLOAD_TRAMP_PAGE_OFF_EXEC_PFN, ctx->rdx);
    PayloadWriteHostU64(page_rec + PAYLOAD_TRAMP_PAGE_OFF_EXEC_HVA, ctx->r9);
    PayloadMgmtTrampPoolUnlock(pool);

    payload_u64 orig_pa = ctx->rcx << 12;
    payload_u64 exec_pa = ctx->rdx << 12;
    PayloadCopyMemory((void*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + exec_pa),
                      (void*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + orig_pa),
                      PAGE_SIZE);

    payload_u64 pending = 0;
    PayloadEptQueueNativeInstallAllEx(ctx->rcx, ctx->rdx, false, 0, &pending,
                                      PAYLOAD_NATIVE_EPT_POLICY_IMMEDIATE_ALL);
    PayloadEptInveptAll();
    return PayloadBridgeCompleteHypercall(ctx, code, idx);
}

static payload_u64 PayloadBridgeHandleVhTrampAddSlot(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 pool = PayloadDiagTrampPoolBase();
    bool is_kernel = ctx->r9 != 0;
    if (!PayloadIsKernelPointer(pool) || !PayloadMgmtTrampPoolLock(pool))
        return PayloadBridgeCompleteHypercall(ctx, code, 0);

    payload_u64 slot_count_off = is_kernel ? PAYLOAD_TRAMP_POOL_KERNEL_SLOT_COUNT_OFF : PAYLOAD_TRAMP_POOL_USER_SLOT_COUNT_OFF;
    payload_u64 page_count_off = is_kernel ? PAYLOAD_TRAMP_POOL_KERNEL_PAGE_COUNT_OFF : PAYLOAD_TRAMP_POOL_USER_PAGE_COUNT_OFF;
    payload_u64 slots_base = pool + (is_kernel ? PAYLOAD_TRAMP_POOL_KERNEL_SLOTS_OFF : PAYLOAD_TRAMP_POOL_USER_SLOTS_OFF);
    unsigned int slot_count = PayloadReadHostU32(pool + slot_count_off);
    unsigned int page_count = PayloadReadHostU32(pool + page_count_off);
    bool ok = false;
    if (slot_count < PAYLOAD_TRAMP_MAX_SLOTS &&
        ctx->rcx < page_count &&
        ctx->rdx < PAGE_SIZE &&
        ctx->r8 >= 8 &&
        ctx->r8 <= 255 &&
        ctx->rdx + ctx->r8 <= PAGE_SIZE)
    {
        payload_u64 slot = slots_base + (payload_u64)slot_count * PAYLOAD_TRAMP_SLOT_SIZE;
        *(volatile unsigned int*)(pool + slot_count_off) = slot_count + 1;
        PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TRAMP_VA, 0);
        PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_BP_RIP, 0);
        PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TARGET_RESUME, 0);
        *(volatile unsigned short*)(slot + 0x18ull) = (unsigned short)ctx->rcx;
        *(volatile unsigned short*)(slot + 0x1Aull) = (unsigned short)ctx->rdx;
        PayloadWriteHostU8(slot + 0x1Cull, (unsigned char)ctx->r8);
        PayloadWriteHostU8(slot + PAYLOAD_TRAMP_SLOT_OFF_OCCUPIED, 0);
        ok = true;
    }
    PayloadMgmtTrampPoolUnlock(pool);
    return PayloadBridgeCompleteHypercall(ctx, code, ok ? 1 : 0);
}

static payload_u64 PayloadBridgeHandleVhTrampSetReady(payload_guest_context* ctx, payload_u64 code)
{
    payload_u64 pool = PayloadDiagTrampPoolBase();
    bool is_kernel = ctx->rcx != 0;
    if (PayloadIsKernelPointer(pool) && PayloadMgmtTrampPoolLock(pool))
    {
        PayloadWriteHostU8(pool + (is_kernel ? PAYLOAD_TRAMP_POOL_KERNEL_READY_OFF : PAYLOAD_TRAMP_POOL_USER_READY_OFF), 1);
        PayloadMgmtTrampPoolUnlock(pool);
    }
    return PayloadBridgeCompleteHypercall(ctx, code, 1);
}
