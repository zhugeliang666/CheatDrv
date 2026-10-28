// 从 ept_trampoline.inl 拆分出来的模块：trampoline/pte_helpers.inl。
// 通过包装头文件包含；确保位于同一编译单元中。

static void PayloadEptInveptAll();

static payload_u64 PayloadEptEntryWithPfnPerms(payload_u64 entry,
                                               payload_u64 pfn,
                                               bool read,
                                               bool write,
                                               bool execute)
{
    payload_u64 out = entry;
    out &= ~PAYLOAD_EPT_PFN_MASK;
    out |= (pfn << 12) & PAYLOAD_EPT_PFN_MASK;
    out &= ~PAYLOAD_EPT_PERM_MASK;
    out |= (read ? 1ull : 0ull) |
           (write ? 2ull : 0ull) |
           (execute ? 4ull : 0ull);
    if ((out & 0x2ull) && !(out & 0x1ull))
        out &= ~0x2ull;
    return out;
}

static payload_u64 PayloadEptPteFromSplitPde(payload_u64 pde, payload_u64 pfn)
{
    // 对齐底层 split_ept_pde() 逻辑：先清零子 PTE，然后仅从 2MB PDE 中复制明确指定的叶子位。
    // 此处保持相同掩码，避免将大页 PDE 直接作为通用模板，防止带入底层已丢弃的保留位或叶子特定属性位。
    static constexpr payload_u64 kCopiedLeafBits =
        0x7ull |                    // R/W/X
        (0x7ull << 3) |             // fallback memory type, overwritten below when MTRR snapshot is available
        (1ull << 6) |               // ignore_pat
        (1ull << 8) |               // accessed
        (1ull << 9) |               // dirty
        (1ull << 10) |              // user_mode_execute
        (1ull << 57) |              // verify_guest_paging
        (1ull << 58) |              // paging_write_access
        (1ull << 60) |              // supervisor_shadow_stack
        (1ull << 63);               // suppress_ve

    payload_u64 pte = pde & kCopiedLeafBits;
    pte &= ~PAYLOAD_EPT_LARGE_PAGE;
    pte &= ~PAYLOAD_EPT_PFN_MASK;
    pte |= (pfn << 12) & PAYLOAD_EPT_PFN_MASK;
    return pte;
}

static bool PayloadEptLocatePte(payload_u64 gpa, payload_u64* pte_pa, payload_u64* pte_value)
{
    if (!pte_pa || !pte_value)
        return false;

    payload_u64 eptp = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_EPT_POINTER, &eptp))
        return false;

    payload_u64 pml4_pa = eptp & PAYLOAD_EPT_PFN_MASK;
    payload_u64 pml4_idx = (gpa >> 39) & 0x1FFull;
    payload_u64 pdpt_idx = (gpa >> 30) & 0x1FFull;
    payload_u64 pd_idx = (gpa >> 21) & 0x1FFull;
    payload_u64 pt_idx = (gpa >> 12) & 0x1FFull;

    payload_u64 pml4e = 0;
    if (!PayloadReadPhys64(pml4_pa + pml4_idx * sizeof(payload_u64), &pml4e) ||
        !(pml4e & PAYLOAD_EPT_PERM_MASK))
    {
        return false;
    }

    payload_u64 pdpt_pa = pml4e & PAYLOAD_EPT_PFN_MASK;
    payload_u64 pdpte = 0;
    if (!PayloadReadPhys64(pdpt_pa + pdpt_idx * sizeof(payload_u64), &pdpte) ||
        !(pdpte & PAYLOAD_EPT_PERM_MASK) ||
        (pdpte & PAYLOAD_EPT_LARGE_PAGE))
    {
        return false;
    }

    payload_u64 pd_pa = pdpte & PAYLOAD_EPT_PFN_MASK;
    payload_u64 pde = 0;
    if (!PayloadReadPhys64(pd_pa + pd_idx * sizeof(payload_u64), &pde) ||
        !(pde & PAYLOAD_EPT_PERM_MASK) ||
        (pde & PAYLOAD_EPT_LARGE_PAGE))
    {
        return false;
    }

    payload_u64 pt_pa = pde & PAYLOAD_EPT_PFN_MASK;
    payload_u64 leaf_pa = pt_pa + pt_idx * sizeof(payload_u64);
    payload_u64 leaf = 0;
    if (!PayloadReadPhys64(leaf_pa, &leaf) || !(leaf & PAYLOAD_EPT_PERM_MASK))
        return false;

    *pte_pa = leaf_pa;
    *pte_value = leaf;
    return true;
}

static bool PayloadEptLocateLeaf(payload_u64 gpa,
                                 payload_u64* leaf_pa,
                                 payload_u64* leaf_value,
                                 bool* large_leaf)
{
    if (!leaf_pa || !leaf_value)
        return false;

    payload_u64 eptp = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_EPT_POINTER, &eptp))
        return false;

    payload_u64 pml4_pa = eptp & PAYLOAD_EPT_PFN_MASK;
    payload_u64 pml4_idx = (gpa >> 39) & 0x1FFull;
    payload_u64 pdpt_idx = (gpa >> 30) & 0x1FFull;
    payload_u64 pd_idx = (gpa >> 21) & 0x1FFull;
    payload_u64 pt_idx = (gpa >> 12) & 0x1FFull;

    payload_u64 pml4e = 0;
    if (!PayloadReadPhys64(pml4_pa + pml4_idx * sizeof(payload_u64), &pml4e) ||
        !(pml4e & PAYLOAD_EPT_PERM_MASK))
    {
        return false;
    }

    payload_u64 pdpt_pa = pml4e & PAYLOAD_EPT_PFN_MASK;
    payload_u64 pdpte_pa = pdpt_pa + pdpt_idx * sizeof(payload_u64);
    payload_u64 pdpte = 0;
    if (!PayloadReadPhys64(pdpte_pa, &pdpte) ||
        !(pdpte & PAYLOAD_EPT_PERM_MASK))
    {
        return false;
    }

    if (pdpte & PAYLOAD_EPT_LARGE_PAGE)
    {
        *leaf_pa = pdpte_pa;
        *leaf_value = pdpte;
        if (large_leaf) *large_leaf = true;
        return true;
    }

    payload_u64 pd_pa = pdpte & PAYLOAD_EPT_PFN_MASK;
    payload_u64 pde_pa = pd_pa + pd_idx * sizeof(payload_u64);
    payload_u64 pde = 0;
    if (!PayloadReadPhys64(pde_pa, &pde) ||
        !(pde & PAYLOAD_EPT_PERM_MASK))
    {
        return false;
    }

    if (pde & PAYLOAD_EPT_LARGE_PAGE)
    {
        *leaf_pa = pde_pa;
        *leaf_value = pde;
        if (large_leaf) *large_leaf = true;
        return true;
    }

    payload_u64 pt_pa = pde & PAYLOAD_EPT_PFN_MASK;
    payload_u64 pte_pa_local = pt_pa + pt_idx * sizeof(payload_u64);
    payload_u64 pte = 0;
    if (!PayloadReadPhys64(pte_pa_local, &pte) || !(pte & PAYLOAD_EPT_PERM_MASK))
        return false;

    *leaf_pa = pte_pa_local;
    *leaf_value = pte;
    if (large_leaf) *large_leaf = false;
    return true;
}

static payload_u64 PayloadEptEntryWithMemoryType(payload_u64 entry, payload_u64 memory_type)
{
    entry &= ~(0x7ull << 3);
    entry |= (memory_type & 0x7ull) << 3;
    return entry;
}

static bool PayloadEptMemoryTypeValid(payload_u64 memory_type)
{
    switch (memory_type & 0x7ull)
    {
    case 0: // UC
    case 1: // WC
    case 4: // WT
    case 5: // WP
    case 6: // WB
        return true;
    default:
        return false;
    }
}

static payload_u64 PayloadEptSanitizeEntry(payload_u64 entry, bool make_permissive)
{
    payload_u64 out = entry;
    payload_u64 mem_type = (out >> 3) & 0x7ull;
    if (!PayloadEptMemoryTypeValid(mem_type))
        out = PayloadEptEntryWithMemoryType(out, 6); // WB

    if (make_permissive)
        out = PayloadEptEntryWithPfnPerms(out, (out & PAYLOAD_EPT_PFN_MASK) >> 12, true, true, true);
    else if ((out & 0x2ull) && !(out & 0x1ull))
        out &= ~0x2ull;

    return out;
}

static bool PayloadEptSanitizeLeafForGpa(payload_u64 gpa, bool make_permissive)
{
    payload_u64 leaf_pa = 0;
    payload_u64 before = 0;
    bool large_leaf = false;
    if (!PayloadEptLocateLeaf(gpa, &leaf_pa, &before, &large_leaf))
        return false;

    UNREFERENCED_PARAMETER(large_leaf);
    payload_u64 after = PayloadEptSanitizeEntry(before, make_permissive);
    if (after == before)
        after = PayloadEptEntryWithPfnPerms(after, (after & PAYLOAD_EPT_PFN_MASK) >> 12, true, true, true);

    if (!PayloadWritePhys64(leaf_pa, after))
        return false;

    PayloadEptInveptAll();
    g_payload_ept_tramp_last_pte_pa = leaf_pa;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = after;
    _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_generic_match_count);
    _InterlockedIncrement64((volatile LONG64*)&g_payload_ept_tramp_handle_count);
    return true;
}

static void PayloadEptInveptAll()
{
    __declspec(align(16)) payload_u64 descriptor[2] = {};
    PayloadInvept(2, descriptor);
}

static bool PayloadEptIsMtrrMsr(payload_u64 msr)
{
    msr &= 0xFFFFFFFFull;
    return msr == PAYLOAD_IA32_MTRR_DEF_TYPE ||
           msr == PAYLOAD_IA32_MTRR_FIX64K_00000 ||
           msr == PAYLOAD_IA32_MTRR_FIX16K_80000 ||
           msr == PAYLOAD_IA32_MTRR_FIX16K_A0000 ||
           (msr >= PAYLOAD_IA32_MTRR_FIX4K_C0000 && msr <= PAYLOAD_IA32_MTRR_FIX4K_F8000) ||
           (msr >= PAYLOAD_IA32_MTRR_PHYSBASE0 && msr <= PAYLOAD_IA32_MTRR_PHYSBASE0 + 511ull);
}

struct payload_mtrr_range
{
    payload_u64 begin;
    payload_u64 end;
    payload_u64 type;
    payload_u64 fixed;
};

struct payload_mtrr_snapshot
{
    payload_u64 default_type;
    payload_u64 count;
    payload_mtrr_range ranges[120];
};

static bool PayloadEptReadMsr(payload_u64 msr, payload_u64* value)
{
    if (!value)
        return false;

    payload_host_exception_info e = {};
    payload_u64 v = PayloadRdmsrSafe(&e, (unsigned long)(msr & 0xFFFFFFFFull));
    if (e.exception_occurred)
        return false;
    *value = v;
    return true;
}

static bool PayloadEptAddMtrrRange(payload_mtrr_snapshot* snap,
                                   payload_u64 begin,
                                   payload_u64 end,
                                   payload_u64 type,
                                   payload_u64 fixed)
{
    if (!snap || snap->count >= 120 || end < begin)
        return false;

    auto& r = snap->ranges[snap->count++];
    r.begin = begin;
    r.end = end;
    r.type = type & 0xFFull;
    r.fixed = fixed ? 1ull : 0ull;
    return true;
}

static bool PayloadEptLoadMtrrSnapshot(payload_mtrr_snapshot* snap)
{
    if (!snap)
        return false;

    PayloadZeroMemory(snap, sizeof(*snap));
    payload_u64 cap = 0;
    payload_u64 def_type = 0;
    if (!PayloadEptReadMsr(PAYLOAD_IA32_MTRR_CAPABILITIES, &cap) ||
        !PayloadEptReadMsr(PAYLOAD_IA32_MTRR_DEF_TYPE, &def_type))
    {
        snap->default_type = 0; // UC
        return false;
    }

    bool mtrr_enabled = (def_type & (1ull << 11)) != 0;
    bool fixed_enabled = (def_type & (1ull << 10)) != 0;
    snap->default_type = mtrr_enabled ? (def_type & 0xFFull) : 0ull;
    if (!mtrr_enabled)
        return true;

    if ((cap & (1ull << 8)) && fixed_enabled)
    {
        payload_u64 value = 0;
        if (PayloadEptReadMsr(PAYLOAD_IA32_MTRR_FIX64K_00000, &value))
        {
            for (payload_u64 i = 0; i < 8; ++i)
                PayloadEptAddMtrrRange(snap, i * 0x10000ull, i * 0x10000ull + 0xFFFFull, (value >> (i * 8)) & 0xFFull, 1);
        }

        for (payload_u64 m = 0; m < 2; ++m)
        {
            if (PayloadEptReadMsr(PAYLOAD_IA32_MTRR_FIX16K_80000 + m, &value))
            {
                payload_u64 base = 0x80000ull + m * 0x20000ull;
                for (payload_u64 i = 0; i < 8; ++i)
                    PayloadEptAddMtrrRange(snap, base + i * 0x4000ull, base + i * 0x4000ull + 0x3FFFull, (value >> (i * 8)) & 0xFFull, 1);
            }
        }

        for (payload_u64 m = 0; m < 8; ++m)
        {
            if (PayloadEptReadMsr(PAYLOAD_IA32_MTRR_FIX4K_C0000 + m, &value))
            {
                payload_u64 base = 0xC0000ull + m * 0x8000ull;
                for (payload_u64 i = 0; i < 8; ++i)
                    PayloadEptAddMtrrRange(snap, base + i * 0x1000ull, base + i * 0x1000ull + 0x0FFFull, (value >> (i * 8)) & 0xFFull, 1);
            }
        }
    }

    payload_u64 variable_count = cap & 0xFFull;
    if (variable_count > 255)
        variable_count = 255;

    payload_u64 max_phys_bits = 48;
    int regs[4] = {};
    __cpuidex(regs, 0x80000000, 0);
    if ((payload_u64)(unsigned int)regs[0] >= 0x80000008ull)
    {
        __cpuidex(regs, 0x80000008, 0);
        payload_u64 bits = (payload_u64)((unsigned int)regs[0] & 0xFFu);
        if (bits >= 36 && bits <= 52)
            max_phys_bits = bits;
    }
    payload_u64 phys_mask = max_phys_bits >= 52
        ? 0x000FFFFFFFFFF000ull
        : (((1ull << max_phys_bits) - 1ull) & 0x000FFFFFFFFFF000ull);

    for (payload_u64 i = 0; i < variable_count && snap->count < 120; ++i)
    {
        payload_u64 base_msr = 0;
        payload_u64 mask_msr = 0;
        if (!PayloadEptReadMsr(PAYLOAD_IA32_MTRR_PHYSBASE0 + i * 2ull, &base_msr) ||
            !PayloadEptReadMsr(PAYLOAD_IA32_MTRR_PHYSMASK0 + i * 2ull, &mask_msr) ||
            !(mask_msr & (1ull << 11)))
        {
            continue;
        }

        payload_u64 base = base_msr & phys_mask;
        payload_u64 mask = mask_msr & phys_mask;
        payload_u64 size_mask = (~mask) & phys_mask;
        payload_u64 size = size_mask + 0x1000ull;
        if (!size)
            continue;

        PayloadEptAddMtrrRange(snap, base, base + size - 1ull, base_msr & 0xFFull, 0);
    }

    return true;
}

static payload_u64 PayloadEptCalcMtrrType(const payload_mtrr_snapshot& snap,
                                          payload_u64 pfn,
                                          bool large_page)
{
    payload_u64 start = large_page ? pfn * 0x200000ull : pfn * PAGE_SIZE;
    payload_u64 end = large_page ? start + 0x1FFFFFull : start + PAGE_SIZE - 1ull;
    payload_u64 type = snap.default_type;

    for (payload_u64 i = 0; i < snap.count; ++i)
    {
        const auto& r = snap.ranges[i];
        if (start >= r.begin && end <= r.end)
        {
            type = r.type;
            if (r.fixed || r.type == 0)
                break;
        }
    }

    return PayloadEptMemoryTypeValid(type) ? type : 6ull;
}

static bool PayloadEptSetMemoryTypeForVcpu(payload_u64 vcpu_ptr,
                                           bool force_uc,
                                           const payload_mtrr_snapshot* snap)
{
    if (!PayloadIsKernelPointer(vcpu_ptr) || !g_cached_hv_diag.vcpu_off_ept)
        return false;

    payload_u64 ept_base = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept;
    payload_u64 pds_base = ept_base + 0x2000ull;
    if (!PayloadIsKernelPointer(pds_base))
        return false;

    for (payload_u64 pdpt = 0; pdpt < 512ull; ++pdpt)
    {
        for (payload_u64 pd = 0; pd < 512ull; ++pd)
        {
            payload_u64 pde_va = pds_base + ((pdpt * 512ull) + pd) * sizeof(payload_u64);
            payload_u64 pde = PayloadReadHostU64(pde_va);
            if (!(pde & PAYLOAD_EPT_PERM_MASK))
                continue;

            if (pde & PAYLOAD_EPT_LARGE_PAGE)
            {
                payload_u64 pfn = (pde & PAYLOAD_EPT_PFN_MASK) >> 12;
                payload_u64 type = force_uc ? 0ull : (snap ? PayloadEptCalcMtrrType(*snap, pfn, true) : 6ull);
                PayloadWriteHostU64(pde_va, PayloadEptEntryWithMemoryType(pde, type));
                continue;
            }

            payload_u64 pt_pa = pde & PAYLOAD_EPT_PFN_MASK;
            if (!PayloadHostPhysicalRangeMapped(pt_pa, PAGE_SIZE))
                continue;

            payload_u64 pt_va = PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pt_pa;
            for (payload_u64 i = 0; i < 512ull; ++i)
            {
                payload_u64 pte_va = pt_va + i * sizeof(payload_u64);
                payload_u64 pte = PayloadReadHostU64(pte_va);
                if (!(pte & PAYLOAD_EPT_PERM_MASK))
                    continue;

                payload_u64 pfn = (pte & PAYLOAD_EPT_PFN_MASK) >> 12;
                payload_u64 type = force_uc ? 0ull : (snap ? PayloadEptCalcMtrrType(*snap, pfn, false) : 6ull);
                PayloadWriteHostU64(pte_va, PayloadEptEntryWithMemoryType(pte, type));
            }
        }
    }

    PayloadEptInveptAll();
    return true;
}

static bool PayloadEptRefreshMemoryTypeForCurrentVcpu(bool force_uc)
{
    payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
    if (!PayloadIsKernelPointer(vcpu_ptr))
        return false;

    payload_mtrr_snapshot snap = {};
    payload_mtrr_snapshot* snap_ptr = nullptr;
    if (!force_uc)
    {
        PayloadEptLoadMtrrSnapshot(&snap);
        snap_ptr = &snap;
    }

    return PayloadEptSetMemoryTypeForVcpu(vcpu_ptr, force_uc, snap_ptr);
}

enum payload_native_ept_install_reason : payload_u64
{
    PAYLOAD_NATIVE_EPT_REASON_NONE = 0,
    PAYLOAD_NATIVE_EPT_REASON_BAD_ARGS = 1,
    PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL = 2,
    PAYLOAD_NATIVE_EPT_REASON_PTE_MISMATCH = 3,
    PAYLOAD_NATIVE_EPT_REASON_NO_ACTIVE_OFFSET = 4,
    PAYLOAD_NATIVE_EPT_REASON_NO_FREE_NODE = 5,
    PAYLOAD_NATIVE_EPT_REASON_PDE_LARGE_PAGE = 6,
    PAYLOAD_NATIVE_EPT_REASON_PDE_POINTS_PT = 7,
    PAYLOAD_NATIVE_EPT_REASON_PDE_NO_PERM = 8,
    PAYLOAD_NATIVE_EPT_REASON_SPLIT_FILL_SUCCESS = 9,
    PAYLOAD_NATIVE_EPT_REASON_SPLIT_NOT_LARGE = 10,
    PAYLOAD_NATIVE_EPT_REASON_SPLIT_RESERVE_SUCCESS = 11,
    PAYLOAD_NATIVE_EPT_REASON_SPLIT_PUBLISH_SUCCESS = 12,
    PAYLOAD_NATIVE_EPT_REASON_SPLIT_PUBLISH_INVEPT_SUCCESS = 13,
    PAYLOAD_NATIVE_EPT_REASON_SPLIT_LEAF_LOCATE_SUCCESS = 14,
    PAYLOAD_NATIVE_EPT_REASON_SPLIT_LEAF_WRITE_SAME_SUCCESS = 15,
    PAYLOAD_NATIVE_EPT_REASON_SPLIT_LEAF_WRITE_SAME_INVEPT_SUCCESS = 16,
    PAYLOAD_NATIVE_EPT_REASON_INSTALL_CURRENT_SUCCESS = 17,
    PAYLOAD_NATIVE_EPT_REASON_SUCCESS = 0x100,
};

enum payload_native_ept_install_policy : payload_u64
{
    PAYLOAD_NATIVE_EPT_POLICY_DEFERRED = 0,
    PAYLOAD_NATIVE_EPT_POLICY_IMMEDIATE_ALL = 1,
    PAYLOAD_NATIVE_EPT_POLICY_QUEUE_ONLY = 2,
    PAYLOAD_NATIVE_EPT_POLICY_WRITE_SAME_CURRENT = 3,
    PAYLOAD_NATIVE_EPT_POLICY_LOCATE_ONLY_NO_SPLIT = 4,
    PAYLOAD_NATIVE_EPT_POLICY_PDE_ONLY = 5,
    PAYLOAD_NATIVE_EPT_POLICY_SPLIT_FILL_ONLY = 6,
    PAYLOAD_NATIVE_EPT_POLICY_SPLIT_RESERVE_ONLY = 7,
    PAYLOAD_NATIVE_EPT_POLICY_SPLIT_PUBLISH_NO_INVEPT = 8,
    PAYLOAD_NATIVE_EPT_POLICY_SPLIT_PUBLISH_INVEPT = 9,
    PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_LOCATE_ONLY = 10,
    PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_WRITE_SAME_ONLY = 11,
    PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_WRITE_SAME_INVEPT_ONLY = 12,
    PAYLOAD_NATIVE_EPT_POLICY_INSTALL_CURRENT_ONLY = 13,
    PAYLOAD_NATIVE_EPT_POLICY_INSTALL_CURRENT_PLUS_ONE = 14,
};

static void PayloadEptNativeSetInstallDiag(payload_u64 reason,
                                           payload_u64 vcpu_index,
                                           payload_u64 vcpu_ptr,
                                           payload_u64 orig_pfn,
                                           payload_u64 exec_pfn,
                                           payload_u64 pte_va,
                                           payload_u64 pte_before,
                                           payload_u64 node)
{
    g_payload_getbuffer_install_native_reason = reason;
    g_payload_getbuffer_install_native_vcpu = vcpu_index;
    g_payload_getbuffer_install_native_vcpu_ptr = vcpu_ptr;
    g_payload_getbuffer_install_native_pte_va = pte_va;
    g_payload_getbuffer_install_native_pte_before = pte_before;
    g_payload_getbuffer_install_native_pte_pfn =
        (pte_before & PAYLOAD_EPT_PFN_MASK) >> 12;
    g_payload_getbuffer_install_orig_pfn = orig_pfn;
    g_payload_getbuffer_install_exec_pfn = exec_pfn;
    g_payload_getbuffer_install_native_node = node;

    payload_u64 used = 0;
    payload_u64 free_count = g_cached_hv_diag.ept_free_page_count ?
        g_cached_hv_diag.ept_free_page_count : 0x1000ull;
    if (PayloadIsKernelPointer(vcpu_ptr) &&
        g_cached_hv_diag.vcpu_off_ept_num_used_free_pages &&
        PayloadIsKernelPointer(vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_num_used_free_pages))
    {
        used = PayloadReadHostU64(vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_num_used_free_pages);
    }
    g_payload_getbuffer_install_native_used = used;
    g_payload_getbuffer_install_native_free = free_count;
}

static bool PayloadEptSplitPdeForVcpu(payload_u64 vcpu_ptr, payload_u64 pde_va, payload_u64 pde)
{
    if (!PayloadIsKernelPointer(vcpu_ptr) ||
        !PayloadIsKernelPointer(pde_va) ||
        !g_cached_hv_diag.vcpu_off_ept_free_pages ||
        !g_cached_hv_diag.vcpu_off_ept_free_page_pfns ||
        !g_cached_hv_diag.vcpu_off_ept_num_used_free_pages)
    {
        return false;
    }

    payload_u64 free_count = g_cached_hv_diag.ept_free_page_count ?
        g_cached_hv_diag.ept_free_page_count : 0x1000ull;
    payload_u64 used_ptr = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_num_used_free_pages;
    payload_u64 used = PayloadReadHostU64(used_ptr);
    if (used >= free_count)
        return false;

    payload_u64 pt_va = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_free_pages + used * PAGE_SIZE;
    payload_u64 pt_pfn = PayloadReadHostU64(
        vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_free_page_pfns + used * sizeof(payload_u64));
    if (!PayloadIsKernelPointer(pt_va) || !pt_pfn)
        return false;

    payload_u64 base_pfn = (pde & PAYLOAD_EPT_PFN_MASK) >> 12;
    bool r = (pde & 0x1ull) != 0;
    bool w = (pde & 0x2ull) != 0;
    bool x = (pde & 0x4ull) != 0;
    payload_mtrr_snapshot snap = {};
    bool have_mtrr = PayloadEptLoadMtrrSnapshot(&snap);
    for (payload_u64 i = 0; i < 512; ++i)
    {
        payload_u64 pfn = base_pfn + i;
        payload_u64 pte = PayloadEptPteFromSplitPde(pde, pfn);
        pte = PayloadEptEntryWithPfnPerms(pte, pfn, r, w, x);
        if (have_mtrr)
            pte = PayloadEptEntryWithMemoryType(pte, PayloadEptCalcMtrrType(snap, pfn, false));
        PayloadWriteHostU64(pt_va + i * sizeof(payload_u64), pte);
    }

    PayloadWriteHostU64(used_ptr, used + 1);
    // 对齐底层行为：split_ept_pde() 将表项重新解释为 ept_pde，清零标志位，
    // 然后设置 R/W/X + user_mode_execute + PT PFN。严禁在非叶子 PDE 中保留仅属于大页叶子的内存类型位；
    // 否则在活动 PDE 发布的瞬间就会立即引发 EPT Misconfiguration 崩溃。
    payload_u64 new_pde = ((pt_pfn << 12) & PAYLOAD_EPT_PFN_MASK) | 0x407ull;
    PayloadWriteHostU64(pde_va, new_pde);
    return true;
}

static bool PayloadEptLocatePteForVcpu(payload_u64 vcpu_ptr,
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

    // vcpu_ept_data 布局：pml4(0x1000), pdpt(0x1000)，随后为 pds/pds_2mb。
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
    if (leaf_pa < pt_pa ||
        !PayloadHostPhysicalRangeMapped(leaf_pa, sizeof(payload_u64)))
    {
        return false;
    }

    payload_u64 leaf = PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + leaf_pa;
    payload_u64 entry = PayloadReadHostU64(leaf);
    if (!(entry & PAYLOAD_EPT_PERM_MASK))
        return false;

    if (pte_va) *pte_va = leaf;
    if (pte_value) *pte_value = entry;
    return true;
}

static payload_u64 PayloadEptVcpuPtrByIndex(payload_u64 index)
{
    if (!g_hv_diag_cache_ready ||
        !g_cached_hv_diag.vcpus ||
        !g_hv_diag_vcpu_stride ||
        index >= g_cached_hv_diag.vcpu_count ||
        index >= PAYLOAD_EPT_MAX_TRACKED_VCPUS)
    {
        return 0;
    }

    payload_u64 ptr = g_cached_hv_diag.vcpus + index * g_hv_diag_vcpu_stride;
    return PayloadIsKernelPointer(ptr) ? ptr : 0;
}

static bool PayloadEptNativeFindHookForVcpu(payload_u64 vcpu_ptr, payload_u64 orig_pfn)
{
    if (!PayloadIsKernelPointer(vcpu_ptr) || !orig_pfn)
        return false;

    payload_u64 active_head_off = PayloadDiagVcpuEptHookActiveOffset();
    if (!active_head_off)
        return false;
    payload_u64 node_next_off = 0;
    payload_u64 node_orig_off = 0;
    if (!PayloadDiagVcpuEptHookNodeLayout(&node_next_off, &node_orig_off, nullptr, nullptr))
        return false;

    payload_u64 node = PayloadReadHostU64(vcpu_ptr + active_head_off);
    for (payload_u64 i = 0; i < PAYLOAD_VCPU_EPT_HOOK_NODE_MAX && PayloadIsKernelPointer(node); ++i)
    {
        if (PayloadReadHostU32(node + node_orig_off) == orig_pfn)
            return true;
        payload_u64 next = PayloadReadHostU64(node + node_next_off);
        if (!next || next == node)
            break;
        node = next;
    }
    return false;
}

static bool PayloadEptNativeInstallForVcpu(payload_u64 vcpu_ptr,
                                           payload_u64 orig_pfn,
                                           payload_u64 exec_pfn,
                                           bool is_fake_page)
{
    payload_u64 vcpu_index = ~0ull;
    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.vcpus &&
        g_hv_diag_vcpu_stride &&
        PayloadIsKernelPointer(vcpu_ptr) &&
        vcpu_ptr >= g_cached_hv_diag.vcpus)
    {
        vcpu_index = (vcpu_ptr - g_cached_hv_diag.vcpus) / g_hv_diag_vcpu_stride;
    }

    if (!PayloadIsKernelPointer(vcpu_ptr) ||
        !orig_pfn ||
        !exec_pfn ||
        orig_pfn > 0xFFFFFFFFull ||
        exec_pfn > 0xFFFFFFFFull)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_BAD_ARGS,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }

    if (PayloadEptNativeFindHookForVcpu(vcpu_ptr, orig_pfn))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_SUCCESS,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return true;
    }

    payload_u64 active_head_off = PayloadDiagVcpuEptHookActiveOffset();
    if (!active_head_off)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_NO_ACTIVE_OFFSET,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }
    payload_u64 node_next_off = 0;
    payload_u64 node_orig_off = 0;
    payload_u64 node_exec_off = 0;
    payload_u64 node_is_fake_off = 0;
    if (!PayloadDiagVcpuEptHookNodeLayout(
            &node_next_off,
            &node_orig_off,
            &node_exec_off,
            &node_is_fake_off))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_NO_ACTIVE_OFFSET,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }

    payload_u64 active_field = vcpu_ptr + active_head_off;
    payload_u64 free_field = active_field + sizeof(payload_u64);
    payload_u64 node = PayloadReadHostU64(free_field);
    if (!PayloadIsKernelPointer(node))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_NO_FREE_NODE,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            node);
        return false;
    }

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (!PayloadEptLocatePteForVcpu(vcpu_ptr, orig_pfn << 12, true, &pte_va, &before))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    payload_u64 next_free = PayloadReadHostU64(node + node_next_off);
    payload_u64 old_head = PayloadReadHostU64(active_field);
    PayloadWriteHostU64(free_field, next_free);
    PayloadWriteHostU64(node + node_next_off, old_head);
    // 对齐底层行为：install_ept_hook() 在填充 orig/exec/is_fake 之前先将节点发布到 active_list_head。
    // 在此二分阶段严格保持该顺序；EPT PTE 仍仅在节点字段填充完毕后激活。
    PayloadWriteHostU64(active_field, node);
    *(volatile unsigned int*)(node + node_orig_off) =
        (unsigned int)orig_pfn;
    *(volatile unsigned int*)(node + node_exec_off) =
        (unsigned int)exec_pfn;
    PayloadWriteHostU8(node + node_is_fake_off, is_fake_page ? 1 : 0);

    payload_u64 after = is_fake_page ? (before & ~0x3ull) : (before & ~0x4ull);
    PayloadWriteHostU64(pte_va, after);
    PayloadEptInveptAll();

    g_payload_ept_last_hook_node = node;
    g_payload_ept_last_is_fake = is_fake_page ? 1ull : 0ull;
    g_payload_ept_tramp_last_pte_pa = pte_va;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = after;
    g_payload_ept_tramp_last_orig_pfn = orig_pfn;
    g_payload_ept_tramp_last_exec_pfn = exec_pfn;
    PayloadEptNativeSetInstallDiag(
        PAYLOAD_NATIVE_EPT_REASON_SUCCESS,
        vcpu_index,
        vcpu_ptr,
        orig_pfn,
        exec_pfn,
        pte_va,
        before,
        node);
    return true;
}

static bool PayloadEptNativeWriteSameForVcpu(payload_u64 vcpu_ptr,
                                             payload_u64 orig_pfn,
                                             payload_u64 exec_pfn)
{
    payload_u64 vcpu_index = ~0ull;
    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.vcpus &&
        g_hv_diag_vcpu_stride &&
        PayloadIsKernelPointer(vcpu_ptr) &&
        vcpu_ptr >= g_cached_hv_diag.vcpus)
    {
        vcpu_index = (vcpu_ptr - g_cached_hv_diag.vcpus) / g_hv_diag_vcpu_stride;
    }

    if (!PayloadIsKernelPointer(vcpu_ptr) ||
        !orig_pfn ||
        !exec_pfn ||
        orig_pfn > 0xFFFFFFFFull ||
        exec_pfn > 0xFFFFFFFFull)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_BAD_ARGS,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (!PayloadEptLocatePteForVcpu(vcpu_ptr, orig_pfn << 12, true, &pte_va, &before))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    payload_u64 current_pfn = (before & PAYLOAD_EPT_PFN_MASK) >> 12;
    if (current_pfn != orig_pfn && current_pfn != exec_pfn)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_PTE_MISMATCH,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    // 仅用于诊断：在定位的 EPT PTE 上执行 Host 写入与 INVEPT，不改变权限或 PFN，
    // 因此该测试不会触发任何 EPT 违例。
    PayloadWriteHostU64(pte_va, before);
    PayloadEptInveptAll();

    g_payload_ept_tramp_last_pte_pa = pte_va;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = before;
    g_payload_ept_tramp_last_orig_pfn = orig_pfn;
    g_payload_ept_tramp_last_exec_pfn = exec_pfn;
    PayloadEptNativeSetInstallDiag(
        PAYLOAD_NATIVE_EPT_REASON_SUCCESS,
        vcpu_index,
        vcpu_ptr,
        orig_pfn,
        exec_pfn,
        pte_va,
        before,
        0);
    return true;
}

static bool PayloadEptNativeLocateOnlyNoSplitForVcpu(payload_u64 vcpu_ptr,
                                                     payload_u64 orig_pfn,
                                                     payload_u64 exec_pfn)
{
    payload_u64 vcpu_index = ~0ull;
    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.vcpus &&
        g_hv_diag_vcpu_stride &&
        PayloadIsKernelPointer(vcpu_ptr) &&
        vcpu_ptr >= g_cached_hv_diag.vcpus)
    {
        vcpu_index = (vcpu_ptr - g_cached_hv_diag.vcpus) / g_hv_diag_vcpu_stride;
    }

    if (!PayloadIsKernelPointer(vcpu_ptr) ||
        !orig_pfn ||
        !exec_pfn ||
        orig_pfn > 0xFFFFFFFFull ||
        exec_pfn > 0xFFFFFFFFull)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_BAD_ARGS,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (!PayloadEptLocatePteForVcpu(vcpu_ptr, orig_pfn << 12, false, &pte_va, &before))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    payload_u64 current_pfn = (before & PAYLOAD_EPT_PFN_MASK) >> 12;
    if (current_pfn != orig_pfn && current_pfn != exec_pfn)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_PTE_MISMATCH,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    // 仅用于诊断：在当前 vCPU 上定位并读取叶子 EPT PTE。
    // 不拆分大页、不写入 PTE、不执行 INVEPT。用于隔离 EPT 页表遍历/物理读取路径与拆分/写入/刷新副作用。
    g_payload_ept_tramp_last_pte_pa = pte_va;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = before;
    g_payload_ept_tramp_last_orig_pfn = orig_pfn;
    g_payload_ept_tramp_last_exec_pfn = exec_pfn;
    PayloadEptNativeSetInstallDiag(
        PAYLOAD_NATIVE_EPT_REASON_SUCCESS,
        vcpu_index,
        vcpu_ptr,
        orig_pfn,
        exec_pfn,
        pte_va,
        before,
        0);
    return true;
}

static bool PayloadEptNativePdeOnlyForVcpu(payload_u64 vcpu_ptr,
                                           payload_u64 orig_pfn,
                                           payload_u64 exec_pfn)
{
    payload_u64 vcpu_index = ~0ull;
    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.vcpus &&
        g_hv_diag_vcpu_stride &&
        PayloadIsKernelPointer(vcpu_ptr) &&
        vcpu_ptr >= g_cached_hv_diag.vcpus)
    {
        vcpu_index = (vcpu_ptr - g_cached_hv_diag.vcpus) / g_hv_diag_vcpu_stride;
    }

    if (!PayloadIsKernelPointer(vcpu_ptr) ||
        !g_cached_hv_diag.vcpu_off_ept ||
        !orig_pfn ||
        !exec_pfn ||
        orig_pfn > 0xFFFFFFFFull ||
        exec_pfn > 0xFFFFFFFFull)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_BAD_ARGS,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }

    payload_u64 gpa = orig_pfn << 12;
    payload_u64 pml4_idx = (gpa >> 39) & 0x1FFull;
    payload_u64 pdpt_idx = (gpa >> 30) & 0x1FFull;
    payload_u64 pd_idx = (gpa >> 21) & 0x1FFull;
    if (pml4_idx != 0 || pdpt_idx >= 512)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }

    payload_u64 ept_base = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept;
    payload_u64 pde_va = ept_base + 0x2000ull +
        ((pdpt_idx * 512ull) + pd_idx) * sizeof(payload_u64);
    if (!PayloadIsKernelPointer(pde_va))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pde_va,
            0,
            0);
        return false;
    }

    // 仅用于诊断：读取用于访问叶子 PTE 的 PDE 表项。不触及叶子物理内存映射，不拆分/写入/INVEPT。
    payload_u64 pde = PayloadReadHostU64(pde_va);
    payload_u64 reason = PAYLOAD_NATIVE_EPT_REASON_PDE_POINTS_PT;
    if (!(pde & PAYLOAD_EPT_PERM_MASK))
        reason = PAYLOAD_NATIVE_EPT_REASON_PDE_NO_PERM;
    else if (pde & PAYLOAD_EPT_LARGE_PAGE)
        reason = PAYLOAD_NATIVE_EPT_REASON_PDE_LARGE_PAGE;

    g_payload_ept_tramp_last_pte_pa = pde_va;
    g_payload_ept_tramp_last_pte_before = pde;
    g_payload_ept_tramp_last_pte_after = pde;
    g_payload_ept_tramp_last_orig_pfn = orig_pfn;
    g_payload_ept_tramp_last_exec_pfn = exec_pfn;
    PayloadEptNativeSetInstallDiag(
        reason,
        vcpu_index,
        vcpu_ptr,
        orig_pfn,
        exec_pfn,
        pde_va,
        pde,
        0);
    return (pde & PAYLOAD_EPT_PERM_MASK) != 0;
}

static bool PayloadEptNativeSplitPrepareForVcpu(payload_u64 vcpu_ptr,
                                                payload_u64 orig_pfn,
                                                payload_u64 exec_pfn,
                                                bool reserve_used,
                                                bool publish_pde,
                                                payload_u64 success_reason)
{
    payload_u64 vcpu_index = ~0ull;
    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.vcpus &&
        g_hv_diag_vcpu_stride &&
        PayloadIsKernelPointer(vcpu_ptr) &&
        vcpu_ptr >= g_cached_hv_diag.vcpus)
    {
        vcpu_index = (vcpu_ptr - g_cached_hv_diag.vcpus) / g_hv_diag_vcpu_stride;
    }

    if (!PayloadIsKernelPointer(vcpu_ptr) ||
        !g_cached_hv_diag.vcpu_off_ept ||
        !g_cached_hv_diag.vcpu_off_ept_free_pages ||
        !g_cached_hv_diag.vcpu_off_ept_free_page_pfns ||
        !g_cached_hv_diag.vcpu_off_ept_num_used_free_pages ||
        !orig_pfn ||
        !exec_pfn ||
        orig_pfn > 0xFFFFFFFFull ||
        exec_pfn > 0xFFFFFFFFull)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_BAD_ARGS,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }

    payload_u64 gpa = orig_pfn << 12;
    payload_u64 pml4_idx = (gpa >> 39) & 0x1FFull;
    payload_u64 pdpt_idx = (gpa >> 30) & 0x1FFull;
    payload_u64 pd_idx = (gpa >> 21) & 0x1FFull;
    if (pml4_idx != 0 || pdpt_idx >= 512)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            0,
            0,
            0);
        return false;
    }

    payload_u64 ept_base = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept;
    payload_u64 pde_va = ept_base + 0x2000ull +
        ((pdpt_idx * 512ull) + pd_idx) * sizeof(payload_u64);
    if (!PayloadIsKernelPointer(pde_va))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pde_va,
            0,
            0);
        return false;
    }

    payload_u64 pde = PayloadReadHostU64(pde_va);
    if (!(pde & PAYLOAD_EPT_PERM_MASK))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_PDE_NO_PERM,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pde_va,
            pde,
            0);
        return false;
    }

    if (!(pde & PAYLOAD_EPT_LARGE_PAGE))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_NOT_LARGE,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pde_va,
            pde,
            0);
        return true;
    }

    payload_u64 free_count = g_cached_hv_diag.ept_free_page_count ?
        g_cached_hv_diag.ept_free_page_count : 0x1000ull;
    payload_u64 used_ptr = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_num_used_free_pages;
    payload_u64 used = PayloadReadHostU64(used_ptr);
    if (used >= free_count)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_NO_FREE_NODE,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pde_va,
            pde,
            used);
        return false;
    }

    payload_u64 pt_va = vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_free_pages + used * PAGE_SIZE;
    payload_u64 pt_pfn = PayloadReadHostU64(
        vcpu_ptr + g_cached_hv_diag.vcpu_off_ept_free_page_pfns + used * sizeof(payload_u64));
    if (!PayloadIsKernelPointer(pt_va) || !pt_pfn)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_NO_FREE_NODE,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pde_va,
            pde,
            pt_va);
        return false;
    }

    // 诊断拆分阶梯：
    //  - fill-only: 填充待拆分的 PT 页面，但不递增已用计数且不发布新 PDE。
    //  - reserve-only: 递增已用计数以预留空闲页，但保持当前活动的 PDE 为大页。
    //  - publish-no-invept: 预留并发布新 PDE，但不执行 INVEPT。
    payload_u64 base_pfn = (pde & PAYLOAD_EPT_PFN_MASK) >> 12;
    bool r = (pde & 0x1ull) != 0;
    bool w = (pde & 0x2ull) != 0;
    bool x = (pde & 0x4ull) != 0;
    for (payload_u64 i = 0; i < 512; ++i)
    {
        payload_u64 pte = PayloadEptPteFromSplitPde(pde, base_pfn + i);
        pte = PayloadEptEntryWithPfnPerms(pte, base_pfn + i, r, w, x);
        PayloadWriteHostU64(pt_va + i * sizeof(payload_u64), pte);
    }

    if (reserve_used)
        PayloadWriteHostU64(used_ptr, used + 1);

    if (publish_pde)
    {
        // 对齐底层 split_ept_pde()：非叶子 PDE 仅保留 R/W/X、user_mode_execute 和 PT PFN。
        // 在发布的 PDE 中严禁保留属于大页叶子的内存类型/缓存标志位。
        payload_u64 new_pde = ((pt_pfn << 12) & PAYLOAD_EPT_PFN_MASK) | 0x407ull;
        PayloadWriteHostU64(pde_va, new_pde);
    }

    g_payload_ept_tramp_last_pte_pa = pde_va;
    g_payload_ept_tramp_last_pte_before = pde;
    g_payload_ept_tramp_last_pte_after = publish_pde ? PayloadReadHostU64(pde_va) : pde;
    g_payload_ept_tramp_last_orig_pfn = orig_pfn;
    g_payload_ept_tramp_last_exec_pfn = exec_pfn;
    PayloadEptNativeSetInstallDiag(
        success_reason,
        vcpu_index,
        vcpu_ptr,
        orig_pfn,
        exec_pfn,
        pde_va,
        pde,
        pt_va);
    return true;
}

static bool PayloadEptNativeSplitLeafLocateForVcpu(payload_u64 vcpu_ptr,
                                                   payload_u64 orig_pfn,
                                                   payload_u64 exec_pfn)
{
    payload_u64 vcpu_index = ~0ull;
    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.vcpus &&
        g_hv_diag_vcpu_stride &&
        PayloadIsKernelPointer(vcpu_ptr) &&
        vcpu_ptr >= g_cached_hv_diag.vcpus)
    {
        vcpu_index = (vcpu_ptr - g_cached_hv_diag.vcpus) / g_hv_diag_vcpu_stride;
    }

    if (!PayloadEptNativeSplitPrepareForVcpu(
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            true,
            true,
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_PUBLISH_INVEPT_SUCCESS))
    {
        return false;
    }

    PayloadEptInveptAll();

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (!PayloadEptLocatePteForVcpu(vcpu_ptr, orig_pfn << 12, false, &pte_va, &before))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    payload_u64 current_pfn = (before & PAYLOAD_EPT_PFN_MASK) >> 12;
    if (current_pfn != orig_pfn && current_pfn != exec_pfn)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_PTE_MISMATCH,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    g_payload_ept_tramp_last_pte_pa = pte_va;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = before;
    g_payload_ept_tramp_last_orig_pfn = orig_pfn;
    g_payload_ept_tramp_last_exec_pfn = exec_pfn;
    PayloadEptNativeSetInstallDiag(
        PAYLOAD_NATIVE_EPT_REASON_SPLIT_LEAF_LOCATE_SUCCESS,
        vcpu_index,
        vcpu_ptr,
        orig_pfn,
        exec_pfn,
        pte_va,
        before,
        0);
    return true;
}

static bool PayloadEptNativeSplitLeafWriteSameForVcpu(payload_u64 vcpu_ptr,
                                                      payload_u64 orig_pfn,
                                                      payload_u64 exec_pfn,
                                                      bool extra_invept,
                                                      payload_u64 success_reason)
{
    payload_u64 vcpu_index = ~0ull;
    if (g_hv_diag_cache_ready &&
        g_cached_hv_diag.vcpus &&
        g_hv_diag_vcpu_stride &&
        PayloadIsKernelPointer(vcpu_ptr) &&
        vcpu_ptr >= g_cached_hv_diag.vcpus)
    {
        vcpu_index = (vcpu_ptr - g_cached_hv_diag.vcpus) / g_hv_diag_vcpu_stride;
    }

    if (!PayloadEptNativeSplitPrepareForVcpu(
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            true,
            true,
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_PUBLISH_INVEPT_SUCCESS))
    {
        return false;
    }

    PayloadEptInveptAll();

    payload_u64 pte_va = 0;
    payload_u64 before = 0;
    if (!PayloadEptLocatePteForVcpu(vcpu_ptr, orig_pfn << 12, false, &pte_va, &before))
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_LOCATE_PTE_FAIL,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    payload_u64 current_pfn = (before & PAYLOAD_EPT_PFN_MASK) >> 12;
    if (current_pfn != orig_pfn && current_pfn != exec_pfn)
    {
        PayloadEptNativeSetInstallDiag(
            PAYLOAD_NATIVE_EPT_REASON_PTE_MISMATCH,
            vcpu_index,
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            pte_va,
            before,
            0);
        return false;
    }

    // 仅用于诊断：在大页 PDE 拆分发布/刷新且叶子 PTE 定位后，写回完全相同的叶子值。
    // 用于隔离 Host 端叶子 PTE 写入动作与任何 PFN/权限变更。
    PayloadWriteHostU64(pte_va, before);
    if (extra_invept)
        PayloadEptInveptAll();

    g_payload_ept_tramp_last_pte_pa = pte_va;
    g_payload_ept_tramp_last_pte_before = before;
    g_payload_ept_tramp_last_pte_after = before;
    g_payload_ept_tramp_last_orig_pfn = orig_pfn;
    g_payload_ept_tramp_last_exec_pfn = exec_pfn;
    PayloadEptNativeSetInstallDiag(
        success_reason,
        vcpu_index,
        vcpu_ptr,
        orig_pfn,
        exec_pfn,
        pte_va,
        before,
        0);
    return true;
}

static bool PayloadEptQueueNativeInstallAll(payload_u64 orig_pfn,
                                            payload_u64 exec_pfn,
                                            bool is_fake_page,
                                            payload_u64* pending_bitmap_out);

static bool PayloadEptQueueNativeInstallAllEx(payload_u64 orig_pfn,
                                              payload_u64 exec_pfn,
                                              bool is_fake_page,
                                              payload_u64 entry_ptr,
                                              payload_u64* pending_bitmap_out,
                                              payload_native_ept_install_policy policy);

static void PayloadEptMarkLegacyEntryActive(payload_u64 entry_ptr, payload_u64 bit)
{
    if (!entry_ptr || !bit || !g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap)
        return;
    payload_u64 field = entry_ptr + g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap;
    if (!PayloadIsKernelPointer(field))
        return;
    _InterlockedOr64((volatile LONG64*)field, (LONG64)bit);
}

static bool PayloadEptTryNativePendingLock()
{
    for (payload_u64 spin = 0; spin < 0x100000ull; ++spin)
    {
        if (_InterlockedCompareExchange(&g_payload_native_ept_pending_lock, 1, 0) == 0)
            return true;
        _mm_pause();
    }
    _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
    return false;
}

static void PayloadEptClearNativePending(payload_u64 entry_ptr,
                                         payload_u64 orig_pfn,
                                         payload_u64 exec_pfn)
{
    if (!PayloadEptTryNativePendingLock())
        return;

    for (payload_u64 i = 0; i < PAYLOAD_NATIVE_EPT_PENDING_CAPACITY; ++i)
    {
        auto& entry = g_payload_native_ept_pending[i];
        bool match = false;
        if (entry_ptr && entry.entry_ptr == entry_ptr)
            match = true;
        if (!match && orig_pfn && exec_pfn &&
            entry.orig_pfn == orig_pfn &&
            entry.exec_pfn == exec_pfn)
        {
            match = true;
        }
        if (!match)
            continue;

        entry.pending_bitmap = 0;
        entry.orig_pfn = 0;
        entry.exec_pfn = 0;
        entry.is_fake_page = 0;
        entry.entry_ptr = 0;
    }

    _InterlockedExchange(&g_payload_native_ept_pending_lock, 0);
    g_payload_getbuffer_install_pending = 0;
}

static void PayloadEptRetireNativePendingIfDone(payload_native_ept_pending_entry* target,
                                                payload_u64 entry_ptr,
                                                payload_u64 orig_pfn,
                                                payload_u64 exec_pfn)
{
    if (!target || target->pending_bitmap)
        return;

    if (!PayloadEptTryNativePendingLock())
        return;

    bool match = false;
    if (target->pending_bitmap == 0)
    {
        if (entry_ptr && target->entry_ptr == entry_ptr)
            match = true;
        if (!match && orig_pfn && exec_pfn &&
            target->orig_pfn == orig_pfn &&
            target->exec_pfn == exec_pfn)
        {
            match = true;
        }
    }

    if (match)
    {
        target->pending_bitmap = 0;
        target->orig_pfn = 0;
        target->exec_pfn = 0;
        target->is_fake_page = 0;
        target->entry_ptr = 0;
    }

    _InterlockedExchange(&g_payload_native_ept_pending_lock, 0);
    if (match)
        g_payload_getbuffer_install_pending = 0;
}

static void PayloadEptArmLegacyPendingInvept(payload_u64 bitmap)
{
    if (!bitmap || !g_cached_hv_diag.ghv_off_pending_ept_invept_bitmap)
        return;

    payload_u64 field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_ept_invept_bitmap, 0);
    if (!PayloadIsKernelPointer(field))
        return;

    _InterlockedOr64((volatile LONG64*)field, (LONG64)bitmap);
}

static bool PayloadEptArmLegacyPendingInstall(payload_u64 entry_ptr,
                                              payload_u64 self_index,
                                              payload_u64* pending_bitmap_out)
{
    if (pending_bitmap_out)
        *pending_bitmap_out = 0;

    if (!entry_ptr ||
        !g_cached_hv_diag.ghv_off_pending_ept_install_entries ||
        !g_cached_hv_diag.ghv_off_pending_ept_install_bitmap)
    {
        return false;
    }

    payload_u64 entries_base = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_ept_install_entries, 0);
    payload_u64 bitmap_field = PayloadDiagGhvField(g_cached_hv_diag.ghv_off_pending_ept_install_bitmap, 0);
    if (!PayloadIsKernelPointer(entries_base) || !PayloadIsKernelPointer(bitmap_field))
        return false;

    payload_u64 capacity = g_cached_hv_diag.ghv_pending_install_capacity;
    if (!capacity || capacity > 256)
        capacity = 64;

    bool placed = false;
    for (payload_u64 i = 0; i < capacity; ++i)
    {
        payload_u64 slot = entries_base + i * sizeof(payload_u64);
        if (!PayloadIsKernelPointer(slot))
            break;

        LONG64 prev = _InterlockedCompareExchange64(
            (volatile LONG64*)slot,
            (LONG64)entry_ptr,
            0);
        if (prev == 0 || (payload_u64)prev == entry_ptr)
        {
            placed = true;
            break;
        }
    }

    if (!placed)
        return false;

    payload_u64 vcpu_count = g_cached_hv_diag.vcpu_count;
    if (vcpu_count > PAYLOAD_EPT_MAX_TRACKED_VCPUS)
        vcpu_count = PAYLOAD_EPT_MAX_TRACKED_VCPUS;
    payload_u64 full = vcpu_count >= 64 ? ~0ull : ((1ull << vcpu_count) - 1ull);
    payload_u64 self_bit = (self_index < 64) ? (1ull << self_index) : 0ull;
    payload_u64 others = full & ~self_bit;
    if (others)
        _InterlockedOr64((volatile LONG64*)bitmap_field, (LONG64)others);

    if (pending_bitmap_out)
        *pending_bitmap_out = others;
    return true;
}

static bool PayloadEptDrainNativePending()
{
    if (!g_hv_diag_cache_ready || !g_cached_hv_diag.vcpu_count)
        return false;

    payload_u64 index = PayloadCurrentVcpuIndex();
    if (index >= PAYLOAD_EPT_MAX_TRACKED_VCPUS)
        return false;
    payload_u64 bit = 1ull << index;
    payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
    if (!PayloadIsKernelPointer(vcpu_ptr))
        return false;

    bool did_work = false;
    for (payload_u64 i = 0; i < PAYLOAD_NATIVE_EPT_PENDING_CAPACITY; ++i)
    {
        auto& entry = g_payload_native_ept_pending[i];
        payload_u64 pending = entry.pending_bitmap;
        if (!(pending & bit))
            continue;

        payload_u64 orig_pfn = entry.orig_pfn;
        payload_u64 exec_pfn = entry.exec_pfn;
        bool is_fake = entry.is_fake_page != 0;
        payload_u64 legacy_entry = entry.entry_ptr;
        if (!orig_pfn || !exec_pfn)
            continue;

        if (PayloadEptNativeInstallForVcpu(vcpu_ptr, orig_pfn, exec_pfn, is_fake))
        {
            PayloadEptMarkLegacyEntryActive(legacy_entry, bit);
            _InterlockedAnd64((volatile LONG64*)&entry.pending_bitmap, ~(LONG64)bit);
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
            g_payload_getbuffer_install_pending = entry.pending_bitmap;
            if (!entry.pending_bitmap)
                PayloadEptRetireNativePendingIfDone(&entry, legacy_entry, orig_pfn, exec_pfn);
            did_work = true;
        }
        else
        {
            _InterlockedAnd64((volatile LONG64*)&entry.pending_bitmap, ~(LONG64)bit);
            g_payload_getbuffer_install_pending = entry.pending_bitmap;
            if (!entry.pending_bitmap)
                PayloadEptRetireNativePendingIfDone(&entry, legacy_entry, orig_pfn, exec_pfn);
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        }
    }

    return did_work;
}

static bool PayloadEptQueueNativeInstallAll(payload_u64 orig_pfn,
                                            payload_u64 exec_pfn,
                                            bool is_fake_page,
                                            payload_u64* pending_bitmap_out)
{
    return PayloadEptQueueNativeInstallAllEx(
        orig_pfn,
        exec_pfn,
        is_fake_page,
        0,
        pending_bitmap_out,
        PAYLOAD_NATIVE_EPT_POLICY_IMMEDIATE_ALL);
}

static bool PayloadEptQueueNativeInstallAllEx(payload_u64 orig_pfn,
                                              payload_u64 exec_pfn,
                                              bool is_fake_page,
                                              payload_u64 entry_ptr,
                                              payload_u64* pending_bitmap_out,
                                              payload_native_ept_install_policy policy)
{
    if (pending_bitmap_out)
        *pending_bitmap_out = 0;
    if (!orig_pfn || !exec_pfn || !g_cached_hv_diag.vcpu_count)
        return false;

    payload_u64 vcpu_count = g_cached_hv_diag.vcpu_count;
    if (vcpu_count > PAYLOAD_EPT_MAX_TRACKED_VCPUS)
        vcpu_count = PAYLOAD_EPT_MAX_TRACKED_VCPUS;
    payload_u64 full = vcpu_count >= 64 ? ~0ull : ((1ull << vcpu_count) - 1ull);
    if (!full)
        return false;
    payload_u64 self_index = PayloadCurrentVcpuIndex();
    payload_u64 self_bit = (self_index < 64) ? (1ull << self_index) : 0ull;
    payload_u64 initial_pending = full;
    if (policy == PAYLOAD_NATIVE_EPT_POLICY_DEFERRED && self_bit)
        initial_pending &= ~self_bit;

#if VT_DEFERRED_EPT_USE_LEGACY_PENDING
    if (policy == PAYLOAD_NATIVE_EPT_POLICY_DEFERRED && entry_ptr)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool self_ok = false;
        if (PayloadIsKernelPointer(vcpu_ptr))
        {
            self_ok = PayloadEptNativeInstallForVcpu(vcpu_ptr, orig_pfn, exec_pfn, is_fake_page);
            if (self_ok && self_bit)
            {
                PayloadEptMarkLegacyEntryActive(entry_ptr, self_bit);
                _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
            }
            else if (!self_ok)
            {
                _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
            }
        }

        payload_u64 legacy_pending = 0;
        if (PayloadEptArmLegacyPendingInstall(entry_ptr, self_index, &legacy_pending))
        {
            g_payload_getbuffer_install_pending = legacy_pending;
            if (pending_bitmap_out)
                *pending_bitmap_out = legacy_pending;
            return self_ok || legacy_pending != 0;
        }
    }
#endif

    if (!PayloadEptTryNativePendingLock())
        return false;

    payload_native_ept_pending_entry* chosen = nullptr;
    for (payload_u64 i = 0; i < PAYLOAD_NATIVE_EPT_PENDING_CAPACITY; ++i)
    {
        auto& entry = g_payload_native_ept_pending[i];
        if (entry.orig_pfn == orig_pfn && entry.exec_pfn == exec_pfn &&
            (!entry_ptr || !entry.entry_ptr || entry.entry_ptr == entry_ptr))
        {
            chosen = &entry;
            break;
        }
        if (!chosen && (entry.orig_pfn == 0 || entry.pending_bitmap == 0))
            chosen = &entry;
    }

    if (chosen)
    {
        chosen->orig_pfn = orig_pfn;
        chosen->exec_pfn = exec_pfn;
        chosen->is_fake_page = is_fake_page ? 1ull : 0ull;
        if (entry_ptr)
            chosen->entry_ptr = entry_ptr;
        _InterlockedOr64((volatile LONG64*)&chosen->pending_bitmap, (LONG64)initial_pending);
        if (pending_bitmap_out)
            *pending_bitmap_out = chosen->pending_bitmap;
    }

    _InterlockedExchange(&g_payload_native_ept_pending_lock, 0);

    if (!chosen)
        return false;

    // PMO 处理器包含两种对齐底层的安装策略与多种诊断模式：
    //
    //   DEFERRED       : 高频用户层钩子（特别是 GetBuffer/Type 3）。
    //                    立即在当前 vCPU 上安装，其它 vCPU 标记挂起并在各自后续
    //                    vmexit 时处理（vh_install_host_deferred/eh_install_all_deferred）。
    //
    //   IMMEDIATE_ALL  : 低频/内核层钩子。当前 PMO vmexit 立即写入所有已知 vCPU 的 EPT 树，
    //                    对齐 vh_install_host/eh_install_all。任何失败位保持挂起以供重试。
    //
    //   QUEUE_ONLY     : 诊断模式。仅记录挂起项，不写入任何 EPT PTE 且不触发 EPT 违例处理。
    //   WRITE_SAME_CURRENT : 诊断模式。定位当前 vCPU EPT PTE，原值写回，INVEPT 并清除挂起。
    //   LOCATE_ONLY_NO_SPLIT : 诊断模式。定位/读取当前 vCPU EPT PTE（不拆分大页、不写入、不刷新）。
    //   PDE_ONLY       : 诊断模式。仅读取覆盖目标 GPA 的当前 vCPU PDE 表项。
    //   SPLIT_FILL_ONLY: 诊断模式。填充待拆分 PT 页，但不递增已用计数、不发布 PDE、不刷新。
    //   SPLIT_RESERVE_ONLY : 诊断模式。填充 PT 页并递增已用计数，但不发布 PDE 且不刷新。
    //   SPLIT_PUBLISH_NO_INVEPT : 诊断模式。填充并发布新 PDE，但不执行 INVEPT。
    //   SPLIT_PUBLISH_INVEPT : 诊断模式。发布新 PDE 并发起全局 INVEPT。
    //   SPLIT_LEAF_LOCATE_ONLY : 诊断模式。拆分、发布、INVEPT 后定位并读取叶子 PTE。
    //   SPLIT_LEAF_WRITE_SAME_ONLY : 诊断模式。拆分发布后原值写回叶子 PTE。
    //   SPLIT_LEAF_WRITE_SAME_INVEPT_ONLY : 诊断模式。原值写回后追加一次全局 INVEPT。
    //   INSTALL_CURRENT_ONLY : 诊断模式。仅对当前 vCPU 运行真实安装路径并清除执行位。
    payload_u64 successful_install_bitmap = 0;

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_INSTALL_CURRENT_ONLY)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        payload_u64 vcpu_index = PayloadCurrentVcpuIndex();
        bool ok = PayloadEptNativeInstallForVcpu(vcpu_ptr, orig_pfn, exec_pfn, is_fake_page);
        if (ok)
        {
            if (vcpu_index < PAYLOAD_EPT_MAX_TRACKED_VCPUS)
                PayloadEptMarkLegacyEntryActive(entry_ptr, 1ull << vcpu_index);
            PayloadEptNativeSetInstallDiag(
                PAYLOAD_NATIVE_EPT_REASON_INSTALL_CURRENT_SUCCESS,
                vcpu_index,
                vcpu_ptr,
                orig_pfn,
                exec_pfn,
                g_payload_ept_tramp_last_pte_pa,
                g_payload_ept_tramp_last_pte_before,
                g_payload_ept_last_hook_node);
        }
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_INSTALL_CURRENT_PLUS_ONE)
    {
        payload_u64 self_index = PayloadCurrentVcpuIndex();
        payload_u64 extra_index = (payload_u64)VT_MM4_INSTALL_EXTRA_VCPU_INDEX;
        payload_u64 ok_count = 0;
        payload_u64 fail_count = 0;

        auto install_one = [&](payload_u64 index) -> void
        {
            if (index >= PAYLOAD_EPT_MAX_TRACKED_VCPUS)
                return;
            payload_u64 vcpu_ptr = (index == self_index)
                ? PayloadCurrentVcpuPtr()
                : PayloadEptVcpuPtrByIndex(index);
            if (!PayloadIsKernelPointer(vcpu_ptr))
            {
                ++fail_count;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
                return;
            }

            bool one_ok = PayloadEptNativeInstallForVcpu(vcpu_ptr, orig_pfn, exec_pfn, is_fake_page);
            if (one_ok)
            {
                ++ok_count;
                if (index < PAYLOAD_EPT_MAX_TRACKED_VCPUS)
                    PayloadEptMarkLegacyEntryActive(entry_ptr, 1ull << index);
                _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
            }
            else
            {
                ++fail_count;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
            }
        };

        install_one(self_index);
        if (extra_index != self_index)
            install_one(extra_index);

        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;

        bool ok = ok_count != 0 && fail_count == 0;
        if (ok)
        {
            PayloadEptNativeSetInstallDiag(
                PAYLOAD_NATIVE_EPT_REASON_INSTALL_CURRENT_SUCCESS,
                extra_index,
                PayloadEptVcpuPtrByIndex(extra_index),
                orig_pfn,
                exec_pfn,
                g_payload_ept_tramp_last_pte_pa,
                g_payload_ept_tramp_last_pte_before,
                g_payload_ept_last_hook_node);
        }
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_WRITE_SAME_INVEPT_ONLY)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeSplitLeafWriteSameForVcpu(
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            true,
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_LEAF_WRITE_SAME_INVEPT_SUCCESS);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_WRITE_SAME_ONLY)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeSplitLeafWriteSameForVcpu(
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            false,
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_LEAF_WRITE_SAME_SUCCESS);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_LOCATE_ONLY)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeSplitLeafLocateForVcpu(vcpu_ptr, orig_pfn, exec_pfn);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_SPLIT_PUBLISH_INVEPT)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeSplitPrepareForVcpu(
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            true,
            true,
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_PUBLISH_INVEPT_SUCCESS);
        if (ok)
            PayloadEptInveptAll();
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_SPLIT_PUBLISH_NO_INVEPT)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeSplitPrepareForVcpu(
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            true,
            true,
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_PUBLISH_SUCCESS);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_SPLIT_RESERVE_ONLY)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeSplitPrepareForVcpu(
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            true,
            false,
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_RESERVE_SUCCESS);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_SPLIT_FILL_ONLY)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeSplitPrepareForVcpu(
            vcpu_ptr,
            orig_pfn,
            exec_pfn,
            false,
            false,
            PAYLOAD_NATIVE_EPT_REASON_SPLIT_FILL_SUCCESS);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_PDE_ONLY)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativePdeOnlyForVcpu(vcpu_ptr, orig_pfn, exec_pfn);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_LOCATE_ONLY_NO_SPLIT)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeLocateOnlyNoSplitForVcpu(vcpu_ptr, orig_pfn, exec_pfn);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_WRITE_SAME_CURRENT)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeWriteSameForVcpu(vcpu_ptr, orig_pfn, exec_pfn);
        chosen->pending_bitmap = 0;
        g_payload_getbuffer_install_pending = 0;
        if (pending_bitmap_out)
            *pending_bitmap_out = 0;
        if (ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        return ok;
    }

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_DEFERRED)
    {
        payload_u64 vcpu_ptr = PayloadCurrentVcpuPtr();
        bool ok = PayloadEptNativeInstallForVcpu(vcpu_ptr, orig_pfn, exec_pfn, is_fake_page);
        if (ok)
        {
            if (self_bit)
            {
                PayloadEptMarkLegacyEntryActive(entry_ptr, self_bit);
                successful_install_bitmap |= self_bit;
            }
            else
            {
                successful_install_bitmap = 1;
            }
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
        }
        else
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
        }
    }

    if (policy != PAYLOAD_NATIVE_EPT_POLICY_QUEUE_ONLY)
        PayloadEptDrainNativePending();

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_IMMEDIATE_ALL)
    {
        payload_u64 newly_installed_bitmap = 0;
        for (payload_u64 index = 0; index < vcpu_count; ++index)
        {
            payload_u64 bit = 1ull << index;
            if (!(chosen->pending_bitmap & bit))
                continue;

            payload_u64 vcpu_ptr = PayloadEptVcpuPtrByIndex(index);
            if (PayloadEptNativeInstallForVcpu(vcpu_ptr, orig_pfn, exec_pfn, is_fake_page))
            {
                PayloadEptMarkLegacyEntryActive(entry_ptr, bit);
                _InterlockedAnd64((volatile LONG64*)&chosen->pending_bitmap, ~(LONG64)bit);
                newly_installed_bitmap |= bit;
                _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_ok);
            }
            else
            {
                _InterlockedAnd64((volatile LONG64*)&chosen->pending_bitmap, ~(LONG64)bit);
                _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_drain_fail);
            }
        }
        successful_install_bitmap |= newly_installed_bitmap;

        payload_u64 self_idx = PayloadCurrentVcpuIndex();
        payload_u64 others = newly_installed_bitmap;
        if (self_idx < 64)
            others &= ~(1ull << self_idx);
        PayloadEptArmLegacyPendingInvept(others);
    }

    payload_u64 final_pending = chosen->pending_bitmap;
    g_payload_getbuffer_install_pending = final_pending;
    if (pending_bitmap_out)
        *pending_bitmap_out = final_pending;
    if (!final_pending)
        PayloadEptRetireNativePendingIfDone(chosen, entry_ptr, orig_pfn, exec_pfn);

    if (policy == PAYLOAD_NATIVE_EPT_POLICY_IMMEDIATE_ALL)
        return successful_install_bitmap != 0;
    if (policy == PAYLOAD_NATIVE_EPT_POLICY_DEFERRED)
        return successful_install_bitmap != 0 || final_pending != 0;
    return final_pending != full;
}

static bool PayloadSetMtfWithPrev(payload_u64 vcpu_index, bool enable, volatile payload_u64* prev_ctrl)
{
    if (vcpu_index >= PAYLOAD_EPT_MAX_TRACKED_VCPUS)
        return false;

    payload_u64 controls = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, &controls))
        return false;

    if (enable)
    {
        if (prev_ctrl)
            prev_ctrl[vcpu_index] = controls;
        return PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, controls | PAYLOAD_VMX_PROCBASED_MTF);
    }

    if (prev_ctrl)
        prev_ctrl[vcpu_index] = controls;
    return PayloadVmwrite(PAYLOAD_VMCS_CTRL_PROC_BASED_EXEC, controls & ~PAYLOAD_VMX_PROCBASED_MTF);
}

static bool PayloadEptSetMtf(payload_u64 vcpu_index, bool enable)
{
    return PayloadSetMtfWithPrev(vcpu_index, enable, g_payload_ept_mtf_prev_ctrl);
}

