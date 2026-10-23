// Split from payload_bridge.inl: core/memory_access.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static payload_u64 PayloadMakeTableEntry(payload_u64 source_entry, payload_u64 table_pa)
{
    payload_u64 entry = source_entry;
    entry &= ~0x000FFFFFFFFFF000ull;
    entry &= ~(1ull << 7);   // next-level table, not a large page
    entry &= ~(1ull << 63);  // executable in host CR3
    entry |= (table_pa & 0x000FFFFFFFFFF000ull);
    entry |= 0x3ull;         // present + writable
    return entry;
}

static payload_u64 PayloadMakeLeafEntry(payload_u64 source_entry)
{
    payload_u64 entry = source_entry;
    entry &= ~(1ull << 63); // executable in host CR3
    entry |= 0x3ull;        // present + writable
    return entry;
}

static bool PayloadEnsureHostChildTable(payload_u64 parent_table_pa,
                                        payload_u64 index,
                                        payload_u64 source_entry,
                                        payload_u64* child_table_pa)
{
    if (!child_table_pa || index >= 512)
        return false;

    payload_u64 entry_pa = parent_table_pa + index * sizeof(payload_u64);
    payload_u64 entry = 0;
    if (!PayloadReadPhys64(entry_pa, &entry))
        return false;

    if (entry & 1ull)
    {
        if (entry & (1ull << 7))
            return false;
        *child_table_pa = entry & 0x000FFFFFFFFFF000ull;
        return true;
    }

    payload_u64 new_table_pa = 0;
    if (!PayloadAllocHostPageTablePage(&new_table_pa))
        return false;

    if (!PayloadWritePhys64(entry_pa, PayloadMakeTableEntry(source_entry, new_table_pa)))
        return false;

    *child_table_pa = new_table_pa;
    return true;
}

static bool PayloadMapHostPage(payload_u64 va)
{
    payload_u64 host_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_HOST_CR3, &host_cr3) || !host_cr3)
        return false;

    payload_source_page_entries src = {};
    if (!PayloadReadSourcePageEntries(va, &src))
        return false;

    payload_u64 pml4_idx = (va >> 39) & 0x1FFull;
    payload_u64 pdpt_idx = (va >> 30) & 0x1FFull;
    payload_u64 pd_idx = (va >> 21) & 0x1FFull;
    payload_u64 pt_idx = (va >> 12) & 0x1FFull;

    payload_u64 host_pml4 = host_cr3 & 0x000FFFFFFFFFF000ull;
    payload_u64 host_pdpt = 0;
    if (!PayloadEnsureHostChildTable(host_pml4, pml4_idx, src.pml4e, &host_pdpt))
        return false;

    payload_u64 pdpte_pa = host_pdpt + pdpt_idx * sizeof(payload_u64);
    if (src.pdpte_large)
    {
        if (!PayloadWritePhys64(pdpte_pa, PayloadMakeLeafEntry(src.pdpte)))
            return false;
        __invlpg((void*)(va & ~0xFFFull));
        return true;
    }

    payload_u64 host_pd = 0;
    if (!PayloadEnsureHostChildTable(host_pdpt, pdpt_idx, src.pdpte, &host_pd))
        return false;

    payload_u64 pde_pa = host_pd + pd_idx * sizeof(payload_u64);
    if (src.pde_large)
    {
        if (!PayloadWritePhys64(pde_pa, PayloadMakeLeafEntry(src.pde)))
            return false;
        __invlpg((void*)(va & ~0xFFFull));
        return true;
    }

    payload_u64 host_pt = 0;
    if (!PayloadEnsureHostChildTable(host_pd, pd_idx, src.pde, &host_pt))
        return false;

    payload_u64 pte_pa = host_pt + pt_idx * sizeof(payload_u64);
    if (!PayloadWritePhys64(pte_pa, PayloadMakeLeafEntry(src.pte)))
        return false;

    __invlpg((void*)(va & ~0xFFFull));
    return true;
}

static bool PayloadMapHostRangeSelf(payload_u64 va, payload_u64 bytes)
{
    if (!va || !bytes || !g_system_cr3)
        return false;

    payload_u64 begin = va & ~0xFFFull;
    payload_u64 end = (va + bytes + 0xFFFull) & ~0xFFFull;
    if (end <= begin)
        return false;

    for (payload_u64 page = begin; page < end; page += PAGE_SIZE)
    {
        if (!PayloadMapHostPage(page))
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_host_map_fail_count);
            return false;
        }
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_host_map_success_count);
    return true;
}

static void* PayloadGvaToHva(payload_u64 gva, payload_u64 size)
{
    payload_u64 cr3 = 0;
    payload_u64 gpa = 0;
    payload_u64 bytes_left = 0;
    bool ok = PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &cr3) &&
        PayloadGvaToGpa(cr3, gva, &gpa, &bytes_left) &&
        PayloadHostPhysicalRangeMapped(gpa, size);
    if (!ok && g_system_cr3)
    {
        cr3 = g_system_cr3;
        ok = PayloadGvaToGpa(cr3, gva, &gpa, &bytes_left) &&
            PayloadHostPhysicalRangeMapped(gpa, size);
    }
    if (!ok)
    {
        return nullptr;
    }

    if (bytes_left && size > bytes_left)
        return nullptr;

    return (void*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + gpa);
}

static void* PayloadGvaToHvaCr3(payload_u64 cr3, payload_u64 gva, payload_u64* bytes_left)
{
    payload_u64 gpa = 0;
    payload_u64 left = 0;
    if (!cr3 ||
        !PayloadGvaToGpa(cr3, gva, &gpa, &left) ||
        !PayloadHostPhysicalRangeMapped(gpa, 1))
    {
        return nullptr;
    }

    if (bytes_left)
        *bytes_left = left ? left : 1;
    return (void*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + gpa);
}

static payload_u64 PayloadMinU64(payload_u64 a, payload_u64 b)
{
    return a < b ? a : b;
}

static payload_u64 PayloadBridgeCopyPhysToGuest(payload_u64 src_pa, payload_u64 dst_gva, payload_u64 size)
{
    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return 0;

    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 dst_left = 0;
        auto dst = PayloadGvaToHvaCr3(guest_cr3, dst_gva + done, &dst_left);
        payload_u64 pa = src_pa + done;
        if (!dst || !PayloadHostPhysicalRangeMapped(pa, 1))
            break;

        payload_u64 phys_left = PAYLOAD_HOST_PHYSICAL_MEMORY_BYTES - pa;
        payload_u64 chunk = PayloadMinU64(size - done, PayloadMinU64(dst_left, phys_left));
        if (!chunk)
            break;

        PayloadCopyMemory(dst, (void*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pa), chunk);
        done += chunk;
    }
    return done;
}

static payload_u64 PayloadBridgeCopyGuestToPhys(payload_u64 dst_pa, payload_u64 src_gva, payload_u64 size)
{
    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return 0;

    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 src_left = 0;
        auto src = PayloadGvaToHvaCr3(guest_cr3, src_gva + done, &src_left);
        payload_u64 pa = dst_pa + done;
        if (!src || !PayloadHostPhysicalRangeMapped(pa, 1))
            break;

        payload_u64 phys_left = PAYLOAD_HOST_PHYSICAL_MEMORY_BYTES - pa;
        payload_u64 chunk = PayloadMinU64(size - done, PayloadMinU64(src_left, phys_left));
        if (!chunk)
            break;

        PayloadCopyMemory((void*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + pa), src, chunk);
        done += chunk;
    }
    return done;
}

static payload_u64 PayloadBridgeCopyVirtToGuest(payload_u64 src_cr3, payload_u64 src_gva, payload_u64 dst_gva, payload_u64 size)
{
    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3 || !src_cr3)
        return 0;

    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 src_left = 0;
        payload_u64 dst_left = 0;
        auto src = PayloadGvaToHvaCr3(src_cr3, src_gva + done, &src_left);
        auto dst = PayloadGvaToHvaCr3(guest_cr3, dst_gva + done, &dst_left);
        if (!src || !dst)
            break;

        payload_u64 chunk = PayloadMinU64(size - done, PayloadMinU64(src_left, dst_left));
        if (!chunk)
            break;

        PayloadCopyMemory(dst, src, chunk);
        done += chunk;
    }
    return done;
}

static payload_u64 PayloadBridgeCopyGuestToVirt(payload_u64 dst_cr3, payload_u64 dst_gva, payload_u64 src_gva, payload_u64 size)
{
    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3 || !dst_cr3)
        return 0;

    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 src_left = 0;
        payload_u64 dst_left = 0;
        auto src = PayloadGvaToHvaCr3(guest_cr3, src_gva + done, &src_left);
        auto dst = PayloadGvaToHvaCr3(dst_cr3, dst_gva + done, &dst_left);
        if (!src || !dst)
            break;

        payload_u64 chunk = PayloadMinU64(size - done, PayloadMinU64(src_left, dst_left));
        if (!chunk)
            break;

        PayloadCopyMemory(dst, src, chunk);
        done += chunk;
    }
    return done;
}

static bool PayloadBridgeSkipInstruction()
{
    payload_u64 rip = 0;
    payload_u64 length = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_RIP, &rip) ||
        !PayloadVmread(PAYLOAD_VMCS_VMEXIT_INSTRUCTION_LENGTH, &length))
    {
        return false;
    }

    if (!length || length > 15)
        return false;

    return PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, rip + length);
}

