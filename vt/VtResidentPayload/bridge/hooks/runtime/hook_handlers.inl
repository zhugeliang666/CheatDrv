// Resident handlers for migrated legacy VTCall hooks.
// Included by hook_dispatch.inl after PMO runtime helpers are available.

#ifndef VT_STABLE_GETBUFFER_ONLY
#define VT_STABLE_GETBUFFER_ONLY 1
#endif

#ifndef PAYLOAD_ENABLE_NT_CSEC_KERNEL_CALLOUT
#define PAYLOAD_ENABLE_NT_CSEC_KERNEL_CALLOUT 0
#endif

#ifndef PAYLOAD_FORCE_GETBUFFER_PURPLE
#define PAYLOAD_FORCE_GETBUFFER_PURPLE 1
#endif

enum payload_hook_action : payload_u64
{
    PAYLOAD_HOOK_ACTION_NONE = 0,
    PAYLOAD_HOOK_ACTION_PASS = 1,
    PAYLOAD_HOOK_ACTION_SKIP_RETURN = 2,
    PAYLOAD_HOOK_ACTION_OBSERVE = 3,
    PAYLOAD_HOOK_ACTION_BLOCK = 4,
};

struct payload_legacy_hook_info
{
    payload_u64 slot;
    payload_u64 type;
    payload_u64 process;
    payload_u64 filter_by_process;
    payload_u64 enabled;
    payload_u64 blank;
    payload_u64 tramp_va;
    payload_u64 bp_rip;
    payload_u64 target_resume;
};

static bool PayloadHookFindLegacySlotInfoByRip(payload_u64 rip, payload_legacy_hook_info* info)
{
    if (info)
        PayloadZeroMemory(info, sizeof(*info));
    if (!info ||
        !rip ||
        !PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) ||
        !g_cached_hv_diag.vt_hook_slot_count ||
        !g_cached_hv_diag.vt_hook_slot_size ||
        !g_cached_hv_diag.vt_hook_slot_off_data_type ||
        !g_cached_hv_diag.vt_hook_slot_off_occupied)
    {
        return false;
    }

    payload_u64 count = g_cached_hv_diag.vt_hook_slot_count;
    if (count > 64)
        count = 64;

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 slot = g_cached_hv_diag.vt_hook_table_ptr +
            i * g_cached_hv_diag.vt_hook_slot_size;
        if (!PayloadIsKernelPointer(slot))
            break;
        if (!PayloadReadHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied))
            continue;

        payload_u64 address = PayloadReadHostU64(
            slot + g_cached_hv_diag.vt_hook_slot_off_data_address);
        if (address != rip)
            continue;

        info->slot = slot;
        info->type = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_type);
        if (g_cached_hv_diag.vt_hook_slot_off_data_process)
            info->process = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_process);
        if (g_cached_hv_diag.vt_hook_slot_off_data_filter_by_process)
            info->filter_by_process = PayloadReadHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_filter_by_process) ? 1ull : 0ull;
        if (g_cached_hv_diag.vt_hook_slot_off_data_is_enable)
            info->enabled = PayloadReadHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_is_enable) ? 1ull : 0ull;
        else
            info->enabled = 1;
        if (g_cached_hv_diag.vt_hook_slot_off_data_blank_memory)
            info->blank = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_blank_memory);
        if (g_cached_hv_diag.vt_hook_slot_off_trampoline_va)
            info->tramp_va = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_trampoline_va);
        if (g_cached_hv_diag.vt_hook_slot_off_bp_rip)
            info->bp_rip = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_bp_rip);
        if (g_cached_hv_diag.vt_hook_slot_off_target_resume)
            info->target_resume = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_target_resume);
        return true;
    }

    return false;
}

static bool PayloadHookIsLegacyBlankRip(payload_u64 rip)
{
    if (!rip ||
        !PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) ||
        !g_cached_hv_diag.vt_hook_slot_count ||
        !g_cached_hv_diag.vt_hook_slot_size ||
        !g_cached_hv_diag.vt_hook_slot_off_data_blank_memory ||
        !g_cached_hv_diag.vt_hook_slot_off_occupied)
    {
        return false;
    }

    payload_u64 count = g_cached_hv_diag.vt_hook_slot_count;
    if (count > 64)
        count = 64;

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 slot = g_cached_hv_diag.vt_hook_table_ptr +
            i * g_cached_hv_diag.vt_hook_slot_size;
        if (!PayloadIsKernelPointer(slot))
            break;
        if (!PayloadReadHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied))
            continue;
        if (PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_blank_memory) == rip)
            return true;
    }

    return false;
}

static void PayloadHookIncrementGhvCounter(payload_u64 offset)
{
    if (!offset || !g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return;
    payload_u64 field = g_cached_hv_diag.ghv + offset;
    if (PayloadIsKernelPointer(field))
        _InterlockedIncrement64((volatile LONG64*)field);
}

static void PayloadHookWriteGhvU64(payload_u64 offset, payload_u64 value)
{
    if (!offset || !g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return;
    payload_u64 field = g_cached_hv_diag.ghv + offset;
    if (PayloadIsKernelPointer(field))
        PayloadWriteHostU64(field, value);
}

static bool PayloadHookReadGuestRspRet(payload_u64* rsp_out, payload_u64* ret_out)
{
    if (rsp_out)
        *rsp_out = 0;
    if (ret_out)
        *ret_out = 0;

    payload_u64 rsp = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_RSP, &rsp) || !rsp)
        return false;

    auto rsp_hva = (payload_u64*)PayloadGvaToHva(rsp, sizeof(payload_u64));
    if (!rsp_hva)
        return false;

    if (rsp_out)
        *rsp_out = rsp;
    if (ret_out)
        *ret_out = *rsp_hva;
    return true;
}

static bool PayloadHookPassThroughTrampoline(const payload_tramp_match* match, payload_u64 type)
{
    if (!match || !match->tramp_va)
        return false;
    g_payload_hook_last_type = type;
    g_payload_hook_last_action = PAYLOAD_HOOK_ACTION_PASS;
    g_payload_hook_last_result = match->tramp_va;
    return PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, match->tramp_va);
}

static bool PayloadHookReturnToCaller(payload_guest_context* ctx, payload_u64 rsp, payload_u64 ret, payload_u64 result, payload_u64 type)
{
    if (!ctx || !rsp || !ret)
        return false;

    ctx->rax = result;
    if (!PayloadVmwrite(PAYLOAD_VMCS_GUEST_RSP, rsp + sizeof(payload_u64)) ||
        !PayloadVmwrite(PAYLOAD_VMCS_GUEST_RIP, ret))
    {
        return false;
    }

    g_payload_hook_last_type = type;
    g_payload_hook_last_action = PAYLOAD_HOOK_ACTION_SKIP_RETURN;
    g_payload_hook_last_retaddr = ret;
    g_payload_hook_last_result = result;
    return true;
}

static bool PayloadHookPrevByteIsCallTarget(payload_u64 guest_cr3, payload_u64 rip)
{
    if (rip < 8)
        return true;

    unsigned char p[7] = {};
    if (!PayloadGuestCopyToHostBuffer(guest_cr3, rip - 7, p, sizeof(p)))
        return true;

    if (p[2] == 0xE8)
        return true;
    if (p[1] == 0xFF && (p[2] == 0x15 || p[2] == 0x90))
        return true;
    if ((p[0] & 0xF0) == 0x40 && p[1] == 0xFF && (p[2] == 0x15 || p[2] == 0x90))
        return true;
    if (p[4] == 0xFF)
    {
        unsigned char m = p[5];
        if ((m & 0xF8) == 0xD0 || (m & 0xC7) == 0x50 || (m & 0xC7) == 0x10)
            return true;
    }
    if (p[5] == 0xFF)
    {
        unsigned char m = p[6];
        if ((m & 0xF8) == 0xD0 || (m & 0xC7) == 0x50 || (m & 0xC7) == 0x10)
            return true;
    }
    return false;
}

static bool PayloadHookCallerIsLegitDwmStrict(payload_u64 ret)
{
    if (!ret)
        return false;

    bool have_range = false;
    bool in_range = false;
    if (g_cached_hv_diag.dwmcore_base && g_cached_hv_diag.dwmcore_size)
    {
        have_range = true;
        in_range = in_range ||
            (ret >= g_cached_hv_diag.dwmcore_base &&
             ret < g_cached_hv_diag.dwmcore_base + g_cached_hv_diag.dwmcore_size);
    }
    if (g_cached_hv_diag.dxgi_base && g_cached_hv_diag.dxgi_size)
    {
        have_range = true;
        in_range = in_range ||
            (ret >= g_cached_hv_diag.dxgi_base &&
             ret < g_cached_hv_diag.dxgi_base + g_cached_hv_diag.dxgi_size);
    }
    if (have_range && !in_range)
        return false;

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return true;
    return PayloadHookPrevByteIsCallTarget(guest_cr3, ret);
}

static bool PayloadHookRangeOverlaps(payload_u64 base,
                                     payload_u64 bytes,
                                     payload_u64 va,
                                     payload_u64 size)
{
    if (!base || !bytes || !va)
        return false;
    if (!size)
        size = 1;

    payload_u64 limit = base + bytes;
    if (limit < base)
        limit = ~0ull;

    payload_u64 end = va + size;
    if (end < va)
        end = ~0ull;

    return va < limit && end > base;
}

static bool PayloadHookPaRangeOverlaps(payload_u64 base,
                                       payload_u64 bytes,
                                       payload_u64 pa,
                                       payload_u64 size)
{
    if (!base || !bytes || !pa)
        return false;
    if (!size)
        size = 1;

    payload_u64 limit = base + bytes;
    if (limit < base)
        limit = ~0ull;

    payload_u64 end = pa + size;
    if (end < pa)
        end = ~0ull;

    return pa < limit && end > base;
}

static bool PayloadHookVaRangeHasProtectedPa(payload_u64 base,
                                             payload_u64 bytes,
                                             payload_u64 pa,
                                             payload_u64 size)
{
    if (!base || !bytes || !pa || !g_system_cr3)
        return false;
    if (!size)
        size = 1;

    payload_u64 begin = base & ~0xFFFull;
    payload_u64 limit = base + bytes;
    if (limit < base)
        limit = ~0ull;
    payload_u64 end_va = (limit + 0xFFFull) & ~0xFFFull;
    if (end_va <= begin)
        end_va = limit;

    for (payload_u64 page = begin; page && page < end_va; page += 0x1000ull)
    {
        payload_u64 page_pa = 0;
        if (!PayloadKernelVaToPa(page, &page_pa) || !page_pa)
            continue;

        payload_u64 page_span = 0x1000ull;
        payload_u64 range_off = 0;
        if (page < base)
            range_off = base - page;
        if (range_off >= page_span)
            continue;

        payload_u64 valid_span = page_span - range_off;
        payload_u64 page_limit = page + page_span;
        if (limit < page_limit)
        {
            valid_span = (limit > page + range_off) ? (limit - (page + range_off)) : 0;
        }
        if (!valid_span)
            continue;

        if (PayloadHookPaRangeOverlaps(page_pa + range_off, valid_span, pa, size))
            return true;
    }

    return false;
}

static bool PayloadHookIsResidentPayloadVa(payload_u64 va, payload_u64 size)
{
    if (!size)
        size = 1;

    // 当前 payload-owned ranges.  In the final payload-only handoff these
    // are the ranges mapDriver hides/seals, so prefer them over legacy
    // TestDriver prot_ranges that may become stale after the carrier unloads.
    if (PayloadHookRangeOverlaps(g_image_base, g_image_size, va, size) ||
        PayloadHookRangeOverlaps(g_arena_base, g_arena_size, va, size) ||
        PayloadHookRangeOverlaps(g_direct_alloc_base, g_direct_alloc_size, va, size) ||
        PayloadHookRangeOverlaps(g_host_state_base, g_host_state_size, va, size) ||
        PayloadHookRangeOverlaps(g_host_stack_base, g_host_stack_size, va, size))
    {
        return true;
    }

    // Resident PoolManager blocks adopted from the carrier.  The manifest is
    // payload-owned and lives in the arena; root-模式 can still 读取 it even
    // after the guest-facing EPT entries have been redirected.
    payload_u64 manifest = g_resident_pool_manifest;
    payload_u64 count = g_resident_pool_count;
    payload_u64 capacity = g_resident_pool_capacity;
    if (manifest && count)
    {
        if (capacity && count > capacity)
            count = capacity;
        if (count > 4096)
            count = 4096;

        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_u64 entry = manifest + i * (payload_u64)sizeof(payload_pool_block);
            payload_u64 base = PayloadReadHostU64(entry + offsetof(payload_pool_block, va));
            payload_u64 bytes = PayloadReadHostU64(entry + offsetof(payload_pool_block, bytes));
            if (PayloadHookRangeOverlaps(base, bytes, va, size))
                return true;
        }
    }

    return false;
}

static bool PayloadHookIsResidentPayloadPa(payload_u64 pa, payload_u64 size)
{
    if (!size)
        size = 1;

    if (PayloadHookVaRangeHasProtectedPa(g_image_base, g_image_size, pa, size) ||
        PayloadHookVaRangeHasProtectedPa(g_arena_base, g_arena_size, pa, size) ||
        PayloadHookVaRangeHasProtectedPa(g_direct_alloc_base, g_direct_alloc_size, pa, size) ||
        PayloadHookVaRangeHasProtectedPa(g_host_state_base, g_host_state_size, pa, size) ||
        PayloadHookVaRangeHasProtectedPa(g_host_stack_base, g_host_stack_size, pa, size))
    {
        return true;
    }

    payload_u64 manifest = g_resident_pool_manifest;
    payload_u64 count = g_resident_pool_count;
    payload_u64 capacity = g_resident_pool_capacity;
    if (manifest && count)
    {
        if (capacity && count > capacity)
            count = capacity;
        if (count > 4096)
            count = 4096;

        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_u64 entry = manifest + i * (payload_u64)sizeof(payload_pool_block);
            payload_u64 base = PayloadReadHostU64(entry + offsetof(payload_pool_block, va));
            payload_u64 bytes = PayloadReadHostU64(entry + offsetof(payload_pool_block, bytes));
            if (PayloadHookVaRangeHasProtectedPa(base, bytes, pa, size))
                return true;
        }
    }

    return false;
}

static bool PayloadHookIsLegacyProtectedVa(payload_u64 va, payload_u64 size)
{
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv) ||
        !g_cached_hv_diag.ghv_off_prot_ranges ||
        !g_cached_hv_diag.ghv_off_prot_range_count ||
        !g_cached_hv_diag.ghv_prot_range_stride)
    {
        return false;
    }

    if (!size)
        size = 1;
    payload_u64 end = va + size;
    if (end < va)
        end = ~0ull;

    payload_u64 count = PayloadReadHostU32(g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_prot_range_count);
    if (g_cached_hv_diag.ghv_prot_range_capacity && count > g_cached_hv_diag.ghv_prot_range_capacity)
        count = g_cached_hv_diag.ghv_prot_range_capacity;
    if (count > 4096)
        count = 4096;

    payload_u64 ranges = g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_prot_ranges;
    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 r = ranges + i * g_cached_hv_diag.ghv_prot_range_stride;
        payload_u64 base = PayloadReadHostU64(r + g_cached_hv_diag.ghv_prot_range_off_base);
        payload_u64 limit = PayloadReadHostU64(r + g_cached_hv_diag.ghv_prot_range_off_end);
        if (base && limit > base && va < limit && end > base)
            return true;
    }
    return false;
}

static bool PayloadHookIsLegacyProtectedPa(payload_u64 pa, payload_u64 size)
{
    if (!g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv) ||
        !g_cached_hv_diag.ghv_off_prot_ranges ||
        !g_cached_hv_diag.ghv_off_prot_range_count ||
        !g_cached_hv_diag.ghv_prot_range_stride)
    {
        return false;
    }

    if (!size)
        size = 1;

    payload_u64 count = PayloadReadHostU32(g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_prot_range_count);
    if (g_cached_hv_diag.ghv_prot_range_capacity && count > g_cached_hv_diag.ghv_prot_range_capacity)
        count = g_cached_hv_diag.ghv_prot_range_capacity;
    if (count > 4096)
        count = 4096;

    payload_u64 ranges = g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_prot_ranges;
    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 r = ranges + i * g_cached_hv_diag.ghv_prot_range_stride;
        payload_u64 base = PayloadReadHostU64(r + g_cached_hv_diag.ghv_prot_range_off_base);
        payload_u64 limit = PayloadReadHostU64(r + g_cached_hv_diag.ghv_prot_range_off_end);
        if (base && limit > base &&
            PayloadHookVaRangeHasProtectedPa(base, limit - base, pa, size))
        {
            return true;
        }
    }
    return false;
}

struct payload_protect_catalog_va_range
{
    payload_u64 base;
    payload_u64 end;
};

struct payload_protect_catalog_pfn_range
{
    payload_u64 first;
    payload_u64 last;
};

static constexpr payload_u64 PAYLOAD_PROTECT_VA_RANGE_CAPACITY = 8192;
static constexpr payload_u64 PAYLOAD_PROTECT_PFN_CAPACITY = 65536;
static payload_protect_catalog_va_range* g_payload_protect_va_ranges = nullptr;
static payload_protect_catalog_pfn_range* g_payload_protect_pfn_ranges = nullptr;
static payload_u64* g_payload_protect_pfns = nullptr;
static volatile payload_u64 g_payload_protect_va_count = 0;
static volatile payload_u64 g_payload_protect_pfn_range_count = 0;
static volatile payload_u64 g_payload_protect_signature = 0;
static volatile payload_u64 g_payload_protect_overflow = 0;
static volatile LONG g_payload_protect_lock = 0;

static void PayloadProtectLock()
{
    while (_InterlockedCompareExchange(&g_payload_protect_lock, 1, 0) != 0)
        _mm_pause();
}

static void PayloadProtectUnlock()
{
    _InterlockedExchange(&g_payload_protect_lock, 0);
}

static payload_u64 PayloadProtectSignature()
{
    payload_u64 sig = 0x504C4450524F5431ull; // PLDPROT1
    sig ^= g_image_base + (g_image_size << 7);
    sig ^= g_arena_base + (g_arena_size << 11);
    sig ^= g_direct_alloc_base + (g_direct_alloc_size << 13);
    sig ^= g_host_state_base + (g_host_state_size << 17);
    sig ^= g_host_stack_base + (g_host_stack_size << 19);
    sig ^= g_resident_pool_manifest + (g_resident_pool_count << 23);
    sig ^= (g_resident_pool_generation << 29);
    sig ^= g_legacy_detach_flags;
    if ((g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0 &&
        g_hv_diag_cache_ready &&
        PayloadIsKernelPointer(g_cached_hv_diag.ghv) &&
        g_cached_hv_diag.ghv_off_prot_range_count)
    {
        sig ^= ((payload_u64)PayloadReadHostU32(
            g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_prot_range_count) << 31);
    }
    return sig ? sig : 1;
}

static bool PayloadProtectEnsureStorage()
{
    if (g_payload_protect_va_ranges &&
        g_payload_protect_pfn_ranges &&
        g_payload_protect_pfns)
    {
        return true;
    }

    g_payload_protect_va_ranges =
        (payload_protect_catalog_va_range*)PayloadArenaAlloc(
            sizeof(payload_protect_catalog_va_range) * PAYLOAD_PROTECT_VA_RANGE_CAPACITY,
            16);
    g_payload_protect_pfn_ranges =
        (payload_protect_catalog_pfn_range*)PayloadArenaAlloc(
            sizeof(payload_protect_catalog_pfn_range) * PAYLOAD_PROTECT_PFN_CAPACITY,
            16);
    g_payload_protect_pfns =
        (payload_u64*)PayloadArenaAlloc(
            sizeof(payload_u64) * PAYLOAD_PROTECT_PFN_CAPACITY,
            16);

    return g_payload_protect_va_ranges &&
        g_payload_protect_pfn_ranges &&
        g_payload_protect_pfns;
}

static void PayloadProtectSortVaRanges(payload_protect_catalog_va_range* ranges, payload_u64 count)
{
    for (payload_u64 gap = count / 2; gap; gap /= 2)
    {
        for (payload_u64 i = gap; i < count; ++i)
        {
            auto tmp = ranges[i];
            payload_u64 j = i;
            while (j >= gap)
            {
                auto prev = ranges[j - gap];
                if (prev.base < tmp.base || (prev.base == tmp.base && prev.end <= tmp.end))
                    break;
                ranges[j] = prev;
                j -= gap;
            }
            ranges[j] = tmp;
        }
    }
}

static void PayloadProtectSortPfns(payload_u64* pfns, payload_u64 count)
{
    for (payload_u64 gap = count / 2; gap; gap /= 2)
    {
        for (payload_u64 i = gap; i < count; ++i)
        {
            payload_u64 tmp = pfns[i];
            payload_u64 j = i;
            while (j >= gap && pfns[j - gap] > tmp)
            {
                pfns[j] = pfns[j - gap];
                j -= gap;
            }
            pfns[j] = tmp;
        }
    }
}

static void PayloadProtectAddRange(payload_u64 base,
                                   payload_u64 bytes,
                                   payload_u64* va_count,
                                   payload_u64* pfn_count,
                                   bool* overflow)
{
    if (!base || !bytes || !va_count || !pfn_count || !overflow)
        return;

    payload_u64 limit = base + bytes;
    if (limit < base)
        limit = ~0ull;
    if (limit <= base)
        return;

    if (*va_count < PAYLOAD_PROTECT_VA_RANGE_CAPACITY)
    {
        g_payload_protect_va_ranges[*va_count].base = base;
        g_payload_protect_va_ranges[*va_count].end = limit;
        (*va_count)++;
    }
    else
    {
        *overflow = true;
    }

    payload_u64 begin = base & ~0xFFFull;
    payload_u64 end = (limit + 0xFFFull) & ~0xFFFull;
    if (end <= begin)
        end = limit;
    for (payload_u64 page = begin; page && page < end; page += 0x1000ull)
    {
        payload_u64 pa = 0;
        if (!PayloadKernelVaToPa(page, &pa) || !pa)
            continue;
        if (*pfn_count < PAYLOAD_PROTECT_PFN_CAPACITY)
        {
            g_payload_protect_pfns[*pfn_count] = pa >> 12;
            (*pfn_count)++;
        }
        else
        {
            *overflow = true;
            break;
        }
    }
}

static bool PayloadProtectRebuildLocked(payload_u64 sig)
{
    if (!PayloadProtectEnsureStorage())
        return false;

    payload_u64 va_count = 0;
    payload_u64 pfn_count = 0;
    bool overflow = false;

    PayloadProtectAddRange(g_image_base, g_image_size, &va_count, &pfn_count, &overflow);
    PayloadProtectAddRange(g_arena_base, g_arena_size, &va_count, &pfn_count, &overflow);
    PayloadProtectAddRange(g_direct_alloc_base, g_direct_alloc_size, &va_count, &pfn_count, &overflow);
    PayloadProtectAddRange(g_host_state_base, g_host_state_size, &va_count, &pfn_count, &overflow);
    PayloadProtectAddRange(g_host_stack_base, g_host_stack_size, &va_count, &pfn_count, &overflow);

    payload_u64 manifest = g_resident_pool_manifest;
    payload_u64 count = g_resident_pool_count;
    payload_u64 capacity = g_resident_pool_capacity;
    if (manifest && count)
    {
        if (capacity && count > capacity)
            count = capacity;
        if (count > 4096)
            count = 4096;
        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_u64 entry = manifest + i * (payload_u64)sizeof(payload_pool_block);
            payload_u64 base = PayloadReadHostU64(entry + offsetof(payload_pool_block, va));
            payload_u64 bytes = PayloadReadHostU64(entry + offsetof(payload_pool_block, bytes));
            PayloadProtectAddRange(base, bytes, &va_count, &pfn_count, &overflow);
        }
    }

    if ((g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0 &&
        g_hv_diag_cache_ready &&
        PayloadIsKernelPointer(g_cached_hv_diag.ghv) &&
        g_cached_hv_diag.ghv_off_prot_ranges &&
        g_cached_hv_diag.ghv_off_prot_range_count &&
        g_cached_hv_diag.ghv_prot_range_stride)
    {
        payload_u64 legacy_count = PayloadReadHostU32(
            g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_prot_range_count);
        if (g_cached_hv_diag.ghv_prot_range_capacity &&
            legacy_count > g_cached_hv_diag.ghv_prot_range_capacity)
            legacy_count = g_cached_hv_diag.ghv_prot_range_capacity;
        if (legacy_count > 4096)
            legacy_count = 4096;

        payload_u64 ranges = g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_prot_ranges;
        for (payload_u64 i = 0; i < legacy_count; ++i)
        {
            payload_u64 r = ranges + i * g_cached_hv_diag.ghv_prot_range_stride;
            payload_u64 base = PayloadReadHostU64(r + g_cached_hv_diag.ghv_prot_range_off_base);
            payload_u64 limit = PayloadReadHostU64(r + g_cached_hv_diag.ghv_prot_range_off_end);
            if (base && limit > base)
                PayloadProtectAddRange(base, limit - base, &va_count, &pfn_count, &overflow);
        }
    }

    if (va_count)
    {
        PayloadProtectSortVaRanges(g_payload_protect_va_ranges, va_count);
        payload_u64 out = 0;
        for (payload_u64 i = 0; i < va_count; ++i)
        {
            auto r = g_payload_protect_va_ranges[i];
            if (!r.base || r.end <= r.base)
                continue;
            if (out && r.base <= g_payload_protect_va_ranges[out - 1].end)
            {
                if (r.end > g_payload_protect_va_ranges[out - 1].end)
                    g_payload_protect_va_ranges[out - 1].end = r.end;
            }
            else
            {
                g_payload_protect_va_ranges[out++] = r;
            }
        }
        va_count = out;
    }

    payload_u64 pfn_range_count = 0;
    if (pfn_count)
    {
        PayloadProtectSortPfns(g_payload_protect_pfns, pfn_count);
        payload_u64 start = g_payload_protect_pfns[0];
        payload_u64 last = start;
        for (payload_u64 i = 1; i < pfn_count; ++i)
        {
            payload_u64 p = g_payload_protect_pfns[i];
            if (p == last || p == last + 1)
            {
                if (p > last)
                    last = p;
                continue;
            }
            if (pfn_range_count < PAYLOAD_PROTECT_PFN_CAPACITY)
                g_payload_protect_pfn_ranges[pfn_range_count++] = { start, last };
            else
                overflow = true;
            start = last = p;
        }
        if (pfn_range_count < PAYLOAD_PROTECT_PFN_CAPACITY)
            g_payload_protect_pfn_ranges[pfn_range_count++] = { start, last };
        else
            overflow = true;
    }

    g_payload_protect_va_count = va_count;
    g_payload_protect_pfn_range_count = pfn_range_count;
    g_payload_protect_overflow = overflow ? 1ull : 0ull;
    g_payload_protect_signature = sig;
    return !overflow;
}

static bool PayloadProtectEnsureCatalog()
{
    payload_u64 sig = PayloadProtectSignature();
    if (g_payload_protect_signature == sig &&
        g_payload_protect_va_ranges &&
        g_payload_protect_pfn_ranges)
    {
        return g_payload_protect_overflow == 0;
    }

    PayloadProtectLock();
    if (g_payload_protect_signature != sig ||
        !g_payload_protect_va_ranges ||
        !g_payload_protect_pfn_ranges)
    {
        PayloadProtectRebuildLocked(sig);
    }
    bool ok = g_payload_protect_overflow == 0;
    PayloadProtectUnlock();
    return ok;
}

static bool PayloadProtectCatalogContainsVa(payload_u64 va, payload_u64 size)
{
    if (!PayloadProtectEnsureCatalog())
        return false;
    if (!size)
        size = 1;
    payload_u64 end = va + size;
    if (end < va)
        end = ~0ull;

    payload_u64 count = g_payload_protect_va_count;
    payload_u64 lo = 0;
    payload_u64 hi = count;
    while (lo < hi)
    {
        payload_u64 mid = lo + ((hi - lo) >> 1);
        if (g_payload_protect_va_ranges[mid].end <= va)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo < count && g_payload_protect_va_ranges[lo].base < end;
}

static bool PayloadProtectCatalogContainsPa(payload_u64 pa, payload_u64 size)
{
    if (!PayloadProtectEnsureCatalog())
        return false;
    if (!size)
        size = 1;

    payload_u64 first = pa >> 12;
    payload_u64 last = (pa + size - 1) >> 12;
    if ((pa + size - 1) < pa)
        last = ~0ull;

    payload_u64 count = g_payload_protect_pfn_range_count;
    payload_u64 lo = 0;
    payload_u64 hi = count;
    while (lo < hi)
    {
        payload_u64 mid = lo + ((hi - lo) >> 1);
        if (g_payload_protect_pfn_ranges[mid].last < first)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo < count && g_payload_protect_pfn_ranges[lo].first <= last;
}

static bool PayloadHookIsProtectedVa(payload_u64 va, payload_u64 size)
{
    if (PayloadProtectCatalogContainsVa(va, size))
        return true;

    if (PayloadHookIsResidentPayloadVa(va, size))
        return true;

    // Before legacy detach completes, keep the old TestDriver prot_ranges as a
    // compatibility fallback.  After detach, those ranges can refer to carrier
    // image/pool VAs that have been unloaded or reused, so payload-only hooks
    // must not filter on them.
    if ((g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0)
        return PayloadHookIsLegacyProtectedVa(va, size);

    return false;
}

static bool PayloadHookIsProtectedPa(payload_u64 pa, payload_u64 size)
{
    if (PayloadProtectCatalogContainsPa(pa, size))
        return true;

    if (PayloadHookIsResidentPayloadPa(pa, size))
        return true;

    if ((g_legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0)
        return PayloadHookIsLegacyProtectedPa(pa, size);

    return false;
}

static payload_u64 PayloadHookFillWithFake(payload_u64 target_gva, payload_u64 size)
{
    if (!target_gva || !size ||
        !g_hv_diag_cache_ready ||
        !PayloadIsKernelPointer(g_cached_hv_diag.ghv) ||
        !g_cached_hv_diag.ghv_off_fake_data)
    {
        return 0;
    }

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return 0;

    payload_u64 fake = g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_fake_data;
    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 cur = target_gva + done;
        payload_u64 dst_left = 0;
        auto dst = PayloadGvaToHvaCr3(guest_cr3, cur, &dst_left);
        if (!dst || !dst_left)
            break;

        payload_u64 page_room = 0x1000ull - (cur & 0xFFFull);
        payload_u64 fake_off = cur & 0xFFFull;
        payload_u64 chunk = PayloadMinU64(size - done, PayloadMinU64(dst_left, page_room));
        PayloadCopyMemory(dst, (void*)(fake + fake_off), chunk);
        done += chunk;
    }

    return done;
}

static void PayloadHookNotifyCaptureAttempt()
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_capture_notify_count);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_capture_notify_count);

    constexpr payload_u64 kHideCycles = 3000000000ull * 5ull;
    payload_u64 target = __rdtsc() + kHideCycles;
    volatile LONG64* field = (volatile LONG64*)&g_payload_overlay_hide_until_tsc;
    LONG64 old = 0;
    do
    {
        old = *field;
        if ((LONG64)target <= old)
            return;
    } while (_InterlockedCompareExchange64(field, (LONG64)target, old) != old);
}

static payload_u64 PayloadHookHandleGetBuffer(payload_guest_context* ctx, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_hits);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_getbuffer_hits);

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (!PayloadHookReadGuestRspRet(&rsp, &ret))
        return PayloadHookPassThroughTrampoline(match, 3) ? 1 : 0;
    g_payload_hook_last_retaddr = ret;

#if !PAYLOAD_FORCE_GETBUFFER_PURPLE
    if (PayloadHookIsLegacyBlankRip(ret))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_pass);
        return PayloadHookPassThroughTrampoline(match, 3) ? 1 : 0;
    }
#endif

    bool alien = !PayloadHookCallerIsLegitDwmStrict(ret);
    if (alien)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_alien);
        PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_getbuffer_alien);
    }

#if PAYLOAD_FORCE_GETBUFFER_PURPLE
    // Purple build: when the hook is active every handled GetBuffer must return
    // the purple-backed fakeTexture and skip original dxgi::GetBuffer.
    //
    // Important: do not explain old GetBuffer crashes as a fixed prologue
    // pattern.  The observed failure class is a bad/missing trampoline match
    // or a return-to-generic path after the VMCALL hook already fired.  The
    // 分发 layer now direct-claims type3 from vt_hook_table and carries
    // slot.trampoline_va/bp_rip/target_resume, so any remaining pass-through
    // fallback is deterministic.  For the purple validation build we still
    // prefer a closed short-return when the substitute texture is unavailable.
#else
    if (!g_payload_pmo_fake_texture ||
        (alien && (!g_payload_pmo_marker_ready || !g_payload_pmo_marker_texture)))
    {
        if (!PayloadPmoTryInitRenderState(ctx) ||
            !g_payload_pmo_fake_texture ||
            (alien && (!g_payload_pmo_marker_ready || !g_payload_pmo_marker_texture)))
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_pass);
            return PayloadHookPassThroughTrampoline(match, 3) ? 1 : 0;
        }
    }
#endif

    payload_u64 out_pp = ctx ? ctx->r9 : 0;
#if PAYLOAD_FORCE_GETBUFFER_PURPLE
    payload_u64 texture =
        (g_payload_pmo_fake_texture &&
         g_payload_pmo_marker_ready &&
         g_payload_pmo_marker_texture)
            ? g_payload_pmo_fake_texture
            : 0;
#else
    payload_u64 texture = alien ? g_payload_pmo_marker_texture : g_payload_pmo_fake_texture;
#endif
    payload_u64 guest_cr3 = 0;
    bool wrote_out = false;
    if (out_pp &&
        PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3))
    {
        wrote_out = PayloadGuestWriteU64(guest_cr3, out_pp, texture);
    }

    if (!texture || !wrote_out)
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_pass);
        return PayloadHookReturnToCaller(ctx, rsp, ret, 0x80004005ull, 3) ? 1 : 0;
    }

    g_payload_pmo_last_getbuffer_out = out_pp;
#if PAYLOAD_FORCE_GETBUFFER_PURPLE
    _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_marker);
#else
    if (alien && texture == g_payload_pmo_marker_texture)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_marker);
#endif
    _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_substitute);
    return PayloadHookReturnToCaller(ctx, rsp, ret, texture ? 0 : 0x80004005ull, 3) ? 1 : 0;
}

static payload_u64 PayloadHookHandlePresentLike(payload_guest_context* ctx,
                                                const payload_tramp_match* match,
                                                payload_u64 type,
                                                volatile payload_u64* hits,
                                                volatile payload_u64* alien_hits,
                                                payload_u64 ghv_hits_off,
                                                payload_u64 ghv_alien_off)
{
    _InterlockedIncrement64((volatile LONG64*)hits);
    PayloadHookIncrementGhvCounter(ghv_hits_off);

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (!PayloadHookReadGuestRspRet(&rsp, &ret))
        return PayloadHookPassThroughTrampoline(match, type) ? 1 : 0;

    if (PayloadHookIsLegacyBlankRip(ret) || PayloadHookCallerIsLegitDwmStrict(ret))
        return PayloadHookPassThroughTrampoline(match, type) ? 1 : 0;

    _InterlockedIncrement64((volatile LONG64*)alien_hits);
    PayloadHookIncrementGhvCounter(ghv_alien_off);
    return PayloadHookReturnToCaller(ctx, rsp, ret, 0x887A0007ull, type) ? 1 : 0;
}

static payload_u64 PayloadHookHandleCopyResource(payload_guest_context*, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_copyresource_hits);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_copyresource_hits);
    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (PayloadHookReadGuestRspRet(&rsp, &ret) &&
        !PayloadHookIsLegacyBlankRip(ret) &&
        !PayloadHookCallerIsLegitDwmStrict(ret))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_copyresource_alien);
        PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_copyresource_alien);
    }
    return PayloadHookPassThroughTrampoline(match, 11) ? 1 : 0;
}

static payload_u64 PayloadHookHandleDuplicateOutput(payload_guest_context* ctx, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_duplicateoutput_hits);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_duplicateoutput_hits);

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (!PayloadHookReadGuestRspRet(&rsp, &ret))
        return PayloadHookPassThroughTrampoline(match, 12) ? 1 : 0;

    if (PayloadHookIsLegacyBlankRip(ret) || PayloadHookCallerIsLegitDwmStrict(ret))
        return PayloadHookPassThroughTrampoline(match, 12) ? 1 : 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_duplicateoutput_alien);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_duplicateoutput_alien);
    payload_u64 guest_cr3 = 0;
    if (ctx && ctx->r8 && PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3))
        PayloadGuestWriteU64(guest_cr3, ctx->r8, 0);
    return PayloadHookReturnToCaller(ctx, rsp, ret, 0x887A0022ull, 12) ? 1 : 0;
}

static bool PayloadHookExecuteProtect(payload_u64 protect)
{
    return (protect & 0xF0ull) != 0;
}

static payload_u64 PayloadHookHandleNtMemoryEvent(payload_guest_context* ctx, const payload_tramp_match* match, payload_u64 type)
{
    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    auto rsp_ok = PayloadHookReadGuestRspRet(&rsp, &ret);
    (void)ret;

    switch (type)
    {
    case 14:
        _InterlockedIncrement64((volatile LONG64*)&g_payload_ntsetevent_hits);
        PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmcopy_hits);
        if (rsp_ok)
            PayloadHookWriteGhvU64(g_cached_hv_diag.ghv_off_diag_mmcopy_last_caller_rip, ret);
        break;
    case 15:
        _InterlockedIncrement64((volatile LONG64*)&g_payload_nt_alloc_hits);
        PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_alloc_hits);
        if (rsp_ok)
        {
            auto rsp_hva = (payload_u64*)PayloadGvaToHva(rsp, sizeof(payload_u64) * 7);
            payload_u64 protect = rsp_hva ? rsp_hva[6] : 0;
            if (PayloadHookExecuteProtect(protect))
            {
                _InterlockedIncrement64((volatile LONG64*)&g_payload_nt_alloc_alien);
                PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_alloc_alien);
                PayloadHookNotifyCaptureAttempt();
            }
        }
        break;
    case 16:
        _InterlockedIncrement64((volatile LONG64*)&g_payload_nt_protect_hits);
        PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_protect_hits);
        if (ctx && PayloadHookExecuteProtect(ctx->r9))
        {
            _InterlockedIncrement64((volatile LONG64*)&g_payload_nt_protect_alien);
            PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_protect_alien);
            PayloadHookNotifyCaptureAttempt();
        }
        break;
    case 17:
        _InterlockedIncrement64((volatile LONG64*)&g_payload_nt_map_hits);
        PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_map_hits);
        if (rsp_ok)
        {
            auto rsp_hva = (payload_u64*)PayloadGvaToHva(rsp, sizeof(payload_u64) * 11);
            payload_u64 protect = rsp_hva ? rsp_hva[10] : 0;
            if (PayloadHookExecuteProtect(protect))
            {
                _InterlockedIncrement64((volatile LONG64*)&g_payload_nt_map_alien);
                PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_map_alien);
                PayloadHookNotifyCaptureAttempt();
            }
        }
        break;
    default:
        break;
    }
    return PayloadHookPassThroughTrampoline(match, type) ? 1 : 0;
}

static bool PayloadHookNtStatusFailed(payload_u64 status)
{
    return ((unsigned int)status & 0x80000000u) != 0;
}

#if PAYLOAD_ENABLE_NT_CSEC_KERNEL_CALLOUT
static bool PayloadHookResolveNtCreateSectionFileName(payload_guest_context* ctx,
                                                      payload_u64 guest_cr3,
                                                      payload_u64 file_handle)
{
    if (!ctx || !guest_cr3 || !file_handle ||
        !PayloadIsKernelPointer(g_cached_hv_diag.ob_reference_object_by_handle_va) ||
        !PayloadIsKernelPointer(g_cached_hv_diag.obf_dereference_object_va) ||
        !g_cached_hv_diag.ntapi_file_name_offset ||
        g_cached_hv_diag.ntapi_file_name_offset > 0x1000ull)
    {
        return false;
    }

    payload_u64 scratch = PayloadPmoReadGhvFieldU64(g_cached_hv_diag.ghv_off_csec_scratch_va);
    if (!PayloadIsKernelPointer(scratch))
        return false;

    // TestDriver used csec_scratch[0] as the shared out slot.  That can race
    // if two DWM threads hit NtCreateSection on different vCPUs, so payload
    // uses one 8-byte slot per vCPU inside the same 4KB scratch page.
    payload_u64 vcpu = PayloadCurrentVcpuIndex();
    if (vcpu == ~0ull || vcpu >= 512ull)
        vcpu = 0;
    payload_u64 out_slot = scratch + vcpu * sizeof(payload_u64);
    if (!PayloadGuestWriteU64(guest_cr3, out_slot, 0))
        return false;

    payload_u64 args[6] = {
        file_handle, // Handle
        0,           // DesiredAccess
        0,           // ObjectType
        1,           // AccessMode = UserMode; FileHandle comes from Nt* caller
        out_slot,    // PVOID* Object
        0            // HandleInformation
    };

    payload_u64 status = 0;
    if (!PayloadPmoCallKernel(
            ctx,
            g_cached_hv_diag.ob_reference_object_by_handle_va,
            args,
            6,
            &status) ||
        PayloadHookNtStatusFailed(status))
    {
        return false;
    }

    payload_u64 file_obj = 0;
    if (!PayloadGuestCopyToHostBuffer(guest_cr3, out_slot, &file_obj, sizeof(file_obj)) ||
        !PayloadIsKernelPointer(file_obj))
    {
        return false;
    }

    bool name_readable = false;
    do
    {
        unsigned char unicode[16] = {};
        if (!PayloadGuestCopyToHostBuffer(
                guest_cr3,
                file_obj + g_cached_hv_diag.ntapi_file_name_offset,
                unicode,
                sizeof(unicode)))
        {
            break;
        }

        unsigned short name_len_bytes = *(unsigned short*)(unicode + 0);
        payload_u64 name_buf = *(payload_u64*)(unicode + 8);
        payload_u64 name_len_chars = (payload_u64)name_len_bytes / sizeof(wchar_t);
        if (!name_buf || !name_len_chars || name_len_chars >= 1024ull)
            break;

        // We no longer CallKernel(DbgPrintEx), so do not copy the full name into
        // shared scratch.  Just prove the UNICODE_STRING 缓冲区 is readable;
        // this keeps the old "filename resolved" diagnostic without the
        // previous scratch-race/re-条目项 surface.
        unsigned short probe = 0;
        if (!PayloadGuestCopyToHostBuffer(guest_cr3, name_buf, &probe, sizeof(probe)))
            break;

        if (name_len_bytes > sizeof(wchar_t) &&
            !PayloadGuestCopyToHostBuffer(
                guest_cr3,
                name_buf + name_len_bytes - sizeof(wchar_t),
                &probe,
                sizeof(probe)))
        {
            break;
        }

        name_readable = true;
    } while (false);

    payload_u64 deref_arg[1] = { file_obj };
    PayloadPmoCallKernel(
        ctx,
        g_cached_hv_diag.obf_dereference_object_va,
        deref_arg,
        1,
        nullptr);

    return name_readable;
}
#endif

static payload_u64 PayloadHookHandleNtCreateSection(payload_guest_context* ctx, const payload_tramp_match* match)
{
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_csec_hits);

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (PayloadHookReadGuestRspRet(&rsp, &ret))
    {
        g_payload_hook_last_retaddr = ret;
        auto rsp_hva = (payload_u64*)PayloadGvaToHva(rsp, sizeof(payload_u64) * 8);
        if (rsp_hva)
        {
            constexpr payload_u64 kSecImage = 0x01000000ull;
            payload_u64 alloc_attr = rsp_hva[6];
            payload_u64 file_handle = rsp_hva[7];
            if ((alloc_attr & kSecImage) && file_handle)
            {
                PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_csec_image);
#if PAYLOAD_ENABLE_NT_CSEC_KERNEL_CALLOUT
                payload_u64 guest_cr3 = 0;
                if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) &&
                    PayloadHookResolveNtCreateSectionFileName(ctx, guest_cr3, file_handle))
                {
                    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_csec_alien);
                }
#else
                (void)ctx;
                PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_nt_csec_alien);
#endif
            }
        }
    }

    return PayloadHookPassThroughTrampoline(match, 6) ? 1 : 0;
}

static payload_u64 PayloadHookHandleLegacyObserveRetaddr(const payload_tramp_match* match, payload_u64 type)
{
    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (PayloadHookReadGuestRspRet(&rsp, &ret))
    {
        g_payload_hook_last_retaddr = ret;
        if (type == 13)
        {
            PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmcopy_hits);
            PayloadHookWriteGhvU64(g_cached_hv_diag.ghv_off_diag_mmcopy_last_caller_rip, ret);
        }
    }
    return PayloadHookPassThroughTrampoline(match, type) ? 1 : 0;
}

static void PayloadHookRecordMm4Hit(payload_u64 type)
{
    payload_u64 vcpu = PayloadCurrentVcpuIndex();
    g_payload_mm4_hit_last_type = type;
    g_payload_mm4_hit_last_vcpu = vcpu;
    if (vcpu < 64)
        _InterlockedOr64((volatile LONG64*)&g_payload_mm4_hit_vcpu_bitmap, (LONG64)(1ull << vcpu));
    if (vcpu == 0)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_mm4_hit_vcpu0);

    volatile payload_u64* type_last_vcpu = nullptr;
    volatile payload_u64* type_bitmap = nullptr;
    volatile payload_u64* type_vcpu0 = nullptr;
    switch (type)
    {
    case 18:
        type_last_vcpu = &g_payload_mm4_hit_type18_last_vcpu;
        type_bitmap = &g_payload_mm4_hit_type18_vcpu_bitmap;
        type_vcpu0 = &g_payload_mm4_hit_type18_vcpu0;
        break;
    case 19:
        type_last_vcpu = &g_payload_mm4_hit_type19_last_vcpu;
        type_bitmap = &g_payload_mm4_hit_type19_vcpu_bitmap;
        type_vcpu0 = &g_payload_mm4_hit_type19_vcpu0;
        break;
    case 20:
        type_last_vcpu = &g_payload_mm4_hit_type20_last_vcpu;
        type_bitmap = &g_payload_mm4_hit_type20_vcpu_bitmap;
        type_vcpu0 = &g_payload_mm4_hit_type20_vcpu0;
        break;
    case 21:
        type_last_vcpu = &g_payload_mm4_hit_type21_last_vcpu;
        type_bitmap = &g_payload_mm4_hit_type21_vcpu_bitmap;
        type_vcpu0 = &g_payload_mm4_hit_type21_vcpu0;
        break;
    default:
        break;
    }

    if (type_last_vcpu)
        *type_last_vcpu = vcpu;
    if (type_bitmap && vcpu < 64)
        _InterlockedOr64((volatile LONG64*)type_bitmap, (LONG64)(1ull << vcpu));
    if (type_vcpu0 && vcpu == 0)
        _InterlockedIncrement64((volatile LONG64*)type_vcpu0);
}

static payload_u64 PayloadHookHandleMmCopyMemory(payload_guest_context* ctx, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmcm_hits);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmcm_hits);
    PayloadHookRecordMm4Hit(18);
    if (!ctx)
        return PayloadHookPassThroughTrampoline(match, 18) ? 1 : 0;

    payload_u64 flags = ctx->r9;
    payload_u64 src = ctx->rdx;
    payload_u64 size = ctx->r8;
    bool protected_source = false;
    // WDK: MM_COPY_MEMORY_PHYSICAL=0x1, MM_COPY_MEMORY_VIRTUAL=0x2.
    if (flags & 2ull)
        protected_source = PayloadHookIsProtectedVa(src, size);
    else if (flags & 1ull)
        protected_source = PayloadHookIsProtectedPa(src, size);
    if (!protected_source)
        return PayloadHookPassThroughTrampoline(match, 18) ? 1 : 0;

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (!PayloadHookReadGuestRspRet(&rsp, &ret))
        return PayloadHookPassThroughTrampoline(match, 18) ? 1 : 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmcm_blocked);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmcm_blocked);
#if VT_MMCM_SKIP_PROTECTED_NO_TOUCH
    // Bisect: prove the hook can claim a protected MmCopyMemory call without
    // falling through to the original hidden-page 读取 and without touching
    // caller output buffers from VMX-root.  If this is stable, re-启用 the
    // BytesTransferred 写入 first, then fake-缓冲区 copy.
    return PayloadHookReturnToCaller(ctx, rsp, ret, 0, 18) ? 1 : 0;
#endif
    PayloadHookFillWithFake(ctx->rcx, size);

    auto rsp_hva = (payload_u64*)PayloadGvaToHva(rsp, sizeof(payload_u64) * 6);
    if (rsp_hva && rsp_hva[5])
    {
        payload_u64 guest_cr3 = 0;
        if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3))
            PayloadGuestWriteU64(guest_cr3, rsp_hva[5], size);
    }
    return PayloadHookReturnToCaller(ctx, rsp, ret, 0, 18) ? 1 : 0;
}

static payload_u64 PayloadHookHandleMmCopyVirtualMemory(payload_guest_context* ctx, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmcvm_hits);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmcvm_hits);
    PayloadHookRecordMm4Hit(19);
    if (!ctx)
        return PayloadHookPassThroughTrampoline(match, 19) ? 1 : 0;

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (!PayloadHookReadGuestRspRet(&rsp, &ret))
        return PayloadHookPassThroughTrampoline(match, 19) ? 1 : 0;
    auto rsp_hva = (payload_u64*)PayloadGvaToHva(rsp, sizeof(payload_u64) * 8);
    payload_u64 size = rsp_hva ? rsp_hva[5] : 0;
    if (!PayloadHookIsProtectedVa(ctx->rdx, size))
        return PayloadHookPassThroughTrampoline(match, 19) ? 1 : 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmcvm_blocked);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmcvm_blocked);
    PayloadHookFillWithFake(ctx->r9, size);
    if (rsp_hva && rsp_hva[7])
    {
        payload_u64 guest_cr3 = 0;
        if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3))
            PayloadGuestWriteU64(guest_cr3, rsp_hva[7], size);
    }
    return PayloadHookReturnToCaller(ctx, rsp, ret, 0, 19) ? 1 : 0;
}

static payload_u64 PayloadHookHandleMmIsAddressValid(payload_guest_context* ctx, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmisav_hits);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmisav_hits);
    PayloadHookRecordMm4Hit(20);
#if VT_MMISAV_FORCE_LOCAL_RETURN
    if (ctx)
    {
        payload_u64 rsp = 0;
        payload_u64 ret = 0;
        if (PayloadHookReadGuestRspRet(&rsp, &ret))
        {
            payload_u64 valid = (payload_u64)VT_MMISAV_FORCE_LOCAL_RESULT;
            return PayloadHookReturnToCaller(ctx, rsp, ret, valid, 20) ? 1 : 0;
        }
    }
#endif
    if (!ctx || !PayloadHookIsProtectedVa(ctx->rcx, 1))
        return PayloadHookPassThroughTrampoline(match, 20) ? 1 : 0;

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (!PayloadHookReadGuestRspRet(&rsp, &ret))
        return PayloadHookPassThroughTrampoline(match, 20) ? 1 : 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmisav_blocked);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmisav_blocked);
    return PayloadHookReturnToCaller(ctx, rsp, ret, 1, 20) ? 1 : 0;
}

static payload_u64 PayloadHookHandleMmMapIoSpace(payload_guest_context* ctx, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmmio_hits);
    PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmmio_hits);
    PayloadHookRecordMm4Hit(21);
    if (ctx && PayloadHookIsProtectedPa(ctx->rcx, ctx->rdx))
    {
        _InterlockedIncrement64((volatile LONG64*)&g_payload_mmmio_blocked);
        PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmmio_blocked);
    }
    return PayloadHookPassThroughTrampoline(match, 21) ? 1 : 0;
}

static payload_u64 PayloadHookHandleNtQueryVirtualMemory(payload_guest_context* ctx, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_ntqvm_hits);
    if (!ctx || !PayloadHookIsProtectedVa(ctx->rdx, 1))
        return PayloadHookPassThroughTrampoline(match, 27) ? 1 : 0;

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (!PayloadHookReadGuestRspRet(&rsp, &ret))
        return PayloadHookPassThroughTrampoline(match, 27) ? 1 : 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_ntqvm_blocked);

    auto rsp_hva = (payload_u64*)PayloadGvaToHva(rsp, sizeof(payload_u64) * 7);
    payload_u64 guest_cr3 = 0;
    if (rsp_hva && PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3))
    {
        payload_u64 info_gva = ctx->r9;
        payload_u64 info_len = rsp_hva[5];
        payload_u64 return_len_gva = rsp_hva[6];

        if (return_len_gva)
            PayloadGuestWriteU64(guest_cr3, return_len_gva, 0);

        if (info_gva && info_len)
        {
            unsigned char zeros[64] = {};
            payload_u64 zero_len = PayloadMinU64(info_len, (payload_u64)sizeof(zeros));
            PayloadGuestCopyFromHostBuffer(guest_cr3, info_gva, zeros, zero_len);
        }
    }

    // NtQueryVirtualMemory is a VAD/user-VA query. For hidden kernel ranges,
    // a parameter failure is less revealing than disclosing a MEMORY_BASIC_INFORMATION.
    return PayloadHookReturnToCaller(ctx, rsp, ret, 0xC000000Dull, 27) ? 1 : 0;
}

static payload_u64 PayloadHookHandleMmGetPhysicalAddress(payload_guest_context* ctx, const payload_tramp_match* match)
{
    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmgpa_hits);
    if (!ctx || !PayloadHookIsProtectedVa(ctx->rcx, 1))
        return PayloadHookPassThroughTrampoline(match, 28) ? 1 : 0;

    payload_u64 rsp = 0;
    payload_u64 ret = 0;
    if (!PayloadHookReadGuestRspRet(&rsp, &ret))
        return PayloadHookPassThroughTrampoline(match, 28) ? 1 : 0;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_mmgpa_blocked);

    payload_u64 fake_pa = 0;
    if (PayloadIsKernelPointer(g_cached_hv_diag.ghv) && g_cached_hv_diag.ghv_off_fake_data)
    {
        payload_u64 fake_va = g_cached_hv_diag.ghv +
            g_cached_hv_diag.ghv_off_fake_data +
            (ctx->rcx & (PAGE_SIZE - 1));
        PayloadKernelVaToPa(fake_va, &fake_pa);
    }

    return PayloadHookReturnToCaller(ctx, rsp, ret, fake_pa, 28) ? 1 : 0;
}

static bool PayloadHookIsMmFilterType(payload_u64 type)
{
    return type == 18 || type == 19 || type == 20 || type == 21 ||
        type == 27 || type == 28 || type == 29;
}

static bool PayloadHookMaybeFuseMmHit(payload_guest_context* ctx,
                                      const payload_tramp_match* match,
                                      payload_u64 type)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(match);
    UNREFERENCED_PARAMETER(type);
    return false;
}

static payload_u64 PayloadBridgeHandleResidentHook(payload_guest_context* ctx,
                                                   const payload_tramp_match* match,
                                                   const payload_legacy_hook_info* info)
{
    if (!ctx || !match || !info || !info->type)
        return 0;

    if (g_payload_vtpanic_active)
        return PayloadHookPassThroughTrampoline(match, info->type) ? 1 : 0;

    if (g_payload_unload_quiesce)
        return PayloadHookPassThroughTrampoline(match, info->type) ? 1 : 0;

    if (info->enabled == 0)
        return PayloadHookPassThroughTrampoline(match, info->type) ? 1 : 0;

#if VT_STABLE_GETBUFFER_ONLY
    // Bisect line: PMO(type=1) is handled before this dispatcher.  Always
    // allow GetBuffer(type=3), then allow only the group currently under test.
    bool payload_hook_type_allowed = (info->type == 3);
    payload_hook_type_allowed = payload_hook_type_allowed ||
        info->type == 18 || info->type == 19 ||
        info->type == 20 || info->type == 21;
    payload_hook_type_allowed = payload_hook_type_allowed || info->type == 29;
    payload_hook_type_allowed = payload_hook_type_allowed || info->type == 27;
    payload_hook_type_allowed = payload_hook_type_allowed || info->type == 28;
    if (!payload_hook_type_allowed)
        return PayloadHookPassThroughTrampoline(match, info->type) ? 1 : 0;
#endif

    if (PayloadHookMaybeFuseMmHit(ctx, match, info->type))
        return 1;

    if (info->filter_by_process && info->process)
    {
        payload_u64 process = 0;
        payload_u64 thread = 0;
        if (!PayloadCurrentGuestIds(&process, &thread) || process != info->process)
            return PayloadHookPassThroughTrampoline(match, info->type) ? 1 : 0;
    }


    g_payload_hook_last_type = info->type;
    payload_u64 handled = 0;
    switch (info->type)
    {
    case 2:
    case 4:
    case 5:
    case 7:
    case 8:
    case 22:
    case 23:
    case 24:
    case 25:
    case 26:
        handled = PayloadHookHandleLegacyObserveRetaddr(match, info->type);
        break;
    case 3:
        handled = PayloadHookHandleGetBuffer(ctx, match);
        break;
    case 6:
        handled = PayloadHookHandleNtCreateSection(ctx, match);
        break;
    case 9:
        handled = PayloadHookHandlePresentLike(
            ctx, match, 9,
            &g_payload_present_hits,
            &g_payload_present_alien,
            g_cached_hv_diag.ghv_off_diag_present_hits,
            g_cached_hv_diag.ghv_off_diag_present_alien);
        break;
    case 10:
        handled = PayloadHookHandlePresentLike(
            ctx, match, 10,
            &g_payload_present1_hits,
            &g_payload_present1_alien,
            g_cached_hv_diag.ghv_off_diag_present1_hits,
            g_cached_hv_diag.ghv_off_diag_present1_alien);
        break;
    case 11:
        handled = PayloadHookHandleCopyResource(ctx, match);
        break;
    case 12:
        handled = PayloadHookHandleDuplicateOutput(ctx, match);
        break;
    case 14:
    case 15:
    case 16:
    case 17:
        handled = PayloadHookHandleNtMemoryEvent(ctx, match, info->type);
        break;
    case 13:
        handled = PayloadHookHandleLegacyObserveRetaddr(match, 13);
        break;
    case 18:
        handled = PayloadHookHandleMmCopyMemory(ctx, match);
        break;
    case 19:
        handled = PayloadHookHandleMmCopyVirtualMemory(ctx, match);
        break;
    case 20:
        handled = PayloadHookHandleMmIsAddressValid(ctx, match);
        break;
    case 21:
        handled = PayloadHookHandleMmMapIoSpace(ctx, match);
        break;
    case 29:
        _InterlockedIncrement64((volatile LONG64*)&g_payload_mmisav_hits);
        PayloadHookIncrementGhvCounter(g_cached_hv_diag.ghv_off_diag_mmisav_hits);
        handled = PayloadHookPassThroughTrampoline(match, 29) ? 1 : 0;
        break;
    case 27:
        handled = PayloadHookHandleNtQueryVirtualMemory(ctx, match);
        break;
    case 28:
        handled = PayloadHookHandleMmGetPhysicalAddress(ctx, match);
        break;
    default:
        return 0;
    }

    if (handled)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_resident_handle_count);
    else
        _InterlockedIncrement64((volatile LONG64*)&g_payload_hook_resident_fail_count);
    return handled;
}
