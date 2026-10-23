// Payload-native IDXGISwapChain::GetBuffer hook installer.
// This replaces the temporary "forward PMO to legacy TestDriver to bootstrap
// type=3" path.  All shared state is prepared by payload in VMX root mode.

#ifndef PAYLOAD_STABLE_GETBUFFER_ONLY
#define PAYLOAD_STABLE_GETBUFFER_ONLY 1
#endif

#ifndef PAYLOAD_BISECT_ENABLE_SWAPCHAIN_EXTRA
#define PAYLOAD_BISECT_ENABLE_SWAPCHAIN_EXTRA 0
#endif
#ifndef PAYLOAD_BISECT_ENABLE_COPY_DUP
#define PAYLOAD_BISECT_ENABLE_COPY_DUP 0
#endif
#ifndef PAYLOAD_BISECT_ENABLE_NT_MEMORY
#define PAYLOAD_BISECT_ENABLE_NT_MEMORY 0
#endif
#ifndef PAYLOAD_BISECT_ENABLE_MM_FILTER
#define PAYLOAD_BISECT_ENABLE_MM_FILTER 0
#endif

#ifndef PAYLOAD_BISECT_ENABLE_MM_FILTER_EXT
#define PAYLOAD_BISECT_ENABLE_MM_FILTER_EXT 0
#endif

#ifndef PAYLOAD_BISECT_EXT_HOOK_IS_ADDRESS_VALID_EX
#define PAYLOAD_BISECT_EXT_HOOK_IS_ADDRESS_VALID_EX 0
#endif

#ifndef PAYLOAD_BISECT_EXT_HOOK_IS_ADDRESS_VALID_EX_OBSERVE_ONLY
#define PAYLOAD_BISECT_EXT_HOOK_IS_ADDRESS_VALID_EX_OBSERVE_ONLY 0
#endif

#ifndef PAYLOAD_BISECT_EXT_HOOK_NT_QUERY_VIRTUAL_MEMORY
#define PAYLOAD_BISECT_EXT_HOOK_NT_QUERY_VIRTUAL_MEMORY 0
#endif

#ifndef PAYLOAD_BISECT_EXT_HOOK_MM_GET_PHYSICAL_ADDRESS
#define PAYLOAD_BISECT_EXT_HOOK_MM_GET_PHYSICAL_ADDRESS 0
#endif

#ifndef PAYLOAD_BISECT_MM_HOOK_COPY_MEMORY
#define PAYLOAD_BISECT_MM_HOOK_COPY_MEMORY 1
#endif

#ifndef PAYLOAD_BISECT_MM_HOOK_COPY_VIRTUAL_MEMORY
#define PAYLOAD_BISECT_MM_HOOK_COPY_VIRTUAL_MEMORY 0
#endif

#ifndef PAYLOAD_BISECT_MM_HOOK_IS_ADDRESS_VALID
#define PAYLOAD_BISECT_MM_HOOK_IS_ADDRESS_VALID 0
#endif

#ifndef PAYLOAD_BISECT_MM_HOOK_MAP_IO_SPACE
#define PAYLOAD_BISECT_MM_HOOK_MAP_IO_SPACE 0
#endif

#ifndef PAYLOAD_MM4_INSTALL_AUTO_ENABLE
#define PAYLOAD_MM4_INSTALL_AUTO_ENABLE 1
#endif

#ifndef PAYLOAD_MM4_INSTALL_EPT_POLICY
#define PAYLOAD_MM4_INSTALL_EPT_POLICY PAYLOAD_NATIVE_EPT_POLICY_IMMEDIATE_ALL
#endif

#ifndef PAYLOAD_ENABLE_NATIVE_GETBUFFER_INSTALL
#define PAYLOAD_ENABLE_NATIVE_GETBUFFER_INSTALL 1
#endif

#ifndef PAYLOAD_GETBUFFER_HANDLER_PASSTHROUGH_ONLY
#define PAYLOAD_GETBUFFER_HANDLER_PASSTHROUGH_ONLY 0
#endif

#ifndef PAYLOAD_GETBUFFER_ALLOW_NOT_READY_PASSTHROUGH_EPT_TEST
#define PAYLOAD_GETBUFFER_ALLOW_NOT_READY_PASSTHROUGH_EPT_TEST 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_EPT_ONLY_NO_DISPATCH
#define PAYLOAD_GETBUFFER_STAGE15_EPT_ONLY_NO_DISPATCH 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_QUEUE_ONLY_NO_EPT_WRITE
#define PAYLOAD_GETBUFFER_STAGE15_QUEUE_ONLY_NO_EPT_WRITE 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_WRITE_SAME_EPT_PTE_ONLY
#define PAYLOAD_GETBUFFER_STAGE15_WRITE_SAME_EPT_PTE_ONLY 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_LOCATE_ONLY_NO_SPLIT_NO_WRITE
#define PAYLOAD_GETBUFFER_STAGE15_LOCATE_ONLY_NO_SPLIT_NO_WRITE 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_PDE_ONLY_NO_LEAF_READ
#define PAYLOAD_GETBUFFER_STAGE15_PDE_ONLY_NO_LEAF_READ 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_SPLIT_FILL_ONLY_NO_COMMIT
#define PAYLOAD_GETBUFFER_STAGE15_SPLIT_FILL_ONLY_NO_COMMIT 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_SPLIT_RESERVE_ONLY_NO_PDE
#define PAYLOAD_GETBUFFER_STAGE15_SPLIT_RESERVE_ONLY_NO_PDE 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_SPLIT_PUBLISH_NO_INVEPT
#define PAYLOAD_GETBUFFER_STAGE15_SPLIT_PUBLISH_NO_INVEPT 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_SPLIT_PUBLISH_INVEPT
#define PAYLOAD_GETBUFFER_STAGE15_SPLIT_PUBLISH_INVEPT 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_LOCATE_ONLY
#define PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_LOCATE_ONLY 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_WRITE_SAME_ONLY
#define PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_WRITE_SAME_ONLY 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_WRITE_SAME_INVEPT_ONLY
#define PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_WRITE_SAME_INVEPT_ONLY 0
#endif

#ifndef PAYLOAD_GETBUFFER_STAGE15_INSTALL_CURRENT_ONLY
#define PAYLOAD_GETBUFFER_STAGE15_INSTALL_CURRENT_ONLY 0
#endif

// Diagnostic gate for GetBuffer migration.  Non-zero means stop after the
// named install stage, clean up any temporary state, and do not retry.
//
// 2026-06-04: PMO render init is stable and GetBuffer passthrough is disabled,
// but GetBuffer itself may not be called after installation. Current diagnostic
// keeps that state and enables PMO draw callout as the visible per-frame path.
#ifndef PAYLOAD_GETBUFFER_BISECT_STOP_AFTER_STAGE
#define PAYLOAD_GETBUFFER_BISECT_STOP_AFTER_STAGE 0
#endif

#if PAYLOAD_STABLE_GETBUFFER_ONLY
#undef PAYLOAD_ENABLE_NATIVE_GETBUFFER_INSTALL
#define PAYLOAD_ENABLE_NATIVE_GETBUFFER_INSTALL 1
#endif

#ifndef PAYLOAD_HDE64_LOCAL_INCLUDED
#define PAYLOAD_HDE64_LOCAL_INCLUDED 1
#include <string.h>
static void* PayloadHdeMemset(void* dst, int value, size_t size)
{
    unsigned char* p = (unsigned char*)dst;
    for (size_t i = 0; i < size; ++i)
        p[i] = (unsigned char)value;
    return dst;
}
#define hde64_disasm PayloadHde64Disasm
#define hde64_table PayloadHde64Table
#define memset PayloadHdeMemset
#if __has_include("../../../../../VtHypervisor/hook/hde64.c")
#include "../../../../../VtHypervisor/hook/hde64.c"
#else
#include "../../../../../VtHypervisor/hook/hde64.c"
#endif
#undef memset
#undef hde64_table
#undef hde64_disasm
#endif

enum payload_getbuffer_install_stage : payload_u64
{
    PAYLOAD_GB_STAGE_NONE = 0,
    PAYLOAD_GB_STAGE_ALREADY = 1,
    PAYLOAD_GB_STAGE_NO_CONTEXT = 2,
    PAYLOAD_GB_STAGE_NO_DIAG = 3,
    PAYLOAD_GB_STAGE_NO_SWAPCHAIN = 4,
    PAYLOAD_GB_STAGE_NO_CR3 = 5,
    PAYLOAD_GB_STAGE_VFUNC = 6,
    PAYLOAD_GB_STAGE_NO_BLANK = 7,
    PAYLOAD_GB_STAGE_NO_PROCESS = 8,
    PAYLOAD_GB_STAGE_DISASM = 9,
    PAYLOAD_GB_STAGE_FAKE_ALLOC = 10,
    PAYLOAD_GB_STAGE_COPY_PAGE = 11,
    PAYLOAD_GB_STAGE_FAKE_PA = 12,
    PAYLOAD_GB_STAGE_TRAMP = 13,
    PAYLOAD_GB_STAGE_SLOT = 14,
    PAYLOAD_GB_STAGE_EPT = 15,
    PAYLOAD_GB_STAGE_DONE = 16,
    PAYLOAD_GB_STAGE_LOCK_BUSY = 17,
    PAYLOAD_GB_STAGE_NOT_READY = 18,
};

static volatile LONG s_payload_native_hook_install_lock = 0;

static constexpr payload_u64 PAYLOAD_VT_HOOK_DATA_OFF_NEXT_ADDRESS = 0x08ull;
static constexpr payload_u64 PAYLOAD_VT_HOOK_DATA_OFF_OLD_BYTE = 0x10ull;
static constexpr payload_u64 PAYLOAD_VT_HOOK_DATA_OFF_NEXT_OLD_BYTE = 0x24ull;
static constexpr payload_u64 PAYLOAD_VT_HOOK_DATA_OFF_SIZE = 0x48ull;
static constexpr payload_u64 PAYLOAD_VT_HOOK_DATA_OFF_FAKE_MEMORY = 0x60ull;
static constexpr payload_u64 PAYLOAD_VT_HOOK_OFF_FAKE_MEM_HVA = 0xA0ull;

struct payload_native_hook_install_result
{
    payload_u64 stage;
    payload_u64 target;
    payload_u64 blank;
    payload_u64 fake;
    payload_u64 tramp;
    payload_u64 slot;
    payload_u64 orig_pfn;
    payload_u64 exec_pfn;
    payload_u64 pending;
    payload_u64 entry;
};

static void PayloadPmoSetGbStage(payload_u64 stage)
{
    g_payload_getbuffer_install_stage = stage;
}

static void PayloadPmoClearGbInstallSnapshot(bool keep_stage)
{
    if (!keep_stage)
        g_payload_getbuffer_install_stage = PAYLOAD_GB_STAGE_NONE;
    g_payload_getbuffer_install_target = 0;
    g_payload_getbuffer_install_blank = 0;
    g_payload_getbuffer_install_fake = 0;
    g_payload_getbuffer_install_tramp = 0;
    g_payload_getbuffer_install_slot = 0;
    g_payload_getbuffer_install_orig_pfn = 0;
    g_payload_getbuffer_install_exec_pfn = 0;
    g_payload_getbuffer_install_pending = 0;
    g_payload_getbuffer_install_native_reason = 0;
    g_payload_getbuffer_install_native_vcpu = 0;
    g_payload_getbuffer_install_native_vcpu_ptr = 0;
    g_payload_getbuffer_install_native_pte_va = 0;
    g_payload_getbuffer_install_native_pte_before = 0;
    g_payload_getbuffer_install_native_pte_pfn = 0;
    g_payload_getbuffer_install_native_used = 0;
    g_payload_getbuffer_install_native_free = 0;
    g_payload_getbuffer_install_native_node = 0;
}

static bool PayloadPmoGbBisectAlreadyStopped()
{
#if PAYLOAD_GETBUFFER_BISECT_STOP_AFTER_STAGE
    if (g_payload_getbuffer_install_stage == PAYLOAD_GETBUFFER_BISECT_STOP_AFTER_STAGE)
    {
        // Pre-EPT bisect stops must not display a stale pending bitmap from an
        // older build/attempt.  EPT-stage stops intentionally keep the live
        // pending bitmap so unload can still retire the committed hook state.
        if (g_payload_getbuffer_install_stage < PAYLOAD_GB_STAGE_EPT)
            g_payload_getbuffer_install_pending = 0;
        return true;
    }
#else
    return false;
#endif
    return false;
}

static bool PayloadPmoGbBisectStopAt(payload_u64 stage)
{
#if PAYLOAD_GETBUFFER_BISECT_STOP_AFTER_STAGE
    if (stage == PAYLOAD_GETBUFFER_BISECT_STOP_AFTER_STAGE)
    {
        PayloadPmoSetGbStage(stage);
        if (stage < PAYLOAD_GB_STAGE_EPT)
            g_payload_getbuffer_install_pending = 0;
        return true;
    }
#endif
    return false;
}

static bool PayloadPmoReadGuestBufferCr3(payload_u64 cr3,
                                         payload_u64 gva,
                                         void* out,
                                         payload_u64 size)
{
    if (!cr3 || !gva || !out || !size)
        return false;

    payload_u64 done = 0;
    while (done < size)
    {
        payload_u64 left = 0;
        auto src = PayloadGvaToHvaCr3(cr3, gva + done, &left);
        if (!src || !left)
            return false;
        payload_u64 chunk = PayloadMinU64(size - done, left);
        PayloadCopyMemory((unsigned char*)out + done, src, chunk);
        done += chunk;
    }
    return true;
}

static bool PayloadPmoDisasmTarget(payload_u64 guest_cr3,
                                   payload_u64 target_va,
                                   unsigned int* out_size,
                                   payload_u64* out_next_va,
                                   unsigned char* old_bytes,
                                   unsigned char* next_old)
{
    if (!out_size || !out_next_va || !old_bytes || !next_old)
        return false;

    unsigned char code[32] = {};
    if (!PayloadPmoReadGuestBufferCr3(guest_cr3, target_va, code, sizeof(code)))
        return false;

    unsigned int size = 0;
    while (size < 3 && size < sizeof(code))
    {
        hde64s hs = {};
        unsigned int len = PayloadHde64Disasm(code + size, &hs);
        if (!len || (hs.flags & F_ERROR))
            return false;
        size += len;
    }
    if (!size || size > 20)
        return false;
    if ((target_va & 0xFFFull) + 3 > PAGE_SIZE)
        return false;

    PayloadZeroMemory(old_bytes, 20);
    PayloadZeroMemory(next_old, 20);
    PayloadCopyMemory(old_bytes, code, size);

    unsigned char next_buf[8] = {};
    if (PayloadPmoReadGuestBufferCr3(guest_cr3, target_va + size, next_buf, 3))
        PayloadCopyMemory(next_old, next_buf, 3);

    *out_size = size;
    *out_next_va = target_va + size;
    return true;
}

static payload_u64 PayloadPmoReadProcessCr3(payload_u64 process)
{
    if (!process ||
        (g_cached_hv_diag.system_eprocess && process == g_cached_hv_diag.system_eprocess))
    {
        return g_system_cr3 & ~0xFFFull;
    }

    if (!g_system_cr3 ||
        !PayloadIsKernelPointer(process) ||
        !g_cached_hv_diag.kprocess_directory_table_base_offset)
    {
        return 0;
    }

    payload_u64 cr3 = 0;
    if (!PayloadPmoReadGuestBufferCr3(
            g_system_cr3,
            process + g_cached_hv_diag.kprocess_directory_table_base_offset,
            &cr3,
            sizeof(cr3)))
    {
        return 0;
    }
    return cr3 & ~0xFFFull;
}

static payload_u64 PayloadPmoEffectiveCr3(payload_u64 process,
                                          payload_u64 target_va,
                                          payload_u64 fallback_cr3)
{
    if (target_va >= 0xFFFF800000000000ull && g_system_cr3)
        return g_system_cr3 & ~0xFFFull;

    payload_u64 cr3 = PayloadPmoReadProcessCr3(process);
    if (!cr3 && fallback_cr3)
        cr3 = fallback_cr3 & ~0xFFFull;
    return cr3;
}

static void PayloadPmoPrewarmAndLockUserTarget(payload_guest_context* ctx,
                                               payload_u64 guest_cr3,
                                               payload_u64 target_va)
{
    if (!ctx || !guest_cr3 || !PayloadIsCanonical(target_va) ||
        PayloadIsKernelPointer(target_va))
    {
        return;
    }

    payload_u64 scratch = g_payload_pmo_render_desc;
    if (!PayloadIsCanonical(scratch))
    {
        payload_u64 scratch_hva = 0;
        if (PayloadPmoAllocUserScratch(ctx, guest_cr3, &scratch, &scratch_hva) &&
            PayloadIsCanonical(scratch))
        {
            g_payload_pmo_render_desc = scratch;
            g_payload_pmo_render_desc_hva = scratch_hva;
            PayloadPmoPublishRenderState();
        }
    }

    if (PayloadIsCanonical(g_cached_hv_diag.ntapi_read_process_memory) &&
        PayloadIsCanonical(scratch))
    {
        payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
        payload_u64 ret = 0;
        args[0] = ~0ull;       // current process pseudo handle
        args[1] = target_va;   // lpBaseAddress
        args[2] = scratch;     // lpBuffer
        args[3] = 1;           // nSize
        args[4] = 0;           // lpNumberOfBytesRead
        PayloadPmoCallUser(ctx, g_cached_hv_diag.ntapi_read_process_memory, args, 5, &ret);
    }

    if (PayloadIsCanonical(g_cached_hv_diag.ntapi_virtual_lock))
    {
        payload_u64 args[PAYLOAD_PMO_MAX_ARGS] = {};
        payload_u64 ret = 0;
        args[0] = target_va & ~0xFFFull;
        args[1] = 0x2000;
        PayloadPmoCallUser(ctx, g_cached_hv_diag.ntapi_virtual_lock, args, 2, &ret);
    }
}

static bool PayloadEhDiagReady()
{
    if (!g_hv_diag_cache_ready ||
        g_cached_hv_diag.magic != MAPCTL_HV_DIAG_MAGIC ||
        !PayloadIsKernelPointer(g_cached_hv_diag.ghv) ||
        !g_cached_hv_diag.ghv_off_ept_hook_table ||
        !g_cached_hv_diag.ept_hook_table_capacity ||
        g_cached_hv_diag.ept_hook_table_capacity > 256 ||
        !g_cached_hv_diag.ept_hook_entry_size ||
        g_cached_hv_diag.ept_hook_entry_size > 0x200 ||
        !g_cached_hv_diag.ept_hook_table_off_active_list_head ||
        !g_cached_hv_diag.ept_hook_table_off_free_list_head ||
        !g_cached_hv_diag.ept_hook_table_off_buffer ||
        !g_cached_hv_diag.ept_hook_table_off_fake_pages ||
        !g_cached_hv_diag.ept_hook_table_off_fake_page_pfns ||
        !g_cached_hv_diag.ept_hook_entry_off_process_cr3 ||
        !g_cached_hv_diag.ept_hook_entry_off_va ||
        !g_cached_hv_diag.ept_hook_entry_off_orig_pfn ||
        !g_cached_hv_diag.ept_hook_entry_off_fake_pfn ||
        !g_cached_hv_diag.ept_hook_entry_off_fake_page_idx ||
        !g_cached_hv_diag.ept_hook_entry_off_in_use ||
        !g_cached_hv_diag.ept_hook_entry_off_is_fake_page ||
        !g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap)
    {
        return false;
    }
    return true;
}

static payload_u64 PayloadEhTableBase()
{
    if (!PayloadEhDiagReady())
        return 0;
    payload_u64 base = g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_ept_hook_table;
    return PayloadIsKernelPointer(base) ? base : 0;
}

static bool PayloadEhTableLock(payload_u64 table)
{
    payload_u64 lock = table + g_cached_hv_diag.ept_hook_table_off_lock;
    for (payload_u64 spin = 0; spin < 0x100000ull; ++spin)
    {
        if (_InterlockedCompareExchange((volatile LONG*)lock, 1, 0) == 0)
            return true;
        _mm_pause();
    }
    return false;
}

static void PayloadEhTableUnlock(payload_u64 table)
{
    payload_u64 lock = table + g_cached_hv_diag.ept_hook_table_off_lock;
    *(volatile LONG*)lock = 0;
}

static bool PayloadEhEntryInTable(payload_u64 table, payload_u64 entry)
{
    if (!PayloadIsKernelPointer(table) || !PayloadIsKernelPointer(entry))
        return false;

    payload_u64 buffer = table + g_cached_hv_diag.ept_hook_table_off_buffer;
    payload_u64 size = g_cached_hv_diag.ept_hook_entry_size;
    payload_u64 cap = g_cached_hv_diag.ept_hook_table_capacity;
    payload_u64 bytes = size * cap;
    if (!buffer || !size || !cap || bytes / size != cap)
        return false;

    if (entry < buffer || entry >= buffer + bytes)
        return false;
    return ((entry - buffer) % size) == 0;
}

static payload_u64 PayloadEhFindEntryLocked(payload_u64 table,
                                            payload_u64 process_cr3,
                                            payload_u64 va_page)
{
    payload_u64 node = PayloadReadHostU64(
        table + g_cached_hv_diag.ept_hook_table_off_active_list_head);
    for (payload_u64 i = 0;
         i < g_cached_hv_diag.ept_hook_table_capacity && PayloadEhEntryInTable(table, node);
         ++i)
    {
        payload_u64 cr3 = PayloadReadHostU64(node + g_cached_hv_diag.ept_hook_entry_off_process_cr3);
        payload_u64 va = PayloadReadHostU64(node + g_cached_hv_diag.ept_hook_entry_off_va);
        if (cr3 == process_cr3 && va == va_page)
            return node;

        payload_u64 next = PayloadReadHostU64(node + g_cached_hv_diag.ept_hook_entry_off_next);
        if (!next || next == node)
            break;
        node = next;
    }
    return 0;
}

static payload_u64 PayloadEhAllocEntryLocked(payload_u64 table)
{
    payload_u64 free_field = table + g_cached_hv_diag.ept_hook_table_off_free_list_head;
    payload_u64 active_field = table + g_cached_hv_diag.ept_hook_table_off_active_list_head;
    payload_u64 entry = PayloadReadHostU64(free_field);
    if (!PayloadEhEntryInTable(table, entry))
        return 0;

    payload_u64 next_free = PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_next);
    payload_u64 active = PayloadReadHostU64(active_field);
    PayloadWriteHostU64(free_field, next_free);
    PayloadWriteHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_next, active);
    PayloadWriteHostU64(active_field, entry);
    PayloadWriteHostU8(entry + g_cached_hv_diag.ept_hook_entry_off_in_use, 1);

    if (g_cached_hv_diag.ept_hook_table_off_in_use_count)
    {
        payload_u64 count_field = table + g_cached_hv_diag.ept_hook_table_off_in_use_count;
        *(volatile unsigned int*)count_field = PayloadReadHostU32(count_field) + 1;
    }
    return entry;
}

static void PayloadEhFreeEntryLocked(payload_u64 table, payload_u64 entry)
{
    if (!PayloadEhEntryInTable(table, entry))
        return;

    payload_u64 active_field = table + g_cached_hv_diag.ept_hook_table_off_active_list_head;
    payload_u64 active = PayloadReadHostU64(active_field);
    if (active == entry)
    {
        PayloadWriteHostU64(
            active_field,
            PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_next));
    }
    else
    {
        payload_u64 prev = active;
        for (payload_u64 i = 0;
             i < g_cached_hv_diag.ept_hook_table_capacity && PayloadEhEntryInTable(table, prev);
             ++i)
        {
            payload_u64 next = PayloadReadHostU64(prev + g_cached_hv_diag.ept_hook_entry_off_next);
            if (next == entry)
            {
                PayloadWriteHostU64(
                    prev + g_cached_hv_diag.ept_hook_entry_off_next,
                    PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_next));
                break;
            }
            if (!next || next == prev)
                break;
            prev = next;
        }
    }

    payload_u64 idx = PayloadReadHostU32(entry + g_cached_hv_diag.ept_hook_entry_off_fake_page_idx);
    PayloadZeroMemory((void*)entry, g_cached_hv_diag.ept_hook_entry_size);
    *(volatile unsigned int*)(entry + g_cached_hv_diag.ept_hook_entry_off_fake_page_idx) =
        (unsigned int)idx;
    PayloadWriteHostU8(entry + g_cached_hv_diag.ept_hook_entry_off_in_use, 0);

    payload_u64 free_field = table + g_cached_hv_diag.ept_hook_table_off_free_list_head;
    payload_u64 old_free = PayloadReadHostU64(free_field);
    PayloadWriteHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_next, old_free);
    PayloadWriteHostU64(free_field, entry);

    if (g_cached_hv_diag.ept_hook_table_off_in_use_count)
    {
        payload_u64 count_field = table + g_cached_hv_diag.ept_hook_table_off_in_use_count;
        unsigned int count = PayloadReadHostU32(count_field);
        if (count)
            *(volatile unsigned int*)count_field = count - 1;
    }
}

static payload_u64 PayloadEhFakePageBase(payload_u64 table, payload_u64 entry)
{
    if (!PayloadEhEntryInTable(table, entry))
        return 0;
    payload_u64 idx = PayloadReadHostU32(entry + g_cached_hv_diag.ept_hook_entry_off_fake_page_idx);
    if (idx >= g_cached_hv_diag.ept_hook_table_capacity)
        return 0;
    payload_u64 fake = table + g_cached_hv_diag.ept_hook_table_off_fake_pages + idx * PAGE_SIZE;
    return PayloadIsKernelPointer(fake) ? fake : 0;
}

static payload_u64 PayloadEhPrepareEntry(payload_u64 process,
                                         payload_u64 process_cr3,
                                         payload_u64 target_va,
                                         bool full_zero,
                                         bool is_fake_page,
                                         bool* freshly)
{
    if (freshly) *freshly = false;
    if (!process_cr3 || !target_va)
        return 0;

    payload_u64 table = PayloadEhTableBase();
    if (!table)
        return 0;

    payload_u64 va_page = target_va & ~0xFFFull;
    if (!PayloadEhTableLock(table))
        return 0;
    payload_u64 entry = PayloadEhFindEntryLocked(table, process_cr3, va_page);
    if (entry)
    {
        PayloadEhTableUnlock(table);
        return entry;
    }

    entry = PayloadEhAllocEntryLocked(table);
    if (!entry)
    {
        PayloadEhTableUnlock(table);
        return 0;
    }

    payload_u64 orig_gpa = 0;
    payload_u64 left = 0;
    if (!PayloadGvaToGpa(process_cr3, va_page, &orig_gpa, &left) || !orig_gpa)
    {
        PayloadEhFreeEntryLocked(table, entry);
        PayloadEhTableUnlock(table);
        return 0;
    }

    payload_u64 fake = PayloadEhFakePageBase(table, entry);
    if (!fake)
    {
        PayloadEhFreeEntryLocked(table, entry);
        PayloadEhTableUnlock(table);
        return 0;
    }

    payload_u64 fake_pfn = PayloadReadHostU64(
        table + g_cached_hv_diag.ept_hook_table_off_fake_page_pfns +
        (payload_u64)PayloadReadHostU32(entry + g_cached_hv_diag.ept_hook_entry_off_fake_page_idx) *
            sizeof(payload_u64));
    if (!fake_pfn)
    {
        payload_u64 fake_pa = 0;
        if (PayloadKernelVaToPa(fake, &fake_pa) && fake_pa)
        {
            fake_pfn = fake_pa >> 12;
            PayloadWriteHostU64(
                table + g_cached_hv_diag.ept_hook_table_off_fake_page_pfns +
                (payload_u64)PayloadReadHostU32(entry + g_cached_hv_diag.ept_hook_entry_off_fake_page_idx) *
                    sizeof(payload_u64),
                fake_pfn);
        }
    }
    if (!fake_pfn)
    {
        PayloadEhFreeEntryLocked(table, entry);
        PayloadEhTableUnlock(table);
        return 0;
    }

    PayloadWriteHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_process, process);
    PayloadWriteHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_process_cr3, process_cr3);
    PayloadWriteHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_va, va_page);
    PayloadWriteHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_orig_pfn, orig_gpa >> 12);
    PayloadWriteHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_fake_pfn, fake_pfn);
    PayloadWriteHostU8(entry + g_cached_hv_diag.ept_hook_entry_off_is_fake_page, is_fake_page ? 1 : 0);
    PayloadWriteHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_per_vcpu_active_bitmap, 0);

    if (full_zero)
        PayloadZeroMemory((void*)fake, PAGE_SIZE);
    else if (!PayloadPmoReadGuestBufferCr3(process_cr3, va_page, (void*)fake, PAGE_SIZE))
        PayloadZeroMemory((void*)fake, PAGE_SIZE);

    PayloadEhTableUnlock(table);
    if (freshly) *freshly = true;
    return entry;
}

static payload_u64 PayloadEhGetFakeHvaForEntry(payload_u64 entry, payload_u64 target_va)
{
    payload_u64 table = PayloadEhTableBase();
    payload_u64 fake = PayloadEhFakePageBase(table, entry);
    if (!fake)
        return 0;
    return fake + (target_va & 0xFFFull);
}

static void PayloadEhFreeEntry(payload_u64 entry)
{
    payload_u64 table = PayloadEhTableBase();
    if (!table || !entry)
        return;
    if (!PayloadEhTableLock(table))
        return;
    PayloadEhFreeEntryLocked(table, entry);
    PayloadEhTableUnlock(table);
}

static void PayloadEhApplyEnableTransition(payload_u64 fake_target_hva)
{
    if (!PayloadIsKernelPointer(fake_target_hva))
        return;
    unsigned char* p = (unsigned char*)fake_target_hva;
    p[0] = 0x0F;
    p[1] = 0x01;
    p[2] = 0xC1;
    _mm_mfence();
    __invlpg((void*)fake_target_hva);
}

static bool PayloadPmoFindHookSlot(payload_u64 type,
                                   payload_u64 target_va,
                                   payload_u64* out_slot,
                                   payload_u64* out_address,
                                   payload_u64* out_blank)
{
    if (out_slot) *out_slot = 0;
    if (out_address) *out_address = 0;
    if (out_blank) *out_blank = 0;

    if (!type ||
        !PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) ||
        !g_cached_hv_diag.vt_hook_slot_count ||
        !g_cached_hv_diag.vt_hook_slot_size ||
        !g_cached_hv_diag.vt_hook_slot_off_occupied ||
        !g_cached_hv_diag.vt_hook_slot_off_data_type)
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
        payload_u64 slot_type = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_type);
        if (slot_type != type)
            continue;
        payload_u64 address =
            PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_address);
        if (target_va && address != target_va)
            continue;
        if (!target_va && !address)
            continue;
        if (out_slot) *out_slot = slot;
        if (out_address) *out_address = address;
        if (out_blank && g_cached_hv_diag.vt_hook_slot_off_data_blank_memory)
            *out_blank = PayloadReadHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_blank_memory);
        return true;
    }
    return false;
}

static bool PayloadPmoFindFreeHookSlot(payload_u64* out_slot)
{
    if (out_slot) *out_slot = 0;
    if (!out_slot ||
        !PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) ||
        !g_cached_hv_diag.vt_hook_slot_count ||
        !g_cached_hv_diag.vt_hook_slot_size ||
        !g_cached_hv_diag.vt_hook_slot_off_occupied ||
        g_cached_hv_diag.vt_hook_slot_size < 0xC1ull)
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
        {
            *out_slot = slot;
            return true;
        }
    }
    return false;
}

static bool PayloadPmoAllocTrampoline(payload_u64 target_va,
                                      const unsigned char* old_bytes,
                                      unsigned int old_size,
                                      bool is_kernel,
                                      payload_u64* out_tramp_va,
                                      payload_u64* out_bp_rip,
                                      payload_u64* out_target_resume)
{
    if (out_tramp_va) *out_tramp_va = 0;
    if (out_bp_rip) *out_bp_rip = 0;
    if (out_target_resume) *out_target_resume = 0;
    if (!target_va || !old_bytes || !old_size || old_size > 20)
        return false;

    payload_u64 pool = g_payload_tramp_pool_base;
    payload_tramp_match meta = {};
    if (!PayloadIsKernelPointer(pool) || !PayloadTrampPoolLooksValid(pool, &meta))
    {
        pool = PayloadDiagTrampPoolBase();
        if (!PayloadIsKernelPointer(pool) || !PayloadTrampPoolLooksValid(pool, &meta))
            return false;
        g_payload_tramp_pool_base = pool;
    }

    payload_u64 slot_count = is_kernel ? meta.kernel_slot_count : meta.user_slot_count;
    payload_u64 ready = is_kernel ? meta.kernel_ready : meta.user_ready;
    if (!ready || !slot_count)
        return false;

    payload_u64 slots_base = pool + (is_kernel
        ? PAYLOAD_TRAMP_POOL_KERNEL_SLOTS_OFF
        : PAYLOAD_TRAMP_POOL_USER_SLOTS_OFF);
    payload_u64 pages_base = pool + (is_kernel
        ? PAYLOAD_TRAMP_POOL_KERNEL_PAGES_OFF
        : PAYLOAD_TRAMP_POOL_USER_PAGES_OFF);
    payload_u64 page_count = PayloadReadHostU32(pool + (is_kernel
        ? PAYLOAD_TRAMP_POOL_KERNEL_PAGE_COUNT_OFF
        : PAYLOAD_TRAMP_POOL_USER_PAGE_COUNT_OFF));
    if (!page_count || page_count > PAYLOAD_TRAMP_MAX_PAGES)
        return false;

    unsigned int needed = old_size + 1;
    for (payload_u64 i = 0; i < slot_count; ++i)
    {
        payload_u64 slot = slots_base + i * PAYLOAD_TRAMP_SLOT_SIZE;
        if (PayloadReadHostU8(slot + PAYLOAD_TRAMP_SLOT_OFF_OCCUPIED))
            continue;

        unsigned int page_index = *(volatile unsigned short*)(slot + 0x18ull);
        unsigned int page_off = *(volatile unsigned short*)(slot + 0x1Aull);
        unsigned int capacity = PayloadReadHostU8(slot + 0x1Cull);
        if (page_index >= page_count ||
            page_off >= PAGE_SIZE ||
            capacity < needed ||
            page_off + capacity > PAGE_SIZE)
        {
            continue;
        }

        payload_u64 page = pages_base + (payload_u64)page_index * PAYLOAD_TRAMP_PAGE_SIZE;
        payload_u64 guest_page = PayloadReadHostU64(page + PAYLOAD_TRAMP_PAGE_OFF_GUEST_PAGE);
        payload_u64 exec_pfn = PayloadReadHostU64(page + PAYLOAD_TRAMP_PAGE_OFF_EXEC_PFN);
        if (!PayloadIsCanonical(guest_page) || !exec_pfn)
            continue;

        payload_u64 exec_pa = (exec_pfn << 12) + page_off;
        if (!PayloadHostPhysicalRangeMapped(exec_pa, needed))
            continue;

        auto exec = (unsigned char*)(PAYLOAD_HOST_PHYSICAL_MEMORY_BASE + exec_pa);
        PayloadCopyMemory(exec, old_bytes, old_size);
        exec[old_size] = 0xCC;

        payload_u64 tramp_va = guest_page + page_off;
        payload_u64 bp_rip = tramp_va + old_size;
        payload_u64 target_resume = target_va + old_size;
        PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TRAMP_VA, tramp_va);
        PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_BP_RIP, bp_rip);
        PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TARGET_RESUME, target_resume);
        PayloadWriteHostU8(slot + PAYLOAD_TRAMP_SLOT_OFF_OCCUPIED, 1);

        if (out_tramp_va) *out_tramp_va = tramp_va;
        if (out_bp_rip) *out_bp_rip = bp_rip;
        if (out_target_resume) *out_target_resume = target_resume;
        return true;
    }

    return false;
}

static bool PayloadPmoAllocUserTrampoline(payload_u64 target_va,
                                          const unsigned char* old_bytes,
                                          unsigned int old_size,
                                          payload_u64* out_tramp_va,
                                          payload_u64* out_bp_rip,
                                          payload_u64* out_target_resume)
{
    return PayloadPmoAllocTrampoline(
        target_va,
        old_bytes,
        old_size,
        false,
        out_tramp_va,
        out_bp_rip,
        out_target_resume);
}

static void PayloadPmoFreeTrampoline(payload_u64 tramp_va)
{
    if (!tramp_va)
        return;

    payload_u64 pool = g_payload_tramp_pool_base;
    payload_tramp_match meta = {};
    if (!PayloadIsKernelPointer(pool) || !PayloadTrampPoolLooksValid(pool, &meta))
    {
        pool = PayloadDiagTrampPoolBase();
        if (!PayloadIsKernelPointer(pool) || !PayloadTrampPoolLooksValid(pool, &meta))
            return;
    }

    auto release_slots = [&](payload_u64 slots_base, payload_u64 count) -> bool
    {
        if (!slots_base || count > PAYLOAD_TRAMP_MAX_SLOTS)
            return false;
        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_u64 slot = slots_base + i * PAYLOAD_TRAMP_SLOT_SIZE;
            if (!PayloadReadHostU8(slot + PAYLOAD_TRAMP_SLOT_OFF_OCCUPIED))
                continue;
            if (PayloadReadHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TRAMP_VA) != tramp_va)
                continue;
            PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TRAMP_VA, 0);
            PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_BP_RIP, 0);
            PayloadWriteHostU64(slot + PAYLOAD_TRAMP_SLOT_OFF_TARGET_RESUME, 0);
            PayloadWriteHostU8(slot + PAYLOAD_TRAMP_SLOT_OFF_OCCUPIED, 0);
            return true;
        }
        return false;
    };

    if (!release_slots(pool + PAYLOAD_TRAMP_POOL_USER_SLOTS_OFF, meta.user_slot_count))
        release_slots(pool + PAYLOAD_TRAMP_POOL_KERNEL_SLOTS_OFF, meta.kernel_slot_count);
}

static bool PayloadPmoWriteLegacyHookSlotNative(payload_u64 slot,
                                                payload_u64 target_va,
                                                payload_u64 next_va,
                                                const unsigned char* old_bytes,
                                                const unsigned char* next_old,
                                                unsigned int old_size,
                                                payload_u64 process,
                                                payload_u64 blank,
                                                payload_u64 type,
                                                bool filter_by_process,
                                                bool auto_enable,
                                                payload_u64 fake_target_hva,
                                                payload_u64 tramp_va,
                                                payload_u64 bp_rip,
                                                payload_u64 target_resume)
{
    if (!PayloadIsKernelPointer(slot) ||
        !target_va ||
        !old_bytes ||
        !next_old ||
        !old_size ||
        !type ||
        !tramp_va ||
        !bp_rip ||
        !target_resume)
    {
        return false;
    }

    payload_u64 slot_size = g_cached_hv_diag.vt_hook_slot_size;
    if (!slot_size || slot_size > 0x1000 || slot_size < 0xC1ull)
        return false;

    PayloadZeroMemory((void*)slot, slot_size);
    PayloadWriteHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_address, target_va);
    PayloadWriteHostU64(slot + PAYLOAD_VT_HOOK_DATA_OFF_NEXT_ADDRESS, next_va);
    PayloadCopyMemory((void*)(slot + PAYLOAD_VT_HOOK_DATA_OFF_OLD_BYTE), old_bytes, 20);
    PayloadCopyMemory((void*)(slot + PAYLOAD_VT_HOOK_DATA_OFF_NEXT_OLD_BYTE), next_old, 20);
    *(volatile unsigned int*)(slot + PAYLOAD_VT_HOOK_DATA_OFF_SIZE) = (unsigned int)old_size;
    if (g_cached_hv_diag.vt_hook_slot_off_data_process)
        PayloadWriteHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_process, process);
    if (g_cached_hv_diag.vt_hook_slot_off_data_blank_memory)
        PayloadWriteHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_blank_memory, blank);
    PayloadWriteHostU64(slot + PAYLOAD_VT_HOOK_DATA_OFF_FAKE_MEMORY, fake_target_hva);
    if (g_cached_hv_diag.vt_hook_slot_off_data_type)
        PayloadWriteHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_data_type, type);
    if (g_cached_hv_diag.vt_hook_slot_off_data_dispatch_mode)
        PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_dispatch_mode, 0);
    if (g_cached_hv_diag.vt_hook_slot_off_data_filter_by_process)
        PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_filter_by_process, filter_by_process ? 1 : 0);
    if (g_cached_hv_diag.vt_hook_slot_off_data_is_enable)
        PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_is_enable, auto_enable ? 1 : 0);

    PayloadWriteHostU64(slot + PAYLOAD_VT_HOOK_OFF_FAKE_MEM_HVA, fake_target_hva);
    PayloadWriteHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_trampoline_va, tramp_va);
    PayloadWriteHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_bp_rip, bp_rip);
    PayloadWriteHostU64(slot + g_cached_hv_diag.vt_hook_slot_off_target_resume, target_resume);
    PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied, 1);
    return true;
}

static bool PayloadPmoWriteGetBufferHookSlot(payload_u64 slot,
                                             payload_u64 target_va,
                                             payload_u64 next_va,
                                             const unsigned char* old_bytes,
                                             const unsigned char* next_old,
                                             unsigned int old_size,
                                             payload_u64 process,
                                             payload_u64 blank,
                                             payload_u64 fake_target_hva,
                                             payload_u64 tramp_va,
                                             payload_u64 bp_rip,
                                             payload_u64 target_resume)
{
    return PayloadPmoWriteLegacyHookSlotNative(
        slot,
        target_va,
        next_va,
        old_bytes,
        next_old,
        old_size,
        process,
        blank,
        3,
        true,
        false,
        fake_target_hva,
        tramp_va,
        bp_rip,
        target_resume);
}

static bool PayloadPmoInstallLegacyHookNative(payload_u64 process,
                                              payload_u64 target_va,
                                              payload_u64 blank,
                                              payload_u64 type,
                                              bool filter_by_process,
                                              bool auto_enable,
                                              payload_u64 fallback_guest_cr3,
                                              payload_native_hook_install_result* result)
{
    payload_native_hook_install_result local = {};
    local.stage = PAYLOAD_GB_STAGE_NONE;
    local.target = target_va;
    local.blank = blank;
    if (result)
        *result = local;

    if (!target_va || !type)
    {
        local.stage = PAYLOAD_GB_STAGE_VFUNC;
        if (result) *result = local;
        return false;
    }

    payload_u64 existing_slot = 0;
    payload_u64 existing_target = 0;
    payload_u64 existing_blank = 0;
    if (PayloadPmoFindHookSlot(type, target_va, &existing_slot, &existing_target, &existing_blank))
    {
        local.stage = PAYLOAD_GB_STAGE_ALREADY;
        local.target = existing_target;
        local.blank = existing_blank;
        local.slot = existing_slot;
        if (result) *result = local;
        return true;
    }

    if (!g_hv_diag_cache_ready ||
        !PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) ||
        !g_cached_hv_diag.vt_hook_slot_off_data_type ||
        !g_cached_hv_diag.vt_hook_slot_off_bp_rip ||
        !g_cached_hv_diag.vt_hook_slot_off_target_resume ||
        !PayloadEhDiagReady())
    {
        local.stage = PAYLOAD_GB_STAGE_NO_DIAG;
        if (result) *result = local;
        return false;
    }

    if (_InterlockedCompareExchange(&s_payload_native_hook_install_lock, 1, 0) != 0)
    {
        local.stage = PAYLOAD_GB_STAGE_LOCK_BUSY;
        if (result) *result = local;
        return false;
    }

    bool ok = false;
    payload_u64 entry = 0;
    bool entry_freshly_allocated = false;
    payload_u64 tramp_va = 0;
    payload_u64 slot = 0;
    bool ept_queue_attempted = false;

    do
    {
        if (PayloadPmoFindHookSlot(type, target_va, &existing_slot, &existing_target, &existing_blank))
        {
            local.stage = PAYLOAD_GB_STAGE_ALREADY;
            local.target = existing_target;
            local.blank = existing_blank;
            local.slot = existing_slot;
            ok = true;
            break;
        }

        payload_u64 target_cr3 = PayloadPmoEffectiveCr3(process, target_va, fallback_guest_cr3);
        if (!target_cr3)
        {
            local.stage = PAYLOAD_GB_STAGE_NO_CR3;
            break;
        }

        unsigned int instr_size = 0;
        payload_u64 next_va = 0;
        unsigned char old_bytes[20] = {};
        unsigned char next_old[20] = {};
        if (!PayloadPmoDisasmTarget(
                target_cr3,
                target_va,
                &instr_size,
                &next_va,
                old_bytes,
                next_old))
        {
            local.stage = PAYLOAD_GB_STAGE_DISASM;
            break;
        }

        entry = PayloadEhPrepareEntry(
            process,
            target_cr3,
            target_va,
            false,
            false,
            &entry_freshly_allocated);
        if (!entry)
        {
            local.stage = PAYLOAD_GB_STAGE_FAKE_ALLOC;
            break;
        }
        local.entry = entry;

        payload_u64 fake_target_hva = PayloadEhGetFakeHvaForEntry(entry, target_va);
        if (!PayloadIsKernelPointer(fake_target_hva))
        {
            local.stage = PAYLOAD_GB_STAGE_COPY_PAGE;
            break;
        }
        local.fake = fake_target_hva;
        local.orig_pfn =
            PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_orig_pfn);
        local.exec_pfn =
            PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_fake_pfn);
        if (!local.orig_pfn || !local.exec_pfn)
        {
            local.stage = PAYLOAD_GB_STAGE_FAKE_PA;
            break;
        }

        payload_u64 bp_rip = 0;
        payload_u64 target_resume = 0;
        bool is_kernel = PayloadIsKernelPointer(target_va);
        if (!PayloadPmoAllocTrampoline(
                target_va,
                old_bytes,
                instr_size,
                is_kernel,
                &tramp_va,
                &bp_rip,
                &target_resume))
        {
            local.stage = PAYLOAD_GB_STAGE_TRAMP;
            break;
        }
        local.tramp = tramp_va;

        if (!PayloadPmoFindFreeHookSlot(&slot) ||
            !PayloadPmoWriteLegacyHookSlotNative(
                slot,
                target_va,
                next_va,
                old_bytes,
                next_old,
                instr_size,
                process,
                blank,
                type,
                filter_by_process,
                false,
                fake_target_hva,
                tramp_va,
                bp_rip,
                target_resume))
        {
            local.stage = PAYLOAD_GB_STAGE_SLOT;
            break;
        }
        local.slot = slot;

        // Match TestDriver vh_install_host(_deferred): commit/enable the
        // shared fake page before EPT is armed.  That removes the window where
        // an EPT redirect is live but the fake page still contains the copied
        // original bytes and keeps the observable install order identical to
        // the validated TestDriver path.
        if (auto_enable)
        {
            PayloadEhApplyEnableTransition(fake_target_hva);
            if (g_cached_hv_diag.vt_hook_slot_off_data_is_enable)
                PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_is_enable, 1);
        }

        payload_u64 pending = 0;
        bool force_deferred_policy =
            (type >= 22 && type <= 26);     // mouse/HID hooks are deferred when bisected on.
                                            //
                                            // Important parity note for the
                                            // resident payload path: the last
                                            // user-reported stable MM4 payload
                                            // build installed kernel targets
                                            // through the generic kernel
                                            // policy below, i.e.
                                            // IMMEDIATE_ALL.  Forcing
                                            // types 18-21 through the resident
                                            // legacy-pending deferred path can
                                            // reboot inside VT before status is
                                            // observable, because every other
                                            // vCPU drains global ntoskrnl hook
                                            // installs from the bridge prelude.
                                            // Keep GetBuffer/type3 on its
                                            // dedicated deferred installer, but
                                            // leave MM4 as kernel
                                            // IMMEDIATE_ALL here.
        payload_native_ept_install_policy install_policy =
            force_deferred_policy
                ? PAYLOAD_NATIVE_EPT_POLICY_DEFERRED
                : (PayloadIsKernelPointer(target_va)
                    ? PAYLOAD_NATIVE_EPT_POLICY_IMMEDIATE_ALL
                    : PAYLOAD_NATIVE_EPT_POLICY_DEFERRED);
#if PAYLOAD_BISECT_ENABLE_MM_FILTER
        if (type >= 18 && type <= 21)
            install_policy = (payload_native_ept_install_policy)PAYLOAD_MM4_INSTALL_EPT_POLICY;
#endif
        ept_queue_attempted = true;
        if (!PayloadEptQueueNativeInstallAllEx(
                local.orig_pfn,
                local.exec_pfn,
                false,
                entry,
                &pending,
                install_policy))
        {
            local.stage = PAYLOAD_GB_STAGE_EPT;
            local.pending = pending;
            break;
        }
        local.pending = pending;

        local.stage = PAYLOAD_GB_STAGE_DONE;
        ok = true;
    } while (false);

    if (!ok)
    {
        if (entry && ept_queue_attempted)
            PayloadEptClearNativePending(entry, local.orig_pfn, local.exec_pfn);
        if (slot && g_cached_hv_diag.vt_hook_slot_off_occupied)
            PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied, 0);
        if (tramp_va)
            PayloadPmoFreeTrampoline(tramp_va);
        if (entry && entry_freshly_allocated)
            PayloadEhFreeEntry(entry);
    }

    _InterlockedExchange(&s_payload_native_hook_install_lock, 0);
    if (result)
        *result = local;
    return ok;
}

static bool PayloadPmoTryInstallGetBuffer(payload_guest_context* ctx)
{
#if !PAYLOAD_ENABLE_NATIVE_GETBUFFER_INSTALL
    payload_u64 existing_slot = 0;
    payload_u64 existing_target = 0;
    if (PayloadPmoFindHookSlot(3, 0, &existing_slot, &existing_target, nullptr))
    {
        g_payload_getbuffer_install_target = existing_target;
        g_payload_getbuffer_install_slot = existing_slot;
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_ALREADY);
        if (!g_payload_getbuffer_install_ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_ok);
        return true;
    }
    return false;
#else
    if (g_payload_unload_quiesce)
        return true;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_probe);

    if (PayloadPmoGbBisectAlreadyStopped())
        return true;

    PayloadPmoClearGbInstallSnapshot(false);

    payload_u64 existing_slot = 0;
    payload_u64 existing_target = 0;
    if (PayloadPmoFindHookSlot(3, 0, &existing_slot, &existing_target, nullptr))
    {
        g_payload_getbuffer_install_target = existing_target;
        g_payload_getbuffer_install_slot = existing_slot;
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_ALREADY);
        if (!g_payload_getbuffer_install_ok)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_ok);
        return true;
    }

    if (!ctx)
    {
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_NO_CONTEXT);
        _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_fail);
        return false;
    }

    if (_InterlockedCompareExchange(&s_payload_native_hook_install_lock, 1, 0) != 0)
    {
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_LOCK_BUSY);
        return true;
    }

    bool ok = false;
    payload_u64 entry = 0;
    bool entry_freshly_allocated = false;
    payload_u64 tramp_va = 0;
    payload_u64 slot = 0;
    bool keep_committed_ept_state = false;
    bool ept_queue_attempted = false;
    do
    {
        existing_target = 0;
        if (PayloadPmoFindHookSlot(3, 0, &existing_slot, &existing_target, nullptr))
        {
            g_payload_getbuffer_install_target = existing_target;
            g_payload_getbuffer_install_slot = existing_slot;
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_ALREADY);
            ok = true;
            break;
        }

        if (!g_hv_diag_cache_ready ||
            !PayloadIsKernelPointer(g_cached_hv_diag.vt_hook_table_ptr) ||
            !g_cached_hv_diag.vt_hook_slot_off_data_type ||
            !g_cached_hv_diag.vt_hook_slot_off_bp_rip ||
            !g_cached_hv_diag.vt_hook_slot_off_target_resume)
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_NO_DIAG);
            break;
        }

        if (!g_payload_pmo_last_isfinish)
        {
#if PAYLOAD_GETBUFFER_ALLOW_NOT_READY_PASSTHROUGH_EPT_TEST && PAYLOAD_GETBUFFER_HANDLER_PASSTHROUGH_ONLY
            // Stage-15 passthrough diagnostics do not need D2D/D3D render
            // objects or fake texture contents; they only need the swapchain
            // pointer from the PMO hit to resolve IDXGISwapChain::GetBuffer and
            // arm EPT/trampoline dispatch.  Keep render init disabled because
            // calling D2D/D3D user code from this VMX-root PMO path caused an
            // immediate VT reset in the 02:07 build.
#else
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_NOT_READY);
            break;
#endif
        }

        payload_u64 swapchain = g_payload_pmo_last_swapchain ? g_payload_pmo_last_swapchain : ctx->rcx;
        if (!PayloadIsCanonical(swapchain))
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_NO_SWAPCHAIN);
            break;
        }

        payload_u64 guest_cr3 = 0;
        if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_NO_CR3);
            break;
        }

        payload_u64 getbuf_va = 0;
        if (!PayloadPmoGetVFunc(guest_cr3, swapchain, 9, &getbuf_va) ||
            !PayloadIsCanonical(getbuf_va) ||
            PayloadIsKernelPointer(getbuf_va))
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_VFUNC);
            break;
        }
        g_payload_getbuffer_install_target = getbuf_va;
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_VFUNC);
        if (PayloadPmoGbBisectStopAt(PAYLOAD_GB_STAGE_VFUNC))
            break;

        if (PayloadPmoFindHookSlot(3, getbuf_va, &existing_slot, nullptr, nullptr))
        {
            g_payload_getbuffer_install_slot = existing_slot;
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_ALREADY);
            ok = true;
            break;
        }

        payload_u64 blank = PayloadPmoFindBlankMemory(1);
        if (!blank)
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_NO_BLANK);
            break;
        }
        g_payload_getbuffer_install_blank = blank;

        PayloadPmoPrewarmAndLockUserTarget(ctx, guest_cr3, getbuf_va);

        payload_u64 process = 0;
        payload_u64 thread = 0;
        if (!PayloadCurrentGuestIds(&process, &thread) || !PayloadIsKernelPointer(process))
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_NO_PROCESS);
            break;
        }

        payload_u64 target_cr3 = PayloadPmoEffectiveCr3(process, getbuf_va, guest_cr3);
        if (!target_cr3)
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_NO_CR3);
            break;
        }

        unsigned int instr_size = 0;
        payload_u64 next_va = 0;
        unsigned char old_bytes[20] = {};
        unsigned char next_old[20] = {};
        if (!PayloadPmoDisasmTarget(
                target_cr3,
                getbuf_va,
                &instr_size,
                &next_va,
                old_bytes,
                next_old))
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_DISASM);
            break;
        }

        entry = PayloadEhPrepareEntry(
            process,
            target_cr3,
            getbuf_va,
            false,
            false,
            &entry_freshly_allocated);
        if (!entry)
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_FAKE_ALLOC);
            break;
        }

        payload_u64 fake_target_hva = PayloadEhGetFakeHvaForEntry(entry, getbuf_va);
        if (!PayloadIsKernelPointer(fake_target_hva))
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_COPY_PAGE);
            break;
        }

        g_payload_getbuffer_install_fake = fake_target_hva;
        g_payload_getbuffer_install_orig_pfn =
            PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_orig_pfn);
        g_payload_getbuffer_install_exec_pfn =
            PayloadReadHostU64(entry + g_cached_hv_diag.ept_hook_entry_off_fake_pfn);
        if (!g_payload_getbuffer_install_orig_pfn ||
            !g_payload_getbuffer_install_exec_pfn)
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_FAKE_PA);
            break;
        }
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_FAKE_PA);
        if (PayloadPmoGbBisectStopAt(PAYLOAD_GB_STAGE_FAKE_PA))
            break;

        payload_u64 bp_rip = 0;
        payload_u64 target_resume = 0;
        if (!PayloadPmoAllocUserTrampoline(
                getbuf_va,
                old_bytes,
                instr_size,
                &tramp_va,
                &bp_rip,
                &target_resume))
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_TRAMP);
            break;
        }
        g_payload_getbuffer_install_tramp = tramp_va;
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_TRAMP);
        if (PayloadPmoGbBisectStopAt(PAYLOAD_GB_STAGE_TRAMP))
            break;

        if (!PayloadPmoFindFreeHookSlot(&slot) ||
            !PayloadPmoWriteGetBufferHookSlot(
                slot,
                getbuf_va,
                next_va,
                old_bytes,
                next_old,
                instr_size,
                process,
                blank,
                fake_target_hva,
                tramp_va,
                bp_rip,
                target_resume))
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_SLOT);
            break;
        }
        g_payload_getbuffer_install_slot = slot;
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_SLOT);
        if (PayloadPmoGbBisectStopAt(PAYLOAD_GB_STAGE_SLOT))
            break;

#if !PAYLOAD_GETBUFFER_STAGE15_EPT_ONLY_NO_DISPATCH
        // TestDriver parity: vh_install_host_deferred applies the vmcall stub
        // and marks the slot enabled before eh_install_all_deferred arms EPT.
        // Keep the same order here; do not let an EPT redirect become visible
        // while fake_target_hva is still an unpatched copy of the original page.
        PayloadEhApplyEnableTransition(fake_target_hva);
        if (g_cached_hv_diag.vt_hook_slot_off_data_is_enable)
            PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_is_enable, 1);
#else
        if (g_cached_hv_diag.vt_hook_slot_off_data_is_enable)
            PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_data_is_enable, 0);
#endif

        payload_u64 pending = 0;
        ept_queue_attempted = true;
        payload_native_ept_install_policy policy =
#if PAYLOAD_GETBUFFER_STAGE15_QUEUE_ONLY_NO_EPT_WRITE
            PAYLOAD_NATIVE_EPT_POLICY_QUEUE_ONLY;
#elif PAYLOAD_GETBUFFER_STAGE15_INSTALL_CURRENT_ONLY
            PAYLOAD_NATIVE_EPT_POLICY_INSTALL_CURRENT_ONLY;
#elif PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_WRITE_SAME_INVEPT_ONLY
            PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_WRITE_SAME_INVEPT_ONLY;
#elif PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_WRITE_SAME_ONLY
            PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_WRITE_SAME_ONLY;
#elif PAYLOAD_GETBUFFER_STAGE15_SPLIT_LEAF_LOCATE_ONLY
            PAYLOAD_NATIVE_EPT_POLICY_SPLIT_LEAF_LOCATE_ONLY;
#elif PAYLOAD_GETBUFFER_STAGE15_SPLIT_PUBLISH_INVEPT
            PAYLOAD_NATIVE_EPT_POLICY_SPLIT_PUBLISH_INVEPT;
#elif PAYLOAD_GETBUFFER_STAGE15_SPLIT_PUBLISH_NO_INVEPT
            PAYLOAD_NATIVE_EPT_POLICY_SPLIT_PUBLISH_NO_INVEPT;
#elif PAYLOAD_GETBUFFER_STAGE15_SPLIT_RESERVE_ONLY_NO_PDE
            PAYLOAD_NATIVE_EPT_POLICY_SPLIT_RESERVE_ONLY;
#elif PAYLOAD_GETBUFFER_STAGE15_SPLIT_FILL_ONLY_NO_COMMIT
            PAYLOAD_NATIVE_EPT_POLICY_SPLIT_FILL_ONLY;
#elif PAYLOAD_GETBUFFER_STAGE15_PDE_ONLY_NO_LEAF_READ
            PAYLOAD_NATIVE_EPT_POLICY_PDE_ONLY;
#elif PAYLOAD_GETBUFFER_STAGE15_LOCATE_ONLY_NO_SPLIT_NO_WRITE
            PAYLOAD_NATIVE_EPT_POLICY_LOCATE_ONLY_NO_SPLIT;
#elif PAYLOAD_GETBUFFER_STAGE15_WRITE_SAME_EPT_PTE_ONLY
            PAYLOAD_NATIVE_EPT_POLICY_WRITE_SAME_CURRENT;
#else
            PAYLOAD_NATIVE_EPT_POLICY_DEFERRED;
#endif
        if (!PayloadEptQueueNativeInstallAllEx(
                g_payload_getbuffer_install_orig_pfn,
                g_payload_getbuffer_install_exec_pfn,
                false,
                entry,
                &pending,
                policy))
        {
            PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_EPT);
            g_payload_getbuffer_install_pending = pending;
            break;
        }
        g_payload_getbuffer_install_pending = pending;
        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_EPT);
        if (PayloadPmoGbBisectStopAt(PAYLOAD_GB_STAGE_EPT))
        {
            // EPT has been committed at least on the current vCPU.  Do not run
            // the normal failure cleanup here: it would free the slot/trampoline
            // and entry while an EPT hook may still point at that fake page.
            // Leave a valid slot for normal unload removal.
            keep_committed_ept_state = true;
            ok = true;
            break;
        }

        PayloadPmoSetGbStage(PAYLOAD_GB_STAGE_DONE);
        ok = true;
    } while (false);

    if (!ok && !keep_committed_ept_state)
    {
        if (entry && ept_queue_attempted)
            PayloadEptClearNativePending(
                entry,
                g_payload_getbuffer_install_orig_pfn,
                g_payload_getbuffer_install_exec_pfn);
        if (slot && g_cached_hv_diag.vt_hook_slot_off_occupied)
            PayloadWriteHostU8(slot + g_cached_hv_diag.vt_hook_slot_off_occupied, 0);
        if (tramp_va)
            PayloadPmoFreeTrampoline(tramp_va);
        if (entry && entry_freshly_allocated)
            PayloadEhFreeEntry(entry);
    }

    _InterlockedExchange(&s_payload_native_hook_install_lock, 0);

    if (ok)
        _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_ok);
    else
        _InterlockedIncrement64((volatile LONG64*)&g_payload_getbuffer_install_fail);

    return ok;
#endif
}

#ifndef PAYLOAD_ENABLE_NATIVE_SWAPCHAIN_EXTRA_INSTALL
#define PAYLOAD_ENABLE_NATIVE_SWAPCHAIN_EXTRA_INSTALL 0
#endif

#ifndef PAYLOAD_ENABLE_NATIVE_COPY_DUP_INSTALL
#define PAYLOAD_ENABLE_NATIVE_COPY_DUP_INSTALL 0
#endif

#ifndef PAYLOAD_ENABLE_NATIVE_NT_MEMORY_INSTALL
#define PAYLOAD_ENABLE_NATIVE_NT_MEMORY_INSTALL 0
#endif

#ifndef PAYLOAD_ENABLE_NATIVE_MM_FILTER_INSTALL
#define PAYLOAD_ENABLE_NATIVE_MM_FILTER_INSTALL 0
#endif

#if PAYLOAD_STABLE_GETBUFFER_ONLY
// Bisect line: keep the resident PMO bootstrap and the native GetBuffer
// purple-marker path, then enable exactly one experimental group at a time.
// Current candidate enables only Present/Present1; Copy/Duplicate, Nt*, and
// Mm* remain off.
#undef PAYLOAD_ENABLE_NATIVE_SWAPCHAIN_EXTRA_INSTALL
#undef PAYLOAD_ENABLE_NATIVE_COPY_DUP_INSTALL
#undef PAYLOAD_ENABLE_NATIVE_NT_MEMORY_INSTALL
#undef PAYLOAD_ENABLE_NATIVE_MM_FILTER_INSTALL
#define PAYLOAD_ENABLE_NATIVE_SWAPCHAIN_EXTRA_INSTALL PAYLOAD_BISECT_ENABLE_SWAPCHAIN_EXTRA
#define PAYLOAD_ENABLE_NATIVE_COPY_DUP_INSTALL PAYLOAD_BISECT_ENABLE_COPY_DUP
#define PAYLOAD_ENABLE_NATIVE_NT_MEMORY_INSTALL PAYLOAD_BISECT_ENABLE_NT_MEMORY
#define PAYLOAD_ENABLE_NATIVE_MM_FILTER_INSTALL PAYLOAD_BISECT_ENABLE_MM_FILTER
#endif

static bool PayloadPmoTryInstallSwapchainExtraHooks(payload_guest_context* ctx)
{
    if (!ctx)
        return false;

    payload_u64 swapchain = g_payload_pmo_last_swapchain ? g_payload_pmo_last_swapchain : ctx->rcx;
    if (!PayloadIsCanonical(swapchain))
        return false;

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return false;

    payload_u64 process = 0;
    payload_u64 thread = 0;
    if (!PayloadCurrentGuestIds(&process, &thread) || !PayloadIsKernelPointer(process))
        return false;

    payload_u64 blank = PayloadPmoFindBlankMemory(1);
    if (!blank)
        return false;

    bool ok_any = false;
    payload_u64 present = 0;
    if (PayloadPmoGetVFunc(guest_cr3, swapchain, 8, &present) &&
        PayloadIsCanonical(present) &&
        !PayloadIsKernelPointer(present))
    {
        payload_native_hook_install_result res = {};
        ok_any = PayloadPmoInstallLegacyHookNative(
            process,
            present,
            blank,
            9,
            true,
            true,
            guest_cr3,
            &res) || ok_any;
    }

    payload_u64 present1 = 0;
    if (PayloadPmoGetVFunc(guest_cr3, swapchain, 22, &present1) &&
        PayloadIsCanonical(present1) &&
        !PayloadIsKernelPointer(present1))
    {
        payload_native_hook_install_result res = {};
        ok_any = PayloadPmoInstallLegacyHookNative(
            process,
            present1,
            blank,
            10,
            true,
            true,
            guest_cr3,
            &res) || ok_any;
    }

    return ok_any;
}

static payload_u64 PayloadPmoReadGhvU64Field(payload_u64 offset)
{
    if (!offset || !g_hv_diag_cache_ready || !PayloadIsKernelPointer(g_cached_hv_diag.ghv))
        return 0;
    payload_u64 field = g_cached_hv_diag.ghv + offset;
    return PayloadIsKernelPointer(field) ? PayloadReadHostU64(field) : 0;
}

static bool PayloadPmoTryInstallCopyDuplicateHooks(payload_guest_context* ctx)
{
    if (!ctx)
        return false;

    payload_u64 guest_cr3 = 0;
    if (!PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) || !guest_cr3)
        return false;

    payload_u64 process = 0;
    payload_u64 thread = 0;
    if (!PayloadCurrentGuestIds(&process, &thread) || !PayloadIsKernelPointer(process))
        return false;

    payload_u64 blank = PayloadPmoFindBlankMemory(1);
    if (!blank)
        return false;

    bool ok_any = false;
    payload_u64 copy_resource = PayloadPmoReadGhvU64Field(g_cached_hv_diag.ghv_off_copyresource_addr);
    if (PayloadIsCanonical(copy_resource) && !PayloadIsKernelPointer(copy_resource))
    {
        payload_native_hook_install_result res = {};
        ok_any = PayloadPmoInstallLegacyHookNative(
            process,
            copy_resource,
            blank,
            11,
            true,
            true,
            guest_cr3,
            &res) || ok_any;
    }

    payload_u64 duplicate_output = PayloadPmoReadGhvU64Field(g_cached_hv_diag.ghv_off_duplicateoutput_addr);
    if (PayloadIsCanonical(duplicate_output) && !PayloadIsKernelPointer(duplicate_output))
    {
        payload_native_hook_install_result res = {};
        ok_any = PayloadPmoInstallLegacyHookNative(
            process,
            duplicate_output,
            blank,
            12,
            true,
            true,
            guest_cr3,
            &res) || ok_any;
    }

    return ok_any;
}

static bool PayloadPmoTryInstallOneKernelHook(payload_u64 target_va,
                                              payload_u64 process,
                                              payload_u64 type,
                                              bool filter_by_process)
{
    if (!PayloadIsKernelPointer(target_va))
        return false;

    payload_native_hook_install_result res = {};
    return PayloadPmoInstallLegacyHookNative(
        filter_by_process ? process : 0,
        target_va,
        0,
        type,
        filter_by_process,
        true,
        g_system_cr3,
        &res);
}

static payload_u64 PayloadPmoMm4BitForType(payload_u64 type)
{
    switch (type)
    {
    case 18: return 0x1ull; // MmCopyMemory
    case 19: return 0x2ull; // MmCopyVirtualMemory
    case 20: return 0x4ull; // MmIsAddressValid
    case 21: return 0x8ull; // MmMapIoSpace
    case 29: return 0x10ull; // MmIsAddressValidEx (observe-only by default)
    case 27: return 0x20ull; // NtQueryVirtualMemory
    case 28: return 0x40ull; // MmGetPhysicalAddress
    default: return 0;
    }
}

static payload_u64 PayloadPmoMmFilterExpectedMask()
{
    payload_u64 mask = 0;
#if PAYLOAD_BISECT_MM_HOOK_COPY_MEMORY
    mask |= PayloadPmoMm4BitForType(18);
#endif
#if PAYLOAD_BISECT_MM_HOOK_COPY_VIRTUAL_MEMORY
    mask |= PayloadPmoMm4BitForType(19);
#endif
#if PAYLOAD_BISECT_MM_HOOK_IS_ADDRESS_VALID
    mask |= PayloadPmoMm4BitForType(20);
#endif
#if PAYLOAD_BISECT_MM_HOOK_MAP_IO_SPACE
    mask |= PayloadPmoMm4BitForType(21);
#endif
#if PAYLOAD_BISECT_ENABLE_MM_FILTER_EXT && PAYLOAD_BISECT_EXT_HOOK_IS_ADDRESS_VALID_EX
#if PAYLOAD_BISECT_EXT_HOOK_IS_ADDRESS_VALID_EX_OBSERVE_ONLY
    mask |= PayloadPmoMm4BitForType(29);
#else
    mask |= PayloadPmoMm4BitForType(20);
#endif
#endif
#if PAYLOAD_BISECT_ENABLE_MM_FILTER_EXT && PAYLOAD_BISECT_EXT_HOOK_NT_QUERY_VIRTUAL_MEMORY
    mask |= PayloadPmoMm4BitForType(27);
#endif
#if PAYLOAD_BISECT_ENABLE_MM_FILTER_EXT && PAYLOAD_BISECT_EXT_HOOK_MM_GET_PHYSICAL_ADDRESS
    mask |= PayloadPmoMm4BitForType(28);
#endif
    return mask;
}

static bool PayloadPmoTryInstallOneMm4Hook(payload_u64 target_va, payload_u64 type)
{
    payload_u64 bit = PayloadPmoMm4BitForType(type);
    if (!bit)
        return false;

    if (g_payload_mm4_install_mask & bit)
        return true;

    _InterlockedIncrement64((volatile LONG64*)&g_payload_mm4_install_probe);
    g_payload_mm4_install_last_type = type;
    g_payload_mm4_install_last_target = target_va;
    g_payload_mm4_install_last_slot = 0;
    g_payload_mm4_install_last_pending = 0;

    if (!PayloadIsKernelPointer(target_va))
    {
        g_payload_mm4_install_last_stage = PAYLOAD_GB_STAGE_VFUNC;
        _InterlockedIncrement64((volatile LONG64*)&g_payload_mm4_install_fail);
        _InterlockedOr64((volatile LONG64*)&g_payload_mm4_install_fail_mask, (LONG64)bit);
        return false;
    }

    payload_native_hook_install_result res = {};
    bool ok = PayloadPmoInstallLegacyHookNative(
        0,
        target_va,
        0,
        type,
        false,
        PAYLOAD_MM4_INSTALL_AUTO_ENABLE != 0,
        g_system_cr3,
        &res);

    g_payload_mm4_install_last_stage = res.stage;
    g_payload_mm4_install_last_target = res.target;
    g_payload_mm4_install_last_slot = res.slot;
    g_payload_mm4_install_last_pending = res.pending;

    if (ok)
    {
        _InterlockedOr64((volatile LONG64*)&g_payload_mm4_install_mask, (LONG64)bit);
        if (res.stage == PAYLOAD_GB_STAGE_ALREADY)
            _InterlockedIncrement64((volatile LONG64*)&g_payload_mm4_install_already);
        else
            _InterlockedIncrement64((volatile LONG64*)&g_payload_mm4_install_ok);
        return true;
    }

    _InterlockedIncrement64((volatile LONG64*)&g_payload_mm4_install_fail);
    _InterlockedOr64((volatile LONG64*)&g_payload_mm4_install_fail_mask, (LONG64)bit);
    return false;
}

static bool PayloadPmoTryInstallNtMemoryHooks(payload_guest_context* ctx)
{
    if (!ctx)
        return false;

    payload_u64 process = 0;
    payload_u64 thread = 0;
    if (!PayloadCurrentGuestIds(&process, &thread) || !PayloadIsKernelPointer(process))
        return false;

    bool ok_any = false;
    ok_any = PayloadPmoTryInstallOneKernelHook(
        g_cached_hv_diag.nt_set_event_va,
        0,
        14,
        false) || ok_any;
    ok_any = PayloadPmoTryInstallOneKernelHook(
        g_cached_hv_diag.nt_allocate_virtual_memory_va,
        process,
        15,
        true) || ok_any;
    ok_any = PayloadPmoTryInstallOneKernelHook(
        g_cached_hv_diag.nt_protect_virtual_memory_va,
        process,
        16,
        true) || ok_any;
    ok_any = PayloadPmoTryInstallOneKernelHook(
        g_cached_hv_diag.nt_map_view_of_section_va,
        process,
        17,
        true) || ok_any;
    ok_any = PayloadPmoTryInstallOneKernelHook(
        g_cached_hv_diag.nt_create_section_va,
        process,
        6,
        true) || ok_any;
    return ok_any;
}

static bool PayloadPmoTryInstallMmFilterHooks(payload_guest_context*)
{
    payload_u64 expected_mask = PayloadPmoMmFilterExpectedMask();
    if (expected_mask && (g_payload_mm4_install_mask & expected_mask) == expected_mask)
        return true;

    bool ok_any = false;
#if PAYLOAD_BISECT_MM_HOOK_COPY_MEMORY
    ok_any = PayloadPmoTryInstallOneMm4Hook(
        g_cached_hv_diag.mm_copy_memory_va,
        18) || ok_any;
#endif
#if PAYLOAD_BISECT_MM_HOOK_COPY_VIRTUAL_MEMORY
    ok_any = PayloadPmoTryInstallOneMm4Hook(
        g_cached_hv_diag.mm_copy_virtual_memory_va,
        19) || ok_any;
#endif
#if PAYLOAD_BISECT_MM_HOOK_IS_ADDRESS_VALID
    ok_any = PayloadPmoTryInstallOneMm4Hook(
        g_cached_hv_diag.mm_is_address_valid_va,
        20) || ok_any;
#endif
#if PAYLOAD_BISECT_ENABLE_MM_FILTER_EXT && PAYLOAD_BISECT_EXT_HOOK_IS_ADDRESS_VALID_EX
    ok_any = PayloadPmoTryInstallOneMm4Hook(
        g_cached_hv_diag.mm_is_address_valid_ex_va,
#if PAYLOAD_BISECT_EXT_HOOK_IS_ADDRESS_VALID_EX_OBSERVE_ONLY
        29
#else
        20
#endif
        ) || ok_any;
#endif
#if PAYLOAD_BISECT_MM_HOOK_MAP_IO_SPACE
    ok_any = PayloadPmoTryInstallOneMm4Hook(
        g_cached_hv_diag.mm_map_io_space_va,
        21) || ok_any;
#endif
#if PAYLOAD_BISECT_ENABLE_MM_FILTER_EXT && PAYLOAD_BISECT_EXT_HOOK_NT_QUERY_VIRTUAL_MEMORY
    ok_any = PayloadPmoTryInstallOneMm4Hook(
        g_cached_hv_diag.nt_query_virtual_memory_va,
        27) || ok_any;
#endif
#if PAYLOAD_BISECT_ENABLE_MM_FILTER_EXT && PAYLOAD_BISECT_EXT_HOOK_MM_GET_PHYSICAL_ADDRESS
    ok_any = PayloadPmoTryInstallOneMm4Hook(
        g_cached_hv_diag.mm_get_physical_address_va,
        28) || ok_any;
#endif
    return ok_any;
}


