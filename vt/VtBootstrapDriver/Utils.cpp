#pragma warning(disable : 4201 4311 4302)

#include "Utils.h"
#include <ntimage.h>
#include "base.h"
#include "common/ntutils.h"
#include "poolmanager/PoolManager.h"
#include "vt/hv.h"

namespace Utils
{
typedef NTSTATUS(NTAPI *DriverEntryProc)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

_DRIVER_OBJECT testDriver;
PVOID imageBase = nullptr;
ULONG imageSize = 0;
BOOLEAN testDriverUnloaded = FALSE;
BOOLEAN testDriverUnloadCallbackCalled = FALSE;
BOOLEAN testDriverImageQuarantined = FALSE;
static volatile LONG g_quarantined_image_count = 0;
static volatile LONG g_quarantined_payload_count = 0;
static volatile LONG g_quarantined_machenike_count = 0;
_DRIVER_OBJECT payloadDriver;
payload_exports *payloadExports = nullptr;
PVOID payloadBase = nullptr;
ULONG payloadSize = 0;
PVOID payloadArenaBase = nullptr;
ULONG payloadArenaSize = 0;
PVOID machenikeBase = nullptr;
ULONG machenikeSize = 0;
BOOLEAN machenikeLoaded = FALSE;
ULONG machenikeMode = 0;
BOOLEAN machenikeUsedIndependent = FALSE;
PDRIVER_UNLOAD machenikeUnload = nullptr;
PDRIVER_DISPATCH machenikeCreateDispatch = nullptr;
PDRIVER_DISPATCH machenikeCloseDispatch = nullptr;
PDRIVER_DISPATCH machenikeDeviceControlDispatch = nullptr;

static volatile LONG g_machenike_text_dual_view_state = 0;
static ULONG g_machenike_text_dual_view_page_count = 0;
static UINT64 g_machenike_text_dual_view_pages[VT_MACHENIKE_TEXT_DUAL_VIEW_MAX_PAGES] = {};

static_assert(VT_MACHENIKE_TEXT_DUAL_VIEW_MAX_PAGES <= VT_EH_TABLE_CAPACITY,
    "Machenike text dual-view page budget exceeds EH table capacity");

static BOOLEAN CollectMachenikeTextPages(
    PVOID image_base,
    ULONG image_size,
    UINT64* pages,
    ULONG* page_count)
{
#if VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED
    if (!image_base || !image_size || !pages || !page_count)
        return FALSE;

    *page_count = 0;

    __try
    {
        auto base = reinterpret_cast<UINT64>(image_base);
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (image_size < sizeof(IMAGE_DOS_HEADER) ||
            dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER))
            return FALSE;

        UINT64 const nt_offset = (UINT64)(ULONG)dos->e_lfanew;
        if (nt_offset > image_size - sizeof(IMAGE_NT_HEADERS64))
            return FALSE;

        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + nt_offset);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return FALSE;

        ULONG const section_count = nt->FileHeader.NumberOfSections;
        if (!section_count || section_count > 96)
            return FALSE;

        UINT64 const section_bytes = (UINT64)section_count * sizeof(IMAGE_SECTION_HEADER);
        UINT64 const section_offset = nt_offset + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER) +
            nt->FileHeader.SizeOfOptionalHeader;
        if (section_offset > image_size || section_bytes > image_size - section_offset)
            return FALSE;

        auto sections = IMAGE_FIRST_SECTION(nt);
        for (ULONG i = 0; i < section_count; ++i)
        {
            auto const& section = sections[i];
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                RtlCompareMemory(section.Name, ".text", 5) != 5)
                continue;

            ULONG section_size = section.Misc.VirtualSize;
            if (!section_size)
                section_size = section.SizeOfRawData;
            if (!section_size || section.VirtualAddress >= image_size ||
                section_size > image_size - section.VirtualAddress)
                return FALSE;

            UINT64 const begin = base + section.VirtualAddress;
            UINT64 const end = begin + section_size;
            UINT64 const first_page = (begin + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1);
            UINT64 const last_page = end & ~(UINT64)(PAGE_SIZE - 1);

            // 只处理完全落在 .text 内的页，跳过与其他节共享的边界页。
            for (UINT64 page = first_page; page < last_page; page += PAGE_SIZE)
            {
                bool duplicate = false;
                for (ULONG j = 0; j < *page_count; ++j)
                {
                    if (pages[j] == page)
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate)
                    continue;
                if (*page_count >= VT_MACHENIKE_TEXT_DUAL_VIEW_MAX_PAGES)
                    return FALSE;
                pages[(*page_count)++] = page;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *page_count = 0;
        return FALSE;
    }

    return *page_count != 0;
#else
    UNREFERENCED_PARAMETER(image_base);
    UNREFERENCED_PARAMETER(image_size);
    UNREFERENCED_PARAMETER(pages);
    if (page_count)
        *page_count = 0;
    return TRUE;
#endif
}

static BOOLEAN MachenikeTextDualViewVmcallAll(
    hv::hypercall_code code,
    UINT64 va)
{
#if VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED
    ULONG attempted = 0;
    ULONG succeeded = 0;
    USHORT const group_count = KeQueryActiveGroupCount();

    for (USHORT group = 0; group < group_count; ++group)
    {
        ULONG const processors = KeQueryActiveProcessorCountEx(group);
        for (ULONG cpu = 0; cpu < processors && cpu < 64; ++cpu)
        {
            GROUP_AFFINITY affinity = {};
            affinity.Group = group;
            affinity.Mask = 1ull << cpu;
            GROUP_AFFINITY previous = {};
            KeSetSystemGroupAffinityThread(&affinity, &previous);

            hv::hypercall_input input = {};
            input.code = code;
            input.key = hv::hypercall_key;
            input.args[0] = 0; // 内核虚拟地址统一归一化到 system_cr3
            input.args[1] = va;
            if (code == hv::hypercall_eh_install)
                input.args[2] = 3; // full_zero + is_fake_page

            UINT64 result = 0;
            bool const call_ok = hv::try_vmcall(input, &result);
            KeRevertToUserGroupAffinityThread(&previous);

            ++attempted;
            if (call_ok && result != 0)
                ++succeeded;
        }
    }

    return attempted != 0 && succeeded == attempted;
#else
    UNREFERENCED_PARAMETER(code);
    UNREFERENCED_PARAMETER(va);
    return TRUE;
#endif
}

BOOLEAN InstallMachenikeTextDualView()
{
#if VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED
    if (!machenikeLoaded || !machenikeBase || !machenikeSize)
        return FALSE;

    LONG const previous = _InterlockedCompareExchange(&g_machenike_text_dual_view_state, -1, 0);
    if (previous != 0)
        return previous == 1 ? TRUE : FALSE;

    UINT64 pages[VT_MACHENIKE_TEXT_DUAL_VIEW_MAX_PAGES] = {};
    ULONG page_count = 0;
    if (!CollectMachenikeTextPages(machenikeBase, machenikeSize, pages, &page_count))
    {
        _InterlockedExchange(&g_machenike_text_dual_view_state, 0);
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike .text dual-view parse failed base=%p size=0x%X\n"),
            machenikeBase, machenikeSize);
        return FALSE;
    }

    ULONG installed = 0;
    for (; installed < page_count; ++installed)
    {
        if (!MachenikeTextDualViewVmcallAll(hv::hypercall_eh_install, pages[installed]))
            break;
    }

    if (installed != page_count)
    {
        for (ULONG i = 0; i < installed; ++i)
            MachenikeTextDualViewVmcallAll(hv::hypercall_eh_remove, pages[i]);
        _InterlockedExchange(&g_machenike_text_dual_view_state, 0);
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike .text dual-view install failed installed=%lu/%lu\n"),
            installed, page_count);
        return FALSE;
    }

    RtlCopyMemory(g_machenike_text_dual_view_pages, pages, sizeof(UINT64) * page_count);
    g_machenike_text_dual_view_page_count = page_count;
    _InterlockedExchange(&g_machenike_text_dual_view_state, 1);
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike .text dual-view active pages=%lu mode=execute-original/read-zero\n"),
        page_count);
    return TRUE;
#else
    return TRUE;
#endif
}

VOID RemoveMachenikeTextDualView()
{
#if VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED
    // 进入移除态，阻止重复加载路径在全核 EH 尚未摘除时重新安装。
    if (_InterlockedCompareExchange(&g_machenike_text_dual_view_state, -1, 1) != 1)
        return;

    ULONG const page_count = g_machenike_text_dual_view_page_count;
    ULONG removed = 0;
    for (ULONG i = 0; i < page_count; ++i)
    {
        if (MachenikeTextDualViewVmcallAll(hv::hypercall_eh_remove, g_machenike_text_dual_view_pages[i]))
            ++removed;
        g_machenike_text_dual_view_pages[i] = 0;
    }
    g_machenike_text_dual_view_page_count = 0;
    _InterlockedExchange(&g_machenike_text_dual_view_state, 0);
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike .text dual-view removed pages=%lu/%lu\n"),
        removed, page_count);
#endif
}

static NTSTATUS ManualDriverInvalidDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    if (!Irp)
        return STATUS_INVALID_DEVICE_REQUEST;

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static void PrepareManualDriverObject(PDRIVER_OBJECT driver, PVOID image, ULONG image_size, PVOID entry)
{
    if (!driver)
        return;

    RtlZeroMemory(driver, sizeof(*driver));
    driver->Type = IO_TYPE_DRIVER;
    driver->Size = sizeof(*driver);
    driver->DriverStart = image;
    driver->DriverSize = image_size;
    driver->DriverInit = (PDRIVER_INITIALIZE)entry;
    driver->DriverUnload = nullptr;

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
        driver->MajorFunction[i] = ManualDriverInvalidDispatch;
}

static void *PayloadHostAlloc(payload_u64 size, payload_u64 tag)
{
    UNREFERENCED_PARAMETER(tag);
    if (!size || size > 0x7FFFFFFFull)
        return nullptr;
    return Util::PoolManagertAllocation((ULONG)size);
}

static void PayloadHostFree(void *ptr)
{
    if (ptr)
        Util::PoolManagerFreePool(ptr);
}

static void *PayloadHostResolve(const unsigned short *routine_name)
{
    if (!routine_name)
        return nullptr;
    UNICODE_STRING name = {};
    RtlInitUnicodeString(&name, (PCWSTR)routine_name);
    return MmGetSystemRoutineAddress(&name);
}

static payload_host_api g_payloadHostApi = {
    PAYLOAD_API_MAGIC,
    sizeof(payload_host_api),
    PAYLOAD_ABI_VERSION,
    PAYLOAD_HOST_API_FLAG_ALLOC | PAYLOAD_HOST_API_FLAG_FREE | PAYLOAD_HOST_API_FLAG_RESOLVE,
    PayloadHostAlloc,
    PayloadHostFree,
    PayloadHostResolve,
    0,
    0,
    0,
    0,
    0,
};

static void PreparePayloadHostApi()
{
    g_payloadHostApi.abi_version = PAYLOAD_ABI_VERSION;
    g_payloadHostApi.size = sizeof(payload_host_api);
    g_payloadHostApi.kernel_flags = 0;
#if VT_MEM_FORCE_EXALLOCPOOL
    g_payloadHostApi.mm_allocate_independent_pages = nullptr;
    g_payloadHostApi.mm_free_independent_pages = nullptr;
    g_payloadHostApi.mm_set_page_protection = nullptr;
#else
    g_payloadHostApi.mm_allocate_independent_pages = MmAllocateIndependentPages;
    g_payloadHostApi.mm_free_independent_pages = MmFreeIndependentPages;
    g_payloadHostApi.mm_set_page_protection = MmSetPageProtection;
    if (MmAllocateIndependentPages && MmFreeIndependentPages && MmSetPageProtection)
        g_payloadHostApi.kernel_flags |= PAYLOAD_KERNEL_API_FLAG_INDEPENDENT_PAGES;
#endif
}
SectionSnap SectionSnaps[kSectionSnapMax] = {};
ULONG SectionSnapCount = 0;

static constexpr ULONGLONG kPayloadRawMagic = 0x504C445241573031ull; // PLDRAW01
static constexpr ULONG kPayloadRawVersion = 2;

#pragma pack(push, 1)
struct PayloadRawHeader
{
    ULONGLONG magic;
    ULONG version;
    ULONG header_size;
    ULONGLONG preferred_base;
    ULONG image_size;
    ULONG entry_rva;
    ULONG section_count;
    ULONG reloc_count;
    ULONG section_table_offset;
    ULONG reloc_table_offset;
    ULONG data_offset;
    ULONG data_size;
};

struct PayloadRawSection
{
    ULONG rva;
    ULONG virtual_size;
    ULONG raw_size;
    ULONG data_offset;
    ULONG characteristics;
};
#pragma pack(pop)

static bool RangeInBuffer(ULONG offset, ULONG size, ULONG total)
{
    return offset <= total && size <= (total - offset);
}

static PUCHAR FileToImage(char *fileBuffer)
{
    if (!fileBuffer)
        return nullptr;

    auto dos = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto nt = (PIMAGE_NT_HEADERS)(fileBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    ULONG imageSize = nt->OptionalHeader.SizeOfImage;
    PUCHAR image = (PUCHAR)Util::PoolManagertAllocation(imageSize);
    if (!image)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] FileToImage allocation failed size=0x%X\n"), imageSize);
        return nullptr;
    }
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] FileToImage allocated base=%p size=0x%X sections=%u\n"), image, imageSize,
              (ULONG)nt->FileHeader.NumberOfSections);

    RtlZeroMemory(image, imageSize);
    RtlCopyMemory(image, fileBuffer, nt->OptionalHeader.SizeOfHeaders);

    auto section = IMAGE_FIRST_SECTION(nt);
    for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (section[i].SizeOfRawData)
        {
            RtlCopyMemory(image + section[i].VirtualAddress, fileBuffer + section[i].PointerToRawData,
                          section[i].SizeOfRawData);
        }
    }

    return image;
}

static void CopyLowerAscii(char *dst, SIZE_T dstSize, const char *src, SIZE_T srcMax)
{
    if (!dst || !dstSize)
        return;

    SIZE_T i = 0;
    for (; i + 1 < dstSize && i < srcMax && src && src[i]; ++i)
    {
        char c = src[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        dst[i] = c;
    }
    dst[i] = 0;
}

static BOOLEAN UpdateRelocation(char *image)
{
    auto dos = (PIMAGE_DOS_HEADER)image;
    auto nt = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);
    auto dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir->VirtualAddress || !dir->Size)
        return TRUE;

    auto base = (PIMAGE_BASE_RELOCATION)(image + dir->VirtualAddress);
    while (base->SizeOfBlock && base->VirtualAddress)
    {
        auto block = (NT::PIMAGE_RELOC)((PUCHAR)base + sizeof(IMAGE_BASE_RELOCATION));
        UINT32 count = (base->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(NT::IMAGE_RELOC);

        for (UINT32 i = 0; i < count; ++i)
        {
            PUCHAR patch = (PUCHAR)image + base->VirtualAddress + block[i].Offset;
            if (block[i].Type == IMAGE_REL_BASED_DIR64)
            {
                auto address = (PUINT64)patch;
                *address = *address - nt->OptionalHeader.ImageBase + (UINT64)image;
            }
            else if (block[i].Type == IMAGE_REL_BASED_HIGHLOW)
            {
                auto address = (PUINT32)patch;
                *address = *address - (UINT32)nt->OptionalHeader.ImageBase + (UINT32)(ULONG_PTR)image;
            }
        }

        base = (PIMAGE_BASE_RELOCATION)((PUCHAR)base + base->SizeOfBlock);
    }

    return TRUE;
}

ULONG_PTR QueryModule(PUCHAR moduleName, ULONG_PTR *moduleSize)
{
    if (!moduleName)
        return 0;

    NT::RTL_PROCESS_MODULES localModules = {0};
    NT::PRTL_PROCESS_MODULES modules = &localModules;
    BOOLEAN allocated = FALSE;
    ULONG bytes = 0;

    NTSTATUS status = NT::ZwQuerySystemInformation(NT::SystemModuleInformation, modules, sizeof(localModules), &bytes);

    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        modules = (NT::PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, bytes, MEM_TAG);
        if (!modules)
            return 0;

        RtlZeroMemory(modules, bytes);
        status = NT::ZwQuerySystemInformation(NT::SystemModuleInformation, modules, bytes, &bytes);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(modules, MEM_TAG);
            return 0;
        }
        allocated = TRUE;
    }
    else if (!NT_SUCCESS(status))
    {
        return 0;
    }

    ULONG_PTR moduleBase = 0;
    if (_stricmp((char *)moduleName, _XOR_("ntoskrnl.exe")) == 0 ||
        _stricmp((char *)moduleName, _XOR_("ntkrnlpa.exe")) == 0)
    {
        moduleBase = (ULONG_PTR)modules->Modules[0].ImageBase;
        if (moduleSize)
            *moduleSize = modules->Modules[0].ImageSize;
    }
    else
    {
        char wanted[260] = {};
        CopyLowerAscii(wanted, sizeof(wanted), (char *)moduleName, 259);

        ULONG moduleCount = modules->NumberOfModules;
        ULONG maxCount = 1;
        if (allocated && bytes > FIELD_OFFSET(NT::RTL_PROCESS_MODULES, Modules))
            maxCount =
                (bytes - FIELD_OFFSET(NT::RTL_PROCESS_MODULES, Modules)) / sizeof(NT::RTL_PROCESS_MODULE_INFORMATION);
        if (moduleCount > maxCount)
            moduleCount = maxCount;

        for (ULONG i = 0; i < moduleCount; ++i)
        {
            auto info = &modules->Modules[i];
            char path[sizeof(info->FullPathName) + 1] = {};
            CopyLowerAscii(path, sizeof(path), info->FullPathName, sizeof(info->FullPathName));

            if (strstr(path, wanted))
            {
                moduleBase = (ULONG_PTR)info->ImageBase;
                if (moduleSize)
                    *moduleSize = info->ImageSize;
                break;
            }
        }
    }

    if (allocated)
        ExFreePoolWithTag(modules, MEM_TAG);

    return moduleBase;
}

static ULONG64 ExportByName(char *moduleBase, char *functionName)
{
    auto dos = (PIMAGE_DOS_HEADER)moduleBase;
    auto nt = (PIMAGE_NT_HEADERS)(moduleBase + dos->e_lfanew);
    auto dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size)
        return 0;

    auto exp = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + dir->VirtualAddress);
    auto functions = (PULONG)(moduleBase + exp->AddressOfFunctions);
    auto names = (PULONG)(moduleBase + exp->AddressOfNames);
    auto ordinals = (PUSHORT)(moduleBase + exp->AddressOfNameOrdinals);

    for (ULONG i = 0; i < exp->NumberOfNames; ++i)
    {
        char *name = moduleBase + names[i];
        if (strcmp(name, functionName) == 0)
            return (ULONG64)moduleBase + functions[ordinals[i]];
    }

    return 0;
}

static BOOLEAN UpdateIAT(char *image)
{
    auto dos = (PIMAGE_DOS_HEADER)image;
    auto nt = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);
    auto dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->VirtualAddress || !dir->Size)
        return TRUE;

    auto desc = (PIMAGE_IMPORT_DESCRIPTOR)(image + dir->VirtualAddress);
    for (; desc->Name; ++desc)
    {
        PUCHAR libName = (PUCHAR)(image + desc->Name);
        ULONG_PTR base = QueryModule(libName, nullptr);
        if (!base)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] IAT module resolve failed: %s\n"), libName);
            return FALSE;
        }

        auto thunkName =
            (PIMAGE_THUNK_DATA)(image + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        auto thunkFunc = (PIMAGE_THUNK_DATA)(image + desc->FirstThunk);
        for (; thunkName->u1.AddressOfData; ++thunkName, ++thunkFunc)
        {
            if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal))
            {
                LOG_DEBUG(_XOR_("[VtBootstrapDriver] IAT ordinal import unsupported: %s ordinal=0x%llX\n"), libName,
                          (ULONGLONG)IMAGE_ORDINAL(thunkName->u1.Ordinal));
                return FALSE;
            }

            auto importName = (PIMAGE_IMPORT_BY_NAME)(image + thunkName->u1.AddressOfData);
            ULONG_PTR func = ExportByName((char *)base, importName->Name);
            if (!func)
            {
                LOG_DEBUG(_XOR_("[VtBootstrapDriver] IAT export resolve failed: %s!%s\n"), libName, importName->Name);
                return FALSE;
            }

            thunkFunc->u1.Function = func;
        }
    }

    return TRUE;
}

static const char *RawAsciiInImage(const char *image, ULONG imageSize, ULONG rva, ULONG maxLength)
{
    if (!image || !maxLength || !RangeInBuffer(rva, 1, imageSize))
        return nullptr;

    ULONG available = imageSize - rva;
    if (available > maxLength)
        available = maxLength;

    const char *text = image + rva;
    for (ULONG i = 0; i < available; ++i)
    {
        if (!text[i])
            return text;
    }
    return nullptr;
}

static BOOLEAN RawImportModuleAllowed(const char *moduleName)
{
    if (!moduleName)
        return FALSE;

    return _stricmp(moduleName, _XOR_("ntoskrnl.exe")) == 0 || _stricmp(moduleName, _XOR_("ntkrnlmp.exe")) == 0 ||
           _stricmp(moduleName, _XOR_("ntkrnlpa.exe")) == 0 || _stricmp(moduleName, _XOR_("ntkrpamp.exe")) == 0 ||
           _stricmp(moduleName, _XOR_("netio.sys")) == 0;
}

// RawPack v2 保留 PE 头，用严格边界检查解析 IAT。任何未知模块、序号导入、
// 未终止字符串或越界 thunk 都会在进入 payload 前失败，避免再次跳转到裸 RVA。
static BOOLEAN UpdateRawIAT(char *image, ULONG imageSize, ULONG *resolvedCount)
{
    if (resolvedCount)
        *resolvedCount = 0;
    if (!image || imageSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    auto dos = (PIMAGE_DOS_HEADER)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        !RangeInBuffer((ULONG)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS64), imageSize))
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload PE header invalid\n"));
        return FALSE;
    }

    auto nt = (PIMAGE_NT_HEADERS64)(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT ||
        nt->OptionalHeader.SizeOfImage != imageSize || !nt->OptionalHeader.SizeOfHeaders ||
        !RangeInBuffer(0, nt->OptionalHeader.SizeOfHeaders, imageSize))
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload NT header invalid image=0x%X\n"), imageSize);
        return FALSE;
    }

    const auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress && !dir.Size)
        return TRUE;
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
        !RangeInBuffer(dir.VirtualAddress, dir.Size, imageSize))
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload import directory invalid rva=0x%X size=0x%X\n"),
                  dir.VirtualAddress, dir.Size);
        return FALSE;
    }

    ULONG resolved = 0;
    BOOLEAN descriptorTerminated = FALSE;
    ULONG descriptorCount = dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (ULONG descriptorIndex = 0; descriptorIndex < descriptorCount; ++descriptorIndex)
    {
        ULONG descriptorRva = dir.VirtualAddress + descriptorIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        auto desc = (PIMAGE_IMPORT_DESCRIPTOR)(image + descriptorRva);
        if (!desc->OriginalFirstThunk && !desc->TimeDateStamp && !desc->ForwarderChain && !desc->Name &&
            !desc->FirstThunk)
        {
            descriptorTerminated = TRUE;
            break;
        }

        const char *moduleName = RawAsciiInImage(image, imageSize, desc->Name, 128);
        if (!moduleName || !RawImportModuleAllowed(moduleName) || !desc->FirstThunk ||
            !(desc->OriginalFirstThunk || desc->FirstThunk))
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload import descriptor rejected index=%u\n"), descriptorIndex);
            return FALSE;
        }

        ULONG_PTR moduleSize = 0;
        ULONG_PTR moduleBase = QueryModule((PUCHAR)moduleName, &moduleSize);
        if (!moduleBase || !moduleSize || moduleBase + moduleSize <= moduleBase)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload import module unavailable: %s\n"), moduleName);
            return FALSE;
        }

        ULONG nameThunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        ULONG maxNameThunks = nameThunkRva < imageSize ? (imageSize - nameThunkRva) / sizeof(IMAGE_THUNK_DATA64) : 0;
        ULONG maxFuncThunks =
            desc->FirstThunk < imageSize ? (imageSize - desc->FirstThunk) / sizeof(IMAGE_THUNK_DATA64) : 0;
        ULONG maxThunks = maxNameThunks < maxFuncThunks ? maxNameThunks : maxFuncThunks;
        if (!maxThunks)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload thunk range invalid: %s\n"), moduleName);
            return FALSE;
        }
        if (maxThunks > 0x10000)
            maxThunks = 0x10000;

        BOOLEAN thunkTerminated = FALSE;
        for (ULONG thunkIndex = 0; thunkIndex < maxThunks; ++thunkIndex)
        {
            auto thunkName = (PIMAGE_THUNK_DATA64)(image + nameThunkRva) + thunkIndex;
            auto thunkFunc = (PIMAGE_THUNK_DATA64)(image + desc->FirstThunk) + thunkIndex;
            ULONGLONG addressOfData = thunkName->u1.AddressOfData;
            if (!addressOfData)
            {
                thunkTerminated = TRUE;
                break;
            }
            if (IMAGE_SNAP_BY_ORDINAL64(thunkName->u1.Ordinal) || addressOfData > MAXULONG)
            {
                LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload ordinal/large import rejected: %s index=%u\n"),
                          moduleName, thunkIndex);
                return FALSE;
            }

            ULONG importRva = (ULONG)addressOfData;
            if (!RangeInBuffer(importRva, FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name) + 1, imageSize))
                return FALSE;
            ULONG importNameRva = importRva + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name);
            const char *importName = RawAsciiInImage(image, imageSize, importNameRva, 256);
            if (!importName)
            {
                LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload import name invalid: %s index=%u\n"), moduleName,
                          thunkIndex);
                return FALSE;
            }

            ULONG_PTR function = (ULONG_PTR)ExportByName((char *)moduleBase, (char *)importName);
            if (!function || function < moduleBase || function >= moduleBase + moduleSize)
            {
                LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload export resolve failed: %s!%s\n"), moduleName,
                          importName);
                return FALSE;
            }

            thunkFunc->u1.Function = function;
            ++resolved;
        }

        if (!thunkTerminated)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload thunk table unterminated: %s\n"), moduleName);
            return FALSE;
        }
    }

    if (!descriptorTerminated)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload import descriptors unterminated\n"));
        return FALSE;
    }

    if (resolvedCount)
        *resolvedCount = resolved;
    return TRUE;
}

static void UpdateCookie(char *image)
{
    auto dos = (PIMAGE_DOS_HEADER)image;
    auto nt = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);
    auto dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!dir->VirtualAddress || !dir->Size)
        return;

    auto config = (PIMAGE_LOAD_CONFIG_DIRECTORY)(image + dir->VirtualAddress);
    if (config->SecurityCookie)
        *(PULONG_PTR)(config->SecurityCookie) += 10;
}

BOOLEAN LoadDriver(PUCHAR fileBuffer, PVOID context)
{
    PUCHAR mappedImage = FileToImage((char *)fileBuffer);
    if (!mappedImage)
        return FALSE;

    BOOLEAN ok = FALSE;
    do
    {
        if (!UpdateRelocation((char *)mappedImage))
            break;

        if (!UpdateIAT((char *)mappedImage))
            break;

        UpdateCookie((char *)mappedImage);

        auto dos = (PIMAGE_DOS_HEADER)mappedImage;
        auto nt = (PIMAGE_NT_HEADERS)(mappedImage + dos->e_lfanew);
        imageSize = nt->OptionalHeader.SizeOfImage;
        auto entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
        if (!entry_rva || entry_rva >= imageSize)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor bad entry rva=0x%X image=0x%X\n"), entry_rva, imageSize);
            break;
        }

        auto entry = (DriverEntryProc)(mappedImage + entry_rva);
        PrepareManualDriverObject(&testDriver, mappedImage, imageSize, (PVOID)entry);
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Calling VtHypervisor entry=%p base=%p size=0x%X ctx=%p\n"), entry,
                  mappedImage, imageSize, context);

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        __try
        {
            status = entry(&testDriver, (PUNICODE_STRING)context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor entry exception=0x%X entry=%p image=%p size=0x%X\n"),
                      status, entry, mappedImage, imageSize);
        }
        if (!NT_SUCCESS(status))
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor entry failed 0x%X entry=%p image=%p size=0x%X\n"), status,
                      entry, mappedImage, imageSize);
            break;
        }

        RtlZeroMemory(SectionSnaps, sizeof(SectionSnaps));
        SectionSnapCount = 0;
        auto section = IMAGE_FIRST_SECTION(nt);
        ULONG section_count = nt->FileHeader.NumberOfSections;
        if (section_count > kSectionSnapMax)
            section_count = kSectionSnapMax;

        for (ULONG i = 0; i < section_count; ++i)
        {
            RtlCopyMemory(SectionSnaps[i].name, section[i].Name, 8);
            SectionSnaps[i].name[8] = 0;
            SectionSnaps[i].va_offset = section[i].VirtualAddress;
            SectionSnaps[i].virtual_size = section[i].Misc.VirtualSize;
            SectionSnaps[i].characteristics = section[i].Characteristics;
        }
        SectionSnapCount = section_count;

#if VT_IMAGE_WIPE_ENABLED
        RtlSecureZeroMemory(mappedImage, PAGE_SIZE);
#endif
        ok = TRUE;
    } while (false);

    if (!ok)
    {
        Util::PoolManagerFreePool(mappedImage);
        imageSize = 0;
    }
    else
    {
        imageBase = mappedImage;
        testDriverUnloaded = FALSE;
        testDriverUnloadCallbackCalled = FALSE;
        testDriverImageQuarantined = FALSE;
    }

    return ok;
}

BOOLEAN LoadPayload(PUCHAR fileBuffer, PVOID context)
{
    PUCHAR mappedImage = FileToImage((char *)fileBuffer);
    if (!mappedImage)
        return FALSE;

    BOOLEAN ok = FALSE;
    ULONG localImageSize = 0;
    do
    {
        if (!UpdateRelocation((char *)mappedImage))
            break;

        if (!UpdateIAT((char *)mappedImage))
            break;

        UpdateCookie((char *)mappedImage);

        auto dos = (PIMAGE_DOS_HEADER)mappedImage;
        auto nt = (PIMAGE_NT_HEADERS)(mappedImage + dos->e_lfanew);
        localImageSize = nt->OptionalHeader.SizeOfImage;
        auto entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
        if (!entry_rva || entry_rva >= localImageSize)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload bad entry rva=0x%X image=0x%X\n"), entry_rva, localImageSize);
            break;
        }

        auto entry = (DriverEntryProc)(mappedImage + entry_rva);

        PreparePayloadHostApi();
        auto boot = (payload_boot_context *)context;
        if (boot && boot->magic == PAYLOAD_BOOT_MAGIC && boot->size >= sizeof(payload_boot_context))
        {
            boot->image_base = (payload_u64)mappedImage;
            boot->image_size = (payload_u64)localImageSize;
            boot->boot_flags = PAYLOAD_BOOT_FLAG_PE_IMAGE | PAYLOAD_BOOT_FLAG_HOST_API;
            boot->host_api = &g_payloadHostApi;
        }

        PrepareManualDriverObject(&payloadDriver, mappedImage, localImageSize, (PVOID)entry);

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        __try
        {
            status = entry(&payloadDriver, (PUNICODE_STRING)context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload entry exception=0x%X entry=%p image=%p size=0x%X\n"), status,
                      entry, mappedImage, localImageSize);
        }
        if (!NT_SUCCESS(status))
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload entry failed 0x%X entry=%p image=%p size=0x%X\n"), status,
                      entry, mappedImage, localImageSize);
            break;
        }

        ok = TRUE;
    } while (false);

    if (!ok)
    {
        Util::PoolManagerFreePool(mappedImage);
        return FALSE;
    }

    payloadBase = mappedImage;
    payloadSize = localImageSize;
    return TRUE;
}

BOOLEAN LoadRawPayload(PUCHAR packetBuffer, ULONG packetSize, PVOID context)
{
    if (!packetBuffer || packetSize < sizeof(PayloadRawHeader))
        return FALSE;

    auto header = (PayloadRawHeader *)packetBuffer;
    if (header->magic != kPayloadRawMagic || header->version != kPayloadRawVersion ||
        header->header_size != sizeof(PayloadRawHeader) || !header->image_size || !header->entry_rva ||
        !header->section_count || header->section_count > 96 ||
        header->reloc_count > header->image_size / sizeof(ULONGLONG))
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload bad header magic=0x%llX ver=%u size=0x%X entry=0x%X\n"),
                  header->magic, header->version, header->image_size, header->entry_rva);
        return FALSE;
    }

    if (header->section_count > packetSize / sizeof(PayloadRawSection) ||
        header->reloc_count > packetSize / sizeof(ULONG) ||
        !RangeInBuffer(header->section_table_offset, header->section_count * (ULONG)sizeof(PayloadRawSection),
                       packetSize) ||
        !RangeInBuffer(header->reloc_table_offset, header->reloc_count * (ULONG)sizeof(ULONG), packetSize) ||
        !RangeInBuffer(header->data_offset, header->data_size, packetSize) ||
        !RangeInBuffer(header->entry_rva, 1, header->image_size))
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload ranges invalid packet=0x%X image=0x%X\n"), packetSize,
                  header->image_size);
        return FALSE;
    }

    PUCHAR mappedImage = (PUCHAR)Util::PoolManagertAllocation(header->image_size);
    if (!mappedImage)
        return FALSE;

    BOOLEAN ok = FALSE;
    do
    {
        RtlZeroMemory(mappedImage, header->image_size);

        auto sections = (PayloadRawSection *)(packetBuffer + header->section_table_offset);
        for (ULONG i = 0; i < header->section_count; i++)
        {
            const auto &sec = sections[i];
            ULONG mem_size = sec.virtual_size ? sec.virtual_size : sec.raw_size;
            if (mem_size && !RangeInBuffer(sec.rva, mem_size, header->image_size))
                break;
            if (sec.raw_size)
            {
                if (!RangeInBuffer(sec.data_offset, sec.raw_size, packetSize) ||
                    !RangeInBuffer(sec.rva, sec.raw_size, header->image_size) ||
                    sec.data_offset < header->data_offset ||
                    !RangeInBuffer(sec.data_offset - header->data_offset, sec.raw_size, header->data_size))
                {
                    break;
                }

                RtlCopyMemory(mappedImage + sec.rva, packetBuffer + sec.data_offset, sec.raw_size);
            }

            if (i + 1 == header->section_count)
                ok = TRUE;
        }
        if (!ok)
            break;

        LONG64 delta = (LONG64)((ULONG_PTR)mappedImage - (ULONG_PTR)header->preferred_base);
        auto relocs = (ULONG *)(packetBuffer + header->reloc_table_offset);
        for (ULONG i = 0; i < header->reloc_count; i++)
        {
            ULONG rva = relocs[i];
            if (!RangeInBuffer(rva, sizeof(ULONGLONG), header->image_size))
            {
                ok = FALSE;
                break;
            }

            auto target = (ULONGLONG *)(mappedImage + rva);
            *target = (ULONGLONG)((LONG64)(*target) + delta);
        }
        if (!ok)
            break;

        ULONG resolvedImports = 0;
        if (!UpdateRawIAT((char *)mappedImage, header->image_size, &resolvedImports))
        {
            ok = FALSE;
            break;
        }

        LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload imports resolved=%u\n"), resolvedImports);

        auto entry = (DriverEntryProc)(mappedImage + header->entry_rva);
        PreparePayloadHostApi();
        auto boot = (payload_boot_context *)context;
        if (boot && boot->magic == PAYLOAD_BOOT_MAGIC && boot->size >= sizeof(payload_boot_context))
        {
            boot->image_base = (payload_u64)mappedImage;
            boot->image_size = (payload_u64)header->image_size;
            boot->boot_flags = PAYLOAD_BOOT_FLAG_RAWPACK | PAYLOAD_BOOT_FLAG_HOST_API;
            boot->host_api = &g_payloadHostApi;
        }

        PrepareManualDriverObject(&payloadDriver, mappedImage, header->image_size, (PVOID)entry);
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Calling raw payload entry=%p base=%p size=0x%X kernel_flags=0x%llX\n"),
                  entry, mappedImage, header->image_size, g_payloadHostApi.kernel_flags);

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        __try
        {
            status = entry(&payloadDriver, (PUNICODE_STRING)context);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload entry exception=0x%X entry=%p image=%p size=0x%X\n"),
                      status, entry, mappedImage, header->image_size);
        }
        if (!NT_SUCCESS(status))
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload entry failed 0x%X\n"), status);
            ok = FALSE;
            break;
        }

        payloadBase = mappedImage;
        payloadSize = header->image_size;
        ok = TRUE;
    } while (false);

    if (!ok)
    {
        Util::PoolManagerFreePool(mappedImage);
        return FALSE;
    }

    LOG_DEBUG(_XOR_("[VtBootstrapDriver] raw payload mapped base=%p size=0x%X sections=%u relocs=%u\n"), payloadBase,
              payloadSize, header->section_count, header->reloc_count);
    return TRUE;
}

static bool PayloadPointerInImage(const void *ptr)
{
    auto base = (ULONG_PTR)payloadBase;
    auto size = (ULONG_PTR)payloadSize;
    auto value = (ULONG_PTR)ptr;

    if (!base || !size || !value)
        return false;

    auto end = base + size;
    if (end <= base)
        return false;

    return value >= base && value < end;
}

VOID FreePayloadArena()
{
    if (!payloadArenaBase || !payloadArenaSize)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload arena disposition skipped base=%p size=0x%X\n"), payloadArenaBase,
                  payloadArenaSize);
        return;
    }

#if VT_MEM_FREE_ARENA_ON_UNLOAD
    if (!MmFreeIndependentPages || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload arena free blocked base=%p size=0x%X free=%p irql=%u\n"),
                  payloadArenaBase, payloadArenaSize, MmFreeIndependentPages, (ULONG)KeGetCurrentIrql());
        return;
    }

    PVOID const arena_base = payloadArenaBase;
    ULONG const arena_size = payloadArenaSize;
    RtlSecureZeroMemory(arena_base, arena_size);
    MmFreeIndependentPages(arena_base, arena_size);
    payloadArenaBase = nullptr;
    payloadArenaSize = 0;
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload arena freed after payload/HV quiesce base=%p size=0x%X\n"), arena_base,
              arena_size);
#else
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload arena quarantined after payload/HV quiesce base=%p size=0x%X\n"),
              payloadArenaBase, payloadArenaSize);
#endif
}

VOID UnloadPayload()
{
    if (!payloadBase)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload unload skipped: base=null\n"));
        return;
    }

    auto unload = payloadDriver.DriverUnload;
    auto stop = payloadExports ? payloadExports->stop : nullptr;
    bool unload_valid = PayloadPointerInImage((const void *)unload);
    bool stop_valid = PayloadPointerInImage((const void *)stop);
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload unload begin base=%p size=0x%X unload=%p valid=%d stop=%p valid=%d\n"),
              payloadBase, payloadSize, unload, (int)unload_valid, stop, (int)stop_valid);
    if (unload && unload_valid)
    {
        __try
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] calling payload DriverUnload\n"));
            unload(&payloadDriver);
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload DriverUnload returned\n"));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload DriverUnload exception=0x%X\n"), GetExceptionCode());
        }
    }
    else if (stop && stop_valid)
    {
        __try
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload DriverUnload invalid, calling payload stop export\n"));
            auto result = stop();
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload stop export returned 0x%llX\n"), result);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload stop export exception=0x%X\n"), GetExceptionCode());
        }
    }
    else if (unload)
    {
        LOG_DEBUG(
            _XOR_("[VtBootstrapDriver] payload DriverUnload skipped invalid unload=%p base=%p size=0x%X stop=%p\n"),
            unload, payloadBase, payloadSize, stop);
    }
    else
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload DriverUnload is null stop=%p valid=%d\n"), stop, (int)stop_valid);
    }

    // Payload CRT/WDF globals may still be linked into nt!ExNpagedLookasideListHead
    // after DriverUnload returns.  Do not wipe/free the image here: a zeroed
    // ListHead leaves a NULL Flink in the kernel's asynchronous scanner and
    // reproduces BugCheck 0xA at nt!ExpScanGeneralLookasideList+0x40.
    PVOID const quarantined_base = payloadBase;
    ULONG const quarantined_size = payloadSize;
    if (quarantined_base && quarantined_size &&
        !Util::PoolManagerDetachPool(quarantined_base))
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload image quarantine failed; active record retained base=%p size=0x%X\n"),
                  quarantined_base, quarantined_size);
        return;
    }
    if (quarantined_base && quarantined_size)
    {
        LONG const quarantine_count = InterlockedIncrement(&g_quarantined_payload_count);
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload image quarantined (not zeroed/freed) base=%p size=0x%X count=%ld\n"),
                  quarantined_base, quarantined_size, quarantine_count);
    }
    payloadBase = nullptr;
    payloadSize = 0;
    payloadExports = nullptr;
    RtlZeroMemory(&payloadDriver, sizeof(payloadDriver));
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload image quarantine complete; image remains resident\n"));

    // The external arena also backs TestDriver/HV 状态.  PayloadStop only
    // proves that payload-owned workers and direct allocations are gone;
    // freeing here races the still-running vCPUs.  Keep the identity until
    // the caller has stopped the hypervisor and then call FreePayloadArena.
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] payload arena disposition deferred until HV stop base=%p size=0x%X\n"),
              payloadArenaBase, payloadArenaSize);
}

VOID UnloadDriver()
{
    UnloadDriverEx(TRUE);
}

VOID UnloadDriverEx(BOOLEAN freeImage)
{
    if (!imageBase)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor unload skipped: base=null\n"));
        return;
    }

    auto unload = testDriver.DriverUnload;
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor unload begin base=%p size=0x%X DriverObject=%p unload=%p\n"),
              imageBase, imageSize, &testDriver, unload);
    if (!testDriverUnloadCallbackCalled && unload)
    {
        __try
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] calling VtHypervisor.DriverUnload\n"));
            unload(&testDriver);
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor.DriverUnload returned\n"));
            testDriverUnloaded = TRUE;
            testDriverUnloadCallbackCalled = TRUE;
            testDriver.DriverUnload = nullptr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor.DriverUnload exception=0x%X\n"), GetExceptionCode());
        }
    }
    else if (!unload)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor DriverUnload is null\n"));
    }
    else
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor DriverUnload already called\n"));
        testDriverUnloaded = TRUE;
        testDriver.DriverUnload = nullptr;
    }

    if (!freeImage)
    {
        testDriverImageQuarantined = TRUE;
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor image quarantined base=%p size=0x%X\n"), imageBase,
                  imageSize);
        return;
    }

    // 不再清零/释放手动映像。UCXXRT/CRT 的 lookaside/PTD 条目可能仍挂在
    // nt!ExNpagedLookasideListHead 上，内核 KeBalanceSetManager 会异步遍历
    // 这些条目；清零后 Flink 变成 NULL，随后触发 0xA。
    // 摘除 PoolManager 跟踪记录，防止后续 PoolManagerUninitialize 误释放；
    // 页面保留到重启，作为延迟回收 quarantine。
    PVOID const quarantined_base = imageBase;
    ULONG const quarantined_size = imageSize;
    if (quarantined_base && quarantined_size &&
        !Util::PoolManagerDetachPool(quarantined_base))
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor image quarantine failed; keeping active record base=%p size=0x%X\n"),
                  quarantined_base, quarantined_size);
        testDriverImageQuarantined = TRUE;
        return;
    }

    if (quarantined_base && quarantined_size)
    {
        LONG const quarantine_count = InterlockedIncrement(&g_quarantined_image_count);
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor image quarantined (not zeroed/freed) base=%p size=0x%X count=%ld\n"),
                  quarantined_base, quarantined_size, quarantine_count);
    }
    imageBase = nullptr;
    imageSize = 0;
    testDriverUnloaded = TRUE;
    testDriverUnloadCallbackCalled = TRUE;
    testDriverImageQuarantined = TRUE;
    RtlZeroMemory(&testDriver, sizeof(testDriver));
    RtlZeroMemory(SectionSnaps, sizeof(SectionSnaps));
    SectionSnapCount = 0;
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] VtHypervisor image quarantine complete; image remains resident\n"));
}

BOOLEAN VerifyAllCpusHvReady(ULONGLONG* expected_mask_out, ULONGLONG* pong_mask_out)
{
    if (expected_mask_out)
        *expected_mask_out = 0;
    if (pong_mask_out)
        *pong_mask_out = 0;

    if (KeGetCurrentIrql() > APC_LEVEL)
        return FALSE;

    ULONGLONG expected_mask = 0;
    ULONGLONG pong_mask = 0;
    ULONG total_cpus = 0;
    ULONG ready_cpus = 0;
    USHORT const group_count = KeQueryActiveGroupCount();

    for (USHORT group = 0; group < group_count; ++group)
    {
        ULONG const processors = KeQueryActiveProcessorCountEx(group);
        for (ULONG cpu = 0; cpu < processors && cpu < 64; ++cpu)
        {
            ULONGLONG const bit = (group == 0) ? (1ull << cpu) : 0ull;
            expected_mask |= bit;
            total_cpus++;

            GROUP_AFFINITY ga = {};
            ga.Group = group;
            ga.Mask = 1ull << cpu;

            GROUP_AFFINITY old_ga = {};
            KeSetSystemGroupAffinityThread(&ga, &old_ga);
            bool const ok = hv::try_ping();
            KeRevertToUserGroupAffinityThread(&old_ga);

            if (ok)
            {
                pong_mask |= bit;
                ready_cpus++;
            }
        }
    }

    if (expected_mask_out)
        *expected_mask_out = expected_mask;
    if (pong_mask_out)
        *pong_mask_out = pong_mask;

    return (total_cpus != 0 && ready_cpus == total_cpus) ? TRUE : FALSE;
}

BOOLEAN LoadMachenike(PUCHAR fileBuffer, PDRIVER_OBJECT hostDriverObj, PUNICODE_STRING registryPath,
                      BOOLEAN isManualMap)
{
    if (machenikeLoaded && machenikeBase)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike already loaded base=%p size=0x%X mode=%u\n"), machenikeBase,
                  machenikeSize, machenikeMode);
        return TRUE;
    }
    if (!fileBuffer || !hostDriverObj)
        return FALSE;

    auto dosSrc = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosSrc->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;
    auto ntSrc = (PIMAGE_NT_HEADERS)(fileBuffer + dosSrc->e_lfanew);
    if (ntSrc->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    ULONG localImageSize = ntSrc->OptionalHeader.SizeOfImage;
    if (!localImageSize)
        return FALSE;

    PUCHAR mappedImage = nullptr;
    BOOLEAN usedIndep = FALSE;
#if !VT_MEM_FORCE_EXALLOCPOOL
    if (MmAllocateIndependentPages && MmFreeIndependentPages && MmSetPageProtection)
    {
        mappedImage = (PUCHAR)MmAllocateIndependentPages(localImageSize, MAXULONG64);
        if (mappedImage)
        {
            if (MmSetPageProtection(mappedImage, localImageSize, PAGE_EXECUTE_READWRITE))
            {
                usedIndep = TRUE;
            }
            else
            {
                MmFreeIndependentPages(mappedImage, localImageSize);
                mappedImage = nullptr;
            }
        }
    }
#endif
    if (!mappedImage)
    {
        mappedImage = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, localImageSize, MEM_TAG);
        usedIndep = FALSE;
    }
    if (!mappedImage)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] LoadMachenike allocation failed size=0x%X\n"), localImageSize);
        return FALSE;
    }
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] LoadMachenike allocated base=%p size=0x%X indep=%d isManualMap=%d\n"),
              mappedImage, localImageSize, (int)usedIndep, (int)isManualMap);

    RtlZeroMemory(mappedImage, localImageSize);
    RtlCopyMemory(mappedImage, fileBuffer, ntSrc->OptionalHeader.SizeOfHeaders);

    auto secSrc = IMAGE_FIRST_SECTION(ntSrc);
    for (ULONG i = 0; i < ntSrc->FileHeader.NumberOfSections; ++i)
    {
        if (secSrc[i].SizeOfRawData)
        {
            RtlCopyMemory(mappedImage + secSrc[i].VirtualAddress, fileBuffer + secSrc[i].PointerToRawData,
                          secSrc[i].SizeOfRawData);
        }
    }

    BOOLEAN ok = FALSE;
    PDEVICE_OBJECT savedDevObj = hostDriverObj->DeviceObject;
    PDRIVER_UNLOAD savedUnload = hostDriverObj->DriverUnload;
    PDRIVER_DISPATCH savedCreate = hostDriverObj->MajorFunction[IRP_MJ_CREATE];
    PDRIVER_DISPATCH savedClose = hostDriverObj->MajorFunction[IRP_MJ_CLOSE];
    PDRIVER_DISPATCH savedDevCtl = hostDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];

    do
    {
        if (!UpdateRelocation((char *)mappedImage))
            break;

        if (!UpdateIAT((char *)mappedImage))
            break;

        UpdateCookie((char *)mappedImage);

        auto dos = (PIMAGE_DOS_HEADER)mappedImage;
        auto nt = (PIMAGE_NT_HEADERS)(mappedImage + dos->e_lfanew);
        auto entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
        if (!entry_rva || entry_rva >= localImageSize)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike bad entry rva=0x%X image=0x%X\n"), entry_rva,
                      localImageSize);
            break;
        }

        if (isManualMap)
        {
            // 内存映射模式：通过 DeviceObject 暂存实际映射基址供 Machenike 读取，调用后立即恢复
            hostDriverObj->DeviceObject = (PDEVICE_OBJECT)mappedImage;
        }

        auto entry = (DriverEntryProc)(mappedImage + entry_rva);
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Calling Machenike entry=%p base=%p size=0x%X hostDrv=%p regOrCfg=%p "
                        "isManualMap=%d\n"),
                  entry, mappedImage, localImageSize, hostDriverObj, registryPath, (int)isManualMap);
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        __try
        {
            status = entry(hostDriverObj, registryPath);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike entry exception=0x%X entry=%p image=%p size=0x%X\n"), status,
                      entry, mappedImage, localImageSize);
        }

        if (isManualMap)
        {
            hostDriverObj->DeviceObject = savedDevObj;
        }

        if (!NT_SUCCESS(status))
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike entry failed 0x%X\n"), status);
            hostDriverObj->DriverUnload = savedUnload;
            hostDriverObj->MajorFunction[IRP_MJ_CREATE] = savedCreate;
            hostDriverObj->MajorFunction[IRP_MJ_CLOSE] = savedClose;
            hostDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = savedDevCtl;
            break;
        }

        machenikeUnload = (hostDriverObj->DriverUnload != savedUnload) ? hostDriverObj->DriverUnload : nullptr;
        if (!isManualMap)
        {
            machenikeCreateDispatch = (hostDriverObj->MajorFunction[IRP_MJ_CREATE] != savedCreate)
                                          ? hostDriverObj->MajorFunction[IRP_MJ_CREATE]
                                          : nullptr;
            machenikeCloseDispatch = (hostDriverObj->MajorFunction[IRP_MJ_CLOSE] != savedClose)
                                         ? hostDriverObj->MajorFunction[IRP_MJ_CLOSE]
                                         : nullptr;
            machenikeDeviceControlDispatch = (hostDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] != savedDevCtl)
                                                 ? hostDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]
                                                 : nullptr;
        }
        else
        {
            machenikeCreateDispatch = nullptr;
            machenikeCloseDispatch = nullptr;
            machenikeDeviceControlDispatch = nullptr;
        }

        hostDriverObj->DriverUnload = savedUnload;
        hostDriverObj->MajorFunction[IRP_MJ_CREATE] = savedCreate;
        hostDriverObj->MajorFunction[IRP_MJ_CLOSE] = savedClose;
        hostDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = savedDevCtl;

        // 手动映射模式仅设置各节页权限；PE 头和节内容保留至双视图页集合登记完成。
        if (isManualMap)
        {
            auto section = IMAGE_FIRST_SECTION(nt);
            ULONG secCount = nt->FileHeader.NumberOfSections;
            for (ULONG i = 0; i < secCount; ++i)
            {
                ULONG secRva = section[i].VirtualAddress;
                ULONG secSize = section[i].Misc.VirtualSize ? section[i].Misc.VirtualSize : section[i].SizeOfRawData;
                if (!secRva || !secSize || secRva >= localImageSize)
                    continue;

                ULONG alignedSize = (secSize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
                if (secRva + alignedSize > localImageSize)
                    alignedSize = localImageSize - secRva;

                bool isDiscardable =
                    (memcmp(section[i].Name, "INIT", 4) == 0) || (memcmp(section[i].Name, ".reloc", 6) == 0);
                if (isDiscardable)
                {
                    if (usedIndep && MmSetPageProtection && ((secRva & (PAGE_SIZE - 1)) == 0) &&
                        alignedSize >= PAGE_SIZE)
                        MmSetPageProtection(mappedImage + secRva, alignedSize & ~(PAGE_SIZE - 1), PAGE_READONLY);
                    continue;
                }

                if (usedIndep && MmSetPageProtection && ((secRva & (PAGE_SIZE - 1)) == 0) && alignedSize >= PAGE_SIZE)
                {
                    ULONG chars = section[i].Characteristics;
                    ULONG prot = PAGE_READONLY;
                    if ((chars & IMAGE_SCN_MEM_EXECUTE) && (chars & IMAGE_SCN_MEM_WRITE))
                        prot = PAGE_EXECUTE_READWRITE;
                    else if (chars & IMAGE_SCN_MEM_EXECUTE)
                        prot = PAGE_EXECUTE_READ;
                    else if (chars & IMAGE_SCN_MEM_WRITE)
                        prot = PAGE_READWRITE;
                    MmSetPageProtection(mappedImage + secRva, alignedSize & ~(PAGE_SIZE - 1), prot);
                }
            }

        }
        ok = TRUE;
    } while (false);

    if (!ok)
    {
        RtlSecureZeroMemory(mappedImage, localImageSize);
        if (usedIndep && MmFreeIndependentPages)
            MmFreeIndependentPages(mappedImage, localImageSize);
        else
            ExFreePoolWithTag(mappedImage, MEM_TAG);
        return FALSE;
    }

    ULONG const localMode = isManualMap ? 2 : 1;
    ULONGLONG expected_cpus = 0;
    ULONGLONG pong_cpus = 0;
    bool const status_published =
        VerifyAllCpusHvReady(&expected_cpus, &pong_cpus) &&
        hv::try_vmcall_set_machenike_status(
            (uint64_t)mappedImage,
            (uint64_t)localImageSize,
            (uint64_t)localMode | ((uint64_t)(usedIndep ? 1 : 0) << 32) | (1ull << 40),
            (uint64_t)machenikeUnload);
    
    if (!status_published)
    {
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike status publish failed expected=0x%llX pong=0x%llX; rolling back\n"),
                  expected_cpus, pong_cpus);
        auto rollback_unload = machenikeUnload;
        machenikeCreateDispatch = nullptr;
        machenikeCloseDispatch = nullptr;
        machenikeDeviceControlDispatch = nullptr;
        machenikeUnload = nullptr;
        machenikeBase = nullptr;
        machenikeSize = 0;
        machenikeMode = 0;
        machenikeUsedIndependent = FALSE;
        machenikeLoaded = FALSE;
        if (rollback_unload)
        {
            __try
            {
                rollback_unload(hostDriverObj);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike rollback DriverUnload exception=0x%X\n"), GetExceptionCode());
            }
        }
        if (usedIndep && MmSetPageProtection)
            MmSetPageProtection(mappedImage, localImageSize, PAGE_READWRITE);
        RtlSecureZeroMemory(mappedImage, localImageSize);
        if (usedIndep && MmFreeIndependentPages)
            MmFreeIndependentPages(mappedImage, localImageSize);
        else
            ExFreePoolWithTag(mappedImage, MEM_TAG);
        return FALSE;
    }

    machenikeBase = mappedImage;
    machenikeSize = localImageSize;
    machenikeUsedIndependent = usedIndep;
    machenikeLoaded = TRUE;
    machenikeMode = localMode;





    LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike loaded base=%p size=0x%X mode=%u indep=%d unload=%p\n"),
              machenikeBase, machenikeSize, machenikeMode, (int)usedIndep, machenikeUnload);
    return TRUE;
}

VOID UnloadMachenike(PDRIVER_OBJECT hostDriverObj)
{
    if (!machenikeLoaded || !machenikeBase)
        return;

    LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike unload begin base=%p size=0x%X mode=%u unload=%p\n"), machenikeBase,
              machenikeSize, machenikeMode, machenikeUnload);

    machenikeCreateDispatch = nullptr;
    machenikeCloseDispatch = nullptr;
    machenikeDeviceControlDispatch = nullptr;

    // 先移除 .text 双视图，再进入 DriverUnload，避免卸载期间仍有活动 EH 条目。
    RemoveMachenikeTextDualView();

    auto unload = machenikeUnload;
    machenikeUnload = nullptr;
    if (unload)
    {
        __try
        {
            unload(hostDriverObj);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike DriverUnload exception=0x%X\n"), GetExceptionCode());
        }
    }

    PVOID base = machenikeBase;
    ULONG size = machenikeSize;
    BOOLEAN usedIndep = machenikeUsedIndependent;
    machenikeBase = nullptr;
    machenikeSize = 0;
    machenikeMode = 0;
    machenikeUsedIndependent = FALSE;
    machenikeLoaded = FALSE;

    if (base && size)
    {
        // Machenike can leave CRT/WDF lookaside nodes registered after its
        // unload callback.  Keep the complete image resident instead of
        // clearing/freeing it while nt!ExpScanGeneralLookasideList can still
        // reach those nodes through the global list.
        LONG const quarantine_count = InterlockedIncrement(&g_quarantined_machenike_count);
        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike image quarantined (not zeroed/freed) base=%p size=0x%X indep=%d count=%ld\n"),
                  base, size, (int)usedIndep, quarantine_count);
    }
    if (VerifyAllCpusHvReady())
        hv::try_vmcall_set_machenike_status(0, 0, 0, 0);
    LOG_DEBUG(_XOR_("[VtBootstrapDriver] Machenike image quarantine complete; image remains resident\n"));
}
} // namespace Utils
