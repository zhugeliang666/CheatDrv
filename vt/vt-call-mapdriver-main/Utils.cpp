#pragma warning(disable : 4201 4311 4302)

#include "Utils.h"
#include <ntimage.h>
#include "base.h"
#include "common/ntutils.h"
#include "poolmanager/PoolManager.h"

namespace Utils
{
    typedef NTSTATUS(NTAPI* DriverEntryProc)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

    _DRIVER_OBJECT testDriver;
    PVOID imageBase = nullptr;
    ULONG imageSize = 0;
    BOOLEAN testDriverUnloaded = FALSE;
    BOOLEAN testDriverUnloadCallbackCalled = FALSE;
    BOOLEAN testDriverImageQuarantined = FALSE;
    _DRIVER_OBJECT payloadDriver;
    payload_exports* payloadExports = nullptr;
    PVOID payloadBase = nullptr;
    ULONG payloadSize = 0;
    PVOID payloadArenaBase = nullptr;
    ULONG payloadArenaSize = 0;

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

    static void* PayloadHostAlloc(payload_u64 size, payload_u64 tag)
    {
        UNREFERENCED_PARAMETER(tag);
        if (!size || size > 0x7FFFFFFFull)
            return nullptr;
        return Util::PoolManagertAllocation((ULONG)size);
    }

    static void PayloadHostFree(void* ptr)
    {
        if (ptr)
            Util::PoolManagerFreePool(ptr);
    }

    static void* PayloadHostResolve(const unsigned short* routine_name)
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
#if MAPDRIVER_FORCE_EXALLOCPOOL
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
    static constexpr ULONG kPayloadRawVersion = 1;

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

    static PUCHAR FileToImage(char* fileBuffer)
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
            return nullptr;

        RtlZeroMemory(image, imageSize);
        RtlCopyMemory(image, fileBuffer, nt->OptionalHeader.SizeOfHeaders);

        auto section = IMAGE_FIRST_SECTION(nt);
        for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (section[i].SizeOfRawData)
            {
                RtlCopyMemory(
                    image + section[i].VirtualAddress,
                    fileBuffer + section[i].PointerToRawData,
                    section[i].SizeOfRawData);
            }
        }

        return image;
    }

    static void CopyLowerAscii(char* dst, SIZE_T dstSize, const char* src, SIZE_T srcMax)
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

    static BOOLEAN UpdateRelocation(char* image)
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

    ULONG_PTR QueryModule(PUCHAR moduleName, ULONG_PTR* moduleSize)
    {
        if (!moduleName)
            return 0;

        NT::RTL_PROCESS_MODULES localModules = { 0 };
        NT::PRTL_PROCESS_MODULES modules = &localModules;
        BOOLEAN allocated = FALSE;
        ULONG bytes = 0;

        NTSTATUS status = NT::ZwQuerySystemInformation(
            NT::SystemModuleInformation,
            modules,
            sizeof(localModules),
            &bytes);

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
        if (_stricmp((char*)moduleName, _XOR_("ntoskrnl.exe")) == 0 ||
            _stricmp((char*)moduleName, _XOR_("ntkrnlpa.exe")) == 0)
        {
            moduleBase = (ULONG_PTR)modules->Modules[0].ImageBase;
            if (moduleSize)
                *moduleSize = modules->Modules[0].ImageSize;
        }
        else
        {
            char wanted[260] = {};
            CopyLowerAscii(wanted, sizeof(wanted), (char*)moduleName, 259);

            ULONG moduleCount = modules->NumberOfModules;
            ULONG maxCount = 1;
            if (allocated && bytes > FIELD_OFFSET(NT::RTL_PROCESS_MODULES, Modules))
                maxCount = (bytes - FIELD_OFFSET(NT::RTL_PROCESS_MODULES, Modules)) / sizeof(NT::RTL_PROCESS_MODULE_INFORMATION);
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

    static ULONG64 ExportByName(char* moduleBase, char* functionName)
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
            char* name = moduleBase + names[i];
            if (strcmp(name, functionName) == 0)
                return (ULONG64)moduleBase + functions[ordinals[i]];
        }

        return 0;
    }

    static BOOLEAN UpdateIAT(char* image)
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
                LOG_DEBUG(_XOR_("[mapDriver] IAT module resolve failed: %s\n"), libName);
                return FALSE;
            }

            auto thunkName = (PIMAGE_THUNK_DATA)(image + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            auto thunkFunc = (PIMAGE_THUNK_DATA)(image + desc->FirstThunk);
            for (; thunkName->u1.AddressOfData; ++thunkName, ++thunkFunc)
            {
                if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal))
                {
                    LOG_DEBUG(_XOR_("[mapDriver] IAT ordinal import unsupported: %s ordinal=0x%llX\n"),
                        libName,
                        (ULONGLONG)IMAGE_ORDINAL(thunkName->u1.Ordinal));
                    return FALSE;
                }

                auto importName = (PIMAGE_IMPORT_BY_NAME)(image + thunkName->u1.AddressOfData);
                ULONG_PTR func = ExportByName((char*)base, importName->Name);
                if (!func)
                {
                    LOG_DEBUG(_XOR_("[mapDriver] IAT export resolve failed: %s!%s\n"),
                        libName,
                        importName->Name);
                    return FALSE;
                }

                thunkFunc->u1.Function = func;
            }
        }

        return TRUE;
    }

    static void UpdateCookie(char* image)
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
        PUCHAR mappedImage = FileToImage((char*)fileBuffer);
        if (!mappedImage)
            return FALSE;

        BOOLEAN ok = FALSE;
        do
        {
            if (!UpdateRelocation((char*)mappedImage))
                break;

            if (!UpdateIAT((char*)mappedImage))
                break;

            UpdateCookie((char*)mappedImage);

            auto dos = (PIMAGE_DOS_HEADER)mappedImage;
            auto nt = (PIMAGE_NT_HEADERS)(mappedImage + dos->e_lfanew);
            imageSize = nt->OptionalHeader.SizeOfImage;
            auto entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
            if (!entry_rva || entry_rva >= imageSize)
            {
                LOG_DEBUG(_XOR_("[mapDriver] TestDriver bad entry rva=0x%X image=0x%X\n"),
                    entry_rva, imageSize);
                break;
            }

            auto entry = (DriverEntryProc)(mappedImage + entry_rva);
            PrepareManualDriverObject(&testDriver, mappedImage, imageSize, (PVOID)entry);

            NTSTATUS status = STATUS_UNSUCCESSFUL;
            __try
            {
                status = entry(&testDriver, (PUNICODE_STRING)context);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
                LOG_DEBUG(_XOR_("[mapDriver] TestDriver entry exception=0x%X entry=%p image=%p size=0x%X\n"),
                    status, entry, mappedImage, imageSize);
            }
            if (!NT_SUCCESS(status))
            {
                LOG_DEBUG(_XOR_("[mapDriver] TestDriver entry failed 0x%X entry=%p image=%p size=0x%X\n"),
                    status, entry, mappedImage, imageSize);
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

#if MAPDRIVER_IMAGE_WIPE_ENABLED
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
        PUCHAR mappedImage = FileToImage((char*)fileBuffer);
        if (!mappedImage)
            return FALSE;

        BOOLEAN ok = FALSE;
        ULONG localImageSize = 0;
        do
        {
            if (!UpdateRelocation((char*)mappedImage))
                break;

            if (!UpdateIAT((char*)mappedImage))
                break;

            UpdateCookie((char*)mappedImage);

            auto dos = (PIMAGE_DOS_HEADER)mappedImage;
            auto nt = (PIMAGE_NT_HEADERS)(mappedImage + dos->e_lfanew);
            localImageSize = nt->OptionalHeader.SizeOfImage;
            auto entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
            if (!entry_rva || entry_rva >= localImageSize)
            {
                LOG_DEBUG(_XOR_("[mapDriver] payload bad entry rva=0x%X image=0x%X\n"),
                    entry_rva, localImageSize);
                break;
            }

            auto entry = (DriverEntryProc)(mappedImage + entry_rva);

            PreparePayloadHostApi();
            auto boot = (payload_boot_context*)context;
            if (boot &&
                boot->magic == PAYLOAD_BOOT_MAGIC &&
                boot->size >= sizeof(payload_boot_context))
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
                LOG_DEBUG(_XOR_("[mapDriver] payload entry exception=0x%X entry=%p image=%p size=0x%X\n"),
                    status, entry, mappedImage, localImageSize);
            }
            if (!NT_SUCCESS(status))
            {
                LOG_DEBUG(_XOR_("[mapDriver] payload entry failed 0x%X entry=%p image=%p size=0x%X\n"),
                    status, entry, mappedImage, localImageSize);
                break;
            }

#if MAPDRIVER_IMAGE_WIPE_ENABLED
            RtlSecureZeroMemory(mappedImage, PAGE_SIZE);
#endif
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

        auto header = (PayloadRawHeader*)packetBuffer;
        if (header->magic != kPayloadRawMagic ||
            header->version != kPayloadRawVersion ||
            header->header_size < sizeof(PayloadRawHeader) ||
            !header->image_size ||
            !header->entry_rva)
        {
            LOG_DEBUG(_XOR_("[mapDriver] raw payload bad header magic=0x%llX ver=%u size=0x%X entry=0x%X\n"),
                header->magic, header->version, header->image_size, header->entry_rva);
            return FALSE;
        }

        if (!RangeInBuffer(header->section_table_offset,
                header->section_count * (ULONG)sizeof(PayloadRawSection),
                packetSize) ||
            !RangeInBuffer(header->reloc_table_offset,
                header->reloc_count * (ULONG)sizeof(ULONG),
                packetSize) ||
            !RangeInBuffer(header->data_offset, header->data_size, packetSize) ||
            !RangeInBuffer(header->entry_rva, 1, header->image_size))
        {
            LOG_DEBUG(_XOR_("[mapDriver] raw payload ranges invalid packet=0x%X image=0x%X\n"),
                packetSize, header->image_size);
            return FALSE;
        }

        PUCHAR mappedImage = (PUCHAR)Util::PoolManagertAllocation(header->image_size);
        if (!mappedImage)
            return FALSE;

        BOOLEAN ok = FALSE;
        do
        {
            RtlZeroMemory(mappedImage, header->image_size);

            auto sections = (PayloadRawSection*)(packetBuffer + header->section_table_offset);
            for (ULONG i = 0; i < header->section_count; i++)
            {
                const auto& sec = sections[i];
                ULONG mem_size = sec.virtual_size ? sec.virtual_size : sec.raw_size;
                if (mem_size && !RangeInBuffer(sec.rva, mem_size, header->image_size))
                    break;
                if (sec.raw_size)
                {
                    if (!RangeInBuffer(sec.data_offset, sec.raw_size, packetSize) ||
                        !RangeInBuffer(sec.rva, sec.raw_size, header->image_size))
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
            auto relocs = (ULONG*)(packetBuffer + header->reloc_table_offset);
            for (ULONG i = 0; i < header->reloc_count; i++)
            {
                ULONG rva = relocs[i];
                if (!RangeInBuffer(rva, sizeof(ULONGLONG), header->image_size))
                {
                    ok = FALSE;
                    break;
                }

                auto target = (ULONGLONG*)(mappedImage + rva);
                *target = (ULONGLONG)((LONG64)(*target) + delta);
            }
            if (!ok)
                break;

            auto entry = (DriverEntryProc)(mappedImage + header->entry_rva);
            PreparePayloadHostApi();
            auto boot = (payload_boot_context*)context;
            if (boot &&
                boot->magic == PAYLOAD_BOOT_MAGIC &&
                boot->size >= sizeof(payload_boot_context))
            {
                boot->image_base = (payload_u64)mappedImage;
                boot->image_size = (payload_u64)header->image_size;
                boot->boot_flags = PAYLOAD_BOOT_FLAG_RAWPACK | PAYLOAD_BOOT_FLAG_HOST_API;
                boot->host_api = &g_payloadHostApi;
            }

            PrepareManualDriverObject(&payloadDriver, mappedImage, header->image_size, (PVOID)entry);

            NTSTATUS status = STATUS_UNSUCCESSFUL;
            __try
            {
                status = entry(&payloadDriver, (PUNICODE_STRING)context);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
                LOG_DEBUG(_XOR_("[mapDriver] raw payload entry exception=0x%X entry=%p image=%p size=0x%X\n"),
                    status, entry, mappedImage, header->image_size);
            }
            if (!NT_SUCCESS(status))
            {
                LOG_DEBUG(_XOR_("[mapDriver] raw payload entry failed 0x%X\n"), status);
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

        LOG_DEBUG(_XOR_("[mapDriver] raw payload mapped base=%p size=0x%X sections=%u relocs=%u\n"),
            payloadBase, payloadSize, header->section_count, header->reloc_count);
        return TRUE;
    }

    static bool PayloadPointerInImage(const void* ptr)
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
        LOG_DEBUG(_XOR_("[mapDriver] payload arena preserved base=%p size=0x%X\n"),
            payloadArenaBase, payloadArenaSize);
    }

    VOID UnloadPayload()
    {
        if (!payloadBase)
        {
            LOG_DEBUG(_XOR_("[mapDriver] payload unload skipped: base=null\n"));
            return;
        }

        auto unload = payloadDriver.DriverUnload;
        auto stop = payloadExports ? payloadExports->stop : nullptr;
        bool unload_valid = PayloadPointerInImage((const void*)unload);
        bool stop_valid = PayloadPointerInImage((const void*)stop);
        LOG_DEBUG(_XOR_("[mapDriver] payload unload begin base=%p size=0x%X unload=%p valid=%d stop=%p valid=%d\n"),
            payloadBase, payloadSize, unload, (int)unload_valid, stop, (int)stop_valid);
        if (unload && unload_valid)
        {
            __try
            {
                LOG_DEBUG(_XOR_("[mapDriver] calling payload DriverUnload\n"));
                unload(&payloadDriver);
                LOG_DEBUG(_XOR_("[mapDriver] payload DriverUnload returned\n"));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                LOG_DEBUG(_XOR_("[mapDriver] payload DriverUnload exception=0x%X\n"),
                    GetExceptionCode());
            }
        }
        else if (stop && stop_valid)
        {
            __try
            {
                LOG_DEBUG(_XOR_("[mapDriver] payload DriverUnload invalid, calling payload stop export\n"));
                auto result = stop();
                LOG_DEBUG(_XOR_("[mapDriver] payload stop export returned 0x%llX\n"),
                    result);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                LOG_DEBUG(_XOR_("[mapDriver] payload stop export exception=0x%X\n"),
                    GetExceptionCode());
            }
        }
        else if (unload)
        {
            LOG_DEBUG(_XOR_("[mapDriver] payload DriverUnload skipped invalid unload=%p base=%p size=0x%X stop=%p\n"),
                unload, payloadBase, payloadSize, stop);
        }
        else
        {
            LOG_DEBUG(_XOR_("[mapDriver] payload DriverUnload is null stop=%p valid=%d\n"),
                stop, (int)stop_valid);
        }

        if (payloadBase && payloadSize)
            RtlSecureZeroMemory(payloadBase, payloadSize);
        Util::PoolManagerFreePool(payloadBase);
        payloadBase = nullptr;
        payloadSize = 0;
        payloadExports = nullptr;
        RtlZeroMemory(&payloadDriver, sizeof(payloadDriver));
        LOG_DEBUG(_XOR_("[mapDriver] payload image freed\n"));

        if (payloadArenaBase && payloadArenaSize && MmFreeIndependentPages)
        {
#if MAPDRIVER_FREE_PAYLOAD_ARENA_ON_UNLOAD
            RtlSecureZeroMemory(payloadArenaBase, payloadArenaSize);
            MmFreeIndependentPages(payloadArenaBase, payloadArenaSize);
            LOG_DEBUG(_XOR_("[mapDriver] payload arena freed base=%p size=0x%X\n"),
                payloadArenaBase, payloadArenaSize);
#else
            LOG_DEBUG(_XOR_("[mapDriver] payload arena quarantine/leak on unload base=%p size=0x%X\n"),
                payloadArenaBase, payloadArenaSize);
#endif
        }
        payloadArenaBase = nullptr;
        payloadArenaSize = 0;
    }

    VOID UnloadDriver()
    {
        UnloadDriverEx(TRUE);
    }

    VOID UnloadDriverEx(BOOLEAN freeImage)
    {
        if (!imageBase)
        {
            LOG_DEBUG(_XOR_("[mapDriver] TestDriver unload skipped: base=null\n"));
            return;
        }

        auto unload = testDriver.DriverUnload;
        LOG_DEBUG(_XOR_("[mapDriver] TestDriver unload begin base=%p size=0x%X DriverObject=%p unload=%p\n"),
            imageBase, imageSize, &testDriver, unload);
        if (!testDriverUnloadCallbackCalled && unload)
        {
            __try
            {
                LOG_DEBUG(_XOR_("[mapDriver] calling TestDriver.DriverUnload\n"));
                unload(&testDriver);
                LOG_DEBUG(_XOR_("[mapDriver] TestDriver.DriverUnload returned\n"));
                testDriverUnloaded = TRUE;
                testDriverUnloadCallbackCalled = TRUE;
                testDriver.DriverUnload = nullptr;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                LOG_DEBUG(_XOR_("[mapDriver] TestDriver.DriverUnload exception=0x%X\n"),
                    GetExceptionCode());
            }
        }
        else if (!unload)
        {
            LOG_DEBUG(_XOR_("[mapDriver] TestDriver DriverUnload is null\n"));
        }
        else
        {
            LOG_DEBUG(_XOR_("[mapDriver] TestDriver DriverUnload already called\n"));
            testDriverUnloaded = TRUE;
            testDriver.DriverUnload = nullptr;
        }

        if (!freeImage)
        {
            testDriverImageQuarantined = TRUE;
            LOG_DEBUG(_XOR_("[mapDriver] TestDriver image quarantined base=%p size=0x%X\n"),
                imageBase, imageSize);
            return;
        }

        if (imageBase && imageSize)
            RtlSecureZeroMemory(imageBase, imageSize);
        Util::PoolManagerFreePool(imageBase);
        imageBase = nullptr;
        imageSize = 0;
        testDriverUnloaded = TRUE;
        testDriverUnloadCallbackCalled = TRUE;
        testDriverImageQuarantined = TRUE;
        RtlZeroMemory(&testDriver, sizeof(testDriver));
        RtlZeroMemory(SectionSnaps, sizeof(SectionSnaps));
        SectionSnapCount = 0;
        LOG_DEBUG(_XOR_("[mapDriver] TestDriver image freed\n"));
    }
}
