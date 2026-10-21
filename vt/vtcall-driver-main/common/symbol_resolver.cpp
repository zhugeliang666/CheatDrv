#include "symbol_resolver.h"

#include "../base.h"
#include "../pdb/oxygenPdb.h"
#include "ntapi.h"
#include "ntutils.h"

#include <map>
#include <set>
#include <string>

#pragma code_seg(".vm")

namespace symbol_resolver {

const KernelSymbolId kHvKernelSymbols[] = {
    KernelSymbolId::NtWriteVirtualMemory,
    KernelSymbolId::NtGetContextThread,
    KernelSymbolId::NtOpenSection,
    KernelSymbolId::NtCreateSection,
    KernelSymbolId::HalReturnToFirmware,
    KernelSymbolId::MmCopyMemory,
    KernelSymbolId::MmCopyVirtualMemory,
    KernelSymbolId::DbgPrintEx,
    KernelSymbolId::NtCreateThreadEx,
    KernelSymbolId::NtSetEvent,
    KernelSymbolId::NtAllocateVirtualMemory,
    KernelSymbolId::NtProtectVirtualMemory,
    KernelSymbolId::NtMapViewOfSection,
    KernelSymbolId::ObReferenceObjectByHandle,
    KernelSymbolId::ObfDereferenceObject,
    KernelSymbolId::MmIsAddressValid,
    KernelSymbolId::MmMapIoSpace,
};

const std::size_t kHvKernelSymbolCount =
    sizeof(kHvKernelSymbols) / sizeof(kHvKernelSymbols[0]);

const KernelFieldId kHvKernelFields[] = {
    KernelFieldId::TebSuppressDebugMsg,
    KernelFieldId::TebDbgSsReserved,
    KernelFieldId::TebClientId,
    KernelFieldId::EprocessVadRoot,
    KernelFieldId::EprocessVadHint,
    KernelFieldId::EprocessExitTime,
    KernelFieldId::EprocessFlags,
    KernelFieldId::EprocessSectionBaseAddress,
    KernelFieldId::EprocessSectionObject,
    KernelFieldId::EprocessUniqueProcessId,
    KernelFieldId::EprocessRundownProtect,
    KernelFieldId::EprocessDebugPort,
    KernelFieldId::EprocessInheritedFromUniqueProcessId,
    KernelFieldId::EprocessSeAuditProcessCreationInfo,
    KernelFieldId::EprocessRestrictSetThreadContext,
    KernelFieldId::EprocessPicoContext,
    KernelFieldId::EprocessPeb,
    KernelFieldId::KprocessDirectoryTableBase,
    KernelFieldId::KthreadTrapFrame,
    KernelFieldId::KthreadApcState,
    KernelFieldId::KthreadKernelTime,
    KernelFieldId::KthreadUserTime,
    KernelFieldId::KthreadBypassProcessFreeze,
    KernelFieldId::KthreadAffinity,
    KernelFieldId::KthreadUserAffinity,
    KernelFieldId::KthreadIdealProcessor,
    KernelFieldId::KthreadUserIdealProcessor,
    KernelFieldId::EthreadWin32StartAddress,
    KernelFieldId::EthreadStartAddress,
    KernelFieldId::EthreadSameThreadPassiveFlags,
    KernelFieldId::EthreadSameThreadApcFlags,
    KernelFieldId::EthreadRundownProtect,
    KernelFieldId::EthreadCrossThreadFlags,
    KernelFieldId::EthreadAllowKernelWritesToExecutableMemory,
    KernelFieldId::EthreadAllowUserWritesToExecutableMemory,
    KernelFieldId::EthreadThreadListEntry,
    KernelFieldId::EthreadBreakOnTermination,
    KernelFieldId::EthreadHideFromDebugger,
    KernelFieldId::KapcStateProcess,
    KernelFieldId::PebProcessParameters,
    KernelFieldId::PebLdr,
    KernelFieldId::RtlUserProcessParametersCurrentDirectory,
    KernelFieldId::CurdirDosPath,
    KernelFieldId::KpcrPrcb,
    KernelFieldId::KprcbCurrentThread,
    KernelFieldId::PebLdrDataInLoadOrderModuleList,
};

const std::size_t kHvKernelFieldCount =
    sizeof(kHvKernelFields) / sizeof(kHvKernelFields[0]);

const KernelSymbolId kNtapiKernelSymbols[] = {
    KernelSymbolId::MiFillPteHierarchy,
    KernelSymbolId::MmDeleteKernelStack,
    KernelSymbolId::MmCreateKernelStack,
    KernelSymbolId::NtCreateDebugObject,
    KernelSymbolId::NtDebugActiveProcess,
    KernelSymbolId::MmFreeIndependentPages,
    KernelSymbolId::MmSetPageProtection,
    KernelSymbolId::MmAllocateIndependentPages,
    KernelSymbolId::NtWriteVirtualMemory,
};

const std::size_t kNtapiKernelSymbolCount =
    sizeof(kNtapiKernelSymbols) / sizeof(kNtapiKernelSymbols[0]);

const KernelFieldId kNtapiKernelFields[] = {
    KernelFieldId::TebSuppressDebugMsg,
    KernelFieldId::EprocessVadRoot,
    KernelFieldId::EprocessImageFilePointer,
    KernelFieldId::KprocessDirectoryTableBase,
    KernelFieldId::KthreadTrapFrame,
    KernelFieldId::FileObjectFileName,
};

const std::size_t kNtapiKernelFieldCount =
    sizeof(kNtapiKernelFields) / sizeof(kNtapiKernelFields[0]);

KernelSymbolTable::KernelSymbolTable()
{
    clear();
}

void KernelSymbolTable::clear()
{
    RtlZeroMemory(values, sizeof(values));
    RtlZeroMemory(present, sizeof(present));
}

bool KernelSymbolTable::has(KernelSymbolId id) const
{
    return present[static_cast<std::size_t>(id)];
}

ULONG64 KernelSymbolTable::get(KernelSymbolId id) const
{
    return values[static_cast<std::size_t>(id)];
}

void KernelSymbolTable::set(KernelSymbolId id, ULONG64 value)
{
    const auto index = static_cast<std::size_t>(id);
    values[index] = value;
    present[index] = true;
}

KernelFieldTable::KernelFieldTable()
{
    clear();
}

void KernelFieldTable::clear()
{
    RtlZeroMemory(values, sizeof(values));
    RtlZeroMemory(present, sizeof(present));
}

bool KernelFieldTable::has(KernelFieldId id) const
{
    return present[static_cast<std::size_t>(id)];
}

ULONG KernelFieldTable::get(KernelFieldId id) const
{
    return values[static_cast<std::size_t>(id)];
}

void KernelFieldTable::set(KernelFieldId id, ULONG value)
{
    const auto index = static_cast<std::size_t>(id);
    values[index] = value;
    present[index] = true;
}

namespace {

std::string kernel_symbol_name(KernelSymbolId id)
{
    switch (id) {
    case KernelSymbolId::NtWriteVirtualMemory: return std::string(_XOR_("NtWriteVirtualMemory"));
    case KernelSymbolId::NtGetContextThread: return std::string(_XOR_("NtGetContextThread"));
    case KernelSymbolId::NtOpenSection: return std::string(_XOR_("NtOpenSection"));
    case KernelSymbolId::NtCreateSection: return std::string(_XOR_("NtCreateSection"));
    case KernelSymbolId::HalReturnToFirmware: return std::string(_XOR_("HalReturnToFirmware"));
    case KernelSymbolId::MmCopyMemory: return std::string(_XOR_("MmCopyMemory"));
    case KernelSymbolId::MmCopyVirtualMemory: return std::string(_XOR_("MmCopyVirtualMemory"));
    case KernelSymbolId::DbgPrintEx: return std::string(_XOR_("DbgPrintEx"));
    case KernelSymbolId::NtCreateThreadEx: return std::string(_XOR_("NtCreateThreadEx"));
    case KernelSymbolId::NtSetEvent: return std::string(_XOR_("NtSetEvent"));
    case KernelSymbolId::NtAllocateVirtualMemory: return std::string(_XOR_("NtAllocateVirtualMemory"));
    case KernelSymbolId::NtProtectVirtualMemory: return std::string(_XOR_("NtProtectVirtualMemory"));
    case KernelSymbolId::NtMapViewOfSection: return std::string(_XOR_("NtMapViewOfSection"));
    case KernelSymbolId::ObReferenceObjectByHandle: return std::string(_XOR_("ObReferenceObjectByHandle"));
    case KernelSymbolId::ObfDereferenceObject: return std::string(_XOR_("ObfDereferenceObject"));
    case KernelSymbolId::MmIsAddressValid: return std::string(_XOR_("MmIsAddressValid"));
    case KernelSymbolId::MmMapIoSpace: return std::string(_XOR_("MmMapIoSpace"));
    case KernelSymbolId::MmIsAddressValidEx: return std::string(_XOR_("MmIsAddressValidEx"));
    case KernelSymbolId::NtQueryVirtualMemory: return std::string(_XOR_("NtQueryVirtualMemory"));
    case KernelSymbolId::MmGetPhysicalAddress: return std::string(_XOR_("MmGetPhysicalAddress"));
    case KernelSymbolId::MiFillPteHierarchy: return std::string(_XOR_("MiFillPteHierarchy"));
    case KernelSymbolId::MmDeleteKernelStack: return std::string(_XOR_("MmDeleteKernelStack"));
    case KernelSymbolId::MmCreateKernelStack: return std::string(_XOR_("MmCreateKernelStack"));
    case KernelSymbolId::NtCreateDebugObject: return std::string(_XOR_("NtCreateDebugObject"));
    case KernelSymbolId::NtDebugActiveProcess: return std::string(_XOR_("NtDebugActiveProcess"));
    case KernelSymbolId::MmFreeIndependentPages: return std::string(_XOR_("MmFreeIndependentPages"));
    case KernelSymbolId::MmSetPageProtection: return std::string(_XOR_("MmSetPageProtection"));
    case KernelSymbolId::MmAllocateIndependentPages: return std::string(_XOR_("MmAllocateIndependentPages"));
    default: return std::string();
    }
}

bool kernel_field_name(KernelFieldId id, std::string& type, std::string& field)
{
    switch (id) {
    case KernelFieldId::TebSuppressDebugMsg:
        type = _XOR_("_TEB"); field = _XOR_("SuppressDebugMsg"); return true;
    case KernelFieldId::TebDbgSsReserved:
        type = _XOR_("_TEB"); field = _XOR_("DbgSsReserved"); return true;
    case KernelFieldId::TebClientId:
        type = _XOR_("_TEB"); field = _XOR_("ClientId"); return true;
    case KernelFieldId::EprocessVadRoot:
        type = _XOR_("_EPROCESS"); field = _XOR_("VadRoot"); return true;
    case KernelFieldId::EprocessVadHint:
        type = _XOR_("_EPROCESS"); field = _XOR_("VadHint"); return true;
    case KernelFieldId::EprocessExitTime:
        type = _XOR_("_EPROCESS"); field = _XOR_("ExitTime"); return true;
    case KernelFieldId::EprocessFlags:
        type = _XOR_("_EPROCESS"); field = _XOR_("Flags"); return true;
    case KernelFieldId::EprocessSectionBaseAddress:
        type = _XOR_("_EPROCESS"); field = _XOR_("SectionBaseAddress"); return true;
    case KernelFieldId::EprocessSectionObject:
        type = _XOR_("_EPROCESS"); field = _XOR_("SectionObject"); return true;
    case KernelFieldId::EprocessUniqueProcessId:
        type = _XOR_("_EPROCESS"); field = _XOR_("UniqueProcessId"); return true;
    case KernelFieldId::EprocessRundownProtect:
        type = _XOR_("_EPROCESS"); field = _XOR_("RundownProtect"); return true;
    case KernelFieldId::EprocessDebugPort:
        type = _XOR_("_EPROCESS"); field = _XOR_("DebugPort"); return true;
    case KernelFieldId::EprocessInheritedFromUniqueProcessId:
        type = _XOR_("_EPROCESS"); field = _XOR_("InheritedFromUniqueProcessId"); return true;
    case KernelFieldId::EprocessSeAuditProcessCreationInfo:
        type = _XOR_("_EPROCESS"); field = _XOR_("SeAuditProcessCreationInfo"); return true;
    case KernelFieldId::EprocessRestrictSetThreadContext:
        type = _XOR_("_EPROCESS"); field = _XOR_("RestrictSetThreadContext"); return true;
    case KernelFieldId::EprocessPicoContext:
        type = _XOR_("_EPROCESS"); field = _XOR_("PicoContext"); return true;
    case KernelFieldId::EprocessPeb:
        type = _XOR_("_EPROCESS"); field = _XOR_("Peb"); return true;
    case KernelFieldId::EprocessImageFilePointer:
        type = _XOR_("_EPROCESS"); field = _XOR_("ImageFilePointer"); return true;
    case KernelFieldId::KprocessDirectoryTableBase:
        type = _XOR_("_KPROCESS"); field = _XOR_("DirectoryTableBase"); return true;
    case KernelFieldId::KthreadTrapFrame:
        type = _XOR_("_KTHREAD"); field = _XOR_("TrapFrame"); return true;
    case KernelFieldId::KthreadApcState:
        type = _XOR_("_KTHREAD"); field = _XOR_("ApcState"); return true;
    case KernelFieldId::KthreadKernelTime:
        type = _XOR_("_KTHREAD"); field = _XOR_("KernelTime"); return true;
    case KernelFieldId::KthreadUserTime:
        type = _XOR_("_KTHREAD"); field = _XOR_("UserTime"); return true;
    case KernelFieldId::KthreadBypassProcessFreeze:
        type = _XOR_("_KTHREAD"); field = _XOR_("BypassProcessFreeze"); return true;
    case KernelFieldId::KthreadAffinity:
        type = _XOR_("_KTHREAD"); field = _XOR_("Affinity"); return true;
    case KernelFieldId::KthreadUserAffinity:
        type = _XOR_("_KTHREAD"); field = _XOR_("UserAffinity"); return true;
    case KernelFieldId::KthreadIdealProcessor:
        type = _XOR_("_KTHREAD"); field = _XOR_("IdealProcessor"); return true;
    case KernelFieldId::KthreadUserIdealProcessor:
        type = _XOR_("_KTHREAD"); field = _XOR_("UserIdealProcessor"); return true;
    case KernelFieldId::EthreadWin32StartAddress:
        type = _XOR_("_ETHREAD"); field = _XOR_("Win32StartAddress"); return true;
    case KernelFieldId::EthreadStartAddress:
        type = _XOR_("_ETHREAD"); field = _XOR_("StartAddress"); return true;
    case KernelFieldId::EthreadSameThreadPassiveFlags:
        type = _XOR_("_ETHREAD"); field = _XOR_("SameThreadPassiveFlags"); return true;
    case KernelFieldId::EthreadSameThreadApcFlags:
        type = _XOR_("_ETHREAD"); field = _XOR_("SameThreadApcFlags"); return true;
    case KernelFieldId::EthreadRundownProtect:
        type = _XOR_("_ETHREAD"); field = _XOR_("RundownProtect"); return true;
    case KernelFieldId::EthreadCrossThreadFlags:
        type = _XOR_("_ETHREAD"); field = _XOR_("CrossThreadFlags"); return true;
    case KernelFieldId::EthreadAllowKernelWritesToExecutableMemory:
        type = _XOR_("_ETHREAD"); field = _XOR_("AllowKernelWritesToExecutableMemory"); return true;
    case KernelFieldId::EthreadAllowUserWritesToExecutableMemory:
        type = _XOR_("_ETHREAD"); field = _XOR_("AllowUserWritesToExecutableMemory"); return true;
    case KernelFieldId::EthreadThreadListEntry:
        type = _XOR_("_ETHREAD"); field = _XOR_("ThreadListEntry"); return true;
    case KernelFieldId::EthreadBreakOnTermination:
        type = _XOR_("_ETHREAD"); field = _XOR_("BreakOnTermination"); return true;
    case KernelFieldId::EthreadHideFromDebugger:
        type = _XOR_("_ETHREAD"); field = _XOR_("HideFromDebugger"); return true;
    case KernelFieldId::KapcStateProcess:
        type = _XOR_("_KAPC_STATE"); field = _XOR_("Process"); return true;
    case KernelFieldId::PebProcessParameters:
        type = _XOR_("_PEB"); field = _XOR_("ProcessParameters"); return true;
    case KernelFieldId::PebLdr:
        type = _XOR_("_PEB"); field = _XOR_("Ldr"); return true;
    case KernelFieldId::RtlUserProcessParametersCurrentDirectory:
        type = _XOR_("_RTL_USER_PROCESS_PARAMETERS"); field = _XOR_("CurrentDirectory"); return true;
    case KernelFieldId::CurdirDosPath:
        type = _XOR_("_CURDIR"); field = _XOR_("DosPath"); return true;
    case KernelFieldId::KpcrPrcb:
        type = _XOR_("_KPCR"); field = _XOR_("Prcb"); return true;
    case KernelFieldId::KprcbCurrentThread:
        type = _XOR_("_KPRCB"); field = _XOR_("CurrentThread"); return true;
    case KernelFieldId::PebLdrDataInLoadOrderModuleList:
        type = _XOR_("_PEB_LDR_DATA"); field = _XOR_("InLoadOrderModuleList"); return true;
    case KernelFieldId::FileObjectFileName:
        type = _XOR_("_FILE_OBJECT"); field = _XOR_("FileName"); return true;
    default:
        return false;
    }
}

bool allow_negative_field_offset(KernelFieldId id, int64_t offset)
{
    return id == KernelFieldId::KpcrPrcb && offset == -1;
}

bool kernel_key_matches(const KernelImageKey& a, const KernelImageKey& b)
{
    return a.build_number == b.build_number &&
           a.time_date_stamp == b.time_date_stamp &&
           a.image_size == b.image_size;
}

bool has_any_symbol(const KernelSymbolTable& table,
    const KernelSymbolId* ids,
    std::size_t id_count)
{
    if (!ids || !id_count)
        return false;

    for (std::size_t i = 0; i < id_count; ++i) {
        if (table.has(ids[i]))
            return true;
    }

    return false;
}

bool has_all_symbols(const KernelSymbolTable& table,
    const KernelSymbolId* ids,
    std::size_t id_count)
{
    if (!ids || !id_count)
        return false;

    for (std::size_t i = 0; i < id_count; ++i) {
        if (!table.has(ids[i]))
            return false;
    }

    return true;
}

void merge_missing_symbols(KernelSymbolTable& dst,
    const KernelSymbolTable& src,
    const KernelSymbolId* ids,
    std::size_t id_count)
{
    if (!ids || !id_count)
        return;

    for (std::size_t i = 0; i < id_count; ++i) {
        const auto id = ids[i];
        if (!dst.has(id) && src.has(id))
            dst.set(id, src.get(id));
    }
}

bool has_any_field(const KernelFieldTable& table,
    const KernelFieldId* ids,
    std::size_t id_count)
{
    if (!ids || !id_count)
        return false;

    for (std::size_t i = 0; i < id_count; ++i) {
        if (table.has(ids[i]))
            return true;
    }

    return false;
}

bool has_all_fields(const KernelFieldTable& table,
    const KernelFieldId* ids,
    std::size_t id_count)
{
    if (!ids || !id_count)
        return false;

    for (std::size_t i = 0; i < id_count; ++i) {
        if (!table.has(ids[i]))
            return false;
    }

    return true;
}

void merge_missing_fields(KernelFieldTable& dst,
    const KernelFieldTable& src,
    const KernelFieldId* ids,
    std::size_t id_count)
{
    if (!ids || !id_count)
        return;

    for (std::size_t i = 0; i < id_count; ++i) {
        const auto id = ids[i];
        if (!dst.has(id) && src.has(id))
            dst.set(id, src.get(id));
    }
}

bool lookup_hardcoded_symbol_rva(const KernelImageKey& key,
    KernelSymbolId id,
    ULONG64& rva)
{
    UNREFERENCED_PARAMETER(key);
    UNREFERENCED_PARAMETER(id);
    UNREFERENCED_PARAMETER(rva);

    // Add build-locked hardcoded RVAs here. Match ALL fields in KernelImageKey
    // before returning true, e.g.:
    // if (key.build_number == 26100 && key.time_date_stamp == 0x12345678 &&
    //     key.image_size == 0x00ABC000 && id == KernelSymbolId::NtSetEvent) {
    //     rva = 0x00123456;
    //     return true;
    // }
    return false;
}

bool lookup_hardcoded_field_offset(const KernelImageKey& key,
    KernelFieldId id,
    ULONG& offset)
{
    UNREFERENCED_PARAMETER(key);
    UNREFERENCED_PARAMETER(id);
    UNREFERENCED_PARAMETER(offset);

    // Add build-locked structure offsets here. Match ALL fields in
    // KernelImageKey before returning true.
    return false;
}

} // namespace

KernelImageKey make_kernel_image_key(ULONG64 ntos_base, ULONG image_size)
{
    KernelImageKey key = {};
    key.image_size = image_size;

    RTL_OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);
    if (NT_SUCCESS(RtlGetVersion(&version)))
        key.build_number = version.dwBuildNumber;

    if (ntos_base) {
        __try {
            const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ntos_base);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                const auto nth = reinterpret_cast<PIMAGE_NT_HEADERS>(
                    reinterpret_cast<PUCHAR>(ntos_base) + dos->e_lfanew);
                if (nth->Signature == IMAGE_NT_SIGNATURE) {
                    key.time_date_stamp = nth->FileHeader.TimeDateStamp;
                    if (!key.image_size)
                        key.image_size = nth->OptionalHeader.SizeOfImage;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            key.time_date_stamp = 0;
        }
    }

    return key;
}

bool resolve_kernel_symbols_from_pdb(
    const kqpdb& pdb,
    ULONG64 ntos_base,
    const KernelSymbolId* ids,
    std::size_t id_count,
    KernelSymbolTable& out,
    bool require_all)
{
    out.clear();

    if (!ntos_base || !ids || !id_count) {
        LOG_DEBUG(_XOR_("[sym] kernel symbol query has invalid input\n"));
        return false;
    }

    std::set<std::string> request;
    for (std::size_t i = 0; i < id_count; ++i) {
        auto name = kernel_symbol_name(ids[i]);
        if (name.empty()) {
            LOG_DEBUG(_XOR_("[sym] unknown kernel symbol id %u\n"), static_cast<unsigned>(ids[i]));
            if (require_all)
                return false;
            continue;
        }
        request.insert(name);
    }

    std::map<std::string, int64_t> offsets;
    try {
        offsets = pdb.get_symbol(request);
    } catch (...) {
        LOG_DEBUG(_XOR_("[sym] pdb.get_symbol threw\n"));
        return false;
    }

    if (offsets.empty()) {
        LOG_DEBUG(_XOR_("[sym] pdb returned no kernel symbols\n"));
        return false;
    }

    bool all_ok = true;
    for (std::size_t i = 0; i < id_count; ++i) {
        auto name = kernel_symbol_name(ids[i]);
        const auto it = offsets.find(name);
        if (it == offsets.end() || it->second <= 0) {
            LOG_DEBUG(_XOR_("[sym] missing kernel symbol %s\n"), name.c_str());
            all_ok = false;
            continue;
        }

        out.set(ids[i], ntos_base + static_cast<ULONG64>(it->second));
    }

    return require_all ? all_ok : true;
}

bool resolve_kernel_fields_from_pdb(
    const kqpdb& pdb,
    const KernelFieldId* ids,
    std::size_t id_count,
    KernelFieldTable& out,
    bool require_all)
{
    out.clear();

    if (!ids || !id_count) {
        LOG_DEBUG(_XOR_("[sym] kernel field query has invalid input\n"));
        return false;
    }

    std::map<std::string, std::set<std::string>> request;
    for (std::size_t i = 0; i < id_count; ++i) {
        std::string type;
        std::string field;
        if (!kernel_field_name(ids[i], type, field)) {
            LOG_DEBUG(_XOR_("[sym] unknown kernel field id %u\n"), static_cast<unsigned>(ids[i]));
            if (require_all)
                return false;
            continue;
        }

        request[type].insert(field);
    }

    std::map<std::string, std::map<std::string, kqpdb::field_info>> structs;
    try {
        structs = pdb.get_struct(request);
    } catch (...) {
        LOG_DEBUG(_XOR_("[sym] pdb.get_struct threw\n"));
        return false;
    }

    if (structs.empty()) {
        LOG_DEBUG(_XOR_("[sym] pdb returned no kernel fields\n"));
        return false;
    }

    bool all_ok = true;
    for (std::size_t i = 0; i < id_count; ++i) {
        std::string type;
        std::string field;
        if (!kernel_field_name(ids[i], type, field)) {
            all_ok = false;
            continue;
        }

        const auto type_it = structs.find(type);
        if (type_it == structs.end()) {
            LOG_DEBUG(_XOR_("[sym] missing kernel struct %s\n"), type.c_str());
            all_ok = false;
            continue;
        }

        const auto field_it = type_it->second.find(field);
        if (field_it == type_it->second.end()) {
            LOG_DEBUG(_XOR_("[sym] missing kernel field %s::%s\n"), type.c_str(), field.c_str());
            all_ok = false;
            continue;
        }

        const auto offset = field_it->second.offset;
        if (offset < 0 && !allow_negative_field_offset(ids[i], offset)) {
            LOG_DEBUG(_XOR_("[sym] invalid kernel field %s::%s offset=%lld\n"),
                type.c_str(), field.c_str(), static_cast<long long>(offset));
            all_ok = false;
            continue;
        }

        out.set(ids[i], static_cast<ULONG>(offset));
    }

    return require_all ? all_ok : true;
}

bool resolve_kernel_symbols_from_hardcoded(
    const KernelImageKey& key,
    ULONG64 ntos_base,
    const KernelSymbolId* ids,
    std::size_t id_count,
    KernelSymbolTable& out,
    bool require_all)
{
    out.clear();

    if (!ntos_base || !ids || !id_count || !key.build_number ||
        !key.time_date_stamp || !key.image_size) {
        return false;
    }

    bool any_ok = false;
    bool all_ok = true;

    for (std::size_t i = 0; i < id_count; ++i) {
        bool found = false;

        ULONG64 rva = 0;
        if (lookup_hardcoded_symbol_rva(key, ids[i], rva) && rva) {
            out.set(ids[i], ntos_base + rva);
            found = true;
            any_ok = true;
        }

        if (!found)
            all_ok = false;
    }

    if (any_ok) {
        LOG_DEBUG(_XOR_("[sym] hardcoded symbols matched build=%lu stamp=0x%08lX size=0x%lX all=%d\n"),
            key.build_number, key.time_date_stamp, key.image_size, (int)all_ok);
    }

    return require_all ? all_ok : any_ok;
}

bool resolve_kernel_fields_from_hardcoded(
    const KernelImageKey& key,
    const KernelFieldId* ids,
    std::size_t id_count,
    KernelFieldTable& out,
    bool require_all)
{
    out.clear();

    if (!ids || !id_count || !key.build_number ||
        !key.time_date_stamp || !key.image_size) {
        return false;
    }

    bool any_ok = false;
    bool all_ok = true;

    for (std::size_t i = 0; i < id_count; ++i) {
        bool found = false;

        ULONG offset = 0;
        if (lookup_hardcoded_field_offset(key, ids[i], offset)) {
            out.set(ids[i], offset);
            found = true;
            any_ok = true;
        }

        if (!found)
            all_ok = false;
    }

    if (any_ok) {
        LOG_DEBUG(_XOR_("[sym] hardcoded fields matched build=%lu stamp=0x%08lX size=0x%lX all=%d\n"),
            key.build_number, key.time_date_stamp, key.image_size, (int)all_ok);
    }

    return require_all ? all_ok : any_ok;
}

bool resolve_kernel_symbols_prefer_hardcoded(
    const kqpdb* pdb,
    const KernelImageKey& key,
    ULONG64 ntos_base,
    const KernelSymbolId* ids,
    std::size_t id_count,
    KernelSymbolTable& out,
    bool require_all)
{
    out.clear();

    KernelSymbolTable hardcoded;
    const bool hardcoded_any = resolve_kernel_symbols_from_hardcoded(
        key, ntos_base, ids, id_count, hardcoded, false);

    if (hardcoded_any) {
        merge_missing_symbols(out, hardcoded, ids, id_count);
        if (has_all_symbols(out, ids, id_count)) {
            LOG_DEBUG(_XOR_("[sym] using complete hardcoded kernel symbol table\n"));
            return true;
        }
        LOG_DEBUG(_XOR_("[sym] hardcoded kernel symbol table is partial; PDB will fill missing entries\n"));
    }

    if (pdb) {
        KernelSymbolTable pdb_symbols;
        if (resolve_kernel_symbols_from_pdb(
                *pdb, ntos_base, ids, id_count, pdb_symbols, false)) {
            merge_missing_symbols(out, pdb_symbols, ids, id_count);
        }
    }

    return require_all ? has_all_symbols(out, ids, id_count)
                       : has_any_symbol(out, ids, id_count);
}

bool resolve_kernel_fields_prefer_hardcoded(
    const kqpdb* pdb,
    const KernelImageKey& key,
    const KernelFieldId* ids,
    std::size_t id_count,
    KernelFieldTable& out,
    bool require_all)
{
    out.clear();

    KernelFieldTable hardcoded;
    const bool hardcoded_any = resolve_kernel_fields_from_hardcoded(
        key, ids, id_count, hardcoded, false);

    if (hardcoded_any) {
        merge_missing_fields(out, hardcoded, ids, id_count);
        if (has_all_fields(out, ids, id_count)) {
            LOG_DEBUG(_XOR_("[sym] using complete hardcoded kernel field table\n"));
            return true;
        }
        LOG_DEBUG(_XOR_("[sym] hardcoded kernel field table is partial; PDB will fill missing entries\n"));
    }

    if (pdb) {
        KernelFieldTable pdb_fields;
        if (resolve_kernel_fields_from_pdb(
                *pdb, ids, id_count, pdb_fields, false)) {
            merge_missing_fields(out, pdb_fields, ids, id_count);
        }
    }

    return require_all ? has_all_fields(out, ids, id_count)
                       : has_any_field(out, ids, id_count);
}

bool assign_ntapi_kernel_symbols(const KernelSymbolTable& table)
{
    bool ok = true;

#define ASSIGN_NTAPI_SYMBOL(_id, _target)                                      \
    do {                                                                       \
        const auto sym_id = KernelSymbolId::_id;                               \
        if (table.has(sym_id)) {                                               \
            *reinterpret_cast<ULONG64*>(&_target) = table.get(sym_id);         \
        } else {                                                               \
            *reinterpret_cast<ULONG64*>(&_target) = 0;                         \
            LOG_DEBUG(_XOR_("[sym] missing ntapi kernel symbol %s\n"), _XOR_(#_id)); \
            ok = false;                                                        \
        }                                                                      \
    } while (false)

    ASSIGN_NTAPI_SYMBOL(MiFillPteHierarchy, MiFillPteHierarchy);
    ASSIGN_NTAPI_SYMBOL(MmDeleteKernelStack, MmDeleteKernelStack);
    ASSIGN_NTAPI_SYMBOL(MmCreateKernelStack, MmCreateKernelStack);
    ASSIGN_NTAPI_SYMBOL(NtCreateDebugObject, NtCreateDebugObject);
    ASSIGN_NTAPI_SYMBOL(NtDebugActiveProcess, NtDebugActiveProcess);
    ASSIGN_NTAPI_SYMBOL(MmFreeIndependentPages, MmFreeIndependentPages);
    ASSIGN_NTAPI_SYMBOL(MmSetPageProtection, MmSetPageProtection);
    ASSIGN_NTAPI_SYMBOL(MmAllocateIndependentPages, MmAllocateIndependentPages);

#undef ASSIGN_NTAPI_SYMBOL

    return ok;
}

void assign_ntapi_offsets(const KernelFieldTable& table, _NTAPI_OFFSETS& offsets)
{
    if (table.has(KernelFieldId::TebSuppressDebugMsg))
        offsets.SuppressDebugMsg = table.get(KernelFieldId::TebSuppressDebugMsg);
    if (table.has(KernelFieldId::EprocessImageFilePointer))
        offsets.ImageFilePointer = table.get(KernelFieldId::EprocessImageFilePointer);
    if (table.has(KernelFieldId::EprocessVadRoot))
        offsets.VadRoot = table.get(KernelFieldId::EprocessVadRoot);
    if (table.has(KernelFieldId::KprocessDirectoryTableBase))
        offsets.DirectoryTableBase = table.get(KernelFieldId::KprocessDirectoryTableBase);
    if (table.has(KernelFieldId::FileObjectFileName))
        offsets.FileName = table.get(KernelFieldId::FileObjectFileName);
    if (table.has(KernelFieldId::KthreadTrapFrame))
        offsets.TrapFrame = table.get(KernelFieldId::KthreadTrapFrame);
}

} // namespace symbol_resolver
