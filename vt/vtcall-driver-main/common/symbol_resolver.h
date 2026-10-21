#pragma once

#include <fltKernel.h>
#include <cstddef>

class kqpdb;
struct _NTAPI_OFFSETS;

namespace symbol_resolver {

enum class KernelSymbolId : unsigned short {
    NtWriteVirtualMemory,
    NtGetContextThread,
    NtOpenSection,
    NtCreateSection,
    HalReturnToFirmware,
    MmCopyMemory,
    MmCopyVirtualMemory,
    DbgPrintEx,
    NtCreateThreadEx,
    NtSetEvent,
    NtAllocateVirtualMemory,
    NtProtectVirtualMemory,
    NtMapViewOfSection,
    ObReferenceObjectByHandle,
    ObfDereferenceObject,
    MmIsAddressValid,
    MmMapIoSpace,
    MmIsAddressValidEx,
    NtQueryVirtualMemory,
    MmGetPhysicalAddress,
    MiFillPteHierarchy,
    MmDeleteKernelStack,
    MmCreateKernelStack,
    NtCreateDebugObject,
    NtDebugActiveProcess,
    MmFreeIndependentPages,
    MmSetPageProtection,
    MmAllocateIndependentPages,
    Count
};

enum class KernelFieldId : unsigned short {
    TebSuppressDebugMsg,
    TebDbgSsReserved,
    TebClientId,

    EprocessVadRoot,
    EprocessVadHint,
    EprocessExitTime,
    EprocessFlags,
    EprocessSectionBaseAddress,
    EprocessSectionObject,
    EprocessUniqueProcessId,
    EprocessRundownProtect,
    EprocessDebugPort,
    EprocessInheritedFromUniqueProcessId,
    EprocessSeAuditProcessCreationInfo,
    EprocessRestrictSetThreadContext,
    EprocessPicoContext,
    EprocessPeb,
    EprocessImageFilePointer,

    KprocessDirectoryTableBase,

    KthreadTrapFrame,
    KthreadApcState,
    KthreadKernelTime,
    KthreadUserTime,
    KthreadBypassProcessFreeze,
    KthreadAffinity,
    KthreadUserAffinity,
    KthreadIdealProcessor,
    KthreadUserIdealProcessor,

    EthreadWin32StartAddress,
    EthreadStartAddress,
    EthreadSameThreadPassiveFlags,
    EthreadSameThreadApcFlags,
    EthreadRundownProtect,
    EthreadCrossThreadFlags,
    EthreadAllowKernelWritesToExecutableMemory,
    EthreadAllowUserWritesToExecutableMemory,
    EthreadThreadListEntry,
    EthreadBreakOnTermination,
    EthreadHideFromDebugger,

    KapcStateProcess,
    PebProcessParameters,
    PebLdr,
    RtlUserProcessParametersCurrentDirectory,
    CurdirDosPath,
    KpcrPrcb,
    KprcbCurrentThread,
    PebLdrDataInLoadOrderModuleList,
    FileObjectFileName,

    Count
};

struct KernelImageKey {
    ULONG build_number;
    ULONG time_date_stamp;
    ULONG image_size;
};

struct KernelSymbolTable {
    KernelSymbolTable();

    void clear();
    bool has(KernelSymbolId id) const;
    ULONG64 get(KernelSymbolId id) const;
    void set(KernelSymbolId id, ULONG64 value);

    ULONG64 values[static_cast<std::size_t>(KernelSymbolId::Count)];
    bool present[static_cast<std::size_t>(KernelSymbolId::Count)];
};

struct KernelFieldTable {
    KernelFieldTable();

    void clear();
    bool has(KernelFieldId id) const;
    ULONG get(KernelFieldId id) const;
    void set(KernelFieldId id, ULONG value);

    ULONG values[static_cast<std::size_t>(KernelFieldId::Count)];
    bool present[static_cast<std::size_t>(KernelFieldId::Count)];
};

KernelImageKey make_kernel_image_key(ULONG64 ntos_base, ULONG image_size);

extern const KernelSymbolId kHvKernelSymbols[];
extern const std::size_t kHvKernelSymbolCount;
extern const KernelFieldId kHvKernelFields[];
extern const std::size_t kHvKernelFieldCount;

extern const KernelSymbolId kNtapiKernelSymbols[];
extern const std::size_t kNtapiKernelSymbolCount;
extern const KernelFieldId kNtapiKernelFields[];
extern const std::size_t kNtapiKernelFieldCount;

bool resolve_kernel_symbols_from_pdb(
    const kqpdb& pdb,
    ULONG64 ntos_base,
    const KernelSymbolId* ids,
    std::size_t id_count,
    KernelSymbolTable& out,
    bool require_all);

bool resolve_kernel_fields_from_pdb(
    const kqpdb& pdb,
    const KernelFieldId* ids,
    std::size_t id_count,
    KernelFieldTable& out,
    bool require_all);

bool resolve_kernel_symbols_prefer_hardcoded(
    const kqpdb* pdb,
    const KernelImageKey& key,
    ULONG64 ntos_base,
    const KernelSymbolId* ids,
    std::size_t id_count,
    KernelSymbolTable& out,
    bool require_all);

bool resolve_kernel_fields_prefer_hardcoded(
    const kqpdb* pdb,
    const KernelImageKey& key,
    const KernelFieldId* ids,
    std::size_t id_count,
    KernelFieldTable& out,
    bool require_all);

bool resolve_kernel_symbols_from_hardcoded(
    const KernelImageKey& key,
    ULONG64 ntos_base,
    const KernelSymbolId* ids,
    std::size_t id_count,
    KernelSymbolTable& out,
    bool require_all);

bool resolve_kernel_fields_from_hardcoded(
    const KernelImageKey& key,
    const KernelFieldId* ids,
    std::size_t id_count,
    KernelFieldTable& out,
    bool require_all);

bool assign_ntapi_kernel_symbols(const KernelSymbolTable& table);
void assign_ntapi_offsets(const KernelFieldTable& table, _NTAPI_OFFSETS& offsets);

} // namespace symbol_resolver
