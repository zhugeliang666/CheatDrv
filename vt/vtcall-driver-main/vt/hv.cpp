                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         #pragma warning(disable: 4996)
#include "../base.h"
#include "hv.h"
#include "vcpu.h"
#include "../amd/svm.h"
#include "mm.h"
#include "arch.h"
#include "oxygenPdb.h"
#include <memory>
#include <stdarg.h>
#include <gamecommon/game.h>
#include <common/ntapi.h>
#include "../common/ntutils.h"
#include "../common/symbol_resolver.h"
#include "poolmanager/PoolManager.h"

#ifndef YVT_ENABLE_EXT_MM_SYMBOLS
#define YVT_ENABLE_EXT_MM_SYMBOLS 1
#endif

#ifndef YVT_EXT_SYMBOL_MM_IS_ADDRESS_VALID_EX
#define YVT_EXT_SYMBOL_MM_IS_ADDRESS_VALID_EX 1
#endif

#ifndef YVT_EXT_SYMBOL_NT_QUERY_VIRTUAL_MEMORY
#define YVT_EXT_SYMBOL_NT_QUERY_VIRTUAL_MEMORY 1
#endif

#ifndef YVT_EXT_SYMBOL_MM_GET_PHYSICAL_ADDRESS
#define YVT_EXT_SYMBOL_MM_GET_PHYSICAL_ADDRESS 1
#endif

// ntoskrnl symbol absolute addresses (resolved in find_offsets() below).
// Declared in vt/hv.h; consumed by dwm/kerneldwm.cpp and game.cpp.
ULONG64 MiReadWriteVirtualMemory = 0;
ULONG64 NtGetContextThread       = 0;
ULONG64 NtOpenSection            = 0;
ULONG64 NtCreatSection           = 0;
ULONG64 HalReturnToFirmware      = 0;
ULONG64 MmCopyMemory_va          = 0;  // Stage 5 memory-hide hook
ULONG64 MmCopyVirtualMemory_va   = 0;  // Stage 5 memory-hide hook (cross-process)
ULONG64 MmIsAddressValid_va      = 0;  // Stage 5 memory-hide hook (probe)
ULONG64 MmMapIoSpace_va          = 0;  // Stage 5 memory-hide hook (PA map)
ULONG64 MmIsAddressValidEx_va    = 0;  // Optional Stage 5 memory-hide hook (extended probe)
ULONG64 NtQueryVirtualMemory_va  = 0;  // Optional Stage 5 memory-hide hook (VAD query)
ULONG64 MmGetPhysicalAddress_va  = 0;  // Optional Stage 5 memory-hide hook (VA->PA disclosure)
ULONG64 DbgPrintEx_va            = 0;  // Stage 锟?in-handler kernel logging
// NtCreateThreadEx_va is private to this TU 鈥?only find_offsets() writes it
// and no other module reads it. Marked static to keep it out of the
// external symbol table. (Other Stage 5 _va globals stay extern because
// game.cpp's hook handlers reference them.)
static ULONG64 NtCreateThreadEx_va = 0;
ULONG64 NtSetEvent_va            = 0;  // Stage 锟?mid-freq hook used to flush vt_log ring
ULONG64 NtAllocateVirtualMemory_va = 0; // anti-screenshot: DWM-only, EXECUTE-class alloc 锟?overlay hide
ULONG64 NtProtectVirtualMemory_va  = 0; // anti-screenshot: DWM-only, EXECUTE-class mprotect 锟?overlay hide
ULONG64 NtMapViewOfSection_va      = 0; // anti-screenshot: DWM-only, EXECUTE-class map 锟?overlay hide
ULONG64 ObReferenceObjectByHandle_va = 0; // anti-screenshot: NtCreateSection handler resolves FileHandle 锟?FILE_OBJECT
ULONG64 ObfDereferenceObject_va      = 0; // anti-screenshot: paired release for ObReferenceObjectByHandle

namespace hv {

    alignas(0x1000) hypervisor g_static_ghv;
    hypervisor* g_ghv = &g_static_ghv;
    static spin_lock s_vt_log_lock;

// Diagnostic dump bank removed 锟?read g_ghv->diag_* directly via WinDbg.

#pragma code_seg(".vm")

    extern "C" {

        // function prototype doesn't really matter
        // since we never call these functions anyways
        NTKERNELAPI void PsGetCurrentThreadProcess();
        NTKERNELAPI void PsGetProcessImageFileName();

    }

    // dynamically find the offsets for various kernel structures
    static bool find_offsets() {

        const auto kernel_key = symbol_resolver::make_kernel_image_key(
            g_yvt.ntosInfo.imageBase,
            static_cast<ULONG>(g_yvt.ntosInfo.imageSize));

        LOG_DEBUG(_XOR_("[YVT] find_offsets: kernel key build=%lu stamp=0x%08lX size=0x%lX\n"),
            kernel_key.build_number, kernel_key.time_date_stamp, kernel_key.image_size);

        std::unique_ptr<kqpdb> pdb_holder;
        auto ensure_pdb = [&]() -> kqpdb* {
            if (pdb_holder)
                return pdb_holder.get();

            LOG_DEBUG(_XOR_("[YVT] find_offsets: hardcoded table incomplete, setting PDB server\n"));
            kqpdb::set_default_server(_XOR_("http://127.0.0.1:9090/"));

            LOG_DEBUG(_XOR_("[YVT] find_offsets: constructing kqpdb (KsInitialize inside)\n"));
            // Construct kqpdb on the heap, NOT the stack. Its constructor reads
            // ntoskrnl.exe (~13 MB) into a std::string and triggers KsInitialize
            // which itself uses several KB of stack for WSK setup. With the default
            // 12 KB driver-load stack this overflows and double-faults (bugcheck 0x7F)
            // on physical machines.
            pdb_holder.reset(new (std::nothrow) kqpdb(_XOR_("\\SystemRoot\\System32\\ntoskrnl.exe")));
            if (!pdb_holder) {
                LOG_DEBUG(_XOR_("[YVT] find_offsets: kqpdb heap alloc failed\n"));
                return nullptr;
            }

            LOG_DEBUG(_XOR_("[YVT] find_offsets: kqpdb constructed\n"));
            return pdb_holder.get();
        };

        symbol_resolver::KernelFieldTable kernel_fields;
        if (!symbol_resolver::resolve_kernel_fields_prefer_hardcoded(
                nullptr,
                kernel_key,
                symbol_resolver::kHvKernelFields,
                symbol_resolver::kHvKernelFieldCount,
                kernel_fields,
                true)) {
            auto* pdb = ensure_pdb();
            if (!pdb ||
                !symbol_resolver::resolve_kernel_fields_prefer_hardcoded(
                    pdb,
                    kernel_key,
                    symbol_resolver::kHvKernelFields,
                    symbol_resolver::kHvKernelFieldCount,
                    kernel_fields,
                    true)) {
                LOG_DEBUG(_XOR_("[YVT] find_offsets: required kernel fields missing, aborting\n"));
                return false;
            }
        }

        using F = symbol_resolver::KernelFieldId;
        const auto field = [&](F id) -> ULONG { return kernel_fields.get(id); };


         g_ghv->SuppressDebugMsg = field(F::TebSuppressDebugMsg);


         g_ghv->VadRoot = field(F::EprocessVadRoot);
         g_ghv->VadHint = field(F::EprocessVadHint);
         g_ghv->ExitTime = field(F::EprocessExitTime);
         g_ghv->Flags = field(F::EprocessFlags);
         g_ghv->SectionBaseAddress = field(F::EprocessSectionBaseAddress);
         g_ghv->SectionObject = field(F::EprocessSectionObject);
         g_ghv->RundownProtect_Process = field(F::EprocessRundownProtect);
         g_ghv->DebugPort = field(F::EprocessDebugPort);
         g_ghv->InheritedFromUniqueProcessId = field(F::EprocessInheritedFromUniqueProcessId);
         g_ghv->Peb = field(F::EprocessPeb);
         g_ghv->Ldr = field(F::PebLdr);

         g_ghv->ProcessParameters = field(F::PebProcessParameters);

         g_ghv->CurrentDirectory = field(F::RtlUserProcessParametersCurrentDirectory);

         g_ghv->DosPath = field(F::CurdirDosPath);

         g_ghv->InLoadOrderModuleList = field(F::PebLdrDataInLoadOrderModuleList);



         g_ghv->DirectoryTableBase = field(F::KprocessDirectoryTableBase);
         g_ghv->kprocess_directory_table_base_offset = field(F::KprocessDirectoryTableBase);

         g_ghv->TrapFrame = field(F::KthreadTrapFrame);
         g_ghv->ApcState = field(F::KthreadApcState);
         g_ghv->KernelTime = field(F::KthreadKernelTime);
         g_ghv->UserTime = field(F::KthreadUserTime);
         g_ghv->kthread_affinity_offset = field(F::KthreadAffinity);
         g_ghv->kthread_user_affinity_offset = field(F::KthreadUserAffinity);
         g_ghv->kthread_ideal_processor_offset = field(F::KthreadIdealProcessor);
         g_ghv->kthread_user_ideal_processor_offset = field(F::KthreadUserIdealProcessor);



         g_ghv->DbgSsReserved = field(F::TebDbgSsReserved);
         g_ghv->ClientId = field(F::TebClientId);


         g_ghv->Win32StartAddress = field(F::EthreadWin32StartAddress);
         g_ghv->StartAddress = field(F::EthreadStartAddress);
         g_ghv->SameThreadPassiveFlags = field(F::EthreadSameThreadPassiveFlags);
         g_ghv->SameThreadApcFlags = field(F::EthreadSameThreadApcFlags);
         g_ghv->RundownProtect = field(F::EthreadRundownProtect);
         g_ghv->CrossThreadFlags = field(F::EthreadCrossThreadFlags);
         g_ghv->AllowKernelWritesToExecutableMemory = field(F::EthreadAllowKernelWritesToExecutableMemory);
         g_ghv->AllowUserWritesToExecutableMemory = field(F::EthreadAllowUserWritesToExecutableMemory);
         g_ghv->ThreadListEntry = field(F::EthreadThreadListEntry);



         g_ghv->Process = field(F::KapcStateProcess);


         g_ghv->BypassProcessFreezeFlagOffset = field(F::KthreadBypassProcessFreeze);
         g_ghv->ThreadHideFromDebuggerFlagOffset = field(F::EthreadHideFromDebugger);
         g_ghv->ThreadBreakOnTerminationFlagOffset = field(F::EthreadBreakOnTermination);
         g_ghv->PicoContextOffset = field(F::EprocessPicoContext);
         g_ghv->RestrictSetThreadContextOffset = field(F::EprocessRestrictSetThreadContext);
         g_ghv->SeAuditProcessCreationInfoOffset = field(F::EprocessSeAuditProcessCreationInfo);




        // TODO: maybe dont hardcode this...
        g_ghv->kprocess_directory_table_base_offset = g_ghv->DirectoryTableBase;
        g_ghv->kpcr_pcrb_offset = field(F::KpcrPrcb);
        if (g_ghv->kpcr_pcrb_offset == MAXULONG) {
            g_ghv->kpcr_pcrb_offset = 0x180;
        }

        g_ghv->kprcb_current_thread_offset = field(F::KprcbCurrentThread);
        g_ghv->kapc_state_process_offset = g_ghv->Process;
        g_ghv->kthread_apc_state_offset = g_ghv->ApcState;

        g_ghv->system_eprocess = reinterpret_cast<uint8_t*>(PsInitialSystemProcess);

        LOG_DEBUG(_XOR_("[YVT] System EPROCESS = 0x%zX.\n"),
            reinterpret_cast<size_t>(g_ghv->system_eprocess));

        auto const ps_get_process_id = reinterpret_cast<uint8_t*>(PsGetProcessId);

        // mov rax, [rcx + OFFSET]
        // retn
        if (ps_get_process_id[0] != 0x48 ||
            ps_get_process_id[1] != 0x8B ||
            ps_get_process_id[2] != 0x81 ||
            ps_get_process_id[7] != 0xC3) {
            LOG_DEBUG(_XOR_("[YVT] Failed to get EPROCESS::UniqueProcessId offset.\n"));
            return false;
        }

        g_ghv->eprocess_unique_process_id_offset = field(F::EprocessUniqueProcessId);

        LOG_DEBUG(_XOR_("[YVT] EPROCESS::UniqueProcessId offset = 0x%zX.\n"),
            g_ghv->eprocess_unique_process_id_offset);

        auto const ps_get_process_image_file_name = reinterpret_cast<uint8_t*>(PsGetProcessImageFileName);

        // lea rax, [rcx + OFFSET]
        // retn
        if (ps_get_process_image_file_name[0] != 0x48 ||
            ps_get_process_image_file_name[1] != 0x8D ||
            ps_get_process_image_file_name[2] != 0x81 ||
            ps_get_process_image_file_name[7] != 0xC3) {
            LOG_DEBUG(_XOR_("[YVT] Failed to get EPROCESS::ImageFileName offset.\n"));
            return false;
        }

        g_ghv->eprocess_image_file_name =
            *reinterpret_cast<uint32_t*>(ps_get_process_image_file_name + 3);

        LOG_DEBUG(_XOR_("[YVT] EPROCESS::ImageFileName offset = 0x%zX.\n"),
            g_ghv->eprocess_image_file_name);

        auto const ps_get_current_thread_process =
            reinterpret_cast<uint8_t*>(PsGetCurrentThreadProcess);



        // store the System cr3 value (found in the System EPROCESS structure)
        g_ghv->system_cr3 = *reinterpret_cast<cr3*>(g_ghv->system_eprocess +
            g_ghv->kprocess_directory_table_base_offset);


        LOG_DEBUG(_XOR_("[YVT] System CR3 = 0x%zX.\n"), g_ghv->system_cr3.flags);

        // Resolve ntoskrnl symbols needed by DWM hook + game module (replaces
        // exceptionhook::Init() PDB lookup 锟?single PDB session now covers everything).
        symbol_resolver::KernelSymbolTable kernel_symbols;
        if (!symbol_resolver::resolve_kernel_symbols_prefer_hardcoded(
                nullptr,
                kernel_key,
                g_yvt.ntosInfo.imageBase,
                symbol_resolver::kHvKernelSymbols,
                symbol_resolver::kHvKernelSymbolCount,
                kernel_symbols,
                true)) {
            auto* pdb = ensure_pdb();
            if (!pdb ||
                !symbol_resolver::resolve_kernel_symbols_prefer_hardcoded(
                    pdb,
                    kernel_key,
                    g_yvt.ntosInfo.imageBase,
                    symbol_resolver::kHvKernelSymbols,
                    symbol_resolver::kHvKernelSymbolCount,
                    kernel_symbols,
                    true)) {
                LOG_DEBUG(_XOR_("[YVT] find_offsets: required ntos symbols missing, aborting\n"));
                return false;
            }
        }

        using S = symbol_resolver::KernelSymbolId;
        const auto sym = [&](S id) -> ULONG64 { return kernel_symbols.get(id); };

        MiReadWriteVirtualMemory = sym(S::NtWriteVirtualMemory);
        NtGetContextThread = sym(S::NtGetContextThread);
        NtOpenSection = sym(S::NtOpenSection);
        NtCreatSection = sym(S::NtCreateSection);
        HalReturnToFirmware = sym(S::HalReturnToFirmware);
        MmCopyMemory_va = sym(S::MmCopyMemory);
        MmCopyVirtualMemory_va = sym(S::MmCopyVirtualMemory);
        DbgPrintEx_va = sym(S::DbgPrintEx);
        NtCreateThreadEx_va = sym(S::NtCreateThreadEx);
        NtSetEvent_va = sym(S::NtSetEvent);
        NtAllocateVirtualMemory_va = sym(S::NtAllocateVirtualMemory);
        NtProtectVirtualMemory_va = sym(S::NtProtectVirtualMemory);
        NtMapViewOfSection_va = sym(S::NtMapViewOfSection);
        ObReferenceObjectByHandle_va = sym(S::ObReferenceObjectByHandle);
        ObfDereferenceObject_va = sym(S::ObfDereferenceObject);
        MmIsAddressValid_va = sym(S::MmIsAddressValid);
        MmMapIoSpace_va = sym(S::MmMapIoSpace);

#if YVT_ENABLE_EXT_MM_SYMBOLS
        // Optional memory-hide targets. Do not make these required: some builds
        // expose MmIsAddressValidEx only as an internal PDB symbol, and the
        // payload can safely fall back to the already validated MmIsAddressValid
        // path when it is absent.
        const symbol_resolver::KernelSymbolId optional_memory_symbols[] = {
#if YVT_EXT_SYMBOL_MM_IS_ADDRESS_VALID_EX
            S::MmIsAddressValidEx,
#endif
#if YVT_EXT_SYMBOL_NT_QUERY_VIRTUAL_MEMORY
            S::NtQueryVirtualMemory,
#endif
#if YVT_EXT_SYMBOL_MM_GET_PHYSICAL_ADDRESS
            S::MmGetPhysicalAddress,
#endif
        };
        symbol_resolver::KernelSymbolTable optional_kernel_symbols;
        if (symbol_resolver::resolve_kernel_symbols_prefer_hardcoded(
                pdb_holder.get(),
                kernel_key,
                g_yvt.ntosInfo.imageBase,
                optional_memory_symbols,
                sizeof(optional_memory_symbols) / sizeof(optional_memory_symbols[0]),
                optional_kernel_symbols,
                false)) {
#if YVT_EXT_SYMBOL_MM_IS_ADDRESS_VALID_EX
            if (optional_kernel_symbols.has(S::MmIsAddressValidEx))
                MmIsAddressValidEx_va = optional_kernel_symbols.get(S::MmIsAddressValidEx);
#endif
#if YVT_EXT_SYMBOL_NT_QUERY_VIRTUAL_MEMORY
            if (optional_kernel_symbols.has(S::NtQueryVirtualMemory))
                NtQueryVirtualMemory_va = optional_kernel_symbols.get(S::NtQueryVirtualMemory);
#endif
#if YVT_EXT_SYMBOL_MM_GET_PHYSICAL_ADDRESS
            if (optional_kernel_symbols.has(S::MmGetPhysicalAddress))
                MmGetPhysicalAddress_va = optional_kernel_symbols.get(S::MmGetPhysicalAddress);
#endif
        }
        LOG_DEBUG(_XOR_("[YVT-DIAG] ext mm symbols: MmIsAddressValidEx=0x%llX NtQueryVirtualMemory=0x%llX MmGetPhysicalAddress=0x%llX\n"),
            (unsigned long long)MmIsAddressValidEx_va,
            (unsigned long long)NtQueryVirtualMemory_va,
            (unsigned long long)MmGetPhysicalAddress_va);
#endif

        // Diagnostic: capture VA + first 8 bytes of NtAllocateVirtualMemory.
        // Compare to WinDbg `dq nt!NtAllocateVirtualMemory L1` on the running
        // host to verify the PDB returned the right offset for this kernel
        // build. If diag_nt_alloc_first8 != actual kernel bytes, PDB symbol is
        // pointing at the wrong VA and any hook at that address will corrupt
        // unrelated code.
        g_ghv->diag_nt_alloc_resolved_va = NtAllocateVirtualMemory_va;
        if (NtAllocateVirtualMemory_va) {
            g_ghv->diag_nt_alloc_first8 =
                *(volatile uint64_t*)NtAllocateVirtualMemory_va;
        }

        LOG_DEBUG(_XOR_("[YVT-DIAG] ntos=0x%llX  NtAllocateVirtualMemory_va=0x%llX  first8=0x%016llX\n"),
            (unsigned long long)g_yvt.ntosInfo.imageBase,
            (unsigned long long)NtAllocateVirtualMemory_va,
            (unsigned long long)g_ghv->diag_nt_alloc_first8);
        LOG_DEBUG(_XOR_("[YVT-DIAG] NtSetEvent_va=0x%llX  NtProtectVirtualMemory_va=0x%llX  NtMapViewOfSection_va=0x%llX\n"),
            (unsigned long long)NtSetEvent_va,
            (unsigned long long)NtProtectVirtualMemory_va,
            (unsigned long long)NtMapViewOfSection_va);

        return true;
    }


    bool IsXeon()
    {
        int cpuInfo[4] = { -1 };
        __cpuid(cpuInfo, 0);
        int nIds = cpuInfo[0];

        char brand[0x40];
        memset(brand, 0, sizeof(brand));

        if (nIds >= 0x80000002)
        {
            for (int i = 0x80000002; i <= 0x80000004; ++i)
            {
                __cpuid(cpuInfo, i);
                memcpy(brand + (i - 0x80000002) * 16, cpuInfo, sizeof(cpuInfo));
            }
        }

        return strstr(brand, _XOR_("Xeon")) != nullptr;
    }

    static void prealloc_buffer(uint64_t& out_va, SIZE_T size, ULONG tag,
        const char* init, SIZE_T init_size)
    {
        if (out_va)
            return;

        auto buffer = (char*)Util::PoolManagertAllocation(size, tag);
        if (!buffer) {
            LOG_DEBUG(_XOR_("[YVT] prealloc tag=0x%08X size=0x%zX failed\n"),
                tag, size);
            return;
        }

        RtlZeroMemory(buffer, size);
        if (init && init_size && init_size <= size)
            memcpy(buffer, init, init_size);

        out_va = (uint64_t)buffer;
    }

    static void preallocate_host_visible_buffers()
    {
        static const char k_mmm_fmt[] = "[MMM] hits=%llu caller=%p\n";
        static const char k_vt_fmt[]  = "[VT] %s\n";
        static const char k_csec_fmt[] = "[CSEC] file=%ws\n";
        static const char k_alloc_fmt[] = "[NVA] protect=0x%X size=0x%llX caller=0x%llX\n";
        static const char k_protect_fmt[] = "[NPV] new=0x%X base=0x%llX size=0x%llX\n";
        static const char k_map_fmt[] = "[NMV] protect=0x%X sec=0x%llX\n";

        prealloc_buffer(g_ghv->kernel_format_buf_va, 0x1000, 'kfmt',
            k_mmm_fmt, sizeof(k_mmm_fmt));
        prealloc_buffer(g_ghv->vt_log_ring_va, VT_LOG_RING_BYTES, 'vlog',
            nullptr, 0);
        if (g_ghv->vt_log_ring_va) {
            g_ghv->vt_log_write_pos = 0;
            g_ghv->vt_log_read_pos = 0;
            g_ghv->vt_log_dropped = 0;
        }
        prealloc_buffer(g_ghv->vt_log_format_va, 0x1000, 'vfmt',
            k_vt_fmt, sizeof(k_vt_fmt));
        prealloc_buffer(g_ghv->csec_scratch_va, 0x1000, 'csec',
            nullptr, 0);
        prealloc_buffer(g_ghv->csec_format_va, 0x1000, 'cfmt',
            k_csec_fmt, sizeof(k_csec_fmt));
        prealloc_buffer(g_ghv->alloc_format_va, 0x1000, 'afmt',
            k_alloc_fmt, sizeof(k_alloc_fmt));
        prealloc_buffer(g_ghv->protect_format_va, 0x1000, 'pfmt',
            k_protect_fmt, sizeof(k_protect_fmt));
        prealloc_buffer(g_ghv->map_format_va, 0x1000, 'mfmt',
            k_map_fmt, sizeof(k_map_fmt));

        g_ghv->tramp_prealloc_count = 0;
        g_ghv->tramp_prealloc_next = 0;
        for (uint32_t i = 0; i < hypervisor::TRAMP_PREALLOC_PAGE_COUNT; i++) {
            auto page = (uint64_t)Util::PoolManagertAllocation(0x1000, 'tram');
            if (!page) {
                LOG_DEBUG(_XOR_("[YVT] trampoline prealloc stopped at %u/%u\n"),
                    i, hypervisor::TRAMP_PREALLOC_PAGE_COUNT);
                break;
            }
            RtlZeroMemory((void*)page, 0x1000);
            g_ghv->tramp_prealloc_pages[g_ghv->tramp_prealloc_count++] = page;
        }

        LOG_DEBUG(_XOR_("[YVT] prealloc host-visible buffers: kfmt=0x%llX vlog=0x%llX vfmt=0x%llX csec=0x%llX tram=%u/%u\n"),
            g_ghv->kernel_format_buf_va, g_ghv->vt_log_ring_va, g_ghv->vt_log_format_va,
            g_ghv->csec_scratch_va, g_ghv->tramp_prealloc_count,
            hypervisor::TRAMP_PREALLOC_PAGE_COUNT);
    }

    void* take_preallocated_tramp_page()
    {
        auto idx = (uint32_t)_InterlockedIncrement(
            (volatile LONG*)&g_ghv->tramp_prealloc_next) - 1;
        if (idx >= g_ghv->tramp_prealloc_count)
            return nullptr;
        return (void*)g_ghv->tramp_prealloc_pages[idx];
    }


    // allocate the hypervisor and vcpus
    static bool create() {
        memset(g_ghv, 0, sizeof(*g_ghv));
        //strcpy((char*)g_ghv->dummy_page, "dummy page");

        g_ghv->affinity_lock_enabled = (YVT_AFFINITY_LOCK_ENABLED != 0);  // default off while debugging; can be enabled by hypercall

        logger_init();
        s_vt_log_lock.initialize();


        g_ghv->vcpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        g_ghv->cr3_monitor_lock.initialize();
        // size of the vcpu array
        auto const arr_size = sizeof(vcpu) * g_ghv->vcpu_count;
        // allocate an array of vcpus

        g_ghv->vcpus = (vcpu*)Util::PoolManagertAllocation(arr_size, 'vcpu');


        LOG_DEBUG(_XOR_("[YVT] vcpu address = %llx\n"), g_ghv->vcpus);


        if (!g_ghv->vcpus) {
            LOG_DEBUG(_XOR_("[YVT] Failed to allocate VCPUs.\n"));
            return false;
        }

        // zero-initialize the vcpu array
        memset(g_ghv->vcpus, 0, arr_size);
        LOG_DEBUG(_XOR_("[YVT] Allocated %u VCPUs (0x%zX bytes).\n"), g_ghv->vcpu_count, arr_size);


        for (auto i = 0; i < g_ghv->vcpu_count; i++)
        {
            g_ghv->vcpus[i].host_stack = (uint8_t*)Util::PoolManagertAllocation(host_stack_size, 'stak');
            if (!g_ghv->vcpus[i].host_stack) {
                LOG_DEBUG(_XOR_("[YVT] Failed to allocate host stack for vCPU %u.\n"), i);
                return false;
            }
            memset(g_ghv->vcpus[i].host_stack, 0, host_stack_size);
        }
        


        //g_ghv->g_cr3_map.pml4e = (ULONG64*)MmAllocateContiguousMemory(0x1000, highestAcceptableAddress);
        g_ghv->g_cr3_map.pml4e =  (ULONG64*)Util::PoolManagertAllocation(0x1000, 'pml4');

        if (g_ghv->g_cr3_map.pml4e == nullptr)
        {
			LOG_DEBUG(_XOR_("[YVT] Failed to allocate PML4E.\n"));
			return false;
        }
        

        // PDB resolution (kqpdb construct + get_struct + get_symbol) goes
        // through WSK 锟?TCP 锟?NDIS 锟?e1000 driver, ~30 stack frames deep.
        // The default 12 KB driver-load stack cannot hold this; on physical
        // machines we hit bugcheck 0x7F EXCEPTION_DOUBLE_FAULT inside the
        // network card driver. Run find_offsets() on a 24 KB expanded stack.
        // No VMX operations live in find_offsets, so KeExpandKernelStackAndCalloutEx
        // is safe here (unlike wrapping hv::start itself).
        bool offsets_ok = false;
        typedef NTSTATUS (NTAPI *PKEXPAND_STACK_EX)(PEXPAND_STACK_CALLOUT, PVOID, SIZE_T, BOOLEAN, PVOID);
        UNICODE_STRING fname;
        RtlInitUnicodeString(&fname, L"KeExpandKernelStackAndCalloutEx");
        auto pExpand = (PKEXPAND_STACK_EX)MmGetSystemRoutineAddress(&fname);
        if (pExpand) {
            NTSTATUS expand_status = pExpand(
                [](PVOID p) { *(bool*)p = find_offsets(); },
                &offsets_ok, 24 * 1024, TRUE, nullptr);
            if (!NT_SUCCESS(expand_status)) {
                LOG_DEBUG(_XOR_("[YVT] find_offsets expanded-stack call failed: 0x%08X\n"), expand_status);
                offsets_ok = false;
            }
        } else {
            offsets_ok = find_offsets();
        }

        if (!offsets_ok) {
            LOG_DEBUG(_XOR_("[YVT] Failed to find offsets.\n"));
            return false;
        }

        preallocate_host_visible_buffers();

        if (!prepare_host_page_tables()) {
            LOG_DEBUG(_XOR_("[YVT] Failed to prepare host page tables.\n"));
            return false;
        }

        LOG_DEBUG(_XOR_("[YVT] Mapped all of physical memory to address 0x%zX.\n"),
            reinterpret_cast<uint64_t>(host_physical_memory_base));


        g_ghv->protect_list.active_list_head = nullptr;
        g_ghv->protect_list.free_list_head = &g_ghv->protect_list.buffer[0];
        for (size_t i = 0; i < g_ghv->protect_list.capacity - 1; ++i)
            g_ghv->protect_list.buffer[i].next = &g_ghv->protect_list.buffer[i + 1];
        g_ghv->protect_list.buffer[g_ghv->protect_list.capacity - 1].next = nullptr;



        g_ghv->cr3_monitor_list.active_list_head = nullptr;
        g_ghv->cr3_monitor_list.free_list_head = &g_ghv->cr3_monitor_list.buffer[0];
        for (size_t i = 0; i < g_ghv->cr3_monitor_list.capacity - 1; ++i)
            g_ghv->cr3_monitor_list.buffer[i].next = &g_ghv->cr3_monitor_list.buffer[i + 1];
        g_ghv->cr3_monitor_list.buffer[g_ghv->cr3_monitor_list.capacity - 1].next = nullptr;

        g_ghv->vtcall_list.active_list_head = nullptr;
        g_ghv->vtcall_list.free_list_head = &g_ghv->vtcall_list.buffer[0];
        for (size_t i = 0; i < g_ghv->vtcall_list.capacity - 1; ++i)
			g_ghv->vtcall_list.buffer[i].next = &g_ghv->vtcall_list.buffer[i + 1];
        g_ghv->vtcall_list.buffer[g_ghv->vtcall_list.capacity - 1].next = nullptr;

        g_ghv->vtcall_lock.initialize();


        g_ghv->vtcallstack_list.active_list_head = nullptr;
        g_ghv->vtcallstack_list.free_list_head = &g_ghv->vtcallstack_list.buffer[0];
        for (size_t i = 0; i < g_ghv->vtcallstack_list.capacity - 1; ++i)
        {
            g_ghv->vtcallstack_list.buffer[i].next = &g_ghv->vtcallstack_list.buffer[i + 1];
            g_ghv->vtcallstack_list.buffer[i].stack_ptr =(((reinterpret_cast<size_t>(g_ghv->vtcallstack_list.buffer[i].stack)
                + host_stack_size) & ~0b1111ull) - 8);
        }
        g_ghv->vtcallstack_list.buffer[g_ghv->vtcallstack_list.capacity - 1].next = nullptr;
        g_ghv->vtcallstack_list.buffer[g_ghv->vtcallstack_list.capacity - 1].stack_ptr = (((reinterpret_cast<size_t>(g_ghv->vtcallstack_list.buffer[g_ghv->vtcallstack_list.capacity - 1].stack)
            + host_stack_size) & ~0b1111ull) - 8);
        g_ghv->vtcallstack_list.lock.initialize();

        // Host-managed EPT hook table: precomputes fake-page PFNs at PASSIVE_LEVEL.
        hv::eh::init_ept_hook_table();
        hv::init_ept_probe_table();
        hv::dbg_init();

        return true;
    }

    static bool pin_current_thread_to_processor(ULONG processor_index, GROUP_AFFINITY* previous)
    {
        if (!previous)
            return false;

        PROCESSOR_NUMBER number = {};
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(processor_index, &number)))
            return false;

        GROUP_AFFINITY target = {};
        target.Group = number.Group;
        target.Mask = (KAFFINITY)1ull << number.Number;
        KeSetSystemGroupAffinityThread(&target, previous);
        return true;
    }

    static void unpin_current_thread_from_processor(const GROUP_AFFINITY* previous)
    {
        if (previous)
            KeRevertToUserGroupAffinityThread(const_cast<PGROUP_AFFINITY>(previous));
    }

    static bool rollback_started_vcpus(unsigned long started_count)
    {
        bool all_stopped = true;
        for (unsigned long i = 0; i < started_count; ++i) {
            GROUP_AFFINITY previous = {};
            if (!pin_current_thread_to_processor(i, &previous)) {
                all_stopped = false;
                continue;
            }

            __try {
                hypercall_input input = {};
                input.code = hypercall_unload;
                input.key = hypercall_key;
                if (g_ghv->vcpus[i].svm.launched)
                    svm::vmmcall(input);
                else
                    vmx_vmcall(input);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                all_stopped = false;
            }
            unpin_current_thread_from_processor(&previous);
        }
        return all_stopped;
    }

    // virtualize the current system
    bool start() {
       
        if (!create()) {
            Util::PoolManagerUninitialize();
            g_ghv->vcpus = nullptr;
            g_ghv->vcpu_count = 0;
            return false;
        }

        // we need to be running at an IRQL below DISPATCH_LEVEL so
        // that KeSetSystemAffinityThreadEx takes effect immediately
        NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

        // virtualize every cpu
        for (unsigned long i = 0; i < g_ghv->vcpu_count; ++i) {
            GROUP_AFFINITY previous = {};
            if (!pin_current_thread_to_processor(i, &previous)) {
                if (rollback_started_vcpus(i)) {
                    Util::PoolManagerUninitialize();
                    g_ghv->vcpus = nullptr;
                    g_ghv->vcpu_count = 0;
                }
                return false;
            }
            g_ghv->vcpus[i].vpid = i+1;
            if (!virtualize_cpu(&g_ghv->vcpus[i])) {
                unpin_current_thread_from_processor(&previous);
                if (rollback_started_vcpus(i)) {
                    Util::PoolManagerUninitialize();
                    g_ghv->vcpus = nullptr;
                    g_ghv->vcpu_count = 0;
                }
                return false;
            }

            unpin_current_thread_from_processor(&previous);
        }

        return true;
      
    }

    // devirtualize the current system
    bool stop() {

        // we need to be running at an IRQL below DISPATCH_LEVEL so
        // that KeSetSystemAffinityThreadEx takes effect immediately
        NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

        if (!g_ghv->vcpus || !g_ghv->vcpu_count)
        {
            LOG_DEBUG(_XOR_("[YVT] hv::stop skipped: vcpus not initialized\n"));
            return false;
        }

        uint64_t const expected =
            (g_ghv->vcpu_count >= 64) ? ~0ull : ((1ull << g_ghv->vcpu_count) - 1ull);
        g_ghv->stop_phase = 1;
        g_ghv->stop_expected_bitmap = expected;
        g_ghv->stop_requested_bitmap = 0;
        g_ghv->stop_before_vmcall_bitmap = 0;
        g_ghv->stop_after_vmcall_bitmap = 0;
        g_ghv->stop_ack_bitmap = 0;
        g_ghv->stop_exception_bitmap = 0;
        g_ghv->stop_cleanup_bitmap = 0;
        g_ghv->stop_last_cpu = ~0ull;
        g_ghv->stop_result = 0;

        // devirtualize every cpu
        for (unsigned long i = 0; i < g_ghv->vcpu_count; ++i) {
            uint64_t const bit = (i < 64) ? (1ull << i) : 0;
            g_ghv->stop_last_cpu = i;
            if (bit)
                _InterlockedOr64((volatile LONG64*)&g_ghv->stop_requested_bitmap,
                    (LONG64)bit);

            GROUP_AFFINITY previous = {};
            if (!pin_current_thread_to_processor(i, &previous)) {
                if (bit)
                    _InterlockedOr64((volatile LONG64*)&g_ghv->stop_exception_bitmap, (LONG64)bit);
                continue;
            }

            // its possible that someone tried to call stop() when the hypervisor
            // wasn't even running, so we're wrapping this in a nice try-except
            // block. nice job.
            __try {
                hv::hypercall_input input;
                input.code = hv::hypercall_unload;
                input.key = hv::hypercall_key;
                if (bit)
                    _InterlockedOr64((volatile LONG64*)&g_ghv->stop_before_vmcall_bitmap,
                        (LONG64)bit);
                if (g_ghv->vcpus[i].svm.launched)
                    svm::vmmcall(input);
                else
                    vmx_vmcall(input);
                if (bit)
                    _InterlockedOr64((volatile LONG64*)&g_ghv->stop_after_vmcall_bitmap,
                        (LONG64)bit);
            }
            __except (1) {
                if (bit)
                    _InterlockedOr64((volatile LONG64*)&g_ghv->stop_exception_bitmap,
                        (LONG64)bit);
            }

            unpin_current_thread_from_processor(&previous);
        }

        uint64_t const after = g_ghv->stop_after_vmcall_bitmap & expected;
        uint64_t const ack = g_ghv->stop_ack_bitmap & expected;
        if (after != expected || ack != expected)
        {
            g_ghv->stop_phase = 0xE;
            g_ghv->stop_result = 0;
            LOG_DEBUG(_XOR_("[YVT] hv::stop incomplete: expected=0x%llX after=0x%llX ack=0x%llX exc=0x%llX; runtime not freed\n"),
                expected, g_ghv->stop_after_vmcall_bitmap, g_ghv->stop_ack_bitmap,
                g_ghv->stop_exception_bitmap);
            return false;
        }

        g_ghv->stop_phase = 2;
        for (auto i = 0; i < g_ghv->vcpu_count; i++)
        {
            svm::destroy_vcpu_state(&g_ghv->vcpus[i]);
            Util::PoolManagerFreePool(g_ghv->vcpus[i].host_stack);
            if (i < 64)
                _InterlockedOr64((volatile LONG64*)&g_ghv->stop_cleanup_bitmap,
                    (LONG64)(1ull << i));
        }

        // PoolManager is now uniformly ExAllocatePoolWithTag (no MmAllocateContiguousMemory
        // path), so a single PoolManagerFreePool handles both Xeon and non-Xeon.
        Util::PoolManagerFreePool(g_ghv->vcpus);
        g_ghv->vcpus = nullptr;
        g_ghv->vcpu_count = 0;
        Util::PoolManagerFreePool(g_ghv->g_cr3_map.pml4e);
        g_ghv->g_cr3_map.pml4e = nullptr;
        g_ghv->stop_phase = 3;
        g_ghv->stop_result = 1;
        return true;

    }

    bool add_protect_process(uint64_t process)
    {
        if (!g_ghv->protect_list.free_list_head)
            return false;



        auto const hook_node = g_ghv->protect_list.free_list_head;
        g_ghv->protect_list.free_list_head = hook_node->next;


        hook_node->next = g_ghv->protect_list.active_list_head;
        g_ghv->protect_list.active_list_head = hook_node;


        hook_node->process = process;


        return true;

    }

    void remove_protect_process(uint64_t process)
    {

        if (!g_ghv->protect_list.active_list_head)
            return;

        // the head is the target node
        if (g_ghv->protect_list.active_list_head->process == process) {
            auto const new_head = g_ghv->protect_list.active_list_head->next;

            // add to the free list
            g_ghv->protect_list.active_list_head->next = g_ghv->protect_list.free_list_head;
            g_ghv->protect_list.free_list_head = g_ghv->protect_list.active_list_head;

            // remove from the active list
            g_ghv->protect_list.active_list_head = new_head;
        }
        else {
            auto prev = g_ghv->protect_list.active_list_head;

            // search for the node BEFORE the target node (prev if this was doubly)
            while (prev->next) {
                if (prev->next->process == process)
                    break;

                prev = prev->next;
            }

            if (!prev->next)
                return;

            auto const new_next = prev->next->next;

            // add to the free list
            prev->next->next = g_ghv->protect_list.free_list_head;
            g_ghv->protect_list.free_list_head = prev->next;

            // remove from the active list
            prev->next = new_next;
        }

    }

    ghv_protect_list_node* find_protect_process(uint64_t process)
    {
        for (auto curr = g_ghv->protect_list.active_list_head; curr; curr = curr->next) {

            if (curr->process == process)
                return curr;

        }

        return nullptr;
    }



    ghv_vtcall_list_node* add_vtcall_node() {

        g_ghv->vtcall_lock.acquire();

        if (!g_ghv->vtcall_list.free_list_head) {
            g_ghv->vtcall_lock.release();
            return nullptr;
        }

        auto const hook_node = g_ghv->vtcall_list.free_list_head;
		g_ghv->vtcall_list.free_list_head = hook_node->next;
        hook_node->next = g_ghv->vtcall_list.active_list_head;
		g_ghv->vtcall_list.active_list_head = hook_node;

        g_ghv->vtcall_lock.release();

        return hook_node;

    }

    bool remove_vtcall_node(ghv_vtcall_list_node* node) {

        g_ghv->vtcall_lock.acquire();

        if (!g_ghv->vtcall_list.active_list_head) {
            g_ghv->vtcall_lock.release();
            return false;
        }

        // match by (process, thread, retRip) 锟?unique per outstanding hv::Call,
        // invariant across vCPU migration (cpu_number is not safe across reschedule)
        if (
            g_ghv->vtcall_list.active_list_head->process == node->process &&
            g_ghv->vtcall_list.active_list_head->thread  == node->thread  &&
            g_ghv->vtcall_list.active_list_head->retRip  == node->retRip) {

			auto const new_head = g_ghv->vtcall_list.active_list_head->next;

			// add to the free list
			g_ghv->vtcall_list.active_list_head->next = g_ghv->vtcall_list.free_list_head;
			g_ghv->vtcall_list.free_list_head = g_ghv->vtcall_list.active_list_head;

			// remove from the active list
			g_ghv->vtcall_list.active_list_head = new_head;
		}
        else {
			auto prev = g_ghv->vtcall_list.active_list_head;

			while (prev->next) {
				if (prev->next->process == node->process &&
                    prev->next->thread  == node->thread  &&
                    prev->next->retRip  == node->retRip)
					break;

				prev = prev->next;
			}

            if (!prev->next)
            {

                g_ghv->vtcall_lock.release();
                return false;

            }

			auto const new_next = prev->next->next;

			// add to the free list
			prev->next->next = g_ghv->vtcall_list.free_list_head;
            memset(&prev->next->newContext, 0, sizeof(guest_context));
            prev->next->newStack = 0;
            prev->next->process = 0;
            prev->next->thread = 0;
            memset(&prev->next->oldContext, 0, sizeof(guest_context));
            prev->next->oldRsp = 0;
            prev->next->oldStack = 0;
            prev->next->retRip = 0;
            memset(prev->next->stack, 0, 0x400);

			g_ghv->vtcall_list.free_list_head = prev->next;


			// remove from the active list
			prev->next = new_next;
		}

        g_ghv->vtcall_lock.release();

		return true;


    }

    ghv_vtcall_list_node* find_vtcall_node(UINT64 process, UINT64 thread, UINT64 retRip)
	{
        g_ghv->vtcall_lock.acquire();
		for (auto curr = g_ghv->vtcall_list.active_list_head; curr; curr = curr->next) {

            // Match by (process, thread, retRip) 锟?guest thread can be
            // rescheduled onto a different vCPU between hv::Call entry and
            // its vmcall return, so cpu_number is unreliable as a key
            // (causes DWM hang on physical multi-core systems).
            if (curr->process == process &&
                curr->thread  == thread  &&
                curr->retRip  == retRip) {
                g_ghv->vtcall_lock.release();
                return curr;
            }
		}
        g_ghv->vtcall_lock.release();
		return nullptr;
	}


    ghv_vtcallstack_node* add_vtcallstack_node() {

        g_ghv->vtcallstack_list.lock.acquire();

        if (!g_ghv->vtcallstack_list.free_list_head) {
            g_ghv->vtcallstack_list.lock.release();
            return nullptr;
        }

        auto const hook_node = g_ghv->vtcallstack_list.free_list_head;
        g_ghv->vtcallstack_list.free_list_head = hook_node->next;
        hook_node->next = g_ghv->vtcallstack_list.active_list_head;
        g_ghv->vtcallstack_list.active_list_head = hook_node;

        g_ghv->vtcallstack_list.lock.release();

        return hook_node;

    }


    bool remove_vtcallstack_node(ghv_vtcallstack_node* node) {

        g_ghv->vtcallstack_list.lock.acquire();

        if (!g_ghv->vtcallstack_list.active_list_head) {
            g_ghv->vtcallstack_list.lock.release();
            return false;
        }

        // the head is the target node
        if (
            g_ghv->vtcallstack_list.active_list_head->stack_ptr == node->stack_ptr) {

            auto const new_head = g_ghv->vtcallstack_list.active_list_head->next;

            // add to the free list
            g_ghv->vtcallstack_list.active_list_head->next = g_ghv->vtcallstack_list.free_list_head;
            g_ghv->vtcallstack_list.free_list_head = g_ghv->vtcallstack_list.active_list_head;

            // remove from the active list
            g_ghv->vtcallstack_list.active_list_head = new_head;
        }
        else {
            auto prev = g_ghv->vtcallstack_list.active_list_head;

            // search for the node BEFORE the target node (prev if this was doubly)
            while (prev->next) {
                if (prev->next->stack_ptr == node->stack_ptr)
                    break;

                prev = prev->next;
            }

            if (!prev->next)
            {

                g_ghv->vtcallstack_list.lock.release();
                return false;

            }

            auto const new_next = prev->next->next;

            prev->next->old_stack_ptr = 0;
            prev->next->cpu_number = 0;

            // add to the free list
            prev->next->next = g_ghv->vtcallstack_list.free_list_head;


            g_ghv->vtcallstack_list.free_list_head = prev->next;


            // remove from the active list
            prev->next = new_next;
        }

        g_ghv->vtcallstack_list.lock.release();



    }

    ghv_vtcallstack_node* find_vtcallstack_node(ULONG64 stack_ptr) {

        g_ghv->vtcallstack_list.lock.acquire();
        for (auto curr = g_ghv->vtcallstack_list.active_list_head; curr; curr = curr->next) {

            if (
                curr->stack_ptr == stack_ptr) {
                g_ghv->vtcallstack_list.lock.release();
                return curr;
            }
        }
        g_ghv->vtcallstack_list.lock.release();
        return nullptr;

    }

    // hv::Call lazy-restore: post entry vCPU's pending HOST_RSP restore from
    // the cross-vCPU return path. Caller (return vCPU's hv::Call cleanup) MUST
    // NOT vmwrite VMCS_HOST_RSP and MUST NOT remove_vtcallstack_node 锟?the
    // entry vCPU's VMCS still points at vtcallstack_node->stack_ptr, and only
    // the entry vCPU is allowed to modify its own VMCS.
    //
    // State machine (no spin-lock, all transitions via interlocked operations):
    //   0 -> 1 : producer claims slot (not visible to consumer yet)
    //   1 -> 2 : producer publishes fully initialized payload
    //   2 -> 3 : entry vCPU restores VMCS_HOST_RSP
    //   3 -> 0 : entry vCPU frees stack node after delay
    //
    // If slot is occupied (state != 0), we spin briefly waiting for the entry
    // vCPU to drain it via its natural vm-exit stream (timer / page fault /
    // hlt). After 5ms timeout, mark gives up and leaks the stack node
    // (does NOT return it to free pool because entry vCPU's VMCS still
    // references it) 锟?this leaks one slot but prevents crash.
    //
    // NOTE: Earlier version sent NMI-IPI via MSR 0x830 to wake the entry
    // vCPU when slot was busy. That caused BugCheck 0x80 (NMI_HARDWARE_FAILURE)
    // because handle_host_interrupt's NMI case unconditionally injects NMI
    // into guest (vt/vcpu.cpp:453) 锟?Windows interprets it as a hardware
    // error. Removed entirely; lazy restore relies on entry vCPU's organic
    // vm-exits (sub-ms cadence in normal operation).
    void mark_vtcall_cross_cpu_return(int entry_cpu_number,
                                      ghv_vtcallstack_node* stack_node)
    {
        auto entry_cpu = &g_ghv->vcpus[entry_cpu_number];

        // TSC threshold for 5ms timeout. Assume ~2.5GHz, 5ms = 12.5M cycles.
        constexpr uint64_t timeout_cycles = 12500000ULL;
        const uint64_t start_tsc = __rdtsc();

        for (;;) {
            if (0 == _InterlockedCompareExchange8(
                    (volatile char*)&entry_cpu->pending_state, 1, 0))
            {
                // claimed slot
                entry_cpu->pending_host_rsp_restore = stack_node->old_stack_ptr;
                entry_cpu->pending_vtcallstack_node = stack_node;
                entry_cpu->pending_release_delay   = 4;
                _InterlockedExchange8((volatile char*)&entry_cpu->pending_state, 2);
                return;
            }

            if (__rdtsc() - start_tsc > timeout_cycles) {
                // give up 锟?leak this node (do NOT free it, entry VMCS still
                // references it). Pool capacity 32 absorbs rare occurrences.
                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mark_timeout);
                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_leaked_node);
                return;
            }

            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_pending_overwrite_wait);
            _mm_pause();
        }
    }

    // Drains pending HOST_RSP restore for the current vCPU. Must be the FIRST
    // thing handle_vm_exit() does after resolving cpu 锟?VMCS_HOST_RSP currently
    // still points at the deferred stack, so any deeper host code that touches
    // the host stack would read/write the soon-to-be-released buffer.
    void process_pending_vtcall_restore(vcpu* cpu)
    {
        if (_InterlockedCompareExchange8((volatile char*)&cpu->pending_state, 2, 2) != 2)
            return;

        vmx_vmwrite(VMCS_HOST_RSP, cpu->pending_host_rsp_restore);
        cpu->pending_host_rsp_restore = 0;
        _InterlockedExchange8((volatile char*)&cpu->pending_state, 3);
    }

    // Release the deferred vtcallstack_node back to the pool, but only after
    // pending_release_delay vm-exits have elapsed on this vCPU. Reason: the
    // CURRENT vm-exit (the one that just restored VMCS_HOST_RSP) is still
    // executing on the node's stack. Need at least one full vm-exit cycle on
    // the new HOST_RSP before the node memory is safe to reuse.
    void process_pending_vtcall_release(vcpu* cpu)
    {
        if (_InterlockedCompareExchange8((volatile char*)&cpu->pending_state, 3, 3) != 3)
            return;

        if (cpu->pending_release_delay > 0) {
            cpu->pending_release_delay--;
            return;
        }

        auto node = (ghv_vtcallstack_node*)cpu->pending_vtcallstack_node;
        cpu->pending_vtcallstack_node = nullptr;
        _InterlockedExchange8((volatile char*)&cpu->pending_state, 0);
        if (node)
            remove_vtcallstack_node(node);
    }


    bool add_cr3_monitor_thread(uint64_t process,uint64_t thread)
    {
        if (!g_ghv->cr3_monitor_list.free_list_head)
            return false;


        for (auto curr = g_ghv->cr3_monitor_list.active_list_head; curr; curr = curr->next)
        {

			if (curr->thread == thread)
				return false;

		}


        auto const hook_node = g_ghv->cr3_monitor_list.free_list_head;
        g_ghv->cr3_monitor_list.free_list_head = hook_node->next;


        hook_node->next = g_ghv->cr3_monitor_list.active_list_head;
        g_ghv->cr3_monitor_list.active_list_head = hook_node;


        hook_node->process = process;
        hook_node->thread = thread;


        return true;

    }

    void remove_cr3_monitor_thread(uint64_t process,uint64_t thread)
    {

        if (!g_ghv->cr3_monitor_list.active_list_head)
            return;

        // the head is the target node
        if (g_ghv->cr3_monitor_list.active_list_head->process == process && g_ghv->cr3_monitor_list.active_list_head->thread == thread) {
            auto const new_head = g_ghv->cr3_monitor_list.active_list_head->next;

            // add to the free list
            g_ghv->cr3_monitor_list.active_list_head->next = g_ghv->cr3_monitor_list.free_list_head;
            g_ghv->cr3_monitor_list.free_list_head = g_ghv->cr3_monitor_list.active_list_head;

            // remove from the active list
            g_ghv->cr3_monitor_list.active_list_head = new_head;
        }
        else {
            auto prev = g_ghv->cr3_monitor_list.active_list_head;

            // search for the node BEFORE the target node (prev if this was doubly)
            while (prev->next) {
                if (prev->next->process == process && prev->next->thread == thread)
                    break;

                prev = prev->next;
            }

            if (!prev->next)
                return;

            auto const new_next = prev->next->next;

            // add to the free list
            prev->next->next = g_ghv->cr3_monitor_list.free_list_head;
            g_ghv->cr3_monitor_list.free_list_head = prev->next;

            // remove from the active list
            prev->next = new_next;
        }

    }

    ghv_cr3_monitor_thread_list_node* find_cr3_monitor_thread(uint64_t process,uint64_t thread)
    {
        for (auto curr = g_ghv->cr3_monitor_list.active_list_head; curr; curr = curr->next) {

            if (curr->thread == thread)
                return curr;

        }

        return nullptr;
    }

    // ====== VT log ring (Stage 锟? ======

    // Minimal host-safe formatter. Subset: %d %u %x %llx %p %s %c %%.
    // Writes into [out, out+out_size); always NUL-terminates.
    // Returns bytes written (excluding NUL).
    static size_t vt_log_format(char* out, size_t out_size,
                                 const char* fmt, va_list args)
    {
        if (!out || out_size == 0) return 0;
        size_t pos = 0;
        auto putc = [&](char c) {
            if (pos + 1 < out_size) out[pos++] = c;
        };
        auto putstr = [&](const char* s) {
            if (!s) s = "(null)";
            while (*s) putc(*s++);
        };
        auto putu = [&](uint64_t v, int base, int min_digits) {
            char buf[32];
            int n = 0;
            if (v == 0) buf[n++] = '0';
            else {
                while (v) {
                    int d = (int)(v % base);
                    buf[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
                    v /= base;
                }
            }
            while (n < min_digits) buf[n++] = '0';
            while (n--) putc(buf[n]);
        };

        for (; *fmt; fmt++) {
            if (*fmt != '%') { putc(*fmt); continue; }
            fmt++;
            bool is_long_long = false;
            if (*fmt == 'l' && *(fmt+1) == 'l') { is_long_long = true; fmt += 2; }
            else if (*fmt == 'l') { is_long_long = true; fmt++; }
            switch (*fmt) {
            case 'd': {
                int64_t v = is_long_long ? va_arg(args, int64_t) : (int64_t)va_arg(args, int);
                if (v < 0) { putc('-'); v = -v; }
                putu((uint64_t)v, 10, 0);
                break;
            }
            case 'u': {
                uint64_t v = is_long_long ? va_arg(args, uint64_t) : (uint64_t)va_arg(args, unsigned);
                putu(v, 10, 0);
                break;
            }
            case 'x': {
                uint64_t v = is_long_long ? va_arg(args, uint64_t) : (uint64_t)va_arg(args, unsigned);
                putu(v, 16, 0);
                break;
            }
            case 'p': {
                void* p = va_arg(args, void*);
                putc('0'); putc('x'); putu((uint64_t)p, 16, 16);
                break;
            }
            case 's': putstr(va_arg(args, const char*)); break;
            case 'c': putc((char)va_arg(args, int)); break;
            case '%': putc('%'); break;
            default:  putc('%'); putc(*fmt); break;
            }
        }
        out[pos] = 0;
        return pos;
    }

    // Push a formatted line into the VT log ring. Host-mode safe (no NT APIs).
    // Ring full 锟?increments dropped counter, line is lost.
    void vt_log(const char* fmt, ...) {
        if (!g_ghv->vt_log_ring_va) return;  // not initialized yet

        scoped_spin_lock guard(s_vt_log_lock);
        uint32_t write = g_ghv->vt_log_write_pos;
        uint32_t read = g_ghv->vt_log_read_pos;
        if ((write - read) >= VT_LOG_ENTRY_COUNT) {
            _InterlockedIncrement((volatile LONG*)&g_ghv->vt_log_dropped);
            return;
        }

        uint32_t slot = write % VT_LOG_ENTRY_COUNT;
        char* base = (char*)g_ghv->vt_log_ring_va + slot * VT_LOG_ENTRY_SIZE;

        va_list ap;
        va_start(ap, fmt);
        vt_log_format(base, VT_LOG_ENTRY_SIZE, fmt, ap);
        va_end(ap);
        // Publish only after the entry contents are complete.
        g_ghv->vt_log_write_pos = write + 1;
    }

    // Pop one line from the ring into `out` (must hold at least
    // VT_LOG_ENTRY_SIZE bytes). Returns true if a line was popped.
    bool vt_log_pop(char* out) {
        if (!g_ghv->vt_log_ring_va) return false;
        scoped_spin_lock guard(s_vt_log_lock);
        uint32_t read = g_ghv->vt_log_read_pos;
        uint32_t write = g_ghv->vt_log_write_pos;
        if (read == write) return false;  // empty

        uint32_t slot = read % VT_LOG_ENTRY_COUNT;
        const char* base = (const char*)g_ghv->vt_log_ring_va + slot * VT_LOG_ENTRY_SIZE;
        memcpy(out, base, VT_LOG_ENTRY_SIZE);
        g_ghv->vt_log_read_pos = read + 1;
        return true;
    }

} // namespace hv
