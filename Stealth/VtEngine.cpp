#include "VtEngine.h"

#if ENABLE_VT_FRAMEWORK

static volatile LONG s_bVtActive = 0;
static volatile LONG s_bPayloadResident = 0;
static volatile LONG s_HiddenSelfPfnCount = 0;
static ULONG64 s_HiddenSelfPfns[VT_MAX_SELF_HIDDEN_PFNS] = {0};

// 放置于 .text 可执行节区的原生 VMCALL (Intel VT-x) 与 VMMCALL (AMD SVM) Stub
// 严格遵循 VT_Drvier 64 位寄存器 ABI：
//   rax = (VT_HYPERCALL_KEY << 8) | (Code & 0xFF)
//   rcx = Args[0], rdx = Args[1], r8 = Args[2], r9 = Args[3], r10 = Args[4], r11 = Args[5]
// 仅使用 Win64 volatile 寄存器，保持 leaf-function 形态；这样即使 VMCALL/VMMCALL
// 触发异常，x64 unwinder 也不需要额外的 .pdata/.xdata 描述。
#pragma code_seg(".text")
__declspec(allocate(".text")) alignas(16) static const UCHAR s_VmCallStub[] = {
    0x48, 0x8B, 0x01,       // mov rax, [rcx+0x00] (Flags)
    0x48, 0x8B, 0x51, 0x10, // mov rdx, [rcx+0x10] (Args[1])
    0x4C, 0x8B, 0x41, 0x18, // mov r8,  [rcx+0x18] (Args[2])
    0x4C, 0x8B, 0x49, 0x20, // mov r9,  [rcx+0x20] (Args[3])
    0x4C, 0x8B, 0x51, 0x28, // mov r10, [rcx+0x28] (Args[4])
    0x4C, 0x8B, 0x59, 0x30, // mov r11, [rcx+0x30] (Args[5])
    0x48, 0x8B, 0x49, 0x08, // mov rcx, [rcx+0x08] (Args[0])
    0x0F, 0x01, 0xC1,       // vmcall (Intel VT-x)
    0xC3                    // ret
};

__declspec(allocate(".text")) alignas(16) static const UCHAR s_SvmCallStub[] = {
    0x48, 0x8B, 0x01,       // mov rax, [rcx+0x00] (Flags)
    0x48, 0x8B, 0x51, 0x10, // mov rdx, [rcx+0x10] (Args[1])
    0x4C, 0x8B, 0x41, 0x18, // mov r8,  [rcx+0x18] (Args[2])
    0x4C, 0x8B, 0x49, 0x20, // mov r9,  [rcx+0x20] (Args[3])
    0x4C, 0x8B, 0x51, 0x28, // mov r10, [rcx+0x28] (Args[4])
    0x4C, 0x8B, 0x59, 0x30, // mov r11, [rcx+0x30] (Args[5])
    0x48, 0x8B, 0x49, 0x08, // mov rcx, [rcx+0x08] (Args[0])
    0x0F, 0x01, 0xD9,       // vmmcall (AMD SVM)
    0xC3                    // ret
};
#pragma code_seg()

static volatile LONG s_CpuVendorState = 0; // 0=Unknown, 1=Intel, 2=AMD

static BOOLEAN VtIsAmdCpu(VOID)
{
    LONG state = InterlockedCompareExchange(&s_CpuVendorState, 0, 0);
    if (state != 0)
    {
        return (state == 2) ? TRUE : FALSE;
    }
    int regs[4] = {0};
    __cpuid(regs, 0);
    // AuthenticAMD: EBX='Auth'(0x68747541), EDX='enti'(0x69746E65), ECX='cAMD'(0x444D4163)
    const BOOLEAN bAmd = (regs[1] == 0x68747541 && regs[3] == 0x69746E65 && regs[2] == 0x444D4163) ? TRUE : FALSE;
    InterlockedExchange(&s_CpuVendorState, bAmd ? 2 : 1);
    return bAmd;
}

typedef ULONG64(__fastcall *FN_VMCALL_STUB)(const VT_HYPERCALL_INPUT *pInput);

NO_OBFUS ULONG64 VtEngine::RawHypercall(_In_ VT_HYPERCALL_CODE Code, _In_ ULONG64 Arg0, _In_ ULONG64 Arg1,
                                        _In_ ULONG64 Arg2, _In_ ULONG64 Arg3, _In_ ULONG64 Arg4, _In_ ULONG64 Arg5)
{
    VT_HYPERCALL_INPUT input;
    input.Flags = (VT_HYPERCALL_KEY << 8) | ((ULONG64)Code & 0xFFULL);
    input.Args[0] = Arg0;
    input.Args[1] = Arg1;
    input.Args[2] = Arg2;
    input.Args[3] = Arg3;
    input.Args[4] = Arg4;
    input.Args[5] = Arg5;

    ULONG64 result = 0;
    __try
    {
        const BOOLEAN bAmd = VtIsAmdCpu();
        if (!bAmd && (__readcr4() & (1ULL << 13)) == 0)
        {
            return 0;
        }
        const FN_VMCALL_STUB fnVmCall = (FN_VMCALL_STUB)(const void *)(bAmd ? s_SvmCallStub : s_VmCallStub);
        result = fnVmCall(&input);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result = 0;
    }
    return result;
}

BOOLEAN VtEngine::IsActive(VOID)
{
    return (InterlockedCompareExchange(&s_bVtActive, 0, 0) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::IsPayloadResident(VOID)
{
    return (InterlockedCompareExchange(&s_bPayloadResident, 0, 0) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::PingHv(VOID)
{
    return (RawHypercall(VT_HC_PING) == VT_HYPERVISOR_SIGNATURE) ? TRUE : FALSE;
}

BOOLEAN VtEngine::PingPayload(_In_ ULONG64 Nonce, _Out_opt_ PULONG64 OutPong)
{
    const ULONG64 pong = RawHypercall(VT_HC_PAYLOAD_PING, Nonce);
    if (OutPong)
    {
        *OutPong = pong;
    }
    return (pong == (PAYLOAD_PONG_MAGIC ^ Nonce)) ? TRUE : FALSE;
}

BOOLEAN VtEngine::GetPayloadStatus(_Out_ payload_status *OutStatus)
{
    if (!OutStatus)
    {
        return FALSE;
    }
    RtlZeroMemory(OutStatus, sizeof(*OutStatus));
    const ULONG64 rc = RawHypercall(VT_HC_GET_PAYLOAD_STATUS, (ULONG64)OutStatus, sizeof(*OutStatus));
    return (rc == PAYLOAD_RESULT_OK && OutStatus->magic == PAYLOAD_STATUS_MAGIC) ? TRUE : FALSE;
}

BOOLEAN VtEngine::GetResidentHvDiag(_Out_ mapctl_hv_diag *OutDiag)
{
    if (!OutDiag)
    {
        return FALSE;
    }
    RtlZeroMemory(OutDiag, sizeof(*OutDiag));
    const ULONG64 copied = RawHypercall(VT_HC_GET_RESIDENT_HV_DIAG, (ULONG64)OutDiag, sizeof(*OutDiag));
    return (copied >= (MAPCTL_HV_DIAG_BASE_U64_COUNT * sizeof(ULONG64)) && OutDiag->magic == MAPCTL_HV_DIAG_MAGIC)
               ? TRUE
               : FALSE;
}

BOOLEAN VtEngine::SetPayloadMode(_In_ ULONG64 Kind, _In_ ULONG64 Mode)
{
    const ULONG64 rc = RawHypercall(VT_HC_SET_PAYLOAD_MODE, Kind, Mode);
    return (rc == PAYLOAD_RESULT_OK) ? TRUE : FALSE;
}

BOOLEAN VtEngine::Initialize(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar, _In_ ULONG BootFlags)
{
    UNREFERENCED_PARAMETER(UserVar);
    InterlockedExchange(&s_bVtActive, 0);
    InterlockedExchange(&s_bPayloadResident, 0);

    if ((BootFlags & DRV_BOOT_FLAG_ENABLE_VT) == 0)
    {
        DBG("[*] VtEngine::Initialize: disabled by boot flags");
        return FALSE;
    }

    const BOOLEAN bHvOk = PingHv();
    ULONG64 pong = 0;
    const ULONG64 kProbeNonce = 0x1337C0DE55AA1234ULL;
    const BOOLEAN bPayloadOk = PingPayload(kProbeNonce, &pong);

    if (!bHvOk && !bPayloadOk)
    {
        DBG("[*] VtEngine::Initialize: VT hypervisor not detected on current CPU, falling back to native System PTE engine.");
        return FALSE;
    }

    InterlockedExchange(&s_bVtActive, 1);
    if (bPayloadOk)
    {
        InterlockedExchange(&s_bPayloadResident, 1);
    }

    DBG("[+] VtEngine::Initialize: VT Hypervisor active (Arch=%s, HvPing=%d, ResidentPayload=%d, Pong=0x%016llX)",
        VtIsAmdCpu() ? "AMD-SVM" : "Intel-VMX", bHvOk, bPayloadOk, pong);
    return TRUE;
}

VOID VtEngine::Cleanup(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);
    if (!IsActive())
    {
        return;
    }

    UnhideAllSelfPages();
    InterlockedExchange(&s_bPayloadResident, 0);
    InterlockedExchange(&s_bVtActive, 0);
    DBG("[+] VtEngine::Cleanup: Restored hidden self PFNs and detached VT state.");
}

ULONG64 VtEngine::GetPhysicalAddress(_In_ ULONG64 Cr3, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return 0;
    }
    return RawHypercall(VT_HC_GET_PHYSICAL_ADDRESS, Cr3, Va);
}

ULONG64 VtEngine::QueryProcessCr3(_In_ ULONG64 TargetPid)
{
    if (!IsActive() || !TargetPid)
    {
        return 0;
    }
    return RawHypercall(VT_HC_QUERY_PROCESS_CR3, TargetPid);
}

ULONG64 VtEngine::ReadPhysicalMemory(_In_ ULONG64 PhysAddr, _Out_writes_bytes_(Size) PVOID Buffer, _In_ ULONG Size)
{
    if (!IsActive() || !PhysAddr || !Buffer || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_READ_PHYS_MEM, PhysAddr, (ULONG64)Buffer, (ULONG64)Size);
}

ULONG64 VtEngine::WritePhysicalMemory(_In_ ULONG64 PhysAddr, _In_reads_bytes_(Size) const VOID *Buffer, _In_ ULONG Size)
{
    if (!IsActive() || !PhysAddr || !Buffer || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_WRITE_PHYS_MEM, PhysAddr, (ULONG64)Buffer, (ULONG64)Size);
}

ULONG64 VtEngine::ReadVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _Out_writes_bytes_(Size) PVOID Buffer,
                                    _In_ ULONG Size)
{
    if (!IsActive() || !Cr3 || !Va || !Buffer || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_READ_VIRT_MEM, Cr3, (ULONG64)Buffer, Va, (ULONG64)Size);
}

ULONG64 VtEngine::WriteVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _In_reads_bytes_(Size) const VOID *Buffer,
                                     _In_ ULONG Size)
{
    if (!IsActive() || !Cr3 || !Va || !Buffer || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_WRITE_VIRT_MEM, Cr3, Va, (ULONG64)Buffer, (ULONG64)Size);
}

BOOLEAN VtEngine::HidePhysicalPage(_In_ ULONG64 Pfn)
{
    if (!IsActive() || !Pfn)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_HIDE_PHYSICAL_PAGE, Pfn) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::UnhidePhysicalPage(_In_ ULONG64 Pfn)
{
    if (!IsActive() || !Pfn)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_UNHIDE_PHYSICAL_PAGE, Pfn) != 0) ? TRUE : FALSE;
}

ULONG64 VtEngine::HidePfnList(_In_reads_(Count) PULONG64 Pfns, _In_ ULONG64 Count)
{
    if (!IsActive() || !Pfns || !Count)
    {
        return 0;
    }
    return RawHypercall(VT_HC_HIDE_PFN_LIST, (ULONG64)Pfns, Count);
}

ULONG64 VtEngine::UnhidePfnList(_In_reads_(Count) PULONG64 Pfns, _In_ ULONG64 Count)
{
    if (!IsActive() || !Pfns || !Count)
    {
        return 0;
    }
    return RawHypercall(VT_HC_UNHIDE_PFN_LIST, (ULONG64)Pfns, Count);
}

BOOLEAN VtEngine::HideVirtualRange(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar, _In_ PVOID BaseVa, _In_ SIZE_T Size)
{
    UNREFERENCED_PARAMETER(UserVar);
    if (!IsActive() || !BaseVa || !Size)
    {
        return FALSE;
    }

    const ULONG64 startVa = (ULONG64)BaseVa & ~0xFFFULL;
    const ULONG64 endVa = ((ULONG64)BaseVa + Size + 0xFFFULL) & ~0xFFFULL;
    if (endVa <= startVa)
    {
        return FALSE;
    }

    ULONG64 hiddenCount = 0;
    for (ULONG64 curVa = startVa; curVa < endVa; curVa += PAGE_SIZE)
    {
        const ULONG64 pa = GetPhysicalAddress(0, curVa);
        if (!pa)
        {
            continue;
        }

        const ULONG64 pfn = pa >> 12;
        if (pfn && HidePhysicalPage(pfn))
        {
            LONG slot = InterlockedIncrement(&s_HiddenSelfPfnCount) - 1;
            if (slot >= 0 && slot < (LONG)VT_MAX_SELF_HIDDEN_PFNS)
            {
                s_HiddenSelfPfns[slot] = pfn;
            }
            hiddenCount++;
        }
    }

    // 同步将 System CR3 页表置为 NX=1，阻断反作弊通过页表遍历检出无模块可执行页
    const ULONG64 pageCount = (endVa - startVa) >> 12;
    if (IsPayloadResident() && pageCount > 0)
    {
        SealSystemCr3PagesNx(startVa, pageCount, TRUE, TRUE);
    }

    DBG("[+] VtEngine::HideVirtualRange: Hidden %llu/%llu PFNs for range [0x%p ~ 0x%p] + System CR3 NX=1 sealed",
        hiddenCount, pageCount, BaseVa, (PVOID)endVa);
    return (hiddenCount > 0) ? TRUE : FALSE;
}

VOID VtEngine::UnhideAllSelfPages(VOID)
{
    if (!IsActive())
    {
        return;
    }

    LONG count = InterlockedExchange(&s_HiddenSelfPfnCount, 0);
    if (count <= 0)
    {
        return;
    }
    if (count > (LONG)VT_MAX_SELF_HIDDEN_PFNS)
    {
        count = (LONG)VT_MAX_SELF_HIDDEN_PFNS;
    }

    UnhidePfnList(s_HiddenSelfPfns, (ULONG64)count);
    RtlZeroMemory(s_HiddenSelfPfns, sizeof(s_HiddenSelfPfns));
}

BOOLEAN VtEngine::SealSystemCr3PagesNx(_In_ ULONG64 BaseVa, _In_ ULONG64 PageCount, _In_ BOOLEAN SetWrite,
                                       _In_ BOOLEAN SetNx)
{
    if (!IsActive() || !BaseVa || !PageCount)
    {
        return FALSE;
    }

    const ULONG64 kBatchMax = 256;
    ULONG64 curVa = BaseVa & ~0xFFFULL;
    ULONG64 remaining = PageCount;
    BOOLEAN allOk = TRUE;

    while (remaining > 0)
    {
        const ULONG64 batch = (remaining > kBatchMax) ? kBatchMax : remaining;
        VT_DBG_PTE_SEAL_REQ req = {0};
        req.Header.Magic = VT_DBG_MAGIC;
        req.Header.Version = VT_DBG_ABI_VERSION;
        req.Header.Size = sizeof(req);
        req.Header.Subcmd = VT_DBG_PTE_SEAL;
        req.Cr3 = 0;
        req.Va = curVa;
        req.PageCount = batch;
        req.Kind = 0; // PAYLOAD_DBG_PTE_SEAL_VA
        req.Flags = VT_DBG_PTE_SEAL_FLAG_SYSTEM_CR3 | (SetWrite ? VT_DBG_PTE_SEAL_FLAG_SET_WRITE : 0) |
                    (SetNx ? VT_DBG_PTE_SEAL_FLAG_SET_NX : 0);

        VT_DBG_PTE_SEAL_RSP rsp = {0};
        const ULONG64 status = DbgDispatch(VT_DBG_PTE_SEAL, &req, sizeof(req), &rsp, sizeof(rsp), 0);
        if (status != 0)
        {
            allOk = FALSE;
        }

        curVa += batch * PAGE_SIZE;
        remaining -= batch;
    }

    return allOk;
}

BOOLEAN VtEngine::EhInstall(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ BOOLEAN FullZero, _In_ BOOLEAN IsFakePage)
{
    if (!IsActive() || !Va)
    {
        return FALSE;
    }
    const ULONG64 flags = (FullZero ? 1ULL : 0ULL) | (IsFakePage ? 2ULL : 0ULL);
    return (RawHypercall(VT_HC_EH_INSTALL, Process, Va, flags) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::EhRemove(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_REMOVE, Process, Va) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::EhEnable(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_ENABLE, Process, Va) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::EhDisable(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_DISABLE, Process, Va) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::EhWrite(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ const VOID *Buffer, _In_ ULONG64 Size)
{
    if (!IsActive() || !Va || !Buffer || !Size)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_WRITE, Process, Va, (ULONG64)Buffer, Size) != 0) ? TRUE : FALSE;
}

ULONG64 VtEngine::EhGetFakeVa(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    if (!IsActive() || !Va)
    {
        return 0;
    }
    return RawHypercall(VT_HC_EH_GET_VA, Process, Va);
}

BOOLEAN VtEngine::EhRemoveAllByProcess(_In_ ULONG64 Process)
{
    if (!IsActive() || !Process)
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_EH_REMOVE_ALL_BY_PROCESS, Process) != 0) ? TRUE : FALSE;
}

ULONG64 VtEngine::VhInstall(_In_ ULONG64 TargetVa, _In_ ULONG64 HookType, _In_ ULONG64 Process,
                            _In_ BOOLEAN FilterByProcess)
{
    if (!IsActive() || !TargetVa)
    {
        return 0;
    }
    const ULONG64 packed = 1ULL | (FilterByProcess ? 2ULL : 0ULL) | ((HookType & 0xFFULL) << 8);
    return RawHypercall(VT_HC_VH_INSTALL, Process, TargetVa, 0, packed);
}

BOOLEAN VtEngine::VhEnable(_In_ ULONG64 SlotIdx)
{
    if (!IsActive())
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_VH_ENABLE, 0, SlotIdx) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::VhDisable(_In_ ULONG64 SlotIdx)
{
    if (!IsActive())
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_VH_DISABLE, 0, SlotIdx) != 0) ? TRUE : FALSE;
}

BOOLEAN VtEngine::VhRemove(_In_ ULONG64 SlotIdx)
{
    if (!IsActive())
    {
        return FALSE;
    }
    return (RawHypercall(VT_HC_VH_REMOVE, 0, SlotIdx) != 0) ? TRUE : FALSE;
}

ULONG64 VtEngine::InstallMmr(_In_ ULONG64 PhysAddr, _In_ ULONG Size, _In_ UCHAR Mode)
{
    if (!IsActive() || !PhysAddr || !Size)
    {
        return 0;
    }
    return RawHypercall(VT_HC_INSTALL_MMR, PhysAddr, (ULONG64)Size, (ULONG64)Mode);
}

BOOLEAN VtEngine::RemoveMmr(_In_ ULONG64 MmrHandle)
{
    if (!IsActive() || !MmrHandle)
    {
        return FALSE;
    }
    RawHypercall(VT_HC_REMOVE_MMR, MmrHandle);
    return TRUE;
}

BOOLEAN VtEngine::RemoveAllMmrs(VOID)
{
    if (!IsActive())
    {
        return FALSE;
    }
    RawHypercall(VT_HC_REMOVE_ALL_MMRS);
    return TRUE;
}

ULONG64 VtEngine::DbgDispatch(_In_ ULONG Subcmd, _In_opt_ const VOID *InBuf, _In_ ULONG64 InSize,
                              _Out_opt_ PVOID OutBuf, _In_ ULONG64 OutSize, _In_ ULONG64 FlagsOrSession)
{
    if (!IsActive())
    {
        return 0xFFFFFFFFULL;
    }
    return RawHypercall(VT_HC_DBG_DISPATCH, (ULONG64)Subcmd, (ULONG64)InBuf, InSize, (ULONG64)OutBuf, OutSize,
                        FlagsOrSession);
}

#else // !ENABLE_VT_FRAMEWORK

BOOLEAN VtEngine::Initialize(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar, _In_ ULONG BootFlags)
{
    UNREFERENCED_PARAMETER(UserVar);
    UNREFERENCED_PARAMETER(BootFlags);
    return FALSE;
}

VOID VtEngine::Cleanup(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar)
{
    UNREFERENCED_PARAMETER(UserVar);
}

BOOLEAN VtEngine::IsActive(VOID)
{
    return FALSE;
}

BOOLEAN VtEngine::IsPayloadResident(VOID)
{
    return FALSE;
}

ULONG64 VtEngine::RawHypercall(_In_ VT_HYPERCALL_CODE Code, _In_ ULONG64 Arg0, _In_ ULONG64 Arg1, _In_ ULONG64 Arg2,
                               _In_ ULONG64 Arg3, _In_ ULONG64 Arg4, _In_ ULONG64 Arg5)
{
    UNREFERENCED_PARAMETER(Code);
    UNREFERENCED_PARAMETER(Arg0);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    UNREFERENCED_PARAMETER(Arg3);
    UNREFERENCED_PARAMETER(Arg4);
    UNREFERENCED_PARAMETER(Arg5);
    return 0;
}

BOOLEAN VtEngine::PingHv(VOID)
{
    return FALSE;
}
BOOLEAN VtEngine::PingPayload(_In_ ULONG64 Nonce, _Out_opt_ PULONG64 OutPong)
{
    UNREFERENCED_PARAMETER(Nonce);
    if (OutPong)
        *OutPong = 0;
    return FALSE;
}
BOOLEAN VtEngine::GetPayloadStatus(_Out_ payload_status *OutStatus)
{
    UNREFERENCED_PARAMETER(OutStatus);
    return FALSE;
}
BOOLEAN VtEngine::GetResidentHvDiag(_Out_ mapctl_hv_diag *OutDiag)
{
    UNREFERENCED_PARAMETER(OutDiag);
    return FALSE;
}
BOOLEAN VtEngine::SetPayloadMode(_In_ ULONG64 Kind, _In_ ULONG64 Mode)
{
    UNREFERENCED_PARAMETER(Kind);
    UNREFERENCED_PARAMETER(Mode);
    return FALSE;
}
ULONG64 VtEngine::GetPhysicalAddress(_In_ ULONG64 Cr3, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Va);
    return 0;
}
ULONG64 VtEngine::QueryProcessCr3(_In_ ULONG64 TargetPid)
{
    UNREFERENCED_PARAMETER(TargetPid);
    return 0;
}
ULONG64 VtEngine::ReadPhysicalMemory(_In_ ULONG64 PhysAddr, _Out_writes_bytes_(Size) PVOID Buffer, _In_ ULONG Size)
{
    UNREFERENCED_PARAMETER(PhysAddr);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}
ULONG64 VtEngine::WritePhysicalMemory(_In_ ULONG64 PhysAddr, _In_reads_bytes_(Size) const VOID *Buffer, _In_ ULONG Size)
{
    UNREFERENCED_PARAMETER(PhysAddr);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}
ULONG64 VtEngine::ReadVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _Out_writes_bytes_(Size) PVOID Buffer,
                                    _In_ ULONG Size)
{
    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}
ULONG64 VtEngine::WriteVirtualMemory(_In_ ULONG64 Cr3, _In_ ULONG64 Va, _In_reads_bytes_(Size) const VOID *Buffer,
                                     _In_ ULONG Size)
{
    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return 0;
}
BOOLEAN VtEngine::HidePhysicalPage(_In_ ULONG64 Pfn)
{
    UNREFERENCED_PARAMETER(Pfn);
    return FALSE;
}
BOOLEAN VtEngine::UnhidePhysicalPage(_In_ ULONG64 Pfn)
{
    UNREFERENCED_PARAMETER(Pfn);
    return FALSE;
}
ULONG64 VtEngine::HidePfnList(_In_reads_(Count) PULONG64 Pfns, _In_ ULONG64 Count)
{
    UNREFERENCED_PARAMETER(Pfns);
    UNREFERENCED_PARAMETER(Count);
    return 0;
}
ULONG64 VtEngine::UnhidePfnList(_In_reads_(Count) PULONG64 Pfns, _In_ ULONG64 Count)
{
    UNREFERENCED_PARAMETER(Pfns);
    UNREFERENCED_PARAMETER(Count);
    return 0;
}
BOOLEAN VtEngine::HideVirtualRange(_In_opt_ PMACHENIKE_KERNEL_INTERFACE UserVar, _In_ PVOID BaseVa, _In_ SIZE_T Size)
{
    UNREFERENCED_PARAMETER(UserVar);
    UNREFERENCED_PARAMETER(BaseVa);
    UNREFERENCED_PARAMETER(Size);
    return FALSE;
}
VOID VtEngine::UnhideAllSelfPages(VOID)
{
}
BOOLEAN VtEngine::SealSystemCr3PagesNx(_In_ ULONG64 BaseVa, _In_ ULONG64 PageCount, _In_ BOOLEAN SetWrite,
                                       _In_ BOOLEAN SetNx)
{
    UNREFERENCED_PARAMETER(BaseVa);
    UNREFERENCED_PARAMETER(PageCount);
    UNREFERENCED_PARAMETER(SetWrite);
    UNREFERENCED_PARAMETER(SetNx);
    return FALSE;
}
BOOLEAN VtEngine::EhInstall(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ BOOLEAN FullZero, _In_ BOOLEAN IsFakePage)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(FullZero);
    UNREFERENCED_PARAMETER(IsFakePage);
    return FALSE;
}
BOOLEAN VtEngine::EhRemove(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    return FALSE;
}
BOOLEAN VtEngine::EhEnable(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    return FALSE;
}
BOOLEAN VtEngine::EhDisable(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    return FALSE;
}
BOOLEAN VtEngine::EhWrite(_In_ ULONG64 Process, _In_ ULONG64 Va, _In_ const VOID *Buffer, _In_ ULONG64 Size)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);
    return FALSE;
}
ULONG64 VtEngine::EhGetFakeVa(_In_ ULONG64 Process, _In_ ULONG64 Va)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Va);
    return 0;
}
BOOLEAN VtEngine::EhRemoveAllByProcess(_In_ ULONG64 Process)
{
    UNREFERENCED_PARAMETER(Process);
    return FALSE;
}
ULONG64 VtEngine::VhInstall(_In_ ULONG64 TargetVa, _In_ ULONG64 HookType, _In_ ULONG64 Process,
                            _In_ BOOLEAN FilterByProcess)
{
    UNREFERENCED_PARAMETER(TargetVa);
    UNREFERENCED_PARAMETER(HookType);
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(FilterByProcess);
    return 0;
}
BOOLEAN VtEngine::VhEnable(_In_ ULONG64 SlotIdx)
{
    UNREFERENCED_PARAMETER(SlotIdx);
    return FALSE;
}
BOOLEAN VtEngine::VhDisable(_In_ ULONG64 SlotIdx)
{
    UNREFERENCED_PARAMETER(SlotIdx);
    return FALSE;
}
BOOLEAN VtEngine::VhRemove(_In_ ULONG64 SlotIdx)
{
    UNREFERENCED_PARAMETER(SlotIdx);
    return FALSE;
}
ULONG64 VtEngine::InstallMmr(_In_ ULONG64 PhysAddr, _In_ ULONG Size, _In_ UCHAR Mode)
{
    UNREFERENCED_PARAMETER(PhysAddr);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(Mode);
    return 0;
}
BOOLEAN VtEngine::RemoveMmr(_In_ ULONG64 MmrHandle)
{
    UNREFERENCED_PARAMETER(MmrHandle);
    return FALSE;
}
BOOLEAN VtEngine::RemoveAllMmrs(VOID)
{
    return FALSE;
}
ULONG64 VtEngine::DbgDispatch(_In_ ULONG Subcmd, _In_opt_ const VOID *InBuf, _In_ ULONG64 InSize,
                              _Out_opt_ PVOID OutBuf, _In_ ULONG64 OutSize, _In_ ULONG64 FlagsOrSession)
{
    UNREFERENCED_PARAMETER(Subcmd);
    UNREFERENCED_PARAMETER(InBuf);
    UNREFERENCED_PARAMETER(InSize);
    UNREFERENCED_PARAMETER(OutBuf);
    UNREFERENCED_PARAMETER(OutSize);
    UNREFERENCED_PARAMETER(FlagsOrSession);
    return 0xFFFFFFFFULL;
}

#endif // ENABLE_VT_FRAMEWORK
