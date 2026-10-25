#include "../VtHypervisor/base.h"
#include "../VtHypervisor/vt/hv.h"
#include "../VtHypervisor/vt/vcpu.h"
#include "hooks/vtcall-hook.h"

#include <cstddef>
#include <intrin.h>

extern "C" unsigned __int64 svm_resident_continue_asm();

// The linked VtHypervisor runtime defines g_ghv/g_vt_hook_table inside this
// image.  Binding them to the arena-resident objects is the mutable ownership
// handoff; VMCB/NPT/MSRPM/host-保存 allocations keep their physical addresses.

extern "C" unsigned __int64 svm_take_resident_loop_c(hv::vcpu* const cpu)
{
    if (!cpu)
        return 0;

    return static_cast<unsigned __int64>(
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&cpu->svm.resident_loop),
            0));
}

extern "C" void svm_ack_resident_loop_c(hv::vcpu* const cpu)
{
    if (!cpu)
        return;

    KeMemoryBarrier();
    _InterlockedExchange64(
        reinterpret_cast<volatile LONG64*>(&cpu->svm.resident_ack),
        1);
}

extern "C" unsigned __int64 PayloadAmdResidentActivate(
    unsigned __int64 ghv,
    unsigned __int64 vt_hook_table,
    unsigned __int64 vcpus,
    unsigned __int64 vcpu_count,
    unsigned __int64 vcpu_stride,
    unsigned __int64 resident_loop_offset,
    unsigned __int64 resident_ack_offset,
    unsigned __int64 mode)
{
    constexpr auto loop_offset =
        offsetof(hv::vcpu, svm) + offsetof(hv::svm_vcpu_state, resident_loop);
    constexpr auto ack_offset =
        offsetof(hv::vcpu, svm) + offsetof(hv::svm_vcpu_state, resident_ack);

    if ((mode != 1 && mode != 2) ||
        !ghv || !vt_hook_table || !vcpus || !vcpu_count || vcpu_count > 64 ||
        vcpu_stride != sizeof(hv::vcpu) ||
        resident_loop_offset != loop_offset || resident_ack_offset != ack_offset ||
        resident_loop_offset > vcpu_stride - sizeof(LONG64) ||
        resident_ack_offset > vcpu_stride - sizeof(LONG64) ||
        (resident_loop_offset & (alignof(LONG64) - 1)) != 0 ||
        (resident_ack_offset & (alignof(LONG64) - 1)) != 0 ||
        (vcpu_count - 1) > (~0ull - vcpus) / vcpu_stride)
    {
        return 0;
    }

    auto const resident_hv = reinterpret_cast<hv::hypervisor*>(ghv);
    if (reinterpret_cast<unsigned __int64>(resident_hv->vcpus) != vcpus ||
        resident_hv->vcpu_count != vcpu_count)
    {
        return 0;
    }

    hv::g_ghv = resident_hv;
    hv::g_vt_hook_table = reinterpret_cast<hv::vt_hook_slot*>(vt_hook_table);

    unsigned __int64 complete = 0;
    for (unsigned __int64 i = 0; i < vcpu_count; ++i)
    {
        auto const base = vcpus + i * vcpu_stride;
        auto const loop = reinterpret_cast<volatile LONG64*>(base + resident_loop_offset);
        auto const ack = reinterpret_cast<volatile LONG64*>(base + resident_ack_offset);
        if (mode == 1)
        {
            _InterlockedExchange64(ack, 0);
            KeMemoryBarrier();
            _InterlockedExchange64(loop, (LONG64)(unsigned __int64)&svm_resident_continue_asm);
        }
        else if (mode == 2 && *ack == 1 && *loop == 0)
        {
            ++complete;
        }
    }

    return mode == 1 ? vcpu_count : complete;
}

