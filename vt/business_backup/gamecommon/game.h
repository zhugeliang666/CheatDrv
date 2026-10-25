#pragma once
#include "ia32.hpp"
#include "vt/vcpu.h"
#include <windef.h>
#include "vt/hv.h"
#include "vt/mm.h"
#include "vt/exception-routines.h"
#include "string"
#include "vt/ept.h"

extern PVOID buffer0;
extern PVOID buffer1;

#define VMCALL_DISPATCH_NORMAL 0
#define VMCALL_DISPATCH_SELF 1
#define VMCALL_DISPATCH_RETABS 2
#define VMCALL_HOOK_MAX 32

#pragma code_seg(".vm")
namespace hv
{
extern PVOID descBuffer;
extern PVOID entityBuffer_hva;
extern PVOID descBuffer_hva;
extern PVOID entityBuffer;

// 锟脚碉拷vmcall锟斤拷

struct VMCALLHookData
{
    PVOID address;             // 要 Hook 锟侥碉拷址
    PVOID nextAddress;         // 锟斤拷一锟斤拷指锟斤拷锟街
    UCHAR oldByte[20];         // 原始锟街节ｏ拷锟斤拷锟斤拷 int 3 hook锟斤拷
    UCHAR nextOldByte[20];     // 锟斤拷一锟斤拷指锟斤拷锟皆始锟街斤拷
    UCHAR retByte;             // 锟斤拷锟斤拷锟街斤拷
    UCHAR originalBytes[15];   // 原始锟街斤拷
    ULONG size;                // Hook 锟斤拷小
    bool isSetJmpCode;         // 锟角凤拷锟斤拷锟斤拷锟斤拷转锟斤拷锟斤拷
    PEPROCESS process;         // 锟斤拷锟教讹拷锟斤拷
    ULONG64 blankMemory;       // 锟秸帮拷锟节达拷锟街
    ULONG64 fakeMemoryAddress; // 锟斤拷锟节达拷锟街
    PETHREAD thread;           // 锟竭程讹拷锟斤拷
    bool isEnable;             // 锟角凤拷锟斤拷锟斤拷
    bool isSwitchCr3;          // 锟角凤拷锟叫伙拷 CR3
    UINT64 type;
    PMDL addressMdl;
    PMDL blankAddressMdl;
    ULONG64 trampleAddress;
    UINT8 dispatch_mode;
    bool filter_by_process;
};

extern PVOID mouse_event;

// Shared host-side VTCall hook slot table (defined in gamecommon/game.cpp).
// Exposed so vt/vtcall-hook.cpp can populate/remove entries without
// double-bookkeeping.
struct vt_hook_slot
{
    VMCALLHookData data;
    void *fake_mem_hva;
    // 0xCC trampoline state. dispatcher sets GUEST_RIP=trampoline_va to
    // execute oldByte then trap on 0xCC; #BP handler matches bp_rip
    // (= 0xCC byte VA, since VMX delivers GUEST_RIP at the trapping byte)
    // and rewrites GUEST_RIP=target_resume to continue past hook site.
    uint64_t trampoline_va; // 0xCC slot start (in ntdll/ntoskrnl)
    uint64_t bp_rip;        // = trampoline_va + oldByte_size
    uint64_t target_resume; // = (uint64_t)data.address + data.size
    bool occupied;
};
extern vt_hook_slot *g_vt_hook_table;

extern "C" vt_call_entry(UINT64 rcx, UINT64 rdx, UINT64 r8);
extern "C" vt_call_exit(UINT64 rcx, UINT64 rdx);

extern UINT64 gamevt_image_base;
extern UINT64 gamevt_driver_unload;

extern UINT64 gameD3d11base;

using fnCallback = void (*)(CONTEXT *context);

extern UINT64 count;

extern bool isMemoryPrepare;

extern PVOID d2dRenderTarget;

extern PVOID colorBrush;

typedef void (*vt_handler_fn)(vcpu *);

extern ULONG64 get_blank_memory(UINT type);
extern void init_vmcall_handlers();

// get the ETHREAD of the current guest
extern PETHREAD current_guest_ethread();

// get the EPROCESS of the current guest
extern PEPROCESS current_guest_eprocess();

extern cr3 current_guest_cr3();

PVOID GetVFunc(PVOID Class, ULONG Index);

VOID Release(PVOID Class);

template <size_t Off, typename Tuple, std::size_t... Ints>
auto select_tuple(std::integral_constant<size_t, Off>, Tuple &&tuple, std::index_sequence<Ints...>)
{
    return std::make_tuple(std::get<Off + Ints>(std::forward<Tuple>(tuple))...);
}

template <std::size_t N> struct make_index_sequence_if
{
    using type = std::make_index_sequence<N>;
};

template <> struct make_index_sequence_if<0>
{
    using type = std::index_sequence<>;
};

#define STACK_POS 0x200
#define STACK_COPY_SIZE 0x400

#define STACK_POS_1 0x200
#define STACK_COPY_SIZE_1 0x400

template <typename Ret = void *, typename ptrType, typename... va> Ret Call(ptrType ptr, va... Args)
{
    auto cpuid = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;
    auto cpu = &g_ghv->vcpus[cpuid];

    ghv_vtcall_list_node *node = add_vtcall_node();

    if (!node)
        return 0;
    node->oldContext_ptr = cpu->ctx;
    node->oldContext = *cpu->ctx;
    node->oldRip = vmx_vmread(VMCS_GUEST_RIP);
    node->oldRsp = vmx_vmread(VMCS_GUEST_RSP);
    node->process = (UINT64)current_guest_eprocess();
    node->thread = (UINT64)current_guest_ethread();
    node->retRip = get_blank_memory(1);
    node->cpu_number = (int)cpuid;

    auto newUserRsp = 0ULL;

    newUserRsp = ((node->oldRsp - STACK_POS) & ~0b1111ull) - 8;

    auto guest_cr3 = current_guest_cr3();

    auto new_rsp_hva = gva2hva(guest_cr3, (void *)newUserRsp);

    memcpy(node->stack, new_rsp_hva, STACK_COPY_SIZE);

    auto am = std::make_tuple(std::forward<va>(Args)...);

    UINT64 cData[9] = {0};

    auto ret_index = typename make_index_sequence_if<(sizeof...(va) >= 4 ? 4 : sizeof...(va))>::type{};

    auto reg_vars = select_tuple(std::integral_constant<size_t, 0>{}, am, ret_index);
    auto remapRegVars = [&](int &indx, auto var)
    {
        if constexpr (!std::is_same<decltype(var), float>::value)
        {
            if (indx == 0)
            {
                cpu->ctx->rcx = *(ULONG64 *)&var;
            }
            if (indx == 1)
            {
                cpu->ctx->rdx = *(ULONG64 *)&var;
            }

            if (indx == 2)
            {
                cpu->ctx->r8 = *(ULONG64 *)&var;
            }
            if (indx == 3)
            {
                cpu->ctx->r9 = *(ULONG64 *)&var;
            }
        }
        else
        {
            if (indx == 0)
            {
                cData[0] = *(UINT64 *)&var;
            }
            if (indx == 1)
            {
                cData[1] = *(UINT64 *)&var;
            }
            if (indx == 2)
            {
                cData[2] = *(UINT64 *)&var;
            }
            if (indx == 3)
            {
                cData[3] = *(UINT64 *)&var;
            }
        };

        *(ULONG64 *)((UINT64)new_rsp_hva + 0x8 + (indx * 8)) = *(ULONG64 *)&var;
        indx++;
    };

    std::apply(
        [&](auto &&...xs)
        {
            int indx = 0;
            (remapRegVars(indx, xs), ...);
        },
        reg_vars);

    if constexpr (sizeof...(va) >= 5)
    {
        auto stackVars =
            select_tuple(std::integral_constant<size_t, 4>{}, am, std::make_index_sequence<sizeof...(Args) - 4>());
        auto remapStackVars = [&](int &indx, auto var)
        {
            *(ULONG64 *)((UINT64)new_rsp_hva + 0x28 + (indx * 8)) = *(ULONG64 *)&var;
            indx++;
        };
        std::apply(
            [&](auto &&...xs)
            {
                int indx = 0;
                (remapStackVars(indx, xs), ...);
            },
            stackVars);
    }

    *(PULONG64)new_rsp_hva = get_blank_memory(1);

    vmx_vmwrite(VMCS_GUEST_RSP, newUserRsp);

    vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)ptr);

    ULONG64 unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

    auto vtcallstack_node = add_vtcallstack_node();

    if (!vtcallstack_node)
    {
        vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);
        vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);
        cpu->ctx = node->oldContext_ptr;
        *cpu->ctx = node->oldContext;
        remove_vtcall_node(node);
        return 0;
    }

    vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->stack_ptr);

    vtcallstack_node->old_stack_ptr = unused_host_stack_ptr_temp;

    vtcallstack_node->cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    // Lock guest thread to entry vCPU. callee runs in guest mode where the
    // scheduler can migrate to another vCPU; a RET-induced #BP on a
    // different vCPU drives the cross-vCPU branch below to vmwrite HOST_RSP
    // into the wrong VMCS, corrupting host state and triple-faulting.
    //
    // Writing only Affinity.Mask is insufficient: scheduler also consults
    // UserAffinity / IdealProcessor / UserIdealProcessor when picking a
    // target core (esp. for soft affinity hints). Write all four together
    // for one consistent "pinned to entry vCPU" snapshot.
    node->saved_affinity = 0;
    node->saved_user_affinity = 0;
    node->saved_ideal_processor = 0;
    node->saved_user_ideal_processor = 0;
    if (g_ghv->affinity_lock_enabled && node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        UINT8 _cpu8 = (UINT8)vtcallstack_node->cpu_number;
        UINT64 _mask = (1ULL << vtcallstack_node->cpu_number);

        auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
        node->saved_affinity = *aff_p;
        *aff_p = _mask;

        if (g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            node->saved_user_affinity = *uaff_p;
            *uaff_p = _mask;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            node->saved_ideal_processor = *ip_p;
            *ip_p = _cpu8;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            node->saved_user_ideal_processor = *uip_p;
            *uip_p = _cpu8;
        }
    }

    vt_call_entry((UINT64)(cpu->ctx), (UINT64) & (node->oldVtRsp), (UINT64)cData);

    auto cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    bool is_cross_vcpu = false;

    if (cpu_number == vtcallstack_node->cpu_number)
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_same_vcpu_call);

        unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

        vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->old_stack_ptr);

        remove_vtcallstack_node(vtcallstack_node);
    }
    else
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_cross_vcpu_call);

        // Lazy restore: don't touch VMCS_HOST_RSP or the stack node here 鈥
        // we're physically on the return vCPU but the entry vCPU's VMCS
        // still points at this stack. Defer the handoff until cleanup ends
        // (see mark_vtcall_cross_cpu_return call at the bottom). The
        // remaining cleanup (memcpy, GUEST_RSP/RIP, ctx restore, affinity
        // restore, remove_vtcall_node) all runs on the stack_node's stack
        // and must finish before the entry vCPU is told to reclaim it.
        is_cross_vcpu = true;
    }

    memcpy((PVOID)new_rsp_hva, node->stack, STACK_COPY_SIZE);

    vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);

    vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);

    float retFloat;

    Ret ret = (Ret)(node->newContext_ptr->rax);

    cpu->ctx = node->oldContext_ptr;
    *cpu->ctx = node->oldContext;

    // Restore guest thread affinity captured at hv::Call entry. Window
    // covers callee execution + RET-induced #BP vmexit + vt_call_exit
    // stack-switch + cross-vCPU branch above.
    // No affinity_lock_enabled gate here 鈥 if entry wrote (enable=true)
    // and switch flipped to false mid-call, we MUST still restore or
    // affinity stays pinned forever. saved_affinity=0 acts as natural
    // no-op when entry didn't write.
    if (node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        if (node->saved_affinity)
        {
            auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
            *aff_p = node->saved_affinity;
        }
        if (node->saved_user_affinity && g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            *uaff_p = node->saved_user_affinity;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            *ip_p = node->saved_ideal_processor;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            *uip_p = node->saved_user_ideal_processor;
        }
    }

    remove_vtcall_node(node);

    // Cross-vCPU lazy handoff: B's cleanup is now fully done (memcpy,
    // VMCS guest writes, ctx restore, affinity restore, vtcall_node free
    // all completed above). Stack node is no longer being touched by B,
    // so it's safe to enqueue for entry vCPU A's lazy restore.
    if (is_cross_vcpu)
    {
        mark_vtcall_cross_cpu_return(vtcallstack_node->cpu_number, vtcallstack_node);
    }

    if constexpr (std::is_same<Ret, float>::value)
        return retFloat;

    return (Ret)ret;
}

template <typename Ret = void *, typename ptrType, typename... va> Ret Call2(ptrType ptr, va... Args)
{
    auto cpuid = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;
    auto cpu = &g_ghv->vcpus[cpuid];

    ghv_vtcall_list_node *node = add_vtcall_node();

    if (!node)
        return 0;
    node->oldContext_ptr = cpu->ctx;
    node->oldContext = *cpu->ctx;
    node->oldRip = vmx_vmread(VMCS_GUEST_RIP);
    node->oldRsp = vmx_vmread(VMCS_GUEST_RSP);
    node->process = (UINT64)current_guest_eprocess();
    node->thread = (UINT64)current_guest_ethread();
    node->retRip = get_blank_memory(2);
    node->cpu_number = (int)cpuid;

    ia32_vmx_procbased_ctls_register proc_based_ctrl;
    proc_based_ctrl.flags = 0;
    proc_based_ctrl.cr3_load_exiting = 0;
    proc_based_ctrl.use_msr_bitmaps = 1;
    proc_based_ctrl.activate_secondary_controls = 1;
    write_ctrl_proc_based_safe(proc_based_ctrl);

    auto newUserRsp = 0ULL;

    newUserRsp = ((node->oldRsp - STACK_POS) & ~0b1111ull) - 8;

    auto guest_cr3 = current_guest_cr3();

    auto new_rsp_hva = gva2hva(guest_cr3, (void *)newUserRsp);

    memcpy(node->stack, new_rsp_hva, STACK_COPY_SIZE);

    auto am = std::make_tuple(std::forward<va>(Args)...);

    UINT64 cData[9] = {0};

    auto ret_index = typename make_index_sequence_if<(sizeof...(va) >= 4 ? 4 : sizeof...(va))>::type{};

    auto reg_vars = select_tuple(std::integral_constant<size_t, 0>{}, am, ret_index);
    auto remapRegVars = [&](int &indx, auto var)
    {
        if constexpr (!std::is_same<decltype(var), float>::value)
        {
            if (indx == 0)
            {
                cpu->ctx->rcx = *(ULONG64 *)&var;
            }
            if (indx == 1)
            {
                cpu->ctx->rdx = *(ULONG64 *)&var;
            }
            if (indx == 2)
            {
                cpu->ctx->r8 = *(ULONG64 *)&var;
            }
            if (indx == 3)
            {
                cpu->ctx->r9 = *(ULONG64 *)&var;
            }
        }
        else
        {
            if (indx == 0)
            {
                cData[0] = *(UINT64 *)&var;
            }
            if (indx == 1)
            {
                cData[1] = *(UINT64 *)&var;
            }
            if (indx == 2)
            {
                cData[2] = *(UINT64 *)&var;
            }
            if (indx == 3)
            {
                cData[3] = *(UINT64 *)&var;
            }
        };
        *(ULONG64 *)((UINT64)new_rsp_hva + 0x8 + (indx * 8)) = *(ULONG64 *)&var;
        indx++;
    };

    std::apply(
        [&](auto &&...xs)
        {
            int indx = 0;
            (remapRegVars(indx, xs), ...);
        },
        reg_vars);

    if constexpr (sizeof...(va) >= 5)
    {
        auto stackVars =
            select_tuple(std::integral_constant<size_t, 4>{}, am, std::make_index_sequence<sizeof...(Args) - 4>());
        auto remapStackVars = [&](int &indx, auto var)
        {
            *(ULONG64 *)((UINT64)new_rsp_hva + 0x28 + (indx * 8)) = *(ULONG64 *)&var;
            indx++;
        };
        std::apply(
            [&](auto &&...xs)
            {
                int indx = 0;
                (remapStackVars(indx, xs), ...);
            },
            stackVars);
    }

    *(PULONG64)new_rsp_hva = get_blank_memory(2);

    vmx_vmwrite(VMCS_GUEST_RSP, newUserRsp);

    vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)ptr);

    ULONG64 unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

    auto vtcallstack_node = add_vtcallstack_node();

    if (!vtcallstack_node)
    {
        vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);
        vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);
        cpu->ctx = node->oldContext_ptr;
        *cpu->ctx = node->oldContext;
        remove_vtcall_node(node);
        proc_based_ctrl.flags = 0;
        proc_based_ctrl.use_msr_bitmaps = 1;
        proc_based_ctrl.activate_secondary_controls = 1;
        write_ctrl_proc_based_safe(proc_based_ctrl);
        return 0;
    }

    vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->stack_ptr);

    vtcallstack_node->old_stack_ptr = unused_host_stack_ptr_temp;

    vtcallstack_node->cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    // Lock guest thread to entry vCPU. See Call() for full rationale.
    node->saved_affinity = 0;
    node->saved_user_affinity = 0;
    node->saved_ideal_processor = 0;
    node->saved_user_ideal_processor = 0;
    if (g_ghv->affinity_lock_enabled && node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        UINT8 _cpu8 = (UINT8)vtcallstack_node->cpu_number;
        UINT64 _mask = (1ULL << vtcallstack_node->cpu_number);

        auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
        node->saved_affinity = *aff_p;
        *aff_p = _mask;

        if (g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            node->saved_user_affinity = *uaff_p;
            *uaff_p = _mask;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            node->saved_ideal_processor = *ip_p;
            *ip_p = _cpu8;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            node->saved_user_ideal_processor = *uip_p;
            *uip_p = _cpu8;
        }
    }

    vt_call_entry((UINT64)(cpu->ctx), (UINT64) & (node->oldVtRsp), (UINT64)cData);

    auto cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    bool is_cross_vcpu = false;

    if (cpu_number == vtcallstack_node->cpu_number)
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_same_vcpu_call);

        unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

        vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->old_stack_ptr);

        remove_vtcallstack_node(vtcallstack_node);
    }
    else
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_cross_vcpu_call);

        // Lazy restore: see Call() for full rationale. mark deferred to
        // end of cleanup (after remove_vtcall_node) so B can finish using
        // the stack node before A reclaims it.
        is_cross_vcpu = true;
    }

    memcpy((PVOID)new_rsp_hva, node->stack, STACK_COPY_SIZE);

    vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);

    vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);

    float retFloat;

    Ret ret = (Ret)(node->newContext_ptr->rax);

    cpu->ctx = node->oldContext_ptr;
    *cpu->ctx = node->oldContext;

    // Restore guest thread affinity captured at hv::Call entry. Window
    // covers callee execution + RET-induced #BP vmexit + vt_call_exit
    // stack-switch + cross-vCPU branch above.
    // No affinity_lock_enabled gate here 鈥 if entry wrote (enable=true)
    // and switch flipped to false mid-call, we MUST still restore or
    // affinity stays pinned forever. saved_affinity=0 acts as natural
    // no-op when entry didn't write.
    if (node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        if (node->saved_affinity)
        {
            auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
            *aff_p = node->saved_affinity;
        }
        if (node->saved_user_affinity && g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            *uaff_p = node->saved_user_affinity;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            *ip_p = node->saved_ideal_processor;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            *uip_p = node->saved_user_ideal_processor;
        }
    }

    remove_vtcall_node(node);

    // Cross-vCPU lazy handoff: B's cleanup is now fully done (memcpy,
    // VMCS guest writes, ctx restore, affinity restore, vtcall_node free
    // all completed above). Stack node is no longer being touched by B,
    // so it's safe to enqueue for entry vCPU A's lazy restore.
    if (is_cross_vcpu)
    {
        mark_vtcall_cross_cpu_return(vtcallstack_node->cpu_number, vtcallstack_node);
    }

    proc_based_ctrl.flags = 0;
    // #ifndef NDEBUG
    proc_based_ctrl.cr3_load_exiting = 0;
    // proc_based_ctrl.cr3_store_exiting           = 1;
    // #endif
    proc_based_ctrl.use_msr_bitmaps = 1;
    // proc_based_ctrl.use_tsc_offsetting          = 1;
    proc_based_ctrl.activate_secondary_controls = 1;
    write_ctrl_proc_based_safe(proc_based_ctrl);

    if constexpr (std::is_same<Ret, float>::value)
        return retFloat;

    return (Ret)ret;
}

template <typename Ret = void *, typename ptrType, typename... va> Ret Call3(ptrType ptr, va... Args)
{
    auto cpuid = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;
    auto cpu = &g_ghv->vcpus[cpuid];

    ghv_vtcall_list_node *node = add_vtcall_node();

    if (!node)
        return 0;
    node->oldContext_ptr = cpu->ctx;
    node->oldContext = *cpu->ctx;
    node->oldRip = vmx_vmread(VMCS_GUEST_RIP);
    node->oldRsp = vmx_vmread(VMCS_GUEST_RSP);
    node->process = (UINT64)current_guest_eprocess();
    node->thread = (UINT64)current_guest_ethread();
    node->retRip = get_blank_memory(3);
    node->cpu_number = (int)cpuid;

    ia32_vmx_procbased_ctls_register proc_based_ctrl;

    proc_based_ctrl.flags = 0;
    // #ifndef NDEBUG
    proc_based_ctrl.cr3_load_exiting = 0;
    // proc_based_ctrl.cr3_store_exiting           = 1;
    // #endif
    proc_based_ctrl.use_msr_bitmaps = 1;
    // proc_based_ctrl.use_tsc_offsetting          = 1;
    proc_based_ctrl.activate_secondary_controls = 1;
    write_ctrl_proc_based_safe(proc_based_ctrl);

    auto newUserRsp = 0ULL;

    newUserRsp = ((node->oldRsp - STACK_POS) & ~0b1111ull) - 8;

    auto guest_cr3 = current_guest_cr3();

    auto new_rsp_hva = gva2hva(guest_cr3, (void *)newUserRsp);

    memcpy(node->stack, new_rsp_hva, STACK_COPY_SIZE);

    auto am = std::make_tuple(std::forward<va>(Args)...);

    UINT64 cData[9] = {0};

    auto ret_index = typename make_index_sequence_if<(sizeof...(va) >= 4 ? 4 : sizeof...(va))>::type{};

    auto reg_vars = select_tuple(std::integral_constant<size_t, 0>{}, am, ret_index);
    auto remapRegVars = [&](int &indx, auto var)
    {
        if constexpr (!std::is_same<decltype(var), float>::value)
        {
            if (indx == 0)
            {
                cpu->ctx->rcx = *(ULONG64 *)&var;
            }
            if (indx == 1)
            {
                cpu->ctx->rdx = *(ULONG64 *)&var;
            }

            if (indx == 2)
            {
                cpu->ctx->r8 = *(ULONG64 *)&var;
            }
            if (indx == 3)
            {
                cpu->ctx->r9 = *(ULONG64 *)&var;
            }
        }
        else
        {
            if (indx == 0)
            {
                cData[0] = *(UINT64 *)&var;
            }
            if (indx == 1)
            {
                cData[1] = *(UINT64 *)&var;
            }
            if (indx == 2)
            {
                cData[2] = *(UINT64 *)&var;
            }
            if (indx == 3)
            {
                cData[3] = *(UINT64 *)&var;
            }
        };

        *(ULONG64 *)((UINT64)new_rsp_hva + 0x8 + (indx * 8)) = *(ULONG64 *)&var;
        indx++;
    };

    std::apply(
        [&](auto &&...xs)
        {
            int indx = 0;
            (remapRegVars(indx, xs), ...);
        },
        reg_vars);

    if constexpr (sizeof...(va) >= 5)
    {
        auto stackVars =
            select_tuple(std::integral_constant<size_t, 4>{}, am, std::make_index_sequence<sizeof...(Args) - 4>());
        auto remapStackVars = [&](int &indx, auto var)
        {
            *(ULONG64 *)((UINT64)new_rsp_hva + 0x28 + (indx * 8)) = *(ULONG64 *)&var;
            indx++;
        };
        std::apply(
            [&](auto &&...xs)
            {
                int indx = 0;
                (remapStackVars(indx, xs), ...);
            },
            stackVars);
    }

    *(PULONG64)new_rsp_hva = get_blank_memory(3);

    vmx_vmwrite(VMCS_GUEST_RSP, newUserRsp);

    vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)ptr);

    // ULONG64 unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

    // vmx_vmwrite(VMCS_HOST_RSP, unused_host_stack_ptr_buffer);

    // unused_host_stack_ptr_buffer = unused_host_stack_ptr_temp;

    // vt_call_entry((UINT64)(cpu->ctx), (UINT64) & (node->oldVtRsp), (UINT64)cData);

    // unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

    // vmx_vmwrite(VMCS_HOST_RSP, unused_host_stack_ptr_buffer);

    // unused_host_stack_ptr_buffer = unused_host_stack_ptr_temp;

    ULONG64 unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

    auto vtcallstack_node = add_vtcallstack_node();

    if (!vtcallstack_node)
    {
        vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);
        vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);
        cpu->ctx = node->oldContext_ptr;
        *cpu->ctx = node->oldContext;
        remove_vtcall_node(node);
        proc_based_ctrl.flags = 0;
        proc_based_ctrl.use_msr_bitmaps = 1;
        proc_based_ctrl.activate_secondary_controls = 1;
        write_ctrl_proc_based_safe(proc_based_ctrl);
        return 0;
    }

    vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->stack_ptr);

    vtcallstack_node->old_stack_ptr = unused_host_stack_ptr_temp;

    vtcallstack_node->cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    // Lock guest thread to entry vCPU. callee runs in guest mode where the
    // scheduler can migrate to another vCPU; a RET-induced #BP on a
    // different vCPU drives the cross-vCPU branch below to vmwrite HOST_RSP
    // into the wrong VMCS, corrupting host state and triple-faulting.
    //
    // Writing only Affinity.Mask is insufficient: scheduler also consults
    // UserAffinity / IdealProcessor / UserIdealProcessor when picking a
    // target core (esp. for soft affinity hints). Write all four together
    // for one consistent "pinned to entry vCPU" snapshot.
    node->saved_affinity = 0;
    node->saved_user_affinity = 0;
    node->saved_ideal_processor = 0;
    node->saved_user_ideal_processor = 0;
    if (g_ghv->affinity_lock_enabled && node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        UINT8 _cpu8 = (UINT8)vtcallstack_node->cpu_number;
        UINT64 _mask = (1ULL << vtcallstack_node->cpu_number);

        auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
        node->saved_affinity = *aff_p;
        *aff_p = _mask;

        if (g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            node->saved_user_affinity = *uaff_p;
            *uaff_p = _mask;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            node->saved_ideal_processor = *ip_p;
            *ip_p = _cpu8;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            node->saved_user_ideal_processor = *uip_p;
            *uip_p = _cpu8;
        }
    }

    vt_call_entry((UINT64)(cpu->ctx), (UINT64) & (node->oldVtRsp), (UINT64)cData);

    auto cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    bool is_cross_vcpu = false;

    if (cpu_number == vtcallstack_node->cpu_number)
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_same_vcpu_call);

        unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

        vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->old_stack_ptr);

        remove_vtcallstack_node(vtcallstack_node);
    }
    else
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_cross_vcpu_call);

        // Lazy restore: don't touch VMCS_HOST_RSP or the stack node here 鈥
        // we're physically on the return vCPU but the entry vCPU's VMCS
        // still points at this stack. Defer the handoff until cleanup ends
        // (see mark_vtcall_cross_cpu_return call at the bottom). The
        // remaining cleanup (memcpy, GUEST_RSP/RIP, ctx restore, affinity
        // restore, remove_vtcall_node) all runs on the stack_node's stack
        // and must finish before the entry vCPU is told to reclaim it.
        is_cross_vcpu = true;
    }

    memcpy((PVOID)new_rsp_hva, node->stack, STACK_COPY_SIZE);

    vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);

    vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);

    float retFloat;

    Ret ret = (Ret)(node->newContext_ptr->rax);

    cpu->ctx = node->oldContext_ptr;
    *cpu->ctx = node->oldContext;

    // Restore guest thread affinity captured at hv::Call entry. Window
    // covers callee execution + RET-induced #BP vmexit + vt_call_exit
    // stack-switch + cross-vCPU branch above.
    // No affinity_lock_enabled gate here 鈥 if entry wrote (enable=true)
    // and switch flipped to false mid-call, we MUST still restore or
    // affinity stays pinned forever. saved_affinity=0 acts as natural
    // no-op when entry didn't write.
    if (node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        if (node->saved_affinity)
        {
            auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
            *aff_p = node->saved_affinity;
        }
        if (node->saved_user_affinity && g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            *uaff_p = node->saved_user_affinity;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            *ip_p = node->saved_ideal_processor;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            *uip_p = node->saved_user_ideal_processor;
        }
    }

    remove_vtcall_node(node);

    // Cross-vCPU lazy handoff: B's cleanup is now fully done (memcpy,
    // VMCS guest writes, ctx restore, affinity restore, vtcall_node free
    // all completed above). Stack node is no longer being touched by B,
    // so it's safe to enqueue for entry vCPU A's lazy restore.
    if (is_cross_vcpu)
    {
        mark_vtcall_cross_cpu_return(vtcallstack_node->cpu_number, vtcallstack_node);
    }

    proc_based_ctrl.flags = 0;
    // #ifndef NDEBUG
    proc_based_ctrl.cr3_load_exiting = 0;
    // proc_based_ctrl.cr3_store_exiting           = 1;
    // #endif
    proc_based_ctrl.use_msr_bitmaps = 1;
    // proc_based_ctrl.use_tsc_offsetting          = 1;
    proc_based_ctrl.activate_secondary_controls = 1;
    write_ctrl_proc_based_safe(proc_based_ctrl);

    if constexpr (std::is_same<Ret, float>::value)
        return retFloat;

    return (Ret)ret;
}

template <typename Ret = void *, typename ptrType, typename... va> Ret Call4(ptrType ptr, va... Args)
{
    auto cpuid = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;
    auto cpu = &g_ghv->vcpus[cpuid];

    ghv_vtcall_list_node *node = add_vtcall_node();

    if (!node)
        return 0;
    node->oldContext_ptr = cpu->ctx;
    node->oldContext = *cpu->ctx;
    node->oldRip = vmx_vmread(VMCS_GUEST_RIP);
    node->oldRsp = vmx_vmread(VMCS_GUEST_RSP);
    node->process = (UINT64)current_guest_eprocess();
    node->thread = (UINT64)current_guest_ethread();
    node->retRip = get_blank_memory(4);
    node->cpu_number = (int)cpuid;

    ia32_vmx_procbased_ctls_register proc_based_ctrl;

    proc_based_ctrl.flags = 0;
    // #ifndef NDEBUG
    proc_based_ctrl.cr3_load_exiting = 0;
    // proc_based_ctrl.cr3_store_exiting           = 1;
    // #endif
    proc_based_ctrl.use_msr_bitmaps = 1;
    // proc_based_ctrl.use_tsc_offsetting          = 1;
    proc_based_ctrl.activate_secondary_controls = 1;
    write_ctrl_proc_based_safe(proc_based_ctrl);

    auto newUserRsp = 0ULL;

    newUserRsp = ((node->oldRsp - STACK_POS) & ~0b1111ull) - 8;

    auto guest_cr3 = current_guest_cr3();

    auto new_rsp_hva = gva2hva(guest_cr3, (void *)newUserRsp);

    memcpy(node->stack, new_rsp_hva, STACK_COPY_SIZE);

    auto am = std::make_tuple(std::forward<va>(Args)...);

    UINT64 cData[9] = {0};

    auto ret_index = typename make_index_sequence_if<(sizeof...(va) >= 4 ? 4 : sizeof...(va))>::type{};

    auto reg_vars = select_tuple(std::integral_constant<size_t, 0>{}, am, ret_index);
    auto remapRegVars = [&](int &indx, auto var)
    {
        if constexpr (!std::is_same<decltype(var), float>::value)
        {
            if (indx == 0)
            {
                cpu->ctx->rcx = *(ULONG64 *)&var;
            }
            if (indx == 1)
            {
                cpu->ctx->rdx = *(ULONG64 *)&var;
            }

            if (indx == 2)
            {
                cpu->ctx->r8 = *(ULONG64 *)&var;
            }
            if (indx == 3)
            {
                cpu->ctx->r9 = *(ULONG64 *)&var;
            }
        }
        else
        {
            if (indx == 0)
            {
                cData[0] = *(UINT64 *)&var;
            }
            if (indx == 1)
            {
                cData[1] = *(UINT64 *)&var;
            }
            if (indx == 2)
            {
                cData[2] = *(UINT64 *)&var;
            }
            if (indx == 3)
            {
                cData[3] = *(UINT64 *)&var;
            }
        };

        *(ULONG64 *)((UINT64)new_rsp_hva + 0x8 + (indx * 8)) = *(ULONG64 *)&var;
        indx++;
    };

    std::apply(
        [&](auto &&...xs)
        {
            int indx = 0;
            (remapRegVars(indx, xs), ...);
        },
        reg_vars);

    if constexpr (sizeof...(va) >= 5)
    {
        auto stackVars =
            select_tuple(std::integral_constant<size_t, 4>{}, am, std::make_index_sequence<sizeof...(Args) - 4>());
        auto remapStackVars = [&](int &indx, auto var)
        {
            *(ULONG64 *)((UINT64)new_rsp_hva + 0x28 + (indx * 8)) = *(ULONG64 *)&var;
            indx++;
        };
        std::apply(
            [&](auto &&...xs)
            {
                int indx = 0;
                (remapStackVars(indx, xs), ...);
            },
            stackVars);
    }

    *(PULONG64)new_rsp_hva = get_blank_memory(4);

    vmx_vmwrite(VMCS_GUEST_RSP, newUserRsp);

    vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)ptr);

    /*    ULONG64 unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

        vmx_vmwrite(VMCS_HOST_RSP, unused_host_stack_ptr_decrypt);


        unused_host_stack_ptr_decrypt = unused_host_stack_ptr_temp;



        vt_call_entry((UINT64)(cpu->ctx), (UINT64) & (node->oldVtRsp), (UINT64)cData);


        unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

        vmx_vmwrite(VMCS_HOST_RSP, unused_host_stack_ptr_decrypt);


        unused_host_stack_ptr_decrypt = unused_host_stack_ptr_temp;*/

    ULONG64 unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

    auto vtcallstack_node = add_vtcallstack_node();

    if (!vtcallstack_node)
    {
        vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);
        vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);
        cpu->ctx = node->oldContext_ptr;
        *cpu->ctx = node->oldContext;
        remove_vtcall_node(node);
        proc_based_ctrl.flags = 0;
        proc_based_ctrl.use_msr_bitmaps = 1;
        proc_based_ctrl.activate_secondary_controls = 1;
        write_ctrl_proc_based_safe(proc_based_ctrl);
        return 0;
    }

    vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->stack_ptr);

    vtcallstack_node->old_stack_ptr = unused_host_stack_ptr_temp;

    vtcallstack_node->cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    // Lock guest thread to entry vCPU. callee runs in guest mode where the
    // scheduler can migrate to another vCPU; a RET-induced #BP on a
    // different vCPU drives the cross-vCPU branch below to vmwrite HOST_RSP
    // into the wrong VMCS, corrupting host state and triple-faulting.
    //
    // Writing only Affinity.Mask is insufficient: scheduler also consults
    // UserAffinity / IdealProcessor / UserIdealProcessor when picking a
    // target core (esp. for soft affinity hints). Write all four together
    // for one consistent "pinned to entry vCPU" snapshot.
    node->saved_affinity = 0;
    node->saved_user_affinity = 0;
    node->saved_ideal_processor = 0;
    node->saved_user_ideal_processor = 0;
    if (g_ghv->affinity_lock_enabled && node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        UINT8 _cpu8 = (UINT8)vtcallstack_node->cpu_number;
        UINT64 _mask = (1ULL << vtcallstack_node->cpu_number);

        auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
        node->saved_affinity = *aff_p;
        *aff_p = _mask;

        if (g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            node->saved_user_affinity = *uaff_p;
            *uaff_p = _mask;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            node->saved_ideal_processor = *ip_p;
            *ip_p = _cpu8;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            node->saved_user_ideal_processor = *uip_p;
            *uip_p = _cpu8;
        }
    }

    vt_call_entry((UINT64)(cpu->ctx), (UINT64) & (node->oldVtRsp), (UINT64)cData);

    auto cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    bool is_cross_vcpu = false;

    if (cpu_number == vtcallstack_node->cpu_number)
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_same_vcpu_call);

        unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

        vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->old_stack_ptr);

        remove_vtcallstack_node(vtcallstack_node);
    }
    else
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_cross_vcpu_call);

        // Lazy restore: don't touch VMCS_HOST_RSP or the stack node here 鈥
        // we're physically on the return vCPU but the entry vCPU's VMCS
        // still points at this stack. Defer the handoff until cleanup ends
        // (see mark_vtcall_cross_cpu_return call at the bottom). The
        // remaining cleanup (memcpy, GUEST_RSP/RIP, ctx restore, affinity
        // restore, remove_vtcall_node) all runs on the stack_node's stack
        // and must finish before the entry vCPU is told to reclaim it.
        is_cross_vcpu = true;
    }

    memcpy((PVOID)new_rsp_hva, node->stack, STACK_COPY_SIZE);

    vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);

    vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);

    float retFloat;

    Ret ret = (Ret)(node->newContext_ptr->rax);

    cpu->ctx = node->oldContext_ptr;
    *cpu->ctx = node->oldContext;

    // Restore guest thread affinity captured at hv::Call entry. Window
    // covers callee execution + RET-induced #BP vmexit + vt_call_exit
    // stack-switch + cross-vCPU branch above.
    // No affinity_lock_enabled gate here 鈥 if entry wrote (enable=true)
    // and switch flipped to false mid-call, we MUST still restore or
    // affinity stays pinned forever. saved_affinity=0 acts as natural
    // no-op when entry didn't write.
    if (node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        if (node->saved_affinity)
        {
            auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
            *aff_p = node->saved_affinity;
        }
        if (node->saved_user_affinity && g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            *uaff_p = node->saved_user_affinity;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            *ip_p = node->saved_ideal_processor;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            *uip_p = node->saved_user_ideal_processor;
        }
    }

    remove_vtcall_node(node);

    // Cross-vCPU lazy handoff: B's cleanup is now fully done (memcpy,
    // VMCS guest writes, ctx restore, affinity restore, vtcall_node free
    // all completed above). Stack node is no longer being touched by B,
    // so it's safe to enqueue for entry vCPU A's lazy restore.
    if (is_cross_vcpu)
    {
        mark_vtcall_cross_cpu_return(vtcallstack_node->cpu_number, vtcallstack_node);
    }

    proc_based_ctrl.flags = 0;
    // #ifndef NDEBUG
    proc_based_ctrl.cr3_load_exiting = 0;
    // proc_based_ctrl.cr3_store_exiting           = 1;
    // #endif
    proc_based_ctrl.use_msr_bitmaps = 1;
    // proc_based_ctrl.use_tsc_offsetting          = 1;
    proc_based_ctrl.activate_secondary_controls = 1;
    write_ctrl_proc_based_safe(proc_based_ctrl);

    if constexpr (std::is_same<Ret, float>::value)
        return retFloat;

    return (Ret)ret;
}

// CallK 鈥 kernel-mode hv::Call variant. Identical to Call() except retRip
// is g_ghv->kernel_blank_va (ntoskrnl padding 0xCC) instead of user-mode
// blank. Used when handler in host root mode invokes a kernel function
// (e.g. DbgPrintEx) with guest CPL=0; user-mode blank would trigger SMEP
// on the return path.
template <typename Ret = void *, typename ptrType, typename... va> Ret CallK(ptrType ptr, va... Args)
{
    auto cpuid = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;
    auto cpu = &g_ghv->vcpus[cpuid];

    if (!g_ghv->kernel_blank_va)
        return 0; // setup not done yet

    ghv_vtcall_list_node *node = add_vtcall_node();

    if (!node)
        return 0;
    node->oldContext_ptr = cpu->ctx;
    node->oldContext = *cpu->ctx;
    node->oldRip = vmx_vmread(VMCS_GUEST_RIP);
    node->oldRsp = vmx_vmread(VMCS_GUEST_RSP);
    node->process = (UINT64)current_guest_eprocess();
    node->thread = (UINT64)current_guest_ethread();
    node->retRip = g_ghv->kernel_blank_va;
    node->cpu_number = (int)cpuid;

    auto newUserRsp = 0ULL;
    newUserRsp = ((node->oldRsp - STACK_POS) & ~0b1111ull) - 8;

    auto guest_cr3 = current_guest_cr3();
    auto new_rsp_hva = gva2hva(guest_cr3, (void *)newUserRsp);
    if (!new_rsp_hva)
    {
        remove_vtcall_node(node);
        return 0;
    }

    memcpy(node->stack, new_rsp_hva, STACK_COPY_SIZE);

    auto am = std::make_tuple(std::forward<va>(Args)...);

    UINT64 cData[9] = {0};

    auto ret_index = typename make_index_sequence_if<(sizeof...(va) >= 4 ? 4 : sizeof...(va))>::type{};

    auto reg_vars = select_tuple(std::integral_constant<size_t, 0>{}, am, ret_index);
    auto remapRegVars = [&](int &indx, auto var)
    {
        if constexpr (!std::is_same<decltype(var), float>::value)
        {
            if (indx == 0)
                cpu->ctx->rcx = *(ULONG64 *)&var;
            if (indx == 1)
                cpu->ctx->rdx = *(ULONG64 *)&var;
            if (indx == 2)
                cpu->ctx->r8 = *(ULONG64 *)&var;
            if (indx == 3)
                cpu->ctx->r9 = *(ULONG64 *)&var;
        }
        else
        {
            if (indx == 0)
                cData[0] = *(UINT64 *)&var;
            if (indx == 1)
                cData[1] = *(UINT64 *)&var;
            if (indx == 2)
                cData[2] = *(UINT64 *)&var;
            if (indx == 3)
                cData[3] = *(UINT64 *)&var;
        }
        *(ULONG64 *)((UINT64)new_rsp_hva + 0x8 + (indx * 8)) = *(ULONG64 *)&var;
        indx++;
    };

    std::apply(
        [&](auto &&...xs)
        {
            int indx = 0;
            (remapRegVars(indx, xs), ...);
        },
        reg_vars);

    if constexpr (sizeof...(va) >= 5)
    {
        auto stackVars =
            select_tuple(std::integral_constant<size_t, 4>{}, am, std::make_index_sequence<sizeof...(Args) - 4>());
        auto remapStackVars = [&](int &indx, auto var)
        {
            *(ULONG64 *)((UINT64)new_rsp_hva + 0x28 + (indx * 8)) = *(ULONG64 *)&var;
            indx++;
        };
        std::apply(
            [&](auto &&...xs)
            {
                int indx = 0;
                (remapStackVars(indx, xs), ...);
            },
            stackVars);
    }

    // Push kernel blank as the return address that callee RET will pop.
    *(PULONG64)new_rsp_hva = g_ghv->kernel_blank_va;

    vmx_vmwrite(VMCS_GUEST_RSP, newUserRsp);
    vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)ptr);

    ULONG64 unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);

    auto vtcallstack_node = add_vtcallstack_node();
    if (!vtcallstack_node)
    {
        vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);
        vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);
        cpu->ctx = node->oldContext_ptr;
        *cpu->ctx = node->oldContext;
        remove_vtcall_node(node);
        return 0;
    }

    vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->stack_ptr);
    vtcallstack_node->old_stack_ptr = unused_host_stack_ptr_temp;
    vtcallstack_node->cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;

    // Affinity lock 鈥 same logic as Call().
    node->saved_affinity = 0;
    node->saved_user_affinity = 0;
    node->saved_ideal_processor = 0;
    node->saved_user_ideal_processor = 0;
    if (g_ghv->affinity_lock_enabled && node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        UINT8 _cpu8 = (UINT8)vtcallstack_node->cpu_number;
        UINT64 _mask = (1ULL << vtcallstack_node->cpu_number);

        auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
        node->saved_affinity = *aff_p;
        *aff_p = _mask;
        if (g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            node->saved_user_affinity = *uaff_p;
            *uaff_p = _mask;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            node->saved_ideal_processor = *ip_p;
            *ip_p = _cpu8;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            node->saved_user_ideal_processor = *uip_p;
            *uip_p = _cpu8;
        }
    }

    vt_call_entry((UINT64)(cpu->ctx), (UINT64) & (node->oldVtRsp), (UINT64)cData);

    auto cpu_number = vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER) - 1;
    bool is_cross_vcpu = false;

    if (cpu_number == vtcallstack_node->cpu_number)
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_same_vcpu_call);
        unused_host_stack_ptr_temp = vmx_vmread(VMCS_HOST_RSP);
        vmx_vmwrite(VMCS_HOST_RSP, vtcallstack_node->old_stack_ptr);
        remove_vtcallstack_node(vtcallstack_node);
    }
    else
    {
        _InterlockedIncrement64((volatile LONG64 *)&g_ghv->diag_cross_vcpu_call);
        is_cross_vcpu = true;
    }

    memcpy((PVOID)new_rsp_hva, node->stack, STACK_COPY_SIZE);

    vmx_vmwrite(VMCS_GUEST_RSP, node->oldRsp);
    vmx_vmwrite(VMCS_GUEST_RIP, node->oldRip);

    float retFloat;
    Ret ret = (Ret)(node->newContext_ptr->rax);

    cpu->ctx = node->oldContext_ptr;
    *cpu->ctx = node->oldContext;

    // Affinity restore.
    if (node->thread && g_ghv->kthread_affinity_offset)
    {
        auto _kt = (uint8_t *)node->thread;
        if (node->saved_affinity)
        {
            auto aff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_affinity_offset);
            *aff_p = node->saved_affinity;
        }
        if (node->saved_user_affinity && g_ghv->kthread_user_affinity_offset)
        {
            auto uaff_p = reinterpret_cast<volatile uint64_t *>(_kt + g_ghv->kthread_user_affinity_offset);
            *uaff_p = node->saved_user_affinity;
        }
        if (g_ghv->kthread_ideal_processor_offset)
        {
            auto ip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_ideal_processor_offset);
            *ip_p = node->saved_ideal_processor;
        }
        if (g_ghv->kthread_user_ideal_processor_offset)
        {
            auto uip_p = reinterpret_cast<volatile uint8_t *>(_kt + g_ghv->kthread_user_ideal_processor_offset);
            *uip_p = node->saved_user_ideal_processor;
        }
    }

    remove_vtcall_node(node);

    if (is_cross_vcpu)
    {
        mark_vtcall_cross_cpu_return(vtcallstack_node->cpu_number, vtcallstack_node);
    }

    if constexpr (std::is_same<Ret, float>::value)
        return retFloat;
    return (Ret)ret;
}

extern spin_lock handler6_spin;

bool get_cache_info(void *cache_base_ptr, void *cache_size_ptr);

bool hide_page(vcpu *cpu, uint64_t pfn);

bool unhide_page(vcpu *cpu, uint64_t pfn);

bool return_old_func(vcpu *cpu);

bool call_user_func(vcpu *cpu, UINT64 blank_memory, UINT64 rip);

void game_add_vmcall_hook(vcpu *cpu);

void game_remove_vmcall_hook(vcpu *cpu);

void game_enable_vmcall_hook(vcpu *cpu);

void game_disable_vmcall_hook(vcpu *cpu);

void handle_nt_create_section(vcpu *cpu);

bool vmcall_hook_dispatch(vcpu *cpu);

bool is_vmcall_blank_rip(ULONG64 rip);

} // namespace hv
