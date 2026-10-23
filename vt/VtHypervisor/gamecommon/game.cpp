#include <fltKernel.h>
#include "game.h"
#include "vt/hv.h"
#include "vt/mm.h"
#include "vt/exception-routines.h"
#include "string"
#include "vt/ept.h"
#include "vt/introspection.h"
#include "../common/ntutils.h"
#include "dx.h"
#include <gamecommon/draw.h>
#include <sjz/sjz.h>
#include <render/render.h>
#include "sjz/sjz_sdk.h"
#include "gamecommon.h"
#include "../dwm/kerneldwm.h"
#include "../vt/vtcall-hook.h"
#include "../mouse/mouse.h"
#include <poolmanager/PoolManager.h>


// 嵌入构建只提供旧映像启动载体；PMO 绘制与游戏业务由 ResidentPayload 接管。
// 独立 Hypervisor 构建仍保留旧 PMO 主体和渲染 tick，二者属于真实构建差异。
#ifndef YVT_PAYLOAD_EMBED_BUILD
#define YVT_PAYLOAD_EMBED_BUILD 0
#endif

// 使用正向业务宏表达能力归属，不再通过测试阶段宏裁剪执行流程。
#if YVT_PAYLOAD_EMBED_BUILD
#define YVT_LEGACY_PMO_BODY_ENABLED 0
#define YVT_LEGACY_RENDER_TICK_ENABLED 0
#else
#define YVT_LEGACY_PMO_BODY_ENABLED 1
#define YVT_LEGACY_RENDER_TICK_ENABLED 1
#endif


float roundf(float value) {
    return (value >= 0.0f) ? floorf(value + 0.5f) : ceilf(value - 0.5f);
}


PVOID buffer0;
PVOID buffer1;
PVOID buffer2;
PVOID buffer0_hva;
PVOID buffer1_hva;
PVOID buffer2_hva;

namespace hv {

    UINT64 gamevt_image_base = 0;
    UINT64 gamevt_driver_unload = 0;

    UINT64 gameD3d11base = 0;

    UINT64 gameRetCallMemory = 0;

    UINT64 count;

    alignas(0x1000) vt_hook_slot g_static_vt_hook_table[VMCALL_HOOK_MAX] = {};
    vt_hook_slot* g_vt_hook_table = g_static_vt_hook_table;
    static vt_handler_fn g_handler_table[VMCALL_HOOK_MAX + 1] = {};

    void register_vt_handler(UINT type, vt_handler_fn fn) {
        if (type <= VMCALL_HOOK_MAX) g_handler_table[type] = fn;
    }

    // get_blank_memory: returns the single shared user-mode blank_memory used
    // by every hv::Call type. blank_memory is just an ntdll padding 0xCC
    // address 鈥 callee RET jumps there 鈫 #BP vmexit 鈫 return_old_func uses
    // (process, thread, retRip) tuple to find the vtcall_node, so a shared
    // blank works for all hv::Call types. Caller passes type only for legacy
    // signature compatibility; the lookup is type-agnostic.
    ULONG64 get_blank_memory(UINT /*type*/) {
        for (int i = 0; i < VMCALL_HOOK_MAX; i++)
            if (g_vt_hook_table[i].occupied && g_vt_hook_table[i].data.blankMemory)
                return g_vt_hook_table[i].data.blankMemory;
        return 0;
    }



    bool isFirst = true;


    
#pragma code_seg(".vm")

    bool hide_page(vcpu* cpu,uint64_t pfn)
    {

        void* pte = nullptr;
       
            pte = get_ept_pte(cpu->ept, pfn << 12, true);

            if(!pte)
               pte = get_ept_pde(cpu->ept, pfn << 12);

            

            // this can occur if we failed to split the PDE
            if (!pte) {

                cpu->ctx->rax = 0;

                return false;
            }

            ((ept_pte*)pte)->page_frame_number = cpu->ept.dummy_page_pfn;
           

            cpu->ctx->rax = 1;



            return true;
    }

    bool unhide_page(vcpu* cpu, uint64_t pfn)
    {

        void* pte = nullptr;
            pte = get_ept_pte(cpu->ept, pfn << 12, true);

            if(!pte)
               pte = get_ept_pde(cpu->ept, pfn << 12);

            // this can occur if we failed to split the PDE
            if (!pte) {
            cpu->ctx->rax = 0;
          
            return false;
        }

        ((ept_pte*)pte)->page_frame_number = pfn;
       

        cpu->ctx->rax = 1;


        return true;



    }





    PETHREAD current_guest_ethread() {
        // KPCR
        auto const kpcr = current_guest_kpcr();

        if (!kpcr)
            return nullptr;

        // KPCR::Prcb
        auto const kprcb = reinterpret_cast<uint8_t*>(kpcr)
            + g_ghv->kpcr_pcrb_offset;

        // KPCRB::CurrentThread
        PETHREAD current_thread = nullptr;
        read_guest_virtual_memory(g_ghv->system_cr3,
            kprcb + g_ghv->kprcb_current_thread_offset, &current_thread, sizeof(current_thread));

        return current_thread;
    }

    // get the EPROCESS of the current guest
    PEPROCESS current_guest_eprocess() {
        // ETHREAD (KTHREAD is first field as well)
        auto const ethread = current_guest_ethread();

        if (!ethread)
            return nullptr;

        // KTHREAD::ApcState
        auto const kapc_state = reinterpret_cast<uint8_t*>(ethread)
            + g_ghv->kthread_apc_state_offset;

        // KAPC_STATE::Process
        PEPROCESS process = nullptr;
        read_guest_virtual_memory(g_ghv->system_cr3,
            kapc_state + g_ghv->kapc_state_process_offset, &process, sizeof(process));

        return process;
    }

    bool return_old_func(vcpu* cpu) {

        // INT3 vmexit: VMCS GUEST_RIP points AT the 0xCC byte (not past it).
        // node->retRip also stores blank_memory itself, so match directly 鈥 no offset.
        // Per dwm/2 dump: diag_bp_last_rip = 0x7ffc025f2198 = blank_memory exactly.
        auto rip = vmx_vmread(VMCS_GUEST_RIP);
        g_ghv->diag_bp_last_retrip = rip;

        // KEY: match by (process, thread, retRip), NOT cpu_number 鈥 guest
        // thread can be rescheduled onto a different vCPU between hv::Call
        // entry and its vmcall return. With cpu_number key, the second
        // vCPU returns false here, dispatch falls through to vmcall_hook_dispatch
        // which doesn't know about this retRip 鈫 infinite vmcall / DWM hang
        // on physical multi-core systems.
        auto node = find_vtcall_node(
            (UINT64)current_guest_eprocess(),
            (UINT64)current_guest_ethread(),
            rip);
        if(!node)
			return false;

        node->newContext_ptr = cpu->ctx;

        // No invept here: the EPT has not been modified on the return path.
        // The previous unconditional invept_all_context was a 5x perf killer
        // under VMware nested VT-x 鈥 every hv::Call triggered a global EPT
        // flush, and 5 keys polled per frame at 60Hz = ~300 Hz invept storm.

        vt_call_exit((UINT64)cpu->ctx, (UINT64)node->oldVtRsp);

        return true;
    }




    bool call_user_func(vcpu* cpu,UINT64 blank_memory,UINT64 new_rip)
    {


        char* buf = (char*)_XOR_("\x0f\x01\xc1");

        auto fake_memory = gva2hva((PVOID)get_blank_memory(1));

        memcpy((VOID*)fake_memory, buf, 3);
        
        auto guest_cr3 = current_guest_cr3();

     
        UINT64 a = (UINT64)Call(MessageBeep,(UINT64)2);

        skip_instruction();

       return false;
    }


    void game_add_vmcall_hook(vcpu* cpu) {
        auto data_hva = (VMCALLHookData*)gva2hva((VMCALLHookData*)cpu->ctx->rcx);
        for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
            if (!g_vt_hook_table[i].occupied) {
                g_vt_hook_table[i].data         = *data_hva;
                g_vt_hook_table[i].data.isEnable = false;
                g_vt_hook_table[i].fake_mem_hva  = nullptr;
                g_vt_hook_table[i].trampoline_va = 0;
                g_vt_hook_table[i].bp_rip        = 0;
                g_vt_hook_table[i].target_resume = 0;
                g_vt_hook_table[i].occupied      = true;
                break;
            }
        }
    }

    void game_remove_vmcall_hook(vcpu* cpu) {
        auto data_hva = (VMCALLHookData*)gva2hva((VMCALLHookData*)cpu->ctx->rcx);
        for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
            auto& slot = g_vt_hook_table[i];
            if (slot.occupied && slot.data.type == data_hva->type) {
                slot.occupied     = false;
                slot.data         = {};
                slot.fake_mem_hva = nullptr;
                slot.trampoline_va = 0;
                slot.bp_rip        = 0;
                slot.target_resume = 0;
                break;
            }
        }
    }

    void game_enable_vmcall_hook(vcpu* cpu) {
        auto data_hva = (VMCALLHookData*)gva2hva((VMCALLHookData*)cpu->ctx->rcx);
        for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
            auto& slot = g_vt_hook_table[i];
            if (slot.occupied && slot.data.type == data_hva->type) {
                slot.data.isEnable = true;
                auto hva0 = gva2hva((PVOID)slot.data.fakeMemoryAddress);
                slot.fake_mem_hva = hva0;
                if (hva0) {
                    memcpy(hva0, _XOR_("\x0f\x01\xc1"), 3);
                    __invlpg(hva0);
                }
                if (slot.data.type == 6) handler6_spin.initialize();
                break;
            }
        }
    }

    void game_disable_vmcall_hook(vcpu* cpu) {
        auto data_hva = (VMCALLHookData*)gva2hva((VMCALLHookData*)cpu->ctx->rcx);
        for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
            auto& slot = g_vt_hook_table[i];
            if (slot.occupied && slot.data.type == data_hva->type) {
                slot.data.isEnable = false;
                if (slot.fake_mem_hva)
                    memcpy(slot.fake_mem_hva, slot.data.oldByte, 3);
                break;
            }
        }
    }


  

    // type 1 鈥 DXGI PresentMultiplaneOverlay (per-frame composition entry).
    // First hit captures the swapchain pointer into hv::swapChain and calls init().
    void handle_present_multiplane_overlay(vcpu* cpu) {

        g_ghv->diag_handler_count++;

#if !YVT_LEGACY_PMO_BODY_ENABLED
        return;
#endif

        if ( (!hv::swapChain || !isFinish))
        {

            swapChain = (PVOID)cpu->ctx->rcx;
            init(cpu);
        }

#if !YVT_LEGACY_RENDER_TICK_ENABLED
        return;
#endif

        if (isFinish) {


            tick(cpu);

            return;

            // sjz phase-1 validation runs directly on the PMO hook path.
            // Keep it read-only + throttled inside sjz::PmoValidateTick().
            // Do not arm coord EPT probes from this generic DWM PMO path:
            // PMO fires as soon as the driver/DWM hook is alive, before the
            // game PID/CR3/world chain is validated. Probe arming must be
            // reintroduced only from an explicit game-ready path.

            // Stage 鈶: install DWM swap chain hooks from PMO handler instead
            // of from driver-side InstallDwmHook. DISABLED 鈥 first verify that
            // the in-handler install mechanism itself doesn't break anything
            // by adding NO new hooks. Re-enable once driver-only build is
            // confirmed stable.

            // ----------------------------------------------------------------
            // Anti-screenshot kernel hooks. Disabled 2026-05-25 鈥 handing off
            // to next phase. Re-enable by removing the `#if 0` below; symbol
            // resolution, handler bodies, ghv counters, and HUD line are all
            // kept so flipping back to live is single-edit. Default install
            // uses dwm + filter_by_process=true (DWM-only). To verify a hook
            // dispatches at all, temporarily switch to nullptr + filter=false.
            //
            // - NtSetEvent     (type 14, baseline kernel-hook stress)
            // - NtAllocateVirtualMemory  (type 15, DWM RWX alloc detector)
            // - NtProtectVirtualMemory   (type 16, DWM RW鈫扲X detector)
            // - NtMapViewOfSection       (type 17, DWM manual-mapper detector)
            // - NtCreateSection          (type 6,  DWM DLL-load name match)
            // ----------------------------------------------------------------

            #if YVT_MOUSE_HOOK_ENABLED
            // ------------------------------------------------------------------
            // Mouse adjustment: hook the original MouClass service callback and
            // edit only live movement packets in-place. No synthetic packet path,
            // no object replacement, and no process filter (mouse callback often
            // runs outside DWM's process context).
            // ------------------------------------------------------------------
            if (!g_ghv->mouse_callback_hook_installed &&
                mouse::mouse_obj.service_callback &&
                g_ghv->tramp_pool.kernel_ready) {
                g_ghv->mouse_callback_install_attempted = 1;
                auto target = (uint64_t)mouse::mouse_obj.service_callback;
                g_ghv->diag_mouse_cb_target_va = target;
                bool ok = hv::vh_install_host_deferred(cpu, nullptr, target,
                    /*blank_mem*/ 0, /*type*/ 22, VMCALL_DISPATCH_NORMAL,
                    /*filter_by_process*/ false, /*auto_enable*/ true);
                g_ghv->mouse_callback_install_result = ok ? 1 : 0;
                if (ok)
                    _InterlockedExchange8((volatile char*)&g_ghv->mouse_callback_hook_installed, 1);
            }

            // MouHid_ReadComplete pre-call probe.
            //
            // Observed MouClass caller return:
            //   mouhid.sys + 0x3AA8
            //
            // Disassembly around that address:
            //   mouhid+0x3A97  mov rax, [rdi+0E8h]       ; ClassService
            //   mouhid+0x3A9E  lea r9,  [rbp-14h]        ; InputDataConsumed
            //   mouhid+0x3AA2  call qword ptr [rip+...]  ; CFG dispatch to rax
            //   mouhid+0x3AA8  ...                       ; return address
            //
            // Hook the call instruction, not the return address, so this
            // handler sees the packet before MouClassServiceCallback runs.
            if (!g_ghv->mouhid_pre_hook_installed &&
                mouse::mouse_obj.hid_driver_base &&
                g_ghv->tramp_pool.kernel_ready) {
                g_ghv->mouhid_pre_install_attempted = 1;
                g_ghv->diag_mouhid_base_va = (uint64_t)mouse::mouse_obj.hid_driver_base;
                g_ghv->diag_mouhid_size = (uint64_t)mouse::mouse_obj.hid_driver_size;

                auto target = (uint64_t)mouse::mouse_obj.hid_driver_base + 0x3AA2;
                g_ghv->diag_mouhid_pre_target_va = target;

                bool sig_ok = false;
                auto target_hva = (uint8_t*)gva2hva((PVOID)target);
                if (target_hva) {
                    // Expected bytes at mouhid.sys RVA 0x3AA2:
                    //   FF 15 58 57 00 00
                    sig_ok = target_hva[0] == 0xFF &&
                             target_hva[1] == 0x15 &&
                             target_hva[2] == 0x58 &&
                             target_hva[3] == 0x57 &&
                             target_hva[4] == 0x00 &&
                             target_hva[5] == 0x00;
                }
                g_ghv->mouhid_pre_signature_ok = sig_ok ? 1 : 0;

                if (sig_ok) {
                    bool ok = hv::vh_install_host_deferred(cpu, nullptr, target,
                        /*blank_mem*/ 0, /*type*/ 23, VMCALL_DISPATCH_NORMAL,
                        /*filter_by_process*/ false, /*auto_enable*/ true);
                    g_ghv->mouhid_pre_install_result = ok ? 1 : 0;
                    if (ok)
                        _InterlockedExchange8((volatile char*)&g_ghv->mouhid_pre_hook_installed, 1);
                }
            }

            // MouHid_StartRead lower-stack send probe.
            // 22H2 mouhid.sys RVA 0x3CB2:
            //   48 FF 15 E7 54 00 00    call cs:IofCallDriver
            // At the call site RCX is the lower HID DeviceObject.
            if (!g_ghv->mouhid_down_hook_installed &&
                mouse::mouse_obj.hid_driver_base &&
                g_ghv->tramp_pool.kernel_ready) {
                g_ghv->mouhid_down_install_attempted = 1;

                auto target = (uint64_t)mouse::mouse_obj.hid_driver_base + 0x3CB2;
                g_ghv->diag_mouhid_down_target_va = target;

                bool sig_ok = false;
                auto target_hva = (uint8_t*)gva2hva((PVOID)target);
                if (target_hva) {
                    sig_ok = target_hva[0] == 0x48 &&
                             target_hva[1] == 0xFF &&
                             target_hva[2] == 0x15 &&
                             target_hva[3] == 0xE7 &&
                             target_hva[4] == 0x54 &&
                             target_hva[5] == 0x00 &&
                             target_hva[6] == 0x00;
                }
                g_ghv->mouhid_down_signature_ok = sig_ok ? 1 : 0;

                if (sig_ok) {
                    bool ok = hv::vh_install_host_deferred(cpu, nullptr, target,
                        /*blank_mem*/ 0, /*type*/ 24, VMCALL_DISPATCH_NORMAL,
                        /*filter_by_process*/ false, /*auto_enable*/ true);
                    g_ghv->mouhid_down_install_result = ok ? 1 : 0;
                    if (ok)
                        _InterlockedExchange8((volatile char*)&g_ghv->mouhid_down_hook_installed, 1);
                }
            }

            // HidUsb lower USB stack send probe.
            // 22H2 hidusb.sys RVA 0x1485:
            //   48 FF 15 FC 9B 00 00    call cs:IofCallDriver
            // At the call site RCX is the lower USB DeviceObject.
            if (!g_ghv->hidusb_down_hook_installed &&
                mouse::mouse_obj.hidusb_driver_base &&
                g_ghv->tramp_pool.kernel_ready) {
                g_ghv->hidusb_down_install_attempted = 1;
                g_ghv->diag_hidusb_base_va = (uint64_t)mouse::mouse_obj.hidusb_driver_base;
                g_ghv->diag_hidusb_size = (uint64_t)mouse::mouse_obj.hidusb_driver_size;

                auto target = (uint64_t)mouse::mouse_obj.hidusb_driver_base + 0x1485;
                g_ghv->diag_hidusb_down_target_va = target;

                bool sig_ok = false;
                auto target_hva = (uint8_t*)gva2hva((PVOID)target);
                if (target_hva) {
                    sig_ok = target_hva[0] == 0x48 &&
                             target_hva[1] == 0xFF &&
                             target_hva[2] == 0x15 &&
                             target_hva[3] == 0xFC &&
                             target_hva[4] == 0x9B &&
                             target_hva[5] == 0x00 &&
                             target_hva[6] == 0x00;
                }
                g_ghv->hidusb_down_signature_ok = sig_ok ? 1 : 0;

                if (sig_ok) {
                    bool ok = hv::vh_install_host_deferred(cpu, nullptr, target,
                        /*blank_mem*/ 0, /*type*/ 25, VMCALL_DISPATCH_NORMAL,
                        /*filter_by_process*/ false, /*auto_enable*/ true);
                    g_ghv->hidusb_down_install_result = ok ? 1 : 0;
                    if (ok)
                        _InterlockedExchange8((volatile char*)&g_ghv->hidusb_down_hook_installed, 1);
                }
            }

            // HidUsb HumReadCompletion entry probe.
            // 22H2 hidusb.sys RVA 0x2D60 prologue starts with:
            //   48 89 5C 24 10 48 89 6C ...
            // Read-only: capture status/buffer/len/first8 before the normal
            // completion routine continues.
            if (!g_ghv->hidusb_comp_hook_installed &&
                mouse::mouse_obj.hidusb_driver_base &&
                g_ghv->tramp_pool.kernel_ready) {
                g_ghv->hidusb_comp_install_attempted = 1;
                g_ghv->diag_hidusb_base_va = (uint64_t)mouse::mouse_obj.hidusb_driver_base;
                g_ghv->diag_hidusb_size = (uint64_t)mouse::mouse_obj.hidusb_driver_size;

                auto target = (uint64_t)mouse::mouse_obj.hidusb_driver_base + 0x2D60;
                g_ghv->diag_hidusb_comp_target_va = target;

                bool sig_ok = false;
                auto target_hva = (uint8_t*)gva2hva((PVOID)target);
                if (target_hva) {
                    sig_ok = target_hva[0] == 0x48 &&
                             target_hva[1] == 0x89 &&
                             target_hva[2] == 0x5C &&
                             target_hva[3] == 0x24 &&
                             target_hva[4] == 0x10 &&
                             target_hva[5] == 0x48 &&
                             target_hva[6] == 0x89 &&
                             target_hva[7] == 0x6C;
                }
                g_ghv->hidusb_comp_signature_ok = sig_ok ? 1 : 0;

                if (sig_ok) {
                    bool ok = hv::vh_install_host_deferred(cpu, nullptr, target,
                        /*blank_mem*/ 0, /*type*/ 26, VMCALL_DISPATCH_NORMAL,
                        /*filter_by_process*/ false, /*auto_enable*/ true);
                    g_ghv->hidusb_comp_install_result = ok ? 1 : 0;
                    if (ok)
                        _InterlockedExchange8((volatile char*)&g_ghv->hidusb_comp_hook_installed, 1);
                }
            }
            #endif

            // ------------------------------------------------------------------
            // Stage 5: install Mm* memory-hide kernel hooks from PMO handler.
            // PMO is the first hook to fire, and by that point kernel_ready=1
            // and prot_ranges is populated by prepare_self_hide_commit. Each
            // Mm* hook checks the probe target against prot_ranges and bails
            // when it overlaps testDriver image / pool. process=nullptr +
            // filter_by_process=false 鈫 fires for every caller process.
            // ------------------------------------------------------------------

            // Stage 鈶-from-handler: install IDXGISwapChain::GetBuffer hook.
            // Target VA is swapChain->vtable[9] in DWM user space.
            //
            // Stale-PFN defense: dwmcore .text is hot but NOT pinned. A page
            // out + page in cycle would assign a NEW PFN to the same VA,
            // leaving our EPT entry pointing at the OLD GPA -> hook becomes
            // silently inert. Sequence:
            //   1) ReadProcessMemory(va, 1)  - forces the page to be present
            //      (resolves any prefetch-pruned PTE before VirtualLock).
            //   2) VirtualLock(va & ~0xFFF, 0x2000) - pins the page (and the
            // GetBuffer install in PMO handler. Each user-mode hook gets its
            // own separate trampoline page (bootstrap_tramp_pool ensures the
            // pool has 2 slots on 2 different pages with 鈮 0x2000 stride).
            // PMO uses page 0; GetBuffer uses page 1 鈥 no shared-page byte
            // interference between the two hooks.
            //
            // Cross-vCPU EPT race mitigations now in place (install_ept_hook
            // idempotency, tramp slot cross-page rejection, drain queue slot
            // recycling) 鈥 re-enabled.
        }

    }

    // type 2 鈥 MiReadWriteVirtualMemory hook landing point.
    // Currently used to kick off mouse-move input from DWM context.
    void handle_mi_rw_virtual_memory(vcpu* cpu) {
        if (g_yvt.dwm != hv::current_guest_eprocess()) return;
        sjz::StartMoveMouse();
    }

    static bool diag_read_kernel_va(uint64_t va, void* out, size_t size) {
        if (!va || !out || !size)
            return false;
        RtlZeroMemory(out, size);
        return read_guest_virtual_memory(g_ghv->system_cr3, (void*)va, out, size) == size;
    }

    static wchar_t diag_lower_wchar(wchar_t ch) {
        if (ch >= L'A' && ch <= L'Z')
            return (wchar_t)(ch + (L'a' - L'A'));
        return ch;
    }

    static bool diag_wide_eq_ci(const wchar_t* s, uint32_t chars, const wchar_t* lit) {
        if (!s || !lit)
            return false;
        uint32_t lit_chars = 0;
        while (lit[lit_chars])
            lit_chars++;
        if (chars != lit_chars)
            return false;
        for (uint32_t i = 0; i < chars; i++) {
            if (diag_lower_wchar(s[i]) != diag_lower_wchar(lit[i]))
                return false;
        }
        return true;
    }

    static uint64_t diag_hash_driver_name_ci(const wchar_t* s, uint32_t chars) {
        uint64_t h = 1469598103934665603ull; // FNV-1a 64
        for (uint32_t i = 0; i < chars; i++) {
            auto ch = (uint16_t)diag_lower_wchar(s[i]);
            h ^= (uint8_t)(ch & 0xff);
            h *= 1099511628211ull;
            h ^= (uint8_t)((ch >> 8) & 0xff);
            h *= 1099511628211ull;
        }
        return h;
    }

    static uint64_t diag_known_driver_code(const wchar_t* name, uint32_t chars, uint64_t driver_base) {
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\MouClass")) return 1;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\MouHID")) return 2;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\HidClass")) return 3;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\HidUsb")) return 4;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\usbccgp")) return 5;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\USBHUB3")) return 6;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\USBXHCI")) return 7;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\ACPI")) return 8;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\Wdf01000")) return 9;
        if (diag_wide_eq_ci(name, chars, L"\\Driver\\HidBth")) return 10;

        // Fallback for cases where DriverName could not be read but the image
        // base matches one of the driver objects resolved during init.
        if (driver_base && mouse::mouse_obj.hid_driver_base &&
            driver_base == (uint64_t)mouse::mouse_obj.hid_driver_base) return 2;
        if (driver_base && mouse::mouse_obj.hidclass_driver_base &&
            driver_base == (uint64_t)mouse::mouse_obj.hidclass_driver_base) return 3;
        if (driver_base && mouse::mouse_obj.hidusb_driver_base &&
            driver_base == (uint64_t)mouse::mouse_obj.hidusb_driver_base) return 4;
        return 0;
    }

    static void diag_capture_lower_device(
        uint64_t lower_device,
        volatile uint64_t& out_device,
        volatile uint64_t& out_driver,
        volatile uint64_t& out_base,
        volatile uint64_t& out_size,
        volatile uint64_t& out_name_hash,
        volatile uint64_t& out_known_code)
    {
        out_device = lower_device;
        out_driver = 0;
        out_base = 0;
        out_size = 0;
        out_name_hash = 0;
        out_known_code = 0;

        if (!lower_device)
            return;

        PDRIVER_OBJECT driver_obj = nullptr;
        if (!diag_read_kernel_va(lower_device + FIELD_OFFSET(DEVICE_OBJECT, DriverObject),
            &driver_obj, sizeof(driver_obj)) || !driver_obj)
            return;

        out_driver = (uint64_t)driver_obj;

        PVOID driver_start = nullptr;
        ULONG driver_size = 0;
        UNICODE_STRING driver_name = {};

        diag_read_kernel_va((uint64_t)driver_obj + FIELD_OFFSET(DRIVER_OBJECT, DriverStart),
            &driver_start, sizeof(driver_start));
        diag_read_kernel_va((uint64_t)driver_obj + FIELD_OFFSET(DRIVER_OBJECT, DriverSize),
            &driver_size, sizeof(driver_size));
        diag_read_kernel_va((uint64_t)driver_obj + FIELD_OFFSET(DRIVER_OBJECT, DriverName),
            &driver_name, sizeof(driver_name));

        out_base = (uint64_t)driver_start;
        out_size = (uint64_t)driver_size;

        wchar_t name_buf[64] = {};
        uint32_t name_chars = 0;
        if (driver_name.Buffer && driver_name.Length >= sizeof(wchar_t)) {
            auto name_bytes = (uint32_t)driver_name.Length;
            if (name_bytes > sizeof(name_buf) - sizeof(wchar_t))
                name_bytes = sizeof(name_buf) - sizeof(wchar_t);
            auto got = read_guest_virtual_memory(g_ghv->system_cr3,
                (void*)driver_name.Buffer, name_buf, name_bytes);
            name_chars = (uint32_t)(got / sizeof(wchar_t));
            if (name_chars) {
                out_name_hash = diag_hash_driver_name_ci(name_buf, name_chars);
            }
        }

        out_known_code = diag_known_driver_code(name_buf, name_chars, (uint64_t)driver_start);
    }

    // The mouhid/hidusb callsite probes are placed on RIP-relative
    // indirect call instructions such as:
    //   FF 15 xx xx xx xx       call qword ptr [rip+disp32]
    //   48 FF 15 xx xx xx xx    call qword ptr [rip+disp32]
    // The generic trampoline copies original bytes to a ntoskrnl padding
    // page. That is unsafe for RIP-relative instructions because the copied
    // instruction would resolve [rip+disp32] relative to the trampoline page,
    // not the original module. So these handlers emulate the call: push the
    // return address to the guest stack, then set GUEST_RIP to the real target.
    static bool diag_emulate_rip_indirect_call(vcpu* cpu,
        uint64_t call_site,
        uint8_t instr_len,
        uint8_t disp_offset)
    {
        if (!cpu || !call_site || instr_len < disp_offset + sizeof(int32_t))
            return false;

        int32_t disp = 0;
        if (!diag_read_kernel_va(call_site + disp_offset, &disp, sizeof(disp)))
            return false;

        uint64_t target_ptr_va = call_site + instr_len + (int64_t)disp;
        uint64_t call_target = 0;
        if (!diag_read_kernel_va(target_ptr_va, &call_target, sizeof(call_target)) || !call_target)
            return false;

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        if (!rsp || rsp < sizeof(uint64_t))
            return false;

        auto new_rsp = rsp - sizeof(uint64_t);
        auto ret_hva = (uint64_t*)gva2hva((PVOID)new_rsp);
        if (!ret_hva)
            ret_hva = (uint64_t*)gva2hva(g_ghv->system_cr3, (PVOID)new_rsp);
        if (!ret_hva)
            return false;

        *ret_hva = call_site + instr_len;
        vmx_vmwrite(VMCS_GUEST_RSP, new_rsp);
        vmx_vmwrite(VMCS_GUEST_RIP, call_target);
        return true;
    }

    // type 22 鈥 original MouClass service callback.
    //
    // Observation-only handler. Runs before the real MouseClassServiceCallback
    // body, records the arguments/first movement packet, then lets the
    // dispatcher trampoline fall through to the original callback unchanged.
    void handle_mouse_class_service_callback(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_hits);

        auto device = (PDEVICE_OBJECT)cpu->ctx->rcx;
        auto start_va = (uint64_t)cpu->ctx->rdx;
        auto end_va = (uint64_t)cpu->ctx->r8;

        uint64_t expected_device = (uint64_t)mouse::mouse_obj.mouse_device;
        g_ghv->diag_mouse_cb_last_device = (uint64_t)device;
        g_ghv->diag_mouse_cb_expected_device = expected_device;
        g_ghv->diag_mouse_cb_last_start = start_va;
        g_ghv->diag_mouse_cb_last_end = end_va;

        // At the real MouClassServiceCallback entry, [RSP] is the caller's
        // return address. This tells us which MouHID/HID path called into the
        // class callback, and is the anchor for moving the hook earlier if
        // needed.
        auto guest_rsp = vmx_vmread(VMCS_GUEST_RSP);
        if (guest_rsp) {
            auto ret_hva = (uint64_t*)gva2hva((PVOID)guest_rsp);
            if (ret_hva)
                g_ghv->diag_mouse_cb_return_va = *ret_hva;
        }

        // Do not early-return on device mismatch here. On some stacks
        // MouClassServiceCallback is hit through a different class device than
        // the one discovered from the MouHID extension walk, and filtering it
        // out makes the hook look "alive" while raw movement stops updating.
        if (expected_device && (uint64_t)device != expected_device)
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_device_mismatch);

        if (!start_va || !end_va || end_va <= start_va) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_bad_args);
            return;
        }

        auto bytes = end_va - start_va;
        if ((bytes % sizeof(MOUSE_INPUT_DATA)) != 0) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_bad_args);
            return;
        }

        auto count = bytes / sizeof(MOUSE_INPUT_DATA);
        g_ghv->diag_mouse_cb_last_count = count;
        if (count == 0 || count > 16) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_bad_args);
            return;
        }

        for (uint64_t i = 0; i < count; i++) {
            auto packet_va = start_va + i * sizeof(MOUSE_INPUT_DATA);
            auto packet = (PMOUSE_INPUT_DATA)gva2hva((PVOID)packet_va);
            if (!packet) {
                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_bad_args);
                break;
            }

            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_packets);

            LONG rawX = packet->LastX;
            LONG rawY = packet->LastY;
            if (!rawX && !rawY) {
                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_zero_packets);
                continue;
            }

            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouse_cb_movement_packets);
            g_ghv->diag_mouse_cb_last_flags = packet->Flags;
            g_ghv->diag_mouse_cb_last_raw_x = rawX;
            g_ghv->diag_mouse_cb_last_raw_y = rawY;
            break;
        }
    }





    // type 24 - MouHid_StartRead lower-stack send probe.
    // Runs at mouhid.sys+0x3CB2 before IofCallDriver(lower HID stack, IRP).
    // RCX = lower DeviceObject, RDX = IRP. Read-only overlay self-check.
    void handle_mouhid_startread_lower_iocall(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_down_hits);
        diag_capture_lower_device((uint64_t)cpu->ctx->rcx,
            g_ghv->diag_mouhid_down_lower_device,
            g_ghv->diag_mouhid_down_lower_driver,
            g_ghv->diag_mouhid_down_driver_base,
            g_ghv->diag_mouhid_down_driver_size,
            g_ghv->diag_mouhid_down_name_hash,
            g_ghv->diag_mouhid_down_known_code);

        auto site = g_ghv->diag_mouhid_down_target_va ?
            g_ghv->diag_mouhid_down_target_va :
            ((uint64_t)mouse::mouse_obj.hid_driver_base + 0x3CB2);
        if (!diag_emulate_rip_indirect_call(cpu, site, 7, 3))
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_down_emulate_fail);
    }

    // type 25 - HidUsb lower USB stack send probe.
    // Runs at hidusb.sys+0x1485 before IofCallDriver(lower USB stack, IRP).
    // RCX = lower DeviceObject, RDX = IRP. known_code=0 means unknown lower.
    void handle_hidusb_lower_iocall(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_hidusb_down_hits);
        diag_capture_lower_device((uint64_t)cpu->ctx->rcx,
            g_ghv->diag_hidusb_down_lower_device,
            g_ghv->diag_hidusb_down_lower_driver,
            g_ghv->diag_hidusb_down_driver_base,
            g_ghv->diag_hidusb_down_driver_size,
            g_ghv->diag_hidusb_down_name_hash,
            g_ghv->diag_hidusb_down_known_code);

        auto site = g_ghv->diag_hidusb_down_target_va ?
            g_ghv->diag_hidusb_down_target_va :
            ((uint64_t)mouse::mouse_obj.hidusb_driver_base + 0x1485);
        if (!diag_emulate_rip_indirect_call(cpu, site, 7, 3))
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_hidusb_down_emulate_fail);
    }

    // type 26 - HidUsb HumReadCompletion entry probe.
    // Runs at hidusb.sys+0x2D60. Entry args:
    //   RCX = DeviceObject, RDX = IRP, R8 = completion context / URB block.
    // 22H2 fields observed:
    //   *(NTSTATUS*)(IRP+0x30), *(ULONG*)(R8+0x24),
    //   *(void**)(R8+0x28), *(void**)(R8+0x30).
    void handle_hidusb_read_completion(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_hidusb_comp_hits);

        auto device = (uint64_t)cpu->ctx->rcx;
        auto irp = (uint64_t)cpu->ctx->rdx;
        auto ctx = (uint64_t)cpu->ctx->r8;

        g_ghv->diag_hidusb_comp_device = device;
        g_ghv->diag_hidusb_comp_irp = irp;
        g_ghv->diag_hidusb_comp_ctx = ctx;
        g_ghv->diag_hidusb_comp_status = 0;
        g_ghv->diag_hidusb_comp_len = 0;
        g_ghv->diag_hidusb_comp_buf = 0;
        g_ghv->diag_hidusb_comp_mdl = 0;
        g_ghv->diag_hidusb_comp_read_bytes = 0;
        g_ghv->diag_hidusb_comp_first8 = 0;

        if (!irp || !ctx) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_hidusb_comp_bad_args);
            return;
        }

        NTSTATUS status = 0;
        ULONG len = 0;
        uint64_t buf = 0;
        uint64_t mdl = 0;

        bool ok_status = diag_read_kernel_va(irp + 0x30, &status, sizeof(status));
        bool ok_len = diag_read_kernel_va(ctx + 0x24, &len, sizeof(len));
        bool ok_buf = diag_read_kernel_va(ctx + 0x28, &buf, sizeof(buf));
        bool ok_mdl = diag_read_kernel_va(ctx + 0x30, &mdl, sizeof(mdl));

        if (!ok_status || !ok_len || !ok_buf || !ok_mdl) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_hidusb_comp_bad_args);
            return;
        }

        g_ghv->diag_hidusb_comp_status = (uint64_t)(uint32_t)status;
        g_ghv->diag_hidusb_comp_len = (uint64_t)len;
        g_ghv->diag_hidusb_comp_buf = buf;
        g_ghv->diag_hidusb_comp_mdl = mdl;

        if (!buf || len == 0 || len > 0x1000)
            return;

        uint8_t bytes[8] = {};
        auto want = (len < sizeof(bytes)) ? len : (ULONG)sizeof(bytes);
        auto got = read_guest_virtual_memory(g_ghv->system_cr3, (void*)buf, bytes, want);
        g_ghv->diag_hidusb_comp_read_bytes = (uint64_t)got;

        uint64_t packed = 0;
        for (size_t i = 0; i < got && i < sizeof(bytes); i++)
            packed |= ((uint64_t)bytes[i]) << (i * 8);
        g_ghv->diag_hidusb_comp_first8 = packed;
    }


    // type 23 - MouHid_ReadComplete pre-callsite probe.
    //
    // Runs at mouhid.sys+0x3AA2, immediately before the CFG indirect call
    // whose return address is mouhid.sys+0x3AA8. At this point the normal
    // MouClassServiceCallback arguments are already prepared:
    //   RCX = DeviceObject
    //   RDX = InputDataStart
    //   R8  = InputDataEnd
    //   R9  = InputDataConsumed
    //   RAX = ClassService callback target
    //
    // Observation-only for now. If we later move adjustment earlier, this is
    // the narrow place to mutate LastX/LastY.
    void handle_mouhid_read_complete_precall(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_hits);

        auto callback = (uint64_t)cpu->ctx->rax;
        auto device = (PDEVICE_OBJECT)cpu->ctx->rcx;
        auto start_va = (uint64_t)cpu->ctx->rdx;
        auto end_va = (uint64_t)cpu->ctx->r8;

        g_ghv->diag_mouhid_pre_callback_va = callback;
        g_ghv->diag_mouhid_pre_last_device = (uint64_t)device;
        g_ghv->diag_mouhid_pre_last_start = start_va;
        g_ghv->diag_mouhid_pre_last_end = end_va;

        do {
            if (!start_va || !end_va || end_va <= start_va) {
                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_bad_args);
                break;
            }

            auto bytes = end_va - start_va;
            if ((bytes % sizeof(MOUSE_INPUT_DATA)) != 0) {
                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_bad_args);
                break;
            }

            auto count = bytes / sizeof(MOUSE_INPUT_DATA);
            g_ghv->diag_mouhid_pre_last_count = count;
            if (count == 0 || count > 16) {
                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_bad_args);
                break;
            }

            for (uint64_t i = 0; i < count; i++) {
                auto packet_va = start_va + i * sizeof(MOUSE_INPUT_DATA);
                auto packet = (PMOUSE_INPUT_DATA)gva2hva((PVOID)packet_va);
                if (!packet) {
                    _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_bad_args);
                    break;
                }

                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_packets);

                LONG rawX = packet->LastX;
                LONG rawY = packet->LastY;
                if (!rawX && !rawY)
                    continue;

                _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_movement_packets);
                g_ghv->diag_mouhid_pre_last_flags = packet->Flags;
                g_ghv->diag_mouhid_pre_last_raw_x = rawX;
                g_ghv->diag_mouhid_pre_last_raw_y = rawY;
                break;
            }
        } while (false);

        // This hook sits on `call qword ptr [rip+disp32]` (mouhid+0x3AA2),
        // so never let the generic trampoline execute the copied call.
        auto site = g_ghv->diag_mouhid_pre_target_va ?
            g_ghv->diag_mouhid_pre_target_va :
            ((uint64_t)mouse::mouse_obj.hid_driver_base + 0x3AA2);
        if (!diag_emulate_rip_indirect_call(cpu, site, 6, 2)) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_emulate_fail);
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mouhid_pre_bad_args);
        }
    }


    // type 3 鈥 IDXGISwapChain::GetBuffer (vtable index 9).
    // dispatch=NORMAL so that "our own hv::Call" path can transparently
    // fall through to the original GetBuffer (render::init needs the real
    // IDXGISurface to build d2dRenderTarget).
    //
    // Three-way classification:
    //   1. our hv::Call (retAddr is a registered blank_memory) 鈥
    //      handler returns without touching RIP; dispatcher fallthroughs
    //      to original GetBuffer so we get the real surface
    //   2. legit dwmcore/dxgi internal 鈥 hand back fakeTexture (backbuffer
    //      copy + overlay, so DWM screen still shows our overlay)
    //   3. alien (anti-cheat injected into DWM) 鈥 hand back markerTexture
    //      (solid magenta, captured frame proves the substitution worked)
    void handle_dxgi_get_buffer(vcpu* cpu) {

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_getbuffer_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PVOID)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;
        auto retAddress = *(PULONG64)rsp_hva;

        // 1. Our own hv::Call (render::init etc.) 鈥 let original GetBuffer run.
        if (is_vmcall_blank_rip(retAddress)) return;

        auto bufferptr = cpu->ctx->r9;
        auto bufferptr_hva = (PVOID)gva2hva((PVOID)bufferptr);

        PVOID texture;
        if (!dwm::caller_is_legit_dwm_strict(retAddress)) {
            // 3. Alien (screenshot tool / anti-cheat injected into DWM).
            //    PMO and GetBuffer are SYNCHRONOUS on the same DWM
            //    compose thread / vCPU 鈥 only one runs at a time. PMO
            //    tick() refreshes fakeTexture (CopyResource backbuffer
            //    鈫 fakeTexture, throttled 1 s) BEFORE BeginDraw, so by
            //    the time alien GetBuffer fires here, fakeTexture holds
            //    the most recent overlay-free snapshot. Hand it back.
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_getbuffer_alien);
            texture = hv::GetFakeTexture();
        } else {
            // 2. Legit DWM caller 鈥 hand back fakeTexture so DWM composites
            //    the overlay-bearing surrogate (overlay stays visible).
            texture = hv::CreateTexture();
        }

        if (bufferptr_hva) *(PVOID*)bufferptr_hva = texture;
        cpu->ctx->rax = texture ? 0 : 0x80004005;  // S_OK if ready, else E_FAIL

        // Skip the original GetBuffer (we already filled OUT params).
        // Pop the saved return slot, redirect RIP to caller's retAddress.
        rsp += 8;
        vmx_vmwrite(VMCS_GUEST_RSP, rsp);
        vmx_vmwrite(VMCS_GUEST_RIP, retAddress);
    }

    // ----------------------------------------------------------------------
    // Stage 鈶-A anti-screenshot helper: classify caller.
    // Three buckets:
    //   0 = our own hv::Call (retAddr is a registered blank_memory) 鈥 pass through
    //   1 = legit dwmcore/dxgi internal call 鈥 pass through
    //   2 = alien (anti-cheat injected into DWM) 鈥 block
    // Caller has already read retAddress from guest RSP.
    enum caller_class { CALLER_OUR_HV = 0, CALLER_LEGIT_DWM = 1, CALLER_ALIEN = 2 };
    static caller_class classify_caller(ULONG64 retAddress) {
        if (is_vmcall_blank_rip(retAddress)) return CALLER_OUR_HV;
        if (dwm::caller_is_legit_dwm_strict(retAddress)) return CALLER_LEGIT_DWM;
        return CALLER_ALIEN;
    }

    // type 9 鈥 IDXGISwapChain::Present (vtable index 8).
    // dispatch=NORMAL: handler returns without touching RIP for legit callers,
    // so dispatcher fallthroughs to the original function. Alien callers get
    // DXGI_ERROR_DEVICE_RESET and the original Present is skipped (RIP jumped
    // past the vmcall stub directly to the return address).
    void handle_present(vcpu* cpu) {

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_present_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PVOID)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;
        auto retAddress = *(PULONG64)rsp_hva;

        if (classify_caller(retAddress) != CALLER_ALIEN) return;

        // Alien 鈥 fail with DXGI_ERROR_DEVICE_RESET so caller falls into a
        // "device lost" code path and never sees our backbuffer.
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_present_alien);
        cpu->ctx->rax = 0x887A0007;  // DXGI_ERROR_DEVICE_RESET
        rsp += 8;
        vmx_vmwrite(VMCS_GUEST_RSP, rsp);
        vmx_vmwrite(VMCS_GUEST_RIP, retAddress);
    }

    // type 10 鈥 IDXGISwapChain1::Present1 (vtable index 22).
    // Same strategy as handle_present.
    void handle_present1(vcpu* cpu) {

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_present1_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PVOID)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;
        auto retAddress = *(PULONG64)rsp_hva;

        if (classify_caller(retAddress) != CALLER_ALIEN) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_present1_alien);
        cpu->ctx->rax = 0x887A0007;  // DXGI_ERROR_DEVICE_RESET
        rsp += 8;
        vmx_vmwrite(VMCS_GUEST_RSP, rsp);
        vmx_vmwrite(VMCS_GUEST_RIP, retAddress);
    }

    // type 11 鈥 ID3D11DeviceContext::CopyResource (vtable index 47).
    // Signature: void CopyResource(this, ID3D11Resource* pDst, ID3D11Resource* pSrc)
    // x64 fastcall: rcx=this, rdx=pDst, r8=pSrc.
    //
    // OBSERVATION MODE: just classify caller + bump counters, then return
    // without touching any register or RIP. Dispatcher fallthrough runs the
    // real CopyResource. Goal: prove the hook installs cleanly and the call
    // rate / caller distribution is sane before we start swapping src.
    void handle_copy_resource(vcpu* cpu) {

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_copyresource_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PVOID)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;
        auto retAddress = *(PULONG64)rsp_hva;

        if (classify_caller(retAddress) == CALLER_ALIEN) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_copyresource_alien);
        }
        // No RIP/register change 鈥 dispatcher falls through to real CopyResource.
    }

    // type 12 鈥 IDXGIOutput1::DuplicateOutput.
    // Signature: HRESULT DuplicateOutput(this, IUnknown* pDevice, IDXGIOutputDuplication** ppOutputDuplication)
    // x64 fastcall: rcx=this, rdx=pDevice, r8=ppOutputDuplication.
    //
    // dispatch=NORMAL. Alien 鈫 return DXGI_ERROR_NOT_CURRENTLY_AVAILABLE
    // (0x887A0022) so OBS/Snipping/Xbox Bar can't start capturing. DWM
    // itself doesn't call DuplicateOutput so the pass-through branch
    // effectively never fires.
    void handle_duplicate_output(vcpu* cpu) {

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_duplicateoutput_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PVOID)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;
        auto retAddress = *(PULONG64)rsp_hva;

        if (classify_caller(retAddress) != CALLER_ALIEN) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_duplicateoutput_alien);

        // Zero out the OUT param so caller's Release(ppOutputDuplication*)
        // doesn't deref garbage.
        auto out_pp = cpu->ctx->r8;
        auto out_pp_hva = (PVOID)gva2hva((PVOID)out_pp);
        if (out_pp_hva) *(PVOID*)out_pp_hva = nullptr;

        cpu->ctx->rax = 0x887A0022;  // DXGI_ERROR_NOT_CURRENTLY_AVAILABLE
        rsp += 8;
        vmx_vmwrite(VMCS_GUEST_RSP, rsp);
        vmx_vmwrite(VMCS_GUEST_RIP, retAddress);
    }
    // ----------------------------------------------------------------------

    // type 13 鈥 NtCreateThreadEx (cross-process thread creation, kernel function,
    // installed lazily from PMO handler).
    // Instead of CallK(DbgPrintEx) per hit (which is heavy), push a line
    // into the vt_log ring; the NtSetEvent flusher (type 14) drains it.
    void handle_mmcopymemory(vcpu* cpu) {
        auto hits = _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmcopy_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PVOID)gva2hva((PVOID)rsp);
        uint64_t caller_rip = 0;
        if (rsp_hva) {
            caller_rip = *(PULONG64)rsp_hva;
            g_ghv->diag_mmcopy_last_caller_rip = caller_rip;
        }

        // Lightweight: write to ring instead of CallK directly.
        VT_RING_LOG("MMM hits=%llu caller=%p", (uint64_t)hits, (void*)caller_rip);
    }
    // ----------------------------------------------------------------------

    // type 14 鈥 NtSetEvent kernel hook.
    // Observation-only: count fires, record caller, return without touching
    // any register or RIP (NORMAL fallthrough runs original NtSetEvent).
    // CallK(DbgPrintEx) removed 鈥 it caused bugcheck 50 because CallK does
    // vmresume-out and while DbgPrintEx runs in guest, another thread can
    // re-enter NtSetEvent on the same vCPU and corrupt this vCPU's fake_page.
    void handle_ntsetevent(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmcopy_hits);
        // No register/RIP change 鈥 dispatcher NORMAL fallthrough runs original.
    }

    // ----------------------------------------------------------------------
    // Anti-screenshot: DWM-only kernel hooks (process filter set at install).
    // BISECT MODE: handler bodies stripped to bare hit-counter. No rsp read,
    // no notify_capture_attempt. If this version still crashes, the issue is
    // in install / dispatcher / trampoline. If it survives, the issue is in
    // handler logic (rsp dereference, notify path).
    //
    // Trigger overlay-hide window when an alien thread inside DWM allocates,
    // mprotects, or maps memory with EXECUTE-class protection. NORMAL
    // fallthrough 鈥 never blocks the call, only sets the hide deadline.
    //
    // Parameter layout at vm-exit: hook is on the kernel function body's first
    // byte, so caller pushed retaddr, allocated 0x20 shadow space, and rcx/rdx/
    // r8/r9 hold the first 4 args; 5th and beyond at [rsp+0x28], [rsp+0x30]...
    // PAGE_EXECUTE_*  = 0x10 | 0x20 | 0x40 | 0x80 = 0xF0 mask.
    // ----------------------------------------------------------------------
    static constexpr ULONG kExecuteMask = 0xF0;

    // type 15 鈥 NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
    //                                    RegionSize, AllocType, Protect)
    // Protect is the 6th argument 鈫 [rsp+0x30]; index 6 in ULONG64* view of rsp.
    // Dispatcher already filtered to DWM process; handler only fires inside DWM.
    void handle_nt_allocate_virtual_memory(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_alloc_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PULONG64)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;

        ULONG protect = (ULONG)rsp_hva[6];
        if (!(protect & kExecuteMask)) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_alloc_alien);

        // Diagnostic: log the alien (EXECUTE) call. caller = [rsp+0] is the
        // kernel return address (KiSystemServiceCopyEnd+0x25 typically); the
        // actual user RIP is one frame deeper but harder to surface here.
        // RegionSize is rdx (pointer to a SIZE_T); we read the pointed value.
        if (DbgPrintEx_va && g_ghv->alloc_format_va) {
            ULONG64 caller_ret = rsp_hva[0];
            ULONG64 region_size = 0;
            auto regsz_hva = (ULONG64*)gva2hva((PVOID)cpu->ctx->r9);
            if (regsz_hva) region_size = *regsz_hva;
            CallK<void*>((void*)DbgPrintEx_va,
                (UINT64)0, (UINT64)0,
                (UINT64)g_ghv->alloc_format_va,
                (UINT64)protect, (UINT64)region_size, (UINT64)caller_ret);
        }

        game::notify_capture_attempt();
    }

    // type 16 鈥 NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize,
    //                                   NewProtect, OldProtect)
    // NewProtect is the 4th argument 鈫 r9. Catches RW鈫扲X transitions which is
    // the classic shellcode unpack signature.
    void handle_nt_protect_virtual_memory(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_protect_hits);

        ULONG newProtect = (ULONG)cpu->ctx->r9;
        if (!(newProtect & kExecuteMask)) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_protect_alien);

        // BaseAddress is rdx (pointer to PVOID); RegionSize is r8 (pointer to SIZE_T).
        if (DbgPrintEx_va && g_ghv->protect_format_va) {
            ULONG64 base = 0;
            ULONG64 size = 0;
            auto base_hva = (ULONG64*)gva2hva((PVOID)cpu->ctx->rdx);
            if (base_hva) base = *base_hva;
            auto size_hva = (ULONG64*)gva2hva((PVOID)cpu->ctx->r8);
            if (size_hva) size = *size_hva;
            CallK<void*>((void*)DbgPrintEx_va,
                (UINT64)0, (UINT64)0,
                (UINT64)g_ghv->protect_format_va,
                (UINT64)newProtect, (UINT64)base, (UINT64)size);
        }

        game::notify_capture_attempt();
    }

    // type 17 鈥 NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
    //                               ZeroBits, CommitSize, SectionOffset,
    //                               ViewSize, InheritDisposition,
    //                               AllocationType, Win32Protect)
    // Win32Protect is the 10th argument 鈫 [rsp+0x50]; index 10 in ULONG64*.
    // Catches manual mappers and SEC_IMAGE-bypass loaders that map executable
    // sections directly. (Standard LdrLoadDll path uses PAGE_READONLY here and
    // is caught instead by the alloc/protect hooks via DllMain.)
    void handle_nt_map_view_of_section(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_map_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PULONG64)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;

        ULONG win32Protect = (ULONG)rsp_hva[10];
        if (!(win32Protect & kExecuteMask)) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_map_alien);

        // SectionHandle is rcx (the HANDLE itself, not a pointer to it).
        if (DbgPrintEx_va && g_ghv->map_format_va) {
            CallK<void*>((void*)DbgPrintEx_va,
                (UINT64)0, (UINT64)0,
                (UINT64)g_ghv->map_format_va,
                (UINT64)win32Protect, (UINT64)cpu->ctx->rcx);
        }

        game::notify_capture_attempt();
    }
    // ----------------------------------------------------------------------

    // type 4 鈥 NtGetContextThread.
    // When the target game calls NtGetContextThread we sniff its XSTATE area
    // for the encrypted SDK key and stash it into sjz::gameData.key.
    void handle_nt_get_context_thread(vcpu* cpu) {


        PEPROCESS currentProcess =  current_guest_eprocess();


        if (currentProcess == game::gameProcess) {


            Call4(NtGetContextThread, cpu->ctx->rcx, cpu->ctx->rdx);

            PVOID context_ptr = (PVOID)cpu->ctx->rdx;

            CONTEXT* context_hva =  (CONTEXT*)gva2hva(context_ptr);


            if (!sjz::gameData.key) {


                if (context_hva->ContextFlags & CONTEXT_XSTATE) {


                    auto DecryptKey = (ULONG64)Read<ULONG64>((ULONG64)context_ptr + 0x658);


                    if ((DecryptKey & 0xF000000000000000))
                    {

                        sjz::gameData.key = DecryptKey;

                    }


                }


            }

           

        }

    }

    PVOID addr = nullptr;

    // type 5 鈥 process-exit notification. rdx carries PEPROCESS of the dying
    // process; if it's our game we tear down state and reset.
    void handle_process_exit_notify(vcpu* cpu) {

        PEPROCESS process = (PEPROCESS)cpu->ctx->rdx;


        if (process == game::gameProcess) {


            game::isExiting = true;
            game::isEnd = true;

            game::Reset();

        }

    }

    spin_lock handler6_spin;

    // ---- DLL blacklist for NtCreateSection capture detection ----
    // Wide-string lower-case substring match (no MSVC RTL 鈥 we're in host).
    // Kept short: only DLLs that legit DWM steady-state never re-loads. Adding
    // generic DLLs (e.g. user32, gdi32) WILL false-positive (DWM does load
    // them at startup; whether it re-loads later varies).
    //
    // ACE / patched NvFBC / Geforce Experience overlay all live behind one
    // of these names.
    static const wchar_t* const kCaptureDllBlacklist[] = {
        L"nvapi64.dll",
        L"nvfbc.dll",
        L"nvfbc64.dll",
        L"nvfbcwrap.dll",
        L"nvencodeapi64.dll",
        L"amfrt64.dll",
        L"amfrt32.dll",
    };

    // Lower-case ASCII char (works on wchar_t for the BMP letters we care about).
    static inline wchar_t ascii_tolower_w(wchar_t c) {
        return (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
    }

    // Case-insensitive ASCII substring match within a UNICODE_STRING-like buffer.
    // hay/hay_chars: probe target. needle/needle_chars: pattern (assumed lowercase).
    static bool wide_contains_ci(const wchar_t* hay, size_t hay_chars,
                                  const wchar_t* needle, size_t needle_chars) {
        if (!hay || !needle || needle_chars == 0 || hay_chars < needle_chars)
            return false;
        size_t span = hay_chars - needle_chars + 1;
        for (size_t i = 0; i < span; i++) {
            size_t j = 0;
            for (; j < needle_chars; j++) {
                if (ascii_tolower_w(hay[i + j]) != needle[j])
                    break;
            }
            if (j == needle_chars) return true;
        }
        return false;
    }

    // Fast wcslen-like for the blacklist (compile-time constants).
    static inline size_t wcslen_local(const wchar_t* s) {
        size_t n = 0; while (s[n]) n++; return n;
    }

    // type 6 鈥 NtCreateSection (DWM-only via dispatcher process filter).
    // BISECT MODE: dump every SEC_IMAGE FileName via CallK(DbgPrintEx) to
    // verify we can read the filename at all. Once dumps look right, replace
    // the print with the blacklist matcher + notify_capture_attempt.
    //
    // Stack layout at function-body entry (kernel hook):
    //   [rsp+ 0]  return address
    //   [rsp+ 8..0x20]  caller's home-save shadow (for rcx/rdx/r8/r9)
    //   [rsp+0x28]  arg5 = SectionPageProtection
    //   [rsp+0x30]  arg6 = AllocationAttributes
    //   [rsp+0x38]  arg7 = FileHandle
    void handle_nt_create_section(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_csec_hits);

        auto rsp = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PULONG64)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;

        ULONG  allocAttr  = (ULONG)rsp_hva[6];   // AllocationAttributes
        HANDLE fileHandle = (HANDLE)rsp_hva[7];  // FileHandle

        static const ULONG kSecImage = 0x01000000;
        if (!(allocAttr & kSecImage)) return;
        if (!fileHandle) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_csec_image);

        if (!ObReferenceObjectByHandle_va || !ObfDereferenceObject_va ||
            !DbgPrintEx_va || !g_ghv->csec_scratch_va || !g_ghv->csec_format_va ||
            !g_yvt.NtapiOffsets.FileName)
            return;

        // First 8 bytes of csec_scratch hold the [out] FILE_OBJECT*.
        auto out_slot_gva = (PVOID*)g_ghv->csec_scratch_va;
        auto out_slot_hva = (PVOID*)gva2hva((PVOID)out_slot_gva);
        if (!out_slot_hva) return;
        *out_slot_hva = nullptr;

        // ObReferenceObjectByHandle(Handle, Access=0, ObjectType=NULL,
        //                            AccessMode=KernelMode (0),
        //                            Object=&out, HandleInfo=NULL)
        NTSTATUS st = (NTSTATUS)(LONG_PTR)CallK<void*>(
            (void*)ObReferenceObjectByHandle_va,
            (UINT64)fileHandle,
            (UINT64)0,
            (UINT64)0,
            (UINT64)0,
            (UINT64)out_slot_gva,
            (UINT64)0);

        if (st < 0) return;

        PVOID fileObj = *out_slot_hva;
        if (!fileObj) return;

        // FILE_OBJECT.FileName is UNICODE_STRING { USHORT Len; USHORT MaxLen; PWSTR Buf; }
        auto unicode_str_gva = (uint8_t*)fileObj + g_yvt.NtapiOffsets.FileName;
        auto unicode_str_hva = (uint8_t*)gva2hva((PVOID)unicode_str_gva);
        if (!unicode_str_hva) {
            CallK<void*>((void*)ObfDereferenceObject_va, (UINT64)fileObj);
            return;
        }

        USHORT  name_len_bytes = *(USHORT*)(unicode_str_hva + 0);
        wchar_t* name_buf_gva  = *(wchar_t**)(unicode_str_hva + 8);
        size_t name_len_chars  = name_len_bytes / sizeof(wchar_t);

        // Copy filename to a guest-readable buffer (the FILE_OBJECT.FileName.Buffer
        // points at NPP; copy it into csec_scratch+0x100 so DbgPrintEx can read
        // through guest CR3 cleanly. Reserve 0..0xFF for the [out] slot.
        if (name_buf_gva && name_len_chars > 0 && name_len_chars < 1024) {
            auto name_src_hva = (wchar_t*)gva2hva((PVOID)name_buf_gva);
            if (name_src_hva) {
                auto name_dst_gva = (wchar_t*)(g_ghv->csec_scratch_va + 0x100);
                auto name_dst_hva = (wchar_t*)gva2hva((PVOID)name_dst_gva);
                if (name_dst_hva) {
                    for (size_t i = 0; i < name_len_chars; i++)
                        name_dst_hva[i] = name_src_hva[i];
                    name_dst_hva[name_len_chars] = 0;

                    _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_nt_csec_alien);
                    CallK<void*>(
                        (void*)DbgPrintEx_va,
                        (UINT64)0,                     // ComponentId
                        (UINT64)0,                     // Level
                        (UINT64)g_ghv->csec_format_va,    // Format
                        (UINT64)name_dst_gva);         // wide filename
                }
            }
        }

        CallK<void*>((void*)ObfDereferenceObject_va, (UINT64)fileObj);
    }

    // type 7 鈥 NtOpenSection trampoline landing point (placeholder; real logic
    // in HookedNtOpenSection in dwm/kerneldwm.cpp).
    void handle_nt_open_section(vcpu* cpu) {



    }

    // type 8 鈥 currently unused, reserved for a future hook target.
    void handle_unused_8(vcpu* cpu) {


    }

    // ====================================================================
    // Stage 5: Mm* memory-hide kernel hooks
    //
    // Each handler checks the probe target VA against hv::g_ghv->prot_ranges
    // (testDriver image + every PoolManager block) and bails with an
    // appropriate failure code, skipping the original function, when the
    // target overlaps a hidden region. Misses fall through to the dispatcher
    // default and let the original function run via trampoline.
    //
    // Skip-original technique (NORMAL dispatch mode):
    //   1. read retAddress from [rsp]
    //   2. set rax = failure code
    //   3. zero any output-by-pointer args the caller expects
    //   4. pop retAddress (rsp += 8)
    //   5. vmwrite GUEST_RIP = retAddress  鈫 caller resumes after its call
    // The dispatcher checks `rip_after != rip` and respects our RIP rewrite,
    // not running the original via trampoline.
    // ====================================================================

    // Fill caller's buffer at `target_gva` (in current guest CR3) with bytes
    // sourced from g_ghv->fake_data, walking page-by-page via gva2hva. Used by
    // Mm* hooks to substitute fake content for hidden regions, instead of
    // returning an explicit error status 鈥 anti-cheat sees a "successful"
    // copy with normal-looking kernel bytes.
    //
    // The fake page is 4 KB; we tile it across the request, sliding the
    // offset with the destination so adjacent requests look like contiguous
    // memory rather than the same 4 KB block repeated.
    static SIZE_T fill_with_fake(ULONG64 target_gva, SIZE_T size) {
        SIZE_T copied = 0;
        while (copied < size) {
            ULONG64 cur = target_gva + copied;
            auto t_hva = (UCHAR*)gva2hva((PVOID)cur);
            if (!t_hva) break;
            SIZE_T page_room = PAGE_SIZE - (cur & 0xFFFull);
            SIZE_T fake_off  = (SIZE_T)(cur & 0xFFFull);
            SIZE_T fake_room = sizeof(g_ghv->fake_data) - fake_off;
            SIZE_T chunk     = size - copied;
            if (chunk > page_room) chunk = page_room;
            if (chunk > fake_room) chunk = fake_room;
            memcpy(t_hva, g_ghv->fake_data + fake_off, chunk);
            copied += chunk;
        }
        return copied;
    }

    // type 18 鈥 MmCopyMemory(TargetAddress, MM_COPY_ADDRESS SourceAddress,
    //                         NumberOfBytes, Flags, PSIZE_T BytesTransferred)
    //   rcx = Target  (PVOID, where to write the result)
    //   rdx = Source  (8-byte by-value union: VA when VIRTUAL, PA when PHYSICAL)
    //   r8  = Size
    //   r9  = Flags   (1 = MM_COPY_MEMORY_VIRTUAL, 2 = MM_COPY_MEMORY_PHYSICAL)
    //   [rsp+0x28] = PSIZE_T BytesTransferred (output)
    //
    // On protected hit: fill caller's TargetAddress with fake_data bytes,
    // report BytesTransferred = size, return STATUS_SUCCESS. Anti-cheat
    // can't tell the read was substituted.
    void handle_mm_copy_memory(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmcm_hits);

        ULONG  flags = (ULONG)cpu->ctx->r9;
        ULONG64 src  = cpu->ctx->rdx;
        SIZE_T size  = (SIZE_T)cpu->ctx->r8;

        // VIRTUAL mode only 鈥 PHYSICAL needs PFN-set lookup not yet wired.
        if (!(flags & 1) || !hv::is_protected_va(src, size)) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmcm_blocked);

        auto rsp     = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PULONG64)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;

        SIZE_T copied = fill_with_fake(cpu->ctx->rcx, size);

        // *BytesTransferred = size (report success even if some pages
        // couldn't be mapped 鈥 caller likely won't validate beyond rax).
        if (auto bt_gva = (ULONG64)rsp_hva[5]) {
            if (auto bt_hva = (SIZE_T*)gva2hva((PVOID)bt_gva)) *bt_hva = size;
        }

        ULONG64 ret = rsp_hva[0];
        cpu->ctx->rax = 0;  // STATUS_SUCCESS
        rsp += 8;
        vmx_vmwrite(VMCS_GUEST_RSP, rsp);
        vmx_vmwrite(VMCS_GUEST_RIP, ret);
    }

    // type 19 鈥 MmCopyVirtualMemory(FromProcess, FromAddress, ToProcess,
    //                                 ToAddress, BufferSize, Mode, BytesCopied)
    //   rcx = FromProcess (PEPROCESS)
    //   rdx = FromAddress (PVOID 鈥 source kernel VA)
    //   r8  = ToProcess
    //   r9  = ToAddress
    //   [rsp+0x28] = BufferSize
    //   [rsp+0x30] = Mode
    //   [rsp+0x38] = PSIZE_T NumberOfBytesCopied
    void handle_mm_copy_virtual_memory(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmcvm_hits);

        ULONG64 from   = cpu->ctx->rdx;
        ULONG64 to_gva = cpu->ctx->r9;

        auto rsp     = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PULONG64)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;

        SIZE_T size = (SIZE_T)rsp_hva[5];  // [rsp+0x28]
        if (!hv::is_protected_va(from, size)) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmcvm_blocked);

        SIZE_T copied = fill_with_fake(to_gva, size);

        // *NumberOfBytesCopied = size at [rsp+0x38]
        if (auto bc_gva = (ULONG64)rsp_hva[7]) {
            if (auto bc_hva = (SIZE_T*)gva2hva((PVOID)bc_gva)) *bc_hva = size;
        }

        ULONG64 ret = rsp_hva[0];
        cpu->ctx->rax = 0;  // STATUS_SUCCESS
        rsp += 8;
        vmx_vmwrite(VMCS_GUEST_RSP, rsp);
        vmx_vmwrite(VMCS_GUEST_RIP, ret);
    }

    // type 20 鈥 MmIsAddressValid(VirtualAddress)
    //   rcx = VA
    //   returns BOOLEAN (low byte of rax)
    //
    // Return TRUE on hit 鈥 pairs with the fake-data substitution above.
    // Anti-cheat probes "is this VA valid?", gets TRUE, then reads via
    // MmCopyMemory / MmCopyVirtualMemory and gets fake bytes back. If we
    // returned FALSE here, the anti-cheat would skip the read entirely
    // and immediately know the address belongs to something hidden.
    void handle_mm_is_address_valid(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmisav_hits);

        ULONG64 va = cpu->ctx->rcx;
        if (!hv::is_protected_va(va, 1)) return;

        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmisav_blocked);

        auto rsp     = vmx_vmread(VMCS_GUEST_RSP);
        auto rsp_hva = (PULONG64)gva2hva((PVOID)rsp);
        if (!rsp_hva) return;

        ULONG64 ret = rsp_hva[0];
        cpu->ctx->rax = 1;  // TRUE 鈥 let caller go on to read fake bytes
        rsp += 8;
        vmx_vmwrite(VMCS_GUEST_RSP, rsp);
        vmx_vmwrite(VMCS_GUEST_RIP, ret);
    }

    // type 21 鈥 MmMapIoSpace(PhysicalAddress, NumberOfBytes, CacheType)
    //   rcx = PA (PHYSICAL_ADDRESS by-value, 8 bytes)
    //   rdx = Size
    //   r8  = CacheType
    //   returns PVOID (NULL on failure)
    //
    // We don't have a fast PA鈫抜s-protected lookup yet (would need a PFN set
    // or sorted pending_hide_pfns binary search). For now we only count the
    // hit and pass through 鈥 the EPT hide on the underlying physical page
    // means any read via the returned VA still ends up at dummy_page.
    void handle_mm_map_io_space(vcpu* cpu) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_mmmio_hits);
        // TODO: walk pending_hide_pfns[] for a PA-protection check if we
        // see real-world abuse via MmMapIoSpace + direct VA read.
    }

    bool vmcall_hook_dispatch(vcpu* cpu) {
        auto rip = vmx_vmread(VMCS_GUEST_RIP);

        g_ghv->diag_dispatch_count++;
        g_ghv->dwm_dispatch_seen_rip = rip;  // last guest RIP that entered dispatcher

        // Record RIP into ring buffer for forensics when no slot matches.
        auto ring_idx = (uint32_t)_InterlockedIncrement(
            (volatile LONG*)&g_ghv->diag_dispatch_rip_idx) - 1;
        g_ghv->diag_dispatch_rip_ring[ring_idx & 7] = rip;

        for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
            auto& slot = g_vt_hook_table[i];
            if (!slot.occupied || !slot.data.address) continue;

            g_ghv->dwm_dispatch_compared_addr = (ULONG64)slot.data.address;  // last addr compared

            if (rip == (ULONG64)slot.data.address) {
                // RIP matched this slot 鈥 vmcall on the fake page already fired,
                // so we MUST redirect RIP (handler-redirect or trampoline) before
                // returning. If we let skip_instruction() advance past the 3-byte
                // vmcall, RIP lands on the 4th byte of the fake page (which holds
                // the original target's instruction tail) 鈫 undefined opcode.
                //
                // Process filter only gates the handler call, not the redirect.
                // Foreign-process callers must still see the original function
                // execute via trampoline.
                bool process_ok = !slot.data.filter_by_process ||
                                   slot.data.process == current_guest_eprocess();

                if (process_ok) {
                    // Increment hit counter 鈥 driver polls g_ghv->dwm_hit_count to
                    // verify the install/hit chain is working.
                    g_ghv->dwm_hit_count++;

                    // Dispatch to registered handler. handle_present_multiplane_overlay
                    // (type=1) chains into render::init / render::tick which uses hv::Call
                    // to invoke D2D / DWrite / D3D11 COM methods on hv::d2dRenderTarget /
                    // colorBrush / TextFormat / context / surface / device.
                    //
                    // Affinity lock is per-hv::Call (game.h Call/Call2/Call3/Call4),
                    // not at dispatcher level. A dispatcher-wide lock was tried and
                    // was less robust against cross-vCPU vt_call_exit corruption
                    // than the tight per-Call window.
                    if (slot.data.type <= VMCALL_HOOK_MAX && g_handler_table[slot.data.type])
                        g_handler_table[slot.data.type](cpu);
                }

                // If the handler already redirected GUEST_RIP (alien short-
                // circuit in GetBuffer / Present / Present1), respect that
                // and do not run the default trampoline rewrite 鈥 otherwise
                // the original function would still execute and overwrite
                // the OUT params the handler just filled in.
                auto rip_after = vmx_vmread(VMCS_GUEST_RIP);
                if (rip_after != rip) {
                    return true;
                }

                switch (slot.data.dispatch_mode) {
                case VMCALL_DISPATCH_RETABS:
                    if (slot.data.isEnable)
                        vmx_vmwrite(VMCS_GUEST_RIP, slot.data.trampleAddress);
                    break;
                case VMCALL_DISPATCH_SELF:
                    break;
                default: {
                    // 0xCC trampoline: GUEST_RIP = oldByte | 0xCC slot in
                    // ntdll/ntoskrnl. CPU executes oldByte then traps on 0xCC;
                    // #BP handler restores RIP to slot.target_resume.
                    // No fallback: PMO and friends MUST continue running the
                    // original function (DWM relies on its return value), so
                    // skipping prologue isn't acceptable. install_host_impl
                    // refuses installs without a tramp slot.
                    if (slot.trampoline_va) {
                        vmx_vmwrite(VMCS_GUEST_RIP, slot.trampoline_va);
                    }
                    break;
                }
                }
                return true;
            }

            if (slot.data.dispatch_mode == VMCALL_DISPATCH_NORMAL &&
                slot.data.nextAddress && rip == (ULONG64)slot.data.nextAddress) {
                // With 0xCC trampoline, nextAddress is never hit 鈥 trampoline
                // returns directly to target+size via #BP handler. This branch
                // remains only for the (now-impossible) legacy path; just
                // acknowledge as handled.
                return true;
            }
        }
        return false;
    }

    bool is_vmcall_blank_rip(ULONG64 rip) {
        for (int i = 0; i < VMCALL_HOOK_MAX; i++)
            if (g_vt_hook_table[i].occupied && g_vt_hook_table[i].data.blankMemory == rip)
                return true;
        return false;
    }

    void init_vmcall_handlers() {
        register_vt_handler(1, handle_present_multiplane_overlay);
        register_vt_handler(2, handle_mi_rw_virtual_memory);
        register_vt_handler(3, handle_dxgi_get_buffer);
        register_vt_handler(4, handle_nt_get_context_thread);
        register_vt_handler(5, handle_process_exit_notify);
        register_vt_handler(6, handle_nt_create_section);
        register_vt_handler(7, handle_nt_open_section);
        register_vt_handler(8, handle_unused_8);
        register_vt_handler(9, handle_present);
        register_vt_handler(10, handle_present1);
        register_vt_handler(11, handle_copy_resource);
        register_vt_handler(12, handle_duplicate_output);
        register_vt_handler(13, handle_mmcopymemory);
        register_vt_handler(14, handle_ntsetevent);
        register_vt_handler(15, handle_nt_allocate_virtual_memory);
        register_vt_handler(16, handle_nt_protect_virtual_memory);
        register_vt_handler(17, handle_nt_map_view_of_section);
        register_vt_handler(18, handle_mm_copy_memory);
        register_vt_handler(19, handle_mm_copy_virtual_memory);
        register_vt_handler(20, handle_mm_is_address_valid);
        register_vt_handler(21, handle_mm_map_io_space);
        #if YVT_MOUSE_HOOK_ENABLED
        register_vt_handler(22, handle_mouse_class_service_callback);
        register_vt_handler(23, handle_mouhid_read_complete_precall);
        register_vt_handler(24, handle_mouhid_startread_lower_iocall);
        register_vt_handler(25, handle_hidusb_lower_iocall);
        register_vt_handler(26, handle_hidusb_read_completion);
        #endif
    }



#pragma code_seg()



}
