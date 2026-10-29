#include "render.h"
#include <gamecommon/gamecommon.h>
#include <gamecommon/draw.h>
#include <gamecommon/dx.h>
#include <sjz/sjz.h>
#include "gamecommon/game.h"
#include <sjz/sjz_sdk.h>


// PMO 渲染启动阶段模式：在常驻 Hook 分发器验证期间，仅在左上角绘制心跳指示器。
// 完整的诊断信息和业务绘制（sjz overlay）在此阶段受 VT_MINIMAL_PMO_HUD 控制而暂不启用。
#define VT_MINIMAL_PMO_HUD 1


namespace hv{


    bool isFinish = false;
    bool isEnd = false;
    bool isMemoryPrepare = false;
    PVOID swapChain = nullptr;
    PVOID context;
    PVOID surface;
    PVOID device;
    PVOID fakeTexture;
    bool isUse = false;
    PVOID backTexture;
    PVOID markerTexture = nullptr;  // alien-path texture: cleared to magenta once,
                                    // never refreshed. Returned to alien GetBuffer
                                    // callers as proof-of-substitution marker.
    bool isScreenShot = false;
    ULONG64 startScreenTime = 0;
    ULONG64 lastCopyTime = 0;

    PVOID descBuffer;
    PVOID entityBuffer_hva;
    PVOID descBuffer_hva;
    PVOID entityBuffer;

    PVOID mouse_event = 0;

    //D2D
    PVOID d2dFactory;
    PVOID dwriteFactory;
    PVOID d2dRenderTarget;
    PVOID d2dSurface;
    PVOID colorBrush;
    PVOID textFormat;

    INT64 perf_frequency, perf_counter;


    PVOID pDWriteFactory;
    PVOID TextFormat;
    PVOID BigTextFormat;

    #define FAILED(hr) (((HRESULT)(hr)) < 0)
#pragma code_seg(".vm")
        PVOID GetVFunc(PVOID Class, ULONG Index) {

            auto class_hva = gva2hva(Class);
            auto vt_hva = (PVOID*)gva2hva(*(PVOID**)class_hva);

            return vt_hva[Index];
        }

        PVOID CreateTexture3() {


            D3D11_TEXTURE2D_DESC sDesc;
            RtlZeroMemory(&sDesc, sizeof(D3D11_TEXTURE2D_DESC));
            RtlZeroMemory(descBuffer_hva, 0x1000);
            RtlZeroMemory(entityBuffer_hva, 0x1000);

            auto ret = (ULONG64)CallUser(GetVFunc(surface, 10), surface, descBuffer);

            if (FAILED(ret)) return 0;





            sDesc = *(D3D11_TEXTURE2D_DESC*)descBuffer_hva;

            RtlCopyMemory(descBuffer_hva, &sDesc, sizeof(sDesc));
            ret = (ULONG64)CallUser(GetVFunc(device, 5), device, descBuffer, (ULONG64)0, entityBuffer);
            auto texture = *(PVOID*)entityBuffer_hva;

            if (texture) {

                ret = (ULONG64)CallUser(GetVFunc(context, 47), context, texture, surface);

                // Anti-screenshot: bump refcount so alien Release storms
                // don't release the texture out from under our refresh loop.
                // AddRef is IUnknown vfunc[1]. 100 calls absorb typical
                // alien Release patterns; if you observe screenshot tools
                // releasing >100 times this needs Release hook instead.
                // Bumped here in CreateTexture3 锟? runs at most a few times
                // (init + tick rebuild only when fakeTexture is null).
                for (int i = 0; i < 100; i++) {
                    CallUser(GetVFunc(texture, 1), (ULONG64)texture);
                }

            }

            return texture;

        }

        VOID Release(PVOID Class) {
            CallUser(GetVFunc(Class, 2), (ULONG64)Class,(UINT64)0);
        }


        void init(vcpu* cpu) {

            g_ghv->diag_init_enter_count++;
            isFinish = false;

            descBuffer = CallUser(VirtualAlloc, (UINT64)0, (UINT64)0x1000, (UINT64)0x1000, (UINT64)0x4);

            entityBuffer = CallUser(VirtualAlloc, (UINT64)0, (UINT64)0x1000, (UINT64)0x1000, (UINT64)0x4);


            buffer0 = CallUser(VirtualAlloc, (UINT64)0, (UINT64)0x1000, (UINT64)0x1000, (UINT64)0x4);

            buffer1 = CallUser(VirtualAlloc, (UINT64)0, (UINT64)0x1000, (UINT64)0x1000, (UINT64)0x4);

            buffer2 = CallUser(VirtualAlloc, (UINT64)0, (UINT64)0x1000, (UINT64)0x1000, (UINT64)0x4);

            CallUser(ReadProcessMemory, (UINT64)-1, (UINT64)descBuffer, (UINT64)descBuffer, (UINT64)0x1, (UINT64)entityBuffer);
            CallUser(ReadProcessMemory, (UINT64)-1, (UINT64)buffer0, (UINT64)buffer0, (UINT64)0x1, (UINT64)descBuffer);
            CallUser(ReadProcessMemory, (UINT64)-1, (UINT64)buffer1, (UINT64)buffer1, (UINT64)0x1, (UINT64)descBuffer);
            CallUser(ReadProcessMemory, (UINT64)-1, (UINT64)buffer2, (UINT64)buffer1, (UINT64)0x1, (UINT64)descBuffer);

             entityBuffer_hva = gva2hva(entityBuffer);
             descBuffer_hva = gva2hva(descBuffer);
             buffer0_hva = gva2hva(buffer0);
             buffer1_hva = gva2hva(buffer1);
             buffer2_hva = gva2hva(buffer2);


            memset((PVOID)descBuffer_hva, 0, 0x1000);
            memset((PVOID)entityBuffer_hva, 0, 0x1000);
            memset((PVOID)buffer0_hva, 0, 0x1000);
            memset((PVOID)buffer1_hva, 0, 0x1000);
            memset((PVOID)buffer2_hva, 0, 0x1000);


            const GUID ID3D11DeviceVar = { 0xdb6f6ddb, 0xac77, 0x4e88, 0x82, 0x53, 0x81, 0x9d, 0xf9, 0xbb, 0xf1, 0x40 };

            memcpy((PVOID)descBuffer_hva, &ID3D11DeviceVar, sizeof(GUID));


            auto ret = (UINT64)CallUser(GetVFunc(swapChain, 7), swapChain, descBuffer, entityBuffer);

            if (ret != 0) { return; }

            device = *(PVOID*)entityBuffer_hva;


            ret = (UINT64)CallUser(GetVFunc(device, 40), device, entityBuffer);
            if (FAILED(ret))
            {
                context = *(PVOID*)entityBuffer_hva;
                LOG_INFO(_XOR_("context = %p\n"), context);
                LOG_INFO(_XOR_("GetImmediateContext failed  error ret = %p\n"), ret);

            }
            else {
                context = *(PVOID*)entityBuffer_hva;
                LOG_INFO(_XOR_("context = %p\n"), context);
            }



            const GUID ID3D11Texture2DVar = { 0x6f15aaf2, 0xd208, 0x4e89, 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c };
            RtlCopyMemory(descBuffer_hva, &ID3D11Texture2DVar, sizeof(ID3D11Texture2DVar));
            ret = (ULONG64)CallUser(GetVFunc(swapChain, 9), swapChain, 0, descBuffer, entityBuffer);
            if (FAILED(ret)) { return; }

            surface = *(PVOID*)entityBuffer_hva;

            if (!fakeTexture) {


                fakeTexture = CreateTexture3();
            }

            if (!backTexture) {

              
                fakeTexture = CreateTexture3();

            }

            Release(surface);
            Release(device);
            Release(context);
           
            

         //06152247-6f50-465a-9245-118bfd3b6007
            const GUID ID2D1FactoryVar = { 0x06152247,0x6f50,0x465a,0x92,0x45,0x11,0x8b,0xfd,0x3b,0x60,0x07 };
            RtlCopyMemory(descBuffer_hva, &ID2D1FactoryVar, sizeof(GUID));
            ret = (ULONG64)CallUser(D2D1CreateFactory, (ULONG64)0, descBuffer, (ULONG64)0, entityBuffer);
            if (FAILED(ret)) { return; }

            d2dFactory = *(PVOID*)entityBuffer_hva;



            const GUID IDXGISurfaceVar = { 0xcafcb56c, 0x6ac3, 0x4889, 0xbf, 0x47, 0x9e, 0x23, 0xbb, 0xd2, 0x60, 0xec };
            RtlCopyMemory(descBuffer_hva, &IDXGISurfaceVar, sizeof(IDXGISurfaceVar));
            ret = (ULONG64)CallUser(GetVFunc(swapChain, 9), swapChain, (ULONG64)0, descBuffer, entityBuffer);
            if (FAILED(ret)) { return; }
            d2dSurface = *(PVOID*)entityBuffer_hva;


            D2D1_PIXEL_FORMAT format;
            format.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
            format.format = DXGI_FORMAT_UNKNOWN;

            D2D1_RENDER_TARGET_PROPERTIES props;
            props.dpiX = 0;
            props.dpiY = 0;
            props.usage = D2D1_RENDER_TARGET_USAGE_NONE;
            props.minLevel = D2D1_FEATURE_LEVEL_DEFAULT;
            props.type = D2D1_RENDER_TARGET_TYPE_DEFAULT;
            props.pixelFormat = format;
            RtlCopyMemory(descBuffer_hva, &props, sizeof(D2D1_RENDER_TARGET_PROPERTIES));
            ret = (ULONG64)CallUser(GetVFunc(d2dFactory, 15), d2dFactory, d2dSurface, descBuffer, entityBuffer);

            if (FAILED(ret)) { return; }


            d2dRenderTarget = *(PVOID*)entityBuffer_hva;


            D2D1_COLOR_F color_brush = ColorF(ColorF::Red);

            RtlCopyMemory(descBuffer_hva, &color_brush, sizeof(D2D1_COLOR_F));
            ret = (ULONG64)CallUser(GetVFunc(d2dRenderTarget, 8), d2dRenderTarget, descBuffer, (ULONG64)0, entityBuffer);

            colorBrush = *(PVOID*)entityBuffer_hva;



            //b859ee5a-d838-4b5b-a2e8-1adc7d93db48"
            const GUID IDWriteFactoryVar = { 0xb859ee5a,0xd838,0x4b5b,0xa2,0xe8,0x1a,0xdc,0x7d,0x93,0xdb,0x48 };
            RtlCopyMemory(descBuffer_hva, &IDWriteFactoryVar, sizeof(GUID));
            ret = (ULONG64)CallUser(DWriteCreateFactory, (ULONG64)0, descBuffer, entityBuffer);

            if (FAILED(ret)) { return; }

            dwriteFactory = *(PVOID*)entityBuffer_hva;

            const WCHAR* fonName = _XOR_(L"微锟斤拷锟脚猴拷");
            const WCHAR* fonArea = _XOR_(L"zh-CN");



            //const WCHAR* className = L"UnityWndClass";
            //const WCHAR* windowName = L"Saffron Fields";
            RtlCopyMemory(descBuffer_hva, fonName, (wcslen(fonName) + 1) * 2);
            RtlCopyMemory((PUCHAR)descBuffer_hva + 0x100, fonArea, (wcslen(fonArea) + 1) * 2);

            // 锟斤拷锟斤拷锟斤拷通锟侥憋拷锟斤拷式
            ret = (ULONG64)CallUser(GetVFunc(dwriteFactory, 15), dwriteFactory,
                (ULONG64)(char*)descBuffer,  // fontFamilyName
                (ULONG64)0,           // fontCollection
                (ULONG64)400,
                (ULONG64)0,
                (ULONG64)3,
                14.0f,       // fontSize
                (ULONG64)(char*)descBuffer + 0x100,    // localeName
                entityBuffer);

            if (FAILED(ret)) { return; }
            TextFormat = *(PVOID*)entityBuffer_hva;



            // 锟斤拷锟斤拷锟斤拷锟斤拷谋锟斤拷锟斤拷?
            ret = (ULONG64)CallUser(GetVFunc(dwriteFactory, 15), dwriteFactory,
                (ULONG64)(char*)descBuffer,  // fontFamilyName
                (ULONG64)0,           // fontCollection
                (ULONG64)200,
                (ULONG64)0,
                (ULONG64)3,
                20.0f,       // fontSize
                (ULONG64)(char*)descBuffer + 0x100,    // localeName
                entityBuffer);

            if (FAILED(ret)) { return; }
            BigTextFormat = *(PVOID*)entityBuffer_hva;




            game::GameCenterW = (ULONG64)CallUser(GetSystemMetrics, 0);
            game::GameCenterH = (ULONG64)CallUser(GetSystemMetrics, 1);
            game::GameCenterX = game::GameCenterW / 2;
            game::GameCenterY = game::GameCenterH / 2;


            hv::CallUser(RtlQueryPerformanceFrequency, (LARGE_INTEGER*)buffer0);
               
            RtlCopyMemory(&perf_frequency, buffer0_hva, sizeof(INT64));

            sjz::gameData.isStartMove = false;
            sjz::vtAimInfo.targetX = 0;
            sjz::vtAimInfo.targetY = 0;

            isUse = false;
            isFinish = true;

            sjz::InitMenu();
            g_ghv->diag_init_done_count++;

            // Build the marker texture: a separate ID3D11Texture2D, cleared to
            // bright magenta via ClearRenderTargetView, never refreshed. This
            // is what we hand back to alien (anti-cheat) GetBuffer callers in
            // place of the real backbuffer. If a captured frame is solid
            // magenta, the hook substitution worked.
            if (!markerTexture) {
                markerTexture = CreateTexture3();
                if (markerTexture) {
                    // CreateRenderTargetView: ID3D11Device vfunc[9].
                    // params: this, pResource, pDesc=NULL, ppRTView
                    RtlZeroMemory(entityBuffer_hva, 0x1000);
                    auto rv_ret = (ULONG64)CallUser(GetVFunc(device, 9),
                        device, markerTexture, (ULONG64)0, entityBuffer);
                    if (!FAILED(rv_ret)) {
                        auto rtv = *(PVOID*)entityBuffer_hva;
                        if (rtv) {
                            // ClearRenderTargetView: ID3D11DeviceContext vfunc[50].
                            // params: this, pRenderTargetView, ColorRGBA[4]
                            // RGBA = (1.0, 0.0, 1.0, 1.0) = magenta
                            float color[4] = { 1.0f, 0.0f, 1.0f, 1.0f };
                            RtlCopyMemory(descBuffer_hva, color, sizeof(color));
                            CallUser(GetVFunc(context, 50), context, rtv, descBuffer);
                            Release(rtv);
                            g_ghv->diag_marker_ready = 1;  // observable from overlay
                        }
                    }
                }
            }

            // Stage 锟?-B: vfunc capture DISABLED 锟? both CopyResource (hook
            // freezes DWM regardless of handler logic, even pure observation
            // mode) and DuplicateOutput (GetContainingOutput hv::CallUser hangs
            // on DWM swap chains) need fundamentally different approaches.
            // GetBuffer/Present/Present1 hooks remain active.
        }


        bool isFirstRunAfterShot = false;



        PVOID CreateTexture() {


            auto texture = fakeTexture;

            // Do NOT clear fakeTexture: multiple anti-screenshot handlers
            // (GetBuffer / CopyResource / AcquireNextFrame) need to return
            // the same pointer. fakeTexture lifetime managed by tick()
            // (CopyResource refresh every 300ms; CreateTexture3 only when null).
            //fakeTexture = nullptr;

            isUse = true;




            isFirstRunAfterShot = true;

            isScreenShot = true;

            sjz::screenCount++;

            return texture;
            //return nullptr;
        }

        // Anti-screenshot helper: read fakeTexture without consuming or counting.
        // Used by Present / CopyResource / AcquireNextFrame alien handlers.
        PVOID GetFakeTexture() {
            return fakeTexture;
        }

        // Anti-screenshot marker: returned to alien GetBuffer callers.
        // Pre-cleared to solid magenta in render::init. A captured frame
        // consisting of solid magenta confirms our GetBuffer hook successfully
        // substituted the backbuffer for an injected anti-cheat thread.
        PVOID GetMarkerTexture() {
            return markerTexture;
        }

        void CreateTexture2() {


          
            isFirstRunAfterShot = true;

            isScreenShot = true;

            sjz::screenCount2++;


        }

    

       

        INT64 lastTime;
        void tick(vcpu* cpu) {

            g_ghv->diag_tick_count++;

            if (game::isEnd) {



            }

           

            if (isUse) {

                if (!fakeTexture) {

                    fakeTexture = CreateTexture3();
                    if (fakeTexture) {
                        isUse = false;
                    }

                }
            }

           


            do {

                if (!game::isEnd) {


                    if (fakeTexture) {

                        UINT64 time;
                        hv::CallUser(RtlQueryPerformanceCounter, (LARGE_INTEGER*)hv::descBuffer);
                        RtlCopyMemory(&time, hv::descBuffer_hva, sizeof(UINT64));

                        auto durationTime = ((time - lastCopyTime) * 1000 / hv::perf_frequency);

                        if (durationTime < 1000) {

                            break;
                        }

                        hv::CallUser(GetVFunc(context, 47), context, fakeTexture, surface);


                        lastCopyTime = time;

                    }
                    else {
                        fakeTexture = CreateTexture3();
                    }
                }
                else {
                    if (fakeTexture) {

                        UINT64 time;
                        hv::CallUser(RtlQueryPerformanceCounter, (LARGE_INTEGER*)hv::descBuffer);
                        RtlCopyMemory(&time, hv::descBuffer_hva, sizeof(UINT64));

                        auto durationTime = ((time - lastCopyTime) * 1000 / hv::perf_frequency);

                        if (durationTime < 1000) {

                            break;
                        }

                        hv::CallUser(GetVFunc(context, 47), context, fakeTexture, surface);

                        lastCopyTime = time;

                    }
                    else {
                        fakeTexture = CreateTexture3();
                    }

                }




            } while (0);

           

           

       

            if (isScreenShot)
            {

                if (isFirstRunAfterShot) {
                    UINT64 time;
                    hv::CallUser(RtlQueryPerformanceCounter, (LARGE_INTEGER*)hv::descBuffer);
                    RtlCopyMemory(&time, hv::descBuffer_hva, sizeof(UINT64));

                    startScreenTime = time;
                    isFirstRunAfterShot = false;
                }


                UINT64 time;
                hv::CallUser(RtlQueryPerformanceCounter, (LARGE_INTEGER*)hv::descBuffer);
                RtlCopyMemory(&time, hv::descBuffer_hva, sizeof(UINT64));

                auto durationTime = ((time - startScreenTime) * 1000 / hv::perf_frequency);

                if (durationTime < 5000) {

                    return;
                }
                isScreenShot = false;
                return;
            }
  


            if (d2dRenderTarget) {



                //wchar_t str1[256];

                //wchar_t* str = (WCHAR*)_XOR_(L"123123");
                //memset(buffer0_hva, 0, 0x1000);
                //memset(buffer1_hva, 0, 0x1000);

                //memcpy(buffer0_hva, str, wcslen(str) * 2 + 2);
                //memcpy((char*)buffer0_hva + 0x100, _XOR_(L"123123"), wcslen(_XOR_(L"123123")) * 2 + 2);
                //hv::CallUser(StringCbPrintfW, buffer1, (ULONG64)0x100, buffer0);
                //memcpy(str1, buffer1_hva, 0x200);


                //DrawCenterText(1000, 1000, ImVec4(255, 255, 255, 255), str1);






                if (!game::hideDraw && !game::overlay_should_hide()) {

                    g_ghv->diag_tick_draw_count++;
                    CallUser(GetVFunc(d2dRenderTarget, 48), d2dRenderTarget);


                    // BISECT minimal tick: BeginDraw + 1 line of text + EndDraw.
                    // No DrawFilledRect, no second/third lines, no sjz menu, no
                    // DrawMain 锟? to isolate whether DWM still crashes with the
                    // smallest possible D2D workload per frame.

                    // Heartbeat: single line shows tick counter + dwm hits.
                    DrawNewTextDebug(20, 2, ImVec4(0.0f, 1.0f, 0.0f, 1.0f),
                        (wchar_t*)L"YVT alive  frame=%llu  dwm_hits=%llu  init=%llu/%llu",
                        g_ghv->diag_tick_count, g_ghv->dwm_hit_count,
                        g_ghv->diag_init_enter_count, g_ghv->diag_init_done_count);

#if !VT_MINIMAL_PMO_HUD
                    DrawNewTextDebug(20, 322, ImVec4(0.2f, 1.0f, 0.2f, 1.0f),
                        (wchar_t*)L"sjz_pmo hit=%llu run=%llu ok=%llu last=%llu stage=%llu pid=%llu cr3=0x%llX",
                        sjz::pmoValidation.pmoHits,
                        sjz::pmoValidation.validateRuns,
                        sjz::pmoValidation.okRuns,
                        sjz::pmoValidation.lastOk,
                        sjz::pmoValidation.failStage,
                        sjz::pmoValidation.pid,
                        sjz::pmoValidation.cr3);

                    DrawNewTextDebug(20, 338, ImVec4(0.2f, 1.0f, 0.2f, 1.0f),
                        (wchar_t*)L"uw=0x%llX lv=0x%llX actors=0x%llX cnt=%d lp=0x%llX key=0x%llX",
                        sjz::pmoValidation.gworld,
                        sjz::pmoValidation.ulevel,
                        sjz::pmoValidation.actorArray,
                        sjz::pmoValidation.actorCount,
                        sjz::pmoValidation.localPlayer,
                        sjz::pmoValidation.key);

                    // Cross-vCPU diagnostics: counts hv::CallUser cleanup paths.
                    // same = entry vCPU == cleanup vCPU (normal); cross = scheduler
                    // migrated guest thread mid-call (lazy-restore fallback).
                    // wait = mark spin-waited on pending_state cmpxchg.
                    DrawNewTextDebug(20, 18, ImVec4(1.0f, 0.6f, 0.0f, 1.0f),
                        (wchar_t*)L"same=%llu cross=%llu wait=%llu",
                        g_ghv->diag_same_vcpu_call, g_ghv->diag_cross_vcpu_call,
                        g_ghv->diag_pending_overwrite_wait);

                    // Lazy-restore failure mode: timeout = mark gave up after
                    // 5ms; leaked = stack node not returned to pool (entry
                    // vCPU's VMCS still references it). Both should stay 0;
                    // any sustained growth means pool is bleeding and DWM
                    // will eventually hang (32 slots).
                    DrawNewTextDebug(20, 34, ImVec4(1.0f, 0.2f, 0.2f, 1.0f),
                        (wchar_t*)L"timeout=%llu leaked=%llu bp_miss=%llu",
                        g_ghv->diag_mark_timeout, g_ghv->diag_leaked_node,
                        g_ghv->diag_bp_miss);

                    // Anti-screenshot hook hit counters. Format "total/alien".
                    // - gb = GetBuffer (must be non-zero, DWM calls each frame)
                    // - pr = Present
                    // - p1 = Present1
                    // alien fires mean an injected anti-cheat thread is trying
                    // to capture; we returned E_FAIL / DEVICE_RESET.
                    DrawNewTextDebug(20, 50, ImVec4(0.2f, 0.8f, 1.0f, 1.0f),
                        (wchar_t*)L"gb=%llu/%llu pr=%llu/%llu p1=%llu/%llu mk=%llu",
                        g_ghv->diag_getbuffer_hits, g_ghv->diag_getbuffer_alien,
                        g_ghv->diag_present_hits, g_ghv->diag_present_alien,
                        g_ghv->diag_present1_hits, g_ghv->diag_present1_alien,
                        g_ghv->diag_marker_ready);

                    // Stage 锟?-B counters: cr = CopyResource, du = DuplicateOutput.
                    // cr fires every frame from DWM; du only fires when external
                    // capture tools (OBS / Snipping Tool / Xbox Bar) try to start.
                    // mmc = MmCopyMemory kernel hook hit count.
                    int mmc_state = g_ghv->mmcopy_install_attempted
                                    ? (g_ghv->mmcopy_install_result == 0 ? 1 : 2) : 0;
                    DrawNewTextDebug(20, 66, ImVec4(1.0f, 0.5f, 1.0f, 1.0f),
                        (wchar_t*)L"cr=%llu/%llu du=%llu/%llu mmc=%llu(s%d)",
                        g_ghv->diag_copyresource_hits, g_ghv->diag_copyresource_alien,
                        g_ghv->diag_duplicateoutput_hits, g_ghv->diag_duplicateoutput_alien,
                        g_ghv->diag_mmcopy_hits, mmc_state);

                    // GetBuffer install progress (Stage 鈶-from-handler).
                    // gb_inst: 1=hooked OK, 0=not yet. Stages: vt_pp/vt_hva/lock/i1/i2.
                    DrawNewTextDebug(20, 82, ImVec4(1.0f, 0.8f, 0.4f, 1.0f),
                        (wchar_t*)L"gb_inst=%d vt_pp=%d vt_hva=%d lock=%d i1=%d i2=%d retry=%llu",
                        (int)g_ghv->getbuffer_hook_installed,
                        (int)g_ghv->diag_gb_vt_pp_ok,
                        (int)g_ghv->diag_gb_vt_hva_ok,
                        (int)g_ghv->diag_gb_lock_called,
                        (int)g_ghv->diag_gb_install_first,
                        (int)g_ghv->diag_gb_install_second,
                        g_ghv->diag_getbuffer_install_retry);

                    // Anti-screenshot kernel hooks: total/alien per syscall +
                    // notify_capture_attempt count. nva=NtAllocateVM,
                    // npv=NtProtectVM, nmv=NtMapViewOfSection,
                    // nsc=NtCreateSection (image+blacklist hits). alien fires
                    // mean a DWM-resident thread allocated EXECUTE-class memory
                    // 鈫 overlay hide window extended 5s.
                    DrawNewTextDebug(20, 98, ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
                        (wchar_t*)L"nva=%llu/%llu npv=%llu/%llu nmv=%llu/%llu nsc=%llu/%llu hide=%llu",
                        g_ghv->diag_nt_alloc_hits, g_ghv->diag_nt_alloc_alien,
                        g_ghv->diag_nt_protect_hits, g_ghv->diag_nt_protect_alien,
                        g_ghv->diag_nt_map_hits, g_ghv->diag_nt_map_alien,
                        g_ghv->diag_nt_csec_image, g_ghv->diag_nt_csec_alien,
                        g_ghv->diag_capture_notify_count);

                    // Symbol-resolution diagnostic. Compare against WinDbg:
                    //   dq nt!NtAllocateVirtualMemory L1
                    // Expected first 3 bytes for fn body: 48 8B C4 (mov rax,rsp).
                    // If first8 != WinDbg value, PDB returned wrong offset.
                    DrawNewTextDebug(20, 114, ImVec4(0.4f, 1.0f, 0.4f, 1.0f),
                        (wchar_t*)L"NtAllocVA=0x%llX bytes=0x%016llX",
                        g_ghv->diag_nt_alloc_resolved_va,
                        g_ghv->diag_nt_alloc_first8);

                    // Mouse callback hook observation. This is read-only:
                    // handler records MouClass callback args and first movement
                    // packet, but does not mutate LastX/LastY.
                    DrawNewTextDebug(20, 130, ImVec4(0.6f, 1.0f, 1.0f, 1.0f),
                        (wchar_t*)L"mouse inst=%d att=%d res=%d tgt=0x%llX hit=%llu pkt=%llu bad=%llu",
                        (int)g_ghv->mouse_callback_hook_installed,
                        (int)g_ghv->mouse_callback_install_attempted,
                        (int)g_ghv->mouse_callback_install_result,
                        g_ghv->diag_mouse_cb_target_va,
                        g_ghv->diag_mouse_cb_hits,
                        g_ghv->diag_mouse_cb_packets,
                        g_ghv->diag_mouse_cb_bad_args);

                    DrawNewTextDebug(20, 146, ImVec4(0.6f, 1.0f, 1.0f, 1.0f),
                        (wchar_t*)L"mouse dev=0x%llX exp=0x%llX cnt=%llu mis=%llu",
                        g_ghv->diag_mouse_cb_last_device,
                        g_ghv->diag_mouse_cb_expected_device,
                        g_ghv->diag_mouse_cb_last_count,
                        g_ghv->diag_mouse_cb_device_mismatch);

                    DrawNewTextDebug(20, 162, ImVec4(0.6f, 1.0f, 1.0f, 1.0f),
                        (wchar_t*)L"mouse mv=%llu zero=%llu flags=0x%llX raw=(%lld,%lld)",
                        g_ghv->diag_mouse_cb_movement_packets,
                        g_ghv->diag_mouse_cb_zero_packets,
                        g_ghv->diag_mouse_cb_last_flags,
                        g_ghv->diag_mouse_cb_last_raw_x,
                        g_ghv->diag_mouse_cb_last_raw_y);

                    DrawNewTextDebug(20, 178, ImVec4(0.6f, 1.0f, 1.0f, 1.0f),
                        (wchar_t*)L"mouse ret=0x%llX",
                        g_ghv->diag_mouse_cb_return_va);

                    DrawNewTextDebug(20, 194, ImVec4(1.0f, 0.8f, 0.4f, 1.0f),
                        (wchar_t*)L"mouhid inst=%d att=%d res=%d sig=%d tgt=0x%llX hit=%llu",
                        (int)g_ghv->mouhid_pre_hook_installed,
                        (int)g_ghv->mouhid_pre_install_attempted,
                        (int)g_ghv->mouhid_pre_install_result,
                        (int)g_ghv->mouhid_pre_signature_ok,
                        g_ghv->diag_mouhid_pre_target_va,
                        g_ghv->diag_mouhid_pre_hits);

                    DrawNewTextDebug(20, 210, ImVec4(1.0f, 0.8f, 0.4f, 1.0f),
                        (wchar_t*)L"mouhid cb=0x%llX cnt=%llu pkt=%llu mv=%llu bad=%llu ef=%llu raw=(%lld,%lld)",
                        g_ghv->diag_mouhid_pre_callback_va,
                        g_ghv->diag_mouhid_pre_last_count,
                        g_ghv->diag_mouhid_pre_packets,
                        g_ghv->diag_mouhid_pre_movement_packets,
                        g_ghv->diag_mouhid_pre_bad_args,
                        g_ghv->diag_mouhid_pre_emulate_fail,
                        g_ghv->diag_mouhid_pre_last_raw_x,
                        g_ghv->diag_mouhid_pre_last_raw_y);

                    DrawNewTextDebug(20, 226, ImVec4(0.4f, 1.0f, 0.6f, 1.0f),
                        (wchar_t*)L"mhid->hid inst=%d att=%d res=%d sig=%d hit=%llu ef=%llu code=%llu hash=%llX",
                        (int)g_ghv->mouhid_down_hook_installed,
                        (int)g_ghv->mouhid_down_install_attempted,
                        (int)g_ghv->mouhid_down_install_result,
                        (int)g_ghv->mouhid_down_signature_ok,
                        g_ghv->diag_mouhid_down_hits,
                        g_ghv->diag_mouhid_down_emulate_fail,
                        g_ghv->diag_mouhid_down_known_code,
                        g_ghv->diag_mouhid_down_name_hash);

                    DrawNewTextDebug(20, 242, ImVec4(0.4f, 1.0f, 0.6f, 1.0f),
                        (wchar_t*)L"mhid low dev=0x%llX drv=0x%llX base=0x%llX size=0x%llX",
                        g_ghv->diag_mouhid_down_lower_device,
                        g_ghv->diag_mouhid_down_lower_driver,
                        g_ghv->diag_mouhid_down_driver_base,
                        g_ghv->diag_mouhid_down_driver_size);

                    DrawNewTextDebug(20, 258, ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                        (wchar_t*)L"hidusb->low inst=%d att=%d res=%d sig=%d hit=%llu ef=%llu code=%llu hash=%llX",
                        (int)g_ghv->hidusb_down_hook_installed,
                        (int)g_ghv->hidusb_down_install_attempted,
                        (int)g_ghv->hidusb_down_install_result,
                        (int)g_ghv->hidusb_down_signature_ok,
                        g_ghv->diag_hidusb_down_hits,
                        g_ghv->diag_hidusb_down_emulate_fail,
                        g_ghv->diag_hidusb_down_known_code,
                        g_ghv->diag_hidusb_down_name_hash);

                    DrawNewTextDebug(20, 274, ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                        (wchar_t*)L"hidusb low dev=0x%llX drv=0x%llX base=0x%llX size=0x%llX",
                        g_ghv->diag_hidusb_down_lower_device,
                        g_ghv->diag_hidusb_down_lower_driver,
                        g_ghv->diag_hidusb_down_driver_base,
                        g_ghv->diag_hidusb_down_driver_size);

                    DrawNewTextDebug(20, 290, ImVec4(1.0f, 0.6f, 1.0f, 1.0f),
                        (wchar_t*)L"hidusb comp inst=%d att=%d res=%d sig=%d hit=%llu bad=%llu st=%08llX len=%llu",
                        (int)g_ghv->hidusb_comp_hook_installed,
                        (int)g_ghv->hidusb_comp_install_attempted,
                        (int)g_ghv->hidusb_comp_install_result,
                        (int)g_ghv->hidusb_comp_signature_ok,
                        g_ghv->diag_hidusb_comp_hits,
                        g_ghv->diag_hidusb_comp_bad_args,
                        g_ghv->diag_hidusb_comp_status,
                        g_ghv->diag_hidusb_comp_len);

                    DrawNewTextDebug(20, 306, ImVec4(1.0f, 0.6f, 1.0f, 1.0f),
                        (wchar_t*)L"hidusb buf=0x%llX mdl=0x%llX rd=%llu b8=%016llX",
                        g_ghv->diag_hidusb_comp_buf,
                        g_ghv->diag_hidusb_comp_mdl,
                        g_ghv->diag_hidusb_comp_read_bytes,
                        g_ghv->diag_hidusb_comp_first8);

                    // DWM bisect: 娓告垙鑿滃崟/涓氬姟缁樺埗鍏堝叧闂锛岄伩鍏 PMO tick
                    // 杩涘叆 sjz::DrawMain -> update_addr/GetData/WorldToScreen 閾俱

#endif // !VT_MINIMAL_PMO_HUD

                    CallUser(GetVFunc(d2dRenderTarget, 49), d2dRenderTarget, 0ull, 0ull);
                    g_ghv->diag_tick_end_count++;


                }
               


            }


        }

        void reset(vcpu* cpu)
        {




        }


#pragma code_seg()
}
