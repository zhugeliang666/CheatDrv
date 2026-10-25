#include "gamecommon.h"
#include "../vt/hv.h"
#include <map>
#include <string.h>
#include"../sjz/sjz.h"
#include <windef.h>
#include "imconfig.h"
#include <intrin.h>

namespace game {


	bool isExiting = false;
	bool isFindingGame = true;
	PEPROCESS gameProcess;


	bool isF3Down = false;
	bool hideDraw = false;


	bool isEnd = true;
	ULONG64 GamePid;
	DWORD64 GameCr3;
	uint64_t GameNULL = NULL;

	ULONG GameCenterW;
	ULONG GameCenterH;
	ULONG GameCenterX;
	ULONG GameCenterY;

	bool isUnSetHook = false;
	bool isSetHook = false;

	// Anti-screenshot overlay-hide window state.
	// Deadline expressed in TSC cycles so notify_capture_attempt /
	// overlay_should_hide can run from host root mode (vm-exit handlers)
	// without calling any NT API. Window length cached at driver init.
	volatile LONG64 g_overlay_hide_until_tsc = 0;
	ULONG64        g_overlay_hide_cycles    = 0;

#pragma code_seg(".vm")

	bool GameInit()
	{



	
		return sjz::GameInit();
	}



	void Reset()
	{



		//rust::Reset();
		sjz::Reset();
		 
		game::gameProcess = 0;
		game::GameCr3 = 0;
		game::GameNULL = 0;
		game::GamePid = NULL;
		game::isFindingGame = true;
	

	}


	void DrawMain()
	{


		return sjz::DrawMain();
	

	}

	void GetData()
	{

	

		//return sjz::GetData();


	}

	void UpdateKey()
	{



		if (IsKeyDown(VK_F3) && IsKeyDown(VK_LMENU))
		{
			if (!isF3Down) {
				isF3Down = true;

				hideDraw = !hideDraw;

			}

		}
		else {
			isF3Down = false;
		}




		sjz::UpdateKeys();
		//rust::UpdateKeys();

		//fc25::UpdateKey();
	}


	void init_overlay_hide_window()
	{
		// 5 seconds in TSC cycles. Same 3 GHz nominal estimate as
		// hypercalls.cpp:684 pending_hide_tsc_threshold; off-by-25% on
		// non-3GHz hosts is fine 鈥 overlay hides 3.75鈥6.25s instead of 5s.
		// __rdtsc reads CPU MSR, callable from host root mode (vm-exit
		// handlers run with interrupts off and no NT API access).
		constexpr uint64_t kTscHz = 3'000'000'000ULL;
		g_overlay_hide_cycles = kTscHz * 5;
	}

	void notify_capture_attempt()
	{
		_InterlockedIncrement64((volatile LONG64*)&hv::g_ghv->diag_capture_notify_count);

		LONG64 target = (LONG64)(__rdtsc() + g_overlay_hide_cycles);

		// CAS-max: only extend the deadline forward, never shrink.
		LONG64 old;
		do {
			old = g_overlay_hide_until_tsc;
			if (target <= old) return;
		} while (_InterlockedCompareExchange64(&g_overlay_hide_until_tsc, target, old) != old);
	}

	bool overlay_should_hide()
	{
		return (LONG64)__rdtsc() < g_overlay_hide_until_tsc;
	}




}


