#pragma once
#include "fltKernel.h"
#include "../common/ntutils.h"
#include "../common/ntapi.h"
#include "memory.h"
#include <ntstrsafe.h>
#include <sjz/sjz.h>


#define FAILED(hr) (((HRESULT)(hr)) < 0)

namespace hv {
	struct RENDERINFO;
	using RenderInfo = RENDERINFO;
}




namespace game {


	struct CM_INFO {
		UINT64 type;
		union {

			PVOID count;
			PVOID swapChain;
			PVOID key;
			PVOID fakeTexture;
			PEPROCESS process;
			sjz::AimInfo* aimInfo;
			PVOID mouse_event;
			hv::RenderInfo* renderInfo;
		}data;
	};

	extern bool isF3Down;
	extern bool hideDraw;

	extern bool isEnd;

	extern 	bool isExiting;

	extern bool  isFindingGame;

	extern PEPROCESS gameProcess;
	extern ULONG64 GamePid;
	extern DWORD64 GameCr3;
	extern uint64_t GameNULL;

	extern ULONG GameCenterW;
	extern ULONG GameCenterH;
	extern ULONG GameCenterX;
	extern ULONG GameCenterY;
	

	extern bool isUnSetHook;
	extern bool isSetHook;

	bool GameInit();

	void Reset();


	void DrawMenu();

	void DrawMain();

	void GetData();

	void UpdateKey();

	// Anti-screenshot overlay-hide window.
	// Set by notify_capture_attempt() (called from kernel-hook handlers when a
	// DWM-resident alien thread allocates / mprotects executable memory or maps
	// an image). Read by render::tick to skip BeginDraw/EndDraw block.
	// Deadline kept in TSC cycles (NOT KeTickCount) so both setter and reader
	// run safely from host root mode without any NT API.
	extern volatile LONG64 g_overlay_hide_until_tsc;
	extern ULONG64        g_overlay_hide_cycles;   // ~5 sec in TSC; init in main

	void init_overlay_hide_window();              // call once at driver init
	void notify_capture_attempt();                // CAS-max to extend hide window
	bool overlay_should_hide();                   // current TSC < hide_until?


}



