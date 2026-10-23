#pragma once
#include "fltKernel.h"
#include "intrin.h"
#include "caller_filter.h"
#include "trampoline_pool.h"

namespace dwm {

	typedef unsigned  long long ULOGN64;


	extern PVOID CDXGISwapChain;

#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))
#define RVA2(Instr, InstrSize, Off) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + Off))


	extern __int64(__fastcall* OriginalDxgkPresentMultiPlaneOverlay3)(PVOID a1);

	__int64 __fastcall HookedDxgkPresentMultiPlaneOverlay3(PVOID a1);


	VOID RemoveDwmHook();

	VOID InstallDwmHook();


	VOID Init();

	VOID UnInit();

	VOID Reset();


}
