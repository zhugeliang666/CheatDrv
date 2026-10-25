#pragma once
#include <fltKernel.h>

namespace dwm {

	struct dwm_module_range {
		ULONG64 start;
		ULONG64 end;
	};

	extern dwm_module_range g_dwm_legit_ranges[2];
	extern volatile LONG g_dwm_legit_ranges_initialized;

	void init_dwm_legit_ranges_lazy();
	bool caller_is_legit_dwm(ULONG64 rip);
	bool caller_is_legit_dwm_strict(ULONG64 rip);

}
