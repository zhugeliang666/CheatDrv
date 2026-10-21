#include "caller_filter.h"
#include "../common/ntutils.h"
#include "../vt/mm.h"

#pragma code_seg(".vm")

namespace dwm {

	dwm_module_range g_dwm_legit_ranges[2] = {};
	volatile LONG g_dwm_legit_ranges_initialized = 0;

	void init_dwm_legit_ranges_lazy()
	{
		if (g_dwm_legit_ranges_initialized) return;
		if (_InterlockedExchange(&g_dwm_legit_ranges_initialized, 1) != 0) return;

		if (g_yvt.dwmcoreInfo.imageBase && g_yvt.dwmcoreInfo.imageSize) {
			g_dwm_legit_ranges[0].start = (ULONG64)g_yvt.dwmcoreInfo.imageBase;
			g_dwm_legit_ranges[0].end = (ULONG64)g_yvt.dwmcoreInfo.imageBase + g_yvt.dwmcoreInfo.imageSize;
		}
		if (g_yvt.dxgiInfo.imageBase && g_yvt.dxgiInfo.imageSize) {
			g_dwm_legit_ranges[1].start = (ULONG64)g_yvt.dxgiInfo.imageBase;
			g_dwm_legit_ranges[1].end = (ULONG64)g_yvt.dxgiInfo.imageBase + g_yvt.dxgiInfo.imageSize;
		}
	}

	bool caller_is_legit_dwm(ULONG64 rip)
	{
		init_dwm_legit_ranges_lazy();
		if (!g_dwm_legit_ranges[0].start && !g_dwm_legit_ranges[1].start) return true;

		for (auto& r : g_dwm_legit_ranges) {
			if (r.start && rip >= r.start && rip < r.end) return true;
		}
		return false;
	}

	static bool prev_byte_is_call_target(ULONG64 rip)
	{
		if (rip < 8) return true;

		unsigned char* p = (unsigned char*)hv::gva2hva((void*)(rip - 7));
		if (!p) return true;

		if (p[2] == 0xE8) return true;

		if (p[1] == 0xFF && p[2] == 0x15) return true;
		if (p[1] == 0xFF && p[2] == 0x90) return true;
		if ((p[0] & 0xF0) == 0x40 && p[1] == 0xFF && (p[2] == 0x15 || p[2] == 0x90)) return true;

		if (p[4] == 0xFF) {
			unsigned char m = p[5];
			if ((m & 0xF8) == 0xD0) return true;
			if ((m & 0xC7) == 0x50) return true;
			if ((m & 0xC7) == 0x10) return true;
		}

		if (p[5] == 0xFF) {
			unsigned char m = p[6];
			if ((m & 0xF8) == 0xD0) return true;
			if ((m & 0xC7) == 0x50) return true;
			if ((m & 0xC7) == 0x10) return true;
		}

		return false;
	}

	bool caller_is_legit_dwm_strict(ULONG64 rip)
	{
		if (!caller_is_legit_dwm(rip)) return false;
		return prev_byte_is_call_target(rip);
	}

}
