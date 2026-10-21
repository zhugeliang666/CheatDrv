#include "trampoline_pool.h"
#include "../base.h"
#include "../hv/hv.h"
#include "../vt/hv.h"
#include <ntimage.h>

#pragma code_seg(".vm")

namespace dwm {

	static bool find_text_section(ULONG64 image_base,
	                              ULONG64& out_text_start,
	                              ULONG64& out_text_size)
	{
		__try {
			auto dos = (PIMAGE_DOS_HEADER)image_base;
			if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
			auto nt = (PIMAGE_NT_HEADERS)(image_base + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
			auto sec = IMAGE_FIRST_SECTION(nt);
			for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
				if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
				    sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
				    sec[i].Name[4] == 't' && sec[i].Name[5] == 0) {
					out_text_start = image_base + sec[i].VirtualAddress;
					out_text_size  = sec[i].Misc.VirtualSize;
					return true;
				}
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
		return false;
	}

	void bootstrap_tramp_pool(ULONG64 image_base, ULONG64 image_size, bool is_kernel)
	{
		constexpr ULONG MIN_RUN = hv::TRAMPOLINE_SLOT_BYTES;

		const ULONG MAX_SLOTS_PER_POOL = is_kernel ? hv::TRAMPOLINE_POOL_KERNEL_SLOTS : 2;
		const ULONG MAX_PAGES_PER_POOL = is_kernel ? hv::TRAMPOLINE_MAX_PAGES_PER_POOL : 2;
		const ULONG MAX_SLOTS_PER_PAGE = 1;
		const ULONG PAGE_STRIDE        = 0x2000;

		// _XOR_(...) returns a pointer into the _XORSTR_ temporary's stack
		// buffer. The temporary destructs at the end of the full-expression,
		// so memcpy MUST take the _XOR_ result directly (same expression) —
		// never assign it to const char* first.
		char tag[8] = {};
		if (is_kernel) memcpy(tag, _XOR_("TRAMP-K"), 7);
		else           memcpy(tag, _XOR_("TRAMP-U"), 7);

		ULONG64 text_start = 0, text_size = 0;
		if (!find_text_section(image_base, text_start, text_size)) {
			LOG_DEBUG(_XOR_("[%s] .text section not found in PE at 0x%llX\n"),
				tag, image_base);
			return;
		}
		LOG_DEBUG(_XOR_("[%s] .text at 0x%llX size=0x%llX\n"),
			tag, text_start, text_size);

		ULONG slots_registered = 0;
		ULONG pages_registered = 0;
		ULONG64 scan_end = text_start + text_size;
		for (ULONG64 page_va = text_start & ~0xFFFull;
		     page_va < scan_end;
		     page_va += PAGE_STRIDE)
		{
			if (slots_registered >= MAX_SLOTS_PER_POOL ||
			    pages_registered >= MAX_PAGES_PER_POOL)
				break;

			ULONG64 phys = MmGetPhysicalAddress((PVOID)page_va).QuadPart;
			if (!phys) continue;

			const uint8_t* bytes = (const uint8_t*)page_va;
			ULONG scan_lo = 0;
			ULONG scan_hi = 0x1000;
			if (page_va < text_start) scan_lo = (ULONG)(text_start - page_va);
			if (page_va + 0x1000 > scan_end) scan_hi = (ULONG)(scan_end - page_va);

			struct slot_info { ULONG off; ULONG len; };
			slot_info found[16];
			ULONG found_count = 0;
			__try {
				ULONG i = scan_lo;
				while (i < scan_hi && found_count < MAX_SLOTS_PER_PAGE) {
					if (bytes[i] != 0xCC) { i++; continue; }
					ULONG j = i;
					while (j < scan_hi && bytes[j] == 0xCC) j++;
					if (j - i >= MIN_RUN) {
						found[found_count].off = i;
						found[found_count].len = (j - i > 255) ? 255 : (j - i);
						found_count++;
					}
					i = j;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				continue;
			}
			if (found_count == 0) continue;

			phys = MmGetPhysicalAddress((PVOID)page_va).QuadPart;
			if (!phys) continue;
			ULONG64 orig_pfn = phys >> 12;

			if (!is_kernel) {
				PMDL mdl = IoAllocateMdl((PVOID)page_va, 0x1000, FALSE, FALSE, nullptr);
				if (mdl) {
					__try {
						MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
					} __except (EXCEPTION_EXECUTE_HANDLER) {
						IoFreeMdl(mdl);
						mdl = nullptr;
					}
				}
				phys = MmGetPhysicalAddress((PVOID)page_va).QuadPart;
				if (!phys) continue;
				orig_pfn = phys >> 12;
			}

			PVOID exec_page = hv::take_preallocated_tramp_page();
			if (!exec_page) {
				LOG_DEBUG(_XOR_("[%s] preallocated trampoline page pool exhausted\n"), tag);
				break;
			}
			ULONG64 exec_pfn = MmGetPhysicalAddress(exec_page).QuadPart >> 12;
			if (!exec_pfn) {
				LOG_DEBUG(_XOR_("[%s] exec_pfn=0 - abort\n"), tag);
				break;
			}

			int64_t pi = hv::vmcall_vh_tramp_add_page(
				orig_pfn, exec_pfn, page_va, (ULONG64)exec_page, is_kernel);
			if (pi < 0) {
				LOG_DEBUG(_XOR_("[%s] add_page FAIL\n"), tag);
				break;
			}
			pages_registered++;
			LOG_DEBUG(_XOR_("[%s] page #%lld va=0x%llX orig_pfn=0x%llX exec_pfn=0x%llX runs=%u\n"),
				tag, pi, page_va, orig_pfn, exec_pfn, found_count);

			for (ULONG k = 0; k < found_count; k++) {
				if (slots_registered >= MAX_SLOTS_PER_POOL) break;
				bool ok = hv::vmcall_vh_tramp_add_slot(
					(uint32_t)pi, found[k].off, found[k].len, is_kernel);
				if (!ok) {
					LOG_DEBUG(_XOR_("[%s] add_slot FAIL page=%lld off=0x%X len=%lu\n"),
						tag, pi, found[k].off, found[k].len);
					break;
				}
				slots_registered++;
				LOG_DEBUG(_XOR_("[%s] slot[%u] page=%lld off=0x%X len=%lu\n"),
					tag, slots_registered, pi, found[k].off, found[k].len);
			}
		}

		if (slots_registered > 0) {
			hv::vmcall_vh_tramp_set_ready(is_kernel);
			LOG_DEBUG(_XOR_("[%s] pool ready: %u slots / %u pages\n"),
				tag, slots_registered, pages_registered);
		} else {
			LOG_DEBUG(_XOR_("[%s] no qualifying 0xCC run found - pool NOT ready\n"), tag);
		}
	}

}
