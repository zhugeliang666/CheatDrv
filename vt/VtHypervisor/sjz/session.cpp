#include "session.h"
#include "internal.h"
#include "coord_cache.h"
#include "../vt/hv.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"

namespace sjz {

#pragma code_seg(".vm")
	static constexpr WCHAR kDebugTargetWindowClass[] = L"UnrealWindow";
	static constexpr WCHAR kDebugTargetWindowName[]  = L"__________  ";

	// Lifecycle flags ___ owned here. Read by scan/draw/aim/input.
	bool isStart = false;
	bool isBegin = false;

	bool GameInit()
	{

		//__________
		gameData.key = 0;
		game::gameProcess = 0;

		


		if (game::isExiting)
		{
			auto pid = GetGamePidByWindow((WCHAR*)kDebugTargetWindowClass, (WCHAR*)kDebugTargetWindowName);

			if (pid == 0)  game::isExiting = false;

			else return false;


		}

	
		if (isStart) {

			if (!game::GamePid) {
				game::GamePid = GetGamePidByWindow((WCHAR*)kDebugTargetWindowClass, (WCHAR*)kDebugTargetWindowName);



				if (!game::GamePid) return false;


				uint64_t cr3 = 0;

				// PID of the process to get the CR3 value of
				auto const target_pid = game::GamePid;

				// ActiveProcessLinks is right after UniqueProcessId in memory
				auto const apl_offset = hv::g_ghv->eprocess_unique_process_id_offset + 8;
				auto const head = hv::g_ghv->system_eprocess + apl_offset;
				auto curr_entry = head;

				// iterate over every EPROCESS in the APL linked list
				do {
					// get the next entry in the linked list
					if (sizeof(curr_entry) != hv::read_guest_virtual_memory(hv::g_ghv->system_cr3,
						curr_entry + offsetof(LIST_ENTRY, Flink), &curr_entry, sizeof(curr_entry)))
						return false;

					// EPROCESS
					auto const process = curr_entry - apl_offset;

					// EPROCESS::UniqueProcessId
					uint64_t pid = 0;
					if (sizeof(pid) != hv::read_guest_virtual_memory(hv::g_ghv->system_cr3,
						process + hv::g_ghv->eprocess_unique_process_id_offset, &pid, sizeof(pid)))
						return false;

					// we found the target process
					if (target_pid == pid) {
						// EPROCESS::DirectoryTableBase
						
						if (sizeof(cr3) != hv::read_guest_virtual_memory(hv::g_ghv->system_cr3,
							process + g_yvt.NtapiOffsets.DirectoryTableBase, &cr3, sizeof(cr3)))
						{

							return false;
						}
						
						game::gameProcess = (PEPROCESS)process;
						game::GameCr3 = cr3 & (~0xfffull);

						
						break;

					}
				} while (curr_entry != head);


			}




			game::GameNULL = 0x140000000;

			
			


			game::isFindingGame = false;
			game::isEnd  = false;
		}


		return true;
	}


	void Reset()
	{

		

		if (game::GameCr3)
		{
			isStart = false;
			game::GameCr3 = 0;
			ClearCoordHookCache();
			memset(&gameData, 0, sizeof(gameData));
			game::gameProcess = 0;
			game::GamePid = 0;
			gameData.key = 0;

		}

	}

#pragma code_seg()

} // namespace sjz
