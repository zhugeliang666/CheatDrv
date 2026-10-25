#include "input.h"
#include "internal.h"
#include "coord_cache.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"

namespace sjz {

#pragma code_seg(".vm")

	// Module-private debounce state. Each flag is "true while the
	// corresponding key is currently held"; toggles fire on the rising edge.
	bool isF2Down       = false;
	bool bDwom          = false;
	bool isHeadDown     = false;
	bool isCampDown     = false;
	bool isMiddleDown   = false;
	bool f3dwom         = false;
	bool isCamp         = false;

	void UpdateKeys()
	{

		if (IsKeyDown(VK_F2))
		{
			if (!isF2Down) {
				isF2Down = true;
				if (isStart) {


					isStart = false;
					isBegin = false;

					game::isEnd = true;
					game::GamePid = 0;
					ClearCoordHookCache();
					memset(&gameData, 0, sizeof(gameData));
					game::Reset();


				}
				else {
					ClearCoordHookCache();
					isBegin = true;
					isStart = true;
				}

			}

		}
		else {
			isF2Down = false;
		}


		if (IsKeyDown(VK_OEM_3)) {

			if (!bDwom) {
				bDwom = true;

				menu::isBattleMode = !menu::isBattleMode;
			}

		}
		else {
			bDwom = false;
		}

		if (IsKeyDown(VK_LMENU) && IsKeyDown(0x31)) {

			if (!f3dwom) {
				f3dwom = true;

				menu::isAim = !menu::isAim;
				gameData.isStartMove = false;
			}

		}
		else {
			f3dwom = false;
		}

		if (IsKeyDown(VK_LMENU) && IsKeyDown(0x32)) {

			if (!isHeadDown) {
				isHeadDown = true;

				menu::isHead = !menu::isHead;
			}

		}
		else {
			isHeadDown = false;
		}

		if (IsKeyDown(VK_LMENU) && IsKeyDown(0x33)) {

			if (!isCampDown) {
				isCampDown = true;

				isCamp = !isCamp;
			}

		}
		else {
			isCampDown = false;
		}

		if (IsKeyDown(VK_MBUTTON)) {

			if (!isMiddleDown) {
				isMiddleDown = true;

				menu::isAim = !menu::isAim;
			}

		}
		else {
			isMiddleDown = false;
		}
	}

#pragma code_seg()

} // namespace sjz
