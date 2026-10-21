#include "menu.h"
#include "internal.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"
#include <gamecommon/draw.h>
#include "../xor.h"

namespace sjz {

#pragma code_seg(".vm")

	MenuState menuState = { 0 };
	static bool isInsertDown = false;

	MenuItem menuItems[] = {
		{ L"____NPC", MENU_ITEM_TOGGLE, &menu::isShowNpc, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isAim, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isHead, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isBox, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isSkeleton, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isHealth,nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isDistance, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isShowContainer, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isShowBox, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isShowDebugInfo, nullptr, 0, 0 },
		{ L"________", MENU_ITEM_TOGGLE, &menu::isShowItem, nullptr, 0, 0 },
		{L"________", MENU_ITEM_TOGGLE,& menu::isItemList, nullptr, 0, 0},
		{ L"________", MENU_ITEM_TOGGLE,& menu::isCenter, nullptr, 0, 0 }

	};
	void InitMenu() {
		menuState.items = menuItems;
		menuState.itemCount = sizeof(menuItems) / sizeof(menuItems[0]);
		menuState.selectedIndex = 0;
		menuState.isOpen = false;
		menuState.menuX = 10.0f;
		menuState.menuY = 200.0f;
		menuState.menuWidth = 200.0f;
		menuState.itemHeight = 25.0f;
		menuState.menuHeight = menuState.itemHeight * menuState.itemCount;
	}
	void DrawMenuItem(const MenuItem& item, float x, float y, float width, float height, bool isSelected) {
		ImVec4 bgColor = isSelected ? ImVec4(0.2f, 0.2f, 0.2f, 0.8f) : ImVec4(0.1f, 0.1f, 0.1f, 0.8f);
		ImVec4 textColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);

		// ________
		DrawFilledRect(x, y, width, height, bgColor, 0, 0);

		// ______________
		wchar_t displayText[256] = { 0 };
		wcscpy_s(displayText, item.name);

		// __________________________
		if (item.type == MENU_ITEM_TOGGLE && item.toggleValue) {
			wcscat_s(displayText, *item.toggleValue ? L" [__]" : L" [__]");
		}
		//else if (item.type == MENU_ITEM_SLIDER && item.sliderValue) {
		//	wchar_t sliderText[32];
		//	swprintf_s(sliderText, L" [%d]", (int)*item.sliderValue);
		//	wcscat_s(displayText, sliderText);
		//}

		// ________
		DrawNewText(x + 5, y + (height - 20) / 2, textColor, displayText);
	}
	void DrawMenu() {
		if (!menuState.isOpen) return;

		// ____________
		DrawFilledRect(menuState.menuX, menuState.menuY, 
					  menuState.menuWidth, menuState.menuHeight,
					  ImVec4(0.1f, 0.1f, 0.1f, 0.9f), 0, 0);

		// ____________
		DrawRect(menuState.menuX, menuState.menuY,
				menuState.menuWidth, menuState.menuHeight,
				ImVec4(1.0f, 1.0f, 1.0f, 1.0f), 1.0f);

		// ______________
		for (int i = 0; i < menuState.itemCount; i++) {
			float itemY = menuState.menuY + i * menuState.itemHeight;
			DrawMenuItem(menuState.items[i], 
						menuState.menuX, itemY,
						menuState.menuWidth, menuState.itemHeight,
						i == menuState.selectedIndex);
		}
	}
	void HandleMenuInput() {

		// No throttle: invept storm in return_old_func was the cause of the
		// VT-layer crash, not the call frequency itself. 5 hv::Calls/frame
		// at 60Hz works fine after the fix.

		if (IsKeyDown(VK_INSERT)) {

			if (!isInsertDown) {
				isInsertDown = true;
				menuState.isOpen = !menuState.isOpen; // ____________
			}
				
		}
		else
		{
			isInsertDown = false;
		}
	
		if (!menuState.isOpen) return;

		static bool keyStates[4] = { false }; // ____________
		bool currentKeyStates[4] = {
			IsKeyDown(VK_UP),
			IsKeyDown(VK_DOWN),
			IsKeyDown(VK_LEFT),
			IsKeyDown(VK_RIGHT)
		};

		// _______________
		for (int i = 0; i < 4; i++) {
			if (currentKeyStates[i] && !keyStates[i]) {
				MenuItem& currentItem = menuState.items[menuState.selectedIndex];
				
				switch (i) {
					case 0: // __
						menuState.selectedIndex = (menuState.selectedIndex - 1 + menuState.itemCount) % menuState.itemCount;
						break;
					case 1: // __
						menuState.selectedIndex = (menuState.selectedIndex + 1) % menuState.itemCount;
						break;
					case 2: // __
						if (currentItem.type == MENU_ITEM_TOGGLE && currentItem.toggleValue) {
							*currentItem.toggleValue = false;
						}
						/*else if (currentItem.type == MENU_ITEM_SLIDER && currentItem.sliderValue) {
							*currentItem.sliderValue = max(currentItem.sliderMin, *currentItem.sliderValue - 10);
						}*/
						break;
					case 3: // __
						if (currentItem.type == MENU_ITEM_TOGGLE && currentItem.toggleValue) {
							*currentItem.toggleValue = true;
						}
						/*else if (currentItem.type == MENU_ITEM_SLIDER && currentItem.sliderValue) {
							*currentItem.sliderValue = min(currentItem.sliderMax, *currentItem.sliderValue + 10);
						}*/
						break;
				}
			}
			keyStates[i] = currentKeyStates[i];
		}

		
		
	}

#pragma code_seg()

} // namespace sjz
