#pragma once
//
// sjz/menu.h
//
// In-game settings menu (INSERT key opens, arrow keys navigate). Built on
// top of the gamecommon Draw* primitives.
//
#include "fltKernel.h"

namespace sjz {

    enum MenuItemType {
        MENU_ITEM_TOGGLE,
        MENU_ITEM_SLIDER,
    };

    struct MenuItem {
        const wchar_t* name;
        MenuItemType   type;
        bool*  toggleValue;
        float* sliderValue;
        float  sliderMin;
        float  sliderMax;
    };

    struct MenuState {
        MenuItem* items;
        int       itemCount;
        int       selectedIndex;
        bool      isOpen;
        float     menuX;
        float     menuY;
        float     menuWidth;
        float     menuHeight;
        float     itemHeight;
    };

    void InitMenu();
    void DrawMenu();
    void HandleMenuInput();

} // namespace sjz
