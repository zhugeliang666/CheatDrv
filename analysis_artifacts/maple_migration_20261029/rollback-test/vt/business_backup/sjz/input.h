#pragma once
//
// sjz/input.h
//
// Keyboard polling + debounce for top-level hotkeys (F2 / `~ / ALT+1 /
// ALT+2 / ALT+3 / MBUTTON). Decoupled from menu.cpp's INSERT handling.
//
namespace sjz {

    void UpdateKeys();

} // namespace sjz
