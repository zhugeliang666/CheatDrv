#pragma once
//
// sjz/session.h
//
// Game-session lifecycle: discover the game's PID + CR3 via the active-
// process linked list, and tear down state on F2 release / process exit.
//
namespace sjz {

    bool GameInit();
    void Reset();

} // namespace sjz
