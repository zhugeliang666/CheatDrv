#pragma once
//
// sjz/aim.h
//
// Aim-bot motion: bezier-pathed mouse delta computation from the current
// target's screen-space head position. Writes AimInfo into module state
// so the ring-3 mouse-event hypercall picks it up next tick.
//
#include "internal.h"
#include "entity.h"

namespace sjz {

    void StartAim       (EntityInfo target);
    void StartMoveMouse ();

    // Selected target. Updated by scan.cpp during entity acquisition.
    extern bool       isUpdateAimInfo;
    extern EntityInfo aimInfo;
    extern ULONG64    aimDistance;

} // namespace sjz
