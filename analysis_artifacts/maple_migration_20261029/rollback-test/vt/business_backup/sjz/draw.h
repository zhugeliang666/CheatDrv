#pragma once
//
// sjz/draw.h
//
// Per-frame drawing: bounding box, skeleton, name bar, distance, hero/
// weapon labels, item highlights, mini-map (radar). Reads scan.cpp's
// shared entity buffers; doesn't mutate them.
//
#include "entity.h"

namespace sjz {

    void DrawMain               ();
    void DrawPlayer             (EntityInfo info);
    void DrawItem               (EntityInfo info);
    void DrawRander             (EntityInfo info);
    void DrawHighValueItemsList ();
    ImColor GetTeamColor        (int teamId);

} // namespace sjz
