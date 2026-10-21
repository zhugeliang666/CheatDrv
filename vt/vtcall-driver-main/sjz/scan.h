#pragma once
//
// sjz/scan.h
//
// Per-frame actor traversal: walks gameData.ULevels[0]'s actor array,
// classifies each entry by EMarkingItemType, and dispatches to
// ReadPlayerData / ReadItemlootingData. Collects the result in the shared
// `screenPosArray` / `otherPosArray` that draw.cpp consumes.
//
#include "entity.h"

namespace sjz {

    // Per-frame entity buffers. scan.cpp populates them, sjz.cpp/draw.cpp
    // make their own copies before draw runs.
    extern int        screenPosCount;
    extern int        otherPosCount;
    extern EntityInfo screenPosArray   [kMaxEntities];
    extern EntityInfo screenPosArrayCopy[kMaxEntities];
    extern EntityInfo otherPosArray    [kMaxEntities];
    extern EntityInfo otherPosArrayCopy[kMaxEntities];
    extern EntityInfo highValueItems   [kMaxEntities];
    extern UINT64     highValueCount;
    extern math_rust::Vector2 screenList[kMaxEntities];
    extern UINT64     screenListCount;

    void ReadData            ();
    void ReadPlayerData      (EntityInfo info);
    void ReadItemlootingData (EntityInfo info);

    // Tick entry-points (called from sjz.cpp).
    void GetData     ();
    void GetOtherData();

} // namespace sjz
