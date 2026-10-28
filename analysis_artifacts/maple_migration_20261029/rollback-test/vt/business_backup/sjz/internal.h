#pragma once
//
// sjz/internal.h
//
// Module-internal shared declarations. ONLY include this from inside sjz/.
// External modules (vt/, dwm/, render/, gamecommon/) MUST go through sjz.h
// public API.
//
// Holds:
//   - the sjz module-state structs (GameData, AimInfo, etc.) used across
//     several sjz/*.cpp files
//   - extern declarations for the shared globals defined inside sjz/
//
// Rationale: keeping these out of sjz.h prevents accidental coupling from
// outside the module. Refactor-safe: rearranging fields below cannot break
// any TU outside sjz/.
//

#include "classes.h"
#include "offsets.h"

namespace sjz {

    // -------------------------------------------------------------------
    // FMinimalViewInfo - single camera snapshot, used by world.cpp
    // -------------------------------------------------------------------
    struct FMinimalViewInfo {
        math_rust::Vector3 Location;
        FRotator           Rotation;
        float              FOV;
    };

    // -------------------------------------------------------------------
    // GameData - per-frame game-world snapshot. Mutated by world.cpp/
    // session.cpp; read by scan/draw/aim/decrypt.
    // -------------------------------------------------------------------
    struct GameData {
        ULONG64 Uworld;
        ULONG64 ULevels;
        ULONG64 levelCount;
        ULONG64 ULevel;
        int     Count;
        ULONG64 Actor;
        ULONG64 GameInstance;
        ULONG64 LocalPlayer;
        ULONG64 LocalPlayers;
        ULONG64 PlayerController;
        ULONG64 AcknowledgedPawn;
        UINT64  objId;
        ULONG64 Martix;
        ULONG64 PlayerRootComponent;
        ULONG64 PlayerPawnMesh;
        ULONG64 PlayerTeam;
        FRotator PlayerRotator;
        bool    isEncrypted;
        math_rust::Vector3 PlayerPos;
        math_rust::Vector2 PlayerScreenPos;
        FVector localPlayerPos;
        FMinimalViewInfo viewInfo;
        ULONG64 func;
        int     ObjectID;
        int     camp;
        ULONG64 key = 0;
        bool    isStartMove;
        ULONG64 address = 0;
    };

    // VectorBones - one bone segment in screen-space, used by scan/draw.
    struct VectorBones {
        math_rust::Vector2 start;
        math_rust::Vector2 end;
        bool IsVisible;
        bool IsAi;
    };

    // -------------------------------------------------------------------
    // AimInfo / AimState - submitted to ring-3 helper via hypercall
    // -------------------------------------------------------------------
    struct AimInfo {
        float targetX;
        float targetY;
    };

    struct AimState {
        float targetX;
        float targetY;
        float currentX;
        float currentY;
        INT64 startTime;
        float duration;
        float totalProgress;
        float lastX;
        float lastY;
        bool  isMoving = false;
    };

    // -------------------------------------------------------------------
    // Module-internal shared globals - definitions live in their owner cpp.
    // -------------------------------------------------------------------
    extern GameData  gameData;          // defined in world.cpp
    extern AimInfo   vtAimInfo;          // defined in aim.cpp
    extern AimState  aimState;           // defined in aim.cpp
    extern bool      isStart;            // defined in session.cpp
    extern bool      isBegin;            // defined in session.cpp
    extern bool      isAiming;           // defined in aim.cpp
    extern UINT64    screenCount;        // defined in sjz.cpp
    extern UINT64    screenCount2;       // defined in sjz.cpp
    extern UINT64    diagPipelineStage;  // compact runtime checkpoint for vtcall pmo
    extern UINT64    diagPackedCounts;   // 0xD1 + saturated scan counters
    extern UINT64    diagDrawMainTicks;  // DrawMain reached counter
    extern UINT64    diagDrawPlayerCalls;// DrawPlayer reached counter

    namespace menu {
        extern bool isHead;
        extern bool isSkeleton;
        extern bool isBox;
        extern bool isAim;
        extern bool isBattleMode;
        extern bool isShowDebugInfo;
        extern bool isHealth;
        extern bool isShowContainer;
        extern bool isShowBox;
        extern bool isShowItem;
        extern bool isItemList;
        extern bool isCenter;
        extern bool isDistance;
        extern bool isShowNpc;
    }

    // GameType enum used by scan/draw for entity classification.
    enum GameType : int {
        player       = 0,
        container    = 1,
        safebox      = 2,
        pickupItem   = 3,
        box          = 4,
        unknow       = 5,
    };

} // namespace sjz
