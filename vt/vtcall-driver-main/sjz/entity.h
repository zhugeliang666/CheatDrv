#pragma once
//
// sjz/entity.h
//
// Per-entity record produced by scan.cpp and consumed by draw.cpp / aim.cpp.
// Includes the supporting structs the scan loop fills in.
//
// Internal-only: external modules use sjz.h, never include this directly.
//
#include "fltKernel.h"
#include <cstdint>
#include "classes.h"
#include "internal.h"
#include <gamecommon/imgui.h>

namespace sjz {

    // Per-bone screen segment captured during scan; consumed by skeleton draw.
    constexpr int kMaxBones = 20;

    // Equipment info one slot ___ populated by Game_GetEquipmentInfo().
    struct FEquipmentInfo {
        uint64_t ItemID;
        uint64_t gid;
        float    Health;
        float    MaxHealth;
        float    Durability;
        float    MaxDurability;
        LONG     level;
    };

    // World-space AABB built from skeleton bone samples.
    struct BoundingBox {
        FVector min;
        FVector max;
        FVector vertices[8];
    };

    // Single per-frame tracked actor record.
    struct EntityInfo {
        FVector            pos;
        math_rust::Vector2 screenPos;
        math_rust::Vector2 screenHeadPos;
        FVector            worldHeadPos;
        wchar_t            objName[128];
        UINT64             objectId;
        ImVec4             color;
        UINT64             teamId;
        int                headth;
        int                exitState;
        int                type;
        ULONG64            distance;
        UINT64             pawnAddr;
        ULONG64            price;
        ULONG64            level;
        ULONG64            size;
        int                camp;
        bool               isOpen;
        BoundingBox        bbox;
        VectorBones        DrawVectorBonesPos[kMaxBones];
        FVector            neckWorldPos;
        FEquipmentInfo     helmetEquipment;
        FEquipmentInfo     armorEquipment;
    };

    constexpr int kMaxEntities = 0x1000;

} // namespace sjz
