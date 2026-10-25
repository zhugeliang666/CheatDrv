#pragma once
//
// sjz/reader.h
//
// Pure read-only helpers over guest memory. No state mutation, no draw,
// no decrypt. Each function takes a pawn / actor pointer and returns a
// scalar / FVector / boolean.
//
#include "classes.h"
#include "internal.h"

namespace sjz {

    FVector  GetWorldLocation(ULONG64 entityPawnAddrss);
    UINT64   GetTeamId       (ULONG64 entityPawnAddrss);
    int      GetHealth       (ULONG64 entityPawnAddrss);
    int      getCamp         (UINT64  pawn);

    BOOLEAN  Game_GetEquipmentInfo (IN ULONG_PTR Actor, IN INT Type, OUT LONG* Quality);
    BOOLEAN  Game_GetActorHeroID   (IN ULONG64 Actor, OUT LONG64* HeroID);
    BOOLEAN  Game_GetActorCurWeapon(IN ULONG64 Actor, OUT LONG64* WeaponID);

    D3DMATRIX MatrixMultiplication(const D3DMATRIX& pM1, const D3DMATRIX& pM2);
    FVector   GetBoneWithRotation (ULONG64 PawnMeshAddress, int BonesId);

} // namespace sjz
