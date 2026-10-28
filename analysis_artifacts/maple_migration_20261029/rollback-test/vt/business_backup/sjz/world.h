#pragma once
//
// sjz/world.h
//
// World <-> screen projection helpers, name resolution from GNames table
// (UTF-8 narrow strings re-encoded to UTF-16), and the per-frame address
// chain refresh (update_addr).
//
// Defines the global `gameData` (declared as extern in internal.h).
//
#include "classes.h"
#include "internal.h"

// Camera-projection matrix layout. Defined at file scope (not inside the
// `sjz` namespace) for parity with the legacy SDK layout used by
// `Read<Matrix4x4>` deserialisation.
struct Matrix4x4 {
    float m[4][4];
};

namespace sjz {

    Matrix4x4 get_matrix();
    bool      WorldToScreen(FVector WorldPos, math_rust::Vector2& ScreenPos);
    bool      InScreen     (math_rust::Vector2 pos);
    bool      update_addr  (ULONG64& engine);

    void      GetName(int objectId, char* result, size_t maxSize, bool& isWide);
    int       MultiByteToWideChar(const char* mbStr, wchar_t* wcStr, size_t wcStrSize);

} // namespace sjz
