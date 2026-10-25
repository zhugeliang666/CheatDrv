#pragma once
//
// sjz/ids.h
//
// Encrypted name lookups: blueprint -> player kind, weapon hash -> name,
// hero hash -> name.
//
// Strings are NOT stored in any static table. Each lookup re-evaluates
// `_XOR_(L"...")` literals which the xorstr.h compile-time obfuscator
// turns into nibble-XOR'd byte arrays in .rdata; the literals are only
// reconstructed on the stack when accessed. This keeps the binary's
// `strings` output clean of BP_DFM* identifiers and CN display names.
//
// Output buffer pattern: callers pass a `wchar_t* out` + capacity. The
// lookup writes into `out` and returns nothing (or a status int). This
// is the only way to safely pass a `_XOR_` decrypt result across a
// function boundary, because `_XOR_` returns a pointer into a stack
// buffer that goes out of scope at the end of the full-expression.
//
#include "fltKernel.h"
#include "../xorstr.h"
#include "classes.h"

namespace sjz {

    // Sentinel returned when no entry matches.
    constexpr int kPlayerKindNone = -1;

    // Look up a UE blueprint class name (e.g. "BP_DFMCharacter_C").
    // Returns a small integer kind when matched, or kPlayerKindNone
    // otherwise. The numeric kind is then resolved to a display name
    // via FillPlayerKindName().
    int  LookupPlayerKind(const wchar_t* bp_name);

    // Write the display name for the given player kind into `out`.
    // Falls back to a generic "AI" sentinel for unknown kinds.
    void FillPlayerKindName(int kind, wchar_t* out, size_t cap);

    // Write the display name for a weapon-hash / hero-hash lookup.
    // Falls back to a localized "unknown" sentinel on miss.
    void FillWeaponName(UINT64 hash, wchar_t* out, size_t cap);
    void FillHeroName  (UINT64 hash, wchar_t* out, size_t cap);

} // namespace sjz
