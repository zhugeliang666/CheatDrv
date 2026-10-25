#pragma once
//
// sjz/coord_cache.h
//
// Small bridge between the generic VT/EPT probe and the sjz actor scanner.
// The probe captures plaintext FVector values at the game's coordinate
// decrypt return site; the scanner can then use those coordinates without
// reimplementing the game's decrypt routine.
//

#include <ntddk.h>

namespace sjz {

    // Current coordinate-decrypt return probe target for the 2026-05-29 dump.
    // This is the first cleanup instruction after the decrypt call returns.
    // Keep the value centralized so ept-probe.cpp and tools agree.
    inline constexpr ULONG64 kCoordProbeDecryptRet = 0x142BE83B5ull;

    struct CoordCacheVec3 {
        float x;
        float y;
        float z;
    };

    struct CoordProbeHitSubmit {
        ULONG64 seq;
        ULONG64 targetVa;
        ULONG64 rip;
        ULONG64 cr3;
        ULONG64 pid;
        ULONG64 rsp;

        ULONG64 rsi;
        ULONG64 r12;
        ULONG64 r13;
        ULONG64 r15;

        // Candidate owner pointers observed at this return site.  The most
        // stable paths vary by caller; keep the original caller stack slots
        // that have carried actor/root/mesh-like pointers in live captures.
        ULONG64 stack0;
        ULONG64 stack4;
        ULONG64 stack5;
        ULONG64 stack6;

        // Raw decoded plaintext coordinate.
        CoordCacheVec3 pos;
    };

    struct CoordHookStats {
        ULONG64 submitted;
        ULONG64 accepted;
        ULONG64 mapped;
        ULONG64 rejected;
        ULONG64 lastSeq;
        ULONG64 lastActor;
        CoordCacheVec3 lastPos;
    };

    // Minimal hook-only snapshot record.  This is intentionally independent
    // from UE actor-array/name/team/health decrypt paths: if those fields move
    // or get re-encrypted, draw code can still consume recent plaintext coords
    // captured at the runtime coordinate boundary.
    struct CoordActorSnapshot {
        ULONG64 key;
        ULONG64 seq;
        ULONG64 pid;
        ULONG64 cr3;
        ULONG64 hits;
        CoordCacheVec3 pos;
    };

    // Called from VM-exit/EPT probe path.  Must stay tiny and non-blocking
    // apart from the local spin lock.
    void SubmitCoordProbeHit(const CoordProbeHitSubmit& hit);

    // Called from scan.cpp for a concrete AActor pointer.
    bool TryGetActorCoord(ULONG64 actor, CoordCacheVec3* outPos, ULONG64* outSeq = nullptr);

    // Copies recent coord-cache entries into caller storage.  Returns the
    // number copied.  Entries are cache keys observed at the hook site, not
    // guaranteed UE AActor pointers, so callers must treat them as opaque ids.
    ULONG SnapshotCoordActors(CoordActorSnapshot* out, ULONG maxCount,
                              ULONG64 maxSeqAge = 4096);

    // Optional diagnostics for overlay/tools.
    CoordHookStats GetCoordHookStats();
    void ClearCoordHookCache();

} // namespace sjz
