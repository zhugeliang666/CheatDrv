#include "coord_cache.h"

#include "../vt/spin-lock.h"

namespace sjz {

#pragma code_seg(".vm")

    namespace {

        constexpr ULONG kCoordActorSlotCount = 1024;
        constexpr ULONG kCoordRecentHitCount = 256;

        struct CoordActorSlot {
            ULONG64 key;
            ULONG64 seq;
            ULONG64 pid;
            ULONG64 cr3;
            CoordCacheVec3 pos;
            ULONG hits;
        };

        struct CoordRecentHit {
            ULONG64 seq;
            ULONG64 actor;
            ULONG64 rsi;
            ULONG64 r12;
            ULONG64 r13;
            ULONG64 r15;
            ULONG64 stack0;
            ULONG64 stack4;
            ULONG64 stack5;
            ULONG64 stack6;
            CoordCacheVec3 pos;
        };

        hv::spin_lock g_coordLock;
        CoordActorSlot g_actorSlots[kCoordActorSlotCount];
        CoordRecentHit g_recentHits[kCoordRecentHitCount];
        ULONG g_recentWrite;
        CoordHookStats g_stats;

        static bool IsFiniteFloat(float v) {
            return (v == v) && (v > -3.4e38f) && (v < 3.4e38f);
        }

        static bool IsPlausibleCoord(const CoordCacheVec3& v) {
            if (!IsFiniteFloat(v.x) || !IsFiniteFloat(v.y) || !IsFiniteFloat(v.z))
                return false;

            if (v.x > -0.01f && v.x < 0.01f &&
                v.y > -0.01f && v.y < 0.01f &&
                v.z > -0.01f && v.z < 0.01f)
                return false;

            // UE world coords in the current map can be large, but bad
            // snapshots usually explode far past this range.
            return v.x > -1000000.0f && v.x < 1000000.0f &&
                   v.y > -1000000.0f && v.y < 1000000.0f &&
                   v.z > -1000000.0f && v.z < 1000000.0f;
        }

        static bool IsLikelyActorPtr(ULONG64 p) {
            // This is only a cache-key heuristic.  Live captures showed some
            // valid UE objects in both high heap ranges (0x42..., 0x82...) and
            // lower allocator ranges (for example 0x39A00040), so do not keep
            // the old high-only cutoff.  False candidates are harmless because
            // scan.cpp asks for concrete pawn/root/mesh keys before drawing.
            return p >= 0x0000000010000000ull &&
                   p <  0x0000800000000000ull &&
                   ((p & 0xFULL) == 0);
        }

        static void StoreActorLocked(ULONG64 actor,
                                     const CoordCacheVec3& pos,
                                     ULONG64 seq,
                                     ULONG64 pid,
                                     ULONG64 cr3) {
            if (!IsLikelyActorPtr(actor))
                return;

            ULONG freeIdx = kCoordActorSlotCount;
            ULONG oldestIdx = 0;
            ULONG64 oldestSeq = ~0ull;

            for (ULONG i = 0; i < kCoordActorSlotCount; i++) {
                if (g_actorSlots[i].key == actor) {
                    g_actorSlots[i].seq = seq;
                    g_actorSlots[i].pid = pid;
                    g_actorSlots[i].cr3 = cr3;
                    g_actorSlots[i].pos = pos;
                    g_actorSlots[i].hits++;
                    g_stats.mapped++;
                    g_stats.lastActor = actor;
                    g_stats.lastPos = pos;
                    return;
                }

                if (!g_actorSlots[i].key && freeIdx == kCoordActorSlotCount)
                    freeIdx = i;

                if (g_actorSlots[i].seq < oldestSeq) {
                    oldestSeq = g_actorSlots[i].seq;
                    oldestIdx = i;
                }
            }

            ULONG idx = (freeIdx != kCoordActorSlotCount) ? freeIdx : oldestIdx;
            g_actorSlots[idx].key = actor;
            g_actorSlots[idx].seq = seq;
            g_actorSlots[idx].pid = pid;
            g_actorSlots[idx].cr3 = cr3;
            g_actorSlots[idx].pos = pos;
            g_actorSlots[idx].hits = 1;
            g_stats.mapped++;
            g_stats.lastActor = actor;
            g_stats.lastPos = pos;
        }

        static ULONG64 SelectPrimaryActor(const CoordProbeHitSubmit& hit) {
            if (IsLikelyActorPtr(hit.stack0))
                return hit.stack0;
            if (IsLikelyActorPtr(hit.stack6))
                return hit.stack6;
            if (IsLikelyActorPtr(hit.stack4))
                return hit.stack4;
            if (IsLikelyActorPtr(hit.stack5))
                return hit.stack5;
            if (IsLikelyActorPtr(hit.r12))
                return hit.r12;
            if (IsLikelyActorPtr(hit.r13))
                return hit.r13;
            if (IsLikelyActorPtr(hit.r15))
                return hit.r15;
            return 0;
        }

        static void StoreCandidateLocked(ULONG64 candidate,
                                         const CoordCacheVec3& pos,
                                         ULONG64 seq,
                                         ULONG64 pid,
                                         ULONG64 cr3,
                                         ULONG64* stored,
                                         ULONG& storedCount) {
            if (!IsLikelyActorPtr(candidate))
                return;

            for (ULONG i = 0; i < storedCount; i++) {
                if (stored[i] == candidate)
                    return;
            }

            StoreActorLocked(candidate, pos, seq, pid, cr3);

            if (storedCount < 8)
                stored[storedCount++] = candidate;
        }

    } // namespace

    void SubmitCoordProbeHit(const CoordProbeHitSubmit& hit) {
        hv::scoped_spin_lock lock(g_coordLock);
        g_stats.submitted++;
        g_stats.lastSeq = hit.seq;

        if (!IsPlausibleCoord(hit.pos)) {
            g_stats.rejected++;
            return;
        }

        g_stats.accepted++;

        const ULONG64 actor = SelectPrimaryActor(hit);
        auto& recent = g_recentHits[g_recentWrite++ % kCoordRecentHitCount];
        recent.seq = hit.seq;
        recent.actor = actor;
        recent.rsi = hit.rsi;
        recent.r12 = hit.r12;
        recent.r13 = hit.r13;
        recent.r15 = hit.r15;
        recent.stack0 = hit.stack0;
        recent.stack4 = hit.stack4;
        recent.stack5 = hit.stack5;
        recent.stack6 = hit.stack6;
        recent.pos = hit.pos;

        // Store all owner-like candidates seen at this return site.  Different
        // callers carry AActor/root/mesh in different preserved registers or
        // stack slots; scan.cpp validates by querying its own known keys.
        ULONG64 stored[8]{};
        ULONG storedCount = 0;
        StoreCandidateLocked(hit.stack0, hit.pos, hit.seq, hit.pid, hit.cr3, stored, storedCount);
        StoreCandidateLocked(hit.stack4, hit.pos, hit.seq, hit.pid, hit.cr3, stored, storedCount);
        StoreCandidateLocked(hit.stack5, hit.pos, hit.seq, hit.pid, hit.cr3, stored, storedCount);
        StoreCandidateLocked(hit.stack6, hit.pos, hit.seq, hit.pid, hit.cr3, stored, storedCount);
        StoreCandidateLocked(hit.r12, hit.pos, hit.seq, hit.pid, hit.cr3, stored, storedCount);
        StoreCandidateLocked(hit.r13, hit.pos, hit.seq, hit.pid, hit.cr3, stored, storedCount);
        StoreCandidateLocked(hit.r15, hit.pos, hit.seq, hit.pid, hit.cr3, stored, storedCount);
    }

    bool TryGetActorCoord(ULONG64 actor, CoordCacheVec3* outPos, ULONG64* outSeq) {
        if (!outPos || !IsLikelyActorPtr(actor))
            return false;

        hv::scoped_spin_lock lock(g_coordLock);
        for (ULONG i = 0; i < kCoordActorSlotCount; i++) {
            if (g_actorSlots[i].key == actor && IsPlausibleCoord(g_actorSlots[i].pos)) {
                *outPos = g_actorSlots[i].pos;
                if (outSeq)
                    *outSeq = g_actorSlots[i].seq;
                return true;
            }
        }
        return false;
    }

    ULONG SnapshotCoordActors(CoordActorSnapshot* out, ULONG maxCount,
                              ULONG64 maxSeqAge) {
        if (!out || !maxCount)
            return 0;

        hv::scoped_spin_lock lock(g_coordLock);

        ULONG copied = 0;
        const ULONG64 newest = g_stats.lastSeq;
        for (ULONG i = 0; i < kCoordActorSlotCount && copied < maxCount; i++) {
            const auto& slot = g_actorSlots[i];
            if (!slot.key || !IsPlausibleCoord(slot.pos))
                continue;

            if (newest && maxSeqAge) {
                if (slot.seq > newest)
                    continue;
                if ((newest - slot.seq) > maxSeqAge)
                    continue;
            }

            out[copied].key = slot.key;
            out[copied].seq = slot.seq;
            out[copied].pid = slot.pid;
            out[copied].cr3 = slot.cr3;
            out[copied].hits = slot.hits;
            out[copied].pos = slot.pos;
            copied++;
        }

        return copied;
    }

    CoordHookStats GetCoordHookStats() {
        hv::scoped_spin_lock lock(g_coordLock);
        return g_stats;
    }

    void ClearCoordHookCache() {
        hv::scoped_spin_lock lock(g_coordLock);
        RtlZeroMemory(g_actorSlots, sizeof(g_actorSlots));
        RtlZeroMemory(g_recentHits, sizeof(g_recentHits));
        RtlZeroMemory(&g_stats, sizeof(g_stats));
        g_recentWrite = 0;
    }

#pragma code_seg()

} // namespace sjz
