#pragma once
//
// sjz/sjz.h - public facade for the sjz business module.
//
// Includes the per-submodule headers so that external translation units
// (vt/, dwm/, render/, gamecommon/) continue to see the same symbols
// they used before the R1 split.
//
// Refactor stage R1: structural split only. R2 will replace the raw
// `extern` symbols below with `query_*` / `submit_*` accessors.
//
#include "fltKernel.h"

#include "internal.h"
#include "session.h"
#include "scan.h"
#include "draw.h"
#include "aim.h"
#include "menu.h"
#include "input.h"

namespace hv {
    struct vcpu;
}

namespace sjz {

    // PMO-thread validation snapshot. Updated only by PmoValidateTick()
    // from the PMO hook path; render/debug code reads it for on-screen proof.
    struct PmoValidationState {
        UINT64 pmoHits;
        UINT64 validateRuns;
        UINT64 okRuns;
        UINT64 failStage;
        UINT64 lastOk;

        UINT64 pid;
        UINT64 cr3;
        UINT64 base;
        UINT64 key;

        UINT64 gworld;
        UINT64 gnamesChunk0;
        UINT64 localPlayer;
        UINT64 globalActors;

        UINT64 ulevels;
        UINT64 ulevel;
        UINT64 actorArrayRaw;
        UINT64 actorArray;

        int    levelCount;
        int    actorCount;
    };

    enum PmoDebugCommand : UINT64 {
        PmoDebugNone = 0,
        PmoDebugRead = 1,
    };

    struct PmoDebugRequest {
        UINT64 seq;
        UINT64 command;
        UINT64 address;
        UINT64 size;
        UINT64 arg0;
        UINT64 arg1;
    };

    struct PmoDebugResult {
        UINT64 seq;
        UINT64 command;
        UINT64 status;
        UINT64 address;
        UINT64 requested;
        UINT64 got;
        UCHAR  bytes[0x400];
    };

    // Legacy top-level entry points - still called from gamecommon.cpp.
    // No-op wrapper for old `hook()` declaration (was never defined).
    void hook();

    void GetData();         // sjz.cpp tick ___ forwards to scan::GetData()
    void GetOtherData();    // sjz.cpp tick ___ forwards to scan::GetOtherData()

    bool PmoValidateOnce();  // one read-chain probe, no drawing / no scan
    void PmoValidateTick();  // throttled PMO-thread validation dispatcher
    void PmoDebugConsume();  // execute pending debug jobs on PMO thread
    void AutoCoordProbeTick(hv::vcpu* cpu); // PMO-thread auto EPT coord probe

    // Module-global state still exposed for external compatibility.
    // R2 will collapse these to inline getters / submit_* functions.
    extern UINT64 screenCount;
    extern UINT64 screenCount2;
    extern bool   isMoving;
    extern PmoValidationState pmoValidation;
    extern PmoDebugRequest    pmoDebugRequest;
    extern PmoDebugResult     pmoDebugResult;

} // namespace sjz
