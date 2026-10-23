#pragma once
//
// sjz/decrypt.h
//
// Game-specific decrypt/encrypt helpers and the NtGetContextThread hook
// (which sniffs the SDK key out of the XSTATE area). Self-contained ___ no
// references to reader/world/draw.
//
#include "fltKernel.h"
#include <cstdint>

namespace sjz {

    UINT64   decrypt_qword(INT64 a1);
    UINT64   decrypt_ptr  (UINT64 value);
    uint64_t sub_23A33    (int64_t a1, int64_t a2);

    int64_t  sub_14853DB40(uint8_t*  a1, uint32_t size);
    int64_t  sub_14853DD50(uint16_t* a1, uint32_t size);

    extern NTSTATUS(*OriginalNtGetContextThread)(IN HANDLE ThreadHandle, IN OUT PCONTEXT Context);
    NTSTATUS HookedNtGetContextThread          (IN HANDLE ThreadHandle, IN OUT PCONTEXT Context);

} // namespace sjz
