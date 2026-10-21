#pragma once
#ifndef _NTIFS_H
#define _NTIFS_H
#endif
#include "fltKernel.h"
#include "common/payload_abi.h"

namespace Utils
{
    ULONG_PTR QueryModule(PUCHAR moduleName, ULONG_PTR* moduleSize);

    extern PVOID imageBase;
    extern ULONG imageSize;
    extern _DRIVER_OBJECT testDriver;
    extern BOOLEAN testDriverUnloaded;
    extern BOOLEAN testDriverUnloadCallbackCalled;
    extern BOOLEAN testDriverImageQuarantined;
    extern PVOID payloadBase;
    extern ULONG payloadSize;
    extern PVOID payloadArenaBase;
    extern ULONG payloadArenaSize;
    extern _DRIVER_OBJECT payloadDriver;
    extern payload_exports* payloadExports;

    struct SectionSnap
    {
        char  name[9];
        ULONG va_offset;
        ULONG virtual_size;
        ULONG characteristics;
    };

    static constexpr ULONG kSectionSnapMax = 32;
    extern SectionSnap SectionSnaps[kSectionSnapMax];
    extern ULONG SectionSnapCount;

    BOOLEAN LoadDriver(PUCHAR fileBuffer, PVOID context = nullptr);
    BOOLEAN LoadPayload(PUCHAR fileBuffer, PVOID context);
    BOOLEAN LoadRawPayload(PUCHAR packetBuffer, ULONG packetSize, PVOID context);
    VOID UnloadDriver();
    VOID UnloadDriverEx(BOOLEAN freeImage);
    VOID UnloadPayload();
    VOID FreePayloadArena();
}
