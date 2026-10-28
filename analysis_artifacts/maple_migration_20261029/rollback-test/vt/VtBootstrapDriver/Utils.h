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
    extern PVOID machenikeBase;
    extern ULONG machenikeSize;
    extern BOOLEAN machenikeLoaded;
    extern ULONG machenikeMode;
    extern BOOLEAN machenikeUsedIndependent;
    extern PDRIVER_UNLOAD machenikeUnload;
    extern PDRIVER_DISPATCH machenikeCreateDispatch;
    extern PDRIVER_DISPATCH machenikeCloseDispatch;
    extern PDRIVER_DISPATCH machenikeDeviceControlDispatch;

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
    BOOLEAN LoadMachenike(PUCHAR fileBuffer, PDRIVER_OBJECT hostDriverObj, PUNICODE_STRING registryPath, BOOLEAN isManualMap = FALSE);
    VOID UnloadDriver();
    VOID UnloadDriverEx(BOOLEAN freeImage);
    VOID UnloadPayload();
    VOID UnloadMachenike(PDRIVER_OBJECT hostDriverObj);
    BOOLEAN InstallMachenikeTextDualView();
    VOID RemoveMachenikeTextDualView();
    BOOLEAN VerifyAllCpusHvReady(ULONGLONG* expected_mask_out = nullptr, ULONGLONG* pong_mask_out = nullptr);
    VOID FreePayloadArena();
}
