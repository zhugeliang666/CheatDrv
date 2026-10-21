#include "ntutils.h"

#include <ntimage.h>
#include "../Utils.h"

YVT g_yvt;

#pragma code_seg(".vm")

namespace
{
    struct MAPDRIVER_CORE_RVA_SET
    {
        ULONG TimeDateStamp;
        ULONG SizeOfImage;
        ULONG CheckSum;
        ULONG MmAllocateIndependentPagesRva;
        ULONG MmFreeIndependentPagesRva;
        ULONG MmSetPageProtectionRva;
    };

    static const MAPDRIVER_CORE_RVA_SET kMapDriverCoreRvas[] =
    {
        // Win10 21H1 test host: ntoskrnl.exe 10.0.19041.1826
        { 0x73F1C0C4, 0x01046000, 0x00A65799, 0x007531E0, 0x00754410, 0x00377CB0 },
        // Win10 22H2 target set: ntoskrnl.exe 10.0.19041.3803
        { 0x5DEE2B07, 0x01046000, 0x00A6C725, 0x00762300, 0x007642B0, 0x00379FE0 },
    };

    static BOOLEAN MapDriverReadNtosKey(ULONG_PTR ntosBase, ULONG& timeDateStamp, ULONG& sizeOfImage, ULONG& checksum)
    {
        timeDateStamp = 0;
        sizeOfImage = 0;
        checksum = 0;

        if (!ntosBase)
            return FALSE;

        __try
        {
            auto dos = (PIMAGE_DOS_HEADER)ntosBase;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return FALSE;

            auto nt = (PIMAGE_NT_HEADERS)((PUCHAR)ntosBase + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return FALSE;

            timeDateStamp = nt->FileHeader.TimeDateStamp;
            sizeOfImage = nt->OptionalHeader.SizeOfImage;
            checksum = nt->OptionalHeader.CheckSum;
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return FALSE;
        }
    }

    static VOID MapDriverClearCoreSymbols()
    {
        MmAllocateIndependentPages = nullptr;
        MmFreeIndependentPages = nullptr;
        MmSetPageProtection = nullptr;
    }

    static BOOLEAN MapDriverResolveCoreSymbols(ULONG_PTR ntosBase)
    {
        ULONG timeDateStamp = 0;
        ULONG sizeOfImage = 0;
        ULONG checksum = 0;

        MapDriverClearCoreSymbols();

        if (!MapDriverReadNtosKey(ntosBase, timeDateStamp, sizeOfImage, checksum))
            return FALSE;

        for (ULONG i = 0; i < ARRAYSIZE(kMapDriverCoreRvas); ++i)
        {
            const auto& item = kMapDriverCoreRvas[i];
            if (item.TimeDateStamp != timeDateStamp ||
                item.SizeOfImage != sizeOfImage ||
                item.CheckSum != checksum)
            {
                continue;
            }

            MmAllocateIndependentPages = (decltype(MmAllocateIndependentPages))(ntosBase + item.MmAllocateIndependentPagesRva);
            MmFreeIndependentPages = (decltype(MmFreeIndependentPages))(ntosBase + item.MmFreeIndependentPagesRva);
            MmSetPageProtection = (decltype(MmSetPageProtection))(ntosBase + item.MmSetPageProtectionRva);
            return TRUE;
        }

        return FALSE;
    }
}

void YVT::InitNtSymbol()
{
    ntosInfo.imageBase = Utils::QueryModule((PUCHAR)_XOR_("ntoskrnl.exe"), &ntosInfo.imageSize);
    MapDriverResolveCoreSymbols(ntosInfo.imageBase);
}

YVT::YVT()
{
    InitNtSymbol();
}

#pragma code_seg()
