#include "ntutils.h"

#include <ntimage.h>
#include "../Utils.h"
#include "../base.h"

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
        // Win10 22H2 目标 设置: ntoskrnl.exe 10.0.19041.3803
        { 0x5DEE2B07, 0x01046000, 0x00A6C725, 0x00762300, 0x007642B0, 0x00379FE0 },
        // Win10 22H2 host: ntoskrnl.exe 10.0.19041.6466 (Build 19045)
        { 0x1C62BEE3, 0x01046000, 0x00A638CA, 0x00761F30, 0x00763B10, 0x003796F0 },
    };

    static BOOLEAN MapDriverGetTextSection(ULONG_PTR ntosBase, PUCHAR& textBase, ULONG& textSize)
    {
        textBase = nullptr;
        textSize = 0;
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
            auto sec = IMAGE_FIRST_SECTION(nt);
            for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
            {
                if (sec->Name[0] == '.' && sec->Name[1] == 't' && sec->Name[2] == 'e' &&
                    sec->Name[3] == 'x' && sec->Name[4] == 't')
                {
                    textBase = (PUCHAR)ntosBase + sec->VirtualAddress;
                    textSize = sec->Misc.VirtualSize;
                    return (textBase != nullptr && textSize > 0x200);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return FALSE;
    }

    static BOOLEAN MapDriverScanCoreSymbolsInText(ULONG_PTR ntosBase)
    {
        PUCHAR textBase = nullptr;
        ULONG textSize = 0;
        if (!MapDriverGetTextSection(ntosBase, textBase, textSize))
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] MapDriverScanCoreSymbolsInText: .text section not found (ntos=%p)\n"), (PVOID)ntosBase);
            return FALSE;
        }

        LOG_DEBUG(_XOR_("[VtBootstrapDriver] MapDriverScanCoreSymbolsInText: scanning .text base=%p size=0x%X\n"), textBase, textSize);

        __try
        {
            for (ULONG i = 0; i + 0x200 < textSize; ++i)
            {
                if (!MmAllocateIndependentPages &&
                    textBase[i] == 0x83 && textBase[i + 1] == 0xCA && textBase[i + 2] == 0xFF &&
                    textBase[i + 3] == 0x48 && textBase[i + 4] == 0x8B && textBase[i + 5] == 0xCE &&
                    textBase[i + 6] == 0xE8 && textBase[i + 11] == 0x48 && textBase[i + 12] == 0x89)
                {
                    LONG relAlloc = *(LONG*)(textBase + i + 7);
                    ULONG_PTR targetAlloc = (ULONG_PTR)(textBase + i + 6 + 5) + (LONG_PTR)relAlloc;
                    for (ULONG j = i + 0x80; j < i + 0x200 && j + 16 < textSize; ++j)
                    {
                        if (textBase[j] == 0x48 && textBase[j + 1] == 0x85 && textBase[j + 2] == 0xC9 &&
                            textBase[j + 3] == 0x74 && textBase[j + 4] == 0x10 &&
                            textBase[j + 5] == 0x48 && textBase[j + 6] == 0x8B && textBase[j + 7] == 0xD6 &&
                            textBase[j + 8] == 0xE8)
                        {
                            LONG relFree = *(LONG*)(textBase + j + 9);
                            ULONG_PTR targetFree = (ULONG_PTR)(textBase + j + 8 + 5) + (LONG_PTR)relFree;
                            MmAllocateIndependentPages = (decltype(MmAllocateIndependentPages))targetAlloc;
                            MmFreeIndependentPages = (decltype(MmFreeIndependentPages))targetFree;
                            LOG_DEBUG(_XOR_("[VtBootstrapDriver] Pattern matched MmAllocateIndependentPages=%p (RVA=0x%X), MmFreeIndependentPages=%p (RVA=0x%X)\n"),
                                MmAllocateIndependentPages, (ULONG)(targetAlloc - ntosBase),
                                MmFreeIndependentPages, (ULONG)(targetFree - ntosBase));
                            break;
                        }
                    }
                }

                if (!MmSetPageProtection &&
                    textBase[i] == 0x48 && textBase[i + 1] == 0x89 && textBase[i + 2] == 0x5C &&
                    textBase[i + 3] == 0x24 && textBase[i + 4] == 0x20 && textBase[i + 5] == 0x55 &&
                    textBase[i + 6] == 0x56 && textBase[i + 7] == 0x57 && textBase[i + 8] == 0x41 &&
                    textBase[i + 9] == 0x56 && textBase[i + 10] == 0x41 && textBase[i + 11] == 0x57 &&
                    textBase[i + 12] == 0x48 && textBase[i + 13] == 0x81 && textBase[i + 14] == 0xEC &&
                    textBase[i + 19] == 0x48 && textBase[i + 20] == 0x8B && textBase[i + 21] == 0x05 &&
                    textBase[i + 26] == 0x48 && textBase[i + 27] == 0x33 && textBase[i + 28] == 0xC4 &&
                    textBase[i + 37] == 0x41 && textBase[i + 38] == 0x8B && textBase[i + 39] == 0xD8)
                {
                    MmSetPageProtection = (decltype(MmSetPageProtection))(textBase + i);
                    LOG_DEBUG(_XOR_("[VtBootstrapDriver] Pattern matched MmSetPageProtection=%p (RVA=0x%X)\n"),
                        MmSetPageProtection, (ULONG)((ULONG_PTR)MmSetPageProtection - ntosBase));
                }

                if (MmAllocateIndependentPages && MmFreeIndependentPages && MmSetPageProtection)
                    return TRUE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] MapDriverScanCoreSymbolsInText exception=0x%X\n"), GetExceptionCode());
        }

        LOG_DEBUG(_XOR_("[VtBootstrapDriver] MapDriverScanCoreSymbolsInText result: alloc=%p free=%p prot=%p\n"),
            MmAllocateIndependentPages, MmFreeIndependentPages, MmSetPageProtection);
        return (MmAllocateIndependentPages && MmFreeIndependentPages && MmSetPageProtection) ? TRUE : FALSE;
    }

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
        {
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] MapDriverReadNtosKey failed for ntos=%p\n"), (PVOID)ntosBase);
            return FALSE;
        }

        LOG_DEBUG(_XOR_("[VtBootstrapDriver] ntoskrnl key: base=%p TimeDateStamp=0x%08X SizeOfImage=0x%08X CheckSum=0x%08X\n"),
            (PVOID)ntosBase, timeDateStamp, sizeOfImage, checksum);

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
            LOG_DEBUG(_XOR_("[VtBootstrapDriver] Hardcoded RVA table hit [#%u]: alloc=%p free=%p prot=%p\n"),
                i, MmAllocateIndependentPages, MmFreeIndependentPages, MmSetPageProtection);
            return TRUE;
        }

        LOG_DEBUG(_XOR_("[VtBootstrapDriver] Hardcoded RVA table miss, falling back to .text pattern scan...\n"));
        return MapDriverScanCoreSymbolsInText(ntosBase);
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
