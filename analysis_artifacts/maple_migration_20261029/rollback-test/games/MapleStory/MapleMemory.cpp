#include "MapleMemory.h"
#include "MapleLayout.h"

static volatile LONG64 g_MapleTargetCr3 = 0;
static volatile LONG64 g_MapleImageBase = 0;

NTSTATUS MapleMemory::BindTarget(ULONG64 TargetCr3, ULONG64 ImageBase)
{
    if ((TargetCr3 & 0xFFFULL) != 0 || TargetCr3 == 0 || !IsUserRange(ImageBase, PAGE_SIZE))
    {
        DBG("[-] [Maple] MapleMemory::BindTarget: Invalid parameter (TargetCr3=0x%llX, ImageBase=0x%llX)", TargetCr3, ImageBase);
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedExchange64(&g_MapleImageBase, static_cast<LONG64>(ImageBase));
    InterlockedExchange64(&g_MapleTargetCr3, static_cast<LONG64>(TargetCr3));
    DBG("[+] [Maple] MapleMemory::BindTarget: Target bound (CR3=0x%llX, Base=0x%llX)", TargetCr3, ImageBase);
    return STATUS_SUCCESS;
}

VOID MapleMemory::Reset()
{
    const ULONG64 prevCr3 = static_cast<ULONG64>(InterlockedExchange64(&g_MapleTargetCr3, 0));
    const ULONG64 prevBase = static_cast<ULONG64>(InterlockedExchange64(&g_MapleImageBase, 0));
    if (prevCr3 != 0 || prevBase != 0)
    {
        DBG("[*] [Maple] MapleMemory::Reset: Target unbound (PrevCR3=0x%llX, PrevBase=0x%llX)", prevCr3, prevBase);
    }
}

BOOLEAN MapleMemory::IsUserRange(ULONG64 Address, ULONG Size)
{
    if (Address < MapleLayout::UserAddressMin || Address > MapleLayout::UserAddressMax || Size == 0)
        return FALSE;

    const ULONG64 last = Address + static_cast<ULONG64>(Size) - 1;
    return last >= Address && last <= MapleLayout::UserAddressMax;
}

BOOLEAN MapleMemory::ReadBuffer(ULONG64 Address, PVOID Buffer, ULONG Size)
{
    const ULONG64 cr3 = GetTargetCr3();
    if (!cr3 || !Buffer || !IsUserRange(Address, Size))
        return FALSE;

    return LeechCoreEngine::ReadVirtualMemory(cr3, Address, Buffer, Size);
}

BOOLEAN MapleMemory::WriteBuffer(ULONG64 Address, const PVOID Buffer, ULONG Size)
{
    const ULONG64 cr3 = GetTargetCr3();
    if (!cr3 || !Buffer || !IsUserRange(Address, Size))
        return FALSE;

    return LeechCoreEngine::WriteVirtualMemory(cr3, Address, Buffer, Size);
}

ULONG64 MapleMemory::GetTargetCr3()
{
    return static_cast<ULONG64>(InterlockedCompareExchange64(&g_MapleTargetCr3, 0, 0));
}

ULONG64 MapleMemory::GetImageBase()
{
    return static_cast<ULONG64>(InterlockedCompareExchange64(&g_MapleImageBase, 0, 0));
}

BOOLEAN MapleMemory::ScanZeroCave(ULONG64 StartAddress, ULONG RangeSize, ULONG RequiredSize, ULONG Alignment, PULONG64 OutAddress)
{
    if (!StartAddress || !RangeSize || !RequiredSize || !OutAddress || RequiredSize > RangeSize)
        return FALSE;

    if (Alignment == 0)
        Alignment = 16;

    // 采用反向回溯分块扫描（Reverse Scan）：节区对齐填充与未用数据天然集中在尾部
    const ULONG chunkSize = 1024;
    UCHAR chunk[chunkSize];

    ULONG consecutiveZeros = 0;
    ULONG64 candidateEnd = 0;
    ULONG64 current = StartAddress + RangeSize;

    while (current > StartAddress)
    {
        ULONG toRead = chunkSize;
        if (current - StartAddress < toRead)
        {
            toRead = static_cast<ULONG>(current - StartAddress);
        }

        ULONG64 readAddr = current - toRead;
        if (!ReadBuffer(readAddr, chunk, toRead))
        {
            consecutiveZeros = 0;
            current = readAddr;
            continue;
        }

        for (LONG i = static_cast<LONG>(toRead) - 1; i >= 0; --i)
        {
            if (chunk[i] == 0)
            {
                if (consecutiveZeros == 0)
                {
                    candidateEnd = readAddr + i + 1;
                }
                consecutiveZeros++;

                if (consecutiveZeros >= RequiredSize)
                {
                    ULONG64 candidateStart = candidateEnd - consecutiveZeros;
                    ULONG64 alignedStart = (candidateStart + Alignment - 1) & ~(static_cast<ULONG64>(Alignment) - 1);
                    if (alignedStart + RequiredSize <= candidateEnd)
                    {
                        *OutAddress = alignedStart;
                        return TRUE;
                    }
                }
            }
            else
            {
                consecutiveZeros = 0;
            }
        }

        current = readAddr;
    }

    return FALSE;
}

BOOLEAN MapleMemory::FindAdaptiveCodeCave(ULONG RequiredSize, PULONG64 OutRva)
{
    if (!OutRva)
        return FALSE;
    *OutRva = 0;

    const ULONG64 imageBase = GetImageBase();
    if (!imageBase)
        return FALSE;

    IMAGE_DOS_HEADER dos = {};
    if (ReadBuffer(imageBase, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 && dos.e_lfanew < 0x1000)
    {
        IMAGE_NT_HEADERS64 nt = {};
        if (ReadBuffer(imageBase + dos.e_lfanew, &nt, sizeof(nt)) && nt.Signature == IMAGE_NT_SIGNATURE)
        {
            const ULONG secCount = nt.FileHeader.NumberOfSections;
            const ULONG64 secBase = imageBase + dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;

            for (ULONG i = 0; i < secCount && i < 64; ++i)
            {
                IMAGE_SECTION_HEADER sec = {};
                if (!ReadBuffer(secBase + i * sizeof(sec), &sec, sizeof(sec)))
                    break;

                // 筛选代码节：IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ，且无 IMAGE_SCN_MEM_WRITE
                if ((sec.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ) &&
                    !(sec.Characteristics & IMAGE_SCN_MEM_WRITE))
                {
                    ULONG secSize = (sec.Misc.VirtualSize + 0xFFF) & ~0xFFF;
                    if (secSize < sec.Misc.VirtualSize)
                        secSize = sec.Misc.VirtualSize;

                    ULONG64 foundAddr = 0;
                    if (ScanZeroCave(imageBase + sec.VirtualAddress, secSize, RequiredSize, 16, &foundAddr))
                    {
                        *OutRva = foundAddr - imageBase;
                        DBG("[+] [MapleMemory] FindAdaptiveCodeCave: Found executable zero cave at RVA=0x%llX (Size=%lu, Sec=%.8s)",
                            *OutRva, RequiredSize, sec.Name);
                        return TRUE;
                    }
                }
            }
        }
    }

    // 回退到经 IDA 确证的基线并探针验证
    ULONG64 defaultAddr = imageBase + MapleLayout::DefaultCodeCaveRva;
    UCHAR probe[64] = {};
    if (ReadBuffer(defaultAddr, probe, sizeof(probe)))
    {
        BOOLEAN isZero = TRUE;
        for (ULONG k = 0; k < sizeof(probe); ++k)
        {
            if (probe[k] != 0)
            {
                isZero = FALSE;
                break;
            }
        }
        if (isZero)
        {
            *OutRva = MapleLayout::DefaultCodeCaveRva;
            DBG("[*] [MapleMemory] FindAdaptiveCodeCave: Fallback baseline RVA=0x%llX verified (clean zeros)", *OutRva);
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN MapleMemory::FindAdaptiveDataCave(ULONG RequiredSize, PULONG64 OutRva)
{
    if (!OutRva)
        return FALSE;
    *OutRva = 0;

    const ULONG64 imageBase = GetImageBase();
    if (!imageBase)
        return FALSE;

    IMAGE_DOS_HEADER dos = {};
    if (ReadBuffer(imageBase, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 && dos.e_lfanew < 0x1000)
    {
        IMAGE_NT_HEADERS64 nt = {};
        if (ReadBuffer(imageBase + dos.e_lfanew, &nt, sizeof(nt)) && nt.Signature == IMAGE_NT_SIGNATURE)
        {
            const ULONG secCount = nt.FileHeader.NumberOfSections;
            const ULONG64 secBase = imageBase + dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;

            for (ULONG i = 0; i < secCount && i < 64; ++i)
            {
                IMAGE_SECTION_HEADER sec = {};
                if (!ReadBuffer(secBase + i * sizeof(sec), &sec, sizeof(sec)))
                    break;

                // 筛选数据节：IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE，且无 IMAGE_SCN_MEM_EXECUTE
                if ((sec.Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) == (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) &&
                    !(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                {
                    ULONG secSize = (sec.Misc.VirtualSize + 0xFFF) & ~0xFFF;
                    if (secSize < sec.Misc.VirtualSize)
                        secSize = sec.Misc.VirtualSize;

                    ULONG64 foundAddr = 0;
                    if (ScanZeroCave(imageBase + sec.VirtualAddress, secSize, RequiredSize, 16, &foundAddr))
                    {
                        *OutRva = foundAddr - imageBase;
                        DBG("[+] [MapleMemory] FindAdaptiveDataCave: Found read/write zero cave at RVA=0x%llX (Size=%lu, Sec=%.8s)",
                            *OutRva, RequiredSize, sec.Name);
                        return TRUE;
                    }
                }
            }
        }
    }

    // 回退到经 IDA 确证的基线并探针验证
    ULONG64 defaultAddr = imageBase + MapleLayout::DefaultDataCaveRva;
    UCHAR probe[64] = {};
    if (ReadBuffer(defaultAddr, probe, sizeof(probe)))
    {
        BOOLEAN isZero = TRUE;
        for (ULONG k = 0; k < sizeof(probe); ++k)
        {
            if (probe[k] != 0)
            {
                isZero = FALSE;
                break;
            }
        }
        if (isZero)
        {
            *OutRva = MapleLayout::DefaultDataCaveRva;
            DBG("[*] [MapleMemory] FindAdaptiveDataCave: Fallback baseline RVA=0x%llX verified (clean zeros)", *OutRva);
            return TRUE;
        }
    }

    return FALSE;
}
