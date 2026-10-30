#include "Common.h"
#include "GameStruct.h"
#include "XString.h"
#include "DebugShellcode.h"

#include <intrin.h>
#include <new>

#pragma section(".xinit$a", execute, read)
#pragma section(".xinit$m", execute, read)
#pragma section(".xinit$z", execute, read)

extern "C" __declspec(allocate(".xinit$a"))
const std::uint8_t RuntimeInitImageStart[] = { 0xC3 };

#pragma code_seg(push, ".xinit$m")

SIZE_T Utils_Strlen(_In_ PCSTR Str)
{
    PCSTR p = Str;
    while (*p)
        ++p;
    return (SIZE_T)(p - Str);
}

BOOLEAN Utils_GetModuleExport(IN ULONG_PTR BaseAddress, IN ULONG U32FunctionName, OUT ULONG_PTR* FunctionAddress)
{
    if (!BaseAddress || !FunctionAddress)
        return FALSE;
    *FunctionAddress = 0;
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)BaseAddress;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE || pDosHdr->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        pDosHdr->e_lfanew > 0x00100000)
        return FALSE;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(BaseAddress + pDosHdr->e_lfanew);
    if (pNtHdr->Signature != IMAGE_NT_SIGNATURE || pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return FALSE;
    const IMAGE_DATA_DIRECTORY exportDir = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.VirtualAddress || !exportDir.Size)
        return FALSE;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(BaseAddress + exportDir.VirtualAddress);
    if (!pExport->NumberOfNames || !pExport->AddressOfNames || !pExport->AddressOfFunctions ||
        !pExport->AddressOfNameOrdinals)
        return FALSE;
    PULONG AddressOfNames = (PULONG)(BaseAddress + pExport->AddressOfNames);
    PULONG AddressOfFunctions = (PULONG)(BaseAddress + pExport->AddressOfFunctions);
    PUSHORT AddressOfNameOrdinals = (PUSHORT)(BaseAddress + pExport->AddressOfNameOrdinals);
    const ULONG exportEnd = exportDir.VirtualAddress + exportDir.Size;
    if (exportEnd < exportDir.VirtualAddress)
        return FALSE;
    for (ULONG i = 0; i < pExport->NumberOfNames; i++)
    {
        if (!AddressOfNames[i])
            continue;
        CHAR* cpFunctionName = (CHAR*)(BaseAddress + AddressOfNames[i]);
        const SIZE_T nameSize = Utils_Strlen(cpFunctionName);
        if (Utils_HashStringImulMagicExA(cpFunctionName, nameSize, TRUE) == U32FunctionName)
        {
            const USHORT ordinal = AddressOfNameOrdinals[i];
            if (ordinal >= pExport->NumberOfFunctions || !AddressOfFunctions[ordinal])
                return FALSE;
            const ULONG functionRva = AddressOfFunctions[ordinal];
            if (functionRva >= exportDir.VirtualAddress && functionRva < exportEnd)
                return FALSE;
            *FunctionAddress = (ULONG_PTR)BaseAddress + functionRva;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN IsValidCfgIndirectCallRet28(
    IN ULONG_PTR ModuleBase,
    IN ULONG ImageSize,
    IN const UCHAR* Instruction)
{
    if (!ModuleBase || ImageSize < 11 || !Instruction || ModuleBase > MAXULONG_PTR - ImageSize)
        return FALSE;

    const ULONG_PTR imageEnd = ModuleBase + ImageSize;
    const ULONG_PTR instructionVa = reinterpret_cast<ULONG_PTR>(Instruction);
    if (instructionVa < ModuleBase || instructionVa > imageEnd - 11)
        return FALSE;

    // FF 15 disp32; add rsp,28h; ret
    if (Instruction[0] != 0xFF || Instruction[1] != 0x15 ||
        Instruction[6] != 0x48 || Instruction[7] != 0x83 ||
        Instruction[8] != 0xC4 || Instruction[9] != 0x28 ||
        Instruction[10] != 0xC3)
    {
        return FALSE;
    }

    const LONG displacement = *reinterpret_cast<const LONG*>(Instruction + 2);
    const ULONG_PTR nextInstruction = instructionVa + 6;
    ULONG_PTR pointerSlot = 0;
    if (displacement >= 0)
    {
        const ULONG_PTR delta = static_cast<ULONG_PTR>(displacement);
        if (nextInstruction > MAXULONG_PTR - delta)
            return FALSE;
        pointerSlot = nextInstruction + delta;
    }
    else
    {
        const ULONG_PTR delta = static_cast<ULONG_PTR>(-(static_cast<LONG64>(displacement)));
        if (nextInstruction < delta)
            return FALSE;
        pointerSlot = nextInstruction - delta;
    }

    if (pointerSlot < ModuleBase || pointerSlot > imageEnd - sizeof(ULONG_PTR))
        return FALSE;
    return *reinterpret_cast<const ULONG_PTR*>(pointerSlot) != 0;
}

#pragma pack(push, 1)
struct SPOOF_UNWIND_CODE {
    UCHAR CodeOffset;
    UCHAR UnwindOp : 4;
    UCHAR OpInfo : 4;
};

struct SPOOF_UNWIND_INFO {
    UCHAR Version : 3;
    UCHAR Flags : 5;
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameRegister : 4;
    UCHAR FrameOffset : 4;
    SPOOF_UNWIND_CODE UnwindCode[1];
};
#pragma pack(pop)

static BOOLEAN QueryInstructionUnwindFrameSize(
    IN ULONG_PTR ModuleBase,
    IN ULONG ImageSize,
    IN ULONG_PTR InstructionVa,
    OUT ULONG* OutFrameSize)
{
    if (!ModuleBase || !ImageSize || !InstructionVa || !OutFrameSize ||
        InstructionVa < ModuleBase || InstructionVa - ModuleBase >= ImageSize)
        return FALSE;

    *OutFrameSize = 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(ModuleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        dos->e_lfanew > 0x00100000)
        return FALSE;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return FALSE;

    const IMAGE_DATA_DIRECTORY& directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) ||
        directory.VirtualAddress >= ImageSize || directory.Size > ImageSize - directory.VirtualAddress)
        return FALSE;

    const ULONG rva = static_cast<ULONG>(InstructionVa - ModuleBase);
    const auto* functions = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(
        ModuleBase + directory.VirtualAddress);
    const ULONG count = directory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    ULONG low = 0;
    ULONG high = count;
    const IMAGE_RUNTIME_FUNCTION_ENTRY* hit = nullptr;
    while (low < high)
    {
        const ULONG middle = low + ((high - low) / 2);
        if (rva < functions[middle].BeginAddress)
            high = middle;
        else if (rva >= functions[middle].EndAddress)
            low = middle + 1;
        else
        {
            hit = &functions[middle];
            break;
        }
    }

    // 不在 .pdata 中的是叶子代码，RtlVirtualUnwind 直接取 [RSP]。
    if (!hit)
        return TRUE;

    const ULONG unwindRva = hit->UnwindInfoAddress & ~3u;
    if (!unwindRva || unwindRva >= ImageSize ||
        ImageSize - unwindRva < sizeof(SPOOF_UNWIND_INFO))
        return FALSE;
    const auto* unwind = reinterpret_cast<const SPOOF_UNWIND_INFO*>(ModuleBase + unwindRva);
    if (unwind->Version != 1 || (unwind->Flags & 0x04) != 0 || unwind->FrameRegister != 0 ||
        rva - hit->BeginAddress < unwind->SizeOfProlog || unwind->CountOfCodes > 128)
        return FALSE;

    ULONG frameSize = 0;
    for (UCHAR i = 0; i < unwind->CountOfCodes; ++i)
    {
        const UCHAR operation = unwind->UnwindCode[i].UnwindOp;
        const UCHAR info = unwind->UnwindCode[i].OpInfo;
        if (operation == 0) // UWOP_PUSH_NONVOL
        {
            if (frameSize > 0xFFFFFFFFu - 8u)
                return FALSE;
            frameSize += 8;
        }
        else if (operation == 1) // UWOP_ALLOC_LARGE
        {
            if (info == 0)
            {
                if (++i >= unwind->CountOfCodes)
                    return FALSE;
                const ULONG allocation = static_cast<ULONG>(
                    *reinterpret_cast<const USHORT*>(&unwind->UnwindCode[i])) * 8u;
                if (frameSize > 0xFFFFFFFFu - allocation)
                    return FALSE;
                frameSize += allocation;
            }
            else if (info == 1)
            {
                if (i + 2 >= unwind->CountOfCodes)
                    return FALSE;
                const ULONG allocation = *reinterpret_cast<const ULONG*>(&unwind->UnwindCode[i + 1]);
                if (frameSize > 0xFFFFFFFFu - allocation)
                    return FALSE;
                frameSize += allocation;
                i += 2;
            }
            else
                return FALSE;
        }
        else if (operation == 2) // UWOP_ALLOC_SMALL
        {
            const ULONG allocation = static_cast<ULONG>(info) * 8u + 8u;
            if (frameSize > 0xFFFFFFFFu - allocation)
                return FALSE;
            frameSize += allocation;
        }
        else if (operation == 3 || operation == 10) // SET_FPREG / PUSH_MACHFRAME
            return FALSE;
        else if (operation == 4 || operation == 5 || operation == 8 || operation == 9)
        {
            // SAVE_NONVOL/SAVE_XMM 只描述已分配帧中的保存槽，不改变 RSP。
            if (operation == 5 || operation == 9)
            {
                if (++i >= unwind->CountOfCodes)
                    return FALSE;
                if (i + 1 >= unwind->CountOfCodes)
                    return FALSE;
                ++i;
            }
            else
            {
                if (++i >= unwind->CountOfCodes)
                    return FALSE;
            }
        }
        else
            return FALSE;
    }

    *OutFrameSize = frameSize;
    return TRUE;
}

static BOOLEAN ScanTextForSpoofGadgets(
    IN ULONG_PTR ModuleBase,
    _Inout_ vt_debug_shellcode::SPOOF_GADGET_PAIR* OutGadgets)
{
    if (!ModuleBase || !OutGadgets)
        return FALSE;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(ModuleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        dos->e_lfanew > 0x00100000)
        return FALSE;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        !nt->OptionalHeader.SizeOfImage || nt->FileHeader.NumberOfSections == 0 ||
        nt->FileHeader.NumberOfSections > 96)
        return FALSE;

    const ULONG imageSize = nt->OptionalHeader.SizeOfImage;
    if (ModuleBase > MAXULONG_PTR - imageSize)
        return FALSE;

    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (USHORT sectionIndex = 0; sectionIndex < nt->FileHeader.NumberOfSections; ++sectionIndex)
    {
        const IMAGE_SECTION_HEADER& section = sections[sectionIndex];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;

        const ULONG sectionSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
        if (!sectionSize || section.VirtualAddress >= imageSize || sectionSize > imageSize - section.VirtualAddress)
            continue;

        const auto* text = reinterpret_cast<const UCHAR*>(ModuleBase + section.VirtualAddress);
        for (ULONG offset = 0; offset + 2 <= sectionSize; ++offset)
        {
            if (!OutGadgets->CallRaxAddRsp28Ret && offset + 7 <= sectionSize &&
                text[offset] == 0xFF && text[offset + 1] == 0xD0 &&
                text[offset + 2] == 0x48 && text[offset + 3] == 0x83 &&
                text[offset + 4] == 0xC4 && text[offset + 5] == 0x28 &&
                text[offset + 6] == 0xC3)
            {
                OutGadgets->CallRaxAddRsp28Ret = reinterpret_cast<ULONG_PTR>(text + offset);
            }

            if (!OutGadgets->CallRaxAddRsp28Ret && offset + 11 <= sectionSize &&
                IsValidCfgIndirectCallRet28(ModuleBase, imageSize, text + offset))
            {
                OutGadgets->CallRaxAddRsp28Ret = reinterpret_cast<ULONG_PTR>(text + offset);
            }

            if (!OutGadgets->JmpQwordPtrRbx &&
                text[offset] == 0xFF && text[offset + 1] == 0x23)
            {
                ULONG frameSize = 0;
                if (QueryInstructionUnwindFrameSize(
                        ModuleBase,
                        imageSize,
                        reinterpret_cast<ULONG_PTR>(text + offset),
                        &frameSize))
                {
                    OutGadgets->JmpQwordPtrRbx = reinterpret_cast<ULONG_PTR>(text + offset);
                    OutGadgets->JmpFrameSize = frameSize;
                }
            }

            if (OutGadgets->CallRaxAddRsp28Ret && OutGadgets->JmpQwordPtrRbx)
                return TRUE;
        }
    }
    return OutGadgets->CallRaxAddRsp28Ret && OutGadgets->JmpQwordPtrRbx;
}

ULONG Utils_HashStringImulMagicExA(IN CONST PCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase)
{
    ULONG Result = 0;
    if (s && Length) {
        if (Length > 2048)
            Length = 2048;
        for (SIZE_T i = 0; i < Length; i++) {
            CHAR c = s[i];
            if (c == '\0')
                break;
            Result *= 0x1003f;
            if (bIgnoreCase && c >= 'A' && c <= 'Z')
                Result += 'a' + c - 'A';
            else
                Result += c;
        }
    }
    return Result;
}

ULONG Utils_HashStringImulMagicExW(IN CONST PWCHAR s, IN SIZE_T Length, IN BOOLEAN bIgnoreCase)
{
    ULONG Result = 0;
    if (s && Length) {
        if (Length > 2048)
            Length = 2048;
        for (SIZE_T i = 0; i < Length; i++) {
            WCHAR c = s[i];
            if (c == L'\0')
                break;
            Result *= 0x1003f;
            if (bIgnoreCase && c >= L'A' && c <= L'Z')
                Result += L'a' + c - L'A';
            else
                Result += c;
        }
    }
    return Result;
}

BOOLEAN Utils_HashStringImulMagicFindA(IN CONST PCHAR s, IN SIZE_T Length, IN ULONG FindData, IN SIZE_T FindSize)
{
    if (s && Length) {
        if (Length > 2048)
            Length = 2048;
        size_t i = 0;
        while (i + FindSize <= Length) {
            if (Utils_HashStringImulMagicExA(s + i, FindSize, true) == FindData)
                return true;
            i++;
        }
    }
    return false;
}

BOOLEAN Utils_HashStringImulMagicFindW(IN CONST PWCHAR s, IN SIZE_T Length, IN ULONG FindData, IN SIZE_T FindSize)
{
    if (s && Length) {
        if (Length > 2048)
            Length = 2048;
        size_t i = 0;
        while (i + FindSize <= Length) {
            if (Utils_HashStringImulMagicExW(s + i, FindSize, true) == FindData)
                return true;
            i++;
        }
    }
    return false;
}

//[[clang::annotate("bcf,fla,sub,mba-subs")]]
void __fastcall RuntimeOffsetInit(IN GENERIC_OFFSET_TABLE*& Offset)
{
    Offset->Class_UWorld                            = (0x1fb98c88);
    Offset->Class_GName                             = (0x206cbe00);
    //常规加密
    //Offset->Class_NormalDecodeParame               = XorU32(0x19cc4f58);
    //Offset->Class_NormalDecodeFlag                 = XorU32(0x19cc4f60);
    //Offset->Class_NormalDecodePtrFunc              = XorU32(0x19cf0920);
    //动态加密
    //Offset->Class_DynamicDecodeCallPtr             = XorU32(0x19025048);
    //Offset->Call_CryptoOffAddress                   = XorU32(0x1221110);
    //GName加密
    Offset->Call_NameDecodeWCHAR                  = (0x14f66260);
    Offset->Call_NameDecodeCHAR                   = (0x14f66050);
    //ComponentToWorld解密
    //Offset->Class_CTWWritePtrHook                   = XorU32(0x187e49d8);
    //position解密
    //Offset->Class_PosWritePtrHook                   = XorU32(0x19cc0ab0);
    //Offset->Class_PosWritePtrOriginal               = XorU32(0x2be86b0);

    //Offset->Class_PosASMCallPtr1                    = XorU32(0x19cc0ab8);
    //Offset->Class_PosASMCallPtr2                    = XorU32(0x187e4a08);
    //Offset->Class_PosASMCallAddress1                = XorU32(0x2be8350);
    //Offset->Class_PosASMCallAddress2                = XorU32(0x2befb50);

    Offset->OffSet_AActor_ObjectID                              = (0x1C);
    //Offset->OffSet_AActor_RootComponent                         = XorU32(0x180);
    Offset->OffSet_UWorld_PersistentLevel                       = (0xF8);
    //Offset->OffSet_UWorld_GameState                             = XorU32(0x140);
    //Offset->OffSet_ADFMGameState_DFMGamePlayerMode              = XorU32(0x6C9);
    //Offset->OffSet_UWorld_Levels                                = XorU32(0x158);
    //Offset->OffSet_UWorld_OwningGameInstance                    = XorU32(0x190);
    //Offset->OffSet_UGameInstance_LocalPlayers                   = XorU32(0x38);
    //Offset->OffSet_UPlayer_PlayerController                     = XorU32(0x30);
    //Offset->OffSet_APlayerController_AcknowledgedPawn           = XorU32(0x3F0);
    //Offset->OffSet_APlayerController_PlayerCameraManager        = XorU32(0x408);
    //Offset->OffSet_APlayerCameraManager_CameraCachePrivate      = XorU32(0x2F2E0);
    //Offset->OffSet_FCameraCacheEntry_POV                        = XorU32(0x10);
    //Offset->OffSet_FMinimalViewInfo_Location                    = XorU32(0);
    Offset->OffSet_ULevel_Tarray                                = (0x98);
    Offset->OffSet_ACHARACTER_Mesh                              = (0x3D0);
    //Offset->OffSet_USceneComponent_Bounds                       = XorU32(0x148);
    //Offset->OffSet_USceneComponent_RelativeLocation             = XorU32(0x168);
    Offset->OffSet_USceneComponent_ComponentToWorld             = (0x210);
    //Offset->OffSet_AGPCharacterBase_CacheCurWeapon              = XorU32(0x1708);
    //Offset->OffSet_AWeaponBase_WeaponFuncComponentFiring        = XorU32(0x4B8);//未公开
    //Offset->OffSet_UGPWeaponFuncComponentFiring_CurrentFireMode = XorU32(0x178);
    //Offset->OffSet_UGPWeaponFireModeBase_Params_0               = XorU32(0xC8);
    //Offset->OffSet_ADFMCharacter_CharacterEquipComponentCache   = XorU32(0x2320);
    //Offset->OffSet_ADFMCharacter_DFMHealthDataComponent         = XorU32(0x2328);
    //Offset->OffSet_UGPHealthDataComponent_HealthSet             = XorU32(0x280);
}

static void RuntimeReleaseContext(IN PGENERIC_RUNTIME_CONTEXT UserVar)
{
    if (!UserVar || !UserVar->Func || !UserVar->Func->free)
        return;
    GENERIC_FUNCTION_TABLE* Func = UserVar->Func;
    if (UserVar->u)
    {
        if (UserVar->u->MessageText)
            Func->free((void*)UserVar->u->MessageText);
        if (UserVar->u->MessageCaption)
            Func->free((void*)UserVar->u->MessageCaption);
        if (UserVar->u->TransformCache)
        {
            if (UserVar->u->TransformCache->Data)
                Func->free(UserVar->u->TransformCache->Data);
            Func->free(UserVar->u->TransformCache);
        }
        Func->free(UserVar->u);
    }
    if (UserVar->p)
        Func->free(UserVar->p);
    if (UserVar->Offset)
        Func->free(UserVar->Offset);
    Func->free(UserVar->Func);
    Func->free(UserVar);
}

static bool RuntimeInitWithInput(IN PGENERIC_RUNTIME_CONTEXT* pUserVar, IN const void* input)
{
    UNREFERENCED_PARAMETER(input);
    WCHAR messageText[31] = {};
    WCHAR messageCaption[17] = {};
    messageText[0] = 0x0044; messageText[1] = 0x0065; messageText[2] = 0x0062;
    messageText[3] = 0x0075; messageText[4] = 0x0067; messageText[5] = 0x0053;
    messageText[6] = 0x0068; messageText[7] = 0x0065; messageText[8] = 0x006C;
    messageText[9] = 0x006C; messageText[10] = 0x0063; messageText[11] = 0x006F;
    messageText[12] = 0x0064; messageText[13] = 0x0065; messageText[14] = 0x0020;
    messageText[15] = 0x0052; messageText[16] = 0x0075; messageText[17] = 0x006E;
    messageText[18] = 0x0074; messageText[19] = 0x0069; messageText[20] = 0x006D;
    messageText[21] = 0x0065; messageText[22] = 0x0044; messageText[23] = 0x0069;
    messageText[24] = 0x0073; messageText[25] = 0x0070; messageText[26] = 0x0061;
    messageText[27] = 0x0074; messageText[28] = 0x0063; messageText[29] = 0x0068;
    messageCaption[0] = 0x004E; messageCaption[1] = 0x006F; messageCaption[2] = 0x0074;
    messageCaption[3] = 0x0065; messageCaption[4] = 0x0070; messageCaption[5] = 0x0061;
    messageCaption[6] = 0x0064; messageCaption[7] = 0x0020; messageCaption[8] = 0x004E;
    messageCaption[9] = 0x0050; messageCaption[10] = 0x0054; messageCaption[11] = 0x0020;
    messageCaption[12] = 0x0074; messageCaption[13] = 0x0065; messageCaption[14] = 0x0073;
    messageCaption[15] = 0x0074;
    volatile ULONG DllBaseArray[] = {
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_ntdll_dll,
        wstr_KERNEL32_dll,
        wstr_KERNEL32_dll,
        wstr_KERNEL32_dll,
        wstr_KERNEL32_dll,
        wstr_KERNEL32_dll,
        wstr_KERNEL32_dll,
        wstr_KERNEL32_dll,
        wstr_ucrtbase_dll,
        wstr_ucrtbase_dll,
        wstr_ucrtbase_dll,
        wstr_ucrtbase_dll,
        wstr_ucrtbase_dll,
        wstr_ucrtbase_dll,
        wstr_USER32_dll,
        wstr_dbgcore_DLL,
        wstr_USER32_dll,
    };
    volatile ULONG FunctionArray[] = {
        str_RtlInitializeCriticalSection,
        str_RtlEnterCriticalSection,
        str_RtlLeaveCriticalSection,
        str_RtlAcquireSRWLockExclusive,
        str_RtlReleaseSRWLockExclusive,
        str_RtlAcquireSRWLockShared,
        str_RtlReleaseSRWLockShared,
        str_RtlTryAcquireSRWLockExclusive,
        str_strcpy_s,
        str_wcscpy_s,
        str_memset,
        str_memcpy,
        str_memmove,
        str_OutputDebugStringA,
        str_OutputDebugStringW,
        str_GetTickCount64,
        str_TerminateProcess,
        str_CreateFileW,
        str_CloseHandle,
        str_VirtualQuery,
        str_stdio_common_vsprintf_s,
        str_stdio_common_vswprintf_s,
        str_malloc,
        str_free,
        str_msize,
        str_realloc,
        str_GetAsyncKeyState,
        str_MiniDumpWriteDump,
        str_MessageBoxW,
    };
    HANDLE CurrentPid = (HANDLE) * (ULONG_PTR*)((PUCHAR)__readgsqword(0x30) + 0x40);
    //HANDLE CurrentTid = (HANDLE) * (ULONG_PTR*)((PUCHAR)__readgsqword(0x30) + 0x48);
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb) {
        if (pPeb->Ldr) {
            GENERIC_FUNCTION_TABLE pfnTable;
            ULONG_PTR* pfnArray = (ULONG_PTR*)&pfnTable;
            volatile ULONG_PTR* pfnZero = pfnArray;
            for (SIZE_T i = 0; i < sizeof(GENERIC_FUNCTION_TABLE) / sizeof(ULONG_PTR); ++i)
                pfnZero[i] = 0;
            ULONG_PTR tempHostImageBase = 0;
            ULONG_PTR tempNtdllBase = 0;
            ULONG_PTR tempKernel32Base = 0;
            ULONG_PTR tempUser32Base = 0;
            for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
                pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
                pListEntry = pListEntry->Flink) {
                PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                ULONG U32BaseDllName = Utils_HashStringImulMagicExW(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / sizeof(WCHAR), TRUE);
                for (size_t i = 0; i < ARRAY_SIZE(DllBaseArray); i++) {
                    if (U32BaseDllName == DllBaseArray[i]) {
                        Utils_GetModuleExport((ULONG_PTR)pEntry->DllBase, FunctionArray[i], &pfnArray[i]);
                    }
                }
                ////get some dll get
                if ( U32BaseDllName == wstr_notepad_exe) {
                    tempHostImageBase = (ULONG_PTR)pEntry->DllBase;
                }
                if (U32BaseDllName == wstr_ntdll_dll)
                    tempNtdllBase = (ULONG_PTR)pEntry->DllBase;
                else if (U32BaseDllName == wstr_KERNEL32_dll)
                    tempKernel32Base = (ULONG_PTR)pEntry->DllBase;
                else if (U32BaseDllName == wstr_USER32_dll)
                    tempUser32Base = (ULONG_PTR)pEntry->DllBase;
            }
            if (!tempHostImageBase || !pfnTable.malloc || !pfnTable.free || !pfnTable.realloc ||
                !pfnTable.memset || !pfnTable.memcpy || !pfnTable.memmove ||
                !pfnTable.GetTickCount64 || !pfnTable.MessageBoxW ||
                !pfnTable.RtlInitializeCriticalSection)
                return false;

            vt_debug_shellcode::SPOOF_GADGET_PAIR spoofGadgets = {};
            const ULONG_PTR gadgetModules[] = {
                tempHostImageBase,
                tempNtdllBase,
                tempKernel32Base,
                tempUser32Base,
            };
            for (SIZE_T i = 0; i < ARRAY_SIZE(gadgetModules); ++i)
            {
                if (gadgetModules[i] && ScanTextForSpoofGadgets(gadgetModules[i], &spoofGadgets))
                    break;
            }

            // Native Gadget 模式只接受合法已加载模块内的 Gadget；缺少任一成员即失败关闭。
            // Ghost 模式不借用 Native Gadget，但仍要求后续由驱动提供已安装的 GhostRetVa。
#if VT_SHELLCODE_SPOOF_MODE != VT_SHELLCODE_SPOOF_MODE_GHOST_CALL
            if (!spoofGadgets.CallRaxAddRsp28Ret || !spoofGadgets.JmpQwordPtrRbx)
                return false;
#endif

            GENERIC_FUNCTION_TABLE* Func = (GENERIC_FUNCTION_TABLE*)pfnTable.malloc(sizeof(GENERIC_FUNCTION_TABLE));
            if (!Func)
                return false;
            pfnTable.memcpy(Func, &pfnTable, sizeof(GENERIC_FUNCTION_TABLE));
            GENERIC_OFFSET_TABLE* Offset = (GENERIC_OFFSET_TABLE*)pfnTable.malloc(sizeof(GENERIC_OFFSET_TABLE));
            if (!Offset)
            {
                pfnTable.free(Func);
                return false;
            }
            RuntimeOffsetInit(Offset);
            //要用到判断必须要清0
            GENERIC_RUNTIME_DATA* Data = (GENERIC_RUNTIME_DATA*)pfnTable.malloc(sizeof(GENERIC_RUNTIME_DATA));
            if (!Data)
            {
                pfnTable.free(Offset);
                pfnTable.free(Func);
                return false;
            }
            GENERIC_RUNTIME_PARAMS* Param = (GENERIC_RUNTIME_PARAMS*)pfnTable.malloc(sizeof(GENERIC_RUNTIME_PARAMS));
            if (!Param)
            {
                pfnTable.free(Data);
                pfnTable.free(Offset);
                pfnTable.free(Func);
                return false;
            }
            GENERIC_RUNTIME_CONTEXT* UserVar = (GENERIC_RUNTIME_CONTEXT*)pfnTable.malloc(sizeof(GENERIC_RUNTIME_CONTEXT));
            if (!UserVar)
            {
                pfnTable.free(Param);
                pfnTable.free(Data);
                pfnTable.free(Offset);
                pfnTable.free(Func);
                return false;
            }
            pfnTable.memset(UserVar, 0, sizeof(GENERIC_RUNTIME_CONTEXT));
            pfnTable.memset(Param , 0, sizeof(GENERIC_RUNTIME_PARAMS));
            pfnTable.memset(Data, 0, sizeof(GENERIC_RUNTIME_DATA));
            UserVar->u                      = Data;
            UserVar->p                      = Param;
            UserVar->Func                   = Func;
            UserVar->Offset                 = Offset;  
            UserVar->p->HostImageBase      = tempHostImageBase;
            UserVar->p->SpoofCallRaxAddRsp28Ret = spoofGadgets.CallRaxAddRsp28Ret;
            UserVar->p->SpoofJmpQwordPtrRbx = spoofGadgets.JmpQwordPtrRbx;
            UserVar->p->JmpFrameSize = spoofGadgets.JmpFrameSize;
            UserVar->u->TransformCache      = (Vector<RuntimeTransform>*)UserVar->Func->malloc(sizeof(Vector<RuntimeTransform>));
            if (!UserVar->u->TransformCache)
            {
                RuntimeReleaseContext(UserVar);
                return false;
            }
            new (UserVar->u->TransformCache) Vector<RuntimeTransform>(UserVar->Func->malloc, UserVar->Func->free, UserVar->Func->realloc, UserVar->Func->memmove);
            ULONGLONG seed = __rdtsc();
            seed ^= ((ULONGLONG)CurrentPid << 16);
            seed ^= pfnTable.GetTickCount64();
            seed ^= (seed << 13);
            seed ^= (seed >> 17);
            seed ^= (seed << 5);
            UserVar->u->XorKey = seed;
            if (!UserVar->Func->MessageBoxW)
            {
                RuntimeReleaseContext(UserVar);
                return false;
            }
            const ULONG messageTextChars = (ULONG)(ARRAY_SIZE(messageText) - 1);
            const ULONG messageCaptionChars = (ULONG)(ARRAY_SIZE(messageCaption) - 1);
            PWCHAR messageTextCopy = (PWCHAR)UserVar->Func->malloc(sizeof(messageText));
            PWCHAR messageCaptionCopy = (PWCHAR)UserVar->Func->malloc(sizeof(messageCaption));
            if (!messageTextCopy || !messageCaptionCopy)
            {
                if (messageTextCopy)
                    UserVar->Func->free(messageTextCopy);
                if (messageCaptionCopy)
                    UserVar->Func->free(messageCaptionCopy);
                RuntimeReleaseContext(UserVar);
                return false;
            }
            UserVar->Func->memcpy(messageTextCopy, messageText, sizeof(messageText));
            UserVar->Func->memcpy(messageCaptionCopy, messageCaption, sizeof(messageCaption));
            UserVar->u->MessageText = messageTextCopy;
            UserVar->u->MessageCaption = messageCaptionCopy;
            UserVar->u->MessageTextChars = messageTextChars;
            UserVar->u->MessageCaptionChars = messageCaptionChars;
            UserVar->u->MessageBoxType = 0;
            UserVar->u->MessageShown = 0;

            UserVar->Func->RtlInitializeCriticalSection(&UserVar->p->ComponentToWorldCS);
            //UserVar->u->Version = XorU64(BUILD_VERSION_CODE);
            UserVar->u->Version = 44;
            //DbgPrintA(UserVar, "UserVar:[%p] ShellCodeBase:[0x%llX] Size:[0x%llX] SpoofStackBase:[0x%llX] Size:[0x%llX]", UserVar, UserVar->p->ShellCodeBase, UserVar->p->ShellCodeSize, UserVar->p->SpoofStackBase, UserVar->p->SpoofStackSize);
            *pUserVar = UserVar;
            return true;
        }
    }
    return false;
}


EXTERN_C bool __fastcall RuntimeInitDispatch(IN PVOID rcx)
{
    if (!rcx)
        return false;

    vt_debug_shellcode::RuntimeSlot* slot = static_cast<vt_debug_shellcode::RuntimeSlot*>(rcx);
    if (slot->state == 2 && slot->value)
        return true;
    if (_InterlockedCompareExchange(&slot->state, 1, 0) == 0)
    {
        const bool ok = RuntimeInitWithInput(&slot->value, NULL);
        _InterlockedExchange(&slot->state, ok ? 2 : 3);
        return ok;
    }
    return slot->state == 2 && slot->value != nullptr;
}

EXTERN_C bool __fastcall RuntimeMessageBoxDispatch(IN PVOID rcx)
{
    if (!rcx)
        return false;

    vt_debug_shellcode::RuntimeSlot* slot = static_cast<vt_debug_shellcode::RuntimeSlot*>(rcx);
    PGENERIC_RUNTIME_CONTEXT userVar = slot->value;
    if (!userVar || !userVar->u || !userVar->p || !userVar->Func)
        return false;
    if (!userVar->u->MessageText)
        return true;
    if (!userVar->Func->MessageBoxW)
        return false;

    // 0=未调用，1=调用进行中，2=已完成；先占位再进入可阻塞的 MessageBoxW，阻断并发重入。
    if (_InterlockedCompareExchange((volatile LONG*)&userVar->u->MessageShown, 1, 0) != 0)
        return true;

    const ULONG spoofMode = slot->SpoofMode ? slot->SpoofMode : VT_SHELLCODE_SPOOF_MODE;
    if (spoofMode != VT_SHELLCODE_SPOOF_MODE)
    {
        _InterlockedExchange((volatile LONG*)&userVar->u->MessageShown, 0);
        return false;
    }

#if VT_SHELLCODE_SPOOF_MODE == VT_SHELLCODE_SPOOF_MODE_GHOST_CALL
    if (!slot->GhostRetVa)
    {
        // 方案2必须由驱动先在合法模块冷分支安装 GhostRetVa；未配置时失败关闭，禁止回退方案1。
        _InterlockedExchange((volatile LONG*)&userVar->u->MessageShown, 0);
        return false;
    }
#else
    if (!userVar->p->SpoofCallRaxAddRsp28Ret || !userVar->p->SpoofJmpQwordPtrRbx)
    {
        _InterlockedExchange((volatile LONG*)&userVar->u->MessageShown, 0);
        return false;
    }
#endif

    vt_debug_shellcode::SPOOF_CALL_CONTEXT context = {};
#if VT_SHELLCODE_SPOOF_MODE == VT_SHELLCODE_SPOOF_MODE_GHOST_CALL
    context.GhostRetVa = slot->GhostRetVa;
#if VT_SHELLCODE_DEEP_UNWIND
    context.JmpFrameSize = slot->JmpFrameSize;
    if (!slot->OriginalRsp || (slot->OriginalRsp & 0x0F) != 8 ||
        context.JmpFrameSize < 0x28 || (context.JmpFrameSize & 0x0F) != 8)
    {
        _InterlockedExchange((volatile LONG*)&userVar->u->MessageShown, 0);
        return false;
    }
    context.OriginalRsp = slot->OriginalRsp;
#endif
#else
    context.CallRaxGadget = userVar->p->SpoofCallRaxAddRsp28Ret;
    context.JmpRbxGadget = userVar->p->SpoofJmpQwordPtrRbx;
    context.JmpFrameSize = userVar->p->JmpFrameSize;
#if VT_SHELLCODE_DEEP_UNWIND
    const ULONG nativeFrameAlignment = static_cast<ULONG>(context.JmpFrameSize & 0x0F);
    if (!slot->OriginalRsp || (slot->OriginalRsp & 0x0F) != 8 ||
        (nativeFrameAlignment != 0 && nativeFrameAlignment != 8))
    {
        _InterlockedExchange((volatile LONG*)&userVar->u->MessageShown, 0);
        return false;
    }
    context.OriginalRsp = slot->OriginalRsp;
#endif
#endif
    context.TargetFunc = reinterpret_cast<ULONG64>(userVar->Func->MessageBoxW);
#if VT_SHELLCODE_SPOOF_MODE == VT_SHELLCODE_SPOOF_MODE_GHOST_CALL
#if VT_SHELLCODE_DEEP_UNWIND
    const int messageResult = SpoofCallGhostDeepInvoke(&context,
#else
    const int messageResult = SpoofCallGhostInvoke(&context,
#endif
#else
    const int messageResult = SpoofCallNativeInvoke(&context,
#endif
        NULL,
        userVar->u->MessageText,
        userVar->u->MessageCaption,
        userVar->u->MessageBoxType);
    _InterlockedExchange((volatile LONG*)&userVar->u->MessageShown, messageResult != 0 ? 2 : 0);
    return messageResult != 0;
}

EXTERN_C __declspec(dllexport) bool __fastcall RuntimeDispatch(IN PVOID rcx)
{
    if (!RuntimeInitDispatch(rcx))
        return false;
    return RuntimeMessageBoxDispatch(rcx);
}

#pragma code_seg(pop)

extern "C" __declspec(allocate(".xinit$z"))
const std::uint8_t RuntimeInitImageEnd[] = { 0xC3 };

extern "C" __declspec(dllexport) std::size_t X1ImageSize() noexcept { return vt_debug_shellcode::X1ImageSize(); }
extern "C" __declspec(dllexport) std::size_t RuntimeInitImageSize() noexcept { return vt_debug_shellcode::RuntimeInitImageSize(); }
extern "C" __declspec(dllexport) bool PatchRuntimeSlot(void *image, std::size_t image_size, std::uint64_t slot) noexcept {
    return vt_debug_shellcode::PatchRuntimeSlot(image, image_size, slot);
}
extern "C" __declspec(dllexport) std::size_t RuntimeDispatchOffset() noexcept {
    return static_cast<std::size_t>(reinterpret_cast<const std::uint8_t *>(RuntimeDispatch) - RuntimeInitImageStart);
}
extern "C" __declspec(dllexport) bool PatchRuntimeDispatch(void *image, std::size_t image_size, std::uint64_t dispatch_entry) noexcept {
    return vt_debug_shellcode::PatchRuntimeDispatch(image, image_size, dispatch_entry);
}








