#pragma once
#include "loader_common.h"
#include "phys_walk.h"
#include <vector>
#include <string>

// ============================================================
// manual_map.h — 内核手动 PE 映射器
//
// 功能：
//   1. 从磁盘读取 drv_wsk.sys PE 文件
//   2. 在用户态完成节区展开（Section Mapping）
//   3. 修复重定位（Relocation）
//   4. 修复 IAT（通过 FindKernelExport 解析 ntoskrnl 导出）
//   5. 生成可注入内核的最终镜像缓冲区
//
// 注意：IAT 解析在用户态完成，填入的是内核 VA（运行时函数地址）
// ============================================================

struct MappedImage {
    std::vector<uint8_t> Image;   // 展开后的完整镜像（大小 = SizeOfImage）
    uint64_t KernelBase;          // 目标内核虚拟基址（分配后填入）
    uint64_t EntryPointOffset;    // DriverEntry 相对于镜像基址的偏移
    uint32_t SizeOfImage;
    uint32_t RelocDirRVA;         // BaseRelocation 目录 RVA
    uint32_t RelocDirSize;        // BaseRelocation 目录大小
    uint64_t OriginalImageBase;   // PE OptionalHeader 中的原始 ImageBase
    uint32_t ExceptionDirRVA;     // ExceptionTable 目录 RVA (.pdata)
    uint32_t ExceptionDirSize;    // ExceptionTable 目录大小 (.pdata)
};

// ---- 从磁盘读取文件 ----
static std::vector<uint8_t> ReadFile(const wchar_t* path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_ERR("ReadFile: cannot open %ls (GLE=%u)", path, GetLastError());
        return {};
    }
    DWORD size = GetFileSize(h, NULL);
    std::vector<uint8_t> buf(size);
    DWORD read = 0;
    ReadFile(h, buf.data(), size, &read, NULL);
    CloseHandle(h);
    LOG_OK("ReadFile: loaded %ls (%u bytes)", path, read);
    return buf;
}

// ---- PE 辅助宏 ----
#define PE_DOS(buf)     ((IMAGE_DOS_HEADER*)(buf))
#define PE_NT(buf)      ((IMAGE_NT_HEADERS64*)((uint8_t*)(buf) + PE_DOS(buf)->e_lfanew))
#define PE_SECHDR(nt)   ((IMAGE_SECTION_HEADER*)((uint8_t*)&(nt)->OptionalHeader + \
                          (nt)->FileHeader.SizeOfOptionalHeader))

// ---- 节区展开：按 SizeOfImage 分配目标缓冲区 ----
static bool SectionMap(const std::vector<uint8_t>& rawBuf, MappedImage& out)
{
    if (rawBuf.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = PE_DOS(rawBuf.data());
    if (dos->e_magic != 0x5A4D) return false;
    auto* nt  = PE_NT(rawBuf.data());
    if (nt->Signature != 0x00004550) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        LOG_ERR("SectionMap: not x64 PE");
        return false;
    }

    out.SizeOfImage        = nt->OptionalHeader.SizeOfImage;
    out.EntryPointOffset   = nt->OptionalHeader.AddressOfEntryPoint;
    out.RelocDirRVA        = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    out.RelocDirSize       = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    out.ExceptionDirRVA    = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    out.ExceptionDirSize   = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    out.OriginalImageBase  = nt->OptionalHeader.ImageBase;
    out.Image.assign(out.SizeOfImage, 0);

    // 复制 PE 头
    uint32_t hdrSize = nt->OptionalHeader.SizeOfHeaders;
    memcpy(out.Image.data(), rawBuf.data(), min(hdrSize, (uint32_t)rawBuf.size()));

    // 复制各节区
    auto* sec = PE_SECHDR(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->VirtualAddress || !sec->SizeOfRawData) continue;
        if (sec->PointerToRawData + sec->SizeOfRawData > rawBuf.size()) {
            LOG_ERR("SectionMap: section '%s' out of file bounds", sec->Name);
            return false;
        }
        memcpy(out.Image.data() + sec->VirtualAddress,
               rawBuf.data() + sec->PointerToRawData,
               sec->SizeOfRawData);
    }

    LOG_OK("SectionMap: %u bytes mapped, EP=+0x%llX",
           out.SizeOfImage, out.EntryPointOffset);
    return true;
}

// ---- 修复重定位（Relocation）----
// delta = kernelBase - ImageBase（优先从 MappedImage 结构体读取，兼容 ErasePEHeader 后的情况）
static inline bool ApplyRelocation(MappedImage& img, uint64_t kernelBase)
{
    uint64_t origBase = img.OriginalImageBase;
    if (origBase == 0) {
        auto* nt = PE_NT(img.Image.data());
        if (nt && nt->Signature == IMAGE_NT_SIGNATURE) {
            origBase = nt->OptionalHeader.ImageBase;
        }
    }
    uint64_t delta = kernelBase - origBase;
    if (delta == 0) {
        LOG_INFO("ApplyRelocation: no delta, skip");
        return true;
    }

    uint32_t relocRVA  = img.RelocDirRVA;
    uint32_t relocSize = img.RelocDirSize;
    if (relocRVA == 0 || relocSize == 0) {
        auto* nt = PE_NT(img.Image.data());
        if (nt && nt->Signature == IMAGE_NT_SIGNATURE) {
            auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            relocRVA  = dd.VirtualAddress;
            relocSize = dd.Size;
        }
    }

    if (!relocRVA || !relocSize) {
        LOG_INFO("ApplyRelocation: no reloc directory");
        return true;
    }

    uint8_t* reloc     = img.Image.data() + relocRVA;
    uint8_t* relocEnd  = reloc + relocSize;

    while (reloc < relocEnd) {
        auto* block = (IMAGE_BASE_RELOCATION*)reloc;
        if (!block->SizeOfBlock) break;

        uint32_t  count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        uint16_t* entry = (uint16_t*)(reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t i = 0; i < count; i++) {
            uint16_t type   = entry[i] >> 12;
            uint16_t offset = entry[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t* pAddr = (uint64_t*)(img.Image.data() + block->VirtualAddress + offset);
                *pAddr += delta;
            }
        }
        reloc += block->SizeOfBlock;
    }

    LOG_OK("ApplyRelocation: delta=0x%llX applied (relocRVA=0x%X, size=0x%X)", delta, relocRVA, relocSize);
    img.KernelBase = kernelBase;
    return true;
}

// ---- 修复 IAT（从已知内核函数 VA 填表）----
// 通过 Psapi 解析任意已加载内核模块基址
static uint64_t FindLoadedDriverBase(const char* moduleName)
{
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        int count = cbNeeded / sizeof(drivers[0]);
        for (int i = 0; i < count; i++) {
            char baseName[MAX_PATH] = {};
            if (GetDeviceDriverBaseNameA(drivers[i], baseName, MAX_PATH)) {
                if (_stricmp(baseName, moduleName) == 0) {
                    return (uint64_t)drivers[i];
                }
                char nameWithoutExt[MAX_PATH] = {};
                strcpy_s(nameWithoutExt, baseName);
                char* dot = strrchr(nameWithoutExt, '.');
                if (dot) *dot = 0;
                if (_stricmp(nameWithoutExt, moduleName) == 0) {
                    return (uint64_t)drivers[i];
                }
            }
        }
    }
    return 0;
}

// ---- 修复 IAT（支持多模块解析，含 ntoskrnl.exe 与 NETIO.SYS 等）----
static bool FixIAT(HANDLE hDev, uint64_t cr3, uint64_t ntoskrnlBase,
                   MappedImage& img)
{
    auto* nt = PE_NT(img.Image.data());
    auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dd.VirtualAddress || !dd.Size) {
        LOG_INFO("FixIAT: no import directory, skipping");
        return true;
    }

    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(img.Image.data() + dd.VirtualAddress);
    for (; desc->Name; desc++) {
        const char* dllName = (const char*)(img.Image.data() + desc->Name);
        LOG_INFO("FixIAT: processing import from '%s'", dllName);

        uint64_t targetModBase = 0;
        if (_stricmp(dllName, "ntoskrnl.exe") == 0 || _stricmp(dllName, "ntoskrnl") == 0) {
            targetModBase = ntoskrnlBase;
        } else {
            targetModBase = FindLoadedDriverBase(dllName);
            if (!targetModBase) {
                LOG_ERR("FixIAT: module '%s' not found in system driver list!", dllName);
                return false;
            }
            LOG_OK("FixIAT: module '%s' resolved to base=0x%016llX", dllName, targetModBase);
        }

        auto* thunk    = (IMAGE_THUNK_DATA64*)(img.Image.data() + desc->OriginalFirstThunk);
        auto* iatEntry = (uint64_t*)(img.Image.data() + desc->FirstThunk);

        for (; thunk->u1.AddressOfData; thunk++, iatEntry++) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                LOG_ERR("FixIAT: ordinal import not supported");
                continue;
            }
            auto* byName = (IMAGE_IMPORT_BY_NAME*)(img.Image.data() + thunk->u1.AddressOfData);
            const char* fnName = byName->Name;

            uint64_t fnVA = FindKernelExport(hDev, cr3, targetModBase, fnName);
            if (!fnVA) {
                // 兜底策略：如果因为内核页表未映射导致读取失败，直接从系统目录加载对应驱动 PE 计算 RVA
                wchar_t sysDrvPath[MAX_PATH] = {};
                swprintf_s(sysDrvPath, L"C:\\Windows\\System32\\drivers\\%hs", dllName);
                HMODULE hLocalMod = LoadLibraryExW(sysDrvPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
                if (hLocalMod) {
                    FARPROC pLocalProc = GetProcAddress(hLocalMod, fnName);
                    if (pLocalProc) {
                        uint64_t rva = (uint64_t)pLocalProc - (uint64_t)hLocalMod;
                        fnVA = targetModBase + rva;
                        LOG_WARN("FixIAT: Fallback resolved '%s' from local PE -> RVA=0x%llX -> VA=0x%016llX",
                                 fnName, rva, fnVA);
                    }
                    FreeLibrary(hLocalMod);
                }
            }

            if (!fnVA) {
                LOG_ERR("FixIAT: '%s' not found in '%s' (targetModBase=0x%016llX)!", fnName, dllName, targetModBase);
                return false;
            }
            *iatEntry = fnVA;
            LOG_HEX("  %-40s → 0x%016llX", fnName, fnVA);
        }
    }
    LOG_OK("FixIAT: completed");
    return true;
}

// ---- 清除 MZ/PE 头（抹除特征，对抗 IPI 物理扫描）----
static void ErasePEHeader(MappedImage& img)
{
    uint32_t hdrSize = PE_NT(img.Image.data())->OptionalHeader.SizeOfHeaders;
    hdrSize = min(hdrSize, (uint32_t)0x1000);
    // 用随机字节覆盖前 4 字节（MZ 标志），其余清零
    img.Image[0] = 0x00;
    img.Image[1] = 0x00;
    memset(img.Image.data() + 2, 0, min((size_t)(hdrSize - 2), img.Image.size() - 2));
    LOG_OK("ErasePEHeader: MZ/PE header zeroed (%u bytes)", hdrSize);
}
