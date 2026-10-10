---
name: kernel-pte-remap-physical-rw
description: Windows 内核通过 PTE Remap（单页 TLB 刷新 __invlpg）实现超高速任意物理内存无痕读写规范。规避 NonPagedPool 2MB 大页陷阱、KASLR PML4 自引用槽位扫描、System PTE 申请、免改 CR0.WP 规避 HVCI 蓝屏及对接 VMMDLL/LeechCore 的全套稳定性工程规范。
---

# Windows 内核 PTE Remap 物理内存无痕读写工程规范

## 1. 核心架构与定位

### 1.1 传统物理读写的缺陷与 PTE Remap 优势
- **`ZwMapViewOfSection` / `\Device\PhysicalMemory`**：
  - 依赖合法句柄，现代 Windows 10/11 对其拦截和只读限制极严；
  - 依赖 `PASSIVE_LEVEL` 运行，无法在高中断级别或原子上下文调用；
  - 频繁的 View 创建与卸载开销巨大，无法满足高频 DMA 仿真需求。
- **`MmMapIoSpace` / `MmMapIoSpaceEx`**：
  - 属于内核明文导出 API，反作弊（如 ACE/EAC/BE）常对 I/O 映射实施调用栈回溯或检测；
  - 每次调用均伴随系统内部 PTE 动态申请与释放，有调用记录与微秒级延迟。
- **PTE Remap（硬件级单页修改 + `__invlpg`）最强架构**：
  - 预先保留一段纯粹的系统虚拟地址（System PTEs）；
  - 读写物理内存时，直接修改该虚拟地址对应的硬件页表项（PTE），仅需单条 `__invlpg` 指令刷新当前核心单页 TLB；
  - **零 API 痕迹、零分配释放开销、纳秒级极速物理读写**，完美支撑 VMMDLL / MemProcFS / LeechCore 硬件级仿真。

---

## 2. 核心避坑铁律与故障根因

### 2.1 致命陷阱一：2MB 大页陷阱（导致读写无效、读出相同脏数据）
- **现象**：
  - 驱动日志显示所有物理地址（`PA=0x0000`, `0x1000`, `0x2000`...）读取成功，但读出的前 16 字节内容全部一模一样；
  - 客户端 `VMMDLL_Initialize` 初始化失败，返回 `VMM handle is NULL!`（因扫描不到真实有效 PML4/DTB）。
- **根因**：
  - 若使用 `ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, ...)` 分配映射槽位，现代 Windows 10/11 的非分页池底层默认采用 **2MB 大页（Large Page）**；
  - 大页在第二级 **PDE（Page Directory Entry）** 上设置了 `PS=1`，**四级页表中压根不存在第四级 PT 和 4KB PTE**；
  - 驱动按公式算出的 PTE 地址实际上无硬件对应。CPU MMU 进行地址转换时查到 PDE 就已经结束，根本不读取第四级 PTE；
  - 访问该虚拟地址时，硬件永远访问最初非分页池物理页，导致物理重映射彻底失效！
- **铁律**：
  - **严禁使用 `ExAllocatePoolWithTag` 或物理内存做映射槽位！**
  - **必须调用 `MmAllocateMappingAddress(SLOT_COUNT * PAGE_SIZE, Tag)` 保留纯虚拟 System PTEs 空间**。该 API 保证分配出来的虚拟地址 100% 具备独立的 4KB System PTE，无真实物理页绑定，专门供驱动重映射。

---

### 2.2 致命陷阱二：乱改 CR0.WP 导致 HVCI / VBS 蓝屏崩溃
- **现象**：在开启内存完整性（Core Isolation / HVCI）的系统上，修改 PTE 时若写入 CR0 触发 BugCheck `0x139` 或系统重启。
- **根因**：
  - 在虚拟化安全保护下，Hypervisor 监控特权寄存器篡改；
  - **System PTE 空间在操作系统内部本身就是 `R/W = 1`（可写）的**！内核内存管理器本身就需要频繁改写页表；
  - 解引用 `pPteVa` 写入新物理页基址并不会触发写保护，**完全不需要也严禁关闭 `CR0.WP`**！

---

### 2.3 致命陷阱三：PTE 标志位不当与未清除保留位
- **现象**：修改 PTE 后偶发性访问缺页异常或触发内核校验。
- **规范**：
  - **读内存标志**：`0x103 & ~(1ULL << 9)`
    - `0x103` = Valid (bit 0) | Write (bit 1) | Global (bit 8)；
    - **必须清除 bit 9**：bit 9 是操作系统软件保留位，部分反作弊或内核组件用其打标记，清除它可以彻底规避系统内部缺页异常。
  - **写内存标志**：`0x1EB & ~(1ULL << 9)`（ForceWrite 包含 Dirty、Accessed、PWT、PAT 属性）。
  - **物理地址掩码**：严格使用 `(PhysAddr & 0xFFFFFFFFFF000ULL)`，截断非物理页高位。

---

### 2.4 致命陷阱四：在关中断上下文使用 C 库调用
- **规范**：
  - 在 `_disable()` 关中断和 `DISPATCH_LEVEL` 期间，严禁调用复杂的库函数 `memmove`（防止破坏 XMM 浮点上下文或引发嵌套调用）；
  - **必须使用纯硬件内联指令 `__movsb`（REP MOVSB）**，CPU 硬件流水线直达，极速且安全。

---

## 3. 标准实现模板（C / C++ 内核驱动）

### 3.1 槽位结构体与引擎定义
```c
#include <intrin.h>

#define LC_PTE_SLOT_COUNT 16

typedef PVOID (*PFN_MmAllocateMappingAddress)(SIZE_T NumberOfBytes, ULONG PoolTag);
typedef VOID (*PFN_MmFreeMappingAddress)(PVOID BaseAddress, ULONG PoolTag);

typedef struct _LC_PTE_SLOT
{
    PVOID pMappedPage;      // System PTEs 保留的虚拟页面地址
    ULONG64 *pPteVa;        // 对应的硬件 PTE 虚拟地址
    ULONG64 OriginalPte;    // 初始 PTE 状态 (用于读写后还原)
    volatile LONG inUse;    // 原子并发锁
} LC_PTE_SLOT, *PLC_PTE_SLOT;

typedef struct _LC_PTE_ENGINE
{
    ULONG64 PteBase;
    BOOLEAN fInitialized;
    LC_PTE_SLOT Slots[LC_PTE_SLOT_COUNT];
} LC_PTE_ENGINE, *PLC_PTE_ENGINE;

static LC_PTE_ENGINE g_PteEngine = {0};
static PFN_MmAllocateMappingAddress g_pfnMmAllocateMappingAddress = NULL;
static PFN_MmFreeMappingAddress g_pfnMmFreeMappingAddress = NULL;
static PVOID g_pReservedSystemVa = NULL;
```

### 3.2 动态获取 PteBase（KASLR 自适应）
```c
static ULONG64 _ScanPteBase(VOID)
{
    // 方法 1 (首选)：ACE 函数 96 硬件级 PML4 自引用槽位扫描
    __try
    {
        ULONG64 cr3 = __readcr3();
        PHYSICAL_ADDRESS pml4Phys;
        pml4Phys.QuadPart = (LONGLONG)(cr3 & 0xFFFFFFFFFFFFF000ULL);

        PULONG64 pml4Virt = (PULONG64)MmGetVirtualForPhysical(pml4Phys);
        if (pml4Virt)
        {
            ULONG64 selfPfn = (ULONG64)pml4Phys.QuadPart & 0xFFFFFFFFF000ULL;
            for (ULONG slot = 256; slot < 512; slot++)
            {
                if ((pml4Virt[slot] & 0xFFFFFFFFF000ULL) == selfPfn)
                {
                    ULONG64 candidate = ((ULONG64)slot + 0x1FFFE00ULL) << 39;
                    if ((candidate >> 48) == 0xFFFF)
                        return candidate;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    // 方法 2 (备用)：从内核导出函数特征扫描或直接校验 +0x22 偏移
    UNICODE_STRING usMmGVP;
    RtlInitUnicodeString(&usMmGVP, L"MmGetVirtualForPhysical");
    PUCHAR pMmGVP = (PUCHAR)MmGetSystemRoutineAddress(&usMmGVP);
    if (pMmGVP)
    {
        __try
        {
            ULONG64 candidate22 = *(PULONG64)(pMmGVP + 0x22);
            if ((candidate22 >> 48) == 0xFFFF)
                return candidate22;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    return 0xFFFFF68000000000ULL; // 历史兜底
}
```

### 3.3 初始化与清理（System PTE 规范）
```c
static NTSTATUS LcPteEngine_Init(VOID)
{
    if (g_PteEngine.fInitialized)
        return STATUS_SUCCESS;

    g_PteEngine.PteBase = _ScanPteBase();
    if (!g_PteEngine.PteBase)
        return STATUS_NOT_FOUND;

    if (!g_pfnMmAllocateMappingAddress || !g_pfnMmFreeMappingAddress)
    {
        UNICODE_STRING uAlloc, uFree;
        RtlInitUnicodeString(&uAlloc, L"MmAllocateMappingAddress");
        RtlInitUnicodeString(&uFree, L"MmFreeMappingAddress");
        g_pfnMmAllocateMappingAddress = (PFN_MmAllocateMappingAddress)MmGetSystemRoutineAddress(&uAlloc);
        g_pfnMmFreeMappingAddress = (PFN_MmFreeMappingAddress)MmGetSystemRoutineAddress(&uFree);
        if (!g_pfnMmAllocateMappingAddress || !g_pfnMmFreeMappingAddress)
            return STATUS_NOT_FOUND;
    }

    // 申请 System PTE 保留空间（彻底杜绝大页）
    SIZE_T totalBytes = LC_PTE_SLOT_COUNT * PAGE_SIZE;
    g_pReservedSystemVa = g_pfnMmAllocateMappingAddress(totalBytes, 'PteR');
    if (!g_pReservedSystemVa)
        return STATUS_INSUFFICIENT_RESOURCES;

    for (INT i = 0; i < LC_PTE_SLOT_COUNT; i++)
    {
        PLC_PTE_SLOT slot = &g_PteEngine.Slots[i];
        slot->pMappedPage = (PUCHAR)g_pReservedSystemVa + (i * PAGE_SIZE);
        slot->pPteVa = (ULONG64 *)(g_PteEngine.PteBase + (((ULONG64)slot->pMappedPage >> 9) & 0x7FFFFFFFF8ULL));
        slot->OriginalPte = *slot->pPteVa;
        slot->inUse = 0;
    }

    g_PteEngine.fInitialized = TRUE;
    return STATUS_SUCCESS;
}

static VOID LcPteEngine_Cleanup(VOID)
{
    if (!g_PteEngine.fInitialized)
        return;

    for (INT i = 0; i < LC_PTE_SLOT_COUNT; i++)
    {
        PLC_PTE_SLOT slot = &g_PteEngine.Slots[i];
        if (slot->pMappedPage && slot->pPteVa)
        {
            *slot->pPteVa = slot->OriginalPte;
            __invlpg(slot->pMappedPage);
        }
        slot->pMappedPage = NULL;
        slot->pPteVa = NULL;
        slot->inUse = 0;
    }

    if (g_pReservedSystemVa && g_pfnMmFreeMappingAddress)
    {
        g_pfnMmFreeMappingAddress(g_pReservedSystemVa, 'PteR');
        g_pReservedSystemVa = NULL;
    }

    g_PteEngine.fInitialized = FALSE;
}
```

### 3.4 原子重映射物理读写核心
```c
static BOOLEAN LcPte_CopyPhysical(
    _In_ ULONG64 PhysAddr,
    _Inout_ PVOID Buffer,
    _In_ ULONG Size,
    _In_ BOOLEAN fWrite)
{
    if (!g_PteEngine.fInitialized || !Buffer || Size == 0)
        return FALSE;

    // 获取空闲槽位
    INT slotIndex = -1;
    for (ULONG retry = 0; retry < 1000; retry++)
    {
        for (INT i = 0; i < LC_PTE_SLOT_COUNT; i++)
        {
            if (_InterlockedCompareExchange(&g_PteEngine.Slots[i].inUse, 1, 0) == 0)
            {
                slotIndex = i;
                break;
            }
        }
        if (slotIndex != -1) break;
        KeStallExecutionProcessor(1);
    }
    if (slotIndex == -1) return FALSE;

    PLC_PTE_SLOT slot = &g_PteEngine.Slots[slotIndex];

    // 原子操作：关中断 + 提升至 DISPATCH_LEVEL 避免线程调度竞争
    _disable();
    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

    ULONG64 flags = fWrite ? 0x1EBULL : 0x103ULL;
    ULONG64 newPte = (PhysAddr & 0xFFFFFFFFFF000ULL) | (flags & ~(1ULL << 9));
    
    // 改写 PTE 并刷新单页 TLB
    *slot->pPteVa = newPte;
    __invlpg(slot->pMappedPage);

    PUCHAR pTarget = (PUCHAR)slot->pMappedPage + (PhysAddr & 0xFFFULL);
    __try
    {
        // 采用 CPU 硬件级 REP MOVSB，杜绝库函数调用开销
        if (!fWrite)
            __movsb((PUCHAR)Buffer, pTarget, Size);
        else
            __movsb(pTarget, (PUCHAR)Buffer, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    // 立即还原原始 PTE 并刷新 TLB
    *slot->pPteVa = slot->OriginalPte;
    __invlpg(slot->pMappedPage);

    KeLowerIrql(oldIrql);
    _enable();

    _InterlockedExchange(&slot->inUse, 0);
    return TRUE;
}
```

---

## 4. 落地核对清单（Checklist）

- [ ] **是否排除了 `ExAllocatePoolWithTag`？**
  - 严禁使用内核池内存充当 PTE 重映射槽位。必须使用 `MmAllocateMappingAddress` 申请 System PTEs 空间。
- [ ] **是否已规避修改 `CR0.WP`？**
  - 不得调用 `__writecr0` 清除 WP 位。System PTE 属于系统页表结构，Ring 0 天生具备写入权限。
- [ ] **是否使用了 `__movsb` 代替 `memmove`？**
  - 在 CLI / DISPATCH_LEVEL 高危上下文中，使用 `__movsb` 保障上下文干净，不触发 XMM/浮点异常。
- [ ] **物理地址跨页切割是否严密？**
  - 外层封装循环必须保证每次调用单次读取长度满足 `min(PAGE_SIZE - pageOffset, remainSize)`，严禁跨越 4KB 边界。
- [ ] **VMMDLL / LeechCore 硬件级仿真兼容**：
  - 物理地址 `0x0000` 必须返回真实 IVT/BDA，`0x1000`+ 返回真实代码页，保障 VMM 能够成功解析 PML4/DTB。
