#include "vtcall-hook.h"
#include "hv.h"
#include "mm.h"
#include "ept.h"
#include "vcpu.h"
#include "vmx.h"
#include "hypercalls.h"
#include "ept-hook.h"
#include "page-tables.h"
#include "hde64.h"

namespace hv {

#pragma code_seg(".vm")

static vt_hook_slot g_static_vt_hook_table[VMCALL_HOOK_MAX] = {};
vt_hook_slot* g_vt_hook_table = g_static_vt_hook_table;

namespace vh {

void init_vtcall_hook_subsystem() {
    // g_vt_hook_table 在程序加载时由零初始化；无需额外构造。
}

// --- 内部辅助函数（Host 端） ---

static uint64_t read_process_cr3_local(PEPROCESS process) {
    if (!process || reinterpret_cast<uint8_t*>(process) == g_ghv->system_eprocess)
        return g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);

    uint64_t cr3_val = 0;
    auto addr = reinterpret_cast<uint8_t*>(process) + g_ghv->kprocess_directory_table_base_offset;
    if (read_guest_virtual_memory(g_ghv->system_cr3, addr, &cr3_val, sizeof(cr3_val))
        != sizeof(cr3_val))
        return 0;
    return cr3_val & ~static_cast<uint64_t>(0xFFF);
}

// 针对内核空间虚拟地址（>= 0xFFFF8...），各进程的 CR3 可能因为 KVA Shadow /
// 局部内核映射而与 system_cr3 产生分歧——使用错误的 CR3 会遍历至错误的 PFN。
// eh_prepare_entry 统一在 system_cr3 下索引内核虚拟地址条目；所有按 (cr3, va)
// 查找条目的启用/禁用/卸载移除路径都必须执行相同的归一化，否则会导致查找未命中。
static uint64_t effective_cr3_for_target(PEPROCESS process, uint64_t target_va) {
    if (target_va >= 0xFFFF800000000000ULL && g_ghv->system_cr3.flags)
        return g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
    return read_process_cr3_local(process);
}

// 在 target_cr3 的 [start, start+max_scan) 区间内查找首个连续 4 字节的 0xCC 填充序列，
// 并返回紧随该 0xCC 序列之后的字节地址（对齐驱动端原始 find_blank 逻辑）。
static uint64_t find_blank_host(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    cr3 c{};
    c.flags = target_cr3;

    // 按 4 KB 块（页面粒度）分批读取并在页内扫描——远比按字节调用
    // read_guest_virtual_memory 更快，且 ntdll 的填充区通常跨越多个页面，
    // 因此总能迅速定位到连续 4 字节的 0xCC 序列。
    uint64_t scanned = 0;
    while (scanned < max_scan) {
        uint64_t va = start + scanned;
        size_t to_read = min(uint64_t(0x1000), max_scan - scanned);
        // 下次迭代对齐至下一个页面边界，确保跨页读取严格按页对齐。
        size_t page_off = va & 0xFFFu;
        if (page_off + to_read > 0x1000u)
            to_read = 0x1000u - page_off;

        uint8_t page[0x1000];
        size_t got = read_guest_virtual_memory(c, reinterpret_cast<void*>(va),
                                                page, to_read);
        if (got < 4) {
            // 页面未呈现或不可读——直接跳至下一个页面边界
            scanned += (0x1000 - page_off);
            continue;
        }
        for (size_t i = 0; i + 3 < got; i++) {
            if (page[i]   == 0xCC && page[i+1] == 0xCC &&
                page[i+2] == 0xCC && page[i+3] == 0xCC) {
                return va + i + 1;
            }
        }
        scanned += got;
    }
    return 0;
}

// 计算从 target_va 开始的指令块尺寸（>= 3 字节）。
// 使用 target_cr3 从 Guest 内存读取，并将原始字节（至多 20 字节被替换指令，以及后随指令的 3 字节）捕获写入输出指针。
static bool disasm_target_host(uint64_t target_va, uint64_t target_cr3,
                                uint32_t& out_size,
                                uint64_t& out_next_va,
                                uint8_t (&out_old)[20],
                                uint8_t (&out_next_old)[20]) {
    cr3 c{};
    c.flags = target_cr3;

    // 读取 32 字节代码进行反汇编（安全覆盖任何带有前缀和长操作数的指令）。
    uint8_t code_buf[32] = {};
    auto got = read_guest_virtual_memory(c, reinterpret_cast<void*>(target_va), code_buf, sizeof(code_buf));
    if (got < 4)
        return false;

    uint32_t size = 0;
    while (size < 3 && size < sizeof(code_buf)) {
        hde64s hs{};
        hde64_disasm(code_buf + size, &hs);
        if (hs.len == 0)
            return false;
        size += hs.len;
    }
    if (size == 0 || size > 20)
        return false;

    // 跨页安全保护防护。
    // 1) vmcall 存根（0F 01 C1，共 3 字节）写入伪造影子页中与 target_va 相同的页内偏移处。
    //    若 (target_va & 0xFFF) + 3 > 0x1000，存根会溢出写入到 fake_pages[idx+1]，
    //    从而破坏其他条目的伪造页。此处直接拒绝安装——fake_pages 虽然虚拟连续但物理不连续，
    //    存根字节合法情况下严禁跨越物理页边界。
    if ((target_va & 0xFFF) + 3 > 0x1000) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_install_xpage_stub);
        return false;
    }
    // 2) target_resume = target_va + 大小尺寸 落入下一个 4KB 页面。
    //    实际执行中是安全的——Guest CR3 + EPT 依然使用原始 PFN 映射该目标后续页
    //    （仅钩子页面本身被重定向），且调用者的工作集此前已包含该页（控制流由此流向）。
    //    此处仅递增诊断计数，不拒绝安装。
    if (((target_va + size - 1) >> 12) != (target_va >> 12)) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_install_xpage_resume);
    }

    out_size = size;
    out_next_va = target_va + size;

    memset(out_old, 0, 20);
    memset(out_next_old, 0, 20);
    memcpy(out_old, code_buf, size);

    // 读取下一条指令开头的 3 字节。
    uint8_t next_buf[8] = {};
    if (read_guest_virtual_memory(c, reinterpret_cast<void*>(out_next_va), next_buf, 3) >= 3)
        memcpy(out_next_old, next_buf, 3);

    return true;
}

// 在 [start, start+max_scan) 范围内查找整页全为 0xCC 的 4KB 页面。
// 返回按页对齐的虚拟地址，若未找到则返回 0。start 自动向上对齐至下一页。
//
// 供跳板池使用：由于 EPT 钩子是以 4KB 页面粒度而非字节粒度进行重定向，因此需要整页 0xCC。
// ntdll 在 .text 节末尾与下一节之间通常拥有近 2MB 的 0xCC 填充区，因此查找 4KB 空间非常稳定。
static uint64_t find_blank_page_host(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    cr3 c{};
    c.flags = target_cr3;

    uint64_t va = (start + 0xFFFu) & ~0xFFFull;
    uint64_t end = start + max_scan;

    while (va + 0x1000 <= end) {
        uint8_t page[0x1000];
        size_t got = read_guest_virtual_memory(c, reinterpret_cast<void*>(va), page, 0x1000);
        if (got < 0x1000) {
            // 页面未呈现或不可读——直接跳过一个完整页面。
            va += 0x1000;
            continue;
        }
        bool all_cc = true;
        for (size_t i = 0; i < 0x1000; i++) {
            if (page[i] != 0xCC) { all_cc = false; break; }
        }
        if (all_cc)
            return va;
        va += 0x1000;
    }
    return 0;
}

// 公共包装接口。
uint64_t find_blank_page_host_public(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    return find_blank_page_host(start, max_scan, target_cr3);
}

static int find_free_slot() {
    for (int i = 0; i < VMCALL_HOOK_MAX; i++)
        if (!g_vt_hook_table[i].occupied)
            return i;
    return -1;
}

static int find_slot_by_address(uint64_t target_va) {
    for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
        auto& s = g_vt_hook_table[i];
        if (s.occupied && reinterpret_cast<uint64_t>(s.data.address) == target_va)
            return i;
    }
    return -1;
}

// 将 vmcall 存根注入单个共享影子页。
static void apply_enable_transition_hva(void* fake_hva) {
    if (!fake_hva)
        return;
    static const uint8_t vmcall_stub[3] = { 0x0F, 0x01, 0xC1 };
    memcpy(fake_hva, vmcall_stub, 3);
    __invlpg(fake_hva);
}

// IPI 安装协同汇合状态。vmcall_vh_install 通过 KeIpiGenericCall 分发，
// 因此所有 vCPU 同时并发进入 install_host_impl。
// 胜出 seq_lock CAS 的单一 vCPU 执行共享初始化（分配槽位/跳板/伪造页/写入 0F01C1 存根），
// 随后发出 init_done 信号。所有 vCPU（包含胜出者）在各自私有的 EPT 树中安装 EPT 映射并执行 invept_single。
// 任何 vCPU 均不跨核写入其他 vCPU 的 EPT——TLB 刷新完全在本核完成。
struct ipi_install_state {
    volatile long       seq_lock;
    volatile long       init_done;
    volatile long       init_failed;
    eh::ept_hook_entry* entry;
    uint64_t            target_va;
};
static ipi_install_state s_ipi_state = {};

// 幂等性辅助：相同的 (target, type) 已存在于 g_vt_hook_table 中。
// 每个 vCPU 仍需在各自的 EPT 页表树中完成安装。
static void install_self_ept_for_slot(vcpu* cpu, vt_hook_slot& s) {
    auto target_va = reinterpret_cast<uint64_t>(s.data.address);
    auto va_page   = target_va & ~static_cast<uint64_t>(0xFFF);
    auto target_cr3 = effective_cr3_for_target(s.data.process, target_va);
    if (!target_cr3) return;

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto entry = eh::find_entry_locked(target_cr3, va_page);
    t.lock.release();
    eh::eh_install_self(cpu, entry);
}

// 同上，但适用于 Host 处理函数路径：调用 vCPU 为所有 vCPU 统一写入 EPT
// （当前 vCPU 在 install_ept_hook 内部执行 invept；其他 vCPU 置位挂起 invept 标志位，
// 在其下一次 vmexit 时生效）。
static void install_all_ept_for_slot(vcpu* cpu, vt_hook_slot& s) {
    auto target_va = reinterpret_cast<uint64_t>(s.data.address);
    auto va_page   = target_va & ~static_cast<uint64_t>(0xFFF);
    auto target_cr3 = effective_cr3_for_target(s.data.process, target_va);
    if (!target_cr3) return;

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto entry = eh::find_entry_locked(target_cr3, va_page);
    t.lock.release();
    eh::eh_install_all(cpu, entry);
}

// 安装 EPT 钩子并在钩子偏移处返回单个共享伪造页的 Host 虚拟地址。
// 兼容旧版入口——为尚未迁移到两阶段 prepare/install_self 模型的调用者保留。
// 内部使用 IPI 风格的逐核遍历路径，仅可在代表安装的单一 vCPU 能进行广播的上下文中安全调用。
static uint64_t eh_install_and_get_fake_va(vcpu* cpu, PEPROCESS process, uint64_t va,
                                            bool full_zero, bool is_fake_page) {
    if (!eh::eh_install_internal(cpu, process, va, full_zero, is_fake_page))
        return 0;

    auto process_cr3 = effective_cr3_for_target(process, va);
    if (!process_cr3)
        return 0;

    auto va_page = va & ~static_cast<uint64_t>(0xFFF);
    auto offset  = va & static_cast<uint64_t>(0xFFF);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto e = eh::find_entry_locked(process_cr3, va_page);
    uint64_t fake_va = 0;
    if (e)
        fake_va = reinterpret_cast<uint64_t>(&t.fake_pages[e->fake_page_idx][offset]);
    t.lock.release();
    return fake_va;
}

// 申请空闲跳板槽位。将 oldByte + 0xCC 写入槽位的 exec_page 执行页中，
// 计算三个关键的 Guest 虚拟地址（tramp_va / bp_rip / target_resume）
// 并通过传出参数返回。若跳板池未就绪或没有容量充足的空闲槽位（需满足 oldByte_size + 1 <= slot.capacity）则返回 false。
static bool alloc_trampoline(uint64_t target_va, const uint8_t* old_bytes,
                              uint32_t size, bool is_kernel,
                              uint64_t& out_tramp_va,
                              uint64_t& out_bp_rip,
                              uint64_t& out_target_resume) {
    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();

    bool ready = is_kernel ? pool.kernel_ready : pool.user_ready;
    g_ghv->diag_alloc_is_kernel  = is_kernel ? 1 : 0;
    g_ghv->diag_alloc_pool_ready = ready ? 1 : 0;
    if (!ready) { pool.lock.release(); return false; }

    auto slots       = is_kernel ? pool.kernel_slots      : pool.user_slots;
    auto slot_count  = is_kernel ? pool.kernel_slot_count : pool.user_slot_count;
    auto pages       = is_kernel ? pool.kernel_pages      : pool.user_pages;

    uint32_t needed = size + 1;  // oldByte + 0xCC
    g_ghv->diag_alloc_slot_count = slot_count;
    g_ghv->diag_alloc_needed     = needed;
    if (slot_count > 0) {
        g_ghv->diag_alloc_slot0_occupied    = slots[0].occupied ? 1 : 0;
        g_ghv->diag_alloc_slot0_capacity    = slots[0].capacity;
        g_ghv->diag_alloc_slot0_page_offset = slots[0].page_offset;
        g_ghv->diag_alloc_slot0_page_index  = slots[0].page_index;
    }
    int idx = -1;
    for (uint32_t i = 0; i < slot_count; i++) {
        if (slots[i].occupied) continue;
        if (slots[i].capacity < needed) continue;
        // 健全性检查：vmcall_vh_tramp_add_slot 在注册时已拒绝跨页槽位。
        // 此检查为深度防御——若触发则说明跳板池构建存在异常。
        if ((uint32_t)slots[i].page_offset + (uint32_t)slots[i].capacity > 0x1000) {
            _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_alloc_xpage_skipped);
            continue;
        }
        idx = (int)i;
        break;
    }
    if (idx < 0) { pool.lock.release(); return false; }

    auto& s   = slots[idx];
    auto& pg  = pages[s.page_index];
    // 通过 host_physical_memory_base 写入而非 pg.exec_hva，
    // 从而避免依赖驱动层系统虚拟地址在 Host 页表中的映射。
    uint8_t* exec_base = host_physical_to_virtual(pg.exec_pfn << 12);
    if (!exec_base) { pool.lock.release(); return false; }
    uint8_t* exec_hva = exec_base + s.page_offset;
    memcpy(exec_hva, old_bytes, size);
    exec_hva[size] = 0xCC;

    s.occupied      = true;
    s.tramp_va      = pg.guest_page_va + s.page_offset;
    // INT3 vm-exit 上报的 GUEST_RIP 直接指向 0xCC 字节本身（而非其后随指令）。
    // 因此 bp_rip 必须为 tramp_va + size，即 0xCC 的准确偏移位置。
    s.bp_rip        = s.tramp_va + size;
    s.target_resume = target_va + size;

    out_tramp_va      = s.tramp_va;
    out_bp_rip        = s.bp_rip;
    out_target_resume = s.target_resume;

    pool.lock.release();
    return true;
}

// 将跳板槽位归还至跳板池。在钩子卸载移除时调用。
static void free_trampoline(uint64_t tramp_va) {
    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();
    auto try_release = [&](tramp_slot* slots, uint32_t count) {
        for (uint32_t i = 0; i < count; i++) {
            if (slots[i].occupied && slots[i].tramp_va == tramp_va) {
                slots[i].occupied      = false;
                slots[i].tramp_va      = 0;
                slots[i].bp_rip        = 0;
                slots[i].target_resume = 0;
                return true;
            }
        }
        return false;
    };
    if (!try_release(pool.user_slots, pool.user_slot_count))
        try_release(pool.kernel_slots, pool.kernel_slot_count);
    pool.lock.release();
}

// Host 内部安装路径。可从任何 Host Root 模式代码中调用。
// PEPROCESS=nullptr -> 系统进程 / system_cr3（内核钩子）。
//
// from_ipi:
//   true  -> 调用者为 vmcall_vh_install 处理函数（KeIpiGenericCall
//           同时向每个 vCPU 分发 vmcall）。单个 vCPU 赢得 seq_lock CAS
//           并执行共享初始化；所有 vCPU（包含胜出者）在各自 EPT 树上调用 eh_install_self。
//   false -> 调用者为运行在单个 vCPU 上的 Host vmexit 处理函数
//           （例如 PMO 处理函数惰性安装 GetBuffer/NtSetEvent）。
//           当前 vCPU 执行共享初始化，并通过 eh_install_all 为所有 vCPU 统一写入 EPT；
//           其他 vCPU 在其下一次 vmexit 时刷新各自的 TLB（通过 pending_ept_invept_bitmap）。
bool install_host_impl(vcpu* cpu, PEPROCESS process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable, bool from_ipi) {
    // 仅针对 PMO 的步骤诊断标记。
    auto self_idx_diag = (uint32_t)(cpu - g_ghv->vcpus);
    bool is_pmo = (type == 1);
    auto bump_step = [&](uint32_t mask) {
        if (is_pmo && self_idx_diag < 16)
            _InterlockedOr((volatile LONG*)&g_ghv->diag_pmo_step[self_idx_diag], (LONG)mask);
    };
    bump_step(1 << 0);   // 已进入

    // 单一全局自旋锁：串行化所有安装条目（共享初始化阶段）。
    // 首个穿透的 vCPU 分配条目项/槽位/跳板并写入 0F01C1 存根机器码。
    // 后续并发进入的 vCPU 发现槽位已被占用，将跳过这些初始化步骤。
    // 随后每个 vCPU 无条件在各自私有的 EPT 页表树中完成安装。
    static volatile long s_install_lock = 0;
    while (_InterlockedCompareExchange(&s_install_lock, 1, 0) != 0)
        _mm_pause();

    g_ghv->diag_install_last_target = target_va;
    g_ghv->diag_install_last_fail   = 0;

    // 查找已存在的槽位（先前已由更早进入的 vCPU 安装）。
    int slot_idx = -1;
    for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
        auto& s = g_vt_hook_table[i];
        if (s.occupied && reinterpret_cast<uint64_t>(s.data.address) == target_va
            && s.data.type == type) {
            slot_idx = i;
            break;
        }
    }

    eh::ept_hook_entry* entry = nullptr;
    bool entry_freshly_allocated = false;

    auto target_cr3 = effective_cr3_for_target(process, target_va);
    if (!target_cr3) {
        g_ghv->diag_install_last_fail = 1;
        s_install_lock = 0;
        return false;
    }
    bump_step(1 << 3);

    if (slot_idx < 0) {
        // 首次安装：分配槽位 + 条目项 + 跳板，写入存根机器码。
        slot_idx = find_free_slot();
        if (slot_idx < 0) {
            g_ghv->diag_install_last_fail = 2;
            s_install_lock = 0;
            return false;
        }
        bump_step(1 << 4);

        uint32_t instr_size = 0;
        uint64_t next_va = 0;
        uint8_t old_bytes[20] = {};
        uint8_t next_old[20] = {};
        if (!disasm_target_host(target_va, target_cr3, instr_size, next_va,
                                 old_bytes, next_old)) {
            g_ghv->diag_install_last_fail = 3;
            s_install_lock = 0;
            return false;
        }
        g_ghv->diag_install_last_instr_size = instr_size;
        bump_step(1 << 5);

        entry = eh::eh_prepare_entry(process, target_va,
                                      /*full_zero=*/false,
                                      /*is_fake_page=*/false,
                                      &entry_freshly_allocated);
        if (!entry) {
            g_ghv->diag_install_last_fail = 4;
            s_install_lock = 0;
            return false;
        }
        bump_step(1 << 6);

        bool is_kernel = (target_va >= 0xFFFF800000000000ULL);
        g_ghv->diag_install_last_is_kernel = is_kernel ? 1 : 0;
        uint64_t tramp_va = 0, bp_rip = 0, target_resume = 0;
        if (!alloc_trampoline(target_va, old_bytes, instr_size, is_kernel,
                              tramp_va, bp_rip, target_resume)) {
            g_ghv->diag_install_last_fail = 5;
            g_ghv->diag_install_pool_user_slots   = g_ghv->tramp_pool.user_slot_count;
            g_ghv->diag_install_pool_kernel_slots = g_ghv->tramp_pool.kernel_slot_count;
            if (entry_freshly_allocated)
                eh::free_entry(entry);
            s_install_lock = 0;
            return false;
        }
        bump_step(1 << 7);

        auto fake_target_hva = eh::eh_get_fake_hva_for_entry(entry, target_va);

        auto& slot = g_vt_hook_table[slot_idx];
        memset(&slot.data, 0, sizeof(slot.data));
        slot.data.address           = reinterpret_cast<PVOID>(target_va);
        slot.data.nextAddress       = reinterpret_cast<PUCHAR>(next_va);
        memcpy(slot.data.oldByte,     old_bytes, sizeof(slot.data.oldByte));
        memcpy(slot.data.nextOldByte, next_old,  sizeof(slot.data.nextOldByte));
        slot.data.size              = instr_size;
        slot.data.process           = process;
        slot.data.blankMemory       = blank_mem;
        slot.data.fakeMemoryAddress = reinterpret_cast<uint64_t>(fake_target_hva);
        slot.data.type              = type;
        slot.data.dispatch_mode     = dispatch_mode;
        slot.data.filter_by_process = filter_by_process;
        slot.data.isEnable          = false;
        slot.fake_mem_hva           = fake_target_hva;
        slot.trampoline_va          = tramp_va;
        slot.bp_rip                 = bp_rip;
        slot.target_resume          = target_resume;
        slot.occupied               = true;

        if (auto_enable) {
            slot.data.isEnable = true;
            apply_enable_transition_hva(slot.fake_mem_hva);
            bump_step(1 << 8);
        }

        if (is_pmo) g_ghv->diag_pmo_target_pa = entry->orig_pfn << 12;
    } else {
        // 槽位已存在——获取该条目以为当前 vCPU 安装 EPT。
        auto& s = g_vt_hook_table[slot_idx];
        auto va_page = (uint64_t)s.data.address & ~0xFFFull;
        auto& t = g_ghv->ept_hook_table;
        t.lock.acquire();
        entry = eh::find_entry_locked(target_cr3, va_page);
        t.lock.release();
        bump_step(1 << 11);   // 幂等：共享初始化已就绪
    }

    // EPT 安装分发：
    //   from_ipi=true  （驱动亲和性遍历循环）：当前 vCPU 仅安装本核私有 EPT。
    //                                           循环遍历所有 CPU，使每个 vCPU 均通过
    //                                           此相同路径完成自我安装。
    //   from_ipi=false （Host vmexit 处理函数）：当前 vCPU 是唯一会进入此函数的核，
    //                                           因此必须在此为所有 vCPU 统一写入 EPT。
    bump_step(1 << 9);
    if (from_ipi)
        eh::eh_install_self(cpu, entry);
    else
        eh::eh_install_all(cpu, entry);
    bump_step(1 << 10);

    if (is_pmo && self_idx_diag < 16 && g_ghv->diag_ieh_last_pte_addr)
        g_ghv->diag_pmo_pte_after[self_idx_diag] =
            *(volatile uint64_t*)g_ghv->diag_ieh_last_pte_addr;

    s_install_lock = 0;
    return true;
}

// find_blank_host 的公共包装接口（仍在 namespace vh 内），以便在当前编译单元外调用。
// 供阶段内核钩子代码路径使用（扫描 ntoskrnl，传入 system_cr3=0）。
uint64_t find_blank_host_public(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    return find_blank_host(start, max_scan, target_cr3);
}

// install_host_impl 的延迟变体：当前 vCPU 立即完成本核 EPT 安装，
// 其他所有 vCPU 均入队等待。其他各 vCPU 在下一次 vmexit 时排空队列并安装各自的 EPT 树。
// 杜绝跨 vCPU 强写 EPT——根除当本核写入其他 vCPU 的 EPT 时，该核恰好在同一页面执行指令所引发的竞态。
bool install_host_impl_deferred(vcpu* cpu, PEPROCESS process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable) {
    // 幂等性保障：若 (目标, type) 已安装，重新为尚未排空队列的其他 vCPU 激活挂起标志，
    // 并确保当前 vCPU 亦已完成本核安装。
    for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
        auto& s = g_vt_hook_table[i];
        if (s.occupied && reinterpret_cast<uint64_t>(s.data.address) == target_va
            && s.data.type == type) {
            auto va_page = target_va & ~static_cast<uint64_t>(0xFFF);
            auto target_cr3 = effective_cr3_for_target(process, target_va);
            if (target_cr3) {
                auto& t = g_ghv->ept_hook_table;
                t.lock.acquire();
                auto entry = eh::find_entry_locked(target_cr3, va_page);
                t.lock.release();
                if (entry) eh::eh_install_all_deferred(cpu, entry);
            }
            return true;
        }
    }

    static volatile long s_install_lock = 0;
    while (_InterlockedCompareExchange(&s_install_lock, 1, 0) != 0)
        _mm_pause();

    auto target_cr3 = effective_cr3_for_target(process, target_va);
    if (!target_cr3) { s_install_lock = 0; return false; }

    int slot_idx = find_free_slot();
    if (slot_idx < 0) { s_install_lock = 0; return false; }

    uint32_t instr_size = 0;
    uint64_t next_va = 0;
    uint8_t old_bytes[20] = {};
    uint8_t next_old[20] = {};
    if (!disasm_target_host(target_va, target_cr3, instr_size, next_va,
                             old_bytes, next_old)) {
        s_install_lock = 0; return false;
    }

    bool entry_freshly_allocated = false;
    auto entry = eh::eh_prepare_entry(process, target_va, /*full_zero=*/false,
                                       /*is_fake_page=*/false,
                                       &entry_freshly_allocated);
    if (!entry) { s_install_lock = 0; return false; }

    bool is_kernel = (target_va >= 0xFFFF800000000000ULL);
    uint64_t tramp_va = 0, bp_rip = 0, target_resume = 0;
    if (!alloc_trampoline(target_va, old_bytes, instr_size, is_kernel,
                          tramp_va, bp_rip, target_resume)) {
        if (entry_freshly_allocated) eh::free_entry(entry);
        s_install_lock = 0; return false;
    }

    auto fake_target_hva = eh::eh_get_fake_hva_for_entry(entry, target_va);

    auto& slot = g_vt_hook_table[slot_idx];
    memset(&slot.data, 0, sizeof(slot.data));
    slot.data.address           = reinterpret_cast<PVOID>(target_va);
    slot.data.nextAddress       = reinterpret_cast<PUCHAR>(next_va);
    memcpy(slot.data.oldByte,     old_bytes, sizeof(slot.data.oldByte));
    memcpy(slot.data.nextOldByte, next_old,  sizeof(slot.data.nextOldByte));
    slot.data.size              = instr_size;
    slot.data.process           = process;
    slot.data.blankMemory       = blank_mem;
    slot.data.fakeMemoryAddress = reinterpret_cast<uint64_t>(fake_target_hva);
    slot.data.type              = type;
    slot.data.dispatch_mode     = dispatch_mode;
    slot.data.filter_by_process = filter_by_process;
    slot.data.isEnable          = false;
    slot.fake_mem_hva           = fake_target_hva;
    slot.trampoline_va          = tramp_va;
    slot.bp_rip                 = bp_rip;
    slot.target_resume          = target_resume;
    slot.occupied               = true;

    if (auto_enable) {
        slot.data.isEnable = true;
        apply_enable_transition_hva(slot.fake_mem_hva);
    }

    // 当前 vCPU 立即安装本核私有 EPT；其他 vCPU 延迟至 vmexit 时排空安装。
    eh::eh_install_all_deferred(cpu, entry);

    s_install_lock = 0;
    return true;
}

// （install_host 移出 namespace vh，以确保供外部模块链接调用；参见文件末尾 namespace hv 的直接定义。）

}  // namespace vh

// install_host 导出供外部调用。这是 Host 处理函数路径（在单个 vCPU 上运行的 Host vmexit 处理函数）
// ——由于缺乏逐核分发的 IPI 协同汇合机制，必须统一为所有 vCPU 写入 EPT。
bool vh_install_host(vcpu* cpu, void* process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable) {
    return vh::install_host_impl(cpu, reinterpret_cast<PEPROCESS>(process),
                                  target_va, blank_mem, type,
                                  dispatch_mode, filter_by_process, auto_enable,
                                  /*from_ipi=*/false);
}

// 延迟安装变体。除 EPT 阶段外与 vh_install_host 完全一致：
// 调用 vCPU 仅安装其自身的私有 EPT 树，并将条目入队等待其他 vCPU 获取，
// 而非同步写入每个 vCPU 的 EPT（后者会与在同一页面执行指令的 Guest 线程发生竞态）。
// 其他每个 vCPU 在其下一次 vmexit 时排空队列并安装自己的 EPT。
//
// 适用于目标页面处于高频热点执行路径时的 Host vmexit 处理函数
// （例如惰性安装 GetBuffer 的 PMO 处理函数）——即其他 vCPU 极大概率此刻正在该页面内执行代码。
bool vh_install_host_deferred(vcpu* cpu, void* process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable) {
    return vh::install_host_impl_deferred(cpu, reinterpret_cast<PEPROCESS>(process),
                                           target_va, blank_mem, type,
                                           dispatch_mode, filter_by_process,
                                           auto_enable);
}

// 公共空闲内存查找扫描器。传入 cr3=0 表示使用系统 CR3（内核扫描）。
uint64_t vh_find_blank_host(uint64_t start, uint64_t max_scan, uint64_t target_cr3) {
    if (!target_cr3)
        target_cr3 = g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
    return vh::find_blank_host_public(start, max_scan, target_cr3);
}


namespace hc {

// （install_host 已移至上方的 namespace vh；vmcall_vh_install 委托调用该实现。）

// 入参：
//   rcx = process
//   rdx = target_va
//   r8  = blank_mem_va
//   r9  = 打包标志位：bit0=auto_enable, bit1=filter_by_process; (type<<8); (dispatch_mode<<16)
void vmcall_vh_install(vcpu* const cpu) {
    auto process       = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto target_va     = cpu->ctx->rdx;
    auto blank_mem     = cpu->ctx->r8;
    auto packed        = cpu->ctx->r9;

    bool auto_enable        = (packed & 0x1) != 0;
    bool filter_by_process  = (packed & 0x2) != 0;
    uint8_t type            = static_cast<uint8_t>((packed >> 8) & 0xFF);
    uint8_t dispatch_mode   = static_cast<uint8_t>((packed >> 16) & 0xFF);

    g_ghv->dwm_install_target_va = target_va;
    g_ghv->dwm_install_status    = 0xFF;  // 已进入处理函数

    // IPI 路径：调用者为通过 KeIpiGenericCall 调用的驱动端，因此该处理函数在每个 vCPU 上各执行一次。
    // 带有 from_ipi=true 的 install_host_impl 执行 CAS 协同汇合并在本核调用 eh_install_self。
    bool ok = vh::install_host_impl(cpu, process, target_va, blank_mem, type,
                                     dispatch_mode, filter_by_process,
                                     auto_enable, /*from_ipi=*/true);

    g_ghv->dwm_install_status = ok ? 1 : 0x14;
    cpu->ctx->rax = ok ? 1 : 0;
    skip_instruction();
}

// 入参：
//   rcx = process
//   rdx = target_va
//   r8  = blank_mem_va
//   r9  = trample_addr_va
//   r10 = 打包参数：bit0=auto_enable, bit1=filter_by_process; (type<<8)
//
// 通过 Host 端 eh_write 为 trample_addr 写入 RetAbs 跳板字节。
// 此极简移植版本中不再支持 hook_fn 指针（命中时跳转目标）与 original_out 指针；
// 调用者应改用 vmcall_vh_install + 处理函数分发模式。
void vmcall_vh_install_ret_abs(vcpu* const cpu) {
    // Host 端重构后当前调用路径不再使用；暴露为返回失败的桩函数。
    // 现有用法已映射至带有 dispatch_mode = VMCALL_DISPATCH_RETABS 的 vmcall_vh_install。
    cpu->ctx->rax = 0;
    skip_instruction();
}

void vmcall_vh_enable(vcpu* const cpu) {
    auto target_va = cpu->ctx->rdx;
    int idx = vh::find_slot_by_address(target_va);
    if (idx < 0) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }
    auto& slot = g_vt_hook_table[idx];
    slot.data.isEnable = true;
    if (slot.fake_mem_hva)
        vh::apply_enable_transition_hva(slot.fake_mem_hva);

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_vh_disable(vcpu* const cpu) {
    auto target_va = cpu->ctx->rdx;
    int idx = vh::find_slot_by_address(target_va);
    if (idx < 0) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }
    g_vt_hook_table[idx].data.isEnable = false;
    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_vh_remove(vcpu* const cpu) {
    auto process   = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto target_va = cpu->ctx->rdx;
    auto cpu_bit = 1ULL << static_cast<uint32_t>(cpu - g_ghv->vcpus);

    int idx = vh::find_slot_by_address(target_va);
    if (idx < 0) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }
    auto& slot = g_vt_hook_table[idx];

    auto target_cr3 = vh::effective_cr3_for_target(slot.data.process, target_va);
    auto blank_mem  = slot.data.blankMemory;

    // 通过与 eh_install 相同的逐 vCPU 路径卸载移除 EPT 钩子。
    auto& t = g_ghv->ept_hook_table;
    auto remove_one = [&](uint64_t va) {
        auto va_page = va & ~static_cast<uint64_t>(0xFFF);
        t.lock.acquire();
        auto e = eh::find_entry_locked(target_cr3, va_page);
        if (!e) { t.lock.release(); return; }
        bool was_active = (e->per_vcpu_active_bitmap & cpu_bit) != 0;
        if (was_active)
            e->per_vcpu_active_bitmap &= ~cpu_bit;
        auto orig_pfn = e->orig_pfn;
        bool free_now = (e->per_vcpu_active_bitmap == 0);
        if (free_now)
            eh::free_entry_locked(e);
        t.lock.release();

        if (was_active)
            remove_ept_hook(cpu->ept, orig_pfn);
    };
    if (target_cr3) {
        remove_one(target_va);
        // blank_mem 不再挂接 EPT 钩子（通过 #BP 陷阱接管），无需卸载移除。
    }

    // 在最后一个 CPU 上彻底清除槽位（此处让每个 CPU 都执行清除；具备无害幂等性）。
    memset(&slot, 0, sizeof(slot));

    (void)process;
    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_vh_uninit(vcpu* const cpu) {
    auto cpu_bit = 1ULL << static_cast<uint32_t>(cpu - g_ghv->vcpus);
    auto& t = g_ghv->ept_hook_table;

    // 最后一个 vCPU 检测：在反初始化位图中清除本核位，观察到位图归零的 vCPU
    // 即为最后一个核，负责 memset 清空槽位数组。若无此机制，
    // vcpu0 在其轮次清空槽位会导致 vcpu1 看到 occupied=0 并跳过自身的 EPT 卸载
    // -> vcpu1 的 EPT 中残留悬挂钩子 -> 驱动卸载后依然从伪造影子页渲染 -> 导致黑屏死锁。
    static volatile uint64_t s_uninit_bitmap = 0;
    if (s_uninit_bitmap == 0) {
        // 首次进入时初始化：为每个活动 vCPU 置位对应标志位。
        // 原子执行——仅有一个 vCPU 能通过 CAS 从 0 切换到全量掩码。
        uint64_t expected = 0;
        uint64_t full = (g_ghv->vcpu_count >= 64) ? ~0ULL : ((1ULL << g_ghv->vcpu_count) - 1);
        _InterlockedCompareExchange64((volatile LONG64*)&s_uninit_bitmap,
            (LONG64)full, (LONG64)expected);
    }

    for (int i = 0; i < VMCALL_HOOK_MAX; i++) {
        auto& slot = g_vt_hook_table[i];
        if (!slot.occupied)
            continue;

        uint64_t addrs[2] = {
            reinterpret_cast<uint64_t>(slot.data.address),
            slot.data.blankMemory
        };
        for (int k = 0; k < 2; k++) {
            if (!addrs[k]) continue;
            auto target_cr3 = vh::effective_cr3_for_target(slot.data.process, addrs[k]);
            if (!target_cr3) continue;
            auto va_page = addrs[k] & ~static_cast<uint64_t>(0xFFF);
            t.lock.acquire();
            auto e = eh::find_entry_locked(target_cr3, va_page);
            if (!e) { t.lock.release(); continue; }
            bool was_active = (e->per_vcpu_active_bitmap & cpu_bit) != 0;
            if (was_active)
                e->per_vcpu_active_bitmap &= ~cpu_bit;
            auto orig_pfn = e->orig_pfn;
            bool free_now = (e->per_vcpu_active_bitmap == 0);
            if (free_now)
                eh::free_entry_locked(e);
            t.lock.release();
            if (was_active)
                remove_ept_hook(cpu->ept, orig_pfn);
        }
    }

    // 清除本核标志位；若我是最后一个 vCPU，则在此释放清空槽位表。
    auto remaining = _InterlockedAnd64((volatile LONG64*)&s_uninit_bitmap,
        ~(LONG64)cpu_bit) & ~cpu_bit;
    if (remaining == 0) {
        for (int i = 0; i < VMCALL_HOOK_MAX; i++)
            memset(&g_vt_hook_table[i], 0, sizeof(g_vt_hook_table[i]));
    }

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_vh_find_blank(vcpu* const cpu) {
    auto process    = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto start_va   = cpu->ctx->rdx;
    auto max_scan   = cpu->ctx->r8;

    auto target_cr3 = vh::read_process_cr3_local(process);
    if (!target_cr3) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    cpu->ctx->rax = vh::find_blank_host(start_va, max_scan, target_cr3);
    skip_instruction();
}

// 入参：
//   rcx = process     （驱动端为 PsGetCurrentProcess；nullptr -> 系统进程）
//   rdx = start_va
//   r8  = max_scan
//
// 返回全为 0xCC 填充的 4KB 页面按页对齐虚拟地址，若未找到则返回 0。
void vmcall_vh_find_blank_page(vcpu* const cpu) {
    auto process  = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto start_va = cpu->ctx->rdx;
    auto max_scan = cpu->ctx->r8;

    auto target_cr3 = vh::read_process_cr3_local(process);
    if (!target_cr3) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }
    cpu->ctx->rax = vh::find_blank_page_host_public(start_va, max_scan, target_cr3);
    skip_instruction();
}

// 入参：
//   rcx = orig_pfn       （包含 0xCC 填充序列的 ntdll/ntoskrnl 原始页 PFN）
//   rdx = exec_pfn       （由 PoolManager 分配的执行页 PFN）
//   r8  = page_va        （页面的 Guest 虚拟地址，页对齐）
//   r9  = exec_hva       （执行页的 Host 虚拟地址；将原始页内容复制至其中）
//   r10 = is_kernel      （1 = 内核跳板池，0 = 用户跳板池）
//
// 成功时返回 page_index >= 0，失败返回 -1。Host 调用端分配时已校验 PFN；
// 此处安装 EPT 钩子并用原始 4KB 页面副本初始化 exec_page，
// 确保非跳板字节被读取时仍呈现为合法模块的原始字节。
void vmcall_vh_tramp_add_page(vcpu* const cpu) {
    auto orig_pfn  = cpu->ctx->rcx;
    auto exec_pfn  = cpu->ctx->rdx;
    auto page_va   = cpu->ctx->r8;
    auto exec_hva  = cpu->ctx->r9;
    bool is_kernel = cpu->ctx->r10 != 0;

    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();

    auto& count = is_kernel ? pool.kernel_page_count : pool.user_page_count;
    auto  pages = is_kernel ? pool.kernel_pages      : pool.user_pages;

    if (count >= TRAMPOLINE_MAX_PAGES_PER_POOL ||
        !orig_pfn || !exec_pfn || !page_va || !exec_hva) {
        pool.lock.release();
        cpu->ctx->rax = static_cast<uint64_t>(-1);
        skip_instruction();
        return;
    }

    // 将原始页面内容复制至 exec_page，确保 Guest 执行非跳板区域字节时依然呈现为合法模块的指令。
    void* orig_hva = host_physical_to_virtual(orig_pfn << 12);
    void* exec_dst = host_physical_to_virtual(exec_pfn << 12);
    if (!orig_hva || !exec_dst) {
        pool.lock.release();
        cpu->ctx->rax = static_cast<uint64_t>(-1);
        skip_instruction();
        return;
    }

    uint32_t idx = count++;
    pages[idx].guest_page_va = page_va;
    pages[idx].orig_pfn      = orig_pfn;
    pages[idx].exec_pfn      = exec_pfn;
    pages[idx].exec_hva      = exec_hva;
    pool.lock.release();

    memcpy(exec_dst, orig_hva, 0x1000);

    // 在每个 vCPU 上构建 EPT 双视图：install_ept_hook(is_fake_page=false)
    // 清除原始 PTE 上的 execute_access 执行权限（PFN 保持不变）。当 Guest 进行指令取指时，
    // 触发 EPT 违例异常，handle_ept_violation 将 PFN 切换至 exec_pfn（X=1, R=W=0）。
    // 当 Guest 尝试读写时，违例处理将其切换回 orig_pfn（R=W=1, X=0）。
    // PatchGuard / 反作弊系统读取 ntoskrnl/ntdll 字节时，永远只能读取到原始的 0xCC 填充，
    // 绝对无法观测到我们的 oldByte+0xCC 指令修改。
    uint32_t vcpu_count = g_ghv->vcpu_count;
    for (uint32_t v = 0; v < vcpu_count; v++) {
        install_ept_hook(g_ghv->vcpus[v].ept, orig_pfn, exec_pfn,
                         /*is_fake_page=*/false);
    }
    vmx_invept(invept_all_context, {});

    cpu->ctx->rax = idx;
    skip_instruction();
}

// 入参：
//   rcx = page_index   （由 vmcall_vh_tramp_add_page 返回）
//   rdx = page_offset  （页面内 0xCC 填充序列起始的字节偏移）
//   r8  = capacity     （0xCC 填充序列长度；必须 >= 8）
//   r9  = is_kernel
//
// 成功时返回 1。
void vmcall_vh_tramp_add_slot(vcpu* const cpu) {
    auto page_index = static_cast<uint32_t>(cpu->ctx->rcx);
    auto page_off   = static_cast<uint32_t>(cpu->ctx->rdx);
    auto capacity   = static_cast<uint32_t>(cpu->ctx->r8);
    bool is_kernel  = cpu->ctx->r9 != 0;

    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();

    auto& slot_count = is_kernel ? pool.kernel_slot_count : pool.user_slot_count;
    auto  slots      = is_kernel ? pool.kernel_slots      : pool.user_slots;
    auto& page_count = is_kernel ? pool.kernel_page_count : pool.user_page_count;
    auto  max_slots  = is_kernel ? TRAMPOLINE_POOL_KERNEL_SLOTS : TRAMPOLINE_POOL_USER_SLOTS;

    if (slot_count >= max_slots || page_index >= page_count ||
        page_off >= 0x1000 || capacity < 8 || capacity > 255 ||
        page_off + capacity > 0x1000) {
        // 拒绝区间 [page_off, page_off+capacity) 跨越 4KB exec_page 边界的槽位。
        // 驱动端引导代码在遍历 ntdll/ntoskrnl 填充区间时理论上可能传入跨页区间；
        // alloc_trampoline 无法跨越页面边界写入 oldByte+0xCC，因为 exec_pages 物理上并不连续。
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_tramp_slot_xpage_reject);
        pool.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    auto& s = slots[slot_count++];
    s.page_index    = static_cast<uint16_t>(page_index);
    s.page_offset   = static_cast<uint16_t>(page_off);
    s.capacity      = static_cast<uint8_t>(capacity);
    s.occupied      = false;
    s.tramp_va      = 0;
    s.bp_rip        = 0;
    s.target_resume = 0;
    pool.lock.release();

    cpu->ctx->rax = 1;
    skip_instruction();
}

// 入参：
//   rcx = is_kernel（1=内核，0=用户）
//
// 翻转跳板池的 _ready 就绪标志位。EPT 此前已由 add_page 在每个 vCPU 上同步完成安装。
void vmcall_vh_tramp_set_ready(vcpu* const cpu) {
    bool is_kernel = cpu->ctx->rcx != 0;
    auto& pool = g_ghv->tramp_pool;
    pool.lock.acquire();
    if (is_kernel) pool.kernel_ready = true;
    else           pool.user_ready   = true;
    pool.lock.release();

    cpu->ctx->rax = 1;
    skip_instruction();
}

}  // namespace hc

}  // namespace hv
