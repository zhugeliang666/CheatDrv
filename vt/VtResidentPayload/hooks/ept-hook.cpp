#include "ept-hook.h"
#include "hv.h"
#include "mm.h"
#include "ept.h"
#include "vcpu.h"
#include "vmx.h"
#include "hypercalls.h"
#include "page-tables.h"

namespace hv {

#pragma code_seg(".vm")

namespace eh {

// --- 内部静态辅助例程 ---

static inline uint32_t vcpu_idx(vcpu* cpu) {
    return static_cast<uint32_t>(cpu - g_ghv->vcpus);
}

static inline uint64_t page_align(uint64_t va) {
    return va & ~static_cast<uint64_t>(0xFFF);
}

static uint64_t read_process_cr3(PEPROCESS process) {
    if (!process)
        return 0;
    uint64_t cr3_val = 0;
    auto addr = reinterpret_cast<uint8_t*>(process) + g_ghv->kprocess_directory_table_base_offset;
    if (read_guest_virtual_memory(g_ghv->system_cr3, addr, &cr3_val, sizeof(cr3_val))
        != sizeof(cr3_val))
        return 0;
    return cr3_val & ~static_cast<uint64_t>(0xFFF);
}

static uint64_t resolve_process_cr3(PEPROCESS process) {
    // 与缓存的 System EPROCESS 指针进行比对（避免直接在 Root 模式下访问
    // PsInitialSystemProcess 内核全局变量）。
    if (!process || reinterpret_cast<uint8_t*>(process) == g_ghv->system_eprocess)
        return g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
    return read_process_cr3(process);
}

// --- 钩子表管理（向 vtcall-hook.cpp 暴露） ---

void init_ept_hook_table() {
    auto& t = g_ghv->ept_hook_table;

    t.lock.initialize();
    t.in_use_count = 0;
    t.active_list_head = nullptr;
    t.free_list_head = nullptr;

    for (size_t i = 0; i < ept_hook_table::capacity; i++) {
        auto& e = t.buffer[i];
        e.next = nullptr;
        e.process = nullptr;
        e.process_cr3 = 0;
        e.va = 0;
        e.orig_pfn = 0;
        e.fake_pfn = 0;
        e.fake_page_idx = static_cast<uint32_t>(i);
        e.in_use = false;
        e.is_fake_page = false;
        e.per_vcpu_active_bitmap = 0;
    }

    for (size_t i = 0; i + 1 < ept_hook_table::capacity; i++)
        t.buffer[i].next = &t.buffer[i + 1];
    t.buffer[ept_hook_table::capacity - 1].next = nullptr;
    t.free_list_head = &t.buffer[0];

    for (uint32_t i = 0; i < ept_hook_table::capacity; i++) {
        void* va = &t.fake_pages[i][0];
        t.fake_page_pfns[i] =
            static_cast<uint64_t>(MmGetPhysicalAddress(va).QuadPart) >> 12;
        memset(va, 0, 0x1000);
    }
}

ept_hook_entry* find_entry_locked(uint64_t process_cr3, uint64_t va_page) {
    auto& t = g_ghv->ept_hook_table;
    for (auto e = t.active_list_head; e; e = e->next) {
        if (e->process_cr3 == process_cr3 && e->va == va_page)
            return e;
    }
    return nullptr;
}

ept_hook_entry* alloc_entry_locked() {
    auto& t = g_ghv->ept_hook_table;
    if (!t.free_list_head)
        return nullptr;

    auto e = t.free_list_head;
    t.free_list_head = e->next;

    e->next = t.active_list_head;
    t.active_list_head = e;

    e->in_use = true;
    t.in_use_count++;
    return e;
}

void free_entry_locked(ept_hook_entry* entry) {
    auto& t = g_ghv->ept_hook_table;

    // 从活动链表中解绑。
    if (t.active_list_head == entry) {
        t.active_list_head = entry->next;
    } else {
        for (auto p = t.active_list_head; p; p = p->next) {
            if (p->next == entry) {
                p->next = entry->next;
                break;
            }
        }
    }

    // 重置条目，保留稳定的 fake_page_idx 索引。
    auto idx = entry->fake_page_idx;
    entry->next = nullptr;
    entry->process = nullptr;
    entry->process_cr3 = 0;
    entry->va = 0;
    entry->orig_pfn = 0;
    entry->fake_pfn = 0;
    entry->fake_page_idx = idx;
    entry->in_use = false;
    entry->is_fake_page = false;
    entry->per_vcpu_active_bitmap = 0;

    // 推入空闲链表。
    entry->next = t.free_list_head;
    t.free_list_head = entry;
    if (t.in_use_count > 0)
        t.in_use_count--;
}

void free_entry(ept_hook_entry* entry) {
    if (!entry) return;
    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    free_entry_locked(entry);
    t.lock.release();
}

// --- 内部安装例程（由 vtcall-hook.cpp 或 vmcall 处理函数调用） ---

// IPI 安装第一阶段。仅由发起 IPI 初始化的 vCPU 执行此阶段：
// 分配条目项，捕获 orig_pfn，将原始页内容复制到 fake_page。此阶段不修改 EPT。
// out_freshly_allocated=true -> 调用者拥有该条目，后续失败时必须调用 free_entry。
// =false -> 复用已有条目，调用者严禁释放。
ept_hook_entry* eh_prepare_entry(PEPROCESS process, uint64_t va,
                                  bool full_zero, uint8_t view_mode,
                                  bool* out_freshly_allocated) {
    if (out_freshly_allocated) *out_freshly_allocated = false;
    auto va_page = page_align(va);

    auto process_cr3 = resolve_process_cr3(process);
    if (!process_cr3)
        return nullptr;

    // 内核虚拟地址快捷路径：当目标为内核空间虚拟地址（>= 0xFFFF8...）时，
    // 强制通过 system_cr3 进行查找与条目索引。各进程的页表在内核空间可能存在 NX 位 /
    // 影子条目 / 不完整的 KVA 映射，若盲目遍历会导致解算出错误的 PFN，从而错误重定向
    // 不相关的物理页。system_cr3 始终包含规范的内核映射。条目中仍会保留调用者传入的
    // process 以供分发器执行过滤，但作为条目表索引键的 process_cr3 必须与下方的
    // 启用/禁用/移除路径保持一致——它们同样必须将内核虚拟地址归一化为 system_cr3（参见 vtcall-hook.cpp 调用方）。
    if (va_page >= 0xFFFF800000000000ULL && g_ghv->system_cr3.flags) {
        process_cr3 = g_ghv->system_cr3.flags & ~static_cast<uint64_t>(0xFFF);
    }

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = find_entry_locked(process_cr3, va_page);
    if (entry) {
        const uint8_t requested_mode = view_mode > ept_view_exec_shadow_read_zero
            ? ept_view_exec_shadow_read_original : view_mode;
        const bool compatible = entry->is_fake_page == requested_mode;
        t.lock.release();
        return compatible ? entry : nullptr;
    }

    entry = alloc_entry_locked();
    if (!entry) { t.lock.release(); return nullptr; }

    cr3 c{};
    c.flags = process_cr3;

    size_t off = 0;
    uint64_t orig_gpa = gva2gpa(c, reinterpret_cast<void*>(va_page), &off);
    if (!orig_gpa) {
        free_entry_locked(entry);
        t.lock.release();
        return nullptr;
    }

    entry->process = process;
    entry->process_cr3 = process_cr3;
    entry->va = va_page;
    entry->orig_pfn = orig_gpa >> 12;
    entry->fake_pfn = t.fake_page_pfns[entry->fake_page_idx];
    if (view_mode > ept_view_exec_shadow_read_zero)
        view_mode = ept_view_exec_shadow_read_original;
    entry->is_fake_page = view_mode;
    entry->per_vcpu_active_bitmap = 0;

    uint8_t* fake = &t.fake_pages[entry->fake_page_idx][0];
    if (full_zero) {
        memset(fake, 0, 0x1000);
    } else {
        void* orig_hva = gva2hva(c, reinterpret_cast<void*>(va_page));
        if (orig_hva) memcpy(fake, orig_hva, 0x1000);
        else          memset(fake, 0, 0x1000);
    }

    t.lock.release();
    if (out_freshly_allocated) *out_freshly_allocated = true;
    return entry;
}

// IPI 安装第二阶段。每个 vCPU 自行执行：修改各自的 EPT 页表树，
// 将 orig_pfn 重定向至 fake_pfn（构建仅执行视图），并刷新各自的 TLB。
void eh_install_self(vcpu* cpu, ept_hook_entry* entry) {
    if (!entry) return;

    auto self_idx = vcpu_idx(cpu);
    uint64_t bit = 1ULL << self_idx;

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    bool already = (entry->per_vcpu_active_bitmap & bit) != 0;
    auto orig_pfn = entry->orig_pfn;
    auto fake_pfn = entry->fake_pfn;
    uint8_t view_mode = entry->is_fake_page;
    t.lock.release();

    if (already) return;

    // install_ept_hook 可能会失败（无可用钩子节点 / get_ept_pte 返回
    // nullptr / 拆分 2MB PDE 失败）。仅在安装成功后才置位该位，
    // 以便失败时后续可以重试，并确保诊断位图准确反映哪些 vCPU 真正安装了钩子。
    if (!install_ept_hook(cpu->ept, orig_pfn, fake_pfn, view_mode))
        return;

    t.lock.acquire();
    entry->per_vcpu_active_bitmap |= bit;
    t.lock.release();
}

// 从单个调用 vCPU 为所有 vCPU 安装（Host 处理函数路径）。
// 当没有 IPI 协同汇合时使用——当前 vCPU 同步修改所有 vCPU 的 EPT 页表树，
// 并置位 pending_ept_invept_bitmap，以便其他 vCPU 在下一次 vmexit 时刷新各自的 TLB。
//
// 这是经过验证的可靠模式：NtSetEvent 通过此路径安装（单个 vCPU 写入全部 16 棵 EPT 树
// + 本地执行 invept_all_context），PMO 驱动端 IPI 成功产生 handler_count > 0, hit_count > 0。
void eh_install_all(vcpu* cpu, ept_hook_entry* entry) {
    if (!entry) return;

    auto self_idx = vcpu_idx(cpu);
    uint32_t vcpu_count = g_ghv->vcpu_count;

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto orig_pfn = entry->orig_pfn;
    auto fake_pfn = entry->fake_pfn;
    uint8_t view_mode = entry->is_fake_page;
    uint64_t bitmap_snapshot = entry->per_vcpu_active_bitmap;
    t.lock.release();

    uint64_t newly_installed_bitmap = 0;
    for (uint32_t v = 0; v < vcpu_count; v++) {
        uint64_t bit = 1ULL << v;
        if (bitmap_snapshot & bit) continue;
        if (install_ept_hook(g_ghv->vcpus[v].ept, orig_pfn, fake_pfn, view_mode))
            newly_installed_bitmap |= bit;
    }

    if (newly_installed_bitmap) {
        t.lock.acquire();
        entry->per_vcpu_active_bitmap |= newly_installed_bitmap;
        t.lock.release();
    }

    uint64_t others = newly_installed_bitmap & ~(1ULL << self_idx);
    if (others)
        _InterlockedOr64((volatile LONG64*)&g_ghv->pending_ept_invept_bitmap,
                         (LONG64)others);
}

// drain_pending_installs：扫描延迟安装队列数组，安装当前 vCPU 尚未加载的所有条目。
// 当条目的 per_vcpu_active_bitmap 在所有活动 vCPU 上均已置位时，
// 通过 CAS 将其原子清零回 nullptr，以便槽位供后续安装复用。
void drain_pending_installs(vcpu* cpu) {
    if (!cpu) return;
    uint32_t vc = g_ghv->vcpu_count;
    uint64_t full_mask = (vc >= 64) ? ~0ULL : ((1ULL << vc) - 1);
    for (uint32_t i = 0; i < g_ghv->pending_install_capacity; i++) {
        auto e = g_ghv->pending_ept_install_entries[i];
        if (!e) continue;
        // eh_install_self 具备幂等性（内部包含 per_vcpu_active_bitmap 校验），
        // 即使传入当前 vCPU 已经安装过的条目也能安全调用。
        eh_install_self(cpu, e);

        // 如果所有活动 vCPU 均已安装此条目，则退役该槽位以便后续安装复用。
        // 采用 CAS 操作避免并发 drain 产生重复清除（同时避免与抢占该槽位的新入队发生竞态——
        // 仅当槽位仍持有 e 时 cmpxchg 才会成功）。
        auto& t = g_ghv->ept_hook_table;
        t.lock.acquire();
        bool retire = (e->per_vcpu_active_bitmap & full_mask) == full_mask;
        t.lock.release();
        if (retire) {
            _InterlockedCompareExchangePointer(
                (PVOID volatile*)&g_ghv->pending_ept_install_entries[i],
                nullptr, e);
        }
    }
}

// Host 处理函数延迟安装：当前 vCPU 立即安装本核 EPT，
// 其他 vCPU 加入队列并置位标志位，在各自下一次 vmexit 时自行排空安装。
void eh_install_all_deferred(vcpu* cpu, ept_hook_entry* entry) {
    if (!entry) return;

    // 1) 当前 vCPU 立即安装本核 EPT（无并发竞态——操作私有树）。
    eh_install_self(cpu, entry);

    // 2) 查找空闲槽位（CAS nullptr -> entry）。所有 vCPU 安装完成后槽位由 drain 退役，
    // 故数组容量有界循环复用，不会单调膨胀。
    bool placed = false;
    for (uint32_t i = 0; i < g_ghv->pending_install_capacity; i++) {
        auto prev = _InterlockedCompareExchangePointer(
            (PVOID volatile*)&g_ghv->pending_ept_install_entries[i],
            entry, nullptr);
        if (prev == nullptr) {
            placed = true;
            break;
        }
        // 相同条目已处于挂起状态（例如幂等路径后重新激活）——视作成功且不重复占用新槽位。
        if (prev == entry) {
            placed = true;
            break;
        }
    }
    if (!placed) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_pending_queue_full);
        return;
    }

    // 3) 为其他所有 vCPU 置位就绪位图。当前 vCPU 已完成。
    uint32_t vc = g_ghv->vcpu_count;
    auto self_idx = vcpu_idx(cpu);
    uint64_t others = ((vc >= 64) ? ~0ULL : ((1ULL << vc) - 1))
                      & ~(1ULL << self_idx);
    _InterlockedOr64((volatile LONG64*)&g_ghv->pending_ept_install_bitmap,
                     (LONG64)others);
}

void* eh_get_fake_hva_for_entry(ept_hook_entry* entry, uint64_t va) {
    if (!entry) return nullptr;
    auto& t = g_ghv->ept_hook_table;
    auto offset = va & static_cast<uint64_t>(0xFFF);
    return &t.fake_pages[entry->fake_page_idx][offset];
}

bool eh_install_internal(vcpu* cpu, PEPROCESS process, uint64_t va,
                         bool full_zero, uint8_t view_mode) {
    bool freshly = false;
    auto entry = eh_prepare_entry(process, va, full_zero, view_mode, &freshly);
    if (!entry) return false;
    eh_install_self(cpu, entry);
    return true;
}

bool eh_write_internal(uint64_t process_cr3, uint64_t dst_va,
                       const void* src_hva, size_t size) {
    auto va_page = page_align(dst_va);
    auto offset = dst_va & static_cast<uint64_t>(0xFFF);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        return false;
    }

    if (offset + size > 0x1000)
        size = 0x1000 - offset;

    auto dst = &t.fake_pages[entry->fake_page_idx][offset];
    memcpy(dst, src_hva, size);

    t.lock.release();
    return true;
}

// 获取 (process_cr3, va_page) 对应共享伪造影子页在指定偏移处的 Host 虚拟地址。
// cpuid 参数已忽略——当前统一使用单共享伪造页（跳板架构替代了原有的每 vCPU 独立修改机制）。
void* eh_get_fake_hva_for_cpu(uint64_t process_cr3, uint64_t va_page, uint32_t /*cpuid*/) {
    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();
    auto entry = find_entry_locked(process_cr3, va_page);
    if (!entry) { t.lock.release(); return nullptr; }
    auto idx = entry->fake_page_idx;
    auto offset = va_page & 0xFFFull;  // va_page 已经页对齐；offset = 0
    t.lock.release();
    return &t.fake_pages[idx][offset];
}

}  // namespace eh


namespace hc {

void vmcall_eh_install(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto flags = cpu->ctx->r8;
    bool full_zero = (flags & 1) != 0;
    uint8_t view_mode = (flags & 4) ? eh::ept_view_exec_shadow_read_zero
                                    : ((flags & 2) ? eh::ept_view_exec_original_read_shadow
                                                    : eh::ept_view_exec_shadow_read_original);

    cpu->ctx->rax = eh::eh_install_internal(cpu, process, va, full_zero, view_mode) ? 1 : 0;
    skip_instruction();
}

void vmcall_eh_remove(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto va_page = eh::page_align(va);
    auto cpu_bit = 1ULL << eh::vcpu_idx(cpu);

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = eh::find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    bool need_remove = (entry->per_vcpu_active_bitmap & cpu_bit) != 0;
    if (need_remove)
        entry->per_vcpu_active_bitmap &= ~cpu_bit;

    auto orig_pfn = entry->orig_pfn;
    bool free_now = (entry->per_vcpu_active_bitmap == 0);
    if (free_now)
        eh::free_entry_locked(entry);

    t.lock.release();

    if (need_remove)
        remove_ept_hook(cpu->ept, orig_pfn);

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_eh_enable(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto va_page = eh::page_align(va);
    auto cpu_idx = eh::vcpu_idx(cpu);
    auto cpu_bit = 1ULL << cpu_idx;

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = eh::find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    bool need_install = (entry->per_vcpu_active_bitmap & cpu_bit) == 0;
    if (need_install)
        entry->per_vcpu_active_bitmap |= cpu_bit;

    auto orig_pfn = entry->orig_pfn;
    auto fake_pfn = entry->fake_pfn;
    uint8_t view_mode = entry->is_fake_page;

    t.lock.release();

    if (need_install)
        install_ept_hook(cpu->ept, orig_pfn, fake_pfn, view_mode);

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_eh_disable(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto va_page = eh::page_align(va);
    auto cpu_bit = 1ULL << eh::vcpu_idx(cpu);

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = eh::find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    bool need_remove = (entry->per_vcpu_active_bitmap & cpu_bit) != 0;
    if (need_remove)
        entry->per_vcpu_active_bitmap &= ~cpu_bit;

    auto orig_pfn = entry->orig_pfn;

    t.lock.release();

    if (need_remove)
        remove_ept_hook(cpu->ept, orig_pfn);

    cpu->ctx->rax = 1;
    skip_instruction();
}

void vmcall_eh_write(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto dst_va = cpu->ctx->rdx;
    auto src_va = cpu->ctx->r8;
    auto size = cpu->ctx->r9;

    auto process_cr3 = eh::resolve_process_cr3(process);
    if (!process_cr3) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    // 读取源字节（调用者在 src_va 中传入内核指针；通过系统 CR3 读取）。
    uint8_t buf[0x1000];
    if (size > sizeof(buf))
        size = sizeof(buf);

    auto got = read_guest_virtual_memory(g_ghv->system_cr3,
        reinterpret_cast<void*>(src_va), buf, size);
    if (got != size) {
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    cpu->ctx->rax = eh::eh_write_internal(process_cr3, dst_va, buf, size) ? 1 : 0;
    skip_instruction();
}

void vmcall_eh_get_va(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto va = cpu->ctx->rdx;
    auto va_page = eh::page_align(va);
    auto offset = va & static_cast<uint64_t>(0xFFF);

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;
    t.lock.acquire();

    auto entry = eh::find_entry_locked(process_cr3, va_page);
    if (!entry) {
        t.lock.release();
        cpu->ctx->rax = 0;
        skip_instruction();
        return;
    }

    auto fake_va = reinterpret_cast<uint64_t>(&t.fake_pages[entry->fake_page_idx][offset]);
    t.lock.release();

    cpu->ctx->rax = fake_va;
    skip_instruction();
}

void vmcall_eh_remove_all_by_process(vcpu* const cpu) {
    auto process = reinterpret_cast<PEPROCESS>(cpu->ctx->rcx);
    auto cpu_bit = 1ULL << eh::vcpu_idx(cpu);

    auto process_cr3 = eh::resolve_process_cr3(process);

    auto& t = g_ghv->ept_hook_table;

    // 在锁保护下快照需要从 EPT 中卸载移除的 PFN 数组。
    uint64_t pfns[eh::ept_hook_table::capacity];
    size_t n = 0;

    t.lock.acquire();
    auto e = t.active_list_head;
    while (e) {
        auto next = e->next;
        if (e->process_cr3 == process_cr3) {
            if (e->per_vcpu_active_bitmap & cpu_bit) {
                if (n < eh::ept_hook_table::capacity)
                    pfns[n++] = e->orig_pfn;
                e->per_vcpu_active_bitmap &= ~cpu_bit;
            }
            if (e->per_vcpu_active_bitmap == 0)
                eh::free_entry_locked(e);
        }
        e = next;
    }
    t.lock.release();

    for (size_t i = 0; i < n; i++)
        remove_ept_hook(cpu->ept, pfns[i]);

    cpu->ctx->rax = 1;
    skip_instruction();
}

}  // namespace hc

}  // namespace hv
