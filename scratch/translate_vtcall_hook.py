with open(r'vt\VtResidentPayload\hooks\vtcall-hook.cpp', 'r', encoding='utf-8') as f:
    content = f.read()

replacements = [
    ("""// For kernel-space VAs (>= 0xFFFF8...), per-process CR3 may diverge from
// system_cr3 due to KVA Shadow / partial kernel mappings 鈥 using the wrong
// CR3 walks to the wrong PFN. eh_prepare_entry indexes kernel-VA entries
// under system_cr3; every 启用/禁用/卸载移除 path that finds entries by
// (cr3, va) must do the same normalization, otherwise lookups miss.""",
     """// 针对内核空间虚拟地址（>= 0xFFFF8...），各进程的 CR3 可能因为 KVA Shadow /
// 局部内核映射而与 system_cr3 产生分歧——使用错误的 CR3 会遍历至错误的 PFN。
// eh_prepare_entry 统一在 system_cr3 下索引内核虚拟地址条目；所有按 (cr3, va)
// 查找条目的启用/禁用/卸载移除路径都必须执行相同的归一化，否则会导致查找未命中。"""),

    ("""    // Read in 4 KB chunks (page granularity) and scan within each 鈥 much
    // faster than per-byte read_guest_virtual_memory, and ntdll padding
    // is typically multi-page so we always find a 4-byte 0xCC run quickly.""",
     """    // 按 4 KB 块（页面粒度）分批读取并在页内扫描——远比按字节调用
    // read_guest_virtual_memory 更快，且 ntdll 的填充区通常跨越多个页面，
    // 因此总能迅速定位到连续 4 字节的 0xCC 序列。"""),

    ("            // page not present or unreadable 鈥 skip ahead to next page boundary",
     "            // 页面未呈现或不可读——直接跳至下一个页面边界"),

    ("""    // Cross-page guards.
    // 1) vmcall stub (0F 01 C1, 3 bytes) is written into the 伪造影子页 at the
    // same 偏移 as target_va. If (target_va & 0xFFF) + 3 > 0x1000, the
    // stub spills into fake_pages[idx+1], corrupting another 条目项's
    //    fake page. Reject the install 鈥 fake_pages are virtually contiguous
    //    but physically not, so stub bytes cannot legally cross the boundary.
    if ((target_va & 0xFFF) + 3 > 0x1000) {
        _InterlockedIncrement64((volatile LONG64*)&g_ghv->diag_install_xpage_stub);
        return false;
    }
    // 2) target_resume = target_va + 大小尺寸 lands on the next 4KB page. This is
    //    safe in practice 鈥 the guest CR3 + EPT continue to map that page
    //    with the original PFN (only the hook page itself is redirected),
    // and the caller's working 设置 already had that page (control flow
    // came from there). Just 数量计数 occurrences for diagnostics; don't
    // refuse the 安装.""",
     """    // 跨页安全保护防护。
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
    //    此处仅递增诊断计数，不拒绝安装。"""),

    ("            // Page not present / unreadable 鈥 skip ahead by a page.",
     "            // 页面未呈现或不可读——直接跳过一个完整页面。"),

    ("// Public wrapper.",
     "// 公共包装接口。"),

    ("""// IPI-安装 rendezvous 状态. vmcall_vh_install is dispatched via
// KeIpiGenericCall, so every vCPU enters install_host_impl simultaneously.
// One vCPU wins the seq_lock CAS and does the shared init (slot/trampoline/
// fake_page/0F01C1 写入), then signals init_done. All vCPUs (including the
// winner) 安装 EPT on THEIR OWN ept tree + invept_single. No vCPU writes
// another vCPU's EPT 鈥 TLB invalidation is per-vCPU.""",
     """// IPI 安装协同汇合状态。vmcall_vh_install 通过 KeIpiGenericCall 分发，
// 因此所有 vCPU 同时并发进入 install_host_impl。
// 胜出 seq_lock CAS 的单一 vCPU 执行共享初始化（分配槽位/跳板/伪造页/写入 0F01C1 存根），
// 随后发出 init_done 信号。所有 vCPU（包含胜出者）在各自私有的 EPT 树中安装 EPT 映射并执行 invept_single。
// 任何 vCPU 均不跨核写入其他 vCPU 的 EPT——TLB 刷新完全在本核完成。"""),

    ("""// Same but for the host-handler path: the calling vCPU writes EPT for ALL
// vCPUs (current vCPU is invept'd by install_ept_hook; others get pending
// invept bits, picked up at next vmexit).""",
     """// 同上，但适用于 Host 处理函数路径：调用 vCPU 为所有 vCPU 统一写入 EPT
// （当前 vCPU 在 install_ept_hook 内部执行 invept；其他 vCPU 置位挂起 invept 标志位，
// 在其下一次 vmexit 时生效）。"""),

    ("""// 安装 EPT hook and return single shared fake HVA at the hook 偏移.
// Legacy entry point 鈥 kept for callers that haven't migrated to the
// two-phase prepare/install_self model. Uses the IPI-style for-each-vCPU
// path internally, so safe to call only from contexts where a single vCPU
// representing the 安装 can broadcast.""",
     """// 安装 EPT 钩子并在钩子偏移处返回单个共享伪造页的 Host 虚拟地址。
// 兼容旧版入口——为尚未迁移到两阶段 prepare/install_self 模型的调用者保留。
// 内部使用 IPI 风格的逐核遍历路径，仅可在代表安装的单一 vCPU 能进行广播的上下文中安全调用。"""),

    ("""// Claim a 释放 trampoline slot. Writes oldByte + 0xCC into the slot's
// 在 exec_page 执行页中计算三个关键的 Guest 虚拟地址（tramp_va / bp_rip / target_resume）
// 并通过传出参数返回。若跳板池未就绪或没有容量充足的空闲槽位（需满足 oldByte_size + 1 <= slot.capacity）则返回 false。""",
     """// 申请空闲跳板槽位。将 oldByte + 0xCC 写入槽位的 exec_page 执行页中，
// 计算三个关键的 Guest 虚拟地址（tramp_va / bp_rip / target_resume）
// 并通过传出参数返回。若跳板池未就绪或没有容量充足的空闲槽位（需满足 oldByte_size + 1 <= slot.capacity）则返回 false。"""),

    ("""        // Sanity: vmcall_vh_tramp_add_slot already rejects cross-page slots
        // at registration. This check is defence-in-depth 鈥 if it ever trips
        // the pool was constructed wrong.""",
     """        // 健全性检查：vmcall_vh_tramp_add_slot 在注册时已拒绝跨页槽位。
        // 此检查为深度防御——若触发则说明跳板池构建存在异常。"""),

    ("""    // 写入 through host_physical_memory_base instead of pg.exec_hva so we
    // don't depend on the driver-side system VA being mapped in host PT.""",
     """    // 通过 host_physical_memory_base 写入而非 pg.exec_hva，
    // 从而避免依赖驱动层系统虚拟地址在 Host 页表中的映射。"""),

    ("""    // INT3 vm-exit reports GUEST_RIP pointing AT the 0xCC byte (not past it).
    // bp_rip must therefore be tramp_va + oldByte_size, the position of 0xCC.""",
     """    // INT3 vm-exit 上报的 GUEST_RIP 直接指向 0xCC 字节本身（而非其后随指令）。
    // 因此 bp_rip 必须为 tramp_va + size，即 0xCC 的准确偏移位置。"""),

    ("// Release a trampoline slot back to its pool. Called on hook 卸载移除.",
     "// 将跳板槽位归还至跳板池。在钩子卸载移除时调用。"),

    ("""// Host-internal 安装 path. Callable from any host root-模式 code.
// PEPROCESS=nullptr 鈫 system process / system_cr3 (kernel hook).
//
// from_ipi:
//   true  鈥 caller is the vmcall_vh_install handler (KeIpiGenericCall
//           delivers vmcall to every vCPU simultaneously). One vCPU wins
//           seq_lock CAS and does the shared init; all vCPUs (winner
//           included) call eh_install_self on their own ept tree.
//   false 鈥 caller is a host vmexit handler running on a single vCPU
//           (e.g. PMO handler lazy-installing GetBuffer/NtSetEvent).
// 当前 vCPU does shared init AND writes EPT for ALL vCPUs
// via eh_install_all; other vCPUs 刷新 their own TLB on
//           their next vmexit (pending_ept_invept_bitmap).""",
     """// Host 内部安装路径。可从任何 Host Root 模式代码中调用。
// PEPROCESS=nullptr -> 系统进程 / system_cr3（内核钩子）。
//
// from_ipi:
//   true  -> 调用者为 vmcall_vh_install 处理函数（KeIpiGenericCall
//           同时向每个 vCPU 分发 vmcall）。单个 vCPU 赢得 seq_lock CAS
//           并执行共享初始化；所有 vCPU（包含胜出者）在各自 EPT 树上调用 eh_install_self。
//   false -> 调用者为运行在单个 vCPU 上的 Host vmexit 处理函数
//           （例如 PMO 处理函数惰性安装 GetBuffer/NtSetEvent）。
//           当前 vCPU 执行共享初始化，并通过 eh_install_all 为所有 vCPU 统一写入 EPT；
//           其他 vCPU 在其下一次 vmexit 时刷新各自的 TLB（通过 pending_ept_invept_bitmap）。"""),

    ("    // PMO-only step diag.",
     "    // 仅针对 PMO 的步骤诊断标记。"),

    ("    bump_step(1 << 0);   // entered",
     "    bump_step(1 << 0);   // 已进入"),

    ("""    // Single global lock: serialize ALL 安装 entries (shared-init phase).
    // First vCPU through allocates 条目项/slot/trampoline and writes 0F01C1.
    // Subsequent vCPUs see slot already occupied and skip those steps.
    // EVERY vCPU then unconditionally installs EPT on its OWN ept tree.""",
     """    // 单一全局自旋锁：串行化所有安装条目（共享初始化阶段）。
    // 首个穿透的 vCPU 分配条目项/槽位/跳板并写入 0F01C1 存根机器码。
    // 后续并发进入的 vCPU 发现槽位已被占用，将跳过这些初始化步骤。
    // 随后每个 vCPU 无条件在各自私有的 EPT 页表树中完成安装。"""),

    ("    // Look for existing slot (already installed by an earlier vCPU).",
     "    // 查找已存在的槽位（先前已由更早进入的 vCPU 安装）。"),

    ("        // First-time 安装: 分配 slot + 条目项 + trampoline, 写入 stub.",
     "        // 首次安装：分配槽位 + 条目项 + 跳板，写入存根机器码。"),

    ("        // Slot already exists 鈥 fetch the entry to install EPT for this vCPU.",
     "        // 槽位已存在——获取该条目以为当前 vCPU 安装 EPT。"),

    ("        bump_step(1 << 11);   // idemp: shared init already done",
     "        bump_step(1 << 11);   // 幂等：共享初始化已就绪"),

    ("""    // EPT 安装:
    //   from_ipi=true  (driver affinity-loop):  current vCPU installs OWN ept.
    //                                            Loop visits every CPU so all
    //                                            vCPUs end up with their own
    // 安装 via this same path.
    //   from_ipi=false (host vmexit handler):   current vCPU is the only one
    //                                            that will ever enter this
    //                                            function 鈥 so it must write
    //                                            EPT for ALL vCPUs from here.""",
     """    // EPT 安装分发：
    //   from_ipi=true  （驱动亲和性遍历循环）：当前 vCPU 仅安装本核私有 EPT。
    //                                           循环遍历所有 CPU，使每个 vCPU 均通过
    //                                           此相同路径完成自我安装。
    //   from_ipi=false （Host vmexit 处理函数）：当前 vCPU 是唯一会进入此函数的核，
    //                                           因此必须在此为所有 vCPU 统一写入 EPT。"""),

    ("""// Public wrapper for find_blank_host (still namespace vh) so it can be
// called from outside this TU. Used by Stage 鈶 kernel hook code path
// (game.cpp scans ntoskrnl with system_cr3=0).""",
     """// find_blank_host 的公共包装接口（仍在 namespace vh 内），以便在当前编译单元外调用。
// 供阶段内核钩子代码路径使用（扫描 ntoskrnl，传入 system_cr3=0）。"""),

    ("""// DEFERRED variant of install_host_impl: 当前 vCPU does its OWN ept
// 安装 immediately, all other vCPUs are enqueued. Each other vCPU drains
// the queue on its next vmexit and installs its own ept tree. No cross-vCPU
// EPT writes 鈥 eliminates the race where this vCPU writes another vCPU's
// ept while that vCPU is mid-instruction on the same page.""",
     """// install_host_impl 的延迟变体：当前 vCPU 立即完成本核 EPT 安装，
// 其他所有 vCPU 均入队等待。其他各 vCPU 在下一次 vmexit 时排空队列并安装各自的 EPT 树。
// 杜绝跨 vCPU 强写 EPT——根除当本核写入其他 vCPU 的 EPT 时，该核恰好在同一页面执行指令所引发的竞态。"""),

    ("""    // Idempotency: if (目标, type) already installed, just re-arm pending
    // for other vCPUs in case some haven't drained yet, and ensure THIS vCPU
    // has it installed too.""",
     """    // 幂等性保障：若 (目标, type) 已安装，重新为尚未排空队列的其他 vCPU 激活挂起标志，
    // 并确保当前 vCPU 亦已完成本核安装。"""),

    ("    // 当前 vCPU installs OWN ept now; others deferred via vmexit drain.",
     "    // 当前 vCPU 立即安装本核私有 EPT；其他 vCPU 延迟至 vmexit 时排空安装。"),

    ("""// (install_host moved out of namespace vh to ensure external linkage from
//  game.cpp; see definition at end of file in namespace hv directly.)""",
     """// （install_host 移出 namespace vh，以确保供外部模块链接调用；参见文件末尾 namespace hv 的直接定义。）"""),

    ("""// install_host needs external linkage so game.cpp can call it. This is the
// HOST-HANDLER path (host vmexit handler running on a single vCPU) 鈥 it writes
// EPT for ALL vCPUs because there is no IPI rendezvous to 分发 per-vCPU.""",
     """// install_host 导出供外部调用。这是 Host 处理函数路径（在单个 vCPU 上运行的 Host vmexit 处理函数）
// ——由于缺乏逐核分发的 IPI 协同汇合机制，必须统一为所有 vCPU 写入 EPT。"""),

    ("""// DEFERRED variant. Identical to vh_install_host except for the EPT phase:
// instead of writing every vCPU's ept tree synchronously (which races with
// guest threads mid-instruction on the same page), the calling vCPU installs
// only its OWN ept tree and enqueues the 条目项 for the other vCPUs. Each
// other vCPU drains the queue on its next vmexit and installs its own ept.
//
// Use this from host vmexit handlers (e.g. PMO handler lazy-installing
// GetBuffer) where the target page is hot 鈥 i.e. some other vCPU is almost
// certainly executing inside the page right now.""",
     """// 延迟安装变体。除 EPT 阶段外与 vh_install_host 完全一致：
// 调用 vCPU 仅安装其自身的私有 EPT 树，并将条目入队等待其他 vCPU 获取，
// 而非同步写入每个 vCPU 的 EPT（后者会与在同一页面执行指令的 Guest 线程发生竞态）。
// 其他每个 vCPU 在其下一次 vmexit 时排空队列并安装自己的 EPT。
//
// 适用于目标页面处于高频热点执行路径时的 Host vmexit 处理函数
// （例如惰性安装 GetBuffer 的 PMO 处理函数）——即其他 vCPU 极大概率此刻正在该页面内执行代码。"""),

    ("// Public find_blank scanner. Pass cr3=0 to use system_cr3 (kernel scan).",
     "// 公共空闲内存查找扫描器。传入 cr3=0 表示使用系统 CR3（内核扫描）。"),

    ("""// (install_host moved to namespace vh above; vmcall_vh_install delegates to it.)

// args:
//   rcx = process
//   rdx = target_va
//   r8  = blank_mem_va
//   r9  = packed flags: bit0=auto_enable, bit1=filter_by_process; (type<<8); (dispatch_mode<<16)""",
     """// （install_host 已移至上方的 namespace vh；vmcall_vh_install 委托调用该实现。）

// 入参：
//   rcx = process
//   rdx = target_va
//   r8  = blank_mem_va
//   r9  = 打包标志位：bit0=auto_enable, bit1=filter_by_process; (type<<8); (dispatch_mode<<16)"""),

    ("    g_ghv->dwm_install_status    = 0xFF;  // entered handler",
     "    g_ghv->dwm_install_status    = 0xFF;  // 已进入处理函数"),

    ("""    // IPI path: caller is the driver invoking via KeIpiGenericCall, so this
    // handler runs once per vCPU. install_host_impl with from_ipi=true does
    // CAS rendezvous and per-vCPU eh_install_self.""",
     """    // IPI 路径：调用者为通过 KeIpiGenericCall 调用的驱动端，因此该处理函数在每个 vCPU 上各执行一次。
    // 带有 from_ipi=true 的 install_host_impl 执行 CAS 协同汇合并在本核调用 eh_install_self。"""),

    ("""// args:
//   rcx = process
//   rdx = target_va
//   r8  = blank_mem_va
//   r9  = trample_addr_va
//   r10 = packed: bit0=auto_enable, bit1=filter_by_process; (type<<8)
//
// Writes RetAbs trampoline bytes via host-side eh_write for trample_addr.
// hook_fn 指针 (where to jump on hit) and original_out 指针 not supported in this
// minimal port; callers should reuse vmcall_vh_install + handler 分发 instead.""",
     """// 入参：
//   rcx = process
//   rdx = target_va
//   r8  = blank_mem_va
//   r9  = trample_addr_va
//   r10 = 打包参数：bit0=auto_enable, bit1=filter_by_process; (type<<8)
//
// 通过 Host 端 eh_write 为 trample_addr 写入 RetAbs 跳板字节。
// 此极简移植版本中不再支持 hook_fn 指针（命中时跳转目标）与 original_out 指针；
// 调用者应改用 vmcall_vh_install + 处理函数分发模式。"""),

    ("""    // Not used by 当前 call paths after the host-side rewrite; expose as
    // a stub returning failure. dwm's existing usage maps onto vmcall_vh_install
    // with dispatch_mode = VMCALL_DISPATCH_RETABS.""",
     """    // Host 端重构后当前调用路径不再使用；暴露为返回失败的桩函数。
    // 现有用法已映射至带有 dispatch_mode = VMCALL_DISPATCH_RETABS 的 vmcall_vh_install。"""),

    ("    // 卸载移除 the EPT hooks via the same per-vcpu path eh_install used.",
     "    // 通过与 eh_install 相同的逐 vCPU 路径卸载移除 EPT 钩子。"),

    ("        // blank_mem no longer has an EPT hook (handled via #BP trap), nothing to 卸载移除.",
     "        // blank_mem 不再挂接 EPT 钩子（通过 #BP 陷阱接管），无需卸载移除。"),

    ("    // 清除 the slot completely on the last cpu (we let every cpu 清除 it; harmless idempotent).",
     "    // 在最后一个 CPU 上彻底清除槽位（此处让每个 CPU 都执行清除；具备无害幂等性）。"),

    ("""    // Last-vcpu detection: 清除 our bit in a per-uninit bitmap, the vcpu that
    // sees a 0 bitmap is the last one and gets to memset slots. Without this,
    // vcpu0 would memset the slot on its pass and vcpu1 would see occupied=0
    // and skip its own EPT removal -> stale hook on vcpu1's EPT -> dxgi
    // renders from 伪造影子页 after unload -> black screen.""",
     """    // 最后一个 vCPU 检测：在反初始化位图中清除本核位，观察到位图归零的 vCPU
    // 即为最后一个核，负责 memset 清空槽位数组。若无此机制，
    // vcpu0 在其轮次清空槽位会导致 vcpu1 看到 occupied=0 并跳过自身的 EPT 卸载
    // -> vcpu1 的 EPT 中残留悬挂钩子 -> 驱动卸载后依然从伪造影子页渲染 -> 导致黑屏死锁。"""),

    ("""        // 初始化 on first 条目项: 设置 bit per active vcpu.
        // Done atomically 鈥 only one vcpu will CAS from 0 to the full mask.""",
     """        // 首次进入时初始化：为每个活动 vCPU 置位对应标志位。
        // 原子执行——仅有一个 vCPU 能通过 CAS 从 0 切换到全量掩码。"""),

    ("    // 清除 my bit; if I was the last vcpu, 释放 the slot 表 now.",
     "    // 清除本核标志位；若我是最后一个 vCPU，则在此释放清空槽位表。"),

    ("""// args:
//   rcx = process     (PsGetCurrentProcess on driver side; nullptr -> system)
//   rdx = start_va
//   r8  = max_scan
//
// Returns the page-aligned VA of a fully-0xCC 4KB page, or 0 if none.""",
     """// 入参：
//   rcx = process     （驱动端为 PsGetCurrentProcess；nullptr -> 系统进程）
//   rdx = start_va
//   r8  = max_scan
//
// 返回全为 0xCC 填充的 4KB 页面按页对齐虚拟地址，若未找到则返回 0。"""),

    ("""// args:
//   rcx = orig_pfn       (PFN of the ntdll/ntoskrnl page containing 0xCC runs)
//   rdx = exec_pfn       (PFN of the PoolManager-allocated exec page)
//   r8  = page_va        (guest VA of the page, page-aligned)
//   r9  = exec_hva       (host VA of the exec page; we copy original-page content into it)
//   r10 = is_kernel      (1 = kernel pool, 0 = user pool)
//
// Returns page_index >= 0 on 执行成功, -1 on failure. The host caller-side
// allocation already verified PFNs; we 安装 the EPT hook and seed the
// exec_page with a copy of the original 4KB so non-trampoline bytes still
// 读取 back as the legit module bytes.""",
     """// 入参：
//   rcx = orig_pfn       （包含 0xCC 填充序列的 ntdll/ntoskrnl 原始页 PFN）
//   rdx = exec_pfn       （由 PoolManager 分配的执行页 PFN）
//   r8  = page_va        （页面的 Guest 虚拟地址，页对齐）
//   r9  = exec_hva       （执行页的 Host 虚拟地址；将原始页内容复制至其中）
//   r10 = is_kernel      （1 = 内核跳板池，0 = 用户跳板池）
//
// 成功时返回 page_index >= 0，失败返回 -1。Host 调用端分配时已校验 PFN；
// 此处安装 EPT 钩子并用原始 4KB 页面副本初始化 exec_page，
// 确保非跳板字节被读取时仍呈现为合法模块的原始字节。"""),

    ("""    // Seed exec_page with original page content so non-trampoline bytes still
    // appear as the legit module's bytes when guest executes them.""",
     """    // 将原始页面内容复制至 exec_page，确保 Guest 执行非跳板区域字节时依然呈现为合法模块的指令。"""),

    ("""    // EPT double-view on EVERY vCPU: install_ept_hook(is_fake_page=false)
    // clears execute_access on the original PTE (PFN unchanged). On guest
    // instruction-fetch a violation fires, handle_ept_violation swaps PFN
    // to exec_pfn (X=1, R=W=0). On guest 读写, violation swaps back
    // to orig_pfn (R=W=1, X=0). PG / 反作弊系统 reading ntoskrnl/ntdll
    // bytes always see the original 0xCC padding, never our oldByte+0xCC.""",
     """    // 在每个 vCPU 上构建 EPT 双视图：install_ept_hook(is_fake_page=false)
    // 清除原始 PTE 上的 execute_access 执行权限（PFN 保持不变）。当 Guest 进行指令取指时，
    // 触发 EPT 违例异常，handle_ept_violation 将 PFN 切换至 exec_pfn（X=1, R=W=0）。
    // 当 Guest 尝试读写时，违例处理将其切换回 orig_pfn（R=W=1, X=0）。
    // PatchGuard / 反作弊系统读取 ntoskrnl/ntdll 字节时，永远只能读取到原始的 0xCC 填充，
    // 绝对无法观测到我们的 oldByte+0xCC 指令修改。"""),

    ("""// args:
//   rcx = page_index   (returned by vmcall_vh_tramp_add_page)
//   rdx = page_offset  (byte offset within the page where the 0xCC run starts)
//   r8  = capacity     (length of the 0xCC run; must be >= 8)
//   r9  = is_kernel
//
// Returns 1 on 执行成功.""",
     """// 入参：
//   rcx = page_index   （由 vmcall_vh_tramp_add_page 返回）
//   rdx = page_offset  （页面内 0xCC 填充序列起始的字节偏移）
//   r8  = capacity     （0xCC 填充序列长度；必须 >= 8）
//   r9  = is_kernel
//
// 成功时返回 1。"""),

    ("""        // Reject slots whose [page_off, page_off+capacity) would cross the
        // 4KB exec_page boundary. The driver-side bootstrap walks ntdll/
        // ntoskrnl padding runs and could in principle hand us a run that
        // straddles a page; alloc_trampoline can't 写入 oldByte+0xCC over
        // a page boundary because exec_pages aren't physically contiguous.""",
     """        // 拒绝区间 [page_off, page_off+capacity) 跨越 4KB exec_page 边界的槽位。
        // 驱动端引导代码在遍历 ntdll/ntoskrnl 填充区间时理论上可能传入跨页区间；
        // alloc_trampoline 无法跨越页面边界写入 oldByte+0xCC，因为 exec_pages 物理上并不连续。"""),

    ("""// args:
//   rcx = is_kernel (1=kernel, 0=user)
//
// Flips the pool's _ready 标志位. EPT was already installed by add_page on
// every vCPU synchronously.""",
     """// 入参：
//   rcx = is_kernel（1=内核，0=用户）
//
// 翻转跳板池的 _ready 就绪标志位。EPT 此前已由 add_page 在每个 vCPU 上同步完成安装。""")
]

for old, new in replacements:
    assert old in content, f"Not found in vtcall-hook.cpp:\n{old}"
    content = content.replace(old, new, 1)

with open(r'vt\VtResidentPayload\hooks\vtcall-hook.cpp', 'w', encoding='utf-8-sig', newline='\r\n') as f:
    f.write(content)

print("Translated vtcall-hook.cpp comments successfully!")
