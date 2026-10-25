with open(r'vt\VtResidentPayload\hooks\ept-hook.cpp', 'r', encoding='utf-8') as f:
    content = f.read()

replacements = [
    ("// --- internal static helpers ---",
     "// --- 内部静态辅助例程 ---"),
    ("""    // Compare against cached System EPROCESS 指针 (avoid touching the
    // PsInitialSystemProcess kernel global directly from root 模式).""",
     """    // 与缓存的 System EPROCESS 指针进行比对（避免直接在 Root 模式下访问
    // PsInitialSystemProcess 内核全局变量）。"""),
    ("// --- 表 management (exposed for vtcall-hook.cpp) ---",
     "// --- 钩子表管理（向 vtcall-hook.cpp 暴露） ---"),
    ("    // Unlink from active list.",
     "    // 从活动链表中解绑。"),
    ("    // Reset, preserving the stable fake_page_idx.",
     "    // 重置条目，保留稳定的 fake_page_idx 索引。"),
    ("    // Push to 释放 list.",
     "    // 推入空闲链表。"),
    ("// --- internal 安装 (called from vtcall-hook.cpp or vmcall handler) ---",
     "// --- 内部安装例程（由 vtcall-hook.cpp 或 vmcall 处理函数调用） ---"),
    ("""// Phase 1 of IPI 安装. Only the IPI initializer vCPU runs this.
// alloc 条目项, capture orig_pfn, memcpy fake_page. Does NOT touch EPT.
// out_freshly_allocated=true 鈫 caller owns the entry and must free_entry
// on later failure. =false 鈫 entry was reused, caller must NOT free.""",
     """// IPI 安装第一阶段。仅由发起 IPI 初始化的 vCPU 执行此阶段：
// 分配条目项，捕获 orig_pfn，将原始页内容复制到 fake_page。此阶段不修改 EPT。
// out_freshly_allocated=true -> 调用者拥有该条目，后续失败时必须调用 free_entry。
// =false -> 复用已有条目，调用者严禁释放。"""),
    ("""    // Kernel VA shortcut: when targeting a kernel-space VA (>= 0xFFFF8...),
    // force lookup AND 条目项 索引下标 through system_cr3. Per-process page
    // tables can have NX bits / shadowed entries / partial KVA mappings for
    // kernel space, which would walk to the wrong PFN and cause us to
    // redirect an unrelated physical page. system_cr3 always has the
    // canonical kernel mapping. The caller's `process` is still preserved
    // on the 条目项 record so dispatcher can do its filtering, but the
    // `process_cr3` used to KEY the 条目项 表 must match what 启用
    // disable / remove paths look up below 鈥 they too must normalize kernel
    // VAs to system_cr3 (see vtcall-hook.cpp callers).""",
     """    // 内核虚拟地址快捷路径：当目标为内核空间虚拟地址（>= 0xFFFF8...）时，
    // 强制通过 system_cr3 进行查找与条目索引。各进程的页表在内核空间可能存在 NX 位 /
    // 影子条目 / 不完整的 KVA 映射，若盲目遍历会导致解算出错误的 PFN，从而错误重定向
    // 不相关的物理页。system_cr3 始终包含规范的内核映射。条目中仍会保留调用者传入的
    // process 以供分发器执行过滤，但作为条目表索引键的 process_cr3 必须与下方的
    // 启用/禁用/移除路径保持一致——它们同样必须将内核虚拟地址归一化为 system_cr3（参见 vtcall-hook.cpp 调用方）。"""),
    ("""// Phase 2 of IPI 安装. Each vCPU runs this for itself: writes its own
// EPT tree to redirect orig_pfn鈫抐ake_pfn (execute-only view) and flushes
// its own TLB.""",
     """// IPI 安装第二阶段。每个 vCPU 自行执行：修改各自的 EPT 页表树，
// 将 orig_pfn 重定向至 fake_pfn（构建仅执行视图），并刷新各自的 TLB。"""),
    ("""    // install_ept_hook can fail (no 释放 hook node / get_ept_pte returned
    // nullptr / 执行失败 to split a 2MB PDE). Only mark the bit AFTER 执行成功
    // so a failed install can be retried later 鈥 and so the diag bitmap
    // accurately reflects which vCPUs actually have the hook.""",
     """    // install_ept_hook 可能会失败（无可用钩子节点 / get_ept_pte 返回
    // nullptr / 拆分 2MB PDE 失败）。仅在安装成功后才置位该位，
    // 以便失败时后续可以重试，并确保诊断位图准确反映哪些 vCPU 真正安装了钩子。"""),
    ("""// Install on ALL vCPUs from a single calling vCPU (host handler path) 鈥
// 安装 on ALL vCPUs from a single calling vCPU (host handler path).
// Used when there's no IPI rendezvous 鈥 current vCPU writes every vCPU's
// EPT tree synchronously and sets pending_ept_invept_bitmap so the other
// vCPUs 刷新 their own TLB on their next vmexit.
//
// This is the known-working pattern: NtSetEvent installed via this path
// (single vCPU writes all 16 ept trees + invept_all_context for self) +
// driver IPI for PMO produced handler_count > 0, hit_count > 0.""",
     """// 从单个调用 vCPU 为所有 vCPU 安装（Host 处理函数路径）。
// 当没有 IPI 协同汇合时使用——当前 vCPU 同步修改所有 vCPU 的 EPT 页表树，
// 并置位 pending_ept_invept_bitmap，以便其他 vCPU 在下一次 vmexit 时刷新各自的 TLB。
//
// 这是经过验证的可靠模式：NtSetEvent 通过此路径安装（单个 vCPU 写入全部 16 棵 EPT 树
// + 本地执行 invept_all_context），PMO 驱动端 IPI 成功产生 handler_count > 0, hit_count > 0。"""),
    ("""// drain_pending_installs: scan the deferred-安装 数组 and 安装 any
// entries this vCPU hasn't yet picked up. Entries whose per_vcpu_active_bitmap
// is fully 设置 across the live vCPU 设置 are CAS-cleared back to nullptr so
// the slot can be reused by a later 安装.""",
     """// drain_pending_installs：扫描延迟安装队列数组，安装当前 vCPU 尚未加载的所有条目。
// 当条目的 per_vcpu_active_bitmap 在所有活动 vCPU 上均已置位时，
// 通过 CAS 将其原子清零回 nullptr，以便槽位供后续安装复用。"""),
    ("""        // eh_install_self is idempotent (per_vcpu_active_bitmap 检查校验 inside)
        // 鈥 safe to call even for entries this vCPU already installed.""",
     """        // eh_install_self 具备幂等性（内部包含 per_vcpu_active_bitmap 校验），
        // 即使传入当前 vCPU 已经安装过的条目也能安全调用。"""),
    ("""        // If every live vCPU now has this 条目项 installed, retire the slot
        // so a future 安装 can reuse it. Use CAS so concurrent drains
        // don't double-清除 (and so we don't race a fresh enqueue that
        // grabbed this slot 鈥 the cmpxchg only succeeds if the slot still
        // holds e).""",
     """        // 如果所有活动 vCPU 均已安装此条目，则退役该槽位以便后续安装复用。
        // 采用 CAS 操作避免并发 drain 产生重复清除（同时避免与抢占该槽位的新入队发生竞态——
        // 仅当槽位仍持有 e 时 cmpxchg 才会成功）。"""),
    ("""// Host-handler DEFERRED 安装: 当前 vCPU installs OWN ept,
// other vCPUs enqueue + bit-设置; each drains on its next vmexit.""",
     """// Host 处理函数延迟安装：当前 vCPU 立即安装本核 EPT，
// 其他 vCPU 加入队列并置位标志位，在各自下一次 vmexit 时自行排空安装。"""),
    ("    // 1) Current vCPU installs its own EPT immediately (no race 鈥 own tree).",
     "    // 1) 当前 vCPU 立即安装本核 EPT（无并发竞态——操作私有树）。"),
    ("""    // 2) Find a free slot (CAS nullptr 鈫 entry). Slots get retired by drain
    // once every vCPU has installed, so the 数组 is bounded reuse, not
    //    monotonic growth.""",
     """    // 2) 查找空闲槽位（CAS nullptr -> entry）。所有 vCPU 安装完成后槽位由 drain 退役，
    // 故数组容量有界循环复用，不会单调膨胀。"""),
    ("""        // Same entry already pending (e.g., re-arm after idempotent path) 鈥
        // treat as 执行成功 without claiming a new slot.""",
     """        // 相同条目已处于挂起状态（例如幂等路径后重新激活）——视作成功且不重复占用新槽位。"""),
    ("    // 3) Arm bitmap for every OTHER vCPU. 当前 vCPU already done.",
     "    // 3) 为其他所有 vCPU 置位就绪位图。当前 vCPU 已完成。"),
    ("""// 获取 the host VA of the shared 伪造影子页 at 偏移 for (process_cr3, va_page).
// cpuid ignored 鈥 single shared fake page now (trampoline replaced per-vCPU mutation).""",
     """// 获取 (process_cr3, va_page) 对应共享伪造影子页在指定偏移处的 Host 虚拟地址。
// cpuid 参数已忽略——当前统一使用单共享伪造页（跳板架构替代了原有的每 vCPU 独立修改机制）。"""),
    ("// va_page is already page-aligned; offset = 0",
     "// va_page 已经页对齐；offset = 0"),
    ("    // 读取 source bytes (caller passes a kernel 指针 in src_va; 读取 via system CR3).",
     "    // 读取源字节（调用者在 src_va 中传入内核指针；通过系统 CR3 读取）。"),
    ("    // Snapshot the PFNs we need to 卸载移除 from EPT under the lock.",
     "    // 在锁保护下快照需要从 EPT 中卸载移除的 PFN 数组。")
]

for old, new in replacements:
    assert old in content, f"Not found in ept-hook.cpp:\n{old}"
    content = content.replace(old, new, 1)

with open(r'vt\VtResidentPayload\hooks\ept-hook.cpp', 'w', encoding='utf-8-sig', newline='\r\n') as f:
    f.write(content)

print("Translated ept-hook.cpp comments successfully!")
