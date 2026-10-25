import re
import os

def clean_and_translate_hv_h():
    path = 'vt/VtHypervisor/vt/hv.h'
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    # 替换已知特定注释
    replacements = [
        (r'// VT log ring sizing \(Stage [^\)]+\)\.', r'// VT 日志环形缓冲区大小规格（用于 Host 根模式日志记录）。'),
        (r'// max bytes claimed per slot', r'// 每个槽位占用的最大字节数'),
        (r'// ntdll-backed, ring-3 hooks', r'// 基于 ntdll 的用户态（Ring-3）挂钩跳板'),
        (r'// ntoskrnl-backed, ring-0 hooks', r'// 基于 ntoskrnl 的内核态（Ring-0）挂钩跳板'),
        (r'// distinct 4KB exec_pages per pool', r'// 每个跳板池独立分配的 4KB 执行页数量上限'),
        (r'// guest VA where oldByte\+0xCC starts \(= GUEST_RIP after dispatcher\)', r'// 包含旧指令机器码与 0xCC 断点的 Guest 虚拟地址（分发器重写后的 GUEST_RIP）'),
        (r'// tramp_va \+ oldByte_size \+ 1; CPU lands here after #BP advances RIP past 0xCC', r'// tramp_va + oldByte_size + 1；CPU 命中 0xCC 触发 #BP 步进后的返回地址'),
        (r'// target_va \+ oldByte_size; what we rewrite GUEST_RIP to', r'// target_va + oldByte_size；#BP 异常拦截处理后恢复重写的目标 Guest RIP'),
        (r'// index into pool\'s pages\[\] \(which exec_page hosts this slot\)', r'// 跳板池 pages[] 数组的索引（指示承载当前槽位的 exec_page）'),
        (r'// byte offset within the exec_page where oldByte starts', r'// exec_page 执行页内旧指令机器码的起始字节偏移'),
        (r'// length of this 0xCC run \(>= oldByte_size \+ 1 required\)', r'// 该 0xCC 填充区域的连续字节长度（必须满足 >= oldByte_size + 1）'),
        (r'// page-aligned VA inside ntdll/ntoskrnl', r'// ntdll/ntoskrnl 内按 4KB 页对齐的虚拟地址'),
        (r'// original PFN \(read view\)', r'// 原始物理页号（只读/数据视图）'),
        (r'// our exec PFN', r'// 驱动分配的执行物理页号（可执行视图）'),
        (r'// host VA of our exec_page \(to write tramp bytes\)', r'// 当前 exec_page 的 Host 虚拟地址（用于向跳板写入机器码）'),
        (r'//protect process list', r'// 保护进程链表'),
        (r'// per-vCPU PTE value after install', r'// 挂载后各 vCPU 对应的 PTE 实测值'),
        (r'// = orig_pfn << 12 of PMO entry', r'// 对应 PMO 条目的目标物理地址（orig_pfn << 12）'),
        (r'// last EPROCESS that matched g_yvt\.dwm', r'// 最近一次与 g_yvt.dwm 匹配的 EPROCESS 地址'),
        (r'// bumped when no free slot found', r'// 当跳板池无可用空闲槽位时递增计数'),
        (r'// bit v set [^\n]+ vCPU v has work to do', r'// 当对应位设置时表示对应的 vCPU 有待处理的 EPT 安装任务'),
        (r'// cleanup ran on different vCPU than entry', r'// 清理流程在与入口不同的 vCPU 上执行（跨核调用）'),
        (r'// cleanup ran on entry vCPU \(normal path\)', r'// 清理流程在入口同一个 vCPU 上执行（标准单核路径）'),
        (r'// mark/restore spin-waited on pending_lock', r'// mark/restore 操作在 pending_lock 自旋锁上产生等待的计数'),
        (r'// mark gave up after 5ms spin \(rare\)', r'// 自旋等待超过 5ms 超时放弃计数（极少触发）'),
        (r'// stack node leaked due to mark timeout', r'// 因标记超时导致栈节点未能及时回收的计数'),
        (r'// \(1<<N\)-1, cleared per-vcpu', r'// 初始掩码为 (1<<N)-1，由每个 vCPU 完成隐藏后逐位清除'),
        (r'// earliest tsc to start hide', r'// 允许启动驱动隐藏的最早 TSC 时间戳阈值'),
        (r'// exclusive', r'// 结束边界（左闭右开区间）'),
        (r'// Stage 5 memory-hide hook \(cross-process\)', r'// 阶段 5 内存隐藏钩子（跨进程安全拷贝）'),
        (r'// Stage 5 memory-hide hook \(probe\)', r'// 阶段 5 内存隐藏钩子（内存地址有效性校验）'),
        (r'// Stage 5 memory-hide hook \(PA map\)', r'// 阶段 5 内存隐藏钩子（物理内存映射过滤）'),
        (r'// Optional Stage 5 memory-hide hook \(extended probe\)', r'// 可选阶段 5 内存隐藏钩子（扩展地址有效性探测）'),
        (r'// Optional Stage 5 memory-hide hook \(VAD query\)', r'// 可选阶段 5 内存隐藏钩子（VAD 虚拟内存查询）'),
        (r'// Optional Stage 5 memory-hide hook \(VA->PA disclosure\)', r'// 可选阶段 5 内存隐藏钩子（虚拟地址转物理地址泄露防护）'),
        (r'// Stage 5 memory-hide hook', r'// 阶段 5 内存隐藏钩子'),
        (r'// Stage [^\n]+ in-handler kernel logging', r'// 内核日志输出例程'),
        (r'// Stage [^\n]+ mid-freq hook used to flush vt_log ring', r'// 用于定时刷出 VT 日志环形缓冲区的中频内核钩子'),
        (r'// anti-screenshot: DWM-only, EXECUTE-class alloc [^\n]+', r'// 防截图感知：仅针对 DWM，拦截可执行内存申请并通知隐藏'),
        (r'// anti-screenshot: DWM-only, EXECUTE-class mprotect [^\n]+', r'// 防截图感知：仅针对 DWM，拦截可执行内存属性修改并通知隐藏'),
        (r'// anti-screenshot: DWM-only, EXECUTE-class map [^\n]+', r'// 防截图感知：仅针对 DWM，拦截节区可执行映射并通知隐藏'),
        (r'// anti-screenshot: NtCreateSection handler [^\n]+', r'// 防截图感知：NtCreateSection 处理中获取目标 FILE_OBJECT'),
        (r'// anti-screenshot: paired release', r'// 防截图感知：成对释放 FILE_OBJECT 对象引用'),
    ]

    for pat, rep in replacements:
        text = re.sub(pat, rep, text)

    # 替换 Deferred self-hide state 大段注释
    old_hide_cmt = """// Deferred self-hide state. mapDriver populates pending_hide_pfns[] via
// hypercall_prepare_self_hide_add (one PFN per call) then commits via
// hypercall_prepare_self_hide_commit. The VM-exit dispatcher checks
// pending_hide_vcpu_bitmap on every exit and, when the bit for the current
// vcpu is set and the TSC threshold has passed, walks the buffer and
// redirects each EPT entry to dummy_page_pfn. Host code runs in host CR3
// so hiding driver image is safe  by then guest is in NTOS not in our .text.
//
// Buffer is inline in ghv so host can read it without gva2hva translation.
// Size budget: 256K entries × 8 bytes = 2MB. Covers ~1GB of physical
// memory worth of pages  needed because vcpu pool block alone is
// ~545MB (136K pages) and the previous 64K cap silently dropped half
// the vcpu hide queue."""
    new_hide_cmt = """// 延迟自身隐藏状态：
// mapDriver 通过 hypercall_prepare_self_hide_add 将物理页 PFN 逐一添加至 pending_hide_pfns[]，
// 随后通过 hypercall_prepare_self_hide_commit 提交生效。VM-exit 分发器在每次退出时检查
// pending_hide_vcpu_bitmap，当当前 vCPU 对应位被置位且已达到 TSC 时间戳阈值时，
// 遍历缓冲区并将每个对应的 EPT 表项重定向至 dummy_page_pfn 影子空页。
// Host 代码运行于 Host CR3 独立地址空间下，因此隐藏驱动自身的物理镜像绝对安全
// （此时 Guest 正运行于 NTOS 内核代码中，而非我们的驱动代码段）。
//
// 该缓冲区内嵌于 ghv 全局上下文中，使 Host 态无需进行 GVA 到 HVA 的地址转换即可直接读取。
// 预留容量：256K 项 × 8 字节 = 2MB，可覆盖约 1GB 物理内存页。
// 这对于容纳 vCPU 内存池块（约 545MB / 136K 物理页）是必需的，彻底根除先前 64K 容量截断丢弃的问题。"""
    if old_hide_cmt in text:
        text = text.replace(old_hide_cmt, new_hide_cmt)

    # 替换 Protected VA-range table 大段注释
    old_prot_cmt = """// Protected VA-range table. Each entry covers a contiguous kernel VA
// span that must be hidden from Mm* kernel probes. Filled by
// prepare_self_hide_commit from:
//   1. testDriver image (one entry: imageBase..imageBase+imageSize)
//   2. each PoolManager block (one entry per Util::Pools active entry)
//
// Total memory: 128 entries × 16 bytes = 2 KB inline (vs 8 MB for a
// page-granular bitmap). Lookup is O(N) over ~60 entries  a couple of
// hundred ns per Mm* hook invocation, well within budget.
//
// Mm* hook handlers (MmCopyMemory / MmCopyVirtualMemory /
// MmIsAddressValidEx) check the target VA against this table and bail
// with STATUS_INVALID_ADDRESS (or FALSE) on a hit."""
    new_prot_cmt = """// 受保护内核虚拟地址区间表（Protected VA-range Table）：
// 每个条目描述一段对 Mm* 系列内核探测例程隐藏的连续内核虚拟地址区间。
// 由 prepare_self_hide_commit 收集并填充：
//   1. 驱动自身映像区间（基址至基址 + 镜像尺寸）；
//   2. 每个 PoolManager 分配块（对应 Util::Pools 中已分配的活动内核条目）。
//
// 内存开销：128 个条目 × 16 字节 = 2 KB 内联空间（相较于页级位图需要 8 MB 极具优势）。
// 线性查找复杂度为 O(N)，总条目数约 60 项，每次 Mm* 钩子命中耗时仅数百纳秒，完全满足实时性要求。
//
// Mm* 系列钩子处理程序（MmCopyMemory / MmCopyVirtualMemory / MmIsAddressValidEx）
// 将目标虚拟地址与该表进行区间匹配，一旦命中立即返回 STATUS_INVALID_ADDRESS 或 FALSE。"""
    if old_prot_cmt in text:
        text = text.replace(old_prot_cmt, new_prot_cmt)

    # 替换 Fake-data page 大段注释
    old_fake_cmt = """// Fake-data page. Mm* hooks fill the caller's buffer with bytes from
// here on a protected-region hit, instead of returning an error. The
// anti-cheat sees a successful copy returning "normal looking" bytes
// and doesn't escalate. Filled at driver init from a slice of ntoskrnl
// image content (real kernel code/data layout  not all zeros, not
// recognizable as testDriver)."""
    new_fake_cmt = """// 伪造数据影子页（Fake-data Page）：
// 当 Mm* 钩子拦截到针对受保护区域的访问时，向调用者的输出缓冲区填充该影子页中的字节，
// 而非直接返回错误状态码。反作弊检测机制将观察到读取成功并返回“看似正常”的内核数据，
// 从而避免引发对抗升级。在驱动初始化阶段，该页面使用真实 ntoskrnl 镜像切片填充
// （呈现真实内核代码/数据布局，非全零且不包含任何驱动特有特征）。"""
    if old_fake_cmt in text:
        text = text.replace(old_fake_cmt, new_fake_cmt)

    # 替换 Per-vCPU vmexit counter
    old_cnt_cmt = """// Per-vCPU vmexit counter  bumped at dispatch_vm_exit entry. Lets us see
// which vCPUs are actually executing vmexits. A vCPU stuck in host or in
// guest with interrupts disabled would show 0/very-low counts."""
    new_cnt_cmt = """// 各 vCPU 的 VM-exit 计数器：在 dispatch_vm_exit 入口处递增。
// 用于精确监测各个 vCPU 是否正常响应并处理虚拟机退出事件。
// 若某个 vCPU 异常停留在 Host 态或因中断屏蔽卡在 Guest 态，该计数值将保持为 0 或显著偏低。"""
    if old_cnt_cmt in text:
        text = text.replace(old_cnt_cmt, new_cnt_cmt)

    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    print("hv.h cleaned successfully")

clean_and_translate_hv_h()
