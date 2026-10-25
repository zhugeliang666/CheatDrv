import re

path = 'vt/VtHypervisor/vt/exit-handlers.cpp'
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    text = f.read()

reps = [
    # CPUID
    (r'// CPUID 0x40000000-0x4FFFFFFF: hypervisor info leaves\.',
     r'// CPUID 0x40000000-0x4FFFFFFF：虚拟机监控程序信息叶子。\n'
     r'  // 模拟 Microsoft Hv (Hyper-V) 规范——现代反作弊系统对 Hyper-V 均有内置白名单，\n'
     r'  // 因为 Windows 11 在默认开启 VBS/HVCI/WSL2 时就是此环境。此处返回原生 GenuineIntel\n'
     r'  // 会是明显的伪造漏洞；返回全零则极度可疑；若返回自定义品牌特征则初次扫描就会被列入黑名单。\n'
     r'  // 采用 Hyper-V 签名可获得最强且最广泛的系统与反作弊兼容性。'),
    (r'// We impersonate Microsoft Hv[^\n]+\n(?:  //[^\n]+\n)*', r''),
    (r'// Hypervisor interface signature: "Hv#1"', r'// 虚拟机监控程序接口签名："Hv#1"'),
    (r'// Hypervisor system identity \(build/version\) [^\n]+', r'// 虚拟机监控程序系统标识（内部版本号/版本信息）——模拟合理合规的极简配置。'),
    (r'// Hypervisor feature identification [^\n]+', r'// 虚拟机监控程序功能标识——不通告任何高危特权功能。'),
    (r'// CPUID\(1\)\.ECX bit31 = hypervisor present flag[^\n]+\n(?:      //[^\n]+\n)*',
     r'// CPUID(1).ECX bit31 = 虚拟机监控程序存在标志位。透传真实状态（当前已处于 Hypervisor\n'
     r'      // 环境下，若将其强行清零将与上方通告的 0x40000000 "Hv" 签名产生冲突，触发反作弊的虚假欺骗检测启发式规则）。\n'),
    (r'// NOTE: IA32_DEBUGCTL is NOT trapped on read[^\n]+\n(?://[^\n]+\n)*',
     r'// 注意：IA32_DEBUGCTL 严禁拦截读取操作——Windows 内核（KiDebugRoutine BTF 位、上下文保存/恢复例程）\n'
     r'// 会高频主动读写该 MSR。若对读取进行虚假应答将导致内核调度与调试状态机彻底紊乱引发蓝屏。\n'
     r'// 下方的写入拦截仍会阻止 Guest 开启 LBR/BTS，且 VMCS 会在每次 VM-exit 时自动清零这些位。\n'),
    (r'// Perfmon MSR interception disabled[^\n]+\n(?://[^\n]+\n)*',
     r'// 性能监控(Perfmon) MSR 拦截已停用——该拦截若与 TSC 偏移混用会导致 DWM 黑屏闪烁。\n'
     r'// 若需安全重新启用，切勿清零 fake_perfmon_base_tsc。\n'),
    (r'// update EPT memory types', r'// 更新 EPT 内存缓存类型(MTRR 属性)'),
    (r'// inject a #GP\(0\) since SMX is disabled in the IA32_FEATURE_CONTROL MSR',
     r'// 因 IA32_FEATURE_CONTROL MSR 中禁用了 SMX，向 Guest 注入通用保护异常 #GP(0)'),
    (r'// TODO: properly implement INVD[^\n]+\n(?://[^\n]+\n)*',
     r'// TODO: 完善 INVD 指令模拟（可在执行 INVD 前构造微型存根刷新特定高速缓存行）\n'),
    (r'// only XCR0 is supported', r'// 当前仅支持 XCR0 扩展控制寄存器'),
    (r'// TODO: assert that it was a #GP\(0\) that occurred[^\n]+\n(?://[^\n]+\n)*',
     r'// TODO: 断言触发的是 #GP(0) 异常（依据 Intel 手册规范，此处不会触发其它类型异常）\n'),
    (r'// usually a #UD doesn\'t trigger a vm-exit, but in this case it is possible\n// that CR4\.VMXE is 1 while guest shadow CR4\.VMXE is 0\.',
     r'// 通常 #UD 不会触发 vm-exit，但在当前场景下真实 CR4.VMXE 可能为 1，而 Guest 影子 CR4.VMXE 为 0。'),
    (r'// order to convince the guest that VMX has been disabled by BIOS\.',
     r'// 旨在向 Guest 伪造证明 VMX 虚拟化技术已在 BIOS 层面被硬件级禁用。'),
    (r'// validate the hypercall key', r'// 校验超调用身份鉴权密钥（Hypercall Key）'),
    (r'// Resident payload freetest parity: do not allow gamevt-range bad-key\n// VMCALLs to bypass key validation and fall into legacy dispatch\.',
     r'// 常驻 Payload 兼容安全校验：严禁非法密钥的 VMCALL 绕过密钥核验渗透进旧版分发逻辑中。'),
    (r'// handle the hypercall', r'// 分发并处理经鉴权确认的超调用请求'),
    (r'// Host-managed EPT hook \(see vt/ept-hook\.cpp\)', r'// Host 根模式统一托管的 EPT 隐藏挂钩（参见 hooks/ept-hook.cpp）'),
    (r'// Host-managed VTCall hook \(see vt/vtcall-hook\.cpp\)', r'// Host 根模式统一托管的 VTCall 内核挂钩（参见 hooks/vtcall-hook.cpp）'),
    (r'// These are payload-owned after bridge handoff\. If they ever reach the\n// legacy handler, fail closed and skip instead of injecting #UD/#PF\.',
     r'// 桥接移交后这些功能归属于常驻 Payload。若其仍意外流向旧版处理例程，严格按默认安全策略阻断并跳过指令，避免注入 #UD/#PF 异常。'),
    (r'// the guest tried to modify CR0\.CD or CR0\.NW, which must be updated manually',
     r'// Guest 尝试修改 CR0.CD（高速缓存禁用）或 CR0.NW（非穿透写），需由 Host 态手动同步更新'),
    (r'// TODO: should we care about NW\?', r'// TODO: 评估是否需针对 CR0.NW 采取特殊处理'),
    (r'// make sure to account for VMX reserved bits when setting the real CR0',
     r'// 设置真实 CR0 寄存器时，必须严格处理 VMX 架构保留位约束'),
    (r'// invalidate TLB entries if required', r'// 若有必要，执行指令刷新相关 TLB 转换表项'),
    (r'// make sure to account for VMX reserved bits when setting the real CR4',
     r'// 设置真实 CR4 寄存器时，必须严格处理 VMX 架构保留位约束'),
    (r'// clear CR0\.TS in the read shadow', r'// 在 CR0 读取影子中清除任务切换标志位(CR0.TS)'),
    (r'// clear CR0\.TS in the real CR0 register', r'// 在真实 CR0 控制寄存器中清除任务切换标志位(CR0.TS)'),
    (r'// update the guest CR0 read shadow', r'// 同步更新 Guest 视角的 CR0 读取影子寄存器'),
    (r'// update the real guest CR0\.', r'// 同步更新底层真实的 Guest CR0 寄存器'),
    (r'// reserved bit\) can\'t be cleared to 0 by the LMSW instruction while in\n// protected mode\.',
     r'// 保护模式下，LMSW 指令禁止将保留控制位清零。'),
    (r'// MOV CRn, XXX', r'// MOV CRn, 寄存器操作指令'),
    (r'// MOV XXX, CRn', r'// MOV 寄存器, CRn 操作指令'),
    (r'// TODO: assert that we\'re accessing CR3 \(and not CR8\)', r'// TODO: 断言当前访问的是 CR3 控制寄存器（而非 CR8）'),
    (r'// CLTS', r'// 清任务切换标志指令 CLTS'),
    (r'// LMSW XXX', r'// 加载机器状态字指令 LMSW'),
    (r'// inject the NMI into the guest', r'// 向 Guest 注入不可屏蔽中断(NMI)'),
    (r'// enqueue an NMI to be injected into the guest later on', r'// 将 NMI 中断压入等待队列，在后续安全时机向 Guest 注入'),
    (r'// DIAG: count all #BP vmexits and record last RIP\.', r'// 诊断度量：统计所有 #BP 导致的 VM-exit 频次并记录最后触发的 RIP'),
    (r'// the 0xCC byte \(not past it\)\. slot\.bp_rip is precomputed to that\n// exact address; on match we rewrite RIP to slot\'s target_resume so\n// the guest continues right after the hooked instruction in the real\n// function \(NOT in our exec_page\)\.',
     r'// 0xCC 断点字节。slot.bp_rip 预先计算为该精准地址；匹配成功后，我们将 Guest RIP\n// 重写恢复为 slot 的 target_resume，使 Guest 在真实函数内紧接被挂钩指令之后无缝继续执行\n// （而非停留在我们创建的 exec_page 影子页中）。'),
    (r'// Lock-free read: pool slots only mutate during install/remove,\n// and bp_rip is unique per occupied slot\. Worst case is missing',
     r'// 无锁安全读取：跳板池槽位仅在安装/移除钩子期间发生变动，\n// 且每个已占用的槽位具备全局唯一的 bp_rip。最坏情况下仅发生瞬时未命中'),
    (r'// INT3 vmexit: GUEST_RIP points past the 0xCC byte\. If this is hv::Call\'s\n// blank_memory landing site, return_old_func consumes the trap and exits\.',
     r'// INT3 触发的 VM-exit：GUEST_RIP 指向 0xCC 断点之后。若命中 hv::Call 的\n// 空白内存落地桩，由 return_old_func 接管异常并安全退出。'),
    (r'// Generic EPT probe: shadow exec page contains a one-byte INT3 at\n// the requested address\.  On hit we snapshot registers, map the\n// original PFN for exactly one instruction via MTF, then restore the\n// shadow page\.  This path is independent from hv::Call/tramp slots\.',
     r'// 通用 EPT 探针：影子执行页在目标探测地址处内嵌单字节 INT3(0xCC)。\n// 命中时捕获寄存器快照，借助监控陷阱标志(MTF)单步映射原始物理页 PFN 执行一条指令，\n// 随后自动恢复影子页映射。该路径与 hv::Call/跳板槽位完全解耦独立。'),
    (r'// Otherwise legit guest #BP \(debugger / __debugbreak / ntdll assert\) -\n// CRITICAL: Intel SDM Vol3A 24\.8\.3 [^\n]+\n// interruption_type MUST be software_exception \(6\), NOT the\n// hardware_exception \(3\) that the vmexit info field reports\. Using the\n// wrong type causes guest IDT delivery to corrupt and DWM hangs\.',
     r'// 其它情况为 Guest 自身的合法 #BP 异常（如调试器、__debugbreak 或 ntdll 断言）：\n// 致命关键点（Intel SDM Vol3A 24.8.3）：重新向 Guest 注入 INT3 时，\n// interruption_type 必须强制指定为软件异常 software_exception (6)，绝对不能使用\n// vmexit info 字段原始上报的 hardware_exception (3)！使用错误类型会导致 Guest IDT\n// 异常分发链状态崩溃，进而引发 DWM 界面死锁挂起。'),
    (r'// inject #UD for every VMX instruction since we\n// don\'t allow the guest to ever enter VMX operation\.',
     r'// 对所有 VMX 虚拟化指令直接注入 #UD 无效指令异常，\n// 严禁 Guest 进入任何嵌套 VMX 虚拟化执行模式。'),
    (r'// guest physical address that caused the ept-violation', r'// 触发 EPT 违例异常的 Guest 物理地址(GPA)'),
    (r'// Debug EPT permission watches are intentionally separate from legacy\n// ept_hook\.  Handle them before find_ept_hook\(\), otherwise watched pages\n// would look like "hook miss" and get injected as #GP\.',
     r'// 调试用的 EPT 权限监视体系与旧版 ept_hook 架构解耦隔离。\n// 必须先于 find_ept_hook() 拦截处理，否则被监视的页面将被误判为“钩子未命中”从而被注入 #GP 崩溃。'),
    (r'// PMO match check: did the violation fire on the page we hooked for PMO\?',
     r'// PMO 命中校验：判断当前 EPT 违例是否发生在专为 PMO 挂接的物理页上'),
    (r'// Read/write access on a hook page\. Default policy: point to[^\n]+\n(?://[^\n]+\n)*',
     r'// 钩子所在页面的读/写违例访问。默认安全策略：将 EPT 重定向至 orig_pfn（原始真实物理页），\n// 使 Guest 读取到未被篡改的真实代码字节（天然免疫反作弊内存校验与哈希比对）。\n// 特例情况：若 guest_rip 正处于当前被访问页内，说明正在执行的代码属于我们的跳板例程\n// （例如访问同页内的局部数据或栈），此时通过 MTF 赋予 exec_pfn 单步可读+可写+可执行权限，\n// 单步执行完毕后立即切回仅执行权限，满足跳板执行与反作弊隐藏的完美双重兼顾。\n'),
    (r'// restore MMR mode', r'// 恢复内存监控(MMR)模式状态'),
    (r'// write access but no read access will generate an EPT misconfiguration',
     r'// EPT 架构规范：仅有写权限而无读权限的页表配置属于非法状态，会引发 EPT Misconfiguration 虚拟机崩溃'),
    (r'// return current TSC', r'// 返回当前时间戳计数器(TSC)计数值'),
]

for pat, rep in reps:
    text = re.sub(pat, rep, text)

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print("exit-handlers.cpp done")
