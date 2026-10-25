import os
import glob
import re

def replace_in_file(path, replacements):
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    orig = content
    for pattern, repl in replacements:
        if isinstance(pattern, str):
            content = content.replace(pattern, repl)
        else:
            content = pattern.sub(repl, content)

    if content != orig:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated: {path}")

def process_amd():
    reps_svm_exit = [
        ("""// Anti-detect posture for AMD: present bare-metal AMD instead of exposing
// our nested SVM state.  Hypervisor leaves are zero and SVM CPUID leaves
// are masked even though SVME remains set in the host VMCB.""",
         """// AMD 反检测安全策略：呈现物理裸机 AMD CPU 状态，严密隐匿嵌套 SVM 虚拟化状态。
// 虚拟机监控程序叶子全部返回零，SVM CPUID 特性叶子全部执行位掩码屏蔽
// （即便 Host 端物理 VMCB 中仍然开启了 SVME 使能位）。"""),
        ("""// Match the Intel backend posture: guest reads see the VMCB value, but
// writes cannot enable LBR/BTS/BTF.  BTF in particular breaks the
// RFLAGS.TF based NPT hook restore path on AMD.""",
         """// 对齐 Intel 后端安全防护策略：Guest 读取时返回 VMCB 原始值，但写入操作
// 严禁启用 LBR/BTS/BTF 特性。尤其是 BTF 会破坏 AMD 上基于 RFLAGS.TF 单步陷阱的 NPT 钩子恢复路径。"""),
        ("// Keep host SVM/SEV-related state immutable and guest-inert.",
         "// 保持 Host 宿主机 SVM/SEV 相关状态不可篡改，且对 Guest 表现为完全惰性。"),
        ("// EXITINFO1: 0 = RDMSR, 1 = WRMSR (same convention used by DBVM).",
         "// EXITINFO1：0 = RDMSR（读 MSR），1 = WRMSR（写 MSR），遵循与 DBVM 相同的架构约定。"),
        ("""// AMD must execute VMMCALL (0F 01 D9).  Intel's VTCall fake page uses
// VMCALL (0F 01 C1), which #UDs on AMD before our VMMCALL intercept.""",
         """// AMD 平台必须执行 VMMCALL (0F 01 D9)。Intel 的 VTCall 伪造影子页使用的是
// VMCALL (0F 01 C1)，在 AMD 硬件下会在触发 VMMCALL 拦截前直接抛出 #UD 未定义指令异常。"""),
        ("""// The AMD backend does not yet call the VMX-specific game handler
// table.  Avoid an infinite VMMCALL loop by falling back to the
// original-instruction trampoline when one exists.""",
         """// AMD 后端不直接调用 VMX 专有的游戏分发处理表。
// 若存在原指令跳板例程，则优雅回退至原始跳板执行，避免陷入 VMMCALL 死循环。"""),
        ("""// Only undo the TF bit we borrowed.  Restoring the whole saved RFLAGS would
// discard flag results produced by the one instruction that just executed on
// the temporary NPT view.""",
         """// 仅清除我们临时借用的 TF 单步标志位。若直接粗暴恢复保存的整个 RFLAGS，
// 会导致刚刚在临时 NPT 视图上执行完毕的那条指令产生的算术标志结果被错误覆盖丢弃。"""),
        ("""// Optimized DBVM-style AMD cloak path:
// while VMCB.N_CR3 points at exec_view, only the active cloaked 4KB page is
// executable.  Any execute fault outside that page means the guest is
// leaving the active page.  Switch back to the normal read/write NPT root
// and let the same instruction be retried there.""",
         """// 优化的 DBVM 风格 AMD 隐匿执行路径：
// 当 VMCB.N_CR3 指向执行视图(exec_view)时，仅有当前处于活动状态的隐匿 4KB 页面具备可执行权限。
// 任何发生在该页面之外的执行违例均意味着 Guest 控制流正在离开当前活动页。
// 此时自动切回常规读写 NPT 根页表，使相同指令在原页表上下文中重新执行。"""),
        ("// AMD NPT has no independent read permission. Temporarily grant execute",
         "// AMD NPT 规范中无独立的读权限控制位，此处临时赋予执行权限以满足单步需要"),
        ("""// Match the VMX hc::unload contract used by hv::stop(): acknowledge
// this exact vCPU while g_ghv and the vCPU array are still valid in
// Host context.  Without this bit AMD teardown returned to Guest but""",
         """// 对齐 hv::stop() 中调用的 VMX hc::unload 契约协议：在 Host 上下文中 g_ghv
// 与 vCPU 数组依然有效时，对当前该特定 vCPU 完成状态确认与注销。"""),
        ("""// AMD keeps the verified legacy VMRUN loop instead of transferring
// HOST_RIP to the resident payload bridge.  These payload-owned calls
// therefore have no valid legacy implementation.  Match the VMX legacy
// contract: fail closed, consume VMMCALL, and let callers fall back
// instead of injecting #UD into a manually mapped kernel image.""",
         """// AMD 端保持稳定验证过的原生 VMRUN 循环，而非将 HOST_RIP 控制权直接移交至常驻 Payload 桥接。
// 因此这些属于 Payload 托管的超调用在旧版实现中无直接处理逻辑。
// 此处严格对齐 VMX 旧版契约：默认闭环处理、正常消费 VMMCALL 并使调用者安全回退，
// 坚决防止在手动映射的手写内核镜像中错误注入 #UD 异常引发系统崩溃。"""),
        ("""// SVM is hidden from the guest, so executing SVM-only instructions
// should look like bare-metal with SVM unavailable.""",
         """// SVM 虚拟化对 Guest 客户机保持完全隐匿，因此执行 SVM 专有指令时
// 其表现必须与未开启 SVM 的物理裸机硬件完全一致。"""),
        ("""// AMD has no MTF. If a hooked page's one-instruction window exits for an
// intercepted instruction (CPUID/MSR/VMMCALL/etc.) instead of #DB, the
// instruction was emulated here, so close the window before re-entering.""",
         """// AMD 架构缺少硬件级 MTF（监控陷阱标志）。若挂钩页面的单指令执行窗口因拦截指令
// （如 CPUID/MSR/VMMCALL 等）触发退出而非触发 #DB 单步异常，说明该指令已由当前例程模拟完成，
// 必须在重新进入 Guest 前主动关闭单步执行窗口。""")
    ]
    replace_in_file('vt/VtHypervisor/amd/svm-exit.cpp', reps_svm_exit)

    reps_svm = [
        ("// initialize svm for the current processor", "// 为当前逻辑处理器初始化 AMD SVM 虚拟化引擎"),
        ("// check svm support", "// 检测 CPU 是否具备 AMD SVM 硬件虚拟化支持"),
        ("// enable svm in msr", "// 在 EFER MSR 寄存器中置位使能 SVM 特性"),
        ("// allocate vmcb", "// 为当前核心分配物理连续的 VMCB 控制块"),
        ("// initialize vmcb", "// 初始化 VMCB 控制块字段与 Host/Guest 执行状态"),
        ("// enter guest mode via vmrun", "// 执行 VMRUN 指令切入 Guest 客户机模式"),
    ]
    replace_in_file('vt/VtHypervisor/amd/svm.cpp', reps_svm)

    reps_npt = [
        ("// allocate nested page tables (NPT)", "// 分配 AMD 嵌套页表(NPT)根目录"),
        ("// build 1:1 identity map for NPT", "// 构建 NPT 的 1:1 全物理内存恒等映射"),
        ("// split 2MB page in NPT", "// 在 NPT 中将 2MB 大页拆分为 4KB 小页"),
    ]
    replace_in_file('vt/VtHypervisor/amd/npt.cpp', reps_npt)

def process_hooks():
    reps_vtcall = [
        ("// install vtcall hook", "// 安装基于 EPT 隐藏的 VTCall 内核挂钩"),
        ("// remove vtcall hook", "// 卸载指定的 VTCall 内核挂钩"),
        ("// allocate trampoline slot", "// 在跳板池中申请空闲槽位"),
        ("// free trampoline slot", "// 释放跳板池中的槽位资源"),
        ("// copy original bytes", "// 保存原函数被覆盖的机器码字节序列"),
        ("// build detour stub", "// 构造跳转至影子页的 Detour 转向存根"),
        ("// find target function address", "// 解析目标内核导出函数的虚拟地址"),
    ]
    replace_in_file('vt/VtResidentPayload/hooks/vtcall-hook.cpp', reps_vtcall)

    reps_epthook = [
        ("// install ept hook", "// 安装 EPT 隐藏页面执行挂钩"),
        ("// remove ept hook", "// 移除 EPT 隐藏挂钩并恢复原始映射"),
        ("// allocate fake page", "// 分配用于存放篡改指令的影子物理页"),
        ("// hook page table entry", "// 篡改 EPT 页表项以实现读写/执行物理页分离"),
        ("// read access gets orig_pfn", "// 读访问重定向至原始物理页 orig_pfn"),
        ("// execute access gets exec_pfn", "// 执行访问重定向至影子执行页 exec_pfn"),
    ]
    replace_in_file('vt/VtResidentPayload/hooks/ept-hook.cpp', reps_epthook)

    reps_eptprobe = [
        ("// install ept probe", "// 安装 EPT 硬件断点探针"),
        ("// remove ept probe", "// 移除指定的 EPT 探针"),
        ("// trigger on single step", "// 在 MTF 单步完成后恢复断点页面"),
    ]
    replace_in_file('vt/VtResidentPayload/hooks/ept-probe.cpp', reps_eptprobe)

def process_bootstrap_and_common():
    reps_boot_main = [
        ("// DriverEntry of bootstrap driver", "// Bootstrap 引导驱动程序入口点 DriverEntry"),
        ("// map payload into kernel space", "// 将常驻核心 Payload 映射至内核高地址空间"),
        ("// resolve kernel imports", "// 动态解析内核导出例程导入表"),
        ("// execute payload entrypoint", "// 执行常驻 Payload 的初始化入口点"),
        ("// clean up bootstrap headers", "// 擦除引导驱动的 PE 头部以隐藏痕迹"),
        ("// register unload routine", "// 注册驱动卸载清理回调例程"),
    ]
    replace_in_file('vt/VtBootstrapDriver/main.cpp', reps_boot_main)

    reps_pool = [
        ("// allocate non-paged pool memory", "// 申请连续的非分页内存池空间"),
        ("// free allocated pool memory", "// 释放所分配的内存池空间"),
        ("// track allocated pool blocks", "// 记录并追踪内存池分配块的生命周期"),
    ]
    replace_in_file('vt/VtHypervisor/poolmanager/PoolManager.cpp', reps_pool)
    replace_in_file('vt/VtBootstrapDriver/poolmanager/PoolManager.cpp', reps_pool)

def batch_translate_general():
    files = [
        p for p in glob.glob('vt/**/*', recursive=True)
        if os.path.isfile(p) and p.endswith(('.cpp', '.h', '.c', '.inl', '.asm'))
        and not any(x in p for x in ['business_backup', 'packages', 'bin', 'x64', 'build'])
    ]

    # 通用常见英文注释短语库（按长度降序排，避免短词局部冲突）
    common_terms = [
        (r'//\s*virtual machine control structure', r'// 虚拟机控制结构(VMCS)'),
        (r'//\s*execute guest until a VM-exit occurs', r'// 执行 Guest 虚拟机直至触发 VM-exit'),
        (r'//\s*advance guest rip past the instruction', r'// 步进 Guest RIP 跳过当前指令'),
        (r'//\s*inject general protection fault', r'// 向 Guest 注入通用保护异常(#GP)'),
        (r'//\s*inject page fault', r'// 向 Guest 注入缺页异常(#PF)'),
        (r'//\s*read guest register', r'// 读取 Guest 寄存器'),
        (r'//\s*write guest register', r'// 写入 Guest 寄存器'),
        (r'//\s*restore host state', r'// 恢复 Host 宿主机寄存器上下文'),
        (r'//\s*save guest state', r'// 保存 Guest 客户机寄存器上下文'),
        (r'//\s*guest physical address', r'// Guest 物理地址(GPA)'),
        (r'//\s*host physical address', r'// Host 物理地址(HPA)'),
        (r'//\s*guest virtual address', r'// Guest 虚拟地址(GVA)'),
        (r'//\s*host virtual address', r'// Host 虚拟地址(HVA)'),
        (r'//\s*page table entry', r'// 页表项(PTE)'),
        (r'//\s*page directory entry', r'// 页目录项(PDE)'),
        (r'//\s*page-directory-pointer-table entry', r'// 页目录指针表项(PDPTE)'),
        (r'//\s*pml4 table entry', r'// PML4 顶级页表项(PML4E)'),
        (r'//\s*flush ept tlb', r'// 刷新 EPT TLB 转换后援缓冲'),
        (r'//\s*invalidate tlb', r'// 刷新 TLB 缓存'),
        (r'//\s*spin lock', r'// 自旋锁'),
        (r'//\s*acquire spin lock', r'// 获取自旋锁'),
        (r'//\s*release spin lock', r'// 释放自旋锁'),
        (r'//\s*allocate memory', r'// 分配物理/虚拟内存'),
        (r'//\s*free memory', r'// 释放所占用的内存'),
        (r'//\s*check if hypervisor is running', r'// 检测虚拟机监控程序是否正在运行'),
        (r'//\s*hypercall arguments', r'// 超调用输入参数'),
        (r'//\s*hypercall handler', r'// 超调用核心分发处理例程'),
        (r'//\s*hypervisor signature', r'// 虚拟机监控程序特征签名'),
        (r'//\s*single step', r'// 硬件单步执行'),
        (r'//\s*breakpoint', r'// 断点拦截'),
        (r'//\s*shadow page', r'// 影子页面'),
        (r'//\s*trampoline', r'// 执行跳板'),
        (r'//\s*return status', r'// 返回执行状态码'),
        (r'//\s*success', r'// 执行成功'),
        (r'//\s*failed', r'// 执行失败'),
        (r'//\s*read access', r'// 读访问权限'),
        (r'//\s*write access', r'// 写访问权限'),
        (r'//\s*execute access', r'// 执行访问权限'),
        (r'//\s*read-only', r'// 只读'),
        (r'//\s*read-write', r'// 读写'),
        (r'//\s*read-execute', r'// 读执行'),
    ]

    for f in files:
        with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
            text = fp.read()
        orig = text
        for pat, rep in common_terms:
            text = re.sub(pat, rep, text, flags=re.IGNORECASE)
        if text != orig:
            with open(f, 'w', encoding='utf-8') as fp:
                fp.write(text)

if __name__ == '__main__':
    process_amd()
    process_hooks()
    process_bootstrap_and_common()
    batch_translate_general()
    print("All translation stages completed.")
