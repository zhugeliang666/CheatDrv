import os
import glob
import re

# 专业系统内核/逆向术语对照表（按长到短排序，防止前缀误匹配）
TERM_DICT = [
    # 架构与异常
    ("general protection fault", "通用保护异常(#GP)"),
    ("page fault", "缺页异常(#PF)"),
    ("undefined opcode", "未定义操作码异常(#UD)"),
    ("breakpoint exception", "断点异常(#BP)"),
    ("monitor trap flag", "监控陷阱标志(MTF)"),
    ("virtual machine control structure", "虚拟机控制结构(VMCS)"),
    ("virtual machine execution control", "虚拟机执行控制字段"),
    ("secondary processor-based", "基于次要处理器的"),
    ("primary processor-based", "基于主要处理器的"),
    ("pin-based VM-execution controls", "基于引脚的 VM 执行控制"),
    ("VM-exit control fields", "VM-exit 退出控制字段"),
    ("VM-entry control fields", "VM-entry 进入控制字段"),
    ("VMCS link pointer", "VMCS 链接指针"),
    ("guest physical address", "Guest 物理地址(GPA)"),
    ("host physical address", "Host 物理地址(HPA)"),
    ("guest virtual address", "Guest 虚拟地址(GVA)"),
    ("host virtual address", "Host 虚拟地址(HVA)"),
    ("page frame number", "物理页帧号(PFN)"),
    ("page table entry", "页表项(PTE)"),
    ("page directory entry", "页目录项(PDE)"),
    ("page-directory-pointer-table", "页目录指针表(PDPT)"),
    ("pml4 table entry", "PML4 页表项(PML4E)"),
    ("nested page table", "嵌套页表(NPT)"),
    ("extended page table", "扩展页表(EPT)"),
    ("logical processor", "逻辑处理器"),
    ("time stamp counter", "时间戳计数器(TSC)"),
    ("interrupt service routine", "中断服务例程(ISR)"),
    ("non-maskable interrupt", "不可屏蔽中断(NMI)"),
    ("directory table base", "页目录基址(CR3)"),
    ("control register", "控制寄存器"),
    ("model specific register", "模式特定寄存器(MSR)"),
    ("system call", "系统调用"),
    ("system thread", "系统线程"),
    ("thread affinity", "线程亲和性"),
    ("non-paged pool", "非分页内存池"),
    ("paged pool", "分页内存池"),
    ("physical memory", "物理内存"),
    ("virtual memory", "虚拟内存"),
    ("spin lock", "自旋锁"),
    ("spinlock", "自旋锁"),
    ("identity map", "恒等映射"),
    ("identity mapping", "恒等映射"),
    ("single step", "单步执行"),
    ("single-step", "单步执行"),
    ("hardware breakpoint", "硬件断点"),
    ("software breakpoint", "软件断点"),
    ("read access", "读访问"),
    ("write access", "写访问"),
    ("execute access", "执行访问"),
    ("read-only", "只读"),
    ("read-write", "读写"),
    ("read/write", "读写"),
    ("shadow page", "影子页面"),
    ("fake page", "伪造影子页"),
    ("detour stub", "Detour 转向存根"),
    ("original bytes", "原始指令字节"),
    ("hypercall handler", "超调用分发处理例程"),
    ("hypercall key", "超调用身份鉴权密钥"),
    ("hypercall arguments", "超调用输入参数"),
    ("hypervisor signature", "虚拟机监控程序特征签名"),
    ("guest state", "Guest 客户机状态"),
    ("host state", "Host 宿主机状态"),
    ("guest registers", "Guest 寄存器"),
    ("host registers", "Host 寄存器"),
    ("guest rip", "Guest RIP 指针"),
    ("guest rsp", "Guest RSP 栈指针"),
    ("guest cr3", "Guest CR3 寄存器"),
    ("host cr3", "Host CR3 寄存器"),
    ("guest cr0", "Guest CR0 寄存器"),
    ("guest cr4", "Guest CR4 寄存器"),
    ("return status", "返回执行状态"),
    ("error status", "错误状态码"),
    ("success", "执行成功"),
    ("failed", "执行失败"),
    ("anti-cheat", "反作弊系统"),
    ("bootstrap driver", "引导驱动"),
    ("resident payload", "常驻 Payload"),
    ("memory pool", "内存池"),
    ("pool block", "内存池块"),
    ("symbol resolver", "符号解析器"),
    ("linear address", "线性地址"),
    ("crash dump", "崩溃转储"),
]

# 经典完整句子/短语映射（高频精确匹配）
SENTENCE_DICT = {
    "// arguments": "// 超调用输入参数",
    "// argument": "// 输入参数",
    "// return value": "// 返回值",
    "// return true on success, false on failure": "// 成功返回 true，失败返回 false",
    "// return true on success": "// 成功返回 true",
    "// return false on failure": "// 失败返回 false",
    "// return status": "// 返回执行状态",
    "// TODO: implement this": "// TODO: 待完善此功能实现",
    "// initialize the vcpu": "// 初始化当前 vCPU 上下文",
    "// virtualize the specified cpu": "// 虚拟化指定的 CPU 核心",
    "// virtualize the current processor": "// 虚拟化当前逻辑处理器",
    "// devirtualize the current processor": "// 去虚拟化当前逻辑处理器（退出虚拟化）",
    "// devirtualize the current vcpu": "// 去虚拟化当前 vCPU",
    "// launch the guest": "// 执行 VMLAUNCH 启动 Guest 虚拟机",
    "// execute guest until a VM-exit occurs": "// 运行 Guest 虚拟机直到发生 VM-exit 退出",
    "// advance guest rip": "// 步进 Guest RIP 跳过当前指令",
    "// advance guest rip past the instruction": "// 步进 Guest RIP 越过当前指令",
    "// skip instruction": "// 跳过当前指令",
    "// skip the instruction": "// 跳过当前指令",
    "// flush ept tlb": "// 刷新 EPT TLB 转换后援缓冲",
    "// flush the ept tlb": "// 刷新 EPT TLB 转换后援缓冲",
    "// invalidate ept": "// 执行 INVEPT 刷新 EPT 缓存",
    "// allocate memory": "// 分配物理/虚拟内存",
    "// free memory": "// 释放占用的内存",
    "// allocate non-paged pool": "// 申请非分页内存池",
    "// allocate non-paged pool memory": "// 申请非分页内存池空间",
    "// free allocated pool memory": "// 释放所分配的内存池空间",
    "// track allocated pool blocks": "// 记录并追踪内存池分配块的生命周期",
    "// acquire spin lock": "// 获取自旋锁",
    "// release spin lock": "// 释放自旋锁",
    "// acquire lock": "// 获取锁",
    "// release lock": "// 释放锁",
    "// write guest state": "// 配置 VMCS 中 Guest 状态字段",
    "// write host state": "// 配置 VMCS 中 Host 状态字段",
    "// write VM-execution control fields": "// 配置 VMCS 中虚拟机执行控制字段",
    "// write VM-exit control fields": "// 配置 VMCS 中虚拟机退出控制字段",
    "// write VM-entry control fields": "// 配置 VMCS 中虚拟机进入控制字段",
    "// write VMCS link pointer": "// 设置 VMCS 链接指针",
    "// pin-based VM-execution controls": "// 基于引脚的 VM 执行控制字段",
    "// primary processor-based VM-execution controls": "// 基于处理器的主要 VM 执行控制字段",
    "// secondary processor-based VM-execution controls": "// 基于处理器的次要 VM 执行控制字段",
    "// VM-exit controls": "// VM-exit 退出控制字段",
    "// VM-entry controls": "// VM-entry 进入控制字段",
    "// initialize host state": "// 初始化 Host 宿主机状态",
    "// initialize guest state": "// 初始化 Guest 客户机状态",
    "// allocate EPT PML4 table": "// 分配 EPT PML4 顶级页表",
    "// identity map the entire physical address space": "// 恒等映射整个物理地址空间",
    "// map a 2MB page": "// 映射 2MB 大页",
    "// map a 4KB page": "// 映射 4KB 物理小页",
    "// split a 2MB page into 4KB pages": "// 将 2MB 大页拆分为 512 个 4KB 小页",
    "// get the EPT pointer (EPTP)": "// 计算并获取 EPT 指针(EPTP)",
    "// update EPT memory type": "// 更新 EPT 物理内存缓存类型(MTRR)",
    "// invalidate EPT translations": "// 执行 INVEPT 刷新失效的 EPT 地址转换",
    "// start the hypervisor": "// 启动并初始化虚拟机监控程序框架",
    "// stop the hypervisor": "// 停止并完全退出虚拟机监控程序框架",
    "// broadcast to all logical processors": "// 向所有在线逻辑处理器广播执行",
    "// allocate resources": "// 分配核心全局资源",
    "// free resources": "// 释放分配的核心全局资源",
    "// initialize global state": "// 初始化全局共享状态",
    "// uninitialize global state": "// 销毁清理全局共享状态",
    "// check if hypervisor is running": "// 检测虚拟机监控程序是否正在运行",
    "// ping the hypervisor to make sure it is running": "// 发送超调用探测虚拟机监控程序以确认其正常运行",
    "// install vtcall hook": "// 安装基于 EPT 隐藏的 VTCall 内核挂钩",
    "// remove vtcall hook": "// 卸载指定的 VTCall 内核挂钩",
    "// install ept hook": "// 安装 EPT 隐藏页面执行挂钩",
    "// remove ept hook": "// 移除 EPT 隐藏挂钩并恢复原始映射",
    "// allocate fake page": "// 分配用于存放篡改指令的影子物理页",
    "// hook page table entry": "// 篡改 EPT 页表项以实现读写/执行物理页分离",
    "// read access gets orig_pfn": "// 读访问重定向至原始物理页 orig_pfn",
    "// execute access gets exec_pfn": "// 执行访问重定向至影子执行页 exec_pfn",
    "// install ept probe": "// 安装 EPT 硬件断点探针",
    "// remove ept probe": "// 移除指定的 EPT 探针",
    "// DriverEntry of bootstrap driver": "// Bootstrap 引导驱动程序入口点 DriverEntry",
    "// map payload into kernel space": "// 将常驻核心 Payload 映射至内核高地址空间",
    "// resolve kernel imports": "// 动态解析内核导出例程导入表",
    "// execute payload entrypoint": "// 执行常驻 Payload 的初始化入口点",
    "// clean up bootstrap headers": "// 擦除引导驱动的 PE 头部以隐藏痕迹",
    "// register unload routine": "// 注册驱动卸载清理回调例程",
}

def translate_comment_line(line):
    prefix = ""
    comment = ""
    # 匹配 // 或 ; 或 /* 开头的注释
    m = re.match(r'^(\s*(?://|;|/\*|\*)\s*)(.*)$', line)
    if not m:
        return line

    prefix = m.group(1)
    content = m.group(2).rstrip('*/').strip()

    if not content:
        return line

    # 如果已经包含中文，不重复翻译
    if re.search(r'[\u4e00-\u9fa5]', content):
        return line

    # 忽略纯代码注释（如 // int x = 0; 或 // #include）
    if re.match(r'^(?:#|return\s|auto\s|int\s|void\s|uint|if\s*\(|for\s*\(|while\s*\(|cpu->|ctx->|\w+\s*=|\w+\s*\()', content):
        return line

    # 精确匹配整句
    raw_comment = prefix.strip() + ' ' + content
    for k, v in SENTENCE_DICT.items():
        if k.lower() == raw_comment.lower():
            indent = line[:len(line) - len(line.lstrip())]
            return indent + v + '\n'

    # 基于术语字典进行自然替换
    translated = content
    for en, cn in TERM_DICT:
        # 使用单词边界替换
        pattern = re.compile(re.escape(en), re.IGNORECASE)
        translated = pattern.sub(cn, translated)

    # 简单动词模式翻译
    verb_maps = [
        (r'\binitialize\b', '初始化'),
        (r'\buninitialize\b', '清理销毁'),
        (r'\ballocate\b', '分配'),
        (r'\bdeallocate\b', '释放'),
        (r'\bfree\b', '释放'),
        (r'\benable\b', '启用'),
        (r'\bdisable\b', '禁用'),
        (r'\bupdate\b', '更新'),
        (r'\bcheck\b', '检查校验'),
        (r'\bvalidate\b', '验证'),
        (r'\bhandle\b', '处理'),
        (r'\bdispatch\b', '分发'),
        (r'\bflush\b', '刷新'),
        (r'\bclear\b', '清除'),
        (r'\bset\b', '设置'),
        (r'\bget\b', '获取'),
        (r'\bread\b', '读取'),
        (r'\bwrite\b', '写入'),
        (r'\brestore\b', '恢复'),
        (r'\bsave\b', '保存'),
        (r'\binstall\b', '安装'),
        (r'\bremove\b', '卸载移除'),
        (r'\bcreate\b', '创建'),
        (r'\bdestroy\b', '销毁'),
        (r'\bregister\b', '注册'),
        (r'\bunregister\b', '注销'),
        (r'\binject\b', '注入'),
        (r'\bemulate\b', '模拟执行'),
        (r'\bexecute\b', '执行'),
        (r'\bcurrent\b', '当前'),
        (r'\btarget\b', '目标'),
        (r'\bdefault\b', '默认'),
        (r'\bmaximum\b', '最大'),
        (r'\bminimum\b', '最小'),
        (r'\bentry\b', '条目项'),
        (r'\bbuffer\b', '缓冲区'),
        (r'\bstructure\b', '结构体'),
        (r'\btable\b', '表'),
        (r'\barray\b', '数组'),
        (r'\bfunction\b', '函数'),
        (r'\broutine\b', '例程'),
        (r'\bcontext\b', '上下文'),
        (r'\bpointer\b', '指针'),
        (r'\baddress\b', '地址'),
        (r'\boffset\b', '偏移'),
        (r'\bsize\b', '大小尺寸'),
        (r'\blength\b', '长度'),
        (r'\bcount\b', '数量计数'),
        (r'\bindex\b', '索引下标'),
        (r'\bflag\b', '标志位'),
        (r'\bflags\b', '标志位集合'),
        (r'\bmask\b', '掩码'),
        (r'\bvalue\b', '值'),
        (r'\bmode\b', '模式'),
        (r'\bstate\b', '状态'),
        (r'\bheader\b', '头部'),
    ]

    for pat, chn in verb_maps:
        translated = re.sub(pat, chn, translated, flags=re.IGNORECASE)

    # 如果翻译后产生了有意义的中文
    if re.search(r'[\u4e00-\u9fa5]', translated):
        indent = line[:len(line) - len(line.lstrip())]
        comment_symbol = '// ' if '//' in prefix else ('; ' if ';' in prefix else prefix)
        return indent + comment_symbol + translated + (' */\n' if '*/' in line else '\n')

    return line

def process_all_files():
    files = [
        p for p in glob.glob('vt/**/*', recursive=True)
        if os.path.isfile(p) and p.endswith(('.cpp', '.h', '.c', '.inl', '.asm'))
        and not any(x in p for x in ['business_backup', 'packages', 'bin', 'x64', 'build'])
    ]

    updated = 0
    for f in files:
        with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
            lines = fp.readlines()

        new_lines = []
        changed = False
        for line in lines:
            nl = translate_comment_line(line)
            if nl != line:
                changed = True
            new_lines.append(nl)

        if changed:
            with open(f, 'w', encoding='utf-8') as fp:
                fp.writelines(new_lines)
            updated += 1

    print(f"Total files updated: {updated}")

if __name__ == '__main__':
    process_all_files()
