import re

path = 'vt/VtBootstrapDriver/main.cpp'
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    text = f.read()

reps = [
    ("""// DriverMain has a large fixed frame and payload mapping has another
// 0x2B70-byte frame.  Never run that chain on the already-consumed loader
// stack; failure to obtain an expanded stack is a hard load failure.""",
     """// DriverMain 具有较大的固定栈帧，且 Payload 映射例程还需要 0x2B70 字节的大栈帧。
// 严禁在已被加载器消耗过半的调用栈上执行该调用链；若申请扩展内核栈失败，直接作为严重加载错误返回。"""),

    ("""// Do not call TestDriver.DriverUnload during resident handoff.  The
// UCXXRT wrapper runs CRT uninitializers on return; calling it again
// handoff we only detach mapDriver ownership and quarantine the mapped
// image; full unload will call DriverUnload exactly once after clearing
// KEEP_HV_ON_UNLOAD.""",
     """// 常驻移交(Resident Handoff)期间严禁调用 TestDriver 的 DriverUnload。
// UCXXRT 封装在返回时会执行 CRT 析构例程，重复调用会导致未定义行为。在常驻移交期间，
// 我们仅解除 mapDriver 的宿主所有权并隔离已映射的驱动镜像；
// 只有在清除 KEEP_HV_ON_UNLOAD 标志后的完全卸载时，才执行仅有的一次 DriverUnload 调用。"""),

    ("""// Reuse the existing printed self_stop line as the compact stop bitmap
// view for both TestDriver::hv::stop() and payload self-stop.""",
     """// 复用既有的 self_stop 打印行，作为 TestDriver::hv::stop() 与 Payload 自停止流程统一的紧凑停止位图视图。"""),

    ("""// Keep the payload VM-exit bridge active until hv::stop() devirtualizes
// every CPU. The bridge pass-throughs hypercall_unload to the original
// TestDriver handler, then its asm epilogue performs VMXOFF/IRET. Restoring
// are delivered to the old handler.""",
     """// 保持 Payload 的 VM-exit 桥接处于活动状态，直到 hv::stop() 完全完成所有 CPU 核心的去虚拟化。
// 桥接例程将 hypercall_unload 透传给原始 TestDriver 处理程序，其汇编尾声负责执行 VMXOFF 并 IRET 返回。
// 确保所有退出事件均安全送达旧版处理程序。"""),

    ("""// Always quarantine first. If hv::stop() fails closed, the TestDriver
// image must remain mapped because some vCPU may still have HOST_RIP /
// are delivered to the old handler.""",
     """// 始终优先执行隔离。若 hv::stop() 按安全策略阻断失败，TestDriver 镜像必须继续保持内存映射，
// 因为部分 vCPU 可能仍保留着指向该镜像的 HOST_RIP 上下文引用。"""),

    ("""// AMD SVM resumes #VMEXIT after VMRUN in the fixed assembly loop and
// has no VMCS HOST_RIP field. Do not treat an absent HOST_RIP as a
// transient condition, and never enter the Intel migration path.""",
     """// AMD SVM 架构在固定的汇编循环中于 VMRUN 指令之后恢复 #VMEXIT 执行，
// 且不存在类似 Intel VMCS 的 HOST_RIP 硬件字段。切勿将缺少 HOST_RIP 视为瞬态异常，
// 且严禁在 AMD 平台下进入 Intel 的迁移路径。"""),

    ("""// Both backends use the same payload-side hook policy.  Intel continues
// into HOST_RIP/HOST_RSP migration; AMD keeps the fixed VMRUN loop and only
// consumes the payload configuration through the resident control plane.""",
     """// 两个硬件后端均遵循相同的 Payload 端挂钩策略。Intel 架构继续进入 HOST_RIP/HOST_RSP 迁移流程；
// AMD 架构则保持固定的 VMRUN 汇编循环，仅通过常驻控制平面同步消费 Payload 的配置项。"""),

    ("""// DriverEntry is required to arrive at PASSIVE_LEVEL.  Do not fall back to
// the caller's small kernel stack if expansion is unavailable.""",
     """// 要求 DriverEntry 必须在 PASSIVE_LEVEL 中断请求级别到达。若扩展栈不可用，
// 严禁回退至调用方极小的默认内核栈中盲目执行。"""),

    ("""// Keep the complete implementation on an expanded kernel stack so later
// cleanup/logging cannot inherit an already exhausted loader stack.""",
     """// 将完整的实现执行保持在扩展内核栈上，防止后续的清理与日志输出例程继承已耗尽的加载器调用栈。"""),

    ("""// Pure IOCTL smoke test: do not query payload status, do not issue
// are delivered to the old handler.""",
     """// 纯粹的 IOCTL 冒烟测试：不查询 Payload 状态，亦不下发实际控制指令。"""),

    ("""// Before releasing the manually mapped TestDriver image, run its WDM
// DriverUnload wrapper exactly once while KEEP_HV_ON_UNLOAD is forced.
// The user's Driver_Unload returns early, so resident VT keeps running,
// but the MSVC/UCXXRT wrapper still tears down CRT globals such as the
// kernel's periodic ExpScanGeneralLookasideList later walks a stale list""",
     """// 在释放手动映射的 TestDriver 驱动镜像前，在强制开启 KEEP_HV_ON_UNLOAD 的前提下
// 执行其 WDM DriverUnload 封装仅一次。用户的 Driver_Unload 会提前返回从而保持常驻 VT 继续运行，
// 但 MSVC/UCXXRT 封装仍会正确拆除 CRT 全局对象（例如快表链表等），
// 避免 Windows 内核的 ExpScanGeneralLookasideList 后续扫描到悬垂链表节点导致崩溃。"""),

    ("""// Preserve the original pre-payload HOST_RSP across repeated switch
// attempts.  If switchrsp is executed a second time, old_rsp may be the
// payload stack (or a transient vtcall stack), and overwriting it would""",
     """// 在多次重复尝试切换时，完好保留切换前的原始 HOST_RSP。
// 若 switchrsp 被二次执行，old_rsp 可能已被赋予 Payload 栈或瞬态 vtcall 栈，
// 此时若错误覆盖将导致无法正确回退。"""),
]

for pat, rep in reps:
    text = text.replace(pat, rep)

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print("VtBootstrapDriver/main.cpp customized replacements done")
