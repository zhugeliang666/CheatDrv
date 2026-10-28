#pragma once

// ============================================================================
// 文件名称: vt_config.h
// 核心职责: 全 VT 虚拟化框架唯一流程控制与架构策略中央配置中心
// 适用模块: VtBootstrapDriver / VtResidentPayload / VtHypervisor
// 架构契约: 纯宏与常量定义，零 C/C++ 运行时依赖，支持编译期前置覆盖
// ============================================================================

// ----------------------------------------------------------------------------
// 【模块 1】虚拟化引导与自动化加载流程 (Bootstrap & Auto-Load)
// ----------------------------------------------------------------------------

// 调试重载模式：
// 1 = 保留控制面，同时执行 Payload/Machenike 隐藏与 .text 双视图，允许反复
//     FullUnload/Reload；0 = 生产路径，执行隐藏与 Resident 迁移并收敛控制面。
// 该宏必须由 Loader、Bootstrap、Hypervisor 与 ResidentPayload 使用同一值。
#ifndef VT_DEBUG_RELOAD_MODE
#define VT_DEBUG_RELOAD_MODE 1
#endif

// 一键自动化全流程加载总开关：
// 驱动加载时按序自动完成旧映像启动、常驻载荷注入、栈切换、桥接切换、AMD/Intel
// 运行态交接、旧映像释放以及控制设备收敛全闭环。
#ifndef VT_BOOT_AUTO_ONEKEY_LOAD
#define VT_BOOT_AUTO_ONEKEY_LOAD 1
#endif

// 载荷交付后自动移交策略：
// 常驻载荷启动成功后，是否由 Bootstrap 立即主动移交并放弃后续流程。
#ifndef VT_BOOT_AUTO_HANDOFF_AFTER_PAYLOAD
#define VT_BOOT_AUTO_HANDOFF_AFTER_PAYLOAD 0
#endif

// 保留控制设备通信端点：
// 控制设备生命周期属于部署策略，默认保留以支持后续状态查询、内存审计与受控卸载。
#ifndef VT_BOOT_KEEP_CONTROL_DEVICE
#define VT_BOOT_KEEP_CONTROL_DEVICE 1
#endif

// 丢弃控制设备端点：
// 在一键加载完成且完成免控制设备密封时，丢弃控制通信设备。
#ifndef VT_BOOT_DROP_CONTROL_DEVICE
#define VT_BOOT_DROP_CONTROL_DEVICE 0
#endif

// 等待 PMO 绘制就绪门禁：
// 卸载或交割前是否强制轮询等待 PMO 绘制稳定。
#ifndef VT_BOOT_WAIT_PMO_READY
#define VT_BOOT_WAIT_PMO_READY 0
#endif

// 内核执行栈调度模式：
// 一键流程默认在当前内核扩展栈上同步执行（0）；仅在必要时才启用独立系统工作线程（1）。
#ifndef VT_BOOT_USE_THREAD
#define VT_BOOT_USE_THREAD 0
#endif

// 扩展内核栈尺寸（默认 64 KB）：
#ifndef VT_BOOT_EXPAND_STACK_SIZE
#define VT_BOOT_EXPAND_STACK_SIZE 0x10000ull
#endif

// 一键加载前置初始延迟（毫秒）：
// 固定延迟默认为 0；实际准入条件由载荷屏障与交接后的状态机检查提供。
#ifndef VT_BOOT_INITIAL_DELAY_MS
#define VT_BOOT_INITIAL_DELAY_MS 0
#endif

// 防重入加载门禁：
// 若检测到系统中已存在活动的 Hypervisor，必须先完成停止，严禁残留状态伪装成新加载成功。
#ifndef VT_BOOT_FAIL_IF_ALREADY_READY
#define VT_BOOT_FAIL_IF_ALREADY_READY 1
#endif

// AMD resident VMRUN 迁移后的旧 Hypervisor 映像释放策略：
// 0 = 保留已隔离映像；
// 1 = 完整 ACK、引用扫描与 RELEASE finalizer 通过后自动释放。
#ifndef VT_AMD_RELEASE_LEGACY_IMAGE_AFTER_HANDOFF
#define VT_AMD_RELEASE_LEGACY_IMAGE_AFTER_HANDOFF 1
#endif

// Resident 迁移准出门禁：旧 Hypervisor 映像必须在 Payload 接管并完成
// 引用扫描后才允许释放；关闭只适合保留旧映像的离线二分调试。
#ifndef VT_REQUIRE_PAYLOAD_HV_MIGRATION
#define VT_REQUIRE_PAYLOAD_HV_MIGRATION 1
#endif

// 卸载重试次数与间隔（毫秒）：
#ifndef VT_BOOT_UNLOAD_RETRY_COUNT
#define VT_BOOT_UNLOAD_RETRY_COUNT 30
#endif
#ifndef VT_BOOT_UNLOAD_RETRY_DELAY_MS
#define VT_BOOT_UNLOAD_RETRY_DELAY_MS 100
#endif

// ----------------------------------------------------------------------------
// 【模块 2】常驻载荷与 VM-Exit 桥接接管流程 (Resident Payload & Bridge)
// ----------------------------------------------------------------------------

// 桥接器自身物理页与页表自映射：
// 启用常驻载荷自身虚拟空间与物理页面在 Host CR3/状态机下的直接私有映射。
#ifndef VT_BRIDGE_SELF_MAP_ENABLED
#define VT_BRIDGE_SELF_MAP_ENABLED 1
#endif

// MOV CR 控制寄存器退出拦截使能：
// 接管 Guest MOV CR3/CR0/CR4 退出指令，由桥接器分发器执行影子寄存器同步与页表追踪。
#ifndef VT_MOV_CR_HANDLER_ENABLED
#define VT_MOV_CR_HANDLER_ENABLED 1
#endif

// 全量接管 Direct Trampoline 槽位：
// 一次性声明并接管所有 Direct Trampoline 执行槽位。
#ifndef VT_DIRECT_SLOT_CLAIM_ALL
#define VT_DIRECT_SLOT_CLAIM_ALL 1
#endif

// 载荷工作线程自启动控制：
// 常驻载荷内部后台 Worker 线程自启动开关（0 为被动分发或通过控制端口调度）。
#ifndef VT_WORKER_AUTOSTART
#define VT_WORKER_AUTOSTART 0
#endif

// 常驻控制端口端点使能：
#ifndef VT_RESIDENT_CTL_ENABLED
#define VT_RESIDENT_CTL_ENABLED 0
#endif

// 延迟 EPT 挂起模式策略：
// 采用挂起状态机保证多核并发修改 EPT 时的内存一致性与安全刷新。
#ifndef VT_DEFERRED_EPT_USE_LEGACY_PENDING
#define VT_DEFERRED_EPT_USE_LEGACY_PENDING 1
#endif

// ----------------------------------------------------------------------------
// 【模块 3】系统稳定性、看门狗与活锁熔断流程 (Pre-Mortem & Storm Breaker)
// ----------------------------------------------------------------------------

// Root-Mode 致命故障安全转储：
// 当 VMX-root 模式发生不可恢复异常时，统一进入可诊断的 BugCheck 路径，彻底阻断静默三重故障。
#ifndef VT_FATAL_BUGCHECK_ENABLED
#define VT_FATAL_BUGCHECK_ENABLED 1
#endif

// 死锁/硬卡死活锁熔断器总开关：
// 当所有 CPU 均陷入 VMX-root 活锁且 Windows 看门狗与工作线程全部失效时，
// 按 vCPU 统计连续相同的 VMEXIT 签名；达到阈值后直接从 VMEXIT 路径调度已校验的 Guest KeBugCheckEx。
#ifndef VT_STORM_BREAKER_ENABLED
#define VT_STORM_BREAKER_ENABLED 1
#endif

// 活锁熔断判定阈值：
#ifndef VT_STORM_BREAKER_THRESHOLD
#define VT_STORM_BREAKER_THRESHOLD 100000ull
#endif

// 显式 BugCheck 诊断码显示开关：
#ifndef VT_STORM_BREAKER_VISIBLE_CODE
#define VT_STORM_BREAKER_VISIBLE_CODE 1
#endif

// AMD SVM 平台启动看门狗流程开关：
#ifndef VT_AMD_STARTUP_WATCHDOG_ENABLED
#define VT_AMD_STARTUP_WATCHDOG_ENABLED 1
#endif

// AMD 启动看门狗超时时间（秒）与 BugCheck 错误码：
#ifndef VT_AMD_STARTUP_WATCHDOG_TIMEOUT_SECONDS
#define VT_AMD_STARTUP_WATCHDOG_TIMEOUT_SECONDS 30
#endif
#ifndef VT_AMD_STARTUP_WATCHDOG_BUGCHECK
#define VT_AMD_STARTUP_WATCHDOG_BUGCHECK 0xE2000A01u
#endif

// ----------------------------------------------------------------------------
// 【模块 4】物理实机内存分配与内存池策略 (Memory Allocation & Pool Policy)
// ----------------------------------------------------------------------------

// 强制使用纯独立物理页分配：
// 载荷与底层 PoolManager 物理后备内存必须统一使用 MmAllocateIndependentPages，
// 严禁使用 ExAllocatePoolWithTag 等宿主系统内存池，阻断生命周期混入与系统池审计特征。
#ifndef VT_MEM_FORCE_INDEPENDENT_PAGES
#define VT_MEM_FORCE_INDEPENDENT_PAGES 1
#endif

// 强制走 Host Pool 分配策略开关（默认 0，严格走独立物理页）：
#ifndef VT_MEM_FORCE_HOST_POOL_ALLOC
#define VT_MEM_FORCE_HOST_POOL_ALLOC 0
#endif

// 独立物理页申请/保护/写校验失败时的单次重试次数上限：
#ifndef VT_MEM_ALLOC_RETRY_COUNT
#define VT_MEM_ALLOC_RETRY_COUNT 3
#endif

// 独立页申请单次重试等待时间（微秒，默认 50000 即 50 毫秒）：
#ifndef VT_MEM_ALLOC_RETRY_DELAY_US
#define VT_MEM_ALLOC_RETRY_DELAY_US 50000
#endif

// 常驻载荷私有 Arena 预分配尺寸（默认 32 MiB）：
// 启动阶段一次性分配，交接后由载荷独占管理；卸载时待引用归零后整体释放。
#ifndef VT_PAYLOAD_ARENA_SIZE
#define VT_PAYLOAD_ARENA_SIZE 0x2000000ul
#endif

// 卸载时释放 Arena 内存：
#ifndef VT_MEM_FREE_ARENA_ON_UNLOAD
#define VT_MEM_FREE_ARENA_ON_UNLOAD 1
#endif

// EPT 拆分空闲物理页池容量（每个拆分页覆盖 2 MiB GPA 区域）：
// 0x400 (1024) 支持每个 vCPU 拥有 1024 个独立的拆分区域，将预留物理内存由 48 MiB 降至 4 MiB。
#ifndef VT_EPT_FREE_PAGE_SPLIT_COUNT
#define VT_EPT_FREE_PAGE_SPLIT_COUNT 0x400
#endif

// ----------------------------------------------------------------------------
// 【模块 5】反作弊对抗、内存隐藏与痕迹治理 (Anti-Cheat & Stealth)
// ----------------------------------------------------------------------------

// VtResidentPayload 映像隐藏总开关：0 = 保持 Payload 可见；1 = 允许 Payload 隐藏细分开关生效。
#ifndef VT_PAYLOAD_IMAGE_HIDE_ENABLED
#define VT_PAYLOAD_IMAGE_HIDE_ENABLED 1
#endif

// Machenike 稳定双视图：仅对 .text 页启用“执行原页、读取零页”。
// .rdata/.data/.pdata/.xdata 保持正常读取，避免常量、IAT 与异常元数据被清零。
#ifndef VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED
#define VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED 1
#endif

// 常驻载荷全量内存隐藏总开关：
#ifndef VT_HIDE_PAYLOAD_ENABLED
#define VT_HIDE_PAYLOAD_ENABLED 1
#endif

// 载荷代码段 EPT 读写分离隐藏开关（Execute-Only，阻断扫描读）：
#ifndef VT_HIDE_PAYLOAD_IMAGE
#define VT_HIDE_PAYLOAD_IMAGE 1
#endif

// 单次 Machenike .text 双视图最多登记的页数；必须不超过 EH 表容量。
#ifndef VT_MACHENIKE_TEXT_DUAL_VIEW_MAX_PAGES
#define VT_MACHENIKE_TEXT_DUAL_VIEW_MAX_PAGES 128
#endif

// EPT/NPT EH 条目表容量，需覆盖稳定双视图的 .text 页预算。
#ifndef VT_EH_TABLE_CAPACITY
#define VT_EH_TABLE_CAPACITY 128
#endif

// 载荷私有 Arena 堆空间 EPT 隐藏开关：
#ifndef VT_HIDE_PAYLOAD_ARENA
#define VT_HIDE_PAYLOAD_ARENA 1
#endif

// 载荷 Direct Trampoline 跳板槽位 EPT 隐藏开关：
#ifndef VT_HIDE_PAYLOAD_DIRECT
#define VT_HIDE_PAYLOAD_DIRECT 1
#endif

// 严格最终隐藏：隐藏整个预分配 Arena 空间（全 32 MiB 而非仅已用前缀）：
#ifndef VT_HIDE_FULL_ARENA
#define VT_HIDE_FULL_ARENA 1
#endif

// 交接确认完成后立即隐藏常驻内存池物理页面：
#ifndef VT_HIDE_RESIDENT_POOLS_AFTER_HANDOFF
#define VT_HIDE_RESIDENT_POOLS_AFTER_HANDOFF 1
#endif

// Debug 重载模式只保留控制设备，其余生产功能保持开启：
// Payload/Machenike 隐藏、.text 双视图、Arena/Pool/Host Stack 隐藏均照常执行。
// FULL_UNLOAD 在释放运行时前通过仍活跃的全核 VMCALL 解除这些映射，随后完成
// VCPU stop ACK 与引用归零，供 --unload/--reload 使用。
#if VT_DEBUG_RELOAD_MODE
#undef VT_BOOT_KEEP_CONTROL_DEVICE
#define VT_BOOT_KEEP_CONTROL_DEVICE 1
#undef VT_BOOT_DROP_CONTROL_DEVICE
#define VT_BOOT_DROP_CONTROL_DEVICE 0
#undef VT_FULL_UNLOAD_PRE_UNHIDE_ENABLED
#define VT_FULL_UNLOAD_PRE_UNHIDE_ENABLED 1
#endif

// PoolManager 与映像隐藏策略解耦：PoolManager 始终负责分配、跟踪、
// quarantine 与卸载；只有 Payload 隐藏链路启用时，resident block 才参与
// Host 映射与 PFN→dummy。Payload 映像 block 始终由调用点排除。
#ifndef VT_POOLMANAGER_ENABLED
#define VT_POOLMANAGER_ENABLED 1
#endif
#ifndef VT_POOLMANAGER_TRACK_RESIDENT_BLOCKS
#define VT_POOLMANAGER_TRACK_RESIDENT_BLOCKS 1
#endif
#ifndef VT_POOLMANAGER_HIDE_RESIDENT_BLOCKS
#define VT_POOLMANAGER_HIDE_RESIDENT_BLOCKS                                                                            \
    (VT_POOLMANAGER_ENABLED && VT_POOLMANAGER_TRACK_RESIDENT_BLOCKS && VT_PAYLOAD_IMAGE_HIDE_ENABLED &&                \
     VT_HIDE_PAYLOAD_ENABLED && VT_HIDE_RESIDENT_POOLS_AFTER_HANDOFF)
#endif
#ifndef VT_POOLMANAGER_HOSTMAP_RESIDENT_BLOCKS
#define VT_POOLMANAGER_HOSTMAP_RESIDENT_BLOCKS                                                                         \
    (VT_POOLMANAGER_HIDE_RESIDENT_BLOCKS && (VT_HOSTMAP_CODE_POOLS_ONLY || VT_HOSTMAP_ALL_POOLS))
#endif
#ifndef VT_POOLMANAGER_EXCLUDE_PAYLOAD_IMAGE
#define VT_POOLMANAGER_EXCLUDE_PAYLOAD_IMAGE 1
#endif
#if !VT_POOLMANAGER_EXCLUDE_PAYLOAD_IMAGE
#error "VT_POOLMANAGER_EXCLUDE_PAYLOAD_IMAGE must remain 1 for Payload EH dual-view stability"
#endif

// PFN 隐藏前 HOST_CR3 私有映射策略：
// 仅为包含可执行 Hook/跳板代码的代码池物理页在 HOST_CR3 建立私有映射（0 为映射全池）。
#ifndef VT_HOSTMAP_CODE_POOLS_ONLY
#define VT_HOSTMAP_CODE_POOLS_ONLY 1
#endif

// 完整卸载阶段禁止发起预解除隐藏 VMCALL（避免 VT 内部复位）：
#ifndef VT_FULL_UNLOAD_PRE_UNHIDE_ENABLED
#define VT_FULL_UNLOAD_PRE_UNHIDE_ENABLED 0
#endif

// 保留旧版 Hypervisor 映像尾部 N 页保持可见与解锁（跳过 EPT 隐藏与页面保护锁定）：
#ifndef VT_LEGACY_HYPERVISOR_TAIL_VISIBLE_PAGES
#define VT_LEGACY_HYPERVISOR_TAIL_VISIBLE_PAGES 50
#endif

// 内核审计链与痕迹抹除开关（PiDDBCacheTable、MmUnloadedDrivers）：
#ifndef VT_TRACE_CLEAN_ENABLED
#define VT_TRACE_CLEAN_ENABLED 1
#endif

// 扩展内存例程符号解析总开关（用于 Stage 5 内存隐藏挂接）：
#ifndef VT_ENABLE_EXT_MM_SYMBOLS
#define VT_ENABLE_EXT_MM_SYMBOLS 1
#endif

// 解析 MmIsAddressValidEx 符号（可选 Stage 5 扩展探针挂接）：
#ifndef VT_EXT_SYMBOL_MM_IS_ADDRESS_VALID_EX
#define VT_EXT_SYMBOL_MM_IS_ADDRESS_VALID_EX 1
#endif

// 解析 NtQueryVirtualMemory 符号（可选 Stage 5 VAD 查询挂接）：
#ifndef VT_EXT_SYMBOL_NT_QUERY_VIRTUAL_MEMORY
#define VT_EXT_SYMBOL_NT_QUERY_VIRTUAL_MEMORY 1
#endif

// 解析 MmGetPhysicalAddress 符号（物理地址解算）：
#ifndef VT_EXT_SYMBOL_MM_GET_PHYSICAL_ADDRESS
#define VT_EXT_SYMBOL_MM_GET_PHYSICAL_ADDRESS 1
#endif

// 驱动服务注册表项自动删除开关：
#ifndef VT_REGISTRY_DELETE_ENABLED
#define VT_REGISTRY_DELETE_ENABLED 1
#endif

// 驱动 PE 镜像头擦除开关：
#ifndef VT_IMAGE_WIPE_ENABLED
#define VT_IMAGE_WIPE_ENABLED 1
#endif

// 驱动磁盘文件隐藏/删除开关（默认 0，避免系统文件系统过滤异常）：
#ifndef VT_DRIVER_FILE_HIDE_ENABLED
#define VT_DRIVER_FILE_HIDE_ENABLED 0
#endif
#ifndef VT_DRIVER_FILE_DELETE_ENABLED
#define VT_DRIVER_FILE_DELETE_ENABLED 0
#endif

// Payload 独立关闭时，只覆盖 Payload 的隐藏细分开关。
#if !VT_PAYLOAD_IMAGE_HIDE_ENABLED
#undef VT_HIDE_PAYLOAD_ENABLED
#define VT_HIDE_PAYLOAD_ENABLED 0
#undef VT_HIDE_PAYLOAD_IMAGE
#define VT_HIDE_PAYLOAD_IMAGE 0
#undef VT_HIDE_PAYLOAD_ARENA
#define VT_HIDE_PAYLOAD_ARENA 0
#undef VT_HIDE_PAYLOAD_DIRECT
#define VT_HIDE_PAYLOAD_DIRECT 0
#undef VT_HIDE_FULL_ARENA
#define VT_HIDE_FULL_ARENA 0
#undef VT_HIDE_RESIDENT_POOLS_AFTER_HANDOFF
#define VT_HIDE_RESIDENT_POOLS_AFTER_HANDOFF 0
#endif

// Machenike 仅保留稳定的 .text 双视图；旧版全映像 PFN→dummy/PE 头擦除路径已删除。

// ----------------------------------------------------------------------------
// 【模块 6】执行流分发、Hook 拦截与 DWM 兼容流程 (Dispatch, Hook & DWM)
// ----------------------------------------------------------------------------

// DWM 兼容安全桥接总开关：
// 载荷全权负责 dbg_dispatch 与 dbg-watch EPT 所有权；普通 INT3 仅观察，精准处理返回/跳板断点。
#ifndef VT_DWM_SAFE_BRIDGE_ENABLED
#define VT_DWM_SAFE_BRIDGE_ENABLED 1
#endif

// 默认 Hook 模式：0=观察 (OBSERVE), 1=透传 (PASSTHROUGH)
#ifndef VT_DEFAULT_HOOK_MODE
#define VT_DEFAULT_HOOK_MODE 0ull
#endif

// 默认断点异常分发模式：0=观察 (OBSERVE), 1=重注入 (REINJECT)
#ifndef VT_DEFAULT_EXBP_MODE
#if VT_DWM_SAFE_BRIDGE_ENABLED
#define VT_DEFAULT_EXBP_MODE 0ull
#else
#define VT_DEFAULT_EXBP_MODE 1ull
#endif
#endif

// 默认 VT 返回分发模式：0=观察 (OBSERVE), 1=严格处理 (HANDLE_STRICT)
#ifndef VT_DEFAULT_VTRET_MODE
#define VT_DEFAULT_VTRET_MODE 1ull
#endif

// 默认跳板处理模式：0=观察 (OBSERVE), 1=处理 (HANDLE)
#ifndef VT_DEFAULT_TRAMP_MODE
#define VT_DEFAULT_TRAMP_MODE 1ull
#endif

// 默认 EPT 处理模式：0=观察 (OBSERVE), 1=处理跳板重定向 (HANDLE_TRAMP)
#ifndef VT_DEFAULT_EPT_MODE
#define VT_DEFAULT_EPT_MODE 1ull
#endif

// 稳定版 GetBuffer 约束使能：
#ifndef VT_STABLE_GETBUFFER_ONLY
#define VT_STABLE_GETBUFFER_ONLY 1
#endif

// 原生 GetBuffer 挂接使能：
#ifndef VT_ENABLE_NATIVE_GETBUFFER_INSTALL
#define VT_ENABLE_NATIVE_GETBUFFER_INSTALL 1
#endif

// PMO 渲染与绘制回调总开关：
#ifndef VT_ENABLE_PMO_RENDER_INIT_CALLOUT
#define VT_ENABLE_PMO_RENDER_INIT_CALLOUT 1
#endif
#ifndef VT_ENABLE_PMO_DRAW_CALLOUT
#define VT_ENABLE_PMO_DRAW_CALLOUT 1
#endif

// PMO 绘制执行核亲和性硬绑定开关：
#ifndef VT_PMO_FORCE_AFFINITY_LOCK
#define VT_PMO_FORCE_AFFINITY_LOCK 1
#endif

// PMO 渲染带入阶段极简心跳 HUD 模式：
// 在 Hook 分发器验证期仅在左上角绘制微小心跳，暂不展开全量 Overlay 绘制。
#ifndef VT_MINIMAL_PMO_HUD
#define VT_MINIMAL_PMO_HUD 1
#endif

// 内存过滤核心自动挂接使能：
#ifndef VT_MM4_INSTALL_AUTO_ENABLE
#define VT_MM4_INSTALL_AUTO_ENABLE 1
#endif
#ifndef VT_MM4_INSTALL_EXTRA_VCPU_INDEX
#define VT_MM4_INSTALL_EXTRA_VCPU_INDEX 1
#endif

// 扩展挂接使能配置（默认禁用不必要的次级挂接，保持最简极简路径）：
#ifndef VT_ENABLE_NATIVE_SWAPCHAIN_EXTRA_INSTALL
#define VT_ENABLE_NATIVE_SWAPCHAIN_EXTRA_INSTALL 0
#endif
#ifndef VT_ENABLE_NATIVE_COPY_DUP_INSTALL
#define VT_ENABLE_NATIVE_COPY_DUP_INSTALL 0
#endif
#ifndef VT_ENABLE_NATIVE_NT_MEMORY_INSTALL
#define VT_ENABLE_NATIVE_NT_MEMORY_INSTALL 0
#endif
#ifndef VT_ENABLE_NATIVE_MM_FILTER_INSTALL
#define VT_ENABLE_NATIVE_MM_FILTER_INSTALL 0
#endif

#ifndef VT_HOSTMAP_ALL_POOLS
#define VT_HOSTMAP_ALL_POOLS 1
#endif
#ifndef VT_BOOT_MIN_PMO_DRAWS
#define VT_BOOT_MIN_PMO_DRAWS 1
#endif
#ifndef VT_BOOT_MIN_BUSINESS_TICKS
#define VT_BOOT_MIN_BUSINESS_TICKS 1
#endif
#ifndef VT_BOOT_AUTO_LOAD_MACHENIKE_ON_BOOT
#define VT_BOOT_AUTO_LOAD_MACHENIKE_ON_BOOT 0
#endif

// ----------------------------------------------------------------------------
// 【模块 7】可观测性与统一分模块日志规范 (Observability & Logging)
// ----------------------------------------------------------------------------

// 全局日志使能控制（可观测性能力，关闭日志绝不改变任何资源所有权和状态流转）：
#ifndef VT_LOG_ENABLED
#define VT_LOG_ENABLED 1
#endif

// 统一子模块日志标签前缀规范 (对齐项目命名体系)
#ifndef LOG_TAG_HV
#define LOG_TAG_HV "[VtHypervisor]"
#endif
#ifndef LOG_TAG_HV_VCPU
#define LOG_TAG_HV_VCPU "[VtHypervisor:VCPU]"
#endif
#ifndef LOG_TAG_HV_DIAG
#define LOG_TAG_HV_DIAG "[VtHypervisor:Diag]"
#endif
#ifndef LOG_TAG_HV_WATCHDOG
#define LOG_TAG_HV_WATCHDOG "[VtHypervisor:Watchdog]"
#endif
#ifndef LOG_TAG_HV_AMD
#define LOG_TAG_HV_AMD "[VtHypervisor:AMD]"
#endif
#ifndef LOG_TAG_BOOT
#define LOG_TAG_BOOT "[VtBootstrapDriver]"
#endif
#ifndef LOG_TAG_BOOT_TRACE
#define LOG_TAG_BOOT_TRACE "[VtBootstrapDriver:Trace]"
#endif
#ifndef LOG_TAG_PAYLOAD
#define LOG_TAG_PAYLOAD "[VtResidentPayload]"
#endif
