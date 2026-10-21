# ADR-0050: 独立 Image-Backed RX 映像节、独立 RW 共享节与单次主线程 GWLP_WNDPROC 子类化架构

- **状态**: 已采纳 (替代 ADR-0047 / ADR-0049 的主模块 Code Cave / Data Cave 写入与 WndProc 入口 Inline Patch)
- **日期**: 2026-10-20
- **上下文与痛点**:
  1. **主模块代码/数据洞写入风险**: 向 `MapleStory.exe` 主模块的 `.text` 或 `.data` 空洞写入 Shellcode 或覆写 `WndProc` 前导 12 字节/`ProcessPacket` 调用点 5 字节，会直接破坏目标主模块的磁盘一致性哈希，易被 Themida 与反作弊周期性完整性巡检捕获；
  2. **非 Image-Backed 私有可执行页特征暴露**: 直接在目标进程分配 `MEM_PRIVATE` + `PAGE_EXECUTE_READ` 内存页缺乏文件对象背书（`VadImageMap`），属于高危内存特征；
  3. **持续劫持线程或外部高频轮询隐患**: 持续挂起线程或依赖外部调试断点无法实现生产环境闭环。

- **技术决策与规范**:
  1. **独立 C++ 项目编译微型 PE 与 `SEC_IMAGE` 独立 RX 映像节 (`MapleRxPayload` + `MapSectionsIntoTarget`)**:
     - 在解决方案中建立独立 C++ 子工程 `MapleRxPayload.vcxproj`（开启 `/NODEFAULTLIB`、`/GS-`、`/MERGE:.rdata=.text`），将纯 C++ 编写的 `SubclassInitEntry` 与 `CustomWndProc` 编译为 0 导入表（`Import Directory = 0`）的标准 64 位 PE 映像 `MapleRxPayload.dll`（包含 `.text` `Execute/Read` 与 `.reloc` 节区）；
     - Post-Build 脚本 `EmbedPeToHeader.ps1` 自动解析导出表 RVA（`SubclassInitEntryRva` / `CustomWndProcRva`）并生成 `MapleRxPayloadImage.h` 嵌入驱动，彻底淘汰手写机器码 `BuildRxImageBytes`；
     - 驱动将嵌入的 PE 镜像落盘至 `\SystemRoot\System32\drivers\mswsk_rx.dll`，通过 `ZwCreateSection(..., PAGE_EXECUTE_READ, SEC_IMAGE, hFile)` 创建真正的 **Image-Backed RX Section** 并经 `ZwMapViewOfSection` 映射进目标进程，VAD 类型为标准 `MEM_IMAGE`；随后通过 `ZwSetInformationVirtualMemory(VmCfgCallTargetInformation)` 将导出函数 `SubclassInitEntry` 与 `CustomWndProc` 注册进目标进程 CFG 位图（`CFG_CALL_TARGET_VALID`），防止 `ntdll!KiUserApcDispatcher` 与 `user32!DispatchMessageW` 间接调用时触发 `0xC0000409` (`FAST_FAIL_GUARD_ICALL_CHECK_FAILURE`) 闪退；
  2. **独立 RW 共享节双端映射与 `__ImageBase` RIP 相对寻址**:
     - 驱动创建 `PAGE_READWRITE` + `SEC_COMMIT` 独立共享节（`0x4000` 字节），承载 `MAPLE_SHARED_THUNK_DATA` 与 `RingBuffer[16]`；
     - 视图 1 映射至内核进程空间 `g_SharedKernelView`（供驱动零跨进程拷贝消费 `RingBuffer` 与下发发包指令）；
     - 视图 2 映射至目标进程紧邻 RX 映像节的 `+0x10000`（64KB 分配粒度边界）处，`MapleRxPayload.cpp` 通过 `reinterpret_cast<ULONG64>(&__ImageBase) + MapleLayout::RxToRwSectionOffset` 编译生成纯 `lea reg, [rip + disp32]` 指令，零全局变量写入直接寻址独立 RW 共享节。
  3. **单次切入主窗口线程执行 `SetWindowLongPtrW(GWLP_WNDPROC)`**:
     - 驱动通过 `QueueSingleWindowThreadInit` 筛选目标进程拥有 Win32k GUI 队列的线程（`PsGetThreadWin32Thread(Thread) != NULL`）投递 `UserMode` APC，执行 `SubclassInitEntry`；
     - `SubclassInitEntry` 先通过 `user32!GetWindowThreadProcessId(TargetHwnd, NULL)` 与 `TEB->ClientId.UniqueThread` (`gs:[0x48]`) 比对确认当前线程即为窗口所属主线程，再通过 `lock cmpxchg` 保证单次执行，调用目标进程 `user32!SetWindowLongPtrW(TargetHwnd, GWLP_WNDPROC (-4), CustomWndProc)` 仅修改窗口实例保存的 `GWLP_WNDPROC` 指针，将原窗口过程存入 `pfnOrigWndProc`，置位 `InitState = 2` 后立即返回；
     - 完成后驱动不再劫持任何线程。
  4. **全量由正常窗口消息驱动 (`CustomWndProc`)**:
     - `uMsg == 0x0401` (`FD_READ`): 调用 `OnRead(pSocket, 0)` -> 循环 `AppendBuffer` -> `DecryptData` -> 提取明文写入独立 RW 共享节 `RingBuffer` 并 `lock inc WriteIndex` -> `InnoHash` -> `ProcessPacket` -> `DestroyInPacket`；
     - `uMsg == 0x0777`: 在主线程安全构造 `StaticOutPacket` 并调用 `OutPacketInit` -> `OutPacketEncodeBuffer` -> `SendPacket`；
     - `uMsg == 0x0778`: 主线程调用 `SetWindowLongPtrW` 还原 `pfnOrigWndProc`；
     - 其它所有消息: 通过 `user32!CallWindowProcW(pfnOrigWndProc, hWnd, uMsg, wParam, lParam)` 原生转发。

- **已知约束与避坑**:
  - 严禁向 `MapleStory.exe` 的 `.text`/`.rdata`/`.data` 节区写入任何字节；
  - `SetWindowLongPtrW(GWLP_WNDPROC)` 必须在创建窗口的主线程内调用；
  - **CFG 位图注册 (`ZwSetInformationVirtualMemory` / `VmCfgCallTargetInformation = 2`) 契约与 `BugCheck 0x7E` 防范**：
    1. **严禁在 `KeUnstackDetachProcess` 后解引用目标进程用户空间地址**：`ZwSetInformationVirtualMemory` 通过 `Zw*` 系统调用桩进入内核时自动将 `KTHREAD->PreviousMode` 置为 `KernelMode (0)`，内核 `nt!NtSetInformationVirtualMemory` 完全豁免 `0x7FFFFFFF0000` 用户态地址探测并支持直接传入目标进程句柄 `hProcess` 与内核栈参数（内部自动完成 `KeStackAttachProcess`/`KeUnstackDetachProcess`）。严禁手动借用目标进程 R3 内存并在 `KeUnstackDetachProcess` 切回 `System` `CR3` 后解引用（如 `*pNumOffsets`），否则必触发 `BugCheck 0x7E (0xC0000005)` 蓝屏；
    2. **`VM_CFG_TARGET_INFORMATION` 结构体必须严格为 `0x28` (40) 字节**：`nt!NtSetInformationVirtualMemory+0x127` 强制校验 `VmInformationLength == 0x28`，否则直接返回 `0xC00000F4` (`STATUS_INVALID_PARAMETER_6`)；且 `CallTargets` 数组必须按 `Offset` 升序排列；
    3. **导出目标 RVA 必须严格 16 字节对齐 (`(RVA & 0xF) == 0`)**：`nt!MiCfgMarkValidEntries` 强制要求 `Offset & 0xF == 0` 且 `nt!MiCopyToCfgBitMap` 仅置位 16 字节对齐偶数位（清零奇数位），故 `MapleRxPayload.vcxproj` 必须开启 `MaxSpeed` (`/O2 /Ot`) 确保所有导出函数入口 16 字节对齐（如 `0x1000`、`0x10A0`）；
  - **UserMode APC 即时唤醒与防 `BugCheck 0xCE` (`DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS`) 排空铁律**：
    1. **严禁单靠 `KeAlertThread(Thread, UserMode)` 唤醒 Win32 消息循环线程**：Win32 消息循环（`GetMessageW` / `PeekMessageW`）的内核等待恒为 `Alertable == FALSE` (`KTHREAD.MiscFlags` Bit 4 == 0)，`nt!KiSignalThreadForApc` 与 `nt!KeAlertThread` 均不会置位 `UserApcPending`，导致 `UserMode` `KAPC` 长期滞留队列；必须伴随投递 `KernelMode` Booster APC 在目标线程上下文调用 `KeTestAlertThread(UserMode)` 强制置位 `KTHREAD.ApcState.UserApcPendingAll |= 2` (`SpecialUserApcPending`)；
    2. **投递后与卸载前必须执行 `KeRemoveQueueApc` 原子排空 (`CancelAllPendingApcs`)**：一旦窗口主线程完成初始化（`InitState == 2`）或驱动进入 `Cleanup()`，必须遍历全部静态 `KAPC` 槽位调用 `KeRemoveQueueApc` 摘除未执行的 `KAPC` 并等待在飞回调彻底退栈，严禁带着挂起的 `KAPC` 卸载驱动引发 `BugCheck 0xCE`；
  - **`SEC_IMAGE` 镜像文件锁 (`0xC0000043` `STATUS_SHARING_VIOLATION`) 与双端视图成对回滚铁律**：
    1. **写句柄与只读 `SEC_IMAGE` 句柄必须分离并支持多槽位轮转 (`mswsk_rx_XX.dll`)**：任何已映射为 `SEC_IMAGE` 的磁盘文件，其 `SectionObjectPointer->ImageSectionObject` 被内核缓存期间，NTFS (`MmFlushImageSection(MmFlushForWrite)`) 会无条件拒绝 `GENERIC_WRITE` / `FILE_OVERWRITE_IF` 并返回 `0xC0000043` (`STATUS_SHARING_VIOLATION`)。因此必须轮询可用槽位（`mswsk_rx.dll` / `mswsk_rx_01.dll`..`mswsk_rx_3F.dll`），先以 `GENERIC_WRITE` 写入并立即 `ZwClose` 写句柄，再以纯 `GENERIC_READ` (`FILE_OPEN`) 打开创建 `SEC_IMAGE`；
    2. **成对映射与卸载前主线程还原 `GWLP_WNDPROC`**：若目标进程 `rxBase + 0x10000` 地址冲突导致 RW 视图映射失败，必须立即 `ZwUnmapViewOfSection(hProcess, rxBase)` 并换址重试，严禁遗留孤立的 `SEC_IMAGE` 视图；驱动 `Cleanup()` 卸载前若 `InitState == 2`，必须先将 `InitState` 置为 `4` 并触发主线程还原 `pfnOrigWndProc`（`InitState == 3`）后再解除 `g_RxSectionUserBase` 与 `g_RwSectionUserBase` 映射。
