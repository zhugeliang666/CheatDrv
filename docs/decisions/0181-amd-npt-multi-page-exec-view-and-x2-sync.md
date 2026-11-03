# ADR-0181：AMD NPT 多页执行视图与 X2 补丁一致性修复

- **状态**：已实现，待目标机 WinDbg/Notepad 实机验证
- **日期**：2026-11-03（2026-11-04 按最终实现修订）
- **上下文与痛点**：Shellcode `.text` 的 8 个虚拟页在物理上离散；旧执行根只放行单页，跨 4KB 指令（实测 `RVA 0x4FFD: c7 43 1c d0 03 00 00`，7 字节；`RVA 0x5FFF: c7 44 24 4c 44 00 69 00`，8 字节）会在执行根与普通根之间反复触发 `#NPF`。X2 在执行视图建立后再写普通页，影子页仍保留模板占位符；尾部 `FF 25 [RIP+0]` 还会在 READ_ZERO 下读 `.text` 数据。
- **技术决策与规范**：
  1. AMD `npt_exec_view` 使用固定 32 槽 PDPT/PD/PT 池（`pdpt_pool[32]`、`pd_pool[32]`、`pt_pool[32]`），按活动 Hook 页的离散物理块建立执行根；普通根继续承担读取视图。`pml4[0]` 覆盖 GPA < 512GiB。
  2. 安装期容量校验 `npt_exec_view_capacity_valid`：统计全部活动 Hook 页 + 候选页的不同 1GiB 区与 2MiB 块数量，任一超过 32 或 GPA 超出 `pml4[0]` 范围即拒绝安装（`install_npt_hook` 返回失败并保持普通视图原状），不在 VM-exit 路径动态分配。
  3. 执行根一次放行全部已注册 Hook 页。**不放行**“物理相邻的未挂钩页”——虚拟相邻页不等于 GPA 相邻，该分支已删除；跨页取指由“两侧页都已注册”保证。
  4. `handle_npf` 在执行根中命中已注册页时直接复用/重建执行根；只有离开注册页才切回普通根。构建失败按 `hook_generation` 缓存（`failed_hook_generation`），同一代内不重复重建，直接走单步安全网。
  5. 普通根与执行根使用不重叠 ASID（普通 `index+1`，执行 `asid + vcpu_count`，超出 `max_asid` 时回退全刷 TLB）；`generation` 拆分为 `hook_generation`（Hook 增删）与 `mapping_generation`（普通视图补映射），执行视图缓存只跟随 `hook_generation`。视图切换只清 VMCB clean bit `ASID(bit3)` 与 `NP(bit4)`。
  6. Hook 页固定 `EXEC_SHADOW_READ_ORIGINAL`（读原页/执行影子）；Shellcode `.text` 固定 `EXEC_SHADOW_READ_ZERO`（读 dummy 零页/执行影子）。
  7. X2 补丁在影子视图已建立时按页调用 `EhWrite` 同步到执行影子页（AMD 的 `exec_pfn` 即 EH `fake_pfn`）；失败时对普通页与影子页全量回滚。
  8. X2 尾部跳板为 **6 字节 `FF 25 disp32`**，目标 `s_NotepadShellcodeResumeSlotVa`（`codeBase + codeSize - PAGE_SIZE`，`.text` 之外、独立 RW 页）：不改寄存器、不写栈、不读 `.text`、CET 安全；安装时断言 `|disp| <= 0x7FFF0000`。
  9. 构建期双层门禁：`generate_embed.py` 按 `.pdata`（RUNTIME_FUNCTION）区间反汇编 `.text`，排除仅供驱动扫描特征偏移的 R0 辅助导出（`PatchRuntimeDispatch`、`PatchRuntimeSlot`；`X1ImageSize`/`X2ImageOffset` 无 `.pdata` 项），按“含 `[rip+disp32]`、非 `LEA`、目标段分类”判定，导出 `constexpr` 的 `g_DebugShellcodeTextSelfReadCount/FirstRva`、`TextXconstReadCount/FirstRva`、`TextDataReadCount`、`TextScannedFunctions`，并在头文件顶部生成审计摘要与 `[VIOLATION]` 定位注释。
  10. 编译期断言：`VT_DEBUG_NOTEPAD_HOOK_DUAL_VIEW && VT_DEBUG_NOTEPAD_SHELLCODE_DUAL_VIEW` 时强制 `TextSelfReadCount == 0`（`[Dual-View Gate]`）；`!VT_SHELLCODE_ENABLE_LOG` 时强制 `TextXconstReadCount == 0`（`[Single-Section Gate]`）；任何配置下强制 `TextScannedFunctions != 0`（防止门禁失效）。
  11. 运行期兜底：`VtEmbeddedPatchRuntime` 与 `VtEmbeddedPatchAdditionalHook` 在写入 `resumeJump` 前拒绝回弹目标落入页对齐后的 `.text` 跨度，避免 READ_ZERO 页执行跳零。
  12. 代码页权限：`VT_DEBUG_NOTEPAD_SHELLCODE_DUAL_VIEW=1` 时 `codeBase` 以 `PAGE_READWRITE` 申请（不授予执行），注入与 X1/X2 补丁全部写完后、X1 hook 安装前由 `VtEmbeddedProtect` 收紧为 `PAGE_EXECUTE_READ`（消除 RWX 窗口）。guest PTE 必须保留执行位：取指先过 guest 页表，NX=1 会先触发 guest `#PF` 而不是执行视图的 `#NPF`；执行本身仍由 NPT 影子页承担。
- **已知约束与避坑**：
  - `X2StolenBytes` 预留固定 22 字节（16 字节重定位槽 + 6 字节跳板），必须断言 `relocatedSize + 6 <= 22`；45 字节版已废弃。
  - Resume 槽页必须在 `.text` 之外。若放进 `.text` 尾部 padding，该页会被 `EXEC_SHADOW_READ_ZERO` 接管，`activate_npt_exec_view` 失败走单步路径时读零导致 `jmp 0`。
  - 校验按**页对齐后的** `.text` 跨度（`align_up(max(RawSize, VirtualSize))`）判断，不能用 `RawSize`：`0x7A00` 与 `0x8000` 之间的尾部区间仍在只读零视图内，且写入区间 `[ResumeSlotVa, +8)` 还必须与整页跨度不相交。
  - 执行视图上限 32 个 1GiB 区与 32 个 2MiB 块；Hook 页 GPA 必须 < 512GiB。
  - VM-Exit 次数模型：纯内联路径 2 次（进/出 Hook 页）；X1/X2 每次调用外部模块（user32/ntdll/kernel32）额外 +2。
  - 该候选只改变副本；必须先在静态构建、目标机 WinDbg 和 Notepad 触发链路中验证，再合并到真实源码。
