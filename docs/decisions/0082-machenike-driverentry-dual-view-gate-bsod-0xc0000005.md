# ADR-0082: Machenike DriverEntry 双视图安装时序与零页取指蓝屏隔离
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: AMD-SVM 手动映射 Machenike 在 DriverEntry 返回前执行旧版全映像 PFN→dummy 隐藏。该路径同时擦除 PE 头并把活动代码页切换到零页，返回路径随后从 `base+0x101E` 取到 `00 00`，触发 `0xC0000005` 写地址 `0x1`。外部 `.text` 双视图安装发生在 `LoadMachenike` 返回后，原有时序无法覆盖 DriverEntry 内的执行流。
- **技术决策与规范**: `VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED=1` 时，跳过 Machenike 旧版全映像擦除、PE 头擦除和 `VtEngine::HideVirtualRange`；保留映像头部至 `InstallMachenikeTextDualView` 完成，随后仅对完整 `.text` 页登记 EH 双视图（执行原页、读取零页）。`.rdata/.data/.pdata/.xdata` 保持正常读取。`VT_MACHENIKE_IMAGE_HIDE_ENABLED` 与双视图宏保持独立，关闭映像隐藏不再隐式关闭双视图。
- **已知约束与避坑**: 严禁在活动 DriverEntry 返回路径上对 `.text` 执行 PFN→dummy；旧版全映像路径仅在双视图关闭时可编译进入。双视图页集合必须在 PE 头仍存在时解析，安装失败走可见稳定模式并保留回滚；卸载必须先移除 EH 条目再进入 Machenike `DriverUnload`。本次验证覆盖 `Machenike.vcxproj` 与 `VtBootstrapDriver.vcxproj` Release|x64 编译、布局检查和回滚副本恢复。
