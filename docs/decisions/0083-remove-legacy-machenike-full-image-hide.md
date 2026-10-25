# ADR-0083: 删除 Machenike 旧版全映像隐藏链路
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: 旧版 Machenike 全映像隐藏通过 `VtEngine::HideVirtualRange` 逐页执行 PFN→dummy，并配合 PE 头、INIT、`.reloc` 擦除。该路径在活动 DriverEntry 返回阶段破坏取指页，WinDbg 现场表现为零页指令 `00 00`、写地址 `0x1` 的 `0xC0000005`。
- **技术决策与规范**: 删除 `HideVirtualRange` 及其自身 PFN 隐藏/解除隐藏和 System CR3 NX 封装；删除 Machenike 手动映射路径的 PE 头、INIT、`.reloc` 和首页擦除；删除 `VT_MACHENIKE_IMAGE_HIDE_ENABLED` 宏。Machenike 只保留完整 `.text` 页 EH 双视图，执行映射原页、读取映射零页，其他节保持原始内容。
- **已知约束与避坑**: Machenike 禁止恢复 PFN→dummy 全映像隐藏；PE 头必须保留到 `InstallMachenikeTextDualView` 完成；卸载先移除全部 EH 条目再执行 `DriverUnload`。Payload/ResidentPayload 的 PFN 隐藏 ABI 与 PoolManager 逻辑不受本次删除影响。
