# ADR-0120: 项目专用 XUserVarInit 初始化镜像
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: 通用 InitProfile/Dispatcher 与独立 MessageBox 适配层引入了不必要的 ABI 和复制镜像复杂度，需要严格复刻 DeltaForceDecrypt 的 XUserVarInit/X1 组织方式。
- **技术决策与规范**: `DebugShellcode` 按 `DeltaForceDecrypt` 的项目结构直接使用 `Common.h`、`XString.h`、`DynamicXor.h`、`FrameWork.h` 与 `GameStruct.h`。`XUserVarOffsetInit`、`XUserVarInit` 使用参考项目相同的命名、固定模块/导出哈希数组和初始化顺序，通过 `GS:[0x60]` 的 PEB/Ldr 模块链定位函数，按 `malloc/memset/memcpy/free` 分配并清零 `Func/Offset/Data/Param/UserVar`，初始化 `CacheTransform`、`XorKey`、临界区与 `Version=44`。新增同镜像 `XInternalDecrypt` 仅在槽位为空时调用 `XUserVarInit`，保持重复进入幂等。ASM 仅保存/恢复寄存器与 XMM0-XMM15，通过两个 imm64 槽位调用复制后的 `XInternalDecrypt`；业务调用、消息框、Worker 和通用 Dispatcher 不进入该镜像。
- **已知约束与避坑**: 复制前必须单独复制 `.xinit$a/.xinit$m/.xinit$z` 镜像并通过 `PatchXUserVarSlot`、`PatchXUserVarInit` 改写槽位；`XUserVarSlot`、输入页和 `UserVar` 普通可读，ASM/初始化代码单独作为执行镜像；初始化失败返回 `false`，不执行任何业务函数。
