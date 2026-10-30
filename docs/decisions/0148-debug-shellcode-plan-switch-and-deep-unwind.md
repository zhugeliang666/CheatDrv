# ADR-0148: DebugShellcode 三方案编译开关与方案3深层栈嫁接

- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: 方案1能够把目标函数调用返回地址落到合法模块 Gadget，但 Shellcode 与运行时 C++ 调度帧仍可能出现在原生线程栈的深层扫描结果中；同时方案2需要驱动先提供合法模块冷分支的 GhostRetVa，不能在缺少安装状态时静默回退。
- **技术决策与规范**: 通过 `Core/StackSpoofConfig.h` 的 `VT_SHELLCODE_SPOOF_PLAN` 统一选择 1/2/3。方案3在 X1 入口保存 `RuntimeSlot::OriginalRsp`，把 RuntimeDispatch 切换到数据页尾部私有栈；进入外部 R3 函数前恢复原生栈锚点，并通过合法 `call rax; add rsp,28h; ret` 与 `jmp [rbx]` Gadget 返回。方案2增加 Ghost 桩与 `GhostRetVa` 字段，但缺少驱动安装的 GhostRetVa 时必须失败关闭。
- **已知约束与避坑**: `RuntimeSlot::state` 固定保持 `0x10`；方案3仅接受入口 `RSP % 16 == 8` 且 Gadget 静态帧为 16 字节倍数的路径；私有栈只使用独立 RW 数据页尾部，不写入 `.text`；方案2的 `GhostRetVa` 必须位于合法模块冷分支的双视图影子执行页，不能填入任意热路径地址。当前 Windows 10 19041.5794 的 `C:\Windows\System32\notepad.exe`（MD5 `6f51bcabf1b2b34ad7e670aee6da451f`）采用 `image + 0x28D3`（`.text + 0x18D3`）：`0x28CE` 为 `E8 rel32`，`0x28D3` 为返回落点，且位于 `.text` 的 `PAGE_EXECUTE_READ` 页；`image + 0x18D3` 只是函数内部的普通指令位置，不是 Ghost 返回点。换目标版本必须重新用 CE 校验，禁止盲复用该 RVA。
