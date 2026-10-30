#pragma once

// DebugShellcode 堆栈伪造方案的单一编译期开关。
// 1：合法模块 Gadget；2：VT 幽灵 call 返回点；3：原生栈嫁接 + 私有栈深层隔离。
#define VT_SHELLCODE_SPOOF_PLAN_NATIVE_GADGET 1
#define VT_SHELLCODE_SPOOF_PLAN_GHOST_CALL 2
#define VT_SHELLCODE_SPOOF_PLAN_DEEP_UNWIND 3

#ifndef VT_SHELLCODE_SPOOF_PLAN
#define VT_SHELLCODE_SPOOF_PLAN 2
#endif

// 方案2升级：保留硬编码 GhostRetRva，同时把目标函数调用嫁接到原生线程栈，
// 用 GhostRet 所在函数的 .pdata 帧大小闭合深层展开；0 表示仅使用基础 Ghost 调用。
#ifndef VT_SHELLCODE_PLAN2_DEEP_UNWIND
#define VT_SHELLCODE_PLAN2_DEEP_UNWIND 1
#endif

// 方案2必须由使用者提供目标模块内冷分支 call 的返回 RVA；0 表示保持失败关闭。
#ifndef VT_SHELLCODE_PLAN2_GHOST_RET_RVA
// Windows 10 19041.5794 当前 notepad.exe：image + 0x28D3（.text + 0x18D3）。
// 0x28CE 为冷错误分支中的 E8 rel32 call，0x28D3 为其返回落点；
// 该落点位于 .text 的 PAGE_EXECUTE_READ 页，运行时由 VT 影子执行视图承载 FF 23。
#define VT_SHELLCODE_PLAN2_GHOST_RET_RVA 0x28D3
#endif

#if VT_SHELLCODE_SPOOF_PLAN != 1 && VT_SHELLCODE_SPOOF_PLAN != 2 && VT_SHELLCODE_SPOOF_PLAN != 3
#error "VT_SHELLCODE_SPOOF_PLAN 必须为 1、2 或 3"
#endif

