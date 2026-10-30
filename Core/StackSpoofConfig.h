#pragma once

// DebugShellcode 堆栈伪造方案的单一编译期开关。
// 1：合法模块 Gadget；2：VT 幽灵 call 返回点；3：原生栈嫁接 + 私有栈深层隔离。
#define VT_SHELLCODE_SPOOF_PLAN_NATIVE_GADGET 1
#define VT_SHELLCODE_SPOOF_PLAN_GHOST_CALL 2
#define VT_SHELLCODE_SPOOF_PLAN_DEEP_UNWIND 3

#ifndef VT_SHELLCODE_SPOOF_PLAN
#define VT_SHELLCODE_SPOOF_PLAN 1
#endif

// 方案2必须由使用者提供目标模块内冷分支 call 的返回 RVA；0 表示保持失败关闭。
#ifndef VT_SHELLCODE_PLAN2_GHOST_RET_RVA
#define VT_SHELLCODE_PLAN2_GHOST_RET_RVA 0
#endif

#if VT_SHELLCODE_SPOOF_PLAN != 1 && VT_SHELLCODE_SPOOF_PLAN != 2 && VT_SHELLCODE_SPOOF_PLAN != 3
#error "VT_SHELLCODE_SPOOF_PLAN 必须为 1、2 或 3"
#endif

