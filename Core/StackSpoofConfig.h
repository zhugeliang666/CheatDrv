#pragma once

// DebugShellcode 的基础调用模式：1=合法模块 Gadget，2=VT 幽灵 call 返回点。
#define VT_SHELLCODE_SPOOF_MODE_NATIVE_GADGET 1
#define VT_SHELLCODE_SPOOF_MODE_GHOST_CALL 2

#ifndef VT_SHELLCODE_SPOOF_MODE
#define VT_SHELLCODE_SPOOF_MODE VT_SHELLCODE_SPOOF_MODE_NATIVE_GADGET
#endif

// 统一深层展开开关：
// 0=基础调用；1=启用当前基础模式对应的原生栈嫁接与私有栈隔离。
// 模式1启用时即为原方案1+方案3；模式2启用时为 GhostRet 深层版本。
#ifndef VT_SHELLCODE_DEEP_UNWIND
#define VT_SHELLCODE_DEEP_UNWIND 1
#endif

#define VT_SHELLCODE_RUNTIME_FLAG_DEEP_UNWIND 0x00000001u

// Ghost 模式必须提供目标模块内冷分支 call 的返回 RVA；0 表示保持失败关闭。
#ifndef VT_SHELLCODE_GHOST_RET_RVA
// Windows 10 19041.5794 当前 notepad.exe：image + 0x28D3（.text + 0x18D3）。
// 0x28CE 为冷错误分支中的 E8 rel32 call，0x28D3 为其返回落点；
// 该落点位于 .text 的 PAGE_EXECUTE_READ 页，运行时由 VT 影子执行视图承载 FF 23。
#define VT_SHELLCODE_GHOST_RET_RVA 0x28D3
#endif

#if VT_SHELLCODE_SPOOF_MODE != VT_SHELLCODE_SPOOF_MODE_NATIVE_GADGET && \
    VT_SHELLCODE_SPOOF_MODE != VT_SHELLCODE_SPOOF_MODE_GHOST_CALL
#error "VT_SHELLCODE_SPOOF_MODE 必须为 NATIVE_GADGET 或 GHOST_CALL"
#endif

