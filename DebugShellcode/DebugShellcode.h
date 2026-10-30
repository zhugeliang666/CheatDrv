#pragma once

#include "Common.h"
#include "XString.h"
#include "../Core/StackSpoofConfig.h"
#include <cstddef>
#include <cstdint>

namespace vt_debug_shellcode {

// 保留安装器使用的槽位布局；首字段与参考项目的 PGENERIC_RUNTIME_CONTEXT* ABI 相同。
struct RuntimeSlot {
    PGENERIC_RUNTIME_CONTEXT value;
    const void *input;
    volatile LONG state; // 0=未初始化，1=初始化中，2=就绪，3=失败
    ULONG RuntimeFlags;  // +0x14：VT_RUNTIME_SLOT_FLAG_*；不改变既有 ABI 尺寸
    ULONG64 OriginalRsp;   // +0x18：X1 入口的原生线程栈锚点
    ULONG64 PrivateStackTop;// +0x20：深层模式私有数据页栈顶
    ULONG64 GhostRetVa;    // +0x28：Ghost 模式由驱动安装的幽灵返回点
    ULONG JmpFrameSize;    // +0x30：当前模式返回点所在函数的静态栈帧大小
    ULONG SpoofMode;       // +0x34：驱动写入的基础调用模式
};

enum : ULONG {
    VT_RUNTIME_SLOT_FLAG_DEEP_UNWIND = VT_SHELLCODE_RUNTIME_FLAG_DEEP_UNWIND,
};

static_assert(offsetof(RuntimeSlot, value) == 0x00, "RuntimeSlot::value 偏移改变");
static_assert(offsetof(RuntimeSlot, input) == 0x08, "RuntimeSlot::input 偏移改变");
static_assert(offsetof(RuntimeSlot, state) == 0x10, "RuntimeSlot::state 偏移改变");
static_assert(offsetof(RuntimeSlot, RuntimeFlags) == 0x14, "RuntimeSlot::RuntimeFlags 偏移改变");
static_assert(offsetof(RuntimeSlot, OriginalRsp) == 0x18, "RuntimeSlot::OriginalRsp 偏移改变");
static_assert(offsetof(RuntimeSlot, GhostRetVa) == 0x28, "RuntimeSlot::GhostRetVa 偏移改变");
static_assert(offsetof(RuntimeSlot, JmpFrameSize) == 0x30, "RuntimeSlot::JmpFrameSize 偏移改变");
static_assert(offsetof(RuntimeSlot, SpoofMode) == 0x34, "RuntimeSlot::SpoofMode 偏移改变");
static_assert(sizeof(RuntimeSlot) == 0x38, "RuntimeSlot 尺寸改变");

#pragma pack(push, 8)
struct SPOOF_GADGET_PAIR {
    ULONG_PTR CallRaxAddRsp28Ret;
    ULONG_PTR JmpQwordPtrRbx;
    ULONG JmpFrameSize;
    ULONG Reserved;
};

struct SPOOF_CALL_CONTEXT {
    ULONG64 FixupRip;
    ULONG64 SavedRbx;
    ULONG64 SavedRetAddr;
    ULONG64 CallRaxGadget;
    ULONG64 JmpRbxGadget;
    ULONG64 TargetFunc;
    ULONG64 OriginalRsp;
    ULONG64 SavedPrivateRsp;
    ULONG64 GhostRetVa;
    ULONG64 JmpFrameSize;
};
static_assert(offsetof(SPOOF_CALL_CONTEXT, OriginalRsp) == 0x30, "SPOOF_CALL_CONTEXT::OriginalRsp 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, SavedPrivateRsp) == 0x38, "SPOOF_CALL_CONTEXT::SavedPrivateRsp 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, GhostRetVa) == 0x40, "SPOOF_CALL_CONTEXT::GhostRetVa 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, JmpFrameSize) == 0x48, "SPOOF_CALL_CONTEXT::JmpFrameSize 偏移改变");
#pragma pack(pop)

inline std::size_t X1ImageSize() noexcept;
inline std::size_t RuntimeInitImageSize() noexcept;

inline bool PatchRuntimeSlot(void *image, std::size_t image_size, std::uint64_t slot) noexcept {
    if (!image || image_size < 10)
        return false;
    auto *bytes = static_cast<std::uint8_t *>(image);
    for (std::size_t offset = 0; offset + 10 <= image_size; ++offset) {
        if (bytes[offset] != 0x49 || bytes[offset + 1] != 0xBB)
            continue;
        for (std::size_t i = 0; i < sizeof(slot); ++i)
            bytes[offset + 2 + i] = static_cast<std::uint8_t>(slot >> (i * 8));
        return true;
    }
    return false;
}

inline bool PatchRuntimeDispatch(void *image, std::size_t image_size, std::uint64_t dispatch_entry) noexcept {
    if (!image || image_size < 10)
        return false;
    auto *bytes = static_cast<std::uint8_t *>(image);
    for (std::size_t offset = 0; offset + 10 <= image_size; ++offset) {
        if (bytes[offset] != 0x49 || bytes[offset + 1] != 0xBA)
            continue;
        for (std::size_t i = 0; i < sizeof(dispatch_entry); ++i)
            bytes[offset + 2 + i] = static_cast<std::uint8_t>(dispatch_entry >> (i * 8));
        return true;
    }
    return false;
}

} // namespace vt_debug_shellcode

extern "C" {
extern const std::uint8_t X1[];
extern const std::uint8_t X1End[];
extern const std::uint8_t RuntimeInitImageStart[];
extern const std::uint8_t RuntimeInitImageEnd[];

extern int __fastcall SpoofCallNativeInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    PVOID hWnd,
    PCWSTR text,
    PCWSTR caption,
    UINT type);
extern int __fastcall SpoofCallGhostInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    PVOID hWnd,
    PCWSTR text,
    PCWSTR caption,
    UINT type);
extern int __fastcall SpoofCallGhostDeepInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    PVOID hWnd,
    PCWSTR text,
    PCWSTR caption,
    UINT type);
extern __declspec(dllexport) bool __fastcall RuntimeDispatch(void *pUserVar);
}

inline std::size_t vt_debug_shellcode::X1ImageSize() noexcept {
    return static_cast<std::size_t>(X1End - X1);
}

inline std::size_t vt_debug_shellcode::RuntimeInitImageSize() noexcept {
    return static_cast<std::size_t>(RuntimeInitImageEnd - RuntimeInitImageStart);
}




