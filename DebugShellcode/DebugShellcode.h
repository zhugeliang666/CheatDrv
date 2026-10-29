#pragma once

#include "Common.h"
#include "XString.h"
#include <cstddef>
#include <cstdint>

namespace vt_debug_shellcode {

// 保留安装器使用的槽位布局；首字段与参考项目的 PGENERIC_RUNTIME_CONTEXT* ABI 相同。
struct RuntimeSlot {
    PGENERIC_RUNTIME_CONTEXT value;
    const void *input;
    volatile LONG state; // 0=未初始化，1=初始化中，2=就绪，3=失败
};

#pragma pack(push, 8)
struct SPOOF_GADGET_PAIR {
    ULONG_PTR CallRaxAddRsp28Ret;
    ULONG_PTR JmpQwordPtrRbx;
};

struct SPOOF_CALL_CONTEXT {
    ULONG64 FixupRip;
    ULONG64 SavedRbx;
    ULONG64 SavedRetAddr;
    ULONG64 CallRaxGadget;
    ULONG64 JmpRbxGadget;
    ULONG64 TargetFunc;
};
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
extern __declspec(dllexport) bool __fastcall RuntimeDispatch(void *pUserVar);
}

inline std::size_t vt_debug_shellcode::X1ImageSize() noexcept {
    return static_cast<std::size_t>(X1End - X1);
}

inline std::size_t vt_debug_shellcode::RuntimeInitImageSize() noexcept {
    return static_cast<std::size_t>(RuntimeInitImageEnd - RuntimeInitImageStart);
}




