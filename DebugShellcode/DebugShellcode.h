#pragma once

#include "Common.h"
#include "XString.h"
#include "../Core/StackSpoofConfig.h"
#include <cstddef>
#include <cstdint>
#include <type_traits>

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
    struct {
        ULONG_PTR Address;
        ULONG CleanupBytes;
        ULONG Reserved;
    } CallRaxGadgets[VT_SHELLCODE_NATIVE_GADGET_COUNT];
};

static_assert(offsetof(SPOOF_CALL_CONTEXT, OriginalRsp) == 0x30, "SPOOF_CALL_CONTEXT::OriginalRsp 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, SavedPrivateRsp) == 0x38, "SPOOF_CALL_CONTEXT::SavedPrivateRsp 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, GhostRetVa) == 0x40, "SPOOF_CALL_CONTEXT::GhostRetVa 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, JmpFrameSize) == 0x48, "SPOOF_CALL_CONTEXT::JmpFrameSize 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, ArgumentFrame) == 0x50, "SPOOF_CALL_CONTEXT::ArgumentFrame 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, ReturnXmm0) == 0x58, "SPOOF_CALL_CONTEXT::ReturnXmm0 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, NativeCleanupBytes) == 0x60, "SPOOF_CALL_CONTEXT::NativeCleanupBytes 偏移改变");
static_assert(offsetof(SPOOF_CALL_CONTEXT, NativeGadgetTable) == 0x68, "SPOOF_CALL_CONTEXT::NativeGadgetTable 偏移改变");

struct SPOOF_CALL_FRAME {
    ULONG64 Gpr[4];
    ULONG64 Xmm[4];
    ULONG64 StackArgs[VT_SHELLCODE_MAX_STACK_ARGS];
    ULONG64 TargetFunc;
    ULONG ArgCount;
    ULONG StackArgCount;
    ULONG XmmMask;
    ULONG ReturnKind;
};
static_assert(offsetof(SPOOF_CALL_FRAME, TargetFunc) == 0x80, "SPOOF_CALL_FRAME::TargetFunc 偏移改变");
static_assert(offsetof(SPOOF_CALL_FRAME, ArgCount) == 0x88, "SPOOF_CALL_FRAME::ArgCount 偏移改变");
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

extern ULONG_PTR __fastcall SpoofCallNativeInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    ULONG_PTR arg0,
    ULONG_PTR arg1,
    ULONG_PTR arg2,
    ULONG_PTR arg3);
extern ULONG_PTR __fastcall SpoofCallGhostInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    ULONG_PTR arg0,
    ULONG_PTR arg1,
    ULONG_PTR arg2,
    ULONG_PTR arg3);
extern ULONG_PTR __fastcall SpoofCallGhostDeepInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    ULONG_PTR arg0,
    ULONG_PTR arg1,
    ULONG_PTR arg2,
    ULONG_PTR arg3);
extern ULONG_PTR __fastcall SpoofCallNativeFrameInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame);
extern ULONG_PTR __fastcall SpoofCallGhostFrameInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame);
extern ULONG_PTR __fastcall SpoofCallGhostDeepFrameInvoke(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame);
extern __declspec(dllexport) bool __fastcall RuntimeDispatch(void *pUserVar);
}

namespace vt_debug_shellcode_detail {

template <typename T>
struct SpoofCallAlwaysFalse : std::false_type {};

template <typename T>
struct IsSpoofCallFloat : std::integral_constant<bool,
    std::is_same<typename std::decay<T>::type, float>::value ||
    std::is_same<typename std::decay<T>::type, double>::value> {};

template <typename T>
struct IsSpoofCallScalar : std::integral_constant<bool,
    std::is_pointer<typename std::decay<T>::type>::value ||
    std::is_integral<typename std::decay<T>::type>::value ||
    std::is_enum<typename std::decay<T>::type>::value ||
    std::is_same<typename std::decay<T>::type, std::nullptr_t>::value ||
    IsSpoofCallFloat<T>::value> {};

inline ULONG64 SpoofCallFloatBits(float value) noexcept {
    union { float value; ULONG32 bits; } bits = { value };
    return bits.bits;
}

inline ULONG64 SpoofCallFloatBits(double value) noexcept {
    union { double value; ULONG64 bits; } bits = { value };
    return bits.bits;
}

inline void StoreSpoofCallBits(
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame,
    std::size_t index,
    ULONG64 bits,
    bool xmm) noexcept {
    if (!frame || index >= VT_SHELLCODE_MAX_ARGS)
        return;
    if (index < 4) {
        if (xmm) {
            frame->Xmm[index] = bits;
            frame->XmmMask |= static_cast<ULONG>(1u << index);
        } else {
            frame->Gpr[index] = bits;
        }
    } else {
        frame->StackArgs[index - 4] = bits;
    }
}

template <typename T>
inline typename std::enable_if<
    std::is_pointer<typename std::decay<T>::type>::value, void>::type
StoreSpoofCallArgument(
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame,
    std::size_t index,
    T value) noexcept {
    StoreSpoofCallBits(frame, index, reinterpret_cast<ULONG64>(value), false);
}

template <typename T>
inline typename std::enable_if<
    std::is_integral<typename std::decay<T>::type>::value ||
        std::is_enum<typename std::decay<T>::type>::value,
    void>::type
StoreSpoofCallArgument(
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame,
    std::size_t index,
    T value) noexcept {
    StoreSpoofCallBits(frame, index, static_cast<ULONG64>(value), false);
}

inline void StoreSpoofCallArgument(
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame,
    std::size_t index,
    std::nullptr_t) noexcept {
    StoreSpoofCallBits(frame, index, 0, false);
}

inline void StoreSpoofCallArgument(
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame,
    std::size_t index,
    float value) noexcept {
    StoreSpoofCallBits(frame, index, SpoofCallFloatBits(value), true);
}

inline void StoreSpoofCallArgument(
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame,
    std::size_t index,
    double value) noexcept {
    StoreSpoofCallBits(frame, index, SpoofCallFloatBits(value), true);
}

template <typename T>
inline typename std::enable_if<!IsSpoofCallScalar<T>::value, void>::type
StoreSpoofCallArgument(
    vt_debug_shellcode::SPOOF_CALL_FRAME *,
    std::size_t,
    T) noexcept {
    static_assert(SpoofCallAlwaysFalse<T>::value,
                  "SpoofCall 仅支持整数、指针、枚举、nullptr、float 和 double");
}

inline void StoreSpoofCallArguments(
    vt_debug_shellcode::SPOOF_CALL_FRAME *,
    std::size_t) noexcept {}

template <typename T, typename... TArgs>
inline void StoreSpoofCallArguments(
    vt_debug_shellcode::SPOOF_CALL_FRAME *frame,
    std::size_t index,
    T value,
    TArgs... args) noexcept {
    StoreSpoofCallArgument(frame, index, value);
    StoreSpoofCallArguments(frame, index + 1, args...);
}

template <typename TTarget>
inline ULONG64 SpoofCallTargetAddress(TTarget target) noexcept {
    using Target = typename std::decay<TTarget>::type;
    static_assert(std::is_pointer<Target>::value &&
                      std::is_function<typename std::remove_pointer<Target>::type>::value,
                  "SpoofCall target 必须是函数指针");
    return reinterpret_cast<ULONG64>(target);
}

template <typename TResult>
struct SpoofCallResultCast {
    static TResult Cast(
        const vt_debug_shellcode::SPOOF_CALL_CONTEXT *,
        ULONG_PTR rawResult) noexcept {
        return static_cast<TResult>(rawResult);
    }
};

template <typename T>
struct SpoofCallResultCast<T *> {
    static T *Cast(
        const vt_debug_shellcode::SPOOF_CALL_CONTEXT *,
        ULONG_PTR rawResult) noexcept {
        return reinterpret_cast<T *>(rawResult);
    }
};

template <>
struct SpoofCallResultCast<void> {
    static void Cast(
        const vt_debug_shellcode::SPOOF_CALL_CONTEXT *,
        ULONG_PTR) noexcept {}
};

template <>
struct SpoofCallResultCast<float> {
    static float Cast(
        const vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
        ULONG_PTR) noexcept {
        union { ULONG32 bits; float value; } result = {
            static_cast<ULONG32>(context ? context->ReturnXmm0 : 0) };
        return result.value;
    }
};

template <>
struct SpoofCallResultCast<double> {
    static double Cast(
        const vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
        ULONG_PTR) noexcept {
        union { ULONG64 bits; double value; } result = {
            context ? context->ReturnXmm0 : 0 };
        return result.value;
    }
};

inline void ClearSpoofCallContext(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context) noexcept {
    if (!context)
        return;
    volatile ULONG64 *contextWords = reinterpret_cast<volatile ULONG64 *>(context);
    for (std::size_t i = 0; i < sizeof(*context) / sizeof(ULONG64); ++i)
        contextWords[i] = 0;
}

inline void ClearSpoofCallTransient(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context) noexcept {
    if (!context)
        return;
    context->FixupRip = 0;
    context->SavedRbx = 0;
    context->SavedRetAddr = 0;
    context->TargetFunc = 0;
    context->OriginalRsp = 0;
    context->SavedPrivateRsp = 0;
    context->GhostRetVa = 0;
    context->ArgumentFrame = 0;
    context->ReturnXmm0 = 0;
    context->NativeCleanupBytes = 0;
}

inline void InitializeSpoofCallContext(
    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
    ULONG64 callRaxGadget,
    ULONG64 jmpRbxGadget,
    ULONG64 jmpFrameSize,
    ULONG64 nativeGadgetTable) noexcept {
    ClearSpoofCallContext(context);
    if (!context)
        return;
    context->CallRaxGadget = callRaxGadget;
    context->JmpRbxGadget = jmpRbxGadget;
    context->JmpFrameSize = jmpFrameSize;
    context->NativeGadgetTable = nativeGadgetTable;
}

template <typename TResult>
struct SpoofCallFinish {
    static TResult Run(
        PGENERIC_RUNTIME_CONTEXT userVar,
        vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
        ULONG_PTR rawResult) noexcept {
        TResult result = SpoofCallResultCast<TResult>::Cast(context, rawResult);
        ClearSpoofCallTransient(context);
        _InterlockedExchange(&userVar->u->SpoofContextBusy, 0);
        return result;
    }
};

template <>
struct SpoofCallFinish<void> {
    static void Run(
        PGENERIC_RUNTIME_CONTEXT userVar,
        vt_debug_shellcode::SPOOF_CALL_CONTEXT *context,
        ULONG_PTR rawResult) noexcept {
        SpoofCallResultCast<void>::Cast(context, rawResult);
        ClearSpoofCallTransient(context);
        _InterlockedExchange(&userVar->u->SpoofContextBusy, 0);
    }
};

inline bool PrepareSpoofCallContext(
    PGENERIC_RUNTIME_CONTEXT userVar,
    const vt_debug_shellcode::RuntimeSlot* slot) noexcept {
    if (!userVar || !userVar->u || !slot)
        return false;

    const ULONG spoofMode = slot->SpoofMode ? slot->SpoofMode : VT_SHELLCODE_SPOOF_MODE;
    if (spoofMode != VT_SHELLCODE_SPOOF_MODE)
        return false;

#if VT_SHELLCODE_SPOOF_MODE == VT_SHELLCODE_SPOOF_MODE_GHOST_CALL
    if (!slot->GhostRetVa)
        return false;
#endif

    vt_debug_shellcode::SPOOF_CALL_CONTEXT* context = &userVar->u->SpoofContext;
    ClearSpoofCallTransient(context);

#if VT_SHELLCODE_SPOOF_MODE == VT_SHELLCODE_SPOOF_MODE_GHOST_CALL
    context->GhostRetVa = slot->GhostRetVa;
#if VT_SHELLCODE_DEEP_UNWIND
    context->JmpFrameSize = slot->JmpFrameSize;
    if (!slot->OriginalRsp || (slot->OriginalRsp & 0x0F) != 8 ||
        context->JmpFrameSize < 0x28 || (context->JmpFrameSize & 0x0F) != 8)
        return false;
    context->OriginalRsp = slot->OriginalRsp;
#endif
#else
    if (!context->CallRaxGadget || !context->JmpRbxGadget ||
        !context->NativeGadgetTable)
        return false;
#if VT_SHELLCODE_DEEP_UNWIND
    const ULONG nativeFrameAlignment = static_cast<ULONG>(context->JmpFrameSize & 0x0F);
    if (!slot->OriginalRsp || (slot->OriginalRsp & 0x0F) != 8 ||
        (nativeFrameAlignment != 0 && nativeFrameAlignment != 8))
        return false;
    context->OriginalRsp = slot->OriginalRsp;
#endif
#endif

    return true;
}

} // namespace vt_debug_shellcode_detail

template <typename TTarget, typename... TArgs>
inline auto SpoofCall(
    PGENERIC_RUNTIME_CONTEXT userVar,
    TTarget target,
    TArgs... args) noexcept
    -> decltype(std::declval<TTarget>()(std::declval<TArgs>()...)) {
    using TResult = decltype(std::declval<TTarget>()(std::declval<TArgs>()...));
    static_assert(sizeof...(TArgs) <= VT_SHELLCODE_MAX_ARGS,
                  "SpoofCall 参数数量超过 VT_SHELLCODE_MAX_ARGS");
    static_assert(std::is_void<TResult>::value ||
                      (!std::is_reference<TResult>::value &&
                       vt_debug_shellcode_detail::IsSpoofCallScalar<TResult>::value),
                  "SpoofCall 返回值仅支持 void、整数、指针、枚举、float 和 double");
    if (!userVar || !userVar->u || !target) {
        return vt_debug_shellcode_detail::SpoofCallResultCast<TResult>::Cast(nullptr, 0);
    }

    vt_debug_shellcode::SPOOF_CALL_CONTEXT *context = &userVar->u->SpoofContext;
    if (_InterlockedCompareExchange(&userVar->u->SpoofContextBusy, 1, 0) != 0)
        return vt_debug_shellcode_detail::SpoofCallResultCast<TResult>::Cast(context, 0);

    vt_debug_shellcode::SPOOF_CALL_FRAME frame;
    volatile ULONG64 *frameWords = reinterpret_cast<volatile ULONG64 *>(&frame);
    for (std::size_t i = 0; i < sizeof(frame) / sizeof(ULONG64); ++i)
        frameWords[i] = 0;
    frame.TargetFunc = 0;
    frame.ArgCount = 0;
    frame.StackArgCount = 0;
    frame.XmmMask = 0;
    frame.ReturnKind = 0;
    frame.TargetFunc = vt_debug_shellcode_detail::SpoofCallTargetAddress(target);
    frame.ArgCount = static_cast<ULONG>(sizeof...(TArgs));
    frame.StackArgCount = frame.ArgCount > 4 ? frame.ArgCount - 4 : 0;
    frame.ReturnKind = std::is_void<TResult>::value ? 2u :
        (std::is_floating_point<TResult>::value ? 1u : 0u);
    vt_debug_shellcode_detail::StoreSpoofCallArguments(&frame, 0, args...);

    context->TargetFunc = frame.TargetFunc;
    context->ArgumentFrame = reinterpret_cast<ULONG64>(&frame);

    ULONG_PTR rawResult = 0;
#if VT_SHELLCODE_SPOOF_MODE == VT_SHELLCODE_SPOOF_MODE_GHOST_CALL
#  if VT_SHELLCODE_DEEP_UNWIND
    rawResult = SpoofCallGhostDeepFrameInvoke(context, &frame);
#  else
    rawResult = SpoofCallGhostFrameInvoke(context, &frame);
#  endif
#else
    rawResult = SpoofCallNativeFrameInvoke(context, &frame);
#endif
    return vt_debug_shellcode_detail::SpoofCallFinish<TResult>::Run(userVar, context, rawResult);
}

#ifndef VT_SPOOF_CALL
#define VT_SPOOF_CALL(userVar, target, ...) \
    (::SpoofCall((userVar), (target), __VA_ARGS__))
#endif

#ifndef SpoofMessageBoxW
#define SpoofMessageBoxW(userVar, hWnd, text, caption, type) \
    (::SpoofCall( \
        (userVar), \
        (userVar)->Func->MessageBoxW, \
        (hWnd), (text), (caption), (type)))
#endif

inline std::size_t vt_debug_shellcode::X1ImageSize() noexcept {
    return static_cast<std::size_t>(X1End - X1);
}

inline std::size_t vt_debug_shellcode::RuntimeInitImageSize() noexcept {
    return static_cast<std::size_t>(RuntimeInitImageEnd - RuntimeInitImageStart);
}




