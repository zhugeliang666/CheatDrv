#pragma once

#include "../../Core/Common.h"
#include "../../Memory/LeechCoreEngine.h"

class MapleMemory
{
  public:
    static NTSTATUS BindTarget(_In_ ULONG64 TargetCr3, _In_ ULONG64 ImageBase);
    static VOID Reset();

    static BOOLEAN ReadBuffer(_In_ ULONG64 Address, _Out_writes_bytes_(Size) PVOID Buffer, _In_ ULONG Size);
    static BOOLEAN WriteBuffer(_In_ ULONG64 Address, _In_reads_bytes_(Size) const PVOID Buffer, _In_ ULONG Size);
    static BOOLEAN IsUserRange(_In_ ULONG64 Address, _In_ ULONG Size);

    static ULONG64 GetTargetCr3();
    static ULONG64 GetImageBase();

    // 自适应扫描模块内部原生纯零对齐空洞
    static BOOLEAN FindAdaptiveCodeCave(_In_ ULONG RequiredSize, _Out_ PULONG64 OutRva);
    static BOOLEAN FindAdaptiveDataCave(_In_ ULONG RequiredSize, _Out_ PULONG64 OutRva);
    static BOOLEAN ScanZeroCave(_In_ ULONG64 StartAddress, _In_ ULONG RangeSize, _In_ ULONG RequiredSize, _In_ ULONG Alignment, _Out_ PULONG64 OutAddress);

    template <typename T> static BOOLEAN Read(_In_ ULONG64 Address, _Out_ T *Value)
    {
        if (!Value)
            return FALSE;
        RtlZeroMemory(Value, sizeof(T));
        return ReadBuffer(Address, Value, sizeof(T));
    }

    template <typename T> static BOOLEAN Write(_In_ ULONG64 Address, _In_ const T &Value)
    {
        return WriteBuffer(Address, const_cast<PVOID>(static_cast<const void *>(&Value)), sizeof(T));
    }
};
