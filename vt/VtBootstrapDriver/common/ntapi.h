#pragma once
#include "../base.h"
#include "ntenums.h"
#include "ntstructs.h"

extern PVOID(*MmAllocateIndependentPages)(UINT64 NumberOfBytes, UINT64 Node);
extern VOID(*MmFreeIndependentPages)(IN PVOID VirtualAddress, IN SIZE_T NumberOfBytes);
extern BOOLEAN(*MmSetPageProtection)(IN PVOID VirtualAddress, IN SIZE_T NumberOfBytes, IN ULONG NewProtect);

namespace NT
{
    EXTERN_C NTSTATUS NTAPI ZwQuerySystemInformation(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
}
