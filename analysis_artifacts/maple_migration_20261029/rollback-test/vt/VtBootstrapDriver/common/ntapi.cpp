#include "ntapi.h"

PVOID(*MmAllocateIndependentPages)(UINT64 NumberOfBytes, UINT64 Node);
VOID(*MmFreeIndependentPages)(IN PVOID VirtualAddress, IN SIZE_T NumberOfBytes);
BOOLEAN(*MmSetPageProtection)(IN PVOID VirtualAddress, IN SIZE_T NumberOfBytes, IN ULONG NewProtect);
