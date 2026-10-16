#pragma once
#include "FrameWork.h"

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;

    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;

    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _WINPMEM_MEMORY_INFO
{
    LARGE_INTEGER CR3;
    LARGE_INTEGER NtBuildNumber;

    LARGE_INTEGER KernBase;

    LARGE_INTEGER KDBG;

    LARGE_INTEGER KPCR[64];

    LARGE_INTEGER PfnDataBase;
    LARGE_INTEGER PsLoadedModuleList;
    LARGE_INTEGER PsActiveProcessHead;



    LARGE_INTEGER NtBuildNumberAddr;



    LARGE_INTEGER Padding[0xfe];

    LARGE_INTEGER NumberOfRuns;


    PHYSICAL_MEMORY_RANGE Run[100];

} WINPMEM_MEMORY_INFO, *PWINPMEM_MEMORY_INFO;
