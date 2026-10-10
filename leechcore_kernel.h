#pragma once

#include "FrameWork.h"
#include "leechrpc_types.h"
#include "Struct.h"

#pragma warning(disable : 4201)
#pragma warning(disable : 4996)

#define LC_CONTEXT_VERSION 0xc0e10004
// ACE对扣：伪装为 NPFS 内核文件系统 Tag，规避 BigPool 审计
#define LC_POOL_TAG 'xFpN'
#define LC_CMD_WINPMEM_GET_INFO 0x4000060000000000ULL

typedef struct _LC_CONTEXT LC_CONTEXT, *PLC_CONTEXT;


typedef struct _LC_MAIN_CONTEXT
{
    FAST_MUTEX Lock;
    PLC_CONTEXT FLink;
    BOOLEAN fInitialized;
    struct _MACHENIKE_KERNEL_INTERFACE *UserVar;
} LC_MAIN_CONTEXT, *PLC_MAIN_CONTEXT;

extern LC_MAIN_CONTEXT g_ctx;

#include "Common.h"


typedef struct _LC_CONTEXT
{
    MACHENIKE_KERNEL_INTERFACE *UserVar;
    ULONG version;
    LONG dwHandleCount;
    PLC_CONTEXT FLink;
    FAST_MUTEX Lock;

    LC_CONFIG Config;
    HANDLE hDevice;
    BOOLEAN fMultiThread;


    VOID (*pfnReadScatter)(_In_ PLC_CONTEXT ctxLC, _In_ ULONG cpMEMs, _Inout_ PMEM_SCATTER *ppMEMs);
    VOID (*pfnWriteScatter)(_In_ PLC_CONTEXT ctxLC, _In_ ULONG cpMEMs, _Inout_ PMEM_SCATTER *ppMEMs);
    BOOLEAN (*pfnGetOption)(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
    BOOLEAN (*pfnSetOption)(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _In_ ULONG64 qwValue);
    BOOLEAN (*pfnCommand)(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 fOption, _In_ ULONG cbDataIn,
                          _In_reads_opt_(cbDataIn) PUCHAR pbDataIn, _Out_opt_ PUCHAR *ppbDataOut,
                          _Out_opt_ PULONG pcbDataOut);
    VOID (*pfnClose)(_Inout_ PLC_CONTEXT ctxLC);


    ULONG cMemMap;
    ULONG cMemMapMax;
    PLC_MEMMAP_ENTRY pMemMap;


    WINPMEM_MEMORY_INFO MemInfo;


    PVOID pDeviceContext;
} LC_CONTEXT, *PLC_CONTEXT;

#ifdef __cplusplus
extern "C"
{
#endif


    NTSTATUS LcCore_Initialize(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    VOID LcCore_Cleanup(VOID);


    HANDLE LcCreateEx(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Inout_ PLC_CONFIG pLcCreateConfig, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
    VOID LcClose(_In_opt_ HANDLE hLC);

    VOID LcReadScatter(_In_ HANDLE hLC, _In_ ULONG cMEMs, _Inout_ PMEM_SCATTER *ppMEMs);
    VOID LcWriteScatter(_In_ HANDLE hLC, _In_ ULONG cMEMs, _Inout_ PMEM_SCATTER *ppMEMs);
    BOOLEAN LcCommand(_In_ HANDLE hLC, _In_ ULONG64 fCommand, _In_ ULONG cbDataIn,
                      _In_reads_opt_(cbDataIn) PUCHAR pbDataIn, _Out_opt_ PUCHAR *ppbDataOut,
                      _Out_opt_ PULONG pcbDataOut);
    BOOLEAN LcGetOption(_In_ HANDLE hLC, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
    BOOLEAN LcSetOption(_In_ HANDLE hLC, _In_ ULONG64 fOption, _In_ ULONG64 qwValue);


    BOOLEAN LcMemMap_AddRange(_In_ PLC_CONTEXT ctxLC, _In_ ULONG64 pa, _In_ ULONG64 cb, _In_ ULONG64 paRemap);
    ULONG64 LcMemMap_GetMaxAddress(_In_ PLC_CONTEXT ctxLC);
    BOOLEAN LcMemMap_GetRangesAsStruct(_In_ PLC_CONTEXT ctxLC, _Out_ PUCHAR *ppbDataOut, _Out_opt_ PULONG pcbDataOut);

    BOOLEAN MachenikeReadMsrSafe(ULONG MsrIndex, PULONG64 pValue);
    VOID Main_TriggerUnload(VOID);

#ifdef __cplusplus
}
#endif
