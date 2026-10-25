#pragma once
#include  "../base.h"
#include "ntenums.h"
#include  "ntstructs.h"




extern struct _DEBUG_OBJECT;
extern struct _DBGKM_APIMSG;



//r3
extern void (*DbgUiRemoteBreakin)();

extern void (*DbgUserBreakPoint)();

extern ULONG64(* LoadLibraryA)(
        char* lpLibFileName
);


extern __int64(__fastcall* DbgUiIssueRemoteBreakin)(__int64 a1);

extern int(__stdcall* GetSystemMetrics)(int nIndex);

extern LONG(__stdcall* GetWindowLongW)(HANDLE hWnd, int nIndex);

extern bool(__stdcall* GetClientRect)(ULONG64 hWnd, PVOID lpRect);

extern bool(__stdcall* IsChild)(ULONG64 hWndParent, ULONG64 hWnd);

extern __int64 (*StringCbPrintfW)(unsigned __int16* a1, unsigned __int64 a2, const unsigned __int16* a3, ...);


extern ULONG64(__stdcall* GetForegroundWindow)();

extern bool(__stdcall* GetCursorPos)(PVOID lpPoint);

extern ULONG64(__stdcall* SetCursor)(ULONG64 hCursor);

extern PVOID RedrawWindow;

extern bool(__stdcall* ScreenToClient)(ULONG64 hWnd, PVOID lpPoint);

extern ULONG64(__stdcall* LoadCursorA)(ULONG64 hInstance, ULONG64 lpCursorName);

extern ULONG64(__stdcall* FindWindowW)(LPCWSTR lpClassName, LPCWSTR lpWindowName);

extern bool(__stdcall* MessageBeep)(UINT32 uType);

extern __int64(__fastcall* RtlQueryPerformanceFrequency)(ULONG64* a1);

extern __int64(__fastcall* RtlQueryPerformanceCounter)(unsigned __int64* a1, __int64 a2);


extern PVOID D2D1CreateFactory;

extern PVOID DWriteCreateFactory;

extern HRESULT(__stdcall *D3DCompile)(
    PVOID pSrcData,
    ULONG64 SrcDataSize,
    PVOID pSourceName,
    PVOID pDefines,
    PVOID pInclude,
    PVOID pEntrypoint,
    PVOID pTarget,
    ULONG Flags1,
    ULONG Flags2,
    PVOID* ppCode,
    PVOID* ppErrorMsgs);


extern DWORD32 (__stdcall* GetWindowThreadProcessId)(
    _In_ ULONG64 hWnd,
    _Out_opt_ PVOID lpdwProcessId);


extern SHORT(__stdcall *GetAsyncKeyState)(int vKey);


extern PVOID( __stdcall *VirtualAlloc)(PVOID lpAddress, SIZE_T dwSize, LONG flAllocationType, LONG flProtect);

// VirtualLock: pin a user-模式 page in 物理内存 (no swapping). Used
// from PMO handler to lock dwmcore code pages before installing GetBuffer
// hook so the GPA captured by EPT 安装 never changes due to page-out.
extern int( __stdcall *VirtualLock)(PVOID lpAddress, SIZE_T dwSize);

extern void(__stdcall *OutputDebugStringW)(const wchar_t* lpOutputString);

extern ULONG64 VirtualFree;

extern bool(__stdcall *ReadProcessMemory)(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
extern bool(__stdcall* WriteProcessMemory)(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);

extern PVOID(__stdcall* VirtualAllocEx)(
    HANDLE hProcess,
    PVOID lpAddress,
    SIZE_T dwSize,
    LONG flAllocationType,
    LONG flProtect);



extern HANDLE(*CreateThread)(
    _In_opt_ PVOID lpThreadAttributes,
    _In_ SIZE_T dwStackSize,
    _In_ PVOID lpStartAddress,
    _In_opt_ __drv_aliasesMem PVOID lpParameter,
    _In_ DWORD32 dwCreationFlags,
    _Out_opt_ PVOID lpThreadId
    );


extern bool(* LdrpIsCODServiceEnabled)();


//r0
extern PVOID(__fastcall* MiObtainReferencedVadEx)(unsigned __int64 a1, char a2, int* a3);
extern void(__fastcall* MiUnlockAndDereferenceVad)(PVOID P);

extern __int64(__fastcall* SetDisplayAffinity)(struct tagWND* hwnd, unsigned int a2);

extern NTSTATUS(*NtUserGetClassName)(
    IN __int64 hwnd,
    IN INT32 bReal,
    IN OUT PUNICODE_STRING pstrClassName);
extern __int64(__fastcall* GetProp)(__int64 a1, __int64 a2, __int64 a3);


extern ULONG64(*MiFillPteHierarchy)(ULONG64 va, NT::PPTE_HIERARCHY Pout);



extern ULONG64 gSharedInfo;

extern INT32(__stdcall* RaiseCustomSystemEventTrigger)(PCUSTOM_SYSTEM_EVENT_TRIGGER_CONFIG CustomSystemEventTriggerConfig);

extern INT64(__fastcall* MiGetPteAddress)(UINT64);


extern __int64 (__fastcall *PsSetProcessFaultInformation)(ULONG_PTR a1, int* a2);

extern  PETHREAD(*PsGetNextProcessThread)(PEPROCESS  Process, PETHREAD Thread);

extern __int64(__fastcall* MmAccessFault)(
    ULONG_PTR BugCheckParameter2,
    signed __int64 BugCheckParameter1,
    char a3,
    ULONG_PTR a4);

extern signed __int64(__fastcall* MmDeleteKernelStack)(unsigned __int64 a1, unsigned int a2);

extern __int64(__fastcall *MmCreateKernelStack)(unsigned int a1, unsigned int a2, unsigned __int64 a3);

extern __int64(__fastcall* PspSetContextThreadInternal)(PETHREAD Thread, __int64 a2, char a3, char a4, char a5);

extern __int64(__fastcall *PspGetContextThreadInternal)(
    PETHREAD thread,
    PVOID context,
    KPROCESSOR_MODE Mode,
    KPROCESSOR_MODE mode_1,
    char a5);

//extern PVOID (__stdcall *MmGetVirtualForPhysical)(PHYSICAL_ADDRESS PhysicalAddress);


extern NTSTATUS(NTAPI* ZwCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID StartContext,
    IN ULONG CreateThreadFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PVOID AttributeList
    );


extern __int64(__fastcall *NtUserGetAsyncKeyState)(unsigned int a1);



extern NTSTATUS
(NTAPI
    * NtCreateDebugObject)(
        OUT PHANDLE DebugObjectHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN ULONG Flags
        ); 


extern
NTSTATUS
(*NtDebugActiveProcess)(
    IN HANDLE ProcessHandle,
    IN HANDLE DebugObjectHandle
    );


extern PVOID(*MmAllocateIndependentPages)(UINT64 NumberOfBytes, UINT64 Node);
extern VOID(*MmFreeIndependentPages)(IN PVOID VirtualAddress, IN SIZE_T NumberOfBytes);
extern BOOLEAN(*MmSetPageProtection)(IN PVOID VirtualAddress, IN SIZE_T NumberOfBytes, IN ULONG NewProtect);




EXTERN_C
NTSTATUS
NTAPI ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);



EXTERN_C 
NTSTATUS NTAPI MmCopyVirtualMemory
(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);


EXTERN_C 
NTSTATUS NTAPI ZwQuerySystemInformation
(
    IN NT::SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);


EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb
(
    IN PEPROCESS Process
);




namespace NT
{

    EXTERN_C NTSTATUS NTAPI KeRaiseUserException(NTSTATUS Status);

    EXTERN_C VOID NTAPI KeGenericCallDpc
    (
        _In_ PKDEFERRED_ROUTINE Routine,
        _In_ PVOID Context
    );

    EXTERN_C VOID NTAPI KeSignalCallDpcDone
    (
        _In_ PVOID SystemArgument1
    );

    EXTERN_C bool NTAPI KeSignalCallDpcSynchronize
    (
        _In_ PVOID SystemArgument2
    );

    EXTERN_C PIMAGE_NT_HEADERS(*RtlImageNtHeader)(PVOID DllBase);




    EXTERN_C PVOID NTAPI PsGetProcessWow64Process
    (
        IN PEPROCESS Process
    );



   EXTERN_C NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName
    (
        PUNICODE_STRING ObjectName,
        ULONG Attributes,
        PACCESS_STATE AccessState,
        ACCESS_MASK DesiredAccess,
        POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode,
        PVOID ParseContext OPTIONAL,
        PVOID* Object
    );

    EXTERN_C  WCHAR* NTAPI PsGetProcessImageFileName(PEPROCESS Process);

    EXTERN_C  NTSTATUS NTAPI ZwQueryInformationJobObject(
        HANDLE JobHandle,
        JOBOBJECTINFOCLASS JobInformationClass,
        PVOID JobInformation,
        ULONG JobInformationLength,
        PULONG ReturnLength
    );

   EXTERN_C NTSTATUS NTAPI ZwQueryInformationProcess(
        HANDLE           ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID            ProcessInformation,
        ULONG            ProcessInformationLength,
        PULONG           ReturnLength
    );

   EXTERN_C bool NTAPI ObFindHandleForObject(
        __in PEPROCESS Process,
        __in_opt PVOID Object OPTIONAL,
        __in_opt POBJECT_TYPE ObjectType OPTIONAL,
        __in_opt POBJECT_HANDLE_INFORMATION HandleInformation,
        __out PHANDLE Handle
    );

   EXTERN_C NTSTATUS NTAPI ZwSetInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength
    );

   EXTERN_C bool NTAPI PsIsProcessBeingDebugged(PEPROCESS Process);

   EXTERN_C HANDLE NTAPI
        PsGetProcessInheritedFromUniqueProcessId(
            __in PEPROCESS Process
        );

    EXTERN_C PVOID NTAPI PsGetCurrentProcessWow64Process();

    EXTERN_C  NTSTATUS
        PsGetContextThread(
            __in PETHREAD Thread,
            __inout PCONTEXT ThreadContext,
            __in KPROCESSOR_MODE Mode
        );


    EXTERN_C PVOID NTAPI
        PsGetThreadTeb(
            _In_ PETHREAD Thread
        );


    EXTERN_C PVOID NTAPI
        PsGetThreadWin32Thread(
            _In_ PETHREAD Thread
        );

    EXTERN_C PVOID NTAPI
        PsGetProcessSectionBaseAddress(
            _In_ PEPROCESS Process
        );


    EXTERN_C NTSTATUS
        NTAPI
        ZwSetSystemInformation(
            _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
            _In_reads_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
            _In_ ULONG SystemInformationLength
        );



    EXTERN_C
    NTSTATUS
    MmAdjustWorkingSetSize(IN SIZE_T WorkingSetMinimumInBytes,
        IN SIZE_T WorkingSetMaximumInBytes,
        IN ULONG SystemCache,
        IN BOOLEAN IncreaseOkay);


    EXTERN_C
        PVOID __fastcall RtlFindExportedRoutineByName(CHAR* image, char* funcName);
}


