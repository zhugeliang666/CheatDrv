#include  "ntapi.h"




//r3

void (*DbgUiRemoteBreakin)();

void (*DbgUserBreakPoint)();

ULONG64(*LoadLibraryA)(char* lpLibFileName);

__int64(__fastcall* DbgUiIssueRemoteBreakin)(__int64 a1);


int(__stdcall* GetSystemMetrics)(int nIndex);


DWORD32
(__stdcall *GetWindowThreadProcessId)( 
		_In_ ULONG64 hWnd,
		_Out_opt_ PVOID lpdwProcessId);


ULONG64 gSharedInfo;

	//user32
bool(__stdcall* GetClientRect)(ULONG64 hWnd, PVOID lpRect);

bool(__stdcall* IsChild)(ULONG64 hWndParent, ULONG64 hWnd);

__int64 (*StringCbPrintfW)(unsigned __int16* a1, unsigned __int64 a2, const unsigned __int16* a3, ...);

ULONG64(__stdcall *GetForegroundWindow)();

bool(__stdcall* GetCursorPos)(PVOID lpPoint);

ULONG64(__stdcall * SetCursor)(ULONG64 hCursor);

PVOID RedrawWindow;

bool(__stdcall *ScreenToClient)(ULONG64 hWnd, PVOID lpPoint);

ULONG64(__stdcall* LoadCursorA)(ULONG64 hInstance, ULONG64 lpCursorName);

ULONG64(__stdcall* FindWindowW)(LPCWSTR lpClassName, LPCWSTR lpWindowName);

bool (__stdcall* MessageBeep)(UINT32 uType);

__int64(__fastcall* RtlQueryPerformanceFrequency)(ULONG64* a1);

__int64(__fastcall* RtlQueryPerformanceCounter)(unsigned __int64* a1, __int64 a2);

PVOID D2D1CreateFactory;

PVOID DWriteCreateFactory;

HRESULT(__stdcall *D3DCompile)(
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


SHORT(__stdcall* GetAsyncKeyState)(int vKey);

PVOID(__stdcall* VirtualAlloc)(PVOID lpAddress, SIZE_T dwSize, LONG flAllocationType, LONG flProtect);

int(__stdcall* VirtualLock)(PVOID lpAddress, SIZE_T dwSize);

void(__stdcall* OutputDebugStringW)(const wchar_t* lpOutputString);

ULONG64 VirtualFree;


bool(__stdcall* ReadProcessMemory)(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
bool(__stdcall* WriteProcessMemory)(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);

bool(*LdrpIsCODServiceEnabled)();





ULONG64(*MiFillPteHierarchy)(ULONG64 va, NT::PPTE_HIERARCHY Pout);



signed __int64(__fastcall *MmDeleteKernelStack)(unsigned __int64 a1, unsigned int a2);

__int64(__fastcall* MmCreateKernelStack)(unsigned int a1, unsigned int a2, unsigned __int64 a3);


PVOID(*MmAllocateIndependentPages)(UINT64 NumberOfBytes, UINT64 Node);
VOID(*MmFreeIndependentPages)(IN PVOID VirtualAddress, IN SIZE_T NumberOfBytes);
BOOLEAN(*MmSetPageProtection)(IN PVOID VirtualAddress, IN SIZE_T NumberOfBytes, IN ULONG NewProtect);

NTSTATUS
(NTAPI
	* NtCreateDebugObject)(
		OUT PHANDLE DebugObjectHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN ULONG Flags
		);


NTSTATUS
	(* NtDebugActiveProcess)(
		IN HANDLE ProcessHandle,
		IN HANDLE DebugObjectHandle
		);

