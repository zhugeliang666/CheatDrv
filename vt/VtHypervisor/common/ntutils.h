#pragma once
#include "fltKernel.h"
#include <utility>
#include <vector>
#include <string>
#include "./ntapi.h"
#include  "./ntstructs.h"



#define DRIVER_TAG 'dHyH'

typedef struct _NTAPI_OFFSETS
{
	ULONG SeAuditProcessCreationInfoOffset;
	ULONG BypassProcessFreezeFlagOffset;
	ULONG ThreadHideFromDebuggerFlagOffset;
	ULONG ThreadBreakOnTerminationFlagOffset;
	ULONG PicoContextOffset;
	ULONG RestrictSetThreadContextOffset;
	ULONG DbgSsReserved;


	//_TEB
	ULONG ClientId;
	ULONG SuppressDebugMsg;

	//_ETHREAD
	ULONG Win32StartAddress;
	ULONG StartAddress;
	ULONG RundownProtect;
	ULONG SameThreadPassiveFlags;
	ULONG SameThreadApcFlags;
	ULONG CrossThreadFlags;
	ULONG AllowKernelWritesToExecutableMemory;
	ULONG AllowUserWritesToExecutableMemory;
	ULONG ThreadListEntry;
	//_KTHREAD
	ULONG TrapFrame;
	ULONG UserTime;
	ULONG KernelTime;
	ULONG CycleTime;


	ULONG ApcState;
	//kprocess
	ULONG  DirectoryTableBase;

	//EPROCESS
	ULONG  VadRoot;
	ULONG VadHint;
	ULONG ExitTime;
	ULONG Flags;
	ULONG SectionBaseAddress;
	ULONG SectionObject;
	ULONG RundownProtect_Process;
	ULONG DebugPort;
	ULONG InheritedFromUniqueProcessId;
	ULONG Peb;
	ULONG Ldr;
	ULONG64 ImageFilePointer;

	//_FILE_OBJECT
	ULONG FileName;


	//_PEB_LDR_DATA
	ULONG InLoadOrderModuleList;

	//_PEB
	ULONG ProcessParameters;

	//_RTL_USER_PROCESS_PARAMETERS
	ULONG CurrentDirectory;


	//_CURDIR
	ULONG DosPath;

		

	//_KAPC_STATE
	ULONG Process;

	//ObpObjectTypes
	NT::POBJECT_TYPE* ObpObjectTypes;

	//PsProcessType
	NT::POBJECT_TYPE* PsProcessType;
	//PsThreadType
	NT::POBJECT_TYPE* PsThreadType;
	//DbgkDebugObjectType
	NT::POBJECT_TYPE* DbgkDebugObjectType;


	bool* PsWatchEnabled;

	ULONG64* PerfGlobalGroupMask;

	UINT32* PspNotifyEnableMask;

	INT16* atomLayer;
	INT16* atomDispAffinity;


}NTAPI_OFFSETS;

typedef struct _REPROTECT_CONTEXT
{
	PMDL   Mdl;
	PUCHAR LockedVa;
} REPROTECT_CONTEXT, * PREPROTECT_CONTEXT;


typedef struct _MODULE_INFO
{
	uint64_t imageBase;
	uint64_t imageSize;
	PVOID sectionTextBase;
	uint64_t sectionTextSize;
	
}MODULE_INFO,*PMODULE_INFO;




struct PROTECT_HWND_INFO {
	HANDLE realHwnd;
	HANDLE fakeHwnd;
	UINT64 tagHwnd;
};


struct PROTECT_PROCESS_INFO {

	HANDLE handle;
	PEPROCESS process;
	ULONG64 cr3;
	ULONG64 baseAddress;
	ULONG64 baseSize;
};

struct SYSTEM_MODULE_INFO {
	PVOID moduleBase;
	ULONG moduleSize;
	char moduleName[256];
};



class YVT
{

	

public:

	YVT();

	// 6 个未使用的 std::vector 全局列表已删除（dead code）


	//定义一个互斥锁变量
	KSPIN_LOCK g_lock;



	uint64_t CurrentWindowsBuildNumber;

	// Host environment detection: probed at DriverMain 条目项 (before hv::start),
	// so guest sees the *real* hypervisor leaf — our VT layer hasn't started
	// disguising as Microsoft Hv yet. Used by DwmInit to select between
	// thunk-based signature scans (VMware/nested) and direct prologue
	// signature scan (bare-metal, where dwmcore prologue layout differs).
	bool is_vmware_host;

	NTAPI_OFFSETS NtapiOffsets;

	ULONG NumberOfActiveDebuggers;

	PEPROCESS csrss;
	PETHREAD csrssMainThread;
	PEPROCESS exploer;
	PEPROCESS dwm;
	PETHREAD  dwmMainThread;
	PEPROCESS svchost;
	PEPROCESS nvidia;


	MODULE_INFO ntdllInfo;
	MODULE_INFO kernelbaseInfo;
	MODULE_INFO kernel32Info;
	MODULE_INFO shell32Info;
	MODULE_INFO apihelpInfo;
	MODULE_INFO user32Info;

	MODULE_INFO dwmcoreInfo;
	MODULE_INFO d3d11Info;
	MODULE_INFO dxgiInfo;
	MODULE_INFO d2d1Info;
	MODULE_INFO dwriteInfo;

	MODULE_INFO mapDllInfo;

	MODULE_INFO vtInfo;
	MODULE_INFO driverInfo;
	MODULE_INFO ntosInfo;

	MODULE_INFO vm2Info;
	MODULE_INFO idataInfo;

	MODULE_INFO unHideInfo[10] = { 0 };

	



	bool isInitFinish = false;

	void get_window_number();

	void InitNtSymbol();

	void add_protect_process(PEPROCESS process);

	void clear_game_process(PEPROCESS process);

	void add_game_process(PEPROCESS process);

	void remove_game_process(PEPROCESS process);

	void remove_protect_process(PEPROCESS process);

	
};

extern YVT g_yvt;


namespace NT
{

	NTSTATUS GetModuleInfo(PEPROCESS process, char* moduleName, PULONG_PTR imageBase, SIZE_T* imageSize);

	bool GetSectionData(CONST CHAR* ImageName, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress);

	bool GetSectionData(ULONG64 baseAddress, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress);

	UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess);

	PVOID FindSignature(PVOID Memory, ULONG64 Size, PCSZ Pattern, PCSZ Mask);

	PVOID FindSignatureSection(PVOID BaseAddress, CONST char* SectionName, PCSZ Pattern, PCSZ Mask);

	PEPROCESS PidToProcess(HANDLE Pid);

	PEPROCESS GetProcessByName(CONST WCHAR* ProcessName);

	PVOID UAlloc(SIZE_T size, ULONG Protect = PAGE_READWRITE, bool load = true);

	PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, const CHAR* ExportedFunctionName);

	VOID UFree(PVOID address, SIZE_T size);

	NTSTATUS AnsiToUtf8(PCSTR ansiStr, PSTR utf8Str, SIZE_T utf8Size);

}
