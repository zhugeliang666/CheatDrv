#include  "ntutils.h"
#include "../base.h"

#include <ctime>
#include <intrin.h>
#include <string>
#include <memory>
#include <ntimage.h>

#include "../kli.hpp"

#include  "./ntapi.h"
#include  "./ntstructs.h"
#include "symbol_resolver.h"
#include "Utils.h"
#include "../poolmanager/PoolManager.h"


YVT g_yvt;

#pragma code_seg(".vm")

namespace NT
{

#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))
#define RVA2(Instr, InstrSize, Off) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + Off))

	bool RtlStringContains(PSTRING Str, PSTRING SubStr, bool CaseInsensitive)
	{
		if (Str == NULL || SubStr == NULL || Str->Length < SubStr->Length)
			return FALSE;

		CONST USHORT NumCharsDiff = (Str->Length - SubStr->Length);
		STRING Slice = *Str;
		Slice.Length = SubStr->Length;

		for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= 1)
		{
			if (KLI_FN(RtlEqualString)(&Slice, SubStr, CaseInsensitive))
				return TRUE;
		}
		return FALSE;
	}


	bool GetProcessInfo(CONST CHAR* Name, ULONG64& ImageSize, PVOID& ImageBase)
	{
		ULONG Bytes;
		NTSTATUS Status;

		Status = KLI_FN(ZwQuerySystemInformation)(SystemModuleInformation, 0, 0, &Bytes);
		PSYSTEM_MODULE_INFORMATION Mods = (PSYSTEM_MODULE_INFORMATION)Util::PoolManagertAllocation(Bytes, 'sysi');
		if (Mods == NULL)
			return FALSE;

		RtlSecureZeroMemory(Mods, Bytes);


		Status = KLI_FN(ZwQuerySystemInformation)(SystemModuleInformation, Mods, Bytes, &Bytes);


		if (NT_SUCCESS(Status) == FALSE)
		{
			Util::PoolManagerFreePool(Mods);
			return FALSE;
		}

		STRING TargetProcessName;
		KLI_FN(RtlInitString)(&TargetProcessName, Name);

		for (ULONG i = 0; i < Mods->ModulesCount; i++)
		{
			STRING CurrentModuleName;
			KLI_FN(RtlInitString)(&CurrentModuleName, (PCSZ)Mods->Modules[i].FullPathName);

			if (RtlStringContains(&CurrentModuleName, &TargetProcessName, TRUE) != NULL)
			{
				if (Mods->Modules[i].ImageSize != NULL)
				{
					ImageSize = Mods->Modules[i].ImageSize;
					ImageBase = Mods->Modules[i].ImageBase;
					Util::PoolManagerFreePool(Mods);
					return TRUE;
				}
			}
		}

		Util::PoolManagerFreePool(Mods);
		return FALSE;
	}




	bool GetSectionData(CONST CHAR* ImageName, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress)
	{
		ULONG64 ImageSize = 0;
		PVOID ImageBase = 0;

		if (GetProcessInfo(ImageName, ImageSize, ImageBase) == FALSE)
			return FALSE;

		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
		PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)(DosHeader->e_lfanew + (ULONG64)ImageBase);
		ULONG NumSections = NtHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

		STRING TargetSectionName;
		KLI_FN(RtlInitString)(&TargetSectionName, SectionName);

		for (ULONG i = 0; i < NumSections; i++)
		{
			STRING CurrentSectionName;
			KLI_FN(RtlInitString)(&CurrentSectionName, (PCSZ)Section->Name);
			if (CurrentSectionName.Length > 8)
				CurrentSectionName.Length = 8;

			if (KLI_FN(RtlCompareString)(&CurrentSectionName, &TargetSectionName, FALSE) == 0)
			{
				SectionSize = Section->Misc.VirtualSize;
				SectionBaseAddress = (PVOID)((ULONG64)ImageBase + (ULONG64)Section->VirtualAddress);

				return TRUE;
			}
			Section++;
		}

		return FALSE;
	}

	bool GetSectionData(ULONG64 ImageBase, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress)
	{

		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
		PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)(DosHeader->e_lfanew + (ULONG64)ImageBase);
		ULONG NumSections = NtHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

		STRING TargetSectionName;
		KLI_FN(RtlInitString)(&TargetSectionName, SectionName);

		for (ULONG i = 0; i < NumSections; i++)
		{
			STRING CurrentSectionName;
			KLI_FN(RtlInitString)(&CurrentSectionName, (PCSZ)Section->Name);
			if (CurrentSectionName.Length > 8)
				CurrentSectionName.Length = 8;

			if (KLI_FN(RtlCompareString)(&CurrentSectionName, &TargetSectionName, FALSE) == 0)
			{
				SectionSize = Section->Misc.VirtualSize;
				SectionBaseAddress = (PVOID)((ULONG64)ImageBase + (ULONG64)Section->VirtualAddress);

				return TRUE;
			}
			Section++;
		}

		return FALSE;

	}


	PVOID FindSignature(PVOID Memory, ULONG64 Size, PCSZ Pattern, PCSZ Mask)
	{
		ULONG64 SigLength = strlen(Mask);
		if (SigLength > Size) return NULL;

		for (ULONG64 i = 0; i < Size - SigLength; i++)
		{
			bool Found = TRUE;
			for (ULONG64 j = 0; j < SigLength; j++)
				Found &= Mask[j] == '?' || Pattern[j] == *((PCHAR)Memory + i + j);

			if (Found)
				return (PCHAR)Memory + i;
		}
		return NULL;
	}

	PVOID FindSignatureSection(PVOID BaseAddress, const char* SectionName, PCSZ Pattern, PCSZ Mask)
	{

		PVOID textbase = nullptr;
		SIZE_T textsize = 0;

		if (!GetSectionData((ULONG64)BaseAddress, SectionName, textsize, textbase))
			return nullptr;

		return FindSignature(textbase, textsize, Pattern, Mask);
	}


	NTSTATUS GetModuleX64(PEPROCESS process, PPEB peb, PUNICODE_STRING moduleName, PULONG_PTR imageBase, SIZE_T* imageSize) {

		SIZE_T retSize = 0;
		NTSTATUS status;
		ULONG_PTR module = 0;
		status = KLI_FN(MmCopyVirtualMemory)(process, peb, process, peb, 8, UserMode, &retSize);
		PPEB_LDR_DATA pebLdr = (PPEB_LDR_DATA)(peb->Ldr);
		LIST_ENTRY currentEntry = pebLdr->InLoadOrderModuleList;
		PLDR_DATA_TABLE_ENTRY nextEntry = (PLDR_DATA_TABLE_ENTRY)(currentEntry.Flink);
		while (nextEntry != (PVOID)&currentEntry) {


			PWCH baseDllName = nextEntry->BaseDllName.Buffer;
			UNICODE_STRING uBaseName;
			KLI_FN(RtlInitUnicodeString)(&uBaseName, baseDllName);

			if (KLI_FN(RtlCompareUnicodeString)(&uBaseName, moduleName, TRUE) == 0) {
				//LOG("baseDllName = %ls", uBaseName.Buffer);
				if (imageBase)
					*(PULONG_PTR)imageBase = (ULONG_PTR)nextEntry->DllBase;
				if (imageSize)
					*imageSize = nextEntry->SizeOfImage;
				//LOG("[Image Info] Image base = %llx  Image Size = %llx", nextEntry->DllBase, nextEntry->SizeOfImage);
				return STATUS_SUCCESS;
			}

			nextEntry = (PLDR_DATA_TABLE_ENTRY)nextEntry->InLoadOrderLinks.Flink;
		}
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS GetModuleInfo(PEPROCESS process, char* moduleName, PULONG_PTR imageBase, SIZE_T* imageSize)
	{
		if (!process || !moduleName)
			return STATUS_INVALID_PARAMETER;

		NTSTATUS status;

		KAPC_STATE apc_state = { 0 };

		ANSI_STRING aMouduleName = { 0 };
		UNICODE_STRING uModuleName = { 0 };
		KLI_FN(RtlInitAnsiString)(&aMouduleName, moduleName);
		status = KLI_FN(RtlAnsiStringToUnicodeString)(&uModuleName, &aMouduleName, TRUE);
		if (!NT_SUCCESS(status)) {

			return STATUS_UNSUCCESSFUL;
		}


		KLI_FN(KeStackAttachProcess)((PRKPROCESS)process, &apc_state);

		PPEB peb = (PPEB)KLI_FN(PsGetProcessPeb)(process);

		status = GetModuleX64((PEPROCESS)process, peb, &uModuleName, imageBase, imageSize);

		if (!NT_SUCCESS(status)) {
			KLI_FN(KeUnstackDetachProcess)(&apc_state);
			return STATUS_UNSUCCESSFUL;
		}


		KLI_FN(KeUnstackDetachProcess)(&apc_state);
		return STATUS_SUCCESS;
	}


	PEPROCESS PidToProcess(HANDLE Pid)
	{
		PEPROCESS Process;


		//if (g_yvt.isInitFinish) {

		//	OriginalPsLookupProcessByProcessId(Pid, &Process);

		//}
		//else {

			KLI_FN(PsLookupProcessByProcessId)((HANDLE)Pid, &Process);

		//}
		return Process;
	}


	PEPROCESS GetProcessByName(CONST WCHAR* ProcessName)
	{
		NTSTATUS Status;
		ULONG Bytes;

		KLI_FN(ZwQuerySystemInformation)(SystemProcessInformation, NULL, NULL, &Bytes);


		PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)Util::PoolManagertAllocation(Bytes, 'sysi');
		if (ProcInfo == NULL)
			return NULL;


		Status = KLI_FN(ZwQuerySystemInformation)(SystemProcessInformation, ProcInfo, Bytes, &Bytes);


		if (NT_SUCCESS(Status) == FALSE)
		{
			Util::PoolManagerFreePool(ProcInfo);
			return NULL;
		}

		UNICODE_STRING ProcessImageName;
		KLI_FN(RtlCreateUnicodeString)(&ProcessImageName, ProcessName);

		for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
		{
			if (Entry->ImageName.Buffer != NULL)
			{
				if (KLI_FN(RtlCompareUnicodeString)(&Entry->ImageName, &ProcessImageName, TRUE) == 0)
				{
					PEPROCESS CurrentPeprocess = PidToProcess(Entry->ProcessId);
					Util::PoolManagerFreePool(ProcInfo);
					return CurrentPeprocess;
				}
			}
		}

		Util::PoolManagerFreePool(ProcInfo);
		return NULL;
	}

	PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, const CHAR* ExportedFunctionName)
	{
		if (!ModuleBase || !ExportedFunctionName)
			return 0;

		KAPC_STATE State;
		PVOID FunctionAddress = 0;
		bool attached = false;
		if (TargetProcess != NULL) {
			KLI_FN(KeStackAttachProcess)((PRKPROCESS)TargetProcess, &State);
			attached = true;
		}

		__try
		{
			do
			{
				PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
				if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
					break;

				PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(DosHeader->e_lfanew + (ULONG64)ModuleBase);
				if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
					break;

				IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				if (ImageDataDirectory.Size == 0 || ImageDataDirectory.VirtualAddress == 0)
					break;

				PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase + ImageDataDirectory.VirtualAddress);
				ULONG* Address = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfFunctions);
				ULONG* Name = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNames);
				USHORT* Ordinal = (USHORT*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNameOrdinals);

				STRING TargetExportedFunctionName;
				KLI_FN(RtlInitString)(&TargetExportedFunctionName, ExportedFunctionName);

				for (size_t i = 0; i < ExportDirectory->NumberOfNames; i++)
				{
					STRING CurrentExportedFunctionName;
					KLI_FN(RtlInitString)(&CurrentExportedFunctionName, (PCHAR)ModuleBase + Name[i]);

					if (KLI_FN(RtlCompareString)(&TargetExportedFunctionName, &CurrentExportedFunctionName, TRUE) == 0)
					{
						FunctionAddress = (PVOID)((ULONG64)ModuleBase + Address[Ordinal[i]]);
						break;
					}
				}

			} while (0);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			FunctionAddress = 0;
		}

		if (attached)
			KLI_FN(KeUnstackDetachProcess)(&State);

		return FunctionAddress;
	}

	bool GetNtdllFunction(PVOID& funcPtr, const CHAR* ExportedFunctionName)
	{


		PVOID ntdllBase{};
		size_t ntdllSize{};

		if (NT_SUCCESS(GetModuleInfo(g_yvt.dwm, (char*)_XOR_("ntdll.dll"), (PULONG_PTR)&ntdllBase, &ntdllSize)))
		{
			funcPtr = GetExportedFunctionAddress(g_yvt.dwm, ntdllBase, ExportedFunctionName);
			return true;
		}


		return false;
	}

	UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess)
	{
		UNICODE_STRING TruncatedFullImageName = { 0 };

		__try
		{
			PUNICODE_STRING FullImageName = (PUNICODE_STRING) * (ULONG64*)((ULONG64)TargetProcess + g_yvt.NtapiOffsets.SeAuditProcessCreationInfoOffset);
			if (FullImageName->Buffer != NULL || FullImageName->Length != 0)
			{
				for (size_t i = FullImageName->Length / 2; i > 0; i--)
				{
					if (FullImageName->Buffer[i] == L'\\')
					{
						RtlInitUnicodeString(&TruncatedFullImageName, &FullImageName->Buffer[i + 1]);
						break;
					}
				}
			}
		}

		__except (EXCEPTION_EXECUTE_HANDLER)
		{

		}

		return TruncatedFullImageName;
	}

	PVOID UAlloc(SIZE_T size, ULONG Protect, bool load) {
		PVOID allocBase = nullptr;

		

		if (!KLI_FN(ZwAllocateVirtualMemory)(ZwCurrentProcess(), &allocBase, 0, &size, MEM_COMMIT, Protect)) {
			if (load)
				RtlZeroMemory(allocBase, size);
		}
		return  allocBase;
	}
	VOID UFree(PVOID base, SIZE_T size) {
		if (!base) return;
		KLI_FN(ZwFreeVirtualMemory)(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
	}


	NTSTATUS AnsiToUtf8(PCSTR ansiStr, PSTR utf8Str, SIZE_T utf8Size) {
		NTSTATUS status = STATUS_SUCCESS;

		// 临时缓冲区，用于转换
		ANSI_STRING ansiStrbuffer = { 0 };
		KLI_FN(RtlInitAnsiString)(&ansiStrbuffer, ansiStr);

		UNICODE_STRING unicodeBuffer = { 0 };

		// 将ANSI字符串转换为Unicode字符串
		status = KLI_FN(RtlAnsiStringToUnicodeString)((PUNICODE_STRING)&unicodeBuffer, &ansiStrbuffer, true);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		// 计算需要的UTF-8缓冲区大小
		ULONG utf8Length = 0;
		status = RtlUnicodeToUTF8N(
			NULL,                       // 目标缓冲区
			0,                          // 目标缓冲区大小
			&utf8Length,                // 返回需要的长度
			unicodeBuffer.Buffer,       // 源字符串
			unicodeBuffer.Length        // 源字符串长度
		);

		if (!NT_SUCCESS(status) || utf8Length > utf8Size) {
			ExFreePool(unicodeBuffer.Buffer);
			return STATUS_BUFFER_TOO_SMALL;
		}

		// 执行实际转换
		status = RtlUnicodeToUTF8N(
			(PCHAR)utf8Str,             // 目标缓冲区
			utf8Size,                   // 目标缓冲区大小
			&utf8Length,                // 返回实际转换的长度
			unicodeBuffer.Buffer,       // 源字符串
			unicodeBuffer.Length        // 源字符串长度
		);

		// 确保字符串以null结尾
		if (NT_SUCCESS(status)) {
			utf8Str[utf8Length] = '\0';
		}

		// 释放内存
		ExFreePool(unicodeBuffer.Buffer);

		return status;
	}

	//NTSTATUS AnsiToUtf8(PCSTR ansiStr, PSTR utf8Str, SIZE_T utf8Size) {


	// NTSTATUS status = STATUS_执行成功;

	//	// 临时缓冲区，用于转换
	//	WCHAR unicodeStr[512];  // 假设最大转换长度为256
	//	ANSI_STRING ansiStrbuffer = { 0 };
	//	KLI_FN(RtlInitAnsiString)(&ansiStrbuffer, ansiStr);

	//	UNICODE_STRING unicodeBuffer = { 0 };

	//	// 将ANSI字符串转换为Unicode字符串
	//	status = KLI_FN(RtlAnsiStringToUnicodeString)((PUNICODE_STRING)&unicodeBuffer, &ansiStrbuffer, true);
	//	if (!NT_SUCCESS(status)) {
	// 返回执行状态码;
	//	}

	//	UTF8_STRING utf8Buffer = { 0 };
	// utf8Buffer.缓冲区 = utf8Str;

	//	// 将Unicode字符串转换为UTF-8字符串
	//	status = KLI_FN(RtlUnicodeStringToUTF8String)(&utf8Buffer, &unicodeBuffer, true);
	//	if (!NT_SUCCESS(status)) {
	//		ExFreePool(unicodeBuffer.Buffer);
	// 返回执行状态码;
	//	}
	//	RtlZeroMemory(utf8Str, utf8Size);
	//	RtlCopyMemory(utf8Str, utf8Buffer.Buffer, utf8Buffer.Length + 1);
	//	ExFreePool(unicodeBuffer.Buffer);
	//	ExFreePool(utf8Buffer.Buffer);
	// 返回执行状态码;
	//}




}



void YVT::InitNtSymbol()
{



	g_yvt.csrss = NT::GetProcessByName(_XOR_(L"csrss.exe"));

	g_yvt.exploer = NT::GetProcessByName(_XOR_(L"explorer.exe"));
	g_yvt.dwm = NT::GetProcessByName(_XOR_(L"dwm.exe"));

	// dwm.exe may not exist yet at driver load time (early boot, or session
	// not yet active on this machine). Without this guard, the subsequent
	// NT::GetModuleInfo / KeStackAttachProcess calls AV on a NULL process
	// 指针, bugcheck 0x1E STATUS_ACCESS_VIOLATION at KeStackAttachProcess+0x2a.
	if (!g_yvt.dwm) {
		LOG_DEBUG(_XOR_("[InitNtSymbol] dwm.exe not present yet — skipping module/symbol init\n"));
		return;
	}


	NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("ntdll.dll"), (PULONG_PTR)&ntdllInfo.imageBase, &ntdllInfo.imageSize);
	NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("KernelBase.dll"), (PULONG_PTR)&kernelbaseInfo.imageBase, &kernelbaseInfo.imageSize);
	NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("kernel32.dll"), (PULONG_PTR)&kernel32Info.imageBase, &kernel32Info.imageSize);
	NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("user32.dll"), (PULONG_PTR)&user32Info.imageBase, &user32Info.imageSize);
	NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("d2d1.dll"), (PULONG_PTR)&d2d1Info.imageBase, &d2d1Info.imageSize);
	NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("d3d11.dll"), (PULONG_PTR)&d3d11Info.imageBase, &d3d11Info.imageSize);


	PVOID temp;

	NT::GetNtdllFunction(temp, _XOR_("DbgUiIssueRemoteBreakin"));
	*(ULONG64*)&DbgUiIssueRemoteBreakin = (ULONG64)temp;

	NT::GetNtdllFunction(temp, _XOR_("RtlQueryPerformanceCounter"));
	*(ULONG64*)&RtlQueryPerformanceCounter = (uint64_t)temp;

	NT::GetNtdllFunction(temp, _XOR_("RtlQueryPerformanceFrequency"));
	*(ULONG64*)&RtlQueryPerformanceFrequency = (uint64_t)temp;

	*(ULONG64*)&StringCbPrintfW = d3d11Info.imageBase + 0x4BA0C;



	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)kernelbaseInfo.imageBase, _XOR_("VirtualAlloc"));
	*(ULONG64*)&VirtualAlloc = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)kernelbaseInfo.imageBase, _XOR_("VirtualLock"));
	*(ULONG64*)&VirtualLock = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)kernelbaseInfo.imageBase, _XOR_("OutputDebugStringW"));
	*(ULONG64*)&OutputDebugStringW = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)kernelbaseInfo.imageBase, _XOR_("ReadProcessMemory"));
	*(ULONG64*)&ReadProcessMemory = (uint64_t)temp;


	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)kernelbaseInfo.imageBase, _XOR_("WriteProcessMemory"));
	*(ULONG64*)&WriteProcessMemory = (uint64_t)temp;

	

	D2D1CreateFactory = NT::GetExportedFunctionAddress(g_yvt.dwm, (PVOID)g_yvt.d2d1Info.imageBase, _XOR_("D2D1CreateFactory"));

	KAPC_STATE apc;
	KeStackAttachProcess(g_yvt.dwm, &apc);

	DWriteCreateFactory = (PVOID)RVA((ULONG64)NT::FindSignatureSection((PVOID)g_yvt.d2d1Info.imageBase, _XOR_(".text"), _XOR_("\x4c\x8d\x47\x00\x48\x8d\x15\x00\x00\x00\x00\xE8\x00\x00\x00\x00"), _XOR_("xxx?xxx????x????")) + 11, 5);
		 LOG_INFO(_XOR_("DWriteCreateFactory address = %p\n"), DWriteCreateFactory);


	KeUnstackDetachProcess(&apc);

	ULONG_PTR d3dcompilerdllBase = 0;
	SIZE_T d3dcompilerdllSize = 0;
	NT::GetModuleInfo(dwm, (char*)_XOR_("d3dcompiler_47.dll"), &d3dcompilerdllBase, &d3dcompilerdllSize);
	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)d3dcompilerdllBase, _XOR_("D3DCompile"));
	*(ULONG64*)&D3DCompile = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("LoadCursorA"));
	*(ULONG64*)&LoadCursorA = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("ScreenToClient"));
	*(ULONG64*)&ScreenToClient = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("SetCursor"));
	*(ULONG64*)&SetCursor = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("GetCursorPos"));
	*(ULONG64*)&GetCursorPos = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("IsChild"));
	*(ULONG64*)&IsChild = (uint64_t)temp;


	

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("GetClientRect"));
	*(ULONG64*)&GetClientRect = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("GetForegroundWindow"));
	*(ULONG64*)&GetForegroundWindow = (uint64_t)temp;


	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("FindWindowW"));
	*(ULONG64*)&FindWindowW = (uint64_t)temp;

	// Used by render::tick during overlay-hide windows to force DWM to
	// repaint the game window — clears any overlay residue our previous
	// frames left in the backbuffer before fakeTexture snapshots it.
	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("RedrawWindow"));
	RedrawWindow = temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("MessageBeep"));
	*(ULONG64*)&MessageBeep = (uint64_t)temp;


	LOG_DEBUG(_XOR_("FindWindowW = %p\n"), FindWindowW);

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("GetWindowThreadProcessId"));
	*(ULONG64*)&GetWindowThreadProcessId = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("GetSystemMetrics"));
	*(ULONG64*)&GetSystemMetrics = (uint64_t)temp;

	temp = NT::GetExportedFunctionAddress(dwm, (PVOID)user32Info.imageBase, _XOR_("GetAsyncKeyState"));
	*(ULONG64*)&GetAsyncKeyState = (uint64_t)temp;


	
	ntosInfo.imageBase = Utils::QueryModule((PUCHAR)_XOR_("ntoskrnl.exe"), &ntosInfo.imageSize);
	const auto kernel_key = symbol_resolver::make_kernel_image_key(
		ntosInfo.imageBase,
		static_cast<ULONG>(ntosInfo.imageSize));

	LOG_DEBUG(_XOR_("[InitNtSymbol] kernel key build=%lu stamp=0x%08lX size=0x%lX\n"),
		kernel_key.build_number, kernel_key.time_date_stamp, kernel_key.image_size);

	symbol_resolver::KernelSymbolTable kernel_symbols;
	if (symbol_resolver::resolve_kernel_symbols_from_hardcoded(
			kernel_key,
			ntosInfo.imageBase,
			symbol_resolver::kNtapiKernelSymbols,
			symbol_resolver::kNtapiKernelSymbolCount,
			kernel_symbols,
			true) ||
		(symbol_resolver::resolve_kernel_symbols_prefer_hardcoded(
			kernel_key,
			ntosInfo.imageBase,
			symbol_resolver::kNtapiKernelSymbols,
			symbol_resolver::kNtapiKernelSymbolCount,
			kernel_symbols,
			false))) {
		symbol_resolver::assign_ntapi_kernel_symbols(kernel_symbols);
	}

	symbol_resolver::KernelFieldTable kernel_fields;
	if (symbol_resolver::resolve_kernel_fields_from_hardcoded(
			kernel_key,
			symbol_resolver::kNtapiKernelFields,
			symbol_resolver::kNtapiKernelFieldCount,
			kernel_fields,
			true) ||
		(symbol_resolver::resolve_kernel_fields_prefer_hardcoded(
			kernel_key,
			symbol_resolver::kNtapiKernelFields,
			symbol_resolver::kNtapiKernelFieldCount,
			kernel_fields,
			false))) {
		symbol_resolver::assign_ntapi_offsets(kernel_fields, g_yvt.NtapiOffsets);
	}



}


YVT::YVT()
{
	Util::PoolManagerInitialize();
	LOG_DEBUG(_XOR_("BEGINE\n"));

	// Do not resolve symbols from the global constructor anymore.  In the
	// resident/mapDriver flow the PoolManager is independent-page only, so the
	// MmAllocateIndependentPages trio must be supplied by the boot 上下文 first.
	// DriverMain applies that boot API and then calls InitNtSymbol on an expanded
	// stack before hv::start allocates vCPU/stack/pml4 blocks.
}
#pragma code_seg()
