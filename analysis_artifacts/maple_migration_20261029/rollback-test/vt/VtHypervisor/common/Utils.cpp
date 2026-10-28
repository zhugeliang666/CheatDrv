#pragma warning( disable : 4201 4311 4302)

#include "Utils.h"
#include <ntimage.h>
#include "ntutils.h"
#include "../kli.hpp"
#include "../xorstr.h"
#include <ntstrsafe.h>
#include <poolmanager/PoolManager.h>


namespace Utils
{
	typedef NTSTATUS(NTAPI *DriverEntryProc)(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg);
	INT64(__fastcall* MiGetPteAddress)(UINT64);
	_DRIVER_OBJECT testDriver;

#pragma code_seg(".vm")


	//内核延时
	VOID KernelSleep(int TimeValue)
	{
		LARGE_INTEGER tin = { 0 };
		tin.QuadPart = -10000 * TimeValue;
		KLI_FN(KeDelayExecutionThread)(KernelMode, FALSE, &tin);
	}




	PUCHAR FileToImage(char * fileBuffer)
	{
		if (!fileBuffer) return NULL;

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)fileBuffer;
		PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(fileBuffer + pDos->e_lfanew);

		//创建imageBuffer
		ULONG sizeofImage = pNts->OptionalHeader.SizeOfImage;
		PUCHAR imageBuffer = (PUCHAR)Util::PoolManagertAllocation(sizeofImage, 'peim');
		if (!imageBuffer) return NULL;
		memset(imageBuffer, 0, sizeofImage);

		//复制PE头
		memcpy(imageBuffer, fileBuffer, pNts->OptionalHeader.SizeOfHeaders);

		ULONG NumberOfSections = pNts->FileHeader.NumberOfSections;

		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNts);

		//拉伸PE 结构
		for (ULONG i = 0; i < NumberOfSections; i++)
		{
			memcpy(imageBuffer + pSection->VirtualAddress, fileBuffer + pSection->PointerToRawData, pSection->SizeOfRawData);
			pSection++;
		}
		//保存虚拟化驱动的地址跟大小
		g_yvt.vtInfo.imageBase = (ULONG64)imageBuffer;
		g_yvt.vtInfo.imageSize = sizeofImage;
		PVOID textBase = nullptr;
		ULONG64 textSize = 0;
		//获取text段的基地址,
		NT::GetSectionData((ULONG64)imageBuffer, _XOR_(".text"), textSize, textBase);
		g_yvt.vtInfo.sectionTextBase = textBase;
		g_yvt.vtInfo.sectionTextSize = textSize;
		return imageBuffer;
	}

	BOOLEAN UpdataRelocation(char * imageBuffer)
	{

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuffer;
		PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imageBuffer + pDos->e_lfanew);

		if (!pNts) return FALSE;

		PIMAGE_DATA_DIRECTORY iRelocation = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		PIMAGE_BASE_RELOCATION pBase = (PIMAGE_BASE_RELOCATION)(imageBuffer + iRelocation->VirtualAddress);

		while (pBase->SizeOfBlock && pBase->VirtualAddress)
		{

			NT::PIMAGE_RELOC RelocationBlock = (NT::PIMAGE_RELOC)((PUCHAR)pBase + sizeof(IMAGE_BASE_RELOCATION));

			UINT32	NumberOfRelocations = (pBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(NT::IMAGE_RELOC);

			for (UINT32 i = 0; i < NumberOfRelocations; i++)
			{
				if (RelocationBlock[i].Type == IMAGE_REL_BASED_DIR64)
				{
					// 64 位
					PUINT64	Address = (PUINT64)((PUINT8)imageBuffer + pBase->VirtualAddress + RelocationBlock[i].Offset);
					UINT64	Delta = (UINT64)(*Address - pNts->OptionalHeader.ImageBase + (PUINT8)imageBuffer);
					*Address = Delta;
				}
				else if (RelocationBlock[i].Type == IMAGE_REL_BASED_HIGHLOW)
				{
					PUINT32	Address = (PUINT32)((PUINT8)imageBuffer + pBase->VirtualAddress + (RelocationBlock[i].Offset));
					UINT32	Delta = (UINT32)(*Address - pNts->OptionalHeader.ImageBase + (PUINT8)imageBuffer);
					*Address = Delta;
				}
			}

			pBase = (PIMAGE_BASE_RELOCATION)((PUCHAR)pBase + pBase->SizeOfBlock);
		}

		return TRUE;
	}

	ULONG_PTR QueryModule(PUCHAR moduleName, ULONG_PTR * moduleSize)
	{
		if (moduleName == NULL) return 0;

		
		NT::RTL_PROCESS_MODULES rtlMoudles = { 0 };
		NT::PRTL_PROCESS_MODULES SystemMoudles = &rtlMoudles;
		BOOLEAN isAllocate = FALSE;
		//测量长度
		ULONG retLen = 0;
		NTSTATUS status = ZwQuerySystemInformation(NT::SystemModuleInformation, SystemMoudles, sizeof(NT::RTL_PROCESS_MODULES), &retLen);

		//分配实际长度内存
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			SystemMoudles = (NT::PRTL_PROCESS_MODULES)Util::PoolManagertAllocation(retLen + sizeof(NT::RTL_PROCESS_MODULES), 'sysi');
			if (!SystemMoudles) return 0;

			memset(SystemMoudles, 0, retLen + sizeof(NT::RTL_PROCESS_MODULES));

			status = ZwQuerySystemInformation(NT::SystemModuleInformation, SystemMoudles, retLen + sizeof(NT::RTL_PROCESS_MODULES), &retLen);

			if (!NT_SUCCESS(status))
			{
				Util::PoolManagerFreePool(SystemMoudles);
				return 0;
			}

			isAllocate = TRUE;
		}

		PUCHAR kernelModuleName = NULL;
		ULONG_PTR moudleBase = 0;

		do
		{
			if (_stricmp((char*)moduleName, _XOR_("ntoskrnl.exe")) == 0 || _stricmp((char*)moduleName, _XOR_("ntkrnlpa.exe")) == 0)
			{
				NT::PRTL_PROCESS_MODULE_INFORMATION moudleInfo = &SystemMoudles->Modules[0];
				moudleBase = (ULONG_PTR)moudleInfo->ImageBase;
				if (moduleSize) *moduleSize = moudleInfo->ImageSize;

				break;
			}


			kernelModuleName = (PUCHAR)Util::PoolManagertAllocation(strlen((char*)moduleName) + 1, 'modn');
			if (!kernelModuleName) break;
			memset(kernelModuleName, 0, strlen((char*)moduleName) + 1);
			memcpy(kernelModuleName, moduleName, strlen((char*)moduleName));
			_strupr((char*)kernelModuleName);


			for (ULONG i = 0; i < SystemMoudles->NumberOfModules; i++)
			{
				NT::PRTL_PROCESS_MODULE_INFORMATION moudleInfo = &SystemMoudles->Modules[i];

				PUCHAR pathName = (PUCHAR)_strupr((char*)moudleInfo->FullPathName);

				if (strstr((char*)pathName, (char*)kernelModuleName))
				{
					moudleBase = (ULONG_PTR)moudleInfo->ImageBase;
					if (moduleSize) *moduleSize = moudleInfo->ImageSize;
					break;
				}
			}

		} while (0);

		if (kernelModuleName)
		{
			Util::PoolManagerFreePool(kernelModuleName);
		}

		if (isAllocate)
		{
			Util::PoolManagerFreePool(SystemMoudles);
		}

		return moudleBase;
	}

	//获取到 LoadLibraryExW
	ULONG64 ExportTableFuncByName(char * pData, char * funcName)
	{
		PIMAGE_DOS_HEADER pHead = (PIMAGE_DOS_HEADER)pData;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pHead->e_lfanew);
		PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)&pNt->OptionalHeader.DataDirectory[0];
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pData + pDir->VirtualAddress);
		ULONG64 funcAddr = 0;

		for (ULONG i = 0; i < pExport->NumberOfNames; i++)
		{
			int* funcAddress = (int*)(pData + pExport->AddressOfFunctions);
			int* names = (int*)(pData + pExport->AddressOfNames);
			short * fh = (short*)(pData + pExport->AddressOfNameOrdinals);
			int index = -1;
			char * name = pData + names[i];

			if (strcmp(name, funcName) == 0)
			{
				index = fh[i];
			}

			if (index != -1)
			{
				funcAddr = (ULONG64)pData + funcAddress[index];
				break;
			}
		}

		if (!funcAddr){
			LOG_DEBUG(_XOR_("don`t find the function:%s"), funcName);
		}
		return funcAddr;
	}

	//修复IAT表
	BOOLEAN UpdataIAT(char * imageBuffer)
	{
		if (!imageBuffer) return FALSE;

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuffer;
		PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imageBuffer + pDos->e_lfanew);
		if (!pNts) return FALSE;

		PIMAGE_DATA_DIRECTORY pimportDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(imageBuffer + pimportDir->VirtualAddress);

		BOOLEAN isSuccess = TRUE;

		for (; import->Name; import++)
		{
			PUCHAR libName = (PUCHAR)(imageBuffer + import->Name);
			ULONG_PTR base = QueryModule(libName, NULL);
			if (!base)
			{
				isSuccess = FALSE;
				break;
			}

			PIMAGE_THUNK_DATA pThuckName = (PIMAGE_THUNK_DATA)(imageBuffer + import->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pThuckFunc = (PIMAGE_THUNK_DATA)(imageBuffer + import->FirstThunk);

			for (; pThuckName->u1.ForwarderString; ++pThuckName, ++pThuckFunc)
			{
				PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)(imageBuffer + pThuckName->u1.AddressOfData);

				ULONG_PTR func = ExportTableFuncByName((char *)base, FuncName->Name);
				if (func)
				{
					pThuckFunc->u1.Function = (ULONG_PTR)func;
				}
				else
				{
					isSuccess = FALSE;
					break;
				}
			}

			if (!isSuccess) break;
		}

		return isSuccess;
	}

	VOID UpdateCookie(char * imageBuffer)
	{
		if (!imageBuffer) return;

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBuffer;
		PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imageBuffer + pDos->e_lfanew);

		//获取NT Header

		if (!pNts) return;

		PIMAGE_DATA_DIRECTORY pConfigDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		PIMAGE_LOAD_CONFIG_DIRECTORY config = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pConfigDir->VirtualAddress + imageBuffer);
		*(PULONG_PTR)(config->SecurityCookie) += 10;
	}

	
	BOOLEAN LoadDriver(PUCHAR fileBuffer)
	{
		PUCHAR imageBase = FileToImage((char*)fileBuffer);
		if (!imageBase) return FALSE;
		BOOLEAN isSuccess = FALSE;

		do
		{
			isSuccess = UpdataRelocation((char*)imageBase);
			if (!isSuccess) break;

			isSuccess = UpdataIAT((char*)imageBase);
			if (!isSuccess) break;

			//修复cookie
			UpdateCookie((char*)imageBase);

			//call 入口点
			PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBase;
			PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imageBase + pDos->e_lfanew);

			ULONG_PTR entry = pNts->OptionalHeader.AddressOfEntryPoint;
			DriverEntryProc EntryPointFunc = (DriverEntryProc)(imageBase + entry);
			NTSTATUS status = EntryPointFunc(&testDriver, NULL);
			if (!NT_SUCCESS(status))
			{
				isSuccess = FALSE;
				break;
			}
			//清空PE头
			memset(imageBase, 0, PAGE_SIZE);


		} while (0);

		if (!isSuccess)
		{
			Util::PoolManagerFreePool(imageBase);
		}

		return isSuccess;
	}




	// 将宽字符转换为多字节字符
	NTSTATUS WideCharToMultiByte(const wchar_t* wideCharStr, char* multiByteStr, ULONG multiByteSize) {
		NTSTATUS status = STATUS_SUCCESS;
		size_t convertedChars = 0;




		// 获取宽字符字符串长度
		size_t wideCharLen = wcslen(wideCharStr);

		// 将宽字符字符串转换为多字节字符字符串
		status = KLI_FN(RtlUnicodeToMultiByteN)(multiByteStr, multiByteSize, (PULONG)&convertedChars, wideCharStr, wideCharLen * sizeof(wchar_t));

		if (!NT_SUCCESS(status)) {
			// 转换失败
			return status;
		}

		// 添加字符串结束符
		multiByteStr[convertedChars] = '\0';

	}

	//将多字节字符转换为宽字符
	NTSTATUS MultiByteToWideChar(const char* multiByteStr, wchar_t* wideCharStr, ULONG wideCharSize) {
		NTSTATUS status = STATUS_SUCCESS;
		size_t convertedChars = 0;

		// 获取多字节字符字符串长度
		size_t multiByteLen = strlen(multiByteStr);

		// 将多字节字符字符串转换为宽字符字符串
		status = KLI_FN(RtlMultiByteToUnicodeN)(wideCharStr, wideCharSize, (PULONG)&convertedChars, multiByteStr, multiByteLen);

		if (!NT_SUCCESS(status)) {
			// 转换失败
			return status;
		}

		// 添加字符串结束符
		wideCharStr[convertedChars] = L'\0';

		return status;
	}

	// WstringToUTF8 / UTF8ToWstring: dead code removed (no callers in project)

	TIME_FIELDS GetTime()
	{
		LARGE_INTEGER TickCount = { 0 };
		LARGE_INTEGER GelinTime = { 0 };
		LARGE_INTEGER LocalTime = { 0 };
		TIME_FIELDS NowFields;
		ULONG Inc = 0;
		ULONG Day = 0;
		ULONG Hour = 0;
		ULONG Minute = 0;
		ULONG Second = 0;

		Inc = KLI_FN(KeQueryTimeIncrement)();
		KeQueryTickCount(&TickCount);
		TickCount.QuadPart *= Inc;
		TickCount.QuadPart /= 10000;
		Day = (ULONG)TickCount.QuadPart / (1000 * 60 * 60 * 24);
		Hour = TickCount.QuadPart % (1000 * 60 * 60 * 24) / (1000 * 60 * 60);
		Minute = TickCount.QuadPart % (1000 * 60 * 60 * 24) % (1000 * 60 * 60) / (1000 * 60);
		Second = TickCount.QuadPart % (1000 * 60 * 60 * 24) % (1000 * 60 * 60) % (1000 * 60) / 1000;

		KeQuerySystemTime(&GelinTime);
		KLI_FN(ExSystemTimeToLocalTime)(&GelinTime, &LocalTime);
		KLI_FN(RtlTimeToTimeFields)(&LocalTime, &NowFields);

		return NowFields;
	}


	PVOID FindVadNodeByVirtualAddress(PEPROCESS Process, PVOID Va)
	{
		LARGE_INTEGER EndingVpn;
		LARGE_INTEGER StartingVpn;

		LONGLONG Vat = (LONGLONG)Va >> 12;

		auto vadRoot = *(PULONG64)((char*)Process + g_yvt.NtapiOffsets.VadRoot);
		NT::_MMVAD* Root = (NT::_MMVAD*)((NT::PRTL_AVL_TREE)vadRoot)->Root;

		if (Root) {
			while (1) {

				EndingVpn.LowPart = Root->Core.EndingVpn;
				EndingVpn.HighPart = Root->Core.EndingVpnHigh;
				if (Vat > EndingVpn.QuadPart)
				{
					Root = (NT::_MMVAD*)Root->Core.ExtraCreateInfo;//right
				}
				else
				{
					StartingVpn.LowPart = Root->Core.StartingVpn;
					StartingVpn.HighPart = Root->Core.StartingVpnHigh;

					if (Vat >= StartingVpn.QuadPart) {
						return Root;
					}
					Root = (NT::_MMVAD*)Root->Core.NextVad;//left
				}

				if (!Root) {
					return 0;
				}
			}
		}
		return 0;
	}


	void DumpBuffer(const WCHAR* TextName, PVOID Buffer, ULONG Size)
	{


		WCHAR* path = (WCHAR*)_XOR_(L"\\??\\C:\\");

		

		WCHAR Name[256];
		memcpy(Name, path, wcslen(path)*2+1);

		wcscat(Name, TextName);

		
		UNICODE_STRING FileName = { 0 };
		RtlInitUnicodeString(&FileName, Name);
		OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
		InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		HANDLE FileHandle;
		IO_STATUS_BLOCK IoStatusBlock;

		NTSTATUS result = ZwCreateFile(&FileHandle, FILE_WRITE_DATA, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		if (NT_SUCCESS(result)) {

			PVOID Temp = Util::PoolManagertAllocation(Size, 'dump');
			if (Temp)
			{
				if (MmIsAddressValid(Buffer))
				{
					RtlCopyMemory(Temp, Buffer, Size);
					ZwWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Temp, Size, NULL, NULL);
				}

				Util::PoolManagerFreePool(Temp);
			}


			ZwClose(FileHandle);
		}
	}



	// Format(const wchar_t* fmt, ...): dead code removed (no callers in project)

	VOID FileLog(CHAR* LogText)
	{


		UNICODE_STRING FileName = { 0 };
		RtlInitUnicodeString(&FileName, _XOR_(L"\\??\\C:\\log.txt"));
		OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
		InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		HANDLE FileHandle;
		IO_STATUS_BLOCK IoStatusBlock;

		NTSTATUS result = ZwCreateFile(&FileHandle, FILE_APPEND_DATA, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		if (NT_SUCCESS(result)) {
			CHAR Str[512] = "";
			sprintf(Str, _XOR_("%s"), LogText);
			ZwWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Str, static_cast<ULONG>(strlen(Str)), NULL, NULL);
			ZwClose(FileHandle);
		}


	}

	void LogPrintFile(__log_type type, const char* fmt, ...)
	{


		char* LogType = NULL;
		LARGE_INTEGER SystemTime = {};
		LARGE_INTEGER LocalTime = {};
		TIME_FIELDS TimeFields = {};
		char TimeBuffer[20] = {};
		char MessageBuffer[412] = {};
		char* OutputFormat = NULL;
		char OutputBuffer[512] = {};
		va_list Args = {};

		switch (type)
		{
		case LOG_TYPE_DEBUG:
		{
			LogType = (char*)_XOR_("[DEBUG]");
			break;
		}
		case LOG_TYPE_DUMP:
		{
			LogType = (char*)_XOR_("[DUMP]");
			break;
		}
		case LOG_TYPE_ERROR:
		{
			LogType = (char*)_XOR_("[ERROR]");
			;			break;
		}
		case LOG_TYPE_INFO:
		{
			LogType = (char*)_XOR_("[INFORMATION]");
			break;
		}
		default:
		{
			break;
		}

		}

		KeQuerySystemTime(&SystemTime);
		ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
		RtlTimeToTimeFields(&LocalTime, &TimeFields);

		RtlStringCchPrintfA(
			TimeBuffer,
			sizeof(TimeBuffer),
			_XOR_("[%02hd:%02hd:%02hd.%03hd]"),
			TimeFields.Hour,
			TimeFields.Minute,
			TimeFields.Second,
			TimeFields.Milliseconds);

		va_start(Args, fmt);
		RtlStringCchVPrintfA(MessageBuffer, sizeof(MessageBuffer), fmt, Args);
		va_end(Args);

		OutputFormat = (char*)_XOR_("%s  %s  %s\r\n");

		RtlStringCchPrintfA(
			OutputBuffer,
			sizeof(OutputBuffer),
			OutputFormat,
			TimeBuffer,
			LogType,
			MessageBuffer);

		//打印
		FileLog(OutputBuffer);

	}







#pragma code_seg()

}

