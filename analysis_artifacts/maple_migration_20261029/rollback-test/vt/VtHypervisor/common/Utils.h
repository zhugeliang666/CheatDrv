#pragma once
#ifndef _NTIFS_H
#define _NTIFS_H
#endif // !_NTIFS_H
#include "fltKernel.h"
#include <string>

typedef struct _CmpTIME_FIELDS
{
	CSHORT Year;        // range [1601...]
	CSHORT Month;       // range [1..12]
	CSHORT Day;         // range [1..31]
	CSHORT Hour;        // range [0..23]
	CSHORT Minute;      // range [0..59]
	CSHORT Second;      // range [0..59]
} CmpTIME_FIELDS;

enum __log_type
{
	LOG_TYPE_DEBUG,
	LOG_TYPE_ERROR,
	LOG_TYPE_DUMP,
	LOG_TYPE_INFO
};

namespace Utils
{
	template <typename T>
	PEPROCESS PidToProcess(T Pid)
	{
		PEPROCESS Process;
		PsLookupProcessByProcessId((HANDLE)Pid, &Process);
		return Process;
	}


	ULONG_PTR QueryModule(PUCHAR moduleName, ULONG_PTR* moduleSize);


	VOID KernelSleep(int TimeValue);

	PUCHAR FileToImage(char * fileBuffer);

	BOOLEAN UpdataRelocation(char * imageBuffer);

	ULONG_PTR QueryModule(PUCHAR moduleName, ULONG_PTR * moduleSize);

	//修复IAT表
	BOOLEAN UpdataIAT(char * imageBuffer);

	//获取到 LoadLibraryExW
	ULONG64 ExportTableFuncByName(char * pData, char * funcName);



	//返回系统模块大小
	NTSTATUS GetNtModuleBaseAndSize(ULONG64 * pModule, ULONG64* pSize);

	//搜索特征
	ULONG_PTR SearchCode(char* moduleName, char* segmentName, char* code, int offset);

	//搜索Nt模块地址
	ULONG_PTR SearchNtCode(char * code, int offset);

	//时间比较
	BOOLEAN TimeCmp();
	TIME_FIELDS GetTime();

	//获取破坏指令长度
	int GetHookLen(ULONG64 Addr, ULONG64 size, BOOLEAN isX64 = true);


	extern _DRIVER_OBJECT testDriver;
	extern size_t imageSize;

	//内存加载驱动
	BOOLEAN LoadDriver(PUCHAR fileBuffer);


	NTSTATUS WideCharToMultiByte(const wchar_t* wideCharStr, char* multiByteStr, ULONG multiByteSize);


	NTSTATUS MultiByteToWideChar(const char* multiByteStr, wchar_t* wideCharStr, ULONG wideCharSize);

	// std::string WstringToUTF8(const std::wstring& str);   // dead code, removed
	// std::wstring UTF8ToWstring(const std::string& str);   // dead code, removed

	TIME_FIELDS GetTime();

	void LogPrintFile(__log_type type, const char* fmt, ...);

	VOID FileLog(CHAR* LogText);

	PVOID FindVadNodeByVirtualAddress(PEPROCESS Process, PVOID Va);

	void DumpBuffer(const WCHAR* TextName, PVOID Buffer, ULONG Size);

	// std::wstring Format(const wchar_t* fmt, ...);   // dead code, removed
}

#define LogFile(format, ...)  \
     Utils::LogPrintFile(LOG_TYPE_DUMP,format , __VA_ARGS__)
