#pragma once
#include "ia32.hpp"
#include "vt/vcpu.h"

extern PVOID buffer0;
extern PVOID buffer1;
extern PVOID buffer0_hva;
extern PVOID buffer1_hva;
extern PVOID buffer2;
extern PVOID buffer2_hva;



namespace hv {



	size_t read_game_virtual_memory(uint8_t* dst, uint8_t* src, size_t size);
	bool write_game_virtual_memory(uint8_t* dst, uint8_t* src, size_t size);
	bool get_game_path(void* path_buffer, size_t size);
	bool get_game_module_base(void* module_name, void* module_base, size_t* size_ptr);


}



void SetProcessPid(DWORD32 dwPid, DWORD64 cr3);


bool ReadMemoryt(ULONG64 uBaseAddr, PVOID lpBuffer, ULONG nSize);

bool ReadMemoryt_Encrypt(ULONG64 uBaseAddr, PVOID lpBuffer, ULONG nSize);

bool WriteMemoryt(ULONG64 uBaseAddr, PVOID lpBuffer, ULONG nSize);



template<typename T>
T Read(ULONG64 ptr)
{
	T buff;
	
	ReadMemoryt(ptr, &buff, sizeof(T));

	return buff;
}

template<typename T>
void Write(ULONG64 ptr,T buff)
{
	WriteMemoryt(ptr, &buff, sizeof(T));
	
}


bool isValidPtr(ULONG_PTR Ptr);

bool IsKeyDown(uint32_t virtual_key_code);

int GetGamePidByWindow(WCHAR* className, WCHAR* windowName);