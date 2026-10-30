#pragma once

//#define wstr_ntdll_dll						XorU32(0xD22E2014) //ntdll.dll
//#define wstr_primary_host_exe			XorU32(0xAB1D2F54) //primary host executable
//#define wstr_ACE_Base64_dll					XorU32(0x570B5EAF) //ACE-Base64.dll
//#define wstr_ucrtbase_dll					XorU32(0x2E1D6317) //ucrtbase.dll
//#define wstr_KERNEL32_dll					XorU32(0x8F7EE672) //KERNEL32.DLL
//#define wstr_KERNELBASE_dll					XorU32(0x6267DEE4) //KERNELBASE.dll
//#define wstr_USER32_dll						XorU32(0xD3361080) //USER32.dll
//#define wstr_dbgcore_DLL					XorU32(0xC9FB0DE)  //dbgcore.DLL
//
//#define str_RtlInitializeCriticalSection	XorU32(0xA3DACB6C)	//RtlInitializeCriticalSection
//#define str_RtlEnterCriticalSection			XorU32(0x3A53F3B8)	//RtlEnterCriticalSection
//#define str_RtlLeaveCriticalSection			XorU32(0xC769E819)	//RtlLeaveCriticalSection
//#define str_RtlAcquireSRWLockExclusive		XorU32(0x5BDA9C67)	//RtlAcquireSRWLockExclusive
//#define str_RtlReleaseSRWLockExclusive		XorU32(0x65C90EB8)	//RtlReleaseSRWLockExclusive
//#define str_RtlAcquireSRWLockShared			XorU32(0xD3090A9C)	//RtlAcquireSRWLockShared
//#define str_RtlReleaseSRWLockShared			XorU32(0xE5CB7B8B)	//RtlReleaseSRWLockShared
//#define str_RtlTryAcquireSRWLockExclusive	XorU32(0x584DE300)	//RtlTryAcquireSRWLockExclusive
//#define str_strcpy_s						XorU32(0x782B60F)	//strcpy_s
//#define str_wcscpy_s						XorU32(0x711C07B9)  //wcscpy_s
//#define str_memmove							XorU32(0xE1F415E6)  //memmove
//#define str_memset							XorU32(0x4593D4CD)  //memset
//#define str_memcpy							XorU32(0x3DBDDF77)	//memcpy
//#define str_OutputDebugStringA				XorU32(0xCB36305E)	//OutputDebugStringA
//#define str_OutputDebugStringW				XorU32(0xCB363074)	//OutputDebugStringW
//#define str_GetTickCount64					XorU32(0x6B0F457A)	//GetTickCount64
//#define str_TerminateProcess				XorU32(0xFC26A9CE)	//TerminateProcess
//#define str_CreateFileW						XorU32(0xDE99D57F)	//CreateFileW
//#define str_CloseHandle						XorU32(0xB3ED1C00)	//CloseHandle
//#define str_VirtualQuery					XorU32(0x38E3B95D)	//VirtualQuery
//#define str_stdio_common_vsprintf_s			XorU32(0x1C5EFAA8)	//__stdio_common_vsprintf_s
//#define str_stdio_common_vswprintf_s		XorU32(0x857092A9)	//__stdio_common_vswprintf_s
//#define str_malloc							XorU32(0x3F31DE8)   //malloc
//#define str_free							XorU32(0xC23F2CCC)  //free
//#define str_msize							XorU32(0x40DAC9EF)  //_msize
//#define str_realloc							XorU32(0xB1AE4962)  //realloc
//
//#define str_GetAsyncKeyState				XorU32(0x60393138)  //GetAsyncKeyState
//#define str_MiniDumpWriteDump				XorU32(0x7CBD4F68)  //MiniDumpWriteDump
//
//#define str_BP_AZCharacter_C									XorU32(0x33C7B183)
//#define str_BP_DFMCharacter_C									XorU32(0x7983D753)
//#define str_BP_DFMCharacter_SafeHouse_C							XorU32(0x8A2FB427)
//#define str_BP_DFM_Character_Breakthrough_C						XorU32(0xE94ECDA5)
//
//#define str_BP_RangeTargetCharacter_C							XorU32(0xAB1EBD0)
//#define str_BP_DFMCharacter_AI_DT_C								XorU32(0x89F99ADB)
//#define str_BP_DFMCharacter_AI_Shark_C							XorU32(0x20EC6FE2)
//#define str_BP_DFMCharacter_AI_Maurice_C						XorU32(0x9D0AC77)
//#define str_BP_DFMAICharacter_ShielderLight_C					XorU32(0xAFA9F6EC)
//#define str_BP_DFMAICharacter_HeavyMachineGun_C					XorU32(0xBF42D84C)
//#define str_BP_DFMCharacter_AI_DT_RPG_C							XorU32(0xC6411925)
//#define str_BP_DFMCharacter_AI_Crocodile_C						XorU32(0xDC0E26A7)
//#define str_BP_DFMCharacter_TutorialPlayerAi_C					XorU32(0xEB1FD17B)
//#define str_BP_DFMCharacter_AI_HS_C								XorU32(0x4396CE56)
//#define str_BP_DFMAICharacter_Firebat_C							XorU32(0xC33BC5AB)
//#define str_BP_DFMAICharacter_Firebat_HS_C						XorU32(0x8D578D07)
//#define str_BP_DFMAICharacter_ShielderLight_HS_C				XorU32(0xF1991C86)
//#define str_BP_DFMAICharacter_HeavyMachineGun_HS_C				XorU32(0x4074326)
//#define str_BP_DFMCharacter_AI_AlwaysFall_HSSniper_C			XorU32(0x80845C0C)
//#define str_BP_DFMCharacter_AI_AlwaysFall_DTSniper_C			XorU32(0x8E431111)
//#define str_BP_DFMCharacter_AI_BossRCV_C						XorU32(0xB8321DB5)
//#define str_BP_DFMCharacter_AI_Reis_C							XorU32(0x73BBD508)
//#define str_BP_DFMAICharacter_Boss03_C							XorU32(0x83DA386C)
//#define str_BP_DFCharacter_Romytheus_Assault_C					XorU32(0x80B2D57F)
//#define str_BP_DFCharacter_Romytheus_Shielder_C					XorU32(0x49F958BC)
//#define str_BP_DFCharacter_Romytheus_C							XorU32(0x7EC963A1)
//#define str_BP_DFMAICharacter_ShielderLight_HS_Tide_C			XorU32(0x972EF7D7)
//#define str_BP_DFMCharacter_AI_Tide_HS_C						XorU32(0xD742DC71)
//#define str_BP_DFMCharacter_AI_Tide_DT_C						XorU32(0xBFE6BA07)
//#define str_BP_DFMCharacter_Boss05_C							XorU32(0x7D2A9026)
//#define str_BP_DFMAICharacter_Boss05_C							XorU32(0x84D6576E)
//#define str_BP_DFMCharacter_AI_Boss05_C							XorU32(0x9657CE1D)
//#define str_BP_DFMCharacter_AI_Boss05_HENC_C					XorU32(0x99DCE07C)
//#define str_BP_DFMCharacter_Boss06_C							XorU32(0x7DA89FA7)
//#define str_BP_DFMAICharacter_Boss06_C							XorU32(0x855466EF)
//#define str_BP_DFMCharacter_AI_Boss06_C							XorU32(0x96D5DD9E)
//#define str_BP_DFMCharacter_AI_Boss06_Warder_C					XorU32(0x98B99DB2)
//#define str_BP_DFMCharacter_AI_Boss06_WarDen_C					XorU32(0x96C15FAE)
//#define str_BP_DFMCharacterAI_Boss06_Warden_C					XorU32(0xD5A2BE2D)
//#define str_BP_DFMCharacterAI_Boss06_Warder_C					XorU32(0xD79AFC31)
//#define str_BP_DFMCharacter_AI_Boss06_WarDen_Attandent_C		XorU32(0xA7522BC4)
//#define str_BP_DFMCharacter_AI_AlwaysFall_HSSniper_Tide_C		XorU32(0x552D5FD1)
//#define str_BP_DFMCharacter_Boss07_NewGuard_C					XorU32(0x8491DC04)
//#define str_BP_DFMCharacter_AI_Boss07_C							XorU32(0x9753ED1F)
//#define str_BP_InventoryPickup_C								XorU32(0xC44D1DEB)
//#define str_BP_InventoryPickup_Container_C						XorU32(0x90C7196D)
//#define str_BP_InventoryPickup_WeapModule_C						XorU32(0x67746405)
//#define str_BP_InventoryPickup_FromSingleItemContainer_C		XorU32(0x53E2FE28)
//#define str_BP_Inventory_DeadBody_C								XorU32(0x3B7F609E)


#define wstr_ntdll_dll						(0xD22E2014) //ntdll.dll
#define wstr_ACE_Base64_dll					(0x570B5EAF) //ACE-Base64.dll
#define wstr_ucrtbase_dll					(0x2E1D6317) //ucrtbase.dll
#define wstr_KERNEL32_dll					(0x8F7EE672) //KERNEL32.DLL
#define wstr_KERNELBASE_dll					(0x6267DEE4) //KERNELBASE.dll
#define wstr_USER32_dll						(0xD3361080) //USER32.dll
#define wstr_dbgcore_DLL					(0xC9FB0DE)  //dbgcore.DLL
#define wstr_notepad_exe					(0x2847CB65) //notepad.exe

#define str_RtlInitializeCriticalSection	(0xA3DACB6C)	//RtlInitializeCriticalSection
#define str_RtlEnterCriticalSection			(0x3A53F3B8)	//RtlEnterCriticalSection
#define str_RtlLeaveCriticalSection			(0xC769E819)	//RtlLeaveCriticalSection
#define str_RtlAcquireSRWLockExclusive		(0x5BDA9C67)	//RtlAcquireSRWLockExclusive
#define str_RtlReleaseSRWLockExclusive		(0x65C90EB8)	//RtlReleaseSRWLockExclusive
#define str_RtlAcquireSRWLockShared			(0xD3090A9C)	//RtlAcquireSRWLockShared
#define str_RtlReleaseSRWLockShared			(0xE5CB7B8B)	//RtlReleaseSRWLockShared
#define str_RtlTryAcquireSRWLockExclusive	(0x584DE300)	//RtlTryAcquireSRWLockExclusive
#define str_strcpy_s						(0x782B60F)	//strcpy_s
#define str_wcscpy_s						(0x711C07B9)  //wcscpy_s
#define str_memmove							(0xE1F415E6)  //memmove
#define str_memset							(0x4593D4CD)  //memset
#define str_memcpy							(0x3DBDDF77)	//memcpy
#define str_OutputDebugStringA				(0xCB36305E)	//OutputDebugStringA
#define str_OutputDebugStringW				(0xCB363074)	//OutputDebugStringW
#define str_GetTickCount64					(0x6B0F457A)	//GetTickCount64
#define str_TerminateProcess				(0xFC26A9CE)	//TerminateProcess
#define str_CreateFileW						(0xDE99D57F)	//CreateFileW
#define str_CloseHandle						(0xB3ED1C00)	//CloseHandle
#define str_VirtualQuery					(0x38E3B95D)	//VirtualQuery
#define str_stdio_common_vsprintf_s			(0x1C5EFAA8)	//__stdio_common_vsprintf_s
#define str_stdio_common_vswprintf_s		(0x857092A9)	//__stdio_common_vswprintf_s
#define str_malloc							(0x3F31DE8)   //malloc
#define str_free							(0xC23F2CCC)  //free
#define str_msize							(0x40DAC9EF)  //_msize
#define str_realloc							(0xB1AE4962)  //realloc

#define str_GetAsyncKeyState				(0x60393138)  //GetAsyncKeyState
#define str_MiniDumpWriteDump				(0x7CBD4F68)  //MiniDumpWriteDump
#define str_MessageBoxW					(0xA0EB10B3)  //MessageBoxW

#define str_BP_AZCharacter_C									(0x33C7B183)
#define str_BP_DFMCharacter_C									(0x7983D753)
#define str_BP_DFMCharacter_SafeHouse_C							(0x8A2FB427)
#define str_BP_DFM_Character_Breakthrough_C						(0xE94ECDA5)
#define str_BP_DFMCharacter_TutorialPlayerAi_C					(0xEB1FD17B)
