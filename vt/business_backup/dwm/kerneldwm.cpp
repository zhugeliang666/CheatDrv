#include "kerneldwm.h"
#include "../kli.hpp"
#include "../xorstr.h"
#include "../vt/hv.h"
#include "../vt/mm.h"
#include "../poolmanager/PoolManager.h"
#include <hv/hv.h>
#include "../hook/vtcallhook.h"
#include "../hook/epthook.h"
#include "../hook/hde64.h"


#define Call dwm::UsermodeCallback2.Call

#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)

typedef hde64s HDE;
#define HDE_DISASM(code, hs) hde64_disasm(code, hs)

DWORD g_offset_stack;
DWORD g_kvashadow;


#pragma data_seg(".vm2data")
NTSTATUS(*OriginalNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE) = NULL;
NTSTATUS(*OriginalNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) = NULL;
#pragma data_seg()


#pragma code_seg(".vm2")
NTSTATUS HookedNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{

	//PFILE_OBJECT FileObject;
	////閻㈢洡rotect閸掋倖鏌囪ぐ鎾冲燬ection閺勵垰鎯侀崣顖涘⒔鐞涘矉绱版稉鈧閼割剙鐨㈢憰浣瑰⒔鐞涘瞼娈慏LL閸滃瓖XE閻ㄥ嫰鍏橀弰鐤璭ction閸欘垱澧界悰宀娈
	//if (SectionPageProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
	//	//閼惧嘲褰嘑ileHandle鐎电懓绨查惃鍑ILE_OBJEC閳ユ柡鈧鏂垮従閺堝嬪灉娴狀剚鍔呴崗纾嬪彯閻ㄥ嫭鍨氶崨妯烘嫲娴ｆ粎鏁
	//	if (NT_SUCCESS(ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL))) {//閼惧嘲褰囬弬鍥︽㈢电呰杽


	//		ANSI_STRING FileName = { 0 };
	//		if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&FileName, &FileObject->FileName, true)))
	//		{
	//			char strFileName[512] = { 0 };
	//			char lowstr[512] = { 0 };

	//			if (FileName.Buffer && FileName.Length > 0 && FileName.Length < sizeof(strFileName))
	//			{
	//				// 婢跺秴鍩楃涙冾儊娑撴彃鍩岄弫鎵绮
	//				memcpy(strFileName, FileName.Buffer, FileName.Length);
	//				strFileName[FileName.Length] = '\0';
	//				
	//				// 婢跺秴鍩楅崚鏉跨毈閸愭瑦鏆熺紒鍕鑻熸潪顒佸床娑撳搫鐨閸?
	//				memcpy(lowstr, strFileName, FileName.Length + 1);
	//				_strlwr(lowstr);
	//			}

	//			RtlFreeAnsiString(&FileName);

	//			// 濡鈧閺屻儲妲搁崥锕瀵橀崥顐ゆ窗閺嶅槏LL閸氬秶袨
	//			if (lowstr[0] != '\0' && (
	//				strstr(lowstr, _XOR_("nvfbc.dll")) != NULL ||
	//				strstr(lowstr, _XOR_("nvfbc64.dll")) != NULL ||
	//				strstr(lowstr, _XOR_("nvencodeapi.dll")) != NULL ||
	//				strstr(lowstr, _XOR_("nvencodeapi64.dll")) != NULL
	//				))
	//			{
	//		}


	//		ObDereferenceObject(FileObject);//閺鎯х磾鐎电穒leObject閻ㄥ嫬绱╅悽?
	//	}
	//}



	if (
		ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer &&
		ObjectAttributes->ObjectName->Length &&
		ObjectAttributes->ObjectName->MaximumLength
		)
	{

		if (wcscmp(ObjectAttributes->ObjectName->Buffer, _XOR_(L"{46E29DC9-EF87-48E3-A497-7D40369DAC79}")) == 0)
		{
			uint64_t dummy = 10;
			hv::vmcall_test(&dummy);
			return STATUS_INVALID_PARAMETER_6;
		}



	}


	//閳ユ粏绻戦崶鐐┾偓婵嗗煂閻鐔割劀閻ㄥ嫧鈧婊嗙儲閺夊簱鈧婵嗩槱,鐎瑰本鍨欻ook鏉╁洨鈻
	auto Status = OriginalNtCreateSection(
		SectionHandle,
		DesiredAccess,
		ObjectAttributes,
		MaximumSize,
		SectionPageProtection,
		AllocationAttributes,
		FileHandle
	);
	return Status;
}


NTSTATUS HookedNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// 閼惧嘲褰囪ぐ鎾冲犳潻娑氣柤娣団剝浼

	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer &&
		ObjectAttributes->ObjectName->Length &&
		ObjectAttributes->ObjectName->MaximumLength)
	{




		if (wcscmp(ObjectAttributes->ObjectName->Buffer, _XOR_(L"{46E29DC9-EF87-48E3-A497-7D40369DAC79}")) == 0)
		{
			uint64_t dummy = 10;
			hv::vmcall_test(&dummy);
			return STATUS_INVALID_PARAMETER;
		}
	}

	NTSTATUS Status = OriginalNtOpenSection(
		SectionHandle,
		DesiredAccess,
		ObjectAttributes
	);

	return Status;
}

#pragma data_seg()

#pragma pack(push, 1)
typedef struct _RET_ABS
{
	UINT8 opcode0;
	UINT32 addr_low;
	UINT8 opcode1;
	UINT8 opcode2;
	UINT8 opcode3;
	UINT8 opcode4;
	UINT32 addr_high;
	UINT8 opcode5;
}RET_ABS;
#pragma pack(pop)

namespace dwm {


	ULONG64 g_pxe_base;
	ULONG64 g_ppe_base;
	ULONG64 g_pde_base;
	ULONG64 g_pte_base;

	PEPROCESS process;
	ULONG64 threadOffset;
	ULOGN64 dwmPresentThreadId;
	PETHREAD drawThread;
	ULOGN64 HookFakeStack;
	ULOGN64 CallBackRetFix;
	ULOGN64 PtrXorKey;

	bool isExit = false;



	PVOID* PlaceVmt;
	PVOID* IDXGISwapChainDWM;
	PVOID CDXGISwapChain;
	ULONG64 originalPresentImpl;
	ULONG64 oriPresentMPO;
	ULONG64 oriPresentMultiplaneOverlay;
	ULONG64 oriCheckMultiplaneOverlay;
	ULONG64 oriPresentImplCore;
	ULONG64 oriGetDisplaySurfaceDataCore;
	ULONG64 oriGetDisplaySurfaceDataForDIB;
	ULONG64 oriAcquireNextFrameOffset;
	ULONG64 oriDwmGetDxSharedSurface;

	ULONG64 oriRtlpAddVectoredHandler;//82080
	ULONG64 preAddress;
	ULONG64 postAddress;
	PMDL hookedOverPresentMdl;
#pragma code_seg(".vm")


	typedef ULONG(*pUlongFun)(...);

	typedef struct  _HZDATA
	{
		ULONGLONG Width;
		ULONGLONG Height;
		ULONGLONG Data;
	}HZDATA;

#define vfunc(Class, Index) (*(ULONG_PTR*)((*(ULONG64*)(Class)) + (Index * 8)))


#define VT
//#define AIM

	//PVOID GetVFunc(PVOID Class, ULONG Index) {
	//	return (*(PVOID**)Class)[Index];
	//}
	VOID InstallDwmHook() {


		VMB

		// vtcallhook::find_blank / install use PsGetCurrentProcess() to read
		// guest memory at user-mode VAs (ntdll/dxgi). We must be attached to
		// the DWM process here 閳?otherwise CR3 points at the loader process
		// (system/services) which doesn't have DWM's user-mode mappings.
		KAPC_STATE _install_apc;
		if (!g_yvt.dwm) { LOG_DEBUG(_XOR_("[TEST] InstallDwmHook: g_yvt.dwm is NULL 閳?abort\n")); VME return; }
		KLI_FN(KeStackAttachProcess)(g_yvt.dwm, &_install_apc);

		// === Trampoline pool init (multi-slot, one-shot per pool) ===
		if (!hv::g_ghv->tramp_pool.user_ready && g_yvt.ntdllInfo.imageBase) {
			bootstrap_tramp_pool(
				(ULONG64)g_yvt.ntdllInfo.imageBase,
				g_yvt.ntdllInfo.imageSize,
				/*is_kernel=*/ false);
		}

		if (oriPresentMultiplaneOverlay)
		{


			LARGE_INTEGER interval;


#ifndef  VT
			exceptionhook::CreateHook(process, (PVOID)oriPresentMultiplaneOverlay, (exceptionhook::fnCallback)HookedPresentMultiplaneOverlay,exceptionhook::eHookType::int3Jmp);
			exceptionhook::EnableHook(process, (PVOID)oriPresentMultiplaneOverlay, true);

			

#else
			{
				// TEST MODE: only install the first hook (oriPresentMultiplaneOverlay)
				// to verify the install/hit chain. Other hooks restored after pass.
				LOG_DEBUG(_XOR_("[TEST] InstallDwmHook entry: oriPMO=%p ntdll=%p dwm_proc=%p\n"),
					(void*)oriPresentMultiplaneOverlay,
					(void*)g_yvt.ntdllInfo.imageBase,
					(void*)g_yvt.dwm);

				ULONG64 b1 = vtcallhook::find_blank((ULONG64)g_yvt.ntdllInfo.imageBase + 0x2000);
				LOG_DEBUG(_XOR_("[TEST] find_blank => 0x%llX\n"), b1);

				if (!b1) {
					LOG_DEBUG(_XOR_("[TEST] find_blank FAILED 閳?abort install\n"));
					KLI_FN(KeUnstackDetachProcess)(&_install_apc);
					VME
					return;
				}

				// Detach before install 閳?vmcall_vh_install loops via affinity
				// switching which requires APCs enabled (KeStackAttachProcess
				// disables APCs and prevents scheduler from migrating threads).
				KLI_FN(KeUnstackDetachProcess)(&_install_apc);

				bool ok = vtcallhook::install(g_yvt.dwm, (PVOID)oriPresentMultiplaneOverlay, b1, 1, true,  true);
				LOG_DEBUG(_XOR_("[TEST] vtcallhook::install returned %d\n"), (int)ok);

				// Reattach for any subsequent driver-side work that needs DWM CR3.
				KLI_FN(KeStackAttachProcess)(g_yvt.dwm, &_install_apc);

				// === Anti-screenshot hooks DISABLED in driver-side install ===
				// GetBuffer / Present / Present1 used to be installed here but
				// driver-side install requires DWM attach + module info walks.
				// Per new architecture, these will be re-installed from inside
				// handle_present_multiplane_overlay handler via hv::Call+EPT
				// path so driver layer stays free of attach traces beyond the
				// single PresentMultiplaneOverlay hook bootstrap above.

			}
#endif // ! VT

		


			

			

		}


		


		//if (oriPresentImplCore) {

		//	exceptionhook::CreateHook(process, (PVOID)oriPresentImplCore, (exceptionhook::fnCallback)HookPresentImplCore, exceptionhook::eHookType::int3);
		//	exceptionhook::EnableHook(process, (PVOID)oriPresentImplCore, true);

		//}

		KLI_FN(KeUnstackDetachProcess)(&_install_apc);

		VME


	}

	VOID RemoveDwmHook() {

		VMB

		KAPC_STATE apc;

		KLI_FN(KeStackAttachProcess)(process, &apc);

#ifdef VT
		vtcallhook::uninit();
#endif // VT

	


		LARGE_INTEGER interval;

		interval.QuadPart = -((LONGLONG)1000 * 10000);
		KLI_FN(KeDelayExecutionThread)(KernelMode, FALSE, &interval);


		KLI_FN(KeUnstackDetachProcess)(&apc);




		if (hookedOverPresentMdl) {
			MmUnlockPages(hookedOverPresentMdl);
			IoFreeMdl(hookedOverPresentMdl);
		}


		VME
	}

//#define TEST


	VOID DwmInit() {

		VMB

		LOG_DEBUG(_XOR_("[TEST] DwmInit enter, g_yvt.dwm=%p\n"), (void*)g_yvt.dwm);

		// g_yvt.dwm captured during InitNtSymbol may be NULL if dwm.exe wasn't
		// up yet. Retry lookup here.
		if (!g_yvt.dwm)
			g_yvt.dwm = NT::GetProcessByName(_XOR_(L"dwm.exe"));

		LOG_DEBUG(_XOR_("[TEST] DwmInit: g_yvt.dwm=%p\n"), (void*)g_yvt.dwm);

		process = g_yvt.dwm;

		if (!process) {
			LOG_DEBUG(_XOR_("[TEST] DwmInit: g_yvt.dwm STILL NULL 閳?abort\n"));
			VME
			return;
		}

		PVOID modulebase = nullptr;
		SIZE_T modulesize = 0;
		KAPC_STATE apc;
		KLI_FN(KeStackAttachProcess)(g_yvt.dwm, &apc);




		if (!NT_SUCCESS(NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("dxgi.dll"), (PULONG_PTR)&modulebase, &modulesize)) ||
			!modulebase || !modulesize)
		{
			LOG_DEBUG(_XOR_("[TEST] DwmInit: dxgi.dll not ready - abort\n"));
			KLI_FN(KeUnstackDetachProcess)(&apc);
			VME
			return;
		}
		LOG_INFO(_XOR_("modulebase  = %p\n"), modulebase);


		NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("d3d11.dll"), (PULONG_PTR)&g_yvt.d3d11Info.imageBase, &g_yvt.d3d11Info.imageSize);
		NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("d2d1.dll"), (PULONG_PTR)&g_yvt.d2d1Info.imageBase, &g_yvt.d2d1Info.imageSize);
		NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("dwmcore.dll"), (PULONG_PTR)&g_yvt.dwmcoreInfo.imageBase, &g_yvt.dwmcoreInfo.imageSize);
		NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("dxgi.dll"), (PULONG_PTR)&g_yvt.dxgiInfo.imageBase, &g_yvt.dxgiInfo.imageSize);
		if (!g_yvt.user32Info.imageBase)
			NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("user32.dll"), (PULONG_PTR)&g_yvt.user32Info.imageBase, &g_yvt.user32Info.imageSize);
		if (!g_yvt.ntdllInfo.imageBase)
			NT::GetModuleInfo(g_yvt.dwm, (char*)_XOR_("ntdll.dll"), (PULONG_PTR)&g_yvt.ntdllInfo.imageBase, &g_yvt.ntdllInfo.imageSize);


		ULONG64 offset = 0;

		// VMware host: dwmcore.dll uses thunk-style PresentMultiplaneOverlay
		// with E9 jmp; the next 4 signatures decode the JMP rel32 to the real
		// function. Bare-metal: function prologue sits inline, none of the
		// thunk signatures match, must use direct prologue scan at line 762.
		// is_vmware_host captured in main.cpp before hv::start() disguises
		// the CPUID 0x40000000 leaf.
		if (!g_yvt.is_vmware_host) {

		  //48 8b 49 ? 48 83 c1 ? e9 ? ? ? ? CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 48 8B   win10  21H1   18363  1909   CDXGISwapChainDWMLegacy::PresentMultiplaneOverlay
		  offset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
		  	_XOR_("\x48\x8b\x49\x00\x48\x83\xc1\x00\xe9\x00\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B"),
		  	_XOR_("xxx?xxx?x????xxxxxxxxxxxxxxxxxxxxx"));
		  if (offset) {

		  	oriPresentMultiplaneOverlay = RVA((ULONG64)offset + 8, 5);

		  }
		  else {

		  	//48 8B 49 ? 48 81 C1 ? ? ? ? E9 ? ? ? ? CC CC CC CC CC CC CC CC 71 D3    win11  21h2   CDXGISwapChainDWMLegacy::PresentMultiplaneOverlay
		  	offset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
		  		_XOR_("\x48\x8B\x49\x00\x48\x81\xC1\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x71\xD3"),
		  		_XOR_("xxx?xxx????x????xxxxxxxxxx"));
		  	if (offset) {
		  		oriPresentMultiplaneOverlay = RVA((ULONG64)offset + 11, 5);
		  	}
		  	else {
		  		//48 8B ?? ?? 48 ?? ?? ?? E9 ?? ?? ?? ?? CC ?? ?? ?? ?? ?? ?? 4C 8B DC    win11  24h2   CDXGISwapChainDWMLegacy::PresentMultiplaneOverlay
		  		offset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
		  			_XOR_("\x48\x8B\x00\x00\x48\x00\x00\x00\xe9\x00\x00\x00\x00\xcc\x00\x00\x00\x00\x00\x00\x4c\x8b\xdc"),
		  			_XOR_("xx??x???x????x??????xxx"));
		  		if (offset) {
		  			oriPresentMultiplaneOverlay = RVA((ULONG64)offset + 8, 5);
		  		}
		  		else {


		  			//48 8B 49 40 48 81 C1 A8 00 00 00 E9 10 00 00 00
		  			offset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
		  				_XOR_("\x48\x8B\x49\x40\x48\x81\xC1\xA8\x00\x00\x00\xe9\x10\x00\x00\x00"),
		  				_XOR_("xxxxxxxxxxxxx???"));

		  			if (offset)
		  			{
		  				oriPresentMultiplaneOverlay = RVA((ULONG64)offset + 11, 5);
		  			}
		  			else {

		  				LOG_INFO(_XOR_("can`t find oriPresentMultiplaneOverlay\n"));
		  				KLI_FN(KeUnstackDetachProcess)(&apc);
		  				return;
		  			}


		  		}
		  	}
		  }
		}  // end if (g_yvt.is_vmware_host)

		if (!oriPresentMultiplaneOverlay)
		{


			oriPresentMultiplaneOverlay = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
				_XOR_("\x40\x53\x48\x83\xec\x00\x48\x8b\x49\x00\x45\x8b\xd8\x44\x8b\x84\x24\x00\x00\x00\x00"),
				_XOR_("xxxxx?xxx?xxxxxxx????"));


		}




		LOG_DEBUG(_XOR_("oriPresentMultiplaneOverlay address = %p\n"), oriPresentMultiplaneOverlay);

		//閺屻儲澹
		//	   
		// 48 ?? ?? ?? 48 8B ?? ?? 4C 8B ?? ?? ?? 48 ?? ?? ?? 4C 89 ?? ?? ??  win10  21H1 21H2  
		ULONG64 fullScreenOffset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
			_XOR_("\x48\x00\x00\x00\x48\x8B\x00\x00\x4C\x8B\x00\x00\x00\x48\x00\x00\x00\x4C\x89\x00\x00\x00"),
			_XOR_("x???xx??xx???x???xx???"));


		if (fullScreenOffset == 0) {


			//48 ?? ?? ?? 48 8B ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B 01 49 ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C 8B  win11 22h2  23H2
			fullScreenOffset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
				_XOR_("\x48\x00\x00\x00\x48\x8B\x00\x00\x48\x00\x00\x00\x00\x00\x00\x48\x8B\x01\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x8B"),
				_XOR_("x???xx??x??????xxxx?????????xx"));

			//48 ?? ?? ?? 48 8B ?? ?? 4C 8B ?? ?? ?? 48 ?? ?? ?? 4C 89 ?? ?? ?? 48 8B 01 48 8B  win11 24H2
			if (fullScreenOffset == 0) {
				fullScreenOffset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
					_XOR_("\x48\x00\x00\x00\x48\x8B\x00\x00\x4C\x8B\x00\x00\x00\x48\x00\x00\x00\x4C\x89\x00\x00\x00\x48\x8B\x01"),
					_XOR_("x???xx??xx???x???xx??xx"));

				LOG_INFO(_XOR_("fullScreenOffset = %p\n"), fullScreenOffset);
			}


		}



		//48 B8 01 00 7A 88 00 00 00 00 C3

		if (!fullScreenOffset)
		{
			LOG_INFO(_XOR_("can`t find fullScreenOffset\n"));
		}
		else {




			LOG_INFO(_XOR_("fullScreenOffset = %p\n"), fullScreenOffset);
			oriCheckMultiplaneOverlay = fullScreenOffset;
			ULONG64 ReturnSize = 0;
			MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)oriCheckMultiplaneOverlay, PsGetCurrentProcess(), (PVOID)oriCheckMultiplaneOverlay, 1, KernelMode, &ReturnSize);
			hookedOverPresentMdl = IoAllocateMdl(PAGE_ALIGN(oriCheckMultiplaneOverlay), PAGE_SIZE, FALSE, FALSE, NULL);
			if (hookedOverPresentMdl) {
				MmProbeAndLockPages(hookedOverPresentMdl, KernelMode, IoReadAccess);
			}
			epthook::hook_write(g_yvt.dwm, oriCheckMultiplaneOverlay, (UINT64)_XOR_("\x48\x31\xC0\xc3"), 4);

			//0x887A0001
		}

		//4C 8B ? ? 33 D2 44 8B ? ? 48 8B CF E8 ? ? ? ? 8B D8 48 8B ? ?  win10  22H2   GetDisplaySurfaceDataCore

		ULONG64 getDisplaySurfaceDataCoreOffset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
			_XOR_("\x4C\x8B\x00\x00\x33\xD2\x44\x8B\x00\x00\x48\x8B\xCF\xE8\x00\x00\x00\x00\x8B\xD8\x48\x8B\x00\x00"),
			_XOR_("xx??xxxx??xxxx????xxxx??"));

		if (getDisplaySurfaceDataCoreOffset) {

			oriGetDisplaySurfaceDataCore = RVA((ULONG64)getDisplaySurfaceDataCoreOffset + 13, 5);

		}

		LOG_INFO(_XOR_("GetDisplaySurfaceDataCore address = %p\n"), oriGetDisplaySurfaceDataCore);

		//48 81 EC 80 01 00 00 48 C7 80 D8 FE FF FF FE FF FF FF   win10 22H2   GetDisplaySurfaceDataForDIB
		//\x48\x81\xEC\x80\x01\x00\x00\x48\xC7\x80\xD8\xFE\xFF\xFF\xFE\xFF\xFF\xFF



		ULONG64 getDisplaySurfaceDataForDIBOffset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
			_XOR_("\x48\x81\xEC\x80\x01\x00\x00\x48\xC7\x80\xD8\xFE\xFF\xFF\xFE\xFF\xFF\xFF"),
			_XOR_("xxxxxxxxxxxxxxxxxx"));

		if (getDisplaySurfaceDataForDIBOffset) {

			oriGetDisplaySurfaceDataForDIB = (ULONG64)getDisplaySurfaceDataForDIBOffset - 11;

		}
		LOG_INFO(_XOR_("GetDisplaySurfaceDataForDIB address = %p\n"), oriGetDisplaySurfaceDataForDIB);




		//\x48\xC7\x84\x24\xA8\x00\x00\x00\xFE\xFF\xFF\xFF  win10 22H2
		//48 C7 84 24 A8 00 00 00 FE FF FF FF
		//


		ULONG64 acquireNextFrameOffset = (ULONG64)NT::FindSignatureSection(modulebase, _XOR_(".text"),
			_XOR_("\x48\xC7\x84\x24\xA8\x00\x00\x00\xFE\xFF\xFF\xFF"),
			_XOR_("xxxxxxxxxxxx"));

		if (acquireNextFrameOffset) {

			oriAcquireNextFrameOffset = (ULONG64)acquireNextFrameOffset - 19;

		}
		LOG_INFO(_XOR_("oriAcquireNextFrameOffset address = %p\n"), oriAcquireNextFrameOffset);



		oriDwmGetDxSharedSurface = (ULONG64)NT::GetExportedFunctionAddress(g_yvt.dwm, (PVOID)g_yvt.user32Info.imageBase, _XOR_("DwmGetDxSharedSurface"));


		LOG_INFO(_XOR_("oriDwmGetDxSharedSurface address = %p\n"), oriDwmGetDxSharedSurface);



		KLI_FN(KeUnstackDetachProcess)(&apc);



		ULONG64 systemcall_addr = __readmsr(0xC0000082);
		if (!systemcall_addr) LOG_INFO(_XOR_("systemcall_addr = %p\n"), systemcall_addr);

		offset = *(ULONG*)(systemcall_addr + 0x8);

		if ((offset & 0xFF) != 0x10) {
			LOG_INFO(_XOR_("systemcall_addr = %p\n"), systemcall_addr);
		}
		offset &= 0xFF00;

		g_offset_stack = offset + 8;

		if (offset != 0) {
			g_kvashadow = 1;
		}
		else {
			g_kvashadow = 0;
		}
		LOG_INFO(_XOR_("systemcall_addr = %p  g_offset_stack = %p\n"), systemcall_addr, g_offset_stack);


		VME
	}


	VOID Init()
	{

		VMB

		LOG_DEBUG(_XOR_("[TEST] dwm::Init enter\n"));

		DwmInit();

		LOG_DEBUG(_XOR_("[TEST] dwm::Init after DwmInit, process=%p\n"), (void*)process);

		if(process)
			InstallDwmHook();

		LOG_DEBUG(_XOR_("[TEST] dwm::Init done\n"));

		VME

	}


	VOID UnInit()
	{

		isExit = true;
		RemoveDwmHook();

	}

	VOID Reset()
	{

	}

#pragma code_seg()
}



