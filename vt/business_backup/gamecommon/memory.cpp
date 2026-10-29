#include "fltKernel.h"

#include "memory.h"
#include "vt/hv.h"
#include "vt/mm.h"
#include "vt/exception-routines.h"
#include "vt/ept.h"
#include "vt/introspection.h"
#include "../common/ntutils.h"
#include "dx.h"
#include <gamecommon/draw.h>
#include <gamecommon/gamecommon.h>
#include "game.h"

using namespace hv;

#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)


DWORD32 GameID = NULL;
DWORD64 Cr3 = NULL;



#pragma code_seg(".vm")




//瀹炵幇涓涓獁char瀛楃︿覆姣旇緝,涓嶅尯鍒嗗ぇ灏忓啓
int wcsicmp(const WCHAR* s1, const WCHAR* s2)
{
    while (towlower(*s1) == towlower(*s2))
    {
        if (*s1 == 0)
            return 0;
        s1++;
        s2++;
    }
    return towlower(*s1) - towlower(*s2);
}


namespace hv{


    typedef struct _LDR_DATA_TABLE_ENTRY
    {
        struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
        struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
        struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
        VOID* DllBase;                                                          //0x30
        VOID* EntryPoint;                                                       //0x38
        ULONG SizeOfImage;                                                      //0x40
        struct _UNICODE_STRING FullDllName;                                     //0x48
        struct _UNICODE_STRING BaseDllName;                                     //0x58
        union
        {
            UCHAR FlagGroup[4];                                                 //0x68
            ULONG Flags;                                                        //0x68
            struct
            {
                ULONG PackagedBinary : 1;                                         //0x68
                ULONG MarkedForRemoval : 1;                                       //0x68
                ULONG ImageDll : 1;                                               //0x68
                ULONG LoadNotificationsSent : 1;                                  //0x68
                ULONG TelemetryEntryProcessed : 1;                                //0x68
                ULONG ProcessStaticImport : 1;                                    //0x68
                ULONG InLegacyLists : 1;                                          //0x68
                ULONG InIndexes : 1;                                              //0x68
                ULONG ShimDll : 1;                                                //0x68
                ULONG InExceptionTable : 1;                                       //0x68
                ULONG ReservedFlags1 : 2;                                         //0x68
                ULONG LoadInProgress : 1;                                         //0x68
                ULONG LoadConfigProcessed : 1;                                    //0x68
                ULONG EntryProcessed : 1;                                         //0x68
                ULONG ProtectDelayLoad : 1;                                       //0x68
                ULONG ReservedFlags3 : 2;                                         //0x68
                ULONG DontCallForThreads : 1;                                     //0x68
                ULONG ProcessAttachCalled : 1;                                    //0x68
                ULONG ProcessAttachFailed : 1;                                    //0x68
                ULONG CorDeferredValidate : 1;                                    //0x68
                ULONG CorImage : 1;                                               //0x68
                ULONG DontRelocate : 1;                                           //0x68
                ULONG CorILOnly : 1;                                              //0x68
                ULONG ChpeImage : 1;                                              //0x68
                ULONG ReservedFlags5 : 2;                                         //0x68
                ULONG Redirected : 1;                                             //0x68
                ULONG ReservedFlags6 : 2;                                         //0x68
                ULONG CompatDatabaseProcessed : 1;                                //0x68
            };
        };
        USHORT ObsoleteLoadCount;                                               //0x6c
        USHORT TlsIndex;                                                        //0x6e
        struct _LIST_ENTRY HashLinks;                                           //0x70
        ULONG TimeDateStamp;                                                    //0x80
        struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
        VOID* Lock;                                                             //0x90
        struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
        struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
        struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
        VOID* ParentDllBase;                                                    //0xb8
        VOID* SwitchBackContext;                                                //0xc0
        struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
        struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
        ULONGLONG OriginalBase;                                                 //0xf8
        union _LARGE_INTEGER LoadTime;                                          //0x100
        ULONG BaseNameHashValue;                                                //0x108
        enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
        ULONG ImplicitPathOptions;                                              //0x110
        ULONG ReferenceCount;                                                   //0x114
        ULONG DependentLoadFlags;                                               //0x118
        UCHAR SigningLevel;                                                     //0x11c
    }LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;




size_t  read_game_virtual_memory(uint8_t* dst, uint8_t* src, size_t size)
{

    cr3  guest_cr3;

    guest_cr3.flags = game::GameCr3;



    size_t bytes_read = 0;

    while (bytes_read < size) {
        size_t dst_remaining = 0, src_remaining = 0;

        // translate the guest virtual addresses into host virtual addresses.
        // this has to be done 1 page at a time. :(
        auto const curr_dst =   gva2hva(dst + bytes_read, &dst_remaining);
        auto const curr_src = gva2hva(guest_cr3, src + bytes_read, &src_remaining);

        if (!curr_dst) {
            
            return bytes_read;
        }

        // this means that the target memory isn't paged in. there's nothing
        // we can do about that since we're not currently in that process's context.
        if (!curr_src)
            break;

        // the maximum allowed size that we can read at once with the translated HVAs
        auto const curr_size = min(size - bytes_read, min(dst_remaining, src_remaining));

        host_exception_info e;
        memcpy_safe(e, curr_dst, curr_src, curr_size);

        if (e.exception_occurred) {
            // this REALLY shouldn't happen... ever...
            //inject_hw_exception(general_protection, 0);
            return bytes_read;
        }

        bytes_read += curr_size;
    }

    return bytes_read;

}

bool write_game_virtual_memory(uint8_t* dst, uint8_t* src, size_t size)
{


    cr3  guest_cr3;

    guest_cr3 = g_ghv->g_cr3_map.realCr3;



    size_t bytes_read = 0;

    while (bytes_read < size) {
        size_t dst_remaining = 0, src_remaining = 0;

        // translate the guest virtual addresses into host virtual addresses.
        // this has to be done 1 page at a time. :(
        auto const curr_dst = gva2hva(guest_cr3, dst + bytes_read, &dst_remaining);
        auto const curr_src = gva2hva(src + bytes_read, &src_remaining);

        if (!curr_src) {
            // guest virtual address that caused the fault
            return false;
        }

        // this means that the target memory isn't paged in. there's nothing
        // we can do about that since we're not currently in that process's context.
        if (!curr_dst)
            break;

        // the maximum allowed size that we can read at once with the translated HVAs
        auto const curr_size = min(size - bytes_read, min(dst_remaining, src_remaining));

        host_exception_info e;
        memcpy_safe(e, curr_dst, curr_src, curr_size);

        if (e.exception_occurred) {
            // this REALLY shouldn't happen... ever...
            inject_hw_exception(general_protection, 0);
            return false;
        }

        bytes_read += curr_size;
    }

    return true;

}

bool get_game_path(void* path_buffer, size_t size)
{


    size_t retSize = 0;

    ULONG64 peb_ptr = (ULONG64)g_ghv->g_cr3_map.srcProcess + g_ghv->Peb;

    ULONG64 peb;

    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)peb_ptr, &peb, sizeof(peb));

    if (!peb)
        return false;

    ULONG64 processParam_ptr = peb + g_ghv->ProcessParameters;

    ULONG64 processParam = 0;



    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)processParam_ptr, &processParam, sizeof(processParam));



    if (!processParam)
        return false;

    ULONG64 CurrentDirectory = processParam + g_ghv->CurrentDirectory;

    if (!CurrentDirectory)
        return false;


    USHORT DosPathLength = 0;



    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)CurrentDirectory, &DosPathLength, sizeof(DosPathLength));

    ULONG64 path_ptr = 0;
    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)(CurrentDirectory + 8), &path_ptr, sizeof(path_ptr));

    if (!path_ptr)
        return false;

    auto path_buffer_hva = gva2hva(path_buffer);
    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)path_ptr, path_buffer_hva, DosPathLength * 2);

    //鎵撳嵃
    return true;

}

bool get_game_module_base(void* module_name, void* module_base, size_t* size_ptr)
{

    size_t retSize = 0;

    ULONG64 peb_ptr = (ULONG64)g_ghv->g_cr3_map.srcProcess + g_ghv->Peb;

    ULONG64 peb;

    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)peb_ptr, &peb, sizeof(peb));

    if (!peb)
        return false;


    ULONG64 ldr_ptr = peb + g_ghv->Ldr;

    ULONG64 ldr;
    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)ldr_ptr, &ldr, sizeof(ldr));

    if (!ldr)
        return false;

    LIST_ENTRY InLoadOrderModuleList;
    ULONG length = 0;

    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)(ldr + g_ghv->InLoadOrderModuleList), &InLoadOrderModuleList, sizeof(InLoadOrderModuleList));
    retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)(ldr), &length, sizeof(length));

    PLIST_ENTRY currentEntry = 0;

    auto nextEntry = (_LDR_DATA_TABLE_ENTRY*)InLoadOrderModuleList.Flink;

    if (!nextEntry)
        return false;



    WCHAR moduleName[1024];
    auto module_name_hva = gva2hva((WCHAR*)module_name);

    int i = length;
    while (nextEntry != (PVOID)currentEntry && i != 0) {

        _LDR_DATA_TABLE_ENTRY tempEntry = { 0 };

        retSize = read_guest_virtual_memory(g_ghv->g_cr3_map.realCr3, (void*)(nextEntry), &tempEntry, sizeof(tempEntry));

        if (tempEntry.DllBase == 0) break;

        do {


            PWCH baseName_ptr = tempEntry.BaseDllName.Buffer;
            auto baseName_hva = gva2hva(g_ghv->g_cr3_map.realCr3, (WCHAR*)baseName_ptr);

            if (!wcsicmp((WCHAR*)baseName_hva, (WCHAR*)module_name_hva)) {

                auto module_base_hva = gva2hva((void*)module_base);
                *(ULONG64*)module_base_hva = (ULONG64)tempEntry.DllBase;
                auto module_size_hva = gva2hva((void*)size_ptr);
                *(size_t*)module_size_hva = tempEntry.SizeOfImage;
                return true;
            }

        } while (0);


        currentEntry = (PLIST_ENTRY)nextEntry;
        nextEntry = (_LDR_DATA_TABLE_ENTRY*)tempEntry.InLoadOrderLinks.Flink;



        i--;

    }

    return false;
}
}




void SetProcessPid(DWORD32 dwPid, DWORD64 cr3)
{
	GameID = dwPid;
	Cr3 = cr3;
}


#define ORIGINALBUFFER

bool ReadMemoryt(ULONG64 uBaseAddr, PVOID lpBuffer, ULONG nSize)
{



	if (uBaseAddr < 0x100000 || uBaseAddr >= 0x7FFFFFFF00000000)
	{
		return false;
	}




#ifdef ORIGINALBUFFER

    SIZE_T  byteRead = hv::read_game_virtual_memory((UINT8*)lpBuffer, (uint8_t*)uBaseAddr, nSize);

    if (byteRead != nSize) {

        memset(lpBuffer, 0, nSize);
        memset(buffer2_hva, 0, 0x1000);

        byteRead = hv::read_game_virtual_memory((UINT8*)buffer2, (uint8_t*)uBaseAddr, nSize);

        memcpy(lpBuffer, buffer2_hva, nSize);

    }

#else 

    memset(lpBuffer, 0, nSize);
    memset(buffer2_hva, 0, 0x1000);

    SIZE_T byteRead = hv::read_game_virtual_memory((UINT8*)buffer2, (uint8_t*)uBaseAddr, nSize);

    memcpy(lpBuffer, buffer2_hva, nSize);

    if (byteRead != nSize) {

         byteRead = hv::read_game_virtual_memory((UINT8*)lpBuffer, (uint8_t*)uBaseAddr, nSize);

    }


#endif // ORIGINALBUFFER


	if (byteRead != nSize)
	{
		return false;
	}

	return true;
}


bool isValidPtr(ULONG_PTR Ptr)
{
	if (Ptr < 0x100000 || Ptr >= 0x7FFFFFFF00000000)
	{
		return false;
	}

	return true;
}


bool IsKeyDown(uint32_t virtual_key_code) {

    short State = (short)hv::CallUser(GetAsyncKeyState, (UINT64)virtual_key_code);

    if (State & 0x80000) {
        return true;
    }
    return false;
}



int GetGamePidByWindow(WCHAR* className,WCHAR* windowName) {

	PEPROCESS process = nullptr;


	RtlCopyMemory(buffer0_hva, className, (wcslen(className) + 1) * 2);
	RtlCopyMemory((PUCHAR)buffer0_hva + 0x100, windowName, (wcslen(windowName) + 1) * 2);
	auto gameHwnd = hv::CallUser(FindWindowW, buffer0, nullptr);


	//鏍规嵁绐楀彛鍙ユ焺鑾峰彇杩涚▼
	if (!gameHwnd) {
		 return 0;
	}



	RtlZeroMemory(buffer0_hva, 0x1000);
	hv::CallUser(GetWindowThreadProcessId, gameHwnd, buffer0);

	auto pid = *(DWORD*)buffer0_hva;

	return pid;
}

#pragma code_seg()
