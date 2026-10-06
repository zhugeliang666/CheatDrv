#pragma once
#include "FrameWork.h"

#if (defined(DBG) && (DBG != 0)) || (defined(_DEBUG) && !defined(NDEBUG))
#define MachenikePrint(fmt, ...) DbgPrint("[Machenike] " fmt "\n", ##__VA_ARGS__)
#else
#define MachenikePrint(...) ((void)0)
#endif

#define DEVICE_NAME L"\\Device\\Machenike"
#define LINK_NAME L"\\DosDevices\\Machenike"

// ACE对抗：通用池 Tag 伪装为 MiniFilter 系统 Tag，规避 BigPool 审计
#define MK_POOL_TAG 'lsMF'
#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))


typedef NTSTATUS(NTAPI *FuncTypeDef_RtlGetVersion)(_Out_ _At_(lpVersionInformation->dwOSVersionInfoSize, _Pre_ _Valid_)
                                                       _When_(lpVersionInformation->dwOSVersionInfoSize ==
                                                                  sizeof(RTL_OSVERSIONINFOEXW),
                                                              _At_((PRTL_OSVERSIONINFOEXW)lpVersionInformation, _Out_))
                                                           PRTL_OSVERSIONINFOW lpVersionInformation);

typedef VOID(NTAPI *FuncTypeDef_RtlInitUnicodeString)(_Out_ PUNICODE_STRING DestinationString,
                                                      _In_opt_z_ __drv_aliasesMem PCWSTR SourceString);

typedef PMDL(NTAPI *FuncTypeDef_IoAllocateMdl)(_In_opt_ __drv_aliasesMem PVOID VirtualAddress, _In_ ULONG Length,
                                               _In_ BOOLEAN SecondaryBuffer, _In_ BOOLEAN ChargeQuota,
                                               _Inout_opt_ PIRP Irp);

typedef VOID(NTAPI *FuncTypeDef_IoFreeMdl)(PMDL Mdl);

typedef NTSTATUS(NTAPI *FuncTypeDef_IoCreateDevice)(
    _In_ PDRIVER_OBJECT DriverObject, _In_ ULONG DeviceExtensionSize, _In_opt_ PUNICODE_STRING DeviceName,
    _In_ DEVICE_TYPE DeviceType, _In_ ULONG DeviceCharacteristics, _In_ BOOLEAN Exclusive,
    _Outptr_result_nullonfailure_ _At_(*DeviceObject,
                                       __drv_allocatesMem(Mem) _When_((((_In_function_class_(DRIVER_INITIALIZE)) ||
                                                                        (_In_function_class_(DRIVER_DISPATCH)))),
                                                                      __drv_aliasesMem)) PDEVICE_OBJECT *DeviceObject);

typedef NTSTATUS(NTAPI *FuncTypeDef_IoCreateSymbolicLink)(_In_ PUNICODE_STRING SymbolicLinkName,
                                                          _In_ PUNICODE_STRING DeviceName);

typedef VOID(NTAPI *FuncTypeDef_IoDeleteDevice)(_In_ __drv_freesMem(Mem) PDEVICE_OBJECT DeviceObject);

typedef NTSTATUS(FASTCALL *FuncTypeDef_IoDeleteSymbolicLink)(_In_ PUNICODE_STRING SymbolicLinkName);

typedef VOID(FASTCALL *FuncTypeDef_IofCompleteRequest)(_In_ PIRP Irp, _In_ CCHAR PriorityBoost);

typedef ULONG(__cdecl *FuncTypeDef_DbgPrint)(_In_z_ _Printf_format_string_ PCSTR Format, ...);

typedef VOID(NTAPI *FuncTypeDef_ProbeForRead)(__in_data_source(USER_MODE)
                                                  _Inout_updates_bytes_(Length) volatile VOID *Address,
                                              _In_ SIZE_T Length, _In_ ULONG Alignment);

typedef VOID(NTAPI *FuncTypeDef_ProbeForWrite)(__in_data_source(USER_MODE)
                                                   _Inout_updates_bytes_(Length) volatile VOID *Address,
                                               _In_ SIZE_T Length, _In_ ULONG Alignment);

typedef PVOID(NTAPI *FuncTypeDef_ExAllocatePoolWithTag)(_In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
                                                        _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);

typedef VOID(NTAPI *FuncTypeDef_ExFreePoolWithTag)(_Pre_notnull_ __drv_freesMem(Mem) PVOID P, _In_ ULONG Tag);

typedef NTSTATUS(NTAPI *FuncTypeDef_ZwOpenSection)(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                                   _In_ POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(NTAPI *FuncTypeDef_ZwMapViewOfSection)(
    _In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle, _Outptr_result_bytebuffer_(*ViewSize) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG Win32Protect);

typedef NTSTATUS(NTAPI *FuncTypeDef_ZwUnmapViewOfSection)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

typedef NTSTATUS(NTAPI *FuncTypeDef_ZwClose)(_In_ HANDLE Handle);

typedef VOID(NTAPI *FuncTypeDef_MmProbeAndLockPages)(_Inout_ PMDL MemoryDescriptorList, _In_ KPROCESSOR_MODE AccessMode,
                                                     _In_ LOCK_OPERATION Operation);

typedef VOID(NTAPI *FuncTypeDef_MmUnlockPages)(_Inout_ PMDL MemoryDescriptorList);

typedef PVOID(NTAPI *FuncTypeDef_MmMapLockedPagesSpecifyCache)(
    _Inout_ PMDL MemoryDescriptorList,
    _In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst) KPROCESSOR_MODE AccessMode,
    _In_ __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType, _In_opt_ PVOID RequestedAddress,
    _In_ ULONG BugCheckOnFailure, _In_ ULONG Priority);

typedef PPHYSICAL_MEMORY_RANGE(NTAPI *FuncTypeDef_MmGetPhysicalMemoryRanges)(VOID);

typedef KIRQL(NTAPI *FuncTypeDef_KeGetCurrentIrql)(VOID);

typedef KAFFINITY(NTAPI *FuncTypeDef_KeQueryActiveProcessors)(VOID);

typedef VOID(NTAPI *FuncTypeDef_KeSetSystemAffinityThread)(_In_ KAFFINITY Affinity);

typedef VOID(NTAPI *FuncTypeDef_KeRevertToUserAffinityThread)(VOID);

typedef VOID(NTAPI *FuncTypeDef_KeQuerySystemTimePrecise)(_Out_ PLARGE_INTEGER CurrentTime);

typedef HANDLE(NTAPI *FuncTypeDef_PsGetCurrentProcessId)(VOID);

typedef void *(__cdecl *FuncTypeDef_memset)(_Out_writes_bytes_all_(_Size) void *_Dst, _In_ int _Val, _In_ size_t _Size);

typedef void *(__cdecl *FuncTypeDef_memcpy)(_Out_writes_bytes_all_(_MaxCount) void *_Dst,
                                            _In_reads_bytes_(_MaxCount) const void *_Src, _In_ size_t _MaxCount);

typedef void *(__cdecl *FuncTypeDef_memmove)(_Out_writes_bytes_all_opt_(_Size) void *_Dst,
                                             _In_reads_bytes_opt_(_Size) const void *_Src, _In_ size_t _Size);

typedef size_t(__cdecl *FuncTypeDef_strlen)(_In_z_ const char *_Str);

typedef void(NTAPI *FuncTypeDef_RtlCopyMemory)(_Out_writes_bytes_all_(_Length) void *_Destination,
                                               _In_reads_bytes_(_Length) const void *_Source, _In_ size_t _Length);

typedef void(NTAPI *FuncTypeDef_RtlZeroMemory)(_Out_writes_bytes_all_(_Length) void *_Destination, _In_ size_t _Length);

typedef NTSTATUS(NTAPI *FuncTypeDef_KeDelayExecutionThread)(_In_ KPROCESSOR_MODE WaitMode, _In_ BOOLEAN Alertable,
                                                            _In_ PLARGE_INTEGER Interval);
typedef NTSTATUS(NTAPI *FuncTypeDef_PsTerminateSystemThread)(_In_ NTSTATUS ExitStatus);
typedef NTSTATUS(NTAPI *FuncTypeDef_PsCreateSystemThread)(_Out_ PHANDLE ThreadHandle, _In_ ULONG DesiredAccess,
                                                          _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                                                          _In_opt_ HANDLE ProcessHandle, _Out_opt_ PCLIENT_ID ClientId,
                                                          _In_ PKSTART_ROUTINE StartRoutine, _In_opt_ PVOID StartContext);
typedef LARGE_INTEGER(NTAPI *FuncTypeDef_KeQueryPerformanceCounter)(_Out_opt_ PLARGE_INTEGER PerformanceFrequency);
typedef PIRP(NTAPI *FuncTypeDef_IoAllocateIrp)(_In_ CCHAR StackSize, _In_ BOOLEAN ChargeQuota);
typedef VOID(NTAPI *FuncTypeDef_IoFreeIrp)(_In_ PIRP Irp);
typedef VOID(NTAPI *FuncTypeDef_KeInitializeEvent)(_Out_ PRKEVENT Event, _In_ EVENT_TYPE Type, _In_ BOOLEAN State);
typedef NTSTATUS(NTAPI *FuncTypeDef_KeWaitForSingleObject)(_In_ _Points_to_data_ PVOID Object,
                                                          _In_ _Strict_type_match_ KWAIT_REASON WaitReason,
                                                          _In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst) KPROCESSOR_MODE WaitMode,
                                                          _In_ BOOLEAN Alertable, _In_opt_ PLARGE_INTEGER Timeout);
typedef LONG(NTAPI *FuncTypeDef_KeSetEvent)(_Inout_ PRKEVENT Event, _In_ KPRIORITY Increment, _In_ _Literal_ BOOLEAN Wait);
typedef NTSTATUS(NTAPI *FuncTypeDef_ZwCreateFile)(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
                                                  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                                                  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                                  _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
                                                  _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition,
                                                  _In_ ULONG CreateOptions, _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
                                                  _In_ ULONG EaLength);
typedef NTSTATUS(NTAPI *FuncTypeDef_ZwReadFile)(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                                _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                                _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID Buffer,
                                                _In_ ULONG Length, _In_opt_ PLARGE_INTEGER ByteOffset, _In_opt_ PULONG Key);
typedef NTSTATUS(NTAPI *FuncTypeDef_ZwWriteFile)(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                                 _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                                 _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_reads_bytes_(Length) PVOID Buffer,
                                                 _In_ ULONG Length, _In_opt_ PLARGE_INTEGER ByteOffset, _In_opt_ PULONG Key);
typedef NTSTATUS(NTAPI *FuncTypeDef_ZwDeviceIoControlFile)(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event,
                                                           _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
                                                           _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG IoControlCode,
                                                           _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                                                           _In_ ULONG InputBufferLength,
                                                           _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
                                                           _In_ ULONG OutputBufferLength);
typedef NTSTATUS(NTAPI *FuncTypeDef_IoGetDeviceInterfaces)(_In_ CONST GUID *InterfaceClassGuid,
                                                           _In_opt_ PDEVICE_OBJECT PhysicalDeviceObject, _In_ ULONG Flags,
                                                           _Outptr_result_nullonfailure_ PWSTR *SymbolicLinkList);
typedef NTSTATUS(NTAPI *FuncTypeDef_ObReferenceObjectByHandle)(_In_ HANDLE Handle, _In_ ACCESS_MASK DesiredAccess,
                                                               _In_opt_ POBJECT_TYPE ObjectType,
                                                               _In_ KPROCESSOR_MODE AccessMode, _Out_ PVOID *Object,
                                                               _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation);
typedef VOID(FASTCALL *FuncTypeDef_ObfDereferenceObject)(_In_ PVOID Object);
typedef PVOID(NTAPI *FuncTypeDef_MmAllocateContiguousMemorySpecifyCache)(_In_ SIZE_T NumberOfBytes,
                                                                        _In_ PHYSICAL_ADDRESS LowestAcceptableAddress,
                                                                        _In_ PHYSICAL_ADDRESS HighestAcceptableAddress,
                                                                        _In_opt_ PHYSICAL_ADDRESS BoundaryAddressMultiple,
                                                                        _In_ MEMORY_CACHING_TYPE CacheType);
typedef VOID(NTAPI *FuncTypeDef_MmFreeContiguousMemory)(_In_ PVOID BaseAddress);

/* ---- ACE Bypass 新增函数类型定义 ---- */
typedef NTSTATUS(NTAPI *FuncTypeDef_IoGetDeviceObjectPointer)(_In_ PUNICODE_STRING ObjectName, _In_ ACCESS_MASK DesiredAccess,
                                                              _Out_ PFILE_OBJECT *FileObject, _Out_ PDEVICE_OBJECT *DeviceObject);
typedef PDEVICE_OBJECT(NTAPI *FuncTypeDef_IoAttachDeviceToDeviceStack)(_In_ PDEVICE_OBJECT SourceDevice,
                                                                       _In_ PDEVICE_OBJECT TargetDevice);
typedef VOID(NTAPI *FuncTypeDef_IoDetachDevice)(_Inout_ PDEVICE_OBJECT TargetDevice);
typedef NTSTATUS(NTAPI *FuncTypeDef_IoCallDriver)(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
typedef VOID(FASTCALL *FuncTypeDef_ExAcquireFastMutex)(_Inout_ PFAST_MUTEX FastMutex);
typedef VOID(FASTCALL *FuncTypeDef_ExReleaseFastMutex)(_Inout_ PFAST_MUTEX FastMutex);

/* ntifs.h/ntddk.h 将 IoCallDriver 宏定义为 IofCallDriver（FASTCALL 版本）
 * 我们的函数指针表字段名使用 IoCallDriver（NTAPI 版本），
 * 必须在结构体定义前取消该宏，否则字段名会被预处理器替换 */
#ifdef IoCallDriver
#undef IoCallDriver
#endif



typedef struct _MACHENIKE_PFN
{
    FuncTypeDef_RtlGetVersion RtlGetVersion;
    FuncTypeDef_RtlInitUnicodeString RtlInitUnicodeString;
    FuncTypeDef_IoAllocateMdl IoAllocateMdl;
    FuncTypeDef_IoFreeMdl IoFreeMdl;
    FuncTypeDef_IoCreateDevice IoCreateDevice;
    FuncTypeDef_IoCreateSymbolicLink IoCreateSymbolicLink;
    FuncTypeDef_IoDeleteDevice IoDeleteDevice;
    FuncTypeDef_IoDeleteSymbolicLink IoDeleteSymbolicLink;
    FuncTypeDef_IofCompleteRequest IofCompleteRequest;
    FuncTypeDef_DbgPrint DbgPrint;
    FuncTypeDef_ProbeForRead ProbeForRead;
    FuncTypeDef_ProbeForWrite ProbeForWrite;
    FuncTypeDef_ExAllocatePoolWithTag ExAllocatePoolWithTag;
    FuncTypeDef_ExFreePoolWithTag ExFreePoolWithTag;
    FuncTypeDef_ZwOpenSection ZwOpenSection;
    FuncTypeDef_ZwMapViewOfSection ZwMapViewOfSection;
    FuncTypeDef_ZwUnmapViewOfSection ZwUnmapViewOfSection;
    FuncTypeDef_ZwClose ZwClose;
    FuncTypeDef_MmProbeAndLockPages MmProbeAndLockPages;
    FuncTypeDef_MmUnlockPages MmUnlockPages;
    FuncTypeDef_MmMapLockedPagesSpecifyCache MmMapLockedPagesSpecifyCache;

    FuncTypeDef_MmGetPhysicalMemoryRanges MmGetPhysicalMemoryRanges;
    FuncTypeDef_KeGetCurrentIrql KeGetCurrentIrql;
    FuncTypeDef_KeQueryActiveProcessors KeQueryActiveProcessors;
    FuncTypeDef_KeSetSystemAffinityThread KeSetSystemAffinityThread;
    FuncTypeDef_KeRevertToUserAffinityThread KeRevertToUserAffinityThread;
    FuncTypeDef_KeQuerySystemTimePrecise KeQuerySystemTimePrecise;
    FuncTypeDef_PsGetCurrentProcessId PsGetCurrentProcessId;
    FuncTypeDef_memset memset;
    FuncTypeDef_memcpy memcpy;
    FuncTypeDef_memmove memmove;
    FuncTypeDef_strlen strlen;
    FuncTypeDef_RtlCopyMemory RtlCopyMemory;
    FuncTypeDef_RtlZeroMemory RtlZeroMemory;
    FuncTypeDef_KeDelayExecutionThread KeDelayExecutionThread;
    FuncTypeDef_PsTerminateSystemThread PsTerminateSystemThread;
    FuncTypeDef_PsCreateSystemThread PsCreateSystemThread;
    FuncTypeDef_KeQueryPerformanceCounter KeQueryPerformanceCounter;
    FuncTypeDef_IoAllocateIrp IoAllocateIrp;
    FuncTypeDef_IoFreeIrp IoFreeIrp;
    FuncTypeDef_KeInitializeEvent KeInitializeEvent;
    FuncTypeDef_KeWaitForSingleObject KeWaitForSingleObject;
    FuncTypeDef_KeSetEvent KeSetEvent;
    FuncTypeDef_ZwCreateFile ZwCreateFile;
    FuncTypeDef_ZwReadFile ZwReadFile;
    FuncTypeDef_ZwWriteFile ZwWriteFile;
    FuncTypeDef_ZwDeviceIoControlFile ZwDeviceIoControlFile;
    FuncTypeDef_IoGetDeviceInterfaces IoGetDeviceInterfaces;
    FuncTypeDef_ObReferenceObjectByHandle ObReferenceObjectByHandle;
    FuncTypeDef_ObfDereferenceObject ObfDereferenceObject;
    FuncTypeDef_MmAllocateContiguousMemorySpecifyCache MmAllocateContiguousMemorySpecifyCache;
    FuncTypeDef_MmFreeContiguousMemory MmFreeContiguousMemory;
    /* ACE Bypass 函数指针 */
    FuncTypeDef_IoGetDeviceObjectPointer            IoGetDeviceObjectPointer;
    FuncTypeDef_IoAttachDeviceToDeviceStack         IoAttachDeviceToDeviceStack;
    FuncTypeDef_IoDetachDevice                      IoDetachDevice;
    FuncTypeDef_IoCallDriver                        IoCallDriver;
    FuncTypeDef_ExAcquireFastMutex                  ExAcquireFastMutex;
    FuncTypeDef_ExReleaseFastMutex                  ExReleaseFastMutex;
} MACHENIKE_PFN, *PMACHENIKE_PFN;



typedef struct _MACHENIKE_KERNEL_INTERFACE
{
    MACHENIKE_PFN Func;
    ULONG HashStringImulMagicValue;
    PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange;
    HANDLE hPhysicalMemory;
    LARGE_INTEGER NtBuildNumber;
    LARGE_INTEGER NtBuildNumberAddr;
    LARGE_INTEGER KernelBase;
    LARGE_INTEGER Cr3;

    ULONGLONG Step;
    ULONG Salt4;
    UCHAR SipHashKey[16];
    struct _MACHENIKE_KERNEL_INTERFACE *StealthContext;
} MACHENIKE_KERNEL_INTERFACE, *PMACHENIKE_KERNEL_INTERFACE;

static __forceinline PMACHENIKE_KERNEL_INTERFACE GetActiveUserVar(PDEVICE_OBJECT pDevObj)
{
    if (!pDevObj || !pDevObj->DeviceExtension)
        return NULL;
    return (PMACHENIKE_KERNEL_INTERFACE)pDevObj->DeviceExtension;
}

#ifdef __cplusplus
extern "C"
{
#endif



    ULONG PhysicalMemoryPartialRead(IN MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ LARGE_INTEGER physAddr,
                                    _Inout_ PUCHAR buf, _In_ ULONG count);

    ULONG PhysicalMemoryPartialWrite(IN MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ LARGE_INTEGER PhysicalAddress,
                                     _In_ PUCHAR lpBuffer, _In_ SIZE_T Length);

#ifdef __cplusplus
}
#endif
