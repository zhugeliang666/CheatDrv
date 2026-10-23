#pragma once
#include  "../base.h"

#define CODEINTEGRITY_OPTION_ENABLED						0x1
#define CODEINTEGRITY_OPTION_TESTSIGN						0x2
#define CODEINTEGRITY_OPTION_UMCI_ENABLED					0x4
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED			0x8
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED	0x10
#define CODEINTEGRITY_OPTION_TEST_BUILD						0x20
#define CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD			0x40
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED				0x80
#define CODEINTEGRITY_OPTION_FLIGHT_BUILD					0x100
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED				0x200
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED				0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED	0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED	0x1000
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED				0x2000


namespace NT
{

    typedef struct _IMAGE_RELOC {

        UINT16 Offset : 12; //偏移
        UINT16 Type : 4;  //类型   3:32位 ,10:64位
    }IMAGE_RELOC, * PIMAGE_RELOC;

    typedef struct _RTL_AVL_TREE
    {
        struct _RTL_BALANCED_NODE* Root;
    } RTL_AVL_TREE, * PRTL_AVL_TREE;

    typedef struct _SYSTEM_POOLTAG
    {
        union
        {
            UCHAR Tag[4];
            ULONG TagUlong;
        };
        ULONG PagedAllocs;
        ULONG PagedFrees;
        SIZE_T PagedUsed;
        ULONG NonPagedAllocs;
        ULONG NonPagedFrees;
        SIZE_T NonPagedUsed;
    }SYSTEM_POOLTAG, * PSYSTEM_POOLTAG;

    typedef struct _SYSTEM_POOLTAG_INFORMATION
    {
        ULONG Count;
        SYSTEM_POOLTAG TagInfo[ANYSIZE_ARRAY];
    }SYSTEM_POOLTAG_INFORMATION, * PSYSTEM_POOLTAG_INFORMATION;

    typedef struct _CURDIR
    {
        UNICODE_STRING DosPath;                                         //0x0
        VOID* Handle;                                                           //0x10
    }CURDIR, * PCURDIR;

    typedef struct _RTL_DRIVE_LETTER_CURDIR
    {
        USHORT Flags;                                                           //0x0
        USHORT Length;                                                          //0x2
        ULONG TimeStamp;                                                        //0x4
        STRING DosPath;                                                 //0x8
    }RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

    typedef struct _RTL_USER_PROCESS_PARAMETERS
    {
        ULONG MaximumLength;                                                    //0x0
        ULONG Length;                                                           //0x4
        ULONG Flags;                                                            //0x8
        ULONG DebugFlags;                                                       //0xc
        VOID* ConsoleHandle;                                                    //0x10
        ULONG ConsoleFlags;                                                     //0x18
        VOID* StandardInput;                                                    //0x20
        VOID* StandardOutput;                                                   //0x28
        VOID* StandardError;                                                    //0x30
        CURDIR CurrentDirectory;                                        //0x38
        UNICODE_STRING DllPath;                                         //0x50
        UNICODE_STRING ImagePathName;                                   //0x60
        UNICODE_STRING CommandLine;                                     //0x70
        VOID* Environment;                                                      //0x80
        ULONG StartingX;                                                        //0x88
        ULONG StartingY;                                                        //0x8c
        ULONG CountX;                                                           //0x90
        ULONG CountY;                                                           //0x94
        ULONG CountCharsX;                                                      //0x98
        ULONG CountCharsY;                                                      //0x9c
        ULONG FillAttribute;                                                    //0xa0
        ULONG WindowFlags;                                                      //0xa4
        ULONG ShowWindowFlags;                                                  //0xa8
        UNICODE_STRING WindowTitle;                                     //0xb0
        UNICODE_STRING DesktopInfo;                                     //0xc0
        UNICODE_STRING ShellInfo;                                       //0xd0
        UNICODE_STRING RuntimeData;                                     //0xe0
        RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
        ULONGLONG EnvironmentSize;                                              //0x3f0
        ULONGLONG EnvironmentVersion;                                           //0x3f8
        VOID* PackageDependencyData;                                            //0x400
        ULONG ProcessGroupId;                                                   //0x408
        ULONG LoaderThreads;                                                    //0x40c
        UNICODE_STRING RedirectionDllName;                              //0x410
        UNICODE_STRING HeapPartitionName;                               //0x420
        ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
        ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
    }RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    typedef struct _OBJECT_HANDLE_ATTRIBUTE_INFORMATION
    {
        bool Inherit;
        bool ProtectFromClose;
    }OBJECT_HANDLE_ATTRIBUTE_INFORMATION, * POBJECT_HANDLE_ATTRIBUTE_INFORMATION;

    typedef struct _JOBOBJECT_BASIC_PROCESS_ID_LIST {
        ULONG NumberOfAssignedProcesses;
        ULONG NumberOfProcessIdsInList;
        ULONG_PTR ProcessIdList[1];
    } JOBOBJECT_BASIC_PROCESS_ID_LIST, * PJOBOBJECT_BASIC_PROCESS_ID_LIST;

    typedef struct _OBJECT_TYPE_INFORMATION
    {
        UNICODE_STRING TypeName;
        ULONG TotalNumberOfObjects;
        ULONG TotalNumberOfHandles;
        ULONG Reserved[40];
    } OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

    typedef struct _OBJECT_TYPES_INFORMATION
    {
        ULONG NumberOfTypes;
        OBJECT_TYPE_INFORMATION TypeInformation[1];
    } OBJECT_TYPES_INFORMATION, * POBJECT_TYPES_INFORMATION;



    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    }SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

    typedef struct _SYSTEM_HANDLE_INFORMATION
    {
        ULONG NumberOfHandles;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
    }SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    }SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX
    {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    }SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

    typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    {
        bool DebuggerAllowed;
        bool DebuggerEnabled;
        bool DebuggerPresent;
    }SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

    typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
    {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    }SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

    typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
    {
        ULONG SessionId;
        ULONG SizeOfBuf;
        PVOID Buffer;
    }SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

    typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
    {
        bool DebuggerEnabled;
        bool DebuggerNotPresent;
    } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

    typedef struct _WOW64_FLOATING_SAVE_AREA
    {
        ULONG ControlWord;
        ULONG StatusWord;
        ULONG TagWord;
        ULONG ErrorOffset;
        ULONG ErrorSelector;
        ULONG DataOffset;
        ULONG DataSelector;
        UCHAR RegisterArea[80];
        ULONG Cr0NpxState;
    } WOW64_FLOATING_SAVE_AREA, * PWOW64_FLOATING_SAVE_AREA;

    typedef struct _WOW64_CONTEXT
    {
        ULONG ContextFlags;

        ULONG Dr0;
        ULONG Dr1;
        ULONG Dr2;
        ULONG Dr3;
        ULONG Dr6;
        ULONG Dr7;

        WOW64_FLOATING_SAVE_AREA FloatSave;

        ULONG SegGs;
        ULONG SegFs;
        ULONG SegEs;
        ULONG SegDs;

        ULONG Edi;
        ULONG Esi;
        ULONG Ebx;
        ULONG Edx;
        ULONG Ecx;
        ULONG Eax;

        ULONG Ebp;
        ULONG Eip;
        ULONG SegCs;
        ULONG EFlags;
        ULONG Esp;
        ULONG SegSs;

        UCHAR ExtendedRegisters[512];

    } WOW64_CONTEXT, * PWOW64_CONTEXT;

    typedef struct _OBJECT_ALL_INFORMATION
    {
        ULONG                   NumberOfObjectsTypes;
        OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
    } OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;

    typedef struct _SYSTEM_THREAD_INFO
    {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        KPRIORITY Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        KWAIT_REASON WaitReason;
    }SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

    typedef struct _SYSTEM_PROCESS_INFO
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        ULONG BasePriority;
        HANDLE ProcessId;
        HANDLE InheritedFromProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey;
        ULONG_PTR PeakVirtualSize;
        ULONG_PTR VirtualSize;
        ULONG PageFaultCount;
        ULONG_PTR PeakWorkingSetSize;
        ULONG_PTR WorkingSetSize;
        ULONG_PTR QuotaPeakPagedPoolUsage;
        ULONG_PTR QuotaPagedPoolUsage;
        ULONG_PTR QuotaPeakNonPagedPoolUsage;
        ULONG_PTR QuotaNonPagedPoolUsage;
        ULONG_PTR PagefileUsage;
        ULONG_PTR PeakPagefileUsage;
        ULONG_PTR PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SYSTEM_THREAD_INFORMATION Threads[1];
    }SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation, // not implemented
        SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
        SystemModuleInformation, // q: RTL_PROCESS_MODULES
        SystemLocksInformation, // q: RTL_PROCESS_LOCKS
        SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
        SystemPagedPoolInformation, // not implemented
        SystemNonPagedPoolInformation, // not implemented
        SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
        SystemVdmBopInformation, // not implemented // 20
        SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemLoadGdiDriverInformation, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation, // s (kernel-mode only)
        SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
        SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
        SystemObsolete0, // not implemented
        SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeperation, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
        SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
        SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
        SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
        SystemSessionCreate, // not implemented
        SystemSessionDetach, // not implemented
        SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
        SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
        SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend, // s (kernel-mode only)
        SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
        SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
        SystemComPlusPackage, // q; s: ULONG
        SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
        SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation, // q: ULONG
        SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
        SystemObjectSecurityMode, // q: ULONG // 70
        SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
        SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
        SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemWow64SharedInformationObsolete, // not implemented
        SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
        SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
        SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
        SystemVerifierTriageInformation, // not implemented
        SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
        SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
        SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
        SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx, // not implemented
        SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
        SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
        SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
        SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
        SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
        SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
        SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
        SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
        SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
        SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
        SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
        SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
        SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
        SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
        SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
        SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
        SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
        SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
        SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
        SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
        SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
        SystemBadPageInformation,
        SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
        SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
        SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
        SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
        SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
        SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION
        SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
        SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
        SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
        SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
        SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
        SystemCriticalProcessErrorLogInformation,
        SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
        SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
        SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation, // 150
        SystemSoftRebootInformation, // q: ULONG
        SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
        SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
        SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
        SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
        SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
        SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
        SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation,
        SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
        SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
        SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
        SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
        SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
        SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
        SystemInterruptSteeringInformation, // SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT // 180
        SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
        SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
        SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
        SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
        SystemControlFlowTransition,
        SystemKernelDebuggingAllowed, // s: ULONG
        SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
        SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
        SystemIntegrityQuotaInformation,
        SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
        SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
        SystemSecureDumpEncryptionInformation,
        SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
        SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
        SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
        SystemFirmwareBootPerformanceInformation,
        SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
        SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
        SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
        SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
        SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
        SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
        SystemCodeIntegrityUnlockModeInformation,
        SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
        SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
        SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
        SystemCodeIntegritySyntheticCacheInformation,
        SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
        SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
        SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
        SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
        SystemSpacesBootInformation, // since 20H2
        SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
        SystemWheaIpmiHardwareInformation,
        SystemDifSetRuleClassInformation,
        SystemDifClearRuleClassInformation,
        SystemDifApplyPluginVerificationOnDriver,
        SystemDifRemovePluginVerificationOnDriver, // 220
        SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
        SystemBuildVersionInformation, // SYSTEM_BUILD_VERSION_INFORMATION
        SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION
        SystemCodeIntegrityAddDynamicStore,
        SystemCodeIntegrityClearDynamicStores,
        SystemDifPoolTrackingInformation,
        SystemPoolZeroingInformation, // SYSTEM_POOL_ZEROING_INFORMATION
        SystemDpcWatchdogInformation,
        SystemDpcWatchdogInformation2,
        SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx  // 230
        SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
        SystemXfgCheckFailureInformation,
        SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
        SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
        SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
        SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
        SystemSecureKernelDebuggerInformation,
        SystemOriginalImageFeatureInformation,
        MaxSystemInfoClass

    } SYSTEM_INFORMATION_CLASS;

    typedef struct _SYSTEM_MODULE_ENTRY {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

    typedef struct _LDR_DATA_TABLE_ENTRY32
    {
        LIST_ENTRY32 InLoadOrderLinks;
        LIST_ENTRY32 InMemoryOrderLinks;
        LIST_ENTRY32 InInitializationOrderLinks;
        ULONG DllBase;
        ULONG EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING32 FullDllName;
        UNICODE_STRING32 BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        LIST_ENTRY32 HashLinks;
        ULONG TimeDateStamp;
    } LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

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

    typedef struct _SYSTEM_MODULE {
        PVOID 	Reserved1;
        PVOID 	Reserved2;
        PVOID 	ImageBaseAddress;
        ULONG 	ImageSize;
        ULONG 	Flags;
        unsigned short 	Id;
        unsigned short 	Rank;
        unsigned short 	Unknown;
        unsigned short 	NameOffset;
        unsigned char 	Name[MAXIMUM_FILENAME_LENGTH];
    } SYSTEM_MODULE, * PSYSTEM_MODULE;

    typedef struct _SYSTEM_MODULE_INFORMATION {
        ULONG                       ModulesCount;
        SYSTEM_MODULE_ENTRY         Modules[1];
        ULONG                       Count;
        SYSTEM_MODULE 	            Sys_Modules[1];
    } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

    struct _EX_FAST_REF
    {
        union
        {
            VOID* Object;                                                       //0x0
            ULONGLONG RefCnt : 4;                                                 //0x0
            ULONGLONG Value;                                                    //0x0
        };
    };


    typedef struct _DEBUG_OBJECT
    {
        KEVENT EventsPresent;
        FAST_MUTEX Mutex;
        LIST_ENTRY64 EventList;
        union
        {
            ULONG Flags;
            struct
            {
                UCHAR DebuggerInactive : 1;
                UCHAR KillProcessOnExit : 1;
            };
        };
    } DEBUG_OBJECT, * PDEBUG_OBJECT;


    //0x4 bytes (sizeof)
    struct _MM_GRAPHICS_VAD_FLAGS
    {
        ULONG Lock : 1;                                                           //0x0
        ULONG LockContended : 1;                                                  //0x0
        ULONG DeleteInProgress : 1;                                               //0x0
        ULONG NoChange : 1;                                                       //0x0
        ULONG VadType : 3;                                                        //0x0
        ULONG Protection : 5;                                                     //0x0
        ULONG PreferredNode : 6;                                                  //0x0
        ULONG PageSize : 2;                                                       //0x0
        ULONG PrivateMemoryAlwaysSet : 1;                                         //0x0
        ULONG WriteWatch : 1;                                                     //0x0
        ULONG FixedLargePageSize : 1;                                             //0x0
        ULONG ZeroFillPagesOptional : 1;                                          //0x0
        ULONG GraphicsAlwaysSet : 1;                                              //0x0
        ULONG GraphicsUseCoherentBus : 1;                                         //0x0
        ULONG GraphicsNoCache : 1;                                                //0x0
        ULONG GraphicsPageProtection : 3;                                         //0x0
    };

    //0x8 bytes (sizeof)
    struct __EX_PUSH_LOCK
    {
        union
        {
            struct
            {
                ULONGLONG Locked : 1;                                             //0x0
                ULONGLONG Waiting : 1;                                            //0x0
                ULONGLONG Waking : 1;                                             //0x0
                ULONGLONG MultipleShared : 1;                                     //0x0
                ULONGLONG Shared : 60;                                            //0x0
            };
            ULONGLONG Value;                                                    //0x0
            VOID* Ptr;                                                          //0x0
        };
    };

    //0x4 bytes (sizeof)
    struct _MM_SHARED_VAD_FLAGS
    {
        ULONG Lock : 1;                                                           //0x0
        ULONG LockContended : 1;                                                  //0x0
        ULONG DeleteInProgress : 1;                                               //0x0
        ULONG NoChange : 1;                                                       //0x0
        ULONG VadType : 3;                                                        //0x0
        ULONG Protection : 5;                                                     //0x0
        ULONG PreferredNode : 6;                                                  //0x0
        ULONG PageSize : 2;                                                       //0x0
        ULONG PrivateMemoryAlwaysClear : 1;                                       //0x0
        ULONG PrivateFixup : 1;                                                   //0x0
        ULONG HotPatchAllowed : 1;                                                //0x0
    };

    //0x4 bytes (sizeof)
    struct _MM_PRIVATE_VAD_FLAGS
    {
        ULONG Lock : 1;                                                           //0x0
        ULONG LockContended : 1;                                                  //0x0
        ULONG DeleteInProgress : 1;                                               //0x0
        ULONG NoChange : 1;                                                       //0x0
        ULONG VadType : 3;                                                        //0x0
        ULONG Protection : 5;                                                     //0x0
        ULONG PreferredNode : 6;                                                  //0x0
        ULONG PageSize : 2;                                                       //0x0
        ULONG PrivateMemoryAlwaysSet : 1;                                         //0x0
        ULONG WriteWatch : 1;                                                     //0x0
        ULONG FixedLargePageSize : 1;                                             //0x0
        ULONG ZeroFillPagesOptional : 1;                                          //0x0
        ULONG Graphics : 1;                                                       //0x0
        ULONG Enclave : 1;                                                        //0x0
        ULONG ShadowStack : 1;                                                    //0x0
        ULONG PhysicalMemoryPfnsReferenced : 1;                                   //0x0
    };


    //0x8 bytes (sizeof)
    struct _MI_VAD_SEQUENTIAL_INFO
    {
        ULONGLONG Length : 12;                                                    //0x0
        ULONGLONG Vpn : 52;                                                       //0x0
    };

    //0x4 bytes (sizeof)
    struct _MMVAD_FLAGS
    {
        ULONG Lock : 1;                                                           //0x0
        ULONG LockContended : 1;                                                  //0x0
        ULONG DeleteInProgress : 1;                                               //0x0
        ULONG NoChange : 1;                                                       //0x0
        ULONG VadType : 3;                                                        //0x0
        ULONG Protection : 5;                                                     //0x0
        ULONG PreferredNode : 6;                                                  //0x0
        ULONG PageSize : 2;                                                       //0x0
        ULONG PrivateMemory : 1;                                                  //0x0
    };

    //0x4 bytes (sizeof)
    struct _MMVAD_FLAGS1
    {
        ULONG CommitCharge : 31;                                                  //0x0
        ULONG MemCommit : 1;                                                      //0x0
    };

    //0x40 bytes (sizeof)
    struct _MMVAD_SHORT
    {
        union
        {
            struct
            {
                struct _MMVAD_SHORT* NextVad;                                   //0x0
                VOID* ExtraCreateInfo;                                          //0x8
            };
            struct _RTL_BALANCED_NODE VadNode;                                  //0x0
        };
        ULONG StartingVpn;                                                      //0x18
        ULONG EndingVpn;                                                        //0x1c
        UCHAR StartingVpnHigh;                                                  //0x20
        UCHAR EndingVpnHigh;                                                    //0x21
        UCHAR CommitChargeHigh;                                                 //0x22
        UCHAR SpareNT64VadUChar;                                                //0x23
        LONG ReferenceCount;                                                    //0x24
    	__EX_PUSH_LOCK PushLock;                                          //0x28
        union
        {
            ULONG LongFlags;                                                    //0x30
            struct _MMVAD_FLAGS VadFlags;                                       //0x30
            struct _MM_PRIVATE_VAD_FLAGS PrivateVadFlags;                       //0x30
            struct _MM_GRAPHICS_VAD_FLAGS GraphicsVadFlags;                     //0x30
            struct _MM_SHARED_VAD_FLAGS SharedVadFlags;                         //0x30
            volatile ULONG VolatileVadLong;                                     //0x30
        } u;                                                                    //0x30
        union
        {
            ULONG LongFlags1;                                                   //0x34
            struct _MMVAD_FLAGS1 VadFlags1;                                     //0x34
        } u1;                                                                   //0x34
        struct _MI_VAD_EVENT_BLOCK* EventList;                                  //0x38
    };

    //0x4 bytes (sizeof)
    struct _MMVAD_FLAGS2
    {
        ULONG FileOffset : 24;                                                    //0x0
        ULONG Large : 1;                                                          //0x0
        ULONG TrimBehind : 1;                                                     //0x0
        ULONG Inherit : 1;                                                        //0x0
        ULONG NoValidationNeeded : 1;                                             //0x0
        ULONG PrivateDemandZero : 1;                                              //0x0
        ULONG Spare : 3;                                                          //0x0
    };

    //0x88 bytes (sizeof)
    struct _MMVAD
    {
        struct _MMVAD_SHORT Core;                                               //0x0
        union
        {
            ULONG LongFlags2;                                                   //0x40
            volatile struct _MMVAD_FLAGS2 VadFlags2;                            //0x40
        } u2;                                                                   //0x40
        struct _SUBSECTION* Subsection;                                         //0x48
        struct _MMPTE* FirstPrototypePte;                                       //0x50
        struct _MMPTE* LastContiguousPte;                                       //0x58
        struct _LIST_ENTRY ViewLinks;                                           //0x60
        struct _EPROCESS* VadsProcess;                                          //0x70
        union
        {
            struct _MI_VAD_SEQUENTIAL_INFO SequentialVa;                        //0x78
            struct _MMEXTEND_INFO* ExtendedInfo;                                //0x78
        } u4;                                                                   //0x78
        struct _FILE_OBJECT* FileObject;                                        //0x80
    };


    typedef struct _FILE_ALLOCATION_INFORMATION {
        LARGE_INTEGER AllocationSize;
    } FILE_ALLOCATION_INFORMATION, * PFILE_ALLOCATION_INFORMATION;




    struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof)
    {
        union                                    // 3 elements, 0x8 bytes (sizeof)
        {
            struct                               // 5 elements, 0x8 bytes (sizeof)
            {
                /*0x000*/             UINT64       Locked : 1;         // 0 BitPosition
                /*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition
                /*0x000*/             UINT64       Waking : 1;         // 2 BitPosition
                /*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition
                /*0x000*/             UINT64       Shared : 60;        // 4 BitPosition
            };
            /*0x000*/         UINT64       Value;
            /*0x000*/         VOID* Ptr;
        };
    }/*EX_PUSH_LOCK, *PEX_PUSH_LOCK*/;


    typedef struct _OBJECT_TYPE_INITIALIZER                                                                                                                                      // 25 elements, 0x70 bytes (sizeof)
    {
        /*0x000*/     UINT16       Length;
        union                                                                                                                                                                       // 2 elements, 0x1 bytes (sizeof)
        {
            /*0x002*/         UINT8        ObjectTypeFlags;
            struct                                                                                                                                                                  // 7 elements, 0x1 bytes (sizeof)
            {
                /*0x002*/             UINT8        CaseInsensitive : 1;                                                                                                                                   // 0 BitPosition
                /*0x002*/             UINT8        UnnamedObjectsOnly : 1;                                                                                                                                // 1 BitPosition
                /*0x002*/             UINT8        UseDefaultObject : 1;                                                                                                                                  // 2 BitPosition
                /*0x002*/             UINT8        SecurityRequired : 1;                                                                                                                                  // 3 BitPosition
                /*0x002*/             UINT8        MaintainHandleCount : 1;                                                                                                                               // 4 BitPosition
                /*0x002*/             UINT8        MaintainTypeList : 1;                                                                                                                                  // 5 BitPosition
                /*0x002*/             UINT8        SupportsObjectCallbacks : 1;                                                                                                                           // 6 BitPosition
            };
        };
        /*0x004*/     ULONG32      ObjectTypeCode;
        /*0x008*/     ULONG32      InvalidAttributes;
        /*0x00C*/     struct _GENERIC_MAPPING GenericMapping;                                                                                                                                     // 4 elements, 0x10 bytes (sizeof)
        /*0x01C*/     ULONG32      ValidAccessMask;
        /*0x020*/     ULONG32      RetainAccess;
        /*0x024*/     enum _POOL_TYPE PoolType;
        /*0x028*/     ULONG32      DefaultPagedPoolCharge;
        /*0x02C*/     ULONG32      DefaultNonPagedPoolCharge;
        /*0x030*/     PVOID DumpProcedure;
        /*0x038*/     PVOID OpenProcedure;
        /*0x040*/     PVOID CloseProcedure;
        /*0x048*/     PVOID DeleteProcedure;
        /*0x050*/     PVOID ParseProcedure;
        /*0x058*/     PVOID SecurityProcedure;
        /*0x060*/     PVOID QueryNameProcedure;
        /*0x068*/     PVOID OkayToCloseProcedure;
    }OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

    typedef struct _OBJECT_TYPE                   // 12 elements, 0xD0 bytes (sizeof)
    {
        /*0x000*/     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)
        /*0x010*/     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)
        /*0x020*/     VOID* DefaultObject;
        /*0x028*/     UINT8        Index;
        /*0x02C*/     ULONG32      TotalNumberOfObjects;
        /*0x030*/     ULONG32      TotalNumberOfHandles;
        /*0x034*/     ULONG32      HighWaterNumberOfObjects;
        /*0x038*/     ULONG32      HighWaterNumberOfHandles;
        /*0x040*/     struct _OBJECT_TYPE_INITIALIZER TypeInfo; // 25 elements, 0x70 bytes (sizeof)
        /*0x0B0*/     struct _EX_PUSH_LOCK TypeLock;            // 7 elements, 0x8 bytes (sizeof)
        /*0x0B8*/     ULONG32      Key;
        /*0x0C0*/     struct _LIST_ENTRY CallbackList;          // 2 elements, 0x10 bytes (sizeof)
    }OBJECT_TYPE, * POBJECT_TYPE;


    typedef struct _SYSTEM_PROCESS_INFORMATION
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
        ULONG HardFaultCount; // since WIN7
        ULONG NumberOfThreadsHighWatermark; // since WIN7
        ULONGLONG CycleTime; // since WIN7
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
        // SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
        // SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
    } SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

    typedef struct _RTL_PROCESS_MODULE_INFORMATION {
        HANDLE Section;                 // Not filled in
        PVOID MappedBase;
        unsigned long long ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        char FullPathName[0x100];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
    static_assert(sizeof(RTL_PROCESS_MODULE_INFORMATION) == 0x128, "RTL_PROCESS_MODULE_INFORMATION size is not 0x128");

    typedef struct _RTL_PROCESS_MODULES {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


    typedef enum _SYSTEM_DLL_TYPE
    {
        PsNativeSystemDll = 0,
        PsWowX86SystemDll = 1,
        PsWowArm32SystemDll = 2,
        PsWowAmd64SystemDll = 3,
        PsWowChpeX86SystemDll = 4,
        PsVsmEnclaveRuntimeDll = 5,
        PsSystemDllTotalTypes = 6
    }SYSTEM_DLL_TYPE;

    typedef struct _PEB_LDR_DATA32
    {
        ULONG 	Length;
        bool 	Initialized;
        ULONG SsHandle;
        LIST_ENTRY32 	InLoadOrderModuleList;
        LIST_ENTRY32 	InMemoryOrderModuleList;
        LIST_ENTRY32 	InInitializationOrderModuleList;
        bool 	ShutdownInProgress;
    }PEB_LDR_DATA32, * PPEB_LDR_DATA32;

    typedef struct _PEB_LDR_DATA {
        ULONG 	Length;
        bool Initialized;
        HANDLE 	SsHandle;
        LIST_ENTRY 	InLoadOrderModuleList;
        LIST_ENTRY 	InMemoryOrderModuleList;
        LIST_ENTRY 	InInitializationOrderModuleList;
        PVOID 	EntryInProgress;
        bool 	ShutdownInProgress;
        HANDLE 	ShutdownThreadId;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

    typedef struct _EWOW64PROCESS
    {
        VOID* Peb;                                                              //0x0
        USHORT Machine;                                                         //0x8
        SYSTEM_DLL_TYPE NtdllType;                                        //0xc
    }EWOW64PROCESS, * PEWOW64PROCESS;

    typedef struct _RTL_CRITICAL_SECTION_DEBUG
    {
        USHORT Type;                                                            //0x0
        USHORT CreatorBackTraceIndex;                                           //0x2
        VOID* CriticalSection;                                  //0x8
        LIST_ENTRY ProcessLocksList;                                            //0x10
        ULONG EntryCount;                                                       //0x20
        ULONG ContentionCount;                                                  //0x24
        ULONG Flags;                                                            //0x28
        USHORT CreatorBackTraceIndexHigh;                                       //0x2c
        USHORT SpareUSHORT;                                                     //0x2e
    }RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG;


    typedef struct _RTL_CRITICAL_SECTION
    {
        PRTL_CRITICAL_SECTION_DEBUG DebugInfo;                          //0x0
        LONG LockCount;                                                         //0x8
        LONG RecursionCount;                                                    //0xc
        VOID* OwningThread;                                                     //0x10
        VOID* LockSemaphore;                                                    //0x18
        ULONGLONG SpinCount;                                                    //0x20
    }RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

    typedef struct _LEAP_SECOND_DATA
    {
        UCHAR Enabled;                                                          //0x0
        ULONG Count;                                                            //0x4
        LARGE_INTEGER Data[1];                                           //0x8
    }LEAP_SECOND_DATA, * PLEAP_SECOND_DATA;


    typedef struct _PEB
    {
        UCHAR InheritedAddressSpace;                                            //0x0
        UCHAR ReadImageFileExecOptions;                                         //0x1
        UCHAR BeingDebugged;                                                    //0x2
        union
        {
            UCHAR BitField;                                                     //0x3
            struct
            {
                UCHAR ImageUsesLargePages : 1;                                    //0x3
                UCHAR IsProtectedProcess : 1;                                     //0x3
                UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
                UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
                UCHAR IsPackagedProcess : 1;                                      //0x3
                UCHAR IsAppContainer : 1;                                         //0x3
                UCHAR IsProtectedProcessLight : 1;                                //0x3
                UCHAR IsLongPathAwareProcess : 1;                                 //0x3
            };
        };
        UCHAR Padding0[4];                                                      //0x4
        VOID* Mutant;                                                           //0x8
        VOID* ImageBaseAddress;                                                 //0x10
        PEB_LDR_DATA* Ldr;                                              //0x18
        NT::RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
        VOID* SubSystemData;                                                    //0x28
        VOID* ProcessHeap;                                                      //0x30
        RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
        SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
        VOID* IFEOKey;                                                          //0x48
        union
        {
            ULONG CrossProcessFlags;                                            //0x50
            struct
            {
                ULONG ProcessInJob : 1;                                           //0x50
                ULONG ProcessInitializing : 1;                                    //0x50
                ULONG ProcessUsingVEH : 1;                                        //0x50
                ULONG ProcessUsingVCH : 1;                                        //0x50
                ULONG ProcessUsingFTH : 1;                                        //0x50
                ULONG ProcessPreviouslyThrottled : 1;                             //0x50
                ULONG ProcessCurrentlyThrottled : 1;                              //0x50
                ULONG ProcessImagesHotPatched : 1;                                //0x50
                ULONG ReservedBits0 : 24;                                         //0x50
            };
        };
        UCHAR Padding1[4];                                                      //0x54
        union
        {
            VOID* KernelCallbackTable;                                          //0x58
            VOID* UserSharedInfoPtr;                                            //0x58
        };
        ULONG SystemReserved;                                                   //0x60
        ULONG AtlThunkSListPtr32;                                               //0x64
        VOID* ApiSetMap;                                                        //0x68
        ULONG TlsExpansionCounter;                                              //0x70
        UCHAR Padding2[4];                                                      //0x74
        VOID* TlsBitmap;                                                        //0x78
        ULONG TlsBitmapBits[2];                                                 //0x80
        VOID* ReadOnlySharedMemoryBase;                                         //0x88
        VOID* SharedData;                                                       //0x90
        VOID** ReadOnlyStaticServerData;                                        //0x98
        VOID* AnsiCodePageData;                                                 //0xa0
        VOID* OemCodePageData;                                                  //0xa8
        VOID* UnicodeCaseTableData;                                             //0xb0
        ULONG NumberOfProcessors;                                               //0xb8
        ULONG NtGlobalFlag;                                                     //0xbc
        LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
        ULONGLONG HeapSegmentReserve;                                           //0xc8
        ULONGLONG HeapSegmentCommit;                                            //0xd0
        ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
        ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
        ULONG NumberOfHeaps;                                                    //0xe8
        ULONG MaximumNumberOfHeaps;                                             //0xec
        VOID** ProcessHeaps;                                                    //0xf0
        VOID* GdiSharedHandleTable;                                             //0xf8
        VOID* ProcessStarterHelper;                                             //0x100
        ULONG GdiDCAttributeList;                                               //0x108
        UCHAR Padding3[4];                                                      //0x10c
        RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
        ULONG OSMajorVersion;                                                   //0x118
        ULONG OSMinorVersion;                                                   //0x11c
        USHORT OSBuildNumber;                                                   //0x120
        USHORT OSCSDVersion;                                                    //0x122
        ULONG OSPlatformId;                                                     //0x124
        ULONG ImageSubsystem;                                                   //0x128
        ULONG ImageSubsystemMajorVersion;                                       //0x12c
        ULONG ImageSubsystemMinorVersion;                                       //0x130
        UCHAR Padding4[4];                                                      //0x134
        ULONGLONG ActiveProcessAffinityMask;                                    //0x138
        ULONG GdiHandleBuffer[60];                                              //0x140
        VOID(*PostProcessInitRoutine)();                                       //0x230
        VOID* TlsExpansionBitmap;                                               //0x238
        ULONG TlsExpansionBitmapBits[32];                                       //0x240
        ULONG SessionId;                                                        //0x2c0
        UCHAR Padding5[4];                                                      //0x2c4
        ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
        ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
        VOID* pShimData;                                                        //0x2d8
        VOID* AppCompatInfo;                                                    //0x2e0
        UNICODE_STRING CSDVersion;                                      //0x2e8
        VOID* ActivationContextData;                 //0x2f8
        VOID* ProcessAssemblyStorageMap;                //0x300
        VOID* SystemDefaultActivationContextData;    //0x308
        VOID* SystemAssemblyStorageMap;                 //0x310
        ULONGLONG MinimumStackCommit;                                           //0x318
        VOID* SparePointers[4];                                                 //0x320
        ULONG SpareUlongs[5];                                                   //0x340
        VOID* WerRegistrationData;                                              //0x358
        VOID* WerShipAssertPtr;                                                 //0x360
        VOID* pUnused;                                                          //0x368
        VOID* pImageHeaderHash;                                                 //0x370
        union
        {
            ULONG TracingFlags;                                                 //0x378
            struct
            {
                ULONG HeapTracingEnabled : 1;                                     //0x378
                ULONG CritSecTracingEnabled : 1;                                  //0x378
                ULONG LibLoaderTracingEnabled : 1;                                //0x378
                ULONG SpareTracingBits : 29;                                      //0x378
            };
        };
        UCHAR Padding6[4];                                                      //0x37c
        ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
        ULONGLONG TppWorkerpListLock;                                           //0x388
        LIST_ENTRY TppWorkerpList;                                      //0x390
        VOID* WaitOnAddressHashTable[128];                                      //0x3a0
        VOID* TelemetryCoverageHeader;                                          //0x7a0
        ULONG CloudFileFlags;                                                   //0x7a8
        ULONG CloudFileDiagFlags;                                               //0x7ac
        CHAR PlaceholderCompatibilityMode;                                      //0x7b0
        CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
        PLEAP_SECOND_DATA LeapSecondData;                               //0x7b8
        union
        {
            ULONG LeapSecondFlags;                                              //0x7c0
            struct
            {
                ULONG SixtySecondEnabled : 1;                                     //0x7c0
                ULONG Reserved : 31;                                              //0x7c0
            };
        };
        ULONG NtGlobalFlag2;                                                    //0x7c4
    }PEB, * PPEB;


    typedef struct _PEB32
    {
        UCHAR InheritedAddressSpace;                                            //0x0
        UCHAR ReadImageFileExecOptions;                                         //0x1
        UCHAR BeingDebugged;                                                    //0x2
        union
        {
            UCHAR BitField;                                                     //0x3
            struct
            {
                UCHAR ImageUsesLargePages : 1;                                    //0x3
                UCHAR IsProtectedProcess : 1;                                     //0x3
                UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
                UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
                UCHAR IsPackagedProcess : 1;                                      //0x3
                UCHAR IsAppContainer : 1;                                         //0x3
                UCHAR IsProtectedProcessLight : 1;                                //0x3
                UCHAR IsLongPathAwareProcess : 1;                                 //0x3
            };
        };
        ULONG Mutant;                                                           //0x4
        ULONG ImageBaseAddress;                                                 //0x8
        ULONG Ldr;                                                              //0xc
        ULONG ProcessParameters;                                                //0x10
        ULONG SubSystemData;                                                    //0x14
        ULONG ProcessHeap;                                                      //0x18
        ULONG FastPebLock;                                                      //0x1c
        ULONG AtlThunkSListPtr;                                                 //0x20
        ULONG IFEOKey;                                                          //0x24
        union
        {
            ULONG CrossProcessFlags;                                            //0x28
            struct
            {
                ULONG ProcessInJob : 1;                                           //0x28
                ULONG ProcessInitializing : 1;                                    //0x28
                ULONG ProcessUsingVEH : 1;                                        //0x28
                ULONG ProcessUsingVCH : 1;                                        //0x28
                ULONG ProcessUsingFTH : 1;                                        //0x28
                ULONG ProcessPreviouslyThrottled : 1;                             //0x28
                ULONG ProcessCurrentlyThrottled : 1;                              //0x28
                ULONG ProcessImagesHotPatched : 1;                                //0x28
                ULONG ReservedBits0 : 24;                                         //0x28
            };
        };
        union
        {
            ULONG KernelCallbackTable;                                          //0x2c
            ULONG UserSharedInfoPtr;                                            //0x2c
        };
        ULONG SystemReserved;                                                   //0x30
        ULONG AtlThunkSListPtr32;                                               //0x34
        ULONG ApiSetMap;                                                        //0x38
        ULONG TlsExpansionCounter;                                              //0x3c
        ULONG TlsBitmap;                                                        //0x40
        ULONG TlsBitmapBits[2];                                                 //0x44
        ULONG ReadOnlySharedMemoryBase;                                         //0x4c
        ULONG SharedData;                                                       //0x50
        ULONG ReadOnlyStaticServerData;                                         //0x54
        ULONG AnsiCodePageData;                                                 //0x58
        ULONG OemCodePageData;                                                  //0x5c
        ULONG UnicodeCaseTableData;                                             //0x60
        ULONG NumberOfProcessors;                                               //0x64
        ULONG NtGlobalFlag;                                                     //0x68
        LARGE_INTEGER CriticalSectionTimeout;                            //0x70
        ULONG HeapSegmentReserve;                                               //0x78
        ULONG HeapSegmentCommit;                                                //0x7c
        ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
        ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
        ULONG NumberOfHeaps;                                                    //0x88
        ULONG MaximumNumberOfHeaps;                                             //0x8c
        ULONG ProcessHeaps;                                                     //0x90
        ULONG GdiSharedHandleTable;                                             //0x94
        ULONG ProcessStarterHelper;                                             //0x98
        ULONG GdiDCAttributeList;                                               //0x9c
        ULONG LoaderLock;                                                       //0xa0
        ULONG OSMajorVersion;                                                   //0xa4
        ULONG OSMinorVersion;                                                   //0xa8
        USHORT OSBuildNumber;                                                   //0xac
        USHORT OSCSDVersion;                                                    //0xae
        ULONG OSPlatformId;                                                     //0xb0
        ULONG ImageSubsystem;                                                   //0xb4
        ULONG ImageSubsystemMajorVersion;                                       //0xb8
        ULONG ImageSubsystemMinorVersion;                                       //0xbc
        ULONG ActiveProcessAffinityMask;                                        //0xc0
        ULONG GdiHandleBuffer[34];                                              //0xc4
        ULONG PostProcessInitRoutine;                                           //0x14c
        ULONG TlsExpansionBitmap;                                               //0x150
        ULONG TlsExpansionBitmapBits[32];                                       //0x154
        ULONG SessionId;                                                        //0x1d4
        ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
        ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
        ULONG pShimData;                                                        //0x1e8
        ULONG AppCompatInfo;                                                    //0x1ec
        STRING32 CSDVersion;                                            //0x1f0
        ULONG ActivationContextData;                                            //0x1f8
        ULONG ProcessAssemblyStorageMap;                                        //0x1fc
        ULONG SystemDefaultActivationContextData;                               //0x200
        ULONG SystemAssemblyStorageMap;                                         //0x204
        ULONG MinimumStackCommit;                                               //0x208
        ULONG SparePointers[4];                                                 //0x20c
        ULONG SpareUlongs[5];                                                   //0x21c
        ULONG WerRegistrationData;                                              //0x230
        ULONG WerShipAssertPtr;                                                 //0x234
        ULONG pUnused;                                                          //0x238
        ULONG pImageHeaderHash;                                                 //0x23c
        union
        {
            ULONG TracingFlags;                                                 //0x240
            struct
            {
                ULONG HeapTracingEnabled : 1;                                     //0x240
                ULONG CritSecTracingEnabled : 1;                                  //0x240
                ULONG LibLoaderTracingEnabled : 1;                                //0x240
                ULONG SpareTracingBits : 29;                                      //0x240
            };
        };
        ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
        ULONG TppWorkerpListLock;                                               //0x250
        LIST_ENTRY32 TppWorkerpList;                                     //0x254
        ULONG WaitOnAddressHashTable[128];                                      //0x25c
        ULONG TelemetryCoverageHeader;                                          //0x45c
        ULONG CloudFileFlags;                                                   //0x460
        ULONG CloudFileDiagFlags;                                               //0x464
        CHAR PlaceholderCompatibilityMode;                                      //0x468
        CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
        ULONG LeapSecondData;                                                   //0x470
        union
        {
            ULONG LeapSecondFlags;                                              //0x474
            struct
            {
                ULONG SixtySecondEnabled : 1;                                     //0x474
                ULONG Reserved : 31;                                              //0x474
            };
        };
        ULONG NtGlobalFlag2;                                                    //0x478
    }PEB32, * PPEB32;


    typedef struct _PTE_HIERARCHY {
        PULONG64* pte;
        PULONG64* PDE;
        PULONG64* PDPTE;
        PULONG64* PML4E;
    }PTE_HIERARCHY, * PPTE_HIERARCHY;
}

   