#pragma once
#include "FrameWork.h"

// ============================================================================
// 【驱动全局调试与功能开关控制台】(集中管理，方便调试一键切换)
// ============================================================================
// 1. 日志输出总开关 (1: 开启内核 DbgPrint 输出; 0: 完全关闭调试输出，无痕模式)
#ifndef ENABLE_DBG_LOG
#define ENABLE_DBG_LOG 1
#endif

// 2. 驱动加载模式开关:
//    0 = 正常驱动加载模式 (标准 SCM 服务加载 / 注册 DriverUnload / 创建 \\Device\\MachenikeIo / 通过 IOCTL
//    控制随时启动或停止) 1 = 手动映射模式 (Manual Map / Shellcode 挂接 / 擦除 DriverObject / 免签名加载)
#ifndef MK_ENABLE_MANUAL_MAP
#define MK_ENABLE_MANUAL_MAP 0
#endif

// 3. ACE 反作弊后台常驻监控引擎开关:
//    1 = 开启后台 WorkItem 持续心跳探测 ACE 模块（应对游戏关闭与重启重新捕获基址）
//    0 = 关闭后台监控引擎
#ifndef ENABLE_ACE_MONITOR_ENGINE
#define ENABLE_ACE_MONITOR_ENGINE 0
#endif

// 4. WFP Bypass 过滤绕过总开关宏:
//    1 = 开启 WFP 端口隐藏与 Bypass 过滤引擎 (仅在 TCP/UDP 网络通信模式下生效)
//    0 = 关闭 WFP 绕过
#ifndef ENABLE_WFP_BYPASS
#define ENABLE_WFP_BYPASS 0
#endif

// 5. WFP Callout 替换执行模式:
//    0 = 仅检测是否存在 ACE 的 Callout 回调 (只读探测模式，不修改任何内核内存，安全无风险)
//    1 = 实际执行 Callout 表项原子替换 (正式绕过模式)
#ifndef WFP_ENABLE_CALLOUT_REPLACE
#define WFP_ENABLE_CALLOUT_REPLACE 0
#endif

// 6. UDP 客户端握手发现开关 (针对手动映射模式/预启动):
//    1 = 启动网络服务端前先执行 5 秒 UDP 局域网广播握手发现客户端
//    0 = 跳过发现，直接拉起 TCP/UDP 服务端 (同机或单机调试推荐)
#ifndef ENABLE_UDP_CLIENT_DISCOVERY
#define ENABLE_UDP_CLIENT_DISCOVERY 0
#endif

// 7. ACE 对抗 - 伪造 LDR 表项开关:
//    1 = 启用（伪造/顶替 LDR 链表项对抗模块扫描）
//    0 = 禁用（保留宿主原生状态，不进行 LDR 链表摘除与伪造）
#ifndef MK_ENABLE_FAKE_LDR
#define MK_ENABLE_FAKE_LDR 0
#endif

// 8. 调试免认证与免删 Loader 开关宏 (NoAuth 开关):
//    1 = 开启免认证模式 (跳过应用层 Token 验证、放行设备打开与协议交互、不粉碎/不删除 host_loader，便于单机开发调试)
//    0 = 正式安全发布模式 (严格执行 Token 防伪验证并精准异步粉碎 host_loader)
#ifndef NO_AUTH
#define NO_AUTH 1
#endif

#ifndef ENABLE_NO_AUTH
#define ENABLE_NO_AUTH NO_AUTH
#endif

#if defined(NOAUTH) && (NOAUTH)
#undef NO_AUTH
#define NO_AUTH 1
#undef ENABLE_NO_AUTH
#define ENABLE_NO_AUTH 1
#endif

// ============================================================================
// 【内核纯游离物理页 GUID 签名防重复加载暗桩】(方案 5: Headless Physical Canary)
// 特性：
// 1. 彻底废除 KUSER_SHARED_DATA 写入（彻底杜绝 PatchGuard 0x109 蓝屏）
// 2. 基于 MmAllocatePagesForMdl 申请纯游离物理页，无 Pool 登记、无内核 VA 映射
// 3. 采用限定窗口 [256MB ~ 512MB] 分配，提供毫秒级高速特征检索
// ============================================================================
#define DRV_CANARY_WINDOW_LOW 0x10000000ULL        // 256MB 起
#define DRV_CANARY_WINDOW_HIGH 0x20000000ULL       // 512MB 止
#define DRV_WSK_CANARY_MAGIC 0x57534B5F4C4F4144ULL // "WSK_LOAD"

// 128 位高熵全局唯一特征签名: {57534B5F-4C4F-4144-B899-A1B2C3D4E5F6}
#define DRV_CANARY_GUID_D1 0x57534B5FUL
#define DRV_CANARY_GUID_D2 0x4C4F
#define DRV_CANARY_GUID_D3 0x4144
#define DRV_CANARY_GUID_D4 {0xB8, 0x99, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6}

#pragma pack(push, 1)
typedef struct _DRV_WSK_CANARY
{
    GUID Signature;         // 16 字节全局唯一 GUID
    ULONG64 Magic;          // DRV_WSK_CANARY_MAGIC (8 字节)
    ULONG64 KernelImageVA;  // 映射的目标核心驱动基址 (8 字节)
    ULONG ImageSize;        // 核心驱动镜像大小 (4 字节)
    ULONG ProtocolVersion;  // 协议版本 (4 字节)
    ULONG64 CanaryPhysAddr; // 该物理页自身的 PA (8 字节)
    ULONG64 Timestamp;      // 加载时间戳 (8 字节)
    ULONG64 Reserved;       // 保留填充 (8 字节)
} DRV_WSK_CANARY, *PDRV_WSK_CANARY;
#pragma pack(pop)

#if ENABLE_DBG_LOG

#pragma warning(push)
#pragma warning(disable : 4505)
__declspec(noinline) static VOID SafeDbgPrint(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    CHAR buffer[512];
    va_list args;
    va_start(args, Format);

    __try
    {
        buffer[0] = '\0';
        NTSTATUS status = RtlStringCchVPrintfA(buffer, sizeof(buffer), Format, args);
        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
        {
            buffer[sizeof(buffer) - 1] = '\0';
            DbgPrint("%s", buffer);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 捕获异常（如非法指针访问、参数解引用缺页等），防止内核蓝屏崩溃
    }

    va_end(args);
}
#pragma warning(pop)

#ifdef DBG
#undef DBG
#endif
#define DBG(fmt, ...) SafeDbgPrint("[DBG] " fmt "\n", ##__VA_ARGS__)
#else
#ifdef DBG
#undef DBG
#endif
#define DBG(...) ((void)0)
#endif
// ============================================================
// Loader 注入启动配置参数（由 Loader 在 DriverEntry rdx 传入）
// 完全取代任何 IOCTL/设备对象/符号链接交互
// ============================================================
#define DRV_BOOT_CONFIG_MAGIC 0x57534B43U // 'WSKC'
#define DRV_BOOT_MAGIC DRV_BOOT_CONFIG_MAGIC
#define DRV_TRANSPORT_TCP 2
#define DRV_TRANSPORT_UDP 3
#define DRV_TRANSPORT_USB 4

#pragma pack(push, 1)
typedef struct _DRV_BOOT_CONFIG
{
    ULONG Magic;         // DRV_BOOT_CONFIG_MAGIC ('WSKC')
    ULONG TransportMode; // 2 = WSK_TCP, 3 = WSK_UDP, 4 = USB
    USHORT Port;         // 通信端口 (如 10001 / 10002)
    USHORT Reserved;
    ULONG AuthToken;        // 握手认证 Token
    ULONG Flags;            // 特性开关
    UCHAR SessionToken[16]; // 云端下发的随机鉴权熵 (扩展防伪校验)
} DRV_BOOT_CONFIG, *PDRV_BOOT_CONFIG;

typedef struct _DRV_BOOT_CONFIG_EX
{
    DRV_BOOT_CONFIG Base;
    WCHAR HostLoaderPath[260]; // 宿主加载器自身绝对路径 (供内核入口挂靠系统线程执行针对性粉碎删除)
    CHAR ApiUrl[128];          // 业务 API 地址
    CHAR LoginUrl[128];        // 鉴权 API 地址
    CHAR ReportUrl[128];       // 上报 API 地址
    CHAR BrandVersion[32];     // 品牌版本
    CHAR SelectedGame[32];     // 所选游戏标识
    CHAR ClientVersion[32];    // 客户端版本
} DRV_BOOT_CONFIG_EX, *PDRV_BOOT_CONFIG_EX;

typedef struct _DRV_BOOT_RESPONSE
{
    NTSTATUS Status;        // 执行状态 (STATUS_SUCCESS = 0)
    USHORT BoundPort;       // 实际生效端口
    USHORT TransportMode;   // 实际生效模式
    UINT64 DriverSignature; // 驱动基于 Token 与内核私钥生成的 SipHash24 指纹
} DRV_BOOT_RESPONSE, *PDRV_BOOT_RESPONSE;

typedef struct _DRV_USER_PAYLOAD_ANCHOR
{
    UINT64 Tag0;                                  // 动态哈希 Tag0 (由动态 Token 派生)
    UINT64 Tag1;                                  // 动态哈希 Tag1 (~Tag0 ^ 0xA5A5A5A55A5A5A5AULL)
    ULONG Nonce;                                  // 随机 Nonce 动态盐
    ULONG CipherLen;                              // 密文长度 (sizeof(DRV_BOOT_CONFIG_EX))
    ULONG Checksum;                               // 明文 Adler32 校验和
    ULONG Reserved;                               // 对齐填充
    UCHAR CipherData[sizeof(DRV_BOOT_CONFIG_EX)]; // RC4 密文载荷
} DRV_USER_PAYLOAD_ANCHOR, *PDRV_USER_PAYLOAD_ANCHOR;
#pragma pack(pop)

static const UCHAR g_SipHashKey[16] = {0x21, 0x7A, 0xA9, 0x3C, 0x10, 0x55, 0xD2, 0x6F, 0x9B, 0x4E, 0x01, 0x88, 0xC7, 0x33, 0xFA, 0x90};

// ============================================================
// 正常加载模式下的 IOCTL 通信控制码与设备名称定义
// 供 R3 应用程序通过 DeviceIoControl 动态下发参数并启动不同传输模式
// ============================================================
#define IOCTL_MK_START_TRANSPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_STOP_TRANSPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MK_DISCOVER_CLIENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MK_DEVICE_NAME L"\\Device\\MsNetEndpoint"
#define MK_DOS_DEVICE_NAME L"\\DosDevices\\MsNetEndpoint"
#define MK_USER_DEVICE_NAME L"\\\\.\\MsNetEndpoint"

// ACE对抗：通用池 Tag 伪装为 MiniFilter 系统 Tag，规避 BigPool 审计
#define MK_POOL_TAG 'lsMF'
#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

typedef NTSTATUS(NTAPI *FuncTypeDef_RtlGetVersion)(_Out_ _At_(lpVersionInformation->dwOSVersionInfoSize, _Pre_ _Valid_)
                                                       _When_(lpVersionInformation->dwOSVersionInfoSize == sizeof(RTL_OSVERSIONINFOEXW),
                                                              _At_((PRTL_OSVERSIONINFOEXW)lpVersionInformation, _Out_))
                                                           PRTL_OSVERSIONINFOW lpVersionInformation);

typedef VOID(NTAPI *FuncTypeDef_RtlInitUnicodeString)(_Out_ PUNICODE_STRING DestinationString,
                                                      _In_opt_z_ __drv_aliasesMem PCWSTR SourceString);

typedef PMDL(NTAPI *FuncTypeDef_IoAllocateMdl)(_In_opt_ __drv_aliasesMem PVOID VirtualAddress, _In_ ULONG Length,
                                               _In_ BOOLEAN SecondaryBuffer, _In_ BOOLEAN ChargeQuota, _Inout_opt_ PIRP Irp);

typedef VOID(NTAPI *FuncTypeDef_IoFreeMdl)(PMDL Mdl);

typedef NTSTATUS(NTAPI *FuncTypeDef_IoCreateDevice)(
    _In_ PDRIVER_OBJECT DriverObject, _In_ ULONG DeviceExtensionSize, _In_opt_ PUNICODE_STRING DeviceName, _In_ DEVICE_TYPE DeviceType,
    _In_ ULONG DeviceCharacteristics, _In_ BOOLEAN Exclusive,
    _Outptr_result_nullonfailure_ _At_(*DeviceObject, __drv_allocatesMem(Mem) _When_((((_In_function_class_(DRIVER_INITIALIZE)) ||
                                                                                       (_In_function_class_(DRIVER_DISPATCH)))),
                                                                                     __drv_aliasesMem)) PDEVICE_OBJECT *DeviceObject);

typedef NTSTATUS(NTAPI *FuncTypeDef_IoCreateSymbolicLink)(_In_ PUNICODE_STRING SymbolicLinkName, _In_ PUNICODE_STRING DeviceName);
typedef VOID(NTAPI *FuncTypeDef_IoDeleteDevice)(_In_ __drv_freesMem(Mem) PDEVICE_OBJECT DeviceObject);
typedef NTSTATUS(FASTCALL *FuncTypeDef_IoDeleteSymbolicLink)(_In_ PUNICODE_STRING SymbolicLinkName);
typedef VOID(FASTCALL *FuncTypeDef_IofCompleteRequest)(_In_ PIRP Irp, _In_ CCHAR PriorityBoost);
typedef ULONG(__cdecl *FuncTypeDef_DbgPrint)(_In_z_ _Printf_format_string_ PCSTR Format, ...);
typedef VOID(NTAPI *FuncTypeDef_ProbeForRead)(__in_data_source(USER_MODE) _Inout_updates_bytes_(Length) volatile VOID *Address,
                                              _In_ SIZE_T Length, _In_ ULONG Alignment);

typedef VOID(NTAPI *FuncTypeDef_ProbeForWrite)(__in_data_source(USER_MODE) _Inout_updates_bytes_(Length) volatile VOID *Address,
                                               _In_ SIZE_T Length, _In_ ULONG Alignment);

typedef PVOID(NTAPI *FuncTypeDef_ExAllocatePoolWithTag)(_In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
                                                        _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);

typedef VOID(NTAPI *FuncTypeDef_ExFreePoolWithTag)(_Pre_notnull_ __drv_freesMem(Mem) PVOID P, _In_ ULONG Tag);

typedef NTSTATUS(NTAPI *FuncTypeDef_ZwOpenSection)(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                                                   _In_ POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(NTAPI *FuncTypeDef_ZwClose)(_In_ HANDLE Handle);

typedef VOID(NTAPI *FuncTypeDef_MmProbeAndLockPages)(_Inout_ PMDL MemoryDescriptorList, _In_ KPROCESSOR_MODE AccessMode,
                                                     _In_ LOCK_OPERATION Operation);

typedef VOID(NTAPI *FuncTypeDef_MmUnlockPages)(_Inout_ PMDL MemoryDescriptorList);

typedef PVOID(NTAPI *FuncTypeDef_MmMapLockedPagesSpecifyCache)(_Inout_ PMDL MemoryDescriptorList,
                                                               _In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)
                                                                   KPROCESSOR_MODE AccessMode,
                                                               _In_ __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType,
                                                               _In_opt_ PVOID RequestedAddress, _In_ ULONG BugCheckOnFailure,
                                                               _In_ ULONG Priority);
typedef PPHYSICAL_MEMORY_RANGE(NTAPI *FuncTypeDef_MmGetPhysicalMemoryRanges)(VOID);
typedef KIRQL(NTAPI *FuncTypeDef_KeGetCurrentIrql)(VOID);
typedef KAFFINITY(NTAPI *FuncTypeDef_KeQueryActiveProcessors)(VOID);
typedef VOID(NTAPI *FuncTypeDef_KeSetSystemAffinityThread)(_In_ KAFFINITY Affinity);
typedef VOID(NTAPI *FuncTypeDef_KeRevertToUserAffinityThread)(VOID);
typedef VOID(NTAPI *FuncTypeDef_KeQuerySystemTimePrecise)(_Out_ PLARGE_INTEGER CurrentTime);
typedef HANDLE(NTAPI *FuncTypeDef_PsGetCurrentProcessId)(VOID);
typedef void *(__cdecl *FuncTypeDef_memset)(_Out_writes_bytes_all_(_Size) void *_Dst, _In_ int _Val, _In_ size_t _Size);
typedef void *(__cdecl *FuncTypeDef_memcpy)(_Out_writes_bytes_all_(_MaxCount) void *_Dst, _In_reads_bytes_(_MaxCount) const void *_Src,
                                            _In_ size_t _MaxCount);

typedef void *(__cdecl *FuncTypeDef_memmove)(_Out_writes_bytes_all_opt_(_Size) void *_Dst, _In_reads_bytes_opt_(_Size) const void *_Src,
                                             _In_ size_t _Size);

typedef size_t(__cdecl *FuncTypeDef_strlen)(_In_z_ const char *_Str);

typedef void(NTAPI *FuncTypeDef_RtlCopyMemory)(_Out_writes_bytes_all_(_Length) void *_Destination,
                                               _In_reads_bytes_(_Length) const void *_Source, _In_ size_t _Length);

typedef void(NTAPI *FuncTypeDef_RtlZeroMemory)(_Out_writes_bytes_all_(_Length) void *_Destination, _In_ size_t _Length);

typedef NTSTATUS(NTAPI *FuncTypeDef_KeDelayExecutionThread)(_In_ KPROCESSOR_MODE WaitMode, _In_ BOOLEAN Alertable,
                                                            _In_ PLARGE_INTEGER Interval);
typedef NTSTATUS(NTAPI *FuncTypeDef_PsTerminateSystemThread)(_In_ NTSTATUS ExitStatus);
typedef NTSTATUS(NTAPI *FuncTypeDef_PsCreateSystemThread)(_Out_ PHANDLE ThreadHandle, _In_ ULONG DesiredAccess,
                                                          _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ HANDLE ProcessHandle,
                                                          _Out_opt_ PCLIENT_ID ClientId, _In_ PKSTART_ROUTINE StartRoutine,
                                                          _In_opt_ PVOID StartContext);
typedef LARGE_INTEGER(NTAPI *FuncTypeDef_KeQueryPerformanceCounter)(_Out_opt_ PLARGE_INTEGER PerformanceFrequency);
typedef PIRP(NTAPI *FuncTypeDef_IoAllocateIrp)(_In_ CCHAR StackSize, _In_ BOOLEAN ChargeQuota);
typedef VOID(NTAPI *FuncTypeDef_IoFreeIrp)(_In_ PIRP Irp);
typedef VOID(NTAPI *FuncTypeDef_KeInitializeEvent)(_Out_ PRKEVENT Event, _In_ EVENT_TYPE Type, _In_ BOOLEAN State);
typedef NTSTATUS(NTAPI *FuncTypeDef_KeWaitForSingleObject)(_In_ _Points_to_data_ PVOID Object,
                                                           _In_ _Strict_type_match_ KWAIT_REASON WaitReason,
                                                           _In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)
                                                               KPROCESSOR_MODE WaitMode,
                                                           _In_ BOOLEAN Alertable, _In_opt_ PLARGE_INTEGER Timeout);
typedef LONG(NTAPI *FuncTypeDef_KeSetEvent)(_Inout_ PRKEVENT Event, _In_ KPRIORITY Increment, _In_ _Literal_ BOOLEAN Wait);
typedef NTSTATUS(NTAPI *FuncTypeDef_ZwCreateFile)(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
                                                  _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                                  _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes, _In_ ULONG ShareAccess,
                                                  _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions,
                                                  _In_reads_bytes_opt_(EaLength) PVOID EaBuffer, _In_ ULONG EaLength);
typedef NTSTATUS(NTAPI *FuncTypeDef_ZwReadFile)(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine,
                                                _In_opt_ PVOID ApcContext, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                                _Out_writes_bytes_(Length) PVOID Buffer, _In_ ULONG Length,
                                                _In_opt_ PLARGE_INTEGER ByteOffset, _In_opt_ PULONG Key);
typedef NTSTATUS(NTAPI *FuncTypeDef_ZwWriteFile)(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine,
                                                 _In_opt_ PVOID ApcContext, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                                 _In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Length,
                                                 _In_opt_ PLARGE_INTEGER ByteOffset, _In_opt_ PULONG Key);
typedef NTSTATUS(NTAPI *FuncTypeDef_ZwDeviceIoControlFile)(
    _In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG IoControlCode, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength);
typedef NTSTATUS(NTAPI *FuncTypeDef_IoGetDeviceInterfaces)(_In_ CONST GUID *InterfaceClassGuid,
                                                           _In_opt_ PDEVICE_OBJECT PhysicalDeviceObject, _In_ ULONG Flags,
                                                           _Outptr_result_nullonfailure_ PWSTR *SymbolicLinkList);
typedef NTSTATUS(NTAPI *FuncTypeDef_ObReferenceObjectByHandle)(_In_ HANDLE Handle, _In_ ACCESS_MASK DesiredAccess,
                                                               _In_opt_ POBJECT_TYPE ObjectType, _In_ KPROCESSOR_MODE AccessMode,
                                                               _Out_ PVOID *Object, _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation);
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
typedef PDEVICE_OBJECT(NTAPI *FuncTypeDef_IoAttachDeviceToDeviceStack)(_In_ PDEVICE_OBJECT SourceDevice, _In_ PDEVICE_OBJECT TargetDevice);
typedef VOID(NTAPI *FuncTypeDef_IoDetachDevice)(_Inout_ PDEVICE_OBJECT TargetDevice);
typedef NTSTATUS(NTAPI *FuncTypeDef_IoCallDriver)(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
typedef VOID(FASTCALL *FuncTypeDef_ExAcquireFastMutex)(_Inout_ PFAST_MUTEX FastMutex);
typedef VOID(FASTCALL *FuncTypeDef_ExReleaseFastMutex)(_Inout_ PFAST_MUTEX FastMutex);

/* ---- 敏感内核与同步操作函数类型定义 ---- */
typedef PVOID(NTAPI *FuncTypeDef_MmGetVirtualForPhysical)(_In_ PHYSICAL_ADDRESS PhysicalAddress);
typedef PVOID(NTAPI *FuncTypeDef_RtlPcToFileHeader)(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);
typedef BOOLEAN(NTAPI *FuncTypeDef_MmIsAddressValid)(_In_ PVOID VirtualAddress);
typedef VOID(NTAPI *FuncTypeDef_MmBuildMdlForNonPagedPool)(_Inout_ PMDL MemoryDescriptorList);
typedef PDEVICE_OBJECT(NTAPI *FuncTypeDef_IoGetLowerDeviceObject)(_In_ PDEVICE_OBJECT DeviceObject);
typedef LONG_PTR(FASTCALL *FuncTypeDef_ObfReferenceObject)(_In_ PVOID Object);
typedef BOOLEAN(NTAPI *FuncTypeDef_IoCancelIrp)(_In_ PIRP Irp);
typedef VOID(NTAPI *FuncTypeDef_KeInitializeSpinLock)(_Out_ PKSPIN_LOCK SpinLock);
typedef KIRQL(NTAPI *FuncTypeDef_KeAcquireSpinLockRaiseToDpc)(_Inout_ PKSPIN_LOCK SpinLock);
typedef VOID(NTAPI *FuncTypeDef_KeReleaseSpinLock)(_Inout_ PKSPIN_LOCK SpinLock, _In_ _IRQL_restores_ KIRQL NewIrql);
typedef VOID(NTAPI *FuncTypeDef_KeLowerIrql)(_In_ _IRQL_restores_ KIRQL NewIrql);
typedef KIRQL(FASTCALL *FuncTypeDef_KfRaiseIrql)(_In_ KIRQL NewIrql);
typedef VOID(NTAPI *FuncTypeDef_KeInitializeMutex)(_Out_ PRKMUTEX Mutex, _In_ ULONG Level);
typedef LONG(NTAPI *FuncTypeDef_KeReleaseMutex)(_Inout_ PRKMUTEX Mutex, _In_ BOOLEAN Wait);
typedef VOID(NTAPI *FuncTypeDef_KeClearEvent)(_Inout_ PRKEVENT Event);
typedef ULONG(NTAPI *FuncTypeDef_KeQueryTimeIncrement)(VOID);
typedef BOOLEAN(NTAPI *FuncTypeDef_KeCancelTimer)(_Inout_ PKTIMER Timer);

struct _WSK_CLIENT_NPI;
struct _WSK_REGISTRATION;
struct _WSK_PROVIDER_NPI;
typedef NTSTATUS(NTAPI *FuncTypeDef_WskRegister)(_In_ const struct _WSK_CLIENT_NPI *WskClientNpi,
                                                 _Out_ struct _WSK_REGISTRATION *WskRegistration);
typedef NTSTATUS(NTAPI *FuncTypeDef_WskCaptureProviderNPI)(_In_ struct _WSK_REGISTRATION *WskRegistration, _In_ ULONG WaitTimeout,
                                                           _Out_ struct _WSK_PROVIDER_NPI *WskProviderNpi);
typedef VOID(NTAPI *FuncTypeDef_WskReleaseProviderNPI)(_In_ struct _WSK_REGISTRATION *WskRegistration);
typedef VOID(NTAPI *FuncTypeDef_WskDeregister)(_In_ struct _WSK_REGISTRATION *WskRegistration);

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
    FuncTypeDef_IoGetDeviceObjectPointer IoGetDeviceObjectPointer;
    FuncTypeDef_IoAttachDeviceToDeviceStack IoAttachDeviceToDeviceStack;
    FuncTypeDef_IoDetachDevice IoDetachDevice;
    FuncTypeDef_IoCallDriver IoCallDriver;
    FuncTypeDef_ExAcquireFastMutex ExAcquireFastMutex;
    FuncTypeDef_ExReleaseFastMutex ExReleaseFastMutex;

    /* 敏感反作弊特征函数动态解析（ntoskrnl.exe） */
    FuncTypeDef_MmGetVirtualForPhysical MmGetVirtualForPhysical;
    FuncTypeDef_RtlPcToFileHeader RtlPcToFileHeader;
    FuncTypeDef_MmIsAddressValid MmIsAddressValid;
    FuncTypeDef_MmBuildMdlForNonPagedPool MmBuildMdlForNonPagedPool;
    FuncTypeDef_IoGetLowerDeviceObject IoGetLowerDeviceObject;
    FuncTypeDef_ObfReferenceObject ObfReferenceObject;
    FuncTypeDef_IoCancelIrp IoCancelIrp;
    FuncTypeDef_KeInitializeSpinLock KeInitializeSpinLock;
    FuncTypeDef_KeAcquireSpinLockRaiseToDpc KeAcquireSpinLockRaiseToDpc;
    FuncTypeDef_KeReleaseSpinLock KeReleaseSpinLock;
    FuncTypeDef_KeLowerIrql KeLowerIrql;
    FuncTypeDef_KfRaiseIrql KfRaiseIrql;
    FuncTypeDef_KeInitializeMutex KeInitializeMutex;
    FuncTypeDef_KeReleaseMutex KeReleaseMutex;
    FuncTypeDef_KeClearEvent KeClearEvent;
    FuncTypeDef_KeQueryTimeIncrement KeQueryTimeIncrement;
    FuncTypeDef_KeCancelTimer KeCancelTimer;
    PEPROCESS *pPsInitialSystemProcess;
    POBJECT_TYPE *pPsThreadType;
    /* WSK 套接字函数（来自 netio.sys） */
    FuncTypeDef_WskRegister WskRegister;
    FuncTypeDef_WskCaptureProviderNPI WskCaptureProviderNPI;
    FuncTypeDef_WskReleaseProviderNPI WskReleaseProviderNPI;
    FuncTypeDef_WskDeregister WskDeregister;
} MACHENIKE_PFN, *PMACHENIKE_PFN;

typedef struct _MACHENIKE_KERNEL_INTERFACE
{
    MACHENIKE_PFN Func;
    ULONG HashStringImulMagicValue;
    PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange;
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
struct _KLDR_DATA_TABLE_ENTRY;
#define ACE_MAX_TRACKED_MODULES 16
typedef struct _ACE_MODULE_RANGE
{
    ULONG_PTR Base;
    ULONG_PTR End;
    ULONG Hash;
    WCHAR Name[32];
} ACE_MODULE_RANGE;

#ifdef __cplusplus
extern "C"
{
#endif

    /* 全局 ACE 反作弊驱动探测缓存（支持同时追踪多个核心模块如 102706/202706/302706） */
    extern ACE_MODULE_RANGE g_AceModules[ACE_MAX_TRACKED_MODULES];
    extern ULONG g_AceModuleCount;
    extern ULONG_PTR g_AceModuleBase;
    extern ULONG_PTR g_AceModuleEnd;
    extern BOOLEAN g_bAceDetected;

    FORCEINLINE BOOLEAN IsAddressInAceModules(ULONG_PTR Address)
    {
        if (!g_bAceDetected || !Address)
            return FALSE;
        for (ULONG i = 0; i < g_AceModuleCount && i < ACE_MAX_TRACKED_MODULES; i++)
        {
            if (Address >= g_AceModules[i].Base && Address < g_AceModules[i].End)
                return TRUE;
        }
        return FALSE;
    }

#ifdef __cplusplus
}
#endif
