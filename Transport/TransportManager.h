#pragma once

#include "FrameWork.h"
#include "wsk_server.h"
#include "usb_server.h"
#include "udp_server.h"

typedef enum _MK_SERVER_MODE
{
    MK_SERVER_MODE_NONE = 0,
    MK_SERVER_MODE_WSK_TCP = 1,
    MK_SERVER_MODE_USB = 2,
    MK_SERVER_MODE_WSK_UDP = 3,
} MK_SERVER_MODE;

typedef struct _MK_SERVER_START_PARAMS
{
    ULONG Mode;
    ULONG Port;
    ULONG Flags;
    UCHAR PipeIn;
    UCHAR PipeOut;
    USHORT Reserved;
    WCHAR DevicePath[260];
} MK_SERVER_START_PARAMS, *PMK_SERVER_START_PARAMS;

typedef struct _MK_SERVER_STATUS
{
    ULONG Mode;
    ULONG Port;
    LONG ActiveConnections;
    BOOLEAN fRunning;
} MK_SERVER_STATUS, *PMK_SERVER_STATUS;


#define MACHENIKE_START_SERVER_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x510, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MACHENIKE_STOP_SERVER_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x511, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MACHENIKE_GET_STATUS_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x512, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MACHENIKE_DISCOVER_DEVICE_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x513, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- WFP Bypass 控制 IOCTL ---- */
#define MACHENIKE_INSTALL_BYPASS_IOCTL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x514, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MACHENIKE_REMOVE_BYPASS_IOCTL     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x515, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MACHENIKE_GET_BYPASS_STATUS_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x516, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- MSR 寄存器读取 IOCTL (仿照 ComputerZ_x64.sys 0xF10024C0 实现) ---- */
#define MACHENIKE_READ_MSR_IOCTL          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x517, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define COMPUTERZ_READ_MSR_IOCTL          0xF10024C0

typedef struct _MK_MSR_DATA
{
    union
    {
        ULONG   MsrIndex;   /* 输入：MSR 寄存器编号，例如 0xC0000082 (IA32_LSTAR) */
        ULONG64 Value;      /* 输出：读取到的 64 位 MSR 值 */
    };
    ULONG ReturnCode;       /* 状态码 / 回显控制码 (如 0xF10024C0) */
} MK_MSR_DATA, *PMK_MSR_DATA;

#define MK_BYPASS_FLAG_WFP_DKOM     0x00000004
#define MK_BYPASS_FLAG_ALL          (MK_BYPASS_FLAG_WFP_DKOM)

typedef struct _MK_BYPASS_PARAMS
{
    ULONG Flags;         /* MK_BYPASS_FLAG_*，0 或未提供输入则默认全部安装 */
    ULONG WfpHiddenPort; /* 指定 WFP 隐藏的目标端口（默认 0 使用默认端口 10001） */
} MK_BYPASS_PARAMS, *PMK_BYPASS_PARAMS;

typedef struct _MK_BYPASS_STATUS
{
    ULONG Flags;                     /* 当前处于激活状态的模块标志位 */
    BOOLEAN WfpBypassInstalled;      /* WFP DKOM Bypass 是否已生效 */
    UCHAR   Reserved[3];
    ULONG   WfpHiddenPort;           /* 当前 WFP 隐藏的端口 */
} MK_BYPASS_STATUS, *PMK_BYPASS_STATUS;

#include "Common.h"
#include "udp_discovery.h"

#ifdef __cplusplus
// ============================================================
// TransportManager: 统一跨环传输层管理器类 (纯静态类)
// ============================================================
class TransportManager
{
public:
    static VOID Init(_In_opt_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    static VOID SetSessionCryptKey(ULONG64 CryptKey);
    static ULONG64 GetSessionCryptKey(VOID);
    static NTSTATUS StartServer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _In_ PMK_SERVER_START_PARAMS pParams);
    static VOID StopServer(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);
    static VOID GetStatus(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar, _Out_ PMK_SERVER_STATUS pStatus);
    static ULONG GetDiscoveredClientIp(VOID);
};
#endif



#ifdef __cplusplus
extern "C" {
#endif
ULONG64 Transport_GetSessionCryptKey(VOID);
VOID Transport_SetSessionCryptKey(ULONG64 CryptKey);
#ifdef __cplusplus
}
#endif
