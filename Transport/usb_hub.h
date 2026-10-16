#pragma once

#include "Common.h"
#include <usb.h>
#include <usbioctl.h>

#ifndef MK_USB_POOL_TAG
// ACE对抗：伪装为 I/O Manager 通用 Tag，规避 BigPool 枚举审计
#define MK_USB_POOL_TAG 'mNoI'
#endif

#define USBHUB_SCAN_RANGE_BYTES     0x40000
#define USBHUB_SCAN_ALIGN           4
#define USBHUB_BULK_PIPE_TYPE       2
#define USBHUB_MIN_PACKET_SIZE      64
#define USBHUB_MAX_PACKET_SIZE      1024

#ifdef __cplusplus
extern "C"
{
#endif

NTSTATUS UsbHub_Init(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ PDEVICE_OBJECT pWinUsbFdo,
    _In_ UCHAR epIn,
    _In_ UCHAR epOut);

VOID UsbHub_Cleanup(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);

NTSTATUS UsbHub_BulkRead(
    _In_  MACHENIKE_KERNEL_INTERFACE *UserVar,
    _Out_ PVOID pBuf,
    _In_  ULONG cbBuf,
    _Out_ PULONG pcbRead);

NTSTATUS UsbHub_BulkWrite(
    _In_  MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_  PVOID pBuf,
    _In_  ULONG cbBuf,
    _Out_ PULONG pcbWritten);

// ★★★ 全双工重叠 I/O：常驻 IRP / MDL 零分配快速读与双缓冲异步写 ★★★
NTSTATUS UsbHub_BulkReadFast(
    _In_  MACHENIKE_KERNEL_INTERFACE *UserVar,
    _Out_ PVOID pBuf,
    _In_  PMDL pMdl,
    _In_  ULONG cbBuf,
    _Out_ PULONG pcbRead);

NTSTATUS UsbHub_BulkWriteAsync(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ ULONG slotIndex,
    _In_ PVOID pBuf,
    _In_ PMDL pMdl,
    _In_ ULONG cbBuf);

NTSTATUS UsbHub_WaitWriteSlot(
    _In_      MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_      ULONG slotIndex,
    _Out_opt_ PULONG pcbWritten);

NTSTATUS UsbHub_AbortPipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ BOOLEAN bIsIn);

NTSTATUS UsbHub_ResetPipe(
    _In_ MACHENIKE_KERNEL_INTERFACE *UserVar,
    _In_ BOOLEAN bIsIn);

BOOLEAN UsbHub_IsReady(VOID);
BOOLEAN UsbHub_HasAceInfo(VOID);

#ifdef __cplusplus
}
#endif
