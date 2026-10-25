#pragma once

#include <ntddk.h>
#include <ntstrsafe.h>

// Shared kernel debug facility used by the main driver and VT projects (ENABLE_DBG_LOG 由 Common.h 统一控制)

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
        NTSTATUS status = RtlStringCchVPrintfA(buffer, RTL_NUMBER_OF(buffer), Format, args);
        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
        {
            buffer[RTL_NUMBER_OF(buffer) - 1] = '\0';
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", buffer);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
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

