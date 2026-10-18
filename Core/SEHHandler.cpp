#include "Common.h"

extern "C"
{
    /*
     * Zero IAT 本地 SEH 异常分发桩:
     * 拦截编译器对 ntoskrnl.exe!__C_specific_handler 的导入依赖，
     * 运行时动态转调真实 ntoskrnl 异常处理器，实现完全 0 静态导入表。
     */
    EXCEPTION_DISPOSITION __C_specific_handler(
        struct _EXCEPTION_RECORD *ExceptionRecord,
        void *EstablisherFrame,
        struct _CONTEXT *ContextRecord,
        struct _DISPATCHER_CONTEXT *DispatcherContext)
    {
        if (g_pGlobalUserVar && g_pGlobalUserVar->Func.pfnCSpecificHandler)
        {
            return g_pGlobalUserVar->Func.pfnCSpecificHandler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
        }
        return ExceptionContinueSearch;
    }
}
