#include "DriverCore.h"

/*
 * DriverEntry — 驱动标准主入口点
 * 遵循纯静态类架构：所有初始化、模块探测与派遣逻辑统一交由 DriverCore 接管
 */
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryPath)
{
    return DriverCore::Initialize(pDriverObj, pRegistryPath);
}
