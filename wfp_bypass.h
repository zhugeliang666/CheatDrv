#pragma once
#include "Common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * wfp_bypass.h
 * ACE WFP Callout DKOM 绕过接口  [W2 方案]
 *
 * W2 原理：
 *   直接扫描 netio.sys 内部的 Callout 表（gCalloutTable），
 *   将 classifyFn 地址落在 ACE 驱动 PE 范围内的条目替换为
 *   WfpBypass_ClassifyWrapper，无论 ACE 何时加载均有效。
 *
 * 调用顺序（Main.cpp 模块枚举阶段）：
 *   1. 发现 netio.sys  → WfpBypass_SetNetioInfo(base, end, pFwpsReg2)
 *   2. 发现 ACE 驱动   → WfpBypass_SetAceInfo(base, end)
 *
 * 控制与调用阶段：
 *   3. IOCTL / 按需初始化 → WfpBypass_Init(UserVar) 扫描并替换 ACE Callout
 *
 * DriverUnload 阶段：
 *   4. WfpBypass_Cleanup(UserVar)           恢复所有 classifyFn
 */

/**
 * 传入 netio.sys 的地址范围和 FwpsCalloutRegister2 函数地址。
 * 在模块枚举发现 netio.sys 时调用。
 * @param netioBase   netio.sys DllBase
 * @param netioEnd    netio.sys DllBase + SizeOfImage
 * @param pFwpsReg2   FwpsCalloutRegister2 函数地址（用于定位 gCalloutTable）
 */
VOID WfpBypass_SetNetioInfo(
    _In_ ULONG_PTR netioBase,
    _In_ ULONG_PTR netioEnd,
    _In_ PVOID     pFwpsReg2);

/**
 * 传入 ACE 驱动的地址范围（classifyFn 落在此范围内视为属于 ACE）。
 * 在模块枚举发现 ACE-CORExxxxxx.sys 时调用。
 * 若未调用此函数，Init 将使用宽松模式（替换所有非 netio Callout）。
 * @param aceBase   ACE DllBase
 * @param aceEnd    ACE DllBase + SizeOfImage
 */
VOID WfpBypass_SetAceInfo(
    _In_ ULONG_PTR aceBase,
    _In_ ULONG_PTR aceEnd);

/**
 * 扫描 gCalloutTable，原子替换属于 ACE 的 classifyFn。
 */
NTSTATUS WfpBypass_Init(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);

/**
 * 恢复所有被替换的 classifyFn。DriverUnload 中调用。
 */
VOID WfpBypass_Cleanup(_In_ MACHENIKE_KERNEL_INTERFACE *UserVar);

/**
 * 设置需要隐藏的本地端口（可选，当前实现对所有 STREAM 流量清零）。
 */
VOID WfpBypass_SetHiddenLocalPort(_In_ USHORT portHostOrder);

/**
 * 查询 WFP DKOM Bypass 是否已激活并替换成功。
 */
BOOLEAN WfpBypass_IsInstalled(VOID);

/**
 * 获取当前配置隐藏的主机序端口号。
 */
USHORT WfpBypass_GetHiddenLocalPort(VOID);

#ifdef __cplusplus
}
#endif
