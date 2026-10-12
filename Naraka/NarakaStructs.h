/*
 * NarakaStructs.h
 *
 * Naraka Bladepoint 游戏内存结构定义
 * 用于数据遍历与结构体匹配
 */

#ifndef NARAKA_STRUCTS_H
#define NARAKA_STRUCTS_H

#include <ntdef.h>

// 强制 8 字节对齐以防止 WOW64 环境下的结构体错位
#pragma pack(push, 8)

// ============================================================================
// IOCTL 通信结构体
// ============================================================================

/**
 * @brief 数据遍历请求结构体
 *
 * 从应用层传递至驱动层，指定遍历目标与范围
 */
typedef struct _NARAKA_TRAVERSE_REQUEST {
    UINT32 TargetPID;              // 目标进程 PID
    UINT32 Reserved1;              // 对齐占位
    UINT64 ModuleBaseAddress;      // NarakaBladepoint.exe 模块基址
    UINT64 SearchRangeStart;       // 搜索起始地址（可选，0 表示自动检测 .data 段）
    UINT64 SearchRangeSize;        // 搜索范围大小（字节，0 表示整个 .data 段）
    UINT32 MaxResults;             // 最大返回结果数量
    UINT32 Reserved2;              // 对齐占位
} NARAKA_TRAVERSE_REQUEST, *PNARAKA_TRAVERSE_REQUEST;

/**
 * @brief 数据遍历结果结构体
 *
 * 驱动层返回给应用层的候选地址列表
 */
typedef struct _NARAKA_TRAVERSE_RESULT {
    UINT32 ResultCount;            // 实际找到的候选数量
    UINT32 ErrorCode;              // 错误码（0 表示成功）
    UINT64 CandidateAddresses[128]; // 候选地址数组（最多 128 个）
    CHAR ErrorMessage[256];        // 错误信息描述
} NARAKA_TRAVERSE_RESULT, *PNARAKA_TRAVERSE_RESULT;

// ============================================================================
// 游戏内存结构体（逆向还原）
// ============================================================================

/**
 * @brief EnhanceEmptyStep 数据结构候选特征
 *
 * 基于初步逆向分析，该结构体可能包含：
 * - 当前步数计数器（UINT32）
 * - 最大步数限制（UINT32）
 * - 冷却时间戳（UINT64）
 * - 启用标志（BOOLEAN）
 *
 * 注意：此结构体为初步推测，需通过遍历验证并持续迭代
 */
typedef struct _ENHANCE_STEP_CANDIDATE {
    UINT32 CurrentStepCount;       // 当前已使用步数
    UINT32 MaxStepCount;           // 最大可用步数
    UINT64 CooldownTimestamp;      // 冷却结束时间戳（毫秒）
    UINT32 IsEnabled;              // 是否启用（布尔值，按 4 字节对齐）
    UINT32 Reserved;               // 对齐占位
} ENHANCE_STEP_CANDIDATE, *PENHANCE_STEP_CANDIDATE;

// ============================================================================
// 特征码与模式匹配常量
// ============================================================================

/**
 * @brief 特征码定义
 *
 * 用于快速定位特定数据结构的字节序列
 * 示例：[0x?? 0x?? 0x05 0x00 0x00 0x00] 可能表示 MaxStepCount = 5
 */
#define ENHANCE_STEP_SIGNATURE_LENGTH 16

typedef struct _MEMORY_PATTERN {
    UCHAR Pattern[ENHANCE_STEP_SIGNATURE_LENGTH];  // 特征码字节序列
    UCHAR Mask[ENHANCE_STEP_SIGNATURE_LENGTH];     // 掩码（0x00 忽略，0xFF 匹配）
    UINT32 PatternLength;                          // 有效特征码长度
    UINT32 Reserved;                               // 对齐占位
} MEMORY_PATTERN, *PMEMORY_PATTERN;

#pragma pack(pop)

// ============================================================================
// 常量定义
// ============================================================================

// IOCTL 控制码（需与 leechcore_kernel.c 中的定义保持一致）
#define IOCTL_NARAKA_TRAVERSE_ENHANCE_STEP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 错误码定义
#define NARAKA_ERROR_SUCCESS              0x00000000
#define NARAKA_ERROR_INVALID_PID          0x00000001
#define NARAKA_ERROR_PROCESS_NOT_FOUND    0x00000002
#define NARAKA_ERROR_MODULE_NOT_FOUND     0x00000003
#define NARAKA_ERROR_INVALID_ADDRESS      0x00000004
#define NARAKA_ERROR_NO_RESULTS           0x00000005
#define NARAKA_ERROR_IRQL_TOO_HIGH        0x00000006

// 默认搜索参数
#define NARAKA_DEFAULT_MAX_RESULTS        128
#define NARAKA_PAGE_SIZE                  0x1000  // 4KB 页大小

#endif // NARAKA_STRUCTS_H
