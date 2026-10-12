/*
 * NarakaActionInit.h
 *
 * 永劫无间 (Naraka: Bladepoint) 动作数据与动作打断事件节点 (Action Event Node) 初始化与控制模块
 * 
 * 核心机制说明：
 * 游戏在 Unity Il2Cpp 层维护了 AnimatorTrackSetDef 与 EventTrackSet。
 * 每个武器/动作在动画轨道上挂载了若干事件节点 (EventNode)，其中 paramType == 91 的事件为动作打断参数 (ActionBreakParam)。
 * 当 ActionBreakMask == to_emptystep_dodge (8196) 时，该节点的 normalizedTime 决定了角色动作后摇何时能够被虚步/闪避打断。
 * 
 * 读写原语说明：
 * 全面集成 CheatDrv 项目原生内核虚拟内存读写接口 (LcReadVirtualMemory / LcWriteVirtualMemory)，
 * 并提供与游戏逆向项目完全一致的 GameRead<T> / GameWrite<T> / GameIsAddressAlign 规范模板。
 */

#ifndef NARAKA_ACTION_INIT_H
#define NARAKA_ACTION_INIT_H

#if defined(_KERNEL_MODE)
#include <ntdef.h>
#include <ntstatus.h>
#else
#include <windows.h>
#endif

#include "../Common.h"
#include "../Utils.h"
#include "../leechcore_kernel.h"

#pragma pack(push, 8)

// ============================================================================
// 一、 Il2Cpp 与动作打断枚举及参数定义
// ============================================================================

/**
 * @brief 动作打断类型掩码 (BreakMask)
 */
typedef enum _NARAKA_BREAK_MASK {
    BREAK_MASK_NONE                     = 0,
    BREAK_MASK_TO_UNIQUE_SKILL_ATTACK   = 1024,
    BREAK_MASK_TO_NORMAL_SKILL2_ATTACK  = 2048,
    BREAK_MASK_TO_AIRHIKE               = 4096,
    BREAK_MASK_TO_EMPTYSTEP_DODGE       = 8196,     // 虚步 / 闪避打断掩码
    BREAK_MASK_TO_EMPTYSTEP_FRONT_DODGE = 16384,    // 前滑步闪避打断
    BREAK_MASK_TO_CROUCH                = 32768,    // 下蹲打断
    BREAK_MASK_TO_SWITCH_WEAPON         = 65536     // 切刀打断
} NARAKA_BREAK_MASK;

/**
 * @brief 打断参数结构 (paramType == 91)
 */
typedef struct _NARAKA_ACTION_BREAK_PARAM {
    UINT32 ActionBreakMask;     // 打断掩码 (NARAKA_BREAK_MASK)
    UINT32 ActionBreakStatus;   // 打断状态 (1: 允许打断)
} NARAKA_ACTION_BREAK_PARAM, *PNARAKA_ACTION_BREAK_PARAM;

/**
 * @brief 动作数据缓存条目
 */
typedef struct _NARAKA_ACTION_NODE_ENTRY {
    UINT32 ActionHash;          // 动作名称哈希 (如 male_katana_attack_light_01_pre)
    UINT32 Reserved;            // 对齐填充
    UINT64 NormalizedTimeAddr;  // 游戏内存中 normalizedTime 的绝对虚拟地址
    FLOAT  OriginalNormalizedTime; // 原始打断归一化时间戳 (备份用于无痕还原)
    FLOAT  TargetNormalizedTime;   // 强化打断时间戳 (通常为 0.001f，动作启动瞬间即可打断)
} NARAKA_ACTION_NODE_ENTRY, *PNARAKA_ACTION_NODE_ENTRY;

#define NARAKA_MAX_ACTION_ENTRIES 256

/**
 * @brief 动作数据初始化全局上下文
 */
typedef struct _NARAKA_ACTION_CONTEXT {
    UINT64 TargetCr3;                                           // 目标游戏进程 CR3 目录基址
    UINT32 EntryCount;                                          // 已捕获的动作节点总数
    UINT32 IsEnhanced;                                          // 当前强化状态标志 (1: 开启, 0: 还原)
    FLOAT  EnhancedTimeValue;                                   // 强化时写入的时间 (默认 0.001f)
    UINT32 Reserved;                                            // 8 字节对齐
    NARAKA_ACTION_NODE_ENTRY Entries[NARAKA_MAX_ACTION_ENTRIES];// 动作条目表
} NARAKA_ACTION_CONTEXT, *PNARAKA_ACTION_CONTEXT;

// ============================================================================
// 二、 动作动画白名单哈希常量定义 (部分常用前摇动作)
// ============================================================================

// 太刀 (Katana) 前摇
#define HASH_MALE_KATANA_ATTACK_LIGHT_01_PRE     0x6E105C0E
#define HASH_MALE_KATANA_RUN_ATTACK_LIGHT_01_PRE 0x8DFD4D9C
#define HASH_MALE_KATANA_ATTACK_HEAVY_01_PRE     0x75B1074E
#define HASH_MALE_KATANA_CROUCH_ATTACK_LIGHT_01_PRE 0x48A31FB2

// 长剑 (Sword) 前摇
#define HASH_MALE_SW_ATTACK_LIGHT_01_PRE         0x3D634DE1
#define HASH_MALE_SW_RUN_ATTACK_LIGHT_01_PRE     0x8FD456B7
#define HASH_MALE_SW_ATTACK_HEAVY_01_PRE         0x2E62A6B2
#define HASH_MALE_SW_CROUCH_ATTACK_LIGHT_01_PRE  0x5A43D11A

// 横刀 (HengDao) 前摇
#define HASH_MALE_HENGDAO_ATTACK_LIGHT_01_PRE    0x0283BE8C
#define HASH_MALE_HENGDAO_RUN_ATTACK_LIGHT_01_PRE 0x2A7320D9
#define HASH_MALE_HENGDAO_ATTACK_HEAVY_01_PRE    0x19B4C72B

// 匕首 (Dagger) 前摇
#define HASH_MALE_DAGGER_ATTACK_LIGHT_01_PRE     0x8B32104A
#define HASH_MALE_DAGGER_ATTACK_HEAVY_01_PRE     0x9F4125CC

// 扇子 (Fan) 前摇
#define HASH_MALE_FAN_ATTACK_LIGHT_01_PRE        0xA14389BC
#define HASH_MALE_FAN_ATTACK_HEAVY_01_PRE        0xB52084E1

// 双节棍 (Nunchucks) 前摇
#define HASH_MALE_NUNCHUCKS_ATTACK_LIGHT_01_PRE  0xC7192A03
#define HASH_MALE_NUNCHUCKS_ATTACK_HEAVY_01_PRE  0xD905847A

// 双刀 / 双戟
#define HASH_MALE_TWINBLADES_ATTACK_LIGHT_01_PRE 0xEA2348B1
#define HASH_MALE_DUALHALBERD_ATTACK_LIGHT_01_PRE 0xF2B39580

#pragma pack(pop)

// ============================================================================
// 三、 项目原生内存读写模板与对齐检查函数 (GameRead / GameWrite)
// ============================================================================

#define NARAKA_USER_ADDR_MIN 0x10000ULL
#define NARAKA_USER_ADDR_MAX 0x00007FFFFFFFFFFFULL

/**
 * @brief 地址有效性与用户态边界检查
 */
static __forceinline BOOLEAN GameIsAddressAlign(IN UINT64 Address)
{
    return (Address >= NARAKA_USER_ADDR_MIN && Address <= NARAKA_USER_ADDR_MAX && (Address & 0x7) == 0);
}

static __forceinline BOOLEAN GameIsAddressValid(IN UINT64 Address)
{
    return (Address >= NARAKA_USER_ADDR_MIN && Address <= NARAKA_USER_ADDR_MAX);
}

// 全局绑定的目标进程 CR3（由驱动或遍历例程在初始化时配置）
extern ULONG64 g_NarakaTargetCr3;

/**
 * @brief 底层直接调用驱动项目中的 LcReadVirtualMemory 读取目标虚拟内存
 */
static __forceinline BOOLEAN Naraka_InternalRead(IN UINT64 Address, OUT PVOID Buffer, IN ULONG Size)
{
    if (!GameIsAddressValid(Address) || !Buffer || Size == 0) return FALSE;
    if (g_NarakaTargetCr3 != 0) {
        return LcReadVirtualMemory(g_NarakaTargetCr3, Address, Buffer, Size);
    }
    return FALSE;
}

/**
 * @brief 底层直接调用驱动项目中的 LcWriteVirtualMemory 写入目标虚拟内存
 */
static __forceinline BOOLEAN Naraka_InternalWrite(IN UINT64 Address, IN const PVOID Buffer, IN ULONG Size)
{
    if (!GameIsAddressValid(Address) || !Buffer || Size == 0) return FALSE;
    if (g_NarakaTargetCr3 != 0) {
        return LcWriteVirtualMemory(g_NarakaTargetCr3, Address, Buffer, Size);
    }
    return FALSE;
}

/**
 * @brief 项目统一的泛型内存直读模板 (对应 Naraka 逆向中的 GameRead<T>)
 */
template <typename T>
static __forceinline T GameRead(IN UINT64 VirtualAddress)
{
    T val = {};
    if (GameIsAddressValid(VirtualAddress)) {
        Naraka_InternalRead(VirtualAddress, &val, sizeof(T));
    }
    return val;
}

/**
 * @brief 项目统一的泛型内存写入模板 (对应 Naraka 逆向中的 GameWrite<T>)
 */
template <typename T>
static __forceinline BOOLEAN GameWrite(IN UINT64 VirtualAddress, IN T Value)
{
    if (!GameIsAddressValid(VirtualAddress)) {
        return FALSE;
    }
    return Naraka_InternalWrite(VirtualAddress, &Value, sizeof(T));
}

// ============================================================================
// 四、 导出函数声明
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 设置当前目标进程的 CR3
 * @param Cr3 目标进程 DirectoryTableBase
 */
VOID NarakaAction_SetTargetCr3(
    IN ULONG64 Cr3
);

/**
 * @brief 初始化动作数据上下文
 * @param Context 动作上下文指针
 * @param TargetCr3 目标进程 CR3
 * @param EnhancedValue 强化打断时间 (通常为 0.001f)
 */
VOID NarakaAction_InitContext(
    OUT PNARAKA_ACTION_CONTEXT Context,
    IN  ULONG64 TargetCr3,
    IN  FLOAT EnhancedValue
);

/**
 * @brief 判断动作哈希是否在关注的白名单中
 * @param ActionHash 动作字符串哈希
 * @return TRUE 表示匹配目标前摇动作
 */
BOOLEAN NarakaAction_IsTargetAction(
    IN UINT32 ActionHash
);

/**
 * @brief 注册/添加一个捕获到的动作打断节点
 * @param Context 动作上下文
 * @param ActionHash 动作哈希
 * @param NormalizedTimeAddress 节点归一化时间内存地址
 * @param OriginalTime 游戏原本的归一化时间
 * @return 是否添加成功
 */
BOOLEAN NarakaAction_RegisterNode(
    IN OUT PNARAKA_ACTION_CONTEXT Context,
    IN     UINT32 ActionHash,
    IN     UINT64 NormalizedTimeAddress,
    IN     FLOAT  OriginalTime
);

/**
 * @brief 穿透 Il2Cpp 静态对象树，执行完整的动作数据获取与节点初始化
 *
 * 遍历路径：
 * GameAssembly.dll -> AnimatorTrackSetDef -> static_fields.ShareTrackSet
 * -> TrackSetDict -> EventTrackSet -> animClipName -> tracks -> nodes
 * -> trackEvent (paramType==91) -> ActionBreakParam (to_emptystep_dodge)
 * -> 提取 normalizedTime 虚拟地址与原值。
 *
 * @param Context 动作数据上下文
 * @param GameAssemblyBase 游戏 GameAssembly.dll 模块基址
 * @param AnimatorTrackSetDef_RVA AnimatorTrackSetDef 类的 Il2CppClass RVA
 * @return 成功捕获的动作节点总数
 */
UINT32 NarakaAction_ScanAndInitialize(
    IN OUT PNARAKA_ACTION_CONTEXT Context,
    IN     UINT64 GameAssemblyBase,
    IN     UINT32 AnimatorTrackSetDef_RVA
);

/**
 * @brief 动态开启或关闭强化虚步（修改/还原动作打断时间）
 * @param Context 动作数据上下文
 * @param Enable TRUE 开启强化 (写入极小时间实现瞬间虚步打断)，FALSE 还原原版时间
 * @return 成功操作的节点数量
 */
UINT32 NarakaAction_SetEnhanceStatus(
    IN OUT PNARAKA_ACTION_CONTEXT Context,
    IN     BOOLEAN Enable
);

#ifdef __cplusplus
}
#endif

#endif // NARAKA_ACTION_INIT_H
