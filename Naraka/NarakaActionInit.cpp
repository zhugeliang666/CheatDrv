/*
 * NarakaActionInit.cpp
 *
 * 永劫无间 (Naraka: Bladepoint) 动作数据与动作打断事件节点初始化与控制实现
 * 
 * 读写原语：直接使用项目统一的 GameRead<T> / GameWrite<T>，底层直通 LcReadVirtualMemory / LcWriteVirtualMemory。
 */

#include "NarakaActionInit.h"

// 全局绑定的目标 CR3
ULONG64 g_NarakaTargetCr3 = 0;

// ============================================================================
// 静态白名单动作哈希表
// ============================================================================

static const UINT32 g_TargetActionHashes[] = {
    HASH_MALE_KATANA_ATTACK_LIGHT_01_PRE,
    HASH_MALE_KATANA_RUN_ATTACK_LIGHT_01_PRE,
    HASH_MALE_KATANA_ATTACK_HEAVY_01_PRE,
    HASH_MALE_KATANA_CROUCH_ATTACK_LIGHT_01_PRE,

    HASH_MALE_SW_ATTACK_LIGHT_01_PRE,
    HASH_MALE_SW_RUN_ATTACK_LIGHT_01_PRE,
    HASH_MALE_SW_ATTACK_HEAVY_01_PRE,
    HASH_MALE_SW_CROUCH_ATTACK_LIGHT_01_PRE,

    HASH_MALE_HENGDAO_ATTACK_LIGHT_01_PRE,
    HASH_MALE_HENGDAO_RUN_ATTACK_LIGHT_01_PRE,
    HASH_MALE_HENGDAO_ATTACK_HEAVY_01_PRE,

    HASH_MALE_DAGGER_ATTACK_LIGHT_01_PRE,
    HASH_MALE_DAGGER_ATTACK_HEAVY_01_PRE,

    HASH_MALE_FAN_ATTACK_LIGHT_01_PRE,
    HASH_MALE_FAN_ATTACK_HEAVY_01_PRE,

    HASH_MALE_NUNCHUCKS_ATTACK_LIGHT_01_PRE,
    HASH_MALE_NUNCHUCKS_ATTACK_HEAVY_01_PRE,

    HASH_MALE_TWINBLADES_ATTACK_LIGHT_01_PRE,
    HASH_MALE_DUALHALBERD_ATTACK_LIGHT_01_PRE
};

// ============================================================================
// 模块接口实现
// ============================================================================

VOID NarakaAction_SetTargetCr3(IN ULONG64 Cr3)
{
    g_NarakaTargetCr3 = Cr3;
}

VOID NarakaAction_InitContext(
    OUT PNARAKA_ACTION_CONTEXT Context,
    IN  ULONG64 TargetCr3,
    IN  FLOAT EnhancedValue
)
{
    if (!Context) return;

    for (SIZE_T i = 0; i < sizeof(NARAKA_ACTION_CONTEXT); i++) {
        ((UCHAR*)Context)[i] = 0;
    }

    Context->TargetCr3         = TargetCr3;
    Context->EnhancedTimeValue = (EnhancedValue > 0.0f) ? EnhancedValue : 0.001f;
    Context->IsEnhanced        = 0;
    Context->EntryCount        = 0;

    NarakaAction_SetTargetCr3(TargetCr3);
}

BOOLEAN NarakaAction_IsTargetAction(IN UINT32 ActionHash)
{
    for (SIZE_T i = 0; i < sizeof(g_TargetActionHashes) / sizeof(g_TargetActionHashes[0]); i++) {
        if (g_TargetActionHashes[i] == ActionHash) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN NarakaAction_RegisterNode(
    IN OUT PNARAKA_ACTION_CONTEXT Context,
    IN     UINT32 ActionHash,
    IN     UINT64 NormalizedTimeAddress,
    IN     FLOAT  OriginalTime
)
{
    if (!Context || !GameIsAddressValid(NormalizedTimeAddress)) {
        return FALSE;
    }

    // 防重判定
    for (UINT32 i = 0; i < Context->EntryCount; i++) {
        if (Context->Entries[i].NormalizedTimeAddr == NormalizedTimeAddress) {
            return TRUE;
        }
    }

    if (Context->EntryCount >= NARAKA_MAX_ACTION_ENTRIES) {
        return FALSE;
    }

    PNARAKA_ACTION_NODE_ENTRY Entry = &Context->Entries[Context->EntryCount++];
    Entry->ActionHash             = ActionHash;
    Entry->NormalizedTimeAddr     = NormalizedTimeAddress;
    Entry->OriginalNormalizedTime = OriginalTime;
    Entry->TargetNormalizedTime   = Context->EnhancedTimeValue;

    return TRUE;
}

UINT32 NarakaAction_ScanAndInitialize(
    IN OUT PNARAKA_ACTION_CONTEXT Context,
    IN     UINT64 GameAssemblyBase,
    IN     UINT32 AnimatorTrackSetDef_RVA
)
{
    if (!Context || !GameAssemblyBase || !AnimatorTrackSetDef_RVA) {
        return 0;
    }

    if (Context->TargetCr3 != 0) {
        NarakaAction_SetTargetCr3(Context->TargetCr3);
    }

    // 1. 获取 AnimatorTrackSetDef 的 Il2CppClass
    UINT64 pAnimatorTrackSetDefClass = GameRead<UINT64>(GameAssemblyBase + AnimatorTrackSetDef_RVA);
    if (!GameIsAddressAlign(pAnimatorTrackSetDefClass)) {
        return 0;
    }

    // 2. 访问静态字段 static_fields (通用 Il2Cpp 偏移 0xB8)
    UINT64 static_fields = GameRead<UINT64>(pAnimatorTrackSetDefClass + 0xB8);
    if (!GameIsAddressAlign(static_fields)) {
        return 0;
    }

    // 3. 访问 ShareTrackSet (字典偏移 0x00)
    UINT64 ShareTrackSet = GameRead<UINT64>(static_fields + 0x00);
    if (!GameIsAddressAlign(ShareTrackSet)) {
        return 0;
    }

    // 4. 解析 Il2Cpp Dictionary (entries: 0x18, count: 0x20)
    UINT64 Entries = GameRead<UINT64>(ShareTrackSet + 0x18);
    INT32 RealLength = GameRead<INT32>(ShareTrackSet + 0x20);
    if (!GameIsAddressAlign(Entries) || RealLength <= 0 || RealLength > 1024) {
        return 0;
    }

    // 字典条目数组首地址 (跳过 Array 头部 0x20)
    UINT64 EntriesVector = Entries + 0x20;
    const SIZE_T EntrySize = 24; // hashCode(4) + next(4) + key(8) + value(8)

    for (INT32 Index = 0; Index < RealLength; Index++) {
        UINT64 ItemAddr = EntriesVector + Index * EntrySize;
        INT32 HashCode = GameRead<INT32>(ItemAddr + 0x00);
        if (HashCode < 0) {
            continue;
        }

        UINT64 pAnimatorTrackSetDef = GameRead<UINT64>(ItemAddr + 0x10);
        if (!GameIsAddressAlign(pAnimatorTrackSetDef)) {
            continue;
        }

        // 5. 访问子字典 TrackSetDict (偏移 0x18)
        UINT64 pTrackSetDict = GameRead<UINT64>(pAnimatorTrackSetDef + 0x18);
        if (!GameIsAddressAlign(pTrackSetDict)) {
            continue;
        }

        UINT64 Entries2 = GameRead<UINT64>(pTrackSetDict + 0x18);
        INT32 RealLength2 = GameRead<INT32>(pTrackSetDict + 0x20);
        if (!GameIsAddressAlign(Entries2) || RealLength2 <= 0 || RealLength2 > 4096) {
            continue;
        }

        UINT64 EntriesVector2 = Entries2 + 0x20;
        for (INT32 Index2 = 0; Index2 < RealLength2; Index2++) {
            UINT64 ItemAddr2 = EntriesVector2 + Index2 * EntrySize;
            INT32 HashCode2 = GameRead<INT32>(ItemAddr2 + 0x00);
            if (HashCode2 < 0) {
                continue;
            }

            UINT64 pEventTrackSet = GameRead<UINT64>(ItemAddr2 + 0x10);
            if (!GameIsAddressAlign(pEventTrackSet)) {
                continue;
            }

            // 6. 读取 animClipName (偏移 0x18) 并计算哈希
            UINT64 pAnimClipName = GameRead<UINT64>(pEventTrackSet + 0x18);
            if (!GameIsAddressAlign(pAnimClipName)) {
                continue;
            }

            INT32 StringLength = GameRead<INT32>(pAnimClipName + 0x10);
            if (StringLength <= 0 || StringLength > 128) {
                continue;
            }

            WCHAR NameBuffer[128] = { 0 };
            Naraka_InternalRead(pAnimClipName + 0x14, NameBuffer, StringLength * sizeof(WCHAR));
            NameBuffer[StringLength] = L'\0';

            // 使用当前项目内置的 Utils_HashStringImulMagicExW 计算动作哈希
            UINT32 ActionHash = Utils_HashStringImulMagicExW(NameBuffer, (SIZE_T)StringLength, TRUE);
            if (!NarakaAction_IsTargetAction(ActionHash)) {
                continue;
            }

            // 7. 读取 tracks 列表 (0x20)
            UINT64 pTracksArray = GameRead<UINT64>(pEventTrackSet + 0x20);
            if (!GameIsAddressAlign(pTracksArray)) {
                continue;
            }

            INT32 TrackCount = GameRead<INT32>(pTracksArray + 0x18);
            if (TrackCount <= 0 || TrackCount > 64) {
                continue;
            }

            for (INT32 iTrack = 0; iTrack < TrackCount; iTrack++) {
                UINT64 pTrack = GameRead<UINT64>(pTracksArray + 0x20 + iTrack * sizeof(UINT64));
                if (!GameIsAddressAlign(pTrack)) {
                    continue;
                }

                // 8. 读取 nodes 列表 (0x18)
                UINT64 pNodesArray = GameRead<UINT64>(pTrack + 0x18);
                if (!GameIsAddressAlign(pNodesArray)) {
                    continue;
                }

                INT32 NodeCount = GameRead<INT32>(pNodesArray + 0x18);
                if (NodeCount <= 0 || NodeCount > 128) {
                    continue;
                }

                for (INT32 iNode = 0; iNode < NodeCount; iNode++) {
                    UINT64 pNode = GameRead<UINT64>(pNodesArray + 0x20 + iNode * sizeof(UINT64));
                    if (!GameIsAddressAlign(pNode)) {
                        continue;
                    }

                    // 9. 检查 EventNode.trackEvent (0x18)
                    UINT64 pTrackEvent = GameRead<UINT64>(pNode + 0x18);
                    if (!GameIsAddressAlign(pTrackEvent)) {
                        continue;
                    }

                    // 10. 检查 TrackEventMessage.paramType (0x10)
                    INT32 ParamType = GameRead<INT32>(pTrackEvent + 0x10);
                    if (ParamType != 91) {
                        continue; // 仅处理动作打断事件 (paramType == 91)
                    }

                    // 11. 读取 ActionBreakParam (0x18)
                    UINT64 pActionBreakParam = GameRead<UINT64>(pTrackEvent + 0x18);
                    if (!GameIsAddressAlign(pActionBreakParam)) {
                        continue;
                    }

                    NARAKA_ACTION_BREAK_PARAM BreakParam = GameRead<NARAKA_ACTION_BREAK_PARAM>(pActionBreakParam + 0x10);

                    // 12. 校验打断类型是否为虚步且状态有效
                    if (BreakParam.ActionBreakMask == BREAK_MASK_TO_EMPTYSTEP_DODGE &&
                        BreakParam.ActionBreakStatus == 1) {

                        // 13. 捕获 normalizedTime (0x20)
                        UINT64 NormalizedTimeAddr = pNode + 0x20;
                        FLOAT OriginalTime = GameRead<FLOAT>(NormalizedTimeAddr);

                        NarakaAction_RegisterNode(Context, ActionHash, NormalizedTimeAddr, OriginalTime);
                    }
                }
            }
        }
    }

    return Context->EntryCount;
}

UINT32 NarakaAction_SetEnhanceStatus(
    IN OUT PNARAKA_ACTION_CONTEXT Context,
    IN     BOOLEAN Enable
)
{
    if (!Context || Context->EntryCount == 0) {
        return 0;
    }

    if (Context->TargetCr3 != 0) {
        NarakaAction_SetTargetCr3(Context->TargetCr3);
    }

    UINT32 SuccessCount = 0;
    for (UINT32 i = 0; i < Context->EntryCount; i++) {
        PNARAKA_ACTION_NODE_ENTRY Entry = &Context->Entries[i];
        if (!GameIsAddressValid(Entry->NormalizedTimeAddr)) {
            continue;
        }

        FLOAT ValueToWrite = Enable ? Entry->TargetNormalizedTime : Entry->OriginalNormalizedTime;
        if (GameWrite<FLOAT>(Entry->NormalizedTimeAddr, ValueToWrite)) {
            SuccessCount++;
        }
    }

    Context->IsEnhanced = Enable ? 1 : 0;
    return SuccessCount;
}
