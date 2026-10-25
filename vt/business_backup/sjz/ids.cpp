//
// sjz/ids.cpp
//
// All blueprint identifiers and CN display names are wrapped in _XOR_(...)
// so they get nibble-XOR'd at compile time (xorstr.h) and decrypted on the
// stack at point-of-use. None of these strings appear in any static data
// section. Each call performs N decryptions worst-case; that cost is
// negligible vs the per-frame actor walk that drives them.
//
// Numeric IDs in WeaponNameMap / HeroNameMap are kept inline as they are
// not text and `strings` won't surface them on their own.
//
#include "ids.h"
#include "../xorstr.h"

namespace sjz {

#pragma code_seg(".vm")

    // ----------------------------------------------------------------
    // Player blueprint kinds. Numeric handles are an internal detail -
    // pick whatever range; just keep the enum stable across this file.
    // ----------------------------------------------------------------
    namespace pk {
        enum : int {
            kSniper = 1,    // BP_DFMCharacter_AI_AlwaysFall_DTSniper_C
            kRpg,           // BP_DFMCharacter_AI_DT_RPG_C
            kHsAgent,       // BP_DFMCharacter_AI_HS_C
            kCrocodile,     // BP_DFMCharacter_AI_Crocodile_C
            kMaurice,       // BP_DFMCharacter_AI_Maurice_C
            kDtTrooper,     // BP_DFMCharacter_AI_DT_C
            kPlayer,        // BP_DFMCharacter_C
            kShielderHs,    // BP_DFMAICharacter_ShielderLight_HS_C
            kHmgGunner,     // BP_DFMAICharacter_HeavyMachineGun_C
            kShielder,      // BP_DFMAICharacter_ShielderLight_C
            kHmgGunnerHs,   // BP_DFMAICharacter_HeavyMachineGun_HS_C
            kFirebat,       // BP_DFMAICharacter_Firebat_C
            kBreakthrough,  // BP_DFM_Character_Breakthrough_C
            kSafeHouse,     // BP_DFMCharacter_SafeHouse_C
            kBreakthrough2, // Shafted_Breakthrough
            kRangeTarget,   // BP_RangeTargetCharacter_C
            kFirebatHs,     // BP_DFMAICharacter_Firebat_HS_C
            kBossRcv,       // BP_DFMCharacter_AI_BossRCV_C  (later entry - Boss)
            kFirebatHs2,    // BP_DFMAICharacter_Firebat_HS_C (later entry)
            kBoss03,        // BP_DFMAICharacter_Boss03_C
            kSniperHs,      // BP_DFMCharacter_AI_AlwaysFall_HSSniper_C (later entry)
            kTutorialAi,    // BP_DFMCharacter_TutorialPlayerAi_C
            kReis,          // BP_DFMCharacter_AI_Reis_C (later entry)
            // Generic AI bucket - anything we recognize but don't have
            // a custom name for.
            kAi,
        };
    } // namespace pk

    // ----------------------------------------------------------------
    // Blueprint name -> kind. The string literals here are the *only*
    // place these BP names appear; .rdata holds only the encrypted
    // byte arrays.
    // ----------------------------------------------------------------
    int LookupPlayerKind(const wchar_t* bp) {
        if (!bp) return kPlayerKindNone;

        // Per-class custom-name tier (16 distinct entries).
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_AlwaysFall_DTSniper_C")))
            return pk::kSniper;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_DT_RPG_C")))
            return pk::kRpg;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_HS_C")))
            return pk::kHsAgent;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_Crocodile_C")))
            return pk::kCrocodile;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_Maurice_C")))
            return pk::kMaurice;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_DT_C")))
            return pk::kDtTrooper;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_C")))
            return pk::kPlayer;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_ShielderLight_HS_C")))
            return pk::kShielderHs;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_HeavyMachineGun_C")))
            return pk::kHmgGunner;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_ShielderLight_C")))
            return pk::kShielder;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_HeavyMachineGun_HS_C")))
            return pk::kHmgGunnerHs;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_Firebat_C")))
            return pk::kFirebat;
        if (!wcscmp(bp, _XOR_(L"BP_DFM_Character_Breakthrough_C")))
            return pk::kBreakthrough;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_SafeHouse_C")))
            return pk::kSafeHouse;
        if (!wcscmp(bp, _XOR_(L"Shafted_Breakthrough")))
            return pk::kBreakthrough2;
        if (!wcscmp(bp, _XOR_(L"BP_RangeTargetCharacter_C")))
            return pk::kRangeTarget;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_Firebat_HS_C")))
            return pk::kFirebatHs;

        // Generic-AI tier. Original code mapped these to L"AI" so the
        // distinction between "named AI" and "generic AI" doesn't matter
        // at the call site.
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_AI_HS_C")))                  return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_AI_C")))                     return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AlwaysFall_HSSniper_C")))      return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AlwaysFall_DTSniper_C")))      return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_BossRCV_C")))               return pk::kBossRcv;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_Reis_C")))                  return pk::kReis;
        if (!wcscmp(bp, _XOR_(L"BP_DFAIMCharacter_AI_Reis_C")))                return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_Boss03_C")))                   return pk::kBoss03;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_Tide_DT_C")))               return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_Tide_HS_C")))               return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_AlwaysFall_HSSniper_Tide_C"))) return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_ShielderLight_HS_Tide_C")))  return pk::kAi;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_Firebat_HS_C")))             return pk::kFirebatHs2;
        if (!wcscmp(bp, _XOR_(L"BP_DFMAICharacter_Boss03_C")))                 return pk::kBoss03;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_AI_AlwaysFall_HSSniper_C")))   return pk::kSniperHs;
        if (!wcscmp(bp, _XOR_(L"BP_DFMCharacter_TutorialPlayerAi_C")))         return pk::kTutorialAi;

        return kPlayerKindNone;
    }

    // ----------------------------------------------------------------
    // Kind -> CN display name. Strings are placeholder underscores -
    // refill with the live game IDs/translations during the next
    // dump pass.
    // ----------------------------------------------------------------
    void FillPlayerKindName(int kind, wchar_t* out, size_t cap) {
        if (!out || cap == 0) return;
        switch (kind) {
        case pk::kSniper:        wcscpy_s(out, cap, _XOR_(L"______"));         break;
        case pk::kRpg:           wcscpy_s(out, cap, _XOR_(L"_____________"));  break;
        case pk::kHsAgent:       wcscpy_s(out, cap, _XOR_(L"________"));       break;
        case pk::kCrocodile:     wcscpy_s(out, cap, _XOR_(L"____"));           break;
        case pk::kMaurice:       wcscpy_s(out, cap, _XOR_(L"______"));         break;
        case pk::kDtTrooper:     wcscpy_s(out, cap, _XOR_(L"______________")); break;
        case pk::kPlayer:        wcscpy_s(out, cap, _XOR_(L"___"));            break;
        case pk::kShielderHs:    wcscpy_s(out, cap, _XOR_(L"________"));       break;
        case pk::kHmgGunner:     wcscpy_s(out, cap, _XOR_(L"____________"));   break;
        case pk::kShielder:      wcscpy_s(out, cap, _XOR_(L"__________"));     break;
        case pk::kHmgGunnerHs:   wcscpy_s(out, cap, _XOR_(L"________"));       break;
        case pk::kFirebat:       wcscpy_s(out, cap, _XOR_(L"____________"));   break;
        case pk::kBreakthrough:  wcscpy_s(out, cap, _XOR_(L"_______"));        break;
        case pk::kSafeHouse:     wcscpy_s(out, cap, _XOR_(L"___"));            break;
        case pk::kBreakthrough2: wcscpy_s(out, cap, _XOR_(L"___"));            break;
        case pk::kRangeTarget:   wcscpy_s(out, cap, _XOR_(L"____"));           break;
        case pk::kFirebatHs:     wcscpy_s(out, cap, _XOR_(L"___"));            break;
        case pk::kBossRcv:       wcscpy_s(out, cap, _XOR_(L"______"));         break;
        case pk::kFirebatHs2:    wcscpy_s(out, cap, _XOR_(L"_________"));      break;
        case pk::kBoss03:        wcscpy_s(out, cap, _XOR_(L"______"));         break;
        case pk::kSniperHs:      wcscpy_s(out, cap, _XOR_(L"___________"));    break;
        case pk::kTutorialAi:    wcscpy_s(out, cap, _XOR_(L"_____________"));  break;
        case pk::kReis:          wcscpy_s(out, cap, _XOR_(L"____"));           break;
        case pk::kAi:            // fallthrough
        default:                 wcscpy_s(out, cap, _XOR_(L"AI"));             break;
        }
    }

    // ----------------------------------------------------------------
    // Weapon hash -> name. Hash values are kept inline (numbers, not
    // text). Names are _XOR_-encrypted.
    // ----------------------------------------------------------------
    void FillWeaponName(UINT64 hash, wchar_t* out, size_t cap) {
        if (!out || cap == 0) return;
        switch (hash) {
        case 0x4E9DD156FULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4EC06496AULL: wcscpy_s(out, cap, _XOR_(L"725"));     break;
        case 0x4EC06496BULL: wcscpy_s(out, cap, _XOR_(L"M870"));    break;
        case 0x4EC06496DULL: wcscpy_s(out, cap, _XOR_(L"S12K"));    break;
        case 0x4EC06496EULL: wcscpy_s(out, cap, _XOR_(L"M1014"));   break;
        case 0x4ECBEDFE4ULL: wcscpy_s(out, cap, _XOR_(L"QCQ171"));  break;
        case 0x4ECBEDFE5ULL: wcscpy_s(out, cap, _XOR_(L"MP7"));     break;
        case 0x4ECBEDFE6ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4ECBEDFE7ULL: wcscpy_s(out, cap, _XOR_(L"SR-3M"));   break;
        case 0x4ECBEDFE9ULL: wcscpy_s(out, cap, _XOR_(L"SMG-45"));  break;
        case 0x4ECBEDFEAULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4ECBEDFEBULL: wcscpy_s(out, cap, _XOR_(L"UZI"));     break;
        case 0x4ECBEDFECULL: wcscpy_s(out, cap, _XOR_(L"Vector"));  break;
        case 0x4ECBEDFEDULL: wcscpy_s(out, cap, _XOR_(L"P90"));     break;
        case 0x4ECBEDFEEULL: wcscpy_s(out, cap, _XOR_(L"MP5"));     break;
        case 0x4EAD805E4ULL: wcscpy_s(out, cap, _XOR_(L"AWM"));     break;
        case 0x4EAD805E6ULL: wcscpy_s(out, cap, _XOR_(L"M700"));    break;
        case 0x4EAD805E7ULL: wcscpy_s(out, cap, _XOR_(L"R93"));     break;
        case 0x4EAD805E8ULL: wcscpy_s(out, cap, _XOR_(L"SV-98"));   break;
        case 0x4EBA3EF4EULL: wcscpy_s(out, cap, _XOR_(L"M191"));    break;
        case 0x4EBA3EF65ULL: wcscpy_s(out, cap, _XOR_(L"G17"));     break;
        case 0x4EBA3EF69ULL: wcscpy_s(out, cap, _XOR_(L"93R"));     break;
        case 0x4EBA3EF6AULL: wcscpy_s(out, cap, _XOR_(L"G18"));     break;
        case 0x4EBA3EF6BULL: wcscpy_s(out, cap, _XOR_(L"________")); break;
        case 0x4EBA3EF6CULL: wcscpy_s(out, cap, _XOR_(L".357"));    break;
        case 0x4EBA3EF6DULL: wcscpy_s(out, cap, _XOR_(L"QSZ92G"));  break;
        case 0x4EB0B56E8ULL: wcscpy_s(out, cap, _XOR_(L"RPG"));     break;
        case 0x4ED709A67ULL: wcscpy_s(out, cap, _XOR_(L"SR-9"));    break;
        case 0x4ED709A68ULL: wcscpy_s(out, cap, _XOR_(L"SR-25"));   break;
        case 0x4ED709A69ULL: wcscpy_s(out, cap, _XOR_(L"SKS"));     break;
        case 0x4ED709A6AULL: wcscpy_s(out, cap, _XOR_(L"M14"));     break;
        case 0x4ED709A6BULL: wcscpy_s(out, cap, _XOR_(L"SVD"));     break;
        case 0x4ED709A6CULL: wcscpy_s(out, cap, _XOR_(L"VSS"));     break;
        case 0x4ED709A6DULL: wcscpy_s(out, cap, _XOR_(L"Mini-14")); break;
        case 0x4ED709A70ULL: wcscpy_s(out, cap, _XOR_(L"PSG-1"));   break;
        case 0x4EDE930E7ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4EDE930EBULL: wcscpy_s(out, cap, _XOR_(L"QJB201"));  break;
        case 0x4EDE930ECULL: wcscpy_s(out, cap, _XOR_(L"M250"));    break;
        case 0x4EDE930EDULL: wcscpy_s(out, cap, _XOR_(L"M249"));    break;
        case 0x4EDE930EEULL: wcscpy_s(out, cap, _XOR_(L"RPK"));     break;
        case 0x4EFD77447ULL: wcscpy_s(out, cap, _XOR_(L"K437"));    break;
        case 0x4EFD77449ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4EFD7744AULL: wcscpy_s(out, cap, _XOR_(L"AS_Val"));  break;
        case 0x4EFD77460ULL: wcscpy_s(out, cap, _XOR_(L"AUG"));     break;
        case 0x4EFD77461ULL: wcscpy_s(out, cap, _XOR_(L"M16A4"));   break;
        case 0x4EFD77462ULL: wcscpy_s(out, cap, _XOR_(L"K416"));    break;
        case 0x4EFD77463ULL: wcscpy_s(out, cap, _XOR_(L"ASH-12"));  break;
        case 0x4EFD77465ULL: wcscpy_s(out, cap, _XOR_(L"AKS-74U")); break;
        case 0x4EFD77467ULL: wcscpy_s(out, cap, _XOR_(L"QBZ95"));   break;
        case 0x4EFD77469ULL: wcscpy_s(out, cap, _XOR_(L"AKM"));     break;
        case 0x4EFD7746EULL: wcscpy_s(out, cap, _XOR_(L"M4A1"));    break;
        case 0x4EFD77470ULL: wcscpy_s(out, cap, _XOR_(L"CAR-15"));  break;
        case 0x4EFD77477ULL: wcscpy_s(out, cap, _XOR_(L"PTR-32"));  break;
        case 0x4EFD77478ULL: wcscpy_s(out, cap, _XOR_(L"G3"));      break;
        case 0x4EFD7747AULL: wcscpy_s(out, cap, _XOR_(L"SCAR-H"));  break;
        case 0x4EFD7747DULL: wcscpy_s(out, cap, _XOR_(L"AK-12"));   break;
        case 0x4EFD7747EULL: wcscpy_s(out, cap, _XOR_(L"SG552"));   break;
        case 0x4EFD7747FULL: wcscpy_s(out, cap, _XOR_(L"M7"));      break;
        case 0x4E875ABE1ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4E875ABE3ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4E875ABE5ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4E875ABE6ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x4E875ABEDULL: wcscpy_s(out, cap, _XOR_(L"________"));break;
        default:             wcscpy_s(out, cap, _XOR_(L"________"));break; // unknown weapon sentinel
        }
    }

    // ----------------------------------------------------------------
    // Hero hash -> name.
    // ----------------------------------------------------------------
    void FillHeroName(UINT64 hash, wchar_t* out, size_t cap) {
        if (!out || cap == 0) return;
        switch (hash) {
        case 0x14A398CEC9ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x14A398CECAULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x14A398CECBULL: wcscpy_s(out, cap, _XOR_(L"___"));     break;
        case 0x14A398CECCULL: wcscpy_s(out, cap, _XOR_(L"______"));  break;
        case 0x14A398CEF1ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x14A398CEF2ULL: wcscpy_s(out, cap, _XOR_(L"______"));  break;
        case 0x14A398CEF3ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x14A398CEF4ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x14A398CEF5ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        case 0x14A398CEF6ULL: wcscpy_s(out, cap, _XOR_(L"____"));    break;
        default:              wcscpy_s(out, cap, _XOR_(L"________"));break; // unknown hero sentinel
        }
    }

#pragma code_seg()

} // namespace sjz
