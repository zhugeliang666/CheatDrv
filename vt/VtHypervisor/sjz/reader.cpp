#include "reader.h"
#include "decrypt.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"

namespace sjz {

#pragma code_seg(".vm")

	FVector GetWorldLocation(ULONG64 entityPawnAddrss) {

		if (!isValidPtr(entityPawnAddrss)) return FVector();

		ULONG64 rootComponent = decrypt_ptr(Read<ULONG64>(entityPawnAddrss + Offsets.RootComponent));

		if (!isValidPtr(rootComponent)) return FVector();

		FVector location = Read<FVector>(rootComponent + Offsets.RelativeLocation);

		return location;
	}

	UINT64 GetTeamId(ULONG64 entityPawnAddrss) {

		if (!isValidPtr(entityPawnAddrss)) return 0;

		//ULONG64 teamComponent = Read<ULONG64>(entityPawnAddrss + Offsets.TeamComponent);

		ULONG64 PlayerState = decrypt_ptr(Read<ULONG64>(entityPawnAddrss + Offsets.PlayerState));

		//PlayerState

		//if (!isValidPtr(teamComponent)) return 0;

		if (!isValidPtr(PlayerState)) return 0;

		UINT32 teamId = Read<UINT32>(PlayerState + Offsets.TeamId);

		return teamId;
	}

	int GetHealth(ULONG64 entityPawnAddrss) {

		if (!isValidPtr(entityPawnAddrss)) return 0;

		ULONG64 healthComponent = decrypt_ptr(Read<ULONG64>(entityPawnAddrss + Offsets.HealthComp));

		if (!isValidPtr(healthComponent)) return 0;


		ULONG64 healSet = decrypt_ptr(Read<ULONG64>(healthComponent + Offsets.HealthSet));

		if (!isValidPtr(healSet)) return 0;

		FGPGameplayAttributeData healData = Read<FGPGameplayAttributeData>(healSet + Offsets.Health);

		return (int)healData.CurrentValue;

	}



	int VGetFirst4Digits(unsigned long long ItemID) {
		// ___________________________
		char str[128]; // 64_______________20_________ + 1____________
		sprintf(str, _XOR_("%llu"), ItemID);

		// _________4_________
		if (strlen(str) >= 4) {
			str[4] = '\0'; // ____________4___
			return atoi(str);
		}

		return 0; // ________________________4____________0
	}
	BOOLEAN Game_GetEquipmentInfo(IN ULONG_PTR Actor, IN INT Type,  OUT LONG* Quality)
	{
		//Type==1 ______
		//Type==2 ______
		//Type==3 ______
		// 
		//Size: 0x30
		//struct FEquipmentInfo {
		//  uint64_t ItemID; // 0x00(0x08)
		//  uint64_t gid; // 0x08(0x08)
		//  float Health; // 0x10(0x04)
		//  float MaxHealth; // 0x14(0x04)
		//  float Durability; // 0x18(0x04)
		//  float MaxDurability; // 0x1c(0x04)
		//  float TotalEquipSeceonds; // 0x20(0x04)
		//  float LastEquipTimeSeconds; // 0x24(0x04)
		//  float TotalApplyDamage; // 0x28(0x04)
		//  char pad_2C[0x4]; // 0x2c(0x04)
		//};
		//*EquipmentItemID = 0;
		*Quality = 0;
		//*EquipmentDurability = 0.f;
		//*EquipmentMaxDurability = 0.f;
		if (!Actor)
			return FALSE;
		
		ULONG64 CharacterEquipComponent = decrypt_ptr(Read<ULONG64>((ULONG64)Actor + Offsets.CharacterEquipComponentCache));
		if (!CharacterEquipComponent)
			return FALSE;

		if (!isValidPtr(CharacterEquipComponent)) return FALSE;
		//struct TArray<struct FEquipmentInfo> EquipmentInfoArray; // 0x1e8(0x10)
		TArray EquipmentInfoArray = Read<TArray<char>>(CharacterEquipComponent + Offsets.EquipmentInfoArray);
		if (!EquipmentInfoArray.Data || !EquipmentInfoArray.Count)
			return FALSE;


		if (!isValidPtr((ULONG_PTR)EquipmentInfoArray.Data)) return FALSE;


		for (LONG i = 0; i < EquipmentInfoArray.Count; i++) {
			ULONG64 CachePtr = (ULONG64)EquipmentInfoArray.Data + i * 0x30;
			if (!isValidPtr((ULONG_PTR)CachePtr)) return FALSE;
			LONG64 ItemID = Read<LONG64>((ULONG64)CachePtr);
			if (ItemID == 0)
				continue;
			float Durability = Read<float>(CachePtr + 0x18);
			float MaxDurability = Read<float>(CachePtr + 0x1C);
			LONG CurQuality = (ItemID / 1000) % 10;
			//11010006003 _________ ______ _________
			switch (VGetFirst4Digits(ItemID))
			{
				//______
			case 1101: {
				if (Type == 1) {
					//*EquipmentItemID = ItemID;
					*Quality = CurQuality;
					//*EquipmentDurability = Durability;
					//*EquipmentMaxDurability = MaxDurability;
					return TRUE;
				}
				break;
			}
					 //______
			case 1105: {
				if (Type == 2) {
					//*EquipmentItemID = ItemID;
					*Quality = CurQuality;
					//*EquipmentDurability = Durability;
					//*EquipmentMaxDurability = MaxDurability;
					return TRUE;
				}
				break;
			}
			default:
				break;
			}
		}
		return FALSE;
	}

	BOOLEAN Game_GetActorCurWeapon(IN ULONG64 Actor, OUT LONG64* WeaponID) {
		*WeaponID = 0;
		if (!Actor) {
			return FALSE;
		}
		ULONG64 CacheCurWeapon = decrypt_ptr(Read<ULONG64>(Actor + Offsets.CacheCurWeapon));
		if (!isValidPtr((ULONG_PTR)CacheCurWeapon)) return FALSE;
		if (CacheCurWeapon) {

			*WeaponID = Read<LONG64>(CacheCurWeapon + Offsets.WeaponID);
			return TRUE;
		}
		return FALSE;
	}

	BOOLEAN Game_GetActorHeroID(IN ULONG64 Actor, OUT LONG64* HeroID)
	{
		*HeroID = 0;
		if (!Actor) {
			return FALSE;
		}
		ULONG64 PlayerState = decrypt_ptr(Read<ULONG64>(Actor + Offsets.PlayerState));
		if (!isValidPtr((ULONG_PTR)PlayerState)) return FALSE;
		if (!PlayerState) {
			return FALSE;
		}
		*HeroID = Read<LONG64>(PlayerState + Offsets.HeroID);
		return TRUE;
	}
	int getCamp(UINT64 pawn) {

		if (!pawn) {
			return FALSE;
		}
		ULONG64 PlayerState = decrypt_ptr(Read<ULONG64>(pawn + Offsets.PlayerState));
		if (!isValidPtr((ULONG_PTR)PlayerState)) return 0;

		return Read<int>(PlayerState + Offsets.Camp);
	}
	D3DMATRIX MatrixMultiplication(const D3DMATRIX& pM1, const D3DMATRIX& pM2) {
		D3DMATRIX pOut;

		// __ pM1 __ pM2 ______________________
		const float m1_11 = pM1._11, m1_12 = pM1._12, m1_13 = pM1._13, m1_14 = pM1._14;
		const float m1_21 = pM1._21, m1_22 = pM1._22, m1_23 = pM1._23, m1_24 = pM1._24;
		const float m1_31 = pM1._31, m1_32 = pM1._32, m1_33 = pM1._33, m1_34 = pM1._34;
		const float m1_41 = pM1._41, m1_42 = pM1._42, m1_43 = pM1._43, m1_44 = pM1._44;

		const float m2_11 = pM2._11, m2_12 = pM2._12, m2_13 = pM2._13, m2_14 = pM2._14;
		const float m2_21 = pM2._21, m2_22 = pM2._22, m2_23 = pM2._23, m2_24 = pM2._24;
		const float m2_31 = pM2._31, m2_32 = pM2._32, m2_33 = pM2._33, m2_34 = pM2._34;
		const float m2_41 = pM2._41, m2_42 = pM2._42, m2_43 = pM2._43, m2_44 = pM2._44;

		// _______
		pOut._11 = m1_11 * m2_11 + m1_12 * m2_21 + m1_13 * m2_31 + m1_14 * m2_41;
		pOut._12 = m1_11 * m2_12 + m1_12 * m2_22 + m1_13 * m2_32 + m1_14 * m2_42;
		pOut._13 = m1_11 * m2_13 + m1_12 * m2_23 + m1_13 * m2_33 + m1_14 * m2_43;
		pOut._14 = m1_11 * m2_14 + m1_12 * m2_24 + m1_13 * m2_34 + m1_14 * m2_44;

		pOut._21 = m1_21 * m2_11 + m1_22 * m2_21 + m1_23 * m2_31 + m1_24 * m2_41;
		pOut._22 = m1_21 * m2_12 + m1_22 * m2_22 + m1_23 * m2_32 + m1_24 * m2_42;
		pOut._23 = m1_21 * m2_13 + m1_22 * m2_23 + m1_23 * m2_33 + m1_24 * m2_43;
		pOut._24 = m1_21 * m2_14 + m1_22 * m2_24 + m1_23 * m2_34 + m1_24 * m2_44;

		pOut._31 = m1_31 * m2_11 + m1_32 * m2_21 + m1_33 * m2_31 + m1_34 * m2_41;
		pOut._32 = m1_31 * m2_12 + m1_32 * m2_22 + m1_33 * m2_32 + m1_34 * m2_42;
		pOut._33 = m1_31 * m2_13 + m1_32 * m2_23 + m1_33 * m2_33 + m1_34 * m2_43;
		pOut._34 = m1_31 * m2_14 + m1_32 * m2_24 + m1_33 * m2_34 + m1_34 * m2_44;

		pOut._41 = m1_41 * m2_11 + m1_42 * m2_21 + m1_43 * m2_31 + m1_44 * m2_41;
		pOut._42 = m1_41 * m2_12 + m1_42 * m2_22 + m1_43 * m2_32 + m1_44 * m2_42;
		pOut._43 = m1_41 * m2_13 + m1_42 * m2_23 + m1_43 * m2_33 + m1_44 * m2_43;
		pOut._44 = m1_41 * m2_14 + m1_42 * m2_24 + m1_43 * m2_34 + m1_44 * m2_44;

		return pOut;
	}


	FVector GetBoneWithRotation(ULONG64 PawnMeshAddress, int BonesId) {

		if (!isValidPtr(PawnMeshAddress)) return FVector();

		ULONG64 BoneArry = decrypt_ptr(Read<ULONG64>(PawnMeshAddress + Offsets.BonearrayA));
		
		if (!isValidPtr(BoneArry)) return FVector();


		FTransform Bone = Read<FTransform>(BoneArry + (static_cast<unsigned long long>(BonesId) * 0x30));


		FTransform ComponentToWorld = Read<FTransform>(PawnMeshAddress + Offsets.ComponentToWorld);


		D3DMATRIX finalMatrix = MatrixMultiplication(Bone.ToMatrixWithScale(), ComponentToWorld.ToMatrixWithScale());

	
		return FVector(finalMatrix._41, finalMatrix._42, finalMatrix._43);
	}

#pragma code_seg()

} // namespace sjz
