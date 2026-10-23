#include "scan.h"
#include "world.h"
#include "reader.h"
#include "decrypt.h"
#include "ids.h"
#include "aim.h"
#include "menu.h"
#include "internal.h"
#include "coord_cache.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"
#include "../vt/hv.h"
#include "../xor.h"
#include <render/render.h>

namespace sjz {

    // Forward decls - scan.cpp's tick handler reads these from sjz.cpp.
    extern UINT64 currentTime;

#pragma code_seg(".vm")

	// Bone-skeleton segments. Order matters: upperBody is unused after the
	// dead-code split, but the others are dispatched through bodyParts[].
	const int MAX_BONES = 20;
	int upperBody[MAX_BONES] = { Neck, Head, -1 };
	int rightArm [MAX_BONES] = { Neck, RightShoulder, RightElbow, RightHand, -1 };
	int leftArm  [MAX_BONES] = { Neck, LeftShoulder,  LeftElbow,  LeftHand,  -1 };
	int spine    [MAX_BONES] = { Neck, 4, 3, 2, Pelvis, -1 };
	int rightLeg [MAX_BONES] = { Pelvis, RightLeg, RightKnee, RightHeel, -1 };
	int leftLeg  [MAX_BONES] = { Pelvis, LeftLeg,  LeftKnee,  LeftHeel,  -1 };

	const int MAX_BODY_PARTS = 5;
	int* bodyParts[MAX_BODY_PARTS] = { rightArm, leftArm, spine, rightLeg, leftLeg };

	struct {
		float extra_aimspeed = 1.0f;
		float factorx = 5.0f;
		float factory = 5.0f;
		int   fov = 200;
		bool  enabled = false;
		int   target_bone = Head;
	} aim;

	const int MAX_ENTITIES = 0x1000;
	const ULONG MAX_HOOK_COORD_SNAPSHOT = 256;
	ULONG64       objectArray[MAX_ENTITIES];
	EntityInfo    screenPosArray   [MAX_ENTITIES];
	EntityInfo    screenPosArrayCopy[MAX_ENTITIES];
	EntityInfo    otherPosArray    [MAX_ENTITIES];
	EntityInfo    otherPosArrayCopy[MAX_ENTITIES];
	EntityInfo    otherPosArray2    [MAX_ENTITIES];
	EntityInfo    otherPosArrayCopy2[MAX_ENTITIES];
	EntityInfo    highValueItems    [MAX_ENTITIES];
	math_rust::Vector2 screenList   [MAX_ENTITIES];
	UINT64        screenListCount = 0;
	UINT64        highValueCount  = 0;
	int           screenPosCount = 0;
	int           otherPosCount  = 0;
	int           otherPosCount2 = 0;
	CoordActorSnapshot hookCoordSnapshot[MAX_HOOK_COORD_SNAPSHOT];

	ULONG64 count = 0, count1 = 0, count2 = 0, count3 = 0;
	ULONG64 count4 = 0, count5 = 0, count6 = 0, count7 = 0;
	ULONG64 item1 = 0, item2 = 0, item3 = 0, item4 = 0;
	ULONG64 item5 = 0, item6 = 0, item7 = 0;

	char ItemName[256] = { 0 };

	static UINT64 Sat8(ULONG64 v) {
		return v > 0xFF ? 0xFF : v;
	}

	static void UpdateScanDiagPacked() {
		diagPackedCounts =
			0xD100000000000000ull |
			(Sat8((ULONG64)screenPosCount) << 48) |
			(Sat8(count) << 40) |
			(Sat8(count1) << 32) |
			(Sat8(count3) << 24) |
			(Sat8(count5) << 16) |
			(Sat8(count6) << 8) |
			(Sat8(count7));
	}

	static bool ScanFiniteFloat(float v) {
		return (v == v) && (v > -3.4e38f) && (v < 3.4e38f);
	}

	static bool ScanPlausibleWorldPos(const FVector& v) {
		if (!ScanFiniteFloat(v.x) || !ScanFiniteFloat(v.y) || !ScanFiniteFloat(v.z)) return false;
		if (v.x > -0.01f && v.x < 0.01f &&
			v.y > -0.01f && v.y < 0.01f &&
			v.z > -0.01f && v.z < 0.01f) return false;
		return v.x > -10000000.0f && v.x < 10000000.0f &&
			v.y > -10000000.0f && v.y < 10000000.0f &&
			v.z > -10000000.0f && v.z < 10000000.0f;
	}

	static bool TryCachedWorldPos(ULONG64 key, FVector* out) {
		if (!out || !isValidPtr(key)) return false;

		CoordCacheVec3 cached{};
		if (!TryGetActorCoord(key, &cached)) return false;

		FVector hookPos(cached.x, cached.y, cached.z);
		if (!ScanPlausibleWorldPos(hookPos)) return false;

		*out = hookPos;
		return true;
	}

	static bool HasEntityInFrame(ULONG64 key) {
		if (!key)
			return false;
		for (int i = 0; i < screenPosCount; i++) {
			if (screenPosArray[i].pawnAddr == key)
				return true;
		}
		return false;
	}

	static void ResetScanFrameState() {
		count = count1 = count2 = count3 = 0;
		count4 = count5 = count6 = count7 = 0;
		item1 = item2 = item3 = item4 = 0;
		item5 = item6 = item7 = 0;

		isUpdateAimInfo = false;
		screenPosCount = 0;
		otherPosCount = 0;
		otherPosCount2 = 0;
		memset(screenPosArray, 0, sizeof(screenPosArray));
		memset(otherPosArray, 0, sizeof(otherPosArray));
		memset(otherPosArray2, 0, sizeof(otherPosArray2));
	}

	static ULONG AppendHookCoordPlayers() {
		if (screenPosCount >= MAX_ENTITIES)
			return 0;

		const ULONG snapCount = SnapshotCoordActors(
			hookCoordSnapshot,
			MAX_HOOK_COORD_SNAPSHOT,
			4096);

		ULONG appended = 0;
		for (ULONG i = 0; i < snapCount && screenPosCount < MAX_ENTITIES; i++) {
			const auto& snap = hookCoordSnapshot[i];
			if (!snap.key || HasEntityInFrame(snap.key))
				continue;

			FVector pos(snap.pos.x, snap.pos.y, snap.pos.z);
			if (!ScanPlausibleWorldPos(pos))
				continue;

			EntityInfo info;
			memset(&info, 0, sizeof(info));

			info.pawnAddr = snap.key;      // opaque hook key / best owner ptr
			info.pos = pos;
			info.type = player;
			info.teamId = 0;
			info.headth = 100;
			info.color = ImColor(255, 64, 64, 255);
			wcscpy_s(info.objName,
				sizeof(info.objName) / sizeof(wchar_t),
				_XOR_(L"HOOK"));

			if (ScanPlausibleWorldPos(gameData.localPlayerPos)) {
				info.distance = sqrt(
					(gameData.localPlayerPos.x - pos.x) * (gameData.localPlayerPos.x - pos.x) +
					(gameData.localPlayerPos.y - pos.y) * (gameData.localPlayerPos.y - pos.y) +
					(gameData.localPlayerPos.z - pos.z) * (gameData.localPlayerPos.z - pos.z));
			}

			info.worldHeadPos = pos;
			info.worldHeadPos.z += 180.0f;
			info.neckWorldPos = pos;
			info.neckWorldPos.z += 150.0f;

			info.bbox.min = FVector(pos.x - 35.0f, pos.y - 35.0f, pos.z);
			info.bbox.max = FVector(pos.x + 35.0f, pos.y + 35.0f, pos.z + 180.0f);

			if (!WorldToScreen(info.pos, info.screenPos))
				continue;

			if (!WorldToScreen(info.worldHeadPos, info.screenHeadPos)) {
				info.screenHeadPos = info.screenPos;
				info.screenHeadPos.y -= 80.0f;
			}

			screenPosArray[screenPosCount++] = info;
			appended++;
		}

		return appended;
	}

	static FVector GetBestActorWorldLocation(ULONG64 pawn, ULONG64 mesh) {
		// Preferred path for encrypted RootComponent builds:
		// EPT probe catches the game's own coordinate decrypt return and
		// caches plaintext coordinates keyed by the owner-like pointer seen at
		// the return site.  Depending on caller it can be pawn, root, or mesh.
		FVector hookPos{};
		if (TryCachedWorldPos(pawn, &hookPos)) return hookPos;

		ULONG64 root = 0;
		if (isValidPtr(pawn)) {
			root = decrypt_ptr(Read<ULONG64>(pawn + Offsets.RootComponent));
			if (TryCachedWorldPos(root, &hookPos)) return hookPos;
		}

		if (TryCachedWorldPos(mesh, &hookPos)) return hookPos;

		FVector location = GetWorldLocation(pawn);
		if (ScanPlausibleWorldPos(location)) return location;

		// Some player RootComponent locations are encrypted. Bone transforms are
		// often still usable enough for a first on-screen box, so use pelvis/neck
		// as a fallback until the PMO coord-cache is wired in.
		if (isValidPtr(mesh)) {
			FVector pelvis = GetBoneWithRotation(mesh, Pelvis);
			if (ScanPlausibleWorldPos(pelvis)) return pelvis;

			FVector neck = GetBoneWithRotation(mesh, Neck);
			if (ScanPlausibleWorldPos(neck)) {
				neck.z -= 170.0f;
				return neck;
			}
		}

		return location;
	}

	void ReadPlayerData(EntityInfo info) {



		count++;

		bool isBigWord = false;

		info.objectId = Read<ULONG>(info.pawnAddr + Offsets.GObjcetID);


		bool isNpc = false;
		info.color = ImColor(255, 255, 255, 255);
		info.type = 0;



		char name[256] = { 0 };
		bool isWide = false;
		GetName(info.objectId, name, sizeof(name), isWide);

		wchar_t wname[128] = { 0 };
		if (!isWide) {
			// ______________
			MultiByteToWideChar(name, wname, sizeof(wname) / sizeof(wchar_t));
		}
		else {
			// ______________________
			//memcpy(wname, name, min(sizeof(wname), strlen((char*)name) * sizeof(wchar_t)));
		}
		wcscpy_s(info.objName, sizeof(info.objName) / sizeof(wchar_t), wname);


		bool isfind = false;

		int kind = LookupPlayerKind(info.objName);
		if (kind != kPlayerKindNone) {
			FillPlayerKindName(kind, info.objName,
				sizeof(info.objName) / sizeof(wchar_t));
			isfind = true;
		}


		if (isfind) {


			info.headth = isValidPtr(info.pawnAddr) ? GetHealth(info.pawnAddr) : 0;


			if (info.headth <= 0)
				info.headth = 100;

			if (info.headth > 0) {

				count1++;



				if (wcscmp(info.objName, _XOR_(L"___")) == 0) {
					info.color = ImColor(255, 0, 0, 255);
				}
				else if (wcscmp(info.objName, _XOR_(L"_______")) == 0) {
					isBigWord = true;
					wcscpy_s(info.objName, sizeof(info.objName) / sizeof(wchar_t), _XOR_(L"___"));
					info.color = ImColor(255, 0, 0, 255);
				}
				else {
					wcscpy_s(info.objName, sizeof(info.objName) / sizeof(wchar_t), _XOR_(L"NPC"));
					isNpc = true;
					if (!menu::isShowNpc) return;
				}
				count2++;
				info.teamId = GetTeamId(info.pawnAddr);
				if (isBigWord) {
					info.camp = getCamp(info.pawnAddr);
					if (info.camp == gameData.camp)
						return;
				}
				if ((info.teamId > 0 && info.teamId < 0x10) || (isNpc) || (isBigWord) || isfind) {


					count3++;

					info.headth = isValidPtr(info.pawnAddr) ? GetHealth(info.pawnAddr) : 0;

					if (gameData.PlayerTeam != 0 && info.teamId == gameData.PlayerTeam && !isBigWord) {
						wcscpy_s(info.objName, sizeof(info.objName) / sizeof(wchar_t), _XOR_(L"____"));
						info.color = ImColor(0, 255, 0, 255);
					}

					auto PlayerState = Read<ULONG64>((info.pawnAddr + Offsets.PlayerState));
					if (PlayerState) {
						auto ExitState = Read<char>((PlayerState + Offsets.ExitState));
						info.exitState = ExitState;
						if (info.exitState == 3) return;
					}

					count4++;

					if (screenPosCount < MAX_ENTITIES) {



						count5++;


						ULONG64 entityPawnMeshAddress = decrypt_ptr(Read<ULONG64>(info.pawnAddr + Offsets.PlayerPawnMesh));
						auto entityWorldPos = GetBestActorWorldLocation(info.pawnAddr, entityPawnMeshAddress);


						if (!ScanPlausibleWorldPos(entityWorldPos)) return;

						info.pos = entityWorldPos;

						const bool hasLocalPos = ScanPlausibleWorldPos(gameData.localPlayerPos);
						info.distance = hasLocalPos ? sqrt(
							(gameData.localPlayerPos.x - entityWorldPos.x) * (gameData.localPlayerPos.x - entityWorldPos.x) +
							(gameData.localPlayerPos.y - entityWorldPos.y) * (gameData.localPlayerPos.y - entityWorldPos.y) +
							(gameData.localPlayerPos.z - entityWorldPos.z) * (gameData.localPlayerPos.z - entityWorldPos.z)) : 0.0f;


						WorldToScreen(info.pos, info.screenPos);

						if (wcscmp(info.objName, _XOR_(L"____")) == 0) {
							if (hasLocalPos && info.distance > 6000) return;
						}

						if (wcscmp(info.objName, _XOR_(L"NPC")) == 0) {
							if (hasLocalPos && info.distance > 15000) return;
						}







						count6++;

						memset(&info.helmetEquipment, 0, sizeof(info.helmetEquipment));
						memset(&info.armorEquipment, 0, sizeof(info.armorEquipment));
						Game_GetEquipmentInfo(info.pawnAddr, 1, &info.helmetEquipment.level);
						Game_GetEquipmentInfo(info.pawnAddr, 2, &info.armorEquipment.level);


						if (wcscmp(info.objName, _XOR_(L"____")) != 0) {

							if (entityPawnMeshAddress) {


								// ____________________
								math_rust::Vector2 LastValidPosition;
								bool hasValidPosition = false;
								math_rust::Vector2 closestBonePos;
								FVector closestBoneWorldPos;
								UINT64 minDistance = MAXULONG64;



								// ____________
								info.bbox.min = FVector(FLT_MAX, FLT_MAX, FLT_MAX);
								info.bbox.max = FVector(-FLT_MAX, -FLT_MAX, -FLT_MAX);



								// __________
								int boxCount = 0;
								for (int partIndex = 0; partIndex < MAX_BODY_PARTS; partIndex++) {
									// _______________
									hasValidPosition = false;
									int* bones = bodyParts[partIndex];

									// ____________________________
									for (int i = 0; i < MAX_BONES && bones[i] != -1; i++) {
										auto boneWorldPosition = GetBoneWithRotation(entityPawnMeshAddress, bones[i]);
										sjz::FVector LastValidWorldPos;
										math_rust::Vector2 ScreenPosition = { 0,0 };
										WorldToScreen(boneWorldPosition, ScreenPosition);

										if (ScreenPosition.x != ScreenPosition.x || ScreenPosition.y != ScreenPosition.y) continue;

										float dx = ScreenPosition.x - game::GameCenterX;
										float dy = ScreenPosition.y - game::GameCenterY;
										float distance = sqrt(dx * dx + dy * dy);




										// _________________
										if (distance < minDistance) {
											minDistance = distance;
											closestBonePos = ScreenPosition;
											closestBoneWorldPos = boneWorldPosition;
										}

										// _______________________
										if (hasValidPosition) {
											if (InScreen(LastValidPosition) && InScreen(ScreenPosition))
											{
												if (
													abs(boneWorldPosition.z - info.pos.z) < 100 &&
													abs(boneWorldPosition.x - info.pos.x) < 100 &&
													abs(boneWorldPosition.y - info.pos.y) < 100

													)
												{
													// ________________
													info.bbox.min.x = min(info.bbox.min.x, boneWorldPosition.x);
													info.bbox.min.y = min(info.bbox.min.y, boneWorldPosition.y);
													info.bbox.min.z = min(info.bbox.min.z, boneWorldPosition.z);
													info.bbox.max.x = max(info.bbox.max.x, boneWorldPosition.x);
													info.bbox.max.y = max(info.bbox.max.y, boneWorldPosition.y);
													info.bbox.max.z = max(info.bbox.max.z, boneWorldPosition.z);
													info.DrawVectorBonesPos[boxCount++] = { LastValidPosition, ScreenPosition,1,0 };
												}

											}
										}
										else {
											hasValidPosition = true; // __________________
										}

										// _________________
										LastValidPosition = ScreenPosition;
										LastValidWorldPos = boneWorldPosition;
									}
								}




								info.bbox.max.z += 35;

								if (menu::isHead) {
									auto headPos = GetBoneWithRotation(entityPawnMeshAddress, Neck);
									headPos.z += 10;
									WorldToScreen(headPos, info.screenHeadPos);
									info.worldHeadPos = headPos;
								}
								else {
									info.screenHeadPos = closestBonePos;
									info.worldHeadPos = closestBoneWorldPos;
								}


								float dx = info.screenHeadPos.x - game::GameCenterX;
								float dy = info.screenHeadPos.y - game::GameCenterY;
								float distance = sqrt(dx * dx + dy * dy);

								if (distance <= aim.fov && !isAiming) {
									// ___________________________
									if (aimInfo.pawnAddr == 0 || distance < aimDistance) {
										aimInfo = info;
										aimDistance = distance;
										isUpdateAimInfo = true;
									}
								}
								else {
									if (aimInfo.pawnAddr != 0 && aimInfo.pawnAddr == info.pawnAddr) {
										aimInfo = info;
										aimDistance = distance;

										isUpdateAimInfo = true;

									}

								}


								info.neckWorldPos = GetBoneWithRotation(entityPawnMeshAddress, Neck);
							}



						}

						count7++;
						screenPosArray[screenPosCount++] = info;
					}

				}

			}



		}


	}
	void ReadItemlootingData(EntityInfo info) {

		item1++;

		if (!menu::isShowItem) return;
		

		memset(ItemName, 0, sizeof(ItemName));
		
		bool isWide = false;
		GetName(info.objectId, ItemName, sizeof(ItemName), isWide);

		wchar_t wname[128] = { 0 };
		if (!isWide) {
			// ______________
			MultiByteToWideChar(ItemName, wname, sizeof(wname) / sizeof(wchar_t));
		}
		else {
			// ______________________
			memcpy(wname, ItemName, min(sizeof(wname), strlen((char*)ItemName) * sizeof(wchar_t)));
		}
		wcscpy_s(info.objName, sizeof(info.objName) / sizeof(wchar_t), wname);

		if (!((wcscmp(info.objName, _XOR_(L"BP_InventoryPickup_C")) == 0) ||
			(wcscmp(info.objName, _XOR_(L"BP_InventoryPickup_FromSingleItemContainer_C")) == 0) ||
			(wcscmp(info.objName, _XOR_(L"BP_InventoryPickup_Container_C")) == 0))) return;


		item2++;


		auto entityWorldPos = GetWorldLocation(info.pawnAddr);
		info.pos = entityWorldPos;
		if (gameData.localPlayerPos.x != gameData.localPlayerPos.x || gameData.localPlayerPos.y != gameData.localPlayerPos.y || gameData.localPlayerPos.z != gameData.localPlayerPos.z) return;
		if (entityWorldPos.x != entityWorldPos.x || entityWorldPos.y != entityWorldPos.y || entityWorldPos.z != entityWorldPos.z) return;
		info.distance = sqrt(
			(gameData.localPlayerPos.x - entityWorldPos.x) * (gameData.localPlayerPos.x - entityWorldPos.x) +
			(gameData.localPlayerPos.y - entityWorldPos.y) * (gameData.localPlayerPos.y - entityWorldPos.y) +
			(gameData.localPlayerPos.z - entityWorldPos.z) * (gameData.localPlayerPos.z - entityWorldPos.z));
		WorldToScreen(info.pos, info.screenPos);

		info.type = 3;
		info.color = ImColor(255, 255, 0, 255);
		wcscpy_s(info.objName, sizeof(info.objName) / sizeof(wchar_t), _XOR_(L"____ "));

		auto lootable = Read<ULONG64>(info.pawnAddr + Offsets.PickupItemInfo);
		item3++;

		if (lootable) {
			if (!isValidPtr(lootable)) return;

			item4++;

			info.price = Read<ULONG>(lootable + Offsets.InitialGuidePrice);
			info.level = Read<ULONG>(lootable + Offsets.Quality);
			info.size = Read<ULONG>(lootable + Offsets.Width) * Read<ULONG>(lootable + Offsets.Length);

			ImVec4 itemColor;
			switch (info.level) {
			case 2: itemColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f); break; // ____
			case 3: itemColor = ImVec4(0.0f, 0.5f, 1.0f, 1.0f); break; // ____
			case 4: itemColor = ImVec4(1.0f, 0.0f, 1.0f, 1.0f); break; // ____
			case 5: itemColor = ImVec4(1.0f, 0.5f, 0.0f, 1.0f); break; // ____
			case 6: itemColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f); break; // ____
			default: itemColor = info.color; break;
			}
			info.color = itemColor;

			if (info.size != 0) {
				if ((info.level > 2 && info.level <= 7 && ((info.price / info.size) > 10000))) {

					item5++;

					if (otherPosCount < MAX_ENTITIES) {
						otherPosArray[otherPosCount++] = info;
					}
				}
			}
		}




	}
	void ReadData() {

		diagPipelineStage = 200; // ReadData entered
		const ULONG64 localPawn = decrypt_ptr(decrypt(gameData.AcknowledgedPawn));

		ResetScanFrameState();
		if (!isValidPtr(gameData.ULevels) || !isValidPtr(gameData.ULevel) || !isValidPtr(gameData.Actor)) {
			diagPipelineStage = 210; // ReadData guard failed
			AppendHookCoordPlayers();
			UpdateScanDiagPacked();
			return;
		}
		diagPipelineStage = 220; // ReadData guard passed



		UINT64 time;
		hv::Call(RtlQueryPerformanceCounter, (LARGE_INTEGER*)hv::descBuffer);
		RtlCopyMemory(&time, hv::descBuffer_hva, sizeof(UINT64));

		currentTime = time;


		auto otherPosCount2_temp = 0;

		



		for (int i = 0; i <1; i++) {

			ULONG64 level = Read<ULONG64>(gameData.ULevels + (i * 8));

			if (!level) continue;

			ULONG64 actorArray = decrypt_qword(Read<ULONG64>(level + Offsets.Actor));

			if (!actorArray) {
				diagPipelineStage = 230; // actor array null
				continue;
			}

			int actorCount = Read<int>(level + Offsets.Count);

			for (int j = 0; j < actorCount; j++) {

				ULONG64 entityPawnAddress = Read<ULONG64>(actorArray + (j * 8));
				if (!isValidPtr(entityPawnAddress)) continue;
				if (isValidPtr(localPawn) && entityPawnAddress == localPawn) continue;

				EntityInfo info;
				memset(&info, 0, sizeof(EntityInfo));
				info.pawnAddr = entityPawnAddress;

				EMarkingItemType type = (EMarkingItemType)Read<char>(entityPawnAddress + Offsets.MarkingItemType);
				info.objectId = Read<ULONG>(entityPawnAddress + Offsets.GObjcetID);

				if (info.objectId == 0) continue;


				if (type == EMarkingItemType::None) {

					
					ReadPlayerData(info);
					

				}
				else if (type == EMarkingItemType::LootingItem) {

				
					ReadItemlootingData(info);
					
				}
				

			}




		}

		diagPipelineStage = 240; // actor loop finished
		if (screenPosCount == 0)
			AppendHookCoordPlayers();
		UpdateScanDiagPacked();


		/*for (int i = 0; i < otherPosCount2_temp; i++) {
			

	
			EntityInfo info = otherPosArrayCopy2[i];
			auto entityPawnAddress = info.pawnAddr;

			if (!isValidPtr(entityPawnAddress)) continue;



			auto entityWorldPos = GetWorldLocation(entityPawnAddress);
			info.pos = entityWorldPos;

			info.distance = sqrt(
				(gameData.localPlayerPos.x - entityWorldPos.x) * (gameData.localPlayerPos.x - entityWorldPos.x) +
				(gameData.localPlayerPos.y - entityWorldPos.y) * (gameData.localPlayerPos.y - entityWorldPos.y) +
				(gameData.localPlayerPos.z - entityWorldPos.z) * (gameData.localPlayerPos.z - entityWorldPos.z));
			WorldToScreen(info.pos, info.screenPos);

			if(!_wcsicmp(info.objName, (L"____"))) {

				if (info.distance > 20000) continue;

			}

			info.isOpen = Read<char>(entityPawnAddress + Offsets.bHasOpened);
			if (info.isOpen) continue;

			if (otherPosCount < MAX_ENTITIES) {

				otherPosArray[otherPosCount++] = info;

			}



		}*/


	}


#pragma code_seg()

} // namespace sjz
