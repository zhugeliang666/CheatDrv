#include "draw.h"
#include "scan.h"
#include "world.h"
#include "reader.h"
#include "aim.h"
#include "ids.h"
#include "menu.h"
#include "session.h"
#include "internal.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"
#include <gamecommon/draw.h>
#include "../vt/hv.h"
#include "../xor.h"

namespace sjz {

    extern UINT64  currentTime;
    extern ULONG64 engine;

    // Slice-fidelity: scan.cpp's debug counters are read from the debug
    // overlay path below. Their definitions live in scan.cpp.
    extern ULONG64 count, count1, count2, count3, count4, count5, count6, count7;
    extern ULONG64 item1, item2, item3, item4, item5, item6, item7;

    // Legacy alias for kMaxEntities — the original DrawItem/DrawHighValue
    // bodies were sliced verbatim and still spell the constant in MACRO
    // form. R3 will fold them into kMaxEntities.
    constexpr int MAX_ENTITIES = kMaxEntities;

#pragma code_seg(".vm")

	// File-scope scratch buffers ___ kept here for slice fidelity. Each is
	// reused per-call so they are NOT thread-safe (frame draw is single-
	// threaded today).
	wchar_t str[256];
	wchar_t itemInfo[256] = { 0 };
	char    temp[128] = { 0 };

	void DrawRander(EntityInfo info) {

		float x = game::GameCenterW - 175, y = 200;

		// ___________
		float relativeX = info.pos.x - gameData.localPlayerPos.x;
		float relativeY = info.pos.y - gameData.localPlayerPos.y;

		// ________
		relativeX /= 100;
		relativeY /= 100;

		// _______
		float R = sqrtf(relativeX * relativeX + relativeY * relativeY);

		// _______
		float Angle = atan2f(relativeY, relativeX) * 180 / 3.1415926f;
		Angle = gameData.PlayerRotator.yaw - Angle;
		Angle = Angle * 3.1415926f / 180;

		// __________150____R______150
		if (R > 150) {
			R = 150;
		}

		// ________________
		float radarX = x - (R * sinf(Angle));
		float radarY = y - (R * cosf(Angle));

		if (radarX != radarX || radarY != radarY) return;

		// ___________
		DrawCircleFilled(radarX, radarY, 3, info.color, 100);


	}
	// HSV__ImColor__h____0~1__s____0~1__v____0~1
	ImColor GetTeamColor(int teamId) {
		// ______10_________________HSV__________
		static const struct {
			float h, s, v;  // __________________
		} teamColors[] = {
			{0.0f,  0.85f, 0.95f},  // ____ (____1)
			{0.33f, 0.85f, 0.95f},  // ____ (____2)
			{0.66f, 0.85f, 0.95f},  // ____ (____3)
			{0.16f, 0.85f, 0.95f},  // ____ (____4)
			{0.5f,  0.85f, 0.95f},  // ____ (____5)
			{0.83f, 0.85f, 0.95f},  // ____ (____6)
			{0.08f, 0.85f, 0.95f},  // ____ (____7)
			{0.41f, 0.85f, 0.95f},  // ______ (____8)
			{0.75f, 0.85f, 0.95f},  // ______ (____9)
			{0.25f, 0.85f, 0.95f}   // ______ (____10)
		};

		// ____teamId____________
		int index = (teamId - 1) % 10;  // __teamId______0-9______
		if (index < 0) index += 10;     // ___________

		float h = teamColors[index].h;
		float s = teamColors[index].s;
		float v = teamColors[index].v;

		float r = 0, g = 0, b = 0;

		int i = int(h * 6);
		float f = h * 6 - i;
		float p = v * (1 - s);
		float q = v * (1 - f * s);
		float t = v * (1 - (1 - f) * s);

		switch (i % 6) {
		case 0: r = v, g = t, b = p; break;
		case 1: r = q, g = v, b = p; break;
		case 2: r = p, g = v, b = t; break;
		case 3: r = p, g = q, b = v; break;
		case 4: r = t, g = p, b = v; break;
		case 5: r = v, g = p, b = q; break;
		}

		return ImColor(r, g, b, 1.0f);
	}

	static bool DrawFiniteFloat(float v) {
		return (v == v) && (v > -3.4e38f) && (v < 3.4e38f);
	}

	static bool DrawFinite2(const math_rust::Vector2& p) {
		return DrawFiniteFloat(p.x) && DrawFiniteFloat(p.y);
	}

	static bool DrawFinite3(const FVector& p) {
		return DrawFiniteFloat(p.x) && DrawFiniteFloat(p.y) && DrawFiniteFloat(p.z);
	}

	static bool DrawPlausibleWorld3(const FVector& p) {
		if (!DrawFinite3(p)) return false;
		if (p.x > -0.01f && p.x < 0.01f &&
			p.y > -0.01f && p.y < 0.01f &&
			p.z > -0.01f && p.z < 0.01f) return false;
		return p.x > -10000000.0f && p.x < 10000000.0f &&
			p.y > -10000000.0f && p.y < 10000000.0f &&
			p.z > -10000000.0f && p.z < 10000000.0f;
	}

	static bool IsUsableBox(const BoundingBox& box) {
		if (!DrawFinite3(box.min) || !DrawFinite3(box.max)) return false;
		if (box.min.x > box.max.x || box.min.y > box.max.y || box.min.z > box.max.z) return false;
		if (box.min.x < -10000000.0f || box.min.y < -10000000.0f || box.min.z < -10000000.0f) return false;
		if (box.max.x > 10000000.0f || box.max.y > 10000000.0f || box.max.z > 10000000.0f) return false;
		return true;
	}

	static bool BuildFallback2DBox(const EntityInfo& info, float& minX, float& minY, float& maxX, float& maxY) {
		FVector footWorld = info.pos;
		if (!DrawPlausibleWorld3(footWorld)) {
			if (DrawPlausibleWorld3(info.worldHeadPos)) {
				footWorld = info.worldHeadPos;
				footWorld.z -= 180.0f;
			}
			else if (DrawPlausibleWorld3(info.neckWorldPos)) {
				footWorld = info.neckWorldPos;
				footWorld.z -= 170.0f;
			}
			else {
				return false;
			}
		}

		math_rust::Vector2 foot = info.screenPos;
		if (!DrawFinite2(foot) || !InScreen(foot)) {
			foot = { 0.0f, 0.0f };
			if (!WorldToScreen(footWorld, foot)) return false;
		}

		math_rust::Vector2 head = info.screenHeadPos;
		if (!DrawFinite2(head) || !InScreen(head)) {
			FVector headWorld = info.worldHeadPos;
			if (!DrawFinite3(headWorld) ||
				(headWorld.x == 0.0f && headWorld.y == 0.0f && headWorld.z == 0.0f)) {
				headWorld = info.pos;
				headWorld.z += 180.0f;
			}
			if (!DrawPlausibleWorld3(headWorld)) {
				headWorld = footWorld;
				headWorld.z += 180.0f;
			}
			head = { 0.0f, 0.0f };
			if (!WorldToScreen(headWorld, head)) return false;
		}

		float boxHeight = fabsf(foot.y - head.y);
		if (!DrawFiniteFloat(boxHeight) || boxHeight < 6.0f || boxHeight > 2000.0f) return false;

		float boxWidth = boxHeight * 0.48f;
		if (boxWidth < 2.0f) boxWidth = 2.0f;

		const float centerX = (head.x + foot.x) * 0.5f;
		minX = centerX - boxWidth * 0.5f;
		maxX = centerX + boxWidth * 0.5f;
		minY = min(head.y, foot.y);
		maxY = max(head.y, foot.y);
		return DrawFiniteFloat(minX) && DrawFiniteFloat(minY) &&
			DrawFiniteFloat(maxX) && DrawFiniteFloat(maxY);
	}

	void DrawPlayer(EntityInfo info) {
		diagDrawPlayerCalls++;
		diagPipelineStage = 320; // DrawPlayer reached

		bool isNotAllin = false;

		// ___________8______
		info.bbox.vertices[0] = FVector(info.bbox.min.x, info.bbox.min.y, info.bbox.min.z);  // ______
		info.bbox.vertices[1] = FVector(info.bbox.max.x, info.bbox.min.y, info.bbox.min.z);  // ______
		info.bbox.vertices[2] = FVector(info.bbox.max.x, info.bbox.max.y, info.bbox.min.z);  // ______
		info.bbox.vertices[3] = FVector(info.bbox.min.x, info.bbox.max.y, info.bbox.min.z);  // ______
		info.bbox.vertices[4] = FVector(info.bbox.min.x, info.bbox.min.y, info.bbox.max.z);  // ______
		info.bbox.vertices[5] = FVector(info.bbox.max.x, info.bbox.min.y, info.bbox.max.z);  // ______
		info.bbox.vertices[6] = FVector(info.bbox.max.x, info.bbox.max.y, info.bbox.max.z);  // ______
		info.bbox.vertices[7] = FVector(info.bbox.min.x, info.bbox.max.y, info.bbox.max.z);  // ______

		// _______________________
		float minX = FLT_MAX, minY = FLT_MAX;
		float maxX = -FLT_MAX, maxY = -FLT_MAX;
		// ________________________________
		math_rust::Vector2 screenVertices[8] = {};
		bool usedFallbackBox = false;
		if (IsUsableBox(info.bbox)) {
			for (int i = 0; i < 8; i++) {
				if (!WorldToScreen(info.bbox.vertices[i], screenVertices[i])) {
					isNotAllin = true;
					continue;
				}
				minX = min(minX, screenVertices[i].x);
				minY = min(minY, screenVertices[i].y);
				maxX = max(maxX, screenVertices[i].x);
				maxY = max(maxY, screenVertices[i].y);
				if (!InScreen(screenVertices[i])) isNotAllin = true;
			}
		}
		else {
			isNotAllin = true;
		}
		if (isNotAllin) {
			if (!BuildFallback2DBox(info, minX, minY, maxX, maxY)) return;
			usedFallbackBox = true;
		}

		// _______________
		float boxHeight = maxY - minY;

		bool isNPC = (wcscmp(info.objName, _XOR_(L"NPC")) == 0);

		if (menu::isBattleMode && isNPC)  return;

		const float borderOffset = 1.0f;  // ______3D____________

		if (minX != minX || minY != minY || maxX!=maxX || maxY!=maxY) return;

		if (menu::isBox)
			DrawRect(
				minX - borderOffset,
				minY - borderOffset,
				maxX - minX + borderOffset * 2,
				maxY - minY + borderOffset * 2,
				info.color,
				1.0f
			);

		

		// ________
		const float healthBarWidth = 4.0f;  // ________
		const float healthBarOffset = 4.0f;  // ______________

		// _________________________
		float healthBarX = minX - borderOffset - healthBarOffset;
		float healthBarY = minY - borderOffset;

		if (healthBarX != healthBarX || healthBarY != healthBarY) return ;

		if (menu::isHealth)
		{
			// ____________________
			DrawFilledRect(
				healthBarX - healthBarWidth / 2,
				healthBarY,
				healthBarWidth,
				boxHeight + borderOffset * 2,
				ImVec4(50, 50, 50, 180), 0, 0
			);

			// ______________
			float healthPercent = (float)info.headth / 100.0f;
			if (healthPercent != healthPercent) return;
			healthPercent = max(0.0f, min(1.0f, healthPercent));  // ______0-1____

			// ____________________________
			ImVec4 healthColor = ImColor(0, 255, 0, 255);

			// ____________
			DrawFilledRect(
				healthBarX - healthBarWidth / 2,
				healthBarY + (boxHeight + borderOffset * 2) * (1.0f - healthPercent),
				healthBarWidth,
				(boxHeight + borderOffset * 2) * healthPercent,
				healthColor, 0, 0
			);

			// ____________
			DrawRect(
				healthBarX - healthBarWidth / 2,
				healthBarY,
				healthBarWidth,
				boxHeight + borderOffset * 2,
				ImColor(255, 255, 255, 255),
				1.0f
			);

		}
		


		if (menu::isSkeleton && !usedFallbackBox) {

			//____________
			for (const auto& bone : info.DrawVectorBonesPos) {
				if (bone.IsVisible) {
					// ____________
					if (bone.start.x != bone.start.x || bone.start.y != bone.start.y)  return;
					if (bone.end.x != bone.end.x || bone.end.y != bone.end.y) return;
					DrawLine(
						bone.start.x, bone.start.y,
						bone.end.x, bone.end.y,
						info.color,  // ___________
						1.0f        // ________
					);

				}
			}

			auto headWorldPos = info.neckWorldPos;
			headWorldPos.z += 10.0f;
			math_rust::Vector2 headScreenPos = { 0, 0 };
			math_rust::Vector2 neckScreenPos = { 0, 0 };

			WorldToScreen(headWorldPos, headScreenPos);
			WorldToScreen(info.neckWorldPos, neckScreenPos);
			if (headScreenPos.x != headScreenPos.x || headScreenPos.y != headScreenPos.y) return;
			DrawCircle(headScreenPos.x, headScreenPos.y, headScreenPos.y - neckScreenPos.y, info.color, 32, 1);

		}
	


		if (!menu::isBattleMode) {



			// __________________

			ImVec2 nameSize = CalaTextSize(info.objName);
			float nameBarPadding = 10.0f; // __________
			float nameBarWidth = nameSize.x + nameBarPadding * 2;
			float nameBarHeight = nameSize.y + 4.0f; // __________
			float circleRadius = nameBarHeight / 2.0f; // _______________
			float circleGap = 2.0f; // ____________

			float totalWidth = isNPC ? nameBarWidth : (circleRadius * 2 + circleGap + nameBarWidth);
			float totalX = (minX + maxX) / 2 - totalWidth / 2;
			float nameBarX = isNPC ? totalX : (totalX + circleRadius * 2 + circleGap);
			float nameBarY = minY - borderOffset - nameBarHeight - 2;
			float circleCenterX = totalX + circleRadius;
			float circleCenterY = nameBarY + nameBarHeight / 2;

			// __NPC__________
			if (!isNPC) {
				ImColor teamColor = GetTeamColor(info.teamId);
				if (circleCenterX != circleCenterX || circleCenterY != circleCenterY || circleRadius != circleRadius) return;
				DrawCircleFilled(circleCenterX, circleCenterY, circleRadius, teamColor);

				DrawCircle(circleCenterX, circleCenterY, circleRadius, ImColor(255, 255, 255, 220), 1.0f);
				char teamStr[16];
				sprintf(teamStr, ("%d"), (int)info.teamId);
				
				WCHAR teamStrW[256] = { 0 };
				MultiByteToWideChar(teamStr, teamStrW, sizeof(teamStrW) / sizeof(wchar_t));
				DrawCenterText(circleCenterX, circleCenterY - 2, ImColor(255, 255, 255, 220), teamStrW);
			}
			if (nameBarX != nameBarX || nameBarY != nameBarY || nameBarWidth != nameBarWidth || nameBarHeight!= nameBarHeight) return;
			// ____________
			DrawFilledRect(
				nameBarX,
				nameBarY,
				nameBarWidth,
				nameBarHeight,
				ImVec4(0.1f, 0.1f, 0.1f, 0.8f), // ______________
				0, 0
			);
			// __________________________
			DrawCenterText(
				nameBarX + nameBarWidth / 2,
				nameBarY + nameBarHeight / 2 - 2,
				ImColor(255, 255, 255, 255),
				info.objName
			);

			if (info.teamId > 0 && info.teamId < 10 || isNPC) {

			



				// ________________
				WCHAR equipInfo[256] = { 0 };
				wcscpy_s(equipInfo, sizeof(equipInfo) / sizeof(wchar_t), (L""));
				char helmetStr[16] = { 0 };
				sprintf(helmetStr, ("%d"), info.helmetEquipment.level);
				wchar_t helmetWStr[16] = { 0 };
				MultiByteToWideChar(helmetStr, helmetWStr, sizeof(helmetWStr) / sizeof(wchar_t));
				wcscat_s(equipInfo, sizeof(equipInfo) / sizeof(wchar_t), helmetWStr);
				wcscat_s(equipInfo, sizeof(equipInfo) / sizeof(wchar_t), (L"__ | "));
				char armorStr[16] = { 0 };
				sprintf(armorStr, ("%d"), info.armorEquipment.level);
				wchar_t armorWStr[16] = { 0 };
				MultiByteToWideChar(armorStr, armorWStr, sizeof(armorWStr) / sizeof(wchar_t));
				wcscat_s(equipInfo, sizeof(equipInfo) / sizeof(wchar_t), armorWStr);
				wcscat_s(equipInfo, sizeof(equipInfo) / sizeof(wchar_t), (L"__"));

				// __________________________________
				float equipInfoY = nameBarY - 14.0f; // ____________14____
				if (nameBarX != nameBarX || equipInfoY != equipInfoY) return;
				DrawCenterText(
					nameBarX + nameBarWidth / 2,
					equipInfoY,
					ImColor(255, 255, 255, 255),
					equipInfo
				);

				// __________________
				wchar_t heroName[128] = { 0 };
				wchar_t weaponName[128] = { 0 };
				LONG64 weaponid;
				LONG64 heroid;

				Game_GetActorHeroID(info.pawnAddr, &heroid);
				Game_GetActorCurWeapon(info.pawnAddr, &weaponid);
				//if (!gameData.isEncrypted)
					weaponid ^= 0xDEADBEEF;

				bool isEncrypted = false;

				//if (!gameData.isEncrypted)
				heroid ^= 0xDEADBEEF;

				FillHeroName(heroid, heroName,
					sizeof(heroName) / sizeof(wchar_t));




				FillWeaponName(weaponid, weaponName,
					sizeof(weaponName) / sizeof(wchar_t));

				// ____________________________________
				WCHAR heroWeaponInfo[256] = { 0 };
				wcscpy_s(heroWeaponInfo, sizeof(heroWeaponInfo) / sizeof(wchar_t), (L""));

				if (isNPC) {
					wcscat_s(heroWeaponInfo, sizeof(heroWeaponInfo) / sizeof(wchar_t), weaponName);
				}
				else {
					wcscat_s(heroWeaponInfo, sizeof(heroWeaponInfo) / sizeof(wchar_t), heroName);
					wcscat_s(heroWeaponInfo, sizeof(heroWeaponInfo) / sizeof(wchar_t), (L" | "));
					wcscat_s(heroWeaponInfo, sizeof(heroWeaponInfo) / sizeof(wchar_t), weaponName);
				}

				float heroWeaponInfoY = equipInfoY - 14.0f; // ______________14____
				if (heroWeaponInfoY != heroWeaponInfoY) return;
				DrawCenterText(
					nameBarX + nameBarWidth / 2,
					heroWeaponInfoY,
					ImColor(255, 255, 255, 255),
					heroWeaponInfo
				);
			}


		}


		if (menu::isDistance) {

			auto screenPos = info.screenPos;

			char teamStr[16];
			sprintf(teamStr, ("%dm"), (int)(int)info.distance / 100);
			WCHAR teamStrW[256] = { 0 };
			MultiByteToWideChar(teamStr, teamStrW, sizeof(teamStrW) / sizeof(wchar_t));

			math_rust::Vector2 boneScreenPos = { 0,0 };
			WorldToScreen(info.bbox.min, boneScreenPos);
			if(screenPos.x != screenPos.x || boneScreenPos.y != boneScreenPos.y) return;
			DrawCenterText(screenPos.x, boneScreenPos.y + 10, info.color, teamStrW);

		}


}
	void DrawItem(EntityInfo info) {

		if (wcscmp(info.objName, _XOR_(L"____")) == 0) {
			if (info.distance > 6000) return;
		}


		if (menu::isBattleMode && info.type == 1) return;
		//if (info.type == 1) continue;

		DrawRander(info);

		if (info.type == 3) {
			if (highValueCount < MAX_ENTITIES) {
				highValueItems[highValueCount++] = info;
			}
		}


		if (!InScreen(info.screenPos)) return;
		
		if (info.type == 3) {
			memset(str, 0, sizeof(str));
			wcscpy_s(str, sizeof(str) / sizeof(wchar_t), info.objName);
			char valueStr[64] = { 0 };
			sprintf(valueStr, _XOR_(" %d %d [%d]"), info.price, info.size, info.level);
			wchar_t valueWStr[64] = { 0 };
			MultiByteToWideChar(valueStr, valueWStr, sizeof(valueWStr) / sizeof(wchar_t));
			wcscat_s(str, sizeof(str) / sizeof(wchar_t), valueWStr);
			wcscpy_s(info.objName, sizeof(info.objName) / sizeof(wchar_t), str);

		}

		// _______
		for (int z = 0; z < screenListCount; z++) {

			auto List = screenList[z];
			if (info.screenPos.x != info.screenPos.x || info.screenPos.y != info.screenPos.y) return;
			if (info.screenPos.x > (List.x - 80.f) && info.screenPos.x < (List.x + 80.f)
				&& info.screenPos.y >(List.y - 15.f) && info.screenPos.y < (List.y + 15.f)) {
				info.screenPos = List;
				info.screenPos.y = info.screenPos.y - 18.f;
			}
		}
		memset(str, 0, sizeof(str));
		wcscpy_s(str, sizeof(str) / sizeof(wchar_t), info.objName);
		char distStr[32] = { 0 };
		sprintf(distStr, _XOR_(" [%dm]"), info.distance / 100);
		wchar_t distWStr[32] = { 0 };
		MultiByteToWideChar(distStr, distWStr, sizeof(distWStr) / sizeof(wchar_t));
		wcscat_s(str, sizeof(str) / sizeof(wchar_t), distWStr);


		DrawCenterText(info.screenPos.x, info.screenPos.y + 3, info.color, str);
		// ______________
		if (screenListCount < MAX_ENTITIES && info.screenPos.x > 0 && info.screenPos.y > 0)
			screenList[screenListCount++] = info.screenPos;


	}
void DrawHighValueItemsList() {
	
	// ____________
	float listX = game::GameCenterW - 350; // ________
	float listY = 400; // ____________
	float listWidth = 300;
	float listHeight = min(400, highValueCount * 18 + 30); // _______16______
	float itemHeight = 18;

	// ________
	DrawFilledRect(listX, listY, listWidth, listHeight, ImVec4(0.1f, 0.1f, 0.1f, 0.9f), 0, 0);
	DrawRect(listX, listY, listWidth, listHeight, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), 1.0f);

	// ________
	DrawNewText(listX + 10, listY + 5, ImVec4(1.0f, 1.0f, 0.0f, 1.0f), (WCHAR*)_XOR_(L"______________"));
	DrawLine(listX + 10, listY + 25, listX + listWidth - 10, listY + 25, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), 1.0f);

	// _____________________15____
	int maxItems = min(15, highValueCount);

	if(maxItems == 0) return; // ___________________________


	// ________________________/_____
	for (int i = 0; i < highValueCount - 1; i++) {
		for (int j = i + 1; j < highValueCount; j++) {
			
			float valueI = highValueItems[i].size != 0 ? (float)highValueItems[i].price / highValueItems[i].size : 0;
			float valueJ = highValueItems[j].size != 0 ? (float)highValueItems[j].price / highValueItems[j].size : 0;
			if (valueI != valueI || valueJ!= valueJ) return;
			if (valueI < valueJ) {
				// ____
				EntityInfo temp = highValueItems[i];
				highValueItems[i] = highValueItems[j];
				highValueItems[j] = temp;
			}
		}
	}

	for (int i = 0; i < maxItems; i++) {
		auto& item = highValueItems[i];
		float itemY = listY + 30 + i * itemHeight;

		// ________________
		ImVec4 itemColor;
		switch (item.level) {
		case 2: itemColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f); break; // ____
		case 3: itemColor = ImVec4(0.0f, 0.5f, 1.0f, 1.0f); break; // ____
		case 4: itemColor = ImVec4(1.0f, 0.0f, 1.0f, 1.0f); break; // ____
		case 5: itemColor = ImVec4(1.0f, 0.5f, 0.0f, 1.0f); break; // ____
		case 6: itemColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f); break; // ____
		default: itemColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f); break;
		}

		// ________________________________
		memset(itemInfo, 0, sizeof(itemInfo));
		memset(temp, 0, sizeof(temp));
		sprintf(temp, ("%d."), i + 1);
		MultiByteToWideChar(temp, itemInfo, sizeof(itemInfo) / sizeof(wchar_t));
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), (L" ____:"));
		sprintf(temp, ("%d"), item.price);
		wchar_t priceW[32] = { 0 };
		MultiByteToWideChar(temp, priceW, sizeof(priceW) / sizeof(wchar_t));
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), priceW);
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), (L" ["));
		sprintf(temp, ("%d"), item.level);
		wchar_t levelW[32] = { 0 };
		MultiByteToWideChar(temp, levelW, sizeof(levelW) / sizeof(wchar_t));
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), levelW);
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), (L"__] ____:"));
		sprintf(temp, ("%d"), (int)item.size);
		wchar_t sizeW[32] = { 0 };
		MultiByteToWideChar(temp, sizeW, sizeof(sizeW) / sizeof(wchar_t));
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), sizeW);
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), (L" ____:"));
		sprintf(temp, ("%d"), (int)item.distance / 100);
		wchar_t distW[32] = { 0 };
		MultiByteToWideChar(temp, distW, sizeof(distW) / sizeof(wchar_t));
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), distW);
		wcscat_s(itemInfo, sizeof(itemInfo) / sizeof(wchar_t), (L"m"));
		if (listX != listX || itemY != itemY) return;
		DrawNewText(listX + 10, itemY, itemColor, itemInfo);
	}
}
	void DrawMain()
	{

		
		if (isStart) {
			diagDrawMainTicks++;
			diagPipelineStage = 100; // DrawMain entered
			

			DrawFilledRect(2, 15, 10, 10, ImVec4(0.0f, 1.f, 0.f, 1.0f), 0, 0);

			if (game::GameNULL == 0) {
				diagPipelineStage = 110; // no game base yet
				return;
			}

			if (update_addr(engine)) {
				diagPipelineStage = 130; // update_addr ok

				if (gameData.Count < 200) {

					diagPipelineStage = 140; // actor count small; keep draw path armed
				}


				DrawFilledRect(2, 28, 10, 10, ImVec4(1.0f, 0.f, 0.f, 1.0f), 0, 0);

				
			
				if (isBegin) {
					diagPipelineStage = 160; // entering GetData/draw path


					DrawFilledRect(2, 28, 10, 10, ImVec4(1.0f, 0.f, 0.f, 1.0f), 0, 0);

					GetData();
					diagPipelineStage = 300; // GetData returned, entering draw loop

					memset(screenPosArrayCopy, 0, sizeof(screenPosArrayCopy));
					memset(otherPosArrayCopy, 0, sizeof(otherPosArrayCopy));
					memcpy(screenPosArrayCopy, screenPosArray, sizeof(screenPosArray));
					memcpy(otherPosArrayCopy, otherPosArray, sizeof(otherPosArray));

					float x = game::GameCenterW - 175, y = 200;
					DrawCircleFilled(x, y, 3, ImColor(0, 0, 0, 128));
					DrawCircle(x, y, 150, ImColor(0, 0, 0, 255));
					DrawCircle(x, y, 100, ImColor(0, 0, 0, 255));
					DrawCircle(x, y, 50, ImColor(0, 0, 0, 255));
					DrawLine(x, y - 150, x, y + 150, ImColor(0, 0, 0, 255), 1);
					DrawLine(x - 150, y, x + 150, y, ImColor(0, 0, 0, 255), 1);
					DrawCircleFilled(x, y, 3, ImColor(255, 255, 255, 255));




					

					for (int i = 0; i < screenPosCount; i++) {
						auto info = screenPosArrayCopy[i];

						if (info.pawnAddr == 0) continue;  // ________

						auto entityPawnAddress = info.pawnAddr;

						if (!isValidPtr(entityPawnAddress)) continue;

						if (info.type == 0) {
							if (info.headth <= 0 && isValidPtr(entityPawnAddress))
								info.headth = GetHealth(entityPawnAddress);
							if (info.headth <= 0)
								info.headth = 100;

							if (info.headth > 0) {
								

								DrawRander(info);

								if (wcscmp(info.objName, (L"____")) == 0) continue;

								// DrawPlayer has its own W2S/fallback-box
								// validation.  Do not hard-filter here:
								// hook-only coords can have an empty/stale
								// screenPos until the fallback path rebuilds
								// head/foot projection from world coords.
								DrawPlayer(info);


							}


						}
					}

					memset(screenList, 0, sizeof(screenList));  // ____ screenList.clear()
					screenListCount = 0;
					highValueCount = 0;
					for (int i = 0; i < otherPosCount; i++) {
						if (otherPosArrayCopy[i].pawnAddr == 0) continue;  // ________

						if (!isValidPtr(otherPosArrayCopy[i].pawnAddr)) continue;
						DrawItem(otherPosArrayCopy[i]);

					}
					if (menu::isItemList) {

						DrawHighValueItemsList();

					}

					do {

						if (menu::isAim && aimInfo.pawnAddr != 0 && (IsKeyDown(VK_LBUTTON) || IsKeyDown(VK_LMENU))) {

							if (!isValidPtr(aimInfo.pawnAddr)) break;


							if (!InScreen(aimInfo.screenHeadPos)) break;

							if (isUpdateAimInfo)
								StartAim(aimInfo);

							isAiming = true;

							//DrawLine(game::GameCenterX, game::GameCenterY, aimInfo.screenHeadPos.x, aimInfo.screenHeadPos.y, aimInfo.color, 1);

						}
						else {
							aimInfo.pawnAddr = 0;
							aimState.isMoving = false;
							aimState.targetX = 0;
							aimState.targetY = 0;
							aimState.currentX = 0;
							aimState.currentY = 0;
							aimState.duration = 0;
							sjz::vtAimInfo.targetX = (int)0;
							sjz::vtAimInfo.targetY = (int)0;
							isAiming = false;

						}


					} while (0);
				



				}
				else {
					diagPipelineStage = 150; // isBegin/encryption guard blocked GetData
				}


			}
			else {
				diagPipelineStage = 120; // update_addr failed
			}


			if (menu::isShowDebugInfo) {
				DrawNewTextDebug(10, 10, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"GamePid = %p"), game::GamePid);
				DrawNewTextDebug(10, 25, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"cr3 = %p"), game::GameCr3);
				DrawNewTextDebug(10, 40, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"GameBase = %p"), game::GameNULL);
				DrawNewTextDebug(10, 55, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"Uworld = %p"), decrypt(gameData.Uworld));
				DrawNewTextDebug(10, 70, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"levelCount = %p"), gameData.levelCount);
				DrawNewTextDebug(10, 85, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"ULevels = %p"), gameData.ULevels);
				DrawNewTextDebug(10, 100, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"GameInstance = %p"), gameData.GameInstance);
				DrawNewTextDebug(10, 115, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"LocalPlayer = %p"), gameData.LocalPlayer);
				DrawNewTextDebug(10, 130, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"PlayerController = %p"), gameData.PlayerController);
				DrawNewTextDebug(10, 145, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"AcknowledgedPawn = %p"), gameData.AcknowledgedPawn);
				DrawNewTextDebug(10, 160, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"Actor = %p"), gameData.Actor);
				DrawNewTextDebug(10, 175, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"Actor Count = %d"), gameData.Count);
				DrawNewTextDebug(10, 190, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"screenCount = %d screenCount2 = %d"), screenCount, screenCount2);
				DrawNewTextDebug(10, 205, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"IsEncryped = %d"), gameData.isEncrypted);
				DrawNewTextDebug(10, 220, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"IsAim(Alt+1) = %d"), menu::isAim);
				DrawNewTextDebug(10, 235, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"IsHead(Alt+2) = %d"), menu::isHead);
				DrawNewTextDebug(10, 250, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"IsBegin = %d"), (int)isBegin);
				DrawNewTextDebug(10, 265, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"key = %p"), gameData.key);
				DrawNewTextDebug(10, 280, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"screenPosCount = %p"), screenPosCount);
				DrawNewTextDebug(10, 295, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"otherPosCount = %p"), otherPosCount);
				DrawNewTextDebug(10, 310, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"count = %p count1 = %p count2 = %p count3 = %p count4 = %p count5 = %p count6 = %p count6 = %p"), count, count1, count2, count3, count4, count5, count6, count7);

				DrawNewTextDebug(10, 325, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"ULevel = %p"), gameData.ULevel);
				DrawNewTextDebug(10, 340, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), (WCHAR*)(L"count = %p count1 = %p count2 = %p count3 = %p count4 = %p count5 = %p count6 = %p count6 = %p"), item1, item2, item3, item4, item5, item6, item7);

			}
			else {
				DrawNewTextDebug(2, 35, ImVec4(0.0f, 1.f, 0.f, 1.0f), (WCHAR*)L"screen1 = %p  screen2 = %p\n", sjz::screenCount, sjz::screenCount2);
				DrawNewTextDebug(2, 50, ImVec4(0.0f, 1.f, 0.f, 1.0f), (WCHAR*)L"isAim = %p  isHead = %p\n", menu::isAim,menu::isHead);
				DrawNewTextDebug(2, 65, ImVec4(0.0f, 1.f, 0.f, 1.0f), (WCHAR*)L"isEncryped = %p\n", gameData.isEncrypted);
			}



		




			
		}



	}

#pragma code_seg()

} // namespace sjz
