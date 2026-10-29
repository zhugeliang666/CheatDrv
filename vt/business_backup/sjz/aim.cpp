#include "aim.h"
#include "world.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"
#include "../vt/Math.h"
#include <render/render.h>

using namespace math;

namespace sjz {

#pragma code_seg(".vm")

	// Aim state ___ written by StartAim, consumed by StartMoveMouse and
	// reset by render.cpp on key release.
	AimInfo  vtAimInfo;
	AimState aimState = { 0 };

	// Selected target ___ set by scan.cpp's entity loop.
	EntityInfo aimInfo;
	bool       isUpdateAimInfo = false;
	ULONG64    aimDistance;

	bool isAiming = false;

Vector2 CalculateBezierPoint(float t, Vector2 p0, Vector2 p1, Vector2 p2) {
	float u = 1 - t;
	float tt = t * t;
	float uu = u * u;

	Vector2 point;
	point.x = uu * p0.x + 2 * u * t * p1.x + tt * p2.x;
	point.y = uu * p0.y + 2 * u * t * p1.y + tt * p2.y;
	return point;
}


// __________________
float CalculateSpeedMultiplier(float progress, float distance) {
	// ____________
	const float baseSpeed = 0.002f;     // ________
	const float maxSpeed = 0.01f;       // _______
	const float acceleration = 0.001f;  // ______


	//const float baseSpeed = 0.03f;     // ________
	//const float maxSpeed = 0.1f;       // _______
	//const float acceleration = 0.006f;  // ______

	// ____________
	float speedMultiplier = baseSpeed + (1.0f - exp(-distance * acceleration));
	speedMultiplier = min(speedMultiplier, maxSpeed);

	// ____________________
	float easeProgress = progress * progress;

	// ____________________
	if (progress < 0.3f) {
		// ____________
		return speedMultiplier * (progress / 0.3f);
	}
	else if (progress > 0.7f) {
		// ____________
		return speedMultiplier * (1.0f - (progress - 0.7f) / 0.3f);
	}
	else {
		// ___________________
		return speedMultiplier;
	}
}
void StartAim(EntityInfo target) {


	

	// ________________________
	float deltaX = target.screenHeadPos.x - game::GameCenterX;
	float deltaY = target.screenHeadPos.y - game::GameCenterY;

	// ____________________
	float distance = sqrt(deltaX * deltaX + deltaY * deltaY);

	if(distance < 5)
		return;

	// _________________________________
	if (!aimState.isMoving) {
		aimState.targetX = deltaX;
		aimState.targetY = deltaY;
		aimState.currentX = 0;
		aimState.currentY = 0;
		UINT64 time;
		hv::CallUser(RtlQueryPerformanceCounter, (LARGE_INTEGER*)hv::descBuffer);
		RtlCopyMemory(&time, hv::descBuffer_hva, sizeof(UINT64));
		aimState.startTime = time;
		aimState.duration = 20; // ____________20ms
		aimState.isMoving = true;
	}
	UINT64 time;
	hv::CallUser(RtlQueryPerformanceCounter, (LARGE_INTEGER*)hv::descBuffer);
	RtlCopyMemory(&time, hv::descBuffer_hva, sizeof(UINT64));
	// ____________
	auto currentTime = time;


	auto elapsedTime = ((currentTime - aimState.startTime) * 1000  / hv::perf_frequency) ;

	// _____________________
	if (elapsedTime < aimState.duration) {
		// __________________0-1__
		float segmentProgress = elapsedTime / aimState.duration;

		// ________________________
		float speedMultiplier = CalculateSpeedMultiplier(segmentProgress, distance);


		// ____________________
		Vector2 start(0, 0);
		Vector2 control(aimState.targetX * 0.5f, aimState.targetY * 0.5f + distance * 0.4f);
		Vector2 end(aimState.targetX, aimState.targetY);

		// _______________________
		Vector2 bezierPoint = CalculateBezierPoint(segmentProgress, start, control, end);



		// ________________________
		float remainingX = bezierPoint.x - aimState.currentX;
		float remainingY = bezierPoint.y - aimState.currentY;

		// ______________
		float moveX = remainingX * speedMultiplier * 0.85;
		float moveY = remainingY * speedMultiplier;

		// ______________
		if (abs(moveX) < 1.0f && abs(remainingX) > 0.0f) {
			moveX = (remainingX > 0) ? 1.0f : -1.0f;
		}
		if (abs(moveY) < 1.0f && abs(remainingY) > 0.0f) {
			moveY = (remainingY > 0) ? 1.0f : -1.0f;
		}

		if (aimState.lastX != 0 && aimState.lastY != 0) {

			if (abs(moveX) > 4.0f || abs(moveY) > 4.0f) {
				if (abs(moveX) > abs(aimState.lastX * 2+1)) {
					moveX = aimState.lastX;
				}
				if (abs(moveY) > abs(aimState.lastY*2+1))
				{
					moveY = aimState.lastY;
				}
			}
		}

		if (abs(moveX) == 1.0f && abs(moveY) == 1.0f) {
			if (abs(aimState.lastX == 1.0f) && abs(aimState.lastY == 1.0f)) {
				moveX = 0;
				moveY = 0;
			}
		}


	

		// _______________
		if (abs(moveX) < 6.f && abs(moveY) < 6.f) {

			if (gameData.isStartMove == false) 
			{
				sjz::vtAimInfo.targetX = (int)moveX;
				sjz::vtAimInfo.targetY = (int)moveY;
				aimState.currentX += moveX;
				aimState.currentY += moveY;
				aimState.lastX = moveX;
				aimState.lastY = moveY;

				gameData.isStartMove = true;
				hv::CallUser(WriteProcessMemory, (UINT64)-1, (UINT64)buffer0, (UINT64)buffer0, (UINT64)0x1, (UINT64)hv::descBuffer);
			}
		

		}
	}
	else {
		// _________________________________
		aimState.targetX = deltaX;
		aimState.targetY = deltaY;
		aimState.currentX = 0;
		aimState.currentY = 0;
		aimState.lastX = 0;
		aimState.lastY = 0;
		aimState.startTime = currentTime;

	}


}
	void StartMoveMouse()
	{


		if (gameData.isStartMove == true) {

			if (hv::mouse_event) {

				hv::Call2(hv::mouse_event, (ULONG64)sjz::vtAimInfo.targetX, (ULONG64)sjz::vtAimInfo.targetY, (ULONG64)0);

			}
			gameData.isStartMove = false;
		}


	
	}

#pragma code_seg()

} // namespace sjz
